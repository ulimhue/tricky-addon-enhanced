use std::os::unix::io::RawFd;

use crate::config::Config;
use super::tasks::{DaemonTask, TaskBackoff, StatusTask, AutomationTask, HealthTask, KeyboxTask, SecurityPatchTask};

const TAG_TASK_BASE: u64 = 100;

pub struct Scheduler {
    slots: Vec<TaskSlot>,
    manager: Option<String>,
}

struct TaskSlot {
    task: Box<dyn DaemonTask>,
    timer_fd: RawFd,
    stagger_done: bool,
    current_interval: u32,
}

impl Scheduler {
    pub fn new(_config: &Config, epoll_fd: RawFd, manager: Option<String>) -> anyhow::Result<Self> {
        let task_defs: Vec<(Box<dyn DaemonTask>, u32)> = vec![
            (Box::new(StatusTask::new()), 5),
            (Box::new(AutomationTask::new()), 10),
            (Box::new(HealthTask::new()), 15),
            (Box::new(KeyboxTask::new()), 20),
            (Box::new(SecurityPatchTask::new()), 25),
        ];

        let mut slots = Vec::with_capacity(task_defs.len());
        for (idx, (task, initial_delay)) in task_defs.into_iter().enumerate() {
            let tfd = create_timerfd()?;
            arm_timerfd_oneshot(tfd, initial_delay);
            super::epoll_add(epoll_fd, tfd, TAG_TASK_BASE + idx as u64)?;
            slots.push(TaskSlot {
                task,
                timer_fd: tfd,
                stagger_done: false,
                current_interval: 0,
            });
        }

        Ok(Self { slots, manager })
    }

    pub fn handle_timer(&mut self, idx: usize, config: &Config) {
        let slot = match self.slots.get_mut(idx) {
            Some(s) => s,
            None => return,
        };
        drain_timerfd(slot.timer_fd);

        if !slot.stagger_done {
            slot.stagger_done = true;
            let interval = slot.task.interval_secs(config);
            slot.current_interval = interval;
            arm_timerfd(slot.timer_fd, interval);
        }

        if !slot.task.is_enabled(config) {
            return;
        }

        match slot.task.run(config, self.manager.as_deref()) {
            Ok(()) => {}
            Err(TaskBackoff(delay)) => {
                tracing::info!("{}: backoff {delay}s", slot.task.name());
                arm_timerfd_oneshot(slot.timer_fd, delay);
            }
        }
    }

    pub fn reconfigure(&mut self, old: &Config, new: &Config) {
        for slot in &mut self.slots {
            if !slot.stagger_done {
                continue;
            }
            let old_interval = slot.task.interval_secs(old);
            let new_interval = slot.task.interval_secs(new);
            if old_interval != new_interval {
                tracing::info!("{}: interval {old_interval}s -> {new_interval}s", slot.task.name());
                slot.current_interval = new_interval;
                arm_timerfd(slot.timer_fd, new_interval);
            }
        }
    }

    pub fn run_automation_now(&mut self, config: &Config) {
        for slot in &mut self.slots {
            if slot.task.name() != "automation" { continue; }
            if !slot.task.is_enabled(config) { return; }
            match slot.task.run(config, self.manager.as_deref()) {
                Ok(()) => {}
                Err(TaskBackoff(delay)) => {
                    tracing::info!("automation: backoff {delay}s");
                    arm_timerfd_oneshot(slot.timer_fd, delay);
                }
            }
            return;
        }
    }

    pub fn close_all(&self) {
        for slot in &self.slots {
            unsafe { libc::close(slot.timer_fd); }
        }
    }
}

fn create_timerfd() -> anyhow::Result<RawFd> {
    let fd = unsafe {
        libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC | libc::TFD_NONBLOCK)
    };
    if fd < 0 {
        anyhow::bail!("timerfd_create failed: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn arm_timerfd(fd: RawFd, interval_secs: u32) {
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: interval_secs as _,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: interval_secs as _,
            tv_nsec: 0,
        },
    };
    unsafe { libc::timerfd_settime(fd, 0, &spec, std::ptr::null_mut()); }
}

fn arm_timerfd_oneshot(fd: RawFd, delay_secs: u32) {
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec {
            tv_sec: delay_secs as _,
            tv_nsec: 0,
        },
    };
    unsafe { libc::timerfd_settime(fd, 0, &spec, std::ptr::null_mut()); }
}

fn drain_timerfd(fd: RawFd) {
    let mut buf = [0u8; 8];
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 8); }
}
