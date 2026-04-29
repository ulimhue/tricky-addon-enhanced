mod tasks;
mod scheduler;

use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::config::{Config, SELF_WRITE};
use crate::platform::signal::SHUTDOWN;
use scheduler::Scheduler;

pub const DATA_DIR: &str = "/data/adb/tricky_store/ta-enhanced";
pub const PID_FILE: &str = "/data/adb/tricky_store/ta-enhanced/daemon.pid";
pub const LOCK_FILE: &str = "/data/adb/tricky_store/ta-enhanced/daemon.lock";
pub const CONFIG_PATH: &str = "/data/adb/tricky_store/ta-enhanced/config.toml";

const TAG_SIGNAL: u64 = 0;
const TAG_INOTIFY: u64 = 1;
const TAG_APP_INOTIFY: u64 = 2;
const TAG_TASK_BASE: u64 = 100;

const APP_DIR: &str = "/data/app";

pub fn handle_daemon(cfg: &Config, manager: Option<&str>) -> anyhow::Result<()> {
    let _ = cfg;
    crate::platform::process::daemonize()?;
    run_daemon(manager.map(|s| s.to_string()))
}

pub fn handle_daemon_stop() -> anyhow::Result<()> {
    let pid = crate::platform::process::read_pid(Path::new(PID_FILE))
        .ok_or_else(|| anyhow::anyhow!("daemon not running (no PID file)"))?;
    if !crate::platform::process::is_running(pid) {
        let _ = std::fs::remove_file(PID_FILE);
        anyhow::bail!("daemon not running (stale PID {pid})");
    }
    unsafe { libc::kill(pid, libc::SIGTERM); }
    println!("sent SIGTERM to daemon (pid {pid})");
    Ok(())
}

pub fn handle_daemon_status() -> anyhow::Result<()> {
    let pid = crate::platform::process::read_pid(Path::new(PID_FILE));
    let running = pid.map(|p| crate::platform::process::is_running(p)).unwrap_or(false);
    let status = serde_json::json!({
        "running": running,
        "pid": if running { pid } else { None },
        "tasks": ["status", "automation", "health", "keybox", "security_patch"],
    });
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

extern "C" fn cleanup_pid_file() {
    let _ = std::fs::remove_file(PID_FILE);
}

fn monotonic_ms() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts); }
    (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
}

fn run_daemon(manager: Option<String>) -> anyhow::Result<()> {
    let _lock = match crate::platform::fs::acquire_instance_lock(Path::new(LOCK_FILE))? {
        Some(f) => f,
        None => {
            eprintln!("another ta-enhanced daemon is already running");
            std::process::exit(1);
        }
    };

    crate::platform::process::write_pid(Path::new(PID_FILE))?;
    unsafe { libc::atexit(cleanup_pid_file); }

    let _ = crate::platform::process::camouflage();

    let mut config = Config::load(Some(Path::new(CONFIG_PATH)))?;
    crate::logging::init(false, &config.logging)?;

    crate::platform::signal::block_signals()?;

    let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epoll_fd < 0 {
        anyhow::bail!("epoll_create1 failed: {}", std::io::Error::last_os_error());
    }

    let signal_fd = crate::platform::signal::create_signal_fd()?;
    epoll_add(epoll_fd, signal_fd, TAG_SIGNAL)?;

    let inotify_fd = create_config_watcher(CONFIG_PATH)?;
    epoll_add(epoll_fd, inotify_fd, TAG_INOTIFY)?;

    let app_inotify_fd = if config.automation.enabled && config.automation.use_inotify {
        match create_app_watcher(APP_DIR) {
            Ok(fd) => {
                epoll_add(epoll_fd, fd, TAG_APP_INOTIFY)?;
                tracing::info!("watching {APP_DIR} for app installs");
                Some(fd)
            }
            Err(e) => {
                tracing::warn!("app directory inotify failed, relying on polling: {e}");
                None
            }
        }
    } else {
        None
    };

    let mut sched = Scheduler::new(&config, epoll_fd, manager)?;

    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 16];
    let mut inotify_debounce: Option<u64> = None;
    let mut app_debounce: Option<u64> = None;
    let mut app_retry: Option<u64> = None;

    tracing::info!("daemon started (pid={})", std::process::id());

    while !SHUTDOWN.load(Ordering::Acquire) {
        let n = unsafe {
            libc::epoll_wait(epoll_fd, events.as_mut_ptr(), events.len() as i32, 1000)
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) { continue; }
            anyhow::bail!("epoll_wait: {e}");
        }

        let now = monotonic_ms();

        for i in 0..n as usize {
            let tag = events[i].u64;
            match tag {
                TAG_SIGNAL => {
                    drain_signalfd(signal_fd);
                    SHUTDOWN.store(true, Ordering::Release);
                    tracing::info!("shutdown signal received");
                }
                TAG_INOTIFY => {
                    let deleted = drain_inotify(inotify_fd);
                    if deleted {
                        let mut rewatched = false;
                        for _ in 0..3 {
                            if rewatch_config(inotify_fd, CONFIG_PATH).is_ok() {
                                rewatched = true;
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        if !rewatched {
                            tracing::error!("config watch lost -- reload disabled until restart");
                        }
                    }
                    inotify_debounce = Some(now + 300);
                }
                TAG_APP_INOTIFY => {
                    drain_inotify_discard(app_inotify_fd.unwrap_or(-1));
                    app_debounce = Some(now + 3000);
                    app_retry = Some(now + 8000);
                }
                t if t >= TAG_TASK_BASE => {
                    let task_idx = (t - TAG_TASK_BASE) as usize;
                    sched.handle_timer(task_idx, &config);
                }
                _ => {}
            }
        }

        if let Some(deadline) = inotify_debounce {
            if now >= deadline {
                inotify_debounce = None;
                if SELF_WRITE.swap(false, Ordering::Relaxed) {
                    continue;
                }
                match Config::load(Some(Path::new(CONFIG_PATH))) {
                    Ok(new_config) => {
                        tracing::info!("config reloaded");
                        sched.reconfigure(&config, &new_config);
                        config = new_config;
                    }
                    Err(e) => tracing::warn!("config reload failed: {e}"),
                }
            }
        }

        if let Some(deadline) = app_debounce {
            if now >= deadline {
                app_debounce = None;
                if config.automation.enabled {
                    tracing::info!("app change detected, running package scan");
                    sched.run_automation_now(&config);
                }
            }
        }

        if let Some(deadline) = app_retry {
            if now >= deadline {
                app_retry = None;
                if config.automation.enabled {
                    tracing::info!("app change retry scan");
                    sched.run_automation_now(&config);
                }
            }
        }
    }

    tracing::info!("daemon shutting down");
    sched.close_all();
    unsafe {
        if let Some(fd) = app_inotify_fd { libc::close(fd); }
        libc::close(inotify_fd);
        libc::close(signal_fd);
        libc::close(epoll_fd);
    }

    Ok(())
}

fn epoll_add(epoll_fd: RawFd, fd: RawFd, tag: u64) -> anyhow::Result<()> {
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: tag,
    };
    let ret = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
    if ret < 0 {
        anyhow::bail!("epoll_ctl ADD failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn drain_signalfd(fd: RawFd) {
    let mut buf = [0u8; 128];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 { break; }
    }
}

fn create_config_watcher(config_path: &str) -> anyhow::Result<RawFd> {
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        anyhow::bail!("inotify_init1 failed: {}", std::io::Error::last_os_error());
    }
    let c_path = std::ffi::CString::new(config_path)?;
    let wd = unsafe {
        libc::inotify_add_watch(fd, c_path.as_ptr(), libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF)
    };
    if wd < 0 {
        tracing::warn!("inotify_add_watch failed (config may not exist yet)");
    }
    Ok(fd)
}

fn rewatch_config(inotify_fd: RawFd, config_path: &str) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(config_path)?;
    let wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            c_path.as_ptr(),
            libc::IN_CLOSE_WRITE | libc::IN_DELETE_SELF,
        )
    };
    if wd < 0 {
        anyhow::bail!("rewatch failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn create_app_watcher(dir: &str) -> anyhow::Result<RawFd> {
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        anyhow::bail!("inotify_init1 failed: {}", std::io::Error::last_os_error());
    }
    let c_path = std::ffi::CString::new(dir)?;
    let wd = unsafe {
        libc::inotify_add_watch(
            fd,
            c_path.as_ptr(),
            libc::IN_CREATE | libc::IN_DELETE | libc::IN_MOVED_TO | libc::IN_MOVED_FROM,
        )
    };
    if wd < 0 {
        unsafe { libc::close(fd); }
        anyhow::bail!("inotify_add_watch({dir}) failed: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn drain_inotify_discard(fd: RawFd) {
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 { break; }
    }
}

fn drain_inotify(fd: RawFd) -> bool {
    let mut buf = [0u8; 4096];
    let mut saw_delete = false;
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 { break; }
        let mut offset = 0usize;
        while offset < n as usize {
            let event = unsafe {
                &*(buf.as_ptr().add(offset) as *const libc::inotify_event)
            };
            if event.mask & libc::IN_DELETE_SELF != 0 {
                saw_delete = true;
            }
            offset += std::mem::size_of::<libc::inotify_event>() + event.len as usize;
        }
    }
    saw_delete
}
