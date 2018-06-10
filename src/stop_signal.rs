extern crate std;

use std::sync::{
    Arc,
    Condvar,
    Mutex,
};

#[derive(Clone)]
pub struct StopSignal {
    signal: Arc<(Mutex<bool>, Condvar)>,
}

impl StopSignal {
    pub fn new() -> Self {
        Self {
            signal: Arc::new((Mutex::new(false), Condvar::new()))
        }
    }

    pub fn wait(&self) {
        let &(ref lock, ref cvar) = &*self.signal;
        let mut finished = lock.lock().unwrap();
        while !*finished {
            finished = match cvar.wait(finished) {
                Ok(f) => f,
                Err(_) => { break } // wire this up to the Health API
            }
        }
    }

    pub fn wait_timeout(&self, duration: std::time::Duration) -> bool {
        let &(ref lock, ref cvar) = &*self.signal;
        let mut finished = lock.lock().unwrap();
        let mut signaled = false;
        while !*finished {
            finished = match cvar.wait_timeout(finished, duration) {
                Ok((done, timeout_result)) => {
                    if timeout_result.timed_out() {
                        break
                    }
                    signaled = true;
                    done
                },
                Err(_) => { break } // wire this up to the Health API
            }
        }

        signaled
    }

    pub fn done(&self) {
        let &(ref lock, ref cvar) = &*self.signal;
        let mut finished = lock.lock().unwrap();
        *finished = true;
        cvar.notify_all();
    }

    pub fn reset(&self) {
        let &(ref lock, _) = &*self.signal;
        let mut finished = lock.lock().unwrap();
        *finished = false;
    }
}