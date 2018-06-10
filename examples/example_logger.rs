extern crate crossbeam_channel;
extern crate osquery_rs;

use std::fs::OpenOptions;
use std::io::prelude::*;

struct TestLoggerDetails {
    file_writer_thread: Option<std::thread::JoinHandle<()>>,
    file_write_tx: crossbeam_channel::Sender<String>,
}

impl TestLoggerDetails {
    fn new(log_filename: &str) -> Self {
        let (file_write_tx, file_write_rx) = crossbeam_channel::unbounded();

        let log_filename = log_filename.to_string();
        let file_writer_thread = Some(std::thread::spawn(move || {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(&log_filename)
                .unwrap();

            let timeout = std::time::Duration::from_millis(500);
            loop {
                match file_write_rx.recv_timeout(timeout.clone()) {
                    Ok(msg) => {
                        match writeln!(file, "{}", msg) {
                            Ok(_) => {},
                            Err(e) => println!("DEBUG: failed to write to log file.")
                        }
                    },
                    Err(err) => {
                        match err {
                            crossbeam_channel::RecvTimeoutError::Disconnected => break,
                            _ => {} // This is usually just arbitrary timeouts
                        }
                    }
                }
            }
        }));

        Self {
            file_writer_thread,
            file_write_tx,
        }
    }
}

impl Drop for TestLoggerDetails {
    fn drop(&mut self) {
        match self.file_writer_thread.take() {
            Some(thread) => {}//thread.join().expect("Failed to join writer thread."),
            None => {}
        }
    }
}

impl osquery_rs::LoggerPluginDetails for TestLoggerDetails {
    fn name(&self) -> String {
        "example_logger".to_string()
    }

    fn log_string(&self, msg: &str) -> osquery_rs::osquery::ExtensionStatus {
        self.file_write_tx.send(format!("{}", msg));
        osquery_rs::osquery::ExtensionStatus::new(0, "OK".to_string(), None)
    }

    fn log_health(&self, msg: &str) -> osquery_rs::osquery::ExtensionStatus {
        self.file_write_tx.send(format!("{}", msg));
        osquery_rs::osquery::ExtensionStatus::new(0, "OK".to_string(), None)

    }

    fn log_snapshot(&self, msg: &str) -> osquery_rs::osquery::ExtensionStatus {
        self.file_write_tx.send(format!("{}", msg));
        osquery_rs::osquery::ExtensionStatus::new(0, "OK".to_string(), None)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    println!("{:#?}", args);

    std::thread::sleep_ms(1500);

    let logger_plugin = Box::new(osquery_rs::LoggerPlugin::new(Box::new(TestLoggerDetails::new("/Users/zbrown/example_logger.log"))));
    let mut extension_server = osquery_rs::ExtensionManagerServer::new_with_path("example_logger", "/Users/zbrown/osquery_shell.em");
    //let mut extension_server = osquery_rs::ExtensionManagerServer::new_with_path("example_logger", "/Users/zbrown/.osquery/shell.em");
    //let mut extension_server = osquery_rs::ExtensionManagerServer::new("example_logger");
    extension_server.register_plugin(logger_plugin);
    extension_server.run();
}
