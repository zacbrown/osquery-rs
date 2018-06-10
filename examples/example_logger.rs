extern crate osquery_rs;

struct TestLoggerDetails;

impl osquery_rs::LoggerPluginDetails for TestLoggerDetails {
    fn name(&self) -> String {
        "example_logger".to_string()
    }

    fn log_string(&self, msg: &str) -> osquery_rs::osquery::ExtensionStatus {
        println!("LOG_STRING: {}", msg);
        osquery_rs::osquery::ExtensionStatus::new(0, "OK".to_string(), None)
    }

    fn log_health(&self, msg: &str) -> osquery_rs::osquery::ExtensionStatus {
        println!("LOG_HEALTH: {}", msg);
        osquery_rs::osquery::ExtensionStatus::new(0, "OK".to_string(), None)

    }

    fn log_snapshot(&self, msg: &str) -> osquery_rs::osquery::ExtensionStatus {
        println!("LOG_SNAPSHOT: {}", msg);
        osquery_rs::osquery::ExtensionStatus::new(0, "OK".to_string(), None)
    }
}

fn main() {
    let logger_plugin = Box::new(osquery_rs::LoggerPlugin::new(Box::new(TestLoggerDetails {})));
    let mut extension_server = osquery_rs::ExtensionManagerServer::new_with_path("example_logger", "/Users/zbrown/.osquery/shell.em");
    extension_server.register_plugin(logger_plugin);
    extension_server.run();
}
