use ::Plugin;
use osquery::*;

pub struct LoggerPlugin {
    details: Box<LoggerPluginDetails>,
}

pub trait LoggerPluginDetails: Sync + Send {
    fn name(&self) -> String;
    fn log_string(&self, &str) -> ExtensionStatus;
    fn log_health(&self, &str) -> ExtensionStatus;
    fn log_snapshot(&self, &str) -> ExtensionStatus;
}

impl Plugin for LoggerPlugin {
    fn name(&self) -> String {
        self.details.name()
    }

    fn registry_name(&self) -> String {
        "logger".to_string()
    }

    fn call(&self, ctx: ExtensionPluginRequest) -> ExtensionResponse {
        if ctx.contains_key("string") {
            let val = ctx.get("string").unwrap();
            ExtensionResponse::new(self.details.log_string(val), vec![])
        } else if ctx.contains_key("health") {
            let val = ctx.get("health").unwrap();
            ExtensionResponse::new(self.details.log_health(val), vec![])
        } else if ctx.contains_key("snapshot") {
            let val = ctx.get("snapshot").unwrap();
            ExtensionResponse::new(self.details.log_snapshot(val), vec![])
        } else if ctx.contains_key("init") {
            let message = "Use Glog for init logging".to_string();
            let status = ExtensionStatus::new(1, message, None);
            ExtensionResponse::new(status, vec![])
        } else if ctx.contains_key("status") {
            let message = "Use Glog for status logging".to_string();
            let status = ExtensionStatus::new(1, message, None);
            ExtensionResponse::new(status, vec![])
        } else {
            let message = "Not a valid logger plugin action".to_string();
            let status = ExtensionStatus::new(1, message, None);
            ExtensionResponse::new(status, vec![])
        }
    }

    fn routes(&self) -> ExtensionResponse {
        let status = ExtensionStatus::new(0, "OK".to_string(), None);
        ExtensionResponse::new(status, vec![])
    }
}

