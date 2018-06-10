extern crate std;

use osquery::*;
use ::Plugin;

pub struct ConfigPlugin {
    details: Box<ConfigPluginDetails>,
}

pub trait ConfigPluginDetails: Sync + Send {
    fn name(&self) -> String;
    fn content(&self) -> ExtensionPluginResponse;
}

impl Plugin for ConfigPlugin {
    fn name(&self) -> String {
        self.details.name()
    }

    fn registry_name(&self) -> String {
        "config".to_string()
    }

    fn call(&self, ctx: ExtensionPluginRequest) -> ExtensionResponse {
        let action_key_str = "action";
        if ctx.contains_key(action_key_str) {
            let action = ctx.get(action_key_str).expect("'action' key expected to have value if in map.");
            if action == "genConfig" {
                let status = ExtensionStatus::new(0, "OK".to_string(), None);
                return ExtensionResponse::new(status, self.details.content())
            }
        }

        let message = "Not a valid config plugin action".to_string();
        let status = ExtensionStatus::new(1, message, None);
        ExtensionResponse::new(status,  vec![])
    }

    fn routes(&self) -> ExtensionResponse {
        let status = ExtensionStatus::new(0, "OK".to_string(), None);
        ExtensionResponse::new(status, vec![])
    }
}
