extern crate ordered_float;
extern crate thrift;
extern crate try_from;
extern crate uuid;

#[cfg(target_family = "unix")]
extern crate unix_socket;

// Auto-generated bindings from Thrift.
pub mod osquery;

use std::collections::BTreeMap;

use thrift::protocol::{TBinaryInputProtocol, TBinaryOutputProtocol};
use thrift::transport::{
    TBufferChannel,
    TBufferedReadTransport,
    TBufferedReadTransportFactory,
    TBufferedWriteTransport,
    TBufferedWriteTransportFactory,
};

use osquery::*;

#[cfg(target_family = "unix")]
mod sys {
    extern crate unix_socket;

    pub const DEFAULT_PIPE_PATH: &'static str ="/var/osquery/osquery.em";
    pub type TChannel = unix_socket::UnixStream;
}

#[cfg(target_os = "windows")]
mod sys {
    extern crate named_pipe;

    pub const DEFAULT_PIPE_PATH: &'static str = r#"\\.\pipe\osquery.em"#;
    // pub type TChannel = ...
}

type ProtocolIn = TBinaryInputProtocol<TBufferedReadTransport<sys::TChannel>>;
type ProtocolOut = TBinaryOutputProtocol<TBufferedWriteTransport<sys::TChannel>>;

// TODO: Once we implement wrapping the thrift-generated client, exposes as pub.
struct ExtensionManagerClient {
    client: osquery::ExtensionManagerSyncClient<ProtocolIn, ProtocolOut>
}

impl ExtensionManagerClient {
    // TODO: Flesh out wrapping the calls to the thrift-generated client.
}

struct ExtensionManagerClientFactory;

impl ExtensionManagerClientFactory {
    // TODO: We should wrap the thrift-generated client with ExtensionManagerClient.
    fn create(uuid: Option<uuid::Uuid>) -> osquery::ExtensionManagerSyncClient<ProtocolIn, ProtocolOut> {
        Self::create_with_path(sys::DEFAULT_PIPE_PATH, uuid)
    }

    // TODO: We should wrap the thrift-generated client with ExtensionManagerClient.
    fn create_with_path(path: &str, uuid: Option<uuid::Uuid>) -> osquery::ExtensionManagerSyncClient<ProtocolIn, ProtocolOut> {
        let path = match uuid {
            Some(uuid) => format!("{}.{}", path, uuid),
            None => path.to_string(),
        };

        if cfg!(target_os = "windows") {
            panic!("Unsupported platform.");
        } else if cfg!(target_family = "unix") {
            let socket = unix_socket::UnixStream::connect(&path).expect(&format!("Unable to connect to {} with unix_socket::UnixStream", path));
            let transport_in = TBufferedReadTransport::new(socket.try_clone().unwrap());
            let transport_out = TBufferedWriteTransport::new(socket.try_clone().unwrap());
            let protocol_in = TBinaryInputProtocol::new(transport_in, false);
            let protocol_out = TBinaryOutputProtocol::new(transport_out, true);

            osquery::ExtensionManagerSyncClient::new(protocol_in, protocol_out)
        } else {
            panic!("Unsupported platform.");
        }
    }
}

pub trait Plugin {
    fn name(&self) -> String;
}

pub trait ConfigPlugin: Plugin {
    fn registry_name(&self) -> String {
        "config".to_string()
    }

    fn call(&self, ctx: ExtensionPluginRequest) -> ExtensionResponse {
        let action_key_str = "action";
        if ctx.contains_key(action_key_str) {
            let action = ctx.get(action_key_str).expect("'action' key expected to have value if in map.");
            if action == "genConfig" {
                let status = ExtensionStatus::new(0, "OK".to_string(), None);
                return ExtensionResponse::new(status, self.content())
            }
        }

        let message = "Not a valid config plugin action".to_string();
        let status = ExtensionStatus::new(1, message, None);
        ExtensionResponse::new(status, vec![])
    }

    fn routes(&self) -> ExtensionResponse {
        let status = ExtensionStatus::new(0, "OK".to_string(), None);
        ExtensionResponse::new(status, vec![])
    }

    fn content(&self) -> ExtensionPluginResponse;
}

pub trait LoggerPlugin: Plugin {
    fn registry_name(&self) -> String {
        "logger".to_string()
    }

    fn call(&self, ctx: ExtensionPluginRequest) -> ExtensionResponse {
        if ctx.contains_key("string") {
            let val = ctx.get("string").unwrap();
            ExtensionResponse::new(self.log_string(val), vec![])
        } else if ctx.contains_key("health") {
            let val = ctx.get("health").unwrap();
            ExtensionResponse::new(self.log_health(val), vec![])
        } else if ctx.contains_key("snapshot") {
            let val = ctx.get("snapshot").unwrap();
            ExtensionResponse::new(self.log_snapshot(val), vec![])
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

    fn log_string(&self, &str) -> ExtensionStatus;
    fn log_health(&self, &str) -> ExtensionStatus;
    fn log_snapshot(&self, &str) -> ExtensionStatus;
}

pub enum ColumnType {
    Text,
    Integer,
    BigInt,
    Double,
}

impl ToString for ColumnType {
    fn to_string(&self) -> String {
        match &self {
            &ColumnType::Text => "TEXT".to_string(),
            &ColumnType::Integer => "INTEGER".to_string(),
            &ColumnType::BigInt => "BIGINT".to_string(),
            &ColumnType::Double => "DOUBLE".to_string(),
        }
    }
}

pub struct ColumnDefinition {
    column_name: String,
    column_type: ColumnType,
}

pub trait TablePlugin: Plugin {
    fn registry_name(&self) -> String {
        "table".to_string()
    }

    fn routes(&self) -> ExtensionResponse {
        let status = ExtensionStatus::new(0, "OK".to_string(), None);
        let mut routes = vec![];

        for column in self.columns() {
            let mut map = BTreeMap::new();
            map.insert("id".to_string(), "column".to_string());
            map.insert("name".to_string(), column.column_name);
            map.insert("type".to_string(), column.column_type.to_string());
            map.insert("op".to_string(), "0".to_string());
            routes.push(map);
        }
        ExtensionResponse::new(status, routes)
    }

    fn call(&self, ctx: ExtensionPluginRequest) -> ExtensionResponse {
        if ctx.contains_key("action") == false {
            let message = "Table plugins must include a request action".to_string();
            let status = ExtensionStatus::new(1, message, None);
            return ExtensionResponse::new(status, vec![])
        }

        let action = ctx.get("action").unwrap();
        match action.as_str() {
            "generate" => {
                let mut constraint_ctx = None;
                if ctx.contains_key("context") {
                    constraint_ctx = Some(ctx.get("context").unwrap());
                }

                // BUGBUG: For now we always ignore the context constraints from the "context" property.
                self.generate(None)
            },
            "columns" => {
                self.routes()
            },
            _ => {
                let status = ExtensionStatus::new(1, format!("Unknown action ('{}')", action), None);
                ExtensionResponse::new(status, vec![])
            }
        }
    }

    fn columns(&self) -> Vec<ColumnDefinition>;
    fn generate(&self, query_context: Option<String>) -> ExtensionResponse;
}

#[cfg(test)]
mod tests {
    extern crate std;

    struct TestTable;
    impl ::Plugin for TestTable {
        fn name(&self) -> String {
            "test_thing123".to_string()
        }
    }

    impl ::TablePlugin for TestTable {

        fn columns(&self) -> Vec<::ColumnDefinition> {
            vec![
                ::ColumnDefinition {
                    column_name: "first_col".to_string(),
                    column_type: ::ColumnType::Integer
                },
                ::ColumnDefinition {
                    column_name: "second_col".to_string(),
                    column_type: ::ColumnType::Double
                },
            ]
        }

        fn generate(&self, query_context: Option<String>) -> ::osquery::ExtensionResponse {
            let status = ::osquery::ExtensionStatus::new(0, "OK".to_string(), None);
            let mut map1 = std::collections::BTreeMap::new();
            map1.insert("first_col".to_string(), "1234".to_string());
            map1.insert("second_col".to_string(), "789".to_string());
            let mut map2 = std::collections::BTreeMap::new();
            map2.insert("first_col".to_string(), "9876".to_string());
            map2.insert("second_col".to_string(), "54321".to_string());

            let rows = vec![
                map1,
                map2
            ];
            ::osquery::ExtensionResponse::new(status, rows)
        }
    }

    #[test]
    fn test_it() {
        use std::collections::BTreeMap;
        use ::osquery::TExtensionManagerSyncClient;
        use ::TablePlugin;

        let mut client = super::ExtensionManagerClientFactory::create_with_path("/Users/zbrown/.osquery/shell.em", None);
        let ext_info = ::osquery::InternalExtensionInfo::new("test_thing123".to_string(), None, None, None);

        let mut extension_registry: ::osquery::ExtensionRegistry = BTreeMap::new();
        let mut extension_routes: ::osquery::ExtensionRouteTable = BTreeMap::new();

        let table_plugin = TestTable {};
        extension_routes.insert("test_thing123".to_string(), table_plugin.routes().response.unwrap());
        extension_registry.insert("table".to_string(), extension_routes);

        client.register_extension(ext_info, extension_registry);
    }
}
