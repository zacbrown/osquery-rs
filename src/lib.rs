extern crate ordered_float;
extern crate thrift;
extern crate try_from;
extern crate uuid;

#[cfg(target_family = "unix")]
extern crate unix_socket;

// Auto-generated bindings from Thrift.
pub mod osquery;

use std::collections::BTreeMap;
use std::sync::{
    Arc,
    Mutex,
    MutexGuard
};

use thrift::protocol::{
    TBinaryInputProtocol,
    TBinaryInputProtocolFactory,
    TBinaryOutputProtocol,
    TBinaryOutputProtocolFactory,};
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
pub struct ExtensionManagerClient {
    client: osquery::ExtensionManagerSyncClient<ProtocolIn, ProtocolOut>
}

impl ExtensionManagerClient {
    pub fn new(uuid: Option<i64>) -> Self {
        Self::new_with_path(sys::DEFAULT_PIPE_PATH, uuid)
    }

    pub fn new_with_path(path: &str, uuid: Option<i64>) -> Self {
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

            let client = osquery::ExtensionManagerSyncClient::new(protocol_in, protocol_out);

            Self {
                client
            }
        } else {
            panic!("Unsupported platform.");
        }
    }

    pub fn call(&mut self, registry: String, item: String, request: ExtensionPluginRequest) -> thrift::Result<ExtensionResponse> {
        self.client.call(registry, item, request)
    }

    pub fn ping(&mut self) -> thrift::Result<ExtensionStatus> {
        self.client.ping()
    }

    pub fn shutdown(&mut self) -> thrift::Result<()> {
        self.client.shutdown()
    }

    pub fn extensions(&mut self) -> thrift::Result<InternalExtensionList> {
        self.client.extensions()
    }

    pub fn options(&mut self) -> thrift::Result<InternalOptionList> {
        self.client.options()
    }

    pub fn register_extension(&mut self, info: InternalExtensionInfo, registry: ExtensionRegistry) -> thrift::Result<ExtensionStatus> {
        self.client.register_extension(info, registry)
    }

    pub fn deregister_extension(&mut self, uuid: ExtensionRouteUUID) -> thrift::Result<ExtensionStatus> {
        self.client.deregister_extension(uuid)
    }

    pub fn query(&mut self, sql: String) -> thrift::Result<ExtensionResponse> {
        self.client.query(sql)
    }

    pub fn get_query_columns(&mut self, sql: String) -> thrift::Result<ExtensionResponse> {
        self.client.get_query_columns(sql)
    }
}

type InternalExtensionPluginRegistry = BTreeMap<String, BTreeMap<String, Box<Plugin>>>;

pub struct ExtensionClientHandler {
    registry: Arc<Mutex<InternalExtensionPluginRegistry>>,
}

impl ExtensionClientHandler {
    pub fn new(registry: InternalExtensionPluginRegistry) -> Self {
        let registry = Arc::new(Mutex::new(registry));
        Self {
            registry
        }
    }
}

impl ExtensionSyncHandler for ExtensionClientHandler {
    fn handle_ping(&self) -> thrift::Result<ExtensionStatus> {
        Ok(ExtensionStatus::new(0, "OK".to_string(), None))
    }

    fn handle_call(&self, registry: String, item: String, request: ExtensionPluginRequest) -> thrift::Result<ExtensionResponse> {
        let mut reg = self.registry.lock().unwrap();
        if (*reg).contains_key(&registry) == false {
            let kind = thrift::ApplicationErrorKind::InvalidMessageType;
            let app_err = thrift::ApplicationError::new(kind, format!("Unknown registry: {}", registry));
            return Err(thrift::Error::Application(app_err))
        }

        let sub_registry = (*reg).get_mut(&registry).unwrap();

        if sub_registry.contains_key(&item) == false {
            let kind = thrift::ApplicationErrorKind::InvalidMessageType;
            let app_err = thrift::ApplicationError::new(kind, format!("Unknown plugin ({}) requested from registry ({})", item, registry));
            return Err(thrift::Error::Application(app_err))
        }

        let plugin = sub_registry.get_mut(&item).unwrap();
        Ok(plugin.call(request))
    }

    fn handle_shutdown(&self) -> thrift::Result<()> {
        Ok(())
    }
}

pub struct ExtensionManagerServer {
    extension_name: String,
    listen_path: String,
    registry: InternalExtensionPluginRegistry
}

impl ExtensionManagerServer {
    pub fn new(name: &str) -> Self {
        let extension_name = name.to_string();
        let listen_path = sys::DEFAULT_PIPE_PATH.to_string();
        let registry = Self::create_blank_registry();
        Self {
            extension_name,
            listen_path,
            registry,
        }
    }

    pub fn new_with_path(name: &str, path: &str) -> Self {
        let extension_name = name.to_string();
        let listen_path = path.to_string();
        let registry = Self::create_blank_registry();
        Self {
            extension_name,
            listen_path,
            registry,
        }
    }

    fn create_blank_registry() -> InternalExtensionPluginRegistry {
        let mut registry = BTreeMap::new();
        let supported_plugin_types = vec![
            "config".to_string(),
            "logger".to_string(),
            "table".to_string(),
        ];

        for p in supported_plugin_types {
            registry.insert(p, BTreeMap::new());
        }

        registry
    }

    pub fn register_plugin(&mut self, plugin: Box<Plugin>) {
        if self.registry.contains_key(&plugin.registry_name()) == false {
            panic!("Unsupported plugin type '{}'", plugin.registry_name());
        }

        let mut plugin_specific_registry = self.registry.get_mut(&plugin.registry_name()).unwrap();
        plugin_specific_registry.insert(plugin.name(), plugin);
    }

    fn generate_registry(&self) -> osquery::ExtensionRegistry {
        let mut registry = BTreeMap::new();
        for (plugin_type, plugins) in &self.registry {
            let mut plugin_mapping = BTreeMap::new();
            for (plugin_name, plugin) in plugins {
                plugin_mapping.insert(plugin_name.clone(), plugin.routes().response.unwrap());
            }

            registry.insert(plugin_type.clone(), plugin_mapping);
        }

        registry
    }

    pub fn run(self) {
        let registry = self.generate_registry();
        let info = InternalExtensionInfo::new(self.extension_name, None, None, None);

        let mut reg_client = ExtensionManagerClient::new_with_path(&self.listen_path, None);
        let uuid = match reg_client.register_extension(info, registry) {
            Ok(response) => {
                println!("{:#?}", response);
                response.uuid
            }
            Err(e) => {
                println!("{:#?}", e);
                panic!("blah");
            }
        };

        let handler = ExtensionClientHandler::new(self.registry);
        let processor = ExtensionSyncProcessor::new(handler);
        let listen_path = format!("{}.{}", self.listen_path, uuid.unwrap());
        let out_transport_factory = TBufferedWriteTransportFactory::new();
        let out_protocol_factory = TBinaryOutputProtocolFactory::new();
        let in_transport_factory = TBufferedReadTransportFactory::new();
        let in_protocol_factory = TBinaryInputProtocolFactory::new();
        let mut server = thrift::server::TServer::new(
            in_transport_factory,
            in_protocol_factory,
            out_transport_factory,
            out_protocol_factory,
            processor,
            3
        );

        println!("listen path: {}", listen_path);
        server.listen(&listen_path).unwrap();
        std::thread::sleep_ms(5000);
    }
}

pub trait Plugin: Sync + Send {
    fn name(&self) -> String;
    fn registry_name(&self) -> String;
    fn call(&self, ctx: ExtensionPluginRequest) -> ExtensionResponse;
    fn routes(&self) -> ExtensionResponse;
}

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

pub struct TablePlugin {
    details: Box<TablePluginDetails>,
}

pub trait TablePluginDetails: Sync + Send {
    fn name(&self) -> String;
    fn columns(&self) -> Vec<ColumnDefinition>;
    fn generate(&self, query_context: Option<String>) -> ExtensionResponse;
}

impl Plugin for TablePlugin {
    fn name(&self) -> String {
        self.details.name()
    }

    fn registry_name(&self) -> String {
        "table".to_string()
    }

    fn routes(&self) -> ExtensionResponse {
        let status = ExtensionStatus::new(0, "OK".to_string(), None);
        let mut routes = vec![];

        for column in self.details.columns() {
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
                self.details.generate(None)
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
}

#[cfg(test)]
mod tests {
    extern crate std;

    struct TestTableDetails;
    use ::Plugin;
    use ::TablePluginDetails;

    impl ::TablePluginDetails for TestTableDetails {
        fn name(&self) -> String {
            "test_thing123".to_string()
        }

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
        use ::Plugin;

        let table_plugin = Box::new(::TablePlugin { details: Box::new(TestTableDetails {}) });

        let mut extension_server = ::ExtensionManagerServer::new_with_path("test_thing123", "/Users/zbrown/.osquery/shell.em");
        extension_server.register_plugin(table_plugin);
        extension_server.run();
        //std::thread::sleep_ms(5000);
    }
}
