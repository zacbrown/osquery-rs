extern crate ordered_float;
extern crate thrift;
extern crate threadpool;
extern crate try_from;
extern crate uuid;

#[cfg(target_family = "unix")]
extern crate unix_socket;

#[macro_use]
mod macros {
    #[macro_export]
    macro_rules! debug_println {
        () => (if cfg!(debug_assertions) { print!("\n") });
        ($fmt:expr) => (if cfg!(debug_assertions) { print!(concat!($fmt, "\n")) });
        ($fmt:expr, $($arg:tt)*) => (if cfg!(debug_assertions) { print!(concat!($fmt, "\n"), $($arg)*) });
    }
}

// Auto-generated bindings from Thrift.
pub mod osquery;
use osquery::*;

pub mod stop_signal;
use stop_signal::*;

mod local_server;
use local_server::*;

pub mod config_plugin;
pub use self::config_plugin::*;

pub mod logger_plugin;
pub use self::logger_plugin::*;

pub mod table_plugin;
pub use self::table_plugin::*;

use std::collections::BTreeMap;
use std::sync::{
    Arc,
    Mutex,
};

use thrift::protocol::{
    TBinaryInputProtocol,
    TBinaryInputProtocolFactory,
    TBinaryOutputProtocol,
    TBinaryOutputProtocolFactory,
};
use thrift::transport::{
    TBufferedReadTransport,
    TBufferedReadTransportFactory,
    TBufferedWriteTransport,
    TBufferedWriteTransportFactory,
};

#[cfg(target_family = "unix")]
pub mod sys {
    extern crate unix_socket;

    pub const DEFAULT_PIPE_PATH: &'static str ="/var/osquery/osquery.em";
    pub type TChannel = unix_socket::UnixStream;
    pub type TListener = unix_socket::UnixListener;
}

#[cfg(target_os = "windows")]
pub mod sys {
    extern crate named_pipe;

    pub const DEFAULT_PIPE_PATH: &'static str = r#"\\.\pipe\osquery.em"#;
    // pub type TChannel = ...
}

type ProtocolIn = TBinaryInputProtocol<TBufferedReadTransport<sys::TChannel>>;
type ProtocolOut = TBinaryOutputProtocol<TBufferedWriteTransport<sys::TChannel>>;

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

type InternalExtensionPluginRegistry = BTreeMap<String, BTreeMap<String, Box<dyn Plugin>>>;

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

    pub fn register_plugin(&mut self, plugin: Box<dyn Plugin>) {
        if self.registry.contains_key(&plugin.registry_name()) == false {
            panic!("Unsupported plugin type '{}'", plugin.registry_name());
        }

        let plugin_specific_registry = self.registry.get_mut(&plugin.registry_name()).unwrap();
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
        debug_println!("Generated Registry:\n{:#?}", registry);
        registry
    }

    pub fn run(self) {
        let registry = self.generate_registry();
        let info = InternalExtensionInfo::new(self.extension_name, None, None, None);

        let mut reg_client = ExtensionManagerClient::new_with_path(&self.listen_path, None);
        let uuid = match reg_client.register_extension(info, registry) {
            Ok(response) => {
                response.uuid
            }
            Err(e) => {
                debug_println!("Error encountered while registering extension: {:?}", e);
                None
            }
        };

        let handler = ExtensionClientHandler::new(self.registry);
        let processor = ExtensionSyncProcessor::new(handler);
        let listen_path = format!("{}.{}", self.listen_path, uuid.unwrap());
        let out_transport_factory = TBufferedWriteTransportFactory::new();
        let out_protocol_factory = TBinaryOutputProtocolFactory::new();
        let in_transport_factory = TBufferedReadTransportFactory::new();
        let in_protocol_factory = TBinaryInputProtocolFactory::new();
        let mut server = LocalServer::new(
            in_transport_factory,
            in_protocol_factory,
            out_transport_factory,
            out_protocol_factory,
            processor,
            3
        );

        let done = StopSignal::new();
        let watcher_done = done.clone();
        let watcher_listen_path = self.listen_path.clone();
        let default_duration = std::time::Duration::from_millis(500);
        std::thread::spawn(move || {
            let mut client = ExtensionManagerClient::new_with_path(&watcher_listen_path, None);

            loop {
                match client.ping() {
                    Ok(_) => {},
                    Err(_) => {
                        watcher_done.done();
                        break
                    }
                }

                std::thread::sleep(default_duration.clone());
            }
        });

        println!("Starting extension, listening on: {}", listen_path);
        match server.listen(&listen_path, done) {
            Ok(_) => {},
            Err(e) => {
                println!("Extension failed to start with error: {}", e);
                println!("{:#?}", e);
            }
        }
    }
}

pub trait Plugin: Sync + Send {
    fn name(&self) -> String;
    fn registry_name(&self) -> String;
    fn call(&self, ctx: ExtensionPluginRequest) -> ExtensionResponse;
    fn routes(&self) -> ExtensionResponse;
}

#[cfg(test)]
mod tests {
    extern crate std;

    struct TestTableDetails;

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

    struct TestLoggerDetails;

    impl ::LoggerPluginDetails for TestLoggerDetails {
        fn name(&self) -> String {
            "big_dumb_logger".to_string()
        }

        fn log_string(&self, msg: &str) -> ::osquery::ExtensionStatus {
            println!("LOG_STRING: {}", msg);
            ::osquery::ExtensionStatus::new(0, "OK".to_string(), None)
        }

        fn log_health(&self, msg: &str) -> ::osquery::ExtensionStatus {
            println!("LOG_HEALTH: {}", msg);
            ::osquery::ExtensionStatus::new(0, "OK".to_string(), None)

        }

        fn log_snapshot(&self, msg: &str) -> ::osquery::ExtensionStatus {
            println!("LOG_SNAPSHOT: {}", msg);
            ::osquery::ExtensionStatus::new(0, "OK".to_string(), None)
        }
    }

    //#[test]
    fn test_table() {
        use std::collections::BTreeMap;
        use ::osquery::TExtensionManagerSyncClient;
        use ::TablePlugin;
        use ::Plugin;

        let table_plugin = Box::new(::TablePlugin::new(Box::new(TestTableDetails {})));

        let mut extension_server = ::ExtensionManagerServer::new_with_path("test_thing123", "/Users/zbrown/.osquery/shell.em");
        extension_server.register_plugin(table_plugin);
        extension_server.run();
    }

    #[test]
    fn test_logger() {
        use std::collections::BTreeMap;
        use ::osquery::TExtensionManagerSyncClient;
        use ::LoggerPlugin;
        use ::Plugin;

        let logger_plugin = Box::new(::LoggerPlugin::new(Box::new(TestLoggerDetails {})));

        let mut extension_server = ::ExtensionManagerServer::new_with_path("test_thing123", "/Users/zbrown/.osquery/shell.em");
        extension_server.register_plugin(logger_plugin);
        extension_server.run();
    }
}
