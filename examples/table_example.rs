extern crate osquery_rs;

use std::fs::OpenOptions;
use std::io::prelude::*;

use osquery_rs::table_plugin::*;
use osquery_rs::osquery::{ExtensionResponse, ExtensionStatus};
use std::collections::BTreeMap;


struct TableDetails {
}

impl osquery_rs::TablePluginDetails for TableDetails {
    fn name(&self) -> String {
        "rust_table".to_owned()
    }

    fn columns(&self) -> Vec<ColumnDefinition> {
        return vec![ColumnDefinition {
            column_name: "c1".to_string(),
            column_type: ColumnType::Text,
        }];
    }

    fn generate(&self, context: Option<String>) -> ExtensionResponse {
        let status = ExtensionStatus::new(0, "OK".to_string(), None);
        let mut rows = vec![];

        let mut map = BTreeMap::new();
        map.insert("c1".to_string(), "test_data".to_string());
        rows.push(map);
        ExtensionResponse::new(status, rows)        
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    println!("{:#?}", args);

    std::thread::sleep_ms(1500);

    let table_plugin = Box::new(osquery_rs::TablePlugin::new(Box::new(TableDetails {})));

    // For Testing
    let mut extension_server = osquery_rs::ExtensionManagerServer::new_with_path("rust_event_tables", "/Users/mgrenier/shell.em");
    
    // For production
    //let mut extension_server = osquery_rs::ExtensionManagerServer::new("rust_event_tables");
    extension_server.register_plugin(table_plugin);
    extension_server.run();
}
