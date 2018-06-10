extern crate std;

use ::Plugin;
use osquery::*;

use std::collections::BTreeMap;

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
    pub column_name: String,
    pub column_type: ColumnType,
}

pub struct TablePlugin {
    details: Box<TablePluginDetails>,
}

pub trait TablePluginDetails: Sync + Send {
    fn name(&self) -> String;
    fn columns(&self) -> Vec<ColumnDefinition>;
    fn generate(&self, query_context: Option<String>) -> ExtensionResponse;
}

impl TablePlugin {
    pub fn new(details: Box<TablePluginDetails>) -> Self {
        Self {
            details
        }
    }
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
                let constraint_ctx = if ctx.contains_key("context") {
                    Some(ctx.get("context").unwrap().to_string())
                } else {
                    None
                };

                // TODO: For now we always ignore the context constraints from the "context" property.
                self.details.generate(constraint_ctx)
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