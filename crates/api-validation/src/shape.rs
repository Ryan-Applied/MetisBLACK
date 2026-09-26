use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::ValidationBounds;

/// A structural JSON description. It deliberately has no field capable of
/// retaining a scalar value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "shape", rename_all = "snake_case", deny_unknown_fields)]
pub enum JsonShape {
    Unknown,
    Null,
    Boolean,
    Integer,
    Number,
    String,
    Object {
        properties: BTreeMap<String, JsonShape>,
    },
    Array {
        item_shapes: Vec<JsonShape>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JsonShapeCapture {
    pub shape: JsonShape,
    pub truncated: bool,
    pub visited_nodes: u32,
}

impl JsonShapeCapture {
    pub fn from_json(value: &Value, bounds: &ValidationBounds) -> Result<Self> {
        bounds.validate()?;
        let mut state = CaptureState {
            bounds,
            nodes: 0,
            truncated: false,
        };
        let shape = state.capture(value, 0)?;
        let capture = Self {
            shape,
            truncated: state.truncated,
            visited_nodes: state.nodes,
        };
        capture.validate(bounds)?;
        Ok(capture)
    }

    pub fn validate(&self, bounds: &ValidationBounds) -> Result<()> {
        ensure!(
            self.visited_nodes > 0 && self.visited_nodes <= bounds.max_shape_nodes,
            "visited_nodes exceeds shape bounds"
        );
        let mut count = 0;
        validate_shape(&self.shape, bounds, 0, &mut count)?;
        ensure!(
            count <= self.visited_nodes,
            "shape node count exceeds visited_nodes"
        );
        Ok(())
    }
}

impl JsonShape {
    pub(crate) fn validate(&self, bounds: &ValidationBounds) -> Result<()> {
        let mut nodes = 0;
        validate_shape(self, bounds, 0, &mut nodes)
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Null => "null",
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::Number => "number",
            Self::String => "string",
            Self::Object { .. } => "object",
            Self::Array { .. } => "array",
        }
    }
}

struct CaptureState<'a> {
    bounds: &'a ValidationBounds,
    nodes: u32,
    truncated: bool,
}

impl CaptureState<'_> {
    fn capture(&mut self, value: &Value, depth: u16) -> Result<JsonShape> {
        if self.nodes >= self.bounds.max_shape_nodes || depth > self.bounds.max_shape_depth {
            self.truncated = true;
            return Ok(JsonShape::Unknown);
        }
        self.nodes += 1;
        Ok(match value {
            Value::Null => JsonShape::Null,
            Value::Bool(_) => JsonShape::Boolean,
            Value::Number(number) if number.is_i64() || number.is_u64() => JsonShape::Integer,
            Value::Number(_) => JsonShape::Number,
            Value::String(_) => JsonShape::String,
            Value::Object(object) => {
                let mut properties = BTreeMap::new();
                if depth == self.bounds.max_shape_depth {
                    if !object.is_empty() {
                        self.truncated = true;
                    }
                    return Ok(JsonShape::Object { properties });
                }
                let limit = usize::try_from(self.bounds.max_properties)?;
                if object.len() > limit {
                    self.truncated = true;
                }
                for (name, child) in object.iter().take(limit) {
                    if self.nodes >= self.bounds.max_shape_nodes {
                        self.truncated = true;
                        break;
                    }
                    properties.insert(name.clone(), self.capture(child, depth + 1)?);
                }
                JsonShape::Object { properties }
            }
            Value::Array(array) => {
                if depth == self.bounds.max_shape_depth {
                    if !array.is_empty() {
                        self.truncated = true;
                    }
                    return Ok(JsonShape::Array {
                        item_shapes: Vec::new(),
                    });
                }
                let limit = usize::try_from(self.bounds.max_array_items)?;
                if array.len() > limit {
                    self.truncated = true;
                }
                let mut item_shapes = Vec::new();
                for child in array.iter().take(limit) {
                    if self.nodes >= self.bounds.max_shape_nodes {
                        self.truncated = true;
                        break;
                    }
                    item_shapes.push(self.capture(child, depth + 1)?);
                }
                item_shapes.sort();
                item_shapes.dedup();
                JsonShape::Array { item_shapes }
            }
        })
    }
}

fn validate_shape(
    shape: &JsonShape,
    bounds: &ValidationBounds,
    depth: u16,
    nodes: &mut u32,
) -> Result<()> {
    ensure!(depth <= bounds.max_shape_depth, "shape depth exceeds bound");
    *nodes = nodes.saturating_add(1);
    ensure!(*nodes <= bounds.max_shape_nodes, "shape nodes exceed bound");
    match shape {
        JsonShape::Object { properties } => {
            ensure!(
                properties.len() <= usize::try_from(bounds.max_properties)?,
                "shape properties exceed bound"
            );
            for child in properties.values() {
                validate_shape(child, bounds, depth + 1, nodes)?;
            }
        }
        JsonShape::Array { item_shapes } => {
            ensure!(
                item_shapes.len() <= usize::try_from(bounds.max_array_items)?,
                "shape array samples exceed bound"
            );
            let mut canonical = item_shapes.clone();
            canonical.sort();
            canonical.dedup();
            ensure!(
                canonical == *item_shapes,
                "array item shapes are not canonical"
            );
            for child in item_shapes {
                validate_shape(child, bounds, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}
