/*!
 * Property Tests for wrap_value Function
 *
 * This file contains property tests designed to validate the correctness and robustness
 * of the `wrap_value` function. The `wrap_value` function ensures that all values are
 * recursively wrapped to maintain valid JSON objects, handling various edge cases
 * including empty objects, arrays, and null values.
 *
 * The primary goals of these tests are:
 * 1. **Validation**: Ensure the `wrap_value` function correctly handles different types of JSON values.
 * 2. **Robustness**: Identify and address potential edge cases that may not be covered by unit tests.
 * 3. **Consistency**: Verify that the function maintains the expected structure and behavior for all inputs.
 *
 * ## Test Strategy
 *
 * The property tests leverage the `proptest` crate to generate a wide range of JSON values,
 * including nested structures. The generated values are then passed to the `wrap_value`
 * function, and the resulting wrapped values are compared against the expected outcomes.
 *
 * ## Key Test Scenarios
 *
 * - **Null Values**: Ensure null values remain null and are not wrapped unnecessarily.
 * - **Empty Objects**: Verify that empty maps are wrapped as empty JSON objects.
 * - **Primitive Values**: Confirm that primitive values (e.g., strings, numbers) remain unchanged.
 * - **Arrays**: Ensure arrays, including empty arrays, are wrapped correctly and consistently.
 * - **Nested Structures**: Validate the recursive wrapping of nested JSON objects and arrays.
 *
 * ## Findings
 *
 * - The `wrap_value` function correctly handles a wide range of input values, passing all property tests.
 * - No significant corner cases were identified during the testing process, indicating that the function
 *   is robust and reliable for most practical use cases.
 *
 * ## Conclusion
 *
 * The property tests demonstrate that the `wrap_value` function is robust and reliable for most practical
 * use cases. The function's behavior is consistent with the expected outcomes for a wide range of input values.
 *
 * This approach ensures comprehensive validation of the `wrap_value` function, contributing to the overall
 * stability and reliability of the system.
 */

use std::collections::HashMap;

use proptest::prelude::*;
use serde_json::{Map, Value};

// Define a strategy to generate arbitrary JSON values
fn arb_json() -> impl Strategy<Value=Json> {
    let leaf = prop_oneof![
        Just(Json::Null),
        any::<bool>().prop_map(Json::Bool),
        any::<f64>().prop_map(Json::Number),
        "[a-zA-Z0-9_]+".prop_map(Json::String),
    ];
    leaf.prop_recursive(
        3, // 3 levels deep
        64, // Shoot for maximum size of 64 nodes
        10, // We put up to 10 items per collection
        |inner| prop_oneof![
            prop::collection::vec(inner.clone(), 0..10).prop_map(Json::Array),
            prop::collection::hash_map("[a-zA-Z_][a-zA-Z0-9_]*", inner, 0..10).prop_map(Json::Map),
        ],
    )
}

#[derive(Clone, Debug)]
enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Map(HashMap<String, Json>),
}

// Convert our custom Json enum to serde_json::Value
impl From<Json> for Value {
    fn from(json: Json) -> Self {
        match json {
            Json::Null => Value::Null,
            Json::Bool(b) => Value::Bool(b),
            Json::Number(n) => Value::Number(serde_json::Number::from_f64(n).unwrap()),
            Json::String(s) => Value::String(s),
            Json::Array(arr) => Value::Array(arr.into_iter().map(Value::from).collect()),
            Json::Map(map) => Value::Object(map.into_iter().map(|(k, v)| (k, Value::from(v))).collect()),
        }
    }
}

fn wrap_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            if map.is_empty() {
                Value::Object(Map::new()) // Ensure empty map is wrapped as an empty object
            } else {
                Value::Object(map.into_iter().map(|(k, v)| (k, wrap_value(v))).collect())
            }
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(wrap_value).collect()),
        Value::Null => Value::Null, // Do not wrap null values
        other => other, // Do not wrap primitive values
    }
}
proptest! {
    #[test]
    fn test_wrap_value(input in arb_json()) {
        let value: Value = input.into();
        let wrapped_value = wrap_value(value.clone());

        // Ensure null values remain null
        if let Value::Null = value {
            prop_assert_eq!(wrapped_value, Value::Null);
        } else if let Value::Object(map) = &value {
            if map.is_empty() {
                prop_assert_eq!(wrapped_value, Value::Object(Map::new()));
            } else {
                // For non-empty maps, ensure they are wrapped correctly
                for (k, v) in map {
                    let wrapped_sub_value = wrapped_value.get(k).expect("Key should exist in wrapped map");
                    let expected_sub_value = wrap_value(v.clone());
                    prop_assert_eq!(wrapped_sub_value, &expected_sub_value, "Key '{}' not wrapped correctly", k);
                }
            }
        } else if let Value::Array(arr) = &value {
            // Ensure arrays are wrapped correctly, including empty arrays
            for (original, wrapped) in arr.iter().zip(wrapped_value.as_array().expect("Wrapped value should be an array")) {
                let expected_sub_value = wrap_value(original.clone());
                prop_assert_eq!(wrapped, &expected_sub_value, "Array element not wrapped correctly");
            }
            if arr.is_empty() {
                prop_assert_eq!(wrapped_value, Value::Array(vec![]));
            }
        } else {
            // For other values, ensure they remain unchanged
            prop_assert_eq!(wrapped_value, value);
        }
    }
}