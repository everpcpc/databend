// Copyright 2021 Datafuse Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(clippy::arc_with_non_send_sync)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::type_complexity)]
#![allow(internal_features)]
#![feature(core_intrinsics)]
#![feature(box_patterns)]
#![feature(type_ascription)]
#![feature(try_blocks)]
#![feature(downcast_unchecked)]
#![feature(str_internals)]

use aggregates::AggregateFunctionFactory;
use ctor::ctor;
use databend_common_expression::FunctionRegistry;

pub mod aggregates;
mod cast_rules;
pub mod scalars;
pub mod srfs;

pub fn is_builtin_function(name: &str) -> bool {
    BUILTIN_FUNCTIONS.contains(name)
        || AggregateFunctionFactory::instance().contains(name)
        || GENERAL_WINDOW_FUNCTIONS.contains(&name)
        || GENERAL_LAMBDA_FUNCTIONS.contains(&name)
        || GENERAL_SEARCH_FUNCTIONS.contains(&name)
        || ASYNC_FUNCTIONS.contains(&name)
}

// The plan of search function, async function and udf contains some arguments defined in meta,
// which may be modified by user at any time. Those functions are not not suitable for caching.
pub fn is_cacheable_function(name: &str) -> bool {
    BUILTIN_FUNCTIONS.contains(name)
        || AggregateFunctionFactory::instance().contains(name)
        || GENERAL_WINDOW_FUNCTIONS.contains(&name)
        || GENERAL_LAMBDA_FUNCTIONS.contains(&name)
}

#[ctor]
pub static BUILTIN_FUNCTIONS: FunctionRegistry = builtin_functions();

pub const ASYNC_FUNCTIONS: [&str; 2] = ["nextval", "dict_get"];

pub const GENERAL_WINDOW_FUNCTIONS: [&str; 13] = [
    "row_number",
    "rank",
    "dense_rank",
    "percent_rank",
    "lag",
    "lead",
    "first_value",
    "first",
    "last_value",
    "last",
    "nth_value",
    "ntile",
    "cume_dist",
];

pub const RANK_WINDOW_FUNCTIONS: [&str; 5] =
    ["first_value", "first", "last_value", "last", "nth_value"];

pub const GENERAL_LAMBDA_FUNCTIONS: [&str; 16] = [
    "array_transform",
    "array_apply",
    "array_map",
    "array_filter",
    "array_reduce",
    "json_array_transform",
    "json_array_apply",
    "json_array_map",
    "json_array_filter",
    "json_array_reduce",
    "map_filter",
    "map_transform_keys",
    "map_transform_values",
    "json_map_filter",
    "json_map_transform_keys",
    "json_map_transform_values",
];

pub const GENERAL_SEARCH_FUNCTIONS: [&str; 3] = ["match", "query", "score"];

fn builtin_functions() -> FunctionRegistry {
    let mut registry = FunctionRegistry::empty();

    cast_rules::register(&mut registry);
    scalars::register(&mut registry);
    srfs::register(&mut registry);

    registry
}
