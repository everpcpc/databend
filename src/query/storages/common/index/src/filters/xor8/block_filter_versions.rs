// Copyright 2023 Datafuse Labs.
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
//

use std::marker::PhantomData;

use common_exception::ErrorCode;
use storages_common_table_meta::meta::testify_version;
use storages_common_table_meta::meta::Versioned;

use crate::filters::BlockFilter;

pub struct V0BloomBlock {}
pub struct V2BloomBlock {}

// deprecated, the classic bloom filter
impl Versioned<0> for V0BloomBlock {}
// deprecated, first version of xor8 bloom filter
impl Versioned<2> for V2BloomBlock {}
// current version of block filter, based on xor bloom filter and new expression framework
impl Versioned<3> for BlockFilter {}

pub enum BlockBloomFilterIndexVersion {
    V0(PhantomData<V0BloomBlock>),
    V2(PhantomData<V2BloomBlock>),
    V3(PhantomData<BlockFilter>),
}

impl TryFrom<u64> for BlockBloomFilterIndexVersion {
    type Error = ErrorCode;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Err(ErrorCode::DeprecatedIndexFormat(
                "v1 bloom filter index is deprecated",
            )),
            // version 2 and version 3 are using the same StringColumn to storage the bloom filter
            2 => Ok(BlockBloomFilterIndexVersion::V2(testify_version::<_, 2>(
                PhantomData,
            ))),
            3 => Ok(BlockBloomFilterIndexVersion::V3(testify_version::<_, 3>(
                PhantomData,
            ))),
            _ => Err(ErrorCode::Internal(format!(
                "unknown block bloom filer index version {value}, versions supported: 1"
            ))),
        }
    }
}
