// Copyright 2026, The Android Open Source Project
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

//! Parse and Fetch attestation keys data

use anyhow::Result;
use std::fs;

pub(crate) struct AttestationKey {
    pub(crate) algorithm: String,
    pub(crate) key: Vec<u8>,
    pub(crate) certs: Vec<Vec<u8>>,
}

// TODO(b/478175656): Add logic to parse attestation keys xml file
pub(crate) fn get_attestation_keys(_file: fs::File) -> Result<Vec<AttestationKey>> {
    Ok(vec![AttestationKey { algorithm: "rsa".to_string(), key: vec![], certs: vec![] }])
}
