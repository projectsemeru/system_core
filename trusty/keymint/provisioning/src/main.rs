// Copyright 2025, The Android Open Source Project
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

//! KeyMint provisioning tool

use android_trusty_provisioning::aidl::android::trusty::provisioning::IProvisioning::{
    AttestationIds::AttestationIds, IProvisioning,
};
use anyhow::{Context, Result};
use binder::{self, AccessorProvider, Strong};
use clap::{Args, Parser, Subcommand};
use log::{error, info, LevelFilter};
use rustutils::android::system_properties;

const ACCESSOR_SERVICE_NAME: &str = "android.os.IAccessor/IProvisioning/security_vm_keymint";
const INTERNAL_RPC_SERVICE_NAME: &str =
    "android.trusty.provisioning.IProvisioning/security_vm_keymint";

#[derive(Parser, Debug)]
#[clap(about = "KeyMint provisioning tool")]
struct Cli {
    #[clap(subcommand)]
    action: Action,
}

#[derive(Subcommand, Debug, Clone)]
enum Action {
    /// Provisions attestation IDs to the KeyMint.
    #[clap(visible_alias = "set-attestation-ids")]
    SetAttestationIds(AttestationIdsArgs),
}

#[derive(Args, Clone, Debug, Default)]
struct AttestationIdsArgs {
    /// Set brand.
    #[arg(long, short = 'b')]
    brand: Option<String>,

    /// Set device.
    #[arg(long, short = 'd')]
    device: Option<String>,

    /// Set product.
    #[arg(long, short = 'p')]
    product: Option<String>,

    /// Set serial.
    #[arg(long, short = 's')]
    serial: Option<String>,

    /// Set manufacturer.
    #[arg(long, short = 'M')]
    manufacturer: Option<String>,

    /// Set model.
    #[arg(long, short = 'm')]
    model: Option<String>,

    /// Set MEID.
    #[arg(long)]
    meid: Option<String>,

    /// Set IMEI (slot 0).
    #[arg(long)]
    imei: Option<String>,

    /// Set second IMEI (slot 1).
    #[arg(long)]
    imei2: Option<String>,
}

fn main() {
    if let Err(e) = try_main() {
        error!("Provisioning failed: {:?}", e);
        panic!("provisioning failed: {:?}", e)
    }
}

fn try_main() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keymint-provisioning-tool")
            .with_max_level(LevelFilter::Info)
            .with_log_buffer(android_logger::LogId::System),
    );
    let cli = Cli::parse();
    info!("Tool started. Arguments: {:?}", cli);

    let _accessor_provider = AccessorProvider::new(&[INTERNAL_RPC_SERVICE_NAME.to_owned()], |s| {
        binder::wait_for_service(ACCESSOR_SERVICE_NAME)
            .and_then(|service| binder::Accessor::from_binder(s, service))
    });
    let provisioning_service: Strong<dyn IProvisioning> =
        binder::wait_for_interface(INTERNAL_RPC_SERVICE_NAME)?;

    info!("Starting command: {:?}", cli.action);
    match &cli.action {
        Action::SetAttestationIds(args) => {
            set_attestation_ids(&provisioning_service, args.clone())?;
        }
    }
    info!("Completed command successfully: {:?}", cli.action);

    Ok(())
}

fn set_attestation_ids(
    provisioning_service: &Strong<dyn IProvisioning>,
    args: AttestationIdsArgs,
) -> Result<()> {
    let attest_ids = collect_attestation_ids(args)?;

    provisioning_service
        .provisionAttestationIds(&attest_ids)
        .context("provision Attestation IDs via RPC binder")?;
    info!("Attestation IDs provisioned successfully.");
    Ok(())
}

fn collect_attestation_ids(args: AttestationIdsArgs) -> Result<AttestationIds> {
    let attest_ids = AttestationIds {
        brand: args.brand.map_or_else(|| get_prop("ro.product.brand"), |s| Ok(s.into_bytes()))?,
        device: args
            .device
            .map_or_else(|| get_prop("ro.product.device"), |s| Ok(s.into_bytes()))?,
        product: args
            .product
            .map_or_else(|| get_prop("ro.product.name"), |s| Ok(s.into_bytes()))?,
        serial: args.serial.map_or_else(|| get_prop("ro.serialno"), |s| Ok(s.into_bytes()))?,
        manufacturer: args
            .manufacturer
            .map_or_else(|| get_prop("ro.product.manufacturer"), |s| Ok(s.into_bytes()))?,
        model: args.model.map_or_else(|| get_prop("ro.product.model"), |s| Ok(s.into_bytes()))?,
        imei: args.imei.map(|s| s.into_bytes()).unwrap_or_default(),
        imei2: args.imei2.map(|s| s.into_bytes()).unwrap_or_default(),
        meid: args.meid.map(|s| s.into_bytes()).unwrap_or_default(),
    };
    Ok(attest_ids)
}

fn get_prop(prop_name: &str) -> Result<Vec<u8>> {
    Ok(system_properties::read(prop_name)?.unwrap_or_default().into())
}
