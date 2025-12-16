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
    /// Fetch attestation IDs from the KeyMint.
    #[clap(visible_alias = "get-attestation-ids")]
    GetAttestationIds,

    /// Provisions attestation IDs to the KeyMint.
    #[clap(visible_alias = "set-attestation-ids")]
    SetAttestationIds(Box<AttestationIdsArgs>),
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
        Action::GetAttestationIds => {
            get_attestation_ids(&provisioning_service)?;
        }
        Action::SetAttestationIds(args) => {
            set_attestation_ids(&provisioning_service, args)?;
        }
    }
    info!("Completed command successfully: {:?}", cli.action);

    Ok(())
}

fn set_attestation_ids(
    provisioning_service: &Strong<dyn IProvisioning>,
    args: &AttestationIdsArgs,
) -> Result<()> {
    let attest_ids = collect_attestation_ids(args)?;

    provisioning_service
        .provisionAttestationIds(&attest_ids)
        .context("provision Attestation IDs via RPC binder")?;
    info!("Attestation IDs provisioned successfully.");
    Ok(())
}

fn get_attestation_ids(provisioning_service: &Strong<dyn IProvisioning>) -> Result<()> {
    let attest_ids: AttestationIds =
        provisioning_service.getAttestationIds().context("get attestation IDs via RPC binder")?;
    info!("Fetched Attestation IDs.");
    print_attestation_ids(&attest_ids);
    Ok(())
}

fn print_attestation_ids(ids: &AttestationIds) {
    println!("AttestationIds {{");
    println!("  brand: {:?}", ids.brand);
    println!("  device: {:?}", ids.device);
    println!("  product: {:?}", ids.product);
    println!("  serial: {:?}", ids.serial);
    println!("  imei: {:?}", ids.imei);
    println!("  imei2: {:?}", ids.imei2);
    println!("  meid:  {:?}", ids.meid);
    println!("  manufacturer: {:?}", ids.manufacturer);
    println!("  model: {:?}", ids.model);
    println!("}}");
}

fn collect_attestation_ids(args: &AttestationIdsArgs) -> Result<AttestationIds> {
    // Use CLI arg if present, otherwise fallback to system property
    let arg_or_prop = |arg: &Option<String>, prop: &str| -> Result<Vec<u8>> {
        match arg {
            Some(s) => Ok(s.as_bytes().to_vec()),
            None => get_prop(prop),
        }
    };

    // Use CLI arg if present, otherwise default to empty
    let arg_or_default = |arg: &Option<String>| -> Vec<u8> {
        arg.as_ref().map(|s| s.as_bytes().to_vec()).unwrap_or_default()
    };

    Ok(AttestationIds {
        brand: arg_or_prop(&args.brand, "ro.product.brand")?,
        device: arg_or_prop(&args.device, "ro.product.device")?,
        product: arg_or_prop(&args.product, "ro.product.name")?,
        serial: arg_or_prop(&args.serial, "ro.serialno")?,
        manufacturer: arg_or_prop(&args.manufacturer, "ro.product.manufacturer")?,
        model: arg_or_prop(&args.model, "ro.product.model")?,
        imei: arg_or_default(&args.imei),
        imei2: arg_or_default(&args.imei2),
        meid: arg_or_default(&args.meid),
    })
}

fn get_prop(prop_name: &str) -> Result<Vec<u8>> {
    Ok(system_properties::read(prop_name)?.unwrap_or_default().into())
}
