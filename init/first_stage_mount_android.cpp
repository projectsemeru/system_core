//
// Copyright (C) 2025 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <android-base/strings.h>
#include <fs_mgr.h>
#include <fs_mgr_overlayfs.h>
#include <libfiemap/image_manager.h>
#include <libgsi/libgsi.h>
#include "first_stage_mount.h"
#include "snapuserd_transition.h"
#include "util.h"

namespace android {
namespace init {

using android::fiemap::IImageManager;
using android::fs_mgr::Fstab;
using android::fs_mgr::FstabEntry;

static bool GetRootEntry(FstabEntry* root_entry) {
    Fstab proc_mounts;
    if (!ReadFstabFromFile("/proc/mounts", &proc_mounts)) {
        LOG(ERROR) << "Could not read /proc/mounts and /system not in fstab, /system will not be "
                      "available for overlayfs";
        return false;
    }

    auto entry = std::find_if(proc_mounts.begin(), proc_mounts.end(), [](const auto& entry) {
        return entry.mount_point == "/" && entry.fs_type != "rootfs";
    });

    if (entry == proc_mounts.end()) {
        LOG(ERROR) << "Could not get mount point for '/' in /proc/mounts, /system will not be "
                      "available for overlayfs";
        return false;
    }

    *root_entry = std::move(*entry);

    // We don't know if we're avb or not, so we query device mapper as if we are avb.  If we get a
    // success, then mark as avb, otherwise default to verify.
    auto& dm = android::dm::DeviceMapper::Instance();
    if (dm.GetState("vroot") != android::dm::DmDeviceState::INVALID) {
        root_entry->fs_mgr_flags.avb = true;
    }
    return true;
}

bool FirstStageMount::InitDmLinearBackingDevices(const android::fs_mgr::LpMetadata& metadata) {
    std::set<std::string> devices;

    auto partition_names = android::fs_mgr::GetBlockDevicePartitionNames(metadata);
    for (const auto& partition_name : partition_names) {
        // The super partition was found in the earlier pass.
        if (partition_name == super_partition_name_) {
            continue;
        }
        devices.emplace(partition_name);
    }
    if (devices.empty()) {
        return true;
    }
    return InitRequiredDevices(std::move(devices));
}

bool FirstStageMount::CreateLogicalPartitions() {
    if (!IsDmLinearEnabled()) {
        return true;
    }
    if (super_path_.empty()) {
        LOG(ERROR) << "Could not locate logical partition tables in partition "
                   << super_partition_name_;
        return false;
    }

    if (!IsMicrodroid() && SnapshotManager::IsSnapshotManagerNeeded()) {
        auto init_devices = [this](const std::string& device) -> bool {
            if (android::base::StartsWith(device, "/dev/block/dm-")) {
                return block_dev_init_.InitDmDevice(device);
            }
            return block_dev_init_.InitDevices({device});
        };

        SnapshotManager::MapTempOtaMetadataPartitionIfNeeded(init_devices);
        auto sm = SnapshotManager::NewForFirstStageMount();
        if (!sm) {
            return false;
        }
        if (sm->NeedSnapshotsInFirstStageMount()) {
            return CreateSnapshotPartitions(sm.get());
        }
    }

    auto metadata = android::fs_mgr::ReadCurrentMetadata(super_path_);
    if (!metadata) {
        LOG(ERROR) << "Could not read logical partition metadata from " << super_path_;
        return false;
    }
    if (!InitDmLinearBackingDevices(*metadata.get())) {
        return false;
    }
    return android::fs_mgr::CreateLogicalPartitions(*metadata.get(), super_path_);
}

bool FirstStageMount::CreateSnapshotPartitions(SnapshotManager* sm) {
    // When COW images are present for snapshots, they are stored on
    // the data partition.
    if (!InitRequiredDevices({"userdata"})) {
        return false;
    }

    use_snapuserd_ = sm->IsSnapuserdRequired();
    if (use_snapuserd_) {
        bool use_ublk = sm->UpdateUsesUblk();
        LOG(INFO) << "using snapuserd in " << (use_ublk ? "UBLK" : "dm-user") << " mode";
        LaunchFirstStageSnapuserd(use_ublk);
    }

    sm->SetUeventRegenCallback([this](const std::string& device) -> bool {
        if (android::base::StartsWith(device, "/dev/block/dm-")) {
            return block_dev_init_.InitDmDevice(device);
        }
        if (android::base::StartsWith(device, "/dev/dm-user/")) {
            return block_dev_init_.InitDmUser(android::base::Basename(device));
        }
        if (android::base::StartsWith(device, "/dev/block/ublkb")) {
            return block_dev_init_.InitDmDevice(device);
        }
        if (android::base::StartsWith(device, "/dev/ublk")) {
            return block_dev_init_.InitUblkMiscDevices(android::base::Basename(device));
        }
        return block_dev_init_.InitDevices({device});
    });
    if (!sm->CreateLogicalAndSnapshotPartitions(super_path_)) {
        return false;
    }

    if (use_snapuserd_) {
        CleanupSnapuserdSocket();
    }
    return true;
}

void FirstStageMount::UseDsuIfPresent() {
    std::string error;

    if (!android::gsi::CanBootIntoGsi(&error)) {
        LOG(INFO) << "DSU " << error << ", proceeding with normal boot";
        return;
    }

    auto init_devices = [this](std::set<std::string> devices) -> bool {
        if (devices.count("userdata") == 0 || devices.size() > 1) {
            dsu_not_on_userdata_ = true;
        }
        return InitRequiredDevices(std::move(devices));
    };
    std::string active_dsu;
    if (!gsi::GetActiveDsu(&active_dsu)) {
        LOG(ERROR) << "Failed to GetActiveDsu";
        return;
    }
    LOG(INFO) << "DSU slot: " << active_dsu;
    auto images = IImageManager::Open("dsu/" + active_dsu, 0ms);
    if (!images || !images->MapAllImages(init_devices)) {
        LOG(ERROR) << "DSU partition layout could not be instantiated";
        return;
    }

    if (!android::gsi::MarkSystemAsGsi()) {
        PLOG(ERROR) << "DSU indicator file could not be written";
        return;
    }

    // Publish the logical partition names for TransformFstabForDsu() and ReadFstabFromFile().
    const auto dsu_partitions = images->GetAllBackingImages();
    WriteFile(gsi::kGsiLpNamesFile, android::base::Join(dsu_partitions, ","));
    TransformFstabForDsu(&fstab_, active_dsu, dsu_partitions);
}

void FirstStageMount::MountOverlays() {
    for (const auto& entry : fstab_) {
        if (entry.fs_type == "overlay") {
            fs_mgr_mount_overlayfs_fstab_entry(entry);
        }
    }

    // If we don't see /system or / in the fstab, then we need to create an root entry for
    // overlayfs.
    if (!GetEntryForMountPoint(&fstab_, "/system") && !GetEntryForMountPoint(&fstab_, "/")) {
        FstabEntry root_entry;
        if (GetRootEntry(&root_entry)) {
            fstab_.emplace_back(std::move(root_entry));
        }
    }

    // heads up for instantiating required device(s) for overlayfs logic
    auto init_devices = [this](std::set<std::string> devices) -> bool {
        for (auto iter = devices.begin(); iter != devices.end();) {
            if (android::base::StartsWith(*iter, "/dev/block/dm-")) {
                if (!block_dev_init_.InitDmDevice(*iter)) {
                    return false;
                }
                iter = devices.erase(iter);
            } else {
                iter++;
            }
        }
        return InitRequiredDevices(std::move(devices));
    };
    MapScratchPartitionIfNeeded(&fstab_, init_devices);

    fs_mgr_overlayfs_mount_all(&fstab_);
}

}  // namespace init
}  // namespace android
