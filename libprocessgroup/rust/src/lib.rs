//
// Copyright (C) 2025 The Android Open-Source Project
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

//! Bindings for Android's libprocessgroup
//!
//! Mangled C++ names provided to `link_name` attributes were suggested by the
//! linker when no name was provided.  The format for functions that take no
//! parameters and return no values is:
//! `'_Z' + Min API Level + Function Name + 'v'`.

#![cfg(target_os = "android")]

use core::ffi::c_int;

/// Android scheduling policy constants
///
/// See: system/core/libprocessgroup/include/processgroup/sched_policy.h
#[repr(C)]
pub enum SchedPolicy {
    /// Default scheduling policy for non-system processes
    Default = -1,
    /// Scheduling policy for applications in the background
    Background = 0,
    /// Scheduling policy for applications in the foreground
    Foreground = 1,
    /// Scheduling policy for system services
    System = 2,
    /// Scheduling policy for audio threads belonging to applications
    AudioApp = 3,
    /// Scheduling policy for audio threads belonging to system services
    AudioSys = 4,
    /// Scheduling policy for "Top Apps"
    TopApp = 5,
    /// Scheduling policy for real-time applications
    RTApp = 6,
    /// Scheduling policy for restricted applications
    Restricted = 7,
    /// Scheduling policy for foregrounded application windows
    ForegroundWindow = 8,
}

impl SchedPolicy {
    /// Default scheduling policy for system processes
    #[allow(non_upper_case_globals)]
    pub const SystemDefault: Self = Self::Foreground;
}

// Temporarily allow dead code as the rest of the module is defined in
// following commits.
unsafe extern "C" {
    /// Check to see if cpusets have been enabled on the system
    pub safe fn cpusets_enabled() -> bool;

    /// Drop the FD cache for the cgroup path.
    #[link_name = "_Z31DropTaskProfilesResourceCachingv"]
    pub safe fn drop_task_profiles_resource_caching();

    /// Set the cpuset policy for the specified process.  A TID of 0 means
    /// that the policy will be applied to the calling thread.
    ///
    /// This function takes no pointer arguments and is thread-safe.
    pub safe fn set_cpuset_policy(tid: libc::pid_t, policy: SchedPolicy) -> c_int;

    /// Set the scheduling policy for the specified process.  A TID of 0
    /// means that the policy will be applied to the calling thread.
    ///
    /// This function takes no pointer arguments and is thread-safe.
    pub safe fn set_sched_policy(tid: libc::pid_t, policy: SchedPolicy) -> c_int;
}
