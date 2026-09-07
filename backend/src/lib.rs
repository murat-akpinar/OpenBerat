// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The binary is a thin wrapper around this: everything worth testing lives in
// the modules, and integration tests reach them through here.

pub mod admin;
pub mod api;
pub mod cache;
pub mod keycloak;
pub mod metrics;
pub mod policy;
pub mod session;
pub mod store;
