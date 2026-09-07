// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The binary is a thin wrapper around this: everything worth testing lives in
// the modules, and integration tests reach them through here.

pub mod admin;
pub mod api;
pub mod audit;
pub mod cache;
pub mod decide;
pub mod keycloak;
pub mod metrics;
pub mod nginx;
pub mod policy;
pub mod portal;
pub mod session;
pub mod store;
pub mod validate;
