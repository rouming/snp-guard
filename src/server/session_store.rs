// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use base64::Engine;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);

pub struct SessionStore {
    sessions: RwLock<HashMap<String, Instant>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Issue a new random session token valid for SESSION_TTL.
    /// Also evicts any already-expired tokens from the store.
    pub fn issue(&self) -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let mut sessions = self.sessions.write().unwrap();
        let now = Instant::now();
        sessions.retain(|_, expiry| *expiry > now);
        sessions.insert(token.clone(), now + SESSION_TTL);
        token
    }

    /// Return true if the token exists and has not yet expired.
    pub fn validate(&self, token: &str) -> bool {
        let sessions = self.sessions.read().unwrap();
        sessions
            .get(token)
            .map(|expiry| *expiry > Instant::now())
            .unwrap_or(false)
    }

    /// Remove a token immediately, invalidating the session server-side.
    pub fn revoke(&self, token: &str) {
        self.sessions.write().unwrap().remove(token);
    }
}
