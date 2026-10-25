//! Bound authentication state. No PINs are retained in the Node adapter between
//! requests. Tokens fence asynchronous prompts, Keychain I/O and hardware work.
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

type Reply = Result<Value, &'static str>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Request {
    operation: String,
    #[serde(default)]
    binding: Option<String>,
    #[serde(default)]
    token: Option<u64>,
    #[serde(default)]
    pin: Option<String>,
    #[serde(default)]
    persisted: bool,
    #[serde(default)]
    values: Vec<String>,
}
impl Drop for Request {
    fn drop(&mut self) {
        if let Some(pin) = &mut self.pin {
            pin.zeroize();
        }
    }
}

struct Entry {
    pin: Zeroizing<String>,
    until: Instant,
}
struct Attempt {
    binding: String,
    epoch: u64,
    created: Instant,
    pin: Option<Zeroizing<String>>,
    persisted: bool,
    attempted: bool,
    used_pin: bool,
    used_without_pin: bool,
}

// An abandoned attempt is only metadata, but 64 of them would turn every later
// `begin` into `busy` until the process restarts. The longest legitimate flow
// (120 s dialog + 15 s hardware operation) is far below this bound.
const ATTEMPT_TTL: Duration = Duration::from_secs(600);

#[derive(Default)]
pub struct Session {
    binding: Option<String>,
    epoch: u64,
    sequence: u64,
    lease: Option<Entry>,
    cached: Option<Entry>,
    persisted: bool,
    attempts: HashMap<u64, Attempt>,
}

fn valid_pin(pin: &str) -> Result<(), &'static str> {
    if pin.is_empty() || pin.len() > 64 || pin.contains(['\r', '\n', '\0']) {
        Err("invalid_pin")
    } else {
        Ok(())
    }
}

impl Session {
    pub fn close(&mut self) {
        self.invalidate();
        self.attempts.clear();
    }
    pub fn expire(&mut self, now: Instant) {
        if self.lease.as_ref().is_some_and(|e| e.until <= now) {
            self.lease = None;
        }
        if self.cached.as_ref().is_some_and(|e| e.until <= now) {
            self.cached = None;
        }
        // Dropping an attempt zeroizes any PIN it still holds.
        self.attempts
            .retain(|_, attempt| now.saturating_duration_since(attempt.created) < ATTEMPT_TTL);
    }
    fn invalidate(&mut self) {
        self.epoch += 1;
        self.binding = None;
        self.lease = None;
        self.cached = None;
        self.persisted = false;
        // Outstanding tokens remain as stale metadata so they can be finalized,
        // but their PIN buffers are erased immediately.
        for attempt in self.attempts.values_mut() {
            attempt.pin = None;
        }
    }
    fn ensure(&self, token: u64) -> Result<(), &'static str> {
        let attempt = self.attempts.get(&token).ok_or("stale")?;
        if attempt.epoch != self.epoch || self.binding.as_ref() != Some(&attempt.binding) {
            Err("stale")
        } else {
            Ok(())
        }
    }
    // Called under the session lock immediately before spawn. This also fences
    // work that was queued before a device change or an explicit forget action.
    pub fn authorize_hardware(
        &mut self,
        token: u64,
        device: Option<&str>,
        pin: Option<&str>,
    ) -> Result<(), &'static str> {
        self.ensure(token)?;
        let attempt = self.attempts.get_mut(&token).unwrap();
        if device != attempt.binding.split(':').next() {
            return Err("stale");
        }
        if let Some(pin) = pin {
            if !attempt.attempted
                || attempt.used_pin
                || attempt.pin.as_ref().map(|v| v.as_str()) != Some(pin)
            {
                return Err("stale");
            }
            attempt.used_pin = true;
        } else {
            if attempt.attempted || attempt.used_without_pin || attempt.pin.is_some() {
                return Err("stale");
            }
            attempt.used_without_pin = true;
        }
        Ok(())
    }
    pub fn handle(&mut self, mut request: Request, now: Instant) -> Reply {
        self.expire(now);
        let token = request.token.unwrap_or(0);
        match request.operation.as_str() {
            "begin" => {
                let binding = request.binding.take().ok_or("invalid_binding")?;
                if binding.is_empty() || binding.len() > 256 {
                    return Err("invalid_binding");
                }
                if self.binding.as_ref() != Some(&binding) {
                    self.invalidate();
                    self.binding = Some(binding.clone());
                }
                if self.attempts.len() >= 64 {
                    return Err("busy");
                }
                let (pin, persisted) = if let Some(pin) = request.pin.take() {
                    let pin = Zeroizing::new(pin);
                    if valid_pin(&pin).is_err() {
                        self.invalidate();
                        return Err("invalid_pin");
                    }
                    (Some(pin), false)
                } else {
                    (
                        self.lease
                            .as_ref()
                            .or(self.cached.as_ref())
                            .map(|e| e.pin.clone()),
                        self.persisted,
                    )
                };
                self.sequence += 1;
                let reply = json!({"token": self.sequence, "epoch": self.epoch,
                    "pin": pin.as_ref().map(|v| v.as_str()), "persisted": persisted && pin.is_some()});
                self.attempts.insert(
                    self.sequence,
                    Attempt {
                        binding,
                        epoch: self.epoch,
                        created: now,
                        pin,
                        persisted,
                        attempted: false,
                        used_pin: false,
                        used_without_pin: false,
                    },
                );
                Ok(reply)
            }
            "provide" => {
                self.ensure(token)?;
                let pin = Zeroizing::new(request.pin.take().ok_or("invalid_pin")?);
                valid_pin(&pin)?;
                let attempt = self.attempts.get_mut(&token).unwrap();
                attempt.pin = Some(pin);
                attempt.persisted = request.persisted;
                Ok(json!({}))
            }
            "check" => {
                self.ensure(token)?;
                Ok(json!({}))
            }
            "attempt" => {
                self.ensure(token)?;
                let attempt = self.attempts.get_mut(&token).unwrap();
                if attempt.pin.is_none() || attempt.attempted {
                    return Err("invalid_command");
                }
                attempt.attempted = true;
                Ok(json!({}))
            }
            "commit" => {
                self.ensure(token)?;
                if !self.attempts[&token].attempted || self.attempts[&token].pin.is_none() {
                    return Err("invalid_command");
                }
                let mut attempt = self.attempts.remove(&token).unwrap();
                let pin = attempt.pin.take().unwrap();
                self.cached = Some(Entry {
                    pin: pin.clone(),
                    until: now + Duration::from_secs(60),
                });
                self.lease = Some(Entry {
                    pin,
                    until: now + Duration::from_secs(300),
                });
                self.persisted = request.persisted || attempt.persisted;
                Ok(json!({}))
            }
            "finish_without_pin" => {
                self.ensure(token)?;
                self.attempts.remove(&token);
                Ok(json!({}))
            }
            "fail" => {
                let current = self.ensure(token).is_ok();
                let remove = self.attempts.remove(&token).is_some_and(|a| a.attempted);
                // A stale completion must never invalidate a newer device's lease.
                if current {
                    self.invalidate();
                }
                Ok(json!({"removeSaved": remove}))
            }
            "invalidate" => {
                self.invalidate();
                Ok(json!({}))
            }
            "clear_cached" => {
                self.cached = None;
                Ok(json!({}))
            }
            "clear_lease" => {
                self.lease = None;
                Ok(json!({}))
            }
            "status" => {
                Ok(json!({"authenticated": self.lease.is_some(), "cached": self.cached.is_some()}))
            }
            "reconcile_devices" | "reconcile_bindings" => {
                if let Some(binding) = &self.binding {
                    let expected = if request.operation == "reconcile_devices" {
                        binding.split(':').next().unwrap_or("")
                    } else {
                        binding
                    };
                    if !request.values.iter().any(|v| v == expected) {
                        self.invalidate();
                    }
                }
                Ok(json!({}))
            }
            _ => Err("invalid_command"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn send(session: &mut Session, value: Value, now: Instant) -> Reply {
        session.handle(serde_json::from_value(value).unwrap(), now)
    }
    fn begin(session: &mut Session, binding: &str, pin: Option<&str>, now: Instant) -> Value {
        send(
            session,
            json!({"operation":"begin", "binding":binding, "pin":pin}),
            now,
        )
        .unwrap()
    }
    fn commit(session: &mut Session, token: &Value, now: Instant) {
        send(session, json!({"operation":"attempt","token":token}), now).unwrap();
        send(
            session,
            json!({"operation":"commit","token":token,"persisted":true}),
            now,
        )
        .unwrap();
    }
    #[test]
    fn only_verified_commit_creates_a_lease() {
        let now = Instant::now();
        let mut s = Session::default();
        let a = begin(&mut s, "a1:certs", Some("test-pin"), now);
        assert!(s.lease.is_none());
        assert!(
            send(
                &mut s,
                json!({"operation":"commit","token":a["token"]}),
                now
            )
            .is_err()
        );
        commit(&mut s, &a["token"], now);
        let a = begin(&mut s, "a1:certs", None, now);
        assert_eq!(a["pin"], "test-pin");
        assert_eq!(a["persisted"], true);
    }
    #[test]
    fn clear_cache_preserves_lease_and_expiry_erases_idle_buffers() {
        let now = Instant::now();
        let mut s = Session::default();
        let a = begin(&mut s, "a1:certs", Some("test-pin"), now);
        commit(&mut s, &a["token"], now);
        send(&mut s, json!({"operation":"clear_cached"}), now).unwrap();
        assert!(s.cached.is_none());
        assert!(s.lease.is_some());
        s.expire(now + Duration::from_secs(300));
        assert!(s.lease.is_none());
        assert!(begin(&mut s, "a1:certs", None, now + Duration::from_secs(301))["pin"].is_null());
    }
    #[test]
    fn replug_certificate_change_and_failed_observation_revoke_credentials() {
        for command in [
            json!({"operation":"reconcile_devices","values":["a2"]}),
            json!({"operation":"reconcile_bindings","values":["a1:new-certs"]}),
            json!({"operation":"invalidate"}),
        ] {
            let now = Instant::now();
            let mut s = Session::default();
            let a = begin(&mut s, "a1:certs", Some("test-pin"), now);
            commit(&mut s, &a["token"], now);
            let pending = begin(&mut s, "a1:certs", None, now);
            send(&mut s, command, now).unwrap();
            assert!(s.lease.is_none());
            assert!(s.attempts.values().all(|a| a.pin.is_none()));
            assert_eq!(
                send(
                    &mut s,
                    json!({"operation":"check","token":pending["token"]}),
                    now
                ),
                Err("stale")
            );
        }
    }
    #[test]
    fn stale_completion_cannot_restore_or_revoke_new_device_session() {
        let now = Instant::now();
        let mut s = Session::default();
        let a = begin(&mut s, "a1:certs", Some("old-pin"), now);
        send(
            &mut s,
            json!({"operation":"attempt","token":a["token"]}),
            now,
        )
        .unwrap();
        let b = begin(&mut s, "b1:certs", Some("new-pin"), now);
        commit(&mut s, &b["token"], now);
        assert_eq!(
            send(
                &mut s,
                json!({"operation":"commit","token":a["token"]}),
                now
            ),
            Err("stale")
        );
        send(&mut s, json!({"operation":"fail","token":a["token"]}), now).unwrap();
        assert_eq!(begin(&mut s, "b1:certs", None, now)["pin"], "new-pin");
    }
    #[test]
    fn rejected_pin_is_removed_once_and_cannot_retry_same_token() {
        let now = Instant::now();
        let mut s = Session::default();
        let a = begin(&mut s, "a1:certs", Some("bad-pin"), now);
        send(
            &mut s,
            json!({"operation":"attempt","token":a["token"]}),
            now,
        )
        .unwrap();
        assert_eq!(
            send(
                &mut s,
                json!({"operation":"attempt","token":a["token"]}),
                now
            ),
            Err("invalid_command")
        );
        assert_eq!(
            send(&mut s, json!({"operation":"fail","token":a["token"]}), now).unwrap()["removeSaved"],
            true
        );
        assert_eq!(
            send(&mut s, json!({"operation":"fail","token":a["token"]}), now).unwrap()["removeSaved"],
            false
        );
        assert!(begin(&mut s, "a1:certs", None, now)["pin"].is_null());
    }
    #[test]
    fn no_pin_success_and_invalid_pins_never_create_lease() {
        let now = Instant::now();
        let mut s = Session::default();
        let a = begin(&mut s, "a1:certs", None, now);
        send(
            &mut s,
            json!({"operation":"finish_without_pin","token":a["token"]}),
            now,
        )
        .unwrap();
        assert!(s.lease.is_none());
        assert!(s.attempts.is_empty());
        for pin in ["", "bad\npin", "bad\0pin", &"证".repeat(22)] {
            assert_eq!(
                send(
                    &mut s,
                    json!({"operation":"begin","binding":"a1:certs","pin":pin}),
                    now
                ),
                Err("invalid_pin")
            );
        }
    }

    #[test]
    fn hardware_authorization_is_bound_and_single_use() {
        let now = Instant::now();
        let mut s = Session::default();
        let a = begin(&mut s, "a1:certs", Some("test-pin"), now);
        let token = a["token"].as_u64().unwrap();
        send(&mut s, json!({"operation":"attempt","token":token}), now).unwrap();
        assert_eq!(
            s.authorize_hardware(token, Some("b1"), Some("test-pin")),
            Err("stale")
        );
        assert_eq!(
            s.authorize_hardware(token, Some("a1"), Some("different-pin")),
            Err("stale")
        );
        assert!(
            s.authorize_hardware(token, Some("a1"), Some("test-pin"))
                .is_ok()
        );
        assert_eq!(
            s.authorize_hardware(token, Some("a1"), Some("test-pin")),
            Err("stale")
        );
    }

    #[test]
    fn pin_free_attempt_allows_exactly_one_pin_fallback() {
        let now = Instant::now();
        let mut s = Session::default();
        let a = begin(&mut s, "a1:certs", None, now);
        let token = a["token"].as_u64().unwrap();
        assert!(s.authorize_hardware(token, Some("a1"), None).is_ok());
        assert_eq!(s.authorize_hardware(token, Some("a1"), None), Err("stale"));
        send(
            &mut s,
            json!({"operation":"provide","token":token,"pin":"test-pin"}),
            now,
        )
        .unwrap();
        send(&mut s, json!({"operation":"attempt","token":token}), now).unwrap();
        assert!(
            s.authorize_hardware(token, Some("a1"), Some("test-pin"))
                .is_ok()
        );
        s.invalidate();
        assert_eq!(
            s.authorize_hardware(token, Some("a1"), Some("test-pin")),
            Err("stale")
        );
    }

    #[test]
    fn abandoned_attempts_expire_instead_of_blocking_forever() {
        let now = Instant::now();
        let mut s = Session::default();
        for _ in 0..64 {
            begin(&mut s, "a1:certs", Some("test-pin"), now);
        }
        assert_eq!(
            send(
                &mut s,
                json!({"operation":"begin","binding":"a1:certs"}),
                now
            ),
            Err("busy")
        );
        // One second short of the bound: still counted.
        s.expire(now + ATTEMPT_TTL - Duration::from_secs(1));
        assert_eq!(s.attempts.len(), 64);
        s.expire(now + ATTEMPT_TTL);
        assert!(s.attempts.is_empty());
        let next = begin(&mut s, "a1:certs", None, now + ATTEMPT_TTL);
        assert!(next["pin"].is_null());
    }

    #[test]
    fn unfinished_requests_are_bounded_and_close_erases_all_state() {
        let now = Instant::now();
        let mut s = Session::default();
        for _ in 0..64 {
            begin(&mut s, "a1:certs", Some("test-pin"), now);
        }
        assert_eq!(
            send(
                &mut s,
                json!({"operation":"begin","binding":"a1:certs"}),
                now
            ),
            Err("busy")
        );
        s.close();
        assert!(s.attempts.is_empty());
        assert!(s.binding.is_none());
        assert!(s.lease.is_none());
        assert!(s.cached.is_none());
        assert!(begin(&mut s, "a1:certs", None, now)["pin"].is_null());
    }
}
