use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct QueryRateLimiter {
    max_global_per_window: u32,
    max_per_ip_per_window: u32,
    max_tracked_ips: usize,
    window: Duration,
    state: Arc<Mutex<QueryRateState>>,
}

#[derive(Debug)]
struct QueryRateState {
    started_at: Instant,
    global_count: u32,
    per_ip_count: HashMap<IpAddr, u32>,
}

#[derive(Debug, Clone)]
pub struct InvalidQueryRateLimiter {
    max_per_key_per_window: u32,
    max_tracked_keys: usize,
    window: Duration,
    state: Arc<Mutex<InvalidQueryRateState>>,
}

#[derive(Debug)]
struct InvalidQueryRateState {
    started_at: Instant,
    per_key_count: HashMap<InvalidQueryKey, u32>,
    key_order: VecDeque<InvalidQueryKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct InvalidQueryKey {
    ip: IpAddr,
    qname: String,
}

impl QueryRateLimiter {
    pub fn new(
        max_global_per_second: u32,
        max_per_ip_per_second: u32,
        max_tracked_ips: usize,
    ) -> Self {
        Self {
            max_global_per_window: max_global_per_second,
            max_per_ip_per_window: max_per_ip_per_second,
            max_tracked_ips,
            window: Duration::from_secs(1),
            state: Arc::new(Mutex::new(QueryRateState {
                started_at: Instant::now(),
                global_count: 0,
                per_ip_count: HashMap::new(),
            })),
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if state.started_at.elapsed() >= self.window {
            state.started_at = Instant::now();
            state.global_count = 0;
            state.per_ip_count.clear();
        }

        if state.global_count >= self.max_global_per_window {
            return false;
        }

        let known_ip = state.per_ip_count.contains_key(&ip);
        if !known_ip && state.per_ip_count.len() >= self.max_tracked_ips {
            return false;
        }

        let per_ip_counter = state.per_ip_count.entry(ip).or_insert(0);
        if *per_ip_counter >= self.max_per_ip_per_window {
            return false;
        }

        *per_ip_counter += 1;
        state.global_count += 1;

        true
    }
}

impl InvalidQueryRateLimiter {
    pub fn new(max_per_key_per_second: u32, max_tracked_keys: usize) -> Self {
        Self {
            max_per_key_per_window: max_per_key_per_second,
            max_tracked_keys,
            window: Duration::from_secs(1),
            state: Arc::new(Mutex::new(InvalidQueryRateState {
                started_at: Instant::now(),
                per_key_count: HashMap::new(),
                key_order: VecDeque::new(),
            })),
        }
    }

    pub fn allow(&self, ip: IpAddr, qname: &str) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if state.started_at.elapsed() >= self.window {
            state.started_at = Instant::now();
            state.per_key_count.clear();
            state.key_order.clear();
        }

        let key = InvalidQueryKey {
            ip,
            qname: qname.to_ascii_lowercase(),
        };

        if let Some(per_key_count) = state.per_key_count.get_mut(&key) {
            if *per_key_count >= self.max_per_key_per_window {
                return false;
            }

            *per_key_count += 1;
            return true;
        }

        while state.per_key_count.len() >= self.max_tracked_keys {
            let Some(oldest_key) = state.key_order.pop_front() else {
                break;
            };
            state.per_key_count.remove(&oldest_key);
        }

        if state.per_key_count.len() >= self.max_tracked_keys {
            return false;
        }

        state.key_order.push_back(key.clone());
        state.per_key_count.insert(key, 1);
        true
    }
}

#[derive(Debug, Clone)]
pub struct TcpConnectionLimiter {
    max_connections: usize,
    max_connections_per_ip: usize,
    state: Arc<Mutex<TcpConnectionState>>,
}

#[derive(Debug)]
struct TcpConnectionState {
    active_total: usize,
    active_per_ip: HashMap<IpAddr, usize>,
}

impl TcpConnectionLimiter {
    pub fn new(max_connections: usize, max_connections_per_ip: usize) -> Self {
        Self {
            max_connections,
            max_connections_per_ip,
            state: Arc::new(Mutex::new(TcpConnectionState {
                active_total: 0,
                active_per_ip: HashMap::new(),
            })),
        }
    }

    pub fn try_acquire(&self, ip: IpAddr) -> Option<TcpConnectionPermit> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if state.active_total >= self.max_connections {
            return None;
        }

        let active_for_ip = state.active_per_ip.entry(ip).or_insert(0);
        if *active_for_ip >= self.max_connections_per_ip {
            return None;
        }

        *active_for_ip += 1;
        state.active_total += 1;

        Some(TcpConnectionPermit {
            limiter: self.clone(),
            ip,
            released: false,
        })
    }

    fn release(&self, ip: IpAddr) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(active_for_ip) = state.active_per_ip.get_mut(&ip) {
            if *active_for_ip > 1 {
                *active_for_ip -= 1;
            } else {
                state.active_per_ip.remove(&ip);
            }
        }

        if state.active_total > 0 {
            state.active_total -= 1;
        }
    }
}

#[derive(Debug)]
pub struct TcpConnectionPermit {
    limiter: TcpConnectionLimiter,
    ip: IpAddr,
    released: bool,
}

impl Drop for TcpConnectionPermit {
    fn drop(&mut self) {
        if !self.released {
            self.limiter.release(self.ip);
            self.released = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(value: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, value))
    }

    #[test]
    fn query_limiter_enforces_per_ip_limit() {
        let limiter = QueryRateLimiter::new(100, 2, 32);

        assert!(limiter.allow(ip(1)));
        assert!(limiter.allow(ip(1)));
        assert!(!limiter.allow(ip(1)));
    }

    #[test]
    fn query_limiter_enforces_global_limit() {
        let limiter = QueryRateLimiter::new(2, 10, 32);

        assert!(limiter.allow(ip(1)));
        assert!(limiter.allow(ip(2)));
        assert!(!limiter.allow(ip(3)));
    }

    #[test]
    fn query_limiter_bounds_tracked_ips() {
        let limiter = QueryRateLimiter::new(100, 10, 2);

        assert!(limiter.allow(ip(1)));
        assert!(limiter.allow(ip(2)));
        assert!(!limiter.allow(ip(3)));
    }

    #[test]
    fn invalid_query_limiter_enforces_per_key_limit() {
        let limiter = InvalidQueryRateLimiter::new(2, 32);

        assert!(limiter.allow(ip(1), "nope.dev.example.com."));
        assert!(limiter.allow(ip(1), "nope.dev.example.com."));
        assert!(!limiter.allow(ip(1), "nope.dev.example.com."));
    }

    #[test]
    fn invalid_query_limiter_tracks_per_ip_and_name() {
        let limiter = InvalidQueryRateLimiter::new(1, 32);

        assert!(limiter.allow(ip(1), "nope.dev.example.com."));
        assert!(limiter.allow(ip(2), "nope.dev.example.com."));
        assert!(limiter.allow(ip(1), "other.dev.example.com."));
        assert!(!limiter.allow(ip(1), "nope.dev.example.com."));
    }

    #[test]
    fn invalid_query_limiter_bounds_tracked_keys() {
        let limiter = InvalidQueryRateLimiter::new(1, 2);

        assert!(limiter.allow(ip(1), "a.dev.example.com."));
        assert!(limiter.allow(ip(1), "b.dev.example.com."));
        assert!(!limiter.allow(ip(1), "a.dev.example.com."));

        // Inserting a third distinct key evicts the oldest tracked key.
        assert!(limiter.allow(ip(1), "c.dev.example.com."));
        assert!(limiter.allow(ip(1), "a.dev.example.com."));
    }

    #[test]
    fn tcp_connection_limiter_enforces_per_ip_and_global_caps() {
        let limiter = TcpConnectionLimiter::new(2, 1);

        let permit1 = limiter.try_acquire(ip(1));
        assert!(permit1.is_some());
        assert!(limiter.try_acquire(ip(1)).is_none());

        let permit2 = limiter.try_acquire(ip(2));
        assert!(permit2.is_some());
        assert!(limiter.try_acquire(ip(3)).is_none());

        drop(permit1);
        assert!(limiter.try_acquire(ip(1)).is_some());
    }
}
