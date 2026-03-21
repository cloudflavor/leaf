use std::collections::HashMap;
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
