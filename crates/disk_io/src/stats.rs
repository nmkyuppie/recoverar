use std::time::Instant;

/// Real-time I/O and recovery metrics.
#[derive(Debug, Clone)]
pub struct RecoveryStats {
    pub start_time: Instant,
    pub total_sectors: u64,
    pub sector_size: u32,
    pub rescued_sectors: u64,
    pub bad_sectors: u64,
    pub non_tried_sectors: u64,
    pub last_speed_check: Instant,
    pub last_rescued_bytes: u64,
    pub current_throughput_mb_s: f64,
}

impl RecoveryStats {
    pub fn new(total_sectors: u64, sector_size: u32) -> Self {
        let now = Instant::now();
        Self {
            start_time: now,
            total_sectors,
            sector_size,
            rescued_sectors: 0,
            bad_sectors: 0,
            non_tried_sectors: total_sectors,
            last_speed_check: now,
            last_rescued_bytes: 0,
            current_throughput_mb_s: 0.0,
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_sectors * self.sector_size as u64
    }

    pub fn rescued_bytes(&self) -> u64 {
        self.rescued_sectors * self.sector_size as u64
    }

    pub fn bad_bytes(&self) -> u64 {
        self.bad_sectors * self.sector_size as u64
    }

    pub fn record_good_sectors(&mut self, count: u64) {
        self.rescued_sectors += count;
        self.non_tried_sectors = self.non_tried_sectors.saturating_sub(count);
        self.update_speed();
    }

    pub fn record_bad_sectors(&mut self, count: u64) {
        self.bad_sectors += count;
        self.non_tried_sectors = self.non_tried_sectors.saturating_sub(count);
        self.update_speed();
    }

    fn update_speed(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_speed_check).as_secs_f64();
        if elapsed >= 0.5 {
            let current_bytes = self.rescued_bytes();
            let delta = current_bytes.saturating_sub(self.last_rescued_bytes);
            self.current_throughput_mb_s = (delta as f64 / (1024.0 * 1024.0)) / elapsed;
            self.last_speed_check = now;
            self.last_rescued_bytes = current_bytes;
        }
    }

    pub fn average_speed_mb_s(&self) -> f64 {
        let total_secs = self.start_time.elapsed().as_secs_f64();
        if total_secs > 0.0 {
            (self.rescued_bytes() as f64 / (1024.0 * 1024.0)) / total_secs
        } else {
            0.0
        }
    }

    pub fn completion_pct(&self) -> f64 {
        if self.total_sectors == 0 {
            100.0
        } else {
            ((self.rescued_sectors + self.bad_sectors) as f64 / self.total_sectors as f64) * 100.0
        }
    }

    pub fn estimated_remaining_seconds(&self) -> Option<u64> {
        let avg_speed = self.average_speed_mb_s();
        if avg_speed > 0.0 {
            let remaining_mb = (self.non_tried_sectors * self.sector_size as u64) as f64 / (1024.0 * 1024.0);
            Some((remaining_mb / avg_speed) as u64)
        } else {
            None
        }
    }
}
