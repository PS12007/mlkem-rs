//! Welch's t-test with dudect-style percentile cropping.
//!
//! dudect (Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?",
//! DATE 2017) measures the running time of a function many times under two
//! input classes and asks a simple statistical question: do the two timing
//! distributions have the same mean? If the code is constant time they
//! should. If the |t| statistic grows large, they do not.
//!
//! Timing distributions have a long right tail (interrupts, cache misses,
//! the other program on the machine). One outlier can dominate a mean. So,
//! like dudect, we also run the test on *cropped* data: only measurements
//! below the p-th percentile, for a range of p. A leak that shows up as a
//! small shift of the bulk of the distribution is easier to see once the
//! tail is cut off. We report the maximum |t| over all the crops.

/// Running mean and variance of two classes (Welford's one-pass update,
/// which avoids the catastrophic cancellation of sum-of-squares formulas).
#[derive(Clone, Copy, Debug, Default)]
pub struct Welch {
    n: [f64; 2],
    mean: [f64; 2],
    m2: [f64; 2],
}

impl Welch {
    pub fn push(&mut self, class: usize, x: f64) {
        self.n[class] += 1.0;
        let delta = x - self.mean[class];
        self.mean[class] += delta / self.n[class];
        self.m2[class] += delta * (x - self.mean[class]);
    }

    pub fn n(&self, class: usize) -> u64 {
        self.n[class] as u64
    }

    pub fn mean(&self, class: usize) -> f64 {
        self.mean[class]
    }

    /// Sample variance (n − 1 denominator).
    pub fn var(&self, class: usize) -> f64 {
        if self.n[class] < 2.0 {
            0.0
        } else {
            self.m2[class] / (self.n[class] - 1.0)
        }
    }

    /// Welch's t statistic: (mean0 − mean1) / sqrt(var0/n0 + var1/n1).
    /// Unlike Student's t-test it does not assume equal variances. 0 if
    /// there is not enough data yet.
    pub fn t(&self) -> f64 {
        if self.n[0] < 2.0 || self.n[1] < 2.0 {
            return 0.0;
        }
        let se = (self.var(0) / self.n[0] + self.var(1) / self.n[1]).sqrt();
        if se == 0.0 {
            0.0
        } else {
            (self.mean[0] - self.mean[1]) / se
        }
    }
}

/// Value at quantile p (0 ≤ p ≤ 1) of an already sorted sample.
pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    assert!(!sorted.is_empty() && (0.0..=1.0).contains(&p));
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

/// The crop points dudect uses: p_k = 1 − 0.5^(10·(k+1)/count). With
/// count = 100 they run from about 6.7% (k = 0) through 50% (k = 9) and
/// 96.9% (k = 49) to 99.9% (k = 99): half of the crops only trim the extreme
/// tail, the rest look at the fast bulk of the distribution.
pub fn dudect_crop_points(count: usize) -> Vec<f64> {
    (0..count)
        .map(|k| 1.0 - 0.5f64.powf(10.0 * (k as f64 + 1.0) / count as f64))
        .collect()
}

/// One t-test per crop, plus the uncropped test.
pub struct TestSet {
    /// (description, threshold in ticks or None = uncropped, test)
    pub tests: Vec<(String, Option<u64>, Welch)>,
}

impl TestSet {
    /// Thresholds come from a calibration sample of measurements.
    pub fn new(calibration: &mut [u64], crops: usize) -> Self {
        calibration.sort_unstable();
        let mut tests = vec![("uncropped".to_string(), None, Welch::default())];
        for p in dudect_crop_points(crops) {
            let thr = percentile(calibration, p);
            tests.push((
                format!("below p{:.4}", p * 100.0),
                Some(thr),
                Welch::default(),
            ));
        }
        TestSet { tests }
    }

    pub fn push(&mut self, class: usize, ticks: u64) {
        for (_, thr, w) in &mut self.tests {
            if thr.is_none_or(|t| ticks < t) {
                w.push(class, ticks as f64);
            }
        }
    }

    /// The test with the largest |t| (index into `tests`).
    pub fn max_abs_t(&self) -> (usize, f64) {
        self.tests
            .iter()
            .enumerate()
            .map(|(i, (_, _, w))| (i, w.t().abs()))
            .fold(
                (0, 0.0),
                |best, cur| if cur.1 > best.1 { cur } else { best },
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-computable case: class 0 = 1..5, class 1 = 2..6. Means 3 and 4,
    /// both variances 2.5, so se = sqrt(2.5/5 + 2.5/5) = 1 and t = −1.
    #[test]
    fn welch_known_value() {
        let mut w = Welch::default();
        for x in 1..=5 {
            w.push(0, x as f64);
            w.push(1, (x + 1) as f64);
        }
        assert!((w.mean(0) - 3.0).abs() < 1e-12);
        assert!((w.var(1) - 2.5).abs() < 1e-12);
        assert!((w.t() + 1.0).abs() < 1e-12);
    }

    /// Welford must not lose precision on large offsets (timings are
    /// around 10^5 ticks with differences of a few ticks).
    #[test]
    fn welford_is_numerically_stable() {
        let mut w = Welch::default();
        for i in 0..1_000_000u64 {
            w.push(0, 1e9 + (i % 2) as f64);
        }
        assert!((w.var(0) - 0.25).abs() < 1e-6, "var = {}", w.var(0));
    }

    #[test]
    fn identical_classes_give_small_t() {
        let mut w = Welch::default();
        let mut x: u64 = 12345;
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17; // xorshift64
            w.push((x & 1) as usize, (x >> 40) as f64);
        }
        assert!(w.t().abs() < 5.0, "t = {}", w.t());
    }

    #[test]
    fn crop_points_and_percentiles() {
        let p = dudect_crop_points(100);
        assert_eq!(p.len(), 100);
        assert!((p[99] - (1.0 - 0.5f64.powi(10))).abs() < 1e-12);
        assert!(p.windows(2).all(|w| w[0] < w[1]));
        let sorted: Vec<u64> = (0..=100).collect();
        assert_eq!(percentile(&sorted, 0.5), 50);
        assert_eq!(percentile(&sorted, 1.0), 100);
    }
}
