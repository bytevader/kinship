//! Time without a clock: the driver passes the current [`Instant`] into every call.

use core::fmt;
use core::ops::{Add, Sub};
use core::time::Duration;

/// A point on the driver's monotonic timeline, in nanoseconds from an arbitrary origin.
///
/// The core never reads a clock. A tokio driver maps `std::time::Instant` onto this by taking
/// the elapsed time since it started; the simulator uses its virtual clock directly. Arithmetic
/// saturates instead of panicking, so a timer computed far in the future clamps to
/// [`Instant::MAX`].
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct Instant(u64);

impl Instant {
    /// The origin of the timeline.
    pub const ZERO: Instant = Instant(0);
    /// The latest representable instant, about 584 years after [`Instant::ZERO`].
    pub const MAX: Instant = Instant(u64::MAX);

    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// `self + d`, or `None` if that is past [`Instant::MAX`].
    pub fn checked_add(self, d: Duration) -> Option<Self> {
        let nanos = u64::try_from(d.as_nanos()).ok()?;
        self.0.checked_add(nanos).map(Self)
    }

    /// `self + d`, clamped to [`Instant::MAX`].
    pub fn saturating_add(self, d: Duration) -> Self {
        self.checked_add(d).unwrap_or(Self::MAX)
    }

    /// Time elapsed from `earlier` to `self`, or `None` if `earlier` is later.
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_nanos)
    }

    /// Time elapsed from `earlier` to `self`, or zero if `earlier` is later.
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.checked_duration_since(earlier)
            .unwrap_or(Duration::ZERO)
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    /// Saturates at [`Instant::MAX`].
    fn add(self, d: Duration) -> Instant {
        self.saturating_add(d)
    }
}

impl Sub for Instant {
    type Output = Duration;

    /// Saturates at zero.
    fn sub(self, earlier: Instant) -> Duration {
        self.saturating_duration_since(earlier)
    }
}

impl fmt::Debug for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Instant({:?})", Duration::from_nanos(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_saturates() {
        let t = Instant::from_nanos(10);
        assert_eq!(t + Duration::from_nanos(5), Instant::from_nanos(15));
        assert_eq!(Instant::MAX + Duration::from_secs(1), Instant::MAX);
        assert_eq!(t + Duration::MAX, Instant::MAX);
        assert_eq!(Instant::ZERO - t, Duration::ZERO);
        assert_eq!(t - Instant::ZERO, Duration::from_nanos(10));
        assert_eq!(Instant::ZERO.checked_duration_since(t), None);
    }
}
