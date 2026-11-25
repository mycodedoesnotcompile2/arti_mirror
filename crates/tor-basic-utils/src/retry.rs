//! An implementation of the "decorrelated jitter" algorithm for scheduling retries.
//!
//! See [`RetryDelay`] for more information.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use saturating_time::SaturatingTime;

use crate::RngExt as _;
use rand::{Rng, seq::SliceRandom};

/// An implementation for retrying a remote operation based on a [decorrelated
/// jitter] schedule.
///
/// The algorithm used here has several desirable properties:
///    * It is randomized, so that multiple timeouts don't have a danger of
///      getting synchronized with each other and hammering the same servers all
///      at once.
///    * It tends on average to wait longer and longer over time, so that if the
///      server is down, it won't get pummeled by a zillion failing clients
///      when it comes back up.
///    * It has a chance of retrying promptly, which results in better client
///      performance on average.
///
/// For a more full specification, see [`dir-spec.txt`].
///
/// [decorrelated jitter]:
///     https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
/// [`dir-spec.txt`]: https://spec.torproject.org/dir-spec
#[derive(Clone, Debug)]
pub struct RetryDelay {
    /// The last delay that this retry delay returned (in msec), or 0
    /// if this never returned a delay.
    last_delay_ms: u32,
    /// The lowest allowable delay (in msec).
    low_bound_ms: u32,
}

/// Lowest possible lower bound, in milliseconds.
// We're doing this in MS, and Tor does it in seconds, so I'm
// multiplying the minimum by 1000 here.
const MIN_LOW_BOUND: u32 = 1000;

/// Largest possible lower bound, in milliseconds.
const MAX_LOW_BOUND: u32 = u32::MAX - 1;

/// Maximum amount to multiply the previous delay by.
const MAX_DELAY_MULT: u32 = 3;

impl RetryDelay {
    /// Construct a new RetryDelay from a given base delay in
    /// milliseconds.
    ///
    /// The base delay defines the lowest possible interval that can
    /// be returned.
    ///
    /// # Limitations
    ///
    /// If the base delay is less than 1000, a base delay of 1000 is
    /// used instead, since that's what the C tor implementation does.
    pub fn from_msec(base_delay_msec: u32) -> Self {
        let low_bound_ms = base_delay_msec.clamp(MIN_LOW_BOUND, MAX_LOW_BOUND);
        RetryDelay {
            last_delay_ms: 0,
            low_bound_ms,
        }
    }

    /// Construct a new RetryDelay from a given base delay.
    ///
    /// See from_msec for more information.
    pub fn from_duration(d: Duration) -> Self {
        let msec = d.as_millis();
        let msec = std::cmp::min(msec, u128::from(MAX_LOW_BOUND)) as u32;
        RetryDelay::from_msec(msec)
    }

    /// Helper: Return a lower and upper bound for the next delay to
    /// be yielded.
    ///
    /// Values are in milliseconds.
    ///
    /// The return value `(low, high)` is guaranteed to have `low < high`.
    fn delay_bounds(&self) -> (u32, u32) {
        let low = self.low_bound_ms;
        let high = std::cmp::max(
            // We don't need a saturating_add here, since low is always
            // <= MAX_LOW_BOUND, so low cannot be equal to u32::MAX.
            low + 1,
            self.last_delay_ms.saturating_mul(MAX_DELAY_MULT),
        );
        (low, high)
    }

    /// Return the next delay to be used (in milliseconds), according
    /// to a given random number generator.
    fn next_delay_msec<R: Rng>(&mut self, rng: &mut R) -> u32 {
        let (low, high) = self.delay_bounds();
        let val = rng.gen_range_checked(low..high).expect("low as not < high");
        self.last_delay_ms = val;
        val
    }

    /// Return the next delay to be used (as a [`Duration`]),
    /// according to a given random number generator.
    pub fn next_delay<R: Rng>(&mut self, rng: &mut R) -> Duration {
        Duration::from_millis(u64::from(self.next_delay_msec(rng)))
    }

    /// Return this [`RetryDelay`] to its original state.
    pub fn reset(&mut self) {
        self.last_delay_ms = 0;
    }
}

impl Default for RetryDelay {
    fn default() -> Self {
        RetryDelay::from_msec(0)
    }
}

/// Priority-queue like wrapper around [`RetryDelay`].
///
/// Internally, it is implemented using a [`BTreeMap`] that is indexed by an
/// [`Instant`] (alongside a unique irrelevant randomized integer allowing for
/// duplicate Instant keys).
///
/// This is useful if you have an immutable set of values and you want to
/// perform operations with them where a success leads to an improvement of their
/// reliability and an error to a decrease in their reliability.  A prime
/// example of this is the set of directory authority download endpoints, where
/// we want to maintain a separate [`RetryDelay`] for every endpoint.
///
/// Interfacing applications utilize this data structure as follows:
/// 1. Initialize the [`RetrySet`] using [`RetrySet::new()`].
/// 2. Use [`RetrySet::with()`] alongside a function that returns a [`Result`].
#[derive(Debug, Clone)]
pub struct RetrySet<T>(BTreeMap<(Instant, usize), (T, RetryDelay)>);

/// Returned by [`RetrySet::new()`] if no values are provided.
#[derive(Debug, Clone, thiserror::Error)]
#[error("the provided values are empty")]
#[non_exhaustive]
pub struct ValuesAreEmpty;

/// Returned by [`RetrySet::with()`] to indicate the caller that no values will
/// be ready until `ready_at` has been reached.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("no value is ready right now")]
#[non_exhaustive]
pub struct NotReadyYet {
    /// The point in time when values will be ready again.
    pub ready_at: Instant,
}

impl<T: Eq> RetrySet<T> {
    /// Creates a new [`RetrySet`] from an iterator.
    ///
    /// The items in the provided iterator get randomized, meaning each item
    /// has a 1/n probability of being chosen in the first call of
    /// [`RetrySet::with()`].
    ///
    /// Duplicates are permitted.
    pub fn new<NowFn: Fn() -> Instant, R: Rng>(
        values: impl Iterator<Item = T>,
        now: NowFn,
        rng: &mut R,
    ) -> Result<Self, ValuesAreEmpty> {
        let now = now();
        let mut values = values.into_iter().collect::<Vec<_>>();
        values.shuffle(rng);
        if values.is_empty() {
            Err(ValuesAreEmpty)?;
        }

        Ok(Self(
            values
                .into_iter()
                .enumerate()
                // Storing the key as (Instant, usize) allows to have the list
                // always sorted by the smallest Instant while allowing for
                // Instants to be duplicate, which is important.
                .map(|(idx, value)| ((now, idx), (value, RetryDelay::default())))
                .collect(),
        ))
    }

    /// Executes a function `f`, with the best possible value.
    ///
    /// Each value has internally associated [`Instant`] and [`RetryDelay`]
    /// instances.  The [`Instant`] value defines when the value is ready to
    /// be used.  The best value is defined as the value with smallest
    /// [`Instant`] value.  If `now` is smaller than the [`Instant`] of the
    /// best value, `f` is not executed and a [`NotReadyYet`] will be returned
    /// with the the [`Instant`] specifying when the next value will be ready.
    /// If the smallest [`Instant`] is shared by multiple values, the best
    /// value is determined in a random but stable fashion.
    ///
    /// At start, all values share the same [`Instant`] value.  Whenever `f`
    /// returns an error, the value's ready value will be bumped to
    /// `now + delay`, with delay being determined by advancing the value's
    /// associated [`RetryDelay`].
    ///
    /// Whenever `f` returns an [`Ok`], the [`RetryDelay`] of the best possible
    /// value gets reset.  It is debatable whether our strategy of fully
    /// resetting it is appropriate, but it is what the current API offers.
    ///
    /// # Example
    ///
    /// ```
    /// use std::net::{SocketAddrV4, Ipv4Addr};
    /// use std::time::Instant;
    /// use rand::rngs::ThreadRng;
    /// use tor_basic_utils::retry::{RetrySet, NotReadyYet};
    ///
    /// fn download(_endpoint: &SocketAddrV4) -> Result<(), ()> {
    ///   // We could now download something here ...
    ///   // A failure would lead the caller to immediately retry all the
    ///   // remaining endpoints.  If they also fail, the caller will wait until
    ///   // the smallest ready time has been reached again.
    ///   Ok(())
    /// }
    ///
    /// let endpoints = [
    ///   SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
    ///   SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8081),
    /// ];
    /// let rng = &mut ThreadRng::default();
    /// let mut set = RetrySet::new(endpoints.into_iter(), Instant::now, rng).unwrap();
    ///
    /// for _ in 0..16 {
    ///   match set.with(Instant::now, rng, download) {
    ///     Ok(Ok(())) => {}, // Download succeeded,
    ///     Ok(Err(())) => {}, // Download failed,
    ///     Err(NotReadyYet { ready_at, .. }) => {
    ///       std::thread::sleep(Instant::now().duration_since(ready_at));
    ///     }
    ///   }
    /// }
    /// ```
    pub fn with<NowFn, R, F, U, E>(
        &mut self,
        now: NowFn,
        rng: &mut R,
        f: F,
    ) -> Result<Result<U, E>, NotReadyYet>
    where
        NowFn: Fn() -> Instant,
        R: Rng,
        F: FnOnce(&T) -> Result<U, E>,
    {
        let ((mut ready_at, idx), (value, mut retry_delay)) =
            self.0.pop_first().expect("RetrySet must not be empty"); // Ensured by new().

        let res = if now() < ready_at {
            Err(NotReadyYet { ready_at })
        } else {
            match f(&value) {
                Ok(x) => {
                    retry_delay.reset();
                    Ok(Ok(x))
                }
                Err(e) => {
                    ready_at = now().saturating_add(retry_delay.next_delay(rng));
                    Ok(Err(e))
                }
            }
        };

        self.0.insert((ready_at, idx), (value, retry_delay));
        res
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::test_rng::testing_rng;
    use web_time_compat::InstantExt;

    #[test]
    fn init() {
        let rd = RetryDelay::from_msec(2000);
        assert_eq!(rd.last_delay_ms, 0);
        assert_eq!(rd.low_bound_ms, 2000);

        let rd = RetryDelay::from_msec(0);
        assert_eq!(rd.last_delay_ms, 0);
        assert_eq!(rd.low_bound_ms, 1000);

        let rd = RetryDelay::from_duration(Duration::new(1, 500_000_000));
        assert_eq!(rd.last_delay_ms, 0);
        assert_eq!(rd.low_bound_ms, 1500);
    }

    #[test]
    fn bounds() {
        let mut rd = RetryDelay::from_msec(1000);
        assert_eq!(rd.delay_bounds(), (1000, 1001));
        rd.last_delay_ms = 1500;
        assert_eq!(rd.delay_bounds(), (1000, 4500));
        rd.last_delay_ms = 3_000_000_000;
        assert_eq!(rd.delay_bounds(), (1000, u32::MAX));
        rd.reset();
        assert_eq!(rd.delay_bounds(), (1000, 1001));
    }

    #[test]
    fn rng() {
        let mut rd = RetryDelay::from_msec(50);
        let real_low_bound = std::cmp::max(50, MIN_LOW_BOUND);

        let mut rng = testing_rng();
        for _ in 1..100 {
            let (b_lo, b_hi) = rd.delay_bounds();
            assert!(b_lo == real_low_bound);
            assert!(b_hi > b_lo);
            let delay = rd.next_delay(&mut rng).as_millis() as u32;
            assert_eq!(delay, rd.last_delay_ms);
            assert!(delay >= b_lo);
            assert!(delay < b_hi);
        }
    }

    /// Tests whether RetrySet picks the proper value, i.e. the one with the
    /// smallest ready_at iff now >= ready_at.
    #[test]
    fn retry_set_correct_pick() {
        let now = Instant::get();
        let now = || now;
        let prev_now = || now() - Duration::from_secs(30);
        let rng = &mut testing_rng();
        let mut set = RetrySet::new([1, 2].into_iter(), now, rng).unwrap();

        // Executing this at now should yield the best result.
        let cur = set.with(now, rng, |i| Ok::<_, ()>(*i)).unwrap().unwrap();

        // We should not get anything if we are in the past, for whatever reason.
        assert_eq!(
            set.with::<_, _, _, (), ()>(prev_now, rng, |_| unreachable!())
                .unwrap_err(),
            NotReadyYet { ready_at: now() }
        );

        // Because the previous inner run succeeded, calling with() again should
        // return the same.
        let cur1 = set.with(now, rng, |i| Ok::<_, ()>(*i)).unwrap().unwrap();
        assert_eq!(cur, cur1);

        // Now, if the inner fails, we should get a new value in the subsequent
        // run.
        set.with(now, rng, |_| Err::<(), _>(()))
            .unwrap()
            .unwrap_err();

        // We let it fail again because then, both values should no longer be
        // reachable afterwards, as we have never advanced now.
        let cur1 = set
            .with(now, rng, |i| Err::<(), _>(*i))
            .unwrap()
            .unwrap_err();
        assert_ne!(cur, cur1);

        // Now, we should get a NotReady in any case for now.
        let err = match set.with::<_, _, _, (), ()>(now, rng, |_| unreachable!()) {
            Err(NotReadyYet { ready_at }) => ready_at,
            x => panic!("want NotReadyYet, got {x:?}"),
        };

        // If we set now to the next possible ready_at, it should work again.
        let now = || err;
        set.with(now, rng, |i| Ok::<_, ()>(*i)).unwrap().unwrap();
    }

    /// Tests whether RetrySet properly resets RetryDelay in the success case.
    #[test]
    fn retry_set_reset() {
        let original_now = Instant::get();
        let mut now: Box<dyn Fn() -> Instant> = Box::new(|| original_now);
        let rng = &mut testing_rng();
        let mut set = RetrySet::new([1].into_iter(), &now, rng).unwrap();

        for _ in 0..1000 {
            set.with(&now, rng, |_| Err::<(), _>(()))
                .unwrap()
                .unwrap_err();
            let ready_at = match set.with(&now, rng, |_| Err::<(), _>(())) {
                Err(NotReadyYet { ready_at }) => ready_at,
                x => panic!("want NotReadyYet, got {x:?}"),
            };
            now = Box::new(move || ready_at);
        }

        // After 1000 runs, now() should be very far off from original_now.
        let hours_off = now().duration_since(original_now).as_secs() / 60 / 60;
        assert!(hours_off > 1000); // This is a big under-estimation actually.

        // Now, if we succeed once and fail again ...
        let original_now = now();
        set.with(&now, rng, |_| Ok::<_, ()>(())).unwrap().unwrap();
        set.with(&now, rng, |_| Err::<(), _>(()))
            .unwrap()
            .unwrap_err();
        let ready_at = match set.with(&now, rng, |_| Err::<(), _>(())) {
            Err(NotReadyYet { ready_at }) => ready_at,
            x => panic!("want NotReadyYet, got {x:?}"),
        };
        now = Box::new(move || ready_at);

        let seconds_off = now().duration_since(original_now).as_secs();
        assert!(seconds_off < 10); // This is a big over-estimation actually.
    }
}
