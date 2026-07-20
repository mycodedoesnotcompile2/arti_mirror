DEPRECATED: `Timebound`: renamed to `TimeBound`, leaving compatibility alias
DEPRECATED: `TimerangeBound`: renamed to `TimeRangeBound`, leaving compatibility alias
ADDED: `TimeRangeBound` now exported at the top-level, not just in `timed`
DEPRECATED: Use `TimeRangeBound::extend_start_bound` instead of `extend_pre_tolerance`
DEPRECATED: Use `TimeRangeBound::extend_end_bound` instead of `extend_tolerance`
ADDED: `TimeRange` (type alias)
ADDED: `TimeRange::new_range`, `apply_to`, `start`, `end`
ADDED: `TimeRange` `From` impls from (inclusive) `std::ops::Range*` types
