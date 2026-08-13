
- We want the Display method for our errors to display _only_ the errors
  themselves, and not their sources.

- We have multiple cases where an error can actually have multiple sources.
  These include retry_error, ConnectError (poss renamed) in ChanMgr,
  anything that uses a happy eyeballs approach, and probably more.

- The standard Error API only supports one source per error.

- Since we don't want Display to recurse down to error sources,
  it is incorrect for these multiple-error types to have a Display information
  that reports all the errors.

- The alternative is to adjust our error-report and error-traversal functions
  to use Error::downcast to see whether an error is a particular type.

- Because Rust doesn't have downcast-to-trait, we can't just define a trait
  that represents "an error with multiple sources" and downcast to that trait
  from dyn Error...

   - Unless we implement some kind of horrible registry-based downcaster...
   - ...and we can't implement one of those because we don't even have a TypeId to
     work with.
     - Though I guess we could squeeze a typeid into description or cause. 
       But that is an evil hack.
     - And we could also solve this with `provide`, if that were table.
     - But this is just a nonstarter.

- Therefore, we should have a single MultiError type (name tbd) that represents
  "multiple errors have occurred".

- This can't be MultiError<T>, since we would have to downcast to _every_
  MultiError<T>.

- But we do want to avoid type erasure when we _do_ know the concrete type of an error.


- We want to avoid blanket type-erasure-based solutions if we can.




- Prior art with dependents
  - rootcause
  - 

- Other prior art with documentation
  - lazy_errors
  - multiple_errors
  - anystack
  - errorstash
  - error_forge