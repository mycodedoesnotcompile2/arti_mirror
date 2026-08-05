# `errvec` - Inspectable errors with multiple sources

## Motivation

We often want to define an error with _multiple_ other errors as a source.
This can occur when:
  - We are attempting to retry an operation until it succeeds,
    but it has failed too many times.
  - We are attempting some operation on multiple targets,
    and we want to treat any failures collectively
    as the reason that the operation failed.
  - We are running multiple steps of an operation in parallel,
    and we want to treat the operation as failed if any of them have failed.

Unfortunately, this is not trivial with Rust's current Error type.

We encounter the difficulty when we try to "walk up"
a stack of errors, with something like:

```rust
# use std::error::Error;
fn display_errors(mut e: &(dyn Error + 'static)) {
    loop {
        println!("{e}");
        let Some(source) = e.source() else {
            break;
        };
        e = source;
    }
}
```

What should we do here with errors that have _multiple_ sources?
Since [`Error::source`] returns a single `Option<&dyn Error + 'static>`,
it isn't clear how to access the any sub-errors except (perhaps)
the one returned by `Error::source`.

Some implementations give the outer error a `Display` implementation
that displays every inner error.
This violates some projects' preferred practice of _not_ having outer errors'
`Display` implementations format their sources,
and also tends to lose information (unless the inner errors are formatted recursively).

## Our solution

We solve the problems above as follows:

We provide an `ErrorExt` extension trait,
implemented on every `Error + 'static` type,
and on `dyn Error + 'static`.
It has a method called [`ErrorExt::direct_sources`]
to return an iterator over all the immediate sources of an error.
(It does not recurse up the error stack;
if the error's sources themselves have sources,
the iterator does not yield those.)

We also provide an `ErrVec<T>`
type that behaves like `Vec<T>`,
except as follows:

 - `ErrVec<T>` can only hold types that implement `Error + Clone + 'static`.
 - If some `dyn Error` is an `ErrVec<T>`, or its `Error::source` is an `ErrVec<T>`,
   then [`ErrorExt::direct_sources`] will iterate
   over every member of the `ErrVec`.

Together, these properties allow us to write code like the following:
```rust
# #[derive(Clone,Debug,thiserror::Error)]
# #[error("didn't get it")]
# struct OneDownloadFailed;
# #[derive(Clone,Debug,thiserror::Error)]
# #[error("kaboom")]
# struct Explosion;

use errvec::{ErrVec, ErrorExt as _};
use std::error::Error;

fn display_tree(e: &(dyn Error + 'static)) {
    fn disp(indent: &str, e: &(dyn Error + 'static)) {
        println!("{indent}{e}");
        let new_indent = format!("   {indent}");
        for source in e.direct_sources() {
            disp(&new_indent, source);
        }
    }
    disp("", e);
}

#[derive(Clone, Debug, thiserror::Error)]
enum MyError {
    #[error("Multiple download attempts failed")]
    AllDownloadsFailed(#[source] ErrVec<OneDownloadFailed>),
    #[error("It keeps going boom")]
    TooManyExplosions(#[source] ErrVec<Explosion>),
}
# let e = MyError::TooManyExplosions(vec![
#     Explosion, Explosion, Explosion,
# ].into());
# display_tree(&e as _);
```

## Comparison with related work

There are several other crates based around collecting multiple errors
into a single error type.

Generally, they are are not attempting to solve the same problem
as we are facing here.

Some of them provide only a type-erased "error set" type,
and not a generic `Vec<T>`.
This makes it somewhat cumbersome
to manipulate their members when the actual type is known.

Some of them assume an ecosystem where _all_ errors in a project
will be rewritten to use their new types or traits.
This is reasonable for some applications,
but is generally not great for library design.

Most of them do not provide a method for finding the sources
of a type-erased `&dyn Error + 'static`.
This makes "tree walking" difficult in practice,
since once you have called `Error::source` to find the source of an error,
you can no longer find out whether _that_ error has more than one source.

Some of them take effort to provide special constructor types.
(We just let you use `Vec<T>`.)

Related work:

  - `rootcause`
  - `lazy_errors`
  - `anystack`
  - `errorstash`
  - `error_forge`
  - `error-trees`
  - `errvec`
  - `multi_error`
  - `error-vec`
