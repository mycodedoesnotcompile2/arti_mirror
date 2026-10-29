#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
#![allow(clippy::collapsible_if)] // See arti#2342
#![deny(clippy::unused_async)]
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::any::Any;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

mod inner;

use inner::{AnyErrVec, AnyErrVecIter};

/// A [`Vec`] of [`Error`] types.
///
/// Unlike `Vec<T>`, [`ErrVec`] can be used with [`ErrorExt`] to
/// dynamically look up the multiple sources of a `&dyn Error`.
///
/// This type implements [`Deref`] and [`DerefMut`] for
/// `Vec<T>`.  Therefore, you can invoke any `Vec` method on an `ErrVec`.
///
/// The main differences between `Vec` and `ErrVec` are:
/// - `ErrVec<T>` implement [`Error`]
///   if `T`  implements `Error`.
/// - If some Error `e` is an `ErrVec`,
///   then [`ErrorExt::as_err_iter`] will yield all the errors in `e`.
/// - If some Error `e` is an `ErrVec` or has an `ErrVec` as its source,
///   then [`ErrorExt::direct_sources`] will yield all the errors
///   in that `ErrVec.`
///
/// ## Displaying an `ErrVec`
///
/// `ErrVec` has a [`Display`] implementation, since that is required by `Error`.
/// Nonetheless, we do not suggest that you display an `ErrVec` directly:
/// doing so will only format a short statement about the number of errors present.
/// Instead, use [`ErrorExt`] to walk your tree of errors,
/// and display the ones that are relevant to you.
///
/// ## Empty `ErrVec`s
///
/// It is usually a mistake to make an empty `ErrVec` be the source of another error.
/// Nonetheless, empty `ErrVec`s are still allowed,
/// since permitting them is the most ergonomic way to build up a non-empty ErrVec.
/// If you want to ensure that an ErrVec is nonempty before using it as the source of an error,
/// you can use [`ErrVec::nonempty`] to return `None` if the `ErrVec` is empty.
///
/// ## Interoperability and `Error::source`
///
/// For interoperability with code that doesn't know about [`ErrorExt`],
/// `ErrVec`'s `Error::source` implementation will return the first error
/// in the `ErrVec`, if it is nonempty.
///
/// This is usually not the behavior you want!  
///
/// ## `T` must be `Clone`
///
/// Since it is so often beneficial to have error types implement `Clone`,
/// we have `ErrVec<T>` implement `Clone` itself.
/// But because of some of our internal type erasure trickery,
/// this forces us to require that `T` implement `Clone`.
///
/// If you need to construct an `ErrVec` of some type that does not
/// implement `Clone`, consider wrapping it in an [`Arc`](std::sync::Arc).
#[derive(Clone, Debug)]
pub struct ErrVec<T: 'static> {
    /// A type-erased Vec of errors.
    ///
    /// See [`AynErrVec`] for discussion of why we type-erase in this way.
    inner: Box<dyn AnyErrVec>,

    /// A marker to ensure that `T` is mentioned in this type.
    _phantom: PhantomData<T>,
}

impl<T: 'static> ErrVec<T> {
    /// If this `ErrVec` contains at least one error, return `self`.
    ///
    /// Otherwise, return None.
    pub fn nonempty(self) -> Option<Self> {
        if self.is_empty() { None } else { Some(self) }
    }
}

impl<T: 'static + Error + Clone> Default for ErrVec<T> {
    fn default() -> Self {
        Vec::<T>::new().into()
    }
}

impl<T: 'static + Error + Clone> ErrVec<T> {
    /// Construct a new empty `ErrVec<T>`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<T: 'static + Error + Clone> From<Vec<T>> for ErrVec<T> {
    fn from(value: Vec<T>) -> Self {
        Self {
            inner: Box::new(value),
            _phantom: PhantomData,
        }
    }
}

impl<T> From<ErrVec<T>> for Vec<T> {
    fn from(value: ErrVec<T>) -> Self {
        let inner: Box<dyn Any + 'static> = value.inner;
        let inner: Box<Vec<T>> = inner.downcast().expect("Mismatched type");
        *inner
    }
}

impl<T: 'static> Deref for ErrVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        let errs_ref: &dyn AnyErrVec = self.inner.as_ref();

        <dyn Any>::downcast_ref(errs_ref).expect("Internal type mismatch")
    }
}

impl<T: 'static> DerefMut for ErrVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let errs_mut: &mut dyn AnyErrVec = self.inner.as_mut();
        <dyn Any>::downcast_mut(errs_mut).expect("Internal type mismatch")
    }
}

impl<T: 'static> AsRef<[T]> for ErrVec<T> {
    fn as_ref(&self) -> &[T] {
        (**self).as_ref()
    }
}

impl<T: Display + 'static> Display for ErrVec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}
impl<T: Error + 'static> Error for ErrVec<T> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // Crucially, the source of a an `ErrVec` is of type `Box<dyn AnyErrVec>`.
        //
        // This fact -- that we can downcast _every_ Errvec.inner to `Box<dyn AnyErrVec>` --
        // is what allows `ErrorExt` to work.
        Some(&self.inner)
    }
}

/// An extension trait for [`Errors`]s that can have multiple sources.
pub trait ErrorExt {
    /// If this error is an [`ErrVec`],
    /// return an iterator over every error it contains.
    ///
    /// Otherwise, return an iterator returning only this error.
    fn as_err_iter(&self) -> ErrorSources<'_>;

    /// Return an iterator over every source of this error.
    ///
    /// If this error is an [`ErrVec`], or if its `source` is an [`ErrVec`],
    /// the iterator will yield every member that [`ErrVec`].
    ///
    /// Otherwise, the iterator will yield the [`Error::source`] of this
    /// error (if it has one).
    ///
    /// ## Naming
    ///
    /// This function is not named `sources`,
    /// to avoid conflict with the not-yet-stable `<dyn Error>::sources`
    /// in the standard library.
    fn direct_sources(&self) -> ErrorSources<'_>;
}

impl ErrorExt for dyn Error + 'static {
    fn as_err_iter(&self) -> ErrorSources<'_> {
        use ErrorSourcesInner::*;

        let inner = if let Some(multisource) = self.downcast_ref::<Box<dyn AnyErrVec>>() {
            // This case shouldn't really be reached: you _shouldn't_ call this on a Box<dyn AnyErrVec>.
            Many(multisource.iter())
        } else if let Some(mysource) = self.source()
            && let Some(multisource) = mysource.downcast_ref::<Box<dyn AnyErrVec>>()
        {
            Many(multisource.iter())
        } else {
            One(self)
        };
        ErrorSources(inner)
    }

    fn direct_sources(&self) -> ErrorSources<'_> {
        use ErrorSourcesInner::*;

        if let x @ ErrorSources(Many(_)) = self.as_err_iter() {
            x
        } else if let Some(source) = self.source() {
            source.as_err_iter()
        } else {
            ErrorSources(NoError)
        }
    }
}

impl<T: Error + 'static> ErrorExt for T {
    fn as_err_iter(&self) -> ErrorSources<'_> {
        let self_ = self as &(dyn Error + 'static);
        ErrorExt::as_err_iter(self_)
    }

    fn direct_sources(&self) -> ErrorSources<'_> {
        let self_ = self as &(dyn Error + 'static);
        ErrorExt::direct_sources(self_)
    }
}

/// An iterator over zero or more errors.
pub struct ErrorSources<'a>(ErrorSourcesInner<'a>);

/// Implementation type for `ErrorSources`.
enum ErrorSourcesInner<'a> {
    /// An empty iterator.
    NoError,

    /// An iterator returning a single error.
    One(&'a (dyn Error + 'static)),

    /// An iterator over multiple errors.
    Many(AnyErrVecIter<'a>),
}

impl<'a> Iterator for ErrorSources<'a> {
    type Item = &'a (dyn Error + 'static);

    fn next(&mut self) -> Option<Self::Item> {
        use ErrorSourcesInner::*;

        match &mut self.0 {
            NoError => None,
            One(error) => {
                let e = *error;
                self.0 = NoError;
                Some(e)
            }
            Many(it) => it.next(),
        }
    }
}

impl<'a> FusedIterator for ErrorSources<'a> {}

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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    #[derive(Clone, Debug, thiserror::Error)]
    #[error("Error A")]
    struct ErrA;

    #[derive(Clone, Debug, thiserror::Error)]
    enum ErrB {
        #[error("Error B case A")]
        CaseA(#[from] ErrA),
        #[error("Error B case B")]
        CaseB,
    }

    #[derive(Clone, Debug, thiserror::Error)]
    enum ErrComplex {
        #[error("Multiple A errors occurred")]
        MultiA(#[from] ErrVec<ErrA>),
        #[error("Multiple B errors occurred")]
        MultiB(#[from] ErrVec<ErrB>),
    }

    #[test]
    fn direct_sources() {
        let e: ErrComplex = {
            let mut v: ErrVec<ErrB> = vec![ErrB::CaseA(ErrA), ErrB::CaseB, ErrB::CaseB].into();
            v.push(ErrB::CaseB);
            v.into()
        };

        let sources: Vec<_> = e.direct_sources().map(|e| format!("{e}")).collect();
        assert_eq!(sources.len(), 4);
        assert_eq!(sources[0].as_str(), "Error B case A");
        assert_eq!(sources[1].as_str(), "Error B case B");

        assert_eq!(e.as_err_iter().count(), 1);
        assert_eq!(e.source().unwrap().as_err_iter().count(), 4);
    }
}
