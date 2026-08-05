//! Define inner types.

use std::{any::Any, error::Error, fmt, iter::FusedIterator};

/// A type-erased `Vec<T>` for some error type T.
///
/// When we use [`Error::source()`] to find the source of an error,
/// it's not reasonable try downcasting it to every possible `Vec<T>`.
///
/// Therefore, we try downcasting to `Box<dyn AnyErrVec>` to see whether
/// the error has a multiplicity.
pub(crate) trait AnyErrVec: Any + fmt::Debug + 'static {
    /// Return a copy of this `Vec` in boxed type-erased form..
    fn duplicate(&self) -> Box<dyn AnyErrVec>;

    /// Return the number of elements in this `Vec`.
    fn len(&self) -> usize;

    /// Return an iterator over the elements in this `Vec`,
    /// as type-erased `&dyn Error + 'static` references.
    fn iter(&self) -> AnyErrVecIter<'_>;

    /// Return a reference to the element in this `Vec` at position
    /// `n`.  Return None if no such element exists.
    fn get(&self, n: usize) -> Option<&(dyn Error + 'static)>;
}

impl<T: Error + Clone + 'static> AnyErrVec for Vec<T> {
    fn duplicate(&self) -> Box<dyn AnyErrVec> {
        Box::new(self.clone())
    }

    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn iter(&self) -> AnyErrVecIter<'_> {
        AnyErrVecIter { next: 0, vec: self }
    }

    fn get(&self, n: usize) -> Option<&(dyn Error + 'static)> {
        self.as_slice().get(n).map(|e| e as _)
    }
}

impl Clone for Box<dyn AnyErrVec> {
    fn clone(&self) -> Self {
        self.duplicate()
    }
}

/// An iterator over the elements of an `AnyErrVec`.
pub(crate) struct AnyErrVecIter<'a> {
    /// The next element to yield.
    ///
    /// If `next >= vec.len()`, this iterator is exhausted.
    next: usize,

    /// The `AnyErrVec` from which to yield.
    vec: &'a dyn AnyErrVec,
}

impl<'a> Iterator for AnyErrVecIter<'a> {
    type Item = &'a (dyn Error + 'static);

    fn next(&mut self) -> Option<Self::Item> {
        let e = self.vec.get(self.next)?;
        self.next += 1;
        Some(e)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.vec.len().saturating_sub(self.next);
        (n, Some(n))
    }
}
impl<'a> FusedIterator for AnyErrVecIter<'a> {}

impl fmt::Display for Box<dyn AnyErrVec> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // See ErrVec documentation for discussion.
        match self.len() {
            0 => write!(f, "(No errors recorded)"),
            1 => write!(f, "(Error occurred)"),
            n => write!(f, "({n} errors occurred)"),
        }
    }
}

impl Error for Box<dyn AnyErrVec> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        // For interoperability, we return the first error as a source,
        // although it is not strictly right.
        //
        // See ErrVec documentation for discussion.
        self.get(0)
    }
}
