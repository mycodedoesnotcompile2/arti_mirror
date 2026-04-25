//! Declare a type to represent the encoding of a request or its body.

use std::{borrow::Cow, sync::Arc};

/// The encoding of a request or its body.
///
/// This type is meant to avoid copies in the case where we want
/// to upload a document in the body of a request.
#[derive(Clone, Debug, Default)]
pub struct RequestBody {
    /// A list containing an `Arc<[u8]>` for each section of the request.
    inner: Vec<Arc<[u8]>>,
}

impl RequestBody {
    /// Create a new empty [`RequestBody`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Return true if this [`RequestBody`] is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.iter().all(|s| s.is_empty())
    }

    /// Return the number of bytes in this [`RequestBody`]
    pub fn len(&self) -> usize {
        self.inner.iter().map(|s| s.len()).sum()
    }

    /// Return a [`String`] holding all the contents of this [`RequestBody`].
    ///
    /// Try to avoid calling this method: it can copy more than we would want.
    pub fn to_owned(&self) -> Vec<u8> {
        self.to_cow_str().into_owned()
    }

    /// Return a [`Cow`] containing this body.
    ///
    /// This method avoids copying when the body has only a single chunk,
    /// but otherwise it needs to allocate a new string and copy everything into it.
    pub fn to_cow_str(&self) -> Cow<'_, [u8]> {
        match &self.inner[..] {
            [] => (&[]).into(),
            [s] => s.as_ref().into(),
            _ => {
                let mut s = Vec::new();
                for chunk in &self.inner {
                    s.extend_from_slice(&chunk[..]);
                }
                s.into()
            }
        }
    }

    /// Add `s` to the end of this [`RequestBody`].
    pub fn push_arc(&mut self, s: Arc<str>) {
        self.inner.push(s.into());
    }

    /// Add `s` to the end of this [`RequestBody`].
    pub fn push_str(&mut self, s: String) {
        self.inner.push(s.into_bytes().into());
    }

    /// Add the contents of `b` to the end of this [`RequestBody`].
    pub fn push_body(&mut self, b: &RequestBody) {
        self.inner.extend(b.iter().cloned());
    }

    /// Return an iterator over the chunks of this [`RequestBody`].
    pub fn iter(&self) -> impl Iterator<Item = &Arc<[u8]>> + '_ {
        self.inner.iter()
    }
}

impl From<String> for RequestBody {
    fn from(s: String) -> Self {
        Self {
            inner: vec![s.into_bytes().into()],
        }
    }
}

impl<'a> From<&'a str> for RequestBody {
    fn from(s: &'a str) -> Self {
        Self {
            inner: vec![s.as_bytes().into()],
        }
    }
}

impl From<Arc<str>> for RequestBody {
    fn from(s: Arc<str>) -> Self {
        Self {
            inner: vec![s.into()],
        }
    }
}

impl From<RequestBody> for Vec<u8> {
    fn from(body: RequestBody) -> Self {
        body.to_owned()
    }
}
