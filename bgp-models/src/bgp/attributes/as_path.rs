use crate::network::Asn;
use itertools::Itertools;
use serde::{Serialize, Serializer};
use smallvec::SmallVec;
use std::borrow::Borrow;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::iter::FromIterator;

/// Enum of AS path segment.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AsPathSegment<'s> {
    AsSequence(Cow<'s, [Asn]>),
    AsSet(Cow<'s, [Asn]>),
    ConfedSequence(Cow<'s, [Asn]>),
    ConfedSet(Cow<'s, [Asn]>),
}

impl AsPathSegment<'static> {
    fn new_as_sequence<T, I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Asn>,
    {
        let buffer = Vec::from_iter(iter.into_iter().map(<T as Into<Asn>>::into));
        AsPathSegment::AsSequence(Cow::Owned(buffer))
    }

    fn new_as_set<T, I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Asn>,
    {
        let buffer = Vec::from_iter(iter.into_iter().map(<T as Into<Asn>>::into));
        AsPathSegment::AsSet(Cow::Owned(buffer))
    }

    fn new_confed_sequence<T, I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Asn>,
    {
        let buffer = Vec::from_iter(iter.into_iter().map(<T as Into<Asn>>::into));
        AsPathSegment::ConfedSequence(Cow::Owned(buffer))
    }

    fn new_confed_set<T, I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Asn>,
    {
        let buffer = Vec::from_iter(iter.into_iter().map(<T as Into<Asn>>::into));
        AsPathSegment::ConfedSet(Cow::Owned(buffer))
    }
}

impl<'s> AsPathSegment<'s> {
    pub fn borrowed(&self) -> AsPathSegment {
        match self {
            AsPathSegment::AsSequence(x) => AsPathSegment::AsSequence(Cow::Borrowed(&**x)),
            AsPathSegment::AsSet(x) => AsPathSegment::AsSet(Cow::Borrowed(&**x)),
            AsPathSegment::ConfedSequence(x) => AsPathSegment::ConfedSequence(Cow::Borrowed(&**x)),
            AsPathSegment::ConfedSet(x) => AsPathSegment::ConfedSet(Cow::Borrowed(&**x)),
        }
    }

    fn to_static_owned(&self) -> AsPathSegment<'static> {
        match self {
            AsPathSegment::AsSequence(x) => AsPathSegment::AsSequence(Cow::Owned(x.to_vec())),
            AsPathSegment::AsSet(x) => AsPathSegment::AsSet(Cow::Owned(x.to_vec())),
            AsPathSegment::ConfedSequence(x) => {
                AsPathSegment::ConfedSequence(Cow::Owned(x.to_vec()))
            }
            AsPathSegment::ConfedSet(x) => AsPathSegment::ConfedSet(Cow::Owned(x.to_vec())),
        }
    }

    pub fn count_asns(&self) -> usize {
        match self {
            AsPathSegment::AsSequence(v) => v.len(),
            AsPathSegment::AsSet(_) => 1,
            AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_) => 0,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum AsPathStorage {
    /// By far the most common type of AS Path appearing in RIB data is a single sequence of between
    /// 1 to ~20 ASNs. We can optimize for this use case by providing space in the structure for
    /// those ASNs before allocating to the heap. After checking a couple of RIB table dumps,
    /// roughly 75% of AS_PATHs consist of a single sequence with 5 ASNs. By expanding to 16, we
    /// can then hold roughly 99.5% of observed AS_PATH attributes on the stack without allocation.
    SingleSequence(SmallVec<[Asn; 16]>),
    /// Fallback case where we defer to the typical list of generic segments
    Mixed(Vec<AsPathSegment<'static>>),
}

impl AsPathStorage {
    fn switch_to_mixed_storage(
        &mut self,
        preserve_single_sequence: bool,
    ) -> &mut Vec<AsPathSegment<'static>> {
        loop {
            match self {
                AsPathStorage::SingleSequence(seq) => {
                    if preserve_single_sequence {
                        let segment = AsPathSegment::AsSequence(Cow::Owned(seq.to_vec()));
                        *self = AsPathStorage::Mixed(vec![segment]);
                    } else {
                        *self = AsPathStorage::Mixed(Vec::new())
                    }
                }
                AsPathStorage::Mixed(segments) => return segments,
            }
        }
    }
}

pub struct SegmentIterator<'s> {
    storage: &'s AsPathStorage,
    index: usize,
}

impl<'s> Iterator for SegmentIterator<'s> {
    type Item = AsPathSegment<'s>;

    fn next(&mut self) -> Option<Self::Item> {
        self.index += 1;

        match self.storage {
            AsPathStorage::SingleSequence(seq) => {
                (self.index == 1).then(|| AsPathSegment::AsSequence(Cow::Borrowed(&seq[..])))
            }
            AsPathStorage::Mixed(segments) => {
                segments.get(self.index - 1).map(AsPathSegment::borrowed)
            }
        }
    }
}

#[doc(hidden)]
pub enum AsPathSegmentBuilder<'a> {
    #[non_exhaustive]
    InPlace(&'a mut SmallVec<[Asn; 16]>),
    #[non_exhaustive]
    Heap(&'a mut Vec<Asn>),
}

impl<'a> AsPathSegmentBuilder<'a> {
    #[inline(always)]
    pub fn push(&mut self, asn: Asn) {
        match self {
            AsPathSegmentBuilder::InPlace(arr) => arr.push(asn),
            AsPathSegmentBuilder::Heap(arr) => arr.push(asn),
        }
    }
}

pub struct AsPathBuilder {
    storage: AsPathStorage,
    first_sequence: bool,
}

impl AsPathBuilder {
    /// Begin a new AS sequence within this path being built. The given length is used similarly to
    /// [Vec::with_capacity] to perform pre-allocation of the underlying storage.
    #[inline(always)]
    pub fn begin_as_sequence(&mut self, length: usize) -> AsPathSegmentBuilder {
        let storage = &mut self.storage;
        if self.first_sequence {
            if let AsPathStorage::SingleSequence(seq) = storage {
                self.first_sequence = false;
                seq.reserve_exact(length);
                return AsPathSegmentBuilder::InPlace(seq);
            }
        }

        Self::begin_sequence_cold_path(storage, length)
    }

    /// Begin a new AS set within this path being built. The given length is used similarly to
    /// [Vec::with_capacity] to perform pre-allocation of the underlying storage.
    #[cold]
    pub fn begin_as_set(&mut self, length: usize) -> AsPathSegmentBuilder {
        let segments = self.storage.switch_to_mixed_storage(!self.first_sequence);
        segments.push(AsPathSegment::AsSet(Cow::Owned(Vec::with_capacity(length))));

        if let Some(AsPathSegment::AsSet(Cow::Owned(asns))) = segments.last_mut() {
            AsPathSegmentBuilder::Heap(asns)
        } else {
            unreachable!("Last segment will match the item pushed to the vec")
        }
    }

    /// Begin a new confed sequence within this path being built. The given length is used similarly to
    /// [Vec::with_capacity] to perform pre-allocation of the underlying storage.
    #[cold]
    pub fn begin_confed_sequence(&mut self, length: usize) -> AsPathSegmentBuilder {
        let segments = self.storage.switch_to_mixed_storage(!self.first_sequence);
        segments.push(AsPathSegment::ConfedSequence(Cow::Owned(
            Vec::with_capacity(length),
        )));

        if let Some(AsPathSegment::ConfedSequence(Cow::Owned(asns))) = segments.last_mut() {
            AsPathSegmentBuilder::Heap(asns)
        } else {
            unreachable!("Last segment will match the item pushed to the vec")
        }
    }

    /// Begin a new confed set within this path being built. The given length is used similarly to
    /// [Vec::with_capacity] to perform pre-allocation of the underlying storage.
    #[cold]
    pub fn begin_confed_set(&mut self, length: usize) -> AsPathSegmentBuilder {
        let segments = self.storage.switch_to_mixed_storage(!self.first_sequence);
        segments.push(AsPathSegment::ConfedSet(Cow::Owned(Vec::with_capacity(
            length,
        ))));

        if let Some(AsPathSegment::ConfedSet(Cow::Owned(asns))) = segments.last_mut() {
            AsPathSegmentBuilder::Heap(asns)
        } else {
            unreachable!("Last segment will match the item pushed to the vec")
        }
    }

    #[inline]
    pub fn build(self) -> AsPath {
        AsPath {
            storage: self.storage,
        }
    }

    #[cold]
    #[inline(never)]
    fn begin_sequence_cold_path(
        storage: &mut AsPathStorage,
        length: usize,
    ) -> AsPathSegmentBuilder {
        let segments = storage.switch_to_mixed_storage(true);

        segments.push(AsPathSegment::AsSequence(Cow::Owned(Vec::with_capacity(
            length,
        ))));

        if let Some(AsPathSegment::AsSequence(Cow::Owned(asns))) = segments.last_mut() {
            AsPathSegmentBuilder::Heap(asns)
        } else {
            unreachable!("Last segment will match the item pushed to the vec")
        }
    }
}

impl Default for AsPathBuilder {
    fn default() -> Self {
        AsPathBuilder {
            storage: AsPathStorage::SingleSequence(SmallVec::new()),
            first_sequence: true,
        }
    }
}

// TODO: Debug and PartialEq need to be redone
#[derive(Debug, PartialEq, Clone, Eq)]
#[repr(transparent)]
pub struct AsPath {
    storage: AsPathStorage,
}

impl Default for AsPath {
    fn default() -> Self {
        Self::new()
    }
}

impl AsPath {
    pub fn new() -> AsPath {
        AsPath {
            storage: AsPathStorage::Mixed(Vec::new()),
        }
    }

    pub fn builder() -> AsPathBuilder {
        AsPathBuilder::default()
    }

    pub fn iter_segments(&self) -> SegmentIterator {
        SegmentIterator {
            storage: &self.storage,
            index: 0,
        }
    }

    pub fn from_segments<I>(segments: I) -> AsPath
    where
        I: IntoIterator<Item = AsPathSegment<'static>>,
    {
        AsPath {
            // Defer to mixed for simplicity. Performance is not as much of a concern as the builder
            // API is also available for higher performance programs.
            storage: AsPathStorage::Mixed(segments.into_iter().collect()),
        }
    }

    pub fn is_empty(&self) -> bool {
        match &self.storage {
            AsPathStorage::SingleSequence(seq) => seq.is_empty(),
            AsPathStorage::Mixed(segments) => segments.is_empty(),
        }
    }

    pub fn add_segment(&mut self, segment: AsPathSegment<'static>) {
        match &mut self.storage {
            AsPathStorage::SingleSequence(seq) => {
                self.storage = AsPathStorage::Mixed(vec![
                    AsPathSegment::AsSequence(Cow::Owned(seq.to_vec())),
                    segment,
                ]);
            }
            AsPathStorage::Mixed(segments) => segments.push(segment),
        }
    }

    pub fn count_asns(&self) -> usize {
        match &self.storage {
            AsPathStorage::SingleSequence(items) => items.len(),
            AsPathStorage::Mixed(segments) => segments.iter().map(AsPathSegment::count_asns).sum(),
        }
    }

    /// Construct AsPath from AS_PATH and AS4_PATH
    ///
    /// https://datatracker.ietf.org/doc/html/rfc6793#section-4.2.3
    ///    If the number of AS numbers in the AS_PATH attribute is less than the
    ///    number of AS numbers in the AS4_PATH attribute, then the AS4_PATH
    ///    attribute SHALL be ignored, and the AS_PATH attribute SHALL be taken
    ///    as the AS path information.
    ///
    ///    If the number of AS numbers in the AS_PATH attribute is larger than
    ///    or equal to the number of AS numbers in the AS4_PATH attribute, then
    ///    the AS path information SHALL be constructed by taking as many AS
    ///    numbers and path segments as necessary from the leading part of the
    ///    AS_PATH attribute, and then prepending them to the AS4_PATH attribute
    ///    so that the AS path information has a number of AS numbers identical
    ///    to that of the AS_PATH attribute.  Note that a valid
    ///    AS_CONFED_SEQUENCE or AS_CONFED_SET path segment SHALL be prepended
    ///    if it is either the leading path segment or is adjacent to a path
    ///    segment that is prepended.
    pub fn merge_aspath_as4path(aspath: &AsPath, as4path: &AsPath) -> Option<AsPath> {
        if as4path.is_empty() || aspath.count_asns() < as4path.count_asns() {
            return Some(aspath.clone());
        }

        let mut new_segs: Vec<AsPathSegment<'static>> = vec![];

        for (seg, as4seg) in aspath.iter_segments().zip(as4path.iter_segments()) {
            if let (AsPathSegment::AsSequence(seq), AsPathSegment::AsSequence(seq4)) =
                (&seg, &as4seg)
            {
                let diff_len = seq.len() - seq4.len();
                let mut new_seq: Vec<Asn> = vec![];
                new_seq.extend(seq.iter().copied().take(diff_len));
                new_seq.extend(seq4.iter().copied());
                new_segs.push(AsPathSegment::AsSequence(Cow::Owned(new_seq)));
            } else {
                new_segs.push(as4seg.to_static_owned());
            }
        }

        Some(AsPath::from_segments(new_segs))
    }

    pub fn get_origin(&self) -> Option<&[Asn]> {
        match &self.storage {
            AsPathStorage::SingleSequence(seq) => seq.last().map(std::slice::from_ref),
            AsPathStorage::Mixed(segments) => match segments.last()? {
                AsPathSegment::AsSequence(v) => v.last().map(std::slice::from_ref),
                AsPathSegment::AsSet(v) => Some(v.borrow()),
                AsPathSegment::ConfedSequence(_) | AsPathSegment::ConfedSet(_) => None,
            },
        }
    }

    pub fn to_u32_vec(&self) -> Option<Vec<u32>> {
        match &self.storage {
            AsPathStorage::SingleSequence(seq) => {
                Some(seq.iter().copied().map(u32::from).collect())
            }
            AsPathStorage::Mixed(segments) => {
                if !segments
                    .iter()
                    .all(|seg| matches!(seg, AsPathSegment::AsSequence(_v)))
                {
                    // as path contains AS set or confederated sequence/set
                    return None;
                }
                let mut path = vec![];
                for s in segments {
                    if let AsPathSegment::AsSequence(seg) = s {
                        path.extend(seg.iter().copied().map(u32::from));
                    } else {
                        // this won't happen
                        return None;
                    }
                }
                Some(path)
            }
        }
    }
}

impl Display for AsPath {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.iter_segments()
                .map(|seg| match seg {
                    AsPathSegment::AsSequence(v) | AsPathSegment::ConfedSequence(v) =>
                        v.iter().join(" "),
                    AsPathSegment::AsSet(v) | AsPathSegment::ConfedSet(v) => {
                        format!("{{{}}}", v.iter().join(","))
                    }
                })
                .join(" ")
        )
    }
}

impl Serialize for AsPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::bgp::attributes::{AsPath, AsPathSegment};

    #[test]
    fn test_aspath_as4path_merge() {
        let aspath =
            AsPath::from_segments([AsPathSegment::new_as_sequence::<u32, _>([1, 2, 3, 5])]);
        let as4path = AsPath::from_segments([AsPathSegment::new_as_sequence::<u32, _>([2, 3, 7])]);
        let newpath = AsPath::merge_aspath_as4path(&aspath, &as4path).unwrap();
        assert_eq!(
            newpath.iter_segments().next().unwrap(),
            AsPathSegment::new_as_sequence::<u32, _>([1, 2, 3, 7])
        );
    }

    #[test]
    fn test_get_origin() {
        let aspath =
            AsPath::from_segments([AsPathSegment::new_as_sequence::<u32, _>([1, 2, 3, 5])]);
        let origins = aspath.get_origin();
        assert!(origins.is_some());
        assert_eq!(origins.unwrap(), vec![5]);

        let aspath = AsPath::from_segments([
            AsPathSegment::new_as_sequence::<u32, _>([1, 2, 3, 5]),
            AsPathSegment::new_as_set::<u32, _>([7, 8]),
        ]);
        let origins = aspath.get_origin();
        assert!(origins.is_some());
        assert_eq!(origins.unwrap(), vec![7, 8]);
    }

    #[test]
    fn test_aspath_to_vec() {
        let as4path = AsPath::from_segments([AsPathSegment::new_as_sequence::<u32, _>([2, 3, 4])]);
        assert_eq!(as4path.to_u32_vec(), Some(vec![2, 3, 4]));

        let as4path = AsPath::from_segments([
            AsPathSegment::new_as_sequence::<u32, _>([2, 3, 4]),
            AsPathSegment::new_as_sequence::<u32, _>([5, 6, 7]),
        ]);
        assert_eq!(as4path.to_u32_vec(), Some(vec![2, 3, 4, 5, 6, 7]));

        let as4path = AsPath::from_segments([AsPathSegment::new_as_set::<u32, _>([2, 3, 4])]);
        assert_eq!(as4path.to_u32_vec(), None);
    }
}
