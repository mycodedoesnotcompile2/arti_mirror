//! Utility to return a random hostname.

use crate::RngExt as _;
use rand::{
    Rng,
    distr::{SampleString as _, slice::Choose},
};

/// The prefix that C Tor uses for fake hostnames, with terminating `.`.
const PREFIX: &str = "www.";

/// The suffix that C Tor uses for fake hostnames, with preceding `.`.
const SUFFIX: &str = ".com";

/// Base32 characters as used by C Tor's fake hostname generator.
const BASE32_CHARS: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', '2', '3', '4', '5', '6', '7',
];

/// Smallest random-label length that C Tor uses.
const MIN_RANDOM_LABEL_LEN: usize = 4;
/// Largest random-label length that C Tor uses.
const MAX_RANDOM_LABEL_LEN: usize = 25;

/// Return a somewhat random-looking hostname.
///
/// The specific format of the hostname is not guaranteed.
pub fn random_hostname<R: Rng>(rng: &mut R) -> String {
    // Mirror C Tor's fake-SNI shape so these names are valid by construction
    // and do not stand out from C Tor's hostnames at the SNI string layer.
    let random_label_len = rng
        .gen_range_checked(MIN_RANDOM_LABEL_LEN..=MAX_RANDOM_LABEL_LEN)
        .expect("Somehow MIN..=MAX wasn't a valid range?");
    let random_label = Choose::new(BASE32_CHARS)
        .expect("BASE32_CHARS was empty!?")
        .sample_string(rng, random_label_len);

    let mut output = String::with_capacity(PREFIX.len() + random_label_len + SUFFIX.len());
    output.push_str(PREFIX);
    output.push_str(&random_label);
    output.push_str(SUFFIX);

    assert_eq!(output.len(), PREFIX.len() + random_label_len + SUFFIX.len());
    output
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

    #[test]
    fn generate_names() {
        let mut rng = testing_rng();

        for _ in 0..100 {
            let name = random_hostname(&mut rng);
            let mut labels = name.split('.');

            assert_eq!(labels.next(), Some("www"));

            let random_label = labels.next().expect("missing random label");
            assert!(random_label.len() >= MIN_RANDOM_LABEL_LEN);
            assert!(random_label.len() <= MAX_RANDOM_LABEL_LEN);
            for ch in random_label.chars() {
                assert!(BASE32_CHARS.contains(&ch));
            }

            assert_eq!(labels.next(), Some("com"));
            assert_eq!(labels.next(), None);
        }
    }
}
