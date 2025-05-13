pub fn find_all<T>(buffer: &[T], pattern: &[Option<T>]) -> Vec<usize>
where
    T: PartialEq,
{
    let mut locations = Vec::new();

    if pattern.len() > buffer.len() {
        return locations;
    }

    for idx in 0..=buffer.len() - pattern.len() {
        let mut match_found = true;

        for (pattern_idx, pattern_val) in pattern.iter().enumerate() {
            match pattern_val {
                Some(val) if *val != buffer[idx + pattern_idx] => {
                    match_found = false;
                    break;
                }
                _ => {} // value matches or is a wildcard
            }
        }

        if match_found {
            locations.push(idx);
        }
    }

    locations
}

#[macro_export]
macro_rules! pattern {
    // match expressions with comments, no trailing semicolon
    ({ $($val:tt),* $(,)? } $($comment:tt)*) => {
        pattern!($($val),*)
    };

    // match pattern with mixed literals and wildcards
    ($($val:tt),* $(,)?) => {
        &[
            $(
                pattern!(@convert $val)
            ),*
        ]
    };

    // convert empty braces {} to None (wildcard)
    (@convert {}) => {
        None
    };

    // convert literal values to Some(value)
    (@convert $val:expr) => {
        Some($val)
    };
}
