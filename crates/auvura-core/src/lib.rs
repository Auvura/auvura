pub mod detector;
pub mod detectors;
pub mod policy;
pub mod redactor;
pub mod types;

#[cfg(feature = "ner")]
pub mod ner;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
