use std::path::Path;
use antelope::chain::abi::ShipABI;
use serde_json::from_str;
use aotc::compile_py_module;
use packvm::compiler::antelope::AntelopeSourceCode;

const TESTABI: &str = include_str!("../../../resources/antelope/test_abi.json");
const STDABI: &str = include_str!("../../../resources/antelope/std_abi.json");

#[test]
fn test_abi() {
    let abi: ShipABI = from_str(TESTABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");

    compile_py_module("testabi", &src, &Path::new("build"), false);
}

#[test]
fn test_std_abi() {
    let abi: ShipABI = from_str(STDABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");

    compile_py_module("stdabi", &src, &Path::new("build"), false);
}
