use antelope::chain::abi::ShipABI;
use packvm::compiler::antelope::AntelopeSourceCode;
use packvm::{assemble, compile_source, debug_log};
use serde_json::from_str;

const STD_ABI: &str = include_str!("std_abi.json");

const TEST_ABI: &str = include_str!("test_abi.json");

#[test]
fn test_abi() {
    let abi: ShipABI = from_str(TEST_ABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");

    let src_ns = compile_source!(src);
    let _exec = assemble!(&src_ns).pretty_string();
    debug_log!("{}", _exec);
}

#[test]
fn test_std_abi() {
    let abi: ShipABI = from_str(STD_ABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");

    let src_ns = compile_source!(src);
    let _exec = assemble!(&src_ns).pretty_string();
    debug_log!("{}", _exec);
}
