use antelope::chain::abi::ShipABI;
use packvm::compiler::antelope::AntelopeSourceCode;
use packvm::{assemble, compile_source, debug_log};
use serde_json::from_str;
use packvm::Executable;

const STD_ABI: &str = include_str!("../../../../resources/antelope/std_abi.json");

const TEST_ABI: &str = include_str!("../../../../resources/antelope/test_abi.json");

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
    let exec = assemble!(&src_ns);
    debug_log!("{}", exec.pretty_string());

    let artifact: Vec<u8> = (&exec).into();

    let dummy_exec = Executable::try_from(artifact.as_slice()).expect("failed to convert to Executable");

    assert_eq!(exec.code.len(), dummy_exec.code.len());
    assert_eq!(exec.str_map.len(), dummy_exec.str_map.len());

    for (k, s) in exec.str_map.iter() {
        let os = dummy_exec.str_map.get_by_left(k).expect("failed to get string map");
        assert_eq!(os, s);
    }

    assert_eq!(exec.var_map, dummy_exec.var_map);
    assert_eq!(exec, dummy_exec);
}
