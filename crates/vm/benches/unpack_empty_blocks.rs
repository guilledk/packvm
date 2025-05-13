use std::time::Duration;
use antelope::chain::abi::ShipABI;
use antelope::chain::varint::VarUint32;
use antelope::serializer::{Encoder, Packer};
use antelope::util::hex_to_bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use once_cell::sync::Lazy;
use serde_json::from_str;
use packvm::compiler::antelope::AntelopeSourceCode;
use packvm::{assemble, compile_source, run_unpack, PackVM, Value};
use packvm::compiler::SourceCode;

static SAMPLE: Lazy<Vec<u8>> = Lazy::new(|| {
    hex_to_bytes("99c7555f0000000000ea3055000000000016da8c9c17de0607fb22bbcccdfc2f95b9c85461d7ccde1fc2c097410efec74205e7462bb45dba6e21443ceb7ccd0c68dd9e6dcafddcb6c18b5c0f7d44439dd15b0ea5bf1a1a399e9f3423ad1e6041810cde302e40931adfccded25013000000000000001f56003fdde5c4ead202d7dde4e7af74ae087aed3a699b5cc6745c9aa6beb14f36761919302cdd6a88cf410a8390fbd2cb76dd4ea0441f30b1fee0b781f11e812b02004f0400002a0101001f1678ccbb248596e3aecb7c37fa5569a37db46d7f09563e1231aaa9bed40fac730c2a2eecd58434cb683dbcdd2f854ab4cc854e874f9f8a4a3695971f66e7d6fc0000a102d02a18681500f507a3a200ff0000030000000000ea305500409e9a2264b89a010000000000ea305500000000a8ed3232660000000000ea305550352ab4a9d177570100000001000216321ff9740bec8421cc2b0279c3a1852ea46e1e7b8159df3c937ad44e2fb6d6010000000100000001000216321ff9740bec8421cc2b0279c3a1852ea46e1e7b8159df3c937ad44e2fb6d6010000000000000000ea305500b0cafe4873bd3e010000000000ea305500000000a8ed3232140000000000ea305550352ab4a9d17757809698000000000000ea305500003f2a1ba6a24a010000000000ea305500000000a8ed3232310000000000ea305550352ab4a9d17757a08601000000000004544c4f53000000a08601000000000004544c4f5300000001000081000000100101001f71e1c8ec416f658f0a59d48e435ce9f539a72f980cd922407315277594e6c70f071a86ad33138b3dd37fdfc38434b3254c0dba17625f239de6c7ac7a7e7fb03e000053d02a18681500f507a3a200ff00000100a6823403ea3055000000572d3ccdcd010000000000ea305500000000a8ed3232210000000000ea305550352ab4a9d17757a08601000000000004544c4f53000000000000")
});

fn make_input(n: usize) -> Vec<u8> {
    let mut enc = Encoder::new(SAMPLE.len() * n);
    VarUint32::new(n as u32).pack(&mut enc);
    for _ in 0..n {
        let buf = enc.alloc(SAMPLE.len());
        buf.copy_from_slice(&SAMPLE);
    }
    enc.get_bytes().to_vec()
}

fn bench_unpack(c: &mut Criterion) {
    let abi: ShipABI = from_str(include_str!("../tests/antelope/std_abi.json")).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");
    let ns = compile_source!(src);
    let code = assemble!(&ns);
    let mut vm = PackVM::from_executable(code);

    let sizes = [10_000];

    let mut grp = c.benchmark_group("unpack_signed_block");
    for &n in &sizes {
        let input = make_input(n);
        let pid = src.program_id_for("signed_block[]").unwrap();

        grp.throughput(Throughput::Elements(n as u64));

        grp.bench_with_input(BenchmarkId::from_parameter(n), input.as_slice(), |b, bytes| {
            b.iter(|| {
                let val = run_unpack!(vm, &pid, bytes);
                // cheap sanity check so optimiser can’t elide the work
                assert!(matches!(val, Value::Array(ref v) if v.len() == n));
            });
        });
    }
    grp.finish();
}

criterion_group! {
    name   = benches;
    config = Criterion::default()
        .without_plots()
        .measurement_time(Duration::from_secs(60));
    targets = bench_unpack
}
criterion_main!(benches);
