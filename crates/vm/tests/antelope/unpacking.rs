use antelope::chain::abi::ShipABI;
use antelope::chain::key_type::{KeyType, KeyTypeTrait};
use antelope::chain::signature::Signature;
use antelope::util::hex_to_bytes;
use antelope::{
    chain::{abi::ABI, binary_extension::BinaryExtension},
    serializer::{Decoder, Encoder, Packer, PackerError},
    EnumPacker, StructPacker,
};
use packvm::isa::diff_values;
use packvm::utils::numbers::{Float, Integer, Long};
use packvm::{
    assemble, compile_source,
    compiler::{antelope::AntelopeSourceCode, compile_type, ProgramNamespace, SourceCode},
    run_pack, run_unpack, Instruction, PackVM, Value,
};
use packvm_macros::{VMEnum, VMStruct};
use serde::Serialize;
use serde_json::from_str;

const TESTABI: &str = include_str!("test_abi.json");

/// Run `PackVM` for the ABI type, feed it the buffer,
/// and assert that the resulting stack equals `$expected`.
macro_rules! unpack_and_assert {
    ($type_name:expr, $bytes:expr, $expected:expr $(,)?) => {{
        // create dummy namespace
        let src = AntelopeSourceCode::default();
        let mut ns = ProgramNamespace::from_source(&src);

        // create dummy program
        let mut program = Default::default();

        // do the equivalent of compile_program
        compile_type(&src, $type_name, &mut program).unwrap_or_else(|e| panic!("{}", e.reason));
        program.code.push(Instruction::Exit);

        ns.set_program(program.clone());

        // finally assemble and run
        let exec = assemble!(&ns);
        let mut vm = PackVM::from_executable(exec);
        let decoded = run_unpack!(vm, program.id, $bytes);

        // compare result with expected
        assert_eq!(decoded, $expected);
    }};
}

#[test]
fn test_unpack_bool() {
    unpack_and_assert!("bool", &[1u8], Value::Bool(true));
    unpack_and_assert!("bool", &[0u8], Value::Bool(false));
}

#[test]
fn test_unpack_uints() {
    unpack_and_assert!("uint8", &[0x12], Value::Int(Integer::from(0x12u8)));
    unpack_and_assert!(
        "uint16",
        &[0x34, 0x12],
        Value::Int(Integer::from(0x1234u16))
    );
    unpack_and_assert!(
        "uint32",
        &[0x78, 0x56, 0x34, 0x12],
        Value::Int(Integer::from(0x12345678u32))
    );
    unpack_and_assert!(
        "uint64",
        &[0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12],
        Value::Int(Integer::from(0x1234567890abcdefu64))
    );
    unpack_and_assert!(
        "uint128",
        &0x112233445566778899aabbccddeeff00u128.to_le_bytes(),
        Value::Long(Long::from(0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128))
    );
}

#[test]
fn test_unpack_ints() {
    unpack_and_assert!("int8", &[0xff], Value::Int(Integer::from(-1i8)));
    unpack_and_assert!("int16", &[0xfe, 0xff], Value::Int(Integer::from(-2i16)));
    unpack_and_assert!(
        "int32",
        &[0xfd, 0xff, 0xff, 0xff],
        Value::Int(Integer::from(-3i32))
    );
    unpack_and_assert!(
        "int64",
        &[0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        Value::Int(Integer::from(-4i64))
    );
    unpack_and_assert!(
        "int128",
        &(-5i128).to_le_bytes(),
        Value::Long(Long::from(-5i128))
    );
}

#[test]
fn test_unpack_varuint32() {
    unpack_and_assert!("varuint32", &[0x7F], Value::Int(Integer::from(0x7Fu32)));
    unpack_and_assert!(
        "varuint32",
        &[0x80, 0x01],
        Value::Int(Integer::from(0x80u32))
    );
}

#[test]
fn test_unpack_floats() {
    unpack_and_assert!(
        "float32",
        &1.0f32.to_le_bytes(),
        Value::Float(Float::from(1.0f32))
    );
    unpack_and_assert!(
        "float64",
        &2.0f64.to_le_bytes(),
        Value::Float(Float::from(2.0f64))
    );
    unpack_and_assert!("float128", &[1u8; 16], Value::Bytes([1u8; 16].to_vec()));
}

#[test]
fn test_unpack_bytes() {
    let mut enc = Encoder::new(0);
    vec![1u8, 2u8, 3u8].pack(&mut enc);
    unpack_and_assert!("bytes", enc.get_bytes(), Value::Bytes(vec![1, 2, 3]));
}

#[test]
fn test_unpack_string() {
    let mut enc = Encoder::new(0);
    "abc".to_string().pack(&mut enc);
    unpack_and_assert!("string", enc.get_bytes(), Value::String("abc".to_string()));
}

#[test]
fn test_unpack_array() {
    let mut enc = Encoder::new(0);
    vec![1u32, 2u32].pack(&mut enc);
    unpack_and_assert!(
        "uint32[]",
        enc.get_bytes(),
        Value::Array(vec![Integer::from(1u32).into(), Integer::from(2u32).into()]),
    );

    let mut enc = Encoder::new(0);
    Vec::<u32>::new().pack(&mut enc);
    unpack_and_assert!("uint32[]", enc.get_bytes(), Value::Array(vec![]),);
}

#[test]
fn test_unpack_option() {
    let mut enc = Encoder::new(0);
    Some(1u32).pack(&mut enc);
    unpack_and_assert!("uint32?", enc.get_bytes(), Value::Int(Integer::from(1u32)));

    let mut enc = Encoder::new(0);
    None::<u32>.pack(&mut enc);
    unpack_and_assert!("uint32?", enc.get_bytes(), Value::None);
}

#[test]
fn test_unpack_extension() {
    let mut enc = Encoder::new(0);
    BinaryExtension::new(Some(1u32)).pack(&mut enc);
    unpack_and_assert!("uint32$", enc.get_bytes(), Value::Int(Integer::from(1u32)));

    let mut enc = Encoder::new(0);
    BinaryExtension::<u32>::new(None).pack(&mut enc);
    unpack_and_assert!("uint32$", enc.get_bytes(), Value::None);

    unpack_and_assert!("uint32$", &[], Value::None);
}

#[test]
fn test_unpack_struct() {
    #[derive(Default, Serialize, PartialEq, Debug, StructPacker, VMStruct)]
    #[vm_name = "test_enum_v0"]
    struct TestStructV0 {
        field: u64,
    }

    #[derive(Default, Serialize, PartialEq, Debug, StructPacker, VMStruct)]
    #[vm_name = "test_enum_v1"]
    struct TestStructV1 {
        field: f64,
    }

    #[derive(Default, Serialize, PartialEq, Debug, StructPacker, VMStruct)]
    #[vm_name = "test_enum_v2"]
    struct TestStructV2 {
        field: String,
    }

    #[derive(Serialize, PartialEq, Debug, EnumPacker, VMEnum)]
    #[vm_name = "test_enum"]
    enum TestEnum {
        Type0(TestStructV0),
        Type1(TestStructV1),
        Type2(TestStructV2),
    }

    #[derive(Serialize, PartialEq, Debug, StructPacker, VMStruct)]
    #[vm_name = "test_struct"]
    struct TestStruct {
        field0: bool,
        field1: u32,
        field2: i32,
        field3: f32,
        field4: Vec<String>,
        field5: Option<Vec<u8>>,
        field6: TestEnum,
        field7: bool,
        field8: u32,
        field9: i32,
        field10: f32,
        field11: Option<String>,
        field12: Option<Vec<u8>>,
        field13: Option<u128>,
        field_end0: BinaryExtension<u128>,
        field_end1: BinaryExtension<u128>,
    }

    let mut enc = Encoder::new(0);
    let test = TestStruct {
        field0: true,
        field1: 420,
        field2: 420,
        field3: 42.0,
        field4: vec![
            "first".to_string(),
            "second".to_string(),
            "third".to_string(),
            "fourth".to_string(),
        ],
        field5: Some(vec![1, 2, 3, 4, 5]),
        field6: TestEnum::Type2(TestStructV2 {
            field: "type2".to_string(),
        }),
        field7: false,
        field8: 69,
        field9: 69,
        field10: 6.9,
        field11: Some("IADJIASJDAJSD".to_string()),
        field12: Some("afsafasfasf".as_bytes().to_vec()),
        field13: None,
        field_end0: BinaryExtension::<u128>::new(Some(4206942u128)),
        field_end1: BinaryExtension::<u128>::new(None),
    };
    test.pack(&mut enc);

    let expected: Value = test.into();

    let abi: ABI = from_str(TESTABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");
    let ns = compile_source!(src);
    let code = assemble!(&ns);

    let pid = src
        .program_id_for("test_struct")
        .expect("failed to get program");

    let mut vm = PackVM::from_executable(code);
    let decoded = run_unpack!(vm, pid, enc.get_bytes());

    if let Some(diffs) = diff_values(&decoded, &expected) {
        println!("Expected: {expected:#?}");
        println!("Actual:   {decoded:#?}");
        println!("{diffs:?}");
    }

    assert_eq!(decoded, expected);
}

const STDABI: &str = include_str!("std_abi.json");

#[test]
fn test_unpack_result() {
    let encoded = hex_to_bytes("011700000000000017d1359487a1d12277aec6a0d50207a7fa3a46a0b18ad11a6a093594b4150000000000001522ebe6ddc1f00b426e69faa006026c7dcf59815d0282cb579c8e21d1010a0000000000000ac54a7ca25f05f01a1caa35040d73e8a1298fbfadc9ad3bf18694243a010900000000000009485ad52d4d4d387b27c562a911790007288231fc107f80c77ebee29b01b801be92725e0000000000ea3055000000000009485ad52d4d4d387b27c562a911790007288231fc107f80c77ebee29b0000000000000000000000000000000000000000000000000000000000000000d007eefcb4c20a0ee78d2dfe8446527d91ab984240edea8fc5a7062100e4dedb00000000000000202ea20c87518fc9bfa42deb7bb1791e81657cca8c52f30042960690b480cd067e2b454c73eebda1087394fbffc9a606043fd89f8a4601abeedebd853873e5c9fa00000000");

    let abi: ShipABI = from_str(STDABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");
    let ns = compile_source!(src);
    let code = assemble!(&ns);

    let pid = src.program_id_for("result").expect("failed to get program");

    let mut vm = PackVM::from_executable(code);
    run_unpack!(vm, pid, encoded.as_slice());
}

#[test]
fn test_unpack_signature() {
    let encoded = hex_to_bytes("001f56003fdde5c4ead202d7dde4e7af74ae087aed3a699b5cc6745c9aa6beb14f36761919302cdd6a88cf410a8390fbd2cb76dd4ea0441f30b1fee0b781f11e812b02");

    let mut dec = Decoder::new(encoded.as_slice());
    let mut sig = Signature::default();
    dec.unpack(&mut sig).expect("failed to unpack signature");

    let abi: ShipABI = from_str(TESTABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");
    let ns = compile_source!(src);
    let code = assemble!(&ns);

    let pid = src
        .program_id_for("test_sig")
        .expect("failed to get program");

    let mut vm = PackVM::from_executable(code);
    let decoded = run_unpack!(vm, pid, encoded.as_slice());
    let dec_sig: Signature = if let Value::Struct(map) = decoded {
        let sig_field = map.get("sig").expect("failed to get sig field");
        if let Value::Bytes(raw_sig) = sig_field {
            Signature::from_bytes(
                raw_sig[1..].to_vec(),
                KeyType::from_index(raw_sig[0]).unwrap(),
            )
        } else {
            panic!("failed to unpack signature expected bytes: {sig_field:?}");
        }
    } else {
        panic!("failed to unpack signature expected map: {decoded:?}");
    };

    assert_eq!(sig, dec_sig);
}

const SIGBLOCKABI: &str = include_str!("signed_block_abi.json");

#[test]
fn test_unpack_signed_block() {
    /*
       {
        "previous": "00000016da8c9c17de0607fb22bbcccdfc2f95b9c85461d7ccde1fc2c097410e",
        "new_producers": null,
        "header_extensions": [],
        "timestamp": 1599457177,
        "schedule_version": 0,
        "action_mroot": "439dd15b0ea5bf1a1a399e9f3423ad1e6041810cde302e40931adfccded25013",
        "producer": 6138663577826885632,
        "producer_signature": "001f56003fdde5c4ead202d7dde4e7af74ae087aed3a699b5cc6745c9aa6beb14f36761919302cdd6a88cf410a8390fbd2cb76dd4ea0441f30b1fee0b781f11e812b",
        "block_extensions": [],
        "transaction_mroot": "fec74205e7462bb45dba6e21443ceb7ccd0c68dd9e6dcafddcb6c18b5c0f7d44",
        "transactions": [
            {
                "cpu_usage_us": 1103,
                "net_usage_words": 42,
                "status": 0,
                "trx": {
                    "packed_context_free_data": "",
                    "signatures": [
                        "001f1678ccbb248596e3aecb7c37fa5569a37db46d7f09563e1231aaa9bed40fac730c2a2eecd58434cb683dbcdd2f854ab4cc854e874f9f8a4a3695971f66e7d6fc"
                    ],
                    "packed_trx": "d02a18681500f507a3a200ff0000030000000000ea305500409e9a2264b89a010000000000ea305500000000a8ed3232660000000000ea305550352ab4a9d177570100000001000216321ff9740bec8421cc2b0279c3a1852ea46e1e7b8159df3c937ad44e2fb6d6010000000100000001000216321ff9740bec8421cc2b0279c3a1852ea46e1e7b8159df3c937ad44e2fb6d6010000000000000000ea305500b0cafe4873bd3e010000000000ea305500000000a8ed3232140000000000ea305550352ab4a9d17757809698000000000000ea305500003f2a1ba6a24a010000000000ea305500000000a8ed3232310000000000ea305550352ab4a9d17757a08601000000000004544c4f53000000a08601000000000004544c4f530000000100",
                    "type": 1,
                    "compression": 0
                }
            },
            {
                "trx": {
                    "compression": 0,
                    "packed_trx": "d02a18681500f507a3a200ff00000100a6823403ea3055000000572d3ccdcd010000000000ea305500000000a8ed3232210000000000ea305550352ab4a9d17757a08601000000000004544c4f530000000000",
                    "type": 1,
                    "packed_context_free_data": "",
                    "signatures": [
                        "001f71e1c8ec416f658f0a59d48e435ce9f539a72f980cd922407315277594e6c70f071a86ad33138b3dd37fdfc38434b3254c0dba17625f239de6c7ac7a7e7fb03e"
                    ]
                },
                "status": 0,
                "cpu_usage_us": 129,
                "net_usage_words": 16
            }
        ],
        "confirmed": 0
    }
         */
    let encoded = hex_to_bytes("99c7555f0000000000ea3055000000000016da8c9c17de0607fb22bbcccdfc2f95b9c85461d7ccde1fc2c097410efec74205e7462bb45dba6e21443ceb7ccd0c68dd9e6dcafddcb6c18b5c0f7d44439dd15b0ea5bf1a1a399e9f3423ad1e6041810cde302e40931adfccded25013000000000000001f56003fdde5c4ead202d7dde4e7af74ae087aed3a699b5cc6745c9aa6beb14f36761919302cdd6a88cf410a8390fbd2cb76dd4ea0441f30b1fee0b781f11e812b02004f0400002a0101001f1678ccbb248596e3aecb7c37fa5569a37db46d7f09563e1231aaa9bed40fac730c2a2eecd58434cb683dbcdd2f854ab4cc854e874f9f8a4a3695971f66e7d6fc0000a102d02a18681500f507a3a200ff0000030000000000ea305500409e9a2264b89a010000000000ea305500000000a8ed3232660000000000ea305550352ab4a9d177570100000001000216321ff9740bec8421cc2b0279c3a1852ea46e1e7b8159df3c937ad44e2fb6d6010000000100000001000216321ff9740bec8421cc2b0279c3a1852ea46e1e7b8159df3c937ad44e2fb6d6010000000000000000ea305500b0cafe4873bd3e010000000000ea305500000000a8ed3232140000000000ea305550352ab4a9d17757809698000000000000ea305500003f2a1ba6a24a010000000000ea305500000000a8ed3232310000000000ea305550352ab4a9d17757a08601000000000004544c4f53000000a08601000000000004544c4f5300000001000081000000100101001f71e1c8ec416f658f0a59d48e435ce9f539a72f980cd922407315277594e6c70f071a86ad33138b3dd37fdfc38434b3254c0dba17625f239de6c7ac7a7e7fb03e000053d02a18681500f507a3a200ff00000100a6823403ea3055000000572d3ccdcd010000000000ea305500000000a8ed3232210000000000ea305550352ab4a9d17757a08601000000000004544c4f53000000000000");

    let abi: ShipABI = from_str(SIGBLOCKABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");
    let ns = compile_source!(src);
    let code = assemble!(&ns);

    let pid = src
        .program_id_for("signed_block")
        .expect("failed to get program");

    let mut vm = PackVM::from_executable(code);
    let decoded = run_unpack!(vm, pid, encoded.as_slice()).clone();
    let re_encoded = run_pack!(vm, pid, &decoded);

    assert_eq!(re_encoded, encoded);

    let re_decoded = run_unpack!(vm, pid, re_encoded.as_slice());
    assert_eq!(re_decoded, decoded);
}
