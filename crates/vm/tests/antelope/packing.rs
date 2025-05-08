use serde::Serialize;
use serde_json::from_str;
use antelope::{chain::{
    abi::{ABI},
    binary_extension::BinaryExtension,
}, name, serializer::{Encoder, Decoder, Packer, PackerError}, EnumPacker, StructPacker};
use antelope::chain::abi::ShipABI;
use antelope::chain::authority::{Authority, KeyWeight};
use antelope::chain::name::Name;
use antelope::chain::public_key::PublicKey;
use packvm::{PackVM, Value, Instruction, compiler::{
    compile_type,
    Program,
    SourceCode,
    ProgramNamespace,
    antelope::AntelopeSourceCode,
}, compile_source, assemble, run_pack};
use packvm::utils::numbers::{U48, Float, Integer, Long};
use packvm_macros::{VMStruct, VMEnum};

const TESTABI: &str = include_str!("test_abi.json");

/// Run `PackVM` for the ABI type, feed it the buffer,
/// and assert that the resulting stack equals `$expected`.
macro_rules! pack_and_assert {
    ($type_name:expr, $value:expr, $expected:expr $(,)?) => {{
        let src = AntelopeSourceCode::default();
        let mut program = Program::default();
        compile_type(&src, $type_name, &mut program).expect("failed to compile");
        program.code.push(Instruction::Exit);
        let mut ns = ProgramNamespace::from_source(&src);
        ns.set_program(U48(1), program);
        let exec = assemble!(&ns);
        let mut vm = PackVM::from_executable(exec);
        let encoded = run_pack!(vm, U48(1), $value);
        assert_eq!(encoded, $expected);
    }};
}

#[test]
fn test_pack_bool() {
    pack_and_assert!("bool", &Value::Bool(true),  &[1u8]);
    pack_and_assert!("bool", &Value::Bool(false), &[0u8]);
}

#[test]
fn test_pack_uints() {
    pack_and_assert!("uint8",   &Value::Int(Integer::from(0x12u8)),                     &[0x12]);
    pack_and_assert!("uint16",  &Value::Int(Integer::from(0x1234u16)),                  &[0x34, 0x12]);
    pack_and_assert!("uint32",  &Value::Int(Integer::from(0x12345678u32)),              &[0x78, 0x56, 0x34, 0x12]);
    pack_and_assert!("uint64",  &Value::Int(Integer::from(0x1234567890abcdefu64)),      &[0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12]);
    pack_and_assert!("uint128", &Value::Long(Long::from(0x112233445566778899aabbccddeeff00u128)),
                     &0x112233445566778899aabbccddeeff00u128.to_le_bytes());
}

#[test]
fn test_pack_ints() {
    pack_and_assert!("int8",   &Value::Int(Integer::from(-1i8)),   &[0xff]);
    pack_and_assert!("int16",  &Value::Int(Integer::from(-2i16)),  &[0xfe, 0xff]);
    pack_and_assert!("int32",  &Value::Int(Integer::from(-3i32)),  &[0xfd, 0xff, 0xff, 0xff]);
    pack_and_assert!("int64",  &Value::Int(Integer::from(-4i64)),  &[0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    pack_and_assert!("int128", &Value::Long(Long::from(-5i128)),   &(-5i128).to_le_bytes());
}

#[test]
fn test_pack_varuint32() {
    pack_and_assert!("varuint32", &Value::VarUInt32(0x7Fu32), &[0x7F]);
    pack_and_assert!("varuint32", &Value::VarUInt32(0x80u32), &[0x80, 0x01]);
}

#[test]
fn test_pack_floats() {
    pack_and_assert!("float32", &Value::Float(Float::from(1.0f32)), &1.0f32.to_le_bytes());
    pack_and_assert!("float64", &Value::Float(Float::from(2.0f64)), &2.0f64.to_le_bytes());
    pack_and_assert!("float128", &Value::Float128([1u8; 16]), &[1u8; 16]);
}

#[test]
fn test_pack_bytes() {
    let mut enc = Encoder::new(0);
    let raw = vec![1u8, 2u8, 3u8];
    raw.pack(&mut enc);
    pack_and_assert!("bytes", &Value::Bytes(raw), enc.get_bytes());
}

#[test]
fn test_pack_string() {
    let mut enc = Encoder::new(0);
    "abc".to_string().pack(&mut enc);
    pack_and_assert!("string", &Value::String("abc".to_string()), enc.get_bytes());
}

#[test]
fn test_pack_array() {
    let mut enc = Encoder::new(0);
    let actual = vec![1u32, 2u32];
    actual.pack(&mut enc);
    pack_and_assert!(
        "uint32[]",
        &Value::Array(vec![Integer::from(1u32).into(), Integer::from(2u32).into()]),
        enc.get_bytes()
    );

    let mut enc = Encoder::new(0);
    let actual: Vec<u32> = Vec::new();
    actual.pack(&mut enc);
    pack_and_assert!(
        "uint32[]",
        &Value::Array(Vec::<Value>::new()),
        enc.get_bytes()
    );
}

#[test]
fn test_pack_option() {
    let mut enc = Encoder::new(0);
    Some(1u32).pack(&mut enc);
    pack_and_assert!("uint32?", &Value::Int(Integer::from(1u32)), enc.get_bytes());

    let mut enc = Encoder::new(0);
    None::<u32>.pack(&mut enc);
    pack_and_assert!("uint32?", &Value::None, enc.get_bytes());
}

#[test]
fn test_pack_extension() {
    pack_and_assert!("uint32$", &Value::Int(Integer::from(1u32)), &[1, 0, 0, 0]);

    let empty: [u8; 0] = [];
    pack_and_assert!("uint32$", &Value::None, &empty);
}

#[test]
fn test_pack_struct() {
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
        field6: TestEnum::Type2(TestStructV2 {field: "type2".to_string()}),
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

    let val: Value = test.into();

    let abi: ABI = from_str(TESTABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");
    let ns = compile_source!(src);
    let code = assemble!(&ns);

    let pid = src.program_id_for("test_struct").expect("failed to get program");

    let mut vm = PackVM::from_executable(code);
    let encoded = run_pack!(vm, pid, &val);
    assert_eq!(encoded, enc.get_bytes());
}

const STDABI: &str = include_str!("std_abi.json");

#[test]
fn test_pack_get_status_request_v0() {

    #[derive(Default, Serialize, PartialEq, Debug, VMStruct)]
    #[vm_name = "get_status_request_v0"]
    struct GetStatusRequestV0;
    impl Packer for GetStatusRequestV0 {
        fn size(&self) -> usize {
            0
        }

        fn pack(&self, _enc: &mut Encoder) -> usize {
            0
        }

        fn unpack(&mut self, _data: &[u8]) -> Result<usize, PackerError> {
            Ok(0)
        }
    }

    #[derive(Serialize, PartialEq, Debug, EnumPacker, VMEnum)]
    #[vm_name = "request"]
    enum Request {
        GetStatus(GetStatusRequestV0),
    }

    let test = Request::GetStatus(GetStatusRequestV0);
    let mut encoder = Encoder::new(0);
    test.pack(&mut encoder);

    let input: Value = test.into();

    let abi: ShipABI = from_str(STDABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");
    let ns = compile_source!(src);
    let code = assemble!(&ns);

    let pid = src.program_id_for("request").expect("failed to get program");
    let mut vm = PackVM::from_executable(code);
    let encoded = run_pack!(vm, pid, &input);

    assert_eq!(encoded.as_slice(), encoder.get_bytes());
}

const EOSIOABI: &str = include_str!("eosio.system.json");

#[test]
fn test_pack_newaccount() {

    #[derive(Clone, Default, Serialize, PartialEq, Debug, StructPacker, VMStruct)]
    struct NewAccountParams {
        creator: Name,
        name: Name,
        owner: Authority,
        active: Authority
    }

    let mut encoder = Encoder::new(0);
    let params = NewAccountParams {
        creator: name!("eosio"),
        name: name!("testaccount"),
        owner: Authority {
            threshold: 1,
            keys: vec![
                KeyWeight {
                    key: PublicKey::new_from_str("PUB_K1_7QsTidrSZpjBWi2dwhXZriaNKPjCB2dxcmETF91cEpoJtCwfcm").unwrap(),
                    weight: 1,
                }
            ],
            accounts: vec![],
            waits: vec![],
        },
        active: Authority {
            threshold: 1,
            keys: vec![
                KeyWeight {
                    key: PublicKey::new_from_str("PUB_K1_7QsTidrSZpjBWi2dwhXZriaNKPjCB2dxcmETF91cEpoJtCwfcm").unwrap(),
                    weight: 1,
                }
            ],
            accounts: vec![],
            waits: vec![],
        }
    };
    let value: Value = params.clone().into();
    params.pack(&mut encoder);
    let params_raw = encoder.get_bytes().to_vec();

    let abi: ABI = from_str(EOSIOABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");
    let ns = compile_source!(src);
    let code = assemble!(&ns);

    let pid = src.program_id_for("newaccount").expect("failed to get program");
    let mut vm = PackVM::from_executable(code);
    let encoded = run_pack!(vm, pid, &value);

    assert_eq!(encoded, params_raw);

    // let action = Action {
    //     account: name!("eosio"),
    //     name: name!("newaccount"),
    //     authorization: vec![
    //         PermissionLevel {actor: name!("eosio"), permission: name!("active")}
    //     ],
    //     data: encoder.get_bytes().to_vec(),
    // };
}