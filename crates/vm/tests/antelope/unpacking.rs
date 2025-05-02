use serde::Serialize;
use serde_json::from_str;
use antelope::{
    chain::{
        abi::{ABI},
        binary_extension::BinaryExtension,
    },
    serializer::{Encoder, Decoder, Packer, PackerError},
    EnumPacker, StructPacker
};
use packvm::{
    PackVM,
    Value,
    IOValue,
    Instruction,
    compiler::{
        compile_type,
        Program,
        SourceCode,
        ProgramNamespace,
        antelope::AntelopeSourceCode,
    },
    compile_source,
    assemble
};
use packvm_macros::{VMStruct, VMEnum};

const TESTABI: &str = include_str!("test_abi.json");

/// Run `PackVM` for the ABI type, feed it the buffer,
/// and assert that the resulting stack equals `$expected`.
macro_rules! unpack_and_assert {
    ($type_name:expr, $bytes:expr, $expected:expr $(,)?) => {{
        let src = AntelopeSourceCode::default();
        let mut program = Program::default();
        compile_type(&src, $type_name, &mut program).expect("failed to compile");
        program.code.push(Instruction::Exit);
        let mut ns = ProgramNamespace::from_source(&src);
        ns.set_program(0, program);
        let exec = assemble!(&ns);
        let mut vm = PackVM::from_executable(&exec);
        let decoded = vm.run_unpack(0, $bytes).expect("Pack failed");
        assert_eq!(*decoded, $expected);
    }};
}

#[test]
fn test_unpack_bool() {
    unpack_and_assert!("bool", &[1u8],  Value::Bool(true));
    unpack_and_assert!("bool", &[0u8],  Value::Bool(false));
}

#[test]
fn test_unpack_uints() {
    unpack_and_assert!("uint8",   &[0x12],                                   Value::Uint8(0x12));
    unpack_and_assert!("uint16",  &[0x34, 0x12],                             Value::Uint16(0x1234));
    unpack_and_assert!("uint32",  &[0x78, 0x56, 0x34, 0x12],                 Value::Uint32(0x12345678));
    unpack_and_assert!(
        "uint64",
        &[0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12],
        Value::Uint64(0x1234567890abcdef)
    );
    unpack_and_assert!(
        "uint128",
        &0x112233445566778899aabbccddeeff00u128.to_le_bytes(),
        Value::Uint128(0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00)
    );
}

#[test]
fn test_unpack_ints() {
    unpack_and_assert!("int8",   &[0xff],                                         Value::Int8(-1));
    unpack_and_assert!("int16",  &[0xfe, 0xff],                                   Value::Int16(-2));
    unpack_and_assert!("int32",  &[0xfd, 0xff, 0xff, 0xff],                       Value::Int32(-3));
    unpack_and_assert!(
        "int64",
        &[0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        Value::Int64(-4)
    );
    unpack_and_assert!(
        "int128",
        &(-5i128).to_le_bytes(),
        Value::Int128(-5)
    );
}

#[test]
fn test_unpack_varuint32() {
    unpack_and_assert!("varuint32", &[0x7F],        Value::VarUInt32(0x7F));
    unpack_and_assert!("varuint32", &[0x80, 0x01],  Value::VarUInt32(0x80));
}

#[test]
fn test_unpack_floats() {
    unpack_and_assert!("float32", &1.0f32.to_le_bytes(), Value::Float32(1.0));
    unpack_and_assert!("float64", &2.0f64.to_le_bytes(), Value::Float64(2.0));
    unpack_and_assert!("float128", &[1u8; 16],           Value::Float128([1u8; 16]));
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
    unpack_and_assert!("string", enc.get_bytes(), Value::Bytes(vec![b'a', b'b', b'c']));
}

#[test]
fn test_unpack_array() {
    let actual: Vec<u32> = vec![1, 2];
    let mut enc = Encoder::new(0);
    actual.pack(&mut enc);
    unpack_and_assert!(
        "uint32[]",
        enc.get_bytes(),
        Value::Array(vec![Value::Uint32(1), Value::Uint32(2)]),
    );
}

#[test]
fn test_unpack_option() {
    let mut enc = Encoder::new(0);
    Some(1u32).pack(&mut enc);
    unpack_and_assert!("uint32?", enc.get_bytes(), Value::Uint32(1));

    let mut enc = Encoder::new(0);
    None::<u32>.pack(&mut enc);
    unpack_and_assert!("uint32?", enc.get_bytes(), Value::None);
}

#[test]
fn test_unpack_extension() {
    let mut enc = Encoder::new(0);
    BinaryExtension::new(Some(1u32)).pack(&mut enc);
    unpack_and_assert!("uint32$", enc.get_bytes(), Value::Uint32(1));

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

    let expected: Value = test.as_io();

    let abi: ABI = from_str(TESTABI).expect("failed to parse ABI JSON");
    let src = AntelopeSourceCode::try_from(abi).expect("failed to convert to SourceCode");
    let ns = compile_source!(src);
    let code = assemble!(&ns);

    let pid = src.program_id_for("test_struct").expect("failed to get program");

    let mut vm = PackVM::from_executable(&code);
    let decoded = vm.run_unpack(pid, enc.get_bytes()).expect("Unpack failed");
    assert_eq!(*decoded, expected);
}