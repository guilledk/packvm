# PackVM

A virtual machine for serialising and deserializing arbitrary data formats — one interpreter, pluggable schemas.

1. **Compile once** – Take a schema description (structs, enums, aliases) and turn it into a compact byte‑code program.
2. **Run anywhere** – Feed that program to the PackVM interpreter to pack or unpack values with deterministic rules.
3. **Swap back‑ends freely** – Implement a handful of traits to teach PackVM about a new format, then reuse the same VM core.

PackVM is format‑agnostic by design.

## Quickstart

```
┌──────────────┐ compile + assemble   ┌───────────────┐ exec   ┌─────────────┐
│ Your schema  │ ───────────────────▶ │ byte‑code     │ ─────▶ │ PackVM core │
│ (traits)     │                      │ program       │        │ (runtime)   │
└──────────────┘                      └───────────────┘        └─────────────┘
```


* **Schema provider** – You describe aliases, structs, and enums by implementing a few lightweight traits.  
* **Compiler** – `compile!` & `assemble!` converts that description into a valid `Executable`.
* **Virtual machine** – `packvm::{PackVM, UnpackVM}` executes the program using a small, tail‑call‑friendly interpreter.  

The interpreter is deliberately *format‑blind*; its instruction set manipulates generic `Value`s (booleans, ints, arrays, structs…) without assuming any domain‑specific meaning.

---

## `SourceCode` trait
Below is the minimal trait set required to plug a new format into `PackVM`:

```rust
pub trait TypeAlias {
    fn new_type_name(&self) -> &str;
    fn from_type_name(&self) -> &str;
}

pub trait TypeDef {
    fn name(&self) -> &str;
    fn type_name(&self) -> &str;
}

pub trait EnumDef {
    fn name(&self) -> &str;
    fn variants(&self) -> &[String];
}

pub trait StructDef<T: TypeDef> {
    fn name(&self) -> &str;
    fn fields(&self) -> &[T];
}

pub trait SourceCode<Alias, Type, Enum, Struct>
where
    Alias: TypeAlias,
    Type: TypeDef,
    Enum: EnumDef,
    Struct: StructDef<Type>,
{
    fn structs(&self) -> &[Struct];
    fn enums(&self) -> &[Enum];
    fn aliases(&self) -> &[Alias];
    fn resolve_alias(&self, alias: &str) -> Option<String>;

    // Predicates used by the compiler
    fn is_std_type(&self, ty: &str) -> bool;
    fn is_alias_of(&self, alias: &str, ty: &str) -> bool;
    fn is_variant(&self, ty: &str) -> bool;
    fn is_variant_of(&self, ty: &str, var: &str) -> bool;

    // Convenience method with a default implementation
    fn program_id_for(&self, name: &str) -> Option<usize> { /* … */ }
}
```

## ISA

```rust
pub enum Instruction {
    // IO manipulation, what to pack/unpack next
    Bool,
    UInt{ size: u8 },
    Int{ size: u8 },
    VarUInt,
    VarInt,
    Float{ size: u8 },
    Bytes,  // bytes with LEB128 encoded size first
    BytesRaw{ size: u8},  // raw bytes, if param is > 0 do size check on stack value

    Optional,  // next value is optional, encode a flag as a u8 before
    Extension,  // extensions are like optionals but they dont encode a flag in a u8

    // structure marks

    Section(  // indicates a new program section
        u8,  // struct type: 1 = enum, 2 = struct
        usize  // program id
    ),

    Field(usize),  // indicate field name string id for next value

    // push condition from io into condition stack
    // param is cnd type, 0 = array len, 1 = enum variant
    PushCND(u8),

    // discard condition from stack
    PopCND,

    // jumps
    Jmp { ptr: usize },  // absolute jmp

    // perform absolute jmp and return on next Exit instruction
    JmpRet{ ptr: usize },


    // conditional jumps based on first value on condition stack

    // ptrdelta: ip delta to apply if top cnd stack == value
    // value: condition value to check for
    // delta: delta to apply to top cnd stack value if != value
    JmpCND{ ptrdelta: isize, value: isize, delta: isize },

    // ptrdelta: ip delta to apply if top cnd stack != value
    // value: condition value to check for
    // delta: delta to apply to top cnd stack value if == value
    JmpNotCND{ ptrdelta: isize, value: isize, delta: isize },  // ip delta to apply, condition value, cnd delta to apply

    // exit program or if ptrs remain in the return stack, pop one and jmp to it
    Exit,
}

```