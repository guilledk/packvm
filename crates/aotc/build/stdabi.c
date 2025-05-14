#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#  error "little-endian host required"
#endif
#ifndef __SIZEOF_INT128__
#  error "int128 compiler support required"
#endif

static inline uint16_t read_le16(const char *p)
{
    return *(const uint16_t *)p;
}

static inline uint32_t read_le32(const char *p)
{
    return *(const uint32_t *)p;
}

static inline uint64_t read_le64(const char *p)
{
    return *(const uint64_t *)p;
}

static inline __attribute__((always_inline, hot, pure))
unsigned long long decode_uleb128(const char *restrict p, size_t *consumed)
{
    const unsigned char *s = (const unsigned char *)p;
    unsigned long long   r = 0;
    unsigned             shift = 0;
    unsigned char        b;

    /* first byte (-90 % of the time) */
    b  = *s++;
    r  =  b & 0x7F;
    if (!(b & 0x80)) {
        if (consumed) *consumed = 1;
        return r;
    }
    shift = 7;

    /* remaining bytes (rare) */
    while ( (b = *s++) & 0x80 ) {
        r |= ((unsigned long long)(b & 0x7F)) << shift;
        shift += 7;
    }
    r |= ((unsigned long long)b) << shift;

    if (consumed) *consumed = (size_t)(s - (const unsigned char *)p);
    return r;
}

static inline __attribute__((always_inline, hot, pure))
long long decode_sleb128(const char *restrict p, size_t *consumed)
{
    const unsigned char *s = (const unsigned char *)p;
    long long           r = 0;
    unsigned            shift = 0;
    unsigned char       b;

    /* first byte fast-path */
    b  = *s++;
    r  =  b & 0x7F;
    if (!(b & 0x80)) {
        if (b & 0x40)   /* sign-extend negative single-byte values */
            r |= -1LL << 7;
        if (consumed) *consumed = 1;
        return r;
    }
    shift = 7;

    /* remaining bytes */
    while ( (b = *s++) & 0x80 ) {
        r |= ((long long)(b & 0x7F)) << shift;
        shift += 7;
    }
    r |= ((long long)b & 0x7F) << shift;

    /* final sign-extension if negative */
    if ((b & 0x40) && (shift + 7 < sizeof(long long) * 8))
        r |= -1LL << (shift + 7);

    if (consumed) *consumed = (size_t)(s - (const unsigned char *)p);
    return r;
}

static inline PyObject *
u128_to_pylong(unsigned __int128 v)
{
    char buf[35];
    snprintf(buf,
             sizeof buf,
             "0x%016llx%016llx",
             (unsigned long long)(v >> 64),
             (unsigned long long)v);
    return PyLong_FromString(buf, NULL, 0);
}

static inline PyObject *unpack_bool (const char *b, size_t buf_len, size_t *c, size_t depth)
{ if (c) *c = 1;  return PyBool_FromLong(b[0] != 0); }

static inline PyObject *unpack_u8   (const char *b, size_t buf_len, size_t *c, size_t depth)
{ if (c) *c = 1;  return PyLong_FromUnsignedLong((unsigned char)b[0]); }

static inline PyObject *unpack_i8   (const char *b, size_t buf_len, size_t *c, size_t depth)
{ if (c) *c = 1;  return PyLong_FromLong((signed char)b[0]); }

static inline PyObject *unpack_u16  (const char *b, size_t buf_len, size_t *c, size_t depth)
{ if (c) *c = 2;  return PyLong_FromUnsignedLong(read_le16(b)); }

static inline PyObject *unpack_i16  (const char *b, size_t buf_len, size_t *c, size_t depth)
{ if (c) *c = 2;  return PyLong_FromLong((int16_t)read_le16(b)); }

static inline PyObject *unpack_u32  (const char *b, size_t buf_len, size_t *c, size_t depth)
{ if (c) *c = 4;  return PyLong_FromUnsignedLong(read_le32(b)); }

static inline PyObject *unpack_i32  (const char *b, size_t buf_len, size_t *c, size_t depth)
{ if (c) *c = 4;  return PyLong_FromLong((int32_t)read_le32(b)); }

static inline PyObject *unpack_u64  (const char *b, size_t buf_len, size_t *c, size_t depth)
{ if (c) *c = 8;  return PyLong_FromUnsignedLongLong(read_le64(b)); }

static inline PyObject *unpack_i64  (const char *b, size_t buf_len, size_t *c, size_t depth)
{ if (c) *c = 8;  return PyLong_FromLongLong((int64_t)read_le64(b)); }

static inline PyObject *unpack_u128 (const char *b, size_t buf_len, size_t *c, size_t depth)
{
    if (c) *c = 16;
    unsigned __int128 v =
        ((unsigned __int128)read_le64(b + 8) << 64) | read_le64(b);
    return u128_to_pylong(v);
}
static inline PyObject *unpack_i128(const char *b, size_t buf_len, size_t *c, size_t depth){
    if (c) *c = 16; __int128 v; /* signed */
    memcpy(&v, b, 16); /* avoids the &-on-temporary */
    return u128_to_pylong((unsigned __int128)v); /* quick & dirty -- adjust if you need signed range */
}

static inline PyObject *unpack_uleb128(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    unsigned long long v = decode_uleb128(b, c);
    return PyLong_FromUnsignedLongLong(v);
}

static inline PyObject *unpack_sleb128(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    long long v = decode_sleb128(b, c);
    return PyLong_FromLongLong(v);
}

static inline PyObject *unpack_f32  (const char *b, size_t buf_len, size_t *c, size_t depth)
{
    if (c) *c = 4;
    float f;
    memcpy(&f, b, 4);
    return PyFloat_FromDouble((double)f);
}

static inline PyObject *unpack_f64  (const char *b, size_t buf_len, size_t *c, size_t depth)
{
    if (c) *c = 8;
    double d;
    memcpy(&d, b, 8);
    return PyFloat_FromDouble(d);
}

static inline PyObject *unpack_raw(const char *b, size_t len, size_t buf_len, size_t *c, size_t depth)
{
    if (c) *c = len;
    return PyBytes_FromStringAndSize(b, len);
}

static inline PyObject *unpack_bytes(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    size_t len_consumed = 0;
    unsigned long long l = decode_uleb128(b, &len_consumed);

    #ifdef __PACKVM_DEBUG
        for (int i = 0; i < depth; i++) {
            PySys_WriteStdout("\t");
        }
        PySys_WriteStdout("leb consumed: %lu\n", len_consumed);
        for (int i = 0; i < depth; i++) {
            PySys_WriteStdout("\t");
        }
        PySys_WriteStdout("about to unpack bytes of size: %llu\n", l);
    #endif

    if (l > PY_SSIZE_T_MAX ||
        l > (unsigned long long)(buf_len - len_consumed)) {
        PyErr_SetString(PyExc_ValueError, "buffer too small for encoded length");
        return NULL;
    }

    if (c) *c = len_consumed + (size_t)l;
    return PyBytes_FromStringAndSize(b + len_consumed, (Py_ssize_t)l);
}

static inline PyObject *unpack_str(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    size_t len_consumed = 0;
    unsigned long long l = decode_uleb128(b, &len_consumed);

    if (l > PY_SSIZE_T_MAX ||
        l > (unsigned long long)(buf_len - len_consumed)) {
        PyErr_SetString(PyExc_ValueError, "buffer too small for encoded length");
        return NULL;
    }

    if (c) *c = len_consumed + (size_t)l;
    return PyUnicode_DecodeUTF8(b + len_consumed, (Py_ssize_t)l, "strict");
}

// forward declarations

static inline PyObject *unpack_asset(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_extended_asset(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_abi_struct_field(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_abi_struct(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_abi_type(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_abi_action(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_abi_variant(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_abi_table(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_abi_clause(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_abi_result(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_abi(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_get_status_request_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_block_position(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_get_status_result_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_get_blocks_request_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_get_blocks_ack_request_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_get_blocks_result_v0_header(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_get_blocks_result_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_row(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_table_delta_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_action(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_account_auth_sequence(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_action_receipt_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_account_delta(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_action_trace_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_action_trace_v1(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_partial_transaction_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_transaction_trace_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_packed_transaction(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_transaction_receipt_header(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_transaction_receipt(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_extension(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_block_header(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_signed_block_header(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_signed_block(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_transaction_header(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_transaction(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_signed_transaction(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_code_id(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_account_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_account_metadata_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_code_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_table_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_row_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_index64_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_index128_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_index256_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_index_double_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_index_long_double_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_producer_key(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_producer_schedule(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_block_signing_authority_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_producer_authority(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_producer_authority_schedule(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_chain_config_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_chain_config_v1(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_wasm_config_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_global_property_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_global_property_v1(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_generated_transaction_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_activated_protocol_feature_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_protocol_state_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_key_weight(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_permission_level(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_permission_level_weight(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_wait_weight(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_authority(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_permission_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_permission_link_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_resource_limits_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_usage_accumulator_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_resource_usage_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_resource_limits_state_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_resource_limits_ratio_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_elastic_limit_parameters_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_resource_limits_config_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_request(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_result(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_action_receipt(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_action_trace(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_partial_transaction(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_transaction_trace(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_transaction_variant(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_table_delta(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_account(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_account_metadata(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_code(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_table(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_row(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_index64(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_index128(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_index256(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_index_double(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_contract_index_long_double(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_chain_config(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_wasm_config(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_global_property(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_generated_transaction(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_activated_protocol_feature(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_protocol_state(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_permission(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_permission_link(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_resource_limits(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_usage_accumulator(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_resource_usage(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_resource_limits_state(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_resource_limits_ratio(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_elastic_limit_parameters(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_resource_limits_config(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_block_signing_authority(const char *b, size_t buf_len, size_t *c, size_t depth);


static inline PyObject *unpack_uint8(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_uint16(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_uint32(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_uint64(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_uint128(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_int8(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_int16(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_int32(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_int64(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_int128(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_varuint32(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_varint32(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_float32(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_float64(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_float128(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_string(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_name(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_account_name(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_symbol(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_symbol_code(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_rd160(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_checksum160(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_sha256(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_checksum256(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_checksum512(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_time_point(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_time_point_sec(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_block_timestamp_type(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_public_key(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_signature(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_transaction_id(const char *b, size_t buf_len, size_t *c, size_t depth);



static inline PyObject *
unpack_asset(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct asset:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "amount",
            "i64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field amount: i64
    PyObject *amount = unpack_i64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!amount) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("amount start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "symbol",
            "u64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field symbol: u64
    PyObject *symbol = unpack_u64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!symbol) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("symbol start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "amount", amount) < 0) goto error;
    if (PyDict_SetItemString(__dict, "symbol", symbol) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(amount);
    Py_DECREF(symbol);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking asset");
    Py_XDECREF(amount);
    Py_XDECREF(symbol);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_extended_asset(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct extended_asset:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "quantity",
            "asset",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field quantity: asset
    PyObject *quantity = unpack_asset(b + __total, buf_len, &__consumed, __depth + 1);

    if (!quantity) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("quantity start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "contract",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field contract: name
    PyObject *contract = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!contract) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("contract start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "quantity", quantity) < 0) goto error;
    if (PyDict_SetItemString(__dict, "contract", contract) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(quantity);
    Py_DECREF(contract);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking extended_asset");
    Py_XDECREF(quantity);
    Py_XDECREF(contract);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_abi_struct_field(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct abi_struct_field:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "name",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field name: string
    PyObject *name = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "type",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field type: string
    PyObject *type = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!type) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("type start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "name", name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "type", type) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(name);
    Py_DECREF(type);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking abi_struct_field");
    Py_XDECREF(name);
    Py_XDECREF(type);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_abi_struct(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct abi_struct:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "name",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field name: string
    PyObject *name = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "base",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field base: string
    PyObject *base = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!base) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("base start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "fields",
            "abi_struct_field",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field fields: abi_struct_field[]
    size_t __len_fields = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *fields = PyList_New(__len_fields);
    if (!fields) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_fields);
    #endif

    for (size_t _i = 0; _i < __len_fields; ++_i) {
        PyObject *_item = unpack_abi_struct_field(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(fields); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(fields, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "name", name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "base", base) < 0) goto error;
    if (PyDict_SetItemString(__dict, "fields", fields) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(name);
    Py_DECREF(base);
    Py_DECREF(fields);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking abi_struct");
    Py_XDECREF(name);
    Py_XDECREF(base);
    Py_XDECREF(fields);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_abi_type(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct abi_type:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "new_type_name",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field new_type_name: string
    PyObject *new_type_name = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!new_type_name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("new_type_name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "type",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field type: string
    PyObject *type = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!type) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("type start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "new_type_name", new_type_name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "type", type) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(new_type_name);
    Py_DECREF(type);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking abi_type");
    Py_XDECREF(new_type_name);
    Py_XDECREF(type);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_abi_action(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct abi_action:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "name",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field name: name
    PyObject *name = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "type",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field type: string
    PyObject *type = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!type) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("type start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ricardian_contract",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ricardian_contract: string
    PyObject *ricardian_contract = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!ricardian_contract) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ricardian_contract start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "name", name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "type", type) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ricardian_contract", ricardian_contract) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(name);
    Py_DECREF(type);
    Py_DECREF(ricardian_contract);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking abi_action");
    Py_XDECREF(name);
    Py_XDECREF(type);
    Py_XDECREF(ricardian_contract);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_abi_variant(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct abi_variant:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "name",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field name: string
    PyObject *name = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "types",
            "string",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field types: string[]
    size_t __len_types = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *types = PyList_New(__len_types);
    if (!types) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_types);
    #endif

    for (size_t _i = 0; _i < __len_types; ++_i) {
        PyObject *_item = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(types); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(types, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("types start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "name", name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "types", types) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(name);
    Py_DECREF(types);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking abi_variant");
    Py_XDECREF(name);
    Py_XDECREF(types);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_abi_table(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct abi_table:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "name",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field name: name
    PyObject *name = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "index_type",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field index_type: string
    PyObject *index_type = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!index_type) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("index_type start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "key_names",
            "string",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field key_names: string[]
    size_t __len_key_names = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *key_names = PyList_New(__len_key_names);
    if (!key_names) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_key_names);
    #endif

    for (size_t _i = 0; _i < __len_key_names; ++_i) {
        PyObject *_item = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(key_names); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(key_names, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("key_names start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "key_types",
            "string",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field key_types: string[]
    size_t __len_key_types = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *key_types = PyList_New(__len_key_types);
    if (!key_types) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_key_types);
    #endif

    for (size_t _i = 0; _i < __len_key_types; ++_i) {
        PyObject *_item = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(key_types); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(key_types, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("key_types start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "type",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field type: string
    PyObject *type = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!type) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("type start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "name", name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "index_type", index_type) < 0) goto error;
    if (PyDict_SetItemString(__dict, "key_names", key_names) < 0) goto error;
    if (PyDict_SetItemString(__dict, "key_types", key_types) < 0) goto error;
    if (PyDict_SetItemString(__dict, "type", type) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(name);
    Py_DECREF(index_type);
    Py_DECREF(key_names);
    Py_DECREF(key_types);
    Py_DECREF(type);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking abi_table");
    Py_XDECREF(name);
    Py_XDECREF(index_type);
    Py_XDECREF(key_names);
    Py_XDECREF(key_types);
    Py_XDECREF(type);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_abi_clause(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct abi_clause:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "id",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field id: string
    PyObject *id = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!id) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("id start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "body",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field body: string
    PyObject *body = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!body) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("body start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "id", id) < 0) goto error;
    if (PyDict_SetItemString(__dict, "body", body) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(id);
    Py_DECREF(body);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking abi_clause");
    Py_XDECREF(id);
    Py_XDECREF(body);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_abi_result(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct abi_result:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "name",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field name: name
    PyObject *name = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "result_type",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field result_type: string
    PyObject *result_type = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!result_type) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("result_type start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "name", name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "result_type", result_type) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(name);
    Py_DECREF(result_type);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking abi_result");
    Py_XDECREF(name);
    Py_XDECREF(result_type);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_abi(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct abi:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "version",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field version: string
    PyObject *version = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!version) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("version start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "types",
            "abi_type",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field types: abi_type[]
    size_t __len_types = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *types = PyList_New(__len_types);
    if (!types) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_types);
    #endif

    for (size_t _i = 0; _i < __len_types; ++_i) {
        PyObject *_item = unpack_abi_type(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(types); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(types, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("types start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "structs",
            "abi_struct",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field structs: abi_struct[]
    size_t __len_structs = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *structs = PyList_New(__len_structs);
    if (!structs) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_structs);
    #endif

    for (size_t _i = 0; _i < __len_structs; ++_i) {
        PyObject *_item = unpack_abi_struct(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(structs); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(structs, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("structs start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "actions",
            "abi_action",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field actions: abi_action[]
    size_t __len_actions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *actions = PyList_New(__len_actions);
    if (!actions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_actions);
    #endif

    for (size_t _i = 0; _i < __len_actions; ++_i) {
        PyObject *_item = unpack_abi_action(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(actions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(actions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("actions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "tables",
            "abi_table",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field tables: abi_table[]
    size_t __len_tables = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *tables = PyList_New(__len_tables);
    if (!tables) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_tables);
    #endif

    for (size_t _i = 0; _i < __len_tables; ++_i) {
        PyObject *_item = unpack_abi_table(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(tables); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(tables, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("tables start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ricardian_clauses",
            "abi_clause",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ricardian_clauses: abi_clause[]
    size_t __len_ricardian_clauses = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *ricardian_clauses = PyList_New(__len_ricardian_clauses);
    if (!ricardian_clauses) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_ricardian_clauses);
    #endif

    for (size_t _i = 0; _i < __len_ricardian_clauses; ++_i) {
        PyObject *_item = unpack_abi_clause(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(ricardian_clauses); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(ricardian_clauses, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ricardian_clauses start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "error_messages",
            "string",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field error_messages: string[]
    size_t __len_error_messages = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *error_messages = PyList_New(__len_error_messages);
    if (!error_messages) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_error_messages);
    #endif

    for (size_t _i = 0; _i < __len_error_messages; ++_i) {
        PyObject *_item = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(error_messages); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(error_messages, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("error_messages start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "abi_extensions",
            "string",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field abi_extensions: string[]
    size_t __len_abi_extensions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *abi_extensions = PyList_New(__len_abi_extensions);
    if (!abi_extensions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_abi_extensions);
    #endif

    for (size_t _i = 0; _i < __len_abi_extensions; ++_i) {
        PyObject *_item = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(abi_extensions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(abi_extensions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("abi_extensions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "variants",
            "abi_variant",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field variants: abi_variant[]
    size_t __len_variants = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *variants = PyList_New(__len_variants);
    if (!variants) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_variants);
    #endif

    for (size_t _i = 0; _i < __len_variants; ++_i) {
        PyObject *_item = unpack_abi_variant(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(variants); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(variants, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("variants start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "version", version) < 0) goto error;
    if (PyDict_SetItemString(__dict, "types", types) < 0) goto error;
    if (PyDict_SetItemString(__dict, "structs", structs) < 0) goto error;
    if (PyDict_SetItemString(__dict, "actions", actions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "tables", tables) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ricardian_clauses", ricardian_clauses) < 0) goto error;
    if (PyDict_SetItemString(__dict, "error_messages", error_messages) < 0) goto error;
    if (PyDict_SetItemString(__dict, "abi_extensions", abi_extensions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "variants", variants) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(version);
    Py_DECREF(types);
    Py_DECREF(structs);
    Py_DECREF(actions);
    Py_DECREF(tables);
    Py_DECREF(ricardian_clauses);
    Py_DECREF(error_messages);
    Py_DECREF(abi_extensions);
    Py_DECREF(variants);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking abi");
    Py_XDECREF(version);
    Py_XDECREF(types);
    Py_XDECREF(structs);
    Py_XDECREF(actions);
    Py_XDECREF(tables);
    Py_XDECREF(ricardian_clauses);
    Py_XDECREF(error_messages);
    Py_XDECREF(abi_extensions);
    Py_XDECREF(variants);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_get_status_request_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct get_status_request_v0:\n");
    #endif

    __depth++;

    // decode fields
    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking get_status_request_v0");
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_block_position(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct block_position:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "block_num",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field block_num: uint32
    PyObject *block_num = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!block_num) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("block_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "block_id",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field block_id: checksum256
    PyObject *block_id = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!block_id) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("block_id start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "block_num", block_num) < 0) goto error;
    if (PyDict_SetItemString(__dict, "block_id", block_id) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(block_num);
    Py_DECREF(block_id);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking block_position");
    Py_XDECREF(block_num);
    Py_XDECREF(block_id);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_get_status_result_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct get_status_result_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "head",
            "block_position",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field head: block_position
    PyObject *head = unpack_block_position(b + __total, buf_len, &__consumed, __depth + 1);

    if (!head) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("head start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "last_irreversible",
            "block_position",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field last_irreversible: block_position
    PyObject *last_irreversible = unpack_block_position(b + __total, buf_len, &__consumed, __depth + 1);

    if (!last_irreversible) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("last_irreversible start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "trace_begin_block",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field trace_begin_block: uint32
    PyObject *trace_begin_block = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!trace_begin_block) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("trace_begin_block start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "trace_end_block",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field trace_end_block: uint32
    PyObject *trace_end_block = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!trace_end_block) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("trace_end_block start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "chain_state_begin_block",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field chain_state_begin_block: uint32
    PyObject *chain_state_begin_block = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!chain_state_begin_block) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("chain_state_begin_block start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "chain_state_end_block",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field chain_state_end_block: uint32
    PyObject *chain_state_end_block = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!chain_state_end_block) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("chain_state_end_block start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "chain_id",
            "checksum256",
            "$"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field chain_id: checksum256$
    PyObject *chain_id = NULL;

    if (__total < buf_len) {
        chain_id = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);
        if (!chain_id) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        chain_id = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("chain_id start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "head", head) < 0) goto error;
    if (PyDict_SetItemString(__dict, "last_irreversible", last_irreversible) < 0) goto error;
    if (PyDict_SetItemString(__dict, "trace_begin_block", trace_begin_block) < 0) goto error;
    if (PyDict_SetItemString(__dict, "trace_end_block", trace_end_block) < 0) goto error;
    if (PyDict_SetItemString(__dict, "chain_state_begin_block", chain_state_begin_block) < 0) goto error;
    if (PyDict_SetItemString(__dict, "chain_state_end_block", chain_state_end_block) < 0) goto error;
    if (PyDict_SetItemString(__dict, "chain_id", chain_id) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(head);
    Py_DECREF(last_irreversible);
    Py_DECREF(trace_begin_block);
    Py_DECREF(trace_end_block);
    Py_DECREF(chain_state_begin_block);
    Py_DECREF(chain_state_end_block);
    Py_DECREF(chain_id);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking get_status_result_v0");
    Py_XDECREF(head);
    Py_XDECREF(last_irreversible);
    Py_XDECREF(trace_begin_block);
    Py_XDECREF(trace_end_block);
    Py_XDECREF(chain_state_begin_block);
    Py_XDECREF(chain_state_end_block);
    Py_XDECREF(chain_id);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_get_blocks_request_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct get_blocks_request_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "start_block_num",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field start_block_num: uint32
    PyObject *start_block_num = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!start_block_num) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("start_block_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "end_block_num",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field end_block_num: uint32
    PyObject *end_block_num = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!end_block_num) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("end_block_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_messages_in_flight",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_messages_in_flight: uint32
    PyObject *max_messages_in_flight = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_messages_in_flight) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_messages_in_flight start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "have_positions",
            "block_position",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field have_positions: block_position[]
    size_t __len_have_positions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *have_positions = PyList_New(__len_have_positions);
    if (!have_positions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_have_positions);
    #endif

    for (size_t _i = 0; _i < __len_have_positions; ++_i) {
        PyObject *_item = unpack_block_position(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(have_positions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(have_positions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("have_positions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "irreversible_only",
            "bool",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field irreversible_only: bool
    PyObject *irreversible_only = unpack_bool(b + __total, buf_len, &__consumed, __depth + 1);

    if (!irreversible_only) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("irreversible_only start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "fetch_block",
            "bool",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field fetch_block: bool
    PyObject *fetch_block = unpack_bool(b + __total, buf_len, &__consumed, __depth + 1);

    if (!fetch_block) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fetch_block start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "fetch_traces",
            "bool",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field fetch_traces: bool
    PyObject *fetch_traces = unpack_bool(b + __total, buf_len, &__consumed, __depth + 1);

    if (!fetch_traces) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fetch_traces start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "fetch_deltas",
            "bool",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field fetch_deltas: bool
    PyObject *fetch_deltas = unpack_bool(b + __total, buf_len, &__consumed, __depth + 1);

    if (!fetch_deltas) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fetch_deltas start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "start_block_num", start_block_num) < 0) goto error;
    if (PyDict_SetItemString(__dict, "end_block_num", end_block_num) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_messages_in_flight", max_messages_in_flight) < 0) goto error;
    if (PyDict_SetItemString(__dict, "have_positions", have_positions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "irreversible_only", irreversible_only) < 0) goto error;
    if (PyDict_SetItemString(__dict, "fetch_block", fetch_block) < 0) goto error;
    if (PyDict_SetItemString(__dict, "fetch_traces", fetch_traces) < 0) goto error;
    if (PyDict_SetItemString(__dict, "fetch_deltas", fetch_deltas) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(start_block_num);
    Py_DECREF(end_block_num);
    Py_DECREF(max_messages_in_flight);
    Py_DECREF(have_positions);
    Py_DECREF(irreversible_only);
    Py_DECREF(fetch_block);
    Py_DECREF(fetch_traces);
    Py_DECREF(fetch_deltas);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking get_blocks_request_v0");
    Py_XDECREF(start_block_num);
    Py_XDECREF(end_block_num);
    Py_XDECREF(max_messages_in_flight);
    Py_XDECREF(have_positions);
    Py_XDECREF(irreversible_only);
    Py_XDECREF(fetch_block);
    Py_XDECREF(fetch_traces);
    Py_XDECREF(fetch_deltas);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_get_blocks_ack_request_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct get_blocks_ack_request_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "num_messages",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field num_messages: uint32
    PyObject *num_messages = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!num_messages) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("num_messages start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "num_messages", num_messages) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(num_messages);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking get_blocks_ack_request_v0");
    Py_XDECREF(num_messages);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_get_blocks_result_v0_header(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct get_blocks_result_v0_header:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "head",
            "block_position",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field head: block_position
    PyObject *head = unpack_block_position(b + __total, buf_len, &__consumed, __depth + 1);

    if (!head) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("head start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "last_irreversible",
            "block_position",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field last_irreversible: block_position
    PyObject *last_irreversible = unpack_block_position(b + __total, buf_len, &__consumed, __depth + 1);

    if (!last_irreversible) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("last_irreversible start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "this_block",
            "block_position",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field this_block: block_position?
    PyObject *this_block = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_this_block = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_this_block, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_this_block) {
        this_block = unpack_block_position(b + __total, buf_len, &__consumed, __depth + 1);
        if (!this_block) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        this_block = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("this_block start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "prev_block",
            "block_position",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field prev_block: block_position?
    PyObject *prev_block = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_prev_block = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_prev_block, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_prev_block) {
        prev_block = unpack_block_position(b + __total, buf_len, &__consumed, __depth + 1);
        if (!prev_block) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        prev_block = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("prev_block start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "head", head) < 0) goto error;
    if (PyDict_SetItemString(__dict, "last_irreversible", last_irreversible) < 0) goto error;
    if (PyDict_SetItemString(__dict, "this_block", this_block) < 0) goto error;
    if (PyDict_SetItemString(__dict, "prev_block", prev_block) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(head);
    Py_DECREF(last_irreversible);
    Py_DECREF(this_block);
    Py_DECREF(prev_block);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking get_blocks_result_v0_header");
    Py_XDECREF(head);
    Py_XDECREF(last_irreversible);
    Py_XDECREF(this_block);
    Py_XDECREF(prev_block);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_get_blocks_result_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct get_blocks_result_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "head",
            "block_position",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field head: block_position
    PyObject *head = unpack_block_position(b + __total, buf_len, &__consumed, __depth + 1);

    if (!head) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("head start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "last_irreversible",
            "block_position",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field last_irreversible: block_position
    PyObject *last_irreversible = unpack_block_position(b + __total, buf_len, &__consumed, __depth + 1);

    if (!last_irreversible) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("last_irreversible start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "this_block",
            "block_position",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field this_block: block_position?
    PyObject *this_block = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_this_block = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_this_block, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_this_block) {
        this_block = unpack_block_position(b + __total, buf_len, &__consumed, __depth + 1);
        if (!this_block) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        this_block = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("this_block start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "prev_block",
            "block_position",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field prev_block: block_position?
    PyObject *prev_block = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_prev_block = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_prev_block, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_prev_block) {
        prev_block = unpack_block_position(b + __total, buf_len, &__consumed, __depth + 1);
        if (!prev_block) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        prev_block = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("prev_block start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "block",
            "bytes",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field block: bytes?
    PyObject *block = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_block = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_block, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_block) {
        block = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);
        if (!block) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        block = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("block start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "traces",
            "bytes",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field traces: bytes?
    PyObject *traces = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_traces = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_traces, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_traces) {
        traces = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);
        if (!traces) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        traces = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("traces start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "deltas",
            "bytes",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field deltas: bytes?
    PyObject *deltas = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_deltas = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_deltas, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_deltas) {
        deltas = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);
        if (!deltas) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        deltas = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("deltas start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "head", head) < 0) goto error;
    if (PyDict_SetItemString(__dict, "last_irreversible", last_irreversible) < 0) goto error;
    if (PyDict_SetItemString(__dict, "this_block", this_block) < 0) goto error;
    if (PyDict_SetItemString(__dict, "prev_block", prev_block) < 0) goto error;
    if (PyDict_SetItemString(__dict, "block", block) < 0) goto error;
    if (PyDict_SetItemString(__dict, "traces", traces) < 0) goto error;
    if (PyDict_SetItemString(__dict, "deltas", deltas) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(head);
    Py_DECREF(last_irreversible);
    Py_DECREF(this_block);
    Py_DECREF(prev_block);
    Py_DECREF(block);
    Py_DECREF(traces);
    Py_DECREF(deltas);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking get_blocks_result_v0");
    Py_XDECREF(head);
    Py_XDECREF(last_irreversible);
    Py_XDECREF(this_block);
    Py_XDECREF(prev_block);
    Py_XDECREF(block);
    Py_XDECREF(traces);
    Py_XDECREF(deltas);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_row(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct row:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "present",
            "bool",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field present: bool
    PyObject *present = unpack_bool(b + __total, buf_len, &__consumed, __depth + 1);

    if (!present) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("present start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "data",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field data: bytes
    PyObject *data = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!data) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("data start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "present", present) < 0) goto error;
    if (PyDict_SetItemString(__dict, "data", data) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(present);
    Py_DECREF(data);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking row");
    Py_XDECREF(present);
    Py_XDECREF(data);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_table_delta_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct table_delta_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "name",
            "string",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field name: string
    PyObject *name = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);

    if (!name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "rows",
            "row",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field rows: row[]
    size_t __len_rows = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *rows = PyList_New(__len_rows);
    if (!rows) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_rows);
    #endif

    for (size_t _i = 0; _i < __len_rows; ++_i) {
        PyObject *_item = unpack_row(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(rows); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(rows, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("rows start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "name", name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "rows", rows) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(name);
    Py_DECREF(rows);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking table_delta_v0");
    Py_XDECREF(name);
    Py_XDECREF(rows);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_action(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct action:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "account",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field account: name
    PyObject *account = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!account) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("account start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "name",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field name: name
    PyObject *name = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "authorization",
            "permission_level",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field authorization: permission_level[]
    size_t __len_authorization = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *authorization = PyList_New(__len_authorization);
    if (!authorization) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_authorization);
    #endif

    for (size_t _i = 0; _i < __len_authorization; ++_i) {
        PyObject *_item = unpack_permission_level(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(authorization); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(authorization, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("authorization start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "data",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field data: bytes
    PyObject *data = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!data) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("data start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "account", account) < 0) goto error;
    if (PyDict_SetItemString(__dict, "name", name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "authorization", authorization) < 0) goto error;
    if (PyDict_SetItemString(__dict, "data", data) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(account);
    Py_DECREF(name);
    Py_DECREF(authorization);
    Py_DECREF(data);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking action");
    Py_XDECREF(account);
    Py_XDECREF(name);
    Py_XDECREF(authorization);
    Py_XDECREF(data);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_account_auth_sequence(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct account_auth_sequence:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "account",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field account: name
    PyObject *account = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!account) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("account start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "sequence",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field sequence: uint64
    PyObject *sequence = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!sequence) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("sequence start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "account", account) < 0) goto error;
    if (PyDict_SetItemString(__dict, "sequence", sequence) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(account);
    Py_DECREF(sequence);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking account_auth_sequence");
    Py_XDECREF(account);
    Py_XDECREF(sequence);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_action_receipt_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct action_receipt_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "receiver",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field receiver: name
    PyObject *receiver = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!receiver) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("receiver start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "act_digest",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field act_digest: checksum256
    PyObject *act_digest = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!act_digest) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("act_digest start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "global_sequence",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field global_sequence: uint64
    PyObject *global_sequence = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!global_sequence) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("global_sequence start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "recv_sequence",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field recv_sequence: uint64
    PyObject *recv_sequence = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!recv_sequence) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("recv_sequence start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "auth_sequence",
            "account_auth_sequence",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field auth_sequence: account_auth_sequence[]
    size_t __len_auth_sequence = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *auth_sequence = PyList_New(__len_auth_sequence);
    if (!auth_sequence) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_auth_sequence);
    #endif

    for (size_t _i = 0; _i < __len_auth_sequence; ++_i) {
        PyObject *_item = unpack_account_auth_sequence(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(auth_sequence); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(auth_sequence, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("auth_sequence start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code_sequence",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code_sequence: varuint32
    PyObject *code_sequence = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code_sequence) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code_sequence start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "abi_sequence",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field abi_sequence: varuint32
    PyObject *abi_sequence = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!abi_sequence) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("abi_sequence start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "receiver", receiver) < 0) goto error;
    if (PyDict_SetItemString(__dict, "act_digest", act_digest) < 0) goto error;
    if (PyDict_SetItemString(__dict, "global_sequence", global_sequence) < 0) goto error;
    if (PyDict_SetItemString(__dict, "recv_sequence", recv_sequence) < 0) goto error;
    if (PyDict_SetItemString(__dict, "auth_sequence", auth_sequence) < 0) goto error;
    if (PyDict_SetItemString(__dict, "code_sequence", code_sequence) < 0) goto error;
    if (PyDict_SetItemString(__dict, "abi_sequence", abi_sequence) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(receiver);
    Py_DECREF(act_digest);
    Py_DECREF(global_sequence);
    Py_DECREF(recv_sequence);
    Py_DECREF(auth_sequence);
    Py_DECREF(code_sequence);
    Py_DECREF(abi_sequence);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking action_receipt_v0");
    Py_XDECREF(receiver);
    Py_XDECREF(act_digest);
    Py_XDECREF(global_sequence);
    Py_XDECREF(recv_sequence);
    Py_XDECREF(auth_sequence);
    Py_XDECREF(code_sequence);
    Py_XDECREF(abi_sequence);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_account_delta(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct account_delta:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "account",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field account: name
    PyObject *account = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!account) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("account start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "delta",
            "int64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field delta: int64
    PyObject *delta = unpack_int64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!delta) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("delta start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "account", account) < 0) goto error;
    if (PyDict_SetItemString(__dict, "delta", delta) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(account);
    Py_DECREF(delta);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking account_delta");
    Py_XDECREF(account);
    Py_XDECREF(delta);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_action_trace_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct action_trace_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "action_ordinal",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field action_ordinal: varuint32
    PyObject *action_ordinal = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!action_ordinal) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("action_ordinal start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "creator_action_ordinal",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field creator_action_ordinal: varuint32
    PyObject *creator_action_ordinal = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!creator_action_ordinal) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("creator_action_ordinal start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "receipt",
            "action_receipt",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field receipt: action_receipt?
    PyObject *receipt = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_receipt = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_receipt, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_receipt) {
        receipt = unpack_action_receipt(b + __total, buf_len, &__consumed, __depth + 1);
        if (!receipt) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        receipt = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("receipt start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "receiver",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field receiver: name
    PyObject *receiver = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!receiver) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("receiver start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "act",
            "action",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field act: action
    PyObject *act = unpack_action(b + __total, buf_len, &__consumed, __depth + 1);

    if (!act) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("act start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "context_free",
            "bool",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field context_free: bool
    PyObject *context_free = unpack_bool(b + __total, buf_len, &__consumed, __depth + 1);

    if (!context_free) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("context_free start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "elapsed",
            "int64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field elapsed: int64
    PyObject *elapsed = unpack_int64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!elapsed) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("elapsed start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "console",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field console: bytes
    PyObject *console = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!console) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("console start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "account_ram_deltas",
            "account_delta",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field account_ram_deltas: account_delta[]
    size_t __len_account_ram_deltas = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *account_ram_deltas = PyList_New(__len_account_ram_deltas);
    if (!account_ram_deltas) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_account_ram_deltas);
    #endif

    for (size_t _i = 0; _i < __len_account_ram_deltas; ++_i) {
        PyObject *_item = unpack_account_delta(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(account_ram_deltas); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(account_ram_deltas, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("account_ram_deltas start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "except",
            "string",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field except: string?
    PyObject *except = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_except = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_except, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_except) {
        except = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);
        if (!except) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        except = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("except start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "error_code",
            "uint64",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field error_code: uint64?
    PyObject *error_code = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_error_code = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_error_code, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_error_code) {
        error_code = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);
        if (!error_code) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        error_code = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("error_code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "action_ordinal", action_ordinal) < 0) goto error;
    if (PyDict_SetItemString(__dict, "creator_action_ordinal", creator_action_ordinal) < 0) goto error;
    if (PyDict_SetItemString(__dict, "receipt", receipt) < 0) goto error;
    if (PyDict_SetItemString(__dict, "receiver", receiver) < 0) goto error;
    if (PyDict_SetItemString(__dict, "act", act) < 0) goto error;
    if (PyDict_SetItemString(__dict, "context_free", context_free) < 0) goto error;
    if (PyDict_SetItemString(__dict, "elapsed", elapsed) < 0) goto error;
    if (PyDict_SetItemString(__dict, "console", console) < 0) goto error;
    if (PyDict_SetItemString(__dict, "account_ram_deltas", account_ram_deltas) < 0) goto error;
    if (PyDict_SetItemString(__dict, "except", except) < 0) goto error;
    if (PyDict_SetItemString(__dict, "error_code", error_code) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(action_ordinal);
    Py_DECREF(creator_action_ordinal);
    Py_DECREF(receipt);
    Py_DECREF(receiver);
    Py_DECREF(act);
    Py_DECREF(context_free);
    Py_DECREF(elapsed);
    Py_DECREF(console);
    Py_DECREF(account_ram_deltas);
    Py_DECREF(except);
    Py_DECREF(error_code);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking action_trace_v0");
    Py_XDECREF(action_ordinal);
    Py_XDECREF(creator_action_ordinal);
    Py_XDECREF(receipt);
    Py_XDECREF(receiver);
    Py_XDECREF(act);
    Py_XDECREF(context_free);
    Py_XDECREF(elapsed);
    Py_XDECREF(console);
    Py_XDECREF(account_ram_deltas);
    Py_XDECREF(except);
    Py_XDECREF(error_code);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_action_trace_v1(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct action_trace_v1:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "action_ordinal",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field action_ordinal: varuint32
    PyObject *action_ordinal = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!action_ordinal) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("action_ordinal start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "creator_action_ordinal",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field creator_action_ordinal: varuint32
    PyObject *creator_action_ordinal = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!creator_action_ordinal) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("creator_action_ordinal start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "receipt",
            "action_receipt",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field receipt: action_receipt?
    PyObject *receipt = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_receipt = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_receipt, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_receipt) {
        receipt = unpack_action_receipt(b + __total, buf_len, &__consumed, __depth + 1);
        if (!receipt) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        receipt = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("receipt start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "receiver",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field receiver: name
    PyObject *receiver = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!receiver) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("receiver start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "act",
            "action",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field act: action
    PyObject *act = unpack_action(b + __total, buf_len, &__consumed, __depth + 1);

    if (!act) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("act start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "context_free",
            "bool",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field context_free: bool
    PyObject *context_free = unpack_bool(b + __total, buf_len, &__consumed, __depth + 1);

    if (!context_free) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("context_free start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "elapsed",
            "int64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field elapsed: int64
    PyObject *elapsed = unpack_int64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!elapsed) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("elapsed start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "console",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field console: bytes
    PyObject *console = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!console) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("console start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "account_ram_deltas",
            "account_delta",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field account_ram_deltas: account_delta[]
    size_t __len_account_ram_deltas = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *account_ram_deltas = PyList_New(__len_account_ram_deltas);
    if (!account_ram_deltas) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_account_ram_deltas);
    #endif

    for (size_t _i = 0; _i < __len_account_ram_deltas; ++_i) {
        PyObject *_item = unpack_account_delta(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(account_ram_deltas); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(account_ram_deltas, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("account_ram_deltas start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "except",
            "string",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field except: string?
    PyObject *except = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_except = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_except, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_except) {
        except = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);
        if (!except) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        except = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("except start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "error_code",
            "uint64",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field error_code: uint64?
    PyObject *error_code = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_error_code = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_error_code, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_error_code) {
        error_code = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);
        if (!error_code) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        error_code = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("error_code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "return_value",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field return_value: bytes
    PyObject *return_value = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!return_value) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("return_value start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "action_ordinal", action_ordinal) < 0) goto error;
    if (PyDict_SetItemString(__dict, "creator_action_ordinal", creator_action_ordinal) < 0) goto error;
    if (PyDict_SetItemString(__dict, "receipt", receipt) < 0) goto error;
    if (PyDict_SetItemString(__dict, "receiver", receiver) < 0) goto error;
    if (PyDict_SetItemString(__dict, "act", act) < 0) goto error;
    if (PyDict_SetItemString(__dict, "context_free", context_free) < 0) goto error;
    if (PyDict_SetItemString(__dict, "elapsed", elapsed) < 0) goto error;
    if (PyDict_SetItemString(__dict, "console", console) < 0) goto error;
    if (PyDict_SetItemString(__dict, "account_ram_deltas", account_ram_deltas) < 0) goto error;
    if (PyDict_SetItemString(__dict, "except", except) < 0) goto error;
    if (PyDict_SetItemString(__dict, "error_code", error_code) < 0) goto error;
    if (PyDict_SetItemString(__dict, "return_value", return_value) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(action_ordinal);
    Py_DECREF(creator_action_ordinal);
    Py_DECREF(receipt);
    Py_DECREF(receiver);
    Py_DECREF(act);
    Py_DECREF(context_free);
    Py_DECREF(elapsed);
    Py_DECREF(console);
    Py_DECREF(account_ram_deltas);
    Py_DECREF(except);
    Py_DECREF(error_code);
    Py_DECREF(return_value);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking action_trace_v1");
    Py_XDECREF(action_ordinal);
    Py_XDECREF(creator_action_ordinal);
    Py_XDECREF(receipt);
    Py_XDECREF(receiver);
    Py_XDECREF(act);
    Py_XDECREF(context_free);
    Py_XDECREF(elapsed);
    Py_XDECREF(console);
    Py_XDECREF(account_ram_deltas);
    Py_XDECREF(except);
    Py_XDECREF(error_code);
    Py_XDECREF(return_value);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_partial_transaction_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct partial_transaction_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "expiration",
            "time_point_sec",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field expiration: time_point_sec
    PyObject *expiration = unpack_time_point_sec(b + __total, buf_len, &__consumed, __depth + 1);

    if (!expiration) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("expiration start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ref_block_num",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ref_block_num: uint16
    PyObject *ref_block_num = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!ref_block_num) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ref_block_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ref_block_prefix",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ref_block_prefix: uint32
    PyObject *ref_block_prefix = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!ref_block_prefix) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ref_block_prefix start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_net_usage_words",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_net_usage_words: varuint32
    PyObject *max_net_usage_words = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_net_usage_words) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_net_usage_words start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_cpu_usage_ms",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_cpu_usage_ms: uint8
    PyObject *max_cpu_usage_ms = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_cpu_usage_ms) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_cpu_usage_ms start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "delay_sec",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field delay_sec: varuint32
    PyObject *delay_sec = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!delay_sec) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("delay_sec start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "transaction_extensions",
            "extension",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field transaction_extensions: extension[]
    size_t __len_transaction_extensions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *transaction_extensions = PyList_New(__len_transaction_extensions);
    if (!transaction_extensions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_transaction_extensions);
    #endif

    for (size_t _i = 0; _i < __len_transaction_extensions; ++_i) {
        PyObject *_item = unpack_extension(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(transaction_extensions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(transaction_extensions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("transaction_extensions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "signatures",
            "signature",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field signatures: signature[]
    size_t __len_signatures = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *signatures = PyList_New(__len_signatures);
    if (!signatures) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_signatures);
    #endif

    for (size_t _i = 0; _i < __len_signatures; ++_i) {
        PyObject *_item = unpack_signature(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(signatures); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(signatures, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("signatures start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "context_free_data",
            "bytes",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field context_free_data: bytes[]
    size_t __len_context_free_data = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *context_free_data = PyList_New(__len_context_free_data);
    if (!context_free_data) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_context_free_data);
    #endif

    for (size_t _i = 0; _i < __len_context_free_data; ++_i) {
        PyObject *_item = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(context_free_data); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(context_free_data, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("context_free_data start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "expiration", expiration) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ref_block_num", ref_block_num) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ref_block_prefix", ref_block_prefix) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_net_usage_words", max_net_usage_words) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_cpu_usage_ms", max_cpu_usage_ms) < 0) goto error;
    if (PyDict_SetItemString(__dict, "delay_sec", delay_sec) < 0) goto error;
    if (PyDict_SetItemString(__dict, "transaction_extensions", transaction_extensions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "signatures", signatures) < 0) goto error;
    if (PyDict_SetItemString(__dict, "context_free_data", context_free_data) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(expiration);
    Py_DECREF(ref_block_num);
    Py_DECREF(ref_block_prefix);
    Py_DECREF(max_net_usage_words);
    Py_DECREF(max_cpu_usage_ms);
    Py_DECREF(delay_sec);
    Py_DECREF(transaction_extensions);
    Py_DECREF(signatures);
    Py_DECREF(context_free_data);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking partial_transaction_v0");
    Py_XDECREF(expiration);
    Py_XDECREF(ref_block_num);
    Py_XDECREF(ref_block_prefix);
    Py_XDECREF(max_net_usage_words);
    Py_XDECREF(max_cpu_usage_ms);
    Py_XDECREF(delay_sec);
    Py_XDECREF(transaction_extensions);
    Py_XDECREF(signatures);
    Py_XDECREF(context_free_data);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_transaction_trace_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct transaction_trace_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "id",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field id: checksum256
    PyObject *id = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!id) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("id start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "status",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field status: uint8
    PyObject *status = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!status) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("status start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "cpu_usage_us",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field cpu_usage_us: uint32
    PyObject *cpu_usage_us = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!cpu_usage_us) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("cpu_usage_us start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "net_usage_words",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field net_usage_words: varuint32
    PyObject *net_usage_words = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!net_usage_words) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("net_usage_words start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "elapsed",
            "int64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field elapsed: int64
    PyObject *elapsed = unpack_int64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!elapsed) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("elapsed start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "net_usage",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field net_usage: uint64
    PyObject *net_usage = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!net_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("net_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "scheduled",
            "bool",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field scheduled: bool
    PyObject *scheduled = unpack_bool(b + __total, buf_len, &__consumed, __depth + 1);

    if (!scheduled) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("scheduled start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "action_traces",
            "action_trace",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field action_traces: action_trace[]
    size_t __len_action_traces = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *action_traces = PyList_New(__len_action_traces);
    if (!action_traces) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_action_traces);
    #endif

    for (size_t _i = 0; _i < __len_action_traces; ++_i) {
        PyObject *_item = unpack_action_trace(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(action_traces); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(action_traces, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("action_traces start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "account_ram_delta",
            "account_delta",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field account_ram_delta: account_delta?
    PyObject *account_ram_delta = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_account_ram_delta = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_account_ram_delta, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_account_ram_delta) {
        account_ram_delta = unpack_account_delta(b + __total, buf_len, &__consumed, __depth + 1);
        if (!account_ram_delta) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        account_ram_delta = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("account_ram_delta start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "except",
            "string",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field except: string?
    PyObject *except = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_except = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_except, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_except) {
        except = unpack_string(b + __total, buf_len, &__consumed, __depth + 1);
        if (!except) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        except = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("except start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "error_code",
            "uint64",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field error_code: uint64?
    PyObject *error_code = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_error_code = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_error_code, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_error_code) {
        error_code = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);
        if (!error_code) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        error_code = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("error_code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "failed_dtrx_trace",
            "transaction_trace",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field failed_dtrx_trace: transaction_trace?
    PyObject *failed_dtrx_trace = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_failed_dtrx_trace = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_failed_dtrx_trace, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_failed_dtrx_trace) {
        failed_dtrx_trace = unpack_transaction_trace(b + __total, buf_len, &__consumed, __depth + 1);
        if (!failed_dtrx_trace) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        failed_dtrx_trace = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("failed_dtrx_trace start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "partial",
            "partial_transaction",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field partial: partial_transaction?
    PyObject *partial = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_partial = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_partial, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_partial) {
        partial = unpack_partial_transaction(b + __total, buf_len, &__consumed, __depth + 1);
        if (!partial) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        partial = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("partial start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "id", id) < 0) goto error;
    if (PyDict_SetItemString(__dict, "status", status) < 0) goto error;
    if (PyDict_SetItemString(__dict, "cpu_usage_us", cpu_usage_us) < 0) goto error;
    if (PyDict_SetItemString(__dict, "net_usage_words", net_usage_words) < 0) goto error;
    if (PyDict_SetItemString(__dict, "elapsed", elapsed) < 0) goto error;
    if (PyDict_SetItemString(__dict, "net_usage", net_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "scheduled", scheduled) < 0) goto error;
    if (PyDict_SetItemString(__dict, "action_traces", action_traces) < 0) goto error;
    if (PyDict_SetItemString(__dict, "account_ram_delta", account_ram_delta) < 0) goto error;
    if (PyDict_SetItemString(__dict, "except", except) < 0) goto error;
    if (PyDict_SetItemString(__dict, "error_code", error_code) < 0) goto error;
    if (PyDict_SetItemString(__dict, "failed_dtrx_trace", failed_dtrx_trace) < 0) goto error;
    if (PyDict_SetItemString(__dict, "partial", partial) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(id);
    Py_DECREF(status);
    Py_DECREF(cpu_usage_us);
    Py_DECREF(net_usage_words);
    Py_DECREF(elapsed);
    Py_DECREF(net_usage);
    Py_DECREF(scheduled);
    Py_DECREF(action_traces);
    Py_DECREF(account_ram_delta);
    Py_DECREF(except);
    Py_DECREF(error_code);
    Py_DECREF(failed_dtrx_trace);
    Py_DECREF(partial);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking transaction_trace_v0");
    Py_XDECREF(id);
    Py_XDECREF(status);
    Py_XDECREF(cpu_usage_us);
    Py_XDECREF(net_usage_words);
    Py_XDECREF(elapsed);
    Py_XDECREF(net_usage);
    Py_XDECREF(scheduled);
    Py_XDECREF(action_traces);
    Py_XDECREF(account_ram_delta);
    Py_XDECREF(except);
    Py_XDECREF(error_code);
    Py_XDECREF(failed_dtrx_trace);
    Py_XDECREF(partial);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_packed_transaction(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct packed_transaction:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "signatures",
            "signature",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field signatures: signature[]
    size_t __len_signatures = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *signatures = PyList_New(__len_signatures);
    if (!signatures) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_signatures);
    #endif

    for (size_t _i = 0; _i < __len_signatures; ++_i) {
        PyObject *_item = unpack_signature(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(signatures); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(signatures, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("signatures start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "compression",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field compression: uint8
    PyObject *compression = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!compression) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("compression start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "packed_context_free_data",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field packed_context_free_data: bytes
    PyObject *packed_context_free_data = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!packed_context_free_data) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("packed_context_free_data start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "packed_trx",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field packed_trx: bytes
    PyObject *packed_trx = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!packed_trx) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("packed_trx start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "signatures", signatures) < 0) goto error;
    if (PyDict_SetItemString(__dict, "compression", compression) < 0) goto error;
    if (PyDict_SetItemString(__dict, "packed_context_free_data", packed_context_free_data) < 0) goto error;
    if (PyDict_SetItemString(__dict, "packed_trx", packed_trx) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(signatures);
    Py_DECREF(compression);
    Py_DECREF(packed_context_free_data);
    Py_DECREF(packed_trx);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking packed_transaction");
    Py_XDECREF(signatures);
    Py_XDECREF(compression);
    Py_XDECREF(packed_context_free_data);
    Py_XDECREF(packed_trx);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_transaction_receipt_header(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct transaction_receipt_header:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "status",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field status: uint8
    PyObject *status = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!status) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("status start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "cpu_usage_us",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field cpu_usage_us: uint32
    PyObject *cpu_usage_us = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!cpu_usage_us) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("cpu_usage_us start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "net_usage_words",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field net_usage_words: varuint32
    PyObject *net_usage_words = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!net_usage_words) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("net_usage_words start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "status", status) < 0) goto error;
    if (PyDict_SetItemString(__dict, "cpu_usage_us", cpu_usage_us) < 0) goto error;
    if (PyDict_SetItemString(__dict, "net_usage_words", net_usage_words) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(status);
    Py_DECREF(cpu_usage_us);
    Py_DECREF(net_usage_words);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking transaction_receipt_header");
    Py_XDECREF(status);
    Py_XDECREF(cpu_usage_us);
    Py_XDECREF(net_usage_words);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_transaction_receipt(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct transaction_receipt:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "status",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field status: uint8
    PyObject *status = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!status) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("status start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "cpu_usage_us",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field cpu_usage_us: uint32
    PyObject *cpu_usage_us = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!cpu_usage_us) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("cpu_usage_us start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "net_usage_words",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field net_usage_words: varuint32
    PyObject *net_usage_words = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!net_usage_words) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("net_usage_words start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "trx",
            "transaction_variant",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field trx: transaction_variant
    PyObject *trx = unpack_transaction_variant(b + __total, buf_len, &__consumed, __depth + 1);

    if (!trx) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("trx start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "status", status) < 0) goto error;
    if (PyDict_SetItemString(__dict, "cpu_usage_us", cpu_usage_us) < 0) goto error;
    if (PyDict_SetItemString(__dict, "net_usage_words", net_usage_words) < 0) goto error;
    if (PyDict_SetItemString(__dict, "trx", trx) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(status);
    Py_DECREF(cpu_usage_us);
    Py_DECREF(net_usage_words);
    Py_DECREF(trx);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking transaction_receipt");
    Py_XDECREF(status);
    Py_XDECREF(cpu_usage_us);
    Py_XDECREF(net_usage_words);
    Py_XDECREF(trx);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_extension(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct extension:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "type",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field type: uint16
    PyObject *type = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!type) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("type start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "data",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field data: bytes
    PyObject *data = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!data) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("data start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "type", type) < 0) goto error;
    if (PyDict_SetItemString(__dict, "data", data) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(type);
    Py_DECREF(data);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking extension");
    Py_XDECREF(type);
    Py_XDECREF(data);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_block_header(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct block_header:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "timestamp",
            "block_timestamp_type",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field timestamp: block_timestamp_type
    PyObject *timestamp = unpack_block_timestamp_type(b + __total, buf_len, &__consumed, __depth + 1);

    if (!timestamp) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("timestamp start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "producer",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field producer: name
    PyObject *producer = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!producer) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("producer start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "confirmed",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field confirmed: uint16
    PyObject *confirmed = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!confirmed) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("confirmed start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "previous",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field previous: checksum256
    PyObject *previous = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!previous) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("previous start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "transaction_mroot",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field transaction_mroot: checksum256
    PyObject *transaction_mroot = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!transaction_mroot) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("transaction_mroot start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "action_mroot",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field action_mroot: checksum256
    PyObject *action_mroot = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!action_mroot) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("action_mroot start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "schedule_version",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field schedule_version: uint32
    PyObject *schedule_version = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!schedule_version) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("schedule_version start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "new_producers",
            "producer_schedule",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field new_producers: producer_schedule?
    PyObject *new_producers = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_new_producers = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_new_producers, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_new_producers) {
        new_producers = unpack_producer_schedule(b + __total, buf_len, &__consumed, __depth + 1);
        if (!new_producers) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        new_producers = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("new_producers start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "header_extensions",
            "extension",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field header_extensions: extension[]
    size_t __len_header_extensions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *header_extensions = PyList_New(__len_header_extensions);
    if (!header_extensions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_header_extensions);
    #endif

    for (size_t _i = 0; _i < __len_header_extensions; ++_i) {
        PyObject *_item = unpack_extension(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(header_extensions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(header_extensions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("header_extensions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "timestamp", timestamp) < 0) goto error;
    if (PyDict_SetItemString(__dict, "producer", producer) < 0) goto error;
    if (PyDict_SetItemString(__dict, "confirmed", confirmed) < 0) goto error;
    if (PyDict_SetItemString(__dict, "previous", previous) < 0) goto error;
    if (PyDict_SetItemString(__dict, "transaction_mroot", transaction_mroot) < 0) goto error;
    if (PyDict_SetItemString(__dict, "action_mroot", action_mroot) < 0) goto error;
    if (PyDict_SetItemString(__dict, "schedule_version", schedule_version) < 0) goto error;
    if (PyDict_SetItemString(__dict, "new_producers", new_producers) < 0) goto error;
    if (PyDict_SetItemString(__dict, "header_extensions", header_extensions) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(timestamp);
    Py_DECREF(producer);
    Py_DECREF(confirmed);
    Py_DECREF(previous);
    Py_DECREF(transaction_mroot);
    Py_DECREF(action_mroot);
    Py_DECREF(schedule_version);
    Py_DECREF(new_producers);
    Py_DECREF(header_extensions);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking block_header");
    Py_XDECREF(timestamp);
    Py_XDECREF(producer);
    Py_XDECREF(confirmed);
    Py_XDECREF(previous);
    Py_XDECREF(transaction_mroot);
    Py_XDECREF(action_mroot);
    Py_XDECREF(schedule_version);
    Py_XDECREF(new_producers);
    Py_XDECREF(header_extensions);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_signed_block_header(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct signed_block_header:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "timestamp",
            "block_timestamp_type",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field timestamp: block_timestamp_type
    PyObject *timestamp = unpack_block_timestamp_type(b + __total, buf_len, &__consumed, __depth + 1);

    if (!timestamp) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("timestamp start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "producer",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field producer: name
    PyObject *producer = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!producer) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("producer start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "confirmed",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field confirmed: uint16
    PyObject *confirmed = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!confirmed) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("confirmed start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "previous",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field previous: checksum256
    PyObject *previous = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!previous) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("previous start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "transaction_mroot",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field transaction_mroot: checksum256
    PyObject *transaction_mroot = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!transaction_mroot) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("transaction_mroot start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "action_mroot",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field action_mroot: checksum256
    PyObject *action_mroot = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!action_mroot) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("action_mroot start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "schedule_version",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field schedule_version: uint32
    PyObject *schedule_version = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!schedule_version) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("schedule_version start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "new_producers",
            "producer_schedule",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field new_producers: producer_schedule?
    PyObject *new_producers = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_new_producers = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_new_producers, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_new_producers) {
        new_producers = unpack_producer_schedule(b + __total, buf_len, &__consumed, __depth + 1);
        if (!new_producers) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        new_producers = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("new_producers start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "header_extensions",
            "extension",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field header_extensions: extension[]
    size_t __len_header_extensions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *header_extensions = PyList_New(__len_header_extensions);
    if (!header_extensions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_header_extensions);
    #endif

    for (size_t _i = 0; _i < __len_header_extensions; ++_i) {
        PyObject *_item = unpack_extension(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(header_extensions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(header_extensions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("header_extensions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "producer_signature",
            "signature",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field producer_signature: signature
    PyObject *producer_signature = unpack_signature(b + __total, buf_len, &__consumed, __depth + 1);

    if (!producer_signature) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("producer_signature start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "timestamp", timestamp) < 0) goto error;
    if (PyDict_SetItemString(__dict, "producer", producer) < 0) goto error;
    if (PyDict_SetItemString(__dict, "confirmed", confirmed) < 0) goto error;
    if (PyDict_SetItemString(__dict, "previous", previous) < 0) goto error;
    if (PyDict_SetItemString(__dict, "transaction_mroot", transaction_mroot) < 0) goto error;
    if (PyDict_SetItemString(__dict, "action_mroot", action_mroot) < 0) goto error;
    if (PyDict_SetItemString(__dict, "schedule_version", schedule_version) < 0) goto error;
    if (PyDict_SetItemString(__dict, "new_producers", new_producers) < 0) goto error;
    if (PyDict_SetItemString(__dict, "header_extensions", header_extensions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "producer_signature", producer_signature) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(timestamp);
    Py_DECREF(producer);
    Py_DECREF(confirmed);
    Py_DECREF(previous);
    Py_DECREF(transaction_mroot);
    Py_DECREF(action_mroot);
    Py_DECREF(schedule_version);
    Py_DECREF(new_producers);
    Py_DECREF(header_extensions);
    Py_DECREF(producer_signature);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking signed_block_header");
    Py_XDECREF(timestamp);
    Py_XDECREF(producer);
    Py_XDECREF(confirmed);
    Py_XDECREF(previous);
    Py_XDECREF(transaction_mroot);
    Py_XDECREF(action_mroot);
    Py_XDECREF(schedule_version);
    Py_XDECREF(new_producers);
    Py_XDECREF(header_extensions);
    Py_XDECREF(producer_signature);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_signed_block(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct signed_block:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "timestamp",
            "block_timestamp_type",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field timestamp: block_timestamp_type
    PyObject *timestamp = unpack_block_timestamp_type(b + __total, buf_len, &__consumed, __depth + 1);

    if (!timestamp) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("timestamp start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "producer",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field producer: name
    PyObject *producer = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!producer) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("producer start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "confirmed",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field confirmed: uint16
    PyObject *confirmed = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!confirmed) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("confirmed start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "previous",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field previous: checksum256
    PyObject *previous = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!previous) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("previous start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "transaction_mroot",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field transaction_mroot: checksum256
    PyObject *transaction_mroot = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!transaction_mroot) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("transaction_mroot start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "action_mroot",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field action_mroot: checksum256
    PyObject *action_mroot = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!action_mroot) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("action_mroot start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "schedule_version",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field schedule_version: uint32
    PyObject *schedule_version = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!schedule_version) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("schedule_version start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "new_producers",
            "producer_schedule",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field new_producers: producer_schedule?
    PyObject *new_producers = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_new_producers = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_new_producers, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_new_producers) {
        new_producers = unpack_producer_schedule(b + __total, buf_len, &__consumed, __depth + 1);
        if (!new_producers) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        new_producers = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("new_producers start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "header_extensions",
            "extension",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field header_extensions: extension[]
    size_t __len_header_extensions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *header_extensions = PyList_New(__len_header_extensions);
    if (!header_extensions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_header_extensions);
    #endif

    for (size_t _i = 0; _i < __len_header_extensions; ++_i) {
        PyObject *_item = unpack_extension(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(header_extensions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(header_extensions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("header_extensions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "producer_signature",
            "signature",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field producer_signature: signature
    PyObject *producer_signature = unpack_signature(b + __total, buf_len, &__consumed, __depth + 1);

    if (!producer_signature) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("producer_signature start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "transactions",
            "transaction_receipt",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field transactions: transaction_receipt[]
    size_t __len_transactions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *transactions = PyList_New(__len_transactions);
    if (!transactions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_transactions);
    #endif

    for (size_t _i = 0; _i < __len_transactions; ++_i) {
        PyObject *_item = unpack_transaction_receipt(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(transactions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(transactions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("transactions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "block_extensions",
            "extension",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field block_extensions: extension[]
    size_t __len_block_extensions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *block_extensions = PyList_New(__len_block_extensions);
    if (!block_extensions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_block_extensions);
    #endif

    for (size_t _i = 0; _i < __len_block_extensions; ++_i) {
        PyObject *_item = unpack_extension(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(block_extensions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(block_extensions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("block_extensions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "timestamp", timestamp) < 0) goto error;
    if (PyDict_SetItemString(__dict, "producer", producer) < 0) goto error;
    if (PyDict_SetItemString(__dict, "confirmed", confirmed) < 0) goto error;
    if (PyDict_SetItemString(__dict, "previous", previous) < 0) goto error;
    if (PyDict_SetItemString(__dict, "transaction_mroot", transaction_mroot) < 0) goto error;
    if (PyDict_SetItemString(__dict, "action_mroot", action_mroot) < 0) goto error;
    if (PyDict_SetItemString(__dict, "schedule_version", schedule_version) < 0) goto error;
    if (PyDict_SetItemString(__dict, "new_producers", new_producers) < 0) goto error;
    if (PyDict_SetItemString(__dict, "header_extensions", header_extensions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "producer_signature", producer_signature) < 0) goto error;
    if (PyDict_SetItemString(__dict, "transactions", transactions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "block_extensions", block_extensions) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(timestamp);
    Py_DECREF(producer);
    Py_DECREF(confirmed);
    Py_DECREF(previous);
    Py_DECREF(transaction_mroot);
    Py_DECREF(action_mroot);
    Py_DECREF(schedule_version);
    Py_DECREF(new_producers);
    Py_DECREF(header_extensions);
    Py_DECREF(producer_signature);
    Py_DECREF(transactions);
    Py_DECREF(block_extensions);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking signed_block");
    Py_XDECREF(timestamp);
    Py_XDECREF(producer);
    Py_XDECREF(confirmed);
    Py_XDECREF(previous);
    Py_XDECREF(transaction_mroot);
    Py_XDECREF(action_mroot);
    Py_XDECREF(schedule_version);
    Py_XDECREF(new_producers);
    Py_XDECREF(header_extensions);
    Py_XDECREF(producer_signature);
    Py_XDECREF(transactions);
    Py_XDECREF(block_extensions);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_transaction_header(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct transaction_header:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "expiration",
            "time_point_sec",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field expiration: time_point_sec
    PyObject *expiration = unpack_time_point_sec(b + __total, buf_len, &__consumed, __depth + 1);

    if (!expiration) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("expiration start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ref_block_num",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ref_block_num: uint16
    PyObject *ref_block_num = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!ref_block_num) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ref_block_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ref_block_prefix",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ref_block_prefix: uint32
    PyObject *ref_block_prefix = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!ref_block_prefix) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ref_block_prefix start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_net_usage_words",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_net_usage_words: varuint32
    PyObject *max_net_usage_words = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_net_usage_words) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_net_usage_words start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_cpu_usage_ms",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_cpu_usage_ms: uint8
    PyObject *max_cpu_usage_ms = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_cpu_usage_ms) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_cpu_usage_ms start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "delay_sec",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field delay_sec: varuint32
    PyObject *delay_sec = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!delay_sec) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("delay_sec start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "expiration", expiration) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ref_block_num", ref_block_num) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ref_block_prefix", ref_block_prefix) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_net_usage_words", max_net_usage_words) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_cpu_usage_ms", max_cpu_usage_ms) < 0) goto error;
    if (PyDict_SetItemString(__dict, "delay_sec", delay_sec) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(expiration);
    Py_DECREF(ref_block_num);
    Py_DECREF(ref_block_prefix);
    Py_DECREF(max_net_usage_words);
    Py_DECREF(max_cpu_usage_ms);
    Py_DECREF(delay_sec);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking transaction_header");
    Py_XDECREF(expiration);
    Py_XDECREF(ref_block_num);
    Py_XDECREF(ref_block_prefix);
    Py_XDECREF(max_net_usage_words);
    Py_XDECREF(max_cpu_usage_ms);
    Py_XDECREF(delay_sec);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_transaction(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct transaction:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "expiration",
            "time_point_sec",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field expiration: time_point_sec
    PyObject *expiration = unpack_time_point_sec(b + __total, buf_len, &__consumed, __depth + 1);

    if (!expiration) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("expiration start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ref_block_num",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ref_block_num: uint16
    PyObject *ref_block_num = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!ref_block_num) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ref_block_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ref_block_prefix",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ref_block_prefix: uint32
    PyObject *ref_block_prefix = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!ref_block_prefix) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ref_block_prefix start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_net_usage_words",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_net_usage_words: varuint32
    PyObject *max_net_usage_words = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_net_usage_words) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_net_usage_words start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_cpu_usage_ms",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_cpu_usage_ms: uint8
    PyObject *max_cpu_usage_ms = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_cpu_usage_ms) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_cpu_usage_ms start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "delay_sec",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field delay_sec: varuint32
    PyObject *delay_sec = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!delay_sec) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("delay_sec start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "context_free_actions",
            "action",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field context_free_actions: action[]
    size_t __len_context_free_actions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *context_free_actions = PyList_New(__len_context_free_actions);
    if (!context_free_actions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_context_free_actions);
    #endif

    for (size_t _i = 0; _i < __len_context_free_actions; ++_i) {
        PyObject *_item = unpack_action(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(context_free_actions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(context_free_actions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("context_free_actions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "actions",
            "action",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field actions: action[]
    size_t __len_actions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *actions = PyList_New(__len_actions);
    if (!actions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_actions);
    #endif

    for (size_t _i = 0; _i < __len_actions; ++_i) {
        PyObject *_item = unpack_action(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(actions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(actions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("actions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "transaction_extensions",
            "extension",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field transaction_extensions: extension[]
    size_t __len_transaction_extensions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *transaction_extensions = PyList_New(__len_transaction_extensions);
    if (!transaction_extensions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_transaction_extensions);
    #endif

    for (size_t _i = 0; _i < __len_transaction_extensions; ++_i) {
        PyObject *_item = unpack_extension(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(transaction_extensions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(transaction_extensions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("transaction_extensions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "expiration", expiration) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ref_block_num", ref_block_num) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ref_block_prefix", ref_block_prefix) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_net_usage_words", max_net_usage_words) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_cpu_usage_ms", max_cpu_usage_ms) < 0) goto error;
    if (PyDict_SetItemString(__dict, "delay_sec", delay_sec) < 0) goto error;
    if (PyDict_SetItemString(__dict, "context_free_actions", context_free_actions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "actions", actions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "transaction_extensions", transaction_extensions) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(expiration);
    Py_DECREF(ref_block_num);
    Py_DECREF(ref_block_prefix);
    Py_DECREF(max_net_usage_words);
    Py_DECREF(max_cpu_usage_ms);
    Py_DECREF(delay_sec);
    Py_DECREF(context_free_actions);
    Py_DECREF(actions);
    Py_DECREF(transaction_extensions);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking transaction");
    Py_XDECREF(expiration);
    Py_XDECREF(ref_block_num);
    Py_XDECREF(ref_block_prefix);
    Py_XDECREF(max_net_usage_words);
    Py_XDECREF(max_cpu_usage_ms);
    Py_XDECREF(delay_sec);
    Py_XDECREF(context_free_actions);
    Py_XDECREF(actions);
    Py_XDECREF(transaction_extensions);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_signed_transaction(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct signed_transaction:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "expiration",
            "time_point_sec",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field expiration: time_point_sec
    PyObject *expiration = unpack_time_point_sec(b + __total, buf_len, &__consumed, __depth + 1);

    if (!expiration) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("expiration start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ref_block_num",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ref_block_num: uint16
    PyObject *ref_block_num = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!ref_block_num) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ref_block_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ref_block_prefix",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ref_block_prefix: uint32
    PyObject *ref_block_prefix = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!ref_block_prefix) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ref_block_prefix start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_net_usage_words",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_net_usage_words: varuint32
    PyObject *max_net_usage_words = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_net_usage_words) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_net_usage_words start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_cpu_usage_ms",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_cpu_usage_ms: uint8
    PyObject *max_cpu_usage_ms = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_cpu_usage_ms) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_cpu_usage_ms start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "delay_sec",
            "varuint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field delay_sec: varuint32
    PyObject *delay_sec = unpack_varuint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!delay_sec) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("delay_sec start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "context_free_actions",
            "action",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field context_free_actions: action[]
    size_t __len_context_free_actions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *context_free_actions = PyList_New(__len_context_free_actions);
    if (!context_free_actions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_context_free_actions);
    #endif

    for (size_t _i = 0; _i < __len_context_free_actions; ++_i) {
        PyObject *_item = unpack_action(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(context_free_actions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(context_free_actions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("context_free_actions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "actions",
            "action",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field actions: action[]
    size_t __len_actions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *actions = PyList_New(__len_actions);
    if (!actions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_actions);
    #endif

    for (size_t _i = 0; _i < __len_actions; ++_i) {
        PyObject *_item = unpack_action(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(actions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(actions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("actions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "transaction_extensions",
            "extension",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field transaction_extensions: extension[]
    size_t __len_transaction_extensions = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *transaction_extensions = PyList_New(__len_transaction_extensions);
    if (!transaction_extensions) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_transaction_extensions);
    #endif

    for (size_t _i = 0; _i < __len_transaction_extensions; ++_i) {
        PyObject *_item = unpack_extension(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(transaction_extensions); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(transaction_extensions, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("transaction_extensions start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "signatures",
            "signature",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field signatures: signature[]
    size_t __len_signatures = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *signatures = PyList_New(__len_signatures);
    if (!signatures) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_signatures);
    #endif

    for (size_t _i = 0; _i < __len_signatures; ++_i) {
        PyObject *_item = unpack_signature(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(signatures); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(signatures, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("signatures start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "context_free_data",
            "bytes",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field context_free_data: bytes[]
    size_t __len_context_free_data = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *context_free_data = PyList_New(__len_context_free_data);
    if (!context_free_data) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_context_free_data);
    #endif

    for (size_t _i = 0; _i < __len_context_free_data; ++_i) {
        PyObject *_item = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(context_free_data); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(context_free_data, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("context_free_data start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "expiration", expiration) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ref_block_num", ref_block_num) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ref_block_prefix", ref_block_prefix) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_net_usage_words", max_net_usage_words) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_cpu_usage_ms", max_cpu_usage_ms) < 0) goto error;
    if (PyDict_SetItemString(__dict, "delay_sec", delay_sec) < 0) goto error;
    if (PyDict_SetItemString(__dict, "context_free_actions", context_free_actions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "actions", actions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "transaction_extensions", transaction_extensions) < 0) goto error;
    if (PyDict_SetItemString(__dict, "signatures", signatures) < 0) goto error;
    if (PyDict_SetItemString(__dict, "context_free_data", context_free_data) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(expiration);
    Py_DECREF(ref_block_num);
    Py_DECREF(ref_block_prefix);
    Py_DECREF(max_net_usage_words);
    Py_DECREF(max_cpu_usage_ms);
    Py_DECREF(delay_sec);
    Py_DECREF(context_free_actions);
    Py_DECREF(actions);
    Py_DECREF(transaction_extensions);
    Py_DECREF(signatures);
    Py_DECREF(context_free_data);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking signed_transaction");
    Py_XDECREF(expiration);
    Py_XDECREF(ref_block_num);
    Py_XDECREF(ref_block_prefix);
    Py_XDECREF(max_net_usage_words);
    Py_XDECREF(max_cpu_usage_ms);
    Py_XDECREF(delay_sec);
    Py_XDECREF(context_free_actions);
    Py_XDECREF(actions);
    Py_XDECREF(transaction_extensions);
    Py_XDECREF(signatures);
    Py_XDECREF(context_free_data);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_code_id(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct code_id:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "vm_type",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field vm_type: uint8
    PyObject *vm_type = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!vm_type) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("vm_type start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "vm_version",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field vm_version: uint8
    PyObject *vm_version = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!vm_version) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("vm_version start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code_hash",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code_hash: checksum256
    PyObject *code_hash = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code_hash) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code_hash start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "vm_type", vm_type) < 0) goto error;
    if (PyDict_SetItemString(__dict, "vm_version", vm_version) < 0) goto error;
    if (PyDict_SetItemString(__dict, "code_hash", code_hash) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(vm_type);
    Py_DECREF(vm_version);
    Py_DECREF(code_hash);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking code_id");
    Py_XDECREF(vm_type);
    Py_XDECREF(vm_version);
    Py_XDECREF(code_hash);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_account_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct account_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "name",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field name: name
    PyObject *name = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "creation_date",
            "block_timestamp_type",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field creation_date: block_timestamp_type
    PyObject *creation_date = unpack_block_timestamp_type(b + __total, buf_len, &__consumed, __depth + 1);

    if (!creation_date) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("creation_date start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "abi",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field abi: bytes
    PyObject *abi = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!abi) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("abi start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "name", name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "creation_date", creation_date) < 0) goto error;
    if (PyDict_SetItemString(__dict, "abi", abi) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(name);
    Py_DECREF(creation_date);
    Py_DECREF(abi);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking account_v0");
    Py_XDECREF(name);
    Py_XDECREF(creation_date);
    Py_XDECREF(abi);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_account_metadata_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct account_metadata_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "name",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field name: name
    PyObject *name = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "privileged",
            "bool",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field privileged: bool
    PyObject *privileged = unpack_bool(b + __total, buf_len, &__consumed, __depth + 1);

    if (!privileged) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("privileged start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "last_code_update",
            "time_point",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field last_code_update: time_point
    PyObject *last_code_update = unpack_time_point(b + __total, buf_len, &__consumed, __depth + 1);

    if (!last_code_update) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("last_code_update start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code",
            "code_id",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code: code_id?
    PyObject *code = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_code = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_code, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_code) {
        code = unpack_code_id(b + __total, buf_len, &__consumed, __depth + 1);
        if (!code) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        code = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "name", name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "privileged", privileged) < 0) goto error;
    if (PyDict_SetItemString(__dict, "last_code_update", last_code_update) < 0) goto error;
    if (PyDict_SetItemString(__dict, "code", code) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(name);
    Py_DECREF(privileged);
    Py_DECREF(last_code_update);
    Py_DECREF(code);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking account_metadata_v0");
    Py_XDECREF(name);
    Py_XDECREF(privileged);
    Py_XDECREF(last_code_update);
    Py_XDECREF(code);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_code_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct code_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "vm_type",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field vm_type: uint8
    PyObject *vm_type = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!vm_type) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("vm_type start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "vm_version",
            "uint8",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field vm_version: uint8
    PyObject *vm_version = unpack_uint8(b + __total, buf_len, &__consumed, __depth + 1);

    if (!vm_version) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("vm_version start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code_hash",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code_hash: checksum256
    PyObject *code_hash = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code_hash) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code_hash start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code: bytes
    PyObject *code = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "vm_type", vm_type) < 0) goto error;
    if (PyDict_SetItemString(__dict, "vm_version", vm_version) < 0) goto error;
    if (PyDict_SetItemString(__dict, "code_hash", code_hash) < 0) goto error;
    if (PyDict_SetItemString(__dict, "code", code) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(vm_type);
    Py_DECREF(vm_version);
    Py_DECREF(code_hash);
    Py_DECREF(code);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking code_v0");
    Py_XDECREF(vm_type);
    Py_XDECREF(vm_version);
    Py_XDECREF(code_hash);
    Py_XDECREF(code);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_contract_table_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct contract_table_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code: name
    PyObject *code = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "scope",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field scope: name
    PyObject *scope = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!scope) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("scope start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "table",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field table: name
    PyObject *table = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!table) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("table start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "payer",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field payer: name
    PyObject *payer = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!payer) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("payer start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "code", code) < 0) goto error;
    if (PyDict_SetItemString(__dict, "scope", scope) < 0) goto error;
    if (PyDict_SetItemString(__dict, "table", table) < 0) goto error;
    if (PyDict_SetItemString(__dict, "payer", payer) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(code);
    Py_DECREF(scope);
    Py_DECREF(table);
    Py_DECREF(payer);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking contract_table_v0");
    Py_XDECREF(code);
    Py_XDECREF(scope);
    Py_XDECREF(table);
    Py_XDECREF(payer);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_contract_row_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct contract_row_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code: name
    PyObject *code = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "scope",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field scope: name
    PyObject *scope = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!scope) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("scope start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "table",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field table: name
    PyObject *table = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!table) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("table start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "primary_key",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field primary_key: uint64
    PyObject *primary_key = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!primary_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("primary_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "payer",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field payer: name
    PyObject *payer = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!payer) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("payer start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "value",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field value: bytes
    PyObject *value = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!value) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("value start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "code", code) < 0) goto error;
    if (PyDict_SetItemString(__dict, "scope", scope) < 0) goto error;
    if (PyDict_SetItemString(__dict, "table", table) < 0) goto error;
    if (PyDict_SetItemString(__dict, "primary_key", primary_key) < 0) goto error;
    if (PyDict_SetItemString(__dict, "payer", payer) < 0) goto error;
    if (PyDict_SetItemString(__dict, "value", value) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(code);
    Py_DECREF(scope);
    Py_DECREF(table);
    Py_DECREF(primary_key);
    Py_DECREF(payer);
    Py_DECREF(value);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking contract_row_v0");
    Py_XDECREF(code);
    Py_XDECREF(scope);
    Py_XDECREF(table);
    Py_XDECREF(primary_key);
    Py_XDECREF(payer);
    Py_XDECREF(value);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_contract_index64_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct contract_index64_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code: name
    PyObject *code = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "scope",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field scope: name
    PyObject *scope = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!scope) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("scope start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "table",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field table: name
    PyObject *table = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!table) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("table start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "primary_key",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field primary_key: uint64
    PyObject *primary_key = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!primary_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("primary_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "payer",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field payer: name
    PyObject *payer = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!payer) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("payer start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "secondary_key",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field secondary_key: uint64
    PyObject *secondary_key = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!secondary_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("secondary_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "code", code) < 0) goto error;
    if (PyDict_SetItemString(__dict, "scope", scope) < 0) goto error;
    if (PyDict_SetItemString(__dict, "table", table) < 0) goto error;
    if (PyDict_SetItemString(__dict, "primary_key", primary_key) < 0) goto error;
    if (PyDict_SetItemString(__dict, "payer", payer) < 0) goto error;
    if (PyDict_SetItemString(__dict, "secondary_key", secondary_key) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(code);
    Py_DECREF(scope);
    Py_DECREF(table);
    Py_DECREF(primary_key);
    Py_DECREF(payer);
    Py_DECREF(secondary_key);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking contract_index64_v0");
    Py_XDECREF(code);
    Py_XDECREF(scope);
    Py_XDECREF(table);
    Py_XDECREF(primary_key);
    Py_XDECREF(payer);
    Py_XDECREF(secondary_key);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_contract_index128_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct contract_index128_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code: name
    PyObject *code = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "scope",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field scope: name
    PyObject *scope = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!scope) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("scope start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "table",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field table: name
    PyObject *table = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!table) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("table start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "primary_key",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field primary_key: uint64
    PyObject *primary_key = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!primary_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("primary_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "payer",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field payer: name
    PyObject *payer = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!payer) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("payer start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "secondary_key",
            "uint128",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field secondary_key: uint128
    PyObject *secondary_key = unpack_uint128(b + __total, buf_len, &__consumed, __depth + 1);

    if (!secondary_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("secondary_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "code", code) < 0) goto error;
    if (PyDict_SetItemString(__dict, "scope", scope) < 0) goto error;
    if (PyDict_SetItemString(__dict, "table", table) < 0) goto error;
    if (PyDict_SetItemString(__dict, "primary_key", primary_key) < 0) goto error;
    if (PyDict_SetItemString(__dict, "payer", payer) < 0) goto error;
    if (PyDict_SetItemString(__dict, "secondary_key", secondary_key) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(code);
    Py_DECREF(scope);
    Py_DECREF(table);
    Py_DECREF(primary_key);
    Py_DECREF(payer);
    Py_DECREF(secondary_key);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking contract_index128_v0");
    Py_XDECREF(code);
    Py_XDECREF(scope);
    Py_XDECREF(table);
    Py_XDECREF(primary_key);
    Py_XDECREF(payer);
    Py_XDECREF(secondary_key);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_contract_index256_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct contract_index256_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code: name
    PyObject *code = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "scope",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field scope: name
    PyObject *scope = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!scope) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("scope start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "table",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field table: name
    PyObject *table = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!table) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("table start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "primary_key",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field primary_key: uint64
    PyObject *primary_key = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!primary_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("primary_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "payer",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field payer: name
    PyObject *payer = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!payer) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("payer start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "secondary_key",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field secondary_key: checksum256
    PyObject *secondary_key = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!secondary_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("secondary_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "code", code) < 0) goto error;
    if (PyDict_SetItemString(__dict, "scope", scope) < 0) goto error;
    if (PyDict_SetItemString(__dict, "table", table) < 0) goto error;
    if (PyDict_SetItemString(__dict, "primary_key", primary_key) < 0) goto error;
    if (PyDict_SetItemString(__dict, "payer", payer) < 0) goto error;
    if (PyDict_SetItemString(__dict, "secondary_key", secondary_key) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(code);
    Py_DECREF(scope);
    Py_DECREF(table);
    Py_DECREF(primary_key);
    Py_DECREF(payer);
    Py_DECREF(secondary_key);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking contract_index256_v0");
    Py_XDECREF(code);
    Py_XDECREF(scope);
    Py_XDECREF(table);
    Py_XDECREF(primary_key);
    Py_XDECREF(payer);
    Py_XDECREF(secondary_key);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_contract_index_double_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct contract_index_double_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code: name
    PyObject *code = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "scope",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field scope: name
    PyObject *scope = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!scope) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("scope start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "table",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field table: name
    PyObject *table = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!table) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("table start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "primary_key",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field primary_key: uint64
    PyObject *primary_key = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!primary_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("primary_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "payer",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field payer: name
    PyObject *payer = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!payer) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("payer start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "secondary_key",
            "float64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field secondary_key: float64
    PyObject *secondary_key = unpack_float64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!secondary_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("secondary_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "code", code) < 0) goto error;
    if (PyDict_SetItemString(__dict, "scope", scope) < 0) goto error;
    if (PyDict_SetItemString(__dict, "table", table) < 0) goto error;
    if (PyDict_SetItemString(__dict, "primary_key", primary_key) < 0) goto error;
    if (PyDict_SetItemString(__dict, "payer", payer) < 0) goto error;
    if (PyDict_SetItemString(__dict, "secondary_key", secondary_key) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(code);
    Py_DECREF(scope);
    Py_DECREF(table);
    Py_DECREF(primary_key);
    Py_DECREF(payer);
    Py_DECREF(secondary_key);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking contract_index_double_v0");
    Py_XDECREF(code);
    Py_XDECREF(scope);
    Py_XDECREF(table);
    Py_XDECREF(primary_key);
    Py_XDECREF(payer);
    Py_XDECREF(secondary_key);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_contract_index_long_double_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct contract_index_long_double_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code: name
    PyObject *code = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "scope",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field scope: name
    PyObject *scope = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!scope) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("scope start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "table",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field table: name
    PyObject *table = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!table) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("table start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "primary_key",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field primary_key: uint64
    PyObject *primary_key = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!primary_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("primary_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "payer",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field payer: name
    PyObject *payer = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!payer) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("payer start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "secondary_key",
            "float128",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field secondary_key: float128
    PyObject *secondary_key = unpack_float128(b + __total, buf_len, &__consumed, __depth + 1);

    if (!secondary_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("secondary_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "code", code) < 0) goto error;
    if (PyDict_SetItemString(__dict, "scope", scope) < 0) goto error;
    if (PyDict_SetItemString(__dict, "table", table) < 0) goto error;
    if (PyDict_SetItemString(__dict, "primary_key", primary_key) < 0) goto error;
    if (PyDict_SetItemString(__dict, "payer", payer) < 0) goto error;
    if (PyDict_SetItemString(__dict, "secondary_key", secondary_key) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(code);
    Py_DECREF(scope);
    Py_DECREF(table);
    Py_DECREF(primary_key);
    Py_DECREF(payer);
    Py_DECREF(secondary_key);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking contract_index_long_double_v0");
    Py_XDECREF(code);
    Py_XDECREF(scope);
    Py_XDECREF(table);
    Py_XDECREF(primary_key);
    Py_XDECREF(payer);
    Py_XDECREF(secondary_key);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_producer_key(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct producer_key:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "producer_name",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field producer_name: name
    PyObject *producer_name = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!producer_name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("producer_name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "block_signing_key",
            "public_key",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field block_signing_key: public_key
    PyObject *block_signing_key = unpack_public_key(b + __total, buf_len, &__consumed, __depth + 1);

    if (!block_signing_key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("block_signing_key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "producer_name", producer_name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "block_signing_key", block_signing_key) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(producer_name);
    Py_DECREF(block_signing_key);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking producer_key");
    Py_XDECREF(producer_name);
    Py_XDECREF(block_signing_key);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_producer_schedule(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct producer_schedule:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "version",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field version: uint32
    PyObject *version = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!version) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("version start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "producers",
            "producer_key",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field producers: producer_key[]
    size_t __len_producers = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *producers = PyList_New(__len_producers);
    if (!producers) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_producers);
    #endif

    for (size_t _i = 0; _i < __len_producers; ++_i) {
        PyObject *_item = unpack_producer_key(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(producers); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(producers, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("producers start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "version", version) < 0) goto error;
    if (PyDict_SetItemString(__dict, "producers", producers) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(version);
    Py_DECREF(producers);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking producer_schedule");
    Py_XDECREF(version);
    Py_XDECREF(producers);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_block_signing_authority_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct block_signing_authority_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "threshold",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field threshold: uint32
    PyObject *threshold = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!threshold) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("threshold start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "keys",
            "key_weight",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field keys: key_weight[]
    size_t __len_keys = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *keys = PyList_New(__len_keys);
    if (!keys) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_keys);
    #endif

    for (size_t _i = 0; _i < __len_keys; ++_i) {
        PyObject *_item = unpack_key_weight(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(keys); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(keys, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("keys start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "threshold", threshold) < 0) goto error;
    if (PyDict_SetItemString(__dict, "keys", keys) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(threshold);
    Py_DECREF(keys);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking block_signing_authority_v0");
    Py_XDECREF(threshold);
    Py_XDECREF(keys);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_producer_authority(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct producer_authority:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "producer_name",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field producer_name: name
    PyObject *producer_name = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!producer_name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("producer_name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "authority",
            "block_signing_authority",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field authority: block_signing_authority
    PyObject *authority = unpack_block_signing_authority(b + __total, buf_len, &__consumed, __depth + 1);

    if (!authority) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("authority start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "producer_name", producer_name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "authority", authority) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(producer_name);
    Py_DECREF(authority);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking producer_authority");
    Py_XDECREF(producer_name);
    Py_XDECREF(authority);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_producer_authority_schedule(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct producer_authority_schedule:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "version",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field version: uint32
    PyObject *version = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!version) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("version start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "producers",
            "producer_authority",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field producers: producer_authority[]
    size_t __len_producers = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *producers = PyList_New(__len_producers);
    if (!producers) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_producers);
    #endif

    for (size_t _i = 0; _i < __len_producers; ++_i) {
        PyObject *_item = unpack_producer_authority(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(producers); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(producers, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("producers start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "version", version) < 0) goto error;
    if (PyDict_SetItemString(__dict, "producers", producers) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(version);
    Py_DECREF(producers);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking producer_authority_schedule");
    Py_XDECREF(version);
    Py_XDECREF(producers);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_chain_config_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct chain_config_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_block_net_usage",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_block_net_usage: uint64
    PyObject *max_block_net_usage = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_block_net_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_block_net_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "target_block_net_usage_pct",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field target_block_net_usage_pct: uint32
    PyObject *target_block_net_usage_pct = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!target_block_net_usage_pct) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("target_block_net_usage_pct start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_transaction_net_usage",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_transaction_net_usage: uint32
    PyObject *max_transaction_net_usage = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_transaction_net_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_transaction_net_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "base_per_transaction_net_usage",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field base_per_transaction_net_usage: uint32
    PyObject *base_per_transaction_net_usage = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!base_per_transaction_net_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("base_per_transaction_net_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "net_usage_leeway",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field net_usage_leeway: uint32
    PyObject *net_usage_leeway = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!net_usage_leeway) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("net_usage_leeway start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "context_free_discount_net_usage_num",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field context_free_discount_net_usage_num: uint32
    PyObject *context_free_discount_net_usage_num = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!context_free_discount_net_usage_num) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("context_free_discount_net_usage_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "context_free_discount_net_usage_den",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field context_free_discount_net_usage_den: uint32
    PyObject *context_free_discount_net_usage_den = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!context_free_discount_net_usage_den) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("context_free_discount_net_usage_den start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_block_cpu_usage",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_block_cpu_usage: uint32
    PyObject *max_block_cpu_usage = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_block_cpu_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_block_cpu_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "target_block_cpu_usage_pct",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field target_block_cpu_usage_pct: uint32
    PyObject *target_block_cpu_usage_pct = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!target_block_cpu_usage_pct) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("target_block_cpu_usage_pct start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_transaction_cpu_usage",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_transaction_cpu_usage: uint32
    PyObject *max_transaction_cpu_usage = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_transaction_cpu_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_transaction_cpu_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "min_transaction_cpu_usage",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field min_transaction_cpu_usage: uint32
    PyObject *min_transaction_cpu_usage = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!min_transaction_cpu_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("min_transaction_cpu_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_transaction_lifetime",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_transaction_lifetime: uint32
    PyObject *max_transaction_lifetime = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_transaction_lifetime) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_transaction_lifetime start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "deferred_trx_expiration_window",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field deferred_trx_expiration_window: uint32
    PyObject *deferred_trx_expiration_window = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!deferred_trx_expiration_window) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("deferred_trx_expiration_window start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_transaction_delay",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_transaction_delay: uint32
    PyObject *max_transaction_delay = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_transaction_delay) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_transaction_delay start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_inline_action_size",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_inline_action_size: uint32
    PyObject *max_inline_action_size = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_inline_action_size) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_inline_action_size start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_inline_action_depth",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_inline_action_depth: uint16
    PyObject *max_inline_action_depth = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_inline_action_depth) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_inline_action_depth start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_authority_depth",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_authority_depth: uint16
    PyObject *max_authority_depth = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_authority_depth) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_authority_depth start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "max_block_net_usage", max_block_net_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "target_block_net_usage_pct", target_block_net_usage_pct) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_transaction_net_usage", max_transaction_net_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "base_per_transaction_net_usage", base_per_transaction_net_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "net_usage_leeway", net_usage_leeway) < 0) goto error;
    if (PyDict_SetItemString(__dict, "context_free_discount_net_usage_num", context_free_discount_net_usage_num) < 0) goto error;
    if (PyDict_SetItemString(__dict, "context_free_discount_net_usage_den", context_free_discount_net_usage_den) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_block_cpu_usage", max_block_cpu_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "target_block_cpu_usage_pct", target_block_cpu_usage_pct) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_transaction_cpu_usage", max_transaction_cpu_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "min_transaction_cpu_usage", min_transaction_cpu_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_transaction_lifetime", max_transaction_lifetime) < 0) goto error;
    if (PyDict_SetItemString(__dict, "deferred_trx_expiration_window", deferred_trx_expiration_window) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_transaction_delay", max_transaction_delay) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_inline_action_size", max_inline_action_size) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_inline_action_depth", max_inline_action_depth) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_authority_depth", max_authority_depth) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(max_block_net_usage);
    Py_DECREF(target_block_net_usage_pct);
    Py_DECREF(max_transaction_net_usage);
    Py_DECREF(base_per_transaction_net_usage);
    Py_DECREF(net_usage_leeway);
    Py_DECREF(context_free_discount_net_usage_num);
    Py_DECREF(context_free_discount_net_usage_den);
    Py_DECREF(max_block_cpu_usage);
    Py_DECREF(target_block_cpu_usage_pct);
    Py_DECREF(max_transaction_cpu_usage);
    Py_DECREF(min_transaction_cpu_usage);
    Py_DECREF(max_transaction_lifetime);
    Py_DECREF(deferred_trx_expiration_window);
    Py_DECREF(max_transaction_delay);
    Py_DECREF(max_inline_action_size);
    Py_DECREF(max_inline_action_depth);
    Py_DECREF(max_authority_depth);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking chain_config_v0");
    Py_XDECREF(max_block_net_usage);
    Py_XDECREF(target_block_net_usage_pct);
    Py_XDECREF(max_transaction_net_usage);
    Py_XDECREF(base_per_transaction_net_usage);
    Py_XDECREF(net_usage_leeway);
    Py_XDECREF(context_free_discount_net_usage_num);
    Py_XDECREF(context_free_discount_net_usage_den);
    Py_XDECREF(max_block_cpu_usage);
    Py_XDECREF(target_block_cpu_usage_pct);
    Py_XDECREF(max_transaction_cpu_usage);
    Py_XDECREF(min_transaction_cpu_usage);
    Py_XDECREF(max_transaction_lifetime);
    Py_XDECREF(deferred_trx_expiration_window);
    Py_XDECREF(max_transaction_delay);
    Py_XDECREF(max_inline_action_size);
    Py_XDECREF(max_inline_action_depth);
    Py_XDECREF(max_authority_depth);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_chain_config_v1(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct chain_config_v1:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_block_net_usage",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_block_net_usage: uint64
    PyObject *max_block_net_usage = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_block_net_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_block_net_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "target_block_net_usage_pct",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field target_block_net_usage_pct: uint32
    PyObject *target_block_net_usage_pct = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!target_block_net_usage_pct) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("target_block_net_usage_pct start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_transaction_net_usage",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_transaction_net_usage: uint32
    PyObject *max_transaction_net_usage = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_transaction_net_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_transaction_net_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "base_per_transaction_net_usage",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field base_per_transaction_net_usage: uint32
    PyObject *base_per_transaction_net_usage = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!base_per_transaction_net_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("base_per_transaction_net_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "net_usage_leeway",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field net_usage_leeway: uint32
    PyObject *net_usage_leeway = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!net_usage_leeway) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("net_usage_leeway start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "context_free_discount_net_usage_num",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field context_free_discount_net_usage_num: uint32
    PyObject *context_free_discount_net_usage_num = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!context_free_discount_net_usage_num) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("context_free_discount_net_usage_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "context_free_discount_net_usage_den",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field context_free_discount_net_usage_den: uint32
    PyObject *context_free_discount_net_usage_den = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!context_free_discount_net_usage_den) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("context_free_discount_net_usage_den start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_block_cpu_usage",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_block_cpu_usage: uint32
    PyObject *max_block_cpu_usage = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_block_cpu_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_block_cpu_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "target_block_cpu_usage_pct",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field target_block_cpu_usage_pct: uint32
    PyObject *target_block_cpu_usage_pct = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!target_block_cpu_usage_pct) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("target_block_cpu_usage_pct start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_transaction_cpu_usage",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_transaction_cpu_usage: uint32
    PyObject *max_transaction_cpu_usage = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_transaction_cpu_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_transaction_cpu_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "min_transaction_cpu_usage",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field min_transaction_cpu_usage: uint32
    PyObject *min_transaction_cpu_usage = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!min_transaction_cpu_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("min_transaction_cpu_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_transaction_lifetime",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_transaction_lifetime: uint32
    PyObject *max_transaction_lifetime = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_transaction_lifetime) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_transaction_lifetime start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "deferred_trx_expiration_window",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field deferred_trx_expiration_window: uint32
    PyObject *deferred_trx_expiration_window = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!deferred_trx_expiration_window) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("deferred_trx_expiration_window start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_transaction_delay",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_transaction_delay: uint32
    PyObject *max_transaction_delay = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_transaction_delay) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_transaction_delay start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_inline_action_size",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_inline_action_size: uint32
    PyObject *max_inline_action_size = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_inline_action_size) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_inline_action_size start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_inline_action_depth",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_inline_action_depth: uint16
    PyObject *max_inline_action_depth = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_inline_action_depth) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_inline_action_depth start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_authority_depth",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_authority_depth: uint16
    PyObject *max_authority_depth = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_authority_depth) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_authority_depth start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_action_return_value_size",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_action_return_value_size: uint32
    PyObject *max_action_return_value_size = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_action_return_value_size) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_action_return_value_size start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "max_block_net_usage", max_block_net_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "target_block_net_usage_pct", target_block_net_usage_pct) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_transaction_net_usage", max_transaction_net_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "base_per_transaction_net_usage", base_per_transaction_net_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "net_usage_leeway", net_usage_leeway) < 0) goto error;
    if (PyDict_SetItemString(__dict, "context_free_discount_net_usage_num", context_free_discount_net_usage_num) < 0) goto error;
    if (PyDict_SetItemString(__dict, "context_free_discount_net_usage_den", context_free_discount_net_usage_den) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_block_cpu_usage", max_block_cpu_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "target_block_cpu_usage_pct", target_block_cpu_usage_pct) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_transaction_cpu_usage", max_transaction_cpu_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "min_transaction_cpu_usage", min_transaction_cpu_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_transaction_lifetime", max_transaction_lifetime) < 0) goto error;
    if (PyDict_SetItemString(__dict, "deferred_trx_expiration_window", deferred_trx_expiration_window) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_transaction_delay", max_transaction_delay) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_inline_action_size", max_inline_action_size) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_inline_action_depth", max_inline_action_depth) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_authority_depth", max_authority_depth) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_action_return_value_size", max_action_return_value_size) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(max_block_net_usage);
    Py_DECREF(target_block_net_usage_pct);
    Py_DECREF(max_transaction_net_usage);
    Py_DECREF(base_per_transaction_net_usage);
    Py_DECREF(net_usage_leeway);
    Py_DECREF(context_free_discount_net_usage_num);
    Py_DECREF(context_free_discount_net_usage_den);
    Py_DECREF(max_block_cpu_usage);
    Py_DECREF(target_block_cpu_usage_pct);
    Py_DECREF(max_transaction_cpu_usage);
    Py_DECREF(min_transaction_cpu_usage);
    Py_DECREF(max_transaction_lifetime);
    Py_DECREF(deferred_trx_expiration_window);
    Py_DECREF(max_transaction_delay);
    Py_DECREF(max_inline_action_size);
    Py_DECREF(max_inline_action_depth);
    Py_DECREF(max_authority_depth);
    Py_DECREF(max_action_return_value_size);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking chain_config_v1");
    Py_XDECREF(max_block_net_usage);
    Py_XDECREF(target_block_net_usage_pct);
    Py_XDECREF(max_transaction_net_usage);
    Py_XDECREF(base_per_transaction_net_usage);
    Py_XDECREF(net_usage_leeway);
    Py_XDECREF(context_free_discount_net_usage_num);
    Py_XDECREF(context_free_discount_net_usage_den);
    Py_XDECREF(max_block_cpu_usage);
    Py_XDECREF(target_block_cpu_usage_pct);
    Py_XDECREF(max_transaction_cpu_usage);
    Py_XDECREF(min_transaction_cpu_usage);
    Py_XDECREF(max_transaction_lifetime);
    Py_XDECREF(deferred_trx_expiration_window);
    Py_XDECREF(max_transaction_delay);
    Py_XDECREF(max_inline_action_size);
    Py_XDECREF(max_inline_action_depth);
    Py_XDECREF(max_authority_depth);
    Py_XDECREF(max_action_return_value_size);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_wasm_config_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct wasm_config_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_mutable_global_bytes",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_mutable_global_bytes: uint32
    PyObject *max_mutable_global_bytes = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_mutable_global_bytes) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_mutable_global_bytes start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_table_elements",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_table_elements: uint32
    PyObject *max_table_elements = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_table_elements) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_table_elements start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_section_elements",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_section_elements: uint32
    PyObject *max_section_elements = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_section_elements) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_section_elements start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_linear_memory_init",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_linear_memory_init: uint32
    PyObject *max_linear_memory_init = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_linear_memory_init) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_linear_memory_init start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_func_local_bytes",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_func_local_bytes: uint32
    PyObject *max_func_local_bytes = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_func_local_bytes) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_func_local_bytes start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_nested_structures",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_nested_structures: uint32
    PyObject *max_nested_structures = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_nested_structures) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_nested_structures start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_symbol_bytes",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_symbol_bytes: uint32
    PyObject *max_symbol_bytes = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_symbol_bytes) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_symbol_bytes start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_module_bytes",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_module_bytes: uint32
    PyObject *max_module_bytes = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_module_bytes) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_module_bytes start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_code_bytes",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_code_bytes: uint32
    PyObject *max_code_bytes = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_code_bytes) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_code_bytes start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_pages",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_pages: uint32
    PyObject *max_pages = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_pages) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_pages start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_call_depth",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_call_depth: uint32
    PyObject *max_call_depth = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_call_depth) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_call_depth start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "max_mutable_global_bytes", max_mutable_global_bytes) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_table_elements", max_table_elements) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_section_elements", max_section_elements) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_linear_memory_init", max_linear_memory_init) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_func_local_bytes", max_func_local_bytes) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_nested_structures", max_nested_structures) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_symbol_bytes", max_symbol_bytes) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_module_bytes", max_module_bytes) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_code_bytes", max_code_bytes) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_pages", max_pages) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_call_depth", max_call_depth) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(max_mutable_global_bytes);
    Py_DECREF(max_table_elements);
    Py_DECREF(max_section_elements);
    Py_DECREF(max_linear_memory_init);
    Py_DECREF(max_func_local_bytes);
    Py_DECREF(max_nested_structures);
    Py_DECREF(max_symbol_bytes);
    Py_DECREF(max_module_bytes);
    Py_DECREF(max_code_bytes);
    Py_DECREF(max_pages);
    Py_DECREF(max_call_depth);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking wasm_config_v0");
    Py_XDECREF(max_mutable_global_bytes);
    Py_XDECREF(max_table_elements);
    Py_XDECREF(max_section_elements);
    Py_XDECREF(max_linear_memory_init);
    Py_XDECREF(max_func_local_bytes);
    Py_XDECREF(max_nested_structures);
    Py_XDECREF(max_symbol_bytes);
    Py_XDECREF(max_module_bytes);
    Py_XDECREF(max_code_bytes);
    Py_XDECREF(max_pages);
    Py_XDECREF(max_call_depth);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_global_property_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct global_property_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "proposed_schedule_block_num",
            "uint32",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field proposed_schedule_block_num: uint32?
    PyObject *proposed_schedule_block_num = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_proposed_schedule_block_num = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_proposed_schedule_block_num, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_proposed_schedule_block_num) {
        proposed_schedule_block_num = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);
        if (!proposed_schedule_block_num) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        proposed_schedule_block_num = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("proposed_schedule_block_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "proposed_schedule",
            "producer_schedule",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field proposed_schedule: producer_schedule
    PyObject *proposed_schedule = unpack_producer_schedule(b + __total, buf_len, &__consumed, __depth + 1);

    if (!proposed_schedule) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("proposed_schedule start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "configuration",
            "chain_config",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field configuration: chain_config
    PyObject *configuration = unpack_chain_config(b + __total, buf_len, &__consumed, __depth + 1);

    if (!configuration) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("configuration start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "proposed_schedule_block_num", proposed_schedule_block_num) < 0) goto error;
    if (PyDict_SetItemString(__dict, "proposed_schedule", proposed_schedule) < 0) goto error;
    if (PyDict_SetItemString(__dict, "configuration", configuration) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(proposed_schedule_block_num);
    Py_DECREF(proposed_schedule);
    Py_DECREF(configuration);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking global_property_v0");
    Py_XDECREF(proposed_schedule_block_num);
    Py_XDECREF(proposed_schedule);
    Py_XDECREF(configuration);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_global_property_v1(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct global_property_v1:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "proposed_schedule_block_num",
            "uint32",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field proposed_schedule_block_num: uint32?
    PyObject *proposed_schedule_block_num = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_proposed_schedule_block_num = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_proposed_schedule_block_num, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_proposed_schedule_block_num) {
        proposed_schedule_block_num = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);
        if (!proposed_schedule_block_num) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        proposed_schedule_block_num = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("proposed_schedule_block_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "proposed_schedule",
            "producer_authority_schedule",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field proposed_schedule: producer_authority_schedule
    PyObject *proposed_schedule = unpack_producer_authority_schedule(b + __total, buf_len, &__consumed, __depth + 1);

    if (!proposed_schedule) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("proposed_schedule start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "configuration",
            "chain_config",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field configuration: chain_config
    PyObject *configuration = unpack_chain_config(b + __total, buf_len, &__consumed, __depth + 1);

    if (!configuration) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("configuration start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "chain_id",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field chain_id: checksum256
    PyObject *chain_id = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!chain_id) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("chain_id start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "wasm_configuration",
            "wasm_config",
            "$"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field wasm_configuration: wasm_config$
    PyObject *wasm_configuration = NULL;

    if (__total < buf_len) {
        wasm_configuration = unpack_wasm_config(b + __total, buf_len, &__consumed, __depth + 1);
        if (!wasm_configuration) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        wasm_configuration = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("wasm_configuration start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "proposed_schedule_block_num", proposed_schedule_block_num) < 0) goto error;
    if (PyDict_SetItemString(__dict, "proposed_schedule", proposed_schedule) < 0) goto error;
    if (PyDict_SetItemString(__dict, "configuration", configuration) < 0) goto error;
    if (PyDict_SetItemString(__dict, "chain_id", chain_id) < 0) goto error;
    if (PyDict_SetItemString(__dict, "wasm_configuration", wasm_configuration) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(proposed_schedule_block_num);
    Py_DECREF(proposed_schedule);
    Py_DECREF(configuration);
    Py_DECREF(chain_id);
    Py_DECREF(wasm_configuration);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking global_property_v1");
    Py_XDECREF(proposed_schedule_block_num);
    Py_XDECREF(proposed_schedule);
    Py_XDECREF(configuration);
    Py_XDECREF(chain_id);
    Py_XDECREF(wasm_configuration);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_generated_transaction_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct generated_transaction_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "sender",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field sender: name
    PyObject *sender = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!sender) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("sender start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "sender_id",
            "uint128",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field sender_id: uint128
    PyObject *sender_id = unpack_uint128(b + __total, buf_len, &__consumed, __depth + 1);

    if (!sender_id) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("sender_id start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "payer",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field payer: name
    PyObject *payer = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!payer) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("payer start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "trx_id",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field trx_id: checksum256
    PyObject *trx_id = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!trx_id) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("trx_id start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "packed_trx",
            "bytes",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field packed_trx: bytes
    PyObject *packed_trx = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);

    if (!packed_trx) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("packed_trx start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "sender", sender) < 0) goto error;
    if (PyDict_SetItemString(__dict, "sender_id", sender_id) < 0) goto error;
    if (PyDict_SetItemString(__dict, "payer", payer) < 0) goto error;
    if (PyDict_SetItemString(__dict, "trx_id", trx_id) < 0) goto error;
    if (PyDict_SetItemString(__dict, "packed_trx", packed_trx) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(sender);
    Py_DECREF(sender_id);
    Py_DECREF(payer);
    Py_DECREF(trx_id);
    Py_DECREF(packed_trx);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking generated_transaction_v0");
    Py_XDECREF(sender);
    Py_XDECREF(sender_id);
    Py_XDECREF(payer);
    Py_XDECREF(trx_id);
    Py_XDECREF(packed_trx);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_activated_protocol_feature_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct activated_protocol_feature_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "feature_digest",
            "checksum256",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field feature_digest: checksum256
    PyObject *feature_digest = unpack_checksum256(b + __total, buf_len, &__consumed, __depth + 1);

    if (!feature_digest) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("feature_digest start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "activation_block_num",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field activation_block_num: uint32
    PyObject *activation_block_num = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!activation_block_num) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("activation_block_num start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "feature_digest", feature_digest) < 0) goto error;
    if (PyDict_SetItemString(__dict, "activation_block_num", activation_block_num) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(feature_digest);
    Py_DECREF(activation_block_num);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking activated_protocol_feature_v0");
    Py_XDECREF(feature_digest);
    Py_XDECREF(activation_block_num);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_protocol_state_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct protocol_state_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "activated_protocol_features",
            "activated_protocol_feature",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field activated_protocol_features: activated_protocol_feature[]
    size_t __len_activated_protocol_features = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *activated_protocol_features = PyList_New(__len_activated_protocol_features);
    if (!activated_protocol_features) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_activated_protocol_features);
    #endif

    for (size_t _i = 0; _i < __len_activated_protocol_features; ++_i) {
        PyObject *_item = unpack_activated_protocol_feature(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(activated_protocol_features); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(activated_protocol_features, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("activated_protocol_features start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "activated_protocol_features", activated_protocol_features) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(activated_protocol_features);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking protocol_state_v0");
    Py_XDECREF(activated_protocol_features);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_key_weight(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct key_weight:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "key",
            "public_key",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field key: public_key
    PyObject *key = unpack_public_key(b + __total, buf_len, &__consumed, __depth + 1);

    if (!key) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("key start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "weight",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field weight: uint16
    PyObject *weight = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!weight) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("weight start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "key", key) < 0) goto error;
    if (PyDict_SetItemString(__dict, "weight", weight) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(key);
    Py_DECREF(weight);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking key_weight");
    Py_XDECREF(key);
    Py_XDECREF(weight);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_permission_level(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct permission_level:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "actor",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field actor: name
    PyObject *actor = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!actor) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("actor start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "permission",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field permission: name
    PyObject *permission = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!permission) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("permission start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "actor", actor) < 0) goto error;
    if (PyDict_SetItemString(__dict, "permission", permission) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(actor);
    Py_DECREF(permission);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking permission_level");
    Py_XDECREF(actor);
    Py_XDECREF(permission);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_permission_level_weight(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct permission_level_weight:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "permission",
            "permission_level",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field permission: permission_level
    PyObject *permission = unpack_permission_level(b + __total, buf_len, &__consumed, __depth + 1);

    if (!permission) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("permission start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "weight",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field weight: uint16
    PyObject *weight = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!weight) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("weight start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "permission", permission) < 0) goto error;
    if (PyDict_SetItemString(__dict, "weight", weight) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(permission);
    Py_DECREF(weight);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking permission_level_weight");
    Py_XDECREF(permission);
    Py_XDECREF(weight);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_wait_weight(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct wait_weight:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "wait_sec",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field wait_sec: uint32
    PyObject *wait_sec = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!wait_sec) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("wait_sec start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "weight",
            "uint16",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field weight: uint16
    PyObject *weight = unpack_uint16(b + __total, buf_len, &__consumed, __depth + 1);

    if (!weight) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("weight start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "wait_sec", wait_sec) < 0) goto error;
    if (PyDict_SetItemString(__dict, "weight", weight) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(wait_sec);
    Py_DECREF(weight);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking wait_weight");
    Py_XDECREF(wait_sec);
    Py_XDECREF(weight);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_authority(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct authority:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "threshold",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field threshold: uint32
    PyObject *threshold = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!threshold) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("threshold start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "keys",
            "key_weight",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field keys: key_weight[]
    size_t __len_keys = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *keys = PyList_New(__len_keys);
    if (!keys) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_keys);
    #endif

    for (size_t _i = 0; _i < __len_keys; ++_i) {
        PyObject *_item = unpack_key_weight(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(keys); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(keys, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("keys start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "accounts",
            "permission_level_weight",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field accounts: permission_level_weight[]
    size_t __len_accounts = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *accounts = PyList_New(__len_accounts);
    if (!accounts) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_accounts);
    #endif

    for (size_t _i = 0; _i < __len_accounts; ++_i) {
        PyObject *_item = unpack_permission_level_weight(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(accounts); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(accounts, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("accounts start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "waits",
            "wait_weight",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field waits: wait_weight[]
    size_t __len_waits = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *waits = PyList_New(__len_waits);
    if (!waits) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_waits);
    #endif

    for (size_t _i = 0; _i < __len_waits; ++_i) {
        PyObject *_item = unpack_wait_weight(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(waits); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(waits, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("waits start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "threshold", threshold) < 0) goto error;
    if (PyDict_SetItemString(__dict, "keys", keys) < 0) goto error;
    if (PyDict_SetItemString(__dict, "accounts", accounts) < 0) goto error;
    if (PyDict_SetItemString(__dict, "waits", waits) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(threshold);
    Py_DECREF(keys);
    Py_DECREF(accounts);
    Py_DECREF(waits);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking authority");
    Py_XDECREF(threshold);
    Py_XDECREF(keys);
    Py_XDECREF(accounts);
    Py_XDECREF(waits);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_permission_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct permission_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "owner",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field owner: name
    PyObject *owner = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!owner) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("owner start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "name",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field name: name
    PyObject *name = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!name) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("name start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "parent",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field parent: name
    PyObject *parent = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!parent) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("parent start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "last_updated",
            "time_point",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field last_updated: time_point
    PyObject *last_updated = unpack_time_point(b + __total, buf_len, &__consumed, __depth + 1);

    if (!last_updated) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("last_updated start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "auth",
            "authority",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field auth: authority
    PyObject *auth = unpack_authority(b + __total, buf_len, &__consumed, __depth + 1);

    if (!auth) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("auth start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "owner", owner) < 0) goto error;
    if (PyDict_SetItemString(__dict, "name", name) < 0) goto error;
    if (PyDict_SetItemString(__dict, "parent", parent) < 0) goto error;
    if (PyDict_SetItemString(__dict, "last_updated", last_updated) < 0) goto error;
    if (PyDict_SetItemString(__dict, "auth", auth) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(owner);
    Py_DECREF(name);
    Py_DECREF(parent);
    Py_DECREF(last_updated);
    Py_DECREF(auth);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking permission_v0");
    Py_XDECREF(owner);
    Py_XDECREF(name);
    Py_XDECREF(parent);
    Py_XDECREF(last_updated);
    Py_XDECREF(auth);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_permission_link_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct permission_link_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "account",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field account: name
    PyObject *account = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!account) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("account start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "code",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field code: name
    PyObject *code = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!code) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("code start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "message_type",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field message_type: name
    PyObject *message_type = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!message_type) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("message_type start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "required_permission",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field required_permission: name
    PyObject *required_permission = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!required_permission) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("required_permission start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "account", account) < 0) goto error;
    if (PyDict_SetItemString(__dict, "code", code) < 0) goto error;
    if (PyDict_SetItemString(__dict, "message_type", message_type) < 0) goto error;
    if (PyDict_SetItemString(__dict, "required_permission", required_permission) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(account);
    Py_DECREF(code);
    Py_DECREF(message_type);
    Py_DECREF(required_permission);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking permission_link_v0");
    Py_XDECREF(account);
    Py_XDECREF(code);
    Py_XDECREF(message_type);
    Py_XDECREF(required_permission);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_resource_limits_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct resource_limits_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "owner",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field owner: name
    PyObject *owner = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!owner) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("owner start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "net_weight",
            "int64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field net_weight: int64
    PyObject *net_weight = unpack_int64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!net_weight) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("net_weight start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "cpu_weight",
            "int64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field cpu_weight: int64
    PyObject *cpu_weight = unpack_int64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!cpu_weight) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("cpu_weight start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ram_bytes",
            "int64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ram_bytes: int64
    PyObject *ram_bytes = unpack_int64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!ram_bytes) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ram_bytes start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "owner", owner) < 0) goto error;
    if (PyDict_SetItemString(__dict, "net_weight", net_weight) < 0) goto error;
    if (PyDict_SetItemString(__dict, "cpu_weight", cpu_weight) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ram_bytes", ram_bytes) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(owner);
    Py_DECREF(net_weight);
    Py_DECREF(cpu_weight);
    Py_DECREF(ram_bytes);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking resource_limits_v0");
    Py_XDECREF(owner);
    Py_XDECREF(net_weight);
    Py_XDECREF(cpu_weight);
    Py_XDECREF(ram_bytes);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_usage_accumulator_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct usage_accumulator_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "last_ordinal",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field last_ordinal: uint32
    PyObject *last_ordinal = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!last_ordinal) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("last_ordinal start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "value_ex",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field value_ex: uint64
    PyObject *value_ex = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!value_ex) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("value_ex start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "consumed",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field consumed: uint64
    PyObject *consumed = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!consumed) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("consumed start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "last_ordinal", last_ordinal) < 0) goto error;
    if (PyDict_SetItemString(__dict, "value_ex", value_ex) < 0) goto error;
    if (PyDict_SetItemString(__dict, "consumed", consumed) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(last_ordinal);
    Py_DECREF(value_ex);
    Py_DECREF(consumed);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking usage_accumulator_v0");
    Py_XDECREF(last_ordinal);
    Py_XDECREF(value_ex);
    Py_XDECREF(consumed);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_resource_usage_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct resource_usage_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "owner",
            "name",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field owner: name
    PyObject *owner = unpack_name(b + __total, buf_len, &__consumed, __depth + 1);

    if (!owner) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("owner start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "net_usage",
            "usage_accumulator",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field net_usage: usage_accumulator
    PyObject *net_usage = unpack_usage_accumulator(b + __total, buf_len, &__consumed, __depth + 1);

    if (!net_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("net_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "cpu_usage",
            "usage_accumulator",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field cpu_usage: usage_accumulator
    PyObject *cpu_usage = unpack_usage_accumulator(b + __total, buf_len, &__consumed, __depth + 1);

    if (!cpu_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("cpu_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "ram_usage",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field ram_usage: uint64
    PyObject *ram_usage = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!ram_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("ram_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "owner", owner) < 0) goto error;
    if (PyDict_SetItemString(__dict, "net_usage", net_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "cpu_usage", cpu_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "ram_usage", ram_usage) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(owner);
    Py_DECREF(net_usage);
    Py_DECREF(cpu_usage);
    Py_DECREF(ram_usage);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking resource_usage_v0");
    Py_XDECREF(owner);
    Py_XDECREF(net_usage);
    Py_XDECREF(cpu_usage);
    Py_XDECREF(ram_usage);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_resource_limits_state_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct resource_limits_state_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "average_block_net_usage",
            "usage_accumulator",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field average_block_net_usage: usage_accumulator
    PyObject *average_block_net_usage = unpack_usage_accumulator(b + __total, buf_len, &__consumed, __depth + 1);

    if (!average_block_net_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("average_block_net_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "average_block_cpu_usage",
            "usage_accumulator",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field average_block_cpu_usage: usage_accumulator
    PyObject *average_block_cpu_usage = unpack_usage_accumulator(b + __total, buf_len, &__consumed, __depth + 1);

    if (!average_block_cpu_usage) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("average_block_cpu_usage start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "total_net_weight",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field total_net_weight: uint64
    PyObject *total_net_weight = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!total_net_weight) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("total_net_weight start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "total_cpu_weight",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field total_cpu_weight: uint64
    PyObject *total_cpu_weight = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!total_cpu_weight) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("total_cpu_weight start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "total_ram_bytes",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field total_ram_bytes: uint64
    PyObject *total_ram_bytes = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!total_ram_bytes) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("total_ram_bytes start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "virtual_net_limit",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field virtual_net_limit: uint64
    PyObject *virtual_net_limit = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!virtual_net_limit) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("virtual_net_limit start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "virtual_cpu_limit",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field virtual_cpu_limit: uint64
    PyObject *virtual_cpu_limit = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!virtual_cpu_limit) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("virtual_cpu_limit start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "average_block_net_usage", average_block_net_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "average_block_cpu_usage", average_block_cpu_usage) < 0) goto error;
    if (PyDict_SetItemString(__dict, "total_net_weight", total_net_weight) < 0) goto error;
    if (PyDict_SetItemString(__dict, "total_cpu_weight", total_cpu_weight) < 0) goto error;
    if (PyDict_SetItemString(__dict, "total_ram_bytes", total_ram_bytes) < 0) goto error;
    if (PyDict_SetItemString(__dict, "virtual_net_limit", virtual_net_limit) < 0) goto error;
    if (PyDict_SetItemString(__dict, "virtual_cpu_limit", virtual_cpu_limit) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(average_block_net_usage);
    Py_DECREF(average_block_cpu_usage);
    Py_DECREF(total_net_weight);
    Py_DECREF(total_cpu_weight);
    Py_DECREF(total_ram_bytes);
    Py_DECREF(virtual_net_limit);
    Py_DECREF(virtual_cpu_limit);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking resource_limits_state_v0");
    Py_XDECREF(average_block_net_usage);
    Py_XDECREF(average_block_cpu_usage);
    Py_XDECREF(total_net_weight);
    Py_XDECREF(total_cpu_weight);
    Py_XDECREF(total_ram_bytes);
    Py_XDECREF(virtual_net_limit);
    Py_XDECREF(virtual_cpu_limit);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_resource_limits_ratio_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct resource_limits_ratio_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "numerator",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field numerator: uint64
    PyObject *numerator = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!numerator) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("numerator start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "denominator",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field denominator: uint64
    PyObject *denominator = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!denominator) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("denominator start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "numerator", numerator) < 0) goto error;
    if (PyDict_SetItemString(__dict, "denominator", denominator) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(numerator);
    Py_DECREF(denominator);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking resource_limits_ratio_v0");
    Py_XDECREF(numerator);
    Py_XDECREF(denominator);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_elastic_limit_parameters_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct elastic_limit_parameters_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "target",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field target: uint64
    PyObject *target = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!target) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("target start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max",
            "uint64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max: uint64
    PyObject *max = unpack_uint64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "periods",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field periods: uint32
    PyObject *periods = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!periods) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("periods start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "max_multiplier",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field max_multiplier: uint32
    PyObject *max_multiplier = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!max_multiplier) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("max_multiplier start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "contract_rate",
            "resource_limits_ratio",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field contract_rate: resource_limits_ratio
    PyObject *contract_rate = unpack_resource_limits_ratio(b + __total, buf_len, &__consumed, __depth + 1);

    if (!contract_rate) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("contract_rate start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "expand_rate",
            "resource_limits_ratio",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field expand_rate: resource_limits_ratio
    PyObject *expand_rate = unpack_resource_limits_ratio(b + __total, buf_len, &__consumed, __depth + 1);

    if (!expand_rate) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("expand_rate start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "target", target) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max", max) < 0) goto error;
    if (PyDict_SetItemString(__dict, "periods", periods) < 0) goto error;
    if (PyDict_SetItemString(__dict, "max_multiplier", max_multiplier) < 0) goto error;
    if (PyDict_SetItemString(__dict, "contract_rate", contract_rate) < 0) goto error;
    if (PyDict_SetItemString(__dict, "expand_rate", expand_rate) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(target);
    Py_DECREF(max);
    Py_DECREF(periods);
    Py_DECREF(max_multiplier);
    Py_DECREF(contract_rate);
    Py_DECREF(expand_rate);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking elastic_limit_parameters_v0");
    Py_XDECREF(target);
    Py_XDECREF(max);
    Py_XDECREF(periods);
    Py_XDECREF(max_multiplier);
    Py_XDECREF(contract_rate);
    Py_XDECREF(expand_rate);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_resource_limits_config_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct resource_limits_config_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "cpu_limit_parameters",
            "elastic_limit_parameters",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field cpu_limit_parameters: elastic_limit_parameters
    PyObject *cpu_limit_parameters = unpack_elastic_limit_parameters(b + __total, buf_len, &__consumed, __depth + 1);

    if (!cpu_limit_parameters) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("cpu_limit_parameters start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "net_limit_parameters",
            "elastic_limit_parameters",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field net_limit_parameters: elastic_limit_parameters
    PyObject *net_limit_parameters = unpack_elastic_limit_parameters(b + __total, buf_len, &__consumed, __depth + 1);

    if (!net_limit_parameters) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("net_limit_parameters start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "account_cpu_usage_average_window",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field account_cpu_usage_average_window: uint32
    PyObject *account_cpu_usage_average_window = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!account_cpu_usage_average_window) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("account_cpu_usage_average_window start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "account_net_usage_average_window",
            "uint32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field account_net_usage_average_window: uint32
    PyObject *account_net_usage_average_window = unpack_uint32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!account_net_usage_average_window) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("account_net_usage_average_window start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "cpu_limit_parameters", cpu_limit_parameters) < 0) goto error;
    if (PyDict_SetItemString(__dict, "net_limit_parameters", net_limit_parameters) < 0) goto error;
    if (PyDict_SetItemString(__dict, "account_cpu_usage_average_window", account_cpu_usage_average_window) < 0) goto error;
    if (PyDict_SetItemString(__dict, "account_net_usage_average_window", account_net_usage_average_window) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(cpu_limit_parameters);
    Py_DECREF(net_limit_parameters);
    Py_DECREF(account_cpu_usage_average_window);
    Py_DECREF(account_net_usage_average_window);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking resource_limits_config_v0");
    Py_XDECREF(cpu_limit_parameters);
    Py_XDECREF(net_limit_parameters);
    Py_XDECREF(account_cpu_usage_average_window);
    Py_XDECREF(account_net_usage_average_window);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_request(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 3) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_get_status_request_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("get_status_request_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        case 1: {
            __ret = unpack_get_blocks_request_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("get_blocks_request_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        case 2: {
            __ret = unpack_get_blocks_ack_request_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("get_blocks_ack_request_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"request\"");
    return NULL;
}

static inline PyObject *
unpack_result(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 2) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_get_status_result_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("get_status_result_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        case 1: {
            __ret = unpack_get_blocks_result_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("get_blocks_result_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"result\"");
    return NULL;
}

static inline PyObject *
unpack_action_receipt(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_action_receipt_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("action_receipt_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"action_receipt\"");
    return NULL;
}

static inline PyObject *
unpack_action_trace(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 2) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_action_trace_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("action_trace_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        case 1: {
            __ret = unpack_action_trace_v1(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("action_trace_v1");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"action_trace\"");
    return NULL;
}

static inline PyObject *
unpack_partial_transaction(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_partial_transaction_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("partial_transaction_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"partial_transaction\"");
    return NULL;
}

static inline PyObject *
unpack_transaction_trace(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_transaction_trace_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("transaction_trace_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"transaction_trace\"");
    return NULL;
}

static inline PyObject *
unpack_transaction_variant(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 2) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_transaction_id(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("transaction_id");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        case 1: {
            __ret = unpack_packed_transaction(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("packed_transaction");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"transaction_variant\"");
    return NULL;
}

static inline PyObject *
unpack_table_delta(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_table_delta_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("table_delta_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"table_delta\"");
    return NULL;
}

static inline PyObject *
unpack_account(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_account_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("account_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"account\"");
    return NULL;
}

static inline PyObject *
unpack_account_metadata(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_account_metadata_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("account_metadata_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"account_metadata\"");
    return NULL;
}

static inline PyObject *
unpack_code(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_code_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("code_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"code\"");
    return NULL;
}

static inline PyObject *
unpack_contract_table(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_contract_table_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("contract_table_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"contract_table\"");
    return NULL;
}

static inline PyObject *
unpack_contract_row(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_contract_row_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("contract_row_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"contract_row\"");
    return NULL;
}

static inline PyObject *
unpack_contract_index64(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_contract_index64_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("contract_index64_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"contract_index64\"");
    return NULL;
}

static inline PyObject *
unpack_contract_index128(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_contract_index128_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("contract_index128_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"contract_index128\"");
    return NULL;
}

static inline PyObject *
unpack_contract_index256(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_contract_index256_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("contract_index256_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"contract_index256\"");
    return NULL;
}

static inline PyObject *
unpack_contract_index_double(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_contract_index_double_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("contract_index_double_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"contract_index_double\"");
    return NULL;
}

static inline PyObject *
unpack_contract_index_long_double(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_contract_index_long_double_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("contract_index_long_double_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"contract_index_long_double\"");
    return NULL;
}

static inline PyObject *
unpack_chain_config(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 2) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_chain_config_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("chain_config_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        case 1: {
            __ret = unpack_chain_config_v1(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("chain_config_v1");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"chain_config\"");
    return NULL;
}

static inline PyObject *
unpack_wasm_config(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_wasm_config_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("wasm_config_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"wasm_config\"");
    return NULL;
}

static inline PyObject *
unpack_global_property(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 2) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_global_property_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("global_property_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        case 1: {
            __ret = unpack_global_property_v1(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("global_property_v1");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"global_property\"");
    return NULL;
}

static inline PyObject *
unpack_generated_transaction(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_generated_transaction_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("generated_transaction_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"generated_transaction\"");
    return NULL;
}

static inline PyObject *
unpack_activated_protocol_feature(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_activated_protocol_feature_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("activated_protocol_feature_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"activated_protocol_feature\"");
    return NULL;
}

static inline PyObject *
unpack_protocol_state(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_protocol_state_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("protocol_state_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"protocol_state\"");
    return NULL;
}

static inline PyObject *
unpack_permission(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_permission_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("permission_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"permission\"");
    return NULL;
}

static inline PyObject *
unpack_permission_link(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_permission_link_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("permission_link_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"permission_link\"");
    return NULL;
}

static inline PyObject *
unpack_resource_limits(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_resource_limits_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("resource_limits_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"resource_limits\"");
    return NULL;
}

static inline PyObject *
unpack_usage_accumulator(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_usage_accumulator_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("usage_accumulator_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"usage_accumulator\"");
    return NULL;
}

static inline PyObject *
unpack_resource_usage(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_resource_usage_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("resource_usage_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"resource_usage\"");
    return NULL;
}

static inline PyObject *
unpack_resource_limits_state(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_resource_limits_state_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("resource_limits_state_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"resource_limits_state\"");
    return NULL;
}

static inline PyObject *
unpack_resource_limits_ratio(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_resource_limits_ratio_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("resource_limits_ratio_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"resource_limits_ratio\"");
    return NULL;
}

static inline PyObject *
unpack_elastic_limit_parameters(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_elastic_limit_parameters_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("elastic_limit_parameters_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"elastic_limit_parameters\"");
    return NULL;
}

static inline PyObject *
unpack_resource_limits_config(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_resource_limits_config_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("resource_limits_config_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"resource_limits_config\"");
    return NULL;
}

static inline PyObject *
unpack_block_signing_authority(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= 1) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
        case 0: {
            __ret = unpack_block_signing_authority_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("block_signing_authority_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"block_signing_authority\"");
    return NULL;
}



static inline PyObject *
unpack_uint8(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u8(b, buf_len, c, depth);
}

static inline PyObject *
unpack_uint16(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u16(b, buf_len, c, depth);
}

static inline PyObject *
unpack_uint32(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u32(b, buf_len, c, depth);
}

static inline PyObject *
unpack_uint64(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u64(b, buf_len, c, depth);
}

static inline PyObject *
unpack_uint128(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u128(b, buf_len, c, depth);
}

static inline PyObject *
unpack_int8(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_i8(b, buf_len, c, depth);
}

static inline PyObject *
unpack_int16(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_i16(b, buf_len, c, depth);
}

static inline PyObject *
unpack_int32(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_i32(b, buf_len, c, depth);
}

static inline PyObject *
unpack_int64(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_i64(b, buf_len, c, depth);
}

static inline PyObject *
unpack_int128(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_i128(b, buf_len, c, depth);
}

static inline PyObject *
unpack_varuint32(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_uleb128(b, buf_len, c, depth);
}

static inline PyObject *
unpack_varint32(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_sleb128(b, buf_len, c, depth);
}

static inline PyObject *
unpack_float32(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_f32(b, buf_len, c, depth);
}

static inline PyObject *
unpack_float64(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_f64(b, buf_len, c, depth);
}

static inline PyObject *
unpack_float128(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_raw(b, 16, buf_len, c, depth);
}

static inline PyObject *
unpack_string(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_str(b, buf_len, c, depth);
}

static inline PyObject *
unpack_name(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u64(b, buf_len, c, depth);
}

static inline PyObject *
unpack_account_name(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u64(b, buf_len, c, depth);
}

static inline PyObject *
unpack_symbol(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u64(b, buf_len, c, depth);
}

static inline PyObject *
unpack_symbol_code(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u64(b, buf_len, c, depth);
}

static inline PyObject *
unpack_rd160(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_raw(b, 20, buf_len, c, depth);
}

static inline PyObject *
unpack_checksum160(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_raw(b, 20, buf_len, c, depth);
}

static inline PyObject *
unpack_sha256(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_raw(b, 32, buf_len, c, depth);
}

static inline PyObject *
unpack_checksum256(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_raw(b, 32, buf_len, c, depth);
}

static inline PyObject *
unpack_checksum512(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_raw(b, 64, buf_len, c, depth);
}

static inline PyObject *
unpack_time_point(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u64(b, buf_len, c, depth);
}

static inline PyObject *
unpack_time_point_sec(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u32(b, buf_len, c, depth);
}

static inline PyObject *
unpack_block_timestamp_type(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u32(b, buf_len, c, depth);
}

static inline PyObject *
unpack_public_key(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_raw(b, 34, buf_len, c, depth);
}

static inline PyObject *
unpack_signature(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_raw(b, 66, buf_len, c, depth);
}

static inline PyObject *
unpack_transaction_id(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_checksum256(b, buf_len, c, depth);
}


#define DEF_FIXED_WRAPPER(pyname, cfunc, size)                           \
    static PyObject *pyname(PyObject *self, PyObject *arg)                \
    {                                                                    \
        if (!PyBytes_Check(arg)) {                                       \
            PyErr_SetString(PyExc_TypeError, "expected a bytes object"); \
            return NULL;                                                 \
        }                                                                \
        Py_ssize_t len;                                                  \
        char *buf;                                                 \
        PyBytes_AsStringAndSize(arg, &buf, &len);                              \
        if ((size_t)len < (size)) {                                      \
            PyErr_SetString(PyExc_ValueError, "buffer too small");       \
            return NULL;                                                 \
        }                                                                \
        return cfunc(buf, (size_t)len, NULL, 0);                         \
    }

#define DEF_WRAPPER(pyname, cfunc)                                       \
    static PyObject *pyname(PyObject *self, PyObject *arg)                \
    {                                                                    \
        if (!PyBytes_Check(arg)) {                                       \
            PyErr_SetString(PyExc_TypeError, "expected a bytes object"); \
            return NULL;                                                 \
        }                                                                \
        Py_ssize_t len;                                                  \
        char *buf;                                                      \
        PyBytes_AsStringAndSize(arg, &buf, &len);                         \
        return cfunc(buf, (size_t)len, NULL, 0);                         \
    }

DEF_FIXED_WRAPPER(py_unpack_bool,    unpack_bool,    1)
DEF_FIXED_WRAPPER(py_unpack_u8,      unpack_u8,      1)
DEF_FIXED_WRAPPER(py_unpack_i8,      unpack_i8,      1)
DEF_FIXED_WRAPPER(py_unpack_u16,     unpack_u16,     2)
DEF_FIXED_WRAPPER(py_unpack_i16,     unpack_i16,     2)
DEF_FIXED_WRAPPER(py_unpack_u32,     unpack_u32,     4)
DEF_FIXED_WRAPPER(py_unpack_i32,     unpack_i32,     4)
DEF_FIXED_WRAPPER(py_unpack_u64,     unpack_u64,     8)
DEF_FIXED_WRAPPER(py_unpack_i64,     unpack_i64,     8)
DEF_FIXED_WRAPPER(py_unpack_u128,    unpack_u128,    16)
DEF_FIXED_WRAPPER(py_unpack_i128,    unpack_i128,    16)
DEF_FIXED_WRAPPER(py_unpack_uleb128, unpack_uleb128, 1)
DEF_FIXED_WRAPPER(py_unpack_sleb128, unpack_sleb128, 1)
DEF_FIXED_WRAPPER(py_unpack_f32,     unpack_f32,     4)
DEF_FIXED_WRAPPER(py_unpack_f64,     unpack_f64,     8)

DEF_WRAPPER(py_unpack_bytes, unpack_bytes)
DEF_WRAPPER(py_unpack_str,   unpack_str)

static PyObject *py_unpack_raw(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    if (!PyLong_Check(args[0])) {
        PyErr_SetString(PyExc_TypeError, "expected an int object");
        return NULL;
    }
    size_t len = PyLong_AsSize_t(args[0]);

    if (!PyBytes_Check(args[1])) {
        PyErr_SetString(PyExc_TypeError, "expected a bytes object");
        return NULL;
    }
    char *buf;
    Py_ssize_t raw_len;
    PyBytes_AsStringAndSize(args[1], &buf, &raw_len);

    return unpack_raw(buf, (size_t)raw_len, len, NULL, 0);
}

// structs & enums
DEF_WRAPPER(py_unpack_asset, unpack_asset);
DEF_WRAPPER(py_unpack_extended_asset, unpack_extended_asset);
DEF_WRAPPER(py_unpack_abi_struct_field, unpack_abi_struct_field);
DEF_WRAPPER(py_unpack_abi_struct, unpack_abi_struct);
DEF_WRAPPER(py_unpack_abi_type, unpack_abi_type);
DEF_WRAPPER(py_unpack_abi_action, unpack_abi_action);
DEF_WRAPPER(py_unpack_abi_variant, unpack_abi_variant);
DEF_WRAPPER(py_unpack_abi_table, unpack_abi_table);
DEF_WRAPPER(py_unpack_abi_clause, unpack_abi_clause);
DEF_WRAPPER(py_unpack_abi_result, unpack_abi_result);
DEF_WRAPPER(py_unpack_abi, unpack_abi);
DEF_WRAPPER(py_unpack_get_status_request_v0, unpack_get_status_request_v0);
DEF_WRAPPER(py_unpack_block_position, unpack_block_position);
DEF_WRAPPER(py_unpack_get_status_result_v0, unpack_get_status_result_v0);
DEF_WRAPPER(py_unpack_get_blocks_request_v0, unpack_get_blocks_request_v0);
DEF_WRAPPER(py_unpack_get_blocks_ack_request_v0, unpack_get_blocks_ack_request_v0);
DEF_WRAPPER(py_unpack_get_blocks_result_v0_header, unpack_get_blocks_result_v0_header);
DEF_WRAPPER(py_unpack_get_blocks_result_v0, unpack_get_blocks_result_v0);
DEF_WRAPPER(py_unpack_row, unpack_row);
DEF_WRAPPER(py_unpack_table_delta_v0, unpack_table_delta_v0);
DEF_WRAPPER(py_unpack_action, unpack_action);
DEF_WRAPPER(py_unpack_account_auth_sequence, unpack_account_auth_sequence);
DEF_WRAPPER(py_unpack_action_receipt_v0, unpack_action_receipt_v0);
DEF_WRAPPER(py_unpack_account_delta, unpack_account_delta);
DEF_WRAPPER(py_unpack_action_trace_v0, unpack_action_trace_v0);
DEF_WRAPPER(py_unpack_action_trace_v1, unpack_action_trace_v1);
DEF_WRAPPER(py_unpack_partial_transaction_v0, unpack_partial_transaction_v0);
DEF_WRAPPER(py_unpack_transaction_trace_v0, unpack_transaction_trace_v0);
DEF_WRAPPER(py_unpack_packed_transaction, unpack_packed_transaction);
DEF_WRAPPER(py_unpack_transaction_receipt_header, unpack_transaction_receipt_header);
DEF_WRAPPER(py_unpack_transaction_receipt, unpack_transaction_receipt);
DEF_WRAPPER(py_unpack_extension, unpack_extension);
DEF_WRAPPER(py_unpack_block_header, unpack_block_header);
DEF_WRAPPER(py_unpack_signed_block_header, unpack_signed_block_header);
DEF_WRAPPER(py_unpack_signed_block, unpack_signed_block);
DEF_WRAPPER(py_unpack_transaction_header, unpack_transaction_header);
DEF_WRAPPER(py_unpack_transaction, unpack_transaction);
DEF_WRAPPER(py_unpack_signed_transaction, unpack_signed_transaction);
DEF_WRAPPER(py_unpack_code_id, unpack_code_id);
DEF_WRAPPER(py_unpack_account_v0, unpack_account_v0);
DEF_WRAPPER(py_unpack_account_metadata_v0, unpack_account_metadata_v0);
DEF_WRAPPER(py_unpack_code_v0, unpack_code_v0);
DEF_WRAPPER(py_unpack_contract_table_v0, unpack_contract_table_v0);
DEF_WRAPPER(py_unpack_contract_row_v0, unpack_contract_row_v0);
DEF_WRAPPER(py_unpack_contract_index64_v0, unpack_contract_index64_v0);
DEF_WRAPPER(py_unpack_contract_index128_v0, unpack_contract_index128_v0);
DEF_WRAPPER(py_unpack_contract_index256_v0, unpack_contract_index256_v0);
DEF_WRAPPER(py_unpack_contract_index_double_v0, unpack_contract_index_double_v0);
DEF_WRAPPER(py_unpack_contract_index_long_double_v0, unpack_contract_index_long_double_v0);
DEF_WRAPPER(py_unpack_producer_key, unpack_producer_key);
DEF_WRAPPER(py_unpack_producer_schedule, unpack_producer_schedule);
DEF_WRAPPER(py_unpack_block_signing_authority_v0, unpack_block_signing_authority_v0);
DEF_WRAPPER(py_unpack_producer_authority, unpack_producer_authority);
DEF_WRAPPER(py_unpack_producer_authority_schedule, unpack_producer_authority_schedule);
DEF_WRAPPER(py_unpack_chain_config_v0, unpack_chain_config_v0);
DEF_WRAPPER(py_unpack_chain_config_v1, unpack_chain_config_v1);
DEF_WRAPPER(py_unpack_wasm_config_v0, unpack_wasm_config_v0);
DEF_WRAPPER(py_unpack_global_property_v0, unpack_global_property_v0);
DEF_WRAPPER(py_unpack_global_property_v1, unpack_global_property_v1);
DEF_WRAPPER(py_unpack_generated_transaction_v0, unpack_generated_transaction_v0);
DEF_WRAPPER(py_unpack_activated_protocol_feature_v0, unpack_activated_protocol_feature_v0);
DEF_WRAPPER(py_unpack_protocol_state_v0, unpack_protocol_state_v0);
DEF_WRAPPER(py_unpack_key_weight, unpack_key_weight);
DEF_WRAPPER(py_unpack_permission_level, unpack_permission_level);
DEF_WRAPPER(py_unpack_permission_level_weight, unpack_permission_level_weight);
DEF_WRAPPER(py_unpack_wait_weight, unpack_wait_weight);
DEF_WRAPPER(py_unpack_authority, unpack_authority);
DEF_WRAPPER(py_unpack_permission_v0, unpack_permission_v0);
DEF_WRAPPER(py_unpack_permission_link_v0, unpack_permission_link_v0);
DEF_WRAPPER(py_unpack_resource_limits_v0, unpack_resource_limits_v0);
DEF_WRAPPER(py_unpack_usage_accumulator_v0, unpack_usage_accumulator_v0);
DEF_WRAPPER(py_unpack_resource_usage_v0, unpack_resource_usage_v0);
DEF_WRAPPER(py_unpack_resource_limits_state_v0, unpack_resource_limits_state_v0);
DEF_WRAPPER(py_unpack_resource_limits_ratio_v0, unpack_resource_limits_ratio_v0);
DEF_WRAPPER(py_unpack_elastic_limit_parameters_v0, unpack_elastic_limit_parameters_v0);
DEF_WRAPPER(py_unpack_resource_limits_config_v0, unpack_resource_limits_config_v0);
DEF_WRAPPER(py_unpack_request, unpack_request);
DEF_WRAPPER(py_unpack_result, unpack_result);
DEF_WRAPPER(py_unpack_action_receipt, unpack_action_receipt);
DEF_WRAPPER(py_unpack_action_trace, unpack_action_trace);
DEF_WRAPPER(py_unpack_partial_transaction, unpack_partial_transaction);
DEF_WRAPPER(py_unpack_transaction_trace, unpack_transaction_trace);
DEF_WRAPPER(py_unpack_transaction_variant, unpack_transaction_variant);
DEF_WRAPPER(py_unpack_table_delta, unpack_table_delta);
DEF_WRAPPER(py_unpack_account, unpack_account);
DEF_WRAPPER(py_unpack_account_metadata, unpack_account_metadata);
DEF_WRAPPER(py_unpack_code, unpack_code);
DEF_WRAPPER(py_unpack_contract_table, unpack_contract_table);
DEF_WRAPPER(py_unpack_contract_row, unpack_contract_row);
DEF_WRAPPER(py_unpack_contract_index64, unpack_contract_index64);
DEF_WRAPPER(py_unpack_contract_index128, unpack_contract_index128);
DEF_WRAPPER(py_unpack_contract_index256, unpack_contract_index256);
DEF_WRAPPER(py_unpack_contract_index_double, unpack_contract_index_double);
DEF_WRAPPER(py_unpack_contract_index_long_double, unpack_contract_index_long_double);
DEF_WRAPPER(py_unpack_chain_config, unpack_chain_config);
DEF_WRAPPER(py_unpack_wasm_config, unpack_wasm_config);
DEF_WRAPPER(py_unpack_global_property, unpack_global_property);
DEF_WRAPPER(py_unpack_generated_transaction, unpack_generated_transaction);
DEF_WRAPPER(py_unpack_activated_protocol_feature, unpack_activated_protocol_feature);
DEF_WRAPPER(py_unpack_protocol_state, unpack_protocol_state);
DEF_WRAPPER(py_unpack_permission, unpack_permission);
DEF_WRAPPER(py_unpack_permission_link, unpack_permission_link);
DEF_WRAPPER(py_unpack_resource_limits, unpack_resource_limits);
DEF_WRAPPER(py_unpack_usage_accumulator, unpack_usage_accumulator);
DEF_WRAPPER(py_unpack_resource_usage, unpack_resource_usage);
DEF_WRAPPER(py_unpack_resource_limits_state, unpack_resource_limits_state);
DEF_WRAPPER(py_unpack_resource_limits_ratio, unpack_resource_limits_ratio);
DEF_WRAPPER(py_unpack_elastic_limit_parameters, unpack_elastic_limit_parameters);
DEF_WRAPPER(py_unpack_resource_limits_config, unpack_resource_limits_config);
DEF_WRAPPER(py_unpack_block_signing_authority, unpack_block_signing_authority);

// aliases
DEF_WRAPPER(py_unpack_uint8, unpack_uint8);
DEF_WRAPPER(py_unpack_uint16, unpack_uint16);
DEF_WRAPPER(py_unpack_uint32, unpack_uint32);
DEF_WRAPPER(py_unpack_uint64, unpack_uint64);
DEF_WRAPPER(py_unpack_uint128, unpack_uint128);
DEF_WRAPPER(py_unpack_int8, unpack_int8);
DEF_WRAPPER(py_unpack_int16, unpack_int16);
DEF_WRAPPER(py_unpack_int32, unpack_int32);
DEF_WRAPPER(py_unpack_int64, unpack_int64);
DEF_WRAPPER(py_unpack_int128, unpack_int128);
DEF_WRAPPER(py_unpack_varuint32, unpack_varuint32);
DEF_WRAPPER(py_unpack_varint32, unpack_varint32);
DEF_WRAPPER(py_unpack_float32, unpack_float32);
DEF_WRAPPER(py_unpack_float64, unpack_float64);
DEF_WRAPPER(py_unpack_float128, unpack_float128);
DEF_WRAPPER(py_unpack_string, unpack_string);
DEF_WRAPPER(py_unpack_name, unpack_name);
DEF_WRAPPER(py_unpack_account_name, unpack_account_name);
DEF_WRAPPER(py_unpack_symbol, unpack_symbol);
DEF_WRAPPER(py_unpack_symbol_code, unpack_symbol_code);
DEF_WRAPPER(py_unpack_rd160, unpack_rd160);
DEF_WRAPPER(py_unpack_checksum160, unpack_checksum160);
DEF_WRAPPER(py_unpack_sha256, unpack_sha256);
DEF_WRAPPER(py_unpack_checksum256, unpack_checksum256);
DEF_WRAPPER(py_unpack_checksum512, unpack_checksum512);
DEF_WRAPPER(py_unpack_time_point, unpack_time_point);
DEF_WRAPPER(py_unpack_time_point_sec, unpack_time_point_sec);
DEF_WRAPPER(py_unpack_block_timestamp_type, unpack_block_timestamp_type);
DEF_WRAPPER(py_unpack_public_key, unpack_public_key);
DEF_WRAPPER(py_unpack_signature, unpack_signature);
DEF_WRAPPER(py_unpack_transaction_id, unpack_transaction_id);

// type name dispatch
typedef PyObject *(*unpack_fn_t)(const char *, size_t, size_t *, size_t);

struct dispatch_entry {
    const char   *name;
    unpack_fn_t   fn;
};

/* table is terminated by {NULL, NULL} for easy iteration */
static const struct dispatch_entry UNPACK_DISPATCH[] = {
    {"bool",    unpack_bool},
    {"u8",      unpack_u8},
    {"i8",      unpack_i8},
    {"u16",     unpack_u16},
    {"i16",     unpack_i16},
    {"u32",     unpack_u32},
    {"i32",     unpack_i32},
    {"u64",     unpack_u64},
    {"i64",     unpack_i64},
    {"u128",    unpack_u128},
    {"i128",    unpack_i128},
    {"uleb128", unpack_uleb128},
    {"sleb128", unpack_sleb128},
    {"f32",     unpack_f32},
    {"f64",     unpack_f64},
    {"bytes",   unpack_bytes},
    {"str",     unpack_str},
    { "asset", unpack_asset },
    { "extended_asset", unpack_extended_asset },
    { "abi_struct_field", unpack_abi_struct_field },
    { "abi_struct", unpack_abi_struct },
    { "abi_type", unpack_abi_type },
    { "abi_action", unpack_abi_action },
    { "abi_variant", unpack_abi_variant },
    { "abi_table", unpack_abi_table },
    { "abi_clause", unpack_abi_clause },
    { "abi_result", unpack_abi_result },
    { "abi", unpack_abi },
    { "get_status_request_v0", unpack_get_status_request_v0 },
    { "block_position", unpack_block_position },
    { "get_status_result_v0", unpack_get_status_result_v0 },
    { "get_blocks_request_v0", unpack_get_blocks_request_v0 },
    { "get_blocks_ack_request_v0", unpack_get_blocks_ack_request_v0 },
    { "get_blocks_result_v0_header", unpack_get_blocks_result_v0_header },
    { "get_blocks_result_v0", unpack_get_blocks_result_v0 },
    { "row", unpack_row },
    { "table_delta_v0", unpack_table_delta_v0 },
    { "action", unpack_action },
    { "account_auth_sequence", unpack_account_auth_sequence },
    { "action_receipt_v0", unpack_action_receipt_v0 },
    { "account_delta", unpack_account_delta },
    { "action_trace_v0", unpack_action_trace_v0 },
    { "action_trace_v1", unpack_action_trace_v1 },
    { "partial_transaction_v0", unpack_partial_transaction_v0 },
    { "transaction_trace_v0", unpack_transaction_trace_v0 },
    { "packed_transaction", unpack_packed_transaction },
    { "transaction_receipt_header", unpack_transaction_receipt_header },
    { "transaction_receipt", unpack_transaction_receipt },
    { "extension", unpack_extension },
    { "block_header", unpack_block_header },
    { "signed_block_header", unpack_signed_block_header },
    { "signed_block", unpack_signed_block },
    { "transaction_header", unpack_transaction_header },
    { "transaction", unpack_transaction },
    { "signed_transaction", unpack_signed_transaction },
    { "code_id", unpack_code_id },
    { "account_v0", unpack_account_v0 },
    { "account_metadata_v0", unpack_account_metadata_v0 },
    { "code_v0", unpack_code_v0 },
    { "contract_table_v0", unpack_contract_table_v0 },
    { "contract_row_v0", unpack_contract_row_v0 },
    { "contract_index64_v0", unpack_contract_index64_v0 },
    { "contract_index128_v0", unpack_contract_index128_v0 },
    { "contract_index256_v0", unpack_contract_index256_v0 },
    { "contract_index_double_v0", unpack_contract_index_double_v0 },
    { "contract_index_long_double_v0", unpack_contract_index_long_double_v0 },
    { "producer_key", unpack_producer_key },
    { "producer_schedule", unpack_producer_schedule },
    { "block_signing_authority_v0", unpack_block_signing_authority_v0 },
    { "producer_authority", unpack_producer_authority },
    { "producer_authority_schedule", unpack_producer_authority_schedule },
    { "chain_config_v0", unpack_chain_config_v0 },
    { "chain_config_v1", unpack_chain_config_v1 },
    { "wasm_config_v0", unpack_wasm_config_v0 },
    { "global_property_v0", unpack_global_property_v0 },
    { "global_property_v1", unpack_global_property_v1 },
    { "generated_transaction_v0", unpack_generated_transaction_v0 },
    { "activated_protocol_feature_v0", unpack_activated_protocol_feature_v0 },
    { "protocol_state_v0", unpack_protocol_state_v0 },
    { "key_weight", unpack_key_weight },
    { "permission_level", unpack_permission_level },
    { "permission_level_weight", unpack_permission_level_weight },
    { "wait_weight", unpack_wait_weight },
    { "authority", unpack_authority },
    { "permission_v0", unpack_permission_v0 },
    { "permission_link_v0", unpack_permission_link_v0 },
    { "resource_limits_v0", unpack_resource_limits_v0 },
    { "usage_accumulator_v0", unpack_usage_accumulator_v0 },
    { "resource_usage_v0", unpack_resource_usage_v0 },
    { "resource_limits_state_v0", unpack_resource_limits_state_v0 },
    { "resource_limits_ratio_v0", unpack_resource_limits_ratio_v0 },
    { "elastic_limit_parameters_v0", unpack_elastic_limit_parameters_v0 },
    { "resource_limits_config_v0", unpack_resource_limits_config_v0 },
    { "request", unpack_request },
    { "result", unpack_result },
    { "action_receipt", unpack_action_receipt },
    { "action_trace", unpack_action_trace },
    { "partial_transaction", unpack_partial_transaction },
    { "transaction_trace", unpack_transaction_trace },
    { "transaction_variant", unpack_transaction_variant },
    { "table_delta", unpack_table_delta },
    { "account", unpack_account },
    { "account_metadata", unpack_account_metadata },
    { "code", unpack_code },
    { "contract_table", unpack_contract_table },
    { "contract_row", unpack_contract_row },
    { "contract_index64", unpack_contract_index64 },
    { "contract_index128", unpack_contract_index128 },
    { "contract_index256", unpack_contract_index256 },
    { "contract_index_double", unpack_contract_index_double },
    { "contract_index_long_double", unpack_contract_index_long_double },
    { "chain_config", unpack_chain_config },
    { "wasm_config", unpack_wasm_config },
    { "global_property", unpack_global_property },
    { "generated_transaction", unpack_generated_transaction },
    { "activated_protocol_feature", unpack_activated_protocol_feature },
    { "protocol_state", unpack_protocol_state },
    { "permission", unpack_permission },
    { "permission_link", unpack_permission_link },
    { "resource_limits", unpack_resource_limits },
    { "usage_accumulator", unpack_usage_accumulator },
    { "resource_usage", unpack_resource_usage },
    { "resource_limits_state", unpack_resource_limits_state },
    { "resource_limits_ratio", unpack_resource_limits_ratio },
    { "elastic_limit_parameters", unpack_elastic_limit_parameters },
    { "resource_limits_config", unpack_resource_limits_config },
    { "block_signing_authority", unpack_block_signing_authority },
    { "uint8", unpack_uint8 },
    { "uint16", unpack_uint16 },
    { "uint32", unpack_uint32 },
    { "uint64", unpack_uint64 },
    { "uint128", unpack_uint128 },
    { "int8", unpack_int8 },
    { "int16", unpack_int16 },
    { "int32", unpack_int32 },
    { "int64", unpack_int64 },
    { "int128", unpack_int128 },
    { "varuint32", unpack_varuint32 },
    { "varint32", unpack_varint32 },
    { "float32", unpack_float32 },
    { "float64", unpack_float64 },
    { "float128", unpack_float128 },
    { "string", unpack_string },
    { "name", unpack_name },
    { "account_name", unpack_account_name },
    { "symbol", unpack_symbol },
    { "symbol_code", unpack_symbol_code },
    { "rd160", unpack_rd160 },
    { "checksum160", unpack_checksum160 },
    { "sha256", unpack_sha256 },
    { "checksum256", unpack_checksum256 },
    { "checksum512", unpack_checksum512 },
    { "time_point", unpack_time_point },
    { "time_point_sec", unpack_time_point_sec },
    { "block_timestamp_type", unpack_block_timestamp_type },
    { "public_key", unpack_public_key },
    { "signature", unpack_signature },
    { "transaction_id", unpack_transaction_id },
    { NULL, NULL }
};

static PyObject *
py_unpack(PyObject *self, PyObject *const *args, Py_ssize_t nargs)
{
    if (!PyUnicode_Check(args[0])) {
        PyErr_SetString(PyExc_TypeError, "expected a bytes object");
        return NULL;
    }
    Py_ssize_t tn_len;
    const char *type_name = PyUnicode_AsUTF8AndSize(args[0], &tn_len);

    if (!PyBytes_Check(args[1])) {
        PyErr_SetString(PyExc_TypeError, "expected a bytes object");
        return NULL;
    }
    Py_ssize_t bl;
    char *buf;
    PyBytes_AsStringAndSize(args[1], &buf, &bl);

    // check type name for modifiers
    bool is_array = tn_len >= 2 &&
                    type_name[tn_len - 1] == ']' &&
                    type_name[tn_len - 2] == '[';

    const char *base = type_name;
    char local_buf[256];  // only used when we need to strip modifiers
    if (is_array) {
        memcpy(local_buf, type_name, tn_len - 2);
        local_buf[tn_len - 2] = '\0';
        base = local_buf;
    }

    // locate the base-type’s unpack function
    unpack_fn_t fn = NULL;
    for (const struct dispatch_entry *it = UNPACK_DISPATCH; it->name; ++it)
        if (strcmp(base, it->name) == 0) {
            fn = it->fn;
            break;
        }

    if (!fn) {
        PyErr_Format(PyExc_ValueError,
                     "unknown type '%s'", type_name);
        return NULL;
    }

    // no modifiers, just delegate
    if (!is_array) {
        size_t consumed = 0;
        return fn(buf, (size_t)bl, &consumed, 0);
    }

    // array path
    size_t hdr_len = 0;
    unsigned long long hdr = decode_uleb128(buf, &hdr_len);
    if (hdr < 0) {
        PyErr_SetString(PyExc_ValueError, "buffer too short for ULEB128 length");
        return NULL;
    }

    size_t offset = hdr_len;
    size_t rem = (size_t)bl - (size_t)hdr;

    PyObject *list = PyList_New((Py_ssize_t)hdr);
    if (!list)
        return NULL;

    for (uint64_t i = 0; i < hdr; i++) {
        size_t consumed = 0;
        PyObject *item = fn(buf + offset, bl - offset, &consumed, 0);
        offset += consumed;
        if (!item) {  // fn should of already set an exception
            Py_DECREF(list);
            return NULL;
        }

        if (PyList_SetItem(list, (Py_ssize_t)i, item) < 0) {  // steal ref
            PyErr_SetString(PyExc_ValueError, "could not set item on list");
            Py_DECREF(item);
            Py_DECREF(list);
            return NULL;
        }

        #ifdef __PACKVM_DEBUG
        if (offset > bl) {
            Py_DECREF(list);
            PyErr_SetString(PyExc_ValueError, "buffer ended mid-array");
            return NULL;
        }
        #endif
    }

    return list;
}

static PyMethodDef Methods[] = {
    // standard types
    {"unpack_bool",    py_unpack_bool,    METH_O, "bool  (1 byte)"},
    {"unpack_u8",      py_unpack_u8,      METH_O, "uint8 (1 byte)"},
    {"unpack_i8",      py_unpack_i8,      METH_O, "int8  (1 byte)"},
    {"unpack_u16",     py_unpack_u16,     METH_O, "uint16 (LE)"},
    {"unpack_i16",     py_unpack_i16,     METH_O, "int16  (LE)"},
    {"unpack_u32",     py_unpack_u32,     METH_O, "uint32 (LE)"},
    {"unpack_i32",     py_unpack_i32,     METH_O, "int32  (LE)"},
    {"unpack_u64",     py_unpack_u64,     METH_O, "uint64 (LE)"},
    {"unpack_i64",     py_unpack_i64,     METH_O, "int64  (LE)"},
    {"unpack_u128",    py_unpack_u128,    METH_O, "uint128 (LE)"},
    {"unpack_i128",    py_unpack_i128,    METH_O, "int128 (LE)"},
    {"unpack_uleb128", py_unpack_uleb128, METH_O, "unsigned LEB128"},
    {"unpack_sleb128", py_unpack_sleb128, METH_O, "signed LEB128"},
    {"unpack_f32",     py_unpack_f32,     METH_O, "float32 (IEEE-754)"},
    {"unpack_f64",     py_unpack_f64,     METH_O, "float64 (IEEE-754)"},
    {"unpack_bytes",   py_unpack_bytes,   METH_O, "ULEB128-length-prefixed bytes"},
    {"unpack_str",     py_unpack_str,     METH_O, "ULEB128-length-prefixed UTF-8 string"},
    {"unpack_raw",     (PyCFunction)py_unpack_raw,     METH_FASTCALL, "bytes without length prefix"},
    // structs & enums
    {"unpack_asset", py_unpack_asset, METH_O, "structure asset"},
    {"unpack_extended_asset", py_unpack_extended_asset, METH_O, "structure extended_asset"},
    {"unpack_abi_struct_field", py_unpack_abi_struct_field, METH_O, "structure abi_struct_field"},
    {"unpack_abi_struct", py_unpack_abi_struct, METH_O, "structure abi_struct"},
    {"unpack_abi_type", py_unpack_abi_type, METH_O, "structure abi_type"},
    {"unpack_abi_action", py_unpack_abi_action, METH_O, "structure abi_action"},
    {"unpack_abi_variant", py_unpack_abi_variant, METH_O, "structure abi_variant"},
    {"unpack_abi_table", py_unpack_abi_table, METH_O, "structure abi_table"},
    {"unpack_abi_clause", py_unpack_abi_clause, METH_O, "structure abi_clause"},
    {"unpack_abi_result", py_unpack_abi_result, METH_O, "structure abi_result"},
    {"unpack_abi", py_unpack_abi, METH_O, "structure abi"},
    {"unpack_get_status_request_v0", py_unpack_get_status_request_v0, METH_O, "structure get_status_request_v0"},
    {"unpack_block_position", py_unpack_block_position, METH_O, "structure block_position"},
    {"unpack_get_status_result_v0", py_unpack_get_status_result_v0, METH_O, "structure get_status_result_v0"},
    {"unpack_get_blocks_request_v0", py_unpack_get_blocks_request_v0, METH_O, "structure get_blocks_request_v0"},
    {"unpack_get_blocks_ack_request_v0", py_unpack_get_blocks_ack_request_v0, METH_O, "structure get_blocks_ack_request_v0"},
    {"unpack_get_blocks_result_v0_header", py_unpack_get_blocks_result_v0_header, METH_O, "structure get_blocks_result_v0_header"},
    {"unpack_get_blocks_result_v0", py_unpack_get_blocks_result_v0, METH_O, "structure get_blocks_result_v0"},
    {"unpack_row", py_unpack_row, METH_O, "structure row"},
    {"unpack_table_delta_v0", py_unpack_table_delta_v0, METH_O, "structure table_delta_v0"},
    {"unpack_action", py_unpack_action, METH_O, "structure action"},
    {"unpack_account_auth_sequence", py_unpack_account_auth_sequence, METH_O, "structure account_auth_sequence"},
    {"unpack_action_receipt_v0", py_unpack_action_receipt_v0, METH_O, "structure action_receipt_v0"},
    {"unpack_account_delta", py_unpack_account_delta, METH_O, "structure account_delta"},
    {"unpack_action_trace_v0", py_unpack_action_trace_v0, METH_O, "structure action_trace_v0"},
    {"unpack_action_trace_v1", py_unpack_action_trace_v1, METH_O, "structure action_trace_v1"},
    {"unpack_partial_transaction_v0", py_unpack_partial_transaction_v0, METH_O, "structure partial_transaction_v0"},
    {"unpack_transaction_trace_v0", py_unpack_transaction_trace_v0, METH_O, "structure transaction_trace_v0"},
    {"unpack_packed_transaction", py_unpack_packed_transaction, METH_O, "structure packed_transaction"},
    {"unpack_transaction_receipt_header", py_unpack_transaction_receipt_header, METH_O, "structure transaction_receipt_header"},
    {"unpack_transaction_receipt", py_unpack_transaction_receipt, METH_O, "structure transaction_receipt"},
    {"unpack_extension", py_unpack_extension, METH_O, "structure extension"},
    {"unpack_block_header", py_unpack_block_header, METH_O, "structure block_header"},
    {"unpack_signed_block_header", py_unpack_signed_block_header, METH_O, "structure signed_block_header"},
    {"unpack_signed_block", py_unpack_signed_block, METH_O, "structure signed_block"},
    {"unpack_transaction_header", py_unpack_transaction_header, METH_O, "structure transaction_header"},
    {"unpack_transaction", py_unpack_transaction, METH_O, "structure transaction"},
    {"unpack_signed_transaction", py_unpack_signed_transaction, METH_O, "structure signed_transaction"},
    {"unpack_code_id", py_unpack_code_id, METH_O, "structure code_id"},
    {"unpack_account_v0", py_unpack_account_v0, METH_O, "structure account_v0"},
    {"unpack_account_metadata_v0", py_unpack_account_metadata_v0, METH_O, "structure account_metadata_v0"},
    {"unpack_code_v0", py_unpack_code_v0, METH_O, "structure code_v0"},
    {"unpack_contract_table_v0", py_unpack_contract_table_v0, METH_O, "structure contract_table_v0"},
    {"unpack_contract_row_v0", py_unpack_contract_row_v0, METH_O, "structure contract_row_v0"},
    {"unpack_contract_index64_v0", py_unpack_contract_index64_v0, METH_O, "structure contract_index64_v0"},
    {"unpack_contract_index128_v0", py_unpack_contract_index128_v0, METH_O, "structure contract_index128_v0"},
    {"unpack_contract_index256_v0", py_unpack_contract_index256_v0, METH_O, "structure contract_index256_v0"},
    {"unpack_contract_index_double_v0", py_unpack_contract_index_double_v0, METH_O, "structure contract_index_double_v0"},
    {"unpack_contract_index_long_double_v0", py_unpack_contract_index_long_double_v0, METH_O, "structure contract_index_long_double_v0"},
    {"unpack_producer_key", py_unpack_producer_key, METH_O, "structure producer_key"},
    {"unpack_producer_schedule", py_unpack_producer_schedule, METH_O, "structure producer_schedule"},
    {"unpack_block_signing_authority_v0", py_unpack_block_signing_authority_v0, METH_O, "structure block_signing_authority_v0"},
    {"unpack_producer_authority", py_unpack_producer_authority, METH_O, "structure producer_authority"},
    {"unpack_producer_authority_schedule", py_unpack_producer_authority_schedule, METH_O, "structure producer_authority_schedule"},
    {"unpack_chain_config_v0", py_unpack_chain_config_v0, METH_O, "structure chain_config_v0"},
    {"unpack_chain_config_v1", py_unpack_chain_config_v1, METH_O, "structure chain_config_v1"},
    {"unpack_wasm_config_v0", py_unpack_wasm_config_v0, METH_O, "structure wasm_config_v0"},
    {"unpack_global_property_v0", py_unpack_global_property_v0, METH_O, "structure global_property_v0"},
    {"unpack_global_property_v1", py_unpack_global_property_v1, METH_O, "structure global_property_v1"},
    {"unpack_generated_transaction_v0", py_unpack_generated_transaction_v0, METH_O, "structure generated_transaction_v0"},
    {"unpack_activated_protocol_feature_v0", py_unpack_activated_protocol_feature_v0, METH_O, "structure activated_protocol_feature_v0"},
    {"unpack_protocol_state_v0", py_unpack_protocol_state_v0, METH_O, "structure protocol_state_v0"},
    {"unpack_key_weight", py_unpack_key_weight, METH_O, "structure key_weight"},
    {"unpack_permission_level", py_unpack_permission_level, METH_O, "structure permission_level"},
    {"unpack_permission_level_weight", py_unpack_permission_level_weight, METH_O, "structure permission_level_weight"},
    {"unpack_wait_weight", py_unpack_wait_weight, METH_O, "structure wait_weight"},
    {"unpack_authority", py_unpack_authority, METH_O, "structure authority"},
    {"unpack_permission_v0", py_unpack_permission_v0, METH_O, "structure permission_v0"},
    {"unpack_permission_link_v0", py_unpack_permission_link_v0, METH_O, "structure permission_link_v0"},
    {"unpack_resource_limits_v0", py_unpack_resource_limits_v0, METH_O, "structure resource_limits_v0"},
    {"unpack_usage_accumulator_v0", py_unpack_usage_accumulator_v0, METH_O, "structure usage_accumulator_v0"},
    {"unpack_resource_usage_v0", py_unpack_resource_usage_v0, METH_O, "structure resource_usage_v0"},
    {"unpack_resource_limits_state_v0", py_unpack_resource_limits_state_v0, METH_O, "structure resource_limits_state_v0"},
    {"unpack_resource_limits_ratio_v0", py_unpack_resource_limits_ratio_v0, METH_O, "structure resource_limits_ratio_v0"},
    {"unpack_elastic_limit_parameters_v0", py_unpack_elastic_limit_parameters_v0, METH_O, "structure elastic_limit_parameters_v0"},
    {"unpack_resource_limits_config_v0", py_unpack_resource_limits_config_v0, METH_O, "structure resource_limits_config_v0"},
    {"unpack_request", py_unpack_request, METH_O, "structure request"},
    {"unpack_result", py_unpack_result, METH_O, "structure result"},
    {"unpack_action_receipt", py_unpack_action_receipt, METH_O, "structure action_receipt"},
    {"unpack_action_trace", py_unpack_action_trace, METH_O, "structure action_trace"},
    {"unpack_partial_transaction", py_unpack_partial_transaction, METH_O, "structure partial_transaction"},
    {"unpack_transaction_trace", py_unpack_transaction_trace, METH_O, "structure transaction_trace"},
    {"unpack_transaction_variant", py_unpack_transaction_variant, METH_O, "structure transaction_variant"},
    {"unpack_table_delta", py_unpack_table_delta, METH_O, "structure table_delta"},
    {"unpack_account", py_unpack_account, METH_O, "structure account"},
    {"unpack_account_metadata", py_unpack_account_metadata, METH_O, "structure account_metadata"},
    {"unpack_code", py_unpack_code, METH_O, "structure code"},
    {"unpack_contract_table", py_unpack_contract_table, METH_O, "structure contract_table"},
    {"unpack_contract_row", py_unpack_contract_row, METH_O, "structure contract_row"},
    {"unpack_contract_index64", py_unpack_contract_index64, METH_O, "structure contract_index64"},
    {"unpack_contract_index128", py_unpack_contract_index128, METH_O, "structure contract_index128"},
    {"unpack_contract_index256", py_unpack_contract_index256, METH_O, "structure contract_index256"},
    {"unpack_contract_index_double", py_unpack_contract_index_double, METH_O, "structure contract_index_double"},
    {"unpack_contract_index_long_double", py_unpack_contract_index_long_double, METH_O, "structure contract_index_long_double"},
    {"unpack_chain_config", py_unpack_chain_config, METH_O, "structure chain_config"},
    {"unpack_wasm_config", py_unpack_wasm_config, METH_O, "structure wasm_config"},
    {"unpack_global_property", py_unpack_global_property, METH_O, "structure global_property"},
    {"unpack_generated_transaction", py_unpack_generated_transaction, METH_O, "structure generated_transaction"},
    {"unpack_activated_protocol_feature", py_unpack_activated_protocol_feature, METH_O, "structure activated_protocol_feature"},
    {"unpack_protocol_state", py_unpack_protocol_state, METH_O, "structure protocol_state"},
    {"unpack_permission", py_unpack_permission, METH_O, "structure permission"},
    {"unpack_permission_link", py_unpack_permission_link, METH_O, "structure permission_link"},
    {"unpack_resource_limits", py_unpack_resource_limits, METH_O, "structure resource_limits"},
    {"unpack_usage_accumulator", py_unpack_usage_accumulator, METH_O, "structure usage_accumulator"},
    {"unpack_resource_usage", py_unpack_resource_usage, METH_O, "structure resource_usage"},
    {"unpack_resource_limits_state", py_unpack_resource_limits_state, METH_O, "structure resource_limits_state"},
    {"unpack_resource_limits_ratio", py_unpack_resource_limits_ratio, METH_O, "structure resource_limits_ratio"},
    {"unpack_elastic_limit_parameters", py_unpack_elastic_limit_parameters, METH_O, "structure elastic_limit_parameters"},
    {"unpack_resource_limits_config", py_unpack_resource_limits_config, METH_O, "structure resource_limits_config"},
    {"unpack_block_signing_authority", py_unpack_block_signing_authority, METH_O, "structure block_signing_authority"},
    // aliases
    {"unpack_uint8", py_unpack_uint8, METH_O, "alias uint8"},
    {"unpack_uint16", py_unpack_uint16, METH_O, "alias uint16"},
    {"unpack_uint32", py_unpack_uint32, METH_O, "alias uint32"},
    {"unpack_uint64", py_unpack_uint64, METH_O, "alias uint64"},
    {"unpack_uint128", py_unpack_uint128, METH_O, "alias uint128"},
    {"unpack_int8", py_unpack_int8, METH_O, "alias int8"},
    {"unpack_int16", py_unpack_int16, METH_O, "alias int16"},
    {"unpack_int32", py_unpack_int32, METH_O, "alias int32"},
    {"unpack_int64", py_unpack_int64, METH_O, "alias int64"},
    {"unpack_int128", py_unpack_int128, METH_O, "alias int128"},
    {"unpack_varuint32", py_unpack_varuint32, METH_O, "alias varuint32"},
    {"unpack_varint32", py_unpack_varint32, METH_O, "alias varint32"},
    {"unpack_float32", py_unpack_float32, METH_O, "alias float32"},
    {"unpack_float64", py_unpack_float64, METH_O, "alias float64"},
    {"unpack_float128", py_unpack_float128, METH_O, "alias float128"},
    {"unpack_string", py_unpack_string, METH_O, "alias string"},
    {"unpack_name", py_unpack_name, METH_O, "alias name"},
    {"unpack_account_name", py_unpack_account_name, METH_O, "alias account_name"},
    {"unpack_symbol", py_unpack_symbol, METH_O, "alias symbol"},
    {"unpack_symbol_code", py_unpack_symbol_code, METH_O, "alias symbol_code"},
    {"unpack_rd160", py_unpack_rd160, METH_O, "alias rd160"},
    {"unpack_checksum160", py_unpack_checksum160, METH_O, "alias checksum160"},
    {"unpack_sha256", py_unpack_sha256, METH_O, "alias sha256"},
    {"unpack_checksum256", py_unpack_checksum256, METH_O, "alias checksum256"},
    {"unpack_checksum512", py_unpack_checksum512, METH_O, "alias checksum512"},
    {"unpack_time_point", py_unpack_time_point, METH_O, "alias time_point"},
    {"unpack_time_point_sec", py_unpack_time_point_sec, METH_O, "alias time_point_sec"},
    {"unpack_block_timestamp_type", py_unpack_block_timestamp_type, METH_O, "alias block_timestamp_type"},
    {"unpack_public_key", py_unpack_public_key, METH_O, "alias public_key"},
    {"unpack_signature", py_unpack_signature, METH_O, "alias signature"},
    {"unpack_transaction_id", py_unpack_transaction_id, METH_O, "alias transaction_id"},
    { "unpack",        (PyCFunction)py_unpack,         METH_FASTCALL, "dispatch-to-type unpack(bytes) helper" },
    // sentinel
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "stdabi",
    "Autogenerated stdabi module",
    -1,
    Methods,
};

PyMODINIT_FUNC
PyInit_stdabi(void)
{
    return PyModule_Create(&module_def);
}