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

static inline PyObject *unpack_test_enum_v0(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_test_enum_v1(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_test_enum_v2(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_test_struct(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_test_sig(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_test_enum(const char *b, size_t buf_len, size_t *c, size_t depth);


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

static inline PyObject *unpack_transaction_id(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_checksum512(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_time_point(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_time_point_sec(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_block_timestamp_type(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_public_key(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_signature(const char *b, size_t buf_len, size_t *c, size_t depth);

static inline PyObject *unpack_bigint(const char *b, size_t buf_len, size_t *c, size_t depth);



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
unpack_test_enum_v0(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct test_enum_v0:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field",
            "u64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field: u64
    PyObject *field = unpack_u64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "field", field) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(field);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking test_enum_v0");
    Py_XDECREF(field);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_test_enum_v1(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct test_enum_v1:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field",
            "f64",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field: f64
    PyObject *field = unpack_f64(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "field", field) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(field);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking test_enum_v1");
    Py_XDECREF(field);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_test_enum_v2(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct test_enum_v2:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field",
            "str",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field: str
    PyObject *field = unpack_str(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "field", field) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(field);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking test_enum_v2");
    Py_XDECREF(field);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_test_struct(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct test_struct:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field0",
            "bool",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field0: bool
    PyObject *field0 = unpack_bool(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field0) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field0 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field1",
            "u32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field1: u32
    PyObject *field1 = unpack_u32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field1) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field1 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field2",
            "i32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field2: i32
    PyObject *field2 = unpack_i32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field2) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field2 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field3",
            "f32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field3: f32
    PyObject *field3 = unpack_f32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field3) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field3 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field4",
            "str",
            "[]"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field4: str[]
    size_t __len_field4 = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *field4 = PyList_New(__len_field4);
    if (!field4) goto error;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("array of size: %lu\n", __len_field4);
    #endif

    for (size_t _i = 0; _i < __len_field4; ++_i) {
        PyObject *_item = unpack_str(b + __total, buf_len, &__consumed, __depth + 1);
        if (!_item) { Py_DECREF(field4); goto error; }
        __total += __consumed;
        PyList_SET_ITEM(field4, _i, _item);
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field4 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field5",
            "bytes",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field5: bytes?
    PyObject *field5 = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_field5 = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_field5, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_field5) {
        field5 = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);
        if (!field5) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        field5 = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field5 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field6",
            "test_enum",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field6: test_enum
    PyObject *field6 = unpack_test_enum(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field6) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field6 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field7",
            "bool",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field7: bool
    PyObject *field7 = unpack_bool(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field7) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field7 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field8",
            "u32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field8: u32
    PyObject *field8 = unpack_u32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field8) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field8 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field9",
            "i32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field9: i32
    PyObject *field9 = unpack_i32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field9) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field9 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field10",
            "f32",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field10: f32
    PyObject *field10 = unpack_f32(b + __total, buf_len, &__consumed, __depth + 1);

    if (!field10) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field10 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field11",
            "str",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field11: str?
    PyObject *field11 = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_field11 = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_field11, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_field11) {
        field11 = unpack_str(b + __total, buf_len, &__consumed, __depth + 1);
        if (!field11) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        field11 = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field11 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field12",
            "bytes",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field12: bytes?
    PyObject *field12 = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_field12 = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_field12, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_field12) {
        field12 = unpack_bytes(b + __total, buf_len, &__consumed, __depth + 1);
        if (!field12) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        field12 = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field12 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field13",
            "bigint",
            "?"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field13: bigint?
    PyObject *field13 = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_field13 = b[__total++];
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_field13, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_field13) {
        field13 = unpack_bigint(b + __total, buf_len, &__consumed, __depth + 1);
        if (!field13) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        field13 = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field13 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field_end0",
            "bigint",
            "$"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field_end0: bigint$
    PyObject *field_end0 = NULL;

    if (__total < buf_len) {
        field_end0 = unpack_bigint(b + __total, buf_len, &__consumed, __depth + 1);
        if (!field_end0) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        field_end0 = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field_end0 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "field_end1",
            "bigint",
            "$"
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field field_end1: bigint$
    PyObject *field_end1 = NULL;

    if (__total < buf_len) {
        field_end1 = unpack_bigint(b + __total, buf_len, &__consumed, __depth + 1);
        if (!field_end1) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        field_end1 = Py_None;
    }

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("field_end1 start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "field0", field0) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field1", field1) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field2", field2) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field3", field3) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field4", field4) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field5", field5) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field6", field6) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field7", field7) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field8", field8) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field9", field9) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field10", field10) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field11", field11) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field12", field12) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field13", field13) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field_end0", field_end0) < 0) goto error;
    if (PyDict_SetItemString(__dict, "field_end1", field_end1) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(field0);
    Py_DECREF(field1);
    Py_DECREF(field2);
    Py_DECREF(field3);
    Py_DECREF(field4);
    Py_DECREF(field5);
    Py_DECREF(field6);
    Py_DECREF(field7);
    Py_DECREF(field8);
    Py_DECREF(field9);
    Py_DECREF(field10);
    Py_DECREF(field11);
    Py_DECREF(field12);
    Py_DECREF(field13);
    Py_DECREF(field_end0);
    Py_DECREF(field_end1);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking test_struct");
    Py_XDECREF(field0);
    Py_XDECREF(field1);
    Py_XDECREF(field2);
    Py_XDECREF(field3);
    Py_XDECREF(field4);
    Py_XDECREF(field5);
    Py_XDECREF(field6);
    Py_XDECREF(field7);
    Py_XDECREF(field8);
    Py_XDECREF(field9);
    Py_XDECREF(field10);
    Py_XDECREF(field11);
    Py_XDECREF(field12);
    Py_XDECREF(field13);
    Py_XDECREF(field_end0);
    Py_XDECREF(field_end1);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_test_sig(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("struct test_sig:\n");
    #endif

    __depth++;

    // decode fields
    
    #if defined(__PACKVM_DEBUG)
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout(
            "%s: %s%s\n",
            "sig",
            "signature",
            ""
        );
    #endif
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    // field sig: signature
    PyObject *sig = unpack_signature(b + __total, buf_len, &__consumed, __depth + 1);

    if (!sig) goto error;
    __total += __consumed;

    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("sig start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif

    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items

    if (PyDict_SetItemString(__dict, "sig", sig) < 0) goto error;
    #ifdef __PACKVM_DEBUG
        
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict

    Py_DECREF(sig);
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking test_sig");
    Py_XDECREF(sig);
    Py_XDECREF(__dict);
    return NULL;
}

static inline PyObject *
unpack_test_enum(const char *b, size_t buf_len, size_t *c, size_t depth)
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
            __ret = unpack_test_enum_v0(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("test_enum_v0");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        case 1: {
            __ret = unpack_test_enum_v1(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("test_enum_v1");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            break;
        }
        case 2: {
            __ret = unpack_test_enum_v2(b + __local, buf_len, &__inner, depth);
            PyObject *type_str = PyUnicode_FromString("test_enum_v2");
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
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"test_enum\"");
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
unpack_transaction_id(const char *b, size_t buf_len, size_t *c, size_t depth)
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
unpack_bigint(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_u128(b, buf_len, c, depth);
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
DEF_WRAPPER(py_unpack_test_enum_v0, unpack_test_enum_v0);
DEF_WRAPPER(py_unpack_test_enum_v1, unpack_test_enum_v1);
DEF_WRAPPER(py_unpack_test_enum_v2, unpack_test_enum_v2);
DEF_WRAPPER(py_unpack_test_struct, unpack_test_struct);
DEF_WRAPPER(py_unpack_test_sig, unpack_test_sig);
DEF_WRAPPER(py_unpack_test_enum, unpack_test_enum);

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
DEF_WRAPPER(py_unpack_transaction_id, unpack_transaction_id);
DEF_WRAPPER(py_unpack_checksum512, unpack_checksum512);
DEF_WRAPPER(py_unpack_time_point, unpack_time_point);
DEF_WRAPPER(py_unpack_time_point_sec, unpack_time_point_sec);
DEF_WRAPPER(py_unpack_block_timestamp_type, unpack_block_timestamp_type);
DEF_WRAPPER(py_unpack_public_key, unpack_public_key);
DEF_WRAPPER(py_unpack_signature, unpack_signature);
DEF_WRAPPER(py_unpack_bigint, unpack_bigint);

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
    { "test_enum_v0", unpack_test_enum_v0 },
    { "test_enum_v1", unpack_test_enum_v1 },
    { "test_enum_v2", unpack_test_enum_v2 },
    { "test_struct", unpack_test_struct },
    { "test_sig", unpack_test_sig },
    { "test_enum", unpack_test_enum },
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
    { "transaction_id", unpack_transaction_id },
    { "checksum512", unpack_checksum512 },
    { "time_point", unpack_time_point },
    { "time_point_sec", unpack_time_point_sec },
    { "block_timestamp_type", unpack_block_timestamp_type },
    { "public_key", unpack_public_key },
    { "signature", unpack_signature },
    { "bigint", unpack_bigint },
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
    {"unpack_test_enum_v0", py_unpack_test_enum_v0, METH_O, "structure test_enum_v0"},
    {"unpack_test_enum_v1", py_unpack_test_enum_v1, METH_O, "structure test_enum_v1"},
    {"unpack_test_enum_v2", py_unpack_test_enum_v2, METH_O, "structure test_enum_v2"},
    {"unpack_test_struct", py_unpack_test_struct, METH_O, "structure test_struct"},
    {"unpack_test_sig", py_unpack_test_sig, METH_O, "structure test_sig"},
    {"unpack_test_enum", py_unpack_test_enum, METH_O, "structure test_enum"},
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
    {"unpack_transaction_id", py_unpack_transaction_id, METH_O, "alias transaction_id"},
    {"unpack_checksum512", py_unpack_checksum512, METH_O, "alias checksum512"},
    {"unpack_time_point", py_unpack_time_point, METH_O, "alias time_point"},
    {"unpack_time_point_sec", py_unpack_time_point_sec, METH_O, "alias time_point_sec"},
    {"unpack_block_timestamp_type", py_unpack_block_timestamp_type, METH_O, "alias block_timestamp_type"},
    {"unpack_public_key", py_unpack_public_key, METH_O, "alias public_key"},
    {"unpack_signature", py_unpack_signature, METH_O, "alias signature"},
    {"unpack_bigint", py_unpack_bigint, METH_O, "alias bigint"},
    { "unpack",        (PyCFunction)py_unpack,         METH_FASTCALL, "dispatch-to-type unpack(bytes) helper" },
    // sentinel
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "testabi",
    "Autogenerated testabi module",
    -1,
    Methods,
};

PyMODINIT_FUNC
PyInit_testabi(void)
{
    return PyModule_Create(&module_def);
}