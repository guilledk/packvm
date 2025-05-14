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
{% for f in functions %}
static inline PyObject *unpack_{{ f.name }}(const char *b, size_t buf_len, size_t *c, size_t depth);
{% endfor %}
{% for a in aliases %}
static inline PyObject *unpack_{{ a.alias }}(const char *b, size_t buf_len, size_t *c, size_t depth);
{% endfor %}

{% for f in functions %}
{{ f.code }}
{% endfor %}

{% for a in aliases %}
{{ a.code }}
{% endfor %}

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
{%- for f in functions %}
DEF_WRAPPER(py_unpack_{{ f.name }}, unpack_{{ f.name }});
{%- endfor %}

// aliases
{%- for a in aliases %}
DEF_WRAPPER(py_unpack_{{ a.alias }}, unpack_{{ a.alias }});
{%- endfor %}

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
{%- for f in functions %}
    { "{{ f.name }}", unpack_{{ f.name }} },
{%- endfor %}
{%- for a in aliases %}
    { "{{ a.alias }}", unpack_{{ a.alias }} },
{%- endfor %}
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
    {%- for f in functions %}
    {"unpack_{{ f.name }}", py_unpack_{{ f.name }}, METH_O, "structure {{ f.name }}"},
    {%- endfor %}
    // aliases
    {%- for a in aliases %}
    {"unpack_{{ a.alias }}", py_unpack_{{ a.alias }}, METH_O, "alias {{ a.alias }}"},
    {%- endfor %}
    { "unpack",        (PyCFunction)py_unpack,         METH_FASTCALL, "dispatch-to-type unpack(bytes) helper" },
    // sentinel
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "{{ m_name }}",
    "{{ m_doc }}",
    -1,
    Methods,
};

PyMODINIT_FUNC
PyInit_{{ m_name }}(void)
{
    return PyModule_Create(&module_def);
}
