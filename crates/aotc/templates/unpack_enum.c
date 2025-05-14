static inline PyObject *
unpack_{{ enum_name }}(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    // decode variant index (ULEB128)
    size_t __local = 0;
    uint64_t idx = decode_uleb128(b, &__local);
    if (idx >= {{ variants.len() }}) {
        PyErr_SetString(PyExc_ValueError,
                        "enum variant index out of range");
        return NULL;
    }

    PyObject *__ret = NULL;
    size_t __inner = 0;
    // dispatch
    switch (idx) {
    {%- for v in variants %}
        case {{ loop.index0 }}: {
            __ret = unpack_{{ v.name }}(b + __local, buf_len, &__inner, depth);
            {% if !v.is_std -%}
            PyObject *type_str = PyUnicode_FromString("{{ v.name }}");
            if (PyDict_SetItemString(__ret, "type", type_str) < 0) goto error;
            Py_DECREF(type_str);
            {%- endif %}
            break;
        }
    {%- endfor %}
        default:  // should be unreachable
            goto error;
    }

    if (c) *c = __local + __inner;
    return __ret;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking enum \"{{ enum_name }}\"");
    return NULL;
}
