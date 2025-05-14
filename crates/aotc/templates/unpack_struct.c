{%- import "macros.c" as m -%}

static inline PyObject *
unpack_{{ fn_name }}(const char *b, size_t buf_len, size_t *c, size_t __depth)
{
    size_t __consumed = 0;
    size_t __total    = 0;

    #ifdef __PACKVM_DEBUG
        size_t __start_total = 0;
        {% call m::write_depth() %}
        PySys_WriteStdout("struct {{ fn_name }}:\n");
    #endif

    __depth++;

    // decode fields
{%- for f in fields -%}
    {% call m::unpack_field(f) %}
{%- endfor %}
    // build python dict
    if (c) *c = __total;

    PyObject *__dict = PyDict_New();
    if (!__dict) goto error;

    // set items
{% for f in fields %}
    if (PyDict_SetItemString(__dict, "{{ f.name }}", {{ f.name }}) < 0) goto error;
{%- endfor %}
    #ifdef __PACKVM_DEBUG
        {% call m::write_depth() %}
        PySys_WriteStdout("fields set on dict\n");
    #endif
    // drop local refs now owned by dict
{% for f in fields %}
    Py_DECREF({{ f.name }});
{%- endfor %}
    return __dict;

error:
    PyErr_SetString(PyExc_RuntimeError, "While unpacking {{ fn_name }}");
{%- for f in fields %}
    Py_XDECREF({{ f.name }});
{%- endfor %}
    Py_XDECREF(__dict);
    return NULL;
}
