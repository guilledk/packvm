{% macro write_depth() %}
    for (int i = 0; i < __depth; i++) {
        PySys_WriteStdout("\t");
    }
{%- endmacro %}

{% macro debug_field(field) %}
    #if defined(__PACKVM_DEBUG)
        {% call write_depth() %}
        PySys_WriteStdout(
            "%s: %s%s\n",
            "{{ field.name }}",
            "{{ field.call.type_name }}",
            {% if f.call.modifier == "Optional" -%}
                 "?"
            {%- else if f.call.modifier == "Extension" -%}
                 "$"
            {%- else if f.call.modifier == "Array" -%}
                 "[]"
            {%- else -%}
                 ""
            {%- endif %}
        );
    #endif
{%- endmacro %}

{% macro unpack_fn(fn_meta) -%}
unpack_{{ fn_meta.type_name }}(b + __total, {% for a in fn_meta.args %}{{ a }}, {% endfor %}buf_len, &__consumed, __depth + 1);
{%- endmacro %}

{% macro unpack_field(f) %}
    {% call debug_field(f) %}
    #ifdef __PACKVM_DEBUG
        __start_total = __total;
    #endif
    {% if f.call.modifier == "None" -%}

    // field {{ f.name }}: {{ f.call.type_name }}
    PyObject *{{ f.name }} = {% call unpack_fn(f.call) %}

    if (!{{ f.name }}) goto error;
    __total += __consumed;

    {%- else if f.call.modifier == "Optional" -%}

    // field {{ f.name }}: {{ f.call.type_name }}?
    PyObject *{{ f.name }} = NULL;

    if (__total >= buf_len) goto error;
    uint8_t __flag_{{ f.name }} = b[__total++];
    #ifdef __PACKVM_DEBUG
        {% call write_depth() %}
        PySys_WriteStdout("optional: %u delta: %lu\n", __flag_{{ f.name }}, __total - __start_total);
        __start_total = __total;
    #endif
    if (__flag_{{ f.name }}) {
        {{ f.name }} = {% call unpack_fn(f.call) %}
        if (!{{ f.name }}) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        {{ f.name }} = Py_None;
    }

    {%- else if f.call.modifier == "Extension" -%}

    // field {{ f.name }}: {{ f.call.type_name }}$
    PyObject *{{ f.name }} = NULL;

    if (__total < buf_len) {
        {{ f.name }} = {% call unpack_fn(f.call) %}
        if (!{{ f.name }}) goto error;
        __total += __consumed;
    } else {
        Py_INCREF(Py_None);
        {{ f.name }} = Py_None;
    }

    {%- else if f.call.modifier == "Array" -%}

    // field {{ f.name }}: {{ f.call.type_name }}[]
    size_t __len_{{ f.name }} = decode_uleb128(b + __total, &__consumed);
    __total += __consumed;

    PyObject *{{ f.name }} = PyList_New(__len_{{ f.name }});
    if (!{{ f.name }}) goto error;

    #ifdef __PACKVM_DEBUG
        {% call write_depth() %}
        PySys_WriteStdout("array of size: %lu\n", __len_{{ f.name }});
    #endif

    for (size_t _i = 0; _i < __len_{{ f.name }}; ++_i) {
        PyObject *_item = {% call unpack_fn(f.call) %}
        if (!_item) { Py_DECREF({{ f.name }}); goto error; }
        __total += __consumed;
        PyList_SET_ITEM({{ f.name }}, _i, _item);
    }

    {%- else %}
        /* unreachable */
    {% endif %}

    #ifdef __PACKVM_DEBUG
        {% call write_depth() %}
        PySys_WriteStdout("{{ f.name }} start: %lu, size: %lu\n", __start_total, __total - __start_total);
    #endif
{% endmacro %}