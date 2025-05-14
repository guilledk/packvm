{%- import "macros.c" as m -%}

static inline PyObject *
unpack_{{ alias }}(const char *b, size_t buf_len, size_t *c, size_t depth)
{
    return unpack_{{ call.type_name }}(b, {% for a in call.args %}{{ a }}, {% endfor %}buf_len, c, depth);
}
