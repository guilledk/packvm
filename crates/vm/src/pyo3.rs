use pyo3::{Bound, IntoPyObject, IntoPyObjectExt, PyAny, PyErr, Python};
use pyo3::prelude::{PyDictMethods, PyListMethods};
use pyo3::types::{PyDict, PyList};
use crate::Value;

impl<'py> IntoPyObject<'py> for Value {
    type Target = PyAny;
    type Output = Bound<'py, Self::Target>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        match self {
            Value::None => Ok(py.None().into_bound_py_any(py)?),
            Value::Bool(b) => Ok(b.into_bound_py_any(py)?),
            Value::Int(num) => if num.is_unsigned() {
                Ok(num.as_u64().unwrap().into_bound_py_any(py)?)
            } else {
                Ok(num.as_i64().unwrap().into_bound_py_any(py)?)
            },
            Value::Long(num) => if num.is_unsigned() {
                Ok(num.as_u128().unwrap().into_bound_py_any(py)?)
            } else {
                Ok(num.as_i128().unwrap().into_bound_py_any(py)?)
            },
            Value::Float(num) => Ok(num.as_f64().into_bound_py_any(py)?),
            Value::String(s) => Ok(s.into_bound_py_any(py)?),
            Value::Bytes(bytes) => Ok(bytes.into_bound_py_any(py)?),
            Value::Array(values) => {
                let py_list = PyList::empty(py);
                for val in values {
                    py_list.append(val.into_pyobject(py)?)?
                }
                Ok(py_list.into_any())
            }
            Value::Struct(obj) => {
                let py_dict = PyDict::new(py);
                for (k, v) in obj {
                    py_dict.set_item(k, v)?
                }
                Ok(py_dict.into_any())
            }
        }
    }
}