use crate::{RunTarget, Value};
use pyo3::prelude::{PyAnyMethods, PyDictMethods, PyListMethods};
use pyo3::types::{PyDict, PyList, PyTuple};
use pyo3::{Bound, FromPyObject, IntoPyObject, IntoPyObjectExt, PyAny, PyErr, PyResult, Python};
use pyo3::exceptions::PyTypeError;
use crate::compiler::TypeModifier;
use crate::utils::numbers::U48;

impl<'py> FromPyObject<'py> for RunTarget {
    fn extract_bound(ob: &Bound<'py, PyAny>) -> PyResult<Self> {
        if let Ok(seq) = ob.downcast::<pyo3::types::PySequence>() {
            let pid = U48(seq.get_item(0)?.extract::<u64>()?);
            let maybe_mod = seq.get_item(1)?;
            let modifier: Option<TypeModifier> = if !maybe_mod.is_none() {
                let _mod = maybe_mod.extract::<u8>()?;
                Some(_mod.into())
            } else {
                None
            };
            Ok(RunTarget::new(pid, modifier))
        } else {
            Err(PyTypeError::new_err(format!("Cant convert {} into RunTarget", ob.to_string())))
        }
    }
}

impl<'py> IntoPyObject<'py> for RunTarget {
    type Target = PyAny;
    type Output = Bound<'py, Self::Target>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        let m: Option<u8> = if let Some(tm) = self.modifier {
            Some(tm.into())
        } else {
            None
        };
        let tuple = PyTuple::new(py, &[
            self.pid.0.into_py_any(py)?,
            m.into_py_any(py)?
        ])?;
        Ok(tuple.into_any())
    }
}

impl<'py> IntoPyObject<'py> for Value {
    type Target = PyAny;
    type Output = Bound<'py, Self::Target>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        match self {
            Value::None => Ok(py.None().into_bound_py_any(py)?),
            Value::Bool(b) => Ok(b.into_bound_py_any(py)?),
            Value::Int(num) => {
                if num.is_unsigned() {
                    Ok(num.as_u64().unwrap().into_bound_py_any(py)?)
                } else {
                    Ok(num.as_i64().unwrap().into_bound_py_any(py)?)
                }
            }
            Value::Long(num) => {
                if num.is_unsigned() {
                    Ok(num.as_u128().unwrap().into_bound_py_any(py)?)
                } else {
                    Ok(num.as_i128().unwrap().into_bound_py_any(py)?)
                }
            }
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
