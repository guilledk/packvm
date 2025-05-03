use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, Data, DeriveInput, Fields, Attribute, Lit, LitStr, Meta, MetaNameValue,
};

#[allow(dead_code)]
fn vm_name_attr(attrs: &[Attribute], default: &str) -> LitStr {
    for attr in attrs {
        if attr.path.is_ident("vm_name") {
            match attr.parse_meta() {
                Ok(Meta::NameValue(MetaNameValue { lit: Lit::Str(lit), .. })) => return lit,
                _ => panic!("`vm_name` must be of the form #[vm_name = \"…\"]"),
            }
        }
    }
    LitStr::new(default, proc_macro2::Span::call_site())
}

#[proc_macro_derive(VMStruct, attributes(vm_name))]
pub fn vm_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name  = &input.ident;

    let fields = match &input.data {
        Data::Struct(s) => &s.fields,
        _ => panic!("VMStruct can only be derived for structs"),
    };
    let field_count = fields.len();

    let inserts = fields.iter().enumerate().map(|(idx, f)| {
        let key = f.ident
            .as_ref()
            .map(|id| id.to_string())
            .unwrap_or_else(|| idx.to_string());

        let access = f.ident.as_ref()
            .map(|id| quote! { value.#id })
            .unwrap_or_else(|| {
                let i = syn::Index::from(idx);
                quote! { value.#i }
            });

        quote! {
            map.insert(#key.to_string(), (#access).into());
        }
    });

    quote! {
        impl From<#name> for ::packvm::Value {
            fn from(value: #name) -> ::packvm::Value {
                let mut map = ::std::collections::HashMap::<String, ::packvm::Value>::with_capacity(#field_count);
                #( #inserts )*
                ::packvm::Value::Struct(map)
            }
        }
    }
        .into()
}

#[proc_macro_derive(VMEnum, attributes(vm_name))]
pub fn vm_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name  = &input.ident;

    let variants = match &input.data {
        Data::Enum(e) => &e.variants,
        _ => panic!("VMEnum can only be derived for enums"),
    };

    let arms = variants.iter().enumerate().map(|(idx, v)| {
        let v_ident = &v.ident;

        if !matches!(v.fields, Fields::Unnamed(ref u) if u.unnamed.len()==1) {
            panic!("Variant {v_ident} must be a tuple struct with exactly one field");
        }

        quote! {
            #name::#v_ident(inner) => {
                let mut map = ::std::collections::HashMap::<String, ::packvm::Value>::new();
                map.insert("type".to_string(), ::packvm::Value::Uint32(#idx as u32));

                match inner.into() {
                    ::packvm::Value::Struct(fields) => {
                        map.extend(fields.into_iter());
                    }
                    other => {
                        map.insert("value".to_string(), other);
                    }
                }

                ::packvm::Value::Struct(map)
            }
        }
    });

    quote! {
        impl From<#name> for ::packvm::Value {
            fn from(value: #name) -> ::packvm::Value {
                match value { #( #arms ),* }
            }
        }
    }
        .into()
}
