use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, Attribute, Lit, LitStr, Meta, MetaNameValue,
};

/// Helper ─ looks for `#[stack_name = "foo"]` on the item.
fn stack_name_attr(attrs: &[Attribute], default: &str) -> LitStr {
    for attr in attrs {
        if attr.path.is_ident("stack_name") {
            match attr.parse_meta() {
                Ok(Meta::NameValue(MetaNameValue {
                                       lit: Lit::Str(lit),
                                       ..
                                   })) => return lit,
                _ => panic!("`stack_name` must be of the form #[stack_name = \"…\"]"),
            }
        }
    }
    LitStr::new(default, proc_macro2::Span::call_site())
}

#[proc_macro_derive(StackStruct, attributes(stack_name))]
pub fn stack_struct(input: TokenStream) -> TokenStream {
    use quote::quote;
    use syn::{parse_macro_input, Data, DeriveInput};

    let input        = parse_macro_input!(input as DeriveInput);
    let name         = &input.ident;
    let struct_name  = stack_name_attr(&input.attrs, &name.to_string());

    // ── collect fields in declaration order ─────────────────────────
    let fields = match &input.data {
        Data::Struct(s) => &s.fields,
        _               => panic!("StackStruct can only be derived for structs"),
    };
    let field_count = fields.len();

    // build Vec<(String, Value)>
    let pushes = fields.iter().enumerate().map(|(idx, f)| {
        let key = f.ident
            .as_ref()
            .map(|id| id.to_string())
            .unwrap_or_else(|| idx.to_string());

        let access = f.ident.as_ref()
            .map(|id| quote! { &self.#id })
            .unwrap_or_else(|| {
                let i = syn::Index::from(idx);
                quote! { &self.#i }
            });

        quote! {
            vec.push((#key.to_string(), ::packvm::IOValue::as_io(#access)));
        }
    });

    quote! {
        impl ::packvm::IOValue for #name {
            fn as_io(&self) -> ::packvm::Value {
                let mut vec = Vec::<(String, ::packvm::Value)>::with_capacity(#field_count);
                #( #pushes )*
                ::packvm::Value::Struct(#struct_name.to_string(), vec)
            }
        }
    }
        .into()
}

#[proc_macro_derive(StackEnum, attributes(stack_name))]
pub fn stack_enum(input: TokenStream) -> TokenStream {
    use quote::quote;
    use syn::{parse_macro_input, Data, DeriveInput, Fields};

    /* ────── parse input ─────────────────────────────────────────── */
    let input      = parse_macro_input!(input as DeriveInput);
    let name       = &input.ident;
    let enum_name  = stack_name_attr(&input.attrs, &name.to_string());

    let variants = match &input.data {
        Data::Enum(e) => &e.variants,
        _             => panic!("StackEnum can only be derived for enums"),
    };

    /* ────── one match-arm per variant ───────────────────────────── */
    let arms = variants.iter().enumerate().map(|(idx, v)| {
        let v_ident = &v.ident;

        // Require `Variant(T)`
        if !matches!(v.fields, Fields::Unnamed(ref u) if u.unnamed.len()==1) {
            panic!("Variant {v_ident} must be a tuple struct with exactly one field");
        }

        quote! {
            #name::#v_ident(inner) => {
                // 1. "type" field with variant index
                let mut vec = Vec::<(String, ::packvm::Value)>::new();
                vec.push((
                    "type".to_string(),
                    ::packvm::Value::Uint32(#idx as u32)
                ));

                // 2. flatten payload if it is a struct, else keep under "value"
                match ::packvm::IOValue::as_io(inner) {
                    ::packvm::Value::Struct(_, mut fields) => {
                        vec.extend(fields.drain(..));
                    }
                    other => vec.push(("value".to_string(), other)),
                }

                ::packvm::Value::Struct(#enum_name.to_string(), vec)
            }
        }
    });

    /* ────── generate impl ───────────────────────────────────────── */
    quote! {
        impl ::packvm::IOValue for #name {
            fn as_io(&self) -> ::packvm::Value {
                match self { #( #arms ),* }
            }
        }
    }
        .into()
}
