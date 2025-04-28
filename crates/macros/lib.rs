use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, Attribute, Data, DeriveInput, Fields, Lit, LitStr, Meta, MetaNameValue,
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

/* -------------------------------------------------------------------------- */
/*                               StackStruct                                  */
/* -------------------------------------------------------------------------- */

#[proc_macro_derive(StackStruct, attributes(stack_name))]
pub fn stack_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name  = &input.ident;
    let struct_lit = stack_name_attr(&input.attrs, &name.to_string());

    let fields = match &input.data {
        Data::Struct(s) => &s.fields,
        _ => panic!("StackStruct can only be derived for structs"),
    };

    let pushes = fields.iter().enumerate().map(|(idx, f)| {
        let access = match &f.ident {
            Some(ident) => quote! { self.#ident },
            None => {
                let i = syn::Index::from(idx);
                quote! { self.#i }
            }
        };
        quote! {
            ::packvm::IOStackValue::push_to_stack(&#access, out);
        }
    });

    TokenStream::from(quote! {
        impl ::packvm::IOStackValue for #name {
            fn push_to_stack(&self, out: &mut Vec<::packvm::Value>) {
                use ::packvm::IOStackValue as _;
                out.push(::packvm::Value::Struct(#struct_lit.to_string()));
                #( #pushes )*
                out.push(::packvm::Value::EndStruct);
            }
        }
    })
}

/* -------------------------------------------------------------------------- */
/*                                StackEnum                                   */
/* -------------------------------------------------------------------------- */

#[proc_macro_derive(StackEnum,   attributes(stack_name))]
pub fn stack_enum(input: TokenStream) -> TokenStream {
    let input  = parse_macro_input!(input as DeriveInput);
    let name   = &input.ident;
    let enum_lit = stack_name_attr(&input.attrs, &name.to_string());

    let variants = match &input.data {
        Data::Enum(e) => &e.variants,
        _ => panic!("StackEnum can only be derived for enums"),
    };

    let arms = variants.iter().enumerate().map(|(idx, v)| {
        let ident = &v.ident;
        let variant_lit = stack_name_attr(&v.attrs, &ident.to_string());   // NEW
        let push = match &v.fields {
            Fields::Unnamed(f) if f.unnamed.len() == 1 =>
                quote! { val.push_to_stack(out); },
            _ => panic!("Each variant must have exactly one unnamed field"),
        };
        quote! {
        #name::#ident(val) => {
            out.push(::packvm::Value::Condition(#idx as isize));
            out.push(::packvm::Value::Struct(#variant_lit.to_string())); // use override
            #push
            out.push(::packvm::Value::EndStruct);
        }
    }
    });


    TokenStream::from(quote! {
        impl ::packvm::IOStackValue for #name {
            fn push_to_stack(&self, out: &mut Vec<::packvm::Value>) {
                out.push(::packvm::Value::Struct(#enum_lit.to_string()));
                match self { #( #arms ),* }
                out.push(::packvm::Value::EndStruct);
            }
        }
    })
}
