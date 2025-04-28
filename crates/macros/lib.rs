use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Fields};

#[proc_macro_derive(StackEnum)]
pub fn stack_enum(input: TokenStream) -> TokenStream {
    let input   = parse_macro_input!(input as DeriveInput);
    let name    = &input.ident;
    let variants = match input.data {
        syn::Data::Enum(ref e) => &e.variants,
        _ => panic!("StackEnum can only be derived for enums"),
    };

    let arms = variants.iter().enumerate().map(|(idx, v)| {
        let ident = &v.ident;
        let field = &v.fields;
        let push = match field {
            Fields::Unnamed(f) if f.unnamed.len() == 1 => quote! { val.push_to_stack(out); },
            _ => panic!("Each variant must have exactly one unnamed field"),
        };
        quote! {
            #name::#ident(val) => {
                out.push(Value::Condition(#idx as isize));
                #push
            }
        }
    });

    TokenStream::from(quote! {
        impl ::packvm::IOStackValue for #name {
            fn push_to_stack(&self, out: &mut Vec<Value>) {
                match self {
                    #( #arms ),*
                }
            }
        }
    })
}

#[proc_macro_derive(StackStruct)]
pub fn stack_struct(input: TokenStream) -> TokenStream {
    let input  = parse_macro_input!(input as DeriveInput);
    let name   = input.ident;
    let fields = match input.data {
        syn::Data::Struct(s) => s.fields,
        _ => panic!("StackStruct can only be derived for structs"),
    };

    let pushes = fields.iter().enumerate().map(|(idx, f)| {
        let access = match &f.ident {
            Some(ident) => quote! { self.#ident },
            None => {
                let index = syn::Index::from(idx);
                quote! { self.#index }
            }
        };
        quote! {
            ::packvm::IOStackValue::push_to_stack(
                &#access,
                out,
            );
        }
    });

    TokenStream::from(quote! {
        impl ::packvm::IOStackValue for #name {
            #[allow(unused_imports)]
            fn push_to_stack(&self, out: &mut Vec<::packvm::Value>) {
                use ::packvm::IOStackValue as _;  // brings the trait into scope
                #( #pushes )*
            }
        }
    })
}
