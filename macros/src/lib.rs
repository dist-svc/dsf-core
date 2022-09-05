extern crate proc_macro;
use proc_macro::{TokenStream, Span};

use quote::{quote, TokenStreamExt};
use syn::{parse_macro_input, DeriveInput, Data, Fields, Ident};

use dsf_core_base::{Parse, Encode};

/// Parse derive helper
#[proc_macro_derive(Parse)]
pub fn derive_parse_impl(input: TokenStream) -> TokenStream {

    let DeriveInput { ident, data, generics, .. } = parse_macro_input!(input);

    // Extract struct fields
    let s = match data {
        Data::Struct(s) => s,
        _ => panic!("Unsupported object type for derivation"),
    };

    // Build parser for each field
    let mut parsers = quote!{};
    let mut fields = quote!{};

    let g = generics.params;

    s.fields.iter().enumerate().for_each(|(i, f)| {
        let ty = &f.ty;

        let id = match f.ident.clone() {
            Some(id) => id,
            None => Ident::new(&format!("_{}", i), ident.span()),
        };

        parsers.extend(quote!{
            let (#id, n) = #ty::parse(&buff[index..])?;
            index += n;
        });

        fields.extend(quote!{ #id, })
    });

    let obj = match s.fields {
        Fields::Named(_) => quote!(Self{#fields}),
        Fields::Unnamed(_) => quote!(Self(#fields)),
        Fields::Unit => quote!(Self{#fields}),
    };

    quote! {
        impl dsf_core_base::Parse for #ident {
            type Output = Self;

            type Error = dsf_core_base::Error;
            
            fn parse<'a>(buff: &'a [u8]) -> Result<(Self::Output, usize), Self::Error> {
                use dsf_core_base::Parse;

                let mut index = 0;
                
                #parsers

                Ok((#obj, index))
            }
        }
    }.into()
}

/// Encode derive helper
#[proc_macro_derive(Encode)]
pub fn derive_encode_impl(input: TokenStream) -> TokenStream {

    let DeriveInput { ident, data, generics, .. } = parse_macro_input!(input);

    // Extract struct fields
    let s = match data {
        Data::Struct(s) => s,
        _ => panic!("Unsupported object type for derivation"),
    };

    // Build parser for each field
    let mut encoders = quote!{};

    s.fields.iter().enumerate().for_each(|(i, f)| {
        let f = match f.ident.clone() {
            Some(id) => {
                quote!{
                    index += self.#id.encode(&mut buff[index..])?;
                }
            },
            None => {
                let id = syn::Index::from(i);
                quote!{
                    index += self.#id.encode(&mut buff[index..])?;
                }
            }
        };

        encoders.extend(f);
    });

    quote! {
        impl dsf_core_base::Encode for #ident {

            type Error = dsf_core_base::Error;
            
            fn encode(&self, buff: &mut [u8]) -> Result<usize, Self::Error> {
                use dsf_core_base::Encode;

                let mut index = 0;
                
                #encoders

                Ok(index)
            }
        }
    }.into()
}
