/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use quote::quote;
use proc_macro::TokenStream;
use syn::{parse_macro_input, ItemFn};


#[proc_macro_attribute]
pub fn debug_show_streams(args: TokenStream, input: TokenStream) -> TokenStream {
    println!("Args:\n{:#?},\n\n", args);
    println!("Input:\n{:#?}", input);
    return input;
}

#[proc_macro_attribute]
pub fn hello_injection(_args: TokenStream, input: TokenStream) -> TokenStream {
    //println!("{:#?}", thing);
    let cloned = input.clone();
    let mut parsed_inp = parse_macro_input!(cloned as ItemFn); // Cannot inline input.clone :(

    let injected = quote!{
        println!("Hello, I am injected code!");
    };
    let body = parsed_inp.block;

    parsed_inp.block = syn::parse2( quote!{
            // the new set of braces instructs quote! to make a new block instead of a normal
            // string of tokens. Without the braces, the code will fail! I have no idea why!
        {
            #injected
            #body
        }
    }).expect(&format!("Error parsing modified function: {}", get_func_name(input.clone())));

    quote!{
        #parsed_inp
    }.into()
}

#[proc_macro_attribute]
pub fn log_uri_access(_args: TokenStream, orig_input: TokenStream) -> TokenStream {
    let cloned_inp = orig_input.clone();
    let mut parsed_inp = parse_macro_input!(cloned_inp as ItemFn);

    // parse the arguments to get the request from the args
    let sig = parsed_inp.clone().sig;
    let args = sig.inputs;

    let fst = match args.first().unwrap(){
        syn::FnArg::Typed(t) => t.clone().pat,
        syn::FnArg::Receiver(_) => {
            panic!("Expected typed arg in fn signature for `{}`, found Receiver. \nTry dumping token tree and evaluating it there!", get_func_name(orig_input.clone()));
        }
    };

    let injected = quote! {
        let headers = &#fst.headers();
        let itr = headers.iter();
        let possible = itr.filter(|i| CONTAINS_IP.contains(&i.0)).collect_vec();
        
        match possible.len() {
            0 => {
                warn!("Somehow, no ip address was found in the header!");
            },
            1 => {
                info!("Serving ({:#?}): {}", possible[0].0, possible[0].1.to_str().unwrap());
            },
            _ => {
                let forwarded = possible.iter().filter(|i| CONTAINS_FORWARDED_IP.contains(&i.0)).collect_vec();
                if forwarded.len() > 0 {
                    info!("Serving ({:#?}): {}", forwarded[0].0, forwarded[0].1.to_str().unwrap());
                } else {
                    info!("Serving ({:#?}): {}", possible[0].0, possible[0].1.to_str().unwrap());
                }
                info!("Serving");
            }
        }
        

        // info!("Serving: {}", #fst.uri());
        // info!("Ip: {}", #fst.
    };
    let orig_bdy = parsed_inp.block;

    parsed_inp.block = syn::parse2( quote!{
            // the new set of braces instructs quote! to make a new block instead of a normal
            // string of tokens. Without the braces, the code will fail! I have no idea why!
        {
            #injected
            #orig_bdy
        }
    }).expect(&format!("Error parsing modified function: {}", get_func_name(orig_input.clone())));

    //println!("{:#?}", parsed_inp);
    quote!{
        #parsed_inp
    }.into()
}

fn get_func_name(ts: TokenStream) -> String {
    let parsed_inp: ItemFn = syn::parse(ts).unwrap();
    
    let name = parsed_inp.sig.ident;
    return String::from(name.to_string());
}
