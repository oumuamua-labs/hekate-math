// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <andrei@oumuamua.dev>
// Copyright (C) 2026 Oumuamua Labs <info@oumuamua.dev>.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use proc_macro2::{Delimiter, Group, Spacing, TokenStream, TokenTree};
use quote::ToTokens;
use std::fs;
use std::path::Path;
use syn::{ImplItem, Item, ItemImpl, ItemMacro, ItemTrait, TraitItem};

const PINS: &str = include_str!("pins.txt");
const EXPECTED_PINS: usize = 147;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

struct Pin<'a> {
    file: &'a str,
    item: &'a str,
    twin: &'a str,
    hash: u64,
}

fn hash_of(source: &str) -> u64 {
    let file = syn::parse_file(source).expect("test source parses");

    hash_items(&resolve(&file.items, &["f"]))
}

fn parse_pin(line: &str) -> Pin<'_> {
    let fields: Vec<&str> = line.split(" | ").collect();

    let &[file, item, twin, hash] = fields.as_slice() else {
        panic!("malformed pin: {line}");
    };

    let hash = u64::from_str_radix(hash, 16).unwrap_or_else(|e| panic!("{line}: {e}"));

    Pin {
        file,
        item,
        twin,
        hash,
    }
}

fn resolve(items: &[Item], path: &[&str]) -> Vec<TokenStream> {
    let Some((&head, rest)) = path.split_first() else {
        return Vec::new();
    };

    items
        .iter()
        .flat_map(|item| resolve_item(item, head, rest))
        .collect()
}

fn resolve_item(item: &Item, head: &str, rest: &[&str]) -> Vec<TokenStream> {
    match (item, rest) {
        (Item::Fn(f), []) if f.sig.ident == head => vec![f.to_token_stream()],
        (Item::Macro(m), []) if macro_matches(m, head) => vec![m.to_token_stream()],
        (Item::Mod(m), [_, ..]) if m.ident == head => match &m.content {
            Some((_, inner)) => resolve(inner, rest),
            None => Vec::new(),
        },
        (Item::Impl(block), [method]) if impl_matches(block, head) => impl_fns(block, method),
        (Item::Trait(t), [method]) if trait_matches(t, head) => trait_fns(t, method),
        _ => Vec::new(),
    }
}

fn macro_matches(m: &ItemMacro, head: &str) -> bool {
    match (
        head.strip_prefix("macro_rules! "),
        head.strip_suffix('!'),
        &m.ident,
    ) {
        (Some(name), _, Some(ident)) => m.mac.path.is_ident("macro_rules") && ident == name,
        (None, Some(name), None) => m.mac.path.is_ident(name),
        _ => false,
    }
}

fn impl_matches(block: &ItemImpl, head: &str) -> bool {
    let Some(spec) = head.strip_prefix("impl ") else {
        return false;
    };

    let actual = match &block.trait_ {
        Some((path, _)) => format!("{}for{}", compact(path), compact(&block.self_ty)),
        None => compact(&block.self_ty),
    };

    actual == compact_str(spec)
}

fn trait_matches(t: &ItemTrait, head: &str) -> bool {
    head.strip_prefix("trait ")
        .is_some_and(|name| t.ident == name)
}

fn impl_fns(block: &ItemImpl, method: &str) -> Vec<TokenStream> {
    block
        .items
        .iter()
        .filter_map(|item| match item {
            ImplItem::Fn(f) if f.sig.ident == method => {
                let mut tokens = TokenStream::new();
                for attr in &block.attrs {
                    attr.to_tokens(&mut tokens);
                }

                f.to_tokens(&mut tokens);
                Some(tokens)
            }
            _ => None,
        })
        .collect()
}

fn trait_fns(t: &ItemTrait, method: &str) -> Vec<TokenStream> {
    t.items
        .iter()
        .filter_map(|item| match item {
            TraitItem::Fn(f) if f.sig.ident == method => Some(f.to_token_stream()),
            _ => None,
        })
        .collect()
}

fn compact(node: &impl ToTokens) -> String {
    compact_str(&node.to_token_stream().to_string())
}

fn compact_str(text: &str) -> String {
    text.split_whitespace().collect()
}

fn hash_items(items: &[TokenStream]) -> u64 {
    let mut hash = FNV_OFFSET;
    for stream in items {
        feed_stream(&mut hash, stream.clone());
    }

    hash
}

fn feed_stream(hash: &mut u64, stream: TokenStream) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();

    let mut i = 0;
    while i < tokens.len() {
        match doc_attr_len(&tokens[i..]) {
            0 => {
                feed_tree(hash, &tokens[i]);
                i += 1;
            }
            len => i += len,
        }
    }
}

fn doc_attr_len(tokens: &[TokenTree]) -> usize {
    match tokens {
        [TokenTree::Punct(p), TokenTree::Group(g), ..] if p.as_char() == '#' && is_doc(g) => 2,
        [
            TokenTree::Punct(p),
            TokenTree::Punct(b),
            TokenTree::Group(g),
            ..,
        ] if p.as_char() == '#' && b.as_char() == '!' && is_doc(g) => 3,
        _ => 0,
    }
}

fn is_doc(group: &Group) -> bool {
    group.delimiter() == Delimiter::Bracket
        && matches!(
            group.stream().into_iter().next(),
            Some(TokenTree::Ident(ident)) if ident == "doc"
        )
}

fn feed_tree(hash: &mut u64, tree: &TokenTree) {
    match tree {
        TokenTree::Group(group) => {
            let delimiter = delimiter_byte(group.delimiter());

            feed(hash, &[b'<', delimiter]);
            feed_stream(hash, group.stream());
            feed(hash, &[b'>', delimiter]);
        }
        TokenTree::Ident(ident) => {
            feed(hash, b"i");
            feed(hash, ident.to_string().as_bytes());
        }
        TokenTree::Punct(punct) => {
            let joint = u8::from(punct.spacing() == Spacing::Joint);

            feed(hash, &[b'p', punct.as_char() as u8, joint]);
        }
        TokenTree::Literal(literal) => {
            feed(hash, b"l");
            feed(hash, literal.to_string().as_bytes());
        }
    }

    feed(hash, &[0xff]);
}

fn delimiter_byte(delimiter: Delimiter) -> u8 {
    match delimiter {
        Delimiter::Parenthesis => b'(',
        Delimiter::Brace => b'{',
        Delimiter::Bracket => b'[',
        Delimiter::None => b'_',
    }
}

fn feed(hash: &mut u64, bytes: &[u8]) {
    for &byte in bytes {
        *hash ^= u64::from(byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
}

fn assert_twin_exists(root: &Path, twin: &str) {
    let Some((file, anchor)) = twin.split_once("::") else {
        panic!("malformed twin: {twin}");
    };

    let text = fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));

    if file.ends_with(".md") {
        assert!(
            text.contains(anchor),
            "{file}: no `{anchor}` for twin `{twin}`"
        );

        return;
    }

    let tokens: TokenStream = text.parse().unwrap_or_else(|e| panic!("{file}: {e}"));

    for name in anchor.split("::") {
        assert!(
            defines(tokens.clone(), name),
            "{file}: no fn, struct or impl `{name}` for twin `{twin}`"
        );
    }
}

fn defines(stream: TokenStream, name: &str) -> bool {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();

    let defined_here = tokens.windows(2).any(|pair| match pair {
        [TokenTree::Ident(kw), TokenTree::Ident(id)] => {
            (kw == "fn" || kw == "struct" || kw == "impl") && id == name
        }
        _ => false,
    });

    if defined_here {
        return true;
    }

    tokens.iter().any(|tree| match tree {
        TokenTree::Group(group) => defines(group.stream(), name),
        _ => false,
    })
}

#[test]
fn twinned_functions_match_their_pins() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut stale = Vec::new();

    let pins: Vec<_> = PINS
        .lines()
        .filter(|line| !line.is_empty())
        .map(parse_pin)
        .collect();

    assert_eq!(
        pins.len(),
        EXPECTED_PINS,
        "update EXPECTED_PINS and verus/exec/pins.txt together"
    );

    for pin in pins {
        let source =
            fs::read_to_string(root.join(pin.file)).unwrap_or_else(|e| panic!("{}: {e}", pin.file));
        let file = syn::parse_file(&source).unwrap_or_else(|e| panic!("{}: {e}", pin.file));
        let path: Vec<&str> = pin.item.split("::").collect();
        let found = resolve(&file.items, &path);

        assert!(!found.is_empty(), "{}: no item `{}`", pin.file, pin.item);
        assert_twin_exists(root, pin.twin);

        let hash = hash_items(&found);

        if hash != pin.hash {
            stale.push(format!(
                "{} | {} | {} | {hash:016x}",
                pin.file, pin.item, pin.twin
            ));
        }
    }

    assert!(
        stale.is_empty(),
        "twinned production functions changed: re-sync each twin, \
         then replace its line in verus/exec/pins.txt with\n{}",
        stale.join("\n")
    );
}

#[test]
fn pin_hash_ignores_comments_and_docs() {
    let base = hash_of("/// one\nfn f() { let x = 1; }");

    assert_eq!(
        base,
        hash_of("// two\n/// three\nfn f() {\n    // four\n    let x = 1;\n}")
    );
    assert_ne!(base, hash_of("fn f() { let x = 2; }"));
    assert_ne!(base, hash_of("#[inline]\nfn f() { let x = 1; }"));
}

#[test]
fn twin_anchor_needs_definition() {
    let source: TokenStream = "verus! { struct Twin; impl Twin { fn new() { ghost() } } }"
        .parse()
        .expect("test source lexes");

    assert!(defines(source.clone(), "Twin"));
    assert!(defines(source.clone(), "new"));
    assert!(!defines(source.clone(), "Tw"));
    assert!(!defines(source, "ghost"));
}
