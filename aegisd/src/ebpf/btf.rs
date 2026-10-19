// SPDX-License-Identifier: MIT OR Apache-2.0
//! Just enough of a BTF reader to find struct member offsets. aya parses
//! BTF too, but keeps struct members private.

use anyhow::{bail, ensure, Context as _, Result};

const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_TYPE_TAG: u32 = 18;

struct Type {
    name_off: u32,
    kind: u32,
    kind_flag: bool,
    /// `type` for modifiers and typedefs.
    size_or_type: u32,
    /// (name_off, type, offset) for structs and unions.
    members: Vec<(u32, u32, u32)>,
}

pub struct Btf {
    /// Index is the type id; id 0 is void.
    types: Vec<Type>,
    strings: Vec<u8>,
}

fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    let bytes = b.get(at..at + 4).context("BTF truncated")?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

impl Btf {
    pub fn parse(data: &[u8]) -> Result<Self> {
        ensure!(
            data.get(..2) == Some(&[0x9f, 0xeb]),
            "not little-endian BTF"
        );
        let hdr_len = u32_at(data, 4)? as usize;
        let type_off = hdr_len + u32_at(data, 8)? as usize;
        let type_len = u32_at(data, 12)? as usize;
        let str_off = hdr_len + u32_at(data, 16)? as usize;
        let str_len = u32_at(data, 20)? as usize;
        let tys = data
            .get(type_off..type_off + type_len)
            .context("BTF type section out of range")?;
        let strings = data
            .get(str_off..str_off + str_len)
            .context("BTF string section out of range")?
            .to_vec();

        let mut types = vec![Type {
            name_off: 0,
            kind: 0,
            kind_flag: false,
            size_or_type: 0,
            members: vec![],
        }];
        let mut at = 0;
        while at < tys.len() {
            let info = u32_at(tys, at + 4)?;
            let (kind, vlen) = ((info >> 24) & 0x1f, (info & 0xffff) as usize);
            let mut ty = Type {
                name_off: u32_at(tys, at)?,
                kind,
                kind_flag: info >> 31 == 1,
                size_or_type: u32_at(tys, at + 8)?,
                members: vec![],
            };
            at += 12;
            let extra = match kind {
                1 | 14 | 17 => 4,             // int, var, decl_tag
                3 => 12,                      // array
                4 | 5 | 15 | 19 => 12 * vlen, // struct, union, datasec, enum64
                6 | 13 => 8 * vlen,           // enum, func_proto
                2 | 7..=12 | 16 | 18 => 0,
                _ => bail!("unknown BTF kind {kind}"),
            };
            if kind == KIND_STRUCT || kind == KIND_UNION {
                for m in 0..vlen {
                    let m = at + m * 12;
                    ty.members
                        .push((u32_at(tys, m)?, u32_at(tys, m + 4)?, u32_at(tys, m + 8)?));
                }
            }
            at += extra;
            types.push(ty);
        }
        Ok(Self { types, strings })
    }

    fn name(&self, off: u32) -> &[u8] {
        let s = self.strings.get(off as usize..).unwrap_or_default();
        &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]
    }

    /// Strips typedefs and qualifiers.
    fn resolve(&self, mut id: u32) -> Option<&Type> {
        loop {
            let ty = self.types.get(id as usize)?;
            match ty.kind {
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                    id = ty.size_or_type
                }
                _ => return Some(ty),
            }
        }
    }

    /// Bit offset of `member` in `ty`, looking through anonymous
    /// structs and unions.
    fn find(&self, ty: &Type, member: &str) -> Option<u32> {
        for &(name_off, type_id, offset) in &ty.members {
            // With kind_flag set, the top 8 bits hold a bitfield size.
            let bits = if ty.kind_flag {
                offset & 0xff_ffff
            } else {
                offset
            };
            if self.name(name_off) == member.as_bytes() {
                return Some(bits);
            }
            if name_off == 0 {
                let inner = self.resolve(type_id)?;
                if let Some(b) = self.find(inner, member) {
                    return Some(bits + b);
                }
            }
        }
        None
    }

    /// Byte offset of `strukt.member`.
    pub fn offset(&self, strukt: &str, member: &str) -> Result<u32> {
        let ty = self
            .types
            .iter()
            .find(|t| t.kind == KIND_STRUCT && self.name(t.name_off) == strukt.as_bytes())
            .with_context(|| format!("struct {strukt} not in kernel BTF"))?;
        let bits = self
            .find(ty, member)
            .with_context(|| format!("{strukt}.{member} not in kernel BTF"))?;
        ensure!(bits % 8 == 0, "{strukt}.{member} is a bitfield");
        Ok(bits / 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// struct s { int a; union { int b; long c; }; }, with c at byte 8.
    #[test]
    fn finds_members_through_anonymous_unions() {
        let strings = b"\0s\0a\0b\0c\0int\0long\0";
        let mut t = Vec::new();
        let mut ty = |name: u32, info: u32, size: u32, extra: &[u32]| {
            for w in [name, info, size].iter().chain(extra) {
                t.extend_from_slice(&w.to_le_bytes());
            }
        };
        ty(9, 1 << 24, 4, &[32]); // 1: int
        ty(13, 1 << 24, 8, &[64]); // 2: long
                                   // c sits at bit 32 of the union so the nested offsets must add up.
        ty(0, 5 << 24 | 2, 8, &[5, 1, 0, 7, 2, 32]); // 3: union { b; c }
        ty(1, 4 << 24 | 2, 16, &[3, 1, 0, 0, 3, 32]); // 4: struct s { a; <anon> }

        let mut data = vec![0x9f, 0xeb, 1, 0];
        for w in [24, 0, t.len() as u32, t.len() as u32, strings.len() as u32] {
            data.extend_from_slice(&w.to_le_bytes());
        }
        data.extend_from_slice(&t);
        data.extend_from_slice(strings);

        let btf = Btf::parse(&data).unwrap();
        assert_eq!(btf.offset("s", "a").unwrap(), 0);
        assert_eq!(btf.offset("s", "b").unwrap(), 4);
        assert_eq!(btf.offset("s", "c").unwrap(), 8);
        assert!(btf.offset("s", "d").is_err());
    }
}
