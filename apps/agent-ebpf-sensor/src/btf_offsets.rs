//! Minimal, narrowly-scoped BTF (BPF Type Format) parser used to resolve the
//! byte offsets of three specific kernel struct fields — `task_struct.real_parent`,
//! `task_struct.tgid`, and `linux_binprm.filename` — from the *running* kernel's
//! BTF metadata at agent startup.
//!
//! # Why this exists
//!
//! The Rust eBPF toolchain (rustc + bpf-linker) has no equivalent of Clang's
//! `__builtin_preserve_access_index`, so it cannot emit CO-RE relocations for
//! arbitrary struct field accesses the way the sibling C tracepoint
//! (`src/bpf/sys_exec.bpf.c`, via `bpf_core_read()`) does. `aya`'s own
//! "manual CO-RE" helper API (aya-rs/aya#530) has been unmerged for years and is
//! not available in the published `aya-obj` release this project depends on.
//!
//! Hardcoding the three field offsets as hardware/kernel-version-specific
//! constants (the previous approach) is unsafe: a kernel with a different
//! `task_struct`/`linux_binprm` layout silently produces wrong pointers, which
//! `bpf_probe_read_kernel` will either fault on (best case) or, worse, read
//! unrelated adjacent memory (near-miss case). This module removes that hazard
//! by resolving the real, running kernel's field offsets from its own BTF at
//! startup, **before** the enforcement program is loaded. If resolution fails
//! for any reason, the caller must refuse to load the enforcement program
//! (fail-closed) — this module never invents or falls back to a guessed value.
//!
//! # Scope
//!
//! This is deliberately *not* a general-purpose BTF library: it implements only
//! enough of the BTF binary format (see `Documentation/bpf/btf.rst` in the Linux
//! kernel source) to walk the type section, locate the two named structs, and
//! read three named members' bit offsets. It does not resolve member *types*,
//! build a full type graph, or support big-endian kernels (this project targets
//! x86_64 only).

use std::fmt;

/// Resolved, kernel-specific byte offsets for the three fields the LSM
/// enforcement hook needs. All three are byte offsets from the start of the
/// containing struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedOffsets {
    /// `linux_binprm.filename` byte offset.
    pub bprm_filename_offset: u64,
    /// `task_struct.real_parent` byte offset.
    pub task_real_parent_offset: u64,
    /// `task_struct.tgid` byte offset.
    pub task_tgid_offset: u64,
}

/// Every distinct way BTF offset resolution can fail. Each variant is meant to
/// be actionable in a startup log line: fail-closed callers should log the
/// `Display` of this error and abort rather than loading the enforcement
/// program with a guessed offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtfOffsetError {
    /// The blob is shorter than a fixed-size field being read requires.
    TooShort {
        context: &'static str,
        need: usize,
        have: usize,
    },
    /// The magic number at offset 0 does not match `0xeB9F` in either byte order.
    BadMagic(u16),
    /// The magic matched only in big-endian byte order; this parser only
    /// supports the little-endian layout used by the x86_64 kernels this
    /// project targets.
    UnsupportedEndianness,
    /// The BTF header declares a version this parser does not understand.
    UnsupportedVersion(u8),
    /// The header's declared `hdr_len` is smaller than the minimum valid size.
    HeaderTooShort { declared: u32, minimum: usize },
    /// A section (type or string) offset/length falls outside the blob.
    SectionOutOfBounds {
        section: &'static str,
        start: u64,
        len: u64,
        blob_len: usize,
    },
    /// An offset/length computation would have overflowed.
    Overflow { context: &'static str },
    /// A `btf_type` record's declared extra-data length runs past the end of
    /// the type section.
    TruncatedTypeRecord { type_id: u32 },
    /// A `BTF_KIND_*` value this parser does not know how to size/skip.
    UnsupportedKind { type_id: u32, kind: u8 },
    /// A member's `name_off` points outside the string section.
    StringOffsetOutOfBounds {
        name_off: u32,
        str_section_len: usize,
    },
    /// A string in the string section is not NUL-terminated before the end of
    /// the section.
    StringNotNulTerminated { name_off: u32 },
    /// A string's bytes are not valid UTF-8 (kernel type/member names are
    /// always plain ASCII; anything else indicates a parsing desync or
    /// corrupted BTF).
    StringNotUtf8 { name_off: u32 },
    /// Neither struct with this name was found as a `BTF_KIND_STRUCT` in the
    /// type section.
    StructNotFound { name: &'static str },
    /// The struct was found, but no member with this name exists on it.
    MemberNotFound {
        struct_name: &'static str,
        member_name: &'static str,
    },
    /// The member is encoded as a bitfield with a non-zero bit width. None of
    /// the three fields this parser resolves are expected to ever be
    /// bitfields; a non-zero bitfield width means the kernel's struct layout
    /// changed in a way this parser does not understand, and it must not
    /// guess.
    UnexpectedBitfield {
        struct_name: &'static str,
        member_name: &'static str,
        bitfield_bits: u8,
    },
    /// The member's bit offset is not byte-aligned (not a multiple of 8).
    UnalignedBitOffset {
        struct_name: &'static str,
        member_name: &'static str,
        bit_offset: u32,
    },
    /// The resolved byte offset is not strictly less than the struct's own
    /// declared size — a strong signal of a parsing desync or unexpected
    /// layout, since a member cannot start at or after the end of its struct.
    OffsetExceedsStructSize {
        struct_name: &'static str,
        member_name: &'static str,
        byte_offset: u64,
        struct_size: u32,
    },
}

impl fmt::Display for BtfOffsetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { context, need, have } => write!(
                f,
                "BTF blob too short while reading {context}: need at least {need} bytes, have {have}"
            ),
            Self::BadMagic(magic) => {
                write!(f, "BTF header has invalid magic 0x{magic:04x} (expected 0xeb9f)")
            }
            Self::UnsupportedEndianness => write!(
                f,
                "BTF blob is big-endian; this parser only supports the little-endian layout used on x86_64"
            ),
            Self::UnsupportedVersion(version) => {
                write!(f, "BTF header declares unsupported version {version} (expected 1)")
            }
            Self::HeaderTooShort { declared, minimum } => write!(
                f,
                "BTF header declares hdr_len={declared}, which is smaller than the minimum valid size {minimum}"
            ),
            Self::SectionOutOfBounds { section, start, len, blob_len } => write!(
                f,
                "BTF {section} section [{start}..{end}) falls outside the {blob_len}-byte blob",
                end = start.saturating_add(*len)
            ),
            Self::Overflow { context } => {
                write!(f, "integer overflow computing {context} while parsing BTF")
            }
            Self::TruncatedTypeRecord { type_id } => write!(
                f,
                "BTF type id {type_id} declares more trailing data than remains in the type section"
            ),
            Self::UnsupportedKind { type_id, kind } => write!(
                f,
                "BTF type id {type_id} has unsupported BTF_KIND value {kind}"
            ),
            Self::StringOffsetOutOfBounds { name_off, str_section_len } => write!(
                f,
                "BTF name_off {name_off} falls outside the {str_section_len}-byte string section"
            ),
            Self::StringNotNulTerminated { name_off } => write!(
                f,
                "BTF string at name_off {name_off} is not NUL-terminated within the string section"
            ),
            Self::StringNotUtf8 { name_off } => {
                write!(f, "BTF string at name_off {name_off} is not valid UTF-8")
            }
            Self::StructNotFound { name } => {
                write!(f, "BTF_KIND_STRUCT named \"{name}\" was not found in the running kernel's BTF")
            }
            Self::MemberNotFound { struct_name, member_name } => write!(
                f,
                "struct \"{struct_name}\" has no member named \"{member_name}\" in the running kernel's BTF"
            ),
            Self::UnexpectedBitfield { struct_name, member_name, bitfield_bits } => write!(
                f,
                "struct \"{struct_name}\" member \"{member_name}\" is encoded as a {bitfield_bits}-bit bitfield; expected a plain byte-aligned field"
            ),
            Self::UnalignedBitOffset { struct_name, member_name, bit_offset } => write!(
                f,
                "struct \"{struct_name}\" member \"{member_name}\" has bit offset {bit_offset}, which is not byte-aligned"
            ),
            Self::OffsetExceedsStructSize { struct_name, member_name, byte_offset, struct_size } => write!(
                f,
                "struct \"{struct_name}\" member \"{member_name}\" resolved to byte offset {byte_offset}, which is not less than the struct's declared size {struct_size}"
            ),
        }
    }
}

impl std::error::Error for BtfOffsetError {}

const BTF_MAGIC: u16 = 0xEB9F;
const BTF_HEADER_MIN_LEN: usize = 24;
const BTF_TYPE_RECORD_LEN: usize = 12;
const BTF_MEMBER_LEN: usize = 12;

const BTF_KIND_STRUCT: u8 = 4;

struct BtfHeader {
    hdr_len: u32,
    type_off: u32,
    type_len: u32,
    str_off: u32,
    str_len: u32,
}

/// A `BTF_KIND_STRUCT` (or `BTF_KIND_UNION`) record's decoded header plus a
/// borrowed slice over its trailing `btf_member` array. Borrows from the
/// original blob passed to [`resolve_offsets`]; never copies.
struct StructInfo<'a> {
    size: u32,
    kind_flag: bool,
    vlen: u16,
    members: &'a [u8],
}

fn read_u32_le(buf: &[u8], offset: usize, context: &'static str) -> Result<u32, BtfOffsetError> {
    let end = offset
        .checked_add(4)
        .ok_or(BtfOffsetError::Overflow { context })?;
    let bytes = buf.get(offset..end).ok_or(BtfOffsetError::TooShort {
        context,
        need: end,
        have: buf.len(),
    })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u8(buf: &[u8], offset: usize, context: &'static str) -> Result<u8, BtfOffsetError> {
    buf.get(offset).copied().ok_or(BtfOffsetError::TooShort {
        context,
        need: offset + 1,
        have: buf.len(),
    })
}

/// Bounds-checked sub-slice by (start, len), rejecting overflow and
/// out-of-range ranges explicitly instead of relying on slice-indexing panics.
fn checked_slice<'a>(
    blob: &'a [u8],
    start: u64,
    len: u64,
    section: &'static str,
) -> Result<&'a [u8], BtfOffsetError> {
    let end = start
        .checked_add(len)
        .ok_or(BtfOffsetError::Overflow { context: section })?;
    if end > blob.len() as u64 {
        return Err(BtfOffsetError::SectionOutOfBounds {
            section,
            start,
            len,
            blob_len: blob.len(),
        });
    }
    // `end <= blob.len()` was just proven above, and both fit in `usize` as a
    // consequence (blob.len() is a valid usize).
    Ok(&blob[start as usize..end as usize])
}

fn parse_header(blob: &[u8]) -> Result<BtfHeader, BtfOffsetError> {
    if blob.len() < BTF_HEADER_MIN_LEN {
        return Err(BtfOffsetError::TooShort {
            context: "btf_header",
            need: BTF_HEADER_MIN_LEN,
            have: blob.len(),
        });
    }

    let magic_le = u16::from_le_bytes([blob[0], blob[1]]);
    if magic_le != BTF_MAGIC {
        let magic_be = u16::from_be_bytes([blob[0], blob[1]]);
        if magic_be == BTF_MAGIC {
            return Err(BtfOffsetError::UnsupportedEndianness);
        }
        return Err(BtfOffsetError::BadMagic(magic_le));
    }

    let version = read_u8(blob, 2, "btf_header.version")?;
    if version != 1 {
        return Err(BtfOffsetError::UnsupportedVersion(version));
    }

    let hdr_len = read_u32_le(blob, 4, "btf_header.hdr_len")?;
    if (hdr_len as usize) < BTF_HEADER_MIN_LEN {
        return Err(BtfOffsetError::HeaderTooShort {
            declared: hdr_len,
            minimum: BTF_HEADER_MIN_LEN,
        });
    }

    let type_off = read_u32_le(blob, 8, "btf_header.type_off")?;
    let type_len = read_u32_le(blob, 12, "btf_header.type_len")?;
    let str_off = read_u32_le(blob, 16, "btf_header.str_off")?;
    let str_len = read_u32_le(blob, 20, "btf_header.str_len")?;

    Ok(BtfHeader {
        hdr_len,
        type_off,
        type_len,
        str_off,
        str_len,
    })
}

/// Number of bytes of kind-specific trailing data that follow the fixed
/// 12-byte `btf_type` header, per `Documentation/bpf/btf.rst`. Every
/// `BTF_KIND_*` value that can appear in a well-formed kernel BTF blob must be
/// handled here so the walk can correctly skip to the next record; an unknown
/// kind is treated as a hard parse error rather than an assumed-zero skip,
/// since guessing wrong would desynchronize every subsequent record.
fn kind_extra_len(kind: u8, vlen: u16, type_id: u32) -> Result<usize, BtfOffsetError> {
    let vlen = vlen as usize;
    let mul = |member_len: usize| {
        vlen.checked_mul(member_len)
            .ok_or(BtfOffsetError::Overflow {
                context: "btf_type trailing array length",
            })
    };
    match kind {
        0 => Ok(0),                   // BTF_KIND_UNKN (void)
        1 => Ok(4),                   // BTF_KIND_INT
        2 => Ok(0),                   // BTF_KIND_PTR
        3 => Ok(12),                  // BTF_KIND_ARRAY (btf_array)
        4 | 5 => mul(BTF_MEMBER_LEN), // BTF_KIND_STRUCT / BTF_KIND_UNION (btf_member[])
        6 => mul(8),                  // BTF_KIND_ENUM (btf_enum[])
        7 => Ok(0),                   // BTF_KIND_FWD
        8 => Ok(0),                   // BTF_KIND_TYPEDEF
        9 => Ok(0),                   // BTF_KIND_VOLATILE
        10 => Ok(0),                  // BTF_KIND_CONST
        11 => Ok(0),                  // BTF_KIND_RESTRICT
        12 => Ok(0),                  // BTF_KIND_FUNC
        13 => mul(8),                 // BTF_KIND_FUNC_PROTO (btf_param[])
        14 => Ok(4),                  // BTF_KIND_VAR (btf_var)
        15 => mul(12),                // BTF_KIND_DATASEC (btf_var_secinfo[])
        16 => Ok(0),                  // BTF_KIND_FLOAT
        17 => Ok(4),                  // BTF_KIND_DECL_TAG (btf_decl_tag)
        18 => Ok(0),                  // BTF_KIND_TYPE_TAG
        19 => mul(12),                // BTF_KIND_ENUM64 (btf_enum64[])
        other => Err(BtfOffsetError::UnsupportedKind {
            type_id,
            kind: other,
        }),
    }
}

fn lookup_name(str_section: &[u8], name_off: u32) -> Result<&str, BtfOffsetError> {
    // `name_off == 0` is the valid "empty name" sentinel used throughout BTF
    // for anonymous types; it is handled by the same bounds-checked lookup as
    // any other offset, since a well-formed string section always starts
    // with a leading NUL byte at offset 0.
    let start = name_off as usize;
    let tail = str_section
        .get(start..)
        .ok_or(BtfOffsetError::StringOffsetOutOfBounds {
            name_off,
            str_section_len: str_section.len(),
        })?;
    let nul_pos = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(BtfOffsetError::StringNotNulTerminated { name_off })?;
    core::str::from_utf8(&tail[..nul_pos]).map_err(|_| BtfOffsetError::StringNotUtf8 { name_off })
}

/// Finds a byte-aligned, non-bitfield member's byte offset within an already
/// located struct. `struct_name`/`member_name` are used only for error
/// context.
fn find_member_byte_offset(
    struct_info: &StructInfo<'_>,
    str_section: &[u8],
    struct_name: &'static str,
    member_name: &'static str,
) -> Result<u64, BtfOffsetError> {
    let mut cursor = 0usize;
    for _ in 0..struct_info.vlen {
        let name_off = read_u32_le(struct_info.members, cursor, "btf_member.name_off")?;
        // struct_info.members[cursor+4..cursor+8] is btf_member.type — the
        // member's own type id. Resolving it further is unnecessary: only the
        // byte offset is needed here, not the member's pointed-to type.
        let raw_offset = read_u32_le(struct_info.members, cursor + 8, "btf_member.offset")?;

        let name = lookup_name(str_section, name_off)?;
        if name == member_name {
            let (bit_offset, bitfield_bits) = if struct_info.kind_flag {
                (raw_offset & 0x00ff_ffff, (raw_offset >> 24) as u8)
            } else {
                (raw_offset, 0u8)
            };

            if bitfield_bits != 0 {
                return Err(BtfOffsetError::UnexpectedBitfield {
                    struct_name,
                    member_name,
                    bitfield_bits,
                });
            }
            if bit_offset % 8 != 0 {
                return Err(BtfOffsetError::UnalignedBitOffset {
                    struct_name,
                    member_name,
                    bit_offset,
                });
            }

            let byte_offset = u64::from(bit_offset / 8);
            if byte_offset >= u64::from(struct_info.size) {
                return Err(BtfOffsetError::OffsetExceedsStructSize {
                    struct_name,
                    member_name,
                    byte_offset,
                    struct_size: struct_info.size,
                });
            }

            return Ok(byte_offset);
        }

        cursor = cursor
            .checked_add(BTF_MEMBER_LEN)
            .ok_or(BtfOffsetError::Overflow {
                context: "btf_member cursor",
            })?;
    }

    Err(BtfOffsetError::MemberNotFound {
        struct_name,
        member_name,
    })
}

/// Walks the entire type section once, looking for `BTF_KIND_STRUCT` records
/// named `task_struct` and `linux_binprm`. The first match for each name wins;
/// a well-formed kernel BTF blob has exactly one definition of each.
fn find_structs<'a>(
    type_section: &'a [u8],
    str_section: &'a [u8],
) -> Result<(StructInfo<'a>, StructInfo<'a>), BtfOffsetError> {
    let mut task_struct: Option<StructInfo<'a>> = None;
    let mut linux_binprm: Option<StructInfo<'a>> = None;

    let mut cursor = 0usize;
    let mut type_id = 1u32; // type id 0 is the reserved "void" sentinel, not a record.

    while cursor < type_section.len() {
        let name_off = read_u32_le(type_section, cursor, "btf_type.name_off")?;
        let info = read_u32_le(type_section, cursor + 4, "btf_type.info")?;
        let size_or_type = read_u32_le(type_section, cursor + 8, "btf_type.size_or_type")?;

        let kind = ((info >> 24) & 0x1f) as u8;
        let kind_flag = (info >> 31) & 1 == 1;
        let vlen = (info & 0xffff) as u16;

        let extra_len = kind_extra_len(kind, vlen, type_id)?;
        let total_len =
            BTF_TYPE_RECORD_LEN
                .checked_add(extra_len)
                .ok_or(BtfOffsetError::Overflow {
                    context: "btf_type record length",
                })?;
        let record_end = cursor
            .checked_add(total_len)
            .ok_or(BtfOffsetError::Overflow {
                context: "btf_type record end",
            })?;
        let record = type_section
            .get(cursor..record_end)
            .ok_or(BtfOffsetError::TruncatedTypeRecord { type_id })?;

        if kind == BTF_KIND_STRUCT {
            let name = lookup_name(str_section, name_off)?;
            let want_task_struct = name == "task_struct" && task_struct.is_none();
            let want_linux_binprm = name == "linux_binprm" && linux_binprm.is_none();
            if want_task_struct || want_linux_binprm {
                let members = &record[BTF_TYPE_RECORD_LEN..];
                let info_struct = StructInfo {
                    size: size_or_type,
                    kind_flag,
                    vlen,
                    members,
                };
                if want_task_struct {
                    task_struct = Some(info_struct);
                } else {
                    linux_binprm = Some(info_struct);
                }
            }
        }

        cursor = record_end;
        type_id = type_id.checked_add(1).ok_or(BtfOffsetError::Overflow {
            context: "btf type id counter",
        })?;
    }

    let task_struct = task_struct.ok_or(BtfOffsetError::StructNotFound {
        name: "task_struct",
    })?;
    let linux_binprm = linux_binprm.ok_or(BtfOffsetError::StructNotFound {
        name: "linux_binprm",
    })?;
    Ok((task_struct, linux_binprm))
}

/// Resolves `task_struct.real_parent`, `task_struct.tgid`, and
/// `linux_binprm.filename` byte offsets from a raw BTF blob (the same wire
/// format read from `/sys/kernel/btf/vmlinux`, or `aya::Btf::to_bytes()`'s
/// re-encoding of it).
///
/// Returns `Err` — never a guessed or default value — if BTF is malformed,
/// either struct or any of the three members cannot be found by name, or any
/// of the three members is unexpectedly encoded as a non-zero-width bitfield
/// or non-byte-aligned. Callers must treat any `Err` as fatal and refuse to
/// load the enforcement program (fail-closed).
pub fn resolve_offsets(btf_blob: &[u8]) -> Result<ResolvedOffsets, BtfOffsetError> {
    let header = parse_header(btf_blob)?;

    let type_section = checked_slice(
        btf_blob,
        u64::from(header.hdr_len) + u64::from(header.type_off),
        u64::from(header.type_len),
        "type",
    )?;
    let str_section = checked_slice(
        btf_blob,
        u64::from(header.hdr_len) + u64::from(header.str_off),
        u64::from(header.str_len),
        "string",
    )?;

    let (task_struct, linux_binprm) = find_structs(type_section, str_section)?;

    let task_real_parent_offset =
        find_member_byte_offset(&task_struct, str_section, "task_struct", "real_parent")?;
    let task_tgid_offset =
        find_member_byte_offset(&task_struct, str_section, "task_struct", "tgid")?;
    let bprm_filename_offset =
        find_member_byte_offset(&linux_binprm, str_section, "linux_binprm", "filename")?;

    Ok(ResolvedOffsets {
        bprm_filename_offset,
        task_real_parent_offset,
        task_tgid_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Real BTF metadata extracted from `/sys/kernel/btf/vmlinux` on a running
    /// `5.15.167.4-microsoft-standard-WSL2` kernel (see
    /// `tests/fixtures/btf/README.md` for provenance). Ground truth for the
    /// three offsets below was independently obtained with `bpftool btf dump
    /// file <path> -j` against this exact file — NOT derived from this
    /// parser — so a match here is a genuine independent cross-check, not a
    /// tautology.
    const WSL2_515_FIXTURE: &str =
        "tests/fixtures/btf/vmlinux-5.15.167.4-microsoft-standard-wsl2.btf";

    /// bpftool-verified ground truth for the WSL2 5.15 fixture:
    /// `bpftool btf dump file <fixture> -j | jq` on `task_struct`/`linux_binprm`
    /// reported `tgid` at bit offset 11488 (byte 1436), `real_parent` at bit
    /// offset 11584 (byte 1448), and `linux_binprm.filename` at bit offset 768
    /// (byte 96). These do NOT match the previous hardcoded constants
    /// (BPRM_FILENAME_OFFSET=72, TASK_REAL_PARENT_OFFSET=1216,
    /// TASK_TGID_OFFSET=104) — that mismatch, observed on a real, currently
    /// supported kernel, is exactly the hazard this resolver removes.
    const WSL2_515_EXPECTED: ResolvedOffsets = ResolvedOffsets {
        bprm_filename_offset: 96,
        task_real_parent_offset: 1448,
        task_tgid_offset: 1436,
    };

    fn fixture_path(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
    }

    fn read_fixture(relative: &str) -> Vec<u8> {
        std::fs::read(fixture_path(relative))
            .unwrap_or_else(|error| panic!("failed to read BTF fixture {relative}: {error}"))
    }

    #[test]
    fn resolves_real_kernel_offsets_matching_bpftool_ground_truth() {
        let blob = read_fixture(WSL2_515_FIXTURE);
        let resolved = resolve_offsets(&blob).expect("resolution must succeed against real BTF");
        assert_eq!(resolved, WSL2_515_EXPECTED);
    }

    /// `aya::Btf::from_sys_fs()` is used at actual agent startup, and its
    /// bytes are obtained via `Btf::to_bytes()`, not a raw file read. This
    /// test proves that parsing aya's own re-encoding of the fixture produces
    /// identical results to parsing the raw kernel bytes directly, so the
    /// production code path (which goes through `aya::Btf`) is exercised by
    /// the same ground truth as the direct-parse test above.
    #[test]
    fn resolves_identically_after_round_tripping_through_aya_btf() {
        let blob = read_fixture(WSL2_515_FIXTURE);
        let parsed = aya::Btf::parse(&blob, aya::Endianness::default())
            .expect("aya must be able to parse the same real BTF blob");
        let re_encoded = parsed.to_bytes();

        let resolved =
            resolve_offsets(&re_encoded).expect("resolution must succeed against re-encoded BTF");
        assert_eq!(resolved, WSL2_515_EXPECTED);
    }

    #[test]
    fn rejects_empty_blob() {
        let error = resolve_offsets(&[]).unwrap_err();
        assert!(matches!(error, BtfOffsetError::TooShort { .. }));
    }

    #[test]
    fn rejects_truncated_header() {
        let blob = read_fixture(WSL2_515_FIXTURE);
        let error = resolve_offsets(&blob[..10]).unwrap_err();
        assert!(matches!(error, BtfOffsetError::TooShort { .. }));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = read_fixture(WSL2_515_FIXTURE);
        blob[0] = 0x00;
        blob[1] = 0x00;
        let error = resolve_offsets(&blob).unwrap_err();
        assert!(matches!(error, BtfOffsetError::BadMagic(0)));
    }

    #[test]
    fn rejects_big_endian_magic() {
        let mut blob = read_fixture(WSL2_515_FIXTURE);
        // Swap the magic bytes to look like a big-endian blob.
        blob[0] = 0xEB;
        blob[1] = 0x9F;
        let error = resolve_offsets(&blob).unwrap_err();
        assert_eq!(error, BtfOffsetError::UnsupportedEndianness);
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut blob = read_fixture(WSL2_515_FIXTURE);
        blob[2] = 7;
        let error = resolve_offsets(&blob).unwrap_err();
        assert_eq!(error, BtfOffsetError::UnsupportedVersion(7));
    }

    #[test]
    fn rejects_header_len_smaller_than_minimum() {
        let mut blob = read_fixture(WSL2_515_FIXTURE);
        blob[4..8].copy_from_slice(&4u32.to_le_bytes());
        let error = resolve_offsets(&blob).unwrap_err();
        assert_eq!(
            error,
            BtfOffsetError::HeaderTooShort {
                declared: 4,
                minimum: 24
            }
        );
    }

    #[test]
    fn rejects_type_section_length_past_end_of_blob() {
        let mut blob = read_fixture(WSL2_515_FIXTURE);
        // type_len lives at header bytes [12..16]; inflate it far past the blob.
        blob[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        let error = resolve_offsets(&blob).unwrap_err();
        assert!(matches!(
            error,
            BtfOffsetError::SectionOutOfBounds {
                section: "type",
                ..
            }
        ));
    }

    #[test]
    fn rejects_string_section_length_past_end_of_blob() {
        let mut blob = read_fixture(WSL2_515_FIXTURE);
        // str_len lives at header bytes [20..24].
        blob[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        let error = resolve_offsets(&blob).unwrap_err();
        assert!(matches!(
            error,
            BtfOffsetError::SectionOutOfBounds {
                section: "string",
                ..
            }
        ));
    }

    #[test]
    fn rejects_truncated_type_section_mid_record() {
        let blob = read_fixture(WSL2_515_FIXTURE);
        // Truncate a few bytes into the type section so the very first
        // record's declared trailing length runs past the (now-shorter) blob.
        let header = parse_header(&blob).expect("fixture header must parse");
        let type_start = (header.hdr_len + header.type_off) as usize;
        let truncated = &blob[..type_start + BTF_TYPE_RECORD_LEN + 2];
        let error = resolve_offsets(truncated).unwrap_err();
        assert!(matches!(
            error,
            BtfOffsetError::SectionOutOfBounds {
                section: "type",
                ..
            } | BtfOffsetError::TruncatedTypeRecord { .. }
        ));
    }

    #[test]
    fn rejects_struct_present_but_target_member_absent() {
        // Build a minimal synthetic BTF blob containing a `task_struct` with
        // none of the members this parser looks for, to prove member-absence
        // is a hard error rather than a silent skip.
        let blob = synthetic_btf_single_struct(
            "task_struct",
            /* size */ 64,
            /* kind_flag */ false,
            &[("unrelated_field", 0)],
        );
        let error = resolve_offsets(&blob).unwrap_err();
        // linux_binprm isn't present at all in this synthetic blob, so the
        // struct-not-found check for it fires first — still a hard failure,
        // never a silent fallback.
        assert!(matches!(
            error,
            BtfOffsetError::StructNotFound {
                name: "linux_binprm"
            }
        ));
    }

    #[test]
    fn rejects_member_absent_when_both_structs_present_but_field_missing() {
        let blob = synthetic_btf_two_structs(
            ("task_struct", 64, false, &[("unrelated_field", 0)]),
            ("linux_binprm", 32, false, &[("filename", 0)]),
        );
        let error = resolve_offsets(&blob).unwrap_err();
        assert_eq!(
            error,
            BtfOffsetError::MemberNotFound {
                struct_name: "task_struct",
                member_name: "real_parent"
            }
        );
    }

    #[test]
    fn rejects_unexpected_bitfield_on_target_member() {
        // kind_flag set, and the target member's packed offset encodes a
        // non-zero bitfield width — must hard-fail, not silently mask off
        // the bitfield-size bits and proceed.
        let blob = synthetic_btf_two_structs(
            (
                "task_struct",
                64,
                true,
                &[("real_parent", (8u32 << 24) | 16), ("tgid", 0)],
            ),
            ("linux_binprm", 32, false, &[("filename", 0)]),
        );
        let error = resolve_offsets(&blob).unwrap_err();
        assert_eq!(
            error,
            BtfOffsetError::UnexpectedBitfield {
                struct_name: "task_struct",
                member_name: "real_parent",
                bitfield_bits: 8,
            }
        );
    }

    #[test]
    fn rejects_unaligned_bit_offset() {
        let blob = synthetic_btf_two_structs(
            (
                "task_struct",
                64,
                false,
                &[("real_parent", 13), ("tgid", 0)],
            ),
            ("linux_binprm", 32, false, &[("filename", 0)]),
        );
        let error = resolve_offsets(&blob).unwrap_err();
        assert_eq!(
            error,
            BtfOffsetError::UnalignedBitOffset {
                struct_name: "task_struct",
                member_name: "real_parent",
                bit_offset: 13,
            }
        );
    }

    #[test]
    fn rejects_offset_at_or_past_struct_size() {
        // Struct declares size=8 bytes, but `real_parent`'s bit offset (64 ==
        // byte 8) is not strictly less than that declared size.
        let blob = synthetic_btf_two_structs(
            ("task_struct", 8, false, &[("real_parent", 64), ("tgid", 0)]),
            ("linux_binprm", 32, false, &[("filename", 0)]),
        );
        let error = resolve_offsets(&blob).unwrap_err();
        assert_eq!(
            error,
            BtfOffsetError::OffsetExceedsStructSize {
                struct_name: "task_struct",
                member_name: "real_parent",
                byte_offset: 8,
                struct_size: 8,
            }
        );
    }

    #[test]
    fn rejects_unsupported_kind_while_walking() {
        // A type record whose kind nibble is 0x1f (31) is not a defined
        // BTF_KIND_* value; the walk must hard-fail rather than guess a skip
        // length.
        let mut blob = minimal_header(0, 0);
        let type_section_start = blob.len();
        // info: kind = 0x1f in bits 24-28, vlen = 0.
        let info: u32 = 0x1f << 24;
        blob.extend_from_slice(&0u32.to_le_bytes()); // name_off
        blob.extend_from_slice(&info.to_le_bytes()); // info
        blob.extend_from_slice(&0u32.to_le_bytes()); // size_or_type
        let type_len = (blob.len() - type_section_start) as u32;
        patch_header_lengths(&mut blob, type_len, 0, 0);

        let error = resolve_offsets(&blob).unwrap_err();
        assert_eq!(
            error,
            BtfOffsetError::UnsupportedKind {
                type_id: 1,
                kind: 0x1f
            }
        );
    }

    // --- synthetic BTF blob builders for negative-path tests -------------

    /// Builds a minimal, well-formed `btf_header` with a not-yet-finalized
    /// `type_off`/`str_off`/`type_len`/`str_len` (all zero); callers append
    /// type and string section bytes, then call [`patch_header_lengths`].
    fn minimal_header(_type_len_hint: u32, _str_len_hint: u32) -> Vec<u8> {
        let mut header = Vec::with_capacity(BTF_HEADER_MIN_LEN);
        header.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        header.push(1); // version
        header.push(0); // flags
        header.extend_from_slice(&(BTF_HEADER_MIN_LEN as u32).to_le_bytes()); // hdr_len
        header.extend_from_slice(&0u32.to_le_bytes()); // type_off (relative to end of header; type section starts immediately after)
        header.extend_from_slice(&0u32.to_le_bytes()); // type_len (patched later)
        header.extend_from_slice(&0u32.to_le_bytes()); // str_off (patched later)
        header.extend_from_slice(&0u32.to_le_bytes()); // str_len (patched later)
        debug_assert_eq!(header.len(), BTF_HEADER_MIN_LEN);
        header
    }

    fn patch_header_lengths(blob: &mut [u8], type_len: u32, str_off: u32, str_len: u32) {
        blob[12..16].copy_from_slice(&type_len.to_le_bytes());
        blob[16..20].copy_from_slice(&str_off.to_le_bytes());
        blob[20..24].copy_from_slice(&str_len.to_le_bytes());
    }

    /// Appends one `BTF_KIND_STRUCT` type record (header + `btf_member[]`) to
    /// `type_buf`, and the struct's own name plus every member's name to
    /// `str_buf` (which always starts with a single leading NUL for the
    /// empty-name sentinel at offset 0). Returns nothing; mutates in place.
    fn append_struct(
        type_buf: &mut Vec<u8>,
        str_buf: &mut Vec<u8>,
        name: &str,
        size: u32,
        kind_flag: bool,
        members: &[(&str, u32)],
    ) {
        let name_off = str_buf.len() as u32;
        str_buf.extend_from_slice(name.as_bytes());
        str_buf.push(0);

        let vlen = members.len() as u16;
        let mut info: u32 = (BTF_KIND_STRUCT as u32) << 24;
        info |= u32::from(vlen);
        if kind_flag {
            info |= 1 << 31;
        }

        type_buf.extend_from_slice(&name_off.to_le_bytes());
        type_buf.extend_from_slice(&info.to_le_bytes());
        type_buf.extend_from_slice(&size.to_le_bytes());

        for (member_name, raw_offset) in members {
            let member_name_off = str_buf.len() as u32;
            str_buf.extend_from_slice(member_name.as_bytes());
            str_buf.push(0);

            type_buf.extend_from_slice(&member_name_off.to_le_bytes());
            type_buf.extend_from_slice(&0u32.to_le_bytes()); // member type id, unused by this parser
            type_buf.extend_from_slice(&raw_offset.to_le_bytes());
        }
    }

    fn synthetic_btf_single_struct(
        name: &str,
        size: u32,
        kind_flag: bool,
        members: &[(&str, u32)],
    ) -> Vec<u8> {
        let mut type_buf = Vec::new();
        let mut str_buf = vec![0u8]; // offset 0 is the empty-name sentinel
        append_struct(&mut type_buf, &mut str_buf, name, size, kind_flag, members);

        let mut blob = minimal_header(0, 0);
        let type_len = type_buf.len() as u32;
        let str_off = type_len; // string section immediately follows type section
        let str_len = str_buf.len() as u32;
        blob.extend_from_slice(&type_buf);
        blob.extend_from_slice(&str_buf);
        patch_header_lengths(&mut blob, type_len, str_off, str_len);
        blob
    }

    fn synthetic_btf_two_structs(
        first: (&str, u32, bool, &[(&str, u32)]),
        second: (&str, u32, bool, &[(&str, u32)]),
    ) -> Vec<u8> {
        let mut type_buf = Vec::new();
        let mut str_buf = vec![0u8];
        append_struct(
            &mut type_buf,
            &mut str_buf,
            first.0,
            first.1,
            first.2,
            first.3,
        );
        append_struct(
            &mut type_buf,
            &mut str_buf,
            second.0,
            second.1,
            second.2,
            second.3,
        );

        let mut blob = minimal_header(0, 0);
        let type_len = type_buf.len() as u32;
        let str_off = type_len;
        let str_len = str_buf.len() as u32;
        blob.extend_from_slice(&type_buf);
        blob.extend_from_slice(&str_buf);
        patch_header_lengths(&mut blob, type_len, str_off, str_len);
        blob
    }
}
