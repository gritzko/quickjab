"use strict";
//  JAB-035: the build-time packer, run by cmake with the freshly built jab
//  (`jab /abs/jsrcpack.js <jsrcdir> <out.pack>`) — no requires, globals only.
//
//  Pack format (what jsrcpack.S embeds and require.cpp unpacks):
//    [0,3)   magic "JSR"
//    [3]     format version
//    [4,8)   raw length of the ustar, u32 little-endian (pre-sizes inflate)
//    [8,16)  content hash: sha256(ustar)[0,8) — the cache dir name, in hex
//    [16,..) the ustar, zlib-deflated (ZLIB wrapper, what zip.inflate speaks)
//  The ustar is a sorted walk with zeroed mtime/uid/gid and a fixed 0644 mode,
//  so the same tree always packs to the same bytes and thus the same hash.

const PRE = 16;
const VERSION = 1;

//  `width`-wide ustar numeric field: width-1 octal digits, then a NUL (the
//  dst is zeroed, so only the digits are written).
function octal(n, width) {
  let s = n.toString(8);
  while (s.length < width - 1) s = "0" + s;
  return s;
}

function put(dst, off, str) { dst.set(utf8.Encode(str), off); }

//  One 512-byte ustar header at `off`: name[100] mode[8] uid[8] gid[8]
//  size[12] mtime[12] chksum[8] type[1] link[100] magic[6] ver[2] ...
//  uname/gname/dev* stay zero; prefix[155] takes the head of a long path.
function header(dst, off, name, size) {
  let prefix = "";
  if (name.length > 100) {
    let cut = -1;
    for (let i = 0; i < name.length; i++)
      if (name[i] === "/" && i <= 155 && name.length - i - 1 <= 100) {
        cut = i;
        break;
      }
    if (cut < 0) throw "jsrcpack: path too long for the archive: " + name;
    prefix = name.slice(0, cut);
    name = name.slice(cut + 1);
  }
  put(dst, off, name);
  put(dst, off + 100, octal(0o644, 8));
  put(dst, off + 108, octal(0, 8));            //  uid
  put(dst, off + 116, octal(0, 8));            //  gid
  put(dst, off + 124, octal(size, 12));
  put(dst, off + 136, octal(0, 12));           //  mtime
  for (let i = 148; i < 156; i++) dst[off + i] = 32;   //  chksum: spaces
  dst[off + 156] = 48;                         //  '0' — a regular file
  put(dst, off + 257, "ustar");                //  magic + NUL (already zero)
  dst[off + 263] = 48;
  dst[off + 264] = 48;                         //  version "00"
  if (prefix) put(dst, off + 345, prefix);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += dst[off + i];
  put(dst, off + 148, octal(sum, 7));          //  6 digits, NUL, space
  dst[off + 154] = 0;
  dst[off + 155] = 32;
}

//  Walk `root` (sorted, no dotfiles) into the ustar, then deflate it behind
//  the preamble.  Returns the pack bytes.
function pack(root) {
  while (root.length > 1 && root[root.length - 1] === "/") root = root.slice(0, -1);
  //  Only regular files go in: a socket/fifo has nothing to carry and a
  //  dangling symlink has nothing to read (io.stat follows and throws).
  const names = [], sizes = [];
  for (const p of io.readdir(root, {recursive: true}).sort()) {
    if (p.endsWith("/")) continue;
    let st = null;
    try { st = io.stat(root + "/" + p); } catch (e) { st = null; }
    if (st === null || st.kind !== "reg") continue;
    names.push(p);
    sizes.push(Number(st.size));
  }
  let raw = 1024;                              //  two zero blocks end the archive
  for (const s of sizes) raw += 512 + ((s + 511) & ~511);
  const tar = new Uint8Array(raw);
  let off = 0;
  for (let i = 0; i < names.length; i++) {
    header(tar, off, names[i], sizes[i]);
    off += 512;
    if (sizes[i]) tar.set(io.mmap(root + "/" + names[i], "r").data(), off);
    off += (sizes[i] + 511) & ~511;
  }
  const hash = sha256(tar);
  const body = zip.deflate(tar);
  const out = new Uint8Array(PRE + body.length);
  put(out, 0, "JSR");
  out[3] = VERSION;
  out[4] = raw & 0xff;
  out[5] = (raw >>> 8) & 0xff;
  out[6] = (raw >>> 16) & 0xff;
  out[7] = (raw >>> 24) & 0xff;
  out.set(hash.subarray(0, 8), 8);
  out.set(body, PRE);
  return out;
}

//  Required as a module (test/jsrcpack.js) -> exports; run as a script -> pack
//  args[0] into args[1].
if (typeof module !== "undefined" && module) {
  module.exports = {pack: pack, PRE: PRE, VERSION: VERSION};
} else {
  if (args.length < 2) throw "usage: jab jsrcpack.js <jsrcdir> <out.pack>";
  const bytes = pack(args[0]);
  const fd = io.open(args[1], "c");
  try { io.writeAll(fd, bytes); } finally { io.close(fd); }
  io.log("jsrcpack: " + args[1] + ", " + bytes.length + " bytes");
}
