# -*- coding: utf-8 -*-
"""
decrypt_my_audio.py — 酷狗加密音频（.kgm / .kgma / .kge / .vpr / .kgg）离线解密工具

说明
----
本脚本是对成熟开源项目的 Python 移植，加密/解密算法本身并非手写，而是逐行翻译自：

  - Aaron-gx/KGG-Decryptor（Rust/Tauri，含 KGG 与 KGM v5 动态密钥支持）
      https://github.com/Aaron-gx/KGG-Decryptor
  - skxxxkx666/Kugo-Music-Converter（Go/Wails，姊妹项目）
      https://github.com/skxxxkx666/Kugo-Music-Converter
  - 底层逻辑参考 unlock-music（um/cli）

支持范围
--------
  - KGM v3：.kgm / .kgma / .kge / .vpr（旧版静态密钥，纯离线直接解密）
  - KGM v5 / KGG：.kgg 及新版客户端产出的 .kgm（动态密钥，绑定本机酷狗客户端，
    需要提供本机密钥库 KGMusicV3.db、安卓概念版 mggkey_multi_process，
    或先用 extract_keys.py 导出的 keys.json）

依赖：pip install pycryptodome

用法
----
    python decrypt_my_audio.py <加密文件或目录> [-o 输出目录] [-r]
                               [--keys keys.json] [--db KGMusicV3.db] [--mmkv mggkey_multi_process]

示例
----
    python decrypt_my_audio.py song.kgg
    python decrypt_my_audio.py D:\\KuGou\\KugouMusic -r -o D:\\out
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import math
import os
import sqlite3
import struct
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.stderr.write("缺少依赖 pycryptodome，请先执行：pip install pycryptodome\n")
    raise


# ---------------------------------------------------------------------------
# 常量（来自 KGG-Decryptor / unlock-music）
# ---------------------------------------------------------------------------

KGM_MAGIC = bytes([
    0x7C, 0xD5, 0x32, 0xEB, 0x86, 0x02, 0x7F, 0x4B,
    0xA8, 0xAF, 0xA6, 0x8E, 0x0F, 0xFF, 0x99, 0x14,
])
VPR_MAGIC = bytes([
    0x05, 0x28, 0xBC, 0x96, 0xE9, 0xE4, 0x5A, 0x43,
    0x91, 0xAA, 0xBD, 0xD0, 0x7A, 0xF5, 0x36, 0x31,
])

# 酷狗客户端魔改 SQLCipher 数据库的默认主密钥（KGMusicV3.db）
DEFAULT_MASTER_KEY = bytes([
    0x1D, 0x61, 0x31, 0x45, 0xB2, 0x47, 0xBF, 0x7F,
    0x3D, 0x18, 0x96, 0x72, 0x14, 0x4F, 0xE4, 0xBF,
    0x00, 0x00, 0x00, 0x00, 0x73, 0x41, 0x6C, 0x54,
])
DB_PAGE_SIZE = 0x400
SQLITE_HEADER = b"SQLite format 3\x00"

TEA_DELTA = 0x9E3779B9

# 手机客户端常给文件追加伪音频后缀（如 xxx.kgg.flac），先剥掉再判断真实格式
FAKE_SUFFIXES = {"mp3", "flac", "ogg", "m4a", "aac", "wav", "dff"}
SUPPORTED_SUFFIXES = {"kgg", "kgm", "kgma", "kge", "vpr"}


class DecryptError(Exception):
    """可预期的解密失败（防呆提示用），区别于代码 bug。"""


# ---------------------------------------------------------------------------
# 酷狗变体 MD5（digest 按字节对调序）
# ---------------------------------------------------------------------------

def kugou_md5(data: bytes) -> bytes:
    d = hashlib.md5(data).digest()
    out = bytearray(16)
    for i in range(0, 16, 2):
        out[i] = d[14 - i]
        out[i + 1] = d[15 - i]
    return bytes(out)


# ---------------------------------------------------------------------------
# KGM v3（.kgm/.kgma/.kge/.vpr，静态密钥）
# ---------------------------------------------------------------------------

def kgm_v3_decrypt(raw: bytes, audio: bytearray) -> None:
    """KGM v3 解密。raw 是整个文件字节（不是只有文件头），audio 是其中待解密区间。

    T(x)=x^(x<<4) 是逐字节线性变换，与 XOR 可交换，
    因此可以把三段密钥流用整段大整数异或一次性合并，避免逐字节 Python 循环。
    已知限制：b"\\xf0" * n 与音频等长，几十 MB 的文件会有一次等量的内存峰值。"""
    n = len(audio)
    if n == 0:
        raise DecryptError("文件内没有音频数据")

    slot_key = kugou_md5(bytes([0x6C, 0x2C, 0x2F, 0x27]))          # 16 字节，静态槽位密钥
    file_key = kugou_md5(raw[0x2C:0x3C]) + b"\x6b"                 # 17 字节，由文件头 master_key 派生

    fk = (file_key * (n // len(file_key) + 1))[:n]
    sk = (slot_key * (n // len(slot_key) + 1))[:n]

    # 位置折叠流：fold(i) = b0 ^ b1 ^ b2 ^ b3（i 的 4 个小端字节异或）
    t16 = bytes(((x & 0xFF) ^ (x >> 8)) for x in range(0x10000))
    pf = bytes((t16[i & 0xFFFF] ^ t16[i >> 16]) for i in range(n))

    f0mask = int.from_bytes(b"\xf0" * n, "little")
    a = int.from_bytes(bytes(audio), "little")
    fk_i = int.from_bytes(fk, "little")
    res = (a ^ ((a << 4) & f0mask)) ^ (fk_i ^ ((fk_i << 4) & f0mask)) \
        ^ int.from_bytes(sk, "little") ^ int.from_bytes(pf, "little")
    audio[:] = res.to_bytes(n, "little")


# ---------------------------------------------------------------------------
# AES-128-CBC（依赖 pycryptodome，用于 KGMusicV3.db 页面解密）
# ---------------------------------------------------------------------------

def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    # 库页面是 NoPadding 的 1024 字节整块，绝不能让它自动去填充
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


# ---------------------------------------------------------------------------
# KGMusicV3.db（魔改 SQLCipher：逐页 AES-128-CBC，第 1 页特殊处理）
# ---------------------------------------------------------------------------

def _u32(v: int) -> int:
    return v & 0xFFFFFFFF


def _derive_iv_seed(seed: int) -> int:
    left = _u32(seed * 0x9EF4)
    right = _u32((seed // 0xCE26) * 0x7FFFFF07)
    value = _u32(left - right)
    if value & 0x80000000 == 0:
        return value
    return _u32(value + 0x7FFFFF07)


def _derive_page_iv(page: int) -> bytes:
    iv_buf = bytearray(16)
    p = page + 1
    for i in range(0, 16, 4):
        p = _derive_iv_seed(p)
        iv_buf[i:i + 4] = p.to_bytes(4, "little")
    return md5(bytes(iv_buf))


def _derive_page_key(page: int) -> bytes:
    mk = bytearray(DEFAULT_MASTER_KEY)
    mk[0x10:0x14] = page.to_bytes(4, "little")
    return md5(bytes(mk))


def _decrypt_page1(buf: bytearray) -> None:
    if len(buf) < DB_PAGE_SIZE:
        return
    o10 = int.from_bytes(buf[0x10:0x14], "little")
    o14 = int.from_bytes(buf[0x14:0x18], "little")
    v6 = (((o10 & 0xFF) << 8) | ((o10 & 0xFF00) << 16)) & 0xFFFFFFFF
    check1 = o14 == 0x20204000
    check2 = _u32(v6 - 0x200) <= 0xFE00
    check3 = (_u32(v6 - 1) & v6) == 0
    if not (check1 and check2 and check3):
        return
    buf[0x10:0x18] = buf[0x08:0x10]
    key = _derive_page_key(1)
    iv = _derive_page_iv(1)
    buf[0x10:DB_PAGE_SIZE] = aes_cbc_decrypt(bytes(buf[0x10:DB_PAGE_SIZE]), key, iv)
    buf[0:16] = SQLITE_HEADER


def decrypt_database(data: bytes) -> bytes:
    """解密酷狗桌面端 KGMusicV3.db。若已是明文 SQLite 则原样返回。"""
    if data.startswith(SQLITE_HEADER):
        return data
    if len(data) < DB_PAGE_SIZE or len(data) % DB_PAGE_SIZE != 0:
        return data
    buf = bytearray(data)
    _decrypt_page1(buf)
    n_pages = len(buf) // DB_PAGE_SIZE
    for pg in range(2, n_pages + 1):
        off = (pg - 1) * DB_PAGE_SIZE
        key = _derive_page_key(pg)
        iv = _derive_page_iv(pg)
        buf[off:off + DB_PAGE_SIZE] = aes_cbc_decrypt(bytes(buf[off:off + DB_PAGE_SIZE]), key, iv)
    return bytes(buf)


def _open_plain_db(db_plain: bytes) -> sqlite3.Connection:
    """把解密后的数据库字节直接反序列化进内存库。

    不再写临时文件：明文密钥库里全是账号绑定密钥，落盘即使马上删除也会留下残影。
    """
    conn = sqlite3.connect(":memory:")
    try:
        conn.deserialize(db_plain)
    except sqlite3.Error:
        conn.close()
        raise
    return conn


def extract_ekey_map_from_db(db_plain: bytes) -> dict:
    """从（已解密的）KGMusicV3.db 中读取 audio_hash -> ekey 映射。

    实测酷狗客户端会定期把 ShareFileItems.EncryptionKey 清空（密钥并未失效，
    而是回写到 DownloadItem.EnKey）。因此两处都读：ShareFileItems 优先，
    DownloadItem 兜底，任一处有值都能用。
    """
    try:
        conn = _open_plain_db(db_plain)
        try:
            share = {
                k: v for k, v in conn.execute(
                    "SELECT EncryptionKeyId, EncryptionKey FROM ShareFileItems "
                    "WHERE EncryptionKey IS NOT NULL AND EncryptionKey != ''"
                ).fetchall() if v
            }
            try:
                downloaded = {
                    k: v for k, v in conn.execute(
                        "SELECT EnHash, EnKey FROM DownloadItem "
                        "WHERE EnKey IS NOT NULL AND EnKey != ''"
                    ).fetchall() if v and k and k != "0" * 32
                }
            except sqlite3.OperationalError:
                downloaded = {}  # 老版本数据库没有 DownloadItem 表
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        raise DecryptError(
            f"密钥库解密失败或表结构不符（{e}）。该库可能不是酷狗桌面端 KGMusicV3.db，"
            "或酷狗已更换数据库加密方案。"
        )
    return {**downloaded, **share}


def query_song_list(db_plain: bytes) -> list:
    """列出密钥库中的歌曲信息（供 extract_keys.py 展示用）。"""
    conn = _open_plain_db(db_plain)
    try:
        rows = conn.execute(
            "SELECT FileNamePure, SongName, Artist, EncryptionKeyId FROM ShareFileItems "
            "WHERE EncryptionKey IS NOT NULL AND EncryptionKey != '' ORDER BY id"
        ).fetchall()
        try:
            rows += conn.execute(
                "SELECT FileName, SongName, Artist, EnHash FROM DownloadItem "
                "WHERE EnKey IS NOT NULL AND EnKey != '' ORDER BY ID"
            ).fetchall()
        except sqlite3.OperationalError:
            pass
    finally:
        conn.close()
    return [
        {"file": r[0] or "", "song": r[1] or "", "artist": r[2] or "", "audio_hash": r[3] or ""}
        for r in rows
    ]


# ---------------------------------------------------------------------------
# 安卓酷狗概念版 MMKV 密钥库（mggkey_multi_process）解析
# ---------------------------------------------------------------------------

def _read_varint(data: bytes, at: int):
    val = 0
    shift = 0
    i = at
    while True:
        if i >= len(data):
            return None
        b = data[i]
        val |= (b & 0x7F) << shift
        i += 1
        if b & 0x80 == 0:
            break
        shift += 7
        if shift > 63:
            return None
    return val, i


def parse_mmkv_ekey_map(data: bytes) -> dict:
    """MMKV 存储格式：每项为 [32位hex hash][varint 整项长度][varint 字符串长度][字符串]。"""
    result = {}
    i = 0
    while i + 32 <= len(data):
        chunk = data[i:i + 32]
        if all(chr(b) in "0123456789abcdefABCDEF" for b in chunk):
            h = chunk.decode("ascii").lower()
            r1 = _read_varint(data, i + 32)
            if r1:
                _, p = r1
                r2 = _read_varint(data, p)
                if r2:
                    length, p2 = r2
                    if p2 + length <= len(data):
                        s = data[p2:p2 + length]
                        if all(b == 0 or b < 128 for b in s):
                            val = s.decode("ascii", "ignore").rstrip("\x00")
                            if len(val) > 16:
                                result[h] = val
                                i = p2 + length
                                continue
        i += 1
    return result


# ---------------------------------------------------------------------------
# 腾讯 TEA（QQMusic ekey 派生链使用）
# ---------------------------------------------------------------------------

def _tea_decrypt_block(block: bytes, key: bytes) -> bytes:
    v0 = int.from_bytes(block[0:4], "big")
    v1 = int.from_bytes(block[4:8], "big")
    k = [int.from_bytes(key[i * 4:i * 4 + 4], "big") for i in range(4)]
    s = _u32(TEA_DELTA * 16)
    for _ in range(16):
        t = _u32(_u32((v0 << 4) + k[2]) ^ _u32(v0 + s) ^ _u32((v0 >> 5) + k[3]))
        v1 = _u32(v1 - t)
        t = _u32(_u32((v1 << 4) + k[0]) ^ _u32(v1 + s) ^ _u32((v1 >> 5) + k[1]))
        v0 = _u32(v0 - t)
        s = _u32(s - TEA_DELTA)
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def decrypt_tencent_tea(data: bytes, key: bytes) -> bytes:
    SALT_LEN = 2
    ZERO_LEN = 7
    if len(data) % 8 != 0 or len(data) < 16:
        raise DecryptError("无效的 TEA 输入长度")
    dest = bytearray(_tea_decrypt_block(data[:8], key))
    pad_len = dest[0] & 0x7
    out_len = len(data) - (1 + pad_len + SALT_LEN + ZERO_LEN)
    if out_len < 0:
        raise DecryptError("无效的 TEA 填充")
    out = bytearray(out_len)
    iv_prev = bytearray(8)
    iv_cur = bytearray(data[:8])
    in_pos = 8
    dest_idx = 1 + pad_len

    def crypt_block():
        nonlocal in_pos, dest_idx, dest, iv_prev, iv_cur
        iv_prev, iv_cur = iv_cur, bytearray(data[in_pos:in_pos + 8])
        for i in range(8):
            dest[i] ^= iv_cur[i]
        dest = bytearray(_tea_decrypt_block(bytes(dest), key))
        in_pos += 8
        dest_idx = 0

    i = 1
    while i <= SALT_LEN:
        if dest_idx < 8:
            dest_idx += 1
            i += 1
        else:
            crypt_block()
    out_pos = 0
    while out_pos < out_len:
        if dest_idx < 8:
            out[out_pos] = dest[dest_idx] ^ iv_prev[dest_idx]
            dest_idx += 1
            out_pos += 1
        else:
            crypt_block()
    return bytes(out)


def _simple_make_key(salt: int, length: int) -> bytes:
    """Rust 端为饱和转换（>255 截到 255，NaN 为 0），此处保持一致。"""
    out = bytearray()
    for i in range(length):
        tmp = abs(math.tan(salt + i * 0.1)) * 100.0
        out.append(0 if math.isnan(tmp) else min(int(tmp), 255))
    return bytes(out)


def _derive_key_v1(raw: bytes) -> bytes:
    if len(raw) < 16:
        raise DecryptError("ekey 长度过短")
    sk = _simple_make_key(106, 8)
    tea_key = bytearray(16)
    for i in range(8):
        tea_key[i * 2] = sk[i]
        tea_key[i * 2 + 1] = raw[i]
    return raw[:8] + decrypt_tencent_tea(raw[8:], bytes(tea_key))


def _derive_key_v2(raw: bytes) -> bytes:
    k1 = bytes([0x33, 0x38, 0x36, 0x5A, 0x4A, 0x59, 0x21, 0x40,
                0x23, 0x2A, 0x24, 0x25, 0x5E, 0x26, 0x29, 0x28])
    k2 = bytes([0x2A, 0x2A, 0x23, 0x21, 0x28, 0x23, 0x24, 0x25,
                0x26, 0x5E, 0x61, 0x31, 0x63, 0x5A, 0x2C, 0x54])
    buf = decrypt_tencent_tea(raw, k1)
    buf = decrypt_tencent_tea(buf, k2)
    try:
        return base64.b64decode(buf)
    except Exception as e:
        raise DecryptError(f"ekey v2 base64 解码失败: {e}")


def derive_key(ekey: str) -> bytes:
    """ekey（base64 文本）-> QMC 流密钥。"""
    try:
        raw = base64.b64decode(ekey)
    except Exception as e:
        raise DecryptError(f"ekey base64 解码失败: {e}")
    v2_prefix = b"QQMusic EncV2,Key:"
    if raw.startswith(v2_prefix):
        raw = _derive_key_v2(raw[len(v2_prefix):])
    return _derive_key_v1(raw)


# ---------------------------------------------------------------------------
# QMC 流密码（KGM v5 / KGG 复用 QMC 体系：Map / Rc4 / Static 三态）
# ---------------------------------------------------------------------------

_MASK_PERIOD = 0x7FFF  # QMC Map 掩码的归一化周期（32767）


def _qmc_mask_shift(v: int, r: int) -> int:
    """上游把它命名为 rotl8（循环左移），但实现是 (v << r) | (v >> r)。

    这与标准循环左移 ((v << r) | (v >> (8 - r))) 不同：上游 JS/Rust 两个版本
    都确实写的是 (v >> r)，所以此处保留上游语义，只把名字改成不容易误读的形式。
    改动这里必须同步更新 test_vectors.py 里的掩码黄金向量。
    """
    return ((v << r) | (v >> r)) & 0xFF if r else v


class MapCipher:
    """QMC Map 流密码：掩码只由偏移决定，且偏移归一化后周期为 0x7FFF。

    因此把 32768 个掩码值预先算成表，解密时直接切片复用，避免逐字节调用 Python 函数。
    """

    def __init__(self, key: bytes):
        self.key = key
        self.size = len(key)
        raw = [self._mask_raw(k) for k in range(_MASK_PERIOD + 1)]
        # _head 覆盖偏移 0..0x7FFF；偏移超过 0x7FFF 后归一化序列为 1,2,...,32766,0 循环
        self._head = bytes(raw)
        self._cycle = bytes(raw[1:_MASK_PERIOD] + raw[:1])

    def _mask_raw(self, v: int) -> int:
        idx = (v * v + 71214) % self.size
        r = ((idx & 0x7) + 4) % 8
        return _qmc_mask_shift(self.key[idx], r)

    def _keystream(self, offset: int, n: int) -> bytes:
        out = bytearray()
        pos = 0
        if offset <= _MASK_PERIOD:
            cnt = min(n, _MASK_PERIOD - offset + 1)
            out += self._head[offset:offset + cnt]
            pos = cnt
            offset += cnt
        while pos < n:
            start = offset % _MASK_PERIOD          # 归一化后的偏移值（0..32766）
            ci = (start - 1) % _MASK_PERIOD        # 对应到 _cycle 的下标
            cnt = min(n - pos, _MASK_PERIOD)
            if ci + cnt <= _MASK_PERIOD:
                out += self._cycle[ci:ci + cnt]
            else:
                out += (self._cycle * 2)[ci:ci + cnt]
            pos += cnt
            offset += cnt
        return bytes(out)

    def decrypt(self, buf: bytearray, offset: int) -> None:
        n = len(buf)
        chunk = 1 << 20  # 1 MiB 一段：既不逐字节调用函数，也不把整段密钥流堆在内存里
        pos = 0
        while pos < n:
            sz = min(chunk, n - pos)
            ks = self._keystream(offset + pos, sz)
            seg = bytes(buf[pos:pos + sz])
            res = int.from_bytes(seg, "little") ^ int.from_bytes(ks, "little")
            buf[pos:pos + sz] = res.to_bytes(sz, "little")
            pos += sz


class Rc4Cipher:
    SEG = 5120
    FIRST = 128

    def __init__(self, key: bytes):
        self.key = key
        self.n = len(key)
        n = self.n
        bx = [i & 0xFF for i in range(n)]
        j = 0
        for i in range(n):
            j = (j + bx[i] + key[i % n]) % n
            bx[i], bx[j] = bx[j], bx[i]
        self.box = bx
        # hash base
        self.hash = 1
        for v in key:
            if v == 0:
                continue
            nxt = _u32(self.hash * v)
            if nxt == 0 or nxt <= self.hash:
                break
            self.hash = nxt

    def _seg_skip(self, seg_id: int) -> int:
        seed = self.key[seg_id % self.n]
        denom = (seg_id + 1) * seed
        if denom == 0:
            return 0
        val = self.hash / denom * 100.0
        if math.isnan(val) or math.isinf(val):
            return 0
        return int(val) % self.n

    def _enc_first(self, buf: bytearray, start: int, length: int, offset: int) -> None:
        key = self.key
        for i in range(length):
            buf[start + i] ^= key[self._seg_skip(offset + i)]

    def _enc_seg(self, buf: bytearray, start: int, length: int, offset: int) -> None:
        bx = self.box[:]
        n = self.n
        j = 0
        k = 0
        skip = (offset % self.SEG) + self._seg_skip(offset // self.SEG)
        for i in range(-skip, length):
            j = (j + 1) % n
            k = (bx[j] + k) % n
            bx[j], bx[k] = bx[k], bx[j]
            if i >= 0:
                buf[start + i] ^= bx[(bx[j] + bx[k]) % n]

    def decrypt(self, buf: bytearray, offset: int) -> None:
        off = offset
        done = 0
        todo = len(buf)
        if off < self.FIRST:
            sz = min(todo, self.FIRST - off)
            self._enc_first(buf, done, sz, off)
            off += sz
            todo -= sz
            done += sz
        if todo > 0 and off % self.SEG != 0:
            sz = min(todo, self.SEG - off % self.SEG)
            self._enc_seg(buf, done, sz, off)
            off += sz
            todo -= sz
            done += sz
        while todo > self.SEG:
            self._enc_seg(buf, done, self.SEG, off)
            off += self.SEG
            todo -= self.SEG
            done += self.SEG
        if todo > 0:
            self._enc_seg(buf, done, todo, off)


class StaticCipher:
    BOX = bytes([
        0x77, 0x48, 0x32, 0x73, 0xDE, 0xF2, 0xC0, 0xC8, 0x95, 0xEC, 0x30, 0xB2, 0x51, 0xC3, 0xE1, 0xA0,
        0x9E, 0xE6, 0x9D, 0xCF, 0xFA, 0x7F, 0x14, 0xD1, 0xCE, 0xB8, 0xDC, 0xC3, 0x4A, 0x67, 0x93, 0xD6,
        0x28, 0xC2, 0x91, 0x70, 0xCA, 0x8D, 0xA2, 0xA4, 0xF0, 0x08, 0x61, 0x90, 0x7E, 0x6F, 0xA2, 0xE0,
        0xEB, 0xAE, 0x3E, 0xB6, 0x67, 0xC7, 0x92, 0xF4, 0x91, 0xB5, 0xF6, 0x6C, 0x5E, 0x84, 0x40, 0xF7,
        0xF3, 0x1B, 0x02, 0x7F, 0xD5, 0xAB, 0x41, 0x89, 0x28, 0xF4, 0x25, 0xCC, 0x52, 0x11, 0xAD, 0x43,
        0x68, 0xA6, 0x41, 0x8B, 0x84, 0xB5, 0xFF, 0x2C, 0x92, 0x4A, 0x26, 0xD8, 0x47, 0x6A, 0x7C, 0x95,
        0x61, 0xCC, 0xE6, 0xCB, 0xBB, 0x3F, 0x47, 0x58, 0x89, 0x75, 0xC3, 0x75, 0xA1, 0xD9, 0xAF, 0xCC,
        0x08, 0x73, 0x17, 0xDC, 0xAA, 0x9A, 0xA2, 0x16, 0x41, 0xD8, 0xA2, 0x06, 0xC6, 0x8B, 0xFC, 0x66,
        0x34, 0x9F, 0xCF, 0x18, 0x23, 0xA0, 0x0A, 0x74, 0xE7, 0x2B, 0x27, 0x70, 0x92, 0xE9, 0xAF, 0x37,
        0xE6, 0x8C, 0xA7, 0xBC, 0x62, 0x65, 0x9C, 0xC2, 0x08, 0xC9, 0x88, 0xB3, 0xF3, 0x43, 0xAC, 0x74,
        0x2C, 0x0F, 0xD4, 0xAF, 0xA1, 0xC3, 0x01, 0x64, 0x95, 0x4E, 0x48, 0x9F, 0xF4, 0x35, 0x78, 0x95,
        0x7A, 0x39, 0xD6, 0x6A, 0xA0, 0x6D, 0x40, 0xE8, 0x4F, 0xA8, 0xEF, 0x11, 0x1D, 0xF3, 0x1B, 0x3F,
        0x3F, 0x07, 0xDD, 0x6F, 0x5B, 0x19, 0x30, 0x19, 0xFB, 0xEF, 0x0E, 0x37, 0xF0, 0x0E, 0xCD, 0x16,
        0x49, 0xFE, 0x53, 0x47, 0x13, 0x1A, 0xBD, 0xA4, 0xF1, 0x40, 0x19, 0x60, 0x0E, 0xED, 0x68, 0x09,
        0x06, 0x5F, 0x4D, 0xCF, 0x3D, 0x1A, 0xFE, 0x20, 0x77, 0xE4, 0xD9, 0xDA, 0xF9, 0xA4, 0x2B, 0x76,
        0x1C, 0x71, 0xDB, 0x00, 0xBC, 0xFD, 0x0C, 0x6C, 0xA5, 0x47, 0xF7, 0xF6, 0x00, 0x79, 0x4A, 0x11,
    ])

    def decrypt(self, buf: bytearray, offset: int) -> None:
        box = self.BOX
        n = len(buf)
        ks = bytes(
            box[(((at % 0x7FFF) if at > 0x7FFF else at) ** 2 + 27) & 0xFF]
            for at in range(offset, offset + n)
        )
        res = int.from_bytes(bytes(buf), "little") ^ int.from_bytes(ks, "little")
        buf[:] = res.to_bytes(n, "little")


def make_qmc_cipher(key: bytes):
    if len(key) > 300:
        return Rc4Cipher(key)
    if len(key) > 0:
        return MapCipher(key)
    return None


# ---------------------------------------------------------------------------
# 文件头解析与音频格式嗅探
# ---------------------------------------------------------------------------

def sniff_ext(data: bytes) -> str:
    if data.startswith(b"ID3"):
        return "mp3"
    if len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
        return "mp3"
    if data.startswith(b"fLaC"):
        return "flac"
    if data.startswith(b"OggS"):
        return "ogg"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WAVE":
        return "wav"
    if data.startswith(b"ADIF") or data.startswith(b"\xff\xf1") or data.startswith(b"\xff\xf9"):
        return "aac"
    if len(data) >= 8 and data[4:8] == b"ftyp":
        return "m4a"
    if data.startswith(bytes([0x30, 0x26, 0xB2, 0x75])):
        return "wma"
    if data.startswith(b"FRM8"):
        return "dff"
    return "bin"


def _read_u32_le(data: bytes, at: int) -> int:
    if at + 4 > len(data):
        raise DecryptError("文件头长度不足")
    return struct.unpack_from("<I", data, at)[0]


def parse_kgm_header(data: bytes):
    """返回 (audio_offset, version, slot_or_none, audio_hash_or_none)。v3/v5 通用。"""
    if len(data) < 0x44:
        raise DecryptError("文件太小，不是有效的酷狗加密文件")
    if not (data.startswith(KGM_MAGIC) or data.startswith(VPR_MAGIC)):
        raise DecryptError("文件头特征不符，不是 KGM/VPR/KGG 加密文件")
    audio_offset = _read_u32_le(data, 0x10)
    version = _read_u32_le(data, 0x14)
    if audio_offset > len(data):
        raise DecryptError("音频数据偏移超出文件范围，文件可能已损坏")
    slot = _read_u32_le(data, 0x18)
    audio_hash = None
    if version == 5:
        hash_len = _read_u32_le(data, 0x44)
        hash_end = 0x48 + hash_len
        if hash_len == 0 or hash_end > len(data):
            raise DecryptError("v5 文件头中的 audio_hash 无效")
        audio_hash = data[0x48:hash_end].decode("utf-8", "replace").rstrip("\x00")
    return audio_offset, version, slot, audio_hash


def strip_fake_suffix(name: str) -> str:
    base = os.path.basename(name)
    stem, dot, ext = base.rpartition(".")
    if dot and ext.lower() in FAKE_SUFFIXES and stem:
        return stem
    return base


def real_suffix(name: str) -> str:
    base = strip_fake_suffix(name)
    _, dot, ext = base.rpartition(".")
    return ext.lower() if dot else ""


# ---------------------------------------------------------------------------
# 密钥定位（v5 / KGG 用）
# ---------------------------------------------------------------------------

def find_db_path() -> Path | None:
    cwd = Path.cwd()
    candidates = [cwd, cwd / "tools", cwd / "..", cwd / ".." / ".."]
    for var in ("APPDATA", "LOCALAPPDATA"):
        base = os.environ.get(var)
        if base:
            candidates.append(Path(base) / "KuGou8")
            candidates.append(Path(base) / "KuGou")
    for d in candidates:
        try:
            for entry in d.iterdir():
                if entry.is_file() and entry.name.lower() == "kgmusicv3.db":
                    return entry
        except OSError:
            continue
    return None


def find_mmkv_path() -> Path | None:
    cwd = Path.cwd()
    candidates = [cwd, cwd / "tools", cwd / "..", cwd / ".." / ".."]
    for var in ("APPDATA", "LOCALAPPDATA"):
        base = os.environ.get(var)
        if base:
            candidates.append(Path(base) / "KuGou8")
            candidates.append(Path(base) / "KuGou")
    for d in candidates:
        try:
            for entry in d.iterdir():
                if entry.is_file() and entry.name == "mggkey_multi_process":
                    return entry
        except OSError:
            continue
    return None


class KeyProvider:
    """ekey 查询链：keys.json -> KGMusicV3.db -> mggkey_multi_process。惰性加载并缓存。"""

    def __init__(self, keys_json: str | None = None, db_path: str | None = None,
                 mmkv_path: str | None = None):
        self._keys_json = Path(keys_json) if keys_json else Path.cwd() / "keys.json"
        self._db_path = Path(db_path) if db_path else None
        self._mmkv_path = Path(mmkv_path) if mmkv_path else None
        self._cache: dict | None = None
        self._tried = False

    def _load(self) -> dict:
        if self._cache is not None:
            return self._cache
        merged: dict = {}
        # 1) keys.json
        if self._keys_json.is_file():
            import json
            try:
                with open(self._keys_json, "r", encoding="utf-8") as f:
                    merged.update(json.load(f))
            except Exception as e:
                print(f"  [警告] 读取 {self._keys_json} 失败: {e}")
        # 2) KGMusicV3.db
        db = self._db_path or find_db_path()
        if db and Path(db).is_file():
            try:
                plain = decrypt_database(Path(db).read_bytes())
                merged = {**extract_ekey_map_from_db(plain), **merged}
            except DecryptError as e:
                print(f"  [警告] {e}")
        # 3) MMKV（安卓概念版）
        mmkv = self._mmkv_path or find_mmkv_path()
        if mmkv and Path(mmkv).is_file():
            merged = {**parse_mmkv_ekey_map(Path(mmkv).read_bytes()), **merged}
        self._cache = merged
        return merged

    def lookup(self, audio_hash: str) -> str:
        keys = self._load()
        ek = keys.get(audio_hash)
        if ek:
            return ek
        raise DecryptError(
            "密钥库中找不到该文件的 ekey（audio_hash=%s）。\n"
            "  可能原因：该歌曲不是用本机酷狗客户端下载的（动态密钥绑定下载机器/账号），\n"
            "  或密钥库未更新。请先在酷狗客户端完整播放/下载该歌曲，\n"
            "  再用 extract_keys.py 重新导出密钥后重试。" % audio_hash
        )


# ---------------------------------------------------------------------------
# 解密主逻辑
# ---------------------------------------------------------------------------

def decrypt_bytes(data: bytes, filename: str, key_provider: KeyProvider):
    """返回 (明文音频 bytes, 输出扩展名)。抛 DecryptError 表示可预期失败。"""
    ext = real_suffix(filename)
    if ext not in SUPPORTED_SUFFIXES:
        raise DecryptError(f"不支持的格式 .{ext or '?'}（仅支持 kgg/kgm/kgma/kge/vpr）")

    audio_offset, version, slot, audio_hash = parse_kgm_header(data)
    audio = bytearray(data[audio_offset:])

    if ext == "kgg" or version == 5:
        if version != 5:
            raise DecryptError(f"不支持的 KGG 加密版本 v{version}（可能是最新动态密钥方案）")
        if key_provider is None:
            raise DecryptError("该文件为 v5 动态密钥加密，需要提供密钥库")
        ekey = key_provider.lookup(audio_hash)
        raw_key = derive_key(ekey)
        cipher = make_qmc_cipher(raw_key)
        if cipher is None:
            raise DecryptError("ekey 派生出的密钥为空，无法解密")
        cipher.decrypt(audio, 0)
    elif version == 3:
        if slot != 1:
            raise DecryptError(f"不支持的 KGM 密钥槽位 {slot}（开源实现仅覆盖槽位 1）")
        kgm_v3_decrypt(data, audio)
    else:
        raise DecryptError(
            f"未知的 KGM 加密版本 v{version}（已知 v3=静态密钥 / v5=动态密钥），"
            "可能是最新版酷狗的新方案，本脚本暂不支持"
        )

    fmt = sniff_ext(audio)
    if fmt == "bin":
        raise DecryptError(
            "解密后的数据无法识别为音频格式。\n"
            "  可能原因：密钥不匹配（v5/KGG 的 ekey 对应不上），或该文件采用了更新的加密方案。"
        )
    return bytes(audio), fmt


def output_stem(filename: str) -> str:
    base = strip_fake_suffix(filename)
    stem, dot, _ = base.rpartition(".")
    return stem if dot else base


def delete_source_after_verify(src: Path, out: Path) -> bool:
    """解密成功后删除原加密文件——执行前必须通过全部安全校验，缺一不可。

    校验清单（任一不满足都严禁删除）：
    1. 源文件必须是已知的加密格式（.kgg/.kgm/.kgma/.kge/.vpr）；
    2. 输出路径与源文件不能是同一个文件；
    3. 输出文件真实存在于硬盘上，且大小大于 0；
    4. 输出文件头部能通过音频魔数嗅探（是真实的音频格式，不是垃圾字节）。
    """
    if real_suffix(src.name) not in SUPPORTED_SUFFIXES:
        print("    解密失败，已保留原文件（源文件不是已知加密格式，拒绝删除）")
        return False
    try:
        if src.resolve() == out.resolve():
            print("    解密失败，已保留原文件（输出与源路径相同，拒绝删除）")
            return False
        if not out.is_file():
            print("    解密失败，已保留原文件（输出文件不存在）")
            return False
        if out.stat().st_size <= 0:
            print("    解密失败，已保留原文件（输出文件大小为 0）")
            return False
        with out.open("rb") as fp:
            head = fp.read(64)
        if sniff_ext(head) == "bin":
            print("    解密失败，已保留原文件（输出文件未通过音频魔数校验）")
            return False
    except OSError as e:
        print(f"    解密失败，已保留原文件（校验输出时出错: {e}）")
        return False
    try:
        src.unlink()
        print(f"    校验通过，已删除原加密文件: {src.name}")
        return True
    except OSError as e:
        print(f"    原文件删除失败（可能被占用），已保留: {e}")
        return False


def process_file(path: Path, out_dir: Path, key_provider: KeyProvider,
                 delete_source: bool = False) -> bool:
    print(f"[*] {path}")
    try:
        data = path.read_bytes()
        plain, fmt = decrypt_bytes(data, path.name, key_provider)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / (output_stem(path.name) + "." + fmt)
        out_path.write_bytes(plain)
        print(f"    成功 -> {out_path.name}  ({len(plain) / 1048576:.2f} MiB)")
        if delete_source:
            delete_source_after_verify(path, out_path)
        return True
    except DecryptError as e:
        print(f"    失败: {e}")
        return False
    except Exception as e:  # 防呆兜底：任何意外异常都不让脚本崩溃
        print(f"    失败(未预期错误): {type(e).__name__}: {e}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description="酷狗加密音频（.kgg/.kgm/.kgma/.kge/.vpr）离线解密工具"
    )
    ap.add_argument("input", help="加密音频文件路径，或包含加密文件的目录")
    ap.add_argument("-o", "--output", default=None, help="输出目录（默认与源文件同目录）")
    ap.add_argument("-r", "--recursive", action="store_true", help="递归处理子目录")
    ap.add_argument("--keys", default=None, help="extract_keys.py 导出的 keys.json 路径")
    ap.add_argument("--db", default=None, help="KGMusicV3.db 路径（v5/KGG 密钥库）")
    ap.add_argument("--mmkv", default=None, help="安卓概念版 mggkey_multi_process 路径")
    ap.add_argument("--delete-source", action="store_true",
                    help="解密成功且输出通过安全校验后，删除原加密文件（默认不删）")
    args = ap.parse_args()

    src = Path(args.input)
    if not src.exists():
        print(f"输入不存在: {src}")
        return 1

    key_provider = KeyProvider(args.keys, args.db, args.mmkv)

    if src.is_file():
        files = [src]
        default_out = src.parent
    else:
        pattern = "**/*" if args.recursive else "*"
        files = [p for p in src.glob(pattern)
                 if p.is_file() and real_suffix(p.name) in SUPPORTED_SUFFIXES]
        default_out = src
        if not files:
            print("目录下没有找到 .kgg/.kgm/.kgma/.kge/.vpr 文件")
            return 1

    out_dir = Path(args.output) if args.output else default_out

    ok = 0
    fail = 0
    for f in files:
        if process_file(f, out_dir, key_provider, args.delete_source):
            ok += 1
        else:
            fail += 1

    print(f"\n完成: 成功 {ok} 个, 失败 {fail} 个")
    if fail and not ok:
        print("提示: 若全部为 v5/KGG 文件，请先运行 extract_keys.py 从本机酷狗密钥库导出密钥。")
    return 0 if fail == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
