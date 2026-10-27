# -*- coding: utf-8 -*-
"""test_vectors.py — 算法回归测试（离线可跑，不需要网络）

为什么要这个文件
----------------
之前只用"真实文件能解出来"做过一次性验证，改动代码后无法确认没有退化。
这里把三类证据固化下来：

1. 黄金向量：掩码表、密钥流、kugou_md5 等函数的期望值逐字节写死，
   任何改动只要动了算法都会立刻报警；
2. 交叉校验：把"预计算表"的密钥流和"逐字节参考实现"逐偏移对比，
   这条专治 MapCipher 改成查表后可能出现的周期映射错误；
3. 官方样本：tests/vectors/kgm_v3_sample.kgm 是开源项目的公开测试样本，
   解出来的明文必须与 kgm_v3_sample.expected 逐字节一致。

黄金值的来源：本实现在真实 .kgg/.kgma 上端到端解出可播放 FLAC，
且 v3 与官方样本逐字节一致，因此把它当前的输出冻结为回归基准。
注意这些值只能防退化，不能证明算法本身正确——后者靠第 3 条和真实文件。

运行
----
    python test_vectors.py
    python test_vectors.py -v
"""

import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import decrypt_my_audio as D  # noqa: E402

VECTORS = HERE / "tests" / "vectors"


def _ref_mask(key: bytes, offset: int) -> int:
    """逐字节参考实现（旧写法），用来交叉校验查表版密钥流。"""
    v = offset % 0x7FFF if offset > 0x7FFF else offset
    idx = (v * v + 71214) % len(key)
    x = key[idx]
    r = ((idx & 0x7) + 4) % 8
    return ((x << r) | (x >> r)) & 0xFF if r else x


class TestKugouMd5(unittest.TestCase):
    def test_slot_seed_golden(self):
        # 槽位 1 的静态密钥，v3 解密全靠它
        self.assertEqual(
            D.kugou_md5(bytes([0x6C, 0x2C, 0x2F, 0x27])).hex(),
            "14e310b10d3b6f41856b79278bfd6185",
        )


class TestMapCipher(unittest.TestCase):
    KEY = bytes(range(256))

    def setUp(self):
        self.c = D.MapCipher(self.KEY)

    def test_head_table_golden(self):
        self.assertEqual(self.c._head[:24].hex(),
                         "bb7d80beff3881fbbbff823cffba8379bb7981baff3c80ff")
        self.assertEqual(self.c._head[-8:].hex(), "bbfb8138ffbe807d")

    def test_cycle_golden(self):
        self.assertEqual(self.c._cycle[:16].hex(), "7d80beff3881fbbbff823cffba8379bb")

    def test_keystream_边界(self):
        # 0x7FFF 是"原样保留"的特殊值，0x8000 起才进入 32767 周期
        self.assertEqual(self.c._keystream(0x7FFE, 8).hex(), "807d7d80beff3881")
        self.assertEqual(self.c._keystream(0x8000, 32).hex(),
                         "7d80beff3881fbbbff823cffba8379bb7981baff3c80ffbbfb8338ffbe827dbb")
        self.assertEqual(self.c._keystream(0x8000 + 0x7FFE, 16).hex(),
                         "bb7d80beff3881fbbbff823cffba8379")

    def test_查表与逐字节实现等价(self):
        offsets = list(range(0, 0x400)) + [
            0x7FFE, 0x7FFF, 0x8000, 0x8001, 0xFFFF, 0x10000,
            0x7FFF * 2, 0x7FFF * 3 + 1, 0x123456, 0x1000000,
        ]
        for off in offsets:
            for n in (1, 7, 64, 4096):
                self.assertEqual(
                    self.c._keystream(off, n),
                    bytes(_ref_mask(self.KEY, off + i) for i in range(n)),
                    f"offset={off} n={n}",
                )

    def test_decrypt_是对合(self):
        buf = bytearray(hashlib.sha256(b"seed").digest() * 200)
        origin = bytes(buf)
        self.c.decrypt(buf, 0)
        self.assertNotEqual(bytes(buf), origin)
        self.c.decrypt(buf, 0)
        self.assertEqual(bytes(buf), origin)

    def test_分段解密等价整段(self):
        data = bytes(range(256)) * 400
        whole = bytearray(data)
        self.c.decrypt(whole, 0)
        piece = bytearray(data)
        for start in range(0, len(piece), 7777):
            view = piece[start:start + 7777]  # 切片是副本，解完要写回
            self.c.decrypt(view, start)
            piece[start:start + 7777] = view
        self.assertEqual(bytes(piece), bytes(whole))


class TestStaticCipher(unittest.TestCase):
    def test_keystream_golden(self):
        box = D.StaticCipher.BOX
        ks = bytes(box[((at % 0x7FFF) if at > 0x7FFF else at) ** 2 + 27 & 0xFF] for at in range(32))
        self.assertEqual(ks.hex(), "c34ad6ca9067f752d8a166629f5b0900c35e95239f13117ed8923fbc90bb740e")

    def test_对合(self):
        c = D.StaticCipher()
        buf = bytearray(bytes(range(128)) * 40)
        origin = bytes(buf)
        c.decrypt(buf, 0)
        c.decrypt(buf, 0)
        self.assertEqual(bytes(buf), origin)


class TestRc4Cipher(unittest.TestCase):
    @staticmethod
    def _key() -> bytes:
        return bytes((i * 7 + 3) & 0xFF for i in range(301))

    def test_keystream_golden(self):
        c = D.Rc4Cipher(self._key())
        buf = bytearray(64)
        c.decrypt(buf, 0)
        self.assertEqual(bytes(buf).hex(), (
            "645e990d6387a2211c3a1f37bd6cb9b8e525ff5c73172c6ac6c3eb4af8cda47d"
            "62eb7a99948740930d11333a89b27d5e5ea36793c33dfa586c06444b5e49ce47"))

    def test_对合与大偏移(self):
        c = D.Rc4Cipher(self._key())
        buf = bytearray(bytes(range(256)) * 60)
        origin = bytes(buf)
        c.decrypt(buf, 0x41234)
        c.decrypt(buf, 0x41234)
        self.assertEqual(bytes(buf), origin)


class TestDeriveKey(unittest.TestCase):
    """ekey -> 256 字节流密钥的整条链（base64 + 腾讯 TEA v1/v2）。

    用本机 keys.json 里的任意一条真实 ekey 跑，只断言长度、稳定性和密码器类型，
    不把任何密钥或哈希写进代码，避免仓库里留下使用者个人信息。
    """

    def test_真实ekey派生结果稳定(self):
        keys_path = HERE / "keys.json"
        if not keys_path.is_file():
            self.skipTest("没有 keys.json，跳过（该用例依赖本机密钥库）")
        with open(keys_path, "r", encoding="utf-8") as f:
            keys = json.load(f)
        if not keys:
            self.skipTest("keys.json 为空")
        ekey = next(iter(keys.values()))
        first = D.derive_key(ekey)
        self.assertEqual(len(first), 256)
        self.assertEqual(D.derive_key(ekey), first)  # 派生必须确定性
        self.assertIsInstance(D.make_qmc_cipher(first), D.MapCipher)


class TestKgmV3官方样本(unittest.TestCase):
    def test_逐字节一致(self):
        sample = VECTORS / "kgm_v3_sample.kgm"
        expected = VECTORS / "kgm_v3_sample.expected"
        if not sample.is_file() or not expected.is_file():
            self.skipTest("缺少官方测试样本 tests/vectors/")
        raw = sample.read_bytes()
        audio_offset, version, slot, audio_hash = D.parse_kgm_header(raw)
        self.assertEqual((version, slot, audio_hash), (3, 1, None))
        audio = bytearray(raw[audio_offset:])
        D.kgm_v3_decrypt(raw, audio)
        self.assertEqual(bytes(audio), expected.read_bytes())
        self.assertEqual(D.sniff_ext(audio), "mp3")


class TestV5全链路(unittest.TestCase):
    """用本机真实 ekey 造一个合成 .kgg，走完整解析->查密钥->解密流程再比对。"""

    def test_合成kgg回环(self):
        keys_path = HERE / "keys.json"
        if not keys_path.is_file():
            self.skipTest("没有 keys.json")
        with open(keys_path, "r", encoding="utf-8") as f:
            keys = json.load(f)
        audio_hash, ekey = next(iter(keys.items()))
        plain = (VECTORS / "kgm_v3_sample.expected").read_bytes()

        enc = bytearray(plain)
        D.make_qmc_cipher(D.derive_key(ekey)).decrypt(enc, 0)  # XOR 对合，解密函数即加密
        h = audio_hash.encode()
        off = 0x48 + len(h)
        hdr = bytearray(off)
        hdr[0:16] = D.KGM_MAGIC
        hdr[0x10:0x14] = off.to_bytes(4, "little")
        hdr[0x14:0x18] = (5).to_bytes(4, "little")
        hdr[0x18:0x1C] = (1).to_bytes(4, "little")
        hdr[0x44:0x48] = len(h).to_bytes(4, "little")
        hdr[0x48:off] = h

        kp = D.KeyProvider(str(keys_path), str(HERE / "__none__.db"), str(HERE / "__none__.mmkv"))
        out, fmt = D.decrypt_bytes(bytes(hdr) + bytes(enc), "roundtrip.kgg", kp)
        self.assertEqual(out, plain)
        self.assertEqual(fmt, "mp3")


class TestSniff(unittest.TestCase):
    def test_常见音频魔数(self):
        self.assertEqual(D.sniff_ext(b"fLaC\x00\x00\x00\x22"), "flac")
        self.assertEqual(D.sniff_ext(b"ID3\x04\x00"), "mp3")
        self.assertEqual(D.sniff_ext(b"\xff\xfb\x90\x00"), "mp3")
        self.assertEqual(D.sniff_ext(b"OggS\x00\x02"), "ogg")
        self.assertEqual(D.sniff_ext(b"RIFF\x00\x00\x00\x00WAVE"), "wav")
        self.assertEqual(D.sniff_ext(b"\x00\x00\x00\x20ftypM4A "), "m4a")
        self.assertEqual(D.sniff_ext(b"\xde\xad\xbe\xef" * 4), "bin")


class TestMmkv(unittest.TestCase):
    @staticmethod
    def _varint(v: int) -> bytes:
        out = bytearray()
        while True:
            b = v & 0x7F
            v >>= 7
            out.append(b | (0x80 if v else 0))
            if not v:
                return bytes(out)

    def test_解析条目(self):
        h = "0123456789abcdef0123456789abcdef"
        ekey = "QQMusic EncV2,Key:" + "Z" * 40
        body = h.encode() + self._varint(len(ekey)) + self._varint(len(ekey)) + ekey.encode()
        blob = b"\x00" * 16 + body + b"\x11" * 8
        self.assertEqual(D.parse_mmkv_ekey_map(blob), {h: ekey})


class TestDatabaseInMemory(unittest.TestCase):
    """明文数据库直接反序列化进内存，不落临时文件。"""

    def _build(self) -> bytes:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE ShareFileItems (id INTEGER PRIMARY KEY, FileNamePure TEXT, "
            "SongName TEXT, Artist TEXT, EncryptionKeyId TEXT, EncryptionKey TEXT)"
        )
        conn.execute("INSERT INTO ShareFileItems (FileNamePure,SongName,Artist,"
                     "EncryptionKeyId,EncryptionKey) VALUES ('a.kgg','歌','人','h1','ekey-1')")
        conn.execute("INSERT INTO ShareFileItems (FileNamePure,SongName,Artist,"
                     "EncryptionKeyId,EncryptionKey) VALUES ('b.kgg','歌2','人2','h2','')")
        # 酷狗会把 ShareFileItems 的密钥清空并回写到 DownloadItem.EnKey
        conn.execute(
            "CREATE TABLE DownloadItem (ID INTEGER PRIMARY KEY, FileName TEXT, SongName TEXT, "
            "Artist TEXT, EnHash TEXT, EnKey TEXT)"
        )
        conn.execute("INSERT INTO DownloadItem (FileName,SongName,Artist,EnHash,EnKey) "
                     "VALUES ('c.kgg','歌3','人3','h3','ekey-3')")
        conn.execute("INSERT INTO DownloadItem (FileName,SongName,Artist,EnHash,EnKey) "
                     "VALUES ('d.kgg','歌4','人4','00000000000000000000000000000000','')")
        blob = conn.serialize()
        conn.close()
        return blob

    def test_extract_ekey_map(self):
        self.assertEqual(D.extract_ekey_map_from_db(self._build()),
                         {"h1": "ekey-1", "h3": "ekey-3"})

    def test_query_song_list(self):
        rows = D.query_song_list(self._build())
        self.assertEqual(len(rows), 2)
        self.assertEqual((rows[0]["file"], rows[0]["song"], rows[0]["audio_hash"]),
                         ("a.kgg", "歌", "h1"))
        self.assertEqual(rows[1]["audio_hash"], "h3")

    def test_坏数据给出可预期错误(self):
        with self.assertRaises(D.DecryptError):
            D.extract_ekey_map_from_db(b"not a database at all" * 100)


class TestDeleteSource(unittest.TestCase):
    """删除原文件前的四道校验：任何一道不过都必须保留。"""

    def test_校验通过才删除(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "a.kgg"
            src.write_bytes(b"encrypted")
            out = Path(td) / "a.flac"
            out.write_bytes(b"fLaC" + b"\x00" * 64)
            self.assertTrue(D.delete_source_after_verify(src, out))
            self.assertFalse(src.exists())

    def test_输出为空时保留(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "b.kgg"
            src.write_bytes(b"encrypted")
            out = Path(td) / "b.flac"
            out.write_bytes(b"")
            self.assertFalse(D.delete_source_after_verify(src, out))
            self.assertTrue(src.exists())

    def test_输出不存在时保留(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "c.kgg"
            src.write_bytes(b"encrypted")
            self.assertFalse(D.delete_source_after_verify(src, Path(td) / "c.flac"))
            self.assertTrue(src.exists())

    def test_魔数不对时保留(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "d.kgg"
            src.write_bytes(b"encrypted")
            out = Path(td) / "d.flac"
            out.write_bytes(b"\x00" * 128)
            self.assertFalse(D.delete_source_after_verify(src, out))
            self.assertTrue(src.exists())

    def test_源后缀不是加密格式时保留(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "e.txt"
            src.write_bytes(b"encrypted")
            out = Path(td) / "e.flac"
            out.write_bytes(b"fLaC" + b"\x00" * 64)
            self.assertFalse(D.delete_source_after_verify(src, out))
            self.assertTrue(src.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
