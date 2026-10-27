# -*- coding: utf-8 -*-
"""
extract_keys.py — 从本机酷狗客户端密钥库中提取 KGM v5 / KGG 解密所需的 ekey

为什么需要它：
  新版酷狗客户端下载的 .kgg（及部分 .kgm，即 KGM v5）使用「每首歌一个动态密钥」，
  密钥保存在本机酷狗的加密 SQLite 数据库 KGMusicV3.db（桌面端，
  通常位于 %APPDATA%\\KuGou8 或 %APPDATA%\\KuGou）
  或安卓酷狗概念版的 MMKV 文件 mggkey_multi_process 中。
  只有下载该歌曲的那台机器/账号的客户端里才有对应密钥。

本脚本做的事：
  1. 定位并解密 KGMusicV3.db（魔改 SQLCipher，逐页 AES-128-CBC）；
  2. 导出 audio_hash -> ekey 映射为 keys.json（供 decrypt_my_audio.py 使用）；
  3. 可选列出密钥库中的歌曲清单，方便核对你要解密的文件是否有对应密钥。

解密算法移植自 Aaron-gx/KGG-Decryptor（https://github.com/Aaron-gx/KGG-Decryptor）。

依赖：pip install pycryptodome

用法：
    python extract_keys.py                     # 自动查找 KGMusicV3.db，导出 keys.json
    python extract_keys.py --db D:\\path\\KGMusicV3.db
    python extract_keys.py --mmkv mggkey_multi_process
    python extract_keys.py --list              # 同时打印歌曲清单
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# 复用主脚本中的解密实现，避免重复维护两套代码
from decrypt_my_audio import (
    DecryptError,
    decrypt_database,
    extract_ekey_map_from_db,
    find_db_path,
    find_mmkv_path,
    parse_mmkv_ekey_map,
    query_song_list,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="从酷狗本机密钥库导出 ekey 到 keys.json")
    ap.add_argument("--db", default=None, help="KGMusicV3.db 路径（缺省自动查找）")
    ap.add_argument("--mmkv", default=None, help="安卓概念版 mggkey_multi_process 路径")
    ap.add_argument("-o", "--output", default="keys.json", help="输出文件（默认 keys.json）")
    ap.add_argument("--list", action="store_true", help="打印密钥库中的歌曲清单")
    args = ap.parse_args()

    keys: dict = {}

    # ---- 桌面端 KGMusicV3.db ----
    db = Path(args.db) if args.db else find_db_path()
    if db and db.is_file():
        print(f"[*] 找到密钥库: {db}")
        try:
            plain = decrypt_database(db.read_bytes())
            if plain == db.read_bytes() and not plain.startswith(b"SQLite format 3\x00"):
                print("    [警告] 数据库解密后仍不是 SQLite 格式，可能酷狗已更换加密方案")
            ekeys = extract_ekey_map_from_db(plain)
            keys.update(ekeys)
            print(f"    提取到 {len(ekeys)} 条 ekey")
            if args.list:
                print("\n    密钥库中的歌曲：")
                for s in query_song_list(plain):
                    print(f"      {s['artist']} - {s['song']}  [{s['audio_hash']}]  {s['file']}")
        except DecryptError as e:
            print(f"    失败: {e}")
    else:
        print("[*] 未自动找到 KGMusicV3.db（可用 --db 手动指定）")

    # ---- 安卓概念版 MMKV ----
    mmkv = Path(args.mmkv) if args.mmkv else find_mmkv_path()
    if mmkv and mmkv.is_file():
        print(f"[*] 找到 MMKV 密钥库: {mmkv}")
        mk = parse_mmkv_ekey_map(mmkv.read_bytes())
        # 不覆盖桌面端已有的键
        for k, v in mk.items():
            keys.setdefault(k, v)
        print(f"    提取到 {len(mk)} 条 ekey")
    elif args.mmkv:
        print(f"    找不到 MMKV 文件: {mmkv}")

    if not keys:
        print("\n未能提取到任何密钥。")
        print("排查建议：")
        print("  1. 确认本机安装过酷狗桌面客户端，且歌曲是用该客户端下载的；")
        print("  2. 用 --db 显式指定 KGMusicV3.db（常见位置：%APPDATA%\\KuGou8\\）；")
        print("  3. 安卓概念版用户需 root 后取出 mggkey_multi_process，用 --mmkv 指定。")
        return 1

    out = Path(args.output)
    out.write_text(json.dumps(keys, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n已导出 {len(keys)} 条 ekey -> {out.resolve()}")
    print("现在可以运行: python decrypt_my_audio.py <你的 .kgg/.kgm 文件> --keys", out.name)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:  # 防呆兜底
        print(f"未预期错误: {type(e).__name__}: {e}")
        sys.exit(1)
