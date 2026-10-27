# kugou-kgg-decryptor

把酷狗客户端加密过的音频还原成普通的 `.flac` / `.mp3` / `.ogg`。纯本地、离线、不联网。

支持格式：

| 后缀 | 加密版本 | 密钥来源 |
|---|---|---|
| `.kgm` / `.kgma` / `.kge` / `.vpr` | KGM v3（静态密钥） | 算法内置，直接解 |
| `.kgg`（含新版客户端产出的 `.kgm`） | KGM v5 动态密钥 | **必须**取自本机酷狗密钥库 |

> v5 是绑定账号/机器下载的，密钥只存在于**你自己电脑**的酷狗数据库里。本工具不内置、不下载、不分发任何密钥——没有本机密钥就解不了，这是设计如此。

## 安装

```bash
pip install -r requirements.txt
```

只需要 `pycryptodome` 一个依赖。

## 用法

### 1) 导出本机密钥（仅 v5 文件需要）

```bash
python extract_keys.py            # 自动查找 KGMusicV3.db，生成 keys.json
python extract_keys.py --list     # 顺便列出密钥库里登记了哪些歌
python extract_keys.py --db "D:\path\KGMusicV3.db"   # 手动指定数据库
```

### 2) 解密

```bash
# 单个文件
python decrypt_my_audio.py "D:\Music\某首歌.kgg"

# 整个目录（-r 递归子目录），输出到指定位置
python decrypt_my_audio.py "D:\Music" -r -o "D:\Music\decrypted"

# 解密成功后删除原加密文件（有四道校验，任一不过就保留原件）
python decrypt_my_audio.py "D:\Music" -r --delete-source
```

### 3) 拖放式（Windows 可选）

```powershell
python unlock_audio.py "文件或文件夹路径"
```

也可以把它做成桌面快捷方式，把 `.kgg` 文件直接拖到图标上。缺密钥时会自动先跑一次 `extract_keys.py` 再重试。

## 删除原件的安全校验

`--delete-source` 不是"解完就删"，必须四道全过才会调用 `Path.unlink()`：

1. 源文件确实是已知加密后缀；
2. 输出路径与源文件不是同一个文件；
3. 输出文件真实存在且大小 > 0；
4. 输出文件头部通过音频魔数校验（`fLaC` / `ID3` / `0xFFFx` / `OggS` / `RIFF` …）。

任何一步失败都会打印「解密失败，已保留原文件」，删除本身也包了 `try/except OSError`（文件被占用时只提示，不崩）。

## 测试

```bash
python test_vectors.py
```

24 个用例，离线可跑（约 0.7 秒），包括：

- 黄金向量：QMC 掩码表、StaticCipher / RC4 密钥流、`kugou_md5`；
- 交叉校验：查表密钥流 vs 逐字节参考实现，覆盖 `0x7FFF` 边界与百万级偏移；
- 官方样本：`tests/vectors/kgm_v3_sample.kgm` 解出的明文与 `.expected` 逐字节一致；
- v5 全链路：用本机真实 ekey 造合成 `.kgg`，走完整解析→查密钥→解密→比对；
- 删除逻辑、内存库解析、MMKV 解析的回归用例。

依赖 `keys.json` 的用例在文件不存在时会自动 skip，所以别人 clone 下来也能跑。

## 实现说明

算法全部移植自成熟开源项目，没有手写密码学：

- [Aaron-gx/KGG-Decryptor](https://github.com/Aaron-gx/KGG-Decryptor)（Rust/Tauri，MIT）—— 主要移植来源，KGM v3/v5、KGG、数据库页面解密、MMKV 解析；
- [skxxxkx666/Kugo-Music-Converter](https://github.com/skxxxkx666/Kugo-Music-Converter)（Go/Wails，GPL-3.0）—— 姊妹项目，交叉参考；
- unlock-music（um/cli）—— 底层格式与 QMC 体系的原始逆向思路。

几个实现细节：

- KGM v3 利用 `T(x)=x^(x<<4)` 与 XOR 可交换的性质，把三段密钥流合并成一次大整数异或；
- QMC Map 掩码只由偏移决定、归一化后周期为 `0x7FFF`，因此预计算 32768 字节表，解密时切片复用（实测比逐字节生成密钥流快约 45 倍）；
- `KGMusicV3.db` 是魔改 SQLCipher：1024 字节一页、逐页 AES-128-CBC，解出的明文直接 `deserialize()` 进内存库，不写临时文件；
- 实测酷狗会定期清空 `ShareFileItems.EncryptionKey` 并把密钥回写到 `DownloadItem.EnKey`，所以两处都读。

已知限制：

- MapCipher 表构建有一份 32 KB 的常驻开销（可忽略）；v3 路径的 `b"\xf0" * n` 会有一次与音频等长的内存峰值；
- 安卓概念版 MMKV 解析用的是启发式滑动扫描，格式一变可能失效（桌面端走 SQLite，不受影响）；
- 只覆盖槽位 1 的 v3 与 v5；遇到新版本加密会明确报错而不是产出垃圾文件。

## 免责声明

仅供学习和个人备份自己已购买/已下载的音乐使用。请遵守酷狗的用户协议与所在地版权法，不要传播解密后的文件。本项目不提供任何密钥，也不绕过账号权限。

同类项目 `unlock-music/cli` 曾因版权投诉被 GitHub DMCA 下架，使用与分发请自行评估风险。

## 许可证

GPL-3.0。移植来源中的 MIT 部分与 GPL-3.0 兼容。
