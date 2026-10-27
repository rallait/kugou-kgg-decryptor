# kugou-kgg-decryptor

**把酷狗客户端加密的音频还原成普通 `.flac` / `.mp3`。纯本地、离线、不联网、不内置任何密钥。**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green)](LICENSE)
[![Deps](https://img.shields.io/badge/dependencies-1-brightgreen)](requirements.txt)
[![Tests](https://img.shields.io/badge/offline%20tests-24%20passed-brightgreen)](test_vectors.py)

---

## 我该走哪条路？

看文件的**后缀**就够了：

```
你的文件是 .kgg ？
├── 是  →  它是 v5 动态密钥，必须先从本机酷狗密钥库取钥匙
│          └─ 走【路线 B】：第 1 步 + 第 2 步
└── 否（.kgm / .kgma / .kge / .vpr）
       → 它是 v3 静态密钥，算法自带钥匙，直接解
          └─ 走【路线 A】：只做第 2 步
```

不确定的话，两个都跑一遍也没有副作用——脚本自己会根据文件头判断版本。

---

## 30 秒上手

### 第 0 步：装依赖（只装一次）

```bash
pip install -r requirements.txt
```

只有一个依赖 `pycryptodome`，不需要任何网络服务。

### 路线 A：`.kgm` / `.kgma` / `.kge` / `.vpr` 直接解

```bash
python decrypt_my_audio.py "D:\Music\某首歌.kgma"
```

解出来的文件就在**原文件旁边**，后缀自动改成 `.flac` 或 `.mp3`。

### 路线 B：`.kgg` 先取钥匙再解

```bash
# 1) 从本机酷狗数据库导出钥匙（每下载新歌后跑一次）
python extract_keys.py

# 2) 解密
python decrypt_my_audio.py "D:\Music\某首歌.kgg"
```

`extract_keys.py` 会自动找到 `%APPDATA%\KuGou8\KGMusicV3.db`，不需要你填路径。

---

## 跑起来长什么样

`extract_keys.py`：

```
[*] 找到密钥库: C:\Users\you\AppData\Roaming\KuGou8\KGMusicV3.db
    提取到 3 条 ekey

已导出 3 条 ekey -> D:\tools\keys.json
现在可以运行: python decrypt_my_audio.py <你的 .kgg/.kgm 文件> --keys keys.json
```

`decrypt_my_audio.py`：

```
[*] D:\Music\某首歌.kgg
    成功 -> 某首歌.flac  (30.90 MiB)

完成: 成功 1 个, 失败 0 个
```

失败时不会崩，会给一句人话原因，例如：

```
    失败: 密钥库中找不到该文件的 ekey（audio_hash=...）。
      可能原因：该歌曲不是用本机酷狗客户端下载的……
```

---

## 支持矩阵

| 后缀 | 加密版本 | 密钥来源 | 需要 `keys.json` |
|---|---|---|---|
| `.kgm` / `.kgma` / `.kge` / `.vpr` | KGM v3（静态） | 算法内置 | 否 |
| `.kgg` | KGM v5（动态） | 本机酷狗密钥库 | 是 |
| 新版客户端产出的 `.kgm` | 可能是 v5 | 同上 | 看文件头，脚本自动判断 |

> **v5 的密钥绑定下载它的机器和账号**，只存在于你自己电脑的酷狗数据库里。本工具不内置、不下载、不分发任何密钥——换台电脑就解不了，这是设计如此，不是 bug。

---

## 命令行参数

### decrypt_my_audio.py

| 参数 | 作用 |
|---|---|
| `<路径>` | 单个文件，或一个目录 |
| `-r` | 递归处理子目录 |
| `-o <目录>` | 输出到指定目录（默认与源文件同目录） |
| `--delete-source` | 解密成功并通过校验后删除原加密文件 |
| `--keys <文件>` | 指定 `keys.json`（默认找当前目录） |
| `--db <文件>` / `--mmkv <文件>` | 直接指定密钥库 |

```bash
# 批量：整个目录连子目录一起解，输出到别处
python decrypt_my_audio.py "D:\Music" -r -o "D:\Music\decrypted"

# 解完顺手删掉加密原件（有安全校验，见下）
python decrypt_my_audio.py "D:\Music" -r --delete-source
```

### extract_keys.py

| 参数 | 作用 |
|---|---|
| （无） | 自动查找数据库并导出 `keys.json` |
| `--list` | 顺便列出密钥库里的歌曲，用来核对有没有你要的那首 |
| `--db <文件>` | 手动指定 `KGMusicV3.db` |
| `--mmkv <文件>` | 安卓概念版 `mggkey_multi_process` |
| `-o <文件>` | 输出路径（默认 `keys.json`） |

### unlock_audio.py（Windows 拖放）

把 `.kgg` 文件或整个文件夹拖到桌面快捷方式上即可。缺密钥时会**自动先跑一次提取再重试**，全程不用开命令行。

---

## 常见问题

| 现象 | 原因 / 解决 |
|---|---|
| **「找不到该文件的 ekey」** | 这首不是本机酷狗下载的，或钥匙库过期。先在酷狗里完整播放/重新下载，再跑 `python extract_keys.py` |
| **「提取到 0 条 ekey」** | 密钥库被清空或路径不对。用 `--db` 手动指定；确认酷狗桌面端装过且下载过该歌 |
| **解出来能播但全是噪音** | 密钥不匹配。别硬解，重跑提取 |
| **「解密后的数据无法识别为音频」** | 同上，或遇到更新的加密方案。脚本会明确报错，不会产出垃圾文件 |
| **「原文件删除失败（可能被占用）」** | 文件正被酷狗或杀软占用。关掉后手动删即可，音频已经解好了 |
| **`.kgm` 提示 v5 / 要密钥** | 新版客户端的 `.kgm` 也可能是动态密钥。按路线 B 处理 |
| **Linux / macOS 能用吗** | 核心解密跨平台；只有自动查找数据库和拖放图标是 Windows 路径逻辑 |

---

## 安全：删除原件不是「解完就删」

`--delete-source` 必须四道校验全过才会调用 `Path.unlink()`：

1. 源文件确实是已知加密后缀；
2. 输出路径与源文件不是同一个文件；
3. 输出文件真实存在且大小 > 0；
4. 输出文件头部通过音频魔数校验（`fLaC` / `ID3` / `0xFFFx` / `OggS` / `RIFF`…）。

任何一步失败都打印「解密失败，已保留原文件」；删除本身也包了 `try/except OSError`，文件被占用时只提示、不崩。

---

## 测试

```bash
python test_vectors.py       # 24 项，约 0.7 秒，完全离线
```

覆盖内容：

- **黄金向量**：QMC 掩码表、StaticCipher / RC4 密钥流、`kugou_md5`；
- **交叉校验**：查表密钥流 vs 逐字节参考实现，含 `0x7FFF` 边界与百万级偏移；
- **官方样本**：`tests/vectors/kgm_v3_sample.kgm` 解出的明文与 `.expected` **逐字节一致**；
- **v5 全链路**：用本机真实 ekey 造合成 `.kgg`，走解析→查密钥→解密→比对；
- **回归**：删除校验、内存库解析、MMKV 解析。

依赖 `keys.json` 的用例在文件不存在时会自动 skip，clone 下来即可跑。

---

## 实现说明

算法全部移植自成熟开源项目，没有手写密码学：

| 项目 | 语言 / 协议 | 移植了什么 |
|---|---|---|
| [Aaron-gx/KGG-Decryptor](https://github.com/Aaron-gx/KGG-Decryptor) | Rust / MIT | 主要来源：KGM v3/v5、KGG、数据库页解密、MMKV |
| [skxxxkx666/Kugo-Music-Converter](https://github.com/skxxxkx666/Kugo-Music-Converter) | Go / GPL-3.0 | 姊妹项目，交叉参考 |
| unlock-music (um/cli) | TS | QMC 体系与格式的原始逆向思路 |

几个实现细节：

- KGM v3 利用 `T(x) = x ^ (x << 4)` 与 XOR 可交换的性质，把三段密钥流合并成一次大整数异或；
- QMC Map 掩码只由偏移决定、归一化后周期为 `0x7FFF`，因此预计算 32768 字节表后切片复用（实测比逐字节生成密钥流快约 **45 倍**）；
- `KGMusicV3.db` 是魔改 SQLCipher：1024 字节一页、逐页 AES-128-CBC；明文直接 `deserialize()` 进内存库，**不写临时文件**；
- 酷狗会定期清空 `ShareFileItems.EncryptionKey` 并把密钥回写到 `DownloadItem.EnKey`，所以两处都读。

### 已知限制

- v3 路径的 `b"\xf0" * n` 有一次与音频等长的内存峰值（几十 MB 级别，可接受）；
- 安卓概念版 MMKV 解析用启发式滑动扫描，格式一变可能失效（桌面端走 SQLite，不受影响）；
- 只覆盖槽位 1 的 v3 与 v5；遇到新方案会明确报错，不硬产出垃圾。

---

## 免责声明

仅供学习和**备份自己已购买/已下载的音乐**。请遵守酷狗用户协议与所在地版权法，不要传播解密后的文件。本项目不提供任何密钥，也不绕过账号权限。

同类项目 `unlock-music/cli` 曾因版权投诉被 GitHub DMCA 下架，使用与分发请自行评估风险。

## 许可证

[GPL-3.0](LICENSE)。移植来源中的 MIT 部分与 GPL-3.0 兼容。
