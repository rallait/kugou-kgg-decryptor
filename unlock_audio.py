# -*- coding: utf-8 -*-
"""拖放解密入口：把 .kgg/.kgm/.kgma 文件或文件夹拖到这个脚本（的桌面图标）上即可解密。

功能：
1. 逐个处理拖进来的文件/文件夹（文件夹自动递归）；
2. 解密成功且输出通过严格安全校验后，自动删除原加密文件；
   （校验：输出真实存在、大小 > 0、通过音频魔数嗅探；任何一步不通过都保留原文件）
3. 有失败项时，自动跑 extract_keys.py 更新钥匙库后重试一次；
4. 结束后停留窗口，让用户看到结果，按回车关闭。
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DECRYPT = os.path.join(HERE, "decrypt_my_audio.py")
EXTRACT = os.path.join(HERE, "extract_keys.py")


def run(script, *args):
    """调用同目录下的脚本，返回退出码（0=全部成功）。"""
    return subprocess.run([sys.executable, script, *args], cwd=HERE).returncode


def decrypt_one(path):
    args = [path, "--delete-source"]
    if os.path.isdir(path):
        args.append("-r")  # 拖进来的是文件夹就递归处理
    return run(DECRYPT, *args)


def main():
    targets = sys.argv[1:]
    print("=" * 46)
    print("  酷狗加密音频 · 拖放解密（成功后自动删原件）")
    print("=" * 46)

    if not targets:
        print("\n用法：把 .kgg / .kgm / .kgma 文件（或整个文件夹）")
        print("直接用鼠标拖到这个图标上，松手即可。")
    else:
        # 第一遍：逐个解密，记下失败的
        failed = []
        for path in targets:
            print(f"\n>>> {os.path.basename(path)}")
            if decrypt_one(path) != 0:
                failed.append(path)

        # 第二遍：有失败就先自动补钥匙库，再重试
        if failed:
            print("\n[*] 有失败项，正在自动更新钥匙库后重试……")
            run(EXTRACT)
            still = []
            for path in failed:
                print(f"\n>>> 重试 {os.path.basename(path)}")
                if decrypt_one(path) != 0:
                    still.append(path)
            if still:
                print("\n[!] 以下文件仍然失败（原文件已全部保留）：")
                for p in still:
                    print("    -", p)
                print("    多半是这首歌不是本机酷狗下载的，本机保险柜里没有它的钥匙。")
            else:
                print("\n[*] 更新钥匙库后，全部解密成功！")

    print("\n完成。解出的音频在原文件旁边，原加密文件已在校验通过后删除。")
    input("\n按回车键关闭窗口……")


if __name__ == "__main__":
    main()
