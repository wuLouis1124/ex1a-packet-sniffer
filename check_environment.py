"""检查实验所需的 Python、Qt 和 Npcap。"""

import ctypes
import os
from pathlib import Path
import sys


def main() -> int:
    failures = 0
    print("实验 1A：环境检查\n")

    if sys.version_info >= (3, 10):
        print(f"[通过] Python {sys.version.split()[0]}")
    else:
        print("[缺少] 需要 Python 3.10 或更新版本")
        failures += 1

    try:
        from PySide6 import QtCore, QtWidgets

        print(f"[通过] Qt 图形界面组件 {QtCore.qVersion()}")
    except (ImportError, OSError) as error:
        print(f"[缺少] Qt 图形界面组件：{error}")
        failures += 1

    if sys.platform != "win32":
        print("[提示] 此检查脚本针对本次 Windows 实验环境")
        return 1

    # Npcap 是系统组件，不随 Python 虚拟环境一起安装。
    system_dir = "System32" if ctypes.sizeof(ctypes.c_void_p) == 8 else "SysWOW64"
    npcap_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / system_dir / "Npcap"
    dll_path = npcap_dir / "wpcap.dll"
    if not dll_path.is_file():
        print("[缺少] Npcap：请从 https://npcap.com/#download 安装后重新检查")
        failures += 1
    else:
        try:
            # 显式指定目录，让 Windows 能找到 wpcap.dll 依赖的其他 DLL。
            with os.add_dll_directory(str(npcap_dir)):
                library = ctypes.CDLL(str(dll_path))
                library.pcap_lib_version.argtypes = []
                library.pcap_lib_version.restype = ctypes.c_char_p
                version = library.pcap_lib_version().decode("utf-8", errors="replace")
                print(f"[通过] {version}")
        except OSError as error:
            print(f"[异常] Npcap 已找到，但加载失败：{error}")
            failures += 1

    print()
    if failures:
        print("请根据上方提示修复依赖后再次运行环境检查。")
        return 1
    print("依赖检查通过。双击 sniffer_gui.bat 可启动嗅探器。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
