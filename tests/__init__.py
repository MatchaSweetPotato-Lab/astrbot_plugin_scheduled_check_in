"""Test package for astrbot_plugin_scheduled_check_in."""

import platform

if platform.system() == "Darwin":
    import ctypes

    try:
        ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    except Exception:
        pass
