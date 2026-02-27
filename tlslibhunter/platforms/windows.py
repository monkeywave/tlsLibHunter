"""Windows platform handler."""

from __future__ import annotations

from tlslibhunter.platforms.base import PlatformHandler

SYSTEM_DIRS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\windows\\microsoft.net\\",
    "\\windows\\assembly\\",
    "\\windows\\systemapps\\",
    "\\windows\\servicing\\",
    "\\windows\\immersivecontrolpanel\\",
    "\\windows\\systemresources\\",
)

SYSTEM_DLLS = {
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "msvcrt.dll",
    "combase.dll",
    "rpcrt4.dll",
    "sechost.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "ucrtbase.dll",
    "msvcp_win.dll",
    "win32u.dll",
    "gdi32full.dll",
    "msctf.dll",
    "imm32.dll",
    "ws2_32.dll",
    "nsi.dll",
    "powrprof.dll",
    "umpdc.dll",
    "cryptbase.dll",
    "cfgmgr32.dll",
    "shlwapi.dll",
    "shcore.dll",
    "profapi.dll",
    "setupapi.dll",
    "clbcatq.dll",
    "wintrust.dll",
    "crypt32.dll",
    "msasn1.dll",
    "imagehlp.dll",
    "devobj.dll",
    "uxtheme.dll",
    "dwmapi.dll",
    "dxgi.dll",
    "d3d11.dll",
    "dwrite.dll",
    "dinput8.dll",
    "version.dll",
    "winhttp.dll",
    "wininet.dll",
    "urlmon.dll",
    "iertutil.dll",
    "dnsapi.dll",
    "iphlpapi.dll",
    "mswsock.dll",
    "secur32.dll",
    "sspicli.dll",
    "dbghelp.dll",
    "dbgcore.dll",
}


class WindowsHandler(PlatformHandler):
    def is_system_library(self, name: str, path: str) -> bool:
        name_lower = name.lower()
        path_lower = path.lower().replace("/", "\\")

        if name_lower in SYSTEM_DLLS:
            return True
        for sys_dir in SYSTEM_DIRS:
            if sys_dir in path_lower:
                return True
        if name_lower.startswith("vcruntime") or name_lower.startswith("msvcp"):
            return True
        return bool(name_lower.startswith("api-ms-win-") or name_lower.startswith("ext-ms-"))

    def get_extraction_order(self) -> list[str]:
        return ["disk_copy", "memory_dump"]
