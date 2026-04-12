/*
 * Process Injection YARA Rules
 * 检测 Windows 进程注入技术
 *
 * ATT&CK 映射:
 *   - T1055: Process Injection
 *   - T1055.001: DLL Injection
 *   - T1055.002: PE Injection
 *   - T1055.003: Thread Execution Hijacking
 *   - T1055.004: APC Injection
 *   - T1055.012: Process Hollowing
 *
 * 用法:
 *   yara -r process_injection.yar <target>
 */

import "pe"

// ============================================================================
// Process Hollowing (T1055.012)
// ============================================================================

rule Process_Hollowing_APIs {
    meta:
        description = "Detects Process Hollowing via API pattern"
        author = "CyberSec Skills"
        severity = "critical"
        technique = "T1055.012"

    strings:
        // 核心 API 序列
        $api1 = "CreateProcessW" ascii wide
        $api2 = "CreateProcessA" ascii wide
        $api3 = "NtUnmapViewOfSection" ascii wide
        $api4 = "ZwUnmapViewOfSection" ascii wide
        $api5 = "VirtualAllocEx" ascii wide
        $api6 = "WriteProcessMemory" ascii wide
        $api7 = "SetThreadContext" ascii wide
        $api8 = "GetThreadContext" ascii wide
        $api9 = "ResumeThread" ascii wide
        $api10 = "NtResumeThread" ascii wide

        // CREATE_SUSPENDED 标志
        $flag = { 04 00 00 00 }  // CREATE_SUSPENDED = 0x4

    condition:
        pe.is_pe and
        (($api1 or $api2) and ($api3 or $api4) and $api5 and $api6 and ($api7 or $api8) and ($api9 or $api10))
}

rule Process_Hollowing_Strings {
    meta:
        description = "Detects Process Hollowing via string patterns"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1055.012"

    strings:
        // 常见被替换的进程
        $target1 = "svchost.exe" ascii wide nocase
        $target2 = "explorer.exe" ascii wide nocase
        $target3 = "RuntimeBroker.exe" ascii wide nocase
        $target4 = "dllhost.exe" ascii wide nocase
        $target5 = "wermgr.exe" ascii wide nocase
        $target6 = "msiexec.exe" ascii wide nocase

        // API 字符串
        $api1 = "NtUnmapViewOfSection" ascii
        $api2 = "ZwUnmapViewOfSection" ascii
        $api3 = "SetThreadContext" ascii

    condition:
        pe.is_pe and
        any of ($target*) and any of ($api*)
}

// ============================================================================
// Classic DLL Injection (T1055.001)
// ============================================================================

rule DLL_Injection_Classic {
    meta:
        description = "Detects Classic DLL Injection technique"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1055.001"

    strings:
        $api1 = "OpenProcess" ascii wide
        $api2 = "VirtualAllocEx" ascii wide
        $api3 = "WriteProcessMemory" ascii wide
        $api4 = "CreateRemoteThread" ascii wide
        $api5 = "LoadLibraryA" ascii wide
        $api6 = "LoadLibraryW" ascii wide
        $api7 = "GetProcAddress" ascii wide
        $api8 = "GetModuleHandleA" ascii wide

    condition:
        pe.is_pe and
        $api1 and $api2 and $api3 and $api4 and ($api5 or $api6)
}

rule DLL_Injection_NtCreateThreadEx {
    meta:
        description = "Detects DLL Injection via NtCreateThreadEx"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1055.001"

    strings:
        $api1 = "NtCreateThreadEx" ascii wide
        $api2 = "RtlCreateUserThread" ascii wide
        $api3 = "VirtualAllocEx" ascii wide
        $api4 = "WriteProcessMemory" ascii wide
        $api5 = "LoadLibrary" ascii wide

    condition:
        pe.is_pe and
        ($api1 or $api2) and $api3 and $api4 and $api5
}

// ============================================================================
// APC Injection (T1055.004)
// ============================================================================

rule APC_Injection {
    meta:
        description = "Detects APC Injection technique"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1055.004"

    strings:
        $api1 = "QueueUserAPC" ascii wide
        $api2 = "NtQueueApcThread" ascii wide
        $api3 = "NtQueueApcThreadEx" ascii wide
        $api4 = "VirtualAllocEx" ascii wide
        $api5 = "WriteProcessMemory" ascii wide
        $api6 = "OpenThread" ascii wide

        // 早期 bird APC
        $api7 = "NtTestAlert" ascii wide
        $api8 = "ZwTestAlert" ascii wide

    condition:
        pe.is_pe and
        ($api1 or $api2 or $api3) and $api4 and $api5
}

rule Early_Bird_APC {
    meta:
        description = "Detects Early Bird APC Injection"
        author = "CyberSec Skills"
        severity = "critical"
        technique = "T1055.004"

    strings:
        $api1 = "CreateProcessW" ascii wide
        $api2 = "CreateProcessA" ascii wide
        $api3 = "VirtualAllocEx" ascii wide
        $api4 = "WriteProcessMemory" ascii wide
        $api5 = "QueueUserAPC" ascii wide
        $api6 = "NtQueueApcThread" ascii wide
        $api7 = "ResumeThread" ascii wide

        // CREATE_SUSPENDED
        $flag = { 04 00 00 00 }

    condition:
        pe.is_pe and
        ($api1 or $api2) and $api3 and $api4 and ($api5 or $api6) and $api7
}

// ============================================================================
// Thread Hijacking (T1055.003)
// ============================================================================

rule Thread_Hijacking {
    meta:
        description = "Detects Thread Execution Hijacking"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1055.003"

    strings:
        $api1 = "SuspendThread" ascii wide
        $api2 = "GetThreadContext" ascii wide
        $api3 = "SetThreadContext" ascii wide
        $api4 = "ResumeThread" ascii wide
        $api5 = "VirtualAllocEx" ascii wide
        $api6 = "WriteProcessMemory" ascii wide
        $api7 = "OpenThread" ascii wide

    condition:
        pe.is_pe and
        $api1 and $api2 and $api3 and $api4 and ($api5 or $api6)
}

// ============================================================================
// Shellcode/PE Injection (T1055.002)
// ============================================================================

rule PE_Injection {
    meta:
        description = "Detects PE Injection technique"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1055.002"

    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtCreateThreadEx" ascii wide

        // PE 操作
        $pe1 = "ImageNtHeaders" ascii wide
        $pe2 = "IMAGE_DOS_HEADER" ascii
        $pe3 = "IMAGE_NT_HEADERS" ascii
        $pe4 = { 4D 5A }  // MZ header

        // 重定位
        $reloc1 = "IMAGE_BASE_RELOCATION" ascii
        $reloc2 = ".reloc" ascii

    condition:
        pe.is_pe and
        $api1 and $api2 and ($api3 or $api4) and any of ($pe*) and any of ($reloc*)
}

rule Shellcode_Injection {
    meta:
        description = "Detects generic shellcode injection"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1055"

    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide

        // PAGE_EXECUTE_READWRITE = 0x40
        $rwx = { 40 00 00 00 }

        // MEM_COMMIT | MEM_RESERVE = 0x3000
        $alloc = { 00 30 00 00 }

    condition:
        pe.is_pe and
        $api1 and $api2 and $api3 and ($rwx or $alloc)
}

// ============================================================================
// Atom Bombing
// ============================================================================

rule Atom_Bombing {
    meta:
        description = "Detects AtomBombing injection technique"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1055"

    strings:
        $api1 = "GlobalAddAtomA" ascii wide
        $api2 = "GlobalAddAtomW" ascii wide
        $api3 = "GlobalGetAtomNameA" ascii wide
        $api4 = "GlobalGetAtomNameW" ascii wide
        $api5 = "NtQueueApcThread" ascii wide
        $api6 = "QueueUserAPC" ascii wide
        $api7 = "ntdll.dll" ascii wide nocase
        $api8 = "RtlDispatchAPC" ascii wide

    condition:
        pe.is_pe and
        ($api1 or $api2) and ($api3 or $api4) and ($api5 or $api6)
}

// ============================================================================
// Module Stomping / DLL Hollowing
// ============================================================================

rule Module_Stomping {
    meta:
        description = "Detects Module Stomping / DLL Hollowing"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1055"

    strings:
        $api1 = "LoadLibraryExW" ascii wide
        $api2 = "LoadLibraryExA" ascii wide
        $api3 = "VirtualProtect" ascii wide
        $api4 = "VirtualProtectEx" ascii wide
        $api5 = "WriteProcessMemory" ascii wide
        $api6 = "memcpy" ascii wide

        // DONT_RESOLVE_DLL_REFERENCES = 0x1
        $flag = "DONT_RESOLVE_DLL_REFERENCES" ascii

    condition:
        pe.is_pe and
        ($api1 or $api2) and ($api3 or $api4) and $api5
}

// ============================================================================
// NTDLL Unhooking (Evasion)
// ============================================================================

rule NTDLL_Unhooking {
    meta:
        description = "Detects NTDLL unhooking for EDR evasion"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1562.001"

    strings:
        $api1 = "NtProtectVirtualMemory" ascii wide
        $api2 = "NtWriteVirtualMemory" ascii wide
        $api3 = "NtReadVirtualMemory" ascii wide
        $api4 = "LdrGetDllHandle" ascii wide

        $str1 = "ntdll.dll" ascii wide nocase
        $str2 = "\\KnownDlls\\ntdll.dll" ascii wide
        $str3 = "\\SystemRoot\\System32\\ntdll.dll" ascii wide

        // 从磁盘读取 ntdll
        $file1 = "CreateFileW" ascii wide
        $file2 = "ReadFile" ascii wide
        $file3 = "MapViewOfFile" ascii wide

    condition:
        pe.is_pe and
        any of ($str*) and (any of ($api*) or (($file1 or $file3) and $file2))
}

// ============================================================================
// Syscall Evasion
// ============================================================================

rule Direct_Syscall {
    meta:
        description = "Detects direct syscall usage for EDR evasion"
        author = "CyberSec Skills"
        severity = "medium"
        technique = "T1106"

    strings:
        // x64 syscall
        $syscall64 = { 0F 05 }  // syscall
        $sysenter = { 0F 34 }   // sysenter (x86)

        // syscall stub patterns
        $stub1 = { 4C 8B D1 B8 ?? ?? 00 00 }  // mov r10, rcx; mov eax, syscall_num
        $stub2 = { B8 ?? ?? 00 00 0F 05 }      // mov eax, num; syscall

        // Nt* function strings
        $nt1 = "NtAllocateVirtualMemory" ascii
        $nt2 = "NtWriteVirtualMemory" ascii
        $nt3 = "NtCreateThreadEx" ascii
        $nt4 = "NtProtectVirtualMemory" ascii

    condition:
        pe.is_pe and
        ($syscall64 or $sysenter) and any of ($stub*) and any of ($nt*)
}

// ============================================================================
// Process Doppelgänging (T1055.013)
// ============================================================================

rule Process_Doppelganging {
    meta:
        description = "Detects Process Doppelgänging technique"
        author = "CyberSec Skills"
        severity = "critical"
        technique = "T1055.013"

    strings:
        $api1 = "NtCreateTransaction" ascii wide
        $api2 = "NtCreateSection" ascii wide
        $api3 = "NtRollbackTransaction" ascii wide
        $api4 = "NtCreateProcessEx" ascii wide
        $api5 = "RtlCreateProcessParametersEx" ascii wide
        $api6 = "NtCreateThreadEx" ascii wide

    condition:
        pe.is_pe and
        $api1 and $api2 and $api3 and ($api4 or $api5 or $api6)
}

// ============================================================================
// Process Herpaderping
// ============================================================================

rule Process_Herpaderping {
    meta:
        description = "Detects Process Herpaderping technique"
        author = "CyberSec Skills"
        severity = "critical"
        technique = "T1055"

    strings:
        $api1 = "NtCreateSection" ascii wide
        $api2 = "NtCreateProcessEx" ascii wide
        $api3 = "NtCreateThreadEx" ascii wide
        $api4 = "SetFileInformationByHandle" ascii wide
        $api5 = "NtSetInformationFile" ascii wide

        // 修改文件内容
        $file1 = "WriteFile" ascii wide
        $file2 = "FlushFileBuffers" ascii wide

    condition:
        pe.is_pe and
        $api1 and $api2 and $api3 and ($api4 or $api5) and ($file1 or $file2)
}

// ============================================================================
// Callback Injection
// ============================================================================

rule Callback_Injection {
    meta:
        description = "Detects callback-based code injection"
        author = "CyberSec Skills"
        severity = "medium"
        technique = "T1055"

    strings:
        // 回调函数 API
        $cb1 = "EnumWindows" ascii wide
        $cb2 = "EnumChildWindows" ascii wide
        $cb3 = "EnumDesktopWindows" ascii wide
        $cb4 = "EnumDateFormatsA" ascii wide
        $cb5 = "EnumSystemLocalesA" ascii wide
        $cb6 = "SetTimer" ascii wide
        $cb7 = "CreateTimerQueueTimer" ascii wide
        $cb8 = "EnumResourceTypesA" ascii wide
        $cb9 = "EnumResourceNamesA" ascii wide
        $cb10 = "CertEnumSystemStore" ascii wide

        // 内存操作
        $mem1 = "VirtualAlloc" ascii wide
        $mem2 = "VirtualProtect" ascii wide
        $mem3 = "HeapAlloc" ascii wide

    condition:
        pe.is_pe and
        2 of ($cb*) and any of ($mem*)
}

// ============================================================================
// Extra Window Memory Injection
// ============================================================================

rule Extra_Window_Memory_Injection {
    meta:
        description = "Detects Extra Window Memory (EWM) Injection"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1055"

    strings:
        $api1 = "SetWindowLongPtrA" ascii wide
        $api2 = "SetWindowLongPtrW" ascii wide
        $api3 = "SetWindowLongA" ascii wide
        $api4 = "SetWindowLongW" ascii wide
        $api5 = "FindWindowA" ascii wide
        $api6 = "FindWindowW" ascii wide
        $api7 = "SendMessageA" ascii wide
        $api8 = "SendMessageW" ascii wide
        $api9 = "SendNotifyMessageA" ascii wide
        $api10 = "SendNotifyMessageW" ascii wide

        // Shell_TrayWnd 是常见目标
        $target = "Shell_TrayWnd" ascii wide

    condition:
        pe.is_pe and
        any of ($api1, $api2, $api3, $api4) and any of ($api5, $api6) and any of ($api7, $api8, $api9, $api10)
}

// ============================================================================
// WOW64 Injection
// ============================================================================

rule WOW64_Heaven_Gate {
    meta:
        description = "Detects Heaven's Gate technique (WOW64 abuse)"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1055"

    strings:
        // Heaven's Gate far jump
        $gate1 = { EA ?? ?? ?? ?? 33 00 }  // jmp far 0x33:address (x86->x64)
        $gate2 = { 6A 33 E8 }              // push 0x33; call
        $gate3 = { 9A ?? ?? ?? ?? 33 00 }  // call far 0x33:address

        // WOW64 相关
        $wow1 = "Wow64DisableWow64FsRedirection" ascii wide
        $wow2 = "Wow64RevertWow64FsRedirection" ascii wide
        $wow3 = "IsWow64Process" ascii wide
        $wow4 = "Wow64GetThreadContext" ascii wide
        $wow5 = "Wow64SetThreadContext" ascii wide

    condition:
        pe.is_pe and
        (any of ($gate*) or (2 of ($wow*)))
}

// ============================================================================
// Generic Suspicious Combinations
// ============================================================================

rule Suspicious_Injection_Combo {
    meta:
        description = "Detects suspicious combination of injection-related APIs"
        author = "CyberSec Skills"
        severity = "medium"
        technique = "T1055"

    strings:
        // 进程/线程访问
        $access1 = "OpenProcess" ascii wide
        $access2 = "OpenThread" ascii wide
        $access3 = "NtOpenProcess" ascii wide

        // 内存操作
        $mem1 = "VirtualAllocEx" ascii wide
        $mem2 = "VirtualProtectEx" ascii wide
        $mem3 = "NtAllocateVirtualMemory" ascii wide

        // 写入
        $write1 = "WriteProcessMemory" ascii wide
        $write2 = "NtWriteVirtualMemory" ascii wide

        // 执行
        $exec1 = "CreateRemoteThread" ascii wide
        $exec2 = "NtCreateThreadEx" ascii wide
        $exec3 = "RtlCreateUserThread" ascii wide
        $exec4 = "QueueUserAPC" ascii wide
        $exec5 = "SetThreadContext" ascii wide

    condition:
        pe.is_pe and
        any of ($access*) and any of ($mem*) and any of ($write*) and any of ($exec*)
}

// ============================================================================
// Reflective DLL Loading
// ============================================================================

rule Reflective_DLL_Loading {
    meta:
        description = "Detects Reflective DLL Loading technique"
        author = "CyberSec Skills"
        severity = "high"
        technique = "T1620"

    strings:
        // 反射加载特征字符串
        $str1 = "ReflectiveLoader" ascii wide nocase
        $str2 = "ReflectiveDll" ascii wide nocase
        $str3 = "_RDI" ascii  // Reflective DLL Injection marker

        // PE 解析
        $pe1 = "VirtualAlloc" ascii wide
        $pe2 = "GetProcAddress" ascii wide
        $pe3 = "LoadLibraryA" ascii wide
        $pe4 = "NtFlushInstructionCache" ascii wide

        // DOS/PE 头处理
        $hdr1 = { 4D 5A }  // MZ
        $hdr2 = "IMAGE_DOS_SIGNATURE" ascii
        $hdr3 = "IMAGE_NT_SIGNATURE" ascii

    condition:
        pe.is_pe and
        (any of ($str*) or (3 of ($pe*) and any of ($hdr*)))
}
