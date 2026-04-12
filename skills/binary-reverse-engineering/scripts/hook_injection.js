/**
 * Windows 进程注入监控脚本 (Frida)
 *
 * 用法:
 *   frida -f malware.exe -l hook_injection.js --no-pause
 *   frida -p <PID> -l hook_injection.js
 *
 * 监控技术:
 *   - Process Hollowing (T1055.012)
 *   - Process Injection (T1055)
 *   - DLL Injection (T1055.001)
 *   - Thread Hijacking (T1055.003)
 *   - APC Injection (T1055.004)
 */

'use strict';

// === 配置 ===
const CONFIG = {
    logToFile: false,
    logPath: 'C:\\temp\\injection_log.txt',
    dumpMemory: true,
    dumpPath: 'C:\\temp\\dumps\\',
    verbose: true
};

// === 颜色输出 ===
const Colors = {
    RED: '\x1b[31m',
    GREEN: '\x1b[32m',
    YELLOW: '\x1b[33m',
    BLUE: '\x1b[34m',
    MAGENTA: '\x1b[35m',
    CYAN: '\x1b[36m',
    RESET: '\x1b[0m'
};

function log(level, msg) {
    const timestamp = new Date().toISOString();
    const colors = {
        'CRITICAL': Colors.RED,
        'WARNING': Colors.YELLOW,
        'INFO': Colors.GREEN,
        'DEBUG': Colors.CYAN
    };
    const color = colors[level] || Colors.RESET;
    console.log(`${color}[${timestamp}] [${level}] ${msg}${Colors.RESET}`);
}

// === 辅助函数 ===
function hexdump(ptr, length) {
    try {
        return Memory.readByteArray(ptr, Math.min(length, 256));
    } catch (e) {
        return null;
    }
}

function readWideString(ptr) {
    try {
        return ptr.readUtf16String();
    } catch (e) {
        return '<error>';
    }
}

function getProcessName(pid) {
    // 简化版，实际需要 NtQueryInformationProcess
    return `PID:${pid}`;
}

// === 进程创建监控 ===
const CreateProcessW = Module.findExportByName('kernel32.dll', 'CreateProcessW');
if (CreateProcessW) {
    Interceptor.attach(CreateProcessW, {
        onEnter: function(args) {
            this.appName = readWideString(args[0]);
            this.cmdLine = readWideString(args[1]);
            this.creationFlags = args[5].toInt32();
            this.processInfo = args[9];

            // 检查 CREATE_SUSPENDED 标志 (0x4)
            const suspended = (this.creationFlags & 0x4) !== 0;

            if (suspended) {
                log('CRITICAL', `[Process Hollowing] CreateProcessW with CREATE_SUSPENDED`);
                log('CRITICAL', `    Application: ${this.appName || '<null>'}`);
                log('CRITICAL', `    CommandLine: ${this.cmdLine || '<null>'}`);
                log('CRITICAL', `    Flags: 0x${this.creationFlags.toString(16)}`);
            } else {
                log('INFO', `CreateProcessW: ${this.cmdLine || this.appName}`);
            }
        },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0 && this.processInfo) {
                try {
                    const hProcess = this.processInfo.readPointer();
                    const hThread = this.processInfo.add(Process.pointerSize).readPointer();
                    const dwProcessId = this.processInfo.add(Process.pointerSize * 2).readU32();
                    const dwThreadId = this.processInfo.add(Process.pointerSize * 2 + 4).readU32();

                    log('INFO', `    => hProcess: ${hProcess}, PID: ${dwProcessId}, TID: ${dwThreadId}`);
                } catch (e) {}
            }
        }
    });
    log('INFO', '[+] Hooked CreateProcessW');
}

// === 内存分配监控 (远程进程) ===
const VirtualAllocEx = Module.findExportByName('kernel32.dll', 'VirtualAllocEx');
if (VirtualAllocEx) {
    Interceptor.attach(VirtualAllocEx, {
        onEnter: function(args) {
            this.hProcess = args[0];
            this.lpAddress = args[1];
            this.dwSize = args[2].toInt32();
            this.flAllocationType = args[3].toInt32();
            this.flProtect = args[4].toInt32();

            // PAGE_EXECUTE_READWRITE = 0x40
            const isRWX = (this.flProtect & 0x40) !== 0;
            const isExecutable = (this.flProtect & 0xF0) !== 0;

            if (isRWX) {
                log('CRITICAL', `[Injection] VirtualAllocEx with PAGE_EXECUTE_READWRITE`);
            } else if (isExecutable) {
                log('WARNING', `[Injection] VirtualAllocEx with executable protection`);
            }

            log('INFO', `VirtualAllocEx(hProcess=${this.hProcess}, size=0x${this.dwSize.toString(16)}, protect=0x${this.flProtect.toString(16)})`);
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                log('INFO', `    => Allocated at: ${retval}`);
            }
        }
    });
    log('INFO', '[+] Hooked VirtualAllocEx');
}

// === 内存写入监控 (远程进程) ===
const WriteProcessMemory = Module.findExportByName('kernel32.dll', 'WriteProcessMemory');
if (WriteProcessMemory) {
    Interceptor.attach(WriteProcessMemory, {
        onEnter: function(args) {
            this.hProcess = args[0];
            this.lpBaseAddress = args[1];
            this.lpBuffer = args[2];
            this.nSize = args[3].toInt32();

            log('CRITICAL', `[Injection] WriteProcessMemory`);
            log('CRITICAL', `    hProcess: ${this.hProcess}`);
            log('CRITICAL', `    Address: ${this.lpBaseAddress}`);
            log('CRITICAL', `    Size: 0x${this.nSize.toString(16)} (${this.nSize} bytes)`);

            // 检查是否写入 PE
            try {
                const header = this.lpBuffer.readByteArray(4);
                const headerBytes = new Uint8Array(header);
                if (headerBytes[0] === 0x4D && headerBytes[1] === 0x5A) { // MZ
                    log('CRITICAL', `    [!] Writing PE file (MZ header detected)`);
                }
            } catch (e) {}

            // Dump 写入内容
            if (CONFIG.dumpMemory && this.nSize > 0) {
                try {
                    const dump = hexdump(this.lpBuffer, this.nSize);
                    if (dump) {
                        log('DEBUG', `    First 64 bytes:`);
                        console.log(dump);
                    }
                } catch (e) {}
            }
        },
        onLeave: function(retval) {
            log('INFO', `    => Result: ${retval.toInt32() !== 0 ? 'SUCCESS' : 'FAILED'}`);
        }
    });
    log('INFO', '[+] Hooked WriteProcessMemory');
}

// === 线程上下文操作 ===
const GetThreadContext = Module.findExportByName('kernel32.dll', 'GetThreadContext');
if (GetThreadContext) {
    Interceptor.attach(GetThreadContext, {
        onEnter: function(args) {
            this.hThread = args[0];
            this.lpContext = args[1];
            log('WARNING', `[Hollowing] GetThreadContext(hThread=${this.hThread})`);
        },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0 && this.lpContext) {
                try {
                    // CONTEXT 结构，EAX/RAX 在不同偏移
                    // x86: EAX at offset 0xB0
                    // x64: Rax at offset 0x78
                    const raxOffset = Process.arch === 'x64' ? 0x78 : 0xB0;
                    const entryPoint = this.lpContext.add(raxOffset).readPointer();
                    log('WARNING', `    Entry Point (RAX/EAX): ${entryPoint}`);
                } catch (e) {}
            }
        }
    });
    log('INFO', '[+] Hooked GetThreadContext');
}

const SetThreadContext = Module.findExportByName('kernel32.dll', 'SetThreadContext');
if (SetThreadContext) {
    Interceptor.attach(SetThreadContext, {
        onEnter: function(args) {
            this.hThread = args[0];
            this.lpContext = args[1];

            log('CRITICAL', `[Hollowing] SetThreadContext(hThread=${this.hThread})`);

            try {
                const raxOffset = Process.arch === 'x64' ? 0x78 : 0xB0;
                const newEntryPoint = this.lpContext.add(raxOffset).readPointer();
                log('CRITICAL', `    New Entry Point: ${newEntryPoint}`);
            } catch (e) {}
        }
    });
    log('INFO', '[+] Hooked SetThreadContext');
}

// === WOW64 上下文操作 (32位进程注入) ===
const Wow64GetThreadContext = Module.findExportByName('kernel32.dll', 'Wow64GetThreadContext');
if (Wow64GetThreadContext) {
    Interceptor.attach(Wow64GetThreadContext, {
        onEnter: function(args) {
            log('WARNING', `[Hollowing] Wow64GetThreadContext(hThread=${args[0]})`);
        }
    });
    log('INFO', '[+] Hooked Wow64GetThreadContext');
}

const Wow64SetThreadContext = Module.findExportByName('kernel32.dll', 'Wow64SetThreadContext');
if (Wow64SetThreadContext) {
    Interceptor.attach(Wow64SetThreadContext, {
        onEnter: function(args) {
            log('CRITICAL', `[Hollowing] Wow64SetThreadContext(hThread=${args[0]})`);
        }
    });
    log('INFO', '[+] Hooked Wow64SetThreadContext');
}

// === 线程恢复 ===
const ResumeThread = Module.findExportByName('kernel32.dll', 'ResumeThread');
if (ResumeThread) {
    Interceptor.attach(ResumeThread, {
        onEnter: function(args) {
            log('CRITICAL', `[Hollowing] ResumeThread(hThread=${args[0]})`);
            log('CRITICAL', `    [!] Injection likely complete - payload executing`);
        }
    });
    log('INFO', '[+] Hooked ResumeThread');
}

// === NtUnmapViewOfSection (Hollowing) ===
const NtUnmapViewOfSection = Module.findExportByName('ntdll.dll', 'NtUnmapViewOfSection');
if (NtUnmapViewOfSection) {
    Interceptor.attach(NtUnmapViewOfSection, {
        onEnter: function(args) {
            log('CRITICAL', `[Hollowing] NtUnmapViewOfSection`);
            log('CRITICAL', `    hProcess: ${args[0]}`);
            log('CRITICAL', `    BaseAddress: ${args[1]}`);
        }
    });
    log('INFO', '[+] Hooked NtUnmapViewOfSection');
}

// === 远程线程创建 ===
const CreateRemoteThread = Module.findExportByName('kernel32.dll', 'CreateRemoteThread');
if (CreateRemoteThread) {
    Interceptor.attach(CreateRemoteThread, {
        onEnter: function(args) {
            this.hProcess = args[0];
            this.lpStartAddress = args[4];
            this.lpParameter = args[5];

            log('CRITICAL', `[Injection] CreateRemoteThread`);
            log('CRITICAL', `    hProcess: ${this.hProcess}`);
            log('CRITICAL', `    StartAddress: ${this.lpStartAddress}`);
            log('CRITICAL', `    Parameter: ${this.lpParameter}`);
        },
        onLeave: function(retval) {
            if (!retval.isNull()) {
                log('CRITICAL', `    => Thread Handle: ${retval}`);
            }
        }
    });
    log('INFO', '[+] Hooked CreateRemoteThread');
}

// === APC 注入 ===
const QueueUserAPC = Module.findExportByName('kernel32.dll', 'QueueUserAPC');
if (QueueUserAPC) {
    Interceptor.attach(QueueUserAPC, {
        onEnter: function(args) {
            log('CRITICAL', `[APC Injection] QueueUserAPC`);
            log('CRITICAL', `    pfnAPC: ${args[0]}`);
            log('CRITICAL', `    hThread: ${args[1]}`);
            log('CRITICAL', `    dwData: ${args[2]}`);
        }
    });
    log('INFO', '[+] Hooked QueueUserAPC');
}

// === DLL 注入检测 ===
const LoadLibraryW = Module.findExportByName('kernel32.dll', 'LoadLibraryW');
if (LoadLibraryW) {
    Interceptor.attach(LoadLibraryW, {
        onEnter: function(args) {
            const dllName = readWideString(args[0]);

            // 检测可疑 DLL 加载
            const suspicious = [
                '.tmp', '.dat', '\\temp\\', '\\appdata\\',
                'users\\', 'public\\', '\\downloads\\'
            ];

            const isSuspicious = suspicious.some(s =>
                dllName.toLowerCase().includes(s)
            );

            if (isSuspicious) {
                log('WARNING', `[DLL Injection?] LoadLibraryW: ${dllName}`);
            } else if (CONFIG.verbose) {
                log('DEBUG', `LoadLibraryW: ${dllName}`);
            }
        }
    });
    log('INFO', '[+] Hooked LoadLibraryW');
}

// === 内存保护修改 ===
const VirtualProtectEx = Module.findExportByName('kernel32.dll', 'VirtualProtectEx');
if (VirtualProtectEx) {
    Interceptor.attach(VirtualProtectEx, {
        onEnter: function(args) {
            this.hProcess = args[0];
            this.lpAddress = args[1];
            this.dwSize = args[2].toInt32();
            this.flNewProtect = args[3].toInt32();

            // 检测 RWX
            if ((this.flNewProtect & 0x40) !== 0) {
                log('WARNING', `[Injection] VirtualProtectEx -> PAGE_EXECUTE_READWRITE`);
                log('WARNING', `    Address: ${this.lpAddress}, Size: 0x${this.dwSize.toString(16)}`);
            }
        }
    });
    log('INFO', '[+] Hooked VirtualProtectEx');
}

// === 启动信息 ===
console.log('\n' + '='.repeat(60));
console.log(`${Colors.GREEN}Windows 进程注入监控已启动${Colors.RESET}`);
console.log('='.repeat(60));
console.log(`进程: ${Process.id}`);
console.log(`架构: ${Process.arch}`);
console.log(`平台: ${Process.platform}`);
console.log('='.repeat(60) + '\n');
