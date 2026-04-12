// Frida 通用 Hook 脚本
// 用法: frida -f ./binary -l hook.js --no-pause

// === 配置区 ===
const CONFIG = {
    hookStrcmp: true,
    hookStrncmp: true,
    hookMemcmp: true,
    hookPtrace: true,  // 反调试绕过
    customHooks: []    // 自定义地址 ["0x401234", "0x401300"]
};

// === strcmp Hook ===
if (CONFIG.hookStrcmp) {
    const strcmp = Module.findExportByName(null, "strcmp");
    if (strcmp) {
        Interceptor.attach(strcmp, {
            onEnter(args) {
                this.s1 = Memory.readUtf8String(args[0]);
                this.s2 = Memory.readUtf8String(args[1]);
            },
            onLeave(retval) {
                console.log(`[strcmp] "${this.s1}" vs "${this.s2}" => ${retval}`);
            }
        });
        console.log("[+] Hooked strcmp");
    }
}

// === strncmp Hook ===
if (CONFIG.hookStrncmp) {
    const strncmp = Module.findExportByName(null, "strncmp");
    if (strncmp) {
        Interceptor.attach(strncmp, {
            onEnter(args) {
                this.s1 = Memory.readUtf8String(args[0]);
                this.s2 = Memory.readUtf8String(args[1]);
                this.n = args[2].toInt32();
            },
            onLeave(retval) {
                console.log(`[strncmp] "${this.s1}" vs "${this.s2}" (n=${this.n}) => ${retval}`);
            }
        });
        console.log("[+] Hooked strncmp");
    }
}

// === memcmp Hook ===
if (CONFIG.hookMemcmp) {
    const memcmp = Module.findExportByName(null, "memcmp");
    if (memcmp) {
        Interceptor.attach(memcmp, {
            onEnter(args) {
                this.size = args[2].toInt32();
                this.buf1 = hexdump(args[0], { length: Math.min(this.size, 64) });
                this.buf2 = hexdump(args[1], { length: Math.min(this.size, 64) });
            },
            onLeave(retval) {
                console.log(`[memcmp] size=${this.size} => ${retval}`);
                console.log("  buf1:", this.buf1);
                console.log("  buf2:", this.buf2);
            }
        });
        console.log("[+] Hooked memcmp");
    }
}

// === 反调试绕过 ===
if (CONFIG.hookPtrace) {
    const ptrace = Module.findExportByName(null, "ptrace");
    if (ptrace) {
        Interceptor.replace(ptrace, new NativeCallback(() => {
            console.log("[!] ptrace() bypassed");
            return 0;
        }, 'long', ['int', 'int', 'pointer', 'pointer']));
        console.log("[+] ptrace anti-debug bypass enabled");
    }
}

// === 自定义地址 Hook ===
CONFIG.customHooks.forEach(addr => {
    Interceptor.attach(ptr(addr), {
        onEnter(args) {
            console.log(`[${addr}] Hit!`);
            console.log("  RAX:", this.context.rax);
            console.log("  RDI:", this.context.rdi);
            console.log("  RSI:", this.context.rsi);
            console.log("  RDX:", this.context.rdx);
        }
    });
    console.log(`[+] Hooked custom address: ${addr}`);
});

console.log("\n=== Frida Hook Ready ===\n");
