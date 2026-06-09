#include <substrate.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

// ==========================================
// 核心防封逻辑 - 编译为 Tweak.dylib
// 注入到游戏进程，比 Frida 更底层更稳定
// ==========================================

// 1. 拦截 ptrace (防止反作弊检测调试器)
static int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == 31) { // PT_DENY_ATTACH
        return 0; // 阻止游戏主动拒绝附加
    }
    return orig_ptrace(request, pid, addr, data);
}

// 2. 拦截 sysctl (抹除进程调试标志)
static int (*orig_sysctl)(int * name, u_int namelen, void * oldp, size_t * oldlenp, void * newp, size_t newlen);
static int my_sysctl(int * name, u_int namelen, void * oldp, size_t * oldlenp, void * newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (ret == 0 && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && oldp) {
        struct kinfo_proc *info = (struct kinfo_proc *)oldp;
        if (info->kp_proc.p_flag & P_TRACED) {
            info->kp_proc.p_flag ^= P_TRACED; // 抹除 P_TRACED 标志
        }
    }
    return ret;
}

// 3. 拦截 _dyld_get_image_name (过滤越狱/外挂动态库)
static const char * (*orig__dyld_get_image_name)(uint32_t image_index);
static const char * my__dyld_get_image_name(uint32_t image_index) {
    const char *ret = orig__dyld_get_image_name(image_index);
    if (ret) {
        if (strstr(ret, "jbroot") || strstr(ret, "ElleKit") || strstr(ret, "roothide") || strstr(ret, "MobileSubstrate") || strstr(ret, "Tweak")) {
            return "/usr/lib/system/libsystem_kernel.dylib"; // 伪装成合法库
        }
    }
    return ret;
}

// 4. 拦截 dladdr (过滤基于地址查询的模块路径)
static int (*orig_dladdr)(const void *, Dl_info *);
static int my_dladdr(const void *addr, Dl_info *info) {
    int ret = orig_dladdr(addr, info);
    if (ret != 0 && info && info->dli_fname) {
        if (strstr(info->dli_fname, "jbroot") || strstr(info->dli_fname, "ElleKit") || strstr(info->dli_fname, "roothide") || strstr(info->dli_fname, "MobileSubstrate") || strstr(info->dli_fname, "Tweak")) {
            // 直接伪装 dli_fname 可能会因为写只读内存崩溃，所以这里直接返回 0 让游戏以为没查到
            memset(info, 0, sizeof(Dl_info));
            return 0;
        }
    }
    return ret;
}

// 5. 拦截文件系统检测 (越狱环境/外挂文件)
static int (*orig_access)(const char *path, int amode);
static int my_access(const char *path, int amode) {
    if (path) {
        if (strstr(path, "jbroot") || strstr(path, "roothide") || strstr(path, "Library/MobileSubstrate") || strstr(path, "Tweak")) {
            return -1; // 假装文件不存在
        }
    }
    return orig_access(path, amode);
}

static int (*orig_stat)(const char *restrict path, struct stat *restrict buf);
static int my_stat(const char *restrict path, struct stat *restrict buf) {
    if (path) {
         if (strstr(path, "jbroot") || strstr(path, "roothide") || strstr(path, "Library/MobileSubstrate") || strstr(path, "Tweak")) {
            return -1; // 假装文件不存在
        }
    }
    return orig_stat(path, buf);
}

// 构造函数，在库加载时自动执行 Hook
__attribute__((constructor)) static void custom_init() {
    MSHookFunction((void *)ptrace, (void *)my_ptrace, (void **)&orig_ptrace);
    MSHookFunction((void *)sysctl, (void *)my_sysctl, (void **)&orig_sysctl);
    MSHookFunction((void *)_dyld_get_image_name, (void *)my__dyld_get_image_name, (void **)&orig__dyld_get_image_name);
    MSHookFunction((void *)dladdr, (void *)my_dladdr, (void **)&orig_dladdr);
    MSHookFunction((void *)access, (void *)my_access, (void **)&orig_access);
    MSHookFunction((void *)stat, (void *)my_stat, (void **)&orig_stat);
}
