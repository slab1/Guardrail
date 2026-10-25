/*
 * Guardrail OS - Native Tier-2 eBPF Seccomp Syscall Interceptor
 * Program Type: BPF_PROG_TYPE_SECCOMP
 * Trap Signal: SIGSYS (31) on unauthorized syscall invocation
 */

#include <linux/bpf.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/ptrace.h>

#define SECCOMP_RET_ALLOW 0x7fff0000U
#define SECCOMP_RET_TRAP  0x00030000U
#define SECCOMP_RET_ERRNO 0x00050000U

/* Seccomp Filter Map for Autonomy Level 0 (Read-Only) */
struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};

SEC("seccomp")
int guardrail_pep_filter(struct seccomp_data *ctx) {
    int syscall_nr = ctx->nr;

    /* Allowed Syscalls for L0 Observer: read(0), close(3), stat(4), fstat(5), openat(257), exit_group(231) */
    if (syscall_nr == 0 || syscall_nr == 3 || syscall_nr == 4 || 
        syscall_nr == 5 || syscall_nr == 257 || syscall_nr == 231) {
        return SECCOMP_RET_ALLOW;
    }

    /* Prohibited Syscalls: write(1), execve(59), socket(41), reboot(169) -> Hardware TRAP_SIGSYS */
    return SECCOMP_RET_TRAP;
}

char _license[] SEC("license") = "GPL";
