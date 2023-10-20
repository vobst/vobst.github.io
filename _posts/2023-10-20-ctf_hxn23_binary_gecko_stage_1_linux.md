---
layout: post
title: "Solving Binary Gecko's Hexacon CTF with frida and angr [stage 1, Linux]"
---

This year's [Hexacon](https://www.hexacon.fr/) featured several CTFs hosted by some of the sponsoring companies. This post is a brief writeup of my solution for the stage-one Linux challenge by [Binary Gecko](https://binarygecko.com/), a "[...] provider of comprehensive and specialized cybersecurity solutions to businesses and institutions of all sizes.", aha.

tl;dr: Work around a bunch of anti-debug techniques to dump a second-stage payload. Use [angr](https://angr.io/) (after convincing it to load the malformatted dump) to solve a standard crackme that yields the flag. Then validate that it is correct, using [frida](https://frida.re/) to work around some more anti-debug annoyances.

## Overview
We are given a static binary without any symbols or useful strings, but with an rwx segment, great. Running it just tells us to 'Get out!'.
```
% readelf --segments hexalinux.bin

Elf file type is EXEC (Executable file)
Entry point 0x2000c0
There are 2 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000200000 0x0000000000200000
                 0x0000000000003a87 0x0000000000003a87  RWE    0x200000
  LOAD           0x0000000000003a87 0x0000000000a03a87 0x0000000000a03a87
                 0x0000000000004010 0x0000000000004010  RW     0x200000
% file hexalinux.bin
hexalinux.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
% ./hexalinux.bin
Get out!!
```
Furthermore, throwing it into a disassembler shows many unprocessed regions, indicating some sort of packing.

## Anti-Debug Vol. 1
Using `strace` shows us the first anti-debug technique: the binary checks `/proc/self/status`. Usually this is a check of the "TracerPid" value to detect the presence of a debugger.
```
% strace ./hexalinux.bin
execve("./hexalinux.bin", ["./hexalinux.bin"], 0x70bb0b5efd70 /* 43 vars */) = 0
getpid()                                = 34999
stat("/proc/34999/status", {st_mode=S_IFREG|0444, st_size=0, ...}) = 0
open("/proc/34999/status", O_RDONLY)    = 3
read(3, "Name:\thexalinux.bin\nUmask:\t0022\n"..., 4095) = 1207
close(3)                                = 0
exit(0)                                 = ?
```
At this point, I went searching for a [gdb script](https://github.com/vobst/ctf_hxn23_binary_gecko_stage_1_linux/blob/master/gdb_script.py) I use in those situations. Using [my favorite decompiler](https://binary.ninja/), I made a list of all the `syscall` addresses in the binary.
```python
[x[0] for x in [[i[1] for i in f.instructions if str(i[0][0]) == 'syscall'] for f in bv.functions] if x]
```
The script simply uses them to place a breakpoint before and after each syscall instruction. Combining this with a [tool to convert syscall numbers to names](https://github.com/martinclauss/syscall_number), we got ourselves a poor-mans `strace`! We can also automate the bypassing of the first anti-debug check by simply overwriting the string that was read from the status file.

## Anti-Debug Vol. 2
Running the binary under our ad-hock `strace` shows a call to `fork` and then many `ptrace` invocations - it seems that the first process is spawning another process and then does some fun stuff to it. However, we soon exit due to some other anti-debug check.
```
SYS_getpid(arg1=0x0,arg2=0x0,arg3=0x0,arg4=0x0,arg5=0x0) -> 0x13f2
SYS_stat(arg1=0x7fffffffd340,arg2=0x7fffffffd3c0,arg3=0x7fffffffd32f,arg4=0x7fffffffd3c0,arg5=0x0) -> 0x0
SYS_open(name=0x7fffffffd340:   "/proc/5106/status",arg2=0x0,arg3=0x0,arg4=0x0,arg5=0x0) -> 0x3
SYS_read(fd=0x3,buf=0x7fffffffd450,n=0xfff,arg4=0xfff,arg5=0x3) -> 0x4b1
[+] remove TracerPid
SYS_close(arg1=0x3,arg2=0x7fffffffd450,arg3=0xfff,arg4=0xfff,arg5=0x0) -> 0x0
[Detaching after fork from child process 5109]
SYS_fork(arg1=0x7fffffffd450,arg2=0x7fffffffd315,arg3=0x7fffffffd45b,arg4=0xfff,arg5=0x0) -> 0x13f5
SYS_rt_sigaction(arg1=0x5,arg2=0x7fffffff6970,arg3=0x0,arg4=0x8,arg5=0x0) -> 0x0
SYS_mmap(arg1=0x0,arg2=0x100000,arg3=0x3,arg4=0x22,arg5=0xffffffff) -> 0x7ffff7ef9000
SYS_getpid(arg1=0x0,arg2=0x100000,arg3=0x3,arg4=0x22,arg5=0x0) -> 0x13f2
SYS_stat(arg1=0x7fffffff6a60,arg2=0x7fffffff6d60,arg3=0x7fffffff6a1f,arg4=0x7fffffff6d60,arg5=0x0) -> 0x0
SYS_open(name=0x7fffffff6a60:   "/proc/5106/status",arg2=0x0,arg3=0x0,arg4=0x0,arg5=0x0) -> 0x3
SYS_read(fd=0x3,buf=0x7fffffff72d0,n=0xfff,arg4=0xfff,arg5=0x3) -> 0x4b1
[+] remove TracerPid
SYS_close(arg1=0x3,arg2=0x7fffffff72d0,arg3=0xfff,arg4=0xfff,arg5=0x0) -> 0x0
SYS_prctl(arg1=0x4,arg2=0x0,arg3=0x0,arg4=0x0,arg5=0x0) -> 0x0
SYS_ptrace(arg1=0x4200,arg2=0x13f5,arg3=0x0,arg4=0x10005e,arg5=0x0) -> 0x0
SYS_ptrace(arg1=0x7,arg2=0x13f5,arg3=0x0,arg4=0x0,arg5=0x0) -> 0x0
SYS_wait4(arg1=0x13f5,arg2=0x7fffffff69ac,arg3=0x40000001,arg4=0x0,arg5=0x0) -> 0x13f5
SYS_getpid(arg1=0x13f5,arg2=0x7ffff7ef9020,arg3=0x7f,arg4=0x0,arg5=0x0) -> 0x13f2
SYS_stat(arg1=0x7fffffff6ae0,arg2=0x7fffffff6df0,arg3=0x7fffffff6a2f,arg4=0x7fffffff6df0,arg5=0x0) -> 0x0
SYS_open(name=0x7fffffff6ae0:   "/proc/5106/status",arg2=0x0,arg3=0x0,arg4=0x0,arg5=0x0) -> 0x3
SYS_read(fd=0x3,buf=0x7fffffff82d0,n=0xfff,arg4=0xfff,arg5=0x3) -> 0x4b1
[+] remove TracerPid
SYS_close(arg1=0x3,arg2=0x7fffffff82d0,arg3=0xfff,arg4=0xfff,arg5=0x0) -> 0x0

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000000000201496 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
[!] Command 'registers' failed to execute properly, reason: [Errno 13] Permission denied: '/proc/35415/maps'
─────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
[!] Command 'dereference' failed to execute properly, reason: [Errno 13] Permission denied: '/proc/35415/maps'
───────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x201489                  jne    0x201002
     0x20148f                  mov    eax, DWORD PTR [rip+0x24db]        # 0x203970
     0x201495                  int3
 →   0x201496                  add    eax, 0x1
     0x201499                  cmp    eax, DWORD PTR [rip+0x24d1]        # 0x203970
     0x20149f                  jne    0x201002
     0x2014a5                  xor    eax, eax
     0x2014a7                  call   0x2026a0
     0x2014ac                  mov    r8d, eax
───────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "hexalinux_patch", stopped 0x201496 in ?? (), reason: SIGTRAP
─────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x201496 → add eax, 0x1
```
There are two interesting things here: we cannot access the `/proc/self/maps` of the debuggee and there is a breakpoint instruction which we did not put there.

The reason behind the first issue is the call to `SYS_prctl` that we can see in the trace above. It is made with the `PR_SET_DUMPABLE` parameter. Apart from the obvious effect of disabling core dumps, this affects the ownership rules of the process' proc files, which is why our debugger cannot access them anymore. I simply used the gdb script to turn the call to prctl into a call `SYS_close(-1)`, i.e., a no-op, and afterwards adjusted the return value to indicate success.

The second observation is more interesting. As we can see in the above trace, the process calls `SYS_rt_sigaction` to set the signal handler for the `SIGTRAP` signal to a function at `0x202070`.
```
00202070  int64_t sigtrap_handler()

00202070  f30f1efa           endbr64
00202074  8305f518000001     add     dword [rel data_203970], 0x1
0020207b  c3                 retn     {__return_addr}

00202080  uint64_t adbg_set_sigtrap_handler()

00202080  f30f1efa           endbr64
00202084  4883ec28           sub     rsp, 0x28
00202088  31d2               xor     edx, edx  {0x0}
0020208a  bf05000000         mov     edi, 0x5
0020208f  4889e6             mov     rsi, rsp {var_28}
00202092  48c7442418ffffff…  mov     qword [rsp+0x18 {var_10}], 0xffffffffffffffff
0020209b  48c7042470202000   mov     qword [rsp {var_28}], sigtrap_handler
002020a3  48c7442408000000…  mov     qword [rsp+0x8 {var_20}], 0x4000000
002020ac  48c7442410602020…  mov     qword [rsp+0x10 {var_18}], data_202060
002020b5  e806060000         call    sigaction
002020ba  85c0               test    eax, eax
002020bc  7805               js      0x2020c3

002020be  4883c428           add     rsp, 0x28
002020c2  c3                 retn     {__return_addr}

002020c3  31ff               xor     edi, edi  {0x0}
002020c5  e816040000         call    exit

```
Your disassembler probably did not catch that upper function on the first round, but it simply increments the memory at `0x203970` by one. The code around the breakpoint then validates that the handler runs when executing the `int3` instruction, cool. Of course the handler will not run when we are debugging, which is another thing we can fix with the script.

## Anti-Debug Vol. 3

Even with all these countermeasures in place, I still crashed due to an invalid memory reference. It happened at a seemingly arbitrary point while debugging the child process (before the parent attaches to it). When executing
```
SYS_getpid(arg1=0x0,arg2=0x0,arg3=0x0,arg4=0x0,arg5=0x0) -> 0x147a
SYS_stat(arg1=0x7fffffffd350,arg2=0x7fffffffd3d0,arg3=0x7fffffffd33f,arg4=0x7fffffffd3d0,arg5=0x0) -> 0x0
SYS_open(name=0x7fffffffd350:   "/proc/5242/status"
,arg2=0x0,arg3=0x0,arg4=0x0,arg5=0x0) -> 0x3
SYS_read(fd=0x3,buf=0x7fffffffd460,n=0xfff,arg4=0xfff,arg5=0x3) -> 0x4b0
[+] remove TracerPid
SYS_close(arg1=0x3,arg2=0x7fffffffd460,arg3=0xfff,arg4=0xfff,arg5=0x0) -> 0x0
[Attaching after process 5242 fork to child process 5245]
[New inferior 2 (process 5245)]
[Detaching after fork from parent process 5242]
[Inferior 1 (process 5242) detached]
SYS_fork(arg1=0x7fffffffd460,arg2=0x7fffffffd325,arg3=0x7fffffffd46b,arg4=0xfff,arg5=0x0) -> 0x0
SYS_setrlimit(arg1=0x4,arg2=0x7fffffffd340,arg3=0x7fffffffd46b,arg4=0x7fffffffd340,arg5=0x0) -> 0x0
SYS_getpid(arg1=0x7fffffffe480,arg2=0x7fffffffd340,arg3=0x7fffffffd46b,arg4=0x7fffffffd340,arg5=0x0) -> 0x147d
SYS_stat(arg1=0x7fffffffd330,arg2=0x7fffffffd3b0,arg3=0x7fffffffd29f,arg4=0x7fffffffd3b0,arg5=0x0) -> 0x0
SYS_open(name=0x7fffffffd330:   "/proc/5245/status",arg2=0x0,arg3=0x0,arg4=0x0,arg5=0x0) -> 0x3
SYS_read(fd=0x3,buf=0x7fffffffd440,n=0xfff,arg4=0xfff,arg5=0x3) -> 0x4b1
[+] remove TracerPid
SYS_close(arg1=0x3,arg2=0x7fffffffd440,arg3=0xfff,arg4=0xfff,arg5=0x0) -> 0x0
SYS_setrlimit(arg1=0x4,arg2=0x7fffffffd2a0,arg3=0x7,arg4=0x7fffffffd2a0,arg5=0x0) -> 0x0

Thread 2.1 "hexalinux_patch" received signal SIGBUS, Bus error.
[...]
$rbp   : 0x89a770da45244a2e
[...]
 →   0x2003be                  mov    eax, DWORD PTR [rbp+0x0]
```
`rbp` was always holding some garbage value. At this point I got kind of annoyed and started patching the code, however, this only increased my dissatisfaction as it turned out that the binary detects code modifications and gets trapped in an endless loop, charming.

I did not investigate these two issues further, but one of the other two (yea, there are more) anti-debug measures performed by the child lead me on the right track.

## Anti-Debug Vol. 4

The first thing that the child does is setting the resource limit for the maximal core dump size to zero, i.e., `SYS_setrlimit(0x4...)`. That's not a problem as we can bypass it by turning it into a no-op `close(-1)` via the debugger. However, the second activity is more interesting: the child sanitizes its environment variables on the stack, removing some variables interpreted by the [dynamic linker](https://man7.org/linux/man-pages/man8/ld.so.8.html) ... interesting: why care about those variables in a static binary?

*Aside*: (I guess) that there is a bug when sanitizing the stack:
```
00202100  char** adbg_sanitize_env(void* argcp)

00202100  f30f1efa           endbr64
00202104  53                 push    rbx {__saved_rbx}
00202105  488d4708           lea     rax, [rdi+0x8]
00202109  4883ec20           sub     rsp, 0x20
0020210d  0f1f00             nop     dword [rax], eax

00202110  4889c2             mov     rdx, rax
00202113  4883c008           add     rax, 0x8
00202117  48833800           cmp     qword [rax], 0x0
0020211b  75f3               jne     0x202110
...
```
Since `rdi` points to points to `argc`, the first loop, which is meant to skip the argument vector `argv`, actually skips the environment variables when the program is executed with no arguments at all (yes, `argv[0]` is optional).

## Change of Strategy

As it didn't look like I could debug either parent or child with any meaningful results, and reversing the binary statically didn't look fun either, (especially due do the poking of the parent via ptrace that makes it hard to reason about the child's control flow, some obvious second stage unpacking, and potentially self-modifying code) I decided to switch tracks.

Remember that the binary printed "Get out!" to stdout? The disassembly I was looking at did not even contain a write system call! At first, I was suspecting that the `write` syscall would be made from shellcode, so I wrote a [small BPF program](https://github.com/vobst/ctf_hxn23_binary_gecko_stage_1_linux/blob/master/hexalinux.bpf.c) that hooks the write syscall and overwrite the code after the syscall instruction with an endless loop, i.e., `jmp 0x0`. This would allow me to inspect whichever process made the syscall, or at least I hoped so.
```c
SEC("tp/syscalls/sys_enter_write")
int tp_sys_enter_write(struct trace_event_raw_sys_exit* tp)
{
  struct task_struct* task = NULL;
  struct pt_regs* regs = NULL;
  int argc = 0, i = 0, ret = 0;
  char buf[16] = { 0 };
  void *ip = 0;

  // only hook child and parent
  if (bpf_get_current_comm((void*)buf, sizeof(buf))) {
    bpf_printk("error: bpf_get_current_comm\n");
    return 0;
  }
  if (__builtin_memcmp(buf, "hexalinux", 9)) {
    return 0;
  }

  // get address of insn after `syscall`
  task = (struct task_struct*)bpf_get_current_task_btf();
  regs = (struct pt_regs*)bpf_task_pt_regs(task);
  ip = (void*)BPF_CORE_READ(regs, ip);

  bpf_printk("IP: 0x%lx\n", (uint64_t)ip);

  // 0:  e9 fb ff ff ff          jmp    0x0
  if(bpf_probe_write_user(ip, "\xE9\xFB\xFF\xFF\xFF", 5)) {
    bpf_printk("error: bpf_probe_write_user\n");
    return 0;
  }

  bpf_printk("success: hooked return address\n");

  return 0;
}
```
Executing the binary with the BPF program loaded lead to some surprising results (those are the logs of three distinct runs).
```
hexalinux.bin-5416    [004] ...21 10744.055618: bpf_trace_printk: IP: 0x7f08d2da3034
hexalinux.bin-5416    [004] ...21 10744.055622: bpf_trace_printk: error: bpf_probe_write_user
hexalinux.bin-5418    [009] ...21 10749.195558: bpf_trace_printk: IP: 0x7fd507691034
hexalinux.bin-5418    [009] ...21 10749.195561: bpf_trace_printk: error: bpf_probe_write_user
hexalinux.bin-5420    [004] ...21 10749.614267: bpf_trace_printk: IP: 0x7f4b510b8034
hexalinux.bin-5420    [004] ...21 10749.614270: bpf_trace_printk: error: bpf_probe_write_user
```
First, the code that makes the syscall is not writable (and thus probably not shellcode, because why bother marking SC NX?). Second, its address changes on each run. Third, the address is pretty large. Replacing the write with sending a SIGSTOP, i.e., `bpf_send_signal(SIGSTOP)`, indeed trapped the child, which was doing the write, in an endless loop. I think this is because the signal causes the write to be aborted, and a notification is sent to the parent, which then resumes the child, which in turn restarts the syscall. However, I have not read the relevant kernel code paths, so this is just a guess.

We can now inspect the child's mappings, and voila, there is a second stage program loaded at `0x800000000`, a dynamic loader, and even a libc.
```
% cat /proc/5523/maps
00200000-00204000 rwxp 00000000 fe:00 3716342                            /home/archie/ctf/hex23/gecko/hexalinux.bin
00a03000-00a08000 rw-p 00003000 fe:00 3716342                            /home/archie/ctf/hex23/gecko/hexalinux.bin
026f4000-02715000 rw-p 00000000 00:00 0                                  [heap]
800000000-800001000 r--p 00000000 00:00 0
800001000-800003000 r-xp 00000000 00:00 0
800003000-800005000 r--p 00000000 00:00 0
800005000-800006000 rw-p 00000000 00:00 0
b00000000-b00001000 r--p 00000000 fe:00 2362658                          /usr/lib/ld-linux-x86-64.so.2
b00001000-b00027000 r-xp 00001000 fe:00 2362658                          /usr/lib/ld-linux-x86-64.so.2
b00027000-b00031000 r--p 00027000 fe:00 2362658                          /usr/lib/ld-linux-x86-64.so.2
b00031000-b00033000 r--p 00031000 fe:00 2362658                          /usr/lib/ld-linux-x86-64.so.2
b00033000-b00035000 rw-p 00033000 fe:00 2362658                          /usr/lib/ld-linux-x86-64.so.2
7f335122c000-7f335122e000 rw-p 00000000 00:00 0
7f335122e000-7f3351254000 r--p 00000000 fe:00 2362697                    /usr/lib/libc.so.6
7f3351254000-7f33513ae000 r-xp 00026000 fe:00 2362697                    /usr/lib/libc.so.6
7f33513ae000-7f3351402000 r--p 00180000 fe:00 2362697                    /usr/lib/libc.so.6
7f3351402000-7f3351406000 r--p 001d3000 fe:00 2362697                    /usr/lib/libc.so.6
7f3351406000-7f3351408000 rw-p 001d7000 fe:00 2362697                    /usr/lib/libc.so.6
7f3351408000-7f3351412000 rw-p 00000000 00:00 0
7fff5b6de000-7fff5b6ff000 rw-p 00000000 00:00 0                          [stack]
7fff5b79c000-7fff5b7a0000 r--p 00000000 00:00 0                          [vvar]
7fff5b7a0000-7fff5b7a2000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```
Seems like either the parent or the child unpacked a second stage in the child's address space, mapped my system's dynamic linker and then jumped right into its entry point, instructing it to load the second stage - essentially a user-land exec, neat. The `write` syscall was thus made using standard libc functions, not shellcode.

[Dumping](https://github.com/vobst/ctf_hxn23_binary_gecko_stage_1_linux/blob/master/memdump.py) the second stage yields something that `readelf` can understand and my disassembler can load, great.

However, before starting to reverse the second stage I wanted to coerce the dynamic linker into loading [frida-gadget](https://frida.re/docs/gadget/) for me. That way I could at least do some dynamic analysis to speed up the process (Since the child gets debugged, using gdb is not an option). Since the child sanitizes its stack before it is traced by the parent, it should be possible to use gdb to skip the check and detach afterwards. To check that I could get constructor code execution, and to verify my conjecture that the dynamic linker was indeed tasked to load the second stage, I wrote a small library that checks the [auxiliary vector](https://man7.org/linux/man-pages/man3/getauxval.3.html) in its constructor, and indeed, it was set up to point at the second stage's entry point.
```c
#include <stdio.h>
#include <sys/auxv.h>

__attribute__((constructor))
void init(void)
{
  puts("Hello World");
  printf("Client base at 0x%lx\n", getauxval(AT_ENTRY));
  getchar();
}
// Hello World
// Client base at 0x800001120
```
Reversing the second stage is interesting as it is written under the assumption that it is being debugged by the parent. Thus, it is not surprising that its first instruction is a breakpoint. Again, there are no symbols in this binary, but this time all function calls are made through function pointers, even the call to `__libc_start_main` at the entry point.
```
800001120  int64_t _start(int64_t arg1, int64_t arg2, int64_t arg3) __noreturn

800001120  90                 nop       // was int3
800001121  0f1efa             nop     edx, edi
800001124  31ed               xor     ebp, ebp  {0x0}
800001126  4989d1             mov     r9, rdx
800001129  5e                 pop     rsi {__return_addr}
80000112a  4889e2             mov     rdx, rsp {arg_8}
80000112d  4883e4f0           and     rsp, 0xfffffffffffffff0
800001131  50                 push    rax {var_8}
800001132  54                 push    rsp {var_8} {var_10}
800001133  4c8d05160f0000     lea     r8, [rel data_800002050]
80000113a  488d0d9f0e0000     lea     rcx, [rel data_800001fe0]
800001141  488d3dc1000000     lea     rdi, [rel main]
800001148  ff15923e0000       call    qword [rel fp___libc_start_main]
```
Probably those function pointers are being resolved by the parent, at least the binary did not contain any relocation information that would have allowed the dynamic linker to do so. Using `frida` it was easy to dump the function pointer table and to convert the addresses back to libc symbols.
```js
Interceptor.attach(Module.findExportByName(null, "write"), {
  onEnter(args) {
    var vars = ptr("0x800004f98"); // function pointers start here

    for (let i = 0; i < 13; i++, vars = vars.add(8)) {
      let addr = vars.readPointer();
      console.log(`${vars}: ${addr}`);
      if (addr != 0) {
        console.log(" -", DebugSymbol.fromAddress(addr));
      }
    }
  },
});
```
However, for some weird reason a few of the function pointers did not correspond to exported libc symbols. Checking the corresponding libc offsets lead to some pretty awful-looking functions, luckily, cross-references outed them as some sort of simd versions of `strlen` and `strcpy`. This, and (the fact that the resolved addresses were already present in dumps that were taken while the program was stuck in my library's constructor) lead me to question my earlier assumption that the parent was responsible for resolving the addresses, but I didn't investigate this issue further, time is money.

Anyway, figuring out the symbol issue is not at all useful for solving the challenge, which turned out to be a standard crackme with the key being the correct flag.
```
800001209  int64_t main() __noreturn

800001209      // was int3
800001237      // PTRACE_TRACEME
800001237      if (ptrace(req: 0, pid: 0, addr: 1, data: nullptr) == -1)
800001240          puts(str: "Get out!!")
800001254      else
800001254          void* rax_3 = malloc(n: 0x64)
800001262          void* rax_4 = malloc(n: 0x64)
800001277          printf(fmt: "give me The correct flag: ")
80000128f          scanf(fmt: &fmt_%s, rax_3)
8000012a4          if (strlen(s: rax_3) != 0x3d)
8000012ad              puts(str: "NOOOO R3V3RS3R!")
8000012bb          if (*rax_3 != 0x46)  // F
800001342              label_800001342:
800001342              puts(str: "NOOOO R3V3RS3R!")
8000012ca          else  // L
8000012ca              if (*(rax_3 + 1) != 0x4c)
8000012ca                  goto label_800001342
8000012d9              if (*(rax_3 + 2) != 0x41)  // A
8000012d9                  goto label_800001342
8000012e8              if (*(rax_3 + 3) != 0x47)  // G
8000012e8                  goto label_800001342
8000012f7              if (*(rax_3 + 4) != 0x7b)  // {
8000012f7                  goto label_800001342
800001300              puts(str: "you are getting somewhere!")
800001326              strncpy(dst: rax_4, src: rax_3 + 5, n: strlen(s: rax_3))
800001334              if (*rax_4 != 0x44)  // D
800001fce                  label_800001fce:
800001fce                  puts(str: "NOOOO R3V3RS3R!")
8000013a8              else // the heavy checks come here
8000013a8                  char rdx_8 = *(rax_4 + 3) ^ *(rax_4 + 5) ^ *(rax_4 + 0xb) ^ *(rax_4 + 0xf) ^ *(rax_4 + 0x14) ^ *(rax_4 + 0x16) ^ *(rax_4 + 0x1a)
8000013dc                  if (sx.d(*(rax_4 + 0x2d) ^ rdx_8 ^ *(rax_4 + 0x24)) == zx.d(*(rax_4 + 0x32) == 0x6c))
8000013dc                      goto label_800001fce
800001401                  if (sx.d(*rax_4) - sx.d(*(rax_4 + 3)) != 0xfffffffb)
800001401                      goto label_800001fce
[continues for quite a bit ...]
```
Interestingly, the child was issuing a second "trace me" request to go down the familiar "Get out!" path. As the child is already being traced there is no easy way to make this request succeed (I guess even if I could get the parent to exit while keeping the child alive, `systemd`, who would become the new parent, would not be expecting the request.) Anyway, `frida` can solve that for us.
```js
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
  onLeave(ret) {
    ret.replace(0);
  },
})
```
It's obvious that those constraints don't want to be solved by hand, and thus I fried up `angr` to solve them for me. However, `cle`'s default backend uses `pyelftools`, which was throwing an exception due to a dynamic tag in a binary without a string table (or something along those lines). Whatever, I already knew that binaryninja was working fine and thus used the experimental binja backend of `cle`. From here on it is really just a few lines of code to solve the challenge.
```python
import angr
import cle
from cle.backends.binja import BinjaBin

# use binja as default loader throws exception
b = BinjaBin(
    "8251_anonymous_dump_0x800000000.bin",
    open("8251_anonymous_dump_0x800000000.bin", "rb"),
)

l = cle.Loader(b)

p = angr.Project(l)

# start of heavy checks
s = p.factory.blank_state(addr=0x1351)

# [rbp - 8] is ptr to our data +5
s.regs.rbp = 0x10000
s.mem[s.regs.rbp - 8].uint64_t = 0x11000
s.mem[0x11000].uint8_t = 0x44

# flag should be printable ascii
for i in range(1, 0x38):
    b = s.memory.load(0x11000 + i, 1)
    s.add_constraints(b < 0x7f, b >= 0x20)

sm = p.factory.simulation_manager(s)

sm.explore(find = 0x1fb4, avoid=[0x1fc7])
ss = sm.found[0]

flag = ["F", "L", "A", "G", "{"]
for i in range(0x64):
    c = chr(ss.mem[0x11000 + i].uint8_t.concrete)
    flag.append(c)
print("".join(flag)) # FLAG{DC_I_0h1nk_y0u_mad3_4_B1G_mil3sUPn3_R3V3@S3d_K33p_G01ng}
```
Finally, what remains is to validate the flag against the actual binary to make sure that we don't submit a wrong result.

## Conclusion

I'm not doing many reversing challenges and thus this binary had a lot it could teach me. Having designed some challenges myself I can really appreciate the amount of work that must have gone into creating such a handcrafted payload.

Looking back at my solution process, it seems like I spent too much time reversing the binary in a top-down approach. I could maybe have switched to the bottom-up approach, i.e., starting at the `write` syscall, a bit earlier. Anyway, I needed at least some of the top-down knowledge to be able to run `frida` and to dump the child process. On the other hand, I avoided going down the rabbit hole of reversing the unpacking process statically and in detail.

I'd actually be interested in seeing other solution approaches, but I doubt that there will be many writeups for such a small CTF.
