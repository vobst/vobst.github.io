---
layout: post
title: "ret2dlresolve: Exploiting with the Dynamic Linker"
---

In this post I'm going to use the ret2dlresolve and DynELF features of
pwntools as an excuse to learn a bit about Linux's dynamic linker (DL).
This piece of low-level software is ubiquitous: it is present in
virtually every process' address space, its code is the first thing
that runs whenever a new program is executed, and it is central to the
implementation of shared libraries and user address space layout
randomization (ASLR) in Linux. Its ubiquity and position at the core of
user space make the DL an interesting subject for exploit developers
and malware authors alike.

But is there even something like *the* DL on a Linux system? Well, this
question is essentially equivalent to asking if there is *the* libc
implementation under Linux. There is not. There's
[GNU libc](https://github.com/bminor/glibc), which is used in almost all
of the well-known desktop and server distributions. There's
[musl libc](https://github.com/bminor/musl), which is used in some
lightweight, embedded or hardened distributions. There's
[Android's bionic](https://github.com/aosp-mirror/platform_bionic).
And there's [so](https://git.uclibc.org/uClibc/tree/)
[much](https://www.sourceware.org/newlib/) [more](https://www.fefe.de/dietlibc/).
We're going to study GNU's glibc (after reading its source code any
other implementation feels like kindergarten) for an amd64 processor.
So keep in mind that what you read here might not help you with pwning
your router or writing malware for your phone.

A typical assignment of the DL consists of three stages: preparing
program startup, providing a runtime environment, and cleaning up at
program shutdown. In this post we will mainly be concerned with its
role at runtime, however, let's start with a quick look at program
startup.

## Program Startup
### Loading
By its very nature, the dynamic linker lives right on the boundary of
user space, which is why we will start our journey in ring 0, the
kernel. If you choose a random program on your system, the probability
that it has an `INTERP` segment is close to one. The corresponding
program header points us to a string embedded in the binary.
`readelf` is so kind to include it in the segment overview
```
$ readelf --segments /bin/chromium

Elf file type is DYN (Position-Independent Executable file)
Entry point 0x13e0
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000002d8 0x00000000000002d8  R      0x8
  INTERP         0x0000000000000318 0x0000000000000318 0x0000000000000318
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
(snip)
```
indicating that we will find the string `/lib64/ld-linux-x86-64.so.2`
at offset `0x318` in the binary. (Note: The terms "dynamic linker"
and "interpreter" will be used interchangeably.)

To understand the purpose of this segment we'll have a look at
program loading in the kernel. If a process wants to change the
program it executes, it can do so via the `execve` system call,
passing the filesystem location of the new program as the first
argument. Eventually, the kernel passes this file to the
(absolutely gigantic)
[`load_elf_binary`](https://elixir.bootlin.com/linux/v6.0.8/source/fs/binfmt_elf.c#L824)
function, which is shown in the code listings below. As we can see,
the function first checks if the process tried to execute an ELF file
(as compared to, e.g., a script starting with `#!` or an ancient
aout binary) by inspecting the file magic [1], and then looks for
an `INTERP` segment [2]. If it is found, the interpreter is recorded in
a variable of the same name [3]. (Note: The
[`struct linux_binprm *bprm`](https://elixir.bootlin.com/linux/v6.0.8/source/include/linux/binfmts.h#L18)
is the central data structure that is used to record and pass around
all kind of information regarding the loading of a program.)
```c
static int load_elf_binary(struct linux_binprm *bprm)
{
(snip)
        struct elf_phdr *elf_ppnt, *elf_phdata, *interp_elf_phdata = NULL;
(snip)
        struct elfhdr *elf_ex = (struct elfhdr *)bprm->buf;
(snip)
	/* First of all, some simple consistency checks */
	if (memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0) // [1]
		goto out;
(snip)
	elf_ppnt = elf_phdata;
	for (i = 0; i < elf_ex->e_phnum; i++, elf_ppnt++) {
		char *elf_interpreter;
(snip)
		if (elf_ppnt->p_type != PT_INTERP) // [2]
			continue;
(snip)
                 retval = elf_read(bprm->file, elf_interpreter, elf_ppnt->p_filesz,
				  elf_ppnt->p_offset);
(snip)
                 interpreter = open_exec(elf_interpreter); // [3]
(snip)
```
Before we can map the new executable file into the process' virtual
address space we have to account for one more thing: the execution of
another program might change the security domains of the process
executing it. A classic example is the execution of a setuid or setgid
program, but Linux Security Modules (LSMs) like selinux or TOMOYO may
as well enforce their own set of security domains at this point.

(Aside: The *LSM subsystem* was introduced to facilitate the
implementation of a wide range of security models via a Loadable Kernel
Module (LKM). Originally, the feature was devised in
response to the [NSA's demand](https://lwn.net/2001/features/KernelSummit/)
for a way to enforce Mandatory Access Control (MAC) on their systems.
The kernel calls into the active LSMs at a number of carefully chosen,
pre-defined places and LSMs can use the `security` member, which you
will find in many structures, to persist state information within an
object.)

(Aside: A filesystem stores not only the file contents, but also some
file metadata. On Linux that typically includes the file's user, group
and *mode*. If the mode of an executable file has the
[`S_ISUID`](https://elixir.bootlin.com/linux/v6.0.8/source/include/uapi/linux/stat.h#L17)
bit set (and the filesystem is not mounted with the
[`nosuid`](https://elixir.bootlin.com/linux/v6.0.8/source/fs/exec.c#L1596)
option), the kernel will
[change the *effective* user and group](https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1623)
of any process executing the program to the ones of the file.)

In any case, accounting for this change has to happen, and does happen
in the call to
[`begin_new_exec`](https://elixir.bootlin.com/linux/v6.0.8/source/fs/binfmt_elf.c#L1002),
before putting anything that belongs to the new program into the
current process (see, e.g, this Serenity OS
[exploit](https://hxp.io/blog/79/hxp-CTF-2020-wisdom2/) for an example
of the kind of race conditions that can arise otherwise).

When mapping the program image into memory, note how the base is only
randomized if the program requests an interpreter [1].
(Aside: A process may use the
[personality](https://man7.org/linux/man-pages/man2/personality.2.html)
system call to, among other things, disable ASLR for itself. For
example, this is what
[gdb does for its inferior (debugee)](https://github.com/bminor/binutils-gdb/blob/8b91f9ce09bbb53ec103ec91583cea5f42f165c0/gdb/nat/linux-personality.c#L43).
This is why the additional checks [2] exits.)
```c
if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space) // [2]
		current->flags |= PF_RANDOMIZE;
(snip)
/* Now we do a little grungy work by mmapping the ELF image into
   the correct location in memory. */
for(i = 0, elf_ppnt = elf_phdata;
	i < elf_ex->e_phnum; i++, elf_ppnt++) {
(snip)
	if (elf_ppnt->p_type != PT_LOAD)
		continue;
(snip)
        vaddr = elf_ppnt->p_vaddr;
(snip)
	if (interpreter) { // [1]
		load_bias = ELF_ET_DYN_BASE;
		if (current->flags & PF_RANDOMIZE) // [2]
			load_bias += arch_mmap_rnd();
(snip)
	error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt,
			elf_prot, elf_flags, total_size);
(snip)
}

e_entry = elf_ex->e_entry + load_bias;
```
Next, we load the interpreter into the virtual memory and set the
address of the first user space instruction to the entry point of the
interpreter.
```c
if (interpreter) {
	elf_entry = load_elf_interp(interp_elf_ex,
					interpreter,
					load_bias, interp_elf_phdata,
					&arch_state);
(snip)
        elf_entry += interp_elf_ex->e_entry;
```
At this point you might ask yourself: "How is the interpreter actually
supposed to *find* the program it has to interpret?". Since their base
addresses are randomized separately this seems like an unsolvable
problem. At least I puzzled about this question for a while.

However, the answer lies in the
[call to `create_elf_tables`](https://elixir.bootlin.com/linux/v6.0.8/source/fs/binfmt_elf.c#L1292).
As we can see, this function places some useful information,
including the interpreter's base address [1] and the program's entry
point [2], in the so-called
[*auxiliary-vector*](https://lwn.net/Articles/519085/) on the stack,
of the new program just below the `envp` array.
```c
/* Create the ELF interpreter info */
elf_info = (elf_addr_t *)mm->saved_auxv;
/* update AT_VECTOR_SIZE_BASE if the number of NEW_AUX_ENT() changes */
#define NEW_AUX_ENT(id, val) \
	do { \
		*elf_info++ = id; \
		*elf_info++ = val; \
	} while (0)
(snip)
	NEW_AUX_ENT(AT_BASE, interp_load_addr); // [1]
(snip)
	NEW_AUX_ENT(AT_ENTRY, e_entry); // [2]
(snip)
         /* Put the elf_info on the stack in the right place.  */
	if (copy_to_user(sp, mm->saved_auxv, ei_index * sizeof(elf_addr_t)))
```
Finally, we prepare our return to the all-new user space by overwriting
the user context that we saved when the process trapped into the kernel.
```c
mm->start_stack = bprm->p;
(snip)
regs = current_pt_regs();
(snip)
START_THREAD(elf_ex, regs, elf_entry, bprm->p);
```
This final macro zeros out all the saved registers, except for the
stack pointer and program counter, which are set to the new stack at
`bprm->p` and the interpreter's entry point at `elf_entry`, respectively.

### Interpretation
The dynamic linker's entry point makes two calls, and then jumps to the program's `_entry` symbol, i.e., its entry point.
```assembly
0x7ffff7fcd050 <_start>:	                mov    rdi,rsp
0x7ffff7fcd053 <_start+3>:	        call   0x7ffff7fcdd70 <_dl_start>
0x7ffff7fcd058 <_dl_start_user>:	        mov    r12,rax
(snip)
0x7ffff7fcd085 <_dl_start_user+45>:	call   0x7ffff7fdc120 <_dl_init>
(snip)
0x7ffff7fcd094 <_dl_start_user+60>:	jmp    r12
```
During the first call, the linker relocates itself to wherever it was
dropped in memory by the kernel. (Aside: Due to ASLR or shared library
dependencies a program might have symbolic references whose actual value
is not known until runtime. Loosely speaking, relocation refers to the
process of filling in those values).

Afterwards, some more "sane" C code parses the auxiliary vector on and
calls
[`dl_main`](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/rtld.c#L1351),
which interprets the program (and is gigantonormous as well).
(Aside: You can execute the DL directly and specify a program as the
first argument, e.g., `$ ld.so /bin/ls`. In that case, the linker loads
the program into memory and adjusts everything (`argv`, `auxv`, ...)
to make it "look like" the program was executed directly, before
starting to interpret it.) Here we first encounter the central data
structure of the DL the list of
[`struct link_map`](https://elixir.bootlin.com/glibc/glibc-2.36/source/include/link.h#L95)
objects. Each entry describes an object in the process' virtual address
space. Among other things, it contains the base address as well as
pointers into the object's
[dynamic segment](http://www.sco.com/developers/gabi/latest/ch5.dynamic.html#dynamic_section),
which is the interface that tells the DL how the library or program
would like to be interpreted.

Some of the high-level steps in the interpretation process are:
1. [Setup of the library search path](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/rtld.c#L1743) for subsequent loads
2. Setting up the [debugger interface](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/rtld-debugger-interface.txt) ([here](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/rtld.c#L1746) and [here](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/rtld.c#L1833))
3. [Handling the pre-loading of libraries via the `ld.so.preload` file or `LD_PRELOAD` environment variable](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/rtld.c#L1844) and load order in general
4. [Loading the libraries requested by the program](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/rtld.c#L1978) and all of their dependencies
5. [Relocating all objects](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/rtld.c#L2318)

We are going to take a look at the second and fifth step as they will
be important later. If the program's dynamic segment has a `DT_DEBUG`
entry, the DL will fill it with the address of the
[`r_debug` structure](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/link.h#L40)
[1].
```c
/* Set up debugging before the debugger is notified for the first time.  */
elf_setup_debug_entry (main_map, r);
(snip)
static inline void
__attribute ((always_inline))
elf_setup_debug_entry (struct link_map *l, struct r_debug *r)
{
  if (l->l_info[DT_DEBUG] != NULL)
    l->l_info[DT_DEBUG]->d_un.d_ptr = (ElfW(Addr)) r; // [1]
}
```
A
[debugger like gdb will search for this entry](https://github.com/bminor/binutils-gdb/blob/master/gdb/solib-svr4.c#L742)
and use the structure to find the list of link maps as well as an
address that is used to facilitate breakpoints on shared library loads.
`gcc` adds this entry by default and stripping a binary does not remove
it, however, its not mandatory and nothing stops you from removing it
(`patchelf --add-debug-tag` adds it again, see also
[patchelf on GitHub](https://github.com/NixOS/patchelf)).

If the `DL_BIND_NOW` environment variable is not set and the program's
`DT_FLAGS` entry does not include the `BIND_NOW` flag, the DL skips the
relocation of functions that are called via the procedure linkage table
(PLT) at startup
([lazy linking](https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter3-29.html#chapter3-4)).
In order to be able to perform them later,
[the DL places](https://elixir.bootlin.com/glibc/glibc-2.36/source/sysdeps/x86_64/dl-machine.h#L61)
two pointers in the second and third global offset table (GOT) entry:
`got[1]` points to the link map of the object (object dependent) and
`got[2]` points to a DL internal function that performs the relocation
at runtime (object independent).

## Program Runtime

### Layz Linking
When a PLT stub is called for the first time, the corresponding GOT
entry points to the push right after the initial jump instruction.
Examining some more stubs, we can observe that each pushes a distinct
integer on the stack before they all jump to same address at the very
beginning of the PLT.
```
(gdb) x/2i 0x401030
0x401030 <read@plt+0>     jmp    QWORD PTR [rip+0x2fca]    # got[3] == 0x401036
0x401036 <read@plt+6>     push   0x0
0x40103b <read@plt+11>    jmp    0x401020
```
There, the object's
[`struct link_map *`](https://elixir.bootlin.com/glibc/glibc-2.36/source/include/link.h#L95)
(previously placed in `got[1]`) is pushed and the execution jumps to the
[`_dl_runtime_resolve` trampoline](https://elixir.bootlin.com/glibc/glibc-2.36/source/sysdeps/x86_64/dl-trampoline.h)
(previously placed in `got[2]`).
```
(gdb) x/2i 0x401020
0x401020:	push   QWORD PTR [rip+0x2fca]    # got[1]
0x401026:	jmp    QWORD PTR [rip+0x2fcc]    # got[2]
```
The trampoline calls
[`_dl_fixup`](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/dl-runtime.c#L41)
[1] (with the arguments that were pushed to the stack) and afterwards
jumps to the implementation of the function whose PLT entry was called
[2]. (Note: I am omitting some code that saves and restores the
processor state in order to make the call transparent to the program.)
```
(gdb) x/100i $rip
   0x7ffff7fe2a90 <_dl_runtime_resolve_xsavec>:	        push   rbx
   0x7ffff7fe2a91 <_dl_runtime_resolve_xsavec+1>:	         mov    rbx,rsp
(snip)
   0x7ffff7fe2afd <_dl_runtime_resolve_xsavec+109>:	mov    rsi,QWORD PTR [rbx+0x10]
   0x7ffff7fe2b01 <_dl_runtime_resolve_xsavec+113>:	mov    rdi,QWORD PTR [rbx+0x8]
   0x7ffff7fe2b05 <_dl_runtime_resolve_xsavec+117>:	call   0x7ffff7fdb620 <_dl_fixup>    // [1]
   0x7ffff7fe2b0a <_dl_runtime_resolve_xsavec+122>:	mov    r11,rax
(snip)
   0x7ffff7fe2b46 <_dl_runtime_resolve_xsavec+182>:	bnd jmp r11    // [2]
```
`_dl_fixup` has to perform two tasks: finding and returning the address of the function that was called (symbol resolution) as well as writing it to the correct GOT entry (relocation). During startup the dynamic linker placed pointers to the binary's [dynamic segment](http://www.sco.com/developers/gabi/latest/ch5.dynamic.html#dynamic_section) in the link map's [`l_info`](https://elixir.bootlin.com/glibc/glibc-2.36/source/include/link.h#L133) member. They are now used to find the relocation, symbol, version and string tables that are needed to fix up the GOT entry.
```c
_dl_fixup (struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]); // [1]
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]); // [2]

  const uintptr_t pltgot = (uintptr_t) D_PTR (l, l_info[DT_PLTGOT]); // [3]
```
Here the DL is extracting pointers to the symbol [1] and string table [2] as well as the GOT [3] from the objects's dynamic segment.
```c
const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL])
		      + reloc_offset (pltgot, reloc_arg)); // [1]
const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)]; // [2]
const ElfW(Sym) *refsym = sym;
void *const rel_addr = (void *)(l->l_addr + reloc->r_offset); // [3]
```
In the next few lines, the DL uses the integer provided by the PLT stub, the value of the `reloc_arg` variable, as an index into the [relocation table](http://www.sco.com/developers/gabi/latest/ch4.reloc.html) [1] to find the relocation entry that corresponds to the PLT stub. Two types of information are extracted from the relocation: the index of the corresponding symbol in the [symbol table](http://www.sco.com/developers/gabi/latest/ch4.symtab.html) [2] and the location where the resolved address should be written [3].

By now the DL has gathered almost all the information that is needed to find the symbol's runtime value, however, glibc also implements [symbol versioning](https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html).
```c
const ElfW(Half) *vernum =
    (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff; // [1]
version = &l->l_versions[ndx]; // [2]
```
The symbol's version is a half integer stored in another table *at the same index as the symbol table entry* [1], which can is used to find the actual version information in yet another table [2]. (Aside: In addition to the symbol name, `readelf -s` also shows the version requested by a binary, e.g., `getenv@GLIBC_2.2.5`. The tables accessed at [1] and [2] can be inspected using `readelf -V`.)

After gathering the name and version of the referenced symbol, the dynamic linker searches the loaded shared objects for a definition using [`_dl_lookup_symbol_x`](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/dl-lookup.c#L751). It should be mentioned that the DL groups loaded objects into namespaces (called scopes in the code), where the depending object's link map specifies in which namespaces a definition should be searched. The linker picks the first definition it can find, i.e., the order of namespaces and objects within them matters.
```c
result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
	    version, ELF_RTYPE_CLASS_PLT, flags, NULL);
```
On success, it returns a pointer to the defining object's link map and (over)writes the `sym`bol entry on `_dl_fixup`'s stack with the actual definition. Performing the relocation and returning the function's address is now a [twoliner](https://elixir.bootlin.com/glibc/glibc-2.36/source/sysdeps/x86_64/dl-machine.h#L225).
```c
// value = result->l_addr + sym->value
value = DL_FIXUP_MAKE_VALUE (result, SYMBOL_ADDRESS (result, sym, false));
(snip)
// return *reloc_addr = value; I <3 glibc.
return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
```

### Loading Shared Objects
The library functions of the `dl*` family, e.g., [`dlopen`](https://elixir.bootlin.com/glibc/glibc-2.36/source/dlfcn/dlopen.c#L76), are exported by `libdl`, not `libc`. They are wrappers around internal dynamic linker functions. For example, `dlopen` essentially exposes [`_dl_open`](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/dl-open.c#L822), which is also used by the dynamic linker at program startup. The real work is done inside [`dl_open_worker`](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/dl-open.c#L771), which accepts a single pointer to [a `struct dl_open_args`](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/dl-open.c#L48) describing the library to be opened. In close analogy to program startup, the procedure involves mapping and relocating the object as well as all of its dependencies, executing constructors and finally adding it to the appropriate scopes to make their symbols available to other parts of the code.

## Exploitation
### Startup - LPEs, Malware & Rootkits
A process can elevate its privileges by executing a setuid or setgid binary. As we saw earlier, the kernel places `argv` and `argc`, which are entirely supplied by the *parent* program, on the stack of the new, more privileged, program. Thus, the new (*forked*) program must treat all of them as untrusted input if it does not want to end up in the long list of setuid binaries that caused security issues, see, e.g., [PwnKit](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034) or [sudoedit](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit) for recent examples of vulnerabilities that arose from improper handling of those inputs. However, the program can be ever so careful, if the DL happily interprets environment variables like `LD_PRELOAD`, `LD_AUDIT` or `LD_LIBRARY_SEARCH_PATH` the party is over long before it gets to execute its first instruction. It looks like more than 10 years ago glibc developers had some issues with that, e.g., [CVE-2010-3847](https://seclists.org/fulldisclosure/2010/Oct/257) or [CVE-2010-3856](https://seclists.org/bugtraq/2010/Oct/200), but since then it's been silent.

At this point I asked myself: How does the DL actually know if it has to operate in *secure mode*, i.e., prevent the previous program from meddling with the execution of the new program? One option would be to use of a combination of syscalls like `get[e](uid|gid)`, however, this would miss occasions where LSMs want to enforce their own security boundaries. Another option could be to implement a dedicated syscall that provides this information to the DL on-demand, since, as we have seen earlier, the kernel already has to account for it. 

Well, close but not quite: the kernel communicates this information up to user space via the `AT_SECURE` entry in the auxiliary vector. LSMs can set the `bprm->secureexec` entry if they are of the opinion that user space code should be informed that it runs after a privilege-gaining exec. We can check the `(apparmor|cap|smack|selinux|...)_bprm_creds_for_exec` functions to see how the different modules determine whether to set the flag or not. Finally, the DL [parses](https://elixir.bootlin.com/glibc/glibc-2.36/source/sysdeps/unix/sysv/linux/dl-parse_auxv.h#L46) `auxv` to determine if it has to operate in secure mode:
```c
__libc_enable_secure = auxv_values[AT_SECURE];
```
As this is, after all, a post on an offensive security blog, not a LWN article, let's do something offensive with our newfound knowledge: You probably also hate having to type your password each time you use `sudo`, but on the other hand you also shy away from root-only or `sudo`'s password less mode for the obvious reasons. So ... wouldn't it be nice to have some sneaky way to get root whenever you want without completely jeopardizing your system's security on first sight? Well, here it is:
```
$ sudo --backdoor
# id
uid=0(root) gid=0(root) groups=0(root),1000(user)
```
where you can of course use any suid binary, restrict usage to certain users, or change the magic flag(s) to make it less obvious in the shell history. So how does it work? If we instruct the dynamic linker to print the auxiliary vector we can observe that it seems like the kernel forgot to set the `AT_SECURE` entry.
```
$ LD_SHOW_AUXV=1 sudo --backdoor
(snip)
AT_SECURE:            0
(snip)
#
```
It also looks like `sudo` requests some funny library named `libpwn.so`, whose constructor drops us the root shell.
```
$ LD_DEBUG=files sudo --backdoor
(snip)
       807:     file=./libpwn.so [0];  needed by sudo [0]
       807:     file=./libpwn.so [0];  generating link map
(snip)
       807:     calling init: ./libpwn.so
#
```
To investigate this can also launch the program under a debugger with the magic flag set.
```
$ gdb --args sudo --backdoor
(snip)
(gdb) starti
Starting program: /usr/bin/sudo --backdoor

Program stopped.
0x00007fee03d9c9c0 in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) x/8gx $rsp
0x7fff3e09a330: 0x0000000000000001      0x00007fff3e09be64
0x7fff3e09a340: 0x0000000000000000      0x00007fff3e09a538
0x7fff3e09a350: 0x00007fff3e09be7d      0x00007fff3e09be8d
0x7fff3e09a360: 0x00007fff3e09be9c      0x00007fff3e09bea9
```
Strange, it looks like the `--backdoor` flag disappeared (`argc=1` and there is only one pointer in the `argv` array). Also notice that the pointer to the first environment variable is smaller than all the other pointers. Examining it reveals what you probably already guessed.
```
(gdb) x/s 0x7fff3e09a538
0x7fff3e09a538: "LD_PRELOAD=./libpwn.so"
```
How could this happen? The short answer is that we injected some code into the kernel: It waits for our custom backdoor trigger, e.g., user *x* executes suid binary *y* with flags *z*, and mangles with the program's stack right before the `exec` system call returns to user space. The mangling is injecting a fake `LD_PRELOAD` environment variable and overwrites the `AT_SECURE` entry. (Aside: If you are interested in the details you can find the source code [here](https://github.com/vobst/golb-ret2dlresolve) and start [here](https://ebpf.io/what-is-ebpf) for an introduction to eBPF.)

In general, the DL's pre-loading mechanism and library search order has a long history of being abused by user space malware, see, e.g., [Symbiote](https://blogs.blackberry.com/en/2022/06/symbiote-a-new-nearly-impossible-to-detect-linux-threat) for a recent real-world example and [Jynx2](https://github.com/chokepoint/Jynx2) or [azazel](https://github.com/chokepoint/azazel) for classic open source rootkit implementations. Note that `LD_PRELOAD`-based rootkits usually inject into any process while the technique described above may allow for a more fine-grained approach.

### Runtime - ret2dlresolve, ret2dl_open_worker & DynELF
Throughout this section, we will use the following vulnerable program to illustrate the exploitation techniques discussed below. Sample code that implements the presented ideas can be found [here](https://github.com/vobst/golb-ret2dlresolve), but you are encouraged to hack it yourself while reading.
```c
// gcc -fno-stack-protector -no-pie -o poc poc.c

#include <unistd.h>

void main(void) {
  char b;
  read(0, &b, 0x1337);
}
```
With corresponding assembly.
```
0000000000401126 <main>:
  401126:	55                   	push   rbp
  401127:	48 89 e5             	mov    rbp,rsp
  40112a:	48 83 ec 10          	sub    rsp,0x10
  40112e:	48 8d 45 ff          	lea    rax,[rbp-0x1]
  401132:	ba 37 13 00 00       	mov    edx,0x1337
  401137:	48 89 c6             	mov    rsi,rax
  40113a:	bf 00 00 00 00       	mov    edi,0x0
  40113f:	e8 ec fe ff ff       	call   401030 <read@plt>
  401144:	90                   	nop
  401145:	c9                   	leave
  401146:	c3                   	ret
```
Note that we *disable* position independent code and stack protectors to simplify exploitation.

#### ret2dlresolve
Suppose that we have
1. an arbitrary write primitive to a known address,
2. the program binary and its base address in memory,
3. `rip` control,
4. and control of the data under `rsp`.

Those are trivial to construct in the above example. With the first and second primitive we can write fake relocation, symbol and string table entries, e.g., to the `.bss` section. We can furthermore arrange for the fake relocation entry to reference the fake symbol, and for the fake symbol to reference the fake string, by computing their offsets from the real symbol and string tables, respectively. The third and fourth primitive can then be used to place a suitably chosen `reloc_arg` on the stack before returning to the DL stub in the PLT. The DL will lookup our symbol and jump right to it. This can be used to *call any function exported by any library dependency* of the program (and any of their dependencies), i.e., the global scope. In particular, we do not need to leak library base addresses or care about the library version present on the system. You can find code to exploit the target binary [here](https://github.com/vobst/golb-ret2dlresolve). Since that is a lot of boilerplate code, pwntools provides a [helper class](https://github.com/Gallopsled/pwntools/blob/493a3e3d92/pwnlib/rop/ret2dlresolve.py#L226-L248) to automate the generation of the payload.

However, there is a problem with this technique: Remember that the symbol index in the relocation entry is also [used](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/dl-runtime.c#L75) to lookup [version information for the symbol](https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html) in another table?
```c
if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0){ // [1]
    const struct r_found_version *version = NULL;

    if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL){ // [2]
        const ElfW(Half) *vernum =
	        (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
        ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff; // [3]
	version = &l->l_versions[ndx]; // [4]
	if (version->hash == 0) // [5]
	    version = NULL;
    }
(snip)
} else {
    // value = l->l_addr + sym->value
    value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true)); // [6]
    result = l;
}
```
Since the entry sizes of the version and symbol tables are very different (0x16 and 0x2 bytes) these reads might lead to unpredictable results.

The first two entries of the array at `l->l_versions` that we access at [4] are always zero. Thus, depending on the binary, we may be able to place our fake symbol such that the read at [3] returns either zero or one. In that case the condition [5] is true. Otherwise, we may fail due to version mismatches or a segmentation fault.

Examining system binaries on Ubuntu and Arch shows that the compiler usually places the `.dynsym` and `.gnu.version` sections next to each other in the read only segment preceding the program text.
```
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
...
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000003538 0x0000000000003538  R      0x1000
...
 Section to Segment mapping:
  Segment Sections...
...
   02     .interp .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt
...
```
Thus, a fake symbol in the read write data after the text will not segfault (since segments are continuous in memory) and there is a chance that `ndx` points to a zero symbol. However, a fake symbol on the heap will almost certainly segfault since the read falls into the unmapped region above the program image and below the heap.
```
Start              End                Offset             Perm Path
0x0055dc04929000 0x0055dc0492d000 0x00000000000000 r-- /usr/bin/ls
...
0x0055dc0494d000 0x0055dc0494e000 0x00000000023000 rw- /usr/bin/ls
0x0055dc0494e000 0x0055dc0494f000 0x00000000000000 rw-
0x0055dc065b2000 0x0055dc065d3000 0x00000000000000 rw- [heap]
```

In case this becomes a problem, one can [modify the link map](https://inaz2-hatenablog-com.translate.goog/entry/2014/07/27/205322?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=de&_x_tr_pto=wapp) to [disable version checking](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/dl-runtime.c#L71) (making the comparison [2] fail), or [fake the whole link map](https://veritas501-github-io.translate.goog/2017_10_07-ret2dl_resolve%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=de&_x_tr_pto=wapp) re-using an existing GOT entry as [`l_addr`](https://elixir.bootlin.com/glibc/glibc-2.36/source/include/link.h#L100). The latter approach also requires writing the offset between the used GOT function and the target function into `st_value` of the fake symbol and forcing the [visibility check](https://elixir.bootlin.com/glibc/glibc-2.36/source/elf/dl-runtime.c#L67) [1] to fail so we do not start to traverse the link map list but rather use the local definition in [4], where `l->l_addr` is the hijacked got entry and `sym->value` is the offset in our fake symbol.

All of the above is really nothing new, in fact, the idea was described in a [Phrack article](http://phrack.org/issues/58/4.html) from 2001 (!). Over time, the glibc developers added quite some code to make heap exploitation harder, see, e.g., [safe linking](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/) for a recent example. So why does the relevant DL code still essentially looks it did 20 years ago? Can you "harden" glibc to "fix" this exploitation technique? All the information needed to add the "missing" bounds checks is available in the binary. To be concrete, the [dynamic section's](http://www.sco.com/developers/gabi/latest/ch5.dynamic.html#dynamic_section) `DT_PLTRELSZ` can be combined with `DT_RELAENT` and `DT_PLTREL` to bounds check the `reloc_arg`. Furthermore, `DT_STRSZ` can be used to check accesses to the string table. However, probably it shouldn't be patched: If an attacker has the required primitives the party is already over in a realistic scenario, so there is no point in attempting defense-in-depth (my opinion). Furthermore, `RELRO` or `DL_BIND_NOW` already mitigate this exploitation technique.

#### ret2dl_open_worker
But what if we are not satisfied with the symbols defined in the global namespace? What if our exploit needs some functionality that is painful to implement in a ROP chain but is readily available in a library that is present on the system? If the program imports `libdl` we can use ret2dlresolve to call `dlopen` with the `RTLD_GLOBAL` flag, and afterwards use the same technique to call functions in the newly loaded library (no need to go through the hassle of fiddling with handles and `dlsym` in a ROP chain). But what if `libdl` is not available? In that case we can use our primitives to fake a `struct dl_open_args` and return directly to `dl_open_worker`. You can find code to load an arbitrary library to call any function in it [here](https://github.com/vobst/golb-ret2dlresolve).

To use this in a ROP exploit, we need the address of `dl_open_worker`. One way would be to calculate it by leaking the address of `_dl_runtime_resolve` saved in the third GOT entry, this, however, requires access to the DL binary of the target system. The technique described in the next section provides an universal way to obtain this information given our primitives.

#### DynELF
During exploitation, we often use concrete bugs to construct generic primitives. Second stage techniques can then build upon those primitives to achieve more complex goals. For example, the the [pwnlib](https://github.com/Gallopsled/pwntools/tree/dev/pwnlib) Python library (from pwntools) provides an abstraction for an *arbitrary read primitive*. In order to use it, we need to implement a function that can leak one or more bytes at any given address, and then wrap it with the [`MemLeak`](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/memleak.py#L20) class. This class implements caching and various convenience functions for the handling of types. (Aside: the pwnlib automatically creates a `MemoryLeak` instance one we have constructed a [`FmtString`](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/fmtstr.py#L879) class from a format string bug.) In our example we could construct such a function by adding a second fake relocation that resolves to the `write` symbol. (You can find the source code to create a `MemLeak` instance [here](https://github.com/vobst/golb-ret2dlresolve).)

On top of this abstraction the pwnlib implements the [`DynELF`](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/dynelf.py#L95) API, which provides methods for resolving addresses of arbitrary symbols in the remote process or dumping any dynamic object present in its address space. However, if we attempt to use it in our current example, we will immediately segfault the process. To understand why, we need to dig a bit deeper into the implementation. On a high-level, it can be split into two parts: getting a foothold in the remote process' memory and mimicking `_dl_lookup_symbol` (with a few shortcuts).

In the constructor the class tries to leverage some valid pointer, which we need to provide, to find the list of `link_map` objects. There are two places in the program image where we can find this piece on information: the second GOT entry and when following the pointer to the `r_debug` symbol that the DL writes to the `DT_DEBUG` entry in the dynamic segment. Both can be found by first inferring the base address, which is done programmatically by [looking for the ELF magic on page boundaries](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/dynelf.py#L287) starting from any pointer to the image, and then [parsing the program headers to find the dynamic segment](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/dynelf.py#L368). From there on, the address of the GOT or `r_debug` structure are readily inferred. This approach works for pointers into the program image as well as any shared object (note: shared objects have no `DT_DEBUG` entry).
**Exercise**: With a slight adjustment, it should also be possible to extend the class to notice when the pointer is into the DL itself, e.g., look how the kernel infers if an ELF file is an interpreter. Then you could pivot to another technique, e.g., locating the `_rtld_global` symbol, which also holds a pointer to the program's link map. Furthermore, it should be possible to implement an algorithm that finds the link map given some valid stack address: locate the stack base by finding the `argv[0]` string, educated guess needed, on a page boundary and then parsing the auxiliary vector to find either be binary's entry point or the DL's base.

Once the link map list is found, the resolution of symbols is really just a re-implementation of DL internals (note: there some neat optimizations like a fast path for libc that attempts to leak the build id of the remote library, downloads it, and then does the lookup locally).

Back to the reason why we looked into the source code: Currently we segfault the process during the `DynELF` constructor since our primitive is leaking `0x1337` bytes at a time, which causes us to access invalid memory when reading the GOT. To circumvent this problem, we can prime `MemLeak`'s cache with targeted reads before constructing the object, and again before using functionality that parses the link maps. (Here, `leaker` is a `MemLeak` instance.)
```python
(snip)
# pre fill cache to avoid segfault
leaker._leak(binary.address, 1)                       # cache ELF and program headers
leaker._leak(binary.got.read - 0x1337, 0x1337)        # cache dynamic and GOT
dynelf = pwnlib.dynelf.DynELF(leaker, binary.address) # now save to use, parses GOT
leaker._leak(dynelf.link_map - 0x550, 1)                 # cache all the link maps
# get remote libc
libc = dynelf.libc                                    # now save to use, parses link maps
(snip)
```
Now that we have libc we are free to do what we want, e.g., constructing a more stable read primitive and dumping the remote DL to prepare a ret2dl_open_worker attack.

## CTF
To practice all of the techniques described in this post, you can try the CTF challenge defined by the following Dockerfile:
```dockerfile
FROM (???) AS builder
RUN (???)
WORKDIR /opt/ctf
COPY libabe.c ./
COPY Makefile ./
COPY poc.c ./
COPY ynetd ./
RUN make poc && make libabe.so
RUN patchelf --set-interpreter '/ld-linux-x86-64.so.2' --set-rpath '/' poc
RUN patchelf --set-interpreter '/ld-linux-x86-64.so.2' --set-rpath '/' ynetd
RUN patchelf --set-interpreter '/ld-linux-x86-64.so.2' --set-rpath '/' libabe.so

FROM scratch
COPY --from=builder /opt/ctf/poc /
COPY --from=builder /opt/ctf/libabe.so /
COPY --from=builder /opt/ctf/ynetd /
COPY --from=builder /usr/lib/ld-linux-x86-64.so.2 /
COPY --from=builder /usr/lib/libc.so.6 /
EXPOSE 1024
CMD ["/ynetd","-sh","n","-p","1024","poc"]
```
You managed to obtain the [`poc`](https://github.com/vobst/golb-ret2dlresolve) binary, but have no clue whatsoever about the libc in the remote container. However, it looks like `libabe.so` exposes a useful function.
```
# readelf -s libabe.so

Symbol table '.dynsym' contains 8 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
(snip)
     3: 000000000000105c    22 FUNC    GLOBAL DEFAULT   10 winner
(snip)
```
There are of course many ways to solve this problem, however, I think that combining the three techniques described above is certainly not the worst one.

## References

### Kernel stuff
- [LWN exec](https://lwn.net/Articles/631631/)
- [LWN auxiliary-vector](https://lwn.net/Articles/519085/)
- [Linux personality](https://man7.org/linux/man-pages/man2/personality.2.html)
- [SerentityOS mapping before creds check](https://hxp.io/blog/79/hxp-CTF-2020-wisdom2/)
- [NSA Linux](https://lwn.net/2001/features/KernelSummit/)

### ret2dlresolve
- [phrack 0xb:0x3a 2001](http://phrack.org/issues/58/4.html)
- [syst3mfailure blog](https://syst3mfailure.io/ret2dl_resolve)
- [modify the link map](https://inaz2-hatenablog-com.translate.goog/entry/2014/07/27/205322?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=de&_x_tr_pto=wapp)
- [fake the whole link map](https://veritas501-github-io.translate.goog/2017_10_07-ret2dl_resolve%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=de&_x_tr_pto=wapp)

### ELF
- [System V gABI](http://www.sco.com/developers/gabi/latest/contents.html)
- [System V ABI amd64](https://gitlab.com/x86-psABIs/x86-64-ABI)
- [Skyfree ELF reference](http://www.skyfree.org/linux/references/ELF_Format.pdf)
- [Symbol versioning](https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-PDA/LSB-PDA.junk/symversion.html)

### libc
- [glibc 2.33 sources](http://ftp.gnu.org/gnu/glibc/)
- [CVE-2010-3847](https://seclists.org/fulldisclosure/2010/Oct/257)
- [CVE-2010-3856](https://seclists.org/bugtraq/2010/Oct/200)
- [safe linking](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/)

### dynamic linker
- [Oracle on runtime linker](https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter3-1.html#scrolltoc)

### Userspace Rootkits
- [Symbiote](https://blogs.blackberry.com/en/2022/06/symbiote-a-new-nearly-impossible-to-detect-linux-threat)
- [Jynx2](https://github.com/chokepoint/Jynx2)
- [azazel](https://github.com/chokepoint/azazel)

### Misc
- [PwnKit](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034)
- [sudoedit](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)
