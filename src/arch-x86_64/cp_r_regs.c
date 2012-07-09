#include <linux/unistd.h>
#include <asm/ldt.h>
#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include "cpimage.h"
#include "cryopid.h"

int page_size;

static void load_chunk_regs(struct user *user, int stopped)
{
    char *cp, *code = (char*)TRAMPOLINE_ADDR;
    struct user_regs_struct *r = &user->regs;
    page_size = getpagesize();
#ifndef PAGE_SIZE
#define PAGE_SIZE page_size
#endif
    /* Create region for mini-resumer process. */
    syscall_check(
	(long)mmap((void*)TRAMPOLINE_ADDR, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0), 0, "mmap");

    cp = code;

    /* put return dest onto stack too */
    r->rsp-=8;
    *(long*)r->rsp = r->rip;

    /* set fs_base */
    *cp++=0x48; *cp++=0xc7; *cp++=0xc0;
    *(int*)(cp) = __NR_arch_prctl; cp+=4; /* mov foo, %rax  */
    *cp++=0x48; *cp++=0xbf;
    *(long*)(cp) = ARCH_SET_FS; cp+=8; /* mov foo, %rdi  */
    *cp++=0x48; *cp++=0xbe;
    *(long*)(cp) = r->fs_base; cp+=8; /* mov foo, %rsi  */
    *cp++=0x0f;*cp++=0x05; /* syscall */

    /* set gs_base */
    *cp++=0x48; *cp++=0xc7; *cp++=0xc0;
    *(int*)(cp) = __NR_arch_prctl; cp+=4; /* mov foo, %rax  */
    *cp++=0x48; *cp++=0xbf;
    *(long*)(cp) = ARCH_SET_GS; cp+=8; /* mov foo, %rdi  */
    *cp++=0x48; *cp++=0xbe;
    *(long*)(cp) = r->gs_base; cp+=8; /* mov foo, %rsi  */
    *cp++=0x0f;*cp++=0x05; /* syscall */

    /* put eflags onto the process' stack so we can pop it off */
    r->rsp-=8;
    *(long*)r->rsp = r->eflags;

    /* munmap our custom malloc space */
    *cp++=0x48; *cp++=0xc7; *cp++=0xc0;
    *(int*)(cp) = __NR_munmap; cp+=4; /* mov foo, %rax */
    *cp++=0x48; *cp++=0xbf;
    *(long*)(cp) = MALLOC_START; cp+=8; /* mov foo, %rdi  */
    *cp++=0x48; *cp++=0xbe;
    *(long*)(cp) = MALLOC_END-MALLOC_START; cp+=8; /* mov foo, %rsi  */
    *cp++=0x0f;*cp++=0x05; /* syscall */

    /* munmap resumer code except for us */
    *cp++=0x48; *cp++=0xc7; *cp++=0xc0;
    *(int*)(cp) = __NR_munmap; cp+=4; /* mov foo, %rax  */
    *cp++=0x48; *cp++=0xbf;
    *(long*)(cp) = RESUMER_START; cp+=8; /* mov foo, %rdi  */
    *cp++=0x48; *cp++=0xbe;
    *(long*)(cp) = RESUMER_END-RESUMER_START; cp+=8; /* mov foo, %rsi  */
    *cp++=0x0f;*cp++=0x05; /* syscall */

    /* raise a SIGSTOP if we were stopped */
    if (stopped) {
	*cp++=0x48; *cp++=0xc7; *cp++=0xc0;
	*(int*)(cp) = __NR_kill; cp+=4;     /* mov $37, %eax (kill)    */
	*cp++=0x48; *cp++=0x31; *cp++=0xff; /* xor %rdi, %rdi          */
	*cp++=0x48; *cp++=0xc7; *cp++=0xc6;
	*(int*)(cp) = SIGSTOP; cp+=4;       /* mov $19, %rsi (SIGSTOP) */
	*cp++=0x0f;*cp++=0x05;              /* syscall                 */
    }

    /* raise a SIGWINCH */
    *cp++=0x48; *cp++=0xc7; *cp++=0xc0;
    *(int*)(cp) = __NR_kill; cp+=4;     /* mov $37, %eax (kill)    */
    *cp++=0x48; *cp++=0x31; *cp++=0xff; /* xor %rdi, %rdi          */
    *cp++=0x48; *cp++=0xc7; *cp++=0xc6;
    *(int*)(cp) = SIGWINCH; cp+=4;       /* mov $19, %rsi (SIGWINCH) */
    *cp++=0x0f;*cp++=0x05;              /* syscall                 */

    /* restore registers */
    *cp++=0x49; *cp++=0xbf; *(long*)(cp) = r->r15; cp+=8;
    *cp++=0x49; *cp++=0xbe; *(long*)(cp) = r->r14; cp+=8;
    *cp++=0x49; *cp++=0xbd; *(long*)(cp) = r->r13; cp+=8;
    *cp++=0x49; *cp++=0xbc; *(long*)(cp) = r->r12; cp+=8;
    *cp++=0x48; *cp++=0xbd; *(long*)(cp) = r->rbp; cp+=8;
    *cp++=0x48; *cp++=0xbb; *(long*)(cp) = r->rbx; cp+=8;
    *cp++=0x49; *cp++=0xbb; *(long*)(cp) = r->r11; cp+=8;
    *cp++=0x49; *cp++=0xba; *(long*)(cp) = r->r10; cp+=8;
    *cp++=0x49; *cp++=0xb9; *(long*)(cp) = r->r9;  cp+=8;
    *cp++=0x49; *cp++=0xb8; *(long*)(cp) = r->r8;  cp+=8;
    *cp++=0x48; *cp++=0xb8; *(long*)(cp) = r->rax; cp+=8;
    *cp++=0x48; *cp++=0xb9; *(long*)(cp) = r->rcx; cp+=8;
    *cp++=0x48; *cp++=0xba; *(long*)(cp) = r->rdx; cp+=8;
    *cp++=0x48; *cp++=0xbe; *(long*)(cp) = r->rsi; cp+=8;
    *cp++=0x48; *cp++=0xbf; *(long*)(cp) = r->rdi; cp+=8;
    *cp++=0x48; *cp++=0xbc; *(long*)(cp) = r->rsp; cp+=8;

    *cp++=0x9d; /* pop eflags */

    /* jump back to where we were. */
    *cp++=0xc3;
}

void read_chunk_regs(void *fptr, int action)
{
    struct user user;
    int stopped;
    read_bit(fptr, &user, sizeof(struct user));
    read_bit(fptr, &stopped, sizeof(int));
    /*
    if (action & ACTION_PRINT) {
	fprintf(stderr, "(registers): Process was %sstopped\n",
		stopped?"":"not ");
	fprintf(stderr, "\teax: 0x%08lx ebx: 0x%08lx ecx: 0x%08lx edx: 0x%08lx\n",
		user.regs.eax, user.regs.ebx, user.regs.ecx, user.regs.edx);
	fprintf(stderr, "\tesi: 0x%08lx edi: 0x%08lx ebp: 0x%08lx esp: 0x%08lx\n",
		user.regs.esi, user.regs.edi, user.regs.ebp, user.regs.esp);
	fprintf(stderr, "\t ds: 0x%08x  es: 0x%08x  fs: 0x%08x  gs: 0x%08x\n",
		user.regs.ds, user.regs.es, user.regs.fs, user.regs.gs);
	fprintf(stderr, "\teip: 0x%08lx eflags: 0x%08lx",
		user.regs.eip, user.regs.eflags);
    }
    */
    if (action & ACTION_LOAD)
	load_chunk_regs(&user, stopped);
}

/* vim:set ts=8 sw=4 noet: */
