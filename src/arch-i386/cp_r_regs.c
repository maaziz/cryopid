#include <linux/user.h>
#include <linux/unistd.h>
#include <asm/ldt.h>
#include <sys/mman.h>
#include <sys/ptrace.h>

#include "cpimage.h"
#include "cryopid.h"

#ifdef USE_GTK
extern int need_gtk;
#endif

static void load_chunk_regs(struct user *user, int stopped)
{
    char *cp, *code = (char*)TRAMPOLINE_ADDR;
    struct user_regs_struct *r = &user->regs;

    /* Create region for mini-resumer process. */
    syscall_check(
	(int)mmap((void*)TRAMPOLINE_ADDR, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0), 0, "mmap");

    cp = code;

    /* put eflags onto the process' stack so we can pop it off */
    r->esp-=4;
    *(long*)r->esp = r->eflags;
    
    /* set up gs */
    if (!emulate_tls && r->gs != 0) {
	*cp++=0x66;*cp++=0xb8; *(short*)(cp) = r->gs; cp+=2; /* mov foo, %eax  */
	*cp++=0x8e;*cp++=0xe8; /* mov %eax, %gs */
    }

    *cp++=0xbd;*(long*)(cp) = r->ebp; cp+=4; /* mov foo, %ebp  */
    *cp++=0xbc;*(long*)(cp) = r->esp; cp+=4; /* mov foo, %esp  */

#ifdef USE_GTK
    if (need_gtk) {
	extern long cryopid_migrate_gtk_windows;
	*cp++=0xb8;*(long*)(cp) = (long)&cryopid_migrate_gtk_windows; cp+=4; /* mov addr,%eax */
	*cp++=0xff;*cp++=0xd0; /* call *%eax */
    }
#endif /* USE_GTK */

    /* munmap our custom malloc space */
    *cp++=0xb8;*(long*)(cp) = __NR_munmap; cp+=4; /* mov foo, %eax  */
    *cp++=0xbb;*(long*)(cp) = MALLOC_START; cp+=4; /* mov foo, %ebx  */
    *cp++=0xb9;*(long*)(cp) = MALLOC_END-MALLOC_START; cp+=4; /* mov foo, %ecx  */
    *cp++=0xcd;*cp++=0x80; /* int $0x80 */

    /* munmap resumer code except for us - except when we're needed for our
     * segvhandler */
    if (!emulate_tls) {
	*cp++=0xb8;*(long*)(cp) = __NR_munmap; cp+=4; /* mov foo, %eax  */
	*cp++=0xbb;*(long*)(cp) = RESUMER_START; cp+=4; /* mov foo, %ebx  */
	*cp++=0xb9;*(long*)(cp) = RESUMER_END-RESUMER_START; cp+=4; /* mov foo, %ecx  */
	*cp++=0xcd;*cp++=0x80; /* int $0x80 */
    }

    /* restore registers */
    *cp++=0xba;*(long*)(cp) = r->edx; cp+=4; /* mov foo, %edx  */
    *cp++=0xbe;*(long*)(cp) = r->esi; cp+=4; /* mov foo, %esi  */
    *cp++=0xbf;*(long*)(cp) = r->edi; cp+=4; /* mov foo, %edi  */
    *cp++=0xbd;*(long*)(cp) = r->ebp; cp+=4; /* mov foo, %ebp  */
    *cp++=0xbc;*(long*)(cp) = r->esp; cp+=4; /* mov foo, %esp  */

    /* raise a SIGSTOP if we were stopped */
    if (stopped) {
	*cp++=0xb8;*(long*)(cp) = __NR_kill; cp+=4; /* mov $37, %eax (kill) */
	*cp++=0x31;*cp++=0xdb;               /* xor %ebx, %ebx       */
	*cp++=0xb9;*(long*)(cp) = SIGSTOP; cp+=4; /* mov $19, %ecx (SIGSTOP) */
	*cp++=0xcd;*cp++=0x80;               /* int $0x80 */
    }

    /* raise a SIGWINCH */
    *cp++=0xb8;*(long*)(cp) = __NR_kill; cp+=4; /* mov $37, %eax (kill) */
    *cp++=0x31;*cp++=0xdb;               /* xor %ebx, %ebx       */
    *cp++=0xb9;*(long*)(cp) = SIGWINCH; cp+=4; /* mov $19, %ecx (SIGWINCH) */
    *cp++=0xcd;*cp++=0x80;               /* int $0x80 */

    /* and the rest of the registers we might have just modified */
    *cp++=0xb8;*(long*)(cp) = r->eax; cp+=4; /* mov foo, %eax  */
    *cp++=0xbb;*(long*)(cp) = r->ebx; cp+=4; /* mov foo, %ebx  */
    *cp++=0xb9;*(long*)(cp) = r->ecx; cp+=4; /* mov foo, %ecx  */

    *cp++=0x9d; /* pop eflags */

    /* jump back to where we were. */
    *cp++=0xea;
    *(unsigned long*)(cp) = r->eip; cp+= 4;
    asm("mov %%cs,%w0": "=q"(r->cs)); /* ensure we use the right CS for the current kernel */
    *(unsigned short*)(cp) = r->cs; cp+= 2; /* jmp cs:foo */
    syscall_check(
	(int)mprotect((void*)TRAMPOLINE_ADDR, PAGE_SIZE, PROT_READ|PROT_EXEC),
	    0, "mmap");
}

void read_chunk_regs(void *fptr, int action)
{
    struct user user;
    int stopped;
    read_bit(fptr, &user, sizeof(struct user));
    read_bit(fptr, &stopped, sizeof(int));
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
    if (action & ACTION_LOAD)
	load_chunk_regs(&user, stopped);
}

/* vim:set ts=8 sw=4 noet: */
