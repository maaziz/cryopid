#define _LARGEFILE64_SOURCE
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <assert.h>
#include <netinet/tcp.h>
#include <linux/net.h>
#include <asm/page.h>
#include <asm/user.h>

#include "linux/tcpcp.h"

#include "cryopid.h"
#include "cpimage.h"
#include "list.h"

static int process_was_stopped = 0;

char* backup_page(pid_t target, void* addr)
{
    long* page = xmalloc(PAGE_SIZE);
    int i;
    long ret;
    for(i = 0; i < PAGE_SIZE/sizeof(long); i++) {
	ret = ptrace(PTRACE_PEEKTEXT, target, (void*)((long)addr+(i*sizeof(long))), 0);
	if (errno) {
	    perror("ptrace(PTRACE_PEEKTEXT)");
	    free(page);
	    return NULL;
	}
	page[i] = ret;
	if (ptrace(PTRACE_POKETEXT, target, (void*)((long)addr+(i*sizeof(long))), ARCH_POISON) == -1) {
	    perror("ptrace(PTRACE_POKETEXT)");
	    free(page);
	    return NULL;
	}
    }

    return (char*)page;
}

int restore_page(pid_t target, void* addr, char* page)
{
    long *p = (long*)page;
    int i;
    assert(page);
    for (i = 0; i < PAGE_SIZE/sizeof(long); i++) {
	if (ptrace(PTRACE_POKETEXT, target, (void*)((long)addr+(i*sizeof(long))), p[i]) == -1) {
	    perror("ptrace(PTRACE_POKETEXT)");
	    free(page);
	    return 0;
	}
    }
    free(page);
    return 1;
}

int memcpy_into_target(pid_t pid, void* dest, const void* src, size_t n)
{
    /* just like memcpy, but copies it into the space of the target pid */
    /* n must be a multiple of 4, or will otherwise be rounded down to be so */
    int i;
    long *d, *s;
    d = (long*) dest;
    s = (long*) src;
    for (i = 0; i < n / sizeof(long); i++) {
	if (ptrace(PTRACE_POKETEXT, pid, d+i, s[i]) == -1) {
	    perror("ptrace(PTRACE_POKETEXT)");
	    return 0;
	}
    }
    return 1;
}

#if 0
int memcpy_from_target(pid_t pid, void* dest, const void* src, size_t n)
{
    /* just like memcpy, but copies it from the space of the target pid */
    /* n must be a multiple of 4, or will otherwise be rounded down to be so */
    int i;
    long *d, *s;
    d = (long*) dest;
    s = (long*) src;
    n /= sizeof(long);
    for (i = 0; i < n; i++) {
	d[i] = ptrace(PTRACE_PEEKTEXT, pid, s+i, 0);
	if (errno) {
	    perror("ptrace(PTRACE_PEEKTEXT)");
	    return 0;
	}
    }
    return 1;
}
#else
int memcpy_from_target(pid_t pid, void* dest, const void* src, size_t n)
{
    /* just like memcpy, but copies it from the space of the target pid */
    /* n must be a multiple of 4, or will otherwise be rounded down to be so */
    int i;
    char s[32];
    int fd;
    off64_t off;
    snprintf(s, sizeof(s), "/proc/%d/mem", pid);
    off = (off64_t)(unsigned long)src;
    if ((fd = open(s, O_RDONLY)) == -1) {
	perror("open");
	abort();
    }
    if (lseek64(fd, off, SEEK_SET) == -1) {
	perror("lseek");
	abort();
    }
    i = read(fd, dest, n);
    if (i == -1) {
	perror("read");
	abort();
    }
    if (i < n) {
	fprintf(stderr, "Short read!\n");
	abort();
    }
    close(fd);
    return 1;
}
#endif

static int save_registers(pid_t pid, struct user_regs_struct *r)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, r) < 0) {
	perror("ptrace getregs");
	return errno;
    }
    return 0;
}

static int restore_registers(pid_t pid, struct user_regs_struct *r)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, r) < 0) {
	perror("ptrace setregs");
	return errno;
    }
    return 0;
}

int is_a_syscall(unsigned long inst, int canonical)
{
    if ((inst&0xffff) == 0x80cd)
	return 1;
    return 0;
}

int is_in_syscall(pid_t pid, struct user *user)
{
    long inst;

    /* If it's in the vsyscall DSO, we've most likely interrupted a syscall. */
    if (user->regs.eip >= vdso_start && user->regs.eip < vdso_end)
	return 1;

    inst = ptrace(PTRACE_PEEKDATA, pid, user->regs.eip-2, 0);
    if (errno) {
	perror("ptrace(PEEKDATA)");
	return 0;
    }

    return is_a_syscall(inst, 0);
}

void set_syscall_return(struct user* user, unsigned long val) {
    user->regs.eax = val;
}

static int process_is_stopped(pid_t pid)
{
    char buf[30];
    char mode;
    FILE *f;
    snprintf(buf, 30, "/proc/%d/stat", pid);
    f = fopen(buf, "r");
    if (f == NULL) return -1;
    fscanf(f, "%*s %*s %c", &mode);
    fclose(f);
    return mode == 'T';
}

static void start_ptrace(pid_t pid)
{
    long ret;
    int status;

    process_was_stopped = process_is_stopped(pid);

    ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
    if (ret == -1) {
	perror("Failed to ptrace");
	exit(1);
    }

    if (process_was_stopped)
	return; /* don't bother waiting for it, we'll just hang */

    ret = waitpid(pid, &status, 0);
    if (ret == -1) {
	perror("Failed to wait for child");
	exit(1);
    }
    if (!WIFSTOPPED(status)) {
	fprintf(stderr, "Failed to get child stopped.\n");
    }
}

static void end_ptrace(pid_t pid)
{
    long ret;

    ret = ptrace(PTRACE_DETACH, pid, 0, 0);
    if (ret == -1) {
	perror("Failed to detach");
	exit(1);
    }
}

void get_process(pid_t pid, int flags, struct list *process_image, long *bin_offset)
{
    int success = 0;
    char* pagebackup;
    struct user_regs_struct r;

    start_ptrace(pid);

    if (save_registers(pid, &r) < 0) {
	fprintf(stderr, "Unable to save process's registers!\n");
	goto out_ptrace;
    }

    /* The order below is very important. Do not change without good reason and
     * careful thought.
     */
    fetch_chunks_tls(pid, flags, process_image);

    /* this gives us a scribble zone: */
    fetch_chunks_vma(pid, flags, process_image, bin_offset);

    if (!scribble_zone) {
	fprintf(stderr, "[-] No suitable scribble zone could be found. Aborting.\n");
	goto out_ptrace;
    }
    pagebackup = backup_page(pid, (void*)scribble_zone);

    fetch_chunks_fd(pid, flags, process_image);

    fetch_chunks_sighand(pid, flags, process_image);
    fetch_chunks_i387_data(pid, flags, process_image);
    fetch_chunks_regs(pid, flags, process_image, process_was_stopped);

    success = 1;

    restore_page(pid, (void*)scribble_zone, pagebackup);
    restore_registers(pid, &r);
out_ptrace:
    end_ptrace(pid);
    
    if (!success)
	abort();
}

static inline unsigned long __remote_syscall(pid_t pid,
	int syscall_no, char *syscall_name,
	int use_ebx, unsigned long ebx,
	int use_ecx, unsigned long ecx,
	int use_edx, unsigned long edx,
	int use_esi, unsigned long esi,
	int use_edi, unsigned long edi)
{
    struct user_regs_struct orig_regs, regs;
    unsigned long ret;
    int status;

    if (!syscall_loc) {
	fprintf(stderr, "No syscall locations found! Cannot do remote syscall.\n");
	abort();
    }

    if (save_registers(pid, &orig_regs) < 0)
	abort();

    memcpy(&regs, &orig_regs, sizeof(regs));

    regs.eax = syscall_no;
    if (use_ebx) regs.ebx = ebx;
    if (use_ecx) regs.ecx = ecx;
    if (use_edx) regs.edx = edx;
    if (use_esi) regs.esi = esi;
    if (use_edi) regs.edi = edi;

    /* Set up registers for ptrace syscall */
    regs.eip = syscall_loc;
    if (restore_registers(pid, &regs) < 0)
	abort();

    /* Execute call */
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
	perror("ptrace singlestep");
	abort();
    }
    ret = waitpid(pid, &status, 0);
    if (ret == -1) {
	perror("Failed to wait for child");
	abort();
    }

    /* Get our new registers */
    if (save_registers(pid, &regs) < 0)
	abort();

    /* Return everything back to normal */
    if (restore_registers(pid, &orig_regs) < 0)
	abort();

    if (regs.eax < 0) {
	errno = -regs.eax;
	return -1;
    }

    return regs.eax;
}

#define __rsyscall0(type,name) \
    type __r_##name(pid_t pid) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		0,0,0,0,0,0,0,0,0,0); \
    }

#define __rsyscall1(type,name,type1,arg1) \
    type __r_##name(pid_t pid, type1 arg1) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		1, (unsigned long)arg1, \
		0,0,0,0,0,0,0,0); \
    }

#define __rsyscall2(type,name,type1,arg1,type2,arg2) \
    type __r_##name(pid_t pid, type1 arg1, type2 arg2) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		1, (unsigned long)arg1, \
		1, (unsigned long)arg2, \
		0,0,0,0,0,0); \
    }

#define __rsyscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
    type __r_##name(pid_t pid, type1 arg1, type2 arg2, type3 arg3) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		1, (unsigned long)arg1, \
		1, (unsigned long)arg2, \
		1, (unsigned long)arg3, \
		0,0,0,0); \
    }

#define __rsyscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
    type __r_##name(pid_t pid, type1 arg1, type2 arg2, type3 arg3, type4 arg4) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		1, (unsigned long)arg1, \
		1, (unsigned long)arg2, \
		1, (unsigned long)arg3, \
		1, (unsigned long)arg4, \
		0,0); \
    }

#define __rsyscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5) \
    type __r_##name(pid_t pid, type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) { \
	return (type)__remote_syscall(pid, __NR_##name, #name, \
		1, (unsigned long)arg1, \
		1, (unsigned long)arg2, \
		1, (unsigned long)arg3, \
		1, (unsigned long)arg4, \
		1, (unsigned long)arg5) \
    }

__rsyscall3(off_t, read, int, fd, void*, buf, size_t, count);
ssize_t r_read(pid_t pid, int fd, void* buf, size_t count)
{
    int off;
    off = 0;
    while (count > 0) {
	int amt = PAGE_SIZE; /* must be less than size of scribble zone */
	int err;
	if (count < amt)
	    amt = count;
	err = __r_read(pid, fd, (void*)scribble_zone, amt);
	if (err <= 0)
	    return err;
	memcpy_from_target(pid, (char*)buf + off, (void*)scribble_zone, err);
	off += err;
	count -= err;
    }
    return off;
}

__rsyscall3(off_t, lseek, int, fd, off_t, offset, int, whence);
off_t r_lseek(pid_t pid, int fd, off_t offset, int whence)
{
    return __r_lseek(pid, fd, offset, whence);
}

__rsyscall2(off_t, fcntl64, int, fd, int, cmd);
int r_fcntl(pid_t pid, int fd, int cmd)
{
    return __r_fcntl64(pid, fd, cmd);
}

__rsyscall3(int, mprotect, void*, start, size_t, len, int, flags);
int r_mprotect(pid_t pid, void* start, size_t len, int flags)
{
    return __r_mprotect(pid, start, len, flags);
}

__rsyscall4(int, rt_sigaction, int, sig, struct k_sigaction*, ksa, struct k_sigaction*, oksa, size_t, masksz);
int r_rt_sigaction(pid_t pid, int sig, struct k_sigaction *ksa, struct k_sigaction *oksa, size_t masksz)
{
    int ret;
    if (ksa)
	memcpy_into_target(pid, (void*)(scribble_zone+0x100), ksa, sizeof(*ksa));
    ret = __r_rt_sigaction(pid, sig, ksa?(void*)(scribble_zone+0x100):NULL,
	    oksa?(void*)(scribble_zone+0x100+sizeof(*ksa)):NULL, masksz);
    if (oksa)
	memcpy_from_target(pid, oksa, (void*)(scribble_zone+0x100+sizeof(*ksa)), sizeof(*oksa));

    return ret;
}

__rsyscall3(int, ioctl, int, fd, int, req, void*, val);
int r_ioctl(pid_t pid, int fd, int req, void* val)
{
    return __r_ioctl(pid, fd, req, val);
}

__rsyscall2(int, socketcall, int, call, void*, args);
int r_getsockopt(pid_t pid, int s, int level, int optname, void* optval, socklen_t *optlen)
{
    long args[5];
    int ret;

    args[0] = s;
    args[1] = level;
    args[2] = optname;
    args[3] = scribble_zone+0x60;
    args[4] = scribble_zone+0x50;

    memcpy_into_target(pid, (void*)(scribble_zone+0x40), args, sizeof(args));
    memcpy_into_target(pid, (void*)(scribble_zone+0x50), optlen, sizeof(*optlen));

    ret = __r_socketcall(pid, SYS_GETSOCKOPT, (void*)(scribble_zone+0x40));
    
    if (ret == -1)
	return -1;

    memcpy_from_target(pid, optlen, (void*)(scribble_zone+0x50), sizeof(*optlen));
    memcpy_from_target(pid, optval, (void*)(scribble_zone+0x60), *optlen);

    return ret;
}

int r_getpeername(pid_t pid, int s, struct sockaddr *name, socklen_t *namelen)
{
    long args[3];
    int ret;

    args[0] = s;
    args[1] = scribble_zone+0x20;
    args[2] = scribble_zone+0x10;

    memcpy_into_target(pid, (void*)(scribble_zone+0x0), args, sizeof(args));
    memcpy_into_target(pid, (void*)(scribble_zone+0x10), namelen, sizeof(*namelen));
    memcpy_into_target(pid, (void*)(scribble_zone+0x20), name, *namelen);

    ret = __r_socketcall(pid, SYS_GETPEERNAME, (void*)(scribble_zone+0x0));
    
    if (ret == -1)
	return -1;

    memcpy_from_target(pid, namelen, (void*)(scribble_zone+0x10), sizeof(*namelen));
    memcpy_from_target(pid, name, (void*)(scribble_zone+0x20), 1+*namelen);

    return ret;
}

int r_getsockname(pid_t pid, int s, struct sockaddr *name, socklen_t *namelen)
{
    long args[3];
    int ret;

    args[0] = s;
    args[1] = scribble_zone+0x20;
    args[2] = scribble_zone+0x10;

    memcpy_into_target(pid, (void*)(scribble_zone+0x0), args, sizeof(args));
    memcpy_into_target(pid, (void*)(scribble_zone+0x10), namelen, sizeof(*namelen));
    memcpy_into_target(pid, (void*)(scribble_zone+0x20), name, *namelen);

    ret = __r_socketcall(pid, SYS_GETSOCKNAME, (void*)(scribble_zone+0x0));
    
    if (ret == -1)
	return -1;

    memcpy_from_target(pid, namelen, (void*)(scribble_zone+0x10), sizeof(*namelen));
    memcpy_from_target(pid, name, (void*)(scribble_zone+0x20), 1+*namelen);

    return ret;
}

/* vim:set ts=8 sw=4 noet: */
