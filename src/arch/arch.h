#ifndef _ARCH_H_
#define _ARCH_H_

#include <asm/unistd.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Used to poison memory that shouldn't be used. */
#define ARCH_POISON		0xdeadbeef04c0ffee

#define _ARCH_NSIG       64
#define _ARCH_NSIG_BPW   64
#define _ARCH_NSIG_WORDS (_ARCH_NSIG / _ARCH_NSIG_BPW)

/* import some definitions */
#if 1
#ifndef __syscall
#define __syscall "syscall"
#endif

#ifndef __syscall_clobber
#define __syscall_clobber "r11","rcx","memory"
#endif

#ifndef __syscall_return
#define __syscall_return(type, res) \
    do { \
        if ((unsigned long)(res) >= (unsigned long)(-127)) { \
            errno = -(res); \
            res = -1; \
        } \
        return (type) (res); \
    } while (0)
#endif

#ifndef _syscall2
#define _syscall2(type,name,type1,arg1,type2,arg2) \
    type name(type1 arg1,type2 arg2) \
{ \
    long __res; \
    __asm__ volatile (__syscall \
            : "=a" (__res) \
            : "0" (__NR_##name),"D" ((long)(arg1)),"S" ((long)(arg2)) : __syscall_clobber ); \
    __syscall_return(type,__res); \
}
#endif

#endif

typedef struct { 
	unsigned long sig[_ARCH_NSIG_WORDS];
} arch_sigset_t;

struct k_sigaction {
    __sighandler_t sa_hand;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    arch_sigset_t sa_mask;
};

static inline int rt_sigaction(int sig, const struct k_sigaction* ksa,
	struct k_sigaction* oksa, size_t sigsetsize) {
	return syscall(__NR_rt_sigaction, sig, ksa, oksa, sigsetsize);
}

extern int r_arch_prctl(pid_t pid, int code, unsigned long addr);

extern unsigned long get_task_size();

#define cp_sigaction rt_sigaction

#endif /* _ARCH_H_ */
