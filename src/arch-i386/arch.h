#ifndef _ARCH_H_
#define _ARCH_H_

#include <sys/syscall.h>
#include <unistd.h>

/* Used to poison memory that shouldn't be used. */
#define ARCH_POISON		0xdeadbeef

#define GB		(1024*1024*1024)

#define _ARCH_NSIG       64
#define _ARCH_NSIG_BPW   32
#define _ARCH_NSIG_WORDS (_ARCH_NSIG / _ARCH_NSIG_BPW)

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
		struct k_sigaction* oksa, size_t sigsetsize)
{
	int ret;
	asm (
		"mov %2,%%ebx\n"
		"int $0x80"
		: "=a"(ret)
		: "a"(__NR_rt_sigaction), "r"(sig),
		"c"(ksa), "d"(oksa), "S"(sigsetsize)
	);
	return ret;
}

static inline unsigned long get_task_size()
{
    int stack_var;
    return (unsigned long)((((unsigned long)&stack_var + GB)/GB)*GB);
}

#define cp_sigaction rt_sigaction

static inline int sys_clone(int flags, void* child_stack) {
	return syscall(__NR_clone, flags, child_stack);
}

void *plt_resolve(void *l, char *what);
void *find_linkmap(void *elf_hdr);

#endif /* _ARCH_H_ */
