#include <sys/mman.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include "cryopid.h"

extern char *get_task_size_code;
extern int get_task_size_code_size;

static inline int myfork() {
    long ret;
    asm volatile (
	    "syscall"
	    : "=a"(ret)
	    : "0"(__NR_fork));
    return ret;
}

static inline void get_task_size_child() {
    asm volatile ("movq %4,%%r10 ; movq %5,%%r8 ; movq %6,%%r9 ; syscall"
	    :
	    : "a"(__NR_mmap),
	      "D"(0x0),
	      "S"(0x1000),
	      "d"(PROT_READ|PROT_WRITE|PROT_EXEC),
	      "g"(MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS),
	      "g"(0),
	      "g"(0));
    asm volatile (
	    "rep movsl"
	    :
	    : "S"(&get_task_size_code),
	      "D"(0x0),
	      "c"(get_task_size_code_size));
    asm volatile("jmp 0x0");
}

unsigned long get_task_size()
{
    int fds[2];
    static unsigned long task_size = 0;

    if (task_size)
	goto out;

    /* Fork off a process to figure out task_size */
    pipe(fds);
    dup2(fds[1], 142);
    close(fds[1]);
    switch (myfork()) {
	case -1:
	    perror("fork");
	    abort();
	    break;
	case 0:
	    /* child */
	    get_task_size_child();
	    /* does not return */
	    break;
    }
    /* parent */
    close(142);
    read(fds[0], &task_size, sizeof(task_size));
    close(fds[0]);
    wait(NULL);
out:
    return task_size;
}

