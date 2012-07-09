#include <sys/ptrace.h>
#include <asm/unistd.h>
#include <asm/termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <asm/user.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

int translate_ioctl(struct user_regs_struct *r, pid_t oldpid, pid_t newpid, int in)
{
    switch(r->ecx) {
	case TIOCSPGRP:
	    if (in) {
		pid_t ioctlpid;
		ioctlpid = ptrace(PTRACE_PEEKDATA, newpid, r->edx, 0);
		//printf("pid is %d, vs oldpid %d\n", ioctlpid, oldpid);
		if (ioctlpid == oldpid) {
		    //printf("Wooy in: %d -> %d!\n", oldpid, newpid);
		    if (ptrace(PTRACE_POKEDATA, newpid, r->edx, newpid) == -1) {
			perror("ptrace(POKEDATA)");
		    }
		    return 0; /* registers not actually modified */
		}
	    } else {
		//printf("newpid was %d returned %d\n", ptrace(PTRACE_PEEKDATA, newpid, r->edx, 0), r->eax);
	    }
	    break;
	default:
	    return 0;
    }
    return 1;
}

int translate_syscall(struct user_regs_struct *r, pid_t oldpid, pid_t newpid, int in)
{
    int syscall = r->orig_eax;
    //printf("in: %d eax: %d orig_eax: %d\n", in, r->eax, r->orig_eax);
    switch(syscall) {
	case __NR_getpid:
	    if (!in) r->eax = oldpid;
	    break;
	case __NR_ioctl:
	    return translate_ioctl(r, oldpid, newpid, in);
	default:
	    return 0;
    }
    return 1;
}

void print_status(FILE* f, int status)
{
    if (WIFEXITED(status)) {
	fprintf(f, "WIFEXITED && WEXITSTATUS == %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
	fprintf(f, "WIFSIGNALED && WTERMSIG == %d\n", WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
	fprintf(f, "WIFSTOPPED && WSTOPSIG == %d\n", WSTOPSIG(status));
    } else {
	fprintf(f, "Unknown status value: 0x%x\n", status);
    }
}

int start_supervisor(pid_t oldpid)
{
    pid_t pid;
    int status;
    pid = fork();
    switch(pid) {
	case -1:
	    perror("fork");
	    _exit(1);
	case 0:
	    break;
	default:
	    wait(NULL);
	    return 0;
    }
    pid = getppid();
    printf("pid is %d\n", pid);
    setsid();
    switch (fork()) {
	case -1: perror("fork()"); exit(1);
	case 0: break;
	case 1: _exit(0);
    }
    sigset_t allmask; /* we don't like signals */
    sigfillset(&allmask);
    sigprocmask(SIG_SETMASK, &allmask, NULL);
    /* parent will never return until the child is done */
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
	perror("ptrace(ATTACH)");
	_exit(1);
    }
    waitpid(pid, &status, 0);
    //print_status(stdout, status);
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
	perror("ptrace(PTRACE_SYSCALL)");
	exit(1);
    }
    for(;;) {
	struct user_regs_struct r;
	waitpid(pid, &status, 0);
	//printf("In: "); print_status(stdout, status);
	if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
	if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP) {
	    ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(status));
	    //printf("Stopped on signal %d\n", WSTOPSIG(status));
	    continue;
	}
	if (WIFSIGNALED(status)) {
	    ptrace(PTRACE_SYSCALL, pid, 0, WTERMSIG(status));
	    printf("Child exited on signal %d\n", WTERMSIG(status));
	    _exit(0);
	}

	if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1) {
	    perror("ptrace(PTRACE_GETREGS)");
	    exit(1);
	}
	/* entry */

	if (translate_syscall(&r, oldpid, pid, 1))
	    if (ptrace(PTRACE_SETREGS, pid, 0, &r) == -1) {
		perror("ptrace(PTRACE_SETREGS)");
		exit(1);
	    }

	if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
	    perror("ptrace(PTRACE_SYSCALL)");
	    exit(1);
	}
	waitpid(pid, &status, 0);
	//printf("Ou: "); print_status(status); 
	if (WIFEXITED(status)) _exit(WEXITSTATUS(status));

	if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1) {
	    perror("ptrace(PTRACE_GETREGS)");
	    exit(1);
	}
	if (translate_syscall(&r, oldpid, pid, 0)) {
	    if (ptrace(PTRACE_SETREGS, pid, 0, &r) == -1) {
		perror("ptrace(PTRACE_SETREGS)");
		exit(1);
	    }
	}

	if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
	    perror("ptrace(PTRACE_SYSCALL)");
	    exit(1);
	}
    }
}

/* vim:set ts=8 sw=4 noet: */
