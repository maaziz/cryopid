#include <bits/types.h>
#include <linux/unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "cryopid.h"
#include "cpimage.h"

void read_chunk_sighand(void *fptr, int action)
{
    int sig_num;
    struct k_sigaction ksa;

    read_bit(fptr, &sig_num, sizeof(int));
    read_bit(fptr, &ksa, sizeof(struct k_sigaction));

    if (action & ACTION_PRINT) {
	static const char *signames[] = {
	    "invalid", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS",
	    "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM",
	    "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG",
	    "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "LOST?", "PWR", "SYS",
	};

	fprintf(stderr, "SIG%s handler: 0x%08lx flags: %lx ", signames[sig_num],
	       (long)ksa.sa_hand, ksa.sa_flags);
    }

    if (action & ACTION_LOAD) {
#ifdef __i386__
	if (emulate_tls && sig_num == SIGSEGV) {
	    install_tls_segv_handler();
	}
	else
#endif
	{
	    syscall_check(cp_sigaction(sig_num, &ksa, NULL, sizeof(arch_sigset_t)), 0,
		    "cp_sigaction(%d, ksa, NULL)", sig_num);
	}
    }
}

/* vim:set ts=8 sw=4 noet: */
