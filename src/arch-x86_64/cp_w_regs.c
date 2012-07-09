#include <linux/user.h>
#include <linux/unistd.h>
#include <asm/ldt.h>
#include <asm/prctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <errno.h>

#include "cpimage.h"
#include "cryopid.h"
#include "process.h"

void fetch_chunks_regs(pid_t pid, int flags, struct list *l, int stopped)
{
    struct cp_chunk *chunk = NULL;
    struct user *user_data;
    long pos;
    long* user_data_ptr;
    unsigned long base;

    user_data = xmalloc(sizeof(struct user));
    user_data_ptr = (long*)user_data;

    /* Get the user struct of the process */
    for(pos = 0; pos < sizeof(struct user)/sizeof(long); pos++) {
	user_data_ptr[pos] =
	    ptrace(PTRACE_PEEKUSER, pid, (void*)(pos*sizeof(long)), NULL);
	if (errno != 0) {
	    perror("ptrace(PTRACE_PEEKDATA): ");
	}
    }

    /* Fill in fs_base and gs_base */
    if (r_arch_prctl(pid, ARCH_GET_FS, (unsigned long)&base) == 0)
	user_data->regs.fs_base = base;
    if (r_arch_prctl(pid, ARCH_GET_GS, (unsigned long)&base) == 0)
	user_data->regs.gs_base = base;

    /* Restart a syscall on the other side */
    if (is_in_syscall(pid, user_data)) {
	fprintf(stderr, "[+] Process is probably in syscall. Returning EINTR.\n");
	set_syscall_return(user_data, -EINTR);
    }

    chunk = xmalloc(sizeof(struct cp_chunk));
    chunk->type = CP_CHUNK_REGS;
    chunk->regs.user_data = user_data;
    chunk->regs.stopped = stopped;
    list_append(l, chunk);
}

void write_chunk_regs(void *fptr, struct cp_regs *data)
{
    write_bit(fptr, data->user_data, sizeof(struct user));
    write_bit(fptr, &data->stopped, sizeof(int));
}

/* vim:set ts=8 sw=4 noet: */
