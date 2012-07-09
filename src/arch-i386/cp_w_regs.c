#include <linux/user.h>
#include <linux/unistd.h>
#include <asm/ldt.h>
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
    int* user_data_ptr;

    user_data = xmalloc(sizeof(struct user));
    user_data_ptr = (int*)user_data;

    /* We have a memory segment. We should retrieve its data */
    for(pos = 0; pos < sizeof(struct user)/sizeof(int); pos++) {
	user_data_ptr[pos] =
	    ptrace(PTRACE_PEEKUSER, pid, (void*)(pos*4), NULL);
	if (errno != 0) {
	    perror("ptrace(PTRACE_PEEKDATA): ");
	}
    }

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
