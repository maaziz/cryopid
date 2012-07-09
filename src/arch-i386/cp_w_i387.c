#include <linux/user.h>
#include <sys/ptrace.h>
#include <string.h>
#include <errno.h>

#include "cpimage.h"
#include "cryopid.h"

void write_chunk_i387_data(void *fptr, struct cp_i387_data *data)
{
    write_bit(fptr, data->i387_data, sizeof(struct user_i387_struct));
}

void fetch_chunks_i387_data(pid_t pid, int flags, struct list *l)
{
    struct cp_chunk *chunk;
    struct user_i387_struct *i387_data;

    i387_data = xmalloc(sizeof(struct user_i387_struct));
    if (ptrace(PTRACE_GETFPREGS, pid, 0, i387_data) == -1) {
	bail("ptrace(PTRACE_PEEKDATA): %s", strerror(errno));
    }

    chunk = xmalloc(sizeof(struct cp_chunk));
    chunk->type = CP_CHUNK_I387_DATA;
    chunk->i387_data.i387_data = i387_data;
    list_append(l, chunk);
}

/* vim:set ts=8 sw=4 noet: */
