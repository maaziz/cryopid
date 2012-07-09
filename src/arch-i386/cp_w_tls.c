#include <linux/user.h>
#include <linux/unistd.h>
#include <signal.h>
#include <asm/ldt.h>
#include <asm/ucontext.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <string.h>
#include <errno.h>

#include "cpimage.h"
#include "cryopid.h"

void fetch_chunks_tls(pid_t pid, int flags, struct list *l)
{
    int i;
    struct cp_chunk *chunk;
    struct user_desc *u = NULL;
    
    for (i = 0; i < 256; i++) { /* FIXME: verify this magic number */
	if (!u) {
	    u = xmalloc(sizeof(struct user_desc));
	    memset(u, 0, sizeof(struct user_desc));
	}
	u->entry_number = i;
	if (ptrace(PTRACE_GET_THREAD_AREA, pid, i, u) == -1)
	    continue;

	chunk = xmalloc(sizeof(struct cp_chunk));
	chunk->type = CP_CHUNK_TLS;
	chunk->tls.u = u;
	list_append(l, chunk);
	u = NULL;
    }
}

void write_chunk_tls(void *fptr, struct cp_tls *data)
{
    write_bit(fptr, data->u, sizeof(struct user_desc));
}

/* vim:set ts=8 sw=4 noet: */
