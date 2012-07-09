#include <bits/types.h>
#include <linux/unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "cryopid.h"
#include "process.h"
#include "cpimage.h"

static int get_signal_handler(pid_t pid, int sig, struct k_sigaction *ksa)
{
    int ret;

    ret = r_rt_sigaction(pid, sig, NULL, ksa, sizeof(arch_sigset_t));

    /* Error checking! */
    if (ret == -1)
	bail("rt_sigaction on target: %s", strerror(errno));

    //printf("%d: sigaction %d was 0x%lx mask 0x%x flags 0x%x restorer 0x%x\n", ret, sig, ksa->sa_hand, ksa->sa_mask.sig[0], ksa->sa_flags, ksa->sa_restorer);

    return 1;
}

void write_chunk_sighand(void *fptr, struct cp_sighand *data)
{
    write_bit(fptr, &data->sig_num, sizeof(int));
    write_bit(fptr, data->ksa, sizeof(struct k_sigaction));
}

void fetch_chunks_sighand(pid_t pid, int flags, struct list *l)
{
    struct cp_chunk *chunk;
    struct k_sigaction *ksa = NULL;
    int i;
    for (i = 1; i < MAX_SIGS; i++) {
	if (i == SIGKILL || i == SIGSTOP)
	    continue;

	if (!ksa)
	    ksa = xmalloc(sizeof(struct k_sigaction));
	if (!get_signal_handler(pid, i, ksa))
	    continue;
	chunk = xmalloc(sizeof(struct cp_chunk));
	chunk->type = CP_CHUNK_SIGHAND;
	chunk->sighand.sig_num = i;
	chunk->sighand.ksa = ksa;
	ksa = NULL;
	list_append(l, chunk);
    }
}

/* vim:set ts=8 sw=4 noet: */
