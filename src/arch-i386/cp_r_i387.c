#include <linux/user.h>
#include <sys/ptrace.h>
#include <string.h>
#include <errno.h>

#include "cpimage.h"
#include "cryopid.h"

void read_chunk_i387_data(void *fptr, int action)
{
    struct user_i387_struct u;
    read_bit(fptr, &u, sizeof(struct user_i387_struct));

    if (action & ACTION_PRINT)
	fprintf(stderr, "i387 state (not currently restored)");

    /* FIXME : figure out how to restore i387 state */
}

/* vim:set ts=8 sw=4 noet: */
