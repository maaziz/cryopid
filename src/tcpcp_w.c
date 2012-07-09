/*
 * tcpcp.c - TCP connection passing high-level API
 *
 * Written 2002 by Werner Almesberger
 * Distributed under the LGPL.
 */


#include <stddef.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/net.h>

#include "linux/tcpcp.h"

#include "cryopid.h"
#include "cpimage.h"
#include "process.h"
#include "tcpcp.h"
extern int r_getsockopt(pid_t pid, int s, int level, int optname, void* optval, socklen_t *optlen);

/* ----- Interface to low-level API ---------------------------------------- */


static int tcp_max_ici_size(pid_t pid, int s,int *size)
{
    socklen_t size_size = sizeof(*size);
    /* return getsockopt(s,SOL_TCP,TCP_MAXICISIZE,size,&size_size); */
    return r_getsockopt(pid, s, SOL_TCP, TCP_MAXICISIZE, size, &size_size);
}


static int tcp_get_ici(pid_t pid, int s, void *ici, int size)
{
    /* return getsockopt(s,SOL_TCP,TCP_ICI,ici,&size); */
    return r_getsockopt(pid, s, SOL_TCP, TCP_ICI, ici, (socklen_t*)&size);
}



/* ----- Public functions -------------------------------------------------- */

int tcpcp_size(const void *ici)
{
    const struct tcpcp_ici *_ici = ici;

    return ntohl(_ici->ici_length);
}


void *tcpcp_get(pid_t pid, int s)
{
    int size,saved_errno;
    void *ici;

    if (tcp_max_ici_size(pid, s, &size) < 0)
	return NULL;

    ici = malloc(size);
    if (!ici)
	return NULL;

    if (!tcp_get_ici(pid, s, ici,size))
	return ici;

    saved_errno = errno;
    free(ici);
    errno = saved_errno;
    return NULL;
}

/* vim:set ts=8 sw=4 noet: */
