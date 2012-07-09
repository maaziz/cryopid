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
#include "tcpcp.h"

/* ----- Interface to low-level API ---------------------------------------- */


static int tcp_set_ici(int s,const void *ici,int size)
{
    return setsockopt(s,SOL_TCP,TCP_ICI,ici,size);
}


static int tcp_set_cp_fn(int s,int function_code)
{
    return setsockopt(s,SOL_TCP,TCP_CP_FN,&function_code,sizeof(function_code));
}


/* ----- Helper functions -------------------------------------------------- */


static int check_ici_v0(const struct tcpcp_ici *ici)
{
    if (!ici->v.major) return 0;
    errno = EINVAL;
    return -1;
}


/* ----- Public functions -------------------------------------------------- */


int tcpcp_size(const void *ici)
{
    const struct tcpcp_ici *_ici = ici;

    return ntohl(_ici->ici_length);
}


int tcpcp_create(const void *ici)
{
    int s,saved_errno;

    s = socket(PF_INET,SOCK_STREAM,0);
    if (s < 0) return s;
    if (!tcp_set_ici(s,ici,tcpcp_size(ici))) return s;
    saved_errno = errno;
    (void) close(s);
    errno = saved_errno;
    return -1;
}


int tcpcp_activate(int s)
{
    int saved_errno = errno;

    if (tcp_set_cp_fn(s,TCPCP_ACTIVATE) >= 0) return 0;
    if (errno != EALREADY) return -1;
    errno = saved_errno;
    return 0;
}


int tcpcp_set_cong(void *ici,enum tcpcp_cong_mode cong_mode)
{
    struct tcpcp_ici *_ici = ici;

    if (check_ici_v0(_ici)) return -1;
    switch (cong_mode) {
	case TCPCP_CONG_DEFAULT:
	case TCPCP_CONG_NEW:
	    _ici->v.flags &= ~htons(TCPCP_ICIF_USEPERF);
	    break;
	case TCPCP_CONG_KEEP:
	    _ici->v.flags |= htons(TCPCP_ICIF_USEPERF);
	    break;
	default:
	    errno = EINVAL;
	    return -1;
    }
    return 0;
}


int tcpcp_set_dst(void *ici,const struct sockaddr *addr)
{
    struct tcpcp_ici *_ici = ici;
    const struct sockaddr_in *sin = (struct sockaddr_in *) addr;

    if (check_ici_v0(_ici)) return -1;
    switch (addr->sa_family) {
	case AF_INET:
	    if (sin->sin_addr.s_addr != htonl(INADDR_ANY))
		_ici->id.ip.v4.ip_dst = sin->sin_addr.s_addr;
	    if (sin->sin_port) _ici->id.tcp_dport = sin->sin_port;
	    return 0;
	default:
	    errno = EAFNOSUPPORT;
	    return -1;
    }
    return 0;
}

/* vim:set ts=8 sw=4 noet: */
