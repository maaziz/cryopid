/*
 * tcpcp.h - TCP connection passing high-level API
 *
 * Written 2002 by Werner Almesberger
 * Distributed under the LGPL.
 */


#ifndef TCPCP_H
#define TCPCP_H

void *tcpcp_get(pid_t pid, int s);
int tcpcp_create(const void *ici);
int tcpcp_activate(int s);

enum tcpcp_cong_mode {
    TCPCP_CONG_DEFAULT = 0,	/* default mode; no privileges required */
    TCPCP_CONG_NEW,		/* slow start; may require CAP_NET_RAW */
    TCPCP_CONG_KEEP,		/* use data in ICI; will require CAP_NET_RAW */
};

int tcpcp_size(const void *ici);
int tcpcp_set_cong(void *ici,enum tcpcp_cong_mode cong_mode);
int tcpcp_set_dst(void *ici,const struct sockaddr *addr);

#endif /* TCPIP_H */

/* vim:set ts=8 sw=4 noet: */
