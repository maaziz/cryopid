#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

#include "cryopid.h"
#include "cpimage.h"
#include "tcpcp.h"

#define PROTO_UNIX	1
#define PROTO_TCP	6
#define PROTO_UDP	17
#define PROTO_X		666

static void read_chunk_fd_socket_tcp(void *fptr, int fd, struct cp_socket_tcp *tcp,
	int action)
{
#ifdef USE_TCPCP
    void *ici;
    int len, s;
#endif

    if (action & ACTION_PRINT)
	fprintf(stderr, "TCP socket ");

#ifdef USE_TCPCP
    read_bit(fptr, &len, sizeof(int));
    if (!len)
	return;
    ici = xmalloc(len);
    read_bit(fptr, ici, len);

    if (action & ACTION_LOAD) {
	syscall_check(s = tcpcp_create(ici), 0, "tcpcp_create");
	if (s != fd) {
	    syscall_check(dup2(s, fd), 0, "dup2");
	    close(s);
	}
	syscall_check(tcpcp_activate(fd), 0, "tcpcp_activate");
    }
#endif
}

static void read_chunk_fd_socket_unix(void *fptr, int fd,
	struct cp_socket_unix *fu, int action)
{
    struct cp_socket_unix u;
    int s;

    if (action & ACTION_PRINT)
	fprintf(stderr, "UNIX socket ");

    read_bit(fptr, &u, sizeof(u));

#ifdef USE_GTK
#endif

    if (action & ACTION_PRINT)
	fprintf(stderr, "%s -> %s ", u.sockname.sun_path, u.peername.sun_path);

    if (action & ACTION_LOAD) {
	syscall_check(s = socket(PF_UNIX, u.type, 0), 0, "socket(PF_UNIX)");
	if (u.sockname.sun_path[0]) {
	    if (bind(s, (const struct sockaddr*)&u.sockname, SUN_LEN(&u.sockname)) < 0)
		fprintf(stderr, "bind to %s: %s", u.sockname.sun_path, strerror(errno));
	}
	if (u.peername.sun_path[0]) {
	    if (connect(s, (const struct sockaddr*)&u.peername, SUN_LEN(&u.peername)) < 0)
		fprintf(stderr, "connect to %s: %s", u.peername.sun_path, strerror(errno));
	} else if (u.listening) {
	    if (listen(s, 8) < 0) { /* FIXME: can we get the backlog value somehow? */
		fprintf(stderr, "listen: %s", strerror(errno));
	    }
	}
	if (s != fd) {
	    dup2(s, fd);
	    close(s);
	}
    }
}

static void read_chunk_fd_socket_x(void *fptr, int fd, int action)
{
    if (action & ACTION_PRINT)
	fprintf(stderr, "X display socket ");

    if (action & ACTION_LOAD) {
#ifdef USE_GTK
	extern int need_gtk;
	int sp[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
	if (!sys_clone(0, 0)) { /* don't give parent notification on exit */
	    extern void x_responder(int);
	    close(sp[1]);
	    x_responder(sp[0]);
	} else
	    close(sp[0]);
	need_gtk = 1;
	if (sp[1] != fd) {
	    dup2(sp[1], fd);
	    close(sp[1]);
	}
#endif
    }
}

void read_chunk_fd_socket(void *fptr, struct cp_fd *fd, int action)
{
    read_bit(fptr, &fd->socket.proto, sizeof(int));
    switch (fd->socket.proto) {
	case PROTO_TCP:
	    read_chunk_fd_socket_tcp(fptr, fd->fd, &fd->socket.s_tcp, action);
	    break;
	case PROTO_UNIX:
	    read_chunk_fd_socket_unix(fptr, fd->fd, &fd->socket.s_unix, action);
	    break;
	case PROTO_X:
	    read_chunk_fd_socket_x(fptr, fd->fd, action);
	    break;
	case PROTO_UDP:
	default:
	    if (action & ACTION_PRINT)
		fprintf(stderr, "unsupported socket type (%d)",
			fd->socket.proto);
	    break;
    }
}

/* vim:set ts=8 sw=4 noet: */
