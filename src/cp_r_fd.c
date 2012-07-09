#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "cryopid.h"
#include "cpimage.h"

/* Some possibly not declared defines */
#ifndef O_DIRECT
#define O_DIRECT	 040000	/* direct disk access hint */
#endif /* O_DIRECT */
#ifndef O_NOATIME
#define O_NOATIME	01000000
#endif /* O_NOATIME */

int console_fd;

static void read_chunk_fd_maxfd(void *fptr, struct cp_fd *fd, int action)
{
    if (action & ACTION_PRINT)
	fprintf(stderr, "highest FD num is %d", fd->fd);

    if (!(action & ACTION_LOAD))
	return;

    /* No read routines needed, however, we do need to move our fd */
    stream_ops->dup2(fptr, fd->fd+1);

    /* And make sure we can get a console on max_fd+2 in case we need it */
    console_fd = fd->fd+2;
    dup2(0, console_fd);
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    stdin = stdout = stderr = fdopen(console_fd, "r+");
    setvbuf(stdout, xmalloc(BUFSIZ), _IOLBF, BUFSIZ);
}

void read_chunk_fd(void *fptr, int action)
{
    struct cp_fd fd;

    read_bit(fptr, &fd.fd, sizeof(int));
    read_bit(fptr, &fd.type, sizeof(int));
    read_bit(fptr, &fd.mode, sizeof(int));
    read_bit(fptr, &fd.close_on_exec, sizeof(int));
    read_bit(fptr, &fd.fcntl_status, sizeof(int));
    read_bit(fptr, &fd.offset, sizeof(off_t));

    if (action & ACTION_PRINT)
	fprintf(stderr, "FD %d (%s) ", fd.fd,
		(fd.mode == O_RDONLY)?"r":
		(fd.mode == O_WRONLY)?"w":
		(fd.mode == O_RDWR)?"rw":
		"-");

    switch (fd.type) {
	case CP_CHUNK_FD_CONSOLE:
	    read_chunk_fd_console(fptr, &fd, action);
	    break;
	case CP_CHUNK_FD_MAXFD:
	    read_chunk_fd_maxfd(fptr, &fd, action);
	    break;
	case CP_CHUNK_FD_FILE:
	    read_chunk_fd_file(fptr, &fd, action);
	    break;
	case CP_CHUNK_FD_FIFO:
	    read_chunk_fd_fifo(fptr, &fd, action);
	    break;
	case CP_CHUNK_FD_SOCKET:
	    read_chunk_fd_socket(fptr, &fd, action);
	    break;
	default:
	    bail("Invalid FD chunk type %d!", fd.type);
    }

    if (action & ACTION_LOAD) {
	if (fd.close_on_exec != -1)
	    fcntl(fd.fd, F_SETFD, fd.close_on_exec);
	if (fd.fcntl_status != -1)
	    fcntl(fd.fd, F_SETFL, fd.fcntl_status);
	if (fd.offset == -2)
	    lseek(fd.fd, 0, SEEK_END);
	else if (fd.offset != -1)
	    lseek(fd.fd, fd.offset, SEEK_SET);
    }

    if (action & ACTION_PRINT) {
	static const int fcntl_mask =
	    O_APPEND | O_ASYNC | O_DIRECT | O_NOATIME | O_NONBLOCK;

	if (fd.close_on_exec != -1 && (fd.close_on_exec & FD_CLOEXEC))
	    fprintf(stderr, "(close-on-exec) ");

	if (fd.fcntl_status & fcntl_mask) {
	    int cnt = 0;
	    fprintf(stderr, "(");
	    if (fd.fcntl_status & O_APPEND)
		fprintf(stderr, "%sO_APPEND", cnt++?", ":"");
	    if (fd.fcntl_status & O_ASYNC)
		fprintf(stderr, "%sO_ASYNC", cnt++?", ":"");
	    if (fd.fcntl_status & O_DIRECT)
		fprintf(stderr, "%sO_DIRECT", cnt++?", ":"");
	    if (fd.fcntl_status & O_NOATIME)
		fprintf(stderr, "%sO_NOATIME", cnt++?", ":"");
	    if (fd.fcntl_status & O_NONBLOCK)
		fprintf(stderr, "%sO_NONBLOCK", cnt++?", ":"");
	    fprintf(stderr, ") ");
	}

	if (fd.offset != -1)
	    fprintf(stderr, "(offset: %ld) ", fd.offset);
    }
}

/* vim:set ts=8 sw=4 noet: */
