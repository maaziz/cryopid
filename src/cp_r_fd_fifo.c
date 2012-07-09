#include <fcntl.h>
#include <unistd.h>

#include "cryopid.h"
#include "cpimage.h"
#include "tcpcp.h"

static void move_fds(int fds[2], int rfd, int wfd)
{
    if (rfd != fds[0]) {
	if (rfd == fds[1])
	    fds[1] = dup(fds[1]);
	dup2(fds[0], rfd);
	close(fds[0]);
    }
    if (wfd != fds[1]) {
	dup2(fds[1], wfd);
	close(fds[1]);
    }
}

void read_chunk_fd_fifo(void *fptr, struct cp_fd *fd, int action)
{
    read_bit(fptr, &fd->fifo.target_pid, sizeof(fd->fifo.target_pid));
    read_bit(fptr, &fd->fifo.self_other_fd, sizeof(fd->fifo.self_other_fd));
    if (action & ACTION_PRINT) {
	if (fd->fifo.target_pid == -1)
	    fprintf(stderr, "FIFO (more details to come) ");
	else
	    fprintf(stderr, "FIFO to %d on FD %d", fd->fifo.target_pid,
		    fd->fifo.self_other_fd);
    }
    if (action & ACTION_LOAD && fd->fifo.self_other_fd != -1) {
	int fds[2];
	syscall_check(pipe(fds), 0, "pipe()");
	/* Now get the FDs in the right places ... */
	if (fd->mode & O_RDONLY)
	    move_fds(fds, fd->fd, fd->fifo.self_other_fd);
	else
	    move_fds(fds, fd->fifo.self_other_fd, fd->fd);
    }
}

/* vim:set ts=8 sw=4 noet: */
