#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "cryopid.h"
#include "cpimage.h"

struct buf_data {
    FILE* f; /* So we can use buffering */
    int fd;
    int offset;
    char *mode;
    char buffer[BUFSIZ];
};

static void *buf_init(int fd, int mode)
{
    struct buf_data *rd;

    rd = xmalloc(sizeof(struct buf_data));

    switch (mode) {
	case O_RDONLY:
	    rd->mode = "r";
	    break;
	case O_WRONLY:
	    rd->mode = "w";
	    break;
	case O_RDWR:
	    rd->mode = "r+";
	    break;
	default:
	    bail("Invalid mode passed!");
    }
    rd->f = fdopen(fd, rd->mode);
    if (!rd->f)
	bail("fdopen(): %s", strerror(errno));

    setvbuf(rd->f, rd->buffer, _IOFBF, BUFSIZ);

    rd->fd = fd;

    rd->offset = 0;

    return rd;
}

static void buf_finish(void *fptr)
{
    struct buf_data *rd = fptr;

    fflush(rd->f);
    close(rd->fd);
    free(rd);
}

static int buf_read(void *fptr, void *buf, int len)
{
    int rlen, togo;
    struct buf_data *rd = fptr;
    char *p;

    togo = len;
    p = buf;
    while (togo > 0) {
	rlen = fread(p, 1, togo, rd->f);
	if (rlen <= 0)
	    bail("fread(%p, 1, %d, rd->f) failed: %s", 
		    p, len, strerror(errno));
	p += rlen;
	togo -= rlen;
    }

    rd->offset += len;

    return len;
}

static int buf_write(void *fptr, void *buf, int len)
{
    int wlen;
    struct buf_data *rd = fptr;

    wlen = fwrite(buf, 1, len, rd->f);
    return wlen;
}

static long buf_ftell(void *fptr)
{
    struct buf_data *rd = fptr;

    return rd->offset;
}

static void buf_dup2(void *fptr, int newfd)
{
    struct buf_data *rd = fptr;

    if (newfd == rd->fd)
	return;

    fflush(rd->f);
    syscall_check(dup2(rd->fd, newfd), 0, "buf_dup2(%d, %d)", rd->fd, newfd);

    /* FIXME: we leak the memory of the original FILE* ... how to fix this? */
    rd->f = fdopen(newfd, rd->mode);

    if (!rd->f)
	bail("fdopen(): %s", strerror(errno));

    close(rd->fd);
    rd->fd = newfd;

    setvbuf(rd->f, rd->buffer, _IOFBF, BUFSIZ);
}

struct stream_ops buf_ops = {
    .init = buf_init,
    .read = buf_read,
    .write = buf_write,
    .finish = buf_finish,
    .ftell = buf_ftell,
    .dup2 = buf_dup2,
};

declare_writer(buffered, buf_ops, "Writes an output file with buffering");

/* vim:set ts=8 sw=4 noet: */
