#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "cryopid.h"
#include "cpimage.h"

struct raw_data {
    int fd;
    int mode;
    int offset;
};

static void *raw_init(int fd, int mode)
{
    struct raw_data *rd;
    rd = xmalloc(sizeof(struct raw_data));

    rd->fd = fd;
    rd->mode = mode;
    rd->offset = 0;

    return rd;
}

static void raw_finish(void *fptr)
{
    struct raw_data *rd = fptr;
    close(rd->fd);
    free(rd);
}

static int raw_read(void *fptr, void *buf, int len)
{
    int rlen, togo;
    struct raw_data *rd = fptr;
    char *p;

    togo = len;
    p = buf;
    while (togo > 0) {
	rlen = read(rd->fd, p, togo);
	if (rlen <= 0)
	    bail("read(rd->fd, %p, %d) failed: %s", 
		    p, togo, strerror(errno));
	p += rlen;
	togo -= rlen;
    }

    rd->offset += len;

    return len;
}

static int raw_write(void *fptr, void *buf, int len)
{
    int wlen;
    struct raw_data *rd = fptr;

    wlen = write(rd->fd, buf, len);
    return wlen;
}

static long raw_ftell(void *fptr)
{
    struct raw_data *rd = fptr;
    return rd->offset;
}

static void raw_dup2(void *fptr, int newfd)
{
    struct raw_data *rd = fptr;

    if (newfd == rd->fd)
	return;

    syscall_check(dup2(rd->fd, newfd), 0, "raw_dup2(%d, %d)", rd->fd, newfd);

    close(rd->fd);
    rd->fd = newfd;
}

struct stream_ops raw_ops = {
    .init = raw_init,
    .read = raw_read,
    .write = raw_write,
    .finish = raw_finish,
    .ftell = raw_ftell,
    .dup2 = raw_dup2,
};

declare_writer(raw, raw_ops, "Writes directly to an output file");

/* vim:set ts=8 sw=4 noet: */
