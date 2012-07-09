#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <lzo1x.h>

#include "cryopid.h"
#include "cpimage.h"

#define MAX_COMPRESSED_SIZE(x) ((x) + (x) / 64 + 16 + 3)
#ifndef IN_LEN
#define IN_LEN	(128 * 1024L)
#endif
#define OUT_LEN	(MAX_COMPRESSED_SIZE(IN_LEN))

struct lzo_data {
    int fd;
    int mode;
    lzo_byte *in, *out, *wrkmem;
    lzo_uint in_len, in_used, out_len;
    int bytesin, bytesout; /* for statistics */
    int offset;
};

static void *lzo_writer_init(int fd, int mode)
{
    struct lzo_data *ld;

    if (mode == O_RDWR)
	bail("lzo writer cannot be used for simultaneous reading and writing!");

    ld = xmalloc(sizeof(struct lzo_data));
    ld->fd = fd;
    ld->mode = mode;

    if (lzo_init() != LZO_E_OK)
	bail("lzo_init() failed!");

    ld->in = xmalloc(IN_LEN);
    ld->out = xmalloc(OUT_LEN);
    if (ld->mode == O_WRONLY)
	ld->wrkmem = xmalloc(LZO1X_1_MEM_COMPRESS);
    else
	ld->wrkmem = NULL;

    ld->in_len = 0;
    ld->in_used = 0;
    ld->out_len = 0;

    ld->bytesin = 0;
    ld->bytesout = 0;

    ld->offset = 0;

    return ld;
}

static void lzo_read_uncompressed(void *fptr)
{
    struct lzo_data *ld = fptr;
    int ret;

    ret = read(ld->fd, &ld->out_len, sizeof(lzo_uint));
    if (ret < 0)
	bail("read(rd->fd, len, %d) failed: %s", sizeof(lzo_uint), strerror(errno));
    if (ret != sizeof(lzo_uint))
	bail("read(rd->fd, len, %d) failed: Short read", sizeof(lzo_uint));

    ret = read(ld->fd, ld->out, ld->out_len);
    if (ret <  0)
	bail("read(rd->fd, %p, %d) failed: %s", 
		ld->out, ld->out_len, strerror(errno));
    if (ret != ld->out_len)
	bail("read(rd->fd, %p, %d) failed: Short read", ld->out, ld->out_len);
}

static void lzo_uncompress_chunk(void *fptr)
{
    struct lzo_data *ld = fptr;
    int r;

    r = lzo1x_decompress(ld->out, ld->out_len, ld->in, &ld->in_len, NULL);
    if (r != LZO_E_OK)
	bail("LZO decompression error: %d", r);
    assert(ld->in_len <= IN_LEN);

    ld->in_used = 0;
}

static int lzo_writer_read(void *fptr, void *buf, int len)
{
    struct lzo_data *ld = fptr;
    int rlen;
    char *p;

    assert(ld->mode == O_RDONLY);
    rlen = len;
    p = buf;
    while (rlen > 0) {
	int bytes_ready = ld->in_len - ld->in_used;
	int x;
	if (bytes_ready == 0) {
	    lzo_read_uncompressed(fptr);
	    lzo_uncompress_chunk(fptr);
	    bytes_ready = ld->in_len - ld->in_used;
	}

	assert(ld->in_used >= 0 && ld->in_used < ld->in_len && ld->in_len <= IN_LEN);
	if (rlen > bytes_ready)
	    x = bytes_ready;
	else
	    x = rlen;

	memcpy(p, &ld->in[ld->in_used], x);
	ld->in_used += x;
	p += x;
	rlen -= x;
    }

    ld->offset += len;

    return len;
}

static void lzo_compress_chunk(void *fptr)
{
    int r;
    struct lzo_data *ld = fptr;

    r = lzo1x_1_compress(ld->in, ld->in_len, ld->out, &ld->out_len, ld->wrkmem);
    if (r != LZO_E_OK)
	bail("LZF internal compression error: %d", r);

    ld->bytesout += ld->out_len;

    ld->in_len = 0;
}

static void lzo_write_compressed(void *fptr)
{
    struct lzo_data *ld = fptr;
    int ret;

    /* Write the size of the chunk first */
    ret = write(ld->fd, &ld->out_len, sizeof(int));
    if (ret < 0)
	bail("write(ld->fd, len, %d) failed: %s", sizeof(int), strerror(errno));
    if (ret != sizeof(int))
	bail("write(ld->fd, len, %d) failed: Short write", sizeof(int));

    ret = write(ld->fd, ld->out, ld->out_len);
    if (ret < 0)
	bail("write(ld->fd, %p, %d) failed: %s",
		ld->out, ld->out_len, strerror(errno));
    if (ret != ld->out_len)
	bail("write(ld->fd, %p, %d) failed: Short write", ld->out, ld->out_len);
}

static int lzo_writer_write(void *fptr, void *buf, int len)
{
    struct lzo_data *ld = fptr;
    int wlen;
    char *p;

    assert(ld->mode == O_WRONLY);
    wlen = len;
    ld->bytesin += wlen;

    p = buf;
    while (wlen > 0) {
	int x;
	int space_remaining = IN_LEN - ld->in_len;
	if (wlen > space_remaining)
	    x = space_remaining;
	else
	    x = wlen;
	memcpy(&ld->in[ld->in_len], p, x);
	ld->in_len += x;
	p += x;
	wlen -= x;
	if (ld->in_len == IN_LEN) {
	    lzo_compress_chunk(fptr);
	    lzo_write_compressed(fptr);
	}
    }

    return len;
}

static void lzo_writer_finish(void *fptr)
{
    struct lzo_data *ld = fptr;

    if (ld->mode == O_WRONLY && ld->in_len > 0) {
	lzo_compress_chunk(fptr);
	lzo_write_compressed(fptr);
    }

    free(ld->wrkmem);
    free(ld->out);
    free(ld->in);

    if (ld->mode == O_WRONLY) {
	fprintf(stderr, "Compressed %d bytes into %d bytes",
		ld->bytesin, ld->bytesout);
	if (ld->bytesin)
	    fprintf(stderr, " (%d%% compression)", 100 - (100 * ld->bytesout / ld->bytesin));
	fprintf(stderr, "\n");
    }

    close(ld->fd);
    free(ld);
}

static long lzo_writer_ftell(void *fptr)
{
    struct lzo_data *ld = fptr;
    return ld->offset;
}

static void lzo_writer_dup2(void *fptr, int newfd)
{
    struct lzo_data *ld = fptr;

    if (newfd == ld->fd)
	return;

    syscall_check(dup2(ld->fd, newfd), 0, "lzo_dup2(%d, %d)", ld->fd, newfd);

    close(ld->fd);
    ld->fd = newfd;
}

struct stream_ops lzo_ops = {
    .init = lzo_writer_init,
    .read = lzo_writer_read,
    .write = lzo_writer_write,
    .finish = lzo_writer_finish,
    .ftell = lzo_writer_ftell,
    .dup2 = lzo_writer_dup2,
};

declare_writer(lzo, lzo_ops, "Compresses output using the LZO compression algorithm");

/* vim:set ts=8 sw=4 noet: */
