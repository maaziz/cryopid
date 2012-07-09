#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <zlib.h>

#include "cryopid.h"
#include "cpimage.h"

#define MAX_COMPRESSED_SIZE(x) ((x) + (x/1000 + 1) + 12)
#ifndef IN_LEN
#define IN_LEN	(128 * 1024L)
#endif
#define OUT_LEN	(MAX_COMPRESSED_SIZE(IN_LEN))

#ifdef COMPILING_STUB
#define GZIP_NO_WRITER
#else
#define GZIP_NO_READER
#endif

struct gzip_data {
    int fd;
    int mode;
    unsigned char *in, *out;
    z_stream c_stream;
    int in_len, in_used, out_len;
    int bytesin, bytesout; /* for statistics */
    int offset;
};

static void *gzip_writer_init(int fd, int mode)
{
    struct gzip_data *zd;

    if (mode == O_RDWR)
	bail("gzip writer cannot be used for simultaneous reading and writing!");

    zd = xmalloc(sizeof(struct gzip_data));
    zd->fd = fd;
    zd->mode = mode;

    memset(&zd->c_stream, 0, sizeof(zd->c_stream));
    zd->c_stream.zalloc = (alloc_func)0;
    zd->c_stream.zfree = (free_func)0;
    zd->c_stream.opaque = (voidpf)0;

#ifndef GZIP_NO_WRITER
    if (zd->mode == O_WRONLY)
    {
	if (deflateInit(&zd->c_stream, Z_DEFAULT_COMPRESSION) != Z_OK)
	    bail("deflateInit() failed!");
    }
#endif
#if !defined(GZIP_NO_READER) && !defined(GZIP_NO_WRITER)
    else
#endif
#ifndef GZIP_NO_READER
    {
	zd->c_stream.next_in = NULL;
	zd->c_stream.avail_in = 0;
	if (inflateInit(&zd->c_stream) != Z_OK)
	    bail("inflateInit() failed!");
    }
#endif

    zd->in = xmalloc(IN_LEN);
    zd->out = xmalloc(OUT_LEN);

    zd->in_len = 0;
    zd->in_used = 0;
    zd->out_len = 0;

    zd->bytesin = 0;
    zd->bytesout = 0;

    zd->offset = 0;

    return zd;
}

#ifndef GZIP_NO_READER
static void gzip_uncompress_chunk(void *fptr)
{
    struct gzip_data *zd = fptr;
    int r;

    if (zd->c_stream.avail_in == 0) {
	zd->out_len = read(zd->fd, zd->out, OUT_LEN);
	if (zd->out_len <  0)
	    bail("read(rd->fd, %p, %ld) failed: %s", zd->out, OUT_LEN, strerror(errno));

	zd->c_stream.next_in   = zd->out;
	zd->c_stream.avail_in  = zd->out_len;
    }

    zd->c_stream.next_out  = zd->in;
    zd->c_stream.avail_out = IN_LEN;

    r = inflate(&zd->c_stream, 0);

    if (r != Z_OK && r != Z_STREAM_END)
	bail("zlib decompression error: %s", zd->c_stream.msg);

    zd->in_len = IN_LEN - zd->c_stream.avail_out;
    assert(0 <= zd->in_len && zd->in_len <= IN_LEN);

    zd->in_used = 0;
}
#endif

#ifndef GZIP_NO_READER
static int gzip_writer_read(void *fptr, void *buf, int len)
{
    struct gzip_data *zd = fptr;
    int rlen;
    char *p;

    assert(zd->mode == O_RDONLY);
    rlen = len;
    p = buf;
    while (rlen > 0) {
	int bytes_ready = zd->in_len - zd->in_used;
	int x;
	if (bytes_ready == 0) {
	    gzip_uncompress_chunk(fptr);
	    bytes_ready = zd->in_len - zd->in_used;
	}

	assert(zd->in_used >= 0 && zd->in_used < zd->in_len && zd->in_len <= IN_LEN);
	if (rlen > bytes_ready)
	    x = bytes_ready;
	else
	    x = rlen;

	memcpy(p, &zd->in[zd->in_used], x);
	zd->in_used += x;
	p += x;
	rlen -= x;
    }

    zd->offset += len;

    return len;
}
#endif

#ifndef GZIP_NO_WRITER
static void gzip_compress_chunk(void *fptr, int flush)
{
    struct gzip_data *zd = fptr;
    int ret;

    zd->c_stream.next_in   = zd->in;
    zd->c_stream.avail_in  = zd->in_len;

    while (zd->c_stream.avail_in > 0) {
	zd->c_stream.next_out  = zd->out;
	zd->c_stream.avail_out = OUT_LEN;

	ret = deflate(&zd->c_stream, flush);

	if (ret != Z_OK && !(flush == Z_FINISH && ret == Z_STREAM_END))
	    bail("zlib internal compression error: %s", zd->c_stream.msg);

	zd->out_len = OUT_LEN - zd->c_stream.avail_out;

	ret = write(zd->fd, zd->out, zd->out_len);
	if (ret < 0)
	    bail("write(zd->fd, %p, %d) failed: %s",
		    zd->out, zd->out_len, strerror(errno));
	if (ret != zd->out_len)
	    bail("write(zd->fd, %p, %d) failed: Short write", zd->out, zd->out_len);
    }

    zd->in_len = 0;
    zd->bytesout += zd->out_len;
}
#endif

#ifndef GZIP_NO_WRITER
static int gzip_writer_write(void *fptr, void *buf, int len)
{
    struct gzip_data *zd = fptr;
    int wlen;
    char *p;

    assert(zd->mode == O_WRONLY);
    wlen = len;
    zd->bytesin += wlen;

    p = buf;
    while (wlen > 0) {
	int x;
	int space_remaining = IN_LEN - zd->in_len;
	if (wlen > space_remaining)
	    x = space_remaining;
	else
	    x = wlen;
	memcpy(&zd->in[zd->in_len], p, x);
	zd->in_len += x;
	p += x;
	wlen -= x;
	if (zd->in_len == IN_LEN) {
	    gzip_compress_chunk(fptr, Z_NO_FLUSH);
	}
    }

    return len;
}
#endif

static void gzip_writer_finish(void *fptr)
{
    struct gzip_data *zd = fptr;

#ifndef GZIP_NO_WRITER
    if (zd->mode == O_WRONLY && zd->in_len > 0) {
	gzip_compress_chunk(fptr, Z_FINISH);
	deflateEnd(&zd->c_stream);
    }
#endif

    free(zd->out);
    free(zd->in);

#ifndef GZIP_NO_WRITER
    if (zd->mode == O_WRONLY) {
	fprintf(stderr, "Compressed %d bytes into %d bytes",
		zd->bytesin, zd->bytesout);
	if (zd->bytesin)
	    fprintf(stderr, " (%d%% compression)", 100 - (100 * zd->bytesout / zd->bytesin));
	fprintf(stderr, "\n");
    }
#endif

    close(zd->fd);
    free(zd);
}

#ifndef GZIP_NO_READER
static long gzip_writer_ftell(void *fptr)
{
    struct gzip_data *zd = fptr;
    return zd->offset;
}
#endif

#ifndef GZIP_NO_READER
static void gzip_writer_dup2(void *fptr, int newfd)
{
    struct gzip_data *zd = fptr;

    if (newfd == zd->fd)
	return;

    syscall_check(dup2(zd->fd, newfd), 0, "gzip_dup2(%d, %d)", zd->fd, newfd);

    close(zd->fd);
    zd->fd = newfd;
}
#endif

struct stream_ops gzip_ops = {
    .init = gzip_writer_init,
#ifndef GZIP_NO_READER
    .read = gzip_writer_read,
#endif
#ifndef GZIP_NO_WRITER
    .write = gzip_writer_write,
#endif
    .finish = gzip_writer_finish,
#ifndef GZIP_NO_READER
    .ftell = gzip_writer_ftell,
    .dup2 = gzip_writer_dup2,
#endif
};

declare_writer(gzip, gzip_ops, "Compresses output using the gzip compression algorithm");

/* vim:set ts=8 sw=4 noet: */
