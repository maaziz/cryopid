#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "cryopid.h"
#include "cpimage.h"
#include "process.h"

static int get_file_size(pid_t pid, int fd)
{
    int offset, sz;
    offset = r_lseek(pid, fd, 0, SEEK_CUR);
    if (offset == -1)
	goto out_err;
    sz = r_lseek(pid, fd, 0, SEEK_END);
    if (sz == -1)
	goto out_err;
    r_lseek(pid, fd, offset, SEEK_SET);
    return sz;
out_err:
    return 0;
}

static int scrape_contents(pid_t pid, int fd, int size, void* data)
{
    int offset, retval;

    retval = 0;
    offset = r_lseek(pid, fd, 0, SEEK_CUR);
    if (offset == -1)
	goto out_err;
    if (r_lseek(pid, fd, 0, SEEK_SET) < 0)
	goto out_err;
    if (r_read(pid, fd, data, size) < 0)
	goto out_err_seek;
    retval = 1;
	
out_err_seek:
    r_lseek(pid, fd, offset, SEEK_SET);
out_err:
    return retval;
}

void fetch_fd_file(pid_t pid, int flags, int fd, int inode, char *fd_path,
	struct cp_file *file)
{
    int bufsz = 512;
    int retsz;
    char *buf = NULL;

    file->filename = NULL;
    file->deleted = 0;
    file->size = get_file_size(pid, fd);
    file->contents = NULL;

    do {
	buf = xmalloc(bufsz);
	retsz = readlink(fd_path, buf, bufsz);
	if (retsz <= 0) {
	    fprintf(stderr, "Error reading FD %d: %s\n", fd, strerror(errno));
	    goto out;
	} else if (retsz < bufsz) {
	    /* Read was successful */
	    buf[retsz] = '\0';
	    file->filename = strdup(buf);
	    break;
	}
	/* Otherwise, double the buffer size and try again */
	free(buf);
	bufsz <<= 1;
    } while (bufsz <= 8192); /* Keep it sane */

    bufsz = strlen(file->filename);
    if (bufsz > 10 && strcmp(" (deleted)", file->filename+bufsz-10) == 0) {
	file->deleted = 1;
	*(file->filename+bufsz-10) = '\0';
	file->contents = xmalloc(file->size);
	if (!scrape_contents(pid, fd, file->size, file->contents)) {
	    xfree(file->contents);
	    file->contents = NULL;
	}
    }
out:
    free(buf);
}

void write_chunk_fd_file(void *fptr, struct cp_file *file)
{
    int have_contents = !!(file->contents);
    write_string(fptr, file->filename);
    write_bit(fptr, &file->deleted, sizeof(int));
    write_bit(fptr, &file->size, sizeof(int));
    write_bit(fptr, &have_contents, sizeof(int));
    if (file->contents)
	write_bit(fptr, file->contents, file->size);
}

/* vim:set ts=8 sw=4 noet: */
