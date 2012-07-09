#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "cryopid.h"
#include "process.h"
#include "cpimage.h"

/* Some possibly not declared defines */
#ifndef O_DIRECT
#define O_DIRECT	 040000	/* direct disk access hint */
#endif /* O_DIRECT */
#ifndef O_NOATIME
#define O_NOATIME	01000000
#endif /* O_NOATIME */

void write_chunk_fd(void *fptr, struct cp_fd *data)
{
    write_bit(fptr, &data->fd, sizeof(int));
    write_bit(fptr, &data->type, sizeof(int));
    write_bit(fptr, &data->mode, sizeof(int));
    write_bit(fptr, &data->close_on_exec, sizeof(int));
    write_bit(fptr, &data->fcntl_status, sizeof(int));
    write_bit(fptr, &data->offset, sizeof(off_t));

    switch (data->type) {
	case CP_CHUNK_FD_CONSOLE:
	    write_chunk_fd_console(fptr, data);
	    break;
	case CP_CHUNK_FD_MAXFD:
	    /* No extra write routines needed. */
	    break;
	case CP_CHUNK_FD_FILE:
	    write_chunk_fd_file(fptr, &data->file);
	    break;
	case CP_CHUNK_FD_FIFO:
	    write_chunk_fd_fifo(fptr, &data->fifo);
	    break;
	case CP_CHUNK_FD_SOCKET:
	    write_chunk_fd_socket(fptr, &data->socket);
	    break;
	default:
	    bail("Invalid FD chunk type %d!", data->type);
    }
}

static dev_t get_term_dev(pid_t pid)
{
    FILE *f;
    char tmp_fn[80], stat_line[80], *stat_ptr;
    dev_t term_dev = 0;

    snprintf(tmp_fn, 80, "/proc/%d/stat", pid);
    memset(stat_line, 0, sizeof(stat_line));
    f = fopen(tmp_fn, "r");
    fgets(stat_line, 80, f);
    fclose(f);
    stat_ptr = strrchr(stat_line, ')');
    if (stat_ptr != NULL) {
	int tty = -1;

	stat_ptr += 2;
	sscanf(stat_ptr, "%*c %*d %*d %*d %d", &tty);
	if (tty > 0) {
	    term_dev = (dev_t)tty;
	    printf("[+] Terminal device appears to be %d:%d\n", tty >> 8, tty & 0xFF);
	}
    }
    return term_dev;
}

void fetch_chunks_fd(pid_t pid, int flags, struct list *l)
{
    struct cp_chunk *chunk = NULL;
    struct dirent *fd_dirent;
    struct stat stat_buf;
    DIR *proc_fd;
    char tmp_fn[1024];
    dev_t term_dev = get_term_dev(pid);
    int max_fd = 0;

    snprintf(tmp_fn, 30, "/proc/%d/fd", pid);
    proc_fd = opendir(tmp_fn);
    for (;;) {
	if (!chunk)
	    chunk = xmalloc(sizeof(struct cp_chunk));

	fd_dirent = readdir(proc_fd);
	if (fd_dirent == NULL)
	    break;

	if (fd_dirent->d_type != DT_LNK)
	    continue;

	chunk->fd.fd = atoi(fd_dirent->d_name);

	if (chunk->fd.fd > max_fd)
	    max_fd = chunk->fd.fd;

	/* Find out if it's open for r/w/rw */
	snprintf(tmp_fn, 1024, "/proc/%d/fd/%d", pid, chunk->fd.fd);
	lstat(tmp_fn, &stat_buf);

	if ((stat_buf.st_mode & S_IRUSR) && (stat_buf.st_mode & S_IWUSR))
	    chunk->fd.mode = O_RDWR;
	else if (stat_buf.st_mode & S_IWUSR)
	    chunk->fd.mode = O_WRONLY;
	else
	    chunk->fd.mode = O_RDONLY;

	chunk->fd.close_on_exec = r_fcntl(pid, chunk->fd.fd, F_GETFD);
	chunk->fd.fcntl_status = r_fcntl(pid, chunk->fd.fd, F_GETFL);
	chunk->fd.offset = r_lseek(pid, chunk->fd.fd, 0, SEEK_CUR);

	/* This time stat the file/fifo/socket/etc, not the link */
	if (stat(tmp_fn, &stat_buf) < 0)
	    bail("Failed to stat(%s): %s", tmp_fn, strerror(errno));

	switch (stat_buf.st_mode & S_IFMT) {
	    case S_IFCHR:
		/* FIXME - only save termios for consoles once */
		/* is our terminal? */
		if (stat_buf.st_rdev == term_dev) {
		    fetch_fd_console(pid, flags, chunk->fd.fd, &chunk->fd.console);
		    chunk->fd.type = CP_CHUNK_FD_CONSOLE;
		    fprintf(stderr, "Saved console chunk (%d).\n", chunk->fd.fd);
		} else {
		    /* hmmm. what to do, what to do? */
		    debug("Ignoring open character device %s", tmp_fn);
		    continue;
		}
		break;
	    case S_IFSOCK:
		fetch_fd_socket(pid, flags, chunk->fd.fd, stat_buf.st_ino,
			&chunk->fd.socket);
		chunk->fd.type = CP_CHUNK_FD_SOCKET;
		break;
	    case S_IFREG:
		fetch_fd_file(pid, flags, chunk->fd.fd, stat_buf.st_ino,
			tmp_fn, &chunk->fd.file);
		chunk->fd.type = CP_CHUNK_FD_FILE;
		if (stat_buf.st_size == chunk->fd.offset)
		    chunk->fd.offset = -2; /* Seek to end */
		break;
	    case S_IFIFO:
		fetch_fd_fifo(pid, flags, chunk->fd.fd, stat_buf.st_ino,
			&chunk->fd.fifo);
		chunk->fd.type = CP_CHUNK_FD_FIFO;
		break;
	    case S_IFBLK:
	    case S_IFDIR:
	    case S_IFLNK:
	    default:
		/* ummmm */
		continue;
	}

	/* Record it */
	chunk->type = CP_CHUNK_FD;
	list_append(l, chunk);
	chunk = NULL;
    }

    /* Note the highest used fd */
    chunk = xmalloc(sizeof(struct cp_chunk));
    chunk->type = CP_CHUNK_FD;
    chunk->fd.type = CP_CHUNK_FD_MAXFD;
    chunk->fd.fd = max_fd;
    list_insert(l, chunk);
}

/* vim:set ts=8 sw=4 noet: */
