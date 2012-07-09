#include <asm/termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "cryopid.h"
#include "cpimage.h"

static void restore_fd_console(int fd, struct cp_console *console)
{
    /* Declare ioctl extern, as including sys/ioctl.h makes compilation unhappy :/ */
    extern int ioctl(int fd, unsigned long req, ...);
    dup2(console_fd, fd);
    ioctl(fd, TCSETS, &console->termios);
}

void read_chunk_fd_console(void *fptr, struct cp_fd *fd, int action)
{
    read_bit(fptr, &fd->console.termios, sizeof(struct termios));
    
    if (action & ACTION_PRINT)
	fprintf(stderr, "console FD ");

    if (action & ACTION_LOAD)
	restore_fd_console(fd->fd, &fd->console);
}

/* vim:set ts=8 sw=4 noet: */
