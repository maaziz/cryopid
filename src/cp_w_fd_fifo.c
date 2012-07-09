#include "cryopid.h"
#include "cpimage.h"

/* Hash table mapping FIFO inode # -> pid owner */
#define FIFO_HASH_SIZE 2048
static struct {
    ino_t inode;
    pid_t pid[2]; int fd[2];
} fifo_hash[FIFO_HASH_SIZE] = {};

static inline int hash_fifo(int inode) {
    return inode % FIFO_HASH_SIZE;
}

static int fifo_hash_add(int inode, pid_t pid, int fd) {
    int i, j;
    assert(inode != 0);
    assert(pid != 0);
    i = j = hash_fifo(inode);
    while (1) {
	if (fifo_hash[j].inode == inode)
	    break; /* Found our match */
	if (fifo_hash[j].inode == 0)
	    break; /* Found a free spot */
	j++;
	if (j == FIFO_HASH_SIZE)
	    j = 0;
	if (j == i)
	    bail("FIFO hash table full! Eeep!");
    }
    assert(fifo_hash[j].pid[1] == 0); /* Can't add more than twice */
    if (fifo_hash[j].pid[0] == 0) {
	fifo_hash[j].pid[0] = pid;
	fifo_hash[j].fd[0] = fd;
    } else {
	fifo_hash[j].pid[1] = pid;
	fifo_hash[j].fd[1] = fd;
    }
    return j;
}

void fetch_fd_fifo(pid_t pid, int flags, int fd, int inode,
		struct cp_fifo *fifo)
{
    int hashindex;

    hashindex = fifo_hash_add(inode, pid, fd);

    fifo->self_other_fd = -1;

    if (fifo_hash[hashindex].pid[1] == 0) { /* First of our kind (inode#) */
	fifo->target_pid = -1;
	return;
    }

    fifo->target_pid = fifo_hash[hashindex].pid[0];
    if (fifo->target_pid == pid) /* Oooo, it attaches to ourself! */
	fifo->self_other_fd = fifo_hash[hashindex].fd[0];
}

void write_chunk_fd_fifo(void *fptr, struct cp_fifo *fifo)
{
    write_bit(fptr, &fifo->target_pid, sizeof(fifo->target_pid));
    write_bit(fptr, &fifo->self_other_fd, sizeof(fifo->self_other_fd));
}

/* vim:set ts=8 sw=4 noet: */
