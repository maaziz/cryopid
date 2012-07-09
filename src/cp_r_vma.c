#include <bits/types.h>
#include <linux/kdev_t.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "cpimage.h"
#include "cryopid.h"

int extra_prot_flags;

void read_chunk_vma(void *fptr, int action)
{
    struct cp_vma vma;
    int fd;

    read_bit(fptr, &vma.start, sizeof(unsigned long));
    read_bit(fptr, &vma.length, sizeof(unsigned long));
    read_bit(fptr, &vma.prot, sizeof(int));
    read_bit(fptr, &vma.flags, sizeof(int));
    read_bit(fptr, &vma.dev, sizeof(int));
    read_bit(fptr, &vma.pg_off, sizeof(long));
    read_bit(fptr, &vma.inode, sizeof(int));
    vma.filename = read_string(fptr, NULL, 1024);

    read_bit(fptr, &vma.have_data, sizeof(vma.have_data));
    read_bit(fptr, &vma.checksum, sizeof(vma.checksum));
    read_bit(fptr, &vma.is_heap, sizeof(vma.is_heap));

    if (action & ACTION_PRINT) {
	fprintf(stderr, "VMA %08lx-%08lx (size:%8ld) %c%c%c%c %08lx %02x:%02x %d\t%s",
		vma.start, vma.start+vma.length, vma.length,
		(vma.prot&PROT_READ)?'r':'-',
		(vma.prot&PROT_WRITE)?'w':'-',
		(vma.prot&PROT_EXEC)?'x':'-',
		(vma.prot&MAP_PRIVATE)?'p':'s',
		vma.pg_off,
		vma.dev >> 8,
		vma.dev & 0xff,
		vma.inode,
		vma.filename
		);
    }

    fd = -1;
    vma.data = (void*)vma.start;
    int try_local_lib = !(vma.prot & PROT_WRITE) && vma.have_data && vma.filename[0];
    int need_checksum = try_local_lib || (!vma.have_data && vma.filename[0]);
    if (need_checksum) {
	int good_lib = 0;
	static char buf[4096];
	/* check if the checksum matches first, else we may as well use
	 * that. */
	if ((fd = open(vma.filename, O_RDONLY)) != -1 &&
	    lseek(fd, vma.pg_off, SEEK_SET) == vma.pg_off) {
	    unsigned int c = 0;
	    int remaining = vma.length;
	    while (remaining > 0) {
		int rlen, len = sizeof(buf);
		if (len > remaining)
		    len = remaining;
		rlen = read(fd, buf, len);
		if (rlen == 0)
		    break;
		c = checksum(buf, rlen, c);
		remaining -= rlen;
	    }
	    /* Pad out the rest with NULLs */
	    memset(buf, 0, sizeof(buf));
	    while (remaining > 0) {
		int remsz = sizeof(buf);
		if (remsz > remaining)
		    remsz = remaining;
		c = checksum(buf, remsz, c);
		remaining -= remsz;
	    }
	    if (remaining == 0) {
		if (c == vma.checksum) {
		    /* we can just load it from disk, save memory */
		    if (vma.have_data) {
			vma.have_data = 0;
			discard_bit(fptr, vma.length);
		    }
		    good_lib = 1;
		} else
		    close(fd);
	    } else
		close(fd);
	}
	if (!vma.have_data && vma.filename[0] && !good_lib) {
	    bail("Aborting: Local libraries have changed (%s).\n"
		    "Resuming will almost certainly fail!",
		    vma.filename);
	}
    }
    if (vma.have_data) {
	if (vma.is_heap) {
	    /* Set the heap appropriately */
	    brk(vma.data+vma.length);
	    /* assert(sbrk(0) == vma.data+vma.length); */
	}
	syscall_check((long)mmap((void*)vma.data, vma.length,
		    PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_FIXED | vma.flags, -1, 0),
		0, "mmap(0x%lx, 0x%lx, 0x%x, 0x%x, -1, 0)",
		vma.data, vma.length, vma.prot,
		MAP_ANONYMOUS | MAP_FIXED | vma.flags);
	read_bit(fptr, vma.data, vma.length);
	syscall_check(mprotect((void*)vma.data, vma.length,
		    vma.prot | extra_prot_flags), 0, "mprotect");
    } else if (vma.filename[0]) {
	if (fd == -1)
	    syscall_check(fd = open(vma.filename, O_RDONLY), 0,
		    "open(%s)", vma.filename);
	syscall_check((long)mmap((void*)vma.data, vma.length,
		    vma.prot,
		    MAP_FIXED | vma.flags, fd, vma.pg_off),
		0, "mmap(0x%lx, 0x%lx, 0x%x, 0x%x, %d, 0x%x)",
		vma.data, vma.length, vma.prot,
		MAP_FIXED | vma.flags, fd, vma.pg_off);
	syscall_check(close(fd), 0, "close(%d)", fd);
	syscall_check(mprotect((void*)vma.data, vma.length,
		    vma.prot | extra_prot_flags), 0, "mprotect");
    } else
	bail("No source for map 0x%lx (size 0x%lx)", vma.start, vma.length);
}

/* vim:set ts=8 sw=4 noet: */
