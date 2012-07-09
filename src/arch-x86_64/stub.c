#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <asm/prctl.h>
#include <asm/page.h>
#include <errno.h>

#include "cryopid.h"
#include "cpimage.h"
#include "process.h"

#if !arch_prctl
_syscall2(int, arch_prctl, int, code, unsigned long, addr);
#endif

int page_size;

void set_fs()
{
    extern int arch_prctl(int code, unsigned long addr);
    unsigned long tls_seg;
    unsigned long brk, brk_start;
    unsigned long cur_fs;
    /* This assumes that our TLS segment is in the heap, and the heap is currently
     * less than a page big... it could break in awful ways if not...
     *
     * Our FS segment is normally mapped at the top of the heap, but because the
     * binary is modified to place the heap where the executable had it, the FS
     * segment gets unmapped when we relocate the stub. Hence we have to relocate
     * our TLS segment first.
     */
    page_size = getpagesize();
#ifndef PAGE_SIZE
#define PAGE_SIZE page_size
#endif
    brk = (unsigned long)sbrk(0);
    tls_seg = (unsigned long)xmalloc(PAGE_SIZE);
    arch_prctl(ARCH_GET_FS, (long)&cur_fs);
    brk_start = brk & ~(PAGE_SIZE-1);
    memcpy((void*)tls_seg, (void*)brk_start, brk-brk_start);
    arch_prctl(ARCH_SET_FS, tls_seg + (cur_fs - brk_start));
}

void seek_to_image(int fd)
{
    Elf64_Ehdr e;
    Elf64_Shdr s;
    int i;
    char* strtab;

    syscall_check(lseek(fd, 0, SEEK_SET), 0, "lseek");
    safe_read(fd, &e, sizeof(e), "Elf64_Ehdr");
    if (e.e_shoff == 0) {
	fprintf(stderr, "No section header found in self! Bugger.\n");
	exit(1);
    }
    if (e.e_shentsize != sizeof(Elf64_Shdr)) {
	fprintf(stderr, "Section headers incorrect size. Bugger.\n");
	exit(1);
    }
    if (e.e_shstrndx == SHN_UNDEF) {
	fprintf(stderr, "String section missing. Bugger.\n");
	exit(1);
    }
    
    /* read the string table */
    syscall_check(lseek(fd, e.e_shoff+(e.e_shstrndx*sizeof(Elf64_Shdr)), SEEK_SET), 0, "lseek");
    safe_read(fd, &s, sizeof(s), "string table section header");
    syscall_check(lseek(fd, s.sh_offset, SEEK_SET), 0, "lseek");
    strtab = xmalloc(s.sh_size);
    safe_read(fd, strtab, s.sh_size, "string table");

    for (i=0; i < e.e_shnum; i++) {
	long offset;

	syscall_check(
		lseek(fd, e.e_shoff+(i*sizeof(Elf64_Shdr)), SEEK_SET), 0, "lseek");
	safe_read(fd, &s, sizeof(s), "Elf64_Shdr");
	if (s.sh_type != SHT_PROGBITS || s.sh_name == 0)
	    continue;

	/* We have potential data! Is it really ours? */
	if (memcmp(strtab+s.sh_name, "cryopid.image", 13) != 0)
	    continue;

	if (s.sh_info != IMAGE_VERSION) {
	    fprintf(stderr, "Incorrect image version found (%d)! Keeping on trying.\n", s.sh_info);
	    continue;
	}

	/* Woo! got it! */
	syscall_check(
		lseek(fd, s.sh_offset, SEEK_SET), 0, "lseek");

	safe_read(fd, &offset, sizeof(offset), "offset");

	syscall_check(
		lseek(fd, offset, SEEK_SET), 0, "lseek");

	return;
    }
    fprintf(stderr, "Program image not found!\n");
    exit(1);
}

/* vim:set ts=8 sw=4 noet: */
