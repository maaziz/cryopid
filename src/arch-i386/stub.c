#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>

#include "cryopid.h"
#include "cpimage.h"
#include "process.h"

void seek_to_image(int fd)
{
    Elf32_Ehdr e;
    Elf32_Shdr s;
    int i;
    char* strtab;

    syscall_check(lseek(fd, 0, SEEK_SET), 0, "lseek");
    safe_read(fd, &e, sizeof(e), "Elf32_Ehdr");
    if (e.e_shoff == 0) {
	fprintf(stderr, "No section header found in self! Bugger.\n");
	exit(1);
    }
    if (e.e_shentsize != sizeof(Elf32_Shdr)) {
	fprintf(stderr, "Section headers incorrect size. Bugger.\n");
	exit(1);
    }
    if (e.e_shstrndx == SHN_UNDEF) {
	fprintf(stderr, "String section missing. Bugger.\n");
	exit(1);
    }
    
    /* read the string table */
    syscall_check(lseek(fd, e.e_shoff+(e.e_shstrndx*sizeof(Elf32_Shdr)), SEEK_SET), 0, "lseek");
    safe_read(fd, &s, sizeof(s), "string table section header");
    syscall_check(lseek(fd, s.sh_offset, SEEK_SET), 0, "lseek");
    strtab = xmalloc(s.sh_size);
    safe_read(fd, strtab, s.sh_size, "string table");

    for (i=0; i < e.e_shnum; i++) {
	long offset;

	syscall_check(
		lseek(fd, e.e_shoff+(i*sizeof(Elf32_Shdr)), SEEK_SET), 0, "lseek");
	safe_read(fd, &s, sizeof(s), "Elf32_Shdr");
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

	safe_read(fd, &offset, 4, "offset");

	syscall_check(
		lseek(fd, offset, SEEK_SET), 0, "lseek");

	return;
    }
    fprintf(stderr, "Program image not found!\n");
    exit(1);
}

/* vim:set ts=8 sw=4 noet: */
