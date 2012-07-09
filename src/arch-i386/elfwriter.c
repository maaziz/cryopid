#include <elf.h>
#include <asm/page.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include "process.h"

extern char *stub_start;
extern long stub_size;

static void write_tramp_snippet(char** tramp, long mmap_addr, long mmap_len,
	int mmap_prot, long src, long dst, long length)
{
    char *p = *tramp;

    /* mmap(new_start, length, PROT_READ|PROT_WRITE,
     *         MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0); */
    *p++=0xb8;*(long*)(p)=__NR_mmap2; p+=4;      /* mov foo, %eax */
    *p++=0xbb;*(long*)(p)=mmap_addr; p+=4;       /* mov foo, %ebx */
    *p++=0xb9;*(long*)(p)=mmap_len; p+=4;        /* mov foo, %ecx */
    *p++=0xba;*(long*)(p)=mmap_prot; p+=4;
						 /* mov foo, %edx */
    *p++=0xbe;*(long*)(p)=MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS; p+=4;
						 /* mov foo, %esi */
    *p++=0xcd;*p++=0x80;			 /* int $0x80 */

    /* now memcpy code */
    *p++=0xbe;*(long*)(p)=src; p+=4;             /* mov foo, %esi */
    *p++=0xbf;*(long*)(p)=dst; p+=4;             /* mov foo, %edi */
    *p++=0xb9;*(long*)(p)=length>>2; p+=4;       /* mov foo, %ecx */
    *p++=0xf3;*p++=0xa5;                         /* rep movsl */

    *tramp = p;
}

static void write_tramp_jump(char **tramp, long entry)
{
    char *p = *tramp;
    /* and go there! */
    *p++=0xb8;*(long*)(p)=entry; p+=4;           /* mov foo, %eax */
    *p++=0xff;*p++=0xe0;                         /* jmp (%eax) */
    *tramp = p;
}

void write_stub(int fd, long offset)
{
    Elf32_Ehdr *e;
    Elf32_Shdr *s;
    Elf32_Phdr *p;
    char* strtab;
    int i, j;
    int got_it;
    unsigned long cur_brk = 0;

    /* offset is where we'd like the heap to begin.
     * We want to set offset to where the code must begin in order to get
     * the heap in the right place.
     * ie, offset = offset - round_to_page(code_len) - round_to_page(data_len)
     */

    e = (Elf32_Ehdr*)stub_start;

    assert(e->e_shoff != 0);
    assert(e->e_shentsize == sizeof(Elf32_Shdr));
    assert(e->e_shstrndx != SHN_UNDEF);

    s = (Elf32_Shdr*)(stub_start+(e->e_shoff+(e->e_shstrndx*e->e_shentsize)));
    strtab = stub_start+s->sh_offset;

    /* Locate where this binary's brk would start */
    for (i = 0; i < e->e_phnum; i++) {
	p = (Elf32_Phdr*)(stub_start+e->e_phoff+(i*e->e_phentsize));
	if (p->p_type != PT_LOAD)
	    continue;
	if (p->p_vaddr + p->p_memsz > cur_brk);
	    cur_brk = p->p_vaddr + p->p_memsz;
    }

    fprintf(stderr, "Heap was at 0x%lx. Want to be at 0x%lx. offset = 0x%lx\n",
	    cur_brk, offset, offset - cur_brk);

    /* Set where we want it to start */
    offset -= cur_brk;
    offset &= ~(PAGE_SIZE - 1);

    got_it = 0;
    for (i = 0; i < e->e_shnum; i++) {
	s = (Elf32_Shdr*)(stub_start+e->e_shoff+(i*e->e_shentsize));
	s->sh_addr += offset;

	if (s->sh_type != SHT_PROGBITS || s->sh_name == 0)
	    continue;

	if (memcmp(strtab+s->sh_name, "cryopid.tramp", 13) == 0) {
	    char *tp = stub_start+s->sh_offset;

	    for (j = 0; j < e->e_phnum; j++) {
		unsigned long mmap_addr, mmap_len;
		int mmap_prot = 0;

		p = (Elf32_Phdr*)(stub_start+e->e_phoff+(j*e->e_phentsize));

		if (p->p_type != PT_LOAD)
		    continue;

		/* FIXME: Set these prot flags more exactly with mprotect later. */
		mmap_prot = PROT_READ | PROT_WRITE;
		if (p->p_flags & PF_X) mmap_prot |= PROT_EXEC;

		mmap_addr = p->p_vaddr & ~(PAGE_SIZE - 1);
		mmap_len = p->p_memsz + (p->p_vaddr - mmap_addr);
		mmap_len = (mmap_len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

		write_tramp_snippet(&tp, 
			mmap_addr, mmap_len, mmap_prot,
			p->p_vaddr + offset, p->p_vaddr, p->p_filesz);
	    }

	    write_tramp_jump(&tp, e->e_entry);
	    e->e_entry = s->sh_addr;
	}

	if (memcmp(strtab+s->sh_name, "cryopid.image", 13) == 0) {
	    /* check the signature from the stub's linker script */
	    if (memcmp(stub_start+s->sh_offset, "CPIM", 4) != 0) {
		fprintf(stderr, "Found an invalid stub! Still trying...\n");
		continue;
	    }

	    s->sh_info = IMAGE_VERSION;
	    *(long*)(stub_start+s->sh_offset) = stub_size;
	    got_it = 1;
	}
    }

    for (i = 0; i < e->e_phnum; i++) {
	p = (Elf32_Phdr*)(stub_start+e->e_phoff+(i*e->e_phentsize));
	p->p_vaddr += offset;
	p->p_paddr += offset;
    }

    if (!got_it) {
	fprintf(stderr, "Couldn't find a valid stub linked in! Bugger.\n");
	exit(1);
    }
    write(fd, stub_start, stub_size);
}

/* vim:set ts=8 sw=4 noet: */
