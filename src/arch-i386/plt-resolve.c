#include <elf.h>
#include <link.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

void *plt_resolve(void *l, char *what)
{
    struct link_map *lm;
    Elf32_Dyn *dyn;
    Elf32_Sym *sym;
    char *strtab;

    void *val = NULL;
    
    for (lm = (struct link_map*)l; lm != NULL; lm = lm->l_next) {
	sym = NULL;
	strtab = NULL;

	for (dyn = (Elf32_Dyn*)(lm->l_ld); dyn->d_tag != DT_NULL; dyn++) {
	    switch (dyn->d_tag) {
		case DT_STRTAB:
		    strtab = (char*)(dyn->d_un.d_ptr);
		    break;
		case DT_SYMTAB:
		    sym = (Elf32_Sym*)(dyn->d_un.d_ptr);
		    break;
	    }
	}
	
	while (sym) {
	    if (sym->st_name > 0x100000)
		break;
	    if (strcmp(strtab + sym->st_name, what) == 0) {
		val = (void*)(lm->l_addr + sym->st_value);
		if (sym->st_value)
		    return val;
	    }
	    sym++;
	}
    }
    if (val == NULL)
	fprintf(stderr, "Argh! Couldn't find %s in binary\n", what);
    return val;
}

void *find_linkmap(void *elf_hdr)
{
    Elf32_Ehdr *elf;
    Elf32_Phdr *phdr;
    Elf32_Dyn *dyn;
    int i, cnt;
    unsigned long *got;
    struct link_map *lm;
    elf = (Elf32_Ehdr*)elf_hdr;
    phdr = (Elf32_Phdr*)((unsigned char *)(elf) + elf->e_phoff);
    
    for (i = 0; i < elf->e_phnum; i++)
	if (phdr[i].p_type == PT_DYNAMIC)
	    break;

    if (i == elf->e_phnum) {
	printf("Not a dynamic elf file?\n");
	return NULL;
    }

    phdr += i;

    dyn = (Elf32_Dyn *)(phdr->p_vaddr);
    cnt = phdr->p_filesz / sizeof(Elf32_Dyn);

    got = NULL;
    for (i = 0; i < cnt; i++)
	if (dyn[i].d_tag == DT_PLTGOT)
	    got = (unsigned long *)(dyn[i].d_un.d_ptr);

    if (got == NULL) {
	printf("Unable to find GOT\n");
	return NULL;
    }

    lm = (struct link_map *)(got[1]);

    return lm;
}

/* vim:set ts=8 sw=4 noet: */
