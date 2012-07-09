#ifndef _STUB_H_
#define _STUB_H_

#include <sys/mman.h>
#include <asm/page.h>
#include "cryopid.h"

static inline void jump_to_trampoline()
{
    asm("jmp *%%eax\n" : : "a"(TRAMPOLINE_ADDR));
}

static inline void* find_top_of_stack()
{
    unsigned int tmp;
    /* Return the top of the current stack page. */
    return (void*)(((long)&tmp + PAGE_SIZE - 1) & ~(PAGE_SIZE-1));
}

static inline void relocate_stack()
{
    void *top_of_old_stack;
    void *top_of_new_stack;
    void *top_of_our_memory = (void*)MALLOC_END;
    void *top_of_all_memory;
    long size_of_new_stack;

    /* Reposition the stack at top_of_old_stack */
    top_of_old_stack = find_top_of_stack();
    top_of_all_memory = (void*)get_task_size();

    top_of_new_stack = (void*)TOP_OF_STACK;
    size_of_new_stack = PAGE_SIZE;

    syscall_check( (int)
	mmap(top_of_new_stack - size_of_new_stack, size_of_new_stack,
	    PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANONYMOUS|MAP_FIXED|MAP_GROWSDOWN|MAP_PRIVATE, -1, 0),
	0, "mmap(newstack)");
    memset(top_of_new_stack - size_of_new_stack, 0, size_of_new_stack);
    memcpy(top_of_new_stack - size_of_new_stack,
	    top_of_old_stack - size_of_new_stack, /* FIX ME */
	    size_of_new_stack);
    __asm__ ("addl %0, %%esp" : : "a"(top_of_new_stack - top_of_old_stack));
    __asm__ ("addl %0, %%ebp" : : "a"(top_of_new_stack - top_of_old_stack));

    /* unmap absolutely everything above us! */
    syscall_check(
	    munmap(top_of_our_memory,
		(top_of_all_memory - top_of_our_memory)),
		0, "munmap(stack)");
}

extern void seek_to_image(int fd);

#endif /* _STUB_H_ */
