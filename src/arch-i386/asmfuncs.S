#include <asm/unistd.h>

.global set_thread_area
.align 4,0x90
set_thread_area:
	push   %ebx
	sub    $0x10,%esp
	mov    0x18(%esp),%ebx
	mov    $__NR_set_thread_area,%eax
	int    $0x80
	mov    %eax,0xc(%esp)
	mov    0xc(%esp),%eax
	add    $0x10,%esp
	pop    %ebx
	ret    
