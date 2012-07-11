
#define varstart 0x0800
#define start (varstart + 0)
#define lower (varstart + 8)
#define upper (varstart + 16)
#define tmp   (varstart + 24)
#define try    %rdx
#define length %rsi

.ALIGN(4096)
.global get_task_size_code
get_task_size_code:
movq	$0x1000,%rax
movq	%rax,start
movq	%rax,lower
movq	$0xfffffffffffff000,upper
1:
movq	upper, length
shr	length
movq	lower, try
shr	try
add	length,try
add	$0xfff,try
and	$0xfffffffffffff000,try
movq	try,length
movq	try,tmp
sub	start,length
movq	start,%rdi
movq	$0xb, %rax  /* munmap */
syscall

cmp	$-22,%eax /* -EINVAL */
je	2f
movq	tmp,%rax
movq	%rax,lower
jmp	3f
2:
movq	tmp,%rax
sub	$0x1000,%rax
movq	%rax,upper
3:
movq	lower,%rax
movq	upper,%rbx
cmp	%rax,%rbx
jne	1b

movq	$1, %rax /* write */
movq	$142, %rdi
movq	$lower, %rsi
movq	$8, %rdx
syscall
movq	$0x3c, %rax /* exit */
movq	$0x0,  %rdi
syscall
.ALIGN(8)
get_task_size_code_end:
.global get_task_size_code_size
get_task_size_code_size:
.int	(get_task_size_code_end - get_task_size_code)
