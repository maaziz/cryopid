/* _start stolen from dietlibc */
.global _start
_start:
	popq	%rdi
	movq	%rsp,%rsi
	pushq	%rdi
	leaq	8(%rsi,%rdi,8),%rdx
	movq	%rdx, environ(%rip)
	call	main
