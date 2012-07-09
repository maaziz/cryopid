/* _start stolen from dietlibc */
.global _start
_start:
	pop	%ecx
	movl	%esp,%esi
	pushl	%ecx
	leal	4(%esi,%ecx,4),%eax
	pushl	%eax
	push	%esi
	push	%ecx
	call	main

