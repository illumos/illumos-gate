	.text
	.globl	foo
	.section	.rodata
foo_addr:
	.string	"string"

	.section	.data.rel.local,"aw",@progbits
	.align 8
	.type	foo, @object
	.size	foo, 8
foo:
	.quad	foo_addr

	.text
	.globl	main
	.type	main, @function
main:
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$16, %rsp
	movl	%edi, -4(%rbp)
	movq	%rsi, -16(%rbp)
	movq	foo@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, %rdi
	call	puts@PLT
	movl	$0, %eax
	leave
	ret
	.size	main, .-main
