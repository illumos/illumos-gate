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
	/*
	 * We do this to explicitly _NOT_ get a REX prefix.
	 * This relies on our load address to actually _work_, and is otherwise
	 * disgusting.
	 */
	movl	foo@GOTPCREL(%rip), %eax
	movq	(%rax), %rax
	movq	%rax, %rdi
	call	puts@PLT
	movl	$0, %eax
	leave
	ret
	.size	main, .-main
