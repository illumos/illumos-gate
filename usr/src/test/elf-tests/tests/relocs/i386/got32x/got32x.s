	.text
	.globl	foo
	.section	.rodata
foo_addr:
	.string	"string"
	.section	.data.rel.local,"aw",@progbits
	.align 4
	.type	foo, @object
	.size	foo, 4
foo:
	.long	foo_addr
	.text
	.globl	main
	.type	main, @function
main:
	leal	4(%esp), %ecx
	andl	$-16, %esp
	pushl	-4(%ecx)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	pushl	%ecx
	call	.LPR0
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	movl	foo@GOT(%eax), %edx
	movl	(%edx), %edx
	subl	$12, %esp
	pushl	%edx
	movl	%eax, %ebx
	call	puts@PLT
	addl	$16, %esp
	movl	$0, %eax
	leal	-8(%ebp), %esp
	popl	%ecx
	popl	%ebx
	popl	%ebp
	leal	-4(%ecx), %esp
	ret
	.size	main, .-main
.LPR0:
	movl	(%esp), %eax
	ret
