	.section .test,"e",@progbits
	.align 8
	.globl foo
	.type foo,@object
foo:
	.quad 0xfeed
	.size foo, 8
