#include <sys/asm_linkage.h>

ENTRY_NP(test_data)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	data_symbol(%rip), %rax
	leave
	ret
SET_SIZE(test_data)

ENTRY_NP(test_bss)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	bss_symbol(%rip), %rax
	leave
	ret
SET_SIZE(test_bss)
