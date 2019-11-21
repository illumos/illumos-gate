int foo(int p, int (*f0)(int), int (*f1)(int), int arg)
{
	return (p ? f0 : f1)(arg);
}

/*
 * check-name: call-complex-pointer
 * check-command: test-linearize -m64 -Wno-decl $file
 * check-assert: sizeof(void *) == 8
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	cbr         %arg1, .L2, .L3

.L2:
	phisrc.64   %phi1 <- %arg2
	br          .L4

.L3:
	ptrcast.64  %r6 <- (64) %arg3
	phisrc.64   %phi2 <- %r6
	br          .L4

.L4:
	phi.64      %r7 <- %phi1, %phi2
	call.32     %r8 <- %r7, %arg4
	ret.32      %r8


 * check-output-end
 */
