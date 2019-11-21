extern int fun(int);

typedef int (*fun_t)(int);

fun_t fa(void) { return &fun; }
fun_t f0(void) { return  fun; }
fun_t f1(void) { return *fun; }

/*
 * check-name: degen-function
 * check-command: test-linearize -m64 -Wno-decl -fdump-ir=linearize $file
 * check-assert: sizeof(void *) == 8
 *
 * check-output-start
fa:
.L0:
	<entry-point>
	symaddr.64  %r1 <- fun
	phisrc.64   %phi1(return) <- %r1
	br          .L1

.L1:
	phi.64      %r2 <- %phi1(return)
	ret.64      %r2


f0:
.L2:
	<entry-point>
	symaddr.64  %r3 <- fun
	phisrc.64   %phi2(return) <- %r3
	br          .L3

.L3:
	phi.64      %r4 <- %phi2(return)
	ret.64      %r4


f1:
.L4:
	<entry-point>
	symaddr.64  %r5 <- fun
	phisrc.64   %phi3(return) <- %r5
	br          .L5

.L5:
	phi.64      %r6 <- %phi3(return)
	ret.64      %r6


 * check-output-end
 */
