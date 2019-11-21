int foo(int p, int (*f0)(int), int (*f1)(int), int arg)
{
	return (p ? f0 : f1)(arg);
}
/*
 * check-name: call-complex-pointer
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-ignore
 * check-output-excludes: ptrcast\\.
 * check-output-contains: select\\.
 */
