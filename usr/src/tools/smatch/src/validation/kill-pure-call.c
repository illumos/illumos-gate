int side(int a);
int pure(int a) __attribute__((pure));

int keep(int a) { return side(a) && 0; }
int kill(int a) { return pure(a) && 0; }

/*
 * check-name: kill-pure-call
 * check-command: test-linearize -Wno-decl $file
 * check-description:
 *	See that the call is optimized away but only
 *	when the function is "pure".
 *
 * check-output-ignore
 * check-output-contains: call\\..* side
 * check-output-excludes: call\\..* pure
 */
