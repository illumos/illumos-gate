char *foo(char **pfmt)
{
	return ++*pfmt;
}

/*
 * check-name: deref-ptr-ptr
 * check-command: test-linearize -m64 -Wno-decl $file
 * check-assert: sizeof(void *) == 8
 *
 * check-output-excludes: load[^.]
 * check-output-contains: load\\.
 * check-output-excludes: store[^.]
 * check-output-contains: store\\.
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	load.64     %r2 <- 0[%arg1]
	add.64      %r3 <- %r2, $1
	store.64    %r3 -> 0[%arg1]
	ret.64      %r3


 * check-output-end
 */
