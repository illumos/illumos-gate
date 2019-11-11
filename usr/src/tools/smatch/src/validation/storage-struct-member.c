int foo(a)
	register int a;
{
	return a;
}

struct s {
	register int a;
};

/*
 * check-name: storage in struct member
 * check-command: sparse -Wno-decl $file
 *
 * check-known-to-fail
 * check-error-start
storage-struct-member.c:2:9: warning: non-ANSI definition of function 'foo'
storage-struct-member.c:8:9: error: storage specifier in structure definition'
 * check-error-end
 */
