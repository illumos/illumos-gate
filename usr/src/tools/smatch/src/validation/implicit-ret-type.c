fun(void);

foo(void) { return 1; }
static bar(void) { return 1; }

/*
 * check-name: implicit-ret-type.c
 * check-command: sparse -Wno-decl $file
 *
 * check-error-start
implicit-ret-type.c:1:1: warning: 'fun()' has implicit return type
implicit-ret-type.c:3:1: warning: 'foo()' has implicit return type
implicit-ret-type.c:4:8: warning: 'bar()' has implicit return type
 * check-error-end
 */
