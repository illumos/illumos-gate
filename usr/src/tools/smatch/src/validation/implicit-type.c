extern a;
static b;
c;

/*
 * check-name: implicit-type.c
 * check-command: sparse -Wno-decl $file
 *
 * check-error-start
implicit-type.c:1:8: warning: 'a' has implicit type
implicit-type.c:2:8: warning: 'b' has implicit type
implicit-type.c:3:1: warning: 'c' has implicit type
 * check-error-end
 */
