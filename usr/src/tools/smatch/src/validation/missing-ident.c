int [2];
int *;
int (*);
int ();
int;
struct foo;
union bar {int x; int y;};
struct baz {int x, :3, y:2;};
/*
 * check-name: handling of identifier-less declarations
 *
 * check-error-start
missing-ident.c:1:8: warning: missing identifier in declaration
missing-ident.c:2:6: warning: missing identifier in declaration
missing-ident.c:3:8: warning: missing identifier in declaration
missing-ident.c:4:7: warning: missing identifier in declaration
 * check-error-end
 */
