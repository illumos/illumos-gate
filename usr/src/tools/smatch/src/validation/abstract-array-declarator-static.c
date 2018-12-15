
extern void f1(int g[static 1]);
extern void f2(int g[static restrict 1]);
extern void f3(int g[restrict static 1]);
extern void f4(int g[static restrict static 1]);	/* duplicate static error */
extern void f5(int g[restrict static static 1]);	/* duplicate static error */

/*
 * check-name: abstract array declarator static
 * check-error-start
abstract-array-declarator-static.c:5:38: error: duplicate array static declarator
abstract-array-declarator-static.c:6:38: error: duplicate array static declarator
 * check-error-end
 */
