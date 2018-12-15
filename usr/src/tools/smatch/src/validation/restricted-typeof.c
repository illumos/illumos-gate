typedef unsigned __attribute__((bitwise)) A;
static A x;
static __typeof__(x) y;
static A *p = &y;
/*
 * check-name: typeof with bitwise types
 * check-command: sparse -Wbitwise $file
 */
