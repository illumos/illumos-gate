#define BIGU 0xfffff00000000000U
#define BIGUL 0xfffff00000000000UL

static unsigned long a = BIGU;
static unsigned long b = BIGUL;

/*
 * check-name: constant-suffix
 * check-command: sparse -m64 -Wconstant-suffix $file
 *
 * check-error-start
constant-suffix-64.c:4:26: warning: constant 0xfffff00000000000U is so big it is unsigned long
 * check-error-end
 */

