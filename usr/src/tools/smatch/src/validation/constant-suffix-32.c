#define BIGU 0xfffff00000000000U
#define BIGULL 0xfffff00000000000ULL

static unsigned long long a = BIGU;
static unsigned long long b = BIGULL;

/*
 * check-name: constant-suffix
 * check-command: sparse -m32 -Wconstant-suffix $file
 *
 * check-error-start
constant-suffix-32.c:4:31: warning: constant 0xfffff00000000000U is so big it is unsigned long long
 * check-error-end
 */

