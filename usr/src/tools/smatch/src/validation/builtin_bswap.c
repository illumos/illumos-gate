static unsigned short x = __builtin_bswap16(0);
static unsigned int y = __builtin_bswap32(0);
static unsigned long long z = __builtin_bswap64(0);

/*
 * check-name: __builtin_bswap
 * check-error-start
 * check-error-end
 */
