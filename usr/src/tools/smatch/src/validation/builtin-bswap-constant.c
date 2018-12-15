unsigned short bswap16(void);
unsigned short bswap16(void)
{
	return __builtin_bswap16(0x1234);
}

unsigned int bswap32(void);
unsigned int bswap32(void)
{
	return __builtin_bswap32(0x12345678);
}

unsigned long long bswap64(void);
unsigned long long bswap64(void)
{
	return __builtin_bswap64(0x123456789abcdef0ULL);
}

unsigned int half_constant(void);
unsigned int half_constant(void)
{
	int v = 0x12345678;
	return __builtin_bswap32(v);
}
/*
 * check-name: builtin-bswap-constant
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-excludes: __builtin_bswap
 * check-output-contains:ret.16 *.0x3412
 * check-output-contains:ret.32 *.0x78563412
 * check-output-contains:ret.64 *.0xf0debc9a78563412
 */
