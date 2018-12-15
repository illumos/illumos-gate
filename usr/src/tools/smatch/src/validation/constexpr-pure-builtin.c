// requires constant integer expressions
static int bar[] = {
	[__builtin_bswap16(0x1234)] = 0,		// OK
	[__builtin_bswap32(0x1234)] = 0,		// OK
	[__builtin_bswap64(0x1234)] = 0,		// OK
};

// requires constant integers
static int foo(unsigned long long a)
{
	switch (a) {
	case __builtin_bswap16(1   <<  8):
	case __builtin_bswap32(2L  << 24):
	case __builtin_bswap64(3LL << 56):
		return 0;
	default:
		return 1;
	}
}

/*
 * check-name: constness of pure/const builtins
 */
