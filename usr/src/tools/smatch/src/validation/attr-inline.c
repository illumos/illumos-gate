
static inline __attribute__((__always_inline__)) int gt(int lhs, int rhs)
{
	return lhs > rhs;
}

extern inline __attribute__((__gnu_inline__)) int ge(int lhs, int rhs)
{
	return lhs >= rhs;
}

static __attribute__((__warning__("That's junk!"))) __attribute__((__unused__))
__attribute__((__noinline__))
void junk(void)
{
	__asm__("");
}

/*
 * check-name: inline attributes
 */
