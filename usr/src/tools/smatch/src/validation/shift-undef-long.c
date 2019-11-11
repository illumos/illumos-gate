static unsigned very_big_shift(unsigned int a)
{
	unsigned r = 0;
	r |= a << (0ULL ^ ~0U);
	r |= a << (((  signed long long) ~0U) + 1);
	r |= a << (((unsigned long long) ~0U) + 1);
	r |= a << (~((unsigned long long) ~0U));
	return r;
}

/*
 * check-name: shift-undef-long
 * check-command: sparse -m64 $file
 *
 * check-error-start
shift-undef-long.c:4:16: warning: shift too big (4294967295) for type unsigned int
shift-undef-long.c:5:16: warning: shift too big (4294967296) for type unsigned int
shift-undef-long.c:6:16: warning: shift too big (4294967296) for type unsigned int
shift-undef-long.c:7:16: warning: shift count is negative (-4294967296)
 * check-error-end
 */
