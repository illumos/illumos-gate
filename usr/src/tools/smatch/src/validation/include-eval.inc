typedef unsigned long long_t;

inline
static unsigned int ok(void)
{
	return sizeof(long_t);
}

static unsigned int ko(void)
{
	return sizeof(long_t);
}
