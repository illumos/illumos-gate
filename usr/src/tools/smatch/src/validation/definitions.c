static inline int f(void);
static int g(void)
{
        return f();
}
static inline int f(void)
{
	return 0;
}
/*
 * check-name: finding definitions
 */
