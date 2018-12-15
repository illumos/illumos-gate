
static __attribute__((__pure__)) int pure1(void)
{
	int i = 0;
	return i;
}

static __attribute__((__pure__)) void *pure2(void)
{
    void *i = (void *)0;
    return i;
}

/*
 * check-name: Pure function attribute
 */
