unsigned long vla_sizeof0(int size)
{
	int a[size];
	return sizeof(a);
}

unsigned long vla_sizeof1(int size)
{
	struct s {
		int a[size];
	};
	return sizeof(struct s);
}

unsigned long vla_sizeof2(int size)
{
	struct s {
		int a[size];
	} *p;
	return sizeof(*p);
}

void* vla_inc(int size, void *base)
{
	struct s {
		int a[size];
	} *p = base;

	++p;
	return p;
}

/*
 * check-name: vla-sizeof.c
 *
 * check-known-to-fail
 */
