void fnp(void)
{
	int a;
	for (;;)
		a += 1;
}

void fnm(void)
{
	int a;
	for (;;)
		a -= 1;
}

void fna(void)
{
	int a;
	for (;;)
		a &= 1;
}

void fno(void)
{
	int a;
	for (;;)
		a |= 1;
}

void fnx(void)
{
	int a;
	for (;;)
		a ^= 1;
}

void fnl(void)
{
	int a;
	for (;;)
		a <<= 1;
}

void fnr(void)
{
	int a;
	for (;;)
		a >>= 1;
}

/*
 * check-name: infinite loop 01
 * check-command: sparse -Wno-decl $file
 * check-timeout:
 */
