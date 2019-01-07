int printf(char *c, ...);
void exit(int c);

#undef PRINT_OUTPUTS

static void test_func_args(int x, int y)
{
	if (x == y)
		exit(1);
}

static int binop_s32(int x, int y)
{
	int a;

	a = a + x;
	a = a / y;
	a = a * x;
	a = a - y;

	return a;
}

static void test_binops(void)
{
	int tmp_s32 = binop_s32(987123, 234);

#ifdef PRINT_OUTPUTS
	printf("binop_s32(987123, 234) == %d\n", tmp_s32);
#else
	if (tmp_s32 != -1470599007)
		exit(2);
#endif
}

int main (int argc, char *argv[])
{
	test_func_args(1, 2);
	test_binops();

	return 0;
}

/*
 * check-name: binary operations
 */
