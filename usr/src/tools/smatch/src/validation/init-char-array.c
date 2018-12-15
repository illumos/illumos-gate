/*
 * for array of char {<string>} gets special treatment in initializer.
 */
static char *s[] = {"aaaaaaaaa"};
static char t[][10] = {"aaaaaaaaa"};
static char u[] = {"aaaaaaaaa"};
static char v[] = "aaaaaaaaa";
static void f(void)
{
	char x[1/(sizeof(s) == sizeof(char *))];
	char y[1/(sizeof(u) == 10)];
	char z[1/(sizeof(v) == 10)];
	char w[1/(sizeof(t) == 10)];
}

/*
 * check-name: char array initializers
 */
