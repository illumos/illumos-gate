static char a[sizeof(char *) + 1];
static char b[1/(sizeof(a) - sizeof(0,a))];
static void f(void)
{
        int c[42];
        typeof((void)0,c) d;
        d = c;
}
/*
 * check-name: Comma and array decay
 * check-description: arguments of comma should degenerate
 */
