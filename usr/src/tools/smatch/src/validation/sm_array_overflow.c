int a[] = {1, 2, 3, 4};
char *b = "abc";
char c[4];
char d[4] = "";

int x;
static int options_write(void)
{
	int i;
	char *str = b;
	char *str2 = "123";
	char *str3;
	char *str4;
	char *str5;
	unsigned int j = 4;

	str3 = str2;
	str4 = str;
	if (x)
		str5 = "asdf";
	else
		str5 = "aa";

	for (i = 0; i < 4 && frob(); i++)
		;
	a[i] = 42;
	b[i] = '\0';
	c[i] = '\0';
	str[j] = '\0';
	str2[j] = '\0';
	str3[j] = '\0';
	str4[j] = '\0';
	str5[j] = '\0';
	d[j] = '\0';
}
/*
 * check-name: smatch array check
 * check-command: smatch --spammy sm_array_overflow.c
 *
 * check-output-start
sm_array_overflow.c:26 options_write() error: buffer overflow 'a' 4 <= 4
sm_array_overflow.c:27 options_write() error: buffer overflow 'b' 4 <= 4
sm_array_overflow.c:28 options_write() error: buffer overflow 'c' 4 <= 4
sm_array_overflow.c:29 options_write() error: buffer overflow 'str' 4 <= 4
sm_array_overflow.c:30 options_write() error: buffer overflow 'str2' 4 <= 4
sm_array_overflow.c:31 options_write() error: buffer overflow 'str3' 4 <= 4
sm_array_overflow.c:32 options_write() error: buffer overflow 'str4' 4 <= 4
sm_array_overflow.c:34 options_write() error: buffer overflow 'd' 4 <= 4
 * check-output-end
 */
