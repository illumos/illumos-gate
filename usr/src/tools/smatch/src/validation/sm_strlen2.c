int strlen(char *str);
int strcpy(char *str);

void func (char *input1, char *input2, char *input3)
{
	char buf1[4];
	char buf2[4];
	char buf3[4];

	if (strlen(input1) > 4)
		return;
	strcpy(buf1, input1);

	if (10 > strlen(input2))
		strcpy(buf2, input2);

	if (strlen(input3) <= 4)
		strcpy(buf3, input3);
}
/*
 * check-name: Smatch strlen test #2
 * check-command: smatch sm_strlen2.c
 *
 * check-output-start
sm_strlen2.c:12 func() error: strcpy() 'input1' too large for 'buf1' (5 vs 4)
sm_strlen2.c:15 func() error: strcpy() 'input2' too large for 'buf2' (10 vs 4)
sm_strlen2.c:18 func() error: strcpy() 'input3' too large for 'buf3' (5 vs 4)
 * check-output-end
 */
