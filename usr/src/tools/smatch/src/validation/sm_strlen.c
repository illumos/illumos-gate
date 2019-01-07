int strlen(char *str);
int strcpy(char *str);

void func (char *input)
{
	int input_len;
	char buf[4];

	input_len = strlen(input);
	if (input_len <= 5) {
		strcpy(buf, input);
	}
	if (input_len <= 3) {
		strcpy(buf, input);
	}
}
/*
 * check-name: Smatch strlen test
 * check-command: smatch sm_strlen.c
 *
 * check-output-start
sm_strlen.c:11 func() error: strcpy() 'input' too large for 'buf' (6 vs 4)
 * check-output-end
 */
