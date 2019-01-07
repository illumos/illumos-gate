int c99(void);
int c99(void)
{
	int r = -1;

	for (int i = 0; i < 10; i++) {
		r = i;
	}

	return r;
}

/*
 * check-name: C99 for loop variable declaration
 * check-command: test-linearize $file
 *
 * check-output-ignore
 * check-output-contains: phisrc\\.
 * check-output-contains: phi\\.
 * check-output-contains: add\\.
 */
