char a;
int b;
void c(void)
{
	if (0) {
		char *d;
		for (;;)
			for (;;)
e:
				*d *= (a && 0) ^ b && *d;
	}
	goto e;
}


/*
 * check-name: crash add-doms
 * check-command: test-linearize $file
 *
 * check-error-ignore
 * check-output-ignore
 */
