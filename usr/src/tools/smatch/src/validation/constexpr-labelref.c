static void a(void)
{
label1:
	;
	static void *b = &&label1;
}

/*
 * check-name: label reference constness verification.
 * check-command: sparse -Wconstexpr-not-const $file
 *
 * check-error-start
 * check-error-end
 */
