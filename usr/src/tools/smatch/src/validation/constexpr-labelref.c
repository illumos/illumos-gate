static void a(void)
{
label1:
	;
	static void *b = &&label1;
}

/*
 * check-name: constexprness label reference
 * check-command: sparse -Wconstexpr-not-const $file
 *
 * check-error-start
 * check-error-end
 */
