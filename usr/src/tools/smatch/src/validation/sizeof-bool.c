static int a(void)
{
	return sizeof(_Bool);
}
/*
 * check-name: sizeof(_Bool) is valid
 * check-description: sizeof(_Bool) was rejected because _Bool is not an even
 * number of bytes
 * check-command: sparse -Wsizeof-bool $file
 * check-error-start
sizeof-bool.c:3:16: warning: expression using sizeof _Bool
 * check-error-end
 */
