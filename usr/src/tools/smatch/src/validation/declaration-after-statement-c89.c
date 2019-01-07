static void func (int i)
{
	i;
	int j = i;
}
/*
 * check-name: declaration after statement (C89)
 * check-command: sparse -std=c89 $file
 * check-error-start
declaration-after-statement-c89.c:4:9: warning: mixing declarations and code
 * check-error-end
 */
