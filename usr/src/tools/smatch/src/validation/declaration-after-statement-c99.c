static void func (int i)
{
	i;
	int j = i;
}
/*
 * check-name: declaration after statement (C99)
 * check-command: sparse -std=c99 $file
 */
