static void func (int i)
{
	i;
	int j = i;
}
/*
 * check-name: declaration after statement (default)
 * check-command: sparse $file
 */
