void *foo(void *def);
void *foo(void *def)
{
	if (!def)
yes:		return &&yes;

	return def;
}

/*
 * check-name: label-as-value
 * check-command: sparsec -c $file -o tmp.o
 */
