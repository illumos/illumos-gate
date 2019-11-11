int foo(int a, int b)
{
	int var = 0;
	int r;

	if (a)
		var = 1;
	if (b)
		r = var;

	return r;		// undef if !b
}

/*
 * check-name: variable partially undefined
 * check-description: trigger a bug in symbol/memop simplification
 * check-description: sparse-llvm is used here as semantic checker of sparse's IR
 * check-command: sparse-llvm -Wno-decl $file
 * check-output-ignore
 */
