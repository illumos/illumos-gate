struct st {
	int i, *d;
};

static int load_i(struct st *st)
{
	return st->i;
}

static void store_i(struct st *st, int i)
{
	st->i = i;
}

static int *load_d(struct st *st)
{
	return st->d;
}

static void store_d(struct st *st, int *d)
{
	st->d = d;
}

/*
 * check-name: struct access code generation
 * check-command: sparsec -c $file -o tmp.o
 */
