struct ctype {
	int			type;
};

struct symbol {
	void			*p;
	const char		*name;
	struct ctype		ctype;
	struct symbol		*next_id;
};

struct unnamed {
	struct { int x, y; };
};

static struct symbol sym;
static struct symbol *sym_p;
static struct symbol *sym_q = &sym;

static struct unnamed un;

/*
 * check-name: Struct code generation
 * check-command: sparsec -c $file -o tmp.o
 */
