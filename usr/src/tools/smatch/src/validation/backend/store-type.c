struct foo;
static struct foo *var;

static void set(struct foo *f)
{
       var = f;
}

/*
 * check-name: Type of stored objects
 * check-command: sparsec -c $file -o tmp.o
 */
