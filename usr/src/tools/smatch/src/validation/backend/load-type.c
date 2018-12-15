extern struct _IO_FILE *stdin;

static void sub(struct _IO_FILE *in) {}

static void test(void) {
        sub(stdin);
}

/*
 * check-name: Type of loaded objects
 * check-command: sparsec -c $file -o tmp.o
 */
