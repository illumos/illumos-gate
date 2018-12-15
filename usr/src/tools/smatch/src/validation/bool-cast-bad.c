typedef unsigned short __attribute__((bitwise)) le16;
struct s {
	int a:2;
	int b:2;
	int c:2;
};

static _Bool fresi(le16 a)     { return a; }
static _Bool frese(le16 a)     { return (_Bool)a; }
static _Bool fstsi(struct s a) { return a; }
static _Bool fstse(struct s a) { return (_Bool)a; }

/*
 * check-name: bool-cast-bad.c
 * check-command: sparse $file
 *
 * check-error-start
bool-cast-bad.c:10:41: warning: incorrect type in return expression (different base types)
bool-cast-bad.c:10:41:    expected bool
bool-cast-bad.c:10:41:    got struct s a
bool-cast-bad.c:11:42: warning: cast from non-scalar
 * check-error-end
 */
