_Static_assert(1, "global ok");

struct foo {
	_Static_assert(1, "struct ok");
};

void bar(void)
{
	_Static_assert(1, " func1 ok");
	int i;
	i = 0;
	_Static_assert(1, " func2 ok");

	if (1) {
		_Static_assert(1, " func3 ok");
	}
}

_Static_assert(0, "expected assertion failure");

static int f;
_Static_assert(f, "non-constant expression");

static int *p;
_Static_assert(p, "non-integer expression");

_Static_assert(0.1, "float expression");

_Static_assert(!0 == 1, "non-trivial expression");

static char array[4];
_Static_assert(sizeof(array) == 4, "sizeof expression");

static const char non_literal_string[] = "non literal string";
_Static_assert(0, non_literal_string);

_Static_assert(1 / 0, "invalid expression: should not show up?");

struct s {
	char arr[16];
	_Static_assert(1, "inside struct");
};

union u {
	char c;
	int  i;
	_Static_assert(1, "inside union");
};

_Static_assert(sizeof(struct s) == 16, "sizeof assertion");

_Static_assert(1, );
_Static_assert(, "");
_Static_assert(,);

/*
 * check-name: static assertion
 *
 * check-error-start
static_assert.c:19:16: error: static assertion failed: "expected assertion failure"
static_assert.c:22:16: error: bad constant expression
static_assert.c:25:16: error: bad constant expression
static_assert.c:27:16: error: bad constant expression
static_assert.c:35:19: error: bad or missing string literal
static_assert.c:37:18: error: bad constant expression
static_assert.c:52:19: error: bad or missing string literal
static_assert.c:53:16: error: Expected constant expression
static_assert.c:54:16: error: Expected constant expression
static_assert.c:54:17: error: bad or missing string literal
 * check-error-end
 */
