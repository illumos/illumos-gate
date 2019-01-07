#define	__aligned(N)	__attribute__((aligned(N)))
#define alignof(X)	__alignof__(X)

struct s {
	short a, b, c;
} __aligned(2*sizeof(short));

static int fs(void) { return  sizeof(struct s); }
static int fa(void) { return alignof(struct s); }

void main(void)
{
	_Static_assert( sizeof(struct s) == 4 * sizeof(short), "size");
	_Static_assert(alignof(struct s) == 2 * sizeof(short), "alignment");
}

/*
 * check-name: type-attribute-align
 */
