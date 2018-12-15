#define	__noderef	__attribute__((noderef))

struct s {
	int i;
} __noderef;


void main(void)
{
	struct s s;

	s.i = 0;
}

/*
 * check-name: type-attribute-mod
 *
 * check-error-start
type-attribute-mod.c:12:9: warning: dereference of noderef expression
 * check-error-end
 */
