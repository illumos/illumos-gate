#define	__user		__attribute__((address_space(1)))

struct s {
	int i;
} __user;


extern void use0(void *);
extern void use1(void __user *);

void main(void)
{
	struct s s;
	int i;

	use0(&s);	// KO
	use0(&i);	// OK
	use1(&s);	// OK
	use1(&i);	// KO
}

/*
 * check-name: type-attribute-as
 *
 * check-error-start
type-attribute-as.c:16:15: warning: incorrect type in argument 1 (different address spaces)
type-attribute-as.c:16:15:    expected void *<noident>
type-attribute-as.c:16:15:    got struct s <asn:1>*<noident>
type-attribute-as.c:19:15: warning: incorrect type in argument 1 (different address spaces)
type-attribute-as.c:19:15:    expected void <asn:1>*<noident>
type-attribute-as.c:19:15:    got int *<noident>
 * check-error-end
 */
