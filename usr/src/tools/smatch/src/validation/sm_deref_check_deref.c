struct ture {
	int a;
};
struct cont {
	struct ture *x;
};

struct ture *x;
struct ture **px;
struct cont *y;
void func (void)
{
	int *a = &(x->a);
	int *b = &x->a;
	int *c = &(y->x->a);
	int *d = &((*px)->a);

	if (x)
		frob();
	if (px)
		frob();
	if (y->x)
		frob();
	if (y)
		frob();

	return;
}
/*
 * check-name: Dereferencing before check
 * check-command: smatch sm_deref_check_deref.c
 *
 * check-output-start
sm_deref_check_deref.c:20 func() warn: variable dereferenced before check 'px' (see line 16)
sm_deref_check_deref.c:24 func() warn: variable dereferenced before check 'y' (see line 15)
 * check-output-end
 */
