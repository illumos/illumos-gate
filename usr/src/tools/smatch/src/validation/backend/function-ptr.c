extern int ival;
extern int *ipval;
extern int array[3];
extern int matrix[3][3];
extern int fun(int);

// via an argument
void arg(int a, int *p, int (*fb)(unsigned char), int (*fi)(int), int (*fl)(long), int (*fv)(void), int (*fip)(int *), int (*fim)(int (*)[3]), int (*fvp)(void *), int (*ffp)(int (*)(int)));
void arg(int a, int *p, int (*fb)(unsigned char), int (*fi)(int), int (*fl)(long), int (*fv)(void), int (*fip)(int *), int (*fim)(int (*)[3]), int (*fvp)(void *), int (*ffp)(int (*)(int)))
{
	fv();

	fb(a);
	fi(a);
	fl(a);
	fb(123);
	fi(123);
	fl(123);
	fb(123L);
	fi(123L);
	fl(123L);
	fb(ival);
	fi(ival);
	fl(ival);

	fip(p);
	fip((void*)0);
	fip(ipval);
	fip(&ival);
	fip(array);
	fim(matrix);

	fvp(p);
	fvp((void*)0);
	fvp(ipval);
	fvp(&ival);
	fvp(array);
	fvp(matrix);

	fvp(fun);
	fvp(&fun);
	ffp(fun);
	ffp(&fun);
}

// a global
extern int (*fb)(unsigned char);
extern int (*fi)(int);
extern int (*fl)(long);
extern int (*fv)(void);
extern int (*fip)(int *);
extern int (*fim)(int (*)[3]);
extern int (*fvp)(void *);
extern int (*ffp)(int (*)(int));

void glb(int a, int *p);
void glb(int a, int *p)
{
	fv();

	fb(a);
	fi(a);
	fl(a);
	fb(123);
	fi(123);
	fl(123);
	fb(123L);
	fi(123L);
	fl(123L);
	fb(ival);
	fi(ival);
	fl(ival);

	fip(p);
	fip((void*)0);
	fip(ipval);
	fip(&ival);
	fip(array);
	fim(matrix);

	fvp(p);
	fvp((void*)0);
	fvp(ipval);
	fvp(&ival);
	fvp(array);
	fvp(matrix);

	fvp(fun);
	fvp(&fun);
	ffp(fun);
	ffp(&fun);
}

// via a struct member:
// -> force to create a register containing the function pointer
struct ops {
	int (*fb)(unsigned char);
	int (*fi)(int);
	int (*fl)(long);
	int (*fv)(void);
	int (*fip)(int *);
	int (*fim)(int (*)[3]);
	int (*fvp)(void *);
	int (*ffp)(int (*)(int));

	int (*const cfi)(int);		// for the fun of it
};

void ops(int a, int *p, struct ops *ops);
void ops(int a, int *p, struct ops *ops)
{
	ops->fv();

	ops->fb(a);
	ops->fi(a);
	ops->fl(a);
	ops->fb(123);
	ops->fi(123);
	ops->fl(123);
	ops->fb(123L);
	ops->fi(123L);
	ops->fl(123L);
	ops->fb(ival);
	ops->fi(ival);
	ops->fl(ival);

	ops->fip(p);
	ops->fip((void*)0);
	ops->fip(ipval);
	ops->fip(&ival);
	ops->fip(array);
	ops->fim(matrix);

	ops->fvp(p);
	ops->fvp((void*)0);
	ops->fvp(ipval);
	ops->fvp(&ival);
	ops->fvp(array);
	ops->fvp(matrix);

	ops->fvp(fun);
	ops->fvp(&fun);
	ops->ffp(fun);
	ops->ffp(&fun);
	ops->fvp(fi);

	ops->cfi(42);
}

/*
 * check-name: Function pointer code generation
 * check-command: sparsec -c $file -o tmp.o
 */
