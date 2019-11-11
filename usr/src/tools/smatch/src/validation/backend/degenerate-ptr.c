extern int array[3];
extern int matrix[3][3];
extern int fun(int);

extern int fia(int []);
extern int fip(int *);
extern int fim(int (*)[3]);
extern int fvp(void *);
extern int ffp(int (*)(int));

void call(void);
void call(void)
{
	fia(array);

	fip(array);
	fim(matrix);

	fvp(array);
	fvp(matrix);

	fvp(fun);
	fvp(&fun);
	ffp(fun);
	ffp(&fun);
}

void local(void);
void local(void)
{
	int *ip;
	int (*im)[3];
	void *vp;
	int (*fp)(int);

	ip = array;
	im = matrix;

	vp = array;
	vp = matrix;

	vp = fun;
	vp = &fun;
	fp = fun;
	fp = &fun;
}


extern int *ip;
extern int (*im)[3];
extern void *vp;
extern int (*fp)(int);

void global(void);
void global(void)
{
	ip = array;
	im = matrix;

	vp = array;
	vp = matrix;

	vp = fun;
	vp = &fun;
	fp = fun;
	fp = &fun;
}

/*
 * check-name: degenerated pointer handling
 * check-command: sparsec -c $file -o tmp.o
 */
