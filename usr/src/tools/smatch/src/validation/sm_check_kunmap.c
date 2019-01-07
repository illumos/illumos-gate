void something();

int kmap(int p);
int kunmap(int p);
int kmap_atomic(int p);
int kunmap_atomic(int p);

int page;
int x;
int y;
int z;

void func(void)
{
	x = kmap(page);
	kunmap(page);
	kunmap(x);
	y = kmap_atomic(z);
	kunmap_atomic(y);
	kunmap_atomic(z);
}
/*
 * check-name: smatch check kunmap
 * check-command: smatch -p=kernel sm_check_kunmap.c
 *
 * check-output-start
sm_check_kunmap.c:17 func() warn: passing the wrong variable to kunmap()
sm_check_kunmap.c:20 func() warn: passing the wrong variable to kmap_atomic()
 * check-output-end
 */
