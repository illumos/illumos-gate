 
extern int bar (int);

extern int foo (int);
   
int foo (int x)
{
	int y = 0;
   
	while (y < 1000) {
		y += bar(x);
	}
   
	return y;
}
    

/*
 * check-name: Loops
 * check-command: sparsec -c $file -o tmp.o
 */
