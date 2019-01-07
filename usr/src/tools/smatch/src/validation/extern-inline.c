extern __inline__ int f(int);

extern __inline__ int
f(int x)
{
        return x;
}

extern int g(int);

extern __inline__ int
g(int x)
{
        return x;
}


/*
 * check-name: extern inline function
 * check-command: sparse $file $file
 * check-description: Extern inline function never emits stand alone copy
 * of the function. It allows multiple such definitions in different file.
 */
