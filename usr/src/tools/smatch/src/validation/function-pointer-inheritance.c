extern int foo(int f(int, void *));

int foo(int (*f)(int, void *))
{
    return 0;
}
/*
 * check-name: Function pointer inheritance
 */
