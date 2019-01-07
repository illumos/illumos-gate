void foo(void)
{
        int a = a || 0;
        if (a) ;
}

/*
 * check-name: internal infinite loop (0)
 * check-command: sparse -Wno-decl $file
 * check-timeout:
 */
