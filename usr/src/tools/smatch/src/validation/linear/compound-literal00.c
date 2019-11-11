struct bfs {
        int a: 2;
        int b: 30;
};

int foo(void)
{
        return (struct bfs){ .a = 1, .b = 2}.b;
}

/*
 * check-name: compound-literal00.c
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$2
 * check-error-end
 */
