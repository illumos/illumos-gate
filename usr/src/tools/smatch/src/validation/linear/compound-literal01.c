struct bfs {
        int a: 2;
        int b: 30;
};

int foo(void)
{
        struct bfs bf = { .a = 1, .b = 2 };
        return (struct bfs[]){bf}[0].b;
}

/*
 * check-name: compound-literal01.c
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: ret\\..*\\$2
 */
