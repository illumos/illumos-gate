extern void func0();
extern void func1(), func2();

/*
 * check-name: strict-prototypes enabled
 * check-command: sparse -Wstrict-prototypes $file
 * check-known-to-fail
 *
 * check-error-start
strict-prototypes1.c:1:18: warning: non-ANSI function declaration of function 'func0'
strict-prototypes1.c:2:18: warning: non-ANSI function declaration of function 'func1'
strict-prototypes1.c:2:27: warning: non-ANSI function declaration of function 'func2'
 * check-error-end
 */
