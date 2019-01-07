struct s {
	int a, b, c;
};

struct s s_init_all(int a)
{
	struct s s = { .a = a, .b = 42, .c = 123, };
	return s;
}

/*
 * check-name: struct implicit init zero not needed
 * check-command: test-linearize -Wno-decl $file
 * check-known-to-fail
 *
 * check-output-start
s_init_all:
.L4:
	<entry-point>
	store.32    %arg1 -> 0[s]
	store.32    $42 -> 4[s]
	store.32    $123 -> 8[s]
	load.96     %r8 <- 0[s]
	ret.96      %r8


 * check-output-end
 */
