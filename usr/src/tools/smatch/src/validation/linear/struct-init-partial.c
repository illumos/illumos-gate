struct s {
	int a, b, c;
};

struct s s_init_first(int a)
{
	struct s s = { .a = a, };
	return s;
}

struct s s_init_third(int a)
{
	struct s s = { .c = a, };
	return s;
}

/*
 * check-name: struct implicit init zero needed
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
s_init_first:
.L0:
	<entry-point>
	store.96    $0 -> 0[s]
	store.32    %arg1 -> 0[s]
	load.96     %r2 <- 0[s]
	ret.96      %r2


s_init_third:
.L2:
	<entry-point>
	store.96    $0 -> 0[s]
	store.32    %arg1 -> 8[s]
	load.96     %r5 <- 0[s]
	ret.96      %r5


 * check-output-end
 */
