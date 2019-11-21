struct s {
	  signed int  :2;
	  signed int f:3;
};

int bfs(struct s s, int a)
{
	s.f = a;
	return s.f;
}

/*
 * check-name: and-or-bfs
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): trunc\\.
 * check-output-pattern(1): sext\\.
 * check-output-excludes: and\\.
 * check-output-excludes: or\\.
 * check-output-excludes: shl\\.
 * check-output-excludes: lsr\\.
 */
