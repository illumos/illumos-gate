struct s {
	char :2;
	char f:3;
};

int foo(struct s s, int a)
{
	s.f = a;
	return s.f;
}

/*
 * check-name: bitfield-store-load signed
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: shl\\.
 * check-output-excludes: lsr\\.
 * check-output-excludes: or\\.
 * check-output-excludes: [sz]ext\\.
 * check-output-excludes: trunc\\.
 * check-output-pattern(1): and\\.
 */
