struct s {
	unsigned int :2;
	unsigned int f:3;
};

int foo(struct s s, int a)
{
	s.f = a;
	return s.f;
}

/*
 * check-name: bitfield-store-load unsigned
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: shl\\.
 * check-output-excludes: lsr\\.
 * check-output-excludes: or\\.
 * check-output-pattern(1): and\\.
 */
