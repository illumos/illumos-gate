struct u {
	unsigned int  :2;
	unsigned int f:3;
};

int bfu(struct u s, int a)
{
	s.f = a;
	return s.f;
}

/*
 * check-name: and-or-bfu
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-pattern(1): and\\.
 * check-output-excludes: or\\.
 * check-output-excludes: shl\\.
 * check-output-excludes: lsr\\.
 */
