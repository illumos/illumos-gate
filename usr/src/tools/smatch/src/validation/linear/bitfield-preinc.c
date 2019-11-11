struct s {
	int f:3;
};

int preinc(void)
{
	struct s s = { 7 };
	return ++s.f;
}

/*
 * check-name: bitfield-preinc
 * check-description: ++X is equivalent to X+=1
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: ret.32 *\\$0
 */
