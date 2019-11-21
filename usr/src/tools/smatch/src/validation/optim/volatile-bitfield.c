struct s {
	int f:3;
};

void foo(volatile struct s *p)
{
	p->f;
}

/*
 * check-name: volatile-bitfield
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-contains: load\\.
 */
