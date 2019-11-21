struct s {
	int f:5;
};

void inc(struct s *p)
{
	p->f++;
}

/*
 * check-name: bitfield-inc
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: add\\.5
 */
