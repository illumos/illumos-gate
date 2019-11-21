struct S {
	         int  :1;
	  signed int s:2;
	unsigned int u:3;
};

int os(int i, struct S *b) { return i || b->s; }
int ou(int i, struct S *b) { return i || b->u; }

/*
 * check-name: trunc-seteq0
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: trunc\\.
 * check-output-excludes: sext\\.
 * check-output-excludes: zext\\.
 */
