typedef	unsigned int u32;

int smulm1(int a) { return a * -1; }
u32 umulm1(u32 a) { return a * (u32) -1; }
int sdivm1(int a) { return a / -1; }
u32 udivm1(u32 a) { return a / (u32) -1; }

/*
 * check-name: muldiv-minus-one
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: mul[us]\\.
 * check-output-excludes: divs\\.
 * check-output-contains: neg\\.
 * check-output-contains: divu\\.
 * check-output-pattern(3): neg\\.
 */
