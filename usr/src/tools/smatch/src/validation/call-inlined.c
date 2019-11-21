static const char messg[] = "def";

static inline int add(int a, int b)
{
	return a + b;
}

int  foo(int a, int b) { return add(a + b, 1); }
void bar(int a, int b) {        add(a + b, 1); }


static inline const char *lstrip(const char *str)
{
	return str + 1;
}

const char *bas(void) { return lstrip("abc"); }
const char *qus(void) { return lstrip(messg); }

/*
 * check-name: call-inlined
 * check-command: test-linearize -Wno-decl -m64 $file
 * check-assert: sizeof(void*) == 8
 *
 * check-output-start
foo:
.L0:
	<entry-point>
	add.32      %r3 <- %arg1, %arg2
	add.32      %r5 <- %r3, $1
	ret.32      %r5


bar:
.L3:
	<entry-point>
	ret


bas:
.L6:
	<entry-point>
	add.64      %r16 <- "abc", $1
	ret.64      %r16


qus:
.L9:
	<entry-point>
	add.64      %r21 <- messg, $1
	ret.64      %r21


 * check-output-end
 */
