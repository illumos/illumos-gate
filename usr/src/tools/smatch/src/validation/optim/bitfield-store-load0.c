int ufoo(unsigned int a)
{
	struct u {
		unsigned int :2;
		unsigned int a:3;
	} bf;

	bf.a = a;
	return bf.a;
}

int sfoo(int a)
{
	struct s {
		signed int :2;
		signed int a:3;
	} bf;

	bf.a = a;
	return bf.a;
}

/*
 * check-name: optim store/load bitfields
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
ufoo:
.L0:
	<entry-point>
	and.32      %r11 <- %arg1, $7
	ret.32      %r11


sfoo:
.L2:
	<entry-point>
	trunc.3     %r16 <- (32) %arg1
	sext.32     %r23 <- (3) %r16
	ret.32      %r23


 * check-output-end
 */
