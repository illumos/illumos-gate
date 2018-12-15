int and_0(int a)
{
	return a && 0;
}

int and_1(int a)
{
	return a && 1;
}

int or_0(int a)
{
	return a || 0;
}

int or_1(int a)
{
	return a || 1;
}

/*
 * check-name: bool-simplify
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
and_0:
.L0:
	<entry-point>
	ret.32      $0


and_1:
.L2:
	<entry-point>
	setne.1     %r8 <- %arg1, $0
	cast.32     %r11 <- (1) %r8
	ret.32      %r11


or_0:
.L4:
	<entry-point>
	setne.1     %r14 <- %arg1, $0
	cast.32     %r17 <- (1) %r14
	ret.32      %r17


or_1:
.L6:
	<entry-point>
	ret.32      $1


 * check-output-end
 */
