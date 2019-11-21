static int foo(b)
	int b: 4;
{
      return 0;
}

/*
 * check-name: bitfield in K&R
 *
 * check-known-to-fail
 * check-error-start
bitfield-kr.c:2:9: error: bitfield in K&R declaration of 'foo'
 * check-error-end
 */
