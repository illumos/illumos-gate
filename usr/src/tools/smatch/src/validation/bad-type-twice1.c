static unsigned long foo(unsigned long val, void *ref)
{
	if (val >= ref)
		val = 0;
	return val;
}

/*
 * check-name: bad-type-twice1
 *
 * check-error-start
bad-type-twice1.c:3:17: error: incompatible types for operation (>=)
bad-type-twice1.c:3:17:    left side has type unsigned long val
bad-type-twice1.c:3:17:    right side has type void *ref
 * check-error-end
 */
