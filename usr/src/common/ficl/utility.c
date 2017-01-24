#include "ficl.h"
#include <limits.h>

/*
 * a l i g n P t r
 * Aligns the given pointer to FICL_ALIGN address units.
 * Returns the aligned pointer value.
 */
void *
ficlAlignPointer(void *ptr)
{
#if FICL_PLATFORM_ALIGNMENT > 1
	intptr_t p = (intptr_t)ptr;

	if (p & (FICL_PLATFORM_ALIGNMENT - 1))
		ptr = (void *)((p & ~(FICL_PLATFORM_ALIGNMENT - 1)) +
		    FICL_PLATFORM_ALIGNMENT);
#endif
	return (ptr);
}

/*
 * s t r r e v
 */
char *
ficlStringReverse(char *string)
{
	int i = strlen(string);
	char *p1 = string;		/* first char of string */
	char *p2 = string + i - 1;	/* last non-NULL char of string */
	char c;

	if (i > 1) {
		while (p1 < p2) {
			c = *p2;
			*p2 = *p1;
			*p1 = c;
			p1++; p2--;
		}
	}

	return (string);
}

/*
 * d i g i t _ t o _ c h a r
 */
static char digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

char
ficlDigitToCharacter(int value)
{
	return (digits[value]);
}

/*
 * i s P o w e r O f T w o
 * Tests whether supplied argument is an integer power of 2 (2**n)
 * where 32 > n > 1, and returns n if so. Otherwise returns zero.
 */
int
ficlIsPowerOfTwo(ficlUnsigned u)
{
	int i = 1;
	ficlUnsigned t = 2;

	for (; ((t <= u) && (t != 0)); i++, t <<= 1) {
		if (u == t)
			return (i);
	}

	return (0);
}

/*
 * l t o a
 */
char *
ficlLtoa(ficlInteger value, char *string, int radix)
{
	char *cp = string;
	int sign = ((radix == 10) && (value < 0));
	int pwr;

	FICL_ASSERT(NULL, radix > 1);
	FICL_ASSERT(NULL, radix < 37);
	FICL_ASSERT(NULL, string);

	pwr = ficlIsPowerOfTwo((ficlUnsigned)radix);

	if (sign)
		value = -value;

	if (value == 0)
		*cp++ = '0';
	else if (pwr != 0) {
		ficlUnsigned v = (ficlUnsigned) value;
		ficlUnsigned mask = ~(ULONG_MAX << pwr);
		while (v) {
			*cp++ = digits[v & mask];
			v >>= pwr;
		}
	} else {
		ficl2UnsignedQR result;
		ficl2Unsigned v;
		FICL_UNSIGNED_TO_2UNSIGNED((ficlUnsigned)value, v);
		while (FICL_2UNSIGNED_NOT_ZERO(v)) {
			result = ficl2UnsignedDivide(v, (ficlUnsigned)radix);
			*cp++ = digits[result.remainder];
			v = result.quotient;
		}
	}

	if (sign)
		*cp++ = '-';

	*cp++ = '\0';

	return (ficlStringReverse(string));
}

/*
 * u l t o a
 */
char *
ficlUltoa(ficlUnsigned value, char *string, int radix)
{
	char *cp = string;
	ficl2Unsigned ud;
	ficl2UnsignedQR result;

	FICL_ASSERT(NULL, radix > 1);
	FICL_ASSERT(NULL, radix < 37);
	FICL_ASSERT(NULL, string);

	if (value == 0)
		*cp++ = '0';
	else {
		FICL_UNSIGNED_TO_2UNSIGNED(value, ud);
		while (FICL_2UNSIGNED_NOT_ZERO(ud)) {
			result = ficl2UnsignedDivide(ud, (ficlUnsigned)radix);
			ud = result.quotient;
			*cp++ = digits[result.remainder];
		}
	}

	*cp++ = '\0';

	return (ficlStringReverse(string));
}

/*
 * c a s e F o l d
 * Case folds a NULL terminated string in place. All characters
 * get converted to lower case.
 */
char *
ficlStringCaseFold(char *cp)
{
	char *oldCp = cp;

	while (*cp) {
		if (isupper((unsigned char)*cp))
			*cp = (char)tolower((unsigned char)*cp);
		cp++;
	}

	return (oldCp);
}

/*
 * s t r i n c m p
 * (jws) simplified the code a bit in hopes of appeasing Purify
 */
int
ficlStrincmp(char *cp1, char *cp2, ficlUnsigned count)
{
	int i = 0;

	for (; 0 < count; ++cp1, ++cp2, --count) {
		i = tolower((unsigned char)*cp1) - tolower((unsigned char)*cp2);
		if (i != 0)
			return (i);
		else if (*cp1 == '\0')
			return (0);
	}
	return (0);
}

/*
 * s k i p S p a c e
 * Given a string pointer, returns a pointer to the first non-space
 * char of the string, or to the NULL terminator if no such char found.
 * If the pointer reaches "end" first, stop there. Pass NULL to
 * suppress this behavior.
 */
char *
ficlStringSkipSpace(char *cp, char *end)
{
	FICL_ASSERT(NULL, cp);

	while ((cp != end) && isspace((unsigned char)*cp))
		cp++;

	return (cp);
}

void
ficlCompatibilityTextOutCallback(ficlCallback *callback, char *text,
    ficlCompatibilityOutputFunction outputFunction)
{
	char buffer[256];
	char *bufferStop = buffer + sizeof (buffer) - 1;

	if (text == NULL) {
		outputFunction(callback->vm, NULL, 0 /* false */);
		return;
	}

	while (*text) {
		int newline = 0 /* false */;
		char *trace = buffer;
		while ((*text) && (trace < bufferStop)) {
			switch (*text) {
			/* throw away \r */
			case '\r':
				text++;
			continue;
			case '\n':
				text++;
				newline = !0 /* true */;
			break;
			default:
				*trace++ = *text++;
			break;
			}
		}

		*trace = 0;
		(outputFunction)(callback->vm, buffer, newline);
	}
}
