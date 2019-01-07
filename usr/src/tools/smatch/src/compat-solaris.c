#include "lib.h"
#include "allocate.h"

#include "compat/mmap-blob.c"

#include <floatingpoint.h>
#include <limits.h>
#include <errno.h>

long double string_to_ld(const char *str, char **endptr)
{
	long double res;
	decimal_record dr;
	enum decimal_string_form form;
	decimal_mode dm;
	fp_exception_field_type excp;
	char *echar;

	string_to_decimal ((char **)&str, INT_MAX, 0,
			   &dr, &form, &echar);
	if (endptr) *endptr = (char *)str;

	if (form == invalid_form) {
		errno = EINVAL;
		return 0.0;
	}

	dm.rd = fp_nearest;
	decimal_to_quadruple (&res, &dm, &dr, &excp);
        if (excp & ((1 << fp_overflow) | (1 << fp_underflow)))
                errno = ERANGE;
	return res;
}
