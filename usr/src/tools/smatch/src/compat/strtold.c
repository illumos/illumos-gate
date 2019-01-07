#include <stdlib.h>

long double string_to_ld(const char *nptr, char **endptr)
{
	return strtold(nptr, endptr);
}
