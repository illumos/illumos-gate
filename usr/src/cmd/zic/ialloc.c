#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* static char	elsieid[] = "@(#)ialloc.c	8.29"; */

/*LINTLIBRARY*/

#include "private.h"

#define	nonzero(n)	(((n) == 0) ? 1 : (n))

char *
imalloc(n)
const int	n;
{
	return (malloc((size_t) nonzero(n)));
}

void *
irealloc(pointer, size)
void * const	pointer;
const int	size;
{
	if (pointer == NULL)
		return (imalloc(size));
	return (realloc((void *) pointer, (size_t) nonzero(size)));
}

char *
icatalloc(old, new)
char * const		old;
const char * const	new;
{
	register char *	result;
	register int	oldsize, newsize;

	newsize = (new == NULL) ? 0 : strlen(new);
	if (old == NULL)
		oldsize = 0;
	else if (newsize == 0)
		return (old);
	else	oldsize = strlen(old);
	if ((result = irealloc(old, oldsize + newsize + 1)) != NULL)
		if (new != NULL)
			(void) strcpy(result + oldsize, new);
	return (result);
}

char *
icpyalloc(string)
const char * const	string;
{
	return (icatalloc((char *) NULL, string));
}

void
ifree(p)
char * const	p;
{
	if (p != NULL)
		(void) free(p);
}
