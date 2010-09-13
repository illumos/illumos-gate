/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This program is copyright Alec Muffett 1993. The author disclaims all
 * responsibility or liability with respect to it's usage or its effect
 * upon hardware or computer systems, and maintains copyright as set out
 * in the "LICENCE" document which accompanies distributions of Crack v4.0
 * and upwards.
 */

#include "packer.h"


char
Chop(register char *string)
{
	register char c;
	register char *ptr;

	c = '\0';

	for (ptr = string; *ptr; ptr++);
	if (ptr != string) {
		c = *(--ptr);
		*ptr = '\0';
	}
	return (c);
}

char
Chomp(register char *string)
{
	register char c;
	register char *ptr;

	c = '\0';

	for (ptr = string; *ptr; ptr++)
		;
	if (ptr != string && isspace(*(--ptr))) {
		c = *ptr;
		*ptr = '\0';
	}
	return (c);
}


char *
Trim(register char *string)
{
	register char *ptr;

	for (ptr = string; *ptr; ptr++);

	while ((--ptr >= string) && isspace(*ptr));

	*(++ptr) = '\0';

	return (ptr);
}
