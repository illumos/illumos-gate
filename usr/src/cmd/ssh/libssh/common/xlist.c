/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include "xmalloc.h"
#include "xlist.h"

char **
xsplit(char *list, char sep)
{
	char **a;
	char *p, *q;
	uint_t n = 0;

	for (n = 0, p = list; p && *p; ) {
		while (p && *p && *p == sep)
			p++;
		if (!*p)
			break;
		n++;
		p = strchr(p, sep);
	}
	a = (char **)xmalloc(sizeof (char *) * (n + 2));
	for (n = 0, p = list; p && *p; ) {
		while (*p == sep)
			p++;
		if (!*p)
			break;
		q = strchr(p, sep);
		if (!q)
			q = p + strlen(p);
		a[n] = (char *)xmalloc((q - p + 2));
		(void) strncpy(a[n], p, q - p);
		a[n][q - p] = '\0';
		n++;
		if (!*q)
			break;
		p = q + 1;
	}
	a[n] = NULL;
	return (a);
}

void
xfree_split_list(char **list)
{
	char **p;
	for (p = list; p && *p; p++) {
		xfree(*p);
	}
	xfree(list);
}

char *
xjoin(char **alist, char sep)
{
	char **p;
	char *list;
	char sep_str[2];
	uint_t n;

	for (n = 1, p = alist; p && *p; p++) {
		if (!*p || !**p)
			continue;
		n += strlen(*p) + 1;
	}
	list = (char *)xmalloc(n);
	*list = '\0';

	sep_str[0] = sep;
	sep_str[1] = '\0';
	for (p = alist; p && *p; p++) {
		if (!*p || !**p)
			continue;
		if (*list != '\0')
			(void) strlcat(list, sep_str, n);
		(void) strlcat(list, *p, n);
	}
	return (list);
}
