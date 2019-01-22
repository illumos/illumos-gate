/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*LINTLIBRARY*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#include <ns.h>
#include <list.h>

/*
 *	Commonly Used routines...
 */

/*
 * FUNCTION:
 *	printer_create(char *name, char **aliases, char *source,
 *			ns_kvp_t **attributes)
 * INPUT(S):
 *	char *name
 *		- primary name of printer
 *	char **aliases
 *		- aliases for printer
 *	char *source
 *		- name service derived from
 *	ks_kvp_t **attributes
 *		- key/value pairs
 * OUTPUT(S):
 *	ns_printer_t * (return value)
 *		- pointer to printer object structure
 * DESCRIPTION:
 */
ns_printer_t *
ns_printer_create(char *name, char **aliases, char *source,
    ns_kvp_t **attributes)
{
	ns_printer_t *printer;

	if ((printer = (ns_printer_t *)calloc(1, sizeof (*printer))) != NULL) {
		printer->name = (char *)name;
		printer->aliases = (char **)aliases;
		printer->source = (char *)source;
		printer->attributes = (ns_kvp_t **)attributes;
	}
	return (printer);
}


static int
ns_strcmp(char *s1, char *s2)
{
	return (strcmp(s1, s2) != 0);
}


/*
 * FUNCTION:
 *	ns_printer_match_name(const ns_printer_t *printer, const char *name)
 * INPUT(S):
 *	const ns_printer_t *printer
 *		- key/value pair to check
 *	const char *key
 *		- key for matching
 * OUTPUT(S):
 *	int (return value)
 *		- 0 if matched
 * DESCRIPTION:
 */
int
ns_printer_match_name(ns_printer_t *printer, const char *name)
{
	if ((printer == NULL) || (printer->name == NULL) || (name == NULL))
		return (-1);

	if ((strcmp(printer->name, name) == 0) ||
	    (list_locate((void **)printer->aliases,
	    (COMP_T)ns_strcmp, (void *)name) != NULL))
		return (0);

	return (-1);
}


static void
_ns_append_printer_name(const char *name, va_list ap)
{
	char *buf = va_arg(ap, char *);
	int bufsize = va_arg(ap, int);

	if (name == NULL)
		return;

	(void) strlcat(buf, name, bufsize);
	(void) strlcat(buf, "|", bufsize);
}

/*
 * FUNCTION:
 *	char *ns_printer_name_list(const ns_printer_t *printer)
 * INPUT:
 *	const ns_printer_t *printer - printer object to generate list from
 * OUTPUT:
 *	char * (return) - a newly allocated string containing the names of
 *			  the printer
 */
char *
ns_printer_name_list(const ns_printer_t *printer)
{
	char buf[BUFSIZ];

	if ((printer == NULL) || (printer->name == NULL))
		return (NULL);

	if (snprintf(buf, sizeof (buf), "%s|", printer->name) >= sizeof (buf)) {
		syslog(LOG_ERR, "ns_printer_name:buffer overflow");
		return (NULL);
	}

	list_iterate((void **)printer->aliases,
	    (VFUNC_T)_ns_append_printer_name, buf, sizeof (buf));

	buf[strlen(buf) - 1] = '\0';

	return (strdup(buf));
}
