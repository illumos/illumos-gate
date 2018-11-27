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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*LINTLIBRARY*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <nss_dbdefs.h>
#include <syslog.h>

#include <ns.h>
#include <list.h>


/*
 * because legacy code can use a variety of values for various name
 * services, this routine is needed to "normalize" them.
 */
char *
normalize_ns_name(char *ns)
{
	if (ns == NULL)
		return (NULL);
	else if ((strcasecmp(ns, "files") == 0) ||
	    (strcasecmp(ns, "system") == 0) ||
	    (strcasecmp(ns, "etc") == 0))
		return ("files");
	else if (strcasecmp(ns, "nis") == 0)
		return ("nis");
	else if (strcasecmp(ns, "ldap") == 0)
		return ("ldap");
	else
		return (ns);
}


/*
 * FUNCTION:
 *	void ns_printer_destroy(ns_printer_t *printer)
 * INPUT:
 *	ns_printer_t *printer - a pointer to the printer "object" to destroy
 * DESCRIPTION:
 *	This function will free all of the memory associated with a printer
 *	object.  It does this by walking the structure ad freeing everything
 *	underneath it, with the exception of the object source field.  This
 *	field is not filled in with newly allocated space when it is
 *	generated
 */
void
ns_printer_destroy(ns_printer_t *printer)
{
	if (printer != NULL) {
		if (printer->attributes != NULL) {	/* attributes */
			list_iterate((void **)printer->attributes,
			    ns_kvp_destroy);
			free(printer->attributes);
		}
		if (printer->aliases != NULL) {		/* aliases */
			free(printer->aliases);
		}
		if (printer->name != NULL)		/* primary name */
			free(printer->name);
		free(printer);
	}
}


/*
 * FUNCTION:
 *	ns_printer_t **ns_printer_get_list()
 * OUTPUT:
 *	ns_printer_t ** (return value) - an array of pointers to printer
 *					 objects.
 * DESCRIPTION:
 *	This function will return a list of all printer objects found in every
 *	configuration interface.
 */
ns_printer_t **
ns_printer_get_list(const char *ns)
{
	char	    buf[NSS_LINELEN_PRINTERS];
	ns_printer_t    **printer_list = NULL;

	(void) setprinterentry(0, (char *)ns);

	ns = normalize_ns_name((char *)ns);
	while (getprinterentry(buf, sizeof (buf), (char *)ns) == 0) {
		ns_printer_t *printer =
		    (ns_printer_t *)_cvt_nss_entry_to_printer(buf, NULL);

		printer_list = (ns_printer_t **)list_append(
		    (void **)printer_list,
		    (void *)printer);
	}

	(void) endprinterentry();

	return (printer_list);
}


/*
 * This function looks for the named printer in the supplied
 * name service (ns), or the name services configured under
 * the nsswitch.
 */
ns_printer_t *
ns_printer_get_name(const char *name, const char *ns)
{
	ns_printer_t *result = NULL;
	char buf[NSS_LINELEN_PRINTERS];

	/*
	 * Reset printer entries to the start so we know we will always
	 * pick up the correct entry
	 */
	endprinterentry();

	if ((result = (ns_printer_t *)posix_name(name)) != NULL)
		return (result);

	ns = normalize_ns_name((char *)ns);
	if (getprinterbyname((char *)name, buf, sizeof (buf), (char *)ns) == 0)
		result = (ns_printer_t *)_cvt_nss_entry_to_printer(buf, NULL);

	return (result);
}


/*
 * FUNCTION:
 *	int ns_printer_put(const ns_printer_t *printer)
 * INPUT:
 *	const ns_printer_t *printer - a printer object
 * DESCRIPTION:
 *	This function attempts to put the data in the printer object back
 *	to the "name service" specified in the source field of the object.
 */
int
ns_printer_put(const ns_printer_t *printer)
{
	char func[32];
	int (*fpt)();

	if ((printer == NULL) || (printer->source == NULL))
		return (-1);

	if (snprintf(func, sizeof (func), "%s_put_printer",
	    normalize_ns_name(printer->source)) >= sizeof (func)) {
			syslog(LOG_ERR, "ns_printer_put: buffer overflow");
			return (-1);
	}

	if ((fpt = (int (*)())dlsym(RTLD_DEFAULT, func)) != NULL)
		return ((*fpt)(printer));

	return (-1);
}
