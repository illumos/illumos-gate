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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

static char **
strsplit(char *string, char *seperators)
{
	char **list = NULL;
	char *where = NULL;
	char *element;

	for (element = strtok_r(string, seperators, &where); element != NULL;
	    element = strtok_r(NULL, seperators, &where))
		list = (char **)list_append((void **)list, element);

	return (list);
}

/*
 *	Manipulate bsd_addr structures
 */
ns_bsd_addr_t *
bsd_addr_create(const char *server, const char *printer, const char *extension)
{
	ns_bsd_addr_t *addr = NULL;

	if ((server != NULL) &&
	    ((addr = calloc(1, sizeof (*addr))) != NULL)) {
		addr->printer = (char *)printer;
		addr->server = (char *)server;
		addr->extension = (char *)extension;
	}

	return (addr);
}

static char *
bsd_addr_to_string(const ns_bsd_addr_t *addr)
{
	char buf[BUFSIZ];

	if ((addr == NULL) || (addr->server == NULL))
		return (NULL);

	if (snprintf(buf, sizeof (buf), "%s", addr->server) >= sizeof (buf)) {
		syslog(LOG_ERR, "bsd_addr_to_string: buffer overflow");
		return (NULL);
	}

	if ((addr->printer != NULL) || (addr->extension != NULL))
		(void) strlcat(buf, ",", sizeof (buf));
	if (addr->printer != NULL)
		if (strlcat(buf, addr->printer, sizeof (buf)) >= sizeof (buf)) {
			syslog(LOG_ERR, "bsd_addr_to_string: buffer overflow");
			return (NULL);
		}
	if (addr->extension != NULL) {
		(void) strlcat(buf, ",", sizeof (buf));
		if (strlcat(buf, addr->extension, sizeof (buf))
		    >= sizeof (buf)) {
			syslog(LOG_ERR, "bsd_addr_to_string: buffer overflow");
			return (NULL);
		}
	}

	return (strdup(buf));
}

ns_bsd_addr_t *
string_to_bsd_addr(const char *string)
{
	char **list, *tmp, *printer = NULL, *extension = NULL;

	if (string == NULL)
		return (NULL);

	tmp = strdup(string);
	list = strsplit(tmp, ",");

	if (list[1] != NULL) {
		printer = list[1];
		if (list[2] != NULL)
			extension = list[2];
	}

	return (bsd_addr_create(list[0], printer, extension));
}

static char *
list_to_string(const char **list)
{
	char buf[BUFSIZ];

	if ((list == NULL) || (*list == NULL))
		return (NULL);

	if (snprintf(buf, sizeof (buf), "%s", *list) >= sizeof (buf)) {
		syslog(LOG_ERR, "list_to_string: buffer overflow");
		return (NULL);
	}

	while (*++list != NULL) {
		(void) strlcat(buf, ",", sizeof (buf));
		if (strlcat(buf, *list, sizeof (buf)) >= sizeof (buf)) {
			syslog(LOG_ERR, "list_to_string: buffer overflow");
			return (NULL);
		}
	}

	return (strdup(buf));
}

static char *
internal_list_to_string(const ns_printer_t **list)
{
	char buf[BUFSIZ];

	if ((list == NULL) || (*list == NULL))
		return (NULL);

	if (snprintf(buf, sizeof (buf), "%s", (*list)->name) >= sizeof (buf)) {
		syslog(LOG_ERR, "internal_list_to_string:buffer overflow");
		return (NULL);
	}

	while (*++list != NULL) {
		(void) strlcat(buf, ",", sizeof (buf));
		if (strlcat(buf, (*list)->name, sizeof (buf)) >= sizeof (buf)) {
			syslog(LOG_ERR,
			    "internal_list_to_string:buffer overflow");
			return (NULL);
		}
	}

	return (strdup(buf));
}


char *
value_to_string(const char *key, void *value)
{
	char *string = NULL;

	if ((key != NULL) && (value != NULL)) {
		if (strcmp(key, NS_KEY_BSDADDR) == 0) {
			string = bsd_addr_to_string(value);
		} else if ((strcmp(key, NS_KEY_ALL) == 0) ||
		    (strcmp(key, NS_KEY_GROUP) == 0)) {
			string = list_to_string(value);
		} else if (strcmp(key, NS_KEY_LIST) == 0) {
			string = internal_list_to_string(value);
		} else {
			string = strdup((char *)value);
		}
	}

	return (string);
}


void *
string_to_value(const char *key, char *string)
{
	void *value = NULL;

	if ((key != NULL) && (string != NULL) && (string[0] != '\0')) {
		if (strcmp(key, NS_KEY_BSDADDR) == 0) {
			value = (void *)string_to_bsd_addr(string);
		} else if ((strcmp(key, NS_KEY_ALL) == 0) ||
		    (strcmp(key, NS_KEY_GROUP) == 0)) {
			value = (void *)strsplit(string, ",");
		} else {
			value = (void *)string;
		}
	}

	return (value);
}

static void
split_name(char *name, const char *delimiter, char **p1, char **p2, char **p3)
{
	char *tmp, *junk = NULL;

	if (p1 != NULL)
		*p1 = NULL;
	if (p2 != NULL)
		*p2 = NULL;
	if (p3 != NULL)
		*p3 = NULL;

	if ((name == NULL) || (delimiter == NULL)) {
		syslog(LOG_DEBUG, "split_name(): name/delimter invalid\n");
		return;
	}

	for (tmp = (char *)strtok_r(name, delimiter, &junk); tmp != NULL;
	    tmp = (char *)strtok_r(NULL, delimiter, &junk))
		if ((p1 != NULL) && (*p1 == NULL)) {
			*p1 = tmp;
		} else if ((p2 != NULL) && (*p2 == NULL)) {
			*p2 = tmp;
			if (p3 == NULL)
				break;
		} else if ((p3 != NULL) && (*p3 == NULL)) {
			*p3 = tmp;
			break;
		}
}

/*
 * This implements support for printer names that are fully resolvable
 * on their own.  These "complete" names are converted into a ns_printer_t
 * structure containing an appropriate "bsdaddr" attribute.  The supported
 * formats are as follows:
 *	POSIX style (server:printer[:conformance]).
 *		This format is an adaptation of the format originally
 *		described in POSIX 1387.4.  The POSIX draft has since been
 *		squashed, but this particular component lives on.  The
 *		conformace field has been added to allow further identification
 *		of the the server.
 */
ns_printer_t *
posix_name(const char *name)
{
	ns_printer_t *printer = NULL;
	char *tmp = NULL;

	if ((name != NULL) && ((tmp = strpbrk(name, ":")) != NULL)) {
		char *server = NULL;
		char *queue = NULL;
		char *extension = NULL;
		char *addr = strdup(name);
		char buf[BUFSIZ];

		if (*tmp == ':')
			split_name(addr, ": \t", &server, &queue, &extension);

		memset(buf, 0, sizeof (buf));
		if ((server != NULL) && (queue != NULL))
			snprintf(buf, sizeof (buf), "%s,%s%s%s", server,
			    queue, (extension != NULL ? "," : ""),
			    (extension != NULL ? extension : ""));

		/* build the structure here */
		if (buf[0] != '\0') {
			ns_kvp_t **list, *kvp;

			kvp = ns_kvp_create(NS_KEY_BSDADDR, buf);
			list = (ns_kvp_t **)list_append(NULL, kvp);
			if (list != NULL)
				printer = ns_printer_create(strdup(name), NULL,
				    "posix", list);
		}
	}

	return (printer);
}

/*
 * FUNCTION:
 *	int ns_bsd_addr_cmp(ns_bsd_addr_t *at, ns_bsd_addr_t *a2)
 * INPUTS:
 *	ns_bsd_addr_t *a1 - a bsd addr
 *	ns_bsd_addr_t *21 - another bsd addr
 * DESCRIPTION:
 *	This functions compare 2 bsd_addr structures to determine if the
 *	information in them is the same.
 */
static int
ns_bsd_addr_cmp(ns_bsd_addr_t *a1, ns_bsd_addr_t *a2)
{
	int rc;

	if ((a1 == NULL) || (a2 == NULL))
		return (1);

	if ((rc = strcmp(a1->server, a2->server)) != 0)
		return (rc);

	if ((a1->printer == NULL) || (a2->printer == NULL))
		return (a1->printer != a2->printer);

	return (strcmp(a1->printer, a2->printer));
}




/*
 * FUNCTION:    ns_bsd_addr_cmp_local()
 *
 * DESCRIPTION: This function compares 2 bsd_addr structures to determine if
 *              the information in them is the same. It destinquishes between
 *              real printer names and alias names while doing the compare.
 *
 * INPUTS:      ns_bsd_addr_t *a1 - a bsd addr
 *              ns_bsd_addr_t *a2 - another bsd addr
 */

static int
ns_bsd_addr_cmp_local(ns_bsd_addr_t *a1, ns_bsd_addr_t *a2)
{
	int rc;

	if ((a1 == NULL) || (a2 == NULL)) {
		return (1);
	}

	if ((rc = strcmp(a1->server, a2->server)) != 0) {
		return (rc);
	}

	if ((a1->printer == NULL) || (a2->printer == NULL)) {
		return (a1->printer != a2->printer);
	}

	rc = strcmp(a1->printer, a2->printer);
	if (rc == 0) {
		/*
		 * The printer's real names are the same, but now check if
		 * their local names (alias) are the same.
		 */
		rc = strcmp(a1->pname, a2->pname);
	}

	return (rc);
} /* ns_bsd_addr_cmp_local */



/*
 * FUNCTION:
 *	ns_bsd_addr_t *ns_bsd_addr_get_name(char *name)
 * INPUTS:
 *	char *name - name of printer to get address for
 * OUTPUTS:
 *	ns_bsd_addr_t *(return) - the address of the printer
 * DESCRIPTION:
 *	This function will get the BSD address of the printer specified.
 *	it fills in the printer name if none is specified in the "name service"
 *	as a convenience to calling functions.
 */
ns_bsd_addr_t *
ns_bsd_addr_get_name(char *name)
{
	ns_printer_t *printer;
	ns_bsd_addr_t *addr = NULL;

	endprinterentry();
	if ((printer = ns_printer_get_name(name, NULL)) != NULL) {
		addr = ns_get_value(NS_KEY_BSDADDR, printer);

		if (addr != NULL && addr->printer == NULL)
			addr->printer = strdup(printer->name);
		if (addr != NULL) {
			/*
			 * if the name given is not the same as that in the
			 * this is an alias/remote name so put that into the
			 * pname field otherwise duplicate the real printer
			 * name
			 */
			if (strcmp(name, printer->name) != 0) {
				addr->pname = strdup(name);
			} else {
				addr->pname = strdup(printer->name);
			}
		}
	}

	return (addr);
}


/*
 * FUNCTION:
 *	ns_bsd_addr_t **ns_bsd_addr_get_list()
 * OUTPUT:
 *	ns_bsd_addr_t **(return) - a list of bsd addresses for all printers
 *				   in all "name services"
 * DESCRIPTION:
 *	This function will gather a list of all printer addresses in all
 *	of the "name services".  All redundancy is removed.
 */
ns_bsd_addr_t **
ns_bsd_addr_get_list(int unique)
{
	ns_printer_t **printers;
	ns_bsd_addr_t **list = NULL;
	char **aliases = NULL;

	for (printers = ns_printer_get_list(NULL);
	    printers != NULL && *printers != NULL; printers++) {
		ns_bsd_addr_t *addr;

		if (strcmp(NS_NAME_ALL, (*printers)->name) == 0)
			continue;

		if ((addr = ns_get_value(NS_KEY_BSDADDR, *printers)) != NULL) {
			if (addr->printer == NULL)
				addr->printer = strdup((*printers)->name);
			addr->pname = strdup((*printers)->name);
		}

		if (unique == UNIQUE)
			list =
			    (ns_bsd_addr_t **)list_append_unique((void **)list,
			    (void *)addr, (COMP_T)ns_bsd_addr_cmp);
		else if (unique == LOCAL_UNIQUE)
			list =
			    (ns_bsd_addr_t **)list_append_unique((void **)list,
			    (void *)addr, (COMP_T)ns_bsd_addr_cmp_local);
		else
			list = (ns_bsd_addr_t **)list_append((void **)list,
			    (void *)addr);

		for (aliases = (*printers)->aliases;
		    (aliases != NULL) && (*aliases != NULL); aliases++) {
			/*
			 * Include any alias names that belong to the printer
			 */

			if ((addr =
			    ns_get_value(NS_KEY_BSDADDR, *printers)) != NULL) {
				if (addr->printer == NULL) {
					addr->printer = strdup(*aliases);
				}
				addr->pname = strdup(*aliases);
			}

			if (unique == UNIQUE) {
				list = (ns_bsd_addr_t **)
				    list_append_unique((void **)list,
				    (void *)addr, (COMP_T)ns_bsd_addr_cmp);
			} else if (unique == LOCAL_UNIQUE) {
				list = (ns_bsd_addr_t **)
				    list_append_unique((void **)list,
				    (void *)addr,
				    (COMP_T)ns_bsd_addr_cmp_local);
			} else {
				list = (ns_bsd_addr_t **)
				    list_append((void **)list, (void *)addr);
			}
		}
	}

	return (list);
}




/*
 * FUNCTION:
 *	ns_bsd_addr_t **ns_bsd_addr_get_list()
 * OUTPUT:
 *	ns_bsd_addr_t **(return) - a list of bsd addresses for "_all" printers
 *				   in the "name service"
 * DESCRIPTION:
 *	This function will use the "_all" entry to find a list of printers and
 *	addresses. The "default" printer is also added to the list.
 *	All redundancy is removed.
 */
ns_bsd_addr_t **
ns_bsd_addr_get_all(int unique)
{
	ns_printer_t *printer;
	ns_bsd_addr_t **list = NULL;
	char **printers;
	char *def = NULL;

	if (((def = (char *)getenv("PRINTER")) == NULL) &&
	    ((def = (char *)getenv("LPDEST")) == NULL))
		def = NS_NAME_DEFAULT;

	list = (ns_bsd_addr_t **)list_append((void **)list,
	    (void *)ns_bsd_addr_get_name(def));

	endprinterentry();
	if ((printer = ns_printer_get_name(NS_NAME_ALL, NULL)) == NULL)
		return (ns_bsd_addr_get_list(unique));

	for (printers = (char **)ns_get_value(NS_KEY_ALL, printer);
	    printers != NULL && *printers != NULL; printers++) {
		ns_bsd_addr_t *addr;

		addr = ns_bsd_addr_get_name(*printers);
		if (addr != NULL)
			addr->pname = *printers;
		if (unique == UNIQUE)
			list =
			    (ns_bsd_addr_t **)list_append_unique((void **)list,
			    (void *)addr, (COMP_T)ns_bsd_addr_cmp);
		else
			list = (ns_bsd_addr_t **)list_append((void **)list,
			    (void *)addr);
	}

	return (list);
}

ns_bsd_addr_t *
ns_bsd_addr_get_default()
{
	char *def = NULL;
	ns_bsd_addr_t *addr;

	if (((def = (char *)getenv("PRINTER")) == NULL) &&
	    ((def = (char *)getenv("LPDEST")) == NULL)) {
		def = NS_NAME_DEFAULT;
		addr = ns_bsd_addr_get_name(def);
		if (addr != NULL) {
			addr->pname = def;
			return (addr);
		}
	}

	return (NULL);
}
