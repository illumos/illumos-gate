/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#ifndef SUNOS_4
#include <libintl.h>
#endif

#include <print/ns.h>
#include <print/network.h>
#include <print/misc.h>
#include <print/list.h>
#include <print/job.h>

#include <cancel_list.h>


/*
 *  printer_compair() compares the printer name in the cancel request and the
 *	printer name passed in.  If they match, 0 is returned.
 */
static int
printer_compair(cancel_req_t *cancel, char *printer)
{
	return (strcmp(cancel->printer, printer));
}

/*
 *  binding_compair() compares the binding in the cancel request and the
 *	binding passed in.  If they match, 0 is returned.
 */
static int
binding_compair(cancel_req_t *cancel, ns_bsd_addr_t *binding)
{
	return (strcmp(cancel->binding->printer, binding->printer) ||
		strcmp(cancel->binding->server, binding->server));
}


/*
 *  cancel_list_element() adds information to the cancel list.  It either adds
 *	information to an existing cancel entry if the printers match, or
 *	adds a new entry to the cancel list.  It returns the new list in either
 *	case.
 */
static cancel_req_t *
cancel_list_element(cancel_req_t ***list, char *printer)
{
	cancel_req_t	*element = NULL;

	if ((element = (cancel_req_t *)list_locate((void **)*list,
	    (COMP_T)printer_compair, (void *)printer)) == NULL) {
		if ((element = calloc(1, sizeof (*element))) != NULL) {
			if ((element->binding = ns_bsd_addr_get_name(printer))
					== NULL) {
				extern int exit_code;

				free(element);
				if (strcmp(printer, NS_NAME_DEFAULT) == 0)
					(void) fprintf(stderr, gettext(
						"No default destination\n"));
				else
					(void) fprintf(stderr, gettext(
						"%s: unknown printer\n"),
						printer);
				exit_code = -1;
				return (NULL);
			}
			element->printer = strdup(printer);
			*list = (cancel_req_t **)list_append((void **)*list,
							(void *)element);
		}
	}

	return (element);
}


/*
 *  cancel_list_element_by_binding() returns an element in the cancel list
 *	passed in that matches the binding passed in.  If none exists, then
 *	one is created, inserted and returned.
 */
static cancel_req_t *
cancel_list_element_by_binding(cancel_req_t ***list, ns_bsd_addr_t *binding)
{
	cancel_req_t	*element = NULL;

	if ((element = (cancel_req_t *)list_locate((void **)*list,
	    (COMP_T)binding_compair, (void *)binding)) == NULL) {
		if ((element = calloc(1, sizeof (*element))) != NULL) {
			element->printer = strdup(binding->printer);
			element->binding = binding;
			*list = (cancel_req_t **)list_append((void **)*list,
							(void *)element);
		}
	}

	return (element);
}


/*
 *  cancel_list_add_item() adds information to the cancel list.  It either adds
 *	information to an existing cancel entry if the printers match, or
 *	adds a new entry to the cancel list.  It returns the new list in either
 *	case.
 */
cancel_req_t **
cancel_list_add_item(cancel_req_t **list, char *printer, char *item)
{
	cancel_req_t	*element = NULL;

	if ((element = cancel_list_element(&list, printer)) != NULL)
		element->list = (char **)list_append((void **)element->list,
							(void *)item);
	return (list);
}


/*
 *  cancel_list_add_list() adds information to the cancel list.  It either adds
 *	information to an existing cancel entry if the printers match, or
 *	adds a new entry to the cancel list.  It returns the new list in either
 *	case.
 */
cancel_req_t **
cancel_list_add_list(cancel_req_t **list, char *printer, char **items)
{
	cancel_req_t	*element = NULL;

	if ((element = cancel_list_element(&list, printer)) != NULL)
		element->list = (char **)list_concatenate(
				(void **)element->list, (void **)items);
	return (list);
}


/*
 *  cancel_list_add_binding_list() adds information to the cancel list.  It
 *	either adds information to an existing cancel entry if the bindings
 *	match, or adds a new entry to the cancel list.  It returns the new
 *	list in either case.
 */
cancel_req_t **
cancel_list_add_binding_list(cancel_req_t **list, ns_bsd_addr_t *binding,
		char **items)
{
	cancel_req_t	*element = NULL;

	if ((element = cancel_list_element_by_binding(&list, binding)) != NULL)
		element->list = (char **)list_concatenate(
				(void **)element->list, (void **)items);
	return (list);
}
