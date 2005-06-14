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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include "cfga_ib.h"


#define	MAX_FORMAT	80	/* for info table */

cfga_ib_ret_t		ib_rcm_offline(const char *, char **, char *,
			    cfga_flags_t);
cfga_ib_ret_t		ib_rcm_online(const char *, char **, char *,
			    cfga_flags_t);
cfga_ib_ret_t		ib_rcm_remove(const char *, char **, char *,
			    cfga_flags_t);
static cfga_ib_ret_t 	ib_rcm_info_table(rcm_info_t *, char **);
static cfga_ib_ret_t 	ib_rcm_init(const char *, cfga_flags_t, char **,
			    uint_t *);


static rcm_handle_t *rcm_handle = NULL;
static mutex_t rcm_handle_lock = DEFAULTMUTEX;


/*
 * Function:
 *	ib_rcm_offline
 * Input:
 *	rsrc		- Resource name (typically an ap_id)
 *	errstring	- Error message filled in case of a failure
 *	rsrc_fixed	- Pointer to fixed path
 *	flags		- flags to RCM
 * Output:
 *	NONE
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	Offline IB resource consumers.
 */
cfga_ib_ret_t
ib_rcm_offline(const char *rsrc, char **errstring, char *rsrc_fixed,
    cfga_flags_t flags)
{
	int		rret;
	uint_t		rflags = 0;
	rcm_info_t	*rinfo = NULL;
	cfga_ib_ret_t	ret = CFGA_IB_OK;

	DPRINTF("ib_rcm_offline:\n");

	if ((ret = ib_rcm_init(rsrc, flags, errstring, &rflags)) !=
	    CFGA_IB_OK) {
		return (ret);
	}

	DPRINTF("ib_rcm_offline: rsrc_fixed: %s\n", rsrc_fixed);

	if ((rret = rcm_request_offline(rcm_handle, rsrc_fixed, rflags, &rinfo))
	    != RCM_SUCCESS) {
		DPRINTF("ib_rcm_offline: rcm_request_offline failed\n");

		if (rinfo) {
			(void) ib_rcm_info_table(rinfo, errstring);
			rcm_free_info(rinfo);
			rinfo = NULL;
		}

		DPRINTF("ib_rcm_offline: table = %s\n", *errstring);

		if (rret == RCM_FAILURE) {
			(void) ib_rcm_online(rsrc, errstring,
			    rsrc_fixed, flags);
		}
		ret = CFGA_IB_RCM_OFFLINE_ERR;
	}

	return (ret);
}


/*
 * Function:
 *	ib_rcm_online
 * Input:
 *	rsrc		- Resource name (typically an ap_id)
 *	errstring	- Error message filled in case of a failure
 *	rsrc_fixed	- Pointer to fixed path
 *	flags		- flags to RCM
 * Output:
 *	NONE
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	Online IB resource consumers that were previously offlined.
 */
cfga_ib_ret_t
ib_rcm_online(const char *rsrc, char **errstring, char *rsrc_fixed,
    cfga_flags_t flags)
{
	rcm_info_t	*rinfo = NULL;
	cfga_ib_ret_t	ret = CFGA_IB_OK;

	DPRINTF("ib_rcm_online:\n");

	if ((ret = ib_rcm_init(rsrc, flags, errstring, NULL)) != CFGA_IB_OK) {
		return (ret);
	}

	if (rcm_notify_online(rcm_handle, rsrc_fixed, 0, &rinfo) !=
	    RCM_SUCCESS && (rinfo != NULL)) {
		DPRINTF("ib_rcm_online: rcm_notify_online failed\n");

		(void) ib_rcm_info_table(rinfo, errstring);
		rcm_free_info(rinfo);
		rinfo = NULL;
		ret = CFGA_IB_RCM_ONLINE_ERR;
	}

	return (ret);
}


/*
 * Function:
 *	ib_rcm_remove
 * Input:
 *	rsrc		- Resource name (typically an ap_id)
 *	errstring	- Error message filled in case of a failure
 *	rsrc_fixed	- Pointer to fixed path
 *	flags		- flags to RCM
 * Output:
 *	NONE
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	Remove IB resource consumers after their kernel removal.
 */
cfga_ib_ret_t
ib_rcm_remove(const char *rsrc, char **errstring, char *rsrc_fixed,
    cfga_flags_t flags)
{
	rcm_info_t	*rinfo = NULL;
	cfga_ib_ret_t	ret = CFGA_IB_OK;

	DPRINTF("ib_rcm_remove:\n");

	if ((ret = ib_rcm_init(rsrc, flags, errstring, NULL)) != CFGA_IB_OK) {
		return (ret);
	}

	if (rcm_notify_remove(rcm_handle, rsrc_fixed, 0, &rinfo) !=
	    RCM_SUCCESS && (rinfo != NULL)) {
		DPRINTF("ib_rcm_remove: rcm_notify_remove failed\n");

		(void) ib_rcm_info_table(rinfo, errstring);
		rcm_free_info(rinfo);
		rinfo = NULL;
		ret = CFGA_IB_RCM_ONLINE_ERR;
	}

	return (ret);
}


/*
 * Function:
 *	ib_rcm_init
 * Input:
 *	rsrc		- Resource name (typically an ap_id)
 *	flags		- flags to RCM
 *	errstring	- Error message filled in case of a failure
 *	rflags		- Flags filled up in case of a failure
 * Output:
 *	NONE
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	Contains common initialization code for entering a ib_rcm_xx() routine.
 */
/* ARGSUSED */
static cfga_ib_ret_t
ib_rcm_init(const char *rsrc, cfga_flags_t flags, char **errstring,
    uint_t *rflags)
{
	DPRINTF("ib_rcm_init:\n");

	/* Validate the rsrc argument */
	if (rsrc == NULL) {
		DPRINTF("ib_rcm_init: rsrc is NULL\n");
		return (CFGA_IB_INTERNAL_ERR);
	}

	/* Translate the cfgadm flags to RCM flags */
	if (rflags && (flags & CFGA_FLAG_FORCE)) {
		*rflags |= RCM_FORCE;
	}

	/* Get a handle for the RCM operations */
	(void) mutex_lock(&rcm_handle_lock);
	if (rcm_handle == NULL) {
		if (rcm_alloc_handle(NULL, RCM_NOPID, NULL, &rcm_handle) !=
		    RCM_SUCCESS) {
			DPRINTF("ib_rcm_init: alloc_handle failed\n");
			(void) mutex_unlock(&rcm_handle_lock);
			return (CFGA_IB_RCM_HANDLE_ERR);
		}
	}
	(void) mutex_unlock(&rcm_handle_lock);
	return (CFGA_IB_OK);
}


/*
 * Function:
 *	ib_rcm_info_table
 * Input:
 *	rinfo		- Resource information
 *	table		- table to be printed
 * Output:
 *	NONE
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	Takes an opaque rcm_info_t pointer and a character pointer,
 *	and appends the rcm_info_t data in the form of a table to the
 *	given character pointer.
 */
static cfga_ib_ret_t
ib_rcm_info_table(rcm_info_t *rinfo, char **table)
{
	int i;
	size_t w;
	size_t width = 0;
	size_t w_rsrc = 0;
	size_t w_info = 0;
	size_t table_size = 0;
	uint_t tuples = 0;
	rcm_info_tuple_t *tuple = NULL;
	char *rsrc;
	char *info;
	char *newtable;
	static char format[MAX_FORMAT];
	const char *infostr;

	DPRINTF("ib_rcm_info_table:\n");

	/* Protect against invalid arguments */
	if (rinfo == NULL || table == NULL) {
		return (CFGA_IB_INTERNAL_ERR);
	}

	/* Set localized table header strings */
	rsrc = dgettext(TEXT_DOMAIN, "Resource");
	info = dgettext(TEXT_DOMAIN, "Information");

	/* A first pass, to size up the RCM information */
	while (tuple = rcm_info_next(rinfo, tuple)) {
		if ((infostr = rcm_info_info(tuple)) != NULL) {
			tuples++;
			if ((w = strlen(rcm_info_rsrc(tuple))) > w_rsrc)
				w_rsrc = w;
			if ((w = strlen(infostr)) > w_info)
				w_info = w;
		}
	}

	/* If nothing was sized up above, stop early */
	if (tuples == 0) {
		DPRINTF("ib_rcm_info_table: no tuples\n");
		return (CFGA_IB_OK);
	}

	/* Adjust column widths for column headings */
	if ((w = strlen(rsrc)) > w_rsrc) {
		w_rsrc = w;
	} else if ((w_rsrc - w) % 2) {
		w_rsrc++;
	}

	if ((w = strlen(info)) > w_info) {
		w_info = w;
	} else if ((w_info - w) % 2) {
		w_info++;
	}

	/*
	 * Compute the total line width of each line,
	 * accounting for intercolumn spacing.
	 */
	width = w_info + w_rsrc + 4;

	/* Allocate space for the table */
	table_size = (2 + tuples) * (width + 1) + 2;
	if (*table == NULL) {
		*table = malloc(table_size);
	} else {
		newtable = realloc(*table, strlen(*table) + table_size);
		if (newtable != NULL)
			*table = newtable;
		else {
			free(*table);
			*table = NULL;
			return (CFGA_IB_ALLOC_FAIL);
		}
	}

	if (*table == NULL) {
		DPRINTF("ib_rcm_info_table: no table\n");
		return (CFGA_IB_ALLOC_FAIL);
	}

	/* Place a table header into the string */

	/* The resource header */
	(void) strlcat(*table, "\n", sizeof (*table));
	w = strlen(rsrc);

	for (i = 0; i < ((w_rsrc - w) / 2); i++) {
		(void) strcat(*table, " ");
	}
	(void) strlcat(*table, rsrc, sizeof (*table));

	for (i = 0; i < ((w_rsrc - w) / 2); i++) {
		(void) strcat(*table, " ");
	}

	/* The information header */
	(void) strcat(*table, "  ");
	w = strlen(info);
	for (i = 0; i < ((w_info - w) / 2); i++) {
		(void) strcat(*table, " ");
	}
	(void) strlcat(*table, info, sizeof (*table));

	for (i = 0; i < ((w_info - w) / 2); i++) {
		(void) strcat(*table, " ");
	}

	(void) strcat(*table, "\n");

	/* Underline the headers */
	for (i = 0; i < w_rsrc; i++) {
		(void) strcat(*table, "-");
	}

	(void) strcat(*table, "  ");
	for (i = 0; i < w_info; i++) {
		(void) strcat(*table, "-");
	}

	(void) strcat(*table, "\n");

	/* Construct the format string */
	(void) snprintf(format, MAX_FORMAT, "%%-%ds  %%-%ds",
	    (int)w_rsrc, (int)w_info);

	/* Add the tuples to the table string */
	tuple = NULL;
	while ((tuple = rcm_info_next(rinfo, tuple)) != NULL) {
		if ((infostr = rcm_info_info(tuple)) != NULL) {
			(void) sprintf(&((*table)[strlen(*table)]),
			    format, rcm_info_rsrc(tuple), infostr);
			(void) strcat(*table, "\n");
		}
	}

	return (CFGA_IB_OK);
}
