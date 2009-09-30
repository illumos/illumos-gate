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

#include "cfga_scsi.h"

#define	MAX_FORMAT	80

static scfga_ret_t scsi_rcm_info_table(rcm_info_t *, char **);
static scfga_ret_t scsi_rcm_init(uint_t, char **, rcm_handle_t **);

/*
 * scsi_rcm_offline()
 *
 *	Offline SCSI resource consumers.
 */
scfga_ret_t
scsi_rcm_offline(char **rsrclist, char **errstring, cfga_flags_t flags)
{
	int rret;
	uint_t rflags = 0;
	rcm_info_t *rinfo = NULL;
	scfga_ret_t ret = SCFGA_OK;
	rcm_handle_t *rcm_handle;

	if (rsrclist == NULL)
		return (ret);

	if ((ret = scsi_rcm_init(0, errstring, &rcm_handle))
	    != SCFGA_OK)
		return (ret);

	if (flags & CFGA_FLAG_FORCE)
		rflags = RCM_FORCE;

	if ((rret = rcm_request_offline_list(rcm_handle, rsrclist, rflags,
	    &rinfo)) != RCM_SUCCESS) {
		if ((flags & FLAG_CLIENT_DEV) == FLAG_CLIENT_DEV) {
			cfga_err(errstring, 0, ERRARG_RCM_CLIENT_OFFLINE, 0);
		} else {
			cfga_err(errstring, 0, ERRARG_RCM_OFFLINE, 0);
		}
		if (rinfo) {
			(void) scsi_rcm_info_table(rinfo, errstring);
			rcm_free_info(rinfo);
		}
		if (rret == RCM_FAILURE)
			(void) rcm_notify_online_list(rcm_handle, rsrclist,
			    rflags & ~RCM_FORCE, NULL);
		ret = SCFGA_BUSY;
	}
	(void) rcm_free_handle(rcm_handle);
	return (ret);
}

/*
 * scsi_rcm_online()
 *
 *	Online SCSI resource consumers that were previously offlined.
 */
/*ARGSUSED2*/
scfga_ret_t
scsi_rcm_online(char **rsrclist, char **errstring, cfga_flags_t flags)
{
	rcm_info_t *rinfo = NULL;
	scfga_ret_t ret = SCFGA_OK;
	rcm_handle_t *rcm_handle;

	if (rsrclist == NULL)
		return (ret);

	if ((ret = scsi_rcm_init(0, errstring, &rcm_handle))
	    != SCFGA_OK)
		return (ret);

	if (rcm_notify_online_list(rcm_handle, rsrclist, 0, &rinfo)
	    != RCM_SUCCESS) {
		cfga_err(errstring, 0, ERRARG_RCM_ONLINE, 0);
		if (rinfo != NULL) {
			(void) scsi_rcm_info_table(rinfo, errstring);
			rcm_free_info(rinfo);
		}
		ret = SCFGA_BUSY;
	}
	(void) rcm_free_handle(rcm_handle);
	return (ret);
}

/*
 * scsi_rcm_remove()
 *
 *	Remove SCSI resource consumers after their kernel removal.
 */
/*ARGSUSED2*/
scfga_ret_t
scsi_rcm_remove(char **rsrclist, char **errstring, cfga_flags_t flags)
{
	rcm_info_t *rinfo = NULL;
	scfga_ret_t ret = SCFGA_OK;
	rcm_handle_t *rcm_handle;

	if (rsrclist == NULL)
		return (ret);

	if ((ret = scsi_rcm_init(0, errstring, &rcm_handle))
	    != SCFGA_OK)
		return (ret);

	if (rcm_notify_remove_list(rcm_handle, rsrclist, 0, &rinfo)
	    != RCM_SUCCESS) {
		cfga_err(errstring, 0, ERRARG_RCM_REMOVE, 0);
		if (rinfo) {
			(void) scsi_rcm_info_table(rinfo, errstring);
			rcm_free_info(rinfo);
		}
		ret = SCFGA_BUSY;
	}

	(void) rcm_free_handle(rcm_handle);
	return (ret);
}

/*
 * scsi_rcm_suspend()
 *
 *	Suspend SCSI resource consumers before a bus quiesce.
 */
scfga_ret_t
scsi_rcm_suspend(char **rsrclist, char **errstring, cfga_flags_t flags,
    int pflag)
{
	int rret;
	uint_t rflags = 0;
	rcm_info_t *rinfo = NULL;
	scfga_ret_t ret = SCFGA_OK;
	rcm_handle_t *rcm_handle;
	timespec_t zerotime = { 0, 0 };

	if (rsrclist == NULL)
		return (ret);

	pflag = pflag ? RCM_NOPID : 0;
	if ((ret = scsi_rcm_init(pflag, errstring, &rcm_handle))
	    != SCFGA_OK)
		return (ret);

	if (flags & CFGA_FLAG_FORCE)
		rflags = RCM_FORCE;

	/*
	 * attempt a suspension on a list of resources
	 */
	if ((rret = rcm_request_suspend_list(rcm_handle, rsrclist, rflags,
	    &zerotime, &rinfo)) != RCM_SUCCESS) {
		cfga_err(errstring, 0, ERRARG_RCM_SUSPEND, 0);
		if (rinfo) {
			(void) scsi_rcm_info_table(rinfo, errstring);
			rcm_free_info(rinfo);
		}
		if (rret == RCM_FAILURE)
			(void) rcm_notify_resume_list(rcm_handle, rsrclist,
			    (rflags & (~RCM_FORCE)), NULL);
		ret = SCFGA_BUSY;
	}
	(void) rcm_free_handle(rcm_handle);
	return (ret);
}

/*
 * scsi_rcm_resume()
 *
 *	Resume SCSI resource consumers after a bus has been unquiesced.
 */
/*ARGSUSED2*/
scfga_ret_t
scsi_rcm_resume(char **rsrclist, char **errstring, cfga_flags_t flags,
    int pflag)
{
	rcm_info_t *rinfo = NULL;
	scfga_ret_t ret = SCFGA_OK;
	rcm_handle_t *rcm_handle;

	if (rsrclist == NULL)
		return (ret);

	pflag = pflag ? RCM_NOPID : 0;
	if ((ret = scsi_rcm_init(pflag, errstring, &rcm_handle))
	    != SCFGA_OK)
		return (ret);

	/*
	 * resume the resource list.
	 */
	if (rcm_notify_resume_list(rcm_handle, rsrclist, 0, &rinfo)
	    != RCM_SUCCESS) {
		cfga_err(errstring, 0, ERRARG_RCM_RESUME, 0);
		if (rinfo != NULL) {
			(void) scsi_rcm_info_table(rinfo, errstring);
			rcm_free_info(rinfo);
		}
		ret = SCFGA_BUSY;
	}
	(void) rcm_free_handle(rcm_handle);
	return (ret);
}

/*
 * scsi_rcm_init()
 *
 *	Contains common initialization code for entering a scsi_rcm_xx()
 * routine.
 */
static scfga_ret_t
scsi_rcm_init(uint_t rcm_flag, char **errstring, rcm_handle_t **hdlp)
{
	/* Get a handle for the RCM operations */
	if (rcm_alloc_handle(NULL, rcm_flag, NULL, hdlp) != RCM_SUCCESS) {
		cfga_err(errstring, 0, ERR_RCM_HANDLE, 0);
		return (SCFGA_LIB_ERR);
	}

	return (SCFGA_OK);
}

/*
 * scsi_rcm_info_table
 *
 *	Takes an opaque rcm_info_t pointer and a character pointer, and appends
 * the rcm_info_t data in the form of a table to the given character pointer.
 */
static scfga_ret_t
scsi_rcm_info_table(rcm_info_t *rinfo, char **table)
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

	/* Protect against invalid arguments */
	if (rinfo == NULL || table == NULL)
		return (SCFGA_ERR);

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
	if (tuples == 0)
		return (SCFGA_OK);

	/* Adjust column widths for column headings */
	if ((w = strlen(rsrc)) > w_rsrc)
		w_rsrc = w;
	else if ((w_rsrc - w) % 2)
		w_rsrc++;
	if ((w = strlen(info)) > w_info)
		w_info = w;
	else if ((w_info - w) % 2)
		w_info++;

	/*
	 * Compute the total line width of each line,
	 * accounting for intercolumn spacing.
	 */
	width = w_info + w_rsrc + 4;

	/* Allocate space for the table */
	table_size = (2 + tuples) * (width + 1) + 2;
	if (*table == NULL) {
		/* zero fill for the strcat() call below */
		*table = calloc(table_size, sizeof (char));
		if (*table == NULL)
			return (SCFGA_ERR);
	} else {
		newtable = realloc(*table, strlen(*table) + table_size);
		if (newtable == NULL)
			return (SCFGA_ERR);
		else
			*table = newtable;
	}

	/* Place a table header into the string */

	/* The resource header */
	(void) strcat(*table, "\n");
	w = strlen(rsrc);
	for (i = 0; i < ((w_rsrc - w) / 2); i++)
		(void) strcat(*table, " ");
	(void) strcat(*table, rsrc);
	for (i = 0; i < ((w_rsrc - w) / 2); i++)
		(void) strcat(*table, " ");

	/* The information header */
	(void) strcat(*table, "  ");
	w = strlen(info);
	for (i = 0; i < ((w_info - w) / 2); i++)
		(void) strcat(*table, " ");
	(void) strcat(*table, info);
	for (i = 0; i < ((w_info - w) / 2); i++)
		(void) strcat(*table, " ");

	/* Underline the headers */
	(void) strcat(*table, "\n");
	for (i = 0; i < w_rsrc; i++)
		(void) strcat(*table, "-");
	(void) strcat(*table, "  ");
	for (i = 0; i < w_info; i++)
		(void) strcat(*table, "-");

	/* Construct the format string */
	(void) snprintf(format, MAX_FORMAT, "%%-%ds  %%-%ds",
	    (int)w_rsrc, (int)w_info);

	/* Add the tuples to the table string */
	tuple = NULL;
	while ((tuple = rcm_info_next(rinfo, tuple)) != NULL) {
		if ((infostr = rcm_info_info(tuple)) != NULL) {
			(void) strcat(*table, "\n");
			(void) sprintf(&((*table)[strlen(*table)]),
			    format, rcm_info_rsrc(tuple),
			    infostr);
		}
	}

	return (SCFGA_OK);
}
