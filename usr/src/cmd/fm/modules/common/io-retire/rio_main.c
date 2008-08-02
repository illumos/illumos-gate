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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>
#include <strings.h>
#include <libdevinfo.h>
#include <sys/modctl.h>

static int	global_disable;

struct except_list {
	char			*el_fault;
	struct except_list	*el_next;
};

static struct except_list *except_list;

static void
parse_exception_string(fmd_hdl_t *hdl, char *estr)
{
	char	*p;
	char	*next;
	size_t	len;
	struct except_list *elem;

	len = strlen(estr);

	p = estr;
	for (;;) {
		/* Remove leading ':' */
		while (*p == ':')
			p++;
		if (*p == '\0')
			break;

		next = strchr(p, ':');

		if (next)
			*next = '\0';

		elem = fmd_hdl_alloc(hdl,
		    sizeof (struct except_list), FMD_SLEEP);
		elem->el_fault = fmd_hdl_strdup(hdl, p, FMD_SLEEP);
		elem->el_next = except_list;
		except_list = elem;

		if (next) {
			*next = ':';
			p = next + 1;
		} else {
			break;
		}
	}

	if (len != strlen(estr)) {
		fmd_hdl_abort(hdl, "Error parsing exception list: %s\n", estr);
	}
}

/*
 * Returns
 *	1  if fault on exception list
 *	0  otherwise
 */
static int
fault_exception(fmd_hdl_t *hdl, nvlist_t *fault)
{
	struct except_list *elem;

	for (elem = except_list; elem; elem = elem->el_next) {
		if (fmd_nvl_class_match(hdl, fault, elem->el_fault)) {
			fmd_hdl_debug(hdl, "rio_recv: Skipping fault "
			    "on exception list (%s)\n", elem->el_fault);
			return (1);
		}
	}

	return (0);
}

static void
free_exception_list(fmd_hdl_t *hdl)
{
	struct except_list *elem;

	while (except_list) {
		elem = except_list;
		except_list = elem->el_next;
		fmd_hdl_strfree(hdl, elem->el_fault);
		fmd_hdl_free(hdl, elem, sizeof (*elem));
	}
}


/*ARGSUSED*/
static void
rio_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	nvlist_t	**faults = NULL;
	nvlist_t	*asru;
	uint_t		nfaults = 0;
	int		f;
	char		*path;
	char		*uuid;
	char		*scheme;
	di_retire_t	drt = {0};
	int		retire;
	int		rval = 0;
	int		error;
	char		*snglfault = FM_FAULT_CLASS"."FM_ERROR_IO".";
	boolean_t	rtr;


	/*
	 * If disabled, we don't do retire. We still do unretires though
	 */
	if (global_disable && strcmp(class, FM_LIST_SUSPECT_CLASS) == 0) {
		fmd_hdl_debug(hdl, "rio_recv: retire disabled\n");
		return;
	}

	drt.rt_abort = (void (*)(void *, const char *, ...))fmd_hdl_abort;
	drt.rt_debug = (void (*)(void *, const char *, ...))fmd_hdl_debug;
	drt.rt_hdl = hdl;

	if (strcmp(class, FM_LIST_SUSPECT_CLASS) == 0) {
		retire = 1;
	} else if (strcmp(class, FM_LIST_REPAIRED_CLASS) == 0) {
		retire = 0;
	} else if (strcmp(class, FM_LIST_UPDATED_CLASS) == 0) {
		retire = 0;
	} else if (strncmp(class, snglfault, strlen(snglfault)) == 0) {
		retire = 1;
		faults = &nvl;
		nfaults = 1;
	} else {
		fmd_hdl_debug(hdl, "rio_recv: not list.* class: %s\n", class);
		return;
	}

	if (nfaults == 0 && nvlist_lookup_nvlist_array(nvl,
	    FM_SUSPECT_FAULT_LIST, &faults, &nfaults) != 0) {
		fmd_hdl_debug(hdl, "rio_recv: no fault list");
		return;
	}

	for (f = 0; f < nfaults; f++) {
		if (nvlist_lookup_boolean_value(faults[f], FM_SUSPECT_RETIRE,
		    &rtr) == 0 && !rtr) {
			fmd_hdl_debug(hdl, "rio_recv: retire suppressed");
			continue;
		}

		if (nvlist_lookup_nvlist(faults[f], FM_FAULT_ASRU,
		    &asru) != 0) {
			fmd_hdl_debug(hdl, "rio_recv: no asru in fault");
			continue;
		}

		scheme = NULL;
		if (nvlist_lookup_string(asru, FM_FMRI_SCHEME, &scheme) != 0 ||
		    strcmp(scheme, FM_FMRI_SCHEME_DEV) != 0) {
			fmd_hdl_debug(hdl, "rio_recv: not \"dev\" scheme: %s",
			    scheme ? scheme : "<NULL>");
			continue;
		}

		if (fault_exception(hdl, faults[f]))
			continue;

		if (nvlist_lookup_string(asru, FM_FMRI_DEV_PATH,
		    &path) != 0 || path[0] == '\0') {
			fmd_hdl_debug(hdl, "rio_recv: no dev path in asru");
			continue;
		}

		if (retire) {
			if (fmd_nvl_fmri_has_fault(hdl, asru,
			    FMD_HAS_FAULT_ASRU, NULL) == 1) {
				error = di_retire_device(path, &drt, 0);
				if (error != 0) {
					fmd_hdl_debug(hdl, "rio_recv:"
					    " di_retire_device failed:"
					    " error: %d %s", error, path);
					rval = -1;
				}
			}
		} else {
			if (fmd_nvl_fmri_has_fault(hdl, asru,
			    FMD_HAS_FAULT_ASRU, NULL) == 0) {
				error = di_unretire_device(path, &drt);
				if (error != 0) {
					fmd_hdl_debug(hdl, "rio_recv:"
					    " di_unretire_device failed:"
					    " error: %d %s", error, path);
					rval = -1;
				}
			}
		}
	}

	/*
	 * The fmd framework takes care of moving a case to the repaired
	 * state. To move the case to the closed state however, we (the
	 * retire agent) need to call fmd_case_uuclose()
	 */
	if (strcmp(class, FM_LIST_SUSPECT_CLASS) == 0 && rval == 0) {
		if (nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid) == 0 &&
		    !fmd_case_uuclosed(hdl, uuid)) {
			fmd_case_uuclose(hdl, uuid);
		}
	}

	/*
	 * Similarly to move the case to the resolved state, we (the
	 * retire agent) need to call fmd_case_uuresolved()
	 */
	if (strcmp(class, FM_LIST_REPAIRED_CLASS) == 0 && rval == 0 &&
	    nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid) == 0)
		fmd_case_uuresolved(hdl, uuid);
}

static const fmd_hdl_ops_t fmd_ops = {
	rio_recv,	/* fmdo_recv */
	NULL,		/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
};

static const fmd_prop_t rio_props[] = {
	{ "global-disable", FMD_TYPE_BOOL, "false" },
	{ "fault-exceptions", FMD_TYPE_STRING, NULL },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"I/O Retire Agent", "2.0", &fmd_ops, rio_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	char	*estr;
	char	*estrdup;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0) {
		fmd_hdl_debug(hdl, "failed to register handle\n");
		return;
	}

	global_disable = fmd_prop_get_int32(hdl, "global-disable");

	estrdup = NULL;
	if (estr = fmd_prop_get_string(hdl, "fault-exceptions")) {
		estrdup = fmd_hdl_strdup(hdl, estr, FMD_SLEEP);
		fmd_prop_free_string(hdl, estr);
		parse_exception_string(hdl, estrdup);
		fmd_hdl_strfree(hdl, estrdup);
	}
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	free_exception_list(hdl);
}
