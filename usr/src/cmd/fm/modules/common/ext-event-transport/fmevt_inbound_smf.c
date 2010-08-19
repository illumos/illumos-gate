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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <strings.h>
#include <libscf.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <fm/libfmevent.h>

#include "fmevt.h"

/*
 * Post-processing according to the FMEV_RULESET_SMF ruleset.
 *
 * Raw event we expect:
 *
 * ==========================================================================
 * Class: "state-transition"
 * Subclasses: The new state, one of SCF_STATE_STRING_* from libscf.h
 * Attr:
 * Name		DATA_TYPE_*	Description
 * ------------ --------------- ---------------------------------------------
 * fmri		STRING		svc:/... (svc scheme shorthand version)
 * transition	INT32		(old_state << 16) | new_state
 * reason-version UINT32	reason-short namespace version
 * reason-short	STRING		Short/keyword reason for transition
 * reason-long	STRING		Long-winded reason for the transition
 * ==========================================================================
 *
 * Protocol event components we return:
 *
 * ==========================================================================
 * Class: ireport.os.smf.state-transition.<new-state>
 * Attr:
 * Name		DATA_TYPE_*	Description
 * ------------ --------------- ----------------------------------------
 * svc		NVLIST		"svc" scheme FMRI of affected service instance
 * svc-string	STRING		SMF FMRI in short string form svc:/foo/bar
 * from-state	STRING		Previous state; SCF_STATE_STRING_*
 * to-state	STRING		New state; SCF_STATE_STRING_*
 * reason-version UINT32	reason-short namespace version
 * reason-short	STRING		Short/keyword reason for transition
 * reason-long	STRING		Long-winded reason for the transition
 * ==========================================================================
 */

/*
 * svc.startd generates events using the FMRI shorthand (svc:/foo/bar)
 * instead of the standard form (svc:///foo/bar).  This function converts to
 * the standard representation.  The caller must free the allocated string.
 */
static char *
shortfmri_to_fmristr(fmd_hdl_t *hdl, const char *shortfmristr)
{
	size_t len;
	char *fmristr;

	if (strncmp(shortfmristr, "svc:/", 5) != 0)
		return (NULL);

	len = strlen(shortfmristr) + 3;
	fmristr = fmd_hdl_alloc(hdl, len, FMD_SLEEP);
	(void) snprintf(fmristr, len, "svc:///%s", shortfmristr + 5);

	return (fmristr);
}

/*
 * Convert a shorthand svc FMRI into a full svc FMRI nvlist
 */
static nvlist_t *
shortfmri_to_fmri(fmd_hdl_t *hdl, const char *shortfmristr)
{
	nvlist_t *ret, *fmri;
	topo_hdl_t *thp;
	char *fmristr;
	int err;

	if ((fmristr = shortfmri_to_fmristr(hdl, shortfmristr)) == NULL)
		return (NULL);

	thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION);

	if (topo_fmri_str2nvl(thp, fmristr, &fmri, &err) != 0) {
		fmd_hdl_error(hdl, "failed to convert '%s' to nvlist\n",
		    fmristr);
		fmd_hdl_strfree(hdl, fmristr);
		fmd_hdl_topo_rele(hdl, thp);
		return (NULL);
	}

	fmd_hdl_strfree(hdl, fmristr);

	if ((ret = fmd_nvl_dup(hdl, fmri, FMD_SLEEP)) == NULL) {
		fmd_hdl_error(hdl, "failed to dup fmri\n");
		nvlist_free(fmri);
		fmd_hdl_topo_rele(hdl, thp);
		return (NULL);
	}

	nvlist_free(fmri);
	fmd_hdl_topo_rele(hdl, thp);

	return (ret);
}

/*ARGSUSED*/
uint_t
fmevt_pp_smf(char *classes[FMEVT_FANOUT_MAX],
    nvlist_t *attr[FMEVT_FANOUT_MAX], const char *ruleset,
    const nvlist_t *detector, nvlist_t *rawattr,
    const struct fmevt_ppargs *eap)
{
	int32_t transition, from, to;
	const char *fromstr, *tostr;
	char *svcname, *rsn, *rsnl;
	nvlist_t *myattr;
	nvlist_t *fmri;
	uint32_t ver;

	if (!fmd_prop_get_int32(fmevt_hdl, "inbound_postprocess_smf"))
		return (0);

	if (rawattr == NULL ||
	    strcmp(eap->pp_rawclass, "state-transition") != 0 ||
	    nvlist_lookup_string(rawattr, "fmri", &svcname) != 0 ||
	    nvlist_lookup_int32(rawattr, "transition", &transition) != 0 ||
	    nvlist_lookup_string(rawattr, "reason-short", &rsn) != 0 ||
	    nvlist_lookup_string(rawattr, "reason-long", &rsnl) != 0 ||
	    nvlist_lookup_uint32(rawattr, "reason-version", &ver) != 0)
		return (0);

	from = transition >> 16;
	to = transition & 0xffff;

	fromstr = smf_state_to_string(from);
	tostr = smf_state_to_string(to);

	if (fromstr == NULL || tostr == NULL)
		return (0);

	if (strcmp(eap->pp_rawsubclass, tostr) != 0)
		return (0);

	if ((fmri = shortfmri_to_fmri(fmevt_hdl, svcname)) == NULL)
		return (0);

	if (snprintf(classes[0], FMEVT_MAX_CLASS, "%s.%s.%s.%s",
	    FM_IREPORT_CLASS, "os.smf", eap->pp_rawclass,
	    eap->pp_rawsubclass) >= FMEVT_MAX_CLASS - 1)
		return (0);

	if ((myattr = fmd_nvl_alloc(fmevt_hdl, FMD_SLEEP)) == NULL)
		return (0);

	if (nvlist_add_nvlist(myattr, "svc", fmri) != 0 ||
	    nvlist_add_string(myattr, "svc-string", svcname) != 0 ||
	    nvlist_add_string(myattr, "from-state", fromstr) != 0 ||
	    nvlist_add_string(myattr, "to-state", tostr) != 0 ||
	    nvlist_add_uint32(myattr, "reason-version", ver) != 0 ||
	    nvlist_add_string(myattr, "reason-short", rsn) != 0 ||
	    nvlist_add_string(myattr, "reason-long", rsnl) != 0) {
		nvlist_free(fmri);
		nvlist_free(myattr);
		return (0);
	}

	attr[0] = myattr;
	nvlist_free(fmri);

	return (1);
}
