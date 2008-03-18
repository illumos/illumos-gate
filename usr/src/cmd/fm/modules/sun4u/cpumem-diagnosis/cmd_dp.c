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

#include <strings.h>
#include <string.h>
#include <errno.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/async.h>
#include <sys/time.h>
#include <cmd.h>
#include <cmd_state.h>
#include <cmd_mem.h>
#include <cmd_dp.h>
#include <cmd_dp_page.h>
#include <libnvpair.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mem.h>
#include <sys/plat_datapath.h>

/*ARGSUSED*/
static nvlist_t *
dp_cpu_fmri(fmd_hdl_t *hdl, uint32_t cpuid, uint64_t serial_id)
{
	nvlist_t	*nvl = NULL;
	int		err;
	char sbuf[21]; /* sizeof (UINT64_MAX) + '\0' */

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		return (NULL);

	err = nvlist_add_string(nvl, FM_FMRI_SCHEME, FM_FMRI_SCHEME_CPU);
	err |= nvlist_add_uint8(nvl, FM_VERSION, FM_CPU_SCHEME_VERSION);
	err |= nvlist_add_uint32(nvl, FM_FMRI_CPU_ID, cpuid);

	/*
	 * Version 1 calls for a string-based serial number
	 */
	(void) snprintf(sbuf, sizeof (sbuf), "%llX", (u_longlong_t)serial_id);
	err |= nvlist_add_string(nvl, FM_FMRI_CPU_SERIAL_ID, sbuf);
	if (err != 0) {
		nvlist_free(nvl);
		return (NULL);
	}
	return (nvl);
}

cmd_dp_t *
cmd_dp_lookup_fault(fmd_hdl_t *hdl, uint32_t cpuid)
{
	cmd_dp_t	*ptr;
	int		i, found = 0;

	/*
	 * Scan the cmd.cmd_datapaths list to see if there is
	 * a fault event present that impacts 'cpuid'
	 */
	for (ptr = cmd_list_next(&cmd.cmd_datapaths); ptr != NULL;
	    ptr = cmd_list_next(ptr)) {
		if (ptr->dp_erpt_type == DP_FAULT) {
			for (i = 0; i < ptr->dp_ncpus; i++) {
				if (ptr->dp_cpuid_list[i] == cpuid) {
					found = 1;
					break;
				}
			}
		}
		if (found)
			break;
	}

	/*
	 * Check if the FMRI for the found cpuid exists in the domain.
	 * If it does not, it implies a DR has been done and this DP_FAULT
	 * is no longer needed.
	 */
	if (ptr != NULL) {
		nvlist_t	*nvl;

		nvl = dp_cpu_fmri(hdl, ptr->dp_cpuid_list[i],
		    ptr->dp_serid_list[i]);

		if (nvl != NULL) {
			if (!fmd_nvl_fmri_present(hdl, nvl)) {
				cmd_dp_destroy(hdl, ptr);
				ptr = NULL;
			}
			nvlist_free(nvl);
		}
	}
	return (ptr);
}

cmd_dp_t *
cmd_dp_lookup_error(cmd_dp_t *dp)
{
	cmd_dp_t	*ptr;

	/*
	 * Scan the cmd.cmd_datapaths list to see if there is
	 * an existing error that matches 'dp'. A match is if
	 * both dp_err and the base cpuid are identical
	 */
	for (ptr = cmd_list_next(&cmd.cmd_datapaths); ptr != NULL;
	    ptr = cmd_list_next(ptr)) {
		if (ptr->dp_erpt_type == DP_ERROR) {
			if ((ptr->dp_err == dp->dp_err) &&
			    (ptr->dp_cpuid_list[0] == dp->dp_cpuid_list[0]))
				return (ptr);
		}
	}
	return (NULL);
}

/*
 * Allocates an nvlist_t, and sets ASRU information according to
 * the cmd_dp_t provided.
 */
/*ARGSUSED*/
nvlist_t *
cmd_dp_setasru(fmd_hdl_t *hdl, cmd_dp_t *dpt)
{
	nvlist_t	*asru, *hcelem[DP_MAX_ASRUS];
	int		i, j, sz, err;
	char		buf[DP_MAX_BUF];

	sz = dpt->dp_ncpus;

	/* put ASRUs in an nvlist */
	for (i = 0; i < sz; i++) {
		(void) snprintf(buf, DP_MAX_BUF, "%d", dpt->dp_cpuid_list[i]);
		if (nvlist_alloc(&hcelem[i], NV_UNIQUE_NAME, 0) != 0)
			return (NULL);

		err = nvlist_add_string(hcelem[i], FM_FMRI_HC_NAME,
		    FM_FMRI_CPU_ID);
		err |= nvlist_add_string(hcelem[i], FM_FMRI_HC_ID, buf);
		if (err != 0) {
			for (j = 0; j < i + 1; j++)
				nvlist_free(hcelem[j]);
			return (NULL);
		}
	}

	/* put it in an HC scheme */
	if (nvlist_alloc(&asru, NV_UNIQUE_NAME, 0) != 0) {
		for (j = 0; j < sz; j++)
			nvlist_free(hcelem[j]);
		return (NULL);
	}
	err = nvlist_add_uint8(asru, FM_VERSION, FM_HC_SCHEME_VERSION);
	err |= nvlist_add_string(asru, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC);
	err |= nvlist_add_string(asru, FM_FMRI_HC_ROOT, "");
	err |= nvlist_add_uint32(asru, FM_FMRI_HC_LIST_SZ, sz);
	err |= nvlist_add_nvlist_array(asru, FM_FMRI_HC_LIST, &hcelem[0],
	    dpt->dp_ncpus);
	if (err != 0) {
		for (j = 0; j < sz; j++)
			nvlist_free(hcelem[j]);
		nvlist_free(asru);
		return (NULL);
	}

	/* free up memory */
	for (j = 0; j < sz; j++)
		nvlist_free(hcelem[j]);

	/* return the ASRU */
	return (asru);
}

void
dp_buf_write(fmd_hdl_t *hdl, cmd_dp_t *dp)
{
	size_t sz;

	if ((sz = fmd_buf_size(hdl, NULL, dp->dp_bufname)) != 0 &&
	    sz != sizeof (cmd_dp_pers_t))
		fmd_buf_destroy(hdl, NULL, dp->dp_bufname);

	fmd_buf_write(hdl, NULL, dp->dp_bufname, &dp->dp_pers,
	    sizeof (cmd_dp_pers_t));
}

static cmd_dp_t *
dp_wrapv0(fmd_hdl_t *hdl, cmd_dp_pers_t *pers, size_t psz)
{
	cmd_dp_t *dp;

	if (psz != sizeof (cmd_dp_pers_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 1 state (%u bytes).\n", sizeof (cmd_dp_pers_t));
	}

	dp = fmd_hdl_zalloc(hdl, sizeof (cmd_dp_t), FMD_SLEEP);
	bcopy(pers, dp, sizeof (cmd_dp_pers_t));
	fmd_hdl_free(hdl, pers, psz);
	return (dp);
}

void *
cmd_dp_restore(fmd_hdl_t *hdl, fmd_case_t *cp, cmd_case_ptr_t *ptr)
{
	cmd_dp_t *dp;

	for (dp = cmd_list_next(&cmd.cmd_datapaths); dp != NULL;
	    dp = cmd_list_next(dp)) {
		if (dp->dp_case == cp)
			break;
	}

	if (dp == NULL) {
		size_t dpsz;

		fmd_hdl_debug(hdl, "restoring dp from %s\n", ptr->ptr_name);

		if ((dpsz = fmd_buf_size(hdl, NULL, ptr->ptr_name)) == 0) {
			if (fmd_case_solved(hdl, cp) ||
			    fmd_case_closed(hdl, cp)) {
				fmd_hdl_debug(hdl, "dp %s from case %s not "
				    "found. Case is already solved or closed\n",
				    ptr->ptr_name, fmd_case_uuid(hdl, cp));
				return (NULL);
			} else {
				fmd_hdl_abort(hdl, "dp referenced by case %s "
				    "does not exist in saved state\n",
				    fmd_case_uuid(hdl, cp));
			}
		} else if (dpsz > CMD_DP_MAXSIZE ||
		    dpsz < CMD_DP_MINSIZE) {
			fmd_hdl_abort(hdl, "dp buffer referenced by "
			    "case %s is out of bounds (is %u bytes, "
			    "max %u, min %u)\n", fmd_case_uuid(hdl, cp),
			    dpsz, CMD_DP_MAXSIZE, CMD_DP_MINSIZE);
		}

		if ((dp = cmd_buf_read(hdl, NULL, ptr->ptr_name, dpsz)) == NULL)
			fmd_hdl_abort(hdl, "failed to read dp buf %s",
			    ptr->ptr_name);

		switch (dp->dp_version) {
		case CMD_DP_VERSION_0:
			dp = dp_wrapv0(hdl, (cmd_dp_pers_t *)dp, dpsz);
			break;
		default:
			fmd_hdl_abort(hdl, "unknown version (found %d) "
			    "for dp state referenced by case %s.\n",
			    dp->dp_version, fmd_case_uuid(hdl, cp));
			break;
		}

		dp->dp_case = cp;

		if (dp->dp_erpt_type == DP_ERROR) {
			fmd_event_t *ep = fmd_case_getprincipal(hdl, cp);

			++cmd.cmd_dp_flag;

			dp->dp_id = fmd_timer_install(hdl,
			    (void *)CMD_TIMERTYPE_DP, ep,
			    (hrtime_t)NANOSEC * (dp->dp_t_value + 120));
		}

		cmd_list_append(&cmd.cmd_datapaths, dp);
	}

	return (dp);
}

void
cmd_dp_close(fmd_hdl_t *hdl, void *arg)
{
	cmd_dp_destroy(hdl, arg);
}

void
cmd_dp_timeout(fmd_hdl_t *hdl, id_t id)
{
	cmd_dp_t		*dp;

	/* close case associated with the timer */
	for (dp = cmd_list_next(&cmd.cmd_datapaths); dp != NULL;
	    dp = cmd_list_next(dp)) {
		if (dp->dp_id == id) {
			cmd_dp_destroy(hdl, dp);
			break;
		}
	}

	fmd_hdl_debug(hdl, "cmd_dp_timeout() complete\n");
}

void
cmd_dp_validate(fmd_hdl_t *hdl)
{
	cmd_dp_t *dp, *next;
	nvlist_t *nvl;
	int i;

	for (dp = cmd_list_next(&cmd.cmd_datapaths); dp != NULL; dp = next) {
		next = cmd_list_next(dp);

		for (i = 0; i < dp->dp_ncpus; i++) {
			nvl = dp_cpu_fmri(hdl, dp->dp_cpuid_list[i],
			    dp->dp_serid_list[i]);

			if (nvl == NULL)
				fmd_hdl_abort(hdl, "could not make CPU fmri");

			if (!fmd_nvl_fmri_present(hdl, nvl))
				cmd_dp_destroy(hdl, dp);

			nvlist_free(nvl);
		}
	}
}

static void
cmd_dp_free(fmd_hdl_t *hdl, cmd_dp_t *dp, int destroy)
{
	if (dp->dp_case != NULL)
		cmd_case_fini(hdl, dp->dp_case, destroy);

	if (destroy && dp->dp_erpt_type == DP_ERROR) {
		--cmd.cmd_dp_flag;
		/*
		 * If there are no active datapath events, replay any
		 * pages that were deferred.
		 */
		if (cmd.cmd_dp_flag == 0)
			cmd_dp_page_replay(hdl);
	}

	if (destroy)
		fmd_buf_destroy(hdl, NULL, dp->dp_bufname);

	cmd_list_delete(&cmd.cmd_datapaths, dp);
	fmd_hdl_free(hdl, dp, sizeof (cmd_dp_t));
}

void
cmd_dp_destroy(fmd_hdl_t *hdl, cmd_dp_t *dp)
{
	cmd_dp_free(hdl, dp, FMD_B_TRUE);
}

/*ARGSUSED*/
int
cmd_dp_error(fmd_hdl_t *hdl)
{
	if (cmd.cmd_dp_flag)
		return (1);
	else
		return (0);
}

int
cmd_dp_get_mcid(uint64_t addr, int *mcid)
{
	int fd, rc;
	mem_info_t data;

	if ((fd = open("/dev/mem", O_RDONLY)) < 0)
		return (-1);

	data.m_addr = addr;
	data.m_synd = 0;
	if ((rc = ioctl(fd, MEM_INFO, &data)) < 0) {
		(void) close(fd);
		return (rc);
	}

	(void) close(fd);
	*mcid = data.m_mcid;

	return (0);
}

/*ARGSUSED*/
int
cmd_dp_fault(fmd_hdl_t *hdl, uint64_t addr)
{
	int mcid;

	if (cmd_dp_get_mcid(addr, &mcid) < 0)
		fmd_hdl_abort(hdl, "cmd_dp_get_mcid failed");

	if (cmd_dp_lookup_fault(hdl, mcid) != NULL)
		return (1);
	else
		return (0);
}

void
cmd_dp_fini(fmd_hdl_t *hdl)
{
	cmd_dp_t *dp;
	cmd_dp_defer_t *dpage;

	while ((dp = cmd_list_next(&cmd.cmd_datapaths)) != NULL)
		cmd_dp_free(hdl, dp, FMD_B_FALSE);

	while ((dpage = cmd_list_next(&cmd.cmd_deferred_pages)) != NULL) {
		cmd_list_delete(&cmd.cmd_deferred_pages, dpage);
		fmd_hdl_free(hdl, dpage, sizeof (cmd_dp_defer_t));
	}
}
