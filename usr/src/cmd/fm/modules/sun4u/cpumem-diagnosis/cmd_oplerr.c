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

/*
 * OPL platform specific functions for
 * CPU/Memory error diagnosis engine.
 */
#include <cmd.h>
#include <cmd_dimm.h>
#include <cmd_bank.h>
#include <cmd_page.h>
#include <cmd_opl.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include <sys/fm/protocol.h>
#include <sys/fm/io/opl_mc_fm.h>
#include <sys/async.h>
#include <sys/opl_olympus_regs.h>
#include <sys/fm/cpu/SPARC64-VI.h>
#include <sys/int_const.h>
#include <sys/mutex.h>
#include <sys/dditypes.h>
#include <opl/sys/mc-opl.h>

/*
 * The following is the common function for handling
 * memory UE with EID=MEM.
 * The error could be detected by either CPU/IO.
 */
cmd_evdisp_t
opl_ue_mem(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    int hdlr_type)
{
	nvlist_t *rsrc = NULL, *asru = NULL, *fru = NULL;
	uint64_t ubc_ue_log_reg, pa;
	cmd_page_t *page;

	if (nvlist_lookup_nvlist(nvl,
	    FM_EREPORT_PAYLOAD_NAME_RESOURCE, &rsrc) != 0)
		return (CMD_EVD_BAD);

	switch (hdlr_type) {
	case CMD_OPL_HDLR_CPU:

		if (nvlist_lookup_uint64(nvl,
		    FM_EREPORT_PAYLOAD_NAME_SFAR, &pa) != 0)
			return (CMD_EVD_BAD);

		fmd_hdl_debug(hdl, "cmd_ue_mem: pa=%llx\n",
		    (u_longlong_t)pa);
		break;

	case CMD_OPL_HDLR_IO:

		if (nvlist_lookup_uint64(nvl, OBERON_UBC_MUE,
		    &ubc_ue_log_reg) != 0)
			return (CMD_EVD_BAD);

		pa = (ubc_ue_log_reg & UBC_UE_ADR_MASK);

		fmd_hdl_debug(hdl, "cmd_ue_mem: ue_log_reg=%llx\n",
		    (u_longlong_t)ubc_ue_log_reg);
		fmd_hdl_debug(hdl, "cmd_ue_mem: pa=%llx\n",
		    (u_longlong_t)pa);
		break;

	default:

		return (CMD_EVD_BAD);
	}

	if ((page = cmd_page_lookup(pa)) != NULL &&
	    page->page_case.cc_cp != NULL &&
	    fmd_case_solved(hdl, page->page_case.cc_cp))
		return (CMD_EVD_REDUND);

	if (nvlist_dup(rsrc, &asru, 0) != 0) {
		fmd_hdl_debug(hdl, "opl_ue_mem nvlist dup failed\n");
		return (CMD_EVD_BAD);
	}

	if (fmd_nvl_fmri_expand(hdl, asru) < 0) {
		nvlist_free(asru);
		CMD_STAT_BUMP(bad_mem_asru);
		return (CMD_EVD_BAD);
	}

	if ((fru = opl_mem_fru_create(hdl, asru)) == NULL) {
		nvlist_free(asru);
		return (CMD_EVD_BAD);
	}

	cmd_page_fault(hdl, asru, fru, ep, pa);
	nvlist_free(asru);
	nvlist_free(fru);
	return (CMD_EVD_OK);
}

/*
 * The following is the main function to handle generating
 * the sibling cpu suspect list for the CPU detected UE
 * error cases.  This is to handle the
 * multiple strand/core architecture on the OPL platform.
 */
cmd_evdisp_t
cmd_opl_ue_cpu(fmd_hdl_t *hdl, fmd_event_t *ep,
    const char *class, const char *fltname,
    cmd_ptrsubtype_t ptr, cmd_cpu_t *cpu,
    cmd_case_t *cc, uint8_t cpumask)
{
	const char *uuid;
	cmd_cpu_t *main_cpu, *sib_cpu;
	nvlist_t *fmri;
	cmd_list_t *cpu_list;
	opl_cpu_t *opl_cpu;
	uint32_t main_cpuid, nsusp = 1;
	uint8_t cert;

	fmd_hdl_debug(hdl,
	    "Enter OPL_CPUUE_HANDLER for class %x\n", class);

	main_cpu = cpu;
	main_cpuid = cpu->cpu_cpuid;

	if (strcmp(fltname, "core") == 0)
		cpu_list = opl_cpulist_insert(hdl, cpu->cpu_cpuid,
		    IS_CORE);
	else if (strcmp(fltname, "chip") == 0)
		cpu_list = opl_cpulist_insert(hdl, cpu->cpu_cpuid,
		    IS_CHIP);
	else
		cpu_list = opl_cpulist_insert(hdl, cpu->cpu_cpuid,
		    IS_STRAND);

	for (opl_cpu = cmd_list_next(cpu_list); opl_cpu != NULL;
	    opl_cpu = cmd_list_next(opl_cpu)) {
		if (opl_cpu->oc_cpuid == main_cpuid) {
			sib_cpu = main_cpu;
			opl_cpu->oc_cmd_cpu = main_cpu;
		} else {
			fmri = cmd_cpu_fmri_create(opl_cpu->oc_cpuid, cpumask);
			if (fmri == NULL) {
				opl_cpu->oc_cmd_cpu = NULL;
				fmd_hdl_debug(hdl,
				    "missing asru, cpuid %u excluded\n",
				    opl_cpu->oc_cpuid);
				continue;
			}

			sib_cpu = cmd_cpu_lookup(hdl, fmri, class,
			    CMD_CPU_LEVEL_THREAD);
			if (sib_cpu == NULL || sib_cpu->cpu_faulting) {
				nvlist_free(fmri);
				opl_cpu->oc_cmd_cpu = NULL;
				fmd_hdl_debug(hdl,
				"cpu not present, cpuid %u excluded\n",
				    opl_cpu->oc_cpuid);
				continue;
			}
			opl_cpu->oc_cmd_cpu = sib_cpu;
			nvlist_free(fmri);
			nsusp++;
		}
		if (cpu->cpu_cpuid == main_cpuid) {
			if (cc->cc_cp != NULL &&
			    fmd_case_solved(hdl, cc->cc_cp)) {
				if (cpu_list != NULL)
					opl_cpulist_free(hdl, cpu_list);
				return (CMD_EVD_REDUND);
			}

			if (cc->cc_cp == NULL)
				cc->cc_cp = cmd_case_create(hdl,
				    &cpu->cpu_header, ptr, &uuid);

			if (cc->cc_serdnm != NULL) {
				fmd_hdl_debug(hdl,
			"destroying existing %s state for class %x\n",
				    cc->cc_serdnm, class);
				fmd_serd_destroy(hdl, cc->cc_serdnm);
				fmd_hdl_strfree(hdl, cc->cc_serdnm);
				cc->cc_serdnm = NULL;
				fmd_case_reset(hdl, cc->cc_cp);
			}
			fmd_case_add_ereport(hdl, cc->cc_cp, ep);
		}
	}
	cert = opl_avg(100, nsusp);
	for (opl_cpu = cmd_list_next(cpu_list); opl_cpu != NULL;
	    opl_cpu = cmd_list_next(opl_cpu)) {
		if (opl_cpu->oc_cmd_cpu != NULL) {
			nvlist_t *cpu_rsrc;

			cpu_rsrc = opl_cpursrc_create(hdl, opl_cpu->oc_cpuid);
			if (cpu_rsrc == NULL) {
				fmd_hdl_debug(hdl,
				"missing rsrc, cpuid %u excluded\n",
				    opl_cpu->oc_cpuid);
				continue;
			}
			cmd_cpu_create_faultlist(hdl, cc->cc_cp,
			    opl_cpu->oc_cmd_cpu, fltname, cpu_rsrc, cert);
			nvlist_free(cpu_rsrc);
		}
	}
	fmd_case_solve(hdl, cc->cc_cp);
	if (cpu_list != NULL)
		opl_cpulist_free(hdl, cpu_list);
	return (CMD_EVD_OK);
}

/*
 * Generates DIMM fault if the number of Permanent CE
 * threshold is exceeded.
 */
static void
opl_ce_thresh_check(fmd_hdl_t *hdl, cmd_dimm_t *dimm)
{
	nvlist_t *dflt;
	fmd_case_t *cp;

	fmd_hdl_debug(hdl,
	    "Permanent CE event threshold checking.\n");

	if (dimm->dimm_flags & CMD_MEM_F_FAULTING) {
		/* We've already complained about this DIMM */
		return;
	}

	if (dimm->dimm_nretired >= fmd_prop_get_int32(hdl,
	    "max_perm_ce_dimm")) {
		dimm->dimm_flags |= CMD_MEM_F_FAULTING;
		cp = fmd_case_open(hdl, NULL);
		dflt = cmd_dimm_create_fault(hdl, dimm, "fault.memory.dimm",
		    CMD_FLTMAXCONF);
		fmd_case_add_suspect(hdl, cp, dflt);
		fmd_case_solve(hdl, cp);
	}
}

/*
 * Notify fault page information (pa and errlog) to XSCF via mc-opl
 */
#define	MC_PHYDEV_DIR	"/devices"
#define	MC_PHYPREFIX	"pseudo-mc@"
static int
opl_scf_log(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	uint32_t *eadd, *elog;
	uint_t n;
	uint64_t pa;
	char path[MAXPATHLEN];
	char *unum;
	nvlist_t *rsrc;
	DIR *mcdir;
	struct dirent *dp;
	mc_flt_page_t flt_page;
	cmd_page_t *page;
	struct stat statbuf;

	/*
	 * Extract ereport.
	 * Sanity check of pa is already done at cmd_opl_mac_common().
	 * mc-opl sets only one entry for MC_OPL_ERR_ADD, MC_OPL_ERR_LOG,
	 * and MC_OPL_BANK.
	 */
	if ((nvlist_lookup_uint64(nvl, MC_OPL_PA, &pa) != 0) ||
	    (nvlist_lookup_uint32_array(nvl, MC_OPL_ERR_ADD, &eadd, &n) != 0) ||
	    (nvlist_lookup_uint32_array(nvl, MC_OPL_ERR_LOG, &elog, &n) != 0)) {
		fmd_hdl_debug(hdl, "opl_scf_log failed to extract ereport.\n");
		return (-1);
	}
	if (nvlist_lookup_nvlist(nvl, FM_EREPORT_PAYLOAD_NAME_RESOURCE,
	    &rsrc) != 0) {
		fmd_hdl_debug(hdl, "opl_scf_log failed to get resource.\n");
		return (-1);
	}
	if (nvlist_lookup_string(rsrc, FM_FMRI_MEM_UNUM, &unum) != 0) {
		fmd_hdl_debug(hdl, "opl_scf_log failed to get unum.\n");
		return (-1);
	}

	page = cmd_page_lookup(pa);
	if (page != NULL && page->page_flags & CMD_MEM_F_FAULTING) {
		/*
		 * fault.memory.page will not be created.
		 */
		return (0);
	}

	flt_page.err_add = eadd[0];
	flt_page.err_log = elog[0];
	flt_page.fmri_addr = (uint64_t)(uint32_t)unum;
	flt_page.fmri_sz = strlen(unum) + 1;

	fmd_hdl_debug(hdl, "opl_scf_log DIMM: %s (%d)\n",
	    unum, strlen(unum) + 1);
	fmd_hdl_debug(hdl, "opl_scf_log pa:%llx add:%x log:%x\n",
	    pa, eadd[0], elog[0]);

	if ((mcdir = opendir(MC_PHYDEV_DIR)) != NULL) {
		while ((dp = readdir(mcdir)) != NULL) {
			int fd;

			if (strncmp(dp->d_name, MC_PHYPREFIX,
			    strlen(MC_PHYPREFIX)) != 0)
				continue;

			(void) snprintf(path, sizeof (path),
			    "%s/%s", MC_PHYDEV_DIR, dp->d_name);

			if (stat(path, &statbuf) != 0 ||
			    (statbuf.st_mode & S_IFCHR) == 0) {
				/* skip if not a character device */
				continue;
			}

			if ((fd = open(path, O_RDONLY)) < 0)
				continue;

			if (ioctl(fd, MCIOC_FAULT_PAGE, &flt_page) == 0) {
				fmd_hdl_debug(hdl, "opl_scf_log ioctl(%s)\n",
				    path);
				(void) close(fd);
				(void) closedir(mcdir);
				return (0);
			}
			(void) close(fd);
		}
		(void) closedir(mcdir);
	}

	fmd_hdl_debug(hdl, "opl_scf_log failed ioctl().\n");

	return (-1);
}

/*
 * This is the common function for processing MAC detected
 * Intermittent and Permanent CEs.
 */

cmd_evdisp_t
cmd_opl_mac_ce(fmd_hdl_t *hdl, fmd_event_t *ep, const char *class,
    nvlist_t *asru, nvlist_t *fru, uint64_t pa, nvlist_t *nvl)
{
	cmd_dimm_t *dimm;
	const char *uuid;

	fmd_hdl_debug(hdl,
	    "Processing CE ereport\n");

	if ((dimm = cmd_dimm_lookup(hdl, asru)) == NULL &&
	    (dimm = cmd_dimm_create(hdl, asru)) == NULL)
		return (CMD_EVD_UNUSED);

	if (dimm->dimm_case.cc_cp == NULL) {
		dimm->dimm_case.cc_cp = cmd_case_create(hdl,
		    &dimm->dimm_header, CMD_PTR_DIMM_CASE, &uuid);
	}

	if (strcmp(class, "ereport.asic.mac.ptrl-ice") == 0) {
		CMD_STAT_BUMP(ce_interm);
		fmd_hdl_debug(hdl, "adding FJ-Intermittent event "
		    "to CE serd engine\n");

		if (dimm->dimm_case.cc_serdnm == NULL) {
			dimm->dimm_case.cc_serdnm =
			    cmd_mem_serdnm_create(hdl,
			    "dimm", dimm->dimm_unum);
			fmd_serd_create(hdl, dimm->dimm_case.cc_serdnm,
			    fmd_prop_get_int32(hdl, "ce_n"),
			    fmd_prop_get_int64(hdl, "ce_t"));
		}

		if (fmd_serd_record(hdl, dimm->dimm_case.cc_serdnm, ep) ==
		    FMD_B_FALSE) {
			return (CMD_EVD_OK); /* engine hasn't fired */
		}
		fmd_hdl_debug(hdl, "ce serd fired\n");
		fmd_case_add_serd(hdl, dimm->dimm_case.cc_cp,
		    dimm->dimm_case.cc_serdnm);
		fmd_serd_reset(hdl, dimm->dimm_case.cc_serdnm);

		(void) opl_scf_log(hdl, nvl);
	} else {
		CMD_STAT_BUMP(ce_sticky);
	}

	dimm->dimm_nretired++;
	dimm->dimm_retstat.fmds_value.ui64++;
	cmd_dimm_dirty(hdl, dimm);

	cmd_page_fault(hdl, asru, fru, ep, pa);
	opl_ce_thresh_check(hdl, dimm);

	return (CMD_EVD_OK);
}

/*
 * This is the common entry for processing MAC detected errors.
 * It is responsible for generating the memory page fault event.
 * The permanent CE (sticky) in normal mode is handled here also
 * in the same way as in the UE case.
 */
/*ARGSUSED*/
cmd_evdisp_t
cmd_opl_mac_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode)
{
	uint64_t pa;
	nvlist_t *rsrc = NULL, *asru = NULL, *fru = NULL;
	cmd_page_t *page;

	fmd_hdl_debug(hdl, "cmd_mac_common: clcode=%ll\n", clcode);

	if (nvlist_lookup_nvlist(nvl, MC_OPL_RESOURCE, &rsrc) != 0)
		return (CMD_EVD_BAD);

	if (nvlist_lookup_uint64(nvl, MC_OPL_PA, &pa)
	    != 0)
		return (CMD_EVD_BAD);

	/*
	 * Check for invalid pa.
	 * The most sig. bit should not be on.
	 * It would be out of the range of possible pa
	 * in MAC's view.
	 */
	if (((uint64_t)1 << 63) & pa)
		return (CMD_EVD_BAD);

	if ((page = cmd_page_lookup(pa)) != NULL &&
	    page->page_case.cc_cp != NULL &&
	    fmd_case_solved(hdl, page->page_case.cc_cp))
		return (CMD_EVD_REDUND);

	if (nvlist_dup(rsrc, &asru, 0) != 0) {
		fmd_hdl_debug(hdl, "cmd_opl_mac_common nvlist dup failed\n");
		return (CMD_EVD_BAD);
	}

	if (fmd_nvl_fmri_expand(hdl, asru) < 0) {
		fmd_hdl_debug(hdl, "cmd_opl_mac_common expand failed\n");
		nvlist_free(asru);
		CMD_STAT_BUMP(bad_mem_asru);
		return (CMD_EVD_BAD);
	}

	if ((fru = opl_mem_fru_create(hdl, asru)) == NULL) {
		fmd_hdl_debug(hdl, "cmd_opl_mac_common fru_create failed\n");
		nvlist_free(asru);
		return (CMD_EVD_BAD);
	}

	/*
	 * process PCE and ICE to create DIMM fault
	 */
	if (strcmp(class, "ereport.asic.mac.mi-ce") == 0 ||
	    strcmp(class, "ereport.asic.mac.ptrl-ce") == 0 ||
	    strcmp(class, "ereport.asic.mac.ptrl-ice") == 0) {
		cmd_evdisp_t ret;

		ret = cmd_opl_mac_ce(hdl, ep, class, asru, fru, pa, nvl);
		nvlist_free(asru);
		nvlist_free(fru);
		if (ret != CMD_EVD_OK) {
			fmd_hdl_debug(hdl,
			    "cmd_opl_mac_common: mac_ce failed\n");
			return (CMD_EVD_BAD);
		} else
			return (CMD_EVD_OK);
	}

	/* The following code handles page retires for UEs and CMPEs.  */

	cmd_page_fault(hdl, asru, fru, ep, pa);
	nvlist_free(asru);
	nvlist_free(fru);
	return (CMD_EVD_OK);
}

/*
 * Common entry points for handling CPU/IO detected UE with
 * respect to EID=MEM.
 */
/*ARGSUSED*/
cmd_evdisp_t
cmd_opl_cpu_mem(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode)
{
	return (opl_ue_mem(hdl, ep, nvl, CMD_OPL_HDLR_CPU));
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_opl_io_mem(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode)
{
	return (opl_ue_mem(hdl, ep, nvl, CMD_OPL_HDLR_IO));
}
