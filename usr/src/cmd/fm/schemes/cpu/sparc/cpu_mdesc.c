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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/processor.h>
#include <fm/fmd_fmri.h>
#include <sys/param.h>
#include <string.h>
#include <errno.h>
#include <cpu_mdesc.h>

md_cpumap_t *
cpu_find_cpumap(uint32_t cpuid) {
	int i;
	md_cpumap_t *mcmp;

	for (i = 0, mcmp = cpu.cpu_mdesc_cpus;
	    i < cpu.cpu_mdesc_ncpus; i++, mcmp++) {
		if (cpuid == mcmp->cpumap_pid) {
			return (mcmp);
		}
	}
	return (NULL);
}

int
cpu_get_serialid_mdesc(uint32_t cpuid, uint64_t *serialidp)
{
	md_cpumap_t *mcmp;
	if ((mcmp = cpu_find_cpumap(cpuid)) != NULL) {
		*serialidp = mcmp->cpumap_serialno;
		return (0);
	}
	return (fmd_fmri_set_errno(ENOENT));
}

int
cpu_mdesc_init(ldom_hdl_t *lhp)
{
	md_t *mdp;
	mde_cookie_t *listp;
	md_cpumap_t *mcmp;
	uint64_t *bufp;
	int num_nodes, idx;
	ssize_t bufsiz = 0;
	char *type, *cpufru, *cpufrusn, *cpufrupn, *cpufrudn;
	int num_comps = 0;
	uint64_t tl;

	if ((bufsiz = ldom_get_core_md(lhp, &bufp)) > 0) {
		if ((mdp = md_init_intern(bufp, fmd_fmri_alloc,
					fmd_fmri_free)) == NULL) {
			fmd_fmri_free(bufp, (size_t)bufsiz);
			return (0);
		}
	} else {
		return (0);
	}

	num_nodes = md_node_count(mdp);
	listp = fmd_fmri_alloc(sizeof (mde_cookie_t) * num_nodes);

	num_comps = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "component"),
	    md_find_name(mdp, "fwd"),
	    listp);

	if (num_comps == 0) {
		cpu.cpu_mdesc_ncpus = md_scan_dag(mdp,
		    MDE_INVAL_ELEM_COOKIE,
		    md_find_name(mdp, "cpu"),
		    md_find_name(mdp, "fwd"),
		    listp);

		cpu.cpu_mdesc_cpus = fmd_fmri_alloc(cpu.cpu_mdesc_ncpus *
		    sizeof (md_cpumap_t));

		for (idx = 0, mcmp = cpu.cpu_mdesc_cpus;
		    idx < cpu.cpu_mdesc_ncpus;
		    idx++, mcmp++) {
			uint64_t tl;

			if (md_get_prop_val(mdp, listp[idx], "id", &tl) < 0)
				tl = (uint64_t)-1; /* invalid value */
			mcmp->cpumap_id = tl;

			if (md_get_prop_val(mdp, listp[idx], "pid", &tl) < 0)
				tl = mcmp->cpumap_id;
			mcmp->cpumap_pid = tl;

			if (md_get_prop_val(mdp, listp[idx], "serial#",
			    &mcmp->cpumap_serialno) < 0)
				mcmp->cpumap_serialno = 0;

			if (md_get_prop_str(mdp, listp[idx], "cpufru",
			    &cpufru) < 0)
				cpufru = "mb";
			mcmp->cpumap_cpufru = fmd_fmri_strdup(cpufru);

			if (md_get_prop_str(mdp, listp[idx], "cpufru-serial#",
			    &cpufrusn) < 0)
				cpufrusn = "";
			mcmp->cpumap_cpufrusn = fmd_fmri_strdup(cpufrusn);

			if (md_get_prop_str(mdp, listp[idx], "cpufru-part#",
			    &cpufrupn) < 0)
				cpufrupn = "";
			mcmp->cpumap_cpufrupn = fmd_fmri_strdup(cpufrupn);
			cpufrudn = "";
			mcmp->cpumap_cpufrudn = fmd_fmri_strdup(cpufrudn);
		}
	} else {
		uint64_t procsn;
		mde_cookie_t procnode = MDE_INVAL_ELEM_COOKIE;

		for (idx = 0; idx < num_comps; idx++) {
		    if (md_get_prop_str(mdp, listp[idx], "type", &type) < 0)
			continue;
		    if (strcmp(type, "systemboard") == 0) {
			cpufru = "MB";
			if (md_get_prop_str(mdp, listp[idx], "serial_number",
			    &cpufrusn) < 0)
				cpufrusn = "";
			if (md_get_prop_str(mdp, listp[idx], "part_number",
			    &cpufrupn) < 0)
				cpufrupn = "";
			if (md_get_prop_str(mdp, listp[idx], "dash_number",
			    &cpufrudn) < 0)
				cpufrudn = "";
			break;
		    }
		}

		for (idx = 0; idx < num_comps; idx++) {
		    if (md_get_prop_str(mdp, listp[idx], "type", &type) < 0)
			continue;
		    if (strcmp(type, "processor") == 0) {
			if (md_get_prop_val(mdp, listp[idx], "serial_number",
			    &procsn) < 0)
				procsn = 0;
			procnode = listp[idx];
			break;
		    }
		}

		/*
		 * scan the procnode to find all strand nodes
		 */
		cpu.cpu_mdesc_ncpus = md_scan_dag(mdp, procnode,
			md_find_name(mdp, "component"),
			md_find_name(mdp, "fwd"),
			listp);

		cpu.cpu_mdesc_cpus = fmd_fmri_alloc(cpu.cpu_mdesc_ncpus *
		    sizeof (md_cpumap_t));

		mcmp = cpu.cpu_mdesc_cpus;
		for (idx = 0; idx < cpu.cpu_mdesc_ncpus; idx++) {
			if (md_get_prop_str(mdp, listp[idx], "type", &type) < 0)
				continue;
			if (strcmp(type, "strand") == 0) {
				if (md_get_prop_val(mdp, listp[idx], "id",
				    &tl) < 0)
					tl = (uint64_t)-1;
				mcmp->cpumap_id = tl;

				mcmp->cpumap_pid = mcmp->cpumap_id;

				mcmp->cpumap_serialno = procsn;
				mcmp->cpumap_cpufru = fmd_fmri_strdup(cpufru);
				mcmp->cpumap_cpufrusn =
				    fmd_fmri_strdup(cpufrusn);
				mcmp->cpumap_cpufrupn =
				    fmd_fmri_strdup(cpufrupn);
				mcmp->cpumap_cpufrudn =
				    fmd_fmri_strdup(cpufrudn);
				mcmp++;
			}
		}

	}

	fmd_fmri_free(listp, sizeof (mde_cookie_t) * num_nodes);
	fmd_fmri_free(bufp, (size_t)bufsiz);
	(void) md_fini(mdp);

	return (0);
}

void
cpu_mdesc_fini(void)
{
	if (cpu.cpu_mdesc_cpus != NULL) {
		int idx;
		md_cpumap_t *mcmp;
		for (idx = 0, mcmp = cpu.cpu_mdesc_cpus;
		    idx < cpu.cpu_mdesc_ncpus;
		    idx++, mcmp++) {
			fmd_fmri_strfree(mcmp->cpumap_cpufru);
			fmd_fmri_strfree(mcmp->cpumap_cpufrusn);
			fmd_fmri_strfree(mcmp->cpumap_cpufrupn);
		}
		fmd_fmri_free(cpu.cpu_mdesc_cpus,
		    cpu.cpu_mdesc_ncpus * sizeof (md_cpumap_t));
	}
}
