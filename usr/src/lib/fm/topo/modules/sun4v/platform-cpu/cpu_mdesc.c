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

#include <string.h>
#include <umem.h>
#include <sys/mdesc.h>
#include <sys/fm/ldom.h>

#include <cpu_mdesc.h>

static void *
cpu_alloc(size_t size)
{
	return (umem_alloc(size, UMEM_DEFAULT));
}

static void
cpu_free(void *data, size_t size)
{
	umem_free(data, size);
}

md_proc_t *
cpu_find_proc(md_info_t *chip, uint32_t procid) {
	int i;
	md_proc_t *procp;

	/* search the processor based on the physical id */
	for (i = 0, procp = chip->procs; i < chip->nprocs; i++, procp++) {
		if (procp->serialno != 0 && procid == procp->id) {
			return (procp);
		}
	}

	return (NULL);
}

md_cpumap_t *
cpu_find_cpumap(md_info_t *chip, uint32_t cpuid) {
	int i;
	md_cpumap_t *mcmp;

	for (i = 0, mcmp = chip->cpus; i < chip->ncpus; i++, mcmp++) {
		if (cpuid == mcmp->cpumap_pid) {
			return (mcmp);
		}
	}
	return (NULL);
}

int
cpu_get_serialid_mdesc(md_info_t *chip, uint32_t cpuid, uint64_t *serialidp)
{
	md_cpumap_t *mcmp;
	if ((mcmp = cpu_find_cpumap(chip, cpuid)) != NULL) {
		*serialidp = mcmp->cpumap_serialno;
		return (0);
	}
	return (-1);
}

static int
cpu_n1_mdesc_init(topo_mod_t *mod, md_t *mdp, md_info_t *chip)
{
	mde_cookie_t *listp;
	md_cpumap_t *mcmp;
	int i, num_nodes, idx;
	uint64_t x;

	num_nodes = md_node_count(mdp);
	listp = topo_mod_zalloc(mod, sizeof (mde_cookie_t) * num_nodes);

	chip->ncpus = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "cpu"),
	    md_find_name(mdp, "fwd"),
	    listp);
	topo_mod_dprintf(mod, "Found %d cpus\n", chip->ncpus);

	chip->cpus = topo_mod_zalloc(mod, chip->ncpus * sizeof (md_cpumap_t));
	chip->nprocs = chip->ncpus;
	chip->procs = topo_mod_zalloc(mod, chip->nprocs * sizeof (md_proc_t));

	for (idx = 0, mcmp = chip->cpus; idx < chip->ncpus; idx++, mcmp++) {

		if (md_get_prop_val(mdp, listp[idx], MD_STR_ID, &x) < 0)
			x = (uint64_t)-1; /* invalid value */
		mcmp->cpumap_id = x;

		if (md_get_prop_val(mdp, listp[idx], MD_STR_PID, &x) < 0)
			x = mcmp->cpumap_id;
		mcmp->cpumap_pid = x;

		mcmp->cpumap_serialno = 0;
		mcmp->cpumap_chipidx = -1;
		if (md_get_prop_val(mdp, listp[idx], MD_STR_CPU_SERIAL,
		    &mcmp->cpumap_serialno) < 0) {
			continue;
		}
		if (mcmp->cpumap_serialno == 0) {
			continue;
		}

		/*
		 * This PRI/MD has no indentity info. of the FRU and no
		 * physical proc id.
		 * Find if there is already an existing processor entry
		 * Assign procid based on the order found during reading
		 */
		for (i = 0; i < chip->nprocs &&
		    chip->procs[i].serialno != 0; i++) {
			if (mcmp->cpumap_serialno == chip->procs[i].serialno) {
				break;
			}
		}
		if (i < chip->nprocs) {
			mcmp->cpumap_chipidx = i;
			if (chip->procs[i].serialno == 0) {
				chip->procs[i].id = i;
				chip->procs[i].serialno = mcmp->cpumap_serialno;
				topo_mod_dprintf(mod,
				    "chip[%d] serial is %llx\n",
				    i, chip->procs[i].serialno);
			}
		}

	}

	topo_mod_free(mod, listp, sizeof (mde_cookie_t) * num_nodes);

	return (0);
}

static int
cpu_n2_mdesc_init(topo_mod_t *mod, md_t *mdp, md_info_t *chip)
{
	mde_cookie_t *list1p, *list2p;
	md_cpumap_t *mcmp;
	md_proc_t *procp;
	md_fru_t *frup;
	int i, j, cnt;
	int procid_flag = 0;
	int nnode, ncomp, nproc, ncpu;
	char *str = NULL;
	uint64_t x, sn;

	nnode = md_node_count(mdp);
	list1p = topo_mod_zalloc(mod, sizeof (mde_cookie_t) * nnode);

	/* Count the number of processors and strands */
	ncomp = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, MD_STR_COMPONENT),
	    md_find_name(mdp, "fwd"),
	    list1p);
	if (ncomp <= 0) {
		topo_mod_dprintf(mod, "Component nodes not found\n");
		topo_mod_free(mod, list1p, sizeof (mde_cookie_t) * nnode);
		return (-1);
	}
	for (i = 0, nproc = 0, ncpu = 0; i < ncomp; i++) {
		if (md_get_prop_str(mdp, list1p[i], MD_STR_TYPE, &str) == 0 &&
		    str != NULL && strcmp(str, MD_STR_PROCESSOR) == 0) {
			nproc++;
			/* check if the physical id exists */
			if (md_get_prop_val(mdp, list1p[i], MD_STR_ID, &x)
			    == 0) {
				procid_flag = 1;
			}
		}
		if (md_get_prop_str(mdp, list1p[i], MD_STR_TYPE, &str) == 0 &&
		    str && strcmp(str, MD_STR_STRAND) == 0) {
			ncpu++;
		}
	}
	topo_mod_dprintf(mod, "Found %d procs and %d strands\n", nproc, ncpu);
	if (nproc == 0 || ncpu == 0) {
		topo_mod_free(mod, list1p, sizeof (mde_cookie_t) * nnode);
		return (-1);
	}

	/* Alloc processors and strand entries */
	list2p = topo_mod_zalloc(mod, sizeof (mde_cookie_t) * 2 * ncpu);
	chip->nprocs = nproc;
	chip->procs = topo_mod_zalloc(mod, nproc * sizeof (md_proc_t));
	chip->ncpus = ncpu;
	chip->cpus = topo_mod_zalloc(mod, ncpu * sizeof (md_cpumap_t));

	/* Visit each processor node */
	procp = chip->procs;
	mcmp = chip->cpus;
	for (i = 0, nproc = 0, ncpu = 0; i < ncomp; i++) {
		if (md_get_prop_str(mdp, list1p[i], MD_STR_TYPE, &str) < 0 ||
		    str == NULL || strcmp(str, MD_STR_PROCESSOR))
			continue;
		if (md_get_prop_val(mdp, list1p[i], MD_STR_SERIAL, &sn) < 0) {
			topo_mod_dprintf(mod,
			    "Failed to get the serial number of proc[%d]\n",
			    nproc);
			continue;
		}
		procp->serialno = sn;

		/* Assign physical proc id */
		procp->id = -1;
		if (procid_flag) {
			if (md_get_prop_val(mdp, list1p[i], MD_STR_ID, &x)
			    == 0) {
				procp->id = x;
			}
		} else {
			procp->id = nproc;
		}
		topo_mod_dprintf(mod, "proc %d: sn=%llx, id=%d\n", nproc,
		    procp->serialno, procp->id);

		/* Get all the strands below this proc */
		cnt = md_scan_dag(mdp,
		    list1p[i],
		    md_find_name(mdp, MD_STR_COMPONENT),
		    md_find_name(mdp, "fwd"),
		    list2p);
		topo_mod_dprintf(mod, "proc[%llx]: Found %d fwd components\n",
		    sn, cnt);
		if (cnt <= 0) {
			nproc++;
			procp++;
			continue;
		}
		for (j = 0; j < cnt; j++) {
			/* Consider only the strand nodes */
			if (md_get_prop_str(mdp, list2p[j], MD_STR_TYPE, &str)
			    < 0 || str == NULL || strcmp(str, MD_STR_STRAND))
				continue;

			if (md_get_prop_val(mdp, list2p[j], MD_STR_ID, &x) < 0)
				x = (uint64_t)-1; /* invalid value */
			mcmp->cpumap_id = x;

			if (md_get_prop_val(mdp, list2p[j], MD_STR_PID, &x) < 0)
				x = mcmp->cpumap_id;
			mcmp->cpumap_pid = x;

			mcmp->cpumap_serialno = sn;
			mcmp->cpumap_chipidx = nproc;
			ncpu++;
			mcmp++;
		}

		/*
		 * To get the fru of this proc, follow the back arc up to
		 * find the first node whose fru field is set
		 */
		cnt = md_scan_dag(mdp,
		    list1p[i],
		    md_find_name(mdp, MD_STR_COMPONENT),
		    md_find_name(mdp, "back"),
		    list2p);
		topo_mod_dprintf(mod, "proc[%d]: Found %d back components\n",
		    nproc, cnt);
		if (cnt <= 0) {
			nproc++;
			procp++;
			continue;
		}
		for (j = 0; j < cnt; j++) {
			/* test the fru field which must be positive number */
			if ((md_get_prop_val(mdp, list2p[j], MD_STR_FRU, &x)
			    == 0) && x > 0)
				break;
		}
		if (j < cnt) {
			/* Found the FRU node, get the fru identity */
			topo_mod_dprintf(mod, "proc[%d] sn=%llx has a fru %d\n",
			    nproc, procp->serialno, j);
			frup = topo_mod_zalloc(mod, sizeof (md_fru_t));
			procp->fru = frup;
			if (!md_get_prop_str(mdp, list2p[j], MD_STR_NAC, &str))
				frup->nac = topo_mod_strdup(mod, str);
			else
				frup->nac = topo_mod_strdup(mod, MD_FRU_DEF);
			if (!md_get_prop_str(mdp, list2p[j], MD_STR_PART, &str))
				frup->part = topo_mod_strdup(mod, str);
			if (!md_get_prop_str(mdp, list2p[j], MD_STR_SERIAL,
			    &str))
				frup->serial = topo_mod_strdup(mod, str);
			if (!md_get_prop_str(mdp, list2p[j], MD_STR_DASH, &str))
				frup->dash = topo_mod_strdup(mod, str);
		} else {
			topo_mod_dprintf(mod, "proc[%d] sn=%llx has no fru\n",
			    i, procp->serialno);
		}

		nproc++;
		procp++;
	} /* for i */

	topo_mod_free(mod, list1p, sizeof (mde_cookie_t) * nnode);
	topo_mod_free(mod, list2p, sizeof (mde_cookie_t) * 2*chip->ncpus);

	return (0);
}

/*
 * Extract from the PRI the processor, strand and their fru identity
 */
int
cpu_mdesc_init(topo_mod_t *mod, md_info_t *chip)
{
	int rc = -1;
	md_t *mdp;
	ssize_t bufsiz = 0;
	uint64_t *bufp;
	ldom_hdl_t *lhp;
	uint32_t type = 0;

	/* get the PRI/MD */
	if ((lhp = ldom_init(cpu_alloc, cpu_free)) == NULL) {
		topo_mod_dprintf(mod, "ldom_init() failed\n");
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	(void) ldom_get_type(lhp, &type);
	if ((type & LDOM_TYPE_CONTROL) != 0) {
		bufsiz = ldom_get_core_md(lhp, &bufp);
	} else {
		bufsiz = ldom_get_local_md(lhp, &bufp);
	}
	if (bufsiz <= 0) {
		topo_mod_dprintf(mod, "failed to get the PRI/MD\n");
		ldom_fini(lhp);
		return (-1);
	}

	if ((mdp = md_init_intern(bufp, cpu_alloc, cpu_free)) == NULL ||
	    md_node_count(mdp) <= 0) {
		cpu_free(bufp, (size_t)bufsiz);
		ldom_fini(lhp);
		return (-1);
	}

	/*
	 * N1 MD contains cpu nodes while N2 MD contains component nodes.
	 */
	if (md_find_name(mdp, MD_STR_COMPONENT) != MDE_INVAL_STR_COOKIE) {
		rc = cpu_n2_mdesc_init(mod, mdp, chip);
	} else if (md_find_name(mdp, MD_STR_CPU) != MDE_INVAL_STR_COOKIE) {
		rc =  cpu_n1_mdesc_init(mod, mdp, chip);
	} else {
		topo_mod_dprintf(mod, "Unsupported PRI/MD\n");
		rc = -1;
	}

	cpu_free(bufp, (size_t)bufsiz);
	(void) md_fini(mdp);
	ldom_fini(lhp);

	return (rc);
}

void
cpu_mdesc_fini(topo_mod_t *mod, md_info_t *chip)
{
	int i;
	md_proc_t *procp;
	md_fru_t *frup;

	if (chip->cpus != NULL)
		topo_mod_free(mod, chip->cpus,
		    chip->ncpus * sizeof (md_cpumap_t));

	if (chip->procs != NULL) {
		procp = chip->procs;
		for (i = 0; i < chip->nprocs; i++) {
			if ((frup = procp->fru) != NULL) {
				topo_mod_strfree(mod, frup->nac);
				topo_mod_strfree(mod, frup->serial);
				topo_mod_strfree(mod, frup->part);
				topo_mod_strfree(mod, frup->dash);
				topo_mod_free(mod, frup, sizeof (md_fru_t));
			}
			procp++;
		}
		topo_mod_free(mod, chip->procs,
		    chip->nprocs * sizeof (md_proc_t));
	}
}
