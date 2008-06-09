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

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>

#include <unistd.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <umem.h>

#include <mem_mdesc.h>

/*
 * Enumerates the DIMMS in a system.  For each DIMM found, the necessary nodes
 * are also constructed.
 */

#define	DIMM_VERSION	TOPO_VERSION
#define	DIMM_NODE_NAME	"dimm"

/* Forward declaration */
static int dimm_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void dimm_release(topo_mod_t *, tnode_t *);


static const topo_modops_t dimm_ops =
	{ dimm_enum, dimm_release };
static const topo_modinfo_t dimm_info =
	{ "dimm", FM_FMRI_SCHEME_HC, DIMM_VERSION, &dimm_ops };


static const topo_pgroup_info_t mem_auth_pgroup = {
	FM_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

int
_topo_init(topo_mod_t *mod)
{
	md_mem_info_t *mem;

	if (getenv("TOPOMEMDBG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing mem enumerator\n");

	if ((mem = topo_mod_zalloc(mod, sizeof (md_mem_info_t))) == NULL)
		return (-1);

	if (mem_mdesc_init(mod, mem) != 0) {
		topo_mod_dprintf(mod, "failed to get dimms from the PRI/MD\n");
		topo_mod_free(mod, mem, sizeof (md_mem_info_t));
		return (-1);
	}

	topo_mod_setspecific(mod, (void *)mem);

	if (topo_mod_register(mod, &dimm_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register hc: "
		    "%s\n", topo_mod_errmsg(mod));
		mem_mdesc_fini(mod, mem);
		topo_mod_free(mod, mem, sizeof (md_mem_info_t));
		return (-1);
	}

	topo_mod_dprintf(mod, "mem enumerator inited\n");

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	md_mem_info_t *mem;

	mem = (md_mem_info_t *)topo_mod_getspecific(mod);

	mem_mdesc_fini(mod, mem);

	topo_mod_free(mod, mem, sizeof (md_mem_info_t));

	topo_mod_unregister(mod);
}

static tnode_t *
mem_tnode_create(topo_mod_t *mod, tnode_t *parent,
    const char *name, topo_instance_t i, char *serial,
    nvlist_t *fru, char *label, void *priv)
{
	int err;
	nvlist_t *fmri;
	tnode_t *ntn;
	nvlist_t *auth = topo_mod_auth(mod, parent);

	fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, name, i,
	    NULL, auth, NULL, NULL, serial);
	nvlist_free(auth);
	if (fmri == NULL) {
		topo_mod_dprintf(mod,
		    "Unable to make nvlist for %s bind: %s.\n",
		    name, topo_mod_errmsg(mod));
		return (NULL);
	}

	ntn = topo_node_bind(mod, parent, name, i, fmri);
	if (ntn == NULL) {
		topo_mod_dprintf(mod,
		    "topo_node_bind (%s%d/%s%d) failed: %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i,
		    topo_strerror(topo_mod_errno(mod)));
		nvlist_free(fmri);
		return (NULL);
	}
	nvlist_free(fmri);
	topo_node_setspecific(ntn, priv);

	if (topo_pgroup_create(ntn, &mem_auth_pgroup, &err) == 0) {
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, &err);
	}

	(void) topo_node_label_set(ntn, label, &err);
	(void) topo_node_fru_set(ntn, fru, 0, &err);

	return (ntn);
}

static nvlist_t *
mem_fmri_create(topo_mod_t *mod, char *serial, char *label)
{
	int err;
	nvlist_t *fmri;

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0)
		return (NULL);
	err = nvlist_add_uint8(fmri, FM_VERSION, FM_MEM_SCHEME_VERSION);
	err |= nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_MEM);
	if (serial != NULL)
		err |= nvlist_add_string(fmri, FM_FMRI_MEM_SERIAL_ID, serial);
	if (label != NULL)
		err |= nvlist_add_string(fmri, FM_FMRI_MEM_UNUM, label);
	if (err != 0) {
		nvlist_free(fmri);
		(void) topo_mod_seterrno(mod, EMOD_FMRI_NVL);
		return (NULL);
	}

	return (fmri);
}

typedef struct {
	const char *nh_name;
	const char *nh_sscan;
} nac_hc_t;

static const nac_hc_t nac_mem_tbl[] = {
	{"branch",	"BR%d"	},
	{"dram-channel", "CH%d"	},
	{"rank",	"R%d"	},
	{"dimm",	"D%d"	},
	{"memboard",	"MR%d"	},
	{"memboard",	"MEM%d" },
	{"chip",	"CMP%d" }
};

static const char *
nac2hc(const char *s, int *inst)
{
	int i;

	if (s == NULL)
		return (NULL);

	for (i = 0; i < sizeof (nac_mem_tbl) / sizeof (nac_hc_t); i++) {
		if (sscanf(s, nac_mem_tbl[i].nh_sscan, inst) == 1)
			return (nac_mem_tbl[i].nh_name);
	}
	return (NULL);
}

static int
create_one_dimm(topo_mod_t *mod, tnode_t *pnode, int inst, mem_dimm_map_t *dp)
{
	tnode_t *cnode;
	nvlist_t *asru, *fru;
	int nerr = 0;

	/*
	 * Because mem_tnode_create will fill in a "FRU" value by default,
	 * but not an "ASRU" value, we have to compute the desired "FRU"
	 * value -before- calling mem_tnode_create, but it's ok to
	 * topo_mod_asru_set() the ASRU value after the topo_node is
	 * created.
	 */

	if ((fru = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION, "dimm",
	    inst, NULL, NULL, dp->dm_part, NULL, dp->dm_serid)) == NULL)
		nerr++;

	cnode = mem_tnode_create(mod, pnode, "dimm", inst,
	    dp->dm_serid, fru, dp->dm_label, NULL);
	nvlist_free(fru);
	if (cnode == NULL)
		return (++nerr);
	if ((asru = mem_fmri_create(mod, dp->dm_serid, dp->dm_label)) == NULL)
		return (++nerr);
	(void) topo_node_asru_set(cnode, asru, 0, &nerr);
	nvlist_free(asru);

	return (nerr);
}

int
slashorend(const char *s, int start)
{
	const char *t = s + start;

	if ((t = strchr(t, '/')) == NULL)
		return (strlen(s)); /* end */
	else
		return (t - s); /* next slash */
}

/*
 * mem_range_create and mem_inst_create are mutually recursive routines which
 * together create the node hierarchy for one dimm and its siblings.
 * mem_range_create is called when creating the first instance of a given node
 * type as child of a parent instance, because it is then, and only then,
 * that a topo range must be created.  It calls mem_inst_create for its first
 * and subsequent instances.  The recursion always starts with
 * mem_range_create, so it performs the up-front sanity checks.
 *
 * Note: the list of mem_dimm_map_t's pointed at by dp must be sorted
 * alphabetically by *dm_label.
 */

static int mem_range_create(topo_mod_t *, tnode_t *, int, mem_dimm_map_t *);

static int
mem_inst_create(topo_mod_t *mod, tnode_t *pnode, int pflen, mem_dimm_map_t *dp)
{
	int inst, pfnext;
	const char *nodename;
	tnode_t *cnode;
	mem_dimm_map_t *d;
	nvlist_t *fru;
	int nerr = 0;

	pfnext = slashorend(dp->dm_label, pflen);
	nodename = nac2hc((dp->dm_label) + pflen, &inst);
	d = dp;
	if (strcmp(nodename, "dimm") == 0) {
		return (create_one_dimm(mod, pnode, inst, dp));
	} else if (*(d->dm_label + pfnext) == '\0') { /* this node has a fru */
		fru = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION,
		    nodename, inst, NULL, NULL, dp->dm_part, NULL,
		    dp->dm_serid);
		cnode = mem_tnode_create(mod, pnode, nodename, inst,
		    dp->dm_serid, fru, dp->dm_label, NULL);
		nvlist_free(fru);
		d = dp->dm_next; /* next mem_dimm_map_t could be child */
	} else {
		cnode = mem_tnode_create(mod, pnode, nodename, inst,
		    NULL, NULL, NULL, NULL);
	}
	if ((d != NULL) &&
	    strncmp(dp->dm_label, d->dm_label, pfnext) == 0)
		nerr += mem_range_create(mod, cnode, pfnext+1, d);
	return (nerr);
}

int
mem_range_create(topo_mod_t *mod, tnode_t *pnode, int pflen,
    mem_dimm_map_t *dp)
{
	int inst, pfnext;
	const char *nodename;
	mem_dimm_map_t *d;
	int nerr = 0;

	if (pnode == NULL)
		return (1);		/* definitely an error */
	if (*(dp->dm_label + pflen) == '\0')
		return (1);  /* recursed too far */

	pfnext = slashorend(dp->dm_label, pflen);
	nodename = nac2hc(dp->dm_label + pflen, &inst);

	if (nodename != NULL) {
		if (topo_node_range_create(mod, pnode, nodename, 0,
		    MEM_DIMM_MAX) < 0) {
			topo_mod_dprintf(mod, "failed to create "
			    "DIMM range %s error %s\n", nodename,
			    topo_mod_errmsg(mod));
			return (-1);
		}
	} else {
		/*
		 * Skip over NAC elements other than those listed
		 * above.  These elements will appear
		 * in the DIMM's unum, but not in hc: scheme hierarchy.
		 */

		return (mem_range_create(mod, pnode, pfnext+1, dp));
	}

	nerr += mem_inst_create(mod, pnode, pflen, dp);

	for (d = dp->dm_next; d != NULL; d = d->dm_next) {
		if (strncmp(dp->dm_label, d->dm_label, pfnext) == 0)
			continue; /* child of 1st instance -- already done */
		else if (strncmp(dp->dm_label, d->dm_label,
		    pflen) == 0) { /* child of same parent */
			if (nodename == nac2hc((d->dm_label)+pflen, &inst)) {
				/*
				 * Same nodename as sibling.  Don't create
				 * new range, or the enumeration will die.
				 */
				nerr += mem_inst_create(mod, pnode, pflen, d);
				dp = d;
			} else {
				nodename = nac2hc((d->dm_label)+pflen, &inst);
				nerr += mem_range_create(mod, pnode, pflen, d);
				dp = d;
			}
		}
		else
			return (nerr); /* finished all children of my parent */
	}
	return (nerr); /* reached end of mem_dimm_map_t list */
}
static int
mem_create(topo_mod_t *mod, tnode_t *rnode, md_mem_info_t *cm)
{
	int l, nerrs;
	char nodename[10]; /* allows up to 10^6 chips in system */
	char *p;
	mem_dimm_map_t *dp;

	if (strcmp(topo_node_name(rnode), "chip") == 0) {

		(void) snprintf(nodename, 10, "CMP%d",
		    topo_node_instance(rnode));

		for (dp = cm->mem_dm; dp != NULL; dp = dp->dm_next) {
			p = strstr(dp->dm_label, nodename);
			if (p != NULL && (p = strchr(p, '/')) != NULL) {
				l = p - (dp->dm_label) + 1;
				break;
			}
		}
	} else if (strcmp(topo_node_name(rnode), "motherboard") == 0) {
		for (dp = cm->mem_dm; dp != NULL; dp = dp->dm_next) {
			p = strstr(dp->dm_label, "MB/MEM");
			if (p != NULL) {
				l = 3; /* start with MEM */
				break;
			}
		}
	} else {
		return (1);
	}

	if (dp != NULL)
		nerrs = mem_range_create(mod, rnode, l, dp);
	else
		nerrs = 1;
	return (nerrs);
}


/*
 * The hc-scheme memory enumerator is invoked from within a platform
 * toplogy file.  Make sure that the invocation is either
 * 1) a child of the chip enumerator, which will cause the argument "rnode"
 * below to be a chip node, and the dimm structures specific for that chip can
 * then be built from its specific node, or
 * 2) a child of the motherboard enumerator -- for Batoka and similar machines
 * with cpu-boards.
 */

/*ARGSUSED*/
static int
dimm_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	md_mem_info_t *mem = (md_mem_info_t *)arg;

	if (strcmp(name, DIMM_NODE_NAME) == 0)
		return (mem_create(mod, rnode, mem));

	return (-1);
}

/*ARGSUSED*/
static void
dimm_release(topo_mod_t *mp, tnode_t *node)
{
}
