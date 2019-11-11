
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Joyent, Inc.
 */

#include <strings.h>
#include <umem.h>
#include <fm/topo_mod.h>
#include <fm/fmd_fmri.h>
#include <fm/fmd_agent.h>
#include <sys/fm/protocol.h>

#include <mem_mdesc.h>

/*
 * This enumerator creates mem-schemed nodes for each dimm found in the
 * sun4v Physical Resource Inventory (PRI).
 * Each node exports five methods: present(), expand(), unusable(), replaced(),
 * and contains().
 *
 */

#define	PLATFORM_MEM_NAME	"platform-mem"
#define	PLATFORM_MEM_VERSION	TOPO_VERSION
#define	MEM_NODE_NAME		"mem"


/* Forward declaration */
static int mem_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void mem_release(topo_mod_t *, tnode_t *);
static int mem_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int mem_replaced(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int mem_expand(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int mem_unusable(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int mem_contains(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);

static const topo_modops_t mem_ops =
	{ mem_enum, mem_release };
static const topo_modinfo_t mem_info =
	{ PLATFORM_MEM_NAME, FM_FMRI_SCHEME_MEM, PLATFORM_MEM_VERSION,
		&mem_ops };

static const topo_method_t mem_methods[] = {
	{ TOPO_METH_PRESENT, TOPO_METH_PRESENT_DESC,
	    TOPO_METH_PRESENT_VERSION, TOPO_STABILITY_INTERNAL, mem_present },
	{ TOPO_METH_REPLACED, TOPO_METH_REPLACED_DESC,
	    TOPO_METH_REPLACED_VERSION, TOPO_STABILITY_INTERNAL, mem_replaced },
	{ TOPO_METH_EXPAND, TOPO_METH_EXPAND_DESC,
	    TOPO_METH_EXPAND_VERSION, TOPO_STABILITY_INTERNAL, mem_expand },
	{ TOPO_METH_UNUSABLE, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_UNUSABLE_VERSION, TOPO_STABILITY_INTERNAL, mem_unusable },
	{ TOPO_METH_CONTAINS, TOPO_METH_CONTAINS_DESC,
	    TOPO_METH_CONTAINS_VERSION, TOPO_STABILITY_INTERNAL, mem_contains },
	{ NULL }
};

int
_topo_init(topo_mod_t *mod)
{
	md_mem_info_t *mem;

	if (getenv("TOPOPLATFORMMEMDBG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing %s enumerator\n",
	    PLATFORM_MEM_NAME);

	if ((mem = topo_mod_zalloc(mod, sizeof (md_mem_info_t))) == NULL)
		return (-1);

	if (mem_mdesc_init(mod, mem) != 0) {
		topo_mod_dprintf(mod, "failed to get dimms from the PRI/MD\n");
		topo_mod_free(mod, mem, sizeof (md_mem_info_t));
		return (-1);
	}

	topo_mod_setspecific(mod, (void *)mem);

	if (topo_mod_register(mod, &mem_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register %s: %s\n",
		    PLATFORM_MEM_NAME, topo_mod_errmsg(mod));
		mem_mdesc_fini(mod, mem);
		topo_mod_free(mod, mem, sizeof (md_mem_info_t));
		return (-1);
	}

	topo_mod_dprintf(mod, "%s enumerator inited\n", PLATFORM_MEM_NAME);

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

/*ARGSUSED*/
static int
mem_present(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	uint8_t version;
	char **nvlserids;
	size_t n, nserids;
	uint32_t present = 0;
	md_mem_info_t *mem = (md_mem_info_t *)topo_mod_getspecific(mod);

	/* sun4v platforms all support dimm serial numbers */

	if (nvlist_lookup_uint8(in, FM_VERSION, &version) != 0 ||
	    version > FM_MEM_SCHEME_VERSION ||
	    nvlist_lookup_string_array(in, FM_FMRI_MEM_SERIAL_ID,
	    &nvlserids, &nserids) != 0) {
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	/* Find the dimm entry */
	for (n = 0; n < nserids; n++) {
		if (mem_get_dimm_by_sn(nvlserids[n], mem) != NULL) {
			present = 1;
			break;
		}
	}

	/* return the present status */
	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_PRESENT_RET, present) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	return (0);
}

/*ARGSUSED*/
static int
mem_replaced(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	uint8_t version;
	char **nvlserids;
	size_t n, nserids;
	uint32_t rval = FMD_OBJ_STATE_NOT_PRESENT;
	md_mem_info_t *mem = (md_mem_info_t *)topo_mod_getspecific(mod);

	/* sun4v platforms all support dimm serial numbers */

	if (nvlist_lookup_uint8(in, FM_VERSION, &version) != 0 ||
	    version > FM_MEM_SCHEME_VERSION ||
	    nvlist_lookup_string_array(in, FM_FMRI_MEM_SERIAL_ID,
	    &nvlserids, &nserids) != 0) {
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	/* Find the dimm entry */
	for (n = 0; n < nserids; n++) {
		if (mem_get_dimm_by_sn(nvlserids[n], mem) != NULL) {
			rval = FMD_OBJ_STATE_STILL_PRESENT;
			break;
		}
	}

	/* return the replaced status */
	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_REPLACED_RET, rval) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	return (0);
}

/*
 * Niagara-1, Niagara-2, and Victoria Falls all have physical address
 * spaces of 40 bits.
 */

#define	MEM_PHYS_ADDRESS_LIMIT	0x10000000000ULL

/*
 * The 'mask' argument to extract_bits has 1's in those bit positions of
 * the physical address used to select the DIMM (or set of DIMMs) which will
 * store the contents of the physical address.  If we extract those bits, ie.
 * remove them and collapse the holes, the result is the 'address' within the
 * DIMM or set of DIMMs where the contents are stored.
 */

static uint64_t
extract_bits(uint64_t paddr, uint64_t mask)
{
	uint64_t from, to;
	uint64_t result = 0;

	to = 1;
	for (from = 1; from <= MEM_PHYS_ADDRESS_LIMIT; from <<= 1) {
		if ((from & mask) == 0) {
			if ((from & paddr) != 0)
				result |= to;
			to <<= 1;
		}
	}
	return (result);
}

/*
 * insert_bits is the reverse operation to extract_bits.  Where extract_bits
 * removes from the physical address those bits which select a DIMM or set
 * of DIMMs, insert_bits reconstitutes a physical address given the DIMM
 * selection 'mask' and the 'value' for the address bits denoted by 1s in
 * the 'mask'.
 */
static uint64_t
insert_bits(uint64_t offset, uint64_t mask, uint64_t value)
{
	uint64_t result = 0;
	uint64_t from, to;

	from = 1;
	for (to = 1; to <= MEM_PHYS_ADDRESS_LIMIT; to <<= 1) {
		if ((to & mask) == 0) {
			if ((offset & from) != 0)
				result |= to;
			from <<= 1;
		} else {
			result |= to & value;
		}
	}
	return (result);
}

uint64_t
calc_phys_addr(mem_seg_map_t *seg, char *ds, uint64_t offset)
{
	mem_bank_map_t *bm;
	mem_dimm_list_t *dl;

	for (bm = seg->sm_grp->mg_bank; bm != NULL; bm = bm->bm_grp) {
		dl = bm->bm_dlist;
		while (dl != NULL) {
			if (strcmp(dl->dl_dimm->dm_serid, ds) == 0)
				return (insert_bits(offset<<bm->bm_shift,
				    bm->bm_mask, bm->bm_match));
			dl = dl->dl_next;
		}
	}
	return ((uint64_t)-1);
}

void
mem_expand_opt(topo_mod_t *mod, nvlist_t *nvl, char **serids)
{
	md_mem_info_t *mem = (md_mem_info_t *)topo_mod_getspecific(mod);
	mem_seg_map_t *seg;
	mem_bank_map_t *bm;
	uint64_t offset, physaddr;

	/*
	 * The following additional expansions are all optional.
	 * Failure to retrieve a data value, or failure to add it
	 * successfully to the FMRI, does NOT cause a failure of
	 * fmd_fmri_expand.  All optional expansions will be attempted
	 * once expand_opt is entered.
	 */

	if (nvlist_lookup_uint64(nvl, FM_FMRI_MEM_OFFSET, &offset) == 0) {
		for (seg = mem->mem_seg; seg != NULL; seg = seg->sm_next) {
			physaddr = calc_phys_addr(seg, *serids, offset);
			if (physaddr >= seg->sm_base &&
			    physaddr < seg->sm_base + seg->sm_size) {
				(void) nvlist_add_uint64(nvl,
				    FM_FMRI_MEM_PHYSADDR, physaddr);
			}
		}
	} else if (nvlist_lookup_uint64(nvl,
	    FM_FMRI_MEM_PHYSADDR, &physaddr) == 0) {
		for (seg = mem->mem_seg; seg != NULL; seg = seg->sm_next) {
			if (physaddr >= seg->sm_base &&
			    physaddr < seg->sm_base + seg->sm_size) {
				bm = seg->sm_grp->mg_bank;
				/*
				 * The mask & shift values for all banks in a
				 * segment are always the same; only the match
				 * values differ, in order to specify a
				 * dimm-pair. But we already have a full unum.
				 */
				offset = extract_bits(physaddr,
				    bm->bm_mask) >> bm->bm_shift;
				(void) (nvlist_add_uint64(nvl,
				    FM_FMRI_MEM_OFFSET, offset));
			}
		}
	}
}

/*
 * The sun4v mem: scheme expand() now assumes that the FMRI -has- serial
 * numbers, therefore we should never have to call mem_unum_burst again.
 * Part numbers will be supplied in hc: scheme from the hc: enumeration.
 * What's left: physical address and offset calculations.
 */

/*ARGSUSED*/
static int
mem_expand(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	int rc;
	uint8_t version;
	char *unum, **nvlserids;
	size_t nserids;

	if (nvlist_lookup_uint8(in, FM_VERSION, &version) != 0 ||
	    version > FM_MEM_SCHEME_VERSION ||
	    nvlist_lookup_string(in, FM_FMRI_MEM_UNUM, &unum) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));

	if ((rc = nvlist_lookup_string_array(in, FM_FMRI_MEM_SERIAL_ID,
	    &nvlserids, &nserids)) == 0) { /* already have serial #s */
		mem_expand_opt(mod, in, nvlserids);
		return (0);
	} else if (rc != ENOENT)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	else
		return (-1);
}

int
mem_page_isretired(topo_mod_t *mod, nvlist_t *nvl)
{
	ldom_hdl_t *lhp;
	int rc;

	if ((lhp = ldom_init(mem_alloc, mem_free)) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		errno = ENOMEM;
		return (FMD_AGENT_RETIRE_FAIL);
	}

	rc = ldom_fmri_status(lhp, nvl);

	ldom_fini(lhp);
	errno = rc;

	if (rc == 0 || rc == EINVAL)
		return (FMD_AGENT_RETIRE_DONE);
	if (rc == EAGAIN)
		return (FMD_AGENT_RETIRE_ASYNC);

	return (FMD_AGENT_RETIRE_FAIL);
}

int
mem_page_retire(topo_mod_t *mod, nvlist_t *nvl)
{
	ldom_hdl_t *lhp;
	int rc;

	if ((lhp = ldom_init(mem_alloc, mem_free)) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		errno = ENOMEM;
		return (FMD_AGENT_RETIRE_FAIL);
	}

	rc = ldom_fmri_retire(lhp, nvl);

	ldom_fini(lhp);
	errno = rc;

	if (rc == 0 || rc == EIO || rc == EINVAL)
		return (FMD_AGENT_RETIRE_DONE);
	if (rc == EAGAIN)
		return (FMD_AGENT_RETIRE_ASYNC);

	return (FMD_AGENT_RETIRE_FAIL);
}

int
mem_page_unretire(topo_mod_t *mod, nvlist_t *nvl)
{
	ldom_hdl_t *lhp;
	int rc;

	if ((lhp = ldom_init(mem_alloc, mem_free)) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		errno = ENOMEM;
		return (FMD_AGENT_RETIRE_FAIL);
	}

	rc = ldom_fmri_unretire(lhp, nvl);

	ldom_fini(lhp);
	errno = rc;

	if (rc == 0 || rc == EIO)
		return (FMD_AGENT_RETIRE_DONE);

	return (FMD_AGENT_RETIRE_FAIL);

}

/*ARGSUSED*/
static int
mem_unusable(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	int rc = -1;
	uint8_t version;
	uint64_t val1, val2;
	int err1, err2;
	uint32_t retval;

	if (nvlist_lookup_uint8(in, FM_VERSION, &version) != 0 ||
	    version > FM_MEM_SCHEME_VERSION)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));

	err1 = nvlist_lookup_uint64(in, FM_FMRI_MEM_OFFSET, &val1);
	err2 = nvlist_lookup_uint64(in, FM_FMRI_MEM_PHYSADDR, &val2);

	if (err1 == ENOENT && err2 == ENOENT)
		return (0); /* no page, so assume it's still usable */

	if ((err1 != 0 && err1 != ENOENT) || (err2 != 0 && err2 != ENOENT))
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));

	/*
	 * Ask the kernel if the page is retired, using
	 * the original mem FMRI with the specified offset or PA.
	 * Refer to the kernel's page_retire_check() for the error codes.
	 */
	rc = mem_page_isretired(mod, in);

	if (rc == FMD_AGENT_RETIRE_FAIL) {
		/*
		 * The page is not retired and is not scheduled for retirement
		 * (i.e. no request pending and has not seen any errors)
		 */
		retval = 0;
	} else if (rc == FMD_AGENT_RETIRE_DONE ||
	    rc == FMD_AGENT_RETIRE_ASYNC) {
		/*
		 * The page has been retired, is in the process of being
		 * retired, or doesn't exist.  The latter is valid if the page
		 * existed in the past but has been DR'd out.
		 */
		retval = 1;
	} else {
		/*
		 * Errors are only signalled to the caller if they're the
		 * caller's fault.  This isn't - it's a failure of the
		 * retirement-check code.  We'll whine about it and tell
		 * the caller the page is unusable.
		 */
		topo_mod_dprintf(mod,
		    "failed to determine page %s=%llx usability: "
		    "rc=%d errno=%d\n", err1 == 0 ? FM_FMRI_MEM_OFFSET :
		    FM_FMRI_MEM_PHYSADDR, err1 == 0 ? (u_longlong_t)val1 :
		    (u_longlong_t)val2, rc, errno);
		retval = 1;
	}

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_UNUSABLE_RET, retval) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	return (0);
}

/* ARGSUSED */
static int
mem_contains(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	int rc = -1, ret = 1;
	uint8_t version;
	unsigned int erx, eex, ersiz, eesiz;
	nvlist_t *er, *ee;
	char **ersna, **eesna;

	/*
	 * Unlike the other exported functions, the 'in' argument here is
	 * not a pass-through -- it is a composite of the 'container' and
	 * 'containee' FMRIs.  Rather than checking the version of 'in',
	 * check the versions of the container and containee.
	 */
	if (nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_FMRI, &er) != 0 ||
	    nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_SUBFMRI, &ee) != 0 ||
	    nvlist_lookup_uint8(er, FM_VERSION, &version) != 0 ||
	    version > FM_MEM_SCHEME_VERSION ||
	    nvlist_lookup_uint8(ee, FM_VERSION, &version) != 0 ||
	    version > FM_MEM_SCHEME_VERSION ||
	    nvlist_lookup_string_array(er, FM_FMRI_MEM_SERIAL_ID,
	    &ersna, &ersiz) != 0 ||
	    nvlist_lookup_string_array(ee, FM_FMRI_MEM_SERIAL_ID,
	    &eesna, &eesiz) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));

	/*
	 * Look up each 'ee' serial number in serial number list of 'er'.
	 * If any are not found, return "false"; if all are found, return
	 * "true".
	 */

	for (eex = 0; eex < eesiz; eex++) {
		for (erx = 0; erx < ersiz; erx++) {
			rc = strcmp(ersna[erx], eesna[eex]);
			if (rc == 0)
				break;
		}
		if (rc != 0) {
			/* failed -- no containment */
			ret = 0;
			break;
		}
	}
	/* success */
	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) == 0) {
		if (nvlist_add_uint32(*out, TOPO_METH_CONTAINS_RET, ret) != 0) {
			nvlist_free(*out);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}
		return (0);
	}
	return (-1);
}

static nvlist_t *
mem_fmri_create(topo_mod_t *mod, char *unum, char *serial)
{
	int err;
	nvlist_t *fmri;

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0)
		return (NULL);
	err = nvlist_add_uint8(fmri, FM_VERSION, FM_MEM_SCHEME_VERSION);
	err |= nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_MEM);
	err |= nvlist_add_string(fmri, FM_FMRI_MEM_UNUM, unum);
	if (serial != NULL)
		err |= nvlist_add_string_array(fmri,
		    FM_FMRI_MEM_SERIAL_ID, &serial, 1);
	if (err != 0) {
		nvlist_free(fmri);
		(void) topo_mod_seterrno(mod, EMOD_FMRI_NVL);
		return (NULL);
	}

	return (fmri);
}

static tnode_t *
mem_tnode_create(topo_mod_t *mod, tnode_t *parent,
    const char *name, topo_instance_t i, char *unum, char *serial, void *priv)
{
	nvlist_t *fmri;
	tnode_t *ntn;

	fmri = mem_fmri_create(mod, unum, serial);
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

	return (ntn);
}

/*ARGSUSED*/
static int
mem_create(topo_mod_t *mod, tnode_t *rnode, const char *name,
    md_mem_info_t *mem)
{
	int i;
	int nerr = 0;
	int ndimms = 0;
	mem_dimm_map_t *mp;
	tnode_t *cnode;

	topo_mod_dprintf(mod, "enumerating memory\n");

	/*
	 * Count the dimms and create a range.  The instance numbers
	 * are not meaningful in this context.
	 */
	for (mp = mem->mem_dm; mp != NULL; mp = mp->dm_next) {
		ndimms++;
	}
	if (ndimms == 0)
		return (-1);
	topo_node_range_destroy(rnode, name);
	if (topo_node_range_create(mod, rnode, name, 0, ndimms+1) < 0) {
		topo_mod_dprintf(mod, "failed to create dimm range[0,%d]: %s\n",
		    ndimms, topo_mod_errmsg(mod));
		return (-1);
	}

	/*
	 * Create the dimm nodes
	 */
	for (mp = mem->mem_dm, i = 0; mp != NULL; mp = mp->dm_next, i++) {
		cnode = mem_tnode_create(mod, rnode, name, (topo_instance_t)i,
		    mp->dm_label, mp->dm_serid, NULL);
		if (cnode == NULL) {
			topo_mod_dprintf(mod,
			    "failed to create dimm=%d node: %s\n",
			    i, topo_mod_errmsg(mod));
			nerr++;
		}
	}

	if (nerr != 0)
		(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);

	return (0);
}

/*ARGSUSED*/
static int
mem_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	topo_mod_dprintf(mod, "%s enumerating %s\n", PLATFORM_MEM_NAME, name);

	if (topo_method_register(mod, rnode, mem_methods) < 0) {
		topo_mod_dprintf(mod, "topo_method_register failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}

	if (strcmp(name, MEM_NODE_NAME) == 0)
		return (mem_create(mod, rnode, name, (md_mem_info_t *)arg));

	return (0);
}

/*ARGSUSED*/
static void
mem_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}
