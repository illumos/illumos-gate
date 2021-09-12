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


/*
 * av1394 configuration ROM
 */
#include <sys/file.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/1394/targets/av1394/av1394_impl.h>

/* configROM parsing */
static int	av1394_cfgrom_parse_rom(av1394_inst_t *);
static void	av1394_cfgrom_unparse_rom(av1394_inst_t *);
static int	av1394_cfgrom_parse_dir(av1394_inst_t *, cmd1394_cmd_t *,
		av1394_cfgrom_parse_arg_t *);
static void	av1394_cfgrom_add_text_leaf(av1394_inst_t *,
		av1394_cfgrom_parsed_dir_t *, uint64_t, uint32_t);
static int	av1394_cfgrom_read_leaf(av1394_inst_t *, uint64_t, mblk_t **);
static void	av1394_cfgrom_grow_parsed_dir(av1394_cfgrom_parsed_dir_t *,
		int);

/* routines involving bus transactions */
static int	av1394_cfgrom_rq(av1394_inst_t *, cmd1394_cmd_t *,
		uint64_t, uint32_t *);

/* the following macros emulate throwing an exception when read fails */
#define	AV1394_CFGROM_RQ(avp, cmd, addr, valp) \
	if ((ret = av1394_cfgrom_rq(avp, cmd, addr, valp)) != 0) { \
		goto catch; \
	}

int
av1394_cfgrom_init(av1394_inst_t *avp)
{
	av1394_cfgrom_t		*crp = &avp->av_a.a_cfgrom;
	ddi_iblock_cookie_t	ibc = avp->av_attachinfo.iblock_cookie;

	rw_init(&crp->cr_rwlock, NULL, RW_DRIVER, ibc);

	return (DDI_SUCCESS);
}

void
av1394_cfgrom_fini(av1394_inst_t *avp)
{
	av1394_cfgrom_t	*crp = &avp->av_a.a_cfgrom;

	rw_destroy(&crp->cr_rwlock);
}

void
av1394_cfgrom_close(av1394_inst_t *avp)
{
	av1394_cfgrom_t	*crp = &avp->av_a.a_cfgrom;

	rw_enter(&crp->cr_rwlock, RW_WRITER);
	if (crp->cr_parsed) {
		av1394_cfgrom_unparse_rom(avp);
	}
	rw_exit(&crp->cr_rwlock);
}

int
av1394_ioctl_node_get_bus_name(av1394_inst_t *avp, void *arg, int mode)
{
	cmd1394_cmd_t	*cmd;
	uint32_t	val;
	int		err;
	int		ret = 0;

	err = t1394_alloc_cmd(avp->av_t1394_hdl, 0, &cmd);
	if (err != DDI_SUCCESS) {
		return (ENOMEM);
	}

	ret = av1394_cfgrom_rq(avp, cmd, AV1394_CFGROM_BUS_NAME_ADDR, &val);
	if (ret == 0) {
		if (ddi_copyout(&val, arg, sizeof (uint32_t), mode) != 0) {
			ret = EFAULT;
		}
	}

	err = t1394_free_cmd(avp->av_t1394_hdl, 0, &cmd);
	ASSERT(err == DDI_SUCCESS);

	return (ret);
}

int
av1394_ioctl_node_get_uid(av1394_inst_t *avp, void *arg, int mode)
{
	cmd1394_cmd_t	*cmd;
	uint64_t	eui64;
	uint32_t	hi, lo;
	int		err;
	int		ret = 0;

	err = t1394_alloc_cmd(avp->av_t1394_hdl, 0, &cmd);
	if (err != DDI_SUCCESS) {
		return (ENOMEM);
	}

	AV1394_CFGROM_RQ(avp, cmd, AV1394_CFGROM_EUI64_HI_ADDR, &hi);
	AV1394_CFGROM_RQ(avp, cmd, AV1394_CFGROM_EUI64_LO_ADDR, &lo);

	eui64 = ((uint64_t)hi << 32) | lo;
	if (ddi_copyout(&eui64, arg, sizeof (uint64_t), mode) != 0) {
		ret = EFAULT;
	}

catch:
	err = t1394_free_cmd(avp->av_t1394_hdl, 0, &cmd);
	ASSERT(err == DDI_SUCCESS);

	return (ret);
}

int
av1394_ioctl_node_get_text_leaf(av1394_inst_t *avp, void *arg, int mode)
{
	av1394_cfgrom_t	*crp = &avp->av_a.a_cfgrom;
	iec61883_node_text_leaf_t tl;
#ifdef _MULTI_DATAMODEL
	iec61883_node_text_leaf32_t tl32;
#endif
	int		n;		/* text leaf number requested */
	int		parent;		/* leaf parent */
	mblk_t		*bp = NULL;
	av1394_cfgrom_parsed_dir_t *pd;
	int		leaf_len;
	uint32_t	spec, lang_id, desc_entry;
	int		ret = 0;

	/* copyin arguments */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		if (ddi_copyin(arg, &tl32, sizeof (tl32), mode) != 0) {
			return (EFAULT);
		}
		n = tl32.tl_num;
		parent = tl32.tl_parent;
	} else {
#endif
	if (ddi_copyin(arg, &tl, sizeof (tl), mode) != 0) {
		return (EFAULT);
	}
	n = tl.tl_num;
	parent = tl.tl_parent;
#ifdef _MULTI_DATAMODEL
	}
#endif
	/* verify arguments */
	if (((parent != IEC61883_ROM_ROOT) && (parent != IEC61883_ROM_UNIT)) ||
	    (n < 0)) {
		return (EINVAL);
	}

	/* parse ConfigROM if not already */
	rw_enter(&crp->cr_rwlock, RW_WRITER);
	if (!crp->cr_parsed) {
		ret = av1394_cfgrom_parse_rom(avp);
		if (ret != 0) {
			rw_exit(&crp->cr_rwlock);
			return (ret);
		}
	}
	rw_downgrade(&crp->cr_rwlock);

	/* get parsed leaf info */
	if (parent == IEC61883_ROM_ROOT) {
		pd = &crp->cr_root_dir;
	} else {
		pd = &crp->cr_unit_dir;
	}

	if (n < pd->pd_tl_next) {
		/* read the leaf */
		ret = av1394_cfgrom_read_leaf(avp, pd->pd_tl[n].tl_addr, &bp);
		if (ret != 0) {
			rw_exit(&crp->cr_rwlock);
			return (ret);
		}
		leaf_len = MBLKL(bp) / 4 - 2;
		ASSERT(leaf_len > 0);
		spec = *(uint32_t *)bp->b_rptr;
		bp->b_rptr += 4;
		lang_id = *(uint32_t *)bp->b_rptr;
		bp->b_rptr += 4;
		desc_entry = pd->pd_tl[n].tl_desc_entry;
	} else {
		/* return success anyway, but with tl_cnt < tl_num */
		spec = lang_id = desc_entry = 0;
		leaf_len = 0;
	}

	/* copyout the results */
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		tl32.tl_cnt = pd->pd_tl_next;
		tl32.tl_desc_entry = desc_entry;
		tl32.tl_rlen = leaf_len;
		tl32.tl_spec = spec;
		tl32.tl_lang_id = lang_id;
		if (ddi_copyout(&tl32, arg, sizeof (tl32), mode) != 0) {
			ret = EFAULT;
		} else if (bp && ddi_copyout(bp->b_rptr,
		    (void *)(uintptr_t)tl32.tl_data,
		    4 * min(tl32.tl_len, tl32.tl_rlen), mode) != 0) {
			ret = EFAULT;
		}
	} else {
#endif
	tl.tl_cnt = pd->pd_tl_next;
	tl.tl_desc_entry = desc_entry;
	tl.tl_rlen = leaf_len;
	tl.tl_spec = spec;
	tl.tl_lang_id = lang_id;
	if (ddi_copyout(&tl, arg, sizeof (tl), mode) != 0) {
		ret = EFAULT;
	} else if (bp && ddi_copyout(bp->b_rptr, tl.tl_data,
	    4 * min(tl.tl_len, tl.tl_rlen), mode) != 0) {
		ret = EFAULT;
	}
#ifdef _MULTI_DATAMODEL
	}
#endif
	rw_exit(&crp->cr_rwlock);

	freemsg(bp);

	return (ret);
}


/*
 *
 * --- configROM parsing
 *
 * Parse entire configROM. Only extract information that interests us.
 * ConfigROM integrity checks are only made to ensure correct parsing.
 */
static int
av1394_cfgrom_parse_rom(av1394_inst_t *avp)
{
	av1394_cfgrom_t	*crp = &avp->av_a.a_cfgrom;
	cmd1394_cmd_t	*cmd;
	uint32_t	val;
	uint64_t	root_addr;	/* root dir address */
	uint16_t	root_len;	/* root dir length */
	av1394_cfgrom_parse_arg_t pa;
	int		err;
	int		ret;

	ASSERT(crp->cr_parsed == B_FALSE);

	err = t1394_alloc_cmd(avp->av_t1394_hdl, 0, &cmd);
	if (err != DDI_SUCCESS) {
		return (ENOMEM);
	}

	/* skip info_len quadlets to get root dir address and length */
	AV1394_CFGROM_RQ(avp, cmd, AV1394_CFGROM_INFO_LEN_ADDR, &val);
	val = AV_SWAP32(val);
	root_addr = IEEE1394_CONFIG_ROM_ADDR + 4 + (val >> 24) * 4;
	AV1394_CFGROM_RQ(avp, cmd, root_addr, &val);
	val = AV_SWAP32(val);
	root_len = IEEE1212_DIR_LEN(val);

	/* parse root dir and everything underneath */
	pa.pa_depth = 0;
	pa.pa_desc_entry = 0;
	pa.pa_parent_k = 0;
	pa.pa_addr = root_addr + 4;
	pa.pa_len = root_len;
	pa.pa_dir = &crp->cr_root_dir;

	ret = av1394_cfgrom_parse_dir(avp, cmd, &pa);

catch:
	if (ret == 0) {
		crp->cr_parsed = B_TRUE;
	} else {
		av1394_cfgrom_unparse_rom(avp);
	}
	err = t1394_free_cmd(avp->av_t1394_hdl, 0, &cmd);
	ASSERT(err == DDI_SUCCESS);

	return (ret);
}

/*
 * parse a directory
 */
static int
av1394_cfgrom_parse_dir(av1394_inst_t *avp, cmd1394_cmd_t *cmd,
		av1394_cfgrom_parse_arg_t *pa)
{
	av1394_cfgrom_t	*crp = &avp->av_a.a_cfgrom;
	int		i;
	uint64_t	entry_addr;
	uint32_t	entry;
	uint64_t	leaf_addr;
	uint64_t	dir_addr;
	uint16_t	dir_len;
	uint8_t		t, k;
	uint16_t	v;
	uint32_t	val;
	av1394_cfgrom_parse_arg_t this_pa;
	int		ret = 0;

	/* safeguard against deep recursion */
	if (pa->pa_depth > AV1394_CFGROM_PARSE_MAX_DEPTH) {
		return (ENOMEM);
	}

	/* initialize parse arguments */
	this_pa.pa_depth = pa->pa_depth + 1;
	this_pa.pa_desc_entry = pa->pa_desc_entry;

	/* walk dir entries */
	entry_addr = pa->pa_addr;
	for (i = 0; i < pa->pa_len; i++) {
		AV1394_CFGROM_RQ(avp, cmd, entry_addr, &entry);
		entry = AV_SWAP32(entry);

		CFGROM_TYPE_KEY_VALUE(entry, t, k, v);
		if ((t == IEEE1212_LEAF_TYPE) &&
		    (k == IEEE1212_TEXTUAL_DESCRIPTOR)) {
			/* save this leaf */
			leaf_addr = entry_addr + 4 * v;
			av1394_cfgrom_add_text_leaf(avp, pa->pa_dir,
			    leaf_addr, this_pa.pa_desc_entry);
		} else if (t == IEEE1212_DIRECTORY_TYPE) {
			dir_addr = entry_addr + 4 * v;
			AV1394_CFGROM_RQ(avp, cmd, dir_addr, &val);
			val = AV_SWAP32(val);
			dir_len = IEEE1212_DIR_LEN(val);

			/* parse this dir */
			this_pa.pa_parent_k = k;
			this_pa.pa_addr = dir_addr + 4;
			this_pa.pa_len = dir_len;
			/* leaves will be added to either root or unit array */
			if (k == IEEE1212_UNIT_DIRECTORY) {
				this_pa.pa_dir = &crp->cr_unit_dir;
			} else {
				this_pa.pa_dir = pa->pa_dir;
			}

			ret = av1394_cfgrom_parse_dir(avp, cmd, &this_pa);
			if (ret != 0) {
				goto catch;
			}
		}

		/*
		 * if we're walking Textual_Descriptor directory,
		 * the described entry is the one preceding directory's entry,
		 * so we need to preserve what was passed in pa->pa_desc_entry
		 */
		if (pa->pa_parent_k != IEEE1212_TEXTUAL_DESCRIPTOR) {
			this_pa.pa_desc_entry = entry;
		}
		entry_addr += 4;
	}

catch:
	return (ret);
}

/*ARGSUSED*/
static void
av1394_cfgrom_add_text_leaf(av1394_inst_t *avp, av1394_cfgrom_parsed_dir_t *pd,
		uint64_t addr, uint32_t desc_entry)
{
	/* grow array of needed */
	if (pd->pd_tl_next >= pd->pd_tl_size) {
		av1394_cfgrom_grow_parsed_dir(pd, 2);
	}
	pd->pd_tl[pd->pd_tl_next].tl_addr = addr;
	pd->pd_tl[pd->pd_tl_next].tl_desc_entry = desc_entry;
	pd->pd_tl_next++;
}

/*
 * this routine cleans up after av1394_cfgrom_parse()
 */
static void
av1394_cfgrom_unparse_rom(av1394_inst_t *avp)
{
	av1394_cfgrom_t	*crp = &avp->av_a.a_cfgrom;
	av1394_cfgrom_parsed_dir_t *pd;

	pd = &crp->cr_root_dir;
	if (pd->pd_tl) {
		kmem_free(pd->pd_tl, pd->pd_tl_size * sizeof (*pd->pd_tl));
		bzero(pd, sizeof (*pd));
	}
	pd = &crp->cr_unit_dir;
	if (pd->pd_tl) {
		kmem_free(pd->pd_tl, pd->pd_tl_size * sizeof (*pd->pd_tl));
		bzero(pd, sizeof (*pd));
	}
	crp->cr_parsed = B_FALSE;
}

/*
 * grow parsed dir leaf array by 'cnt' entries
 */
static void
av1394_cfgrom_grow_parsed_dir(av1394_cfgrom_parsed_dir_t *pd, int cnt)
{
	int	new_size;
	void	*new_tl;

	ASSERT(cnt > 0);

	new_size = (pd->pd_tl_size + cnt) * sizeof (av1394_cfgrom_text_leaf_t);
	new_tl = kmem_zalloc(new_size, KM_SLEEP);
	if (pd->pd_tl_size > 0) {
		bcopy(pd->pd_tl, new_tl, pd->pd_tl_size * sizeof (*pd->pd_tl));
		kmem_free(pd->pd_tl, pd->pd_tl_size * sizeof (*pd->pd_tl));
	}
	pd->pd_tl = new_tl;
	pd->pd_tl_size += cnt;
}

static int
av1394_cfgrom_read_leaf(av1394_inst_t *avp, uint64_t leaf_addr, mblk_t **bpp)
{
	cmd1394_cmd_t	*cmd;
	uint64_t	addr;
	uint32_t	val;
	int		leaf_len;	/* leaf length in quadlets */
	mblk_t		*bp = NULL;
	int		i;
	int		err;
	int		ret = 0;

	err = t1394_alloc_cmd(avp->av_t1394_hdl, 0, &cmd);
	if (err != DDI_SUCCESS) {
		return (ENOMEM);
	}

	/* read leaf length */
	AV1394_CFGROM_RQ(avp, cmd, leaf_addr, &val);
	val = AV_SWAP32(val);
	leaf_len = IEEE1212_DIR_LEN(val);

	if (leaf_len < 3) {
		ret = EIO;
		goto catch;
	}

	if ((bp = allocb(leaf_len * 4, BPRI_HI)) == NULL) {
		return (ENOMEM);
	}

	/* read leaf value */
	addr = leaf_addr + 4;
	for (i = 0; i < leaf_len; i++) {
		AV1394_CFGROM_RQ(avp, cmd, addr, (uint32_t *)bp->b_wptr);
		bp->b_wptr += 4;
		addr += 4;
	}

catch:
	if (ret == 0) {
		*bpp = bp;
	} else {
		freemsg(bp);
	}
	err = t1394_free_cmd(avp->av_t1394_hdl, 0, &cmd);
	ASSERT(err == DDI_SUCCESS);

	return (ret);
}

/*
 *
 * --- routines involving bus transactions
 *
 */
static int
av1394_cfgrom_rq(av1394_inst_t *avp, cmd1394_cmd_t *cmd, uint64_t addr,
		uint32_t *rval)
{
	int	err;

	cmd->cmd_type = CMD1394_ASYNCH_RD_QUAD;
	cmd->cmd_options = CMD1394_BLOCKING;
	cmd->cmd_addr = addr;

	err = t1394_read(avp->av_t1394_hdl, cmd);
	if ((err == DDI_SUCCESS) && (cmd->cmd_result == CMD1394_CMDSUCCESS)) {
		*rval = cmd->cmd_u.q.quadlet_data;
		return (0);
	} else {
		return (EIO);
	}
}
