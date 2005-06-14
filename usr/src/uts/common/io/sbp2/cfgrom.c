/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SBP2 config ROM routines
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/1394/ieee1212.h>
#include <sys/sbp2/impl.h>

static int	sbp2_cfgrom_rq(sbp2_tgt_t *, void *, uint64_t, uint32_t *);
static int	sbp2_cfgrom_parse_dir(sbp2_tgt_t *, void *,
		sbp2_cfgrom_parse_arg_t *);
static int	sbp2_cfgrom_read_leaf(sbp2_tgt_t *, void *,
		sbp2_cfgrom_ent_t *);
static int	sbp2_cfgrom_read_bib(sbp2_tgt_t *, void *, sbp2_cfgrom_bib_t *);
static void	sbp2_cfgrom_free_bib(sbp2_tgt_t *, sbp2_cfgrom_bib_t *);
static void	sbp2_cfgrom_dir_grow(sbp2_cfgrom_dir_t *, int);
static sbp2_cfgrom_ent_t *sbp2_cfgrom_dir_new_ent(sbp2_cfgrom_dir_t *);
static int	sbp2_cfgrom_walk_impl(sbp2_cfgrom_ent_t *,
		int (*)(void *, sbp2_cfgrom_ent_t *, int), void *, int);
static int	sbp2_cfgrom_ent_by_key_walker(void *, sbp2_cfgrom_ent_t *,
		int);
static void	sbp2_cfgrom_walk_free(sbp2_cfgrom_ent_t *);

static hrtime_t sbp2_cfgrom_read_delay = 20 * 1000000;	/* in ns */

/* imitate throwing an exception when read fails */
#define	SBP2_CFGROM_RQ(tp, cmd, addr, q) \
	if ((ret = sbp2_cfgrom_rq(tp, cmd, addr, q)) != 0) { \
		goto rq_error; \
	}

static int
sbp2_cfgrom_rq(sbp2_tgt_t *tp, void *cmd, uint64_t addr, uint32_t *q)
{
	hrtime_t	tm;	/* time since last read */
	int		berr;
	int		ret;

	tm = gethrtime() - tp->t_last_cfgrd;
	if (tm < sbp2_cfgrom_read_delay) {
		delay(drv_usectohz((sbp2_cfgrom_read_delay - tm) / 1000));
	}
	ret = SBP2_RQ(tp, cmd, addr, q, &berr);
	*q = SBP2_SWAP32(*q);
	tp->t_last_cfgrd = gethrtime();
	return (ret);
}

int
sbp2_cfgrom_parse(sbp2_tgt_t *tp, sbp2_cfgrom_t *crp)
{
	sbp2_cfgrom_ent_t *root_dir = &crp->cr_root;
	sbp2_cfgrom_bib_t *bib = &crp->cr_bib;
	void		*cmd;
	int		ret;
	sbp2_cfgrom_parse_arg_t pa;

	if ((ret = SBP2_ALLOC_CMD(tp, &cmd, 0)) != SBP2_SUCCESS) {
		return (ret);
	}

	if ((ret = sbp2_cfgrom_read_bib(tp, cmd, bib)) != SBP2_SUCCESS) {
		SBP2_FREE_CMD(tp, cmd);
		return (ret);
	}

	/* parse root directory and everything underneath */
	bzero(root_dir, sizeof (sbp2_cfgrom_ent_t));
	root_dir->ce_kt = IEEE1212_DIRECTORY_TYPE;
	root_dir->ce_offset = SBP2_CFGROM_ADDR(tp) + 4 + bib->cb_len * 4;
	pa.pa_dir = root_dir;
	pa.pa_pdir = NULL;
	pa.pa_ref = NULL;
	pa.pa_depth = 0;

	if ((ret = sbp2_cfgrom_parse_dir(tp, cmd, &pa)) != SBP2_SUCCESS) {
		sbp2_cfgrom_free(tp, crp);
	}

	SBP2_FREE_CMD(tp, cmd);
	return (ret);
}


/*
 * Caller must initialize pa and pa->pa_dir.
 */
static int
sbp2_cfgrom_parse_dir(sbp2_tgt_t *tp, void *cmd, sbp2_cfgrom_parse_arg_t *pa)
{
	sbp2_cfgrom_ent_t	*dir = pa->pa_dir; /* directory being parsed */
	sbp2_cfgrom_ent_t	*cep;		/* current entry structure */
	sbp2_cfgrom_ent_t	*pcep = NULL;	/* previous entry structure */
	sbp2_cfgrom_parse_arg_t	this_pa;	/* parse args */
	uint64_t		addr;		/* current address */
	uint32_t		entry;		/* current entry */
	uint8_t			t, k;		/* key type and value */
	uint32_t		v;		/* entry value */
	int			i;
	int			ret = 0;

	this_pa.pa_pdir = dir;
	this_pa.pa_ref = pa->pa_ref;
	this_pa.pa_depth = pa->pa_depth + 1;

	/* read directory entry and initialize the structure */
	SBP2_CFGROM_RQ(tp, cmd, dir->ce_offset, &entry);
	dir->ce_len = IEEE1212_DIR_LEN(entry);
	sbp2_cfgrom_dir_grow(&dir->ce_data.dir, dir->ce_len);

	/* walk directory entries */
	addr = dir->ce_offset + 4;
	for (i = 0; i < dir->ce_len; i++, addr += 4) {
		SBP2_CFGROM_RQ(tp, cmd, addr, &entry);
		CFGROM_TYPE_KEY_VALUE(entry, t, k, v);

		cep = sbp2_cfgrom_dir_new_ent(&dir->ce_data.dir);
		cep->ce_kt = t;
		cep->ce_kv = k;
		switch (t) {
		case IEEE1212_IMMEDIATE_TYPE:
			cep->ce_len = 1;
			cep->ce_offset = addr;
			cep->ce_data.imm = v;
			break;
		case IEEE1212_CSR_OFFSET_TYPE:
			cep->ce_len = 1;
			cep->ce_offset = addr;
			cep->ce_data.offset = v;
			break;
		case IEEE1212_LEAF_TYPE:
			cep->ce_offset = addr + 4 * v;
			if (dir->ce_kv != IEEE1212_TEXTUAL_DESCRIPTOR) {
				/* text leaf describes preceding entry */
				cep->ce_ref = pcep;
			} else {
				/* text directory describes preceding entry */
				cep->ce_ref = this_pa.pa_ref;
			}
			ret = sbp2_cfgrom_read_leaf(tp, cmd, cep);
			break;
		case IEEE1212_DIRECTORY_TYPE:
			cep->ce_offset = addr + 4 * v;
			this_pa.pa_dir = cep;
			this_pa.pa_ref = pcep;
			if (this_pa.pa_depth < SBP2_CFGROM_MAX_DEPTH) {
				ret = sbp2_cfgrom_parse_dir(tp, cmd, &this_pa);
			}
			break;
		default:
			ASSERT(0);
		}
		pcep = cep;
	}

rq_error:
	return (ret);
}


static int
sbp2_cfgrom_read_leaf(sbp2_tgt_t *tp, void *cmd, sbp2_cfgrom_ent_t *cep)
{
	uint32_t	val;
	int		ret;
	int		i;
	uint64_t	addr = cep->ce_offset;

	/* header */
	SBP2_CFGROM_RQ(tp, cmd, addr, &val);
	addr += 4;

	/* verify data length */
	cep->ce_len = (val >> 16);
	if (cep->ce_len < 1) {
		return (SBP2_EDATA);
	}
	cep->ce_data.leaf = kmem_zalloc(cep->ce_len * 4, KM_SLEEP);

	/* data */
	for (i = 0; i < cep->ce_len; i++, addr += 4) {
		SBP2_CFGROM_RQ(tp, cmd, addr, &cep->ce_data.leaf[i]);
	}

	return (ret);

rq_error:
	if (cep->ce_data.leaf) {
		kmem_free(cep->ce_data.leaf, cep->ce_len * 4);
	}
	return (ret);
}


static int
sbp2_cfgrom_read_bib(sbp2_tgt_t *tp, void *cmd, sbp2_cfgrom_bib_t *cbp)
{
	uint32_t	val;
	int		ret;
	int		i;
	uint64_t	addr = SBP2_CFGROM_ADDR(tp);

	/* header */
	SBP2_CFGROM_RQ(tp, cmd, addr, &val);
	addr += 4;

	/* verify data length */
	cbp->cb_len = (val >> 24);
	if (cbp->cb_len < 1) {
		return (SBP2_EDATA);
	}
	cbp->cb_buf = kmem_zalloc(cbp->cb_len * 4, KM_SLEEP);

	/* data */
	for (i = 0; i < cbp->cb_len; i++, addr += 4) {
		SBP2_CFGROM_RQ(tp, cmd, addr, &cbp->cb_buf[i]);
	}

rq_error:
	sbp2_cfgrom_free_bib(tp, cbp);
	return (ret);
}


/*ARGSUSED*/
static void
sbp2_cfgrom_free_bib(sbp2_tgt_t *tp, sbp2_cfgrom_bib_t *cbp)
{
	if ((cbp->cb_buf != NULL) && (cbp->cb_len > 0)) {
		kmem_free(cbp->cb_buf, cbp->cb_len * 4);
		cbp->cb_buf = NULL;
	}
}

static void
sbp2_cfgrom_dir_grow(sbp2_cfgrom_dir_t *dir, int incr)
{
	int	new_size, old_size;
	void	*new_ent;

	ASSERT(incr > 0);

	new_size = (dir->cd_size + incr) * sizeof (sbp2_cfgrom_ent_t);
	new_ent = kmem_zalloc(new_size, KM_SLEEP);
	if (dir->cd_size > 0) {
		old_size = dir->cd_size * sizeof (sbp2_cfgrom_ent_t);
		bcopy(dir->cd_ent, new_ent, old_size);
		kmem_free(dir->cd_ent, old_size);
	}
	dir->cd_ent = new_ent;
	dir->cd_size += incr;
}

static sbp2_cfgrom_ent_t *
sbp2_cfgrom_dir_new_ent(sbp2_cfgrom_dir_t *dir)
{
	/* grow if out of entries */
	if (dir->cd_cnt >= dir->cd_size) {
		ASSERT(dir->cd_cnt == dir->cd_size);
		sbp2_cfgrom_dir_grow(dir, SBP2_CFGROM_GROW_INCR);
	}

	return (&dir->cd_ent[dir->cd_cnt++]);
}

/*
 * walk Config ROM entries calling the specified function for each
 */
void
sbp2_cfgrom_walk(sbp2_cfgrom_ent_t *dir,
    int (*func)(void *, sbp2_cfgrom_ent_t *, int), void *arg)
{
	ASSERT(dir->ce_kt == IEEE1212_DIRECTORY_TYPE);
	(void) sbp2_cfgrom_walk_impl(dir, func, arg, 0);
}

static int
sbp2_cfgrom_walk_impl(sbp2_cfgrom_ent_t *dir,
    int (*func)(void *, sbp2_cfgrom_ent_t *, int), void *arg, int level)
{
	int		i;
	sbp2_cfgrom_ent_t *ent;

	for (i = 0; i < dir->ce_data.dir.cd_cnt; i++) {
		ent = &dir->ce_data.dir.cd_ent[i];
		if (func(arg, ent, level) == SBP2_WALK_STOP) {
			return (SBP2_WALK_STOP);
		}
		if (ent->ce_kt == IEEE1212_DIRECTORY_TYPE) {
			if (sbp2_cfgrom_walk_impl(ent, func, arg, level + 1) ==
			    SBP2_WALK_STOP) {
				return (SBP2_WALK_STOP);
			}
		}
	}
	return (SBP2_WALK_CONTINUE);
}


sbp2_cfgrom_ent_t *
sbp2_cfgrom_ent_by_key(sbp2_cfgrom_ent_t *dir, int8_t kt, int8_t kv, int num)
{
	sbp2_cfgrom_ent_by_key_t ebk;

	ebk.kt = kt;
	ebk.kv = kv;
	ebk.num = num;
	ebk.ent = NULL;
	ebk.cnt = 0;
	sbp2_cfgrom_walk(dir, sbp2_cfgrom_ent_by_key_walker, &ebk);

	return (ebk.ent);
}

/*ARGSUSED*/
static int
sbp2_cfgrom_ent_by_key_walker(void *arg, sbp2_cfgrom_ent_t *ent, int level)
{
	sbp2_cfgrom_ent_by_key_t *ebk = arg;

	if ((ent->ce_kt == ebk->kt) && (ent->ce_kv == ebk->kv)) {
		if (ebk->cnt == ebk->num) {
			ebk->ent = ent;
			return (SBP2_WALK_STOP);
		}
		ebk->cnt++;
	}
	return (SBP2_WALK_CONTINUE);
}


void
sbp2_cfgrom_free(sbp2_tgt_t *tp, sbp2_cfgrom_t *crp)
{
	sbp2_cfgrom_free_bib(tp, &crp->cr_bib);
	sbp2_cfgrom_walk_free(&crp->cr_root);
}

static void
sbp2_cfgrom_walk_free(sbp2_cfgrom_ent_t *dir)
{
	int		i;
	sbp2_cfgrom_dir_t *cdp = &dir->ce_data.dir;
	sbp2_cfgrom_ent_t *ent = cdp->cd_ent;

	for (i = 0; i < cdp->cd_cnt; i++) {
		if (ent[i].ce_kt == IEEE1212_DIRECTORY_TYPE) {
			sbp2_cfgrom_walk_free(&ent[i]);
		} else if ((ent[i].ce_kt == IEEE1212_LEAF_TYPE) &&
		    (ent[i].ce_data.leaf != NULL)) {
			kmem_free(ent[i].ce_data.leaf, ent[i].ce_len * 4);
		}
	}
	if (ent) {
		kmem_free(ent, cdp->cd_size * sizeof (sbp2_cfgrom_ent_t));
	}
}
