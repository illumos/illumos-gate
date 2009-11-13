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
 * memory management for serengeti dr memory
 */

#include <sys/obpdefs.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/cpuvar.h>
#include <sys/memlist_impl.h>
#include <sys/machsystm.h>
#include <sys/promif.h>
#include <sys/mem_cage.h>
#include <sys/kmem.h>
#include <sys/note.h>
#include <sys/lgrp.h>

#include <sys/sbd_ioctl.h>
#include <sys/sbd.h>
#include <sys/sbdp_priv.h>
#include <sys/sbdp_mem.h>
#include <sys/sun4asi.h>
#include <sys/cheetahregs.h>
#include <sys/cpu_module.h>
#include <sys/esunddi.h>

#include <vm/page.h>

static int	sbdp_get_meminfo(pnode_t, int, uint64_t *, uint64_t *);
int		mc_read_regs(pnode_t, mc_regs_t *);
uint64_t	mc_get_addr(pnode_t, int, uint_t *);
static pnode_t	mc_get_sibling_cpu(pnode_t nodeid);
static int	mc_get_sibling_cpu_impl(pnode_t nodeid);
static sbd_cond_t mc_check_sibling_cpu(pnode_t nodeid);
static void	_sbdp_copy_rename_end(void);
static int	sbdp_copy_rename__relocatable(sbdp_cr_handle_t *,
			struct memlist *, sbdp_rename_script_t *);
static int	sbdp_prep_rename_script(sbdp_cr_handle_t *);
static int	sbdp_get_lowest_addr_in_node(pnode_t, uint64_t *);

extern void bcopy32_il(uint64_t, uint64_t);
extern void flush_ecache_il(uint64_t physaddr, size_t size, size_t linesize);
extern uint64_t lddphys_il(uint64_t physaddr);
extern uint64_t ldxasi_il(uint64_t physaddr, uint_t asi);
extern void sbdp_exec_script_il(sbdp_rename_script_t *rsp);
void sbdp_fill_bank_info(uint64_t, sbdp_bank_t **);
int sbdp_add_nodes_banks(pnode_t node, sbdp_bank_t **banks);
void sbdp_add_bank_to_seg(sbdp_bank_t *);
void sbdp_remove_bank_from_seg(sbdp_bank_t *);
uint64_t sbdp_determine_slice(sbdp_handle_t *);
sbdp_seg_t *sbdp_get_seg(uint64_t);
#ifdef DEBUG
void sbdp_print_seg(sbdp_seg_t *);
#endif

/*
 * Head to the system segments link list
 */
sbdp_seg_t *sys_seg = NULL;

uint64_t
sbdp_determine_slice(sbdp_handle_t *hp)
{
	int size;

	size = sbdp_get_mem_size(hp);

	if (size <= SG_SLICE_16G_SIZE) {
		return (SG_SLICE_16G_SIZE);
	} else if (size <= SG_SLICE_32G_SIZE) {
		return (SG_SLICE_32G_SIZE);
	} else {
		return (SG_SLICE_64G_SIZE);
	}
}

/* ARGSUSED */
int
sbdp_get_mem_alignment(sbdp_handle_t *hp, dev_info_t *dip, uint64_t *align)
{
	*align = sbdp_determine_slice(hp);
	return (0);
}


void
sbdp_memlist_dump(struct memlist *mlist)
{
	register struct memlist *ml;

	if (mlist == NULL) {
		SBDP_DBG_MEM("memlist> EMPTY\n");
	} else {
		for (ml = mlist; ml; ml = ml->next)
			SBDP_DBG_MEM("memlist>  0x%" PRIx64", 0x%" PRIx64"\n",
			    ml->address, ml->size);
	}
}

struct mem_arg {
	int	board;
	int	ndips;
	dev_info_t **list;
};

/*
 * Returns mem dip held
 */
static int
sbdp_get_mem_dip(pnode_t node, void *arg, uint_t flags)
{
	_NOTE(ARGUNUSED(flags))

	dev_info_t *dip;
	pnode_t nodeid;
	mem_op_t mem = {0};
	struct mem_arg *ap = arg;

	if (node == OBP_BADNODE || node == OBP_NONODE)
		return (DDI_FAILURE);

	mem.nodes = &nodeid;
	mem.board = ap->board;
	mem.nmem = 0;

	(void) sbdp_is_mem(node, &mem);

	ASSERT(mem.nmem == 0 || mem.nmem == 1);

	if (mem.nmem == 0 || nodeid != node)
		return (DDI_FAILURE);

	dip = e_ddi_nodeid_to_dip(nodeid);
	if (dip) {
		ASSERT(ap->ndips < SBDP_MAX_MEM_NODES_PER_BOARD);
		ap->list[ap->ndips++] = dip;
	}
	return (DDI_SUCCESS);
}

struct memlist *
sbdp_get_memlist(sbdp_handle_t *hp, dev_info_t *dip)
{
	_NOTE(ARGUNUSED(dip))

	int i, j, skip = 0;
	dev_info_t	*list[SBDP_MAX_MEM_NODES_PER_BOARD];
	struct mem_arg	arg = {0};
	uint64_t	base_pa, size;
	struct memlist	*mlist = NULL;

	list[0] = NULL;
	arg.board = hp->h_board;
	arg.list = list;

	sbdp_walk_prom_tree(prom_rootnode(), sbdp_get_mem_dip, &arg);

	for (i = 0; i < arg.ndips; i++) {
		if (list[i] == NULL)
			continue;

		size = 0;
		for (j = 0; j < SBDP_MAX_MCS_PER_NODE; j++) {
			if (sbdp_get_meminfo(ddi_get_nodeid(list[i]), j,
			    &size, &base_pa)) {
				skip++;
				continue;
			}
			if (size == -1 || size == 0)
				continue;

			(void) memlist_add_span(base_pa, size, &mlist);
		}

		/*
		 * Release hold acquired in sbdp_get_mem_dip()
		 */
		ddi_release_devi(list[i]);
	}

	/*
	 * XXX - The following two lines are from existing code.
	 * However, this appears to be incorrect - this check should be
	 * made for each dip in list i.e within the for(i) loop.
	 */
	if (skip == SBDP_MAX_MCS_PER_NODE)
		sbdp_set_err(hp->h_err, ESGT_INTERNAL, NULL);

	SBDP_DBG_MEM("memlist for board %d\n", hp->h_board);
	sbdp_memlist_dump(mlist);
	return (mlist);
}

struct memlist *
sbdp_memlist_dup(struct memlist *mlist)
{
	struct memlist *hl, *prev;

	if (mlist == NULL)
		return (NULL);

	prev = NULL;
	hl = NULL;
	for (; mlist; mlist = mlist->next) {
		struct memlist *mp;

		mp = memlist_get_one();
		if (mp == NULL) {
			if (hl != NULL)
				memlist_free_list(hl);
			hl = NULL;
			break;
		}
		mp->address = mlist->address;
		mp->size = mlist->size;
		mp->next = NULL;
		mp->prev = prev;

		if (prev == NULL)
			hl = mp;
		else
			prev->next = mp;
		prev = mp;
	}

	return (hl);
}

int
sbdp_del_memlist(sbdp_handle_t *hp, struct memlist *mlist)
{
	_NOTE(ARGUNUSED(hp))

	memlist_free_list(mlist);

	return (0);
}

/*ARGSUSED*/
static void
sbdp_flush_ecache(uint64_t a, uint64_t b)
{
	cpu_flush_ecache();
}

typedef enum {
	SBDP_CR_OK,
	SBDP_CR_MC_IDLE_ERR
} sbdp_cr_err_t;

int
sbdp_move_memory(sbdp_handle_t *hp, int t_bd)
{
	sbdp_bd_t	*s_bdp, *t_bdp;
	int		err = 0;
	caddr_t		mempage;
	ulong_t		data_area, index_area;
	ulong_t		e_area, e_page;
	int		availlen, indexlen, funclen, scriptlen;
	int		*indexp;
	time_t		copytime;
	int		(*funcp)();
	size_t		size;
	struct memlist	*mlist;
	sbdp_sr_handle_t	*srhp;
	sbdp_rename_script_t	*rsp;
	sbdp_rename_script_t	*rsbuffer;
	sbdp_cr_handle_t	*cph;
	int		linesize;
	uint64_t	neer;
	sbdp_cr_err_t	cr_err;

	cph =  kmem_zalloc(sizeof (sbdp_cr_handle_t), KM_SLEEP);

	SBDP_DBG_MEM("moving memory from memory board %d to board %d\n",
	    hp->h_board, t_bd);

	s_bdp = sbdp_get_bd_info(hp->h_wnode, hp->h_board);
	t_bdp = sbdp_get_bd_info(hp->h_wnode, t_bd);

	if ((s_bdp == NULL) || (t_bdp == NULL)) {
		sbdp_set_err(hp->h_err, ESGT_INTERNAL, NULL);
		return (-1);
	}

	funclen = (int)((ulong_t)_sbdp_copy_rename_end -
	    (ulong_t)sbdp_copy_rename__relocatable);

	if (funclen > PAGESIZE) {
		cmn_err(CE_WARN,
		    "sbdp: copy-rename funclen (%d) > PAGESIZE (%d)",
		    funclen, PAGESIZE);
		sbdp_set_err(hp->h_err, ESGT_INTERNAL, NULL);
		return (-1);
	}

	/*
	 * mempage will be page aligned, since we're calling
	 * kmem_alloc() with an exact multiple of PAGESIZE.
	 */
	mempage = kmem_alloc(PAGESIZE, KM_SLEEP);

	SBDP_DBG_MEM("mempage = 0x%p\n", mempage);

	/*
	 * Copy the code for the copy-rename routine into
	 * a page aligned piece of memory.  We do this to guarantee
	 * that we're executing within the same page and thus reduce
	 * the possibility of cache collisions between different
	 * pages.
	 */
	bcopy((caddr_t)sbdp_copy_rename__relocatable, mempage, funclen);

	funcp = (int (*)())mempage;

	SBDP_DBG_MEM("copy-rename funcp = 0x%p (len = 0x%x)\n", funcp, funclen);

	/*
	 * Prepare data page that will contain script of
	 * operations to perform during copy-rename.
	 * Allocate temporary buffer to hold script.
	 */

	size = sizeof (sbdp_rename_script_t) * SBDP_RENAME_MAXOP;
	rsbuffer = kmem_zalloc(size, KM_SLEEP);

	cph->s_bdp = s_bdp;
	cph->t_bdp = t_bdp;
	cph->script = rsbuffer;

	/*
	 * We need to make sure we don't switch cpus since we depend on the
	 * correct cpu processing
	 */
	affinity_set(CPU_CURRENT);
	scriptlen = sbdp_prep_rename_script(cph);
	if (scriptlen <= 0) {
		cmn_err(CE_WARN, "sbdp failed to prep for copy-rename");
		sbdp_set_err(hp->h_err, ESGT_INTERNAL, NULL);
		err = 1;
		goto cleanup;
	}
	SBDP_DBG_MEM("copy-rename script length = 0x%x\n", scriptlen);

	indexlen = sizeof (*indexp) << 1;

	if ((funclen + scriptlen + indexlen) > PAGESIZE) {
		cmn_err(CE_WARN, "sbdp: func len (%d) + script len (%d) "
		    "+ index len (%d) > PAGESIZE (%d)", funclen, scriptlen,
		    indexlen, PAGESIZE);
		sbdp_set_err(hp->h_err, ESGT_INTERNAL, NULL);
		err = 1;
		goto cleanup;
	}

	linesize = cpunodes[CPU->cpu_id].ecache_linesize;

	/*
	 * Find aligned area within data page to maintain script.
	 */
	data_area = (ulong_t)mempage;
	data_area += (ulong_t)funclen + (ulong_t)(linesize - 1);
	data_area &= ~((ulong_t)(linesize - 1));

	availlen = PAGESIZE - indexlen;
	availlen -= (int)(data_area - (ulong_t)mempage);

	if (availlen < scriptlen) {
		cmn_err(CE_WARN, "sbdp: available len (%d) < script len (%d)",
		    availlen, scriptlen);
		sbdp_set_err(hp->h_err, ESGT_INTERNAL, NULL);
		err = 1;
		goto cleanup;
	}

	SBDP_DBG_MEM("copy-rename script data area = 0x%lx\n",
	    data_area);

	bcopy((caddr_t)rsbuffer, (caddr_t)data_area, scriptlen);
	rsp = (sbdp_rename_script_t *)data_area;

	index_area = data_area + (ulong_t)scriptlen + (ulong_t)(linesize - 1);
	index_area &= ~((ulong_t)(linesize - 1));
	indexp = (int *)index_area;
	indexp[0] = 0;
	indexp[1] = 0;

	e_area = index_area + (ulong_t)indexlen;
	e_page = (ulong_t)mempage + PAGESIZE;
	if (e_area > e_page) {
		cmn_err(CE_WARN,
		    "sbdp: index area size (%d) > available (%d)\n",
		    indexlen, (int)(e_page - index_area));
		sbdp_set_err(hp->h_err, ESGT_INTERNAL, NULL);
		err = 1;
		goto cleanup;
	}

	SBDP_DBG_MEM("copy-rename index area = 0x%p\n", indexp);

	SBDP_DBG_MEM("cpu %d\n", CPU->cpu_id);

	srhp = sbdp_get_sr_handle();
	ASSERT(srhp);

	srhp->sr_flags = hp->h_flags;

	copytime = ddi_get_lbolt();

	mutex_enter(&s_bdp->bd_mutex);
	mlist = sbdp_memlist_dup(s_bdp->ml);
	mutex_exit(&s_bdp->bd_mutex);

	if (mlist == NULL) {
		SBDP_DBG_MEM("Didn't find memory list\n");
	}
	SBDP_DBG_MEM("src\n\tbd\t%d\n\tnode\t%d\n\tbpa 0x%lx\n\tnodes\t%p\n",
	    s_bdp->bd, s_bdp->wnode, s_bdp->bpa, s_bdp->nodes);
	sbdp_memlist_dump(s_bdp->ml);
	SBDP_DBG_MEM("tgt\n\tbd\t%d\n\tnode\t%d\n\tbpa 0x%lx\n\tnodes\t%p\n",
	    t_bdp->bd, t_bdp->wnode, t_bdp->bpa, t_bdp->nodes);
	sbdp_memlist_dump(t_bdp->ml);

	/*
	 * Quiesce the OS.
	 */
	if (sbdp_suspend(srhp)) {
		sbd_error_t	*sep;
		cmn_err(CE_WARN, "sbdp: failed to quiesce OS for copy-rename");
		sep = &srhp->sep;
		sbdp_set_err(hp->h_err, sep->e_code, sep->e_rsc);
		sbdp_release_sr_handle(srhp);
		sbdp_del_memlist(hp, mlist);
		err = 1;
		goto cleanup;
	}

	/*
	 * =================================
	 * COPY-RENAME BEGIN.
	 * =================================
	 */
	SBDP_DBG_MEM("s_base 0x%lx t_base 0x%lx\n", cph->s_bdp->bpa,
	    cph->t_bdp->bpa);

	cph->ret = 0;

	SBDP_DBG_MEM("cph return 0x%lx\n", cph->ret);

	SBDP_DBG_MEM("Flushing all of the cpu caches\n");
	xc_all(sbdp_flush_ecache, 0, 0);

	/* disable CE reporting */
	neer = get_error_enable();
	set_error_enable(neer & ~EN_REG_CEEN);

	cr_err = (*funcp)(cph, mlist, rsp);

	/* enable CE reporting */
	set_error_enable(neer);

	SBDP_DBG_MEM("s_base 0x%lx t_base 0x%lx\n", cph->s_bdp->bpa,
	    cph->t_bdp->bpa);
	SBDP_DBG_MEM("cph return 0x%lx\n", cph->ret);
	SBDP_DBG_MEM("after execking the function\n");

	/*
	 * =================================
	 * COPY-RENAME END.
	 * =================================
	 */
	SBDP_DBG_MEM("err is 0x%d\n", err);

	/*
	 * Resume the OS.
	 */
	sbdp_resume(srhp);
	if (srhp->sep.e_code) {
		sbd_error_t	*sep;
		cmn_err(CE_WARN,
		    "sbdp: failed to resume OS for copy-rename");
		sep = &srhp->sep;
		sbdp_set_err(hp->h_err, sep->e_code, sep->e_rsc);
		err = 1;
	}

	copytime = ddi_get_lbolt() - copytime;

	sbdp_release_sr_handle(srhp);
	sbdp_del_memlist(hp, mlist);

	SBDP_DBG_MEM("copy-rename elapsed time = %ld ticks (%ld secs)\n",
	    copytime, copytime / hz);

	switch (cr_err) {
	case SBDP_CR_OK:
		break;
	case SBDP_CR_MC_IDLE_ERR: {
		dev_info_t *dip;
		pnode_t nodeid = cph->busy_mc->node;
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		dip = e_ddi_nodeid_to_dip(nodeid);

		ASSERT(dip != NULL);

		(void) ddi_pathname(dip, path);
		ddi_release_devi(dip);
		cmn_err(CE_WARN, "failed to idle memory controller %s: "
		    "copy-rename aborted", path);
		kmem_free(path, MAXPATHLEN);
		sbdp_set_err(hp->h_err, ESBD_MEMFAIL, NULL);
		err = 1;
		break;
	}
	default:
		sbdp_set_err(hp->h_err, ESGT_INTERNAL, NULL);
		cmn_err(CE_WARN, "unknown copy-rename error code (%d)", cr_err);
		err = 1;
		break;
	}

	if (err)
		goto cleanup;

	/*
	 * Rename memory for lgroup.
	 * Source and target board numbers are packaged in arg.
	 */
	lgrp_plat_config(LGRP_CONFIG_MEM_RENAME,
	    (uintptr_t)(s_bdp->bd | (t_bdp->bd << 16)));

	/*
	 * swap list of banks
	 */
	sbdp_swap_list_of_banks(s_bdp, t_bdp);

	/*
	 * Update the cached board info for both the source and the target
	 */
	sbdp_update_bd_info(s_bdp);
	sbdp_update_bd_info(t_bdp);

	/*
	 * Tell the sc that we have swapped slices.
	 */
	if (sbdp_swap_slices(s_bdp->bd, t_bdp->bd) != 0) {
		/* This is dangerous. The in use slice could be re-used! */
		SBDP_DBG_MEM("swaping slices failed\n");
	}

cleanup:
	kmem_free(rsbuffer, size);
	kmem_free(mempage, PAGESIZE);
	kmem_free(cph, sizeof (sbdp_cr_handle_t));
	affinity_clear();

	return (err ? -1 : 0);
}

static int
sbdp_copy_regs(pnode_t node, uint64_t bpa, uint64_t new_base, int inval,
	sbdp_rename_script_t *rsp, int *index)
{
	int		i, m;
	mc_regs_t	regs;
	uint64_t	*mc_decode;

	if (mc_read_regs(node, &regs)) {
		SBDP_DBG_MEM("sbdp_copy_regs: failed to read source Decode "
		    "Regs");
		return (-1);
	}

	mc_decode = regs.mc_decode;

	m = *index;
	for (i = 0; i < SBDP_MAX_MCS_PER_NODE; i++) {
		uint64_t	offset, seg_pa, tmp_base;

		/*
		 * Skip invalid banks
		 */
		if ((mc_decode[i] & SG_DECODE_VALID) != SG_DECODE_VALID) {
			continue;
		}

		tmp_base = new_base;
		if (!inval) {
			/*
			 * We need to calculate the offset from the base pa
			 * to add it appropriately to the new_base.
			 * The offset needs to be in UM relative to the mc
			 * decode register.  Since we are going from physical
			 * address to UM, we need to shift it by PHYS2UM_SHIFT.
			 * To get it ready to OR it with the MC decode reg,
			 * we need to shift it left MC_UM_SHIFT
			 */
			seg_pa = MC_BASE(mc_decode[i]) << PHYS2UM_SHIFT;
			offset = (seg_pa - bpa);
			/* Convert tmp_base into a physical address */
			tmp_base = (tmp_base >> MC_UM_SHIFT) << PHYS2UM_SHIFT;
			tmp_base += offset;
			/* Convert tmp_base to be MC reg ready */
			tmp_base = (tmp_base >> PHYS2UM_SHIFT) << MC_UM_SHIFT;
		}

		mc_decode[i] &= ~SG_DECODE_UM;
		mc_decode[i] |= tmp_base;
		mc_decode[i] |= SG_DECODE_VALID;

		/*
		 * Step 1:	Write source base address to the MC
		 *		with present bit off.
		 */
		rsp[m].masr_addr = mc_get_addr(node, i, &rsp[m].asi);
		rsp[m].masr = mc_decode[i] & ~SG_DECODE_VALID;
		m++;
		/*
		 * Step 2:	Now rewrite the mc reg with present bit on.
		 */
		rsp[m].masr_addr = rsp[m-1].masr_addr;
		rsp[m].masr = mc_decode[i];
		rsp[m].asi = rsp[m-1].asi;
		m++;
	}

	*index = m;
	return (0);
}

static int
sbdp_get_reg_addr(pnode_t nodeid, uint64_t *pa)
{
	mc_regspace	reg;
	int		len;

	len = prom_getproplen(nodeid, "reg");
	if (len != sizeof (mc_regspace))
		return (-1);

	if (prom_getprop(nodeid, "reg", (caddr_t)&reg) < 0)
		return (-1);

	ASSERT(pa != NULL);

	*pa = ((uint64_t)reg.regspec_addr_hi) << 32;
	*pa |= (uint64_t)reg.regspec_addr_lo;

	return (0);
}

static int
mc_get_sibling_cpu_impl(pnode_t mc_node)
{
	int	len, impl;
	pnode_t	cpu_node;
	char	namebuf[OBP_MAXPROPNAME];

	cpu_node = mc_get_sibling_cpu(mc_node);
	if (cpu_node == OBP_NONODE) {
		SBDP_DBG_MEM("mc_get_sibling_cpu failed: dnode=0x%x\n",
		    mc_node);
		return (-1);
	}

	len = prom_getproplen(cpu_node, "name");
	if (len < 0) {
		SBDP_DBG_MEM("invalid prom_getproplen for name prop: "
		    "len=%d, dnode=0x%x\n", len, cpu_node);
		return (-1);
	}

	if (prom_getprop(cpu_node, "name", (caddr_t)namebuf) == -1) {
		SBDP_DBG_MEM("failed to read name property for dnode=0x%x\n",
		    cpu_node);
		return (-1);
	}

	/*
	 * If this is a CMP node, the child has the implementation
	 * property.
	 */
	if (strcmp(namebuf, "cmp") == 0) {
		cpu_node = prom_childnode(cpu_node);
		ASSERT(cpu_node != OBP_NONODE);
	}

	if (prom_getprop(cpu_node, "implementation#", (caddr_t)&impl) == -1) {
		SBDP_DBG_MEM("failed to read implementation# property for "
		    "dnode=0x%x\n", cpu_node);
		return (-1);
	}

	SBDP_DBG_MEM("mc_get_sibling_cpu_impl: found impl=0x%x, dnode=0x%x\n",
	    impl, cpu_node);

	return (impl);
}

/*
 * Provide EMU Activity Status register ASI and address.  Only valid for
 * Panther processors.
 */
static int
mc_get_idle_reg(pnode_t nodeid, uint64_t *addr, uint_t *asi)
{
	int	portid;
	uint64_t reg_pa;

	ASSERT(nodeid != OBP_NONODE);
	ASSERT(mc_get_sibling_cpu_impl(nodeid) == PANTHER_IMPL);

	if (prom_getprop(nodeid, "portid", (caddr_t)&portid) < 0 ||
	    portid == -1) {
		SBDP_DBG_MEM("mc_get_idle_reg: failed to read portid prop "
		    "for dnode=0x%x\n", nodeid);
		return (-1);
	}

	if (sbdp_get_reg_addr(nodeid, &reg_pa) != 0) {
		SBDP_DBG_MEM("mc_get_idle_reg: failed to read reg prop "
		    "for dnode=0x%x\n", nodeid);
		return (-1);
	}

	/*
	 * Local access will be via ASI 0x4a, otherwise via Safari PIO.
	 * This assumes the copy-rename will later run on the same proc,
	 * hence there is an assumption we are already bound.
	 */
	ASSERT(curthread->t_bound_cpu == CPU);
	if (SG_CPUID_TO_PORTID(CPU->cpu_id) == portid) {
		*addr = ASI_EMU_ACT_STATUS_VA;
		*asi = ASI_SAFARI_CONFIG;
	} else {
		*addr = MC_ACTIVITY_STATUS(reg_pa);
		*asi = ASI_IO;
	}

	return (0);
}

/*
 * If non-Panther board, add phys_banks entry for each physical bank.
 * If Panther board, add mc_idle_regs entry for each EMU Activity Status
 * register.  Increment the array indices b_idx and r_idx for each entry
 * populated by this routine.
 *
 * The caller is responsible for allocating sufficient array entries.
 */
static int
sbdp_prep_mc_idle_one(sbdp_bd_t *bp, sbdp_rename_script_t phys_banks[],
    int *b_idx, sbdp_mc_idle_script_t mc_idle_regs[], int *r_idx)
{
	int		i, j;
	pnode_t		*memnodes;
	mc_regs_t	regs;
	uint64_t	addr;
	uint_t		asi;
	sbd_cond_t	sibling_cpu_cond;
	int		impl = -1;

	memnodes = bp->nodes;

	for (i = 0; i < SBDP_MAX_MEM_NODES_PER_BOARD; i++) {
		if (memnodes[i] == OBP_NONODE) {
			continue;
		}

		/* MC should not be accessed if cpu has failed  */
		sibling_cpu_cond = mc_check_sibling_cpu(memnodes[i]);
		if (sibling_cpu_cond == SBD_COND_FAILED ||
		    sibling_cpu_cond == SBD_COND_UNUSABLE) {
			SBDP_DBG_MEM("sbdp: skipping MC with failed cpu: "
			    "board=%d, mem node=%d, condition=%d",
			    bp->bd, i, sibling_cpu_cond);
			continue;
		}

		/*
		 * Initialize the board cpu type, assuming all board cpus are
		 * the same type.  This is true of all Cheetah-based processors.
		 * Failure to read the cpu type is considered a fatal error.
		 */
		if (impl == -1) {
			impl = mc_get_sibling_cpu_impl(memnodes[i]);
			if (impl == -1) {
				SBDP_DBG_MEM("sbdp: failed to get cpu impl "
				    "for MC dnode=0x%x\n", memnodes[i]);
				return (-1);
			}
		}

		switch (impl) {
		case CHEETAH_IMPL:
		case CHEETAH_PLUS_IMPL:
		case JAGUAR_IMPL:
			if (mc_read_regs(memnodes[i], &regs)) {
				SBDP_DBG_MEM("sbdp: failed to read source "
				    "Decode Regs of board %d", bp->bd);
				return (-1);
			}

			for (j = 0; j < SBDP_MAX_MCS_PER_NODE; j++) {
				uint64_t mc_decode = regs.mc_decode[j];

				if ((mc_decode & SG_DECODE_VALID) !=
				    SG_DECODE_VALID) {
					continue;
				}

				addr = (MC_BASE(mc_decode) << PHYS2UM_SHIFT) |
				    (MC_LM(mc_decode) << MC_LM_SHIFT);

				phys_banks[*b_idx].masr_addr = addr;
				phys_banks[*b_idx].masr = 0;	/* unused */
				phys_banks[*b_idx].asi = ASI_MEM;
				(*b_idx)++;
			}
			break;
		case PANTHER_IMPL:
			if (mc_get_idle_reg(memnodes[i], &addr, &asi)) {
				return (-1);
			}

			mc_idle_regs[*r_idx].addr = addr;
			mc_idle_regs[*r_idx].asi = asi;
			mc_idle_regs[*r_idx].node = memnodes[i];
			mc_idle_regs[*r_idx].bd_id = bp->bd;
			(*r_idx)++;
			break;
		default:
			cmn_err(CE_WARN, "Unknown cpu implementation=0x%x",
			    impl);
			ASSERT(0);
			return (-1);
		}
	}

	return (0);
}

/*
 * For non-Panther MCs that do not support read-bypass-write, we do a read
 * to each physical bank, relying on the reads to block until all outstanding
 * write requests have completed.  This mechanism is referred to as the bus
 * sync list and is used for Cheetah, Cheetah+, and Jaguar processors.  The
 * bus sync list PAs for the source and target are kept together and comprise
 * Section 1 of the rename script.
 *
 * For Panther processors that support the EMU Activity Status register,
 * we ensure the writes have completed by polling the MCU_ACT_STATUS
 * field several times to make sure the MC queues are empty.  The
 * EMU Activity Status register PAs for the source and target are
 * kept together and comprise Section 2 of the rename script.
 */
static int
sbdp_prep_mc_idle_script(sbdp_bd_t *s_bp, sbdp_bd_t *t_bp,
    sbdp_rename_script_t *rsp, int *rsp_idx)
{
	sbdp_rename_script_t *phys_banks;
	sbdp_mc_idle_script_t *mc_idle_regs;
	int	max_banks, max_regs;
	size_t	bsize, msize;
	int	nbanks = 0, nregs = 0;
	int	i;

	/* CONSTCOND */
	ASSERT(sizeof (sbdp_rename_script_t) ==
	    sizeof (sbdp_mc_idle_script_t));

	/* allocate space for both source and target */
	max_banks = SBDP_MAX_MEM_NODES_PER_BOARD *
	    SG_MAX_BANKS_PER_MC * 2;
	max_regs = SBDP_MAX_MEM_NODES_PER_BOARD * 2;

	bsize = sizeof (sbdp_rename_script_t) * max_banks;
	msize = sizeof (sbdp_mc_idle_script_t) * max_regs;

	phys_banks = kmem_zalloc(bsize, KM_SLEEP);
	mc_idle_regs = kmem_zalloc(msize, KM_SLEEP);

	if (sbdp_prep_mc_idle_one(t_bp, phys_banks, &nbanks,
	    mc_idle_regs, &nregs) != 0 ||
	    sbdp_prep_mc_idle_one(s_bp, phys_banks, &nbanks,
	    mc_idle_regs, &nregs) != 0) {
		kmem_free(phys_banks, bsize);
		kmem_free(mc_idle_regs, msize);
		return (-1);
	}

	/* section 1 */
	for (i = 0; i < nbanks; i++)
		rsp[(*rsp_idx)++] = phys_banks[i];

	/* section 2 */
	for (i = 0; i < nregs; i++)
		rsp[(*rsp_idx)++] = *(sbdp_rename_script_t *)&mc_idle_regs[i];

	kmem_free(phys_banks, bsize);
	kmem_free(mc_idle_regs, msize);

	return (0);
}

/*
 * code assumes single mem-unit.
 */
static int
sbdp_prep_rename_script(sbdp_cr_handle_t *cph)
{
	pnode_t			*s_nodes, *t_nodes;
	int			m = 0, i;
	sbdp_bd_t		s_bd, t_bd, *s_bdp, *t_bdp;
	sbdp_rename_script_t	*rsp;
	uint64_t		new_base, old_base, temp_base;
	int			s_num, t_num;

	mutex_enter(&cph->s_bdp->bd_mutex);
	s_bd = *cph->s_bdp;
	mutex_exit(&cph->s_bdp->bd_mutex);
	mutex_enter(&cph->t_bdp->bd_mutex);
	t_bd = *cph->t_bdp;
	mutex_exit(&cph->t_bdp->bd_mutex);

	s_bdp = &s_bd;
	t_bdp = &t_bd;
	s_nodes = s_bdp->nodes;
	t_nodes = t_bdp->nodes;
	s_num = s_bdp->nnum;
	t_num = t_bdp->nnum;
	rsp = cph->script;

	/*
	 * Calculate the new base address for the target bd
	 */

	new_base = (s_bdp->bpa >> PHYS2UM_SHIFT) << MC_UM_SHIFT;

	/*
	 * Calculate the old base address for the source bd
	 */

	old_base = (t_bdp->bpa >> PHYS2UM_SHIFT) << MC_UM_SHIFT;

	temp_base = SG_INVAL_UM;

	SBDP_DBG_MEM("new 0x%lx old_base ox%lx temp_base 0x%lx\n", new_base,
	    old_base, temp_base);

	m = 0;

	/*
	 * Ensure the MC queues have been idled on the source and target
	 * following the copy.
	 */
	if (sbdp_prep_mc_idle_script(s_bdp, t_bdp, rsp, &m) < 0)
		return (-1);

	/*
	 * Script section terminator
	 */
	rsp[m].masr_addr = 0ull;
	rsp[m].masr = 0;
	rsp[m].asi = 0;
	m++;

	/*
	 * Invalidate the base in the target mc registers
	 */
	for (i = 0; i < t_num; i++) {
		if (sbdp_copy_regs(t_nodes[i], t_bdp->bpa, temp_base, 1, rsp,
		    &m) < 0)
			return (-1);
	}
	/*
	 * Invalidate the base in the source mc registers
	 */
	for (i = 0; i < s_num; i++) {
		if (sbdp_copy_regs(s_nodes[i], s_bdp->bpa, temp_base, 1, rsp,
		    &m) < 0)
			return (-1);
	}
	/*
	 * Copy the new base into the targets mc registers
	 */
	for (i = 0; i < t_num; i++) {
		if (sbdp_copy_regs(t_nodes[i], t_bdp->bpa, new_base, 0, rsp,
		    &m) < 0)
			return (-1);
	}
	/*
	 * Copy the old base into the source mc registers
	 */
	for (i = 0; i < s_num; i++) {
		if (sbdp_copy_regs(s_nodes[i], s_bdp->bpa, old_base, 0, rsp,
		    &m) < 0)
			return (-1);
	}
	/*
	 * Zero masr_addr value indicates the END.
	 */
	rsp[m].masr_addr = 0ull;
	rsp[m].masr = 0;
	rsp[m].asi = 0;
	m++;

#ifdef DEBUG
	{
		int	i;

		SBDP_DBG_MEM("dumping copy-rename script:\n");
		for (i = 0; i < m; i++) {
			SBDP_DBG_MEM("0x%lx = 0x%lx, asi 0x%x\n",
			    rsp[i].masr_addr, rsp[i].masr, rsp[i].asi);
		}
		DELAY(1000000);
	}
#endif /* DEBUG */

	return (m * sizeof (sbdp_rename_script_t));
}

/*
 * EMU Activity Status Register needs to be read idle several times.
 * See Panther PRM 12.5.
 */
#define	SBDP_MCU_IDLE_RETRIES	10
#define	SBDP_MCU_IDLE_READS	3

/*
 * Using the "__relocatable" suffix informs DTrace providers (and anything
 * else, for that matter) that this function's text may be manually relocated
 * elsewhere before it is executed.  That is, it cannot be safely instrumented
 * with any methodology that is PC-relative.
 */
static int
sbdp_copy_rename__relocatable(sbdp_cr_handle_t *hp, struct memlist *mlist,
		register sbdp_rename_script_t *rsp)
{
	sbdp_cr_err_t	err = SBDP_CR_OK;
	size_t		csize;
	size_t		linesize;
	uint_t		size;
	uint64_t	caddr;
	uint64_t	s_base, t_base;
	sbdp_bd_t	*s_sbp, *t_sbp;
	struct memlist	*ml;
	sbdp_mc_idle_script_t *isp;
	int		i;

	caddr = ecache_flushaddr;
	csize = (size_t)(cpunodes[CPU->cpu_id].ecache_size * 2);
	linesize = (size_t)(cpunodes[CPU->cpu_id].ecache_linesize);

	size = 0;
	s_sbp = hp->s_bdp;
	t_sbp = hp->t_bdp;

	s_base = (uint64_t)s_sbp->bpa;
	t_base = (uint64_t)t_sbp->bpa;

	hp->ret = s_base;
	/*
	 * DO COPY.
	 */
	for (ml = mlist; ml; ml = ml->next) {
		uint64_t	s_pa, t_pa;
		uint64_t	nbytes;

		s_pa = ml->address;
		t_pa = t_base + (ml->address - s_base);
		nbytes = ml->size;

		size += nbytes;
		while (nbytes != 0ull) {
			/*
			 * This copy does NOT use an ASI
			 * that avoids the Ecache, therefore
			 * the dst_pa addresses may remain
			 * in our Ecache after the dst_pa
			 * has been removed from the system.
			 * A subsequent write-back to memory
			 * will cause an ARB-stop because the
			 * physical address no longer exists
			 * in the system. Therefore we must
			 * flush out local Ecache after we
			 * finish the copy.
			 */

			/* copy 32 bytes at src_pa to dst_pa */
			bcopy32_il(s_pa, t_pa);

			/* increment by 32 bytes */
			s_pa += (4 * sizeof (uint64_t));
			t_pa += (4 * sizeof (uint64_t));

			/* decrement by 32 bytes */
			nbytes -= (4 * sizeof (uint64_t));
		}
	}

	/*
	 * Since bcopy32_il() does NOT use an ASI to bypass
	 * the Ecache, we need to flush our Ecache after
	 * the copy is complete.
	 */
	flush_ecache_il(caddr, csize, linesize);	/* inline version */

	/*
	 * Non-Panther MCs are idled by reading each physical bank.
	 */
	for (i = 0; rsp[i].asi == ASI_MEM; i++) {
		(void) lddphys_il(rsp[i].masr_addr);
	}

	isp = (sbdp_mc_idle_script_t *)&rsp[i];

	/*
	 * Panther MCs are idled by polling until the MCU idle state
	 * is read SBDP_MCU_IDLE_READS times in succession.
	 */
	while (isp->addr != 0ull) {
		for (i = 0; i < SBDP_MCU_IDLE_RETRIES; i++) {
			register uint64_t v;
			register int n_idle = 0;


			do {
				v = ldxasi_il(isp->addr, isp->asi) &
				    MCU_ACT_STATUS;
			} while (v != MCU_ACT_STATUS &&
			    ++n_idle < SBDP_MCU_IDLE_READS);

			if (n_idle == SBDP_MCU_IDLE_READS)
				break;
		}

		if (i == SBDP_MCU_IDLE_RETRIES) {
			/* bailout */
			hp->busy_mc = isp;
			return (SBDP_CR_MC_IDLE_ERR);
		}

		isp++;
	}

	/* skip terminator */
	isp++;

	/*
	 * The following inline assembly routine caches
	 * the rename script and then caches the code that
	 * will do the rename.  This is necessary
	 * so that we don't have any memory references during
	 * the reprogramming.  We accomplish this by first
	 * jumping through the code to guarantee it's cached
	 * before we actually execute it.
	 */
	sbdp_exec_script_il((sbdp_rename_script_t *)isp);

	return (err);
}
static void
_sbdp_copy_rename_end(void)
{
	/*
	 * IMPORTANT:   This function's location MUST be located immediately
	 *		following sbdp_copy_rename__relocatable to accurately
	 *		estimate its size.  Note that this assumes (!)the
	 *		compiler keeps these functions in the order in which
	 *		they appear :-o
	 */
}
int
sbdp_memory_rename(sbdp_handle_t *hp)
{
#ifdef lint
	/*
	 * Delete when implemented
	 */
	hp = hp;
#endif
	return (0);
}


/*
 * In Serengeti this is a nop
 */
int
sbdp_post_configure_mem(sbdp_handle_t *hp)
{
#ifdef lint
	hp = hp;
#endif
	return (0);
}

/*
 * In Serengeti this is a nop
 */
int
sbdp_post_unconfigure_mem(sbdp_handle_t *hp)
{
#ifdef lint
	hp = hp;
#endif
	return (0);
}

/* ARGSUSED */
int
sbdphw_disable_memctrl(sbdp_handle_t *hp, dev_info_t *dip)
{
	return (0);
}

/* ARGSUSED */
int
sbdphw_enable_memctrl(sbdp_handle_t *hp, dev_info_t *dip)
{
	return (0);
}

/*
 * We are assuming one memory node therefore the base address is the lowest
 * segment possible
 */
#define	PA_ABOVE_MAX	(0x8000000000000000ull)
int
sbdphw_get_base_physaddr(sbdp_handle_t *hp, dev_info_t *dip, uint64_t *pa)
{
	_NOTE(ARGUNUSED(hp))

	int i, board = -1, wnode;
	pnode_t	nodeid;
	struct mem_arg arg = {0};
	uint64_t seg_pa, tmp_pa;
	dev_info_t *list[SBDP_MAX_MEM_NODES_PER_BOARD];
	int rc;

	if (dip == NULL)
		return (-1);

	nodeid = ddi_get_nodeid(dip);

	if (sbdp_get_bd_and_wnode_num(nodeid, &board, &wnode) < 0)
		return (-1);

	list[0] = NULL;
	arg.board = board;
	arg.list = list;

	(void) sbdp_walk_prom_tree(prom_rootnode(), sbdp_get_mem_dip, &arg);

	if (arg.ndips <= 0)
		return (-1);

	seg_pa = PA_ABOVE_MAX;

	rc = -1;
	for (i = 0; i < arg.ndips; i++) {
		if (list[i] == NULL)
			continue;
		if (sbdp_get_lowest_addr_in_node(ddi_get_nodeid(list[i]),
		    &tmp_pa) == 0) {
			rc = 0;
			if (tmp_pa < seg_pa)
				seg_pa = tmp_pa;
		}

		/*
		 * Release hold acquired in sbdp_get_mem_dip()
		 */
		ddi_release_devi(list[i]);
	}

	if (rc == 0)
		*pa = seg_pa;
	else {
		/*
		 * Record the fact that an error has occurred
		 */
		sbdp_set_err(hp->h_err, ESGT_INTERNAL, NULL);
	}

	return (rc);
}

static int
sbdp_get_lowest_addr_in_node(pnode_t node, uint64_t *pa)
{
	uint64_t	mc_decode, seg_pa, tmp_pa;
	mc_regs_t	mc_regs, *mc_regsp = &mc_regs;
	int		i, valid;
	int		rc;


	seg_pa = PA_ABOVE_MAX;

	if (mc_read_regs(node, mc_regsp)) {
		SBDP_DBG_MEM("sbdp_get_lowest_addr_in_node: failed to "
		    "read source Decode Regs\n");
		return (-1);
	}

	rc = -1;
	for (i = 0; i < SBDP_MAX_MCS_PER_NODE; i++) {
		mc_decode = mc_regsp->mc_decode[i];
		valid = mc_decode >> MC_VALID_SHIFT;
		tmp_pa = MC_BASE(mc_decode) << PHYS2UM_SHIFT;
		if (valid)
			rc = 0;
		if (valid && (tmp_pa < seg_pa))
			seg_pa = tmp_pa;
	}

	if (rc == 0)
		*pa = seg_pa;

	return (rc);
}

int
sbdp_is_mem(pnode_t node, void *arg)
{
	mem_op_t	*memp = (mem_op_t *)arg;
	char		type[OBP_MAXPROPNAME];
	int		bd;
	pnode_t		*list;
	int		board;
	char		name[OBP_MAXDRVNAME];
	int		len;

	ASSERT(memp);

	list = memp->nodes;
	board = memp->board;

	/*
	 * Make sure that this node doesn't have its status
	 * as failed
	 */
	if (sbdp_get_comp_status(node) != SBD_COND_OK) {
		return (DDI_FAILURE);
	}

	len = prom_getproplen(node, "device_type");
	if ((len > 0) && (len < OBP_MAXPROPNAME))
		(void) prom_getprop(node, "device_type", (caddr_t)type);
	else
		type[0] = '\0';

	if (strcmp(type, "memory-controller") == 0) {
		int	wnode;

		if (sbdp_get_bd_and_wnode_num(node, &bd, &wnode) < 0)
			return (DDI_FAILURE);

		if (bd == board) {
			/*
			 * Make sure we don't overwrite the array
			 */
			if (memp->nmem >= SBDP_MAX_MEM_NODES_PER_BOARD)
				return (DDI_FAILURE);
			(void) prom_getprop(node, OBP_NAME, (caddr_t)name);
			SBDP_DBG_MEM("name %s  boot bd %d board %d\n", name,
			    board, bd);
			list[memp->nmem++] = node;
			return (DDI_SUCCESS);
		}
	}

	return (DDI_FAILURE);
}

static int
sbdp_get_meminfo(pnode_t nodeid, int mc, uint64_t *size, uint64_t *base_pa)
{
	int		board, wnode;
	int		valid;
	mc_regs_t	mc_regs, *mc_regsp = &mc_regs;
	uint64_t	mc_decode = 0;

	if (sbdp_get_bd_and_wnode_num(nodeid, &board, &wnode) < 0)
		return (-1);

	if (mc_read_regs(nodeid, mc_regsp)) {
		SBDP_DBG_MEM("sbdp_get_meminfo: failed to read source "
		    "Decode Regs");
		return (-1);
	}
	/*
	 * Calculate memory size
	 */
	mc_decode = mc_regsp->mc_decode[mc];

	/*
	 * Check the valid bit to see if bank is there
	 */
	valid = mc_decode >> MC_VALID_SHIFT;
	if (valid) {
		*size = MC_UK2SPAN(mc_decode);
		*base_pa = MC_BASE(mc_decode) << PHYS2UM_SHIFT;
	}

	return (0);
}


/*
 * Luckily for us mem nodes and cpu/CMP nodes are siblings.  All we need to
 * do is search in the same branch as the mem node for its sibling cpu or
 * CMP node.
 */
pnode_t
mc_get_sibling_cpu(pnode_t nodeid)
{
	int	portid;

	if (prom_getprop(nodeid, OBP_PORTID, (caddr_t)&portid) < 0)
		return (OBP_NONODE);

	/*
	 * cpus and memory are siblings so we don't need to traverse
	 * the whole tree, just a branch
	 */
	return (sbdp_find_nearby_cpu_by_portid(nodeid, portid));
}

/*
 * Given a memory node, check it's sibling cpu or CMP to see if
 * access to mem will be ok. We need to search for the node and
 * if found get its condition.
 */
sbd_cond_t
mc_check_sibling_cpu(pnode_t nodeid)
{
	pnode_t	cpu_node;
	sbd_cond_t	cond;
	int		i;

	cpu_node = mc_get_sibling_cpu(nodeid);

	cond = sbdp_get_comp_status(cpu_node);

	if (cond == SBD_COND_OK) {
		int 		wnode;
		int		bd;
		int		unit;
		int		portid;

		if (sbdp_get_bd_and_wnode_num(nodeid, &bd, &wnode) < 0)
			return (SBD_COND_UNKNOWN);

		(void) prom_getprop(nodeid, OBP_PORTID, (caddr_t)&portid);

		/*
		 * Access to the memory controller should not
		 * be attempted if any of the cores are marked
		 * as being in reset.
		 */
		for (i = 0; i < SBDP_MAX_CORES_PER_CMP; i++) {
			unit = SG_PORTID_TO_CPU_UNIT(portid, i);
			if (sbdp_is_cpu_present(wnode, bd, unit) &&
			    sbdp_is_cpu_in_reset(wnode, bd, unit)) {
				cond = SBD_COND_UNUSABLE;
				break;
			}
		}
	}

	return (cond);
}

int
mc_read_regs(pnode_t nodeid, mc_regs_t *mc_regsp)
{
	int			len;
	uint64_t		mc_addr, mask;
	mc_regspace		reg;
	sbd_cond_t		sibling_cpu_cond;
	int			local_mc;
	int			portid;
	int			i;

	if ((prom_getprop(nodeid, "portid", (caddr_t)&portid) < 0) ||
	    (portid == -1))
		return (-1);

	/*
	 * mc should not be accessed if their corresponding cpu
	 * has failed.
	 */
	sibling_cpu_cond = mc_check_sibling_cpu(nodeid);

	if ((sibling_cpu_cond == SBD_COND_FAILED) ||
	    (sibling_cpu_cond == SBD_COND_UNUSABLE)) {
		return (-1);
	}

	len = prom_getproplen(nodeid, "reg");
	if (len != sizeof (mc_regspace))
		return (-1);

	if (prom_getprop(nodeid, "reg", (caddr_t)&reg) < 0)
		return (-1);

	mc_addr = ((uint64_t)reg.regspec_addr_hi) << 32;
	mc_addr |= (uint64_t)reg.regspec_addr_lo;

	/*
	 * Make sure we don't switch cpus
	 */
	affinity_set(CPU_CURRENT);
	if (portid == cpunodes[CPU->cpu_id].portid)
		local_mc = 1;
	else
		local_mc = 0;

	for (i = 0; i < SG_MAX_BANKS_PER_MC; i++) {
		mask = SG_REG_2_OFFSET(i);

		/*
		 * If the memory controller is local to this CPU, we use
		 * the special ASI to read the decode registers.
		 * Otherwise, we load the values from a magic address in
		 * I/O space.
		 */
		if (local_mc) {
			mc_regsp->mc_decode[i] = lddmcdecode(
			    mask & MC_OFFSET_MASK);
		} else {
			mc_regsp->mc_decode[i] = lddphysio(
			    (mc_addr | mask));
		}
	}
	affinity_clear();

	return (0);
}

uint64_t
mc_get_addr(pnode_t nodeid, int mc, uint_t *asi)
{
	int			len;
	uint64_t		mc_addr, addr;
	mc_regspace		reg;
	int			portid;
	int			local_mc;

	if ((prom_getprop(nodeid, "portid", (caddr_t)&portid) < 0) ||
	    (portid == -1))
		return (-1);

	len = prom_getproplen(nodeid, "reg");
	if (len != sizeof (mc_regspace))
		return (-1);

	if (prom_getprop(nodeid, "reg", (caddr_t)&reg) < 0)
		return (-1);

	mc_addr = ((uint64_t)reg.regspec_addr_hi) << 32;
	mc_addr |= (uint64_t)reg.regspec_addr_lo;

	/*
	 * Make sure we don't switch cpus
	 */
	affinity_set(CPU_CURRENT);
	if (portid == cpunodes[CPU->cpu_id].portid)
		local_mc = 1;
	else
		local_mc = 0;

	if (local_mc) {
		*asi = ASI_MC_DECODE;
		addr = SG_REG_2_OFFSET(mc) & MC_OFFSET_MASK;
	} else {
		*asi = ASI_IO;
		addr = SG_REG_2_OFFSET(mc) | mc_addr;
	}
	affinity_clear();

	return (addr);
}

/* ARGSUSED */
int
sbdp_mem_add_span(sbdp_handle_t *hp, uint64_t address, uint64_t size)
{
	return (0);
}

int
sbdp_mem_del_span(sbdp_handle_t *hp, uint64_t address, uint64_t size)
{
	pfn_t		 basepfn = (pfn_t)(address >> PAGESHIFT);
	pgcnt_t		 npages = (pgcnt_t)(size >> PAGESHIFT);

	if (size > 0) {
		int rv;
		rv = kcage_range_delete_post_mem_del(basepfn, npages);
		if (rv != 0) {
			cmn_err(CE_WARN,
			    "unexpected kcage_range_delete_post_mem_del"
			    " return value %d", rv);
			sbdp_set_err(hp->h_err, ESGT_INTERNAL, NULL);
			return (-1);
		}
	}
	return (0);
}

/*
 * This routine gets the size including the
 * bad banks
 */
int
sbdp_get_mem_size(sbdp_handle_t *hp)
{
	uint64_t	size = 0;
	struct memlist	*mlist, *ml;

	mlist = sbdp_get_memlist(hp, (dev_info_t *)NULL);

	for (ml = mlist; ml; ml = ml->next)
		size += ml->size;

	(void) sbdp_del_memlist(hp, mlist);

	SBDP_DBG_MEM("sbdp_get_mem_size: size 0x%" PRIx64 "\n", size);

	return (btop(size));
}

/*
 * This function compares the list of banks passed with the banks
 * in the segment
 */
int
sbdp_check_seg_with_banks(sbdp_seg_t *seg, sbdp_bank_t *banks)
{
	sbdp_bank_t	*cur_bank, *bank;
	int		i = 0;

	for (cur_bank = seg->banks; cur_bank; cur_bank = cur_bank->seg_next) {
		for (bank = banks; bank; bank = bank->bd_next) {
			if (!bank->valid)
				continue;

			if (cur_bank == bank) {
				i++;
			}
		}
	}

	SBDP_DBG_MEM("banks found = %d total banks = %d\n", i, seg->nbanks);
	/*
	 * If we find the same num of banks that are equal, then this segment
	 * is not interleaved across boards
	 */
	if (i == seg->nbanks)
		return (0);

	return (1);
}


/*
 * This routine determines if any of the memory banks on the board
 * participate in across board memory interleaving
 */
int
sbdp_isinterleaved(sbdp_handle_t *hp, dev_info_t *dip)
{
	_NOTE(ARGUNUSED(dip))

	sbdp_bank_t	*bankp;
	int		wnode, board;
	int		is_interleave = 0;
	sbdp_bd_t	*bdp;
	uint64_t	base;
	sbdp_seg_t	*seg;

	board = hp->h_board;
	wnode = hp->h_wnode;

#ifdef DEBUG
	sbdp_print_all_segs();
#endif
	/*
	 * Get the banks for this board
	 */
	bdp = sbdp_get_bd_info(wnode, board);

	if (bdp == NULL)
		return (-1);

	/*
	 * Search for the first bank with valid memory
	 */
	for (bankp = bdp->banks; bankp; bankp = bankp->bd_next)
		if (bankp->valid)
			break;

	/*
	 * If there are no banks in the board, then the board is
	 * not interleaved across boards
	 */
	if (bankp == NULL) {
		return (0);
	}

	base = bankp->um & ~(bankp->uk);

	/*
	 * Find the segment for the first bank
	 */
	if ((seg = sbdp_get_seg(base)) == NULL) {
		/*
		 * Something bad has happened.
		 */
		return (-1);
	}
	/*
	 * Make sure that this segment is only composed of the banks
	 * in this board. If one is missing or we have an extra one
	 * the board is interleaved across boards
	 */
	is_interleave = sbdp_check_seg_with_banks(seg, bdp->banks);

	SBDP_DBG_MEM("interleave is %d\n", is_interleave);

	return (is_interleave);
}


/*
 * Each node has 4 logical banks.  This routine adds all the banks (including
 * the invalid ones to the passed list. Note that we use the bd list and not
 * the seg list
 */
int
sbdp_add_nodes_banks(pnode_t node, sbdp_bank_t **banks)
{
	int		i;
	mc_regs_t	regs;
	uint64_t	*mc_decode;
	sbdp_bank_t 	*bank;

	if (mc_read_regs(node, &regs) == -1)
		return (-1);

	mc_decode = regs.mc_decode;

	for (i = 0; i < SBDP_MAX_MCS_PER_NODE; i++) {
		/*
		 * This creates the mem for the new member of the list
		 */
		sbdp_fill_bank_info(mc_decode[i], &bank);

		SBDP_DBG_MEM("adding bank %d\n", bank->id);

		/*
		 * Insert bank into the beginning of the list
		 */
		bank->bd_next = *banks;
		*banks = bank;

		/*
		 * Add this bank into its corresponding
		 * segment
		 */
		sbdp_add_bank_to_seg(bank);
	}
	return (0);
}

/*
 * given the info, create a new bank node and set the info
 * as appropriate. We allocate the memory for the bank. It is
 * up to the caller to ensure the mem is freed
 */
void
sbdp_fill_bank_info(uint64_t mc_decode, sbdp_bank_t **bank)
{
	static int	id = 0;
	sbdp_bank_t	*new;

	new = kmem_zalloc(sizeof (sbdp_bank_t), KM_SLEEP);

	new->id = id++;
	new->valid = (mc_decode >> MC_VALID_SHIFT);
	new->uk = MC_UK(mc_decode);
	new->um = MC_UM(mc_decode);
	new->lk = MC_LK(mc_decode);
	new->lm = MC_LM(mc_decode);
	new->bd_next = NULL;
	new->seg_next = NULL;

	*bank = new;
}

/*
 * Each bd has the potential of having mem banks on it.  The banks
 * may be empty or not.  This routine gets all the mem banks
 * for this bd
 */
void
sbdp_init_bd_banks(sbdp_bd_t *bdp)
{
	int		i, nmem;
	pnode_t		*lists;

	lists = bdp->nodes;
	nmem = bdp->nnum;

	if (bdp->banks != NULL) {
		return;
	}

	bdp->banks = NULL;

	for (i = 0; i < nmem; i++) {
		(void) sbdp_add_nodes_banks(lists[i], &bdp->banks);
	}
}

/*
 * swap the list of banks for the 2 boards
 */
void
sbdp_swap_list_of_banks(sbdp_bd_t *bdp1, sbdp_bd_t *bdp2)
{
	sbdp_bank_t	*tmp_ptr;

	if ((bdp1 == NULL) || (bdp2 == NULL))
		return;

	tmp_ptr = bdp1->banks;
	bdp1->banks = bdp2->banks;
	bdp2->banks = tmp_ptr;
}

/*
 * free all the banks on the board.  Note that a bank node belongs
 * to 2 lists. The first list is the board list. The second one is
 * the seg list. We only need to remove the bank from both lists but only
 * free the node once.
 */
void
sbdp_fini_bd_banks(sbdp_bd_t *bdp)
{
	sbdp_bank_t	*bkp, *nbkp;

	for (bkp = bdp->banks; bkp; ) {
		/*
		 * Remove the bank from the seg list first
		 */
		SBDP_DBG_MEM("Removing bank %d\n", bkp->id);
		sbdp_remove_bank_from_seg(bkp);
		nbkp = bkp->bd_next;
		bkp->bd_next = NULL;
		kmem_free(bkp, sizeof (sbdp_bank_t));

		bkp = nbkp;
	}
	bdp->banks = NULL;
}

#ifdef DEBUG
void
sbdp_print_bd_banks(sbdp_bd_t *bdp)
{
	sbdp_bank_t	*bp;
	int		i;

	SBDP_DBG_MEM("BOARD %d\n", bdp->bd);

	for (bp = bdp->banks, i = 0; bp; bp = bp->bd_next, i++) {
		SBDP_DBG_MEM("BANK [%d]:\n", bp->id);
		SBDP_DBG_MEM("\tvalid %d\tuk 0x%x\tum 0x%x\tlk 0x%x"
		    "\tlm 0x%x\n", bp->valid, bp->uk, bp->um,
		    bp->lk, bp->lm);
	}
}

void
sbdp_print_all_segs(void)
{
	sbdp_seg_t	*cur_seg;

	for (cur_seg = sys_seg; cur_seg; cur_seg = cur_seg->next)
		sbdp_print_seg(cur_seg);
}

void
sbdp_print_seg(sbdp_seg_t *seg)
{
	sbdp_bank_t	*bp;
	int		i;

	SBDP_DBG_MEM("SEG %d\n", seg->id);

	for (bp = seg->banks, i = 0; bp; bp = bp->seg_next, i++) {
		SBDP_DBG_MEM("BANK [%d]:\n", bp->id);
		SBDP_DBG_MEM("\tvalid %d\tuk 0x%x\tum 0x%x\tlk 0x%x"
		    "\tlm 0x%x\n", bp->valid, bp->uk, bp->um,
		    bp->lk, bp->lm);
	}
}
#endif

void
sbdp_add_bank_to_seg(sbdp_bank_t *bank)
{
	uint64_t	base;
	sbdp_seg_t	*cur_seg;
	static int	id = 0;

	/*
	 * if we got an invalid bank just skip it
	 */
	if (bank == NULL || !bank->valid)
		return;
	base = bank->um & ~(bank->uk);

	if ((cur_seg = sbdp_get_seg(base)) == NULL) {
		/*
		 * This bank is part of a new segment, so create
		 * a struct for it and added to the list of segments
		 */
		cur_seg = kmem_zalloc(sizeof (sbdp_seg_t), KM_SLEEP);
		cur_seg->id = id++;
		cur_seg->base = base;
		cur_seg->size = ((bank->uk +1) << PHYS2UM_SHIFT);
		cur_seg->intlv = ((bank->lk ^ 0xF) + 1);
		/*
		 * add to the seg list
		 */
		cur_seg->next = sys_seg;
		sys_seg = cur_seg;
	}

	cur_seg->nbanks++;
	/*
	 * add bank into segs bank list.  Note we add at the head
	 */
	bank->seg_next = cur_seg->banks;
	cur_seg->banks = bank;
}

/*
 * Remove this segment from the seg list
 */
void
sbdp_rm_seg(sbdp_seg_t *seg)
{
	sbdp_seg_t	**curpp, *curp;

	curpp = &sys_seg;

	while ((curp = *curpp) != NULL) {
		if (curp == seg) {
			*curpp = curp->next;
			break;
		}
		curpp = &curp->next;
	}

	if (curp != NULL) {
		kmem_free(curp, sizeof (sbdp_seg_t));
		curp = NULL;
	}
}

/*
 * remove this bank from its seg list
 */
void
sbdp_remove_bank_from_seg(sbdp_bank_t *bank)
{
	uint64_t	base;
	sbdp_seg_t	*cur_seg;
	sbdp_bank_t	**curpp, *curp;

	/*
	 * if we got an invalid bank just skip it
	 */
	if (bank == NULL || !bank->valid)
		return;
	base = bank->um & ~(bank->uk);

	/*
	 * If the bank doesn't belong to any seg just return
	 */
	if ((cur_seg = sbdp_get_seg(base)) == NULL) {
		SBDP_DBG_MEM("bank %d with no segment\n", bank->id);
		return;
	}

	/*
	 * Find bank in the seg
	 */
	curpp = &cur_seg->banks;

	while ((curp = *curpp) != NULL) {
		if (curp->id == bank->id) {
			/*
			 * found node, remove it
			 */
			*curpp = curp->seg_next;
			break;
		}
		curpp = &curp->seg_next;
	}

	if (curp != NULL) {
		cur_seg->nbanks--;
	}

	if (cur_seg->nbanks == 0) {
		/*
		 * No banks left on this segment, remove the segment
		 */
		SBDP_DBG_MEM("No banks left in this segment, removing it\n");
		sbdp_rm_seg(cur_seg);
	}
}

sbdp_seg_t *
sbdp_get_seg(uint64_t base)
{
	sbdp_seg_t	*cur_seg;

	for (cur_seg = sys_seg; cur_seg; cur_seg = cur_seg->next) {
		if (cur_seg-> base == base)
			break;
	}

	return (cur_seg);
}

#ifdef DEBUG
int
sbdp_passthru_readmem(sbdp_handle_t *hp, void *arg)
{
	_NOTE(ARGUNUSED(hp))
	_NOTE(ARGUNUSED(arg))

	struct memlist	*ml;
	uint64_t	src_pa;
	uint64_t	dst_pa;
	uint64_t	dst;


	dst_pa = va_to_pa(&dst);

	memlist_read_lock();
	for (ml = phys_install; ml; ml = ml->next) {
		uint64_t	nbytes;

		src_pa = ml->address;
		nbytes = ml->size;

		while (nbytes != 0ull) {

			/* copy 32 bytes at src_pa to dst_pa */
			bcopy32_il(src_pa, dst_pa);

			/* increment by 32 bytes */
			src_pa += (4 * sizeof (uint64_t));

			/* decrement by 32 bytes */
			nbytes -= (4 * sizeof (uint64_t));
		}
	}
	memlist_read_unlock();

	return (0);
}

static int
isdigit(int ch)
{
	return (ch >= '0' && ch <= '9');
}

#define	isspace(c)	((c) == ' ' || (c) == '\t' || (c) == '\n')

int
sbdp_strtoi(char *p, char **pos)
{
	int n;
	int c, neg = 0;

	if (!isdigit(c = *p)) {
		while (isspace(c))
			c = *++p;
		switch (c) {
			case '-':
				neg++;
				/* FALLTHROUGH */
			case '+':
				c = *++p;
		}
		if (!isdigit(c)) {
			if (pos != NULL)
				*pos = p;
			return (0);
		}
	}
	for (n = '0' - c; isdigit(c = *++p); ) {
		n *= 10; /* two steps to avoid unnecessary overflow */
		n += '0' - c; /* accum neg to avoid surprises at MAX */
	}
	if (pos != NULL)
		*pos = p;
	return (neg ? n : -n);
}

int
sbdp_passthru_prep_script(sbdp_handle_t *hp, void *arg)
{
	int			board, i;
	sbdp_bd_t		*t_bdp, *s_bdp;
	char			*opts;
	int			t_board;
	sbdp_rename_script_t	*rsbuffer;
	sbdp_cr_handle_t	*cph;
	int			scriptlen, size;

	opts = (char *)arg;
	board = hp->h_board;

	opts += strlen("prep-script=");
	t_board = sbdp_strtoi(opts, NULL);

	cph =  kmem_zalloc(sizeof (sbdp_cr_handle_t), KM_SLEEP);

	size = sizeof (sbdp_rename_script_t) * SBDP_RENAME_MAXOP;
	rsbuffer = kmem_zalloc(size, KM_SLEEP);

	s_bdp = sbdp_get_bd_info(hp->h_wnode, board);
	t_bdp = sbdp_get_bd_info(hp->h_wnode, t_board);

	cph->s_bdp = s_bdp;
	cph->t_bdp = t_bdp;
	cph->script = rsbuffer;

	affinity_set(CPU_CURRENT);
	scriptlen = sbdp_prep_rename_script(cph);

	if (scriptlen <= 0) {
		cmn_err(CE_WARN,
		"sbdp failed to prep for copy-rename");
	}
	prom_printf("SCRIPT from board %d to board %d ->\n", board, t_board);
	for (i = 0;  i < (scriptlen / (sizeof (sbdp_rename_script_t))); i++) {
		prom_printf("0x%lx = 0x%lx, asi 0x%x\n",
		    rsbuffer[i].masr_addr, rsbuffer[i].masr, rsbuffer[i].asi);
	}
	prom_printf("\n");

	affinity_clear();
	kmem_free(rsbuffer, size);
	kmem_free(cph, sizeof (sbdp_cr_handle_t));

	return (0);
}
#endif
