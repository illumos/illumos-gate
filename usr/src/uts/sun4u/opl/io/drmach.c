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
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/dditypes.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/opl_olympus_regs.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/mem_config.h>
#include <sys/ddi_impldefs.h>
#include <sys/systm.h>
#include <sys/machsystm.h>
#include <sys/autoconf.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/x_call.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/membar.h>
#include <vm/seg_kmem.h>
#include <sys/mem_cage.h>
#include <sys/stack.h>
#include <sys/archsystm.h>
#include <vm/hat_sfmmu.h>
#include <sys/pte.h>
#include <sys/mmu.h>
#include <sys/cpu_module.h>
#include <sys/obpdefs.h>
#include <sys/note.h>
#include <sys/ontrap.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/opl.h>
#include <sys/cpu_impl.h>


#include <sys/promimpl.h>
#include <sys/prom_plat.h>
#include <sys/kobj.h>

#include <sys/sysevent.h>
#include <sys/sysevent/dr.h>
#include <sys/sysevent/eventdefs.h>

#include <sys/drmach.h>
#include <sys/dr_util.h>

#include <sys/fcode.h>
#include <sys/opl_cfg.h>

extern void		bcopy32_il(uint64_t, uint64_t);
extern void		flush_cache_il(void);
extern void		drmach_sleep_il(void);

typedef struct {
	struct drmach_node	*node;
	void			*data;
} drmach_node_walk_args_t;

typedef struct drmach_node {
	void		*here;

	pnode_t		(*get_dnode)(struct drmach_node *node);
	int		(*walk)(struct drmach_node *node, void *data,
				int (*cb)(drmach_node_walk_args_t *args));
	dev_info_t	*(*n_getdip)(struct drmach_node *node);
	int		(*n_getproplen)(struct drmach_node *node, char *name,
				int *len);
	int		(*n_getprop)(struct drmach_node *node, char *name,
				void *buf, int len);
	int		(*get_parent)(struct drmach_node *node,
				struct drmach_node *pnode);
} drmach_node_t;

typedef struct {
	int		 min_index;
	int		 max_index;
	int		 arr_sz;
	drmachid_t	*arr;
} drmach_array_t;

typedef struct {
	void		*isa;

	void		(*dispose)(drmachid_t);
	sbd_error_t	*(*release)(drmachid_t);
	sbd_error_t	*(*status)(drmachid_t, drmach_status_t *);

	char		 name[MAXNAMELEN];
} drmach_common_t;

typedef	struct {
	uint32_t	core_present;
	uint32_t	core_hotadded;
	uint32_t	core_started;
} drmach_cmp_t;

typedef struct {
	drmach_common_t	 cm;
	int		 bnum;
	int		 assigned;
	int		 powered;
	int		 connected;
	int		 cond;
	drmach_node_t	*tree;
	drmach_array_t	*devices;
	int		boot_board;	/* if board exists on bootup */
	drmach_cmp_t	cores[OPL_MAX_COREID_PER_BOARD];
} drmach_board_t;

typedef struct {
	drmach_common_t	 cm;
	drmach_board_t	*bp;
	int		 unum;
	int		portid;
	int		 busy;
	int		 powered;
	const char	*type;
	drmach_node_t	*node;
} drmach_device_t;

typedef struct drmach_cpu {
	drmach_device_t  dev;
	processorid_t    cpuid;
	int		sb;
	int		chipid;
	int		coreid;
	int		strandid;
	int		status;
#define	OPL_CPU_HOTADDED	1
} drmach_cpu_t;

typedef struct drmach_mem {
	drmach_device_t  dev;
	uint64_t	slice_base;
	uint64_t	slice_size;
	uint64_t	base_pa;	/* lowest installed memory base */
	uint64_t	nbytes;		/* size of installed memory */
	struct memlist *memlist;
} drmach_mem_t;

typedef struct drmach_io {
	drmach_device_t  dev;
	int	channel;
	int	leaf;
} drmach_io_t;

typedef struct drmach_domain_info {
	uint32_t	floating;
	int		allow_dr;
} drmach_domain_info_t;

drmach_domain_info_t drmach_domain;

typedef struct {
	int		 flags;
	drmach_device_t	*dp;
	sbd_error_t	*err;
	dev_info_t	*dip;
} drmach_config_args_t;

typedef struct {
	drmach_board_t	*obj;
	int		 ndevs;
	void		*a;
	sbd_error_t	*(*found)(void *a, const char *, int, drmachid_t);
	sbd_error_t	*err;
} drmach_board_cb_data_t;

static drmach_array_t	*drmach_boards;

static sbd_error_t	*drmach_device_new(drmach_node_t *,
				drmach_board_t *, int, drmachid_t *);
static sbd_error_t	*drmach_cpu_new(drmach_device_t *, drmachid_t *);
static sbd_error_t	*drmach_mem_new(drmach_device_t *, drmachid_t *);
static sbd_error_t	*drmach_io_new(drmach_device_t *, drmachid_t *);

static dev_info_t	*drmach_node_ddi_get_dip(drmach_node_t *np);
static int		 drmach_node_ddi_get_prop(drmach_node_t *np,
				char *name, void *buf, int len);
static int		 drmach_node_ddi_get_proplen(drmach_node_t *np,
				char *name, int *len);

static int		drmach_get_portid(drmach_node_t *);
static	sbd_error_t	*drmach_i_status(drmachid_t, drmach_status_t *);
static int		opl_check_dr_status();
static void		drmach_io_dispose(drmachid_t);
static sbd_error_t	*drmach_io_release(drmachid_t);
static sbd_error_t	*drmach_io_status(drmachid_t, drmach_status_t *);
static int		drmach_init(void);
static void		drmach_fini(void);
static void		drmach_swap_pa(drmach_mem_t *, drmach_mem_t *);
static drmach_board_t	*drmach_get_board_by_bnum(int);

static sbd_error_t	*drmach_board_release(drmachid_t);
static sbd_error_t	*drmach_board_status(drmachid_t, drmach_status_t *);
static void		drmach_cpu_dispose(drmachid_t);
static sbd_error_t	*drmach_cpu_release(drmachid_t);
static sbd_error_t	*drmach_cpu_status(drmachid_t, drmach_status_t *);
static void		drmach_mem_dispose(drmachid_t);
static sbd_error_t	*drmach_mem_release(drmachid_t);
static sbd_error_t	*drmach_mem_status(drmachid_t, drmach_status_t *);

/* options for the second argument in drmach_add_remove_cpu() */
#define	HOTADD_CPU	1
#define	HOTREMOVE_CPU	2

#define	ON_BOARD_CORE_NUM(x)	(((uint_t)(x) / OPL_MAX_STRANDID_PER_CORE) & \
	(OPL_MAX_COREID_PER_BOARD - 1))

extern struct cpu	*SIGBCPU;

static int		drmach_name2type_idx(char *);
static drmach_board_t	*drmach_board_new(int, int);

#ifdef DEBUG

#define	DRMACH_PR		if (drmach_debug) printf
int drmach_debug = 1;		 /* set to non-zero to enable debug messages */
#else

#define	DRMACH_PR		_NOTE(CONSTANTCONDITION) if (0) printf
#endif /* DEBUG */


#define	DRMACH_OBJ(id)		((drmach_common_t *)id)

#define	DRMACH_NULL_ID(id)	((id) == 0)

#define	DRMACH_IS_BOARD_ID(id)	\
	((id != 0) &&		\
	(DRMACH_OBJ(id)->isa == (void *)drmach_board_new))

#define	DRMACH_IS_CPU_ID(id)	\
	((id != 0) &&		\
	(DRMACH_OBJ(id)->isa == (void *)drmach_cpu_new))

#define	DRMACH_IS_MEM_ID(id)	\
	((id != 0) &&		\
	(DRMACH_OBJ(id)->isa == (void *)drmach_mem_new))

#define	DRMACH_IS_IO_ID(id)	\
	((id != 0) &&		\
	(DRMACH_OBJ(id)->isa == (void *)drmach_io_new))

#define	DRMACH_IS_DEVICE_ID(id)					\
	((id != 0) &&						\
	(DRMACH_OBJ(id)->isa == (void *)drmach_cpu_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_mem_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_io_new))

#define	DRMACH_IS_ID(id)					\
	((id != 0) &&						\
	(DRMACH_OBJ(id)->isa == (void *)drmach_board_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_cpu_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_mem_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_io_new))

#define	DRMACH_INTERNAL_ERROR() \
	drerr_new(1, EOPL_INTERNAL, drmach_ie_fmt, __LINE__)

static char		*drmach_ie_fmt = "drmach.c %d";

static struct {
	const char	*name;
	const char	*type;
	sbd_error_t	*(*new)(drmach_device_t *, drmachid_t *);
} drmach_name2type[] = {
	{ "cpu",	DRMACH_DEVTYPE_CPU,		drmach_cpu_new },
	{ "pseudo-mc",	DRMACH_DEVTYPE_MEM,		drmach_mem_new },
	{ "pci",	DRMACH_DEVTYPE_PCI,		drmach_io_new  },
};

/* utility */
#define	MBYTE	(1048576ull)

/*
 * drmach autoconfiguration data structures and interfaces
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"OPL DR 1.1"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

static krwlock_t drmach_boards_rwlock;

typedef const char	*fn_t;

int
_init(void)
{
	int err;

	if ((err = drmach_init()) != 0) {
		return (err);
	}

	if ((err = mod_install(&modlinkage)) != 0) {
		drmach_fini();
	}

	return (err);
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&modlinkage)) == 0)
		drmach_fini();

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

struct drmach_mc_lookup {
	int	bnum;
	drmach_board_t	*bp;
	dev_info_t *dip;	/* rv - set if found */
};

#define	_ptob64(p) ((uint64_t)(p) << PAGESHIFT)
#define	_b64top(b) ((pgcnt_t)((b) >> PAGESHIFT))

static int
drmach_setup_mc_info(dev_info_t *dip, drmach_mem_t *mp)
{
	uint64_t	memory_ranges[128];
	int len;
	struct memlist	*ml;
	int rv;
	hwd_sb_t *hwd;
	hwd_memory_t *pm;

	len = sizeof (memory_ranges);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "sb-mem-ranges", (caddr_t)&memory_ranges[0], &len) !=
	    DDI_PROP_SUCCESS) {
		mp->slice_base = 0;
		mp->slice_size = 0;
		return (-1);
	}
	mp->slice_base = memory_ranges[0];
	mp->slice_size = memory_ranges[1];

	if (!mp->dev.bp->boot_board) {
		int i;

		rv = opl_read_hwd(mp->dev.bp->bnum, NULL,  NULL, NULL, &hwd);

		if (rv != 0) {
			return (-1);
		}

		ml = NULL;
		pm = &hwd->sb_cmu.cmu_memory;
		for (i = 0; i < HWD_MAX_MEM_CHUNKS; i++) {
			if (pm->mem_chunks[i].chnk_size > 0) {
				ml = memlist_add_span(ml,
				    pm->mem_chunks[i].chnk_start_address,
				    pm->mem_chunks[i].chnk_size);
			}
		}
	} else {
		/*
		 * we intersect phys_install to get base_pa.
		 * This only works at bootup time.
		 */

		memlist_read_lock();
		ml = memlist_dup(phys_install);
		memlist_read_unlock();

		ml = memlist_del_span(ml, 0ull, mp->slice_base);
		if (ml) {
			uint64_t basepa, endpa;
			endpa = _ptob64(physmax + 1);

			basepa = mp->slice_base + mp->slice_size;

			ml = memlist_del_span(ml, basepa, endpa - basepa);
		}
	}

	if (ml) {
		uint64_t nbytes = 0;
		struct memlist *p;
		for (p = ml; p; p = p->ml_next) {
			nbytes += p->ml_size;
		}
		if ((mp->nbytes = nbytes) > 0)
			mp->base_pa = ml->ml_address;
		else
			mp->base_pa = 0;
		mp->memlist = ml;
	} else {
		mp->base_pa = 0;
		mp->nbytes = 0;
	}
	return (0);
}


struct drmach_hotcpu {
	drmach_board_t *bp;
	int	bnum;
	int	core_id;
	int	rv;
	int	option;
};

static int
drmach_cpu_cb(dev_info_t *dip, void *arg)
{
	struct drmach_hotcpu *p = (struct drmach_hotcpu *)arg;
	char name[OBP_MAXDRVNAME];
	int len = OBP_MAXDRVNAME;
	int bnum, core_id, strand_id;
	drmach_board_t *bp;

	if (dip == ddi_root_node()) {
		return (DDI_WALK_CONTINUE);
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "name",
	    (caddr_t)name, &len) != DDI_PROP_SUCCESS) {
		return (DDI_WALK_PRUNECHILD);
	}

	/* only cmp has board number */
	bnum = -1;
	len = sizeof (bnum);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_BOARDNUM,
	    (caddr_t)&bnum, &len) != DDI_PROP_SUCCESS) {
		bnum = -1;
	}

	if (strcmp(name, "cmp") == 0) {
		if (bnum != p->bnum)
			return (DDI_WALK_PRUNECHILD);
		return (DDI_WALK_CONTINUE);
	}
	/* we have already pruned all unwanted cores and cpu's above */
	if (strcmp(name, "core") == 0) {
		return (DDI_WALK_CONTINUE);
	}
	if (strcmp(name, "cpu") == 0) {
		processorid_t cpuid;
		len = sizeof (cpuid);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "cpuid",
		    (caddr_t)&cpuid, &len) != DDI_PROP_SUCCESS) {
			p->rv = -1;
			return (DDI_WALK_TERMINATE);
		}

		core_id = p->core_id;

		bnum = LSB_ID(cpuid);

		if (ON_BOARD_CORE_NUM(cpuid) != core_id)
			return (DDI_WALK_CONTINUE);

		bp = p->bp;
		ASSERT(bnum == bp->bnum);

		if (p->option == HOTADD_CPU) {
			if (prom_hotaddcpu(cpuid) != 0) {
				p->rv = -1;
				return (DDI_WALK_TERMINATE);
			}
			strand_id = STRAND_ID(cpuid);
			bp->cores[core_id].core_hotadded |= (1 << strand_id);
		} else if (p->option == HOTREMOVE_CPU) {
			if (prom_hotremovecpu(cpuid) != 0) {
				p->rv = -1;
				return (DDI_WALK_TERMINATE);
			}
			strand_id = STRAND_ID(cpuid);
			bp->cores[core_id].core_hotadded &= ~(1 << strand_id);
		}
		return (DDI_WALK_CONTINUE);
	}

	return (DDI_WALK_PRUNECHILD);
}


static int
drmach_add_remove_cpu(int bnum, int core_id, int option)
{
	struct drmach_hotcpu arg;
	drmach_board_t *bp;

	bp = drmach_get_board_by_bnum(bnum);
	ASSERT(bp);

	arg.bp = bp;
	arg.bnum = bnum;
	arg.core_id = core_id;
	arg.rv = 0;
	arg.option = option;
	ddi_walk_devs(ddi_root_node(), drmach_cpu_cb, (void *)&arg);
	return (arg.rv);
}

struct drmach_setup_core_arg {
	drmach_board_t *bp;
};

static int
drmach_setup_core_cb(dev_info_t *dip, void *arg)
{
	struct drmach_setup_core_arg *p = (struct drmach_setup_core_arg *)arg;
	char name[OBP_MAXDRVNAME];
	int len = OBP_MAXDRVNAME;
	int bnum;
	int core_id, strand_id;

	if (dip == ddi_root_node()) {
		return (DDI_WALK_CONTINUE);
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "name",
	    (caddr_t)name, &len) != DDI_PROP_SUCCESS) {
		return (DDI_WALK_PRUNECHILD);
	}

	/* only cmp has board number */
	bnum = -1;
	len = sizeof (bnum);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, OBP_BOARDNUM,
	    (caddr_t)&bnum, &len) != DDI_PROP_SUCCESS) {
		bnum = -1;
	}

	if (strcmp(name, "cmp") == 0) {
		if (bnum != p->bp->bnum)
			return (DDI_WALK_PRUNECHILD);
		return (DDI_WALK_CONTINUE);
	}
	/* we have already pruned all unwanted cores and cpu's above */
	if (strcmp(name, "core") == 0) {
		return (DDI_WALK_CONTINUE);
	}
	if (strcmp(name, "cpu") == 0) {
		processorid_t cpuid;
		len = sizeof (cpuid);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "cpuid",
		    (caddr_t)&cpuid, &len) != DDI_PROP_SUCCESS) {
			return (DDI_WALK_TERMINATE);
		}
		bnum = LSB_ID(cpuid);
		ASSERT(bnum == p->bp->bnum);
		core_id = ON_BOARD_CORE_NUM(cpuid);
		strand_id = STRAND_ID(cpuid);
		p->bp->cores[core_id].core_present |= (1 << strand_id);
		return (DDI_WALK_CONTINUE);
	}

	return (DDI_WALK_PRUNECHILD);
}


static void
drmach_setup_core_info(drmach_board_t *obj)
{
	struct drmach_setup_core_arg arg;
	int i;

	for (i = 0; i < OPL_MAX_COREID_PER_BOARD; i++) {
		obj->cores[i].core_present = 0;
		obj->cores[i].core_hotadded = 0;
		obj->cores[i].core_started = 0;
	}
	arg.bp = obj;
	ddi_walk_devs(ddi_root_node(), drmach_setup_core_cb, (void *)&arg);

	for (i = 0; i < OPL_MAX_COREID_PER_BOARD; i++) {
		if (obj->boot_board) {
			obj->cores[i].core_hotadded =
			    obj->cores[i].core_started =
			    obj->cores[i].core_present;
		}
	}
}

/*
 * drmach_node_* routines serve the purpose of separating the
 * rest of the code from the device tree and OBP.  This is necessary
 * because of In-Kernel-Probing.  Devices probed after stod, are probed
 * by the in-kernel-prober, not OBP.  These devices, therefore, do not
 * have dnode ids.
 */

typedef struct {
	drmach_node_walk_args_t	*nwargs;
	int			(*cb)(drmach_node_walk_args_t *args);
	int			err;
} drmach_node_ddi_walk_args_t;

static int
drmach_node_ddi_walk_cb(dev_info_t *dip, void *arg)
{
	drmach_node_ddi_walk_args_t	*nargs;

	nargs = (drmach_node_ddi_walk_args_t *)arg;

	/*
	 * dip doesn't have to be held here as we are called
	 * from ddi_walk_devs() which holds the dip.
	 */
	nargs->nwargs->node->here = (void *)dip;

	nargs->err = nargs->cb(nargs->nwargs);


	/*
	 * Set "here" to NULL so that unheld dip is not accessible
	 * outside ddi_walk_devs()
	 */
	nargs->nwargs->node->here = NULL;

	if (nargs->err)
		return (DDI_WALK_TERMINATE);
	else
		return (DDI_WALK_CONTINUE);
}

static int
drmach_node_ddi_walk(drmach_node_t *np, void *data,
    int (*cb)(drmach_node_walk_args_t *args))
{
	drmach_node_walk_args_t		args;
	drmach_node_ddi_walk_args_t	nargs;


	/* initialized args structure for callback */
	args.node = np;
	args.data = data;

	nargs.nwargs = &args;
	nargs.cb = cb;
	nargs.err = 0;

	/*
	 * Root node doesn't have to be held in any way.
	 */
	ddi_walk_devs(ddi_root_node(), drmach_node_ddi_walk_cb, (void *)&nargs);

	return (nargs.err);
}

static int
drmach_node_ddi_get_parent(drmach_node_t *np, drmach_node_t *pp)
{
	dev_info_t	*ndip;
	static char	*fn = "drmach_node_ddi_get_parent";

	ndip = np->n_getdip(np);
	if (ndip == NULL) {
		cmn_err(CE_WARN, "%s: NULL dip", fn);
		return (-1);
	}

	bcopy(np, pp, sizeof (drmach_node_t));

	pp->here = (void *)ddi_get_parent(ndip);
	if (pp->here == NULL) {
		cmn_err(CE_WARN, "%s: NULL parent dip", fn);
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
static pnode_t
drmach_node_ddi_get_dnode(drmach_node_t *np)
{
	return (0);
}

static drmach_node_t *
drmach_node_new(void)
{
	drmach_node_t *np;

	np = kmem_zalloc(sizeof (drmach_node_t), KM_SLEEP);

	np->get_dnode = drmach_node_ddi_get_dnode;
	np->walk = drmach_node_ddi_walk;
	np->n_getdip = drmach_node_ddi_get_dip;
	np->n_getproplen = drmach_node_ddi_get_proplen;
	np->n_getprop = drmach_node_ddi_get_prop;
	np->get_parent = drmach_node_ddi_get_parent;

	return (np);
}

static void
drmach_node_dispose(drmach_node_t *np)
{
	kmem_free(np, sizeof (*np));
}

static dev_info_t *
drmach_node_ddi_get_dip(drmach_node_t *np)
{
	return ((dev_info_t *)np->here);
}

static int
drmach_node_walk(drmach_node_t *np, void *param,
    int (*cb)(drmach_node_walk_args_t *args))
{
	return (np->walk(np, param, cb));
}

static int
drmach_node_ddi_get_prop(drmach_node_t *np, char *name, void *buf, int len)
{
	int		rv = 0;
	dev_info_t	*ndip;
	static char	*fn = "drmach_node_ddi_get_prop";


	ndip = np->n_getdip(np);
	if (ndip == NULL) {
		cmn_err(CE_WARN, "%s: NULL dip", fn);
		rv = -1;
	} else if (ddi_getlongprop_buf(DDI_DEV_T_ANY, ndip,
	    DDI_PROP_DONTPASS, name,
	    (caddr_t)buf, &len) != DDI_PROP_SUCCESS) {
		rv = -1;
	}

	return (rv);
}

static int
drmach_node_ddi_get_proplen(drmach_node_t *np, char *name, int *len)
{
	int		rv = 0;
	dev_info_t	*ndip;

	ndip = np->n_getdip(np);
	if (ndip == NULL) {
		rv = -1;
	} else if (ddi_getproplen(DDI_DEV_T_ANY, ndip, DDI_PROP_DONTPASS, name,
	    len) != DDI_PROP_SUCCESS) {
		rv = -1;
	}

	return (rv);
}

static drmachid_t
drmach_node_dup(drmach_node_t *np)
{
	drmach_node_t *dup;

	dup = drmach_node_new();
	dup->here = np->here;
	dup->get_dnode = np->get_dnode;
	dup->walk = np->walk;
	dup->n_getdip = np->n_getdip;
	dup->n_getproplen = np->n_getproplen;
	dup->n_getprop = np->n_getprop;
	dup->get_parent = np->get_parent;

	return (dup);
}

/*
 * drmach_array provides convenient array construction, access,
 * bounds checking and array destruction logic.
 */

static drmach_array_t *
drmach_array_new(int min_index, int max_index)
{
	drmach_array_t *arr;

	arr = kmem_zalloc(sizeof (drmach_array_t), KM_SLEEP);

	arr->arr_sz = (max_index - min_index + 1) * sizeof (void *);
	if (arr->arr_sz > 0) {
		arr->min_index = min_index;
		arr->max_index = max_index;

		arr->arr = kmem_zalloc(arr->arr_sz, KM_SLEEP);
		return (arr);
	} else {
		kmem_free(arr, sizeof (*arr));
		return (0);
	}
}

static int
drmach_array_set(drmach_array_t *arr, int idx, drmachid_t val)
{
	if (idx < arr->min_index || idx > arr->max_index)
		return (-1);
	else {
		arr->arr[idx - arr->min_index] = val;
		return (0);
	}
	/*NOTREACHED*/
}

static int
drmach_array_get(drmach_array_t *arr, int idx, drmachid_t *val)
{
	if (idx < arr->min_index || idx > arr->max_index)
		return (-1);
	else {
		*val = arr->arr[idx - arr->min_index];
		return (0);
	}
	/*NOTREACHED*/
}

static int
drmach_array_first(drmach_array_t *arr, int *idx, drmachid_t *val)
{
	int rv;

	*idx = arr->min_index;
	while ((rv = drmach_array_get(arr, *idx, val)) == 0 && *val == NULL)
		*idx += 1;

	return (rv);
}

static int
drmach_array_next(drmach_array_t *arr, int *idx, drmachid_t *val)
{
	int rv;

	*idx += 1;
	while ((rv = drmach_array_get(arr, *idx, val)) == 0 && *val == NULL)
		*idx += 1;

	return (rv);
}

static void
drmach_array_dispose(drmach_array_t *arr, void (*disposer)(drmachid_t))
{
	drmachid_t	val;
	int		idx;
	int		rv;

	rv = drmach_array_first(arr, &idx, &val);
	while (rv == 0) {
		(*disposer)(val);
		rv = drmach_array_next(arr, &idx, &val);
	}

	kmem_free(arr->arr, arr->arr_sz);
	kmem_free(arr, sizeof (*arr));
}

static drmach_board_t *
drmach_get_board_by_bnum(int bnum)
{
	drmachid_t id;

	if (drmach_array_get(drmach_boards, bnum, &id) == 0)
		return ((drmach_board_t *)id);
	else
		return (NULL);
}

static pnode_t
drmach_node_get_dnode(drmach_node_t *np)
{
	return (np->get_dnode(np));
}

/*ARGSUSED*/
sbd_error_t *
drmach_configure(drmachid_t id, int flags)
{
	drmach_device_t		*dp;
	sbd_error_t		*err = NULL;
	dev_info_t		*rdip;
	dev_info_t		*fdip = NULL;

	if (DRMACH_IS_CPU_ID(id)) {
		return (NULL);
	}
	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	dp = id;
	rdip = dp->node->n_getdip(dp->node);

	ASSERT(rdip);

	ASSERT(e_ddi_branch_held(rdip));

	if (e_ddi_branch_configure(rdip, &fdip, 0) != 0) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		dev_info_t *dip = (fdip != NULL) ? fdip : rdip;

		(void) ddi_pathname(dip, path);
		err = drerr_new(1,  EOPL_DRVFAIL, path);

		kmem_free(path, MAXPATHLEN);

		/* If non-NULL, fdip is returned held and must be released */
		if (fdip != NULL)
			ddi_release_devi(fdip);
	}

	return (err);
}


static sbd_error_t *
drmach_device_new(drmach_node_t *node,
    drmach_board_t *bp, int portid, drmachid_t *idp)
{
	int		 i;
	int		 rv;
	drmach_device_t	proto;
	sbd_error_t	*err;
	char		 name[OBP_MAXDRVNAME];

	rv = node->n_getprop(node, "name", name, OBP_MAXDRVNAME);
	if (rv) {
		/* every node is expected to have a name */
		err = drerr_new(1, EOPL_GETPROP, "device node %s: property %s",
		    ddi_node_name(node->n_getdip(node)), "name");
		return (err);
	}

	/*
	 * The node currently being examined is not listed in the name2type[]
	 * array.  In this case, the node is no interest to drmach.  Both
	 * dp and err are initialized here to yield nothing (no device or
	 * error structure) for this case.
	 */
	i = drmach_name2type_idx(name);


	if (i < 0) {
		*idp = (drmachid_t)0;
		return (NULL);
	}

	/* device specific new function will set unum */

	bzero(&proto, sizeof (proto));
	proto.type = drmach_name2type[i].type;
	proto.bp = bp;
	proto.node = node;
	proto.portid = portid;

	return (drmach_name2type[i].new(&proto, idp));
}

static void
drmach_device_dispose(drmachid_t id)
{
	drmach_device_t *self = id;

	self->cm.dispose(id);
}


static drmach_board_t *
drmach_board_new(int bnum, int boot_board)
{
	drmach_board_t	*bp;

	bp = kmem_zalloc(sizeof (drmach_board_t), KM_SLEEP);

	bp->cm.isa = (void *)drmach_board_new;
	bp->cm.release = drmach_board_release;
	bp->cm.status = drmach_board_status;

	(void) drmach_board_name(bnum, bp->cm.name, sizeof (bp->cm.name));

	bp->bnum = bnum;
	bp->devices = NULL;
	bp->connected = boot_board;
	bp->tree = drmach_node_new();
	bp->assigned = boot_board;
	bp->powered = boot_board;
	bp->boot_board = boot_board;

	/*
	 * If this is not bootup initialization, we have to wait till
	 * IKP sets up the device nodes in drmach_board_connect().
	 */
	if (boot_board)
		drmach_setup_core_info(bp);

	(void) drmach_array_set(drmach_boards, bnum, bp);
	return (bp);
}

static void
drmach_board_dispose(drmachid_t id)
{
	drmach_board_t *bp;

	ASSERT(DRMACH_IS_BOARD_ID(id));
	bp = id;

	if (bp->tree)
		drmach_node_dispose(bp->tree);

	if (bp->devices)
		drmach_array_dispose(bp->devices, drmach_device_dispose);

	kmem_free(bp, sizeof (*bp));
}

static sbd_error_t *
drmach_board_status(drmachid_t id, drmach_status_t *stat)
{
	sbd_error_t	*err = NULL;
	drmach_board_t	*bp;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	bp = id;

	stat->assigned = bp->assigned;
	stat->powered = bp->powered;
	stat->busy = 0;			/* assume not busy */
	stat->configured = 0;		/* assume not configured */
	stat->empty = 0;
	stat->cond = bp->cond = SBD_COND_OK;
	(void) strncpy(stat->type, "System Brd", sizeof (stat->type));
	stat->info[0] = '\0';

	if (bp->devices) {
		int		 rv;
		int		 d_idx;
		drmachid_t	 d_id;

		rv = drmach_array_first(bp->devices, &d_idx, &d_id);
		while (rv == 0) {
			drmach_status_t	d_stat;

			err = drmach_i_status(d_id, &d_stat);
			if (err)
				break;

			stat->busy |= d_stat.busy;
			stat->configured |= d_stat.configured;

			rv = drmach_array_next(bp->devices, &d_idx, &d_id);
		}
	}

	return (err);
}

int
drmach_board_is_floating(drmachid_t id)
{
	drmach_board_t *bp;

	if (!DRMACH_IS_BOARD_ID(id))
		return (0);

	bp = (drmach_board_t *)id;

	return ((drmach_domain.floating & (1 << bp->bnum)) ? 1 : 0);
}

static int
drmach_init(void)
{
	dev_info_t	*rdip;
	int		i, rv, len;
	int		*floating;

	rw_init(&drmach_boards_rwlock, NULL, RW_DEFAULT, NULL);

	drmach_boards = drmach_array_new(0, MAX_BOARDS - 1);

	rdip = ddi_root_node();

	if (ddi_getproplen(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
	    "floating-boards", &len) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "Cannot get floating-boards proplen\n");
	} else {
		floating = (int *)kmem_alloc(len, KM_SLEEP);
		rv = ddi_prop_op(DDI_DEV_T_ANY, rdip, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_DONTPASS, "floating-boards", (caddr_t)floating,
		    &len);
		if (rv != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "Cannot get floating-boards prop\n");
		} else {
			drmach_domain.floating = 0;
			for (i = 0; i < len / sizeof (int); i++) {
				drmach_domain.floating |= (1 << floating[i]);
			}
		}
		kmem_free(floating, len);
	}
	drmach_domain.allow_dr = opl_check_dr_status();

	rdip = ddi_get_child(ddi_root_node());
	do {
		int		 bnum;
		drmachid_t	 id;

		bnum = -1;
		bnum = ddi_getprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
		    OBP_BOARDNUM, -1);
		if (bnum == -1)
			continue;

		if (drmach_array_get(drmach_boards, bnum, &id) == -1) {
			cmn_err(CE_WARN, "Device node 0x%p has invalid "
			    "property value, %s=%d", (void *)rdip,
			    OBP_BOARDNUM, bnum);
			goto error;
		} else if (id == NULL) {
			(void) drmach_board_new(bnum, 1);
		}
	} while ((rdip = ddi_get_next_sibling(rdip)) != NULL);

	opl_hold_devtree();

	/*
	 * Initialize the IKP feature.
	 *
	 * This can be done only after DR has acquired a hold on all the
	 * device nodes that are interesting to IKP.
	 */
	if (opl_init_cfg() != 0) {
		cmn_err(CE_WARN, "DR - IKP initialization failed");

		opl_release_devtree();

		goto error;
	}

	return (0);
error:
	drmach_array_dispose(drmach_boards, drmach_board_dispose);
	rw_destroy(&drmach_boards_rwlock);
	return (ENXIO);
}

static void
drmach_fini(void)
{
	rw_enter(&drmach_boards_rwlock, RW_WRITER);
	drmach_array_dispose(drmach_boards, drmach_board_dispose);
	drmach_boards = NULL;
	rw_exit(&drmach_boards_rwlock);

	/*
	 * Walk immediate children of the root devinfo node
	 * releasing holds acquired on branches in drmach_init()
	 */

	opl_release_devtree();

	rw_destroy(&drmach_boards_rwlock);
}

/*
 *	Each system board contains 2 Oberon PCI bridge and
 *	1 CMUCH.
 *	Each oberon has 2 channels.
 *	Each channel has 2 pci-ex leaf.
 *	Each CMUCH has 1 pci bus.
 *
 *
 *	Device Path:
 *	/pci@<portid>,reg
 *
 *	where
 *	portid[10] = 0
 *	portid[9:0] = LLEAF_ID[9:0] of the Oberon Channel
 *
 *	LLEAF_ID[9:8] = 0
 *	LLEAF_ID[8:4] = LSB_ID[4:0]
 *	LLEAF_ID[3:1] = IO Channel#[2:0] (0,1,2,3 for Oberon)
 *			channel 4 is pcicmu
 *	LLEAF_ID[0] = PCI Leaf Number (0 for leaf-A, 1 for leaf-B)
 *
 *	Properties:
 *	name = pci
 *	device_type = "pciex"
 *	board# = LSBID
 *	reg = int32 * 2, Oberon CSR space of the leaf and the UBC space
 *	portid = Jupiter Bus Device ID ((LSB_ID << 3)|pciport#)
 */

static sbd_error_t *
drmach_io_new(drmach_device_t *proto, drmachid_t *idp)
{
	drmach_io_t	*ip;

	int		 portid;

	portid = proto->portid;
	ASSERT(portid != -1);
	proto->unum = portid & (MAX_IO_UNITS_PER_BOARD - 1);

	ip = kmem_zalloc(sizeof (drmach_io_t), KM_SLEEP);
	bcopy(proto, &ip->dev, sizeof (ip->dev));
	ip->dev.node = drmach_node_dup(proto->node);
	ip->dev.cm.isa = (void *)drmach_io_new;
	ip->dev.cm.dispose = drmach_io_dispose;
	ip->dev.cm.release = drmach_io_release;
	ip->dev.cm.status = drmach_io_status;
	ip->channel = (portid >> 1) & 0x7;
	ip->leaf = (portid & 0x1);

	(void) snprintf(ip->dev.cm.name, sizeof (ip->dev.cm.name), "%s%d",
	    ip->dev.type, ip->dev.unum);

	*idp = (drmachid_t)ip;
	return (NULL);
}


static void
drmach_io_dispose(drmachid_t id)
{
	drmach_io_t *self;

	ASSERT(DRMACH_IS_IO_ID(id));

	self = id;
	if (self->dev.node)
		drmach_node_dispose(self->dev.node);

	kmem_free(self, sizeof (*self));
}

/*ARGSUSED*/
sbd_error_t *
drmach_pre_op(int cmd, drmachid_t id, drmach_opts_t *opts)
{
	drmach_board_t	*bp = (drmach_board_t *)id;
	sbd_error_t	*err = NULL;

	/* allow status and ncm operations to always succeed */
	if ((cmd == SBD_CMD_STATUS) || (cmd == SBD_CMD_GETNCM)) {
		return (NULL);
	}

	/* check all other commands for the required option string */

	if ((opts->size > 0) && (opts->copts != NULL)) {

		DRMACH_PR("platform options: %s\n", opts->copts);

		if (strstr(opts->copts, "opldr") == NULL) {
			err = drerr_new(1, EOPL_SUPPORT, NULL);
		}
	} else {
		err = drerr_new(1, EOPL_SUPPORT, NULL);
	}

	if (!err && id && DRMACH_IS_BOARD_ID(id)) {
		switch (cmd) {
			case SBD_CMD_TEST:
			case SBD_CMD_STATUS:
			case SBD_CMD_GETNCM:
				break;
			case SBD_CMD_CONNECT:
				if (bp->connected)
					err = drerr_new(0, ESBD_STATE, NULL);
				else if (!drmach_domain.allow_dr)
					err = drerr_new(1, EOPL_SUPPORT, NULL);
				break;
			case SBD_CMD_DISCONNECT:
				if (!bp->connected)
					err = drerr_new(0, ESBD_STATE, NULL);
				else if (!drmach_domain.allow_dr)
					err = drerr_new(1, EOPL_SUPPORT, NULL);
				break;
			default:
				if (!drmach_domain.allow_dr)
					err = drerr_new(1, EOPL_SUPPORT, NULL);
				break;

		}
	}

	return (err);
}

/*ARGSUSED*/
sbd_error_t *
drmach_post_op(int cmd, drmachid_t id, drmach_opts_t *opts)
{
	return (NULL);
}

sbd_error_t *
drmach_board_assign(int bnum, drmachid_t *id)
{
	sbd_error_t	*err = NULL;

	rw_enter(&drmach_boards_rwlock, RW_WRITER);

	if (drmach_array_get(drmach_boards, bnum, id) == -1) {
		err = drerr_new(1, EOPL_BNUM, "%d", bnum);
	} else {
		drmach_board_t	*bp;

		if (*id)
			rw_downgrade(&drmach_boards_rwlock);

		bp = *id;
		if (!(*id))
			bp = *id  =
			    (drmachid_t)drmach_board_new(bnum, 0);
		bp->assigned = 1;
	}

	rw_exit(&drmach_boards_rwlock);

	return (err);
}

/*ARGSUSED*/
sbd_error_t *
drmach_board_connect(drmachid_t id, drmach_opts_t *opts)
{
	extern int	cpu_alljupiter;
	drmach_board_t	*obj = (drmach_board_t *)id;
	unsigned	cpu_impl;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	if (opl_probe_sb(obj->bnum, &cpu_impl) != 0)
		return (drerr_new(1, EOPL_PROBE, NULL));

	if (cpu_alljupiter) {
		if (cpu_impl & (1 << OLYMPUS_C_IMPL)) {
			(void) opl_unprobe_sb(obj->bnum);
			return (drerr_new(1, EOPL_MIXED_CPU, NULL));
		}
	}

	(void) prom_attach_notice(obj->bnum);

	drmach_setup_core_info(obj);

	obj->connected = 1;

	return (NULL);
}

static int drmach_cache_flush_flag[NCPU];

/*ARGSUSED*/
static void
drmach_flush_cache(uint64_t id, uint64_t dummy)
{
	extern void cpu_flush_ecache(void);

	cpu_flush_ecache();
	drmach_cache_flush_flag[id] = 0;
}

static void
drmach_flush_all()
{
	cpuset_t	xc_cpuset;
	int		i;

	xc_cpuset = cpu_ready_set;
	for (i = 0; i < NCPU; i++) {
		if (CPU_IN_SET(xc_cpuset, i)) {
			drmach_cache_flush_flag[i] = 1;
			xc_one(i, drmach_flush_cache, i, 0);
			while (drmach_cache_flush_flag[i]) {
				DELAY(1000);
			}
		}
	}
}

static int
drmach_disconnect_cpus(drmach_board_t *bp)
{
	int i, bnum;

	bnum = bp->bnum;

	for (i = 0; i < OPL_MAX_COREID_PER_BOARD; i++) {
		if (bp->cores[i].core_present) {
			if (bp->cores[i].core_started)
				return (-1);
			if (bp->cores[i].core_hotadded) {
				if (drmach_add_remove_cpu(bnum, i,
				    HOTREMOVE_CPU)) {
					cmn_err(CE_WARN, "Failed to remove "
					    "CMP %d on board %d\n", i, bnum);
					return (-1);
				}
			}
		}
	}
	return (0);
}

/*ARGSUSED*/
sbd_error_t *
drmach_board_disconnect(drmachid_t id, drmach_opts_t *opts)
{
	drmach_board_t *obj;
	int rv = 0;
	sbd_error_t		*err = NULL;

	if (DRMACH_NULL_ID(id))
		return (NULL);

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	obj = (drmach_board_t *)id;

	if (drmach_disconnect_cpus(obj)) {
		err = drerr_new(1, EOPL_DEPROBE, obj->cm.name);
		return (err);
	}

	rv = opl_unprobe_sb(obj->bnum);

	if (rv == 0) {
		(void) prom_detach_notice(obj->bnum);
		obj->connected = 0;

	} else
		err = drerr_new(1, EOPL_DEPROBE, obj->cm.name);

	return (err);
}

static int
drmach_get_portid(drmach_node_t *np)
{
	int		portid;
	char		type[OBP_MAXPROPNAME];

	if (np->n_getprop(np, "portid", &portid, sizeof (portid)) == 0)
		return (portid);

	/*
	 * Get the device_type property to see if we should
	 * continue processing this node.
	 */
	if (np->n_getprop(np, "device_type", &type, sizeof (type)) != 0)
		return (-1);

	if (strcmp(type, OPL_CPU_NODE) == 0) {
		/*
		 * We return cpuid because it has no portid
		 */
		if (np->n_getprop(np, "cpuid", &portid, sizeof (portid)) == 0)
			return (portid);
	}

	return (-1);
}

/*
 * This is a helper function to determine if a given
 * node should be considered for a dr operation according
 * to predefined dr type nodes and the node's name.
 * Formal Parameter : The name of a device node.
 * Return Value: -1, name does not map to a valid dr type.
 *		 A value greater or equal to 0, name is a valid dr type.
 */
static int
drmach_name2type_idx(char *name)
{
	int	index, ntypes;

	if (name == NULL)
		return (-1);

	/*
	 * Determine how many possible types are currently supported
	 * for dr.
	 */
	ntypes = sizeof (drmach_name2type) / sizeof (drmach_name2type[0]);

	/* Determine if the node's name correspond to a predefined type. */
	for (index = 0; index < ntypes; index++) {
		if (strcmp(drmach_name2type[index].name, name) == 0)
			/* The node is an allowed type for dr. */
			return (index);
	}

	/*
	 * If the name of the node does not map to any of the
	 * types in the array drmach_name2type then the node is not of
	 * interest to dr.
	 */
	return (-1);
}

/*
 * there is some complication on OPL:
 * - pseudo-mc nodes do not have portid property
 * - portid[9:5] of cmp node is LSB #, portid[7:3] of pci is LSB#
 * - cmp has board#
 * - core and cpu nodes do not have portid and board# properties
 * starcat uses portid to derive the board# but that does not work
 * for us.  starfire reads board# property to filter the devices.
 * That does not work either.  So for these specific device,
 * we use specific hard coded methods to get the board# -
 * cpu: LSB# = CPUID[9:5]
 */

static int
drmach_board_find_devices_cb(drmach_node_walk_args_t *args)
{
	drmach_node_t			*node = args->node;
	drmach_board_cb_data_t		*data = args->data;
	drmach_board_t			*obj = data->obj;

	int		rv, portid;
	int		bnum;
	drmachid_t	id;
	drmach_device_t	*device;
	char name[OBP_MAXDRVNAME];

	portid = drmach_get_portid(node);
	/*
	 * core, cpu and pseudo-mc do not have portid
	 * we use cpuid as the portid of the cpu node
	 * for pseudo-mc, we do not use portid info.
	 */

	rv = node->n_getprop(node, "name", name, OBP_MAXDRVNAME);
	if (rv)
		return (0);


	rv = node->n_getprop(node, OBP_BOARDNUM, &bnum, sizeof (bnum));

	if (rv) {
		/*
		 * cpu does not have board# property.  We use
		 * CPUID[9:5]
		 */
		if (strcmp("cpu", name) == 0) {
			bnum = (portid >> 5) & 0x1f;
		} else
			return (0);
	}


	if (bnum != obj->bnum)
		return (0);

	if (drmach_name2type_idx(name) < 0) {
		return (0);
	}

	/*
	 * Create a device data structure from this node data.
	 * The call may yield nothing if the node is not of interest
	 * to drmach.
	 */
	data->err = drmach_device_new(node, obj, portid, &id);
	if (data->err)
		return (-1);
	else if (!id) {
		/*
		 * drmach_device_new examined the node we passed in
		 * and determined that it was one not of interest to
		 * drmach.  So, it is skipped.
		 */
		return (0);
	}

	rv = drmach_array_set(obj->devices, data->ndevs++, id);
	if (rv) {
		data->err = DRMACH_INTERNAL_ERROR();
		return (-1);
	}
	device = id;

	data->err = (*data->found)(data->a, device->type, device->unum, id);
	return (data->err == NULL ? 0 : -1);
}

sbd_error_t *
drmach_board_find_devices(drmachid_t id, void *a,
    sbd_error_t *(*found)(void *a, const char *, int, drmachid_t))
{
	drmach_board_t		*bp = (drmach_board_t *)id;
	sbd_error_t		*err;
	int			 max_devices;
	int			 rv;
	drmach_board_cb_data_t	data;


	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	max_devices  = MAX_CPU_UNITS_PER_BOARD;
	max_devices += MAX_MEM_UNITS_PER_BOARD;
	max_devices += MAX_IO_UNITS_PER_BOARD;

	bp->devices = drmach_array_new(0, max_devices);

	if (bp->tree == NULL)
		bp->tree = drmach_node_new();

	data.obj = bp;
	data.ndevs = 0;
	data.found = found;
	data.a = a;
	data.err = NULL;

	rv = drmach_node_walk(bp->tree, &data, drmach_board_find_devices_cb);
	if (rv == 0)
		err = NULL;
	else {
		drmach_array_dispose(bp->devices, drmach_device_dispose);
		bp->devices = NULL;

		if (data.err)
			err = data.err;
		else
			err = DRMACH_INTERNAL_ERROR();
	}

	return (err);
}

int
drmach_board_lookup(int bnum, drmachid_t *id)
{
	int	rv = 0;

	rw_enter(&drmach_boards_rwlock, RW_READER);
	if (drmach_array_get(drmach_boards, bnum, id)) {
		*id = 0;
		rv = -1;
	}
	rw_exit(&drmach_boards_rwlock);
	return (rv);
}

sbd_error_t *
drmach_board_name(int bnum, char *buf, int buflen)
{
	(void) snprintf(buf, buflen, "SB%d", bnum);
	return (NULL);
}

sbd_error_t *
drmach_board_poweroff(drmachid_t id)
{
	drmach_board_t	*bp;
	sbd_error_t	*err;
	drmach_status_t	 stat;

	if (DRMACH_NULL_ID(id))
		return (NULL);

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	bp = id;

	err = drmach_board_status(id, &stat);

	if (!err) {
		if (stat.configured || stat.busy)
			err = drerr_new(0, EOPL_CONFIGBUSY, bp->cm.name);
		else {
			bp->powered = 0;
		}
	}
	return (err);
}

sbd_error_t *
drmach_board_poweron(drmachid_t id)
{
	drmach_board_t	*bp;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	bp = id;

	bp->powered = 1;

	return (NULL);
}

static sbd_error_t *
drmach_board_release(drmachid_t id)
{
	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	return (NULL);
}

/*ARGSUSED*/
sbd_error_t *
drmach_board_test(drmachid_t id, drmach_opts_t *opts, int force)
{
	return (NULL);
}

sbd_error_t *
drmach_board_unassign(drmachid_t id)
{
	drmach_board_t	*bp;
	sbd_error_t	*err;
	drmach_status_t	 stat;

	if (DRMACH_NULL_ID(id))
		return (NULL);

	if (!DRMACH_IS_BOARD_ID(id)) {
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	}
	bp = id;

	rw_enter(&drmach_boards_rwlock, RW_WRITER);

	err = drmach_board_status(id, &stat);
	if (err) {
		rw_exit(&drmach_boards_rwlock);
		return (err);
	}
	if (stat.configured || stat.busy) {
		err = drerr_new(0, EOPL_CONFIGBUSY, bp->cm.name);
	} else {
		if (drmach_array_set(drmach_boards, bp->bnum, 0) != 0)
			err = DRMACH_INTERNAL_ERROR();
		else
			drmach_board_dispose(bp);
	}
	rw_exit(&drmach_boards_rwlock);
	return (err);
}

/*
 * We have to do more on OPL - e.g. set up sram tte, read cpuid, strand id,
 * implementation #, etc
 */

static sbd_error_t *
drmach_cpu_new(drmach_device_t *proto, drmachid_t *idp)
{
	int		 portid;
	drmach_cpu_t	*cp = NULL;

	/* portid is CPUID of the node */
	portid = proto->portid;
	ASSERT(portid != -1);

	/* unum = (CMP/CHIP ID) + (ON_BOARD_CORE_NUM * MAX_CMPID_PER_BOARD) */
	proto->unum = ((portid/OPL_MAX_CPUID_PER_CMP) &
	    (OPL_MAX_CMPID_PER_BOARD - 1)) +
	    ((portid & (OPL_MAX_CPUID_PER_CMP - 1)) *
	    (OPL_MAX_CMPID_PER_BOARD));

	cp = kmem_zalloc(sizeof (drmach_cpu_t), KM_SLEEP);
	bcopy(proto, &cp->dev, sizeof (cp->dev));
	cp->dev.node = drmach_node_dup(proto->node);
	cp->dev.cm.isa = (void *)drmach_cpu_new;
	cp->dev.cm.dispose = drmach_cpu_dispose;
	cp->dev.cm.release = drmach_cpu_release;
	cp->dev.cm.status = drmach_cpu_status;

	(void) snprintf(cp->dev.cm.name, sizeof (cp->dev.cm.name), "%s%d",
	    cp->dev.type, cp->dev.unum);

/*
 *	CPU ID representation
 *	CPUID[9:5] = SB#
 *	CPUID[4:3] = Chip#
 *	CPUID[2:1] = Core# (Only 2 core for OPL)
 *	CPUID[0:0] = Strand#
 */

/*
 *	reg property of the strand contains strand ID
 *	reg property of the parent node contains core ID
 *	We should use them.
 */
	cp->cpuid = portid;
	cp->sb = (portid >> 5) & 0x1f;
	cp->chipid = (portid >> 3) & 0x3;
	cp->coreid = (portid >> 1) & 0x3;
	cp->strandid = portid & 0x1;

	*idp = (drmachid_t)cp;
	return (NULL);
}


static void
drmach_cpu_dispose(drmachid_t id)
{
	drmach_cpu_t	*self;

	ASSERT(DRMACH_IS_CPU_ID(id));

	self = id;
	if (self->dev.node)
		drmach_node_dispose(self->dev.node);

	kmem_free(self, sizeof (*self));
}

static int
drmach_cpu_start(struct cpu *cp)
{
	int		cpuid = cp->cpu_id;
	extern int	restart_other_cpu(int);

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpunodes[cpuid].nodeid != (pnode_t)0);

	cp->cpu_flags &= ~CPU_POWEROFF;

	/*
	 * NOTE: restart_other_cpu pauses cpus during the
	 *	 slave cpu start.  This helps to quiesce the
	 *	 bus traffic a bit which makes the tick sync
	 *	 routine in the prom more robust.
	 */
	DRMACH_PR("COLD START for cpu (%d)\n", cpuid);

	(void) restart_other_cpu(cpuid);

	return (0);
}

static sbd_error_t *
drmach_cpu_release(drmachid_t id)
{
	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	return (NULL);
}

static sbd_error_t *
drmach_cpu_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_cpu_t *cp;
	drmach_device_t *dp;

	ASSERT(DRMACH_IS_CPU_ID(id));
	cp = (drmach_cpu_t *)id;
	dp = &cp->dev;

	stat->assigned = dp->bp->assigned;
	stat->powered = dp->bp->powered;
	mutex_enter(&cpu_lock);
	stat->configured = (cpu_get(cp->cpuid) != NULL);
	mutex_exit(&cpu_lock);
	stat->busy = dp->busy;
	(void) strncpy(stat->type, dp->type, sizeof (stat->type));
	stat->info[0] = '\0';

	return (NULL);
}

sbd_error_t *
drmach_cpu_disconnect(drmachid_t id)
{

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	return (NULL);
}

sbd_error_t *
drmach_cpu_get_id(drmachid_t id, processorid_t *cpuid)
{
	drmach_cpu_t *cpu;

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	cpu = (drmach_cpu_t *)id;

	/* get from cpu directly on OPL */
	*cpuid = cpu->cpuid;
	return (NULL);
}

sbd_error_t *
drmach_cpu_get_impl(drmachid_t id, int *ip)
{
	drmach_device_t *cpu;
	drmach_node_t	*np;
	drmach_node_t	pp;
	int		impl;
	char		type[OBP_MAXPROPNAME];

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	cpu = id;
	np = cpu->node;

	if (np->get_parent(np, &pp) != 0) {
		return (DRMACH_INTERNAL_ERROR());
	}

	/* the parent should be core */

	if (pp.n_getprop(&pp, "device_type", &type, sizeof (type)) != 0) {
		return (drerr_new(0, EOPL_GETPROP, NULL));
	}

	if (strcmp(type, OPL_CORE_NODE) == 0) {
		if (pp.n_getprop(&pp, "implementation#", &impl,
		    sizeof (impl)) != 0) {
			return (drerr_new(0, EOPL_GETPROP, NULL));
		}
	} else {
		return (DRMACH_INTERNAL_ERROR());
	}

	*ip = impl;

	return (NULL);
}

sbd_error_t *
drmach_get_dip(drmachid_t id, dev_info_t **dip)
{
	drmach_device_t	*dp;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	dp = id;

	*dip = dp->node->n_getdip(dp->node);
	return (NULL);
}

sbd_error_t *
drmach_io_is_attached(drmachid_t id, int *yes)
{
	drmach_device_t *dp;
	dev_info_t	*dip;
	int		state;

	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	dp = id;

	dip = dp->node->n_getdip(dp->node);
	if (dip == NULL) {
		*yes = 0;
		return (NULL);
	}

	state = ddi_get_devstate(dip);
	*yes = ((i_ddi_node_state(dip) >= DS_ATTACHED) ||
	    (state == DDI_DEVSTATE_UP));

	return (NULL);
}

struct drmach_io_cb {
	char	*name;	/* name of the node */
	int	(*func)(dev_info_t *);
	int	rv;
	dev_info_t *dip;
};

#define	DRMACH_IO_POST_ATTACH	0
#define	DRMACH_IO_PRE_RELEASE	1

static int
drmach_io_cb_check(dev_info_t *dip, void *arg)
{
	struct drmach_io_cb *p = (struct drmach_io_cb *)arg;
	char name[OBP_MAXDRVNAME];
	int len = OBP_MAXDRVNAME;

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "name",
	    (caddr_t)name, &len) != DDI_PROP_SUCCESS) {
		return (DDI_WALK_PRUNECHILD);
	}

	if (strcmp(name, p->name) == 0) {
		ndi_hold_devi(dip);
		p->dip = dip;
		return (DDI_WALK_TERMINATE);
	}

	return (DDI_WALK_CONTINUE);
}


static int
drmach_console_ops(drmachid_t *id, int state)
{
	drmach_io_t *obj = (drmach_io_t *)id;
	struct drmach_io_cb arg;
	int (*msudetp)(dev_info_t *);
	int (*msuattp)(dev_info_t *);
	dev_info_t *dip, *pdip;

	/* 4 is pcicmu channel */
	if (obj->channel != 4)
		return (0);

	arg.name = "serial";
	arg.func = NULL;
	if (state == DRMACH_IO_PRE_RELEASE) {
		msudetp = (int (*)(dev_info_t *))
		    modgetsymvalue("oplmsu_dr_detach", 0);
		if (msudetp != NULL)
			arg.func = msudetp;
	} else if (state == DRMACH_IO_POST_ATTACH) {
		msuattp = (int (*)(dev_info_t *))
		    modgetsymvalue("oplmsu_dr_attach", 0);
		if (msuattp != NULL)
			arg.func = msuattp;
	} else {
		return (0);
	}

	if (arg.func == NULL) {
		return (0);
	}

	arg.rv = 0;
	arg.dip = NULL;

	dip = obj->dev.node->n_getdip(obj->dev.node);
	pdip = ddi_get_parent(dip);
	if (pdip == NULL) {
		/* this cannot happen unless something bad happens */
		return (-1);
	}
	ndi_hold_devi(pdip);
	ndi_devi_enter(pdip);

	ddi_walk_devs(dip, drmach_io_cb_check, (void *)&arg);

	ndi_devi_exit(pdip);
	ndi_rele_devi(pdip);

	if (arg.dip) {
		arg.rv = (*arg.func)(arg.dip);
		ndi_rele_devi(arg.dip);
	} else {
		arg.rv = -1;
	}

	return (arg.rv);
}

sbd_error_t *
drmach_io_pre_release(drmachid_t id)
{
	int rv;

	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	rv = drmach_console_ops(id, DRMACH_IO_PRE_RELEASE);

	if (rv != 0)
		cmn_err(CE_WARN, "IO callback failed in pre-release\n");

	return (NULL);
}

static sbd_error_t *
drmach_io_release(drmachid_t id)
{
	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	return (NULL);
}

sbd_error_t *
drmach_io_unrelease(drmachid_t id)
{
	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	return (NULL);
}

/*ARGSUSED*/
sbd_error_t *
drmach_io_post_release(drmachid_t id)
{
	return (NULL);
}

/*ARGSUSED*/
sbd_error_t *
drmach_io_post_attach(drmachid_t id)
{
	int rv;

	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	rv = drmach_console_ops(id, DRMACH_IO_POST_ATTACH);

	if (rv != 0)
		cmn_err(CE_WARN, "IO callback failed in post-attach\n");

	return (0);
}

static sbd_error_t *
drmach_io_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_device_t *dp;
	sbd_error_t	*err;
	int		 configured;

	ASSERT(DRMACH_IS_IO_ID(id));
	dp = id;

	err = drmach_io_is_attached(id, &configured);
	if (err)
		return (err);

	stat->assigned = dp->bp->assigned;
	stat->powered = dp->bp->powered;
	stat->configured = (configured != 0);
	stat->busy = dp->busy;
	(void) strncpy(stat->type, dp->type, sizeof (stat->type));
	stat->info[0] = '\0';

	return (NULL);
}

static sbd_error_t *
drmach_mem_new(drmach_device_t *proto, drmachid_t *idp)
{
	dev_info_t *dip;
	int rv;

	drmach_mem_t	*mp;

	rv = 0;

	if ((proto->node->n_getproplen(proto->node, "mc-addr", &rv) < 0) ||
	    (rv <= 0)) {
		*idp = (drmachid_t)0;
		return (NULL);
	}

	mp = kmem_zalloc(sizeof (drmach_mem_t), KM_SLEEP);
	proto->unum = 0;

	bcopy(proto, &mp->dev, sizeof (mp->dev));
	mp->dev.node = drmach_node_dup(proto->node);
	mp->dev.cm.isa = (void *)drmach_mem_new;
	mp->dev.cm.dispose = drmach_mem_dispose;
	mp->dev.cm.release = drmach_mem_release;
	mp->dev.cm.status = drmach_mem_status;

	(void) snprintf(mp->dev.cm.name, sizeof (mp->dev.cm.name), "%s",
	    mp->dev.type);

	dip = mp->dev.node->n_getdip(mp->dev.node);
	if (drmach_setup_mc_info(dip, mp) != 0) {
		return (drerr_new(1, EOPL_MC_SETUP, NULL));
	}

	/* make sure we do not create memoryless nodes */
	if (mp->nbytes == 0) {
		*idp = (drmachid_t)NULL;
		kmem_free(mp, sizeof (drmach_mem_t));
	} else
		*idp = (drmachid_t)mp;

	return (NULL);
}

static void
drmach_mem_dispose(drmachid_t id)
{
	drmach_mem_t *mp;

	ASSERT(DRMACH_IS_MEM_ID(id));


	mp = id;

	if (mp->dev.node)
		drmach_node_dispose(mp->dev.node);

	if (mp->memlist) {
		memlist_delete(mp->memlist);
		mp->memlist = NULL;
	}

	kmem_free(mp, sizeof (*mp));
}

sbd_error_t *
drmach_mem_add_span(drmachid_t id, uint64_t basepa, uint64_t size)
{
	pfn_t		basepfn = (pfn_t)(basepa >> PAGESHIFT);
	pgcnt_t		npages = (pgcnt_t)(size >> PAGESHIFT);
	int		rv;

	ASSERT(size != 0);

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	rv = kcage_range_add(basepfn, npages, KCAGE_DOWN);
	if (rv == ENOMEM) {
		cmn_err(CE_WARN, "%lu megabytes not available to kernel cage",
		    (ulong_t)(size == 0 ? 0 : size / MBYTE));
	} else if (rv != 0) {
		/* catch this in debug kernels */
		ASSERT(0);

		cmn_err(CE_WARN, "unexpected kcage_range_add return value %d",
		    rv);
	}

	if (rv) {
		return (DRMACH_INTERNAL_ERROR());
	}
	else
		return (NULL);
}

sbd_error_t *
drmach_mem_del_span(drmachid_t id, uint64_t basepa, uint64_t size)
{
	pfn_t		basepfn = (pfn_t)(basepa >> PAGESHIFT);
	pgcnt_t		npages = (pgcnt_t)(size >> PAGESHIFT);
	int		rv;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	if (size > 0) {
		rv = kcage_range_delete_post_mem_del(basepfn, npages);
		if (rv != 0) {
			cmn_err(CE_WARN,
			    "unexpected kcage_range_delete_post_mem_del"
			    " return value %d", rv);
			return (DRMACH_INTERNAL_ERROR());
		}
	}

	return (NULL);
}

sbd_error_t *
drmach_mem_disable(drmachid_t id)
{
	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	else {
		drmach_flush_all();
		return (NULL);
	}
}

sbd_error_t *
drmach_mem_enable(drmachid_t id)
{
	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	else
		return (NULL);
}

sbd_error_t *
drmach_mem_get_info(drmachid_t id, drmach_mem_info_t *mem)
{
	drmach_mem_t *mp;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	mp = (drmach_mem_t *)id;

	/*
	 * This is only used by dr to round up/down the memory
	 * for copying. Our unit of memory isolation is 64 MB.
	 */

	mem->mi_alignment_mask = (64 * 1024 * 1024 - 1);
	mem->mi_basepa = mp->base_pa;
	mem->mi_size = mp->nbytes;
	mem->mi_slice_size = mp->slice_size;

	return (NULL);
}

sbd_error_t *
drmach_mem_get_base_physaddr(drmachid_t id, uint64_t *pa)
{
	drmach_mem_t *mp;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	mp = (drmach_mem_t *)id;

	*pa = mp->base_pa;
	return (NULL);
}

sbd_error_t *
drmach_mem_get_memlist(drmachid_t id, struct memlist **ml)
{
	drmach_mem_t	*mem;
#ifdef	DEBUG
	int		rv;
#endif
	struct memlist	*mlist;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	mem = (drmach_mem_t *)id;
	mlist = memlist_dup(mem->memlist);

#ifdef DEBUG
	/*
	 * Make sure the incoming memlist doesn't already
	 * intersect with what's present in the system (phys_install).
	 */
	memlist_read_lock();
	rv = memlist_intersect(phys_install, mlist);
	memlist_read_unlock();
	if (rv) {
		DRMACH_PR("Derived memlist intersects with phys_install\n");
		memlist_dump(mlist);

		DRMACH_PR("phys_install memlist:\n");
		memlist_dump(phys_install);

		memlist_delete(mlist);
		return (DRMACH_INTERNAL_ERROR());
	}

	DRMACH_PR("Derived memlist:");
	memlist_dump(mlist);
#endif
	*ml = mlist;

	return (NULL);
}

sbd_error_t *
drmach_mem_get_slice_size(drmachid_t id, uint64_t *bytes)
{
	drmach_mem_t	*mem;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	mem = (drmach_mem_t *)id;

	*bytes = mem->slice_size;

	return (NULL);
}


/* ARGSUSED */
processorid_t
drmach_mem_cpu_affinity(drmachid_t id)
{
	return (CPU_CURRENT);
}

static sbd_error_t *
drmach_mem_release(drmachid_t id)
{
	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	return (NULL);
}

static sbd_error_t *
drmach_mem_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_mem_t *dp;
	uint64_t	 pa, slice_size;
	struct memlist	*ml;

	ASSERT(DRMACH_IS_MEM_ID(id));
	dp = id;

	/* get starting physical address of target memory */
	pa = dp->base_pa;

	/* round down to slice boundary */
	slice_size = dp->slice_size;
	pa &= ~(slice_size - 1);

	/* stop at first span that is in slice */
	memlist_read_lock();
	for (ml = phys_install; ml; ml = ml->ml_next)
		if (ml->ml_address >= pa && ml->ml_address < pa + slice_size)
			break;
	memlist_read_unlock();

	stat->assigned = dp->dev.bp->assigned;
	stat->powered = dp->dev.bp->powered;
	stat->configured = (ml != NULL);
	stat->busy = dp->dev.busy;
	(void) strncpy(stat->type, dp->dev.type, sizeof (stat->type));
	stat->info[0] = '\0';

	return (NULL);
}


sbd_error_t *
drmach_board_deprobe(drmachid_t id)
{
	drmach_board_t	*bp;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	bp = id;

	cmn_err(CE_CONT, "DR: detach board %d\n", bp->bnum);

	if (bp->tree) {
		drmach_node_dispose(bp->tree);
		bp->tree = NULL;
	}
	if (bp->devices) {
		drmach_array_dispose(bp->devices, drmach_device_dispose);
		bp->devices = NULL;
	}

	bp->boot_board = 0;

	return (NULL);
}

/*ARGSUSED*/
static sbd_error_t *
drmach_pt_ikprobe(drmachid_t id, drmach_opts_t *opts)
{
	drmach_board_t		*bp = (drmach_board_t *)id;
	sbd_error_t		*err = NULL;
	int	rv;
	unsigned cpu_impl;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	DRMACH_PR("calling opl_probe_board for bnum=%d\n", bp->bnum);
	rv = opl_probe_sb(bp->bnum, &cpu_impl);
	if (rv != 0) {
		err = drerr_new(1, EOPL_PROBE, bp->cm.name);
		return (err);
	}
	return (err);
}

/*ARGSUSED*/
static sbd_error_t *
drmach_pt_ikdeprobe(drmachid_t id, drmach_opts_t *opts)
{
	drmach_board_t	*bp;
	sbd_error_t	*err = NULL;
	int	rv;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	bp = (drmach_board_t *)id;

	cmn_err(CE_CONT, "DR: in-kernel unprobe board %d\n", bp->bnum);

	rv = opl_unprobe_sb(bp->bnum);
	if (rv != 0) {
		err = drerr_new(1, EOPL_DEPROBE, bp->cm.name);
	}

	return (err);
}


/*ARGSUSED*/
sbd_error_t *
drmach_pt_readmem(drmachid_t id, drmach_opts_t *opts)
{
	struct memlist	*ml;
	uint64_t	src_pa;
	uint64_t	dst_pa;
	uint64_t	dst;

	dst_pa = va_to_pa(&dst);

	memlist_read_lock();
	for (ml = phys_install; ml; ml = ml->ml_next) {
		uint64_t	nbytes;

		src_pa = ml->ml_address;
		nbytes = ml->ml_size;

		while (nbytes != 0ull) {

			/* copy 32 bytes at arc_pa to dst_pa */
			bcopy32_il(src_pa, dst_pa);

			/* increment by 32 bytes */
			src_pa += (4 * sizeof (uint64_t));

			/* decrement by 32 bytes */
			nbytes -= (4 * sizeof (uint64_t));
		}
	}
	memlist_read_unlock();

	return (NULL);
}

static struct {
	const char	*name;
	sbd_error_t	*(*handler)(drmachid_t id, drmach_opts_t *opts);
} drmach_pt_arr[] = {
	{ "readmem",		drmach_pt_readmem		},
	{ "ikprobe",	drmach_pt_ikprobe	},
	{ "ikdeprobe",	drmach_pt_ikdeprobe	},

	/* the following line must always be last */
	{ NULL,			NULL				}
};

/*ARGSUSED*/
sbd_error_t *
drmach_passthru(drmachid_t id, drmach_opts_t *opts)
{
	int		i;
	sbd_error_t	*err;

	i = 0;
	while (drmach_pt_arr[i].name != NULL) {
		int len = strlen(drmach_pt_arr[i].name);

		if (strncmp(drmach_pt_arr[i].name, opts->copts, len) == 0)
			break;

		i += 1;
	}

	if (drmach_pt_arr[i].name == NULL)
		err = drerr_new(0, EOPL_UNKPTCMD, opts->copts);
	else
		err = (*drmach_pt_arr[i].handler)(id, opts);

	return (err);
}

sbd_error_t *
drmach_release(drmachid_t id)
{
	drmach_common_t *cp;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	cp = id;

	return (cp->release(id));
}

sbd_error_t *
drmach_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_common_t *cp;
	sbd_error_t	*err;

	rw_enter(&drmach_boards_rwlock, RW_READER);

	if (!DRMACH_IS_ID(id)) {
		rw_exit(&drmach_boards_rwlock);
		return (drerr_new(0, EOPL_NOTID, NULL));
	}
	cp = (drmach_common_t *)id;
	err = cp->status(id, stat);

	rw_exit(&drmach_boards_rwlock);

	return (err);
}

static sbd_error_t *
drmach_i_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_common_t *cp;

	if (!DRMACH_IS_ID(id))
		return (drerr_new(0, EOPL_NOTID, NULL));
	cp = id;

	return (cp->status(id, stat));
}

/*ARGSUSED*/
sbd_error_t *
drmach_unconfigure(drmachid_t id, int flags)
{
	drmach_device_t *dp;
	dev_info_t	*rdip, *fdip = NULL;
	char name[OBP_MAXDRVNAME];
	int rv;

	if (DRMACH_IS_CPU_ID(id))
		return (NULL);

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	dp = id;

	rdip = dp->node->n_getdip(dp->node);

	ASSERT(rdip);

	rv = dp->node->n_getprop(dp->node, "name", name, OBP_MAXDRVNAME);

	if (rv)
		return (NULL);

	/*
	 * Note: FORCE flag is no longer necessary under devfs
	 */

	ASSERT(e_ddi_branch_held(rdip));
	if (e_ddi_branch_unconfigure(rdip, &fdip, 0)) {
		sbd_error_t	*err;
		char		*path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		/*
		 * If non-NULL, fdip is returned held and must be released.
		 */
		if (fdip != NULL) {
			(void) ddi_pathname(fdip, path);
			ndi_rele_devi(fdip);
		} else {
			(void) ddi_pathname(rdip, path);
		}

		err = drerr_new(1, EOPL_DRVFAIL, path);

		kmem_free(path, MAXPATHLEN);

		return (err);
	}

	return (NULL);
}


int
drmach_cpu_poweron(struct cpu *cp)
{
	int bnum, cpuid, onb_core_num, strand_id;
	drmach_board_t *bp;

	DRMACH_PR("drmach_cpu_poweron: starting cpuid %d\n", cp->cpu_id);

	cpuid = cp->cpu_id;
	bnum = LSB_ID(cpuid);
	onb_core_num = ON_BOARD_CORE_NUM(cpuid);
	strand_id = STRAND_ID(cpuid);
	bp = drmach_get_board_by_bnum(bnum);

	ASSERT(bp);
	if (bp->cores[onb_core_num].core_hotadded == 0) {
		if (drmach_add_remove_cpu(bnum, onb_core_num,
		    HOTADD_CPU) != 0) {
			cmn_err(CE_WARN, "Failed to add CMP %d on board %d\n",
			    onb_core_num, bnum);
			return (EIO);
		}
	}

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (drmach_cpu_start(cp) != 0) {
		if (bp->cores[onb_core_num].core_started == 0) {
			/*
			 * we must undo the hotadd or no one will do that
			 * If this fails, we will do this again in
			 * drmach_board_disconnect.
			 */
			if (drmach_add_remove_cpu(bnum, onb_core_num,
			    HOTREMOVE_CPU) != 0) {
				cmn_err(CE_WARN, "Failed to remove CMP %d "
				    "on board %d\n", onb_core_num, bnum);
			}
		}
		return (EBUSY);
	} else {
		bp->cores[onb_core_num].core_started |= (1 << strand_id);
		return (0);
	}
}

int
drmach_cpu_poweroff(struct cpu *cp)
{
	int		rv = 0;
	processorid_t	cpuid = cp->cpu_id;

	DRMACH_PR("drmach_cpu_poweroff: stopping cpuid %d\n", cp->cpu_id);

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Capture all CPUs (except for detaching proc) to prevent
	 * crosscalls to the detaching proc until it has cleared its
	 * bit in cpu_ready_set.
	 *
	 * The CPU's remain paused and the prom_mutex is known to be free.
	 * This prevents the x-trap victim from blocking when doing prom
	 * IEEE-1275 calls at a high PIL level.
	 */

	promsafe_pause_cpus();

	/*
	 * Quiesce interrupts on the target CPU. We do this by setting
	 * the CPU 'not ready'- (i.e. removing the CPU from cpu_ready_set) to
	 * prevent it from receiving cross calls and cross traps.
	 * This prevents the processor from receiving any new soft interrupts.
	 */
	mp_cpu_quiesce(cp);

	rv = prom_stopcpu_bycpuid(cpuid);
	if (rv == 0)
		cp->cpu_flags = CPU_OFFLINE | CPU_QUIESCED | CPU_POWEROFF;

	start_cpus();

	if (rv == 0) {
		int bnum, onb_core_num, strand_id;
		drmach_board_t *bp;

		CPU_SIGNATURE(OS_SIG, SIGST_DETACHED, SIGSUBST_NULL, cpuid);

		bnum = LSB_ID(cpuid);
		onb_core_num = ON_BOARD_CORE_NUM(cpuid);
		strand_id = STRAND_ID(cpuid);
		bp = drmach_get_board_by_bnum(bnum);
		ASSERT(bp);

		bp->cores[onb_core_num].core_started &= ~(1 << strand_id);
		if (bp->cores[onb_core_num].core_started == 0) {
			if (drmach_add_remove_cpu(bnum, onb_core_num,
			    HOTREMOVE_CPU) != 0) {
				cmn_err(CE_WARN, "Failed to remove CMP %d LSB "
				    "%d\n", onb_core_num, bnum);
				return (EIO);
			}
		}
	}

	return (rv);
}

/*ARGSUSED*/
int
drmach_verify_sr(dev_info_t *dip, int sflag)
{
	return (0);
}

void
drmach_suspend_last(void)
{
}

void
drmach_resume_first(void)
{
}

/*
 * Log a DR sysevent.
 * Return value: 0 success, non-zero failure.
 */
int
drmach_log_sysevent(int board, char *hint, int flag, int verbose)
{
	sysevent_t			*ev;
	sysevent_id_t			eid;
	int				rv, km_flag;
	sysevent_value_t		evnt_val;
	sysevent_attr_list_t		*evnt_attr_list = NULL;
	char				attach_pnt[MAXNAMELEN];

	km_flag = (flag == SE_SLEEP) ? KM_SLEEP : KM_NOSLEEP;
	attach_pnt[0] = '\0';
	if (drmach_board_name(board, attach_pnt, MAXNAMELEN)) {
		rv = -1;
		goto logexit;
	}
	if (verbose) {
		DRMACH_PR("drmach_log_sysevent: %s %s, flag: %d, verbose: %d\n",
		    attach_pnt, hint, flag, verbose);
	}

	if ((ev = sysevent_alloc(EC_DR, ESC_DR_AP_STATE_CHANGE,
	    SUNW_KERN_PUB"dr", km_flag)) == NULL) {
		rv = -2;
		goto logexit;
	}
	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = attach_pnt;
	if ((rv = sysevent_add_attr(&evnt_attr_list, DR_AP_ID, &evnt_val,
	    km_flag)) != 0)
		goto logexit;

	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = hint;
	if ((rv = sysevent_add_attr(&evnt_attr_list, DR_HINT, &evnt_val,
	    km_flag)) != 0) {
		sysevent_free_attr(evnt_attr_list);
		goto logexit;
	}

	(void) sysevent_attach_attributes(ev, evnt_attr_list);

	/*
	 * Log the event but do not sleep waiting for its
	 * delivery. This provides insulation from syseventd.
	 */
	rv = log_sysevent(ev, SE_NOSLEEP, &eid);

logexit:
	if (ev)
		sysevent_free(ev);
	if ((rv != 0) && verbose)
		cmn_err(CE_WARN, "drmach_log_sysevent failed (rv %d) for %s "
		    " %s\n", rv, attach_pnt, hint);

	return (rv);
}

#define	OPL_DR_STATUS_PROP "dr-status"

static int
opl_check_dr_status()
{
	pnode_t	node;
	int	rtn, len;
	char	*str;

	node = prom_rootnode();
	if (node == OBP_BADNODE) {
		return (1);
	}

	len = prom_getproplen(node, OPL_DR_STATUS_PROP);
	if (len == -1) {
		/*
		 * dr-status doesn't exist when DR is activated and
		 * any warning messages aren't needed.
		 */
		return (1);
	}

	str = (char *)kmem_zalloc(len+1, KM_SLEEP);
	rtn = prom_getprop(node, OPL_DR_STATUS_PROP, str);
	kmem_free(str, len + 1);
	if (rtn == -1) {
		return (1);
	} else {
		return (0);
	}
}

/* we are allocating memlist from TLB locked pages to avoid tlbmisses */

static struct memlist *
drmach_memlist_add_span(drmach_copy_rename_program_t *p,
    struct memlist *mlist, uint64_t base, uint64_t len)
{
	struct memlist	*ml, *tl, *nl;

	if (len == 0ull)
		return (NULL);

	if (mlist == NULL) {
		mlist = p->free_mlist;
		if (mlist == NULL)
			return (NULL);
		p->free_mlist = mlist->ml_next;
		mlist->ml_address = base;
		mlist->ml_size = len;
		mlist->ml_next = mlist->ml_prev = NULL;

		return (mlist);
	}

	for (tl = ml = mlist; ml; tl = ml, ml = ml->ml_next) {
		if (base < ml->ml_address) {
			if ((base + len) < ml->ml_address) {
				nl = p->free_mlist;
				if (nl == NULL)
					return (NULL);
				p->free_mlist = nl->ml_next;
				nl->ml_address = base;
				nl->ml_size = len;
				nl->ml_next = ml;
				if ((nl->ml_prev = ml->ml_prev) != NULL)
					nl->ml_prev->ml_next = nl;
				ml->ml_prev = nl;
				if (mlist == ml)
					mlist = nl;
			} else {
				ml->ml_size = MAX((base + len),
				    (ml->ml_address + ml->ml_size)) - base;
				ml->ml_address = base;
			}
			break;

		} else if (base <= (ml->ml_address + ml->ml_size)) {
			ml->ml_size =
			    MAX((base + len), (ml->ml_address + ml->ml_size)) -
			    MIN(ml->ml_address, base);
			ml->ml_address = MIN(ml->ml_address, base);
			break;
		}
	}
	if (ml == NULL) {
		nl = p->free_mlist;
		if (nl == NULL)
			return (NULL);
		p->free_mlist = nl->ml_next;
		nl->ml_address = base;
		nl->ml_size = len;
		nl->ml_next = NULL;
		nl->ml_prev = tl;
		tl->ml_next = nl;
	}

	return (mlist);
}

/*
 * The routine performs the necessary memory COPY and MC adr SWITCH.
 * Both operations MUST be at the same "level" so that the stack is
 * maintained correctly between the copy and switch.  The switch
 * portion implements a caching mechanism to guarantee the code text
 * is cached prior to execution.  This is to guard against possible
 * memory access while the MC adr's are being modified.
 *
 * IMPORTANT: The _drmach_copy_rename_end() function must immediately
 * follow drmach_copy_rename_prog__relocatable() so that the correct
 * "length" of the drmach_copy_rename_prog__relocatable can be
 * calculated.  This routine MUST be a LEAF function, i.e. it can
 * make NO function calls, primarily for two reasons:
 *
 *	1. We must keep the stack consistent across the "switch".
 *	2. Function calls are compiled to relative offsets, and
 *	   we execute this function we'll be executing it from
 *	   a copied version in a different area of memory, thus
 *	   the relative offsets will be bogus.
 *
 * Moreover, it must have the "__relocatable" suffix to inform DTrace
 * providers (and anything else, for that matter) that this
 * function's text is manually relocated elsewhere before it is
 * executed.  That is, it cannot be safely instrumented with any
 * methodology that is PC-relative.
 */

/*
 * We multiply this to system_clock_frequency so we
 * are setting a delay of fmem_timeout second for
 * the rename command.
 *
 * FMEM command itself should complete within 15 sec.
 * We add 2 more sec to be conservative.
 *
 * Note that there is also a SCF BUSY bit checking
 * in drmach_asm.s right before FMEM command is
 * issued.  XSCF sets the SCF BUSY bit when the
 * other domain on the same PSB reboots and it
 * will not be able to service the FMEM command
 * within 15 sec.   After setting the SCF BUSY
 * bit, XSCF will wait a while before servicing
 * other reboot command so there is no race
 * condition.
 */

static int	fmem_timeout = 17;

/*
 *	The empirical data on some OPL system shows that
 *	we can copy 250 MB per second.  We set it to
 *	80 MB to be conservative.  In normal case,
 *	this timeout does not affect anything.
 */

static int	min_copy_size_per_sec = 80 * 1024 * 1024;

/*
 *	This is the timeout value for the xcall synchronization
 *	to get all the CPU ready to do the parallel copying.
 *	Even on a fully loaded system, 10 sec. should be long
 *	enough.
 */

static int	cpu_xcall_delay = 10;
int drmach_disable_mcopy = 0;

/*
 * The following delay loop executes sleep instruction to yield the
 * CPU to other strands.  If this is not done, some strand will tie
 * up the CPU in busy loops while the other strand cannot do useful
 * work.  The copy procedure will take a much longer time without this.
 */
#define	DR_DELAY_IL(ms, freq)					\
	{							\
		uint64_t start;					\
		uint64_t nstick;				\
		volatile uint64_t now;				\
		nstick = ((uint64_t)ms * freq)/1000;		\
		start = drmach_get_stick_il();			\
		now = start;					\
		while ((now - start) <= nstick) {		\
			drmach_sleep_il();			\
			now = drmach_get_stick_il();		\
		}						\
	}

/* Each loop is 2ms, timeout at 1000ms */
static int drmach_copy_rename_timeout = 500;

static int
drmach_copy_rename_prog__relocatable(drmach_copy_rename_program_t *prog,
    int cpuid)
{
	struct memlist		*ml;
	register int		rtn;
	int			i;
	register uint64_t	curr, limit;
	extern uint64_t		drmach_get_stick_il();
	extern void		membar_sync_il();
	extern void		flush_instr_mem_il(void*);
	extern void		flush_windows_il(void);
	uint64_t		copy_start;

	/*
	 * flush_windows is moved here to make sure all
	 * registers used in the callers are flushed to
	 * memory before the copy.
	 *
	 * If flush_windows() is called too early in the
	 * calling function, the compiler might put some
	 * data in the local registers after flush_windows().
	 * After FMA, if there is any fill trap, the registers
	 * will contain stale data.
	 */

	flush_windows_il();

	prog->critical->stat[cpuid] = FMEM_LOOP_COPY_READY;
	membar_sync_il();

	if (prog->data->cpuid == cpuid) {
		limit = drmach_get_stick_il();
		limit += cpu_xcall_delay * system_clock_freq;
		for (i = 0; i < NCPU; i++) {
			if (CPU_IN_SET(prog->data->cpu_slave_set, i)) {
				/* wait for all CPU's to be ready */
				for (;;) {
					if (prog->critical->stat[i] ==
					    FMEM_LOOP_COPY_READY) {
						break;
					}
					DR_DELAY_IL(1, prog->data->stick_freq);
				}
				curr = drmach_get_stick_il();
				if (curr > limit) {
					prog->data->fmem_status.error =
					    EOPL_FMEM_XC_TIMEOUT;
					return (EOPL_FMEM_XC_TIMEOUT);
				}
			}
		}
		prog->data->fmem_status.stat = FMEM_LOOP_COPY_READY;
		membar_sync_il();
		copy_start = drmach_get_stick_il();
	} else {
		for (;;) {
			if (prog->data->fmem_status.stat ==
			    FMEM_LOOP_COPY_READY) {
				break;
			}
			if (prog->data->fmem_status.error) {
				prog->data->error[cpuid] = EOPL_FMEM_TERMINATE;
				return (EOPL_FMEM_TERMINATE);
			}
			DR_DELAY_IL(1, prog->data->stick_freq);
		}
	}

	/*
	 * DO COPY.
	 */
	if (CPU_IN_SET(prog->data->cpu_copy_set, cpuid)) {
		for (ml = prog->data->cpu_ml[cpuid]; ml; ml = ml->ml_next) {
			uint64_t	s_pa, t_pa;
			uint64_t	nbytes;

			s_pa = prog->data->s_copybasepa + ml->ml_address;
			t_pa = prog->data->t_copybasepa + ml->ml_address;
			nbytes = ml->ml_size;

			while (nbytes != 0ull) {
				/*
				 * If the master has detected error, we just
				 * bail out
				 */
				if (prog->data->fmem_status.error !=
				    ESBD_NOERROR) {
					prog->data->error[cpuid] =
					    EOPL_FMEM_TERMINATE;
					return (EOPL_FMEM_TERMINATE);
				}
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

				/*
				 * increment the counter to signal that we are
				 * alive
				 */
				prog->stat->nbytes[cpuid] += 32;

				/* increment by 32 bytes */
				s_pa += (4 * sizeof (uint64_t));
				t_pa += (4 * sizeof (uint64_t));

				/* decrement by 32 bytes */
				nbytes -= (4 * sizeof (uint64_t));
			}
		}
		prog->critical->stat[cpuid] = FMEM_LOOP_COPY_DONE;
		membar_sync_il();
	}

	/*
	 * Since bcopy32_il() does NOT use an ASI to bypass
	 * the Ecache, we need to flush our Ecache after
	 * the copy is complete.
	 */
	flush_cache_il();

	/*
	 * drmach_fmem_exec_script()
	 */
	if (prog->data->cpuid == cpuid) {
		uint64_t	last, now;

		limit = copy_start + prog->data->copy_delay;
		for (i = 0; i < NCPU; i++) {
			if (!CPU_IN_SET(prog->data->cpu_slave_set, i))
				continue;

			for (;;) {
				/*
				 * we get FMEM_LOOP_FMEM_READY in
				 * normal case
				 */
				if (prog->critical->stat[i] ==
				    FMEM_LOOP_FMEM_READY) {
					break;
				}
				/* got error traps */
				if (prog->data->error[i] ==
				    EOPL_FMEM_COPY_ERROR) {
					prog->data->fmem_status.error =
					    EOPL_FMEM_COPY_ERROR;
					return (EOPL_FMEM_COPY_ERROR);
				}
				/*
				 * if we have not reached limit, wait
				 * more
				 */
				curr = drmach_get_stick_il();
				if (curr <= limit)
					continue;

				prog->data->slowest_cpuid = i;
				prog->data->copy_wait_time = curr - copy_start;

				/* now check if slave is alive */
				last = prog->stat->nbytes[i];

				DR_DELAY_IL(1, prog->data->stick_freq);

				now = prog->stat->nbytes[i];
				if (now <= last) {
					/*
					 * no progress, perhaps just
					 * finished
					 */
					DR_DELAY_IL(1, prog->data->stick_freq);
					if (prog->critical->stat[i] ==
					    FMEM_LOOP_FMEM_READY)
						break;
					/* copy error */
					if (prog->data->error[i] ==
					    EOPL_FMEM_COPY_ERROR) {
						prog->data-> fmem_status.error =
						    EOPL_FMEM_COPY_ERROR;
						return (EOPL_FMEM_COPY_ERROR);
					}

					prog->data->copy_rename_count++;
					if (prog->data->copy_rename_count
					    < drmach_copy_rename_timeout) {
						continue;
					} else {
						prog->data->fmem_status.error =
						    EOPL_FMEM_COPY_TIMEOUT;
						return (EOPL_FMEM_COPY_TIMEOUT);
					}
				}
			}
		}

		prog->critical->stat[cpuid] = FMEM_LOOP_FMEM_READY;
		prog->data->fmem_status.stat  = FMEM_LOOP_FMEM_READY;

		membar_sync_il();
		flush_instr_mem_il((void*) (prog->critical));
		/*
		 * drmach_fmem_exec_script()
		 */
		rtn = prog->critical->fmem((void *)prog->critical, PAGESIZE);
		return (rtn);
	} else {
		flush_instr_mem_il((void*) (prog->critical));
		/*
		 * drmach_fmem_loop_script()
		 */
		rtn = prog->critical->loop((void *)(prog->critical), PAGESIZE,
		    (void *)&(prog->critical->stat[cpuid]));
		prog->data->error[cpuid] = rtn;
		/* slave thread does not care the rv */
		return (0);
	}
}

static void
drmach_copy_rename_end(void)
{
	/*
	 * IMPORTANT:	This function's location MUST be located immediately
	 *		following drmach_copy_rename_prog__relocatable to
	 *		accurately estimate its size.  Note that this assumes
	 *		the compiler keeps these functions in the order in
	 *		which they appear :-o
	 */
}


static int
drmach_setup_memlist(drmach_copy_rename_program_t *p)
{
	struct memlist *ml;
	caddr_t buf;
	int nbytes, s, n_elements;

	nbytes = PAGESIZE;
	n_elements = 0;
	s = roundup(sizeof (struct memlist), sizeof (void *));
	p->free_mlist = NULL;
	buf = p->memlist_buffer;
	while (nbytes >= sizeof (struct memlist)) {
		ml = (struct memlist *)buf;
		ml->ml_next = p->free_mlist;
		p->free_mlist = ml;
		buf += s;
		n_elements++;
		nbytes -= s;
	}
	return (n_elements);
}

static void
drmach_lock_critical(caddr_t va, caddr_t new_va)
{
	tte_t tte;
	int i;

	kpreempt_disable();

	for (i = 0; i < DRMACH_FMEM_LOCKED_PAGES; i++) {
		vtag_flushpage(new_va, (uint64_t)ksfmmup);
		sfmmu_memtte(&tte, va_to_pfn(va), PROC_DATA|HAT_NOSYNC, TTE8K);
		tte.tte_intlo |= TTE_LCK_INT;
		sfmmu_dtlb_ld_kva(new_va, &tte);
		sfmmu_itlb_ld_kva(new_va, &tte);
		va += PAGESIZE;
		new_va += PAGESIZE;
	}
}

static void
drmach_unlock_critical(caddr_t va)
{
	int i;

	for (i = 0; i < DRMACH_FMEM_LOCKED_PAGES; i++) {
		vtag_flushpage(va, (uint64_t)ksfmmup);
		va += PAGESIZE;
	}

	kpreempt_enable();
}

sbd_error_t *
drmach_copy_rename_init(drmachid_t t_id, drmachid_t s_id,
    struct memlist *c_ml, drmachid_t *pgm_id)
{
	drmach_mem_t	*s_mem;
	drmach_mem_t	*t_mem;
	struct memlist	*x_ml;
	uint64_t	s_copybasepa, t_copybasepa;
	uint_t		len;
	caddr_t		bp, wp;
	int		s_bd, t_bd, cpuid, active_cpus, i;
	int		max_elms, mlist_size, rv;
	uint64_t	c_addr;
	size_t		c_size, copy_sz, sz;
	extern void	drmach_fmem_loop_script();
	extern void	drmach_fmem_loop_script_rtn();
	extern int	drmach_fmem_exec_script();
	extern void	drmach_fmem_exec_script_end();
	sbd_error_t	*err;
	drmach_copy_rename_program_t *prog = NULL;
	drmach_copy_rename_program_t *prog_kmem = NULL;
	void		(*mc_suspend)(void);
	void		(*mc_resume)(void);
	int		(*scf_fmem_start)(int, int);
	int		(*scf_fmem_end)(void);
	int		(*scf_fmem_cancel)(void);
	uint64_t	(*scf_get_base_addr)(void);

	if (!DRMACH_IS_MEM_ID(s_id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));
	if (!DRMACH_IS_MEM_ID(t_id))
		return (drerr_new(0, EOPL_INAPPROP, NULL));

	for (i = 0; i < NCPU; i++) {
		int lsb_id, onb_core_num, strand_id;
		drmach_board_t *bp;

		/*
		 * this kind of CPU will spin in cache
		 */
		if (CPU_IN_SET(cpu_ready_set, i))
			continue;

		/*
		 * Now check for any inactive CPU's that
		 * have been hotadded.  This can only occur in
		 * error condition in drmach_cpu_poweron().
		 */
		lsb_id = LSB_ID(i);
		onb_core_num = ON_BOARD_CORE_NUM(i);
		strand_id = STRAND_ID(i);
		bp = drmach_get_board_by_bnum(lsb_id);
		if (bp == NULL)
			continue;
		if (bp->cores[onb_core_num].core_hotadded &
		    (1 << strand_id)) {
			if (!(bp->cores[onb_core_num].core_started &
			    (1 << strand_id))) {
				return (drerr_new(1, EOPL_CPU_STATE, NULL));
			}
		}
	}

	mc_suspend = (void (*)(void))
	    modgetsymvalue("opl_mc_suspend", 0);
	mc_resume = (void (*)(void))
	    modgetsymvalue("opl_mc_resume", 0);

	if (mc_suspend == NULL || mc_resume == NULL) {
		return (drerr_new(1, EOPL_MC_OPL, NULL));
	}

	scf_fmem_start = (int (*)(int, int))
	    modgetsymvalue("scf_fmem_start", 0);
	if (scf_fmem_start == NULL) {
		return (drerr_new(1, EOPL_SCF_FMEM, NULL));
	}
	scf_fmem_end = (int (*)(void))
	    modgetsymvalue("scf_fmem_end", 0);
	if (scf_fmem_end == NULL) {
		return (drerr_new(1, EOPL_SCF_FMEM, NULL));
	}
	scf_fmem_cancel = (int (*)(void))
	    modgetsymvalue("scf_fmem_cancel", 0);
	if (scf_fmem_cancel == NULL) {
		return (drerr_new(1, EOPL_SCF_FMEM, NULL));
	}
	scf_get_base_addr = (uint64_t (*)(void))
	    modgetsymvalue("scf_get_base_addr", 0);
	if (scf_get_base_addr == NULL) {
		return (drerr_new(1, EOPL_SCF_FMEM, NULL));
	}
	s_mem = s_id;
	t_mem = t_id;

	s_bd = s_mem->dev.bp->bnum;
	t_bd = t_mem->dev.bp->bnum;

	/* calculate source and target base pa */

	s_copybasepa = s_mem->slice_base;
	t_copybasepa = t_mem->slice_base;

	/* adjust copy memlist addresses to be relative to copy base pa */
	x_ml = c_ml;
	mlist_size = 0;
	while (x_ml != NULL) {
		x_ml->ml_address -= s_copybasepa;
		x_ml = x_ml->ml_next;
		mlist_size++;
	}

	/*
	 * bp will be page aligned, since we're calling
	 * kmem_zalloc() with an exact multiple of PAGESIZE.
	 */

	prog_kmem = (drmach_copy_rename_program_t *)kmem_zalloc(
	    DRMACH_FMEM_LOCKED_PAGES * PAGESIZE, KM_SLEEP);

	prog_kmem->prog = prog_kmem;

	/*
	 * To avoid MTLB hit, we allocate a new VM space and remap
	 * the kmem_alloc buffer to that address.  This solves
	 * 2 problems we found:
	 * - the kmem_alloc buffer can be just a chunk inside
	 *   a much larger, e.g. 4MB buffer and MTLB will occur
	 *   if there are both a 4MB and a 8K TLB mapping to
	 *   the same VA range.
	 * - the kmem mapping got dropped into the TLB by other
	 *   strands, unintentionally.
	 * Note that the pointers like data, critical, memlist_buffer,
	 * and stat inside the copy rename structure are mapped to this
	 * alternate VM space so we must make sure we lock the TLB mapping
	 * whenever we access data pointed to by these pointers.
	 */

	prog = prog_kmem->locked_prog = vmem_alloc(heap_arena,
	    DRMACH_FMEM_LOCKED_PAGES * PAGESIZE, VM_SLEEP);
	wp = bp = (caddr_t)prog;

	/* Now remap prog_kmem to prog */
	drmach_lock_critical((caddr_t)prog_kmem, (caddr_t)prog);

	/* All pointers in prog are based on the alternate mapping */
	prog->data = (drmach_copy_rename_data_t *)roundup(((uint64_t)prog +
	    sizeof (drmach_copy_rename_program_t)), sizeof (void *));

	ASSERT(((uint64_t)prog->data + sizeof (drmach_copy_rename_data_t))
	    <= ((uint64_t)prog + PAGESIZE));

	prog->critical = (drmach_copy_rename_critical_t *)
	    (wp + DRMACH_FMEM_CRITICAL_PAGE * PAGESIZE);

	prog->memlist_buffer = (caddr_t)(wp + DRMACH_FMEM_MLIST_PAGE *
	    PAGESIZE);

	prog->stat = (drmach_cr_stat_t *)(wp + DRMACH_FMEM_STAT_PAGE *
	    PAGESIZE);

	/* LINTED */
	ASSERT(sizeof (drmach_cr_stat_t) <= ((DRMACH_FMEM_LOCKED_PAGES -
	    DRMACH_FMEM_STAT_PAGE) * PAGESIZE));

	prog->critical->scf_reg_base = (uint64_t)-1;
	prog->critical->scf_td[0] = (s_bd & 0xff);
	prog->critical->scf_td[1] = (t_bd & 0xff);
	for (i = 2; i < 15; i++) {
		prog->critical->scf_td[i]   = 0;
	}
	prog->critical->scf_td[15] = ((0xaa + s_bd + t_bd) & 0xff);

	bp = (caddr_t)prog->critical;
	len = sizeof (drmach_copy_rename_critical_t);
	wp = (caddr_t)roundup((uint64_t)bp + len, sizeof (void *));

	len = (uint_t)((ulong_t)drmach_copy_rename_end -
	    (ulong_t)drmach_copy_rename_prog__relocatable);

	/*
	 * We always leave 1K nop's to prevent the processor from
	 * speculative execution that causes memory access
	 */
	wp = wp + len + 1024;

	len = (uint_t)((ulong_t)drmach_fmem_exec_script_end -
	    (ulong_t)drmach_fmem_exec_script);
	/* this is the entry point of the loop script */
	wp = wp + len + 1024;

	len = (uint_t)((ulong_t)drmach_fmem_exec_script -
	    (ulong_t)drmach_fmem_loop_script);
	wp = wp + len + 1024;

	/* now we make sure there is 1K extra */

	if ((wp - bp) > PAGESIZE) {
		err = drerr_new(1, EOPL_FMEM_SETUP, NULL);
		goto out;
	}

	bp = (caddr_t)prog->critical;
	len = sizeof (drmach_copy_rename_critical_t);
	wp = (caddr_t)roundup((uint64_t)bp + len, sizeof (void *));

	prog->critical->run = (int (*)())(wp);
	len = (uint_t)((ulong_t)drmach_copy_rename_end -
	    (ulong_t)drmach_copy_rename_prog__relocatable);

	bcopy((caddr_t)drmach_copy_rename_prog__relocatable, wp, len);

	wp = (caddr_t)roundup((uint64_t)wp + len, 1024);

	prog->critical->fmem = (int (*)())(wp);
	len = (int)((ulong_t)drmach_fmem_exec_script_end -
	    (ulong_t)drmach_fmem_exec_script);
	bcopy((caddr_t)drmach_fmem_exec_script, wp, len);

	len = (int)((ulong_t)drmach_fmem_exec_script_end -
	    (ulong_t)drmach_fmem_exec_script);
	wp = (caddr_t)roundup((uint64_t)wp + len, 1024);

	prog->critical->loop = (int (*)())(wp);
	len = (int)((ulong_t)drmach_fmem_exec_script -
	    (ulong_t)drmach_fmem_loop_script);
	bcopy((caddr_t)drmach_fmem_loop_script, (void *)wp, len);
	len = (int)((ulong_t)drmach_fmem_loop_script_rtn-
	    (ulong_t)drmach_fmem_loop_script);
	prog->critical->loop_rtn = (void (*)()) (wp+len);

	prog->data->fmem_status.error = ESBD_NOERROR;

	/* now we are committed, call SCF, soft suspend mac patrol */
	if ((*scf_fmem_start)(s_bd, t_bd)) {
		err = drerr_new(1, EOPL_SCF_FMEM_START, NULL);
		goto out;
	}
	prog->data->scf_fmem_end = scf_fmem_end;
	prog->data->scf_fmem_cancel = scf_fmem_cancel;
	prog->data->scf_get_base_addr = scf_get_base_addr;
	prog->data->fmem_status.op |= OPL_FMEM_SCF_START;

	/* soft suspend mac patrol */
	(*mc_suspend)();
	prog->data->fmem_status.op |= OPL_FMEM_MC_SUSPEND;
	prog->data->mc_resume = mc_resume;

	prog->critical->inst_loop_ret  =
	    *(uint64_t *)(prog->critical->loop_rtn);

	/*
	 * 0x30800000 is op code "ba,a	+0"
	 */

	*(uint_t *)(prog->critical->loop_rtn) = (uint_t)(0x30800000);

	/*
	 * set the value of SCF FMEM TIMEOUT
	 */
	prog->critical->delay = fmem_timeout * system_clock_freq;

	prog->data->s_mem = (drmachid_t)s_mem;
	prog->data->t_mem = (drmachid_t)t_mem;

	cpuid = CPU->cpu_id;
	prog->data->cpuid = cpuid;
	prog->data->cpu_ready_set = cpu_ready_set;
	prog->data->cpu_slave_set = cpu_ready_set;
	prog->data->slowest_cpuid = (processorid_t)-1;
	prog->data->copy_wait_time = 0;
	prog->data->copy_rename_count = 0;
	CPUSET_DEL(prog->data->cpu_slave_set, cpuid);

	for (i = 0; i < NCPU; i++) {
		prog->data->cpu_ml[i] = NULL;
	}

	/*
	 * max_elms -	max number of memlist structures that
	 *		may be allocated for the CPU memory list.
	 *		If there are too many memory span (because
	 *		of fragmentation) than number of memlist
	 *		available, we should return error.
	 */
	max_elms = drmach_setup_memlist(prog);
	if (max_elms < mlist_size) {
		err = drerr_new(1, EOPL_FMEM_SETUP, NULL);
		goto err_out;
	}

	active_cpus = 0;
	if (drmach_disable_mcopy) {
		active_cpus = 1;
		CPUSET_ADD(prog->data->cpu_copy_set, cpuid);
	} else {
		int max_cpu_num;
		/*
		 * The parallel copy procedure is going to split some
		 * of the elements of the original memory copy list.
		 * The number of added elements can be up to
		 * (max_cpu_num - 1).  It means that max_cpu_num
		 * should satisfy the following condition:
		 * (max_cpu_num - 1) + mlist_size <= max_elms.
		 */
		max_cpu_num = max_elms - mlist_size + 1;

		for (i = 0; i < NCPU; i++) {
			if (CPU_IN_SET(cpu_ready_set, i) &&
			    CPU_ACTIVE(cpu[i])) {
				/*
				 * To reduce the level-2 cache contention only
				 * one strand per core will participate
				 * in the copy. If the strand with even cpu_id
				 * number is present in the ready set, we will
				 * include this strand in the copy set. If it
				 * is not present in the ready set, we check for
				 * the strand with the consecutive odd cpu_id
				 * and include it, provided that it is
				 * present in the ready set.
				 */
				if (!(i & 0x1) ||
				    !CPU_IN_SET(prog->data->cpu_copy_set,
				    i - 1)) {
					CPUSET_ADD(prog->data->cpu_copy_set, i);
					active_cpus++;
					/*
					 * We cannot have more than
					 * max_cpu_num CPUs in the copy
					 * set, because each CPU has to
					 * have at least one element
					 * long memory copy list.
					 */
					if (active_cpus >= max_cpu_num)
						break;

				}
			}
		}
	}

	x_ml = c_ml;
	sz = 0;
	while (x_ml != NULL) {
		sz += x_ml->ml_size;
		x_ml = x_ml->ml_next;
	}

	copy_sz = sz/active_cpus;
	copy_sz = roundup(copy_sz, MMU_PAGESIZE4M);

	while (sz > copy_sz*active_cpus) {
		copy_sz += MMU_PAGESIZE4M;
	}

	prog->data->stick_freq = system_clock_freq;
	prog->data->copy_delay = ((copy_sz / min_copy_size_per_sec) + 2) *
	    system_clock_freq;

	x_ml = c_ml;
	c_addr = x_ml->ml_address;
	c_size = x_ml->ml_size;

	for (i = 0; i < NCPU; i++) {
		prog->stat->nbytes[i] = 0;
		if (!CPU_IN_SET(prog->data->cpu_copy_set, i)) {
			continue;
		}
		sz = copy_sz;

		while (sz) {
			if (c_size > sz) {
				if ((prog->data->cpu_ml[i] =
				    drmach_memlist_add_span(prog,
				    prog->data->cpu_ml[i],
				    c_addr, sz)) == NULL) {
					cmn_err(CE_WARN,
					    "Unexpected drmach_memlist_add_span"
					    " failure.");
					err = drerr_new(1, EOPL_FMEM_SETUP,
					    NULL);
					mc_resume();
					goto out;
				}
				c_addr += sz;
				c_size -= sz;
				break;
			} else {
				sz -= c_size;
				if ((prog->data->cpu_ml[i] =
				    drmach_memlist_add_span(prog,
				    prog->data->cpu_ml[i],
				    c_addr, c_size)) == NULL) {
					cmn_err(CE_WARN,
					    "Unexpected drmach_memlist_add_span"
					    " failure.");
					err = drerr_new(1, EOPL_FMEM_SETUP,
					    NULL);
					mc_resume();
					goto out;
				}

				x_ml = x_ml->ml_next;
				if (x_ml != NULL) {
					c_addr = x_ml->ml_address;
					c_size = x_ml->ml_size;
				} else {
					goto end;
				}
			}
		}
	}
end:
	prog->data->s_copybasepa = s_copybasepa;
	prog->data->t_copybasepa = t_copybasepa;
	prog->data->c_ml = c_ml;
	*pgm_id = prog_kmem;

	/* Unmap the alternate space.  It will have to be remapped again */
	drmach_unlock_critical((caddr_t)prog);
	return (NULL);

err_out:
	mc_resume();
	rv = (*prog->data->scf_fmem_cancel)();
	if (rv) {
		cmn_err(CE_WARN, "scf_fmem_cancel() failed rv=0x%x", rv);
	}
out:
	if (prog != NULL) {
		drmach_unlock_critical((caddr_t)prog);
		vmem_free(heap_arena, prog, DRMACH_FMEM_LOCKED_PAGES *
		    PAGESIZE);
	}
	if (prog_kmem != NULL) {
		kmem_free(prog_kmem, DRMACH_FMEM_LOCKED_PAGES * PAGESIZE);
	}
	return (err);
}

sbd_error_t *
drmach_copy_rename_fini(drmachid_t id)
{
	drmach_copy_rename_program_t	*prog = id;
	sbd_error_t			*err = NULL;
	int				rv;
	uint_t				fmem_error;

	/*
	 * Note that we have to delay calling SCF to find out the
	 * status of the FMEM operation here because SCF cannot
	 * respond while it is suspended.
	 * This create a small window when we are sure about the
	 * base address of the system board.
	 * If there is any call to mc-opl to get memory unum,
	 * mc-opl will return UNKNOWN as the unum.
	 */

	/*
	 * we have to remap again because all the pointer like data,
	 * critical in prog are based on the alternate vmem space.
	 */
	(void) drmach_lock_critical((caddr_t)prog, (caddr_t)prog->locked_prog);

	if (prog->data->c_ml != NULL)
		memlist_delete(prog->data->c_ml);

	if ((prog->data->fmem_status.op &
	    (OPL_FMEM_SCF_START | OPL_FMEM_MC_SUSPEND)) !=
	    (OPL_FMEM_SCF_START | OPL_FMEM_MC_SUSPEND)) {
		cmn_err(CE_PANIC, "drmach_copy_rename_fini: invalid op "
		    "code %x\n", prog->data->fmem_status.op);
	}

	fmem_error = prog->data->fmem_status.error;
	if (fmem_error != ESBD_NOERROR) {
		err = drerr_new(1, fmem_error, NULL);
	}

	/* possible ops are SCF_START, MC_SUSPEND */
	if (prog->critical->fmem_issued) {
		if (fmem_error != ESBD_NOERROR) {
			cmn_err(CE_PANIC, "Irrecoverable FMEM error %d\n",
			    fmem_error);
		}
		rv = (*prog->data->scf_fmem_end)();
		if (rv) {
			cmn_err(CE_PANIC, "scf_fmem_end() failed rv=%d", rv);
		}
		/*
		 * If we get here, rename is successful.
		 * Do all the copy rename post processing.
		 */
		drmach_swap_pa((drmach_mem_t *)prog->data->s_mem,
		    (drmach_mem_t *)prog->data->t_mem);
	} else {
		rv = (*prog->data->scf_fmem_cancel)();
		if (rv) {
			cmn_err(CE_WARN, "scf_fmem_cancel() failed rv=0x%x",
			    rv);
			if (!err) {
				err = drerr_new(1, EOPL_SCF_FMEM_CANCEL,
				    "scf_fmem_cancel() failed. rv = 0x%x", rv);
			}
		}
	}
	/* soft resume mac patrol */
	(*prog->data->mc_resume)();

	drmach_unlock_critical((caddr_t)prog->locked_prog);

	vmem_free(heap_arena, prog->locked_prog,
	    DRMACH_FMEM_LOCKED_PAGES * PAGESIZE);
	kmem_free(prog, DRMACH_FMEM_LOCKED_PAGES * PAGESIZE);
	return (err);
}

/*ARGSUSED*/
static void
drmach_copy_rename_slave(struct regs *rp, drmachid_t id)
{
	drmach_copy_rename_program_t	*prog =
	    (drmach_copy_rename_program_t *)id;
	register int			cpuid;
	extern void			drmach_flush();
	extern void			membar_sync_il();
	extern void			drmach_flush_icache();
	on_trap_data_t			otd;

	cpuid = CPU->cpu_id;

	if (on_trap(&otd, OT_DATA_EC)) {
		no_trap();
		prog->data->error[cpuid] = EOPL_FMEM_COPY_ERROR;
		prog->critical->stat[cpuid] = FMEM_LOOP_EXIT;
		drmach_flush_icache();
		membar_sync_il();
		return;
	}


	/*
	 * jmp drmach_copy_rename_prog().
	 */

	drmach_flush(prog->critical, PAGESIZE);
	(void) prog->critical->run(prog, cpuid);
	drmach_flush_icache();

	no_trap();

	prog->critical->stat[cpuid] = FMEM_LOOP_EXIT;

	membar_sync_il();
}

static void
drmach_swap_pa(drmach_mem_t *s_mem, drmach_mem_t *t_mem)
{
	uint64_t s_base, t_base;
	drmach_board_t *s_board, *t_board;
	struct memlist *ml;

	s_board = s_mem->dev.bp;
	t_board = t_mem->dev.bp;
	if (s_board == NULL || t_board == NULL) {
		cmn_err(CE_PANIC, "Cannot locate source or target board\n");
		return;
	}
	s_base = s_mem->slice_base;
	t_base = t_mem->slice_base;

	s_mem->slice_base = t_base;
	s_mem->base_pa = (s_mem->base_pa - s_base) + t_base;

	for (ml = s_mem->memlist; ml; ml = ml->ml_next) {
		ml->ml_address = ml->ml_address - s_base + t_base;
	}

	t_mem->slice_base = s_base;
	t_mem->base_pa = (t_mem->base_pa - t_base) + s_base;

	for (ml = t_mem->memlist; ml; ml = ml->ml_next) {
		ml->ml_address = ml->ml_address - t_base + s_base;
	}

	/*
	 * IKP has to update the sb-mem-ranges for mac patrol driver
	 * when it resumes, it will re-read the sb-mem-range property
	 * to get the new base address
	 */
	if (oplcfg_pa_swap(s_board->bnum, t_board->bnum) != 0)
		cmn_err(CE_PANIC, "Could not update device nodes\n");
}

void
drmach_copy_rename(drmachid_t id)
{
	drmach_copy_rename_program_t	*prog_kmem = id;
	drmach_copy_rename_program_t	*prog;
	cpuset_t	cpuset;
	int		cpuid;
	uint64_t	inst;
	register int	rtn;
	extern int	in_sync;
	int		old_in_sync;
	extern void	drmach_sys_trap();
	extern void	drmach_flush();
	extern void	drmach_flush_icache();
	extern uint64_t	patch_inst(uint64_t *, uint64_t);
	on_trap_data_t	otd;


	prog = prog_kmem->locked_prog;


	/*
	 * We must immediately drop in the TLB because all pointers
	 * are based on the alternate vmem space.
	 */

	(void) drmach_lock_critical((caddr_t)prog_kmem, (caddr_t)prog);

	/*
	 * we call scf to get the base address here becuase if scf
	 * has not been suspended yet, the active path can be changing and
	 * sometimes it is not even mapped.  We call the interface when
	 * the OS has been quiesced.
	 */
	prog->critical->scf_reg_base = (*prog->data->scf_get_base_addr)();

	if (prog->critical->scf_reg_base == (uint64_t)-1 ||
	    prog->critical->scf_reg_base == 0) {
		prog->data->fmem_status.error = EOPL_FMEM_SCF_ERR;
		drmach_unlock_critical((caddr_t)prog);
		return;
	}

	cpuset = prog->data->cpu_ready_set;

	for (cpuid = 0; cpuid < NCPU; cpuid++) {
		if (CPU_IN_SET(cpuset, cpuid)) {
			prog->critical->stat[cpuid] = FMEM_LOOP_START;
			prog->data->error[cpuid] = ESBD_NOERROR;
		}
	}

	old_in_sync = in_sync;
	in_sync = 1;
	cpuid = CPU->cpu_id;

	CPUSET_DEL(cpuset, cpuid);

	for (cpuid = 0; cpuid < NCPU; cpuid++) {
		if (CPU_IN_SET(cpuset, cpuid)) {
			xc_one(cpuid, (xcfunc_t *)drmach_lock_critical,
			    (uint64_t)prog_kmem, (uint64_t)prog);
		}
	}

	cpuid = CPU->cpu_id;

	xt_some(cpuset, (xcfunc_t *)drmach_sys_trap,
	    (uint64_t)drmach_copy_rename_slave, (uint64_t)prog);
	xt_sync(cpuset);

	if (on_trap(&otd, OT_DATA_EC)) {
		rtn = EOPL_FMEM_COPY_ERROR;
		drmach_flush_icache();
		goto done;
	}

	/*
	 * jmp drmach_copy_rename_prog().
	 */

	drmach_flush(prog->critical, PAGESIZE);
	rtn = prog->critical->run(prog, cpuid);

	drmach_flush_icache();


done:
	no_trap();
	if (rtn == EOPL_FMEM_HW_ERROR) {
		kpreempt_enable();
		prom_panic("URGENT_ERROR_TRAP is detected during FMEM.\n");
	}

	/*
	 * In normal case, all slave CPU's are still spinning in
	 * the assembly code.  The master has to patch the instruction
	 * to get them out.
	 * In error case, e.g. COPY_ERROR, some slave CPU's might
	 * have aborted and already returned and sset LOOP_EXIT status.
	 * Some CPU might still be copying.
	 * In any case, some delay is necessary to give them
	 * enough time to set the LOOP_EXIT status.
	 */

	for (;;) {
		inst = patch_inst((uint64_t *)prog->critical->loop_rtn,
		    prog->critical->inst_loop_ret);
		if (prog->critical->inst_loop_ret == inst) {
			break;
		}
	}

	for (cpuid = 0; cpuid < NCPU; cpuid++) {
		uint64_t	last, now;
		if (!CPU_IN_SET(cpuset, cpuid)) {
			continue;
		}
		last = prog->stat->nbytes[cpuid];
		/*
		 * Wait for all CPU to exit.
		 * However we do not want an infinite loop
		 * so we detect hangup situation here.
		 * If the slave CPU is still copying data,
		 * we will continue to wait.
		 * In error cases, the master has already set
		 * fmem_status.error to abort the copying.
		 * 1 m.s delay for them to abort copying and
		 * return to drmach_copy_rename_slave to set
		 * FMEM_LOOP_EXIT status should be enough.
		 */
		for (;;) {
			if (prog->critical->stat[cpuid] == FMEM_LOOP_EXIT)
				break;
			drmach_sleep_il();
			drv_usecwait(1000);
			now = prog->stat->nbytes[cpuid];
			if (now <= last) {
				drv_usecwait(1000);
				if (prog->critical->stat[cpuid] ==
				    FMEM_LOOP_EXIT)
					break;
				cmn_err(CE_PANIC, "CPU %d hang during Copy "
				    "Rename", cpuid);
			}
			last = now;
		}
		if (prog->data->error[cpuid] == EOPL_FMEM_HW_ERROR) {
			prom_panic("URGENT_ERROR_TRAP is detected during "
			    "FMEM.\n");
		}
	}

	/*
	 * This must be done after all strands have exit.
	 * Removing the TLB entry will affect both strands
	 * in the same core.
	 */

	for (cpuid = 0; cpuid < NCPU; cpuid++) {
		if (CPU_IN_SET(cpuset, cpuid)) {
			xc_one(cpuid, (xcfunc_t *)drmach_unlock_critical,
			    (uint64_t)prog, 0);
		}
	}

	in_sync = old_in_sync;

	/*
	 * we should unlock before the following lock to keep the kpreempt
	 * count correct.
	 */
	(void) drmach_unlock_critical((caddr_t)prog);

	/*
	 * we must remap again.  TLB might have been removed in above xcall.
	 */

	(void) drmach_lock_critical((caddr_t)prog_kmem, (caddr_t)prog);

	if (prog->data->fmem_status.error == ESBD_NOERROR)
		prog->data->fmem_status.error = rtn;

	if (prog->data->copy_wait_time > 0) {
		DRMACH_PR("Unexpected long wait time %ld seconds "
		    "during copy rename on CPU %d\n",
		    prog->data->copy_wait_time/prog->data->stick_freq,
		    prog->data->slowest_cpuid);
	}
	drmach_unlock_critical((caddr_t)prog);
}
