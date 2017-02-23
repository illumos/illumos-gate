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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
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
#include <sys/processor.h>
#include <sys/spitregs.h>
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

#include <sys/starfire.h>	/* plat_max_... decls */
#include <sys/cvc.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/drmach.h>
#include <sys/dr_util.h>
#include <sys/pda.h>

#include <sys/sysevent.h>
#include <sys/sysevent/dr.h>
#include <sys/sysevent/eventdefs.h>


extern void		bcopy32_il(uint64_t, uint64_t);
extern void		flush_ecache_il(
				uint64_t physaddr, int size, int linesz);
extern uint_t		ldphysio_il(uint64_t physaddr);
extern void		stphysio_il(uint64_t physaddr, uint_t value);

extern uint64_t		mc_get_mem_alignment(void);
extern uint64_t		mc_get_asr_addr(pnode_t);
extern uint64_t		mc_get_idle_addr(pnode_t);
extern uint64_t		mc_get_alignment_mask(pnode_t);
extern int		mc_read_asr(pnode_t, uint_t *);
extern int		mc_write_asr(pnode_t, uint_t);
extern uint64_t		mc_asr_to_pa(uint_t);
extern uint_t		mc_pa_to_asr(uint_t, uint64_t);

extern int		pc_madr_add(int, int, int, int);

typedef struct {
	struct drmach_node	*node;
	void			*data;
} drmach_node_walk_args_t;

typedef struct drmach_node {
	void		*here;

	pnode_t		 (*get_dnode)(struct drmach_node *node);
	int		 (*walk)(struct drmach_node *node, void *data,
				int (*cb)(drmach_node_walk_args_t *args));
} drmach_node_t;

typedef struct {
	int		 min_index;
	int		 max_index;
	int		 arr_sz;
	drmachid_t	*arr;
} drmach_array_t;

typedef struct {
	void		*isa;

	sbd_error_t	*(*release)(drmachid_t);
	sbd_error_t	*(*status)(drmachid_t, drmach_status_t *);

	char		 name[MAXNAMELEN];
} drmach_common_t;

typedef struct {
	drmach_common_t	 cm;
	int		 bnum;
	int		 assigned;
	int		 powered;
	int		 connect_cpuid;
	int		 cond;
	drmach_node_t	*tree;
	drmach_array_t	*devices;
} drmach_board_t;

typedef struct {
	drmach_common_t	 cm;
	drmach_board_t	*bp;
	int		 unum;
	int		 busy;
	int		 powered;
	const char	*type;
	drmach_node_t	*node;
} drmach_device_t;

typedef struct {
	int		 flags;
	drmach_device_t	*dp;
	sbd_error_t	*err;
	dev_info_t	*dip;
} drmach_config_args_t;

typedef struct {
	uint64_t	 idle_addr;
	drmach_device_t	*mem;
} drmach_mc_idle_script_t;

typedef struct {
	uint64_t	masr_addr;
	uint_t		masr;
	uint_t		_filler;
} drmach_rename_script_t;

typedef struct {
	void		(*run)(void *arg);
	caddr_t		data;
	pda_handle_t	*ph;
	struct memlist	*c_ml;
	uint64_t	s_copybasepa;
	uint64_t	t_copybasepa;
	drmach_device_t	*restless_mc;	/* diagnostic output */
} drmach_copy_rename_program_t;

typedef enum {
	DO_IDLE,
	DO_UNIDLE,
	DO_PAUSE,
	DO_UNPAUSE
} drmach_iopc_op_t;

typedef struct {
	drmach_board_t	*obj;
	int		 ndevs;
	void		*a;
	sbd_error_t	*(*found)(void *a, const char *, int, drmachid_t);
	sbd_error_t	*err;
} drmach_board_cb_data_t;

static caddr_t		 drmach_shutdown_va;

static int		 drmach_initialized;
static drmach_array_t	*drmach_boards;

static int		 drmach_cpu_delay = 100;
static int		 drmach_cpu_ntries = 50000;

volatile uchar_t	*drmach_xt_mb;

/*
 * Do not change the drmach_shutdown_mbox structure without
 * considering the drmach_shutdown_asm assembly language code.
 */
struct drmach_shutdown_mbox {
	uint64_t	estack;
	uint64_t	flushaddr;
	int		size;
	int		linesize;
	uint64_t	physaddr;
};
struct drmach_shutdown_mbox	*drmach_shutdown_asm_mbox;

static int		drmach_fini(void);
static sbd_error_t	*drmach_device_new(drmach_node_t *,
				drmach_board_t *, drmach_device_t **);
static sbd_error_t	*drmach_cpu_new(drmach_device_t *);
static sbd_error_t	*drmach_mem_new(drmach_device_t *);
static sbd_error_t	*drmach_io_new(drmach_device_t *);
static sbd_error_t	*drmach_board_release(drmachid_t);
static sbd_error_t	*drmach_board_status(drmachid_t, drmach_status_t *);
static sbd_error_t	*drmach_cpu_release(drmachid_t);
static sbd_error_t	*drmach_cpu_status(drmachid_t, drmach_status_t *);
static sbd_error_t	*drmach_io_release(drmachid_t);
static sbd_error_t	*drmach_io_status(drmachid_t, drmach_status_t *);
static sbd_error_t	*drmach_mem_release(drmachid_t);
static sbd_error_t	*drmach_mem_status(drmachid_t, drmach_status_t *);

extern struct cpu	*SIGBCPU;

#ifdef DEBUG

#define	DRMACH_PR		if (drmach_debug) printf
int drmach_debug = 0;		 /* set to non-zero to enable debug messages */
#else

#define	DRMACH_PR		_NOTE(CONSTANTCONDITION) if (0) printf
#endif /* DEBUG */

#define	DRMACH_OBJ(id)		((drmach_common_t *)id)

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

#define	DRMACH_CPUID2BNUM(cpuid) \
	((cpuid) / MAX_CPU_UNITS_PER_BOARD)

#define	DRMACH_INTERNAL_ERROR() \
	drerr_new(1, ESTF_INTERNAL, drmach_ie_fmt, __LINE__)
static char		*drmach_ie_fmt = "drmach.c %d";

static struct {
	const char	 *name;
	const char	 *type;
	sbd_error_t	 *(*new)(drmach_device_t *);
} name2type[] = {
	{ "SUNW,UltraSPARC",	DRMACH_DEVTYPE_CPU,  drmach_cpu_new },
	{ "mem-unit",		DRMACH_DEVTYPE_MEM,  drmach_mem_new },
	{ "pci",		DRMACH_DEVTYPE_PCI,  drmach_io_new  },
	{ "sbus",		DRMACH_DEVTYPE_SBUS, drmach_io_new  },
};

/* node types to cleanup when a board is unconfigured */
#define	MISC_COUNTER_TIMER_DEVNAME	"counter-timer"
#define	MISC_PERF_COUNTER_DEVNAME	"perf-counter"

/* utility */
#define	MBYTE	(1048576ull)

/*
 * drmach autoconfiguration data structures and interfaces
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"Sun Enterprise 10000 DR"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

static kmutex_t drmach_i_lock;

int
_init(void)
{
	int err;

	/* check that we have the correct version of obp */
	if (prom_test("SUNW,UE10000,add-brd") != 0) {

		cmn_err(CE_WARN, "!OBP/SSP upgrade is required to enable "
		    "DR Functionality");

		return (-1);
	}

	mutex_init(&drmach_i_lock, NULL, MUTEX_DRIVER, NULL);

	drmach_xt_mb = (uchar_t *)vmem_alloc(static_alloc_arena,
	    NCPU * sizeof (uchar_t), VM_SLEEP);
	drmach_shutdown_asm_mbox = (struct drmach_shutdown_mbox *)
	    vmem_alloc(static_alloc_arena, sizeof (struct drmach_shutdown_mbox),
	    VM_SLEEP);

	if ((err = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&drmach_i_lock);
		vmem_free(static_alloc_arena, (void *)drmach_xt_mb,
		    NCPU * sizeof (uchar_t));
		vmem_free(static_alloc_arena, (void *)drmach_shutdown_asm_mbox,
		    sizeof (struct drmach_shutdown_mbox));
	}

	return (err);
}

int
_fini(void)
{
	if (drmach_fini())
		return (DDI_FAILURE);
	else
		return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static pnode_t
drmach_node_obp_get_dnode(drmach_node_t *np)
{
	return ((pnode_t)(uintptr_t)np->here);
}

static int
drmach_node_obp_walk(drmach_node_t *np, void *data,
		int (*cb)(drmach_node_walk_args_t *args))
{
	pnode_t			nodeid;
	int			rv;
	drmach_node_walk_args_t	args;

	/* initialized args structure for callback */
	args.node = np;
	args.data = data;

	nodeid = prom_childnode(prom_rootnode());

	/* save our new position with in the tree */
	np->here = (void *)(uintptr_t)nodeid;

	rv = 0;
	while (nodeid != OBP_NONODE) {
		rv = (*cb)(&args);
		if (rv)
			break;

		nodeid = prom_nextnode(nodeid);

		/* save our new position with in the tree */
		np->here = (void *)(uintptr_t)nodeid;
	}

	return (rv);
}

static drmach_node_t *
drmach_node_new(void)
{
	drmach_node_t *np;

	np = kmem_zalloc(sizeof (drmach_node_t), KM_SLEEP);

	np->get_dnode = drmach_node_obp_get_dnode;
	np->walk = drmach_node_obp_walk;

	return (np);
}

static void
drmach_node_dispose(drmach_node_t *np)
{
	kmem_free(np, sizeof (*np));
}

static dev_info_t *
drmach_node_get_dip(drmach_node_t *np)
{
	pnode_t nodeid;

	nodeid = np->get_dnode(np);
	if (nodeid == OBP_NONODE)
		return (NULL);
	else {
		dev_info_t *dip;

		/* The root node doesn't have to be held */
		dip = e_ddi_nodeid_to_dip(nodeid);
		if (dip) {
			/*
			 * Branch rooted at dip is already held, so release
			 * hold acquired in e_ddi_nodeid_to_dip()
			 */
			ddi_release_devi(dip);
			ASSERT(e_ddi_branch_held(dip));
		}

		return (dip);
	}
	/*NOTREACHED*/
}

static pnode_t
drmach_node_get_dnode(drmach_node_t *np)
{
	return (np->get_dnode(np));
}

static int
drmach_node_walk(drmach_node_t *np, void *param,
		int (*cb)(drmach_node_walk_args_t *args))
{
	return (np->walk(np, param, cb));
}

static int
drmach_node_get_prop(drmach_node_t *np, char *name, void *buf)
{
	pnode_t	nodeid;
	int	rv;

	nodeid = np->get_dnode(np);
	if (nodeid == OBP_NONODE)
		rv = -1;
	else if (prom_getproplen(nodeid, (caddr_t)name) < 0)
		rv = -1;
	else {
		(void) prom_getprop(nodeid, (caddr_t)name, (caddr_t)buf);
		rv = 0;
	}

	return (rv);
}

static int
drmach_node_get_proplen(drmach_node_t *np, char *name, int *len)
{
	pnode_t	 nodeid;
	int	 rv;

	nodeid = np->get_dnode(np);
	if (nodeid == OBP_NONODE)
		rv = -1;
	else {
		*len = prom_getproplen(nodeid, (caddr_t)name);
		rv = (*len < 0 ? -1 : 0);
	}

	return (rv);
}

static drmachid_t
drmach_node_dup(drmach_node_t *np)
{
	drmach_node_t *dup;

	dup = drmach_node_new();
	dup->here = np->here;

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

/*ARGSUSED*/
static int
drmach_prom_select(pnode_t nodeid, void *arg, uint_t flags)
{
	int			rprop[64];
	pnode_t			saved;
	drmach_config_args_t	*ap = (drmach_config_args_t *)arg;
	drmach_device_t		*dp = ap->dp;
	sbd_error_t		*err;

	saved = drmach_node_get_dnode(dp->node);

	if (nodeid != saved)
		return (DDI_FAILURE);

	if (saved == OBP_NONODE) {
		err = DRMACH_INTERNAL_ERROR();
		DRERR_SET_C(&ap->err, &err);
		return (DDI_FAILURE);
	}

	if (prom_getprop(nodeid, OBP_REG, (caddr_t)rprop) <= 0) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static void
drmach_branch_callback(dev_info_t *rdip, void *arg, uint_t flags)
{
	drmach_config_args_t	*ap = (drmach_config_args_t *)arg;

	ASSERT(ap->dip == NULL);

	ap->dip = rdip;
}

sbd_error_t *
drmach_configure(drmachid_t id, int flags)
{
	drmach_device_t		*dp;
	sbd_error_t		*err;
	drmach_config_args_t	ca;
	devi_branch_t		b = {0};
	dev_info_t		*fdip = NULL;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	dp = id;

	ca.dp = dp;
	ca.flags = flags;
	ca.err = NULL;		/* will be set if error detected */
	ca.dip = NULL;

	b.arg = &ca;
	b.type = DEVI_BRANCH_PROM;
	b.create.prom_branch_select = drmach_prom_select;
	b.devi_branch_callback = drmach_branch_callback;

	if (e_ddi_branch_create(ddi_root_node(), &b, &fdip,
	    DEVI_BRANCH_CHILD | DEVI_BRANCH_CONFIGURE) != 0) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		/*
		 * If non-NULL, fdip is returned held and must be released.
		 */
		if (fdip != NULL) {
			(void) ddi_pathname(fdip, path);
			ddi_release_devi(fdip);
		} else if (ca.dip != NULL) {
			/* safe to call ddi_pathname as dip already held */
			(void) ddi_pathname(ca.dip, path);
		} else {
			(void) strcpy(path, "<none>");
		}

		err = drerr_new(1, ESTF_DRVFAIL, path);
		DRERR_SET_C(&ca.err, &err);
		kmem_free(path, MAXPATHLEN);
	}

	return (ca.err);
}

static sbd_error_t *
drmach_device_new(drmach_node_t *node,
	drmach_board_t *bp, drmach_device_t **dpp)
{
	int		 i;
	int		 rv;
	drmach_device_t	*dp;
	sbd_error_t	*err;
	char		 name[OBP_MAXDRVNAME];

	rv = drmach_node_get_prop(node, OBP_NAME, name);
	if (rv) {
		/* every node is expected to have a name */
		err = drerr_new(1, ESTF_GETPROP,
		    "PROM Node 0x%x: property %s",
		    (uint_t)node->get_dnode(node), OBP_NAME);

		return (err);
	}

	/*
	 * The node currently being examined is not listed in the name2type[]
	 * array.  In this case, the node is no interest to drmach.  Both
	 * dp and err are initialized here to yield nothing (no device or
	 * error structure) for this case.
	 */
	for (i = 0; i < sizeof (name2type) / sizeof (name2type[0]); i++)
		if (strcmp(name2type[i].name, name) == 0)
			break;

	if (i < sizeof (name2type) / sizeof (name2type[0])) {
		dp = kmem_zalloc(sizeof (drmach_device_t), KM_SLEEP);

		dp->bp = bp;
		dp->unum = -1;
		dp->node = drmach_node_dup(node);
		dp->type = name2type[i].type;

		err = (name2type[i].new)(dp);
		if (err) {
			drmach_node_dispose(node);
			kmem_free(dp, sizeof (*dp));
			dp = NULL;
		}

		*dpp = dp;
		return (err);
	}

	/*
	 * The node currently being examined is not listed in the name2type[]
	 * array.  In this case, the node is no interest to drmach.  Both
	 * dp and err are initialized here to yield nothing (no device or
	 * error structure) for this case.
	 */
	*dpp = NULL;
	return (NULL);
}

static void
drmach_device_dispose(drmachid_t id)
{
	drmach_device_t *self = id;

	if (self->node)
		drmach_node_dispose(self->node);

	kmem_free(self, sizeof (*self));
}

static sbd_error_t *
drmach_device_get_prop(drmach_device_t *dp, char *name, void *buf)
{
	sbd_error_t	*err = NULL;
	int		 rv;

	rv = drmach_node_get_prop(dp->node, name, buf);
	if (rv) {
		err = drerr_new(1, ESTF_GETPROP,
		    "%s::%s: property %s",
		    dp->bp->cm.name, dp->cm.name, name);
	}

	return (err);
}

static sbd_error_t *
drmach_device_get_proplen(drmach_device_t *dp, char *name, int *len)
{
	sbd_error_t	*err = NULL;
	int		 rv;

	rv = drmach_node_get_proplen(dp->node, name, len);
	if (rv) {
		err = drerr_new(1, ESTF_GETPROPLEN,
		    "%s::%s: property %s",
		    dp->bp->cm.name, dp->cm.name, name);
	}

	return (err);
}

static drmach_board_t *
drmach_board_new(int bnum)
{
	drmach_board_t	*bp;

	bp = kmem_zalloc(sizeof (drmach_board_t), KM_SLEEP);

	bp->cm.isa = (void *)drmach_board_new;
	bp->cm.release = drmach_board_release;
	bp->cm.status = drmach_board_status;

	(void) drmach_board_name(bnum, bp->cm.name, sizeof (bp->cm.name));

	bp->bnum = bnum;
	bp->devices = NULL;
	bp->connect_cpuid = -1;
	bp->tree = drmach_node_new();
	bp->assigned = !drmach_initialized;
	bp->powered = !drmach_initialized;

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
		return (drerr_new(0, ESTF_INAPPROP, NULL));
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

			err = drmach_status(d_id, &d_stat);
			if (err)
				break;

			stat->busy |= d_stat.busy;
			stat->configured |= d_stat.configured;

			rv = drmach_array_next(bp->devices, &d_idx, &d_id);
		}
	}

	return (err);
}

/* a simple routine to reduce redundancy of this common logic */
static pda_handle_t
drmach_pda_open(void)
{
	pda_handle_t ph;

	ph = pda_open();
	if (ph == NULL) {
		/* catch in debug kernels */
		ASSERT(0);
		cmn_err(CE_WARN, "pda_open failed");
	}

	return (ph);
}

#ifdef DEBUG
int drmach_init_break = 0;
#endif

static int
hold_rele_branch(dev_info_t *rdip, void *arg)
{
	int	i;
	int	*holdp = (int *)arg;
	char	*name = ddi_node_name(rdip);

	/*
	 * For Starfire, we must be children of the root devinfo node
	 */
	ASSERT(ddi_get_parent(rdip) == ddi_root_node());

	for (i = 0; i < sizeof (name2type) / sizeof (name2type[0]); i++)
		if (strcmp(name2type[i].name, name) == 0)
			break;

	if (i == sizeof (name2type) / sizeof (name2type[0])) {
		/* Not of interest to us */
		return (DDI_WALK_PRUNECHILD);
	}

	if (*holdp) {
		ASSERT(!e_ddi_branch_held(rdip));
		e_ddi_branch_hold(rdip);
	} else {
		ASSERT(e_ddi_branch_held(rdip));
		e_ddi_branch_rele(rdip);
	}

	return (DDI_WALK_PRUNECHILD);
}

static int
drmach_init(void)
{
	pnode_t		nodeid;
	dev_info_t	*rdip;
	int		hold, circ;

#ifdef DEBUG
	if (drmach_init_break)
		debug_enter("drmach_init: drmach_init_break set\n");
#endif
	mutex_enter(&drmach_i_lock);
	if (drmach_initialized) {
		mutex_exit(&drmach_i_lock);
		return (0);
	}

	drmach_boards = drmach_array_new(0, MAX_BOARDS - 1);

	nodeid = prom_childnode(prom_rootnode());
	do {
		int		 bnum;
		drmachid_t	 id;

		bnum = -1;
		(void) prom_getprop(nodeid, OBP_BOARDNUM, (caddr_t)&bnum);
		if (bnum == -1)
			continue;

		if (drmach_array_get(drmach_boards, bnum, &id) == -1) {
			cmn_err(CE_WARN, "OBP node 0x%x has"
			    " invalid property value, %s=%d",
			    nodeid, OBP_BOARDNUM, bnum);

			/* clean up */
			drmach_array_dispose(
			    drmach_boards, drmach_board_dispose);

			mutex_exit(&drmach_i_lock);
			return (-1);
		} else if (id == NULL)
			(void) drmach_board_new(bnum);
	} while ((nodeid = prom_nextnode(nodeid)) != OBP_NONODE);

	drmach_shutdown_va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);

	/*
	 * Walk immediate children of devinfo root node and hold
	 * all devinfo branches of interest.
	 */
	hold = 1;
	rdip = ddi_root_node();

	ndi_devi_enter(rdip, &circ);
	ddi_walk_devs(ddi_get_child(rdip), hold_rele_branch, &hold);
	ndi_devi_exit(rdip, circ);

	drmach_initialized = 1;

	mutex_exit(&drmach_i_lock);

	return (0);
}

static int
drmach_fini(void)
{
	dev_info_t	*rdip;
	int		hold, circ;

	if (drmach_initialized) {
		int		busy = 0;
		int		rv;
		int		idx;
		drmachid_t	id;

		ASSERT(drmach_boards != NULL);

		rv = drmach_array_first(drmach_boards, &idx, &id);
		while (rv == 0) {
			sbd_error_t	*err;
			drmach_status_t stat;

			err = drmach_board_status(id, &stat);
			if (err) {
				/* catch in debug kernels */
				ASSERT(0);
				sbd_err_clear(&err);
				busy = 1;
			} else
				busy |= stat.busy;

			rv = drmach_array_next(drmach_boards, &idx, &id);
		}

		if (busy)
			return (-1);

		drmach_array_dispose(drmach_boards, drmach_board_dispose);
		drmach_boards = NULL;

		vmem_free(heap_arena, drmach_shutdown_va, PAGESIZE);

		/*
		 * Walk immediate children of the root devinfo node
		 * releasing holds acquired on branches in drmach_init()
		 */
		hold = 0;
		rdip = ddi_root_node();

		ndi_devi_enter(rdip, &circ);
		ddi_walk_devs(ddi_get_child(rdip), hold_rele_branch, &hold);
		ndi_devi_exit(rdip, circ);

		mutex_destroy(&drmach_i_lock);

		drmach_initialized = 0;
	}
	if (drmach_xt_mb != NULL) {
		vmem_free(static_alloc_arena, (void *)drmach_xt_mb,
		    NCPU * sizeof (uchar_t));
	}
	if (drmach_shutdown_asm_mbox != NULL) {
		vmem_free(static_alloc_arena, (void *)drmach_shutdown_asm_mbox,
		    sizeof (struct drmach_shutdown_mbox));
	}
	return (0);
}

static sbd_error_t *
drmach_get_mc_asr_addr(drmachid_t id, uint64_t *pa)
{
	drmach_device_t	*dp;
	pnode_t		nodeid;
	uint64_t	addr;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	dp = id;

	nodeid = drmach_node_get_dnode(dp->node);
	if (nodeid == OBP_NONODE || nodeid == OBP_BADNODE)
		return (DRMACH_INTERNAL_ERROR());

	addr = mc_get_asr_addr(nodeid);
	if (addr == (uint64_t)-1)
		return (DRMACH_INTERNAL_ERROR());

	*pa = addr;
	return (NULL);
}

static sbd_error_t *
drmach_get_mc_idle_addr(drmachid_t id, uint64_t *pa)
{
	drmach_device_t	*dp;
	pnode_t		nodeid;
	uint64_t	addr;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	dp = id;

	nodeid = drmach_node_get_dnode(dp->node);
	if (nodeid == OBP_NONODE || nodeid == OBP_BADNODE)
		return (DRMACH_INTERNAL_ERROR());

	addr = mc_get_idle_addr(nodeid);
	if (addr == (uint64_t)-1)
		return (DRMACH_INTERNAL_ERROR());

	*pa = addr;
	return (NULL);
}

static sbd_error_t *
drmach_read_mc_asr(drmachid_t id, uint_t *mcregp)
{
	drmach_device_t	*dp;
	pnode_t		 nodeid;
	sbd_error_t	*err;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	dp = id;

	nodeid = drmach_node_get_dnode(dp->node);
	if (nodeid == OBP_NONODE || nodeid == OBP_BADNODE)
		err = DRMACH_INTERNAL_ERROR();
	else if (mc_read_asr(nodeid, mcregp) == -1)
		err = DRMACH_INTERNAL_ERROR();
	else
		err = NULL;

	return (err);
}

static sbd_error_t *
drmach_write_mc_asr(drmachid_t id, uint_t mcreg)
{
	drmach_device_t	*dp;
	pnode_t		 nodeid;
	sbd_error_t	*err;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	dp = id;

	nodeid = drmach_node_get_dnode(dp->node);
	if (nodeid == OBP_NONODE || nodeid == OBP_BADNODE)
		err = DRMACH_INTERNAL_ERROR();
	else if (mc_write_asr(nodeid, mcreg) == -1)
		err = DRMACH_INTERNAL_ERROR();
	else
		err = NULL;

	return (err);
}

static sbd_error_t *
drmach_prep_rename_script(drmach_device_t *s_mem, drmach_device_t *t_mem,
	uint64_t t_slice_offset, caddr_t buf, int buflen)
{
	int			i, b, m;
	drmach_mc_idle_script_t	*isp;
	drmach_rename_script_t	*rsp;
	int			s_bd, t_bd;
	uint_t			s_masr, t_masr;
	uint64_t		s_new_basepa, t_new_basepa;
	int			b_idx, rv;
	sbd_error_t		*err;
	drmachid_t		 b_id;
	drmach_board_t		*brd;

#ifdef DEBUG
	/*
	 * Starfire CPU/MEM/IO boards have only one MC per board.
	 * This function has been coded with that fact in mind.
	 */
	ASSERT(MAX_MEM_UNITS_PER_BOARD == 1);

	/*
	 * calculate the maximum space that could be consumed,
	 * then verify the available buffer space is adequate.
	 */
	m  = sizeof (drmach_mc_idle_script_t *) * 2; /* two MCs */
	b  = sizeof (drmach_rename_script_t *) * 3 * MAX_CPU_UNITS_PER_BOARD;
	b += sizeof (drmach_rename_script_t *) * 3 * MAX_IO_UNITS_PER_BOARD;
	b *= MAX_BOARDS;
	b += sizeof (drmach_rename_script_t *) * 3;
	b += sizeof (drmach_rename_script_t *) * 1;
	ASSERT(m + b < buflen);
#endif

	/*
	 * construct an array of MC idle register addresses of
	 * both MCs.  The array is zero terminated -- as expected
	 * by drmach_copy_rename_prog__relocatable().
	 */
	isp = (drmach_mc_idle_script_t *)buf;

	/* source mc */
	err = drmach_get_mc_idle_addr(s_mem, &isp->idle_addr);
	if (err)
		return (err);
	isp->mem = s_mem;
	isp += 1;

	/* target mc */
	err = drmach_get_mc_idle_addr(t_mem, &isp->idle_addr);
	if (err)
		return (err);
	isp->mem = t_mem;
	isp += 1;

	/* terminator */
	isp->idle_addr = 0;
	isp->mem = NULL;
	isp += 1;

	/* fetch source mc asr register value */
	err = drmach_read_mc_asr(s_mem, &s_masr);
	if (err)
		return (err);
	else if (s_masr & STARFIRE_MC_INTERLEAVE_MASK) {
		return (drerr_new(1, ESTF_INTERBOARD, "%s::%s",
		    s_mem->bp->cm.name, s_mem->cm.name));
	}

	/* fetch target mc asr register value */
	err = drmach_read_mc_asr(t_mem, &t_masr);
	if (err)
		return (err);
	else if (t_masr & STARFIRE_MC_INTERLEAVE_MASK) {
		return (drerr_new(1, ESTF_INTERBOARD, "%s::%s",
		    t_mem->bp->cm.name, t_mem->cm.name));
	}

	/* get new source base pa from target's masr */
	s_new_basepa = mc_asr_to_pa(t_masr);

	/*
	 * remove any existing slice offset to realign
	 * memory with board's slice boundary
	 */
	s_new_basepa &= ~ (mc_get_mem_alignment() - 1);

	/* get new target base pa from source's masr */
	t_new_basepa  = mc_asr_to_pa(s_masr);

	/* remove any existing slice offset, then apply new offset */
	t_new_basepa &= ~ (mc_get_mem_alignment() - 1);
	t_new_basepa += t_slice_offset;

	/* encode new base pa into s_masr.  turn off mem present bit */
	s_masr  = mc_pa_to_asr(s_masr, s_new_basepa);
	s_masr &= ~STARFIRE_MC_MEM_PRESENT_MASK;

	/* encode new base pa into t_masr.  turn on mem present bit */
	t_masr  = mc_pa_to_asr(t_masr, t_new_basepa);
	t_masr |= STARFIRE_MC_MEM_PRESENT_MASK;

	/*
	 * Step 0:	Mark source memory as not present.
	 */
	m = 0;
	rsp = (drmach_rename_script_t *)isp;
	err = drmach_get_mc_asr_addr(s_mem, &rsp[m].masr_addr);
	if (err)
		return (err);
	rsp[m].masr = s_masr;
	m++;

	/*
	 * Step 1:	Write source base address to target MC
	 *		with present bit off.
	 */
	err = drmach_get_mc_asr_addr(t_mem, &rsp[m].masr_addr);
	if (err)
		return (err);
	rsp[m].masr = t_masr & ~STARFIRE_MC_MEM_PRESENT_MASK;
	m++;

	/*
	 * Step 2:	Now rewrite target reg with present bit on.
	 */
	rsp[m].masr_addr = rsp[m-1].masr_addr;
	rsp[m].masr = t_masr;
	m++;

	s_bd = s_mem->bp->bnum;
	t_bd = t_mem->bp->bnum;

	DRMACH_PR("preparing script for CPU and IO units:\n");

	rv = drmach_array_first(drmach_boards, &b_idx, &b_id);
	if (rv) {
		/* catch this in debug kernels */
		ASSERT(0);
		return (DRMACH_INTERNAL_ERROR());
	}

	do {
		int			 d_idx;
		drmachid_t		 d_id;
		drmach_device_t		*device;

		ASSERT(DRMACH_IS_BOARD_ID(b_id));
		brd = b_id;
		b = brd->bnum;

		/*
		 * Step 3:	Update PC MADR tables for CPUs.
		 */
		if (brd->devices == NULL) {
			/* devices not initialized */
			continue;
		}

		rv = drmach_array_first(brd->devices, &d_idx, &d_id);
		if (rv) {
			/* must mean no devices on this board */
			break;
		}

		DRMACH_PR("\t%s\n", brd->cm.name);

		do {
			ASSERT(DRMACH_IS_DEVICE_ID(d_id));

			if (!DRMACH_IS_CPU_ID(d_id))
				continue;

			device = d_id;
			i = device->unum;

			DRMACH_PR("\t\t%s\n", device->cm.name);

			/*
			 * Disabled detaching mem node.
			 */
			rsp[m].masr_addr = STARFIRE_PC_MADR_ADDR(b, s_bd, i);
			rsp[m].masr = s_masr;
			m++;
			/*
			 * Always write masr with present bit
			 * off and then again with it on.
			 */
			rsp[m].masr_addr = STARFIRE_PC_MADR_ADDR(b, t_bd, i);
			rsp[m].masr = t_masr & ~STARFIRE_MC_MEM_PRESENT_MASK;
			m++;
			rsp[m].masr_addr = rsp[m-1].masr_addr;
			rsp[m].masr = t_masr;
			m++;

		} while (drmach_array_next(brd->devices, &d_idx, &d_id) == 0);

		/*
		 * Step 4:	Update PC MADR tables for IOs.
		 */
		rv = drmach_array_first(brd->devices, &d_idx, &d_id);
		/* this worked for previous loop, must work here too */
		ASSERT(rv == 0);

		do {
			ASSERT(DRMACH_IS_DEVICE_ID(d_id));

			if (!DRMACH_IS_IO_ID(d_id))
				continue;

			device = d_id;
			i = device->unum;

			DRMACH_PR("\t\t%s\n", device->cm.name);

			/*
			 * Disabled detaching mem node.
			 */
			rsp[m].masr_addr = STARFIRE_PC_MADR_ADDR(b, s_bd, i+4);
			rsp[m].masr = s_masr;
			m++;
			/*
			 * Always write masr with present bit
			 * off and then again with it on.
			 */
			rsp[m].masr_addr = STARFIRE_PC_MADR_ADDR(b, t_bd, i+4);
			rsp[m].masr = t_masr & ~STARFIRE_MC_MEM_PRESENT_MASK;
			m++;
			rsp[m].masr_addr = rsp[m-1].masr_addr;
			rsp[m].masr = t_masr;
			m++;

		} while (drmach_array_next(brd->devices, &d_idx, &d_id) == 0);
	} while (drmach_array_next(drmach_boards, &b_idx, &b_id) == 0);

	/*
	 * Zero masr_addr value indicates the END.
	 */
	rsp[m].masr_addr = 0ull;
	rsp[m].masr = 0;
	DRMACH_PR("number of steps in rename script = %d\n", m);
	m++;

	/* paranoia */
	ASSERT((caddr_t)&rsp[m] <= buf + buflen);

#ifdef DEBUG
	{
		int	j;

		DRMACH_PR("mc idle register address list:");
		isp = (drmach_mc_idle_script_t *)buf;
		DRMACH_PR("source mc idle addr 0x%lx, mem id %p",
		    isp[0].idle_addr, (void *)isp[0].mem);
		DRMACH_PR("target mc idle addr 0x%lx, mem id %p",
		    isp[1].idle_addr, (void *)isp[1].mem);
		ASSERT(isp[2].idle_addr == 0);

		DRMACH_PR("copy-rename script:");
		for (j = 0; j < m; j++) {
			DRMACH_PR("0x%lx = 0x%08x",
			    rsp[j].masr_addr, rsp[j].masr);
		}

		DELAY(1000000);
	}
#endif

	/* return number of bytes consumed */
	b = (caddr_t)&rsp[m] - buf;
	DRMACH_PR("total number of bytes consumed is %d\n", b);
	ASSERT(b <= buflen);

#ifdef lint
	buflen = buflen;
#endif

	return (NULL);
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
static void
drmach_copy_rename_prog__relocatable(drmach_copy_rename_program_t *prog)
{
	extern void drmach_exec_script_il(drmach_rename_script_t *rsp);

	drmach_mc_idle_script_t		*isp;
	struct memlist			*ml;
	int				csize;
	int				lnsize;
	uint64_t			caddr;

	isp = (drmach_mc_idle_script_t *)prog->data;

	caddr = ecache_flushaddr;
	csize = (cpunodes[CPU->cpu_id].ecache_size << 1);
	lnsize = cpunodes[CPU->cpu_id].ecache_linesize;

	/*
	 * DO COPY.
	 */
	for (ml = prog->c_ml; ml; ml = ml->ml_next) {
		uint64_t	s_pa, t_pa;
		uint64_t	nbytes;

		s_pa = prog->s_copybasepa + ml->ml_address;
		t_pa = prog->t_copybasepa + ml->ml_address;
		nbytes = ml->ml_size;

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
	flush_ecache_il(caddr, csize, lnsize);		/* inline version */

	/*
	 * Wait for MCs to go idle.
	 */
	do {
		register int	t = 10;
		register uint_t	v;

		/* loop t cycles waiting for each mc to indicate it's idle */
		do {
			v = ldphysio_il(isp->idle_addr)
			    & STARFIRE_MC_IDLE_MASK;

		} while (v != STARFIRE_MC_IDLE_MASK && t-- > 0);

		/* bailout if timedout */
		if (t <= 0) {
			prog->restless_mc = isp->mem;
			return;
		}

		isp += 1;

		/* stop if terminating zero has been reached */
	} while (isp->idle_addr != 0);

	/* advance passed terminating zero */
	isp += 1;

	/*
	 * The following inline assembly routine caches
	 * the rename script and then caches the code that
	 * will do the rename.  This is necessary
	 * so that we don't have any memory references during
	 * the reprogramming.  We accomplish this by first
	 * jumping through the code to guarantee it's cached
	 * before we actually execute it.
	 */
	drmach_exec_script_il((drmach_rename_script_t *)isp);
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

sbd_error_t *
drmach_copy_rename_init(drmachid_t t_id, uint64_t t_slice_offset,
	drmachid_t s_id, struct memlist *c_ml, drmachid_t *pgm_id)
{
	drmach_device_t	*s_mem;
	drmach_device_t	*t_mem;
	struct memlist	*x_ml;
	uint64_t	off_mask, s_copybasepa, t_copybasepa, t_basepa;
	int		len;
	caddr_t		bp, wp;
	pda_handle_t	ph;
	sbd_error_t	*err;
	drmach_copy_rename_program_t *prog;

	if (!DRMACH_IS_MEM_ID(s_id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	if (!DRMACH_IS_MEM_ID(t_id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	s_mem = s_id;
	t_mem = t_id;

	/* get starting physical address of target memory */
	err = drmach_mem_get_base_physaddr(t_id, &t_basepa);
	if (err)
		return (err);

	/* calculate slice offset mask from slice size */
	off_mask = mc_get_mem_alignment() - 1;

	/* calculate source and target base pa */
	s_copybasepa = c_ml->ml_address;
	t_copybasepa =
	    t_basepa + ((c_ml->ml_address & off_mask) - t_slice_offset);

	/* paranoia */
	ASSERT((c_ml->ml_address & off_mask) >= t_slice_offset);

	/* adjust copy memlist addresses to be relative to copy base pa */
	x_ml = c_ml;
	while (x_ml != NULL) {
		x_ml->ml_address -= s_copybasepa;
		x_ml = x_ml->ml_next;
	}

#ifdef DEBUG
	{
	uint64_t s_basepa, s_size, t_size;

	x_ml = c_ml;
	while (x_ml->ml_next != NULL)
		x_ml = x_ml->ml_next;

	DRMACH_PR("source copy span: base pa 0x%lx, end pa 0x%lx\n",
	    s_copybasepa,
	    s_copybasepa + x_ml->ml_address + x_ml->ml_size);

	DRMACH_PR("target copy span: base pa 0x%lx, end pa 0x%lx\n",
	    t_copybasepa,
	    t_copybasepa + x_ml->ml_address + x_ml->ml_size);

	DRMACH_PR("copy memlist (relative to copy base pa):\n");
	MEMLIST_DUMP(c_ml);

	err = drmach_mem_get_base_physaddr(s_id, &s_basepa);
	ASSERT(err == NULL);

	err = drmach_mem_get_size(s_id, &s_size);
	ASSERT(err == NULL);

	err = drmach_mem_get_size(t_id, &t_size);
	ASSERT(err == NULL);

	DRMACH_PR("current source base pa 0x%lx, size 0x%lx\n",
	    s_basepa, s_size);
	DRMACH_PR("current target base pa 0x%lx, size 0x%lx\n",
	    t_basepa, t_size);

	ASSERT(s_copybasepa + x_ml->ml_address + x_ml->ml_size <=
	    s_basepa + s_size);
	ASSERT(t_copybasepa + x_ml->ml_address + x_ml->ml_size <=
	    t_basepa + t_size);
	}
#endif

	ph = drmach_pda_open();
	if (ph == NULL)
		return (DRMACH_INTERNAL_ERROR());

	/*
	 * bp will be page aligned, since we're calling
	 * kmem_zalloc() with an exact multiple of PAGESIZE.
	 */
	wp = bp = kmem_zalloc(PAGESIZE, KM_SLEEP);

	/* allocate space for copy rename struct */
	len = sizeof (drmach_copy_rename_program_t);
	DRMACH_PR("prog = 0x%p, header len %d\n", (void *)wp, len);
	prog = (drmach_copy_rename_program_t *)wp;
	wp += (len + ecache_alignsize - 1) & ~ (ecache_alignsize - 1);

	/*
	 * Copy the code for the copy-rename routine into
	 * a page aligned piece of memory.  We do this to guarantee
	 * that we're executing within the same page and thus reduce
	 * the possibility of cache collisions between different
	 * pages.
	 */
	len = (int)((ulong_t)drmach_copy_rename_end -
	    (ulong_t)drmach_copy_rename_prog__relocatable);
	ASSERT(wp + len < bp + PAGESIZE);
	bcopy((caddr_t)drmach_copy_rename_prog__relocatable, wp, len);

	DRMACH_PR("copy-rename function 0x%p, len %d\n", (void *)wp, len);
	prog->run = (void (*)())wp;
	wp += (len + ecache_alignsize - 1) & ~ (ecache_alignsize - 1);

	/*
	 * Prepare data page that will contain script of
	 * operations to perform during copy-rename.
	 * Allocate temporary buffer to hold script.
	 */
	err = drmach_prep_rename_script(s_mem, t_mem, t_slice_offset,
	    wp, PAGESIZE - (wp - bp));
	if (err) {
		(void) drmach_copy_rename_fini(prog);
		return (err);
	}

	DRMACH_PR("copy-rename script 0x%p, len %d\n", (void *)wp, len);
	prog->data = wp;
	wp += (len + ecache_alignsize - 1) & ~ (ecache_alignsize - 1);

	prog->ph = ph;
	prog->s_copybasepa = s_copybasepa;
	prog->t_copybasepa = t_copybasepa;
	prog->c_ml = c_ml;
	*pgm_id = prog;

	return (NULL);
}

sbd_error_t *
drmach_copy_rename_fini(drmachid_t id)
{
	drmach_copy_rename_program_t	*prog = id;
	sbd_error_t			*err = NULL;

	if (prog->c_ml != NULL)
		memlist_delete(prog->c_ml);

	if (prog->ph != NULL)
		pda_close(prog->ph);

	if (prog->restless_mc != 0) {
		cmn_err(CE_WARN, "MC did not idle; OBP Node 0x%x",
		    (uint_t)drmach_node_get_dnode(prog->restless_mc->node));

		err = DRMACH_INTERNAL_ERROR();
	}

	kmem_free(prog, PAGESIZE);

	return (err);
}

static sbd_error_t *
drmach_io_new(drmach_device_t *dp)
{
	sbd_error_t	*err;
	int		 portid;

	err = drmach_device_get_prop(dp, "upa-portid", &portid);
	if (err == NULL) {
		ASSERT(portid & 0x40);
		dp->unum = portid & 1;
	}

	dp->cm.isa = (void *)drmach_io_new;
	dp->cm.release = drmach_io_release;
	dp->cm.status = drmach_io_status;

	(void) snprintf(dp->cm.name, sizeof (dp->cm.name), "%s%d", dp->type,
	    dp->unum);

	return (err);
}

static void
drmach_iopc_op(pda_handle_t ph, drmach_iopc_op_t op)
{
	register int b;

	for (b = 0; b < MAX_BOARDS; b++) {
		int		p;
		ushort_t	bda_ioc;
		board_desc_t	*bdesc;

		if (pda_board_present(ph, b) == 0)
			continue;

		bdesc = (board_desc_t *)pda_get_board_info(ph, b);
		/*
		 * Update PCs for IOCs.
		 */
		bda_ioc = bdesc->bda_ioc;
		for (p = 0; p < MAX_IOCS; p++) {
			u_longlong_t	idle_addr;
			uchar_t		value;

			if (BDA_NBL(bda_ioc, p) != BDAN_GOOD)
				continue;

			idle_addr = STARFIRE_BB_PC_ADDR(b, p, 1);

			switch (op) {
			case DO_PAUSE:
				value = STARFIRE_BB_PC_PAUSE(p);
				break;

			case DO_IDLE:
				value = STARFIRE_BB_PC_IDLE(p);
				break;

			case DO_UNPAUSE:
				value = ldbphysio(idle_addr);
				value &= ~STARFIRE_BB_PC_PAUSE(p);
				break;

			case DO_UNIDLE:
				value = ldbphysio(idle_addr);
				value &= ~STARFIRE_BB_PC_IDLE(p);
				break;

			default:
				cmn_err(CE_PANIC,
				    "drmach_iopc_op: unknown op (%d)",
				    (int)op);
				/*NOTREACHED*/
			}
			stbphysio(idle_addr, value);
		}
	}
}

void
drmach_copy_rename(drmachid_t id)
{
	drmach_copy_rename_program_t	*prog = id;
	uint64_t			neer;

	/*
	 * UPA IDLE
	 * Protocol = PAUSE -> IDLE -> UNPAUSE
	 * In reality since we only "idle" the IOPCs it's sufficient
	 * to just issue the IDLE operation since (in theory) all IOPCs
	 * in the field are PC6.  However, we'll be robust and do the
	 * proper workaround protocol so that we never have to worry!
	 */
	drmach_iopc_op(prog->ph, DO_PAUSE);
	drmach_iopc_op(prog->ph, DO_IDLE);
	DELAY(100);
	drmach_iopc_op(prog->ph, DO_UNPAUSE);
	DELAY(100);

	/* disable CE reporting */
	neer = get_error_enable();
	set_error_enable(neer & ~EER_CEEN);

	/* run the copy/rename program */
	prog->run(prog);

	/* enable CE reporting */
	set_error_enable(neer);

	/*
	 * UPA UNIDLE
	 * Protocol = UNIDLE
	 */
	drmach_iopc_op(prog->ph, DO_UNIDLE);
	DELAY(100);
}

/*
 * The counter-timer and perf-counter nodes are not being cleaned
 * up after a board that was present at start of day is detached.
 * If the board has become unconfigured with this operation, walk
 * the prom tree and find all counter-timer and perf-counter nodes
 * that have the same board number as the board that was just
 * unconfigured and remove them.
 */
static sbd_error_t *
drmach_remove_counter_nodes(drmachid_t id)
{
	int		num;
	char		name[OBP_MAXDRVNAME];
	pnode_t		child;
	dev_info_t	*dip;
	sbd_error_t	*err;
	drmach_status_t	stat;
	drmach_board_t	*bp;

	if (!DRMACH_IS_BOARD_ID(id)) {
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	}

	if ((err = drmach_board_status(id, &stat)) != NULL) {
		return (err);
	}

	/*
	 * Only clean up the counter-timer and perf-counter
	 * nodes when the entire board is unconfigured.
	 */
	if (stat.configured) {
		return (NULL);
	}

	bp = (drmach_board_t *)id;

	err = NULL;

	for (child = prom_childnode(prom_rootnode()); child != OBP_NONODE;
	    child = prom_nextnode(child)) {

		if (prom_getprop(child, OBP_BOARDNUM, (caddr_t)&num) == -1) {
			continue;
		}

		if (bp->bnum != num) {
			continue;
		}

		if (prom_getprop(child, OBP_NAME, (caddr_t)name) == -1) {
			continue;
		}

		if (strncmp(name, MISC_COUNTER_TIMER_DEVNAME, OBP_MAXDRVNAME) &&
		    strncmp(name, MISC_PERF_COUNTER_DEVNAME, OBP_MAXDRVNAME)) {
				continue;
		}

		/* Root node doesn't have to be held */
		dip = e_ddi_nodeid_to_dip(child);

		/*
		 * If the node is only in the OBP tree, then
		 * we don't have to remove it.
		 */
		if (dip) {
			dev_info_t *fdip = NULL;

			DRMACH_PR("removing %s devinfo node\n", name);

			e_ddi_branch_hold(dip);
			ddi_release_devi(dip); /* held in e_ddi_nodeid_to_dip */

			if (e_ddi_branch_destroy(dip, &fdip, 0)) {
				char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

				/*
				 * If non-NULL, fdip is held and must be
				 * released.
				 */
				if (fdip != NULL) {
					(void) ddi_pathname(fdip, path);
					ddi_release_devi(fdip);
				} else {
					(void) ddi_pathname(dip, path);
				}

				err = drerr_new(1, ESTF_DRVFAIL, path);
				kmem_free(path, MAXPATHLEN);
				e_ddi_branch_rele(dip);
				break;
			}
		}
	}

	return (err);
}

/*ARGSUSED*/
sbd_error_t *
drmach_pre_op(int cmd, drmachid_t id, drmach_opts_t *opts)
{
	/* allow status and ncm operations to always succeed */
	if ((cmd == SBD_CMD_STATUS) || (cmd == SBD_CMD_GETNCM)) {
		return (NULL);
	}

	/* check all other commands for the required option string */
	if ((opts->size > 0) && (opts->copts != NULL)) {

		DRMACH_PR("platform options: %s\n", opts->copts);

		if (strstr(opts->copts, "xfdr") != NULL) {
			return (NULL);
		}
	}

	return (drerr_new(0, ESTF_SUPPORT, NULL));
}

/*ARGSUSED*/
sbd_error_t *
drmach_post_op(int cmd, drmachid_t id, drmach_opts_t *opts)
{
	sbd_error_t	*err = NULL;

	switch (cmd) {
	case SBD_CMD_UNCONFIGURE:

		err = drmach_remove_counter_nodes(id);
		break;

	case SBD_CMD_CONFIGURE:
	case SBD_CMD_DISCONNECT:
	case SBD_CMD_CONNECT:
	case SBD_CMD_GETNCM:
	case SBD_CMD_STATUS:
		break;

	default:
		break;
	}

	return (err);
}

sbd_error_t *
drmach_board_assign(int bnum, drmachid_t *id)
{
	sbd_error_t	*err;

	if (!drmach_initialized && drmach_init() == -1) {
		err = DRMACH_INTERNAL_ERROR();
	} else if (drmach_array_get(drmach_boards, bnum, id) == -1) {
		err = drerr_new(1, ESTF_BNUM, "%d", bnum);
	} else if (*id != NULL) {
		err = NULL;
	} else {
		drmach_board_t	*bp;

		*id  = (drmachid_t)drmach_board_new(bnum);
		bp = *id;
		bp->assigned = 1;
		err = NULL;
	}

	return (err);
}

static int
drmach_attach_board(void *arg)
{
	drmach_board_t	*obj = (drmach_board_t *)arg;
	cpuset_t	cset;
	int		retval;

	/*
	 * OBP disables traps during the board probe.
	 * So, in order to prevent cross-call/cross-trap timeouts,
	 * and thus panics, we effectively block anybody from
	 * issuing xc's/xt's by doing a promsafe_xc_attention.
	 * In the previous version of Starfire DR (2.6), a timeout
	 * suspension mechanism was implemented in the send-mondo
	 * assembly.  That mechanism is unnecessary with the
	 * existence of xc_attention/xc_dismissed.
	 */
	cset = cpu_ready_set;
	promsafe_xc_attention(cset);

	retval = prom_starfire_add_brd(obj->connect_cpuid);

	xc_dismissed(cset);

	return (retval);
}

sbd_error_t *
drmach_board_connect(drmachid_t id, drmach_opts_t *opts)
{
	drmach_board_t	*obj = (drmach_board_t *)id;
	int		retval;
	sbd_error_t	*err;
	char		*cptr, *copts;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));

	if (opts->size > 0)
		copts = opts->copts;

	if ((cptr = strstr(copts, "cpuid=")) != NULL) {
		int cpuid;

		cptr += strlen("cpuid=");
		cpuid = stoi(&cptr);

		if (DRMACH_CPUID2BNUM(cpuid) == obj->bnum) {
			obj->connect_cpuid = cpuid;
			obj->assigned = 1;
		} else
			return (drerr_new(1, ESTF_SETCPUVAL, "%d", cpuid));
	} else {
		/* cpuid was not specified */
		obj->connect_cpuid = -1;
	}

	if (obj->connect_cpuid == -1) {
		err =  drerr_new(1, ESTF_NOCPUID, obj->cm.name);
		return (err);
	}

	cmn_err(CE_CONT, "DRMACH: PROM attach %s CPU %d\n",
	    obj->cm.name, obj->connect_cpuid);

	retval = prom_tree_update(drmach_attach_board, obj);

	if (retval == 0)
		err = NULL;
	else {
		cmn_err(CE_WARN, "prom error: prom_starfire_add_brd(%d) "
		    "returned %d", obj->connect_cpuid, retval);

		err = drerr_new(1, ESTF_PROBE, obj->cm.name);
	}

	obj->connect_cpuid = -1;

	return (err);
}

/*ARGSUSED*/
sbd_error_t *
drmach_board_disconnect(drmachid_t id, drmach_opts_t *opts)
{
	drmach_board_t		*bp;
	int			rv;
	int			d_idx;	/* device index */
	drmachid_t		d_id;	/* device ID */
	sbd_error_t		*err;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));

	bp = id;

	/*
	 * We need to make sure all of the board's device nodes
	 * have been removed from the Solaris device tree before
	 * continuing with the disconnect. Otherwise, we could
	 * disconnect the board and remove the OBP device tree
	 * nodes with Solaris device tree nodes remaining.
	 *
	 * On Starfire, Solaris device tree nodes are deleted
	 * during unconfigure by drmach_unconfigure(). It's
	 * necessary to do this here because drmach_unconfigure()
	 * failures are not handled during unconfigure.
	 */
	if (bp->devices) {
		rv = drmach_array_first(bp->devices, &d_idx, &d_id);
		while (rv == 0) {
			err = drmach_unconfigure(d_id, DRMACH_DEVI_REMOVE);
			if (err)
				return (err);

			rv = drmach_array_next(bp->devices, &d_idx, &d_id);
		}
	}

	/*
	 * Starfire board Solaris device tree counter nodes,
	 * which are only present on start-of-day boards, are
	 * removed in the dr_post_op() code flow after the
	 * board is unconfigured. We call the counter node
	 * removal function here because unconfigure errors
	 * can cause the dr_post_op() function to be skipped
	 * after an unconfigure operation even though all of
	 * the board's devices have been transitioned to the
	 * unconfigured state.
	 */
	err = drmach_remove_counter_nodes(id);
	if (err)
		return (err);

	return (NULL);
}

static int
drmach_board_find_devices_cb(drmach_node_walk_args_t *args)
{
	drmach_node_t			*node = args->node;
	drmach_board_cb_data_t		*data = args->data;
	drmach_board_t			*obj = data->obj;

	int		 rv;
	int		 bnum;
	drmach_device_t	*device;

	rv = drmach_node_get_prop(node, OBP_BOARDNUM, &bnum);
	if (rv) {
		/*
		 * if the node does not have a board# property, then
		 * by that information alone it is known that drmach
		 * is not interested in it.
		 */
		return (0);
	} else if (bnum != obj->bnum)
		return (0);

	/*
	 * Create a device data structure from this node data.
	 * The call may yield nothing if the node is not of interest
	 * to drmach.
	 */
	data->err = drmach_device_new(node, obj, &device);
	if (data->err)
		return (-1);
	else if (device == NULL) {
		/*
		 * drmach_device_new examined the node we passed in
		 * and determined that it was one not of interest to
		 * drmach.  So, it is skipped.
		 */
		return (0);
	}

	rv = drmach_array_set(obj->devices, data->ndevs++, device);
	if (rv) {
		drmach_device_dispose(device);
		data->err = DRMACH_INTERNAL_ERROR();
		return (-1);
	}

	data->err = (*data->found)(data->a, device->type, device->unum, device);
	return (data->err == NULL ? 0 : -1);
}

sbd_error_t *
drmach_board_find_devices(drmachid_t id, void *a,
	sbd_error_t *(*found)(void *a, const char *, int, drmachid_t))
{
	extern int		 plat_max_cpu_units_per_board();
	extern int		 plat_max_mem_units_per_board();
	extern int		 plat_max_io_units_per_board();

	drmach_board_t		*obj = (drmach_board_t *)id;
	sbd_error_t		*err;
	int			 max_devices;
	int			 rv;
	drmach_board_cb_data_t	data;

	max_devices  = plat_max_cpu_units_per_board();
	max_devices += plat_max_mem_units_per_board();
	max_devices += plat_max_io_units_per_board();

	obj->devices = drmach_array_new(0, max_devices);

	data.obj = obj;
	data.ndevs = 0;
	data.found = found;
	data.a = a;
	data.err = NULL;

	rv = drmach_node_walk(obj->tree, &data, drmach_board_find_devices_cb);
	if (rv == 0)
		err = NULL;
	else {
		drmach_array_dispose(obj->devices, drmach_device_dispose);
		obj->devices = NULL;

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

	if (!drmach_initialized && drmach_init() == -1) {
		*id = 0;
		rv = -1;
	} else if (drmach_array_get(drmach_boards, bnum, id)) {
		*id = 0;
		rv = -1;
	}
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

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	bp = id;

	err = drmach_board_status(id, &stat);
	if (err)
		return (err);
	else if (stat.configured || stat.busy)
		return (drerr_new(0, ESTF_CONFIGBUSY, bp->cm.name));
	else {
		/* board power off is essentially a noop for Starfire */
		bp->powered = 0;
		return (NULL);
	}
	/*NOTREACHED*/
}

sbd_error_t *
drmach_board_poweron(drmachid_t id)
{
	drmach_board_t	*bp;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	bp = id;

	/* board power on is essentially a noop for Starfire */
	bp->powered = 1;

	return (NULL);
}

static sbd_error_t *
drmach_board_release(drmachid_t id)
{
	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
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

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	bp = id;

	err = drmach_board_status(id, &stat);
	if (err)
		return (err);
	else if (stat.configured || stat.busy)
		return (drerr_new(0, ESTF_CONFIGBUSY, bp->cm.name));
	else if (drmach_array_set(drmach_boards, bp->bnum, 0) != 0)
		return (DRMACH_INTERNAL_ERROR());
	else {
		drmach_board_dispose(bp);
		return (NULL);
	}
	/*NOTREACHED*/
}

static sbd_error_t *
drmach_cpu_new(drmach_device_t *dp)
{
	sbd_error_t	*err;
	int		 portid;

	err = drmach_device_get_prop(dp, "upa-portid", &portid);
	if (err == NULL)
		dp->unum = portid & 3;

	dp->cm.isa = (void *)drmach_cpu_new;
	dp->cm.release = drmach_cpu_release;
	dp->cm.status = drmach_cpu_status;

	(void) snprintf(dp->cm.name, sizeof (dp->cm.name), "%s%d", dp->type,
	    dp->unum);

	return (err);
}

/*
 * drmach_cpu_obp_detach()
 *  This requires two steps, first, we must put the cpuid into the OBP
 *  idle loop (Idle in Program) state.  Then we call OBP to place the CPU
 *  into the "Detached" state, which does any special processing to
 *  actually detach the cpu, such as flushing ecache, and also ensures
 *  that a subsequent breakpoint won't restart the cpu (if it was just in
 *  Idle in Program state).
 */
static void
drmach_cpu_obp_detach(int cpuid)
{
	/*
	 * Cpu may not be under OBP's control. Eg, if cpu exited to download
	 * helper on a prior attach.
	 */
	if (CPU_SGN_EXISTS(cpuid) &&
	    !SGN_CPU_IS_OS(cpuid) &&
	    !SGN_CPU_IS_OBP(cpuid)) {
		cmn_err(CE_WARN,
		    "unexpected signature (0x%x) for cpu %d",
		    get_cpu_sgn(cpuid), cpuid);
	}

	/*
	 * Now we place the CPU into the "Detached" idle loop in OBP.
	 * This is so that the CPU won't be restarted if we break into
	 * OBP with a breakpoint or BREAK key from the console, and also
	 * if we need to do any special processing, such as flushing the
	 * cpu's ecache, disabling interrupts (by turning of the ET bit in
	 * the PSR) and/or spinning in BBSRAM rather than global memory.
	 */
	DRMACH_PR("prom_starfire_rm_cpu(%d)\n", cpuid);
	prom_starfire_rm_cpu(cpuid);
}

/*
 * drmach_cpu_obp_is_detached() returns TRUE if the cpu sigblock signature state
 * is SIGBST_DETACHED; otherwise it returns FALSE. This routine should only
 * be called after we have asked OBP to detach the CPU. It should NOT be
 * called as a check during any other flow.
 */
static int
drmach_cpu_obp_is_detached(int cpuid)
{
	if (!CPU_SGN_EXISTS(cpuid) ||
	    (SGN_CPU_IS_OS(cpuid) && SGN_CPU_STATE_IS_DETACHED(cpuid)))
		return (1);
	else
		return (0);
}

static int
drmach_cpu_start(struct cpu *cp)
{
	int		cpuid = cp->cpu_id;
	int		ntries = drmach_cpu_ntries;
	extern void	restart_other_cpu(int);

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

	prom_starfire_add_cpu(cpuid);

	restart_other_cpu(cpuid);

	/*
	 * Wait for the cpu to reach its idle thread before
	 * we zap it with a request to blow away the mappings
	 * it (might) have for the drmach_shutdown_asm code
	 * it may have executed on unconfigure.
	 */
	while ((cp->cpu_thread != cp->cpu_idle_thread) && (ntries > 0)) {
		DELAY(drmach_cpu_delay);
		ntries--;
	}

	DRMACH_PR("waited %d out of %d loops for cpu %d\n",
	    drmach_cpu_ntries - ntries, drmach_cpu_ntries, cpuid);

	xt_one(cpuid, vtag_flushpage_tl1,
	    (uint64_t)drmach_shutdown_va, (uint64_t)ksfmmup);

	return (0);
}

/*
 * A detaching CPU is xcalled with an xtrap to drmach_cpu_stop_self() after
 * it has been offlined. The function of this routine is to get the cpu
 * spinning in a safe place. The requirement is that the system will not
 * reference anything on the detaching board (memory and i/o is detached
 * elsewhere) and that the CPU not reference anything on any other board
 * in the system.  This isolation is required during and after the writes
 * to the domain masks to remove the board from the domain.
 *
 * To accomplish this isolation the following is done:
 *	1) Create a locked mapping to a location in BBSRAM where
 *	   the cpu will execute.
 *	2) Copy the target function (drmach_shutdown_asm) in which
 *	   the cpu will execute into BBSRAM.
 *	3) Jump into function with BBSRAM.
 *	   Function will:
 *	   3.1) Flush its Ecache (displacement).
 *	   3.2) Flush its Dcache with HW mechanism.
 *	   3.3) Flush its Icache with HW mechanism.
 *	   3.4) Flush all valid and _unlocked_ D-TLB entries.
 *	   3.5) Flush all valid and _unlocked_ I-TLB entries.
 *	   3.6) Clear xt_mb to signal completion. Note: cache line is
 *		recovered by drmach_cpu_poweroff().
 *	4) Jump into a tight loop.
 */
#define	DRMACH_BBSRAM_OFFSET	0x1000

static void
drmach_cpu_stop_self(void)
{
	int		cpuid = (int)CPU->cpu_id;
	tte_t		tte;
	volatile uint_t	*src, *dst;
	size_t		funclen;
	uint64_t	bbsram_pa, bbsram_offset;
	uint_t		bbsram_pfn;
	uint64_t	bbsram_addr;
	void		(*bbsram_func)(uint64_t);
	extern void	drmach_shutdown_asm(uint64_t);
	extern void	drmach_shutdown_asm_end(void);

	funclen = (uintptr_t)drmach_shutdown_asm_end -
	    (uintptr_t)drmach_shutdown_asm;
	ASSERT(funclen <= MMU_PAGESIZE);
	/*
	 * We'll start from the 0th's base.
	 */
	bbsram_pa = STARFIRE_UPAID2UPS(cpuid) | STARFIRE_PSI_BASE;
	bbsram_offset = bbsram_pa | 0xfe0ULL;
	bbsram_pa += ldphysio(bbsram_offset) + DRMACH_BBSRAM_OFFSET;

	bbsram_pfn = (uint_t)(bbsram_pa >> MMU_PAGESHIFT);

	bbsram_addr = (uint64_t)drmach_shutdown_va;
	drmach_shutdown_asm_mbox->estack = bbsram_addr + funclen;

	tte.tte_inthi = TTE_VALID_INT | TTE_SZ_INT(TTE8K) |
	    TTE_PFN_INTHI(bbsram_pfn);
	tte.tte_intlo = TTE_PFN_INTLO(bbsram_pfn) |
	    TTE_HWWR_INT | TTE_PRIV_INT | TTE_LCK_INT;
	sfmmu_dtlb_ld_kva(drmach_shutdown_va, &tte);	/* load dtlb */
	sfmmu_itlb_ld_kva(drmach_shutdown_va, &tte);	/* load itlb */

	for (src = (uint_t *)drmach_shutdown_asm, dst = (uint_t *)bbsram_addr;
	    src < (uint_t *)drmach_shutdown_asm_end; src++, dst++)
		*dst = *src;

	bbsram_func = (void (*)())bbsram_addr;
	drmach_shutdown_asm_mbox->flushaddr = ecache_flushaddr;
	drmach_shutdown_asm_mbox->size = (cpunodes[cpuid].ecache_size << 1);
	drmach_shutdown_asm_mbox->linesize = cpunodes[cpuid].ecache_linesize;
	drmach_shutdown_asm_mbox->physaddr =
	    va_to_pa((void *)&drmach_xt_mb[cpuid]);

	/*
	 * Signal to drmach_cpu_poweroff() is via drmach_xt_mb cleared
	 * by asm code
	 */

	(*bbsram_func)(va_to_pa((void *)drmach_shutdown_asm_mbox));
}

static void
drmach_cpu_shutdown_self(void)
{
	cpu_t		*cp = CPU;
	int		cpuid = cp->cpu_id;
	extern void	flush_windows(void);

	flush_windows();

	(void) spl8();

	ASSERT(cp->cpu_intr_actv == 0);
	ASSERT(cp->cpu_thread == cp->cpu_idle_thread ||
	    cp->cpu_thread == cp->cpu_startup_thread);

	cp->cpu_flags = CPU_OFFLINE | CPU_QUIESCED | CPU_POWEROFF;

	drmach_cpu_stop_self();

	cmn_err(CE_PANIC, "CPU %d FAILED TO SHUTDOWN", cpuid);
}

/* a helper routine to keep the math in one place */
static processorid_t
drmach_cpu_calc_id(drmach_device_t *dp)
{
	return (dp->bp->bnum * MAX_CPU_UNITS_PER_BOARD + dp->unum);
}

/*
 * Move bootproc (SIGBCPU) to another cpu.  If dst_cpu is NULL, a
 * destination cpu is chosen from the set of cpus not located on the
 * same board as the current bootproc cpu.
 */
static sbd_error_t *
drmach_cpu_juggle_bootproc(drmach_device_t *dst_cpu)
{
	processorid_t	 cpuid;
	struct cpu	*cp;
	sbd_error_t	*err;
	int		 rv;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/* dst_cpu is NULL when target cpu is unspecified. So, pick one. */
	if (dst_cpu == NULL) {
		int avoid_board = DRMACH_CPUID2BNUM(SIGBCPU->cpu_id);
		int max_cpuid = MAX_BOARDS * MAX_CPU_UNITS_PER_BOARD;

		for (cpuid = 0; cpuid < max_cpuid; cpuid++)
			if (DRMACH_CPUID2BNUM(cpuid) != avoid_board) {
				cp = cpu_get(cpuid);
				if (cp != NULL && cpu_is_online(cp))
					break;
			}

		if (cpuid == max_cpuid) {
			err = drerr_new(1, ESTF_JUGGLE, NULL);
			return (err);
		}

		/* else, cp points to the selected target cpu */
	} else {
		cpuid = drmach_cpu_calc_id(dst_cpu);

		if ((cp = cpu_get(cpuid)) == NULL) {
			err = drerr_new(1, ESTF_NODEV, "%s::%s",
			    dst_cpu->bp->cm.name, dst_cpu->cm.name);
			return (err);
		}

		if (cpuid == SIGBCPU->cpu_id) {
			cmn_err(CE_WARN,
			    "SIGBCPU(%d) same as new selection(%d)",
			    SIGBCPU->cpu_id, cpuid);

			/* technically not an error, but a no-op */
			return (NULL);
		}
	}

	cmn_err(CE_NOTE, "?relocating SIGBCPU from %d to %d",
	    SIGBCPU->cpu_id, cpuid);

	DRMACH_PR("moving SIGBCPU to CPU %d\n", cpuid);

	/*
	 * Tell OBP to initialize cvc-offset field of new CPU0
	 * so that it's in sync with OBP and cvc_server
	 */
	prom_starfire_init_console(cpuid);

	/*
	 * Assign cvc to new cpu0's bbsram for I/O.  This has to be
	 * done BEFORE cpu0 is moved via obp, since this logic
	 * will cause obp_helper to switch to a different bbsram for
	 * cvc I/O.  We don't want cvc writing to a buffer from which
	 * nobody will pick up the data!
	 */
	cvc_assign_iocpu(cpuid);

	rv = prom_starfire_move_cpu0(cpuid);

	if (rv == 0) {
		SIGBCPU = cp;

		DRMACH_PR("successfully juggled to CPU %d\n", cpuid);
		return (NULL);
	} else {
		DRMACH_PR("prom error: prom_starfire_move_cpu0(%d) "
		    "returned %d\n", cpuid, rv);

		/*
		 * The move failed, hopefully obp_helper is still back
		 * at the old bootproc.  Move cvc back there.
		 */
		cvc_assign_iocpu(SIGBCPU->cpu_id);


		err = drerr_new(1, ESTF_MOVESIGB, "CPU %d", cpuid);
		return (err);
	}
	/*NOTREACHED*/
}

static sbd_error_t *
drmach_cpu_release(drmachid_t id)
{
	drmach_device_t	*dp;
	processorid_t	 cpuid;
	struct cpu	*cp;
	sbd_error_t	*err;

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	dp = id;
	cpuid = drmach_cpu_calc_id(dp);

	ASSERT(MUTEX_HELD(&cpu_lock));

	cp = cpu_get(cpuid);
	if (cp == NULL)
		err = DRMACH_INTERNAL_ERROR();
	else if (SIGBCPU->cpu_id == cp->cpu_id)
		err = drmach_cpu_juggle_bootproc(NULL);
	else
		err = NULL;

	return (err);
}

static sbd_error_t *
drmach_cpu_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_device_t *dp;

	ASSERT(DRMACH_IS_CPU_ID(id));
	dp = id;

	stat->assigned = dp->bp->assigned;
	stat->powered = dp->bp->powered;
	mutex_enter(&cpu_lock);
	stat->configured = (cpu_get(drmach_cpu_calc_id(dp)) != NULL);
	mutex_exit(&cpu_lock);
	stat->busy = dp->busy;
	(void) strncpy(stat->type, dp->type, sizeof (stat->type));
	stat->info[0] = '\0';

	return (NULL);
}

sbd_error_t *
drmach_cpu_disconnect(drmachid_t id)
{
	drmach_device_t	*cpu;
	int		 cpuid;
	int		 ntries;
	int		 p;
	u_longlong_t	 pc_addr;
	uchar_t		 rvalue;

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	cpu = id;

	cpuid = drmach_cpu_calc_id(cpu);
	if (SIGBCPU->cpu_id == cpuid) {
		/* this cpu is SIGBCPU, can't disconnect */
		return (drerr_new(1, ESTF_HASSIGB, "%s::%s",
		    cpu->bp->cm.name, cpu->cm.name));
	}

	/*
	 * Make sure SIGBST_DETACHED is set before
	 * mapping out the sig block.
	 */
	ntries = drmach_cpu_ntries;
	while (!drmach_cpu_obp_is_detached(cpuid) && ntries) {
		DELAY(drmach_cpu_delay);
		ntries--;
	}
	if (!drmach_cpu_obp_is_detached(cpuid)) {
		cmn_err(CE_WARN, "failed to mark cpu %d detached in sigblock",
		    cpuid);
	}

	/* map out signature block */
	if (CPU_SGN_EXISTS(cpuid)) {
		CPU_SGN_MAPOUT(cpuid);
	}

	/*
	 * We now PC IDLE the processor to guarantee we
	 * stop any transactions from coming from it.
	 */
	p = cpu->unum & 1;
	pc_addr = STARFIRE_BB_PC_ADDR(cpu->bp->bnum, cpu->unum, 0);

	DRMACH_PR("PC idle cpu %d (addr = 0x%llx, port = %d, p = %d)",
	    drmach_cpu_calc_id(cpu), pc_addr, cpu->unum, p);

	rvalue = ldbphysio(pc_addr);
	rvalue |= STARFIRE_BB_PC_IDLE(p);
	stbphysio(pc_addr, rvalue);
	DELAY(50000);

	return (NULL);
}

sbd_error_t *
drmach_cpu_get_id(drmachid_t id, processorid_t *cpuid)
{
	drmach_device_t *cpu;

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	cpu = id;

	*cpuid = drmach_cpu_calc_id(cpu);
	return (NULL);
}

sbd_error_t *
drmach_cpu_get_impl(drmachid_t id, int *ip)
{
	drmach_device_t *cpu;
	int		impl;

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));

	cpu = id;

	if (drmach_node_get_prop(cpu->node, "implementation#", &impl) == -1) {
		return (DRMACH_INTERNAL_ERROR());
	}

	*ip = impl;

	return (NULL);
}

void
drmach_cpu_flush_ecache_sync(void)
{
	ASSERT(curthread->t_bound_cpu == CPU);

	/*
	 * Now let's flush our ecache thereby removing all references
	 * to the target (detaching) memory from all ecache's in
	 * system.
	 */
	cpu_flush_ecache();

	/*
	 * Delay 100 usec out of paranoia to insure everything
	 * (hardware queues) has drained before we start reprogramming
	 * the hardware.
	 */
	DELAY(100);
}

sbd_error_t *
drmach_get_dip(drmachid_t id, dev_info_t **dip)
{
	drmach_device_t	*dp;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	dp = id;

	*dip = drmach_node_get_dip(dp->node);
	return (NULL);
}

sbd_error_t *
drmach_io_is_attached(drmachid_t id, int *yes)
{
	drmach_device_t *dp;
	dev_info_t	*dip;
	int		state;

	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	dp = id;

	dip = drmach_node_get_dip(dp->node);
	if (dip == NULL) {
		*yes = 0;
		return (NULL);
	}

	state = ddi_get_devstate(dip);
	*yes = (i_ddi_devi_attached(dip) || (state == DDI_DEVSTATE_UP));

	return (NULL);
}

sbd_error_t *
drmach_io_pre_release(drmachid_t id)
{
	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	return (NULL);
}

static sbd_error_t *
drmach_io_release(drmachid_t id)
{
	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	return (NULL);
}

sbd_error_t *
drmach_io_unrelease(drmachid_t id)
{
	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
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
	return (NULL);
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
drmach_mem_new(drmach_device_t *dp)
{
	dp->unum = 0;
	dp->cm.isa = (void *)drmach_mem_new;
	dp->cm.release = drmach_mem_release;
	dp->cm.status = drmach_mem_status;

	(void) snprintf(dp->cm.name, sizeof (dp->cm.name), "%s", dp->type);

	return (NULL);
}

sbd_error_t *
drmach_mem_add_span(drmachid_t id, uint64_t basepa, uint64_t size)
{
	pfn_t		basepfn = (pfn_t)(basepa >> PAGESHIFT);
	pgcnt_t		npages = (pgcnt_t)(size >> PAGESHIFT);
	pda_handle_t	ph;
	int		rv;

	ASSERT(size != 0);

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));

	rv = kcage_range_add(basepfn, npages, KCAGE_DOWN);
	if (rv == ENOMEM) {
		cmn_err(CE_WARN, "%lu megabytes not available to kernel cage",
		    (ulong_t)(size == 0 ? 0 : size / MBYTE));
	} else if (rv != 0) {
		/* catch this in debug kernels */
		ASSERT(0);

		cmn_err(CE_WARN, "unexpected kcage_range_add"
		    " return value %d", rv);
	}

	/*
	 * Update the PDA (post2obp) structure with the
	 * range of the newly added memory.
	 */
	ph = drmach_pda_open();
	if (ph != NULL) {
		pda_mem_add_span(ph, basepa, size);
		pda_close(ph);
	}

	return (NULL);
}

sbd_error_t *
drmach_mem_del_span(drmachid_t id, uint64_t basepa, uint64_t size)
{
	drmach_device_t	*mem = id;
	pfn_t		basepfn = (pfn_t)(basepa >> PAGESHIFT);
	pgcnt_t		npages = (pgcnt_t)(size >> PAGESHIFT);
	uint_t		mcreg;
	sbd_error_t	*err;
	pda_handle_t	ph;
	int		rv;

	err = drmach_read_mc_asr(id, &mcreg);
	if (err)
		return (err);
	else if (mcreg & STARFIRE_MC_INTERLEAVE_MASK) {
		return (drerr_new(1, ESTF_INTERBOARD, "%s::%s",
		    mem->bp->cm.name, mem->cm.name));
	}

	if (size > 0) {
		rv = kcage_range_delete_post_mem_del(basepfn, npages);
		if (rv != 0) {
			cmn_err(CE_WARN,
			    "unexpected kcage_range_delete_post_mem_del"
			    " return value %d", rv);
			return (DRMACH_INTERNAL_ERROR());
		}
	}

	/*
	 * Update the PDA (post2obp) structure with the
	 * range of removed memory.
	 */
	ph = drmach_pda_open();
	if (ph != NULL) {
		if (size > 0)
			pda_mem_del_span(ph, basepa, size);

		/* update PDA to board's new mc register settings */
		pda_mem_sync(ph, mem->bp->bnum, 0);

		pda_close(ph);
	}

	return (NULL);
}

/* support routine for enable and disable */
static sbd_error_t *
drmach_mem_update_interconnect(drmachid_t id, uint_t mcreg)
{
	drmach_device_t	*dp;
	pda_handle_t	 ph;
	int		 b;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	dp = id;

	ph = drmach_pda_open();
	if (ph == NULL)
		return (DRMACH_INTERNAL_ERROR());

	for (b = 0; b < MAX_BOARDS; b++) {
		int		p;
		int		rv;
		ushort_t	bda_proc, bda_ioc;
		board_desc_t	*bdesc;

		if (pda_board_present(ph, b) == 0)
			continue;

		bdesc = (board_desc_t *)pda_get_board_info(ph, b);

		/*
		 * Update PCs for CPUs.
		 */

		/* make sure definition in platmod is in sync with pda */
		ASSERT(MAX_PROCMODS == MAX_CPU_UNITS_PER_BOARD);

		bda_proc = bdesc->bda_proc;
		for (p = 0; p < MAX_PROCMODS; p++) {
			if (BDA_NBL(bda_proc, p) != BDAN_GOOD)
				continue;

			rv = pc_madr_add(b, dp->bp->bnum, p, mcreg);
			if (rv) {
				pda_close(ph);
				return (DRMACH_INTERNAL_ERROR());
			}
		}

		/*
		 * Update PCs for IOCs.
		 */

		/* make sure definition in platmod is in sync with pda */
		ASSERT(MAX_IOCS == MAX_IO_UNITS_PER_BOARD);

		bda_ioc = bdesc->bda_ioc;
		for (p = 0; p < MAX_IOCS; p++) {
			if (BDA_NBL(bda_ioc, p) != BDAN_GOOD)
				continue;

			rv = pc_madr_add(b, dp->bp->bnum, p + 4, mcreg);
			if (rv) {
				pda_close(ph);
				return (DRMACH_INTERNAL_ERROR());
			}
		}
	}

	pda_close(ph);
	return (NULL);
}

sbd_error_t *
drmach_mem_disable(drmachid_t id)
{
	sbd_error_t	*err;
	uint_t		 mcreg;

	err = drmach_read_mc_asr(id, &mcreg);
	if (err == NULL) {
		ASSERT(mcreg & STARFIRE_MC_MEM_PRESENT_MASK);

		/* Turn off presence bit. */
		mcreg &= ~STARFIRE_MC_MEM_PRESENT_MASK;

		err = drmach_mem_update_interconnect(id, mcreg);
		if (err == NULL)
			err = drmach_write_mc_asr(id, mcreg);
	}

	return (err);
}

sbd_error_t *
drmach_mem_enable(drmachid_t id)
{
	sbd_error_t	*err;
	uint_t		 mcreg;

	err = drmach_read_mc_asr(id, &mcreg);
	if (err == NULL) {
		mcreg |= STARFIRE_MC_MEM_PRESENT_MASK;

		err = drmach_write_mc_asr(id, mcreg);
		if (err == NULL)
			err = drmach_mem_update_interconnect(id, mcreg);
	}

	return (err);
}

sbd_error_t *
drmach_mem_get_alignment(drmachid_t id, uint64_t *mask)
{
	drmach_device_t	*mem;
	sbd_error_t	*err;
	pnode_t		 nodeid;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	mem = id;

	nodeid = drmach_node_get_dnode(mem->node);
	if (nodeid == OBP_NONODE || nodeid == OBP_BADNODE)
		err = DRMACH_INTERNAL_ERROR();
	else {
		uint64_t size;

		size = mc_get_alignment_mask(nodeid);
		if (size == (uint64_t)-1)
			err = DRMACH_INTERNAL_ERROR();
		else {
			*mask = size - 1;
			err = NULL;
		}
	}

	return (err);
}

sbd_error_t *
drmach_mem_get_base_physaddr(drmachid_t id, uint64_t *pa)
{
	sbd_error_t	*err;
	uint_t		 mcreg;

	err = drmach_read_mc_asr(id, &mcreg);
	if (err == NULL)
		*pa = mc_asr_to_pa(mcreg);

	return (err);
}

/*
 * Use of this routine after copy/rename will yield incorrect results,
 * because the OBP MEMAVAIL property will not correctly reflect the
 * programming of the MCs.
 */
sbd_error_t *
drmach_mem_get_memlist(drmachid_t id, struct memlist **ml)
{
	drmach_device_t	*mem;
	int		rv, i, rlen, rblks;
	sbd_error_t	*err;
	struct memlist	*mlist;
	struct sf_memunit_regspec *rlist;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	mem = id;

	err = drmach_device_get_proplen(mem, "dr-available", &rlen);
	if (err)
		return (err);

	rlist = kmem_zalloc(rlen, KM_SLEEP);

	err = drmach_device_get_prop(mem, "dr-available", rlist);
	if (err) {
		kmem_free(rlist, rlen);
		return (err);
	}

	mlist = NULL;
	rblks = rlen / sizeof (struct sf_memunit_regspec);
	for (i = 0; i < rblks; i++) {
		uint64_t	addr, size;

		addr  = (uint64_t)rlist[i].regspec_addr_hi << 32;
		addr |= (uint64_t)rlist[i].regspec_addr_lo;
		size  = (uint64_t)rlist[i].regspec_size_hi << 32;
		size |= (uint64_t)rlist[i].regspec_size_lo;

		mlist = memlist_add_span(mlist, addr, size);
	}

	kmem_free(rlist, rlen);

	/*
	 * Make sure the incoming memlist doesn't already
	 * intersect with what's present in the system (phys_install).
	 */
	memlist_read_lock();
	rv = memlist_intersect(phys_install, mlist);
	memlist_read_unlock();
	if (rv) {
#ifdef DEBUG
		DRMACH_PR("OBP derived memlist intersects"
		    " with phys_install\n");
		memlist_dump(mlist);

		DRMACH_PR("phys_install memlist:\n");
		memlist_dump(phys_install);
#endif

		memlist_delete(mlist);
		return (DRMACH_INTERNAL_ERROR());
	}

#ifdef DEBUG
	DRMACH_PR("OBP derived memlist:");
	memlist_dump(mlist);
#endif

	*ml = mlist;
	return (NULL);
}

sbd_error_t *
drmach_mem_get_size(drmachid_t id, uint64_t *bytes)
{
	drmach_device_t	*mem;
	pda_handle_t	ph;
	pgcnt_t		npages;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	mem = id;

	ph = drmach_pda_open();
	if (ph == NULL)
		return (DRMACH_INTERNAL_ERROR());

	npages = pda_get_mem_size(ph, mem->bp->bnum);
	*bytes = (uint64_t)npages << PAGESHIFT;

	pda_close(ph);
	return (NULL);
}

sbd_error_t *
drmach_mem_get_slice_size(drmachid_t id, uint64_t *bytes)
{
	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));

	*bytes = mc_get_mem_alignment();
	return (NULL);
}

/* field debugging tool */
processorid_t drmach_mem_cpu_affinity_nail = 0;

processorid_t
drmach_mem_cpu_affinity(drmachid_t id)
{
	drmach_device_t	*mp;
	drmach_board_t	*bp;
	processorid_t	 cpuid;

	if (!DRMACH_IS_MEM_ID(id))
		return (CPU_CURRENT);

	if (drmach_mem_cpu_affinity_nail) {
		cpuid = drmach_mem_cpu_affinity_nail;

		if (cpuid < 0 || cpuid > NCPU)
			return (CPU_CURRENT);

		mutex_enter(&cpu_lock);
		if (cpu[cpuid] == NULL || !CPU_ACTIVE(cpu[cpuid]))
			cpuid = CPU_CURRENT;
		mutex_exit(&cpu_lock);

		return (cpuid);
	}

	/* try to choose a proc on the target board */
	mp = id;
	bp = mp->bp;
	if (bp->devices) {
		int		rv;
		int		d_idx;
		drmachid_t	d_id;

		rv = drmach_array_first(bp->devices, &d_idx, &d_id);
		while (rv == 0) {
			if (DRMACH_IS_CPU_ID(d_id)) {
				cpuid = drmach_cpu_calc_id(d_id);

				mutex_enter(&cpu_lock);
				if (cpu[cpuid] && CPU_ACTIVE(cpu[cpuid])) {
					mutex_exit(&cpu_lock);
					DRMACH_PR("drmach_mem_cpu_affinity: "
					    "selected cpuid=%d\n", cpuid);
					return (cpuid);
				} else {
					mutex_exit(&cpu_lock);
				}
			}

			rv = drmach_array_next(bp->devices, &d_idx, &d_id);
		}
	}

	/* otherwise, this proc, wherever it is */
	DRMACH_PR("drmach_mem_cpu_affinity: using default CPU_CURRENT\n");

	return (CPU_CURRENT);
}

static sbd_error_t *
drmach_mem_release(drmachid_t id)
{
	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	return (NULL);
}

static sbd_error_t *
drmach_mem_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_device_t *dp;
	sbd_error_t	*err;
	uint64_t	 pa, slice_size;
	struct memlist	*ml;

	ASSERT(DRMACH_IS_MEM_ID(id));
	dp = id;

	/* get starting physical address of target memory */
	err = drmach_mem_get_base_physaddr(id, &pa);
	if (err)
		return (err);

	/* round down to slice boundary */
	slice_size = mc_get_mem_alignment();
	pa &= ~ (slice_size - 1);

	/* stop at first span that is in slice */
	memlist_read_lock();
	for (ml = phys_install; ml; ml = ml->ml_next)
		if (ml->ml_address >= pa && ml->ml_address < pa + slice_size)
			break;
	memlist_read_unlock();

	stat->assigned = dp->bp->assigned;
	stat->powered = dp->bp->powered;
	stat->configured = (ml != NULL);
	stat->busy = dp->busy;
	(void) strncpy(stat->type, dp->type, sizeof (stat->type));
	stat->info[0] = '\0';

	return (NULL);
}

static int
drmach_detach_board(void *arg)
{
	cpuset_t	cset;
	int		retval;
	drmach_board_t	*bp = (drmach_board_t *)arg;

	cset = cpu_ready_set;
	promsafe_xc_attention(cset);

	retval = prom_starfire_rm_brd(bp->bnum);

	xc_dismissed(cset);

	return (retval);
}

sbd_error_t *
drmach_board_deprobe(drmachid_t id)
{
	drmach_board_t	*bp;
	int		 retval;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	bp = id;

	cmn_err(CE_CONT, "DR: PROM detach board %d\n", bp->bnum);

	retval = prom_tree_update(drmach_detach_board, bp);

	if (retval == 0)
		return (NULL);
	else {
		cmn_err(CE_WARN, "prom error: prom_starfire_rm_brd(%d) "
		    "returned %d", bp->bnum, retval);
		return (drerr_new(1, ESTF_DEPROBE, "%s", bp->cm.name));
	}
}

/*ARGSUSED*/
static sbd_error_t *
drmach_pt_juggle_bootproc(drmachid_t id, drmach_opts_t *opts)
{
	drmach_device_t	*cpu;
	sbd_error_t	*err;

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	cpu = id;

	mutex_enter(&cpu_lock);

	err = drmach_cpu_juggle_bootproc(cpu);

	mutex_exit(&cpu_lock);

	return (err);
}

/*ARGSUSED*/
static sbd_error_t *
drmach_pt_dump_pdainfo(drmachid_t id, drmach_opts_t *opts)
{
	drmach_board_t	*bp;
	int		board;
	int		i;
	pda_handle_t	ph;
	board_desc_t	*bdesc;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	bp = id;
	board = bp->bnum;

	ph = drmach_pda_open();
	if (ph == NULL)
		return (DRMACH_INTERNAL_ERROR());

	if (pda_board_present(ph, board) == 0) {
		cmn_err(CE_CONT, "board %d is MISSING\n", board);
		pda_close(ph);
		return (DRMACH_INTERNAL_ERROR());
	}

	cmn_err(CE_CONT, "board %d is PRESENT\n", board);

	bdesc = (board_desc_t *)pda_get_board_info(ph, board);
	if (bdesc == NULL) {
		cmn_err(CE_CONT,
		    "no board descriptor found for board %d\n",
		    board);
		pda_close(ph);
		return (DRMACH_INTERNAL_ERROR());
	}

	/* make sure definition in platmod is in sync with pda */
	ASSERT(MAX_PROCMODS == MAX_CPU_UNITS_PER_BOARD);

	for (i = 0; i < MAX_PROCMODS; i++) {
		if (BDA_NBL(bdesc->bda_proc, i) == BDAN_GOOD)
			cmn_err(CE_CONT,
			    "proc %d.%d PRESENT\n", board, i);
		else
			cmn_err(CE_CONT,
			    "proc %d.%d MISSING\n", board, i);
	}

	for (i = 0; i < MAX_MGROUPS; i++) {
		if (BDA_NBL(bdesc->bda_mgroup, i) == BDAN_GOOD)
			cmn_err(CE_CONT,
			    "mgroup %d.%d PRESENT\n", board, i);
		else
			cmn_err(CE_CONT,
			    "mgroup %d.%d MISSING\n", board, i);
	}

	/* make sure definition in platmod is in sync with pda */
	ASSERT(MAX_IOCS == MAX_IO_UNITS_PER_BOARD);

	for (i = 0; i < MAX_IOCS; i++) {
		int	s;

		if (BDA_NBL(bdesc->bda_ioc, i) == BDAN_GOOD) {
			cmn_err(CE_CONT,
			    "ioc %d.%d PRESENT\n", board, i);
			for (s = 0; s < MAX_SLOTS_PER_IOC; s++) {
				if (BDA_NBL(bdesc->bda_ios[i], s) != BDAN_GOOD)
					continue;
				cmn_err(CE_CONT,
				    "..scard %d.%d.%d PRESENT\n",
				    board, i, s);
			}
		} else {
			cmn_err(CE_CONT,
			    "ioc %d.%d MISSING\n",
			    board, i);
		}
	}

	cmn_err(CE_CONT,
	    "board %d memsize = %d pages\n",
	    board, pda_get_mem_size(ph, board));

	pda_close(ph);

	return (NULL);
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
	{ "juggle",		drmach_pt_juggle_bootproc	},
	{ "pda",		drmach_pt_dump_pdainfo		},
	{ "readmem",		drmach_pt_readmem		},

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
		err = drerr_new(0, ESTF_UNKPTCMD, opts->copts);
	else
		err = (*drmach_pt_arr[i].handler)(id, opts);

	return (err);
}

sbd_error_t *
drmach_release(drmachid_t id)
{
	drmach_common_t *cp;
	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));
	cp = id;

	return (cp->release(id));
}

sbd_error_t *
drmach_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_common_t *cp;

	if (!DRMACH_IS_ID(id))
		return (drerr_new(0, ESTF_NOTID, NULL));
	cp = id;

	return (cp->status(id, stat));
}

sbd_error_t *
drmach_unconfigure(drmachid_t id, int flags)
{
	drmach_device_t	*dp;
	pnode_t		 nodeid;
	dev_info_t	*dip, *fdip = NULL;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, ESTF_INAPPROP, NULL));

	dp = id;

	nodeid = drmach_node_get_dnode(dp->node);
	if (nodeid == OBP_NONODE)
		return (DRMACH_INTERNAL_ERROR());

	dip = e_ddi_nodeid_to_dip(nodeid);
	if (dip == NULL)
		return (NULL);

	/*
	 * Branch already held, so hold acquired in
	 * e_ddi_nodeid_to_dip() can be released
	 */
	ddi_release_devi(dip);

	if (flags & DEVI_BRANCH_DESTROY)
		flags |= DEVI_BRANCH_EVENT;

	/*
	 * Force flag is no longer necessary. See starcat/io/drmach.c
	 * for details.
	 */
	ASSERT(e_ddi_branch_held(dip));
	if (e_ddi_branch_unconfigure(dip, &fdip, flags)) {
		sbd_error_t	*err;
		char		*path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		/*
		 * If non-NULL, fdip is returned held and must be released.
		 */
		if (fdip != NULL) {
			(void) ddi_pathname(fdip, path);
			ndi_rele_devi(fdip);
		} else {
			(void) ddi_pathname(dip, path);
		}

		err = drerr_new(1, ESTF_DRVFAIL, path);

		kmem_free(path, MAXPATHLEN);

		return (err);
	}

	return (NULL);
}

/*
 * drmach interfaces to legacy Starfire platmod logic
 * linkage via runtime symbol look up, called from plat_cpu_power*
 */

/*
 * Start up a cpu.  It is possible that we're attempting to restart
 * the cpu after an UNCONFIGURE in which case the cpu will be
 * spinning in its cache.  So, all we have to do is wake it up.
 * Under normal circumstances the cpu will be coming from a previous
 * CONNECT and thus will be spinning in OBP.  In both cases, the
 * startup sequence is the same.
 */
int
drmach_cpu_poweron(struct cpu *cp)
{
	DRMACH_PR("drmach_cpu_poweron: starting cpuid %d\n", cp->cpu_id);

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (drmach_cpu_start(cp) != 0)
		return (EBUSY);
	else
		return (0);
}

int
drmach_cpu_poweroff(struct cpu *cp)
{
	int		ntries, cnt;
	processorid_t	cpuid = cp->cpu_id;
	void		drmach_cpu_shutdown_self(void);

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

	/* setup xt_mb, will be cleared by drmach_shutdown_asm when ready */
	drmach_xt_mb[cpuid] = 0x80;

	xt_one_unchecked(cpuid, (xcfunc_t *)idle_stop_xcall,
	    (uint64_t)drmach_cpu_shutdown_self, NULL);

	ntries = drmach_cpu_ntries;
	cnt = 0;
	while (drmach_xt_mb[cpuid] && ntries) {
		DELAY(drmach_cpu_delay);
		ntries--;
		cnt++;
	}

	drmach_xt_mb[cpuid] = 0;	/* steal the cache line back */

	start_cpus();

	DRMACH_PR("waited %d out of %d tries for "
	    "drmach_cpu_shutdown_self on cpu%d",
	    drmach_cpu_ntries - ntries, drmach_cpu_ntries, cp->cpu_id);

	drmach_cpu_obp_detach(cpuid);

	CPU_SIGNATURE(OS_SIG, SIGST_DETACHED, SIGSUBST_NULL, cpuid);

	return (0);
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
	if (verbose)
		DRMACH_PR("drmach_log_sysevent: %s %s, flag: %d, verbose: %d\n",
		    attach_pnt, hint, flag, verbose);

	if ((ev = sysevent_alloc(EC_DR, ESC_DR_AP_STATE_CHANGE,
	    SUNW_KERN_PUB"dr", km_flag)) == NULL) {
		rv = -2;
		goto logexit;
	}
	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = attach_pnt;
	if ((rv = sysevent_add_attr(&evnt_attr_list, DR_AP_ID,
	    &evnt_val, km_flag)) != 0)
		goto logexit;

	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = hint;
	if ((rv = sysevent_add_attr(&evnt_attr_list, DR_HINT,
	    &evnt_val, km_flag)) != 0) {
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
		cmn_err(CE_WARN,
		    "drmach_log_sysevent failed (rv %d) for %s  %s\n",
		    rv, attach_pnt, hint);

	return (rv);
}

/*ARGSUSED*/
int
drmach_allow_memrange_modify(drmachid_t id)
{
	return (1);	/* TRUE */
}
