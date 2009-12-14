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

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/ddi_impldefs.h>
#include <sys/autoconf.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/promif.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/promif.h>
#include <sys/conf.h>
#include <sys/obpdefs.h>
#include <sys/cpuvar.h>
#include <vm/seg_kmem.h>
#include <sys/prom_plat.h>
#include <sys/machsystm.h>
#include <sys/note.h>
#include <sys/memlist.h>
#include <sys/ssm.h>

#include <sys/sbd_ioctl.h>
#include <sys/sbd.h>
#include <sys/sbdp_priv.h>
#include <sys/sbdp_mem.h>
#include <sys/sbdp_error.h>
#include <sys/serengeti.h>

#include <sys/sgsbbc.h>		/* To get fn_t type definition */

/*
 * Config information
 */
#ifdef DEBUG
uint_t sbdp_debug = 0x0;
#endif /* DEBUG */

/*
 * Enable or disable dr
 */
int sbdp_dr_available = 1;

/* name properties for some Serengeti device nodes */
#define	CMP_DEVNAME		"cmp"
#define	MEM_DEVNAME		"memory"
#define	CPU_DEVNAME		"cpu"
#define	IO_PCI_DEVNAME		"pci"
#define	IO_SGHSC_DEVNAME	"sghsc"
#define	IO_WCI_DEVNAME		"wci"

static	sbd_devattr_t	sbdp_devattr[] = {
	{ CMP_DEVNAME,		"cmp",			SBD_COMP_CMP },
	{ MEM_DEVNAME,		"memory-controller",	SBD_COMP_MEM },
	{ CPU_DEVNAME,		"cpu",			SBD_COMP_CPU },
	{ IO_PCI_DEVNAME,	"pci",			SBD_COMP_IO },
	{ IO_SGHSC_DEVNAME,	"sghsc",		SBD_COMP_IO },
	{ IO_WCI_DEVNAME,	"wci",			SBD_COMP_IO },
	/* last item must be blank */
	{ NULL,			NULL,			SBD_COMP_UNKNOWN }
};

/*
 * In the case of a busy mbox, if a status cmd comes in we return a cached
 * copy.  This cache is a link list of wnodes that contains bd structs with
 * the appropriate info.  When a new wnode is created a whole entry is added
 * to the list.
 */
sbdp_wnode_t	*first_node = NULL; /* first wnode. Entry to the link list */
int		cur_num_wnodes = 0; /* how many nodes are currently running */

/* Macros to access fields in the previous array */
#define	SBDP_CT(i)		sbdp_devattr[i].s_dnodetype
#define	SBDP_DEVNAME(i)		sbdp_devattr[(i)].s_devname
#define	SBDP_OTYPE(i)		sbdp_devattr[(i)].s_obp_type

/*
 * Prototypes
 */
sbdp_wnode_t *sbdp_get_wnodep(int);

/*
 * Module linkage information for the kernel.
 */

static struct modlmisc modlmisc = {
	&mod_miscops,
	"Serengeti sbdp",
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

/*
 * VA area used during CPU shutdown.
 */
caddr_t	sbdp_shutdown_va;

/*
 * Mutex to protect our inventory
 */
kmutex_t	sbdp_wnode_mutex;

int
_init(void)
{
	int e;

	e = mod_install(&modlinkage);
	if (e != 0)
		return (e);

	sbdp_shutdown_va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
	ASSERT(sbdp_shutdown_va != NULL);
	sbdp_valp = (uint64_t *)vmem_alloc(static_alloc_arena,
	    sizeof (uint64_t), VM_SLEEP);

	mutex_init(&sbdp_wnode_mutex, NULL, MUTEX_DRIVER, NULL);
	return (e);
}

int
_fini(void)
{
	int e;

	/*
	 * Remove the module.
	 */
	e = mod_remove(&modlinkage);
	if (e != 0)
		return (e);

	vmem_free(heap_arena, sbdp_shutdown_va, PAGESIZE);
	sbdp_shutdown_va = NULL;
	vmem_free(static_alloc_arena, (void *)sbdp_valp, sizeof (uint64_t));
	sbdp_valp = NULL;

	mutex_destroy(&sbdp_wnode_mutex);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
sbdp_get_bd_and_wnode_num(pnode_t nodeid, int *bd, int *wnode)
{
	int portid;
	static fn_t	f = "sbdp_get_bd_and_wnode_num";
	extern int	get_portid(pnode_t node, pnode_t *cmpp);

	SBDP_DBG_FUNC("%s\n", f);

	if (sbdp_is_node_bad(nodeid))
		return (-1);

	if ((portid = get_portid(nodeid, NULL)) == -1)
		return (-1);

	/*
	 * decode the board number
	 */
	*bd = SG_PORTID_TO_BOARD_NUM(portid);
	*wnode = SG_PORTID_TO_NODEID(portid);

	return (0);
}

int
sbdp_get_board_num(sbdp_handle_t *hp, dev_info_t *dip)
{
	_NOTE(ARGUNUSED(hp))

	pnode_t		nodeid;
	int		bd, wnode;
	static fn_t	f = "sbdp_get_board_num";

	SBDP_DBG_FUNC("%s\n", f);

	if (dip == NULL)
		return (-1);

	nodeid = ddi_get_nodeid(dip);

	/*
	 * Portid has encoded the nodeid and the agent id.  The top
	 * 4 bits are correspond to the wcnodeid and the lower 5 are the
	 * agent id.
	 * Each agent id represents a physical location hence we can
	 * obtain the board number
	 */
	if (sbdp_get_bd_and_wnode_num(nodeid, &bd, &wnode) < 0)
		return (-1);

	return (bd);
}


sbd_devattr_t *
sbdp_get_devattr(void)
{
	return (&sbdp_devattr[0]);
}

int
sbdp_portid_to_cpu_unit(int cmp, int core)
{
	return (SG_PORTID_TO_CPU_UNIT(cmp, core));
}

int
sbdp_get_unit_num(sbdp_handle_t *hp, dev_info_t *dip)
{
	int		unit = -1;
	int		portid;
	processorid_t	cpuid;
	sbd_comp_type_t	type;
	char		dev_type[OBP_MAXPROPNAME];
	int		i;
	pnode_t		nodeid;
	static fn_t	f = "sbdp_get_unit_num";

	SBDP_DBG_FUNC("%s\n", f);

	if (dip == NULL)
		return (-1);

	nodeid = ddi_get_nodeid(dip);

	if (sbdp_is_node_bad(nodeid))
		return (-1);

	if (prom_getprop(nodeid, "device_type", (caddr_t)dev_type) < 0) {
		SBDP_DBG_MISC("%s: couldn't get device_type\n", f);
		return (-1);
	}

	for (i = 0; SBDP_CT(i) != SBD_COMP_UNKNOWN; i++) {
		if (strcmp(dev_type, SBDP_OTYPE(i)) != 0)
			continue;
		type = SBDP_CT(i);
	}

	switch (type) {
	case SBD_COMP_CPU:
		if ((cpuid = sbdp_get_cpuid(hp, dip)) != -1) {
			unit = SG_CPUID_TO_CPU_UNIT(cpuid);
		}
		break;
	case SBD_COMP_MEM:
		unit = 0;
		break;
	case SBD_COMP_IO: {
		regspace_t	regs[3];
		int		len = 0;

		/*
		 * Check to see if this is a cpci node
		 * cpci nodes are assign unit nums of 5 for now
		 * So they don't conflict with the pci unit nums
		 */

		if (strcmp(dev_type, "sghsc") == 0) {
			SBDP_DBG_MISC("it is a sghsc\n");
			return (4);
		}

		if (prom_getprop(nodeid, "portid", (caddr_t)&portid) <= 0) {
			SBDP_DBG_MISC("%s: couldn't get portid\n", f);
			return (-1);
		}

		len = prom_getproplen(nodeid, "reg");
		if (len <= 0) {
			SBDP_DBG_MISC("%s: couldn't get length\n", f);
			return (-1);
		}

		if (prom_getprop(nodeid, "reg", (caddr_t)regs) < 0) {
			SBDP_DBG_MISC("%s: couldn't get registers\n", f);
			return (-1);
		}

		if ((portid % 2) != 0)
			if ((regs[0].regspec_addr_lo & 0x700000) ==
			    0x700000)
				unit = 0;
			else
				unit = 1;
		else
			if ((regs[0].regspec_addr_lo & 0x700000) ==
			    0x700000)
				unit = 2;
			else
				unit = 3;

		SBDP_DBG_MISC("unit is %d\n", unit);
		break;
	}
	default:
		break;

	}

	return (unit);
}

struct sbdp_mem_dip {
	sbdp_bd_t	*bdp;
	dev_info_t	*dip;
};

static int
sbdp_get_mem_dip(pnode_t node, void *arg, uint_t flags)
{
	_NOTE(ARGUNUSED(flags))

	struct sbdp_mem_dip	*smdp = (struct sbdp_mem_dip *)arg;
	mem_op_t	mem = {0};

	if (node == OBP_NONODE || node == OBP_BADNODE)
		return (DDI_FAILURE);

	mem.nodes = smdp->bdp->nodes;
	mem.board = smdp->bdp->bd;
	mem.nmem  = smdp->bdp->nnum;

	(void) sbdp_is_mem(node, &mem);

	/*
	 * We need to find the dip only for the first nodeid
	 */
	if (smdp->bdp->nnum == 0 && mem.nmem == 1) {
		ASSERT(smdp->dip == NULL);
		smdp->dip = e_ddi_nodeid_to_dip(node);
	}

	smdp->bdp->nnum = mem.nmem;

	return (DDI_SUCCESS);
}


/*
 * Update the board info.  Required after a copy rename
 */
void
sbdp_update_bd_info(sbdp_bd_t *bdp)
{
	attach_pkt_t		apkt, *apktp = &apkt;
	struct sbdp_mem_dip	smd = {0};
	static fn_t	f = "sbdp_update_bd_info";

	SBDP_DBG_FUNC("%s\n", f);

	if (bdp == NULL) {
		return;
	}
	/*
	 * Grab the lock
	 */
	mutex_enter(&bdp->bd_mutex);

	/*
	 * we get the top nodes here.  This will have a side effect of
	 * updating the present bit for cpus
	 */
	apktp->node = bdp->wnode;
	apktp->board = bdp->bd;
	apktp->num_of_nodes = 0;
	apktp->flags = 0;
	sbdp_walk_prom_tree(prom_rootnode(), sbdp_select_top_nodes,
	    (void *) apktp);

	/*
	 * We need to clear nnum since we are looking again for the
	 * nodes
	 */
	bdp->nnum = 0;
	smd.bdp = bdp;

	/*
	 * If a dip is found by sbdp_get_mem_dip(), it will be
	 * returned held
	 */
	sbdp_walk_prom_tree(prom_rootnode(), sbdp_get_mem_dip, &smd);
	if (smd.dip != NULL) {
		sbdp_handle_t		*hp;

		hp = kmem_zalloc(sizeof (sbdp_handle_t), KM_SLEEP);
		hp->h_board = bdp->bd;
		hp->h_wnode = bdp->wnode;
		hp->h_err = kmem_zalloc(sizeof (*hp->h_err), KM_SLEEP);
		if (bdp->ml != NULL) {
			(void) sbdp_del_memlist(hp, bdp->ml);
		}
		bdp->ml = sbdp_get_memlist(hp, (dev_info_t *)NULL);
		/*
		 * if the board doesn't have banks initialize them,
		 * otherwise we assume they have been updated if
		 * necessary
		 */
		if (bdp->banks == NULL) {
			sbdp_init_bd_banks(bdp);
		}
#ifdef DEBUG
		sbdp_print_bd_banks(bdp);
#endif

		if (sbdphw_get_base_physaddr(hp, smd.dip, &bdp->bpa))
			bdp->bpa = -1;
		ddi_release_devi(smd.dip);
		kmem_free(hp->h_err, sizeof (*hp->h_err));
		kmem_free(hp, sizeof (sbdp_handle_t));
	}
	mutex_exit(&bdp->bd_mutex);
}

/*
 * Initialize the board struct.  This remains cached.  We update it
 * every time we have a successful show_board and after a copy-rename
 */
void
sbdp_bd_init(sbdp_bd_t *bdp, int bd, int wnode)
{
	static fn_t	f = "sbdp_bd_init";

	SBDP_DBG_FUNC("%s\n", f);

	bdp->bd = bd;
	bdp->wnode = wnode;

	SBDP_UNSET_ALL_CPUS_IN_RESET(bdp);

	bdp->cpus_present = 0;

	sbdp_update_bd_info(bdp);

	mutex_init(&bdp->bd_mutex, NULL, MUTEX_DRIVER, NULL);
	bdp->bd_sc = (show_board_t *)kmem_zalloc(sizeof (show_board_t),
	    KM_SLEEP);
	bdp->valid_cp = -1;
}

/*
 * This entry is going away.  Clean up
 */
void
sbdp_bd_fini(sbdp_bd_t *bdp)
{
	static fn_t	f = "sbdp_bd_fini";

	SBDP_DBG_FUNC("%s\n", f);

	sbdp_cleanup_bd(bdp->wnode, bdp->bd);
	kmem_free(bdp->bd_sc, sizeof (show_board_t));
	bdp->bd_sc = NULL;
	mutex_destroy(&bdp->bd_mutex);
#ifdef DEBUG
	sbdp_print_all_segs();
#endif
}

/*
 * A new wnode has arrived.  Initialize the struct and create
 * the board structures.
 */
void
sbdp_wnode_init(sbdp_wnode_t *wnodep, int wnode, int boards)
{
	int		i;
	static fn_t	f = "sbdp_wnode_init";

	SBDP_DBG_FUNC("%s\n", f);

	wnodep->wnode = wnode;
	wnodep->nbds = boards;
	wnodep->bds = kmem_zalloc(sizeof (sbdp_bd_t) * boards, KM_SLEEP);
	wnodep->next = wnodep->prev = NULL;

	for (i = 0; i < boards; i++)
		sbdp_bd_init(&wnodep->bds[i], i, wnode);
}

/*
 * Wnode got DRed out.  Clean up all the node stuff including the boards
 */
void
sbdp_wnode_fini(sbdp_wnode_t *wnodep)
{
	int	boards;
	int	i;
	static fn_t	f = "sbdp_wnode_fini";

	SBDP_DBG_FUNC("%s\n", f);

	boards = wnodep->nbds;

	for (i = 0; i < boards; i++)
		sbdp_bd_fini(&wnodep->bds[i]);

	kmem_free(wnodep->bds, sizeof (sbdp_bd_t) * boards);
	wnodep->next = wnodep->prev = NULL;
	kmem_free(wnodep, sizeof (sbdp_wnode_t));
}

/*
 * Add all the necessary fields to this board's struct
 */
void
sbdp_add_new_bd_info(int wnode, int board)
{
	sbdp_wnode_t	*cur;
	static fn_t	f = "sbdp_add_new_bd_info";

	SBDP_DBG_FUNC("%s\n", f);

	cur = sbdp_get_wnodep(wnode);

	SBDP_DBG_MISC("adding new board info %d\n", board);

	sbdp_update_bd_info(&cur->bds[board]);

}

/*
 * This board has gone away.  Clean the necessary fields
 */
void
sbdp_cleanup_bd(int wnode, int board)
{
	sbdp_wnode_t	*cur;
	sbdp_handle_t	handle, *hp;
	sbdp_bd_t	*bdp;
	int		i;
	static fn_t	f = "sbdp_cleanup_bd";

	SBDP_DBG_FUNC("%s\n", f);

	cur = sbdp_get_wnodep(wnode);

	SBDP_DBG_MISC("cleaning up bd info for bd %d\n", board);
	if (cur == NULL) {
		SBDP_DBG_MISC("cur is null\n");
		return;
	}

	bdp = &cur->bds[board];

	/*
	 * Grab the lock
	 */
	mutex_enter(&bdp->bd_mutex);

	for (i = 0; i < bdp->nnum; i++)
		bdp->nodes[i] = (pnode_t)0;
	bdp->nnum = 0;

	sbdp_fini_bd_banks(bdp);

	hp = &handle;
	hp->h_board = bdp->bd;
	hp->h_wnode = bdp->wnode;
	if (bdp->ml) {
		(void) sbdp_del_memlist(hp, bdp->ml);
	}

	bdp->ml = NULL;

	bdp->bpa = -1;

	sbdp_cpu_in_reset(wnode, bdp->bd, SBDP_ALL_CPUS, 0);

	bdp->cpus_present = 0;

	mutex_exit(&bdp->bd_mutex);
}

/*
 *  Traverse the list looking for wnode. Return it when found
 */
sbdp_wnode_t *
sbdp_get_wnodep(int wnode)
{
	sbdp_wnode_t	*cur;
	int		i;
	static fn_t	f = "sbdp_get_wnodep";

	SBDP_DBG_FUNC("%s\n", f);

	mutex_enter(&sbdp_wnode_mutex);
	for (i = 0, cur = first_node; i < cur_num_wnodes; i++,
	    cur = cur->next) {
		if (cur->wnode == wnode) {
			mutex_exit(&sbdp_wnode_mutex);
			return (cur);
		}
	}
	mutex_exit(&sbdp_wnode_mutex);

	return (NULL);
}

/*
 * Insert this brand new node into our master list. It leaves it all
 * initialized
 */
void
sbdp_insert_wnode(int wnode, int max_boards)
{
	sbdp_wnode_t	*wnodep;
	sbdp_wnode_t	*cur;
	static fn_t	f = "sbdp_insert_wnode";

	SBDP_DBG_FUNC("%s\n", f);

	wnodep = kmem_zalloc(sizeof (sbdp_wnode_t), KM_SLEEP);

	mutex_enter(&sbdp_wnode_mutex);
	if (first_node == NULL) {
		first_node = wnodep;
		cur_num_wnodes++;
	} else {
		cur = first_node + cur_num_wnodes++;
		cur->next = wnodep;
		wnodep->prev = cur;
	}
	mutex_exit(&sbdp_wnode_mutex);
	sbdp_wnode_init(wnodep, wnode, max_boards);
}

/*
 * This node is gone.  Remove it from the list and also clean up
 */
void
sbdp_remove_wnode(sbdp_wnode_t *wnodep)
{
	sbdp_wnode_t	*cur;
	static fn_t	f = "sbdp_remove_wnode";

	SBDP_DBG_FUNC("%s\n", f);

	if (wnodep != NULL) {
		sbdp_wnode_fini(wnodep);
		mutex_enter(&sbdp_wnode_mutex);

		if (first_node == wnodep)
			first_node = NULL;
		else {
			cur = wnodep->prev;
			if (cur != NULL)
				cur->next = wnodep->next;
			if (wnodep->next != NULL)
				wnodep->next->prev = cur;
		}

		cur_num_wnodes--;
		mutex_exit(&sbdp_wnode_mutex);
	}
}

/*
 * Entry point from sbd.  This is called when a new node is added.  We
 * create an entry in our inventory and initialize all the stuff that will be
 * needed
 */
int
sbdp_setup_instance(caddr_t arg)
{
	ssm_sbdp_info_t	*sbdp_info;
	int		instance;
	int		wnode;
	int		max_boards;
	static fn_t	f = "sbdp_setup_instance";

	SBDP_DBG_FUNC("%s\n", f);

	/*
	 * We get this directly from ssm
	 */
	sbdp_info = (ssm_sbdp_info_t *)arg;

	instance = sbdp_info->instance;
	wnode = sbdp_info->wnode;
	max_boards = plat_max_boards();

	SBDP_DBG_MISC("sbdp_setup_instance: instance %d wnode %d\n", instance,
	    sbdp_info->wnode);

	if (sbdp_get_wnodep(wnode) == NULL) {
		/*
		 * This node has not been instanstiated
		 * create one
		 */
		sbdp_insert_wnode(wnode, max_boards);
	}

	return (DDI_SUCCESS);
}

/*
 * Entry point from sbd. This is called when a node has been removed (or is
 * going away. We do all the necessary cleanup
 */
int
sbdp_teardown_instance(caddr_t arg)
{
	ssm_sbdp_info_t	*sbdp_info;
	int		instance;
	int		wnode;
	sbdp_wnode_t	*wnodep;
	static fn_t	f = "sbdp_teardown_instance";

	SBDP_DBG_FUNC("%s\n", f);

	/*
	 * ssm should have set this up
	 */
	sbdp_info = (ssm_sbdp_info_t *)arg;

	instance = sbdp_info->instance;
	wnode = sbdp_info->wnode;

	SBDP_DBG_MISC("sbdp_teardown_instance: instance %d wnode %d\n",
	    instance, wnode);

	/*
	 * Find this node and then remove it
	 */
	if ((wnodep = sbdp_get_wnodep(wnode)) != NULL) {
		sbdp_remove_wnode(wnodep);
	}
	return (DDI_SUCCESS);
}

int
sbdp_disabled_component(sbdp_handle_t *hp)
{
#ifdef lint
	hp = hp;
#endif
	return (0);
}

/* ARGSUSED */
int
sbdp_release_component(sbdp_handle_t *hp, dev_info_t *dip)
{
	return (0);
}

void
sbdp_set_err(sbd_error_t *ep, int ecode, char *rsc)
{
	static fn_t	f = "sbdp_set_err";

	SBDP_DBG_FUNC("%s\n", f);
	ASSERT(ep != NULL);
	ep->e_code = ecode;

	if (rsc != NULL) {
		(void) strcpy((caddr_t)(ep->e_rsc), (caddr_t)rsc);
	}
}

/*
 * Serengeti DR passthrus are for debugging purposes only.
 */
static struct {
	const char	*name;
	int		(*handler)(sbdp_handle_t *, void *);
} sbdp_passthrus[] = {
#ifdef DEBUG
	{ "readmem",		sbdp_passthru_readmem		},
	{ "prep-script",	sbdp_passthru_prep_script	},
	{ "test-quiesce",	sbdp_passthru_test_quiesce	},
	{ "inject-error",	sbdp_passthru_inject_error	},
	{ "reset-error",	sbdp_passthru_reset_error	},
#endif

	/* the following line must always be last */
	{ NULL,			NULL				}
};


/*ARGSUSED*/
int
sbdp_ioctl(sbdp_handle_t *hp, sbdp_ioctl_arg_t *sbdpi)
{
#ifdef DEBUG
	char buf[512];
	int rv;
	sbd_ioctl_arg_t *sbdi   = (sbd_ioctl_arg_t *)sbdpi->h_iap;
	int		i;
	static fn_t	f = "sbdp_ioctl";

	SBDP_DBG_FUNC("%s\n", f);

	if (sbdi->i_len >= sizeof (buf) ||
	    ddi_copyin(sbdi->i_opts, buf, sbdi->i_len, sbdpi->h_mode)) {
		sbdp_set_err(hp->h_err, ESBD_FAULT, NULL);
		return (-1);
	}

	i = 0;
	while (sbdp_passthrus[i].name != NULL) {
		int	len;

		len = strlen(sbdp_passthrus[i].name);
		if (strncmp(sbdp_passthrus[i].name, buf, len) == 0)
			break;
		i++;
	}

	if (sbdp_passthrus[i].name == NULL) {
		sbdp_set_err(hp->h_err, ESBD_INVAL, NULL);
		rv = EIO;
	} else {
		rv = (*sbdp_passthrus[i].handler)(hp, buf);
		if (rv != ESBD_NOERROR) {
			sbdp_set_err(hp->h_err, rv, NULL);
			rv = EIO;
		}

	}

	return (rv);
#else
	return (0);
#endif
}

/*
 * Check the dnode we obtained.  Need to find a better way to determine
 * if the node has the correct starting address
 */
int
sbdp_is_node_bad(pnode_t node)
{
	static fn_t	f = "sbdp_is_node_bad";

	SBDP_DBG_FUNC("%s\n", f);

	return ((node == OBP_NONODE) || (node == OBP_BADNODE) ||
	    ((node & 0x80000000u) != 0x80000000u));
}

/*
 * Retrieve the information we have on this board from
 * the inventory
 */
sbdp_bd_t *
sbdp_get_bd_info(int wnode, int board)
{
	sbdp_wnode_t	*wnodep;
	sbdp_bd_t	*bdp;
	int		max_bds;
	static fn_t	f = "sbdp_get_bd_info";

	SBDP_DBG_FUNC("%s\n", f);

	wnodep = sbdp_get_wnodep(wnode);
	max_bds = plat_max_boards();

	if ((wnodep == NULL) || ((board < 0) && (board > max_bds))) {
		return (NULL);
	}

	bdp = &wnodep->bds[board];

	/*
	 * We might not have the complete bd info.  With cheetah we
	 * cannot access the memory decode registers when then cpu is
	 * in reset. If the mem info is incomplete, then we try to gather it
	 * here
	 */
	sbdp_update_bd_info(bdp);

	return (bdp);
}

/*
 * There are certain cases where obp marks components as failed
 * If the status is ok the node won't have any status property. It
 * is only there if the status is other than ok.
 */
sbd_cond_t
sbdp_get_comp_status(pnode_t nodeid)
{
	char			status_buf[OBP_MAXPROPNAME];
	static const char	*status = "status";
	static const char	*failed = "fail";
	static const char	*disabled = "disabled";
	static fn_t		f = "sbdp_get_comp_status";

	SBDP_DBG_FUNC("%s\n", f);

	if (sbdp_is_node_bad(nodeid)) {
		SBDP_DBG_STATE("node is not ok\n");
		return (SBD_COND_UNKNOWN);
	}

	if (prom_getproplen(nodeid, (char *)status) <= 0) {
		SBDP_DBG_STATE("status is ok\n");
		return (SBD_COND_OK);
	}

	if (prom_getprop(nodeid, (char *)status, status_buf) < 0) {
		SBDP_DBG_STATE("status is unknown\n");
		return (SBD_COND_UNKNOWN);
	}

	if (strncmp(status_buf, failed, strlen(failed)) == 0) {
		SBDP_DBG_STATE("status of failed\n");
		return (SBD_COND_FAILED);
	}

	if (strcmp(status_buf, disabled) == 0) {
		SBDP_DBG_STATE("status of unusable\n");
		return (SBD_COND_UNUSABLE);
	}

	return (SBD_COND_OK);
}

void
sbdp_cpu_in_reset(int node, int bd, int unit, int reset)
{
	sbdp_wnode_t	*cur;
	sbdp_bd_t	*bdp;
	static fn_t	f = "sbdp_cpu_in_reset";

	SBDP_DBG_FUNC("%s\n", f);

	if ((unit < -1) || (bd < 0) || (node < 0)) {
		return;
	}

	cur = sbdp_get_wnodep(node);

	SBDP_DBG_MISC("marking cpu %d %s for board %d\n", unit,
	    (reset) ? "in reset" : "out of reset", bd);

	if (cur == NULL) {
		return;
	}

	bdp = &cur->bds[bd];

	if (unit == SBDP_ALL_CPUS)
		if (reset == 1)
			SBDP_SET_ALL_CPUS_IN_RESET(bdp);
		else
			SBDP_UNSET_ALL_CPUS_IN_RESET(bdp);
	else
		if (reset == 1)
			SBDP_SET_CPU_IN_RESET(bdp, unit);
		else
			SBDP_UNSET_CPU_IN_RESET(bdp, unit);
}

int
sbdp_set_cpu_present(int node, int bd, int unit)
{
	sbdp_wnode_t	*cur;
	sbdp_bd_t	*bdp;
	static fn_t	f = "sbdp_set_cpu_present";

	SBDP_DBG_FUNC("%s\n", f);

	if ((unit < 0) || (bd < 0) || (node < 0)) {
		return (-1);
	}

	cur = sbdp_get_wnodep(node);
	if (cur == NULL) {
		return (-1);
	}

	bdp = &cur->bds[bd];

	SBDP_SET_CPU_PRESENT(bdp, unit);

	return (0);
}

int
sbdp_is_cpu_present(int node, int bd, int unit)
{
	sbdp_wnode_t	*cur;
	sbdp_bd_t	*bdp;
	static fn_t	f = "sbdp_is_cpu_present";

	SBDP_DBG_FUNC("%s\n", f);

	if ((unit < 0) || (bd < 0) || (node < 0)) {
		return (-1);
	}

	cur = sbdp_get_wnodep(node);
	if (cur == NULL) {
		return (-1);
	}

	bdp = &cur->bds[bd];

	return (SBDP_IS_CPU_PRESENT(bdp, unit));
}

int
sbdp_is_cpu_in_reset(int node, int bd, int unit)
{
	sbdp_wnode_t	*cur;
	sbdp_bd_t	*bdp;
	static fn_t	f = "sbdp_is_cpu_in_reset";

	SBDP_DBG_FUNC("%s\n", f);

	if ((unit < 0) || (bd < 0) || (node < 0)) {
		return (-1);
	}

	cur = sbdp_get_wnodep(node);

	if (cur == NULL) {
		return (-1);
	}

	bdp = &cur->bds[bd];

	return (SBDP_IS_CPU_IN_RESET(bdp, unit));
}

int
sbdp_dr_avail(void)
{
	static fn_t	f = "sbdp_dr_avail";

	SBDP_DBG_FUNC("%s\n", f);

	if (sbdp_dr_available)
		if (sg_prom_sb_dr_check() == 0)
			return (1);
	return (0);
}
