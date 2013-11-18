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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#include <sys/note.h>
#include <sys/t_lock.h>
#include <sys/cmn_err.h>
#include <sys/instance.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/hwconf.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/modctl.h>
#include <sys/contract/device_impl.h>
#include <sys/dacf.h>
#include <sys/promif.h>
#include <sys/pci.h>
#include <sys/cpuvar.h>
#include <sys/pathname.h>
#include <sys/taskq.h>
#include <sys/sysevent.h>
#include <sys/sunmdi.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/fs/snode.h>
#include <sys/fs/dv_node.h>
#include <sys/reboot.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/fs/sdev_impl.h>
#include <sys/sunldi.h>
#include <sys/sunldi_impl.h>
#include <sys/bootprops.h>
#include <sys/varargs.h>
#include <sys/modhash.h>
#include <sys/instance.h>

#if defined(__amd64) && !defined(__xpv)
#include <sys/iommulib.h>
#endif

#ifdef DEBUG
int ddidebug = DDI_AUDIT;
#else
int ddidebug = 0;
#endif

#define	MT_CONFIG_OP	0
#define	MT_UNCONFIG_OP	1

/* Multi-threaded configuration */
struct mt_config_handle {
	kmutex_t mtc_lock;
	kcondvar_t mtc_cv;
	int mtc_thr_count;
	dev_info_t *mtc_pdip;	/* parent dip for mt_config_children */
	dev_info_t **mtc_fdip;	/* "a" dip where unconfigure failed */
	major_t mtc_parmajor;	/* parent major for mt_config_driver */
	major_t mtc_major;
	int mtc_flags;
	int mtc_op;		/* config or unconfig */
	int mtc_error;		/* operation error */
	struct brevq_node **mtc_brevqp;	/* outstanding branch events queue */
#ifdef DEBUG
	int total_time;
	timestruc_t start_time;
#endif /* DEBUG */
};

struct devi_nodeid {
	pnode_t nodeid;
	dev_info_t *dip;
	struct devi_nodeid *next;
};

struct devi_nodeid_list {
	kmutex_t dno_lock;		/* Protects other fields */
	struct devi_nodeid *dno_head;	/* list of devi nodeid elements */
	struct devi_nodeid *dno_free;	/* Free list */
	uint_t dno_list_length;		/* number of dips in list */
};

/* used to keep track of branch remove events to be generated */
struct brevq_node {
	char *brn_deviname;
	struct brevq_node *brn_sibling;
	struct brevq_node *brn_child;
};

static struct devi_nodeid_list devi_nodeid_list;
static struct devi_nodeid_list *devimap = &devi_nodeid_list;

/*
 * Well known nodes which are attached first at boot time.
 */
dev_info_t *top_devinfo;		/* root of device tree */
dev_info_t *options_dip;
dev_info_t *pseudo_dip;
dev_info_t *clone_dip;
dev_info_t *scsi_vhci_dip;		/* MPXIO dip */
major_t clone_major;

/*
 * A non-global zone's /dev is derived from the device tree.
 * This generation number serves to indicate when a zone's
 * /dev may need to be updated.
 */
volatile ulong_t devtree_gen;		/* generation number */

/* block all future dev_info state changes */
hrtime_t volatile devinfo_freeze = 0;

/* number of dev_info attaches/detaches currently in progress */
static ulong_t devinfo_attach_detach = 0;

extern int	sys_shutdown;
extern kmutex_t global_vhci_lock;

/* bitset of DS_SYSAVAIL & DS_RECONFIG - no races, no lock */
static int devname_state = 0;

/*
 * The devinfo snapshot cache and related variables.
 * The only field in the di_cache structure that needs initialization
 * is the mutex (cache_lock). However, since this is an adaptive mutex
 * (MUTEX_DEFAULT) - it is automatically initialized by being allocated
 * in zeroed memory (static storage class). Therefore no explicit
 * initialization of the di_cache structure is needed.
 */
struct di_cache	di_cache = {1};
int		di_cache_debug = 0;

/* For ddvis, which needs pseudo children under PCI */
int pci_allow_pseudo_children = 0;

/* Allow path-oriented alias driver binding on driver.conf enumerated nodes */
int driver_conf_allow_path_alias = 1;

/*
 * The following switch is for service people, in case a
 * 3rd party driver depends on identify(9e) being called.
 */
int identify_9e = 0;

/*
 * Add flag so behaviour of preventing attach for retired persistant nodes
 * can be disabled.
 */
int retire_prevents_attach = 1;

int mtc_off;					/* turn off mt config */

int quiesce_debug = 0;

boolean_t ddi_aliases_present = B_FALSE;
ddi_alias_t ddi_aliases;
uint_t tsd_ddi_redirect;

#define	DDI_ALIAS_HASH_SIZE	(2700)

static kmem_cache_t *ddi_node_cache;		/* devinfo node cache */
static devinfo_log_header_t *devinfo_audit_log;	/* devinfo log */
static int devinfo_log_size;			/* size in pages */

boolean_t ddi_err_panic = B_FALSE;

static int lookup_compatible(dev_info_t *, uint_t);
static char *encode_composite_string(char **, uint_t, size_t *, uint_t);
static void link_to_driver_list(dev_info_t *);
static void unlink_from_driver_list(dev_info_t *);
static void add_to_dn_list(struct devnames *, dev_info_t *);
static void remove_from_dn_list(struct devnames *, dev_info_t *);
static dev_info_t *find_duplicate_child();
static void add_global_props(dev_info_t *);
static void remove_global_props(dev_info_t *);
static int uninit_node(dev_info_t *);
static void da_log_init(void);
static void da_log_enter(dev_info_t *);
static int walk_devs(dev_info_t *, int (*f)(dev_info_t *, void *), void *, int);
static int reset_nexus_flags(dev_info_t *, void *);
static void ddi_optimize_dtree(dev_info_t *);
static int is_leaf_node(dev_info_t *);
static struct mt_config_handle *mt_config_init(dev_info_t *, dev_info_t **,
    int, major_t, int, struct brevq_node **);
static void mt_config_children(struct mt_config_handle *);
static void mt_config_driver(struct mt_config_handle *);
static int mt_config_fini(struct mt_config_handle *);
static int devi_unconfig_common(dev_info_t *, dev_info_t **, int, major_t,
    struct brevq_node **);
static int
ndi_devi_config_obp_args(dev_info_t *parent, char *devnm,
    dev_info_t **childp, int flags);
static void i_link_vhci_node(dev_info_t *);
static void ndi_devi_exit_and_wait(dev_info_t *dip,
    int circular, clock_t end_time);
static int ndi_devi_unbind_driver(dev_info_t *dip);

static int i_ddi_check_retire(dev_info_t *dip);

static void quiesce_one_device(dev_info_t *, void *);

dev_info_t *ddi_alias_redirect(char *alias);
char *ddi_curr_redirect(char *currpath);


/*
 * dev_info cache and node management
 */

/* initialize dev_info node cache */
void
i_ddi_node_cache_init()
{
	ASSERT(ddi_node_cache == NULL);
	ddi_node_cache = kmem_cache_create("dev_info_node_cache",
	    sizeof (struct dev_info), 0, NULL, NULL, NULL, NULL, NULL, 0);

	if (ddidebug & DDI_AUDIT)
		da_log_init();
}


/*
 * Allocating a dev_info node, callable from interrupt context with KM_NOSLEEP
 * The allocated node has a reference count of 0.
 */
dev_info_t *
i_ddi_alloc_node(dev_info_t *pdip, char *node_name, pnode_t nodeid,
    int instance, ddi_prop_t *sys_prop, int flag)
{
	struct dev_info *devi;
	struct devi_nodeid *elem;
	static char failed[] = "i_ddi_alloc_node: out of memory";

	ASSERT(node_name != NULL);

	if ((devi = kmem_cache_alloc(ddi_node_cache, flag)) == NULL) {
		cmn_err(CE_NOTE, failed);
		return (NULL);
	}

	bzero(devi, sizeof (struct dev_info));

	if (devinfo_audit_log) {
		devi->devi_audit = kmem_zalloc(sizeof (devinfo_audit_t), flag);
		if (devi->devi_audit == NULL)
			goto fail;
	}

	if ((devi->devi_node_name = i_ddi_strdup(node_name, flag)) == NULL)
		goto fail;

	/* default binding name is node name */
	devi->devi_binding_name = devi->devi_node_name;
	devi->devi_major = DDI_MAJOR_T_NONE;	/* unbound by default */

	/*
	 * Make a copy of system property
	 */
	if (sys_prop &&
	    (devi->devi_sys_prop_ptr = i_ddi_prop_list_dup(sys_prop, flag))
	    == NULL)
		goto fail;

	/*
	 * Assign devi_nodeid, devi_node_class, devi_node_attributes
	 * according to the following algorithm:
	 *
	 * nodeid arg			node class		node attributes
	 *
	 * DEVI_PSEUDO_NODEID		DDI_NC_PSEUDO		A
	 * DEVI_SID_NODEID		DDI_NC_PSEUDO		A,P
	 * DEVI_SID_HIDDEN_NODEID	DDI_NC_PSEUDO		A,P,H
	 * DEVI_SID_HP_NODEID		DDI_NC_PSEUDO		A,P,h
	 * DEVI_SID_HP_HIDDEN_NODEID	DDI_NC_PSEUDO		A,P,H,h
	 * other			DDI_NC_PROM		P
	 *
	 * Where A = DDI_AUTO_ASSIGNED_NODEID (auto-assign a nodeid)
	 * and	 P = DDI_PERSISTENT
	 * and	 H = DDI_HIDDEN_NODE
	 * and	 h = DDI_HOTPLUG_NODE
	 *
	 * auto-assigned nodeids are also auto-freed.
	 */
	devi->devi_node_attributes = 0;
	switch (nodeid) {
	case DEVI_SID_HIDDEN_NODEID:
		devi->devi_node_attributes |= DDI_HIDDEN_NODE;
		goto sid;

	case DEVI_SID_HP_NODEID:
		devi->devi_node_attributes |= DDI_HOTPLUG_NODE;
		goto sid;

	case DEVI_SID_HP_HIDDEN_NODEID:
		devi->devi_node_attributes |= DDI_HIDDEN_NODE;
		devi->devi_node_attributes |= DDI_HOTPLUG_NODE;
		goto sid;

	case DEVI_SID_NODEID:
sid:		devi->devi_node_attributes |= DDI_PERSISTENT;
		if ((elem = kmem_zalloc(sizeof (*elem), flag)) == NULL)
			goto fail;
		/*FALLTHROUGH*/

	case DEVI_PSEUDO_NODEID:
		devi->devi_node_attributes |= DDI_AUTO_ASSIGNED_NODEID;
		devi->devi_node_class = DDI_NC_PSEUDO;
		if (impl_ddi_alloc_nodeid(&devi->devi_nodeid)) {
			panic("i_ddi_alloc_node: out of nodeids");
			/*NOTREACHED*/
		}
		break;

	default:
		if ((elem = kmem_zalloc(sizeof (*elem), flag)) == NULL)
			goto fail;

		/*
		 * the nodetype is 'prom', try to 'take' the nodeid now.
		 * This requires memory allocation, so check for failure.
		 */
		if (impl_ddi_take_nodeid(nodeid, flag) != 0) {
			kmem_free(elem, sizeof (*elem));
			goto fail;
		}

		devi->devi_nodeid = nodeid;
		devi->devi_node_class = DDI_NC_PROM;
		devi->devi_node_attributes = DDI_PERSISTENT;
		break;
	}

	if (ndi_dev_is_persistent_node((dev_info_t *)devi)) {
		mutex_enter(&devimap->dno_lock);
		elem->next = devimap->dno_free;
		devimap->dno_free = elem;
		mutex_exit(&devimap->dno_lock);
	}

	/*
	 * Instance is normally initialized to -1. In a few special
	 * cases, the caller may specify an instance (e.g. CPU nodes).
	 */
	devi->devi_instance = instance;

	/*
	 * set parent and bus_ctl parent
	 */
	devi->devi_parent = DEVI(pdip);
	devi->devi_bus_ctl = DEVI(pdip);

	NDI_CONFIG_DEBUG((CE_CONT,
	    "i_ddi_alloc_node: name=%s id=%d\n", node_name, devi->devi_nodeid));

	cv_init(&(devi->devi_cv), NULL, CV_DEFAULT, NULL);
	mutex_init(&(devi->devi_lock), NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&(devi->devi_pm_lock), NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&(devi->devi_pm_busy_lock), NULL, MUTEX_DEFAULT, NULL);

	RIO_TRACE((CE_NOTE, "i_ddi_alloc_node: Initing contract fields: "
	    "dip=%p, name=%s", (void *)devi, node_name));

	mutex_init(&(devi->devi_ct_lock), NULL, MUTEX_DEFAULT, NULL);
	cv_init(&(devi->devi_ct_cv), NULL, CV_DEFAULT, NULL);
	devi->devi_ct_count = -1;	/* counter not in use if -1 */
	list_create(&(devi->devi_ct), sizeof (cont_device_t),
	    offsetof(cont_device_t, cond_next));

	i_ddi_set_node_state((dev_info_t *)devi, DS_PROTO);
	da_log_enter((dev_info_t *)devi);
	return ((dev_info_t *)devi);

fail:
	if (devi->devi_sys_prop_ptr)
		i_ddi_prop_list_delete(devi->devi_sys_prop_ptr);
	if (devi->devi_node_name)
		kmem_free(devi->devi_node_name, strlen(node_name) + 1);
	if (devi->devi_audit)
		kmem_free(devi->devi_audit, sizeof (devinfo_audit_t));
	kmem_cache_free(ddi_node_cache, devi);
	cmn_err(CE_NOTE, failed);
	return (NULL);
}

/*
 * free a dev_info structure.
 * NB. Not callable from interrupt since impl_ddi_free_nodeid may block.
 */
void
i_ddi_free_node(dev_info_t *dip)
{
	struct dev_info *devi = DEVI(dip);
	struct devi_nodeid *elem;

	ASSERT(devi->devi_ref == 0);
	ASSERT(devi->devi_addr == NULL);
	ASSERT(devi->devi_node_state == DS_PROTO);
	ASSERT(devi->devi_child == NULL);
	ASSERT(devi->devi_hp_hdlp == NULL);

	/* free devi_addr_buf allocated by ddi_set_name_addr() */
	if (devi->devi_addr_buf)
		kmem_free(devi->devi_addr_buf, 2 * MAXNAMELEN);

	if (i_ndi_dev_is_auto_assigned_node(dip))
		impl_ddi_free_nodeid(DEVI(dip)->devi_nodeid);

	if (ndi_dev_is_persistent_node(dip)) {
		mutex_enter(&devimap->dno_lock);
		ASSERT(devimap->dno_free);
		elem = devimap->dno_free;
		devimap->dno_free = elem->next;
		mutex_exit(&devimap->dno_lock);
		kmem_free(elem, sizeof (*elem));
	}

	if (DEVI(dip)->devi_compat_names)
		kmem_free(DEVI(dip)->devi_compat_names,
		    DEVI(dip)->devi_compat_length);
	if (DEVI(dip)->devi_rebinding_name)
		kmem_free(DEVI(dip)->devi_rebinding_name,
		    strlen(DEVI(dip)->devi_rebinding_name) + 1);

	ddi_prop_remove_all(dip);	/* remove driver properties */
	if (devi->devi_sys_prop_ptr)
		i_ddi_prop_list_delete(devi->devi_sys_prop_ptr);
	if (devi->devi_hw_prop_ptr)
		i_ddi_prop_list_delete(devi->devi_hw_prop_ptr);

	if (DEVI(dip)->devi_devid_str)
		ddi_devid_str_free(DEVI(dip)->devi_devid_str);

	i_ddi_set_node_state(dip, DS_INVAL);
	da_log_enter(dip);
	if (devi->devi_audit) {
		kmem_free(devi->devi_audit, sizeof (devinfo_audit_t));
	}
	if (devi->devi_device_class)
		kmem_free(devi->devi_device_class,
		    strlen(devi->devi_device_class) + 1);
	cv_destroy(&(devi->devi_cv));
	mutex_destroy(&(devi->devi_lock));
	mutex_destroy(&(devi->devi_pm_lock));
	mutex_destroy(&(devi->devi_pm_busy_lock));

	RIO_TRACE((CE_NOTE, "i_ddi_free_node: destroying contract fields: "
	    "dip=%p", (void *)dip));
	contract_device_remove_dip(dip);
	ASSERT(devi->devi_ct_count == -1);
	ASSERT(list_is_empty(&(devi->devi_ct)));
	cv_destroy(&(devi->devi_ct_cv));
	list_destroy(&(devi->devi_ct));
	/* free this last since contract_device_remove_dip() uses it */
	mutex_destroy(&(devi->devi_ct_lock));
	RIO_TRACE((CE_NOTE, "i_ddi_free_node: destroyed all contract fields: "
	    "dip=%p, name=%s", (void *)dip, devi->devi_node_name));

	kmem_free(devi->devi_node_name, strlen(devi->devi_node_name) + 1);

	/* free event data */
	if (devi->devi_ev_path)
		kmem_free(devi->devi_ev_path, MAXPATHLEN);

	kmem_cache_free(ddi_node_cache, devi);
}


/*
 * Node state transitions
 */

/*
 * Change the node name
 */
int
ndi_devi_set_nodename(dev_info_t *dip, char *name, int flags)
{
	_NOTE(ARGUNUSED(flags))
	char *nname, *oname;

	ASSERT(dip && name);

	oname = DEVI(dip)->devi_node_name;
	if (strcmp(oname, name) == 0)
		return (DDI_SUCCESS);

	/*
	 * pcicfg_fix_ethernet requires a name change after node
	 * is linked into the tree. When pcicfg is fixed, we
	 * should only allow name change in DS_PROTO state.
	 */
	if (i_ddi_node_state(dip) >= DS_BOUND) {
		/*
		 * Don't allow name change once node is bound
		 */
		cmn_err(CE_NOTE,
		    "ndi_devi_set_nodename: node already bound dip = %p,"
		    " %s -> %s", (void *)dip, ddi_node_name(dip), name);
		return (NDI_FAILURE);
	}

	nname = i_ddi_strdup(name, KM_SLEEP);
	DEVI(dip)->devi_node_name = nname;
	i_ddi_set_binding_name(dip, nname);
	kmem_free(oname, strlen(oname) + 1);

	da_log_enter(dip);
	return (NDI_SUCCESS);
}

void
i_ddi_add_devimap(dev_info_t *dip)
{
	struct devi_nodeid *elem;

	ASSERT(dip);

	if (!ndi_dev_is_persistent_node(dip))
		return;

	ASSERT(ddi_get_parent(dip) == NULL || (DEVI_VHCI_NODE(dip)) ||
	    DEVI_BUSY_OWNED(ddi_get_parent(dip)));

	mutex_enter(&devimap->dno_lock);

	ASSERT(devimap->dno_free);

	elem = devimap->dno_free;
	devimap->dno_free = elem->next;

	elem->nodeid = ddi_get_nodeid(dip);
	elem->dip = dip;
	elem->next = devimap->dno_head;
	devimap->dno_head = elem;

	devimap->dno_list_length++;

	mutex_exit(&devimap->dno_lock);
}

static int
i_ddi_remove_devimap(dev_info_t *dip)
{
	struct devi_nodeid *prev, *elem;
	static const char *fcn = "i_ddi_remove_devimap";

	ASSERT(dip);

	if (!ndi_dev_is_persistent_node(dip))
		return (DDI_SUCCESS);

	mutex_enter(&devimap->dno_lock);

	/*
	 * The following check is done with dno_lock held
	 * to prevent race between dip removal and
	 * e_ddi_prom_node_to_dip()
	 */
	if (e_ddi_devi_holdcnt(dip)) {
		mutex_exit(&devimap->dno_lock);
		return (DDI_FAILURE);
	}

	ASSERT(devimap->dno_head);
	ASSERT(devimap->dno_list_length > 0);

	prev = NULL;
	for (elem = devimap->dno_head; elem; elem = elem->next) {
		if (elem->dip == dip) {
			ASSERT(elem->nodeid == ddi_get_nodeid(dip));
			break;
		}
		prev = elem;
	}

	if (elem && prev)
		prev->next = elem->next;
	else if (elem)
		devimap->dno_head = elem->next;
	else
		panic("%s: devinfo node(%p) not found",
		    fcn, (void *)dip);

	devimap->dno_list_length--;

	elem->nodeid = 0;
	elem->dip = NULL;

	elem->next = devimap->dno_free;
	devimap->dno_free = elem;

	mutex_exit(&devimap->dno_lock);

	return (DDI_SUCCESS);
}

/*
 * Link this node into the devinfo tree and add to orphan list
 * Not callable from interrupt context
 */
static void
link_node(dev_info_t *dip)
{
	struct dev_info *devi = DEVI(dip);
	struct dev_info *parent = devi->devi_parent;
	dev_info_t **dipp;

	ASSERT(parent);	/* never called for root node */

	NDI_CONFIG_DEBUG((CE_CONT, "link_node: parent = %s child = %s\n",
	    parent->devi_node_name, devi->devi_node_name));

	/*
	 * Hold the global_vhci_lock before linking any direct
	 * children of rootnex driver. This special lock protects
	 * linking and unlinking for rootnext direct children.
	 */
	if ((dev_info_t *)parent == ddi_root_node())
		mutex_enter(&global_vhci_lock);

	/*
	 * attach the node to end of the list unless the node is already there
	 */
	dipp = (dev_info_t **)(&DEVI(parent)->devi_child);
	while (*dipp && (*dipp != dip)) {
		dipp = (dev_info_t **)(&DEVI(*dipp)->devi_sibling);
	}
	ASSERT(*dipp == NULL);	/* node is not linked */

	/*
	 * Now that we are in the tree, update the devi-nodeid map.
	 */
	i_ddi_add_devimap(dip);

	/*
	 * This is a temporary workaround for Bug 4618861.
	 * We keep the scsi_vhci nexus node on the left side of the devinfo
	 * tree (under the root nexus driver), so that virtual nodes under
	 * scsi_vhci will be SUSPENDed first and RESUMEd last.	This ensures
	 * that the pHCI nodes are active during times when their clients
	 * may be depending on them.  This workaround embodies the knowledge
	 * that system PM and CPR both traverse the tree left-to-right during
	 * SUSPEND and right-to-left during RESUME.
	 * Extending the workaround to IB Nexus/VHCI
	 * driver also.
	 */
	if (strcmp(devi->devi_binding_name, "scsi_vhci") == 0) {
		/* Add scsi_vhci to beginning of list */
		ASSERT((dev_info_t *)parent == top_devinfo);
		/* scsi_vhci under rootnex */
		devi->devi_sibling = parent->devi_child;
		parent->devi_child = devi;
	} else if (strcmp(devi->devi_binding_name, "ib") == 0) {
		i_link_vhci_node(dip);
	} else {
		/* Add to end of list */
		*dipp = dip;
		DEVI(dip)->devi_sibling = NULL;
	}

	/*
	 * Release the global_vhci_lock before linking any direct
	 * children of rootnex driver.
	 */
	if ((dev_info_t *)parent == ddi_root_node())
		mutex_exit(&global_vhci_lock);

	/* persistent nodes go on orphan list */
	if (ndi_dev_is_persistent_node(dip))
		add_to_dn_list(&orphanlist, dip);
}

/*
 * Unlink this node from the devinfo tree
 */
static int
unlink_node(dev_info_t *dip)
{
	struct dev_info *devi = DEVI(dip);
	struct dev_info *parent = devi->devi_parent;
	dev_info_t **dipp;
	ddi_hp_cn_handle_t *hdlp;

	ASSERT(parent != NULL);
	ASSERT(devi->devi_node_state == DS_LINKED);

	NDI_CONFIG_DEBUG((CE_CONT, "unlink_node: name = %s\n",
	    ddi_node_name(dip)));

	/* check references */
	if (devi->devi_ref || i_ddi_remove_devimap(dip) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Hold the global_vhci_lock before linking any direct
	 * children of rootnex driver.
	 */
	if ((dev_info_t *)parent == ddi_root_node())
		mutex_enter(&global_vhci_lock);

	dipp = (dev_info_t **)(&DEVI(parent)->devi_child);
	while (*dipp && (*dipp != dip)) {
		dipp = (dev_info_t **)(&DEVI(*dipp)->devi_sibling);
	}
	if (*dipp) {
		*dipp = (dev_info_t *)(devi->devi_sibling);
		devi->devi_sibling = NULL;
	} else {
		NDI_CONFIG_DEBUG((CE_NOTE, "unlink_node: %s not linked",
		    devi->devi_node_name));
	}

	/*
	 * Release the global_vhci_lock before linking any direct
	 * children of rootnex driver.
	 */
	if ((dev_info_t *)parent == ddi_root_node())
		mutex_exit(&global_vhci_lock);

	/* Remove node from orphan list */
	if (ndi_dev_is_persistent_node(dip)) {
		remove_from_dn_list(&orphanlist, dip);
	}

	/* Update parent's hotplug handle list */
	for (hdlp = DEVI(parent)->devi_hp_hdlp; hdlp; hdlp = hdlp->next) {
		if (hdlp->cn_info.cn_child == dip)
			hdlp->cn_info.cn_child = NULL;
	}
	return (DDI_SUCCESS);
}

/*
 * Bind this devinfo node to a driver. If compat is NON-NULL, try that first.
 * Else, use the node-name.
 *
 * NOTE: IEEE1275 specifies that nodename should be tried before compatible.
 *	Solaris implementation binds nodename after compatible.
 *
 * If we find a binding,
 * - set the binding name to the string,
 * - set major number to driver major
 *
 * If we don't find a binding,
 * - return failure
 */
static int
bind_node(dev_info_t *dip)
{
	char *p = NULL;
	major_t major = DDI_MAJOR_T_NONE;
	struct dev_info *devi = DEVI(dip);
	dev_info_t *parent = ddi_get_parent(dip);

	ASSERT(devi->devi_node_state == DS_LINKED);

	NDI_CONFIG_DEBUG((CE_CONT, "bind_node: 0x%p(name = %s)\n",
	    (void *)dip, ddi_node_name(dip)));

	mutex_enter(&DEVI(dip)->devi_lock);
	if (DEVI(dip)->devi_flags & DEVI_NO_BIND) {
		mutex_exit(&DEVI(dip)->devi_lock);
		return (DDI_FAILURE);
	}
	mutex_exit(&DEVI(dip)->devi_lock);

	/* find the driver with most specific binding using compatible */
	major = ddi_compatible_driver_major(dip, &p);
	if (major == DDI_MAJOR_T_NONE)
		return (DDI_FAILURE);

	devi->devi_major = major;
	if (p != NULL) {
		i_ddi_set_binding_name(dip, p);
		NDI_CONFIG_DEBUG((CE_CONT, "bind_node: %s bound to %s\n",
		    devi->devi_node_name, p));
	}

	/* Link node to per-driver list */
	link_to_driver_list(dip);

	/*
	 * reset parent flag so that nexus will merge .conf props
	 */
	if (ndi_dev_is_persistent_node(dip)) {
		mutex_enter(&DEVI(parent)->devi_lock);
		DEVI(parent)->devi_flags &=
		    ~(DEVI_ATTACHED_CHILDREN|DEVI_MADE_CHILDREN);
		mutex_exit(&DEVI(parent)->devi_lock);
	}
	return (DDI_SUCCESS);
}

/*
 * Unbind this devinfo node
 * Called before the node is destroyed or driver is removed from system
 */
static int
unbind_node(dev_info_t *dip)
{
	ASSERT(DEVI(dip)->devi_node_state == DS_BOUND);
	ASSERT(DEVI(dip)->devi_major != DDI_MAJOR_T_NONE);

	/* check references */
	if (DEVI(dip)->devi_ref)
		return (DDI_FAILURE);

	NDI_CONFIG_DEBUG((CE_CONT, "unbind_node: 0x%p(name = %s)\n",
	    (void *)dip, ddi_node_name(dip)));

	unlink_from_driver_list(dip);

	DEVI(dip)->devi_major = DDI_MAJOR_T_NONE;
	DEVI(dip)->devi_binding_name = DEVI(dip)->devi_node_name;
	return (DDI_SUCCESS);
}

/*
 * Initialize a node: calls the parent nexus' bus_ctl ops to do the operation.
 * Must hold parent and per-driver list while calling this function.
 * A successful init_node() returns with an active ndi_hold_devi() hold on
 * the parent.
 */
static int
init_node(dev_info_t *dip)
{
	int error;
	dev_info_t *pdip = ddi_get_parent(dip);
	int (*f)(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *, void *);
	char *path;
	major_t	major;
	ddi_devid_t devid = NULL;

	ASSERT(i_ddi_node_state(dip) == DS_BOUND);

	/* should be DS_READY except for pcmcia ... */
	ASSERT(i_ddi_node_state(pdip) >= DS_PROBED);

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, path);
	NDI_CONFIG_DEBUG((CE_CONT, "init_node: entry: path %s 0x%p\n",
	    path, (void *)dip));

	/*
	 * The parent must have a bus_ctl operation.
	 */
	if ((DEVI(pdip)->devi_ops->devo_bus_ops == NULL) ||
	    (f = DEVI(pdip)->devi_ops->devo_bus_ops->bus_ctl) == NULL) {
		error = DDI_FAILURE;
		goto out;
	}

	add_global_props(dip);

	/*
	 * Invoke the parent's bus_ctl operation with the DDI_CTLOPS_INITCHILD
	 * command to transform the child to canonical form 1. If there
	 * is an error, ddi_remove_child should be called, to clean up.
	 */
	error = (*f)(pdip, pdip, DDI_CTLOPS_INITCHILD, dip, NULL);
	if (error != DDI_SUCCESS) {
		NDI_CONFIG_DEBUG((CE_CONT, "init_node: %s 0x%p failed\n",
		    path, (void *)dip));
		remove_global_props(dip);

		/*
		 * If a nexus INITCHILD implementation calls ddi_devid_regster()
		 * prior to setting devi_addr, the devid is not recorded in
		 * the devid cache (i.e. DEVI_CACHED_DEVID is not set).
		 * With mpxio, while the vhci client path may be missing
		 * from the cache, phci pathinfo paths may have already be
		 * added to the cache, against the client dip, by use of
		 * e_devid_cache_pathinfo().  Because of this, when INITCHILD
		 * of the client fails, we need to purge the client dip from
		 * the cache even if DEVI_CACHED_DEVID is not set - if only
		 * devi_devid_str is set.
		 */
		mutex_enter(&DEVI(dip)->devi_lock);
		if ((DEVI(dip)->devi_flags & DEVI_CACHED_DEVID) ||
		    DEVI(dip)->devi_devid_str) {
			DEVI(dip)->devi_flags &= ~DEVI_CACHED_DEVID;
			mutex_exit(&DEVI(dip)->devi_lock);
			ddi_devid_unregister(dip);
		} else
			mutex_exit(&DEVI(dip)->devi_lock);

		/* in case nexus driver didn't clear this field */
		ddi_set_name_addr(dip, NULL);
		error = DDI_FAILURE;
		goto out;
	}

	ndi_hold_devi(pdip);			/* initial hold of parent */

	/* recompute path after initchild for @addr information */
	(void) ddi_pathname(dip, path);

	/* Check for duplicate nodes */
	if (find_duplicate_child(pdip, dip) != NULL) {
		/*
		 * uninit_node() the duplicate - a successful uninit_node()
		 * will release inital hold of parent using ndi_rele_devi().
		 */
		if ((error = uninit_node(dip)) != DDI_SUCCESS) {
			ndi_rele_devi(pdip);	/* release initial hold */
			cmn_err(CE_WARN, "init_node: uninit of duplicate "
			    "node %s failed", path);
		}
		NDI_CONFIG_DEBUG((CE_CONT, "init_node: duplicate uninit "
		    "%s 0x%p%s\n", path, (void *)dip,
		    (error == DDI_SUCCESS) ? "" : " failed"));
		error = DDI_FAILURE;
		goto out;
	}

	/*
	 * If a devid was registered for a DS_BOUND node then the devid_cache
	 * may not have captured the path. Detect this situation and ensure that
	 * the path enters the cache now that devi_addr is established.
	 */
	if (!(DEVI(dip)->devi_flags & DEVI_CACHED_DEVID) &&
	    (ddi_devid_get(dip, &devid) == DDI_SUCCESS)) {
		if (e_devid_cache_register(dip, devid) == DDI_SUCCESS) {
			mutex_enter(&DEVI(dip)->devi_lock);
			DEVI(dip)->devi_flags |= DEVI_CACHED_DEVID;
			mutex_exit(&DEVI(dip)->devi_lock);
		}

		ddi_devid_free(devid);
	}

	/*
	 * Check to see if we have a path-oriented driver alias that overrides
	 * the current driver binding. If so, we need to rebind. This check
	 * needs to be delayed until after a successful DDI_CTLOPS_INITCHILD,
	 * so the unit-address is established on the last component of the path.
	 *
	 * NOTE: Allowing a path-oriented alias to change the driver binding
	 * of a driver.conf node results in non-intuitive property behavior.
	 * We provide a tunable (driver_conf_allow_path_alias) to control
	 * this behavior. See uninit_node() for more details.
	 *
	 * NOTE: If you are adding a path-oriented alias for the boot device,
	 * and there is mismatch between OBP and the kernel in regard to
	 * generic name use, like "disk" .vs. "ssd", then you will need
	 * to add a path-oriented alias for both paths.
	 */
	major = ddi_name_to_major(path);
	if (driver_active(major) && (major != DEVI(dip)->devi_major) &&
	    (ndi_dev_is_persistent_node(dip) || driver_conf_allow_path_alias)) {

		/* Mark node for rebind processing. */
		mutex_enter(&DEVI(dip)->devi_lock);
		DEVI(dip)->devi_flags |= DEVI_REBIND;
		mutex_exit(&DEVI(dip)->devi_lock);

		/*
		 * Add an extra hold on the parent to prevent it from ever
		 * having a zero devi_ref during the child rebind process.
		 * This is necessary to ensure that the parent will never
		 * detach(9E) during the rebind.
		 */
		ndi_hold_devi(pdip);		/* extra hold of parent */

		/*
		 * uninit_node() current binding - a successful uninit_node()
		 * will release extra hold of parent using ndi_rele_devi().
		 */
		if ((error = uninit_node(dip)) != DDI_SUCCESS) {
			ndi_rele_devi(pdip);	/* release extra hold */
			ndi_rele_devi(pdip);	/* release initial hold */
			cmn_err(CE_WARN, "init_node: uninit for rebind "
			    "of node %s failed", path);
			goto out;
		}

		/* Unbind: demote the node back to DS_LINKED.  */
		if ((error = ndi_devi_unbind_driver(dip)) != DDI_SUCCESS) {
			ndi_rele_devi(pdip);	/* release initial hold */
			cmn_err(CE_WARN, "init_node: unbind for rebind "
			    "of node %s failed", path);
			goto out;
		}

		/* establish rebinding name */
		if (DEVI(dip)->devi_rebinding_name == NULL)
			DEVI(dip)->devi_rebinding_name =
			    i_ddi_strdup(path, KM_SLEEP);

		/*
		 * Now that we are demoted and marked for rebind, repromote.
		 * We need to do this in steps, instead of just calling
		 * ddi_initchild, so that we can redo the merge operation
		 * after we are rebound to the path-bound driver.
		 *
		 * Start by rebinding node to the path-bound driver.
		 */
		if ((error = ndi_devi_bind_driver(dip, 0)) != DDI_SUCCESS) {
			ndi_rele_devi(pdip);	/* release initial hold */
			cmn_err(CE_WARN, "init_node: rebind "
			    "of node %s failed", path);
			goto out;
		}

		/*
		 * If the node is not a driver.conf node then merge
		 * driver.conf properties from new path-bound driver.conf.
		 */
		if (ndi_dev_is_persistent_node(dip))
			(void) i_ndi_make_spec_children(pdip, 0);

		/*
		 * Now that we have taken care of merge, repromote back
		 * to DS_INITIALIZED.
		 */
		error = ddi_initchild(pdip, dip);
		NDI_CONFIG_DEBUG((CE_CONT, "init_node: rebind "
		    "%s 0x%p\n", path, (void *)dip));

		/*
		 * Release our initial hold. If ddi_initchild() was
		 * successful then it will return with the active hold.
		 */
		ndi_rele_devi(pdip);
		goto out;
	}

	/*
	 * Apply multi-parent/deep-nexus optimization to the new node
	 */
	DEVI(dip)->devi_instance = e_ddi_assign_instance(dip);
	ddi_optimize_dtree(dip);
	error = DDI_SUCCESS;		/* return with active hold */

out:	if (error != DDI_SUCCESS) {
		/* On failure ensure that DEVI_REBIND is cleared */
		mutex_enter(&DEVI(dip)->devi_lock);
		DEVI(dip)->devi_flags &= ~DEVI_REBIND;
		mutex_exit(&DEVI(dip)->devi_lock);
	}
	kmem_free(path, MAXPATHLEN);
	return (error);
}

/*
 * Uninitialize node
 * The per-driver list must be held busy during the call.
 * A successful uninit_node() releases the init_node() hold on
 * the parent by calling ndi_rele_devi().
 */
static int
uninit_node(dev_info_t *dip)
{
	int node_state_entry;
	dev_info_t *pdip;
	struct dev_ops *ops;
	int (*f)();
	int error;
	char *addr;

	/*
	 * Don't check for references here or else a ref-counted
	 * dip cannot be downgraded by the framework.
	 */
	node_state_entry = i_ddi_node_state(dip);
	ASSERT((node_state_entry == DS_BOUND) ||
	    (node_state_entry == DS_INITIALIZED));
	pdip = ddi_get_parent(dip);
	ASSERT(pdip);

	NDI_CONFIG_DEBUG((CE_CONT, "uninit_node: 0x%p(%s%d)\n",
	    (void *)dip, ddi_driver_name(dip), ddi_get_instance(dip)));

	if (((ops = ddi_get_driver(pdip)) == NULL) ||
	    (ops->devo_bus_ops == NULL) ||
	    ((f = ops->devo_bus_ops->bus_ctl) == NULL)) {
		return (DDI_FAILURE);
	}

	/*
	 * save the @addr prior to DDI_CTLOPS_UNINITCHILD for use in
	 * freeing the instance if it succeeds.
	 */
	if (node_state_entry == DS_INITIALIZED) {
		addr = ddi_get_name_addr(dip);
		if (addr)
			addr = i_ddi_strdup(addr, KM_SLEEP);
	} else {
		addr = NULL;
	}

	error = (*f)(pdip, pdip, DDI_CTLOPS_UNINITCHILD, dip, (void *)NULL);
	if (error == DDI_SUCCESS) {
		/* ensure that devids are unregistered */
		mutex_enter(&DEVI(dip)->devi_lock);
		if ((DEVI(dip)->devi_flags & DEVI_CACHED_DEVID)) {
			DEVI(dip)->devi_flags &= ~DEVI_CACHED_DEVID;
			mutex_exit(&DEVI(dip)->devi_lock);
			ddi_devid_unregister(dip);
		} else
			mutex_exit(&DEVI(dip)->devi_lock);

		/* if uninitchild forgot to set devi_addr to NULL do it now */
		ddi_set_name_addr(dip, NULL);

		/*
		 * Free instance number. This is a no-op if instance has
		 * been kept by probe_node().  Avoid free when we are called
		 * from init_node (DS_BOUND) because the instance has not yet
		 * been assigned.
		 */
		if (node_state_entry == DS_INITIALIZED) {
			e_ddi_free_instance(dip, addr);
			DEVI(dip)->devi_instance = -1;
		}

		/* release the init_node hold */
		ndi_rele_devi(pdip);

		remove_global_props(dip);

		/*
		 * NOTE: The decision on whether to allow a path-oriented
		 * rebind of a driver.conf enumerated node is made by
		 * init_node() based on driver_conf_allow_path_alias. The
		 * rebind code below prevents deletion of system properties
		 * on driver.conf nodes.
		 *
		 * When driver_conf_allow_path_alias is set, property behavior
		 * on rebound driver.conf file is non-intuitive. For a
		 * driver.conf node, the unit-address properties come from
		 * the driver.conf file as system properties. Removing system
		 * properties from a driver.conf node makes the node
		 * useless (we get node without unit-address properties) - so
		 * we leave system properties in place. The result is a node
		 * where system properties come from the node being rebound,
		 * and global properties come from the driver.conf file
		 * of the driver we are rebinding to.  If we could determine
		 * that the path-oriented alias driver.conf file defined a
		 * node at the same unit address, it would be best to use
		 * that node and avoid the non-intuitive property behavior.
		 * Unfortunately, the current "merge" code does not support
		 * this, so we live with the non-intuitive property behavior.
		 */
		if (!((ndi_dev_is_persistent_node(dip) == 0) &&
		    (DEVI(dip)->devi_flags & DEVI_REBIND)))
			e_ddi_prop_remove_all(dip);
	} else {
		NDI_CONFIG_DEBUG((CE_CONT, "uninit_node failed: 0x%p(%s%d)\n",
		    (void *)dip, ddi_driver_name(dip), ddi_get_instance(dip)));
	}

	if (addr)
		kmem_free(addr, strlen(addr) + 1);
	return (error);
}

/*
 * Invoke driver's probe entry point to probe for existence of hardware.
 * Keep instance permanent for successful probe and leaf nodes.
 *
 * Per-driver list must be held busy while calling this function.
 */
static int
probe_node(dev_info_t *dip)
{
	int rv;

	ASSERT(i_ddi_node_state(dip) == DS_INITIALIZED);

	NDI_CONFIG_DEBUG((CE_CONT, "probe_node: 0x%p(%s%d)\n",
	    (void *)dip, ddi_driver_name(dip), ddi_get_instance(dip)));

	/* temporarily hold the driver while we probe */
	DEVI(dip)->devi_ops = ndi_hold_driver(dip);
	if (DEVI(dip)->devi_ops == NULL) {
		NDI_CONFIG_DEBUG((CE_CONT,
		    "probe_node: 0x%p(%s%d) cannot load driver\n",
		    (void *)dip, ddi_driver_name(dip), ddi_get_instance(dip)));
		return (DDI_FAILURE);
	}

	if (identify_9e != 0)
		(void) devi_identify(dip);

	rv = devi_probe(dip);

	/* release the driver now that probe is complete */
	ndi_rele_driver(dip);
	DEVI(dip)->devi_ops = NULL;

	switch (rv) {
	case DDI_PROBE_SUCCESS:			/* found */
	case DDI_PROBE_DONTCARE:		/* ddi_dev_is_sid */
		e_ddi_keep_instance(dip);	/* persist instance */
		rv = DDI_SUCCESS;
		break;

	case DDI_PROBE_PARTIAL:			/* maybe later */
	case DDI_PROBE_FAILURE:			/* not found */
		NDI_CONFIG_DEBUG((CE_CONT,
		    "probe_node: 0x%p(%s%d) no hardware found%s\n",
		    (void *)dip, ddi_driver_name(dip), ddi_get_instance(dip),
		    (rv == DDI_PROBE_PARTIAL) ? " yet" : ""));
		rv = DDI_FAILURE;
		break;

	default:
#ifdef	DEBUG
		cmn_err(CE_WARN, "probe_node: %s%d: illegal probe(9E) value",
		    ddi_driver_name(dip), ddi_get_instance(dip));
#endif	/* DEBUG */
		rv = DDI_FAILURE;
		break;
	}
	return (rv);
}

/*
 * Unprobe a node. Simply reset the node state.
 * Per-driver list must be held busy while calling this function.
 */
static int
unprobe_node(dev_info_t *dip)
{
	ASSERT(i_ddi_node_state(dip) == DS_PROBED);

	/*
	 * Don't check for references here or else a ref-counted
	 * dip cannot be downgraded by the framework.
	 */

	NDI_CONFIG_DEBUG((CE_CONT, "unprobe_node: 0x%p(name = %s)\n",
	    (void *)dip, ddi_node_name(dip)));
	return (DDI_SUCCESS);
}

/*
 * Attach devinfo node.
 * Per-driver list must be held busy.
 */
static int
attach_node(dev_info_t *dip)
{
	int rv;

	ASSERT(DEVI_BUSY_OWNED(ddi_get_parent(dip)));
	ASSERT(i_ddi_node_state(dip) == DS_PROBED);

	NDI_CONFIG_DEBUG((CE_CONT, "attach_node: 0x%p(%s%d)\n",
	    (void *)dip, ddi_driver_name(dip), ddi_get_instance(dip)));

	/*
	 * Tell mpxio framework that a node is about to online.
	 */
	if ((rv = mdi_devi_online(dip, 0)) != NDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* no recursive attachment */
	ASSERT(DEVI(dip)->devi_ops == NULL);

	/*
	 * Hold driver the node is bound to.
	 */
	DEVI(dip)->devi_ops = ndi_hold_driver(dip);
	if (DEVI(dip)->devi_ops == NULL) {
		/*
		 * We were able to load driver for probing, so we should
		 * not get here unless something really bad happened.
		 */
		cmn_err(CE_WARN, "attach_node: no driver for major %d",
		    DEVI(dip)->devi_major);
		return (DDI_FAILURE);
	}

	if (NEXUS_DRV(DEVI(dip)->devi_ops))
		DEVI(dip)->devi_taskq = ddi_taskq_create(dip,
		    "nexus_enum_tq", 1,
		    TASKQ_DEFAULTPRI, 0);

	mutex_enter(&(DEVI(dip)->devi_lock));
	DEVI_SET_ATTACHING(dip);
	DEVI_SET_NEED_RESET(dip);
	mutex_exit(&(DEVI(dip)->devi_lock));

	rv = devi_attach(dip, DDI_ATTACH);

	mutex_enter(&(DEVI(dip)->devi_lock));
	DEVI_CLR_ATTACHING(dip);

	if (rv != DDI_SUCCESS) {
		DEVI_CLR_NEED_RESET(dip);
		mutex_exit(&DEVI(dip)->devi_lock);

		/*
		 * Cleanup dacf reservations
		 */
		mutex_enter(&dacf_lock);
		dacf_clr_rsrvs(dip, DACF_OPID_POSTATTACH);
		dacf_clr_rsrvs(dip, DACF_OPID_PREDETACH);
		mutex_exit(&dacf_lock);
		if (DEVI(dip)->devi_taskq)
			ddi_taskq_destroy(DEVI(dip)->devi_taskq);
		ddi_remove_minor_node(dip, NULL);

		/* release the driver if attach failed */
		ndi_rele_driver(dip);
		DEVI(dip)->devi_ops = NULL;
		NDI_CONFIG_DEBUG((CE_CONT, "attach_node: 0x%p(%s%d) failed\n",
		    (void *)dip, ddi_driver_name(dip), ddi_get_instance(dip)));
		return (DDI_FAILURE);
	} else
		mutex_exit(&DEVI(dip)->devi_lock);

	/* successful attach, return with driver held */

	return (DDI_SUCCESS);
}

/*
 * Detach devinfo node.
 * Per-driver list must be held busy.
 */
static int
detach_node(dev_info_t *dip, uint_t flag)
{
	struct devnames	*dnp;
	int		rv;

	ASSERT(DEVI_BUSY_OWNED(ddi_get_parent(dip)));
	ASSERT(i_ddi_node_state(dip) == DS_ATTACHED);

	/* check references */
	if (DEVI(dip)->devi_ref)
		return (DDI_FAILURE);

	NDI_CONFIG_DEBUG((CE_CONT, "detach_node: 0x%p(%s%d)\n",
	    (void *)dip, ddi_driver_name(dip), ddi_get_instance(dip)));

	/*
	 * NOTE: If we are processing a pHCI node then the calling code
	 * must detect this and ndi_devi_enter() in (vHCI, parent(pHCI))
	 * order unless pHCI and vHCI are siblings.  Code paths leading
	 * here that must ensure this ordering include:
	 * unconfig_immediate_children(), devi_unconfig_one(),
	 * ndi_devi_unconfig_one(), ndi_devi_offline().
	 */
	ASSERT(!MDI_PHCI(dip) ||
	    (ddi_get_parent(mdi_devi_get_vdip(dip)) == ddi_get_parent(dip)) ||
	    DEVI_BUSY_OWNED(mdi_devi_get_vdip(dip)));

	/* Offline the device node with the mpxio framework. */
	if (mdi_devi_offline(dip, flag) != NDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* drain the taskq */
	if (DEVI(dip)->devi_taskq)
		ddi_taskq_wait(DEVI(dip)->devi_taskq);

	rv = devi_detach(dip, DDI_DETACH);

	if (rv != DDI_SUCCESS) {
		NDI_CONFIG_DEBUG((CE_CONT,
		    "detach_node: 0x%p(%s%d) failed\n",
		    (void *)dip, ddi_driver_name(dip), ddi_get_instance(dip)));
		return (DDI_FAILURE);
	}

	mutex_enter(&(DEVI(dip)->devi_lock));
	DEVI_CLR_NEED_RESET(dip);
	mutex_exit(&(DEVI(dip)->devi_lock));

#if defined(__amd64) && !defined(__xpv)
	/*
	 * Close any iommulib mediated linkage to an IOMMU
	 */
	if (IOMMU_USED(dip))
		iommulib_nex_close(dip);
#endif

	/* destroy the taskq */
	if (DEVI(dip)->devi_taskq) {
		ddi_taskq_destroy(DEVI(dip)->devi_taskq);
		DEVI(dip)->devi_taskq = NULL;
	}

	/* Cleanup dacf reservations */
	mutex_enter(&dacf_lock);
	dacf_clr_rsrvs(dip, DACF_OPID_POSTATTACH);
	dacf_clr_rsrvs(dip, DACF_OPID_PREDETACH);
	mutex_exit(&dacf_lock);

	/* remove any additional flavors that were added */
	if (DEVI(dip)->devi_flavorv_n > 1 && DEVI(dip)->devi_flavorv != NULL) {
		kmem_free(DEVI(dip)->devi_flavorv,
		    (DEVI(dip)->devi_flavorv_n - 1) * sizeof (void *));
		DEVI(dip)->devi_flavorv = NULL;
	}

	/* Remove properties and minor nodes in case driver forgots */
	ddi_remove_minor_node(dip, NULL);
	ddi_prop_remove_all(dip);

	/* a detached node can't have attached or .conf children */
	mutex_enter(&DEVI(dip)->devi_lock);
	DEVI(dip)->devi_flags &= ~(DEVI_MADE_CHILDREN|DEVI_ATTACHED_CHILDREN);
	mutex_exit(&DEVI(dip)->devi_lock);

	/*
	 * If the instance has successfully detached in detach_driver() context,
	 * clear DN_DRIVER_HELD for correct ddi_hold_installed_driver()
	 * behavior. Consumers like qassociate() depend on this (via clnopen()).
	 */
	if (flag & NDI_DETACH_DRIVER) {
		dnp = &(devnamesp[DEVI(dip)->devi_major]);
		LOCK_DEV_OPS(&dnp->dn_lock);
		dnp->dn_flags &= ~DN_DRIVER_HELD;
		UNLOCK_DEV_OPS(&dnp->dn_lock);
	}

	/* successful detach, release the driver */
	ndi_rele_driver(dip);
	DEVI(dip)->devi_ops = NULL;
	return (DDI_SUCCESS);
}

/*
 * Run dacf post_attach routines
 */
static int
postattach_node(dev_info_t *dip)
{
	int rval;

	/*
	 * For hotplug busses like USB, it's possible that devices
	 * are removed but dip is still around. We don't want to
	 * run dacf routines as part of detach failure recovery.
	 *
	 * Pretend success until we figure out how to prevent
	 * access to such devinfo nodes.
	 */
	if (DEVI_IS_DEVICE_REMOVED(dip))
		return (DDI_SUCCESS);

	/*
	 * if dacf_postattach failed, report it to the framework
	 * so that it can be retried later at the open time.
	 */
	mutex_enter(&dacf_lock);
	rval = dacfc_postattach(dip);
	mutex_exit(&dacf_lock);

	/*
	 * Plumbing during postattach may fail because of the
	 * underlying device is not ready. This will fail ndi_devi_config()
	 * in dv_filldir() and a warning message is issued. The message
	 * from here will explain what happened
	 */
	if (rval != DACF_SUCCESS) {
		cmn_err(CE_WARN, "Postattach failed for %s%d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Run dacf pre-detach routines
 */
static int
predetach_node(dev_info_t *dip, uint_t flag)
{
	int ret;

	/*
	 * Don't auto-detach if DDI_FORCEATTACH or DDI_NO_AUTODETACH
	 * properties are set.
	 */
	if (flag & NDI_AUTODETACH) {
		struct devnames *dnp;
		int pflag = DDI_PROP_NOTPROM | DDI_PROP_DONTPASS;

		if ((ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    pflag, DDI_FORCEATTACH, 0) == 1) ||
		    (ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    pflag, DDI_NO_AUTODETACH, 0) == 1))
			return (DDI_FAILURE);

		/* check for driver global version of DDI_NO_AUTODETACH */
		dnp = &devnamesp[DEVI(dip)->devi_major];
		LOCK_DEV_OPS(&dnp->dn_lock);
		if (dnp->dn_flags & DN_NO_AUTODETACH) {
			UNLOCK_DEV_OPS(&dnp->dn_lock);
			return (DDI_FAILURE);
		}
		UNLOCK_DEV_OPS(&dnp->dn_lock);
	}

	mutex_enter(&dacf_lock);
	ret = dacfc_predetach(dip);
	mutex_exit(&dacf_lock);

	return (ret);
}

/*
 * Wrapper for making multiple state transitions
 */

/*
 * i_ndi_config_node: upgrade dev_info node into a specified state.
 * It is a bit tricky because the locking protocol changes before and
 * after a node is bound to a driver. All locks are held external to
 * this function.
 */
int
i_ndi_config_node(dev_info_t *dip, ddi_node_state_t state, uint_t flag)
{
	_NOTE(ARGUNUSED(flag))
	int rv = DDI_SUCCESS;

	ASSERT(DEVI_BUSY_OWNED(ddi_get_parent(dip)));

	while ((i_ddi_node_state(dip) < state) && (rv == DDI_SUCCESS)) {

		/* don't allow any more changes to the device tree */
		if (devinfo_freeze) {
			rv = DDI_FAILURE;
			break;
		}

		switch (i_ddi_node_state(dip)) {
		case DS_PROTO:
			/*
			 * only caller can reference this node, no external
			 * locking needed.
			 */
			link_node(dip);
			translate_devid((dev_info_t *)dip);
			i_ddi_set_node_state(dip, DS_LINKED);
			break;
		case DS_LINKED:
			/*
			 * Three code path may attempt to bind a node:
			 * - boot code
			 * - add_drv
			 * - hotplug thread
			 * Boot code is single threaded, add_drv synchronize
			 * on a userland lock, and hotplug synchronize on
			 * hotplug_lk. There could be a race between add_drv
			 * and hotplug thread. We'll live with this until the
			 * conversion to top-down loading.
			 */
			if ((rv = bind_node(dip)) == DDI_SUCCESS)
				i_ddi_set_node_state(dip, DS_BOUND);

			break;
		case DS_BOUND:
			/*
			 * The following transitions synchronizes on the
			 * per-driver busy changing flag, since we already
			 * have a driver.
			 */
			if ((rv = init_node(dip)) == DDI_SUCCESS)
				i_ddi_set_node_state(dip, DS_INITIALIZED);
			break;
		case DS_INITIALIZED:
			if ((rv = probe_node(dip)) == DDI_SUCCESS)
				i_ddi_set_node_state(dip, DS_PROBED);
			break;
		case DS_PROBED:
			/*
			 * If node is retired and persistent, then prevent
			 * attach. We can't do this for non-persistent nodes
			 * as we would lose evidence that the node existed.
			 */
			if (i_ddi_check_retire(dip) == 1 &&
			    ndi_dev_is_persistent_node(dip) &&
			    retire_prevents_attach == 1) {
				rv = DDI_FAILURE;
				break;
			}
			atomic_add_long(&devinfo_attach_detach, 1);
			if ((rv = attach_node(dip)) == DDI_SUCCESS)
				i_ddi_set_node_state(dip, DS_ATTACHED);
			atomic_add_long(&devinfo_attach_detach, -1);
			break;
		case DS_ATTACHED:
			if ((rv = postattach_node(dip)) == DDI_SUCCESS)
				i_ddi_set_node_state(dip, DS_READY);
			break;
		case DS_READY:
			break;
		default:
			/* should never reach here */
			ASSERT("unknown devinfo state");
		}
	}

	if (ddidebug & DDI_AUDIT)
		da_log_enter(dip);
	return (rv);
}

/*
 * i_ndi_unconfig_node: downgrade dev_info node into a specified state.
 */
int
i_ndi_unconfig_node(dev_info_t *dip, ddi_node_state_t state, uint_t flag)
{
	int	rv = DDI_SUCCESS;

	ASSERT(DEVI_BUSY_OWNED(ddi_get_parent(dip)));

	while ((i_ddi_node_state(dip) > state) && (rv == DDI_SUCCESS)) {

		/* don't allow any more changes to the device tree */
		if (devinfo_freeze) {
			rv = DDI_FAILURE;
			break;
		}

		switch (i_ddi_node_state(dip)) {
		case DS_PROTO:
			break;
		case DS_LINKED:
			/*
			 * Persistent nodes are only removed by hotplug code
			 * .conf nodes synchronizes on per-driver list.
			 */
			if ((rv = unlink_node(dip)) == DDI_SUCCESS)
				i_ddi_set_node_state(dip, DS_PROTO);
			break;
		case DS_BOUND:
			/*
			 * The following transitions synchronizes on the
			 * per-driver busy changing flag, since we already
			 * have a driver.
			 */
			if ((rv = unbind_node(dip)) == DDI_SUCCESS)
				i_ddi_set_node_state(dip, DS_LINKED);
			break;
		case DS_INITIALIZED:
			if ((rv = uninit_node(dip)) == DDI_SUCCESS)
				i_ddi_set_node_state(dip, DS_BOUND);
			break;
		case DS_PROBED:
			if ((rv = unprobe_node(dip)) == DDI_SUCCESS)
				i_ddi_set_node_state(dip, DS_INITIALIZED);
			break;
		case DS_ATTACHED:
			atomic_add_long(&devinfo_attach_detach, 1);

			mutex_enter(&(DEVI(dip)->devi_lock));
			DEVI_SET_DETACHING(dip);
			mutex_exit(&(DEVI(dip)->devi_lock));

			membar_enter();	/* ensure visibility for hold_devi */

			if ((rv = detach_node(dip, flag)) == DDI_SUCCESS)
				i_ddi_set_node_state(dip, DS_PROBED);

			mutex_enter(&(DEVI(dip)->devi_lock));
			DEVI_CLR_DETACHING(dip);
			mutex_exit(&(DEVI(dip)->devi_lock));

			atomic_add_long(&devinfo_attach_detach, -1);
			break;
		case DS_READY:
			if ((rv = predetach_node(dip, flag)) == DDI_SUCCESS)
				i_ddi_set_node_state(dip, DS_ATTACHED);
			break;
		default:
			ASSERT("unknown devinfo state");
		}
	}
	da_log_enter(dip);
	return (rv);
}

/*
 * ddi_initchild: transform node to DS_INITIALIZED state
 */
int
ddi_initchild(dev_info_t *parent, dev_info_t *proto)
{
	int ret, circ;

	ndi_devi_enter(parent, &circ);
	ret = i_ndi_config_node(proto, DS_INITIALIZED, 0);
	ndi_devi_exit(parent, circ);

	return (ret);
}

/*
 * ddi_uninitchild: transform node down to DS_BOUND state
 */
int
ddi_uninitchild(dev_info_t *dip)
{
	int ret, circ;
	dev_info_t *parent = ddi_get_parent(dip);
	ASSERT(parent);

	ndi_devi_enter(parent, &circ);
	ret = i_ndi_unconfig_node(dip, DS_BOUND, 0);
	ndi_devi_exit(parent, circ);

	return (ret);
}

/*
 * i_ddi_attachchild: transform node to DS_READY/i_ddi_devi_attached() state
 */
static int
i_ddi_attachchild(dev_info_t *dip)
{
	dev_info_t	*parent = ddi_get_parent(dip);
	int		ret;

	ASSERT(parent && DEVI_BUSY_OWNED(parent));

	if ((i_ddi_node_state(dip) < DS_BOUND) || DEVI_IS_DEVICE_OFFLINE(dip))
		return (DDI_FAILURE);

	ret = i_ndi_config_node(dip, DS_READY, 0);
	if (ret == NDI_SUCCESS) {
		ret = DDI_SUCCESS;
	} else {
		/*
		 * Take it down to DS_INITIALIZED so pm_pre_probe is run
		 * on the next attach
		 */
		(void) i_ndi_unconfig_node(dip, DS_INITIALIZED, 0);
		ret = DDI_FAILURE;
	}

	return (ret);
}

/*
 * i_ddi_detachchild: transform node down to DS_PROBED state
 *	If it fails, put it back to DS_READY state.
 * NOTE: A node that fails detach may be at DS_ATTACHED instead
 * of DS_READY for a small amount of time - this is the source of
 * transient DS_READY->DS_ATTACHED->DS_READY state changes.
 */
static int
i_ddi_detachchild(dev_info_t *dip, uint_t flags)
{
	dev_info_t	*parent = ddi_get_parent(dip);
	int		ret;

	ASSERT(parent && DEVI_BUSY_OWNED(parent));

	ret = i_ndi_unconfig_node(dip, DS_PROBED, flags);
	if (ret != DDI_SUCCESS)
		(void) i_ndi_config_node(dip, DS_READY, 0);
	else
		/* allow pm_pre_probe to reestablish pm state */
		(void) i_ndi_unconfig_node(dip, DS_INITIALIZED, 0);
	return (ret);
}

/*
 * Add a child and bind to driver
 */
dev_info_t *
ddi_add_child(dev_info_t *pdip, char *name, uint_t nodeid, uint_t unit)
{
	int circ;
	dev_info_t *dip;

	/* allocate a new node */
	dip = i_ddi_alloc_node(pdip, name, nodeid, (int)unit, NULL, KM_SLEEP);

	ndi_devi_enter(pdip, &circ);
	(void) i_ndi_config_node(dip, DS_BOUND, 0);
	ndi_devi_exit(pdip, circ);
	return (dip);
}

/*
 * ddi_remove_child: remove the dip. The parent must be attached and held
 */
int
ddi_remove_child(dev_info_t *dip, int dummy)
{
	_NOTE(ARGUNUSED(dummy))
	int circ, ret;
	dev_info_t *parent = ddi_get_parent(dip);
	ASSERT(parent);

	ndi_devi_enter(parent, &circ);

	/*
	 * If we still have children, for example SID nodes marked
	 * as persistent but not attached, attempt to remove them.
	 */
	if (DEVI(dip)->devi_child) {
		ret = ndi_devi_unconfig(dip, NDI_DEVI_REMOVE);
		if (ret != NDI_SUCCESS) {
			ndi_devi_exit(parent, circ);
			return (DDI_FAILURE);
		}
		ASSERT(DEVI(dip)->devi_child == NULL);
	}

	ret = i_ndi_unconfig_node(dip, DS_PROTO, 0);
	ndi_devi_exit(parent, circ);

	if (ret != DDI_SUCCESS)
		return (ret);

	ASSERT(i_ddi_node_state(dip) == DS_PROTO);
	i_ddi_free_node(dip);
	return (DDI_SUCCESS);
}

/*
 * NDI wrappers for ref counting, node allocation, and transitions
 */

/*
 * Hold/release the devinfo node itself.
 * Caller is assumed to prevent the devi from detaching during this call
 */
void
ndi_hold_devi(dev_info_t *dip)
{
	mutex_enter(&DEVI(dip)->devi_lock);
	ASSERT(DEVI(dip)->devi_ref >= 0);
	DEVI(dip)->devi_ref++;
	membar_enter();			/* make sure stores are flushed */
	mutex_exit(&DEVI(dip)->devi_lock);
}

void
ndi_rele_devi(dev_info_t *dip)
{
	ASSERT(DEVI(dip)->devi_ref > 0);

	mutex_enter(&DEVI(dip)->devi_lock);
	DEVI(dip)->devi_ref--;
	membar_enter();			/* make sure stores are flushed */
	mutex_exit(&DEVI(dip)->devi_lock);
}

int
e_ddi_devi_holdcnt(dev_info_t *dip)
{
	return (DEVI(dip)->devi_ref);
}

/*
 * Hold/release the driver the devinfo node is bound to.
 */
struct dev_ops *
ndi_hold_driver(dev_info_t *dip)
{
	if (i_ddi_node_state(dip) < DS_BOUND)
		return (NULL);

	ASSERT(DEVI(dip)->devi_major != -1);
	return (mod_hold_dev_by_major(DEVI(dip)->devi_major));
}

void
ndi_rele_driver(dev_info_t *dip)
{
	ASSERT(i_ddi_node_state(dip) >= DS_BOUND);
	mod_rele_dev_by_major(DEVI(dip)->devi_major);
}

/*
 * Single thread entry into devinfo node for modifying its children (devinfo,
 * pathinfo, and minor). To verify in ASSERTS use DEVI_BUSY_OWNED macro.
 */
void
ndi_devi_enter(dev_info_t *dip, int *circular)
{
	struct dev_info *devi = DEVI(dip);
	ASSERT(dip != NULL);

	/* for vHCI, enforce (vHCI, pHCI) ndi_deve_enter() order */
	ASSERT(!MDI_VHCI(dip) || (mdi_devi_pdip_entered(dip) == 0) ||
	    DEVI_BUSY_OWNED(dip));

	mutex_enter(&devi->devi_lock);
	if (devi->devi_busy_thread == curthread) {
		devi->devi_circular++;
	} else {
		while (DEVI_BUSY_CHANGING(devi) && !panicstr)
			cv_wait(&(devi->devi_cv), &(devi->devi_lock));
		if (panicstr) {
			mutex_exit(&devi->devi_lock);
			return;
		}
		devi->devi_flags |= DEVI_BUSY;
		devi->devi_busy_thread = curthread;
	}
	*circular = devi->devi_circular;
	mutex_exit(&devi->devi_lock);
}

/*
 * Release ndi_devi_enter or successful ndi_devi_tryenter.
 */
void
ndi_devi_exit(dev_info_t *dip, int circular)
{
	struct dev_info	*devi = DEVI(dip);
	struct dev_info	*vdevi;
	ASSERT(dip != NULL);

	if (panicstr)
		return;

	mutex_enter(&(devi->devi_lock));
	if (circular != 0) {
		devi->devi_circular--;
	} else {
		devi->devi_flags &= ~DEVI_BUSY;
		ASSERT(devi->devi_busy_thread == curthread);
		devi->devi_busy_thread = NULL;
		cv_broadcast(&(devi->devi_cv));
	}
	mutex_exit(&(devi->devi_lock));

	/*
	 * For pHCI exit we issue a broadcast to vHCI for ndi_devi_config_one()
	 * doing cv_wait on vHCI.
	 */
	if (MDI_PHCI(dip)) {
		vdevi = DEVI(mdi_devi_get_vdip(dip));
		if (vdevi) {
			mutex_enter(&(vdevi->devi_lock));
			if (vdevi->devi_flags & DEVI_PHCI_SIGNALS_VHCI) {
				vdevi->devi_flags &= ~DEVI_PHCI_SIGNALS_VHCI;
				cv_broadcast(&(vdevi->devi_cv));
			}
			mutex_exit(&(vdevi->devi_lock));
		}
	}
}

/*
 * Release ndi_devi_enter and wait for possibility of new children, avoiding
 * possibility of missing broadcast before getting to cv_timedwait().
 */
static void
ndi_devi_exit_and_wait(dev_info_t *dip, int circular, clock_t end_time)
{
	struct dev_info	*devi = DEVI(dip);
	ASSERT(dip != NULL);

	if (panicstr)
		return;

	/*
	 * We are called to wait for of a new child, and new child can
	 * only be added if circular is zero.
	 */
	ASSERT(circular == 0);

	/* like ndi_devi_exit with circular of zero */
	mutex_enter(&(devi->devi_lock));
	devi->devi_flags &= ~DEVI_BUSY;
	ASSERT(devi->devi_busy_thread == curthread);
	devi->devi_busy_thread = NULL;
	cv_broadcast(&(devi->devi_cv));

	/* now wait for new children while still holding devi_lock */
	(void) cv_timedwait(&devi->devi_cv, &(devi->devi_lock), end_time);
	mutex_exit(&(devi->devi_lock));
}

/*
 * Attempt to single thread entry into devinfo node for modifying its children.
 */
int
ndi_devi_tryenter(dev_info_t *dip, int *circular)
{
	int rval = 1;		   /* assume we enter */
	struct dev_info *devi = DEVI(dip);
	ASSERT(dip != NULL);

	mutex_enter(&devi->devi_lock);
	if (devi->devi_busy_thread == (void *)curthread) {
		devi->devi_circular++;
	} else {
		if (!DEVI_BUSY_CHANGING(devi)) {
			devi->devi_flags |= DEVI_BUSY;
			devi->devi_busy_thread = (void *)curthread;
		} else {
			rval = 0;	/* devi is busy */
		}
	}
	*circular = devi->devi_circular;
	mutex_exit(&devi->devi_lock);
	return (rval);
}

/*
 * Allocate and initialize a new dev_info structure.
 *
 * This routine may be called at interrupt time by a nexus in
 * response to a hotplug event, therefore memory allocations are
 * not allowed to sleep.
 */
int
ndi_devi_alloc(dev_info_t *parent, char *node_name, pnode_t nodeid,
    dev_info_t **ret_dip)
{
	ASSERT(node_name != NULL);
	ASSERT(ret_dip != NULL);

	*ret_dip = i_ddi_alloc_node(parent, node_name, nodeid, -1, NULL,
	    KM_NOSLEEP);
	if (*ret_dip == NULL) {
		return (NDI_NOMEM);
	}

	return (NDI_SUCCESS);
}

/*
 * Allocate and initialize a new dev_info structure
 * This routine may sleep and should not be called at interrupt time
 */
void
ndi_devi_alloc_sleep(dev_info_t *parent, char *node_name, pnode_t nodeid,
    dev_info_t **ret_dip)
{
	ASSERT(node_name != NULL);
	ASSERT(ret_dip != NULL);

	*ret_dip = i_ddi_alloc_node(parent, node_name, nodeid, -1, NULL,
	    KM_SLEEP);
	ASSERT(*ret_dip);
}

/*
 * Remove an initialized (but not yet attached) dev_info
 * node from it's parent.
 */
int
ndi_devi_free(dev_info_t *dip)
{
	ASSERT(dip != NULL);

	if (i_ddi_node_state(dip) >= DS_INITIALIZED)
		return (DDI_FAILURE);

	NDI_CONFIG_DEBUG((CE_CONT, "ndi_devi_free: %s%d (%p)\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), (void *)dip));

	(void) ddi_remove_child(dip, 0);

	return (NDI_SUCCESS);
}

/*
 * ndi_devi_bind_driver() binds a driver to a given device. If it fails
 * to bind the driver, it returns an appropriate error back. Some drivers
 * may want to know if the actually failed to bind.
 */
int
ndi_devi_bind_driver(dev_info_t *dip, uint_t flags)
{
	int ret = NDI_FAILURE;
	int circ;
	dev_info_t *pdip = ddi_get_parent(dip);
	ASSERT(pdip);

	NDI_CONFIG_DEBUG((CE_CONT,
	    "ndi_devi_bind_driver: %s%d (%p) flags: %x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), (void *)dip, flags));

	ndi_devi_enter(pdip, &circ);
	if (i_ndi_config_node(dip, DS_BOUND, flags) == DDI_SUCCESS)
		ret = NDI_SUCCESS;
	ndi_devi_exit(pdip, circ);

	return (ret);
}

/*
 * ndi_devi_unbind_driver: unbind the dip
 */
static int
ndi_devi_unbind_driver(dev_info_t *dip)
{
	ASSERT(DEVI_BUSY_OWNED(ddi_get_parent(dip)));

	return (i_ndi_unconfig_node(dip, DS_LINKED, 0));
}

/*
 * Misc. help routines called by framework only
 */

/*
 * Get the state of node
 */
ddi_node_state_t
i_ddi_node_state(dev_info_t *dip)
{
	return (DEVI(dip)->devi_node_state);
}

/*
 * Set the state of node
 */
void
i_ddi_set_node_state(dev_info_t *dip, ddi_node_state_t state)
{
	DEVI(dip)->devi_node_state = state;
	membar_enter();			/* make sure stores are flushed */
}

/*
 * Determine if node is attached. The implementation accommodates transient
 * DS_READY->DS_ATTACHED->DS_READY state changes.  Outside this file, this
 * function should be instead of i_ddi_node_state() DS_ATTACHED/DS_READY
 * state checks.
 */
int
i_ddi_devi_attached(dev_info_t *dip)
{
	return (DEVI(dip)->devi_node_state >= DS_ATTACHED);
}

/*
 * Common function for finding a node in a sibling list given name and addr.
 *
 * By default, name is matched with devi_node_name. The following
 * alternative match strategies are supported:
 *
 *	FIND_NODE_BY_NODENAME: Match on node name - typical use.
 *
 *	FIND_NODE_BY_DRIVER: A match on driver name bound to node is conducted.
 *		This support is used for support of OBP generic names and
 *		for the conversion from driver names to generic names. When
 *		more consistency in the generic name environment is achieved
 *		(and not needed for upgrade) this support can be removed.
 *
 *	FIND_NODE_BY_ADDR: Match on just the addr.
 *		This support is only used/needed during boot to match
 *		a node bound via a path-based driver alias.
 *
 * If a child is not named (dev_addr == NULL), there are three
 * possible actions:
 *
 *	(1) skip it
 *	(2) FIND_ADDR_BY_INIT: bring child to DS_INITIALIZED state
 *	(3) FIND_ADDR_BY_CALLBACK: use a caller-supplied callback function
 */
#define	FIND_NODE_BY_NODENAME	0x01
#define	FIND_NODE_BY_DRIVER	0x02
#define	FIND_NODE_BY_ADDR	0x04
#define	FIND_ADDR_BY_INIT	0x10
#define	FIND_ADDR_BY_CALLBACK	0x20

static dev_info_t *
find_sibling(dev_info_t *head, char *cname, char *caddr, uint_t flag,
    int (*callback)(dev_info_t *, char *, int))
{
	dev_info_t	*dip;
	char		*addr, *buf;
	major_t		major;
	uint_t		by;

	/* only one way to find a node */
	by = flag &
	    (FIND_NODE_BY_DRIVER | FIND_NODE_BY_NODENAME | FIND_NODE_BY_ADDR);
	ASSERT(by && BIT_ONLYONESET(by));

	/* only one way to name a node */
	ASSERT(((flag & FIND_ADDR_BY_INIT) == 0) ||
	    ((flag & FIND_ADDR_BY_CALLBACK) == 0));

	if (by == FIND_NODE_BY_DRIVER) {
		major = ddi_name_to_major(cname);
		if (major == DDI_MAJOR_T_NONE)
			return (NULL);
	}

	/* preallocate buffer of naming node by callback */
	if (flag & FIND_ADDR_BY_CALLBACK)
		buf = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	/*
	 * Walk the child list to find a match
	 */
	if (head == NULL)
		return (NULL);
	ASSERT(DEVI_BUSY_OWNED(ddi_get_parent(head)));
	for (dip = head; dip; dip = ddi_get_next_sibling(dip)) {
		if (by == FIND_NODE_BY_NODENAME) {
			/* match node name */
			if (strcmp(cname, DEVI(dip)->devi_node_name) != 0)
				continue;
		} else if (by == FIND_NODE_BY_DRIVER) {
			/* match driver major */
			if (DEVI(dip)->devi_major != major)
				continue;
		}

		if ((addr = DEVI(dip)->devi_addr) == NULL) {
			/* name the child based on the flag */
			if (flag & FIND_ADDR_BY_INIT) {
				if (ddi_initchild(ddi_get_parent(dip), dip)
				    != DDI_SUCCESS)
					continue;
				addr = DEVI(dip)->devi_addr;
			} else if (flag & FIND_ADDR_BY_CALLBACK) {
				if ((callback == NULL) || (callback(
				    dip, buf, MAXNAMELEN) != DDI_SUCCESS))
					continue;
				addr = buf;
			} else {
				continue;	/* skip */
			}
		}

		/* match addr */
		ASSERT(addr != NULL);
		if (strcmp(caddr, addr) == 0)
			break;	/* node found */

	}
	if (flag & FIND_ADDR_BY_CALLBACK)
		kmem_free(buf, MAXNAMELEN);
	return (dip);
}

/*
 * Find child of pdip with name: cname@caddr
 * Called by init_node() to look for duplicate nodes
 */
static dev_info_t *
find_duplicate_child(dev_info_t *pdip, dev_info_t *dip)
{
	dev_info_t *dup;
	char *cname = DEVI(dip)->devi_node_name;
	char *caddr = DEVI(dip)->devi_addr;

	/* search nodes before dip */
	dup = find_sibling(ddi_get_child(pdip), cname, caddr,
	    FIND_NODE_BY_NODENAME, NULL);
	if (dup != dip)
		return (dup);

	/*
	 * search nodes after dip; normally this is not needed,
	 */
	return (find_sibling(ddi_get_next_sibling(dip), cname, caddr,
	    FIND_NODE_BY_NODENAME, NULL));
}

/*
 * Find a child of a given name and address, using a callback to name
 * unnamed children. cname is the binding name.
 */
dev_info_t *
ndi_devi_findchild_by_callback(dev_info_t *pdip, char *dname, char *ua,
    int (*make_ua)(dev_info_t *, char *, int))
{
	int	by = FIND_ADDR_BY_CALLBACK;

	ASSERT(DEVI_BUSY_OWNED(pdip));
	by |= dname ? FIND_NODE_BY_DRIVER : FIND_NODE_BY_ADDR;
	return (find_sibling(ddi_get_child(pdip), dname, ua, by, make_ua));
}

/*
 * Find a child of a given name and address, invoking initchild to name
 * unnamed children. cname is the node name.
 */
static dev_info_t *
find_child_by_name(dev_info_t *pdip, char *cname, char *caddr)
{
	dev_info_t	*dip;

	/* attempt search without changing state of preceding siblings */
	dip = find_sibling(ddi_get_child(pdip), cname, caddr,
	    FIND_NODE_BY_NODENAME, NULL);
	if (dip)
		return (dip);

	return (find_sibling(ddi_get_child(pdip), cname, caddr,
	    FIND_NODE_BY_NODENAME|FIND_ADDR_BY_INIT, NULL));
}

/*
 * Find a child of a given name and address, invoking initchild to name
 * unnamed children. cname is the node name.
 */
static dev_info_t *
find_child_by_driver(dev_info_t *pdip, char *cname, char *caddr)
{
	dev_info_t	*dip;

	/* attempt search without changing state of preceding siblings */
	dip = find_sibling(ddi_get_child(pdip), cname, caddr,
	    FIND_NODE_BY_DRIVER, NULL);
	if (dip)
		return (dip);

	return (find_sibling(ddi_get_child(pdip), cname, caddr,
	    FIND_NODE_BY_DRIVER|FIND_ADDR_BY_INIT, NULL));
}

/*
 * Find a child of a given address, invoking initchild to name
 * unnamed children. cname is the node name.
 *
 * NOTE: This function is only used during boot. One would hope that
 * unique sibling unit-addresses on hardware branches of the tree would
 * be a requirement to avoid two drivers trying to control the same
 * piece of hardware. Unfortunately there are some cases where this
 * situation exists (/ssm@0,0/pci@1c,700000 /ssm@0,0/sghsc@1c,700000).
 * Until unit-address uniqueness of siblings is guaranteed, use of this
 * interface for purposes other than boot should be avoided.
 */
static dev_info_t *
find_child_by_addr(dev_info_t *pdip, char *caddr)
{
	dev_info_t	*dip;

	/* return NULL if called without a unit-address */
	if ((caddr == NULL) || (*caddr == '\0'))
		return (NULL);

	/* attempt search without changing state of preceding siblings */
	dip = find_sibling(ddi_get_child(pdip), NULL, caddr,
	    FIND_NODE_BY_ADDR, NULL);
	if (dip)
		return (dip);

	return (find_sibling(ddi_get_child(pdip), NULL, caddr,
	    FIND_NODE_BY_ADDR|FIND_ADDR_BY_INIT, NULL));
}

/*
 * Deleting a property list. Take care, since some property structures
 * may not be fully built.
 */
void
i_ddi_prop_list_delete(ddi_prop_t *prop)
{
	while (prop) {
		ddi_prop_t *next = prop->prop_next;
		if (prop->prop_name)
			kmem_free(prop->prop_name, strlen(prop->prop_name) + 1);
		if ((prop->prop_len != 0) && prop->prop_val)
			kmem_free(prop->prop_val, prop->prop_len);
		kmem_free(prop, sizeof (struct ddi_prop));
		prop = next;
	}
}

/*
 * Duplicate property list
 */
ddi_prop_t *
i_ddi_prop_list_dup(ddi_prop_t *prop, uint_t flag)
{
	ddi_prop_t *result, *prev, *copy;

	if (prop == NULL)
		return (NULL);

	result = prev = NULL;
	for (; prop != NULL; prop = prop->prop_next) {
		ASSERT(prop->prop_name != NULL);
		copy = kmem_zalloc(sizeof (struct ddi_prop), flag);
		if (copy == NULL)
			goto fail;

		copy->prop_dev = prop->prop_dev;
		copy->prop_flags = prop->prop_flags;
		copy->prop_name = i_ddi_strdup(prop->prop_name, flag);
		if (copy->prop_name == NULL)
			goto fail;

		if ((copy->prop_len = prop->prop_len) != 0) {
			copy->prop_val = kmem_zalloc(prop->prop_len, flag);
			if (copy->prop_val == NULL)
				goto fail;

			bcopy(prop->prop_val, copy->prop_val, prop->prop_len);
		}

		if (prev == NULL)
			result = prev = copy;
		else
			prev->prop_next = copy;
		prev = copy;
	}
	return (result);

fail:
	i_ddi_prop_list_delete(result);
	return (NULL);
}

/*
 * Create a reference property list, currently used only for
 * driver global properties. Created with ref count of 1.
 */
ddi_prop_list_t *
i_ddi_prop_list_create(ddi_prop_t *props)
{
	ddi_prop_list_t *list = kmem_alloc(sizeof (*list), KM_SLEEP);
	list->prop_list = props;
	list->prop_ref = 1;
	return (list);
}

/*
 * Increment/decrement reference count. The reference is
 * protected by dn_lock. The only interfaces modifying
 * dn_global_prop_ptr is in impl_make[free]_parlist().
 */
void
i_ddi_prop_list_hold(ddi_prop_list_t *prop_list, struct devnames *dnp)
{
	ASSERT(prop_list->prop_ref >= 0);
	ASSERT(mutex_owned(&dnp->dn_lock));
	prop_list->prop_ref++;
}

void
i_ddi_prop_list_rele(ddi_prop_list_t *prop_list, struct devnames *dnp)
{
	ASSERT(prop_list->prop_ref > 0);
	ASSERT(mutex_owned(&dnp->dn_lock));
	prop_list->prop_ref--;

	if (prop_list->prop_ref == 0) {
		i_ddi_prop_list_delete(prop_list->prop_list);
		kmem_free(prop_list, sizeof (*prop_list));
	}
}

/*
 * Free table of classes by drivers
 */
void
i_ddi_free_exported_classes(char **classes, int n)
{
	if ((n == 0) || (classes == NULL))
		return;

	kmem_free(classes, n * sizeof (char *));
}

/*
 * Get all classes exported by dip
 */
int
i_ddi_get_exported_classes(dev_info_t *dip, char ***classes)
{
	extern void lock_hw_class_list();
	extern void unlock_hw_class_list();
	extern int get_class(const char *, char **);

	static char *rootclass = "root";
	int n = 0, nclass = 0;
	char **buf;

	ASSERT(i_ddi_node_state(dip) >= DS_BOUND);

	if (dip == ddi_root_node())	/* rootnode exports class "root" */
		nclass = 1;
	lock_hw_class_list();
	nclass += get_class(ddi_driver_name(dip), NULL);
	if (nclass == 0) {
		unlock_hw_class_list();
		return (0);		/* no class exported */
	}

	*classes = buf = kmem_alloc(nclass * sizeof (char *), KM_SLEEP);
	if (dip == ddi_root_node()) {
		*buf++ = rootclass;
		n = 1;
	}
	n += get_class(ddi_driver_name(dip), buf);
	unlock_hw_class_list();

	ASSERT(n == nclass);	/* make sure buf wasn't overrun */
	return (nclass);
}

/*
 * Helper functions, returns NULL if no memory.
 */
char *
i_ddi_strdup(char *str, uint_t flag)
{
	char *copy;

	if (str == NULL)
		return (NULL);

	copy = kmem_alloc(strlen(str) + 1, flag);
	if (copy == NULL)
		return (NULL);

	(void) strcpy(copy, str);
	return (copy);
}

/*
 * Load driver.conf file for major. Load all if major == -1.
 *
 * This is called
 * - early in boot after devnames array is initialized
 * - from vfs code when certain file systems are mounted
 * - from add_drv when a new driver is added
 */
int
i_ddi_load_drvconf(major_t major)
{
	extern int modrootloaded;

	major_t low, high, m;

	if (major == DDI_MAJOR_T_NONE) {
		low = 0;
		high = devcnt - 1;
	} else {
		if (major >= devcnt)
			return (EINVAL);
		low = high = major;
	}

	for (m = low; m <= high; m++) {
		struct devnames *dnp = &devnamesp[m];
		LOCK_DEV_OPS(&dnp->dn_lock);
		dnp->dn_flags &= ~(DN_DRIVER_HELD|DN_DRIVER_INACTIVE);
		(void) impl_make_parlist(m);
		UNLOCK_DEV_OPS(&dnp->dn_lock);
	}

	if (modrootloaded) {
		ddi_walk_devs(ddi_root_node(), reset_nexus_flags,
		    (void *)(uintptr_t)major);
	}

	/* build dn_list from old entries in path_to_inst */
	e_ddi_unorphan_instance_nos();
	return (0);
}

/*
 * Unload a specific driver.conf.
 * Don't support unload all because it doesn't make any sense
 */
int
i_ddi_unload_drvconf(major_t major)
{
	int error;
	struct devnames *dnp;

	if (major >= devcnt)
		return (EINVAL);

	/*
	 * Take the per-driver lock while unloading driver.conf
	 */
	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);
	error = impl_free_parlist(major);
	UNLOCK_DEV_OPS(&dnp->dn_lock);
	return (error);
}

/*
 * Merge a .conf node. This is called by nexus drivers to augment
 * hw node with properties specified in driver.conf file. This function
 * takes a callback routine to name nexus children.
 * The parent node must be held busy.
 *
 * It returns DDI_SUCCESS if the node is merged and DDI_FAILURE otherwise.
 */
int
ndi_merge_node(dev_info_t *dip, int (*make_ua)(dev_info_t *, char *, int))
{
	dev_info_t *hwdip;

	ASSERT(ndi_dev_is_persistent_node(dip) == 0);
	ASSERT(ddi_get_name_addr(dip) != NULL);

	hwdip = ndi_devi_findchild_by_callback(ddi_get_parent(dip),
	    ddi_binding_name(dip), ddi_get_name_addr(dip), make_ua);

	/*
	 * Look for the hardware node that is the target of the merge;
	 * return failure if not found.
	 */
	if ((hwdip == NULL) || (hwdip == dip)) {
		char *buf = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		NDI_CONFIG_DEBUG((CE_WARN, "No HW node to merge conf node %s",
		    ddi_deviname(dip, buf)));
		kmem_free(buf, MAXNAMELEN);
		return (DDI_FAILURE);
	}

	/*
	 * Make sure the hardware node is uninitialized and has no property.
	 * This may not be the case if new .conf files are load after some
	 * hardware nodes have already been initialized and attached.
	 *
	 * N.B. We return success here because the node was *intended*
	 *	to be a merge node because there is a hw node with the name.
	 */
	mutex_enter(&DEVI(hwdip)->devi_lock);
	if (ndi_dev_is_persistent_node(hwdip) == 0) {
		char *buf;
		mutex_exit(&DEVI(hwdip)->devi_lock);

		buf = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		NDI_CONFIG_DEBUG((CE_NOTE, "Duplicate .conf node %s",
		    ddi_deviname(dip, buf)));
		kmem_free(buf, MAXNAMELEN);
		return (DDI_SUCCESS);
	}

	/*
	 * If it is possible that the hardware has already been touched
	 * then don't merge.
	 */
	if (i_ddi_node_state(hwdip) >= DS_INITIALIZED ||
	    (DEVI(hwdip)->devi_sys_prop_ptr != NULL) ||
	    (DEVI(hwdip)->devi_drv_prop_ptr != NULL)) {
		char *buf;
		mutex_exit(&DEVI(hwdip)->devi_lock);

		buf = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		NDI_CONFIG_DEBUG((CE_NOTE,
		    "!Cannot merge .conf node %s with hw node %p "
		    "-- not in proper state",
		    ddi_deviname(dip, buf), (void *)hwdip));
		kmem_free(buf, MAXNAMELEN);
		return (DDI_SUCCESS);
	}

	mutex_enter(&DEVI(dip)->devi_lock);
	DEVI(hwdip)->devi_sys_prop_ptr = DEVI(dip)->devi_sys_prop_ptr;
	DEVI(hwdip)->devi_drv_prop_ptr = DEVI(dip)->devi_drv_prop_ptr;
	DEVI(dip)->devi_sys_prop_ptr = NULL;
	DEVI(dip)->devi_drv_prop_ptr = NULL;
	mutex_exit(&DEVI(dip)->devi_lock);
	mutex_exit(&DEVI(hwdip)->devi_lock);

	return (DDI_SUCCESS);
}

/*
 * Merge a "wildcard" .conf node. This is called by nexus drivers to
 * augment a set of hw node with properties specified in driver.conf file.
 * The parent node must be held busy.
 *
 * There is no failure mode, since the nexus may or may not have child
 * node bound the driver specified by the wildcard node.
 */
void
ndi_merge_wildcard_node(dev_info_t *dip)
{
	dev_info_t *hwdip;
	dev_info_t *pdip = ddi_get_parent(dip);
	major_t major = ddi_driver_major(dip);

	/* never attempt to merge a hw node */
	ASSERT(ndi_dev_is_persistent_node(dip) == 0);
	/* must be bound to a driver major number */
	ASSERT(major != DDI_MAJOR_T_NONE);

	/*
	 * Walk the child list to find all nodes bound to major
	 * and copy properties.
	 */
	mutex_enter(&DEVI(dip)->devi_lock);
	ASSERT(DEVI_BUSY_OWNED(pdip));
	for (hwdip = ddi_get_child(pdip); hwdip;
	    hwdip = ddi_get_next_sibling(hwdip)) {
		/*
		 * Skip nodes not bound to same driver
		 */
		if (ddi_driver_major(hwdip) != major)
			continue;

		/*
		 * Skip .conf nodes
		 */
		if (ndi_dev_is_persistent_node(hwdip) == 0)
			continue;

		/*
		 * Make sure the node is uninitialized and has no property.
		 */
		mutex_enter(&DEVI(hwdip)->devi_lock);
		if (i_ddi_node_state(hwdip) >= DS_INITIALIZED ||
		    (DEVI(hwdip)->devi_sys_prop_ptr != NULL) ||
		    (DEVI(hwdip)->devi_drv_prop_ptr != NULL)) {
			mutex_exit(&DEVI(hwdip)->devi_lock);
			NDI_CONFIG_DEBUG((CE_NOTE, "HW node %p state not "
			    "suitable for merging wildcard conf node %s",
			    (void *)hwdip, ddi_node_name(dip)));
			continue;
		}

		DEVI(hwdip)->devi_sys_prop_ptr =
		    i_ddi_prop_list_dup(DEVI(dip)->devi_sys_prop_ptr, KM_SLEEP);
		DEVI(hwdip)->devi_drv_prop_ptr =
		    i_ddi_prop_list_dup(DEVI(dip)->devi_drv_prop_ptr, KM_SLEEP);
		mutex_exit(&DEVI(hwdip)->devi_lock);
	}
	mutex_exit(&DEVI(dip)->devi_lock);
}

/*
 * Return the major number based on the compatible property. This interface
 * may be used in situations where we are trying to detect if a better driver
 * now exists for a device, so it must use the 'compatible' property.  If
 * a non-NULL formp is specified and the binding was based on compatible then
 * return the pointer to the form used in *formp.
 */
major_t
ddi_compatible_driver_major(dev_info_t *dip, char **formp)
{
	struct dev_info *devi = DEVI(dip);
	void		*compat;
	size_t		len;
	char		*p = NULL;
	major_t		major = DDI_MAJOR_T_NONE;

	if (formp)
		*formp = NULL;

	if (ddi_prop_exists(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
	    "ddi-assigned")) {
		major = ddi_name_to_major("nulldriver");
		return (major);
	}

	/*
	 * Highest precedence binding is a path-oriented alias. Since this
	 * requires a 'path', this type of binding occurs via more obtuse
	 * 'rebind'. The need for a path-oriented alias 'rebind' is detected
	 * after a successful DDI_CTLOPS_INITCHILD to another driver: this is
	 * is the first point at which the unit-address (or instance) of the
	 * last component of the path is available (even though the path is
	 * bound to the wrong driver at this point).
	 */
	if (devi->devi_flags & DEVI_REBIND) {
		p = devi->devi_rebinding_name;
		major = ddi_name_to_major(p);
		if (driver_active(major)) {
			if (formp)
				*formp = p;
			return (major);
		}

		/*
		 * If for some reason devi_rebinding_name no longer resolves
		 * to a proper driver then clear DEVI_REBIND.
		 */
		mutex_enter(&devi->devi_lock);
		devi->devi_flags &= ~DEVI_REBIND;
		mutex_exit(&devi->devi_lock);
	}

	/* look up compatible property */
	(void) lookup_compatible(dip, KM_SLEEP);
	compat = (void *)(devi->devi_compat_names);
	len = devi->devi_compat_length;

	/* find the highest precedence compatible form with a driver binding */
	while ((p = prom_decode_composite_string(compat, len, p)) != NULL) {
		major = ddi_name_to_major(p);
		if (driver_active(major)) {
			if (formp)
				*formp = p;
			return (major);
		}
	}

	/*
	 * none of the compatible forms have a driver binding, see if
	 * the node name has a driver binding.
	 */
	major = ddi_name_to_major(ddi_node_name(dip));
	if (driver_active(major))
		return (major);

	/* no driver */
	return (DDI_MAJOR_T_NONE);
}

/*
 * Static help functions
 */

/*
 * lookup the "compatible" property and cache it's contents in the
 * device node.
 */
static int
lookup_compatible(dev_info_t *dip, uint_t flag)
{
	int rv;
	int prop_flags;
	uint_t ncompatstrs;
	char **compatstrpp;
	char *di_compat_strp;
	size_t di_compat_strlen;

	if (DEVI(dip)->devi_compat_names) {
		return (DDI_SUCCESS);
	}

	prop_flags = DDI_PROP_TYPE_STRING | DDI_PROP_DONTPASS;

	if (flag & KM_NOSLEEP) {
		prop_flags |= DDI_PROP_DONTSLEEP;
	}

	if (ndi_dev_is_prom_node(dip) == 0) {
		prop_flags |= DDI_PROP_NOTPROM;
	}

	rv = ddi_prop_lookup_common(DDI_DEV_T_ANY, dip, prop_flags,
	    "compatible", &compatstrpp, &ncompatstrs,
	    ddi_prop_fm_decode_strings);

	if (rv == DDI_PROP_NOT_FOUND) {
		return (DDI_SUCCESS);
	}

	if (rv != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * encode the compatible property data in the dev_info node
	 */
	rv = DDI_SUCCESS;
	if (ncompatstrs != 0) {
		di_compat_strp = encode_composite_string(compatstrpp,
		    ncompatstrs, &di_compat_strlen, flag);
		if (di_compat_strp != NULL) {
			DEVI(dip)->devi_compat_names = di_compat_strp;
			DEVI(dip)->devi_compat_length = di_compat_strlen;
		} else {
			rv = DDI_FAILURE;
		}
	}
	ddi_prop_free(compatstrpp);
	return (rv);
}

/*
 * Create a composite string from a list of strings.
 *
 * A composite string consists of a single buffer containing one
 * or more NULL terminated strings.
 */
static char *
encode_composite_string(char **strings, uint_t nstrings, size_t *retsz,
    uint_t flag)
{
	uint_t index;
	char  **strpp;
	uint_t slen;
	size_t cbuf_sz = 0;
	char *cbuf_p;
	char *cbuf_ip;

	if (strings == NULL || nstrings == 0 || retsz == NULL) {
		return (NULL);
	}

	for (index = 0, strpp = strings; index < nstrings; index++)
		cbuf_sz += strlen(*(strpp++)) + 1;

	if ((cbuf_p = kmem_alloc(cbuf_sz, flag)) == NULL) {
		cmn_err(CE_NOTE,
		    "?failed to allocate device node compatstr");
		return (NULL);
	}

	cbuf_ip = cbuf_p;
	for (index = 0, strpp = strings; index < nstrings; index++) {
		slen = strlen(*strpp);
		bcopy(*(strpp++), cbuf_ip, slen);
		cbuf_ip += slen;
		*(cbuf_ip++) = '\0';
	}

	*retsz = cbuf_sz;
	return (cbuf_p);
}

static void
link_to_driver_list(dev_info_t *dip)
{
	major_t major = DEVI(dip)->devi_major;
	struct devnames *dnp;

	ASSERT(major != DDI_MAJOR_T_NONE);

	/*
	 * Remove from orphan list
	 */
	if (ndi_dev_is_persistent_node(dip)) {
		dnp = &orphanlist;
		remove_from_dn_list(dnp, dip);
	}

	/*
	 * Add to per driver list
	 */
	dnp = &devnamesp[major];
	add_to_dn_list(dnp, dip);
}

static void
unlink_from_driver_list(dev_info_t *dip)
{
	major_t major = DEVI(dip)->devi_major;
	struct devnames *dnp;

	ASSERT(major != DDI_MAJOR_T_NONE);

	/*
	 * Remove from per-driver list
	 */
	dnp = &devnamesp[major];
	remove_from_dn_list(dnp, dip);

	/*
	 * Add to orphan list
	 */
	if (ndi_dev_is_persistent_node(dip)) {
		dnp = &orphanlist;
		add_to_dn_list(dnp, dip);
	}
}

/*
 * scan the per-driver list looking for dev_info "dip"
 */
static dev_info_t *
in_dn_list(struct devnames *dnp, dev_info_t *dip)
{
	struct dev_info *idevi;

	if ((idevi = DEVI(dnp->dn_head)) == NULL)
		return (NULL);

	while (idevi) {
		if (idevi == DEVI(dip))
			return (dip);
		idevi = idevi->devi_next;
	}
	return (NULL);
}

/*
 * insert devinfo node 'dip' into the per-driver instance list
 * headed by 'dnp'
 *
 * Nodes on the per-driver list are ordered: HW - SID - PSEUDO.  The order is
 * required for merging of .conf file data to work properly.
 */
static void
add_to_ordered_dn_list(struct devnames *dnp, dev_info_t *dip)
{
	dev_info_t **dipp;

	ASSERT(mutex_owned(&(dnp->dn_lock)));

	dipp = &dnp->dn_head;
	if (ndi_dev_is_prom_node(dip)) {
		/*
		 * Find the first non-prom node or end of list
		 */
		while (*dipp && (ndi_dev_is_prom_node(*dipp) != 0)) {
			dipp = (dev_info_t **)&DEVI(*dipp)->devi_next;
		}
	} else if (ndi_dev_is_persistent_node(dip)) {
		/*
		 * Find the first non-persistent node
		 */
		while (*dipp && (ndi_dev_is_persistent_node(*dipp) != 0)) {
			dipp = (dev_info_t **)&DEVI(*dipp)->devi_next;
		}
	} else {
		/*
		 * Find the end of the list
		 */
		while (*dipp) {
			dipp = (dev_info_t **)&DEVI(*dipp)->devi_next;
		}
	}

	DEVI(dip)->devi_next = DEVI(*dipp);
	*dipp = dip;
}

/*
 * add a list of device nodes to the device node list in the
 * devnames structure
 */
static void
add_to_dn_list(struct devnames *dnp, dev_info_t *dip)
{
	/*
	 * Look to see if node already exists
	 */
	LOCK_DEV_OPS(&(dnp->dn_lock));
	if (in_dn_list(dnp, dip)) {
		cmn_err(CE_NOTE, "add_to_dn_list: node %s already in list",
		    DEVI(dip)->devi_node_name);
	} else {
		add_to_ordered_dn_list(dnp, dip);
	}
	UNLOCK_DEV_OPS(&(dnp->dn_lock));
}

static void
remove_from_dn_list(struct devnames *dnp, dev_info_t *dip)
{
	dev_info_t **plist;

	LOCK_DEV_OPS(&(dnp->dn_lock));

	plist = (dev_info_t **)&dnp->dn_head;
	while (*plist && (*plist != dip)) {
		plist = (dev_info_t **)&DEVI(*plist)->devi_next;
	}

	if (*plist != NULL) {
		ASSERT(*plist == dip);
		*plist = (dev_info_t *)(DEVI(dip)->devi_next);
		DEVI(dip)->devi_next = NULL;
	} else {
		NDI_CONFIG_DEBUG((CE_NOTE,
		    "remove_from_dn_list: node %s not found in list",
		    DEVI(dip)->devi_node_name));
	}

	UNLOCK_DEV_OPS(&(dnp->dn_lock));
}

/*
 * Add and remove reference driver global property list
 */
static void
add_global_props(dev_info_t *dip)
{
	struct devnames *dnp;
	ddi_prop_list_t *plist;

	ASSERT(DEVI(dip)->devi_global_prop_list == NULL);
	ASSERT(DEVI(dip)->devi_major != DDI_MAJOR_T_NONE);

	dnp = &devnamesp[DEVI(dip)->devi_major];
	LOCK_DEV_OPS(&dnp->dn_lock);
	plist = dnp->dn_global_prop_ptr;
	if (plist == NULL) {
		UNLOCK_DEV_OPS(&dnp->dn_lock);
		return;
	}
	i_ddi_prop_list_hold(plist, dnp);
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	mutex_enter(&DEVI(dip)->devi_lock);
	DEVI(dip)->devi_global_prop_list = plist;
	mutex_exit(&DEVI(dip)->devi_lock);
}

static void
remove_global_props(dev_info_t *dip)
{
	ddi_prop_list_t *proplist;

	mutex_enter(&DEVI(dip)->devi_lock);
	proplist = DEVI(dip)->devi_global_prop_list;
	DEVI(dip)->devi_global_prop_list = NULL;
	mutex_exit(&DEVI(dip)->devi_lock);

	if (proplist) {
		major_t major;
		struct devnames *dnp;

		major = ddi_driver_major(dip);
		ASSERT(major != DDI_MAJOR_T_NONE);
		dnp = &devnamesp[major];
		LOCK_DEV_OPS(&dnp->dn_lock);
		i_ddi_prop_list_rele(proplist, dnp);
		UNLOCK_DEV_OPS(&dnp->dn_lock);
	}
}

#ifdef DEBUG
/*
 * Set this variable to '0' to disable the optimization,
 * and to 2 to print debug message.
 */
static int optimize_dtree = 1;

static void
debug_dtree(dev_info_t *devi, struct dev_info *adevi, char *service)
{
	char *adeviname, *buf;

	/*
	 * Don't print unless optimize dtree is set to 2+
	 */
	if (optimize_dtree <= 1)
		return;

	buf = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	adeviname = ddi_deviname((dev_info_t *)adevi, buf);
	if (*adeviname == '\0')
		adeviname = "root";

	cmn_err(CE_CONT, "%s %s -> %s\n",
	    ddi_deviname(devi, buf), service, adeviname);

	kmem_free(buf, MAXNAMELEN);
}
#else /* DEBUG */
#define	debug_dtree(a1, a2, a3)	 /* nothing */
#endif	/* DEBUG */

static void
ddi_optimize_dtree(dev_info_t *devi)
{
	struct dev_info *pdevi;
	struct bus_ops *b;

	pdevi = DEVI(devi)->devi_parent;
	ASSERT(pdevi);

	/*
	 * Set the unoptimized values
	 */
	DEVI(devi)->devi_bus_map_fault = pdevi;
	DEVI(devi)->devi_bus_dma_allochdl = pdevi;
	DEVI(devi)->devi_bus_dma_freehdl = pdevi;
	DEVI(devi)->devi_bus_dma_bindhdl = pdevi;
	DEVI(devi)->devi_bus_dma_bindfunc =
	    pdevi->devi_ops->devo_bus_ops->bus_dma_bindhdl;
	DEVI(devi)->devi_bus_dma_unbindhdl = pdevi;
	DEVI(devi)->devi_bus_dma_unbindfunc =
	    pdevi->devi_ops->devo_bus_ops->bus_dma_unbindhdl;
	DEVI(devi)->devi_bus_dma_flush = pdevi;
	DEVI(devi)->devi_bus_dma_win = pdevi;
	DEVI(devi)->devi_bus_dma_ctl = pdevi;
	DEVI(devi)->devi_bus_ctl = pdevi;

#ifdef DEBUG
	if (optimize_dtree == 0)
		return;
#endif /* DEBUG */

	b = pdevi->devi_ops->devo_bus_ops;

	if (i_ddi_map_fault == b->bus_map_fault) {
		DEVI(devi)->devi_bus_map_fault = pdevi->devi_bus_map_fault;
		debug_dtree(devi, DEVI(devi)->devi_bus_map_fault,
		    "bus_map_fault");
	}

	if (ddi_dma_allochdl == b->bus_dma_allochdl) {
		DEVI(devi)->devi_bus_dma_allochdl =
		    pdevi->devi_bus_dma_allochdl;
		debug_dtree(devi, DEVI(devi)->devi_bus_dma_allochdl,
		    "bus_dma_allochdl");
	}

	if (ddi_dma_freehdl == b->bus_dma_freehdl) {
		DEVI(devi)->devi_bus_dma_freehdl = pdevi->devi_bus_dma_freehdl;
		debug_dtree(devi, DEVI(devi)->devi_bus_dma_freehdl,
		    "bus_dma_freehdl");
	}

	if (ddi_dma_bindhdl == b->bus_dma_bindhdl) {
		DEVI(devi)->devi_bus_dma_bindhdl = pdevi->devi_bus_dma_bindhdl;
		DEVI(devi)->devi_bus_dma_bindfunc =
		    pdevi->devi_bus_dma_bindhdl->devi_ops->
		    devo_bus_ops->bus_dma_bindhdl;
		debug_dtree(devi, DEVI(devi)->devi_bus_dma_bindhdl,
		    "bus_dma_bindhdl");
	}

	if (ddi_dma_unbindhdl == b->bus_dma_unbindhdl) {
		DEVI(devi)->devi_bus_dma_unbindhdl =
		    pdevi->devi_bus_dma_unbindhdl;
		DEVI(devi)->devi_bus_dma_unbindfunc =
		    pdevi->devi_bus_dma_unbindhdl->devi_ops->
		    devo_bus_ops->bus_dma_unbindhdl;
		debug_dtree(devi, DEVI(devi)->devi_bus_dma_unbindhdl,
		    "bus_dma_unbindhdl");
	}

	if (ddi_dma_flush == b->bus_dma_flush) {
		DEVI(devi)->devi_bus_dma_flush = pdevi->devi_bus_dma_flush;
		debug_dtree(devi, DEVI(devi)->devi_bus_dma_flush,
		    "bus_dma_flush");
	}

	if (ddi_dma_win == b->bus_dma_win) {
		DEVI(devi)->devi_bus_dma_win = pdevi->devi_bus_dma_win;
		debug_dtree(devi, DEVI(devi)->devi_bus_dma_win,
		    "bus_dma_win");
	}

	if (ddi_dma_mctl == b->bus_dma_ctl) {
		DEVI(devi)->devi_bus_dma_ctl = pdevi->devi_bus_dma_ctl;
		debug_dtree(devi, DEVI(devi)->devi_bus_dma_ctl, "bus_dma_ctl");
	}

	if (ddi_ctlops == b->bus_ctl) {
		DEVI(devi)->devi_bus_ctl = pdevi->devi_bus_ctl;
		debug_dtree(devi, DEVI(devi)->devi_bus_ctl, "bus_ctl");
	}
}

#define	MIN_DEVINFO_LOG_SIZE	max_ncpus
#define	MAX_DEVINFO_LOG_SIZE	max_ncpus * 10

static void
da_log_init()
{
	devinfo_log_header_t *dh;
	int logsize = devinfo_log_size;

	if (logsize == 0)
		logsize = MIN_DEVINFO_LOG_SIZE;
	else if (logsize > MAX_DEVINFO_LOG_SIZE)
		logsize = MAX_DEVINFO_LOG_SIZE;

	dh = kmem_alloc(logsize * PAGESIZE, KM_SLEEP);
	mutex_init(&dh->dh_lock, NULL, MUTEX_DEFAULT, NULL);
	dh->dh_max = ((logsize * PAGESIZE) - sizeof (*dh)) /
	    sizeof (devinfo_audit_t) + 1;
	dh->dh_curr = -1;
	dh->dh_hits = 0;

	devinfo_audit_log = dh;
}

/*
 * Log the stack trace in per-devinfo audit structure and also enter
 * it into a system wide log for recording the time history.
 */
static void
da_log_enter(dev_info_t *dip)
{
	devinfo_audit_t *da_log, *da = DEVI(dip)->devi_audit;
	devinfo_log_header_t *dh = devinfo_audit_log;

	if (devinfo_audit_log == NULL)
		return;

	ASSERT(da != NULL);

	da->da_devinfo = dip;
	da->da_timestamp = gethrtime();
	da->da_thread = curthread;
	da->da_node_state = DEVI(dip)->devi_node_state;
	da->da_device_state = DEVI(dip)->devi_state;
	da->da_depth = getpcstack(da->da_stack, DDI_STACK_DEPTH);

	/*
	 * Copy into common log and note the location for tracing history
	 */
	mutex_enter(&dh->dh_lock);
	dh->dh_hits++;
	dh->dh_curr++;
	if (dh->dh_curr >= dh->dh_max)
		dh->dh_curr -= dh->dh_max;
	da_log = &dh->dh_entry[dh->dh_curr];
	mutex_exit(&dh->dh_lock);

	bcopy(da, da_log, sizeof (devinfo_audit_t));
	da->da_lastlog = da_log;
}

static void
attach_drivers()
{
	int i;
	for (i = 0; i < devcnt; i++) {
		struct devnames *dnp = &devnamesp[i];
		if ((dnp->dn_flags & DN_FORCE_ATTACH) &&
		    (ddi_hold_installed_driver((major_t)i) != NULL))
			ddi_rele_driver((major_t)i);
	}
}

/*
 * Launch a thread to force attach drivers. This avoids penalty on boot time.
 */
void
i_ddi_forceattach_drivers()
{

	/*
	 * Attach IB VHCI driver before the force-attach thread attaches the
	 * IB HCA driver. IB HCA driver will fail if IB Nexus has not yet
	 * been attached.
	 */
	(void) ddi_hold_installed_driver(ddi_name_to_major("ib"));

	(void) thread_create(NULL, 0, (void (*)())attach_drivers, NULL, 0, &p0,
	    TS_RUN, minclsyspri);
}

/*
 * This is a private DDI interface for optimizing boot performance.
 * I/O subsystem initialization is considered complete when devfsadm
 * is executed.
 *
 * NOTE: The start of syseventd happens to be a convenient indicator
 *	of the completion of I/O initialization during boot.
 *	The implementation should be replaced by something more robust.
 */
int
i_ddi_io_initialized()
{
	extern int sysevent_daemon_init;
	return (sysevent_daemon_init);
}

/*
 * May be used to determine system boot state
 * "Available" means the system is for the most part up
 * and initialized, with all system services either up or
 * capable of being started.  This state is set by devfsadm
 * during the boot process.  The /dev filesystem infers
 * from this when implicit reconfig can be performed,
 * ie, devfsadm can be invoked.  Please avoid making
 * further use of this unless it's really necessary.
 */
int
i_ddi_sysavail()
{
	return (devname_state & DS_SYSAVAIL);
}

/*
 * May be used to determine if boot is a reconfigure boot.
 */
int
i_ddi_reconfig()
{
	return (devname_state & DS_RECONFIG);
}

/*
 * Note system services are up, inform /dev.
 */
void
i_ddi_set_sysavail()
{
	if ((devname_state & DS_SYSAVAIL) == 0) {
		devname_state |= DS_SYSAVAIL;
		sdev_devstate_change();
	}
}

/*
 * Note reconfiguration boot, inform /dev.
 */
void
i_ddi_set_reconfig()
{
	if ((devname_state & DS_RECONFIG) == 0) {
		devname_state |= DS_RECONFIG;
		sdev_devstate_change();
	}
}


/*
 * device tree walking
 */

struct walk_elem {
	struct walk_elem *next;
	dev_info_t *dip;
};

static void
free_list(struct walk_elem *list)
{
	while (list) {
		struct walk_elem *next = list->next;
		kmem_free(list, sizeof (*list));
		list = next;
	}
}

static void
append_node(struct walk_elem **list, dev_info_t *dip)
{
	struct walk_elem *tail;
	struct walk_elem *elem = kmem_alloc(sizeof (*elem), KM_SLEEP);

	elem->next = NULL;
	elem->dip = dip;

	if (*list == NULL) {
		*list = elem;
		return;
	}

	tail = *list;
	while (tail->next)
		tail = tail->next;

	tail->next = elem;
}

/*
 * The implementation of ddi_walk_devs().
 */
static int
walk_devs(dev_info_t *dip, int (*f)(dev_info_t *, void *), void *arg,
    int do_locking)
{
	struct walk_elem *head = NULL;

	/*
	 * Do it in two passes. First pass invoke callback on each
	 * dip on the sibling list. Second pass invoke callback on
	 * children of each dip.
	 */
	while (dip) {
		switch ((*f)(dip, arg)) {
		case DDI_WALK_TERMINATE:
			free_list(head);
			return (DDI_WALK_TERMINATE);

		case DDI_WALK_PRUNESIB:
			/* ignore sibling by setting dip to NULL */
			append_node(&head, dip);
			dip = NULL;
			break;

		case DDI_WALK_PRUNECHILD:
			/* don't worry about children */
			dip = ddi_get_next_sibling(dip);
			break;

		case DDI_WALK_CONTINUE:
		default:
			append_node(&head, dip);
			dip = ddi_get_next_sibling(dip);
			break;
		}

	}

	/* second pass */
	while (head) {
		int circ;
		struct walk_elem *next = head->next;

		if (do_locking)
			ndi_devi_enter(head->dip, &circ);
		if (walk_devs(ddi_get_child(head->dip), f, arg, do_locking) ==
		    DDI_WALK_TERMINATE) {
			if (do_locking)
				ndi_devi_exit(head->dip, circ);
			free_list(head);
			return (DDI_WALK_TERMINATE);
		}
		if (do_locking)
			ndi_devi_exit(head->dip, circ);
		kmem_free(head, sizeof (*head));
		head = next;
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * This general-purpose routine traverses the tree of dev_info nodes,
 * starting from the given node, and calls the given function for each
 * node that it finds with the current node and the pointer arg (which
 * can point to a structure of information that the function
 * needs) as arguments.
 *
 * It does the walk a layer at a time, not depth-first. The given function
 * must return one of the following values:
 *	DDI_WALK_CONTINUE
 *	DDI_WALK_PRUNESIB
 *	DDI_WALK_PRUNECHILD
 *	DDI_WALK_TERMINATE
 *
 * N.B. Since we walk the sibling list, the caller must ensure that
 *	the parent of dip is held against changes, unless the parent
 *	is rootnode.  ndi_devi_enter() on the parent is sufficient.
 *
 *	To avoid deadlock situations, caller must not attempt to
 *	configure/unconfigure/remove device node in (*f)(), nor should
 *	it attempt to recurse on other nodes in the system. Any
 *	ndi_devi_enter() done by (*f)() must occur 'at-or-below' the
 *	node entered prior to ddi_walk_devs(). Furthermore, if (*f)()
 *	does any multi-threading (in framework *or* in driver) then the
 *	ndi_devi_enter() calls done by dependent threads must be
 *	'strictly-below'.
 *
 *	This is not callable from device autoconfiguration routines.
 *	They include, but not limited to, _init(9e), _fini(9e), probe(9e),
 *	attach(9e), and detach(9e).
 */

void
ddi_walk_devs(dev_info_t *dip, int (*f)(dev_info_t *, void *), void *arg)
{

	ASSERT(dip == NULL || ddi_get_parent(dip) == NULL ||
	    DEVI_BUSY_OWNED(ddi_get_parent(dip)));

	(void) walk_devs(dip, f, arg, 1);
}

/*
 * This is a general-purpose routine traverses the per-driver list
 * and calls the given function for each node. must return one of
 * the following values:
 *	DDI_WALK_CONTINUE
 *	DDI_WALK_TERMINATE
 *
 * N.B. The same restrictions from ddi_walk_devs() apply.
 */

void
e_ddi_walk_driver(char *drv, int (*f)(dev_info_t *, void *), void *arg)
{
	major_t major;
	struct devnames *dnp;
	dev_info_t *dip;

	major = ddi_name_to_major(drv);
	if (major == DDI_MAJOR_T_NONE)
		return;

	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);
	dip = dnp->dn_head;
	while (dip) {
		ndi_hold_devi(dip);
		UNLOCK_DEV_OPS(&dnp->dn_lock);
		if ((*f)(dip, arg) == DDI_WALK_TERMINATE) {
			ndi_rele_devi(dip);
			return;
		}
		LOCK_DEV_OPS(&dnp->dn_lock);
		ndi_rele_devi(dip);
		dip = ddi_get_next(dip);
	}
	UNLOCK_DEV_OPS(&dnp->dn_lock);
}

/*
 * argument to i_find_devi, a devinfo node search callback function.
 */
struct match_info {
	dev_info_t	*dip;		/* result */
	char		*nodename;	/* if non-null, nodename must match */
	int		instance;	/* if != -1, instance must match */
	int		attached;	/* if != 0, i_ddi_devi_attached() */
};

static int
i_find_devi(dev_info_t *dip, void *arg)
{
	struct match_info *info = (struct match_info *)arg;

	if (((info->nodename == NULL) ||
	    (strcmp(ddi_node_name(dip), info->nodename) == 0)) &&
	    ((info->instance == -1) ||
	    (ddi_get_instance(dip) == info->instance)) &&
	    ((info->attached == 0) || i_ddi_devi_attached(dip))) {
		info->dip = dip;
		ndi_hold_devi(dip);
		return (DDI_WALK_TERMINATE);
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * Find dip with a known node name and instance and return with it held
 */
dev_info_t *
ddi_find_devinfo(char *nodename, int instance, int attached)
{
	struct match_info	info;

	info.nodename = nodename;
	info.instance = instance;
	info.attached = attached;
	info.dip = NULL;

	ddi_walk_devs(ddi_root_node(), i_find_devi, &info);
	return (info.dip);
}

extern ib_boot_prop_t *iscsiboot_prop;
static void
i_ddi_parse_iscsi_name(char *name, char **nodename, char **addrname,
    char **minorname)
{
	char *cp, *colon;
	static char nulladdrname[] = "";

	/* default values */
	if (nodename)
		*nodename = name;
	if (addrname)
		*addrname = nulladdrname;
	if (minorname)
		*minorname = NULL;

	cp = colon = name;
	while (*cp != '\0') {
		if (addrname && *cp == '@') {
			*addrname = cp + 1;
			*cp = '\0';
		} else if (minorname && *cp == ':') {
			*minorname = cp + 1;
			colon = cp;
		}
		++cp;
	}
	if (colon != name) {
		*colon = '\0';
	}
}

/*
 * Parse for name, addr, and minor names. Some args may be NULL.
 */
void
i_ddi_parse_name(char *name, char **nodename, char **addrname, char **minorname)
{
	char *cp;
	static char nulladdrname[] = "";

	/* default values */
	if (nodename)
		*nodename = name;
	if (addrname)
		*addrname = nulladdrname;
	if (minorname)
		*minorname = NULL;

	cp = name;
	while (*cp != '\0') {
		if (addrname && *cp == '@') {
			*addrname = cp + 1;
			*cp = '\0';
		} else if (minorname && *cp == ':') {
			*minorname = cp + 1;
			*cp = '\0';
		}
		++cp;
	}
}

static char *
child_path_to_driver(dev_info_t *parent, char *child_name, char *unit_address)
{
	char *p, *drvname = NULL;
	major_t maj;

	/*
	 * Construct the pathname and ask the implementation
	 * if it can do a driver = f(pathname) for us, if not
	 * we'll just default to using the node-name that
	 * was given to us.  We want to do this first to
	 * allow the platform to use 'generic' names for
	 * legacy device drivers.
	 */
	p = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(parent, p);
	(void) strcat(p, "/");
	(void) strcat(p, child_name);
	if (unit_address && *unit_address) {
		(void) strcat(p, "@");
		(void) strcat(p, unit_address);
	}

	/*
	 * Get the binding. If there is none, return the child_name
	 * and let the caller deal with it.
	 */
	maj = path_to_major(p);

	kmem_free(p, MAXPATHLEN);

	if (maj != DDI_MAJOR_T_NONE)
		drvname = ddi_major_to_name(maj);
	if (drvname == NULL)
		drvname = child_name;

	return (drvname);
}


#define	PCI_EX_CLASS	"pciexclass"
#define	PCI_EX		"pciex"
#define	PCI_CLASS	"pciclass"
#define	PCI		"pci"

int
ddi_is_pci_dip(dev_info_t *dip)
{
	char	*prop = NULL;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "compatible", &prop) == DDI_PROP_SUCCESS) {
		ASSERT(prop);
		if (strncmp(prop, PCI_EX_CLASS, sizeof (PCI_EX_CLASS) - 1)
		    == 0 ||
		    strncmp(prop, PCI_EX, sizeof (PCI_EX)- 1)
		    == 0 ||
		    strncmp(prop, PCI_CLASS, sizeof (PCI_CLASS) - 1)
		    == 0 ||
		    strncmp(prop, PCI, sizeof (PCI) - 1)
		    == 0) {
			ddi_prop_free(prop);
			return (1);
		}
	}

	if (prop != NULL) {
		ddi_prop_free(prop);
	}

	return (0);
}

/*
 * Given the pathname of a device, fill in the dev_info_t value and/or the
 * dev_t value and/or the spectype, depending on which parameters are non-NULL.
 * If there is an error, this function returns -1.
 *
 * NOTE: If this function returns the dev_info_t structure, then it
 * does so with a hold on the devi. Caller should ensure that they get
 * decremented via ddi_release_devi() or ndi_rele_devi();
 *
 * This function can be invoked in the boot case for a pathname without
 * device argument (:xxxx), traditionally treated as a minor name.
 * In this case, we do the following
 * (1) search the minor node of type DDM_DEFAULT.
 * (2) if no DDM_DEFAULT minor exists, then the first non-alias minor is chosen.
 * (3) if neither exists, a dev_t is faked with minor number = instance.
 * As of S9 FCS, no instance of #1 exists. #2 is used by several platforms
 * to default the boot partition to :a possibly by other OBP definitions.
 * #3 is used for booting off network interfaces, most SPARC network
 * drivers support Style-2 only, so only DDM_ALIAS minor exists.
 *
 * It is possible for OBP to present device args at the end of the path as
 * well as in the middle. For example, with IB the following strings are
 * valid boot paths.
 *	a /pci@8,700000/ib@1,2:port=1,pkey=ff,dhcp,...
 *	b /pci@8,700000/ib@1,1:port=1/ioc@xxxxxx,yyyyyyy:dhcp
 * Case (a), we first look for minor node "port=1,pkey...".
 * Failing that, we will pass "port=1,pkey..." to the bus_config
 * entry point of ib (HCA) driver.
 * Case (b), configure ib@1,1 as usual. Then invoke ib's bus_config
 * with argument "ioc@xxxxxxx,yyyyyyy:port=1". After configuring
 * the ioc, look for minor node dhcp. If not found, pass ":dhcp"
 * to ioc's bus_config entry point.
 */
int
resolve_pathname(char *pathname,
	dev_info_t **dipp, dev_t *devtp, int *spectypep)
{
	int			error;
	dev_info_t		*parent, *child;
	struct pathname		pn;
	char			*component, *config_name;
	char			*minorname = NULL;
	char			*prev_minor = NULL;
	dev_t			devt = NODEV;
	int			spectype;
	struct ddi_minor_data	*dmn;
	int			circ;

	if (*pathname != '/')
		return (EINVAL);
	parent = ddi_root_node();	/* Begin at the top of the tree */

	if (error = pn_get(pathname, UIO_SYSSPACE, &pn))
		return (error);
	pn_skipslash(&pn);

	ASSERT(i_ddi_devi_attached(parent));
	ndi_hold_devi(parent);

	component = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	config_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	while (pn_pathleft(&pn)) {
		/* remember prev minor (:xxx) in the middle of path */
		if (minorname)
			prev_minor = i_ddi_strdup(minorname, KM_SLEEP);

		/* Get component and chop off minorname */
		(void) pn_getcomponent(&pn, component);
		if ((iscsiboot_prop != NULL) &&
		    (strcmp((DEVI(parent)->devi_node_name), "iscsi") == 0)) {
			i_ddi_parse_iscsi_name(component, NULL, NULL,
			    &minorname);
		} else {
			i_ddi_parse_name(component, NULL, NULL, &minorname);
		}
		if (prev_minor == NULL) {
			(void) snprintf(config_name, MAXNAMELEN, "%s",
			    component);
		} else {
			(void) snprintf(config_name, MAXNAMELEN, "%s:%s",
			    component, prev_minor);
			kmem_free(prev_minor, strlen(prev_minor) + 1);
			prev_minor = NULL;
		}

		/*
		 * Find and configure the child
		 */
		if (ndi_devi_config_one(parent, config_name, &child,
		    NDI_PROMNAME | NDI_NO_EVENT) != NDI_SUCCESS) {
			ndi_rele_devi(parent);
			pn_free(&pn);
			kmem_free(component, MAXNAMELEN);
			kmem_free(config_name, MAXNAMELEN);
			return (-1);
		}

		ASSERT(i_ddi_devi_attached(child));
		ndi_rele_devi(parent);
		parent = child;
		pn_skipslash(&pn);
	}

	/*
	 * First look for a minor node matching minorname.
	 * Failing that, try to pass minorname to bus_config().
	 */
	if (minorname && i_ddi_minorname_to_devtspectype(parent,
	    minorname, &devt, &spectype) == DDI_FAILURE) {
		(void) snprintf(config_name, MAXNAMELEN, "%s", minorname);
		if (ndi_devi_config_obp_args(parent,
		    config_name, &child, 0) != NDI_SUCCESS) {
			ndi_rele_devi(parent);
			pn_free(&pn);
			kmem_free(component, MAXNAMELEN);
			kmem_free(config_name, MAXNAMELEN);
			NDI_CONFIG_DEBUG((CE_NOTE,
			    "%s: minor node not found\n", pathname));
			return (-1);
		}
		minorname = NULL;	/* look for default minor */
		ASSERT(i_ddi_devi_attached(child));
		ndi_rele_devi(parent);
		parent = child;
	}

	if (devtp || spectypep) {
		if (minorname == NULL) {
			/*
			 * Search for a default entry with an active
			 * ndi_devi_enter to protect the devi_minor list.
			 */
			ndi_devi_enter(parent, &circ);
			for (dmn = DEVI(parent)->devi_minor; dmn;
			    dmn = dmn->next) {
				if (dmn->type == DDM_DEFAULT) {
					devt = dmn->ddm_dev;
					spectype = dmn->ddm_spec_type;
					break;
				}
			}

			if (devt == NODEV) {
				/*
				 * No default minor node, try the first one;
				 * else, assume 1-1 instance-minor mapping
				 */
				dmn = DEVI(parent)->devi_minor;
				if (dmn && ((dmn->type == DDM_MINOR) ||
				    (dmn->type == DDM_INTERNAL_PATH))) {
					devt = dmn->ddm_dev;
					spectype = dmn->ddm_spec_type;
				} else {
					devt = makedevice(
					    DEVI(parent)->devi_major,
					    ddi_get_instance(parent));
					spectype = S_IFCHR;
				}
			}
			ndi_devi_exit(parent, circ);
		}
		if (devtp)
			*devtp = devt;
		if (spectypep)
			*spectypep = spectype;
	}

	pn_free(&pn);
	kmem_free(component, MAXNAMELEN);
	kmem_free(config_name, MAXNAMELEN);

	/*
	 * If there is no error, return the appropriate parameters
	 */
	if (dipp != NULL)
		*dipp = parent;
	else {
		/*
		 * We should really keep the ref count to keep the node from
		 * detaching but ddi_pathname_to_dev_t() specifies a NULL dipp,
		 * so we have no way of passing back the held dip.  Not holding
		 * the dip allows detaches to occur - which can cause problems
		 * for subsystems which call ddi_pathname_to_dev_t (console).
		 *
		 * Instead of holding the dip, we place a ddi-no-autodetach
		 * property on the node to prevent auto detaching.
		 *
		 * The right fix is to remove ddi_pathname_to_dev_t and replace
		 * it, and all references, with a call that specifies a dipp.
		 * In addition, the callers of this new interfaces would then
		 * need to call ndi_rele_devi when the reference is complete.
		 *
		 */
		(void) ddi_prop_update_int(DDI_DEV_T_NONE, parent,
		    DDI_NO_AUTODETACH, 1);
		ndi_rele_devi(parent);
	}

	return (0);
}

/*
 * Given the pathname of a device, return the dev_t of the corresponding
 * device.  Returns NODEV on failure.
 *
 * Note that this call sets the DDI_NO_AUTODETACH property on the devinfo node.
 */
dev_t
ddi_pathname_to_dev_t(char *pathname)
{
	dev_t devt;
	int error;

	error = resolve_pathname(pathname, NULL, &devt, NULL);

	return (error ? NODEV : devt);
}

/*
 * Translate a prom pathname to kernel devfs pathname.
 * Caller is assumed to allocate devfspath memory of
 * size at least MAXPATHLEN
 *
 * The prom pathname may not include minor name, but
 * devfs pathname has a minor name portion.
 */
int
i_ddi_prompath_to_devfspath(char *prompath, char *devfspath)
{
	dev_t		devt = (dev_t)NODEV;
	dev_info_t	*dip = NULL;
	char		*minor_name = NULL;
	int		spectype;
	int		error;
	int		circ;

	error = resolve_pathname(prompath, &dip, &devt, &spectype);
	if (error)
		return (DDI_FAILURE);
	ASSERT(dip && devt != NODEV);

	/*
	 * Get in-kernel devfs pathname
	 */
	(void) ddi_pathname(dip, devfspath);

	ndi_devi_enter(dip, &circ);
	minor_name = i_ddi_devtspectype_to_minorname(dip, devt, spectype);
	if (minor_name) {
		(void) strcat(devfspath, ":");
		(void) strcat(devfspath, minor_name);
	} else {
		/*
		 * If minor_name is NULL, we have an alias minor node.
		 * So manufacture a path to the corresponding clone minor.
		 */
		(void) snprintf(devfspath, MAXPATHLEN, "%s:%s",
		    CLONE_PATH, ddi_driver_name(dip));
	}
	ndi_devi_exit(dip, circ);

	/* release hold from resolve_pathname() */
	ndi_rele_devi(dip);
	return (0);
}

/*
 * This function is intended to identify drivers that must quiesce for fast
 * reboot to succeed.  It does not claim to have more knowledge about the device
 * than its driver.  If a driver has implemented quiesce(), it will be invoked;
 * if a so identified driver does not manage any device that needs to be
 * quiesced, it must explicitly set its devo_quiesce dev_op to
 * ddi_quiesce_not_needed.
 */
static int skip_pseudo = 1;	/* Skip pseudo devices */
static int skip_non_hw = 1;	/* Skip devices with no hardware property */
static int
should_implement_quiesce(dev_info_t *dip)
{
	struct dev_info *devi = DEVI(dip);
	dev_info_t *pdip;

	/*
	 * If dip is pseudo and skip_pseudo is set, driver doesn't have to
	 * implement quiesce().
	 */
	if (skip_pseudo &&
	    strncmp(ddi_binding_name(dip), "pseudo", sizeof ("pseudo")) == 0)
		return (0);

	/*
	 * If parent dip is pseudo and skip_pseudo is set, driver doesn't have
	 * to implement quiesce().
	 */
	if (skip_pseudo && (pdip = ddi_get_parent(dip)) != NULL &&
	    strncmp(ddi_binding_name(pdip), "pseudo", sizeof ("pseudo")) == 0)
		return (0);

	/*
	 * If not attached, driver doesn't have to implement quiesce().
	 */
	if (!i_ddi_devi_attached(dip))
		return (0);

	/*
	 * If dip has no hardware property and skip_non_hw is set,
	 * driver doesn't have to implement quiesce().
	 */
	if (skip_non_hw && devi->devi_hw_prop_ptr == NULL)
		return (0);

	return (1);
}

static int
driver_has_quiesce(struct dev_ops *ops)
{
	if ((ops->devo_rev >= 4) && (ops->devo_quiesce != nodev) &&
	    (ops->devo_quiesce != NULL) && (ops->devo_quiesce != nulldev) &&
	    (ops->devo_quiesce != ddi_quiesce_not_supported))
		return (1);
	else
		return (0);
}

/*
 * Check to see if a driver has implemented the quiesce() DDI function.
 */
int
check_driver_quiesce(dev_info_t *dip, void *arg)
{
	struct dev_ops *ops;

	if (!should_implement_quiesce(dip))
		return (DDI_WALK_CONTINUE);

	if ((ops = ddi_get_driver(dip)) == NULL)
		return (DDI_WALK_CONTINUE);

	if (driver_has_quiesce(ops)) {
		if ((quiesce_debug & 0x2) == 0x2) {
			if (ops->devo_quiesce == ddi_quiesce_not_needed)
				cmn_err(CE_CONT, "%s does not need to be "
				    "quiesced", ddi_driver_name(dip));
			else
				cmn_err(CE_CONT, "%s has quiesce routine",
				    ddi_driver_name(dip));
		}
	} else {
		if (arg != NULL)
			*((int *)arg) = -1;
		cmn_err(CE_WARN, "%s has no quiesce()", ddi_driver_name(dip));
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * Quiesce device.
 */
static void
quiesce_one_device(dev_info_t *dip, void *arg)
{
	struct dev_ops *ops;
	int should_quiesce = 0;

	/*
	 * If the device is not attached it doesn't need to be quiesced.
	 */
	if (!i_ddi_devi_attached(dip))
		return;

	if ((ops = ddi_get_driver(dip)) == NULL)
		return;

	should_quiesce = should_implement_quiesce(dip);

	/*
	 * If there's an implementation of quiesce(), always call it even if
	 * some of the drivers don't have quiesce() or quiesce() have failed
	 * so we can do force fast reboot.  The implementation of quiesce()
	 * should not negatively affect a regular reboot.
	 */
	if (driver_has_quiesce(ops)) {
		int rc = DDI_SUCCESS;

		if (ops->devo_quiesce == ddi_quiesce_not_needed)
			return;

		rc = devi_quiesce(dip);

		if (rc != DDI_SUCCESS && should_quiesce) {
#ifdef DEBUG
			cmn_err(CE_WARN, "quiesce() failed for %s%d",
			    ddi_driver_name(dip), ddi_get_instance(dip));
#endif /* DEBUG */
			if (arg != NULL)
				*((int *)arg) = -1;
		}
	} else if (should_quiesce && arg != NULL) {
		*((int *)arg) = -1;
	}
}

/*
 * Traverse the dev info tree in a breadth-first manner so that we quiesce
 * children first.  All subtrees under the parent of dip will be quiesced.
 */
void
quiesce_devices(dev_info_t *dip, void *arg)
{
	/*
	 * if we're reached here, the device tree better not be changing.
	 * so either devinfo_freeze better be set or we better be panicing.
	 */
	ASSERT(devinfo_freeze || panicstr);

	for (; dip != NULL; dip = ddi_get_next_sibling(dip)) {
		quiesce_devices(ddi_get_child(dip), arg);

		quiesce_one_device(dip, arg);
	}
}

/*
 * Reset all the pure leaf drivers on the system at halt time
 */
static int
reset_leaf_device(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))
	struct dev_ops *ops;

	/* if the device doesn't need to be reset then there's nothing to do */
	if (!DEVI_NEED_RESET(dip))
		return (DDI_WALK_CONTINUE);

	/*
	 * if the device isn't a char/block device or doesn't have a
	 * reset entry point then there's nothing to do.
	 */
	ops = ddi_get_driver(dip);
	if ((ops == NULL) || (ops->devo_cb_ops == NULL) ||
	    (ops->devo_reset == nodev) || (ops->devo_reset == nulldev) ||
	    (ops->devo_reset == NULL))
		return (DDI_WALK_CONTINUE);

	if (DEVI_IS_ATTACHING(dip) || DEVI_IS_DETACHING(dip)) {
		static char path[MAXPATHLEN];

		/*
		 * bad news, this device has blocked in it's attach or
		 * detach routine, which means it not safe to call it's
		 * devo_reset() entry point.
		 */
		cmn_err(CE_WARN, "unable to reset device: %s",
		    ddi_pathname(dip, path));
		return (DDI_WALK_CONTINUE);
	}

	NDI_CONFIG_DEBUG((CE_NOTE, "resetting %s%d\n",
	    ddi_driver_name(dip), ddi_get_instance(dip)));

	(void) devi_reset(dip, DDI_RESET_FORCE);
	return (DDI_WALK_CONTINUE);
}

void
reset_leaves(void)
{
	/*
	 * if we're reached here, the device tree better not be changing.
	 * so either devinfo_freeze better be set or we better be panicing.
	 */
	ASSERT(devinfo_freeze || panicstr);

	(void) walk_devs(top_devinfo, reset_leaf_device, NULL, 0);
}


/*
 * devtree_freeze() must be called before quiesce_devices() and reset_leaves()
 * during a normal system shutdown.  It attempts to ensure that there are no
 * outstanding attach or detach operations in progress when quiesce_devices() or
 * reset_leaves()is invoked.  It must be called before the system becomes
 * single-threaded because device attach and detach are multi-threaded
 * operations.	(note that during system shutdown the system doesn't actually
 * become single-thread since other threads still exist, but the shutdown thread
 * will disable preemption for itself, raise it's pil, and stop all the other
 * cpus in the system there by effectively making the system single-threaded.)
 */
void
devtree_freeze(void)
{
	int delayed = 0;

	/* if we're panicing then the device tree isn't going to be changing */
	if (panicstr)
		return;

	/* stop all dev_info state changes in the device tree */
	devinfo_freeze = gethrtime();

	/*
	 * if we're not panicing and there are on-going attach or detach
	 * operations, wait for up to 3 seconds for them to finish.  This
	 * is a randomly chosen interval but this should be ok because:
	 * - 3 seconds is very small relative to the deadman timer.
	 * - normal attach and detach operations should be very quick.
	 * - attach and detach operations are fairly rare.
	 */
	while (!panicstr && atomic_add_long_nv(&devinfo_attach_detach, 0) &&
	    (delayed < 3)) {
		delayed += 1;

		/* do a sleeping wait for one second */
		ASSERT(!servicing_interrupt());
		delay(drv_usectohz(MICROSEC));
	}
}

static int
bind_dip(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))
	char	*path;
	major_t	major, pmajor;

	/*
	 * If the node is currently bound to the wrong driver, try to unbind
	 * so that we can rebind to the correct driver.
	 */
	if (i_ddi_node_state(dip) >= DS_BOUND) {
		major = ddi_compatible_driver_major(dip, NULL);
		if ((DEVI(dip)->devi_major == major) &&
		    (i_ddi_node_state(dip) >= DS_INITIALIZED)) {
			/*
			 * Check for a path-oriented driver alias that
			 * takes precedence over current driver binding.
			 */
			path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			(void) ddi_pathname(dip, path);
			pmajor = ddi_name_to_major(path);
			if (driver_active(pmajor))
				major = pmajor;
			kmem_free(path, MAXPATHLEN);
		}

		/* attempt unbind if current driver is incorrect */
		if (driver_active(major) &&
		    (major != DEVI(dip)->devi_major))
			(void) ndi_devi_unbind_driver(dip);
	}

	/* If unbound, try to bind to a driver */
	if (i_ddi_node_state(dip) < DS_BOUND)
		(void) ndi_devi_bind_driver(dip, 0);

	return (DDI_WALK_CONTINUE);
}

void
i_ddi_bind_devs(void)
{
	/* flush devfs so that ndi_devi_unbind_driver will work when possible */
	(void) devfs_clean(top_devinfo, NULL, 0);

	ddi_walk_devs(top_devinfo, bind_dip, (void *)NULL);
}

/* callback data for unbind_children_by_alias() */
typedef struct unbind_data {
	major_t	drv_major;
	char	*drv_alias;
	int	ndevs_bound;
	int	unbind_errors;
} unbind_data_t;

/*
 * A utility function provided for testing and support convenience
 * Called for each device during an upgrade_drv -d bound to the alias
 * that cannot be unbound due to device in use.
 */
static void
unbind_alias_dev_in_use(dev_info_t *dip, char *alias)
{
	if (moddebug & MODDEBUG_BINDING) {
		cmn_err(CE_CONT, "%s%d: state %d: bound to %s\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    i_ddi_node_state(dip), alias);
	}
}

/*
 * walkdevs callback for unbind devices bound to specific driver
 * and alias.  Invoked within the context of update_drv -d <alias>.
 */
static int
unbind_children_by_alias(dev_info_t *dip, void *arg)
{
	int		circ;
	dev_info_t	*cdip;
	dev_info_t	*next;
	unbind_data_t	*ub = (unbind_data_t *)(uintptr_t)arg;
	int		rv;

	/*
	 * We are called from update_drv to try to unbind a specific
	 * set of aliases for a driver.  Unbind what persistent nodes
	 * we can, and return the number of nodes which cannot be unbound.
	 * If not all nodes can be unbound, update_drv leaves the
	 * state of the driver binding files unchanged, except in
	 * the case of -f.
	 */
	ndi_devi_enter(dip, &circ);
	for (cdip = ddi_get_child(dip); cdip; cdip = next) {
		next = ddi_get_next_sibling(cdip);
		if ((ddi_driver_major(cdip) != ub->drv_major) ||
		    (strcmp(DEVI(cdip)->devi_node_name, ub->drv_alias) != 0))
			continue;
		if (i_ddi_node_state(cdip) >= DS_BOUND) {
			rv = ndi_devi_unbind_driver(cdip);
			if (rv != DDI_SUCCESS ||
			    (i_ddi_node_state(cdip) >= DS_BOUND)) {
				unbind_alias_dev_in_use(cdip, ub->drv_alias);
				ub->ndevs_bound++;
				continue;
			}
			if (ndi_dev_is_persistent_node(cdip) == 0)
				(void) ddi_remove_child(cdip, 0);
		}
	}
	ndi_devi_exit(dip, circ);

	return (DDI_WALK_CONTINUE);
}

/*
 * Unbind devices by driver & alias
 * Context: update_drv [-f] -d -i <alias> <driver>
 */
int
i_ddi_unbind_devs_by_alias(major_t major, char *alias)
{
	unbind_data_t	*ub;
	int		rv;

	ub = kmem_zalloc(sizeof (*ub), KM_SLEEP);
	ub->drv_major = major;
	ub->drv_alias = alias;
	ub->ndevs_bound = 0;
	ub->unbind_errors = 0;

	/* flush devfs so that ndi_devi_unbind_driver will work when possible */
	(void) devfs_clean(top_devinfo, NULL, 0);
	ddi_walk_devs(top_devinfo, unbind_children_by_alias,
	    (void *)(uintptr_t)ub);

	/* return the number of devices remaining bound to the alias */
	rv = ub->ndevs_bound + ub->unbind_errors;
	kmem_free(ub, sizeof (*ub));
	return (rv);
}

/*
 * walkdevs callback for unbind devices by driver
 */
static int
unbind_children_by_driver(dev_info_t *dip, void *arg)
{
	int		circ;
	dev_info_t	*cdip;
	dev_info_t	*next;
	major_t		major = (major_t)(uintptr_t)arg;
	int		rv;

	/*
	 * We are called either from rem_drv or update_drv when reloading
	 * a driver.conf file. In either case, we unbind persistent nodes
	 * and destroy .conf nodes. In the case of rem_drv, this will be
	 * the final state. In the case of update_drv,	i_ddi_bind_devs()
	 * may be invoked later to re-enumerate (new) driver.conf rebind
	 * persistent nodes.
	 */
	ndi_devi_enter(dip, &circ);
	for (cdip = ddi_get_child(dip); cdip; cdip = next) {
		next = ddi_get_next_sibling(cdip);
		if (ddi_driver_major(cdip) != major)
			continue;
		if (i_ddi_node_state(cdip) >= DS_BOUND) {
			rv = ndi_devi_unbind_driver(cdip);
			if (rv == DDI_FAILURE ||
			    (i_ddi_node_state(cdip) >= DS_BOUND))
				continue;
			if (ndi_dev_is_persistent_node(cdip) == 0)
				(void) ddi_remove_child(cdip, 0);
		}
	}
	ndi_devi_exit(dip, circ);

	return (DDI_WALK_CONTINUE);
}

/*
 * Unbind devices by driver
 * Context: rem_drv or unload driver.conf
 */
void
i_ddi_unbind_devs(major_t major)
{
	/* flush devfs so that ndi_devi_unbind_driver will work when possible */
	(void) devfs_clean(top_devinfo, NULL, 0);
	ddi_walk_devs(top_devinfo, unbind_children_by_driver,
	    (void *)(uintptr_t)major);
}

/*
 * I/O Hotplug control
 */

/*
 * create and attach a dev_info node from a .conf file spec
 */
static void
init_spec_child(dev_info_t *pdip, struct hwc_spec *specp, uint_t flags)
{
	_NOTE(ARGUNUSED(flags))
	dev_info_t *dip;
	char *node_name;

	if (((node_name = specp->hwc_devi_name) == NULL) ||
	    (ddi_name_to_major(node_name) == DDI_MAJOR_T_NONE)) {
		char *tmp = node_name;
		if (tmp == NULL)
			tmp = "<none>";
		cmn_err(CE_CONT,
		    "init_spec_child: parent=%s, bad spec (%s)\n",
		    ddi_node_name(pdip), tmp);
		return;
	}

	dip = i_ddi_alloc_node(pdip, node_name, (pnode_t)DEVI_PSEUDO_NODEID,
	    -1, specp->hwc_devi_sys_prop_ptr, KM_SLEEP);

	if (dip == NULL)
		return;

	if (ddi_initchild(pdip, dip) != DDI_SUCCESS)
		(void) ddi_remove_child(dip, 0);
}

/*
 * Lookup hwc specs from hash tables and make children from the spec
 * Because some .conf children are "merge" nodes, we also initialize
 * .conf children to merge properties onto hardware nodes.
 *
 * The pdip must be held busy.
 */
int
i_ndi_make_spec_children(dev_info_t *pdip, uint_t flags)
{
	extern struct hwc_spec *hwc_get_child_spec(dev_info_t *, major_t);
	int			circ;
	struct hwc_spec		*list, *spec;

	ndi_devi_enter(pdip, &circ);
	if (DEVI(pdip)->devi_flags & DEVI_MADE_CHILDREN) {
		ndi_devi_exit(pdip, circ);
		return (DDI_SUCCESS);
	}

	list = hwc_get_child_spec(pdip, DDI_MAJOR_T_NONE);
	for (spec = list; spec != NULL; spec = spec->hwc_next) {
		init_spec_child(pdip, spec, flags);
	}
	hwc_free_spec_list(list);

	mutex_enter(&DEVI(pdip)->devi_lock);
	DEVI(pdip)->devi_flags |= DEVI_MADE_CHILDREN;
	mutex_exit(&DEVI(pdip)->devi_lock);
	ndi_devi_exit(pdip, circ);
	return (DDI_SUCCESS);
}

/*
 * Run initchild on all child nodes such that instance assignment
 * for multiport network cards are contiguous.
 *
 * The pdip must be held busy.
 */
static void
i_ndi_init_hw_children(dev_info_t *pdip, uint_t flags)
{
	dev_info_t *dip;

	ASSERT(DEVI(pdip)->devi_flags & DEVI_MADE_CHILDREN);

	/* contiguous instance assignment */
	e_ddi_enter_instance();
	dip = ddi_get_child(pdip);
	while (dip) {
		if (ndi_dev_is_persistent_node(dip))
			(void) i_ndi_config_node(dip, DS_INITIALIZED, flags);
		dip = ddi_get_next_sibling(dip);
	}
	e_ddi_exit_instance();
}

/*
 * report device status
 */
static void
i_ndi_devi_report_status_change(dev_info_t *dip, char *path)
{
	char *status;

	if (!DEVI_NEED_REPORT(dip) ||
	    (i_ddi_node_state(dip) < DS_INITIALIZED) ||
	    ndi_dev_is_hidden_node(dip)) {
		return;
	}

	/* Invalidate the devinfo snapshot cache */
	i_ddi_di_cache_invalidate();

	if (DEVI_IS_DEVICE_REMOVED(dip)) {
		status = "removed";
	} else if (DEVI_IS_DEVICE_OFFLINE(dip)) {
		status = "offline";
	} else if (DEVI_IS_DEVICE_DOWN(dip)) {
		status = "down";
	} else if (DEVI_IS_BUS_QUIESCED(dip)) {
		status = "quiesced";
	} else if (DEVI_IS_BUS_DOWN(dip)) {
		status = "down";
	} else if (i_ddi_devi_attached(dip)) {
		status = "online";
	} else {
		status = "unknown";
	}

	if (path == NULL) {
		path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		cmn_err(CE_CONT, "?%s (%s%d) %s\n",
		    ddi_pathname(dip, path), ddi_driver_name(dip),
		    ddi_get_instance(dip), status);
		kmem_free(path, MAXPATHLEN);
	} else {
		cmn_err(CE_CONT, "?%s (%s%d) %s\n",
		    path, ddi_driver_name(dip),
		    ddi_get_instance(dip), status);
	}

	mutex_enter(&(DEVI(dip)->devi_lock));
	DEVI_REPORT_DONE(dip);
	mutex_exit(&(DEVI(dip)->devi_lock));
}

/*
 * log a notification that a dev_info node has been configured.
 */
static int
i_log_devfs_add_devinfo(dev_info_t *dip, uint_t flags)
{
	int			se_err;
	char			*pathname;
	sysevent_t		*ev;
	sysevent_id_t		eid;
	sysevent_value_t	se_val;
	sysevent_attr_list_t	*ev_attr_list = NULL;
	char			*class_name;
	int			no_transport = 0;

	ASSERT(dip && ddi_get_parent(dip) &&
	    DEVI_BUSY_OWNED(ddi_get_parent(dip)));

	/* do not generate ESC_DEVFS_DEVI_ADD event during boot */
	if (!i_ddi_io_initialized())
		return (DDI_SUCCESS);

	/* Invalidate the devinfo snapshot cache */
	i_ddi_di_cache_invalidate();

	ev = sysevent_alloc(EC_DEVFS, ESC_DEVFS_DEVI_ADD, EP_DDI, SE_SLEEP);

	pathname = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	(void) ddi_pathname(dip, pathname);
	ASSERT(strlen(pathname));

	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = pathname;
	if (sysevent_add_attr(&ev_attr_list, DEVFS_PATHNAME,
	    &se_val, SE_SLEEP) != 0) {
		goto fail;
	}

	/* add the device class attribute */
	if ((class_name = i_ddi_devi_class(dip)) != NULL) {
		se_val.value_type = SE_DATA_TYPE_STRING;
		se_val.value.sv_string = class_name;

		if (sysevent_add_attr(&ev_attr_list,
		    DEVFS_DEVI_CLASS, &se_val, SE_SLEEP) != 0) {
			sysevent_free_attr(ev_attr_list);
			goto fail;
		}
	}

	/*
	 * must log a branch event too unless NDI_BRANCH_EVENT_OP is set,
	 * in which case the branch event will be logged by the caller
	 * after the entire branch has been configured.
	 */
	if ((flags & NDI_BRANCH_EVENT_OP) == 0) {
		/*
		 * Instead of logging a separate branch event just add
		 * DEVFS_BRANCH_EVENT attribute. It indicates devfsadmd to
		 * generate a EC_DEV_BRANCH event.
		 */
		se_val.value_type = SE_DATA_TYPE_INT32;
		se_val.value.sv_int32 = 1;
		if (sysevent_add_attr(&ev_attr_list,
		    DEVFS_BRANCH_EVENT, &se_val, SE_SLEEP) != 0) {
			sysevent_free_attr(ev_attr_list);
			goto fail;
		}
	}

	if (sysevent_attach_attributes(ev, ev_attr_list) != 0) {
		sysevent_free_attr(ev_attr_list);
		goto fail;
	}

	if ((se_err = log_sysevent(ev, SE_SLEEP, &eid)) != 0) {
		if (se_err == SE_NO_TRANSPORT)
			no_transport = 1;
		goto fail;
	}

	sysevent_free(ev);
	kmem_free(pathname, MAXPATHLEN);

	return (DDI_SUCCESS);

fail:
	cmn_err(CE_WARN, "failed to log ESC_DEVFS_DEVI_ADD event for %s%s",
	    pathname, (no_transport) ? " (syseventd not responding)" : "");

	cmn_err(CE_WARN, "/dev may not be current for driver %s. "
	    "Run devfsadm -i %s",
	    ddi_driver_name(dip), ddi_driver_name(dip));

	sysevent_free(ev);
	kmem_free(pathname, MAXPATHLEN);
	return (DDI_SUCCESS);
}

/*
 * log a notification that a dev_info node has been unconfigured.
 */
static int
i_log_devfs_remove_devinfo(char *pathname, char *class_name, char *driver_name,
    int instance, uint_t flags)
{
	sysevent_t		*ev;
	sysevent_id_t		eid;
	sysevent_value_t	se_val;
	sysevent_attr_list_t	*ev_attr_list = NULL;
	int			se_err;
	int			no_transport = 0;

	if (!i_ddi_io_initialized())
		return (DDI_SUCCESS);

	/* Invalidate the devinfo snapshot cache */
	i_ddi_di_cache_invalidate();

	ev = sysevent_alloc(EC_DEVFS, ESC_DEVFS_DEVI_REMOVE, EP_DDI, SE_SLEEP);

	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = pathname;
	if (sysevent_add_attr(&ev_attr_list, DEVFS_PATHNAME,
	    &se_val, SE_SLEEP) != 0) {
		goto fail;
	}

	if (class_name) {
		/* add the device class, driver name and instance attributes */

		se_val.value_type = SE_DATA_TYPE_STRING;
		se_val.value.sv_string = class_name;
		if (sysevent_add_attr(&ev_attr_list,
		    DEVFS_DEVI_CLASS, &se_val, SE_SLEEP) != 0) {
			sysevent_free_attr(ev_attr_list);
			goto fail;
		}

		se_val.value_type = SE_DATA_TYPE_STRING;
		se_val.value.sv_string = driver_name;
		if (sysevent_add_attr(&ev_attr_list,
		    DEVFS_DRIVER_NAME, &se_val, SE_SLEEP) != 0) {
			sysevent_free_attr(ev_attr_list);
			goto fail;
		}

		se_val.value_type = SE_DATA_TYPE_INT32;
		se_val.value.sv_int32 = instance;
		if (sysevent_add_attr(&ev_attr_list,
		    DEVFS_INSTANCE, &se_val, SE_SLEEP) != 0) {
			sysevent_free_attr(ev_attr_list);
			goto fail;
		}
	}

	/*
	 * must log a branch event too unless NDI_BRANCH_EVENT_OP is set,
	 * in which case the branch event will be logged by the caller
	 * after the entire branch has been unconfigured.
	 */
	if ((flags & NDI_BRANCH_EVENT_OP) == 0) {
		/*
		 * Instead of logging a separate branch event just add
		 * DEVFS_BRANCH_EVENT attribute. It indicates devfsadmd to
		 * generate a EC_DEV_BRANCH event.
		 */
		se_val.value_type = SE_DATA_TYPE_INT32;
		se_val.value.sv_int32 = 1;
		if (sysevent_add_attr(&ev_attr_list,
		    DEVFS_BRANCH_EVENT, &se_val, SE_SLEEP) != 0) {
			sysevent_free_attr(ev_attr_list);
			goto fail;
		}
	}

	if (sysevent_attach_attributes(ev, ev_attr_list) != 0) {
		sysevent_free_attr(ev_attr_list);
		goto fail;
	}

	if ((se_err = log_sysevent(ev, SE_SLEEP, &eid)) != 0) {
		if (se_err == SE_NO_TRANSPORT)
			no_transport = 1;
		goto fail;
	}

	sysevent_free(ev);
	return (DDI_SUCCESS);

fail:
	sysevent_free(ev);
	cmn_err(CE_WARN, "failed to log ESC_DEVFS_DEVI_REMOVE event for %s%s",
	    pathname, (no_transport) ? " (syseventd not responding)" : "");
	return (DDI_SUCCESS);
}

static void
i_ddi_log_devfs_device_remove(dev_info_t *dip)
{
	char	*path;

	ASSERT(dip && ddi_get_parent(dip) &&
	    DEVI_BUSY_OWNED(ddi_get_parent(dip)));
	ASSERT(DEVI_IS_DEVICE_REMOVED(dip));

	ASSERT(i_ddi_node_state(dip) >= DS_INITIALIZED);
	if (i_ddi_node_state(dip) < DS_INITIALIZED)
		return;

	/* Inform LDI_EV_DEVICE_REMOVE callbacks. */
	ldi_invoke_finalize(dip, DDI_DEV_T_ANY, 0, LDI_EV_DEVICE_REMOVE,
	    LDI_EV_SUCCESS, NULL);

	/* Generate EC_DEVFS_DEVI_REMOVE sysevent. */
	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) i_log_devfs_remove_devinfo(ddi_pathname(dip, path),
	    i_ddi_devi_class(dip), (char *)ddi_driver_name(dip),
	    ddi_get_instance(dip), 0);
	kmem_free(path, MAXPATHLEN);
}

static void
i_ddi_log_devfs_device_insert(dev_info_t *dip)
{
	ASSERT(dip && ddi_get_parent(dip) &&
	    DEVI_BUSY_OWNED(ddi_get_parent(dip)));
	ASSERT(!DEVI_IS_DEVICE_REMOVED(dip));

	(void) i_log_devfs_add_devinfo(dip, 0);
}


/*
 * log an event that a dev_info branch has been configured or unconfigured.
 */
static int
i_log_devfs_branch(char *node_path, char *subclass)
{
	int se_err;
	sysevent_t *ev;
	sysevent_id_t eid;
	sysevent_value_t se_val;
	sysevent_attr_list_t *ev_attr_list = NULL;
	int no_transport = 0;

	/* do not generate the event during boot */
	if (!i_ddi_io_initialized())
		return (DDI_SUCCESS);

	/* Invalidate the devinfo snapshot cache */
	i_ddi_di_cache_invalidate();

	ev = sysevent_alloc(EC_DEVFS, subclass, EP_DDI, SE_SLEEP);

	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = node_path;

	if (sysevent_add_attr(&ev_attr_list, DEVFS_PATHNAME,
	    &se_val, SE_SLEEP) != 0) {
		goto fail;
	}

	if (sysevent_attach_attributes(ev, ev_attr_list) != 0) {
		sysevent_free_attr(ev_attr_list);
		goto fail;
	}

	if ((se_err = log_sysevent(ev, SE_SLEEP, &eid)) != 0) {
		if (se_err == SE_NO_TRANSPORT)
			no_transport = 1;
		goto fail;
	}

	sysevent_free(ev);
	return (DDI_SUCCESS);

fail:
	cmn_err(CE_WARN, "failed to log %s branch event for %s%s",
	    subclass, node_path,
	    (no_transport) ? " (syseventd not responding)" : "");

	sysevent_free(ev);
	return (DDI_FAILURE);
}

/*
 * log an event that a dev_info tree branch has been configured.
 */
static int
i_log_devfs_branch_add(dev_info_t *dip)
{
	char *node_path;
	int rv;

	node_path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, node_path);
	rv = i_log_devfs_branch(node_path, ESC_DEVFS_BRANCH_ADD);
	kmem_free(node_path, MAXPATHLEN);

	return (rv);
}

/*
 * log an event that a dev_info tree branch has been unconfigured.
 */
static int
i_log_devfs_branch_remove(char *node_path)
{
	return (i_log_devfs_branch(node_path, ESC_DEVFS_BRANCH_REMOVE));
}

/*
 * enqueue the dip's deviname on the branch event queue.
 */
static struct brevq_node *
brevq_enqueue(struct brevq_node **brevqp, dev_info_t *dip,
    struct brevq_node *child)
{
	struct brevq_node *brn;
	char *deviname;

	deviname = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) ddi_deviname(dip, deviname);

	brn = kmem_zalloc(sizeof (*brn), KM_SLEEP);
	brn->brn_deviname = i_ddi_strdup(deviname, KM_SLEEP);
	kmem_free(deviname, MAXNAMELEN);
	brn->brn_child = child;
	brn->brn_sibling = *brevqp;
	*brevqp = brn;

	return (brn);
}

/*
 * free the memory allocated for the elements on the branch event queue.
 */
static void
free_brevq(struct brevq_node *brevq)
{
	struct brevq_node *brn, *next_brn;

	for (brn = brevq; brn != NULL; brn = next_brn) {
		next_brn = brn->brn_sibling;
		ASSERT(brn->brn_child == NULL);
		kmem_free(brn->brn_deviname, strlen(brn->brn_deviname) + 1);
		kmem_free(brn, sizeof (*brn));
	}
}

/*
 * log the events queued up on the branch event queue and free the
 * associated memory.
 *
 * node_path must have been allocated with at least MAXPATHLEN bytes.
 */
static void
log_and_free_brevq(char *node_path, struct brevq_node *brevq)
{
	struct brevq_node *brn;
	char *p;

	p = node_path + strlen(node_path);
	for (brn = brevq; brn != NULL; brn = brn->brn_sibling) {
		(void) strcpy(p, brn->brn_deviname);
		(void) i_log_devfs_branch_remove(node_path);
	}
	*p = '\0';

	free_brevq(brevq);
}

/*
 * log the events queued up on the branch event queue and free the
 * associated memory. Same as the previous function but operates on dip.
 */
static void
log_and_free_brevq_dip(dev_info_t *dip, struct brevq_node *brevq)
{
	char *path;

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, path);
	log_and_free_brevq(path, brevq);
	kmem_free(path, MAXPATHLEN);
}

/*
 * log the outstanding branch remove events for the grand children of the dip
 * and free the associated memory.
 */
static void
log_and_free_br_events_on_grand_children(dev_info_t *dip,
    struct brevq_node *brevq)
{
	struct brevq_node *brn;
	char *path;
	char *p;

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, path);
	p = path + strlen(path);
	for (brn = brevq; brn != NULL; brn = brn->brn_sibling) {
		if (brn->brn_child) {
			(void) strcpy(p, brn->brn_deviname);
			/* now path contains the node path to the dip's child */
			log_and_free_brevq(path, brn->brn_child);
			brn->brn_child = NULL;
		}
	}
	kmem_free(path, MAXPATHLEN);
}

/*
 * log and cleanup branch remove events for the grand children of the dip.
 */
static void
cleanup_br_events_on_grand_children(dev_info_t *dip, struct brevq_node **brevqp)
{
	dev_info_t *child;
	struct brevq_node *brevq, *brn, *prev_brn, *next_brn;
	char *path;
	int circ;

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	prev_brn = NULL;
	brevq = *brevqp;

	ndi_devi_enter(dip, &circ);
	for (brn = brevq; brn != NULL; brn = next_brn) {
		next_brn = brn->brn_sibling;
		for (child = ddi_get_child(dip); child != NULL;
		    child = ddi_get_next_sibling(child)) {
			if (i_ddi_node_state(child) >= DS_INITIALIZED) {
				(void) ddi_deviname(child, path);
				if (strcmp(path, brn->brn_deviname) == 0)
					break;
			}
		}

		if (child != NULL && !(DEVI_EVREMOVE(child))) {
			/*
			 * Event state is not REMOVE. So branch remove event
			 * is not going be generated on brn->brn_child.
			 * If any branch remove events were queued up on
			 * brn->brn_child log them and remove the brn
			 * from the queue.
			 */
			if (brn->brn_child) {
				(void) ddi_pathname(dip, path);
				(void) strcat(path, brn->brn_deviname);
				log_and_free_brevq(path, brn->brn_child);
			}

			if (prev_brn)
				prev_brn->brn_sibling = next_brn;
			else
				*brevqp = next_brn;

			kmem_free(brn->brn_deviname,
			    strlen(brn->brn_deviname) + 1);
			kmem_free(brn, sizeof (*brn));
		} else {
			/*
			 * Free up the outstanding branch remove events
			 * queued on brn->brn_child since brn->brn_child
			 * itself is eligible for branch remove event.
			 */
			if (brn->brn_child) {
				free_brevq(brn->brn_child);
				brn->brn_child = NULL;
			}
			prev_brn = brn;
		}
	}

	ndi_devi_exit(dip, circ);
	kmem_free(path, MAXPATHLEN);
}

static int
need_remove_event(dev_info_t *dip, int flags)
{
	if ((flags & (NDI_NO_EVENT | NDI_AUTODETACH)) == 0 &&
	    (flags & (NDI_DEVI_OFFLINE | NDI_UNCONFIG | NDI_DEVI_REMOVE)) &&
	    !(DEVI_EVREMOVE(dip)))
		return (1);
	else
		return (0);
}

/*
 * Unconfigure children/descendants of the dip.
 *
 * If the operation involves a branch event NDI_BRANCH_EVENT_OP is set
 * through out the unconfiguration. On successful return *brevqp is set to
 * a queue of dip's child devinames for which branch remove events need
 * to be generated.
 */
static int
devi_unconfig_branch(dev_info_t *dip, dev_info_t **dipp, int flags,
    struct brevq_node **brevqp)
{
	int rval;

	*brevqp = NULL;

	if ((!(flags & NDI_BRANCH_EVENT_OP)) && need_remove_event(dip, flags))
		flags |= NDI_BRANCH_EVENT_OP;

	if (flags & NDI_BRANCH_EVENT_OP) {
		rval = devi_unconfig_common(dip, dipp, flags, DDI_MAJOR_T_NONE,
		    brevqp);

		if (rval != NDI_SUCCESS && (*brevqp)) {
			log_and_free_brevq_dip(dip, *brevqp);
			*brevqp = NULL;
		}
	} else
		rval = devi_unconfig_common(dip, dipp, flags, DDI_MAJOR_T_NONE,
		    NULL);

	return (rval);
}

/*
 * If the dip is already bound to a driver transition to DS_INITIALIZED
 * in order to generate an event in the case where the node was left in
 * DS_BOUND state since boot (never got attached) and the node is now
 * being offlined.
 */
static void
init_bound_node_ev(dev_info_t *pdip, dev_info_t *dip, int flags)
{
	if (need_remove_event(dip, flags) &&
	    i_ddi_node_state(dip) == DS_BOUND &&
	    i_ddi_devi_attached(pdip) && !DEVI_IS_DEVICE_OFFLINE(dip))
		(void) ddi_initchild(pdip, dip);
}

/*
 * attach a node/branch with parent already held busy
 */
static int
devi_attach_node(dev_info_t *dip, uint_t flags)
{
	dev_info_t *pdip = ddi_get_parent(dip);

	ASSERT(pdip && DEVI_BUSY_OWNED(pdip));

	mutex_enter(&(DEVI(dip)->devi_lock));
	if (flags & NDI_DEVI_ONLINE) {
		if (!i_ddi_devi_attached(dip))
			DEVI_SET_REPORT(dip);
		DEVI_SET_DEVICE_ONLINE(dip);
	}
	if (DEVI_IS_DEVICE_OFFLINE(dip)) {
		mutex_exit(&(DEVI(dip)->devi_lock));
		return (NDI_FAILURE);
	}
	mutex_exit(&(DEVI(dip)->devi_lock));

	if (i_ddi_attachchild(dip) != DDI_SUCCESS) {
		mutex_enter(&(DEVI(dip)->devi_lock));
		DEVI_SET_EVUNINIT(dip);
		mutex_exit(&(DEVI(dip)->devi_lock));

		if (ndi_dev_is_persistent_node(dip))
			(void) ddi_uninitchild(dip);
		else {
			/*
			 * Delete .conf nodes and nodes that are not
			 * well formed.
			 */
			(void) ddi_remove_child(dip, 0);
		}
		return (NDI_FAILURE);
	}

	i_ndi_devi_report_status_change(dip, NULL);

	/*
	 * log an event, but not during devfs lookups in which case
	 * NDI_NO_EVENT is set.
	 */
	if ((flags & NDI_NO_EVENT) == 0 && !(DEVI_EVADD(dip))) {
		(void) i_log_devfs_add_devinfo(dip, flags);

		mutex_enter(&(DEVI(dip)->devi_lock));
		DEVI_SET_EVADD(dip);
		mutex_exit(&(DEVI(dip)->devi_lock));
	} else if (!(flags & NDI_NO_EVENT_STATE_CHNG)) {
		mutex_enter(&(DEVI(dip)->devi_lock));
		DEVI_SET_EVADD(dip);
		mutex_exit(&(DEVI(dip)->devi_lock));
	}

	return (NDI_SUCCESS);
}

/* internal function to config immediate children */
static int
config_immediate_children(dev_info_t *pdip, uint_t flags, major_t major)
{
	dev_info_t	*child, *next;
	int		circ;

	ASSERT(i_ddi_devi_attached(pdip));

	if (!NEXUS_DRV(ddi_get_driver(pdip)))
		return (NDI_SUCCESS);

	NDI_CONFIG_DEBUG((CE_CONT,
	    "config_immediate_children: %s%d (%p), flags=%x\n",
	    ddi_driver_name(pdip), ddi_get_instance(pdip),
	    (void *)pdip, flags));

	ndi_devi_enter(pdip, &circ);

	if (flags & NDI_CONFIG_REPROBE) {
		mutex_enter(&DEVI(pdip)->devi_lock);
		DEVI(pdip)->devi_flags &= ~DEVI_MADE_CHILDREN;
		mutex_exit(&DEVI(pdip)->devi_lock);
	}
	(void) i_ndi_make_spec_children(pdip, flags);
	i_ndi_init_hw_children(pdip, flags);

	child = ddi_get_child(pdip);
	while (child) {
		/* NOTE: devi_attach_node() may remove the dip */
		next = ddi_get_next_sibling(child);

		/*
		 * Configure all nexus nodes or leaf nodes with
		 * matching driver major
		 */
		if ((major == DDI_MAJOR_T_NONE) ||
		    (major == ddi_driver_major(child)) ||
		    ((flags & NDI_CONFIG) && (is_leaf_node(child) == 0)))
			(void) devi_attach_node(child, flags);
		child = next;
	}

	ndi_devi_exit(pdip, circ);

	return (NDI_SUCCESS);
}

/* internal function to config grand children */
static int
config_grand_children(dev_info_t *pdip, uint_t flags, major_t major)
{
	struct mt_config_handle *hdl;

	/* multi-threaded configuration of child nexus */
	hdl = mt_config_init(pdip, NULL, flags, major, MT_CONFIG_OP, NULL);
	mt_config_children(hdl);

	return (mt_config_fini(hdl));	/* wait for threads to exit */
}

/*
 * Common function for device tree configuration,
 * either BUS_CONFIG_ALL or BUS_CONFIG_DRIVER.
 * The NDI_CONFIG flag causes recursive configuration of
 * grandchildren, devfs usage should not recurse.
 */
static int
devi_config_common(dev_info_t *dip, int flags, major_t major)
{
	int error;
	int (*f)();

	if (!i_ddi_devi_attached(dip))
		return (NDI_FAILURE);

	if (pm_pre_config(dip, NULL) != DDI_SUCCESS)
		return (NDI_FAILURE);

	if ((DEVI(dip)->devi_ops->devo_bus_ops == NULL) ||
	    (DEVI(dip)->devi_ops->devo_bus_ops->busops_rev < BUSO_REV_5) ||
	    (f = DEVI(dip)->devi_ops->devo_bus_ops->bus_config) == NULL) {
		error = config_immediate_children(dip, flags, major);
	} else {
		/* call bus_config entry point */
		ddi_bus_config_op_t bus_op = (major == DDI_MAJOR_T_NONE) ?
		    BUS_CONFIG_ALL : BUS_CONFIG_DRIVER;
		error = (*f)(dip,
		    flags, bus_op, (void *)(uintptr_t)major, NULL, 0);
	}

	if (error) {
		pm_post_config(dip, NULL);
		return (error);
	}

	/*
	 * Some callers, notably SCSI, need to mark the devfs cache
	 * to be rebuilt together with the config operation.
	 */
	if (flags & NDI_DEVFS_CLEAN)
		(void) devfs_clean(dip, NULL, 0);

	if (flags & NDI_CONFIG)
		(void) config_grand_children(dip, flags, major);

	pm_post_config(dip, NULL);

	return (NDI_SUCCESS);
}

/*
 * Framework entry point for BUS_CONFIG_ALL
 */
int
ndi_devi_config(dev_info_t *dip, int flags)
{
	NDI_CONFIG_DEBUG((CE_CONT,
	    "ndi_devi_config: par = %s%d (%p), flags = 0x%x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), (void *)dip, flags));

	return (devi_config_common(dip, flags, DDI_MAJOR_T_NONE));
}

/*
 * Framework entry point for BUS_CONFIG_DRIVER, bound to major
 */
int
ndi_devi_config_driver(dev_info_t *dip, int flags, major_t major)
{
	/* don't abuse this function */
	ASSERT(major != DDI_MAJOR_T_NONE);

	NDI_CONFIG_DEBUG((CE_CONT,
	    "ndi_devi_config_driver: par = %s%d (%p), flags = 0x%x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), (void *)dip, flags));

	return (devi_config_common(dip, flags, major));
}

/*
 * Called by nexus drivers to configure its children.
 */
static int
devi_config_one(dev_info_t *pdip, char *devnm, dev_info_t **cdipp,
    uint_t flags, clock_t timeout)
{
	dev_info_t	*vdip = NULL;
	char		*drivername = NULL;
	int		find_by_addr = 0;
	char		*name, *addr;
	int		v_circ, p_circ;
	clock_t		end_time;	/* 60 sec */
	int		probed;
	dev_info_t	*cdip;
	mdi_pathinfo_t	*cpip;

	*cdipp = NULL;

	if (!NEXUS_DRV(ddi_get_driver(pdip)))
		return (NDI_FAILURE);

	/* split name into "name@addr" parts */
	i_ddi_parse_name(devnm, &name, &addr, NULL);

	/*
	 * If the nexus is a pHCI and we are not processing a pHCI from
	 * mdi bus_config code then we need to know the vHCI.
	 */
	if (MDI_PHCI(pdip))
		vdip = mdi_devi_get_vdip(pdip);

	/*
	 * We may have a genericname on a system that creates drivername
	 * nodes (from .conf files).  Find the drivername by nodeid. If we
	 * can't find a node with devnm as the node name then we search by
	 * drivername.	This allows an implementation to supply a genericly
	 * named boot path (disk) and locate drivename nodes (sd).  The
	 * NDI_PROMNAME flag does not apply to /devices/pseudo paths.
	 */
	if ((flags & NDI_PROMNAME) && (pdip != pseudo_dip)) {
		drivername = child_path_to_driver(pdip, name, addr);
		find_by_addr = 1;
	}

	/*
	 * Determine end_time: This routine should *not* be called with a
	 * constant non-zero timeout argument, the caller should be adjusting
	 * the timeout argument relative to when it *started* its asynchronous
	 * enumeration.
	 */
	if (timeout > 0)
		end_time = ddi_get_lbolt() + timeout;

	for (;;) {
		/*
		 * For pHCI, enter (vHCI, pHCI) and search for pathinfo/client
		 * child - break out of for(;;) loop if child found.
		 * NOTE: Lock order for ndi_devi_enter is (vHCI, pHCI).
		 */
		if (vdip) {
			/* use mdi_devi_enter ordering */
			ndi_devi_enter(vdip, &v_circ);
			ndi_devi_enter(pdip, &p_circ);
			cpip = mdi_pi_find(pdip, NULL, addr);
			cdip = mdi_pi_get_client(cpip);
			if (cdip)
				break;
		} else
			ndi_devi_enter(pdip, &p_circ);

		/*
		 * When not a  vHCI or not all pHCI devices are required to
		 * enumerated under the vHCI (NDI_MDI_FALLBACK) search for
		 * devinfo child.
		 */
		if ((vdip == NULL) || (flags & NDI_MDI_FALLBACK)) {
			/* determine if .conf nodes already built */
			probed = (DEVI(pdip)->devi_flags & DEVI_MADE_CHILDREN);

			/*
			 * Search for child by name, if not found then search
			 * for a node bound to the drivername driver with the
			 * specified "@addr". Break out of for(;;) loop if
			 * child found.  To support path-oriented aliases
			 * binding on boot-device, we do a search_by_addr too.
			 */
again:			(void) i_ndi_make_spec_children(pdip, flags);
			cdip = find_child_by_name(pdip, name, addr);
			if ((cdip == NULL) && drivername)
				cdip = find_child_by_driver(pdip,
				    drivername, addr);
			if ((cdip == NULL) && find_by_addr)
				cdip = find_child_by_addr(pdip, addr);
			if (cdip)
				break;

			/*
			 * determine if we should reenumerate .conf nodes
			 * and look for child again.
			 */
			if (probed &&
			    i_ddi_io_initialized() &&
			    (flags & NDI_CONFIG_REPROBE) &&
			    ((timeout <= 0) || (ddi_get_lbolt() >= end_time))) {
				probed = 0;
				mutex_enter(&DEVI(pdip)->devi_lock);
				DEVI(pdip)->devi_flags &= ~DEVI_MADE_CHILDREN;
				mutex_exit(&DEVI(pdip)->devi_lock);
				goto again;
			}
		}

		/* break out of for(;;) if time expired */
		if ((timeout <= 0) || (ddi_get_lbolt() >= end_time))
			break;

		/*
		 * Child not found, exit and wait for asynchronous enumeration
		 * to add child (or timeout). The addition of a new child (vhci
		 * or phci) requires the asynchronous enumeration thread to
		 * ndi_devi_enter/ndi_devi_exit. This exit will signal devi_cv
		 * and cause us to return from ndi_devi_exit_and_wait, after
		 * which we loop and search for the requested child again.
		 */
		NDI_DEBUG(flags, (CE_CONT,
		    "%s%d: waiting for child %s@%s, timeout %ld",
		    ddi_driver_name(pdip), ddi_get_instance(pdip),
		    name, addr, timeout));
		if (vdip) {
			/*
			 * Mark vHCI for pHCI ndi_devi_exit broadcast.
			 */
			mutex_enter(&DEVI(vdip)->devi_lock);
			DEVI(vdip)->devi_flags |=
			    DEVI_PHCI_SIGNALS_VHCI;
			mutex_exit(&DEVI(vdip)->devi_lock);
			ndi_devi_exit(pdip, p_circ);

			/*
			 * NB: There is a small race window from above
			 * ndi_devi_exit() of pdip to cv_wait() in
			 * ndi_devi_exit_and_wait() which can result in
			 * not immediately finding a new pHCI child
			 * of a pHCI that uses NDI_MDI_FAILBACK.
			 */
			ndi_devi_exit_and_wait(vdip, v_circ, end_time);
		} else {
			ndi_devi_exit_and_wait(pdip, p_circ, end_time);
		}
	}

	/* done with paddr, fixup i_ddi_parse_name '@'->'\0' change */
	if (addr && *addr != '\0')
		*(addr - 1) = '@';

	/* attach and hold the child, returning pointer to child */
	if (cdip && (devi_attach_node(cdip, flags) == NDI_SUCCESS)) {
		ndi_hold_devi(cdip);
		*cdipp = cdip;
	}

	ndi_devi_exit(pdip, p_circ);
	if (vdip)
		ndi_devi_exit(vdip, v_circ);
	return (*cdipp ? NDI_SUCCESS : NDI_FAILURE);
}

/*
 * Enumerate and attach a child specified by name 'devnm'.
 * Called by devfs lookup and DR to perform a BUS_CONFIG_ONE.
 * Note: devfs does not make use of NDI_CONFIG to configure
 * an entire branch.
 */
int
ndi_devi_config_one(dev_info_t *pdip, char *devnm, dev_info_t **dipp, int flags)
{
	int error;
	int (*f)();
	char *nmdup;
	int duplen;
	int branch_event = 0;

	ASSERT(pdip);
	ASSERT(devnm);
	ASSERT(dipp);
	ASSERT(i_ddi_devi_attached(pdip));

	NDI_CONFIG_DEBUG((CE_CONT,
	    "ndi_devi_config_one: par = %s%d (%p), child = %s\n",
	    ddi_driver_name(pdip), ddi_get_instance(pdip),
	    (void *)pdip, devnm));

	*dipp = NULL;

	if (pm_pre_config(pdip, devnm) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "preconfig failed: %s", devnm);
		return (NDI_FAILURE);
	}

	if ((flags & (NDI_NO_EVENT | NDI_BRANCH_EVENT_OP)) == 0 &&
	    (flags & NDI_CONFIG)) {
		flags |= NDI_BRANCH_EVENT_OP;
		branch_event = 1;
	}

	nmdup = strdup(devnm);
	duplen = strlen(devnm) + 1;

	if ((DEVI(pdip)->devi_ops->devo_bus_ops == NULL) ||
	    (DEVI(pdip)->devi_ops->devo_bus_ops->busops_rev < BUSO_REV_5) ||
	    (f = DEVI(pdip)->devi_ops->devo_bus_ops->bus_config) == NULL) {
		error = devi_config_one(pdip, devnm, dipp, flags, 0);
	} else {
		/* call bus_config entry point */
		error = (*f)(pdip, flags, BUS_CONFIG_ONE, (void *)devnm, dipp);
	}

	if (error) {
		*dipp = NULL;
	}

	/*
	 * if we fail to lookup and this could be an alias, lookup currdip
	 * To prevent recursive lookups into the same hash table, only
	 * do the currdip lookups once the hash table init is complete.
	 * Use tsd so that redirection doesn't recurse
	 */
	if (error) {
		char *alias = kmem_alloc(MAXPATHLEN, KM_NOSLEEP);
		if (alias == NULL) {
			ddi_err(DER_PANIC, pdip, "alias alloc failed: %s",
			    nmdup);
		}
		(void) ddi_pathname(pdip, alias);
		(void) strlcat(alias, "/", MAXPATHLEN);
		(void) strlcat(alias, nmdup, MAXPATHLEN);

		*dipp = ddi_alias_redirect(alias);
		error = (*dipp ? NDI_SUCCESS : NDI_FAILURE);

		kmem_free(alias, MAXPATHLEN);
	}
	kmem_free(nmdup, duplen);

	if (error || !(flags & NDI_CONFIG)) {
		pm_post_config(pdip, devnm);
		return (error);
	}

	/*
	 * DR usage (i.e. call with NDI_CONFIG) recursively configures
	 * grandchildren, performing a BUS_CONFIG_ALL from the node attached
	 * by the BUS_CONFIG_ONE.
	 */
	ASSERT(*dipp);
	error = devi_config_common(*dipp, flags, DDI_MAJOR_T_NONE);

	pm_post_config(pdip, devnm);

	if (branch_event)
		(void) i_log_devfs_branch_add(*dipp);

	return (error);
}

/*
 * Enumerate and attach a child specified by name 'devnm'.
 * Called during configure the OBP options. This configures
 * only one node.
 */
static int
ndi_devi_config_obp_args(dev_info_t *parent, char *devnm,
    dev_info_t **childp, int flags)
{
	int error;
	int (*f)();

	ASSERT(childp);
	ASSERT(i_ddi_devi_attached(parent));

	NDI_CONFIG_DEBUG((CE_CONT, "ndi_devi_config_obp_args: "
	    "par = %s%d (%p), child = %s\n", ddi_driver_name(parent),
	    ddi_get_instance(parent), (void *)parent, devnm));

	if ((DEVI(parent)->devi_ops->devo_bus_ops == NULL) ||
	    (DEVI(parent)->devi_ops->devo_bus_ops->busops_rev < BUSO_REV_5) ||
	    (f = DEVI(parent)->devi_ops->devo_bus_ops->bus_config) == NULL) {
		error = NDI_FAILURE;
	} else {
		/* call bus_config entry point */
		error = (*f)(parent, flags,
		    BUS_CONFIG_OBP_ARGS, (void *)devnm, childp);
	}
	return (error);
}

/*
 * Pay attention, the following is a bit tricky:
 * There are three possible cases when constraints are applied
 *
 *	- A constraint is applied and the offline is disallowed.
 *	  Simply return failure and block the offline
 *
 *	- A constraint is applied and the offline is allowed.
 *	  Mark the dip as having passed the constraint and allow
 *	  offline to proceed.
 *
 *	- A constraint is not applied. Allow the offline to proceed for now.
 *
 * In the latter two cases we allow the offline to proceed. If the
 * offline succeeds (no users) everything is fine. It is ok for an unused
 * device to be offlined even if no constraints were imposed on the offline.
 * If the offline fails because there are users, we look at the constraint
 * flag on the dip. If the constraint flag is set (implying that it passed
 * a constraint) we allow the dip to be retired. If not, we don't allow
 * the retire. This ensures that we don't allow unconstrained retire.
 */
int
e_ddi_offline_notify(dev_info_t *dip)
{
	int retval;
	int constraint;
	int failure;

	RIO_VERBOSE((CE_NOTE, "e_ddi_offline_notify(): entered: dip=%p",
	    (void *) dip));

	constraint = 0;
	failure = 0;

	/*
	 * Start with userland constraints first - applied via device contracts
	 */
	retval = contract_device_offline(dip, DDI_DEV_T_ANY, 0);
	switch (retval) {
	case CT_NACK:
		RIO_DEBUG((CE_NOTE, "Received NACK for dip=%p", (void *)dip));
		failure = 1;
		goto out;
	case CT_ACK:
		constraint = 1;
		RIO_DEBUG((CE_NOTE, "Received ACK for dip=%p", (void *)dip));
		break;
	case CT_NONE:
		/* no contracts */
		RIO_DEBUG((CE_NOTE, "No contracts on dip=%p", (void *)dip));
		break;
	default:
		ASSERT(retval == CT_NONE);
	}

	/*
	 * Next, use LDI to impose kernel constraints
	 */
	retval = ldi_invoke_notify(dip, DDI_DEV_T_ANY, 0, LDI_EV_OFFLINE, NULL);
	switch (retval) {
	case LDI_EV_FAILURE:
		contract_device_negend(dip, DDI_DEV_T_ANY, 0, CT_EV_FAILURE);
		RIO_DEBUG((CE_NOTE, "LDI callback failed on dip=%p",
		    (void *)dip));
		failure = 1;
		goto out;
	case LDI_EV_SUCCESS:
		constraint = 1;
		RIO_DEBUG((CE_NOTE, "LDI callback success on dip=%p",
		    (void *)dip));
		break;
	case LDI_EV_NONE:
		/* no matching LDI callbacks */
		RIO_DEBUG((CE_NOTE, "No LDI callbacks for dip=%p",
		    (void *)dip));
		break;
	default:
		ASSERT(retval == LDI_EV_NONE);
	}

out:
	mutex_enter(&(DEVI(dip)->devi_lock));
	if ((DEVI(dip)->devi_flags & DEVI_RETIRING) && failure) {
		RIO_VERBOSE((CE_NOTE, "e_ddi_offline_notify(): setting "
		    "BLOCKED flag. dip=%p", (void *)dip));
		DEVI(dip)->devi_flags |= DEVI_R_BLOCKED;
		if (DEVI(dip)->devi_flags & DEVI_R_CONSTRAINT) {
			RIO_VERBOSE((CE_NOTE, "e_ddi_offline_notify(): "
			    "blocked. clearing RCM CONSTRAINT flag. dip=%p",
			    (void *)dip));
			DEVI(dip)->devi_flags &= ~DEVI_R_CONSTRAINT;
		}
	} else if ((DEVI(dip)->devi_flags & DEVI_RETIRING) && constraint) {
		RIO_VERBOSE((CE_NOTE, "e_ddi_offline_notify(): setting "
		    "CONSTRAINT flag. dip=%p", (void *)dip));
		DEVI(dip)->devi_flags |= DEVI_R_CONSTRAINT;
	} else if ((DEVI(dip)->devi_flags & DEVI_RETIRING) &&
	    ((DEVI(dip)->devi_ops != NULL &&
	    DEVI(dip)->devi_ops->devo_bus_ops != NULL) ||
	    DEVI(dip)->devi_ref == 0)) {
		/* also allow retire if nexus or if device is not in use */
		RIO_VERBOSE((CE_NOTE, "e_ddi_offline_notify(): device not in "
		    "use. Setting CONSTRAINT flag. dip=%p", (void *)dip));
		DEVI(dip)->devi_flags |= DEVI_R_CONSTRAINT;
	} else {
		/*
		 * Note: We cannot ASSERT here that DEVI_R_CONSTRAINT is
		 * not set, since other sources (such as RCM) may have
		 * set the flag.
		 */
		RIO_VERBOSE((CE_NOTE, "e_ddi_offline_notify(): not setting "
		    "constraint flag. dip=%p", (void *)dip));
	}
	mutex_exit(&(DEVI(dip)->devi_lock));


	RIO_VERBOSE((CE_NOTE, "e_ddi_offline_notify(): exit: dip=%p",
	    (void *) dip));

	return (failure ? DDI_FAILURE : DDI_SUCCESS);
}

void
e_ddi_offline_finalize(dev_info_t *dip, int result)
{
	RIO_DEBUG((CE_NOTE, "e_ddi_offline_finalize(): entry: result=%s, "
	    "dip=%p", result == DDI_SUCCESS ? "SUCCESS" : "FAILURE",
	    (void *)dip));

	contract_device_negend(dip, DDI_DEV_T_ANY, 0,  result == DDI_SUCCESS ?
	    CT_EV_SUCCESS : CT_EV_FAILURE);

	ldi_invoke_finalize(dip, DDI_DEV_T_ANY, 0,
	    LDI_EV_OFFLINE, result == DDI_SUCCESS ?
	    LDI_EV_SUCCESS : LDI_EV_FAILURE, NULL);

	RIO_VERBOSE((CE_NOTE, "e_ddi_offline_finalize(): exit: dip=%p",
	    (void *)dip));
}

void
e_ddi_degrade_finalize(dev_info_t *dip)
{
	RIO_DEBUG((CE_NOTE, "e_ddi_degrade_finalize(): entry: "
	    "result always = DDI_SUCCESS, dip=%p", (void *)dip));

	contract_device_degrade(dip, DDI_DEV_T_ANY, 0);
	contract_device_negend(dip, DDI_DEV_T_ANY, 0, CT_EV_SUCCESS);

	ldi_invoke_finalize(dip, DDI_DEV_T_ANY, 0, LDI_EV_DEGRADE,
	    LDI_EV_SUCCESS, NULL);

	RIO_VERBOSE((CE_NOTE, "e_ddi_degrade_finalize(): exit: dip=%p",
	    (void *)dip));
}

void
e_ddi_undegrade_finalize(dev_info_t *dip)
{
	RIO_DEBUG((CE_NOTE, "e_ddi_undegrade_finalize(): entry: "
	    "result always = DDI_SUCCESS, dip=%p", (void *)dip));

	contract_device_undegrade(dip, DDI_DEV_T_ANY, 0);
	contract_device_negend(dip, DDI_DEV_T_ANY, 0, CT_EV_SUCCESS);

	RIO_VERBOSE((CE_NOTE, "e_ddi_undegrade_finalize(): exit: dip=%p",
	    (void *)dip));
}

/*
 * detach a node with parent already held busy
 */
static int
devi_detach_node(dev_info_t *dip, uint_t flags)
{
	dev_info_t *pdip = ddi_get_parent(dip);
	int ret = NDI_SUCCESS;
	ddi_eventcookie_t cookie;
	char *path = NULL;
	char *class = NULL;
	char *driver = NULL;
	int instance = -1;
	int post_event = 0;

	ASSERT(pdip && DEVI_BUSY_OWNED(pdip));

	/*
	 * Invoke notify if offlining
	 */
	if (flags & NDI_DEVI_OFFLINE) {
		RIO_DEBUG((CE_NOTE, "devi_detach_node: offlining dip=%p",
		    (void *)dip));
		if (e_ddi_offline_notify(dip) != DDI_SUCCESS) {
			RIO_DEBUG((CE_NOTE, "devi_detach_node: offline NACKed"
			    "dip=%p", (void *)dip));
			return (NDI_FAILURE);
		}
	}

	if (flags & NDI_POST_EVENT) {
		if (i_ddi_devi_attached(pdip)) {
			if (ddi_get_eventcookie(dip, DDI_DEVI_REMOVE_EVENT,
			    &cookie) == NDI_SUCCESS)
				(void) ndi_post_event(dip, dip, cookie, NULL);
		}
	}

	/*
	 * dv_mknod places a hold on the dev_info_t for each devfs node
	 * created.  If we're to succeed in detaching this device, we must
	 * first release all outstanding references held by devfs.
	 */
	(void) devfs_clean(pdip, NULL, DV_CLEAN_FORCE);

	if (i_ddi_detachchild(dip, flags) != DDI_SUCCESS) {
		if (flags & NDI_DEVI_OFFLINE) {
			RIO_DEBUG((CE_NOTE, "devi_detach_node: offline failed."
			    " Calling e_ddi_offline_finalize with result=%d. "
			    "dip=%p", DDI_FAILURE, (void *)dip));
			e_ddi_offline_finalize(dip, DDI_FAILURE);
		}
		return (NDI_FAILURE);
	}

	if (flags & NDI_DEVI_OFFLINE) {
		RIO_DEBUG((CE_NOTE, "devi_detach_node: offline succeeded."
		    " Calling e_ddi_offline_finalize with result=%d, "
		    "dip=%p", DDI_SUCCESS, (void *)dip));
		e_ddi_offline_finalize(dip, DDI_SUCCESS);
	}

	if (flags & NDI_AUTODETACH)
		return (NDI_SUCCESS);

	/*
	 * For DR, even bound nodes may need to have offline
	 * flag set.
	 */
	if (flags & NDI_DEVI_OFFLINE) {
		mutex_enter(&(DEVI(dip)->devi_lock));
		DEVI_SET_DEVICE_OFFLINE(dip);
		mutex_exit(&(DEVI(dip)->devi_lock));
	}

	if (i_ddi_node_state(dip) == DS_INITIALIZED) {
		struct dev_info *devi = DEVI(dip);

		if (devi->devi_ev_path == NULL) {
			devi->devi_ev_path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			(void) ddi_pathname(dip, devi->devi_ev_path);
		}
		if (flags & NDI_DEVI_OFFLINE)
			i_ndi_devi_report_status_change(dip,
			    devi->devi_ev_path);

		if (need_remove_event(dip, flags)) {
			/*
			 * instance and path data are lost in call to
			 * ddi_uninitchild
			 */
			devi->devi_ev_instance = ddi_get_instance(dip);

			mutex_enter(&(DEVI(dip)->devi_lock));
			DEVI_SET_EVREMOVE(dip);
			mutex_exit(&(DEVI(dip)->devi_lock));
		}
	}

	if (flags & (NDI_UNCONFIG | NDI_DEVI_REMOVE)) {
		ret = ddi_uninitchild(dip);
		if (ret == NDI_SUCCESS) {
			/*
			 * Remove uninitialized pseudo nodes because
			 * system props are lost and the node cannot be
			 * reattached.
			 */
			if (!ndi_dev_is_persistent_node(dip))
				flags |= NDI_DEVI_REMOVE;

			if (flags & NDI_DEVI_REMOVE) {
				/*
				 * NOTE: If there is a consumer of LDI events,
				 * ddi_uninitchild above would have failed
				 * because of active devi_ref from ldi_open().
				 */

				if (DEVI_EVREMOVE(dip)) {
					path = i_ddi_strdup(
					    DEVI(dip)->devi_ev_path,
					    KM_SLEEP);
					class =
					    i_ddi_strdup(i_ddi_devi_class(dip),
					    KM_SLEEP);
					driver =
					    i_ddi_strdup(
					    (char *)ddi_driver_name(dip),
					    KM_SLEEP);
					instance = DEVI(dip)->devi_ev_instance;
					post_event = 1;
				}

				ret = ddi_remove_child(dip, 0);
				if (post_event && ret == NDI_SUCCESS) {
					/* Generate EC_DEVFS_DEVI_REMOVE */
					(void) i_log_devfs_remove_devinfo(path,
					    class, driver, instance, flags);
				}
			}

		}
	}

	if (path)
		strfree(path);
	if (class)
		strfree(class);
	if (driver)
		strfree(driver);

	return (ret);
}

/*
 * unconfigure immediate children of bus nexus device
 */
static int
unconfig_immediate_children(
	dev_info_t *dip,
	dev_info_t **dipp,
	int flags,
	major_t major)
{
	int rv = NDI_SUCCESS;
	int circ, vcirc;
	dev_info_t *child;
	dev_info_t *vdip = NULL;
	dev_info_t *next;

	ASSERT(dipp == NULL || *dipp == NULL);

	/*
	 * Scan forward to see if we will be processing a pHCI child. If we
	 * have a child that is a pHCI and vHCI and pHCI are not siblings then
	 * enter vHCI before parent(pHCI) to prevent deadlock with mpxio
	 * Client power management operations.
	 */
	ndi_devi_enter(dip, &circ);
	for (child = ddi_get_child(dip); child;
	    child = ddi_get_next_sibling(child)) {
		/* skip same nodes we skip below */
		if (((major != DDI_MAJOR_T_NONE) &&
		    (major != ddi_driver_major(child))) ||
		    ((flags & NDI_AUTODETACH) && !is_leaf_node(child)))
			continue;

		if (MDI_PHCI(child)) {
			vdip = mdi_devi_get_vdip(child);
			/*
			 * If vHCI and vHCI is not a sibling of pHCI
			 * then enter in (vHCI, parent(pHCI)) order.
			 */
			if (vdip && (ddi_get_parent(vdip) != dip)) {
				ndi_devi_exit(dip, circ);

				/* use mdi_devi_enter ordering */
				ndi_devi_enter(vdip, &vcirc);
				ndi_devi_enter(dip, &circ);
				break;
			} else
				vdip = NULL;
		}
	}

	child = ddi_get_child(dip);
	while (child) {
		next = ddi_get_next_sibling(child);

		if ((major != DDI_MAJOR_T_NONE) &&
		    (major != ddi_driver_major(child))) {
			child = next;
			continue;
		}

		/* skip nexus nodes during autodetach */
		if ((flags & NDI_AUTODETACH) && !is_leaf_node(child)) {
			child = next;
			continue;
		}

		if (devi_detach_node(child, flags) != NDI_SUCCESS) {
			if (dipp && *dipp == NULL) {
				ndi_hold_devi(child);
				*dipp = child;
			}
			rv = NDI_FAILURE;
		}

		/*
		 * Continue upon failure--best effort algorithm
		 */
		child = next;
	}

	ndi_devi_exit(dip, circ);
	if (vdip)
		ndi_devi_exit(vdip, vcirc);

	return (rv);
}

/*
 * unconfigure grand children of bus nexus device
 */
static int
unconfig_grand_children(
	dev_info_t *dip,
	dev_info_t **dipp,
	int flags,
	major_t major,
	struct brevq_node **brevqp)
{
	struct mt_config_handle *hdl;

	if (brevqp)
		*brevqp = NULL;

	/* multi-threaded configuration of child nexus */
	hdl = mt_config_init(dip, dipp, flags, major, MT_UNCONFIG_OP, brevqp);
	mt_config_children(hdl);

	return (mt_config_fini(hdl));	/* wait for threads to exit */
}

/*
 * Unconfigure children/descendants of the dip.
 *
 * If brevqp is not NULL, on return *brevqp is set to a queue of dip's
 * child devinames for which branch remove events need to be generated.
 */
static int
devi_unconfig_common(
	dev_info_t *dip,
	dev_info_t **dipp,
	int flags,
	major_t major,
	struct brevq_node **brevqp)
{
	int rv;
	int pm_cookie;
	int (*f)();
	ddi_bus_config_op_t bus_op;

	if (dipp)
		*dipp = NULL;
	if (brevqp)
		*brevqp = NULL;

	/*
	 * Power up the dip if it is powered off.  If the flag bit
	 * NDI_AUTODETACH is set and the dip is not at its full power,
	 * skip the rest of the branch.
	 */
	if (pm_pre_unconfig(dip, flags, &pm_cookie, NULL) != DDI_SUCCESS)
		return ((flags & NDI_AUTODETACH) ? NDI_SUCCESS :
		    NDI_FAILURE);

	/*
	 * Some callers, notably SCSI, need to clear out the devfs
	 * cache together with the unconfig to prevent stale entries.
	 */
	if (flags & NDI_DEVFS_CLEAN)
		(void) devfs_clean(dip, NULL, 0);

	rv = unconfig_grand_children(dip, dipp, flags, major, brevqp);

	if ((rv != NDI_SUCCESS) && ((flags & NDI_AUTODETACH) == 0)) {
		if (brevqp && *brevqp) {
			log_and_free_br_events_on_grand_children(dip, *brevqp);
			free_brevq(*brevqp);
			*brevqp = NULL;
		}
		pm_post_unconfig(dip, pm_cookie, NULL);
		return (rv);
	}

	if (dipp && *dipp) {
		ndi_rele_devi(*dipp);
		*dipp = NULL;
	}

	/*
	 * It is possible to have a detached nexus with children
	 * and grandchildren (for example: a branch consisting
	 * entirely of bound nodes.) Since the nexus is detached
	 * the bus_unconfig entry point cannot be used to remove
	 * or unconfigure the descendants.
	 */
	if (!i_ddi_devi_attached(dip) ||
	    (DEVI(dip)->devi_ops->devo_bus_ops == NULL) ||
	    (DEVI(dip)->devi_ops->devo_bus_ops->busops_rev < BUSO_REV_5) ||
	    (f = DEVI(dip)->devi_ops->devo_bus_ops->bus_unconfig) == NULL) {
		rv = unconfig_immediate_children(dip, dipp, flags, major);
	} else {
		/*
		 * call bus_unconfig entry point
		 * It should reset nexus flags if unconfigure succeeds.
		 */
		bus_op = (major == DDI_MAJOR_T_NONE) ?
		    BUS_UNCONFIG_ALL : BUS_UNCONFIG_DRIVER;
		rv = (*f)(dip, flags, bus_op, (void *)(uintptr_t)major);
	}

	pm_post_unconfig(dip, pm_cookie, NULL);

	if (brevqp && *brevqp)
		cleanup_br_events_on_grand_children(dip, brevqp);

	return (rv);
}

/*
 * called by devfs/framework to unconfigure children bound to major
 * If NDI_AUTODETACH is specified, this is invoked by either the
 * moduninstall daemon or the modunload -i 0 command.
 */
int
ndi_devi_unconfig_driver(dev_info_t *dip, int flags, major_t major)
{
	NDI_CONFIG_DEBUG((CE_CONT,
	    "ndi_devi_unconfig_driver: par = %s%d (%p), flags = 0x%x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), (void *)dip, flags));

	return (devi_unconfig_common(dip, NULL, flags, major, NULL));
}

int
ndi_devi_unconfig(dev_info_t *dip, int flags)
{
	NDI_CONFIG_DEBUG((CE_CONT,
	    "ndi_devi_unconfig: par = %s%d (%p), flags = 0x%x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), (void *)dip, flags));

	return (devi_unconfig_common(dip, NULL, flags, DDI_MAJOR_T_NONE, NULL));
}

int
e_ddi_devi_unconfig(dev_info_t *dip, dev_info_t **dipp, int flags)
{
	NDI_CONFIG_DEBUG((CE_CONT,
	    "e_ddi_devi_unconfig: par = %s%d (%p), flags = 0x%x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), (void *)dip, flags));

	return (devi_unconfig_common(dip, dipp, flags, DDI_MAJOR_T_NONE, NULL));
}

/*
 * Unconfigure child by name
 */
static int
devi_unconfig_one(dev_info_t *pdip, char *devnm, int flags)
{
	int		rv, circ;
	dev_info_t	*child;
	dev_info_t	*vdip = NULL;
	int		v_circ;

	ndi_devi_enter(pdip, &circ);
	child = ndi_devi_findchild(pdip, devnm);

	/*
	 * If child is pHCI and vHCI and pHCI are not siblings then enter vHCI
	 * before parent(pHCI) to avoid deadlock with mpxio Client power
	 * management operations.
	 */
	if (child && MDI_PHCI(child)) {
		vdip = mdi_devi_get_vdip(child);
		if (vdip && (ddi_get_parent(vdip) != pdip)) {
			ndi_devi_exit(pdip, circ);

			/* use mdi_devi_enter ordering */
			ndi_devi_enter(vdip, &v_circ);
			ndi_devi_enter(pdip, &circ);
			child = ndi_devi_findchild(pdip, devnm);
		} else
			vdip = NULL;
	}

	if (child) {
		rv = devi_detach_node(child, flags);
	} else {
		NDI_CONFIG_DEBUG((CE_CONT,
		    "devi_unconfig_one: %s not found\n", devnm));
		rv = NDI_SUCCESS;
	}

	ndi_devi_exit(pdip, circ);
	if (vdip)
		ndi_devi_exit(vdip, v_circ);

	return (rv);
}

int
ndi_devi_unconfig_one(
	dev_info_t *pdip,
	char *devnm,
	dev_info_t **dipp,
	int flags)
{
	int		(*f)();
	int		circ, rv;
	int		pm_cookie;
	dev_info_t	*child;
	dev_info_t	*vdip = NULL;
	int		v_circ;
	struct brevq_node *brevq = NULL;

	ASSERT(i_ddi_devi_attached(pdip));

	NDI_CONFIG_DEBUG((CE_CONT,
	    "ndi_devi_unconfig_one: par = %s%d (%p), child = %s\n",
	    ddi_driver_name(pdip), ddi_get_instance(pdip),
	    (void *)pdip, devnm));

	if (pm_pre_unconfig(pdip, flags, &pm_cookie, devnm) != DDI_SUCCESS)
		return (NDI_FAILURE);

	if (dipp)
		*dipp = NULL;

	ndi_devi_enter(pdip, &circ);
	child = ndi_devi_findchild(pdip, devnm);

	/*
	 * If child is pHCI and vHCI and pHCI are not siblings then enter vHCI
	 * before parent(pHCI) to avoid deadlock with mpxio Client power
	 * management operations.
	 */
	if (child && MDI_PHCI(child)) {
		vdip = mdi_devi_get_vdip(child);
		if (vdip && (ddi_get_parent(vdip) != pdip)) {
			ndi_devi_exit(pdip, circ);

			/* use mdi_devi_enter ordering */
			ndi_devi_enter(vdip, &v_circ);
			ndi_devi_enter(pdip, &circ);
			child = ndi_devi_findchild(pdip, devnm);
		} else
			vdip = NULL;
	}

	if (child == NULL) {
		NDI_CONFIG_DEBUG((CE_CONT, "ndi_devi_unconfig_one: %s"
		    " not found\n", devnm));
		rv = NDI_SUCCESS;
		goto out;
	}

	/*
	 * Unconfigure children/descendants of named child
	 */
	rv = devi_unconfig_branch(child, dipp, flags | NDI_UNCONFIG, &brevq);
	if (rv != NDI_SUCCESS)
		goto out;

	init_bound_node_ev(pdip, child, flags);

	if ((DEVI(pdip)->devi_ops->devo_bus_ops == NULL) ||
	    (DEVI(pdip)->devi_ops->devo_bus_ops->busops_rev < BUSO_REV_5) ||
	    (f = DEVI(pdip)->devi_ops->devo_bus_ops->bus_unconfig) == NULL) {
		rv = devi_detach_node(child, flags);
	} else {
		/* call bus_config entry point */
		rv = (*f)(pdip, flags, BUS_UNCONFIG_ONE, (void *)devnm);
	}

	if (brevq) {
		if (rv != NDI_SUCCESS)
			log_and_free_brevq_dip(child, brevq);
		else
			free_brevq(brevq);
	}

	if (dipp && rv != NDI_SUCCESS) {
		ndi_hold_devi(child);
		ASSERT(*dipp == NULL);
		*dipp = child;
	}

out:
	ndi_devi_exit(pdip, circ);
	if (vdip)
		ndi_devi_exit(vdip, v_circ);

	pm_post_unconfig(pdip, pm_cookie, devnm);

	return (rv);
}

struct async_arg {
	dev_info_t *dip;
	uint_t flags;
};

/*
 * Common async handler for:
 *	ndi_devi_bind_driver_async
 *	ndi_devi_online_async
 */
static int
i_ndi_devi_async_common(dev_info_t *dip, uint_t flags, void (*func)())
{
	int tqflag;
	int kmflag;
	struct async_arg *arg;
	dev_info_t *pdip = ddi_get_parent(dip);

	ASSERT(pdip);
	ASSERT(DEVI(pdip)->devi_taskq);
	ASSERT(ndi_dev_is_persistent_node(dip));

	if (flags & NDI_NOSLEEP) {
		kmflag = KM_NOSLEEP;
		tqflag = TQ_NOSLEEP;
	} else {
		kmflag = KM_SLEEP;
		tqflag = TQ_SLEEP;
	}

	arg = kmem_alloc(sizeof (*arg), kmflag);
	if (arg == NULL)
		goto fail;

	arg->flags = flags;
	arg->dip = dip;
	if (ddi_taskq_dispatch(DEVI(pdip)->devi_taskq, func, arg, tqflag) ==
	    DDI_SUCCESS) {
		return (NDI_SUCCESS);
	}

fail:
	NDI_CONFIG_DEBUG((CE_CONT, "%s%d: ddi_taskq_dispatch failed",
	    ddi_driver_name(pdip), ddi_get_instance(pdip)));

	if (arg)
		kmem_free(arg, sizeof (*arg));
	return (NDI_FAILURE);
}

static void
i_ndi_devi_bind_driver_cb(struct async_arg *arg)
{
	(void) ndi_devi_bind_driver(arg->dip, arg->flags);
	kmem_free(arg, sizeof (*arg));
}

int
ndi_devi_bind_driver_async(dev_info_t *dip, uint_t flags)
{
	return (i_ndi_devi_async_common(dip, flags,
	    (void (*)())i_ndi_devi_bind_driver_cb));
}

/*
 * place the devinfo in the ONLINE state.
 */
int
ndi_devi_online(dev_info_t *dip, uint_t flags)
{
	int circ, rv;
	dev_info_t *pdip = ddi_get_parent(dip);
	int branch_event = 0;

	ASSERT(pdip);

	NDI_CONFIG_DEBUG((CE_CONT, "ndi_devi_online: %s%d (%p)\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), (void *)dip));

	ndi_devi_enter(pdip, &circ);
	/* bind child before merging .conf nodes */
	rv = i_ndi_config_node(dip, DS_BOUND, flags);
	if (rv != NDI_SUCCESS) {
		ndi_devi_exit(pdip, circ);
		return (rv);
	}

	/* merge .conf properties */
	(void) i_ndi_make_spec_children(pdip, flags);

	flags |= (NDI_DEVI_ONLINE | NDI_CONFIG);

	if (flags & NDI_NO_EVENT) {
		/*
		 * Caller is specifically asking for not to generate an event.
		 * Set the following flag so that devi_attach_node() don't
		 * change the event state.
		 */
		flags |= NDI_NO_EVENT_STATE_CHNG;
	}

	if ((flags & (NDI_NO_EVENT | NDI_BRANCH_EVENT_OP)) == 0 &&
	    ((flags & NDI_CONFIG) || DEVI_NEED_NDI_CONFIG(dip))) {
		flags |= NDI_BRANCH_EVENT_OP;
		branch_event = 1;
	}

	/*
	 * devi_attach_node() may remove dip on failure
	 */
	if ((rv = devi_attach_node(dip, flags)) == NDI_SUCCESS) {
		if ((flags & NDI_CONFIG) || DEVI_NEED_NDI_CONFIG(dip)) {
			/*
			 * Hold the attached dip, and exit the parent while
			 * we drive configuration of children below the
			 * attached dip.
			 */
			ndi_hold_devi(dip);
			ndi_devi_exit(pdip, circ);

			(void) ndi_devi_config(dip, flags);

			ndi_devi_enter(pdip, &circ);
			ndi_rele_devi(dip);
		}

		if (branch_event)
			(void) i_log_devfs_branch_add(dip);
	}

	ndi_devi_exit(pdip, circ);

	/*
	 * Notify devfs that we have a new node. Devfs needs to invalidate
	 * cached directory contents.
	 *
	 * For PCMCIA devices, it is possible the pdip is not fully
	 * attached. In this case, calling back into devfs will
	 * result in a loop or assertion error. Hence, the check
	 * on node state.
	 *
	 * If we own parent lock, this is part of a branch operation.
	 * We skip the devfs_clean() step because the cache invalidation
	 * is done higher up in the device tree.
	 */
	if (rv == NDI_SUCCESS && i_ddi_devi_attached(pdip) &&
	    !DEVI_BUSY_OWNED(pdip))
		(void) devfs_clean(pdip, NULL, 0);
	return (rv);
}

static void
i_ndi_devi_online_cb(struct async_arg *arg)
{
	(void) ndi_devi_online(arg->dip, arg->flags);
	kmem_free(arg, sizeof (*arg));
}

int
ndi_devi_online_async(dev_info_t *dip, uint_t flags)
{
	/* mark child as need config if requested. */
	if (flags & NDI_CONFIG) {
		mutex_enter(&(DEVI(dip)->devi_lock));
		DEVI_SET_NDI_CONFIG(dip);
		mutex_exit(&(DEVI(dip)->devi_lock));
	}

	return (i_ndi_devi_async_common(dip, flags,
	    (void (*)())i_ndi_devi_online_cb));
}

/*
 * Take a device node Offline
 * To take a device Offline means to detach the device instance from
 * the driver and prevent devfs requests from re-attaching the device
 * instance.
 *
 * The flag NDI_DEVI_REMOVE causes removes the device node from
 * the driver list and the device tree. In this case, the device
 * is assumed to be removed from the system.
 */
int
ndi_devi_offline(dev_info_t *dip, uint_t flags)
{
	int		circ, rval = 0;
	dev_info_t	*pdip = ddi_get_parent(dip);
	dev_info_t	*vdip = NULL;
	int		v_circ;
	struct brevq_node *brevq = NULL;

	ASSERT(pdip);

	flags |= NDI_DEVI_OFFLINE;

	/*
	 * If child is pHCI and vHCI and pHCI are not siblings then enter vHCI
	 * before parent(pHCI) to avoid deadlock with mpxio Client power
	 * management operations.
	 */
	if (MDI_PHCI(dip)) {
		vdip = mdi_devi_get_vdip(dip);
		if (vdip && (ddi_get_parent(vdip) != pdip))
			ndi_devi_enter(vdip, &v_circ);
		else
			vdip = NULL;
	}
	ndi_devi_enter(pdip, &circ);

	if (i_ddi_devi_attached(dip)) {
		/*
		 * If dip is in DS_READY state, there may be cached dv_nodes
		 * referencing this dip, so we invoke devfs code path.
		 * Note that we must release busy changing on pdip to
		 * avoid deadlock against devfs.
		 */
		char *devname = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);
		(void) ddi_deviname(dip, devname);

		ndi_devi_exit(pdip, circ);
		if (vdip)
			ndi_devi_exit(vdip, v_circ);

		/*
		 * If we are explictly told to clean, then clean. If we own the
		 * parent lock then this is part of a branch operation, and we
		 * skip the devfs_clean() step.
		 *
		 * NOTE: A thread performing a devfs file system lookup/
		 * bus_config can't call devfs_clean to unconfig without
		 * causing rwlock problems in devfs. For ndi_devi_offline, this
		 * means that the NDI_DEVFS_CLEAN flag is safe from ioctl code
		 * or from an async hotplug thread, but is not safe from a
		 * nexus driver's bus_config implementation.
		 */
		if ((flags & NDI_DEVFS_CLEAN) ||
		    (!DEVI_BUSY_OWNED(pdip)))
			(void) devfs_clean(pdip, devname + 1, DV_CLEAN_FORCE);

		kmem_free(devname, MAXNAMELEN + 1);

		rval = devi_unconfig_branch(dip, NULL, flags|NDI_UNCONFIG,
		    &brevq);

		if (rval)
			return (NDI_FAILURE);

		if (vdip)
			ndi_devi_enter(vdip, &v_circ);
		ndi_devi_enter(pdip, &circ);
	}

	init_bound_node_ev(pdip, dip, flags);

	rval = devi_detach_node(dip, flags);
	if (brevq) {
		if (rval != NDI_SUCCESS)
			log_and_free_brevq_dip(dip, brevq);
		else
			free_brevq(brevq);
	}

	ndi_devi_exit(pdip, circ);
	if (vdip)
		ndi_devi_exit(vdip, v_circ);

	return (rval);
}

/*
 * Find the child dev_info node of parent nexus 'p' whose unit address
 * matches "cname@caddr".  Recommend use of ndi_devi_findchild() instead.
 */
dev_info_t *
ndi_devi_find(dev_info_t *pdip, char *cname, char *caddr)
{
	dev_info_t *child;
	int circ;

	if (pdip == NULL || cname == NULL || caddr == NULL)
		return ((dev_info_t *)NULL);

	ndi_devi_enter(pdip, &circ);
	child = find_sibling(ddi_get_child(pdip), cname, caddr,
	    FIND_NODE_BY_NODENAME, NULL);
	ndi_devi_exit(pdip, circ);
	return (child);
}

/*
 * Find the child dev_info node of parent nexus 'p' whose unit address
 * matches devname "name@addr".  Permits caller to hold the parent.
 */
dev_info_t *
ndi_devi_findchild(dev_info_t *pdip, char *devname)
{
	dev_info_t *child;
	char	*cname, *caddr;
	char	*devstr;

	ASSERT(DEVI_BUSY_OWNED(pdip));

	devstr = i_ddi_strdup(devname, KM_SLEEP);
	i_ddi_parse_name(devstr, &cname, &caddr, NULL);

	if (cname == NULL || caddr == NULL) {
		kmem_free(devstr, strlen(devname)+1);
		return ((dev_info_t *)NULL);
	}

	child = find_sibling(ddi_get_child(pdip), cname, caddr,
	    FIND_NODE_BY_NODENAME, NULL);
	kmem_free(devstr, strlen(devname)+1);
	return (child);
}

/*
 * Misc. routines called by framework only
 */

/*
 * Clear the DEVI_MADE_CHILDREN/DEVI_ATTACHED_CHILDREN flags
 * if new child spec has been added.
 */
static int
reset_nexus_flags(dev_info_t *dip, void *arg)
{
	struct hwc_spec	*list;
	int		circ;

	if (((DEVI(dip)->devi_flags & DEVI_MADE_CHILDREN) == 0) ||
	    ((list = hwc_get_child_spec(dip, (major_t)(uintptr_t)arg)) == NULL))
		return (DDI_WALK_CONTINUE);

	hwc_free_spec_list(list);

	/* coordinate child state update */
	ndi_devi_enter(dip, &circ);
	mutex_enter(&DEVI(dip)->devi_lock);
	DEVI(dip)->devi_flags &= ~(DEVI_MADE_CHILDREN | DEVI_ATTACHED_CHILDREN);
	mutex_exit(&DEVI(dip)->devi_lock);
	ndi_devi_exit(dip, circ);

	return (DDI_WALK_CONTINUE);
}

/*
 * Helper functions, returns NULL if no memory.
 */

/*
 * path_to_major:
 *
 * Return an alternate driver name binding for the leaf device
 * of the given pathname, if there is one. The purpose of this
 * function is to deal with generic pathnames. The default action
 * for platforms that can't do this (ie: x86 or any platform that
 * does not have prom_finddevice functionality, which matches
 * nodenames and unit-addresses without the drivers participation)
 * is to return DDI_MAJOR_T_NONE.
 *
 * Used in loadrootmodules() in the swapgeneric module to
 * associate a given pathname with a given leaf driver.
 *
 */
major_t
path_to_major(char *path)
{
	dev_info_t *dip;
	char *p, *q;
	pnode_t nodeid;
	major_t major;

	/* check for path-oriented alias */
	major = ddi_name_to_major(path);
	if (driver_active(major)) {
		NDI_CONFIG_DEBUG((CE_NOTE, "path_to_major: %s path bound %s\n",
		    path, ddi_major_to_name(major)));
		return (major);
	}

	/*
	 * Get the nodeid of the given pathname, if such a mapping exists.
	 */
	dip = NULL;
	nodeid = prom_finddevice(path);
	if (nodeid != OBP_BADNODE) {
		/*
		 * Find the nodeid in our copy of the device tree and return
		 * whatever name we used to bind this node to a driver.
		 */
		dip = e_ddi_nodeid_to_dip(nodeid);
	}

	if (dip == NULL) {
		NDI_CONFIG_DEBUG((CE_WARN,
		    "path_to_major: can't bind <%s>\n", path));
		return (DDI_MAJOR_T_NONE);
	}

	/*
	 * If we're bound to something other than the nodename,
	 * note that in the message buffer and system log.
	 */
	p = ddi_binding_name(dip);
	q = ddi_node_name(dip);
	if (p && q && (strcmp(p, q) != 0))
		NDI_CONFIG_DEBUG((CE_NOTE, "path_to_major: %s bound to %s\n",
		    path, p));

	major = ddi_name_to_major(p);

	ndi_rele_devi(dip);		/* release e_ddi_nodeid_to_dip hold */

	return (major);
}

/*
 * Return the held dip for the specified major and instance, attempting to do
 * an attach if specified. Return NULL if the devi can't be found or put in
 * the proper state. The caller must release the hold via ddi_release_devi if
 * a non-NULL value is returned.
 *
 * Some callers expect to be able to perform a hold_devi() while in a context
 * where using ndi_devi_enter() to ensure the hold might cause deadlock (see
 * open-from-attach code in consconfig_dacf.c). Such special-case callers
 * must ensure that an ndi_devi_enter(parent)/ndi_hold_devi() from a safe
 * context is already active. The hold_devi() implementation must accommodate
 * these callers.
 */
static dev_info_t *
hold_devi(major_t major, int instance, int flags)
{
	struct devnames	*dnp;
	dev_info_t	*dip;
	char		*path;
	char		*vpath;

	if ((major >= devcnt) || (instance == -1))
		return (NULL);

	/* try to find the instance in the per driver list */
	dnp = &(devnamesp[major]);
	LOCK_DEV_OPS(&(dnp->dn_lock));
	for (dip = dnp->dn_head; dip;
	    dip = (dev_info_t *)DEVI(dip)->devi_next) {
		/* skip node if instance field is not valid */
		if (i_ddi_node_state(dip) < DS_INITIALIZED)
			continue;

		/* look for instance match */
		if (DEVI(dip)->devi_instance == instance) {
			/*
			 * To accommodate callers that can't block in
			 * ndi_devi_enter() we do an ndi_hold_devi(), and
			 * afterwards check that the node is in a state where
			 * the hold prevents detach(). If we did not manage to
			 * prevent detach then we ndi_rele_devi() and perform
			 * the slow path below (which can result in a blocking
			 * ndi_devi_enter() while driving attach top-down).
			 * This code depends on the ordering of
			 * DEVI_SET_DETACHING and the devi_ref check in the
			 * detach_node() code path.
			 */
			ndi_hold_devi(dip);
			if (i_ddi_devi_attached(dip) &&
			    !DEVI_IS_DETACHING(dip)) {
				UNLOCK_DEV_OPS(&(dnp->dn_lock));
				return (dip);	/* fast-path with devi held */
			}
			ndi_rele_devi(dip);

			/* try slow-path */
			dip = NULL;
			break;
		}
	}
	ASSERT(dip == NULL);
	UNLOCK_DEV_OPS(&(dnp->dn_lock));

	if (flags & E_DDI_HOLD_DEVI_NOATTACH)
		return (NULL);		/* told not to drive attach */

	/* slow-path may block, so it should not occur from interrupt */
	ASSERT(!servicing_interrupt());
	if (servicing_interrupt())
		return (NULL);

	/* reconstruct the path and drive attach by path through devfs. */
	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (e_ddi_majorinstance_to_path(major, instance, path) == 0) {
		dip = e_ddi_hold_devi_by_path(path, flags);

		/*
		 * Verify that we got the correct device - a path_to_inst file
		 * with a bogus/corrupt path (or a nexus that changes its
		 * unit-address format) could result in an incorrect answer
		 *
		 * Verify major, instance, and path.
		 */
		vpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		if (dip &&
		    ((DEVI(dip)->devi_major != major) ||
		    ((DEVI(dip)->devi_instance != instance)) ||
		    (strcmp(path, ddi_pathname(dip, vpath)) != 0))) {
			ndi_rele_devi(dip);
			dip = NULL;	/* no answer better than wrong answer */
		}
		kmem_free(vpath, MAXPATHLEN);
	}
	kmem_free(path, MAXPATHLEN);
	return (dip);			/* with devi held */
}

/*
 * The {e_}ddi_hold_devi{_by_{instance|dev|path}} hold the devinfo node
 * associated with the specified arguments.  This hold should be released
 * by calling ddi_release_devi.
 *
 * The E_DDI_HOLD_DEVI_NOATTACH flag argument allows the caller to to specify
 * a failure return if the node is not already attached.
 *
 * NOTE: by the time we make e_ddi_hold_devi public, we should be able to reuse
 * ddi_hold_devi again.
 */
dev_info_t *
ddi_hold_devi_by_instance(major_t major, int instance, int flags)
{
	return (hold_devi(major, instance, flags));
}

dev_info_t *
e_ddi_hold_devi_by_dev(dev_t dev, int flags)
{
	major_t	major = getmajor(dev);
	dev_info_t	*dip;
	struct dev_ops	*ops;
	dev_info_t	*ddip = NULL;

	dip = hold_devi(major, dev_to_instance(dev), flags);

	/*
	 * The rest of this routine is legacy support for drivers that
	 * have broken DDI_INFO_DEVT2INSTANCE implementations but may have
	 * functional DDI_INFO_DEVT2DEVINFO implementations.  This code will
	 * diagnose inconsistency and, for maximum compatibility with legacy
	 * drivers, give preference to the drivers DDI_INFO_DEVT2DEVINFO
	 * implementation over the above derived dip based the driver's
	 * DDI_INFO_DEVT2INSTANCE implementation. This legacy support should
	 * be removed when DDI_INFO_DEVT2DEVINFO is deprecated.
	 *
	 * NOTE: The following code has a race condition. DEVT2DEVINFO
	 *	returns a dip which is not held. By the time we ref ddip,
	 *	it could have been freed. The saving grace is that for
	 *	most drivers, the dip returned from hold_devi() is the
	 *	same one as the one returned by DEVT2DEVINFO, so we are
	 *	safe for drivers with the correct getinfo(9e) impl.
	 */
	if (((ops = ddi_hold_driver(major)) != NULL) &&
	    CB_DRV_INSTALLED(ops) && ops->devo_getinfo)  {
		if ((*ops->devo_getinfo)(NULL, DDI_INFO_DEVT2DEVINFO,
		    (void *)dev, (void **)&ddip) != DDI_SUCCESS)
			ddip = NULL;
	}

	/* give preference to the driver returned DEVT2DEVINFO dip */
	if (ddip && (dip != ddip)) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "%s: inconsistent getinfo(9E) implementation",
		    ddi_driver_name(ddip));
#endif	/* DEBUG */
		ndi_hold_devi(ddip);
		if (dip)
			ndi_rele_devi(dip);
		dip = ddip;
	}

	if (ops)
		ddi_rele_driver(major);

	return (dip);
}

/*
 * For compatibility only. Do not call this function!
 */
dev_info_t *
e_ddi_get_dev_info(dev_t dev, vtype_t type)
{
	dev_info_t *dip = NULL;
	if (getmajor(dev) >= devcnt)
		return (NULL);

	switch (type) {
	case VCHR:
	case VBLK:
		dip = e_ddi_hold_devi_by_dev(dev, 0);
	default:
		break;
	}

	/*
	 * For compatibility reasons, we can only return the dip with
	 * the driver ref count held. This is not a safe thing to do.
	 * For certain broken third-party software, we are willing
	 * to venture into unknown territory.
	 */
	if (dip) {
		(void) ndi_hold_driver(dip);
		ndi_rele_devi(dip);
	}
	return (dip);
}

dev_info_t *
e_ddi_hold_devi_by_path(char *path, int flags)
{
	dev_info_t	*dip;

	/* can't specify NOATTACH by path */
	ASSERT(!(flags & E_DDI_HOLD_DEVI_NOATTACH));

	return (resolve_pathname(path, &dip, NULL, NULL) ? NULL : dip);
}

void
e_ddi_hold_devi(dev_info_t *dip)
{
	ndi_hold_devi(dip);
}

void
ddi_release_devi(dev_info_t *dip)
{
	ndi_rele_devi(dip);
}

/*
 * Associate a streams queue with a devinfo node
 * NOTE: This function is called by STREAM driver's put procedure.
 *	It cannot block.
 */
void
ddi_assoc_queue_with_devi(queue_t *q, dev_info_t *dip)
{
	queue_t *rq = _RD(q);
	struct stdata *stp;
	vnode_t *vp;

	/* set flag indicating that ddi_assoc_queue_with_devi was called */
	mutex_enter(QLOCK(rq));
	rq->q_flag |= _QASSOCIATED;
	mutex_exit(QLOCK(rq));

	/* get the vnode associated with the queue */
	stp = STREAM(rq);
	vp = stp->sd_vnode;
	ASSERT(vp);

	/* change the hardware association of the vnode */
	spec_assoc_vp_with_devi(vp, dip);
}

/*
 * ddi_install_driver(name)
 *
 * Driver installation is currently a byproduct of driver loading.  This
 * may change.
 */
int
ddi_install_driver(char *name)
{
	major_t major = ddi_name_to_major(name);

	if ((major == DDI_MAJOR_T_NONE) ||
	    (ddi_hold_installed_driver(major) == NULL)) {
		return (DDI_FAILURE);
	}
	ddi_rele_driver(major);
	return (DDI_SUCCESS);
}

struct dev_ops *
ddi_hold_driver(major_t major)
{
	return (mod_hold_dev_by_major(major));
}


void
ddi_rele_driver(major_t major)
{
	mod_rele_dev_by_major(major);
}


/*
 * This is called during boot to force attachment order of special dips
 * dip must be referenced via ndi_hold_devi()
 */
int
i_ddi_attach_node_hierarchy(dev_info_t *dip)
{
	dev_info_t	*parent;
	int		ret, circ;

	/*
	 * Recurse up until attached parent is found.
	 */
	if (i_ddi_devi_attached(dip))
		return (DDI_SUCCESS);
	parent = ddi_get_parent(dip);
	if (i_ddi_attach_node_hierarchy(parent) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Come top-down, expanding .conf nodes under this parent
	 * and driving attach.
	 */
	ndi_devi_enter(parent, &circ);
	(void) i_ndi_make_spec_children(parent, 0);
	ret = i_ddi_attachchild(dip);
	ndi_devi_exit(parent, circ);

	return (ret);
}

/* keep this function static */
static int
attach_driver_nodes(major_t major)
{
	struct devnames *dnp;
	dev_info_t *dip;
	int error = DDI_FAILURE;

	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);
	dip = dnp->dn_head;
	while (dip) {
		ndi_hold_devi(dip);
		UNLOCK_DEV_OPS(&dnp->dn_lock);
		if (i_ddi_attach_node_hierarchy(dip) == DDI_SUCCESS)
			error = DDI_SUCCESS;
		/*
		 * Set the 'ddi-config-driver-node' property on a nexus
		 * node to cause attach_driver_nodes() to configure all
		 * immediate children of the nexus. This property should
		 * be set on nodes with immediate children that bind to
		 * the same driver as parent.
		 */
		if ((error == DDI_SUCCESS) && (ddi_prop_exists(DDI_DEV_T_ANY,
		    dip, DDI_PROP_DONTPASS, "ddi-config-driver-node"))) {
			(void) ndi_devi_config(dip, NDI_NO_EVENT);
		}
		LOCK_DEV_OPS(&dnp->dn_lock);
		ndi_rele_devi(dip);
		dip = ddi_get_next(dip);
	}
	if (error == DDI_SUCCESS)
		dnp->dn_flags |= DN_NO_AUTODETACH;
	UNLOCK_DEV_OPS(&dnp->dn_lock);


	return (error);
}

/*
 * i_ddi_attach_hw_nodes configures and attaches all hw nodes
 * bound to a specific driver. This function replaces calls to
 * ddi_hold_installed_driver() for drivers with no .conf
 * enumerated nodes.
 *
 * This facility is typically called at boot time to attach
 * platform-specific hardware nodes, such as ppm nodes on xcal
 * and grover and keyswitch nodes on cherrystone. It does not
 * deal with .conf enumerated node. Calling it beyond the boot
 * process is strongly discouraged.
 */
int
i_ddi_attach_hw_nodes(char *driver)
{
	major_t major;

	major = ddi_name_to_major(driver);
	if (major == DDI_MAJOR_T_NONE)
		return (DDI_FAILURE);

	return (attach_driver_nodes(major));
}

/*
 * i_ddi_attach_pseudo_node configures pseudo drivers which
 * has a single node. The .conf nodes must be enumerated
 * before calling this interface. The dip is held attached
 * upon returning.
 *
 * This facility should only be called only at boot time
 * by the I/O framework.
 */
dev_info_t *
i_ddi_attach_pseudo_node(char *driver)
{
	major_t major;
	dev_info_t *dip;

	major = ddi_name_to_major(driver);
	if (major == DDI_MAJOR_T_NONE)
		return (NULL);

	if (attach_driver_nodes(major) != DDI_SUCCESS)
		return (NULL);

	dip = devnamesp[major].dn_head;
	ASSERT(dip && ddi_get_next(dip) == NULL);
	ndi_hold_devi(dip);
	return (dip);
}

static void
diplist_to_parent_major(dev_info_t *head, char parents[])
{
	major_t major;
	dev_info_t *dip, *pdip;

	for (dip = head; dip != NULL; dip = ddi_get_next(dip)) {
		pdip = ddi_get_parent(dip);
		ASSERT(pdip);	/* disallow rootnex.conf nodes */
		major = ddi_driver_major(pdip);
		if ((major != DDI_MAJOR_T_NONE) && parents[major] == 0)
			parents[major] = 1;
	}
}

/*
 * Call ddi_hold_installed_driver() on each parent major
 * and invoke mt_config_driver() to attach child major.
 * This is part of the implementation of ddi_hold_installed_driver.
 */
static int
attach_driver_by_parent(major_t child_major, char parents[])
{
	major_t par_major;
	struct mt_config_handle *hdl;
	int flags = NDI_DEVI_PERSIST | NDI_NO_EVENT;

	hdl = mt_config_init(NULL, NULL, flags, child_major, MT_CONFIG_OP,
	    NULL);
	for (par_major = 0; par_major < devcnt; par_major++) {
		/* disallow recursion on the same driver */
		if (parents[par_major] == 0 || par_major == child_major)
			continue;
		if (ddi_hold_installed_driver(par_major) == NULL)
			continue;
		hdl->mtc_parmajor = par_major;
		mt_config_driver(hdl);
		ddi_rele_driver(par_major);
	}
	(void) mt_config_fini(hdl);

	return (i_ddi_devs_attached(child_major));
}

int
i_ddi_devs_attached(major_t major)
{
	dev_info_t *dip;
	struct devnames *dnp;
	int error = DDI_FAILURE;

	/* check for attached instances */
	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);
	for (dip = dnp->dn_head; dip != NULL; dip = ddi_get_next(dip)) {
		if (i_ddi_devi_attached(dip)) {
			error = DDI_SUCCESS;
			break;
		}
	}
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	return (error);
}

int
i_ddi_minor_node_count(dev_info_t *ddip, const char *node_type)
{
	int			circ;
	struct ddi_minor_data	*dp;
	int			count = 0;

	ndi_devi_enter(ddip, &circ);
	for (dp = DEVI(ddip)->devi_minor; dp != NULL; dp = dp->next) {
		if (strcmp(dp->ddm_node_type, node_type) == 0)
			count++;
	}
	ndi_devi_exit(ddip, circ);
	return (count);
}

/*
 * ddi_hold_installed_driver configures and attaches all
 * instances of the specified driver. To accomplish this
 * it configures and attaches all possible parents of
 * the driver, enumerated both in h/w nodes and in the
 * driver's .conf file.
 *
 * NOTE: This facility is for compatibility purposes only and will
 *	eventually go away. Its usage is strongly discouraged.
 */
static void
enter_driver(struct devnames *dnp)
{
	mutex_enter(&dnp->dn_lock);
	ASSERT(dnp->dn_busy_thread != curthread);
	while (dnp->dn_flags & DN_DRIVER_BUSY)
		cv_wait(&dnp->dn_wait, &dnp->dn_lock);
	dnp->dn_flags |= DN_DRIVER_BUSY;
	dnp->dn_busy_thread = curthread;
	mutex_exit(&dnp->dn_lock);
}

static void
exit_driver(struct devnames *dnp)
{
	mutex_enter(&dnp->dn_lock);
	ASSERT(dnp->dn_busy_thread == curthread);
	dnp->dn_flags &= ~DN_DRIVER_BUSY;
	dnp->dn_busy_thread = NULL;
	cv_broadcast(&dnp->dn_wait);
	mutex_exit(&dnp->dn_lock);
}

struct dev_ops *
ddi_hold_installed_driver(major_t major)
{
	struct dev_ops *ops;
	struct devnames *dnp;
	char *parents;
	int error;

	ops = ddi_hold_driver(major);
	if (ops == NULL)
		return (NULL);

	/*
	 * Return immediately if all the attach operations associated
	 * with a ddi_hold_installed_driver() call have already been done.
	 */
	dnp = &devnamesp[major];
	enter_driver(dnp);
	ASSERT(driver_active(major));

	if (dnp->dn_flags & DN_DRIVER_HELD) {
		exit_driver(dnp);
		if (i_ddi_devs_attached(major) == DDI_SUCCESS)
			return (ops);
		ddi_rele_driver(major);
		return (NULL);
	}

	LOCK_DEV_OPS(&dnp->dn_lock);
	dnp->dn_flags |= (DN_DRIVER_HELD | DN_NO_AUTODETACH);
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	DCOMPATPRINTF((CE_CONT,
	    "ddi_hold_installed_driver: %s\n", dnp->dn_name));

	/*
	 * When the driver has no .conf children, it is sufficient
	 * to attach existing nodes in the device tree. Nodes not
	 * enumerated by the OBP are not attached.
	 */
	if (dnp->dn_pl == NULL) {
		if (attach_driver_nodes(major) == DDI_SUCCESS) {
			exit_driver(dnp);
			return (ops);
		}
		exit_driver(dnp);
		ddi_rele_driver(major);
		return (NULL);
	}

	/*
	 * Driver has .conf nodes. We find all possible parents
	 * and recursively all ddi_hold_installed_driver on the
	 * parent driver; then we invoke ndi_config_driver()
	 * on all possible parent node in parallel to speed up
	 * performance.
	 */
	parents = kmem_zalloc(devcnt * sizeof (char), KM_SLEEP);

	LOCK_DEV_OPS(&dnp->dn_lock);
	/* find .conf parents */
	(void) impl_parlist_to_major(dnp->dn_pl, parents);
	/* find hw node parents */
	diplist_to_parent_major(dnp->dn_head, parents);
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	error = attach_driver_by_parent(major, parents);
	kmem_free(parents, devcnt * sizeof (char));
	if (error == DDI_SUCCESS) {
		exit_driver(dnp);
		return (ops);
	}

	exit_driver(dnp);
	ddi_rele_driver(major);
	return (NULL);
}

/*
 * Default bus_config entry point for nexus drivers
 */
int
ndi_busop_bus_config(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **child, clock_t timeout)
{
	major_t major;

	/*
	 * A timeout of 30 minutes or more is probably a mistake
	 * This is intended to catch uses where timeout is in
	 * the wrong units.  timeout must be in units of ticks.
	 */
	ASSERT(timeout < SEC_TO_TICK(1800));

	major = DDI_MAJOR_T_NONE;
	switch (op) {
	case BUS_CONFIG_ONE:
		NDI_DEBUG(flags, (CE_CONT, "%s%d: bus config %s timeout=%ld\n",
		    ddi_driver_name(pdip), ddi_get_instance(pdip),
		    (char *)arg, timeout));
		return (devi_config_one(pdip, (char *)arg, child, flags,
		    timeout));

	case BUS_CONFIG_DRIVER:
		major = (major_t)(uintptr_t)arg;
		/*FALLTHROUGH*/
	case BUS_CONFIG_ALL:
		NDI_DEBUG(flags, (CE_CONT, "%s%d: bus config timeout=%ld\n",
		    ddi_driver_name(pdip), ddi_get_instance(pdip),
		    timeout));
		if (timeout > 0) {
			NDI_DEBUG(flags, (CE_CONT,
			    "%s%d: bus config all timeout=%ld\n",
			    ddi_driver_name(pdip), ddi_get_instance(pdip),
			    timeout));
			delay(timeout);
		}
		return (config_immediate_children(pdip, flags, major));

	default:
		return (NDI_FAILURE);
	}
	/*NOTREACHED*/
}

/*
 * Default busop bus_unconfig handler for nexus drivers
 */
int
ndi_busop_bus_unconfig(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg)
{
	major_t major;

	major = DDI_MAJOR_T_NONE;
	switch (op) {
	case BUS_UNCONFIG_ONE:
		NDI_DEBUG(flags, (CE_CONT, "%s%d: bus unconfig %s\n",
		    ddi_driver_name(pdip), ddi_get_instance(pdip),
		    (char *)arg));
		return (devi_unconfig_one(pdip, (char *)arg, flags));

	case BUS_UNCONFIG_DRIVER:
		major = (major_t)(uintptr_t)arg;
		/*FALLTHROUGH*/
	case BUS_UNCONFIG_ALL:
		NDI_DEBUG(flags, (CE_CONT, "%s%d: bus unconfig all\n",
		    ddi_driver_name(pdip), ddi_get_instance(pdip)));
		return (unconfig_immediate_children(pdip, NULL, flags, major));

	default:
		return (NDI_FAILURE);
	}
	/*NOTREACHED*/
}

/*
 * dummy functions to be removed
 */
void
impl_rem_dev_props(dev_info_t *dip)
{
	_NOTE(ARGUNUSED(dip))
	/* do nothing */
}

/*
 * Determine if a node is a leaf node. If not sure, return false (0).
 */
static int
is_leaf_node(dev_info_t *dip)
{
	major_t major = ddi_driver_major(dip);

	if (major == DDI_MAJOR_T_NONE)
		return (0);

	return (devnamesp[major].dn_flags & DN_LEAF_DRIVER);
}

/*
 * Multithreaded [un]configuration
 */
static struct mt_config_handle *
mt_config_init(dev_info_t *pdip, dev_info_t **dipp, int flags,
    major_t major, int op, struct brevq_node **brevqp)
{
	struct mt_config_handle	*hdl = kmem_alloc(sizeof (*hdl), KM_SLEEP);

	mutex_init(&hdl->mtc_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&hdl->mtc_cv, NULL, CV_DEFAULT, NULL);
	hdl->mtc_pdip = pdip;
	hdl->mtc_fdip = dipp;
	hdl->mtc_parmajor = DDI_MAJOR_T_NONE;
	hdl->mtc_flags = flags;
	hdl->mtc_major = major;
	hdl->mtc_thr_count = 0;
	hdl->mtc_op = op;
	hdl->mtc_error = 0;
	hdl->mtc_brevqp = brevqp;

#ifdef DEBUG
	gethrestime(&hdl->start_time);
	hdl->total_time = 0;
#endif /* DEBUG */

	return (hdl);
}

#ifdef DEBUG
static int
time_diff_in_msec(timestruc_t start, timestruc_t end)
{
	int	nsec, sec;

	sec = end.tv_sec - start.tv_sec;
	nsec = end.tv_nsec - start.tv_nsec;
	if (nsec < 0) {
		nsec += NANOSEC;
		sec -= 1;
	}

	return (sec * (NANOSEC >> 20) + (nsec >> 20));
}

#endif	/* DEBUG */

static int
mt_config_fini(struct mt_config_handle *hdl)
{
	int		rv;
#ifdef DEBUG
	int		real_time;
	timestruc_t	end_time;
#endif /* DEBUG */

	mutex_enter(&hdl->mtc_lock);
	while (hdl->mtc_thr_count > 0)
		cv_wait(&hdl->mtc_cv, &hdl->mtc_lock);
	rv = hdl->mtc_error;
	mutex_exit(&hdl->mtc_lock);

#ifdef DEBUG
	gethrestime(&end_time);
	real_time = time_diff_in_msec(hdl->start_time, end_time);
	if ((ddidebug & DDI_MTCONFIG) && hdl->mtc_pdip)
		cmn_err(CE_NOTE,
		    "config %s%d: total time %d msec, real time %d msec",
		    ddi_driver_name(hdl->mtc_pdip),
		    ddi_get_instance(hdl->mtc_pdip),
		    hdl->total_time, real_time);
#endif /* DEBUG */

	cv_destroy(&hdl->mtc_cv);
	mutex_destroy(&hdl->mtc_lock);
	kmem_free(hdl, sizeof (*hdl));

	return (rv);
}

struct mt_config_data {
	struct mt_config_handle	*mtc_hdl;
	dev_info_t		*mtc_dip;
	major_t			mtc_major;
	int			mtc_flags;
	struct brevq_node	*mtc_brn;
	struct mt_config_data	*mtc_next;
};

static void
mt_config_thread(void *arg)
{
	struct mt_config_data	*mcd = (struct mt_config_data *)arg;
	struct mt_config_handle	*hdl = mcd->mtc_hdl;
	dev_info_t		*dip = mcd->mtc_dip;
	dev_info_t		*rdip, **dipp;
	major_t			major = mcd->mtc_major;
	int			flags = mcd->mtc_flags;
	int			rv = 0;

#ifdef DEBUG
	timestruc_t start_time, end_time;
	gethrestime(&start_time);
#endif /* DEBUG */

	rdip = NULL;
	dipp = hdl->mtc_fdip ? &rdip : NULL;

	switch (hdl->mtc_op) {
	case MT_CONFIG_OP:
		rv = devi_config_common(dip, flags, major);
		break;
	case MT_UNCONFIG_OP:
		if (mcd->mtc_brn) {
			struct brevq_node *brevq = NULL;
			rv = devi_unconfig_common(dip, dipp, flags, major,
			    &brevq);
			mcd->mtc_brn->brn_child = brevq;
		} else
			rv = devi_unconfig_common(dip, dipp, flags, major,
			    NULL);
		break;
	}

	mutex_enter(&hdl->mtc_lock);
#ifdef DEBUG
	gethrestime(&end_time);
	hdl->total_time += time_diff_in_msec(start_time, end_time);
#endif /* DEBUG */

	if ((rv != NDI_SUCCESS) && (hdl->mtc_error == 0)) {
		hdl->mtc_error = rv;
#ifdef	DEBUG
		if ((ddidebug & DDI_DEBUG) && (major != DDI_MAJOR_T_NONE)) {
			char	*path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

			(void) ddi_pathname(dip, path);
			cmn_err(CE_NOTE, "mt_config_thread: "
			    "op %d.%d.%x at %s failed %d",
			    hdl->mtc_op, major, flags, path, rv);
			kmem_free(path, MAXPATHLEN);
		}
#endif	/* DEBUG */
	}

	if (hdl->mtc_fdip && *hdl->mtc_fdip == NULL) {
		*hdl->mtc_fdip = rdip;
		rdip = NULL;
	}

	if (rdip) {
		ASSERT(rv != NDI_SUCCESS);
		ndi_rele_devi(rdip);
	}

	ndi_rele_devi(dip);

	if (--hdl->mtc_thr_count == 0)
		cv_broadcast(&hdl->mtc_cv);
	mutex_exit(&hdl->mtc_lock);
	kmem_free(mcd, sizeof (*mcd));
}

/*
 * Multi-threaded config/unconfig of child nexus
 */
static void
mt_config_children(struct mt_config_handle *hdl)
{
	dev_info_t		*pdip = hdl->mtc_pdip;
	major_t			major = hdl->mtc_major;
	dev_info_t		*dip;
	int			circ;
	struct brevq_node	*brn;
	struct mt_config_data	*mcd_head = NULL;
	struct mt_config_data	*mcd_tail = NULL;
	struct mt_config_data	*mcd;
#ifdef DEBUG
	timestruc_t		end_time;

	/* Update total_time in handle */
	gethrestime(&end_time);
	hdl->total_time += time_diff_in_msec(hdl->start_time, end_time);
#endif

	ndi_devi_enter(pdip, &circ);
	dip = ddi_get_child(pdip);
	while (dip) {
		if (hdl->mtc_op == MT_UNCONFIG_OP && hdl->mtc_brevqp &&
		    !(DEVI_EVREMOVE(dip)) &&
		    i_ddi_node_state(dip) >= DS_INITIALIZED) {
			/*
			 * Enqueue this dip's deviname.
			 * No need to hold a lock while enqueuing since this
			 * is the only thread doing the enqueue and no one
			 * walks the queue while we are in multithreaded
			 * unconfiguration.
			 */
			brn = brevq_enqueue(hdl->mtc_brevqp, dip, NULL);
		} else
			brn = NULL;

		/*
		 * Hold the child that we are processing so he does not get
		 * removed. The corrisponding ndi_rele_devi() for children
		 * that are not being skipped is done at the end of
		 * mt_config_thread().
		 */
		ndi_hold_devi(dip);

		/*
		 * skip leaf nodes and (for configure) nodes not
		 * fully attached.
		 */
		if (is_leaf_node(dip) ||
		    (hdl->mtc_op == MT_CONFIG_OP &&
		    i_ddi_node_state(dip) < DS_READY)) {
			ndi_rele_devi(dip);
			dip = ddi_get_next_sibling(dip);
			continue;
		}

		mcd = kmem_alloc(sizeof (*mcd), KM_SLEEP);
		mcd->mtc_dip = dip;
		mcd->mtc_hdl = hdl;
		mcd->mtc_brn = brn;

		/*
		 * Switch a 'driver' operation to an 'all' operation below a
		 * node bound to the driver.
		 */
		if ((major == DDI_MAJOR_T_NONE) ||
		    (major == ddi_driver_major(dip)))
			mcd->mtc_major = DDI_MAJOR_T_NONE;
		else
			mcd->mtc_major = major;

		/*
		 * The unconfig-driver to unconfig-all conversion above
		 * constitutes an autodetach for NDI_DETACH_DRIVER calls,
		 * set NDI_AUTODETACH.
		 */
		mcd->mtc_flags = hdl->mtc_flags;
		if ((mcd->mtc_flags & NDI_DETACH_DRIVER) &&
		    (hdl->mtc_op == MT_UNCONFIG_OP) &&
		    (major == ddi_driver_major(pdip)))
			mcd->mtc_flags |= NDI_AUTODETACH;

		mutex_enter(&hdl->mtc_lock);
		hdl->mtc_thr_count++;
		mutex_exit(&hdl->mtc_lock);

		/*
		 * Add to end of list to process after ndi_devi_exit to avoid
		 * locking differences depending on value of mtc_off.
		 */
		mcd->mtc_next = NULL;
		if (mcd_head == NULL)
			mcd_head = mcd;
		else
			mcd_tail->mtc_next = mcd;
		mcd_tail = mcd;

		dip = ddi_get_next_sibling(dip);
	}
	ndi_devi_exit(pdip, circ);

	/* go through the list of held children */
	for (mcd = mcd_head; mcd; mcd = mcd_head) {
		mcd_head = mcd->mtc_next;
		if (mtc_off || (mcd->mtc_flags & NDI_MTC_OFF))
			mt_config_thread(mcd);
		else
			(void) thread_create(NULL, 0, mt_config_thread, mcd,
			    0, &p0, TS_RUN, minclsyspri);
	}
}

static void
mt_config_driver(struct mt_config_handle *hdl)
{
	major_t			par_major = hdl->mtc_parmajor;
	major_t			major = hdl->mtc_major;
	struct devnames		*dnp = &devnamesp[par_major];
	dev_info_t		*dip;
	struct mt_config_data	*mcd_head = NULL;
	struct mt_config_data	*mcd_tail = NULL;
	struct mt_config_data	*mcd;
#ifdef DEBUG
	timestruc_t		end_time;

	/* Update total_time in handle */
	gethrestime(&end_time);
	hdl->total_time += time_diff_in_msec(hdl->start_time, end_time);
#endif
	ASSERT(par_major != DDI_MAJOR_T_NONE);
	ASSERT(major != DDI_MAJOR_T_NONE);

	LOCK_DEV_OPS(&dnp->dn_lock);
	dip = devnamesp[par_major].dn_head;
	while (dip) {
		/*
		 * Hold the child that we are processing so he does not get
		 * removed. The corrisponding ndi_rele_devi() for children
		 * that are not being skipped is done at the end of
		 * mt_config_thread().
		 */
		ndi_hold_devi(dip);

		/* skip leaf nodes and nodes not fully attached */
		if (!i_ddi_devi_attached(dip) || is_leaf_node(dip)) {
			ndi_rele_devi(dip);
			dip = ddi_get_next(dip);
			continue;
		}

		mcd = kmem_alloc(sizeof (*mcd), KM_SLEEP);
		mcd->mtc_dip = dip;
		mcd->mtc_hdl = hdl;
		mcd->mtc_major = major;
		mcd->mtc_flags = hdl->mtc_flags;

		mutex_enter(&hdl->mtc_lock);
		hdl->mtc_thr_count++;
		mutex_exit(&hdl->mtc_lock);

		/*
		 * Add to end of list to process after UNLOCK_DEV_OPS to avoid
		 * locking differences depending on value of mtc_off.
		 */
		mcd->mtc_next = NULL;
		if (mcd_head == NULL)
			mcd_head = mcd;
		else
			mcd_tail->mtc_next = mcd;
		mcd_tail = mcd;

		dip = ddi_get_next(dip);
	}
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	/* go through the list of held children */
	for (mcd = mcd_head; mcd; mcd = mcd_head) {
		mcd_head = mcd->mtc_next;
		if (mtc_off || (mcd->mtc_flags & NDI_MTC_OFF))
			mt_config_thread(mcd);
		else
			(void) thread_create(NULL, 0, mt_config_thread, mcd,
			    0, &p0, TS_RUN, minclsyspri);
	}
}

/*
 * Given the nodeid for a persistent (PROM or SID) node, return
 * the corresponding devinfo node
 * NOTE: This function will return NULL for .conf nodeids.
 */
dev_info_t *
e_ddi_nodeid_to_dip(pnode_t nodeid)
{
	dev_info_t		*dip = NULL;
	struct devi_nodeid	*prev, *elem;

	mutex_enter(&devimap->dno_lock);

	prev = NULL;
	for (elem = devimap->dno_head; elem; elem = elem->next) {
		if (elem->nodeid == nodeid) {
			ndi_hold_devi(elem->dip);
			dip = elem->dip;
			break;
		}
		prev = elem;
	}

	/*
	 * Move to head for faster lookup next time
	 */
	if (elem && prev) {
		prev->next = elem->next;
		elem->next = devimap->dno_head;
		devimap->dno_head = elem;
	}

	mutex_exit(&devimap->dno_lock);
	return (dip);
}

static void
free_cache_task(void *arg)
{
	ASSERT(arg == NULL);

	mutex_enter(&di_cache.cache_lock);

	/*
	 * The cache can be invalidated without holding the lock
	 * but it can be made valid again only while the lock is held.
	 * So if the cache is invalid when the lock is held, it will
	 * stay invalid until lock is released.
	 */
	if (!di_cache.cache_valid)
		i_ddi_di_cache_free(&di_cache);

	mutex_exit(&di_cache.cache_lock);

	if (di_cache_debug)
		cmn_err(CE_NOTE, "system_taskq: di_cache freed");
}

extern int modrootloaded;

void
i_ddi_di_cache_free(struct di_cache *cache)
{
	int	error;
	extern int sys_shutdown;

	ASSERT(mutex_owned(&cache->cache_lock));

	if (cache->cache_size) {
		ASSERT(cache->cache_size > 0);
		ASSERT(cache->cache_data);

		kmem_free(cache->cache_data, cache->cache_size);
		cache->cache_data = NULL;
		cache->cache_size = 0;

		if (di_cache_debug)
			cmn_err(CE_NOTE, "i_ddi_di_cache_free: freed cachemem");
	} else {
		ASSERT(cache->cache_data == NULL);
		if (di_cache_debug)
			cmn_err(CE_NOTE, "i_ddi_di_cache_free: NULL cache");
	}

	if (!modrootloaded || rootvp == NULL ||
	    vn_is_readonly(rootvp) || sys_shutdown) {
		if (di_cache_debug) {
			cmn_err(CE_WARN, "/ not mounted/RDONLY. Skip unlink");
		}
		return;
	}

	error = vn_remove(DI_CACHE_FILE, UIO_SYSSPACE, RMFILE);
	if (di_cache_debug && error && error != ENOENT) {
		cmn_err(CE_WARN, "%s: unlink failed: %d", DI_CACHE_FILE, error);
	} else if (di_cache_debug && !error) {
		cmn_err(CE_NOTE, "i_ddi_di_cache_free: unlinked cache file");
	}
}

void
i_ddi_di_cache_invalidate()
{
	int	cache_valid;

	if (!modrootloaded || !i_ddi_io_initialized()) {
		if (di_cache_debug)
			cmn_err(CE_NOTE, "I/O not inited. Skipping invalidate");
		return;
	}

	/* Increment devtree generation number. */
	atomic_inc_ulong(&devtree_gen);

	/* Invalidate the in-core cache and dispatch free on valid->invalid */
	cache_valid = atomic_swap_uint(&di_cache.cache_valid, 0);
	if (cache_valid) {
		/*
		 * This is an optimization to start cleaning up a cached
		 * snapshot early.  For this reason, it is OK for
		 * taskq_dispatach to fail (and it is OK to not track calling
		 * context relative to sleep, and assume NOSLEEP).
		 */
		(void) taskq_dispatch(system_taskq, free_cache_task, NULL,
		    TQ_NOSLEEP);
	}

	if (di_cache_debug) {
		cmn_err(CE_NOTE, "invalidation");
	}
}


static void
i_bind_vhci_node(dev_info_t *dip)
{
	DEVI(dip)->devi_major = ddi_name_to_major(ddi_node_name(dip));
	i_ddi_set_node_state(dip, DS_BOUND);
}

static char vhci_node_addr[2];

static int
i_init_vhci_node(dev_info_t *dip)
{
	add_global_props(dip);
	DEVI(dip)->devi_ops = ndi_hold_driver(dip);
	if (DEVI(dip)->devi_ops == NULL)
		return (-1);

	DEVI(dip)->devi_instance = e_ddi_assign_instance(dip);
	e_ddi_keep_instance(dip);
	vhci_node_addr[0]	= '\0';
	ddi_set_name_addr(dip, vhci_node_addr);
	i_ddi_set_node_state(dip, DS_INITIALIZED);
	return (0);
}

static void
i_link_vhci_node(dev_info_t *dip)
{
	ASSERT(MUTEX_HELD(&global_vhci_lock));

	/*
	 * scsi_vhci should be kept left most of the device tree.
	 */
	if (scsi_vhci_dip) {
		DEVI(dip)->devi_sibling = DEVI(scsi_vhci_dip)->devi_sibling;
		DEVI(scsi_vhci_dip)->devi_sibling = DEVI(dip);
	} else {
		DEVI(dip)->devi_sibling = DEVI(top_devinfo)->devi_child;
		DEVI(top_devinfo)->devi_child = DEVI(dip);
	}
}


/*
 * This a special routine to enumerate vhci node (child of rootnex
 * node) without holding the ndi_devi_enter() lock. The device node
 * is allocated, initialized and brought into DS_READY state before
 * inserting into the device tree. The VHCI node is handcrafted
 * here to bring the node to DS_READY, similar to rootnex node.
 *
 * The global_vhci_lock protects linking the node into the device
 * as same lock is held before linking/unlinking any direct child
 * of rootnex children.
 *
 * This routine is a workaround to handle a possible deadlock
 * that occurs while trying to enumerate node in a different sub-tree
 * during _init/_attach entry points.
 */
/*ARGSUSED*/
dev_info_t *
ndi_devi_config_vhci(char *drvname, int flags)
{
	struct devnames		*dnp;
	dev_info_t		*dip;
	major_t			major = ddi_name_to_major(drvname);

	if (major == -1)
		return (NULL);

	/* Make sure we create the VHCI node only once */
	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);
	if (dnp->dn_head) {
		dip = dnp->dn_head;
		UNLOCK_DEV_OPS(&dnp->dn_lock);
		return (dip);
	}
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	/* Allocate the VHCI node */
	ndi_devi_alloc_sleep(top_devinfo, drvname, DEVI_SID_NODEID, &dip);
	ndi_hold_devi(dip);

	/* Mark the node as VHCI */
	DEVI(dip)->devi_node_attributes |= DDI_VHCI_NODE;

	i_ddi_add_devimap(dip);
	i_bind_vhci_node(dip);
	if (i_init_vhci_node(dip) == -1) {
		ndi_rele_devi(dip);
		(void) ndi_devi_free(dip);
		return (NULL);
	}

	mutex_enter(&(DEVI(dip)->devi_lock));
	DEVI_SET_ATTACHING(dip);
	mutex_exit(&(DEVI(dip)->devi_lock));

	if (devi_attach(dip, DDI_ATTACH) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "Could not attach %s driver", drvname);
		e_ddi_free_instance(dip, vhci_node_addr);
		ndi_rele_devi(dip);
		(void) ndi_devi_free(dip);
		return (NULL);
	}
	mutex_enter(&(DEVI(dip)->devi_lock));
	DEVI_CLR_ATTACHING(dip);
	mutex_exit(&(DEVI(dip)->devi_lock));

	mutex_enter(&global_vhci_lock);
	i_link_vhci_node(dip);
	mutex_exit(&global_vhci_lock);
	i_ddi_set_node_state(dip, DS_READY);

	LOCK_DEV_OPS(&dnp->dn_lock);
	dnp->dn_flags |= DN_DRIVER_HELD;
	dnp->dn_head = dip;
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	i_ndi_devi_report_status_change(dip, NULL);

	return (dip);
}

/*
 * Maintain DEVI_DEVICE_REMOVED hotplug devi_state for remove/reinsert hotplug
 * of open devices. Currently, because of tight coupling between the devfs file
 * system and the Solaris device tree, a driver can't always make the device
 * tree state (esp devi_node_state) match device hardware hotplug state. Until
 * resolved, to overcome this deficiency we use the following interfaces that
 * maintain the DEVI_DEVICE_REMOVED devi_state status bit.  These interface
 * report current state, and drive operation (like events and cache
 * invalidation) when a driver changes remove/insert state of an open device.
 *
 * The ndi_devi_device_isremoved() returns 1 if the device is currently removed.
 *
 * The ndi_devi_device_remove() interface declares the device as removed, and
 * returns 1 if there was a state change associated with this declaration.
 *
 * The ndi_devi_device_insert() declares the device as inserted, and returns 1
 * if there was a state change associated with this declaration.
 */
int
ndi_devi_device_isremoved(dev_info_t *dip)
{
	return (DEVI_IS_DEVICE_REMOVED(dip));
}

int
ndi_devi_device_remove(dev_info_t *dip)
{
	ASSERT(dip && ddi_get_parent(dip) &&
	    DEVI_BUSY_OWNED(ddi_get_parent(dip)));

	/* Return if already marked removed. */
	if (ndi_devi_device_isremoved(dip))
		return (0);

	/* Mark the device as having been physically removed. */
	mutex_enter(&(DEVI(dip)->devi_lock));
	ndi_devi_set_hidden(dip);	/* invisible: lookup/snapshot */
	DEVI_SET_DEVICE_REMOVED(dip);
	DEVI_SET_EVREMOVE(dip);		/* this clears EVADD too */
	mutex_exit(&(DEVI(dip)->devi_lock));

	/* report remove (as 'removed') */
	i_ndi_devi_report_status_change(dip, NULL);

	/*
	 * Invalidate the cache to ensure accurate
	 * (di_state() & DI_DEVICE_REMOVED).
	 */
	i_ddi_di_cache_invalidate();

	/*
	 * Generate sysevent for those interested in removal (either
	 * directly via private EC_DEVFS or indirectly via devfsadmd
	 * generated EC_DEV). This will generate LDI DEVICE_REMOVE
	 * event too.
	 */
	i_ddi_log_devfs_device_remove(dip);

	return (1);		/* DEVICE_REMOVED state changed */
}

int
ndi_devi_device_insert(dev_info_t *dip)
{
	ASSERT(dip && ddi_get_parent(dip) &&
	    DEVI_BUSY_OWNED(ddi_get_parent(dip)));

	/* Return if not marked removed. */
	if (!ndi_devi_device_isremoved(dip))
		return (0);

	/* Mark the device as having been physically reinserted. */
	mutex_enter(&(DEVI(dip)->devi_lock));
	ndi_devi_clr_hidden(dip);	/* visible: lookup/snapshot */
	DEVI_SET_DEVICE_REINSERTED(dip);
	DEVI_SET_EVADD(dip);		/* this clears EVREMOVE too */
	mutex_exit(&(DEVI(dip)->devi_lock));

	/* report insert (as 'online') */
	i_ndi_devi_report_status_change(dip, NULL);

	/*
	 * Invalidate the cache to ensure accurate
	 * (di_state() & DI_DEVICE_REMOVED).
	 */
	i_ddi_di_cache_invalidate();

	/*
	 * Generate sysevent for those interested in removal (either directly
	 * via EC_DEVFS or indirectly via devfsadmd generated EC_DEV).
	 */
	i_ddi_log_devfs_device_insert(dip);

	return (1);		/* DEVICE_REMOVED state changed */
}

/*
 * ibt_hw_is_present() returns 0 when there is no IB hardware actively
 * running.  This is primarily useful for modules like rpcmod which
 * needs a quick check to decide whether or not it should try to use
 * InfiniBand
 */
int ib_hw_status = 0;
int
ibt_hw_is_present()
{
	return (ib_hw_status);
}

/*
 * ASSERT that constraint flag is not set and then set the "retire attempt"
 * flag.
 */
int
e_ddi_mark_retiring(dev_info_t *dip, void *arg)
{
	char	**cons_array = (char **)arg;
	char	*path;
	int	constraint;
	int	i;

	constraint = 0;
	if (cons_array) {
		path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(dip, path);
		for (i = 0; cons_array[i] != NULL; i++) {
			if (strcmp(path, cons_array[i]) == 0) {
				constraint = 1;
				break;
			}
		}
		kmem_free(path, MAXPATHLEN);
	}

	mutex_enter(&DEVI(dip)->devi_lock);
	ASSERT(!(DEVI(dip)->devi_flags & DEVI_R_CONSTRAINT));
	DEVI(dip)->devi_flags |= DEVI_RETIRING;
	if (constraint)
		DEVI(dip)->devi_flags |= DEVI_R_CONSTRAINT;
	mutex_exit(&DEVI(dip)->devi_lock);

	RIO_VERBOSE((CE_NOTE, "marked dip as undergoing retire process dip=%p",
	    (void *)dip));

	if (constraint)
		RIO_DEBUG((CE_NOTE, "marked dip as constrained, dip=%p",
		    (void *)dip));

	if (MDI_PHCI(dip))
		mdi_phci_mark_retiring(dip, cons_array);

	return (DDI_WALK_CONTINUE);
}

static void
free_array(char **cons_array)
{
	int	i;

	if (cons_array == NULL)
		return;

	for (i = 0; cons_array[i] != NULL; i++) {
		kmem_free(cons_array[i], strlen(cons_array[i]) + 1);
	}
	kmem_free(cons_array, (i+1) * sizeof (char *));
}

/*
 * Walk *every* node in subtree and check if it blocks, allows or has no
 * comment on a proposed retire.
 */
int
e_ddi_retire_notify(dev_info_t *dip, void *arg)
{
	int	*constraint = (int *)arg;

	RIO_DEBUG((CE_NOTE, "retire notify: dip = %p", (void *)dip));

	(void) e_ddi_offline_notify(dip);

	mutex_enter(&(DEVI(dip)->devi_lock));
	if (!(DEVI(dip)->devi_flags & DEVI_RETIRING)) {
		RIO_DEBUG((CE_WARN, "retire notify: dip in retire "
		    "subtree is not marked: dip = %p", (void *)dip));
		*constraint = 0;
	} else if (DEVI(dip)->devi_flags & DEVI_R_BLOCKED) {
		ASSERT(!(DEVI(dip)->devi_flags & DEVI_R_CONSTRAINT));
		RIO_DEBUG((CE_NOTE, "retire notify: BLOCKED: dip = %p",
		    (void *)dip));
		*constraint = 0;
	} else if (!(DEVI(dip)->devi_flags & DEVI_R_CONSTRAINT)) {
		RIO_DEBUG((CE_NOTE, "retire notify: NO CONSTRAINT: "
		    "dip = %p", (void *)dip));
		*constraint = 0;
	} else {
		RIO_DEBUG((CE_NOTE, "retire notify: CONSTRAINT set: "
		    "dip = %p", (void *)dip));
	}
	mutex_exit(&DEVI(dip)->devi_lock);

	if (MDI_PHCI(dip))
		mdi_phci_retire_notify(dip, constraint);

	return (DDI_WALK_CONTINUE);
}

int
e_ddi_retire_finalize(dev_info_t *dip, void *arg)
{
	int constraint = *(int *)arg;
	int finalize;
	int phci_only;

	mutex_enter(&DEVI(dip)->devi_lock);
	if (!(DEVI(dip)->devi_flags & DEVI_RETIRING)) {
		RIO_DEBUG((CE_WARN,
		    "retire: unmarked dip(%p) in retire subtree",
		    (void *)dip));
		ASSERT(!(DEVI(dip)->devi_flags & DEVI_RETIRED));
		ASSERT(!(DEVI(dip)->devi_flags & DEVI_R_CONSTRAINT));
		ASSERT(!(DEVI(dip)->devi_flags & DEVI_R_BLOCKED));
		mutex_exit(&DEVI(dip)->devi_lock);
		return (DDI_WALK_CONTINUE);
	}

	/*
	 * retire the device if constraints have been applied
	 * or if the device is not in use
	 */
	finalize = 0;
	if (constraint) {
		ASSERT(DEVI_BUSY_OWNED(ddi_get_parent(dip)));

		ASSERT(DEVI(dip)->devi_flags & DEVI_R_CONSTRAINT);
		ASSERT(!(DEVI(dip)->devi_flags & DEVI_R_BLOCKED));
		DEVI(dip)->devi_flags &= ~DEVI_R_CONSTRAINT;
		DEVI(dip)->devi_flags &= ~DEVI_RETIRING;
		DEVI(dip)->devi_flags |= DEVI_RETIRED;
		mutex_exit(&DEVI(dip)->devi_lock);
		(void) spec_fence_snode(dip, NULL);
		RIO_DEBUG((CE_NOTE, "Fenced off: dip = %p", (void *)dip));
		e_ddi_offline_finalize(dip, DDI_SUCCESS);
	} else {
		if (DEVI(dip)->devi_flags & DEVI_R_BLOCKED) {
			ASSERT(!(DEVI(dip)->devi_flags & DEVI_R_CONSTRAINT));
			DEVI(dip)->devi_flags &= ~DEVI_R_BLOCKED;
			DEVI(dip)->devi_flags &= ~DEVI_RETIRING;
			/* we have already finalized during notify */
		} else if (DEVI(dip)->devi_flags & DEVI_R_CONSTRAINT) {
			DEVI(dip)->devi_flags &= ~DEVI_R_CONSTRAINT;
			DEVI(dip)->devi_flags &= ~DEVI_RETIRING;
			finalize = 1;
		} else {
			DEVI(dip)->devi_flags &= ~DEVI_RETIRING;
			/*
			 * even if no contracts, need to call finalize
			 * to clear the contract barrier on the dip
			 */
			finalize = 1;
		}
		mutex_exit(&DEVI(dip)->devi_lock);
		RIO_DEBUG((CE_NOTE, "finalize: NOT retired: dip = %p",
		    (void *)dip));
		if (finalize)
			e_ddi_offline_finalize(dip, DDI_FAILURE);
	}

	/*
	 * phci_only variable indicates no client checking, just
	 * offline the PHCI. We set that to 0 to enable client
	 * checking
	 */
	phci_only = 0;
	if (MDI_PHCI(dip))
		mdi_phci_retire_finalize(dip, phci_only, arg);

	return (DDI_WALK_CONTINUE);
}

/*
 * Returns
 *	DDI_SUCCESS if constraints allow retire
 *	DDI_FAILURE if constraints don't allow retire.
 * cons_array is a NULL terminated array of node paths for
 * which constraints have already been applied.
 */
int
e_ddi_retire_device(char *path, char **cons_array)
{
	dev_info_t	*dip;
	dev_info_t	*pdip;
	int		circ;
	int		circ2;
	int		constraint;
	char		*devnm;

	/*
	 * First, lookup the device
	 */
	dip = e_ddi_hold_devi_by_path(path, 0);
	if (dip == NULL) {
		/*
		 * device does not exist. This device cannot be
		 * a critical device since it is not in use. Thus
		 * this device is always retireable. Return DDI_SUCCESS
		 * to indicate this. If this device is ever
		 * instantiated, I/O framework will consult the
		 * the persistent retire store, mark it as
		 * retired and fence it off.
		 */
		RIO_DEBUG((CE_NOTE, "Retire device: device doesn't exist."
		    " NOP. Just returning SUCCESS. path=%s", path));
		free_array(cons_array);
		return (DDI_SUCCESS);
	}

	RIO_DEBUG((CE_NOTE, "Retire device: found dip = %p.", (void *)dip));

	pdip = ddi_get_parent(dip);
	ndi_hold_devi(pdip);

	/*
	 * Run devfs_clean() in case dip has no constraints and is
	 * not in use, so is retireable but there are dv_nodes holding
	 * ref-count on the dip. Note that devfs_clean() always returns
	 * success.
	 */
	devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);
	(void) ddi_deviname(dip, devnm);
	(void) devfs_clean(pdip, devnm + 1, DV_CLEAN_FORCE);
	kmem_free(devnm, MAXNAMELEN + 1);

	ndi_devi_enter(pdip, &circ);

	/* release hold from e_ddi_hold_devi_by_path */
	ndi_rele_devi(dip);

	/*
	 * If it cannot make a determination, is_leaf_node() assumes
	 * dip is a nexus.
	 */
	(void) e_ddi_mark_retiring(dip, cons_array);
	if (!is_leaf_node(dip)) {
		ndi_devi_enter(dip, &circ2);
		ddi_walk_devs(ddi_get_child(dip), e_ddi_mark_retiring,
		    cons_array);
		ndi_devi_exit(dip, circ2);
	}
	free_array(cons_array);

	/*
	 * apply constraints
	 */
	RIO_DEBUG((CE_NOTE, "retire: subtree retire notify: path = %s", path));

	constraint = 1;	/* assume constraints allow retire */
	(void) e_ddi_retire_notify(dip, &constraint);
	if (!is_leaf_node(dip)) {
		ndi_devi_enter(dip, &circ2);
		ddi_walk_devs(ddi_get_child(dip), e_ddi_retire_notify,
		    &constraint);
		ndi_devi_exit(dip, circ2);
	}

	/*
	 * Now finalize the retire
	 */
	(void) e_ddi_retire_finalize(dip, &constraint);
	if (!is_leaf_node(dip)) {
		ndi_devi_enter(dip, &circ2);
		ddi_walk_devs(ddi_get_child(dip), e_ddi_retire_finalize,
		    &constraint);
		ndi_devi_exit(dip, circ2);
	}

	if (!constraint) {
		RIO_DEBUG((CE_WARN, "retire failed: path = %s", path));
	} else {
		RIO_DEBUG((CE_NOTE, "retire succeeded: path = %s", path));
	}

	ndi_devi_exit(pdip, circ);
	ndi_rele_devi(pdip);
	return (constraint ? DDI_SUCCESS : DDI_FAILURE);
}

static int
unmark_and_unfence(dev_info_t *dip, void *arg)
{
	char	*path = (char *)arg;

	ASSERT(path);

	(void) ddi_pathname(dip, path);

	mutex_enter(&DEVI(dip)->devi_lock);
	DEVI(dip)->devi_flags &= ~DEVI_RETIRED;
	DEVI_SET_DEVICE_ONLINE(dip);
	mutex_exit(&DEVI(dip)->devi_lock);

	RIO_VERBOSE((CE_NOTE, "Cleared RETIRED flag: dip=%p, path=%s",
	    (void *)dip, path));

	(void) spec_unfence_snode(dip);
	RIO_DEBUG((CE_NOTE, "Unfenced device: %s", path));

	if (MDI_PHCI(dip))
		mdi_phci_unretire(dip);

	return (DDI_WALK_CONTINUE);
}

struct find_dip {
	char	*fd_buf;
	char	*fd_path;
	dev_info_t *fd_dip;
};

static int
find_dip_fcn(dev_info_t *dip, void *arg)
{
	struct find_dip *findp = (struct find_dip *)arg;

	(void) ddi_pathname(dip, findp->fd_buf);

	if (strcmp(findp->fd_path, findp->fd_buf) != 0)
		return (DDI_WALK_CONTINUE);

	ndi_hold_devi(dip);
	findp->fd_dip = dip;

	return (DDI_WALK_TERMINATE);
}

int
e_ddi_unretire_device(char *path)
{
	int		circ;
	int		circ2;
	char		*path2;
	dev_info_t	*pdip;
	dev_info_t	*dip;
	struct find_dip	 find_dip;

	ASSERT(path);
	ASSERT(*path == '/');

	if (strcmp(path, "/") == 0) {
		cmn_err(CE_WARN, "Root node cannot be retired. Skipping "
		    "device unretire: %s", path);
		return (0);
	}

	/*
	 * We can't lookup the dip (corresponding to path) via
	 * e_ddi_hold_devi_by_path() because the dip may be offline
	 * and may not attach. Use ddi_walk_devs() instead;
	 */
	find_dip.fd_buf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	find_dip.fd_path = path;
	find_dip.fd_dip = NULL;

	pdip = ddi_root_node();

	ndi_devi_enter(pdip, &circ);
	ddi_walk_devs(ddi_get_child(pdip), find_dip_fcn, &find_dip);
	ndi_devi_exit(pdip, circ);

	kmem_free(find_dip.fd_buf, MAXPATHLEN);

	if (find_dip.fd_dip == NULL) {
		cmn_err(CE_WARN, "Device not found in device tree. Skipping "
		    "device unretire: %s", path);
		return (0);
	}

	dip = find_dip.fd_dip;

	pdip = ddi_get_parent(dip);

	ndi_hold_devi(pdip);

	ndi_devi_enter(pdip, &circ);

	path2 = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	(void) unmark_and_unfence(dip, path2);
	if (!is_leaf_node(dip)) {
		ndi_devi_enter(dip, &circ2);
		ddi_walk_devs(ddi_get_child(dip), unmark_and_unfence, path2);
		ndi_devi_exit(dip, circ2);
	}

	kmem_free(path2, MAXPATHLEN);

	/* release hold from find_dip_fcn() */
	ndi_rele_devi(dip);

	ndi_devi_exit(pdip, circ);

	ndi_rele_devi(pdip);

	return (0);
}

/*
 * Called before attach on a dip that has been retired.
 */
static int
mark_and_fence(dev_info_t *dip, void *arg)
{
	char	*fencepath = (char *)arg;

	/*
	 * We have already decided to retire this device. The various
	 * constraint checking should not be set.
	 * NOTE that the retire flag may already be set due to
	 * fenced -> detach -> fenced transitions.
	 */
	mutex_enter(&DEVI(dip)->devi_lock);
	ASSERT(!(DEVI(dip)->devi_flags & DEVI_R_CONSTRAINT));
	ASSERT(!(DEVI(dip)->devi_flags & DEVI_R_BLOCKED));
	ASSERT(!(DEVI(dip)->devi_flags & DEVI_RETIRING));
	DEVI(dip)->devi_flags |= DEVI_RETIRED;
	mutex_exit(&DEVI(dip)->devi_lock);
	RIO_VERBOSE((CE_NOTE, "marked as RETIRED dip=%p", (void *)dip));

	if (fencepath) {
		(void) spec_fence_snode(dip, NULL);
		RIO_DEBUG((CE_NOTE, "Fenced: %s",
		    ddi_pathname(dip, fencepath)));
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * Checks the retire database and:
 *
 * - if device is present in the retire database, marks the device retired
 *   and fences it off.
 * - if device is not in retire database, allows the device to attach normally
 *
 * To be called only by framework attach code on first attach attempt.
 *
 */
static int
i_ddi_check_retire(dev_info_t *dip)
{
	char		*path;
	dev_info_t	*pdip;
	int		circ;
	int		phci_only;
	int		constraint;

	pdip = ddi_get_parent(dip);

	/*
	 * Root dip is treated special and doesn't take this code path.
	 * Also root can never be retired.
	 */
	ASSERT(pdip);
	ASSERT(DEVI_BUSY_OWNED(pdip));
	ASSERT(i_ddi_node_state(dip) < DS_ATTACHED);

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	(void) ddi_pathname(dip, path);

	RIO_VERBOSE((CE_NOTE, "Checking if dip should attach: dip=%p, path=%s",
	    (void *)dip, path));

	/*
	 * Check if this device is in the "retired" store i.e.	should
	 * be retired. If not, we have nothing to do.
	 */
	if (e_ddi_device_retired(path) == 0) {
		RIO_VERBOSE((CE_NOTE, "device is NOT retired: path=%s", path));
		if (DEVI(dip)->devi_flags & DEVI_RETIRED)
			(void) e_ddi_unretire_device(path);
		kmem_free(path, MAXPATHLEN);
		return (0);
	}

	RIO_DEBUG((CE_NOTE, "attach: device is retired: path=%s", path));

	/*
	 * Mark dips and fence off snodes (if any)
	 */
	RIO_DEBUG((CE_NOTE, "attach: Mark and fence subtree: path=%s", path));
	(void) mark_and_fence(dip, path);
	if (!is_leaf_node(dip)) {
		ndi_devi_enter(dip, &circ);
		ddi_walk_devs(ddi_get_child(dip), mark_and_fence, path);
		ndi_devi_exit(dip, circ);
	}

	kmem_free(path, MAXPATHLEN);

	/*
	 * We don't want to check the client. We just want to
	 * offline the PHCI
	 */
	phci_only = 1;
	constraint = 1;
	if (MDI_PHCI(dip))
		mdi_phci_retire_finalize(dip, phci_only, &constraint);
	return (1);
}


#define	VAL_ALIAS(array, x)	(strlen(array[x].pair_alias))
#define	VAL_CURR(array, x)	(strlen(array[x].pair_curr))
#define	SWAP(array, x, y)			\
{						\
	alias_pair_t tmpair = array[x];		\
	array[x] = array[y];			\
	array[y] = tmpair;			\
}

static int
partition_curr(alias_pair_t *array, int start, int end)
{
	int	i = start - 1;
	int	j = end + 1;
	int	pivot = start;

	for (;;) {
		do {
			j--;
		} while (VAL_CURR(array, j) > VAL_CURR(array, pivot));

		do {
			i++;
		} while (VAL_CURR(array, i) < VAL_CURR(array, pivot));

		if (i < j)
			SWAP(array, i, j)
		else
			return (j);
	}
}

static int
partition_aliases(alias_pair_t *array, int start, int end)
{
	int	i = start - 1;
	int	j = end + 1;
	int	pivot = start;

	for (;;) {
		do {
			j--;
		} while (VAL_ALIAS(array, j) > VAL_ALIAS(array, pivot));

		do {
			i++;
		} while (VAL_ALIAS(array, i) < VAL_ALIAS(array, pivot));

		if (i < j)
			SWAP(array, i, j)
		else
			return (j);
	}
}
static void
sort_alias_pairs(alias_pair_t *array, int start, int end)
{
	int mid;

	if (start < end) {
		mid = partition_aliases(array, start, end);
		sort_alias_pairs(array, start, mid);
		sort_alias_pairs(array, mid + 1, end);
	}
}

static void
sort_curr_pairs(alias_pair_t *array, int start, int end)
{
	int mid;

	if (start < end) {
		mid = partition_curr(array, start, end);
		sort_curr_pairs(array, start, mid);
		sort_curr_pairs(array, mid + 1, end);
	}
}

static void
create_sorted_pairs(plat_alias_t *pali, int npali)
{
	int		i;
	int		j;
	int		k;
	int		count;

	count = 0;
	for (i = 0; i < npali; i++) {
		count += pali[i].pali_naliases;
	}

	ddi_aliases.dali_alias_pairs = kmem_zalloc(
	    (sizeof (alias_pair_t)) * count, KM_NOSLEEP);
	if (ddi_aliases.dali_alias_pairs == NULL) {
		cmn_err(CE_PANIC, "alias path-pair alloc failed");
		/*NOTREACHED*/
	}

	ddi_aliases.dali_curr_pairs = kmem_zalloc(
	    (sizeof (alias_pair_t)) * count, KM_NOSLEEP);
	if (ddi_aliases.dali_curr_pairs == NULL) {
		cmn_err(CE_PANIC, "curr path-pair alloc failed");
		/*NOTREACHED*/
	}

	for (i = 0, k = 0; i < npali; i++) {
		for (j = 0; j < pali[i].pali_naliases; j++, k++) {
			ddi_aliases.dali_alias_pairs[k].pair_curr =
			    ddi_aliases.dali_curr_pairs[k].pair_curr =
			    pali[i].pali_current;
			ddi_aliases.dali_alias_pairs[k].pair_alias =
			    ddi_aliases.dali_curr_pairs[k].pair_alias =
			    pali[i].pali_aliases[j];
		}
	}

	ASSERT(k == count);

	ddi_aliases.dali_num_pairs = count;

	/* Now sort the array based on length of pair_alias */
	sort_alias_pairs(ddi_aliases.dali_alias_pairs, 0, count - 1);
	sort_curr_pairs(ddi_aliases.dali_curr_pairs, 0, count - 1);
}

void
ddi_register_aliases(plat_alias_t *pali, uint64_t npali)
{

	ASSERT((pali == NULL) ^ (npali != 0));

	if (npali == 0) {
		ddi_err(DER_PANIC, NULL, "npali == 0");
		/*NOTREACHED*/
	}

	if (ddi_aliases_present == B_TRUE) {
		ddi_err(DER_PANIC, NULL, "multiple init");
		/*NOTREACHED*/
	}

	ddi_aliases.dali_alias_TLB = mod_hash_create_strhash(
	    "ddi-alias-tlb", DDI_ALIAS_HASH_SIZE, mod_hash_null_valdtor);
	if (ddi_aliases.dali_alias_TLB == NULL) {
		ddi_err(DER_PANIC, NULL, "alias TLB hash alloc failed");
		/*NOTREACHED*/
	}

	ddi_aliases.dali_curr_TLB = mod_hash_create_strhash(
	    "ddi-curr-tlb", DDI_ALIAS_HASH_SIZE, mod_hash_null_valdtor);
	if (ddi_aliases.dali_curr_TLB == NULL) {
		ddi_err(DER_PANIC, NULL, "curr TLB hash alloc failed");
		/*NOTREACHED*/
	}

	create_sorted_pairs(pali, npali);

	tsd_create(&tsd_ddi_redirect, NULL);

	ddi_aliases_present = B_TRUE;
}

static dev_info_t *
path_to_dip(char *path)
{
	dev_info_t	*currdip;
	int		error;
	char		*pdup;

	pdup = ddi_strdup(path, KM_NOSLEEP);
	if (pdup == NULL) {
		cmn_err(CE_PANIC, "path strdup failed: %s", path);
		/*NOTREACHED*/
	}

	error = resolve_pathname(pdup, &currdip, NULL, NULL);

	kmem_free(pdup, strlen(path) + 1);

	return (error ? NULL : currdip);
}

dev_info_t *
ddi_alias_to_currdip(char *alias, int i)
{
	alias_pair_t *pair;
	char *curr;
	dev_info_t *currdip = NULL;
	char *aliasdup;
	int rv, len;

	pair = &(ddi_aliases.dali_alias_pairs[i]);
	len = strlen(pair->pair_alias);

	curr = NULL;
	aliasdup = ddi_strdup(alias, KM_NOSLEEP);
	if (aliasdup == NULL) {
		cmn_err(CE_PANIC, "aliasdup alloc failed");
		/*NOTREACHED*/
	}

	if (strncmp(alias, pair->pair_alias, len)  != 0)
		goto out;

	if (alias[len] != '/' && alias[len] != '\0')
		goto out;

	curr = kmem_alloc(MAXPATHLEN, KM_NOSLEEP);
	if (curr == NULL) {
		cmn_err(CE_PANIC, "curr alloc failed");
		/*NOTREACHED*/
	}
	(void) strlcpy(curr, pair->pair_curr, MAXPATHLEN);
	if (alias[len] == '/') {
		(void) strlcat(curr, "/", MAXPATHLEN);
		(void) strlcat(curr, &alias[len + 1], MAXPATHLEN);
	}

	currdip = path_to_dip(curr);

out:
	if (currdip) {
		rv = mod_hash_insert(ddi_aliases.dali_alias_TLB,
		    (mod_hash_key_t)aliasdup, (mod_hash_val_t)curr);
		if (rv != 0) {
			kmem_free(curr, MAXPATHLEN);
			strfree(aliasdup);
		}
	} else {
		rv = mod_hash_insert(ddi_aliases.dali_alias_TLB,
		    (mod_hash_key_t)aliasdup, (mod_hash_val_t)NULL);
		if (rv != 0) {
			strfree(aliasdup);
		}
		if (curr)
			kmem_free(curr, MAXPATHLEN);
	}

	return (currdip);
}

char *
ddi_curr_to_alias(char *curr, int i)
{
	alias_pair_t	*pair;
	char		*alias;
	char		*currdup;
	int		len;
	int		rv;

	pair = &(ddi_aliases.dali_curr_pairs[i]);

	len = strlen(pair->pair_curr);

	alias = NULL;

	currdup = ddi_strdup(curr, KM_NOSLEEP);
	if (currdup == NULL) {
		cmn_err(CE_PANIC, "currdup alloc failed");
		/*NOTREACHED*/
	}

	if (strncmp(curr, pair->pair_curr, len) != 0)
		goto out;

	if (curr[len] != '/' && curr[len] != '\0')
		goto out;

	alias = kmem_alloc(MAXPATHLEN, KM_NOSLEEP);
	if (alias == NULL) {
		cmn_err(CE_PANIC, "alias alloc failed");
		/*NOTREACHED*/
	}

	(void) strlcpy(alias, pair->pair_alias, MAXPATHLEN);
	if (curr[len] == '/') {
		(void) strlcat(alias, "/", MAXPATHLEN);
		(void) strlcat(alias, &curr[len + 1], MAXPATHLEN);
	}

	if (e_ddi_path_to_instance(alias) == NULL) {
		kmem_free(alias, MAXPATHLEN);
		alias = NULL;
	}

out:
	rv = mod_hash_insert(ddi_aliases.dali_curr_TLB,
	    (mod_hash_key_t)currdup, (mod_hash_val_t)alias);
	if (rv != 0) {
		strfree(currdup);
	}

	return (alias);
}

dev_info_t *
ddi_alias_redirect(char *alias)
{
	char		*curr;
	dev_info_t	*currdip;
	int		i;

	if (ddi_aliases_present == B_FALSE)
		return (NULL);

	if (tsd_get(tsd_ddi_redirect))
		return (NULL);

	(void) tsd_set(tsd_ddi_redirect, (void *)1);

	ASSERT(ddi_aliases.dali_alias_TLB);
	ASSERT(ddi_aliases.dali_alias_pairs);

	curr = NULL;
	if (mod_hash_find(ddi_aliases.dali_alias_TLB,
	    (mod_hash_key_t)alias, (mod_hash_val_t *)&curr) == 0) {
		currdip = curr ? path_to_dip(curr) : NULL;
		goto out;
	}

	/* The TLB has no translation, do it the hard way */
	currdip = NULL;
	for (i = ddi_aliases.dali_num_pairs - 1; i >= 0; i--) {
		currdip = ddi_alias_to_currdip(alias, i);
		if (currdip)
			break;
	}
out:
	(void) tsd_set(tsd_ddi_redirect, NULL);

	return (currdip);
}

char *
ddi_curr_redirect(char *curr)
{
	char 	*alias;
	int i;

	if (ddi_aliases_present == B_FALSE)
		return (NULL);

	if (tsd_get(tsd_ddi_redirect))
		return (NULL);

	(void) tsd_set(tsd_ddi_redirect, (void *)1);

	ASSERT(ddi_aliases.dali_curr_TLB);
	ASSERT(ddi_aliases.dali_curr_pairs);

	alias = NULL;
	if (mod_hash_find(ddi_aliases.dali_curr_TLB,
	    (mod_hash_key_t)curr, (mod_hash_val_t *)&alias) == 0) {
		goto out;
	}


	/* The TLB has no translation, do it the slow way */
	alias = NULL;
	for (i = ddi_aliases.dali_num_pairs - 1; i >= 0; i--) {
		alias = ddi_curr_to_alias(curr, i);
		if (alias)
			break;
	}

out:
	(void) tsd_set(tsd_ddi_redirect, NULL);

	return (alias);
}

void
ddi_err(ddi_err_t ade, dev_info_t *rdip, const char *fmt, ...)
{
	va_list ap;
	char strbuf[256];
	char *buf;
	size_t buflen, tlen;
	int ce;
	int de;
	const char *fmtbad = "Invalid arguments to ddi_err()";

	de = DER_CONT;
	strbuf[1] = '\0';

	switch (ade) {
	case DER_CONS:
		strbuf[0] = '^';
		break;
	case DER_LOG:
		strbuf[0] = '!';
		break;
	case DER_VERB:
		strbuf[0] = '?';
		break;
	default:
		strbuf[0] = '\0';
		de = ade;
		break;
	}

	tlen = strlen(strbuf);
	buf = strbuf + tlen;
	buflen = sizeof (strbuf) - tlen;

	if (rdip && ddi_get_instance(rdip) == -1) {
		(void) snprintf(buf, buflen, "%s: ",
		    ddi_driver_name(rdip));
	} else if (rdip) {
		(void) snprintf(buf, buflen, "%s%d: ",
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
	}

	tlen = strlen(strbuf);
	buf = strbuf + tlen;
	buflen = sizeof (strbuf) - tlen;

	va_start(ap, fmt);
	switch (de) {
	case DER_CONT:
		(void) vsnprintf(buf, buflen, fmt, ap);
		if (ade != DER_CONT) {
			(void) strlcat(strbuf, "\n", sizeof (strbuf));
		}
		ce = CE_CONT;
		break;
	case DER_NOTE:
		(void) vsnprintf(buf, buflen, fmt, ap);
		ce = CE_NOTE;
		break;
	case DER_WARN:
		(void) vsnprintf(buf, buflen, fmt, ap);
		ce = CE_WARN;
		break;
	case DER_MODE:
		(void) vsnprintf(buf, buflen, fmt, ap);
		if (ddi_err_panic == B_TRUE) {
			ce = CE_PANIC;
		} else {
			ce = CE_WARN;
		}
		break;
	case DER_DEBUG:
		(void) snprintf(buf, buflen, "DEBUG: ");
		tlen = strlen("DEBUG: ");
		(void) vsnprintf(buf + tlen, buflen - tlen, fmt, ap);
		ce = CE_CONT;
		break;
	case DER_PANIC:
		(void) vsnprintf(buf, buflen, fmt, ap);
		ce = CE_PANIC;
		break;
	case DER_INVALID:
	default:
		(void) snprintf(buf, buflen, fmtbad);
		tlen = strlen(fmtbad);
		(void) vsnprintf(buf + tlen, buflen - tlen, fmt, ap);
		ce = CE_PANIC;
		break;
	}
	va_end(ap);

	cmn_err(ce, strbuf);
}

/*ARGSUSED*/
void
ddi_mem_update(uint64_t addr, uint64_t size)
{
#if defined(__x86) && !defined(__xpv)
	extern void immu_physmem_update(uint64_t addr, uint64_t size);
	immu_physmem_update(addr, size);
#else
	/*LINTED*/
	;
#endif
}
