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

/*
 * Copyright 2019 Peter Tribble.
 */

/*
 * Safari Configurator  (gptwocfg)
 *
 */

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/autoconf.h>
#include <sys/ksynch.h>
#include <sys/promif.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/gp2cfg.h>
#include <sys/machsystm.h>
#include <sys/platform_module.h>

#ifdef DEBUG
int gptwocfg_debug = 0;

static void debug(char *, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t);

#define	GPTWO_DEBUG0(level, flag, s) if (gptwocfg_debug >= level) \
    cmn_err(flag, s)
#define	GPTWO_DEBUG1(level, flag, fmt, a1) if (gptwocfg_debug >= level) \
    debug(fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	GPTWO_DEBUG2(level, flag, fmt, a1, a2) if (gptwocfg_debug >= level) \
    debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	GPTWO_DEBUG3(level, flag, fmt, a1, a2, a3) \
    if (gptwocfg_debug >= level) \
    debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), (uintptr_t)(a3), 0, 0);
#else
#define	GPTWO_DEBUG0(level, flag, s)
#define	GPTWO_DEBUG1(level, flag, fmt, a1)
#define	GPTWO_DEBUG2(level, flag, fmt, a1, a2)
#define	GPTWO_DEBUG3(level, flag, fmt, a1, a2, a3)
#endif

kmutex_t gptwo_handle_list_lock;
gptwocfg_handle_list_t *gptwocfg_handle_list;

static kmutex_t gptwo_config_list_lock;
static gptwocfg_config_t *gptwo_config_list;

static gptwo_new_nodes_t *
    gptwocfg_get_obp_created_nodes(dev_info_t *, uint_t);

void (*gptwocfg_unclaim_address)(uint_t);

extern caddr_t efcode_vaddr;
extern int efcode_size;

#define		GPTWO_NUMBER_OF_DEVICE_TYPES	6

static kmutex_t gptwocfg_ops_table_lock;
gptwocfg_ops_t *gptwocfg_ops_table[GPTWO_NUMBER_OF_DEVICE_TYPES];

/*
 * Module linkage information for the kernel.
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, /* Type of module */
	"gptwo configurator",
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	unsigned int i;

	GPTWO_DEBUG0(1, CE_WARN, "gptwocfg (Safari Configurator) "
	    "has been loaded\n");

	mutex_init(&gptwo_config_list_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&gptwocfg_ops_table_lock, NULL, MUTEX_DRIVER, NULL);
	gptwo_config_list = NULL;

	mutex_init(&gptwo_handle_list_lock, NULL, MUTEX_DRIVER, NULL);
	gptwocfg_handle_list = NULL;

	for (i = 0; i < GPTWO_NUMBER_OF_DEVICE_TYPES; i++)
		gptwocfg_ops_table[i] = NULL;

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error != 0) {
		return (error);
	}
	mutex_destroy(&gptwo_config_list_lock);
	mutex_destroy(&gptwocfg_ops_table_lock);
	mutex_destroy(&gptwo_handle_list_lock);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

gptwo_new_nodes_t *
gptwocfg_allocate_node_list(int number_of_nodes)
{
	gptwo_new_nodes_t	*gptwo_new_nodes;
	int size;

	GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_allocate_node_list- %d nodes",
	    number_of_nodes);

	size = sizeof (gptwo_new_nodes_t) +
	    ((number_of_nodes -1) * sizeof (dev_info_t *));

	gptwo_new_nodes = kmem_zalloc(size, KM_SLEEP);

	gptwo_new_nodes->gptwo_number_of_nodes = number_of_nodes;
	gptwo_new_nodes->gptwo_version = GP2_VERSION;

	GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_allocate_node_list- returned %p\n",
	    gptwo_new_nodes);

	return (gptwo_new_nodes);
}

void
gptwocfg_free_node_list(gptwo_new_nodes_t *gptwo_new_nodes)
{
	int size;

	GPTWO_DEBUG2(1, CE_CONT, "gptwocfg_free_node_list- %p %d nodes",
	    gptwo_new_nodes, gptwo_new_nodes->gptwo_number_of_nodes);

	size = sizeof (gptwo_new_nodes_t) +
	    ((gptwo_new_nodes->gptwo_number_of_nodes - 1) *
	    sizeof (dev_info_t *));

	kmem_free(gptwo_new_nodes, size);
}

void
gptwocfg_register_ops(uint_t type, gptwo_cfgfunc_t *cfg_func,
    gptwo_uncfgfunc_t *uncfg_func)
{
	/* KM_SLEEP guarantees success */
	gptwocfg_ops_t *ops = kmem_zalloc(sizeof (gptwocfg_ops_t), KM_SLEEP);

	GPTWO_DEBUG2(1, CE_CONT, "gptwocfg_register_ops: type=%x ops=%lx\n",
	    type, ops);
	ASSERT(type < GPTWO_NUMBER_OF_DEVICE_TYPES);
	ops->gptwocfg_type = type;
	ops->gptwocfg_version = GPTWOCFG_OPS_VERSION;
	ops->gptwocfg_configure = cfg_func;
	ops->gptwocfg_unconfigure = uncfg_func;

	mutex_enter(&gptwocfg_ops_table_lock);
	gptwocfg_ops_table[type] = ops;
	mutex_exit(&gptwocfg_ops_table_lock);
}



void
gptwocfg_unregister_ops(uint_t type)
{
	GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_unregister_ops: type=%x\n", type);

	ASSERT(type < GPTWO_NUMBER_OF_DEVICE_TYPES);

	mutex_enter(&gptwocfg_ops_table_lock);
	kmem_free(gptwocfg_ops_table[type], sizeof (gptwocfg_ops_t));
	gptwocfg_ops_table[type] = NULL;
	mutex_exit(&gptwocfg_ops_table_lock);
}

gptwocfg_cookie_t
gptwocfg_configure(dev_info_t *ap, spcd_t *pcd, gptwo_aid_t id)
{
	gptwo_new_nodes_t *new_nodes = NULL;
	gptwocfg_config_t *config;
	gptwocfg_ops_t *ops;

	GPTWO_DEBUG3(1, CE_CONT, "gptwocfg_configure:  ap=0x%p pcd=%p id=%x\n",
	    ap, pcd, id);

	/*
	 * Look to see if the port is already configured.
	 */
	mutex_enter(&gptwo_config_list_lock);
	config = gptwo_config_list;
	while (config != NULL) {
		if (config->gptwo_portid == id) {
			cmn_err(CE_WARN, "gptwocfg: gptwocfg_configure: "
			    "0x%x Port already configured\n", id);
			mutex_exit(&gptwo_config_list_lock);
			return (NULL);
		}
		config = config->gptwo_next;
	}
	mutex_exit(&gptwo_config_list_lock);

	if (pcd == NULL) {
		GPTWO_DEBUG0(1, CE_CONT, "gptwocfg_configure: pcd=NULL\n");
		return (NULL);
	}

	if ((pcd->spcd_magic != PCD_MAGIC) ||
	    (pcd->spcd_version != PCD_VERSION)) {
		cmn_err(CE_WARN, "gptwocfg: Invalid Port "
		    "Configuration Descriptor\n");
		return (NULL);
	}

	if (pcd->spcd_ptype >= GPTWO_NUMBER_OF_DEVICE_TYPES) {
		cmn_err(CE_WARN,
		    "gptwocfg: Invalid device type %x", pcd->spcd_ptype);
		return (NULL);
	}

	if (pcd->spcd_prsv != SPCD_RSV_PASS) {
		cmn_err(CE_WARN,
		    "gptwocfg: Agent at ID %x has not passed test(s)\n", id);
		return (NULL);
	}

	mutex_enter(&gptwocfg_ops_table_lock);

	ops = gptwocfg_ops_table[pcd->spcd_ptype];

	if (ops == NULL) {
		cmn_err(CE_WARN, "gptwocfg: Ops for type %x have not been "
		    "registered\n", pcd->spcd_ptype);
		mutex_exit(&gptwocfg_ops_table_lock);
		return (NULL);
	}

	if (ops->gptwocfg_configure == NULL) {
		cmn_err(CE_WARN, "gptwocfg: no configure routine registered "
		    "for sfaari type %x\n", pcd->spcd_ptype);
		mutex_exit(&gptwocfg_ops_table_lock);
		return (NULL);
	}

	new_nodes = ops->gptwocfg_configure(ap, pcd, id);

	mutex_exit(&gptwocfg_ops_table_lock);

	if (new_nodes != NULL) {
		config = kmem_zalloc(sizeof (gptwocfg_config_t), KM_SLEEP);
		config->gptwo_version = GP2_VERSION;
		config->gptwo_ap = ap;
		config->gptwo_portid = id;
		config->gptwo_nodes = new_nodes;
		config->gptwo_ops = ops;

		/*
		 * put config on config list
		 */
		mutex_enter(&gptwo_config_list_lock);
		config->gptwo_next = gptwo_config_list;
		gptwo_config_list = config;
		mutex_exit(&gptwo_config_list_lock);
	} else {
		config = NULL;
	}

	return ((gptwocfg_cookie_t)config);
}

gptwocfg_cookie_t
gptwocfg_unconfigure(dev_info_t *ap, gptwo_aid_t id)
{
	int i, circ;
	int failure = 0;
	dev_info_t *saf_dip;
	gptwocfg_config_t *config, *temp;
	gptwo_new_nodes_t *obp_nodes;
	gptwocfg_ops_t *ops;

	GPTWO_DEBUG2(1, CE_CONT, "gptwocfg_unconfigure: ap=0x%p id=0x%lx\n",
	    ap, id);

	mutex_enter(&gptwo_config_list_lock);
	config = gptwo_config_list;
	while (config != NULL) {
		if (config->gptwo_portid == id) {
			break;
		}
		config = config->gptwo_next;
	}
	mutex_exit(&gptwo_config_list_lock);

	if (config == NULL) {
		/*
		 * There is no config structure associated with this agent id
		 * so it was probably built by firmware at start of day.  We
		 * need to create a config structure before we can continue.
		 */
		GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_unconfigure: id=0x%lx "
		    "No config structure - Need to build one\n", id);

		obp_nodes = gptwocfg_get_obp_created_nodes(ap, id);

		if (obp_nodes != NULL) {
			config = kmem_zalloc(sizeof (gptwocfg_config_t),
			    KM_SLEEP);
			config->gptwo_version = GP2_VERSION;
			config->gptwo_ap = ap;
			config->gptwo_portid = id;
			config->gptwo_nodes = obp_nodes;

			/*
			 * put config on config list
			 */
			mutex_enter(&gptwo_config_list_lock);
			config->gptwo_next = gptwo_config_list;
			gptwo_config_list = config;
			mutex_exit(&gptwo_config_list_lock);
		} else {
			cmn_err(CE_WARN, "gptwocfg: gptwocfg_unconfigure: "
			    "No OBP created nodes for ap=0x%lx agent id=0x%x",
			    (long)ap, id);
			return (NULL);
		}
	}

	GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_unconfigure config=0x%lx\n",
	    config);

	ops = config->gptwo_ops;

	GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_unconfigure: ops=%lx\n", ops);

	ndi_devi_enter(ap, &circ);

	for (i = 0; i < config->gptwo_nodes->gptwo_number_of_nodes; i++) {
		dev_info_t *fdip = NULL;

		saf_dip = config->gptwo_nodes->gptwo_nodes[i];

		GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_unconfigure saf_dip=0x%lx\n",
		    saf_dip);

		if (saf_dip == NULL) {
			GPTWO_DEBUG0(1, CE_CONT, "gptwocfg_unconfigure: "
			    "skipping NULLL saf device\n");

			continue;
		}

		config->gptwo_nodes->gptwo_nodes[i] = NULL;

		if (ops) {
			GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_configure "
			    "ops->gptwocfg_configure=%lx\n",
			    ops->gptwocfg_configure);

			GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_unconfigure "
			    "ops->gptwocfg_unconfigure=%lx\n",
			    ops->gptwocfg_unconfigure);

			if (ops->gptwocfg_unconfigure != NULL) {
				config->gptwo_nodes->gptwo_nodes[i] =
				    ops->gptwocfg_unconfigure(saf_dip);

			}
		}

		GPTWO_DEBUG1(1, CE_CONT, "e_ddi_branch_destroy <%s>\n",
		    ddi_get_name(saf_dip));

		ASSERT(e_ddi_branch_held(saf_dip));

		/*
		 * Don't hold parent busy when calling
		 * e_ddi_branch_unconfigure/destroy/referenced()
		 */
		ndi_devi_exit(ap, circ);
		if (e_ddi_branch_destroy(saf_dip, &fdip, 0)) {
			char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

			/*
			 * If non-NULL, fdip is held and must be released.
			 */
			if (fdip != NULL) {
				(void) ddi_pathname(fdip, path);
				ddi_release_devi(fdip);
			} else {
				(void) ddi_pathname(saf_dip, path);
			}

			cmn_err(CE_WARN, "saf node removal failed: %s (%p)",
			    path, fdip ? (void *)fdip : (void *)saf_dip);

			kmem_free(path, MAXPATHLEN);

			config->gptwo_nodes->gptwo_nodes[i] = saf_dip;
			failure = 1;
		}
		ndi_devi_enter(ap, &circ);
	}

	ndi_devi_exit(ap, circ);

	if (!failure) {
		gptwocfg_free_node_list(config->gptwo_nodes);

		mutex_enter(&gptwo_config_list_lock);
		if (gptwo_config_list == config) {
			gptwo_config_list = config->gptwo_next;
		} else {
			temp = gptwo_config_list;
			while (temp->gptwo_next != config) {
				temp = temp->gptwo_next;
			}
			temp->gptwo_next = config->gptwo_next;
		}
		mutex_exit(&gptwo_config_list_lock);

		kmem_free(config, sizeof (gptwocfg_config_t));
		config = NULL;
	}

	return (config);
}

int
gptwocfg_next_node(gptwocfg_cookie_t c, dev_info_t *previous, dev_info_t **next)
{
	gptwocfg_config_t *cookie;
	int i, j;

	GPTWO_DEBUG3(1, CE_WARN, "gptwocfg_next_node"
	    "(c=0x%lx, previous=0x%lx, next=0x%lx)\n", c, previous, next);

	cookie = (gptwocfg_config_t *)c;

	for (i = 0; i < cookie->gptwo_nodes->gptwo_number_of_nodes; i++) {
		GPTWO_DEBUG1(1, CE_WARN, "0x%lx\n",
		    cookie->gptwo_nodes->gptwo_nodes[i]);
	}

	if (previous == NULL) {
		for (i = 0; i < cookie->gptwo_nodes->gptwo_number_of_nodes;
		    i++) {
			if (cookie->gptwo_nodes->gptwo_nodes[i]) {
				*next = cookie->gptwo_nodes->gptwo_nodes[i];
				GPTWO_DEBUG1(1, CE_WARN, "returned 0x%lx\n",
				    *next);
				return (1);
			}
		}
		return (0);
	}

	for (i = 0; i < cookie->gptwo_nodes->gptwo_number_of_nodes; i++) {
		if (cookie->gptwo_nodes->gptwo_nodes[i] == previous) {
			for (j = i + 1;
			    j < cookie->gptwo_nodes->gptwo_number_of_nodes;
			    j++) {
				if (cookie->gptwo_nodes->gptwo_nodes[j]) {
					*next =
					    cookie->gptwo_nodes->gptwo_nodes[j];
					GPTWO_DEBUG1(1, CE_WARN,
					    "returned 0x%lx\n",	*next);
					return (1);
				}
			}
			*next = NULL;
			GPTWO_DEBUG1(1, CE_WARN, "returned 0x%lx\n",
			    *next);
			return (1);
		}
	}

	/*
	 * previous is probably an invalid dev_info.
	 */
	return (0);
}

static gptwo_new_nodes_t *
gptwocfg_get_obp_created_nodes(dev_info_t *ap, uint_t id)
{
	gptwo_new_nodes_t *obp_nodes;
	dev_info_t *saf_dev;
	int i = 0, nodes = 0;
	int circular_count;

	GPTWO_DEBUG2(1, CE_CONT, "gptwocfg_get_obp_created_nodes - ap=0x%lx "
	    "id=0x%x\n", ap, id);

	ndi_devi_enter(ap, &circular_count);

	/*
	 * First go through all the children of the attachment point
	 * to count matching safari agent ids
	 */
	saf_dev = ddi_get_child(ap);
	while (saf_dev != NULL) {
		if (ddi_getprop(DDI_DEV_T_ANY, saf_dev, DDI_PROP_DONTPASS,
		    "portid", -1) == id) {
			nodes++;
		}
		saf_dev = ddi_get_next_sibling(saf_dev);
	}

	GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_get_obp_created_nodes - %d nodes "
	    "found\n", nodes);

	obp_nodes = gptwocfg_allocate_node_list(nodes);

	/*
	 * Then fill in the nodes structure.
	 */
	saf_dev = ddi_get_child(ap);
	while ((saf_dev != NULL) && (i < nodes)) {
		if (ddi_getprop(DDI_DEV_T_ANY, saf_dev, DDI_PROP_DONTPASS,
		    "portid", -1) == id) {
			/*
			 * Branch rooted at this dip must have been
			 * held by the DR driver.
			 */
			ASSERT(e_ddi_branch_held(saf_dev));
			obp_nodes->gptwo_nodes[i++] = saf_dev;
		}
		saf_dev = ddi_get_next_sibling(saf_dev);
	}

	ndi_devi_exit(ap, circular_count);

	GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_get_obp_created_nodes - "
	    "Returning 0x%lx\n", obp_nodes);

	return (obp_nodes);
}

void
gptwocfg_save_handle(dev_info_t *dip, fco_handle_t fco_handle)
{
	gptwocfg_handle_list_t *h;

	GPTWO_DEBUG2(1, CE_CONT, "gptwocfg_save_handle - "
	    "dip=%lx fco_handle=%lx\n", dip, fco_handle);

	h = kmem_zalloc(sizeof (gptwocfg_handle_list_t), KM_SLEEP);

	mutex_enter(&gptwo_handle_list_lock);

	h->next = gptwocfg_handle_list;
	h->dip = dip;
	h->fco_handle = fco_handle;
	gptwocfg_handle_list = h;

	mutex_exit(&gptwo_handle_list_lock);
}

fco_handle_t
gptwocfg_get_handle(dev_info_t *dip)
{
	gptwocfg_handle_list_t *h, *last;
	fco_handle_t fco_handle;

	mutex_enter(&gptwo_handle_list_lock);

	h = last = gptwocfg_handle_list;

	while (h != NULL) {
		if (h->dip == dip) {
			if (h == gptwocfg_handle_list)
				gptwocfg_handle_list = h->next;
			else
				last->next = h->next;

			mutex_exit(&gptwo_handle_list_lock);

			fco_handle = h->fco_handle;

			kmem_free(h, sizeof (gptwocfg_handle_list_t));

			GPTWO_DEBUG2(1, CE_CONT, "gptwocfg_get_handle - "
			    "dip=%lx fco_handle=%lx\n", dip, fco_handle);

			return (fco_handle);
		}
		last = h;
		h = h->next;
	}

	mutex_exit(&gptwo_handle_list_lock);

	GPTWO_DEBUG1(1, CE_CONT, "gptwocfg_get_handle - dip=%lx NO HANDLE\n",
	    dip);

	return (0);
}

void
gptwocfg_devi_attach_to_parent(dev_info_t *dip)
{
	(void) i_ndi_config_node(dip, DS_LINKED, 0);
}

#ifdef DEBUG
static void
debug(char *fmt, uintptr_t a1, uintptr_t a2, uintptr_t a3,
    uintptr_t a4, uintptr_t a5)
{
	cmn_err(CE_CONT, fmt, a1, a2, a3, a4, a5);
}
#endif
