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
 * Schizo/PCI Functions to the Safari Configurator
 *
 */

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/conf.h>
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
#include <sys/machsystm.h>
#include <sys/gp2cfg.h>
#include <sys/gptwo_pci.h>

#ifdef DEBUG
int gptwo_pci_debug = 0;

static void debug(char *, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t);

#define	GPTWO_DEBUG0(level, flag, s) if (gptwo_pci_debug >= level) \
    cmn_err(flag, s)
#define	GPTWO_DEBUG1(level, flag, fmt, a1) if (gptwo_pci_debug >= level) \
    debug(fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	GPTWO_DEBUG2(level, flag, fmt, a1, a2) if (gptwo_pci_debug >= level) \
    debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	GPTWO_DEBUG3(level, flag, fmt, a1, a2, a3) \
    if (gptwo_pci_debug >= level) \
    debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), (uintptr_t)(a3), 0, 0);
#else
#define	GPTWO_DEBUG0(level, flag, s)
#define	GPTWO_DEBUG1(level, flag, fmt, a1)
#define	GPTWO_DEBUG2(level, flag, fmt, a1, a2)
#define	GPTWO_DEBUG3(level, flag, fmt, a1, a2, a3)
#endif

void gptwocfg_devi_attach_to_parent(dev_info_t *);
static char *gptwo_get_probe_string(spcd_t *, int);
static void gptwo_find_nodes(dev_info_t *, int, gptwo_new_nodes_t *);

extern caddr_t efcode_vaddr;
extern int efcode_size;

/*
 * Module linkage information for the kernel.
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, /* Type of module */
	"gptwo->pci configurator",
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	int err = 0;

	/*
	 * Create a resource map for the contigous memory allocated
	 * at start-of-day in startup.c
	 */
	if (ndi_ra_map_setup(ddi_root_node(), "gptwo-contigousmem")
	    == NDI_FAILURE) {
		GPTWO_DEBUG0(1, CE_WARN,
		    "Can not setup resource map - gptwo-contigousmem\n");
		return (1);
	}

	/*
	 * Put the allocated memory into the pool.
	 */
	(void) ndi_ra_free(ddi_root_node(), (uint64_t)efcode_vaddr,
	    (uint64_t)efcode_size, "gptwo-contigousmem", 0);

	/* register devices with the configurator */
	gptwocfg_register_ops(SAFPTYPE_sPCI, gptwo_configure_pci,
	    gptwo_unconfigure_pci);
	gptwocfg_register_ops(SAFPTYPE_cPCI, gptwo_configure_pci,
	    gptwo_unconfigure_pci);
	gptwocfg_register_ops(SAFPTYPE_PCIX, gptwo_configure_pci,
	    gptwo_unconfigure_pci);

	if ((err = mod_install(&modlinkage)) != 0) {
		GPTWO_DEBUG1(1, CE_WARN, "gptwo_pci (PCI Functions) "
		"failed to load, error=%d\n", err);
		gptwocfg_unregister_ops(SAFPTYPE_sPCI);
		gptwocfg_unregister_ops(SAFPTYPE_cPCI);
		gptwocfg_unregister_ops(SAFPTYPE_PCIX);
	} else {
		GPTWO_DEBUG0(1, CE_WARN, "gptwo_pci (PCI Functions) "
		"has been loaded.\n");
	}
	return (err);
}

int
_fini(void)
{
	gptwocfg_unregister_ops(SAFPTYPE_sPCI);
	gptwocfg_unregister_ops(SAFPTYPE_cPCI);
	gptwocfg_unregister_ops(SAFPTYPE_PCIX);
	return (mod_remove(&modlinkage));
}

int
_info(modinfop)
struct modinfo *modinfop;
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
set_name_prop(dev_info_t *dip, void *arg, uint_t flags)
{
	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "name", "pci") != DDI_SUCCESS) {
		return (DDI_WALK_ERROR);
	}

	return (DDI_WALK_TERMINATE);
}

/*ARGSUSED*/
static void
get_new_child(dev_info_t *rdip, void *arg, uint_t flags)
{
	dev_info_t **dipp = (dev_info_t **)arg;

	ASSERT(dipp && (*dipp == NULL));

	*dipp = rdip;
}

gptwo_new_nodes_t *
gptwo_configure_pci(dev_info_t *ap, spcd_t *pcd, uint_t id)
{
	fco_handle_t fco_handle;
	int error, i, circ, freq;
	dev_info_t *new_child;
	char unit_address[64];
	gptwo_new_nodes_t *new_nodes;
	char *probe_string;
	devi_branch_t b = {0};

	GPTWO_DEBUG2(1, CE_CONT, "gptwo_configure_pci: id=%x pcd=%lx\n",
	    id, pcd);

	new_nodes = gptwocfg_allocate_node_list(IOBUS_PER_PORT);

	i = IOBUS_PER_PORT;

	while (i) {
		i--;

		if (pcd->spcd_iobus_rsv[i] != SPCD_RSV_PASS) {

			cmn_err(CE_WARN, "gptwo_configure_pci: saf id=0x%x "
			    "leaf %d - Can not be probed\n", id, i);

			continue;
		}

		/*
		 * Ideally, fcode would be run from the "sid_branch_create"
		 * callback (that is the primary purpose of that callback).
		 * However, the fcode interpreter was written with the
		 * assumption that the "new_child" was linked into the
		 * device tree. The callback is invoked with the devinfo node
		 * in the DS_PROTO state. More investigation is needed before
		 * we can invoke the interpreter from the callback. For now,
		 * we create the "new_child" in the BOUND state, invoke the
		 * fcode interpreter and then rebind the dip to use any
		 * compatible properties created by fcode.
		 */

		new_child = NULL;

		b.arg = &new_child;
		b.type = DEVI_BRANCH_SID;
		b.create.sid_branch_create = set_name_prop;
		b.devi_branch_callback = get_new_child;

		/*
		 * Prevent any changes to new_child
		 * until we have bound it to the correct driver.
		 */
		ndi_devi_enter(ap, &circ);
		if (e_ddi_branch_create(ap, &b, NULL, 0)) {
			ASSERT(new_child == NULL);

			if (new_nodes->gptwo_nodes[0] == NULL) {
				GPTWO_DEBUG0(1, CE_CONT, "gptwo_configure_pci: "
				    "No nodes configured - "
				    "removing new_nodes\n");
				gptwocfg_free_node_list(new_nodes);
				new_nodes = NULL;
			}

			ndi_devi_exit(ap, circ);

			return (new_nodes);
		}

		/*
		 * The platform DR interfaces created the dip in
		 * bound state. Bring devinfo node down to linked
		 * state and hold it there until compatible
		 * properties are created.
		 */
		e_ddi_branch_rele(new_child);
		(void) i_ndi_unconfig_node(new_child, DS_LINKED, 0);
		ASSERT(i_ddi_node_state(new_child) == DS_LINKED);
		e_ddi_branch_hold(new_child);

		mutex_enter(&DEVI(new_child)->devi_lock);
		DEVI(new_child)->devi_flags |= DEVI_NO_BIND;
		mutex_exit(&DEVI(new_child)->devi_lock);

		/*
		 * Drop the busy-hold on parent before calling
		 * fcode_interpreter to prevent potential deadlocks
		 */
		ndi_devi_exit(ap, circ);

		(void) sprintf(unit_address, "%x", id);

		/*
		 * Build the probe string from the PCD that will be passed
		 * in to the interpreter as my-args.  This will tell the
		 * fcode what pci devices to probe after the pci node has
		 * been probed.
		 */
		probe_string = gptwo_get_probe_string(pcd, i);

		GPTWO_DEBUG3(1, CE_CONT, "gptwo_configure_pci: args to "
		    "interpreter ap=%lx new_child=%lx unit_address=%s\n",
		    ap, new_child, unit_address);

		if (probe_string)
			GPTWO_DEBUG1(1, CE_CONT, "gptwo_configure_pci: "
			    "probe string=%s\n", probe_string);

		fco_handle = gp2_fc_ops_alloc_handle(ap, new_child, NULL, NULL,
		    unit_address, probe_string);

		GPTWO_DEBUG0(1, CE_CONT,
		    "gptwocfg: Calling Fcode Interpeter...\n");

		error = fcode_interpreter(ap, &gp2_fc_ops, fco_handle);

		GPTWO_DEBUG1(1, CE_CONT,
		    "gptwo_configure_pci: fcode_interpreter "
		    " returned %x\n", error);

		if (error) {
			cmn_err(CE_WARN, "gptwo_pci: Unable to probe pci leaf "
			    "%s\n", unit_address);

			gp2_fc_ops_free_handle(fco_handle);

			(void) e_ddi_branch_destroy(new_child, NULL, 0);
		} else {
			gptwocfg_save_handle(new_child, fco_handle);

			/*
			 * Compatible properties (if any) have been created,
			 * so bind driver.
			 */
			ndi_devi_enter(ap, &circ);
			ASSERT(i_ddi_node_state(new_child) <= DS_LINKED);

			mutex_enter(&DEVI(new_child)->devi_lock);
			DEVI(new_child)->devi_flags &= ~DEVI_NO_BIND;
			mutex_exit(&DEVI(new_child)->devi_lock);

			ndi_devi_exit(ap, circ);

			if (ndi_devi_bind_driver(new_child, 0) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN, "gptwo_pci: Unable to bind"
				    " new pci child at dip=0x%p\n",
				    new_child);
			}

			/*
			 * If POST provided a frequency, the clock-frequency
			 * property needs to be updated.
			 */
			if (pcd->spcd_afreq) {

				/*
				 * The upper byte is for leaf B and the lower
				 * byte is for leaf A.
				 */
				if (i)
					freq = pcd->spcd_afreq >> 8;
				else
					freq = pcd->spcd_afreq & 0x00ff;

				(void) ndi_prop_update_int(DDI_DEV_T_NONE,
				    new_child, "clock-frequency",
				    (freq * 1000 * 1000));
			}
		}
	}

	gptwo_find_nodes(ap, id, new_nodes);

	if (new_nodes->gptwo_nodes[0] == NULL) {
		GPTWO_DEBUG0(1, CE_CONT, "gptwo_configure_pci: "
		    "No nodes configured - removing new_nodes\n");
		gptwocfg_free_node_list(new_nodes);
		new_nodes = NULL;
	}

	GPTWO_DEBUG1(1, CE_CONT, "gptwo_configure_pci: "
	    "Returning new_nodes=%p\n", new_nodes);

	return (new_nodes);
}

dev_info_t *
gptwo_unconfigure_pci(dev_info_t *dip)
{
	fco_handle_t fco_handle;

	fco_handle = gptwocfg_get_handle(dip);

	if (fco_handle != NULL) {
		/*
		 * If there is a handle, there may be resources
		 * that need to be freed from when the
		 * devices's fcode ran.
		 */
		GPTWO_DEBUG1(1, CE_CONT, "fco_handle=%lx\n", fco_handle);
		gp2_fc_ops_free_handle(fco_handle);
	}
	return (NULL);
}

static void
gptwo_find_nodes(dev_info_t *ap, int id, gptwo_new_nodes_t *new_nodes)
{
	dev_info_t *saf_dev;
	int found, j, circ;
	int i = 0;

	GPTWO_DEBUG1(1, CE_CONT, "gptwo_find_nodes - id=%x\n", id);

	/*
	 * We are walking child list of ap, so hold it busy
	 */
	ndi_devi_enter(ap, &circ);

	saf_dev = ddi_get_child(ap);
	while (saf_dev != NULL) {
		if (ddi_getprop(DDI_DEV_T_ANY, saf_dev,
		    DDI_PROP_DONTPASS, "portid", -1) == id) {
			if (i < IOBUS_PER_PORT) {

				GPTWO_DEBUG2(1, CE_CONT,
				    "gptwo_find_nodes - "
				    "Found %d %p\n", i, saf_dev);

				found = 0;
				for (j = 0; j < IOBUS_PER_PORT; j++) {
					if (new_nodes->gptwo_nodes[j] ==
					    saf_dev) {
						found = 1;
					}
				}
				if (!found) {
					/*
					 * Branch rooted at saf-dev was
					 * held earlier.
					 */
					ASSERT(e_ddi_branch_held(saf_dev));
					new_nodes->gptwo_nodes[i] = saf_dev;
					i++;
				}
			} else {
				GPTWO_DEBUG0(1, CE_CONT,
				    "gptwo_find_nodes - "
				    "No room in new_nodes\n");
			}
		}
		saf_dev = ddi_get_next_sibling(saf_dev);
	}

	ndi_devi_exit(ap, circ);
}

static char *
gptwo_get_probe_string(spcd_t *pcd, int bus_number)
{
	int i, str_size;
	char temp[64];
	char num[8];
	char *probe;

	GPTWO_DEBUG2(1, CE_CONT, "gptwo_get_probe_string - %p %x\n", pcd,
	    bus_number);

	temp[0] = NULL;

	for (i = 0; i < IOCARD_PER_BUS; i++) {

		GPTWO_DEBUG2(1, CE_CONT, "gptwo_get_probe_string - "
		    "card status %x %x\n",
		    i, pcd->spcd_iocard_rsv[bus_number][i]);

		if (pcd->spcd_iocard_rsv[bus_number][i] == SPCD_RSV_PASS) {
			numtos(i, num);
			if (temp[0] == NULL)
				(void) sprintf(temp, "%s", num);
			else
				(void) sprintf(temp, "%s,%s", temp, num);
		}
	}

	if (bus_number == 0)
		(void) sprintf(temp, "%sa", temp); /* Append a 'a' for leaf A */
	else
		(void) sprintf(temp, "%sb", temp); /* Append a 'b' for leaf B */

	str_size = strlen(temp);

	if (str_size == 0)
		return (NULL);

	probe = kmem_zalloc(str_size + 1, KM_SLEEP);

	(void) strcpy(probe, temp);

	GPTWO_DEBUG1(1, CE_CONT, "gptwo_get_probe_string - Returning %s\n",
	    probe);

	return (probe);
}

#ifdef DEBUG
static void
debug(char *fmt, uintptr_t a1, uintptr_t a2, uintptr_t a3,
	uintptr_t a4, uintptr_t a5)
{
	cmn_err(CE_CONT, fmt, a1, a2, a3, a4, a5);
}
#endif
