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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/promif.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/debug.h>
#include <sys/psm_common.h>
#include <sys/sunndi.h>
#include <sys/ksynch.h>

/* Global configurables */

char *psm_module_name;	/* used to store name of psm module */

/*
 * acpi_irq_check_elcr: when set elcr will also be consulted for building
 * the reserved irq list.  When 0 (false), the existing state of the ELCR
 * is ignored when selecting a vector during IRQ translation, and the ELCR
 * is programmed to the proper setting for the type of bus (level-triggered
 * for PCI, edge-triggered for non-PCI).  When non-zero (true), vectors
 * set to edge-mode will not be used when in PIC-mode.  The default value
 * is 0 (false).  Note that ACPI's SCI vector is always set to conform to
 * ACPI-specification regardless of this.
 *
 */
int acpi_irq_check_elcr = 0;

int psm_verbose = 0;

#define	PSM_VERBOSE_IRQ(fmt)	\
		if (psm_verbose & PSM_VERBOSE_IRQ_FLAG) \
			cmn_err fmt;

#define	PSM_VERBOSE_POWEROFF(fmt)  \
		if (psm_verbose & PSM_VERBOSE_POWEROFF_FLAG || \
		    psm_verbose & PSM_VERBOSE_POWEROFF_PAUSE_FLAG) \
			prom_printf fmt;

#define	PSM_VERBOSE_POWEROFF_PAUSE(fmt) \
		if (psm_verbose & PSM_VERBOSE_POWEROFF_FLAG || \
		    psm_verbose & PSM_VERBOSE_POWEROFF_PAUSE_FLAG) {\
			prom_printf fmt; \
			if (psm_verbose & PSM_VERBOSE_POWEROFF_PAUSE_FLAG) \
				(void) goany(); \
		}


/* Local storage */
static ACPI_HANDLE acpi_sbobj = NULL;
static kmutex_t acpi_irq_cache_mutex;

/*
 * irq_cache_table is a list that serves a two-key cache. It is used
 * as a pci busid/devid/ipin <-> irq cache and also as a acpi
 * interrupt lnk <-> irq cache.
 */
static irq_cache_t *irq_cache_table;

#define	IRQ_CACHE_INITLEN	20
static int irq_cache_len = 0;
static int irq_cache_valid = 0;

static int acpi_get_gsiv(dev_info_t *dip, ACPI_HANDLE pciobj, int devno,
	int ipin, int *pci_irqp, iflag_t *iflagp,  acpi_psm_lnk_t *acpipsmlnkp);

static int acpi_eval_lnk(dev_info_t *dip, char *lnkname,
    int *pci_irqp, iflag_t *intr_flagp, acpi_psm_lnk_t *acpipsmlnkp);

static int acpi_get_irq_lnk_cache_ent(ACPI_HANDLE lnkobj, int *pci_irqp,
    iflag_t *intr_flagp);

extern int goany(void);


#define	NEXT_PRT_ITEM(p)	\
		(void *)(((char *)(p)) + (p)->Length)

static int
acpi_get_gsiv(dev_info_t *dip, ACPI_HANDLE pciobj, int devno, int ipin,
    int *pci_irqp, iflag_t *intr_flagp, acpi_psm_lnk_t *acpipsmlnkp)
{
	ACPI_BUFFER rb;
	ACPI_PCI_ROUTING_TABLE *prtp;
	int status;
	int dev_adr;

	/*
	 * Get the IRQ routing table
	 */
	rb.Pointer = NULL;
	rb.Length = ACPI_ALLOCATE_BUFFER;
	if (AcpiGetIrqRoutingTable(pciobj, &rb) != AE_OK) {
		return (ACPI_PSM_FAILURE);
	}

	status = ACPI_PSM_FAILURE;
	dev_adr = (devno << 16 | 0xffff);
	for (prtp = rb.Pointer; prtp->Length != 0; prtp = NEXT_PRT_ITEM(prtp)) {
		/* look until a matching dev/pin is found */
		if (dev_adr != prtp->Address || ipin != prtp->Pin)
			continue;

		/* NULL Source name means index is GSIV */
		if (*prtp->Source == 0) {
			intr_flagp->intr_el = INTR_EL_LEVEL;
			intr_flagp->intr_po = INTR_PO_ACTIVE_LOW;
			ASSERT(pci_irqp != NULL);
			*pci_irqp = prtp->SourceIndex;
			status = ACPI_PSM_SUCCESS;
		} else
			status = acpi_eval_lnk(dip, prtp->Source, pci_irqp,
			    intr_flagp, acpipsmlnkp);

		break;

	}

	AcpiOsFree(rb.Pointer);
	return (status);
}

/*
 *
 * If the interrupt link device is already configured,
 * stores polarity and sensitivity in the structure pointed to by
 * intr_flagp, and irqno in the value pointed to by pci_irqp.
 *
 * Returns:
 *	ACPI_PSM_SUCCESS if the interrupt link device is already configured.
 *	ACPI_PSM_PARTIAL if configuration is needed.
 * 	ACPI_PSM_FAILURE in case of error.
 *
 * When two devices share the same interrupt link device, and the
 * link device is already configured (i.e. found in the irq cache)
 * we need to use the already configured irq instead of reconfiguring
 * the link device.
 */
static int
acpi_eval_lnk(dev_info_t *dip, char *lnkname, int *pci_irqp,
    iflag_t *intr_flagp, acpi_psm_lnk_t *acpipsmlnkp)
{
	ACPI_HANDLE	tmpobj;
	ACPI_HANDLE	lnkobj;
	int status;

	/*
	 * Convert the passed-in link device name to a handle
	 */
	if (AcpiGetHandle(NULL, lnkname, &lnkobj) != AE_OK) {
		return (ACPI_PSM_FAILURE);
	}

	/*
	 * Assume that the link device is invalid if no _CRS method
	 * exists, since _CRS method is a required method
	 */
	if (AcpiGetHandle(lnkobj, "_CRS", &tmpobj) != AE_OK) {
		return (ACPI_PSM_FAILURE);
	}

	ASSERT(acpipsmlnkp != NULL);
	acpipsmlnkp->lnkobj = lnkobj;
	if ((acpi_get_irq_lnk_cache_ent(lnkobj, pci_irqp, intr_flagp)) ==
	    ACPI_PSM_SUCCESS) {
		PSM_VERBOSE_IRQ((CE_CONT, "!psm: link object found from cache "
		    " for device %s, instance #%d, irq no %d\n",
		    ddi_get_name(dip), ddi_get_instance(dip), *pci_irqp));
		return (ACPI_PSM_SUCCESS);
	} else {
		if (acpica_eval_int(lnkobj, "_STA", &status) == AE_OK) {
			acpipsmlnkp->device_status = (uchar_t)status;
		}

		return (ACPI_PSM_PARTIAL);
	}
}

int
acpi_psm_init(char *module_name, int verbose_flags)
{
	psm_module_name = module_name;

	psm_verbose = verbose_flags;

	if (AcpiGetHandle(NULL, "\\_SB", &acpi_sbobj) != AE_OK) {
		cmn_err(CE_WARN, "!psm: get _SB failed");
		return (ACPI_PSM_FAILURE);
	}

	mutex_init(&acpi_irq_cache_mutex, NULL, MUTEX_DEFAULT, NULL);

	return (ACPI_PSM_SUCCESS);

}

/*
 * Return bus/dev/fn for PCI dip (note: not the parent "pci" node).
 */

int
get_bdf(dev_info_t *dip, int *bus, int *device, int *func)
{
	pci_regspec_t *pci_rp;
	int len;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&pci_rp, (uint_t *)&len) != DDI_SUCCESS)
		return (-1);

	if (len < (sizeof (pci_regspec_t) / sizeof (int))) {
		ddi_prop_free(pci_rp);
		return (-1);
	}
	if (bus != NULL)
		*bus = (int)PCI_REG_BUS_G(pci_rp->pci_phys_hi);
	if (device != NULL)
		*device = (int)PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	if (func != NULL)
		*func = (int)PCI_REG_FUNC_G(pci_rp->pci_phys_hi);
	ddi_prop_free(pci_rp);
	return (0);
}


/*
 * Build the reserved ISA irq list, and store it in the table pointed to by
 * reserved_irqs_table. The caller is responsible for allocating this table
 * with a minimum of MAX_ISA_IRQ + 1 entries.
 *
 * The routine looks in the device tree at the subtree rooted at /isa
 * for each of the devices under that node, if an interrupts property
 * is present, its values are used to "reserve" irqs so that later ACPI
 * configuration won't choose those irqs.
 *
 * In addition, if acpi_irq_check_elcr is set, will use ELCR register
 * to identify reserved IRQs.
 */
void
build_reserved_irqlist(uchar_t *reserved_irqs_table)
{
	dev_info_t *isanode = ddi_find_devinfo("isa", -1, 0);
	dev_info_t *isa_child = 0;
	int i;
	uint_t	elcrval;

	/* Initialize the reserved ISA IRQs: */
	for (i = 0; i <= MAX_ISA_IRQ; i++)
		reserved_irqs_table[i] = 0;

	if (acpi_irq_check_elcr) {

		elcrval = (inb(ELCR_PORT2) << 8) | (inb(ELCR_PORT1));
		if (ELCR_EDGE(elcrval, 0) && ELCR_EDGE(elcrval, 1) &&
		    ELCR_EDGE(elcrval, 2) && ELCR_EDGE(elcrval, 8) &&
		    ELCR_EDGE(elcrval, 13)) {
			/* valid ELCR */
			for (i = 0; i <= MAX_ISA_IRQ; i++)
				if (!ELCR_LEVEL(elcrval, i))
					reserved_irqs_table[i] = 1;
		}
	}

	/* always check the isa devinfo nodes */

	if (isanode != 0) { /* Found ISA */
		uint_t intcnt;		/* Interrupt count */
		int *intrs;		/* Interrupt values */

		/* Load first child: */
		isa_child = ddi_get_child(isanode);
		while (isa_child != 0) { /* Iterate over /isa children */
			/* if child has any interrupts, save them */
			if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, isa_child,
			    DDI_PROP_DONTPASS, "interrupts", &intrs, &intcnt)
			    == DDI_PROP_SUCCESS) {
				/*
				 * iterate over child interrupt list, adding
				 * them to the reserved irq list
				 */
				while (intcnt-- > 0) {
					/*
					 * Each value MUST be <= MAX_ISA_IRQ
					 */

					if ((intrs[intcnt] > MAX_ISA_IRQ) ||
					    (intrs[intcnt] < 0))
						continue;

					reserved_irqs_table[intrs[intcnt]] = 1;
				}
				ddi_prop_free(intrs);
			}
			isa_child = ddi_get_next_sibling(isa_child);
		}
		/* The isa node was held by ddi_find_devinfo, so release it */
		ndi_rele_devi(isanode);
	}

	/*
	 * Reserve IRQ14 & IRQ15 for IDE.  It shouldn't be hard-coded
	 * here but there's no other way to find the irqs for
	 * legacy-mode ata (since it's hard-coded in pci-ide also).
	 */
	reserved_irqs_table[14] = 1;
	reserved_irqs_table[15] = 1;
}

/*
 * Examine devinfo node to determine if it is a PCI-PCI bridge
 *
 * Returns:
 *	0 if not a bridge or error
 *	1 if a bridge
 */
static int
psm_is_pci_bridge(dev_info_t *dip)
{
	ddi_acc_handle_t cfg_handle;
	int rv = 0;

	if (pci_config_setup(dip, &cfg_handle) == DDI_SUCCESS) {
		rv = ((pci_config_get8(cfg_handle, PCI_CONF_BASCLASS) ==
		    PCI_CLASS_BRIDGE) && (pci_config_get8(cfg_handle,
		    PCI_CONF_SUBCLASS) == PCI_BRIDGE_PCI));
		pci_config_teardown(&cfg_handle);
	}

	return (rv);
}

/*
 * Examines ACPI node for presence of _PRT object
 * Check _STA to make sure node is present and/or enabled
 *
 * Returns:
 *	0 if no _PRT or error
 *	1 if _PRT is present
 */
static int
psm_node_has_prt(ACPI_HANDLE *ah)
{
	ACPI_HANDLE rh;
	int sta;

	/*
	 * Return 0 for "no _PRT" if device does not exist
	 * According to ACPI Spec,
	 * 1) setting either bit 0 or bit 3 means that device exists.
	 * 2) Absence of _STA method means all status bits set.
	 */
	if (ACPI_SUCCESS(acpica_eval_int(ah, "_STA", &sta)) &&
	    !(sta & (ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_FUNCTIONING)))
		return (0);

	return (AcpiGetHandle(ah, "_PRT", &rh) == AE_OK);
}


/*
 * Look first for an ACPI PCI bus node matching busid, then for a _PRT on the
 * parent node; then drop into the bridge-chasing code (which will also
 * look for _PRTs on the way up the tree of bridges)
 *
 * Stores polarity and sensitivity in the structure pointed to by
 * intr_flagp, and irqno in the value pointed to by pci_irqp.  *
 * Returns:
 *  	ACPI_PSM_SUCCESS on success.
 *	ACPI_PSM_PARTIAL to indicate need to configure the interrupt
 *	link device.
 * 	ACPI_PSM_FAILURE  if an error prevented the system from
 *	obtaining irq information for dip.
 */
int
acpi_translate_pci_irq(dev_info_t *dip, int ipin, int *pci_irqp,
    iflag_t *intr_flagp, acpi_psm_lnk_t *acpipsmlnkp)
{
	ACPI_HANDLE pciobj;
	int status = AE_ERROR;
	dev_info_t *curdip, *parentdip;
	int curpin, curbus, curdev;


	curpin = ipin;
	curdip = dip;
	while (curdip != ddi_root_node()) {
		parentdip = ddi_get_parent(curdip);
		ASSERT(parentdip != NULL);

		if (get_bdf(curdip, &curbus, &curdev, NULL) != 0)
			break;

		status = acpica_get_handle(parentdip, &pciobj);
		if ((status == AE_OK) && psm_node_has_prt(pciobj)) {
			return (acpi_get_gsiv(curdip, pciobj, curdev, curpin,
			    pci_irqp, intr_flagp, acpipsmlnkp));
		}

		/* if we got here, we need to traverse a bridge upwards */
		if (!psm_is_pci_bridge(parentdip))
			break;

		/*
		 * This is the rotating scheme that Compaq is using
		 * and documented in the PCI-PCI spec.  Also, if the
		 * PCI-PCI bridge is behind another PCI-PCI bridge,
		 * then it needs to keep ascending until an interrupt
		 * entry is found or the top is reached
		 */
		curpin = (curdev + curpin) % PCI_INTD;
		curdip = parentdip;
	}

	/*
	 * We should never, ever get here; didn't find a _PRT
	 */
	return (ACPI_PSM_FAILURE);
}

/*
 * Sets the irq resource of the lnk object to the requested irq value.
 *
 * Returns ACPI_PSM_SUCCESS on success, ACPI_PSM_FAILURE upon failure.
 */
int
acpi_set_irq_resource(acpi_psm_lnk_t *acpipsmlnkp, int irq)
{
	ACPI_BUFFER	rsb;
	ACPI_RESOURCE	*resp;
	ACPI_RESOURCE	*srsp;
	ACPI_HANDLE lnkobj;
	int srs_len, status;

	ASSERT(acpipsmlnkp != NULL);

	lnkobj = acpipsmlnkp->lnkobj;

	/*
	 * Fetch the possible resources for the link
	 */

	rsb.Pointer = NULL;
	rsb.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiGetPossibleResources(lnkobj, &rsb);
	if (status != AE_OK) {
		cmn_err(CE_WARN, "!psm: set_irq: _PRS failed");
		return (ACPI_PSM_FAILURE);
	}

	/*
	 * Find an IRQ resource descriptor to use as template
	 */
	srsp = NULL;
	for (resp = rsb.Pointer; resp->Type != ACPI_RESOURCE_TYPE_END_TAG;
	    resp = ACPI_NEXT_RESOURCE(resp)) {
		if ((resp->Type == ACPI_RESOURCE_TYPE_IRQ) ||
		    (resp->Type == ACPI_RESOURCE_TYPE_EXTENDED_IRQ)) {
			ACPI_RESOURCE *endtag;
			/*
			 * Allocate enough room for this resource entry
			 * and one end tag following it
			 */
			srs_len = resp->Length + sizeof (*endtag);
			srsp = kmem_zalloc(srs_len, KM_SLEEP);
			bcopy(resp, srsp, resp->Length);
			endtag = ACPI_NEXT_RESOURCE(srsp);
			endtag->Type = ACPI_RESOURCE_TYPE_END_TAG;
			endtag->Length = 0;
			break;	/* drop out of the loop */
		}
	}

	/*
	 * We're done with the PRS values, toss 'em lest we forget
	 */
	AcpiOsFree(rsb.Pointer);

	if (srsp == NULL)
		return (ACPI_PSM_FAILURE);

	/*
	 * The Interrupts[] array is always at least one entry
	 * long; see the definition of ACPI_RESOURCE.
	 */
	switch (srsp->Type) {
	case ACPI_RESOURCE_TYPE_IRQ:
		srsp->Data.Irq.InterruptCount = 1;
		srsp->Data.Irq.Interrupts[0] = (uint8_t)irq;
		break;
	case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
		srsp->Data.ExtendedIrq.InterruptCount = 1;
		srsp->Data.ExtendedIrq.Interrupts[0] = irq;
		break;
	}

	rsb.Pointer = srsp;
	rsb.Length = srs_len;
	status = AcpiSetCurrentResources(lnkobj, &rsb);
	kmem_free(srsp, srs_len);
	if (status != AE_OK) {
		cmn_err(CE_WARN, "!psm: set_irq: _SRS failed");
		return (ACPI_PSM_FAILURE);
	}

	if (acpica_eval_int(lnkobj, "_STA", &status) == AE_OK) {
		acpipsmlnkp->device_status = (uchar_t)status;
		return (ACPI_PSM_SUCCESS);
	} else
		return (ACPI_PSM_FAILURE);
}


/*
 *
 */
static int
psm_acpi_edgelevel(UINT32 el)
{
	switch (el) {
	case ACPI_EDGE_SENSITIVE:
		return (INTR_EL_EDGE);
	case ACPI_LEVEL_SENSITIVE:
		return (INTR_EL_LEVEL);
	default:
		/* el is a single bit; should never reach here */
		return (INTR_EL_CONFORM);
	}
}


/*
 *
 */
static int
psm_acpi_po(UINT32 po)
{
	switch (po) {
	case ACPI_ACTIVE_HIGH:
		return (INTR_PO_ACTIVE_HIGH);
	case ACPI_ACTIVE_LOW:
		return (INTR_PO_ACTIVE_LOW);
	default:
		/* po is a single bit; should never reach here */
		return (INTR_PO_CONFORM);
	}
}


/*
 * Retrieves the current irq setting for the interrrupt link device.
 *
 * Stores polarity and sensitivity in the structure pointed to by
 * intr_flagp, and irqno in the value pointed to by pci_irqp.
 *
 * Returns ACPI_PSM_SUCCESS on success, ACPI_PSM_FAILURE upon failure.
 */
int
acpi_get_current_irq_resource(acpi_psm_lnk_t *acpipsmlnkp, int *pci_irqp,
    iflag_t *intr_flagp)
{
	ACPI_HANDLE lnkobj;
	ACPI_BUFFER rb;
	ACPI_RESOURCE *rp;
	int irq;
	int status = ACPI_PSM_FAILURE;

	ASSERT(acpipsmlnkp != NULL);
	lnkobj = acpipsmlnkp->lnkobj;

	if (!(acpipsmlnkp->device_status & STA_PRESENT) ||
	    !(acpipsmlnkp->device_status & STA_ENABLE)) {
		PSM_VERBOSE_IRQ((CE_WARN, "!psm: crs device either not "
		    "present or disabled, status 0x%x",
		    acpipsmlnkp->device_status));
		return (ACPI_PSM_FAILURE);
	}

	rb.Pointer = NULL;
	rb.Length = ACPI_ALLOCATE_BUFFER;
	if (AcpiGetCurrentResources(lnkobj, &rb) != AE_OK) {
		PSM_VERBOSE_IRQ((CE_WARN, "!psm: no crs object found or"
		" evaluation failed"));
		return (ACPI_PSM_FAILURE);
	}

	irq = -1;
	for (rp = rb.Pointer; rp->Type != ACPI_RESOURCE_TYPE_END_TAG;
	    rp = ACPI_NEXT_RESOURCE(rp)) {
		if (rp->Type == ACPI_RESOURCE_TYPE_IRQ) {
			if (irq > 0) {
				PSM_VERBOSE_IRQ((CE_WARN, "!psm: multiple IRQ"
				" from _CRS "));
				status = ACPI_PSM_FAILURE;
				break;
			}

			if (rp->Data.Irq.InterruptCount != 1) {
				PSM_VERBOSE_IRQ((CE_WARN, "!psm: <>1 interrupt"
				" from _CRS "));
				status = ACPI_PSM_FAILURE;
				break;
			}

			intr_flagp->intr_el = psm_acpi_edgelevel(
			    rp->Data.Irq.Triggering);
			intr_flagp->intr_po = psm_acpi_po(
			    rp->Data.Irq.Polarity);
			irq = rp->Data.Irq.Interrupts[0];
			status = ACPI_PSM_SUCCESS;
		} else if (rp->Type == ACPI_RESOURCE_TYPE_EXTENDED_IRQ) {
			if (irq > 0) {
				PSM_VERBOSE_IRQ((CE_WARN, "!psm: multiple IRQ"
				" from _CRS "));
				status = ACPI_PSM_FAILURE;
				break;
			}

			if (rp->Data.ExtendedIrq.InterruptCount != 1) {
				PSM_VERBOSE_IRQ((CE_WARN, "!psm: <>1 interrupt"
				" from _CRS "));
				status = ACPI_PSM_FAILURE;
				break;
			}

			intr_flagp->intr_el = psm_acpi_edgelevel(
			    rp->Data.ExtendedIrq.Triggering);
			intr_flagp->intr_po = psm_acpi_po(
			    rp->Data.ExtendedIrq.Polarity);
			irq = rp->Data.ExtendedIrq.Interrupts[0];
			status = ACPI_PSM_SUCCESS;
		}
	}

	AcpiOsFree(rb.Pointer);
	if (status == ACPI_PSM_SUCCESS) {
		*pci_irqp =  irq;
	}

	return (status);
}

/*
 * Searches for the given IRQ in the irqlist passed in.
 *
 * If multiple matches exist, this returns true on the first match.
 * Returns the interrupt flags, if a match was found, in `intr_flagp' if
 * it's passed in non-NULL
 */
int
acpi_irqlist_find_irq(acpi_irqlist_t *irqlistp, int irq, iflag_t *intr_flagp)
{
	int found = 0;
	int i;

	while (irqlistp != NULL && !found) {
		for (i = 0; i < irqlistp->num_irqs; i++) {
			if (irqlistp->irqs[i] == irq) {
				if (intr_flagp)
					*intr_flagp = irqlistp->intr_flags;
				found = 1;
				break;	/* out of for() */
			}
		}
	}

	return (found ? ACPI_PSM_SUCCESS : ACPI_PSM_FAILURE);
}

/*
 * Frees the irqlist allocated by acpi_get_possible_irq_resource.
 * It takes a count of number of entries in the list.
 */
void
acpi_free_irqlist(acpi_irqlist_t *irqlistp)
{
	acpi_irqlist_t *freednode;

	while (irqlistp != NULL) {
		/* Free the irq list */
		kmem_free(irqlistp->irqs, irqlistp->num_irqs *
		    sizeof (int32_t));

		freednode = irqlistp;
		irqlistp = irqlistp->next;
		kmem_free(freednode, sizeof (acpi_irqlist_t));
	}
}

/*
 * Creates a new entry in the given irqlist with the information passed in.
 */
static void
acpi_add_irqlist_entry(acpi_irqlist_t **irqlistp, uint32_t *irqlist,
    int irqlist_len, iflag_t *intr_flagp)
{
	acpi_irqlist_t *newent;

	ASSERT(irqlist != NULL);
	ASSERT(intr_flagp != NULL);

	newent = kmem_alloc(sizeof (acpi_irqlist_t), KM_SLEEP);
	newent->intr_flags = *intr_flagp;
	newent->irqs = irqlist;
	newent->num_irqs = irqlist_len;
	newent->next = *irqlistp;

	*irqlistp = newent;
}


/*
 * Retrieves a list of possible interrupt settings for the interrupt link
 * device.
 *
 * Stores polarity and sensitivity in the structure pointed to by intr_flagp.
 * Updates value pointed to by irqlistp with the address of a table it
 * allocates. where interrupt numbers are stored. Stores the number of entries
 * in this table in the value pointed to by num_entriesp;
 *
 * Each element in this table is of type int32_t. The table should be later
 * freed by caller via acpi_free_irq_list().
 *
 * Returns ACPI_PSM_SUCCESS on success and ACPI_PSM_FAILURE upon failure
 */
int
acpi_get_possible_irq_resources(acpi_psm_lnk_t *acpipsmlnkp,
    acpi_irqlist_t **irqlistp)
{
	ACPI_HANDLE lnkobj;
	ACPI_BUFFER rsb;
	ACPI_RESOURCE *resp;
	int status;

	int i, el, po, irqlist_len;
	uint32_t *irqlist;
	void *tmplist;
	iflag_t intr_flags;

	ASSERT(acpipsmlnkp != NULL);
	lnkobj = acpipsmlnkp->lnkobj;

	rsb.Pointer = NULL;
	rsb.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiGetPossibleResources(lnkobj, &rsb);
	if (status != AE_OK) {
		cmn_err(CE_WARN, "!psm: get_irq: _PRS failed");
		return (ACPI_PSM_FAILURE);
	}

	/*
	 * Scan the resources looking for an interrupt resource
	 */
	*irqlistp = 0;
	for (resp = rsb.Pointer; resp->Type != ACPI_RESOURCE_TYPE_END_TAG;
	    resp = ACPI_NEXT_RESOURCE(resp)) {
		switch (resp->Type) {
		case ACPI_RESOURCE_TYPE_IRQ:
			irqlist_len = resp->Data.Irq.InterruptCount;
			tmplist = resp->Data.Irq.Interrupts;
			el = resp->Data.Irq.Triggering;
			po = resp->Data.Irq.Polarity;
			break;
		case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
			irqlist_len = resp->Data.ExtendedIrq.InterruptCount;
			tmplist = resp->Data.ExtendedIrq.Interrupts;
			el = resp->Data.ExtendedIrq.Triggering;
			po = resp->Data.ExtendedIrq.Polarity;
			break;
		default:
			continue;
		}

		if (resp->Type != ACPI_RESOURCE_TYPE_IRQ &&
		    resp->Type != ACPI_RESOURCE_TYPE_EXTENDED_IRQ) {
			cmn_err(CE_WARN, "!psm: get_irq: no IRQ resource");
			return (ACPI_PSM_FAILURE);
		}

		/* NEEDSWORK: move this into add_irqlist_entry someday */
		irqlist = kmem_zalloc(irqlist_len * sizeof (*irqlist),
		    KM_SLEEP);
		for (i = 0; i < irqlist_len; i++)
			if (resp->Type == ACPI_RESOURCE_TYPE_IRQ)
				irqlist[i] = ((uint8_t *)tmplist)[i];
			else
				irqlist[i] = ((uint32_t *)tmplist)[i];
		intr_flags.intr_el = psm_acpi_edgelevel(el);
		intr_flags.intr_po = psm_acpi_po(po);
		acpi_add_irqlist_entry(irqlistp, irqlist, irqlist_len,
		    &intr_flags);
	}

	AcpiOsFree(rsb.Pointer);
	return (irqlistp == NULL ? ACPI_PSM_FAILURE : ACPI_PSM_SUCCESS);
}

/*
 * Adds a new cache entry to the irq cache which maps an irq and
 * its attributes to PCI bus/dev/ipin and optionally to its associated ACPI
 * interrupt link device object.
 */
void
acpi_new_irq_cache_ent(int bus, int dev, int ipin, int pci_irq,
    iflag_t *intr_flagp, acpi_psm_lnk_t *acpipsmlnkp)
{
	int newsize;
	irq_cache_t *new_arr, *ep;

	mutex_enter(&acpi_irq_cache_mutex);
	if (irq_cache_valid >= irq_cache_len) {
		/* initially, or re-, allocate array */

		newsize = (irq_cache_len ?
		    irq_cache_len * 2 : IRQ_CACHE_INITLEN);
		new_arr = kmem_zalloc(newsize * sizeof (irq_cache_t), KM_SLEEP);
		if (irq_cache_len != 0) {
			/* realloc: copy data, free old */
			bcopy(irq_cache_table, new_arr,
			    irq_cache_len * sizeof (irq_cache_t));
			kmem_free(irq_cache_table,
			    irq_cache_len * sizeof (irq_cache_t));
		}
		irq_cache_len = newsize;
		irq_cache_table = new_arr;
	}
	ep = &irq_cache_table[irq_cache_valid++];
	ep->bus = (uchar_t)bus;
	ep->dev = (uchar_t)dev;
	ep->ipin = (uchar_t)ipin;
	ep->flags = *intr_flagp;
	ep->irq = (uchar_t)pci_irq;
	ASSERT(acpipsmlnkp != NULL);
	ep->lnkobj = acpipsmlnkp->lnkobj;
	mutex_exit(&acpi_irq_cache_mutex);
}


/*
 * Searches the irq caches for the given bus/dev/ipin.
 *
 * If info is found, stores polarity and sensitivity in the structure
 * pointed to by intr_flagp, and irqno in the value pointed to by pci_irqp,
 * and returns ACPI_PSM_SUCCESS.
 * Otherwise, ACPI_PSM_FAILURE is returned.
 */
int
acpi_get_irq_cache_ent(uchar_t bus, uchar_t dev, int ipin,
    int *pci_irqp, iflag_t *intr_flagp)
{

	irq_cache_t *irqcachep;
	int i;
	int ret = ACPI_PSM_FAILURE;

	mutex_enter(&acpi_irq_cache_mutex);
	for (irqcachep = irq_cache_table, i = 0; i < irq_cache_valid;
	    irqcachep++, i++)
		if ((irqcachep->bus == bus) &&
		    (irqcachep->dev == dev) &&
		    (irqcachep->ipin == ipin)) {
			ASSERT(pci_irqp != NULL && intr_flagp != NULL);
			*pci_irqp = irqcachep->irq;
			*intr_flagp = irqcachep->flags;
			ret = ACPI_PSM_SUCCESS;
			break;
		}

	mutex_exit(&acpi_irq_cache_mutex);
	return (ret);
}

/*
 * Searches the irq caches for the given interrupt lnk device object.
 *
 * If info is found, stores polarity and sensitivity in the structure
 * pointed to by intr_flagp, and irqno in the value pointed to by pci_irqp,
 * and returns ACPI_PSM_SUCCESS.
 * Otherwise, ACPI_PSM_FAILURE is returned.
 */
int
acpi_get_irq_lnk_cache_ent(ACPI_HANDLE lnkobj, int *pci_irqp,
    iflag_t *intr_flagp)
{

	irq_cache_t *irqcachep;
	int i;
	int ret = ACPI_PSM_FAILURE;

	if (lnkobj == NULL)
		return (ACPI_PSM_FAILURE);

	mutex_enter(&acpi_irq_cache_mutex);
	for (irqcachep = irq_cache_table, i = 0; i < irq_cache_valid;
	    irqcachep++, i++)
		if (irqcachep->lnkobj == lnkobj) {
			ASSERT(pci_irqp != NULL);
			*pci_irqp = irqcachep->irq;
			ASSERT(intr_flagp != NULL);
			*intr_flagp = irqcachep->flags;
			ret = ACPI_PSM_SUCCESS;
			break;
		}
	mutex_exit(&acpi_irq_cache_mutex);
	return (ret);
}

/*
 * Walk the irq_cache_table and re-configure the link device to
 * the saved state.
 */
void
acpi_restore_link_devices(void)
{
	irq_cache_t *irqcachep;
	acpi_psm_lnk_t psmlnk;
	int i, status;

	/* XXX: may not need to hold this mutex */
	mutex_enter(&acpi_irq_cache_mutex);
	for (irqcachep = irq_cache_table, i = 0; i < irq_cache_valid;
	    irqcachep++, i++) {
		if (irqcachep->lnkobj != NULL) {
			/* only field used from psmlnk in set_irq is lnkobj */
			psmlnk.lnkobj = irqcachep->lnkobj;
			status = acpi_set_irq_resource(&psmlnk, irqcachep->irq);
			/* warn if set_irq failed; soldier on */
			if (status != ACPI_PSM_SUCCESS)
				cmn_err(CE_WARN, "Could not restore interrupt "
				    "link device for IRQ 0x%x: Devices using "
				    "this IRQ may no longer function properly."
				    "\n", irqcachep->irq);
		}
	}
	mutex_exit(&acpi_irq_cache_mutex);
}

int
acpi_poweroff(void)
{
	extern int acpica_use_safe_delay;
	ACPI_STATUS status;

	PSM_VERBOSE_POWEROFF(("acpi_poweroff: starting poweroff\n"));

	acpica_use_safe_delay = 1;

	status = AcpiEnterSleepStatePrep(5);
	if (status != AE_OK) {
		PSM_VERBOSE_POWEROFF(("acpi_poweroff: failed to prepare for "
		    "poweroff, status=0x%x\n", status));
		return (1);
	}
	ACPI_DISABLE_IRQS();
	status = AcpiEnterSleepState(5);
	ACPI_ENABLE_IRQS();

	/* we should be off; if we get here it's an error */
	PSM_VERBOSE_POWEROFF(("acpi_poweroff: failed to actually power "
	    "off, status=0x%x\n", status));
	return (1);
}


/*
 * psm_set_elcr() sets ELCR bit for specified vector
 */
void
psm_set_elcr(int vecno, int val)
{
	int elcr_port = ELCR_PORT1 + (vecno >> 3);
	int elcr_bit = 1 << (vecno & 0x07);

	ASSERT((vecno >= 0) && (vecno < 16));

	if (val) {
		/* set bit to force level-triggered mode */
		outb(elcr_port, inb(elcr_port) | elcr_bit);
	} else {
		/* clear bit to force edge-triggered mode */
		outb(elcr_port, inb(elcr_port) & ~elcr_bit);
	}
}

/*
 * psm_get_elcr() returns status of ELCR bit for specific vector
 */
int
psm_get_elcr(int vecno)
{
	int elcr_port = ELCR_PORT1 + (vecno >> 3);
	int elcr_bit = 1 << (vecno & 0x07);

	ASSERT((vecno >= 0) && (vecno < 16));

	return ((inb(elcr_port) & elcr_bit) ? 1 : 0);
}
