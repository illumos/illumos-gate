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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Peter Tribble.
 */

/*
 * Psycho+ specifics implementation:
 *	interrupt mapping register
 *	PBM configuration
 *	ECC and PBM error handling
 *	Iommu mapping handling
 *	Streaming Cache flushing
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/async.h>
#include <sys/systm.h>
#include <sys/intreg.h>		/* UPAID_TO_IGN() */
#include <sys/ivintr.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/machsystm.h>
#include <sys/fm/util.h>
#include <sys/ddi_impldefs.h>
#include <sys/iommutsb.h>
#include <sys/spl.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/fm/io/pci.h>
#include <sys/fm/io/sun4upci.h>
#include <sys/pci/pci_obj.h>
#include <sys/pci/pcipsy.h>

static uint32_t pci_identity_init(pci_t *pci_p);
static int pci_intr_setup(pci_t *pci_p);
static void pci_pbm_errstate_get(pci_t *pci_p, pbm_errstate_t *pbm_err_p);

static pci_ksinfo_t	*pci_name_kstat;

/*LINTLIBRARY*/
/* called by pci_attach() DDI_ATTACH to initialize pci objects */
int
pci_obj_setup(pci_t *pci_p)
{
	pci_common_t *cmn_p;
	int ret;

	mutex_enter(&pci_global_mutex);
	cmn_p = get_pci_common_soft_state(pci_p->pci_id);
	if (cmn_p == NULL) {
		uint_t id = pci_p->pci_id;
		if (alloc_pci_common_soft_state(id) != DDI_SUCCESS) {
			mutex_exit(&pci_global_mutex);
			return (DDI_FAILURE);
		}
		cmn_p = get_pci_common_soft_state(id);
		cmn_p->pci_common_id = id;
	}

	ASSERT((pci_p->pci_side == 0) || (pci_p->pci_side == 1));
	if (cmn_p->pci_p[pci_p->pci_side]) {
		/* second side attach */
		pci_p->pci_side = PCI_OTHER_SIDE(pci_p->pci_side);
		ASSERT(cmn_p->pci_p[pci_p->pci_side] == NULL);
	}

	cmn_p->pci_p[pci_p->pci_side] = pci_p;
	pci_p->pci_common_p = cmn_p;

	if (cmn_p->pci_common_refcnt == 0) {
		/* Perform allocation first to avoid delicate unwinding. */
		if (pci_alloc_tsb(pci_p) != DDI_SUCCESS) {
			cmn_p->pci_p[pci_p->pci_side] = NULL;
			pci_p->pci_common_p = NULL;
			free_pci_common_soft_state(cmn_p->pci_common_id);
			mutex_exit(&pci_global_mutex);
			return (DDI_FAILURE);
		}
		cmn_p->pci_common_tsb_cookie = pci_p->pci_tsb_cookie;
		cmn_p->pci_chip_id = pci_identity_init(pci_p);

		ib_create(pci_p);
		cmn_p->pci_common_ib_p = pci_p->pci_ib_p;

		cb_create(pci_p);
		cmn_p->pci_common_cb_p = pci_p->pci_cb_p;

		iommu_create(pci_p);
		cmn_p->pci_common_iommu_p = pci_p->pci_iommu_p;

		ecc_create(pci_p);
		cmn_p->pci_common_ecc_p = pci_p->pci_ecc_p;
	} else {
		ASSERT(cmn_p->pci_common_refcnt == 1);

		pci_p->pci_tsb_cookie = cmn_p->pci_common_tsb_cookie;
		pci_p->pci_ib_p = cmn_p->pci_common_ib_p;
		pci_p->pci_cb_p = cmn_p->pci_common_cb_p;
		pci_p->pci_iommu_p = cmn_p->pci_common_iommu_p;
		pci_p->pci_ecc_p = cmn_p->pci_common_ecc_p;
	}

	pbm_create(pci_p);
	sc_create(pci_p);

	pci_fm_create(pci_p);

	if ((ret = pci_intr_setup(pci_p)) != DDI_SUCCESS)
		goto done;
	if (CHIP_TYPE(pci_p) == PCI_CHIP_PSYCHO)
		pci_kstat_create(pci_p);

	cmn_p->pci_common_attachcnt++;
	cmn_p->pci_common_refcnt++;
done:
	mutex_exit(&pci_global_mutex);
	if (ret != DDI_SUCCESS)
		cmn_err(CE_NOTE, "Interrupt register failure, returning 0x%x\n",
		    ret);
	return (ret);
}

/* called by pci_detach() DDI_DETACH to destroy pci objects */
void
pci_obj_destroy(pci_t *pci_p)
{
	pci_common_t *cmn_p;

	mutex_enter(&pci_global_mutex);

	cmn_p = pci_p->pci_common_p;
	cmn_p->pci_common_refcnt--;
	cmn_p->pci_common_attachcnt--;

	pci_kstat_destroy(pci_p);

	sc_destroy(pci_p);
	pbm_destroy(pci_p);
	pci_fm_destroy(pci_p);

	if (cmn_p->pci_common_refcnt != 0) {
		cmn_p->pci_p[pci_p->pci_side] = NULL;
		mutex_exit(&pci_global_mutex);
		return;
	}

	ecc_destroy(pci_p);
	iommu_destroy(pci_p);
	cb_destroy(pci_p);
	ib_destroy(pci_p);

	free_pci_common_soft_state(cmn_p->pci_common_id);
	pci_intr_teardown(pci_p);
	mutex_exit(&pci_global_mutex);
}

/* called by pci_attach() DDI_RESUME to (re)initialize pci objects */
void
pci_obj_resume(pci_t *pci_p)
{
	pci_common_t *cmn_p = pci_p->pci_common_p;

	mutex_enter(&pci_global_mutex);

	if (cmn_p->pci_common_attachcnt == 0) {
		ib_configure(pci_p->pci_ib_p);
		iommu_configure(pci_p->pci_iommu_p);
		ecc_configure(pci_p);
		ib_resume(pci_p->pci_ib_p);
	}

	pbm_configure(pci_p->pci_pbm_p);
	sc_configure(pci_p->pci_sc_p);

	if (cmn_p->pci_common_attachcnt == 0)
		cb_resume(pci_p->pci_cb_p);

	pbm_resume(pci_p->pci_pbm_p);

	cmn_p->pci_common_attachcnt++;
	mutex_exit(&pci_global_mutex);
}

/* called by pci_detach() DDI_SUSPEND to suspend pci objects */
void
pci_obj_suspend(pci_t *pci_p)
{
	mutex_enter(&pci_global_mutex);

	pbm_suspend(pci_p->pci_pbm_p);
	if (!--pci_p->pci_common_p->pci_common_attachcnt) {
		ib_suspend(pci_p->pci_ib_p);
		cb_suspend(pci_p->pci_cb_p);
	}

	mutex_exit(&pci_global_mutex);
}

static uint32_t javelin_prom_fix[] = {0xfff800, 0, 0, 0x3f};
static int
pci_intr_setup(pci_t *pci_p)
{
	extern char *platform;
	dev_info_t *dip = pci_p->pci_dip;
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	cb_t *cb_p = pci_p->pci_cb_p;
	int i, no_of_intrs;

	/*
	 * This is a hack to fix a broken imap entry in the javelin PROM.
	 * see bugid 4226603
	 */
	if (strcmp((const char *)&platform, "SUNW,Ultra-250") == 0)
		(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
		    "interrupt-map-mask", (caddr_t)javelin_prom_fix,
		    sizeof (javelin_prom_fix));

	/*
	 * Get the interrupts property.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupts", (caddr_t)&pci_p->pci_inos,
	    &pci_p->pci_inos_len) != DDI_SUCCESS)
		cmn_err(CE_PANIC, "%s%d: no interrupts property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));

	/*
	 * figure out number of interrupts in the "interrupts" property
	 * and convert them all into ino.
	 */
	i = ddi_getprop(DDI_DEV_T_ANY, dip, 0, "#interrupt-cells", 1);
	i = CELLS_1275_TO_BYTES(i);
	no_of_intrs = pci_p->pci_inos_len / i;
	for (i = 0; i < no_of_intrs; i++)
		pci_p->pci_inos[i] = IB_MONDO_TO_INO(pci_p->pci_inos[i]);

	if (pci_p->pci_common_p->pci_common_refcnt == 0) {
		cb_p->cb_no_of_inos = no_of_intrs;
		if (i = cb_register_intr(pci_p))
			goto teardown;
		if (i = ecc_register_intr(pci_p))
			goto teardown;

		intr_dist_add(cb_intr_dist, cb_p);
		cb_enable_intr(pci_p);
		ecc_enable_intr(pci_p);
	}

	if (i = pbm_register_intr(pbm_p)) {
		if (pci_p->pci_common_p->pci_common_refcnt == 0)
			intr_dist_rem(cb_intr_dist, cb_p);
		goto teardown;
	}
	intr_dist_add(pbm_intr_dist, pbm_p);
	ib_intr_enable(pci_p, pci_p->pci_inos[CBNINTR_PBM]);

	if (pci_p->pci_common_p->pci_common_refcnt == 0)
		intr_dist_add_weighted(ib_intr_dist_all, pci_p->pci_ib_p);
	return (DDI_SUCCESS);
teardown:
	pci_intr_teardown(pci_p);
	return (i);
}

/*
 * pci_fix_ranges - fixes the config space entry of the "ranges"
 *	property on psycho+ platforms
 */
void
pci_fix_ranges(pci_ranges_t *rng_p, int rng_entries)
{
	int i;
	for (i = 0; i < rng_entries; i++, rng_p++)
		if ((rng_p->child_high & PCI_REG_ADDR_M) == PCI_ADDR_CONFIG)
			rng_p->parent_low |= rng_p->child_high;
}

/*
 * map_pci_registers
 *
 * This function is called from the attach routine to map the registers
 * accessed by this driver.
 *
 * used by: pci_attach()
 *
 * return value: DDI_FAILURE on failure
 */
int
map_pci_registers(pci_t *pci_p, dev_info_t *dip)
{
	ddi_device_acc_attr_t attr;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	if (ddi_regs_map_setup(dip, 0, &pci_p->pci_address[0], 0, 0,
	    &attr, &pci_p->pci_ac[0]) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: unable to map reg entry 0\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}
	/*
	 * if we don't have streaming buffer, then we don't have
	 * pci_address[2].
	 */
	if (pci_stream_buf_exists &&
	    ddi_regs_map_setup(dip, 2, &pci_p->pci_address[2], 0, 0,
	    &attr, &pci_p->pci_ac[2]) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: unable to map reg entry 2\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		ddi_regs_map_free(&pci_p->pci_ac[0]);
		return (DDI_FAILURE);
	}

	/*
	 * The second register set contains the bridge's configuration
	 * header.  This header is at the very beginning of the bridge's
	 * configuration space.  This space has litte-endian byte order.
	 */
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	if (ddi_regs_map_setup(dip, 1, &pci_p->pci_address[1], 0,
	    PCI_CONF_HDR_SIZE, &attr, &pci_p->pci_ac[1]) != DDI_SUCCESS) {

		cmn_err(CE_WARN, "%s%d: unable to map reg entry 1\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		ddi_regs_map_free(&pci_p->pci_ac[0]);
		if (pci_stream_buf_exists)
			ddi_regs_map_free(&pci_p->pci_ac[2]);
		return (DDI_FAILURE);
	}
	DEBUG3(DBG_ATTACH, dip, "address (%p,%p,%p)\n",
	    pci_p->pci_address[0], pci_p->pci_address[1],
	    pci_p->pci_address[2]);

	return (DDI_SUCCESS);
}

/*
 * unmap_pci_registers:
 *
 * This routine unmap the registers mapped by map_pci_registers.
 *
 * used by: pci_detach()
 *
 * return value: none
 */
void
unmap_pci_registers(pci_t *pci_p)
{
	ddi_regs_map_free(&pci_p->pci_ac[0]);
	ddi_regs_map_free(&pci_p->pci_ac[1]);
	if (pci_stream_buf_exists)
		ddi_regs_map_free(&pci_p->pci_ac[2]);
}

/*
 * These convenience wrappers relies on map_pci_registers() to setup
 * pci_address[0-2] correctly at first.
 */
/* The psycho+ reg base is at 1fe.0000.0000 */
static uintptr_t
get_reg_base(pci_t *pci_p)
{
	return ((uintptr_t)pci_p->pci_address[pci_stream_buf_exists ? 2 : 0]);
}

/* The psycho+ config reg base is always the 2nd reg entry */
static uintptr_t
get_config_reg_base(pci_t *pci_p)
{
	return ((uintptr_t)(pci_p->pci_address[1]));
}

uint64_t
ib_get_map_reg(ib_mondo_t mondo, uint32_t cpu_id)
{
	return ((mondo) | (cpu_id << COMMON_INTR_MAP_REG_TID_SHIFT) |
	    COMMON_INTR_MAP_REG_VALID);

}

uint32_t
ib_map_reg_get_cpu(volatile uint64_t reg)
{
	return ((reg & COMMON_INTR_MAP_REG_TID) >>
	    COMMON_INTR_MAP_REG_TID_SHIFT);
}

uint64_t *
ib_intr_map_reg_addr(ib_t *ib_p, ib_ino_t ino)
{
	uint64_t *addr;

	if (ino & 0x20)
		addr = (uint64_t *)(ib_p->ib_obio_intr_map_regs +
		    (((uint_t)ino & 0x1f) << 3));
	else
		addr = (uint64_t *)(ib_p->ib_slot_intr_map_regs +
		    (((uint_t)ino & 0x3c) << 1));
	return (addr);
}

uint64_t *
ib_clear_intr_reg_addr(ib_t *ib_p, ib_ino_t ino)
{
	uint64_t *addr;

	if (ino & 0x20)
		addr = (uint64_t *)(ib_p->ib_obio_clear_intr_regs +
		    (((uint_t)ino & 0x1f) << 3));
	else
		addr = (uint64_t *)(ib_p->ib_slot_clear_intr_regs +
		    (((uint_t)ino & 0x1f) << 3));
	return (addr);
}

/*
 * psycho have one mapping register per slot
 */
void
ib_ino_map_reg_share(ib_t *ib_p, ib_ino_t ino, ib_ino_info_t *ino_p)
{
	if (!IB_IS_OBIO_INO(ino)) {
		ASSERT(ino_p->ino_slot_no < 8);
		ib_p->ib_map_reg_counters[ino_p->ino_slot_no]++;
	}
}

/*
 * return true if the ino shares mapping register with other interrupts
 * of the same slot, or is still shared by other On-board devices.
 */
int
ib_ino_map_reg_unshare(ib_t *ib_p, ib_ino_t ino, ib_ino_info_t *ino_p)
{
	ASSERT(IB_IS_OBIO_INO(ino) || ino_p->ino_slot_no < 8);

	if (IB_IS_OBIO_INO(ino))
		return (ino_p->ino_ipil_size);
	else
		return (--ib_p->ib_map_reg_counters[ino_p->ino_slot_no]);
}

/*ARGSUSED*/
void
pci_pbm_intr_dist(pbm_t *pbm_p)
{
}

uintptr_t
pci_ib_setup(ib_t *ib_p)
{
	pci_t *pci_p = ib_p->ib_pci_p;
	uintptr_t a = get_reg_base(pci_p);

	ib_p->ib_ign = PCI_ID_TO_IGN(pci_p->pci_id);
	ib_p->ib_max_ino = PSYCHO_MAX_INO;
	ib_p->ib_slot_intr_map_regs = a + PSYCHO_IB_SLOT_INTR_MAP_REG_OFFSET;
	ib_p->ib_obio_intr_map_regs = a + PSYCHO_IB_OBIO_INTR_MAP_REG_OFFSET;
	ib_p->ib_obio_clear_intr_regs =
	    a + PSYCHO_IB_OBIO_CLEAR_INTR_REG_OFFSET;
	return (a);
}

uint32_t
pci_xlate_intr(dev_info_t *dip, dev_info_t *rdip, ib_t *ib_p, uint32_t intr)
{
	int32_t len;
	dev_info_t *cdip;
	pci_regspec_t *pci_rp;
	uint32_t bus, dev, phys_hi;

	if ((intr > PCI_INTD) || (intr < PCI_INTA))
		goto done;
	if (ddi_prop_exists(DDI_DEV_T_ANY, rdip, 0, "interrupt-map"))
		goto done;
	/*
	 * Hack for pre 1275 imap machines e.g. quark & tazmo
	 * We need to turn any PCI interrupts into ino interrupts.  machines
	 * supporting imap will have this done in the map.
	 */
	cdip = get_my_childs_dip(dip, rdip);
	if (ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&pci_rp, &len) != DDI_SUCCESS)
		return (0);
	phys_hi = pci_rp->pci_phys_hi;
	kmem_free(pci_rp, len);

	bus = PCI_REG_BUS_G(phys_hi);
	dev = PCI_REG_DEV_G(phys_hi);

	/*
	 * The ino for a given device id is derived as 0BSSNN where
	 *
	 *	B = 0 for bus A, 1 for bus B
	 *	SS = dev - 1 for bus A, dev - 2 for bus B
	 *	NN = 00 for INTA#, 01 for INTB#, 10 for INTC#, 11 for INTD#
	 *
	 * if pci bus number > 0x80, then devices are located on the A side(66)
	 */
	DEBUG3(DBG_IB, dip, "pci_xlate_intr: bus=%x, dev=%x, intr=%x\n",
	    bus, dev, intr);
	intr--;
	intr |= (bus & 0x80) ? ((dev - 1) << 2) : (0x10 | ((dev - 2) << 2));

	DEBUG1(DBG_IB, dip, "pci_xlate_intr: done ino=%x\n", intr);
done:
	return (IB_INO_TO_MONDO(ib_p, intr));
}

/*
 * Return the cpuid to to be used for an ino. Psycho has special slot-cpu
 * constraints on cpu assignment:
 *
 * On multi-function pci cards, functions have separate devinfo nodes and
 * interrupts. Some pci support hardware, such as the psycho/pcipsy chip,
 * control interrupt-to-cpu binding on a per pci-slot basis instead of per
 * function.  For hardware like this, if an interrupt for one function has
 * already been directed to a particular cpu, we can't choose a different
 * cpu for another function implemented in the same pci-slot - if we did
 * we would be redirecting the first function too (which causes problems
 * for consistent interrupt distribution).
 *
 * This function determines if there is already an established slot-oriented
 * interrupt-to-cpu binding established, if there is then it returns that
 * cpu.  Otherwise a new cpu is selected by intr_dist_cpuid().
 *
 * The devinfo node we are trying to associate a cpu with is
 * ino_p->ino_ipil_p->ipil_ih_head->ih_dip.
 */
uint32_t
pci_intr_dist_cpuid(ib_t *ib_p, ib_ino_info_t *ino_p)
{
	dev_info_t	*rdip = ino_p->ino_ipil_p->ipil_ih_head->ih_dip;
	dev_info_t	*prdip = ddi_get_parent(rdip);
	ib_ino_info_t	*sino_p;
	dev_info_t	*sdip;
	dev_info_t	*psdip;
	char		*buf1 = NULL, *buf2 = NULL;
	char		*s1, *s2, *s3;
	int		l2;
	int		cpu_id;

	/* must be psycho driver parent (not ebus) */
	if (strcmp(ddi_driver_name(prdip), "pcipsy") != 0)
		goto newcpu;

	/*
	 * From PCI 1275 binding: 2.2.1.3 Unit Address representation:
	 *   Since the "unit-number" is the address that appears in on Open
	 *   Firmware 'device path', it follows that only the DD and DD,FF
	 *   forms of the text representation can appear in a 'device path'.
	 *
	 * The rdip unit address is of the form "DD[,FF]".  Define two
	 * unit address strings that represent same-slot use: "DD" and "DD,".
	 * The first compare uses strcmp, the second uses strncmp.
	 */
	s1 = ddi_get_name_addr(rdip);
	if (s1 == NULL)
		goto newcpu;

	buf1 = kmem_alloc(MAXNAMELEN, KM_SLEEP);	/* strcmp */
	buf2 = kmem_alloc(MAXNAMELEN, KM_SLEEP);	/* strncmp */
	s1 = strcpy(buf1, s1);
	s2 = strcpy(buf2, s1);

	s1 = strrchr(s1, ',');
	if (s1) {
		*s1 = '\0';			/* have "DD,FF" */
		s1 = buf1;			/* search via strcmp "DD" */

		s2 = strrchr(s2, ',');
		*(s2 + 1) = '\0';
		s2 = buf2;
		l2 = strlen(s2);		/* search via strncmp "DD," */
	} else {
		(void) strcat(s2, ",");		/* have "DD" */
		l2 = strlen(s2);		/* search via strncmp "DD," */
	}

	/*
	 * Search the established ino list for devinfo nodes bound
	 * to an ino that matches one of the slot use strings.
	 */
	ASSERT(MUTEX_HELD(&ib_p->ib_ino_lst_mutex));
	for (sino_p = ib_p->ib_ino_lst; sino_p; sino_p = sino_p->ino_next_p) {
		/* skip self and non-established */
		if ((sino_p == ino_p) || (sino_p->ino_established == 0))
			continue;

		/* skip non-siblings */
		sdip = sino_p->ino_ipil_p->ipil_ih_head->ih_dip;
		psdip = ddi_get_parent(sdip);
		if (psdip != prdip)
			continue;

		/* must be psycho driver parent (not ebus) */
		if (strcmp(ddi_driver_name(psdip), "pcipsy") != 0)
			continue;

		s3 = ddi_get_name_addr(sdip);
		if ((s1 && (strcmp(s1, s3) == 0)) ||
		    (strncmp(s2, s3, l2) == 0)) {
			extern int intr_dist_debug;

			if (intr_dist_debug)
				cmn_err(CE_CONT, "intr_dist: "
				    "pcipsy`pci_intr_dist_cpuid "
				    "%s#%d %s: cpu %d established "
				    "by %s#%d %s\n", ddi_driver_name(rdip),
				    ddi_get_instance(rdip),
				    ddi_deviname(rdip, buf1), sino_p->ino_cpuid,
				    ddi_driver_name(sdip),
				    ddi_get_instance(sdip),
				    ddi_deviname(sdip, buf2));
			break;
		}
	}

	/* If a slot use match is found then use established cpu */
	if (sino_p) {
		cpu_id = sino_p->ino_cpuid;	/* target established cpu */
		goto out;
	}

newcpu:	cpu_id = intr_dist_cpuid();		/* target new cpu */

out:	if (buf1)
		kmem_free(buf1, MAXNAMELEN);
	if (buf2)
		kmem_free(buf2, MAXNAMELEN);
	return (cpu_id);
}


/*ARGSUSED*/
static void
cb_thermal_timeout(void *arg)
{
	do_shutdown();

	/*
	 * In case do_shutdown() fails to halt the system.
	 */
	(void) timeout((void(*)(void *))power_down, NULL,
	    thermal_powerdown_delay * hz);
}

/*
 * High-level handler for psycho's CBNINTR_THERMAL interrupt.
 *
 * Use timeout(9f) to implement the core functionality so that the
 * timeout(9f) function can sleep, if needed.
 */
/*ARGSUSED*/
uint_t
cb_thermal_intr(caddr_t a)
{
	cmn_err(CE_WARN, "pci: Thermal warning detected!\n");
	if (pci_thermal_intr_fatal) {
		(void) timeout(cb_thermal_timeout, NULL, 0);
	}
	return (DDI_INTR_CLAIMED);
}

void
pci_cb_teardown(pci_t *pci_p)
{
	cb_t	*cb_p = pci_p->pci_cb_p;
	uint32_t mondo;

	if (pci_p->pci_thermal_interrupt != -1) {
		mondo = ((pci_p->pci_cb_p->cb_ign  << PCI_INO_BITS) |
		    pci_p->pci_inos[CBNINTR_THERMAL]);
		mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

		cb_disable_nintr(cb_p, CBNINTR_THERMAL, IB_INTR_WAIT);
		VERIFY(rem_ivintr(mondo, pci_pil[CBNINTR_THERMAL]) == 0);
	}
}

int
cb_register_intr(pci_t *pci_p)
{
	uint32_t mondo;

	if (pci_p->pci_thermal_interrupt == -1)
		return (DDI_SUCCESS);

	mondo = ((pci_p->pci_cb_p->cb_ign << PCI_INO_BITS) |
	    pci_p->pci_inos[CBNINTR_THERMAL]);
	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

	VERIFY(add_ivintr(mondo, pci_pil[CBNINTR_THERMAL],
	    (intrfunc)cb_thermal_intr, (caddr_t)pci_p->pci_cb_p,
	    NULL, NULL) == 0);

	return (PCI_ATTACH_RETCODE(PCI_CB_OBJ, PCI_OBJ_INTR_ADD, DDI_SUCCESS));
}

void
cb_enable_intr(pci_t *pci_p)
{
	if (pci_p->pci_thermal_interrupt != -1)
		cb_enable_nintr(pci_p, CBNINTR_THERMAL);
}

uint64_t
cb_ino_to_map_pa(cb_t *cb_p, ib_ino_t ino)
{
	return (cb_p->cb_map_pa + ((ino & 0x1f) << 3));
}

uint64_t
cb_ino_to_clr_pa(cb_t *cb_p, ib_ino_t ino)
{
	return (cb_p->cb_clr_pa + ((ino & 0x1f) << 3));
}

/*
 * allow removal of exported/shared thermal interrupt
 */
int
cb_remove_xintr(pci_t *pci_p, dev_info_t *dip, dev_info_t *rdip,
    ib_ino_t ino, ib_mondo_t mondo)
{
	if (ino != pci_p->pci_inos[CBNINTR_THERMAL])
		return (DDI_FAILURE);

	cb_disable_nintr(pci_p->pci_cb_p, CBNINTR_THERMAL, IB_INTR_WAIT);
	VERIFY(rem_ivintr(mondo, pci_pil[CBNINTR_THERMAL]) == 0);

	DEBUG1(DBG_R_INTX, dip, "remove xintr %x\n", ino);
	return (DDI_SUCCESS);
}

int
pci_ecc_add_intr(pci_t *pci_p, int inum, ecc_intr_info_t *eii_p)
{
	uint32_t mondo;

	mondo = ((pci_p->pci_cb_p->cb_ign << PCI_INO_BITS) |
	    pci_p->pci_inos[inum]);
	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

	VERIFY(add_ivintr(mondo, pci_pil[inum], (intrfunc)ecc_intr,
	    (caddr_t)eii_p, NULL, NULL) == 0);

	return (PCI_ATTACH_RETCODE(PCI_ECC_OBJ, PCI_OBJ_INTR_ADD, DDI_SUCCESS));
}

void
pci_ecc_rem_intr(pci_t *pci_p, int inum, ecc_intr_info_t *eii_p)
{
	uint32_t mondo;

	mondo = ((pci_p->pci_cb_p->cb_ign << PCI_INO_BITS) |
	    pci_p->pci_inos[inum]);
	mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, mondo);

	VERIFY(rem_ivintr(mondo, pci_pil[inum]) == 0);
}

static int pbm_has_pass_1_cheerio(pci_t *pci_p);

void
pbm_configure(pbm_t *pbm_p)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;
	cb_t *cb_p = pci_p->pci_cb_p;
	dev_info_t *dip = pci_p->pci_dip;
	int instance = ddi_get_instance(dip);
	uint32_t mask = 1 << instance;
	uint64_t l;
	uint16_t s = 0;

	/*
	 * Workarounds for hardware bugs:
	 *
	 * bus parking
	 *
	 *	Pass 2 psycho parts have a bug that requires bus
	 *	parking to be disabled.
	 *
	 *	Pass 1 cheerio parts have a bug which prevents them
	 *	from working on a PBM with bus parking enabled.
	 *
	 * rerun disable
	 *
	 *	Pass 1 and 2 psycho's require that the rerun's be
	 *	enabled.
	 *
	 * retry limit
	 *
	 *	For pass 1 and pass 2 psycho parts we disable the
	 *	retry limit.  This is because the limit of 16 seems
	 *	too restrictive for devices that are children of pci
	 *	to pci bridges.  For pass 3 this limit will be 64.
	 *
	 * DMA write/PIO read sync
	 *
	 *	For pass 2 psycho, the disable this feature.
	 */
	l = lddphysio(cb_p->cb_base_pa + PSYCHO_CB_CONTROL_STATUS_REG_OFFSET);
	l &= PSYCHO_CB_CONTROL_STATUS_VER;
	l >>= PSYCHO_CB_CONTROL_STATUS_VER_SHIFT;

	DEBUG2(DBG_ATTACH, dip, "cb_create: ver=%d, mask=%x\n", l, mask);
	pci_rerun_disable = (uint32_t)-1;

	switch (l) {
	case 0:
		DEBUG0(DBG_ATTACH, dip, "cb_create: psycho pass 1\n");
		if (!pci_disable_pass1_workarounds) {
			if (pbm_has_pass_1_cheerio(pci_p))
				pci_bus_parking_enable &= ~mask;
			pci_rerun_disable &= ~mask;
			pci_retry_disable |= mask;
		}
		break;
	case 1:
		if (!pci_disable_pass2_workarounds) {
			pci_bus_parking_enable &= ~mask;
			pci_rerun_disable &= ~mask;
			pci_retry_disable |= mask;
			pci_dwsync_disable |= mask;
		}
		break;
	case 2:
		if (!pci_disable_pass3_workarounds) {
			pci_dwsync_disable |= mask;
			if (pbm_has_pass_1_cheerio(pci_p))
				pci_bus_parking_enable &= ~mask;
		}
		break;
	case 3:
		if (!pci_disable_plus_workarounds) {
			pci_dwsync_disable |= mask;
			if (pbm_has_pass_1_cheerio(pci_p))
				pci_bus_parking_enable &= ~mask;
		}
		break;
	default:
		if (!pci_disable_default_workarounds) {
			pci_dwsync_disable |= mask;
			if (pbm_has_pass_1_cheerio(pci_p))
				pci_bus_parking_enable &= ~mask;
		}
		break;
	}

	/*
	 * Clear any PBM errors.
	 */
	l = (PSYCHO_PCI_AFSR_E_MASK << PSYCHO_PCI_AFSR_PE_SHIFT) |
	    (PSYCHO_PCI_AFSR_E_MASK << PSYCHO_PCI_AFSR_SE_SHIFT);
	*pbm_p->pbm_async_flt_status_reg = l;

	/*
	 * Clear error bits in configuration status register.
	 */
	s = PCI_STAT_PERROR | PCI_STAT_S_PERROR |
	    PCI_STAT_R_MAST_AB | PCI_STAT_R_TARG_AB |
	    PCI_STAT_S_TARG_AB | PCI_STAT_S_PERROR;
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: conf status reg=%x\n", s);
	pbm_p->pbm_config_header->ch_status_reg = s;
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: conf status reg==%x\n",
	    pbm_p->pbm_config_header->ch_status_reg);

	l = *pbm_p->pbm_ctrl_reg;	/* save control register state */
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: ctrl reg==%llx\n", l);

	/*
	 * See if any SERR# signals are asserted.  We'll clear them later.
	 */
	if (l & COMMON_PCI_CTRL_SERR)
		cmn_err(CE_WARN, "%s%d: SERR asserted on pci bus\n",
		    ddi_driver_name(dip), instance);

	/*
	 * Determine if PCI bus is running at 33 or 66 mhz.
	 */
	if (l & COMMON_PCI_CTRL_SPEED)
		pbm_p->pbm_speed = PBM_SPEED_66MHZ;
	else
		pbm_p->pbm_speed = PBM_SPEED_33MHZ;
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: %d mhz\n",
	    pbm_p->pbm_speed  == PBM_SPEED_66MHZ ? 66 : 33);

	/*
	 * Enable error interrupts.
	 */
	if (pci_error_intr_enable & mask)
		l |= PSYCHO_PCI_CTRL_ERR_INT_EN;
	else
		l &= ~PSYCHO_PCI_CTRL_ERR_INT_EN;

	/*
	 * Disable pci streaming byte errors and error interrupts.
	 */
	pci_sbh_error_intr_enable &= ~mask;
	l &= ~PSYCHO_PCI_CTRL_SBH_INT_EN;

	/*
	 * Enable/disable bus parking.
	 */
	if ((pci_bus_parking_enable & mask) &&
	    !ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "no-bus-parking"))
		l |= PSYCHO_PCI_CTRL_ARB_PARK;
	else
		l &= ~PSYCHO_PCI_CTRL_ARB_PARK;

	/*
	 * Enable arbitration.
	 */
	if (pci_p->pci_side == B)
		l = (l & ~PSYCHO_PCI_CTRL_ARB_EN_MASK) | pci_b_arb_enable;
	else
		l = (l & ~PSYCHO_PCI_CTRL_ARB_EN_MASK) | pci_a_arb_enable;

	/*
	 * Make sure SERR is clear
	 */
	l |= COMMON_PCI_CTRL_SERR;

	/*
	 * Make sure power management interrupt is disabled.
	 */
	l &= ~PSYCHO_PCI_CTRL_WAKEUP_EN;

	/*
	 * Now finally write the control register with the appropriate value.
	 */
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: ctrl reg=%llx\n", l);
	*pbm_p->pbm_ctrl_reg = l;

	/*
	 * Allow the diag register to be set based upon variable that
	 * can be configured via /etc/system.
	 */
	l = *pbm_p->pbm_diag_reg;
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: PCI diag reg==%llx\n", l);
	if (pci_retry_disable & mask)
		l |= COMMON_PCI_DIAG_DIS_RETRY;
	if (pci_retry_enable & mask)
		l &= ~COMMON_PCI_DIAG_DIS_RETRY;
	if (pci_intsync_disable & mask)
		l |= COMMON_PCI_DIAG_DIS_INTSYNC;
	else
		l &= ~COMMON_PCI_DIAG_DIS_INTSYNC;
	if (pci_dwsync_disable & mask)
		l |= PSYCHO_PCI_DIAG_DIS_DWSYNC;
	else
		l &= ~PSYCHO_PCI_DIAG_DIS_DWSYNC;
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: PCI diag reg=%llx\n", l);
	*pbm_p->pbm_diag_reg = l;

	/*
	 * Enable SERR# and parity reporting via command register.
	 */
	s = pci_perr_enable & mask ? PCI_COMM_PARITY_DETECT : 0;
	s |= pci_serr_enable & mask ? PCI_COMM_SERR_ENABLE : 0;
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: conf command reg=%x\n", s);
	pbm_p->pbm_config_header->ch_command_reg = s;
	DEBUG1(DBG_ATTACH, dip, "pbm_configure: conf command reg==%x\n",
	    pbm_p->pbm_config_header->ch_command_reg);

	/*
	 * The current versions of the obp are suppose to set the latency
	 * timer register but do not.  Bug 1234181 is open against this
	 * problem.  Until this bug is fixed we check to see if the obp
	 * has attempted to set the latency timer register by checking
	 * for the existence of a "latency-timer" property.
	 */
	if (pci_set_latency_timer_register) {
		DEBUG1(DBG_ATTACH, dip,
		    "pbm_configure: set psycho latency timer to %x\n",
		    pci_latency_timer);
		pbm_p->pbm_config_header->ch_latency_timer_reg =
		    pci_latency_timer;
	}

	(void) ndi_prop_update_int(DDI_DEV_T_ANY, dip, "latency-timer",
	    (int)pbm_p->pbm_config_header->ch_latency_timer_reg);
}

uint_t
pbm_disable_pci_errors(pbm_t *pbm_p)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;
	ib_t *ib_p = pci_p->pci_ib_p;

	/*
	 * Disable error and streaming byte hole interrupts via the
	 * PBM control register.
	 */
	*pbm_p->pbm_ctrl_reg &=
	    ~(PSYCHO_PCI_CTRL_ERR_INT_EN | PSYCHO_PCI_CTRL_SBH_INT_EN);

	/*
	 * Disable error interrupts via the interrupt mapping register.
	 */
	ib_intr_disable(ib_p, pci_p->pci_inos[CBNINTR_PBM], IB_INTR_NOWAIT);
	return (BF_NONE);
}

/*ARGSUSED*/
uint64_t
pci_sc_configure(pci_t *pci_p)
{
	return (0);
}

/*ARGSUSED*/
void
pci_pbm_dma_sync(pbm_t *pbm_p, ib_ino_t ino)
{
	uint64_t pa = pbm_p->pbm_sync_reg_pa;
	if (pa)
		(void) lddphysio(pa);		/* Load from Sync Register */
}

/*ARGSUSED*/
dvma_context_t
pci_iommu_get_dvma_context(iommu_t *iommu_p, dvma_addr_t dvma_pg_index)
{
	ASSERT(0);
	return (0);
}

/*ARGSUSED*/
void
pci_iommu_free_dvma_context(iommu_t *iommu_p, dvma_context_t ctx)
{
	ASSERT(0);
}

void
pci_iommu_config(iommu_t *iommu_p, uint64_t iommu_ctl, uint64_t cfgpa)
{
	volatile uint64_t *pbm_csr_p = (volatile uint64_t *)
	    get_pbm_reg_base(iommu_p->iommu_pci_p);
	volatile uint64_t pbm_ctl = *pbm_csr_p;

	volatile uint64_t *iommu_ctl_p = iommu_p->iommu_ctrl_reg;
	volatile uint64_t tsb_bar_val = iommu_p->iommu_tsb_paddr;
	volatile uint64_t *tsb_bar_p = iommu_p->iommu_tsb_base_addr_reg;

	DEBUG2(DBG_ATTACH, iommu_p->iommu_pci_p->pci_dip,
	    "\npci_iommu_config: pbm_csr_p=%016llx pbm_ctl=%016llx",
	    pbm_csr_p, pbm_ctl);
	DEBUG2(DBG_ATTACH|DBG_CONT, iommu_p->iommu_pci_p->pci_dip,
	    "\n\tiommu_ctl_p=%016llx iommu_ctl=%016llx",
	    iommu_ctl_p, iommu_ctl);
	DEBUG2(DBG_ATTACH|DBG_CONT, iommu_p->iommu_pci_p->pci_dip,
	    "\n\tcfgpa=%016llx tsb_bar_val=%016llx", cfgpa, tsb_bar_val);

	if (!cfgpa)
		goto reprog;

	/* disable PBM arbiters - turn off bits 0-7 */
	*pbm_csr_p = (pbm_ctl >> 8) << 8;

	/* make sure we own the bus by reading any child device config space */
	(void) ldphysio(cfgpa); /* also flushes the prev write */
reprog:
	*tsb_bar_p = tsb_bar_val;
	*iommu_ctl_p = iommu_ctl;

	*pbm_csr_p = pbm_ctl;	/* re-enable bus arbitration */
	pbm_ctl = *pbm_csr_p;	/* flush all prev writes */
}

int
pci_sc_ctx_inv(dev_info_t *dip, sc_t *sc_p, ddi_dma_impl_t *mp)
{
	ASSERT(0);
	return (DDI_FAILURE);
}

void
pci_cb_setup(pci_t *pci_p)
{
	uint64_t csr, csr_pa, pa;
	cb_t *cb_p = pci_p->pci_cb_p;

	/* cb_p->cb_node_id = 0; */
	cb_p->cb_ign = PCI_ID_TO_IGN(pci_p->pci_id);
	pa = (uint64_t)hat_getpfnum(kas.a_hat, pci_p->pci_address[0]);
	cb_p->cb_base_pa  = pa = pa >> (32 - MMU_PAGESHIFT) << 32;
	cb_p->cb_map_pa = pa + PSYCHO_IB_OBIO_INTR_MAP_REG_OFFSET;
	cb_p->cb_clr_pa = pa + PSYCHO_IB_OBIO_CLEAR_INTR_REG_OFFSET;
	cb_p->cb_obsta_pa = pa + COMMON_IB_OBIO_INTR_STATE_DIAG_REG;

	csr_pa = pa + PSYCHO_CB_CONTROL_STATUS_REG_OFFSET;
	csr = lddphysio(csr_pa);

	/*
	 * Clear any pending address parity errors.
	 */
	if (csr & COMMON_CB_CONTROL_STATUS_APERR) {
		csr |= COMMON_CB_CONTROL_STATUS_APERR;
		cmn_err(CE_WARN, "clearing UPA address parity error\n");
	}
	csr |= COMMON_CB_CONTROL_STATUS_APCKEN;
	csr &= ~COMMON_CB_CONTROL_STATUS_IAP;
	stdphysio(csr_pa, csr);

}

void
pci_ecc_setup(ecc_t *ecc_p)
{
	ecc_p->ecc_ue.ecc_errpndg_mask = 0;
	ecc_p->ecc_ue.ecc_offset_mask = PSYCHO_ECC_UE_AFSR_DW_OFFSET;
	ecc_p->ecc_ue.ecc_offset_shift = PSYCHO_ECC_UE_AFSR_DW_OFFSET_SHIFT;
	ecc_p->ecc_ue.ecc_size_log2 = 3;

	ecc_p->ecc_ce.ecc_errpndg_mask = 0;
	ecc_p->ecc_ce.ecc_offset_mask = PSYCHO_ECC_CE_AFSR_DW_OFFSET;
	ecc_p->ecc_ce.ecc_offset_shift = PSYCHO_ECC_CE_AFSR_DW_OFFSET_SHIFT;
	ecc_p->ecc_ce.ecc_size_log2 = 3;
}

/*
 * overwrite dvma end address (only on virtual-dma systems)
 * initialize tsb size
 * reset context bits
 * return: IOMMU CSR bank base address (VA)
 */
uintptr_t
pci_iommu_setup(iommu_t *iommu_p)
{
	pci_dvma_range_prop_t *dvma_prop;
	int dvma_prop_len;

	pci_t *pci_p = iommu_p->iommu_pci_p;
	dev_info_t *dip = pci_p->pci_dip;
	uint_t tsb_size = iommu_tsb_cookie_to_size(pci_p->pci_tsb_cookie);
	uint_t tsb_size_prop;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "virtual-dma", (caddr_t)&dvma_prop, &dvma_prop_len) !=
	    DDI_PROP_SUCCESS)
		goto tsb_done;

	if (dvma_prop_len != sizeof (pci_dvma_range_prop_t)) {
		cmn_err(CE_WARN, "%s%d: invalid virtual-dma property",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		goto tsb_end;
	}
	iommu_p->iommu_dvma_end = dvma_prop->dvma_base +
	    (dvma_prop->dvma_len - 1);
	tsb_size_prop = IOMMU_BTOP(dvma_prop->dvma_len) * sizeof (uint64_t);
	tsb_size = MIN(tsb_size_prop, tsb_size);
tsb_end:
	kmem_free(dvma_prop, dvma_prop_len);
tsb_done:
	iommu_p->iommu_tsb_size = iommu_tsb_size_encode(tsb_size);

	if (CHIP_TYPE(pci_p) != PCI_CHIP_HUMMINGBIRD)
		pci_preserve_iommu_tsb = 0;

	/*
	 * Psycho has no context support.
	 */
	iommu_p->iommu_ctx_bitmap = NULL;
	iommu_p->iommu_flush_ctx_reg = NULL;
	pci_use_contexts = 0;
	pci_sc_use_contexts = 0;

	/*
	 * Determine the virtual address of the register block
	 * containing the iommu control registers.
	 */
	return (get_reg_base(pci_p));
}

/*ARGSUSED*/
void
pci_iommu_teardown(iommu_t *iommu_p)
{
}

/* The psycho+ PBM reg base is at 1fe.0000.2000 */
uintptr_t
get_pbm_reg_base(pci_t *pci_p)
{
	return ((uintptr_t)(pci_p->pci_address[0] +
	    (pci_stream_buf_exists ? 0 : PSYCHO_PCI_PBM_REG_BASE)));
}

void
pci_post_uninit_child(pci_t *pci_p)
{
}

void
pci_pbm_setup(pbm_t *pbm_p)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;

	/*
	 * Get the base virtual address for the PBM control block.
	 */
	uintptr_t a = get_pbm_reg_base(pci_p);

	/*
	 * Get the virtual address of the PCI configuration header.
	 * This should be mapped little-endian.
	 */
	pbm_p->pbm_config_header =
	    (config_header_t *)get_config_reg_base(pci_p);

	/*
	 * Get the virtual addresses for control, error and diag
	 * registers.
	 */
	pbm_p->pbm_ctrl_reg = (uint64_t *)(a + PSYCHO_PCI_CTRL_REG_OFFSET);
	pbm_p->pbm_diag_reg = (uint64_t *)(a + PSYCHO_PCI_DIAG_REG_OFFSET);
	pbm_p->pbm_async_flt_status_reg =
	    (uint64_t *)(a + PSYCHO_PCI_ASYNC_FLT_STATUS_REG_OFFSET);
	pbm_p->pbm_async_flt_addr_reg =
	    (uint64_t *)(a + PSYCHO_PCI_ASYNC_FLT_ADDR_REG_OFFSET);

	if (CHIP_TYPE(pci_p) >= PCI_CHIP_SABRE)
		pbm_p->pbm_sync_reg_pa =
		    pci_p->pci_cb_p->cb_base_pa + DMA_WRITE_SYNC_REG;
}

/*ARGSUSED*/
void
pci_pbm_teardown(pbm_t *pbm_p)
{
}

void
pci_sc_setup(sc_t *sc_p)
{
	pci_t *pci_p = sc_p->sc_pci_p;

	/*
	 * Determine the virtual addresses of the streaming cache
	 * control/status and flush registers.
	 */
	uintptr_t a = get_pbm_reg_base(pci_p);
	sc_p->sc_ctrl_reg = (uint64_t *)(a + PSYCHO_SC_CTRL_REG_OFFSET);
	sc_p->sc_invl_reg = (uint64_t *)(a + PSYCHO_SC_INVL_REG_OFFSET);
	sc_p->sc_sync_reg = (uint64_t *)(a + PSYCHO_SC_SYNC_REG_OFFSET);

	/*
	 * Determine the virtual addresses of the streaming cache
	 * diagnostic access registers.
	 */
	a = get_reg_base(pci_p);
	if (pci_p->pci_bus_range.lo != 0) {
		sc_p->sc_data_diag_acc = (uint64_t *)
		    (a + PSYCHO_SC_A_DATA_DIAG_OFFSET);
		sc_p->sc_tag_diag_acc = (uint64_t *)
		    (a + PSYCHO_SC_A_TAG_DIAG_OFFSET);
		sc_p->sc_ltag_diag_acc = (uint64_t *)
		    (a + PSYCHO_SC_A_LTAG_DIAG_OFFSET);
	} else {
		sc_p->sc_data_diag_acc = (uint64_t *)
		    (a + PSYCHO_SC_B_DATA_DIAG_OFFSET);
		sc_p->sc_tag_diag_acc = (uint64_t *)
		    (a + PSYCHO_SC_B_TAG_DIAG_OFFSET);
		sc_p->sc_ltag_diag_acc = (uint64_t *)
		    (a + PSYCHO_SC_B_LTAG_DIAG_OFFSET);
	}
}

int
pci_get_numproxy(dev_info_t *dip)
{
	return (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "#upa-interrupt-proxies", 1));
}

int
pci_get_portid(dev_info_t *dip)
{
	return (ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "upa-portid", -1));
}

/*
 * pbm_has_pass_1_cheerio
 *
 *
 * Given a PBM soft state pointer, this routine scans it child nodes
 * to see if one is a pass 1 cheerio.
 *
 * return value: 1 if pass 1 cheerio is found, 0 otherwise
 */
static int
pbm_has_pass_1_cheerio(pci_t *pci_p)
{
	dev_info_t *cdip;
	int found = 0;
	char *s;
	int rev;

	cdip = ddi_get_child(pci_p->pci_dip);
	while (cdip != NULL && found == 0) {
		s = ddi_get_name(cdip);
		if (strcmp(s, "ebus") == 0 || strcmp(s, "pci108e,1000") == 0) {
			rev =
			    ddi_getprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
			    "revision-id", 0);
			if (rev == 0)
				found = 1;
		}
		cdip = ddi_get_next_sibling(cdip);
	}
	return (found);
}

/*
 * Psycho Performance Events.
 */
pci_kev_mask_t
psycho_pci_events[] = {
	{"dvma_stream_rd_a", 0x0},	{"dvma_stream_wr_a", 0x1},
	{"dvma_const_rd_a", 0x2},	{"dvma_const_wr_a", 0x3},
	{"dvma_stream_buf_mis_a", 0x4}, {"dvma_cycles_a", 0x5},
	{"dvma_wd_xfr_a", 0x6},		{"pio_cycles_a", 0x7},
	{"dvma_stream_rd_b", 0x8},	{"dvma_stream_wr_b", 0x9},
	{"dvma_const_rd_b", 0xa},	{"dvma_const_wr_b", 0xb},
	{"dvma_stream_buf_mis_b", 0xc}, {"dvma_cycles_b", 0xd},
	{"dvma_wd_xfr_b", 0xe},		{"pio_cycles_b", 0xf},
	{"dvma_tlb_misses", 0x10},	{"interrupts", 0x11},
	{"upa_inter_nack", 0x12},	{"pio_reads", 0x13},
	{"pio_writes", 0x14},		{"merge_buffer", 0x15},
	{"dma_tbwalk_a", 0x16},		{"dma_stc_a", 0x17},
	{"dma_tbwalk_b", 0x18},		{"dma_stc_b", 0x19},
	{"clear_pic", 0x1f}
};

/*
 * Create the picN kstat's.
 */
void
pci_kstat_init()
{
	pci_name_kstat = (pci_ksinfo_t *)kmem_alloc(sizeof (pci_ksinfo_t),
	    KM_NOSLEEP);

	if (pci_name_kstat == NULL) {
		cmn_err(CE_WARN, "pcipsy : no space for kstat\n");
	} else {
		pci_name_kstat->pic_no_evs =
		    sizeof (psycho_pci_events) / sizeof (pci_kev_mask_t);
		pci_name_kstat->pic_shift[0] = PSYCHO_SHIFT_PIC0;
		pci_name_kstat->pic_shift[1] = PSYCHO_SHIFT_PIC1;
		pci_create_name_kstat("pcip",
		    pci_name_kstat, psycho_pci_events);
	}
}

/*
 * Called from _fini()
 */
void
pci_kstat_fini()
{
	if (pci_name_kstat != NULL) {
		pci_delete_name_kstat(pci_name_kstat);
		kmem_free(pci_name_kstat, sizeof (pci_ksinfo_t));
		pci_name_kstat = NULL;
	}
}

/* ARGSUSED */
void
pci_add_pci_kstat(pci_t *pci_p)
{
}

/* ARGSUSED */
void
pci_rem_pci_kstat(pci_t *pci_p)
{
}

/*
 * Create the performance 'counters' kstat.
 */
void
pci_add_upstream_kstat(pci_t *pci_p)
{
	pci_common_t	*cmn_p = pci_p->pci_common_p;
	pci_cntr_pa_t	*cntr_pa_p = &cmn_p->pci_cmn_uks_pa;
	uint64_t regbase = va_to_pa((void *)get_reg_base(pci_p));

	cntr_pa_p->pcr_pa = regbase + PSYCHO_PERF_PCR_OFFSET;
	cntr_pa_p->pic_pa = regbase + PSYCHO_PERF_PIC_OFFSET;
	cmn_p->pci_common_uksp = pci_create_cntr_kstat(pci_p, "pcip",
	    NUM_OF_PICS, pci_cntr_kstat_pa_update, cntr_pa_p);
}

/*
 * Extract the drivers binding name to identify which chip
 * we're binding to.  Whenever a new bus bridge is created, the driver alias
 * entry should be added here to identify the device if needed.  If a device
 * isn't added, the identity defaults to PCI_CHIP_UNIDENTIFIED.
 */
static uint32_t
pci_identity_init(pci_t *pci_p)
{
	dev_info_t *dip = pci_p->pci_dip;
	char *name = ddi_binding_name(dip);

	if (strcmp(name, "pci108e,8000") == 0)
		return (CHIP_ID(PCI_CHIP_PSYCHO, 0x00, 0x00));
	if (strcmp(name, "pci108e,a000") == 0)
		return (CHIP_ID(PCI_CHIP_SABRE, 0x00, 0x00));
	if (strcmp(name, "pci108e,a001") == 0)
		return (CHIP_ID(PCI_CHIP_HUMMINGBIRD, 0x00, 0x00));
	cmn_err(CE_CONT, "?%s%d:using default chip identity\n",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	return (CHIP_ID(PCI_CHIP_PSYCHO, 0x00, 0x00));
}

/*ARGSUSED*/
void
pci_post_init_child(pci_t *pci_p, dev_info_t *child)
{
}

/*ARGSUSED*/
int
pci_pbm_add_intr(pci_t *pci_p)
{
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
void
pci_pbm_rem_intr(pci_t *pci_p)
{
}

/*ARGSUSED*/
void
pci_pbm_suspend(pci_t *pci_p)
{
}

/*ARGSUSED*/
void
pci_pbm_resume(pci_t *pci_p)
{
}

/*
 * pcipsy error handling 101:
 *
 * The various functions below are responsible for error handling. Given
 * a particular error, they must gather the appropriate state, report all
 * errors with correct payload, and attempt recovery where ever possible.
 *
 * Recovery in the context of this driver is being able notify a leaf device
 * of the failed transaction. This leaf device may either be the master or
 * target for this transaction and may have already received an error
 * notification via a PCI interrupt. Notification is done via DMA and access
 * handles. If we capture an address for the transaction then we can map it
 * to a handle(if the leaf device is fma-compliant) and fault the handle as
 * well as call the device driver registered callback.
 *
 * The hardware can either interrupt or trap upon detection of an error, in
 * some rare cases it also causes a fatal reset.
 *
 * pbm_error_intr() and ecc_intr() are responsible for PCI Block Module
 * errors(generic PCI + bridge specific) and ECC errors, respectively. They
 * are common between pcisch and pcipsy and therefore exist in pci_pbm.c and
 * pci_ecc.c. To support error handling certain chip specific handlers
 * must exist and they are defined below.
 *
 * cpu_deferred_error() and cpu_async_error(), handle the traps that may
 * have originated from IO space. They call into the registered IO callbacks
 * to report and handle errors that may have caused the trap.
 *
 * pci_pbm_err_handler() is called by pbm_error_intr() or pci_err_callback()
 * (generic fma callback for pcipsy/pcisch, pci_fm.c). pci_err_callback() is
 * called when the CPU has trapped because of a possible IO error(TO/BERR/UE).
 * It will call pci_pbm_err_handler() to report and handle all PCI/PBM/IOMMU
 * related errors which are detected by the chip.
 *
 * pci_pbm_err_handler() calls a generic interface pbm_afsr_report()(pci_pbm.c)
 * to report the pbm specific errors and attempt to map the failed address
 * (if captured) to a device instance. pbm_afsr_report() calls a chip specific
 * interface to interpret the afsr bits pci_pbm_classify()(pcisch.c/pcipsy.c).
 *
 * ecc_err_handler()(pci_ecc.c) also calls a chip specific interface to
 * interpret the afsr, pci_ecc_classify(). ecc_err_handler() also calls
 * pci_pbm_err_handler() and ndi_fm_handler_dispatch() to log any related
 * errors.
 *
 * To make sure that the trap code and the interrupt code are not going
 * to step on each others toes we have a per chip pci_fm_mutex. This also
 * makes it necessary for us to be cautious while we are at a high PIL, so
 * that we do not cause a subsequent trap that causes us to hang.
 *
 * The attempt to commonize code was meant to keep in line with the current
 * pci driver implementation and it was not meant to confuse. If you are
 * confused then don't worry, I was too.
 */

/*
 * For Psycho, a UE is always fatal, except if it is a translation error on a
 * Darwin platform.  We ignore these because they do not cause data corruption.
 */
int
ecc_ue_is_fatal(struct async_flt *ecc)
{
	return (((uint_t)(ecc->flt_stat >> SABRE_UE_AFSR_PDTE_SHIFT) &
	    SABRE_UE_AFSR_E_PDTE) == 0);
}

/*
 * pci_ecc_classify, called by ecc_handler to classify ecc errors
 * and determine if we should panic or not.
 *
 * Note that it is possible yet extremely rare for more than one
 * primary error bit to be set.  We classify the ecc error based
 * on the first set bit that is found.
 */
void
pci_ecc_classify(uint64_t err, ecc_errstate_t *ecc_err_p)
{
	struct async_flt *ecc = &ecc_err_p->ecc_aflt;
	pci_common_t *cmn_p = ecc_err_p->ecc_ii_p.ecc_p->ecc_pci_cmn_p;

	ASSERT(MUTEX_HELD(&cmn_p->pci_fm_mutex));

	ecc_err_p->ecc_bridge_type = PCI_BRIDGE_TYPE(cmn_p);
	/*
	 * Get the parent bus id that caused the error.
	 */
	ecc_err_p->ecc_dev_id = (ecc_err_p->ecc_afsr & PSYCHO_ECC_UE_AFSR_ID)
	    >> PSYCHO_ECC_UE_AFSR_ID_SHIFT;
	/*
	 * Determine the doubleword offset of the error.
	 */
	ecc_err_p->ecc_dw_offset = (ecc_err_p->ecc_afsr &
	    PSYCHO_ECC_UE_AFSR_DW_OFFSET)
	    >> PSYCHO_ECC_UE_AFSR_DW_OFFSET_SHIFT;
	/*
	 * Determine the primary error type.
	 */
	if (err & COMMON_ECC_AFSR_E_PIO) {
		if (ecc_err_p->ecc_ii_p.ecc_type == CBNINTR_UE) {
			if (ecc_err_p->ecc_pri) {
				ecc->flt_erpt_class = PCI_ECC_PIO_UE;
			} else {
				ecc->flt_erpt_class = PCI_ECC_SEC_PIO_UE;
			}
			ecc->flt_panic = ecc_ue_is_fatal(&ecc_err_p->ecc_aflt);
		} else {
			ecc->flt_erpt_class = ecc_err_p->ecc_pri ?
			    PCI_ECC_PIO_CE : PCI_ECC_SEC_PIO_CE;
			return;
		}
	} else if (err & COMMON_ECC_AFSR_E_DRD) {
		if (ecc_err_p->ecc_ii_p.ecc_type == CBNINTR_UE) {
			if (ecc_err_p->ecc_pri) {
				ecc->flt_erpt_class = PCI_ECC_DRD_UE;
			} else {
				ecc->flt_erpt_class = PCI_ECC_SEC_DRD_UE;
			}
			ecc->flt_panic = ecc_ue_is_fatal(&ecc_err_p->ecc_aflt);
		} else {
			ecc->flt_erpt_class = ecc_err_p->ecc_pri ?
			    PCI_ECC_DRD_CE : PCI_ECC_SEC_DRD_CE;
			return;
		}
	} else if (err & COMMON_ECC_AFSR_E_DWR) {
		if (ecc_err_p->ecc_ii_p.ecc_type == CBNINTR_UE) {
			if (ecc_err_p->ecc_pri) {
				ecc->flt_erpt_class = PCI_ECC_DWR_UE;
			} else {
				ecc->flt_erpt_class = PCI_ECC_SEC_DWR_UE;
			}
			ecc->flt_panic = ecc_ue_is_fatal(&ecc_err_p->ecc_aflt);
		} else {
			ecc->flt_erpt_class = ecc_err_p->ecc_pri ?
			    PCI_ECC_DWR_CE : PCI_ECC_SEC_DWR_CE;
			return;
		}
	}
}

ushort_t
pci_ecc_get_synd(uint64_t afsr)
{
	return ((ushort_t)((afsr & PSYCHO_ECC_CE_AFSR_SYND)
	    >> PSYCHO_ECC_CE_AFSR_SYND_SHIFT));
}

/*
 * pci_pbm_classify, called by pbm_afsr_report to classify piow afsr.
 */
int
pci_pbm_classify(pbm_errstate_t *pbm_err_p)
{
	uint32_t e;
	int nerr = 0;
	char **tmp_class;

	if (pbm_err_p->pbm_pri) {
		tmp_class = &pbm_err_p->pbm_pci.pci_err_class;
		e = PBM_AFSR_TO_PRIERR(pbm_err_p->pbm_afsr);
		pbm_err_p->pbm_log = FM_LOG_PCI;
	} else {
		tmp_class = &pbm_err_p->pbm_err_class;
		e = PBM_AFSR_TO_SECERR(pbm_err_p->pbm_afsr);
		pbm_err_p->pbm_log = FM_LOG_PBM;
	}

	if (e & PSYCHO_PCI_AFSR_E_MA) {
		*tmp_class = pbm_err_p->pbm_pri ? PCI_MA : PCI_SEC_MA;
		nerr++;
	}
	if (e & PSYCHO_PCI_AFSR_E_TA) {
		*tmp_class = pbm_err_p->pbm_pri ? PCI_REC_TA : PCI_SEC_REC_TA;
		nerr++;
	}
	if (e & PSYCHO_PCI_AFSR_E_RTRY) {
		pbm_err_p->pbm_err_class = pbm_err_p->pbm_pri ?
		    PCI_PBM_RETRY : PCI_SEC_PBM_RETRY;
		pbm_err_p->pbm_log = FM_LOG_PBM;
		nerr++;
	}
	if (e & PSYCHO_PCI_AFSR_E_PERR) {
		*tmp_class = pbm_err_p->pbm_pri ? PCI_MDPE : PCI_SEC_MDPE;
		nerr++;
	}
	return (nerr);
}

/*
 * Function used to clear PBM/PCI/IOMMU error state after error handling
 * is complete. Only clearing error bits which have been logged. Called by
 * pci_pbm_err_handler and pci_bus_exit.
 */
static void
pci_clear_error(pci_t *pci_p, pbm_errstate_t *pbm_err_p)
{
	pbm_t *pbm_p = pci_p->pci_pbm_p;

	ASSERT(MUTEX_HELD(&pbm_p->pbm_pci_p->pci_common_p->pci_fm_mutex));

	*pbm_p->pbm_ctrl_reg = pbm_err_p->pbm_ctl_stat;
	*pbm_p->pbm_async_flt_status_reg = pbm_err_p->pbm_afsr;
	pbm_p->pbm_config_header->ch_status_reg =
	    pbm_err_p->pbm_pci.pci_cfg_stat;
}

/*ARGSUSED*/
int
pci_pbm_err_handler(dev_info_t *dip, ddi_fm_error_t *derr,
    const void *impl_data, int caller)
{
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;
	uint32_t prierr, secerr;
	pbm_errstate_t pbm_err;
	char buf[FM_MAX_CLASS];
	pci_t *pci_p = (pci_t *)impl_data;
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	int ret = 0;
	uint64_t pbm_ctl_stat;
	uint16_t pci_cfg_stat;

	ASSERT(MUTEX_HELD(&pci_p->pci_common_p->pci_fm_mutex));
	pci_pbm_errstate_get(pci_p, &pbm_err);

	derr->fme_ena = derr->fme_ena ? derr->fme_ena :
	    fm_ena_generate(0, FM_ENA_FMT1);

	prierr = PBM_AFSR_TO_PRIERR(pbm_err.pbm_afsr);
	secerr = PBM_AFSR_TO_SECERR(pbm_err.pbm_afsr);

	if (derr->fme_flag == DDI_FM_ERR_EXPECTED) {
		if (caller == PCI_TRAP_CALL) {
			/*
			 * For ddi_caut_get treat all events as
			 * nonfatal. The trampoline will set
			 * err_ena = 0, err_status = NONFATAL. We only
			 * really call this function so that pci_clear_error()
			 * and ndi_fm_handler_dispatch() will get called.
			 */
			derr->fme_status = DDI_FM_NONFATAL;
			nonfatal++;
			goto done;
		} else {
			/*
			 * For ddi_caut_put treat all events as nonfatal. Here
			 * we have the handle and can call ndi_fm_acc_err_set().
			 */
			derr->fme_status = DDI_FM_NONFATAL;
			ndi_fm_acc_err_set(pbm_p->pbm_excl_handle, derr);
			nonfatal++;
			goto done;
		}
	} else if (derr->fme_flag == DDI_FM_ERR_PEEK) {
		/*
		 * For ddi_peek treat all events as nonfatal. We only
		 * really call this function so that pci_clear_error()
		 * and ndi_fm_handler_dispatch() will get called.
		 */
		nonfatal++;
		goto done;
	} else if (derr->fme_flag == DDI_FM_ERR_POKE) {
		/*
		 * For ddi_poke we can treat as nonfatal if the
		 * following conditions are met :
		 * 1. Make sure only primary error is MA/TA
		 * 2. Make sure no secondary error
		 * 3. check pci config header stat reg to see MA/TA is
		 *    logged. We cannot verify only MA/TA is recorded
		 *    since it gets much more complicated when a
		 *    PCI-to-PCI bridge is present.
		 */
		if ((prierr == PSYCHO_PCI_AFSR_E_MA) && !secerr &&
		    (pbm_err.pbm_pci.pci_cfg_stat & PCI_STAT_R_MAST_AB)) {
			nonfatal++;
			goto done;
		}
		if ((prierr == PSYCHO_PCI_AFSR_E_TA) && !secerr &&
		    (pbm_err.pbm_pci.pci_cfg_stat & PCI_STAT_R_TARG_AB)) {
			nonfatal++;
			goto done;
		}
	}

	if (prierr || secerr) {
		ret = pbm_afsr_report(dip, derr->fme_ena, &pbm_err);
		if (ret == DDI_FM_FATAL)
			fatal++;
		else
			nonfatal++;
	}

	ret = pci_cfg_report(dip, derr, &pbm_err.pbm_pci, caller, prierr);
	if (ret == DDI_FM_FATAL)
		fatal++;
	else if (ret == DDI_FM_NONFATAL)
		nonfatal++;

	pbm_ctl_stat = pbm_err.pbm_ctl_stat;
	pci_cfg_stat = pbm_err.pbm_pci.pci_cfg_stat;

	/*
	 * PBM Received System Error - During any transaction, or
	 * at any point on the bus, some device may detect a critical
	 * error and signal a system error to the system.
	 */
	if (pbm_ctl_stat & COMMON_PCI_CTRL_SERR) {
		/*
		 * may be expected (master abort from pci-pci bridge during
		 * poke will generate SERR)
		 */
		if (derr->fme_flag != DDI_FM_ERR_POKE) {
			pbm_err.pbm_pci.pci_err_class = PCI_REC_SERR;
			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    PCI_ERROR_SUBCLASS, pbm_err.pbm_pci.pci_err_class);
			ddi_fm_ereport_post(dip, buf, derr->fme_ena,
			    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
			    PCI_CONFIG_STATUS, DATA_TYPE_UINT16, pci_cfg_stat,
			    PCI_CONFIG_COMMAND, DATA_TYPE_UINT16,
			    pbm_err.pbm_pci.pci_cfg_comm, PCI_PA,
			    DATA_TYPE_UINT64, (uint64_t)0, NULL);
		}
		unknown++;
	}

	/* Streaming Byte Hole Error */
	if (pbm_ctl_stat & COMMON_PCI_CTRL_SBH_ERR) {
		if (pci_panic_on_sbh_errors)
			fatal++;
		else
			nonfatal++;
		pbm_err.pbm_err_class = PCI_PSY_SBH;
		pbm_ereport_post(dip, derr->fme_ena, &pbm_err);
	}
done:
	ret = ndi_fm_handler_dispatch(dip, NULL, derr);
	if (ret == DDI_FM_FATAL) {
		fatal++;
	} else if (ret == DDI_FM_NONFATAL) {
		nonfatal++;
	} else if (ret == DDI_FM_UNKNOWN) {
		unknown++;
	}

	/*
	 * rserr not claimed as nonfatal by a child is treated as fatal
	 */
	if (unknown && !nonfatal && !fatal)
		fatal++;

	/* Cleanup and reset error bits */
	pci_clear_error(pci_p, &pbm_err);

	return (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    (unknown ? DDI_FM_UNKNOWN : DDI_FM_OK)));
}

int
pci_check_error(pci_t *pci_p)
{
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	uint16_t pci_cfg_stat;
	uint64_t pbm_ctl_stat, pbm_afsr;

	ASSERT(MUTEX_HELD(&pci_p->pci_common_p->pci_fm_mutex));

	pci_cfg_stat = pbm_p->pbm_config_header->ch_status_reg;
	pbm_ctl_stat = *pbm_p->pbm_ctrl_reg;
	pbm_afsr = *pbm_p->pbm_async_flt_status_reg;

	if ((pci_cfg_stat & (PCI_STAT_S_PERROR | PCI_STAT_S_TARG_AB |
	    PCI_STAT_R_TARG_AB | PCI_STAT_R_MAST_AB |
	    PCI_STAT_S_SYSERR | PCI_STAT_PERROR)) ||
	    (pbm_ctl_stat & (COMMON_PCI_CTRL_SBH_ERR |
	    COMMON_PCI_CTRL_SERR)) ||
	    (PBM_AFSR_TO_PRIERR(pbm_afsr)))
		return (1);

	return (0);

}

/*
 * Function used to gather PBM/PCI error state for the
 * pci_pbm_err_handler. This function must be called while pci_fm_mutex
 * is held.
 */
static void
pci_pbm_errstate_get(pci_t *pci_p, pbm_errstate_t *pbm_err_p)
{
	pbm_t *pbm_p = pci_p->pci_pbm_p;

	ASSERT(MUTEX_HELD(&pci_p->pci_common_p->pci_fm_mutex));
	bzero(pbm_err_p, sizeof (pbm_errstate_t));

	/*
	 * Capture all pbm error state for later logging
	 */
	pbm_err_p->pbm_bridge_type = PCI_BRIDGE_TYPE(pci_p->pci_common_p);
	pbm_err_p->pbm_pci.pci_cfg_stat =
	    pbm_p->pbm_config_header->ch_status_reg;
	pbm_err_p->pbm_ctl_stat = *pbm_p->pbm_ctrl_reg;
	pbm_err_p->pbm_pci.pci_cfg_comm =
	    pbm_p->pbm_config_header->ch_command_reg;
	pbm_err_p->pbm_afsr = *pbm_p->pbm_async_flt_status_reg;
	pbm_err_p->pbm_afar = *pbm_p->pbm_async_flt_addr_reg;
	pbm_err_p->pbm_pci.pci_pa = *pbm_p->pbm_async_flt_addr_reg;
}

void
pbm_clear_error(pbm_t *pbm_p)
{
	uint64_t pbm_afsr, pbm_ctl_stat;

	/*
	 * for poke() support - called from POKE_FLUSH. Spin waiting
	 * for MA, TA or SERR to be cleared by a pbm_error_intr().
	 * We have to wait for SERR too in case the device is beyond
	 * a pci-pci bridge.
	 */
	pbm_ctl_stat = *pbm_p->pbm_ctrl_reg;
	pbm_afsr = *pbm_p->pbm_async_flt_status_reg;
	while (((pbm_afsr >> PSYCHO_PCI_AFSR_PE_SHIFT) &
	    (PSYCHO_PCI_AFSR_E_MA | PSYCHO_PCI_AFSR_E_TA)) ||
	    (pbm_ctl_stat & COMMON_PCI_CTRL_SERR)) {
		pbm_ctl_stat = *pbm_p->pbm_ctrl_reg;
		pbm_afsr = *pbm_p->pbm_async_flt_status_reg;
	}
}

/*ARGSUSED*/
void
pci_format_addr(dev_info_t *dip, uint64_t *afar, uint64_t afsr)
{
	/*
	 * For Psycho the full address is stored in hardware. So
	 * there is no need to format it.
	 */
}

/*ARGSUSED*/
int
pci_bus_quiesce(pci_t *pci_p, dev_info_t *dip, void *result)
{
	return (DDI_FAILURE);
}

/*ARGSUSED*/
int
pci_bus_unquiesce(pci_t *pci_p, dev_info_t *dip, void *result)
{
	return (DDI_FAILURE);
}

int
pci_reloc_getkey(void)
{
	return (0x100);
}

void
pci_vmem_free(iommu_t *iommu_p, ddi_dma_impl_t *mp, void *dvma_addr,
    size_t npages)
{
	pci_vmem_do_free(iommu_p, dvma_addr, npages,
	    (mp->dmai_flags & DMAI_FLAGS_VMEMCACHE));
}


/*
 * NOTE: This call is only used by legacy systems (eg. E250 and E450) that
 * require unregistering the pci driver's thermal intrerrupt handler before
 * they can register their own.
 */
void
pci_thermal_rem_intr(dev_info_t *rdip, uint_t inum)
{
	pci_t		*pci_p;
	dev_info_t	*pdip;
	uint32_t	dev_mondo, pci_mondo;
	int		instance;

	for (pdip = ddi_get_parent(rdip); pdip; pdip = ddi_get_parent(pdip)) {
		if (strcmp(ddi_driver_name(pdip), "pcipsy") == 0)
			break;
	}

	if (!pdip) {
		cmn_err(CE_WARN, "pci_thermal_rem_intr() no pcipsy parent\n");
		return;
	}

	instance = ddi_get_instance(pdip);
	pci_p = get_pci_soft_state(instance);

	/* Calculate the requesting device's mondo */
	dev_mondo = pci_xlate_intr(pci_p->pci_dip, rdip, pci_p->pci_ib_p,
	    IB_MONDO_TO_INO(i_ddi_get_inum(rdip, inum)));

	/* get pci's thermal mondo */
	pci_mondo = ((pci_p->pci_cb_p->cb_ign << PCI_INO_BITS) |
	    pci_p->pci_inos[CBNINTR_THERMAL]);
	pci_mondo = CB_MONDO_TO_XMONDO(pci_p->pci_cb_p, pci_mondo);

	if (pci_mondo == dev_mondo) {
		DEBUG2(DBG_ATTACH, rdip, "pci_thermal_rem_intr unregistered "
		    "for dip=%s%d:", ddi_driver_name(rdip),
		    ddi_get_instance(rdip));
		VERIFY(rem_ivintr(pci_mondo, pci_pil[CBNINTR_THERMAL]) == 0);
	}
}

/*
 * pci_iommu_bypass_end_configure
 *
 * Support for 40-bit bus width to UPA in DVMA and iommu bypass transfers:
 */

dma_bypass_addr_t
pci_iommu_bypass_end_configure(void)
{

	return ((dma_bypass_addr_t)UPA_IOMMU_BYPASS_END);
}
