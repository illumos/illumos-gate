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
 * Copyright (c) 2010-2013, by Broadcom, Inc.
 * All Rights Reserved.
 */

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates.
 * All rights reserved.
 */

#include "bge_impl.h"

#define	PIO_ADDR(bgep, offset)	((void *)((caddr_t)(bgep)->io_regs+(offset)))
#define	APE_ADDR(bgep, offset)	((void *)((caddr_t)(bgep)->ape_regs+(offset)))

/*
 * Future features ... ?
 */
#define	BGE_CFG_IO8	1	/* 8/16-bit cfg space BIS/BIC	*/
#define	BGE_IND_IO32	1	/* indirect access code		*/
#define	BGE_SEE_IO32	1	/* SEEPROM access code		*/
#define	BGE_FLASH_IO32	1	/* FLASH access code		*/

/*
 * BGE MSI tunable:
 *
 * By default MSI is enabled on all supported platforms but it is disabled
 * for some Broadcom chips due to known MSI hardware issues. Currently MSI
 * is enabled only for 5714C A2 and 5715C A2 broadcom chips.
 */
boolean_t bge_enable_msi = B_TRUE;

/*
 * PCI-X/PCI-E relaxed ordering tunable for OS/Nexus driver
 */
boolean_t bge_relaxed_ordering = B_TRUE;

/*
 * Patchable globals:
 *
 *	bge_autorecover
 *		Enables/disables automatic recovery after fault detection
 *
 *	bge_mlcr_default
 *		Value to program into the MLCR; controls the chip's GPIO pins
 *
 *	bge_dma_{rd,wr}prio
 *		Relative priorities of DMA reads & DMA writes respectively.
 *		These may each be patched to any value 0-3.  Equal values
 *		will give "fair" (round-robin) arbitration for PCI access.
 *		Unequal values will give one or the other function priority.
 *
 *	bge_dma_rwctrl
 *		Value to put in the Read/Write DMA control register.  See
 *	        the Broadcom PRM for things you can fiddle with in this
 *		register ...
 *
 *	bge_{tx,rx}_{count,ticks}_{norm,intr}
 *		Send/receive interrupt coalescing parameters.  Counts are
 *		#s of descriptors, ticks are in microseconds.  *norm* values
 *		apply between status updates/interrupts; the *intr* values
 *		refer to the 'during-interrupt' versions - see the PRM.
 *
 *		NOTE: these values have been determined by measurement. They
 *		differ significantly from the values recommended in the PRM.
 */
static uint32_t bge_autorecover = 1;
static uint32_t bge_mlcr_default_5714 = MLCR_DEFAULT_5714;

static uint32_t bge_dma_rdprio = 1;
static uint32_t bge_dma_wrprio = 0;
static uint32_t bge_dma_rwctrl = PDRWCR_VAR_DEFAULT;
static uint32_t bge_dma_rwctrl_5721 = PDRWCR_VAR_5721;
static uint32_t bge_dma_rwctrl_5714 = PDRWCR_VAR_5714;
static uint32_t bge_dma_rwctrl_5715 = PDRWCR_VAR_5715;

uint32_t bge_rx_ticks_norm = 128;
uint32_t bge_tx_ticks_norm = 512;
uint32_t bge_rx_count_norm = 8;
uint32_t bge_tx_count_norm = 128;

static uint32_t bge_rx_ticks_intr = 128;
static uint32_t bge_tx_ticks_intr = 0;		/* 8 for FJ2+ !?!?	*/
static uint32_t bge_rx_count_intr = 2;
static uint32_t bge_tx_count_intr = 0;

/*
 * Memory pool configuration parameters.
 *
 * These are generally specific to each member of the chip family, since
 * each one may have a different memory size/configuration.
 *
 * Setting the mbuf pool length for a specific type of chip to 0 inhibits
 * the driver from programming the various registers; instead they are left
 * at their hardware defaults.  This is the preferred option for later chips
 * (5705+), whereas the older chips *required* these registers to be set,
 * since the h/w default was 0 ;-(
 */
static uint32_t bge_mbuf_pool_base	= MBUF_POOL_BASE_DEFAULT;
static uint32_t bge_mbuf_pool_base_5704	= MBUF_POOL_BASE_5704;
static uint32_t bge_mbuf_pool_base_5705	= MBUF_POOL_BASE_5705;
static uint32_t bge_mbuf_pool_base_5721 = MBUF_POOL_BASE_5721;
static uint32_t bge_mbuf_pool_len	= MBUF_POOL_LENGTH_DEFAULT;
static uint32_t bge_mbuf_pool_len_5704	= MBUF_POOL_LENGTH_5704;
static uint32_t bge_mbuf_pool_len_5705	= 0;	/* use h/w default	*/
static uint32_t bge_mbuf_pool_len_5721	= 0;

/*
 * Various high and low water marks, thresholds, etc ...
 *
 * Note: these are taken from revision 7 of the PRM, and some are different
 * from both the values in earlier PRMs *and* those determined experimentally
 * and used in earlier versions of this driver ...
 */
static uint32_t bge_mbuf_hi_water	= MBUF_HIWAT_DEFAULT;
static uint32_t bge_mbuf_lo_water_rmac	= MAC_RX_MBUF_LOWAT_DEFAULT;
static uint32_t bge_mbuf_lo_water_rdma	= RDMA_MBUF_LOWAT_DEFAULT;

static uint32_t bge_dmad_lo_water	= DMAD_POOL_LOWAT_DEFAULT;
static uint32_t bge_dmad_hi_water	= DMAD_POOL_HIWAT_DEFAULT;
static uint32_t bge_lowat_recv_frames	= LOWAT_MAX_RECV_FRAMES_DEFAULT;

static uint32_t bge_replenish_std	= STD_RCV_BD_REPLENISH_DEFAULT;
static uint32_t bge_replenish_mini	= MINI_RCV_BD_REPLENISH_DEFAULT;
static uint32_t bge_replenish_jumbo	= JUMBO_RCV_BD_REPLENISH_DEFAULT;

static uint32_t	bge_watchdog_count	= 1 << 16;
static uint16_t bge_dma_miss_limit	= 20;

static uint32_t bge_stop_start_on_sync	= 0;

/*
 * bge_intr_max_loop controls the maximum loop number within bge_intr.
 * When loading NIC with heavy network traffic, it is useful.
 * Increasing this value could have positive effect to throughput,
 * but it might also increase ticks of a bge ISR stick on CPU, which might
 * lead to bad UI interactive experience. So tune this with caution.
 */
static int bge_intr_max_loop = 1;

/*
 * ========== Low-level chip & ring buffer manipulation ==========
 */

#define	BGE_DBG		BGE_DBG_REGS	/* debug flag for this code	*/


/*
 * Config space read-modify-write routines
 */

#if	BGE_CFG_IO8

static void bge_cfg_clr16(bge_t *bgep, bge_regno_t regno, uint16_t bits);
#pragma	inline(bge_cfg_clr16)

static void
bge_cfg_clr16(bge_t *bgep, bge_regno_t regno, uint16_t bits)
{
	uint16_t regval;

	BGE_TRACE(("bge_cfg_clr16($%p, 0x%lx, 0x%x)",
	    (void *)bgep, regno, bits));

	regval = pci_config_get16(bgep->cfg_handle, regno);

	BGE_DEBUG(("bge_cfg_clr16($%p, 0x%lx, 0x%x): 0x%x => 0x%x",
	    (void *)bgep, regno, bits, regval, regval & ~bits));

	regval &= ~bits;
	pci_config_put16(bgep->cfg_handle, regno, regval);
}

#endif	/* BGE_CFG_IO8 */

static void bge_cfg_clr32(bge_t *bgep, bge_regno_t regno, uint32_t bits);
#pragma	inline(bge_cfg_clr32)

static void
bge_cfg_clr32(bge_t *bgep, bge_regno_t regno, uint32_t bits)
{
	uint32_t regval;

	BGE_TRACE(("bge_cfg_clr32($%p, 0x%lx, 0x%x)",
	    (void *)bgep, regno, bits));

	regval = pci_config_get32(bgep->cfg_handle, regno);

	BGE_DEBUG(("bge_cfg_clr32($%p, 0x%lx, 0x%x): 0x%x => 0x%x",
	    (void *)bgep, regno, bits, regval, regval & ~bits));

	regval &= ~bits;
	pci_config_put32(bgep->cfg_handle, regno, regval);
}

#if	BGE_IND_IO32

/*
 * Indirect access to registers & RISC scratchpads, using config space
 * accesses only.
 *
 * This isn't currently used, but someday we might want to use it for
 * restoring the Subsystem Device/Vendor registers (which aren't directly
 * writable in Config Space), or for downloading firmware into the RISCs
 *
 * In any case there are endian issues to be resolved before this code is
 * enabled; the bizarre way that bytes get twisted by this chip AND by
 * the PCI bridge in SPARC systems mean that we shouldn't enable it until
 * it's been thoroughly tested for all access sizes on all supported
 * architectures (SPARC *and* x86!).
 */
uint32_t bge_ind_get32(bge_t *bgep, bge_regno_t regno);
#pragma	inline(bge_ind_get32)

uint32_t
bge_ind_get32(bge_t *bgep, bge_regno_t regno)
{
	uint32_t val;

	BGE_TRACE(("bge_ind_get32($%p, 0x%lx)", (void *)bgep, regno));

#ifdef __sparc
	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		regno = LE_32(regno);
	}
#endif
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_RIAAR, regno);
	val = pci_config_get32(bgep->cfg_handle, PCI_CONF_BGE_RIADR);

	BGE_DEBUG(("bge_ind_get32($%p, 0x%lx) => 0x%x",
	    (void *)bgep, regno, val));

	val = LE_32(val);

	return (val);
}

void bge_ind_put32(bge_t *bgep, bge_regno_t regno, uint32_t val);
#pragma	inline(bge_ind_put32)

void
bge_ind_put32(bge_t *bgep, bge_regno_t regno, uint32_t val)
{
	BGE_TRACE(("bge_ind_put32($%p, 0x%lx, 0x%x)",
	    (void *)bgep, regno, val));

	val = LE_32(val);
#ifdef __sparc
	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		regno = LE_32(regno);
	}
#endif
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_RIAAR, regno);
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_RIADR, val);
}

#endif	/* BGE_IND_IO32 */

#if	BGE_DEBUGGING

static void bge_pci_check(bge_t *bgep);
#pragma	no_inline(bge_pci_check)

static void
bge_pci_check(bge_t *bgep)
{
	uint16_t pcistatus;

	pcistatus = pci_config_get16(bgep->cfg_handle, PCI_CONF_STAT);
	if ((pcistatus & (PCI_STAT_R_MAST_AB | PCI_STAT_R_TARG_AB)) != 0)
		BGE_DEBUG(("bge_pci_check($%p): PCI status 0x%x",
		    (void *)bgep, pcistatus));
}

#endif	/* BGE_DEBUGGING */

/*
 * Perform first-stage chip (re-)initialisation, using only config-space
 * accesses:
 *
 * + Read the vendor/device/revision/subsystem/cache-line-size registers,
 *   returning the data in the structure pointed to by <idp>.
 * + Configure the target-mode endianness (swap) options.
 * + Disable interrupts and enable Memory Space accesses.
 * + Enable or disable Bus Mastering according to the <enable_dma> flag.
 *
 * This sequence is adapted from Broadcom document 570X-PG102-R,
 * page 102, steps 1-3, 6-8 and 11-13.  The omitted parts of the sequence
 * are 4 and 5 (Reset Core and wait) which are handled elsewhere.
 *
 * This function MUST be called before any non-config-space accesses
 * are made; on this first call <enable_dma> is B_FALSE, and it
 * effectively performs steps 3-1(!) of the initialisation sequence
 * (the rest are not required but should be harmless).
 *
 * It MUST also be called after a chip reset, as this disables
 * Memory Space cycles!  In this case, <enable_dma> is B_TRUE, and
 * it is effectively performing steps 6-8.
 */
void bge_chip_cfg_init(bge_t *bgep, chip_id_t *cidp, boolean_t enable_dma);
#pragma	no_inline(bge_chip_cfg_init)

void
bge_chip_cfg_init(bge_t *bgep, chip_id_t *cidp, boolean_t enable_dma)
{
	ddi_acc_handle_t handle;
	uint16_t command;
	uint32_t mhcr;
	uint32_t prodid;
	uint32_t pci_state;
	uint16_t value16;
	int i;

	BGE_TRACE(("bge_chip_cfg_init($%p, $%p, %d)",
	    (void *)bgep, (void *)cidp, enable_dma));

	/*
	 * Step 3: save PCI cache line size and subsystem vendor ID
	 *
	 * Read all the config-space registers that characterise the
	 * chip, specifically vendor/device/revision/subsystem vendor
	 * and subsystem device id.  We expect (but don't check) that
	 * (vendor == VENDOR_ID_BROADCOM) && (device == DEVICE_ID_5704)
	 *
	 * Also save all bus-transaction related registers (cache-line
	 * size, bus-grant/latency parameters, etc).  Some of these are
	 * cleared by reset, so we'll have to restore them later.  This
	 * comes from the Broadcom document 570X-PG102-R ...
	 *
	 * Note: Broadcom document 570X-PG102-R seems to be in error
	 * here w.r.t. the offsets of the Subsystem Vendor ID and
	 * Subsystem (Device) ID registers, which are the opposite way
	 * round according to the PCI standard.  For good measure, we
	 * save/restore both anyway.
	 */
	handle = bgep->cfg_handle;

	/*
	 * For some chipsets (e.g., BCM5718), if MHCR_ENABLE_ENDIAN_BYTE_SWAP
	 * has been set in PCI_CONF_COMM already, we need to write the
	 * byte-swapped value to it. So we just write zero first for simplicity.
	 */
	cidp->device = pci_config_get16(handle, PCI_CONF_DEVID);
	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		pci_config_put32(handle, PCI_CONF_BGE_MHCR, 0);
	}

	mhcr = pci_config_get32(handle, PCI_CONF_BGE_MHCR);
	cidp->asic_rev = (mhcr & MHCR_CHIP_REV_MASK);
	cidp->asic_rev_prod_id = 0;
	if ((cidp->asic_rev & 0xf0000000) == CHIP_ASIC_REV_USE_PROD_ID_REG) {
		prodid = CHIP_ASIC_REV_PROD_ID_REG;
		if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
			prodid = CHIP_ASIC_REV_PROD_ID_GEN2_REG;
		}
		cidp->asic_rev_prod_id = pci_config_get32(handle, prodid);
	}

	cidp->businfo = pci_config_get32(handle, PCI_CONF_BGE_PCISTATE);
	cidp->command = pci_config_get16(handle, PCI_CONF_COMM);

	cidp->vendor = pci_config_get16(handle, PCI_CONF_VENID);
	cidp->subven = pci_config_get16(handle, PCI_CONF_SUBVENID);
	cidp->subdev = pci_config_get16(handle, PCI_CONF_SUBSYSID);
	cidp->revision = pci_config_get8(handle, PCI_CONF_REVID);
	cidp->clsize = pci_config_get8(handle, PCI_CONF_CACHE_LINESZ);
	cidp->latency = pci_config_get8(handle, PCI_CONF_LATENCY_TIMER);

	/* 5717 C0 is treated just like 5720 A0 */
	if (pci_config_get16(bgep->cfg_handle, PCI_CONF_DEVID) ==
	    DEVICE_ID_5717_C0) {
		cidp->device = DEVICE_ID_5720;
	}

	BGE_DEBUG(("bge_chip_cfg_init: %s bus is %s and %s; #INTA is %s",
	    cidp->businfo & PCISTATE_BUS_IS_PCI ? "PCI" : "PCI-X",
	    cidp->businfo & PCISTATE_BUS_IS_FAST ? "fast" : "slow",
	    cidp->businfo & PCISTATE_BUS_IS_32_BIT ? "narrow" : "wide",
	    cidp->businfo & PCISTATE_INTA_STATE ? "high" : "low"));
	BGE_DEBUG(("bge_chip_cfg_init: vendor 0x%x device 0x%x revision 0x%x",
	    cidp->vendor, cidp->device, cidp->revision));
	BGE_DEBUG(("bge_chip_cfg_init: subven 0x%x subdev 0x%x asic_rev 0x%x",
	    cidp->subven, cidp->subdev, cidp->asic_rev));
	BGE_DEBUG(("bge_chip_cfg_init: clsize %d latency %d command 0x%x",
	    cidp->clsize, cidp->latency, cidp->command));

	/*
	 * Step 2 (also step 6): disable and clear interrupts.
	 * Steps 11-13: configure PIO endianness options, and enable
	 * indirect register access.  We'll also select any other
	 * options controlled by the MHCR (e.g. tagged status, mask
	 * interrupt mode) at this stage ...
	 *
	 * Note: internally, the chip is 64-bit and BIG-endian, but
	 * since it talks to the host over a (LITTLE-endian) PCI bus,
	 * it normally swaps bytes around at the PCI interface.
	 * However, the PCI host bridge on SPARC systems normally
	 * swaps the byte lanes around too, since SPARCs are also
	 * BIG-endian.  So it turns out that on SPARC, the right
	 * option is to tell the chip to swap (and the host bridge
	 * will swap back again), whereas on x86 we ask the chip
	 * NOT to swap, so the natural little-endianness of the
	 * PCI bus is assumed.  Then the only thing that doesn't
	 * automatically work right is access to an 8-byte register
	 * by a little-endian host; but we don't want to set the
	 * MHCR_ENABLE_REGISTER_WORD_SWAP bit because then 4-byte
	 * accesses don't go where expected ;-(  So we live with
	 * that, and perform word-swaps in software in the few cases
	 * where a chip register is defined as an 8-byte value --
	 * see the code below for details ...
	 *
	 * Note: the meaning of the 'MASK_INTERRUPT_MODE' bit isn't
	 * very clear in the register description in the PRM, but
	 * Broadcom document 570X-PG104-R page 248 explains a little
	 * more (under "Broadcom Mask Mode").  The bit changes the way
	 * the MASK_PCI_INT_OUTPUT bit works: with MASK_INTERRUPT_MODE
	 * clear, the chip interprets MASK_PCI_INT_OUTPUT in the same
	 * way as the 5700 did, which isn't very convenient.  Setting
	 * the MASK_INTERRUPT_MODE bit makes the MASK_PCI_INT_OUTPUT
	 * bit do just what its name says -- MASK the PCI #INTA output
	 * (i.e. deassert the signal at the pin) leaving all internal
	 * state unchanged.  This is much more convenient for our
	 * interrupt handler, so we set MASK_INTERRUPT_MODE here.
	 *
	 * Note: the inconvenient semantics of the interrupt mailbox
	 * (nonzero disables and acknowledges/clears the interrupt,
	 * zero enables AND CLEARS it) would make race conditions
	 * likely in the interrupt handler:
	 *
	 * (1)	acknowledge & disable interrupts
	 * (2)	while (more to do)
	 * 		process packets
	 * (3)	enable interrupts -- also clears pending
	 *
	 * If the chip received more packets and internally generated
	 * an interrupt between the check at (2) and the mbox write
	 * at (3), this interrupt would be lost :-(
	 *
	 * The best way to avoid this is to use TAGGED STATUS mode,
	 * where the chip includes a unique tag in each status block
	 * update, and the host, when re-enabling interrupts, passes
	 * the last tag it saw back to the chip; then the chip can
	 * see whether the host is truly up to date, and regenerate
	 * its interrupt if not.
	 */
	mhcr = MHCR_ENABLE_INDIRECT_ACCESS |
	       MHCR_ENABLE_PCI_STATE_RW |
	       MHCR_ENABLE_TAGGED_STATUS_MODE |
	       MHCR_MASK_INTERRUPT_MODE |
	       MHCR_CLEAR_INTERRUPT_INTA;
	if (bgep->intr_type == DDI_INTR_TYPE_FIXED)
		mhcr |= MHCR_MASK_PCI_INT_OUTPUT;

#ifdef	_BIG_ENDIAN
	mhcr |= MHCR_ENABLE_ENDIAN_WORD_SWAP | MHCR_ENABLE_ENDIAN_BYTE_SWAP;
#endif	/* _BIG_ENDIAN */
	pci_config_put32(handle, PCI_CONF_BGE_MHCR, mhcr);

#ifdef BGE_IPMI_ASF
	bgep->asf_wordswapped = B_FALSE;
#endif

	pci_state = (PCISTATE_EXT_ROM_ENABLE | PCISTATE_EXT_ROM_RETRY);
	/* allow reads and writes to the APE register and memory space */
	if (bgep->ape_enabled) {
		pci_state |= PCISTATE_ALLOW_APE_CTLSPC_WR |
		    PCISTATE_ALLOW_APE_SHMEM_WR | PCISTATE_ALLOW_APE_PSPACE_WR;
	}
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_PCISTATE, pci_state);

	/*
	 * Step 1 (also step 7): Enable PCI Memory Space accesses
	 *			 Disable Memory Write/Invalidate
	 *			 Enable or disable Bus Mastering
	 *
	 * Note that all other bits are taken from the original value saved
	 * the first time through here, rather than from the current register
	 * value, 'cos that will have been cleared by a soft RESET since.
	 * In this way we preserve the OBP/nexus-parent's preferred settings
	 * of the parity-error and system-error enable bits across multiple
	 * chip RESETs.
	 */
	command = bgep->chipid.command | PCI_COMM_MAE;
	command &= ~(PCI_COMM_ME|PCI_COMM_MEMWR_INVAL);
	if (enable_dma)
		command |= PCI_COMM_ME;
	/*
	 * on BCM5714 revision A0, false parity error gets generated
	 * due to a logic bug. Provide a workaround by disabling parity
	 * error.
	 */
	if (((cidp->device == DEVICE_ID_5714C) ||
	    (cidp->device == DEVICE_ID_5714S)) &&
	    (cidp->revision == REVISION_ID_5714_A0)) {
		command &= ~PCI_COMM_PARITY_DETECT;
	}
	pci_config_put16(handle, PCI_CONF_COMM, command);

	/*
	 * On some PCI-E device, there were instances when
	 * the device was still link training.
	 */
	if (bgep->chipid.pci_type == BGE_PCI_E) {
		i = 0;
		value16 = pci_config_get16(handle, PCI_CONF_COMM);
		while ((value16 != command) && (i < 100)) {
			drv_usecwait(200);
			value16 = pci_config_get16(handle, PCI_CONF_COMM);
			++i;
		}
	}

	/*
	 * Clear any remaining error status bits
	 */
	pci_config_put16(handle, PCI_CONF_STAT, ~0);

	/*
	 * Do following if and only if the device is NOT BCM5714C OR
	 * BCM5715C
	 */
	if (!((cidp->device == DEVICE_ID_5714C) ||
	    (cidp->device == DEVICE_ID_5715C))) {
		/*
		 * Make sure these indirect-access registers are sane
		 * rather than random after power-up or reset
		 */
		pci_config_put32(handle, PCI_CONF_BGE_RIAAR, 0);
		pci_config_put32(handle, PCI_CONF_BGE_MWBAR, 0);
	}
	/*
	 * Step 8: Disable PCI-X/PCI-E Relaxed Ordering
	 */
	bge_cfg_clr16(bgep, PCIX_CONF_COMM, PCIX_COMM_RELAXED);

	if (cidp->pci_type == BGE_PCI_E) {
		if (DEVICE_5723_SERIES_CHIPSETS(bgep)) {
			bge_cfg_clr16(bgep, PCI_CONF_DEV_CTRL_5723,
			    DEV_CTRL_NO_SNOOP | DEV_CTRL_RELAXED);
		} else if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
		           DEVICE_5725_SERIES_CHIPSETS(bgep)) {
			bge_cfg_clr16(bgep, PCI_CONF_DEV_CTRL_5717,
			    DEV_CTRL_NO_SNOOP | DEV_CTRL_RELAXED);
		} else {
			bge_cfg_clr16(bgep, PCI_CONF_DEV_CTRL,
			    DEV_CTRL_NO_SNOOP | DEV_CTRL_RELAXED);
		}
	}
}

#ifdef __amd64
/*
 * Distinguish CPU types
 *
 * These use to  distinguish AMD64 or Intel EM64T of CPU running mode.
 * If CPU runs on Intel EM64T mode,the 64bit operation cannot works fine
 * for PCI-Express based network interface card. This is the work-around
 * for those nics.
 */
static boolean_t bge_get_em64t_type(void);
#pragma	inline(bge_get_em64t_type)

static boolean_t
bge_get_em64t_type(void)
{

	return (x86_vendor == X86_VENDOR_Intel);
}
#endif

/*
 * Operating register get/set access routines
 */

uint32_t bge_reg_get32(bge_t *bgep, bge_regno_t regno);
#pragma	inline(bge_reg_get32)

uint32_t
bge_reg_get32(bge_t *bgep, bge_regno_t regno)
{
	BGE_TRACE(("bge_reg_get32($%p, 0x%lx)",
	    (void *)bgep, regno));

	return (ddi_get32(bgep->io_handle, PIO_ADDR(bgep, regno)));
}

void bge_reg_put32(bge_t *bgep, bge_regno_t regno, uint32_t data);
#pragma	inline(bge_reg_put32)

void
bge_reg_put32(bge_t *bgep, bge_regno_t regno, uint32_t data)
{
	BGE_TRACE(("bge_reg_put32($%p, 0x%lx, 0x%x)",
	    (void *)bgep, regno, data));

	ddi_put32(bgep->io_handle, PIO_ADDR(bgep, regno), data);
	BGE_PCICHK(bgep);
}

void bge_reg_set32(bge_t *bgep, bge_regno_t regno, uint32_t bits);
#pragma	inline(bge_reg_set32)

void
bge_reg_set32(bge_t *bgep, bge_regno_t regno, uint32_t bits)
{
	uint32_t regval;

	BGE_TRACE(("bge_reg_set32($%p, 0x%lx, 0x%x)",
	    (void *)bgep, regno, bits));

	regval = bge_reg_get32(bgep, regno);
	regval |= bits;
	bge_reg_put32(bgep, regno, regval);
}

void bge_reg_clr32(bge_t *bgep, bge_regno_t regno, uint32_t bits);
#pragma	inline(bge_reg_clr32)

void
bge_reg_clr32(bge_t *bgep, bge_regno_t regno, uint32_t bits)
{
	uint32_t regval;

	BGE_TRACE(("bge_reg_clr32($%p, 0x%lx, 0x%x)",
	    (void *)bgep, regno, bits));

	regval = bge_reg_get32(bgep, regno);
	regval &= ~bits;
	bge_reg_put32(bgep, regno, regval);
}

static uint64_t bge_reg_get64(bge_t *bgep, bge_regno_t regno);
#pragma	inline(bge_reg_get64)

static uint64_t
bge_reg_get64(bge_t *bgep, bge_regno_t regno)
{
	uint64_t regval;

#ifdef	__amd64
	if (DEVICE_5723_SERIES_CHIPSETS(bgep) ||
	    bge_get_em64t_type() ||
	    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		regval = ddi_get32(bgep->io_handle, PIO_ADDR(bgep, regno + 4));
		regval <<= 32;
		regval |= ddi_get32(bgep->io_handle, PIO_ADDR(bgep, regno));
	} else {
		regval = ddi_get64(bgep->io_handle, PIO_ADDR(bgep, regno));
	}
#elif defined(__sparc)
	if (DEVICE_5723_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		regval = ddi_get32(bgep->io_handle, PIO_ADDR(bgep, regno));
		regval <<= 32;
		regval |= ddi_get32(bgep->io_handle, PIO_ADDR(bgep, regno + 4));
	} else {
		regval = ddi_get64(bgep->io_handle, PIO_ADDR(bgep, regno));
	}
#else
	regval = ddi_get64(bgep->io_handle, PIO_ADDR(bgep, regno));
#endif

#ifdef	_LITTLE_ENDIAN
	regval = (regval >> 32) | (regval << 32);
#endif	/* _LITTLE_ENDIAN */

	BGE_TRACE(("bge_reg_get64($%p, 0x%lx) = 0x%016llx",
	    (void *)bgep, regno, regval));

	return (regval);
}

static void bge_reg_put64(bge_t *bgep, bge_regno_t regno, uint64_t data);
#pragma	inline(bge_reg_put64)

static void
bge_reg_put64(bge_t *bgep, bge_regno_t regno, uint64_t data)
{
	BGE_TRACE(("bge_reg_put64($%p, 0x%lx, 0x%016llx)",
	    (void *)bgep, regno, data));

#ifdef	_LITTLE_ENDIAN
	data = ((data >> 32) | (data << 32));
#endif	/* _LITTLE_ENDIAN */

#ifdef	__amd64
	if (DEVICE_5723_SERIES_CHIPSETS(bgep) ||
	    bge_get_em64t_type() ||
	    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		ddi_put32(bgep->io_handle,
		    PIO_ADDR(bgep, regno), (uint32_t)data);
		BGE_PCICHK(bgep);
		ddi_put32(bgep->io_handle,
		    PIO_ADDR(bgep, regno + 4), (uint32_t)(data >> 32));

	} else {
		ddi_put64(bgep->io_handle, PIO_ADDR(bgep, regno), data);
	}
#elif defined(__sparc)
	if (DEVICE_5723_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		ddi_put32(bgep->io_handle,
		    PIO_ADDR(bgep, regno + 4), (uint32_t)data);
		BGE_PCICHK(bgep);
		ddi_put32(bgep->io_handle,
		    PIO_ADDR(bgep, regno), (uint32_t)(data >> 32));
	} else {
		ddi_put64(bgep->io_handle, PIO_ADDR(bgep, regno), data);
	}
#else
	ddi_put64(bgep->io_handle, PIO_ADDR(bgep, regno), data);
#endif

	BGE_PCICHK(bgep);
}

/*
 * The DDI doesn't provide get/put functions for 128 bit data
 * so we put RCBs out as two 64-bit chunks instead.
 */
static void bge_reg_putrcb(bge_t *bgep, bge_regno_t addr, bge_rcb_t *rcbp);
#pragma	inline(bge_reg_putrcb)

static void
bge_reg_putrcb(bge_t *bgep, bge_regno_t addr, bge_rcb_t *rcbp)
{
	uint64_t *p;

	BGE_TRACE(("bge_reg_putrcb($%p, 0x%lx, 0x%016llx:%04x:%04x:%08x)",
	    (void *)bgep, addr, rcbp->host_ring_addr,
	    rcbp->max_len, rcbp->flags, rcbp->nic_ring_addr));

	ASSERT((addr % sizeof (*rcbp)) == 0);

	p = (void *)rcbp;
	bge_reg_put64(bgep, addr, *p++);
	bge_reg_put64(bgep, addr+8, *p);
}

void bge_mbx_put(bge_t *bgep, bge_regno_t regno, uint64_t data);
#pragma	inline(bge_mbx_put)

void
bge_mbx_put(bge_t *bgep, bge_regno_t regno, uint64_t data)
{
	if (DEVICE_5906_SERIES_CHIPSETS(bgep))
		regno += INTERRUPT_LP_MBOX_0_REG - INTERRUPT_MBOX_0_REG + 4;

	BGE_TRACE(("bge_mbx_put($%p, 0x%lx, 0x%016llx)",
	    (void *)bgep, regno, data));

	/*
	 * Mailbox registers are nominally 64 bits on the 5701, but
	 * the MSW isn't used.  On the 5703, they're only 32 bits
	 * anyway.  So here we just write the lower(!) 32 bits -
	 * remembering that the chip is big-endian, even though the
	 * PCI bus is little-endian ...
	 */
#ifdef	_BIG_ENDIAN
	ddi_put32(bgep->io_handle, PIO_ADDR(bgep, regno+4), (uint32_t)data);
#else
	ddi_put32(bgep->io_handle, PIO_ADDR(bgep, regno), (uint32_t)data);
#endif	/* _BIG_ENDIAN */
	BGE_PCICHK(bgep);
}

uint32_t bge_mbx_get(bge_t *bgep, bge_regno_t regno);
#pragma inline(bge_mbx_get)

uint32_t
bge_mbx_get(bge_t *bgep, bge_regno_t regno)
{
	uint32_t val32;

	if (DEVICE_5906_SERIES_CHIPSETS(bgep))
		regno += INTERRUPT_LP_MBOX_0_REG - INTERRUPT_MBOX_0_REG + 4;

	BGE_TRACE(("bge_mbx_get($%p, 0x%lx)",
	    (void *)bgep, regno));

#ifdef	_BIG_ENDIAN
	val32 = ddi_get32(bgep->io_handle, PIO_ADDR(bgep, regno+4));
#else
	val32 = ddi_get32(bgep->io_handle, PIO_ADDR(bgep, regno));
#endif	/* _BIG_ENDIAN */
	BGE_PCICHK(bgep);

	BGE_DEBUG(("bge_mbx_get($%p, 0x%lx) => 0x%08x",
	    (void *)bgep, regno, val32));

	return (val32);
}


#if	BGE_DEBUGGING

void bge_led_mark(bge_t *bgep);
#pragma	no_inline(bge_led_mark)

void
bge_led_mark(bge_t *bgep)
{
	uint32_t led_ctrl = LED_CONTROL_OVERRIDE_LINK |
	    LED_CONTROL_1000MBPS_LED |
	    LED_CONTROL_100MBPS_LED |
	    LED_CONTROL_10MBPS_LED;

	/*
	 * Blink all three LINK LEDs on simultaneously, then all off,
	 * then restore to automatic hardware control.  This is used
	 * in laboratory testing to trigger a logic analyser or scope.
	 */
	bge_reg_set32(bgep, ETHERNET_MAC_LED_CONTROL_REG, led_ctrl);
	led_ctrl ^= LED_CONTROL_OVERRIDE_LINK;
	bge_reg_clr32(bgep, ETHERNET_MAC_LED_CONTROL_REG, led_ctrl);
	led_ctrl = LED_CONTROL_OVERRIDE_LINK;
	bge_reg_clr32(bgep, ETHERNET_MAC_LED_CONTROL_REG, led_ctrl);
}

#endif	/* BGE_DEBUGGING */

/*
 * NIC on-chip memory access routines
 *
 * Only 32K of NIC memory is visible at a time, controlled by the
 * Memory Window Base Address Register (in PCI config space).  Once
 * this is set, the 32K region of NIC-local memory that it refers
 * to can be directly addressed in the upper 32K of the 64K of PCI
 * memory space used for the device.
 */

static void bge_nic_setwin(bge_t *bgep, bge_regno_t base);
#pragma	inline(bge_nic_setwin)

static void
bge_nic_setwin(bge_t *bgep, bge_regno_t base)
{
	chip_id_t *cidp;

	BGE_TRACE(("bge_nic_setwin($%p, 0x%lx)",
	    (void *)bgep, base));

	ASSERT((base & MWBAR_GRANULE_MASK) == 0);

	/*
	 * Don't do repeated zero data writes,
	 * if the device is BCM5714C/15C.
	 */
	cidp = &bgep->chipid;
	if ((cidp->device == DEVICE_ID_5714C) ||
	    (cidp->device == DEVICE_ID_5715C)) {
		if (bgep->lastWriteZeroData && (base == (bge_regno_t)0))
			return;
		/* Adjust lastWriteZeroData */
		bgep->lastWriteZeroData = ((base == (bge_regno_t)0) ?
		    B_TRUE : B_FALSE);
	}
#ifdef __sparc
	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		base = LE_32(base);
	}
#endif
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MWBAR, base);
}

static uint32_t bge_nic_get32(bge_t *bgep, bge_regno_t addr);
#pragma	inline(bge_nic_get32)

static uint32_t
bge_nic_get32(bge_t *bgep, bge_regno_t addr)
{
	uint32_t data;

#if defined(BGE_IPMI_ASF) && !defined(__sparc)
	if (bgep->asf_enabled && !bgep->asf_wordswapped) {
		/* workaround for word swap error */
		if (addr & 4)
			addr = addr - 4;
		else
			addr = addr + 4;
	}
#endif

#ifdef __sparc
	data = bge_nic_read32(bgep, addr);
#else
	bge_nic_setwin(bgep, addr & ~MWBAR_GRANULE_MASK);
	addr &= MWBAR_GRANULE_MASK;
	addr += NIC_MEM_WINDOW_OFFSET;

	data = ddi_get32(bgep->io_handle, PIO_ADDR(bgep, addr));
#endif

	BGE_TRACE(("bge_nic_get32($%p, 0x%lx) = 0x%08x",
	    (void *)bgep, addr, data));

	return (data);
}

void bge_nic_put32(bge_t *bgep, bge_regno_t addr, uint32_t data);
#pragma inline(bge_nic_put32)

void
bge_nic_put32(bge_t *bgep, bge_regno_t addr, uint32_t data)
{
	BGE_TRACE(("bge_nic_put32($%p, 0x%lx, 0x%08x)",
	    (void *)bgep, addr, data));

#if defined(BGE_IPMI_ASF) && !defined(__sparc)
	if (bgep->asf_enabled && !bgep->asf_wordswapped) {
		/* workaround for word swap error */
		if (addr & 4)
			addr = addr - 4;
		else
			addr = addr + 4;
	}
#endif

#ifdef __sparc
	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		addr = LE_32(addr);
	}
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MWBAR, addr);
	data = LE_32(data);
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MWDAR, data);
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MWBAR, 0);
#else
	bge_nic_setwin(bgep, addr & ~MWBAR_GRANULE_MASK);
	addr &= MWBAR_GRANULE_MASK;
	addr += NIC_MEM_WINDOW_OFFSET;
	ddi_put32(bgep->io_handle, PIO_ADDR(bgep, addr), data);
	BGE_PCICHK(bgep);
#endif
}

static uint64_t bge_nic_get64(bge_t *bgep, bge_regno_t addr);
#pragma	inline(bge_nic_get64)

static uint64_t
bge_nic_get64(bge_t *bgep, bge_regno_t addr)
{
	uint64_t data;

	bge_nic_setwin(bgep, addr & ~MWBAR_GRANULE_MASK);
	addr &= MWBAR_GRANULE_MASK;
	addr += NIC_MEM_WINDOW_OFFSET;

#ifdef	__amd64
	if (DEVICE_5723_SERIES_CHIPSETS(bgep) ||
	    bge_get_em64t_type() ||
	    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		data = ddi_get32(bgep->io_handle,
		    PIO_ADDR(bgep, addr + 4));
		data <<= 32;
		data |= ddi_get32(bgep->io_handle, PIO_ADDR(bgep, addr));
	} else {
		data = ddi_get64(bgep->io_handle, PIO_ADDR(bgep, addr));
	}
#elif defined(__sparc)
	if (DEVICE_5723_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		data = ddi_get32(bgep->io_handle, PIO_ADDR(bgep, addr));
		data <<= 32;
		data |= ddi_get32(bgep->io_handle,
		    PIO_ADDR(bgep, addr + 4));
	} else {
		data = ddi_get64(bgep->io_handle, PIO_ADDR(bgep, addr));
	}
#else
	data = ddi_get64(bgep->io_handle, PIO_ADDR(bgep, addr));
#endif

	BGE_TRACE(("bge_nic_get64($%p, 0x%lx) = 0x%016llx",
	    (void *)bgep, addr, data));

	return (data);
}

static void bge_nic_put64(bge_t *bgep, bge_regno_t addr, uint64_t data);
#pragma	inline(bge_nic_put64)

static void
bge_nic_put64(bge_t *bgep, bge_regno_t addr, uint64_t data)
{
	BGE_TRACE(("bge_nic_put64($%p, 0x%lx, 0x%016llx)",
	    (void *)bgep, addr, data));

	bge_nic_setwin(bgep, addr & ~MWBAR_GRANULE_MASK);
	addr &= MWBAR_GRANULE_MASK;
	addr += NIC_MEM_WINDOW_OFFSET;

#ifdef	__amd64
	if (DEVICE_5723_SERIES_CHIPSETS(bgep) ||
	    bge_get_em64t_type() ||
	    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		ddi_put32(bgep->io_handle,
		    PIO_ADDR(bgep, addr + 4), (uint32_t)data);
		BGE_PCICHK(bgep);
		ddi_put32(bgep->io_handle,
		    PIO_ADDR(bgep, addr), (uint32_t)(data >> 32));
	} else {
		ddi_put64(bgep->io_handle, PIO_ADDR(bgep, addr), data);
	}
#elif defined(__sparc)
	if (DEVICE_5723_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		ddi_put32(bgep->io_handle,
		    PIO_ADDR(bgep, addr + 4), (uint32_t)data);
		BGE_PCICHK(bgep);
		ddi_put32(bgep->io_handle,
		    PIO_ADDR(bgep, addr), (uint32_t)(data >> 32));
	} else {
		ddi_put64(bgep->io_handle, PIO_ADDR(bgep, addr), data);
	}
#else
	ddi_put64(bgep->io_handle, PIO_ADDR(bgep, addr), data);
#endif

	BGE_PCICHK(bgep);
}

/*
 * The DDI doesn't provide get/put functions for 128 bit data
 * so we put RCBs out as two 64-bit chunks instead.
 */
static void bge_nic_putrcb(bge_t *bgep, bge_regno_t addr, bge_rcb_t *rcbp);
#pragma	inline(bge_nic_putrcb)

static void
bge_nic_putrcb(bge_t *bgep, bge_regno_t addr, bge_rcb_t *rcbp)
{
	uint64_t *p;

	BGE_TRACE(("bge_nic_putrcb($%p, 0x%lx, 0x%016llx:%04x:%04x:%08x)",
	    (void *)bgep, addr, rcbp->host_ring_addr,
	    rcbp->max_len, rcbp->flags, rcbp->nic_ring_addr));

	ASSERT((addr % sizeof (*rcbp)) == 0);

	bge_nic_setwin(bgep, addr & ~MWBAR_GRANULE_MASK);
	addr &= MWBAR_GRANULE_MASK;
	addr += NIC_MEM_WINDOW_OFFSET;

	p = (void *)rcbp;
#ifdef	__amd64
	if (DEVICE_5723_SERIES_CHIPSETS(bgep) ||
	    bge_get_em64t_type() ||
	    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		ddi_put32(bgep->io_handle, PIO_ADDR(bgep, addr),
		    (uint32_t)(*p));
		ddi_put32(bgep->io_handle, PIO_ADDR(bgep, addr + 4),
		    (uint32_t)(*p++ >> 32));
		ddi_put32(bgep->io_handle, PIO_ADDR(bgep, addr + 8),
		    (uint32_t)(*p));
		ddi_put32(bgep->io_handle, PIO_ADDR(bgep, addr + 12),
		    (uint32_t)(*p >> 32));

	} else {
		ddi_put64(bgep->io_handle, PIO_ADDR(bgep, addr), *p++);
		ddi_put64(bgep->io_handle, PIO_ADDR(bgep, addr+8), *p);
	}
#elif defined(__sparc)
	if (DEVICE_5723_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		ddi_put32(bgep->io_handle, PIO_ADDR(bgep, addr + 4),
		    (uint32_t)(*p));
		ddi_put32(bgep->io_handle, PIO_ADDR(bgep, addr),
		    (uint32_t)(*p++ >> 32));
		ddi_put32(bgep->io_handle, PIO_ADDR(bgep, addr + 12),
		    (uint32_t)(*p));
		ddi_put32(bgep->io_handle, PIO_ADDR(bgep, addr + 8),
		    (uint32_t)(*p >> 32));
	} else {
		ddi_put64(bgep->io_handle, PIO_ADDR(bgep, addr), *p++);
		ddi_put64(bgep->io_handle, PIO_ADDR(bgep, addr + 8), *p);
	}
#else
	ddi_put64(bgep->io_handle, PIO_ADDR(bgep, addr), *p++);
	ddi_put64(bgep->io_handle, PIO_ADDR(bgep, addr + 8), *p);
#endif

	BGE_PCICHK(bgep);
}

static void bge_nic_zero(bge_t *bgep, bge_regno_t addr, uint32_t nbytes);
#pragma	inline(bge_nic_zero)

static void
bge_nic_zero(bge_t *bgep, bge_regno_t addr, uint32_t nbytes)
{
	BGE_TRACE(("bge_nic_zero($%p, 0x%lx, 0x%x)",
	    (void *)bgep, addr, nbytes));

	ASSERT((addr & ~MWBAR_GRANULE_MASK) ==
	    ((addr+nbytes) & ~MWBAR_GRANULE_MASK));

	bge_nic_setwin(bgep, addr & ~MWBAR_GRANULE_MASK);
	addr &= MWBAR_GRANULE_MASK;
	addr += NIC_MEM_WINDOW_OFFSET;

	(void) ddi_device_zero(bgep->io_handle, PIO_ADDR(bgep, addr),
	    nbytes, 1, DDI_DATA_SZ08_ACC);
	BGE_PCICHK(bgep);
}

/*
 * MII (PHY) register get/set access routines
 *
 * These use the chip's MII auto-access method, controlled by the
 * MII Communication register at 0x044c, so the CPU doesn't have
 * to fiddle with the individual bits.
 */

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_MII	/* debug flag for this code	*/

static uint16_t bge_mii_access(bge_t *bgep, bge_regno_t regno,
				uint16_t data, uint32_t cmd);
#pragma	no_inline(bge_mii_access)

static uint16_t
bge_mii_access(bge_t *bgep, bge_regno_t regno, uint16_t data, uint32_t cmd)
{
	uint32_t timeout;
	uint32_t regval1;
	uint32_t regval2;

	BGE_TRACE(("bge_mii_access($%p, 0x%lx, 0x%x, 0x%x)",
	    (void *)bgep, regno, data, cmd));

	ASSERT(mutex_owned(bgep->genlock));

	/*
	 * Assemble the command ...
	 */
	cmd |= data << MI_COMMS_DATA_SHIFT;
	cmd |= regno << MI_COMMS_REGISTER_SHIFT;
	cmd |= bgep->phy_mii_addr << MI_COMMS_ADDRESS_SHIFT;
	cmd |= MI_COMMS_START;

	/*
	 * Wait for any command already in progress ...
	 *
	 * Note: this *shouldn't* ever find that there is a command
	 * in progress, because we already hold the <genlock> mutex.
	 * Nonetheless, we have sometimes seen the MI_COMMS_START
	 * bit set here -- it seems that the chip can initiate MII
	 * accesses internally, even with polling OFF.
	 */
	regval1 = regval2 = bge_reg_get32(bgep, MI_COMMS_REG);
	for (timeout = 100; ; ) {
		if ((regval2 & MI_COMMS_START) == 0) {
			bge_reg_put32(bgep, MI_COMMS_REG, cmd);
			break;
		}
		if (--timeout == 0)
			break;
		drv_usecwait(10);
		regval2 = bge_reg_get32(bgep, MI_COMMS_REG);
	}

	if (timeout == 0)
		return ((uint16_t)~0u);

	if (timeout != 100)
		BGE_REPORT((bgep, "bge_mii_access: cmd 0x%x -- "
		    "MI_COMMS_START set for %d us; 0x%x->0x%x",
		    cmd, 10*(100-timeout), regval1, regval2));

	regval1 = bge_reg_get32(bgep, MI_COMMS_REG);
	for (timeout = 1000; ; ) {
		if ((regval1 & MI_COMMS_START) == 0)
			break;
		if (--timeout == 0)
			break;
		drv_usecwait(10);
		regval1 = bge_reg_get32(bgep, MI_COMMS_REG);
	}

	/*
	 * Drop out early if the READ FAILED bit is set -- this chip
	 * could be a 5703/4S, with a SerDes instead of a PHY!
	 */
	if (regval2 & MI_COMMS_READ_FAILED)
		return ((uint16_t)~0u);

	if (timeout == 0)
		return ((uint16_t)~0u);

	/*
	 * The PRM says to wait 5us after seeing the START bit clear
	 * and then re-read the register to get the final value of the
	 * data field, in order to avoid a race condition where the
	 * START bit is clear but the data field isn't yet valid.
	 *
	 * Note: we don't actually seem to be encounter this race;
	 * except when the START bit is seen set again (see below),
	 * the data field doesn't change during this 5us interval.
	 */
	drv_usecwait(5);
	regval2 = bge_reg_get32(bgep, MI_COMMS_REG);

	/*
	 * Unfortunately, when following the PRMs instructions above,
	 * we have occasionally seen the START bit set again(!) in the
	 * value read after the 5us delay. This seems to be due to the
	 * chip autonomously starting another MII access internally.
	 * In such cases, the command/data/etc fields relate to the
	 * internal command, rather than the one that we thought had
	 * just finished.  So in this case, we fall back to returning
	 * the data from the original read that showed START clear.
	 */
	if (regval2 & MI_COMMS_START) {
		BGE_REPORT((bgep, "bge_mii_access: cmd 0x%x -- "
		    "MI_COMMS_START set after transaction; 0x%x->0x%x",
		    cmd, regval1, regval2));
		regval2 = regval1;
	}

	if (regval2 & MI_COMMS_START)
		return ((uint16_t)~0u);

	if (regval2 & MI_COMMS_READ_FAILED)
		return ((uint16_t)~0u);

	return ((regval2 & MI_COMMS_DATA_MASK) >> MI_COMMS_DATA_SHIFT);
}

uint16_t bge_mii_get16(bge_t *bgep, bge_regno_t regno);
#pragma	no_inline(bge_mii_get16)

uint16_t
bge_mii_get16(bge_t *bgep, bge_regno_t regno)
{
	BGE_TRACE(("bge_mii_get16($%p, 0x%lx)",
	    (void *)bgep, regno));

	ASSERT(mutex_owned(bgep->genlock));

	if (DEVICE_5906_SERIES_CHIPSETS(bgep) && ((regno == MII_AUX_CONTROL) ||
	    (regno == MII_MSCONTROL)))
		return (0);

	return (bge_mii_access(bgep, regno, 0, MI_COMMS_COMMAND_READ));
}

void bge_mii_put16(bge_t *bgep, bge_regno_t regno, uint16_t data);
#pragma	no_inline(bge_mii_put16)

void
bge_mii_put16(bge_t *bgep, bge_regno_t regno, uint16_t data)
{
	BGE_TRACE(("bge_mii_put16($%p, 0x%lx, 0x%x)",
	    (void *)bgep, regno, data));

	ASSERT(mutex_owned(bgep->genlock));

	if (DEVICE_5906_SERIES_CHIPSETS(bgep) && ((regno == MII_AUX_CONTROL) ||
	    (regno == MII_MSCONTROL)))
		return;

	(void) bge_mii_access(bgep, regno, data, MI_COMMS_COMMAND_WRITE);
}

uint16_t
bge_phydsp_read(bge_t *bgep, bge_regno_t regno)
{
	BGE_TRACE(("bge_phydsp_read($%p, 0x%lx)",
	          (void *)bgep, regno));

	ASSERT(mutex_owned(bgep->genlock));

	bge_mii_put16(bgep, MII_DSP_ADDRESS, regno);
	return bge_mii_get16(bgep, MII_DSP_RW_PORT);
}

#pragma	no_inline(bge_phydsp_write)

void
bge_phydsp_write(bge_t *bgep, bge_regno_t regno, uint16_t data)
{
	BGE_TRACE(("bge_phydsp_write($%p, 0x%lx, 0x%x)",
	          (void *)bgep, regno, data));

	ASSERT(mutex_owned(bgep->genlock));

	bge_mii_put16(bgep, MII_DSP_ADDRESS, regno);
	bge_mii_put16(bgep, MII_DSP_RW_PORT, data);
}

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_SEEPROM	/* debug flag for this code	*/

#if	BGE_SEE_IO32 || BGE_FLASH_IO32

/*
 * Basic SEEPROM get/set access routine
 *
 * This uses the chip's SEEPROM auto-access method, controlled by the
 * Serial EEPROM Address/Data Registers at 0x6838/683c, so the CPU
 * doesn't have to fiddle with the individual bits.
 *
 * The caller should hold <genlock> and *also* have already acquired
 * the right to access the SEEPROM, via bge_nvmem_acquire() above.
 *
 * Return value:
 *	0 on success,
 *	ENODATA on access timeout (maybe retryable: device may just be busy)
 *	EPROTO on other h/w or s/w errors.
 *
 * <*dp> is an input to a SEEPROM_ACCESS_WRITE operation, or an output
 * from a (successful) SEEPROM_ACCESS_READ.
 */
static int bge_seeprom_access(bge_t *bgep, uint32_t cmd, bge_regno_t addr,
				uint32_t *dp);
#pragma	no_inline(bge_seeprom_access)

static int
bge_seeprom_access(bge_t *bgep, uint32_t cmd, bge_regno_t addr, uint32_t *dp)
{
	uint32_t tries;
	uint32_t regval;

	ASSERT(mutex_owned(bgep->genlock));

	/*
	 * On the newer chips that support both SEEPROM & Flash, we need
	 * to specifically enable SEEPROM access (Flash is the default).
	 * On older chips, we don't; SEEPROM is the only NVtype supported,
	 * and the NVM control registers don't exist ...
	 */
	switch (bgep->chipid.nvtype) {
	case BGE_NVTYPE_NONE:
	case BGE_NVTYPE_UNKNOWN:
		_NOTE(NOTREACHED)
	case BGE_NVTYPE_SEEPROM:
		break;

	case BGE_NVTYPE_LEGACY_SEEPROM:
	case BGE_NVTYPE_UNBUFFERED_FLASH:
	case BGE_NVTYPE_BUFFERED_FLASH:
	default:
		bge_reg_set32(bgep, NVM_CONFIG1_REG,
		    NVM_CFG1_LEGACY_SEEPROM_MODE);
		break;
	}

	/*
	 * Check there's no command in progress.
	 *
	 * Note: this *shouldn't* ever find that there is a command
	 * in progress, because we already hold the <genlock> mutex.
	 * Also, to ensure we don't have a conflict with the chip's
	 * internal firmware or a process accessing the same (shared)
	 * SEEPROM through the other port of a 5704, we've already
	 * been through the "software arbitration" protocol.
	 * So this is just a final consistency check: we shouldn't
	 * see EITHER the START bit (command started but not complete)
	 * OR the COMPLETE bit (command completed but not cleared).
	 */
	regval = bge_reg_get32(bgep, SERIAL_EEPROM_ADDRESS_REG);
	if (regval & SEEPROM_ACCESS_START)
		return (EPROTO);
	if (regval & SEEPROM_ACCESS_COMPLETE)
		return (EPROTO);

	/*
	 * Assemble the command ...
	 */
	cmd |= addr & SEEPROM_ACCESS_ADDRESS_MASK;
	addr >>= SEEPROM_ACCESS_ADDRESS_SIZE;
	addr <<= SEEPROM_ACCESS_DEVID_SHIFT;
	cmd |= addr & SEEPROM_ACCESS_DEVID_MASK;
	cmd |= SEEPROM_ACCESS_START;
	cmd |= SEEPROM_ACCESS_COMPLETE;
	cmd |= regval & SEEPROM_ACCESS_HALFCLOCK_MASK;

	bge_reg_put32(bgep, SERIAL_EEPROM_DATA_REG, *dp);
	bge_reg_put32(bgep, SERIAL_EEPROM_ADDRESS_REG, cmd);

	/*
	 * By observation, a successful access takes ~20us on a 5703/4,
	 * but apparently much longer (up to 1000us) on the obsolescent
	 * BCM5700/BCM5701.  We want to be sure we don't get any false
	 * timeouts here; but OTOH, we don't want a bogus access to lock
	 * out interrupts for longer than necessary. So we'll allow up
	 * to 1000us ...
	 */
	for (tries = 0; tries < 1000; ++tries) {
		regval = bge_reg_get32(bgep, SERIAL_EEPROM_ADDRESS_REG);
		if (regval & SEEPROM_ACCESS_COMPLETE)
			break;
		drv_usecwait(1);
	}

	if (regval & SEEPROM_ACCESS_COMPLETE) {
		/*
		 * All OK; read the SEEPROM data register, then write back
		 * the value read from the address register in order to
		 * clear the <complete> bit and leave the SEEPROM access
		 * state machine idle, ready for the next access ...
		 */
		BGE_DEBUG(("bge_seeprom_access: complete after %d us", tries));
		*dp = bge_reg_get32(bgep, SERIAL_EEPROM_DATA_REG);
		bge_reg_put32(bgep, SERIAL_EEPROM_ADDRESS_REG, regval);
		return (0);
	}

	/*
	 * Hmm ... what happened here?
	 *
	 * Most likely, the user addressed a non-existent SEEPROM. Or
	 * maybe the SEEPROM was busy internally (e.g. processing a write)
	 * and didn't respond to being addressed. Either way, it's left
	 * the SEEPROM access state machine wedged. So we'll reset it
	 * before we leave, so it's ready for next time ...
	 */
	BGE_DEBUG(("bge_seeprom_access: timed out after %d us", tries));
	bge_reg_set32(bgep, SERIAL_EEPROM_ADDRESS_REG, SEEPROM_ACCESS_INIT);
	return (ENODATA);
}

/*
 * Basic Flash get/set access routine
 *
 * These use the chip's Flash auto-access method, controlled by the
 * Flash Access Registers at 0x7000-701c, so the CPU doesn't have to
 * fiddle with the individual bits.
 *
 * The caller should hold <genlock> and *also* have already acquired
 * the right to access the Flash, via bge_nvmem_acquire() above.
 *
 * Return value:
 *	0 on success,
 *	ENODATA on access timeout (maybe retryable: device may just be busy)
 *	ENODEV if the NVmem device is missing or otherwise unusable
 *
 * <*dp> is an input to a NVM_FLASH_CMD_WR operation, or an output
 * from a (successful) NVM_FLASH_CMD_RD.
 */
static int bge_flash_access(bge_t *bgep, uint32_t cmd, bge_regno_t addr,
				uint32_t *dp);
#pragma	no_inline(bge_flash_access)

static int
bge_flash_access(bge_t *bgep, uint32_t cmd, bge_regno_t addr, uint32_t *dp)
{
	uint32_t tries;
	uint32_t regval;

	ASSERT(mutex_owned(bgep->genlock));

	/*
	 * On the newer chips that support both SEEPROM & Flash, we need
	 * to specifically disable SEEPROM access while accessing Flash.
	 * The older chips don't support Flash, and the NVM registers don't
	 * exist, so we shouldn't be here at all!
	 */
	switch (bgep->chipid.nvtype) {
	case BGE_NVTYPE_NONE:
	case BGE_NVTYPE_UNKNOWN:
		_NOTE(NOTREACHED)
	case BGE_NVTYPE_SEEPROM:
		return (ENODEV);

	case BGE_NVTYPE_LEGACY_SEEPROM:
	case BGE_NVTYPE_UNBUFFERED_FLASH:
	case BGE_NVTYPE_BUFFERED_FLASH:
	default:
		bge_reg_clr32(bgep, NVM_CONFIG1_REG,
		    NVM_CFG1_LEGACY_SEEPROM_MODE);
		break;
	}

	/*
	 * Assemble the command ...
	 */
	addr &= NVM_FLASH_ADDR_MASK;
	cmd |= NVM_FLASH_CMD_DOIT;
	cmd |= NVM_FLASH_CMD_FIRST;
	cmd |= NVM_FLASH_CMD_LAST;
	cmd |= NVM_FLASH_CMD_DONE;

	bge_reg_put32(bgep, NVM_FLASH_WRITE_REG, *dp);
	bge_reg_put32(bgep, NVM_FLASH_ADDR_REG, addr);
	bge_reg_put32(bgep, NVM_FLASH_CMD_REG, cmd);

	/*
	 * Allow up to 1000ms ...
	 */
	for (tries = 0; tries < 1000; ++tries) {
		regval = bge_reg_get32(bgep, NVM_FLASH_CMD_REG);
		if (regval & NVM_FLASH_CMD_DONE)
			break;
		drv_usecwait(1);
	}

	if (regval & NVM_FLASH_CMD_DONE) {
		/*
		 * All OK; read the data from the Flash read register
		 */
		BGE_DEBUG(("bge_flash_access: complete after %d us", tries));
		*dp = bge_reg_get32(bgep, NVM_FLASH_READ_REG);
		return (0);
	}

	/*
	 * Hmm ... what happened here?
	 *
	 * Most likely, the user addressed a non-existent Flash. Or
	 * maybe the Flash was busy internally (e.g. processing a write)
	 * and didn't respond to being addressed. Either way, there's
	 * nothing we can here ...
	 */
	BGE_DEBUG(("bge_flash_access: timed out after %d us", tries));
	return (ENODATA);
}

/*
 * The next two functions regulate access to the NVram (if fitted).
 *
 * On a 5704 (dual core) chip, there's only one SEEPROM and one Flash
 * (SPI) interface, but they can be accessed through either port. These
 * are managed by different instance of this driver and have no software
 * state in common.
 *
 * In addition (and even on a single core chip) the chip's internal
 * firmware can access the SEEPROM/Flash, most notably after a RESET
 * when it may download code to run internally.
 *
 * So we need to arbitrate between these various software agents.  For
 * this purpose, the chip provides the Software Arbitration Register,
 * which implements hardware(!) arbitration.
 *
 * This functionality didn't exist on older (5700/5701) chips, so there's
 * nothing we can do by way of arbitration on those; also, if there's no
 * SEEPROM/Flash fitted (or we couldn't determine what type), there's also
 * nothing to do.
 *
 * The internal firmware appears to use Request 0, which is the highest
 * priority.  So we'd like to use Request 2, leaving one higher and one
 * lower for any future developments ... but apparently this doesn't
 * always work.  So for now, the code uses Request 1 ;-(
 */

#define	NVM_READ_REQ	NVM_READ_REQ1
#define	NVM_RESET_REQ	NVM_RESET_REQ1
#define	NVM_SET_REQ	NVM_SET_REQ1

static void bge_nvmem_relinquish(bge_t *bgep);
#pragma	no_inline(bge_nvmem_relinquish)

static void
bge_nvmem_relinquish(bge_t *bgep)
{
	ASSERT(mutex_owned(bgep->genlock));

	switch (bgep->chipid.nvtype) {
	case BGE_NVTYPE_NONE:
	case BGE_NVTYPE_UNKNOWN:
		_NOTE(NOTREACHED)
		return;

	case BGE_NVTYPE_SEEPROM:
		/*
		 * No arbitration performed, no release needed
		 */
		return;

	case BGE_NVTYPE_LEGACY_SEEPROM:
	case BGE_NVTYPE_UNBUFFERED_FLASH:
	case BGE_NVTYPE_BUFFERED_FLASH:
	default:
		break;
	}

	/*
	 * Our own request should be present (whether or not granted) ...
	 */
	(void) bge_reg_get32(bgep, NVM_SW_ARBITRATION_REG);

	/*
	 * ... this will make it go away.
	 */
	bge_reg_put32(bgep, NVM_SW_ARBITRATION_REG, NVM_RESET_REQ);
	(void) bge_reg_get32(bgep, NVM_SW_ARBITRATION_REG);
}

/*
 * Arbitrate for access to the NVmem, if necessary
 *
 * Return value:
 *	0 on success
 *	EAGAIN if the device is in use (retryable)
 *	ENODEV if the NVmem device is missing or otherwise unusable
 */
static int bge_nvmem_acquire(bge_t *bgep);
#pragma	no_inline(bge_nvmem_acquire)

static int
bge_nvmem_acquire(bge_t *bgep)
{
	uint32_t regval;
	uint32_t tries;

	ASSERT(mutex_owned(bgep->genlock));

	switch (bgep->chipid.nvtype) {
	case BGE_NVTYPE_NONE:
	case BGE_NVTYPE_UNKNOWN:
		/*
		 * Access denied: no (recognisable) device fitted
		 */
		return (ENODEV);

	case BGE_NVTYPE_SEEPROM:
		/*
		 * Access granted: no arbitration needed (or possible)
		 */
		return (0);

	case BGE_NVTYPE_LEGACY_SEEPROM:
	case BGE_NVTYPE_UNBUFFERED_FLASH:
	case BGE_NVTYPE_BUFFERED_FLASH:
	default:
		/*
		 * Access conditional: conduct arbitration protocol
		 */
		break;
	}

	/*
	 * We're holding the per-port mutex <genlock>, so no-one other
	 * thread can be attempting to access the NVmem through *this*
	 * port. But it could be in use by the *other* port (of a 5704),
	 * or by the chip's internal firmware, so we have to go through
	 * the full (hardware) arbitration protocol ...
	 *
	 * Note that *because* we're holding <genlock>, the interrupt handler
	 * won't be able to progress.  So we're only willing to spin for a
	 * fairly short time.  Specifically:
	 *
	 *	We *must* wait long enough for the hardware to resolve all
	 *	requests and determine the winner.  Fortunately, this is
	 *	"almost instantaneous", even as observed by GHz CPUs.
	 *
	 *	A successful access by another Solaris thread (via either
	 *	port) typically takes ~20us.  So waiting a bit longer than
	 *	that will give a good chance of success, if the other user
	 *	*is* another thread on the other port.
	 *
	 *	However, the internal firmware can hold on to the NVmem
	 *	for *much* longer: at least 10 milliseconds just after a
	 *	RESET, and maybe even longer if the NVmem actually contains
	 *	code to download and run on the internal CPUs.
	 *
	 * So, we'll allow 50us; if that's not enough then it's up to the
	 * caller to retry later (hence the choice of return code EAGAIN).
	 */
	regval = bge_reg_get32(bgep, NVM_SW_ARBITRATION_REG);
	bge_reg_put32(bgep, NVM_SW_ARBITRATION_REG, NVM_SET_REQ);

	for (tries = 0; tries < 50; ++tries) {
		regval = bge_reg_get32(bgep, NVM_SW_ARBITRATION_REG);
		if (regval & NVM_WON_REQ1)
			break;
		drv_usecwait(1);
	}

	if (regval & NVM_WON_REQ1) {
		BGE_DEBUG(("bge_nvmem_acquire: won after %d us", tries));
		return (0);
	}

	/*
	 * Somebody else must be accessing the NVmem, so abandon our
	 * attempt take control of it.  The caller can try again later ...
	 */
	BGE_DEBUG(("bge_nvmem_acquire: lost after %d us", tries));
	bge_nvmem_relinquish(bgep);
	return (EAGAIN);
}

/*
 * This code assumes that the GPIO1 bit has been wired up to the NVmem
 * write protect line in such a way that the NVmem is protected when
 * GPIO1 is an input, or is an output but driven high.  Thus, to make the
 * NVmem writable we have to change GPIO1 to an output AND drive it low.
 *
 * Note: there's only one set of GPIO pins on a 5704, even though they
 * can be accessed through either port.  So the chip has to resolve what
 * happens if the two ports program a single pin differently ... the rule
 * it uses is that if the ports disagree about the *direction* of a pin,
 * "output" wins over "input", but if they disagree about its *value* as
 * an output, then the pin is TRISTATED instead!  In such a case, no-one
 * wins, and the external signal does whatever the external circuitry
 * defines as the default -- which we've assumed is the PROTECTED state.
 * So, we always change GPIO1 back to being an *input* whenever we're not
 * specifically using it to unprotect the NVmem. This allows either port
 * to update the NVmem, although obviously only one at a time!
 *
 * The caller should hold <genlock> and *also* have already acquired the
 * right to access the NVmem, via bge_nvmem_acquire() above.
 */
static void bge_nvmem_protect(bge_t *bgep, boolean_t protect);
#pragma	inline(bge_nvmem_protect)

static void
bge_nvmem_protect(bge_t *bgep, boolean_t protect)
{
	uint32_t regval;

	ASSERT(mutex_owned(bgep->genlock));

	regval = bge_reg_get32(bgep, MISC_LOCAL_CONTROL_REG);
	if (protect) {
		regval |= MLCR_MISC_PINS_OUTPUT_1;
		regval &= ~MLCR_MISC_PINS_OUTPUT_ENABLE_1;
	} else {
		regval &= ~MLCR_MISC_PINS_OUTPUT_1;
		regval |= MLCR_MISC_PINS_OUTPUT_ENABLE_1;
	}
	bge_reg_put32(bgep, MISC_LOCAL_CONTROL_REG, regval);
}

/*
 * Now put it all together ...
 *
 * Try to acquire control of the NVmem; if successful, then:
 *	unprotect it (if we want to write to it)
 *	perform the requested access
 *	reprotect it (after a write)
 *	relinquish control
 *
 * Return value:
 *	0 on success,
 *	EAGAIN if the device is in use (retryable)
 *	ENODATA on access timeout (maybe retryable: device may just be busy)
 *	ENODEV if the NVmem device is missing or otherwise unusable
 *	EPROTO on other h/w or s/w errors.
 */
static int
bge_nvmem_rw32(bge_t *bgep, uint32_t cmd, bge_regno_t addr, uint32_t *dp)
{
	int err;

	if ((err = bge_nvmem_acquire(bgep)) == 0) {
		switch (cmd) {
		case BGE_SEE_READ:
			err = bge_seeprom_access(bgep,
			    SEEPROM_ACCESS_READ, addr, dp);
			break;

		case BGE_SEE_WRITE:
			bge_nvmem_protect(bgep, B_FALSE);
			err = bge_seeprom_access(bgep,
			    SEEPROM_ACCESS_WRITE, addr, dp);
			bge_nvmem_protect(bgep, B_TRUE);
			break;

		case BGE_FLASH_READ:
			if (DEVICE_5721_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5723_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5725_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5714_SERIES_CHIPSETS(bgep)) {
				bge_reg_set32(bgep, NVM_ACCESS_REG,
				    NVM_ACCESS_ENABLE);
			}
			err = bge_flash_access(bgep,
			    NVM_FLASH_CMD_RD, addr, dp);
			if (DEVICE_5721_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5723_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5725_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5714_SERIES_CHIPSETS(bgep)) {
				bge_reg_clr32(bgep, NVM_ACCESS_REG,
				    NVM_ACCESS_ENABLE);
			}
			break;

		case BGE_FLASH_WRITE:
			if (DEVICE_5721_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5723_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5725_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5714_SERIES_CHIPSETS(bgep)) {
				bge_reg_set32(bgep, NVM_ACCESS_REG,
				    NVM_WRITE_ENABLE|NVM_ACCESS_ENABLE);
			}
			bge_nvmem_protect(bgep, B_FALSE);
			err = bge_flash_access(bgep,
			    NVM_FLASH_CMD_WR, addr, dp);
			bge_nvmem_protect(bgep, B_TRUE);
			if (DEVICE_5721_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5723_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5725_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5714_SERIES_CHIPSETS(bgep)) {
				bge_reg_clr32(bgep, NVM_ACCESS_REG,
				    NVM_WRITE_ENABLE|NVM_ACCESS_ENABLE);
			}

			break;

		default:
			_NOTE(NOTREACHED)
			break;
		}
		bge_nvmem_relinquish(bgep);
	}

	BGE_DEBUG(("bge_nvmem_rw32: err %d", err));
	return (err);
}

static uint32_t
bge_nvmem_access_cmd(bge_t *bgep, boolean_t read)
{
	switch (bgep->chipid.nvtype) {
	case BGE_NVTYPE_NONE:
	case BGE_NVTYPE_UNKNOWN:
	default:
		return 0;

	case BGE_NVTYPE_SEEPROM:
	case BGE_NVTYPE_LEGACY_SEEPROM:
		return (read ? BGE_SEE_READ : BGE_SEE_WRITE);

	case BGE_NVTYPE_UNBUFFERED_FLASH:
	case BGE_NVTYPE_BUFFERED_FLASH:
		return (read ? BGE_FLASH_READ : BGE_FLASH_WRITE);
	}
}


int
bge_nvmem_read32(bge_t *bgep, bge_regno_t addr, uint32_t *dp)
{
	return (bge_nvmem_rw32(bgep, bge_nvmem_access_cmd(bgep, B_TRUE),
	    addr, dp));
}


int
bge_nvmem_write32(bge_t *bgep, bge_regno_t addr, uint32_t *dp)
{
	return (bge_nvmem_rw32(bgep, bge_nvmem_access_cmd(bgep, B_FALSE),
	    addr, dp));
}


/*
 * Attempt to get a MAC address from the SEEPROM or Flash, if any
 */
static uint64_t bge_get_nvmac(bge_t *bgep);
#pragma no_inline(bge_get_nvmac)

static uint64_t
bge_get_nvmac(bge_t *bgep)
{
	uint32_t mac_high;
	uint32_t mac_low;
	uint32_t addr;
	uint32_t cmd;
	uint64_t mac;

	BGE_TRACE(("bge_get_nvmac($%p)",
	    (void *)bgep));

	switch (bgep->chipid.nvtype) {
	case BGE_NVTYPE_NONE:
	case BGE_NVTYPE_UNKNOWN:
	default:
		return (0ULL);

	case BGE_NVTYPE_SEEPROM:
	case BGE_NVTYPE_LEGACY_SEEPROM:
		cmd = BGE_SEE_READ;
		break;

	case BGE_NVTYPE_UNBUFFERED_FLASH:
	case BGE_NVTYPE_BUFFERED_FLASH:
		cmd = BGE_FLASH_READ;
		break;
	}

	if (DEVICE_5906_SERIES_CHIPSETS(bgep))
		addr = NVMEM_DATA_MAC_ADDRESS_5906;
	else
		addr = NVMEM_DATA_MAC_ADDRESS;

	if (bge_nvmem_rw32(bgep, cmd, addr, &mac_high))
		return (0ULL);
	addr += 4;
	if (bge_nvmem_rw32(bgep, cmd, addr, &mac_low))
		return (0ULL);

	/*
	 * The Broadcom chip is natively BIG-endian, so that's how the
	 * MAC address is represented in NVmem.  We may need to swap it
	 * around on a little-endian host ...
	 */
#ifdef	_BIG_ENDIAN
	mac = mac_high;
	mac = mac << 32;
	mac |= mac_low;
#else
	mac = BGE_BSWAP_32(mac_high);
	mac = mac << 32;
	mac |= BGE_BSWAP_32(mac_low);
#endif	/* _BIG_ENDIAN */

	return (mac);
}

#else	/* BGE_SEE_IO32 || BGE_FLASH_IO32 */

/*
 * Dummy version for when we're not supporting NVmem access
 */
static uint64_t bge_get_nvmac(bge_t *bgep);
#pragma inline(bge_get_nvmac)

static uint64_t
bge_get_nvmac(bge_t *bgep)
{
	_NOTE(ARGUNUSED(bgep))
	return (0ULL);
}

#endif	/* BGE_SEE_IO32 || BGE_FLASH_IO32 */

/*
 * Determine the type of NVmem that is (or may be) attached to this chip,
 */
static enum bge_nvmem_type bge_nvmem_id(bge_t *bgep);
#pragma no_inline(bge_nvmem_id)

static enum bge_nvmem_type
bge_nvmem_id(bge_t *bgep)
{
	enum bge_nvmem_type nvtype;
	uint32_t config1;

	BGE_TRACE(("bge_nvmem_id($%p)",
	    (void *)bgep));

	switch (bgep->chipid.device) {
	default:
		/*
		 * We shouldn't get here; it means we don't recognise
		 * the chip, which means we don't know how to determine
		 * what sort of NVmem (if any) it has.  So we'll say
		 * NONE, to disable the NVmem access code ...
		 */
		nvtype = BGE_NVTYPE_NONE;
		break;

	case DEVICE_ID_5700:
	case DEVICE_ID_5700x:
	case DEVICE_ID_5701:
		/*
		 * These devices support *only* SEEPROMs
		 */
		nvtype = BGE_NVTYPE_SEEPROM;
		break;

	case DEVICE_ID_5702:
	case DEVICE_ID_5702fe:
	case DEVICE_ID_5703C:
	case DEVICE_ID_5703S:
	case DEVICE_ID_5704C:
	case DEVICE_ID_5704S:
	case DEVICE_ID_5704:
	case DEVICE_ID_5705M:
	case DEVICE_ID_5705C:
	case DEVICE_ID_5705_2:
	case DEVICE_ID_5717:
	case DEVICE_ID_5718:
	case DEVICE_ID_5719:
	case DEVICE_ID_5720:
	case DEVICE_ID_5724:
	case DEVICE_ID_5725:
	case DEVICE_ID_5727:
	case DEVICE_ID_57780:
	case DEVICE_ID_5780:
	case DEVICE_ID_5782:
	case DEVICE_ID_5785:
	case DEVICE_ID_5787:
	case DEVICE_ID_5787M:
	case DEVICE_ID_5788:
	case DEVICE_ID_5789:
	case DEVICE_ID_5751:
	case DEVICE_ID_5751M:
	case DEVICE_ID_5752:
	case DEVICE_ID_5752M:
	case DEVICE_ID_5754:
	case DEVICE_ID_5755:
	case DEVICE_ID_5755M:
	case DEVICE_ID_5756M:
	case DEVICE_ID_5721:
	case DEVICE_ID_5722:
	case DEVICE_ID_5723:
	case DEVICE_ID_5761:
	case DEVICE_ID_5761E:
	case DEVICE_ID_5764:
	case DEVICE_ID_5714C:
	case DEVICE_ID_5714S:
	case DEVICE_ID_5715C:
	case DEVICE_ID_5715S:
		config1 = bge_reg_get32(bgep, NVM_CONFIG1_REG);
		if (config1 & NVM_CFG1_FLASH_MODE)
			if (config1 & NVM_CFG1_BUFFERED_MODE)
				nvtype = BGE_NVTYPE_BUFFERED_FLASH;
			else
				nvtype = BGE_NVTYPE_UNBUFFERED_FLASH;
		else
			nvtype = BGE_NVTYPE_LEGACY_SEEPROM;
		break;
	case DEVICE_ID_5906:
	case DEVICE_ID_5906M:
		nvtype = BGE_NVTYPE_BUFFERED_FLASH;
		break;
	}

	return (nvtype);
}

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_APE	/* debug flag for this code	*/

uint32_t bge_ape_get32(bge_t *bgep, bge_regno_t regno);
#pragma	inline(bge_ape_get32)

uint32_t
bge_ape_get32(bge_t *bgep, bge_regno_t regno)
{
	BGE_TRACE(("bge_ape_get32($%p, 0x%lx)",
	    (void *)bgep, regno));

	return (ddi_get32(bgep->ape_handle, APE_ADDR(bgep, regno)));
}

void bge_ape_put32(bge_t *bgep, bge_regno_t regno, uint32_t data);
#pragma	inline(bge_ape_put32)

void
bge_ape_put32(bge_t *bgep, bge_regno_t regno, uint32_t data)
{
	BGE_TRACE(("bge_ape_put32($%p, 0x%lx, 0x%x)",
	    (void *)bgep, regno, data));

	ddi_put32(bgep->ape_handle, APE_ADDR(bgep, regno), data);
	BGE_PCICHK(bgep);
}

void
bge_ape_lock_init(bge_t *bgep)
{
	int i;
	uint32_t regbase;
	uint32_t bit;

	BGE_TRACE(("bge_ape_lock_init($%p)", (void *)bgep));

	if (bgep->chipid.device == DEVICE_ID_5761)
		regbase = BGE_APE_LOCK_GRANT;
	else
		regbase = BGE_APE_PER_LOCK_GRANT;

	/* Make sure the driver hasn't any stale locks. */
	for (i = BGE_APE_LOCK_PHY0; i <= BGE_APE_LOCK_GPIO; i++) {
		switch (i) {
		case BGE_APE_LOCK_PHY0:
		case BGE_APE_LOCK_PHY1:
		case BGE_APE_LOCK_PHY2:
		case BGE_APE_LOCK_PHY3:
			bit = APE_LOCK_GRANT_DRIVER;
			break;
		default:
			if (!bgep->pci_func)
				bit = APE_LOCK_GRANT_DRIVER;
			else
				bit = 1 << bgep->pci_func;
		}
		bge_ape_put32(bgep, regbase + 4 * i, bit);
	}
}

static int
bge_ape_lock(bge_t *bgep, int locknum)
{
	int i, off;
	int ret = 0;
	uint32_t status;
	uint32_t req;
	uint32_t gnt;
	uint32_t bit;

	BGE_TRACE(("bge_ape_lock($%p, 0x%x)", (void *)bgep, locknum));

	if (!bgep->ape_enabled)
		return (0);

	switch (locknum) {
	case BGE_APE_LOCK_GPIO:
		if (bgep->chipid.device == DEVICE_ID_5761)
			return (0);
	case BGE_APE_LOCK_GRC:
	case BGE_APE_LOCK_MEM:
		if (!bgep->pci_func)
			bit = APE_LOCK_REQ_DRIVER;
		else
			bit = 1 << bgep->pci_func;
		break;
	case BGE_APE_LOCK_PHY0:
	case BGE_APE_LOCK_PHY1:
	case BGE_APE_LOCK_PHY2:
	case BGE_APE_LOCK_PHY3:
		bit = APE_LOCK_REQ_DRIVER;
		break;
	default:
		return (-1);
	}

	if (bgep->chipid.device == DEVICE_ID_5761) {
		req = BGE_APE_LOCK_REQ;
		gnt = BGE_APE_LOCK_GRANT;
	} else {
		req = BGE_APE_PER_LOCK_REQ;
		gnt = BGE_APE_PER_LOCK_GRANT;
	}

	off = 4 * locknum;

	bge_ape_put32(bgep, req + off, bit);

	/* Wait for up to 1 millisecond to acquire lock. */
	for (i = 0; i < 100; i++) {
		status = bge_ape_get32(bgep, gnt + off);
		if (status == bit)
			break;
		drv_usecwait(10);
	}

	if (status != bit) {
		/* Revoke the lock request. */
		bge_ape_put32(bgep, gnt + off, bit);
		ret = -1;
	}

	return (ret);
}

static void
bge_ape_unlock(bge_t *bgep, int locknum)
{
	uint32_t gnt;
	uint32_t bit;

	BGE_TRACE(("bge_ape_unlock($%p, 0x%x)", (void *)bgep, locknum));

	if (!bgep->ape_enabled)
		return;

	switch (locknum) {
	case BGE_APE_LOCK_GPIO:
		if (bgep->chipid.device == DEVICE_ID_5761)
			return;
	case BGE_APE_LOCK_GRC:
	case BGE_APE_LOCK_MEM:
		if (!bgep->pci_func)
			bit = APE_LOCK_GRANT_DRIVER;
		else
			bit = 1 << bgep->pci_func;
		break;
	case BGE_APE_LOCK_PHY0:
	case BGE_APE_LOCK_PHY1:
	case BGE_APE_LOCK_PHY2:
	case BGE_APE_LOCK_PHY3:
		bit = APE_LOCK_GRANT_DRIVER;
		break;
	default:
		return;
	}

	if (bgep->chipid.device == DEVICE_ID_5761)
		gnt = BGE_APE_LOCK_GRANT;
	else
		gnt = BGE_APE_PER_LOCK_GRANT;

	bge_ape_put32(bgep, gnt + 4 * locknum, bit);
}

/* wait for pending event to finish, if successful returns with MEM locked */
static int
bge_ape_event_lock(bge_t *bgep, uint32_t timeout_us)
{
	uint32_t apedata;

	BGE_TRACE(("bge_ape_event_lock($%p, %d)", (void *)bgep, timeout_us));

	ASSERT(timeout_us > 0);

	while (timeout_us) {
		if (bge_ape_lock(bgep, BGE_APE_LOCK_MEM))
			return (-1);

		apedata = bge_ape_get32(bgep, BGE_APE_EVENT_STATUS);
		if (!(apedata & APE_EVENT_STATUS_EVENT_PENDING))
			break;

		bge_ape_unlock(bgep, BGE_APE_LOCK_MEM);

		drv_usecwait(10);
		timeout_us -= (timeout_us > 10) ? 10 : timeout_us;
	}

	return (timeout_us ? 0 : -1);
}

/* wait for pending event to finish, returns non-zero if not finished */
static int
bge_ape_wait_for_event(bge_t *bgep, uint32_t timeout_us)
{
	uint32_t i;
	uint32_t apedata;

	BGE_TRACE(("bge_ape_wait_for_event($%p, %d)", (void *)bgep, timeout_us));

	ASSERT(timeout_us > 0);

	for (i = 0; i < timeout_us / 10; i++) {
		apedata = bge_ape_get32(bgep, BGE_APE_EVENT_STATUS);

		if (!(apedata & APE_EVENT_STATUS_EVENT_PENDING))
			break;

		drv_usecwait(10);
	}

	return (i == timeout_us / 10);
}

int
bge_ape_scratchpad_read(bge_t *bgep, uint32_t *data, uint32_t base_off,
    uint32_t lenToRead)
{
	int err;
	uint32_t i;
	uint32_t bufoff;
	uint32_t msgoff;
	uint32_t maxlen;
	uint32_t apedata;

	BGE_TRACE(("bge_ape_scratchpad_read($%p, %p, 0x%0x, %d)",
	    (void *)bgep, (void*)data, base_off, lenToRead));

	if (!bgep->ape_has_ncsi)
		return (0);

	apedata = bge_ape_get32(bgep, BGE_APE_SEG_SIG);
	if (apedata != APE_SEG_SIG_MAGIC)
		return (-1);

	apedata = bge_ape_get32(bgep, BGE_APE_FW_STATUS);
	if (!(apedata & APE_FW_STATUS_READY))
		return (-1);

	bufoff = (bge_ape_get32(bgep, BGE_APE_SEG_MSG_BUF_OFF) +
	          BGE_APE_SHMEM_BASE);
	msgoff = bufoff + 2 * sizeof(uint32_t);
	maxlen = bge_ape_get32(bgep, BGE_APE_SEG_MSG_BUF_LEN);

	while (lenToRead) {
		uint32_t transferLen;

		/* Cap xfer sizes to scratchpad limits. */
		transferLen = (lenToRead > maxlen) ? maxlen : lenToRead;
		lenToRead -= transferLen;

		apedata = bge_ape_get32(bgep, BGE_APE_FW_STATUS);
		if (!(apedata & APE_FW_STATUS_READY))
			return (-1);

		/* Wait for up to 1 millisecond for APE to service previous event. */
		err = bge_ape_event_lock(bgep, 1000);
		if (err)
			return (err);

		apedata = (APE_EVENT_STATUS_DRIVER_EVNT |
		           APE_EVENT_STATUS_SCRTCHPD_READ |
		           APE_EVENT_STATUS_EVENT_PENDING);
		bge_ape_put32(bgep, BGE_APE_EVENT_STATUS, apedata);

		bge_ape_put32(bgep, bufoff, base_off);
		bge_ape_put32(bgep, bufoff + sizeof(uint32_t), transferLen);

		bge_ape_unlock(bgep, BGE_APE_LOCK_MEM);
		bge_ape_put32(bgep, BGE_APE_EVENT, APE_EVENT_1);

		base_off += transferLen;

		if (bge_ape_wait_for_event(bgep, 30000))
			return (-1);

		for (i = 0; transferLen; i += 4, transferLen -= 4) {
			uint32_t val = bge_ape_get32(bgep, msgoff + i);
			memcpy(data, &val, sizeof(uint32_t));
			data++;
		}
	}

	return (0);
}

int
bge_ape_scratchpad_write(bge_t *bgep, uint32_t dstoff, uint32_t *data,
    uint32_t lenToWrite)
{
	int err;
	uint32_t i;
	uint32_t bufoff;
	uint32_t msgoff;
	uint32_t maxlen;
	uint32_t apedata;

	BGE_TRACE(("bge_ape_scratchpad_write($%p, %d, %p, %d)",
	    (void *)bgep, dstoff, data, lenToWrite));

	if (!bgep->ape_has_ncsi)
		return (0);

	apedata = bge_ape_get32(bgep, BGE_APE_SEG_SIG);
	if (apedata != APE_SEG_SIG_MAGIC)
		return (-1);

	apedata = bge_ape_get32(bgep, BGE_APE_FW_STATUS);
	if (!(apedata & APE_FW_STATUS_READY))
		return (-1);

	bufoff = (bge_ape_get32(bgep, BGE_APE_SEG_MSG_BUF_OFF) +
	          BGE_APE_SHMEM_BASE);
	msgoff = bufoff + 2 * sizeof(uint32_t);
	maxlen = bge_ape_get32(bgep, BGE_APE_SEG_MSG_BUF_LEN);

	while (lenToWrite) {
		uint32_t transferLen;

		/* Cap xfer sizes to scratchpad limits. */
		transferLen = (lenToWrite > maxlen) ? maxlen : lenToWrite;
		lenToWrite -= transferLen;

		/* Wait for up to 1 millisecond for
		 * APE to service previous event.
		 */
		err = bge_ape_event_lock(bgep, 1000);
		if (err)
			return (err);

		bge_ape_put32(bgep, bufoff, dstoff);
		bge_ape_put32(bgep, bufoff + sizeof(uint32_t), transferLen);
		apedata = msgoff;

		dstoff += transferLen;

		for (i = 0; transferLen; i += 4, transferLen -= 4) {
			bge_ape_put32(bgep, apedata, *data++);
			apedata += sizeof(uint32_t);
		}

		apedata = (APE_EVENT_STATUS_DRIVER_EVNT |
		           APE_EVENT_STATUS_SCRTCHPD_WRITE |
		           APE_EVENT_STATUS_EVENT_PENDING);
		bge_ape_put32(bgep, BGE_APE_EVENT_STATUS, apedata);

		bge_ape_unlock(bgep, BGE_APE_LOCK_MEM);
		bge_ape_put32(bgep, BGE_APE_EVENT, APE_EVENT_1);
	}

	return (0);
}

static int
bge_ape_send_event(bge_t *bgep, uint32_t event)
{
	int err;
	uint32_t apedata;

	BGE_TRACE(("bge_ape_send_event($%p, %d)", (void *)bgep, event));

	apedata = bge_ape_get32(bgep, BGE_APE_SEG_SIG);
	if (apedata != APE_SEG_SIG_MAGIC)
		return (-1);

	apedata = bge_ape_get32(bgep, BGE_APE_FW_STATUS);
	if (!(apedata & APE_FW_STATUS_READY))
		return (-1);

	/* Wait for up to 1 millisecond for APE to service previous event. */
	err = bge_ape_event_lock(bgep, 1000);
	if (err)
		return (err);

	bge_ape_put32(bgep, BGE_APE_EVENT_STATUS,
	              event | APE_EVENT_STATUS_EVENT_PENDING);

	bge_ape_unlock(bgep, BGE_APE_LOCK_MEM);
	bge_ape_put32(bgep, BGE_APE_EVENT, APE_EVENT_1);

	return 0;
}

static void
bge_ape_driver_state_change(bge_t *bgep, int mode)
{
	uint32_t event;
	uint32_t apedata;

	BGE_TRACE(("bge_ape_driver_state_change($%p, %d)",
	    (void *)bgep, mode));

	if (!bgep->ape_enabled)
		return;

	switch (mode) {
	case BGE_INIT_RESET:
		bge_ape_put32(bgep, BGE_APE_HOST_SEG_SIG,
		              APE_HOST_SEG_SIG_MAGIC);
		bge_ape_put32(bgep, BGE_APE_HOST_SEG_LEN,
		              APE_HOST_SEG_LEN_MAGIC);
		apedata = bge_ape_get32(bgep, BGE_APE_HOST_INIT_COUNT);
		bge_ape_put32(bgep, BGE_APE_HOST_INIT_COUNT, ++apedata);
		bge_ape_put32(bgep, BGE_APE_HOST_DRIVER_ID,
		              APE_HOST_DRIVER_ID_MAGIC(1, 0));
		bge_ape_put32(bgep, BGE_APE_HOST_BEHAVIOR,
		              APE_HOST_BEHAV_NO_PHYLOCK);
		bge_ape_put32(bgep, BGE_APE_HOST_DRVR_STATE,
		              BGE_APE_HOST_DRVR_STATE_START);

		event = APE_EVENT_STATUS_STATE_START;
		break;
	case BGE_SHUTDOWN_RESET:
		/* With the interface we are currently using,
		 * APE does not track driver state.  Wiping
		 * out the HOST SEGMENT SIGNATURE forces
		 * the APE to assume OS absent status.
		 */
		bge_ape_put32(bgep, BGE_APE_HOST_SEG_SIG, 0x0);

#if 0
		if (WOL supported) {
			bge_ape_put32(bgep, BGE_APE_HOST_WOL_SPEED,
			              BGE_APE_HOST_WOL_SPEED_AUTO);
			apedata = BGE_APE_HOST_DRVR_STATE_WOL;
		} else
#endif
			apedata = BGE_APE_HOST_DRVR_STATE_UNLOAD;

		bge_ape_put32(bgep, BGE_APE_HOST_DRVR_STATE, apedata);

		event = APE_EVENT_STATUS_STATE_UNLOAD;
		break;
	case BGE_SUSPEND_RESET:
		event = APE_EVENT_STATUS_STATE_SUSPEND;
		break;
	default:
		return;
	}

	event |= APE_EVENT_STATUS_DRIVER_EVNT | APE_EVENT_STATUS_STATE_CHNGE;

	bge_ape_send_event(bgep, event);
}

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_CHIP	/* debug flag for this code	*/

static void
bge_init_recv_rule(bge_t *bgep)
{
	bge_recv_rule_t *rulep = bgep->recv_rules;
	uint32_t i;

	/*
	 * Initialize receive rule registers.
	 * Note that rules may persist across each bge_m_start/stop() call.
	 */
	for (i = 0; i < RECV_RULES_NUM_MAX; i++, rulep++) {
		bge_reg_put32(bgep, RECV_RULE_MASK_REG(i), rulep->mask_value);
		bge_reg_put32(bgep, RECV_RULE_CONTROL_REG(i), rulep->control);
	}
}

/*
 * Using the values captured by bge_chip_cfg_init(), and additional probes
 * as required, characterise the chip fully: determine the label by which
 * to refer to this chip, the correct settings for various registers, and
 * of course whether the device and/or subsystem are supported!
 */
int bge_chip_id_init(bge_t *bgep);
#pragma	no_inline(bge_chip_id_init)

int
bge_chip_id_init(bge_t *bgep)
{
	char buf[MAXPATHLEN];		/* any risk of stack overflow?	*/
	boolean_t dev_ok;
	chip_id_t *cidp;
	uint32_t subid;
	char *devname;
	char *sysname;
	int *ids;
	int err;
	uint_t i;

	dev_ok = B_FALSE;
	cidp = &bgep->chipid;

	/*
	 * Check the PCI device ID to determine the generic chip type and
	 * select parameters that depend on this.
	 *
	 * Note: because the SPARC platforms in general don't fit the
	 * SEEPROM 'behind' the chip, the PCI revision ID register reads
	 * as zero - which is why we use <asic_rev> rather than <revision>
	 * below ...
	 *
	 * Note: in general we can't distinguish between the Copper/SerDes
	 * versions by ID alone, as some Copper devices (e.g. some but not
	 * all 5703Cs) have the same ID as the SerDes equivalents.  So we
	 * treat them the same here, and the MII code works out the media
	 * type later on ...
	 */
	cidp->mbuf_base = bge_mbuf_pool_base;
	cidp->mbuf_length = bge_mbuf_pool_len;
	cidp->recv_slots = BGE_RECV_SLOTS_USED;
	cidp->bge_dma_rwctrl = bge_dma_rwctrl;
	cidp->pci_type = BGE_PCI_X;
	cidp->statistic_type = BGE_STAT_BLK;
	cidp->mbuf_lo_water_rdma = bge_mbuf_lo_water_rdma;
	cidp->mbuf_lo_water_rmac = bge_mbuf_lo_water_rmac;
	cidp->mbuf_hi_water = bge_mbuf_hi_water;
	cidp->rx_ticks_norm = bge_rx_ticks_norm;
	cidp->rx_count_norm = bge_rx_count_norm;
	cidp->tx_ticks_norm = bge_tx_ticks_norm;
	cidp->tx_count_norm = bge_tx_count_norm;
	cidp->mask_pci_int = MHCR_MASK_PCI_INT_OUTPUT;

	if (cidp->rx_rings == 0 || cidp->rx_rings > BGE_RECV_RINGS_MAX)
		cidp->rx_rings = BGE_RECV_RINGS_DEFAULT;
	if (cidp->tx_rings == 0 || cidp->tx_rings > BGE_SEND_RINGS_MAX)
		cidp->tx_rings = BGE_SEND_RINGS_DEFAULT;

	cidp->msi_enabled = B_FALSE;

	switch (cidp->device) {
	case DEVICE_ID_5717:
	case DEVICE_ID_5718:
	case DEVICE_ID_5719:
	case DEVICE_ID_5720:
	case DEVICE_ID_5724:
	case DEVICE_ID_5725:
	case DEVICE_ID_5727:
		if (cidp->device == DEVICE_ID_5717) {
			cidp->chip_label = 5717;
		} else if (cidp->device == DEVICE_ID_5718) {
			cidp->chip_label = 5718;
		} else if (cidp->device == DEVICE_ID_5719) {
			cidp->chip_label = 5719;
		} else if (cidp->device == DEVICE_ID_5720) {
			if (pci_config_get16(bgep->cfg_handle, PCI_CONF_DEVID) ==
			    DEVICE_ID_5717_C0) {
				cidp->chip_label = 5717;
			} else {
				cidp->chip_label = 5720;
			}
		} else if (cidp->device == DEVICE_ID_5724) {
			cidp->chip_label = 5724;
		} else if (cidp->device == DEVICE_ID_5725) {
			cidp->chip_label = 5725;
		} else /* (cidp->device == DEVICE_ID_5727) */ {
			cidp->chip_label = 5727;
		}
		cidp->msi_enabled = bge_enable_msi;
#ifdef __sparc
		cidp->mask_pci_int = LE_32(MHCR_MASK_PCI_INT_OUTPUT);
#endif
		cidp->bge_dma_rwctrl = LE_32(PDRWCR_VAR_5717);
		cidp->pci_type = BGE_PCI_E;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5717;
		cidp->mbuf_hi_water = MBUF_HIWAT_5717;
		cidp->mbuf_base = bge_mbuf_pool_base_5705;
		cidp->mbuf_length = bge_mbuf_pool_len_5705;
		cidp->recv_slots = BGE_RECV_SLOTS_5705;
		cidp->bge_mlcr_default = MLCR_DEFAULT_5717;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5700:
	case DEVICE_ID_5700x:
		cidp->chip_label = 5700;
		cidp->flags |= CHIP_FLAG_PARTIAL_CSUM;
		break;

	case DEVICE_ID_5701:
		cidp->chip_label = 5701;
		dev_ok = B_TRUE;
		cidp->flags |= CHIP_FLAG_PARTIAL_CSUM;
		break;

	case DEVICE_ID_5702:
	case DEVICE_ID_5702fe:
		cidp->chip_label = 5702;
		dev_ok = B_TRUE;
		cidp->flags |= CHIP_FLAG_PARTIAL_CSUM;
		cidp->pci_type = BGE_PCI;
		break;

	case DEVICE_ID_5703C:
	case DEVICE_ID_5703S:
	case DEVICE_ID_5703:
		/*
		 * Revision A0 of the 5703/5793 had various errata
		 * that we can't or don't work around, so it's not
		 * supported, but all later versions are
		 */
		cidp->chip_label = cidp->subven == VENDOR_ID_SUN ? 5793 : 5703;
		if (bgep->chipid.asic_rev != MHCR_CHIP_REV_5703_A0)
			dev_ok = B_TRUE;
		cidp->flags |= CHIP_FLAG_PARTIAL_CSUM;
		break;

	case DEVICE_ID_5704C:
	case DEVICE_ID_5704S:
	case DEVICE_ID_5704:
		cidp->chip_label = cidp->subven == VENDOR_ID_SUN ? 5794 : 5704;
		cidp->mbuf_base = bge_mbuf_pool_base_5704;
		cidp->mbuf_length = bge_mbuf_pool_len_5704;
		dev_ok = B_TRUE;
		cidp->flags |= CHIP_FLAG_PARTIAL_CSUM;
		break;

	case DEVICE_ID_5705C:
	case DEVICE_ID_5705M:
	case DEVICE_ID_5705MA3:
	case DEVICE_ID_5705F:
	case DEVICE_ID_5705_2:
	case DEVICE_ID_5754:
		if (cidp->device == DEVICE_ID_5754) {
			cidp->chip_label = 5754;
			cidp->pci_type = BGE_PCI_E;
		} else {
			cidp->chip_label = 5705;
			cidp->pci_type = BGE_PCI;
			cidp->flags |= CHIP_FLAG_PARTIAL_CSUM;
		}
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5705;
		cidp->mbuf_length = bge_mbuf_pool_len_5705;
		cidp->recv_slots = BGE_RECV_SLOTS_5705;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5906:
	case DEVICE_ID_5906M:
		cidp->chip_label = 5906;
		cidp->pci_type = BGE_PCI_E;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5906;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5906;
		cidp->mbuf_hi_water = MBUF_HIWAT_5906;
		cidp->mbuf_base = bge_mbuf_pool_base;
		cidp->mbuf_length = bge_mbuf_pool_len;
		cidp->recv_slots = BGE_RECV_SLOTS_5705;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5753:
		cidp->chip_label = 5753;
		cidp->pci_type = BGE_PCI_E;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5705;
		cidp->mbuf_length = bge_mbuf_pool_len_5705;
		cidp->recv_slots = BGE_RECV_SLOTS_5705;
		cidp->bge_mlcr_default |= MLCR_MISC_PINS_OUTPUT_ENABLE_1;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5755:
	case DEVICE_ID_5755M:
		cidp->chip_label = 5755;
		cidp->pci_type = BGE_PCI_E;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5705;
		cidp->mbuf_length = bge_mbuf_pool_len_5705;
		cidp->recv_slots = BGE_RECV_SLOTS_5705;
		cidp->bge_mlcr_default |= MLCR_MISC_PINS_OUTPUT_ENABLE_1;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		if (cidp->device == DEVICE_ID_5755M)
			cidp->flags |= CHIP_FLAG_PARTIAL_CSUM;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5756M:
		/*
		 * This is nearly identical to the 5755M.
		 * (Actually reports the 5755 chip ID.)
		 */
		cidp->chip_label = 5756;
		cidp->pci_type = BGE_PCI_E;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5705;
		cidp->mbuf_length = bge_mbuf_pool_len_5705;
		cidp->recv_slots = BGE_RECV_SLOTS_5705;
		cidp->bge_mlcr_default |= MLCR_MISC_PINS_OUTPUT_ENABLE_1;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5787:
	case DEVICE_ID_5787M:
		cidp->chip_label = 5787;
		cidp->pci_type = BGE_PCI_E;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5705;
		cidp->mbuf_length = bge_mbuf_pool_len_5705;
		cidp->recv_slots = BGE_RECV_SLOTS_5705;
		cidp->bge_mlcr_default |= MLCR_MISC_PINS_OUTPUT_ENABLE_1;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5723:
	case DEVICE_ID_5761:
	case DEVICE_ID_5761E:
	case DEVICE_ID_57780:
		cidp->msi_enabled = bge_enable_msi;
		/*
		 * We don't use MSI for BCM5764 and BCM5785, as the
		 * status block may fail to update when the network
		 * traffic is heavy.
		 */
		/* FALLTHRU */
	case DEVICE_ID_5785:
	case DEVICE_ID_5764:
		if (cidp->device == DEVICE_ID_5723)
			cidp->chip_label = 5723;
		else if (cidp->device == DEVICE_ID_5764)
			cidp->chip_label = 5764;
		else if (cidp->device == DEVICE_ID_5785)
			cidp->chip_label = 5785;
		else if (cidp->device == DEVICE_ID_57780)
			cidp->chip_label = 57780;
		else
			cidp->chip_label = 5761;
		cidp->bge_dma_rwctrl = bge_dma_rwctrl_5721;
		cidp->pci_type = BGE_PCI_E;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5705;
		cidp->mbuf_length = bge_mbuf_pool_len_5705;
		cidp->recv_slots = BGE_RECV_SLOTS_5705;
		cidp->bge_mlcr_default |= MLCR_MISC_PINS_OUTPUT_ENABLE_1;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	/* PCI-X device, identical to 5714 */
	case DEVICE_ID_5780:
		cidp->chip_label = 5780;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5721;
		cidp->mbuf_length = bge_mbuf_pool_len_5721;
		cidp->recv_slots = BGE_RECV_SLOTS_5721;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5782:
		/*
		 * Apart from the label, we treat this as a 5705(?)
		 */
		cidp->chip_label = 5782;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5705;
		cidp->mbuf_length = bge_mbuf_pool_len_5705;
		cidp->recv_slots = BGE_RECV_SLOTS_5705;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		cidp->flags |= CHIP_FLAG_PARTIAL_CSUM;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5788:
		/*
		 * Apart from the label, we treat this as a 5705(?)
		 */
		cidp->chip_label = 5788;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5705;
		cidp->mbuf_length = bge_mbuf_pool_len_5705;
		cidp->recv_slots = BGE_RECV_SLOTS_5705;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->statistic_type = BGE_STAT_REG;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5714C:
		if (cidp->revision >= REVISION_ID_5714_A2)
			cidp->msi_enabled = bge_enable_msi;
		/* FALLTHRU */
	case DEVICE_ID_5714S:
		cidp->chip_label = 5714;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5721;
		cidp->mbuf_length = bge_mbuf_pool_len_5721;
		cidp->recv_slots = BGE_RECV_SLOTS_5721;
		cidp->bge_dma_rwctrl = bge_dma_rwctrl_5714;
		cidp->bge_mlcr_default = bge_mlcr_default_5714;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->pci_type = BGE_PCI_E;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5715C:
	case DEVICE_ID_5715S:
		cidp->chip_label = 5715;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5721;
		cidp->mbuf_length = bge_mbuf_pool_len_5721;
		cidp->recv_slots = BGE_RECV_SLOTS_5721;
		cidp->bge_dma_rwctrl = bge_dma_rwctrl_5715;
		cidp->bge_mlcr_default = bge_mlcr_default_5714;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->pci_type = BGE_PCI_E;
		cidp->statistic_type = BGE_STAT_REG;
		if (cidp->revision >= REVISION_ID_5715_A2)
			cidp->msi_enabled = bge_enable_msi;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5721:
		cidp->chip_label = 5721;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5721;
		cidp->mbuf_length = bge_mbuf_pool_len_5721;
		cidp->recv_slots = BGE_RECV_SLOTS_5721;
		cidp->bge_dma_rwctrl = bge_dma_rwctrl_5721;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->pci_type = BGE_PCI_E;
		cidp->statistic_type = BGE_STAT_REG;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5722:
		cidp->chip_label = 5722;
		cidp->pci_type = BGE_PCI_E;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5705;
		cidp->mbuf_length = bge_mbuf_pool_len_5705;
		cidp->recv_slots = BGE_RECV_SLOTS_5705;
		cidp->bge_mlcr_default |= MLCR_MISC_PINS_OUTPUT_ENABLE_1;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		cidp->statistic_type = BGE_STAT_REG;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5751:
	case DEVICE_ID_5751M:
		cidp->chip_label = 5751;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5721;
		cidp->mbuf_length = bge_mbuf_pool_len_5721;
		cidp->recv_slots = BGE_RECV_SLOTS_5721;
		cidp->bge_dma_rwctrl = bge_dma_rwctrl_5721;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->pci_type = BGE_PCI_E;
		cidp->statistic_type = BGE_STAT_REG;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5752:
	case DEVICE_ID_5752M:
		cidp->chip_label = 5752;
		cidp->mbuf_lo_water_rdma = RDMA_MBUF_LOWAT_5705;
		cidp->mbuf_lo_water_rmac = MAC_RX_MBUF_LOWAT_5705;
		cidp->mbuf_hi_water = MBUF_HIWAT_5705;
		cidp->mbuf_base = bge_mbuf_pool_base_5721;
		cidp->mbuf_length = bge_mbuf_pool_len_5721;
		cidp->recv_slots = BGE_RECV_SLOTS_5721;
		cidp->bge_dma_rwctrl = bge_dma_rwctrl_5721;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_SEND_RINGS_MAX_5705;
		cidp->pci_type = BGE_PCI_E;
		cidp->statistic_type = BGE_STAT_REG;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		dev_ok = B_TRUE;
		break;

	case DEVICE_ID_5789:
		cidp->chip_label = 5789;
		cidp->mbuf_base = bge_mbuf_pool_base_5721;
		cidp->mbuf_length = bge_mbuf_pool_len_5721;
		cidp->recv_slots = BGE_RECV_SLOTS_5721;
		cidp->bge_dma_rwctrl = bge_dma_rwctrl_5721;
		cidp->rx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->tx_rings = BGE_RECV_RINGS_MAX_5705;
		cidp->pci_type = BGE_PCI_E;
		cidp->statistic_type = BGE_STAT_REG;
		cidp->flags |= CHIP_FLAG_PARTIAL_CSUM;
		cidp->flags |= CHIP_FLAG_NO_JUMBO;
		cidp->msi_enabled = B_TRUE;
		dev_ok = B_TRUE;
		break;

	}

	/*
	 * Setup the default jumbo parameter.
	 */
	cidp->ethmax_size = ETHERMAX;
	cidp->snd_buff_size = BGE_SEND_BUFF_SIZE_DEFAULT;
	cidp->std_buf_size = BGE_STD_BUFF_SIZE;

	/*
	 * If jumbo is enabled and this kind of chipset supports jumbo feature,
	 * setup below jumbo specific parameters.
	 *
	 * For BCM5714/5715, there is only one standard receive ring. So the
	 * std buffer size should be set to BGE_JUMBO_BUFF_SIZE when jumbo
	 * feature is enabled.
	 *
	 * For the BCM5718 family we hijack the standard receive ring for
	 * the jumboframe traffic, keeps it simple.
	 */
	if (!(cidp->flags & CHIP_FLAG_NO_JUMBO) &&
	    (cidp->default_mtu > BGE_DEFAULT_MTU)) {
		if (DEVICE_5714_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
			cidp->mbuf_lo_water_rdma =
			    RDMA_MBUF_LOWAT_5714_JUMBO;
			cidp->mbuf_lo_water_rmac =
			    MAC_RX_MBUF_LOWAT_5714_JUMBO;
			cidp->mbuf_hi_water = MBUF_HIWAT_5714_JUMBO;
			cidp->jumbo_slots = 0;
			cidp->std_buf_size = BGE_JUMBO_BUFF_SIZE;
		} else {
			cidp->mbuf_lo_water_rdma =
			    RDMA_MBUF_LOWAT_JUMBO;
			cidp->mbuf_lo_water_rmac =
			    MAC_RX_MBUF_LOWAT_JUMBO;
			cidp->mbuf_hi_water = MBUF_HIWAT_JUMBO;
			cidp->jumbo_slots = BGE_JUMBO_SLOTS_USED;
		}
		cidp->recv_jumbo_size = BGE_JUMBO_BUFF_SIZE;
		cidp->snd_buff_size = BGE_SEND_BUFF_SIZE_JUMBO;
		cidp->ethmax_size = cidp->default_mtu +
		    sizeof (struct ether_header);
	}

	/*
	 * Identify the NV memory type: SEEPROM or Flash?
	 */
	cidp->nvtype = bge_nvmem_id(bgep);

	/*
	 * Now check what we've discovered: is this truly a supported
	 * chip on (the motherboard of) a supported platform?
	 *
	 * Possible problems here:
	 * 1)	it's a completely unheard-of chip
	 * 2)	it's a recognised but unsupported chip (e.g. 5701, 5703C-A0)
	 * 3)	it's a chip we would support if it were on the motherboard
	 *	of a Sun platform, but this one isn't ;-(
	 */
	if (cidp->chip_label == 0)
		bge_problem(bgep,
		    "Device 'pci%04x,%04x' not recognized (%d?)",
		    cidp->vendor, cidp->device, cidp->device);
	else if (!dev_ok)
		bge_problem(bgep,
		    "Device 'pci%04x,%04x' (%d) revision %d not supported",
		    cidp->vendor, cidp->device, cidp->chip_label,
		    cidp->revision);
	else
		cidp->flags |= CHIP_FLAG_SUPPORTED;

	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
		return (EIO);

	return (0);
}

void
bge_chip_msi_trig(bge_t *bgep)
{
	uint32_t	regval;

	regval = bgep->param_msi_cnt<<4;
	bge_reg_set32(bgep, HOST_COALESCE_MODE_REG, regval);
	BGE_DEBUG(("bge_chip_msi_trig:data = %d", regval));
}

/*
 * Various registers that control the chip's internal engines (state
 * machines) have a <reset> and <enable> bits (fortunately, in the
 * same place in each such register :-).
 *
 * To reset the state machine, the <reset> bit must be written with 1;
 * it will then read back as 1 while the reset is in progress, but
 * self-clear to 0 when the reset completes.
 *
 * To enable a state machine, one must set the <enable> bit, which
 * will continue to read back as 0 until the state machine is running.
 *
 * To disable a state machine, the <enable> bit must be cleared, but
 * it will continue to read back as 1 until the state machine actually
 * stops.
 *
 * This routine implements polling for completion of a reset, enable
 * or disable operation, returning B_TRUE on success (bit reached the
 * required state) or B_FALSE on timeout (200*100us == 20ms).
 */
static boolean_t bge_chip_poll_engine(bge_t *bgep, bge_regno_t regno,
					uint32_t mask, uint32_t val);
#pragma	no_inline(bge_chip_poll_engine)

static boolean_t
bge_chip_poll_engine(bge_t *bgep, bge_regno_t regno,
	uint32_t mask, uint32_t val)
{
	uint32_t regval;
	uint32_t n;

	BGE_TRACE(("bge_chip_poll_engine($%p, 0x%lx, 0x%x, 0x%x)",
	    (void *)bgep, regno, mask, val));

	for (n = 200; n; --n) {
		regval = bge_reg_get32(bgep, regno);
		if ((regval & mask) == val)
			return (B_TRUE);
		drv_usecwait(100);
	}

	bge_problem(bgep, "bge_chip_poll_engine failed: regno = 0x%lx", regno);
	bge_fm_ereport(bgep, DDI_FM_DEVICE_NO_RESPONSE);
	return (B_FALSE);
}

/*
 * Various registers that control the chip's internal engines (state
 * machines) have a <reset> bit (fortunately, in the same place in
 * each such register :-).  To reset the state machine, this bit must
 * be written with 1; it will then read back as 1 while the reset is
 * in progress, but self-clear to 0 when the reset completes.
 *
 * This code sets the bit, then polls for it to read back as zero.
 * The return value is B_TRUE on success (reset bit cleared itself),
 * or B_FALSE if the state machine didn't recover :(
 *
 * NOTE: the Core reset is similar to other resets, except that we
 * can't poll for completion, since the Core reset disables memory
 * access!  So we just have to assume that it will all complete in
 * 100us.  See Broadcom document 570X-PG102-R, p102, steps 4-5.
 */
static boolean_t bge_chip_reset_engine(bge_t *bgep, bge_regno_t regno);
#pragma	no_inline(bge_chip_reset_engine)

static boolean_t
bge_chip_reset_engine(bge_t *bgep, bge_regno_t regno)
{
	uint32_t regval;
	uint16_t val16;
	uint32_t val32;
	uint32_t mhcr;

	regval = bge_reg_get32(bgep, regno);

	BGE_TRACE(("bge_chip_reset_engine($%p, 0x%lx)",
	    (void *)bgep, regno));
	BGE_DEBUG(("bge_chip_reset_engine: 0x%lx before reset = 0x%08x",
	    regno, regval));

	regval |= STATE_MACHINE_RESET_BIT;

	switch (regno) {
	case MISC_CONFIG_REG:
		/*
		 * BCM5714/5721/5751 pcie chip special case. In order to avoid
		 * resetting PCIE block and bringing PCIE link down, bit 29
		 * in the register needs to be set first, and then set it again
		 * while the reset bit is written.
		 * See:P500 of 57xx-PG102-RDS.pdf.
		 */
		if (DEVICE_5705_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5725_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5721_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5723_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5714_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5906_SERIES_CHIPSETS(bgep)) {
			regval |= MISC_CONFIG_GPHY_POWERDOWN_OVERRIDE;
			if (bgep->chipid.pci_type == BGE_PCI_E) {
				if (bgep->chipid.asic_rev ==
				    MHCR_CHIP_REV_5751_A0 ||
				    bgep->chipid.asic_rev ==
				    MHCR_CHIP_REV_5721_A0 ||
				    bgep->chipid.asic_rev ==
				    MHCR_CHIP_REV_5755_A0) {
					val32 = bge_reg_get32(bgep,
					    PHY_TEST_CTRL_REG);
					if (val32 == (PHY_PCIE_SCRAM_MODE |
					    PHY_PCIE_LTASS_MODE))
						bge_reg_put32(bgep,
						    PHY_TEST_CTRL_REG,
						    PHY_PCIE_SCRAM_MODE);
					val32 = pci_config_get32
					    (bgep->cfg_handle,
					    PCI_CONF_BGE_CLKCTL);
					val32 |= CLKCTL_PCIE_A0_FIX;
					pci_config_put32(bgep->cfg_handle,
					    PCI_CONF_BGE_CLKCTL, val32);
				}
				bge_reg_set32(bgep, regno,
				    MISC_CONFIG_GRC_RESET_DISABLE);
				regval |= MISC_CONFIG_GRC_RESET_DISABLE;
			}
		}

		/*
		 * Special case - causes Core reset
		 *
		 * On SPARC v9 we want to ensure that we don't start
		 * timing until the I/O access has actually reached
		 * the chip, otherwise we might make the next access
		 * too early.  And we can't just force the write out
		 * by following it with a read (even to config space)
		 * because that would cause the fault we're trying
		 * to avoid.  Hence the need for membar_sync() here.
		 */
		ddi_put32(bgep->io_handle, PIO_ADDR(bgep, regno), regval);
#ifdef	__sparcv9
		membar_sync();
#endif	/* __sparcv9 */
		/*
		 * On some platforms,system need about 300us for
		 * link setup.
		 */
		drv_usecwait(300);
		if (DEVICE_5906_SERIES_CHIPSETS(bgep)) {
			bge_reg_set32(bgep, VCPU_STATUS_REG, VCPU_DRV_RESET);
			bge_reg_clr32(
			    bgep, VCPU_EXT_CTL, VCPU_EXT_CTL_HALF);
		}

		if (bgep->chipid.pci_type == BGE_PCI_E) {
			/* PCI-E device need more reset time */
			drv_usecwait(120000);

			/*
			 * (re)Disable interrupts as the bit can be reset after a
			 * core clock reset.
			 */
			mhcr = pci_config_get32(bgep->cfg_handle, PCI_CONF_BGE_MHCR);
			pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MHCR,
			    mhcr | MHCR_MASK_PCI_INT_OUTPUT);

			/* Set PCIE max payload size and clear error status. */
			if ((bgep->chipid.chip_label == 5721) ||
			    (bgep->chipid.chip_label == 5751) ||
			    (bgep->chipid.chip_label == 5752) ||
			    (bgep->chipid.chip_label == 5789) ||
			    (bgep->chipid.chip_label == 5906)) {
				pci_config_put16(bgep->cfg_handle,
				    PCI_CONF_DEV_CTRL, READ_REQ_SIZE_MAX);
				pci_config_put16(bgep->cfg_handle,
				    PCI_CONF_DEV_STUS, DEVICE_ERROR_STUS);
			}

			if ((bgep->chipid.chip_label == 5723) ||
			    (bgep->chipid.chip_label == 5761)) {
				pci_config_put16(bgep->cfg_handle,
				    PCI_CONF_DEV_CTRL_5723, READ_REQ_SIZE_MAX);
				pci_config_put16(bgep->cfg_handle,
				    PCI_CONF_DEV_STUS_5723, DEVICE_ERROR_STUS);
			}

			if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
			    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
				val16 = pci_config_get16(bgep->cfg_handle,
				                         PCI_CONF_DEV_CTRL_5717);
				val16 &= ~READ_REQ_SIZE_MASK;
				val16 |= READ_REQ_SIZE_2K;
				pci_config_put16(bgep->cfg_handle,
				    PCI_CONF_DEV_CTRL_5717, val16);
			}
		}

		BGE_PCICHK(bgep);
		return (B_TRUE);

	default:
		bge_reg_put32(bgep, regno, regval);
		return (bge_chip_poll_engine(bgep, regno,
		    STATE_MACHINE_RESET_BIT, 0));
	}
}

/*
 * Various registers that control the chip's internal engines (state
 * machines) have an <enable> bit (fortunately, in the same place in
 * each such register :-).  To stop the state machine, this bit must
 * be written with 0, then polled to see when the state machine has
 * actually stopped.
 *
 * The return value is B_TRUE on success (enable bit cleared), or
 * B_FALSE if the state machine didn't stop :(
 */
static boolean_t bge_chip_disable_engine(bge_t *bgep, bge_regno_t regno,
						uint32_t morebits);
#pragma	no_inline(bge_chip_disable_engine)

static boolean_t
bge_chip_disable_engine(bge_t *bgep, bge_regno_t regno, uint32_t morebits)
{
	uint32_t regval;

	BGE_TRACE(("bge_chip_disable_engine($%p, 0x%lx, 0x%x)",
	    (void *)bgep, regno, morebits));

	switch (regno) {
	case FTQ_RESET_REG:
		/*
		 * For Schumacher's bugfix CR6490108
		 */
#ifdef BGE_IPMI_ASF
#ifdef BGE_NETCONSOLE
		if (bgep->asf_enabled)
			return (B_TRUE);
#endif
#endif
		/*
		 * Not quite like the others; it doesn't
		 * have an <enable> bit, but instead we
		 * have to set and then clear all the bits
		 */
		bge_reg_put32(bgep, regno, ~(uint32_t)0);
		drv_usecwait(100);
		bge_reg_put32(bgep, regno, 0);
		return (B_TRUE);

	default:
		if (DEVICE_5704_SERIES_CHIPSETS(bgep)) {
			break;
		}

		if ((regno == RCV_LIST_SELECTOR_MODE_REG) ||
		    (regno == DMA_COMPLETION_MODE_REG) ||
		    (regno == MBUF_CLUSTER_FREE_MODE_REG) ||
		    (regno == BUFFER_MANAGER_MODE_REG) ||
		    (regno == MEMORY_ARBITER_MODE_REG)) {
			return B_TRUE;
		}

		break;
	}

	regval = bge_reg_get32(bgep, regno);
	regval &= ~STATE_MACHINE_ENABLE_BIT;
	regval &= ~morebits;
	bge_reg_put32(bgep, regno, regval);

	return bge_chip_poll_engine(bgep, regno, STATE_MACHINE_ENABLE_BIT, 0);
}

/*
 * Various registers that control the chip's internal engines (state
 * machines) have an <enable> bit (fortunately, in the same place in
 * each such register :-).  To start the state machine, this bit must
 * be written with 1, then polled to see when the state machine has
 * actually started.
 *
 * The return value is B_TRUE on success (enable bit set), or
 * B_FALSE if the state machine didn't start :(
 */
static boolean_t bge_chip_enable_engine(bge_t *bgep, bge_regno_t regno,
					uint32_t morebits);
#pragma	no_inline(bge_chip_enable_engine)

static boolean_t
bge_chip_enable_engine(bge_t *bgep, bge_regno_t regno, uint32_t morebits)
{
	uint32_t regval;

	BGE_TRACE(("bge_chip_enable_engine($%p, 0x%lx, 0x%x)",
	    (void *)bgep, regno, morebits));

	switch (regno) {
	case FTQ_RESET_REG:
#ifdef BGE_IPMI_ASF
#ifdef BGE_NETCONSOLE
		if (bgep->asf_enabled)
			return (B_TRUE);
#endif
#endif
		/*
		 * Not quite like the others; it doesn't
		 * have an <enable> bit, but instead we
		 * have to set and then clear all the bits
		 */
		bge_reg_put32(bgep, regno, ~(uint32_t)0);
		drv_usecwait(100);
		bge_reg_put32(bgep, regno, 0);
		return (B_TRUE);

	default:
		regval = bge_reg_get32(bgep, regno);
		regval |= STATE_MACHINE_ENABLE_BIT;
		regval |= morebits;
		bge_reg_put32(bgep, regno, regval);
		return (bge_chip_poll_engine(bgep, regno,
		    STATE_MACHINE_ENABLE_BIT, STATE_MACHINE_ENABLE_BIT));
	}
}

/*
 * Reprogram the Ethernet, Transmit, and Receive MAC
 * modes to match the param_* variables
 */
void bge_sync_mac_modes(bge_t *bgep);
#pragma	no_inline(bge_sync_mac_modes)

void
bge_sync_mac_modes(bge_t *bgep)
{
	uint32_t macmode;
	uint32_t regval;

	ASSERT(mutex_owned(bgep->genlock));

	/*
	 * Reprogram the Ethernet MAC mode ...
	 */
	macmode = regval = bge_reg_get32(bgep, ETHERNET_MAC_MODE_REG);
	macmode &= ~ETHERNET_MODE_LINK_POLARITY;
	macmode &= ~ETHERNET_MODE_PORTMODE_MASK;
	if ((bgep->chipid.flags & CHIP_FLAG_SERDES) &&
	    (bgep->param_loop_mode != BGE_LOOP_INTERNAL_MAC)) {
		if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5725_SERIES_CHIPSETS(bgep) ||
		    DEVICE_5714_SERIES_CHIPSETS(bgep))
			macmode |= ETHERNET_MODE_PORTMODE_GMII;
		else
			macmode |= ETHERNET_MODE_PORTMODE_TBI;
	} else if (bgep->param_link_speed == 10 ||
	    bgep->param_link_speed == 100)
		macmode |= ETHERNET_MODE_PORTMODE_MII;
	else
		macmode |= ETHERNET_MODE_PORTMODE_GMII;
	if (bgep->param_link_duplex == LINK_DUPLEX_HALF)
		macmode |= ETHERNET_MODE_HALF_DUPLEX;
	else
		macmode &= ~ETHERNET_MODE_HALF_DUPLEX;
	if (bgep->param_loop_mode == BGE_LOOP_INTERNAL_MAC)
		macmode |= ETHERNET_MODE_MAC_LOOPBACK;
	else
		macmode &= ~ETHERNET_MODE_MAC_LOOPBACK;
	bge_reg_put32(bgep, ETHERNET_MAC_MODE_REG, macmode);
	BGE_DEBUG(("bge_sync_mac_modes($%p) Ethernet MAC mode 0x%x => 0x%x",
	    (void *)bgep, regval, macmode));

	/*
	 * ... the Transmit MAC mode ...
	 */
	macmode = regval = bge_reg_get32(bgep, TRANSMIT_MAC_MODE_REG);
	if (bgep->param_link_tx_pause)
		macmode |= TRANSMIT_MODE_FLOW_CONTROL;
	else
		macmode &= ~TRANSMIT_MODE_FLOW_CONTROL;
	bge_reg_put32(bgep, TRANSMIT_MAC_MODE_REG, macmode);
	BGE_DEBUG(("bge_sync_mac_modes($%p) Transmit MAC mode 0x%x => 0x%x",
	    (void *)bgep, regval, macmode));

	/*
	 * ... and the Receive MAC mode
	 */
	macmode = regval = bge_reg_get32(bgep, RECEIVE_MAC_MODE_REG);
	if (bgep->param_link_rx_pause)
		macmode |= RECEIVE_MODE_FLOW_CONTROL;
	else
		macmode &= ~RECEIVE_MODE_FLOW_CONTROL;
	bge_reg_put32(bgep, RECEIVE_MAC_MODE_REG, macmode);
	BGE_DEBUG(("bge_sync_mac_modes($%p) Receive MAC mode 0x%x => 0x%x",
	    (void *)bgep, regval, macmode));

	/*
	 * For BCM5785, we need to configure the link status in the MI Status
	 * register with a write command when auto-polling is disabled.
	 */
	if (bgep->chipid.device == DEVICE_ID_5785)
		if (bgep->param_link_speed == 10)
			bge_reg_put32(bgep, MI_STATUS_REG, MI_STATUS_LINK
			    | MI_STATUS_10MBPS);
		else
			bge_reg_put32(bgep, MI_STATUS_REG, MI_STATUS_LINK);
}

/*
 * bge_chip_sync() -- program the chip with the unicast MAC address,
 * the multicast hash table, the required level of promiscuity, and
 * the current loopback mode ...
 */
#ifdef BGE_IPMI_ASF
int bge_chip_sync(bge_t *bgep, boolean_t asf_keeplive);
#else
int bge_chip_sync(bge_t *bgep);
#endif
#pragma	no_inline(bge_chip_sync)

int
#ifdef BGE_IPMI_ASF
bge_chip_sync(bge_t *bgep, boolean_t asf_keeplive)
#else
bge_chip_sync(bge_t *bgep)
#endif
{
	void (*opfn)(bge_t *bgep, bge_regno_t reg, uint32_t bits);
	boolean_t promisc;
	uint64_t macaddr;
	uint32_t fill = 0;
	int i, j;
	int retval = DDI_SUCCESS;

	BGE_TRACE(("bge_chip_sync($%p)",
	    (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

	promisc = B_FALSE;
	fill = ~(uint32_t)0;

	if (bgep->promisc)
		promisc = B_TRUE;
	else
		fill = (uint32_t)0;

	/*
	 * If the TX/RX MAC engines are already running, we should stop
	 * them (and reset the RX engine) before changing the parameters.
	 * If they're not running, this will have no effect ...
	 *
	 * NOTE: this is currently disabled by default because stopping
	 * and restarting the Tx engine may cause an outgoing packet in
	 * transit to be truncated.  Also, stopping and restarting the
	 * Rx engine seems to not work correctly on the 5705.  Testing
	 * has not (yet!) revealed any problems with NOT stopping and
	 * restarting these engines (and Broadcom say their drivers don't
	 * do this), but if it is found to cause problems, this variable
	 * can be patched to re-enable the old behaviour ...
	 */
	if (bge_stop_start_on_sync) {
#ifdef BGE_IPMI_ASF
		if (!bgep->asf_enabled) {
			if (!bge_chip_disable_engine(bgep,
			    RECEIVE_MAC_MODE_REG, RECEIVE_MODE_KEEP_VLAN_TAG))
				retval = DDI_FAILURE;
		} else {
			if (!bge_chip_disable_engine(bgep,
			    RECEIVE_MAC_MODE_REG, 0))
				retval = DDI_FAILURE;
		}
#else
		if (!bge_chip_disable_engine(bgep, RECEIVE_MAC_MODE_REG,
		    RECEIVE_MODE_KEEP_VLAN_TAG))
			retval = DDI_FAILURE;
#endif
		if (!bge_chip_disable_engine(bgep, TRANSMIT_MAC_MODE_REG, 0))
			retval = DDI_FAILURE;
		if (!bge_chip_reset_engine(bgep, RECEIVE_MAC_MODE_REG))
			retval = DDI_FAILURE;
	}

	/*
	 * Reprogram the hashed multicast address table ...
	 */
	for (i = 0; i < BGE_HASH_TABLE_SIZE/32; ++i)
		bge_reg_put32(bgep, MAC_HASH_REG(i), 0);

	for (i = 0; i < BGE_HASH_TABLE_SIZE/32; ++i)
		bge_reg_put32(bgep, MAC_HASH_REG(i),
			bgep->mcast_hash[i] | fill);

#ifdef BGE_IPMI_ASF
	if (!bgep->asf_enabled || !asf_keeplive) {
#endif
		/*
		 * Transform the MAC address(es) from host to chip format, then
		 * reprogram the transmit random backoff seed and the unicast
		 * MAC address(es) ...
		 */
		for (j = 0; j < MAC_ADDRESS_REGS_MAX; j++) {
			for (i = 0, macaddr = 0ull;
			    i < ETHERADDRL; ++i) {
				macaddr <<= 8;
				macaddr |= bgep->curr_addr[j].addr[i];
			}
			fill += (macaddr >> 16) + (macaddr & 0xffffffff);
			bge_reg_put64(bgep, MAC_ADDRESS_REG(j), macaddr);

			BGE_DEBUG(("bge_chip_sync($%p) "
			    "setting MAC address %012llx",
			    (void *)bgep, macaddr));
		}
#ifdef BGE_IPMI_ASF
	}
#endif
	/*
	 * Set random seed of backoff interval
	 *   - Writing zero means no backoff interval
	 */
	fill = ((fill >> 20) + (fill >> 10) + fill) & 0x3ff;
	if (fill == 0)
		fill = 1;
	bge_reg_put32(bgep, MAC_TX_RANDOM_BACKOFF_REG, fill);

	/*
	 * Set or clear the PROMISCUOUS mode bit
	 */
	opfn = promisc ? bge_reg_set32 : bge_reg_clr32;
	(*opfn)(bgep, RECEIVE_MAC_MODE_REG, RECEIVE_MODE_PROMISCUOUS);

	/*
	 * Sync the rest of the MAC modes too ...
	 */
	bge_sync_mac_modes(bgep);

	/*
	 * Restart RX/TX MAC engines if required ...
	 */
	if (bgep->bge_chip_state == BGE_CHIP_RUNNING) {
		if (!bge_chip_enable_engine(bgep, TRANSMIT_MAC_MODE_REG, 0))
			retval = DDI_FAILURE;
#ifdef BGE_IPMI_ASF
		if (!bgep->asf_enabled) {
			if (!bge_chip_enable_engine(bgep,
			    RECEIVE_MAC_MODE_REG, RECEIVE_MODE_KEEP_VLAN_TAG))
				retval = DDI_FAILURE;
		} else {
			if (!bge_chip_enable_engine(bgep,
			    RECEIVE_MAC_MODE_REG, 0))
				retval = DDI_FAILURE;
		}
#else
		if (!bge_chip_enable_engine(bgep, RECEIVE_MAC_MODE_REG,
		    RECEIVE_MODE_KEEP_VLAN_TAG))
			retval = DDI_FAILURE;
#endif
	}
	return (retval);
}

#ifndef __sparc
static bge_regno_t quiesce_regs[] = {
	READ_DMA_MODE_REG,
	DMA_COMPLETION_MODE_REG,
	WRITE_DMA_MODE_REG,
	BGE_REGNO_NONE
};

void bge_chip_stop_nonblocking(bge_t *bgep);
#pragma no_inline(bge_chip_stop_nonblocking)

/*
 * This function is called by bge_quiesce(). We
 * turn off all the DMA engines here.
 */
void
bge_chip_stop_nonblocking(bge_t *bgep)
{
	bge_regno_t *rbp;

	/*
	 * Flag that no more activity may be initiated
	 */
	bgep->progress &= ~PROGRESS_READY;

	rbp = quiesce_regs;
	while (*rbp != BGE_REGNO_NONE) {
		(void) bge_chip_disable_engine(bgep, *rbp, 0);
		++rbp;
	}

	bgep->bge_chip_state = BGE_CHIP_STOPPED;
}

#endif

/*
 * bge_chip_stop() -- stop all chip processing
 *
 * If the <fault> parameter is B_TRUE, we're stopping the chip because
 * we've detected a problem internally; otherwise, this is a normal
 * (clean) stop (at user request i.e. the last STREAM has been closed).
 */
void bge_chip_stop(bge_t *bgep, boolean_t fault);
#pragma	no_inline(bge_chip_stop)

void
bge_chip_stop(bge_t *bgep, boolean_t fault)
{
	bge_regno_t regno;
	bge_regno_t *rbp;
	boolean_t ok = B_TRUE;

	BGE_TRACE(("bge_chip_stop($%p)",
	    (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));

	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MHCR,
	    (pci_config_get32(bgep->cfg_handle, PCI_CONF_BGE_MHCR) |
	     MHCR_MASK_PCI_INT_OUTPUT));

	ok &= bge_chip_disable_engine(bgep, RECEIVE_MAC_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, RCV_BD_INITIATOR_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, RCV_LIST_PLACEMENT_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, RCV_LIST_SELECTOR_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, RCV_DATA_BD_INITIATOR_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, RCV_DATA_COMPLETION_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, RCV_BD_COMPLETION_MODE_REG, 0);

	ok &= bge_chip_disable_engine(bgep, SEND_BD_SELECTOR_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, SEND_BD_INITIATOR_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, SEND_DATA_INITIATOR_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, READ_DMA_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, SEND_DATA_COMPLETION_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, DMA_COMPLETION_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, SEND_BD_COMPLETION_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, TRANSMIT_MAC_MODE_REG, 0);

	bge_reg_clr32(bgep, ETHERNET_MAC_MODE_REG, ETHERNET_MODE_ENABLE_TDE);
	drv_usecwait(40);

	ok &= bge_chip_disable_engine(bgep, HOST_COALESCE_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, WRITE_DMA_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, MBUF_CLUSTER_FREE_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, FTQ_RESET_REG, 0);
	ok &= bge_chip_disable_engine(bgep, BUFFER_MANAGER_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, MEMORY_ARBITER_MODE_REG, 0);
	ok &= bge_chip_disable_engine(bgep, MEMORY_ARBITER_MODE_REG, 0);

	if (!ok && !fault)
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_UNAFFECTED);

	/*
	 * Finally, disable (all) MAC events & clear the MAC status
	 */
	bge_reg_put32(bgep, ETHERNET_MAC_EVENT_ENABLE_REG, 0);
	bge_reg_put32(bgep, ETHERNET_MAC_STATUS_REG, ~0);

	/*
	 * if we're stopping the chip because of a detected fault then do
	 * appropriate actions
	 */
	if (fault) {
		if (bgep->bge_chip_state != BGE_CHIP_FAULT) {
			bgep->bge_chip_state = BGE_CHIP_FAULT;
			if (!bgep->manual_reset)
				ddi_fm_service_impact(bgep->devinfo,
				    DDI_SERVICE_LOST);
			if (bgep->bge_dma_error) {
				/*
				 * need to free buffers in case the fault was
				 * due to a memory error in a buffer - got to
				 * do a fair bit of tidying first
				 */
				if (bgep->progress & PROGRESS_KSTATS) {
					bge_fini_kstats(bgep);
					bgep->progress &= ~PROGRESS_KSTATS;
				}
				if (bgep->progress & PROGRESS_INTR) {
					bge_intr_disable(bgep);
					rw_enter(bgep->errlock, RW_WRITER);
					bge_fini_rings(bgep);
					rw_exit(bgep->errlock);
					bgep->progress &= ~PROGRESS_INTR;
				}
				if (bgep->progress & PROGRESS_BUFS) {
					bge_free_bufs(bgep);
					bgep->progress &= ~PROGRESS_BUFS;
				}
				bgep->bge_dma_error = B_FALSE;
			}
		}
	} else
		bgep->bge_chip_state = BGE_CHIP_STOPPED;
}

/*
 * Poll for completion of chip's ROM firmware; also, at least on the
 * first time through, find and return the hardware MAC address, if any.
 */
static uint64_t bge_poll_firmware(bge_t *bgep);
#pragma	no_inline(bge_poll_firmware)

static uint64_t
bge_poll_firmware(bge_t *bgep)
{
	uint64_t magic;
	uint64_t mac;
	uint32_t gen, val;
	uint32_t i;

	/*
	 * Step 19: poll for firmware completion (GENCOMM port set
	 * to the ones complement of T3_MAGIC_NUMBER).
	 *
	 * While we're at it, we also read the MAC address register;
	 * at some stage the firmware will load this with the
	 * factory-set value.
	 *
	 * When both the magic number and the MAC address are set,
	 * we're done; but we impose a time limit of one second
	 * (1000*1000us) in case the firmware fails in some fashion
	 * or the SEEPROM that provides that MAC address isn't fitted.
	 *
	 * After the first time through (chip state != INITIAL), we
	 * don't need the MAC address to be set (we've already got it
	 * or not, from the first time), so we don't wait for it, but
	 * we still have to wait for the T3_MAGIC_NUMBER.
	 *
	 * Note: the magic number is only a 32-bit quantity, but the NIC
	 * memory is 64-bit (and big-endian) internally.  Addressing the
	 * GENCOMM word as "the upper half of a 64-bit quantity" makes
	 * it work correctly on both big- and little-endian hosts.
	 */
	if (MHCR_CHIP_ASIC_REV(bgep) == MHCR_CHIP_ASIC_REV_5906) {
		for (i = 0; i < 1000; ++i) {
			drv_usecwait(1000);
			val = bge_reg_get32(bgep, VCPU_STATUS_REG);
			if (val & VCPU_INIT_DONE)
				break;
		}
		BGE_DEBUG(("bge_poll_firmware($%p): return after %d loops",
		    (void *)bgep, i));
		mac = bge_reg_get64(bgep, MAC_ADDRESS_REG(0));
	} else {
		for (i = 0; i < 1000; ++i) {
			drv_usecwait(1000);
			gen = bge_nic_get64(bgep, NIC_MEM_GENCOMM) >> 32;
			if (i == 0 && DEVICE_5704_SERIES_CHIPSETS(bgep))
				drv_usecwait(100000);
			mac = bge_reg_get64(bgep, MAC_ADDRESS_REG(0));
#ifdef BGE_IPMI_ASF
			if (!bgep->asf_enabled) {
#endif
				if (gen != ~T3_MAGIC_NUMBER)
					continue;
#ifdef BGE_IPMI_ASF
			}
#endif
			if (mac != 0ULL)
				break;
			if (bgep->bge_chip_state != BGE_CHIP_INITIAL)
				break;
		}
	}

	magic = bge_nic_get64(bgep, NIC_MEM_GENCOMM);
	BGE_DEBUG(("bge_poll_firmware($%p): PXE magic 0x%x after %d loops",
	    (void *)bgep, gen, i));
	BGE_DEBUG(("bge_poll_firmware: MAC %016llx, GENCOMM %016llx",
	    mac, magic));

	return (mac);
}

/*
 * Maximum times of trying to get the NVRAM access lock
 * by calling bge_nvmem_acquire()
 */
#define	MAX_TRY_NVMEM_ACQUIRE	10000

#ifdef BGE_IPMI_ASF
int bge_chip_reset(bge_t *bgep, boolean_t enable_dma, uint_t asf_mode);
#else
int bge_chip_reset(bge_t *bgep, boolean_t enable_dma);
#endif
#pragma	no_inline(bge_chip_reset)

int
#ifdef BGE_IPMI_ASF
bge_chip_reset(bge_t *bgep, boolean_t enable_dma, uint_t asf_mode)
#else
bge_chip_reset(bge_t *bgep, boolean_t enable_dma)
#endif
{
	chip_id_t chipid;
	uint64_t mac;
	uint64_t magic;
	uint32_t tmp;
	uint32_t mhcr_base;
	uint32_t mhcr;
	uint32_t sx0;
	uint32_t i, tries;
#ifdef BGE_IPMI_ASF
	uint32_t mailbox;
#endif
	int retval = DDI_SUCCESS;

	BGE_TRACE(("bge_chip_reset($%p, %d)",
		(void *)bgep, enable_dma));

	ASSERT(mutex_owned(bgep->genlock));

	BGE_DEBUG(("bge_chip_reset($%p, %d): current state is %d",
		(void *)bgep, enable_dma, bgep->bge_chip_state));

	/*
	 * Do we need to stop the chip cleanly before resetting?
	 */
	switch (bgep->bge_chip_state) {
	default:
		_NOTE(NOTREACHED)
		return (DDI_FAILURE);

	case BGE_CHIP_INITIAL:
	case BGE_CHIP_STOPPED:
	case BGE_CHIP_RESET:
		break;

	case BGE_CHIP_RUNNING:
	case BGE_CHIP_ERROR:
	case BGE_CHIP_FAULT:
		bge_chip_stop(bgep, B_FALSE);
		break;
	}

	mhcr_base = MHCR_ENABLE_INDIRECT_ACCESS |
	            MHCR_ENABLE_PCI_STATE_RW |
	            MHCR_ENABLE_TAGGED_STATUS_MODE |
	            MHCR_MASK_INTERRUPT_MODE |
	            MHCR_MASK_PCI_INT_OUTPUT |
	            MHCR_CLEAR_INTERRUPT_INTA;

#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled) {
		mhcr = mhcr_base;
#ifdef _BIG_ENDIAN
		mhcr |= (MHCR_ENABLE_ENDIAN_WORD_SWAP |
		         MHCR_ENABLE_ENDIAN_BYTE_SWAP);
#endif
		pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MHCR, mhcr);

		bge_reg_put32(bgep, MEMORY_ARBITER_MODE_REG,
			bge_reg_get32(bgep, MEMORY_ARBITER_MODE_REG) |
			MEMORY_ARBITER_ENABLE);

		if (asf_mode == ASF_MODE_INIT) {
			bge_asf_pre_reset_operations(bgep, BGE_INIT_RESET);
		} else if (asf_mode == ASF_MODE_SHUTDOWN) {
			bge_asf_pre_reset_operations(bgep, BGE_SHUTDOWN_RESET);
		}
	}
#endif

	/*
	 * Adapted from Broadcom document 570X-PG102-R, pp 102-116.
	 * Updated to reflect Broadcom document 570X-PG104-R, pp 146-159.
	 *
	 * Before reset Core clock,it is
	 * also required to initialize the Memory Arbiter as specified in step9
	 * and Misc Host Control Register as specified in step-13
	 * Step 4-5: reset Core clock & wait for completion
	 * Steps 6-8: are done by bge_chip_cfg_init()
	 * put the T3_MAGIC_NUMBER into the GENCOMM port before reset
	 */
	if (!bge_chip_enable_engine(bgep, MEMORY_ARBITER_MODE_REG, 0))
		retval = DDI_FAILURE;

	mhcr = mhcr_base;
#ifdef _BIG_ENDIAN
	mhcr |= (MHCR_ENABLE_ENDIAN_WORD_SWAP |
	         MHCR_ENABLE_ENDIAN_BYTE_SWAP);
#endif
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MHCR, mhcr);

#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled)
		bgep->asf_wordswapped = B_FALSE;
#endif
	/*
	 * NVRAM Corruption Workaround
	 */
	for (tries = 0; tries < MAX_TRY_NVMEM_ACQUIRE; tries++)
		if (bge_nvmem_acquire(bgep) != EAGAIN)
			break;
	if (tries >= MAX_TRY_NVMEM_ACQUIRE)
		BGE_DEBUG(("%s: fail to acquire nvram lock",
			bgep->ifname));

	bge_ape_lock(bgep, BGE_APE_LOCK_GRC);

#ifdef BGE_IPMI_ASF
	if (!bgep->asf_enabled) {
#endif
		magic = (uint64_t)T3_MAGIC_NUMBER << 32;
		bge_nic_put64(bgep, NIC_MEM_GENCOMM, magic);
#ifdef BGE_IPMI_ASF
	}
#endif

	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		bge_reg_set32(bgep, FAST_BOOT_PC, 0);
		if (!bge_chip_enable_engine(bgep, MEMORY_ARBITER_MODE_REG, 0))
			retval = DDI_FAILURE;
	}

	mhcr = mhcr_base;
#ifdef _BIG_ENDIAN
	mhcr |= (MHCR_ENABLE_ENDIAN_WORD_SWAP |
	         MHCR_ENABLE_ENDIAN_BYTE_SWAP);
#endif
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MHCR, mhcr);

	if (!bge_chip_reset_engine(bgep, MISC_CONFIG_REG))
		retval = DDI_FAILURE;

	bge_chip_cfg_init(bgep, &chipid, enable_dma);

	/*
	 * Step 8a: This may belong elsewhere, but BCM5721 needs
	 * a bit set to avoid a fifo overflow/underflow bug.
	 */
	if ((bgep->chipid.chip_label == 5721) ||
		(bgep->chipid.chip_label == 5751) ||
		(bgep->chipid.chip_label == 5752) ||
		(bgep->chipid.chip_label == 5755) ||
		(bgep->chipid.chip_label == 5756) ||
		(bgep->chipid.chip_label == 5789) ||
		(bgep->chipid.chip_label == 5906))
		bge_reg_set32(bgep, TLP_CONTROL_REG, TLP_DATA_FIFO_PROTECT);

	/*
	 * Step 9: enable MAC memory arbiter,bit30 and bit31 of 5714/5715 should
	 * not be changed.
	 */
	if (!bge_chip_enable_engine(bgep, MEMORY_ARBITER_MODE_REG, 0))
		retval = DDI_FAILURE;

	/*
	 * Steps 10-11: configure PIO endianness options and
	 * enable indirect register access -- already done
	 * Steps 12-13: enable writing to the PCI state & clock
	 * control registers -- not required; we aren't going to
	 * use those features.
	 * Steps 14-15: Configure DMA endianness options.  See
	 * the comments on the setting of the MHCR above.
	 */
	tmp = MODE_WORD_SWAP_FRAME | MODE_BYTE_SWAP_FRAME;
#ifdef _BIG_ENDIAN
	tmp |= (MODE_WORD_SWAP_NONFRAME | MODE_BYTE_SWAP_NONFRAME);
#endif
#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled)
		tmp |= MODE_HOST_STACK_UP;
#endif
	bge_reg_put32(bgep, MODE_CONTROL_REG, tmp);

#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled) {
#ifdef __sparc
		bge_reg_put32(bgep, MEMORY_ARBITER_MODE_REG,
			MEMORY_ARBITER_ENABLE |
			bge_reg_get32(bgep, MEMORY_ARBITER_MODE_REG));
#endif

#ifdef  BGE_NETCONSOLE
		if (!bgep->asf_newhandshake) {
			if ((asf_mode == ASF_MODE_INIT) ||
			(asf_mode == ASF_MODE_POST_INIT)) {
				bge_asf_post_reset_old_mode(bgep,
					BGE_INIT_RESET);
			} else {
				bge_asf_post_reset_old_mode(bgep,
					BGE_SHUTDOWN_RESET);
			}
		}
#endif

		/* Wait for NVRAM init */
		i = 0;
		drv_usecwait(5000);
		mailbox = bge_nic_get32(bgep, BGE_FIRMWARE_MAILBOX);

		while ((mailbox != (uint32_t)
			~BGE_MAGIC_NUM_FIRMWARE_INIT_DONE) &&
			(i < 10000)) {
			drv_usecwait(100);
			mailbox = bge_nic_get32(bgep,
				BGE_FIRMWARE_MAILBOX);
			i++;
		}

#ifndef BGE_NETCONSOLE
		if (!bgep->asf_newhandshake) {
			if ((asf_mode == ASF_MODE_INIT) ||
				(asf_mode == ASF_MODE_POST_INIT)) {

				bge_asf_post_reset_old_mode(bgep,
					BGE_INIT_RESET);
			} else {
				bge_asf_post_reset_old_mode(bgep,
					BGE_SHUTDOWN_RESET);
			}
		}
#endif
	}
#endif

	bge_ape_unlock(bgep, BGE_APE_LOCK_GRC);

	/*
	 * Steps 16-17: poll for firmware completion
	 */
	mac = bge_poll_firmware(bgep);

	if (bgep->chipid.device == DEVICE_ID_5720) {
		tmp = bge_reg_get32(bgep, CPMU_CLCK_ORIDE_REG);
		bge_reg_put32(bgep, CPMU_CLCK_ORIDE_REG,
		              (tmp & ~CPMU_CLCK_ORIDE_MAC_ORIDE_EN));
	}

	/*
	 * Step 18: enable external memory -- doesn't apply.
	 *
	 * However we take the opportunity to set the MLCR anyway, as
	 * this register also controls the SEEPROM auto-access method
	 * which we may want to use later ...
	 *
	 * The proper value here depends on the way the chip is wired
	 * into the circuit board, as this register *also* controls which
	 * of the "Miscellaneous I/O" pins are driven as outputs and the
	 * values driven onto those pins!
	 *
	 * See also step 74 in the PRM ...
	 */
	bge_reg_put32(bgep, MISC_LOCAL_CONTROL_REG,
	    bgep->chipid.bge_mlcr_default);

	if ((bgep->chipid.flags & CHIP_FLAG_SERDES) &&
	    DEVICE_5714_SERIES_CHIPSETS(bgep)) {
		tmp = bge_reg_get32(bgep, SERDES_RX_CONTROL);
		tmp |= SERDES_RX_CONTROL_SIG_DETECT;
		bge_reg_put32(bgep, SERDES_RX_CONTROL, tmp);
	}

	bge_reg_set32(bgep, SERIAL_EEPROM_ADDRESS_REG, SEEPROM_ACCESS_INIT);

	/*
	 * Step 20: clear the Ethernet MAC mode register
	 */
	if (bgep->ape_enabled)
		bge_reg_put32(bgep, ETHERNET_MAC_MODE_REG,
		    ETHERNET_MODE_APE_TX_EN | ETHERNET_MODE_APE_RX_EN);
	else
		bge_reg_put32(bgep, ETHERNET_MAC_MODE_REG, 0);

	/*
	 * Step 21: restore cache-line-size, latency timer, and
	 * subsystem ID registers to their original values (not
	 * those read into the local structure <chipid>, 'cos
	 * that was after they were cleared by the RESET).
	 *
	 * Note: the Subsystem Vendor/Device ID registers are not
	 * directly writable in config space, so we use the shadow
	 * copy in "Page Zero" of register space to restore them
	 * both in one go ...
	 */
	pci_config_put8(bgep->cfg_handle, PCI_CONF_CACHE_LINESZ,
		bgep->chipid.clsize);
	pci_config_put8(bgep->cfg_handle, PCI_CONF_LATENCY_TIMER,
		bgep->chipid.latency);
	bge_reg_put32(bgep, PCI_CONF_SUBVENID,
		(bgep->chipid.subdev << 16) | bgep->chipid.subven);

	/*
	 * The SEND INDEX registers should be reset to zero by the
	 * global chip reset; if they're not, there'll be trouble
	 * later on.
	 */
	sx0 = bge_reg_get32(bgep, NIC_DIAG_SEND_INDEX_REG(0));
	if (sx0 != 0) {
		BGE_REPORT((bgep, "SEND INDEX - device didn't RESET"));
		bge_fm_ereport(bgep, DDI_FM_DEVICE_INVAL_STATE);
		retval = DDI_FAILURE;
	}

	/* Enable MSI code */
	if (bgep->intr_type == DDI_INTR_TYPE_MSI)
		bge_reg_set32(bgep, MSI_MODE_REG,
		    MSI_PRI_HIGHEST|MSI_MSI_ENABLE|MSI_ERROR_ATTENTION);

	/*
	 * On the first time through, save the factory-set MAC address
	 * (if any).  If bge_poll_firmware() above didn't return one
	 * (from a chip register) consider looking in the attached NV
	 * memory device, if any.  Once we have it, we save it in both
	 * register-image (64-bit) and byte-array forms.  All-zero and
	 * all-one addresses are not valid, and we refuse to stash those.
	 */
	if (bgep->bge_chip_state == BGE_CHIP_INITIAL) {
		if (mac == 0ULL)
			mac = bge_get_nvmac(bgep);
		if (mac != 0ULL && mac != ~0ULL) {
			bgep->chipid.hw_mac_addr = mac;
			for (i = ETHERADDRL; i-- != 0; ) {
				bgep->chipid.vendor_addr.addr[i] = (uchar_t)mac;
				mac >>= 8;
			}
			bgep->chipid.vendor_addr.set = B_TRUE;
		}
	}

#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled && bgep->asf_newhandshake) {
		if (asf_mode != ASF_MODE_NONE) {
			if ((asf_mode == ASF_MODE_INIT) ||
				(asf_mode == ASF_MODE_POST_INIT)) {

				bge_asf_post_reset_new_mode(bgep,
					BGE_INIT_RESET);
			} else {
				bge_asf_post_reset_new_mode(bgep,
					BGE_SHUTDOWN_RESET);
			}
		}
	}
#endif

	/*
	 * Record the new state
	 */
	bgep->chip_resets += 1;
	bgep->bge_chip_state = BGE_CHIP_RESET;
	return (retval);
}

/*
 * bge_chip_start() -- start the chip transmitting and/or receiving,
 * including enabling interrupts
 */
int bge_chip_start(bge_t *bgep, boolean_t reset_phys);
#pragma	no_inline(bge_chip_start)

void
bge_chip_coalesce_update(bge_t *bgep)
{
	bge_reg_put32(bgep, SEND_COALESCE_MAX_BD_REG,
	    bgep->chipid.tx_count_norm);
	bge_reg_put32(bgep, SEND_COALESCE_TICKS_REG,
	    bgep->chipid.tx_ticks_norm);
	bge_reg_put32(bgep, RCV_COALESCE_MAX_BD_REG,
	    bgep->chipid.rx_count_norm);
	bge_reg_put32(bgep, RCV_COALESCE_TICKS_REG,
	    bgep->chipid.rx_ticks_norm);
}

int
bge_chip_start(bge_t *bgep, boolean_t reset_phys)
{
	uint32_t coalmode;
	uint32_t ledctl;
	uint32_t mtu;
	uint32_t maxring;
	uint32_t stats_mask;
	uint32_t dma_wrprio;
	uint64_t ring;
	uint32_t reg;
	uint32_t regval;
	uint32_t mhcr;
	int retval = DDI_SUCCESS;
	int i;

	BGE_TRACE(("bge_chip_start($%p)",
	    (void *)bgep));

	ASSERT(mutex_owned(bgep->genlock));
	ASSERT(bgep->bge_chip_state == BGE_CHIP_RESET);

	/* Initialize EEE, enable MAC control of LPI */
	bge_eee_init(bgep);

	if (bgep->ape_enabled) {
		/*
		 * Allow reads and writes to the
		 * APE register and memory space.
		 */
		regval = pci_config_get32(bgep->cfg_handle,
		    PCI_CONF_BGE_PCISTATE);
		regval |= PCISTATE_ALLOW_APE_CTLSPC_WR |
		    PCISTATE_ALLOW_APE_SHMEM_WR | PCISTATE_ALLOW_APE_PSPACE_WR;
		pci_config_put32(bgep->cfg_handle,
		    PCI_CONF_BGE_PCISTATE, regval);
	}

	/*
	 * Taken from Broadcom document 570X-PG102-R, pp 102-116.
	 * The document specifies 95 separate steps to fully
	 * initialise the chip!!!!
	 *
	 * The reset code above has already got us as far as step
	 * 21, so we continue with ...
	 *
	 * Step 22: clear the MAC statistics block
	 * (0x0300-0x0aff in NIC-local memory)
	 */
	if (bgep->chipid.statistic_type == BGE_STAT_BLK)
		bge_nic_zero(bgep, NIC_MEM_STATISTICS,
		    NIC_MEM_STATISTICS_SIZE);

	/*
	 * Step 23: clear the status block (in host memory)
	 */
	DMA_ZERO(bgep->status_block);

	/*
	 * Step 24: set DMA read/write control register
	 */
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_PDRWCR,
	    bgep->chipid.bge_dma_rwctrl);

	/*
	 * Step 25: Configure DMA endianness -- already done (16/17)
	 * Step 26: Configure Host-Based Send Rings
	 * Step 27: Indicate Host Stack Up
	 */
	bge_reg_set32(bgep, MODE_CONTROL_REG,
	    MODE_HOST_SEND_BDS |
	    MODE_HOST_STACK_UP);

	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		reg = (CHIP_ASIC_REV(bgep) == CHIP_ASIC_REV_5762)
		          ? RDMA_RSRV_CTRL_REG2 : RDMA_RSRV_CTRL_REG;
		regval = bge_reg_get32(bgep, reg);
		if ((bgep->chipid.device == DEVICE_ID_5719) ||
		    (bgep->chipid.device == DEVICE_ID_5720) ||
		    (CHIP_ASIC_REV(bgep) == CHIP_ASIC_REV_5762)) {
			regval &= ~(RDMA_RSRV_CTRL_TXMRGN_MASK |
			            RDMA_RSRV_CTRL_FIFO_LWM_MASK |
			            RDMA_RSRV_CTRL_FIFO_HWM_MASK);
			regval |= (RDMA_RSRV_CTRL_TXMRGN_320B |
			           RDMA_RSRV_CTRL_FIFO_LWM_1_5K |
			           RDMA_RSRV_CTRL_FIFO_HWM_1_5K);
		}
		/* Enable the DMA FIFO Overrun fix. */
		bge_reg_put32(bgep, reg,
		    (regval | RDMA_RSRV_CTRL_FIFO_OFLW_FIX));

		if ((CHIP_ASIC_REV(bgep) == CHIP_ASIC_REV_5719) ||
		    (CHIP_ASIC_REV(bgep) == CHIP_ASIC_REV_5720) ||
		    (CHIP_ASIC_REV(bgep) == CHIP_ASIC_REV_5762)) {
			reg = (CHIP_ASIC_REV(bgep) == CHIP_ASIC_REV_5762)
			          ? RDMA_CORR_CTRL_REG2 : RDMA_CORR_CTRL_REG;
			regval = bge_reg_get32(bgep, reg);
			bge_reg_put32(bgep, reg, (regval |
			                          RDMA_CORR_CTRL_BLEN_BD_4K |
			                          RDMA_CORR_CTRL_BLEN_LSO_4K));
		}
	}

	/*
	 * Step 28: Configure checksum options:
	 *	Solaris supports the hardware default checksum options.
	 *
	 *	Workaround for Incorrect pseudo-header checksum calculation.
	 */
	if (bgep->chipid.flags & CHIP_FLAG_PARTIAL_CSUM)
		bge_reg_set32(bgep, MODE_CONTROL_REG,
		    MODE_SEND_NO_PSEUDO_HDR_CSUM);

	/*
	 * Step 29: configure Timer Prescaler.  The value is always the
	 * same: the Core Clock frequency in MHz (66), minus 1, shifted
	 * into bits 7-1.  Don't set bit 0, 'cos that's the RESET bit
	 * for the whole chip!
	 */
	regval = bge_reg_get32(bgep, MISC_CONFIG_REG);
	regval = (regval & 0xffffff00) | MISC_CONFIG_DEFAULT;
	bge_reg_put32(bgep, MISC_CONFIG_REG, regval);

	if (DEVICE_5906_SERIES_CHIPSETS(bgep)) {
		drv_usecwait(40);
		/* put PHY into ready state */
		bge_reg_clr32(bgep, MISC_CONFIG_REG, MISC_CONFIG_EPHY_IDDQ);
		(void) bge_reg_get32(bgep, MISC_CONFIG_REG); /* flush */
		drv_usecwait(40);
	}

	/*
	 * Steps 30-31: Configure MAC local memory pool & DMA pool registers
	 *
	 * If the mbuf_length is specified as 0, we just leave these at
	 * their hardware defaults, rather than explicitly setting them.
	 * As the Broadcom HRM,driver better not change the parameters
	 * when the chipsets is 5705/5788/5721/5751/5714 and 5715.
	 */
	if ((bgep->chipid.mbuf_length != 0) &&
	    (DEVICE_5704_SERIES_CHIPSETS(bgep))) {
			bge_reg_put32(bgep, MBUF_POOL_BASE_REG,
			    bgep->chipid.mbuf_base);
			bge_reg_put32(bgep, MBUF_POOL_LENGTH_REG,
			    bgep->chipid.mbuf_length);
			bge_reg_put32(bgep, DMAD_POOL_BASE_REG,
			    DMAD_POOL_BASE_DEFAULT);
			bge_reg_put32(bgep, DMAD_POOL_LENGTH_REG,
			    DMAD_POOL_LENGTH_DEFAULT);
	}

	/*
	 * Step 32: configure MAC memory pool watermarks
	 */
	bge_reg_put32(bgep, RDMA_MBUF_LOWAT_REG,
	    bgep->chipid.mbuf_lo_water_rdma);
	bge_reg_put32(bgep, MAC_RX_MBUF_LOWAT_REG,
	    bgep->chipid.mbuf_lo_water_rmac);
	bge_reg_put32(bgep, MBUF_HIWAT_REG,
	    bgep->chipid.mbuf_hi_water);

	/*
	 * Step 33: configure DMA resource watermarks
	 */
	if (DEVICE_5704_SERIES_CHIPSETS(bgep)) {
		bge_reg_put32(bgep, DMAD_POOL_LOWAT_REG,
		    bge_dmad_lo_water);
		bge_reg_put32(bgep, DMAD_POOL_HIWAT_REG,
		    bge_dmad_hi_water);
	}
	bge_reg_put32(bgep, LOWAT_MAX_RECV_FRAMES_REG, bge_lowat_recv_frames);

	/*
	 * Steps 34-36: enable buffer manager & internal h/w queues
	 */
	regval = STATE_MACHINE_ATTN_ENABLE_BIT;
	if (bgep->chipid.device == DEVICE_ID_5719)
		regval |= BUFFER_MANAGER_MODE_NO_TX_UNDERRUN;
	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep))
		regval |= BUFFER_MANAGER_MODE_MBLOW_ATTN_ENABLE;
	if (!bge_chip_enable_engine(bgep, BUFFER_MANAGER_MODE_REG, regval))
		retval = DDI_FAILURE;

	if (!bge_chip_enable_engine(bgep, FTQ_RESET_REG, 0))
		retval = DDI_FAILURE;

	/*
	 * Steps 37-39: initialise Receive Buffer (Producer) RCBs
	 */
	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		buff_ring_t *brp = &bgep->buff[BGE_STD_BUFF_RING];
		bge_reg_put64(bgep, STD_RCV_BD_RING_RCB_REG,
		    brp->desc.cookie.dmac_laddress);
		bge_reg_put32(bgep, STD_RCV_BD_RING_RCB_REG + 8,
		    (brp->desc.nslots) << 16 | brp->buf[0].size << 2);
		bge_reg_put32(bgep, STD_RCV_BD_RING_RCB_REG + 0xc,
		    NIC_MEM_SHADOW_BUFF_STD_5717);
	} else
		bge_reg_putrcb(bgep, STD_RCV_BD_RING_RCB_REG,
		    &bgep->buff[BGE_STD_BUFF_RING].hw_rcb);

	if (DEVICE_5704_SERIES_CHIPSETS(bgep)) {
		bge_reg_putrcb(bgep, JUMBO_RCV_BD_RING_RCB_REG,
		    &bgep->buff[BGE_JUMBO_BUFF_RING].hw_rcb);
		bge_reg_putrcb(bgep, MINI_RCV_BD_RING_RCB_REG,
		    &bgep->buff[BGE_MINI_BUFF_RING].hw_rcb);
	}

	/*
	 * Step 40: set Receive Buffer Descriptor Ring replenish thresholds
	 */
	bge_reg_put32(bgep, STD_RCV_BD_REPLENISH_REG, bge_replenish_std);
	if (DEVICE_5704_SERIES_CHIPSETS(bgep)) {
		bge_reg_put32(bgep, JUMBO_RCV_BD_REPLENISH_REG,
		    bge_replenish_jumbo);
		bge_reg_put32(bgep, MINI_RCV_BD_REPLENISH_REG,
		    bge_replenish_mini);
	}

	/*
	 * Steps 41-43: clear Send Ring Producer Indices and initialise
	 * Send Producer Rings (0x0100-0x01ff in NIC-local memory)
	 */
	if (DEVICE_5704_SERIES_CHIPSETS(bgep))
		maxring = BGE_SEND_RINGS_MAX;
	else
		maxring = BGE_SEND_RINGS_MAX_5705;
	for (ring = 0; ring < maxring; ++ring) {
		bge_mbx_put(bgep, SEND_RING_HOST_INDEX_REG(ring), 0);
		bge_mbx_put(bgep, SEND_RING_NIC_INDEX_REG(ring), 0);
		bge_nic_putrcb(bgep, NIC_MEM_SEND_RING(ring),
		    &bgep->send[ring].hw_rcb);
	}

	/*
	 * Steps 44-45: initialise Receive Return Rings
	 * (0x0200-0x02ff in NIC-local memory)
	 */
	if (DEVICE_5704_SERIES_CHIPSETS(bgep))
		maxring = BGE_RECV_RINGS_MAX;
	else
		maxring = BGE_RECV_RINGS_MAX_5705;
	for (ring = 0; ring < maxring; ++ring)
		bge_nic_putrcb(bgep, NIC_MEM_RECV_RING(ring),
		    &bgep->recv[ring].hw_rcb);

	/*
	 * Step 46: initialise Receive Buffer (Producer) Ring indexes
	 */
	bge_mbx_put(bgep, RECV_STD_PROD_INDEX_REG, 0);
	if (DEVICE_5704_SERIES_CHIPSETS(bgep)) {
		bge_mbx_put(bgep, RECV_JUMBO_PROD_INDEX_REG, 0);
		bge_mbx_put(bgep, RECV_MINI_PROD_INDEX_REG, 0);
	}
	/*
	 * Step 47: configure the MAC unicast address
	 * Step 48: configure the random backoff seed
	 * Step 96: set up multicast filters
	 */
#ifdef BGE_IPMI_ASF
	if (bge_chip_sync(bgep, B_FALSE) == DDI_FAILURE)
#else
	if (bge_chip_sync(bgep) == DDI_FAILURE)
#endif
		retval = DDI_FAILURE;

	/*
	 * Step 49: configure the MTU
	 */
	mtu = bgep->chipid.ethmax_size+ETHERFCSL+VLAN_TAGSZ;
	bge_reg_put32(bgep, MAC_RX_MTU_SIZE_REG, mtu);

	/*
	 * Step 50: configure the IPG et al
	 */
	bge_reg_put32(bgep, MAC_TX_LENGTHS_REG, MAC_TX_LENGTHS_DEFAULT);

	/*
	 * Step 51: configure the default Rx Return Ring
	 */
	bge_reg_put32(bgep, RCV_RULES_CONFIG_REG, RCV_RULES_CONFIG_DEFAULT);

	/*
	 * Steps 52-54: configure Receive List Placement,
	 * and enable Receive List Placement Statistics
	 */
	bge_reg_put32(bgep, RCV_LP_CONFIG_REG,
	    RCV_LP_CONFIG(bgep->chipid.rx_rings));
	switch (MHCR_CHIP_ASIC_REV(bgep)) {
	case MHCR_CHIP_ASIC_REV_5700:
	case MHCR_CHIP_ASIC_REV_5701:
	case MHCR_CHIP_ASIC_REV_5703:
	case MHCR_CHIP_ASIC_REV_5704:
		bge_reg_put32(bgep, RCV_LP_STATS_ENABLE_MASK_REG, ~0);
		break;
	case MHCR_CHIP_ASIC_REV_5705:
		break;
	default:
		stats_mask = bge_reg_get32(bgep, RCV_LP_STATS_ENABLE_MASK_REG);
		stats_mask &= ~RCV_LP_STATS_DISABLE_MACTQ;
		bge_reg_put32(bgep, RCV_LP_STATS_ENABLE_MASK_REG, stats_mask);
		break;
	}
	bge_reg_set32(bgep, RCV_LP_STATS_CONTROL_REG, RCV_LP_STATS_ENABLE);

	if (bgep->chipid.rx_rings > 1)
		bge_init_recv_rule(bgep);

	/*
	 * Steps 55-56: enable Send Data Initiator Statistics
	 */
	bge_reg_put32(bgep, SEND_INIT_STATS_ENABLE_MASK_REG, ~0);
	if (DEVICE_5704_SERIES_CHIPSETS(bgep)) {
		bge_reg_put32(bgep, SEND_INIT_STATS_CONTROL_REG,
		    SEND_INIT_STATS_ENABLE | SEND_INIT_STATS_FASTER);
	} else {
		bge_reg_put32(bgep, SEND_INIT_STATS_CONTROL_REG,
		    SEND_INIT_STATS_ENABLE);
	}
	/*
	 * Steps 57-58: stop (?) the Host Coalescing Engine
	 */
	if (!bge_chip_disable_engine(bgep, HOST_COALESCE_MODE_REG, ~0))
		retval = DDI_FAILURE;

	/*
	 * Steps 59-62: initialise Host Coalescing parameters
	 */
	bge_chip_coalesce_update(bgep);
	if (DEVICE_5704_SERIES_CHIPSETS(bgep)) {
		bge_reg_put32(bgep, SEND_COALESCE_INT_BD_REG,
		    bge_tx_count_intr);
		bge_reg_put32(bgep, SEND_COALESCE_INT_TICKS_REG,
		    bge_tx_ticks_intr);
		bge_reg_put32(bgep, RCV_COALESCE_INT_BD_REG,
		    bge_rx_count_intr);
		bge_reg_put32(bgep, RCV_COALESCE_INT_TICKS_REG,
		    bge_rx_ticks_intr);
	}

	/*
	 * Steps 63-64: initialise status block & statistics
	 * host memory addresses
	 * The statistic block does not exist in some chipsets
	 * Step 65: initialise Statistics Coalescing Tick Counter
	 */
	bge_reg_put64(bgep, STATUS_BLOCK_HOST_ADDR_REG,
	    bgep->status_block.cookie.dmac_laddress);

	/*
	 * Steps 66-67: initialise status block & statistics
	 * NIC-local memory addresses
	 */
	if (DEVICE_5704_SERIES_CHIPSETS(bgep)) {
		bge_reg_put64(bgep, STATISTICS_HOST_ADDR_REG,
		    bgep->statistics.cookie.dmac_laddress);
		bge_reg_put32(bgep, STATISTICS_TICKS_REG,
		    STATISTICS_TICKS_DEFAULT);
		bge_reg_put32(bgep, STATUS_BLOCK_BASE_ADDR_REG,
		    NIC_MEM_STATUS_BLOCK);
		bge_reg_put32(bgep, STATISTICS_BASE_ADDR_REG,
		    NIC_MEM_STATISTICS);
	}

	/*
	 * Steps 68-71: start the Host Coalescing Engine, the Receive BD
	 * Completion Engine, the Receive List Placement Engine, and the
	 * Receive List selector.Pay attention:0x3400 is not exist in BCM5714
	 * and BCM5715.
	 */

	if (bgep->chipid.device == DEVICE_ID_5719) {
		for (i = 0; i < BGE_NUM_RDMA_CHANNELS; i++) {
			if (bge_reg_get32(bgep, (BGE_RDMA_LENGTH + (i << 2))) >
			    bgep->chipid.default_mtu)
				break;
		}
		if (i < BGE_NUM_RDMA_CHANNELS) {
			regval = bge_reg_get32(bgep, RDMA_CORR_CTRL_REG);
			regval |= RDMA_CORR_CTRL_TX_LENGTH_WA;
			bge_reg_put32(bgep, RDMA_CORR_CTRL_REG, regval);
			bgep->rdma_length_bug_on_5719 = B_TRUE;
		}
	}

	if (bgep->chipid.tx_rings <= COALESCE_64_BYTE_RINGS &&
	    bgep->chipid.rx_rings <= COALESCE_64_BYTE_RINGS)
		coalmode = COALESCE_64_BYTE_STATUS;
	else
		coalmode = 0;
	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep))
		coalmode = COALESCE_CLR_TICKS_RX;
	if (!bge_chip_enable_engine(bgep, HOST_COALESCE_MODE_REG, coalmode))
		retval = DDI_FAILURE;
	if (!bge_chip_enable_engine(bgep, RCV_BD_COMPLETION_MODE_REG,
	    STATE_MACHINE_ATTN_ENABLE_BIT))
		retval = DDI_FAILURE;
	if (!bge_chip_enable_engine(bgep, RCV_LIST_PLACEMENT_MODE_REG, 0))
		retval = DDI_FAILURE;

	if (DEVICE_5704_SERIES_CHIPSETS(bgep))
		if (!bge_chip_enable_engine(bgep, RCV_LIST_SELECTOR_MODE_REG,
		    STATE_MACHINE_ATTN_ENABLE_BIT))
			retval = DDI_FAILURE;

	/*
	 * Step 72: Enable MAC DMA engines
	 * Step 73: Clear & enable MAC statistics
	 */
	if (bgep->ape_enabled) {
		/* XXX put32 instead of set32 ? */
		bge_reg_put32(bgep, ETHERNET_MAC_MODE_REG,
		    ETHERNET_MODE_APE_TX_EN | ETHERNET_MODE_APE_RX_EN);
	}
	bge_reg_set32(bgep, ETHERNET_MAC_MODE_REG,
	    ETHERNET_MODE_ENABLE_FHDE |
	    ETHERNET_MODE_ENABLE_RDE |
	    ETHERNET_MODE_ENABLE_TDE);
	bge_reg_set32(bgep, ETHERNET_MAC_MODE_REG,
	    ETHERNET_MODE_ENABLE_TX_STATS |
	    ETHERNET_MODE_ENABLE_RX_STATS |
	    ETHERNET_MODE_CLEAR_TX_STATS |
	    ETHERNET_MODE_CLEAR_RX_STATS);

	drv_usecwait(140);

	if (bgep->ape_enabled) {
		/* Write our heartbeat update interval to APE. */
		bge_ape_put32(bgep, BGE_APE_HOST_HEARTBEAT_INT_MS,
		    APE_HOST_HEARTBEAT_INT_DISABLE);
	}

	/*
	 * Step 74: configure the MLCR (Miscellaneous Local Control
	 * Register); not required, as we set up the MLCR in step 10
	 * (part of the reset code) above.
	 *
	 * Step 75: clear Interrupt Mailbox 0
	 */
	bge_mbx_put(bgep, INTERRUPT_MBOX_0_REG, 0);

	/*
	 * Steps 76-87: Gentlemen, start your engines ...
	 *
	 * Enable the DMA Completion Engine, the Write DMA Engine,
	 * the Read DMA Engine, Receive Data Completion Engine,
	 * the MBuf Cluster Free Engine, the Send Data Completion Engine,
	 * the Send BD Completion Engine, the Receive BD Initiator Engine,
	 * the Receive Data Initiator Engine, the Send Data Initiator Engine,
	 * the Send BD Initiator Engine, and the Send BD Selector Engine.
	 *
	 * Beware exhaust fumes?
	 */
	if (DEVICE_5704_SERIES_CHIPSETS(bgep))
		if (!bge_chip_enable_engine(bgep, DMA_COMPLETION_MODE_REG, 0))
			retval = DDI_FAILURE;
	dma_wrprio = (bge_dma_wrprio << DMA_PRIORITY_SHIFT) |
	    ALL_DMA_ATTN_BITS;
	/* the 5723 check here covers all newer chip families (OK) */
	if ((MHCR_CHIP_ASIC_REV(bgep) == MHCR_CHIP_ASIC_REV_5755) ||
	    (MHCR_CHIP_ASIC_REV(bgep) == MHCR_CHIP_ASIC_REV_5723) ||
	    (MHCR_CHIP_ASIC_REV(bgep) == MHCR_CHIP_ASIC_REV_5906)) {
		dma_wrprio |= DMA_STATUS_TAG_FIX_CQ12384;
	}
	if (!bge_chip_enable_engine(bgep, WRITE_DMA_MODE_REG,
	    dma_wrprio))
		retval = DDI_FAILURE;

	drv_usecwait(40);

	if (DEVICE_5723_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep))
		bge_dma_rdprio = 0;
	if (!bge_chip_enable_engine(bgep, READ_DMA_MODE_REG,
	    (bge_dma_rdprio << DMA_PRIORITY_SHIFT) | ALL_DMA_ATTN_BITS))
		retval = DDI_FAILURE;

	drv_usecwait(40);

	if (!bge_chip_enable_engine(bgep, RCV_DATA_COMPLETION_MODE_REG,
	    STATE_MACHINE_ATTN_ENABLE_BIT))
		retval = DDI_FAILURE;
	if (DEVICE_5704_SERIES_CHIPSETS(bgep))
		if (!bge_chip_enable_engine(bgep,
		    MBUF_CLUSTER_FREE_MODE_REG, 0))
			retval = DDI_FAILURE;
	if (!bge_chip_enable_engine(bgep, SEND_DATA_COMPLETION_MODE_REG, 0))
		retval = DDI_FAILURE;
	if (!bge_chip_enable_engine(bgep, SEND_BD_COMPLETION_MODE_REG,
	    STATE_MACHINE_ATTN_ENABLE_BIT))
		retval = DDI_FAILURE;
	if (!bge_chip_enable_engine(bgep, RCV_BD_INITIATOR_MODE_REG,
	    RCV_BD_DISABLED_RING_ATTN))
		retval = DDI_FAILURE;
	if (!bge_chip_enable_engine(bgep, RCV_DATA_BD_INITIATOR_MODE_REG,
	    RCV_DATA_BD_ILL_RING_ATTN))
		retval = DDI_FAILURE;
	if (!bge_chip_enable_engine(bgep, SEND_DATA_INITIATOR_MODE_REG, 0))
		retval = DDI_FAILURE;
	if (!bge_chip_enable_engine(bgep, SEND_BD_INITIATOR_MODE_REG,
	    STATE_MACHINE_ATTN_ENABLE_BIT))
		retval = DDI_FAILURE;
	if (!bge_chip_enable_engine(bgep, SEND_BD_SELECTOR_MODE_REG,
	    STATE_MACHINE_ATTN_ENABLE_BIT))
		retval = DDI_FAILURE;

	drv_usecwait(40);

	/*
	 * Step 88: download firmware -- doesn't apply
	 * Steps 89-90: enable Transmit & Receive MAC Engines
	 */
	regval = 0;
	if (DEVICE_5717_SERIES_CHIPSETS(bgep)) {
		regval |= TRANSMIT_MODE_MBUF_LOCKUP_FIX;
	}
	if (!bge_chip_enable_engine(bgep, TRANSMIT_MAC_MODE_REG, regval))
		retval = DDI_FAILURE;

	drv_usecwait(100);

#ifdef BGE_IPMI_ASF
	if (!bgep->asf_enabled) {
		if (!bge_chip_enable_engine(bgep, RECEIVE_MAC_MODE_REG,
		    RECEIVE_MODE_KEEP_VLAN_TAG))
			retval = DDI_FAILURE;
	} else {
		if (!bge_chip_enable_engine(bgep, RECEIVE_MAC_MODE_REG, 0))
			retval = DDI_FAILURE;
	}
#else
	if (!bge_chip_enable_engine(bgep, RECEIVE_MAC_MODE_REG,
	    RECEIVE_MODE_KEEP_VLAN_TAG))
		retval = DDI_FAILURE;
#endif

	drv_usecwait(100);

	/*
	 * Step 91: disable auto-polling of PHY status
	 */
	bge_reg_put32(bgep, MI_MODE_REG, MI_MODE_DEFAULT);

	/*
	 * Step 92: configure D0 power state (not required)
	 * Step 93: initialise LED control register ()
	 */
	ledctl = LED_CONTROL_DEFAULT;
	switch (bgep->chipid.device) {
	case DEVICE_ID_5700:
	case DEVICE_ID_5700x:
	case DEVICE_ID_5701:
		/*
		 * Switch to 5700 (MAC) mode on these older chips
		 */
		ledctl &= ~LED_CONTROL_LED_MODE_MASK;
		ledctl |= LED_CONTROL_LED_MODE_5700;
		break;

	default:
		break;
	}
	bge_reg_put32(bgep, ETHERNET_MAC_LED_CONTROL_REG, ledctl);

	/*
	 * Step 94: activate link
	 */
	bge_reg_put32(bgep, MI_STATUS_REG, MI_STATUS_LINK);

	/*
	 * Step 95: set up physical layer (PHY/SerDes)
	 * restart autoneg (if required)
	 */
	if (reset_phys)
	{
		if (bge_phys_update(bgep) == DDI_FAILURE)
			retval = DDI_FAILURE;
		/* forcing a mac link update here */
		bge_phys_check(bgep);
		bgep->link_state = (bgep->param_link_up) ? LINK_STATE_UP :
		                                           LINK_STATE_DOWN;
		bge_sync_mac_modes(bgep);
		mac_link_update(bgep->mh, bgep->link_state);
	}

	/*
	 * Extra step (DSG): hand over all the Receive Buffers to the chip
	 */
	for (ring = 0; ring < BGE_BUFF_RINGS_USED; ++ring)
		bge_mbx_put(bgep, bgep->buff[ring].chip_mbx_reg,
		    bgep->buff[ring].rf_next);

	/*
	 * MSI bits:The least significant MSI 16-bit word.
	 * ISR will be triggered different.
	 */
	if (bgep->intr_type == DDI_INTR_TYPE_MSI)
		bge_reg_set32(bgep, HOST_COALESCE_MODE_REG, 0x70);

	/*
	 * Extra step (DSG): select which interrupts are enabled
	 *
	 * Program the Ethernet MAC engine to signal attention on
	 * Link Change events, then enable interrupts on MAC, DMA,
	 * and FLOW attention signals.
	 */
	bge_reg_set32(bgep, ETHERNET_MAC_EVENT_ENABLE_REG,
	    ETHERNET_EVENT_LINK_INT |
	    ETHERNET_STATUS_PCS_ERROR_INT);
#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled) {
		bge_reg_set32(bgep, MODE_CONTROL_REG,
		    MODE_INT_ON_FLOW_ATTN |
		    MODE_INT_ON_DMA_ATTN |
		    MODE_HOST_STACK_UP|
		    MODE_INT_ON_MAC_ATTN);
	} else {
#endif
		bge_reg_set32(bgep, MODE_CONTROL_REG,
		    MODE_INT_ON_FLOW_ATTN |
		    MODE_INT_ON_DMA_ATTN |
		    MODE_INT_ON_MAC_ATTN);
#ifdef BGE_IPMI_ASF
	}
#endif

	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		bge_cfg_clr16(bgep, PCI_CONF_DEV_CTRL_5717,
		    DEV_CTRL_NO_SNOOP | DEV_CTRL_RELAXED);
#if 0
		mhcr = pci_config_get32(bgep->cfg_handle, PCI_CONF_BGE_MHCR);
		pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MHCR,
		                 (mhcr | MHCR_TLP_MINOR_ERR_TOLERANCE));
#endif
	}

	/*
	 * Step 97: enable PCI interrupts!!!
	 */
	if (bgep->intr_type == DDI_INTR_TYPE_FIXED)
		bge_cfg_clr32(bgep, PCI_CONF_BGE_MHCR,
		    bgep->chipid.mask_pci_int);

	/*
	 * All done!
	 */
	bgep->bge_chip_state = BGE_CHIP_RUNNING;
	return (retval);
}


/*
 * ========== Hardware interrupt handler ==========
 */

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_INT	/* debug flag for this code	*/

/*
 * Sync the status block, then atomically clear the specified bits in
 * the <flags-and-tag> field of the status block.
 * the <flags> word of the status block, returning the value of the
 * <tag> and the <flags> before the bits were cleared.
 */
static int bge_status_sync(bge_t *bgep, uint64_t bits, uint64_t *flags);
#pragma	inline(bge_status_sync)

static int
bge_status_sync(bge_t *bgep, uint64_t bits, uint64_t *flags)
{
	bge_status_t *bsp;
	int retval;

	BGE_TRACE(("bge_status_sync($%p, 0x%llx)",
	    (void *)bgep, bits));

	ASSERT(bgep->bge_guard == BGE_GUARD);

	DMA_SYNC(bgep->status_block, DDI_DMA_SYNC_FORKERNEL);
	retval = bge_check_dma_handle(bgep, bgep->status_block.dma_hdl);
	if (retval != DDI_FM_OK)
		return (retval);

	bsp = DMA_VPTR(bgep->status_block);
	*flags = bge_atomic_clr64(&bsp->flags_n_tag, bits);

	BGE_DEBUG(("bge_status_sync($%p, 0x%llx) returning 0x%llx",
	    (void *)bgep, bits, *flags));

	return (retval);
}

void bge_wake_factotum(bge_t *bgep);
#pragma	inline(bge_wake_factotum)

void
bge_wake_factotum(bge_t *bgep)
{
	mutex_enter(bgep->softintrlock);
	if (bgep->factotum_flag == 0) {
		bgep->factotum_flag = 1;
		ddi_trigger_softintr(bgep->factotum_id);
	}
	mutex_exit(bgep->softintrlock);
}

static void
bge_intr_error_handler(bge_t *bgep)
{
	uint32_t flow;
	uint32_t rdma;
	uint32_t wdma;
	uint32_t tmac;
	uint32_t rmac;
	uint32_t rxrs;
	uint32_t emac;
	uint32_t msis;
	uint32_t txrs = 0;

	ASSERT(mutex_owned(bgep->genlock));

	/*
	 * Read all the registers that show the possible
	 * reasons for the ERROR bit to be asserted
	 */
	flow = bge_reg_get32(bgep, FLOW_ATTN_REG);
	rdma = bge_reg_get32(bgep, READ_DMA_STATUS_REG);
	wdma = bge_reg_get32(bgep, WRITE_DMA_STATUS_REG);
	tmac = bge_reg_get32(bgep, TRANSMIT_MAC_STATUS_REG);
	rmac = bge_reg_get32(bgep, RECEIVE_MAC_STATUS_REG);
	rxrs = bge_reg_get32(bgep, RX_RISC_STATE_REG);
	emac = bge_reg_get32(bgep, ETHERNET_MAC_STATUS_REG);
	msis = bge_reg_get32(bgep, MSI_STATUS_REG);
	if (DEVICE_5704_SERIES_CHIPSETS(bgep))
		txrs = bge_reg_get32(bgep, TX_RISC_STATE_REG);

	BGE_DEBUG(("factotum($%p) flow 0x%x rdma 0x%x wdma 0x%x emac 0x%x msis 0x%x",
	    (void *)bgep, flow, rdma, wdma, emac, msis));
	BGE_DEBUG(("factotum($%p) tmac 0x%x rmac 0x%x rxrs 0x%08x txrs 0x%08x",
	    (void *)bgep, tmac, rmac, rxrs, txrs));

	/*
	 * For now, just clear all the errors ...
	 */
	if (DEVICE_5704_SERIES_CHIPSETS(bgep))
		bge_reg_put32(bgep, TX_RISC_STATE_REG, ~0);
	bge_reg_put32(bgep, RX_RISC_STATE_REG, ~0);
	bge_reg_put32(bgep, RECEIVE_MAC_STATUS_REG, ~0);
	bge_reg_put32(bgep, WRITE_DMA_STATUS_REG, ~0);
	bge_reg_put32(bgep, READ_DMA_STATUS_REG, ~0);
	bge_reg_put32(bgep, FLOW_ATTN_REG, ~0);
}

/*
 *	bge_intr() -- handle chip interrupts
 */
uint_t bge_intr(caddr_t arg1, caddr_t arg2);
#pragma	no_inline(bge_intr)

uint_t
bge_intr(caddr_t arg1, caddr_t arg2)
{
	bge_t *bgep = (void *)arg1;		/* private device info	*/
	bge_status_t *bsp;
	uint64_t flags;
	uint32_t regval;
	uint_t result;
	int retval, loop_cnt = 0;

	BGE_TRACE(("bge_intr($%p) ($%p)", arg1, arg2));

	/*
	 * GLD v2 checks that s/w setup is complete before passing
	 * interrupts to this routine, thus eliminating the old
	 * (and well-known) race condition around ddi_add_intr()
	 */
	ASSERT(bgep->progress & PROGRESS_HWINT);

	result = DDI_INTR_UNCLAIMED;
	mutex_enter(bgep->genlock);

	if (bgep->intr_type == DDI_INTR_TYPE_FIXED) {
		/*
		 * Check whether chip's says it's asserting #INTA;
		 * if not, don't process or claim the interrupt.
		 *
		 * Note that the PCI signal is active low, so the
		 * bit is *zero* when the interrupt is asserted.
		 */
		regval = bge_reg_get32(bgep, MISC_LOCAL_CONTROL_REG);
		if (!(DEVICE_5717_SERIES_CHIPSETS(bgep) ||
		      DEVICE_5725_SERIES_CHIPSETS(bgep)) &&
		    (regval & MLCR_INTA_STATE)) {
			if (bge_check_acc_handle(bgep, bgep->io_handle)
			    != DDI_FM_OK)
				goto chip_stop;
			mutex_exit(bgep->genlock);
			return (result);
		}

		/*
		 * Block further PCI interrupts ...
		 */
		bge_reg_set32(bgep, PCI_CONF_BGE_MHCR,
		    bgep->chipid.mask_pci_int);

	} else {
		/*
		 * Check MSI status
		 */
		regval = bge_reg_get32(bgep, MSI_STATUS_REG);
		if (regval & MSI_ERROR_ATTENTION) {
			BGE_REPORT((bgep, "msi error attention,"
			    " status=0x%x", regval));
			bge_reg_put32(bgep, MSI_STATUS_REG, regval);
		}
	}

	result = DDI_INTR_CLAIMED;

	BGE_DEBUG(("bge_intr($%p) ($%p) regval 0x%08x", arg1, arg2, regval));

	/*
	 * Sync the status block and grab the flags-n-tag from it.
	 * We count the number of interrupts where there doesn't
	 * seem to have been a DMA update of the status block; if
	 * it *has* been updated, the counter will be cleared in
	 * the while() loop below ...
	 */
	bgep->missed_dmas += 1;
	bsp = DMA_VPTR(bgep->status_block);
	for (loop_cnt = 0; loop_cnt < bge_intr_max_loop; loop_cnt++) {
		if (bgep->bge_chip_state != BGE_CHIP_RUNNING) {
			/*
			 * bge_chip_stop() may have freed dma area etc
			 * while we were in this interrupt handler -
			 * better not call bge_status_sync()
			 */
			(void) bge_check_acc_handle(bgep,
			    bgep->io_handle);
			mutex_exit(bgep->genlock);
			return (DDI_INTR_CLAIMED);
		}

		retval = bge_status_sync(bgep, STATUS_FLAG_UPDATED |
		    STATUS_FLAG_LINK_CHANGED | STATUS_FLAG_ERROR, &flags);
		if (retval != DDI_FM_OK) {
			bgep->bge_dma_error = B_TRUE;
			goto chip_stop;
		}

		if (!(flags & STATUS_FLAG_UPDATED))
			break;

		/*
		 * Tell the chip that we're processing the interrupt
		 */
		bge_mbx_put(bgep, INTERRUPT_MBOX_0_REG,
		    INTERRUPT_MBOX_DISABLE(flags));
		if (bge_check_acc_handle(bgep, bgep->io_handle) !=
		    DDI_FM_OK)
			goto chip_stop;

		if (flags & STATUS_FLAG_LINK_CHANGED) {
			BGE_DEBUG(("bge_intr($%p) ($%p) link event", arg1, arg2));
			if (bge_phys_check(bgep)) {
				bgep->link_state = bgep->param_link_up ?
				    LINK_STATE_UP : LINK_STATE_DOWN;
				bge_sync_mac_modes(bgep);
				mac_link_update(bgep->mh, bgep->link_state);
			}

			if (bge_check_acc_handle(bgep, bgep->io_handle) !=
			    DDI_FM_OK)
				goto chip_stop;
		}

		if (flags & STATUS_FLAG_ERROR) {
			bge_intr_error_handler(bgep);

			if (bge_check_acc_handle(bgep, bgep->io_handle) !=
			    DDI_FM_OK)
				goto chip_stop;
		}

		/*
		 * Drop the mutex while we:
		 * 	Receive any newly-arrived packets
		 *	Recycle any newly-finished send buffers
		 */
		bgep->bge_intr_running = B_TRUE;
		mutex_exit(bgep->genlock);
		bge_receive(bgep, bsp);
		(void) bge_recycle(bgep, bsp);
		mutex_enter(bgep->genlock);
		bgep->bge_intr_running = B_FALSE;

		/*
		 * Tell the chip we've finished processing, and
		 * give it the tag that we got from the status
		 * block earlier, so that it knows just how far
		 * we've gone.  If it's got more for us to do,
		 * it will now update the status block and try
		 * to assert an interrupt (but we've got the
		 * #INTA blocked at present).  If we see the
		 * update, we'll loop around to do some more.
		 * Eventually we'll get out of here ...
		 */
		bge_mbx_put(bgep, INTERRUPT_MBOX_0_REG,
		    INTERRUPT_MBOX_ENABLE(flags));
		if (bgep->chipid.pci_type == BGE_PCI_E)
			(void) bge_mbx_get(bgep, INTERRUPT_MBOX_0_REG);
		bgep->missed_dmas = 0;
	}

	if (bgep->missed_dmas) {
		/*
		 * Probably due to the internal status tag not
		 * being reset.  Force a status block update now;
		 * this should ensure that we get an update and
		 * a new interrupt.  After that, we should be in
		 * sync again ...
		 */
		BGE_REPORT((bgep, "interrupt: flags 0x%llx - "
		    "not updated?", flags));
		bgep->missed_updates++;
		bge_reg_set32(bgep, HOST_COALESCE_MODE_REG,
		    COALESCE_NOW);

		if (bgep->missed_dmas >= bge_dma_miss_limit) {
			/*
			 * If this happens multiple times in a row,
			 * it means DMA is just not working.  Maybe
			 * the chip's failed, or maybe there's a
			 * problem on the PCI bus or in the host-PCI
			 * bridge (Tomatillo).
			 *
			 * At all events, we want to stop further
			 * interrupts and let the recovery code take
			 * over to see whether anything can be done
			 * about it ...
			 */
			bge_fm_ereport(bgep,
			    DDI_FM_DEVICE_BADINT_LIMIT);
			goto chip_stop;
		}
	}

	/*
	 * Reenable assertion of #INTA, unless there's a DMA fault
	 */
	if (bgep->intr_type == DDI_INTR_TYPE_FIXED) {
		bge_reg_clr32(bgep, PCI_CONF_BGE_MHCR,
		    bgep->chipid.mask_pci_int);
		if (bge_check_acc_handle(bgep, bgep->cfg_handle) !=
		    DDI_FM_OK)
			goto chip_stop;
	}

	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
		goto chip_stop;

	mutex_exit(bgep->genlock);
	return (result);

chip_stop:

#ifdef BGE_IPMI_ASF
	if (bgep->asf_enabled && bgep->asf_status == ASF_STAT_RUN) {
		/*
		 * We must stop ASF heart beat before
		 * bge_chip_stop(), otherwise some
		 * computers (ex. IBM HS20 blade
		 * server) may crash.
		 */
		bge_asf_update_status(bgep);
		bge_asf_stop_timer(bgep);
		bgep->asf_status = ASF_STAT_STOP;

		bge_asf_pre_reset_operations(bgep, BGE_INIT_RESET);
		(void) bge_check_acc_handle(bgep, bgep->cfg_handle);
	}
#endif
	bge_chip_stop(bgep, B_TRUE);
	(void) bge_check_acc_handle(bgep, bgep->io_handle);
	mutex_exit(bgep->genlock);
	return (result);
}

/*
 * ========== Factotum, implemented as a softint handler ==========
 */

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_FACT	/* debug flag for this code	*/

/*
 * Factotum routine to check for Tx stall, using the 'watchdog' counter
 */
static boolean_t bge_factotum_stall_check(bge_t *bgep);
#pragma	no_inline(bge_factotum_stall_check)

static boolean_t
bge_factotum_stall_check(bge_t *bgep)
{
	uint32_t dogval;
	bge_status_t *bsp;
	uint64_t now = gethrtime();

	if ((now - bgep->timestamp) < BGE_CYCLIC_PERIOD)
		return (B_FALSE);

	bgep->timestamp = now;

	ASSERT(mutex_owned(bgep->genlock));

	/*
	 * Specific check for Tx stall ...
	 *
	 * The 'watchdog' counter is incremented whenever a packet
	 * is queued, reset to 1 when some (but not all) buffers
	 * are reclaimed, reset to 0 (disabled) when all buffers
	 * are reclaimed, and shifted left here.  If it exceeds the
	 * threshold value, the chip is assumed to have stalled and
	 * is put into the ERROR state.  The factotum will then reset
	 * it on the next pass.
	 *
	 * All of which should ensure that we don't get into a state
	 * where packets are left pending indefinitely!
	 */
	dogval = bge_atomic_shl32(&bgep->watchdog, 1);
	bsp = DMA_VPTR(bgep->status_block);
	if (dogval < bge_watchdog_count || bge_recycle(bgep, bsp))
		return (B_FALSE);

#if !defined(BGE_NETCONSOLE)
	BGE_REPORT((bgep, "Tx stall detected, watchdog code 0x%x", dogval));
#endif
	bge_fm_ereport(bgep, DDI_FM_DEVICE_STALL);
	return (B_TRUE);
}

/*
 * The factotum is woken up when there's something to do that we'd rather
 * not do from inside a hardware interrupt handler or high-level cyclic.
 * Its main task is to reset & restart the chip after an error.
 */
uint_t bge_chip_factotum(caddr_t arg);
#pragma	no_inline(bge_chip_factotum)

uint_t
bge_chip_factotum(caddr_t arg)
{
	bge_t *bgep;
	uint_t result;
	boolean_t error;
	int dma_state;

	bgep = (void *)arg;

	BGE_TRACE(("bge_chip_factotum($%p)", (void *)bgep));

	mutex_enter(bgep->softintrlock);
	if (bgep->factotum_flag == 0) {
		mutex_exit(bgep->softintrlock);
		return (DDI_INTR_UNCLAIMED);
	}
	bgep->factotum_flag = 0;
	mutex_exit(bgep->softintrlock);

	result = DDI_INTR_CLAIMED;
	error = B_FALSE;

	mutex_enter(bgep->genlock);
	switch (bgep->bge_chip_state) {
	default:
		break;

	case BGE_CHIP_RUNNING:

		if (bgep->chipid.device == DEVICE_ID_5700) {
			if (bge_phys_check(bgep)) {
				bgep->link_state = (bgep->param_link_up) ?
				    LINK_STATE_UP : LINK_STATE_DOWN;
				bge_sync_mac_modes(bgep);
				mac_link_update(bgep->mh, bgep->link_state);
			}
		}

		error = bge_factotum_stall_check(bgep);
		if (dma_state != DDI_FM_OK) {
			bgep->bge_dma_error = B_TRUE;
			error = B_TRUE;
		}
		if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
			error = B_TRUE;
		if (error)
			bgep->bge_chip_state = BGE_CHIP_ERROR;
		break;

	case BGE_CHIP_ERROR:
		error = B_TRUE;
		break;

	case BGE_CHIP_FAULT:
		/*
		 * Fault detected, time to reset ...
		 */
		if (bge_autorecover) {
			if (!(bgep->progress & PROGRESS_BUFS)) {
				/*
				 * if we can't allocate the ring buffers,
				 * try later
				 */
				if (bge_alloc_bufs(bgep) != DDI_SUCCESS) {
					mutex_exit(bgep->genlock);
					return (result);
				}
				bgep->progress |= PROGRESS_BUFS;
			}
			if (!(bgep->progress & PROGRESS_INTR)) {
				bge_init_rings(bgep);
				bge_intr_enable(bgep);
				bgep->progress |= PROGRESS_INTR;
			}
			if (!(bgep->progress & PROGRESS_KSTATS)) {
				bge_init_kstats(bgep,
				    ddi_get_instance(bgep->devinfo));
				bgep->progress |= PROGRESS_KSTATS;
			}

			BGE_REPORT((bgep, "automatic recovery activated"));

			if (bge_restart(bgep, B_FALSE) != DDI_SUCCESS) {
				bgep->bge_chip_state = BGE_CHIP_ERROR;
				error = B_TRUE;
			}
			if (bge_check_acc_handle(bgep, bgep->cfg_handle) !=
			    DDI_FM_OK) {
				bgep->bge_chip_state = BGE_CHIP_ERROR;
				error = B_TRUE;
			}
			if (bge_check_acc_handle(bgep, bgep->io_handle) !=
			    DDI_FM_OK) {
				bgep->bge_chip_state = BGE_CHIP_ERROR;
				error = B_TRUE;
			}
			if (error == B_FALSE) {
#ifdef BGE_IPMI_ASF
				if (bgep->asf_enabled &&
				    bgep->asf_status != ASF_STAT_RUN) {
					bgep->asf_timeout_id = timeout(
					    bge_asf_heartbeat, (void *)bgep,
					    drv_usectohz(
					    BGE_ASF_HEARTBEAT_INTERVAL));
					bgep->asf_status = ASF_STAT_RUN;
				}
#endif
				if (!bgep->manual_reset) {
					ddi_fm_service_impact(bgep->devinfo,
					    DDI_SERVICE_RESTORED);
				}
			}
		}
		break;
	}

	/*
	 * If an error is detected, stop the chip now, marking it as
	 * faulty, so that it will be reset next time through ...
	 *
	 * Note that if intr_running is set, then bge_intr() has dropped
	 * genlock to call bge_receive/bge_recycle. Can't stop the chip at
	 * this point so have to wait until the next time the factotum runs.
	 */
	if (error && !bgep->bge_intr_running) {
#ifdef BGE_IPMI_ASF
		if (bgep->asf_enabled && (bgep->asf_status == ASF_STAT_RUN)) {
			/*
			 * We must stop ASF heart beat before bge_chip_stop(),
			 * otherwise some computers (ex. IBM HS20 blade server)
			 * may crash.
			 */
			bge_asf_update_status(bgep);
			bge_asf_stop_timer(bgep);
			bgep->asf_status = ASF_STAT_STOP;

			bge_asf_pre_reset_operations(bgep, BGE_INIT_RESET);
			(void) bge_check_acc_handle(bgep, bgep->cfg_handle);
		}
#endif
		bge_chip_stop(bgep, B_TRUE);
		(void) bge_check_acc_handle(bgep, bgep->io_handle);
	}
	mutex_exit(bgep->genlock);

	return (result);
}

/*
 * High-level cyclic handler
 *
 * This routine schedules a (low-level) softint callback to the
 * factotum, and prods the chip to update the status block (which
 * will cause a hardware interrupt when complete).
 */
void bge_chip_cyclic(void *arg);
#pragma	no_inline(bge_chip_cyclic)

void
bge_chip_cyclic(void *arg)
{
	bge_t *bgep;
	uint32_t regval;

	bgep = arg;

	switch (bgep->bge_chip_state) {
	default:
		return;

	case BGE_CHIP_RUNNING:

		/* XXX I really don't like this forced interrupt... */
		bge_reg_set32(bgep, HOST_COALESCE_MODE_REG, COALESCE_NOW);
		if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_UNAFFECTED);

		break;

	case BGE_CHIP_FAULT:
	case BGE_CHIP_ERROR:

		break;
	}

	mutex_enter(bgep->genlock);

	if (bgep->eee_lpi_wait && !--bgep->eee_lpi_wait) {
		BGE_DEBUG(("eee cyclic, lpi enabled"));
		bge_eee_enable(bgep);
	}

	if (bgep->rdma_length_bug_on_5719) {
		if ((bge_reg_get32(bgep, STAT_IFHCOUT_UPKGS_REG) +
		     bge_reg_get32(bgep, STAT_IFHCOUT_MPKGS_REG) +
		     bge_reg_get32(bgep, STAT_IFHCOUT_BPKGS_REG)) >
		    BGE_NUM_RDMA_CHANNELS) {
			regval = bge_reg_get32(bgep, RDMA_CORR_CTRL_REG);
			regval &= ~RDMA_CORR_CTRL_TX_LENGTH_WA;
			bge_reg_put32(bgep, RDMA_CORR_CTRL_REG, regval);
			bgep->rdma_length_bug_on_5719 = B_FALSE;
		}
	}

	mutex_exit(bgep->genlock);

	bge_wake_factotum(bgep);

}


/*
 * ========== Ioctl subfunctions ==========
 */

#undef	BGE_DBG
#define	BGE_DBG		BGE_DBG_PPIO	/* debug flag for this code	*/

#if	BGE_DEBUGGING || BGE_DO_PPIO

static void bge_chip_peek_cfg(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_peek_cfg)

static void
bge_chip_peek_cfg(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint64_t regval;
	uint64_t regno;

	BGE_TRACE(("bge_chip_peek_cfg($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	regno = ppd->pp_acc_offset;

	switch (ppd->pp_acc_size) {
	case 1:
		regval = pci_config_get8(bgep->cfg_handle, regno);
		break;

	case 2:
		regval = pci_config_get16(bgep->cfg_handle, regno);
		break;

	case 4:
		regval = pci_config_get32(bgep->cfg_handle, regno);
		break;

	case 8:
		regval = pci_config_get64(bgep->cfg_handle, regno);
		break;
	}

	ppd->pp_acc_data = regval;
}

static void bge_chip_poke_cfg(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_poke_cfg)

static void
bge_chip_poke_cfg(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint64_t regval;
	uint64_t regno;

	BGE_TRACE(("bge_chip_poke_cfg($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	regno = ppd->pp_acc_offset;
	regval = ppd->pp_acc_data;

	switch (ppd->pp_acc_size) {
	case 1:
		pci_config_put8(bgep->cfg_handle, regno, regval);
		break;

	case 2:
		pci_config_put16(bgep->cfg_handle, regno, regval);
		break;

	case 4:
		pci_config_put32(bgep->cfg_handle, regno, regval);
		break;

	case 8:
		pci_config_put64(bgep->cfg_handle, regno, regval);
		break;
	}
}

static void bge_chip_peek_reg(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_peek_reg)

static void
bge_chip_peek_reg(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint64_t regval;
	void *regaddr;

	BGE_TRACE(("bge_chip_peek_reg($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	regaddr = PIO_ADDR(bgep, ppd->pp_acc_offset);

	switch (ppd->pp_acc_size) {
	case 1:
		regval = ddi_get8(bgep->io_handle, regaddr);
		break;

	case 2:
		regval = ddi_get16(bgep->io_handle, regaddr);
		break;

	case 4:
		regval = ddi_get32(bgep->io_handle, regaddr);
		break;

	case 8:
		regval = ddi_get64(bgep->io_handle, regaddr);
		break;
	}

	ppd->pp_acc_data = regval;
}

static void bge_chip_poke_reg(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_peek_reg)

static void
bge_chip_poke_reg(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint64_t regval;
	void *regaddr;

	BGE_TRACE(("bge_chip_poke_reg($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	regaddr = PIO_ADDR(bgep, ppd->pp_acc_offset);
	regval = ppd->pp_acc_data;

	switch (ppd->pp_acc_size) {
	case 1:
		ddi_put8(bgep->io_handle, regaddr, regval);
		break;

	case 2:
		ddi_put16(bgep->io_handle, regaddr, regval);
		break;

	case 4:
		ddi_put32(bgep->io_handle, regaddr, regval);
		break;

	case 8:
		ddi_put64(bgep->io_handle, regaddr, regval);
		break;
	}
	BGE_PCICHK(bgep);
}

static void bge_chip_peek_nic(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_peek_nic)

static void
bge_chip_peek_nic(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint64_t regoff;
	uint64_t regval;
	void *regaddr;

	BGE_TRACE(("bge_chip_peek_nic($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	regoff = ppd->pp_acc_offset;
	bge_nic_setwin(bgep, regoff & ~MWBAR_GRANULE_MASK);
	regoff &= MWBAR_GRANULE_MASK;
	regoff += NIC_MEM_WINDOW_OFFSET;
	regaddr = PIO_ADDR(bgep, regoff);

	switch (ppd->pp_acc_size) {
	case 1:
		regval = ddi_get8(bgep->io_handle, regaddr);
		break;

	case 2:
		regval = ddi_get16(bgep->io_handle, regaddr);
		break;

	case 4:
		regval = ddi_get32(bgep->io_handle, regaddr);
		break;

	case 8:
		regval = ddi_get64(bgep->io_handle, regaddr);
		break;
	}

	ppd->pp_acc_data = regval;
}

static void bge_chip_poke_nic(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_poke_nic)

static void
bge_chip_poke_nic(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint64_t regoff;
	uint64_t regval;
	void *regaddr;

	BGE_TRACE(("bge_chip_poke_nic($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	regoff = ppd->pp_acc_offset;
	bge_nic_setwin(bgep, regoff & ~MWBAR_GRANULE_MASK);
	regoff &= MWBAR_GRANULE_MASK;
	regoff += NIC_MEM_WINDOW_OFFSET;
	regaddr = PIO_ADDR(bgep, regoff);
	regval = ppd->pp_acc_data;

	switch (ppd->pp_acc_size) {
	case 1:
		ddi_put8(bgep->io_handle, regaddr, regval);
		break;

	case 2:
		ddi_put16(bgep->io_handle, regaddr, regval);
		break;

	case 4:
		ddi_put32(bgep->io_handle, regaddr, regval);
		break;

	case 8:
		ddi_put64(bgep->io_handle, regaddr, regval);
		break;
	}
	BGE_PCICHK(bgep);
}

static void bge_chip_peek_mii(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_peek_mii)

static void
bge_chip_peek_mii(bge_t *bgep, bge_peekpoke_t *ppd)
{
	BGE_TRACE(("bge_chip_peek_mii($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	ppd->pp_acc_data = bge_mii_get16(bgep, ppd->pp_acc_offset/2);
}

static void bge_chip_poke_mii(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_poke_mii)

static void
bge_chip_poke_mii(bge_t *bgep, bge_peekpoke_t *ppd)
{
	BGE_TRACE(("bge_chip_poke_mii($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	bge_mii_put16(bgep, ppd->pp_acc_offset/2, ppd->pp_acc_data);
}

#if	BGE_SEE_IO32

static void bge_chip_peek_seeprom(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_peek_seeprom)

static void
bge_chip_peek_seeprom(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint32_t data;
	int err;

	BGE_TRACE(("bge_chip_peek_seeprom($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	err = bge_nvmem_rw32(bgep, BGE_SEE_READ, ppd->pp_acc_offset, &data);
	ppd->pp_acc_data = err ? ~0ull : data;
}

static void bge_chip_poke_seeprom(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_poke_seeprom)

static void
bge_chip_poke_seeprom(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint32_t data;

	BGE_TRACE(("bge_chip_poke_seeprom($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	data = ppd->pp_acc_data;
	(void) bge_nvmem_rw32(bgep, BGE_SEE_WRITE, ppd->pp_acc_offset, &data);
}
#endif	/* BGE_SEE_IO32 */

#if	BGE_FLASH_IO32

static void bge_chip_peek_flash(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_peek_flash)

static void
bge_chip_peek_flash(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint32_t data;
	int err;

	BGE_TRACE(("bge_chip_peek_flash($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	err = bge_nvmem_rw32(bgep, BGE_FLASH_READ, ppd->pp_acc_offset, &data);
	ppd->pp_acc_data = err ? ~0ull : data;
}

static void bge_chip_poke_flash(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_poke_flash)

static void
bge_chip_poke_flash(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint32_t data;

	BGE_TRACE(("bge_chip_poke_flash($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	data = ppd->pp_acc_data;
	(void) bge_nvmem_rw32(bgep, BGE_FLASH_WRITE,
	    ppd->pp_acc_offset, &data);
}
#endif	/* BGE_FLASH_IO32 */

static void bge_chip_peek_mem(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_peek_mem)

static void
bge_chip_peek_mem(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint64_t regval;
	void *vaddr;

	BGE_TRACE(("bge_chip_peek_bge($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	vaddr = (void *)(uintptr_t)ppd->pp_acc_offset;

	switch (ppd->pp_acc_size) {
	case 1:
		regval = *(uint8_t *)vaddr;
		break;

	case 2:
		regval = *(uint16_t *)vaddr;
		break;

	case 4:
		regval = *(uint32_t *)vaddr;
		break;

	case 8:
		regval = *(uint64_t *)vaddr;
		break;
	}

	BGE_DEBUG(("bge_chip_peek_mem($%p, $%p) peeked 0x%llx from $%p",
	    (void *)bgep, (void *)ppd, regval, vaddr));

	ppd->pp_acc_data = regval;
}

static void bge_chip_poke_mem(bge_t *bgep, bge_peekpoke_t *ppd);
#pragma	no_inline(bge_chip_poke_mem)

static void
bge_chip_poke_mem(bge_t *bgep, bge_peekpoke_t *ppd)
{
	uint64_t regval;
	void *vaddr;

	BGE_TRACE(("bge_chip_poke_mem($%p, $%p)",
	    (void *)bgep, (void *)ppd));

	vaddr = (void *)(uintptr_t)ppd->pp_acc_offset;
	regval = ppd->pp_acc_data;

	BGE_DEBUG(("bge_chip_poke_mem($%p, $%p) poking 0x%llx at $%p",
	    (void *)bgep, (void *)ppd, regval, vaddr));

	switch (ppd->pp_acc_size) {
	case 1:
		*(uint8_t *)vaddr = (uint8_t)regval;
		break;

	case 2:
		*(uint16_t *)vaddr = (uint16_t)regval;
		break;

	case 4:
		*(uint32_t *)vaddr = (uint32_t)regval;
		break;

	case 8:
		*(uint64_t *)vaddr = (uint64_t)regval;
		break;
	}
}

static enum ioc_reply bge_pp_ioctl(bge_t *bgep, int cmd, mblk_t *mp,
					struct iocblk *iocp);
#pragma	no_inline(bge_pp_ioctl)

static enum ioc_reply
bge_pp_ioctl(bge_t *bgep, int cmd, mblk_t *mp, struct iocblk *iocp)
{
	void (*ppfn)(bge_t *bgep, bge_peekpoke_t *ppd);
	bge_peekpoke_t *ppd;
	dma_area_t *areap;
	uint64_t sizemask;
	uint64_t mem_va;
	uint64_t maxoff;
	boolean_t peek;

	switch (cmd) {
	default:
		/* NOTREACHED */
		bge_error(bgep, "bge_pp_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case BGE_PEEK:
		peek = B_TRUE;
		break;

	case BGE_POKE:
		peek = B_FALSE;
		break;
	}

	/*
	 * Validate format of ioctl
	 */
	if (iocp->ioc_count != sizeof (bge_peekpoke_t))
		return (IOC_INVAL);
	if (mp->b_cont == NULL)
		return (IOC_INVAL);
	ppd = (void *)mp->b_cont->b_rptr;

	/*
	 * Validate request parameters
	 */
	switch (ppd->pp_acc_space) {
	default:
		return (IOC_INVAL);

	case BGE_PP_SPACE_CFG:
		/*
		 * Config space
		 */
		sizemask = 8|4|2|1;
		mem_va = 0;
		maxoff = PCI_CONF_HDR_SIZE;
		ppfn = peek ? bge_chip_peek_cfg : bge_chip_poke_cfg;
		break;

	case BGE_PP_SPACE_REG:
		/*
		 * Memory-mapped I/O space
		 */
		sizemask = 8|4|2|1;
		mem_va = 0;
		maxoff = RIAAR_REGISTER_MAX;
		ppfn = peek ? bge_chip_peek_reg : bge_chip_poke_reg;
		break;

	case BGE_PP_SPACE_NIC:
		/*
		 * NIC on-chip memory
		 */
		sizemask = 8|4|2|1;
		mem_va = 0;
		maxoff = MWBAR_ONCHIP_MAX;
		ppfn = peek ? bge_chip_peek_nic : bge_chip_poke_nic;
		break;

	case BGE_PP_SPACE_MII:
		/*
		 * PHY's MII registers
		 * NB: all PHY registers are two bytes, but the
		 * addresses increment in ones (word addressing).
		 * So we scale the address here, then undo the
		 * transformation inside the peek/poke functions.
		 */
		ppd->pp_acc_offset *= 2;
		sizemask = 2;
		mem_va = 0;
		maxoff = (MII_MAXREG+1)*2;
		ppfn = peek ? bge_chip_peek_mii : bge_chip_poke_mii;
		break;

#if	BGE_SEE_IO32
	case BGE_PP_SPACE_SEEPROM:
		/*
		 * Attached SEEPROM(s), if any.
		 * NB: we use the high-order bits of the 'address' as
		 * a device select to accommodate multiple SEEPROMS,
		 * If each one is the maximum size (64kbytes), this
		 * makes them appear contiguous.  Otherwise, there may
		 * be holes in the mapping.  ENxS doesn't have any
		 * SEEPROMs anyway ...
		 */
		sizemask = 4;
		mem_va = 0;
		maxoff = SEEPROM_DEV_AND_ADDR_MASK;
		ppfn = peek ? bge_chip_peek_seeprom : bge_chip_poke_seeprom;
		break;
#endif	/* BGE_SEE_IO32 */

#if	BGE_FLASH_IO32
	case BGE_PP_SPACE_FLASH:
		/*
		 * Attached Flash device (if any); a maximum of one device
		 * is currently supported.  But it can be up to 1MB (unlike
		 * the 64k limit on SEEPROMs) so why would you need more ;-)
		 */
		sizemask = 4;
		mem_va = 0;
		maxoff = NVM_FLASH_ADDR_MASK;
		ppfn = peek ? bge_chip_peek_flash : bge_chip_poke_flash;
		break;
#endif	/* BGE_FLASH_IO32 */

	case BGE_PP_SPACE_BGE:
		/*
		 * BGE data structure!
		 */
		sizemask = 8|4|2|1;
		mem_va = (uintptr_t)bgep;
		maxoff = sizeof (*bgep);
		ppfn = peek ? bge_chip_peek_mem : bge_chip_poke_mem;
		break;

	case BGE_PP_SPACE_STATUS:
	case BGE_PP_SPACE_STATISTICS:
	case BGE_PP_SPACE_TXDESC:
	case BGE_PP_SPACE_TXBUFF:
	case BGE_PP_SPACE_RXDESC:
	case BGE_PP_SPACE_RXBUFF:
		/*
		 * Various DMA_AREAs
		 */
		switch (ppd->pp_acc_space) {
		case BGE_PP_SPACE_TXDESC:
			areap = &bgep->tx_desc;
			break;
		case BGE_PP_SPACE_TXBUFF:
			areap = &bgep->tx_buff[0];
			break;
		case BGE_PP_SPACE_RXDESC:
			areap = &bgep->rx_desc[0];
			break;
		case BGE_PP_SPACE_RXBUFF:
			areap = &bgep->rx_buff[0];
			break;
		case BGE_PP_SPACE_STATUS:
			areap = &bgep->status_block;
			break;
		case BGE_PP_SPACE_STATISTICS:
			if (bgep->chipid.statistic_type == BGE_STAT_BLK)
				areap = &bgep->statistics;
			break;
		}

		sizemask = 8|4|2|1;
		mem_va = (uintptr_t)areap->mem_va;
		maxoff = areap->alength;
		ppfn = peek ? bge_chip_peek_mem : bge_chip_poke_mem;
		break;
	}

	switch (ppd->pp_acc_size) {
	default:
		return (IOC_INVAL);

	case 8:
	case 4:
	case 2:
	case 1:
		if ((ppd->pp_acc_size & sizemask) == 0)
			return (IOC_INVAL);
		break;
	}

	if ((ppd->pp_acc_offset % ppd->pp_acc_size) != 0)
		return (IOC_INVAL);

	if (ppd->pp_acc_offset >= maxoff)
		return (IOC_INVAL);

	if (ppd->pp_acc_offset+ppd->pp_acc_size > maxoff)
		return (IOC_INVAL);

	/*
	 * All OK - go do it!
	 */
	ppd->pp_acc_offset += mem_va;
	(*ppfn)(bgep, ppd);
	return (peek ? IOC_REPLY : IOC_ACK);
}

static enum ioc_reply bge_diag_ioctl(bge_t *bgep, int cmd, mblk_t *mp,
					struct iocblk *iocp);
#pragma	no_inline(bge_diag_ioctl)

static enum ioc_reply
bge_diag_ioctl(bge_t *bgep, int cmd, mblk_t *mp, struct iocblk *iocp)
{
	ASSERT(mutex_owned(bgep->genlock));

	switch (cmd) {
	default:
		/* NOTREACHED */
		bge_error(bgep, "bge_diag_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case BGE_DIAG:
		/*
		 * Currently a no-op
		 */
		return (IOC_ACK);

	case BGE_PEEK:
	case BGE_POKE:
		return (bge_pp_ioctl(bgep, cmd, mp, iocp));

	case BGE_PHY_RESET:
		return (IOC_RESTART_ACK);

	case BGE_SOFT_RESET:
	case BGE_HARD_RESET:
		/*
		 * Reset and reinitialise the 570x hardware
		 */
		bgep->bge_chip_state = BGE_CHIP_FAULT;
		ddi_trigger_softintr(bgep->factotum_id);
		(void) bge_restart(bgep, cmd == BGE_HARD_RESET);
		return (IOC_ACK);
	}

	/* NOTREACHED */
}

#endif	/* BGE_DEBUGGING || BGE_DO_PPIO */

static enum ioc_reply bge_mii_ioctl(bge_t *bgep, int cmd, mblk_t *mp,
				    struct iocblk *iocp);
#pragma	no_inline(bge_mii_ioctl)

static enum ioc_reply
bge_mii_ioctl(bge_t *bgep, int cmd, mblk_t *mp, struct iocblk *iocp)
{
	struct bge_mii_rw *miirwp;

	/*
	 * Validate format of ioctl
	 */
	if (iocp->ioc_count != sizeof (struct bge_mii_rw))
		return (IOC_INVAL);
	if (mp->b_cont == NULL)
		return (IOC_INVAL);
	miirwp = (void *)mp->b_cont->b_rptr;

	/*
	 * Validate request parameters ...
	 */
	if (miirwp->mii_reg > MII_MAXREG)
		return (IOC_INVAL);

	switch (cmd) {
	default:
		/* NOTREACHED */
		bge_error(bgep, "bge_mii_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case BGE_MII_READ:
		miirwp->mii_data = bge_mii_get16(bgep, miirwp->mii_reg);
		return (IOC_REPLY);

	case BGE_MII_WRITE:
		bge_mii_put16(bgep, miirwp->mii_reg, miirwp->mii_data);
		return (IOC_ACK);
	}

	/* NOTREACHED */
}

#if	BGE_SEE_IO32

static enum ioc_reply bge_see_ioctl(bge_t *bgep, int cmd, mblk_t *mp,
				    struct iocblk *iocp);
#pragma	no_inline(bge_see_ioctl)

static enum ioc_reply
bge_see_ioctl(bge_t *bgep, int cmd, mblk_t *mp, struct iocblk *iocp)
{
	struct bge_see_rw *seerwp;

	/*
	 * Validate format of ioctl
	 */
	if (iocp->ioc_count != sizeof (struct bge_see_rw))
		return (IOC_INVAL);
	if (mp->b_cont == NULL)
		return (IOC_INVAL);
	seerwp = (void *)mp->b_cont->b_rptr;

	/*
	 * Validate request parameters ...
	 */
	if (seerwp->see_addr & ~SEEPROM_DEV_AND_ADDR_MASK)
		return (IOC_INVAL);

	switch (cmd) {
	default:
		/* NOTREACHED */
		bge_error(bgep, "bge_see_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case BGE_SEE_READ:
	case BGE_SEE_WRITE:
		iocp->ioc_error = bge_nvmem_rw32(bgep, cmd,
		    seerwp->see_addr, &seerwp->see_data);
		return (IOC_REPLY);
	}

	/* NOTREACHED */
}

#endif	/* BGE_SEE_IO32 */

#if	BGE_FLASH_IO32

static enum ioc_reply bge_flash_ioctl(bge_t *bgep, int cmd, mblk_t *mp,
				    struct iocblk *iocp);
#pragma	no_inline(bge_flash_ioctl)

static enum ioc_reply
bge_flash_ioctl(bge_t *bgep, int cmd, mblk_t *mp, struct iocblk *iocp)
{
	struct bge_flash_rw *flashrwp;

	/*
	 * Validate format of ioctl
	 */
	if (iocp->ioc_count != sizeof (struct bge_flash_rw))
		return (IOC_INVAL);
	if (mp->b_cont == NULL)
		return (IOC_INVAL);
	flashrwp = (void *)mp->b_cont->b_rptr;

	/*
	 * Validate request parameters ...
	 */
	if (flashrwp->flash_addr & ~NVM_FLASH_ADDR_MASK)
		return (IOC_INVAL);

	switch (cmd) {
	default:
		/* NOTREACHED */
		bge_error(bgep, "bge_flash_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case BGE_FLASH_READ:
	case BGE_FLASH_WRITE:
		iocp->ioc_error = bge_nvmem_rw32(bgep, cmd,
		    flashrwp->flash_addr, &flashrwp->flash_data);
		return (IOC_REPLY);
	}

	/* NOTREACHED */
}

#endif	/* BGE_FLASH_IO32 */

enum ioc_reply bge_chip_ioctl(bge_t *bgep, queue_t *wq, mblk_t *mp,
				struct iocblk *iocp);
#pragma	no_inline(bge_chip_ioctl)

enum ioc_reply
bge_chip_ioctl(bge_t *bgep, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	int cmd;

	BGE_TRACE(("bge_chip_ioctl($%p, $%p, $%p, $%p)",
	    (void *)bgep, (void *)wq, (void *)mp, (void *)iocp));

	ASSERT(mutex_owned(bgep->genlock));

	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		/* NOTREACHED */
		bge_error(bgep, "bge_chip_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case BGE_DIAG:
	case BGE_PEEK:
	case BGE_POKE:
	case BGE_PHY_RESET:
	case BGE_SOFT_RESET:
	case BGE_HARD_RESET:
#if	BGE_DEBUGGING || BGE_DO_PPIO
		return (bge_diag_ioctl(bgep, cmd, mp, iocp));
#else
		return (IOC_INVAL);
#endif	/* BGE_DEBUGGING || BGE_DO_PPIO */

	case BGE_MII_READ:
	case BGE_MII_WRITE:
		return (bge_mii_ioctl(bgep, cmd, mp, iocp));

#if	BGE_SEE_IO32
	case BGE_SEE_READ:
	case BGE_SEE_WRITE:
		return (bge_see_ioctl(bgep, cmd, mp, iocp));
#endif	/* BGE_SEE_IO32 */

#if	BGE_FLASH_IO32
	case BGE_FLASH_READ:
	case BGE_FLASH_WRITE:
		return (bge_flash_ioctl(bgep, cmd, mp, iocp));
#endif	/* BGE_FLASH_IO32 */
	}

	/* NOTREACHED */
}

/* ARGSUSED */
void
bge_chip_blank(void *arg, time_t ticks, uint_t count, int flag)
{
	recv_ring_t *rrp = arg;
	bge_t *bgep = rrp->bgep;

	mutex_enter(bgep->genlock);
	rrp->poll_flag = flag;
#ifdef NOT_YET
	/*
	 * XXX-Sunay: Since most broadcom cards support only one
	 * interrupt but multiple rx rings, we can't disable the
	 * physical interrupt. This need to be done via capability
	 * negotiation depending on the NIC.
	 */
	bge_reg_put32(bgep, RCV_COALESCE_TICKS_REG, ticks);
	bge_reg_put32(bgep, RCV_COALESCE_MAX_BD_REG, count);
#endif
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_UNAFFECTED);
	mutex_exit(bgep->genlock);
}

#ifdef BGE_IPMI_ASF

uint32_t
bge_nic_read32(bge_t *bgep, bge_regno_t addr)
{
	uint32_t data;

#ifndef __sparc
	if (!bgep->asf_wordswapped) {
		/* a workaround word swap error */
		if (addr & 4)
			addr = addr - 4;
		else
			addr = addr + 4;
	}
#else
	if (DEVICE_5717_SERIES_CHIPSETS(bgep) ||
	    DEVICE_5725_SERIES_CHIPSETS(bgep)) {
		addr = LE_32(addr);
	}
#endif

	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MWBAR, addr);
	data = pci_config_get32(bgep->cfg_handle, PCI_CONF_BGE_MWDAR);
	pci_config_put32(bgep->cfg_handle, PCI_CONF_BGE_MWBAR, 0);

	data = LE_32(data);

	BGE_DEBUG(("bge_nic_read32($%p, 0x%x) => 0x%x",
	    (void *)bgep, addr, data));

	return (data);
}

void
bge_asf_update_status(bge_t *bgep)
{
	uint32_t event;

	bge_nic_put32(bgep, BGE_CMD_MAILBOX, BGE_CMD_NICDRV_ALIVE);
	bge_nic_put32(bgep, BGE_CMD_LENGTH_MAILBOX, 4);
	bge_nic_put32(bgep, BGE_CMD_DATA_MAILBOX,   3);

	event = bge_reg_get32(bgep, RX_RISC_EVENT_REG);
	bge_reg_put32(bgep, RX_RISC_EVENT_REG, event | RRER_ASF_EVENT);
}


/*
 * The driver is supposed to notify ASF that the OS is still running
 * every three seconds, otherwise the management server may attempt
 * to reboot the machine.  If it hasn't actually failed, this is
 * not a desirable result.  However, this isn't running as a real-time
 * thread, and even if it were, it might not be able to generate the
 * heartbeat in a timely manner due to system load.  As it isn't a
 * significant strain on the machine, we will set the interval to half
 * of the required value.
 */
void
bge_asf_heartbeat(void *arg)
{
	bge_t *bgep = (bge_t *)arg;

	mutex_enter(bgep->genlock);
	bge_asf_update_status((bge_t *)bgep);
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK)
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
	if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
	mutex_exit(bgep->genlock);
	((bge_t *)bgep)->asf_timeout_id = timeout(bge_asf_heartbeat, bgep,
	    drv_usectohz(BGE_ASF_HEARTBEAT_INTERVAL));
}


void
bge_asf_stop_timer(bge_t *bgep)
{
	timeout_id_t tmp_id = 0;

	while ((bgep->asf_timeout_id != 0) &&
	    (tmp_id != bgep->asf_timeout_id)) {
		tmp_id = bgep->asf_timeout_id;
		(void) untimeout(tmp_id);
	}
	bgep->asf_timeout_id = 0;
}



/*
 * This function should be placed at the earliest position of bge_attach().
 */
void
bge_asf_get_config(bge_t *bgep)
{
	uint32_t nicsig;
	uint32_t niccfg;

	bgep->asf_enabled = B_FALSE;
	nicsig = bge_nic_read32(bgep, BGE_NIC_DATA_SIG_ADDR);
	if (nicsig == BGE_NIC_DATA_SIG) {
		niccfg = bge_nic_read32(bgep, BGE_NIC_DATA_NIC_CFG_ADDR);
		if (niccfg & BGE_NIC_CFG_ENABLE_ASF)
			/*
			 * Here, we don't consider BAXTER, because BGE haven't
			 * supported BAXTER (that is 5752). Also, as I know,
			 * BAXTER doesn't support ASF feature.
			 */
			bgep->asf_enabled = B_TRUE;
		else
			bgep->asf_enabled = B_FALSE;
	} else
		bgep->asf_enabled = B_FALSE;
}


void
bge_asf_pre_reset_operations(bge_t *bgep, uint32_t mode)
{
	uint32_t tries;
	uint32_t event;

	ASSERT(bgep->asf_enabled);

	/* Issues "pause firmware" command and wait for ACK */
	bge_nic_put32(bgep, BGE_CMD_MAILBOX, BGE_CMD_NICDRV_PAUSE_FW);
	event = bge_reg_get32(bgep, RX_RISC_EVENT_REG);
	bge_reg_put32(bgep, RX_RISC_EVENT_REG, event | RRER_ASF_EVENT);

	event = bge_reg_get32(bgep, RX_RISC_EVENT_REG);
	tries = 0;
	while ((event & RRER_ASF_EVENT) && (tries < 100)) {
		drv_usecwait(1);
		tries ++;
		event = bge_reg_get32(bgep, RX_RISC_EVENT_REG);
	}

	bge_nic_put32(bgep, BGE_FIRMWARE_MAILBOX,
	    BGE_MAGIC_NUM_FIRMWARE_INIT_DONE);

	if (bgep->asf_newhandshake) {
		switch (mode) {
		case BGE_INIT_RESET:
			bge_nic_put32(bgep, BGE_DRV_STATE_MAILBOX,
			    BGE_DRV_STATE_START);
			break;
		case BGE_SHUTDOWN_RESET:
			bge_nic_put32(bgep, BGE_DRV_STATE_MAILBOX,
			    BGE_DRV_STATE_UNLOAD);
			break;
		case BGE_SUSPEND_RESET:
			bge_nic_put32(bgep, BGE_DRV_STATE_MAILBOX,
			    BGE_DRV_STATE_SUSPEND);
			break;
		default:
			break;
		}
	}

	if (mode == BGE_INIT_RESET ||
	    mode == BGE_SUSPEND_RESET)
		bge_ape_driver_state_change(bgep, mode);
}


void
bge_asf_post_reset_old_mode(bge_t *bgep, uint32_t mode)
{
	switch (mode) {
	case BGE_INIT_RESET:
		bge_nic_put32(bgep, BGE_DRV_STATE_MAILBOX,
		    BGE_DRV_STATE_START);
		break;
	case BGE_SHUTDOWN_RESET:
		bge_nic_put32(bgep, BGE_DRV_STATE_MAILBOX,
		    BGE_DRV_STATE_UNLOAD);
		break;
	case BGE_SUSPEND_RESET:
		bge_nic_put32(bgep, BGE_DRV_STATE_MAILBOX,
		    BGE_DRV_STATE_SUSPEND);
		break;
	default:
		break;
	}
}


void
bge_asf_post_reset_new_mode(bge_t *bgep, uint32_t mode)
{
	switch (mode) {
	case BGE_INIT_RESET:
		bge_nic_put32(bgep, BGE_DRV_STATE_MAILBOX,
		    BGE_DRV_STATE_START_DONE);
		break;
	case BGE_SHUTDOWN_RESET:
		bge_nic_put32(bgep, BGE_DRV_STATE_MAILBOX,
		    BGE_DRV_STATE_UNLOAD_DONE);
		break;
	default:
		break;
	}

	if (mode == BGE_SHUTDOWN_RESET)
		bge_ape_driver_state_change(bgep, mode);
}

#endif /* BGE_IPMI_ASF */
