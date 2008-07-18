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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/vmsystm.h>
#include <sys/vmem.h>
#include <sys/machsystm.h>	/* lddphys() */
#include <sys/iommutsb.h>
#include <sys/pci.h>
#include <sys/hotplug/pci/pciehpc.h>
#include <pcie_pwr.h>
#include <px_obj.h>
#include "px_regs.h"
#include "oberon_regs.h"
#include "px_csr.h"
#include "px_lib4u.h"
#include "px_err.h"

/*
 * Registers that need to be saved and restored during suspend/resume.
 */

/*
 * Registers in the PEC Module.
 * LPU_RESET should be set to 0ull during resume
 *
 * This array is in reg,chip form. PX_CHIP_UNIDENTIFIED is for all chips
 * or PX_CHIP_FIRE for Fire only, or PX_CHIP_OBERON for Oberon only.
 */
static struct px_pec_regs {
	uint64_t reg;
	uint64_t chip;
} pec_config_state_regs[] = {
	{PEC_CORE_AND_BLOCK_INTERRUPT_ENABLE, PX_CHIP_UNIDENTIFIED},
	{ILU_ERROR_LOG_ENABLE, PX_CHIP_UNIDENTIFIED},
	{ILU_INTERRUPT_ENABLE, PX_CHIP_UNIDENTIFIED},
	{TLU_CONTROL, PX_CHIP_UNIDENTIFIED},
	{TLU_OTHER_EVENT_LOG_ENABLE, PX_CHIP_UNIDENTIFIED},
	{TLU_OTHER_EVENT_INTERRUPT_ENABLE, PX_CHIP_UNIDENTIFIED},
	{TLU_DEVICE_CONTROL, PX_CHIP_UNIDENTIFIED},
	{TLU_LINK_CONTROL, PX_CHIP_UNIDENTIFIED},
	{TLU_UNCORRECTABLE_ERROR_LOG_ENABLE, PX_CHIP_UNIDENTIFIED},
	{TLU_UNCORRECTABLE_ERROR_INTERRUPT_ENABLE, PX_CHIP_UNIDENTIFIED},
	{TLU_CORRECTABLE_ERROR_LOG_ENABLE, PX_CHIP_UNIDENTIFIED},
	{TLU_CORRECTABLE_ERROR_INTERRUPT_ENABLE, PX_CHIP_UNIDENTIFIED},
	{DLU_LINK_LAYER_CONFIG, PX_CHIP_OBERON},
	{DLU_FLOW_CONTROL_UPDATE_CONTROL, PX_CHIP_OBERON},
	{DLU_TXLINK_REPLAY_TIMER_THRESHOLD, PX_CHIP_OBERON},
	{LPU_LINK_LAYER_INTERRUPT_MASK, PX_CHIP_FIRE},
	{LPU_PHY_INTERRUPT_MASK, PX_CHIP_FIRE},
	{LPU_RECEIVE_PHY_INTERRUPT_MASK, PX_CHIP_FIRE},
	{LPU_TRANSMIT_PHY_INTERRUPT_MASK, PX_CHIP_FIRE},
	{LPU_GIGABLAZE_GLUE_INTERRUPT_MASK, PX_CHIP_FIRE},
	{LPU_LTSSM_INTERRUPT_MASK, PX_CHIP_FIRE},
	{LPU_RESET, PX_CHIP_FIRE},
	{LPU_DEBUG_CONFIG, PX_CHIP_FIRE},
	{LPU_INTERRUPT_MASK, PX_CHIP_FIRE},
	{LPU_LINK_LAYER_CONFIG, PX_CHIP_FIRE},
	{LPU_FLOW_CONTROL_UPDATE_CONTROL, PX_CHIP_FIRE},
	{LPU_TXLINK_FREQUENT_NAK_LATENCY_TIMER_THRESHOLD, PX_CHIP_FIRE},
	{LPU_TXLINK_REPLAY_TIMER_THRESHOLD, PX_CHIP_FIRE},
	{LPU_REPLAY_BUFFER_MAX_ADDRESS, PX_CHIP_FIRE},
	{LPU_TXLINK_RETRY_FIFO_POINTER, PX_CHIP_FIRE},
	{LPU_LTSSM_CONFIG2, PX_CHIP_FIRE},
	{LPU_LTSSM_CONFIG3, PX_CHIP_FIRE},
	{LPU_LTSSM_CONFIG4, PX_CHIP_FIRE},
	{LPU_LTSSM_CONFIG5, PX_CHIP_FIRE},
	{DMC_CORE_AND_BLOCK_INTERRUPT_ENABLE, PX_CHIP_UNIDENTIFIED},
	{DMC_DEBUG_SELECT_FOR_PORT_A, PX_CHIP_UNIDENTIFIED},
	{DMC_DEBUG_SELECT_FOR_PORT_B, PX_CHIP_UNIDENTIFIED}
};

#define	PEC_KEYS	\
	((sizeof (pec_config_state_regs))/sizeof (struct px_pec_regs))

#define	PEC_SIZE	(PEC_KEYS * sizeof (uint64_t))

/*
 * Registers for the MMU module.
 * MMU_TTE_CACHE_INVALIDATE needs to be cleared. (-1ull)
 */
static uint64_t mmu_config_state_regs[] = {
	MMU_TSB_CONTROL,
	MMU_CONTROL_AND_STATUS,
	MMU_ERROR_LOG_ENABLE,
	MMU_INTERRUPT_ENABLE
};
#define	MMU_SIZE (sizeof (mmu_config_state_regs))
#define	MMU_KEYS (MMU_SIZE / sizeof (uint64_t))

/*
 * Registers for the IB Module
 */
static uint64_t ib_config_state_regs[] = {
	IMU_ERROR_LOG_ENABLE,
	IMU_INTERRUPT_ENABLE
};
#define	IB_SIZE (sizeof (ib_config_state_regs))
#define	IB_KEYS (IB_SIZE / sizeof (uint64_t))
#define	IB_MAP_SIZE (INTERRUPT_MAPPING_ENTRIES * sizeof (uint64_t))

/*
 * Registers for the JBC module.
 * JBC_ERROR_STATUS_CLEAR needs to be cleared. (-1ull)
 */
static uint64_t	jbc_config_state_regs[] = {
	JBUS_PARITY_CONTROL,
	JBC_FATAL_RESET_ENABLE,
	JBC_CORE_AND_BLOCK_INTERRUPT_ENABLE,
	JBC_ERROR_LOG_ENABLE,
	JBC_INTERRUPT_ENABLE
};
#define	JBC_SIZE (sizeof (jbc_config_state_regs))
#define	JBC_KEYS (JBC_SIZE / sizeof (uint64_t))

/*
 * Registers for the UBC module.
 * UBC_ERROR_STATUS_CLEAR needs to be cleared. (-1ull)
 */
static uint64_t	ubc_config_state_regs[] = {
	UBC_ERROR_LOG_ENABLE,
	UBC_INTERRUPT_ENABLE
};
#define	UBC_SIZE (sizeof (ubc_config_state_regs))
#define	UBC_KEYS (UBC_SIZE / sizeof (uint64_t))

static uint64_t	msiq_config_other_regs[] = {
	ERR_COR_MAPPING,
	ERR_NONFATAL_MAPPING,
	ERR_FATAL_MAPPING,
	PM_PME_MAPPING,
	PME_TO_ACK_MAPPING,
	MSI_32_BIT_ADDRESS,
	MSI_64_BIT_ADDRESS
};
#define	MSIQ_OTHER_SIZE	(sizeof (msiq_config_other_regs))
#define	MSIQ_OTHER_KEYS	(MSIQ_OTHER_SIZE / sizeof (uint64_t))

#define	MSIQ_STATE_SIZE		(EVENT_QUEUE_STATE_ENTRIES * sizeof (uint64_t))
#define	MSIQ_MAPPING_SIZE	(MSI_MAPPING_ENTRIES * sizeof (uint64_t))

/* OPL tuning variables for link unstable issue */
int wait_perst = 5000000; 	/* step 9, default: 5s */
int wait_enable_port = 30000;	/* step 11, default: 30ms */
int link_retry_count = 2; 	/* step 11, default: 2 */
int link_status_check = 400000;	/* step 11, default: 400ms */

static uint64_t msiq_suspend(devhandle_t dev_hdl, pxu_t *pxu_p);
static void msiq_resume(devhandle_t dev_hdl, pxu_t *pxu_p);
static void jbc_init(caddr_t xbc_csr_base, pxu_t *pxu_p);
static void ubc_init(caddr_t xbc_csr_base, pxu_t *pxu_p);

/*
 * Initialize the bus, but do not enable interrupts.
 */
/* ARGSUSED */
void
hvio_cb_init(caddr_t xbc_csr_base, pxu_t *pxu_p)
{
	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		ubc_init(xbc_csr_base, pxu_p);
		break;
	case PX_CHIP_FIRE:
		jbc_init(xbc_csr_base, pxu_p);
		break;
	default:
		DBG(DBG_CB, NULL, "hvio_cb_init - unknown chip type: 0x%x\n",
		    PX_CHIP_TYPE(pxu_p));
		break;
	}
}

/*
 * Initialize the JBC module, but do not enable interrupts.
 */
/* ARGSUSED */
static void
jbc_init(caddr_t xbc_csr_base, pxu_t *pxu_p)
{
	uint64_t val;

	/* Check if we need to enable inverted parity */
	val = (1ULL << JBUS_PARITY_CONTROL_P_EN);
	CSR_XS(xbc_csr_base, JBUS_PARITY_CONTROL, val);
	DBG(DBG_CB, NULL, "jbc_init, JBUS_PARITY_CONTROL: 0x%llx\n",
	    CSR_XR(xbc_csr_base, JBUS_PARITY_CONTROL));

	val = (1 << JBC_FATAL_RESET_ENABLE_SPARE_P_INT_EN) |
	    (1 << JBC_FATAL_RESET_ENABLE_MB_PEA_P_INT_EN) |
	    (1 << JBC_FATAL_RESET_ENABLE_CPE_P_INT_EN) |
	    (1 << JBC_FATAL_RESET_ENABLE_APE_P_INT_EN) |
	    (1 << JBC_FATAL_RESET_ENABLE_PIO_CPE_INT_EN) |
	    (1 << JBC_FATAL_RESET_ENABLE_JTCEEW_P_INT_EN) |
	    (1 << JBC_FATAL_RESET_ENABLE_JTCEEI_P_INT_EN) |
	    (1 << JBC_FATAL_RESET_ENABLE_JTCEER_P_INT_EN);
	CSR_XS(xbc_csr_base, JBC_FATAL_RESET_ENABLE, val);
	DBG(DBG_CB, NULL, "jbc_init, JBC_FATAL_RESET_ENABLE: 0x%llx\n",
	    CSR_XR(xbc_csr_base, JBC_FATAL_RESET_ENABLE));

	/*
	 * Enable merge, jbc and dmc interrupts.
	 */
	CSR_XS(xbc_csr_base, JBC_CORE_AND_BLOCK_INTERRUPT_ENABLE, -1ull);
	DBG(DBG_CB, NULL,
	    "jbc_init, JBC_CORE_AND_BLOCK_INTERRUPT_ENABLE: 0x%llx\n",
	    CSR_XR(xbc_csr_base, JBC_CORE_AND_BLOCK_INTERRUPT_ENABLE));

	/*
	 * CSR_V JBC's interrupt regs (log, enable, status, clear)
	 */
	DBG(DBG_CB, NULL, "jbc_init, JBC_ERROR_LOG_ENABLE: 0x%llx\n",
	    CSR_XR(xbc_csr_base, JBC_ERROR_LOG_ENABLE));

	DBG(DBG_CB, NULL, "jbc_init, JBC_INTERRUPT_ENABLE: 0x%llx\n",
	    CSR_XR(xbc_csr_base, JBC_INTERRUPT_ENABLE));

	DBG(DBG_CB, NULL, "jbc_init, JBC_INTERRUPT_STATUS: 0x%llx\n",
	    CSR_XR(xbc_csr_base, JBC_INTERRUPT_STATUS));

	DBG(DBG_CB, NULL, "jbc_init, JBC_ERROR_STATUS_CLEAR: 0x%llx\n",
	    CSR_XR(xbc_csr_base, JBC_ERROR_STATUS_CLEAR));
}

/*
 * Initialize the UBC module, but do not enable interrupts.
 */
/* ARGSUSED */
static void
ubc_init(caddr_t xbc_csr_base, pxu_t *pxu_p)
{
	/*
	 * Enable Uranus bus error log bits.
	 */
	CSR_XS(xbc_csr_base, UBC_ERROR_LOG_ENABLE, -1ull);
	DBG(DBG_CB, NULL, "ubc_init, UBC_ERROR_LOG_ENABLE: 0x%llx\n",
	    CSR_XR(xbc_csr_base, UBC_ERROR_LOG_ENABLE));

	/*
	 * Clear Uranus bus errors.
	 */
	CSR_XS(xbc_csr_base, UBC_ERROR_STATUS_CLEAR, -1ull);
	DBG(DBG_CB, NULL, "ubc_init, UBC_ERROR_STATUS_CLEAR: 0x%llx\n",
	    CSR_XR(xbc_csr_base, UBC_ERROR_STATUS_CLEAR));

	/*
	 * CSR_V UBC's interrupt regs (log, enable, status, clear)
	 */
	DBG(DBG_CB, NULL, "ubc_init, UBC_ERROR_LOG_ENABLE: 0x%llx\n",
	    CSR_XR(xbc_csr_base, UBC_ERROR_LOG_ENABLE));

	DBG(DBG_CB, NULL, "ubc_init, UBC_INTERRUPT_ENABLE: 0x%llx\n",
	    CSR_XR(xbc_csr_base, UBC_INTERRUPT_ENABLE));

	DBG(DBG_CB, NULL, "ubc_init, UBC_INTERRUPT_STATUS: 0x%llx\n",
	    CSR_XR(xbc_csr_base, UBC_INTERRUPT_STATUS));

	DBG(DBG_CB, NULL, "ubc_init, UBC_ERROR_STATUS_CLEAR: 0x%llx\n",
	    CSR_XR(xbc_csr_base, UBC_ERROR_STATUS_CLEAR));
}

/*
 * Initialize the module, but do not enable interrupts.
 */
/* ARGSUSED */
void
hvio_ib_init(caddr_t csr_base, pxu_t *pxu_p)
{
	/*
	 * CSR_V IB's interrupt regs (log, enable, status, clear)
	 */
	DBG(DBG_IB, NULL, "hvio_ib_init - IMU_ERROR_LOG_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, IMU_ERROR_LOG_ENABLE));

	DBG(DBG_IB, NULL, "hvio_ib_init - IMU_INTERRUPT_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, IMU_INTERRUPT_ENABLE));

	DBG(DBG_IB, NULL, "hvio_ib_init - IMU_INTERRUPT_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, IMU_INTERRUPT_STATUS));

	DBG(DBG_IB, NULL, "hvio_ib_init - IMU_ERROR_STATUS_CLEAR: 0x%llx\n",
	    CSR_XR(csr_base, IMU_ERROR_STATUS_CLEAR));
}

/*
 * Initialize the module, but do not enable interrupts.
 */
/* ARGSUSED */
static void
ilu_init(caddr_t csr_base, pxu_t *pxu_p)
{
	/*
	 * CSR_V ILU's interrupt regs (log, enable, status, clear)
	 */
	DBG(DBG_ILU, NULL, "ilu_init - ILU_ERROR_LOG_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, ILU_ERROR_LOG_ENABLE));

	DBG(DBG_ILU, NULL, "ilu_init - ILU_INTERRUPT_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, ILU_INTERRUPT_ENABLE));

	DBG(DBG_ILU, NULL, "ilu_init - ILU_INTERRUPT_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, ILU_INTERRUPT_STATUS));

	DBG(DBG_ILU, NULL, "ilu_init - ILU_ERROR_STATUS_CLEAR: 0x%llx\n",
	    CSR_XR(csr_base, ILU_ERROR_STATUS_CLEAR));
}

/*
 * Initialize the module, but do not enable interrupts.
 */
/* ARGSUSED */
static void
tlu_init(caddr_t csr_base, pxu_t *pxu_p)
{
	uint64_t val;

	/*
	 * CSR_V TLU_CONTROL Expect OBP ???
	 */

	/*
	 * L0s entry default timer value - 7.0 us
	 * Completion timeout select default value - 67.1 ms and
	 * OBP will set this value.
	 *
	 * Configuration - Bit 0 should always be 0 for upstream port.
	 * Bit 1 is clock - how is this related to the clock bit in TLU
	 * Link Control register?  Both are hardware dependent and likely
	 * set by OBP.
	 *
	 * NOTE: Do not set the NPWR_EN bit.  The desired value of this bit
	 * will be set by OBP.
	 */
	val = CSR_XR(csr_base, TLU_CONTROL);
	val |= (TLU_CONTROL_L0S_TIM_DEFAULT << TLU_CONTROL_L0S_TIM) |
	    TLU_CONTROL_CONFIG_DEFAULT;

	/*
	 * For Oberon, NPWR_EN is set to 0 to prevent PIO reads from blocking
	 * behind non-posted PIO writes. This blocking could cause a master or
	 * slave timeout on the host bus if multiple serialized PIOs were to
	 * suffer Completion Timeouts because the CTO delays for each PIO ahead
	 * of the read would accumulate. Since the Olympus processor can have
	 * only 1 PIO outstanding, there is no possibility of PIO accesses from
	 * a given CPU to a given device being re-ordered by the PCIe fabric;
	 * therefore turning off serialization should be safe from a PCIe
	 * ordering perspective.
	 */
	if (PX_CHIP_TYPE(pxu_p) == PX_CHIP_OBERON)
		val &= ~(1ull << TLU_CONTROL_NPWR_EN);

	/*
	 * Set Detect.Quiet. This will disable automatic link
	 * re-training, if the link goes down e.g. power management
	 * turns off power to the downstream device. This will enable
	 * Fire to go to Drain state, after link down. The drain state
	 * forces a reset to the FC state machine, which is required for
	 * proper link re-training.
	 */
	val |= (1ull << TLU_REMAIN_DETECT_QUIET);
	CSR_XS(csr_base, TLU_CONTROL, val);
	DBG(DBG_TLU, NULL, "tlu_init - TLU_CONTROL: 0x%llx\n",
	    CSR_XR(csr_base, TLU_CONTROL));

	/*
	 * CSR_V TLU_STATUS Expect HW 0x4
	 */

	/*
	 * Only bit [7:0] are currently defined.  Bits [2:0]
	 * are the state, which should likely be in state active,
	 * 100b.  Bit three is 'recovery', which is not understood.
	 * All other bits are reserved.
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, TLU_STATUS));

	/*
	 * CSR_V TLU_PME_TURN_OFF_GENERATE Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_PME_TURN_OFF_GENERATE: 0x%llx\n",
	    CSR_XR(csr_base, TLU_PME_TURN_OFF_GENERATE));

	/*
	 * CSR_V TLU_INGRESS_CREDITS_INITIAL Expect HW 0x10000200C0
	 */

	/*
	 * Ingress credits initial register.  Bits [39:32] should be
	 * 0x10, bits [19:12] should be 0x20, and bits [11:0] should
	 * be 0xC0.  These are the reset values, and should be set by
	 * HW.
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_INGRESS_CREDITS_INITIAL: 0x%llx\n",
	    CSR_XR(csr_base, TLU_INGRESS_CREDITS_INITIAL));

	/*
	 * CSR_V TLU_DIAGNOSTIC Expect HW 0x0
	 */

	/*
	 * Diagnostic register - always zero unless we are debugging.
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_DIAGNOSTIC: 0x%llx\n",
	    CSR_XR(csr_base, TLU_DIAGNOSTIC));

	/*
	 * CSR_V TLU_EGRESS_CREDITS_CONSUMED Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_EGRESS_CREDITS_CONSUMED: 0x%llx\n",
	    CSR_XR(csr_base, TLU_EGRESS_CREDITS_CONSUMED));

	/*
	 * CSR_V TLU_EGRESS_CREDIT_LIMIT Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_EGRESS_CREDIT_LIMIT: 0x%llx\n",
	    CSR_XR(csr_base, TLU_EGRESS_CREDIT_LIMIT));

	/*
	 * CSR_V TLU_EGRESS_RETRY_BUFFER Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_EGRESS_RETRY_BUFFER: 0x%llx\n",
	    CSR_XR(csr_base, TLU_EGRESS_RETRY_BUFFER));

	/*
	 * CSR_V TLU_INGRESS_CREDITS_ALLOCATED Expected HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_INGRESS_CREDITS_ALLOCATED: 0x%llx\n",
	    CSR_XR(csr_base, TLU_INGRESS_CREDITS_ALLOCATED));

	/*
	 * CSR_V TLU_INGRESS_CREDITS_RECEIVED Expected HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_INGRESS_CREDITS_RECEIVED: 0x%llx\n",
	    CSR_XR(csr_base, TLU_INGRESS_CREDITS_RECEIVED));

	/*
	 * CSR_V TLU's interrupt regs (log, enable, status, clear)
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_OTHER_EVENT_LOG_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, TLU_OTHER_EVENT_LOG_ENABLE));

	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_OTHER_EVENT_INTERRUPT_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, TLU_OTHER_EVENT_INTERRUPT_ENABLE));

	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_OTHER_EVENT_INTERRUPT_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, TLU_OTHER_EVENT_INTERRUPT_STATUS));

	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_OTHER_EVENT_STATUS_CLEAR: 0x%llx\n",
	    CSR_XR(csr_base, TLU_OTHER_EVENT_STATUS_CLEAR));

	/*
	 * CSR_V TLU_RECEIVE_OTHER_EVENT_HEADER1_LOG Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_RECEIVE_OTHER_EVENT_HEADER1_LOG: 0x%llx\n",
	    CSR_XR(csr_base, TLU_RECEIVE_OTHER_EVENT_HEADER1_LOG));

	/*
	 * CSR_V TLU_RECEIVE_OTHER_EVENT_HEADER2_LOG Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_RECEIVE_OTHER_EVENT_HEADER2_LOG: 0x%llx\n",
	    CSR_XR(csr_base, TLU_RECEIVE_OTHER_EVENT_HEADER2_LOG));

	/*
	 * CSR_V TLU_TRANSMIT_OTHER_EVENT_HEADER1_LOG Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_TRANSMIT_OTHER_EVENT_HEADER1_LOG: 0x%llx\n",
	    CSR_XR(csr_base, TLU_TRANSMIT_OTHER_EVENT_HEADER1_LOG));

	/*
	 * CSR_V TLU_TRANSMIT_OTHER_EVENT_HEADER2_LOG Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_TRANSMIT_OTHER_EVENT_HEADER2_LOG: 0x%llx\n",
	    CSR_XR(csr_base, TLU_TRANSMIT_OTHER_EVENT_HEADER2_LOG));

	/*
	 * CSR_V TLU_PERFORMANCE_COUNTER_SELECT Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_PERFORMANCE_COUNTER_SELECT: 0x%llx\n",
	    CSR_XR(csr_base, TLU_PERFORMANCE_COUNTER_SELECT));

	/*
	 * CSR_V TLU_PERFORMANCE_COUNTER_ZERO Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_PERFORMANCE_COUNTER_ZERO: 0x%llx\n",
	    CSR_XR(csr_base, TLU_PERFORMANCE_COUNTER_ZERO));

	/*
	 * CSR_V TLU_PERFORMANCE_COUNTER_ONE Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_PERFORMANCE_COUNTER_ONE: 0x%llx\n",
	    CSR_XR(csr_base, TLU_PERFORMANCE_COUNTER_ONE));

	/*
	 * CSR_V TLU_PERFORMANCE_COUNTER_TWO Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_PERFORMANCE_COUNTER_TWO: 0x%llx\n",
	    CSR_XR(csr_base, TLU_PERFORMANCE_COUNTER_TWO));

	/*
	 * CSR_V TLU_DEBUG_SELECT_A Expect HW 0x0
	 */

	DBG(DBG_TLU, NULL, "tlu_init - TLU_DEBUG_SELECT_A: 0x%llx\n",
	    CSR_XR(csr_base, TLU_DEBUG_SELECT_A));

	/*
	 * CSR_V TLU_DEBUG_SELECT_B Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_DEBUG_SELECT_B: 0x%llx\n",
	    CSR_XR(csr_base, TLU_DEBUG_SELECT_B));

	/*
	 * CSR_V TLU_DEVICE_CAPABILITIES Expect HW 0xFC2
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_DEVICE_CAPABILITIES: 0x%llx\n",
	    CSR_XR(csr_base, TLU_DEVICE_CAPABILITIES));

	/*
	 * CSR_V TLU_DEVICE_CONTROL Expect HW 0x0
	 */

	/*
	 * Bits [14:12] are the Max Read Request Size, which is always 64
	 * bytes which is 000b.  Bits [7:5] are Max Payload Size, which
	 * start at 128 bytes which is 000b.  This may be revisited if
	 * init_child finds greater values.
	 */
	val = 0x0ull;
	CSR_XS(csr_base, TLU_DEVICE_CONTROL, val);
	DBG(DBG_TLU, NULL, "tlu_init - TLU_DEVICE_CONTROL: 0x%llx\n",
	    CSR_XR(csr_base, TLU_DEVICE_CONTROL));

	/*
	 * CSR_V TLU_DEVICE_STATUS Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_DEVICE_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, TLU_DEVICE_STATUS));

	/*
	 * CSR_V TLU_LINK_CAPABILITIES Expect HW 0x15C81
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_LINK_CAPABILITIES: 0x%llx\n",
	    CSR_XR(csr_base, TLU_LINK_CAPABILITIES));

	/*
	 * CSR_V TLU_LINK_CONTROL Expect OBP 0x40
	 */

	/*
	 * The CLOCK bit should be set by OBP if the hardware dictates,
	 * and if it is set then ASPM should be used since then L0s exit
	 * latency should be lower than L1 exit latency.
	 *
	 * Note that we will not enable power management during bringup
	 * since it has not been test and is creating some problems in
	 * simulation.
	 */
	val = (1ull << TLU_LINK_CONTROL_CLOCK);

	CSR_XS(csr_base, TLU_LINK_CONTROL, val);
	DBG(DBG_TLU, NULL, "tlu_init - TLU_LINK_CONTROL: 0x%llx\n",
	    CSR_XR(csr_base, TLU_LINK_CONTROL));

	/*
	 * CSR_V TLU_LINK_STATUS Expect OBP 0x1011
	 */

	/*
	 * Not sure if HW or OBP will be setting this read only
	 * register.  Bit 12 is Clock, and it should always be 1
	 * signifying that the component uses the same physical
	 * clock as the platform.  Bits [9:4] are for the width,
	 * with the expected value above signifying a x1 width.
	 * Bits [3:0] are the speed, with 1b signifying 2.5 Gb/s,
	 * the only speed as yet supported by the PCI-E spec.
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_LINK_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, TLU_LINK_STATUS));

	/*
	 * CSR_V TLU_SLOT_CAPABILITIES Expect OBP ???
	 */

	/*
	 * Power Limits for the slots.  Will be platform
	 * dependent, and OBP will need to set after consulting
	 * with the HW guys.
	 *
	 * Bits [16:15] are power limit scale, which most likely
	 * will be 0b signifying 1x.  Bits [14:7] are the Set
	 * Power Limit Value, which is a number which is multiplied
	 * by the power limit scale to get the actual power limit.
	 */
	DBG(DBG_TLU, NULL, "tlu_init - TLU_SLOT_CAPABILITIES: 0x%llx\n",
	    CSR_XR(csr_base, TLU_SLOT_CAPABILITIES));

	/*
	 * CSR_V TLU_UNCORRECTABLE_ERROR_LOG_ENABLE Expect Kernel 0x17F011
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_UNCORRECTABLE_ERROR_LOG_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_LOG_ENABLE));

	/*
	 * CSR_V TLU_UNCORRECTABLE_ERROR_INTERRUPT_ENABLE Expect
	 * Kernel 0x17F0110017F011
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_UNCORRECTABLE_ERROR_INTERRUPT_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_INTERRUPT_ENABLE));

	/*
	 * CSR_V TLU_UNCORRECTABLE_ERROR_INTERRUPT_STATUS Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_UNCORRECTABLE_ERROR_INTERRUPT_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_INTERRUPT_STATUS));

	/*
	 * CSR_V TLU_UNCORRECTABLE_ERROR_STATUS_CLEAR Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_UNCORRECTABLE_ERROR_STATUS_CLEAR: 0x%llx\n",
	    CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_STATUS_CLEAR));

	/*
	 * CSR_V TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER1_LOG HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER1_LOG: 0x%llx\n",
	    CSR_XR(csr_base, TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER1_LOG));

	/*
	 * CSR_V TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER2_LOG HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER2_LOG: 0x%llx\n",
	    CSR_XR(csr_base, TLU_RECEIVE_UNCORRECTABLE_ERROR_HEADER2_LOG));

	/*
	 * CSR_V TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER1_LOG HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER1_LOG: 0x%llx\n",
	    CSR_XR(csr_base, TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER1_LOG));

	/*
	 * CSR_V TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER2_LOG HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER2_LOG: 0x%llx\n",
	    CSR_XR(csr_base, TLU_TRANSMIT_UNCORRECTABLE_ERROR_HEADER2_LOG));


	/*
	 * CSR_V TLU's CE interrupt regs (log, enable, status, clear)
	 * Plus header logs
	 */

	/*
	 * CSR_V TLU_CORRECTABLE_ERROR_LOG_ENABLE Expect Kernel 0x11C1
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_CORRECTABLE_ERROR_LOG_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, TLU_CORRECTABLE_ERROR_LOG_ENABLE));

	/*
	 * CSR_V TLU_CORRECTABLE_ERROR_INTERRUPT_ENABLE Kernel 0x11C1000011C1
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_CORRECTABLE_ERROR_INTERRUPT_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, TLU_CORRECTABLE_ERROR_INTERRUPT_ENABLE));

	/*
	 * CSR_V TLU_CORRECTABLE_ERROR_INTERRUPT_STATUS Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_CORRECTABLE_ERROR_INTERRUPT_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, TLU_CORRECTABLE_ERROR_INTERRUPT_STATUS));

	/*
	 * CSR_V TLU_CORRECTABLE_ERROR_STATUS_CLEAR Expect HW 0x0
	 */
	DBG(DBG_TLU, NULL,
	    "tlu_init - TLU_CORRECTABLE_ERROR_STATUS_CLEAR: 0x%llx\n",
	    CSR_XR(csr_base, TLU_CORRECTABLE_ERROR_STATUS_CLEAR));
}

/* ARGSUSED */
static void
lpu_init(caddr_t csr_base, pxu_t *pxu_p)
{
	/* Variables used to set the ACKNAK Latency Timer and Replay Timer */
	int link_width, max_payload;

	uint64_t val;

	/*
	 * ACKNAK Latency Threshold Table.
	 * See Fire PRM 2.0 section 1.2.12.2, table 1-17.
	 */
	int acknak_timer_table[LINK_MAX_PKT_ARR_SIZE][LINK_WIDTH_ARR_SIZE] = {
		{0xED,   0x49,  0x43,  0x30},
		{0x1A0,  0x76,  0x6B,  0x48},
		{0x22F,  0x9A,  0x56,  0x56},
		{0x42F,  0x11A, 0x96,  0x96},
		{0x82F,  0x21A, 0x116, 0x116},
		{0x102F, 0x41A, 0x216, 0x216}
	};

	/*
	 * TxLink Replay Timer Latency Table
	 * See Fire PRM 2.0 sections 1.2.12.3, table 1-18.
	 */
	int replay_timer_table[LINK_MAX_PKT_ARR_SIZE][LINK_WIDTH_ARR_SIZE] = {
		{0x379,  0x112, 0xFC,  0xB4},
		{0x618,  0x1BA, 0x192, 0x10E},
		{0x831,  0x242, 0x143, 0x143},
		{0xFB1,  0x422, 0x233, 0x233},
		{0x1EB0, 0x7E1, 0x412, 0x412},
		{0x3CB0, 0xF61, 0x7D2, 0x7D2}
	};

	/*
	 * Get the Link Width.  See table above LINK_WIDTH_ARR_SIZE #define
	 * Only Link Widths of x1, x4, and x8 are supported.
	 * If any width is reported other than x8, set default to x8.
	 */
	link_width = CSR_FR(csr_base, TLU_LINK_STATUS, WIDTH);
	DBG(DBG_LPU, NULL, "lpu_init - Link Width: x%d\n", link_width);

	/*
	 * Convert link_width to match timer array configuration.
	 */
	switch (link_width) {
	case 1:
		link_width = 0;
		break;
	case 4:
		link_width = 1;
		break;
	case 8:
		link_width = 2;
		break;
	case 16:
		link_width = 3;
		break;
	default:
		link_width = 0;
	}

	/*
	 * Get the Max Payload Size.
	 * See table above LINK_MAX_PKT_ARR_SIZE #define
	 */
	max_payload = ((CSR_FR(csr_base, TLU_CONTROL, CONFIG) &
	    TLU_CONTROL_MPS_MASK) >> TLU_CONTROL_MPS_SHIFT);

	DBG(DBG_LPU, NULL, "lpu_init - May Payload: %d\n",
	    (0x80 << max_payload));

	/* Make sure the packet size is not greater than 4096 */
	max_payload = (max_payload >= LINK_MAX_PKT_ARR_SIZE) ?
	    (LINK_MAX_PKT_ARR_SIZE - 1) : max_payload;

	/*
	 * CSR_V LPU_ID Expect HW 0x0
	 */

	/*
	 * This register has link id, phy id and gigablaze id.
	 * Should be set by HW.
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_ID: 0x%llx\n",
	    CSR_XR(csr_base, LPU_ID));

	/*
	 * CSR_V LPU_RESET Expect Kernel 0x0
	 */

	/*
	 * No reason to have any reset bits high until an error is
	 * detected on the link.
	 */
	val = 0ull;
	CSR_XS(csr_base, LPU_RESET, val);
	DBG(DBG_LPU, NULL, "lpu_init - LPU_RESET: 0x%llx\n",
	    CSR_XR(csr_base, LPU_RESET));

	/*
	 * CSR_V LPU_DEBUG_STATUS Expect HW 0x0
	 */

	/*
	 * Bits [15:8] are Debug B, and bit [7:0] are Debug A.
	 * They are read-only.  What do the 8 bits mean, and
	 * how do they get set if they are read only?
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_DEBUG_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_DEBUG_STATUS));

	/*
	 * CSR_V LPU_DEBUG_CONFIG Expect Kernel 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_DEBUG_CONFIG: 0x%llx\n",
	    CSR_XR(csr_base, LPU_DEBUG_CONFIG));

	/*
	 * CSR_V LPU_LTSSM_CONTROL Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_LTSSM_CONTROL: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_CONTROL));

	/*
	 * CSR_V LPU_LINK_STATUS Expect HW 0x101
	 */

	/*
	 * This register has bits [9:4] for link width, and the
	 * default 0x10, means a width of x16.  The problem is
	 * this width is not supported according to the TLU
	 * link status register.
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_LINK_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_STATUS));

	/*
	 * CSR_V LPU_INTERRUPT_STATUS Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_INTERRUPT_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_INTERRUPT_STATUS));

	/*
	 * CSR_V LPU_INTERRUPT_MASK Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_INTERRUPT_MASK: 0x%llx\n",
	    CSR_XR(csr_base, LPU_INTERRUPT_MASK));

	/*
	 * CSR_V LPU_LINK_PERFORMANCE_COUNTER_SELECT Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LINK_PERFORMANCE_COUNTER_SELECT: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_PERFORMANCE_COUNTER_SELECT));

	/*
	 * CSR_V LPU_LINK_PERFORMANCE_COUNTER_CONTROL Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LINK_PERFORMANCE_COUNTER_CONTROL: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_PERFORMANCE_COUNTER_CONTROL));

	/*
	 * CSR_V LPU_LINK_PERFORMANCE_COUNTER1 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LINK_PERFORMANCE_COUNTER1: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_PERFORMANCE_COUNTER1));

	/*
	 * CSR_V LPU_LINK_PERFORMANCE_COUNTER1_TEST Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LINK_PERFORMANCE_COUNTER1_TEST: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_PERFORMANCE_COUNTER1_TEST));

	/*
	 * CSR_V LPU_LINK_PERFORMANCE_COUNTER2 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LINK_PERFORMANCE_COUNTER2: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_PERFORMANCE_COUNTER2));

	/*
	 * CSR_V LPU_LINK_PERFORMANCE_COUNTER2_TEST Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LINK_PERFORMANCE_COUNTER2_TEST: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_PERFORMANCE_COUNTER2_TEST));

	/*
	 * CSR_V LPU_LINK_LAYER_CONFIG Expect HW 0x100
	 */

	/*
	 * This is another place where Max Payload can be set,
	 * this time for the link layer.  It will be set to
	 * 128B, which is the default, but this will need to
	 * be revisited.
	 */
	val = (1ull << LPU_LINK_LAYER_CONFIG_VC0_EN);
	CSR_XS(csr_base, LPU_LINK_LAYER_CONFIG, val);
	DBG(DBG_LPU, NULL, "lpu_init - LPU_LINK_LAYER_CONFIG: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_LAYER_CONFIG));

	/*
	 * CSR_V LPU_LINK_LAYER_STATUS Expect OBP 0x5
	 */

	/*
	 * Another R/W status register.  Bit 3, DL up Status, will
	 * be set high.  The link state machine status bits [2:0]
	 * are set to 0x1, but the status bits are not defined in the
	 * PRM.  What does 0x1 mean, what others values are possible
	 * and what are thier meanings?
	 *
	 * This register has been giving us problems in simulation.
	 * It has been mentioned that software should not program
	 * any registers with WE bits except during debug.  So
	 * this register will no longer be programmed.
	 */

	DBG(DBG_LPU, NULL, "lpu_init - LPU_LINK_LAYER_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_LAYER_STATUS));

	/*
	 * CSR_V LPU_LINK_LAYER_INTERRUPT_AND_STATUS_TEST Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LINK_LAYER_INTERRUPT_AND_STATUS_TEST: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_LAYER_INTERRUPT_AND_STATUS_TEST));

	/*
	 * CSR_V LPU Link Layer interrupt regs (mask, status)
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LINK_LAYER_INTERRUPT_MASK: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_LAYER_INTERRUPT_MASK));

	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LINK_LAYER_INTERRUPT_AND_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LINK_LAYER_INTERRUPT_AND_STATUS));

	/*
	 * CSR_V LPU_FLOW_CONTROL_UPDATE_CONTROL Expect OBP 0x7
	 */

	/*
	 * The PRM says that only the first two bits will be set
	 * high by default, which will enable flow control for
	 * posted and non-posted updates, but NOT completetion
	 * updates.
	 */
	val = (1ull << LPU_FLOW_CONTROL_UPDATE_CONTROL_FC0_U_NP_EN) |
	    (1ull << LPU_FLOW_CONTROL_UPDATE_CONTROL_FC0_U_P_EN);
	CSR_XS(csr_base, LPU_FLOW_CONTROL_UPDATE_CONTROL, val);
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_FLOW_CONTROL_UPDATE_CONTROL: 0x%llx\n",
	    CSR_XR(csr_base, LPU_FLOW_CONTROL_UPDATE_CONTROL));

	/*
	 * CSR_V LPU_LINK_LAYER_FLOW_CONTROL_UPDATE_TIMEOUT_VALUE
	 * Expect OBP 0x1D4C
	 */

	/*
	 * This should be set by OBP.  We'll check to make sure.
	 */
	DBG(DBG_LPU, NULL, "lpu_init - "
	    "LPU_LINK_LAYER_FLOW_CONTROL_UPDATE_TIMEOUT_VALUE: 0x%llx\n",
	    CSR_XR(csr_base,
	    LPU_LINK_LAYER_FLOW_CONTROL_UPDATE_TIMEOUT_VALUE));

	/*
	 * CSR_V LPU_LINK_LAYER_VC0_FLOW_CONTROL_UPDATE_TIMER0 Expect OBP ???
	 */

	/*
	 * This register has Flow Control Update Timer values for
	 * non-posted and posted requests, bits [30:16] and bits
	 * [14:0], respectively.  These are read-only to SW so
	 * either HW or OBP needs to set them.
	 */
	DBG(DBG_LPU, NULL, "lpu_init - "
	    "LPU_LINK_LAYER_VC0_FLOW_CONTROL_UPDATE_TIMER0: 0x%llx\n",
	    CSR_XR(csr_base,
	    LPU_LINK_LAYER_VC0_FLOW_CONTROL_UPDATE_TIMER0));

	/*
	 * CSR_V LPU_LINK_LAYER_VC0_FLOW_CONTROL_UPDATE_TIMER1 Expect OBP ???
	 */

	/*
	 * Same as timer0 register above, except for bits [14:0]
	 * have the timer values for completetions.  Read-only to
	 * SW; OBP or HW need to set it.
	 */
	DBG(DBG_LPU, NULL, "lpu_init - "
	    "LPU_LINK_LAYER_VC0_FLOW_CONTROL_UPDATE_TIMER1: 0x%llx\n",
	    CSR_XR(csr_base,
	    LPU_LINK_LAYER_VC0_FLOW_CONTROL_UPDATE_TIMER1));

	/*
	 * CSR_V LPU_TXLINK_FREQUENT_NAK_LATENCY_TIMER_THRESHOLD
	 */
	val = acknak_timer_table[max_payload][link_width];
	CSR_XS(csr_base, LPU_TXLINK_FREQUENT_NAK_LATENCY_TIMER_THRESHOLD, val);

	DBG(DBG_LPU, NULL, "lpu_init - "
	    "LPU_TXLINK_FREQUENT_NAK_LATENCY_TIMER_THRESHOLD: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_FREQUENT_NAK_LATENCY_TIMER_THRESHOLD));

	/*
	 * CSR_V LPU_TXLINK_ACKNAK_LATENCY_TIMER Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_ACKNAK_LATENCY_TIMER: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_ACKNAK_LATENCY_TIMER));

	/*
	 * CSR_V LPU_TXLINK_REPLAY_TIMER_THRESHOLD
	 */
	val = replay_timer_table[max_payload][link_width];
	CSR_XS(csr_base, LPU_TXLINK_REPLAY_TIMER_THRESHOLD, val);

	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_REPLAY_TIMER_THRESHOLD: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_REPLAY_TIMER_THRESHOLD));

	/*
	 * CSR_V LPU_TXLINK_REPLAY_TIMER Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_TXLINK_REPLAY_TIMER: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_REPLAY_TIMER));

	/*
	 * CSR_V LPU_TXLINK_REPLAY_NUMBER_STATUS Expect OBP 0x3
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_REPLAY_NUMBER_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_REPLAY_NUMBER_STATUS));

	/*
	 * CSR_V LPU_REPLAY_BUFFER_MAX_ADDRESS Expect OBP 0xB3F
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_REPLAY_BUFFER_MAX_ADDRESS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_REPLAY_BUFFER_MAX_ADDRESS));

	/*
	 * CSR_V LPU_TXLINK_RETRY_FIFO_POINTER Expect OBP 0xFFFF0000
	 */
	val = ((LPU_TXLINK_RETRY_FIFO_POINTER_RTRY_FIFO_TLPTR_DEFAULT <<
	    LPU_TXLINK_RETRY_FIFO_POINTER_RTRY_FIFO_TLPTR) |
	    (LPU_TXLINK_RETRY_FIFO_POINTER_RTRY_FIFO_HDPTR_DEFAULT <<
	    LPU_TXLINK_RETRY_FIFO_POINTER_RTRY_FIFO_HDPTR));

	CSR_XS(csr_base, LPU_TXLINK_RETRY_FIFO_POINTER, val);
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_RETRY_FIFO_POINTER: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_RETRY_FIFO_POINTER));

	/*
	 * CSR_V LPU_TXLINK_RETRY_FIFO_R_W_POINTER Expect OBP 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_RETRY_FIFO_R_W_POINTER: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_RETRY_FIFO_R_W_POINTER));

	/*
	 * CSR_V LPU_TXLINK_RETRY_FIFO_CREDIT Expect HW 0x1580
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_RETRY_FIFO_CREDIT: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_RETRY_FIFO_CREDIT));

	/*
	 * CSR_V LPU_TXLINK_SEQUENCE_COUNTER Expect OBP 0xFFF0000
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_TXLINK_SEQUENCE_COUNTER: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_SEQUENCE_COUNTER));

	/*
	 * CSR_V LPU_TXLINK_ACK_SENT_SEQUENCE_NUMBER Expect HW 0xFFF
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_ACK_SENT_SEQUENCE_NUMBER: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_ACK_SENT_SEQUENCE_NUMBER));

	/*
	 * CSR_V LPU_TXLINK_SEQUENCE_COUNT_FIFO_MAX_ADDR Expect OBP 0x157
	 */

	/*
	 * Test only register.  Will not be programmed.
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_SEQUENCE_COUNT_FIFO_MAX_ADDR: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_SEQUENCE_COUNT_FIFO_MAX_ADDR));

	/*
	 * CSR_V LPU_TXLINK_SEQUENCE_COUNT_FIFO_POINTERS Expect HW 0xFFF0000
	 */

	/*
	 * Test only register.  Will not be programmed.
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_SEQUENCE_COUNT_FIFO_POINTERS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_SEQUENCE_COUNT_FIFO_POINTERS));

	/*
	 * CSR_V LPU_TXLINK_SEQUENCE_COUNT_R_W_POINTERS Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_SEQUENCE_COUNT_R_W_POINTERS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_SEQUENCE_COUNT_R_W_POINTERS));

	/*
	 * CSR_V LPU_TXLINK_TEST_CONTROL Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_TXLINK_TEST_CONTROL: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_TEST_CONTROL));

	/*
	 * CSR_V LPU_TXLINK_MEMORY_ADDRESS_CONTROL Expect HW 0x0
	 */

	/*
	 * Test only register.  Will not be programmed.
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_MEMORY_ADDRESS_CONTROL: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_MEMORY_ADDRESS_CONTROL));

	/*
	 * CSR_V LPU_TXLINK_MEMORY_DATA_LOAD0 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_MEMORY_DATA_LOAD0: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_MEMORY_DATA_LOAD0));

	/*
	 * CSR_V LPU_TXLINK_MEMORY_DATA_LOAD1 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_MEMORY_DATA_LOAD1: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_MEMORY_DATA_LOAD1));

	/*
	 * CSR_V LPU_TXLINK_MEMORY_DATA_LOAD2 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_MEMORY_DATA_LOAD2: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_MEMORY_DATA_LOAD2));

	/*
	 * CSR_V LPU_TXLINK_MEMORY_DATA_LOAD3 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_MEMORY_DATA_LOAD3: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_MEMORY_DATA_LOAD3));

	/*
	 * CSR_V LPU_TXLINK_MEMORY_DATA_LOAD4 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_MEMORY_DATA_LOAD4: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_MEMORY_DATA_LOAD4));

	/*
	 * CSR_V LPU_TXLINK_RETRY_DATA_COUNT Expect HW 0x0
	 */

	/*
	 * Test only register.  Will not be programmed.
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_TXLINK_RETRY_DATA_COUNT: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_RETRY_DATA_COUNT));

	/*
	 * CSR_V LPU_TXLINK_SEQUENCE_BUFFER_COUNT Expect HW 0x0
	 */

	/*
	 * Test only register.  Will not be programmed.
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_SEQUENCE_BUFFER_COUNT: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_SEQUENCE_BUFFER_COUNT));

	/*
	 * CSR_V LPU_TXLINK_SEQUENCE_BUFFER_BOTTOM_DATA Expect HW 0x0
	 */

	/*
	 * Test only register.
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TXLINK_SEQUENCE_BUFFER_BOTTOM_DATA: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TXLINK_SEQUENCE_BUFFER_BOTTOM_DATA));

	/*
	 * CSR_V LPU_RXLINK_NEXT_RECEIVE_SEQUENCE_1_COUNTER Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - "
	    "LPU_RXLINK_NEXT_RECEIVE_SEQUENCE_1_COUNTER: 0x%llx\n",
	    CSR_XR(csr_base, LPU_RXLINK_NEXT_RECEIVE_SEQUENCE_1_COUNTER));

	/*
	 * CSR_V LPU_RXLINK_UNSUPPORTED_DLLP_RECEIVED Expect HW 0x0
	 */

	/*
	 * test only register.
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_RXLINK_UNSUPPORTED_DLLP_RECEIVED: 0x%llx\n",
	    CSR_XR(csr_base, LPU_RXLINK_UNSUPPORTED_DLLP_RECEIVED));

	/*
	 * CSR_V LPU_RXLINK_TEST_CONTROL Expect HW 0x0
	 */

	/*
	 * test only register.
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_RXLINK_TEST_CONTROL: 0x%llx\n",
	    CSR_XR(csr_base, LPU_RXLINK_TEST_CONTROL));

	/*
	 * CSR_V LPU_PHYSICAL_LAYER_CONFIGURATION Expect HW 0x10
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_PHYSICAL_LAYER_CONFIGURATION: 0x%llx\n",
	    CSR_XR(csr_base, LPU_PHYSICAL_LAYER_CONFIGURATION));

	/*
	 * CSR_V LPU_PHY_LAYER_STATUS Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_PHY_LAYER_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_PHY_LAYER_STATUS));

	/*
	 * CSR_V LPU_PHY_INTERRUPT_AND_STATUS_TEST Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_PHY_INTERRUPT_AND_STATUS_TEST: 0x%llx\n",
	    CSR_XR(csr_base, LPU_PHY_INTERRUPT_AND_STATUS_TEST));

	/*
	 * CSR_V LPU PHY LAYER interrupt regs (mask, status)
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_PHY_INTERRUPT_MASK: 0x%llx\n",
	    CSR_XR(csr_base, LPU_PHY_INTERRUPT_MASK));

	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_PHY_LAYER_INTERRUPT_AND_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_PHY_LAYER_INTERRUPT_AND_STATUS));

	/*
	 * CSR_V LPU_RECEIVE_PHY_CONFIG Expect HW 0x0
	 */

	/*
	 * This also needs some explanation.  What is the best value
	 * for the water mark?  Test mode enables which test mode?
	 * Programming model needed for the Receiver Reset Lane N
	 * bits.
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_RECEIVE_PHY_CONFIG: 0x%llx\n",
	    CSR_XR(csr_base, LPU_RECEIVE_PHY_CONFIG));

	/*
	 * CSR_V LPU_RECEIVE_PHY_STATUS1 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_RECEIVE_PHY_STATUS1: 0x%llx\n",
	    CSR_XR(csr_base, LPU_RECEIVE_PHY_STATUS1));

	/*
	 * CSR_V LPU_RECEIVE_PHY_STATUS2 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_RECEIVE_PHY_STATUS2: 0x%llx\n",
	    CSR_XR(csr_base, LPU_RECEIVE_PHY_STATUS2));

	/*
	 * CSR_V LPU_RECEIVE_PHY_STATUS3 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_RECEIVE_PHY_STATUS3: 0x%llx\n",
	    CSR_XR(csr_base, LPU_RECEIVE_PHY_STATUS3));

	/*
	 * CSR_V LPU_RECEIVE_PHY_INTERRUPT_AND_STATUS_TEST Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_RECEIVE_PHY_INTERRUPT_AND_STATUS_TEST: 0x%llx\n",
	    CSR_XR(csr_base, LPU_RECEIVE_PHY_INTERRUPT_AND_STATUS_TEST));

	/*
	 * CSR_V LPU RX LAYER interrupt regs (mask, status)
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_RECEIVE_PHY_INTERRUPT_MASK: 0x%llx\n",
	    CSR_XR(csr_base, LPU_RECEIVE_PHY_INTERRUPT_MASK));

	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_RECEIVE_PHY_INTERRUPT_AND_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_RECEIVE_PHY_INTERRUPT_AND_STATUS));

	/*
	 * CSR_V LPU_TRANSMIT_PHY_CONFIG Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_TRANSMIT_PHY_CONFIG: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TRANSMIT_PHY_CONFIG));

	/*
	 * CSR_V LPU_TRANSMIT_PHY_STATUS Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_TRANSMIT_PHY_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TRANSMIT_PHY_STATUS));

	/*
	 * CSR_V LPU_TRANSMIT_PHY_INTERRUPT_AND_STATUS_TEST Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TRANSMIT_PHY_INTERRUPT_AND_STATUS_TEST: 0x%llx\n",
	    CSR_XR(csr_base,
	    LPU_TRANSMIT_PHY_INTERRUPT_AND_STATUS_TEST));

	/*
	 * CSR_V LPU TX LAYER interrupt regs (mask, status)
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TRANSMIT_PHY_INTERRUPT_MASK: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TRANSMIT_PHY_INTERRUPT_MASK));

	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_TRANSMIT_PHY_INTERRUPT_AND_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TRANSMIT_PHY_INTERRUPT_AND_STATUS));

	/*
	 * CSR_V LPU_TRANSMIT_PHY_STATUS_2 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_TRANSMIT_PHY_STATUS_2: 0x%llx\n",
	    CSR_XR(csr_base, LPU_TRANSMIT_PHY_STATUS_2));

	/*
	 * CSR_V LPU_LTSSM_CONFIG1 Expect OBP 0x205
	 */

	/*
	 * The new PRM has values for LTSSM 8 ns timeout value and
	 * LTSSM 20 ns timeout value.  But what do these values mean?
	 * Most of the other bits are questions as well.
	 *
	 * As such we will use the reset value.
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_LTSSM_CONFIG1: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_CONFIG1));

	/*
	 * CSR_V LPU_LTSSM_CONFIG2 Expect OBP 0x2DC6C0
	 */

	/*
	 * Again, what does '12 ms timeout value mean'?
	 */
	val = (LPU_LTSSM_CONFIG2_LTSSM_12_TO_DEFAULT <<
	    LPU_LTSSM_CONFIG2_LTSSM_12_TO);
	CSR_XS(csr_base, LPU_LTSSM_CONFIG2, val);
	DBG(DBG_LPU, NULL, "lpu_init - LPU_LTSSM_CONFIG2: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_CONFIG2));

	/*
	 * CSR_V LPU_LTSSM_CONFIG3 Expect OBP 0x7A120
	 */
	val = (LPU_LTSSM_CONFIG3_LTSSM_2_TO_DEFAULT <<
	    LPU_LTSSM_CONFIG3_LTSSM_2_TO);
	CSR_XS(csr_base, LPU_LTSSM_CONFIG3, val);
	DBG(DBG_LPU, NULL, "lpu_init - LPU_LTSSM_CONFIG3: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_CONFIG3));

	/*
	 * CSR_V LPU_LTSSM_CONFIG4 Expect OBP 0x21300
	 */
	val = ((LPU_LTSSM_CONFIG4_DATA_RATE_DEFAULT <<
	    LPU_LTSSM_CONFIG4_DATA_RATE) |
	    (LPU_LTSSM_CONFIG4_N_FTS_DEFAULT <<
	    LPU_LTSSM_CONFIG4_N_FTS));
	CSR_XS(csr_base, LPU_LTSSM_CONFIG4, val);
	DBG(DBG_LPU, NULL, "lpu_init - LPU_LTSSM_CONFIG4: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_CONFIG4));

	/*
	 * CSR_V LPU_LTSSM_CONFIG5 Expect OBP 0x0
	 */
	val = 0ull;
	CSR_XS(csr_base, LPU_LTSSM_CONFIG5, val);
	DBG(DBG_LPU, NULL, "lpu_init - LPU_LTSSM_CONFIG5: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_CONFIG5));

	/*
	 * CSR_V LPU_LTSSM_STATUS1 Expect OBP 0x0
	 */

	/*
	 * LTSSM Status registers are test only.
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_LTSSM_STATUS1: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_STATUS1));

	/*
	 * CSR_V LPU_LTSSM_STATUS2 Expect OBP 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_LTSSM_STATUS2: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_STATUS2));

	/*
	 * CSR_V LPU_LTSSM_INTERRUPT_AND_STATUS_TEST Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LTSSM_INTERRUPT_AND_STATUS_TEST: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_INTERRUPT_AND_STATUS_TEST));

	/*
	 * CSR_V LPU LTSSM  LAYER interrupt regs (mask, status)
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_LTSSM_INTERRUPT_MASK: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_INTERRUPT_MASK));

	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LTSSM_INTERRUPT_AND_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_INTERRUPT_AND_STATUS));

	/*
	 * CSR_V LPU_LTSSM_STATUS_WRITE_ENABLE Expect OBP 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_LTSSM_STATUS_WRITE_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, LPU_LTSSM_STATUS_WRITE_ENABLE));

	/*
	 * CSR_V LPU_GIGABLAZE_GLUE_CONFIG1 Expect OBP 0x88407
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_GIGABLAZE_GLUE_CONFIG1: 0x%llx\n",
	    CSR_XR(csr_base, LPU_GIGABLAZE_GLUE_CONFIG1));

	/*
	 * CSR_V LPU_GIGABLAZE_GLUE_CONFIG2 Expect OBP 0x35
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_GIGABLAZE_GLUE_CONFIG2: 0x%llx\n",
	    CSR_XR(csr_base, LPU_GIGABLAZE_GLUE_CONFIG2));

	/*
	 * CSR_V LPU_GIGABLAZE_GLUE_CONFIG3 Expect OBP 0x4400FA
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_GIGABLAZE_GLUE_CONFIG3: 0x%llx\n",
	    CSR_XR(csr_base, LPU_GIGABLAZE_GLUE_CONFIG3));

	/*
	 * CSR_V LPU_GIGABLAZE_GLUE_CONFIG4 Expect OBP 0x1E848
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_GIGABLAZE_GLUE_CONFIG4: 0x%llx\n",
	    CSR_XR(csr_base, LPU_GIGABLAZE_GLUE_CONFIG4));

	/*
	 * CSR_V LPU_GIGABLAZE_GLUE_STATUS Expect OBP 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_GIGABLAZE_GLUE_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_GIGABLAZE_GLUE_STATUS));

	/*
	 * CSR_V LPU_GIGABLAZE_GLUE_INTERRUPT_AND_STATUS_TEST Expect OBP 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - "
	    "LPU_GIGABLAZE_GLUE_INTERRUPT_AND_STATUS_TEST: 0x%llx\n",
	    CSR_XR(csr_base,
	    LPU_GIGABLAZE_GLUE_INTERRUPT_AND_STATUS_TEST));

	/*
	 * CSR_V LPU GIGABLASE LAYER interrupt regs (mask, status)
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_GIGABLAZE_GLUE_INTERRUPT_MASK: 0x%llx\n",
	    CSR_XR(csr_base, LPU_GIGABLAZE_GLUE_INTERRUPT_MASK));

	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_GIGABLAZE_GLUE_INTERRUPT_AND_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, LPU_GIGABLAZE_GLUE_INTERRUPT_AND_STATUS));

	/*
	 * CSR_V LPU_GIGABLAZE_GLUE_POWER_DOWN1 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_GIGABLAZE_GLUE_POWER_DOWN1: 0x%llx\n",
	    CSR_XR(csr_base, LPU_GIGABLAZE_GLUE_POWER_DOWN1));

	/*
	 * CSR_V LPU_GIGABLAZE_GLUE_POWER_DOWN2 Expect HW 0x0
	 */
	DBG(DBG_LPU, NULL,
	    "lpu_init - LPU_GIGABLAZE_GLUE_POWER_DOWN2: 0x%llx\n",
	    CSR_XR(csr_base, LPU_GIGABLAZE_GLUE_POWER_DOWN2));

	/*
	 * CSR_V LPU_GIGABLAZE_GLUE_CONFIG5 Expect OBP 0x0
	 */
	DBG(DBG_LPU, NULL, "lpu_init - LPU_GIGABLAZE_GLUE_CONFIG5: 0x%llx\n",
	    CSR_XR(csr_base, LPU_GIGABLAZE_GLUE_CONFIG5));
}

/* ARGSUSED */
static void
dlu_init(caddr_t csr_base, pxu_t *pxu_p)
{
uint64_t val;

	CSR_XS(csr_base, DLU_INTERRUPT_MASK, 0ull);
	DBG(DBG_TLU, NULL, "dlu_init - DLU_INTERRUPT_MASK: 0x%llx\n",
	    CSR_XR(csr_base, DLU_INTERRUPT_MASK));

	val = (1ull << DLU_LINK_LAYER_CONFIG_VC0_EN);
	CSR_XS(csr_base, DLU_LINK_LAYER_CONFIG, val);
	DBG(DBG_TLU, NULL, "dlu_init - DLU_LINK_LAYER_CONFIG: 0x%llx\n",
	    CSR_XR(csr_base, DLU_LINK_LAYER_CONFIG));

	val = (1ull << DLU_FLOW_CONTROL_UPDATE_CONTROL_FC0_U_NP_EN) |
	    (1ull << DLU_FLOW_CONTROL_UPDATE_CONTROL_FC0_U_P_EN);

	CSR_XS(csr_base, DLU_FLOW_CONTROL_UPDATE_CONTROL, val);
	DBG(DBG_TLU, NULL, "dlu_init - DLU_FLOW_CONTROL_UPDATE_CONTROL: "
	    "0x%llx\n", CSR_XR(csr_base, DLU_FLOW_CONTROL_UPDATE_CONTROL));

	val = (DLU_TXLINK_REPLAY_TIMER_THRESHOLD_DEFAULT <<
	    DLU_TXLINK_REPLAY_TIMER_THRESHOLD_RPLAY_TMR_THR);

	CSR_XS(csr_base, DLU_TXLINK_REPLAY_TIMER_THRESHOLD, val);

	DBG(DBG_TLU, NULL, "dlu_init - DLU_TXLINK_REPLAY_TIMER_THRESHOLD: "
	    "0x%llx\n", CSR_XR(csr_base, DLU_TXLINK_REPLAY_TIMER_THRESHOLD));
}

/* ARGSUSED */
static void
dmc_init(caddr_t csr_base, pxu_t *pxu_p)
{
	uint64_t val;

/*
 * CSR_V DMC_CORE_AND_BLOCK_INTERRUPT_ENABLE Expect OBP 0x8000000000000003
 */

	val = -1ull;
	CSR_XS(csr_base, DMC_CORE_AND_BLOCK_INTERRUPT_ENABLE, val);
	DBG(DBG_DMC, NULL,
	    "dmc_init - DMC_CORE_AND_BLOCK_INTERRUPT_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, DMC_CORE_AND_BLOCK_INTERRUPT_ENABLE));

	/*
	 * CSR_V DMC_CORE_AND_BLOCK_ERROR_STATUS Expect HW 0x0
	 */
	DBG(DBG_DMC, NULL,
	    "dmc_init - DMC_CORE_AND_BLOCK_ERROR_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, DMC_CORE_AND_BLOCK_ERROR_STATUS));

	/*
	 * CSR_V DMC_DEBUG_SELECT_FOR_PORT_A Expect HW 0x0
	 */
	val = 0x0ull;
	CSR_XS(csr_base, DMC_DEBUG_SELECT_FOR_PORT_A, val);
	DBG(DBG_DMC, NULL, "dmc_init - DMC_DEBUG_SELECT_FOR_PORT_A: 0x%llx\n",
	    CSR_XR(csr_base, DMC_DEBUG_SELECT_FOR_PORT_A));

	/*
	 * CSR_V DMC_DEBUG_SELECT_FOR_PORT_B Expect HW 0x0
	 */
	val = 0x0ull;
	CSR_XS(csr_base, DMC_DEBUG_SELECT_FOR_PORT_B, val);
	DBG(DBG_DMC, NULL, "dmc_init - DMC_DEBUG_SELECT_FOR_PORT_B: 0x%llx\n",
	    CSR_XR(csr_base, DMC_DEBUG_SELECT_FOR_PORT_B));
}

void
hvio_pec_init(caddr_t csr_base, pxu_t *pxu_p)
{
	uint64_t val;

	ilu_init(csr_base, pxu_p);
	tlu_init(csr_base, pxu_p);

	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		dlu_init(csr_base, pxu_p);
		break;
	case PX_CHIP_FIRE:
		lpu_init(csr_base, pxu_p);
		break;
	default:
		DBG(DBG_PEC, NULL, "hvio_pec_init - unknown chip type: 0x%x\n",
		    PX_CHIP_TYPE(pxu_p));
		break;
	}

	dmc_init(csr_base, pxu_p);

/*
 * CSR_V PEC_CORE_AND_BLOCK_INTERRUPT_ENABLE Expect Kernel 0x800000000000000F
 */

	val = -1ull;
	CSR_XS(csr_base, PEC_CORE_AND_BLOCK_INTERRUPT_ENABLE, val);
	DBG(DBG_PEC, NULL,
	    "hvio_pec_init - PEC_CORE_AND_BLOCK_INTERRUPT_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, PEC_CORE_AND_BLOCK_INTERRUPT_ENABLE));

	/*
	 * CSR_V PEC_CORE_AND_BLOCK_INTERRUPT_STATUS Expect HW 0x0
	 */
	DBG(DBG_PEC, NULL,
	    "hvio_pec_init - PEC_CORE_AND_BLOCK_INTERRUPT_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, PEC_CORE_AND_BLOCK_INTERRUPT_STATUS));
}

/*
 * Convert a TTE to physical address
 */
static r_addr_t
mmu_tte_to_pa(uint64_t tte, pxu_t *pxu_p)
{
	uint64_t pa_mask;

	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		pa_mask = MMU_OBERON_PADDR_MASK;
		break;
	case PX_CHIP_FIRE:
		pa_mask = MMU_FIRE_PADDR_MASK;
		break;
	default:
		DBG(DBG_MMU, NULL, "mmu_tte_to_pa - unknown chip type: 0x%x\n",
		    PX_CHIP_TYPE(pxu_p));
		pa_mask = 0;
		break;
	}
	return ((tte & pa_mask) >> MMU_PAGE_SHIFT);
}

/*
 * Return MMU bypass noncache bit for chip
 */
static r_addr_t
mmu_bypass_noncache(pxu_t *pxu_p)
{
	r_addr_t bypass_noncache_bit;

	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		bypass_noncache_bit = MMU_OBERON_BYPASS_NONCACHE;
		break;
	case PX_CHIP_FIRE:
		bypass_noncache_bit = MMU_FIRE_BYPASS_NONCACHE;
		break;
	default:
		DBG(DBG_MMU, NULL,
		    "mmu_bypass_nocache - unknown chip type: 0x%x\n",
		    PX_CHIP_TYPE(pxu_p));
		bypass_noncache_bit = 0;
		break;
	}
	return (bypass_noncache_bit);
}

/*
 * Calculate number of TSB entries for the chip.
 */
/* ARGSUSED */
static uint_t
mmu_tsb_entries(caddr_t csr_base, pxu_t *pxu_p)
{
	uint64_t tsb_ctrl;
	uint_t obp_tsb_entries, obp_tsb_size;

	tsb_ctrl = CSR_XR(csr_base, MMU_TSB_CONTROL);

	obp_tsb_size = tsb_ctrl & 0xF;

	obp_tsb_entries = MMU_TSBSIZE_TO_TSBENTRIES(obp_tsb_size);

	return (obp_tsb_entries);
}

/*
 * Initialize the module, but do not enable interrupts.
 */
void
hvio_mmu_init(caddr_t csr_base, pxu_t *pxu_p)
{
	uint64_t	val, i, obp_tsb_pa, *base_tte_addr;
	uint_t obp_tsb_entries;

	bzero(pxu_p->tsb_vaddr, pxu_p->tsb_size);

	/*
	 * Preserve OBP's TSB
	 */
	obp_tsb_pa = CSR_XR(csr_base, MMU_TSB_CONTROL) & MMU_TSB_PA_MASK;

	obp_tsb_entries = mmu_tsb_entries(csr_base, pxu_p);

	base_tte_addr = pxu_p->tsb_vaddr +
	    ((pxu_p->tsb_size >> 3) - obp_tsb_entries);

	for (i = 0; i < obp_tsb_entries; i++) {
		uint64_t tte = lddphys(obp_tsb_pa + i * 8);

		if (!MMU_TTE_VALID(tte))
			continue;

		base_tte_addr[i] = tte;
	}

	/*
	 * Invalidate the TLB through the diagnostic register.
	 */

	CSR_XS(csr_base, MMU_TTE_CACHE_INVALIDATE, -1ull);

	/*
	 * Configure the Fire MMU TSB Control Register.  Determine
	 * the encoding for either 8KB pages (0) or 64KB pages (1).
	 *
	 * Write the most significant 30 bits of the TSB physical address
	 * and the encoded TSB table size.
	 */
	for (i = 8; i && (pxu_p->tsb_size < (0x2000 << i)); i--) {}

	val = (((((va_to_pa(pxu_p->tsb_vaddr)) >> 13) << 13) |
	    ((MMU_PAGE_SHIFT == 13) ? 0 : 1) << 8) | i);

	CSR_XS(csr_base, MMU_TSB_CONTROL, val);

	/*
	 * Enable the MMU, set the "TSB Cache Snoop Enable",
	 * the "Cache Mode", the "Bypass Enable" and
	 * the "Translation Enable" bits.
	 */
	val = CSR_XR(csr_base, MMU_CONTROL_AND_STATUS);
	val |= ((1ull << MMU_CONTROL_AND_STATUS_SE)
	    | (MMU_CONTROL_AND_STATUS_CM_MASK << MMU_CONTROL_AND_STATUS_CM)
	    | (1ull << MMU_CONTROL_AND_STATUS_BE)
	    | (1ull << MMU_CONTROL_AND_STATUS_TE));

	CSR_XS(csr_base, MMU_CONTROL_AND_STATUS, val);

	/*
	 * Read the register here to ensure that the previous writes to
	 * the Fire MMU registers have been flushed.  (Technically, this
	 * is not entirely necessary here as we will likely do later reads
	 * during Fire initialization, but it is a small price to pay for
	 * more modular code.)
	 */
	(void) CSR_XR(csr_base, MMU_CONTROL_AND_STATUS);

	/*
	 * CSR_V TLU's UE interrupt regs (log, enable, status, clear)
	 * Plus header logs
	 */
	DBG(DBG_MMU, NULL, "mmu_init - MMU_ERROR_LOG_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, MMU_ERROR_LOG_ENABLE));

	DBG(DBG_MMU, NULL, "mmu_init - MMU_INTERRUPT_ENABLE: 0x%llx\n",
	    CSR_XR(csr_base, MMU_INTERRUPT_ENABLE));

	DBG(DBG_MMU, NULL, "mmu_init - MMU_INTERRUPT_STATUS: 0x%llx\n",
	    CSR_XR(csr_base, MMU_INTERRUPT_STATUS));

	DBG(DBG_MMU, NULL, "mmu_init - MMU_ERROR_STATUS_CLEAR: 0x%llx\n",
	    CSR_XR(csr_base, MMU_ERROR_STATUS_CLEAR));
}

/*
 * Generic IOMMU Servies
 */

/* ARGSUSED */
uint64_t
hvio_iommu_map(devhandle_t dev_hdl, pxu_t *pxu_p, tsbid_t tsbid, pages_t pages,
    io_attributes_t io_attr, void *addr, size_t pfn_index, int flags)
{
	tsbindex_t	tsb_index = PCI_TSBID_TO_TSBINDEX(tsbid);
	uint64_t	attr = MMU_TTE_V;
	int		i;

	if (io_attr & PCI_MAP_ATTR_WRITE)
		attr |= MMU_TTE_W;

	if ((PX_CHIP_TYPE(pxu_p) == PX_CHIP_OBERON) &&
	    (io_attr & PCI_MAP_ATTR_RO))
		attr |= MMU_TTE_RO;

	if (attr & MMU_TTE_RO) {
		DBG(DBG_MMU, NULL, "hvio_iommu_map: pfn_index=0x%x "
		    "pages=0x%x attr = 0x%lx\n", pfn_index, pages, attr);
	}

	if (flags & MMU_MAP_PFN) {
		ddi_dma_impl_t	*mp = (ddi_dma_impl_t *)addr;
		for (i = 0; i < pages; i++, pfn_index++, tsb_index++) {
			px_iopfn_t pfn = PX_GET_MP_PFN(mp, pfn_index);
			pxu_p->tsb_vaddr[tsb_index] = MMU_PTOB(pfn) | attr;

			/*
			 * Oberon will need to flush the corresponding TTEs in
			 * Cache. We only need to flush every cache line.
			 * Extra PIO's are expensive.
			 */
			if (PX_CHIP_TYPE(pxu_p) == PX_CHIP_OBERON) {
				if ((i == (pages-1))||!((tsb_index+1) & 0x7)) {
					CSR_XS(dev_hdl,
					    MMU_TTE_CACHE_FLUSH_ADDRESS,
					    (pxu_p->tsb_paddr+
					    (tsb_index*MMU_TTE_SIZE)));
				}
			}
		}
	} else {
		caddr_t	a = (caddr_t)addr;
		for (i = 0; i < pages; i++, a += MMU_PAGE_SIZE, tsb_index++) {
			px_iopfn_t pfn = hat_getpfnum(kas.a_hat, a);
			pxu_p->tsb_vaddr[tsb_index] = MMU_PTOB(pfn) | attr;

			/*
			 * Oberon will need to flush the corresponding TTEs in
			 * Cache. We only need to flush every cache line.
			 * Extra PIO's are expensive.
			 */
			if (PX_CHIP_TYPE(pxu_p) == PX_CHIP_OBERON) {
				if ((i == (pages-1))||!((tsb_index+1) & 0x7)) {
					CSR_XS(dev_hdl,
					    MMU_TTE_CACHE_FLUSH_ADDRESS,
					    (pxu_p->tsb_paddr+
					    (tsb_index*MMU_TTE_SIZE)));
				}
			}
		}
	}

	return (H_EOK);
}

/* ARGSUSED */
uint64_t
hvio_iommu_demap(devhandle_t dev_hdl, pxu_t *pxu_p, tsbid_t tsbid,
    pages_t pages)
{
	tsbindex_t	tsb_index = PCI_TSBID_TO_TSBINDEX(tsbid);
	int		i;

	for (i = 0; i < pages; i++, tsb_index++) {
		pxu_p->tsb_vaddr[tsb_index] = MMU_INVALID_TTE;

			/*
			 * Oberon will need to flush the corresponding TTEs in
			 * Cache. We only need to flush every cache line.
			 * Extra PIO's are expensive.
			 */
			if (PX_CHIP_TYPE(pxu_p) == PX_CHIP_OBERON) {
				if ((i == (pages-1))||!((tsb_index+1) & 0x7)) {
					CSR_XS(dev_hdl,
					    MMU_TTE_CACHE_FLUSH_ADDRESS,
					    (pxu_p->tsb_paddr+
					    (tsb_index*MMU_TTE_SIZE)));
				}
			}
	}

	return (H_EOK);
}

/* ARGSUSED */
uint64_t
hvio_iommu_getmap(devhandle_t dev_hdl, pxu_t *pxu_p, tsbid_t tsbid,
    io_attributes_t *attr_p, r_addr_t *r_addr_p)
{
	tsbindex_t	tsb_index = PCI_TSBID_TO_TSBINDEX(tsbid);
	uint64_t	*tte_addr;
	uint64_t	ret = H_EOK;

	tte_addr = (uint64_t *)(pxu_p->tsb_vaddr) + tsb_index;

	if (*tte_addr & MMU_TTE_V) {
		*r_addr_p = mmu_tte_to_pa(*tte_addr, pxu_p);
		*attr_p = (*tte_addr & MMU_TTE_W) ?
		    PCI_MAP_ATTR_WRITE:PCI_MAP_ATTR_READ;
	} else {
		*r_addr_p = 0;
		*attr_p = 0;
		ret = H_ENOMAP;
	}

	return (ret);
}

/* ARGSUSED */
uint64_t
hvio_get_bypass_base(pxu_t *pxu_p)
{
	uint64_t base;

	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		base = MMU_OBERON_BYPASS_BASE;
		break;
	case PX_CHIP_FIRE:
		base = MMU_FIRE_BYPASS_BASE;
		break;
	default:
		DBG(DBG_MMU, NULL,
		    "hvio_get_bypass_base - unknown chip type: 0x%x\n",
		    PX_CHIP_TYPE(pxu_p));
		base = 0;
		break;
	}
	return (base);
}

/* ARGSUSED */
uint64_t
hvio_get_bypass_end(pxu_t *pxu_p)
{
	uint64_t end;

	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		end = MMU_OBERON_BYPASS_END;
		break;
	case PX_CHIP_FIRE:
		end = MMU_FIRE_BYPASS_END;
		break;
	default:
		DBG(DBG_MMU, NULL,
		    "hvio_get_bypass_end - unknown chip type: 0x%x\n",
		    PX_CHIP_TYPE(pxu_p));
		end = 0;
		break;
	}
	return (end);
}

/* ARGSUSED */
uint64_t
hvio_iommu_getbypass(devhandle_t dev_hdl, pxu_t *pxu_p, r_addr_t ra,
    io_attributes_t attr, io_addr_t *io_addr_p)
{
	uint64_t	pfn = MMU_BTOP(ra);

	*io_addr_p = hvio_get_bypass_base(pxu_p) | ra |
	    (pf_is_memory(pfn) ? 0 : mmu_bypass_noncache(pxu_p));

	return (H_EOK);
}

/*
 * Generic IO Interrupt Servies
 */

/*
 * Converts a device specific interrupt number given by the
 * arguments devhandle and devino into a system specific ino.
 */
/* ARGSUSED */
uint64_t
hvio_intr_devino_to_sysino(devhandle_t dev_hdl, pxu_t *pxu_p, devino_t devino,
    sysino_t *sysino)
{
	if (devino > INTERRUPT_MAPPING_ENTRIES) {
		DBG(DBG_IB, NULL, "ino %x is invalid\n", devino);
		return (H_ENOINTR);
	}

	*sysino = DEVINO_TO_SYSINO(pxu_p->portid, devino);

	return (H_EOK);
}

/*
 * Returns state in intr_valid_state if the interrupt defined by sysino
 * is valid (enabled) or not-valid (disabled).
 */
uint64_t
hvio_intr_getvalid(devhandle_t dev_hdl, sysino_t sysino,
    intr_valid_state_t *intr_valid_state)
{
	if (CSRA_BR((caddr_t)dev_hdl, INTERRUPT_MAPPING,
	    SYSINO_TO_DEVINO(sysino), ENTRIES_V)) {
		*intr_valid_state = INTR_VALID;
	} else {
		*intr_valid_state = INTR_NOTVALID;
	}

	return (H_EOK);
}

/*
 * Sets the 'valid' state of the interrupt defined by
 * the argument sysino to the state defined by the
 * argument intr_valid_state.
 */
uint64_t
hvio_intr_setvalid(devhandle_t dev_hdl, sysino_t sysino,
    intr_valid_state_t intr_valid_state)
{
	switch (intr_valid_state) {
	case INTR_VALID:
		CSRA_BS((caddr_t)dev_hdl, INTERRUPT_MAPPING,
		    SYSINO_TO_DEVINO(sysino), ENTRIES_V);
		break;
	case INTR_NOTVALID:
		CSRA_BC((caddr_t)dev_hdl, INTERRUPT_MAPPING,
		    SYSINO_TO_DEVINO(sysino), ENTRIES_V);
		break;
	default:
		return (EINVAL);
	}

	return (H_EOK);
}

/*
 * Returns the current state of the interrupt given by the sysino
 * argument.
 */
uint64_t
hvio_intr_getstate(devhandle_t dev_hdl, sysino_t sysino,
    intr_state_t *intr_state)
{
	intr_state_t state;

	state = CSRA_FR((caddr_t)dev_hdl, INTERRUPT_CLEAR,
	    SYSINO_TO_DEVINO(sysino), ENTRIES_INT_STATE);

	switch (state) {
	case INTERRUPT_IDLE_STATE:
		*intr_state = INTR_IDLE_STATE;
		break;
	case INTERRUPT_RECEIVED_STATE:
		*intr_state = INTR_RECEIVED_STATE;
		break;
	case INTERRUPT_PENDING_STATE:
		*intr_state = INTR_DELIVERED_STATE;
		break;
	default:
		return (EINVAL);
	}

	return (H_EOK);

}

/*
 * Sets the current state of the interrupt given by the sysino
 * argument to the value given in the argument intr_state.
 *
 * Note: Setting the state to INTR_IDLE clears any pending
 * interrupt for sysino.
 */
uint64_t
hvio_intr_setstate(devhandle_t dev_hdl, sysino_t sysino,
    intr_state_t intr_state)
{
	intr_state_t state;

	switch (intr_state) {
	case INTR_IDLE_STATE:
		state = INTERRUPT_IDLE_STATE;
		break;
	case INTR_DELIVERED_STATE:
		state = INTERRUPT_PENDING_STATE;
		break;
	default:
		return (EINVAL);
	}

	CSRA_FS((caddr_t)dev_hdl, INTERRUPT_CLEAR,
	    SYSINO_TO_DEVINO(sysino), ENTRIES_INT_STATE, state);

	return (H_EOK);
}

/*
 * Returns the cpuid that is the current target of the
 * interrupt given by the sysino argument.
 *
 * The cpuid value returned is undefined if the target
 * has not been set via intr_settarget.
 */
uint64_t
hvio_intr_gettarget(devhandle_t dev_hdl, pxu_t *pxu_p, sysino_t sysino,
    cpuid_t *cpuid)
{
	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		*cpuid = CSRA_FR((caddr_t)dev_hdl, INTERRUPT_MAPPING,
		    SYSINO_TO_DEVINO(sysino), ENTRIES_T_DESTID);
		break;
	case PX_CHIP_FIRE:
		*cpuid = CSRA_FR((caddr_t)dev_hdl, INTERRUPT_MAPPING,
		    SYSINO_TO_DEVINO(sysino), ENTRIES_T_JPID);
		break;
	default:
		DBG(DBG_CB, NULL, "hvio_intr_gettarget - "
		    "unknown chip type: 0x%x\n", PX_CHIP_TYPE(pxu_p));
		return (EINVAL);
	}

	return (H_EOK);
}

/*
 * Set the target cpu for the interrupt defined by the argument
 * sysino to the target cpu value defined by the argument cpuid.
 */
uint64_t
hvio_intr_settarget(devhandle_t dev_hdl, pxu_t *pxu_p, sysino_t sysino,
    cpuid_t cpuid)
{

	uint64_t	val, intr_controller;
	uint32_t	ino = SYSINO_TO_DEVINO(sysino);

	/*
	 * For now, we assign interrupt controller in a round
	 * robin fashion.  Later, we may need to come up with
	 * a more efficient assignment algorithm.
	 */
	intr_controller = 0x1ull << (cpuid % 4);

	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		val = (((cpuid &
		    INTERRUPT_MAPPING_ENTRIES_T_DESTID_MASK) <<
		    INTERRUPT_MAPPING_ENTRIES_T_DESTID) |
		    ((intr_controller &
		    INTERRUPT_MAPPING_ENTRIES_INT_CNTRL_NUM_MASK)
		    << INTERRUPT_MAPPING_ENTRIES_INT_CNTRL_NUM));
		break;
	case PX_CHIP_FIRE:
		val = (((cpuid & INTERRUPT_MAPPING_ENTRIES_T_JPID_MASK) <<
		    INTERRUPT_MAPPING_ENTRIES_T_JPID) |
		    ((intr_controller &
		    INTERRUPT_MAPPING_ENTRIES_INT_CNTRL_NUM_MASK)
		    << INTERRUPT_MAPPING_ENTRIES_INT_CNTRL_NUM));
		break;
	default:
		DBG(DBG_CB, NULL, "hvio_intr_settarget - "
		    "unknown chip type: 0x%x\n", PX_CHIP_TYPE(pxu_p));
		return (EINVAL);
	}

	/* For EQ interrupts, set DATA MONDO bit */
	if ((ino >= PX_DEFAULT_MSIQ_1ST_DEVINO) &&
	    (ino < (PX_DEFAULT_MSIQ_1ST_DEVINO + PX_DEFAULT_MSIQ_CNT)))
		val |= (0x1ull << INTERRUPT_MAPPING_ENTRIES_MDO_MODE);

	CSRA_XS((caddr_t)dev_hdl, INTERRUPT_MAPPING, ino, val);

	return (H_EOK);
}

/*
 * MSIQ Functions:
 */
uint64_t
hvio_msiq_init(devhandle_t dev_hdl, pxu_t *pxu_p)
{
	CSRA_XS((caddr_t)dev_hdl, EVENT_QUEUE_BASE_ADDRESS, 0,
	    (uint64_t)pxu_p->msiq_mapped_p);
	DBG(DBG_IB, NULL,
	    "hvio_msiq_init: EVENT_QUEUE_BASE_ADDRESS 0x%llx\n",
	    CSR_XR((caddr_t)dev_hdl, EVENT_QUEUE_BASE_ADDRESS));

	CSRA_XS((caddr_t)dev_hdl, INTERRUPT_MONDO_DATA_0, 0,
	    (uint64_t)ID_TO_IGN(PX_CHIP_TYPE(pxu_p),
	    pxu_p->portid) << INO_BITS);
	DBG(DBG_IB, NULL, "hvio_msiq_init: "
	    "INTERRUPT_MONDO_DATA_0: 0x%llx\n",
	    CSR_XR((caddr_t)dev_hdl, INTERRUPT_MONDO_DATA_0));

	return (H_EOK);
}

uint64_t
hvio_msiq_getvalid(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_valid_state_t *msiq_valid_state)
{
	uint32_t	eq_state;
	uint64_t	ret = H_EOK;

	eq_state = CSRA_FR((caddr_t)dev_hdl, EVENT_QUEUE_STATE,
	    msiq_id, ENTRIES_STATE);

	switch (eq_state) {
	case EQ_IDLE_STATE:
		*msiq_valid_state = PCI_MSIQ_INVALID;
		break;
	case EQ_ACTIVE_STATE:
	case EQ_ERROR_STATE:
		*msiq_valid_state = PCI_MSIQ_VALID;
		break;
	default:
		ret = H_EIO;
		break;
	}

	return (ret);
}

uint64_t
hvio_msiq_setvalid(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_valid_state_t msiq_valid_state)
{
	uint64_t	ret = H_EOK;

	switch (msiq_valid_state) {
	case PCI_MSIQ_INVALID:
		CSRA_BS((caddr_t)dev_hdl, EVENT_QUEUE_CONTROL_CLEAR,
		    msiq_id, ENTRIES_DIS);
		break;
	case PCI_MSIQ_VALID:
		CSRA_BS((caddr_t)dev_hdl, EVENT_QUEUE_CONTROL_SET,
		    msiq_id, ENTRIES_EN);
		break;
	default:
		ret = H_EINVAL;
		break;
	}

	return (ret);
}

uint64_t
hvio_msiq_getstate(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_state_t *msiq_state)
{
	uint32_t	eq_state;
	uint64_t	ret = H_EOK;

	eq_state = CSRA_FR((caddr_t)dev_hdl, EVENT_QUEUE_STATE,
	    msiq_id, ENTRIES_STATE);

	switch (eq_state) {
	case EQ_IDLE_STATE:
	case EQ_ACTIVE_STATE:
		*msiq_state = PCI_MSIQ_STATE_IDLE;
		break;
	case EQ_ERROR_STATE:
		*msiq_state = PCI_MSIQ_STATE_ERROR;
		break;
	default:
		ret = H_EIO;
	}

	return (ret);
}

uint64_t
hvio_msiq_setstate(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_state_t msiq_state)
{
	uint32_t	eq_state;
	uint64_t	ret = H_EOK;

	eq_state = CSRA_FR((caddr_t)dev_hdl, EVENT_QUEUE_STATE,
	    msiq_id, ENTRIES_STATE);

	switch (eq_state) {
	case EQ_IDLE_STATE:
		if (msiq_state == PCI_MSIQ_STATE_ERROR)
			ret = H_EIO;
		break;
	case EQ_ACTIVE_STATE:
		if (msiq_state == PCI_MSIQ_STATE_ERROR)
			CSRA_BS((caddr_t)dev_hdl, EVENT_QUEUE_CONTROL_SET,
			    msiq_id, ENTRIES_ENOVERR);
		else
			ret = H_EIO;
		break;
	case EQ_ERROR_STATE:
		if (msiq_state == PCI_MSIQ_STATE_IDLE)
			CSRA_BS((caddr_t)dev_hdl, EVENT_QUEUE_CONTROL_CLEAR,
			    msiq_id, ENTRIES_E2I);
		else
			ret = H_EIO;
		break;
	default:
		ret = H_EIO;
	}

	return (ret);
}

uint64_t
hvio_msiq_gethead(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqhead_t *msiq_head)
{
	*msiq_head = CSRA_FR((caddr_t)dev_hdl, EVENT_QUEUE_HEAD,
	    msiq_id, ENTRIES_HEAD);

	return (H_EOK);
}

uint64_t
hvio_msiq_sethead(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqhead_t msiq_head)
{
	CSRA_FS((caddr_t)dev_hdl, EVENT_QUEUE_HEAD, msiq_id,
	    ENTRIES_HEAD, msiq_head);

	return (H_EOK);
}

uint64_t
hvio_msiq_gettail(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqtail_t *msiq_tail)
{
	*msiq_tail = CSRA_FR((caddr_t)dev_hdl, EVENT_QUEUE_TAIL,
	    msiq_id, ENTRIES_TAIL);

	return (H_EOK);
}

/*
 * MSI Functions:
 */
uint64_t
hvio_msi_init(devhandle_t dev_hdl, uint64_t addr32, uint64_t addr64)
{
	/* PCI MEM 32 resources to perform 32 bit MSI transactions */
	CSRA_FS((caddr_t)dev_hdl, MSI_32_BIT_ADDRESS, 0,
	    ADDR, (uint64_t)addr32 >> MSI_32_BIT_ADDRESS_ADDR);
	DBG(DBG_IB, NULL, "hvio_msi_init: MSI_32_BIT_ADDRESS: 0x%llx\n",
	    CSR_XR((caddr_t)dev_hdl, MSI_32_BIT_ADDRESS));

	/* Reserve PCI MEM 64 resources to perform 64 bit MSI transactions */
	CSRA_FS((caddr_t)dev_hdl, MSI_64_BIT_ADDRESS, 0,
	    ADDR, (uint64_t)addr64 >> MSI_64_BIT_ADDRESS_ADDR);
	DBG(DBG_IB, NULL, "hvio_msi_init: MSI_64_BIT_ADDRESS: 0x%llx\n",
	    CSR_XR((caddr_t)dev_hdl, MSI_64_BIT_ADDRESS));

	return (H_EOK);
}

uint64_t
hvio_msi_getmsiq(devhandle_t dev_hdl, msinum_t msi_num,
    msiqid_t *msiq_id)
{
	*msiq_id = CSRA_FR((caddr_t)dev_hdl, MSI_MAPPING,
	    msi_num, ENTRIES_EQNUM);

	return (H_EOK);
}

uint64_t
hvio_msi_setmsiq(devhandle_t dev_hdl, msinum_t msi_num,
    msiqid_t msiq_id)
{
	CSRA_FS((caddr_t)dev_hdl, MSI_MAPPING, msi_num,
	    ENTRIES_EQNUM, msiq_id);

	return (H_EOK);
}

uint64_t
hvio_msi_getvalid(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_valid_state_t *msi_valid_state)
{
	*msi_valid_state = CSRA_BR((caddr_t)dev_hdl, MSI_MAPPING,
	    msi_num, ENTRIES_V);

	return (H_EOK);
}

uint64_t
hvio_msi_setvalid(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_valid_state_t msi_valid_state)
{
	uint64_t	ret = H_EOK;

	switch (msi_valid_state) {
	case PCI_MSI_VALID:
		CSRA_BS((caddr_t)dev_hdl, MSI_MAPPING, msi_num,
		    ENTRIES_V);
		break;
	case PCI_MSI_INVALID:
		CSRA_BC((caddr_t)dev_hdl, MSI_MAPPING, msi_num,
		    ENTRIES_V);
		break;
	default:
		ret = H_EINVAL;
	}

	return (ret);
}

uint64_t
hvio_msi_getstate(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_state_t *msi_state)
{
	*msi_state = CSRA_BR((caddr_t)dev_hdl, MSI_MAPPING,
	    msi_num, ENTRIES_EQWR_N);

	return (H_EOK);
}

uint64_t
hvio_msi_setstate(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_state_t msi_state)
{
	uint64_t	ret = H_EOK;

	switch (msi_state) {
	case PCI_MSI_STATE_IDLE:
		CSRA_BS((caddr_t)dev_hdl, MSI_CLEAR, msi_num,
		    ENTRIES_EQWR_N);
		break;
	case PCI_MSI_STATE_DELIVERED:
	default:
		ret = H_EINVAL;
		break;
	}

	return (ret);
}

/*
 * MSG Functions:
 */
uint64_t
hvio_msg_getmsiq(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    msiqid_t *msiq_id)
{
	uint64_t	ret = H_EOK;

	switch (msg_type) {
	case PCIE_PME_MSG:
		*msiq_id = CSR_FR((caddr_t)dev_hdl, PM_PME_MAPPING, EQNUM);
		break;
	case PCIE_PME_ACK_MSG:
		*msiq_id = CSR_FR((caddr_t)dev_hdl, PME_TO_ACK_MAPPING,
		    EQNUM);
		break;
	case PCIE_CORR_MSG:
		*msiq_id = CSR_FR((caddr_t)dev_hdl, ERR_COR_MAPPING, EQNUM);
		break;
	case PCIE_NONFATAL_MSG:
		*msiq_id = CSR_FR((caddr_t)dev_hdl, ERR_NONFATAL_MAPPING,
		    EQNUM);
		break;
	case PCIE_FATAL_MSG:
		*msiq_id = CSR_FR((caddr_t)dev_hdl, ERR_FATAL_MAPPING, EQNUM);
		break;
	default:
		ret = H_EINVAL;
		break;
	}

	return (ret);
}

uint64_t
hvio_msg_setmsiq(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    msiqid_t msiq_id)
{
	uint64_t	ret = H_EOK;

	switch (msg_type) {
	case PCIE_PME_MSG:
		CSR_FS((caddr_t)dev_hdl, PM_PME_MAPPING, EQNUM, msiq_id);
		break;
	case PCIE_PME_ACK_MSG:
		CSR_FS((caddr_t)dev_hdl, PME_TO_ACK_MAPPING, EQNUM, msiq_id);
		break;
	case PCIE_CORR_MSG:
		CSR_FS((caddr_t)dev_hdl, ERR_COR_MAPPING, EQNUM, msiq_id);
		break;
	case PCIE_NONFATAL_MSG:
		CSR_FS((caddr_t)dev_hdl, ERR_NONFATAL_MAPPING, EQNUM, msiq_id);
		break;
	case PCIE_FATAL_MSG:
		CSR_FS((caddr_t)dev_hdl, ERR_FATAL_MAPPING, EQNUM, msiq_id);
		break;
	default:
		ret = H_EINVAL;
		break;
	}

	return (ret);
}

uint64_t
hvio_msg_getvalid(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t *msg_valid_state)
{
	uint64_t	ret = H_EOK;

	switch (msg_type) {
	case PCIE_PME_MSG:
		*msg_valid_state = CSR_BR((caddr_t)dev_hdl, PM_PME_MAPPING, V);
		break;
	case PCIE_PME_ACK_MSG:
		*msg_valid_state = CSR_BR((caddr_t)dev_hdl,
		    PME_TO_ACK_MAPPING, V);
		break;
	case PCIE_CORR_MSG:
		*msg_valid_state = CSR_BR((caddr_t)dev_hdl, ERR_COR_MAPPING, V);
		break;
	case PCIE_NONFATAL_MSG:
		*msg_valid_state = CSR_BR((caddr_t)dev_hdl,
		    ERR_NONFATAL_MAPPING, V);
		break;
	case PCIE_FATAL_MSG:
		*msg_valid_state = CSR_BR((caddr_t)dev_hdl, ERR_FATAL_MAPPING,
		    V);
		break;
	default:
		ret = H_EINVAL;
		break;
	}

	return (ret);
}

uint64_t
hvio_msg_setvalid(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t msg_valid_state)
{
	uint64_t	ret = H_EOK;

	switch (msg_valid_state) {
	case PCIE_MSG_VALID:
		switch (msg_type) {
		case PCIE_PME_MSG:
			CSR_BS((caddr_t)dev_hdl, PM_PME_MAPPING, V);
			break;
		case PCIE_PME_ACK_MSG:
			CSR_BS((caddr_t)dev_hdl, PME_TO_ACK_MAPPING, V);
			break;
		case PCIE_CORR_MSG:
			CSR_BS((caddr_t)dev_hdl, ERR_COR_MAPPING, V);
			break;
		case PCIE_NONFATAL_MSG:
			CSR_BS((caddr_t)dev_hdl, ERR_NONFATAL_MAPPING, V);
			break;
		case PCIE_FATAL_MSG:
			CSR_BS((caddr_t)dev_hdl, ERR_FATAL_MAPPING, V);
			break;
		default:
			ret = H_EINVAL;
			break;
		}

		break;
	case PCIE_MSG_INVALID:
		switch (msg_type) {
		case PCIE_PME_MSG:
			CSR_BC((caddr_t)dev_hdl, PM_PME_MAPPING, V);
			break;
		case PCIE_PME_ACK_MSG:
			CSR_BC((caddr_t)dev_hdl, PME_TO_ACK_MAPPING, V);
			break;
		case PCIE_CORR_MSG:
			CSR_BC((caddr_t)dev_hdl, ERR_COR_MAPPING, V);
			break;
		case PCIE_NONFATAL_MSG:
			CSR_BC((caddr_t)dev_hdl, ERR_NONFATAL_MAPPING, V);
			break;
		case PCIE_FATAL_MSG:
			CSR_BC((caddr_t)dev_hdl, ERR_FATAL_MAPPING, V);
			break;
		default:
			ret = H_EINVAL;
			break;
		}
		break;
	default:
		ret = H_EINVAL;
	}

	return (ret);
}

/*
 * Suspend/Resume Functions:
 *	(pec, mmu, ib)
 *	cb
 * Registers saved have all been touched in the XXX_init functions.
 */
uint64_t
hvio_suspend(devhandle_t dev_hdl, pxu_t *pxu_p)
{
	uint64_t	*config_state;
	int		total_size;
	int		i;

	if (msiq_suspend(dev_hdl, pxu_p) != H_EOK)
		return (H_EIO);

	total_size = PEC_SIZE + MMU_SIZE + IB_SIZE + IB_MAP_SIZE;
	config_state = kmem_zalloc(total_size, KM_NOSLEEP);

	if (config_state == NULL) {
		return (H_EIO);
	}

	/*
	 * Soft state for suspend/resume  from pxu_t
	 * uint64_t	*pec_config_state;
	 * uint64_t	*mmu_config_state;
	 * uint64_t	*ib_intr_map;
	 * uint64_t	*ib_config_state;
	 * uint64_t	*xcb_config_state;
	 */

	/* Save the PEC configuration states */
	pxu_p->pec_config_state = config_state;
	for (i = 0; i < PEC_KEYS; i++) {
		if ((pec_config_state_regs[i].chip == PX_CHIP_TYPE(pxu_p)) ||
		    (pec_config_state_regs[i].chip == PX_CHIP_UNIDENTIFIED)) {
			pxu_p->pec_config_state[i] =
			    CSR_XR((caddr_t)dev_hdl,
			    pec_config_state_regs[i].reg);
		}
	}

	/* Save the MMU configuration states */
	pxu_p->mmu_config_state = pxu_p->pec_config_state + PEC_KEYS;
	for (i = 0; i < MMU_KEYS; i++) {
		pxu_p->mmu_config_state[i] =
		    CSR_XR((caddr_t)dev_hdl, mmu_config_state_regs[i]);
	}

	/* Save the interrupt mapping registers */
	pxu_p->ib_intr_map = pxu_p->mmu_config_state + MMU_KEYS;
	for (i = 0; i < INTERRUPT_MAPPING_ENTRIES; i++) {
		pxu_p->ib_intr_map[i] =
		    CSRA_XR((caddr_t)dev_hdl, INTERRUPT_MAPPING, i);
	}

	/* Save the IB configuration states */
	pxu_p->ib_config_state = pxu_p->ib_intr_map + INTERRUPT_MAPPING_ENTRIES;
	for (i = 0; i < IB_KEYS; i++) {
		pxu_p->ib_config_state[i] =
		    CSR_XR((caddr_t)dev_hdl, ib_config_state_regs[i]);
	}

	return (H_EOK);
}

void
hvio_resume(devhandle_t dev_hdl, devino_t devino, pxu_t *pxu_p)
{
	int		total_size;
	sysino_t	sysino;
	int		i;
	uint64_t	ret;

	/* Make sure that suspend actually did occur */
	if (!pxu_p->pec_config_state) {
		return;
	}

	/* Restore IB configuration states */
	for (i = 0; i < IB_KEYS; i++) {
		CSR_XS((caddr_t)dev_hdl, ib_config_state_regs[i],
		    pxu_p->ib_config_state[i]);
	}

	/*
	 * Restore the interrupt mapping registers
	 * And make sure the intrs are idle.
	 */
	for (i = 0; i < INTERRUPT_MAPPING_ENTRIES; i++) {
		CSRA_FS((caddr_t)dev_hdl, INTERRUPT_CLEAR, i,
		    ENTRIES_INT_STATE, INTERRUPT_IDLE_STATE);
		CSRA_XS((caddr_t)dev_hdl, INTERRUPT_MAPPING, i,
		    pxu_p->ib_intr_map[i]);
	}

	/* Restore MMU configuration states */
	/* Clear the cache. */
	CSR_XS((caddr_t)dev_hdl, MMU_TTE_CACHE_INVALIDATE, -1ull);

	for (i = 0; i < MMU_KEYS; i++) {
		CSR_XS((caddr_t)dev_hdl, mmu_config_state_regs[i],
		    pxu_p->mmu_config_state[i]);
	}

	/* Restore PEC configuration states */
	/* Make sure all reset bits are low until error is detected */
	CSR_XS((caddr_t)dev_hdl, LPU_RESET, 0ull);

	for (i = 0; i < PEC_KEYS; i++) {
		if ((pec_config_state_regs[i].chip == PX_CHIP_TYPE(pxu_p)) ||
		    (pec_config_state_regs[i].chip == PX_CHIP_UNIDENTIFIED)) {
			CSR_XS((caddr_t)dev_hdl, pec_config_state_regs[i].reg,
			    pxu_p->pec_config_state[i]);
		}
	}

	/* Enable PCI-E interrupt */
	if ((ret = hvio_intr_devino_to_sysino(dev_hdl, pxu_p, devino,
	    &sysino)) != H_EOK) {
		cmn_err(CE_WARN,
		    "hvio_resume: hvio_intr_devino_to_sysino failed, "
		    "ret 0x%lx", ret);
	}

	if ((ret =  hvio_intr_setstate(dev_hdl, sysino, INTR_IDLE_STATE))
	    != H_EOK) {
		cmn_err(CE_WARN,
		    "hvio_resume: hvio_intr_setstate failed, "
		    "ret 0x%lx", ret);
	}

	total_size = PEC_SIZE + MMU_SIZE + IB_SIZE + IB_MAP_SIZE;
	kmem_free(pxu_p->pec_config_state, total_size);

	pxu_p->pec_config_state = NULL;
	pxu_p->mmu_config_state = NULL;
	pxu_p->ib_config_state = NULL;
	pxu_p->ib_intr_map = NULL;

	msiq_resume(dev_hdl, pxu_p);
}

uint64_t
hvio_cb_suspend(devhandle_t dev_hdl, pxu_t *pxu_p)
{
	uint64_t *config_state, *cb_regs;
	int i, cb_size, cb_keys;

	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		cb_size = UBC_SIZE;
		cb_keys = UBC_KEYS;
		cb_regs = ubc_config_state_regs;
		break;
	case PX_CHIP_FIRE:
		cb_size = JBC_SIZE;
		cb_keys = JBC_KEYS;
		cb_regs = jbc_config_state_regs;
		break;
	default:
		DBG(DBG_CB, NULL, "hvio_cb_suspend - unknown chip type: 0x%x\n",
		    PX_CHIP_TYPE(pxu_p));
		break;
	}

	config_state = kmem_zalloc(cb_size, KM_NOSLEEP);

	if (config_state == NULL) {
		return (H_EIO);
	}

	/* Save the configuration states */
	pxu_p->xcb_config_state = config_state;
	for (i = 0; i < cb_keys; i++) {
		pxu_p->xcb_config_state[i] =
		    CSR_XR((caddr_t)dev_hdl, cb_regs[i]);
	}

	return (H_EOK);
}

void
hvio_cb_resume(devhandle_t pci_dev_hdl, devhandle_t xbus_dev_hdl,
    devino_t devino, pxu_t *pxu_p)
{
	sysino_t sysino;
	uint64_t *cb_regs;
	int i, cb_size, cb_keys;
	uint64_t ret;

	switch (PX_CHIP_TYPE(pxu_p)) {
	case PX_CHIP_OBERON:
		cb_size = UBC_SIZE;
		cb_keys = UBC_KEYS;
		cb_regs = ubc_config_state_regs;
		/*
		 * No reason to have any reset bits high until an error is
		 * detected on the link.
		 */
		CSR_XS((caddr_t)xbus_dev_hdl, UBC_ERROR_STATUS_CLEAR, -1ull);
		break;
	case PX_CHIP_FIRE:
		cb_size = JBC_SIZE;
		cb_keys = JBC_KEYS;
		cb_regs = jbc_config_state_regs;
		/*
		 * No reason to have any reset bits high until an error is
		 * detected on the link.
		 */
		CSR_XS((caddr_t)xbus_dev_hdl, JBC_ERROR_STATUS_CLEAR, -1ull);
		break;
	default:
		DBG(DBG_CB, NULL, "hvio_cb_resume - unknown chip type: 0x%x\n",
		    PX_CHIP_TYPE(pxu_p));
		break;
	}

	ASSERT(pxu_p->xcb_config_state);

	/* Restore the configuration states */
	for (i = 0; i < cb_keys; i++) {
		CSR_XS((caddr_t)xbus_dev_hdl, cb_regs[i],
		    pxu_p->xcb_config_state[i]);
	}

	/* Enable XBC interrupt */
	if ((ret = hvio_intr_devino_to_sysino(pci_dev_hdl, pxu_p, devino,
	    &sysino)) != H_EOK) {
		cmn_err(CE_WARN,
		    "hvio_cb_resume: hvio_intr_devino_to_sysino failed, "
		    "ret 0x%lx", ret);
	}

	if ((ret = hvio_intr_setstate(pci_dev_hdl, sysino, INTR_IDLE_STATE))
	    != H_EOK) {
		cmn_err(CE_WARN,
		    "hvio_cb_resume: hvio_intr_setstate failed, "
		    "ret 0x%lx", ret);
	}

	kmem_free(pxu_p->xcb_config_state, cb_size);

	pxu_p->xcb_config_state = NULL;
}

static uint64_t
msiq_suspend(devhandle_t dev_hdl, pxu_t *pxu_p)
{
	size_t	bufsz;
	volatile uint64_t *cur_p;
	int i;

	bufsz = MSIQ_STATE_SIZE + MSIQ_MAPPING_SIZE + MSIQ_OTHER_SIZE;
	if ((pxu_p->msiq_config_state = kmem_zalloc(bufsz, KM_NOSLEEP)) ==
	    NULL)
		return (H_EIO);

	cur_p = pxu_p->msiq_config_state;

	/* Save each EQ state */
	for (i = 0; i < EVENT_QUEUE_STATE_ENTRIES; i++, cur_p++)
		*cur_p = CSRA_XR((caddr_t)dev_hdl, EVENT_QUEUE_STATE, i);

	/* Save MSI mapping registers */
	for (i = 0; i < MSI_MAPPING_ENTRIES; i++, cur_p++)
		*cur_p = CSRA_XR((caddr_t)dev_hdl, MSI_MAPPING, i);

	/* Save all other MSIQ registers */
	for (i = 0; i < MSIQ_OTHER_KEYS; i++, cur_p++)
		*cur_p = CSR_XR((caddr_t)dev_hdl, msiq_config_other_regs[i]);
	return (H_EOK);
}

static void
msiq_resume(devhandle_t dev_hdl, pxu_t *pxu_p)
{
	size_t	bufsz;
	uint64_t *cur_p, state;
	int i;
	uint64_t ret;

	bufsz = MSIQ_STATE_SIZE + MSIQ_MAPPING_SIZE + MSIQ_OTHER_SIZE;
	cur_p = pxu_p->msiq_config_state;
	/*
	 * Initialize EQ base address register and
	 * Interrupt Mondo Data 0 register.
	 */
	if ((ret = hvio_msiq_init(dev_hdl, pxu_p)) != H_EOK) {
		cmn_err(CE_WARN,
		    "msiq_resume: hvio_msiq_init failed, "
		    "ret 0x%lx", ret);
	}

	/* Restore EQ states */
	for (i = 0; i < EVENT_QUEUE_STATE_ENTRIES; i++, cur_p++) {
		state = (*cur_p) & EVENT_QUEUE_STATE_ENTRIES_STATE_MASK;
		if ((state == EQ_ACTIVE_STATE) || (state == EQ_ERROR_STATE))
			CSRA_BS((caddr_t)dev_hdl, EVENT_QUEUE_CONTROL_SET,
			    i, ENTRIES_EN);
	}

	/* Restore MSI mapping */
	for (i = 0; i < MSI_MAPPING_ENTRIES; i++, cur_p++)
		CSRA_XS((caddr_t)dev_hdl, MSI_MAPPING, i, *cur_p);

	/*
	 * Restore all other registers. MSI 32 bit address and
	 * MSI 64 bit address are restored as part of this.
	 */
	for (i = 0; i < MSIQ_OTHER_KEYS; i++, cur_p++)
		CSR_XS((caddr_t)dev_hdl, msiq_config_other_regs[i], *cur_p);

	kmem_free(pxu_p->msiq_config_state, bufsz);
	pxu_p->msiq_config_state = NULL;
}

/*
 * sends PME_Turn_Off message to put the link in L2/L3 ready state.
 * called by px_goto_l23ready.
 * returns DDI_SUCCESS or DDI_FAILURE
 */
int
px_send_pme_turnoff(caddr_t csr_base)
{
	volatile uint64_t reg;

	reg = CSR_XR(csr_base, TLU_PME_TURN_OFF_GENERATE);
	/* If already pending, return failure */
	if (reg & (1ull << TLU_PME_TURN_OFF_GENERATE_PTO)) {
		DBG(DBG_PWR, NULL, "send_pme_turnoff: pending PTO bit "
		    "tlu_pme_turn_off_generate = %x\n", reg);
		return (DDI_FAILURE);
	}

	/* write to PME_Turn_off reg to boradcast */
	reg |= (1ull << TLU_PME_TURN_OFF_GENERATE_PTO);
	CSR_XS(csr_base,  TLU_PME_TURN_OFF_GENERATE, reg);

	return (DDI_SUCCESS);
}

/*
 * Checks for link being in L1idle state.
 * Returns
 * DDI_SUCCESS - if the link is in L1idle
 * DDI_FAILURE - if the link is not in L1idle
 */
int
px_link_wait4l1idle(caddr_t csr_base)
{
	uint8_t ltssm_state;
	int ntries = px_max_l1_tries;

	while (ntries > 0) {
		ltssm_state = CSR_FR(csr_base, LPU_LTSSM_STATUS1, LTSSM_STATE);
		if (ltssm_state == LPU_LTSSM_L1_IDLE || (--ntries <= 0))
			break;
		delay(1);
	}
	DBG(DBG_PWR, NULL, "check_for_l1idle: ltssm_state %x\n", ltssm_state);
	return ((ltssm_state == LPU_LTSSM_L1_IDLE) ? DDI_SUCCESS : DDI_FAILURE);
}

/*
 * Tranisition the link to L0, after it is down.
 */
int
px_link_retrain(caddr_t csr_base)
{
	volatile uint64_t reg;

	reg = CSR_XR(csr_base, TLU_CONTROL);
	if (!(reg & (1ull << TLU_REMAIN_DETECT_QUIET))) {
		DBG(DBG_PWR, NULL, "retrain_link: detect.quiet bit not set\n");
		return (DDI_FAILURE);
	}

	/* Clear link down bit in TLU Other Event Clear Status Register. */
	CSR_BS(csr_base, TLU_OTHER_EVENT_STATUS_CLEAR, LDN_P);

	/* Clear Drain bit in TLU Status Register */
	CSR_BS(csr_base, TLU_STATUS, DRAIN);

	/* Clear Remain in Detect.Quiet bit in TLU Control Register */
	reg = CSR_XR(csr_base, TLU_CONTROL);
	reg &= ~(1ull << TLU_REMAIN_DETECT_QUIET);
	CSR_XS(csr_base, TLU_CONTROL, reg);

	return (DDI_SUCCESS);
}

void
px_enable_detect_quiet(caddr_t csr_base)
{
	volatile uint64_t tlu_ctrl;

	tlu_ctrl = CSR_XR(csr_base, TLU_CONTROL);
	tlu_ctrl |= (1ull << TLU_REMAIN_DETECT_QUIET);
	CSR_XS(csr_base, TLU_CONTROL, tlu_ctrl);
}

static uint_t
oberon_hp_pwron(caddr_t csr_base)
{
	volatile uint64_t reg;
	boolean_t link_retry, link_up;
	int loop, i;

	DBG(DBG_HP, NULL, "oberon_hp_pwron the slot\n");

	/* Check Leaf Reset status */
	reg = CSR_XR(csr_base, ILU_ERROR_LOG_ENABLE);
	if (!(reg & (1ull << ILU_ERROR_LOG_ENABLE_SPARE3))) {
		DBG(DBG_HP, NULL, "oberon_hp_pwron fails: leaf not reset\n");
		goto fail;
	}

	/* Check HP Capable */
	if (!CSR_BR(csr_base, TLU_SLOT_CAPABILITIES, HP)) {
		DBG(DBG_HP, NULL, "oberon_hp_pwron fails: leaf not "
		    "hotplugable\n");
		goto fail;
	}

	/* Check Slot status */
	reg = CSR_XR(csr_base, TLU_SLOT_STATUS);
	if (!(reg & (1ull << TLU_SLOT_STATUS_PSD)) ||
	    (reg & (1ull << TLU_SLOT_STATUS_MRLS))) {
		DBG(DBG_HP, NULL, "oberon_hp_pwron fails: slot status %lx\n",
		    reg);
		goto fail;
	}

	/* Blink power LED, this is done from pciehpc already */

	/* Turn on slot power */
	CSR_BS(csr_base, HOTPLUG_CONTROL, PWREN);

	/* power fault detection */
	delay(drv_usectohz(25000));
	CSR_BS(csr_base, TLU_SLOT_STATUS, PWFD);
	CSR_BC(csr_base, HOTPLUG_CONTROL, PWREN);

	/* wait to check power state */
	delay(drv_usectohz(25000));

	if (!CSR_BR(csr_base, TLU_SLOT_STATUS, PWFD)) {
		DBG(DBG_HP, NULL, "oberon_hp_pwron fails: power fault\n");
		goto fail1;
	}

	/* power is good */
	CSR_BS(csr_base, HOTPLUG_CONTROL, PWREN);

	delay(drv_usectohz(25000));
	CSR_BS(csr_base, TLU_SLOT_STATUS, PWFD);
	CSR_BS(csr_base, TLU_SLOT_CONTROL, PWFDEN);

	/* Turn on slot clock */
	CSR_BS(csr_base, HOTPLUG_CONTROL, CLKEN);

	link_up = B_FALSE;
	link_retry = B_FALSE;

	for (loop = 0; (loop < link_retry_count) && (link_up == B_FALSE);
	    loop++) {
		if (link_retry == B_TRUE) {
			DBG(DBG_HP, NULL, "oberon_hp_pwron : retry link loop "
			    "%d\n", loop);
			CSR_BS(csr_base, TLU_CONTROL, DRN_TR_DIS);
			CSR_XS(csr_base, FLP_PORT_CONTROL, 0x1);
			delay(drv_usectohz(10000));
			CSR_BC(csr_base, TLU_CONTROL, DRN_TR_DIS);
			CSR_BS(csr_base, TLU_DIAGNOSTIC, IFC_DIS);
			CSR_BC(csr_base, HOTPLUG_CONTROL, N_PERST);
			delay(drv_usectohz(50000));
		}

		/* Release PCI-E Reset */
		delay(drv_usectohz(wait_perst));
		CSR_BS(csr_base, HOTPLUG_CONTROL, N_PERST);

		/*
		 * Open events' mask
		 * This should be done from pciehpc already
		 */

		/* Enable PCIE port */
		delay(drv_usectohz(wait_enable_port));
		CSR_BS(csr_base, TLU_CONTROL, DRN_TR_DIS);
		CSR_XS(csr_base, FLP_PORT_CONTROL, 0x20);

		/* wait for the link up */
		/* BEGIN CSTYLED */
		for (i = 0; (i < 2) && (link_up == B_FALSE); i++) {
			delay(drv_usectohz(link_status_check));
			reg = CSR_XR(csr_base, DLU_LINK_LAYER_STATUS);

		    if ((((reg >> DLU_LINK_LAYER_STATUS_INIT_FC_SM_STS) &
			DLU_LINK_LAYER_STATUS_INIT_FC_SM_STS_MASK) ==
			DLU_LINK_LAYER_STATUS_INIT_FC_SM_STS_FC_INIT_DONE) &&
			(reg & (1ull << DLU_LINK_LAYER_STATUS_DLUP_STS)) &&
			((reg & DLU_LINK_LAYER_STATUS_LNK_STATE_MACH_STS_MASK)
			==
			DLU_LINK_LAYER_STATUS_LNK_STATE_MACH_STS_DL_ACTIVE)) {
			DBG(DBG_HP, NULL, "oberon_hp_pwron : link is up\n");
				link_up = B_TRUE;
		    } else
			link_retry = B_TRUE;
		}
		/* END CSTYLED */
	}

	if (link_up == B_FALSE) {
		DBG(DBG_HP, NULL, "oberon_hp_pwron fails to enable "
		    "PCI-E port\n");
		goto fail2;
	}

	/* link is up */
	CSR_BC(csr_base, TLU_DIAGNOSTIC, IFC_DIS);
	CSR_BS(csr_base, FLP_PORT_ACTIVE_STATUS, TRAIN_ERROR);
	CSR_BS(csr_base, TLU_UNCORRECTABLE_ERROR_STATUS_CLEAR, TE_P);
	CSR_BS(csr_base, TLU_UNCORRECTABLE_ERROR_STATUS_CLEAR, TE_S);
	CSR_BC(csr_base, TLU_CONTROL, DRN_TR_DIS);

	/* Restore LUP/LDN */
	reg = CSR_XR(csr_base, TLU_OTHER_EVENT_LOG_ENABLE);
	if (px_tlu_oe_log_mask & (1ull << TLU_OTHER_EVENT_STATUS_SET_LUP_P))
		reg |= 1ull << TLU_OTHER_EVENT_STATUS_SET_LUP_P;
	if (px_tlu_oe_log_mask & (1ull << TLU_OTHER_EVENT_STATUS_SET_LDN_P))
		reg |= 1ull << TLU_OTHER_EVENT_STATUS_SET_LDN_P;
	if (px_tlu_oe_log_mask & (1ull << TLU_OTHER_EVENT_STATUS_SET_LUP_S))
		reg |= 1ull << TLU_OTHER_EVENT_STATUS_SET_LUP_S;
	if (px_tlu_oe_log_mask & (1ull << TLU_OTHER_EVENT_STATUS_SET_LDN_S))
		reg |= 1ull << TLU_OTHER_EVENT_STATUS_SET_LDN_S;
	CSR_XS(csr_base, TLU_OTHER_EVENT_LOG_ENABLE, reg);

	/*
	 * Initialize Leaf
	 * SPLS = 00b, SPLV = 11001b, i.e. 25W
	 */
	reg = CSR_XR(csr_base, TLU_SLOT_CAPABILITIES);
	reg &= ~(TLU_SLOT_CAPABILITIES_SPLS_MASK <<
	    TLU_SLOT_CAPABILITIES_SPLS);
	reg &= ~(TLU_SLOT_CAPABILITIES_SPLV_MASK <<
	    TLU_SLOT_CAPABILITIES_SPLV);
	reg |= (0x19 << TLU_SLOT_CAPABILITIES_SPLV);
	CSR_XS(csr_base, TLU_SLOT_CAPABILITIES, reg);

	/* Turn on Power LED */
	reg = CSR_XR(csr_base, TLU_SLOT_CONTROL);
	reg &= ~PCIE_SLOTCTL_PWR_INDICATOR_MASK;
	reg = pcie_slotctl_pwr_indicator_set(reg,
	    PCIE_SLOTCTL_INDICATOR_STATE_ON);
	CSR_XS(csr_base, TLU_SLOT_CONTROL, reg);

	/* Notify to SCF */
	if (CSR_BR(csr_base, HOTPLUG_CONTROL, SLOTPON))
		CSR_BC(csr_base, HOTPLUG_CONTROL, SLOTPON);
	else
		CSR_BS(csr_base, HOTPLUG_CONTROL, SLOTPON);

	/* Wait for one second */
	delay(drv_usectohz(1000000));

	return (DDI_SUCCESS);

fail2:
	/* Link up is failed */
	CSR_BS(csr_base, FLP_PORT_CONTROL, PORT_DIS);
	CSR_BC(csr_base, HOTPLUG_CONTROL, N_PERST);
	delay(drv_usectohz(150));

	CSR_BC(csr_base, HOTPLUG_CONTROL, CLKEN);
	delay(drv_usectohz(100));

fail1:
	CSR_BC(csr_base, TLU_SLOT_CONTROL, PWFDEN);

	CSR_BC(csr_base, HOTPLUG_CONTROL, PWREN);

	reg = CSR_XR(csr_base, TLU_SLOT_CONTROL);
	reg &= ~PCIE_SLOTCTL_PWR_INDICATOR_MASK;
	reg = pcie_slotctl_pwr_indicator_set(reg,
	    PCIE_SLOTCTL_INDICATOR_STATE_OFF);
	CSR_XS(csr_base, TLU_SLOT_CONTROL, reg);

	CSR_BC(csr_base, TLU_SLOT_STATUS, PWFD);

fail:
	return ((uint_t)DDI_FAILURE);
}

hrtime_t oberon_leaf_reset_timeout = 120ll * NANOSEC;	/* 120 seconds */

static uint_t
oberon_hp_pwroff(caddr_t csr_base)
{
	volatile uint64_t reg;
	volatile uint64_t reg_tluue, reg_tluce;
	hrtime_t start_time, end_time;

	DBG(DBG_HP, NULL, "oberon_hp_pwroff the slot\n");

	/* Blink power LED, this is done from pciehpc already */

	/* Clear Slot Event */
	CSR_BS(csr_base, TLU_SLOT_STATUS, PSDC);
	CSR_BS(csr_base, TLU_SLOT_STATUS, PWFD);

	/* DRN_TR_DIS on */
	CSR_BS(csr_base, TLU_CONTROL, DRN_TR_DIS);
	delay(drv_usectohz(10000));

	/* Disable LUP/LDN */
	reg = CSR_XR(csr_base, TLU_OTHER_EVENT_LOG_ENABLE);
	reg &= ~((1ull << TLU_OTHER_EVENT_STATUS_SET_LDN_P) |
	    (1ull << TLU_OTHER_EVENT_STATUS_SET_LUP_P) |
	    (1ull << TLU_OTHER_EVENT_STATUS_SET_LDN_S) |
	    (1ull << TLU_OTHER_EVENT_STATUS_SET_LUP_S));
	CSR_XS(csr_base, TLU_OTHER_EVENT_LOG_ENABLE, reg);

	/* Save the TLU registers */
	reg_tluue = CSR_XR(csr_base, TLU_UNCORRECTABLE_ERROR_LOG_ENABLE);
	reg_tluce = CSR_XR(csr_base, TLU_CORRECTABLE_ERROR_LOG_ENABLE);
	/* All clear */
	CSR_XS(csr_base, TLU_UNCORRECTABLE_ERROR_LOG_ENABLE, 0);
	CSR_XS(csr_base, TLU_CORRECTABLE_ERROR_LOG_ENABLE, 0);

	/* Disable port */
	CSR_BS(csr_base, FLP_PORT_CONTROL, PORT_DIS);

	/* PCIE reset */
	delay(drv_usectohz(10000));
	CSR_BC(csr_base, HOTPLUG_CONTROL, N_PERST);

	/* PCIE clock stop */
	delay(drv_usectohz(150));
	CSR_BC(csr_base, HOTPLUG_CONTROL, CLKEN);

	/* Turn off slot power */
	delay(drv_usectohz(100));
	CSR_BC(csr_base, TLU_SLOT_CONTROL, PWFDEN);
	CSR_BC(csr_base, HOTPLUG_CONTROL, PWREN);
	delay(drv_usectohz(25000));
	CSR_BS(csr_base, TLU_SLOT_STATUS, PWFD);

	/* write 0 to bit 7 of ILU Error Log Enable Register */
	CSR_BC(csr_base, ILU_ERROR_LOG_ENABLE, SPARE3);

	/* Set back TLU registers */
	CSR_XS(csr_base, TLU_UNCORRECTABLE_ERROR_LOG_ENABLE, reg_tluue);
	CSR_XS(csr_base, TLU_CORRECTABLE_ERROR_LOG_ENABLE, reg_tluce);

	/* Power LED off */
	reg = CSR_XR(csr_base, TLU_SLOT_CONTROL);
	reg &= ~PCIE_SLOTCTL_PWR_INDICATOR_MASK;
	reg = pcie_slotctl_pwr_indicator_set(reg,
	    PCIE_SLOTCTL_INDICATOR_STATE_OFF);
	CSR_XS(csr_base, TLU_SLOT_CONTROL, reg);

	/* Indicator LED blink */
	reg = CSR_XR(csr_base, TLU_SLOT_CONTROL);
	reg &= ~PCIE_SLOTCTL_ATTN_INDICATOR_MASK;
	reg = pcie_slotctl_attn_indicator_set(reg,
	    PCIE_SLOTCTL_INDICATOR_STATE_BLINK);
	CSR_XS(csr_base, TLU_SLOT_CONTROL, reg);

	/* Notify to SCF */
	if (CSR_BR(csr_base, HOTPLUG_CONTROL, SLOTPON))
		CSR_BC(csr_base, HOTPLUG_CONTROL, SLOTPON);
	else
		CSR_BS(csr_base, HOTPLUG_CONTROL, SLOTPON);

	start_time = gethrtime();
	/* Check Leaf Reset status */
	while (!(CSR_BR(csr_base, ILU_ERROR_LOG_ENABLE, SPARE3))) {
		if ((end_time = (gethrtime() - start_time)) >
		    oberon_leaf_reset_timeout) {
			cmn_err(CE_WARN, "Oberon leaf reset is not completed, "
			    "even after waiting %llx ticks", end_time);

			break;
		}

		/* Wait for one second */
		delay(drv_usectohz(1000000));
	}

	/* Indicator LED off */
	reg = CSR_XR(csr_base, TLU_SLOT_CONTROL);
	reg &= ~PCIE_SLOTCTL_ATTN_INDICATOR_MASK;
	reg = pcie_slotctl_attn_indicator_set(reg,
	    PCIE_SLOTCTL_INDICATOR_STATE_OFF);
	CSR_XS(csr_base, TLU_SLOT_CONTROL, reg);

	return (DDI_SUCCESS);
}

static uint_t
oberon_hpreg_get(void *cookie, off_t off)
{
	caddr_t csr_base = *(caddr_t *)cookie;
	volatile uint64_t val = -1ull;

	switch (off) {
	case PCIE_SLOTCAP:
		val = CSR_XR(csr_base, TLU_SLOT_CAPABILITIES);
		break;
	case PCIE_SLOTCTL:
		val = CSR_XR(csr_base, TLU_SLOT_CONTROL);

		/* Get the power state */
		val |= (CSR_XR(csr_base, HOTPLUG_CONTROL) &
		    (1ull << HOTPLUG_CONTROL_PWREN)) ?
		    0 : PCIE_SLOTCTL_PWR_CONTROL;
		break;
	case PCIE_SLOTSTS:
		val = CSR_XR(csr_base, TLU_SLOT_STATUS);
		break;
	case PCIE_LINKCAP:
		val = CSR_XR(csr_base, TLU_LINK_CAPABILITIES);
		break;
	case PCIE_LINKSTS:
		val = CSR_XR(csr_base, TLU_LINK_STATUS);
		break;
	default:
		DBG(DBG_HP, NULL, "oberon_hpreg_get(): "
		    "unsupported offset 0x%lx\n", off);
		break;
	}

	return ((uint_t)val);
}

static uint_t
oberon_hpreg_put(void *cookie, off_t off, uint_t val)
{
	caddr_t csr_base = *(caddr_t *)cookie;
	volatile uint64_t pwr_state_on, pwr_fault;
	uint_t pwr_off, ret = DDI_SUCCESS;

	DBG(DBG_HP, NULL, "oberon_hpreg_put 0x%lx: cur %x, new %x\n",
	    off, oberon_hpreg_get(cookie, off), val);

	switch (off) {
	case PCIE_SLOTCTL:
		/*
		 * Depending on the current state, insertion or removal
		 * will go through their respective sequences.
		 */
		pwr_state_on = CSR_BR(csr_base, HOTPLUG_CONTROL, PWREN);
		pwr_off = val & PCIE_SLOTCTL_PWR_CONTROL;

		if (!pwr_off && !pwr_state_on)
			ret = oberon_hp_pwron(csr_base);
		else if (pwr_off && pwr_state_on) {
			pwr_fault = CSR_XR(csr_base, TLU_SLOT_STATUS) &
			    (1ull << TLU_SLOT_STATUS_PWFD);

			if (pwr_fault) {
				DBG(DBG_HP, NULL, "oberon_hpreg_put: power "
				    "off because of power fault\n");
				CSR_BC(csr_base, HOTPLUG_CONTROL, PWREN);
			}
			else
				ret = oberon_hp_pwroff(csr_base);
		} else
			CSR_XS(csr_base, TLU_SLOT_CONTROL, val);
		break;
	case PCIE_SLOTSTS:
		CSR_XS(csr_base, TLU_SLOT_STATUS, val);
		break;
	default:
		DBG(DBG_HP, NULL, "oberon_hpreg_put(): "
		    "unsupported offset 0x%lx\n", off);
		ret = (uint_t)DDI_FAILURE;
		break;
	}

	return (ret);
}

int
hvio_hotplug_init(dev_info_t *dip, void *arg)
{
	pciehpc_regops_t *regops = (pciehpc_regops_t *)arg;
	px_t	*px_p = DIP_TO_STATE(dip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;
	volatile uint64_t reg;

	if (PX_CHIP_TYPE(pxu_p) == PX_CHIP_OBERON) {
		if (!CSR_BR((caddr_t)pxu_p->px_address[PX_REG_CSR],
		    TLU_SLOT_CAPABILITIES, HP)) {
			DBG(DBG_HP, NULL, "%s%d: hotplug capabale not set\n",
			    ddi_driver_name(dip), ddi_get_instance(dip));
			return (DDI_FAILURE);
		}

		/* For empty or disconnected slot, disable LUP/LDN */
		if (!CSR_BR((caddr_t)pxu_p->px_address[PX_REG_CSR],
		    TLU_SLOT_STATUS, PSD) ||
		    !CSR_BR((caddr_t)pxu_p->px_address[PX_REG_CSR],
		    HOTPLUG_CONTROL, PWREN)) {

			reg = CSR_XR((caddr_t)pxu_p->px_address[PX_REG_CSR],
			    TLU_OTHER_EVENT_LOG_ENABLE);
			reg &= ~((1ull << TLU_OTHER_EVENT_STATUS_SET_LDN_P) |
			    (1ull << TLU_OTHER_EVENT_STATUS_SET_LUP_P) |
			    (1ull << TLU_OTHER_EVENT_STATUS_SET_LDN_S) |
			    (1ull << TLU_OTHER_EVENT_STATUS_SET_LUP_S));
			CSR_XS((caddr_t)pxu_p->px_address[PX_REG_CSR],
			    TLU_OTHER_EVENT_LOG_ENABLE, reg);
		}

		regops->get = oberon_hpreg_get;
		regops->put = oberon_hpreg_put;

		/* cookie is the csr_base */
		regops->cookie = (void *)&pxu_p->px_address[PX_REG_CSR];

		return (DDI_SUCCESS);
	}

	return (DDI_ENOTSUP);
}

int
hvio_hotplug_uninit(dev_info_t *dip)
{
	px_t	*px_p = DIP_TO_STATE(dip);
	pxu_t	*pxu_p = (pxu_t *)px_p->px_plat_p;

	if (PX_CHIP_TYPE(pxu_p) == PX_CHIP_OBERON)
		return (DDI_SUCCESS);

	return (DDI_FAILURE);
}
