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

#include <sys/sunddi.h>
#include <sys/amd_iommu.h>
#include "amd_iommu_impl.h"
#include "amd_iommu_log.h"


static const char *
get_hw_error(uint8_t type)
{
	const char *hwerr;

	switch (type) {
	case 0:
		hwerr = "Reserved";
		break;
	case 1:
		hwerr = "Master Abort";
		break;
	case 2:
		hwerr = "Target Abort";
		break;
	case 3:
		hwerr = "Data Error";
		break;
	default:
		hwerr = "Unknown";
		break;
	}

	return (hwerr);
}

const char *
get_illegal_req(uint8_t type, uint8_t TR)
{
	const char *illreq;

	switch (type) {
	case 0:
		illreq = (TR == 1) ? "Translation I=0/V=0/V=1&&TV=0" :
		    "Read or Non-posted Write in INTR Range";
		break;
	case 1:
		illreq = (TR == 1) ? "Translation INTR/Port-IO/SysMgt; OR"
		    "Translation when SysMgt=11b/Port-IO when IOCTL=10b "
		    "while V=1 && TV=0" :
		    "Pre-translated transaction from device with I=0 or V=0";
		break;
	case 2:
		illreq = (TR == 1) ? "Reserved":
		    "Port-IO transaction for device with IoCtl = 00b";
		break;
	case 3:
		illreq = (TR == 1) ? "Reserved":
		    "Posted write to SysMgt with device SysMgt=00b "
		    "OR SysMgt=10b && message not INTx "
		    "OR Posted write to addr transaltion range with "
		    "HtAtsResv=1";
		break;
	case 4:
		illreq = (TR == 1) ? "Reserved":
		    "Read request or non-posted write in SysMgt with "
		    "device SysMgt=10b or 0xb"
		    "OR Read request or non-posted write in "
		    "addr translation range with HtAtsResv=1";
		break;
	case 5:
		illreq = (TR == 1) ? "Reserved":
		    "Posted write to Interrupt/EOI Range "
		    "for device that has IntCtl=00b";
		break;
	case 6:
		illreq = (TR == 1) ? "Reserved":
		    "Posted write to reserved Interrupt Address Range";
		break;
	case 7:
		illreq = (TR == 1) ? "Reserved":
		    "transaction to SysMgt when SysMgt=11b OR "
		    "transaction to Port-IO when IoCtl=10b while "
		    "while V=1 TV=0";
		break;
	default:
		illreq = "Unknown error";
		break;
	}
	return (illreq);
}

static void
devtab_illegal_entry(amd_iommu_t *iommu, uint32_t *event)
{
	uint16_t deviceid;
	uint8_t TR;
	uint8_t RZ;
	uint8_t RW;
	uint8_t I;
	uint32_t vaddr_lo;
	uint32_t vaddr_hi;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "devtab_illegal_entry";

	ASSERT(AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_TYPE) ==
	    AMD_IOMMU_EVENT_DEVTAB_ILLEGAL_ENTRY);

	deviceid = AMD_IOMMU_REG_GET32(&event[0],
	    AMD_IOMMU_EVENT_DEVTAB_ILL_DEVICEID);

	TR = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_DEVTAB_ILL_TR);

	RZ = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_DEVTAB_ILL_RZ);

	RW = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_DEVTAB_ILL_RW);

	I = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_DEVTAB_ILL_INTR);

	vaddr_lo = AMD_IOMMU_REG_GET32(&event[2],
	    AMD_IOMMU_EVENT_DEVTAB_ILL_VADDR_LO);

	vaddr_hi = event[3];

	cmn_err(CE_WARN, "%s: %s%d: idx = %d. Illegal device table entry "
	    "deviceid=%u, %s request, %s %s transaction, %s request, "
	    "virtual address = %p",
	    f, driver, instance, iommu->aiomt_idx,
	    deviceid,
	    TR == 1 ? "Translation" : "Transaction",
	    RZ == 1 ? "Non-zero reserved bit" : "Illegal Level encoding",
	    RW == 1 ? "Write" : "Read",
	    I == 1 ? "Interrupt" : "Memory",
	    (void *)(uintptr_t)(((uint64_t)vaddr_hi) << 32 | vaddr_lo));
}

static void
io_page_fault(amd_iommu_t *iommu, uint32_t *event)
{
	uint16_t deviceid;
	uint16_t domainid;
	uint8_t TR;
	uint8_t RZ;
	uint8_t RW;
	uint8_t PE;
	uint8_t PR;
	uint8_t I;
	uint32_t vaddr_lo;
	uint32_t vaddr_hi;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "io_page_fault";

	ASSERT(AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_TYPE) ==
	    AMD_IOMMU_EVENT_IO_PAGE_FAULT);

	deviceid = AMD_IOMMU_REG_GET32(&event[0],
	    AMD_IOMMU_EVENT_IO_PGFAULT_DEVICEID);

	TR = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_IO_PGFAULT_TR);

	RZ = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_IO_PGFAULT_RZ);

	PE = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_IO_PGFAULT_PE);

	RW = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_IO_PGFAULT_RW);

	PR = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_IO_PGFAULT_PR);

	I = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_IO_PGFAULT_INTR);

	domainid = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_IO_PGFAULT_DOMAINID);

	vaddr_lo = event[2];

	vaddr_hi = event[3];

	cmn_err(CE_WARN, "%s: %s%d: idx = %d. IO Page Fault. "
	    "deviceid=%u, %s request, %s, %s permissions, %s transaction, "
	    "%s, %s request, domainid=%u, virtual address = %p",
	    f, driver, instance, iommu->aiomt_idx,
	    deviceid,
	    TR == 1 ? "Translation" : "Transaction",
	    RZ == 1 ? "Non-zero reserved bit" : "Illegal Level encoding",
	    PE == 1 ? "did not have" : "had",
	    RW == 1 ? "Write" : "Read",
	    PR == 1 ? "Page present or Interrupt Remapped" :
	    "Page not present or Interrupt Blocked",
	    I == 1 ? "Interrupt" : "Memory",
	    domainid,
	    (void *)(uintptr_t)(((uint64_t)vaddr_hi) << 32 | vaddr_lo));
}

static void
devtab_hw_error(amd_iommu_t *iommu, uint32_t *event)
{
	uint16_t deviceid;
	uint8_t type;
	uint8_t TR;
	uint8_t RW;
	uint8_t I;
	uint32_t physaddr_lo;
	uint32_t physaddr_hi;
	const char *hwerr;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "devtab_hw_error";

	ASSERT(AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_TYPE) ==
	    AMD_IOMMU_EVENT_DEVTAB_HW_ERROR);

	deviceid = AMD_IOMMU_REG_GET32(&event[0],
	    AMD_IOMMU_EVENT_DEVTAB_HWERR_DEVICEID);

	type = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_DEVTAB_HWERR_TYPE);

	hwerr = get_hw_error(type);

	TR = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_DEVTAB_HWERR_TR);

	RW = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_DEVTAB_HWERR_RW);

	I = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_DEVTAB_HWERR_INTR);

	physaddr_lo = AMD_IOMMU_REG_GET32(&event[2],
	    AMD_IOMMU_EVENT_DEVTAB_HWERR_PHYSADDR_LO);

	physaddr_hi = event[3];

	cmn_err(CE_WARN, "%s: %s%d: idx = %d. Device Table HW Error. "
	    "deviceid=%u, HW error type: %s, %s request, %s transaction, "
	    "%s request, physical address = %p",
	    f, driver, instance, iommu->aiomt_idx,
	    deviceid, hwerr,
	    TR == 1 ? "Translation" : "Transaction",
	    RW == 1 ? "Write" : "Read",
	    I == 1 ? "Interrupt" : "Memory",
	    (void *)(uintptr_t)(((uint64_t)physaddr_hi) << 32 | physaddr_lo));
}


static void
pgtable_hw_error(amd_iommu_t *iommu, uint32_t *event)
{
	uint16_t deviceid;
	uint16_t domainid;
	uint8_t type;
	uint8_t TR;
	uint8_t RW;
	uint8_t I;
	uint32_t physaddr_lo;
	uint32_t physaddr_hi;
	const char *hwerr;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "pgtable_hw_error";

	ASSERT(AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_TYPE) ==
	    AMD_IOMMU_EVENT_PGTABLE_HW_ERROR);

	deviceid = AMD_IOMMU_REG_GET32(&event[0],
	    AMD_IOMMU_EVENT_PGTABLE_HWERR_DEVICEID);

	type = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_DEVTAB_HWERR_TYPE);

	hwerr = get_hw_error(type);

	TR = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_PGTABLE_HWERR_TR);

	RW = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_PGTABLE_HWERR_RW);

	I = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_PGTABLE_HWERR_INTR);

	domainid = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_PGTABLE_HWERR_DOMAINID);

	physaddr_lo = AMD_IOMMU_REG_GET32(&event[2],
	    AMD_IOMMU_EVENT_PGTABLE_HWERR_PHYSADDR_LO);

	physaddr_hi = event[3];

	cmn_err(CE_WARN, "%s: %s%d: idx = %d. Page Table HW Error. "
	    "deviceid=%u, HW error type: %s, %s request, %s transaction, "
	    "%s request, domainid=%u, physical address = %p",
	    f, driver, instance, iommu->aiomt_idx,
	    deviceid, hwerr,
	    TR == 1 ? "Translation" : "Transaction",
	    RW == 1 ? "Write" : "Read",
	    I == 1 ? "Interrupt" : "Memory",
	    domainid,
	    (void *)(uintptr_t)(((uint64_t)physaddr_hi) << 32 | physaddr_lo));
}

static void
cmdbuf_illegal_cmd(amd_iommu_t *iommu, uint32_t *event)
{
	uint32_t physaddr_lo;
	uint32_t physaddr_hi;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "cmdbuf_illegal_cmd";

	ASSERT(AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_TYPE) ==
	    AMD_IOMMU_EVENT_CMDBUF_ILLEGAL_CMD);

	physaddr_lo = AMD_IOMMU_REG_GET32(&event[2],
	    AMD_IOMMU_EVENT_CMDBUF_ILLEGAL_CMD_PHYS_LO);

	physaddr_hi = event[3];

	cmn_err(CE_WARN, "%s: %s%d: idx = %d. Illegal IOMMU command. "
	    "command physical address = %p",
	    f, driver, instance, iommu->aiomt_idx,
	    (void *)(uintptr_t)(((uint64_t)physaddr_hi) << 32 | physaddr_lo));
}

static void
cmdbuf_hw_error(amd_iommu_t *iommu, uint32_t *event)
{
	uint32_t physaddr_lo;
	uint32_t physaddr_hi;
	uint8_t type;
	const char *hwerr;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "cmdbuf_hw_error";

	ASSERT(AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_TYPE) ==
	    AMD_IOMMU_EVENT_CMDBUF_HW_ERROR);

	type = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_CMDBUF_HWERR_TYPE);

	hwerr = get_hw_error(type);

	physaddr_lo = AMD_IOMMU_REG_GET32(&event[2],
	    AMD_IOMMU_EVENT_CMDBUF_HWERR_PHYS_LO);

	physaddr_hi = event[3];

	cmn_err(CE_WARN, "%s: %s%d: idx = %d. Command Buffer HW error. "
	    "HW error type = %s, command buffer physical address = %p",
	    f, driver, instance, iommu->aiomt_idx,
	    hwerr,
	    (void *)(uintptr_t)(((uint64_t)physaddr_hi) << 32 | physaddr_lo));
}

static void
iotlb_inval_to(amd_iommu_t *iommu, uint32_t *event)
{
	uint16_t deviceid;
	uint32_t physaddr_lo;
	uint32_t physaddr_hi;
	uint8_t type;
	const char *hwerr;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "iotlb_inval_to";

	ASSERT(AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_TYPE) ==
	    AMD_IOMMU_EVENT_IOTLB_INVAL_TO);

	deviceid = AMD_IOMMU_REG_GET32(&event[0],
	    AMD_IOMMU_EVENT_IOTLB_INVAL_TO_DEVICEID);

	/*
	 * XXX bug in spec. Is the type field available +04 26:25 or is
	 * it reserved
	 */
	type = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_IOTLB_INVAL_TO_TYPE);
	hwerr = get_hw_error(type);

	physaddr_lo = AMD_IOMMU_REG_GET32(&event[2],
	    AMD_IOMMU_EVENT_IOTLB_INVAL_TO_PHYS_LO);

	physaddr_hi = event[3];

	cmn_err(CE_WARN, "%s: %s%d: idx = %d. deviceid = %u "
	    "IOTLB invalidation Timeout. "
	    "HW error type = %s, invalidation command physical address = %p",
	    f, driver, instance, iommu->aiomt_idx, deviceid,
	    hwerr,
	    (void *)(uintptr_t)(((uint64_t)physaddr_hi) << 32 | physaddr_lo));
}

static void
device_illegal_req(amd_iommu_t *iommu, uint32_t *event)
{
	uint16_t deviceid;
	uint8_t TR;
	uint32_t addr_lo;
	uint32_t addr_hi;
	uint8_t type;
	const char *reqerr;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "device_illegal_req";

	ASSERT(AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_TYPE) ==
	    AMD_IOMMU_EVENT_DEVICE_ILLEGAL_REQ);

	deviceid = AMD_IOMMU_REG_GET32(&event[0],
	    AMD_IOMMU_EVENT_DEVICE_ILLEGAL_REQ_DEVICEID);

	TR = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_DEVICE_ILLEGAL_REQ_TR);

	type = AMD_IOMMU_REG_GET32(&event[1],
	    AMD_IOMMU_EVENT_DEVICE_ILLEGAL_REQ_TYPE);

	reqerr = get_illegal_req(type, TR);


	addr_lo = event[2];
	addr_hi = event[3];

	cmn_err(CE_WARN, "%s: %s%d: idx = %d. deviceid = %d "
	    "Illegal Device Request. "
	    "Illegal Request type = %s, %s request, address accessed = %p",
	    f, driver, instance, iommu->aiomt_idx, deviceid,
	    reqerr,
	    TR == 1 ? "Translation" : "Transaction",
	    (void *)(uintptr_t)(((uint64_t)addr_hi) << 32 | addr_lo));
}

static void
amd_iommu_process_one_event(amd_iommu_t *iommu)
{
	uint32_t event[4];
	amd_iommu_event_t event_type;
	int i;
	const char *driver = ddi_driver_name(iommu->aiomt_dip);
	int instance = ddi_get_instance(iommu->aiomt_dip);
	const char *f = "amd_iommu_process_one_event";

	ASSERT(MUTEX_HELD(&iommu->aiomt_eventlock));

	SYNC_FORKERN(iommu->aiomt_dmahdl);
	for (i = 0; i < 4; i++) {
		event[i] =  iommu->aiomt_event_head[i];
	}

	event_type = AMD_IOMMU_REG_GET32(&event[1], AMD_IOMMU_EVENT_TYPE);

	switch (event_type) {
	case AMD_IOMMU_EVENT_DEVTAB_ILLEGAL_ENTRY:
		devtab_illegal_entry(iommu, event);
		break;
	case AMD_IOMMU_EVENT_IO_PAGE_FAULT:
		io_page_fault(iommu, event);
		break;
	case AMD_IOMMU_EVENT_DEVTAB_HW_ERROR:
		devtab_hw_error(iommu, event);
		break;
	case AMD_IOMMU_EVENT_PGTABLE_HW_ERROR:
		pgtable_hw_error(iommu, event);
		break;
	case AMD_IOMMU_EVENT_CMDBUF_HW_ERROR:
		cmdbuf_hw_error(iommu, event);
		break;
	case AMD_IOMMU_EVENT_CMDBUF_ILLEGAL_CMD:
		cmdbuf_illegal_cmd(iommu, event);
		break;
	case AMD_IOMMU_EVENT_IOTLB_INVAL_TO:
		iotlb_inval_to(iommu, event);
		break;
	case AMD_IOMMU_EVENT_DEVICE_ILLEGAL_REQ:
		device_illegal_req(iommu, event);
		break;
	default:
		cmn_err(CE_WARN, "%s: %s%d: idx = %d. Unknown event: %u",
		    f, driver, instance, iommu->aiomt_idx, event_type);
		break;
	}
}

int
amd_iommu_read_log(amd_iommu_t *iommu, amd_iommu_log_op_t op)
{
	caddr_t evtail;
	uint64_t evtail_off;
	uint64_t evhead_off;

	ASSERT(op != AMD_IOMMU_LOG_INVALID_OP);

	mutex_enter(&iommu->aiomt_eventlock);

	ASSERT(iommu->aiomt_event_head != NULL);

	/* XXX verify */
	evtail_off = AMD_IOMMU_REG_GET64(
	    REGADDR64(iommu->aiomt_reg_eventlog_tail_va),
	    AMD_IOMMU_EVENTTAILPTR);

	evtail_off = EV2OFF(evtail_off);

	ASSERT(evtail_off <  iommu->aiomt_eventlog_sz);

	evtail = iommu->aiomt_eventlog + evtail_off;

	if (op == AMD_IOMMU_LOG_DISCARD) {
		/*LINTED*/
		iommu->aiomt_event_head = (uint32_t *)evtail;
		AMD_IOMMU_REG_SET64(REGADDR64(
		    iommu->aiomt_reg_eventlog_head_va),
		    AMD_IOMMU_EVENTHEADPTR, OFF2EV(evtail_off));
		cmn_err(CE_NOTE, "Discarded IOMMU event log");
		mutex_exit(&iommu->aiomt_eventlock);
		return (DDI_SUCCESS);
	}

	/*LINTED*/
	while (1) {
		if ((caddr_t)iommu->aiomt_event_head == evtail)
			break;

		cmn_err(CE_WARN, "evtail_off = %p, head = %p, tail = %p",
		    (void *)(uintptr_t)evtail_off,
		    (void *)iommu->aiomt_event_head,
		    (void *)evtail);

		amd_iommu_process_one_event(iommu);

		/*
		 * Update the head pointer in soft state
		 * and the head pointer register
		 */
		iommu->aiomt_event_head += 4;
		if ((caddr_t)iommu->aiomt_event_head >=
		    iommu->aiomt_eventlog + iommu->aiomt_eventlog_sz) {
			/* wraparound */
			iommu->aiomt_event_head =
			/*LINTED*/
			    (uint32_t *)iommu->aiomt_eventlog;
			evhead_off = 0;
		} else {
			evhead_off =  (caddr_t)iommu->aiomt_event_head
			/*LINTED*/
			    - iommu->aiomt_eventlog;
		}

		ASSERT(evhead_off < iommu->aiomt_eventlog_sz);

		AMD_IOMMU_REG_SET64(REGADDR64(
		    iommu->aiomt_reg_eventlog_head_va),
		    AMD_IOMMU_EVENTHEADPTR, OFF2EV(evhead_off));
	}
	mutex_exit(&iommu->aiomt_eventlock);

	return (DDI_SUCCESS);
}
