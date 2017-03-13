/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/mdb_modapi.h>
#include <sys/usb/hcd/xhci/xhci.h>

#define	XHCI_MDB_TRB_INDENT	4

static const char *xhci_mdb_epctx_eptypes[] = {
	"Not Valid",
	"ISOCH OUT",
	"BULK OUT",
	"INTR OUT",
	"CONTROL",
	"ISOCH IN",
	"BULK IN",
	"INTR IN"
};

static const char *xhci_mdb_epctx_states[] = {
	"Disabled",
	"Running",
	"Halted",
	"Stopped",
	"Error",
	"<Unknown>",
	"<Unknown>",
	"<Unknown>"
};

static const mdb_bitmask_t xhci_mdb_trb_flags[] = {
	{ "C", XHCI_TRB_CYCLE, XHCI_TRB_CYCLE },
	{ "ENT", XHCI_TRB_ENT, XHCI_TRB_ENT },
	{ "ISP", XHCI_TRB_ISP, XHCI_TRB_ISP },
	{ "NS", XHCI_TRB_NOSNOOP, XHCI_TRB_NOSNOOP },
	{ "CH", XHCI_TRB_CHAIN, XHCI_TRB_CHAIN },
	{ "IOC", XHCI_TRB_IOC, XHCI_TRB_IOC },
	{ "IDT", XHCI_TRB_IDT, XHCI_TRB_IDT },
	{ "BEI", XHCI_TRB_BEI, XHCI_TRB_BEI },
	{ NULL, 0, 0 }
};

typedef struct xhci_mdb_walk_endpoint {
	xhci_device_t	xmwe_device;
	uint_t		xmwe_ep;
} xhci_mdb_walk_endpoint_t;

static const char *
xhci_mdb_trb_code_to_str(int code)
{
	switch (code) {
	case XHCI_CODE_INVALID:
		return ("Invalid");
	case XHCI_CODE_SUCCESS:
		return ("Success");
	case XHCI_CODE_DATA_BUF:
		return ("Data Overrun or Underrun");
	case XHCI_CODE_BABBLE:
		return ("Babble");
	case XHCI_CODE_TXERR:
		return ("Transaction Error");
	case XHCI_CODE_TRB:
		return ("Invalid TRB");
	case XHCI_CODE_STALL:
		return ("Stall");
	case XHCI_CODE_RESOURCE:
		return ("No Resources Available");
	case XHCI_CODE_BANDWIDTH:
		return ("No Bandwidth Available");
	case XHCI_CODE_NO_SLOTS:
		return ("No Slots Available");
	case XHCI_CODE_STREAM_TYPE:
		return ("Stream Context Type Detected");
	case XHCI_CODE_SLOT_NOT_ON:
		return ("Slot disabled");
	case XHCI_CODE_ENDP_NOT_ON:
		return ("Endpoint disabled");
	case XHCI_CODE_SHORT_XFER:
		return ("Short Transfer");
	case XHCI_CODE_RING_UNDERRUN:
		return ("Isoch. Ring Underrun");
	case XHCI_CODE_RING_OVERRUN:
		return ("Isoch. Ring Overrun");
	case XHCI_CODE_VF_RING_FULL:
		return ("VF Ring Full");
	case XHCI_CODE_PARAMETER:
		return ("Invalid Context Parameter");
	case XHCI_CODE_BW_OVERRUN:
		return ("Bandwidth Overrun");
	case XHCI_CODE_CONTEXT_STATE:
		return ("Illegal Context Transition");
	case XHCI_CODE_NO_PING_RESP:
		return ("Failed to Complete Periodic Transfer");
	case XHCI_CODE_EV_RING_FULL:
		return ("Event Ring Full");
	case XHCI_CODE_INCOMPAT_DEV:
		return ("Incompatible Device");
	case XHCI_CODE_MISSED_SRV:
		return ("Missed Isoch. Service Window");
	case XHCI_CODE_CMD_RING_STOP:
		return ("Command Ring Stop");
	case XHCI_CODE_CMD_ABORTED:
		return ("Command Aborted");
	case XHCI_CODE_XFER_STOPPED:
		return ("Transfer Stopped");
	case XHCI_CODE_XFER_STOPINV:
		return ("Invalid Transfer Length");
	case XHCI_CODE_XFER_STOPSHORT:
		return ("Stopped before End of Transfer Descriptor");
	case XHCI_CODE_MELAT:
		return ("Max Exit Latency too large");
	case XHCI_CODE_RESERVED:
		return ("Reserved");
	case XHCI_CODE_ISOC_OVERRUN:
		return ("Isochronus Overrun");
	case XHCI_CODE_EVENT_LOST:
		return ("Event Lost");
	case XHCI_CODE_UNDEFINED:
		return ("Undefined Fatal Error");
	case XHCI_CODE_INVALID_SID:
		return ("Invalid Stream ID");
	case XHCI_CODE_SEC_BW:
		return ("Secondary Bandwith Allocation Failure");
	case XHCI_CODE_SPLITERR:
		return ("USB2 Split Transaction Error");
	default:
		break;
	}

	if (code >= 192 && code <= 223)
		return ("Vendor Defined Error");
	if (code >= 224 && code <= 255)
		return ("Vendor Defined Info");

	return ("Reserved");
}

static const char *
xhci_mdb_trb_type_to_str(int code)
{
	/*
	 * The macros for the types are all already shifted over based on their
	 * place in the TRB, so shift there again ourselves.
	 */
	switch (code << 10) {
	case XHCI_TRB_TYPE_NORMAL:
		return ("Normal");
	case XHCI_TRB_TYPE_SETUP:
		return ("Setup");
	case XHCI_TRB_TYPE_DATA:
		return ("Data");
	case XHCI_TRB_TYPE_STATUS:
		return ("Status");
	case XHCI_TRB_TYPE_LINK:
		return ("Link");
	case XHCI_TRB_TYPE_EVENT:
		return ("Event");
	case XHCI_TRB_TYPE_NOOP:
		return ("No-Op");
	case XHCI_CMD_ENABLE_SLOT:
		return ("Enable Slot");
	case XHCI_CMD_DISABLE_SLOT:
		return ("Disable Slot");
	case XHCI_CMD_ADDRESS_DEVICE:
		return ("Address Device");
	case XHCI_CMD_CONFIG_EP:
		return ("Configure Endpoint");
	case XHCI_CMD_EVAL_CTX:
		return ("Evaluate Context");
	case XHCI_CMD_RESET_EP:
		return ("Reset Endpoint");
	case XHCI_CMD_STOP_EP:
		return ("Stop Endpoint");
	case XHCI_CMD_SET_TR_DEQ:
		return ("Set Transfer Ring Dequeue Pointer");
	case XHCI_CMD_RESET_DEV:
		return ("Reset Device");
	case XHCI_CMD_FEVENT:
		return ("Force Event");
	case XHCI_CMD_NEG_BW:
		return ("Negotiate Bandwidth");
	case XHCI_CMD_SET_LT:
		return ("Set Latency Tolerance");
	case XHCI_CMD_GET_BW:
		return ("Get Bandwidth");
	case XHCI_CMD_FHEADER:
		return ("Force Header");
	case XHCI_CMD_NOOP:
		return ("No-Op Command");
	case XHCI_EVT_XFER:
		return ("Transfer Event");
	case XHCI_EVT_CMD_COMPLETE:
		return ("Command Completion Event");
	case XHCI_EVT_PORT_CHANGE:
		return ("Port Status Change Event");
	case XHCI_EVT_BW_REQUEST:
		return ("Bandwidth Request Event");
	case XHCI_EVT_DOORBELL:
		return ("Doorbell Event");
	case XHCI_EVT_HOST_CTRL:
		return ("Host Controller Event");
	case XHCI_EVT_DEVICE_NOTIFY:
		return ("Device Notification Event");
	case XHCI_EVT_MFINDEX_WRAP:
		return ("MFINDEX Wrap Event");
	default:
		break;
	}

	if (code >= 43 && code <= 63)
		return ("Vendor Defiend");
	return ("Reserved");
}

/* ARGSUSED */
static int
xhci_mdb_print_epctx(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	uint32_t info, info2, txinfo;
	xhci_endpoint_context_t epctx;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("::xhci_epctx requires an address\n");
		return (DCMD_USAGE);
	}

	if (mdb_vread(&epctx, sizeof (epctx), addr) != sizeof (epctx)) {
		mdb_warn("failed to read xhci_endpoint_context_t at %p", addr);
		return (DCMD_ERR);
	}

	info = LE_32(epctx.xec_info);
	info2 = LE_32(epctx.xec_info2);
	txinfo = LE_32(epctx.xec_txinfo);

	mdb_printf("Endpoint State: %s (%d)\n",
	    xhci_mdb_epctx_states[XHCI_EPCTX_STATE(info)],
	    XHCI_EPCTX_STATE(info));

	mdb_printf("Mult: %d\n", XHCI_EPCTX_GET_MULT(info));
	mdb_printf("Max Streams: %d\n", XHCI_EPCTX_GET_MAXP_STREAMS(info));
	mdb_printf("LSA: %d\n", XHCI_EPCTX_GET_LSA(info));
	mdb_printf("Interval: %d\n", XHCI_EPCTX_GET_IVAL(info));
	mdb_printf("Max ESIT Hi: %d\n", XHCI_EPCTX_GET_MAX_ESIT_HI(info));

	mdb_printf("CErr: %d\n", XHCI_EPCTX_GET_CERR(info2));
	mdb_printf("EP Type: %s (%d)\n",
	    xhci_mdb_epctx_eptypes[XHCI_EPCTX_GET_EPTYPE(info2)],
	    XHCI_EPCTX_GET_EPTYPE(info2));
	mdb_printf("Host Initiate Disable: %d\n", XHCI_EPCTX_GET_HID(info2));
	mdb_printf("Max Burst: %d\n", XHCI_EPCTX_GET_MAXB(info2));
	mdb_printf("Max Packet Size: %d\n", XHCI_EPCTX_GET_MPS(info2));

	mdb_printf("Ring DCS: %d\n", LE_64(epctx.xec_dequeue) & 0x1);
	mdb_printf("Ring PA: 0x%lx\n", LE_64(epctx.xec_dequeue) & ~0xf);

	mdb_printf("Average TRB Length: %d\n", XHCI_EPCTX_AVG_TRB_LEN(txinfo));
	mdb_printf("Max ESIT: %d\n", XHCI_EPCTX_GET_MAX_ESIT_PAYLOAD(txinfo));

	return (DCMD_OK);
}

/* ARGSUSED */
static int
xhci_mdb_print_slotctx(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	uint32_t info, info2, tt, state;
	xhci_slot_context_t sctx;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("::xhci_slotctx requires an address\n");
		return (DCMD_USAGE);
	}

	if (mdb_vread(&sctx, sizeof (sctx), addr) != sizeof (sctx)) {
		mdb_warn("failed to read xhci_slot_context_t at %p", addr);
		return (DCMD_ERR);
	}

	info = LE_32(sctx.xsc_info);
	info2 = LE_32(sctx.xsc_info2);
	tt = LE_32(sctx.xsc_tt);
	state = LE_32(sctx.xsc_state);

	mdb_printf("Route: 0x%x\n", XHCI_SCTX_GET_ROUTE(info));

	mdb_printf("Slot Speed: ");
	switch (XHCI_SCTX_GET_SPEED(info)) {
	case XHCI_SPEED_FULL:
		mdb_printf("Full");
		break;
	case XHCI_SPEED_LOW:
		mdb_printf("Low");
		break;
	case XHCI_SPEED_HIGH:
		mdb_printf("High");
		break;
	case XHCI_SPEED_SUPER:
		mdb_printf("Super");
		break;
	default:
		mdb_printf("Unknown");
		break;
	}
	mdb_printf(" (%d)\n", XHCI_SCTX_GET_SPEED(info));


	mdb_printf("MTT: %d\n", XHCI_SCTX_GET_MTT(info));
	mdb_printf("HUB: %d\n", XHCI_SCTX_GET_HUB(info));
	mdb_printf("DCI: %d\n", XHCI_SCTX_GET_DCI(info));

	mdb_printf("Max Exit Latency: %d\n", XHCI_SCTX_GET_MAX_EL(info2));
	mdb_printf("Root Hub Port: %d\n", XHCI_SCTX_GET_RHPORT(info2));
	mdb_printf("Hub Number of Ports: %d\n", XHCI_SCTX_GET_NPORTS(info2));

	mdb_printf("TT Hub Slot id: %d\n", XHCI_SCTX_GET_TT_HUB_SID(tt));
	mdb_printf("TT Port Number: %d\n", XHCI_SCTX_GET_TT_PORT_NUM(tt));
	mdb_printf("TT Think Time: %d\n", XHCI_SCTX_GET_TT_THINK_TIME(tt));
	mdb_printf("IRQ Target: %d\n", XHCI_SCTX_GET_IRQ_TARGET(tt));

	mdb_printf("Device Address: 0x%x\n", XHCI_SCTX_GET_DEV_ADDR(state));
	mdb_printf("Slot State: ");
	switch (XHCI_SCTX_GET_SLOT_STATE(state)) {
	case XHCI_SLOT_DIS_ENAB:
		mdb_printf("Disabled/Enabled");
		break;
	case XHCI_SLOT_DEFAULT:
		mdb_printf("Default");
		break;
	case XHCI_SLOT_ADDRESSED:
		mdb_printf("Addressed");
		break;
	case XHCI_SLOT_CONFIGURED:
		mdb_printf("Configured");
		break;
	default:
		mdb_printf("Unknown");
		break;
	}
	mdb_printf(" (%d)\n", XHCI_SCTX_GET_SLOT_STATE(state));

	return (DCMD_OK);
}

static int
xhci_mdb_print_transfer_event(uint64_t pa, uint32_t status, uint32_t flags)
{
	mdb_printf("TRB Address: 0x%lx\n", pa);
	mdb_printf("Transfer Length (Remain): %d\n", XHCI_TRB_REMAIN(status));
	mdb_printf("Completion Code: %s (%d)\n",
	    xhci_mdb_trb_code_to_str(XHCI_TRB_GET_CODE(status)),
	    XHCI_TRB_GET_CODE(status));

	mdb_printf("Cycle: %d\n", XHCI_TRB_GET_CYCLE(flags));
	mdb_printf("Event Data: %d\n", XHCI_TRB_GET_ED(flags));
	mdb_printf("Endpoint ID: %d\n", XHCI_TRB_GET_EP(flags));
	mdb_printf("Slot ID: %d\n", XHCI_TRB_GET_SLOT(flags));
	mdb_dec_indent(XHCI_MDB_TRB_INDENT);

	return (DCMD_OK);
}

static int
xhci_mdb_print_command_event(uint64_t pa, uint32_t status, uint32_t flags)
{
	mdb_printf("TRB Address: 0x%lx\n", pa);
	mdb_printf("Command Param: 0x%x\n", XHCI_TRB_REMAIN(status));
	mdb_printf("Completion Code: %s (%d)\n",
	    xhci_mdb_trb_code_to_str(XHCI_TRB_GET_CODE(status)),
	    XHCI_TRB_GET_CODE(status));

	mdb_printf("Cycle: %d\n", XHCI_TRB_GET_CYCLE(flags));
	/* Skip VF ID as we don't support VFs */
	mdb_printf("Slot ID: %d\n", XHCI_TRB_GET_SLOT(flags));
	mdb_dec_indent(XHCI_MDB_TRB_INDENT);

	return (DCMD_OK);
}

/* ARGSUSED */
static int
xhci_mdb_print_psc(uint64_t pa, uint32_t status, uint32_t flags)
{
	mdb_printf("Port: %d\n", XHCI_TRB_PORTID(pa));
	mdb_printf("Completion Code: %s (%d)\n",
	    xhci_mdb_trb_code_to_str(XHCI_TRB_GET_CODE(status)),
	    XHCI_TRB_GET_CODE(status));
	mdb_dec_indent(XHCI_MDB_TRB_INDENT);
	return (DCMD_OK);
}

static int
xhci_mdb_print_normal_trb(uint64_t pa, uint32_t status, uint32_t flags)
{
	mdb_printf("TRB Address: 0x%lx\n", pa);
	mdb_printf("TRB Length: %d bytes\n", XHCI_TRB_LEN(status));
	mdb_printf("TRB TD Size: %d packets\n", XHCI_TRB_GET_TDREM(status));
	mdb_printf("TRB Interrupt: %d\n", XHCI_TRB_GET_INTR(status));
	mdb_printf("TRB Flags: %b (0x%x)\n", flags, xhci_mdb_trb_flags,
	    XHCI_TRB_GET_FLAGS(flags));
	mdb_dec_indent(XHCI_MDB_TRB_INDENT);

	return (DCMD_OK);
}

/* ARGSUSED */
static int
xhci_mdb_print_trb(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	xhci_trb_t trb;
	uint64_t pa;
	uint32_t status, trbflags, type;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("::xhci_trb expects an address\n");
		return (DCMD_USAGE);
	}

	if (mdb_vread(&trb, sizeof (trb), addr) != sizeof (trb)) {
		mdb_warn("failed to read xhci_trb_t at 0x%x", addr);
		return (DCMD_ERR);
	}

	pa = LE_64(trb.trb_addr);
	status = LE_32(trb.trb_status);
	trbflags = LE_32(trb.trb_flags);

	type = XHCI_TRB_GET_TYPE(trbflags);

	if ((flags & DCMD_LOOP) && !(flags & DCMD_LOOPFIRST))
		mdb_printf("\n");

	mdb_set_dot(addr + sizeof (xhci_trb_t));
	mdb_printf("%s TRB (%d)\n", xhci_mdb_trb_type_to_str(type), type);
	mdb_inc_indent(XHCI_MDB_TRB_INDENT);

	switch (XHCI_RING_TYPE_SHIFT(type)) {
	case XHCI_EVT_XFER:
		return (xhci_mdb_print_transfer_event(pa, status, trbflags));
	case XHCI_EVT_CMD_COMPLETE:
		return (xhci_mdb_print_command_event(pa, status, trbflags));
	case XHCI_EVT_PORT_CHANGE:
		return (xhci_mdb_print_psc(pa, status, trbflags));
	case XHCI_TRB_TYPE_NORMAL:
		return (xhci_mdb_print_normal_trb(pa, status, trbflags));
	}

	/*
	 * Just print generic information if we don't have a specific printer
	 * for that TRB type.
	 */
	mdb_printf("TRB Address: 0x%lx\n", pa);
	mdb_printf("TRB Status: 0x%x\n", status);
	mdb_printf("TRB Flags: 0x%x\n", trbflags);
	mdb_dec_indent(XHCI_MDB_TRB_INDENT);

	return (DCMD_OK);
}

static int
xhci_mdb_walk_xhci_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;
	uintptr_t addr;

	if (wsp->walk_addr != 0) {
		mdb_warn("::walk xhci only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_lookup_by_obj("xhci", "xhci_soft_state", &sym) != 0) {
		mdb_warn("failed to find xhci_soft_state symbol");
		return (WALK_ERR);
	}

	if (mdb_vread(&addr, sizeof (addr), sym.st_value) != sizeof (addr)) {
		mdb_warn("failed to read xhci_soft_state at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = addr;
	if (mdb_layered_walk("softstate", wsp) != 0) {
		mdb_warn("failed to walk softstate");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
xhci_mdb_walk_xhci_step(mdb_walk_state_t *wsp)
{
	xhci_t xhci;

	if (mdb_vread(&xhci, sizeof (xhci), wsp->walk_addr) != sizeof (xhci)) {
		mdb_warn("failed to read xhci_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(wsp->walk_addr, &xhci, wsp->walk_cbdata));
}

static int
xhci_mdb_walk_xhci_device_init(mdb_walk_state_t *wsp)
{
	uintptr_t addr;

	if (wsp->walk_addr == 0) {
		mdb_warn("::walk xhci_device requires an xhci_t\n");
		return (WALK_ERR);
	}

	addr = wsp->walk_addr;
	addr += offsetof(xhci_t, xhci_usba);
	addr += offsetof(xhci_usba_t, xa_devices);
	wsp->walk_addr = (uintptr_t)addr;
	if (mdb_layered_walk("list", wsp) != 0) {
		mdb_warn("failed to walk list");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
xhci_mdb_walk_xhci_device_step(mdb_walk_state_t *wsp)
{
	xhci_device_t xd;

	if (mdb_vread(&xd, sizeof (xd), wsp->walk_addr) != sizeof (xd)) {
		mdb_warn("failed to read xhci_device_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(wsp->walk_addr, &xd, wsp->walk_cbdata));
}

static int
xhci_mdb_walk_xhci_endpoint_init(mdb_walk_state_t *wsp)
{
	xhci_mdb_walk_endpoint_t *xm;
	xhci_device_t *xd;

	if (wsp->walk_addr == 0) {
		mdb_warn("::walk xhci_endpoint requires an xhci_device_t\n");
		return (WALK_ERR);
	}

	xm = mdb_alloc(sizeof (xhci_mdb_walk_endpoint_t), UM_SLEEP | UM_GC);
	xm->xmwe_ep = 0;
	xd = &xm->xmwe_device;
	if (mdb_vread(xd, sizeof (*xd), wsp->walk_addr) != sizeof (*xd)) {
		mdb_warn("failed to read xhci_endpoint_t at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}
	wsp->walk_data = xm;

	return (WALK_NEXT);
}

static int
xhci_mdb_walk_xhci_endpoint_step(mdb_walk_state_t *wsp)
{
	int ret;
	uintptr_t addr;
	xhci_mdb_walk_endpoint_t *xm = wsp->walk_data;

	if (xm->xmwe_ep >= XHCI_NUM_ENDPOINTS)
		return (WALK_DONE);

	addr = (uintptr_t)xm->xmwe_device.xd_endpoints[xm->xmwe_ep];
	if (addr != NULL) {
		xhci_endpoint_t xe;

		if (mdb_vread(&xe, sizeof (xe), addr) != sizeof (xe)) {
			mdb_warn("failed to read xhci_endpoint_t at %p",
			    xm->xmwe_device.xd_endpoints[xm->xmwe_ep]);
			return (WALK_ERR);
		}

		ret = wsp->walk_callback(addr, &xe, wsp->walk_cbdata);
	} else {
		ret = WALK_NEXT;
	}
	xm->xmwe_ep++;

	return (ret);
}

typedef struct xhci_mdb_find {
	int		xmf_slot;
	int		xmf_ep;
	uintptr_t	xmf_addr;
} xhci_mdb_find_t;

static int
xhci_mdb_find_endpoint_cb(uintptr_t addr, const void *data, void *arg)
{
	const xhci_endpoint_t *xep = data;
	xhci_mdb_find_t *xmf = arg;

	/*
	 * The endpoints that are presented here are off by one from the actual
	 * endpoint ID in the xhci_endpoint_t, as we're really displaying the
	 * index into the device input context.
	 */
	if (xep->xep_num + 1 == xmf->xmf_ep) {
		xmf->xmf_addr = addr;
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

static int
xhci_mdb_find_device_cb(uintptr_t addr, const void *data, void *arg)
{
	const xhci_device_t *xd = data;
	xhci_mdb_find_t *xmf = arg;

	if (xd->xd_slot == xmf->xmf_slot) {
		if (xmf->xmf_ep == -1) {
			xmf->xmf_addr = addr;
			return (WALK_DONE);
		}

		if (mdb_pwalk("xhci`xhci_endpoint", xhci_mdb_find_endpoint_cb,
		    xmf, addr) == -1) {
			mdb_warn("failed to walk xhci_endpoint at %p", addr);
			return (WALK_ERR);
		}

		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

static int
xhci_mdb_find(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	uintptr_t ep, slot;
	boolean_t ep_set, slot_set;
	xhci_mdb_find_t xmf;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	ep_set = slot_set = B_FALSE;
	if (mdb_getopts(argc, argv, 'e', MDB_OPT_UINTPTR_SET, &ep_set, &ep,
	    's', MDB_OPT_UINTPTR_SET, &slot_set, &slot) != argc)
		return (DCMD_USAGE);

	if (!slot_set) {
		mdb_warn("-s is required\n");
		return (DCMD_USAGE);
	}

	xmf.xmf_slot = (int)slot;
	if (ep_set)
		xmf.xmf_ep = (int)ep;
	else
		xmf.xmf_ep = -1;
	xmf.xmf_addr = 0;

	if (mdb_pwalk("xhci`xhci_device", xhci_mdb_find_device_cb,
	    &xmf, addr) == -1) {
		mdb_warn("failed to walk xhci_device at %p", addr);
		return (DCMD_ERR);
	}

	if (xmf.xmf_addr == 0) {
		if (ep_set) {
			mdb_warn("failed to find xhci_endpoint_t for slot %d "
			    "and endpoint %d\n", slot, ep);
		} else {
			mdb_warn("failed to find xhci_device_t for slot %d\n",
			    slot);
		}
		return (DCMD_ERR);
	}

	mdb_printf("%p\n", xmf.xmf_addr);
	return (DCMD_OK);
}

/* ARGSUSED */
static int
xhci_mdb_endpoint_count(uintptr_t addr, const void *ep, void *arg)
{
	int *countp = arg;

	*countp += 1;
	return (WALK_NEXT);
}

/* ARGSUSED */
static int
xhci_mdb_print_endpoint_summary(uintptr_t addr, const void *ep, void *arg)
{
	const xhci_device_t *xd = arg;
	const xhci_endpoint_t *xep = ep;
	const char *type;
	const char *state;
	xhci_endpoint_context_t epctx;
	int eptype;

	if (mdb_vread(&epctx, sizeof (epctx),
	    (uintptr_t)xd->xd_endout[xep->xep_num]) != sizeof (epctx)) {
		mdb_warn("failed to read endpoint context at %p",
		    xd->xd_endout[xep->xep_num]);
		return (WALK_ERR);
	}

	eptype = XHCI_EPCTX_GET_EPTYPE(LE_32(epctx.xec_info2));
	type = xhci_mdb_epctx_eptypes[eptype];
	state = xhci_mdb_epctx_states[XHCI_EPCTX_STATE(LE_32(epctx.xec_info))];

	mdb_printf("%-4d %-10s %-10s 0x%-04x 0x%-04x\n", xep->xep_num, type,
	    state, xep->xep_ring.xr_head, xep->xep_ring.xr_tail);

	return (WALK_NEXT);
}

/* ARGSUSED */
static int
xhci_mdb_print_device(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	int count;
	xhci_device_t xd;
	usba_device_t ud;
	char product[256], mfg[256];

	if (!(flags & DCMD_ADDRSPEC)) {
		return (mdb_eval("::walk xhci`xhci | ::walk xhci`xhci_device | "
		    "::xhci_device"));
	}

	if (mdb_vread(&xd, sizeof (xd), addr) != sizeof (xd)) {
		mdb_warn("failed to read xhci_device_t at 0x%x", addr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&ud, sizeof (ud), (uintptr_t)xd.xd_usbdev) !=
	    sizeof (ud)) {
		mdb_warn("failed to read usba_device_t at %p\n", xd.xd_usbdev);
		return (DCMD_ERR);
	}

	if (ud.usb_mfg_str == NULL || mdb_readstr(mfg, sizeof (mfg),
	    (uintptr_t)ud.usb_mfg_str) <= 0) {
		(void) strlcpy(mfg, "Unknown Manufacturer", sizeof (mfg));
	}

	if (ud.usb_product_str == NULL || mdb_readstr(product, sizeof (product),
	    (uintptr_t)ud.usb_product_str) <= 0) {
		(void) strlcpy(product, "Unknown Product", sizeof (product));
	}

	mdb_printf("%<b>%s - %s%</b>\n", mfg, product);

	count = 0;
	if (mdb_pwalk("xhci`xhci_endpoint", xhci_mdb_endpoint_count, &count,
	    addr) == -1) {
		mdb_warn("failed to walk xhci_endpoint rooted at 0x%x", addr);
		return (DCMD_ERR);
	}

	mdb_printf("Port %02d | Slot %02d | # Endpoints %02d\n", xd.xd_port,
	    xd.xd_slot, count);
	mdb_printf("%<u>%-4s %-10s %-10s %-6s %-6s%</u>\n", "EP", "Type",
	    "State", "Head", "Tail");

	if (mdb_pwalk("xhci`xhci_endpoint", xhci_mdb_print_endpoint_summary,
	    &xd, addr) == -1) {
		mdb_warn("failed to walk xhci_endpoint rooted at 0x%x", addr);
		return (DCMD_ERR);
	}


	mdb_printf("\n");

	return (DCMD_OK);
}

static int
xhci_mdb_find_trb(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	xhci_ring_t xr;
	uint64_t base, max, target;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("missing required xhci_ring_t\n");
		return (DCMD_USAGE);
	}

	if (argc == 0) {
		mdb_warn("missing required PA of ring\n");
		return (DCMD_USAGE);
	}

	if (argc > 1) {
		mdb_warn("too many arguments\n");
		return (DCMD_USAGE);
	}

	if (mdb_vread(&xr, sizeof (xr), addr) != sizeof (xr)) {
		mdb_warn("failed to read xhci_ring_t at %p", addr);
		return (DCMD_USAGE);
	}

	if (argv[0].a_type == MDB_TYPE_IMMEDIATE) {
		target = argv[0].a_un.a_val;
	} else if (argv[0].a_type == MDB_TYPE_STRING) {
		target = mdb_strtoull(argv[0].a_un.a_str);
	} else {
		mdb_warn("argument is an unknown supported type: %d\n",
		    argv[0].a_type);
		return (DCMD_USAGE);
	}
	target = roundup(target, sizeof (xhci_trb_t));

	base = xr.xr_dma.xdb_cookies[0].dmac_laddress;
	max = base + xr.xr_ntrb * sizeof (xhci_trb_t);

	if (target < base || target > max) {
		mdb_warn("target address %p is outside the range of PAs for "
		    "TRBs in the ring [%p, %p)", target, base, max);
		return (DCMD_ERR);
	}
	target -= base;
	mdb_printf("0x%" PRIx64 "\n", target + (uintptr_t)xr.xr_trb);

	return (DCMD_OK);
}

static const mdb_dcmd_t xhci_dcmds[] = {
	{ "xhci_epctx", ":", "print endpoint context",
	    xhci_mdb_print_epctx, NULL },
	{ "xhci_slotctx", ":", "print slot context",
	    xhci_mdb_print_slotctx, NULL },
	{ "xhci_trb", ":", "print TRB",
	    xhci_mdb_print_trb, NULL },
	{ "xhci_find", ": -s slot [-e endpiont]",
	    "find given xhci slot or endpoint",
	    xhci_mdb_find, NULL },
	{ "xhci_device", ":", "device summary",
	    xhci_mdb_print_device, NULL },
	{ "xhci_find_trb", ": pa", "find trb with PA in ring",
	    xhci_mdb_find_trb, NULL },
	{ NULL }
};

static const mdb_walker_t xhci_walkers[] = {
	{ "xhci", "walk list of xhci_t structures",
	    xhci_mdb_walk_xhci_init, xhci_mdb_walk_xhci_step, NULL },
	{ "xhci_device", "walk list of xhci_device_t structures",
	    xhci_mdb_walk_xhci_device_init, xhci_mdb_walk_xhci_device_step,
	    NULL },
	{ "xhci_endpoint", "walk list of xhci_endpoint_t structures",
	    xhci_mdb_walk_xhci_endpoint_init, xhci_mdb_walk_xhci_endpoint_step,
	    NULL },
	{ NULL }
};

static const mdb_modinfo_t xhci_modinfo = {
	MDB_API_VERSION, xhci_dcmds, xhci_walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&xhci_modinfo);
}
