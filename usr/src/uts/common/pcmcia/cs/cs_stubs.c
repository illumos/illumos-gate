/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This is the PCMCIA Card Services kernel stubs module. It provides
 *	the various PCMCIA kernel framework entry points.
 */

#if defined(DEBUG)
#define	CS_STUBS_DEBUG
#endif

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/autoconf.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/varargs.h>
#include <sys/var.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/utsname.h>
#include <sys/vtrace.h>
#include <sys/kstat.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/callb.h>

#include <sys/pctypes.h>
#include <pcmcia/sys/cs_types.h>
#include <sys/pcmcia.h>
#include <sys/sservice.h>
#include <pcmcia/sys/cis.h>
#include <pcmcia/sys/cis_handlers.h>
#include <pcmcia/sys/cs.h>
#include <pcmcia/sys/cs_priv.h>
#include <pcmcia/sys/cs_stubs.h>

#ifdef	CS_STUBS_DEBUG
int cs_stubs_debug = 0;
#endif

static csfunction_t *cardservices = NULL;
static int do_cs_call = 0;
static int cs_no_carservices(int32_t, ...);

#define	CardServices	(do_cs_call ? (*cardservices) :		\
			(cs_no_carservices))

#ifdef	USE_CS_STUBS_MODULE

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops,
	"PCMCIA Card Services stub module"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	if (!do_cs_call)
	    return (mod_remove(&modlinkage));
	else
	    return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
#endif	/* USE_CS_STUBS_MODULE */

/*
 * csx_register_cardservices - The Card Services loadable module
 *	calls this runction to register it's entry point.
 *
 * Returns:	CS_SUCCESS - if operation sucessful
 *		CS_UNSUPPORTED_FUNCTION - if invalid function code
 *		CS_BAD_HANDLE - if Card Services is not registered
 */
int32_t
csx_register_cardservices(cs_register_cardservices_t *rcs)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 2)
	    cmn_err(CE_CONT, "csx_register_cardservices: "
		"magic: 0x%x function: 0x%x cardservices: 0x%p\n",
		rcs->magic, rcs->function, (void *)rcs->cardservices);
#endif

	if (rcs->magic != CS_STUBS_MAGIC)
	    return (CS_BAD_ARGS);

	switch (rcs->function) {
	    case CS_ENTRY_REGISTER:
		cardservices = rcs->cardservices;
		do_cs_call = 1;
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 2)
	    cmn_err(CE_CONT, "csx_register_cardservices: CS_ENTRY_REGISTER\n");
#endif

		return (CS_SUCCESS);

	    case CS_ENTRY_DEREGISTER:
		do_cs_call = 0;
		cardservices = cs_no_carservices;
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 2)
	    cmn_err(CE_CONT,
		"csx_register_cardservices: CS_ENTRY_DEREGISTER\n");
#endif
		return (CS_UNSUPPORTED_FUNCTION);

	    case CS_ENTRY_INQUIRE:
		rcs->cardservices = cardservices;
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 2)
	    cmn_err(CE_CONT, "csx_register_cardservices: CS_ENTRY_INQUIRE\n");
#endif

		if (do_cs_call)
		    return (CS_SUCCESS);
		else
		    return (CS_BAD_HANDLE);

	    default:
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 2)
	    cmn_err(CE_CONT, "csx_register_cardservices: (unknown function)\n");
#endif
		return (CS_UNSUPPORTED_FUNCTION);
	}

}

int32_t
csx_RegisterClient(client_handle_t *ch, client_reg_t *cr)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_RegisterClient: (no handle yet)\n");
#endif
	return (CardServices(RegisterClient, ch, cr));
}

int32_t
csx_DeregisterClient(client_handle_t ch)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_DeregisterClient: handle: 0x%x\n", ch);
#endif
	return (CardServices(DeregisterClient, ch));
}

int32_t
csx_GetStatus(client_handle_t ch, get_status_t *gs)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetStatus: handle: 0x%x\n", ch);
#endif
	return (CardServices(GetStatus, ch, gs));
}

int32_t
csx_SetEventMask(client_handle_t ch, sockevent_t *se)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_SetEventMask: handle: 0x%x\n", ch);
#endif
	return (CardServices(SetEventMask, ch, se));
}

int32_t
csx_GetEventMask(client_handle_t ch, sockevent_t *se)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetEventMask: handle: 0x%x\n", ch);
#endif
	return (CardServices(GetEventMask, ch, se));
}

int32_t
csx_RequestIO(client_handle_t ch, io_req_t *ior)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_RequestIO: handle: 0x%x\n", ch);
#endif
	return (CardServices(RequestIO, ch, ior));
}

int32_t
csx_ReleaseIO(client_handle_t ch, io_req_t *ior)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ReleaseIO: handle: 0x%x\n", ch);
#endif
	return (CardServices(ReleaseIO, ch, ior));
}

int32_t
csx_RequestIRQ(client_handle_t ch, irq_req_t *irqr)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_RequestIRQ: handle: 0x%x\n", ch);
#endif
	return (CardServices(RequestIRQ, ch, irqr));
}

int32_t
csx_ReleaseIRQ(client_handle_t ch, irq_req_t *irqr)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ReleaseIRQ: handle: 0x%x\n", ch);
#endif
	return (CardServices(ReleaseIRQ, ch, irqr));
}

int32_t
csx_RequestWindow(client_handle_t ch, window_handle_t *wh, win_req_t *wr)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_RequestWindow: handle: 0x%x\n", ch);
#endif
	return (CardServices(RequestWindow, ch, wh, wr));
}

int32_t
csx_ReleaseWindow(window_handle_t wh)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ReleaseWindow: handle: 0x%x\n", wh);
#endif
	return (CardServices(ReleaseWindow, wh));
}

int32_t
csx_ModifyWindow(window_handle_t wh, modify_win_t *mw)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ModifyWindow: handle: 0x%x\n", wh);
#endif
	return (CardServices(ModifyWindow, wh, mw));
}

int32_t
csx_MapMemPage(window_handle_t wh, map_mem_page_t *mmp)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_MapMemPage: handle: 0x%x\n", wh);
#endif
	return (CardServices(MapMemPage, wh, mmp));
}

int32_t
csx_RequestSocketMask(client_handle_t ch, request_socket_mask_t *sm)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_RequestSocketMask: handle: 0x%x\n", ch);
#endif
	return (CardServices(RequestSocketMask, ch, sm));
}

int32_t
csx_ReleaseSocketMask(client_handle_t ch, release_socket_mask_t *rsm)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ReleaseSocketMask: handle: 0x%x\n", ch);
#endif
	return (CardServices(ReleaseSocketMask, ch, rsm));
}

int32_t
csx_RequestConfiguration(client_handle_t ch, config_req_t *cr)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_RequestConfiguration: handle: 0x%x\n", ch);
#endif
	return (CardServices(RequestConfiguration, ch, cr));
}

int32_t
csx_ModifyConfiguration(client_handle_t ch, modify_config_t *mc)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ModifyConfiguration: handle: 0x%x\n", ch);
#endif
	return (CardServices(ModifyConfiguration, ch, mc));
}

int32_t
csx_ReleaseConfiguration(client_handle_t ch, release_config_t *rc)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ReleaseConfiguration: handle: 0x%x\n", ch);
#endif
	return (CardServices(ReleaseConfiguration, ch, rc));
}

int32_t
csx_AccessConfigurationRegister(client_handle_t ch, access_config_reg_t *acr)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT,
		"csx_AccessConfigurationRegister: handle: 0x%x\n", ch);
#endif
	return (CardServices(AccessConfigurationRegister, ch, acr));
}

int32_t
csx_GetFirstTuple(client_handle_t ch, tuple_t *tp)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetFirstTuple: handle: 0x%x\n", ch);
#endif
	return (CardServices(GetFirstTuple, ch, tp));
}

int32_t
csx_GetNextTuple(client_handle_t ch, tuple_t *tp)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetNextTuple: handle: 0x%x\n", ch);
#endif
	return (CardServices(GetNextTuple, ch, tp));
}

int32_t
csx_GetTupleData(client_handle_t ch, tuple_t *tp)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetTupleData: handle: 0x%x\n", ch);
#endif
	return (CardServices(GetTupleData, ch, tp));
}

int32_t
csx_MapLogSocket(client_handle_t ch, map_log_socket_t *mls)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_MapLogSocket: handle: 0x%x\n", ch);
#endif
	return (CardServices(MapLogSocket, ch, mls));
}

int32_t
csx_ValidateCIS(client_handle_t ch, cisinfo_t *ci)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ValidateCIS: handle: 0x%x\n", ch);
#endif
	return (CardServices(ValidateCIS, ch, ci));
}

int32_t
csx_MakeDeviceNode(client_handle_t ch, make_device_node_t *mdn)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_MakeDeviceNode: handle: 0x%x\n", ch);
#endif
	return (CardServices(MakeDeviceNode, ch, mdn));
}

int32_t
csx_RemoveDeviceNode(client_handle_t ch, remove_device_node_t *rdn)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_RemoveDeviceNode: handle: 0x%x\n", ch);
#endif
	return (CardServices(RemoveDeviceNode, ch, rdn));
}

int32_t
csx_ConvertSpeed(convert_speed_t *cp)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ConvertSpeed\n");
#endif
	return (CardServices(ConvertSpeed, cp));
}

int32_t
csx_ConvertSize(convert_size_t *cp)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ConvertSize\n");
#endif
	return (CardServices(ConvertSize, cp));
}

int32_t
csx_Event2Text(event2text_t *e2t)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Event2Text\n");
#endif
	return (CardServices(Event2Text, e2t));
}

int32_t
csx_Error2Text(error2text_t *e2t)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Error2Text\n");
#endif
	return (CardServices(Error2Text, e2t));
}

int32_t
csx_CS_DDI_Info(cs_ddi_info_t *cp)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_CS_DDI_Info\n");
#endif
	return (CardServices(CS_DDI_Info, cp));
}

int32_t
csx_CS_Sys_Ctl(cs_sys_ctl_t *csc)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_CS_Sys_Ctl\n");
#endif
	return (CardServices(CS_Sys_Ctl, csc));
}

int32_t
csx_GetClientInfo(client_handle_t ch, client_info_t *ci)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetClientInfo: handle: 0x%x\n", ch);
#endif

	return (CardServices(GetClientInfo, ch, ci));
}

int32_t
csx_GetFirstClient(get_firstnext_client_t *fnc)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetFirstClient\n");
#endif

	return (CardServices(GetFirstClient, fnc));
}

int32_t
csx_GetNextClient(get_firstnext_client_t *fnc)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetNextClient\n");
#endif

	return (CardServices(GetNextClient, fnc));
}

int32_t
csx_ResetFunction(client_handle_t ch, reset_function_t *rf)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ResetFunction: handle: 0x%x\n", ch);
#endif

	return (CardServices(ResetFunction, ch, rf));
}

int32_t
csx_GetCardServicesInfo(client_handle_t ch, get_cardservices_info_t *gcsi)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetCardServicesInfo: handle: 0x%x\n", ch);
#endif

	return (CardServices(GetCardServicesInfo, ch, gcsi));
}

int32_t
csx_GetConfigurationInfo(client_handle_t *ch, get_configuration_info_t *gci)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetConfigurationInfo: "
		"handle: (no handle yet)\n");
#endif

	return (CardServices(GetConfigurationInfo, ch, gci));
}

int32_t
csx_GetPhysicalAdapterInfo(client_handle_t ch, get_physical_adapter_info_t *gp)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetPhysicalAdapterInfo: handle: 0x%x\n", ch);
#endif

	return (CardServices(GetPhysicalAdapterInfo, ch, gp));
}

/*
 * CIS tuple parsing functions - one entrypoint per tuple that we know
 *	how to parse
 */
int32_t
csx_Parse_CISTPL_CONFIG(client_handle_t ch, tuple_t *tp, cistpl_config_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_CONFIG: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_CONFIG;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_DEVICE(client_handle_t ch, tuple_t *tp, cistpl_device_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_DEVICE: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_DEVICE;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_DEVICE_A(client_handle_t ch, tuple_t *tp, cistpl_device_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_DEVICE_A: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_DEVICE_A;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_DEVICE_OA(client_handle_t ch, tuple_t *tp, cistpl_device_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_DEVICE_OA: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_DEVICE_OA;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_DEVICE_OC(client_handle_t ch, tuple_t *tp, cistpl_device_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_DEVICE_OC: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_DEVICE_OC;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_VERS_1(client_handle_t ch, tuple_t *tp, cistpl_vers_1_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_VERS_1: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_VERS_1;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_VERS_2(client_handle_t ch, tuple_t *tp, cistpl_vers_2_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_VERS_2: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_VERS_2;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_JEDEC_A(client_handle_t ch, tuple_t *tp, cistpl_jedec_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_JEDEC_A: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_JEDEC_A;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_JEDEC_C(client_handle_t ch, tuple_t *tp, cistpl_jedec_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_JEDEC_C: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_JEDEC_C;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_FORMAT(client_handle_t ch, tuple_t *tp, cistpl_format_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_FORMAT: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_FORMAT;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_FORMAT_A(client_handle_t ch, tuple_t *tp, cistpl_format_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_FORMAT_A: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_FORMAT_A;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_GEOMETRY(client_handle_t ch, tuple_t *tp,
    cistpl_geometry_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_GEOMETRY: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_GEOMETRY;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_BYTEORDER(client_handle_t ch, tuple_t *tp,
    cistpl_byteorder_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_BYTEORDER: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_BYTEORDER;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_DATE(client_handle_t ch, tuple_t *tp, cistpl_date_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_DATE: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_DATE;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_BATTERY(client_handle_t ch, tuple_t *tp, cistpl_battery_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_BATTERY: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_BATTERY;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_ORG(client_handle_t ch, tuple_t *tp, cistpl_org_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_ORG: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_ORG;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_MANFID(client_handle_t ch, tuple_t *tp, cistpl_manfid_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_MANFID: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_MANFID;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_FUNCID(client_handle_t ch, tuple_t *tp, cistpl_funcid_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_FUNCID: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_FUNCID;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_FUNCE(client_handle_t ch, tuple_t *tp,
    cistpl_funce_t *pt, uint32_t function)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_FUNCE: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_FUNCE;
	return (CardServices(ParseTuple, ch, tp, pt, function));
}

int32_t
csx_Parse_CISTPL_CFTABLE_ENTRY(client_handle_t ch, tuple_t *tp,
    cistpl_cftable_entry_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT,
		"csx_Parse_CISTPL_CFTABLE_ENTRY: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_CFTABLE_ENTRY;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_LINKTARGET(client_handle_t ch, tuple_t *tp,
    cistpl_linktarget_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_LINKTARGET: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_LINKTARGET;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_LONGLINK_A(client_handle_t ch, tuple_t *tp,
    cistpl_longlink_ac_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_LONGLINK_A: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_LONGLINK_A;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_LONGLINK_C(client_handle_t ch, tuple_t *tp,
    cistpl_longlink_ac_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_LONGLINK_C: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_LONGLINK_C;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_LONGLINK_MFC(client_handle_t ch, tuple_t *tp,
    cistpl_longlink_mfc_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_LONGLINK_MFC: "
						"handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_LONGLINK_MFC;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t csx_Parse_CISTPL_LONGLINK_CB(client_handle_t ch, tuple_t *tp,
    cistpl_longlink_cb_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_LONGLINK_CB: "
						"handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_LONGLINK_CB;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_SPCL(client_handle_t ch, tuple_t *tp,
    cistpl_spcl_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_SPCL: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_SPCL;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_SWIL(client_handle_t ch, tuple_t *tp,
    cistpl_swil_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_SWIL: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_SWIL;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t csx_Parse_CISTPL_BAR(client_handle_t ch, tuple_t *tp,
    cistpl_bar_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_BAR: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_BAR;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_DEVICEGEO(client_handle_t ch, tuple_t *tp,
    cistpl_devicegeo_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_DEVICEGEO: handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_DEVICEGEO;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_Parse_CISTPL_DEVICEGEO_A(client_handle_t ch, tuple_t *tp,
    cistpl_devicegeo_t *pt)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_Parse_CISTPL_DEVICEGEO_A: "
						"handle: 0x%x\n", ch);
#endif
	tp->DesiredTuple = CISTPL_DEVICEGEO_A;
	return (CardServices(ParseTuple, ch, tp, pt));
}

int32_t
csx_ParseTuple(client_handle_t ch, tuple_t *tp, cisparse_t *cp, uint32_t ef)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_ParseTuple: handle: 0x%x\n", ch);
#endif
	return (CardServices(ParseTuple, ch, tp, cp, ef));
}

/*
 * The following functions are used to access various datatypes.
 *	These functions are not specific to PCMCIA client drivers
 *	and they don't depend on Card Services being present to
 *	operate.
 */
void
csx_Put8(acc_handle_t handle, uint32_t offset, uint8_t value)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_put8(handle, (uint8_t *)(hp->ah_addr + offset), value);
}

void
csx_Put16(acc_handle_t handle, uint32_t offset, uint16_t value)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_put16(handle, (uint16_t *)(hp->ah_addr + offset), value);
}

void
csx_Put32(acc_handle_t handle, uint32_t offset, uint32_t value)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_put32(handle, (uint32_t *)(hp->ah_addr + offset), value);
}

void
csx_Put64(acc_handle_t handle, uint32_t offset, uint64_t value)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_put64(handle, (uint64_t *)(hp->ah_addr + offset), value);
}

uint8_t
csx_Get8(acc_handle_t handle, uint32_t offset)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	return (ddi_get8(handle, (uint8_t *)(hp->ah_addr + offset)));
}

uint16_t
csx_Get16(acc_handle_t handle, uint32_t offset)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	return (ddi_get16(handle, (uint16_t *)(hp->ah_addr + offset)));
}

uint32_t
csx_Get32(acc_handle_t handle, uint32_t offset)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	return (ddi_get32(handle, (uint32_t *)(hp->ah_addr + offset)));
}

uint64_t
csx_Get64(acc_handle_t handle, uint32_t offset)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	return (ddi_get64(handle, (uint64_t *)(hp->ah_addr + offset)));
}

void
csx_RepPut8(acc_handle_t handle, uint8_t *hostaddr, uint32_t offset,
						uint32_t rc, uint32_t flags)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_rep_put8(handle, hostaddr, (uint8_t *)(hp->ah_addr + offset),
		rc, (uint32_t)flags);
}

void
csx_RepPut16(acc_handle_t handle, uint16_t *hostaddr, uint32_t offset,
						uint32_t rc, uint32_t flags)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_rep_put16(handle, hostaddr, (uint16_t *)(hp->ah_addr + offset),
		rc, (uint32_t)flags);
}

void
csx_RepPut32(acc_handle_t handle, uint32_t *hostaddr, uint32_t offset,
						uint32_t rc, uint32_t flags)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_rep_put32(handle, hostaddr, (uint32_t *)(hp->ah_addr + offset),
		rc, (uint32_t)flags);
}

void
csx_RepPut64(acc_handle_t handle, uint64_t *hostaddr, uint32_t offset,
						uint32_t rc, uint32_t flags)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_rep_put64(handle, hostaddr, (uint64_t *)(hp->ah_addr + offset),
		rc, (uint32_t)flags);
}

void
csx_RepGet8(acc_handle_t handle, uint8_t *hostaddr, uint32_t offset,
						uint32_t rc, uint32_t flags)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_rep_get8(handle, hostaddr, (uint8_t *)(hp->ah_addr + offset),
		rc, (uint32_t)flags);
}

void
csx_RepGet16(acc_handle_t handle, uint16_t *hostaddr, uint32_t offset,
						uint32_t rc, uint32_t flags)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_rep_get16(handle, hostaddr, (uint16_t *)(hp->ah_addr + offset),
		rc, (uint32_t)flags);
}

void
csx_RepGet32(acc_handle_t handle, uint32_t *hostaddr, uint32_t offset,
						uint32_t rc, uint32_t flags)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_rep_get32(handle, hostaddr, (uint32_t *)(hp->ah_addr + offset),
		rc, (uint32_t)flags);
}

void
csx_RepGet64(acc_handle_t handle, uint64_t *hostaddr, uint32_t offset,
						uint32_t rc, uint32_t flags)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	ddi_rep_get64(handle, hostaddr, (uint64_t *)(hp->ah_addr + offset),
		rc, (uint32_t)flags);
}

/*
 * The following two functions return the mapped (virtual) or physical
 *	base address associated with the passed handle if the address
 *	can be directly accessed by the caller. If the object represented
 *	by the handle needs to be accessed through a common access
 *	function, CS_BAD_BASE is returned.
 *
 * XXX - Need to figure out how to determine when to return CS_BAD_BASE
 *	and also we need more generic return codes not tied to CS.
 */
int32_t
csx_GetMappedAddr(acc_handle_t handle, void **addr)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetMappedAddr: handle: 0x%p\n", handle);
#endif

	*addr = hp->ah_addr;

	return (CS_SUCCESS);	/* XXX should be generic return code */
}

int32_t
csx_GetPhysAddr(acc_handle_t handle, void **addr)
{
#ifndef	lint
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);
#endif	/* lint */

#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetPhysAddr: handle: 0x%p\n", handle);
#endif

	*addr = NULL;

	return (CS_BAD_BASE);
}

/*ARGSUSED*/
int32_t
csx_DupHandle(acc_handle_t handle, acc_handle_t *dup, uint32_t flags)
{
#ifndef	lint
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);
#endif	/* lint */

#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_DupHandle: handle: 0x%p\n", handle);
#endif

	return (CS_BAD_HANDLE);

#ifdef	XXX
	*dup = (acc_handle_t)kmem_alloc(sizeof (acc_hdl_t), KM_SLEEP);
	((acc_hdl_t *)*dup)->ddi_handle =
		(ddi_acc_handle_t *)kmem_alloc(sizeof (ddi_acc_impl_t),
		    KM_SLEEP);

	bcopy((caddr_t)hp, (caddr_t)((acc_hdl_t *)*dup)->ddi_handle,
	    sizeof (ddi_acc_impl_t));

	return (CS_SUCCESS);
#endif
}

int32_t
csx_FreeHandle(acc_handle_t *handle)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_FreeHandle: handle: 0x%p\n", *handle);
#endif
	return (CS_BAD_HANDLE);

#ifdef	XXX

	kmem_free((void *)((acc_hdl_t *)*handle)->ddi_handle,
		sizeof (ddi_acc_impl_t));
	kmem_free((void *)(acc_hdl_t *)*handle, sizeof (acc_hdl_t));

	return (CS_SUCCESS);
#endif
}

/*
 * XXX - Probably want to remove these fucntions soon
 */
int32_t
csx_GetHandleOffset(acc_handle_t handle, uint32_t *offset)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_GetHandleOffset: handle: 0x%p\n", handle);
#endif

	*offset = hp->ah_offset;

	return (CS_SUCCESS);
}

int32_t
csx_SetHandleOffset(acc_handle_t handle, uint32_t offset)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "csx_SetHandleOffset: handle: 0x%p\n", handle);
#endif

	hp->ah_offset = offset;

	return (CS_SUCCESS);
}

static int
cs_no_carservices(int32_t arg __unused, ...)
{
#ifdef	CS_STUBS_DEBUG
	if (cs_stubs_debug > 3)
	    cmn_err(CE_CONT, "cs_no_carservices\n");
#endif
	return (CS_UNSUPPORTED_FUNCTION);
}
