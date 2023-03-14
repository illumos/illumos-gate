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
 * Copyright 2020, The University of Queensland
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2020 RackTop Systems, Inc.
 * Copyright 2023 MNX Cloud, Inc.
 */

/*
 * Controls the management of commands that are issues to and from the HCA
 * command queue.
 */

#include <mlxcx.h>

#include <sys/debug.h>
#include <sys/sysmacros.h>

/*
 * When we start up the command queue, it will undergo some internal
 * initialization after we set the command queue address. These values allow us
 * to control how much time we should wait for that to occur.
 */
clock_t mlxcx_cmd_init_delay = 1000 * 10; /* 10 ms in us */
uint_t mlxcx_cmd_init_trys = 100; /* Wait at most 1s */

clock_t mlxcx_cmd_delay = 1000 * 1; /* 1 ms in us */
uint_t mlxcx_cmd_tries = 5000; /* Wait at most 1s */

/*
 * This macro is used to identify that we care about our own function that we're
 * communicating with. We always use this function.
 */
#define	MLXCX_FUNCTION_SELF	(to_be16(0))

static const char *
mlxcx_cmd_response_string(mlxcx_cmd_ret_t ret)
{
	switch (ret) {
	case MLXCX_CMD_R_OK:
		return ("MLXCX_CMD_R_OK");
	case MLXCX_CMD_R_INTERNAL_ERR:
		return ("MLXCX_CMD_R_INTERNAL_ERR");
	case MLXCX_CMD_R_BAD_OP:
		return ("MLXCX_CMD_R_BAD_OP");
	case MLXCX_CMD_R_BAD_PARAM:
		return ("MLXCX_CMD_R_BAD_PARAM");
	case MLXCX_CMD_R_BAD_SYS_STATE:
		return ("MLXCX_CMD_R_BAD_SYS_STATE");
	case MLXCX_CMD_R_BAD_RESOURCE:
		return ("MLXCX_CMD_R_BAD_RESOURCE");
	case MLXCX_CMD_R_RESOURCE_BUSY:
		return ("MLXCX_CMD_R_RESOURCE_BUSY");
	case MLXCX_CMD_R_EXCEED_LIM:
		return ("MLXCX_CMD_R_EXCEED_LIM");
	case MLXCX_CMD_R_BAD_RES_STATE:
		return ("MLXCX_CMD_R_BAD_RES_STATE");
	case MLXCX_CMD_R_BAD_INDEX:
		return ("MLXCX_CMD_R_BAD_INDEX");
	case MLXCX_CMD_R_NO_RESOURCES:
		return ("MLXCX_CMD_R_NO_RESOURCES");
	case MLXCX_CMD_R_BAD_INPUT_LEN:
		return ("MLXCX_CMD_R_BAD_INPUT_LEN");
	case MLXCX_CMD_R_BAD_OUTPUT_LEN:
		return ("MLXCX_CMD_R_BAD_OUTPUT_LEN");
	case MLXCX_CMD_R_BAD_RESOURCE_STATE:
		return ("MLXCX_CMD_R_BAD_RESOURCE_STATE");
	case MLXCX_CMD_R_BAD_PKT:
		return ("MLXCX_CMD_R_BAD_PKT");
	case MLXCX_CMD_R_BAD_SIZE:
		return ("MLXCX_CMD_R_BAD_SIZE");
	default:
		return ("Unknown command");
	}
}

static const char *
mlxcx_cmd_opcode_string(mlxcx_cmd_op_t op)
{
	switch (op) {
	case MLXCX_OP_QUERY_HCA_CAP:
		return ("MLXCX_OP_QUERY_HCA_CAP");
	case MLXCX_OP_QUERY_ADAPTER:
		return ("MLXCX_OP_QUERY_ADAPTER");
	case MLXCX_OP_INIT_HCA:
		return ("MLXCX_OP_INIT_HCA");
	case MLXCX_OP_TEARDOWN_HCA:
		return ("MLXCX_OP_TEARDOWN_HCA");
	case MLXCX_OP_ENABLE_HCA:
		return ("MLXCX_OP_ENABLE_HCA");
	case MLXCX_OP_DISABLE_HCA:
		return ("MLXCX_OP_DISABLE_HCA");
	case MLXCX_OP_QUERY_PAGES:
		return ("MLXCX_OP_QUERY_PAGES");
	case MLXCX_OP_MANAGE_PAGES:
		return ("MLXCX_OP_MANAGE_PAGES");
	case MLXCX_OP_SET_HCA_CAP:
		return ("MLXCX_OP_SET_HCA_CAP");
	case MLXCX_OP_QUERY_ISSI:
		return ("MLXCX_OP_QUERY_ISSI");
	case MLXCX_OP_SET_ISSI:
		return ("MLXCX_OP_SET_ISSI");
	case MLXCX_OP_SET_DRIVER_VERSION:
		return ("MLXCX_OP_SET_DRIVER_VERSION");
	case MLXCX_OP_QUERY_OTHER_HCA_CAP:
		return ("MLXCX_OP_QUERY_OTHER_HCA_CAP");
	case MLXCX_OP_MODIFY_OTHER_HCA_CAP:
		return ("MLXCX_OP_MODIFY_OTHER_HCA_CAP");
	case MLXCX_OP_SET_TUNNELED_OPERATIONS:
		return ("MLXCX_OP_SET_TUNNELED_OPERATIONS");
	case MLXCX_OP_CREATE_MKEY:
		return ("MLXCX_OP_CREATE_MKEY");
	case MLXCX_OP_QUERY_MKEY:
		return ("MLXCX_OP_QUERY_MKEY");
	case MLXCX_OP_DESTROY_MKEY:
		return ("MLXCX_OP_DESTROY_MKEY");
	case MLXCX_OP_QUERY_SPECIAL_CONTEXTS:
		return ("MLXCX_OP_QUERY_SPECIAL_CONTEXTS");
	case MLXCX_OP_PAGE_FAULT_RESUME:
		return ("MLXCX_OP_PAGE_FAULT_RESUME");
	case MLXCX_OP_CREATE_EQ:
		return ("MLXCX_OP_CREATE_EQ");
	case MLXCX_OP_DESTROY_EQ:
		return ("MLXCX_OP_DESTROY_EQ");
	case MLXCX_OP_QUERY_EQ:
		return ("MLXCX_OP_QUERY_EQ");
	case MLXCX_OP_GEN_EQE:
		return ("MLXCX_OP_GEN_EQE");
	case MLXCX_OP_CREATE_CQ:
		return ("MLXCX_OP_CREATE_CQ");
	case MLXCX_OP_DESTROY_CQ:
		return ("MLXCX_OP_DESTROY_CQ");
	case MLXCX_OP_QUERY_CQ:
		return ("MLXCX_OP_QUERY_CQ");
	case MLXCX_OP_MODIFY_CQ:
		return ("MLXCX_OP_MODIFY_CQ");
	case MLXCX_OP_CREATE_QP:
		return ("MLXCX_OP_CREATE_QP");
	case MLXCX_OP_DESTROY_QP:
		return ("MLXCX_OP_DESTROY_QP");
	case MLXCX_OP_RST2INIT_QP:
		return ("MLXCX_OP_RST2INIT_QP");
	case MLXCX_OP_INIT2RTR_QP:
		return ("MLXCX_OP_INIT2RTR_QP");
	case MLXCX_OP_RTR2RTS_QP:
		return ("MLXCX_OP_RTR2RTS_QP");
	case MLXCX_OP_RTS2RTS_QP:
		return ("MLXCX_OP_RTS2RTS_QP");
	case MLXCX_OP_SQERR2RTS_QP:
		return ("MLXCX_OP_SQERR2RTS_QP");
	case MLXCX_OP__2ERR_QP:
		return ("MLXCX_OP__2ERR_QP");
	case MLXCX_OP__2RST_QP:
		return ("MLXCX_OP__2RST_QP");
	case MLXCX_OP_QUERY_QP:
		return ("MLXCX_OP_QUERY_QP");
	case MLXCX_OP_SQD_RTS_QP:
		return ("MLXCX_OP_SQD_RTS_QP");
	case MLXCX_OP_INIT2INIT_QP:
		return ("MLXCX_OP_INIT2INIT_QP");
	case MLXCX_OP_CREATE_PSV:
		return ("MLXCX_OP_CREATE_PSV");
	case MLXCX_OP_DESTROY_PSV:
		return ("MLXCX_OP_DESTROY_PSV");
	case MLXCX_OP_CREATE_SRQ:
		return ("MLXCX_OP_CREATE_SRQ");
	case MLXCX_OP_DESTROY_SRQ:
		return ("MLXCX_OP_DESTROY_SRQ");
	case MLXCX_OP_QUERY_SRQ:
		return ("MLXCX_OP_QUERY_SRQ");
	case MLXCX_OP_ARM_RQ:
		return ("MLXCX_OP_ARM_RQ");
	case MLXCX_OP_CREATE_XRC_SRQ:
		return ("MLXCX_OP_CREATE_XRC_SRQ");
	case MLXCX_OP_DESTROY_XRC_SRQ:
		return ("MLXCX_OP_DESTROY_XRC_SRQ");
	case MLXCX_OP_QUERY_XRC_SRQ:
		return ("MLXCX_OP_QUERY_XRC_SRQ");
	case MLXCX_OP_ARM_XRC_SRQ:
		return ("MLXCX_OP_ARM_XRC_SRQ");
	case MLXCX_OP_CREATE_DCT:
		return ("MLXCX_OP_CREATE_DCT");
	case MLXCX_OP_DESTROY_DCT:
		return ("MLXCX_OP_DESTROY_DCT");
	case MLXCX_OP_DRAIN_DCT:
		return ("MLXCX_OP_DRAIN_DCT");
	case MLXCX_OP_QUERY_DCT:
		return ("MLXCX_OP_QUERY_DCT");
	case MLXCX_OP_ARM_DCT_FOR_KEY_VIOLATION:
		return ("MLXCX_OP_ARM_DCT_FOR_KEY_VIOLATION");
	case MLXCX_OP_CREATE_XRQ:
		return ("MLXCX_OP_CREATE_XRQ");
	case MLXCX_OP_DESTROY_XRQ:
		return ("MLXCX_OP_DESTROY_XRQ");
	case MLXCX_OP_QUERY_XRQ:
		return ("MLXCX_OP_QUERY_XRQ");
	case MLXCX_OP_CREATE_NVMF_BACKEND_CONTROLLER:
		return ("MLXCX_OP_CREATE_NVMF_BACKEND_CONTROLLER");
	case MLXCX_OP_DESTROY_NVMF_BACKEND_CONTROLLER:
		return ("MLXCX_OP_DESTROY_NVMF_BACKEND_CONTROLLER");
	case MLXCX_OP_QUERY_NVMF_BACKEND_CONTROLLER:
		return ("MLXCX_OP_QUERY_NVMF_BACKEND_CONTROLLER");
	case MLXCX_OP_ATTACH_NVMF_NAMESPACE:
		return ("MLXCX_OP_ATTACH_NVMF_NAMESPACE");
	case MLXCX_OP_DETACH_NVMF_NAMESPACE:
		return ("MLXCX_OP_DETACH_NVMF_NAMESPACE");
	case MLXCX_OP_QUERY_XRQ_DC_PARAMS_ENTRY:
		return ("MLXCX_OP_QUERY_XRQ_DC_PARAMS_ENTRY");
	case MLXCX_OP_SET_XRQ_DC_PARAMS_ENTRY:
		return ("MLXCX_OP_SET_XRQ_DC_PARAMS_ENTRY");
	case MLXCX_OP_QUERY_XRQ_ERROR_PARAMS:
		return ("MLXCX_OP_QUERY_XRQ_ERROR_PARAMS");
	case MLXCX_OP_QUERY_VPORT_STATE:
		return ("MLXCX_OP_QUERY_VPORT_STATE");
	case MLXCX_OP_MODIFY_VPORT_STATE:
		return ("MLXCX_OP_MODIFY_VPORT_STATE");
	case MLXCX_OP_QUERY_ESW_VPORT_CONTEXT:
		return ("MLXCX_OP_QUERY_ESW_VPORT_CONTEXT");
	case MLXCX_OP_MODIFY_ESW_VPORT_CONTEXT:
		return ("MLXCX_OP_MODIFY_ESW_VPORT_CONTEXT");
	case MLXCX_OP_QUERY_NIC_VPORT_CONTEXT:
		return ("MLXCX_OP_QUERY_NIC_VPORT_CONTEXT");
	case MLXCX_OP_MODIFY_NIC_VPORT_CONTEXT:
		return ("MLXCX_OP_MODIFY_NIC_VPORT_CONTEXT");
	case MLXCX_OP_QUERY_ROCE_ADDRESS:
		return ("MLXCX_OP_QUERY_ROCE_ADDRESS");
	case MLXCX_OP_SET_ROCE_ADDRESS:
		return ("MLXCX_OP_SET_ROCE_ADDRESS");
	case MLXCX_OP_QUERY_HCA_VPORT_CONTEXT:
		return ("MLXCX_OP_QUERY_HCA_VPORT_CONTEXT");
	case MLXCX_OP_MODIFY_HCA_VPORT_CONTEXT:
		return ("MLXCX_OP_MODIFY_HCA_VPORT_CONTEXT");
	case MLXCX_OP_QUERY_HCA_VPORT_GID:
		return ("MLXCX_OP_QUERY_HCA_VPORT_GID");
	case MLXCX_OP_QUERY_HCA_VPORT_PKEY:
		return ("MLXCX_OP_QUERY_HCA_VPORT_PKEY");
	case MLXCX_OP_QUERY_VPORT_COUNTER:
		return ("MLXCX_OP_QUERY_VPORT_COUNTER");
	case MLXCX_OP_ALLOC_Q_COUNTER:
		return ("MLXCX_OP_ALLOC_Q_COUNTER");
	case MLXCX_OP_DEALLOC_Q_COUNTER:
		return ("MLXCX_OP_DEALLOC_Q_COUNTER");
	case MLXCX_OP_QUERY_Q_COUNTER:
		return ("MLXCX_OP_QUERY_Q_COUNTER");
	case MLXCX_OP_SET_PP_RATE_LIMIT:
		return ("MLXCX_OP_SET_PP_RATE_LIMIT");
	case MLXCX_OP_QUERY_PP_RATE_LIMIT:
		return ("MLXCX_OP_QUERY_PP_RATE_LIMIT");
	case MLXCX_OP_ALLOC_PD:
		return ("MLXCX_OP_ALLOC_PD");
	case MLXCX_OP_DEALLOC_PD:
		return ("MLXCX_OP_DEALLOC_PD");
	case MLXCX_OP_ALLOC_UAR:
		return ("MLXCX_OP_ALLOC_UAR");
	case MLXCX_OP_DEALLOC_UAR:
		return ("MLXCX_OP_DEALLOC_UAR");
	case MLXCX_OP_CONFIG_INT_MODERATION:
		return ("MLXCX_OP_CONFIG_INT_MODERATION");
	case MLXCX_OP_ACCESS_REG:
		return ("MLXCX_OP_ACCESS_REG");
	case MLXCX_OP_ATTACH_TO_MCG:
		return ("MLXCX_OP_ATTACH_TO_MCG");
	case MLXCX_OP_DETACH_FROM_MCG:
		return ("MLXCX_OP_DETACH_FROM_MCG");
	case MLXCX_OP_MAD_IFC:
		return ("MLXCX_OP_MAD_IFC");
	case MLXCX_OP_QUERY_MAD_DEMUX:
		return ("MLXCX_OP_QUERY_MAD_DEMUX");
	case MLXCX_OP_SET_MAD_DEMUX:
		return ("MLXCX_OP_SET_MAD_DEMUX");
	case MLXCX_OP_NOP:
		return ("MLXCX_OP_NOP");
	case MLXCX_OP_ALLOC_XRCD:
		return ("MLXCX_OP_ALLOC_XRCD");
	case MLXCX_OP_DEALLOC_XRCD:
		return ("MLXCX_OP_DEALLOC_XRCD");
	case MLXCX_OP_ALLOC_TRANSPORT_DOMAIN:
		return ("MLXCX_OP_ALLOC_TRANSPORT_DOMAIN");
	case MLXCX_OP_DEALLOC_TRANSPORT_DOMAIN:
		return ("MLXCX_OP_DEALLOC_TRANSPORT_DOMAIN");
	case MLXCX_OP_QUERY_CONG_STATUS:
		return ("MLXCX_OP_QUERY_CONG_STATUS");
	case MLXCX_OP_MODIFY_CONG_STATUS:
		return ("MLXCX_OP_MODIFY_CONG_STATUS");
	case MLXCX_OP_QUERY_CONG_PARAMS:
		return ("MLXCX_OP_QUERY_CONG_PARAMS");
	case MLXCX_OP_MODIFY_CONG_PARAMS:
		return ("MLXCX_OP_MODIFY_CONG_PARAMS");
	case MLXCX_OP_QUERY_CONG_STATISTICS:
		return ("MLXCX_OP_QUERY_CONG_STATISTICS");
	case MLXCX_OP_ADD_VXLAN_UDP_DPORT:
		return ("MLXCX_OP_ADD_VXLAN_UDP_DPORT");
	case MLXCX_OP_DELETE_VXLAN_UDP_DPORT:
		return ("MLXCX_OP_DELETE_VXLAN_UDP_DPORT");
	case MLXCX_OP_SET_L2_TABLE_ENTRY:
		return ("MLXCX_OP_SET_L2_TABLE_ENTRY");
	case MLXCX_OP_QUERY_L2_TABLE_ENTRY:
		return ("MLXCX_OP_QUERY_L2_TABLE_ENTRY");
	case MLXCX_OP_DELETE_L2_TABLE_ENTRY:
		return ("MLXCX_OP_DELETE_L2_TABLE_ENTRY");
	case MLXCX_OP_SET_WOL_ROL:
		return ("MLXCX_OP_SET_WOL_ROL");
	case MLXCX_OP_QUERY_WOL_ROL:
		return ("MLXCX_OP_QUERY_WOL_ROL");
	case MLXCX_OP_CREATE_TIR:
		return ("MLXCX_OP_CREATE_TIR");
	case MLXCX_OP_MODIFY_TIR:
		return ("MLXCX_OP_MODIFY_TIR");
	case MLXCX_OP_DESTROY_TIR:
		return ("MLXCX_OP_DESTROY_TIR");
	case MLXCX_OP_QUERY_TIR:
		return ("MLXCX_OP_QUERY_TIR");
	case MLXCX_OP_CREATE_SQ:
		return ("MLXCX_OP_CREATE_SQ");
	case MLXCX_OP_MODIFY_SQ:
		return ("MLXCX_OP_MODIFY_SQ");
	case MLXCX_OP_DESTROY_SQ:
		return ("MLXCX_OP_DESTROY_SQ");
	case MLXCX_OP_QUERY_SQ:
		return ("MLXCX_OP_QUERY_SQ");
	case MLXCX_OP_CREATE_RQ:
		return ("MLXCX_OP_CREATE_RQ");
	case MLXCX_OP_MODIFY_RQ:
		return ("MLXCX_OP_MODIFY_RQ");
	case MLXCX_OP_DESTROY_RQ:
		return ("MLXCX_OP_DESTROY_RQ");
	case MLXCX_OP_QUERY_RQ:
		return ("MLXCX_OP_QUERY_RQ");
	case MLXCX_OP_CREATE_RMP:
		return ("MLXCX_OP_CREATE_RMP");
	case MLXCX_OP_MODIFY_RMP:
		return ("MLXCX_OP_MODIFY_RMP");
	case MLXCX_OP_DESTROY_RMP:
		return ("MLXCX_OP_DESTROY_RMP");
	case MLXCX_OP_QUERY_RMP:
		return ("MLXCX_OP_QUERY_RMP");
	case MLXCX_OP_CREATE_TIS:
		return ("MLXCX_OP_CREATE_TIS");
	case MLXCX_OP_MODIFY_TIS:
		return ("MLXCX_OP_MODIFY_TIS");
	case MLXCX_OP_DESTROY_TIS:
		return ("MLXCX_OP_DESTROY_TIS");
	case MLXCX_OP_QUERY_TIS:
		return ("MLXCX_OP_QUERY_TIS");
	case MLXCX_OP_CREATE_RQT:
		return ("MLXCX_OP_CREATE_RQT");
	case MLXCX_OP_MODIFY_RQT:
		return ("MLXCX_OP_MODIFY_RQT");
	case MLXCX_OP_DESTROY_RQT:
		return ("MLXCX_OP_DESTROY_RQT");
	case MLXCX_OP_QUERY_RQT:
		return ("MLXCX_OP_QUERY_RQT");
	case MLXCX_OP_SET_FLOW_TABLE_ROOT:
		return ("MLXCX_OP_SET_FLOW_TABLE_ROOT");
	case MLXCX_OP_CREATE_FLOW_TABLE:
		return ("MLXCX_OP_CREATE_FLOW_TABLE");
	case MLXCX_OP_DESTROY_FLOW_TABLE:
		return ("MLXCX_OP_DESTROY_FLOW_TABLE");
	case MLXCX_OP_QUERY_FLOW_TABLE:
		return ("MLXCX_OP_QUERY_FLOW_TABLE");
	case MLXCX_OP_CREATE_FLOW_GROUP:
		return ("MLXCX_OP_CREATE_FLOW_GROUP");
	case MLXCX_OP_DESTROY_FLOW_GROUP:
		return ("MLXCX_OP_DESTROY_FLOW_GROUP");
	case MLXCX_OP_QUERY_FLOW_GROUP:
		return ("MLXCX_OP_QUERY_FLOW_GROUP");
	case MLXCX_OP_SET_FLOW_TABLE_ENTRY:
		return ("MLXCX_OP_SET_FLOW_TABLE_ENTRY");
	case MLXCX_OP_QUERY_FLOW_TABLE_ENTRY:
		return ("MLXCX_OP_QUERY_FLOW_TABLE_ENTRY");
	case MLXCX_OP_DELETE_FLOW_TABLE_ENTRY:
		return ("MLXCX_OP_DELETE_FLOW_TABLE_ENTRY");
	case MLXCX_OP_ALLOC_FLOW_COUNTER:
		return ("MLXCX_OP_ALLOC_FLOW_COUNTER");
	case MLXCX_OP_DEALLOC_FLOW_COUNTER:
		return ("MLXCX_OP_DEALLOC_FLOW_COUNTER");
	case MLXCX_OP_QUERY_FLOW_COUNTER:
		return ("MLXCX_OP_QUERY_FLOW_COUNTER");
	case MLXCX_OP_MODIFY_FLOW_TABLE:
		return ("MLXCX_OP_MODIFY_FLOW_TABLE");
	case MLXCX_OP_ALLOC_ENCAP_HEADER:
		return ("MLXCX_OP_ALLOC_ENCAP_HEADER");
	case MLXCX_OP_DEALLOC_ENCAP_HEADER:
		return ("MLXCX_OP_DEALLOC_ENCAP_HEADER");
	case MLXCX_OP_QUERY_ENCAP_HEADER:
		return ("MLXCX_OP_QUERY_ENCAP_HEADER");
	default:
		return ("Unknown Opcode");
	}
}

const char *
mlxcx_port_status_string(mlxcx_port_status_t st)
{
	switch (st) {
	case MLXCX_PORT_STATUS_UP:
		return ("UP");
	case MLXCX_PORT_STATUS_DOWN:
		return ("DOWN");
	case MLXCX_PORT_STATUS_UP_ONCE:
		return ("UP_ONCE");
	case MLXCX_PORT_STATUS_DISABLED:
		return ("DISABLED");
	default:
		return ("UNKNOWN");
	}
}

void
mlxcx_eth_proto_to_string(mlxcx_eth_proto_t p, mlxcx_ext_eth_proto_t ep,
    char *buf, size_t size)
{
	if (p & MLXCX_PROTO_SGMII)
		(void) strlcat(buf, "SGMII|", size);
	if (p & MLXCX_PROTO_1000BASE_KX)
		(void) strlcat(buf, "1000BASE_KX|", size);
	if (p & MLXCX_PROTO_10GBASE_CX4)
		(void) strlcat(buf, "10GBASE_CX4|", size);
	if (p & MLXCX_PROTO_10GBASE_KX4)
		(void) strlcat(buf, "10GBASE_KX4|", size);
	if (p & MLXCX_PROTO_10GBASE_KR)
		(void) strlcat(buf, "10GBASE_KR|", size);
	if (p & MLXCX_PROTO_40GBASE_CR4)
		(void) strlcat(buf, "40GBASE_CR4|", size);
	if (p & MLXCX_PROTO_40GBASE_KR4)
		(void) strlcat(buf, "40GBASE_KR4|", size);
	if (p & MLXCX_PROTO_SGMII_100BASE)
		(void) strlcat(buf, "SGMII_100BASE|", size);
	if (p & MLXCX_PROTO_10GBASE_CR)
		(void) strlcat(buf, "10GBASE_CR|", size);
	if (p & MLXCX_PROTO_10GBASE_SR)
		(void) strlcat(buf, "10GBASE_SR|", size);
	if (p & MLXCX_PROTO_10GBASE_ER_LR)
		(void) strlcat(buf, "10GBASE_ER_LR|", size);
	if (p & MLXCX_PROTO_40GBASE_SR4)
		(void) strlcat(buf, "40GBASE_SR4|", size);
	if (p & MLXCX_PROTO_40GBASE_LR4_ER4)
		(void) strlcat(buf, "40GBASE_LR4_ER4|", size);
	if (p & MLXCX_PROTO_50GBASE_SR2)
		(void) strlcat(buf, "50GBASE_SR2|", size);
	if (p & MLXCX_PROTO_100GBASE_CR4)
		(void) strlcat(buf, "100GBASE_CR4|", size);
	if (p & MLXCX_PROTO_100GBASE_SR4)
		(void) strlcat(buf, "100GBASE_SR4|", size);
	if (p & MLXCX_PROTO_100GBASE_KR4)
		(void) strlcat(buf, "100GBASE_KR4|", size);
	if (p & MLXCX_PROTO_100GBASE_LR4_ER4)
		(void) strlcat(buf, "100GBASE_LR4_ER4|", size);
	if (p & MLXCX_PROTO_100BASE_TX)
		(void) strlcat(buf, "100BASE_TX|", size);
	if (p & MLXCX_PROTO_1000BASE_T)
		(void) strlcat(buf, "1000BASE_T|", size);
	if (p & MLXCX_PROTO_10GBASE_T)
		(void) strlcat(buf, "10GBASE_T|", size);
	if (p & MLXCX_PROTO_25GBASE_CR)
		(void) strlcat(buf, "25GBASE_CR|", size);
	if (p & MLXCX_PROTO_25GBASE_KR)
		(void) strlcat(buf, "25GBASE_KR|", size);
	if (p & MLXCX_PROTO_25GBASE_SR)
		(void) strlcat(buf, "25GBASE_SR|", size);
	if (p & MLXCX_PROTO_50GBASE_CR2)
		(void) strlcat(buf, "50GBASE_CR2|", size);
	if (p & MLXCX_PROTO_50GBASE_KR2)
		(void) strlcat(buf, "50GBASE_KR2|", size);

	/* Now, for the extended bits... */
	if (ep & MLXCX_EXTPROTO_SGMII_100BASE)
		(void) strlcat(buf, "SGMII_100BASE|", size);
	if (ep & MLXCX_EXTPROTO_1000BASE_X_SGMII)
		(void) strlcat(buf, "1000BASE_X_SGMII|", size);
	if (ep & MLXCX_EXTPROTO_5GBASE_R)
		(void) strlcat(buf, "5GBASE_R|", size);
	if (ep & MLXCX_EXTPROTO_10GBASE_XFI_XAUI_1)
		(void) strlcat(buf, "10GBASE_XFI_XAUI_1|", size);
	if (ep & MLXCX_EXTPROTO_40GBASE_XLAUI_4_XLPPI_4)
		(void) strlcat(buf, "40GBASE_XLAUI_4_XLPPI_4|", size);
	if (ep & MLXCX_EXTPROTO_25GAUI_1_25GBASE_CR_KR)
		(void) strlcat(buf, "25GAUI_1_25GBASE_CR_KR|", size);
	if (ep & MLXCX_EXTPROTO_50GAUI_2_LAUI_2_50GBASE_CR2_KR2)
		(void) strlcat(buf, "50GAUI_2_LAUI_2_50GBASE_CR2_KR2|", size);
	if (ep & MLXCX_EXTPROTO_50GAUI_1_LAUI_1_50GBASE_CR_KR)
		(void) strlcat(buf, "50GAUI_1_LAUI_1_50GBASE_CR_KR|", size);
	if (ep & MLXCX_EXTPROTO_CAUI_4_100GBASE_CR4_KR4)
		(void) strlcat(buf, "CAUI_4_100GBASE_CR4_KR4|", size);
	if (ep & MLXCX_EXTPROTO_100GAUI_2_100GBASE_CR2_KR2)
		(void) strlcat(buf, "100GAUI_2_100GBASE_CR2_KR2|", size);
	if (ep & MLXCX_EXTPROTO_100GAUI_1_100GBASE_CR_KR)
		(void) strlcat(buf, "100GAUI_1_100GBASE_CR_KR|", size);
	/* Print these if we need 'em for debugging... */
	if (ep & MLXCX_EXTPROTO_200GAUI_4_200GBASE_CR4_KR4)
		(void) strlcat(buf, "200GAUI_4_200GBASE_CR4_KR4|", size);
	if (ep & MLXCX_EXTPROTO_200GAUI_2_200GBASE_CR2_KR2)
		(void) strlcat(buf, "200GAUI_2_200GBASE_CR2_KR2|", size);
	if (ep & MLXCX_EXTPROTO_400GAUI_8_400GBASE_CR8)
		(void) strlcat(buf, "400GAUI_8_400GBASE_CR8|", size);
	if (ep & MLXCX_EXTPROTO_400GAUI_4_400GBASE_CR4)
		(void) strlcat(buf, "400GAUI_4_400GBASE_CR4|", size);

	/* Chop off the trailing '|' */
	if (strlen(buf) > 0)
		buf[strlen(buf) - 1] = '\0';
}

void
mlxcx_cmd_queue_fini(mlxcx_t *mlxp)
{
	mlxcx_cmd_queue_t *cmd = &mlxp->mlx_cmd;

	if (cmd->mcmd_tokens != NULL) {
		id_space_destroy(cmd->mcmd_tokens);
		cmd->mcmd_tokens = NULL;
	}

	if (cmd->mcmd_taskq != NULL) {
		ddi_taskq_destroy(cmd->mcmd_taskq);
		cmd->mcmd_taskq = NULL;
	}

	cv_destroy(&cmd->mcmd_cv);
	mutex_destroy(&cmd->mcmd_lock);

	mlxcx_dma_free(&cmd->mcmd_dma);
}

boolean_t
mlxcx_cmd_queue_init(mlxcx_t *mlxp)
{
	uint32_t tmp, cmd_low, cmd_high, i;
	mlxcx_cmd_queue_t *cmd = &mlxp->mlx_cmd;
	char buf[32];
	char tq_name[TASKQ_NAMELEN];
	const ddi_dma_cookie_t *ck;

	ddi_device_acc_attr_t acc;
	ddi_dma_attr_t attr;

	tmp = mlxcx_get32(mlxp, MLXCX_ISS_FIRMWARE);
	mlxp->mlx_fw_maj = MLXCX_ISS_FW_MAJOR(tmp);
	mlxp->mlx_fw_min = MLXCX_ISS_FW_MINOR(tmp);

	tmp = mlxcx_get32(mlxp, MLXCX_ISS_FW_CMD);
	mlxp->mlx_fw_rev = MLXCX_ISS_FW_REV(tmp);
	mlxp->mlx_cmd_rev = MLXCX_ISS_CMD_REV(tmp);

	if (mlxp->mlx_cmd_rev != MLXCX_CMD_REVISION) {
		mlxcx_warn(mlxp, "found unsupported command revision: %u, "
		    "expected %u", mlxp->mlx_cmd_rev, MLXCX_CMD_REVISION);
		return (B_FALSE);
	}

	cmd_low = mlxcx_get32(mlxp, MLXCX_ISS_CMD_LOW);
	cmd->mcmd_size_l2 = MLXCX_ISS_CMDQ_SIZE(cmd_low);
	cmd->mcmd_stride_l2 = MLXCX_ISS_CMDQ_STRIDE(cmd_low);
	cmd->mcmd_size = 1U << cmd->mcmd_size_l2;

	if (cmd->mcmd_size > MLXCX_CMD_MAX) {
		mlxcx_warn(mlxp, "command queue size %u is too "
		    "large. Maximum is %u", cmd->mcmd_size, MLXCX_CMD_MAX);
		return (B_FALSE);
	}

	cmd->mcmd_mask = (uint32_t)((1ULL << cmd->mcmd_size) - 1);

	mutex_init(&cmd->mcmd_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&cmd->mcmd_cv, NULL, CV_DRIVER, NULL);

	(void) snprintf(buf, sizeof (buf), "mlxcx_tokens_%d", mlxp->mlx_inst);
	if ((cmd->mcmd_tokens = id_space_create(buf, 1, UINT8_MAX)) == NULL) {
		mlxcx_warn(mlxp, "failed to allocate token id space");
		mlxcx_cmd_queue_fini(mlxp);
		return (B_FALSE);
	}

	(void) snprintf(tq_name, sizeof (tq_name), "cmdq_%d", mlxp->mlx_inst);
	if ((cmd->mcmd_taskq = ddi_taskq_create(mlxp->mlx_dip, tq_name, 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		mlxcx_warn(mlxp, "failed to create command queue task queue");
		mlxcx_cmd_queue_fini(mlxp);
		return (B_FALSE);
	}

	mlxcx_dma_acc_attr(mlxp, &acc);
	mlxcx_dma_page_attr(mlxp, &attr);

	if (!mlxcx_dma_alloc(mlxp, &cmd->mcmd_dma, &attr, &acc, B_TRUE,
	    MLXCX_CMD_DMA_PAGE_SIZE, B_TRUE)) {
		mlxcx_warn(mlxp, "failed to allocate command dma buffer");
		mlxcx_cmd_queue_fini(mlxp);
		return (B_FALSE);
	}

	ck = mlxcx_dma_cookie_one(&cmd->mcmd_dma);
	cmd_high = (uint32_t)(ck->dmac_laddress >> 32);
	cmd_low = (uint32_t)(ck->dmac_laddress & UINT32_MAX);

	mlxcx_put32(mlxp, MLXCX_ISS_CMD_HIGH, cmd_high);
	mlxcx_put32(mlxp, MLXCX_ISS_CMD_LOW, cmd_low);

	/*
	 * Before this is ready, the initializing bit must become zero.
	 */
	for (i = 0; i < mlxcx_cmd_init_trys; i++) {
		uint32_t init = mlxcx_get32(mlxp, MLXCX_ISS_INIT);

		if (MLXCX_ISS_INITIALIZING(init) == 0)
			break;
		delay(drv_usectohz(mlxcx_cmd_init_delay));
	}
	if (i == mlxcx_cmd_init_trys) {
		mlxcx_warn(mlxp, "timed out initializing command queue");
		mlxcx_cmd_queue_fini(mlxp);
		return (B_FALSE);
	}

	/*
	 * start in polling mode.
	 */
	mlxcx_cmd_eq_disable(mlxp);

	return (B_TRUE);
}

void
mlxcx_cmd_eq_enable(mlxcx_t *mlxp)
{
	mlxp->mlx_cmd.mcmd_polled = B_FALSE;
}

void
mlxcx_cmd_eq_disable(mlxcx_t *mlxp)
{
	mlxp->mlx_cmd.mcmd_polled = B_TRUE;
}

static void
mlxcx_cmd_in_header_init(mlxcx_cmd_t *cmd, mlxcx_cmd_in_t *in,
    mlxcx_cmd_op_t op, uint16_t mod)
{
	ASSERT3U(op, <=, UINT16_MAX);
	in->mci_opcode = to_be16(op);
	in->mci_op_mod = to_be16(mod);
	cmd->mlcmd_op = op;
}

static boolean_t
mlxcx_cmd_mbox_alloc(mlxcx_t *mlxp, list_t *listp, uint8_t nblocks)
{
	uint8_t i;
	ddi_device_acc_attr_t acc;
	ddi_dma_attr_t attr;

	mlxcx_dma_acc_attr(mlxp, &acc);
	mlxcx_dma_page_attr(mlxp, &attr);

	for (i = 0; i < nblocks; i++) {
		mlxcx_cmd_mbox_t *mbox;

		mbox = kmem_zalloc(sizeof (*mbox), KM_SLEEP);
		if (!mlxcx_dma_alloc(mlxp, &mbox->mlbox_dma, &attr, &acc,
		    B_TRUE, sizeof (mlxcx_cmd_mailbox_t), B_TRUE)) {
			mlxcx_warn(mlxp, "failed to allocate mailbox dma "
			    "buffer");
			kmem_free(mbox, sizeof (*mbox));
			/*
			 * mlxcx_cmd_fini will clean up any mboxes that we
			 * already placed onto listp.
			 */
			return (B_FALSE);
		}
		mbox->mlbox_data = (void *)mbox->mlbox_dma.mxdb_va;
		list_insert_tail(listp, mbox);
	}

	return (B_TRUE);
}

static void
mlxcx_cmd_mbox_free(mlxcx_cmd_mbox_t *mbox)
{
	mlxcx_dma_free(&mbox->mlbox_dma);
	kmem_free(mbox, sizeof (mlxcx_cmd_mbox_t));
}

static void
mlxcx_cmd_fini(mlxcx_t *mlxp, mlxcx_cmd_t *cmd)
{
	mlxcx_cmd_mbox_t *mbox;

	while ((mbox = list_remove_head(&cmd->mlcmd_mbox_out)) != NULL) {
		mlxcx_cmd_mbox_free(mbox);
	}
	list_destroy(&cmd->mlcmd_mbox_out);
	while ((mbox = list_remove_head(&cmd->mlcmd_mbox_in)) != NULL) {
		mlxcx_cmd_mbox_free(mbox);
	}
	list_destroy(&cmd->mlcmd_mbox_in);
	id_free(mlxp->mlx_cmd.mcmd_tokens, cmd->mlcmd_token);
	cv_destroy(&cmd->mlcmd_cv);
	mutex_destroy(&cmd->mlcmd_lock);
}

static void
mlxcx_cmd_init(mlxcx_t *mlxp, mlxcx_cmd_t *cmd)
{
	bzero(cmd, sizeof (*cmd));
	mutex_init(&cmd->mlcmd_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mlxp->mlx_async_intr_pri));
	cv_init(&cmd->mlcmd_cv, NULL, CV_DRIVER, NULL);
	cmd->mlcmd_token = id_alloc(mlxp->mlx_cmd.mcmd_tokens);
	cmd->mlcmd_poll = mlxp->mlx_cmd.mcmd_polled;
	list_create(&cmd->mlcmd_mbox_in, sizeof (mlxcx_cmd_mbox_t),
	    offsetof(mlxcx_cmd_mbox_t, mlbox_node));
	list_create(&cmd->mlcmd_mbox_out, sizeof (mlxcx_cmd_mbox_t),
	    offsetof(mlxcx_cmd_mbox_t, mlbox_node));
}

static void
mlxcx_cmd_prep_input(mlxcx_cmd_ent_t *ent, mlxcx_cmd_t *cmd)
{
	uint32_t rem = cmd->mlcmd_inlen;
	uint8_t i;
	const void *in = cmd->mlcmd_in;
	uint32_t copy;
	mlxcx_cmd_mbox_t *mbox;
	const ddi_dma_cookie_t *ck;

	copy = MIN(MLXCX_CMD_INLINE_INPUT_LEN, rem);
	bcopy(in, ent->mce_input, copy);

	rem -= copy;
	in += copy;

	if (rem == 0) {
		ent->mce_in_mbox = to_be64(0);
		VERIFY3U(cmd->mlcmd_nboxes_in, ==, 0);
		return;
	}

	mbox = list_head(&cmd->mlcmd_mbox_in);
	ck = mlxcx_dma_cookie_one(&mbox->mlbox_dma);
	ent->mce_in_mbox = to_be64(ck->dmac_laddress);
	for (i = 0; mbox != NULL;
	    mbox = list_next(&cmd->mlcmd_mbox_in, mbox), i++) {
		mlxcx_cmd_mbox_t *next;
		mlxcx_cmd_mailbox_t *mp = mbox->mlbox_data;

		copy = MIN(MLXCX_CMD_MAILBOX_LEN, rem);
		bcopy(in, mp->mlxb_data, copy);
		rem -= copy;
		in += copy;

		mp->mlxb_token = cmd->mlcmd_token;
		mp->mlxb_blockno = to_be32(i);

		next = list_next(&cmd->mlcmd_mbox_in, mbox);
		if (next == NULL) {
			mp->mlxb_nextp = to_be64(0);
		} else {
			ck = mlxcx_dma_cookie_one(&next->mlbox_dma);
			mp->mlxb_nextp = to_be64(ck->dmac_laddress);
		}
		MLXCX_DMA_SYNC(mbox->mlbox_dma, DDI_DMA_SYNC_FORDEV);
	}
	VERIFY3U(i, ==, cmd->mlcmd_nboxes_in);
	VERIFY0(rem);
}

static void
mlxcx_cmd_prep_output(mlxcx_cmd_ent_t *ent, mlxcx_cmd_t *cmd)
{
	uint8_t i;
	mlxcx_cmd_mbox_t *mbox;
	const ddi_dma_cookie_t *ck;

	if (cmd->mlcmd_nboxes_out == 0) {
		ent->mce_out_mbox = to_be64(0);
		return;
	}

	mbox = list_head(&cmd->mlcmd_mbox_out);
	ck = mlxcx_dma_cookie_one(&mbox->mlbox_dma);
	ent->mce_out_mbox = to_be64(ck->dmac_laddress);
	for (i = 0, mbox = list_head(&cmd->mlcmd_mbox_out); mbox != NULL;
	    mbox = list_next(&cmd->mlcmd_mbox_out, mbox), i++) {
		mlxcx_cmd_mbox_t *next;
		mlxcx_cmd_mailbox_t *mp = mbox->mlbox_data;

		mp->mlxb_token = cmd->mlcmd_token;
		mp->mlxb_blockno = to_be32(i);

		next = list_next(&cmd->mlcmd_mbox_out, mbox);
		if (next == NULL) {
			mp->mlxb_nextp = to_be64(0);
		} else {
			ck = mlxcx_dma_cookie_one(&next->mlbox_dma);
			mp->mlxb_nextp = to_be64(ck->dmac_laddress);
		}
		MLXCX_DMA_SYNC(mbox->mlbox_dma, DDI_DMA_SYNC_FORDEV);
	}
	VERIFY3U(i, ==, cmd->mlcmd_nboxes_out);
}

static void
mlxcx_cmd_copy_output(mlxcx_cmd_ent_t *ent, mlxcx_cmd_t *cmd)
{
	void *out = cmd->mlcmd_out;
	uint32_t rem = cmd->mlcmd_outlen;
	uint32_t copy;
	mlxcx_cmd_mbox_t *mbox;

	copy = MIN(rem, MLXCX_CMD_INLINE_OUTPUT_LEN);
	bcopy(ent->mce_output, out, copy);
	out += copy;
	rem -= copy;

	if (rem == 0) {
		VERIFY0(cmd->mlcmd_nboxes_out);
		return;
	}

	for (mbox = list_head(&cmd->mlcmd_mbox_out); mbox != NULL;
	    mbox = list_next(&cmd->mlcmd_mbox_out, mbox)) {
		MLXCX_DMA_SYNC(mbox->mlbox_dma, DDI_DMA_SYNC_FORKERNEL);
		copy = MIN(MLXCX_CMD_MAILBOX_LEN, rem);
		bcopy(mbox->mlbox_data->mlxb_data, out, copy);
		out += copy;
		rem -= copy;
	}
	VERIFY0(rem);
}

static uint_t
mlxcx_cmd_reserve_slot(mlxcx_cmd_queue_t *cmdq)
{
	uint_t slot;

	mutex_enter(&cmdq->mcmd_lock);
	slot = ddi_ffs(cmdq->mcmd_mask);
	while (slot == 0) {
		cv_wait(&cmdq->mcmd_cv, &cmdq->mcmd_lock);
		slot = ddi_ffs(cmdq->mcmd_mask);
	}

	cmdq->mcmd_mask &= ~(1U << --slot);

	ASSERT3P(cmdq->mcmd_active[slot], ==, NULL);

	mutex_exit(&cmdq->mcmd_lock);

	return (slot);
}

static void
mlxcx_cmd_release_slot(mlxcx_cmd_queue_t *cmdq, uint_t slot)
{
	mutex_enter(&cmdq->mcmd_lock);
	cmdq->mcmd_mask |= 1U << slot;
	cv_broadcast(&cmdq->mcmd_cv);
	mutex_exit(&cmdq->mcmd_lock);
}

static void
mlxcx_cmd_done(mlxcx_cmd_t *cmd, uint_t slot)
{
	mlxcx_t *mlxp = cmd->mlcmd_mlxp;
	mlxcx_cmd_queue_t *cmdq = &mlxp->mlx_cmd;
	mlxcx_cmd_ent_t *ent;

	/*
	 * Command is done. Save relevant data. Once we broadcast on the CV and
	 * drop the lock, we must not touch it again.
	 */
	MLXCX_DMA_SYNC(cmdq->mcmd_dma, DDI_DMA_SYNC_FORKERNEL);

	ent = (mlxcx_cmd_ent_t *)(cmdq->mcmd_dma.mxdb_va +
	    (slot << cmdq->mcmd_stride_l2));

	mutex_enter(&cmd->mlcmd_lock);
	cmd->mlcmd_status = MLXCX_CMD_STATUS(ent->mce_status);
	if (cmd->mlcmd_status == 0)
		mlxcx_cmd_copy_output(ent, cmd);

	cmd->mlcmd_state = MLXCX_CMD_S_DONE;
	cv_broadcast(&cmd->mlcmd_cv);
	mutex_exit(&cmd->mlcmd_lock);

	cmdq->mcmd_active[slot] = NULL;
	mlxcx_cmd_release_slot(cmdq, slot);
}

static void
mlxcx_cmd_taskq(void *arg)
{
	mlxcx_cmd_t *cmd = arg;
	mlxcx_t *mlxp = cmd->mlcmd_mlxp;
	mlxcx_cmd_queue_t *cmdq = &mlxp->mlx_cmd;
	mlxcx_cmd_ent_t *ent;
	uint_t poll, slot;

	ASSERT3S(cmd->mlcmd_op, !=, 0);

	slot = mlxcx_cmd_reserve_slot(cmdq);
	ent = (mlxcx_cmd_ent_t *)(cmdq->mcmd_dma.mxdb_va +
	    (slot << cmdq->mcmd_stride_l2));

	cmdq->mcmd_active[slot] = cmd;

	/*
	 * Command queue is currently ours as we set busy.
	 */
	bzero(ent, sizeof (*ent));
	ent->mce_type = MLXCX_CMD_TRANSPORT_PCI;
	ent->mce_in_length = to_be32(cmd->mlcmd_inlen);
	ent->mce_out_length = to_be32(cmd->mlcmd_outlen);
	ent->mce_token = cmd->mlcmd_token;
	ent->mce_sig = 0;
	ent->mce_status = MLXCX_CMD_HW_OWNED;
	mlxcx_cmd_prep_input(ent, cmd);
	mlxcx_cmd_prep_output(ent, cmd);
	MLXCX_DMA_SYNC(cmdq->mcmd_dma, DDI_DMA_SYNC_FORDEV);

	mlxcx_put32(mlxp, MLXCX_ISS_CMD_DOORBELL, 1 << slot);

	if (!cmd->mlcmd_poll)
		return;

	for (poll = 0; poll < mlxcx_cmd_tries; poll++) {
		delay(drv_usectohz(mlxcx_cmd_delay));
		MLXCX_DMA_SYNC(cmdq->mcmd_dma, DDI_DMA_SYNC_FORKERNEL);
		if ((ent->mce_status & MLXCX_CMD_HW_OWNED) == 0)
			break;
	}

	/*
	 * Command is done (or timed out). Save relevant data. Once we broadcast
	 * on the CV and drop the lock, we must not touch the cmd again.
	 */

	if (poll == mlxcx_cmd_tries) {
		mutex_enter(&cmd->mlcmd_lock);
		cmd->mlcmd_status = MLXCX_CMD_R_TIMEOUT;
		cmd->mlcmd_state = MLXCX_CMD_S_ERROR;
		cv_broadcast(&cmd->mlcmd_cv);
		mutex_exit(&cmd->mlcmd_lock);

		mlxcx_fm_ereport(mlxp, DDI_FM_DEVICE_NO_RESPONSE);

		cmdq->mcmd_active[slot] = NULL;
		mlxcx_cmd_release_slot(cmdq, slot);

		return;
	}

	mlxcx_cmd_done(cmd, slot);
}

void
mlxcx_cmd_completion(mlxcx_t *mlxp, mlxcx_eventq_ent_t *ent)
{
	mlxcx_cmd_queue_t *cmdq = &mlxp->mlx_cmd;
	mlxcx_evdata_cmd_completion_t *eqe_cmd = &ent->mleqe_cmd_completion;
	mlxcx_cmd_t *cmd;
	uint32_t comp_vec = from_be32(eqe_cmd->mled_cmd_completion_vec);
	uint_t slot;

	DTRACE_PROBE2(cmd_event, mlxcx_t *, mlxp,
	    mlxcx_evdata_cmd_completion_t *, eqe_cmd);

	while ((slot = ddi_ffs(comp_vec)) != 0) {
		comp_vec &= ~(1U << --slot);

		cmd = cmdq->mcmd_active[slot];
		if (cmd->mlcmd_poll)
			continue;

		mlxcx_cmd_done(cmd, slot);
	}
}

static boolean_t
mlxcx_cmd_send(mlxcx_t *mlxp, mlxcx_cmd_t *cmd, const void *in, uint32_t inlen,
    void *out, uint32_t outlen)
{
	if (inlen > MLXCX_CMD_INLINE_INPUT_LEN) {
		uint32_t need = inlen - MLXCX_CMD_INLINE_INPUT_LEN;
		uint8_t nblocks;

		if (need / MLXCX_CMD_MAILBOX_LEN + 1 > UINT8_MAX) {
			mlxcx_warn(mlxp, "requested too many input blocks for "
			    "%u byte input len", inlen);
			return (B_FALSE);
		}

		nblocks = need / MLXCX_CMD_MAILBOX_LEN + 1;
		if (!mlxcx_cmd_mbox_alloc(mlxp, &cmd->mlcmd_mbox_in, nblocks)) {
			mlxcx_warn(mlxp, "failed to allocate %u blocks of "
			    "input mailbox", nblocks);
			return (B_FALSE);
		}
		cmd->mlcmd_nboxes_in = nblocks;
	}

	if (outlen > MLXCX_CMD_INLINE_OUTPUT_LEN) {
		uint32_t need = outlen - MLXCX_CMD_INLINE_OUTPUT_LEN;
		uint8_t nblocks;

		if (need / MLXCX_CMD_MAILBOX_LEN + 1 > UINT8_MAX) {
			mlxcx_warn(mlxp, "requested too many output blocks for "
			    "%u byte output len", outlen);
			return (B_FALSE);
		}

		nblocks = need / MLXCX_CMD_MAILBOX_LEN + 1;
		if (!mlxcx_cmd_mbox_alloc(mlxp, &cmd->mlcmd_mbox_out,
		    nblocks)) {
			mlxcx_warn(mlxp, "failed to allocate %u blocks of "
			    "output mailbox", nblocks);
			return (B_FALSE);
		}
		cmd->mlcmd_nboxes_out = nblocks;
	}

	cmd->mlcmd_in = in;
	cmd->mlcmd_inlen = inlen;
	cmd->mlcmd_out = out;
	cmd->mlcmd_outlen = outlen;
	cmd->mlcmd_mlxp = mlxp;

	/*
	 * Now that all allocations have been done, all that remains is for us
	 * to dispatch the request to process this to the taskq for it to be
	 * processed.
	 */
	if (ddi_taskq_dispatch(mlxp->mlx_cmd.mcmd_taskq, mlxcx_cmd_taskq, cmd,
	    DDI_SLEEP) != DDI_SUCCESS) {
		mlxcx_warn(mlxp, "failed to submit command to taskq");
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
mlxcx_cmd_wait(mlxcx_cmd_t *cmd)
{
	mutex_enter(&cmd->mlcmd_lock);
	while (cmd->mlcmd_state == 0) {
		cv_wait(&cmd->mlcmd_cv, &cmd->mlcmd_lock);
	}
	mutex_exit(&cmd->mlcmd_lock);
}

static boolean_t
mlxcx_cmd_evaluate(mlxcx_t *mlxp, mlxcx_cmd_t *cmd)
{
	mlxcx_cmd_out_t *out;

	if ((cmd->mlcmd_state & MLXCX_CMD_S_ERROR) != 0) {
		mlxcx_warn(mlxp, "command %s (0x%x) failed due to an internal "
		    "driver error",
		    mlxcx_cmd_opcode_string(cmd->mlcmd_op),
		    cmd->mlcmd_op);
		return (B_FALSE);
	}

	if (cmd->mlcmd_status != 0) {
		mlxcx_warn(mlxp, "command %s (0x%x) failed with command queue "
		    "error 0x%x",
		    mlxcx_cmd_opcode_string(cmd->mlcmd_op),
		    cmd->mlcmd_op, cmd->mlcmd_status);
		return (B_FALSE);
	}

	out = cmd->mlcmd_out;
	if (out->mco_status != MLXCX_CMD_R_OK) {
		mlxcx_warn(mlxp, "command %s 0x%x failed with status code %s "
		    "(0x%x)", mlxcx_cmd_opcode_string(cmd->mlcmd_op),
		    cmd->mlcmd_op, mlxcx_cmd_response_string(out->mco_status),
		    out->mco_status);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
mlxcx_cmd_disable_hca(mlxcx_t *mlxp)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_disable_hca_in_t in;
	mlxcx_cmd_disable_hca_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_disable_hca_head,
	    MLXCX_OP_DISABLE_HCA, 0);
	in.mlxi_disable_hca_func = MLXCX_FUNCTION_SELF;
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_enable_hca(mlxcx_t *mlxp)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_enable_hca_in_t in;
	mlxcx_cmd_enable_hca_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_enable_hca_head,
	    MLXCX_OP_ENABLE_HCA, 0);
	in.mlxi_enable_hca_func = MLXCX_FUNCTION_SELF;
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_query_issi(mlxcx_t *mlxp, uint32_t *issip)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_query_issi_in_t in;
	mlxcx_cmd_query_issi_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_query_issi_head,
	    MLXCX_OP_QUERY_ISSI, 0);
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		*issip = out.mlxo_supported_issi;
	} else if (cmd.mlcmd_status == 0 &&
	    out.mlxo_query_issi_head.mco_status == MLXCX_CMD_R_BAD_OP) {
		/*
		 * The PRM says that if we get a bad operation, that means this
		 * command isn't supported so it only supports version 1 of the
		 * ISSI, which means bit zero should be set.
		 */
		ret = B_TRUE;
		*issip = 1;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_set_issi(mlxcx_t *mlxp, uint16_t issi)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_set_issi_in_t in;
	mlxcx_cmd_set_issi_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_set_issi_head,
	    MLXCX_OP_SET_ISSI, 0);
	in.mlxi_set_issi_current = to_be16(issi);
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_query_pages(mlxcx_t *mlxp, uint_t type, int32_t *npages)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_query_pages_in_t in;
	mlxcx_cmd_query_pages_out_t out;
	boolean_t ret;

	switch (type) {
	case MLXCX_QUERY_PAGES_OPMOD_BOOT:
	case MLXCX_QUERY_PAGES_OPMOD_INIT:
	case MLXCX_QUERY_PAGES_OPMOD_REGULAR:
		break;
	default:
		mlxcx_warn(mlxp, "!passed invalid type to query pages: %u",
		    type);
		return (B_FALSE);
	}

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_query_pages_head,
	    MLXCX_OP_QUERY_PAGES, type);
	in.mlxi_query_pages_func = MLXCX_FUNCTION_SELF;
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		*npages = from_be32(out.mlxo_query_pages_npages);
	}
	mlxcx_cmd_fini(mlxp, &cmd);

	return (ret);
}

boolean_t
mlxcx_cmd_give_pages(mlxcx_t *mlxp, uint_t type, int32_t npages,
    mlxcx_dev_page_t **pages)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_manage_pages_in_t *in;
	mlxcx_cmd_manage_pages_out_t out;
	size_t insize, outsize;
	boolean_t ret;
	uint32_t i;
	uint64_t pa;
	const ddi_dma_cookie_t *ck;

	switch (type) {
	case MLXCX_MANAGE_PAGES_OPMOD_ALLOC_FAIL:
		if (npages != 0) {
			mlxcx_warn(mlxp, "passed non-zero number of pages (%d) "
			    "but asked to fail page allocation", npages);
			return (B_FALSE);
		}
		break;
	case MLXCX_MANAGE_PAGES_OPMOD_GIVE_PAGES:
		ASSERT3S(npages, <=, MLXCX_MANAGE_PAGES_MAX_PAGES);
		if (npages <= 0) {
			mlxcx_warn(mlxp, "passed invalid number of pages (%d) "
			    "to give pages", npages);
			return (B_FALSE);
		}
		break;
	default:
		mlxcx_warn(mlxp, "!passed invalid type to give pages: %u",
		    type);
		return (B_FALSE);
	}

	insize = offsetof(mlxcx_cmd_manage_pages_in_t, mlxi_manage_pages_pas) +
	    npages * sizeof (uint64_t);
	outsize = offsetof(mlxcx_cmd_manage_pages_out_t, mlxo_manage_pages_pas);

	in = kmem_zalloc(insize, KM_SLEEP);
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in->mlxi_manage_pages_head,
	    MLXCX_OP_MANAGE_PAGES, type);
	in->mlxi_manage_pages_func = MLXCX_FUNCTION_SELF;
	in->mlxi_manage_pages_npages = to_be32(npages);
	for (i = 0; i < npages; i++) {
		ck = mlxcx_dma_cookie_one(&pages[i]->mxdp_dma);
		pa = ck->dmac_laddress;
		ASSERT3U(pa & 0xfff, ==, 0);
		ASSERT3U(ck->dmac_size, ==, MLXCX_HW_PAGE_SIZE);
		in->mlxi_manage_pages_pas[i] = to_be64(pa);
	}

	if ((ret = mlxcx_cmd_send(mlxp, &cmd, in, insize, &out, outsize))) {
		mlxcx_cmd_wait(&cmd);
		ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	}

	mlxcx_cmd_fini(mlxp, &cmd);

	kmem_free(in, insize);
	return (ret);
}

boolean_t
mlxcx_cmd_return_pages(mlxcx_t *mlxp, int32_t nreq, uint64_t *pas,
    int32_t *nret)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_manage_pages_in_t in;
	mlxcx_cmd_manage_pages_out_t *out;
	size_t insize, outsize;
	boolean_t ret;
	uint32_t i;

	if (nreq <= 0) {
		mlxcx_warn(mlxp, "passed invalid number of pages (%d) "
		    "to return pages", nreq);
		return (B_FALSE);
	}

	insize = offsetof(mlxcx_cmd_manage_pages_in_t, mlxi_manage_pages_pas);
	outsize = offsetof(mlxcx_cmd_manage_pages_out_t,
	    mlxo_manage_pages_pas) + nreq * sizeof (uint64_t);

	bzero(&in, sizeof (in));
	out = kmem_alloc(outsize, KM_SLEEP);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_manage_pages_head,
	    MLXCX_OP_MANAGE_PAGES, MLXCX_MANAGE_PAGES_OPMOD_RETURN_PAGES);
	in.mlxi_manage_pages_func = MLXCX_FUNCTION_SELF;
	in.mlxi_manage_pages_npages = to_be32(nreq);

	if ((ret = mlxcx_cmd_send(mlxp, &cmd, &in, insize, out, outsize))) {
		mlxcx_cmd_wait(&cmd);

		ret = mlxcx_cmd_evaluate(mlxp, &cmd);
		if (ret) {
			*nret = from_be32(out->mlxo_manage_pages_npages);
			for (i = 0; i < *nret; i++) {
				pas[i] =
				    from_be64(out->mlxo_manage_pages_pas[i]);
			}
		}
	}

	mlxcx_cmd_fini(mlxp, &cmd);

	kmem_free(out, outsize);
	return (ret);
}

boolean_t
mlxcx_cmd_query_hca_cap(mlxcx_t *mlxp, mlxcx_hca_cap_type_t type,
    mlxcx_hca_cap_mode_t mode, mlxcx_hca_cap_t *capp)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_query_hca_cap_in_t in;
	mlxcx_cmd_query_hca_cap_out_t *out;
	boolean_t ret;
	uint16_t opmode;

	bzero(&in, sizeof (in));
	out = kmem_zalloc(sizeof (mlxcx_cmd_query_hca_cap_out_t), KM_SLEEP);
	mlxcx_cmd_init(mlxp, &cmd);

	opmode = type << 1 | mode;
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_query_hca_cap_head,
	    MLXCX_OP_QUERY_HCA_CAP, opmode);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), out, sizeof (*out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		kmem_free(out, sizeof (mlxcx_cmd_query_hca_cap_out_t));
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		capp->mhc_mode = mode;
		capp->mhc_type = type;
		ASSERT3U(sizeof (out->mlxo_query_hca_cap_data), ==,
		    sizeof (capp->mhc_bulk));
		bcopy(out->mlxo_query_hca_cap_data, capp->mhc_bulk,
		    sizeof (capp->mhc_bulk));
	}
	mlxcx_cmd_fini(mlxp, &cmd);

	kmem_free(out, sizeof (mlxcx_cmd_query_hca_cap_out_t));
	return (B_TRUE);
}

boolean_t
mlxcx_cmd_init_hca(mlxcx_t *mlxp)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_init_hca_in_t in;
	mlxcx_cmd_init_hca_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_init_hca_head,
	    MLXCX_OP_INIT_HCA, 0);
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_set_driver_version(mlxcx_t *mlxp, const char *version)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_set_driver_version_in_t in;
	mlxcx_cmd_set_driver_version_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_set_driver_version_head,
	    MLXCX_OP_SET_DRIVER_VERSION, 0);
	VERIFY3U(strlcpy(in.mlxi_set_driver_version_version, version,
	    sizeof (in.mlxi_set_driver_version_version)), <=,
	    sizeof (in.mlxi_set_driver_version_version));
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_alloc_uar(mlxcx_t *mlxp, mlxcx_uar_t *mlup)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_alloc_uar_in_t in;
	mlxcx_cmd_alloc_uar_out_t out;
	boolean_t ret;
	size_t i;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_alloc_uar_head,
	    MLXCX_OP_ALLOC_UAR, 0);
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlup->mlu_allocated = B_TRUE;
		mlup->mlu_num = from_be24(out.mlxo_alloc_uar_uar);
		VERIFY3U(mlup->mlu_num, >, 0);
		mlup->mlu_base = mlup->mlu_num * MLXCX_HW_PAGE_SIZE;

		for (i = 0; i < MLXCX_BF_PER_UAR; ++i) {
			mlup->mlu_bf[i].mbf_even = mlup->mlu_base +
			    MLXCX_BF_BASE + MLXCX_BF_SIZE * 2 * i;
			mlup->mlu_bf[i].mbf_odd = mlup->mlu_bf[i].mbf_even +
			    MLXCX_BF_SIZE;
		}
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_dealloc_uar(mlxcx_t *mlxp, mlxcx_uar_t *mlup)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_dealloc_uar_in_t in;
	mlxcx_cmd_dealloc_uar_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_dealloc_uar_head,
	    MLXCX_OP_DEALLOC_UAR, 0);
	VERIFY(mlup->mlu_allocated);
	in.mlxi_dealloc_uar_uar = to_be24(mlup->mlu_num);
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlup->mlu_allocated = B_FALSE;
		mlup->mlu_num = 0;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_alloc_pd(mlxcx_t *mlxp, mlxcx_pd_t *mlpd)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_alloc_pd_in_t in;
	mlxcx_cmd_alloc_pd_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_alloc_pd_head,
	    MLXCX_OP_ALLOC_PD, 0);
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlpd->mlpd_allocated = B_TRUE;
		mlpd->mlpd_num = from_be24(out.mlxo_alloc_pd_pdn);
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_dealloc_pd(mlxcx_t *mlxp, mlxcx_pd_t *mlpd)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_dealloc_pd_in_t in;
	mlxcx_cmd_dealloc_pd_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_dealloc_pd_head,
	    MLXCX_OP_DEALLOC_PD, 0);
	VERIFY(mlpd->mlpd_allocated);
	in.mlxi_dealloc_pd_pdn = to_be24(mlpd->mlpd_num);
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlpd->mlpd_allocated = B_FALSE;
		mlpd->mlpd_num = 0;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_alloc_tdom(mlxcx_t *mlxp, mlxcx_tdom_t *mltd)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_alloc_tdom_in_t in;
	mlxcx_cmd_alloc_tdom_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_alloc_tdom_head,
	    MLXCX_OP_ALLOC_TRANSPORT_DOMAIN, 0);
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mltd->mltd_allocated = B_TRUE;
		mltd->mltd_num = from_be24(out.mlxo_alloc_tdom_tdomn);
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_dealloc_tdom(mlxcx_t *mlxp, mlxcx_tdom_t *mltd)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_dealloc_tdom_in_t in;
	mlxcx_cmd_dealloc_tdom_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_dealloc_tdom_head,
	    MLXCX_OP_DEALLOC_TRANSPORT_DOMAIN, 0);
	VERIFY(mltd->mltd_allocated);
	in.mlxi_dealloc_tdom_tdomn = to_be24(mltd->mltd_num);
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mltd->mltd_allocated = B_FALSE;
		mltd->mltd_num = 0;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_teardown_hca(mlxcx_t *mlxp)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_teardown_hca_in_t in;
	mlxcx_cmd_teardown_hca_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_teardown_hca_head,
	    MLXCX_OP_TEARDOWN_HCA, 0);
	in.mlxi_teardown_hca_profile = to_be16(MLXCX_TEARDOWN_HCA_GRACEFUL);
	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_query_nic_vport_ctx(mlxcx_t *mlxp, mlxcx_port_t *mlp)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_query_nic_vport_ctx_in_t in;
	mlxcx_cmd_query_nic_vport_ctx_out_t out;
	boolean_t ret;
	const mlxcx_nic_vport_ctx_t *ctx;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlp->mlp_mtx));
	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_query_nic_vport_ctx_head,
	    MLXCX_OP_QUERY_NIC_VPORT_CONTEXT, MLXCX_VPORT_TYPE_VNIC);

	in.mlxi_query_nic_vport_ctx_vport_number = to_be16(mlp->mlp_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		ctx = &out.mlxo_query_nic_vport_ctx_context;
		mlp->mlp_guid = from_be64(ctx->mlnvc_port_guid);
		mlp->mlp_mtu = from_be16(ctx->mlnvc_mtu);
		bcopy(ctx->mlnvc_permanent_address, mlp->mlp_mac_address,
		    sizeof (mlp->mlp_mac_address));
		mlp->mlp_wqe_min_inline = get_bits64(ctx->mlnvc_flags,
		    MLXCX_VPORT_CTX_MIN_WQE_INLINE);
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

static const char *
mlxcx_reg_name(mlxcx_register_id_t rid)
{
	switch (rid) {
	case MLXCX_REG_PMTU:
		return ("PMTU");
	case MLXCX_REG_PAOS:
		return ("PAOS");
	case MLXCX_REG_PCAM:
		return ("PCAM");
	case MLXCX_REG_PTYS:
		return ("PTYS");
	case MLXCX_REG_MSGI:
		return ("MSGI");
	case MLXCX_REG_PMAOS:
		return ("PMAOS");
	case MLXCX_REG_MLCR:
		return ("MLCR");
	case MLXCX_REG_MCIA:
		return ("MCIA");
	case MLXCX_REG_PPCNT:
		return ("PPCNT");
	case MLXCX_REG_PPLM:
		return ("PPLM");
	case MLXCX_REG_MTCAP:
		return ("MTCAP");
	case MLXCX_REG_MTMP:
		return ("MTMP");
	default:
		return ("???");
	}
}

boolean_t
mlxcx_cmd_access_register(mlxcx_t *mlxp, mlxcx_cmd_reg_opmod_t opmod,
    mlxcx_register_id_t rid, mlxcx_register_data_t *data)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_access_register_in_t in;
	mlxcx_cmd_access_register_out_t out;
	boolean_t ret;
	size_t dsize, insize, outsize;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_access_register_head,
	    MLXCX_OP_ACCESS_REG, opmod);

	in.mlxi_access_register_register_id = to_be16(rid);

	switch (rid) {
	case MLXCX_REG_PMTU:
		dsize = sizeof (mlxcx_reg_pmtu_t);
		break;
	case MLXCX_REG_PAOS:
		dsize = sizeof (mlxcx_reg_paos_t);
		break;
	case MLXCX_REG_PCAM:
		dsize = sizeof (mlxcx_reg_pcam_t);
		break;
	case MLXCX_REG_PTYS:
		dsize = sizeof (mlxcx_reg_ptys_t);
		break;
	case MLXCX_REG_MLCR:
		dsize = sizeof (mlxcx_reg_mlcr_t);
		break;
	case MLXCX_REG_PMAOS:
		dsize = sizeof (mlxcx_reg_pmaos_t);
		break;
	case MLXCX_REG_MCIA:
		dsize = sizeof (mlxcx_reg_mcia_t);
		break;
	case MLXCX_REG_PPCNT:
		dsize = sizeof (mlxcx_reg_ppcnt_t);
		break;
	case MLXCX_REG_PPLM:
		dsize = sizeof (mlxcx_reg_pplm_t);
		break;
	case MLXCX_REG_MTCAP:
		dsize = sizeof (mlxcx_reg_mtcap_t);
		break;
	case MLXCX_REG_MTMP:
		dsize = sizeof (mlxcx_reg_mtmp_t);
		break;
	default:
		dsize = 0;
		VERIFY(0);
		return (B_FALSE);
	}
	insize = dsize + offsetof(mlxcx_cmd_access_register_in_t,
	    mlxi_access_register_data);
	outsize = dsize + offsetof(mlxcx_cmd_access_register_out_t,
	    mlxo_access_register_data);

	bcopy(data, &in.mlxi_access_register_data, dsize);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, insize, &out, outsize)) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		bcopy(&out.mlxo_access_register_data, data, dsize);
	} else {
		mlxcx_warn(mlxp, "failed OP_ACCESS_REG was for register "
		    "%04x (%s)", rid, mlxcx_reg_name(rid));
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_query_port_mtu(mlxcx_t *mlxp, mlxcx_port_t *mlp)
{
	mlxcx_register_data_t data;
	boolean_t ret;

	/*
	 * Since we modify the port here we require that the caller is holding
	 * the port mutex.
	 */
	ASSERT(mutex_owned(&mlp->mlp_mtx));
	bzero(&data, sizeof (data));
	data.mlrd_pmtu.mlrd_pmtu_local_port = mlp->mlp_num + 1;

	ret = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_READ,
	    MLXCX_REG_PMTU, &data);

	if (ret) {
		mlp->mlp_mtu = from_be16(data.mlrd_pmtu.mlrd_pmtu_admin_mtu);
		mlp->mlp_max_mtu = from_be16(data.mlrd_pmtu.mlrd_pmtu_max_mtu);
	}

	return (ret);
}

boolean_t
mlxcx_cmd_query_module_status(mlxcx_t *mlxp, uint_t id,
    mlxcx_module_status_t *pstatus, mlxcx_module_error_type_t *perr)
{
	mlxcx_register_data_t data;
	boolean_t ret;

	bzero(&data, sizeof (data));
	ASSERT3U(id, <, 0xff);
	data.mlrd_pmaos.mlrd_pmaos_module = (uint8_t)id;

	ret = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_READ,
	    MLXCX_REG_PMAOS, &data);

	if (ret) {
		if (pstatus != NULL)
			*pstatus = data.mlrd_pmaos.mlrd_pmaos_oper_status;
		if (perr != NULL)
			*perr = data.mlrd_pmaos.mlrd_pmaos_error_type;
	}

	return (ret);
}

boolean_t
mlxcx_cmd_set_port_mtu(mlxcx_t *mlxp, mlxcx_port_t *mlp)
{
	mlxcx_register_data_t data;
	boolean_t ret;

	ASSERT(mutex_owned(&mlp->mlp_mtx));
	bzero(&data, sizeof (data));
	data.mlrd_pmtu.mlrd_pmtu_local_port = mlp->mlp_num + 1;
	data.mlrd_pmtu.mlrd_pmtu_admin_mtu = to_be16(mlp->mlp_mtu);

	ret = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_WRITE,
	    MLXCX_REG_PMTU, &data);

	return (ret);
}

boolean_t
mlxcx_cmd_set_port_led(mlxcx_t *mlxp, mlxcx_port_t *mlp, uint16_t sec)
{
	mlxcx_register_data_t data;
	boolean_t ret;

	ASSERT(mutex_owned(&mlp->mlp_mtx));
	bzero(&data, sizeof (data));
	data.mlrd_mlcr.mlrd_mlcr_local_port = mlp->mlp_num + 1;
	set_bits8(&data.mlrd_mlcr.mlrd_mlcr_flags, MLXCX_MLCR_LED_TYPE,
	    MLXCX_LED_TYPE_PORT);
	data.mlrd_mlcr.mlrd_mlcr_beacon_duration = to_be16(sec);

	ret = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_WRITE,
	    MLXCX_REG_MLCR, &data);

	return (ret);
}

boolean_t
mlxcx_cmd_query_port_status(mlxcx_t *mlxp, mlxcx_port_t *mlp)
{
	mlxcx_register_data_t data;
	boolean_t ret;

	ASSERT(mutex_owned(&mlp->mlp_mtx));
	bzero(&data, sizeof (data));
	data.mlrd_paos.mlrd_paos_local_port = mlp->mlp_num + 1;

	ret = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_READ,
	    MLXCX_REG_PAOS, &data);

	if (ret) {
		mlp->mlp_admin_status = data.mlrd_paos.mlrd_paos_admin_status;
		mlp->mlp_oper_status = data.mlrd_paos.mlrd_paos_oper_status;
	}

	return (ret);
}

boolean_t
mlxcx_cmd_modify_port_status(mlxcx_t *mlxp, mlxcx_port_t *mlp,
    mlxcx_port_status_t status)
{
	mlxcx_register_data_t data;
	boolean_t ret;

	ASSERT(mutex_owned(&mlp->mlp_mtx));
	bzero(&data, sizeof (data));
	data.mlrd_paos.mlrd_paos_local_port = mlp->mlp_num + 1;
	data.mlrd_paos.mlrd_paos_admin_status = status;
	set_bit32(&data.mlrd_paos.mlrd_paos_flags, MLXCX_PAOS_ADMIN_ST_EN);

	ret = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_WRITE,
	    MLXCX_REG_PAOS, &data);

	return (ret);
}

boolean_t
mlxcx_cmd_query_port_speed(mlxcx_t *mlxp, mlxcx_port_t *mlp)
{
	mlxcx_register_data_t data;
	boolean_t ret;

	ASSERT(mutex_owned(&mlp->mlp_mtx));
	bzero(&data, sizeof (data));
	data.mlrd_ptys.mlrd_ptys_local_port = mlp->mlp_num + 1;
	set_bit8(&data.mlrd_ptys.mlrd_ptys_proto_mask,
	    MLXCX_PTYS_PROTO_MASK_ETH);

	ret = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_READ,
	    MLXCX_REG_PTYS, &data);

	if (ret) {
		if (get_bit8(data.mlrd_ptys.mlrd_ptys_autoneg_flags,
		    MLXCX_AUTONEG_DISABLE)) {
			mlp->mlp_autoneg = B_FALSE;
		} else {
			mlp->mlp_autoneg = B_TRUE;
		}
		mlp->mlp_max_proto =
		    from_bits32(data.mlrd_ptys.mlrd_ptys_proto_cap);
		mlp->mlp_admin_proto =
		    from_bits32(data.mlrd_ptys.mlrd_ptys_proto_admin);
		mlp->mlp_oper_proto =
		    from_bits32(data.mlrd_ptys.mlrd_ptys_proto_oper);
		if (mlxp->mlx_caps->mlc_ext_ptys) {
			/*
			 * Populate these bits only if we know the HW
			 * supports them.  Otherwise keep them zeroed
			 * per the above bzero() and use that zero-ness to
			 * skip over them as need be.
			 */
			mlp->mlp_ext_max_proto = from_bits32(
			    data.mlrd_ptys.mlrd_ptys_ext_proto_cap);
			mlp->mlp_ext_admin_proto = from_bits32(
			    data.mlrd_ptys.mlrd_ptys_ext_proto_admin);
			mlp->mlp_ext_oper_proto = from_bits32(
			    data.mlrd_ptys.mlrd_ptys_ext_proto_oper);
		}
	}

	return (ret);
}

boolean_t
mlxcx_cmd_query_port_fec(mlxcx_t *mlxp, mlxcx_port_t *mlp)
{
	mlxcx_register_data_t data;
	boolean_t ret;

	ASSERT(mutex_owned(&mlp->mlp_mtx));
	bzero(&data, sizeof (data));
	data.mlrd_pplm.mlrd_pplm_local_port = mlp->mlp_num + 1;

	ret = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_READ,
	    MLXCX_REG_PPLM, &data);

	if (ret) {
		mlp->mlp_fec_active =
		    from_be24(data.mlrd_pplm.mlrd_pplm_fec_mode_active);
	}

	return (ret);
}

boolean_t
mlxcx_cmd_modify_port_fec(mlxcx_t *mlxp, mlxcx_port_t *mlp,
    mlxcx_pplm_fec_caps_t fec)
{
	mlxcx_register_data_t data_in, data_out;
	mlxcx_pplm_fec_caps_t caps;
	mlxcx_reg_pplm_t *pplm_in, *pplm_out;
	boolean_t ret;

	ASSERT(mutex_owned(&mlp->mlp_mtx));
	bzero(&data_in, sizeof (data_in));
	pplm_in = &data_in.mlrd_pplm;
	pplm_in->mlrd_pplm_local_port = mlp->mlp_num + 1;

	ret = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_READ,
	    MLXCX_REG_PPLM, &data_in);

	if (!ret)
		return (B_FALSE);

	bzero(&data_out, sizeof (data_out));
	pplm_out = &data_out.mlrd_pplm;
	pplm_out->mlrd_pplm_local_port = mlp->mlp_num + 1;

	caps = get_bits32(pplm_in->mlrd_pplm_fec_override_cap,
	    MLXCX_PPLM_CAP_56G);
	set_bits32(&pplm_out->mlrd_pplm_fec_override_admin,
	    MLXCX_PPLM_CAP_56G, fec & caps);

	caps = get_bits32(pplm_in->mlrd_pplm_fec_override_cap,
	    MLXCX_PPLM_CAP_100G);
	set_bits32(&pplm_out->mlrd_pplm_fec_override_admin,
	    MLXCX_PPLM_CAP_100G, fec & caps);

	caps = get_bits32(pplm_in->mlrd_pplm_fec_override_cap,
	    MLXCX_PPLM_CAP_50G);
	set_bits32(&pplm_out->mlrd_pplm_fec_override_admin,
	    MLXCX_PPLM_CAP_50G, fec & caps);

	caps = get_bits32(pplm_in->mlrd_pplm_fec_override_cap,
	    MLXCX_PPLM_CAP_25G);
	set_bits32(&pplm_out->mlrd_pplm_fec_override_admin,
	    MLXCX_PPLM_CAP_25G, fec & caps);

	caps = get_bits32(pplm_in->mlrd_pplm_fec_override_cap,
	    MLXCX_PPLM_CAP_10_40G);
	set_bits32(&pplm_out->mlrd_pplm_fec_override_admin,
	    MLXCX_PPLM_CAP_10_40G, fec & caps);

	ret = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_WRITE,
	    MLXCX_REG_PPLM, &data_out);

	return (ret);
}

boolean_t
mlxcx_cmd_modify_nic_vport_ctx(mlxcx_t *mlxp, mlxcx_port_t *mlp,
    mlxcx_modify_nic_vport_ctx_fields_t fields)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_modify_nic_vport_ctx_in_t in;
	mlxcx_cmd_modify_nic_vport_ctx_out_t out;
	boolean_t ret;
	mlxcx_nic_vport_ctx_t *ctx;

	ASSERT(mutex_owned(&mlp->mlp_mtx));
	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_modify_nic_vport_ctx_head,
	    MLXCX_OP_MODIFY_NIC_VPORT_CONTEXT, MLXCX_VPORT_TYPE_VNIC);

	in.mlxi_modify_nic_vport_ctx_vport_number = to_be16(mlp->mlp_num);
	in.mlxi_modify_nic_vport_ctx_field_select = to_be32(fields);

	ctx = &in.mlxi_modify_nic_vport_ctx_context;
	if (fields & MLXCX_MODIFY_NIC_VPORT_CTX_PROMISC) {
		set_bit16(&ctx->mlnvc_promisc_list_type,
		    MLXCX_VPORT_PROMISC_ALL);
	}
	if (fields & MLXCX_MODIFY_NIC_VPORT_CTX_MTU) {
		ctx->mlnvc_mtu = to_be16(mlp->mlp_mtu);
	}

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		if (fields & MLXCX_MODIFY_NIC_VPORT_CTX_PROMISC) {
			mlp->mlp_flags |= MLXCX_PORT_VPORT_PROMISC;
		}
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_create_eq(mlxcx_t *mlxp, mlxcx_event_queue_t *mleq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_create_eq_in_t in;
	mlxcx_cmd_create_eq_out_t out;
	boolean_t ret;
	mlxcx_eventq_ctx_t *ctx;
	size_t rem, insize;
	const ddi_dma_cookie_t *c;
	uint64_t pa, npages;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mleq->mleq_mtx));
	VERIFY(mleq->mleq_state & MLXCX_EQ_ALLOC);
	VERIFY0(mleq->mleq_state & MLXCX_EQ_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_create_eq_head,
	    MLXCX_OP_CREATE_EQ, 0);

	ctx = &in.mlxi_create_eq_context;
	ctx->mleqc_uar_page = to_be24(mleq->mleq_uar->mlu_num);
	ctx->mleqc_log_eq_size = mleq->mleq_entshift;
	ctx->mleqc_intr = mleq->mleq_intr_index;

	in.mlxi_create_eq_event_bitmask = to_be64(mleq->mleq_events);

	npages = 0;
	c = NULL;
	while ((c = mlxcx_dma_cookie_iter(&mleq->mleq_dma, c)) != NULL) {
		pa = c->dmac_laddress;
		rem = c->dmac_size;
		while (rem > 0) {
			ASSERT3U(pa & 0xfff, ==, 0);
			ASSERT3U(rem, >=, MLXCX_HW_PAGE_SIZE);
			in.mlxi_create_eq_pas[npages++] = to_be64(pa);
			rem -= MLXCX_HW_PAGE_SIZE;
			pa += MLXCX_HW_PAGE_SIZE;
		}
	}
	ASSERT3U(npages, <=, MLXCX_CREATE_QUEUE_MAX_PAGES);

	insize = offsetof(mlxcx_cmd_create_eq_in_t, mlxi_create_eq_pas) +
	    sizeof (uint64_t) * npages;

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, insize, &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mleq->mleq_state |= MLXCX_EQ_CREATED;
		mleq->mleq_num = out.mlxo_create_eq_eqn;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_query_eq(mlxcx_t *mlxp, mlxcx_event_queue_t *mleq,
    mlxcx_eventq_ctx_t *ctxp)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_query_eq_in_t in;
	mlxcx_cmd_query_eq_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	VERIFY(mleq->mleq_state & MLXCX_EQ_ALLOC);
	VERIFY(mleq->mleq_state & MLXCX_EQ_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_query_eq_head,
	    MLXCX_OP_QUERY_EQ, 0);

	in.mlxi_query_eq_eqn = mleq->mleq_num;

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		bcopy(&out.mlxo_query_eq_context, ctxp,
		    sizeof (mlxcx_eventq_ctx_t));
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_destroy_eq(mlxcx_t *mlxp, mlxcx_event_queue_t *mleq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_destroy_eq_in_t in;
	mlxcx_cmd_destroy_eq_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mleq->mleq_mtx));
	VERIFY(mleq->mleq_state & MLXCX_EQ_ALLOC);
	VERIFY(mleq->mleq_state & MLXCX_EQ_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_destroy_eq_head,
	    MLXCX_OP_DESTROY_EQ, 0);

	in.mlxi_destroy_eq_eqn = mleq->mleq_num;

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mleq->mleq_state |= MLXCX_EQ_DESTROYED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_query_special_ctxs(mlxcx_t *mlxp)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_query_special_ctxs_in_t in;
	mlxcx_cmd_query_special_ctxs_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_query_special_ctxs_head,
	    MLXCX_OP_QUERY_SPECIAL_CONTEXTS, 0);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlxp->mlx_rsvd_lkey = from_be32(
		    out.mlxo_query_special_ctxs_resd_lkey);
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_create_cq(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_create_cq_in_t in;
	mlxcx_cmd_create_cq_out_t out;
	boolean_t ret;
	mlxcx_completionq_ctx_t *ctx;
	size_t rem, insize;
	const ddi_dma_cookie_t *c;
	uint64_t pa, npages;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlcq->mlcq_mtx));
	VERIFY(mlcq->mlcq_state & MLXCX_CQ_ALLOC);
	VERIFY0(mlcq->mlcq_state & MLXCX_CQ_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_create_cq_head,
	    MLXCX_OP_CREATE_CQ, 0);

	ctx = &in.mlxi_create_cq_context;
	ctx->mlcqc_uar_page = to_be24(mlcq->mlcq_uar->mlu_num);
	ctx->mlcqc_log_cq_size = mlcq->mlcq_entshift;
	ctx->mlcqc_eqn = mlcq->mlcq_eq->mleq_num;
	ctx->mlcqc_cq_period = to_be16(mlcq->mlcq_cqemod_period_usec);
	ctx->mlcqc_cq_max_count = to_be16(mlcq->mlcq_cqemod_count);

	c = mlxcx_dma_cookie_one(&mlcq->mlcq_doorbell_dma);
	ctx->mlcqc_dbr_addr = to_be64(c->dmac_laddress);
	ASSERT3U(c->dmac_size, >=, sizeof (mlxcx_completionq_doorbell_t));

	npages = 0;
	c = NULL;
	while ((c = mlxcx_dma_cookie_iter(&mlcq->mlcq_dma, c)) != NULL) {
		pa = c->dmac_laddress;
		rem = c->dmac_size;
		while (rem > 0) {
			ASSERT3U(pa & 0xfff, ==, 0);
			ASSERT3U(rem, >=, MLXCX_HW_PAGE_SIZE);
			in.mlxi_create_cq_pas[npages++] = to_be64(pa);
			rem -= MLXCX_HW_PAGE_SIZE;
			pa += MLXCX_HW_PAGE_SIZE;
		}
	}
	ASSERT3U(npages, <=, MLXCX_CREATE_QUEUE_MAX_PAGES);

	insize = offsetof(mlxcx_cmd_create_cq_in_t, mlxi_create_cq_pas) +
	    sizeof (uint64_t) * npages;

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, insize, &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		atomic_or_uint(&mlcq->mlcq_state, MLXCX_CQ_CREATED);
		mlcq->mlcq_num = from_be24(out.mlxo_create_cq_cqn);
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_query_rq(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq,
    mlxcx_rq_ctx_t *ctxp)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_query_rq_in_t in;
	mlxcx_cmd_query_rq_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	VERIFY(mlwq->mlwq_state & MLXCX_WQ_ALLOC);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_CREATED);
	ASSERT3S(mlwq->mlwq_type, ==, MLXCX_WQ_TYPE_RECVQ);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_query_rq_head,
	    MLXCX_OP_QUERY_RQ, 0);

	in.mlxi_query_rq_rqn = to_be24(mlwq->mlwq_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		bcopy(&out.mlxo_query_rq_context, ctxp,
		    sizeof (mlxcx_rq_ctx_t));
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_query_sq(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq,
    mlxcx_sq_ctx_t *ctxp)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_query_sq_in_t in;
	mlxcx_cmd_query_sq_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	VERIFY(mlwq->mlwq_state & MLXCX_WQ_ALLOC);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_CREATED);
	ASSERT3S(mlwq->mlwq_type, ==, MLXCX_WQ_TYPE_SENDQ);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_query_sq_head,
	    MLXCX_OP_QUERY_SQ, 0);

	in.mlxi_query_sq_sqn = to_be24(mlwq->mlwq_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		bcopy(&out.mlxo_query_sq_context, ctxp,
		    sizeof (mlxcx_sq_ctx_t));
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_query_cq(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq,
    mlxcx_completionq_ctx_t *ctxp)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_query_cq_in_t in;
	mlxcx_cmd_query_cq_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	VERIFY(mlcq->mlcq_state & MLXCX_CQ_ALLOC);
	VERIFY(mlcq->mlcq_state & MLXCX_CQ_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_query_cq_head,
	    MLXCX_OP_QUERY_CQ, 0);

	in.mlxi_query_cq_cqn = to_be24(mlcq->mlcq_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		bcopy(&out.mlxo_query_cq_context, ctxp,
		    sizeof (mlxcx_completionq_ctx_t));
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_destroy_cq(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_destroy_cq_in_t in;
	mlxcx_cmd_destroy_cq_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlcq->mlcq_mtx));
	VERIFY(mlcq->mlcq_state & MLXCX_CQ_ALLOC);
	VERIFY(mlcq->mlcq_state & MLXCX_CQ_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_destroy_cq_head,
	    MLXCX_OP_DESTROY_CQ, 0);

	in.mlxi_destroy_cq_cqn = to_be24(mlcq->mlcq_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		atomic_or_uint(&mlcq->mlcq_state, MLXCX_CQ_DESTROYED);
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_create_rq(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_create_rq_in_t in;
	mlxcx_cmd_create_rq_out_t out;
	boolean_t ret;
	mlxcx_rq_ctx_t *ctx;
	size_t rem, insize;
	const ddi_dma_cookie_t *c;
	uint64_t pa, npages;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));
	VERIFY3U(mlwq->mlwq_type, ==, MLXCX_WQ_TYPE_RECVQ);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_ALLOC);
	VERIFY0(mlwq->mlwq_state & MLXCX_WQ_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_create_rq_head,
	    MLXCX_OP_CREATE_RQ, 0);

	ctx = &in.mlxi_create_rq_context;

	set_bit32(&ctx->mlrqc_flags, MLXCX_RQ_FLAGS_RLKEY);
	set_bit32(&ctx->mlrqc_flags, MLXCX_RQ_FLAGS_FLUSH_IN_ERROR);
	set_bit32(&ctx->mlrqc_flags, MLXCX_RQ_FLAGS_VLAN_STRIP_DISABLE);
	ctx->mlrqc_cqn = to_be24(mlwq->mlwq_cq->mlcq_num);

	set_bits32(&ctx->mlrqc_wq.mlwqc_flags, MLXCX_WORKQ_CTX_TYPE,
	    MLXCX_WORKQ_TYPE_CYCLIC);
	ctx->mlrqc_wq.mlwqc_pd = to_be24(mlwq->mlwq_pd->mlpd_num);
	ctx->mlrqc_wq.mlwqc_log_wq_sz = mlwq->mlwq_entshift;
	ctx->mlrqc_wq.mlwqc_log_wq_stride = MLXCX_RECVQ_STRIDE_SHIFT;

	c = mlxcx_dma_cookie_one(&mlwq->mlwq_doorbell_dma);
	ctx->mlrqc_wq.mlwqc_dbr_addr = to_be64(c->dmac_laddress);
	ASSERT3U(c->dmac_size, >=, sizeof (mlxcx_workq_doorbell_t));

	npages = 0;
	c = NULL;
	while ((c = mlxcx_dma_cookie_iter(&mlwq->mlwq_dma, c)) != NULL) {
		pa = c->dmac_laddress;
		rem = c->dmac_size;
		while (rem > 0) {
			ASSERT3U(pa & 0xfff, ==, 0);
			ASSERT3U(rem, >=, MLXCX_HW_PAGE_SIZE);
			ctx->mlrqc_wq.mlwqc_pas[npages++] = to_be64(pa);
			rem -= MLXCX_HW_PAGE_SIZE;
			pa += MLXCX_HW_PAGE_SIZE;
		}
	}
	ASSERT3U(npages, <=, MLXCX_WORKQ_CTX_MAX_ADDRESSES);

	insize = offsetof(mlxcx_cmd_create_rq_in_t, mlxi_create_rq_context) +
	    offsetof(mlxcx_rq_ctx_t, mlrqc_wq) +
	    offsetof(mlxcx_workq_ctx_t, mlwqc_pas) +
	    sizeof (uint64_t) * npages;

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, insize, &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlwq->mlwq_state |= MLXCX_WQ_CREATED;
		mlwq->mlwq_num = from_be24(out.mlxo_create_rq_rqn);
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_start_rq(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_modify_rq_in_t in;
	mlxcx_cmd_modify_rq_out_t out;
	boolean_t ret;
	ddi_fm_error_t err;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_ALLOC);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_CREATED);
	VERIFY0(mlwq->mlwq_state & MLXCX_WQ_STARTED);

	/*
	 * Before starting the queue, we have to be sure that it is
	 * empty and the doorbell and counters are set to 0.
	 */
	ASSERT(mutex_owned(&mlwq->mlwq_cq->mlcq_mtx));
	ASSERT(list_is_empty(&mlwq->mlwq_cq->mlcq_buffers));
	ASSERT(list_is_empty(&mlwq->mlwq_cq->mlcq_buffers_b));

	mlwq->mlwq_doorbell->mlwqd_recv_counter = to_be16(0);
	MLXCX_DMA_SYNC(mlwq->mlwq_doorbell_dma, DDI_DMA_SYNC_FORDEV);
	ddi_fm_dma_err_get(mlwq->mlwq_doorbell_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status != DDI_FM_OK)
		return (B_FALSE);
	mlwq->mlwq_pc = 0;

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_modify_rq_head,
	    MLXCX_OP_MODIFY_RQ, 0);

	in.mlxi_modify_rq_rqn = to_be24(mlwq->mlwq_num);

	/* From state */
	set_bits8(&in.mlxi_modify_rq_state, MLXCX_CMD_MODIFY_RQ_STATE,
	    MLXCX_RQ_STATE_RST);
	/* To state */
	set_bits32(&in.mlxi_modify_rq_context.mlrqc_flags, MLXCX_RQ_STATE,
	    MLXCX_RQ_STATE_RDY);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlwq->mlwq_state |= MLXCX_WQ_STARTED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_stop_rq(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_modify_rq_in_t in;
	mlxcx_cmd_modify_rq_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_ALLOC);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_CREATED);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_STARTED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_modify_rq_head,
	    MLXCX_OP_MODIFY_RQ, 0);

	in.mlxi_modify_rq_rqn = to_be24(mlwq->mlwq_num);

	/* From state */
	set_bits8(&in.mlxi_modify_rq_state, MLXCX_CMD_MODIFY_RQ_STATE,
	    MLXCX_RQ_STATE_RDY);
	/* To state */
	set_bits32(&in.mlxi_modify_rq_context.mlrqc_flags, MLXCX_RQ_STATE,
	    MLXCX_RQ_STATE_RST);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlwq->mlwq_state &= ~MLXCX_WQ_STARTED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_destroy_rq(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_destroy_rq_in_t in;
	mlxcx_cmd_destroy_rq_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_ALLOC);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_CREATED);
	VERIFY0(mlwq->mlwq_state & MLXCX_WQ_STARTED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_destroy_rq_head,
	    MLXCX_OP_DESTROY_RQ, 0);

	in.mlxi_destroy_rq_rqn = to_be24(mlwq->mlwq_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlwq->mlwq_state |= MLXCX_WQ_DESTROYED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_create_tir(mlxcx_t *mlxp, mlxcx_tir_t *mltir)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_create_tir_in_t in;
	mlxcx_cmd_create_tir_out_t out;
	mlxcx_tir_ctx_t *ctx;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	VERIFY0(mltir->mltir_state & MLXCX_TIR_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_create_tir_head,
	    MLXCX_OP_CREATE_TIR, 0);

	ctx = &in.mlxi_create_tir_context;
	ctx->mltirc_transport_domain = to_be24(mltir->mltir_tdom->mltd_num);
	set_bits8(&ctx->mltirc_disp_type, MLXCX_TIR_CTX_DISP_TYPE,
	    mltir->mltir_type);
	switch (mltir->mltir_type) {
	case MLXCX_TIR_INDIRECT:
		VERIFY(mltir->mltir_rqtable != NULL);
		VERIFY(mltir->mltir_rqtable->mlrqt_state & MLXCX_RQT_CREATED);
		ctx->mltirc_indirect_table =
		    to_be24(mltir->mltir_rqtable->mlrqt_num);
		set_bits8(&ctx->mltirc_hash_lb, MLXCX_TIR_RX_HASH_FN,
		    mltir->mltir_hash_fn);
		bcopy(mltir->mltir_toeplitz_key,
		    ctx->mltirc_rx_hash_toeplitz_key,
		    sizeof (ctx->mltirc_rx_hash_toeplitz_key));
		set_bits32(&ctx->mltirc_rx_hash_fields_outer,
		    MLXCX_RX_HASH_L3_TYPE, mltir->mltir_l3_type);
		set_bits32(&ctx->mltirc_rx_hash_fields_outer,
		    MLXCX_RX_HASH_L4_TYPE, mltir->mltir_l4_type);
		set_bits32(&ctx->mltirc_rx_hash_fields_outer,
		    MLXCX_RX_HASH_FIELDS, mltir->mltir_hash_fields);
		break;
	case MLXCX_TIR_DIRECT:
		VERIFY(mltir->mltir_rq != NULL);
		VERIFY(mltir->mltir_rq->mlwq_state & MLXCX_WQ_CREATED);
		ctx->mltirc_inline_rqn = to_be24(mltir->mltir_rq->mlwq_num);
		break;
	default:
		VERIFY(0);
	}

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mltir->mltir_state |= MLXCX_TIR_CREATED;
		mltir->mltir_num = from_be24(out.mlxo_create_tir_tirn);
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_destroy_tir(mlxcx_t *mlxp, mlxcx_tir_t *mltir)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_destroy_tir_in_t in;
	mlxcx_cmd_destroy_tir_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	VERIFY(mltir->mltir_state & MLXCX_TIR_CREATED);
	VERIFY0(mltir->mltir_state & MLXCX_TIR_DESTROYED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_destroy_tir_head,
	    MLXCX_OP_DESTROY_TIR, 0);

	in.mlxi_destroy_tir_tirn = to_be24(mltir->mltir_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mltir->mltir_state |= MLXCX_TIR_DESTROYED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_create_tis(mlxcx_t *mlxp, mlxcx_tis_t *mltis)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_create_tis_in_t in;
	mlxcx_cmd_create_tis_out_t out;
	mlxcx_tis_ctx_t *ctx;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	VERIFY0(mltis->mltis_state & MLXCX_TIS_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_create_tis_head,
	    MLXCX_OP_CREATE_TIS, 0);

	ctx = &in.mlxi_create_tis_context;
	ctx->mltisc_transport_domain = to_be24(mltis->mltis_tdom->mltd_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mltis->mltis_state |= MLXCX_TIS_CREATED;
		mltis->mltis_num = from_be24(out.mlxo_create_tis_tisn);
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_destroy_tis(mlxcx_t *mlxp, mlxcx_tis_t *mltis)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_destroy_tis_in_t in;
	mlxcx_cmd_destroy_tis_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	VERIFY(mltis->mltis_state & MLXCX_TIR_CREATED);
	VERIFY0(mltis->mltis_state & MLXCX_TIR_DESTROYED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_destroy_tis_head,
	    MLXCX_OP_DESTROY_TIS, 0);

	in.mlxi_destroy_tis_tisn = to_be24(mltis->mltis_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mltis->mltis_state |= MLXCX_TIS_DESTROYED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_create_flow_table(mlxcx_t *mlxp, mlxcx_flow_table_t *mlft)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_create_flow_table_in_t in;
	mlxcx_cmd_create_flow_table_out_t out;
	mlxcx_flow_table_ctx_t *ctx;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlft->mlft_mtx));
	VERIFY0(mlft->mlft_state & MLXCX_FLOW_TABLE_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_create_flow_table_head,
	    MLXCX_OP_CREATE_FLOW_TABLE, 0);

	in.mlxi_create_flow_table_vport_number =
	    to_be16(mlft->mlft_port->mlp_num);
	in.mlxi_create_flow_table_table_type = mlft->mlft_type;
	ctx = &in.mlxi_create_flow_table_context;
	ctx->mlftc_log_size = mlft->mlft_entshift;
	ctx->mlftc_level = mlft->mlft_level;

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlft->mlft_num = from_be24(out.mlxo_create_flow_table_table_id);
		mlft->mlft_state |= MLXCX_FLOW_TABLE_CREATED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_destroy_flow_table(mlxcx_t *mlxp, mlxcx_flow_table_t *mlft)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_destroy_flow_table_in_t in;
	mlxcx_cmd_destroy_flow_table_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlft->mlft_mtx));
	VERIFY(mlft->mlft_state & MLXCX_FLOW_TABLE_CREATED);
	VERIFY0(mlft->mlft_state & MLXCX_FLOW_TABLE_DESTROYED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_destroy_flow_table_head,
	    MLXCX_OP_DESTROY_FLOW_TABLE, 0);

	in.mlxi_destroy_flow_table_vport_number =
	    to_be16(mlft->mlft_port->mlp_num);
	in.mlxi_destroy_flow_table_table_type = mlft->mlft_type;
	in.mlxi_destroy_flow_table_table_id = to_be24(mlft->mlft_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlft->mlft_state |= MLXCX_FLOW_TABLE_DESTROYED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_set_flow_table_root(mlxcx_t *mlxp, mlxcx_flow_table_t *mlft)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_set_flow_table_root_in_t in;
	mlxcx_cmd_set_flow_table_root_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlft->mlft_mtx));
	VERIFY(mlft->mlft_state & MLXCX_FLOW_TABLE_CREATED);
	VERIFY0(mlft->mlft_state & MLXCX_FLOW_TABLE_DESTROYED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_set_flow_table_root_head,
	    MLXCX_OP_SET_FLOW_TABLE_ROOT, 0);

	in.mlxi_set_flow_table_root_vport_number =
	    to_be16(mlft->mlft_port->mlp_num);
	in.mlxi_set_flow_table_root_table_type = mlft->mlft_type;
	in.mlxi_set_flow_table_root_table_id = to_be24(mlft->mlft_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlft->mlft_state |= MLXCX_FLOW_TABLE_ROOT;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_create_flow_group(mlxcx_t *mlxp, mlxcx_flow_group_t *mlfg)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_create_flow_group_in_t in;
	mlxcx_cmd_create_flow_group_out_t out;
	boolean_t ret;
	const mlxcx_flow_table_t *mlft;
	mlxcx_flow_header_match_t *hdrs;
	mlxcx_flow_params_match_t *params;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlft = mlfg->mlfg_table;
	ASSERT(mutex_owned(&mlft->mlft_mtx));
	VERIFY(mlft->mlft_state & MLXCX_FLOW_TABLE_CREATED);
	VERIFY0(mlft->mlft_state & MLXCX_FLOW_TABLE_DESTROYED);
	VERIFY0(mlfg->mlfg_state & MLXCX_FLOW_GROUP_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_create_flow_group_head,
	    MLXCX_OP_CREATE_FLOW_GROUP, 0);

	in.mlxi_create_flow_group_vport_number =
	    to_be16(mlft->mlft_port->mlp_num);
	in.mlxi_create_flow_group_table_type = mlft->mlft_type;
	in.mlxi_create_flow_group_table_id = to_be24(mlft->mlft_num);
	in.mlxi_create_flow_group_start_flow_index =
	    to_be32(mlfg->mlfg_start_idx);
	in.mlxi_create_flow_group_end_flow_index =
	    to_be32(mlfg->mlfg_start_idx + (mlfg->mlfg_size - 1));

	hdrs = &in.mlxi_create_flow_group_match_criteria.mlfm_outer_headers;
	params = &in.mlxi_create_flow_group_match_criteria.mlfm_misc_parameters;
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_SMAC) {
		in.mlxi_create_flow_group_match_criteria_en |=
		    MLXCX_FLOW_GROUP_MATCH_OUTER_HDRS;
		(void) memset(&hdrs->mlfh_smac, 0xff, sizeof (hdrs->mlfh_smac));
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_DMAC) {
		in.mlxi_create_flow_group_match_criteria_en |=
		    MLXCX_FLOW_GROUP_MATCH_OUTER_HDRS;
		(void) memset(&hdrs->mlfh_dmac, 0xff, sizeof (hdrs->mlfh_dmac));
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_VLAN) {
		in.mlxi_create_flow_group_match_criteria_en |=
		    MLXCX_FLOW_GROUP_MATCH_OUTER_HDRS;
		set_bit24(&hdrs->mlfh_tcp_ip_flags, MLXCX_FLOW_HDR_CVLAN_TAG);
		set_bit24(&hdrs->mlfh_tcp_ip_flags, MLXCX_FLOW_HDR_SVLAN_TAG);
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_VID) {
		ASSERT(mlfg->mlfg_mask & MLXCX_FLOW_MATCH_VLAN);
		set_bits16(&hdrs->mlfh_first_vid_flags,
		    MLXCX_FLOW_HDR_FIRST_VID, UINT16_MAX);
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_IP_VER) {
		in.mlxi_create_flow_group_match_criteria_en |=
		    MLXCX_FLOW_GROUP_MATCH_OUTER_HDRS;
		set_bits24(&hdrs->mlfh_tcp_ip_flags, MLXCX_FLOW_HDR_IP_VERSION,
		    UINT32_MAX);
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_SRCIP) {
		ASSERT(mlfg->mlfg_mask & MLXCX_FLOW_MATCH_IP_VER);
		(void) memset(&hdrs->mlfh_src_ip, 0xff,
		    sizeof (hdrs->mlfh_src_ip));
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_DSTIP) {
		ASSERT(mlfg->mlfg_mask & MLXCX_FLOW_MATCH_IP_VER);
		(void) memset(&hdrs->mlfh_src_ip, 0xff,
		    sizeof (hdrs->mlfh_dst_ip));
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_IP_PROTO) {
		in.mlxi_create_flow_group_match_criteria_en |=
		    MLXCX_FLOW_GROUP_MATCH_OUTER_HDRS;
		hdrs->mlfh_ip_protocol = UINT8_MAX;
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_SRCIP) {
		ASSERT(mlfg->mlfg_mask & MLXCX_FLOW_MATCH_IP_VER);
		(void) memset(&hdrs->mlfh_src_ip, 0xff,
		    sizeof (hdrs->mlfh_src_ip));
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_DSTIP) {
		ASSERT(mlfg->mlfg_mask & MLXCX_FLOW_MATCH_IP_VER);
		(void) memset(&hdrs->mlfh_src_ip, 0xff,
		    sizeof (hdrs->mlfh_dst_ip));
	}

	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_SQN) {
		in.mlxi_create_flow_group_match_criteria_en |=
		    MLXCX_FLOW_GROUP_MATCH_MISC_PARAMS;
		params->mlfp_source_sqn = to_be24(UINT32_MAX);
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_VXLAN) {
		in.mlxi_create_flow_group_match_criteria_en |=
		    MLXCX_FLOW_GROUP_MATCH_MISC_PARAMS;
		params->mlfp_vxlan_vni = to_be24(UINT32_MAX);
	}

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlfg->mlfg_state |= MLXCX_FLOW_GROUP_CREATED;
		mlfg->mlfg_num = from_be24(out.mlxo_create_flow_group_group_id);
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_destroy_flow_group(mlxcx_t *mlxp, mlxcx_flow_group_t *mlfg)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_destroy_flow_group_in_t in;
	mlxcx_cmd_destroy_flow_group_out_t out;
	boolean_t ret;
	const mlxcx_flow_table_t *mlft;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlft = mlfg->mlfg_table;
	ASSERT(mutex_owned(&mlft->mlft_mtx));
	VERIFY(mlft->mlft_state & MLXCX_FLOW_TABLE_CREATED);
	VERIFY0(mlft->mlft_state & MLXCX_FLOW_TABLE_DESTROYED);
	VERIFY(mlfg->mlfg_state & MLXCX_FLOW_GROUP_CREATED);
	VERIFY0(mlfg->mlfg_state & MLXCX_FLOW_GROUP_DESTROYED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_destroy_flow_group_head,
	    MLXCX_OP_DESTROY_FLOW_GROUP, 0);

	in.mlxi_destroy_flow_group_vport_number =
	    to_be16(mlft->mlft_port->mlp_num);
	in.mlxi_destroy_flow_group_table_type = mlft->mlft_type;
	in.mlxi_destroy_flow_group_table_id = to_be24(mlft->mlft_num);
	in.mlxi_destroy_flow_group_group_id = to_be32(mlfg->mlfg_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlfg->mlfg_state |= MLXCX_FLOW_GROUP_DESTROYED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_set_flow_table_entry(mlxcx_t *mlxp, mlxcx_flow_entry_t *mlfe)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_set_flow_table_entry_in_t in;
	mlxcx_cmd_set_flow_table_entry_out_t out;
	boolean_t ret;
	size_t insize;
	mlxcx_flow_entry_ctx_t *ctx;
	const mlxcx_flow_table_t *mlft;
	mlxcx_flow_group_t *mlfg;
	mlxcx_flow_dest_t *d;
	uint_t i;
	mlxcx_flow_header_match_t *hdrs;
	mlxcx_flow_params_match_t *params;
	mlxcx_cmd_set_flow_table_entry_opmod_t opmod;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlft = mlfe->mlfe_table;
	ASSERT(mutex_owned(&mlft->mlft_mtx));
	VERIFY(mlft->mlft_state & MLXCX_FLOW_TABLE_CREATED);
	VERIFY0(mlft->mlft_state & MLXCX_FLOW_TABLE_DESTROYED);

	mlfg = mlfe->mlfe_group;
	VERIFY(mlfg->mlfg_state & MLXCX_FLOW_GROUP_CREATED);
	VERIFY0(mlfg->mlfg_state & MLXCX_FLOW_GROUP_DESTROYED);

	opmod = MLXCX_CMD_FLOW_ENTRY_SET_NEW;
	if (mlfe->mlfe_state & MLXCX_FLOW_ENTRY_CREATED) {
		ASSERT(mlfe->mlfe_state & MLXCX_FLOW_ENTRY_DIRTY);
		opmod = MLXCX_CMD_FLOW_ENTRY_MODIFY;
	}

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_set_flow_table_entry_head,
	    MLXCX_OP_SET_FLOW_TABLE_ENTRY, opmod);

	in.mlxi_set_flow_table_entry_vport_number =
	    to_be16(mlft->mlft_port->mlp_num);
	in.mlxi_set_flow_table_entry_table_type = mlft->mlft_type;
	in.mlxi_set_flow_table_entry_table_id = to_be24(mlft->mlft_num);
	in.mlxi_set_flow_table_entry_flow_index = to_be32(mlfe->mlfe_index);

	if (mlfe->mlfe_state & MLXCX_FLOW_ENTRY_CREATED) {
		set_bit8(&in.mlxi_set_flow_table_entry_modify_bitmask,
		    MLXCX_CMD_FLOW_ENTRY_SET_ACTION);
		set_bit8(&in.mlxi_set_flow_table_entry_modify_bitmask,
		    MLXCX_CMD_FLOW_ENTRY_SET_DESTINATION);
	}

	ctx = &in.mlxi_set_flow_table_entry_context;
	ctx->mlfec_group_id = to_be32(mlfg->mlfg_num);

	insize = offsetof(mlxcx_cmd_set_flow_table_entry_in_t,
	    mlxi_set_flow_table_entry_context) +
	    offsetof(mlxcx_flow_entry_ctx_t, mlfec_destination);

	ctx->mlfec_action = to_be16(mlfe->mlfe_action);

	switch (mlfe->mlfe_action) {
	case MLXCX_FLOW_ACTION_ALLOW:
	case MLXCX_FLOW_ACTION_DROP:
		break;
	case MLXCX_FLOW_ACTION_FORWARD:
		ASSERT3U(mlfe->mlfe_ndest, <=, MLXCX_FLOW_MAX_DESTINATIONS);
		ASSERT3U(mlfe->mlfe_ndest, <=,
		    mlxp->mlx_caps->mlc_max_rx_fe_dest);
		ctx->mlfec_destination_list_size = to_be24(mlfe->mlfe_ndest);
		for (i = 0; i < mlfe->mlfe_ndest; ++i) {
			insize += sizeof (mlxcx_flow_dest_t);
			d = &ctx->mlfec_destination[i];
			if (mlfe->mlfe_dest[i].mlfed_tir != NULL) {
				d->mlfd_destination_type = MLXCX_FLOW_DEST_TIR;
				d->mlfd_destination_id = to_be24(
				    mlfe->mlfe_dest[i].mlfed_tir->mltir_num);
			} else if (mlfe->mlfe_dest[i].mlfed_flow != NULL) {
				d->mlfd_destination_type =
				    MLXCX_FLOW_DEST_FLOW_TABLE;
				d->mlfd_destination_id = to_be24(
				    mlfe->mlfe_dest[i].mlfed_flow->mlft_num);
			} else {
				/* Invalid flow entry destination */
				VERIFY(0);
			}
		}
		break;
	case MLXCX_FLOW_ACTION_COUNT:
		/* We don't support count actions yet. */
		VERIFY(0);
		break;
	case MLXCX_FLOW_ACTION_ENCAP:
	case MLXCX_FLOW_ACTION_DECAP:
		/* We don't support encap/decap actions yet. */
		VERIFY(0);
		break;
	}

	hdrs = &ctx->mlfec_match_value.mlfm_outer_headers;
	params = &ctx->mlfec_match_value.mlfm_misc_parameters;
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_SMAC) {
		bcopy(mlfe->mlfe_smac, hdrs->mlfh_smac,
		    sizeof (hdrs->mlfh_smac));
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_DMAC) {
		bcopy(mlfe->mlfe_dmac, hdrs->mlfh_dmac,
		    sizeof (hdrs->mlfh_dmac));
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_VLAN) {
		switch (mlfe->mlfe_vlan_type) {
		case MLXCX_VLAN_TYPE_CVLAN:
			set_bit24(&hdrs->mlfh_tcp_ip_flags,
			    MLXCX_FLOW_HDR_CVLAN_TAG);
			break;
		case MLXCX_VLAN_TYPE_SVLAN:
			set_bit24(&hdrs->mlfh_tcp_ip_flags,
			    MLXCX_FLOW_HDR_SVLAN_TAG);
			break;
		default:
			break;
		}
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_VID) {
		ASSERT(mlfg->mlfg_mask & MLXCX_FLOW_MATCH_VLAN);
		set_bits16(&hdrs->mlfh_first_vid_flags,
		    MLXCX_FLOW_HDR_FIRST_VID, mlfe->mlfe_vid);
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_IP_VER) {
		set_bits24(&hdrs->mlfh_tcp_ip_flags, MLXCX_FLOW_HDR_IP_VERSION,
		    mlfe->mlfe_ip_version);
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_SRCIP) {
		ASSERT(mlfg->mlfg_mask & MLXCX_FLOW_MATCH_IP_VER);
		bcopy(mlfe->mlfe_srcip, hdrs->mlfh_src_ip,
		    sizeof (hdrs->mlfh_src_ip));
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_DSTIP) {
		ASSERT(mlfg->mlfg_mask & MLXCX_FLOW_MATCH_IP_VER);
		bcopy(mlfe->mlfe_dstip, hdrs->mlfh_src_ip,
		    sizeof (hdrs->mlfh_dst_ip));
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_IP_PROTO) {
		hdrs->mlfh_ip_protocol = mlfe->mlfe_ip_proto;
	}

	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_SQN) {
		params->mlfp_source_sqn = to_be24(mlfe->mlfe_sqn);
	}
	if (mlfg->mlfg_mask & MLXCX_FLOW_MATCH_VXLAN) {
		params->mlfp_vxlan_vni = to_be24(mlfe->mlfe_vxlan_vni);
	}

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, insize, &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlfe->mlfe_state |= MLXCX_FLOW_ENTRY_CREATED;
		mlfe->mlfe_state &= ~MLXCX_FLOW_ENTRY_DIRTY;
		mlfg->mlfg_state |= MLXCX_FLOW_GROUP_BUSY;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_delete_flow_table_entry(mlxcx_t *mlxp, mlxcx_flow_entry_t *mlfe)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_delete_flow_table_entry_in_t in;
	mlxcx_cmd_delete_flow_table_entry_out_t out;
	boolean_t ret;
	const mlxcx_flow_table_t *mlft;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlft = mlfe->mlfe_table;
	ASSERT(mutex_owned(&mlft->mlft_mtx));
	VERIFY(mlft->mlft_state & MLXCX_FLOW_TABLE_CREATED);
	VERIFY0(mlft->mlft_state & MLXCX_FLOW_TABLE_DESTROYED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_delete_flow_table_entry_head,
	    MLXCX_OP_DELETE_FLOW_TABLE_ENTRY, 0);

	in.mlxi_delete_flow_table_entry_vport_number =
	    to_be16(mlft->mlft_port->mlp_num);
	in.mlxi_delete_flow_table_entry_table_type = mlft->mlft_type;
	in.mlxi_delete_flow_table_entry_table_id = to_be24(mlft->mlft_num);
	in.mlxi_delete_flow_table_entry_flow_index = to_be32(mlfe->mlfe_index);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		/*
		 * Note that flow entries have a different lifecycle to most
		 * other things we create -- we have to be able to re-use them
		 * after they have been deleted, since they exist at a fixed
		 * position in their flow table.
		 *
		 * So we clear the CREATED bit here for them to let us call
		 * create_flow_table_entry() on the same entry again later.
		 */
		mlfe->mlfe_state &= ~MLXCX_FLOW_ENTRY_CREATED;
		mlfe->mlfe_state |= MLXCX_FLOW_ENTRY_DELETED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_create_sq(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_create_sq_in_t in;
	mlxcx_cmd_create_sq_out_t out;
	boolean_t ret;
	mlxcx_sq_ctx_t *ctx;
	size_t rem, insize;
	const ddi_dma_cookie_t *c;
	uint64_t pa, npages;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));
	VERIFY3U(mlwq->mlwq_type, ==, MLXCX_WQ_TYPE_SENDQ);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_ALLOC);
	VERIFY0(mlwq->mlwq_state & MLXCX_WQ_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_create_sq_head,
	    MLXCX_OP_CREATE_SQ, 0);

	ctx = &in.mlxi_create_sq_context;

	set_bit32(&ctx->mlsqc_flags, MLXCX_SQ_FLAGS_RLKEY);
	set_bit32(&ctx->mlsqc_flags, MLXCX_SQ_FLAGS_FLUSH_IN_ERROR);
	set_bits32(&ctx->mlsqc_flags, MLXCX_SQ_MIN_WQE_INLINE,
	    mlwq->mlwq_inline_mode);
	ctx->mlsqc_cqn = to_be24(mlwq->mlwq_cq->mlcq_num);

	VERIFY(mlwq->mlwq_tis != NULL);
	ctx->mlsqc_tis_lst_sz = to_be16(1);
	ctx->mlsqc_tis_num = to_be24(mlwq->mlwq_tis->mltis_num);

	set_bits32(&ctx->mlsqc_wq.mlwqc_flags, MLXCX_WORKQ_CTX_TYPE,
	    MLXCX_WORKQ_TYPE_CYCLIC);
	ctx->mlsqc_wq.mlwqc_pd = to_be24(mlwq->mlwq_pd->mlpd_num);
	ctx->mlsqc_wq.mlwqc_uar_page = to_be24(mlwq->mlwq_uar->mlu_num);
	ctx->mlsqc_wq.mlwqc_log_wq_sz = mlwq->mlwq_entshift;
	ctx->mlsqc_wq.mlwqc_log_wq_stride = MLXCX_SENDQ_STRIDE_SHIFT;

	c = mlxcx_dma_cookie_one(&mlwq->mlwq_doorbell_dma);
	ctx->mlsqc_wq.mlwqc_dbr_addr = to_be64(c->dmac_laddress);
	ASSERT3U(c->dmac_size, >=, sizeof (mlxcx_workq_doorbell_t));

	npages = 0;
	c = NULL;
	while ((c = mlxcx_dma_cookie_iter(&mlwq->mlwq_dma, c)) != NULL) {
		pa = c->dmac_laddress;
		rem = c->dmac_size;
		while (rem > 0) {
			ASSERT3U(pa & 0xfff, ==, 0);
			ASSERT3U(rem, >=, MLXCX_HW_PAGE_SIZE);
			ctx->mlsqc_wq.mlwqc_pas[npages++] = to_be64(pa);
			rem -= MLXCX_HW_PAGE_SIZE;
			pa += MLXCX_HW_PAGE_SIZE;
		}
	}
	ASSERT3U(npages, <=, MLXCX_WORKQ_CTX_MAX_ADDRESSES);

	insize = offsetof(mlxcx_cmd_create_sq_in_t, mlxi_create_sq_context) +
	    offsetof(mlxcx_sq_ctx_t, mlsqc_wq) +
	    offsetof(mlxcx_workq_ctx_t, mlwqc_pas) +
	    sizeof (uint64_t) * npages;

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, insize, &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlwq->mlwq_state |= MLXCX_WQ_CREATED;
		mlwq->mlwq_num = from_be24(out.mlxo_create_sq_sqn);
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_start_sq(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_modify_sq_in_t in;
	mlxcx_cmd_modify_sq_out_t out;
	boolean_t ret;
	ddi_fm_error_t err;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));
	ASSERT(mlwq->mlwq_cq != NULL);

	VERIFY(mlwq->mlwq_state & MLXCX_WQ_ALLOC);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_CREATED);
	VERIFY0(mlwq->mlwq_state & MLXCX_WQ_STARTED);

	/*
	 * Before starting the queue, we have to be sure that it is
	 * empty and the doorbell and counters are set to 0.
	 */
	ASSERT(mutex_owned(&mlwq->mlwq_cq->mlcq_mtx));
	ASSERT(list_is_empty(&mlwq->mlwq_cq->mlcq_buffers));
	ASSERT(list_is_empty(&mlwq->mlwq_cq->mlcq_buffers_b));

	mlwq->mlwq_doorbell->mlwqd_recv_counter = to_be16(0);
	MLXCX_DMA_SYNC(mlwq->mlwq_doorbell_dma, DDI_DMA_SYNC_FORDEV);
	ddi_fm_dma_err_get(mlwq->mlwq_doorbell_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status != DDI_FM_OK)
		return (B_FALSE);
	mlwq->mlwq_pc = 0;

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_modify_sq_head,
	    MLXCX_OP_MODIFY_SQ, 0);

	in.mlxi_modify_sq_sqn = to_be24(mlwq->mlwq_num);

	/* From state */
	set_bits8(&in.mlxi_modify_sq_state, MLXCX_CMD_MODIFY_SQ_STATE,
	    MLXCX_SQ_STATE_RST);
	/* To state */
	set_bits32(&in.mlxi_modify_sq_context.mlsqc_flags, MLXCX_SQ_STATE,
	    MLXCX_SQ_STATE_RDY);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlwq->mlwq_state |= MLXCX_WQ_STARTED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_stop_sq(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_modify_sq_in_t in;
	mlxcx_cmd_modify_sq_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_ALLOC);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_CREATED);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_STARTED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_modify_sq_head,
	    MLXCX_OP_MODIFY_SQ, 0);

	in.mlxi_modify_sq_sqn = to_be24(mlwq->mlwq_num);

	/* From state */
	set_bits8(&in.mlxi_modify_sq_state, MLXCX_CMD_MODIFY_SQ_STATE,
	    MLXCX_SQ_STATE_RDY);
	/* To state */
	set_bits32(&in.mlxi_modify_sq_context.mlsqc_flags, MLXCX_SQ_STATE,
	    MLXCX_SQ_STATE_RST);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlwq->mlwq_state &= ~MLXCX_WQ_STARTED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_destroy_sq(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_destroy_sq_in_t in;
	mlxcx_cmd_destroy_sq_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_ALLOC);
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_CREATED);
	VERIFY0(mlwq->mlwq_state & MLXCX_WQ_STARTED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_destroy_sq_head,
	    MLXCX_OP_DESTROY_SQ, 0);

	in.mlxi_destroy_sq_sqn = to_be24(mlwq->mlwq_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlwq->mlwq_state |= MLXCX_WQ_DESTROYED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_create_rqt(mlxcx_t *mlxp, mlxcx_rqtable_t *mlrqt)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_create_rqt_in_t in;
	mlxcx_cmd_create_rqt_out_t out;
	mlxcx_rqtable_ctx_t *ctx;
	boolean_t ret;
	uint_t i;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	VERIFY0(mlrqt->mlrqt_state & MLXCX_RQT_CREATED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_create_rqt_head,
	    MLXCX_OP_CREATE_RQT, 0);

	ctx = &in.mlxi_create_rqt_context;
	ASSERT3U(mlrqt->mlrqt_max, <=, MLXCX_RQT_MAX_RQ_REFS);
	ASSERT3U(mlrqt->mlrqt_max, <=, mlxp->mlx_caps->mlc_max_rqt_size);
	ctx->mlrqtc_max_size = to_be16(mlrqt->mlrqt_max);
	ctx->mlrqtc_actual_size = to_be16(mlrqt->mlrqt_used);
	for (i = 0; i < mlrqt->mlrqt_used; ++i) {
		ctx->mlrqtc_rqref[i].mlrqtr_rqn = to_be24(
		    mlrqt->mlrqt_rq[i]->mlwq_num);
	}

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlrqt->mlrqt_num = from_be24(out.mlxo_create_rqt_rqtn);
		mlrqt->mlrqt_state |= MLXCX_RQT_CREATED;
		mlrqt->mlrqt_state &= ~MLXCX_RQT_DIRTY;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_destroy_rqt(mlxcx_t *mlxp, mlxcx_rqtable_t *mlrqt)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_destroy_rqt_in_t in;
	mlxcx_cmd_destroy_rqt_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	VERIFY(mlrqt->mlrqt_state & MLXCX_RQT_CREATED);
	VERIFY0(mlrqt->mlrqt_state & MLXCX_RQT_DESTROYED);

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_destroy_rqt_head,
	    MLXCX_OP_DESTROY_RQT, 0);

	in.mlxi_destroy_rqt_rqtn = to_be24(mlrqt->mlrqt_num);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	if (ret) {
		mlrqt->mlrqt_state |= MLXCX_RQT_DESTROYED;
	}
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

boolean_t
mlxcx_cmd_set_int_mod(mlxcx_t *mlxp, uint_t intr, uint_t min_delay)
{
	mlxcx_cmd_t cmd;
	mlxcx_cmd_config_int_mod_in_t in;
	mlxcx_cmd_config_int_mod_out_t out;
	boolean_t ret;

	bzero(&in, sizeof (in));
	bzero(&out, sizeof (out));

	mlxcx_cmd_init(mlxp, &cmd);
	mlxcx_cmd_in_header_init(&cmd, &in.mlxi_config_int_mod_head,
	    MLXCX_OP_CONFIG_INT_MODERATION, MLXCX_CMD_CONFIG_INT_MOD_WRITE);

	in.mlxi_config_int_mod_int_vector = to_be16(intr);
	in.mlxi_config_int_mod_min_delay = to_be16(min_delay);

	if (!mlxcx_cmd_send(mlxp, &cmd, &in, sizeof (in), &out, sizeof (out))) {
		mlxcx_cmd_fini(mlxp, &cmd);
		return (B_FALSE);
	}
	mlxcx_cmd_wait(&cmd);

	ret = mlxcx_cmd_evaluate(mlxp, &cmd);
	mlxcx_cmd_fini(mlxp, &cmd);
	return (ret);
}

/*
 * CTASSERTs here are for the structs in mlxcx_reg.h, to check they match
 * against offsets from the PRM.
 *
 * They're not in the header file, to avoid them being used by multiple .c
 * files.
 */

CTASSERT(offsetof(mlxcx_eventq_ent_t, mleqe_unknown_data) == 0x20);
CTASSERT(offsetof(mlxcx_eventq_ent_t, mleqe_signature) == 0x3c + 2);
CTASSERT(sizeof (mlxcx_eventq_ent_t) == 64);

CTASSERT(offsetof(mlxcx_completionq_error_ent_t, mlcqee_byte_cnt) == 0x2C);
CTASSERT(offsetof(mlxcx_completionq_error_ent_t, mlcqee_wqe_opcode) == 0x38);

CTASSERT(sizeof (mlxcx_completionq_error_ent_t) ==
    sizeof (mlxcx_completionq_ent_t));
CTASSERT(sizeof (mlxcx_wqe_control_seg_t) == (1 << 4));

CTASSERT(offsetof(mlxcx_wqe_eth_seg_t, mles_inline_headers) == 0x0e);
CTASSERT(sizeof (mlxcx_wqe_eth_seg_t) == (1 << 5));

CTASSERT(sizeof (mlxcx_wqe_data_seg_t) == (1 << 4));

CTASSERT(sizeof (mlxcx_sendq_ent_t) == (1 << MLXCX_SENDQ_STRIDE_SHIFT));

CTASSERT(sizeof (mlxcx_sendq_bf_t) == (1 << MLXCX_SENDQ_STRIDE_SHIFT));

CTASSERT(sizeof (mlxcx_sendq_extra_ent_t) == (1 << MLXCX_SENDQ_STRIDE_SHIFT));

CTASSERT(sizeof (mlxcx_recvq_ent_t) == (1 << MLXCX_RECVQ_STRIDE_SHIFT));

CTASSERT(offsetof(mlxcx_workq_ctx_t, mlwqc_dbr_addr) == 0x10);
CTASSERT(offsetof(mlxcx_workq_ctx_t, mlwqc_pas) == 0xc0);

CTASSERT(offsetof(mlxcx_rq_ctx_t, mlrqc_cqn) == 0x09);
CTASSERT(offsetof(mlxcx_rq_ctx_t, mlrqc_wq) == 0x30);

CTASSERT(offsetof(mlxcx_sq_ctx_t, mlsqc_cqn) == 0x09);
CTASSERT(offsetof(mlxcx_sq_ctx_t, mlsqc_tis_lst_sz) == 0x20);
CTASSERT(offsetof(mlxcx_sq_ctx_t, mlsqc_tis_num) == 0x2d);
CTASSERT(offsetof(mlxcx_sq_ctx_t, mlsqc_wq) == 0x30);

CTASSERT(sizeof (mlxcx_tis_ctx_t) == 0xa0);
CTASSERT(offsetof(mlxcx_tis_ctx_t, mltisc_transport_domain) == 0x25);

CTASSERT(offsetof(mlxcx_rqtable_ctx_t, mlrqtc_max_size) == 0x16);
CTASSERT(offsetof(mlxcx_rqtable_ctx_t, mlrqtc_rqref) == 0xF0);

CTASSERT(offsetof(mlxcx_cmd_create_eq_in_t, mlxi_create_eq_event_bitmask) ==
    0x58);
CTASSERT(offsetof(mlxcx_cmd_create_eq_in_t, mlxi_create_eq_pas) == 0x110);
CTASSERT(offsetof(mlxcx_cmd_create_eq_in_t, mlxi_create_eq_context) == 0x10);

CTASSERT(offsetof(mlxcx_cmd_create_tir_in_t, mlxi_create_tir_context) == 0x20);

CTASSERT(offsetof(mlxcx_cmd_create_tis_in_t, mlxi_create_tis_context) == 0x20);

CTASSERT(offsetof(mlxcx_cmd_query_special_ctxs_out_t,
    mlxo_query_special_ctxs_resd_lkey) == 0x0c);

CTASSERT(offsetof(mlxcx_cmd_query_cq_out_t, mlxo_query_cq_context) == 0x10);
CTASSERT(offsetof(mlxcx_cmd_query_cq_out_t, mlxo_query_cq_pas) == 0x110);

CTASSERT(offsetof(mlxcx_cmd_query_rq_out_t, mlxo_query_rq_context) == 0x20);

CTASSERT(offsetof(mlxcx_cmd_create_sq_in_t, mlxi_create_sq_context) == 0x20);

CTASSERT(offsetof(mlxcx_cmd_modify_sq_in_t, mlxi_modify_sq_context) == 0x20);

CTASSERT(offsetof(mlxcx_cmd_query_sq_out_t, mlxo_query_sq_context) == 0x20);

CTASSERT(offsetof(mlxcx_cmd_create_rqt_in_t, mlxi_create_rqt_context) == 0x20);

CTASSERT(offsetof(mlxcx_reg_pmtu_t, mlrd_pmtu_oper_mtu) == 0x0C);

CTASSERT(sizeof (mlxcx_reg_ptys_t) == 64);
CTASSERT(offsetof(mlxcx_reg_ptys_t, mlrd_ptys_ext_proto_cap) == 0x08);
CTASSERT(offsetof(mlxcx_reg_ptys_t, mlrd_ptys_proto_cap) == 0x0c);
CTASSERT(offsetof(mlxcx_reg_ptys_t, mlrd_ptys_ext_proto_admin) == 0x14);
CTASSERT(offsetof(mlxcx_reg_ptys_t, mlrd_ptys_proto_admin) == 0x18);
CTASSERT(offsetof(mlxcx_reg_ptys_t, mlrd_ptys_proto_partner_advert) == 0x30);

CTASSERT(offsetof(mlxcx_reg_mcia_t, mlrd_mcia_data) == 0x10);

CTASSERT(offsetof(mlxcx_ppcnt_ieee_802_3_t,
    mlppc_ieee_802_3_in_range_len_err) == 0x50);
CTASSERT(offsetof(mlxcx_ppcnt_ieee_802_3_t,
    mlppc_ieee_802_3_pause_tx) == 0x90);

CTASSERT(sizeof (mlxcx_reg_ppcnt_t) == 256);
CTASSERT(offsetof(mlxcx_reg_ppcnt_t, mlrd_ppcnt_data) == 0x08);

CTASSERT(offsetof(mlxcx_cmd_access_register_in_t,
    mlxi_access_register_argument) == 0x0C);
CTASSERT(offsetof(mlxcx_cmd_access_register_in_t,
    mlxi_access_register_data) == 0x10);

CTASSERT(offsetof(mlxcx_cmd_access_register_out_t,
    mlxo_access_register_data) == 0x10);

CTASSERT(sizeof (mlxcx_cmd_set_flow_table_root_in_t) == 64);
CTASSERT(offsetof(mlxcx_cmd_set_flow_table_root_in_t,
    mlxi_set_flow_table_root_table_id) == 0x15);
CTASSERT(offsetof(mlxcx_cmd_set_flow_table_root_in_t,
    mlxi_set_flow_table_root_esw_owner_vhca_id_valid) == 0x1C);
