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

/* Copyright © 2003-2011 Emulex. All rights reserved.  */

/*
 * Header file containing the command structures for Hardware
 */

#ifndef _OCE_HW_H_
#define	_OCE_HW_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#pragma pack(1)

#define	OC_CNA_GEN2			0x2
#define	OC_CNA_GEN3			0x3
#define	DEVID_TIGERSHARK		0x700
#define	DEVID_TOMCAT			0x710

/* PCI CSR offsets */
#define	PCICFG_F1_CSR			0x0 /* F1 for NIC */
#define	PCICFG_SEMAPHORE		0xbc
#define	PCICFG_SOFT_RESET		0x5c
#define	PCICFG_UE_STATUS_HI_MASK	0xac
#define	PCICFG_UE_STATUS_LO_MASK	0xa8
#define	PCICFG_ONLINE0			0xb0
#define	PCICFG_ONLINE1			0xb4
#define	INTR_EN				0x20000000
#define	IMAGE_TRANSFER_SIZE		(32 * 1024) /* 32K at a time */

/* CSR register offsets */
#define	MPU_EP_CONTROL			0
#define	MPU_EP_SEMAPHORE		0xac
#define	PCICFG_INTR_CTRL		0xfc
#define	HOSTINTR_MASK			(1 << 29)
#define	HOSTINTR_PFUNC_SHIFT		26
#define	HOSTINTR_PFUNC_MASK		7

/* POST status reg struct */
#define	POST_STAGE_POWER_ON_RESET	0x00
#define	POST_STAGE_AWAITING_HOST_RDY	0x01
#define	POST_STAGE_HOST_RDY		0x02
#define	POST_STAGE_CHIP_RESET		0x03
#define	POST_STAGE_ARMFW_READY		0xc000
#define	POST_STAGE_ARMFW_UE		0xf000

/* DOORBELL registers */
#define	PD_RXULP_DB			0x0100
#define	PD_TXULP_DB			0x0060
#define	DB_RQ_ID_MASK			0x3FF

#define	PD_CQ_DB			0x0120
#define	PD_EQ_DB			PD_CQ_DB
#define	PD_MPU_MBOX_DB			0x0160
#define	PD_MQ_DB			0x0140

/* EQE completion types */
#define	EQ_MINOR_CODE_COMPLETION 	0x00
#define	EQ_MINOR_CODE_OTHER		0x01
#define	EQ_MAJOR_CODE_COMPLETION 	0x00

/* Link Status field values */
#define	PHY_LINK_FAULT_NONE		0x0
#define	PHY_LINK_FAULT_LOCAL		0x01
#define	PHY_LINK_FAULT_REMOTE		0x02

#define	PHY_LINK_SPEED_ZERO		0x0 /* No link */
#define	PHY_LINK_SPEED_10MBPS		0x1 /* (10 Mbps) */
#define	PHY_LINK_SPEED_100MBPS		0x2 /* (100 Mbps) */
#define	PHY_LINK_SPEED_1GBPS		0x3 /* (1 Gbps) */
#define	PHY_LINK_SPEED_10GBPS		0x4 /* (10 Gbps) */

#define	PHY_LINK_DUPLEX_NONE		0x0
#define	PHY_LINK_DUPLEX_HALF		0x1
#define	PHY_LINK_DUPLEX_FULL		0x2

#define	NTWK_PORT_A			0x0 /* (Port A) */
#define	NTWK_PORT_B			0x1 /* (Port B) */

#define	PHY_LINK_SPEED_ZERO			0x0 /* (No link.) */
#define	PHY_LINK_SPEED_10MBPS		0x1 /* (10 Mbps) */
#define	PHY_LINK_SPEED_100MBPS		0x2 /* (100 Mbps) */
#define	PHY_LINK_SPEED_1GBPS		0x3 /* (1 Gbps) */
#define	PHY_LINK_SPEED_10GBPS		0x4 /* (10 Gbps) */

/* Hardware Address types */
#define	MAC_ADDRESS_TYPE_STORAGE	0x0 /* (Storage MAC Address) */
#define	MAC_ADDRESS_TYPE_NETWORK	0x1 /* (Network MAC Address) */
#define	MAC_ADDRESS_TYPE_PD		0x2 /* (Protection Domain MAC Addr) */
#define	MAC_ADDRESS_TYPE_MANAGEMENT	0x3 /* (Management MAC Address) */
#define	MAC_ADDRESS_TYPE_FCOE		0x4 /* (FCoE MAC Address) */

/* CREATE_IFACE capability and cap_en flags */
#define	MBX_RX_IFACE_FLAGS_RSS		0x4
#define	MBX_RX_IFACE_FLAGS_PROMISCUOUS	0x8
#define	MBX_RX_IFACE_FLAGS_BROADCAST 	0x10
#define	MBX_RX_IFACE_FLAGS_UNTAGGED	0x20
#define	MBX_RX_IFACE_FLAGS_ULP		0x40
#define	MBX_RX_IFACE_FLAGS_VLAN_PROMISCUOUS	0x80
#define	MBX_RX_IFACE_FLAGS_VLAN			0x100
#define	MBX_RX_IFACE_FLAGS_MCAST_PROMISCUOUS	0x200
#define	MBX_RX_IFACE_FLAGS_PASS_L2	0x400
#define	MBX_RX_IFACE_FLAGS_PASS_L3L4	0x800

#define	MQ_RING_CONTEXT_SIZE_16		0x5 /* (16 entries) */
#define	MQ_RING_CONTEXT_SIZE_32		0x6 /* (32 entries) */
#define	MQ_RING_CONTEXT_SIZE_64		0x7 /* (64 entries) */
#define	MQ_RING_CONTEXT_SIZE_128	0x8 /* (128 entries) */


#define	MBX_DB_READY_BIT		0x1
#define	MBX_DB_HI_BIT			0x2
#define	ASYNC_EVENT_CODE_LINK_STATE	0x1
#define	ASYNC_EVENT_LINK_UP		0x1
#define	ASYNC_EVENT_LINK_DOWN		0x0

/* port link_status */
#define	ASYNC_EVENT_LOGICAL		0x02

/* Logical Link Status */
#define	NTWK_LOGICAL_LINK_DOWN		0
#define	NTWK_LOGICAL_LINK_UP		1

/* Rx filter bits */
#define	NTWK_RX_FILTER_IP_CKSUM 	0x1
#define	NTWK_RX_FILTER_TCP_CKSUM	0x2
#define	NTWK_RX_FILTER_UDP_CKSUM	0x4
#define	NTWK_RX_FILTER_STRIP_CRC	0x8

/* max SGE per mbx */
#define	MAX_MBX_SGE			19

/* physical address structure to be used in MBX */
struct phys_addr {
	/* dw0 */
	uint32_t lo;
	/* dw1 */
	uint32_t hi;
};

typedef union pcicfg_intr_ctl_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t winselect:2;
		uint32_t hostintr:1;
		uint32_t pfnum:3;
		uint32_t vf_cev_int_line_en:1;
		uint32_t winaddr:23;
		uint32_t membarwinen:1;
#else
		uint32_t membarwinen:1;
		uint32_t winaddr:23;
		uint32_t vf_cev_int_line_en:1;
		uint32_t pfnum:3;
		uint32_t hostintr:1;
		uint32_t winselect:2;
#endif
	} bits;
}pcicfg_intr_ctl_t;

typedef union  pcicfg_semaphore_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t rsvd:31;
		uint32_t lock:1;
#else
		uint32_t lock:1;
		uint32_t rsvd:31;
#endif
	}bits;
}pcicfg_semaphore_t;

typedef union pcicfg_soft_reset_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t nec_ll_rcvdetect:8;
		uint32_t dbg_all_reqs_62_49:14;
		uint32_t scratchpad0:1;
		uint32_t exception_oe:1;
		uint32_t soft_reset:1;
		uint32_t rsvd0:7;
#else
		uint32_t rsvd0:7;
		uint32_t soft_reset:1;
		uint32_t exception_oe:1;
		uint32_t scratchpad0:1;
		uint32_t dbg_all_reqs_62_49:14;
		uint32_t nec_ll_rcvdetect:8;
#endif
	}bits;
}pcicfg_soft_reset_t;

typedef union pcicfg_online1_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t host8_online:1;
		uint32_t host7_online:1;
		uint32_t host6_online:1;
		uint32_t host5_online:1;
		uint32_t host4_online:1;
		uint32_t host3_online:1;
		uint32_t host2_online:1;
		uint32_t ipc_online:1;
		uint32_t arm_online:1;
		uint32_t txp_online:1;
		uint32_t xaui_online:1;
		uint32_t rxpp_online:1;
		uint32_t txpb_online:1;
		uint32_t rr_online:1;
		uint32_t pmem_online:1;
		uint32_t pctl1_online:1;
		uint32_t pctl0_online:1;
		uint32_t pcs1online_online:1;
		uint32_t mpu_iram_online:1;
		uint32_t pcs0online_online:1;
		uint32_t mgmt_mac_online:1;
		uint32_t lpcmemhost_online:1;
#else
		uint32_t lpcmemhost_online:1;
		uint32_t mgmt_mac_online:1;
		uint32_t pcs0online_online:1;
		uint32_t mpu_iram_online:1;
		uint32_t pcs1online_online:1;
		uint32_t pctl0_online:1;
		uint32_t pctl1_online:1;
		uint32_t pmem_online:1;
		uint32_t rr_online:1;
		uint32_t txpb_online:1;
		uint32_t rxpp_online:1;
		uint32_t xaui_online:1;
		uint32_t txp_online:1;
		uint32_t arm_online:1;
		uint32_t ipc_online:1;
		uint32_t host2_online:1;
		uint32_t host3_online:1;
		uint32_t host4_online:1;
		uint32_t host5_online:1;
		uint32_t host6_online:1;
		uint32_t host7_online:1;
		uint32_t host8_online:1;
#endif
	}bits;
}pcicfg_online1_t;

typedef union mpu_ep_semaphore_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t error:1;
		uint32_t backup_fw:1;
		uint32_t iscsi_no_ip:1;
		uint32_t iscsi_ip_conflict:1;
		uint32_t option_rom_installed:1;
		uint32_t iscsi_drv_loaded:1;
		uint32_t rsvd0:10;
		uint32_t stage:16;
#else
		uint32_t stage:16;
		uint32_t rsvd0:10;
		uint32_t iscsi_drv_loaded:1;
		uint32_t option_rom_installed:1;
		uint32_t iscsi_ip_conflict:1;
		uint32_t iscsi_no_ip:1;
		uint32_t backup_fw:1;
		uint32_t error:1;
#endif
	}bits;
}mpu_ep_semaphore_t;

typedef union mpu_ep_control_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t cpu_reset:1;
		uint32_t rsvd1:15;
		uint32_t ep_ram_init_status:1;
		uint32_t rsvd0:12;
		uint32_t m2_rxpbuf:1;
		uint32_t m1_rxpbuf:1;
		uint32_t m0_rxpbuf:1;
#else
		uint32_t m0_rxpbuf:1;
		uint32_t m1_rxpbuf:1;
		uint32_t m2_rxpbuf:1;
		uint32_t rsvd0:12;
		uint32_t ep_ram_init_status:1;
		uint32_t rsvd1:15;
		uint32_t cpu_reset:1;
#endif
	}bits;
}mpu_ep_control_t;

/* RX doorbell */
typedef union pd_rxulp_db_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t num_posted:8;
		uint32_t invalidate:1;
		uint32_t rsvd1:13;
		uint32_t qid:10;
#else
		uint32_t qid:10;
		uint32_t rsvd1:13;
		uint32_t invalidate:1;
		uint32_t num_posted:8;
#endif
	}bits;
}pd_rxulp_db_t;

/* TX doorbell */
typedef union pd_txulp_db_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t rsvd1:2;
		uint32_t num_posted:14;
		uint32_t rsvd0:6;
		uint32_t qid:10;
#else
		uint32_t qid:10;
		uint32_t rsvd0:6;
		uint32_t num_posted:14;
		uint32_t rsvd1:2;
#endif
	}bits;
}pd_txulp_db_t;

/* CQ doorbell */
typedef union cq_db_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t rsvd1:2;
		uint32_t rearm:1;
		uint32_t num_popped:13;
		uint32_t rsvd0:5;
		uint32_t event:1;
		uint32_t qid:10;
#else
		uint32_t qid:10;
		uint32_t event:1;
		uint32_t rsvd0:5;
		uint32_t num_popped:13;
		uint32_t rearm:1;
		uint32_t rsvd1:2;
#endif
	}bits;
}cq_db_t;

/* EQ doorbell */
typedef union eq_db_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t rsvd1:2;
		uint32_t rearm:1;
		uint32_t num_popped:13;
		uint32_t rsvd0:5;
		uint32_t event:1;
		uint32_t clrint:1;
		uint32_t qid:9;
#else
		uint32_t qid:9;
		uint32_t clrint:1;
		uint32_t event:1;
		uint32_t rsvd0:5;
		uint32_t num_popped:13;
		uint32_t rearm:1;
		uint32_t rsvd1:2;
#endif
	}bits;
}eq_db_t;

/* bootstrap mbox doorbell */
typedef union pd_mpu_mbox_db_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t address:30;
		uint32_t hi:1;
		uint32_t ready:1;
#else
		uint32_t ready:1;
		uint32_t hi:1;
		uint32_t address:30;
#endif
	}bits;
}pd_mpu_mbox_db_t;


/* MQ ring doorbell */
typedef union pd_mq_db_u {
	uint32_t dw0;
	struct {
#ifdef _BIG_ENDIAN
		uint32_t rsvd1:2;
		uint32_t num_posted:14;
		uint32_t rsvd0:5;
		uint32_t mq_id:11;
#else
		uint32_t mq_id:11;
		uint32_t rsvd0:5;
		uint32_t num_posted:14;
		uint32_t rsvd1:2;
#endif
	}bits;
}pd_mq_db_t;

/*
 * Event Queue Entry
 */
struct oce_eqe {
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint32_t resource_id:16;
			uint32_t minor_code:12;
			uint32_t major_code:3;
			uint32_t valid:1;
#else
			uint32_t valid:1;
			uint32_t major_code:3;
			uint32_t minor_code:12;
			uint32_t resource_id:16;
#endif
		}s;
		uint32_t dw0;
	}u0;
};

/* MQ scatter gather entry. Array of these make an SGL */
struct oce_mq_sge {
	uint32_t pa_lo;
	uint32_t pa_hi;
	uint32_t length;
};

/*
 * payload can contain an SGL or an embedded array of upto 59 dwords
 */
struct oce_mbx_payload {
	union {
		union {
			struct oce_mq_sge sgl[MAX_MBX_SGE];
			uint32_t embedded[59];
		}u1;
		uint32_t dw[59];
	}u0;
};

/*
 * MQ MBX structure
 */
struct oce_mbx {
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint32_t special : 8;
			uint32_t rsvd1 : 16;
			uint32_t sge_count : 5;
			uint32_t rsvd0 : 2;
			uint32_t embedded : 1;
#else
			uint32_t embedded:1;
			uint32_t rsvd0:2;
			uint32_t sge_count:5;
			uint32_t rsvd1:16;
			uint32_t special:8;
#endif
		}s;
		uint32_t dw0;
	}u0;

	uint32_t payload_length;
	uint32_t tag[2];
	uint32_t rsvd2[1];
	struct oce_mbx_payload payload;
};

/* completion queue entry for MQ */
struct oce_mq_cqe {
	union {
		struct {
#ifdef _BIG_ENDIAN
			/* dw0 */
			uint32_t extended_status:16;
			uint32_t completion_status:16;
			/* dw1 dw2 */
			uint32_t mq_tag[2];
			/* dw3 */
			uint32_t valid:1;
			uint32_t async_event:1;
			uint32_t hpi_buffer_cmpl:1;
			uint32_t completed:1;
			uint32_t consumed:1;
			uint32_t rsvd0:27;
#else
			/* dw0 */
			uint32_t completion_status:16;
			uint32_t extended_status:16;
			/* dw1 dw2 */
			uint32_t mq_tag[2];
			/* dw3 */
			uint32_t rsvd0:27;
			uint32_t consumed:1;
			uint32_t completed:1;
			uint32_t hpi_buffer_cmpl:1;
			uint32_t async_event:1;
			uint32_t valid:1;
#endif
		}s;
		uint32_t dw[4];
	}u0;
};

struct oce_async_cqe_link_state {
	union {
		struct {
#ifdef _BIG_ENDIAN
			/* dw0 */
			uint8_t speed;
			uint8_t duplex;
			uint8_t link_status;
			uint8_t phy_port;
			/* dw1 */
			uint8_t rsvd0[3];
			uint8_t fault;
			/* dw2 */
			uint32_t event_tag;
			/* dw3 */
			uint32_t valid:1;
			uint32_t async_event:1;
			uint32_t rsvd2:6;
			uint32_t event_type:8;
			uint32_t event_code:8;
			uint32_t rsvd1:8;
#else
			/* dw0 */
			uint8_t phy_port;
			uint8_t link_status;
			uint8_t duplex;
			uint8_t speed;
			/* dw1 */
			uint8_t fault;
			uint8_t rsvd0[3];
			/* dw2 */
			uint32_t event_tag;
			/* dw3 */
			uint32_t rsvd1:8;
			uint32_t event_code:8;
			uint32_t event_type:8;
			uint32_t rsvd2:6;
			uint32_t async_event:1;
			uint32_t valid:1;
#endif
		}s;
		uint32_t dw[4];
	}u0;
};

/* MQ mailbox structure */
struct oce_bmbx {
	struct oce_mbx mbx;
	struct oce_mq_cqe cqe;
};

/* ---[ MBXs start here ]---------------------------------------------- */
/* MBXs sub system codes */
enum {
	MBX_SUBSYSTEM_RSVD = 0,
	MBX_SUBSYSTEM_COMMON = 1,
	MBX_SUBSYSTEM_COMMON_ISCSI = 2,
	MBX_SUBSYSTEM_NIC = 3,
	MBX_SUBSYSTEM_TOE = 4,
	MBX_SUBSYSTEM_PXE_UNDI = 5,
	MBX_SUBSYSTEM_ISCSI_INI	= 6,
	MBX_SUBSYSTEM_ISCSI_TGT	= 7,
	MBX_SUBSYSTEM_MILI_PTL = 8,
	MBX_SUBSYSTEM_MILI_TMD = 9,
	MBX_SUBSYSTEM_RDMA = 10,
	MBX_SUBSYSTEM_LOWLEVEL = 11,
	MBX_SUBSYSTEM_LRO = 13,
	IOCBMBX_SUBSYSTEM_DCBX = 15,
	IOCBMBX_SUBSYSTEM_DIAG = 16,
	IOCBMBX_SUBSYSTEM_VENDOR = 17
};

/* common ioctl opcodes */
enum {
	OPCODE_QUERY_COMMON_IFACE_MAC = 1,
	OPCODE_SET_COMMON_IFACE_MAC = 2,
	OPCODE_SET_COMMON_IFACE_MULTICAST = 3,
	OPCODE_CONFIG_COMMON_IFACE_VLAN	= 4,
	OPCODE_QUERY_COMMON_LINK_STATUS = 5,
	OPCODE_READ_COMMON_FLASHROM = 6,
	OPCODE_WRITE_COMMON_FLASHROM = 7,
	OPCODE_QUERY_COMMON_MAX_MBX_BUFFER_SIZE = 8,
	OPCODE_ADD_COMMON_PAGE_TABLES = 9,
	OPCODE_REMOVE_COMMON_PAGE_TABLES = 10,
	OPCODE_CREATE_COMMON_CQ = 12,
	OPCODE_CREATE_COMMON_EQ = 13,
	OPCODE_CREATE_COMMON_MQ = 21,
	OPCODE_COMMON_JELL_CONFIG = 22,
	OPCODE_COMMON_ADD_TEMPLATE_HEADER_BUFFERS = 24,
	OPCODE_COMMON_REMOVE_TEMPLATE_HEADER_BUFFERS = 25,
	OPCODE_COMMON_POST_ZERO_BUFFER = 26,
	OPCODE_COMMON_GET_QOS = 27,
	OPCODE_COMMON_SET_QOS = 28,
	OPCODE_COMMON_TCP_GET_STATISTICS = 29,
	OPCODE_READ_COMMON_SEEPROM = 30,
	OPCODE_COMMON_TCP_STATE_QUERY = 31,
	OPCODE_GET_COMMON_CNTL_ATTRIBUTES = 32,
	OPCODE_COMMON_NOP = 33,
	OPCODE_COMMON_NTWK_RX_FILTER = 34,
	OPCODE_GET_COMMON_FW_VERSION = 35,
	OPCODE_SET_COMMON_FLOW_CONTROL = 36,
	OPCODE_GET_COMMON_FLOW_CONTROL = 37,
	OPCODE_COMMON_SET_TCP_PARAMETERS = 38,
	OPCODE_SET_COMMON_FRAME_SIZE = 39,
	OPCODE_COMMON_GET_FAT = 40,
	OPCODE_MODIFY_COMMON_EQ_DELAY = 41,
	OPCODE_COMMON_FIRMWARE_CONFIG = 42,
	OPCODE_COMMON_ENABLE_DISABLE_DOMAINS = 43,
	OPCODE_COMMON_GET_DOMAIN_CONFIG = 44,
	OPCODE_COMMON_GET_PORT_EQUALIZATION = 47,
	OPCODE_COMMON_SET_PORT_EQUALIZATION = 48,
	OPCODE_COMMON_RED_CONFIG = 49,
	OPCODE_CREATE_COMMON_IFACE = 50,
	OPCODE_DESTROY_COMMON_IFACE = 51,
	OPCODE_COMMON_CEV_MODIFY_MSI_MESSAGES = 52,
	OPCODE_DESTROY_COMMON_MQ = 53,
	OPCODE_DESTROY_COMMON_CQ = 54,
	OPCODE_DESTROY_COMMON_EQ = 55,
	OPCODE_COMMON_TCP_UPL_OAD = 56,
	OPCODE_SET_COMMON_LINK_SPEED = 57,
	OPCODE_QUERY_COMMON_FIRMWARE_CONFIG = 58,
	OPCODE_ADD_COMMON_IFACE_MAC = 59,
	OPCODE_DEL_COMMON_IFACE_MAC = 60,
	OPCODE_COMMON_FUNCTION_RESET = 61,
	OPCODE_COMMON_FUNCTION_LINK_CONFIG = 80
};

/* common ioctl header */
struct mbx_hdr {
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint8_t domain;
			uint8_t port_number;
			uint8_t subsystem;
			uint8_t opcode;
#else
			uint8_t opcode;
			uint8_t subsystem;
			uint8_t port_number;
			uint8_t domain;
#endif
			uint32_t timeout;
			uint32_t request_length;
			uint32_t rsvd0;
		}req;

		struct {
			/* dw 0 */
			uint8_t opcode;
			uint8_t subsystem;
			uint8_t rsvd0;
			uint8_t domain;
			/* dw 1 */
			uint8_t status;
			uint8_t additional_status;
			uint16_t rsvd1;

			uint32_t rsp_length;
			uint32_t actual_rsp_length;
		}rsp;
		uint32_t dw[4];
	}u0;
};
#define	OCE_BMBX_RHDR_SZ 20
#define	OCE_MBX_RRHDR_SZ sizeof (struct mbx_hdr)
#define	OCE_MBX_ADDL_STATUS(_MHDR) ((_MHDR)->u0.rsp.additional_status)
#define	OCE_MBX_STATUS(_MHDR) ((_MHDR)->u0.rsp.status)

/* [05] OPCODE_QUERY_COMMON_LINK_STATUS */
struct mbx_query_common_link_status {
	struct mbx_hdr hdr;
	union {
		struct {
			uint32_t rsvd0;
		}req;

		struct {
			/* dw 0 */
			uint8_t physical_port;
			uint8_t mac_duplex;
			uint8_t mac_speed;
			uint8_t mac_fault;
			/* dw 1 */
			uint8_t mgmt_mac_duplex;
			uint8_t mgmt_mac_speed;
			uint16_t qos_link_speed;
			uint32_t logical_link_status;
		}rsp;
	}params;
};

/* [57] OPCODE_SET_COMMON_LINK_SPEED */
struct mbx_set_common_link_speed {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint8_t rsvd0;
			uint8_t mac_speed;
			uint8_t virtual_port;
			uint8_t physical_port;
#else
			uint8_t physical_port;
			uint8_t virtual_port;
			uint8_t mac_speed;
			uint8_t rsvd0;
#endif
		}req;

		struct {
			uint32_t rsvd0;
		}rsp;

		uint32_t dw;
	}params;
};

struct mac_address_format {
	uint16_t size_of_struct;
	uint8_t	mac_addr[6];
};

/* [01] OPCODE_QUERY_COMMON_IFACE_MAC */
struct mbx_query_common_iface_mac {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint16_t if_id;
			uint8_t	permanent;
			uint8_t type;
#else
			uint8_t type;
			uint8_t	permanent;
			uint16_t if_id;
#endif

		}req;

		struct {
			struct mac_address_format mac;
		}rsp;
	}params;
};

/* [02] OPCODE_SET_COMMON_IFACE_MAC */
struct mbx_set_common_iface_mac {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			/* dw 0 */
			uint16_t if_id;
			uint8_t invalidate;
			uint8_t type;
#else
			/* dw 0 */
			uint8_t type;
			uint8_t invalidate;
			uint16_t if_id;
#endif
			/* dw 1 */
			struct mac_address_format mac;
		}req;

		struct {
			uint32_t rsvd0;
		}rsp;

		uint32_t dw[2];
	}params;
};

/* [03] OPCODE_SET_COMMON_IFACE_MULTICAST */
struct mbx_set_common_iface_multicast {
	struct mbx_hdr hdr;
	union {
		struct {
			/* dw 0 */
			uint16_t num_mac;
			uint8_t promiscuous;
			uint8_t if_id;
			/* dw 1-48 */
			struct {
				uint8_t byte[6];
			} mac[32];

		}req;

		struct {
			uint32_t rsvd0;
		}rsp;

		uint32_t dw[49];
	}params;
};

struct qinq_vlan {
#ifdef _BIG_ENDIAN
	uint16_t inner;
	uint16_t outer;
#else
	uint16_t outer;
	uint16_t inner;
#endif
};

struct normal_vlan {
	uint16_t vtag;
};

struct ntwk_if_vlan_tag {
	union {
		struct normal_vlan normal;
		struct qinq_vlan qinq;
	}u0;
};

/* [50] OPCODE_CREATE_COMMON_IFACE */
struct mbx_create_common_iface {
	struct mbx_hdr hdr;
	union {
		struct {
			uint32_t version;
			uint32_t cap_flags;
			uint32_t enable_flags;
			uint8_t mac_addr[6];
			uint8_t rsvd0;
			uint8_t mac_invalid;
			struct ntwk_if_vlan_tag vlan_tag;
		}req;

		struct {
			uint32_t if_id;
			uint32_t pmac_id;
		}rsp;
		uint32_t dw[4];
	}params;
};

/* [51] OPCODE_DESTROY_COMMON_IFACE */
struct mbx_destroy_common_iface {
	struct mbx_hdr hdr;
	union {
		struct {
			uint32_t if_id;
		}req;

		struct {
			uint32_t rsvd0;
		}rsp;

		uint32_t dw;
	}params;
};

/* event queue context structure */
struct   oce_eq_ctx {
#ifdef _BIG_ENDIAN
	/* dw0 */
	uint32_t size:1;
	uint32_t rsvd1:1;
	uint32_t valid:1;
	uint32_t epidx:13;
	uint32_t rsvd0:3;
	uint32_t cidx:13;

	/* dw1 */
	uint32_t armed:1;
	uint32_t stalled:1;
	uint32_t sol_event:1;
	uint32_t count:3;
	uint32_t pd:10;
	uint32_t rsvd2:3;
	uint32_t pidx:13;

	/* dw2 */
	uint32_t rsvd6:4;
	uint32_t nodelay:1;
	uint32_t phase:2;
	uint32_t rsvd5:2;
	uint32_t delay_mult:10;
	uint32_t rsvd4:1;
	uint32_t function:8;
	uint32_t rsvd3:4;

	/* dw 3 */
	uint32_t rsvd7;
#else
	/* dw0 */
	uint32_t cidx:13;
	uint32_t rsvd0:3;
	uint32_t epidx:13;
	uint32_t valid:1;
	uint32_t rsvd1:1;
	uint32_t size:1;

	/* dw1 */
	uint32_t pidx:13;
	uint32_t rsvd2:3;
	uint32_t pd:10;
	uint32_t count:3;
	uint32_t sol_event:1;
	uint32_t stalled:1;
	uint32_t armed:1;

	/* dw2 */
	uint32_t rsvd3:4;
	uint32_t function:8;
	uint32_t rsvd4:1;
	uint32_t delay_mult:10;
	uint32_t rsvd5:2;
	uint32_t phase:2;
	uint32_t nodelay:1;
	uint32_t rsvd6:4;

	/* dw3 */
	uint32_t rsvd7;
#endif
};

/* [13] OPCODE_CREATE_COMMON_EQ */
	struct mbx_create_common_eq {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint16_t rsvd0;
			uint16_t num_pages;
#else
			uint16_t num_pages;
			uint16_t rsvd0;
#endif
			struct oce_eq_ctx eq_ctx;
			struct phys_addr pages[8];
		}req;

		struct {
			uint16_t eq_id;
			uint16_t rsvd0;
		}rsp;
	}params;
};

/* [55] OPCODE_DESTROY_COMMON_EQ */
struct mbx_destroy_common_eq {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint16_t rsvd0;
			uint16_t id;
#else
			uint16_t id;
			uint16_t rsvd0;
#endif
		}req;

		struct {
			uint32_t rsvd0;
		}rsp;
	}params;
};

struct oce_cq_ctx {
#ifdef _BIG_ENDIAN
	/* dw0 */
	uint32_t eventable:1;
	uint32_t sol_event:1;
	uint32_t valid:1;
	uint32_t count:2;
	uint32_t rsvd1:1;
	uint32_t epidx:11;
	uint32_t nodelay:1;
	uint32_t coalesce_wm:2;
	uint32_t rsvd0:1;
	uint32_t cidx:11;

	/* dw1 */
	uint32_t armed:1;
	uint32_t stalled:1;
	uint32_t eq_id:8;
	uint32_t pd:10;
	uint32_t rsvd2:1;
	uint32_t pidx:11;

	/* dw2 */
	uint32_t rsvd4:20;
	uint32_t function:8;
	uint32_t rsvd3:4;
#else
	/* dw0 */
	uint32_t cidx:11;
	uint32_t rsvd0:1;
	uint32_t coalesce_wm:2;
	uint32_t nodelay:1;
	uint32_t epidx:11;
	uint32_t rsvd1:1;
	uint32_t count:2;
	uint32_t valid:1;
	uint32_t sol_event:1;
	uint32_t eventable:1;

	/* dw1 */
	uint32_t pidx:11;
	uint32_t rsvd2:1;
	uint32_t pd:10;
	uint32_t eq_id:8;
	uint32_t stalled:1;
	uint32_t armed:1;

	/* dw2 */
	uint32_t rsvd3:4;
	uint32_t function:8;
	uint32_t rsvd4:20;
#endif
	uint32_t rsvd5;
};

/* [12] OPCODE_CREATE_COMMON_CQ */
struct mbx_create_common_cq {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint16_t rsvd0;
			uint16_t num_pages;
#else
			uint16_t num_pages;
			uint16_t rsvd0;
#endif
			struct oce_cq_ctx cq_ctx;
			struct phys_addr pages[4];
		}req;

		struct {
			uint16_t cq_id;
			uint16_t rsvd0;
		}rsp;
	}params;
};

/* [54] OPCODE_DESTROY_COMMON_CQ */
struct mbx_destroy_common_cq {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint16_t rsvd0;
			uint16_t id;
#else
			uint16_t id;
			uint16_t rsvd0;
#endif
		}req;

		struct {
			uint32_t rsvd0;
		}rsp;
	}params;
};

struct mq_ring_ctx {
	union {
		struct {
#ifdef _BIG_ENDIAN
			/* dw 0 */
			uint32_t cq_id:10;
			uint32_t fetch_r2t:1;
			uint32_t fetch_wrb:1;
			uint32_t ring_size:4;
			uint32_t rsvd0:2;
			uint32_t con_index:14;

			/* dw1 */
			uint32_t valid:1;
			uint32_t pdid:9;
			uint32_t fid:8;
			uint32_t prod_index:14;

			/* dw 2 */
			uint32_t rsvd1:21;
			uint32_t async_cq_id:10;
			uint32_t async_cq_valid:1;
#else
			/* dw 0 */
			uint32_t con_index:14;
			uint32_t rsvd0:2;
			uint32_t ring_size:4;
			uint32_t fetch_wrb:1;
			uint32_t fetch_r2t:1;
			uint32_t cq_id:10;

			/* dw1 */
			uint32_t prod_index:14;
			uint32_t fid:8;
			uint32_t pdid:9;
			uint32_t valid:1;

			/* dw 2 */
			uint32_t async_cq_valid:1;
			uint32_t async_cq_id:10;
			uint32_t rsvd1:21;
#endif
			/* dw3 */
			uint32_t rsvd3;
		}s;
		uint32_t dw[4];
	}u0;
};

/* [21] OPCODE_CREATE_COMMON_MQ */
struct mbx_create_common_mq {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint16_t rsvd0;
			uint16_t num_pages;
#else
			uint16_t num_pages;
			uint16_t rsvd0;
#endif
			struct mq_ring_ctx context;
			struct phys_addr pages[8];
		}req;

		struct {
			uint32_t mq_id:16;
			uint32_t rsvd0:16;
		}rsp;
	}params;
};

/* [53] OPCODE_DESTROY_COMMON_MQ */
struct mbx_destroy_common_mq {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint16_t rsvd0;
			uint16_t id;
#else
			uint16_t id;
			uint16_t rsvd0;
#endif
		}req;

		struct {
			uint32_t rsvd0;
		}rsp;
	}params;
};

/* [35] OPCODE_GET_COMMON_ FW_VERSION */
struct mbx_get_common_fw_version {
	struct mbx_hdr hdr;
	union {
		struct {
			uint32_t rsvd0;
		}req;

		struct {
			uint8_t fw_ver_str[32];
			uint8_t fw_on_flash_ver_str[32];
		}rsp;
	}params;
};

/* [52] OPCODE_COMMON_CEV_MODIFY_MSI_MESSAGES */
struct mbx_common_cev_modify_msi_messages {
	struct mbx_hdr hdr;
	union {
		struct {
			uint32_t num_msi_msgs;
		}req;

		struct {
			uint32_t rsvd0;
		}rsp;
	}params;
};

/* [36] OPCODE_SET_COMMON_FLOW_CONTROL */
/* [37] OPCODE_GET_COMMON_FLOW_CONTROL */
struct mbx_common_get_set_flow_control {
	struct mbx_hdr hdr;
#ifdef _BIG_ENDIAN
	uint16_t tx_flow_control;
	uint16_t rx_flow_control;
#else
	uint16_t rx_flow_control;
	uint16_t tx_flow_control;
#endif
};

enum e_flash_opcode {
	MGMT_FLASHROM_OPCODE_FLASH = 1,
	MGMT_FLASHROM_OPCODE_SAVE = 2
};

/* [06]	OPCODE_READ_COMMON_FLASHROM */
/* [07]	OPCODE_WRITE_COMMON_FLASHROM */

struct mbx_common_read_write_flashrom {
	struct mbx_hdr hdr;
	uint32_t    flash_op_code;
	uint32_t    flash_op_type;
	uint32_t    data_buffer_size;
	uint32_t    data_offset;
	uint8_t		data_buffer[4];  /* + IMAGE_TRANSFER_SIZE */
};

/* ULP MODE SUPPORTED */
enum {
	ULP_TOE_MODE = 0x1,
	ULP_NIC_MODE = 0x2,
	ULP_RDMA_MODE = 0x4,
	ULP_ISCSI_INI_MODE = 0x10,
	ULP_ISCSI_TGT_MODE = 0x20,
	ULP_FCOE_INI_MODE = 0x40,
	ULP_FCOE_TGT_MODE = 0x80,
	ULP_DAL_MODE = 0x100,
	ULP_LRO_MODE = 0x200
};

/* Function Mode Supported */
enum {
	TOE_MODE = 0x1, /* TCP offload  */
	NIC_MODE = 0x2, /* Raw Ethernet  */
	RDMA_MODE = 0x4, /*  RDMA  */
	VM_MODE = 0x8,   /* VM  */
	ISCSI_INI_MODE = 0x10, /*  iSCSI initiator */
	ISCSI_TGT_MODE = 0x20, /* iSCSI target plus initiator */
	FCOE_INI_MODE = 0x40, /* FCoE Initiator */
	FCOE_TGT_MODE = 0x80, /* FCoE target */
	DAL_MODE = 0x100, /* DAL */
	LRO_MODE = 0x200, /* LRO */
	FLEX10_MODE = 0x400, /*  FLEX-10  or VNIC */
	NCSI_MODE = 0x800, /* NCSI */
	INVALID_MODE = 0x8000 /* Invalid */
};

struct mbx_common_query_fw_config {
	struct mbx_hdr hdr;
	union {
		struct {
			uint32_t rsvd0[30];
		}req;

		struct {
			uint32_t    config_number;
			uint32_t    asic_revision;
			uint32_t    port_id; /* used for stats retrieval */
			uint32_t    function_mode;
			struct {

				uint32_t    mode;
				uint32_t    wq_base;
				uint32_t    wq_count;
				uint32_t    sq_base;
				uint32_t    sq_count;
				uint32_t    rq_base;
				uint32_t    rq_count;
				uint32_t    dq_base;
				uint32_t    dq_count;
				uint32_t    lro_base;
				uint32_t    lro_count;
				uint32_t    icd_base;
				uint32_t    icd_count;
			} ulp[2];
			uint32_t function_caps;
		}rsp;
	}params;
};

struct mbx_common_config_vlan {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint8_t num_vlans;
			uint8_t untagged;
			uint8_t promisc;
			uint8_t if_id;
#else
			uint8_t if_id;
			uint8_t promisc;
			uint8_t untagged;
			uint8_t num_vlans;
#endif
			union {
				struct normal_vlan normal_vlans[64];
				struct qinq_vlan  qinq_vlans[32];
			}tags;
		}req;

		struct {
			uint32_t rsvd;
		}rsp;
	}params;
};

/* [34] OPCODE_COMMON_NTWK_RX_FILTER */
struct mbx_set_common_ntwk_rx_filter {
	struct mbx_hdr hdr;
	uint32_t global_flags_mask;
	uint32_t global_flags;
	uint32_t iface_flags_mask;
	uint32_t iface_flags;
	uint32_t if_id;
	uint32_t num_mcast;
	struct {
		uint8_t byte[6];
	}mac[32];
};
/* [41] OPCODE_MODIFY_COMMON_EQ_DELAY */
struct mbx_modify_common_eq_delay {
	struct mbx_hdr hdr;
	union {
		struct {
			uint32_t num_eq;
			struct {
				uint32_t eq_id;
				uint32_t phase;
				uint32_t dm;
			}delay[8];
		}req;

		struct {
			uint32_t rsvd0;
		}rsp;
	}params;
};
/* [59] OPCODE_ADD_COMMON_IFACE_MAC */
struct mbx_add_common_iface_mac {
	struct mbx_hdr hdr;
	union {
		struct {
			uint32_t if_id;
			uint8_t mac_address[6];
			uint8_t rsvd0[2];
		}req;
		struct {
			uint32_t pmac_id;
		}rsp;
	} params;
};

/* [60] OPCODE_DEL_COMMON_IFACE_MAC */
struct mbx_del_common_iface_mac {
	struct mbx_hdr hdr;
	union {
		struct {
			uint32_t if_id;
			uint32_t pmac_id;
		}req;
		struct {
			uint32_t rsvd0;
		}rsp;
	} params;
};

/* [8] OPCODE_QUERY_COMMON_MAX_MBX_BUFFER_SIZE */
struct mbx_query_common_max_mbx_buffer_size {
	struct mbx_hdr hdr;
	struct {
		uint32_t max_ioctl_bufsz;
	} rsp;
};

/* [61] OPCODE_COMMON_FUNCTION_RESET */
struct ioctl_common_function_reset {
	struct mbx_hdr hdr;
};

/* [80] OPCODE_COMMON_FUNCTION_LINK_CONFIG */
struct mbx_common_func_link_cfg {
	struct mbx_hdr hdr;
	union {
		struct {
			uint32_t enable;
		}req;
		struct {
			uint32_t rsvd0;
		}rsp;
	} params;
};

#pragma pack()

#ifdef __cplusplus
}
#endif

#endif /* _OCE_HW_H_ */
