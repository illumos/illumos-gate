/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_FCF_H
#define	_EMLXS_FCF_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	FCFTAB_MAX_FCFI_COUNT		1
#define	FCFI_MAX_VFI_COUNT		1

/* Internal generic events */
#define	FCF_EVENT_STATE_ENTER		0

/* External async fabric events */
#define	FCF_EVENT_SHUTDOWN		1
#define	FCF_EVENT_LINKUP		2
#define	FCF_EVENT_LINKDOWN		3
#define	FCF_EVENT_CVL			4
#define	FCF_EVENT_FCFTAB_FULL		5
#define	FCF_EVENT_FCF_FOUND		6
#define	FCF_EVENT_FCF_LOST		7
#define	FCF_EVENT_FCF_CHANGED		8

/* Internal async events */
#define	FCF_EVENT_FCFTAB_ONLINE		9
#define	FCF_EVENT_FCFTAB_OFFLINE	10

#define	FCF_EVENT_FCFI_ONLINE		11
#define	FCF_EVENT_FCFI_OFFLINE		12
#define	FCF_EVENT_FCFI_PAUSE		13

#define	FCF_EVENT_VFI_ONLINE		14
#define	FCF_EVENT_VFI_OFFLINE		15
#define	FCF_EVENT_VFI_PAUSE		16

#define	FCF_EVENT_VPI_ONLINE		17
#define	FCF_EVENT_VPI_OFFLINE		18
#define	FCF_EVENT_VPI_PAUSE		19

#define	FCF_EVENT_RPI_ONLINE		20
#define	FCF_EVENT_RPI_OFFLINE		21
#define	FCF_EVENT_RPI_PAUSE		22
#define	FCF_EVENT_RPI_RESUME		23

/* State change reason codes */		  /* explan */
#define	FCF_REASON_NONE			0
#define	FCF_REASON_REENTER		1
#define	FCF_REASON_EVENT		2 /* evt */
#define	FCF_REASON_REQUESTED		3
#define	FCF_REASON_NO_MBOX		4
#define	FCF_REASON_NO_BUFFER		5
#define	FCF_REASON_SEND_FAILED		6 /* status */
#define	FCF_REASON_MBOX_FAILED		7 /* status */
#define	FCF_REASON_MBOX_BUSY		8 /* status */
#define	FCF_REASON_NO_FCFI		9
#define	FCF_REASON_NO_VFI		10
#define	FCF_REASON_ONLINE_FAILED	11
#define	FCF_REASON_OFFLINE_FAILED	12
#define	FCF_REASON_OP_FAILED		13 /* attempts */
#define	FCF_REASON_NO_PKT		14
#define	FCF_REASON_NO_NODE		15
#define	FCF_REASON_NOT_ALLOWED		16
#define	FCF_REASON_UNUSED		17
#define	FCF_REASON_INVALID		18

typedef struct XRIobj
{
	struct XRIobj	*_f;
	struct XRIobj	*_b;
	uint16_t	XRI;
	uint16_t	state;
#define	XRI_STATE_FREE			0
#define	XRI_STATE_ALLOCATED		1

	uint16_t	sge_count;
	uint16_t	iotag;
	MBUF_INFO	SGList;
	struct RPIobj	*rpip;
	struct RPIobj	*reserved_rpip;
	emlxs_buf_t	*sbp;
	uint32_t 	rx_id; /* Used for unsol exchanges */
	uint32_t 	flag;
#define	EMLXS_XRI_RESERVED		0x00000001
#define	EMLXS_XRI_PENDING_IO		0x00000002
#define	EMLXS_XRI_BUSY			0x00000004

	uint32_t 	type;
#define	EMLXS_XRI_SOL_FCP_TYPE		1
#define	EMLXS_XRI_UNSOL_FCP_TYPE	2
#define	EMLXS_XRI_SOL_CT_TYPE		3
#define	EMLXS_XRI_UNSOL_CT_TYPE		4
#define	EMLXS_XRI_SOL_ELS_TYPE		5
#define	EMLXS_XRI_UNSOL_ELS_TYPE	6
#define	EMLXS_XRI_SOL_BLS_TYPE		7

} XRIobj_t;


typedef struct emlxs_deferred_cmpl
{
	struct emlxs_port *port;
	struct emlxs_node *node;

	void *arg1;
	void *arg2;
	void *arg3;

} emlxs_deferred_cmpl_t;


#define	FABRIC_RPI		0xffff

typedef struct RPIobj
{
	uint16_t	index;
	uint16_t	RPI;

	uint16_t	prev_reason;
	uint16_t	prev_state;

	uint16_t	reason;
	uint16_t	state;
#define	RPI_STATE_FREE			0

#define	RPI_STATE_RESERVED		1
#define	RPI_STATE_OFFLINE		2

#define	RPI_STATE_UNREG_CMPL		3
#define	RPI_STATE_UNREG_FAILED		4
#define	RPI_STATE_UNREG			5

#define	RPI_STATE_REG			6
#define	RPI_STATE_REG_FAILED		7
#define	RPI_STATE_REG_CMPL		8

#define	RPI_STATE_PAUSED		9

#define	RPI_STATE_RESUME		10
#define	RPI_STATE_RESUME_FAILED		11
#define	RPI_STATE_RESUME_CMPL		12

#define	RPI_STATE_ONLINE		13


	uint32_t	flag;
#define	EMLXS_RPI_VPI			0x00000010 /* rpi_online set */
#define	EMLXS_RPI_PAUSED		0x00000020 /* rpi_paused set */
#define	EMLXS_RPI_REG			0x00000040

#define	EMLXS_RPI_FIRST			0x80000000

	uint32_t	attempts;
	uint32_t	xri_count;  /* Managed by XRIobj_t */

	uint32_t	idle_timer;

	struct VPIobj 	*vpip;

	/* Node info */
	struct emlxs_node	*node;
	uint32_t	did;
	SERV_PARM	sparam;

	emlxs_deferred_cmpl_t *cmpl;

} RPIobj_t;


typedef struct VPIobj
{
	uint16_t 	index;
	uint16_t 	VPI;

	uint16_t	prev_reason;
	uint16_t	prev_state;

	uint16_t	reason;
	uint16_t	state;
#define	VPI_STATE_OFFLINE		0

#define	VPI_STATE_INIT			1
#define	VPI_STATE_INIT_FAILED		2
#define	VPI_STATE_INIT_CMPL		3

#define	VPI_STATE_UNREG_CMPL		4
#define	VPI_STATE_UNREG_FAILED		5
#define	VPI_STATE_UNREG			6

#define	VPI_STATE_LOGO_CMPL		7
#define	VPI_STATE_LOGO_FAILED		8
#define	VPI_STATE_LOGO			9

#define	VPI_STATE_PORT_OFFLINE		10
#define	VPI_STATE_PORT_ONLINE		11

#define	VPI_STATE_LOGI			12
#define	VPI_STATE_LOGI_FAILED		13
#define	VPI_STATE_LOGI_CMPL		14

#define	VPI_STATE_REG			15
#define	VPI_STATE_REG_FAILED		16
#define	VPI_STATE_REG_CMPL		17

#define	VPI_STATE_PAUSED		18
#define	VPI_STATE_ONLINE		19


	uint32_t 	flag;
#define	EMLXS_VPI_ONLINE_REQ		0x00000001
#define	EMLXS_VPI_OFFLINE_REQ		0x00000002
#define	EMLXS_VPI_PAUSE_REQ		0x00000004
#define	EMLXS_VPI_REQ_MASK		0x0000000F

#define	EMLXS_VPI_VFI			0x00000010 /* vpi_online set */
#define	EMLXS_VPI_VFI_LOGI		0x00000020 /* logi_count set */
#define	EMLXS_VPI_INIT			0x00000040
#define	EMLXS_VPI_REG			0x00000080
#define	EMLXS_VPI_PORT_ONLINE		0x00000100
#define	EMLXS_VPI_LOGI			0x00000200
#define	EMLXS_VPI_PORT_UNBIND		0x40000000
#define	EMLXS_VPI_PORT_ENABLED		0x80000000

	uint32_t	attempts;

	RPIobj_t	fabric_rpi;	/* Reserved Fabric RPI object */
	RPIobj_t	*fabric_rpip;	/* Fabric RPI pointer (&fabric_rpi) */
	RPIobj_t	*p2p_rpip;

	struct emlxs_port *port;

	struct VFIobj	*vfip; /* Managed by VFIobj_t */
	uint32_t	rpi_online; /* Managed by RPIobj_t */
	uint32_t	rpi_paused; /* Managed by RPIobj_t */

} VPIobj_t;


typedef struct VFIobj
{
	uint16_t	index;
	uint16_t	VFI;

	uint16_t	prev_reason;
	uint16_t	prev_state;

	uint16_t	reason;
	uint16_t	state;
#define	VFI_STATE_OFFLINE		0

#define	VFI_STATE_INIT			1
#define	VFI_STATE_INIT_FAILED		2
#define	VFI_STATE_INIT_CMPL		3

#define	VFI_STATE_VPI_OFFLINE_CMPL	4
#define	VFI_STATE_VPI_OFFLINE		5

#define	VFI_STATE_VPI_ONLINE		6
#define	VFI_STATE_VPI_ONLINE_CMPL	7

#define	VFI_STATE_UNREG_CMPL		8
#define	VFI_STATE_UNREG_FAILED		9
#define	VFI_STATE_UNREG			10

#define	VFI_STATE_REG			11
#define	VFI_STATE_REG_FAILED		12
#define	VFI_STATE_REG_CMPL		13

#define	VFI_STATE_PAUSED		14
#define	VFI_STATE_ONLINE		15

	uint32_t	flag;
#define	EMLXS_VFI_ONLINE_REQ		0x00000001
#define	EMLXS_VFI_OFFLINE_REQ		0x00000002
#define	EMLXS_VFI_PAUSE_REQ		0x00000004
#define	EMLXS_VFI_REQ_MASK		0x0000000F

#define	EMLXS_VFI_FCFI			0x00000010 /* vfi_online set */
#define	EMLXS_VFI_INIT			0x00000020
#define	EMLXS_VFI_REG			0x00000040

	SERV_PARM	sparam;		/* Last registered sparams */

	uint32_t	attempts;

	struct FCFIobj 	*fcfp;		/* Managed by FCFIobj_t */

	uint32_t	vpi_online;	/* Managed by VPIobj_t */
	uint32_t 	logi_count;	/* Managed by VPIobj_t */
	struct VPIobj 	*flogi_vpip;	/* Managed by VPIobj_t */

} VFIobj_t;


typedef struct FCFIobj
{
	uint16_t	index;
	uint16_t	FCFI;

	uint16_t	fcf_index;
	uint16_t	vlan_id;

	uint16_t	prev_reason;
	uint16_t	prev_state;

	uint16_t	reason;
	uint16_t	state;
#define	FCFI_STATE_FREE			0

#define	FCFI_STATE_OFFLINE		1

#define	FCFI_STATE_UNREG_CMPL		2
#define	FCFI_STATE_UNREG_FAILED		3
#define	FCFI_STATE_UNREG		4

#define	FCFI_STATE_REG			5
#define	FCFI_STATE_REG_FAILED		6
#define	FCFI_STATE_REG_CMPL		7

#define	FCFI_STATE_VFI_OFFLINE_CMPL	8
#define	FCFI_STATE_VFI_OFFLINE		9

#define	FCFI_STATE_VFI_ONLINE		10
#define	FCFI_STATE_VFI_ONLINE_CMPL	11

#define	FCFI_STATE_PAUSED		12
#define	FCFI_STATE_ONLINE		13


	uint16_t 	pad;
	uint16_t 	generation;

	uint32_t 	offline_timer;
	uint32_t 	attempts;

	uint32_t	event_tag;
	uint32_t	flag;
#define	EMLXS_FCFI_ONLINE_REQ		0x00000001
#define	EMLXS_FCFI_OFFLINE_REQ		0x00000002
#define	EMLXS_FCFI_PAUSE_REQ		0x00000004
#define	EMLXS_FCFI_REQ_MASK		0x0000000F

#define	EMLXS_FCFI_FCFTAB		0x00000010 /* fcfi_online set */
#define	EMLXS_FCFI_REG			0x00000020

#define	EMLXS_FCFI_VALID		0x00000100
#define	EMLXS_FCFI_AVAILABLE		0x00000200
#define	EMLXS_FCFI_CONFIGURED		0x00000400
#define	EMLXS_FCFI_FRESH		0x00000800
#define	EMLXS_FCFI_FAILED		0x00001000
#define	EMLXS_FCFI_SELECTED		0x00002000 /* in use */

#define	EMLXS_FCFI_VLAN_ID		0x00010000
#define	EMLXS_FCFI_BOOT			0x00020000
#define	EMLXS_FCFI_PRIMARY		0x00040000

#define	EMLXS_FCFI_TAGGED		0x80000000

	/* struct VFTable	vftab */

	FCF_RECORD_t	fcf_rec;
	uint32_t	priority;

	uint32_t	vfi_online;  /* Managed by VFIobj_t */

} FCFIobj_t;


typedef struct VFTable
{
	uint16_t 	prev_reason;
	uint16_t 	prev_state;

	uint16_t 	reason;
	uint16_t 	state;
#define	VFTAB_STATE_DISABLED		0

	uint32_t	vfi_active;
	uint32_t	vfi_count;
	VFIobj_t	*table;

} VFTable_t;

typedef struct FCFTable
{

	uint16_t 	prev_reason;
	uint16_t 	prev_state;

	uint16_t 	reason;
	uint16_t 	state;
/* Common states */
#define	FCFTAB_STATE_SHUTDOWN			0
#define	FCFTAB_STATE_OFFLINE			1

/* FCOE states */
#define	FCOE_FCFTAB_STATE_SHUTDOWN		FCFTAB_STATE_SHUTDOWN
#define	FCOE_FCFTAB_STATE_OFFLINE		FCFTAB_STATE_OFFLINE

#define	FCOE_FCFTAB_STATE_SOLICIT		2
#define	FCOE_FCFTAB_STATE_SOLICIT_FAILED	3
#define	FCOE_FCFTAB_STATE_SOLICIT_CMPL		4

#define	FCOE_FCFTAB_STATE_READ			5
#define	FCOE_FCFTAB_STATE_READ_FAILED		6
#define	FCOE_FCFTAB_STATE_READ_CMPL		7

#define	FCOE_FCFTAB_STATE_FCFI_OFFLINE_CMPL	8
#define	FCOE_FCFTAB_STATE_FCFI_OFFLINE		9

#define	FCOE_FCFTAB_STATE_FCFI_ONLINE		10
#define	FCOE_FCFTAB_STATE_FCFI_ONLINE_CMPL	11

#define	FCOE_FCFTAB_STATE_ONLINE		12


/* FC states */
#define	FC_FCFTAB_STATE_SHUTDOWN		FCFTAB_STATE_SHUTDOWN
#define	FC_FCFTAB_STATE_OFFLINE			FCFTAB_STATE_OFFLINE

#define	FC_FCFTAB_STATE_TOPO			2
#define	FC_FCFTAB_STATE_TOPO_FAILED		3
#define	FC_FCFTAB_STATE_TOPO_CMPL		4

#define	FC_FCFTAB_STATE_CFGLINK			5
#define	FC_FCFTAB_STATE_CFGLINK_FAILED		6
#define	FC_FCFTAB_STATE_CFGLINK_CMPL		7

#define	FC_FCFTAB_STATE_SPARM			8
#define	FC_FCFTAB_STATE_SPARM_FAILED		9
#define	FC_FCFTAB_STATE_SPARM_CMPL		10

#define	FC_FCFTAB_STATE_FCFI_OFFLINE_CMPL	11
#define	FC_FCFTAB_STATE_FCFI_OFFLINE		12

#define	FC_FCFTAB_STATE_FCFI_ONLINE		13
#define	FC_FCFTAB_STATE_FCFI_ONLINE_CMPL	14

#define	FC_FCFTAB_STATE_ONLINE			15


	uint16_t 	TID;
	uint16_t 	generation;

	uint32_t 	flag;
/* Common flags */
#define	EMLXS_FCFTAB_REQ_MASK			0x0000000F
#define	EMLXS_FCFTAB_SHUTDOWN			0x80000000

/* FCOE flags */
#define	EMLXS_FCOE_FCFTAB_SOL_REQ		0x00000001
#define	EMLXS_FCOE_FCFTAB_READ_REQ		0x00000002
#define	EMLXS_FCOE_FCFTAB_OFFLINE_REQ		0x00000004

/* FC flags */
#define	EMLXS_FC_FCFTAB_TOPO_REQ		0x00000001
#define	EMLXS_FC_FCFTAB_CFGLINK_REQ		0x00000002
#define	EMLXS_FC_FCFTAB_SPARM_REQ		0x00000004
#define	EMLXS_FC_FCFTAB_OFFLINE_REQ		0x00000008

	uint32_t 	attempts;

	uint32_t	fcfi_online;  /* Managed by FCFIobj_t */

	FCFIobj_t	*fcfi[FCFTAB_MAX_FCFI_COUNT];
	uint32_t	fcfi_count;

	FCFIobj_t	*table;
	uint16_t	table_count;

	uint32_t 	online_timer;	/* FC */

	uint32_t 	sol_timer;	/* FCOE */
	uint32_t 	read_timer;	/* FCOE */

} FCFTable_t;
#define	FCFTAB_READ_ALL		(void*)0xffff

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_FCF_H */
