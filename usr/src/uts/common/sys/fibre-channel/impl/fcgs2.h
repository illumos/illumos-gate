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

#ifndef	_SYS_FIBRE_CHANNEL_IMPL_FCGS2_H
#define	_SYS_FIBRE_CHANNEL_IMPL_FCGS2_H


#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * A device handle describes the characterics of a device
 * Node. Each device handle also contains information
 * on the serveral different ports it is discovered on.
 *
 * Classification of Name Server Objects
 *
 * +-----------------------------------+---------------------------+
 * |  Device (node) Specific           |  Port Specific            |
 * +-----------------------------------+---------------------------+
 * |  Node Name (NN)                   | Port type (PT)            |
 * |  Symbolic Node Name Length        | Port Id (ID)              |
 * |  Symbloic Node Name(SNN)          | Symbolic Port Name length |
 * |  Initial Process associator(IPA)  | Symbolic Port Name (SPN)  |
 * |                                   | Class of Service (CS)     |
 * |                                   | fc4 types (FT)            |
 * |                                   | IP Address (IP)           |
 * +-----------------------------------+---------------------------+
 *
 * The above classification causes some inconvenience in not having
 * the ability to directly copy all the nameserver objects into a
 * contiguous piece of memory. But we'll live with it.
 */

#define	CT_REV			0x01	/* Common Transport revision */

/* FCS types */
#define	FCSTYPE_KEYSERVICE	0xF7
#define	FCSTYPE_ALIAS		0xF8
#define	FCSTYPE_MGMTSERVICE	0xFA
#define	FCSTYPE_TIMESERVICE	0xFB
#define	FCSTYPE_DIRECTORY	0xFC
#define	FCSTYEP_FABRIC		0xFD

/*
 * FCS subtypes for Directory Service
 */
#define	FCSSUB_DS_NAME_SERVER		0x02	/* Zoned Name Server */
#define	FCSSUB_DS_IPADDR_SERVER		0x03	/* IP Address Server */

/*
 * FCS subtypes for Management Service
 */
#define	FCSSUB_MS_CONFIG_SERVER		0x01	/* Fabric Config Server */
#define	FCSSUB_MS_UNZONED_NAME_SERVER	0x02	/* Unzoned Name Server */
#define	FCSSUB_MS_ZONE_SERVER		0x03	/* Fabric Zone Server */

/*
 * FCS subtypes for Time Service
 */
#define	FCSSUB_TS_TIME_SERVER		0x01	/* Time Server */

/*
 * FCS subtypes for Alias Service
 */
#define	FCSSUB_AS_ALIAS_SERVER		0x01	/* Alias Server */

/*
 * FCS subtypes for Key Service
 */
#define	FCSSUB_KS_KEY_SERVER		0x00	/* Key Distribution Server */

/* FC-CT response codes */
#define	FS_RJT_IU		0x8001
#define	FS_ACC_IU		0x8002

/* FS_RJT Reason Codes */
#define	FSRJT_BADCMD		0x01	/* Invalid command code */
#define	FSRJT_BADVER		0x02	/* Invalid version level */
#define	FSRJT_LOGICALERR	0x03	/* Logical error */
#define	FSRJT_BADSIZE		0x04	/* Invalid IU size */
#define	FSRJT_BUSY		0x05	/* Logical busy */
#define	FSRJT_PROTOCOLERR	0x07	/* Protocol error */
#define	FSRJT_CMDFAILED		0x08	/* Unable to perform command */
#define	FSRJT_UNSUPP		0x0b	/* Command not supported */
#define	FSRJT_VENDOR		0xff	/* vendor unique error */

/* Name Service Command Codes */
#define	NS_GA_NXT		0x0100	/* Get All next */
#define	NS_GPN_ID		0x0112	/* Get Port Name */
#define	NS_GNN_ID		0x0113	/* Get Node Name */
#define	NS_GCS_ID		0x0114	/* Get Class Of service */
#define	NS_GFT_ID		0x0117	/* Get FC-4 Types */
#define	NS_GSPN_ID		0x0118	/* Get Sym Port name */
#define	NS_GPT_ID		0x011A	/* Get Port Type */
#define	NS_GID_PN		0x0121	/* Get port id for PN */
#define	NS_GID_NN		0x0131	/* Get port id for NN */
#define	NS_GIP_NN		0x0135	/* Get IP address */
#define	NS_GIPA_NN		0x0136	/* Get I.P.A */
#define	NS_GSNN_NN		0x0139	/* Get Sym Node name */
#define	NS_GNN_IP		0x0153	/* Get Node name for IP */
#define	NS_GIPA_IP		0x0156	/* Get I.P.A for IP */
#define	NS_GID_FT		0x0171	/* Get port Id for FC-4 type */
#define	NS_GID_PT		0x01A1	/* Get port Id for type */
#define	NS_RPN_ID		0x0212	/* Reg port name */
#define	NS_RNN_ID		0x0213	/* Reg node name */
#define	NS_RCS_ID		0x0214	/* Reg C.O.S */
#define	NS_RFT_ID		0x0217	/* Reg FC-4 Types */
#define	NS_RSPN_ID		0x0218	/* Reg Sym Port name */
#define	NS_RPT_ID		0x021A	/* Reg Port Type */
#define	NS_RIP_NN		0x0235	/* Reg I.P address */
#define	NS_RIPA_NN		0x0236	/* Reg I.P.A */
#define	NS_RSNN_NN		0x0239	/* Reg Sym Node name */
#define	NS_DA_ID		0x0300	/* De-Register all */

/* Name service reject explanation codes */
#define	NSRJTX_NONE		0x00	/* No additional explanation */
#define	NSRJTX_PORTNOTREG	0x01	/* Port ID not registered */
#define	NSRJTX_PWWNNOTREG	0x02	/* Port Name not registered */
#define	NSRJTX_NWWNNOTREG	0x03	/* Node Name not registered */
#define	NSRJTX_CoSNOTREG	0x04	/* Class of Service no registered */
#define	NSRJTX_IPNOTREG		0x05	/* IP Address not registered */
#define	NSRJTX_IPANOTREG	0x06	/* Initial Proc. Assoc not reg. */
#define	NSRJTX_FC4NOTREG	0x07	/* FC$ types not registered */
#define	NSRJTX_SPNNOTREG	0x08	/* Symbolic port name not registered */
#define	NSRJTX_SNNNOTREG	0x09	/* Symbolic node name not registered */
#define	NSRJTX_TYPENOTREG	0x0a	/* Port type not registered */
#define	NSRJTX_NOPERM		0x10	/* Access denied */
#define	NSRJTX_BADPORTID	0x11	/* Unacceptable port ID */
#define	NSRJTX_DBEMPTY		0x12	/* Data base empty */

/* Management Service Command Codes */
#define	MS_GIEL		0x0101	/* Get Interconnect Element List */

#define	FC_NS_CLASSF		0x01
#define	FC_NS_CLASS1		0x02
#define	FC_NS_CLASS2		0x04
#define	FC_NS_CLASS3		0x08
#define	FC_NS_CLASS4		0x10
#define	FC_NS_CLASS5		0x20
#define	FC_NS_CLASS6		0x40

#define	FC_NS_PORT_UNKNOWN	0x00
#define	FC_NS_PORT_N		0x01
#define	FC_NS_PORT_NL		0x02
#define	FC_NS_PORT_F_NL		0x03
#define	FC_NS_PORT_NX		0x7F
#define	FC_NS_PORT_F		0x81
#define	FC_NS_PORT_FL		0x82
#define	FC_NS_PORT_E		0x84

#define	FC_IS_CMD_A_QUERY(cmd)	((cmd) >= NS_GA_NXT && (cmd) <= NS_GID_PT)
#define	FC_IS_CMD_A_REG(cmd)	((cmd) >= NS_RPN_ID && (cmd) <= NS_DA_ID)
#define	NS_GAN_RESP_LEN		(sizeof (ns_resp_gan_t))

/*
 * SCR registration function codes
 */
#define	FC_SCR_FABRIC_REGISTRATION	0x01
#define	FC_SCR_NPORT_REGISTRATION	0x02
#define	FC_SCR_FULL_REGISTRATION	0x03
#define	FC_SCR_CLEAR_REGISTRATION	0xFF

/*
 * Register port/node name request payload
 *
 * 'x' means either P (port) or N (node)
 */
typedef struct rxn_id {
	fc_portid_t	rxn_port_id;	/* Port Identfier */
	la_wwn_t	rxn_xname;		/* Port/Node Name */
} ns_rxn_req_t;

/*
 * Register Class of service request payload
 */
typedef struct rcos {
	fc_portid_t	rcos_port_id;
	uint32_t	rcos_cos;
} ns_rcos_t;

/*
 * Register FC-4 TYPEs request payload
 */
typedef struct rfc_type {
	fc_portid_t	rfc_port_id;
	uchar_t		rfc_types[32];	/* bit map of ULP types */
} ns_rfc_type_t;

/*
 * Register symbolic port name request payload
 */
typedef struct spn {
	fc_portid_t	spn_port_id;
	uchar_t		spn_len;
	/*
	 * What follows here is the actual name
	 * which is allocated on the fly during
	 * packet allocation.
	 */
} ns_spn_t;

/*
 * Register port type request payload
 */
typedef struct rpt {
	fc_portid_t	rpt_port_id;
	fc_porttype_t	rpt_type;
} ns_rpt_t;

/*
 * Register IP address request payload
 */
typedef struct rip {
	la_wwn_t	rip_node_name;
	uchar_t		rip_ip_addr[16];
} ns_rip_t;

/*
 * Register Initial Process Associator request payload
 */
typedef struct ipa {
	la_wwn_t	ipa_node_name;
	uchar_t		ipa_value[8];
} ns_ipa_t;

/*
 * Register Symbolic Node Name request payload
 */
typedef struct snn {
	la_wwn_t	snn_node_name;
	uchar_t		snn_len;
	/*
	 * What follows here is the actual name
	 * which is allocated on the fly during
	 * packet allocation.
	 */
} ns_snn_t;

/*
 * Remove all request payload
 */
typedef struct remall {
	fc_portid_t	rem_port_id;
} ns_remall_t;

typedef fc_ct_header_t fc_reg_resp_t;
typedef fc_ct_header_t fc_query_resp_t;

typedef struct ns_req_gid_pt {
	fc_porttype_t	port_type;
} ns_req_gid_pt_t;

typedef struct ns_resp_gid_pt {
	fc_portid_t	gid_port_id;
} ns_resp_gid_pt_t;

typedef struct ns_req_gan {
	fc_portid_t	pid;
} ns_req_gan_t;

typedef struct ns_resp_gan {
	fc_porttype_t	gan_type_id;		/* type and id next */
	la_wwn_t	gan_pwwn;		/* Port Name */
	uchar_t		gan_spnlen;		/* Sym P Name Len */
	char		gan_spname[255];	/* Sym Port name */

	la_wwn_t	gan_nwwn;		/* Node Name */
	uchar_t		gan_snnlen;		/* Sym N name Len */
	char		gan_snname[255];	/* Sym Node name */

	uchar_t		gan_ipa[8];		/* Initial Proc assoc */
	uchar_t		gan_ip[16];		/* IP Address */
	uint32_t	gan_cos;		/* Class of Service */

	uint32_t	gan_fc4types[8];	/* FC-4 Types */
} ns_resp_gan_t;

typedef struct ns_req_gid_pn {
	la_wwn_t	pwwn;
} ns_req_gid_pn_t;

typedef struct ns_resp_gid_pn {
	fc_portid_t	pid;
} ns_resp_gid_pn_t;

typedef struct ns_req_gpn_id {
	fc_portid_t	pid;
} ns_req_gpn_id_t;

typedef struct ns_resp_gpn_id {
	la_wwn_t	pwwn;
} ns_resp_gpn_id_t;

typedef struct ns_req_gpt_id {
	fc_portid_t	pid;
} ns_req_gpt_id_t;

typedef struct ns_resp_gpt_id {
	fc_porttype_t	port_type;
} ns_resp_gpt_id_t;

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per request", ns_resp_gpn_id))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", rxn_id))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", ns_req_gpn_id))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", ns_resp_gid_pn))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", ns_req_gid_pn))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", ns_resp_gan))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", ns_req_gan))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", ns_req_gid_pt))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", ns_req_gpt_id))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", ns_resp_gpt_id))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", remall))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", snn))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", ipa))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", rip))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", rpt))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", spn))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", rfc_type))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", rcos))
#endif /* __lint */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FIBRE_CHANNEL_IMPL_FCGS2_H */
