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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _ISCSI_IF_H
#define	_ISCSI_IF_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/strsubr.h>	/* for prototype of kstrgetmsg */
#include <sys/socket.h>
#include <sys/socketvar.h>	/* for struct sonode */
#endif
#include <sys/param.h>		/* for MAXPATHLEN */
#include <netinet/in.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/iscsi_protocol.h>

/*
 * Each of the top level structures have a version field as
 * the first member. That version value will be set by the
 * caller. The consumer of the structure will check to see
 * if the version is correct.
 */
#define	ISCSI_INTERFACE_VERSION			3

/*
 * Login parameter values are used instead of ascii text
 * between the IMA plug-in and kernel.
 */
#define	ISCSI_LOGIN_PARAM_DATA_SEQUENCE_IN_ORDER	0x0000  /* bool */
#define	ISCSI_LOGIN_PARAM_IMMEDIATE_DATA		0x0001  /* bool */
#define	ISCSI_LOGIN_PARAM_INITIAL_R2T			0x0002  /* bool */
#define	ISCSI_LOGIN_PARAM_DATA_PDU_IN_ORDER		0x0003  /* bool */
#define	ISCSI_LOGIN_PARAM_HEADER_DIGEST			0x0004	/* int */
#define	ISCSI_LOGIN_PARAM_DATA_DIGEST			0x0005	/* int */
#define	ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_RETAIN		0x0006  /* int */
#define	ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_WAIT		0x0007  /* int */
#define	ISCSI_LOGIN_PARAM_MAX_RECV_DATA_SEGMENT_LENGTH	0x0008  /* int */
#define	ISCSI_LOGIN_PARAM_FIRST_BURST_LENGTH		0x0009  /* int */
#define	ISCSI_LOGIN_PARAM_MAX_BURST_LENGTH		0x000A  /* int */
#define	ISCSI_LOGIN_PARAM_MAX_CONNECTIONS		0x000B  /* int */
#define	ISCSI_LOGIN_PARAM_OUTSTANDING_R2T		0x000C  /* int */
#define	ISCSI_LOGIN_PARAM_ERROR_RECOVERY_LEVEL		0x000D  /* int */
/*
 * number of login parameters - needs to be updated when new parameter added
 */
#define	ISCSI_NUM_LOGIN_PARAM				0x000E

/*
 * Used internally by the persistent store code. Currently a bitmap is kept of
 * which params are currently set. This allows for quick a look up instead of
 * cycling through the possible entries. Using an unsigned int as the bitmap we
 * can have parameter numbers up through 31. Since the current only has 22
 * we're okay.
 */
#define	ISCSI_LOGIN_PARAM_DB_ENTRY			0x0020
/*
 * Special case. When this parameter value is set in iscsi_param_set_t
 * the member s_value (type iscsi_param_set_t) is not used.
 * The name field contains the InitiatorName for the system which
 * should be used for all future sessions.
 */
#define	ISCSI_LOGIN_PARAM_INITIATOR_NAME		0x0021
#define	ISCSI_LOGIN_PARAM_INITIATOR_ALIAS		0x0022

#define	ISCSI_DEVCTL		"devctl"
#define	ISCSI_DRIVER_DEVCTL	"/devices/iscsi:" ISCSI_DEVCTL

/*
 * ioctls supported by the driver.
 */
#define	ISCSI_IOCTL		(('i' << 24) | ('S' << 16) | ('C' << 8))
#define	ISCSI_CREATE_OID		(ISCSI_IOCTL | 2)
#define	ISCSI_LOGIN			(ISCSI_IOCTL | 3)
#define	ISCSI_LOGOUT			(ISCSI_IOCTL | 4)
#define	ISCSI_PARAM_GET			(ISCSI_IOCTL | 5)
#define	ISCSI_PARAM_SET			(ISCSI_IOCTL | 6)
#define	ISCSI_TARGET_PARAM_CLEAR	(ISCSI_IOCTL | 8)
#define	ISCSI_TARGET_OID_LIST_GET	(ISCSI_IOCTL | 9)
#define	ISCSI_TARGET_PROPS_GET		(ISCSI_IOCTL | 10)
#define	ISCSI_TARGET_PROPS_SET		(ISCSI_IOCTL | 11)
#define	ISCSI_TARGET_ADDRESS_GET	(ISCSI_IOCTL | 12)
#define	ISCSI_CHAP_SET			(ISCSI_IOCTL | 13)
#define	ISCSI_CHAP_GET			(ISCSI_IOCTL | 14)
#define	ISCSI_CHAP_CLEAR		(ISCSI_IOCTL | 15)
#define	ISCSI_STATIC_GET		(ISCSI_IOCTL | 16)
#define	ISCSI_STATIC_SET		(ISCSI_IOCTL | 17)
#define	ISCSI_STATIC_CLEAR		(ISCSI_IOCTL | 18)
#define	ISCSI_DISCOVERY_SET		(ISCSI_IOCTL | 19)
#define	ISCSI_DISCOVERY_GET		(ISCSI_IOCTL | 20)
#define	ISCSI_DISCOVERY_CLEAR		(ISCSI_IOCTL | 21)
#define	ISCSI_DISCOVERY_PROPS		(ISCSI_IOCTL | 22)
#define	ISCSI_DISCOVERY_ADDR_SET	(ISCSI_IOCTL | 23)
#define	ISCSI_DISCOVERY_ADDR_LIST_GET	(ISCSI_IOCTL | 24)
#define	ISCSI_DISCOVERY_ADDR_CLEAR	(ISCSI_IOCTL | 25)
#define	ISCSI_RADIUS_SET		(ISCSI_IOCTL | 26)
#define	ISCSI_RADIUS_GET		(ISCSI_IOCTL | 27)
#define	ISCSI_LUN_OID_LIST_GET		(ISCSI_IOCTL | 29)
#define	ISCSI_LUN_PROPS_GET		(ISCSI_IOCTL | 30)
#define	ISCSI_CONN_OID_LIST_GET		(ISCSI_IOCTL | 31)
#define	ISCSI_CONN_PROPS_GET		(ISCSI_IOCTL | 32)
#define	ISCSI_USCSI			(ISCSI_IOCTL | 33)
#define	ISCSI_SMF_ONLINE		(ISCSI_IOCTL | 34)
#define	ISCSI_DISCOVERY_EVENTS		(ISCSI_IOCTL | 35)
#define	ISCSI_AUTH_SET			(ISCSI_IOCTL | 36)
#define	ISCSI_AUTH_GET			(ISCSI_IOCTL | 37)
#define	ISCSI_AUTH_CLEAR		(ISCSI_IOCTL | 38)
#define	ISCSI_SENDTGTS_GET		(ISCSI_IOCTL | 39)
#define	ISCSI_ISNS_SERVER_ADDR_SET	(ISCSI_IOCTL | 40)
#define	ISCSI_ISNS_SERVER_ADDR_LIST_GET	(ISCSI_IOCTL | 41)
#define	ISCSI_ISNS_SERVER_ADDR_CLEAR	(ISCSI_IOCTL | 42)
#define	ISCSI_ISNS_SERVER_GET		(ISCSI_IOCTL | 43)
#define	ISCSI_GET_CONFIG_SESSIONS	(ISCSI_IOCTL | 44)
#define	ISCSI_SET_CONFIG_SESSIONS	(ISCSI_IOCTL | 45)
#define	ISCSI_INIT_NODE_NAME_SET	(ISCSI_IOCTL | 46)
#define	ISCSI_IS_ACTIVE			(ISCSI_IOCTL | 47)
#define	ISCSI_BOOTPROP_GET		(ISCSI_IOCTL | 48)
#define	ISCSI_SMF_OFFLINE		(ISCSI_IOCTL | 49)
#define	ISCSI_SMF_GET			(ISCSI_IOCTL | 50)
#define	ISCSI_TUNABLE_PARAM_GET		(ISCSI_IOCTL | 51)
#define	ISCSI_TUNABLE_PARAM_SET		(ISCSI_IOCTL | 52)
#define	ISCSI_TARGET_REENUM		(ISCSI_IOCTL | 53)
#define	ISCSI_DB_DUMP			(ISCSI_IOCTL | 100) /* DBG */

/*
 * Misc. defines
 */
#define	ISCSI_CHAP_NAME_LEN			512
#define	ISCSI_CHAP_SECRET_LEN			16
#define	ISCSI_TGT_OID_LIST			0x0001
#define	ISCSI_STATIC_TGT_OID_LIST		0x0002
#define	ISCSI_TGT_PARAM_OID_LIST		0x0004
#define	ISCSI_SESS_PARAM			0x0001
#define	ISCSI_CONN_PARAM			0x0002

/* digest level defines */
#define	ISCSI_DIGEST_NONE		0
#define	ISCSI_DIGEST_CRC32C		1
#define	ISCSI_DIGEST_CRC32C_NONE	2 /* offer both, prefer CRC32C */
#define	ISCSI_DIGEST_NONE_CRC32C	3 /* offer both, prefer None */

/*
 * A last error associated with each target session is returned in the
 * iscsi_target_t structure.
 */
typedef enum iscsi_error {
	NoError, AuthenticationError, LoginParamError, ConnectionReset
} iscsi_error_t;

/*
 * The values associated with each enum is based on the IMA specification.
 */
typedef enum	iSCSIDiscoveryMethod {
	iSCSIDiscoveryMethodUnknown	= 0,
	iSCSIDiscoveryMethodStatic	= 1,
	iSCSIDiscoveryMethodSLP		= 2,
	iSCSIDiscoveryMethodISNS	= 4,
	iSCSIDiscoveryMethodSendTargets	= 8,
	/*
	 * Since there is no specification about boot discovery method,
	 * we should leave a value gap in case of other discovery
	 * methods added.
	 */
	iSCSIDiscoveryMethodBoot	= 128
} iSCSIDiscoveryMethod_t;
#define	ISCSI_ALL_DISCOVERY_METHODS	(iSCSIDiscoveryMethodStatic |	\
					iSCSIDiscoveryMethodSLP |	\
					iSCSIDiscoveryMethodISNS |	\
					iSCSIDiscoveryMethodSendTargets)

/*
 * Before anything can be done to a target it must have an OID.
 */
typedef struct iscsi_oid {
	uint32_t		o_vers;				/* In */
	uchar_t			o_name[ISCSI_MAX_NAME_LEN];	/* In */
	/*
	 * tpgt is only 16 bits per spec.  use 32 in ioctl to reduce
	 * packing issue.  Also -1 tpgt denotes default value.  iSCSI
	 * stack will detemermine tpgt during login.
	 */
	int			o_tpgt;				/* In */
	uint32_t		o_oid;				/* Out */
} iscsi_oid_t;
#define	ISCSI_OID_NOTSET	0
#define	ISCSI_INITIATOR_OID	1	/* Other OIDs follow > 1 */
#define	ISCSI_DEFAULT_TPGT	-1

/*
 * iSCSI Login Parameters - Reference iscsi draft for
 * definitions of the below login params.
 */
typedef struct iscsi_login_params {
	boolean_t	immediate_data;
	boolean_t	initial_r2t;
	int		first_burst_length;	/* range: 512 - 2**24-1 */
	int		max_burst_length;	/* range: 512 - 2**24-1 */
	boolean_t	data_pdu_in_order;
	boolean_t	data_sequence_in_order;
	int		default_time_to_wait;
	int		default_time_to_retain;
	int		header_digest;
	int		data_digest;
	int		max_recv_data_seg_len;	/* range: 512 - 2**24-1 */
	int		max_xmit_data_seg_len;	/* range: 512 - 2**24-1 */
	int		max_connections;
	int		max_outstanding_r2t;
	int		error_recovery_level;
	boolean_t	ifmarker;
	boolean_t	ofmarker;
} iscsi_login_params_t;

#define		ISCSI_TUNABLE_PARAM_RX_TIMEOUT_VALUE		0x0001
#define		ISCSI_TUNABLE_PARAM_CONN_LOGIN_MAX		0x0002
#define		ISCSI_TUNABLE_PARAM_LOGIN_POLLING_DELAY		0x0004

/*
 * Once parameters have been set via ISCSI_SET_PARAM the login is initiated
 * by sending an ISCSI_LOGIN ioctl with the following structure filled in.
 */
typedef struct entry {
	int			e_vers;
	uint32_t		e_oid;
	union {
		struct in_addr		u_in4;
		struct in6_addr		u_in6;
	} e_u;
	/*
	 * e_insize indicates which of the previous structs is valid.
	 */
	int			e_insize;
	int			e_port;
	int			e_tpgt;
	/* e_boot should be true if a boot session is created. */
	boolean_t		e_boot;
} entry_t;

/*
 * Used when setting or gettnig the Initiator Name or Alias.
 */
typedef struct node_name {
	unsigned char		n_name[ISCSI_MAX_NAME_LEN];
	int			n_len;
} node_name_t;

typedef struct	_iSCSIMinMaxValue {
	uint32_t		i_current,
				i_default,
				i_min,
				i_max,
				i_incr;
} iscsi_int_info_t;

typedef struct	_iSCSIBoolValue {
	boolean_t		b_current,
				b_default;
} iscsi_bool_info_t;

typedef struct	_iSCSIParamValueGet {
	boolean_t		v_valid,
				v_settable;
	iscsi_int_info_t	v_integer;
	iscsi_bool_info_t	v_bool;
	uchar_t			v_name[ISCSI_MAX_NAME_LEN];
} iscsi_get_value_t;

typedef struct	_iSCSILoginParamGet {
	uint32_t		g_vers;				/* In */
	uint32_t		g_oid;				/* In */
	uint32_t		g_param;			/* Out */
	iscsi_get_value_t	g_value;			/* Out */
	uint32_t		g_conn_cid;			/* In */

	/*
	 * To indicate whether session or connection related param is
	 * being requested.
	 */
	uint32_t		g_param_type;			/* In */
} iscsi_param_get_t;

typedef struct	iscsi_set_value {
	uint32_t		v_integer;
	boolean_t		v_bool;
	uchar_t			v_name[ISCSI_MAX_NAME_LEN];
} iscsi_set_value_t;

/*
 * All of the members of this structure are set by the user agent and
 * consumed by the driver.
 */
typedef struct	iSCSILoginParamSet {
	uint32_t		s_vers,
				s_oid;
	uint32_t		s_param;
	iscsi_set_value_t	s_value;
} iscsi_param_set_t;

/* Data structure used for tunable object parameters */
typedef struct _iSCSITunableValue {
	uint32_t	v_integer;
	boolean_t	v_bool;
	uchar_t		v_name[ISCSI_MAX_NAME_LEN];
} iscsi_tunable_value_t;

typedef struct iSCSITunalbeParamObject {
	boolean_t		t_set;
	uint32_t		t_oid;
	uint32_t		t_param;
	iscsi_tunable_value_t	t_value;
} iscsi_tunable_object_t;

/*
 * Data in this structure is set by the user agent and consumed by
 * the driver.
 */
typedef struct chap_props {
	uint32_t		c_vers,
				c_retries,
				c_oid;
	unsigned char		c_user[ISCSI_MAX_C_USER_LEN];
	uint32_t		c_user_len;
	unsigned char		c_secret[16];
	uint32_t		c_secret_len;
} iscsi_chap_props_t;

typedef enum	authMethod {
	authMethodNone  = 0x00,
	authMethodCHAP  = 0x01,
	authMethodSRP   = 0x02,
	authMethodKRB5  = 0x04,
	authMethodSPKM1 = 0x08,
	authMethodSPKM2 = 0x10
} authMethod_t;

/*
 * Data in this structure is set by the user agent and consumed by
 * the driver.
 */
typedef struct auth_props {
	uint32_t a_vers;
	uint32_t a_oid;
	boolean_t a_bi_auth;
	authMethod_t a_auth_method;
} iscsi_auth_props_t;

/*
 * Data in this structure is set by the user agent and consumed by
 * the driver.
 */
#define	MAX_RAD_SHARED_SECRET_LEN 128
typedef struct radius_props {
	uint32_t		r_vers;
	uint32_t		r_oid;
	union {
		struct in_addr		u_in4;
		struct in6_addr		u_in6;
	} r_addr;
	/*
	 * r_insize indicates which of the previous structs is valid.
	 */
	int			r_insize;

	uint32_t		r_port;
	uint8_t			r_shared_secret[MAX_RAD_SHARED_SECRET_LEN];
	boolean_t		r_radius_access;
	boolean_t		r_radius_config_valid;
	uint32_t		r_shared_secret_len;
} iscsi_radius_props_t;

typedef struct	_IPAddress {
	union {
		struct in_addr	in4;
		struct in6_addr	in6;
	} i_addr;
	/* i_insize determines which is valid in the union above */
	int			i_insize;
} iscsi_ipaddr_t;

typedef struct	_iSCSITargetAddressKey {
	iscsi_ipaddr_t		a_addr;
	uint32_t		a_port,
				a_oid;
} iscsi_addr_t;

typedef struct	_iSCSITargetAddressKeyProperties {
	uint32_t		al_vers,			/* In */
				al_oid;				/* In */
	uint32_t		al_in_cnt;			/* In */
	uint32_t		al_out_cnt;			/* Out */
	uint32_t		al_tpgt;			/* Out */
	iscsi_addr_t		al_addrs[1];			/* Out */
} iscsi_addr_list_t;

typedef struct	_iSCSITargetProperties {
	uint32_t		p_vers,				/* In */
				p_oid;				/* In */
	uchar_t			p_name[ISCSI_MAX_NAME_LEN];	/* Out */
	uint_t			p_name_len;			/* Out */
	uchar_t			p_alias[ISCSI_MAX_NAME_LEN];	/* Out */
	uint_t			p_alias_len;			/* Out */
	iSCSIDiscoveryMethod_t	p_discovery;			/* Out */
	boolean_t		p_connected;			/* Out */
	uint32_t		p_num_of_connections;		/* Out */
	/* ---- If connected == B_TRUE then lastErr has no meaning. ---- */
	iscsi_error_t		p_last_err;			/* Out */
	/*
	 * Target portal group tag = -1 value means default.
	 */
	int			p_tpgt_conf;			/* Out */
	int			p_tpgt_nego;			/* Out */
	uchar_t			p_isid[ISCSI_ISID_LEN];		/* Out */
	uchar_t			p_reserved[128];
} iscsi_property_t;

typedef struct	_iSCSITargetDeviceList {
	uint32_t		tl_vers,			/* In */
				tl_in_cnt,			/* In */
				tl_tgt_list_type,		/* In */
				tl_out_cnt,			/* Out */
				tl_oid_list[1];			/* Out */
} iscsi_target_list_t;

typedef struct	_iSCSIStaticTargetProperties {
	uint32_t		p_vers,				/* In */
				p_oid;				/* In */
	uchar_t			p_name[ISCSI_MAX_NAME_LEN];	/* Out */
	uint_t			p_name_len;			/* Out */
	iscsi_addr_list_t	p_addr_list;			/* Out */
} iscsi_static_property_t;

typedef enum iscsi_lun_status {
	LunValid, LunDoesNotExist
} iscsi_lun_status_t;

/*
 * SCSI inquiry vendor and product identifier buffer length - these values are
 * defined by the identifier length plus 1 byte for the
 * null termination.
 */
#define	ISCSI_INQ_VID_BUF_LEN		9	/* 8 byte ID */
#define	ISCSI_INQ_PID_BUF_LEN		17	/* 16 byte ID */

typedef struct iscsi_lun_props {
	uint32_t		lp_vers,			/* In */
				lp_tgt_oid,			/* In */
				lp_oid,				/* In */
				lp_num,				/* Out */
				lp_status;			/* Out */
	char			lp_pathname[MAXPATHLEN],	/* Out */
				lp_vid[ISCSI_INQ_VID_BUF_LEN],	/* Out */
				lp_pid[ISCSI_INQ_PID_BUF_LEN];	/* Out */
	time_t			lp_time_online;			/* Out */
} iscsi_lun_props_t;

typedef struct iscsi_if_lun {
	uint32_t		l_tgt_oid,
				l_oid,
				l_num;
} iscsi_if_lun_t;

typedef struct iscsi_lun_list {
	uint32_t		ll_vers;			/* In */
	boolean_t		ll_all_tgts;			/* In */
	uint32_t		ll_tgt_oid,			/* In */
				ll_in_cnt,			/* In */
				ll_out_cnt;			/* Out */
	iscsi_if_lun_t		ll_luns[1];			/* Out */
} iscsi_lun_list_t;

typedef struct iscsi_conn_props {
	uint32_t		cp_vers,			/* In */
				cp_oid,				/* In */
				cp_cid,				/* In */
				cp_sess_oid;			/* In */
	union {
		struct	sockaddr_in	soa4;
		struct	sockaddr_in6	soa6;
	} cp_local;						/* Out */
	union {
		struct	sockaddr_in	soa4;
		struct	sockaddr_in6	soa6;
	} cp_peer;						/* Out */


	iscsi_login_params_t 	cp_params;
	boolean_t 		cp_params_valid;

} iscsi_conn_props_t;

typedef struct iscsi_if_conn {
	uint32_t		c_sess_oid,
				c_oid,
				c_cid;
} iscsi_if_conn_t;

typedef struct iscsi_conn_list {
	uint32_t		cl_vers;			/* In */
	boolean_t		cl_all_sess;			/* In */
	uint32_t		cl_sess_oid,			/* In */
				cl_in_cnt,			/* In */
				cl_out_cnt;			/* Out */
	iscsi_if_conn_t		cl_list[1];			/* Out */
} iscsi_conn_list_t;

typedef enum iSNSDiscoveryMethod {
	iSNSDiscoveryMethodStatic	= 0,
	iSNSDiscoveryMethodDHCP		= 1,
	iSNSDiscoveryMethodSLP		= 2
} isns_method_t;

typedef struct iSCSIDiscoveryProperties {
	uint32_t		vers;
	boolean_t		iSNSDiscoverySettable;
	boolean_t		iSNSDiscoveryEnabled;
	isns_method_t		iSNSDiscoveryMethod;
	unsigned char		iSNSDomainName[256];
	boolean_t		SLPDiscoverySettable;
	boolean_t		SLPDiscoveryEnabled;
	boolean_t		StaticDiscoverySettable;
	boolean_t		StaticDiscoveryEnabled;
	boolean_t		SendTargetsDiscoverySettable;
	boolean_t		SendTargetsDiscoveryEnabled;
} iSCSIDiscoveryProperties_t;

typedef struct iscsi_uscsi {
	uint32_t		iu_vers;
	uint32_t		iu_oid;
	int			iu_tpgt;
	uint32_t		iu_len;
	uint32_t		iu_lun;
	struct uscsi_cmd	iu_ucmd;
} iscsi_uscsi_t;

#if defined(_SYSCALL32)
typedef struct iscsi_uscsi32 {
	uint32_t		iu_vers;
	uint32_t		iu_oid;
	int			iu_tpgt;
	uint32_t		iu_len;
	uint32_t		iu_lun;
	struct uscsi_cmd32	iu_ucmd;
} iscsi_uscsi32_t;
#endif /* _SYSCALL32 */

typedef struct iscsi_sendtgts_entry {
	/* ---- Node name, NULL terminated UTF-8 string ---- */
	uchar_t			ste_name[ISCSI_MAX_NAME_LEN];

	iscsi_addr_t		ste_ipaddr;
	int			ste_tpgt;
} iscsi_sendtgts_entry_t;

typedef struct iscsi_sendtgts_list {
	entry_t			stl_entry;			/* In */
	uint32_t		stl_in_cnt,			/* In */
				stl_out_cnt;			/* Out */
	iscsi_sendtgts_entry_t	stl_list[1];			/* Out */
} iscsi_sendtgts_list_t;

typedef struct iscsi_statictgt_entry {
	entry_t			te_entry;			/* In */
	uchar_t			te_name[ISCSI_MAX_NAME_LEN];	/* In */
} iscsi_target_entry_t;

/* iSNS Draft - section 4.1.1. */
typedef struct isns_portal_group {
	uint8_t pg_iscsi_name[ISCSI_MAX_NAME_LEN];
	union {
		in_addr_t	u_ip4;
		in6_addr_t	u_ip6;
	} pg_ip_addr;
	int	insize;

	in_port_t pg_port;
	uint16_t pg_tag;

	iscsi_ipaddr_t	isns_server_ip;
	uint32_t	isns_server_port;
} isns_portal_group_t;

typedef struct isns_portal_group_list {
	uint32_t		pg_in_cnt,
				pg_out_cnt;
	isns_portal_group_t	pg_list[1];
} isns_portal_group_list_t;

typedef struct isns_server_portal_group_list {
	iscsi_addr_t		    addr;
	isns_portal_group_list_t    addr_port_list;
} isns_server_portal_group_list_t;

#define	ISCSI_MIN_CONFIG_SESSIONS	1
/* lowered max config sessions due to ct_power_cnt >= 0 assert */
#define	ISCSI_MAX_CONFIG_SESSIONS	4

typedef struct iscsi_config_sess {
	uint32_t	ics_ver;
	uint32_t	ics_oid;
	boolean_t	ics_bound;
	uint_t		ics_in;
	uint_t		ics_out;
	iscsi_ipaddr_t	ics_bindings[1];
} iscsi_config_sess_t;

/* iscsi re-enumeration */
typedef struct iscsi_reen {
	uint32_t	re_ver;
	uint32_t	re_oid;
} iscsi_reen_t;

/* iscsi booting prop */
typedef struct iscsi_boot_property {
	node_name_t	ini_name;
	node_name_t	tgt_name;
	iscsi_auth_props_t	auth;
	iscsi_chap_props_t	ini_chap;
	iscsi_chap_props_t	tgt_chap;
	int iscsiboot;
	boolean_t hba_mpxio_enabled;
} iscsi_boot_property_t;

#define	ISCSI_SESSION_CONFIG_SIZE(SIZE)		\
	(sizeof (iscsi_config_sess_t) +		\
	((SIZE - 1) * sizeof (iscsi_ipaddr_t)))

/*
 * Event class and subclass information
 */
#define	EC_ISCSI			"EC_iSCSI"
#define	ESC_ISCSI_STATIC_START		"ESC_static_start"
#define	ESC_ISCSI_STATIC_END		"ESC_static_end"
#define	ESC_ISCSI_SEND_TARGETS_START	"ESC_send_targets_start"
#define	ESC_ISCSI_SEND_TARGETS_END	"ESC_send_targets_end"
#define	ESC_ISCSI_SLP_START		"ESC_slp_start"
#define	ESC_ISCSI_SLP_END		"ESC_slp_end"
#define	ESC_ISCSI_ISNS_START		"ESC_isns_start"
#define	ESC_ISCSI_ISNS_END		"ESC_isns_end"
#define	ESC_ISCSI_PROP_CHANGE		"ESC_prop_change"

#ifdef _KERNEL
/* ---- iscsi_utils.c ---- */
extern int		iscsid_open(char *, int, int);
extern int		iscsid_close(int);
extern int		iscsid_remove(char *filename);
extern int		iscsid_rename(char *oldname, char *newname);
extern ssize_t		iscsid_write(int, void *, ssize_t);
extern ssize_t		iscsid_read(int, void *, ssize_t);
extern ssize_t		iscsid_sendto(struct sonode *, void *, size_t,
    struct sockaddr *, socklen_t);
extern ssize_t		iscsid_recvfrom(struct sonode *, void *buffer,
    size_t len);
extern int		iscsid_errno;
#endif

/*
 * Function prototypes for those routines found in the common code
 */
/* ---- utils.c ---- */
extern boolean_t	utils_iqn_create(char *, int);
extern char		*prt_bitmap(int, char *, char *, int);
extern char		*utils_map_param(int);
extern boolean_t	parse_addr_port_tpgt(char *in, char **addr,
			    int *type, char **port, char **tpgt);

#ifdef __cplusplus
}
#endif

#endif /* _ISCSI_IF_H */
