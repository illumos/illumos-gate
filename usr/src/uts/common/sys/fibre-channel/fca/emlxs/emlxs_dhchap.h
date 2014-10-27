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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_DHCHAP_H
#define	_EMLXS_DHCHAP_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef DHCHAP_SUPPORT
#include <sys/random.h>


/* emlxs_auth_cfg_t */
#define	PASSWORD_TYPE_ASCII	1
#define	PASSWORD_TYPE_BINARY	2
#define	PASSWORD_TYPE_IGNORE	3

#define	AUTH_MODE_DISABLED	1
#define	AUTH_MODE_ACTIVE	2
#define	AUTH_MODE_PASSIVE	3

#define	ELX_DHCHAP		0x01	/* Only one currently supported */
#define	ELX_FCAP		0x02
#define	ELX_FCPAP		0x03
#define	ELX_KERBEROS		0x04

#define	ELX_MD5			0x01
#define	ELX_SHA1		0x02

#define	ELX_GROUP_NULL		0x01
#define	ELX_GROUP_1024		0x02
#define	ELX_GROUP_1280		0x03
#define	ELX_GROUP_1536		0x04
#define	ELX_GROUP_2048		0x05


/* AUTH_ELS Code */
#define	ELS_CMD_AUTH_CODE	0x90

/* AUTH_ELS Flags */

/* state ? */
#define	AUTH_FINISH		0xFF
#define	AUTH_ABORT		0xFE

/* auth_msg code for DHCHAP */
#define	AUTH_REJECT		0x0A
#define	AUTH_NEGOTIATE		0x0B
#define	AUTH_DONE		0x0C
#define	DHCHAP_CHALLENGE	0x10
#define	DHCHAP_REPLY		0x11
#define	DHCHAP_SUCCESS		0x12

/* BIG ENDIAN and LITTLE ENDIAN */

/* authentication protocol identifiers */
#ifdef EMLXS_BIG_ENDIAN

#define	AUTH_DHCHAP		0x00000001
#define	AUTH_FCAP		0x00000002
#define	AUTH_FCPAP		0x00000003
#define	AUTH_KERBEROS		0x00000004

#define	HASH_LIST_TAG		0x0001
#define	DHGID_LIST_TAG		0x0002

/* hash function identifiers */
#define	AUTH_SHA1		0x00000006
#define	AUTH_MD5		0x00000005

/* DHCHAP group ids */
#define	GROUP_NULL		0x00000000
#define	GROUP_1024		0x00000001
#define	GROUP_1280		0x00000002
#define	GROUP_1536		0x00000003
#define	GROUP_2048		0x00000004

/* Tran_id Mask */
#define	AUTH_TRAN_ID_MASK	0x000000FF

#endif	/* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN

#define	AUTH_DHCHAP		0x01000000
#define	AUTH_FCAP		0x02000000
#define	AUTH_FCPAP		0x03000000
#define	AUTH_KERBEROS		0x04000000

#define	HASH_LIST_TAG		0x0100
#define	DHGID_LIST_TAG		0x0200

/* hash function identifiers */
#define	AUTH_SHA1		0x06000000
#define	AUTH_MD5		0x05000000

/* DHCHAP group ids */
#define	GROUP_NULL		0x00000000
#define	GROUP_1024		0x01000000
#define	GROUP_1280		0x02000000
#define	GROUP_1536		0x03000000
#define	GROUP_2048		0x04000000

/* Tran_id Mask */
#define	AUTH_TRAN_ID_MASK	0xFF000000

#endif	/* EMLXS_LITTLE_ENDIAN */

/* hash funcs hash length in byte */
#define	SHA1_LEN		0x00000014	/* 20 bytes */
#define	MD5_LEN			0x00000010	/* 16 bytes */

#define	HBA_SECURITY			0x20

/* AUTH_Reject Reason Codes */
#define	AUTHRJT_FAILURE			0x01
#define	AUTHRJT_LOGIC_ERR		0x02

/* LS_RJT Reason Codes for AUTH_ELS */
#define	LSRJT_AUTH_REQUIRED		0x03
#define	LSRJT_AUTH_LOGICAL_BSY		0x05
#define	LSRJT_AUTH_ELS_NOT_SUPPORTED	0x0B
#define	LSRJT_AUTH_NOT_LOGGED_IN	0x09

/* AUTH_Reject Reason Code Explanations */
#define	AUTHEXP_MECH_UNUSABLE		0x01 /* AUTHRJT_LOGIC_ERR */
#define	AUTHEXP_DHGROUP_UNUSABLE	0x02 /* AUTHRJT_LOGIC_ERR */
#define	AUTHEXP_HASHFUNC_UNUSABLE	0x03 /* AUTHRJT_LOGIC_ERR */
#define	AUTHEXP_AUTHTRAN_STARTED	0x04 /* AUTHRJT_LOGIC_ERR */
#define	AUTHEXP_AUTH_FAILED		0x05 /* AUTHRJT_FAILURE */
#define	AUTHEXP_BAD_PAYLOAD		0x06 /* AUTHRJT_FAILURE */
#define	AUTHEXP_BAD_PROTOCOL		0x07 /* AUTHRJT_FAILURE */
#define	AUTHEXP_RESTART_AUTH		0x08 /* AUTHRJT_LOGIC_ERR */
#define	AUTHEXP_CONCAT_UNSUPP		0x09 /* AUTHRJT_LOGIC_ERR */
#define	AUTHEXP_BAD_PROTOVERS		0x0A /* AUTHRJT_LOGIC_ERR */

/* LS_RJT Reason Code Explanations for AUTH_ELS */
#define	LSEXP_AUTH_REQUIRED		0x48
#define	LSEXP_AUTH_ELS_NOT_SUPPORTED	0x2C
#define	LSEXP_AUTH_ELS_NOT_LOGGED_IN	0x1E
#define	LSEXP_AUTH_LOGICAL_BUSY		0x00


#define	MAX_AUTH_MSA_SIZE 1024

#define	MAX_AUTH_PID 	0x4	/* Max auth proto identifier list */

/* parameter tag */
#define	HASH_LIST	0x0001
#define	DHG_ID_LIST	0x0002

/* name tag from Table 13 v1.8 pp 30 */
#ifdef EMLXS_BIG_ENDIAN
#define	AUTH_NAME_ID		0x0001
#define	AUTH_NAME_LEN		0x0008
#define	AUTH_PROTO_NUM		0x00000001
#define	AUTH_NULL_PARA_LEN	0x00000028
#endif	/* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
#define	AUTH_NAME_ID		0x0100
#define	AUTH_NAME_LEN		0x0800
#define	AUTH_PROTO_NUM		0x01000000
#define	AUTH_NULL_PARA_LEN	0x28000000
#endif	/* EMLXS_LITTLE_ENDIAN */

/* name tag from Table 103 v 1.8 pp 123 */
#define	AUTH_NODE_NAME		0x0002
#define	AUTH_PORT_NAME		0x0003


/* From HBAnyware dfc lib FC-SP */
typedef struct emlxs_auth_cfg
{
	NAME_TYPE		local_entity;	/* host wwpn (NPIV support) */
	NAME_TYPE		remote_entity;	/* switch or target wwpn */
	uint32_t		authentication_timeout;
	uint32_t		authentication_mode;
	uint32_t		bidirectional:1;
	uint32_t		reserved:31;
	uint32_t		authentication_type_priority[4];
	uint32_t		hash_priority[4];
	uint32_t		dh_group_priority[8];
	uint32_t		reauthenticate_time_interval;

	dfc_auth_status_t	auth_status;
	time_t			auth_time;
	struct emlxs_node	*node;

	struct emlxs_auth_cfg	*prev;
	struct emlxs_auth_cfg	*next;
} emlxs_auth_cfg_t;


typedef struct emlxs_auth_key
{
	NAME_TYPE		local_entity;		/* host wwpn */
							/* (NPIV support) */
	NAME_TYPE		remote_entity;		/* switch or target */
							/* wwpn */
	uint16_t		local_password_length;
	uint16_t		local_password_type;
	uint8_t			local_password[128];	/* hba authenticates */
							/* to switch  */
	uint16_t		remote_password_length;
	uint16_t		remote_password_type;
	uint8_t			remote_password[128];	/* hba authenticates */
							/* to switch  */

	struct emlxs_node	*node;

	struct emlxs_auth_key	*prev;
	struct emlxs_auth_key	*next;
} emlxs_auth_key_t;


typedef struct emlxs_auth_misc
{
	uint8_t		bi_cval[20];		/* our challenge for bi-dir */
						/* auth in reply as initiator */
	uint32_t	bi_cval_len;		/* 16 for MD5, 20 for SHA1 */
	uint8_t		pub_key[512];		/* max is 512 bytes value of */
						/* (g^y mod p) */
	uint32_t	pubkey_len;		/* real length of the pub key */
	uint8_t		ses_key[512];		/* session key: value of */
						/* (g^xy mod p) */
	uint32_t	seskey_len;		/* real length of the session */
						/* key */

	/* The following are parameters when host is the responder */
	uint8_t		hrsp_cval[20];		/* challenge value from host */
						/* as responder */
	uint32_t	hrsp_cval_len;		/* host as the responder its */
						/* challenge value len */
	uint8_t		hrsp_priv_key[20];	/* the private key generated */
						/* in host as responder */
	uint8_t		hrsp_pub_key[512];	/* public key calculated when */
						/* host as responder */
	uint32_t	hrsp_pubkey_len;	/* public key length when */
						/* host is responder */
	uint8_t		hrsp_ses_key[512];	/* session key computed when */
						/* host is responder */
	uint32_t	hrsp_seskey_len;	/* session key length when */
						/* host is responder */
} emlxs_auth_misc_t;


/*
 * emlxs_port_dhc struct to be used by emlxs_port_t in emlxs_fc.h
 *
 * This structure contains all the data used by DHCHAP.
 * They are from EMLXSHBA_t in emlxs driver.
 *
 */
typedef struct emlxs_port_dhc
{

	int32_t			state;
#define	ELX_FABRIC_STATE_UNKNOWN	0x00
#define	ELX_FABRIC_AUTH_DISABLED	0x01
#define	ELX_FABRIC_AUTH_FAILED		0x02
#define	ELX_FABRIC_AUTH_SUCCESS		0x03
#define	ELX_FABRIC_IN_AUTH		0x04
#define	ELX_FABRIC_IN_REAUTH		0x05

	dfc_auth_status_t	auth_status;  /* Fabric auth status */
	time_t			auth_time;

} emlxs_port_dhc_t;


/* Node Events */
#define	NODE_EVENT_DEVICE_RM		0x0	/* Auth response timeout and */
						/* fail */
#define	NODE_EVENT_DEVICE_RECOVERY	0x1	/* Auth response timeout and */
						/* recovery */
#define	NODE_EVENT_RCV_AUTH_MSG		0x2	/* Unsolicited Auth received */
#define	NODE_EVENT_CMPL_AUTH_MSG	0x3
#define	NODE_EVENT_MAX_EVENT		0x4

/*
 * emlxs_node_dhc struct to be used in emlxs_node_t.
 * They are from emlxs_nodelist_t in emlxs driver.
 */
typedef struct emlxs_node_dhc
{
	uint16_t		state;		/* used for state machine */
#define	NODE_STATE_UNKNOWN				0x00
#define	NODE_STATE_AUTH_DISABLED 			0x01
#define	NODE_STATE_AUTH_FAILED				0x02
#define	NODE_STATE_AUTH_SUCCESS				0x03
#define	NODE_STATE_AUTH_NEGOTIATE_ISSUE			0x04
#define	NODE_STATE_AUTH_NEGOTIATE_RCV			0x05
#define	NODE_STATE_AUTH_NEGOTIATE_CMPL_WAIT4NEXT	0x06
#define	NODE_STATE_DHCHAP_CHALLENGE_ISSUE		0x07
#define	NODE_STATE_DHCHAP_REPLY_ISSUE			0x08
#define	NODE_STATE_DHCHAP_CHALLENGE_CMPL_WAIT4NEXT	0x09
#define	NODE_STATE_DHCHAP_REPLY_CMPL_WAIT4NEXT		0x0A
#define	NODE_STATE_DHCHAP_SUCCESS_ISSUE			0x0B
#define	NODE_STATE_DHCHAP_SUCCESS_ISSUE_WAIT4NEXT	0x0C
#define	NODE_STATE_DHCHAP_SUCCESS_CMPL_WAIT4NEXT	0x0D
#define	NODE_STATE_NOCHANGE				0xFFFFFFFF

	uint16_t		prev_state;  /* for info only */

	uint32_t		disc_refcnt;

	emlxs_auth_cfg_t	auth_cfg;
	emlxs_auth_key_t	auth_key;

	uint32_t		nlp_authrsp_tmo;	/* Response timeout */
	uint32_t		nlp_authrsp_tmocnt;

	uint32_t		nlp_auth_tranid_ini;	/* tran_id when this */
							/* node is initiator */
	uint32_t		nlp_auth_tranid_rsp;	/* tran_id when this */
							/* node is responder */

	uint32_t		nlp_auth_flag;		/* 1:initiator */
							/* 2:responder */
	uint32_t		nlp_auth_limit;		/* 1: NULL DHCHAP */
							/* 2: full support */

	/* information in DHCHAP_Challenge as the auth responder */
	uint32_t		nlp_auth_hashid;
	uint32_t		nlp_auth_dhgpid;
	uint32_t		nlp_auth_bidir;
	NAME_TYPE		nlp_auth_wwn;

	emlxs_auth_misc_t	nlp_auth_misc;

	uint32_t		nlp_reauth_tmo;
	uint16_t		nlp_reauth_status;
#define	NLP_HOST_REAUTH_DISABLED	0x0
#define	NLP_HOST_REAUTH_ENABLED		0x1
#define	NLP_HOST_REAUTH_IN_PROGRESS	0x2

	uint32_t		nlp_fb_vendor;
#define	NLP_FABRIC_CISCO	0x1
#define	NLP_FABRIC_OTHERS	0x2

	uint32_t		fc_dhchap_success_expected;

	/* hash_id, dhgp_id are set from responder, host is the initiator */
	uint32_t		hash_id;		/* 0x05 for MD5 */
							/* 0x06 for SHA-1 */
	uint32_t		dhgp_id;		/* DH grp identifier */

	uint8_t			bi_cval[20];		/* our challenge for */
							/* bi-dir auth in */
							/* reply as initiator */
	uint32_t		bi_cval_len;		/* 16 for MD5 */
							/* 20 for SHA1 */
	uint8_t			pub_key[512];		/* max is 512 bytes */
							/* value (g^y mod p) */
	uint32_t		pubkey_len;		/* real length of the */
							/* pub key */
	uint8_t			ses_key[512];		/* session key: */
							/* value (g^xy mod p) */
	uint32_t		seskey_len;		/* real length of the */
							/* session key */

	/* The following are parameters when host is the responder */

	uint8_t			hrsp_cval[20];		/* challenge value */
	uint32_t		hrsp_cval_len;		/* challenge value */
							/* length */
	uint8_t			hrsp_priv_key[20];	/* private key */
							/* generated */
	uint8_t			hrsp_pub_key[512];	/* public key */
							/* computed */
	uint32_t		hrsp_pubkey_len;	/* public key length */
	uint8_t			hrsp_ses_key[512];	/* session key */
							/* computed */
	uint32_t		hrsp_seskey_len;	/* session key length */

	uint8_t			*deferred_sbp;		/* Pending IO for */
							/* auth completion */
	uint8_t			*deferred_ubp;

	uint32_t		flag;
#define	NLP_REMOTE_AUTH			0x00000001
#define	NLP_SET_REAUTH_TIME		0x00000002

	emlxs_auth_cfg_t	*parent_auth_cfg;	/* Original auth_cfg */
							/* table entry */
	emlxs_auth_key_t	*parent_auth_key;	/* Original auth_key */
							/* table entry */
} emlxs_node_dhc_t;


/* For NULL DHCHAP with MD5 and SHA-1 */
typedef struct _AUTH_NEGOT_PARAMS_1
{
	uint16_t  name_tag;		/* set to 0x0001 */
	uint16_t  name_len;		/* set to 0x0008 */
	NAME_TYPE nodeName;		/* WWPN */
	uint32_t  proto_num;		/* set to 0x5 */
	uint32_t  para_len;		/* set to 0x28 i.e., 40 bytes */
	uint32_t  proto_id;		/* set to HDCHAP */
	uint16_t  HashList_tag;		/* set to 0x0001 */
	uint16_t  HashList_wcnt;	/* set to 0x0002 i.e. MD5 and SHA-1 */
	uint32_t  HashList_value1;	/* set to MD5 or SHA1 ID 0x00000005,6 */
	uint16_t  DHgIDList_tag;	/* set to 0x0002 */
	uint16_t  DHgIDList_wnt;	/* set to 0x0005 i.e., Full DH groups */
	uint32_t  DHgIDList_g0;		/* set to 0x0000 0000 */
	uint32_t  DHgIDList_g1;		/* set to 0x0000 0001 */
	uint32_t  DHgIDList_g2;		/* set to 0x0000 0002 */
	uint32_t  DHgIDList_g3;		/* set to 0x0000 0003 */
	uint32_t  DHgIDList_g4;		/* set to 0x0000 0004 */
} AUTH_NEGOT_PARAMS_1;


typedef struct _AUTH_NEGOT_PARAMS_2
{
	uint16_t  name_tag;		/* set to 0x0001 */
	uint16_t  name_len;		/* set to 0x0008 */
	NAME_TYPE nodeName;		/* WWPN */
	uint32_t  proto_num;		/* set to 0x5 */
	uint32_t  para_len;		/* set to 0x28 i.e., 40 bytes */
	uint32_t  proto_id;		/* set to HDCHAP */
	uint16_t  HashList_tag;		/* set to 0x0001 */
	uint16_t  HashList_wcnt;	/* set to 0x0002 i.e. MD5 and SHA-1 */
	uint32_t  HashList_value1;	/* set to MD5's   ID 0x00000005 */
	uint32_t  HashList_value2;	/* set to SHA-1's ID 0x00000006 */
	uint16_t  DHgIDList_tag;	/* set to 0x0002 */
	uint16_t  DHgIDList_wnt;	/* set to 0x0005 i.e., Full DH groups */
	uint32_t  DHgIDList_g0;		/* set to 0x0000 0000 */
	uint32_t  DHgIDList_g1;		/* set to 0x0000 0001 */
	uint32_t  DHgIDList_g2;		/* set to 0x0000 0002 */
	uint32_t  DHgIDList_g3;		/* set to 0x0000 0003 */
	uint32_t  DHgIDList_g4;		/* set to 0x0000 0004 */
} AUTH_NEGOT_PARAMS_2;


/* For NULL DHCHAP with MD5 and SHA-1 */
typedef struct _AUTH_NEGOT_PARAMS
{
	uint16_t  name_tag;		/* set to 0x0001 */
	uint16_t  name_len;		/* set to 0x0008 */
	NAME_TYPE nodeName;		/* WWPN */
	uint32_t  proto_num;		/* set to 0x5 */
	uint32_t  para_len;		/* set to 0x28 i.e., 40 bytes */
	uint32_t  proto_id;		/* set to HDCHAP */
	uint16_t  HashList_tag;		/* set to 0x0001 */
	uint16_t  HashList_wcnt;	/* set to 0x0002 i.e. MD5 and SHA-1 */
	uint32_t  HashList_value1;	/* set to MD5's   ID 0x00000005 */
	uint32_t  HashList_value2;	/* set to SHA-1's ID 0x00000006 */
	uint16_t  DHgIDList_tag;	/* set to 0x0002 */
	uint16_t  DHgIDList_wnt;	/* set to 0x0005 i.e., Full DH groups */
	uint32_t  DHgIDList_g0;		/* set to 0x0000 0000 */
	uint32_t  DHgIDList_g1;		/* set to 0x0000 0001 */
	uint32_t  DHgIDList_g2;		/* set to 0x0000 0002 */
	uint32_t  DHgIDList_g3;		/* set to 0x0000 0003 */
	uint32_t  DHgIDList_g4;		/* set to 0x0000 0004 */
} AUTH_NEGOT_PARAMS;

typedef struct _AUTH_NEGOT_PARAMS_NULL_1
{
	uint16_t  name_tag;		/* set to 0x0001 */
	uint16_t  name_len;		/* set to 0x0008 */
	NAME_TYPE nodeName;		/* WWPN */
	uint32_t  proto_num;		/* set to 0x5 */
	uint32_t  para_len;		/* set to 0x28 i.e., 40 bytes */
	uint32_t  proto_id;		/* set to HDCHAP */
	uint16_t  HashList_tag;		/* set to 0x0001 */
	uint16_t  HashList_wcnt;	/* set to 0x0002 i.e. MD5 and SHA-1 */
	uint32_t  HashList_value1;	/* set to MD5's   ID 0x00000005 */
	uint16_t  DHgIDList_tag;	/* set to 0x0002 */
	uint16_t  DHgIDList_wnt;	/* set to 0x0005 i.e., Full DH groups */
	uint32_t  DHgIDList_g0;		/* set to 0x0000 0000 */
} AUTH_NEGOT_PARAMS_NULL_1;

typedef struct _AUTH_NEGOT_PARAMS_NULL_2
{
	uint16_t  name_tag;		/* set to 0x0001 */
	uint16_t  name_len;		/* set to 0x0008 */
	NAME_TYPE nodeName;		/* WWPN */
	uint32_t  proto_num;		/* set to 0x5 */
	uint32_t  para_len;		/* set to 0x28 i.e., 40 bytes */
	uint32_t  proto_id;		/* set to HDCHAP */
	uint16_t  HashList_tag;		/* set to 0x0001 */
	uint16_t  HashList_wcnt;	/* set to 0x0002 i.e. MD5 and SHA-1 */
	uint32_t  HashList_value1;	/* set to MD5's   ID 0x00000005 */
	uint32_t  HashList_value2;
	uint16_t  DHgIDList_tag;	/* set to 0x0002 */
	uint16_t  DHgIDList_wnt;	/* set to 0x0005 i.e., Full DH groups */
	uint32_t  DHgIDList_g0;		/* set to 0x0000 0000 */
} AUTH_NEGOT_PARAMS_NULL_2;


/* Generic AUTH ELS Header */
typedef struct _AUTH_MSG_HDR
{
	/* 20 bytes in total */
	uint8_t		auth_els_code;	/* always 0x90h */
	uint8_t		auth_els_flags;
	uint8_t		auth_msg_code;	/* see above */
	uint8_t		proto_version;
	uint32_t	msg_len;	/* size of msg payload in byte */
	uint32_t	tran_id;
	uint16_t	name_tag;	/* set to 0x0001 */
	uint16_t	name_len;	/* set to 0x0008 */
	NAME_TYPE	nodeName;	/* WWPN */
} AUTH_MSG_HDR;


typedef struct _SHA1_CVAL
{
	uint8_t val[20];
} SHA1_CVAL;


typedef struct _MD5_CVAL
{
	uint8_t	val[16];
} MD5_CVAL;


union challenge_val
{
	SHA1_CVAL	sha1;
	MD5_CVAL	md5;
};


/* DHCHAP_Replay */
typedef struct _DHCHAP_REPLY_HDR
{
	uint8_t  auth_els_code;	/* always 0x90h */
	uint8_t  auth_els_flags;
	uint8_t  auth_msg_code;	/* see above */
	uint8_t  proto_version;
	uint32_t msg_len;	/* size of msg payload in byte */
	uint32_t tran_id;	/* transaction id */
} DHCHAP_REPLY_HDR;


/* DHCHAP_Challenge */
typedef struct _DHCHAP_CHALL_NULL
{
	AUTH_MSG_HDR	msg_hdr;
	uint32_t	hash_id;
	uint32_t	dhgp_id;
	uint32_t	cval_len;
} DHCHAP_CHALL_NULL;

typedef struct _DHCHAP_CHALL
{
	DHCHAP_CHALL_NULL	cnul;
	uint8_t			*dhval;
} DHCHAP_CHALL;

/*
 * size of msg_payload is variable based on the different protocol
 * parameters supported in the driver.
 *
 * For DHCHAP we plan to support NULL, group 1, 2, 3, 4.
 *
 * For NULL DHCHAP protocol only: of these protocol identifiers,
 * we need name_tag = 2 bytes name_len_size = 2 bytes name_len = 8 bytes
 * number of usable auth proto = 4 bytes
 *
 * --------- for example for NULL DHCAHP only --------------------
 * auth proto #1 len = 4 bytes #1 ID  = 4 bytes #1 params = 4 + 16 bytes.
 * ------ Total for NULL DHCHAP = (16 + 12 + 16 ) = 44 bytes.
 *
 * If number of usable auth proto is 5, then we should have 5 auth proto params.
 * assume we are using name_tag 0x0001, then auth name in total = 12 bytes.
 *
 * 12 bytes + 4 bytes = 16 bytes. 4 + 4 + 4 = 12 bytes
 * (num of usable auth proto size = 4
 * auth proto params #1 len size = 4
 * auth prot ID for #1 size  = 4
 *
 * For DHCHAP param: HashList	2 param tag size (set to 0x0001 as HashList)
 * 2 param word cnt size (set to 0x0002 as two hash funcs)
 * 8 for hash ids: MD5 and SHA-1 DHgIDList
 * 2 param tag size (set to 0x0002 as DHgIDList)
 * 2 param word cnt size (set to 0x0005 as NULL and 1/2/3/4 groups) 20 for
 * 5 groups 0x0000 0000 0x0000 0001 0x0000 0002 0x0000 0003 0x0000 0004
 * Total for FULL group support (16 + 12 + 12 + 24 ) = 64 bytes.
 *
 */

typedef struct _AUTH_MSG_NEGOT_1 { /* in Big Endian format */
	uint8_t			auth_els_code;  /* always 0x90h */
	uint8_t			auth_els_flags;
	uint8_t			auth_msg_code;  /* see above */
	uint8_t			proto_version;
	uint32_t		msg_len;	/* size of msg payload */
						/* in byte */
	uint32_t		tran_id;	/* transaction identifier */

	/* anything else is variable in size (bytes) */
	/* uint8_t   msg_payload[MAX_AUTH_MSG_SIZE]; */
	AUTH_NEGOT_PARAMS_1	params;
} AUTH_MSG_NEGOT_1, *PAUTH_MSG_NEGOT_1;


typedef struct _AUTH_MSG_NEGOT_2 { /* in Big Endian format */
	uint8_t			auth_els_code;  /* always 0x90h */
	uint8_t			auth_els_flags;
	uint8_t			auth_msg_code;  /* see above */
	uint8_t			proto_version;
	uint32_t		msg_len;	/* size of msg payload */
						/* in byte */
	uint32_t		tran_id;	/* transaction identifier */

	/* anything else is variable in size (bytes) */
	/* uint8_t   msg_payload[MAX_AUTH_MSG_SIZE]; */
	AUTH_NEGOT_PARAMS_2	params;
} AUTH_MSG_NEGOT_2, *PAUTH_MSG_NEGOT_2;


typedef struct _AUTH_MSG_NEGOT
{
	/* in Big Endian format */
	uint8_t			auth_els_code;	/* always 0x90h */
	uint8_t			auth_els_flags;
	uint8_t			auth_msg_code;	/* see above */
	uint8_t			proto_version;
	uint32_t		msg_len;	/* size of msg payload */
						/* in byte */
	uint32_t		tran_id;	/* transaction identifier */

	/* anything else is variable in size (bytes) */
	/* uint8_t	msg_payload[MAX_AUTH_MSG_SIZE]; */
	AUTH_NEGOT_PARAMS	params;
} AUTH_MSG_NEGOT, *PAUTH_MSG_NEGOT;


/* AUTH_Negotiate msg for NULL DH support only */
typedef struct _AUTH_MSG_NEGOT_NULL
{
	uint8_t  auth_els_code;
	uint8_t  auth_els_flags;
	uint8_t  auth_msg_code;
	uint8_t  proto_version;
	uint32_t msg_len;
	uint32_t tran_id;
} AUTH_MSG_NEGOT_NULL, *PAUTH_MSG_NEGOT_NULL;

typedef struct _AUTH_MSG_NEGOT_NULL_1
{
	uint8_t				auth_els_code;
	uint8_t				auth_els_flags;
	uint8_t				auth_msg_code;
	uint8_t				proto_version;
	uint32_t			msg_len;
	uint32_t			tran_id;

	AUTH_NEGOT_PARAMS_NULL_1	params;

} AUTH_MSG_NEGOT_NULL_1, *PAUTH_MSG_NEGOT_NULL_1;

typedef struct _AUTH_MSG_NEGOT_NULL_2
{
	uint8_t				auth_els_code;
	uint8_t				auth_els_flags;
	uint8_t				auth_msg_code;
	uint8_t				proto_version;
	uint32_t			msg_len;
	uint32_t			tran_id;

	AUTH_NEGOT_PARAMS_NULL_2	params;

} AUTH_MSG_NEGOT_NULL_2, *PAUTH_MSG_NEGOT_NULL_2;


/* auth_els_flags */
#define	AUTH_ELS_FLAGS_MASK	0x0f;


typedef struct _AUTH_RJT
{
	uint8_t  auth_els_code;	/* always 0x90h */
	uint8_t  auth_els_flags;
	uint8_t  auth_msg_code;	/* see above */
	uint8_t  proto_version;
	uint32_t msg_len;	/* size of msg payload in byte */
	uint32_t tran_id;	/* transaction identifier */

	uint8_t  ReasonCode;
	uint8_t  ReasonCodeExplanation;
	uint16_t Reserved;
} AUTH_RJT, *PAUTH_RJT;

typedef struct _DHCHAP_SUCCESS_HDR
{
	uint8_t  auth_els_code;	/* always 0x90h */
	uint8_t  auth_els_flags;
	uint8_t  auth_msg_code;	/* see above */
	uint8_t  proto_version;
	uint32_t msg_len;	/* size of msg payload in byte */
	uint32_t tran_id;	/* transaction identifier */

	uint32_t RspVal_len;
} DHCHAP_SUCCESS_HDR, *PDHCHAP_SUCCESS_HDR;


typedef struct dh_group_st
{
	unsigned long   groupid;
	unsigned long   length;
	unsigned char   value[256];
} DH_GROUP, *PDH_GROUP;

#pragma weak random_get_pseudo_bytes


#endif	/* DHCHAP_SUPPORT */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_DHCHAP_H */
