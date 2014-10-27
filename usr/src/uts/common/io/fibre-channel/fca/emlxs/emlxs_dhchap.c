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

#include <emlxs.h>

#ifdef DHCHAP_SUPPORT

#include <md5.h>
#include <sha1.h>
#include <sys/sha1_consts.h>
#include <bignum.h>
#include <sys/time.h>


#define	RAND

#ifndef ENABLE
#define	ENABLE   1
#endif	/* ENABLE */

#ifndef DISABLE
#define	DISABLE   0
#endif	/* DISABLE */


/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_DHCHAP_C);

static char *emlxs_dhc_pstate_xlate(uint32_t state);
static char *emlxs_dhc_nstate_xlate(uint32_t state);
static uint32_t emlxs_check_dhgp(emlxs_port_t *port, NODELIST *ndlp,
	uint32_t *dh_id, uint16_t cnt, uint32_t *dhgp_id);
static void emlxs_dhc_set_reauth_time(emlxs_port_t *port,
	emlxs_node_t *ndlp, uint32_t status);

static void emlxs_auth_cfg_init(emlxs_hba_t *hba);
static void emlxs_auth_cfg_fini(emlxs_hba_t *hba);
static void emlxs_auth_cfg_read(emlxs_hba_t *hba);
static uint32_t emlxs_auth_cfg_parse(emlxs_hba_t *hba,
	emlxs_auth_cfg_t *config, char *prop_str);
static emlxs_auth_cfg_t *emlxs_auth_cfg_get(emlxs_hba_t *hba,
	uint8_t *lwwpn, uint8_t *rwwpn);
static emlxs_auth_cfg_t *emlxs_auth_cfg_create(emlxs_hba_t *hba,
	uint8_t *lwwpn, uint8_t *rwwpn);
static void emlxs_auth_cfg_destroy(emlxs_hba_t *hba,
	emlxs_auth_cfg_t *auth_cfg);
static void emlxs_auth_cfg_print(emlxs_hba_t *hba,
	emlxs_auth_cfg_t *auth_cfg);

static void emlxs_auth_key_init(emlxs_hba_t *hba);
static void emlxs_auth_key_fini(emlxs_hba_t *hba);
static void emlxs_auth_key_read(emlxs_hba_t *hba);
static uint32_t emlxs_auth_key_parse(emlxs_hba_t *hba,
	emlxs_auth_key_t *auth_key, char *prop_str);
static emlxs_auth_key_t *emlxs_auth_key_get(emlxs_hba_t *hba,
	uint8_t *lwwpn, uint8_t *rwwpn);
static emlxs_auth_key_t *emlxs_auth_key_create(emlxs_hba_t *hba,
	uint8_t *lwwpn, uint8_t *rwwpn);
static void emlxs_auth_key_destroy(emlxs_hba_t *hba,
	emlxs_auth_key_t *auth_key);
static void emlxs_auth_key_print(emlxs_hba_t *hba,
	emlxs_auth_key_t *auth_key);

static void emlxs_get_random_bytes(NODELIST *ndlp, uint8_t *rdn,
	uint32_t len);
static emlxs_auth_cfg_t *emlxs_auth_cfg_find(emlxs_port_t *port,
	uint8_t *rwwpn);
static emlxs_auth_key_t *emlxs_auth_key_find(emlxs_port_t *port,
	uint8_t *rwwpn);
static void emlxs_dhc_auth_complete(emlxs_port_t *port,
	emlxs_node_t *ndlp, uint32_t status);
static void emlxs_log_auth_event(emlxs_port_t *port, NODELIST *ndlp,
	char *subclass, char *info);
static int emlxs_issue_auth_negotiate(emlxs_port_t *port,
	emlxs_node_t *ndlp, uint8_t retry);
static void emlxs_cmpl_auth_negotiate_issue(fc_packet_t *pkt);
static uint32_t *emlxs_hash_rsp(emlxs_port_t *port,
	emlxs_port_dhc_t *port_dhc, NODELIST *ndlp, uint32_t tran_id,
	union challenge_val un_cval, uint8_t *dhval, uint32_t dhvallen);
static fc_packet_t *emlxs_prep_els_fc_pkt(emlxs_port_t *port,
	uint32_t d_id, uint32_t cmd_size, uint32_t rsp_size,
	uint32_t datalen, int32_t sleepflag);

static uint32_t *emlxs_hash_vrf(emlxs_port_t *port,
	emlxs_port_dhc_t *port_dhc, NODELIST *ndlp, uint32_t tran_id,
	union challenge_val un_cval);


static BIG_ERR_CODE
emlxs_interm_hash(emlxs_port_t *port, emlxs_port_dhc_t *port_dhc,
	NODELIST *ndlp, void *hash_val, uint32_t tran_id,
	union challenge_val un_cval, uint8_t *dhval, uint32_t *);

static BIG_ERR_CODE
emlxs_BIGNUM_get_pubkey(emlxs_port_t *port, emlxs_port_dhc_t *port_dhc,
	NODELIST *ndlp, uint8_t *dhval, uint32_t *dhvallen,
	uint32_t hash_size, uint32_t dhgp_id);
static BIG_ERR_CODE
emlxs_BIGNUM_get_dhval(emlxs_port_t *port, emlxs_port_dhc_t *port_dhc,
	NODELIST *ndlp, uint8_t *dhval, uint32_t *dhval_len,
	uint32_t dhgp_id, uint8_t *priv_key, uint32_t privkey_len);
static uint32_t *
emlxs_hash_verification(emlxs_port_t *port, emlxs_port_dhc_t *port_dhc,
	NODELIST *ndlp, uint32_t tran_id, uint8_t *dhval,
	uint32_t dhval_len, uint32_t flag, uint8_t *bi_cval);

static uint32_t *
emlxs_hash_get_R2(emlxs_port_t *port, emlxs_port_dhc_t *port_dhc,
	NODELIST *ndlp, uint32_t tran_id, uint8_t *dhval,
	uint32_t dhval_len, uint32_t flag, uint8_t *bi_cval);

static uint32_t emlxs_issue_auth_reject(emlxs_port_t *port,
	NODELIST *ndlp, int retry, uint32_t *arg, uint8_t ReasonCode,
	uint8_t ReasonCodeExplanation);

static uint32_t emlxs_disc_neverdev(emlxs_port_t *port, void *arg1,
	void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_rcv_auth_msg_unmapped_node(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_rcv_auth_msg_npr_node(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_cmpl_auth_msg_npr_node(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_rcv_auth_msg_auth_negotiate_issue(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_cmpl_auth_msg_auth_negotiate_issue(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_rcv_auth_msg_auth_negotiate_rcv(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_cmpl_auth_msg_auth_negotiate_rcv(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_rcv_auth_msg_auth_negotiate_cmpl_wait4next(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_cmpl_auth_msg_auth_negotiate_cmpl_wait4next(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_rcv_auth_msg_dhchap_challenge_issue(emlxs_port_t *port, void *arg1,
	void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_cmpl_auth_msg_dhchap_challenge_issue(emlxs_port_t *port, void *arg1,
	void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_rcv_auth_msg_dhchap_reply_issue(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_cmpl_auth_msg_dhchap_reply_issue(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_rcv_auth_msg_dhchap_challenge_cmpl_wait4next(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_cmpl_auth_msg_dhchap_challenge_cmpl_wait4next(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_rcv_auth_msg_dhchap_reply_cmpl_wait4next(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_cmpl_auth_msg_dhchap_reply_cmpl_wait4next(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_rcv_auth_msg_dhchap_success_issue(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_cmpl_auth_msg_dhchap_success_issue(emlxs_port_t *port, void *arg1,
	void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_rcv_auth_msg_dhchap_success_issue_wait4next(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_cmpl_auth_msg_dhchap_success_issue_wait4next(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_rcv_auth_msg_dhchap_success_cmpl_wait4next(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t
emlxs_cmpl_auth_msg_dhchap_success_cmpl_wait4next(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);


static uint32_t emlxs_device_recov_unmapped_node(emlxs_port_t *port,
	void *arg1, void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_device_rm_npr_node(emlxs_port_t *port, void *arg1,
	void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_device_recov_npr_node(emlxs_port_t *port, void *arg1,
	void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_device_rem_auth(emlxs_port_t *port, void *arg1,
	void *arg2, void *arg3, void *arg4, uint32_t evt);
static uint32_t emlxs_device_recov_auth(emlxs_port_t *port, void *arg1,
	void *arg2, void *arg3, void *arg4, uint32_t evt);

static uint8_t emlxs_null_wwn[8] =
	{0, 0, 0, 0, 0, 0, 0, 0};
static uint8_t emlxs_fabric_wwn[8] =
	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

unsigned char dhgp1_pVal[] =
{0xEE, 0xAF, 0x0A, 0xB9, 0xAD, 0xB3, 0x8D, 0xD6, 0x9C, 0x33, 0xF8, 0x0A, 0xFA,
0x8F, 0xC5, 0xE8,
0x60, 0x72, 0x61, 0x87, 0x75, 0xFF, 0x3C, 0x0B, 0x9E, 0xA2, 0x31, 0x4C, 0x9C,
0x25, 0x65, 0x76,
0xD6, 0x74, 0xDF, 0x74, 0x96, 0xEA, 0x81, 0xD3, 0x38, 0x3B, 0x48, 0x13, 0xD6,
0x92, 0xC6, 0xE0,
0xE0, 0xD5, 0xD8, 0xE2, 0x50, 0xB9, 0x8B, 0xE4, 0x8E, 0x49, 0x5C, 0x1D, 0x60,
0x89, 0xDA, 0xD1,
0x5D, 0xC7, 0xD7, 0xB4, 0x61, 0x54, 0xD6, 0xB6, 0xCE, 0x8E, 0xF4, 0xAD, 0x69,
0xB1, 0x5D, 0x49,
0x82, 0x55, 0x9B, 0x29, 0x7B, 0xCF, 0x18, 0x85, 0xC5, 0x29, 0xF5, 0x66, 0x66,
0x0E, 0x57, 0xEC,
0x68, 0xED, 0xBC, 0x3C, 0x05, 0x72, 0x6C, 0xC0, 0x2F, 0xD4, 0xCB, 0xF4, 0x97,
0x6E, 0xAA, 0x9A,
0xFD, 0x51, 0x38, 0xFE, 0x83, 0x76, 0x43, 0x5B, 0x9F, 0xC6, 0x1D, 0x2F, 0xC0,
0xEB, 0x06, 0xE3,
};

unsigned char dhgp2_pVal[] =
{0xD7, 0x79, 0x46, 0x82, 0x6E, 0x81, 0x19, 0x14, 0xB3, 0x94, 0x01, 0xD5, 0x6A,
0x0A, 0x78, 0x43,
0xA8, 0xE7, 0x57, 0x5D, 0x73, 0x8C, 0x67, 0x2A, 0x09, 0x0A, 0xB1, 0x18, 0x7D,
0x69, 0x0D, 0xC4,
0x38, 0x72, 0xFC, 0x06, 0xA7, 0xB6, 0xA4, 0x3F, 0x3B, 0x95, 0xBE, 0xAE, 0xC7,
0xDF, 0x04, 0xB9,
0xD2, 0x42, 0xEB, 0xDC, 0x48, 0x11, 0x11, 0x28, 0x32, 0x16, 0xCE, 0x81, 0x6E,
0x00, 0x4B, 0x78,
0x6C, 0x5F, 0xCE, 0x85, 0x67, 0x80, 0xD4, 0x18, 0x37, 0xD9, 0x5A, 0xD7, 0x87,
0xA5, 0x0B, 0xBE,
0x90, 0xBD, 0x3A, 0x9C, 0x98, 0xAC, 0x0F, 0x5F, 0xC0, 0xDE, 0x74, 0x4B, 0x1C,
0xDE, 0x18, 0x91,
0x69, 0x08, 0x94, 0xBC, 0x1F, 0x65, 0xE0, 0x0D, 0xE1, 0x5B, 0x4B, 0x2A, 0xA6,
0xD8, 0x71, 0x00,
0xC9, 0xEC, 0xC2, 0x52, 0x7E, 0x45, 0xEB, 0x84, 0x9D, 0xEB, 0x14, 0xBB, 0x20,
0x49, 0xB1, 0x63,
0xEA, 0x04, 0x18, 0x7F, 0xD2, 0x7C, 0x1B, 0xD9, 0xC7, 0x95, 0x8C, 0xD4, 0x0C,
0xE7, 0x06, 0x7A,
0x9C, 0x02, 0x4F, 0x9B, 0x7C, 0x5A, 0x0B, 0x4F, 0x50, 0x03, 0x68, 0x61, 0x61,
0xF0, 0x60, 0x5B
};

unsigned char dhgp3_pVal[] =
{0x9D, 0xEF, 0x3C, 0xAF, 0xB9, 0x39, 0x27, 0x7A, 0xB1, 0xF1, 0x2A, 0x86, 0x17,
0xA4, 0x7B, 0xBB,
0xDB, 0xA5, 0x1D, 0xF4, 0x99, 0xAC, 0x4C, 0x80, 0xBE, 0xEE, 0xA9, 0x61, 0x4B,
0x19, 0xCC, 0x4D,
0x5F, 0x4F, 0x5F, 0x55, 0x6E, 0x27, 0xCB, 0xDE, 0x51, 0xC6, 0xA9, 0x4B, 0xE4,
0x60, 0x7A, 0x29,
0x15, 0x58, 0x90, 0x3B, 0xA0, 0xD0, 0xF8, 0x43, 0x80, 0xB6, 0x55, 0xBB, 0x9A,
0x22, 0xE8, 0xDC,
0xDF, 0x02, 0x8A, 0x7C, 0xEC, 0x67, 0xF0, 0xD0, 0x81, 0x34, 0xB1, 0xC8, 0xB9,
0x79, 0x89, 0x14,
0x9B, 0x60, 0x9E, 0x0B, 0xE3, 0xBA, 0xB6, 0x3D, 0x47, 0x54, 0x83, 0x81, 0xDB,
0xC5, 0xB1, 0xFC,
0x76, 0x4E, 0x3F, 0x4B, 0x53, 0xDD, 0x9D, 0xA1, 0x15, 0x8B, 0xFD, 0x3E, 0x2B,
0x9C, 0x8C, 0xF5,
0x6E, 0xDF, 0x01, 0x95, 0x39, 0x34, 0x96, 0x27, 0xDB, 0x2F, 0xD5, 0x3D, 0x24,
0xB7, 0xC4, 0x86,
0x65, 0x77, 0x2E, 0x43, 0x7D, 0x6C, 0x7F, 0x8C, 0xE4, 0x42, 0x73, 0x4A, 0xF7,
0xCC, 0xB7, 0xAE,
0x83, 0x7C, 0x26, 0x4A, 0xE3, 0xA9, 0xBE, 0xB8, 0x7F, 0x8A, 0x2F, 0xE9, 0xB8,
0xB5, 0x29, 0x2E,
0x5A, 0x02, 0x1F, 0xFF, 0x5E, 0x91, 0x47, 0x9E, 0x8C, 0xE7, 0xA2, 0x8C, 0x24,
0x42, 0xC6, 0xF3,
0x15, 0x18, 0x0F, 0x93, 0x49, 0x9A, 0x23, 0x4D, 0xCF, 0x76, 0xE3, 0xFE, 0xD1,
0x35, 0xF9, 0xBB
};

unsigned char dhgp4_pVal[] =
{0xAC, 0x6B, 0xDB, 0x41, 0x32, 0x4A, 0x9A, 0x9B, 0xF1, 0x66, 0xDE, 0x5E, 0x13,
0x89, 0x58, 0x2F,
0xAF, 0x72, 0xB6, 0x65, 0x19, 0x87, 0xEE, 0x07, 0xFC, 0x31, 0x92, 0x94, 0x3D,
0xB5, 0x60, 0x50,
0xA3, 0x73, 0x29, 0xCB, 0xB4, 0xA0, 0x99, 0xED, 0x81, 0x93, 0xE0, 0x75, 0x77,
0x67, 0xA1, 0x3D,
0xD5, 0x23, 0x12, 0xAB, 0x4B, 0x03, 0x31, 0x0D, 0xCD, 0x7F, 0x48, 0xA9, 0xDA,
0x04, 0xFD, 0x50,
0xE8, 0x08, 0x39, 0x69, 0xED, 0xB7, 0x67, 0xB0, 0xCF, 0x60, 0x95, 0x17, 0x9A,
0x16, 0x3A, 0xB3,
0x66, 0x1A, 0x05, 0xFB, 0xD5, 0xFA, 0xAA, 0xE8, 0x29, 0x18, 0xA9, 0x96, 0x2F,
0x0B, 0x93, 0xB8,
0x55, 0xF9, 0x79, 0x93, 0xEC, 0x97, 0x5E, 0xEA, 0xA8, 0x0D, 0x74, 0x0A, 0xDB,
0xF4, 0xFF, 0x74,
0x73, 0x59, 0xD0, 0x41, 0xD5, 0xC3, 0x3E, 0xA7, 0x1D, 0x28, 0x1E, 0x44, 0x6B,
0x14, 0x77, 0x3B,
0xCA, 0x97, 0xB4, 0x3A, 0x23, 0xFB, 0x80, 0x16, 0x76, 0xBD, 0x20, 0x7A, 0x43,
0x6C, 0x64, 0x81,
0xF1, 0xD2, 0xB9, 0x07, 0x87, 0x17, 0x46, 0x1A, 0x5B, 0x9D, 0x32, 0xE6, 0x88,
0xF8, 0x77, 0x48,
0x54, 0x45, 0x23, 0xB5, 0x24, 0xB0, 0xD5, 0x7D, 0x5E, 0xA7, 0x7A, 0x27, 0x75,
0xD2, 0xEC, 0xFA,
0x03, 0x2C, 0xFB, 0xDB, 0xF5, 0x2F, 0xB3, 0x78, 0x61, 0x60, 0x27, 0x90, 0x04,
0xE5, 0x7A, 0xE6,
0xAF, 0x87, 0x4E, 0x73, 0x03, 0xCE, 0x53, 0x29, 0x9C, 0xCC, 0x04, 0x1C, 0x7B,
0xC3, 0x08, 0xD8,
0x2A, 0x56, 0x98, 0xF3, 0xA8, 0xD0, 0xC3, 0x82, 0x71, 0xAE, 0x35, 0xF8, 0xE9,
0xDB, 0xFB, 0xB6,
0x94, 0xB5, 0xC8, 0x03, 0xD8, 0x9F, 0x7A, 0xE4, 0x35, 0xDE, 0x23, 0x6D, 0x52,
0x5F, 0x54, 0x75,
0x9B, 0x65, 0xE3, 0x72, 0xFC, 0xD6, 0x8E, 0xF2, 0x0F, 0xA7, 0x11, 0x1F, 0x9E,
0x4A, 0xFF, 0x73
};

/*
 * myrand is used for test only, eventually it should be replaced by the random
 * number. AND it is basically the private key.
 */
/* #define	MYRAND */
#ifdef MYRAND
unsigned char myrand[] =
{0x11, 0x11, 0x22, 0x22,
	0x33, 0x33, 0x44, 0x44,
	0x55, 0x55, 0x66, 0x66,
	0x77, 0x77, 0x88, 0x88,
0x99, 0x99, 0x00, 0x00};
#endif	/* MYRAND */




/* Node Events */
#define	NODE_EVENT_DEVICE_RM	0x0 /* Auth response timeout & fail */
#define	NODE_EVENT_DEVICE_RECOVERY 0x1 /* Auth response timeout & recovery */
#define	NODE_EVENT_RCV_AUTH_MSG	 0x2 /* Unsolicited Auth received */
#define	NODE_EVENT_CMPL_AUTH_MSG 0x3
#define	NODE_EVENT_MAX_EVENT	 0x4

emlxs_table_t emlxs_event_table[] =
{
	{NODE_EVENT_DEVICE_RM, "DEVICE_REMOVE"},
	{NODE_EVENT_DEVICE_RECOVERY, "DEVICE_RECOVERY"},
	{NODE_EVENT_RCV_AUTH_MSG, "AUTH_MSG_RCVD"},
	{NODE_EVENT_CMPL_AUTH_MSG, "AUTH_MSG_CMPL"},

};	/* emlxs_event_table() */

emlxs_table_t emlxs_pstate_table[] =
{
	{ELX_FABRIC_STATE_UNKNOWN, "FABRIC_STATE_UNKNOWN"},
	{ELX_FABRIC_AUTH_DISABLED, "FABRIC_AUTH_DISABLED"},
	{ELX_FABRIC_AUTH_FAILED, "FABRIC_AUTH_FAILED"},
	{ELX_FABRIC_AUTH_SUCCESS, "FABRIC_AUTH_SUCCESS"},
	{ELX_FABRIC_IN_AUTH, "FABRIC_IN_AUTH"},
	{ELX_FABRIC_IN_REAUTH, "FABRIC_IN_REAUTH"},

};	/* emlxs_pstate_table() */

emlxs_table_t emlxs_nstate_table[] =
{
{NODE_STATE_UNKNOWN, "STATE_UNKNOWN"},
{NODE_STATE_AUTH_DISABLED, "AUTH_DISABLED"},
{NODE_STATE_AUTH_FAILED, "AUTH_FAILED"},
{NODE_STATE_AUTH_SUCCESS, "AUTH_SUCCESS"},
{NODE_STATE_AUTH_NEGOTIATE_ISSUE, "NEGOTIATE_ISSUE"},
{NODE_STATE_AUTH_NEGOTIATE_RCV, "NEGOTIATE_RCV"},
{NODE_STATE_AUTH_NEGOTIATE_CMPL_WAIT4NEXT, "NEGOTIATE_CMPL"},
{NODE_STATE_DHCHAP_CHALLENGE_ISSUE, "DHCHAP_CHALLENGE_ISSUE"},
{NODE_STATE_DHCHAP_REPLY_ISSUE, "DHCHAP_REPLY_ISSUE"},
{NODE_STATE_DHCHAP_CHALLENGE_CMPL_WAIT4NEXT, "DHCHAP_CHALLENGE_CMPL"},
{NODE_STATE_DHCHAP_REPLY_CMPL_WAIT4NEXT, "DHCHAP_REPLY_CMPL"},
{NODE_STATE_DHCHAP_SUCCESS_ISSUE, "DHCHAP_SUCCESS_ISSUE"},
{NODE_STATE_DHCHAP_SUCCESS_ISSUE_WAIT4NEXT, "DHCHAP_SUCCESS_ISSUE_WAIT"},
{NODE_STATE_DHCHAP_SUCCESS_CMPL_WAIT4NEXT, "DHCHAP_SUCCESS_CMPL"},
};	/* emlxs_nstate_table() */

extern char *
emlxs_dhc_event_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_event_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_event_table[i].code) {
			return (emlxs_event_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "event=0x%x", state);
	return (buffer);

} /* emlxs_dhc_event_xlate() */


extern void
emlxs_dhc_state(emlxs_port_t *port, emlxs_node_t *ndlp, uint32_t state,
	uint32_t reason, uint32_t explaination)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_dhc_t *port_dhc = &port->port_dhc;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint32_t pstate;

	if ((state != NODE_STATE_NOCHANGE) && (node_dhc->state != state)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_state_msg,
		    "Node:0x%x %s --> %s", ndlp->nlp_DID,
		    emlxs_dhc_nstate_xlate(node_dhc->state),
		    emlxs_dhc_nstate_xlate(state));

		node_dhc->prev_state = node_dhc->state;
		node_dhc->state = (uint16_t)state;

		/* Perform common functions based on state */
		switch (state) {
		case NODE_STATE_UNKNOWN:
		case NODE_STATE_AUTH_DISABLED:
			node_dhc->nlp_authrsp_tmo = 0;
			node_dhc->nlp_authrsp_tmocnt = 0;
			emlxs_dhc_set_reauth_time(port, ndlp, DISABLE);
			break;

		case NODE_STATE_AUTH_SUCCESS:
			/* Record auth time */
			if (ndlp->nlp_DID == FABRIC_DID) {
				port_dhc->auth_time = DRV_TIME;
			} else if (node_dhc->parent_auth_cfg) {
				node_dhc->parent_auth_cfg->auth_time = DRV_TIME;
			}
			hba->rdn_flag = 0;
			node_dhc->nlp_authrsp_tmo = 0;

			if (node_dhc->flag & NLP_SET_REAUTH_TIME) {
				emlxs_dhc_set_reauth_time(port, ndlp, ENABLE);
			}
			break;

		default:
			break;
		}

		/* Check for switch port */
		if (ndlp->nlp_DID == FABRIC_DID) {
			switch (state) {
			case NODE_STATE_UNKNOWN:
				pstate = ELX_FABRIC_STATE_UNKNOWN;
				break;

			case NODE_STATE_AUTH_DISABLED:
				pstate = ELX_FABRIC_AUTH_DISABLED;
				break;

			case NODE_STATE_AUTH_FAILED:
				pstate = ELX_FABRIC_AUTH_FAILED;
				break;

			case NODE_STATE_AUTH_SUCCESS:
				pstate = ELX_FABRIC_AUTH_SUCCESS;
				break;

				/* Auth active */
			default:
				if (port_dhc->state ==
				    ELX_FABRIC_AUTH_SUCCESS) {
					pstate = ELX_FABRIC_IN_REAUTH;
				} else if (port_dhc->state !=
				    ELX_FABRIC_IN_REAUTH) {
					pstate = ELX_FABRIC_IN_AUTH;
				}
				break;
			}

			if (port_dhc->state != pstate) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_state_msg,
				    "Port: %s --> %s",
				    emlxs_dhc_pstate_xlate(port_dhc->state),
				    emlxs_dhc_pstate_xlate(pstate));

				port_dhc->state = pstate;
			}
		}
	}
	/* Update auth status */
	mutex_enter(&hba->auth_lock);
	emlxs_dhc_status(port, ndlp, reason, explaination);
	mutex_exit(&hba->auth_lock);

	return;

} /* emlxs_dhc_state() */


/* auth_lock must be held when calling this */
extern void
emlxs_dhc_status(emlxs_port_t *port, emlxs_node_t *ndlp, uint32_t reason,
	uint32_t explaination)
{
	emlxs_port_dhc_t *port_dhc;
	emlxs_node_dhc_t *node_dhc;
	dfc_auth_status_t *auth_status;
	uint32_t drv_time;

	if (!ndlp || !ndlp->nlp_active || ndlp->node_dhc.state ==
	    NODE_STATE_UNKNOWN) {
		return;
	}
	port_dhc = &port->port_dhc;
	node_dhc = &ndlp->node_dhc;

	/* Get auth status object */
	if (ndlp->nlp_DID == FABRIC_DID) {
		auth_status = &port_dhc->auth_status;
	} else if (node_dhc->parent_auth_cfg) {
		auth_status = &node_dhc->parent_auth_cfg->auth_status;
	} else {
		/* No auth status to be updated */
		return;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_status_msg,
	    "Node:0x%x state=%s rsn=0x%x exp=0x%x (%x,%x)",
	    ndlp->nlp_DID, emlxs_dhc_nstate_xlate(node_dhc->state), reason,
	    explaination, auth_status->auth_state,
	    auth_status->auth_failReason);

	/* Set state and auth_failReason */
	switch (node_dhc->state) {
	case NODE_STATE_UNKNOWN:	/* Connection */
		if (auth_status->auth_state != DFC_AUTH_STATE_FAILED) {
			auth_status->auth_state = DFC_AUTH_STATE_OFF;
			auth_status->auth_failReason = 0;
		}
		break;

	case NODE_STATE_AUTH_DISABLED:
		auth_status->auth_state = DFC_AUTH_STATE_OFF;
		auth_status->auth_failReason = 0;
		break;

	case NODE_STATE_AUTH_FAILED:
		/* Check failure reason and update if neccessary */
		switch (reason) {
		case AUTHRJT_FAILURE:	/* 0x01 */
		case AUTHRJT_LOGIC_ERR:	/* 0x02 */
			auth_status->auth_state = DFC_AUTH_STATE_FAILED;
			auth_status->auth_failReason = DFC_AUTH_FAIL_REJECTED;
			break;

		case LSRJT_AUTH_REQUIRED:	/* 0x03 */
			switch (explaination) {
			case LSEXP_AUTH_REQUIRED:
				auth_status->auth_state = DFC_AUTH_STATE_FAILED;
				auth_status->auth_failReason =
				    DFC_AUTH_FAIL_LS_RJT;
				break;
			default:
				auth_status->auth_state = DFC_AUTH_STATE_FAILED;
				auth_status->auth_failReason =
				    DFC_AUTH_FAIL_REJECTED;
			}
			break;

		case LSRJT_AUTH_LOGICAL_BSY:	/* 0x05 */
			auth_status->auth_state = DFC_AUTH_STATE_FAILED;
			auth_status->auth_failReason = DFC_AUTH_FAIL_BSY_LS_RJT;
			break;

		case LSRJT_AUTH_ELS_NOT_SUPPORTED:	/* 0x0B */
			auth_status->auth_state = DFC_AUTH_STATE_FAILED;
			auth_status->auth_failReason = DFC_AUTH_FAIL_LS_RJT;
			break;

		case LSRJT_AUTH_NOT_LOGGED_IN:	/* 0x09 */
			auth_status->auth_state = DFC_AUTH_STATE_FAILED;
			auth_status->auth_failReason = DFC_AUTH_FAIL_BSY_LS_RJT;
			break;
		}

		/* Make sure the state is set to failed at this point */
		if (auth_status->auth_state != DFC_AUTH_STATE_FAILED) {
			auth_status->auth_state = DFC_AUTH_STATE_FAILED;
			auth_status->auth_failReason = DFC_AUTH_FAIL_GENERIC;
		}
		break;

	case NODE_STATE_AUTH_SUCCESS:
		auth_status->auth_state = DFC_AUTH_STATE_ON;
		auth_status->auth_failReason = 0;
		break;

		/* Authentication currently active */
	default:
		/* Set defaults */
		auth_status->auth_state = DFC_AUTH_STATE_INP;
		auth_status->auth_failReason = 0;

		/* Check codes for exceptions */
		switch (reason) {
		case AUTHRJT_FAILURE:	/* 0x01 */
			switch (explaination) {
			case AUTHEXP_AUTH_FAILED:	/* 0x05 */
			case AUTHEXP_BAD_PAYLOAD:	/* 0x06 */
			case AUTHEXP_BAD_PROTOCOL:	/* 0x07 */
				auth_status->auth_state = DFC_AUTH_STATE_FAILED;
				auth_status->auth_failReason =
				    DFC_AUTH_FAIL_REJECTED;
				break;
			}
			break;

		case AUTHRJT_LOGIC_ERR:	/* 0x02 */
			switch (explaination) {
			case AUTHEXP_MECH_UNUSABLE:	/* 0x01 */
			case AUTHEXP_DHGROUP_UNUSABLE:	/* 0x02 */
			case AUTHEXP_HASHFUNC_UNUSABLE:	/* 0x03 */
			case AUTHEXP_CONCAT_UNSUPP:	/* 0x09 */
			case AUTHEXP_BAD_PROTOVERS:	/* 0x0A */
				auth_status->auth_state = DFC_AUTH_STATE_FAILED;
				auth_status->auth_failReason =
				    DFC_AUTH_FAIL_REJECTED;
				break;
			}
			break;

		case LSRJT_AUTH_REQUIRED:	/* 0x03 */
			switch (explaination) {
			case LSEXP_AUTH_REQUIRED:
				auth_status->auth_state = DFC_AUTH_STATE_FAILED;
				auth_status->auth_failReason =
				    DFC_AUTH_FAIL_LS_RJT;
				break;
			}
			break;

		case LSRJT_AUTH_LOGICAL_BSY:	/* 0x05 */
			auth_status->auth_state = DFC_AUTH_STATE_FAILED;
			auth_status->auth_failReason = DFC_AUTH_FAIL_BSY_LS_RJT;
			break;

		case LSRJT_AUTH_ELS_NOT_SUPPORTED:	/* 0x0B */
			auth_status->auth_state = DFC_AUTH_STATE_FAILED;
			auth_status->auth_failReason = DFC_AUTH_FAIL_LS_RJT;
			break;

		case LSRJT_AUTH_NOT_LOGGED_IN:	/* 0x09 */
			auth_status->auth_state = DFC_AUTH_STATE_FAILED;
			auth_status->auth_failReason = DFC_AUTH_FAIL_BSY_LS_RJT;
			break;
		}
		break;
	}

	if (auth_status->auth_state != DFC_AUTH_STATE_ON) {
		auth_status->time_until_next_auth = 0;
		auth_status->localAuth = 0;
		auth_status->remoteAuth = 0;
		auth_status->group_priority = 0;
		auth_status->hash_priority = 0;
		auth_status->type_priority = 0;
	} else {
		switch (node_dhc->nlp_reauth_status) {
		case NLP_HOST_REAUTH_ENABLED:
		case NLP_HOST_REAUTH_IN_PROGRESS:
			drv_time = DRV_TIME;

			if (node_dhc->nlp_reauth_tmo > drv_time) {
				auth_status->time_until_next_auth =
				    node_dhc->nlp_reauth_tmo - drv_time;
			} else {
				auth_status->time_until_next_auth = 0;
			}
			break;

		case NLP_HOST_REAUTH_DISABLED:
		default:
			auth_status->time_until_next_auth = 0;
			break;
		}

		if (node_dhc->flag & NLP_REMOTE_AUTH) {
			auth_status->localAuth = 0;
			auth_status->remoteAuth = 1;
		} else {
			auth_status->localAuth = 1;
			auth_status->remoteAuth = 0;
		}

		auth_status->type_priority = DFC_AUTH_TYPE_DHCHAP;

		switch (node_dhc->nlp_auth_dhgpid) {
		case GROUP_NULL:
			auth_status->group_priority = ELX_GROUP_NULL;
			break;

		case GROUP_1024:
			auth_status->group_priority = ELX_GROUP_1024;
			break;

		case GROUP_1280:
			auth_status->group_priority = ELX_GROUP_1280;
			break;

		case GROUP_1536:
			auth_status->group_priority = ELX_GROUP_1536;
			break;

		case GROUP_2048:
			auth_status->group_priority = ELX_GROUP_2048;
			break;
		}

		switch (node_dhc->nlp_auth_hashid) {
		case 0:
			auth_status->hash_priority = 0;
			break;

		case AUTH_SHA1:
			auth_status->hash_priority = ELX_SHA1;
			break;

		case AUTH_MD5:
			auth_status->hash_priority = ELX_MD5;
			break;
		}
	}

	return;

} /* emlxs_dhc_status()  */

static char *
emlxs_dhc_pstate_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_pstate_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_pstate_table[i].code) {
			return (emlxs_pstate_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "state=0x%x", state);
	return (buffer);

} /* emlxs_dhc_pstate_xlate() */


static char *
emlxs_dhc_nstate_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_nstate_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_nstate_table[i].code) {
			return (emlxs_nstate_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "state=0x%x", state);
	return (buffer);

} /* emlxs_dhc_nstate_xlate() */


static uint32_t
emlxs_check_dhgp(
	emlxs_port_t *port,
	NODELIST *ndlp,
	uint32_t *dh_id,
	uint16_t cnt,
	uint32_t *dhgp_id)
{
	uint32_t i, j, rc = 1;
	uint32_t wnt;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "dhgp: 0x%x, id[0..4]=0x%x 0x%x 0x%x 0x%x 0x%x pri[1]=0x%x",
	    cnt, dh_id[0], dh_id[1], dh_id[2], dh_id[3], dh_id[4],
	    node_dhc->auth_cfg.dh_group_priority[1]);

	/*
	 * Here are the rules, as the responder We always try to select ours
	 * highest setup
	 */

	/* Check to see if there is any repeated dhgp in initiator's list */
	/* If available, it is a invalid payload */
	if (cnt >= 2) {
		for (i = 0; i <= cnt - 2; i++) {
			for (j = i + 1; j <= cnt - 1; j++) {
				if (dh_id[i] == dh_id[j]) {
					rc = 2;
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_fcsp_detail_msg,
					    ":Rpt dhid[%x]=%x dhid[%x]=%x",
					    i, dh_id[i], j, dh_id[j]);
					break;
				}
			}

			if (rc == 2) {
				break;
			}
		}

		if ((i == cnt - 1) && (j == cnt)) {
			rc = 1;
		}
		if (rc == 2) {
			/* duplicate invalid payload */
			return (rc);
		}
	}
	/* Check how many dhgps the responder specified */
	wnt = 0;
	while (node_dhc->auth_cfg.dh_group_priority[wnt] != 0xF) {
		wnt++;
	}

	/* Determine the most suitable dhgp the responder should use */
	for (i = 0; i < wnt; i++) {
		for (j = 0; j < cnt; j++) {
			if (node_dhc->auth_cfg.dh_group_priority[i] ==
			    dh_id[j]) {
				rc = 0;
				*dhgp_id =
				    node_dhc->auth_cfg.dh_group_priority[i];
				break;
			}
		}

		if (rc == 0) {
			break;
		}
	}

	if (i == wnt) {
		/* no match */
		rc = 1;
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "check_dhgp: dhgp_id=0x%x", *dhgp_id);

	return (rc);
} /* emlxs_check_dhgp */


static void
emlxs_get_random_bytes(
	NODELIST *ndlp,
	uint8_t *rdn,
	uint32_t len)
{
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	hrtime_t now;
	uint8_t sha1_digest[20];
	SHA1_CTX sha1ctx;

	now = gethrtime();

	bzero(&sha1ctx, sizeof (SHA1_CTX));
	SHA1Init(&sha1ctx);
	SHA1Update(&sha1ctx, (void *) &node_dhc->auth_cfg.local_entity,
	    sizeof (NAME_TYPE));
	SHA1Update(&sha1ctx, (void *) &now, sizeof (hrtime_t));
	SHA1Final((void *) sha1_digest, &sha1ctx);
	bcopy((void *) &sha1_digest[0], (void *) &rdn[0], len);

	return;

} /* emlxs_get_random_bytes */


/* **************************** STATE MACHINE ************************** */

static void *emlxs_dhchap_action[] =
{
	/* Action routine		Event */

/* NODE_STATE_UNKNOWN  0x00 */
	(void *) emlxs_disc_neverdev,	/* DEVICE_RM */
	(void *) emlxs_disc_neverdev,	/* DEVICE_RECOVERY */
	(void *) emlxs_disc_neverdev,	/* RCV_AUTH_MSG */
	(void *) emlxs_disc_neverdev,	/* CMPL_AUTH_MSG */

/* NODE_STATE_AUTH_DISABLED  0x01 */
	(void *) emlxs_disc_neverdev,	/* DEVICE_RM */
	(void *) emlxs_disc_neverdev,	/* DEVICE_RECOVERY */
	(void *) emlxs_disc_neverdev,	/* RCV_AUTH_MSG */
	(void *) emlxs_disc_neverdev,	/* CMPL_AUTH_MSG */

/* NODE_STATE_AUTH_FAILED  0x02 */
	(void *) emlxs_device_rm_npr_node,	/* DEVICE_RM */
	(void *) emlxs_device_recov_npr_node,	/* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_npr_node,	/* RCV_AUTH_MSG */
	(void *) emlxs_cmpl_auth_msg_npr_node,	/* CMPL_AUTH_MSG */

/* NODE_STATE_AUTH_SUCCESS  0x03 */
	(void *) emlxs_disc_neverdev,			/* DEVICE_RM */
	(void *) emlxs_device_recov_unmapped_node,	/* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_unmapped_node,	/* RCV_AUTH_MSG */
	(void *) emlxs_disc_neverdev,			/* CMPL_AUTH_MSG */

/* NODE_STATE_AUTH_NEGOTIATE_ISSUE  0x04 */
	(void *) emlxs_device_rem_auth,	/* DEVICE_RM */
	(void *) emlxs_device_recov_auth, /* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_auth_negotiate_issue, /* RCV_AUTH_MSG  */
	(void *) emlxs_cmpl_auth_msg_auth_negotiate_issue, /* CMPL_AUTH_MSG */

/* NODE_STATE_AUTH_NEGOTIATE_RCV  0x05 */
	(void *) emlxs_device_rem_auth,	/* DEVICE_RM */
	(void *) emlxs_device_recov_auth,	/* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_auth_negotiate_rcv,	/* RCV_AUTH_MSG */
	(void *) emlxs_cmpl_auth_msg_auth_negotiate_rcv, /* CMPL_AUTH_MSG */

/* NODE_STATE_AUTH_NEGOTIATE_CMPL_WAIT4NEXT  0x06 */
	(void *) emlxs_device_rem_auth,	/* DEVICE_RM */
	(void *) emlxs_device_recov_auth,	/* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_auth_negotiate_cmpl_wait4next,
						/* RCV_AUTH_MSG */
	(void *) emlxs_cmpl_auth_msg_auth_negotiate_cmpl_wait4next,
						/* CMPL_AUTH_MSG */

/* NODE_STATE_DHCHAP_CHALLENGE_ISSUE  0x07 */
	(void *) emlxs_device_rem_auth,	/* DEVICE_RM */
	(void *) emlxs_device_recov_auth,	/* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_dhchap_challenge_issue, /* RCV_AUTH_MSG */
	(void *) emlxs_cmpl_auth_msg_dhchap_challenge_issue, /* CMPL_AUTH_MSG */

/* NODE_STATE_DHCHAP_REPLY_ISSUE  0x08 */
	(void *) emlxs_device_rem_auth,	/* DEVICE_RM */
	(void *) emlxs_device_recov_auth,	/* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_dhchap_reply_issue,	/* RCV_AUTH_MSG */
	(void *) emlxs_cmpl_auth_msg_dhchap_reply_issue, /* CMPL_AUTH_MSG */

/* NODE_STATE_DHCHAP_CHALLENGE_CMPL_WAIT4NEXT  0x09 */
	(void *) emlxs_device_rem_auth,	/* DEVICE_RM */
	(void *) emlxs_device_recov_auth,	/* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_dhchap_challenge_cmpl_wait4next,
						/* RCV_AUTH_MSG   */
	(void *) emlxs_cmpl_auth_msg_dhchap_challenge_cmpl_wait4next,
						/* CMPL_AUTH_MSG */

/* NODE_STATE_DHCHAP_REPLY_CMPL_WAIT4NEXT  0x0A */
	(void *) emlxs_device_rem_auth,	/* DEVICE_RM */
	(void *) emlxs_device_recov_auth,	/* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_dhchap_reply_cmpl_wait4next,
						/* RCV_AUTH_MSG */
	(void *) emlxs_cmpl_auth_msg_dhchap_reply_cmpl_wait4next,
						/* CMPL_AUTH_MSG */

/* NODE_STATE_DHCHAP_SUCCESS_ISSUE  0x0B */
	(void *) emlxs_device_rem_auth,	/* DEVICE_RM */
	(void *) emlxs_device_recov_auth,	/* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_dhchap_success_issue,
						/* RCV_AUTH_MSG */
	(void *) emlxs_cmpl_auth_msg_dhchap_success_issue,
						/* CMPL_AUTH_MSG */

/* NODE_STATE_DHCHAP_SUCCESS_ISSUE_WAIT4NEXT  0x0C */
	(void *) emlxs_device_rem_auth,	/* DEVICE_RM */
	(void *) emlxs_device_recov_auth,	/* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_dhchap_success_issue_wait4next,
						/* RCV_AUTH_MSG */
	(void *) emlxs_cmpl_auth_msg_dhchap_success_issue_wait4next,
						/* CMPL_AUTH_MSG */

/* NODE_STATE_DHCHAP_SUCCESS_CMPL_WAIT4NEXT  0x0D */
	(void *) emlxs_device_rem_auth,	/* DEVICE_RM */
	(void *) emlxs_device_recov_auth,	/* DEVICE_RECOVERY */
	(void *) emlxs_rcv_auth_msg_dhchap_success_cmpl_wait4next,
						/* RCV_AUTH_MSG */
	(void *) emlxs_cmpl_auth_msg_dhchap_success_cmpl_wait4next,
						/* CMPL_AUTH_MSG */

}; /* emlxs_dhchap_action[] */


extern int
emlxs_dhchap_state_machine(emlxs_port_t *port, CHANNEL *cp,
		IOCBQ *iocbq, MATCHMAP *mp,
		NODELIST *ndlp, int evt)
{
	emlxs_hba_t *hba = HBA;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint32_t rc;
	uint32_t(*func) (emlxs_port_t *, CHANNEL *, IOCBQ *, MATCHMAP *,
	    NODELIST *, uint32_t);

	mutex_enter(&hba->dhc_lock);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_event_msg,
	    "%s: did=0x%x",
	    emlxs_dhc_event_xlate(evt), ndlp->nlp_DID);

	node_dhc->disc_refcnt++;

	func = (uint32_t(*) (emlxs_port_t *, CHANNEL *, IOCBQ *, MATCHMAP *,
	    NODELIST *, uint32_t))
	    emlxs_dhchap_action[(node_dhc->state * NODE_EVENT_MAX_EVENT) + evt];

	rc = (func) (port, cp, iocbq, mp, ndlp, evt);

	node_dhc->disc_refcnt--;

	mutex_exit(&hba->dhc_lock);

	return (rc);

} /* emlxs_dhchap_state_machine() */

/* ARGSUSED */
static uint32_t
emlxs_disc_neverdev(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *) arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "disc_neverdev: did=0x%x.",
	    ndlp->nlp_DID);

	emlxs_dhc_state(port, ndlp, NODE_STATE_UNKNOWN, 0, 0);

	return (node_dhc->state);

} /* emlxs_disc_neverdev() */


/*
 * ! emlxs_cmpl_dhchap_challenge_issue
 *
 * \pre \post \param   cmdiocb \param   rspiocb \return  void
 *
 * \b Description: iocb_cmpl callback function. when the ELS DHCHAP_Challenge
 * msg sent back got the ACC/RJT from initiator.
 *
 */
static void
emlxs_cmpl_dhchap_challenge_issue(fc_packet_t *pkt)
{
	emlxs_port_t *port = pkt->pkt_ulp_private;
	emlxs_buf_t *sbp;
	NODELIST *ndlp;
	uint32_t did;

	did = pkt->pkt_cmd_fhdr.d_id;
	sbp = (emlxs_buf_t *)pkt->pkt_fca_private;
	ndlp = sbp->node;

	if (!ndlp) {
		ndlp = emlxs_node_find_did(port, did, 1);
	}
	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "cmpl_dhchap_challenge_issue: did=0x%x state=%x",
		    did, pkt->pkt_state);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "cmpl_dhchap_challenge_issue: did=0x%x. Succcess.",
		    did);
	}

	if (ndlp) {
		if (pkt->pkt_state == FC_PKT_SUCCESS) {
			(void) emlxs_dhchap_state_machine(port, NULL, NULL,
			    NULL, ndlp, NODE_EVENT_CMPL_AUTH_MSG);
		}
	}
	emlxs_pkt_free(pkt);

	return;

} /* emlxs_cmpl_dhchap_challenge_issue */




/*
 * ! emlxs_cmpl_dhchap_success_issue
 *
 * \pre \post \param   phba \param   cmdiocb \param   rspiocb \return  void
 *
 * \b Description: iocb_cmpl callback function.
 *
 */
static void
emlxs_cmpl_dhchap_success_issue(fc_packet_t *pkt)
{
	emlxs_port_t *port = pkt->pkt_ulp_private;
	NODELIST *ndlp;
	uint32_t did;
	emlxs_buf_t *sbp;

	did = pkt->pkt_cmd_fhdr.d_id;
	sbp = (emlxs_buf_t *)pkt->pkt_fca_private;
	ndlp = sbp->node;

	if (!ndlp) {
		ndlp = emlxs_node_find_did(port, did, 1);
	}
	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "cmpl_dhchap_success_issue: 0x%x %x. No retry.",
		    did, pkt->pkt_state);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "cmpl_dhchap_success_issue: did=0x%x. Succcess.",
		    did);
	}

	if (ndlp) {
		if (pkt->pkt_state == FC_PKT_SUCCESS) {
			(void) emlxs_dhchap_state_machine(port, NULL, NULL,
			    NULL, ndlp, NODE_EVENT_CMPL_AUTH_MSG);
		}
	}
	emlxs_pkt_free(pkt);

	return;

} /* emlxs_cmpl_dhchap_success_issue */


/*
 * if rsp == NULL, this is only the DHCHAP_Success msg
 *
 * if rsp != NULL, DHCHAP_Success contains rsp to the challenge.
 */
/* ARGSUSED */
uint32_t
emlxs_issue_dhchap_success(
	emlxs_port_t *port,
	NODELIST *ndlp,
	int retry,
	uint8_t *rsp)
{
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	fc_packet_t *pkt;
	uint32_t cmd_size;
	uint32_t rsp_size;
	uint8_t *pCmd;
	uint16_t cmdsize;
	DHCHAP_SUCCESS_HDR *ap;
	uint8_t *tmp;
	uint32_t len;
	uint32_t ret;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "issue_dhchap_success: did=0x%x", ndlp->nlp_DID);

	if (ndlp->nlp_DID == FABRIC_DID) {
		if (node_dhc->nlp_auth_hashid == AUTH_MD5)
			len = MD5_LEN;
		else
			len = SHA1_LEN;
	} else {
		len = (node_dhc->nlp_auth_hashid == AUTH_MD5) ?
		    MD5_LEN : SHA1_LEN;
	}

	if (rsp == NULL) {
		cmdsize = sizeof (DHCHAP_SUCCESS_HDR);
	} else {

		cmdsize = sizeof (DHCHAP_SUCCESS_HDR) + len;
	}

	cmd_size = cmdsize;
	rsp_size = 4;

	if ((pkt = emlxs_prep_els_fc_pkt(port, ndlp->nlp_DID, cmd_size,
	    rsp_size, 0, KM_NOSLEEP)) == NULL) {
		return (1);
	}
	pCmd = (uint8_t *)pkt->pkt_cmd;

	ap = (DHCHAP_SUCCESS_HDR *)pCmd;
	tmp = (uint8_t *)pCmd;

	ap->auth_els_code = ELS_CMD_AUTH_CODE;
	ap->auth_els_flags = 0x0;
	ap->auth_msg_code = DHCHAP_SUCCESS;
	ap->proto_version = 0x01;

	/*
	 * In case of rsp == NULL meaning that this is DHCHAP_Success issued
	 * when Host is the initiator AND this DHCHAP_Success is issused in
	 * response to the bi-directional authentication, meaning Host
	 * authenticate another entity, therefore no more DHCHAP_Success
	 * expected. OR this DHCHAP_Success is issued by host when host is
	 * the responder BUT it is uni-directional auth, therefore no more
	 * DHCHAP_Success expected.
	 *
	 * In case of rsp != NULL it indicates this DHCHAP_Success is issued
	 * when host is the responder AND this DHCHAP_Success has reply
	 * embedded therefore the host expects DHCHAP_Success from other
	 * entity in transaction.
	 */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "issue_dhchap_success: 0x%x 0x%x 0x%x 0x%x 0x%x %p",
	    ndlp->nlp_DID, node_dhc->nlp_auth_hashid,
	    node_dhc->nlp_auth_tranid_rsp,
	    node_dhc->nlp_auth_tranid_ini, cmdsize, rsp);

	if (rsp == NULL) {
		ap->msg_len = LE_SWAP32(0x00000004);
		ap->RspVal_len = 0x0;

		node_dhc->fc_dhchap_success_expected = 0;
	} else {
		node_dhc->fc_dhchap_success_expected = 1;

		ap->msg_len = LE_SWAP32(4 + len);

		tmp += sizeof (DHCHAP_SUCCESS_HDR) - sizeof (uint32_t);
		*(uint32_t *)tmp = LE_SWAP32(len);
		tmp += sizeof (uint32_t);
		bcopy((void *)rsp, (void *)tmp, len);
	}

	if (node_dhc->nlp_reauth_status == NLP_HOST_REAUTH_IN_PROGRESS) {
		ap->tran_id = LE_SWAP32(node_dhc->nlp_auth_tranid_rsp);
	} else {
		if (node_dhc->nlp_auth_flag == 2) {
			ap->tran_id =
			    LE_SWAP32(node_dhc->nlp_auth_tranid_rsp);
		} else if (node_dhc->nlp_auth_flag == 1) {
			ap->tran_id =
			    LE_SWAP32(node_dhc->nlp_auth_tranid_ini);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_debug_msg,
			    "is_dhch_success: (1) 0x%x 0x%x 0x%x 0x%x",
			    ndlp->nlp_DID, node_dhc->nlp_auth_flag,
			    node_dhc->nlp_auth_tranid_rsp,
			    node_dhc->nlp_auth_tranid_ini);

			return (1);
		}
	}

	pkt->pkt_comp = emlxs_cmpl_dhchap_success_issue;

	ret = emlxs_pkt_send(pkt, 1);

	if (ret != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "issue_dhchap_success: Unable to send packet. 0x%x",
		    ret);

		emlxs_pkt_free(pkt);

		return (1);
	}
	return (0);

} /* emlxs_issue_dhchap_success */


/*
 * ! emlxs_cmpl_auth_reject_issue
 *
 * \pre \post \param   phba \param   cmdiocb \param   rspiocb \return  void
 *
 * \b Description: iocb_cmpl callback function.
 *
 */
static void
emlxs_cmpl_auth_reject_issue(fc_packet_t *pkt)
{
	emlxs_port_t *port = pkt->pkt_ulp_private;
	emlxs_buf_t *sbp;
	NODELIST *ndlp;
	uint32_t did;

	did = pkt->pkt_cmd_fhdr.d_id;
	sbp = (emlxs_buf_t *)pkt->pkt_fca_private;
	ndlp = sbp->node;

	if (!ndlp) {
		ndlp = emlxs_node_find_did(port, did, 1);
	}
	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "cmpl_auth_reject_issue: 0x%x %x. No retry.",
		    did, pkt->pkt_state);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "cmpl_auth_reject_issue: did=0x%x. Succcess.",
		    did);
	}

	if (ndlp) {
		/* setup the new state */
		emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_FAILED, 0, 0);

		if (pkt->pkt_state == FC_PKT_SUCCESS) {
			(void) emlxs_dhchap_state_machine(port, NULL, NULL,
			    NULL, ndlp, NODE_EVENT_CMPL_AUTH_MSG);
		}
	}
	emlxs_pkt_free(pkt);

	return;

} /* emlxs_cmpl_auth_reject_issue */


/*
 * If Logical Error and Reason Code Explanation is "Restart Authentication
 * Protocol" then the Transaction Identifier could be
 * any value.
 */
/* ARGSUSED */
static uint32_t
emlxs_issue_auth_reject(
	emlxs_port_t *port,
	NODELIST *ndlp,
	int retry,
	uint32_t *arg,
	uint8_t ReasonCode,
	uint8_t ReasonCodeExplanation)
{
	fc_packet_t *pkt;
	uint32_t cmd_size;
	uint32_t rsp_size;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint16_t cmdsize;
	AUTH_RJT *ap;
	char info[64];

	if (node_dhc->nlp_authrsp_tmo) {
		node_dhc->nlp_authrsp_tmo = 0;
	}
	cmdsize = sizeof (AUTH_RJT);
	cmd_size = cmdsize;
	rsp_size = 4;

	if ((pkt = emlxs_prep_els_fc_pkt(port, ndlp->nlp_DID, cmd_size,
	    rsp_size, 0, KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "Auth reject failed: Unable to allocate pkt. 0x%x %x %x",
		    ndlp->nlp_DID, ReasonCode, ReasonCodeExplanation);

		return (1);
	}
	ap = (AUTH_RJT *) pkt->pkt_cmd;
	ap->auth_els_code = ELS_CMD_AUTH_CODE;
	ap->auth_els_flags = 0x0;
	ap->auth_msg_code = AUTH_REJECT;
	ap->proto_version = 0x01;
	ap->msg_len = LE_SWAP32(4);

	if (node_dhc->nlp_auth_flag == 2) {
		ap->tran_id = LE_SWAP32(node_dhc->nlp_auth_tranid_rsp);
	} else if (node_dhc->nlp_auth_flag == 1) {
		ap->tran_id = LE_SWAP32(node_dhc->nlp_auth_tranid_ini);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "Auth reject failed.Invalid flag=%d. 0x%x %x expl=%x",
		    ndlp->nlp_DID, node_dhc->nlp_auth_flag, ReasonCode,
		    ReasonCodeExplanation);

		emlxs_pkt_free(pkt);

		return (1);
	}

	ap->ReasonCode = ReasonCode;
	ap->ReasonCodeExplanation = ReasonCodeExplanation;

	pkt->pkt_comp = emlxs_cmpl_auth_reject_issue;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_debug_msg,
	    "Auth reject: did=0x%x reason=%x expl=%x",
	    ndlp->nlp_DID, ReasonCode, ReasonCodeExplanation);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "Auth reject failed. Unable to send pkt. 0x%x %x expl=%x",
		    ndlp->nlp_DID, node_dhc->nlp_auth_flag, ReasonCode,
		    ReasonCodeExplanation);

		emlxs_pkt_free(pkt);

		return (1);
	}
	(void) snprintf(info, sizeof (info),
	    "Auth-Reject: ReasonCode=0x%x, ReasonCodeExplanation=0x%x",
	    ReasonCode, ReasonCodeExplanation);

	emlxs_log_auth_event(port, ndlp, "issue_auth_reject", info);

	return (0);

} /* emlxs_issue_auth_reject */


static fc_packet_t *
	emlxs_prep_els_fc_pkt(
	emlxs_port_t *port,
	uint32_t d_id,
	uint32_t cmd_size,
	uint32_t rsp_size,
	uint32_t datalen,
	int32_t sleepflag)
{
	fc_packet_t *pkt;

	/* simulate the ULP stack's fc_packet send out */
	if (!(pkt = emlxs_pkt_alloc(port, cmd_size, rsp_size,
	    datalen, sleepflag))) {
		return (NULL);
	}
	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = 35;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = LE_SWAP24_LO(d_id);
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_ELS_REQ;
	pkt->pkt_cmd_fhdr.s_id = LE_SWAP24_LO(port->did);
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.rx_id = 0xFFFF;
	pkt->pkt_cmd_fhdr.ro = 0;

	return ((fc_packet_t *)pkt);

} /* emlxs_prep_els_fc_pkt */


/*
 * ! emlxs_issue_auth_negotiate
 *
 * \pre \post \param   port \param   ndlp \param   retry \param   flag \return
 * int
 *
 * \b Description:
 *
 * The routine is invoked when host as the authentication initiator which
 * issue the AUTH_ELS command AUTH_Negotiate to the other
 * entity ndlp. When this Auth_Negotiate command is completed, the iocb_cmpl
 * will get called as the solicited mbox cmd
 * callback. Some switch only support NULL dhchap in which case negotiate
 * should be modified to only have NULL DH specificed.
 *
 */
/* ARGSUSED */
static int
emlxs_issue_auth_negotiate(
	emlxs_port_t *port,
	emlxs_node_t *ndlp,
	uint8_t retry)
{
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	fc_packet_t *pkt;
	uint32_t cmd_size;
	uint32_t rsp_size;
	uint16_t cmdsize;
	AUTH_MSG_NEGOT_NULL_1 *null_ap1;
	AUTH_MSG_NEGOT_NULL_2 *null_ap2;
	uint32_t num_hs = 0;
	uint8_t flag;
	AUTH_MSG_NEGOT_1 *ap1;
	AUTH_MSG_NEGOT_2 *ap2;
	uint16_t para_len = 0;
	uint16_t hash_wcnt = 0;
	uint16_t dhgp_wcnt = 0;


	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_NEGOTIATE_ISSUE, 0, 0);

	/* Full DH group support limit:2, only NULL group support limit:1 */
	flag = (node_dhc->nlp_auth_limit == 2) ? 1 : 0;

	/* first: determine the cmdsize based on the auth cfg parameters */
	if (flag == 1) {
		/* May be Full DH group + 2 hash may not be */
		cmdsize = sizeof (AUTH_MSG_NEGOT_NULL);

		cmdsize += 2 + 2;	/* name tag: 2, name length: 2 */
		cmdsize += 8;	/* WWN: 8 */
		cmdsize += 4;	/* num of protocol: 4 */
		cmdsize += 4;	/* protocol parms length: 4 */
		cmdsize += 4;	/* protocol id: 4 */
		para_len += 4;

		cmdsize += 2 + 2;	/* hashlist: tag: 2, count:2 */
		para_len += 4;

		if (node_dhc->auth_cfg.hash_priority[1] == 0x00) {
			/* only one hash func */
			cmdsize += 4;
			num_hs = 1;
			para_len += 4;
			hash_wcnt = 1;
		} else {
			/* two hash funcs */
			cmdsize += 4 + 4;
			num_hs = 2;
			para_len += 4 + 4;
			hash_wcnt = 2;
		}

		cmdsize += 2 + 2;
		para_len += 4;
		if (node_dhc->auth_cfg.dh_group_priority[1] == 0xf) {
			/* only one dhgp specified: could be NULL or non-NULL */
			cmdsize += 4;
			para_len += 4;
			dhgp_wcnt = 1;

		} else if (node_dhc->auth_cfg.dh_group_priority[2] == 0xf) {
			/* two dhgps specified */
			cmdsize += 4 + 4;
			para_len += 4 + 4;
			dhgp_wcnt = 2;

		} else if (node_dhc->auth_cfg.dh_group_priority[3] == 0xf) {
			/* three dhgps specified */
			cmdsize += 4 + 4 + 4;
			para_len += 4 + 4 + 4;
			dhgp_wcnt = 3;

		} else if (node_dhc->auth_cfg.dh_group_priority[4] == 0xf) {
			/* four dhgps specified */
			cmdsize += 4 + 4 + 4 + 4;
			para_len += 4 + 4 + 4 + 4;
			dhgp_wcnt = 4;

		} else if (node_dhc->auth_cfg.dh_group_priority[5] == 0xf) {
			cmdsize += 4 + 4 + 4 + 4 + 4;
			para_len += 4 + 4 + 4 + 4 + 4;
			dhgp_wcnt = 5;

		}
	} else {
		cmdsize = sizeof (AUTH_MSG_NEGOT_NULL);

		/*
		 * get the right payload size in byte: determined by config
		 * parameters
		 */
		cmdsize += 2 + 2 + 8;	/* name tag:2, name length:2, name */
					/* value content:8 */
		cmdsize += 4;	/* number of usable authentication */
				/* protocols:4 */
		cmdsize += 4;	/* auth protocol params length: 4 */
		cmdsize += 4;	/* auth protocol identifier: 4 */

		/* hash list infor */
		cmdsize += 4;	/* hashlist: tag:2, count:2 */

		if (node_dhc->auth_cfg.hash_priority[1] == 0x00) {
			cmdsize += 4;	/* only one hash function provided */
			num_hs = 1;
		} else {
			num_hs = 2;
			cmdsize += 4 + 4;	/* sha1: 4, md5: 4 */
		}

		/* dhgp list info */
		/* since this is NULL DH group */
		cmdsize += 4;	/* dhgroup: tag:2, count:2 */
		cmdsize += 4;	/* set it to zero */
	}

	cmd_size = cmdsize;
	rsp_size = 4;

	if ((pkt = emlxs_prep_els_fc_pkt(port, ndlp->nlp_DID, cmd_size,
	    rsp_size, 0, KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "issue_auth_negotiate: Unable to allocate pkt. 0x%x %d",
		    ndlp->nlp_DID, cmd_size);

		return (1);
	}
	/* Fill in AUTH_MSG_NEGOT payload */
	if (flag == 1) {
		if (hash_wcnt == 1) {
			ap1 = (AUTH_MSG_NEGOT_1 *)pkt->pkt_cmd;
			ap1->auth_els_code = ELS_CMD_AUTH_CODE;
			ap1->auth_els_flags = 0x00;
			ap1->auth_msg_code = AUTH_NEGOTIATE;
			ap1->proto_version = 0x01;
			ap1->msg_len = LE_SWAP32(cmdsize -
			    sizeof (AUTH_MSG_NEGOT_NULL));
		} else {
			ap2 = (AUTH_MSG_NEGOT_2 *)pkt->pkt_cmd;
			ap2->auth_els_code = ELS_CMD_AUTH_CODE;
			ap2->auth_els_flags = 0x00;
			ap2->auth_msg_code = AUTH_NEGOTIATE;
			ap2->proto_version = 0x01;
			ap2->msg_len = LE_SWAP32(cmdsize -
			    sizeof (AUTH_MSG_NEGOT_NULL));
		}
	} else {
		if (node_dhc->auth_cfg.hash_priority[1] == 0x00) {
			null_ap1 = (AUTH_MSG_NEGOT_NULL_1 *)pkt->pkt_cmd;
			null_ap1->auth_els_code = ELS_CMD_AUTH_CODE;
			null_ap1->auth_els_flags = 0x0;
			null_ap1->auth_msg_code = AUTH_NEGOTIATE;
			null_ap1->proto_version = 0x01;
			null_ap1->msg_len = LE_SWAP32(cmdsize -
			    sizeof (AUTH_MSG_NEGOT_NULL));

		} else {
			null_ap2 = (AUTH_MSG_NEGOT_NULL_2 *)pkt->pkt_cmd;
			null_ap2->auth_els_code = ELS_CMD_AUTH_CODE;
			null_ap2->auth_els_flags = 0x0;
			null_ap2->auth_msg_code = AUTH_NEGOTIATE;
			null_ap2->proto_version = 0x01;
			null_ap2->msg_len = LE_SWAP32(cmdsize -
			    sizeof (AUTH_MSG_NEGOT_NULL));
		}
	}

	/*
	 * For host reauthentication heart beat, the tran_id is incremented
	 * by one for each heart beat being fired and round back to 1 when
	 * 0xffffffff is reached. tran_id 0 is reserved as the initial linkup
	 * authentication transaction id.
	 */

	/* responder flag:2, initiator flag:1 */
	node_dhc->nlp_auth_flag = 2;	/* ndlp is the always the auth */
					/* responder */

	if (node_dhc->nlp_reauth_status == NLP_HOST_REAUTH_IN_PROGRESS) {
		if (node_dhc->nlp_auth_tranid_rsp == 0xffffffff) {
			node_dhc->nlp_auth_tranid_rsp = 1;
		} else {
			node_dhc->nlp_auth_tranid_rsp++;
		}
	} else {	/* !NLP_HOST_REAUTH_IN_PROGRESS */
		node_dhc->nlp_auth_tranid_rsp = 0;
	}

	if (flag == 1) {
		if (hash_wcnt == 1) {
			ap1->tran_id =
			    LE_SWAP32(node_dhc->nlp_auth_tranid_rsp);

			ap1->params.name_tag = AUTH_NAME_ID;
			ap1->params.name_len = AUTH_NAME_LEN;
			bcopy((void *)&port->wwpn,
			    (void *) &ap1->params.nodeName, sizeof (NAME_TYPE));
			ap1->params.proto_num = AUTH_PROTO_NUM;
			ap1->params.para_len = LE_SWAP32(para_len);
			ap1->params.proto_id = AUTH_DHCHAP;
			ap1->params.HashList_tag = HASH_LIST_TAG;
			ap1->params.HashList_wcnt = LE_SWAP16(hash_wcnt);
			ap1->params.HashList_value1 =
			    node_dhc->auth_cfg.hash_priority[0];
			ap1->params.DHgIDList_tag = DHGID_LIST_TAG;
			ap1->params.DHgIDList_wnt = LE_SWAP16(dhgp_wcnt);

			switch (dhgp_wcnt) {
			case 5:
				ap1->params.DHgIDList_g4 =
				    (node_dhc->auth_cfg.dh_group_priority[4]);
				ap1->params.DHgIDList_g3 =
				    (node_dhc->auth_cfg.dh_group_priority[3]);
				ap1->params.DHgIDList_g2 =
				    (node_dhc->auth_cfg.dh_group_priority[2]);
				ap1->params.DHgIDList_g1 =
				    (node_dhc->auth_cfg.dh_group_priority[1]);
				ap1->params.DHgIDList_g0 =
				    (node_dhc->auth_cfg.dh_group_priority[0]);
				break;
			case 4:
				ap1->params.DHgIDList_g3 =
				    (node_dhc->auth_cfg.dh_group_priority[3]);
				ap1->params.DHgIDList_g2 =
				    (node_dhc->auth_cfg.dh_group_priority[2]);
				ap1->params.DHgIDList_g1 =
				    (node_dhc->auth_cfg.dh_group_priority[1]);
				ap1->params.DHgIDList_g0 =
				    (node_dhc->auth_cfg.dh_group_priority[0]);
				break;
			case 3:
				ap1->params.DHgIDList_g2 =
				    (node_dhc->auth_cfg.dh_group_priority[2]);
				ap1->params.DHgIDList_g1 =
				    (node_dhc->auth_cfg.dh_group_priority[1]);
				ap1->params.DHgIDList_g0 =
				    (node_dhc->auth_cfg.dh_group_priority[0]);
				break;
			case 2:
				ap1->params.DHgIDList_g1 =
				    (node_dhc->auth_cfg.dh_group_priority[1]);
				ap1->params.DHgIDList_g0 =
				    (node_dhc->auth_cfg.dh_group_priority[0]);
				break;
			case 1:
				ap1->params.DHgIDList_g0 =
				    (node_dhc->auth_cfg.dh_group_priority[0]);
				break;
			}
		} else {
			ap2->tran_id =
			    LE_SWAP32(node_dhc->nlp_auth_tranid_rsp);

			ap2->params.name_tag = AUTH_NAME_ID;
			ap2->params.name_len = AUTH_NAME_LEN;
			bcopy((void *) &port->wwpn,
			    (void *) &ap2->params.nodeName, sizeof (NAME_TYPE));
			ap2->params.proto_num = AUTH_PROTO_NUM;
			ap2->params.para_len = LE_SWAP32(para_len);
			ap2->params.proto_id = AUTH_DHCHAP;
			ap2->params.HashList_tag = HASH_LIST_TAG;
			ap2->params.HashList_wcnt = LE_SWAP16(hash_wcnt);
			ap2->params.HashList_value1 =
			    (node_dhc->auth_cfg.hash_priority[0]);
			ap2->params.HashList_value2 =
			    (node_dhc->auth_cfg.hash_priority[1]);

			ap2->params.DHgIDList_tag = DHGID_LIST_TAG;
			ap2->params.DHgIDList_wnt = LE_SWAP16(dhgp_wcnt);

			switch (dhgp_wcnt) {
			case 5:
				ap2->params.DHgIDList_g4 =
				    (node_dhc->auth_cfg.dh_group_priority[4]);
				ap2->params.DHgIDList_g3 =
				    (node_dhc->auth_cfg.dh_group_priority[3]);
				ap2->params.DHgIDList_g2 =
				    (node_dhc->auth_cfg.dh_group_priority[2]);
				ap2->params.DHgIDList_g1 =
				    (node_dhc->auth_cfg.dh_group_priority[1]);
				ap2->params.DHgIDList_g0 =
				    (node_dhc->auth_cfg.dh_group_priority[0]);
				break;
			case 4:
				ap2->params.DHgIDList_g3 =
				    (node_dhc->auth_cfg.dh_group_priority[3]);
				ap2->params.DHgIDList_g2 =
				    (node_dhc->auth_cfg.dh_group_priority[2]);
				ap2->params.DHgIDList_g1 =
				    (node_dhc->auth_cfg.dh_group_priority[1]);
				ap2->params.DHgIDList_g0 =
				    (node_dhc->auth_cfg.dh_group_priority[0]);
				break;
			case 3:
				ap2->params.DHgIDList_g2 =
				    (node_dhc->auth_cfg.dh_group_priority[2]);
				ap2->params.DHgIDList_g1 =
				    (node_dhc->auth_cfg.dh_group_priority[1]);
				ap2->params.DHgIDList_g0 =
				    (node_dhc->auth_cfg.dh_group_priority[0]);
				break;
			case 2:
				ap2->params.DHgIDList_g1 =
				    (node_dhc->auth_cfg.dh_group_priority[1]);
				ap2->params.DHgIDList_g0 =
				    (node_dhc->auth_cfg.dh_group_priority[0]);
				break;
			case 1:
				ap2->params.DHgIDList_g0 =
				    (node_dhc->auth_cfg.dh_group_priority[0]);
				break;
			}
		}
	} else {
		if (num_hs == 1) {
			null_ap1->tran_id =
			    LE_SWAP32(node_dhc->nlp_auth_tranid_rsp);

			null_ap1->params.name_tag = AUTH_NAME_ID;
			null_ap1->params.name_len = AUTH_NAME_LEN;
			bcopy((void *) &port->wwpn,
			    (void *) &null_ap1->params.nodeName,
			    sizeof (NAME_TYPE));
			null_ap1->params.proto_num = AUTH_PROTO_NUM;
			null_ap1->params.para_len = LE_SWAP32(0x00000014);
			null_ap1->params.proto_id = AUTH_DHCHAP;
			null_ap1->params.HashList_tag = HASH_LIST_TAG;
			null_ap1->params.HashList_wcnt = LE_SWAP16(0x0001);
			null_ap1->params.HashList_value1 =
			    (node_dhc->auth_cfg.hash_priority[0]);
			null_ap1->params.DHgIDList_tag = DHGID_LIST_TAG;
			null_ap1->params.DHgIDList_wnt = LE_SWAP16(0x0001);
			null_ap1->params.DHgIDList_g0 = 0x0;
		} else {
			null_ap2->tran_id =
			    LE_SWAP32(node_dhc->nlp_auth_tranid_rsp);

			null_ap2->params.name_tag = AUTH_NAME_ID;
			null_ap2->params.name_len = AUTH_NAME_LEN;
			bcopy((void *) &port->wwpn,
			    (void *) &null_ap2->params.nodeName,
			    sizeof (NAME_TYPE));
			null_ap2->params.proto_num = AUTH_PROTO_NUM;
			null_ap2->params.para_len = LE_SWAP32(0x00000018);
			null_ap2->params.proto_id = AUTH_DHCHAP;

			null_ap2->params.HashList_tag = HASH_LIST_TAG;
			null_ap2->params.HashList_wcnt = LE_SWAP16(0x0002);
			null_ap2->params.HashList_value1 =
			    (node_dhc->auth_cfg.hash_priority[0]);
			null_ap2->params.HashList_value2 =
			    (node_dhc->auth_cfg.hash_priority[1]);

			null_ap2->params.DHgIDList_tag = DHGID_LIST_TAG;
			null_ap2->params.DHgIDList_wnt = LE_SWAP16(0x0001);
			null_ap2->params.DHgIDList_g0 = 0x0;
		}
	}

	pkt->pkt_comp = emlxs_cmpl_auth_negotiate_issue;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_debug_msg,
	    "issue_auth_negotiate: %x flag=%d size=%d hash=%x,%x tid=%x,%x",
	    ndlp->nlp_DID, flag, cmd_size,
	    node_dhc->auth_cfg.hash_priority[0],
	    node_dhc->auth_cfg.hash_priority[1],
	    node_dhc->nlp_auth_tranid_rsp, node_dhc->nlp_auth_tranid_ini);

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		emlxs_pkt_free(pkt);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "issue_auth_negotiate: Unable to send pkt. did=0x%x",
		    ndlp->nlp_DID);

		return (1);
	}
	return (0);

} /* emlxs_issue_auth_negotiate() */



/*
 * ! emlxs_cmpl_auth_negotiate_issue
 *
 * \pre \post \param   phba \param   cmdiocb \param   rspiocb \return  void
 *
 * \b Description: iocb_cmpl callback function.
 *
 */
static void
emlxs_cmpl_auth_negotiate_issue(fc_packet_t *pkt)
{
	emlxs_port_t *port = pkt->pkt_ulp_private;
	emlxs_buf_t *sbp;
	NODELIST *ndlp;
	emlxs_node_dhc_t *node_dhc;
	uint32_t did;

	did = pkt->pkt_cmd_fhdr.d_id;
	sbp = (emlxs_buf_t *)pkt->pkt_fca_private;
	ndlp = sbp->node;
	node_dhc = &ndlp->node_dhc;

	if (!ndlp) {
		ndlp = emlxs_node_find_did(port, did, 1);
	}
	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "cmpl_dhchap_negotiate_issue: 0x%x %x. Noretry.",
		    did, pkt->pkt_state);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "cmpl_dhchap_negotiate_issue: did=0x%x. Succcess.",
		    did);
	}

	if (ndlp) {
		if (pkt->pkt_state == FC_PKT_SUCCESS) {
			(void) emlxs_dhchap_state_machine(port, NULL, NULL,
			    NULL, ndlp, NODE_EVENT_CMPL_AUTH_MSG);
		} else {
			emlxs_dhc_set_reauth_time(port, ndlp, DISABLE);

			emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_FAILED,
			    0, 0);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_debug_msg,
			    "Reauth disabled. did=0x%x state=%x",
			    ndlp->nlp_DID, node_dhc->state);

			emlxs_dhc_auth_complete(port, ndlp, 1);
		}
	}
	emlxs_pkt_free(pkt);

	return;

} /* emlxs_cmpl_auth_negotiate_issue */


/*
 * ! emlxs_cmpl_auth_msg_auth_negotiate_issue
 *
 * \pre \post \param   port \param   CHANNEL * rp \param   arg \param   evt
 * \return  uint32_t \b Description:
 *
 * This routine is invoked when the host receive the solicited ACC/RJT ELS
 * cmd from an NxPort or FxPort that has received the ELS
 * AUTH Negotiate msg from the host. in case of RJT, Auth_Negotiate should
 * be retried in emlxs_cmpl_auth_negotiate_issue
 * call. in case of ACC, the host must be the initiator because its current
 * state could be "AUTH_NEGOTIATE_RCV" if it is the
 * responder. Then the next stat = AUTH_NEGOTIATE_CMPL_WAIT4NEXT
 */
/* ARGSUSED */
static uint32_t
emlxs_cmpl_auth_msg_auth_negotiate_issue(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp, */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "cmpl_auth_msg_auth_negotiate_issue: did=0x%x",
	    ndlp->nlp_DID);

	/* start the emlxs_dhc_authrsp_timeout timer */
	if (node_dhc->nlp_authrsp_tmo == 0) {
		node_dhc->nlp_authrsp_tmo = DRV_TIME +
		    node_dhc->auth_cfg.authentication_timeout;
	}
	/*
	 * The next state should be
	 * emlxs_rcv_auth_msg_auth_negotiate_cmpl_wait4next
	 */
	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_NEGOTIATE_CMPL_WAIT4NEXT,
	    0, 0);

	return (node_dhc->state);

} /* emlxs_cmpl_auth_msg_auth_negotiate_issue */



/*
 * ! emlxs_rcv_auth_msg_auth_negotiate_issue
 *
 * \pre \post \param   phba \param   ndlp \param   arg \param   evt \return
 * uint32_t \b Description:
 *
 * This routine is supported for HBA in either auth initiator mode or
 * responder mode.
 *
 * This routine is invoked when the host receive an unsolicited ELS AUTH Msg
 * from an NxPort or FxPort to which the host has just
 * sent out an ELS AUTH negotiate msg. and the NxPort or FxPort also LS_ACC
 * to the host's AUTH_Negotiate msg.
 *
 * If this unsolicited ELS auth msg is from the FxPort or a NxPort with a
 * numerically lower WWPN, the host will be the winner in
 * this authentication transaction initiation phase, the host as the
 * initiator will send back ACC and then Auth_Reject message
 * with the Reason Code 'Logical Error' and Reason Code Explanation'
 * Authentication Transaction Already Started' and with the
 * current state unchanged and mark itself as auth_initiator.
 *
 * Otherwise, the host will be the responder that will reply to the received
 * AUTH_Negotiate message will ACC (or RJT?) and abort
 * its own transaction upon receipt of the AUTH_Reject message. The new state
 * will be "AUTH_NEGOTIATE_RCV" and mark the host as
 * auth_responder.
 */
/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_auth_negotiate_issue(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	IOCBQ *iocbq = (IOCBQ *) arg2;
	uint8_t ReasonCode;
	uint8_t ReasonCodeExplanation;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_auth_negotiate_issue: did=0x%x",
	    ndlp->nlp_DID);

	/* Anyway we accept it first and then send auth_reject */
	(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC, ELS_CMD_AUTH, 0, 0);

	/* host is always the initiator and it should win */
	ReasonCode = AUTHRJT_LOGIC_ERR;
	ReasonCodeExplanation = AUTHEXP_AUTHTRAN_STARTED;

	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_NEGOTIATE_ISSUE,
	    ReasonCode, ReasonCodeExplanation);
	(void) emlxs_issue_auth_reject(port, ndlp, 0, 0, ReasonCode,
	    ReasonCodeExplanation);

	return (node_dhc->state);

} /* emlxs_rcv_auth_msg_auth_negotiate_issue */


/*
 * ! emlxs_cmpl_dhchap_reply_issue
 *
 * \pre \post \param   phba \param   cmdiocb \param   rspiocb \return  void
 *
 * \b Description: iocb_cmpl callback function.
 *
 */
static void
emlxs_cmpl_dhchap_reply_issue(fc_packet_t *pkt)
{
	emlxs_port_t *port = pkt->pkt_ulp_private;
	emlxs_buf_t *sbp;
	NODELIST *ndlp;
	uint32_t did;

	did = pkt->pkt_cmd_fhdr.d_id;
	sbp = (emlxs_buf_t *)pkt->pkt_fca_private;
	ndlp = sbp->node;

	if (!ndlp) {
		ndlp = emlxs_node_find_did(port, did, 1);
	}
	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "cmpl_dhchap_reply_issue: 0x%x %x. No retry.",
		    did, pkt->pkt_state);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "cmpl_dhchap_reply_issue: did=0x%x. Succcess.",
		    did);
	}

	if (ndlp) {
		if (pkt->pkt_state == FC_PKT_SUCCESS) {
			(void) emlxs_dhchap_state_machine(port, NULL, NULL,
			    NULL, ndlp, NODE_EVENT_CMPL_AUTH_MSG);
		}
	}
	emlxs_pkt_free(pkt);

	return;

} /* emlxs_cmpl_dhchap_reply_issue */


/*
 * arg: the AUTH_Negotiate payload from the initiator. payload_len: the
 * payload length
 *
 * We always send out the challenge parameter based on our preference
 * order configured on the host side no matter what perference
 * order looks like from auth_negotiate . In other words, if the host issue
 * the challenge the host will make the decision as to
 * what hash function, what dhgp_id is to be used.
 *
 * This challenge value should not be confused with the challenge value for
 * bi-dir as part of reply when host is the initiator.
 */
/* ARGSUSED */
uint32_t
emlxs_issue_dhchap_challenge(
	emlxs_port_t *port,
	NODELIST *ndlp,
	int retry,
	void *arg,
	uint32_t payload_len,
	uint32_t hash_id,
	uint32_t dhgp_id)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	uint32_t cmd_size;
	uint32_t rsp_size;
	uint16_t cmdsize = 0;
	uint8_t *pCmd;
	emlxs_port_dhc_t *port_dhc = &port->port_dhc;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	DHCHAP_CHALL *chal;
	uint8_t *tmp;
	uint8_t random_number[20];
	uint8_t dhval[256];
	uint32_t dhval_len;
	uint32_t tran_id;
	BIG_ERR_CODE err = BIG_OK;

	/*
	 * we assume the HBAnyware should configure the driver the right
	 * parameters for challenge. for now, we create our own challenge.
	 */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "issue_dhchap_challenge: did=0x%x hashlist=[%x,%x,%x,%x]",
	    ndlp->nlp_DID, node_dhc->auth_cfg.hash_priority[0],
	    node_dhc->auth_cfg.hash_priority[1],
	    node_dhc->auth_cfg.hash_priority[2],
	    node_dhc->auth_cfg.hash_priority[3]);

	/*
	 * Here is my own challenge structure:
	 *
	 * 1: AUTH_MSG_HDR (12 bytes + 4 bytes + 8 bytes) 2: hasd_id (4
	 * bytes) 3: dhgp_id (4 bytes) 4: cval_len (4 bytes) 5: cval
	 * (20 bytes or 16 bytes: cval_len bytes) 6: dhval_len (4 bytes)
	 * 7: dhval (dhval_len bytes) all these information should be stored
	 * in port_dhc struct
	 */
	if (hash_id == AUTH_SHA1) {
		cmdsize = (12 + 4 + 8) + (4 + 4 + 4) + 20 + 4;
	} else if (hash_id == AUTH_MD5) {
		cmdsize = (12 + 4 + 8) + (4 + 4 + 4) + 16 + 4;
	} else {
		return (1);
	}


	switch (dhgp_id) {
	case GROUP_NULL:
		break;

	case GROUP_1024:
		cmdsize += 128;
		break;

	case GROUP_1280:
		cmdsize += 160;
		break;

	case GROUP_1536:
		cmdsize += 192;
		break;

	case GROUP_2048:
		cmdsize += 256;
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "issue_dhchap_challenge: Invalid dhgp_id=0x%x",
		    dhgp_id);
		return (1);
	}

	cmd_size = cmdsize;
	rsp_size = 4;

	if ((pkt = emlxs_prep_els_fc_pkt(port, ndlp->nlp_DID, cmd_size,
	    rsp_size,
	    0, KM_NOSLEEP)) == NULL) {
		return (1);
	}
	pCmd = (uint8_t *)pkt->pkt_cmd;

	tmp = (uint8_t *)arg;
	tmp += 8;
	/* collect tran_id: this tran_id is set by the initiator */
	tran_id = *(uint32_t *)tmp;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "issue_dhchap_challenge: 0x%x 0x%x 0x%x %d 0x%x 0x%x 0x%x",
	    ndlp->nlp_DID, node_dhc->nlp_auth_tranid_ini,
	    node_dhc->nlp_auth_tranid_rsp,
	    cmdsize, tran_id, hash_id, dhgp_id);

	/* store the tran_id : ndlp is the initiator */
	node_dhc->nlp_auth_tranid_ini = LE_SWAP32(tran_id);

	tmp += sizeof (uint32_t);

	chal = (DHCHAP_CHALL *)pCmd;
	chal->cnul.msg_hdr.auth_els_code = ELS_CMD_AUTH_CODE;
	chal->cnul.msg_hdr.auth_els_flags = 0x0;
	chal->cnul.msg_hdr.auth_msg_code = DHCHAP_CHALLENGE;
	chal->cnul.msg_hdr.proto_version = 0x01;
	chal->cnul.msg_hdr.msg_len = LE_SWAP32(cmdsize - 12);
	chal->cnul.msg_hdr.tran_id = tran_id;
	chal->cnul.msg_hdr.name_tag = (AUTH_NAME_ID);
	chal->cnul.msg_hdr.name_len = (AUTH_NAME_LEN);

	bcopy((void *) &port->wwpn,
	    (void *) &chal->cnul.msg_hdr.nodeName, sizeof (NAME_TYPE));

	chal->cnul.hash_id = hash_id;
	chal->cnul.dhgp_id = dhgp_id;

	chal->cnul.cval_len = ((chal->cnul.hash_id == AUTH_SHA1) ?
	    LE_SWAP32(SHA1_LEN) : LE_SWAP32(MD5_LEN));

	tmp = (uint8_t *)pCmd;
	tmp += sizeof (DHCHAP_CHALL_NULL);

#ifdef RAND
	/* generate a random number as the challenge */
	bzero(random_number, LE_SWAP32(chal->cnul.cval_len));

	if (hba->rdn_flag == 1) {
		emlxs_get_random_bytes(ndlp, random_number, 20);
	} else {
		(void) random_get_pseudo_bytes(random_number,
		    LE_SWAP32(chal->cnul.cval_len));
	}

	/*
	 * the host should store the challenge for later usage when later on
	 * host get the reply msg, host needs to verify it by using its old
	 * challenge, its private key as the input to the hash function. the
	 * challenge as the random_number should be stored in
	 * node_dhc->hrsp_cval[]
	 */
	if (ndlp->nlp_DID == FABRIC_DID) {
		bcopy((void *) &random_number[0],
		    (void *) &node_dhc->hrsp_cval[0],
		    LE_SWAP32(chal->cnul.cval_len));
		/* save another copy in partner's ndlp */
		bcopy((void *) &random_number[0],
		    (void *) &node_dhc->nlp_auth_misc.hrsp_cval[0],
		    LE_SWAP32(chal->cnul.cval_len));
	} else {
		bcopy((void *) &random_number[0],
		    (void *) &node_dhc->nlp_auth_misc.hrsp_cval[0],
		    LE_SWAP32(chal->cnul.cval_len));
	}
	bcopy((void *) &random_number[0], (void *) tmp,
	    LE_SWAP32(chal->cnul.cval_len));

#endif	/* RAND */

	/* for test only hardcode the challenge value */
#ifdef MYRAND
	if (ndlp->nlp_DID == FABRIC_DID) {
		bcopy((void *) myrand, (void *) &node_dhc->hrsp_cval[0],
		    LE_SWAP32(chal->cnul.cval_len));
		/* save another copy in partner's ndlp */
		bcopy((void *) myrand,
		    (void *) &node_dhc->nlp_auth_misc.hrsp_cval[0],
		    LE_SWAP32(chal->cnul.cval_len));
	} else {
		bcopy((void *) myrand,
		    (void *) &node_dhc->nlp_auth_misc.hrsp_cval[0],
		    LE_SWAP32(chal->cnul.cval_len));
	}
	bcopy((void *) myrand, (void *) tmp,
	    LE_SWAP32(chal->cnul.cval_len));

#endif	/* MYRAND */

	if (ndlp->nlp_DID == FABRIC_DID) {
		node_dhc->hrsp_cval_len = LE_SWAP32(chal->cnul.cval_len);
		node_dhc->nlp_auth_misc.hrsp_cval_len =
		    LE_SWAP32(chal->cnul.cval_len);
	} else {
		node_dhc->nlp_auth_misc.hrsp_cval_len =
		    LE_SWAP32(chal->cnul.cval_len);
	}

	tmp += LE_SWAP32(chal->cnul.cval_len);

	/*
	 * we need another random number as the private key x which will be
	 * used to compute the public key i.e. g^x mod p we intentionally set
	 * the length of private key as the same length of challenge. we have
	 * to store the private key in node_dhc->hrsp_priv_key[20].
	 */
#ifdef RAND

	if (dhgp_id != GROUP_NULL) {

		bzero(random_number, LE_SWAP32(chal->cnul.cval_len));

		if (hba->rdn_flag == 1) {
			emlxs_get_random_bytes(ndlp, random_number, 20);
		} else {
			(void) random_get_pseudo_bytes(random_number,
			    LE_SWAP32(chal->cnul.cval_len));
		}

		if (ndlp->nlp_DID == FABRIC_DID) {
			bcopy((void *) &random_number[0],
			    (void *) node_dhc->hrsp_priv_key,
			    LE_SWAP32(chal->cnul.cval_len));
			bcopy((void *) &random_number[0],
			    (void *) node_dhc->nlp_auth_misc.hrsp_priv_key,
			    LE_SWAP32(chal->cnul.cval_len));
		} else {
			bcopy((void *) &random_number[0],
			    (void *) node_dhc->nlp_auth_misc.hrsp_priv_key,
			    LE_SWAP32(chal->cnul.cval_len));
		}
	}
#endif	/* RAND */

#ifdef MYRAND
	if (dhgp_id != GROUP_NULL) {
		/* For test only we hardcode the priv_key here */
		bcopy((void *) myrand, (void *) node_dhc->hrsp_priv_key,
		    LE_SWAP32(chal->cnul.cval_len));

		if (ndlp->nlp_DID == FABRIC_DID) {
			bcopy((void *) myrand,
			    (void *) node_dhc->hrsp_priv_key,
			    LE_SWAP32(chal->cnul.cval_len));
			bcopy((void *) myrand,
			    (void *) node_dhc->nlp_auth_misc.hrsp_priv_key,
			    LE_SWAP32(chal->cnul.cval_len));
		} else {
			bcopy((void *) myrand,
			    (void *) node_dhc->nlp_auth_misc.hrsp_priv_key,
			    LE_SWAP32(chal->cnul.cval_len));
		}
	}
#endif	/* MYRAND */

	/* also store the hash function and dhgp_id being used in challenge. */
	/* These information could be configurable through HBAnyware */
	node_dhc->nlp_auth_hashid = hash_id;
	node_dhc->nlp_auth_dhgpid = dhgp_id;

	/*
	 * generate the DH value DH value is g^x mod p  and it is also called
	 * public key in which g is 2, x is the random number ontained above.
	 * p is the dhgp3_pVal
	 */

#ifdef MYRAND

	/* to get (g^x mod p) with x private key */
	if (dhgp_id != GROUP_NULL) {

		err = emlxs_BIGNUM_get_dhval(port, port_dhc, ndlp, dhval,
		    &dhval_len, chal->cnul.dhgp_id,
		    myrand, LE_SWAP32(chal->cnul.cval_len));

		if (err != BIG_OK) {
			emlxs_pkt_free(pkt);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "issue_dhchap_challenge: error. 0x%x",
			    err);

			return (1);
		}
		/* we are not going to use dhval and dhval_len */

		/* *(uint32_t *)tmp = dhval_len; */
		if (ndlp->nlp_DID == FABRIC_DID) {
			*(uint32_t *)tmp =
			    LE_SWAP32(node_dhc->hrsp_pubkey_len);
		} else {
			*(uint32_t *)tmp =
			    LE_SWAP32(
			    node_dhc->nlp_auth_misc.hrsp_pubkey_len);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "issue_dhchap_challenge: 0x%x: 0x%x 0x%x",
		    ndlp->nlp_DID, *(uint32_t *)tmp, dhval_len);

		tmp += sizeof (uint32_t);

		if (ndlp->nlp_DID == FABRIC_DID) {
			bcopy((void *) node_dhc->hrsp_pub_key, (void *)tmp,
			    node_dhc->hrsp_pubkey_len);
		} else {
			bcopy((void *) node_dhc->nlp_auth_misc.hrsp_pub_key,
			    (void *)tmp,
			    node_dhc->nlp_auth_misc.hrsp_pubkey_len);
		}
	} else {
		/* NULL DHCHAP */
		*(uint32_t *)tmp = 0;
	}

#endif	/* MYRAND */

#ifdef RAND

	/* to get (g^x mod p) with x private key */
	if (dhgp_id != GROUP_NULL) {

		err = emlxs_BIGNUM_get_dhval(port, port_dhc, ndlp, dhval,
		    &dhval_len, chal->cnul.dhgp_id,
		    random_number, LE_SWAP32(chal->cnul.cval_len));

		if (err != BIG_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "issue_dhchap_challenge: error. 0x%x",
			    err);

			emlxs_pkt_free(pkt);
			return (1);
		}
		/* we are not going to use dhval and dhval_len */

		/* *(uint32_t *)tmp = dhval_len; */
		if (ndlp->nlp_DID == FABRIC_DID) {
			*(uint32_t *)tmp =
			    LE_SWAP32(node_dhc->hrsp_pubkey_len);
		} else {
			*(uint32_t *)tmp =
			    LE_SWAP32(
			    node_dhc->nlp_auth_misc.hrsp_pubkey_len);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "issue_dhchap_challenge: did=0x%x: pubkey_len=0x%x",
		    ndlp->nlp_DID, *(uint32_t *)tmp);

		tmp += sizeof (uint32_t);

		if (ndlp->nlp_DID == FABRIC_DID) {
			bcopy((void *) node_dhc->hrsp_pub_key, (void *)tmp,
			    node_dhc->hrsp_pubkey_len);
		} else {
			bcopy((void *) node_dhc->nlp_auth_misc.hrsp_pub_key,
			    (void *)tmp,
			    node_dhc->nlp_auth_misc.hrsp_pubkey_len);
		}
	} else {
		/* NULL DHCHAP */
		*(uint32_t *)tmp = 0;
	}

#endif	/* RAND */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "issue_dhchap_challenge: 0x%x 0x%x 0x%x 0x%x 0x%x",
	    ndlp->nlp_DID, node_dhc->nlp_auth_tranid_ini,
	    node_dhc->nlp_auth_tranid_rsp,
	    chal->cnul.hash_id, chal->cnul.dhgp_id);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "issue_dhchap_challenge: 0x%x 0x%x 0x%x 0x%x",
	    ndlp->nlp_DID, tran_id, node_dhc->nlp_auth_hashid,
	    node_dhc->nlp_auth_dhgpid);

	pkt->pkt_comp = emlxs_cmpl_dhchap_challenge_issue;

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		emlxs_pkt_free(pkt);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "issue_dhchap_challenge: Unable to send fc packet.");

		return (1);
	}
	return (0);

} /* emlxs_issue_dhchap_challenge */


/*
 * DHCHAP_Reply msg
 */
/* ARGSUSED */
uint32_t
emlxs_issue_dhchap_reply(
	emlxs_port_t *port,
	NODELIST *ndlp,
	int retry,
	uint32_t *arg1, /* response */
	uint8_t *dhval,
	uint32_t dhval_len,
	uint8_t *arg2,	/* random number */
	uint32_t arg2_len)
{
	fc_packet_t *pkt;
	uint32_t cmd_size;
	uint32_t rsp_size;
	uint16_t cmdsize = 0;
	DHCHAP_REPLY_HDR *ap;
	uint8_t *pCmd;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	/* Header size */
	cmdsize = sizeof (DHCHAP_REPLY_HDR);

	/* Rsp value len size (4) + Response value size */
	if (ndlp->nlp_DID == FABRIC_DID) {
		if (node_dhc->hash_id == AUTH_MD5) {
			cmdsize += 4 + MD5_LEN;
		}
		if (node_dhc->hash_id == AUTH_SHA1) {
			cmdsize += 4 + SHA1_LEN;
		}
	} else {
		if (node_dhc->nlp_auth_hashid == AUTH_MD5) {
			cmdsize += 4 + MD5_LEN;
		}
		if (node_dhc->nlp_auth_hashid == AUTH_SHA1) {
			cmdsize += 4 + SHA1_LEN;
		}
	}

	/* DH value len size (4) + DH value size */
	if (ndlp->nlp_DID == FABRIC_DID) {
		switch (node_dhc->dhgp_id) {
		case GROUP_NULL:

			break;

		case GROUP_1024:
		case GROUP_1280:
		case GROUP_1536:
		case GROUP_2048:
		default:
			break;
		}
	}

	cmdsize += 4 + dhval_len;

	/* Challenge value len size (4) + Challenge value size */
	if (node_dhc->auth_cfg.bidirectional == 0) {
		cmdsize += 4;
	} else {
		if (ndlp->nlp_DID == FABRIC_DID) {
			cmdsize += 4 + ((node_dhc->hash_id == AUTH_MD5) ?
			    MD5_LEN : SHA1_LEN);
		} else {
			cmdsize += 4 +
			    ((node_dhc->nlp_auth_hashid == AUTH_MD5) ? MD5_LEN :
			    SHA1_LEN);
		}
	}

	cmd_size = cmdsize;
	rsp_size = 4;

	if ((pkt = emlxs_prep_els_fc_pkt(port, ndlp->nlp_DID, cmd_size,
	    rsp_size, 0, KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "issue_dhchap_reply failed: did=0x%x size=%x,%x",
		    ndlp->nlp_DID, cmd_size, rsp_size);

		return (1);
	}
	pCmd = (uint8_t *)pkt->pkt_cmd;

	ap = (DHCHAP_REPLY_HDR *)pCmd;
	ap->auth_els_code = ELS_CMD_AUTH_CODE;
	ap->auth_els_flags = 0x0;
	ap->auth_msg_code = DHCHAP_REPLY;
	ap->proto_version = 0x01;
	ap->msg_len = LE_SWAP32(cmdsize - sizeof (DHCHAP_REPLY_HDR));
	ap->tran_id = LE_SWAP32(node_dhc->nlp_auth_tranid_rsp);

	pCmd = (uint8_t *)(pCmd + sizeof (DHCHAP_REPLY_HDR));

	if (ndlp->nlp_DID == FABRIC_DID) {
		if (node_dhc->hash_id == AUTH_MD5) {
			*(uint32_t *)pCmd = LE_SWAP32(MD5_LEN);
		} else {
			*(uint32_t *)pCmd = LE_SWAP32(SHA1_LEN);
		}
	} else {
		if (node_dhc->nlp_auth_hashid == AUTH_MD5) {
			*(uint32_t *)pCmd = LE_SWAP32(MD5_LEN);
		} else {
			*(uint32_t *)pCmd = LE_SWAP32(SHA1_LEN);
		}
	}

	pCmd = (uint8_t *)(pCmd + 4);

	if (ndlp->nlp_DID == FABRIC_DID) {
		if (node_dhc->hash_id == AUTH_MD5) {
			bcopy((void *)arg1, pCmd, MD5_LEN);
			pCmd = (uint8_t *)(pCmd + MD5_LEN);
		} else {
			bcopy((void *)arg1, (void *)pCmd, SHA1_LEN);

			pCmd = (uint8_t *)(pCmd + SHA1_LEN);
		}
	} else {
		if (node_dhc->nlp_auth_hashid == AUTH_MD5) {
			bcopy((void *)arg1, pCmd, MD5_LEN);
			pCmd = (uint8_t *)(pCmd + MD5_LEN);
		} else {
			bcopy((void *)arg1, (void *)pCmd, SHA1_LEN);
			pCmd = (uint8_t *)(pCmd + SHA1_LEN);
		}
	}

	*(uint32_t *)pCmd = LE_SWAP32(dhval_len);

	if (dhval_len != 0) {
		pCmd = (uint8_t *)(pCmd + 4);

		switch (node_dhc->dhgp_id) {
		case GROUP_NULL:

			break;

		case GROUP_1024:
		case GROUP_1280:
		case GROUP_1536:
		case GROUP_2048:
		default:
			break;
		}
		/* elx_bcopy((void *)dhval, (void *)pCmd, dhval_len); */
		/*
		 * The new DH parameter (g^y mod p) is stored in
		 * node_dhc->pub_key
		 */
		/* pubkey_len should be equal to dhval_len */

		if (ndlp->nlp_DID == FABRIC_DID) {
			bcopy((void *) node_dhc->pub_key, (void *)pCmd,
			    node_dhc->pubkey_len);
		} else {
			bcopy((void *) node_dhc->nlp_auth_misc.pub_key,
			    (void *)pCmd,
			    node_dhc->nlp_auth_misc.pubkey_len);
		}
		pCmd = (uint8_t *)(pCmd + dhval_len);
	} else
		pCmd = (uint8_t *)(pCmd + 4);

	if (node_dhc->auth_cfg.bidirectional == 0) {
		*(uint32_t *)pCmd = 0x0;
	} else {
		if (ndlp->nlp_DID == FABRIC_DID) {
			if (node_dhc->hash_id == AUTH_MD5) {
				*(uint32_t *)pCmd = LE_SWAP32(MD5_LEN);
				pCmd = (uint8_t *)(pCmd + 4);
				bcopy((void *)arg2, (void *)pCmd, arg2_len);
			} else if (node_dhc->hash_id == AUTH_SHA1) {
				*(uint32_t *)pCmd = LE_SWAP32(SHA1_LEN);
				pCmd = (uint8_t *)(pCmd + 4);
				/* store the challenge */
				bcopy((void *)arg2, (void *)pCmd, arg2_len);
			}
		} else {
			if (node_dhc->nlp_auth_hashid == AUTH_MD5) {
				*(uint32_t *)pCmd = LE_SWAP32(MD5_LEN);
				pCmd = (uint8_t *)(pCmd + 4);
				bcopy((void *)arg2, (void *)pCmd, arg2_len);
			} else if (node_dhc->nlp_auth_hashid == AUTH_SHA1) {
				*(uint32_t *)pCmd = LE_SWAP32(SHA1_LEN);
				pCmd = (uint8_t *)(pCmd + 4);
				bcopy((void *)arg2, (void *)pCmd, arg2_len);
			}
		}
	}

	pkt->pkt_comp = emlxs_cmpl_dhchap_reply_issue;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "issue_dhchap_reply: did=0x%x  (%x,%x,%x,%x,%x,%x)",
	    ndlp->nlp_DID, dhval_len, arg2_len, cmdsize,
	    node_dhc->hash_id, node_dhc->nlp_auth_hashid,
	    LE_SWAP32(ap->tran_id));

	if (emlxs_pkt_send(pkt, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "issue_dhchap_reply failed: Unable to send packet.");

		emlxs_pkt_free(pkt);

		return (1);
	}
	return (0);

} /* emlxs_issue_dhchap_reply */



/*
 * ! emlxs_rcv_auth_msg_auth_negotiate_cmpl_wait4next
 *
 * \pre \post \param   phba \param   ndlp \param   arg \param   evt \return
 * uint32_t \b Description:
 *
 * This routine is invoked when the host received an unsolicted ELS AUTH MSG
 * from an NxPort or FxPort which already replied (ACC)
 * the ELS AUTH_Negotiate msg from the host. if msg is DHCHAP_Chellenge,
 * based on the msg content (DHCHAP computation etc.,)
 * the host send back ACC and 1. send back AUTH_Reject and set next state =
 * NPR_NODE or 2. send back DHCHAP_Reply msg and set
 * next state = DHCHAP_REPLY_ISSUE for bi-directional, the DHCHAP_Reply
 * includes challenge from host. for uni-directional, no
 * more challenge. if msg is AUTH_Reject or anything else, host send back
 * ACC and set next state = NPR_NODE. And based on the
 * reject code, host may need to retry negotiate with NULL DH only
 *
 * If the msg is AUTH_ELS cmd, cancel the nlp_authrsp_timeout timer immediately.
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_auth_negotiate_cmpl_wait4next(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	emlxs_hba_t *hba = HBA;
	emlxs_port_dhc_t *port_dhc = &port->port_dhc;
	IOCBQ *iocbq = (IOCBQ *)arg2;
	MATCHMAP *mp = (MATCHMAP *)arg3;
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint8_t *bp;
	uint32_t *lp;
	DHCHAP_CHALL_NULL *ncval;
	uint16_t namelen;
	uint32_t dhvallen;
	uint8_t *tmp;
	uint8_t ReasonCode;
	uint8_t ReasonCodeExplanation;

	union challenge_val un_cval;

	uint8_t *dhval = NULL;
	uint8_t random_number[20];	/* for both SHA1 and MD5 */
	uint32_t *arg5 = NULL;	/* response */
	uint32_t tran_id;	/* Transaction Identifier */
	uint32_t arg2len = 0;	/* len of new challenge for bidir auth */

	AUTH_RJT *rjt;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_auth_negotiate_cmpl_wait4next: did=0x%x",
	    ndlp->nlp_DID);

	emlxs_dhc_state(port, ndlp, NODE_STATE_DHCHAP_REPLY_ISSUE, 0, 0);

	(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC, ELS_CMD_AUTH, 0, 0);

	bp = mp->virt;
	lp = (uint32_t *)bp;

	/*
	 * 1. we process the DHCHAP_Challenge 2. ACC it first 3. based on the
	 * result of 1 we DHCHAP_Reply or AUTH_Reject
	 */
	ncval = (DHCHAP_CHALL_NULL *)((uint8_t *)lp);

	if (ncval->msg_hdr.auth_els_code != ELS_CMD_AUTH_CODE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_auth_negotiate_cmpl_wait4next: 0x%x %x",
		    ndlp->nlp_DID, ncval->msg_hdr.auth_els_code);

		/* need to setup reason code/reason explanation code  */
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PROTOCOL;
		goto AUTH_Reject;
	}
	if (ncval->msg_hdr.auth_msg_code == AUTH_REJECT) {
		rjt = (AUTH_RJT *)((uint8_t *)lp);
		ReasonCode = rjt->ReasonCode;
		ReasonCodeExplanation = rjt->ReasonCodeExplanation;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_auth_negotiate_cmpl_wait4next: 0x%x.%x,%x",
		    ndlp->nlp_DID, ReasonCode, ReasonCodeExplanation);

		switch (ReasonCode) {
		case AUTHRJT_LOGIC_ERR:
			switch (ReasonCodeExplanation) {
			case AUTHEXP_MECH_UNUSABLE:
			case AUTHEXP_DHGROUP_UNUSABLE:
			case AUTHEXP_HASHFUNC_UNUSABLE:
				ReasonCode = AUTHRJT_LOGIC_ERR;
				ReasonCodeExplanation = AUTHEXP_RESTART_AUTH;
				break;

			case AUTHEXP_RESTART_AUTH:
				/*
				 * Cancel the rsp timer if not cancelled yet.
				 * and restart auth tran now.
				 */
				if (node_dhc->nlp_authrsp_tmo != 0) {
					node_dhc->nlp_authrsp_tmo = 0;
					node_dhc->nlp_authrsp_tmocnt = 0;
				}
				if (emlxs_dhc_auth_start(port, ndlp, NULL,
				    NULL) != 0) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_fcsp_debug_msg,
					    "Reauth timeout. failed. 0x%x %x",
					    ndlp->nlp_DID, node_dhc->state);
				}
				return (node_dhc->state);

			default:
				ReasonCode = AUTHRJT_FAILURE;
				ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
				break;
			}
			break;

		case AUTHRJT_FAILURE:
		default:
			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
			break;
		}

		goto AUTH_Reject;
	}
	if (ncval->msg_hdr.auth_msg_code != DHCHAP_CHALLENGE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_auth_negotiate_cmpl_wait4next: 0x%x.%x",
		    ndlp->nlp_DID, ncval->msg_hdr.auth_msg_code);

		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PROTOCOL;
		goto AUTH_Reject;
	}
	tran_id = ncval->msg_hdr.tran_id;

	if (LE_SWAP32(tran_id) != node_dhc->nlp_auth_tranid_rsp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_auth_negotiate_cmpl_wait4next:0x%x %x!=%x",
		    ndlp->nlp_DID, LE_SWAP32(tran_id),
		    node_dhc->nlp_auth_tranid_rsp);

		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;
		goto AUTH_Reject;
	}
	node_dhc->nlp_authrsp_tmo = 0;

	namelen = ncval->msg_hdr.name_len;

	if (namelen == AUTH_NAME_LEN) {
		/*
		 * store another copy of wwn of fabric/or nport used in
		 * AUTH_ELS cmd
		 */
		bcopy((void *)&ncval->msg_hdr.nodeName,
		    (void *)&node_dhc->nlp_auth_wwn, sizeof (NAME_TYPE));
	}
	/* Collect the challenge value */
	tmp = (uint8_t *)((uint8_t *)lp + sizeof (DHCHAP_CHALL_NULL));

	if (ncval->hash_id == AUTH_MD5) {
		if (ncval->cval_len != LE_SWAP32(MD5_LEN)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_auth_negotiate_cmpl_wait4next:0x%x.%x!=%x",
		    ndlp->nlp_DID, ncval->cval_len, LE_SWAP32(MD5_LEN));

			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;
			goto AUTH_Reject;
		}
		bzero(un_cval.md5.val, sizeof (MD5_CVAL));
		bcopy((void *)tmp, (void *)un_cval.md5.val,
		    sizeof (MD5_CVAL));
		tmp += sizeof (MD5_CVAL);

		arg2len = MD5_LEN;

	} else if (ncval->hash_id == AUTH_SHA1) {
		if (ncval->cval_len != LE_SWAP32(SHA1_LEN)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_auth_negotiate_cmpl_wait4next: 0x%x %x!=%x",
		    ndlp->nlp_DID, ncval->cval_len, LE_SWAP32(MD5_LEN));

			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;
			goto AUTH_Reject;
		}
		bzero(un_cval.sha1.val, sizeof (SHA1_CVAL));
		bcopy((void *)tmp, (void *)un_cval.sha1.val,
		    sizeof (SHA1_CVAL));
		tmp += sizeof (SHA1_CVAL);

		arg2len = SHA1_LEN;

	} else {
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "rcv_auth_msg_auth_negotiate_cmpl_wait4next: 0x%x %x",
	    ndlp->nlp_DID, ncval->hash_id);

		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;
		goto AUTH_Reject;
	}

	/*
	 * store hash_id for later usage : hash_id is set by responder in its
	 * dhchap_challenge
	 */
	node_dhc->hash_id = ncval->hash_id;

	/* always use this */
	/* store another copy of the hash_id */
	node_dhc->nlp_auth_hashid = ncval->hash_id;

	/* store dhgp_id for later usage */
	node_dhc->dhgp_id = ncval->dhgp_id;

	/* store another copy of dhgp_id */
	/* always use this */
	node_dhc->nlp_auth_dhgpid = ncval->dhgp_id;

	/*
	 * ndlp->nlp_auth_hashid, nlp_auth_dhgpid store the hashid and dhgpid
	 * when this very ndlp is the auth transaction responder (in other
	 * words, responder means that this ndlp is send the host the
	 * challenge. ndlp could be fffffe or another initiator or target
	 * nport.
	 */

	dhvallen = *((uint32_t *)(tmp));

	switch (ncval->dhgp_id) {
	case GROUP_NULL:
		/* null DHCHAP only */
		if (LE_SWAP32(dhvallen) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_auth_negotiate_cmpl_wait4next: 0x%x %x %x",
		    ndlp->nlp_DID, ncval->dhgp_id, LE_SWAP32(dhvallen));

			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;
			goto AUTH_Reject;
		}
		break;

	case GROUP_1024:
	case GROUP_1280:
	case GROUP_1536:
	case GROUP_2048:
		/* Collect the DH Value */
		tmp += sizeof (uint32_t);

		dhval = (uint8_t *)kmem_zalloc(LE_SWAP32(dhvallen),
		    KM_NOSLEEP);
		if (dhval == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_auth_negotiate_cmpl_wait4next: 0x%x %x %x",
		    ndlp->nlp_DID, ncval->dhgp_id, dhval);

			ReasonCode = AUTHRJT_LOGIC_ERR;
			ReasonCodeExplanation = AUTHEXP_RESTART_AUTH;
			goto AUTH_Reject;
		}
		bcopy((void *)tmp, (void *)dhval, LE_SWAP32(dhvallen));
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_auth_negotiate_cmpl_wait4next: 0x%x %x.",
		    ndlp->nlp_DID, ncval->dhgp_id);

		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;
		goto AUTH_Reject;
	}

	/*
	 * Calculate the hash value, hash function, DH group, secret etc.
	 * could be stored in port_dhc.
	 */

	/* arg5 has the response with NULL or Full DH group support */
	arg5 = (uint32_t *)emlxs_hash_rsp(port, port_dhc,
	    ndlp, tran_id, un_cval, dhval, LE_SWAP32(dhvallen));

	/* Or should check ndlp->auth_cfg..... */
	if (node_dhc->auth_cfg.bidirectional == 1) {
		/* get arg2 here */
		/*
		 * arg2 is the new challenge C2 from initiator if bi-dir auth
		 * is supported
		 */
		bzero(&random_number, sizeof (random_number));

		if (hba->rdn_flag == 1) {
			emlxs_get_random_bytes(ndlp, random_number, 20);
		} else {
			(void) random_get_pseudo_bytes(random_number, arg2len);
		}

		/* cache it for later verification usage */
		if (ndlp->nlp_DID == FABRIC_DID) {
			bcopy((void *)&random_number[0],
			    (void *)&node_dhc->bi_cval[0], arg2len);
			node_dhc->bi_cval_len = arg2len;

			/* save another copy in our partner's ndlp */
			bcopy((void *)&random_number[0],
			    (void *)&node_dhc->nlp_auth_misc.bi_cval[0],
			    arg2len);
			node_dhc->nlp_auth_misc.bi_cval_len = arg2len;
		} else {
			bcopy((void *)&random_number[0],
			    (void *)&node_dhc->nlp_auth_misc.bi_cval[0],
			    arg2len);
			node_dhc->nlp_auth_misc.bi_cval_len = arg2len;
		}
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_auth_negotiate_cmpl_wait4next:0x%x(%x,%x,%x,%x,%x)",
	    ndlp->nlp_DID, node_dhc->nlp_auth_tranid_rsp,
	    node_dhc->nlp_auth_tranid_ini,
	    ncval->hash_id, ncval->dhgp_id, dhvallen);

	/* Issue ELS DHCHAP_Reply */
	/*
	 * arg1 has the response, arg2 has the new challenge if needed (g^y
	 * mod p) is the pubkey: all are ready and to go
	 */

	/* return 0 success, otherwise failure */
	if (emlxs_issue_dhchap_reply(port, ndlp, 0, arg5, dhval,
	    LE_SWAP32(dhvallen),
	    random_number, arg2len)) {
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "rcv_auth_msg_auth_negotiate_cmpl_wait4next: 0x%x.failed.",
	    ndlp->nlp_DID);

		kmem_free(dhval, LE_SWAP32(dhvallen));
		ReasonCode = AUTHRJT_LOGIC_ERR;
		ReasonCodeExplanation = AUTHEXP_RESTART_AUTH;
		goto AUTH_Reject;
	}
	return (node_dhc->state);

AUTH_Reject:

	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_FAILED, ReasonCode,
	    ReasonCodeExplanation);
	(void) emlxs_issue_auth_reject(port, ndlp, 0, 0, ReasonCode,
	    ReasonCodeExplanation);
	emlxs_dhc_auth_complete(port, ndlp, 1);

	return (node_dhc->state);

} /* emlxs_rcv_auth_msg_auth_negotiate_cmpl_wait4next */


/*
 * This routine should be set to emlxs_disc_neverdev
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_cmpl_auth_msg_auth_negotiate_cmpl_wait4next(
emlxs_port_t	*port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "cmpl_auth_msg_auth_negotiate_cmpl_wait4next.0x%x. Not iplted.",
	    ndlp->nlp_DID);

	return (0);
} /* emlxs_cmpl_auth_msg_auth_negotiate_cmpl_wait4next() */


/*
 * ! emlxs_rcv_auth_msg_dhchap_reply_issue
 *
 * This routine is invoked when the host received an unsolicited ELS AUTH
 * msg from an NxPort or FxPort into which the host has
 * sent an ELS DHCHAP_Reply msg. since the host is the initiator and the
 * AUTH transaction is in progress between host and the
 * NxPort or FxPort, as a result, the host will send back ACC and AUTH_Reject
 * and set the next state = NPR_NODE.
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_dhchap_reply_issue(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ   * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "rcv_auth_msg_dhchap_reply_issue called. 0x%x. Not implemented.",
	    ndlp->nlp_DID);

	return (0);

} /* emlxs_rcv_auth_msg_dhchap_reply_issue */



/*
 * ! emlxs_cmpl_auth_msg_dhchap_reply_issue
 *
 * This routine is invoked when
 * the host received a solicited ACC/RJT from ELS command from an NxPort
 * or FxPort that already received the ELS DHCHAP_Reply
 * msg from the host. in case of ACC, next state = DHCHAP_REPLY_CMPL_WAIT4NEXT
 * in case of RJT, next state = NPR_NODE
 */
/* ARGSUSED */
static uint32_t
emlxs_cmpl_auth_msg_dhchap_reply_issue(
emlxs_port_t *port,
/* CHANNEL  * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *) arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "cmpl_auth_msg_dhchap_reply_issue: did=0x%x",
	    ndlp->nlp_DID);

	/* start the emlxs_dhc_authrsp_timeout timer now */
	if (node_dhc->nlp_authrsp_tmo == 0) {
		node_dhc->nlp_authrsp_tmo = DRV_TIME +
		    node_dhc->auth_cfg.authentication_timeout;
	}
	/*
	 * The next state should be
	 * emlxs_rcv_auth_msg_dhchap_reply_cmpl_wait4next
	 */
	emlxs_dhc_state(port, ndlp,
	    NODE_STATE_DHCHAP_REPLY_CMPL_WAIT4NEXT, 0, 0);

	return (node_dhc->state);

} /* emlxs_cmpl_auth_msg_dhchap_reply_issue */



/*
 * ! emlxs_rcv_auth_msg_dhchap_reply_cmpl_wait4next
 *
 * \pre \post \param   phba \param   ndlp \param   arg \param   evt \return
 * uint32_t \b Description: This rountine is invoked
 * when the host received an unsolicited ELS AUTH Msg from the NxPort or
 * FxPort that already sent ACC back to the host after
 * receipt of DHCHAP_Reply msg. In normal case, this unsolicited msg could
 * be DHCHAP_Success msg.
 *
 * if msg is ELS DHCHAP_Success, based on the payload, host send back ACC and 1.
 * for uni-directional, and set next state =
 * REG_LOGIN. 2. for bi-directional,  and host do some computations
 * (hash etc) and send back either DHCHAP_Success Msg and set
 * next state = DHCHAP_SUCCESS_ISSUE_WAIT4NEXT or AUTH_Reject and set next
 * state = NPR_NODE. if msg is ELS AUTH_Reject, then
 * send back ACC and set next state = NPR_NODE if msg is anything else, then
 * RJT and set next state = NPR_NODE
 */
/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_dhchap_reply_cmpl_wait4next(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	emlxs_port_dhc_t *port_dhc = &port->port_dhc;
	IOCBQ *iocbq = (IOCBQ *)arg2;
	MATCHMAP *mp = (MATCHMAP *)arg3;
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint8_t *bp;
	uint32_t *lp;
	DHCHAP_SUCCESS_HDR *dh_success;
	uint8_t *tmp;
	uint8_t rsp_size;
	AUTH_RJT *auth_rjt;
	uint32_t tran_id;
	uint32_t *hash_val;
	union challenge_val un_cval;
	uint8_t ReasonCode;
	uint8_t ReasonCodeExplanation;
	char info[64];

	bp = mp->virt;
	lp = (uint32_t *)bp;

	/*
	 * 1. we process the DHCHAP_Success or AUTH_Reject 2. ACC it first 3.
	 * based on the result of 1 we goto the next stage SCR etc.
	 */

	/* sp = (SERV_PARM *)((uint8_t *)lp + sizeof(uint32_t)); */
	dh_success = (DHCHAP_SUCCESS_HDR *)((uint8_t *)lp);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_dhchap_reply_cmpl_wait4next: 0x%x 0x%x 0x%x",
	    ndlp->nlp_DID, dh_success->auth_els_code,
	    dh_success->auth_msg_code);

	node_dhc->nlp_authrsp_tmo = 0;

	(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC, ELS_CMD_AUTH, 0, 0);

	if (dh_success->auth_msg_code == AUTH_REJECT) {
		/* ACC it and retry etc.  */
		auth_rjt = (AUTH_RJT *) dh_success;
		ReasonCode = auth_rjt->ReasonCode;
		ReasonCodeExplanation = auth_rjt->ReasonCodeExplanation;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_dhchap_reply_cmpl_wait4next: 0x%x.(%x,%x)",
	    ndlp->nlp_DID, ReasonCode, ReasonCodeExplanation);

		switch (ReasonCode) {
		case AUTHRJT_LOGIC_ERR:
			switch (ReasonCodeExplanation) {
			case AUTHEXP_MECH_UNUSABLE:
			case AUTHEXP_DHGROUP_UNUSABLE:
			case AUTHEXP_HASHFUNC_UNUSABLE:
				ReasonCode = AUTHRJT_LOGIC_ERR;
				ReasonCodeExplanation = AUTHEXP_RESTART_AUTH;
				break;

			case AUTHEXP_RESTART_AUTH:
				/*
				 * Cancel the rsp timer if not cancelled yet.
				 * and restart auth tran now.
				 */
				if (node_dhc->nlp_authrsp_tmo != 0) {
					node_dhc->nlp_authrsp_tmo = 0;
					node_dhc->nlp_authrsp_tmocnt = 0;
				}
				if (emlxs_dhc_auth_start(port, ndlp,
				    NULL, NULL) != 0) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_fcsp_debug_msg,
					    "Reauth timeout.failed. 0x%x %x",
					    ndlp->nlp_DID, node_dhc->state);
				}
				return (node_dhc->state);

			default:
				ReasonCode = AUTHRJT_FAILURE;
				ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
				break;
			}
			break;

		case AUTHRJT_FAILURE:
		default:
			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
			emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_FAILED,
			    ReasonCode, ReasonCodeExplanation);
			goto out;
		}

		goto AUTH_Reject;
	}
	if (dh_success->auth_msg_code == DHCHAP_SUCCESS) {

		/* Verify the tran_id */
		tran_id = dh_success->tran_id;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_dhchap_reply_cmpl_wait4next: 0x%x 0x%x 0x%x 0x%x",
	    ndlp->nlp_DID, LE_SWAP32(tran_id),
	    node_dhc->nlp_auth_tranid_rsp,
	    node_dhc->nlp_auth_tranid_ini);

		if (LE_SWAP32(tran_id) != node_dhc->nlp_auth_tranid_rsp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_dhchap_reply_cmpl_wait4next:0x%x %x!=%x",
		    ndlp->nlp_DID, LE_SWAP32(tran_id),
		    node_dhc->nlp_auth_tranid_rsp);

			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;
			goto AUTH_Reject;
		}
		if (node_dhc->auth_cfg.bidirectional == 0) {
			node_dhc->flag |=
			    (NLP_REMOTE_AUTH | NLP_SET_REAUTH_TIME);

			emlxs_dhc_state(port, ndlp,
			    NODE_STATE_AUTH_SUCCESS, 0, 0);
			emlxs_log_auth_event(port, ndlp,
			    "rcv_auth_msg_dhchap_reply_cmpl_wait4next",
			    "Host-initiated-unidir-auth-success");
			emlxs_dhc_auth_complete(port, ndlp, 0);
		} else {
			/* bidir auth needed */
			/* if (LE_SWAP32(dh_success->msg_len) > 4) { */

			tmp = (uint8_t *)((uint8_t *)lp);
			tmp += 8;
			tran_id = *(uint32_t *)tmp;
			tmp += 4;
			rsp_size = *(uint32_t *)tmp;
			tmp += 4;

			/* tmp has the response from responder */

			/*
			 * node_dhc->bi_cval has the bidir challenge value
			 * from initiator
			 */

			if (LE_SWAP32(rsp_size) == 16) {
				bzero(un_cval.md5.val, LE_SWAP32(rsp_size));
				if (ndlp->nlp_DID == FABRIC_DID)
					bcopy((void *)node_dhc->bi_cval,
					    (void *)un_cval.md5.val,
					    LE_SWAP32(rsp_size));
				else
				bcopy(
				    (void *)node_dhc->nlp_auth_misc.bi_cval,
				    (void *)un_cval.md5.val,
				    LE_SWAP32(rsp_size));

			} else if (LE_SWAP32(rsp_size) == 20) {

				bzero(un_cval.sha1.val, LE_SWAP32(rsp_size));
				if (ndlp->nlp_DID == FABRIC_DID)
					bcopy((void *)node_dhc->bi_cval,
					    (void *)un_cval.sha1.val,
					    LE_SWAP32(rsp_size));
				else
				bcopy(
				    (void *)node_dhc->nlp_auth_misc.bi_cval,
				    (void *)un_cval.sha1.val,
				    LE_SWAP32(rsp_size));
			}
			/* verify the response */
			/* NULL DHCHAP works for now */
			/* for DH group as well */

			/*
			 * Cai2 = H (C2 || ((g^x mod p)^y mod p) ) = H (C2 ||
			 * (g^xy mod p) )
			 *
			 * R = H (Ti || Km || Cai2) R ?= R2
			 */
			hash_val = emlxs_hash_vrf(port, port_dhc, ndlp,
			    tran_id, un_cval);

			if (bcmp((void *)tmp, (void *)hash_val,
			    LE_SWAP32(rsp_size))) {
				if (hash_val != NULL) {
					/* not identical */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_dhchap_reply_cmpl_wait4next: 0x%x.failed. %x",
	    ndlp->nlp_DID, *(uint32_t *)hash_val);
				}
				ReasonCode = AUTHRJT_FAILURE;
				ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
				goto AUTH_Reject;
			}
			emlxs_dhc_state(port, ndlp,
			    NODE_STATE_DHCHAP_SUCCESS_ISSUE_WAIT4NEXT, 0, 0);

			/* send out DHCHAP_SUCCESS */
			(void) emlxs_issue_dhchap_success(port, ndlp, 0, 0);
		}
	}
	return (node_dhc->state);

AUTH_Reject:

	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_FAILED,
	    ReasonCode, ReasonCodeExplanation);
	(void) emlxs_issue_auth_reject(port, ndlp, 0, 0, ReasonCode,
	    ReasonCodeExplanation);
	emlxs_dhc_auth_complete(port, ndlp, 1);

	return (node_dhc->state);
out:
	(void) snprintf(info, sizeof (info),
	    "Auth Failed: ReasonCode=0x%x, ReasonCodeExplanation=0x%x",
	    ReasonCode, ReasonCodeExplanation);

	emlxs_log_auth_event(port, ndlp,
	    "rcv_auth_msg_dhchap_reply_cmpl_wait4next", info);
	emlxs_dhc_auth_complete(port, ndlp, 1);

	return (node_dhc->state);

} /* emlxs_rcv_auth_msg_dhchap_reply_cmpl_wait4next */



/*
 * This routine should be set to emlxs_disc_neverdev as it shouldnot happen.
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_cmpl_auth_msg_dhchap_reply_cmpl_wait4next(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ  * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "cmpl_auth_msg_dhchap_reply_cmpl_wait4next. 0x%x.Not ipleted.",
	    ndlp->nlp_DID);

	return (0);

} /* emlxs_cmpl_auth_msg_dhchap_reply_cmpl_wait4next */


/*
 * emlxs_rcv_auth_msg_dhchap_success_issue_wait4next
 *
 * This routine is supported
 * for HBA in either auth initiator mode or responder mode.
 *
 * This routine is invoked when the host as the auth responder received
 * an unsolicited ELS AUTH msg from the NxPort as the auth
 * initiator that already received the ELS DHCHAP_Success.
 *
 * If the host is the auth initiator and since the AUTH transction is
 * already in progress, therefore, any auth els msg should not
 * happen and if happened, RJT and move to NPR_NODE.
 *
 * If the host is the auth reponder, this unsolicited els auth msg should
 * be DHCHAP_Success for this bi-directional auth
 * transaction. In which case, the host should send ACC back and move state
 * to REG_LOGIN. If this unsolicited els auth msg is
 * DHCHAP_Reject, which could mean that the auth failed, then host should
 * send back ACC and set the next state to NPR_NODE.
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_dhchap_success_issue_wait4next(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *) arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "rcv_auth_msg_dhchap_success_issue_wait4next. 0x%x. Not iplted.",
	    ndlp->nlp_DID);

	return (0);

} /* emlxs_rcv_auth_msg_dhchap_success_issue_wait4next */



/*
 * ! emlxs_cmpl_auth_msg_dhchap_success_issue_wait4next
 *
 * This routine is invoked when
 * the host as the auth initiator received an solicited ACC/RJT from the
 * NxPort or FxPort that already received DHCHAP_Success
 * Msg the host sent before. in case of ACC, set next state = REG_LOGIN.
 * in case of RJT, set next state = NPR_NODE.
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_cmpl_auth_msg_dhchap_success_issue_wait4next(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	/*
	 * Either host is the initiator and auth or (reauth bi-direct) is
	 * done, so start host reauth heartbeat timer now if host side reauth
	 * heart beat never get started. Or host is the responder and the
	 * other entity is done with its reauth heart beat with
	 * uni-directional auth. Anyway we start host side reauth heart beat
	 * timer now.
	 */

	node_dhc->flag &= ~NLP_REMOTE_AUTH;
	node_dhc->flag |= NLP_SET_REAUTH_TIME;

	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_SUCCESS, 0, 0);
	emlxs_log_auth_event(port, ndlp,
	    "cmpl_auth_msg_dhchap_success_issue_wait4next",
	    "Host-initiated-bidir-auth-success");
	emlxs_dhc_auth_complete(port, ndlp, 0);

	return (node_dhc->state);

} /* emlxs_cmpl_auth_msg_dhchap_success_issue_wait4next */


/*
 * ! emlxs_cmpl_auth_msg_auth_negotiate_rcv
 *
 * This routine is invoked when
 * the host received the solicited ACC/RJT ELS cmd from an FxPort or an
 * NxPort that has received the ELS DHCHAP_Challenge.
 * The host is the auth responder and the auth transaction is still in
 * progress.
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_cmpl_auth_msg_auth_negotiate_rcv(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "cmpl_auth_msg_auth_negotiate_rcv called. 0x%x. Not implemented.",
	    ndlp->nlp_DID);

	return (0);

} /* emlxs_cmpl_auth_msg_auth_negotiate_rcv */



/*
 * ! emlxs_rcv_auth_msg_dhchap_challenge_issue
 *
 * \pre \post \param   phba \param   ndlp \param   arg \param   evt \return
 * uint32_t \b Description: This routine should be
 * emlxs_disc_neverdev. The host is the auth responder and the auth
 * transaction is still in progress, any unsolicited els auth
 * msg is unexpected and should not happen in normal case.
 *
 * If DHCHAP_Reject, ACC and next state = NPR_NODE. anything else, RJT and
 * next state = NPR_NODE.
 */
/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_dhchap_challenge_issue(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "rcv_auth_msg_dhchap_challenge_issue called. 0x%x. Not iplted.",
	    ndlp->nlp_DID);

	return (0);

} /* emlxs_rcv_auth_msg_dhchap_challenge_issue */



/*
 * ! emlxs_cmpl_auth_msg_dhchap_challenge_issue
 *
 * \pre \post \param   phba \param   ndlp \param   arg \param   evt \return
 * uint32_t \b Description: This routine is invoked when
 * the host as the responder received the solicited response (ACC or RJT)
 * from initiator to the DHCHAP_Challenge msg sent from
 * host. In case of ACC, the next state = DHCHAP_CHALLENGE_CMPL_WAIT4NEXT
 * In case of RJT, the next state = NPR_NODE.
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_cmpl_auth_msg_dhchap_challenge_issue(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	/*
	 * The next state should be
	 * emlxs_rcv_auth_msg_dhchap_challenge_cmpl_wait4next
	 */
	emlxs_dhc_state(port, ndlp,
	    NODE_STATE_DHCHAP_CHALLENGE_CMPL_WAIT4NEXT, 0, 0);

	/* Start the fc_authrsp_timeout timer */
	if (node_dhc->nlp_authrsp_tmo == 0) {
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "cmpl_auth_msg_dhchap_challenge_issue: Starting authrsp timer.");

		node_dhc->nlp_authrsp_tmo = DRV_TIME +
		    node_dhc->auth_cfg.authentication_timeout;
	}
	return (node_dhc->state);

} /* emlxs_cmpl_auth_msg_dhchap_challenge_issue */


/*
 * ! emlxs_rcv_auth_msg_dhchap_challenge_cmpl_wait4next
 *
 * \pre \post \param   phba \param   ndlp \param   arg \param   evt \return
 * uint32_t \b Description: This routine is invoked when
 * the host as the auth responder received an unsolicited auth msg from the
 * FxPort or NxPort that already sent ACC to the DHCH_
 * Challenge it received. In normal case this unsolicited auth msg should
 * be DHCHAP_Reply msg from the initiator.
 *
 * For DHCHAP_Reply msg, the host send back ACC and then do verification
 * (hash?) and send back DHCHAP_Success and next state as
 * DHCHAP_SUCCESS_ISSUE or DHCHAP_Reject and next state as NPR_NODE based on
 * the verification result.
 *
 * For bi-directional auth transaction, Reply msg should have the new
 * challenge value from the initiator. thus the Success msg
 * sent out should have the corresponding Reply from the responder.
 *
 * For uni-directional, Reply msg received does not contains the new
 * challenge and therefore the Success msg does not include the
 * Reply msg.
 *
 * For DHCHAP_Reject, send ACC and moved to the next state NPR_NODE. For
 * anything else, send RJT and moved to NPR_NODE.
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_dhchap_challenge_cmpl_wait4next(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	emlxs_port_dhc_t *port_dhc = &port->port_dhc;
	IOCBQ *iocbq = (IOCBQ *)arg2;
	MATCHMAP *mp = (MATCHMAP *)arg3;
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint8_t *bp;
	uint32_t *lp;
	DHCHAP_REPLY_HDR *dh_reply;
	uint8_t *tmp;
	uint32_t rsp_len;
	uint8_t rsp[20];	/* should cover SHA-1 and MD5's rsp */
	uint32_t dhval_len;
	uint8_t dhval[512];
	uint32_t cval_len;
	uint8_t cval[20];
	uint32_t tran_id;
	uint32_t *hash_val = NULL;
	uint8_t ReasonCode;
	uint8_t ReasonCodeExplanation;
	AUTH_RJT *rjt;

	/* ACC the ELS DHCHAP_Reply msg first */

	(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC, ELS_CMD_AUTH, 0, 0);

	bp = mp->virt;
	lp = (uint32_t *)bp;

	/*
	 * send back ELS AUTH_Reject or DHCHAP_Success msg based on the
	 * verification result. i.e., hash computation etc.
	 */
	dh_reply = (DHCHAP_REPLY_HDR *)((uint8_t *)lp);
	tmp = (uint8_t *)((uint8_t *)lp);

	tran_id = dh_reply->tran_id;

	if (LE_SWAP32(tran_id) != node_dhc->nlp_auth_tranid_ini) {

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "rcv_auth_msg_dhchap_challenge_cmpl_wait4next:0x%x 0x%x 0x%x",
	    ndlp->nlp_DID, tran_id, node_dhc->nlp_auth_tranid_ini);

		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PROTOCOL;
		goto Reject;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_a_m_dhch_chll_cmpl_wait4next:0x%x 0x%x 0x%x 0x%x 0x%x",
	    ndlp->nlp_DID, tran_id, node_dhc->nlp_auth_tranid_ini,
	    node_dhc->nlp_auth_tranid_rsp, dh_reply->auth_msg_code);

	/* cancel the nlp_authrsp_timeout timer and send out Auth_Reject */
	if (node_dhc->nlp_authrsp_tmo) {
		node_dhc->nlp_authrsp_tmo = 0;
	}
	if (dh_reply->auth_msg_code == AUTH_REJECT) {

		rjt = (AUTH_RJT *)((uint8_t *)lp);
		ReasonCode = rjt->ReasonCode;
		ReasonCodeExplanation = rjt->ReasonCodeExplanation;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_a_msg_dhch_chall_cmpl_wait4next:RJT rcved:0x%x 0x%x",
	    ReasonCode, ReasonCodeExplanation);

		switch (ReasonCode) {
		case AUTHRJT_LOGIC_ERR:
			switch (ReasonCodeExplanation) {
			case AUTHEXP_MECH_UNUSABLE:
			case AUTHEXP_DHGROUP_UNUSABLE:
			case AUTHEXP_HASHFUNC_UNUSABLE:
				ReasonCode = AUTHRJT_LOGIC_ERR;
				ReasonCodeExplanation = AUTHEXP_RESTART_AUTH;
				break;

			case AUTHEXP_RESTART_AUTH:
				/*
				 * Cancel the rsp timer if not cancelled yet.
				 * and restart auth tran now.
				 */
				if (node_dhc->nlp_authrsp_tmo != 0) {
					node_dhc->nlp_authrsp_tmo = 0;
					node_dhc->nlp_authrsp_tmocnt = 0;
				}
				if (emlxs_dhc_auth_start(port, ndlp,
				    NULL, NULL) != 0) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_debug_msg,
				    "Reauth timeout.Auth initfailed. 0x%x %x",
				    ndlp->nlp_DID, node_dhc->state);
				}
				return (node_dhc->state);

			default:
				ReasonCode = AUTHRJT_FAILURE;
				ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
				break;
			}
			break;

		case AUTHRJT_FAILURE:
		default:
			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
			break;
		}

		goto Reject;

	}
	if (dh_reply->auth_msg_code == DHCHAP_REPLY) {

		/* We must send out DHCHAP_Success msg and wait for ACC */
		/* _AND_ if bi-dir auth, we have to wait for next */

		/*
		 * Send back DHCHAP_Success or AUTH_Reject based on the
		 * verification result
		 */
		tmp += sizeof (DHCHAP_REPLY_HDR);
		rsp_len = LE_SWAP32(*(uint32_t *)tmp);
		tmp += sizeof (uint32_t);

		/* collect the response data */
		bcopy((void *)tmp, (void *)rsp, rsp_len);

		tmp += rsp_len;
		dhval_len = LE_SWAP32(*(uint32_t *)tmp);

		tmp += sizeof (uint32_t);



		if (dhval_len != 0) {
			/* collect the DH value */
			bcopy((void *)tmp, (void *)dhval, dhval_len);
			tmp += dhval_len;
		}
		/*
		 * Check to see if there is any challenge for bi-dir auth in
		 * the reply msg
		 */
		cval_len = LE_SWAP32(*(uint32_t *)tmp);
		if (cval_len != 0) {
			/* collect challenge value */
			tmp += sizeof (uint32_t);
			bcopy((void *)tmp, (void *)cval, cval_len);

			if (ndlp->nlp_DID == FABRIC_DID) {
				node_dhc->nlp_auth_bidir = 1;
			} else {
				node_dhc->nlp_auth_bidir = 1;
			}
		} else {
			node_dhc->nlp_auth_bidir = 0;
		}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_a_m_dhchap_challenge_cmpl_wait4next:Reply:%x %lx %x %x %x\n",
	    ndlp->nlp_DID, *(uint32_t *)rsp, rsp_len, dhval_len, cval_len);

		/* Verify the response based on the hash func, dhgp_id etc. */
		/*
		 * all the information needed are stored in
		 * node_dhc->hrsp_xxx or ndlp->nlp_auth_misc.
		 */
		/*
		 * Basically compare the rsp value with the computed hash
		 * value
		 */

		/* allocate hash_val first as rsp_len bytes */
		/*
		 * we set bi-cval pointer as NULL because we are using
		 * node_dhc->hrsp_cval[]
		 */
		hash_val = emlxs_hash_verification(port, port_dhc, ndlp,
		    (tran_id), dhval, (dhval_len), 1, 0);

		if (hash_val == NULL) {
			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
			goto Reject;
		}
		if (bcmp((void *) rsp, (void *)hash_val, rsp_len)) {
			/* not identical */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "rcv_auth_msg_dhchap_challenge_cmpl_wait4next: Not authted(1).");

			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
			goto Reject;
		}
		kmem_free(hash_val, rsp_len);
		hash_val = NULL;

		/* generate the reply based on the challenge received if any */
		if ((cval_len) != 0) {
			/*
			 * Cal R2 = H (Ti || Km || Ca2) Ca2 = H (C2 || ((g^y
			 * mod p)^x mod p) ) = H (C2 || (g^(x*y) mod p)) = H
			 * (C2 || seskey) Km is the password associated with
			 * responder. Here cval: C2 dhval: (g^y mod p)
			 */
			hash_val = emlxs_hash_get_R2(port, port_dhc,
			    ndlp, (tran_id), dhval,
			    (dhval_len), 1, cval);

			if (hash_val == NULL) {
				ReasonCode = AUTHRJT_FAILURE;
				ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
				goto Reject;
			}
		}
		emlxs_dhc_state(port, ndlp,
		    NODE_STATE_DHCHAP_SUCCESS_ISSUE, 0, 0);

		if (emlxs_issue_dhchap_success(port, ndlp, 0,
		    (uint8_t *)hash_val)) {
			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
			goto Reject;
		}
	}
	return (node_dhc->state);

Reject:

	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_FAILED,
	    ReasonCode, ReasonCodeExplanation);
	(void) emlxs_issue_auth_reject(port, ndlp, 0, 0, ReasonCode,
	    ReasonCodeExplanation);
	emlxs_dhc_auth_complete(port, ndlp, 1);

out:

	return (node_dhc->state);

} /* emlxs_rcv_auth_msg_dhchap_challenge_cmpl_wait4next */



/*
 * This routine should be emlxs_disc_neverdev.
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_cmpl_auth_msg_dhchap_challenge_cmpl_wait4next(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "cmpl_a_m_dhch_chall_cmpl_wait4next.0x%x. Not implemented.",
	    ndlp->nlp_DID);

	return (0);

} /* emlxs_cmpl_auth_msg_dhchap_challenge_cmpl_wait4next */


/*
 * ! emlxs_rcv_auth_msg_dhchap_success_issue
 *
 * \pre \post \param   phba \param   ndlp \param   arg \param   evt \return
 * uint32_t \b Description:
 *
 * The host is the auth responder and the auth transaction is still in
 * progress, any unsolicited els auth msg is unexpected and
 * should not happen. If DHCHAP_Reject received, ACC back and move to next
 * state NPR_NODE. anything else, RJT and move to
 * NPR_NODE.
 */
/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_dhchap_success_issue(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "rcv_a_m_dhch_success_issue called. did=0x%x. Not implemented.",
	    ndlp->nlp_DID);

	return (0);

} /* emlxs_rcv_auth_msg_dhchap_success_issue */



/*
 * emlxs_cmpl_auth_msg_dhchap_success_issue
 *
 * This routine is invoked when
 * host as the auth responder received the solicited response (ACC or RJT)
 * from the initiator that received DHCHAP_ Success.
 *
 * For uni-dirctional authentication, we are done so the next state =
 * REG_LOGIN for bi-directional authentication, we will expect
 * DHCHAP_Success msg. so the next state = DHCHAP_SUCCESS_CMPL_WAIT4NEXT
 * and start the emlxs_dhc_authrsp_timeout timer
 */
/* ARGSUSED */
static uint32_t
emlxs_cmpl_auth_msg_dhchap_success_issue(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "cmpl_a_m_dhch_success_issue: did=0x%x auth_bidir=0x%x",
	    ndlp->nlp_DID, node_dhc->nlp_auth_bidir);

	if (node_dhc->nlp_auth_bidir == 1) {
		/* we would expect the bi-dir authentication result */

		/*
		 * the next state should be
		 * emlxs_rcv_auth_msg_dhchap_success_cmpl_wait4next
		 */
		emlxs_dhc_state(port, ndlp,
		    NODE_STATE_DHCHAP_SUCCESS_CMPL_WAIT4NEXT, 0, 0);

		/* start the emlxs_dhc_authrsp_timeout timer */
		node_dhc->nlp_authrsp_tmo = DRV_TIME +
		    node_dhc->auth_cfg.authentication_timeout;
	} else {
		node_dhc->flag &= ~NLP_REMOTE_AUTH;

		emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_SUCCESS, 0, 0);
		emlxs_log_auth_event(port, ndlp,
		    "cmpl_auth_msg_dhchap_success_issue",
		    "Node-initiated-unidir-reauth-success");
		emlxs_dhc_auth_complete(port, ndlp, 0);
	}

	return (node_dhc->state);

} /* emlxs_cmpl_auth_msg_dhchap_success_issue */


/* ARGSUSED */
static uint32_t
emlxs_device_recov_unmapped_node(
	emlxs_port_t *port,
	void *arg1,
	void *arg2,
	void *arg3,
	void *arg4,
	uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "device_recov_unmapped_node called. 0x%x. Not implemented.",
	    ndlp->nlp_DID);

	return (0);

} /* emlxs_device_recov_unmapped_node */



/* ARGSUSED */
static uint32_t
emlxs_device_rm_npr_node(
	emlxs_port_t *port,
	void *arg1,
	void *arg2,
	void *arg3,
	void *arg4,
	uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "device_rm_npr_node called. 0x%x. Not implemented.",
	    ndlp->nlp_DID);

	return (0);

} /* emlxs_device_rm_npr_node */


/* ARGSUSED */
static uint32_t
emlxs_device_recov_npr_node(
	emlxs_port_t *port,
	void *arg1,
	void *arg2,
	void *arg3,
	void *arg4,
	uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "device_recov_npr_node called. 0x%x. Not implemented.",
	    ndlp->nlp_DID);

	return (0);

} /* emlxs_device_recov_npr_node */


/* ARGSUSED */
static uint32_t
emlxs_device_rem_auth(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "device_rem_auth: 0x%x.",
	    ndlp->nlp_DID);

	emlxs_dhc_state(port, ndlp, NODE_STATE_UNKNOWN, 0, 0);

	return (node_dhc->state);

} /* emlxs_device_rem_auth */


/*
 * This routine is invoked when linkdown event happens during authentication
 */
/* ARGSUSED */
static uint32_t
emlxs_device_recov_auth(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "device_recov_auth: 0x%x.",
	    ndlp->nlp_DID);

	node_dhc->nlp_authrsp_tmo = 0;

	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_FAILED, 0, 0);

	return (node_dhc->state);

} /* emlxs_device_recov_auth */



/*
 * This routine is invoked when the host as the responder sent out the
 * ELS DHCHAP_Success to the initiator, the initiator ACC
 * it. AND then the host received an unsolicited auth msg from the initiator,
 * this msg is supposed to be the ELS DHCHAP_Success
 * msg for the bi-directional authentication.
 *
 * next state should be REG_LOGIN
 */
/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_dhchap_success_cmpl_wait4next(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	IOCBQ *iocbq = (IOCBQ *)arg2;
	MATCHMAP *mp = (MATCHMAP *)arg3;
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint8_t *bp;
	uint32_t *lp;
	DHCHAP_SUCCESS_HDR *dh_success;
	AUTH_RJT *auth_rjt;
	uint8_t ReasonCode;
	uint8_t ReasonCodeExplanation;

	bp = mp->virt;
	lp = (uint32_t *)bp;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_dhchap_success_cmpl_wait4next: did=0x%x",
	    ndlp->nlp_DID);

	dh_success = (DHCHAP_SUCCESS_HDR *)((uint8_t *)lp);

	(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC, ELS_CMD_AUTH, 0, 0);

	if (dh_success->auth_msg_code == AUTH_REJECT) {
		/* ACC it and retry etc.  */
		auth_rjt = (AUTH_RJT *)dh_success;
		ReasonCode = auth_rjt->ReasonCode;
		ReasonCodeExplanation = auth_rjt->ReasonCodeExplanation;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_a_m_dhch_success_cmpl_wait4next:REJECT rvd. 0x%x 0x%x 0x%x",
	    ndlp->nlp_DID, ReasonCode, ReasonCodeExplanation);

		switch (ReasonCode) {
		case AUTHRJT_LOGIC_ERR:
			switch (ReasonCodeExplanation) {
			case AUTHEXP_MECH_UNUSABLE:
			case AUTHEXP_DHGROUP_UNUSABLE:
			case AUTHEXP_HASHFUNC_UNUSABLE:
				ReasonCode = AUTHRJT_LOGIC_ERR;
				ReasonCodeExplanation = AUTHEXP_RESTART_AUTH;
				break;

			case AUTHEXP_RESTART_AUTH:
				/*
				 * Cancel the rsp timer if not cancelled yet.
				 * and restart auth tran now.
				 */
				if (node_dhc->nlp_authrsp_tmo != 0) {
					node_dhc->nlp_authrsp_tmo = 0;
					node_dhc->nlp_authrsp_tmocnt = 0;
				}
				if (emlxs_dhc_auth_start(port, ndlp,
				    NULL, NULL) != 0) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_debug_msg,
				    "Reauth timeout. Auth initfailed. 0x%x %x",
				    ndlp->nlp_DID, node_dhc->state);
				}
				return (node_dhc->state);

			default:
				ReasonCode = AUTHRJT_FAILURE;
				ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
				break;

			}
			break;

		case AUTHRJT_FAILURE:
		default:
			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
			break;

		}

		goto Reject;

	} else if (dh_success->auth_msg_code == DHCHAP_SUCCESS) {
		if (LE_SWAP32(dh_success->tran_id) !=
		    node_dhc->nlp_auth_tranid_ini) {
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "rcv_a_m_dhch_success_cmpl_wait4next: 0x%x 0x%lx, 0x%lx",
	    ndlp->nlp_DID, dh_success->tran_id, node_dhc->nlp_auth_tranid_ini);

			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_BAD_PROTOCOL;
			goto Reject;
		}
		node_dhc->flag |= NLP_REMOTE_AUTH;

		emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_SUCCESS, 0, 0);
		emlxs_log_auth_event(port, ndlp,
		    "rcv_auth_msg_dhchap_success_cmpl_wait4next",
		    "Node-initiated-bidir-reauth-success");
		emlxs_dhc_auth_complete(port, ndlp, 0);
	} else {
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PROTOCOL;
		goto Reject;
	}

	return (node_dhc->state);

Reject:

	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_FAILED,
	    ReasonCode, ReasonCodeExplanation);
	(void) emlxs_issue_auth_reject(port, ndlp, 0, 0, ReasonCode,
	    ReasonCodeExplanation);
	emlxs_dhc_auth_complete(port, ndlp, 1);

out:

	return (node_dhc->state);

} /* emlxs_rcv_auth_msg_dhchap_success_cmpl_wait4next */


/* ARGSUSED */
static uint32_t
emlxs_cmpl_auth_msg_dhchap_success_cmpl_wait4next(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{

	return (0);

} /* emlxs_cmpl_auth_msg_dhchap_success_cmpl_wait4next */


/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_auth_negotiate_rcv(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
	    "rcv_a_m_auth_negotiate_rcv called. did=0x%x. Not implemented.",
	    ndlp->nlp_DID);

	return (0);

} /* emlxs_rcv_auth_msg_auth_negotiate_rcv */


/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_npr_node(
emlxs_port_t *port,
/* CHANNEL  * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
	uint32_t evt)
{
	IOCBQ *iocbq = (IOCBQ *)arg2;
	MATCHMAP *mp = (MATCHMAP *)arg3;
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint8_t *bp;

	uint32_t *lp;
	uint32_t msglen;
	uint8_t *tmp;

	AUTH_MSG_HDR *msg;

	uint8_t *temp;
	uint32_t rc, i, hs_id[2], dh_id[5];
					/* from initiator */
	uint32_t hash_id, dhgp_id;	/* to be used by responder */
	uint16_t num_hs = 0;
	uint16_t num_dh = 0;

	bp = mp->virt;
	lp = (uint32_t *)bp;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_npr_node:");

	/*
	 * 1. process the auth msg, should acc first no matter what. 2.
	 * return DHCHAP_Challenge for AUTH_Negotiate auth msg, AUTH_Reject
	 * for anything else.
	 */
	(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC, ELS_CMD_AUTH, 0, 0);

	msg = (AUTH_MSG_HDR *)((uint8_t *)lp);
	msglen = msg->msg_len;
	tmp = ((uint8_t *)lp);

	/* temp is used for error checking */
	temp = (uint8_t *)((uint8_t *)lp);
	/* Check the auth_els_code */
	if (((*(uint32_t *)temp) & 0xFFFFFFFF) != LE_SWAP32(0x90000B01)) {
		/* ReasonCode = AUTHRJT_FAILURE; */
		/* ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD; */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_npr_node: payload(1)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	temp += 3 * sizeof (uint32_t);
	/* Check name tag and name length */
	if (((*(uint32_t *)temp) & 0xFFFFFFFF) != LE_SWAP32(0x00010008)) {
		/* ReasonCode = AUTHRJT_FAILURE; */
		/* ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD; */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_npr_node: payload(2)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	temp += sizeof (uint32_t) + 8;
	/* Check proto_num */
	if (((*(uint32_t *)temp) & 0xFFFFFFFF) != LE_SWAP32(0x00000001)) {
		/* ReasonCode = AUTHRJT_FAILURE; */
		/* ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD; */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_npr_node: payload(3)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	temp += sizeof (uint32_t);
	/* Get para_len */
	/* para_len = LE_SWAP32(*(uint32_t *)temp); */

	temp += sizeof (uint32_t);
	/* Check proto_id */
	if (((*(uint32_t *)temp) & 0xFFFFFFFF) != AUTH_DHCHAP) {
		/* ReasonCode = AUTHRJT_FAILURE; */
		/* ReasonCodeExplanation = AUTHEXP_BAD_PROTOCOL; */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_npr_node: payload(4)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	temp += sizeof (uint32_t);
	/* Check hashlist tag */
	if ((LE_SWAP32(*(uint32_t *)temp) & 0xFFFF0000) >> 16 !=
	    LE_SWAP16(HASH_LIST_TAG)) {
		/* ReasonCode = AUTHRJT_FAILURE; */
		/* ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD; */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_npr_node: payload(5)=0x%x",
		    (LE_SWAP32(*(uint32_t *)temp) & 0xFFFF0000) >> 16);

		goto AUTH_Reject;
	}
	/* Get num_hs  */
	num_hs = LE_SWAP32(*(uint32_t *)temp) & 0x0000FFFF;

	temp += sizeof (uint32_t);
	/* Check HashList_value1 */
	hs_id[0] = *(uint32_t *)temp;

	if ((hs_id[0] != AUTH_MD5) && (hs_id[0] != AUTH_SHA1)) {
		/* ReasonCode = AUTHRJT_LOGIC_ERR; */
		/* ReasonCodeExplanation = AUTHEXP_HASHFUNC_UNUSABLE; */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_npr_node: payload(6)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	if (num_hs == 1) {
		hs_id[1] = 0;
	} else if (num_hs == 2) {
		temp += sizeof (uint32_t);
		hs_id[1] = *(uint32_t *)temp;

		if ((hs_id[1] != AUTH_MD5) && (hs_id[1] != AUTH_SHA1)) {
			/* ReasonCode = AUTHRJT_LOGIC_ERR; */
			/* ReasonCodeExplanation = AUTHEXP_HASHFUNC_UNUSABLE; */

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "rcv_auth_msg_npr_node: payload(7)=0x%x",
			    (*(uint32_t *)temp));

			goto AUTH_Reject;
		}
		if (hs_id[0] == hs_id[1]) {
			/* ReasonCode = AUTHRJT_FAILURE; */
			/* ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD; */

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "rcv_auth_msg_npr_node: payload(8)=0x%x",
			    (*(uint32_t *)temp));

			goto AUTH_Reject;
		}
	} else {
		/* ReasonCode = AUTHRJT_FAILURE; */
		/* ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD; */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_npr_node: payload(9)=0x%x",
		    (*(uint32_t *)(temp - sizeof (uint32_t))));

		goto AUTH_Reject;
	}

	/* Which hash_id should we use */
	if (num_hs == 1) {
		/*
		 * We always use the highest priority specified by us if we
		 * match initiator's , Otherwise, we use the next higher we
		 * both have. CR 26238
		 */
		if (node_dhc->auth_cfg.hash_priority[0] == hs_id[0]) {
			hash_id = node_dhc->auth_cfg.hash_priority[0];
		} else if (node_dhc->auth_cfg.hash_priority[1] == hs_id[0]) {
			hash_id = node_dhc->auth_cfg.hash_priority[1];
		} else {
			/* ReasonCode = AUTHRJT_LOGIC_ERR; */
			/* ReasonCodeExplanation = AUTHEXP_HASHFUNC_UNUSABLE; */

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "rcv_auth_msg_npr_node: payload(10)=0x%lx",
			    (*(uint32_t *)temp));

			goto AUTH_Reject;
		}
	} else {
		/*
		 * Since the initiator specified two hashs, we always select
		 * our first one.
		 */
		hash_id = node_dhc->auth_cfg.hash_priority[0];
	}

	temp += sizeof (uint32_t);
	/* Check DHgIDList_tag */
	if ((LE_SWAP32(*(uint32_t *)temp) & 0xFFFF0000) >> 16 !=
	    LE_SWAP16(DHGID_LIST_TAG)) {
		/* ReasonCode = AUTHRJT_FAILURE; */
		/* ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD; */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_npr_node: payload(11)=0x%lx",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	/* Get num_dh */
	num_dh = LE_SWAP32(*(uint32_t *)temp) & 0x0000FFFF;

	if (num_dh == 0) {
		/* ReasonCode = AUTHRJT_FAILURE; */
		/* ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD; */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_npr_node: payload(12)=0x%lx",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	for (i = 0; i < num_dh; i++) {
		temp += sizeof (uint32_t);
		/* Check DHgIDList_g0 */
		dh_id[i] = (*(uint32_t *)temp);
	}

	rc = emlxs_check_dhgp(port, ndlp, dh_id, num_dh, &dhgp_id);

	if (rc == 1) {
		/* ReasonCode = AUTHRJT_LOGIC_ERR; */
		/* ReasonCodeExplanation = AUTHEXP_DHGROUP_UNUSABLE; */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_npr_node: payload(13)=0x%lx",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	} else if (rc == 2) {
		/* ReasonCode = AUTHRJT_FAILURE; */
		/* ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD; */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "rcv_auth_msg_npr_node: payload(14)=0x%lx",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	/* We should update the tran_id */
	node_dhc->nlp_auth_tranid_ini = msg->tran_id;

	if (msg->auth_msg_code == AUTH_NEGOTIATE) {
		node_dhc->nlp_auth_flag = 1;	/* ndlp is the initiator */

		/* Send back the DHCHAP_Challenge with the proper paramaters */
		if (emlxs_issue_dhchap_challenge(port, ndlp, 0, tmp,
		    LE_SWAP32(msglen),
		    hash_id, dhgp_id)) {
			goto AUTH_Reject;
		}
		emlxs_dhc_state(port, ndlp,
		    NODE_STATE_DHCHAP_CHALLENGE_ISSUE, 0, 0);

	} else {
		goto AUTH_Reject;
	}

	return (node_dhc->state);

AUTH_Reject:

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_npr_node: AUTH_Reject it.");

	return (node_dhc->state);

} /* emlxs_rcv_auth_msg_npr_node */


/* ARGSUSED */
static uint32_t
emlxs_cmpl_auth_msg_npr_node(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
uint32_t evt)
{
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	/*
	 * we donot cancel the nodev timeout here because we donot know if we
	 * can get the authentication restarted from other side once we got
	 * the new auth transaction kicked off we cancel nodev tmo
	 * immediately.
	 */
	/* we goto change the hba state back to where it used to be */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "cmpl_auth_msg_npr_node: 0x%x 0x%x prev_state=0x%x\n",
	    ndlp->nlp_DID, node_dhc->state, node_dhc->prev_state);

	return (node_dhc->state);

} /* emlxs_cmpl_auth_msg_npr_node */


/*
 * ! emlxs_rcv_auth_msg_unmapped_node
 *
 * \pre \post \param   phba \param   ndlp \param   arg \param   evt \return
 * uint32_t
 *
 * \b Description: This routine is invoked when the host received an
 * unsolicited els authentication msg from the Fx_Port which is
 * wellknown port 0xFFFFFE in unmapped state, or from Nx_Port which is
 * in the unmapped state meaning that it is either a target
 * which there is no scsi id associated with it or it could be another
 * initiator. (end-to-end)
 *
 * For the Fabric F_Port (FFFFFE) we mark the port to the state in re_auth
 * state without disruppting the traffic. Then the fabric
 * will go through the authentication processes until it is done.
 *
 * most of the cases, the fabric should send us AUTH_Negotiate ELS msg. Once
 * host received this auth_negotiate els msg, host
 * should sent back ACC first and then send random challenge, plus DH value
 * (i.e., host's publick key)
 *
 * Host side needs to store the challenge value and public key for later
 * verification usage. (i.e., to verify the response from
 * initiator)
 *
 * If two FC_Ports start the reauthentication transaction at the same time,
 * one of the two authentication transactions shall be
 * aborted. In case of Host and Fabric the Nx_Port shall remain the
 * authentication initiator, while the Fx_Port shall become
 * the authentication responder.
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_rcv_auth_msg_unmapped_node(
emlxs_port_t *port,
/* CHANNEL * rp, */ void *arg1,
/* IOCBQ * iocbq, */ void *arg2,
/* MATCHMAP * mp, */ void *arg3,
/* NODELIST * ndlp */ void *arg4,
	uint32_t evt)
{
	IOCBQ *iocbq = (IOCBQ *)arg2;
	MATCHMAP *mp = (MATCHMAP *)arg3;
	NODELIST *ndlp = (NODELIST *)arg4;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint8_t *bp;
	uint32_t *lp;
	uint32_t msglen;
	uint8_t *tmp;

	uint8_t ReasonCode;
	uint8_t ReasonCodeExplanation;
	AUTH_MSG_HDR *msg;
	uint8_t *temp;
	uint32_t rc, i, hs_id[2], dh_id[5];
					/* from initiator */
	uint32_t hash_id, dhgp_id;	/* to be used by responder */
	uint16_t num_hs = 0;
	uint16_t num_dh = 0;

	/*
	 * 1. process the auth msg, should acc first no matter what. 2.
	 * return DHCHAP_Challenge for AUTH_Negotiate auth msg, AUTH_Reject
	 * for anything else.
	 */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_unmapped_node: Sending ACC: did=0x%x",
	    ndlp->nlp_DID);

	(void) emlxs_els_reply(port, iocbq, ELS_CMD_ACC, ELS_CMD_AUTH, 0, 0);

	bp = mp->virt;
	lp = (uint32_t *)bp;

	msg = (AUTH_MSG_HDR *)((uint8_t *)lp);
	msglen = msg->msg_len;

	tmp = ((uint8_t *)lp);

	/* temp is used for error checking */
	temp = (uint8_t *)((uint8_t *)lp);
	/* Check the auth_els_code */
	if (((*(uint32_t *)temp) & 0xFFFFFFFF) != LE_SWAP32(0x90000B01)) {
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: payload(1)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	temp += 3 * sizeof (uint32_t);
	/* Check name tag and name length */
	if (((*(uint32_t *)temp) & 0xFFFFFFFF) != LE_SWAP32(0x00010008)) {
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: payload(2)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	temp += sizeof (uint32_t) + 8;
	/* Check proto_num */
	if (((*(uint32_t *)temp) & 0xFFFFFFFF) != LE_SWAP32(0x00000001)) {
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: payload(3)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	temp += sizeof (uint32_t);

	/* Get para_len */
	/* para_len = *(uint32_t *)temp; */
	temp += sizeof (uint32_t);

	/* Check proto_id */
	if (((*(uint32_t *)temp) & 0xFFFFFFFF) != AUTH_DHCHAP) {
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PROTOCOL;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: payload(4)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	temp += sizeof (uint32_t);
	/* Check hashlist tag */
	if ((LE_SWAP32(*(uint32_t *)temp) & 0xFFFF0000) >> 16 !=
	    LE_SWAP16(HASH_LIST_TAG)) {
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: payload(5)=0x%x",
		    (LE_SWAP32(*(uint32_t *)temp) & 0xFFFF0000) >> 16);

		goto AUTH_Reject;
	}
	/* Get num_hs  */
	num_hs = LE_SWAP32(*(uint32_t *)temp) & 0x0000FFFF;

	temp += sizeof (uint32_t);
	/* Check HashList_value1 */
	hs_id[0] = *(uint32_t *)temp;

	if ((hs_id[0] != AUTH_MD5) && (hs_id[0] != AUTH_SHA1)) {
		ReasonCode = AUTHRJT_LOGIC_ERR;
		ReasonCodeExplanation = AUTHEXP_HASHFUNC_UNUSABLE;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: payload(6)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	if (num_hs == 1) {
		hs_id[1] = 0;
	} else if (num_hs == 2) {
		temp += sizeof (uint32_t);
		hs_id[1] = *(uint32_t *)temp;

		if ((hs_id[1] != AUTH_MD5) && (hs_id[1] != AUTH_SHA1)) {
			ReasonCode = AUTHRJT_LOGIC_ERR;
			ReasonCodeExplanation = AUTHEXP_HASHFUNC_UNUSABLE;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
			    "rcv_auth_msg_unmapped_node: payload(7)=0x%x",
			    (*(uint32_t *)temp));

			goto AUTH_Reject;
		}
		if (hs_id[0] == hs_id[1]) {
			ReasonCode = AUTHRJT_FAILURE;
			ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
			    "rcv_auth_msg_unmapped_node: payload(8)=0x%x",
			    (*(uint32_t *)temp));

			goto AUTH_Reject;
		}
	} else {
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: payload(9)=0x%x",
		    (*(uint32_t *)(temp - sizeof (uint32_t))));

		goto AUTH_Reject;
	}

	/* Which hash_id should we use */
	if (num_hs == 1) {
		/*
		 * We always use the highest priority specified by us if we
		 * match initiator's , Otherwise, we use the next higher we
		 * both have. CR 26238
		 */
		if (node_dhc->auth_cfg.hash_priority[0] == hs_id[0]) {
			hash_id = node_dhc->auth_cfg.hash_priority[0];
		} else if (node_dhc->auth_cfg.hash_priority[1] == hs_id[0]) {
			hash_id = node_dhc->auth_cfg.hash_priority[1];
		} else {
			ReasonCode = AUTHRJT_LOGIC_ERR;
			ReasonCodeExplanation = AUTHEXP_HASHFUNC_UNUSABLE;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
			    "rcv_auth_msg_unmapped_node: pload(10)=0x%x",
			    (*(uint32_t *)temp));

			goto AUTH_Reject;
		}
	} else {
		/*
		 * Since the initiator specified two hashs, we always select
		 * our first one.
		 */
		hash_id = node_dhc->auth_cfg.hash_priority[0];
	}

	temp += sizeof (uint32_t);
	/* Check DHgIDList_tag */
	if ((LE_SWAP32(*(uint32_t *)temp) & 0xFFFF0000) >> 16 !=
	    LE_SWAP16(DHGID_LIST_TAG)) {
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: payload(11)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	/* Get num_dh */
	num_dh = LE_SWAP32(*(uint32_t *)temp) & 0x0000FFFF;

	if (num_dh == 0) {
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: payload(12)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	for (i = 0; i < num_dh; i++) {
		temp += sizeof (uint32_t);
		/* Check DHgIDList_g0 */
		dh_id[i] = (*(uint32_t *)temp);
	}

	rc = emlxs_check_dhgp(port, ndlp, dh_id, num_dh, &dhgp_id);

	if (rc == 1) {
		ReasonCode = AUTHRJT_LOGIC_ERR;
		ReasonCodeExplanation = AUTHEXP_DHGROUP_UNUSABLE;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: payload(13)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	} else if (rc == 2) {
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PAYLOAD;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: payload(14)=0x%x",
		    (*(uint32_t *)temp));

		goto AUTH_Reject;
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "rcv_auth_msg_unmapped_node: 0x%x 0x%x 0x%x 0x%x 0x%x",
	    hash_id, dhgp_id, msg->auth_msg_code, msglen, msg->tran_id);

	/*
	 * since ndlp is the initiator, tran_id is store in
	 * nlp_auth_tranid_ini
	 */
	node_dhc->nlp_auth_tranid_ini = LE_SWAP32(msg->tran_id);

	if (msg->auth_msg_code == AUTH_NEGOTIATE) {

		/*
		 * at this point, we know for sure we received the
		 * auth-negotiate msg from another entity, so cancel the
		 * auth-rsp timeout timer if we are expecting it. should
		 * never happen?
		 */
		node_dhc->nlp_auth_flag = 1;

		if (node_dhc->nlp_authrsp_tmo) {
			node_dhc->nlp_authrsp_tmo = 0;
		}
		/*
		 * If at this point, the host is doing reauthentication
		 * (reauth heart beat) to this ndlp, then Host should remain
		 * as the auth initiator, host should reply to the received
		 * AUTH_Negotiate message with an AUTH_Reject message with
		 * Reason Code 'Logical Error' and Reason Code Explanation
		 * 'Authentication Transaction Already Started'.
		 */
		if (node_dhc->nlp_reauth_status ==
		    NLP_HOST_REAUTH_IN_PROGRESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "rcv_auth_msg_unmapped_node: Ht reauth inprgress.");

			ReasonCode = AUTHRJT_LOGIC_ERR;
			ReasonCodeExplanation = AUTHEXP_AUTHTRAN_STARTED;

			goto AUTH_Reject;
		}
		/* Send back the DHCHAP_Challenge with the proper paramaters */
		if (emlxs_issue_dhchap_challenge(port, ndlp, 0, tmp,
		    LE_SWAP32(msglen),
		    hash_id, dhgp_id)) {

			goto AUTH_Reject;
		}
		/* setup the proper state */
		emlxs_dhc_state(port, ndlp,
		    NODE_STATE_DHCHAP_CHALLENGE_ISSUE, 0, 0);

	} else {
		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_BAD_PROTOCOL;

		goto AUTH_Reject;
	}

	return (node_dhc->state);

AUTH_Reject:

	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_FAILED,
	    ReasonCode, ReasonCodeExplanation);
	(void) emlxs_issue_auth_reject(port, ndlp, 0, 0, ReasonCode,
	    ReasonCodeExplanation);
	emlxs_dhc_auth_complete(port, ndlp, 1);

	return (node_dhc->state);

} /* emlxs_rcv_auth_msg_unmapped_node */




/*
 * emlxs_hash_vrf for verification only the host is the initiator in
 * the routine.
 */
/* ARGSUSED */
static uint32_t *
emlxs_hash_vrf(
	emlxs_port_t *port,
	emlxs_port_dhc_t *port_dhc,
	NODELIST *ndlp,
	uint32_t tran_id,
	union challenge_val un_cval)
{
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint32_t dhgp_id;
	uint32_t hash_id;
	uint32_t *hash_val;
	uint32_t hash_size;
	MD5_CTX mdctx;
	SHA1_CTX sha1ctx;
	uint8_t sha1_digest[20];
	uint8_t md5_digest[16];
	uint8_t mytran_id = 0x00;

	char *remote_key;

	tran_id = (AUTH_TRAN_ID_MASK & tran_id);
	mytran_id = (uint8_t)(LE_SWAP32(tran_id));


	if (ndlp->nlp_DID == FABRIC_DID) {
		remote_key = (char *)node_dhc->auth_key.remote_password;
		hash_id = node_dhc->hash_id;
		dhgp_id = node_dhc->dhgp_id;
	} else {
		remote_key = (char *)node_dhc->auth_key.remote_password;
		hash_id = node_dhc->nlp_auth_hashid;
		dhgp_id = node_dhc->nlp_auth_dhgpid;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "hash_vrf: 0x%x 0x%x 0x%x tran_id=0x%x",
	    ndlp->nlp_DID, hash_id, dhgp_id, mytran_id);

	if (dhgp_id == 0) {
		/* NULL DHCHAP */
		if (hash_id == AUTH_MD5) {
			bzero(&mdctx, sizeof (MD5_CTX));

			hash_size = MD5_LEN;

			MD5Init(&mdctx);

			/* Transaction Identifier T */
			MD5Update(&mdctx, (unsigned char *) &mytran_id, 1);

			MD5Update(&mdctx, (unsigned char *) remote_key,
			    node_dhc->auth_key.remote_password_length);

			/* Augmented challenge: NULL DHCHAP i.e., Challenge */
			MD5Update(&mdctx,
			    (unsigned char *)&(un_cval.md5.val[0]), MD5_LEN);

			MD5Final((uint8_t *)md5_digest, &mdctx);

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				return (NULL);
			} else {
				bcopy((void *)&md5_digest,
				    (void *)hash_val, MD5_LEN);
			}
			/*
			 * emlxs_md5_digest_to_hex((uint8_t *)hash_val,
			 * output);
			 */
		}
		if (hash_id == AUTH_SHA1) {
			bzero(&sha1ctx, sizeof (SHA1_CTX));
			hash_size = SHA1_LEN;
			SHA1Init(&sha1ctx);

			SHA1Update(&sha1ctx, (void *)&mytran_id, 1);

			SHA1Update(&sha1ctx, (void *)remote_key,
			    node_dhc->auth_key.remote_password_length);

			SHA1Update(&sha1ctx,
			    (void *)&(un_cval.sha1.val[0]), SHA1_LEN);

			SHA1Final((void *)sha1_digest, &sha1ctx);

			/*
			 * emlxs_sha1_digest_to_hex((uint8_t *)hash_val,
			 * output);
			 */

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				return (NULL);
			} else {
				bcopy((void *)&sha1_digest,
				    (void *)hash_val, SHA1_LEN);
			}
		}
		return ((uint32_t *)hash_val);
	} else {
		/* Verification of bi-dir auth for DH-CHAP group */
		/* original challenge is node_dhc->bi_cval[] */
		/* session key is node_dhc->ses_key[] */
		/* That's IT */
		/*
		 * H(bi_cval || ses_key) = C H(Ti || Km || C)  = hash_val
		 */
		if (hash_id == AUTH_MD5) {
			bzero(&mdctx, sizeof (MD5_CTX));
			hash_size = MD5_LEN;

			MD5Init(&mdctx);

			MD5Update(&mdctx,
			    (void *)&(un_cval.md5.val[0]), MD5_LEN);

			if (ndlp->nlp_DID == FABRIC_DID) {
				MD5Update(&mdctx,
				    (void *)&node_dhc->ses_key[0],
				    node_dhc->seskey_len);
			} else {
				/* ses_key is obtained in emlxs_hash_rsp */
				MD5Update(&mdctx,
				    (void *)&node_dhc->nlp_auth_misc.ses_key[0],
				    node_dhc->nlp_auth_misc.seskey_len);
			}

			MD5Final((void *)md5_digest, &mdctx);

			MD5Init(&mdctx);

			MD5Update(&mdctx, (void *)&mytran_id, 1);

			MD5Update(&mdctx, (void *)remote_key,
			    node_dhc->auth_key.remote_password_length);

			MD5Update(&mdctx, (void *)md5_digest, MD5_LEN);

			MD5Final((void *)md5_digest, &mdctx);

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				return (NULL);
			} else {
				bcopy((void *)&md5_digest,
				    (void *)hash_val, MD5_LEN);
			}
		}
		if (hash_id == AUTH_SHA1) {
			bzero(&sha1ctx, sizeof (SHA1_CTX));
			hash_size = SHA1_LEN;

			SHA1Init(&sha1ctx);

			SHA1Update(&sha1ctx,
			    (void *)&(un_cval.sha1.val[0]), SHA1_LEN);

			if (ndlp->nlp_DID == FABRIC_DID) {
				SHA1Update(&sha1ctx,
				    (void *)&node_dhc->ses_key[0],
				    node_dhc->seskey_len);
			} else {
				/* ses_key was obtained in emlxs_hash_rsp */
				SHA1Update(&sha1ctx,
				    (void *)&node_dhc->nlp_auth_misc.ses_key[0],
				    node_dhc->nlp_auth_misc.seskey_len);
			}

			SHA1Final((void *)sha1_digest, &sha1ctx);

			SHA1Init(&sha1ctx);

			SHA1Update(&sha1ctx, (void *)&mytran_id, 1);

			SHA1Update(&sha1ctx, (void *)remote_key,
			    node_dhc->auth_key.remote_password_length);

			SHA1Update(&sha1ctx, (void *)sha1_digest, SHA1_LEN);

			SHA1Final((void *)sha1_digest, &sha1ctx);

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				return (NULL);
			} else {
				bcopy((void *)&sha1_digest,
				    (void *)hash_val, SHA1_LEN);
			}
		}
		return ((uint32_t *)hash_val);
	}

} /* emlxs_hash_vrf */


/*
 * If dhval == NULL, NULL DHCHAP else, DHCHAP group.
 *
 * This routine is used by the auth transaction initiator (Who does the
 * auth-negotiate) to calculate the R1 (response) based on
 * the dh value it received, its own random private key, the challenge it
 * received, and Transaction id, as well as the password
 * associated with this very initiator in the auth pair.
 */
uint32_t *
emlxs_hash_rsp(
emlxs_port_t *port,
emlxs_port_dhc_t *port_dhc,
NODELIST *ndlp,
uint32_t tran_id,
union challenge_val un_cval,
uint8_t *dhval,
uint32_t dhvallen)
{
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint32_t dhgp_id;
	uint32_t hash_id;
	uint32_t *hash_val;
	uint32_t hash_size;
	MD5_CTX mdctx;
	SHA1_CTX sha1ctx;
	uint8_t sha1_digest[20];
	uint8_t md5_digest[16];
	uint8_t Cai[20];
	uint8_t mytran_id = 0x00;
	char *mykey;
	BIG_ERR_CODE err = BIG_OK;

	if (ndlp->nlp_DID == FABRIC_DID) {
		hash_id = node_dhc->hash_id;
		dhgp_id = node_dhc->dhgp_id;
	} else {
		hash_id = node_dhc->nlp_auth_hashid;
		dhgp_id = node_dhc->nlp_auth_dhgpid;
	}

	tran_id = (AUTH_TRAN_ID_MASK & tran_id);
	mytran_id = (uint8_t)(LE_SWAP32(tran_id));

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "hash_rsp: 0x%x 0x%x 0x%x 0x%x dhvallen=0x%x",
	    ndlp->nlp_DID, hash_id, dhgp_id, mytran_id, dhvallen);

	if (ndlp->nlp_DID == FABRIC_DID) {
		mykey = (char *)node_dhc->auth_key.local_password;

	} else {
		mykey = (char *)node_dhc->auth_key.local_password;
	}

	if (dhval == NULL) {
		/* NULL DHCHAP */
		if (hash_id == AUTH_MD5) {
			bzero(&mdctx, sizeof (MD5_CTX));
			hash_size = MD5_LEN;

			MD5Init(&mdctx);

			MD5Update(&mdctx, (unsigned char *)&mytran_id, 1);

			MD5Update(&mdctx, (unsigned char *)mykey,
			    node_dhc->auth_key.local_password_length);

			MD5Update(&mdctx,
			    (unsigned char *)&(un_cval.md5.val[0]),
			    MD5_LEN);

			MD5Final((uint8_t *)md5_digest, &mdctx);

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				return (NULL);
			} else {
				bcopy((void *)&md5_digest,
				    (void *)hash_val, MD5_LEN);
			}

			/*
			 * emlxs_md5_digest_to_hex((uint8_t *)hash_val,
			 * output);
			 */

		}
		if (hash_id == AUTH_SHA1) {
			bzero(&sha1ctx, sizeof (SHA1_CTX));
			hash_size = SHA1_LEN;
			SHA1Init(&sha1ctx);

			SHA1Update(&sha1ctx, (void *)&mytran_id, 1);

			SHA1Update(&sha1ctx, (void *)mykey,
			    node_dhc->auth_key.local_password_length);

			SHA1Update(&sha1ctx,
			    (void *)&(un_cval.sha1.val[0]), SHA1_LEN);

			SHA1Final((void *)sha1_digest, &sha1ctx);

			/*
			 * emlxs_sha1_digest_to_hex((uint8_t *)hash_val,
			 * output);
			 */

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				return (NULL);
			} else {
				bcopy((void *)&sha1_digest,
				    (void *)hash_val, SHA1_LEN);
			}
		}
		return ((uint32_t *)hash_val);
	} else {

		/* process DH grops */
		/*
		 * calculate interm hash value Ca1 Ca1 = H(C1 || (g^x mod
		 * p)^y mod p) in which C1 is the challenge received. g^x mod
		 * p is the dhval received y is the random number in 16 bytes
		 * for MD5, 20 bytes for SHA1 p is hardcoded value based on
		 * different DH groups.
		 *
		 * To calculate hash value R1 R1 = H (Ti || Kn || Cai) in which
		 * Ti is the transaction identifier Kn is the shared secret.
		 * Cai is the result from interm hash.
		 *
		 * g^y mod p is reserved in port_dhc as pubkey (public key).for
		 * bi-dir challenge is another random number. y is prikey
		 * (private key). ((g^x mod p)^y mod p) is sekey (session
		 * key)
		 */
		err = emlxs_interm_hash(port, port_dhc, ndlp,
		    (void *)&Cai, tran_id,
		    un_cval, dhval, &dhvallen);

		if (err != BIG_OK) {
			return (NULL);
		}
		if (hash_id == AUTH_MD5) {
			bzero(&mdctx, sizeof (MD5_CTX));
			hash_size = MD5_LEN;

			MD5Init(&mdctx);

			MD5Update(&mdctx, (unsigned char *)&mytran_id, 1);

			MD5Update(&mdctx, (unsigned char *)mykey,
			    node_dhc->auth_key.local_password_length);

			MD5Update(&mdctx, (unsigned char *)Cai, MD5_LEN);

			MD5Final((uint8_t *)md5_digest, &mdctx);

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				return (NULL);
			} else {
				bcopy((void *)&md5_digest,
				    (void *)hash_val, MD5_LEN);
			}
		}
		if (hash_id == AUTH_SHA1) {
			bzero(&sha1ctx, sizeof (SHA1_CTX));
			hash_size = SHA1_LEN;

			SHA1Init(&sha1ctx);

			SHA1Update(&sha1ctx, (void *)&mytran_id, 1);

			SHA1Update(&sha1ctx, (void *)mykey,
			    node_dhc->auth_key.local_password_length);

			SHA1Update(&sha1ctx, (void *)&Cai[0], SHA1_LEN);

			SHA1Final((void *)sha1_digest, &sha1ctx);

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				return (NULL);
			} else {
				bcopy((void *)&sha1_digest,
				    (void *)hash_val, SHA1_LEN);
			}
		}
		return ((uint32_t *)hash_val);
	}

} /* emlxs_hash_rsp */


/*
 * To get the augmented challenge Cai Stored in hash_val
 *
 * Cai = Hash (C1 || ((g^x mod p)^y mod p)) = Hash (C1 || (g^(x*y) mod p)
 *
 * C1:challenge received from the remote entity (g^x mod p): dh val
 * received from the remote entity (remote entity's pubkey) y:
 * random private key from the local entity Hash: hash function used in
 * agreement. (g^(x*y) mod p): shared session key (aka
 * shared secret) (g^y mod p): local entity's pubkey
 */
/* ARGSUSED */
BIG_ERR_CODE
emlxs_interm_hash(
emlxs_port_t *port,
emlxs_port_dhc_t *port_dhc,
NODELIST *ndlp,
void *hash_val,
uint32_t tran_id,
union challenge_val un_cval,
uint8_t *dhval,
uint32_t *dhvallen)
{
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint32_t dhgp_id;
	uint32_t hash_id;
	MD5_CTX mdctx;
	SHA1_CTX sha1ctx;
	uint8_t sha1_digest[20];
	uint8_t md5_digest[16];
	uint32_t hash_size;
	BIG_ERR_CODE err = BIG_OK;

	if (ndlp->nlp_DID == FABRIC_DID) {
		hash_id = node_dhc->hash_id;
		dhgp_id = node_dhc->dhgp_id;
	} else {
		hash_id = node_dhc->nlp_auth_hashid;
		dhgp_id = node_dhc->nlp_auth_dhgpid;
	}

	if (hash_id == AUTH_MD5) {
		bzero(&mdctx, sizeof (MD5_CTX));
		hash_size = MD5_LEN;
		MD5Init(&mdctx);
		MD5Update(&mdctx,
		    (unsigned char *)&(un_cval.md5.val[0]), MD5_LEN);

		/*
		 * get the pub key (g^y mod p) and session key (g^(x*y) mod
		 * p) and stored them in the partner's ndlp structure
		 */
		err = emlxs_BIGNUM_get_pubkey(port, port_dhc, ndlp,
		    dhval, dhvallen, hash_size, dhgp_id);

		if (err != BIG_OK) {
			return (err);
		}
		if (ndlp->nlp_DID == FABRIC_DID) {
			MD5Update(&mdctx,
			    (unsigned char *)&node_dhc->ses_key[0],
			    node_dhc->seskey_len);
		} else {
		MD5Update(&mdctx,
		    (unsigned char *)&node_dhc->nlp_auth_misc.ses_key[0],
		    node_dhc->nlp_auth_misc.seskey_len);
		}

		MD5Final((uint8_t *)md5_digest, &mdctx);

		bcopy((void *)&md5_digest, (void *)hash_val, MD5_LEN);
	}
	if (hash_id == AUTH_SHA1) {
		bzero(&sha1ctx, sizeof (SHA1_CTX));

		hash_size = SHA1_LEN;

		SHA1Init(&sha1ctx);

		SHA1Update(&sha1ctx, (void *)&(un_cval.sha1.val[0]), SHA1_LEN);

		/* get the pub key and session key */
		err = emlxs_BIGNUM_get_pubkey(port, port_dhc, ndlp,
		    dhval, dhvallen, hash_size, dhgp_id);

		if (err != BIG_OK) {
			return (err);
		}
		if (ndlp->nlp_DID == FABRIC_DID) {
			SHA1Update(&sha1ctx, (void *)&node_dhc->ses_key[0],
			    node_dhc->seskey_len);
		} else {
			SHA1Update(&sha1ctx,
			    (void *)&node_dhc->nlp_auth_misc.ses_key[0],
			    node_dhc->nlp_auth_misc.seskey_len);
		}

		SHA1Final((void *)sha1_digest, &sha1ctx);

		bcopy((void *)&sha1_digest, (void *)hash_val, SHA1_LEN);
	}
	return (err);

} /* emlxs_interm_hash */

/*
 * This routine get the pubkey and session key. these pubkey and session
 * key are stored in the partner's ndlp structure.
 */
/* ARGSUSED */
BIG_ERR_CODE
emlxs_BIGNUM_get_pubkey(
			emlxs_port_t *port,
			emlxs_port_dhc_t *port_dhc,
			NODELIST *ndlp,
			uint8_t *dhval,
			uint32_t *dhvallen,
			uint32_t hash_size,
			uint32_t dhgp_id)
{
	emlxs_hba_t *hba = HBA;

	BIGNUM a, e, n, result;
	uint32_t plen;
	uint8_t random_number[20];
	unsigned char *tmp = NULL;
	BIGNUM g, result1;

#ifdef BIGNUM_CHUNK_32
	uint8_t gen[] = {0x00, 0x00, 0x00, 0x02};
#else
	uint8_t gen[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
#endif /* BIGNUM_CHUNK_32 */

	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	BIG_ERR_CODE err = BIG_OK;

	/*
	 * compute a^e mod n assume a < n, n odd, result->value at least as
	 * long as n->value.
	 *
	 * a is the public key received from responder. e is the private key
	 * generated by me. n is the wellknown modulus.
	 */

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "BIGNUM_get_pubkey: 0x%x 0x%x 0x%x 0x%x",
	    ndlp->nlp_DID, *dhvallen, hash_size, dhgp_id);

	/* size should be in the unit of (BIG_CHUNK_TYPE) words */
	if (big_init(&a, CHARLEN2BIGNUMLEN(*dhvallen))  != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_pubkey: big_init failed. a size=%d",
		    CHARLEN2BIGNUMLEN(*dhvallen));

		err = BIG_NO_MEM;
		return (err);
	}
	/* a: (g^x mod p) */
	/*
	 * dhval is in big-endian format. This call converts from
	 * byte-big-endian format to big number format (words in little
	 * endian order, but bytes within the words big endian)
	 */
	bytestring2bignum(&a, (unsigned char *)dhval, *dhvallen);

	if (big_init(&e, CHARLEN2BIGNUMLEN(hash_size)) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_pubkey: big_init failed. e size=%d",
		    CHARLEN2BIGNUMLEN(hash_size));

		err = BIG_NO_MEM;
		goto ret1;
	}
#ifdef RAND

	bzero(&random_number, hash_size);

	/* to get random private key: y */
	/* remember y is short lived private key */
	if (hba->rdn_flag == 1) {
		emlxs_get_random_bytes(ndlp, random_number, 20);
	} else {
		(void) random_get_pseudo_bytes(random_number, hash_size);
	}

	/* e: y */
	bytestring2bignum(&e, (unsigned char *)random_number, hash_size);

#endif	/* RAND */

#ifdef MYRAND
	bytestring2bignum(&e, (unsigned char *)myrand, hash_size);

	printf("myrand random_number as Y ================\n");
	for (i = 0; i < 5; i++) {
		for (j = 0; j < 4; j++) {
			printf("%x", myrand[(i * 4) + j]);
		}
		printf("\n");
	}
#endif	/* MYRAND */

	switch (dhgp_id) {
	case GROUP_1024:
		plen = 128;
		tmp = dhgp1_pVal;
		break;

	case GROUP_1280:
		plen = 160;
		tmp = dhgp2_pVal;
		break;

	case GROUP_1536:
		plen = 192;
		tmp = dhgp3_pVal;
		break;

	case GROUP_2048:
		plen = 256;
		tmp = dhgp4_pVal;
		break;
	}

	if (big_init(&n, CHARLEN2BIGNUMLEN(plen)) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_pubkey: big_init failed. n size=%d",
		    CHARLEN2BIGNUMLEN(plen));
		err = BIG_NO_MEM;
		goto ret2;
	}
	bytestring2bignum(&n, (unsigned char *)tmp, plen);

	if (big_init(&result, CHARLEN2BIGNUMLEN(512)) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_pubkey: big_init failed. result size=%d",
		    CHARLEN2BIGNUMLEN(512));

		err = BIG_NO_MEM;
		goto ret3;
	}
	if (big_cmp_abs(&a, &n) > 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_pubkey: big_cmp_abs error.");
		err = BIG_GENERAL_ERR;
		goto ret4;
	}
	/* perform computation on big numbers to get seskey  */
	/* a^e mod n */
	/* i.e., (g^x mod p)^y mod p  */

	if (big_modexp(&result, &a, &e, &n, NULL) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_pubkey: big_modexp result error");
		err = BIG_NO_MEM;
		goto ret4;
	}
	/* convert big number ses_key to bytestring */
	if (ndlp->nlp_DID == FABRIC_DID) {
		/*
		 * This call converts from big number format to
		 * byte-big-endian format. big number format is words in
		 * little endian order, but bytes within words in native byte
		 * order
		 */
		bignum2bytestring(node_dhc->ses_key, &result,
		    sizeof (BIG_CHUNK_TYPE) * (result.len));
		node_dhc->seskey_len = sizeof (BIG_CHUNK_TYPE) * (result.len);

		/* we can store another copy in ndlp */
		bignum2bytestring(node_dhc->nlp_auth_misc.ses_key, &result,
		    sizeof (BIG_CHUNK_TYPE) * (result.len));
		node_dhc->nlp_auth_misc.seskey_len =
		    sizeof (BIG_CHUNK_TYPE) * (result.len);
	} else {
		/* for end-to-end auth */
		bignum2bytestring(node_dhc->nlp_auth_misc.ses_key, &result,
		    sizeof (BIG_CHUNK_TYPE) * (result.len));
		node_dhc->nlp_auth_misc.seskey_len =
		    sizeof (BIG_CHUNK_TYPE) * (result.len);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "BIGNUM_get_pubkey: after seskey cal: 0x%x 0x%x 0x%x",
	    node_dhc->nlp_auth_misc.seskey_len, result.size, result.len);


	/* to get pub_key: g^y mod p, g is 2 */

	if (big_init(&g, 1) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_pubkey: big_init failed. g size=1");

		err = BIG_NO_MEM;
		goto ret4;
	}
	if (big_init(&result1, CHARLEN2BIGNUMLEN(512)) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_pubkey: big_init failed. result1 size=%d",
		    CHARLEN2BIGNUMLEN(512));
		err = BIG_NO_MEM;
		goto ret5;
	}

	bytestring2bignum(&g,
	    (unsigned char *)&gen, sizeof (BIG_CHUNK_TYPE));

	if (big_modexp(&result1, &g, &e, &n, NULL) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_pubkey: big_modexp result1 error");
		err = BIG_NO_MEM;
		goto ret6;
	}
	/* convert big number pub_key to bytestring */
	if (ndlp->nlp_DID == FABRIC_DID) {

		bignum2bytestring(node_dhc->pub_key, &result1,
		    sizeof (BIG_CHUNK_TYPE) * (result1.len));
		node_dhc->pubkey_len = (result1.len) * sizeof (BIG_CHUNK_TYPE);

		/* save another copy in ndlp */
		bignum2bytestring(node_dhc->nlp_auth_misc.pub_key, &result1,
		    sizeof (BIG_CHUNK_TYPE) * (result1.len));
		node_dhc->nlp_auth_misc.pubkey_len =
		    (result1.len) * sizeof (BIG_CHUNK_TYPE);

	} else {
		/* for end-to-end auth */
		bignum2bytestring(node_dhc->nlp_auth_misc.pub_key, &result1,
		    sizeof (BIG_CHUNK_TYPE) * (result1.len));
		node_dhc->nlp_auth_misc.pubkey_len =
		    (result1.len) * sizeof (BIG_CHUNK_TYPE);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "BIGNUM_get_pubkey: after pubkey cal: 0x%x 0x%x 0x%x",
	    node_dhc->nlp_auth_misc.pubkey_len, result1.size, result1.len);


ret6:
	big_finish(&result1);
ret5:
	big_finish(&g);
ret4:
	big_finish(&result);
ret3:
	big_finish(&n);
ret2:
	big_finish(&e);
ret1:
	big_finish(&a);

	return (err);

} /* emlxs_BIGNUM_get_pubkey */


/*
 * g^x mod p x is the priv_key g and p are wellknow based on dhgp_id
 */
/* ARGSUSED */
static BIG_ERR_CODE
emlxs_BIGNUM_get_dhval(
emlxs_port_t *port,
emlxs_port_dhc_t *port_dhc,
NODELIST *ndlp,
uint8_t *dhval,
uint32_t *dhval_len,
uint32_t dhgp_id,
uint8_t *priv_key,
uint32_t privkey_len)
{
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	BIGNUM g, e, n, result1;
	uint32_t plen;
	unsigned char *tmp = NULL;

#ifdef BIGNUM_CHUNK_32
	uint8_t gen[] = {0x00, 0x00, 0x00, 0x02};
#else
	uint8_t gen[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
#endif /* BIGNUM_CHUNK_32 */

	BIG_ERR_CODE err = BIG_OK;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "BIGNUM_get_dhval: did=0x%x privkey_len=0x%x dhgp_id=0x%x",
	    ndlp->nlp_DID, privkey_len, dhgp_id);

	if (big_init(&result1, CHARLEN2BIGNUMLEN(512)) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_dhval: big_init failed. result1 size=%d",
		    CHARLEN2BIGNUMLEN(512));

		err = BIG_NO_MEM;
		return (err);
	}
	if (big_init(&g, 1) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_dhval: big_init failed. g size=1");

		err = BIG_NO_MEM;
		goto ret1;
	}
	/* get g */
	bytestring2bignum(&g, (unsigned char *)gen, sizeof (BIG_CHUNK_TYPE));

	if (big_init(&e, CHARLEN2BIGNUMLEN(privkey_len)) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_dhval: big_init failed. e size=%d",
		    CHARLEN2BIGNUMLEN(privkey_len));

		err = BIG_NO_MEM;
		goto ret2;
	}
	/* get x */
	bytestring2bignum(&e, (unsigned char *)priv_key, privkey_len);

	switch (dhgp_id) {
	case GROUP_1024:
		plen = 128;
		tmp = dhgp1_pVal;
		break;

	case GROUP_1280:
		plen = 160;
		tmp = dhgp2_pVal;
		break;

	case GROUP_1536:
		plen = 192;
		tmp = dhgp3_pVal;
		break;

	case GROUP_2048:
		plen = 256;
		tmp = dhgp4_pVal;
		break;
	}

	if (big_init(&n, CHARLEN2BIGNUMLEN(plen)) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_dhval: big_init failed. n size=%d",
		    CHARLEN2BIGNUMLEN(plen));

		err = BIG_NO_MEM;
		goto ret3;
	}
	/* get p */
	bytestring2bignum(&n, (unsigned char *)tmp, plen);

	/* to cal: (g^x mod p) */
	if (big_modexp(&result1, &g, &e, &n, NULL) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_get_dhval: big_modexp result1 error");

		err = BIG_GENERAL_ERR;
		goto ret4;
	}
	/* convert big number pub_key to bytestring */
	if (ndlp->nlp_DID == FABRIC_DID) {
		bignum2bytestring(node_dhc->hrsp_pub_key, &result1,
		    sizeof (BIG_CHUNK_TYPE) * (result1.len));
		node_dhc->hrsp_pubkey_len =
		    (result1.len) * sizeof (BIG_CHUNK_TYPE);

		/* save another copy in partner's ndlp */
		bignum2bytestring(node_dhc->nlp_auth_misc.hrsp_pub_key,
		    &result1,
		    sizeof (BIG_CHUNK_TYPE) * (result1.len));

		node_dhc->nlp_auth_misc.hrsp_pubkey_len =
		    (result1.len) * sizeof (BIG_CHUNK_TYPE);
	} else {
		bignum2bytestring(node_dhc->nlp_auth_misc.hrsp_pub_key,
		    &result1,
		    sizeof (BIG_CHUNK_TYPE) * (result1.len));
		node_dhc->nlp_auth_misc.hrsp_pubkey_len =
		    (result1.len) * sizeof (BIG_CHUNK_TYPE);
	}


	if (ndlp->nlp_DID == FABRIC_DID) {
		bcopy((void *)node_dhc->hrsp_pub_key, (void *)dhval,
		    node_dhc->hrsp_pubkey_len);
	} else {
		bcopy((void *)node_dhc->nlp_auth_misc.hrsp_pub_key,
		    (void *)dhval,
		    node_dhc->nlp_auth_misc.hrsp_pubkey_len);
	}

	*(uint32_t *)dhval_len = (result1.len) * sizeof (BIG_CHUNK_TYPE);


ret4:
	big_finish(&result1);
ret3:
	big_finish(&e);
ret2:
	big_finish(&n);
ret1:
	big_finish(&g);

	return (err);

} /* emlxs_BIGNUM_get_dhval */


/*
 * to get ((g^y mod p)^x mod p) a^e mod n
 */
BIG_ERR_CODE
emlxs_BIGNUM_pubkey(
		    emlxs_port_t *port,
		    void *pubkey,
		    uint8_t *dhval,	/* g^y mod p */
		    uint32_t dhvallen,
		    uint8_t *key,	/* x */
		    uint32_t key_size,
		    uint32_t dhgp_id,
		    uint32_t *pubkeylen)
{
	BIGNUM a, e, n, result;
	uint32_t plen;
	unsigned char *tmp = NULL;
	BIG_ERR_CODE err = BIG_OK;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "BIGNUM_pubkey: dhvallen=0x%x dhgp_id=0x%x",
	    dhvallen, dhgp_id);

	if (big_init(&a, CHARLEN2BIGNUMLEN(dhvallen)) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_pubkey: big_init failed. a size=%d",
		    CHARLEN2BIGNUMLEN(dhvallen));

		err = BIG_NO_MEM;
		return (err);
	}
	/* get g^y mod p */
	bytestring2bignum(&a, (unsigned char *)dhval, dhvallen);

	if (big_init(&e, CHARLEN2BIGNUMLEN(key_size)) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_pubkey: big_init failed. e size=%d",
		    CHARLEN2BIGNUMLEN(key_size));

		err = BIG_NO_MEM;
		goto ret1;
	}
	/* get x */
	bytestring2bignum(&e, (unsigned char *)key, key_size);

	switch (dhgp_id) {
	case GROUP_1024:
		plen = 128;
		tmp = dhgp1_pVal;
		break;

	case GROUP_1280:
		plen = 160;
		tmp = dhgp2_pVal;
		break;

	case GROUP_1536:
		plen = 192;
		tmp = dhgp3_pVal;
		break;

	case GROUP_2048:
		plen = 256;
		tmp = dhgp4_pVal;
		break;
	}

	if (big_init(&n, CHARLEN2BIGNUMLEN(plen)) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_pubkey: big_init failed. n size=%d",
		    CHARLEN2BIGNUMLEN(plen));

		err = BIG_NO_MEM;
		goto ret2;
	}
	bytestring2bignum(&n, (unsigned char *)tmp, plen);

	if (big_init(&result, CHARLEN2BIGNUMLEN(512)) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_pubkey: big_init failed. result size=%d",
		    CHARLEN2BIGNUMLEN(512));

		err = BIG_NO_MEM;
		goto ret3;
	}
	if (big_cmp_abs(&a, &n) > 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_pubkey: big_cmp_abs error");

		err = BIG_GENERAL_ERR;
		goto ret4;
	}
	if (big_modexp(&result, &a, &e, &n, NULL) != BIG_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
		    "BIGNUM_pubkey: big_modexp result error");

		err = BIG_NO_MEM;
		goto ret4;
	}
	bignum2bytestring(pubkey, &result,
	    sizeof (BIG_CHUNK_TYPE) * (result.len));
	*pubkeylen = sizeof (BIG_CHUNK_TYPE) * (result.len);

	/* This pubkey is actually session key */

ret4:
	big_finish(&result);
ret3:
	big_finish(&n);
ret2:
	big_finish(&e);
ret1:
	big_finish(&a);

	return (err);

} /* emlxs_BIGNUM_pubkey */


/*
 * key: x dhval: (g^y mod p) tran_id: Ti bi_cval: C2 hash_id: H dhgp_id: p/g
 *
 * Cai = H (C2 || ((g^y mod p)^x mod p) )
 *
 */
/* ARGSUSED */
BIG_ERR_CODE
emlxs_hash_Cai(
	emlxs_port_t *port,
	emlxs_port_dhc_t *port_dhc,
	NODELIST *ndlp,
	void *Cai,
	uint32_t hash_id,
	uint32_t dhgp_id,
	uint32_t tran_id,
	uint8_t *cval,
	uint32_t cval_len,
	uint8_t *key,
	uint8_t *dhval,
	uint32_t dhvallen)
{
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	MD5_CTX mdctx;
	SHA1_CTX sha1ctx;
	uint8_t sha1_digest[20];
	uint8_t md5_digest[16];
	uint8_t pubkey[512];
	uint32_t pubkey_len = 0;
	uint32_t key_size;
	BIG_ERR_CODE err = BIG_OK;

	key_size = cval_len;
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "hash_Cai: 0x%x 0x%x 0x%x 0x%x 0x%x",
	    ndlp->nlp_DID, hash_id, dhgp_id, tran_id, dhvallen);

	if (hash_id == AUTH_MD5) {
		bzero(&mdctx, sizeof (MD5_CTX));
		MD5Init(&mdctx);
		MD5Update(&mdctx, (unsigned char *)cval, cval_len);

		/* this pubkey obtained is actually the session key */
		/*
		 * pubkey: ((g^y mod p)^x mod p)
		 */
		err = emlxs_BIGNUM_pubkey(port, pubkey, dhval, dhvallen,
		    key, key_size, dhgp_id, &pubkey_len);

		if (err != BIG_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "hash_Cai: MD5 BIGNUM_pubkey error: 0x%x",
			    err);

			err = BIG_GENERAL_ERR;
			return (err);
		}
		if (pubkey_len == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "hash_Cai: MD5 BIGNUM_pubkey error: len=0");

			err = BIG_GENERAL_ERR;
			return (err);
		}
		if (ndlp->nlp_DID == FABRIC_DID) {
			bcopy((void *)pubkey,
			    (void *)node_dhc->hrsp_ses_key, pubkey_len);
			node_dhc->hrsp_seskey_len = pubkey_len;

			/* store extra copy */
			bcopy((void *)pubkey,
			    (void *)node_dhc->nlp_auth_misc.hrsp_ses_key,
			    pubkey_len);
			node_dhc->nlp_auth_misc.hrsp_seskey_len = pubkey_len;

		} else {
			bcopy((void *)pubkey,
			    (void *)node_dhc->nlp_auth_misc.hrsp_ses_key,
			    pubkey_len);
			node_dhc->nlp_auth_misc.hrsp_seskey_len = pubkey_len;
		}

		MD5Update(&mdctx, (unsigned char *)pubkey, pubkey_len);
		MD5Final((uint8_t *)md5_digest, &mdctx);
		bcopy((void *)&md5_digest, (void *)Cai, MD5_LEN);
	}
	if (hash_id == AUTH_SHA1) {
		bzero(&sha1ctx, sizeof (SHA1_CTX));
		SHA1Init(&sha1ctx);

		SHA1Update(&sha1ctx, (void *)cval, cval_len);

		err = emlxs_BIGNUM_pubkey(port, pubkey, dhval, dhvallen,
		    key, key_size, dhgp_id, &pubkey_len);

		if (err != BIG_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "hash_Cai: SHA1 BIGNUM_pubkey error: 0x%x",
			    err);

			err = BIG_GENERAL_ERR;
			return (err);
		}
		if (pubkey_len == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "hash_Cai: SA1 BUM_pubkey error: key_len=0");

			err = BIG_GENERAL_ERR;
			return (err);
		}
		if (ndlp->nlp_DID == FABRIC_DID) {
			bcopy((void *)pubkey,
			    (void *)node_dhc->hrsp_ses_key,
			    pubkey_len);
			node_dhc->hrsp_seskey_len = pubkey_len;

			/* store extra copy */
			bcopy((void *)pubkey,
			    (void *)node_dhc->nlp_auth_misc.hrsp_ses_key,
			    pubkey_len);
			node_dhc->nlp_auth_misc.hrsp_seskey_len = pubkey_len;

		} else {
			bcopy((void *)pubkey,
			    (void *)node_dhc->nlp_auth_misc.hrsp_ses_key,
			    pubkey_len);
			node_dhc->nlp_auth_misc.hrsp_seskey_len = pubkey_len;
		}

		SHA1Update(&sha1ctx, (void *)pubkey, pubkey_len);
		SHA1Final((void *)sha1_digest, &sha1ctx);
		bcopy((void *)&sha1_digest, (void *)Cai, SHA1_LEN);
	}
	return (err);

} /* emlxs_hash_Cai */


/*
 * This routine is to verify the DHCHAP_Reply from initiator by the host
 * as the responder.
 *
 * flag: 1: if host is the responder 0: if host is the initiator
 *
 * if bi_cval != NULL, this routine is used to calculate the response based
 * on the challenge from initiator as part of
 * DHCHAP_Reply for bi-dirctional authentication.
 *
 */
/* ARGSUSED */
static uint32_t *
emlxs_hash_verification(
	emlxs_port_t *port,
	emlxs_port_dhc_t *port_dhc,
	NODELIST *ndlp,
	uint32_t tran_id,
	uint8_t *dhval,
	uint32_t dhval_len,
	uint32_t flag,	/* always 1 for now */
	uint8_t *bi_cval)
{			/* always 0 for now */
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint32_t dhgp_id;
	uint32_t hash_id;
	uint32_t *hash_val = NULL;
	uint32_t hash_size;
	MD5_CTX mdctx;
	SHA1_CTX sha1ctx;
	uint8_t sha1_digest[20];
	uint8_t md5_digest[16];
	uint8_t Cai[20];
	/* union challenge_val un_cval; */
	uint8_t key[20];
	uint8_t cval[20];
	uint32_t cval_len;
	uint8_t mytran_id = 0x00;
	char *remote_key;
	BIG_ERR_CODE err = BIG_OK;

	tran_id = (AUTH_TRAN_ID_MASK & tran_id);
	mytran_id = (uint8_t)(LE_SWAP32(tran_id));

	if (ndlp->nlp_DID == FABRIC_DID) {
		remote_key = (char *)node_dhc->auth_key.remote_password;
	} else {
		/*
		 * in case of end-to-end auth, this remote password should be
		 * the password associated with the remote entity. (i.e.,)
		 * for now it is actually local_password.
		 */
		remote_key = (char *)node_dhc->auth_key.remote_password;
	}

	if (flag == 0) {
		dhgp_id = node_dhc->dhgp_id;
		hash_id = node_dhc->hash_id;
	} else {
		dhgp_id = node_dhc->nlp_auth_dhgpid;
		hash_id = node_dhc->nlp_auth_hashid;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "hash_verification: 0x%x 0x%x hash_id=0x%x dhgp_id=0x%x",
	    ndlp->nlp_DID, mytran_id, hash_id, dhgp_id);

	if (dhval_len == 0) {
		/* NULL DHCHAP group */
		if (hash_id == AUTH_MD5) {
			bzero(&mdctx, sizeof (MD5_CTX));
			hash_size = MD5_LEN;
			MD5Init(&mdctx);

			MD5Update(&mdctx, (unsigned char *)&mytran_id, 1);

			if (ndlp->nlp_DID == FABRIC_DID) {
				MD5Update(&mdctx,
				    (unsigned char *)remote_key,
				    node_dhc->auth_key.remote_password_length);
			} else {
				MD5Update(&mdctx,
				    (unsigned char *)remote_key,
				    node_dhc->auth_key.remote_password_length);
			}

			if (ndlp->nlp_DID == FABRIC_DID) {
				MD5Update(&mdctx,
				    (unsigned char *)&node_dhc->hrsp_cval[0],
				    MD5_LEN);
			} else {
		MD5Update(&mdctx,
		    (unsigned char *)&node_dhc->nlp_auth_misc.hrsp_cval[0],
		    MD5_LEN);
			}

			MD5Final((uint8_t *)md5_digest, &mdctx);

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
				    "hash_verification: alloc failed");

				return (NULL);
			} else {
				bcopy((void *)md5_digest,
				    (void *)hash_val, MD5_LEN);
			}
		}
		if (hash_id == AUTH_SHA1) {
			bzero(&sha1ctx, sizeof (SHA1_CTX));
			hash_size = SHA1_LEN;
			SHA1Init(&sha1ctx);
			SHA1Update(&sha1ctx, (void *)&mytran_id, 1);

			if (ndlp->nlp_DID == FABRIC_DID) {
				SHA1Update(&sha1ctx, (void *)remote_key,
				    node_dhc->auth_key.remote_password_length);
			} else {
				SHA1Update(&sha1ctx, (void *)remote_key,
				    node_dhc->auth_key.remote_password_length);
			}

			if (ndlp->nlp_DID == FABRIC_DID) {
				SHA1Update(&sha1ctx,
				    (void *)&node_dhc->hrsp_cval[0],
				    SHA1_LEN);
			} else {
			SHA1Update(&sha1ctx,
			    (void *)&node_dhc->nlp_auth_misc.hrsp_cval[0],
			    SHA1_LEN);
			}

			SHA1Final((void *)sha1_digest, &sha1ctx);
			hash_val = (uint32_t *)kmem_zalloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
				    "hash_verification: alloc failed");

				return (NULL);
			} else {
				bcopy((void *)sha1_digest,
				    (void *)hash_val, SHA1_LEN);
			}
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "hash_verification: hash_val=0x%x",
		    *(uint32_t *)hash_val);

		return ((uint32_t *)hash_val);
	} else {

		/* DHCHAP group 1,2,3,4 */
		/*
		 * host received (g^x mod p) as dhval host has its own
		 * private key y as node_dhc->hrsp_priv_key[] host has its
		 * original challenge c as node_dhc->hrsp_cval[]
		 *
		 * H(c || (g^x mod p)^y mod p) = Cai H(Ti || Km || Cai) =
		 * hash_val returned. Ti : tran_id, Km : shared secret, Cai:
		 * obtained above.
		 */
		if (hash_id == AUTH_MD5) {
			if (ndlp->nlp_DID == FABRIC_DID) {
				bcopy((void *)node_dhc->hrsp_priv_key,
				    (void *)key, MD5_LEN);
			} else {
			bcopy(
			    (void *)node_dhc->nlp_auth_misc.hrsp_priv_key,
			    (void *)key, MD5_LEN);
			}
		}
		if (hash_id == AUTH_SHA1) {
			if (ndlp->nlp_DID == FABRIC_DID) {
				bcopy((void *)node_dhc->hrsp_priv_key,
				    (void *)key, SHA1_LEN);
			} else {
			bcopy(
			    (void *)node_dhc->nlp_auth_misc.hrsp_priv_key,
			    (void *)key, SHA1_LEN);
			}
		}
		if (ndlp->nlp_DID == FABRIC_DID) {
			bcopy((void *)node_dhc->hrsp_cval,
			    (void *)cval, node_dhc->hrsp_cval_len);
			cval_len = node_dhc->hrsp_cval_len;
		} else {
			bcopy((void *)node_dhc->nlp_auth_misc.hrsp_cval,
			    (void *)cval,
			    node_dhc->nlp_auth_misc.hrsp_cval_len);
			cval_len = node_dhc->nlp_auth_misc.hrsp_cval_len;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "hash_verification: N-Null gp. 0x%x 0x%x",
		    ndlp->nlp_DID, cval_len);

		err = emlxs_hash_Cai(port, port_dhc, ndlp, (void *)Cai,
		    hash_id, dhgp_id,
		    tran_id, cval, cval_len,
		    key, dhval, dhval_len);

		if (err != BIG_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "hash_verification: Cai error. ret=0x%x",
			    err);

			return (NULL);
		}
		if (hash_id == AUTH_MD5) {
			bzero(&mdctx, sizeof (MD5_CTX));
			hash_size = MD5_LEN;

			MD5Init(&mdctx);
			MD5Update(&mdctx, (unsigned char *)&mytran_id, 1);

			if (ndlp->nlp_DID == FABRIC_DID) {
				MD5Update(&mdctx,
				    (unsigned char *)remote_key,
				    node_dhc->auth_key.remote_password_length);
			} else {
				MD5Update(&mdctx,
				    (unsigned char *)remote_key,
				    node_dhc->auth_key.remote_password_length);
			}

			MD5Update(&mdctx, (unsigned char *)Cai, MD5_LEN);
			MD5Final((uint8_t *)md5_digest, &mdctx);

			hash_val = (uint32_t *)kmem_zalloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
				    "hash_vf: alloc failed(Non-NULL dh)");

				return (NULL);
			} else {
				bcopy((void *)&md5_digest,
				    (void *)hash_val, MD5_LEN);
			}
		}
		if (hash_id == AUTH_SHA1) {
			bzero(&sha1ctx, sizeof (SHA1_CTX));
			hash_size = SHA1_LEN;

			SHA1Init(&sha1ctx);
			SHA1Update(&sha1ctx, (void *)&mytran_id, 1);

			if (ndlp->nlp_DID == FABRIC_DID) {
				SHA1Update(&sha1ctx, (void *)remote_key,
				    node_dhc->auth_key.remote_password_length);
			} else {
				SHA1Update(&sha1ctx, (void *)remote_key,
				    node_dhc->auth_key.remote_password_length);
			}

			SHA1Update(&sha1ctx, (void *)Cai, SHA1_LEN);
			SHA1Final((void *)sha1_digest, &sha1ctx);

			hash_val = (uint32_t *)kmem_zalloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "hash_vf: val alloc failed (Non-NULL dh)");

				return (NULL);
			} else {
				bcopy((void *)&sha1_digest,
				    (void *)hash_val, SHA1_LEN);
			}
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
		    "hash_verification: hash_val=0x%x",
		    *(uint32_t *)hash_val);

		return ((uint32_t *)hash_val);
	}

} /* emlxs_hash_verification */



/*
 * When DHCHAP_Success msg was sent from responder to the initiator,
 * with bi-directional authentication requested, the
 * DHCHAP_Success contains the response R2 to the challenge C2 received.
 *
 * DHCHAP response R2: The value of R2 is computed using the hash function
 * H() selected by the HashID parameter of the
 * DHCHAP_Challenge msg, and the augmented challenge Ca2.
 *
 * NULL DH group: Ca2 = C2 Non NULL DH group: Ca2 = H(C2 ||
 * (g^y mod p)^x mod p)) x is selected by the authentication responder
 * which is the node_dhc->hrsp_priv_key[] (g^y mod p) is dhval received
 * from authentication initiator.
 *
 * R2 = H(Ti || Km || Ca2) Ti is the least significant byte of the
 * transaction id. Km is the secret associated with the
 * authentication responder.
 *
 * emlxs_hash_get_R2 and emlxs_hash_verification could be mergerd into one
 * function later.
 *
 */
static uint32_t *
emlxs_hash_get_R2(
	emlxs_port_t *port,
	emlxs_port_dhc_t *port_dhc,
	NODELIST *ndlp,
	uint32_t tran_id,
	uint8_t *dhval,
	uint32_t dhval_len,
	uint32_t flag,	/* flag 1 rsponder or 0 initiator */
	uint8_t *bi_cval)
{
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	uint32_t dhgp_id;
	uint32_t hash_id;
	uint32_t *hash_val = NULL;
	uint32_t hash_size;
	MD5_CTX mdctx;
	SHA1_CTX sha1ctx;
	uint8_t sha1_digest[20];
	uint8_t md5_digest[16];
	uint8_t Cai[20];
	/* union challenge_val un_cval; */
	uint8_t key[20];
	uint32_t cval_len;
	uint8_t mytran_id = 0x00;

	char *mykey;
	BIG_ERR_CODE err = BIG_OK;

	if (ndlp->nlp_DID == FABRIC_DID) {
		dhgp_id = node_dhc->nlp_auth_dhgpid;
		hash_id = node_dhc->nlp_auth_hashid;
	} else {
		if (flag == 0) {
			dhgp_id = node_dhc->dhgp_id;
			hash_id = node_dhc->hash_id;
		} else {
			dhgp_id = node_dhc->nlp_auth_dhgpid;
			hash_id = node_dhc->nlp_auth_hashid;
		}
	}

	tran_id = (AUTH_TRAN_ID_MASK & tran_id);
	mytran_id = (uint8_t)(LE_SWAP32(tran_id));

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_detail_msg,
	    "hash_get_R2:0x%x 0x%x dhgp_id=0x%x mytran_id=0x%x",
	    ndlp->nlp_DID, hash_id, dhgp_id, mytran_id);

	if (ndlp->nlp_DID == FABRIC_DID) {
		mykey = (char *)node_dhc->auth_key.local_password;

	} else {
		/* in case of end-to-end mykey should be remote_password */
		mykey = (char *)node_dhc->auth_key.remote_password;
	}

	if (dhval_len == 0) {
		/* NULL DHCHAP group */
		if (hash_id == AUTH_MD5) {
			bzero(&mdctx, sizeof (MD5_CTX));
			hash_size = MD5_LEN;
			MD5Init(&mdctx);

			MD5Update(&mdctx, (unsigned char *)&mytran_id, 1);

			if (ndlp->nlp_DID == FABRIC_DID) {
				MD5Update(&mdctx, (unsigned char *)mykey,
				    node_dhc->auth_key.local_password_length);
			} else {
				MD5Update(&mdctx, (unsigned char *)mykey,
				    node_dhc->auth_key.remote_password_length);
			}

			MD5Update(&mdctx, (unsigned char *)bi_cval, MD5_LEN);

			MD5Final((uint8_t *)md5_digest, &mdctx);

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				return (NULL);
			} else {
				bcopy((void *)md5_digest,
				    (void *)hash_val, MD5_LEN);
			}
		}
		if (hash_id == AUTH_SHA1) {
			bzero(&sha1ctx, sizeof (SHA1_CTX));
			hash_size = SHA1_LEN;
			SHA1Init(&sha1ctx);
			SHA1Update(&sha1ctx, (void *)&mytran_id, 1);

			if (ndlp->nlp_DID == FABRIC_DID) {
				SHA1Update(&sha1ctx, (void *)mykey,
				    node_dhc->auth_key.local_password_length);
			} else {
				SHA1Update(&sha1ctx, (void *)mykey,
				    node_dhc->auth_key.remote_password_length);
			}

			SHA1Update(&sha1ctx, (void *)bi_cval, SHA1_LEN);
			SHA1Final((void *)sha1_digest, &sha1ctx);
			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
				return (NULL);
			} else {
				bcopy((void *)sha1_digest,
				    (void *)hash_val, SHA1_LEN);
			}
		}
	} else {
		/* NON-NULL DHCHAP */
		if (ndlp->nlp_DID == FABRIC_DID) {
			if (hash_id == AUTH_MD5) {
				bcopy((void *)node_dhc->hrsp_priv_key,
				    (void *)key, MD5_LEN);
			}
			if (hash_id == AUTH_SHA1) {
				bcopy((void *)node_dhc->hrsp_priv_key,
				    (void *)key, SHA1_LEN);
			}
			cval_len = node_dhc->hrsp_cval_len;
		} else {
			if (hash_id == AUTH_MD5) {
			bcopy(
			    (void *)node_dhc->nlp_auth_misc.hrsp_priv_key,
			    (void *)key, MD5_LEN);
			}
			if (hash_id == AUTH_SHA1) {
			bcopy(
			    (void *)node_dhc->nlp_auth_misc.hrsp_priv_key,
			    (void *)key, SHA1_LEN);
			}
			cval_len = node_dhc->nlp_auth_misc.hrsp_cval_len;
		}

		/* use bi_cval here */
		/*
		 * key: x dhval: (g^y mod p) tran_id: Ti bi_cval: C2 hash_id:
		 * H dhgp_id: p/g
		 *
		 * Cai = H (C2 || ((g^y mod p)^x mod p) )
		 *
		 * R2 = H (Ti || Km || Cai)
		 */
		err = emlxs_hash_Cai(port, port_dhc, ndlp, (void *)Cai,
		    hash_id, dhgp_id, tran_id, bi_cval, cval_len,
		    key, dhval, dhval_len);

		if (err != BIG_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "hash_get_R2: hash_Cai error. ret=0x%x",
			    err);

			return (NULL);
		}
		if (hash_id == AUTH_MD5) {
			bzero(&mdctx, sizeof (MD5_CTX));
			hash_size = MD5_LEN;

			MD5Init(&mdctx);
			MD5Update(&mdctx, (unsigned char *) &mytran_id, 1);

			/*
			 * Here we use the same key: mykey, note: this mykey
			 * should be the key associated with the
			 * authentication responder i.e. the remote key.
			 */
			if (ndlp->nlp_DID == FABRIC_DID)
				MD5Update(&mdctx, (unsigned char *)mykey,
				    node_dhc->auth_key.local_password_length);
			else
				MD5Update(&mdctx, (unsigned char *)mykey,
				    node_dhc->auth_key.remote_password_length);

			MD5Update(&mdctx, (unsigned char *)Cai, MD5_LEN);
			MD5Final((uint8_t *)md5_digest, &mdctx);

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "hash_get_R2: hash_val MD5 alloc failed.");

				return (NULL);
			} else {
				bcopy((void *)md5_digest,
				    (void *)hash_val, MD5_LEN);
			}
		}
		if (hash_id == AUTH_SHA1) {
			bzero(&sha1ctx, sizeof (SHA1_CTX));
			hash_size = SHA1_LEN;

			SHA1Init(&sha1ctx);
			SHA1Update(&sha1ctx, (void *)&mytran_id, 1);

			if (ndlp->nlp_DID == FABRIC_DID) {
				SHA1Update(&sha1ctx, (void *)mykey,
				    node_dhc->auth_key.local_password_length);
			} else {
				SHA1Update(&sha1ctx, (void *)mykey,
				    node_dhc->auth_key.remote_password_length);
			}

			SHA1Update(&sha1ctx, (void *)Cai, SHA1_LEN);
			SHA1Final((void *)sha1_digest, &sha1ctx);

			hash_val = (uint32_t *)kmem_alloc(hash_size,
			    KM_NOSLEEP);
			if (hash_val == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_error_msg,
			    "hash_get_R2: hash_val SHA1 alloc failed.");

				return (NULL);
			} else {
				bcopy((void *)sha1_digest,
				    (void *)hash_val, SHA1_LEN);
			}
		}
	}

	return ((uint32_t *)hash_val);

} /* emlxs_hash_get_R2 */


static void
emlxs_log_auth_event(
	emlxs_port_t *port,
	NODELIST *ndlp,
	char *subclass,
	char *info)
{
	emlxs_hba_t *hba = HBA;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	nvlist_t *attr_list = NULL;
	dev_info_t *dip = hba->dip;
	emlxs_auth_cfg_t *auth_cfg;
	char *tmp = "No_more_logging_information_available";
	uint8_t lwwn[8];
	uint8_t rwwn[8];
	char *lwwn_str = NULL;
	char *rwwn_str = NULL;
	char ext_subclass[128];
	char ext_class[32];

	auth_cfg = &(node_dhc->auth_cfg);

	if (info == NULL) {
		info = tmp;
	}
	bcopy((void *) &auth_cfg->local_entity, (void *)lwwn, 8);
	lwwn_str = (char *)kmem_zalloc(32, KM_NOSLEEP);
	if (lwwn_str == NULL) {
		return;
	}
	(void) snprintf(lwwn_str, 32, "%02X%02X%02X%02X%02X%02X%02X%02X",
	    lwwn[0], lwwn[1], lwwn[2], lwwn[3], lwwn[4], lwwn[5], lwwn[6],
	    lwwn[7]);

	bcopy((void *)&auth_cfg->remote_entity, (void *)rwwn, 8);
	rwwn_str = (char *)kmem_zalloc(32, KM_NOSLEEP);
	if (rwwn_str == NULL) {
		kmem_free(lwwn_str, 32);
		return;
	}

	(void) snprintf(rwwn_str, 32, "%02X%02X%02X%02X%02X%02X%02X%02X",
	    rwwn[0], rwwn[1], rwwn[2], rwwn[3], rwwn[4], rwwn[5], rwwn[6],
	    rwwn[7]);

	(void) snprintf(ext_subclass, sizeof (ext_subclass),
	    "ESC_%s_%s", DRIVER_NAME, subclass);
	(void) snprintf(ext_class, sizeof (ext_class),
	    "EC_%s", DRIVER_NAME);

	if (nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE, KM_NOSLEEP)
	    == DDI_SUCCESS) {
		if ((nvlist_add_uint32(attr_list, "instance",
		    ddi_get_instance(dip)) == DDI_SUCCESS) &&
		    (nvlist_add_string(attr_list, "lwwn",
		    lwwn_str) == DDI_SUCCESS) &&
		    (nvlist_add_string(attr_list, "rwwn",
		    rwwn_str) == DDI_SUCCESS) &&
		    (nvlist_add_string(attr_list, "Info",
		    info) == DDI_SUCCESS) &&
		    (nvlist_add_string(attr_list, "Class",
		    ext_class) == DDI_SUCCESS) &&
		    (nvlist_add_string(attr_list, "SubClass",
		    ext_subclass) == DDI_SUCCESS)) {

			(void) ddi_log_sysevent(dip,
			    emlxs_strtoupper(DRIVER_NAME),
			    ext_class,
			    ext_subclass,
			    attr_list,
			    NULL,
			    DDI_NOSLEEP);
		}
		nvlist_free(attr_list);
		attr_list = NULL;
	}
	kmem_free(lwwn_str, 32);
	kmem_free(rwwn_str, 32);

	return;

} /* emlxs_log_auth_event() */


/* **************************** AUTH DHC INTERFACE ************************* */

extern int
emlxs_dhc_auth_start(
	emlxs_port_t *port,
	emlxs_node_t *ndlp,
	uint8_t *deferred_sbp,
	uint8_t *deferred_ubp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	emlxs_auth_cfg_t *auth_cfg;
	emlxs_auth_key_t *auth_key;
	uint32_t i;
	uint32_t fabric;
	uint32_t fabric_switch;

	/* The ubp represents an unsolicted PLOGI */
	/* The sbp represents a solicted PLOGI    */

	fabric = ((ndlp->nlp_DID & FABRIC_DID_MASK) == FABRIC_DID_MASK) ? 1 : 0;
	fabric_switch = ((ndlp->nlp_DID == FABRIC_DID) ? 1 : 0);

	/* Return is authentication is not enabled */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_start_msg,
		    "Not started. Auth disabled. did=0x%x", ndlp->nlp_DID);

		emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_DISABLED, 0, 0);

		return (1);
	}
	if (port->vpi != 0 && cfg[CFG_AUTH_NPIV].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_start_msg,
		    "Not started. NPIV auth disabled. did=0x%x", ndlp->nlp_DID);

		emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_DISABLED, 0, 0);

		return (1);
	}
	if (!fabric_switch && fabric) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_start_msg,
		    "Not started. FS auth disabled. did=0x%x", ndlp->nlp_DID);

		emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_DISABLED, 0, 0);

		return (1);
	}
	/* Return if fcsp support to this node is not enabled */
	if (!fabric_switch && cfg[CFG_AUTH_E2E].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_start_msg,
		    "Not started. E2E auth disabled. did=0x%x", ndlp->nlp_DID);

		emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_DISABLED, 0, 0);

		return (1);
	}
	if ((deferred_sbp && node_dhc->deferred_sbp) ||
	    (deferred_ubp && node_dhc->deferred_ubp)) {
		/* Clear previous authentication */
		emlxs_dhc_auth_stop(port, ndlp);
	}
	mutex_enter(&hba->auth_lock);

	/* Intialize node */
	node_dhc->parent_auth_cfg = NULL;
	node_dhc->parent_auth_key = NULL;

	/* Acquire auth configuration */
	if (fabric_switch) {
		auth_cfg = emlxs_auth_cfg_find(port,
		    (uint8_t *)emlxs_fabric_wwn);
		auth_key = emlxs_auth_key_find(port,
		    (uint8_t *)emlxs_fabric_wwn);
	} else {
		auth_cfg = emlxs_auth_cfg_find(port,
		    (uint8_t *)&ndlp->nlp_portname);
		auth_key = emlxs_auth_key_find(port,
		    (uint8_t *)&ndlp->nlp_portname);
	}

	if (!auth_cfg) {
		mutex_exit(&hba->auth_lock);

		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_start_msg,
		    "Not started. No auth cfg entry found. did=0x%x",
		    ndlp->nlp_DID);

		emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_DISABLED, 0, 0);

		return (1);
	}
	if (fabric_switch) {
		auth_cfg->node = NULL;
	} else {
		node_dhc->parent_auth_cfg = auth_cfg;
		auth_cfg->node = ndlp;
	}

	if (!auth_key) {
		mutex_exit(&hba->auth_lock);

		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_start_msg,
		    "Not started. No auth key entry found. did=0x%x",
		    ndlp->nlp_DID);

		emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_DISABLED, 0, 0);

		return (1);
	}
	if (fabric_switch) {
		auth_key->node = NULL;
	} else {
		node_dhc->parent_auth_key = auth_key;
		auth_key->node = ndlp;
	}

	/* Remote port does not support fcsp */
	if (ndlp->sparm.cmn.fcsp_support == 0) {
		switch (auth_cfg->authentication_mode) {
		case AUTH_MODE_PASSIVE:
			mutex_exit(&hba->auth_lock);

			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_fcsp_start_msg,
			    "Not started. Auth unsupported. did=0x%x",
			    ndlp->nlp_DID);

			emlxs_dhc_state(port, ndlp,
			    NODE_STATE_AUTH_DISABLED, 0, 0);
			return (1);

		case AUTH_MODE_ACTIVE:
			mutex_exit(&hba->auth_lock);

			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_fcsp_start_msg,
			    "Failed. Auth unsupported. did=0x%x",
			    ndlp->nlp_DID);

			/*
			 * Save packet for deferred completion until
			 * authentication is complete
			 */
			ndlp->node_dhc.deferred_sbp = deferred_sbp;
			ndlp->node_dhc.deferred_ubp = deferred_ubp;

			goto failed;

		case AUTH_MODE_DISABLED:
		default:
			mutex_exit(&hba->auth_lock);

			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_fcsp_start_msg,
			    "Not started. Auth mode=disabled. did=0x%x",
			    ndlp->nlp_DID);

			emlxs_dhc_state(port, ndlp,
			    NODE_STATE_AUTH_DISABLED, 0, 0);
			return (1);
		}
	} else {	/* Remote port supports fcsp */
		switch (auth_cfg->authentication_mode) {
		case AUTH_MODE_PASSIVE:
		case AUTH_MODE_ACTIVE:
			/* start auth */
			break;

		case AUTH_MODE_DISABLED:
		default:
			mutex_exit(&hba->auth_lock);

			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_fcsp_start_msg,
			    "Failed. Auth mode=disabled. did=0x%x",
			    ndlp->nlp_DID);

			/*
			 * Save packet for deferred completion until
			 * authentication is complete
			 */
			ndlp->node_dhc.deferred_sbp = deferred_sbp;
			ndlp->node_dhc.deferred_ubp = deferred_ubp;

			goto failed;
		}
	}

	/* We have a GO for authentication */

	/*
	 * Save pointers for deferred completion until authentication is
	 * complete
	 */
	node_dhc->deferred_sbp = deferred_sbp;
	node_dhc->deferred_ubp = deferred_ubp;

	bzero(&node_dhc->auth_cfg, sizeof (node_dhc->auth_cfg));
	bzero(&node_dhc->auth_key, sizeof (node_dhc->auth_key));

	/* Program node's auth cfg */
	bcopy((uint8_t *)&port->wwpn,
	    (uint8_t *)&node_dhc->auth_cfg.local_entity, 8);
	bcopy((uint8_t *)&ndlp->nlp_portname,
	    (uint8_t *)&node_dhc->auth_cfg.remote_entity, 8);

	node_dhc->auth_cfg.authentication_timeout =
	    auth_cfg->authentication_timeout;
	node_dhc->auth_cfg.authentication_mode =
	    auth_cfg->authentication_mode;

	/*
	 * If remote password type is "ignore", then only unidirectional auth
	 * is allowed
	 */
	if (auth_key->remote_password_type == 3) {
		node_dhc->auth_cfg.bidirectional = 0;
	} else {
		node_dhc->auth_cfg.bidirectional = auth_cfg->bidirectional;
	}

	node_dhc->auth_cfg.reauthenticate_time_interval =
	    auth_cfg->reauthenticate_time_interval;

	for (i = 0; i < 4; i++) {
		switch (auth_cfg->authentication_type_priority[i]) {
		case ELX_DHCHAP:
			node_dhc->auth_cfg.authentication_type_priority[i] =
			    AUTH_DHCHAP;
			break;

		case ELX_FCAP:
			node_dhc->auth_cfg.authentication_type_priority[i] =
			    AUTH_FCAP;
			break;

		case ELX_FCPAP:
			node_dhc->auth_cfg.authentication_type_priority[i] =
			    AUTH_FCPAP;
			break;

		case ELX_KERBEROS:
			node_dhc->auth_cfg.authentication_type_priority[i] =
			    AUTH_KERBEROS;
			break;

		default:
			node_dhc->auth_cfg.authentication_type_priority[i] =
			    0;
			break;
		}

		switch (auth_cfg->hash_priority[i]) {
		case ELX_SHA1:
			node_dhc->auth_cfg.hash_priority[i] = AUTH_SHA1;
			break;

		case ELX_MD5:
			node_dhc->auth_cfg.hash_priority[i] = AUTH_MD5;
			break;

		default:
			node_dhc->auth_cfg.hash_priority[i] = 0;
			break;
		}
	}

	for (i = 0; i < 8; i++) {
		switch (auth_cfg->dh_group_priority[i]) {
		case ELX_GROUP_NULL:
			node_dhc->auth_cfg.dh_group_priority[i] = GROUP_NULL;
			break;

		case ELX_GROUP_1024:
			node_dhc->auth_cfg.dh_group_priority[i] = GROUP_1024;
			break;

		case ELX_GROUP_1280:
			node_dhc->auth_cfg.dh_group_priority[i] = GROUP_1280;
			break;

		case ELX_GROUP_1536:
			node_dhc->auth_cfg.dh_group_priority[i] = GROUP_1536;
			break;

		case ELX_GROUP_2048:
			node_dhc->auth_cfg.dh_group_priority[i] = GROUP_2048;
			break;

		default:
			node_dhc->auth_cfg.dh_group_priority[i] = 0xF;
			break;
		}
	}

	/* Program the node's key */
	if (auth_key) {
		bcopy((uint8_t *)auth_key,
		    (uint8_t *)&node_dhc->auth_key,
		    sizeof (emlxs_auth_key_t));
		node_dhc->auth_key.next = NULL;
		node_dhc->auth_key.prev = NULL;

		bcopy((uint8_t *)&port->wwpn,
		    (uint8_t *)&node_dhc->auth_key.local_entity, 8);
		bcopy((uint8_t *)&ndlp->nlp_portname,
		    (uint8_t *)&node_dhc->auth_key.remote_entity,
		    8);
	}
	mutex_exit(&hba->auth_lock);

	node_dhc->nlp_auth_limit = 2;
	node_dhc->nlp_fb_vendor = 1;

	node_dhc->nlp_authrsp_tmocnt = 0;
	node_dhc->nlp_authrsp_tmo = 0;

	if (deferred_ubp) {
		/* Acknowledge the unsolicited PLOGI */
		/* This should trigger the other port to start authentication */
		if (emlxs_ub_send_login_acc(port,
		    (fc_unsol_buf_t *)deferred_ubp) != FC_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_fcsp_start_msg,
			    "Not started. Unable to send PLOGI ACC. did=0x%x",
			    ndlp->nlp_DID);

			goto failed;
		}
		/* Start the auth rsp timer */
		node_dhc->nlp_authrsp_tmo = DRV_TIME +
		    node_dhc->auth_cfg.authentication_timeout;

		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_start_msg,
		    "Authrsp timer activated. did=0x%x",
		    ndlp->nlp_DID);

		/* The next state should be emlxs_rcv_auth_msg_unmapped_node */
		emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_SUCCESS, 0, 0);
	} else {
		node_dhc->nlp_auth_flag = 1;	/* host is the initiator */

		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_start_msg,
		    "Auth initiated. did=0x%x limit=%d sbp=%p",
		    ndlp->nlp_DID, node_dhc->nlp_auth_limit, deferred_sbp);

		if (emlxs_issue_auth_negotiate(port, ndlp, 0)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_start_msg,
			    "Failed. Auth initiation failed. did=0x%x",
			    ndlp->nlp_DID);

			goto failed;
		}
	}

	return (0);

failed:

	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_FAILED, 0, 0);

	/* Complete authentication with failed status */
	emlxs_dhc_auth_complete(port, ndlp, 1);

	return (0);

} /* emlxs_dhc_auth_start() */



/* This is called to indicate the driver has lost connection with this node */
extern void
emlxs_dhc_auth_stop(
	emlxs_port_t *port,
	emlxs_node_t *ndlp)
{
	emlxs_port_dhc_t *port_dhc = &port->port_dhc;
	emlxs_node_dhc_t *node_dhc;
	uint32_t i;

	if (port_dhc->state == ELX_FABRIC_STATE_UNKNOWN) {
		/* Nothing to stop */
		return;
	}
	if (ndlp) {
		node_dhc = &ndlp->node_dhc;

		if (node_dhc->state == NODE_STATE_UNKNOWN) {
			/* Nothing to stop */
			return;
		}
		if (ndlp->nlp_DID != FABRIC_DID) {
			emlxs_dhc_state(port, ndlp, NODE_STATE_UNKNOWN, 0, 0);
		}
		emlxs_dhc_auth_complete(port, ndlp, 2);
	} else {	/* Lost connection to all nodes for this port */
		rw_enter(&port->node_rwlock, RW_READER);
		for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
			ndlp = port->node_table[i];

			if (!ndlp) {
				continue;
			}
			node_dhc = &ndlp->node_dhc;

			if (node_dhc->state == NODE_STATE_UNKNOWN) {
				continue;
			}
			if (ndlp->nlp_DID != FABRIC_DID) {
				emlxs_dhc_state(port, ndlp,
				    NODE_STATE_UNKNOWN, 0, 0);
			}
			emlxs_dhc_auth_complete(port, ndlp, 2);
		}
		rw_exit(&port->node_rwlock);
	}

	return;

} /* emlxs_dhc_auth_stop */


/* state = 0   - Successful completion. Continue connection to node */
/* state = 1   - Failed completion. Do not continue with connection to node */
/* state = 2   - Stopped completion. Do not continue with connection to node */

static void
emlxs_dhc_auth_complete(
			emlxs_port_t *port,
			emlxs_node_t *ndlp,
			uint32_t status)
{
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint32_t fabric;
	uint32_t fabric_switch;

	fabric = ((ndlp->nlp_DID & FABRIC_DID_MASK) == FABRIC_DID_MASK) ? 1 : 0;
	fabric_switch = ((ndlp->nlp_DID == FABRIC_DID) ? 1 : 0);

	EMLXS_MSGF(EMLXS_CONTEXT,
	    &emlxs_fcsp_complete_msg,
	    "did=0x%x status=%d sbp=%p ubp=%p",
	    ndlp->nlp_DID, status, node_dhc->deferred_sbp,
	    node_dhc->deferred_ubp);

	if (status == 1) {
		if (fabric_switch) {
			/* Virtual link down */
			(void) emlxs_port_offline(port, 0xfeffffff);
		} else if (!fabric) {
			/* Port offline */
			(void) emlxs_port_offline(port, ndlp->nlp_DID);
		}
	}
	/* Send a LOGO if authentication was not successful */
	if (status == 1) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_complete_msg,
		    "Sending LOGO to did=0x%x...",
		    ndlp->nlp_DID);
		emlxs_send_logo(port, ndlp->nlp_DID);
	}

	/* Process deferred cmpl now */
	emlxs_mb_deferred_cmpl(port, status,
	    (emlxs_buf_t *)node_dhc->deferred_sbp,
	    (fc_unsol_buf_t *)node_dhc->deferred_ubp, 0);

	node_dhc->deferred_sbp = 0;
	node_dhc->deferred_ubp = 0;

	return;

} /* emlxs_dhc_auth_complete */


extern void
emlxs_dhc_attach(emlxs_hba_t *hba)
{
	mutex_init(&hba->auth_lock, NULL, MUTEX_DRIVER, NULL);

	mutex_init(&hba->dhc_lock, NULL, MUTEX_DRIVER, NULL);

	emlxs_auth_cfg_init(hba);

	emlxs_auth_key_init(hba);

	hba->rdn_flag = 1;

	return;

} /* emlxs_dhc_attach() */


extern void
emlxs_dhc_detach(emlxs_hba_t *hba)
{
	emlxs_auth_cfg_fini(hba);

	emlxs_auth_key_fini(hba);

	mutex_destroy(&hba->dhc_lock);
	mutex_destroy(&hba->auth_lock);

	return;

} /* emlxs_dhc_detach() */


extern void
emlxs_dhc_init_sp(emlxs_port_t *port, uint32_t did, SERV_PARM *sp, char **msg)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	uint32_t fabric;
	uint32_t fabric_switch;
	emlxs_auth_cfg_t *auth_cfg = NULL;
	emlxs_auth_key_t *auth_key = NULL;

	fabric = ((did & FABRIC_DID_MASK) == FABRIC_DID_MASK) ? 1 : 0;
	fabric_switch = ((did == FABRIC_DID) ? 1 : 0);

	/* Return is authentication is not enabled */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		sp->cmn.fcsp_support = 0;
		bcopy("fcsp:Disabled (0)", (void *) &msg[0],
		    sizeof ("fcsp:Disabled (0)"));
		return;
	}

	if (port->vpi != 0 && cfg[CFG_AUTH_NPIV].current == 0) {
		sp->cmn.fcsp_support = 0;
		bcopy("fcsp:Disabled (npiv)", (void *) &msg[0],
		    sizeof ("fcsp:Disabled (npiv)"));
		return;
	}
	if (!fabric_switch && fabric) {
		sp->cmn.fcsp_support = 0;
		bcopy("fcsp:Disabled (fs)", (void *) &msg[0],
		    sizeof ("fcsp:Disabled (fs)"));
		return;
	}
	/* Return if fcsp support to this node is not enabled */
	if (!fabric_switch && cfg[CFG_AUTH_E2E].current == 0) {
		sp->cmn.fcsp_support = 0;
		bcopy("fcsp:Disabled (e2e)", (void *) &msg[0],
		    sizeof ("fcsp:Disabled (e2e)"));
		return;
	}

	mutex_enter(&hba->auth_lock);
	if (fabric_switch) {
		auth_cfg = emlxs_auth_cfg_find(port,
		    (uint8_t *)emlxs_fabric_wwn);
		auth_key = emlxs_auth_key_find(port,
		    (uint8_t *)emlxs_fabric_wwn);
		if ((!auth_cfg) || (!auth_key)) {
			sp->cmn.fcsp_support = 0;
			bcopy("fcsp:Disabled (1)", (void *) &msg[0],
			    sizeof ("fcsp:Disabled (1)"));
			mutex_exit(&hba->auth_lock);
			return;
		}
	}
	mutex_exit(&hba->auth_lock);

	sp->cmn.fcsp_support = 1;

	return;

} /* emlxs_dhc_init_sp() */


extern uint32_t
emlxs_dhc_verify_login(emlxs_port_t *port, uint32_t sid, SERV_PARM *sp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	emlxs_auth_cfg_t *auth_cfg;
	emlxs_auth_key_t *auth_key;
	uint32_t fabric;
	uint32_t fabric_switch;

	fabric = ((sid & FABRIC_DID_MASK) == FABRIC_DID_MASK) ? 1 : 0;
	fabric_switch = ((sid == FABRIC_DID) ? 1 : 0);

	if (port->port_dhc.state == ELX_FABRIC_AUTH_FAILED) {
		/* Reject login */
		return (1);
	}
	/* Remote host supports FCSP */
	if (sp->cmn.fcsp_support) {
		/* Continue login */
		return (0);
	}
	/* Auth disabled in host */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		/* Continue login */
		return (0);
	}
	/* Auth disabled for npiv */
	if (port->vpi != 0 && cfg[CFG_AUTH_NPIV].current == 0) {
		/* Continue login */
		return (0);
	}
	if (!fabric_switch && fabric) {
		/* Continue login */
		return (0);
	}
	/* Auth disabled for p2p */
	if (!fabric_switch && cfg[CFG_AUTH_E2E].current == 0) {
		/* Continue login */
		return (0);
	}

	/* Remote port does NOT support FCSP */
	/* Host has FCSP enabled */
	/* Now check to make sure auth mode for this port is also enabled */

	mutex_enter(&hba->auth_lock);

	/* Acquire auth configuration */
	if (fabric_switch) {
		auth_cfg = emlxs_auth_cfg_find(port,
		    (uint8_t *)emlxs_fabric_wwn);
		auth_key = emlxs_auth_key_find(port,
		    (uint8_t *)emlxs_fabric_wwn);
	} else {
		auth_cfg = emlxs_auth_cfg_find(port,
		    (uint8_t *)&sp->portName);
		auth_key = emlxs_auth_key_find(port,
		    (uint8_t *)&sp->portName);
	}

	if (auth_key && auth_cfg &&
	    (auth_cfg->authentication_mode == AUTH_MODE_ACTIVE)) {
		mutex_exit(&hba->auth_lock);

		/* Reject login */
		return (1);
	}
	mutex_exit(&hba->auth_lock);

	return (0);

} /* emlxs_dhc_verify_login() */


/*
 * ! emlxs_dhc_reauth_timeout
 *
 * \pre \post \param phba \param arg1: \param arg2: ndlp to which the host
 * is to be authenticated. \return void
 *
 * \b Description:
 *
 * Timeout handler for reauthentication heartbeat.
 *
 * The reauthentication heart beat will be triggered 1 min by default after
 * the first authentication success. reauth_intval is
 * configurable. if reauth_intval is set to zero, it means no reauth heart
 * beat anymore.
 *
 * reauth heart beat will be triggered by IOCTL call from user space. Reauth
 * heart beat will go through the authentication process
 * all over again without causing IO traffic disruption. Initially it should
 * be triggered after authentication success.
 * Subsequently disable/enable reauth heart beat will be performed by
 * HBAnyware or other utility.
 *
 */
/* ARGSUSED */
extern void
emlxs_dhc_reauth_timeout(
	emlxs_port_t *port,
	void *arg1,
	void *arg2)
{
	emlxs_port_dhc_t *port_dhc = &port->port_dhc;
	NODELIST *ndlp = (NODELIST *) arg2;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;

	if (node_dhc->auth_cfg.reauthenticate_time_interval == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "Reauth timeout. Reauth no longer enabled. 0x%x %x",
		    ndlp->nlp_DID, node_dhc->state);

		emlxs_dhc_set_reauth_time(port, ndlp, DISABLE);

		return;
	}
	/* This should not happen!! */
	if (port_dhc->state == ELX_FABRIC_IN_AUTH) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_error_msg,
		    "Reauth timeout. Fabric in auth. Quiting. 0x%x %x",
		    ndlp->nlp_DID, node_dhc->state);

		emlxs_dhc_set_reauth_time(port, ndlp, DISABLE);

		return;
	}
	if (node_dhc->state != NODE_STATE_AUTH_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "Reauth timeout. Auth not done. Restarting. 0x%x %x",
		    ndlp->nlp_DID, node_dhc->state);

		goto restart;
	}
	/*
	 * This might happen, the ndlp is doing reauthencation. meaning ndlp
	 * is being re-authenticated to the host. Thus not necessary to have
	 * host re-authenticated to the ndlp at this point because ndlp might
	 * support bi-directional auth. we can just simply donothing and
	 * restart the timer.
	 */
	if (port_dhc->state == ELX_FABRIC_IN_REAUTH) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "Reauth timeout. Fabric in reauth. Restarting. 0x%x %x",
		    ndlp->nlp_DID, node_dhc->state);

		goto restart;
	}
	/*
	 * node's reauth heart beat is running already, cancel it first and
	 * then restart
	 */
	if (node_dhc->nlp_reauth_status == NLP_HOST_REAUTH_IN_PROGRESS) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "Reauth timeout. Fabric in reauth. Restarting. 0x%x %x",
		    ndlp->nlp_DID, node_dhc->state);

		goto restart;
	}
	EMLXS_MSGF(EMLXS_CONTEXT,
	    &emlxs_fcsp_debug_msg,
	    "Reauth timeout. Auth initiated. did=0x%x",
	    ndlp->nlp_DID);

	emlxs_dhc_set_reauth_time(port, ndlp, ENABLE);
	node_dhc->nlp_reauth_status = NLP_HOST_REAUTH_IN_PROGRESS;

	/* Attempt to restart authentication */
	if (emlxs_dhc_auth_start(port, ndlp, NULL, NULL) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "Reauth timeout. Auth initiation failed. 0x%x %x",
		    ndlp->nlp_DID, node_dhc->state);

		return;
	}
	return;

restart:

	emlxs_dhc_set_reauth_time(port, ndlp, ENABLE);

	return;

} /* emlxs_dhc_reauth_timeout */


static void
emlxs_dhc_set_reauth_time(
	emlxs_port_t *port,
	emlxs_node_t *ndlp,
	uint32_t status)
{
	emlxs_port_dhc_t *port_dhc = &port->port_dhc;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint32_t drv_time;
	uint32_t timeout;
	uint32_t reauth_tmo;
	time_t last_auth_time;

	node_dhc->flag &= ~NLP_SET_REAUTH_TIME;

	if ((status == ENABLE) &&
	    node_dhc->auth_cfg.reauthenticate_time_interval) {

		timeout =
		    (60 * node_dhc->auth_cfg.reauthenticate_time_interval);
		drv_time = DRV_TIME;

		/* Get last successful auth time */
		if (ndlp->nlp_DID == FABRIC_DID) {
			last_auth_time = port_dhc->auth_time;
		} else if (node_dhc->parent_auth_cfg) {
			last_auth_time = node_dhc->parent_auth_cfg->auth_time;
		} else {
			last_auth_time = 0;
		}

		if (last_auth_time) {
			reauth_tmo = last_auth_time + timeout;

			/* Validate reauth_tmo */
			if ((reauth_tmo < drv_time) ||
			    (reauth_tmo > drv_time + timeout)) {
				reauth_tmo = drv_time + timeout;
			}
		} else {
			reauth_tmo = drv_time + timeout;
		}

		node_dhc->nlp_reauth_tmo = reauth_tmo;
		node_dhc->nlp_reauth_status = NLP_HOST_REAUTH_ENABLED;

		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "Reauth enabled. did=0x%x state=%x tmo=%d,%d",
		    ndlp->nlp_DID, node_dhc->state,
		    node_dhc->auth_cfg.reauthenticate_time_interval,
		    (reauth_tmo - drv_time));

	} else {
		node_dhc->nlp_reauth_tmo = 0;
		node_dhc->nlp_reauth_status = NLP_HOST_REAUTH_DISABLED;

		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "Reauth disabled. did=0x%x state=%x",
		    ndlp->nlp_DID, node_dhc->state);
	}

	return;

} /* emlxs_dhc_set_reauth_time */


/* ARGSUSED */
extern void
emlxs_dhc_authrsp_timeout(
	emlxs_port_t *port,
	void *arg1,
	void *arg2)
{
	NODELIST *ndlp = (NODELIST *)arg1;
	emlxs_node_dhc_t *node_dhc = &ndlp->node_dhc;
	uint8_t ReasonCode;
	uint8_t ReasonCodeExplanation;

	node_dhc->nlp_authrsp_tmo = 0;
	node_dhc->nlp_authrsp_tmocnt++;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_debug_msg,
	    "Authrsp timeout. did=0x%x count=%d",
	    ndlp->nlp_DID, node_dhc->nlp_authrsp_tmocnt);

	/*
	 * According to the FC-SP spec v1.8 pp76.
	 *
	 * When the AUTH_TMO error is detected, the entity may: 1. Act as if the
	 * authentication transaction has failed and terminate the
	 * communication; or 2. Restart a new authentication transaction, by
	 * sending an AUTH_Reject msg with Reason Code `Logical Error' and
	 * Reason Code Explanation 'Restart Authentication Protocol', The
	 * action performed by the entity receiving such a AUTH_Reject should
	 * restart the authentication Transaction by sending a new
	 * AUTH_Negotiate. We plan to use 2 as the action for now.
	 *
	 */

	if (node_dhc->nlp_authrsp_tmocnt > 3) {
		/* Generate a remove event for the nodelist entry */
		(void) emlxs_dhchap_state_machine(port, NULL, NULL,
		    NULL, ndlp, NODE_EVENT_DEVICE_RM);

		ReasonCode = AUTHRJT_FAILURE;
		ReasonCodeExplanation = AUTHEXP_AUTH_FAILED;
	} else {
		/* Generate a recovery event for the nodelist entry */
		(void) emlxs_dhchap_state_machine(port, NULL, NULL,
		    NULL, ndlp, NODE_EVENT_DEVICE_RECOVERY);

		ReasonCode = AUTHRJT_LOGIC_ERR;
		ReasonCodeExplanation = AUTHEXP_RESTART_AUTH;
	}

	emlxs_dhc_state(port, ndlp, NODE_STATE_AUTH_FAILED, ReasonCode,
	    ReasonCodeExplanation);
	(void) emlxs_issue_auth_reject(port, ndlp, 0, 0, ReasonCode,
	    ReasonCodeExplanation);
	emlxs_dhc_auth_complete(port, ndlp, 1);

	/*
	 * It is expected the other party should restart the authentication
	 * transaction
	 */

	return;

} /* emlxs_dhc_authrsp_timeout() */


/* **************************** AUTH CFG MANAGEMENT ************************ */

/* auth_lock must be held */
static emlxs_auth_cfg_t *
emlxs_auth_cfg_find(emlxs_port_t *port, uint8_t *rwwpn)
{
	emlxs_hba_t *hba = HBA;
	emlxs_auth_cfg_t *auth_cfg;

	if (rwwpn) {
		/* lwwpn, rwwpn */
		auth_cfg = emlxs_auth_cfg_get(hba,
		    (uint8_t *)&port->wwpn, (uint8_t *)rwwpn);

		if (auth_cfg) {
			emlxs_auth_cfg_print(hba, auth_cfg);
			return (auth_cfg);
		}
		/* null, rwwpn */
		auth_cfg = emlxs_auth_cfg_get(hba,
		    (uint8_t *)emlxs_null_wwn, (uint8_t *)rwwpn);

		if (auth_cfg) {
			emlxs_auth_cfg_print(hba, auth_cfg);
			return (auth_cfg);
		}
	}
	/* lwwpn, null */
	auth_cfg = emlxs_auth_cfg_get(hba,
	    (uint8_t *)&port->wwpn, (uint8_t *)emlxs_null_wwn);

	if (auth_cfg) {
		emlxs_auth_cfg_print(hba, auth_cfg);
		return (auth_cfg);
	}
	/* null, null */
	return (&hba->auth_cfg);

} /* emlxs_auth_cfg_find() */

static void
emlxs_auth_cfg_init(emlxs_hba_t *hba)
{
	emlxs_config_t *cfg = &CFG;
	emlxs_auth_cfg_t *auth_cfg;

	/* Destroy old table if one exists */
	emlxs_auth_cfg_fini(hba);

	mutex_enter(&hba->auth_lock);

	/* Zero default entry */
	auth_cfg = &hba->auth_cfg;
	bzero(auth_cfg, sizeof (emlxs_auth_cfg_t));
	auth_cfg->next = auth_cfg;
	auth_cfg->prev = auth_cfg;

	/* Configure the default entry */
	auth_cfg->authentication_timeout =
	    cfg[CFG_AUTH_TMO].current;
	auth_cfg->authentication_mode =
	    cfg[CFG_AUTH_MODE].current;
	auth_cfg->bidirectional =
	    cfg[CFG_AUTH_BIDIR].current;
	auth_cfg->authentication_type_priority[0] =
	    (cfg[CFG_AUTH_TYPE].current & 0xF000) >> 12;
	auth_cfg->authentication_type_priority[1] =
	    (cfg[CFG_AUTH_TYPE].current & 0x0F00) >> 8;
	auth_cfg->authentication_type_priority[2] =
	    (cfg[CFG_AUTH_TYPE].current & 0x00F0) >> 4;
	auth_cfg->authentication_type_priority[3] =
	    (cfg[CFG_AUTH_TYPE].current & 0x000F);
	auth_cfg->hash_priority[0] =
	    (cfg[CFG_AUTH_HASH].current & 0xF000) >> 12;
	auth_cfg->hash_priority[1] =
	    (cfg[CFG_AUTH_HASH].current & 0x0F00) >> 8;
	auth_cfg->hash_priority[2] =
	    (cfg[CFG_AUTH_HASH].current & 0x00F0) >> 4;
	auth_cfg->hash_priority[3] =
	    (cfg[CFG_AUTH_HASH].current & 0x000F);
	auth_cfg->dh_group_priority[0] =
	    (cfg[CFG_AUTH_GROUP].current & 0xF0000000) >> 28;
	auth_cfg->dh_group_priority[1] =
	    (cfg[CFG_AUTH_GROUP].current & 0x0F000000) >> 24;
	auth_cfg->dh_group_priority[2] =
	    (cfg[CFG_AUTH_GROUP].current & 0x00F00000) >> 20;
	auth_cfg->dh_group_priority[3] =
	    (cfg[CFG_AUTH_GROUP].current & 0x000F0000) >> 16;
	auth_cfg->dh_group_priority[4] =
	    (cfg[CFG_AUTH_GROUP].current & 0x0000F000) >> 12;
	auth_cfg->dh_group_priority[5] =
	    (cfg[CFG_AUTH_GROUP].current & 0x00000F00) >> 8;
	auth_cfg->dh_group_priority[6] =
	    (cfg[CFG_AUTH_GROUP].current & 0x000000F0) >> 4;
	auth_cfg->dh_group_priority[7] =
	    (cfg[CFG_AUTH_GROUP].current & 0x0000000F);
	auth_cfg->reauthenticate_time_interval =
	    cfg[CFG_AUTH_INTERVAL].current;

	emlxs_auth_cfg_read(hba);

	mutex_exit(&hba->auth_lock);

	return;

} /* emlxs_auth_cfg_init() */


static void
emlxs_auth_cfg_fini(emlxs_hba_t *hba)
{
	emlxs_auth_cfg_t *auth_cfg = hba->auth_cfg.next;
	emlxs_auth_cfg_t *next;

	mutex_enter(&hba->auth_lock);

	while (auth_cfg && auth_cfg != &hba->auth_cfg) {
		next = auth_cfg->next;
		emlxs_auth_cfg_destroy(hba, auth_cfg);
		auth_cfg = next;
	}

	mutex_exit(&hba->auth_lock);

	return;

} /* emlxs_auth_cfg_fini() */


static void
emlxs_auth_cfg_print(emlxs_hba_t *hba, emlxs_auth_cfg_t *auth_cfg)
{
	emlxs_port_t *port = &PPORT;

	char s_lwwpn[32];
	char s_rwwpn[32];

	/* Create and add new entry */
	EMLXS_MSGF(EMLXS_CONTEXT,
	    &emlxs_fcsp_detail_msg,
	    "%s:%s:%x:%x:%x:%x%x%x%x:%x%x%x%x:%x%x%x%x%x%x%x%x:%x",
	    emlxs_wwn_xlate(s_lwwpn, sizeof (s_lwwpn),
	    (uint8_t *)&auth_cfg->local_entity),
	    emlxs_wwn_xlate(s_rwwpn, sizeof (s_rwwpn),
	    (uint8_t *)&auth_cfg->remote_entity),
	    auth_cfg->authentication_timeout,
	    auth_cfg->authentication_mode,
	    auth_cfg->bidirectional,
	    auth_cfg->authentication_type_priority[0],
	    auth_cfg->authentication_type_priority[1],
	    auth_cfg->authentication_type_priority[2],
	    auth_cfg->authentication_type_priority[3],
	    auth_cfg->hash_priority[0],
	    auth_cfg->hash_priority[1],
	    auth_cfg->hash_priority[2],
	    auth_cfg->hash_priority[3],
	    auth_cfg->dh_group_priority[0],
	    auth_cfg->dh_group_priority[1],
	    auth_cfg->dh_group_priority[2],
	    auth_cfg->dh_group_priority[3],
	    auth_cfg->dh_group_priority[4],
	    auth_cfg->dh_group_priority[5],
	    auth_cfg->dh_group_priority[6],
	    auth_cfg->dh_group_priority[7],
	    auth_cfg->reauthenticate_time_interval);

} /* emlxs_auth_cfg_print() */


/* auth_lock must be held */
static emlxs_auth_cfg_t *
emlxs_auth_cfg_get(emlxs_hba_t *hba, uint8_t *lwwpn, uint8_t *rwwpn)
{
	emlxs_auth_cfg_t *auth_cfg;

	if (!lwwpn || !rwwpn) {
		return (NULL);
	}

	/* Check for default entry */
	if ((bcmp(lwwpn, emlxs_null_wwn, 8) == 0) &&
	    (bcmp(rwwpn, emlxs_null_wwn, 8) == 0)) {
		return (&hba->auth_cfg);
	}

	for (auth_cfg = hba->auth_cfg.next;
	    auth_cfg != &hba->auth_cfg; auth_cfg = auth_cfg->next) {
		/* Find pwd entry for this local port */

		/* Check for exact wwpn match */
		if (bcmp((void *)&auth_cfg->local_entity,
		    (void *)lwwpn, 8) != 0) {
			continue;
		}
		/* Find pwd entry for remote port */

		/* Check for exact wwpn match */
		if (bcmp((void *)&auth_cfg->remote_entity,
		    (void *)rwwpn, 8) != 0) {
			continue;
		}
		return (auth_cfg);
	}

	return (NULL);

} /* emlxs_auth_cfg_get() */


/* auth_lock must be held */
static emlxs_auth_cfg_t *
emlxs_auth_cfg_create(emlxs_hba_t *hba, uint8_t *lwwpn, uint8_t *rwwpn)
{
	emlxs_auth_cfg_t *auth_cfg;

	/* First check if entry already exists */
	auth_cfg = emlxs_auth_cfg_get(hba, lwwpn, rwwpn);

	if (auth_cfg) {
		return (auth_cfg);
	}
	/* Allocate entry */
	auth_cfg = (emlxs_auth_cfg_t *)kmem_zalloc(sizeof (emlxs_auth_cfg_t),
	    KM_NOSLEEP);

	if (!auth_cfg) {
		return (NULL);
	}
	/* Add to list */
	auth_cfg->next = &hba->auth_cfg;
	auth_cfg->prev = hba->auth_cfg.prev;
	hba->auth_cfg.prev->next = auth_cfg;
	hba->auth_cfg.prev = auth_cfg;
	hba->auth_cfg_count++;

	/* Initialize name pair */
	if (lwwpn) {
		bcopy((void *)lwwpn, (void *)&auth_cfg->local_entity, 8);
	}
	if (rwwpn) {
		bcopy((void *)rwwpn, (void *)&auth_cfg->remote_entity, 8);
	}
	auth_cfg->auth_status.auth_state = DFC_AUTH_STATE_OFF;

	return (auth_cfg);

} /* emlxs_auth_cfg_create() */


/* auth_lock must be held */
static void
emlxs_auth_cfg_destroy(emlxs_hba_t *hba, emlxs_auth_cfg_t *auth_cfg)
{

	if (!auth_cfg) {
		return;
	}
	if (auth_cfg == &hba->auth_cfg) {
		return;
	}
	/* Remove from  list */
	auth_cfg->next->prev = auth_cfg->prev;
	auth_cfg->prev->next = auth_cfg->next;
	hba->auth_cfg_count--;

	/* Remove node binding */
	if (auth_cfg->node &&
	    auth_cfg->node->nlp_active &&
	    (auth_cfg->node->node_dhc.parent_auth_cfg == auth_cfg)) {
		auth_cfg->node->node_dhc.parent_auth_cfg = NULL;
	}
	bzero(auth_cfg, sizeof (emlxs_auth_cfg_t));
	kmem_free(auth_cfg, sizeof (emlxs_auth_cfg_t));

	return;

} /* emlxs_auth_cfg_destroy() */


/* auth_lock must be held */
static void
emlxs_auth_cfg_read(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	char **arrayp;
	emlxs_auth_cfg_t auth_cfg;
	emlxs_auth_cfg_t *auth_cfg2;
	uint32_t cnt;
	uint32_t rval;
	char buffer[64];
	char *prop_str;
	uint32_t i;

	/* Check for the per adapter setting */
	(void) snprintf(buffer, sizeof (buffer), "%s%d-auth-cfgs", DRIVER_NAME,
	    hba->ddiinst);
	cnt = 0;
	arrayp = NULL;
	rval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba->dip,
	    (DDI_PROP_DONTPASS),
	    buffer, &arrayp, &cnt);

	if ((rval != DDI_PROP_SUCCESS) || !cnt || !arrayp) {
		/* Check for the global setting */
		cnt = 0;
		arrayp = NULL;
		rval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY,
		    hba->dip, (DDI_PROP_DONTPASS),
		    "auth-cfgs", &arrayp, &cnt);
	}
	if ((rval != DDI_PROP_SUCCESS) || !cnt || !arrayp) {
		return;
	}
	for (i = 0; i < cnt; i++) {
		prop_str = arrayp[i];
		if (prop_str == NULL) {
			break;
		}
		/* parse the string */
		if (emlxs_auth_cfg_parse(hba, &auth_cfg, prop_str) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_msg,
			    "Error parsing auth_cfgs property. entry=%d", i);
			continue;
		}
		auth_cfg2 = emlxs_auth_cfg_create(hba,
		    (uint8_t *)&auth_cfg.local_entity,
		    (uint8_t *)&auth_cfg.remote_entity);

		if (!auth_cfg2) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_msg,
			    "Out of memory parsing auth_cfgs property. ey=%d",
			    i);
			return;
		}
		auth_cfg.next = auth_cfg2->next;
		auth_cfg.prev = auth_cfg2->prev;
		bcopy((uint8_t *)&auth_cfg,
		    (uint8_t *)auth_cfg2,
		    sizeof (emlxs_auth_cfg_t));
	}

	return;

} /* emlxs_auth_cfg_read() */


/* auth_lock must be held */
static uint32_t
emlxs_auth_cfg_parse(
	emlxs_hba_t *hba,
	emlxs_auth_cfg_t *auth_cfg,
	char *prop_str)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	uint32_t errors = 0;
	uint32_t c1;
	uint8_t *np;
	uint32_t j;
	uint32_t i;
	uint32_t sum;
	char *s;

	s = prop_str;
	bzero(auth_cfg, sizeof (emlxs_auth_cfg_t));

	/* Read local wwpn */
	np = (uint8_t *)&auth_cfg->local_entity;
	for (j = 0; j < 8; j++) {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = ((c1 - '0') << 4);
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = ((c1 - 'a' + 10) << 4);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = ((c1 - 'A' + 10) << 4);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err:Invalid LWWPN found. byte=%d hi_nibble=%c",
			    j, c1);
			errors++;
		}

		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum |= (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum |= (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum |= (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid LWWPN found. %d %c",
			    j, c1);
			errors++;
		}

		*np++ = (uint8_t)sum;
	}

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Cfg err: Invalid delimiter after LWWPN.");
		goto out;
	}
	/* Read remote wwpn */
	np = (uint8_t *)&auth_cfg->remote_entity;
	for (j = 0; j < 8; j++) {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = ((c1 - '0') << 4);
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = ((c1 - 'a' + 10) << 4);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = ((c1 - 'A' + 10) << 4);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid RWWPN found.byte=%d hi_nibble=%c",
			    j, c1);
			errors++;
		}

		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum |= (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum |= (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum |= (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid RWWPN found. %d %c",
			    j, c1);
			errors++;
		}

		*np++ = (uint8_t)sum;
	}

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Cfg err: Invalid delimiter after RWWPN.");
		goto out;
	}
	/* Read auth_tov (%x) */
	sum = 0;
	do {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = (sum << 4) + (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = (sum << 4) + (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = (sum << 4) + (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid auth_tov found. c=%c sum=%d",
			    c1, sum);

			errors++;
		}

	} while (*s != ':' && *s != 0);
	auth_cfg->authentication_timeout = sum;

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Cfg err: Invalid delimiter after auth_tov.");
		goto out;
	}
	/* Read auth_mode */
	sum = 0;
	do {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = (sum << 4) + (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = (sum << 4) + (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = (sum << 4) + (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid auth_mode found. c=%c sum=%d",
			    c1, sum);

			errors++;
		}

	} while (*s != ':' && *s != 0);
	auth_cfg->authentication_mode = sum;

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Config error: Invalid delimiter after auth_mode.");
		goto out;
	}
	/* Read auth_bidir */
	sum = 0;
	do {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = (sum << 4) + (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = (sum << 4) + (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = (sum << 4) + (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid auth_bidir found. c=%c sum=%d",
			    c1, sum);

			errors++;
		}

	} while (*s != ':' && *s != 0);
	auth_cfg->bidirectional = sum;

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Cfg err: Invalid delimiter after auth_bidir.");
		goto out;
	}
	/* Read type_priority[4] */
	for (i = 0; i < 4; i++) {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid type_pty[%d] found. c=%c sum=%d",
			    i, c1, sum);

			errors++;
		}

		auth_cfg->authentication_type_priority[i] = sum;
	}

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Cfg err: Invalid delimiter after type_priority.");

		goto out;
	}
	/* Read hash_priority[4] */
	for (i = 0; i < 4; i++) {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid hash_priority[%d] fd. %c %d",
			    i, c1, sum);

			errors++;
		}

		auth_cfg->hash_priority[i] = sum;
	}

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Cfg err: Invalid delimiter after hash_priority.");

		goto out;
	}
	/* Read group_priority[8] */
	for (i = 0; i < 8; i++) {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid group_priority[%d] fd. %c %d",
			    i, c1, sum);

			errors++;
		}

		auth_cfg->dh_group_priority[i] = sum;
	}

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Cfg err: Invalid delimiter after group_priority.");
		goto out;
	}
	/* Read reauth_tov */
	sum = 0;
	do {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = (sum << 4) + (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = (sum << 4) + (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = (sum << 4) + (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid reauth_tov found. c=%c sum=%d",
			    c1, sum);

			errors++;
		}

	} while (*s != ':' && *s != 0);
	auth_cfg->reauthenticate_time_interval = sum;

	if (errors) {
		goto out;
	}
	/* Verify values */

	/* Check authentication_timeout */
	if (auth_cfg->authentication_timeout < cfg[CFG_AUTH_TMO].low) {
		auth_cfg->authentication_timeout = cfg[CFG_AUTH_TMO].current;
	} else if (auth_cfg->authentication_timeout > cfg[CFG_AUTH_TMO].hi) {
		auth_cfg->authentication_timeout = cfg[CFG_AUTH_TMO].current;
	}
	/* Check authentication_mode */
	if (auth_cfg->authentication_mode < cfg[CFG_AUTH_MODE].low) {
		auth_cfg->authentication_mode = cfg[CFG_AUTH_MODE].current;
	} else if (auth_cfg->authentication_mode > cfg[CFG_AUTH_MODE].hi) {
		auth_cfg->authentication_mode = cfg[CFG_AUTH_MODE].current;
	}
	/* Check bidirectional */
	if (auth_cfg->bidirectional < cfg[CFG_AUTH_BIDIR].low) {
		auth_cfg->bidirectional = cfg[CFG_AUTH_BIDIR].current;
	} else if (auth_cfg->bidirectional > cfg[CFG_AUTH_BIDIR].hi) {
		auth_cfg->bidirectional = cfg[CFG_AUTH_BIDIR].current;
	}
	/* Check authentication_type_priority and hash_priority */
	for (i = 0; i < 4; i++) {
		if (auth_cfg->authentication_type_priority[i] >
		    DFC_AUTH_TYPE_MAX) {
			/* Set to current default */
			auth_cfg->authentication_type_priority[i] =
			    hba->auth_cfg.authentication_type_priority[i];
		}
		if (auth_cfg->hash_priority[i] > DFC_AUTH_HASH_MAX) {
			/* Set to current default */
			auth_cfg->hash_priority[i] =
			    hba->auth_cfg.hash_priority[i];
		}
	}

	/* Check dh_group_priority */
	for (i = 0; i < 8; i++) {
		if (auth_cfg->dh_group_priority[i] > DFC_AUTH_GROUP_MAX) {
			/* Set to current default */
			auth_cfg->dh_group_priority[i] =
			    hba->auth_cfg.dh_group_priority[i];
		}
	}

	/* Check reauthenticate_time_interval */
	if (auth_cfg->reauthenticate_time_interval <
	    cfg[CFG_AUTH_INTERVAL].low) {
		auth_cfg->reauthenticate_time_interval =
		    cfg[CFG_AUTH_INTERVAL].current;
	} else if (auth_cfg->reauthenticate_time_interval >
	    cfg[CFG_AUTH_INTERVAL].hi) {
		auth_cfg->reauthenticate_time_interval =
		    cfg[CFG_AUTH_INTERVAL].current;
	}
	emlxs_auth_cfg_print(hba, auth_cfg);

out:

	if (errors) {
		bzero(auth_cfg, sizeof (emlxs_auth_cfg_t));
		return (0);
	}
	return (1);

} /* emlxs_auth_cfg_parse() */


/* **************************** AUTH KEY MANAGEMENT ************************* */

/* auth_lock must be held */
extern emlxs_auth_key_t *
emlxs_auth_key_find(emlxs_port_t *port, uint8_t *rwwpn)
{
	emlxs_hba_t *hba = HBA;
	emlxs_auth_key_t *auth_key;

	if (rwwpn) {
		/* lwwpn, rwwpn */
		auth_key = emlxs_auth_key_get(hba,
		    (uint8_t *)&port->wwpn, (uint8_t *)rwwpn);

		if (auth_key) {
			emlxs_auth_key_print(hba, auth_key);
			return (auth_key);
		}
		/* null, rwwpn */
		auth_key = emlxs_auth_key_get(hba,
		    (uint8_t *)emlxs_null_wwn, (uint8_t *)rwwpn);

		if (auth_key) {
			emlxs_auth_key_print(hba, auth_key);
			return (auth_key);
		}
	}
	/* lwwpn, null */
	auth_key = emlxs_auth_key_get(hba,
	    (uint8_t *)&port->wwpn, (uint8_t *)emlxs_null_wwn);

	if (auth_key) {
		emlxs_auth_key_print(hba, auth_key);
		return (auth_key);
	}
	return (NULL);

} /* emlxs_auth_key_find() */


static void
emlxs_auth_key_init(emlxs_hba_t *hba)
{
	emlxs_auth_key_t *auth_key;

	/* Destroy old table if one exists */
	emlxs_auth_key_fini(hba);

	mutex_enter(&hba->auth_lock);

	/* Zero default entry */
	auth_key = &hba->auth_key;
	bzero(auth_key, sizeof (emlxs_auth_key_t));
	auth_key->next = auth_key;
	auth_key->prev = auth_key;

	/* Configure the default entry */
	auth_key->local_password_type = PASSWORD_TYPE_IGNORE;
	auth_key->remote_password_type = PASSWORD_TYPE_IGNORE;

	emlxs_auth_key_read(hba);

	mutex_exit(&hba->auth_lock);

	return;

} /* emlxs_auth_key_init() */


static void
emlxs_auth_key_fini(emlxs_hba_t *hba)
{
	emlxs_auth_key_t *auth_key = hba->auth_key.next;
	emlxs_auth_key_t *next;

	mutex_enter(&hba->auth_lock);

	while (auth_key && auth_key != &hba->auth_key) {
		next = auth_key->next;
		emlxs_auth_key_destroy(hba, auth_key);
		auth_key = next;
	}

	mutex_exit(&hba->auth_lock);

	return;

} /* emlxs_auth_key_fini() */


static void
emlxs_auth_key_print(emlxs_hba_t *hba, emlxs_auth_key_t *auth_key)
{
	emlxs_port_t *port = &PPORT;
	char s_lwwpn[32];
	char s_rwwpn[32];

	EMLXS_MSGF(EMLXS_CONTEXT,
	    &emlxs_fcsp_detail_msg,
	    "auth-key> %s:%s:%x:*%d chars*:%x:*%d chars*",
	    emlxs_wwn_xlate(s_lwwpn, sizeof (s_lwwpn),
	    (uint8_t *)&auth_key->local_entity),
	    emlxs_wwn_xlate(s_rwwpn, sizeof (s_rwwpn),
	    (uint8_t *)&auth_key->remote_entity),
	    auth_key->local_password_type, auth_key->local_password_length,
	    auth_key->remote_password_type, auth_key->remote_password_length);

	return;

} /* emlxs_auth_key_print() */


/* auth_lock must be held */
static emlxs_auth_key_t *
emlxs_auth_key_get(emlxs_hba_t *hba, uint8_t *lwwpn, uint8_t *rwwpn)
{
	emlxs_auth_key_t *auth_key;

	if (!lwwpn || !rwwpn) {
		return (NULL);
	}
	/* Check for default entry */
	if ((bcmp(lwwpn, emlxs_null_wwn, 8) == 0) &&
	    (bcmp(rwwpn, emlxs_null_wwn, 8) == 0)) {
		return (&hba->auth_key);
	}
	for (auth_key = hba->auth_key.next; auth_key !=
	    &hba->auth_key; auth_key = auth_key->next) {
		/* Find pwd entry for this local port */

		/* Check for exact wwpn match */
		if (bcmp((void *)&auth_key->local_entity,
		    (void *)lwwpn, 8) != 0) {
			continue;
		}
		/* Find pwd entry for remote port */

		/* Check for exact wwpn match */
		if (bcmp((void *)&auth_key->remote_entity,
		    (void *)rwwpn, 8) != 0) {
			continue;
		}
		return (auth_key);
	}

	return (NULL);

} /* emlxs_auth_key_get() */


/* auth_lock must be held */
static emlxs_auth_key_t *
emlxs_auth_key_create(emlxs_hba_t *hba, uint8_t *lwwpn, uint8_t *rwwpn)
{
	emlxs_auth_key_t *auth_key;

	/* First check if entry already exists */
	auth_key = emlxs_auth_key_get(hba, lwwpn, rwwpn);

	if (auth_key) {
		return (auth_key);
	}
	/* Allocate entry */
	auth_key = (emlxs_auth_key_t *)kmem_zalloc(sizeof (emlxs_auth_key_t),
	    KM_NOSLEEP);

	if (!auth_key) {
		return (NULL);
	}
	/* Initialize name pair */
	if (lwwpn) {
		bcopy((void *)lwwpn, (void *)&auth_key->local_entity, 8);
	}
	if (rwwpn) {
		bcopy((void *)rwwpn, (void *)&auth_key->remote_entity, 8);
	}
	/* Initialize type */
	auth_key->local_password_type = PASSWORD_TYPE_IGNORE;
	auth_key->remote_password_type = PASSWORD_TYPE_IGNORE;

	/* Add to list */
	auth_key->next = &hba->auth_key;
	auth_key->prev = hba->auth_key.prev;
	hba->auth_key.prev->next = auth_key;
	hba->auth_key.prev = auth_key;
	hba->auth_key_count++;

	return (auth_key);

} /* emlxs_auth_key_create() */


/* auth_lock must be held */
static void
emlxs_auth_key_destroy(emlxs_hba_t *hba, emlxs_auth_key_t *auth_key)
{

	if (!auth_key) {
		return;
	}
	if (auth_key == &hba->auth_key) {
		return;
	}
	/* Remove from  list */
	auth_key->next->prev = auth_key->prev;
	auth_key->prev->next = auth_key->next;
	hba->auth_key_count--;

	/* Remove node binding */
	if (auth_key->node &&
	    auth_key->node->nlp_active &&
	    (auth_key->node->node_dhc.parent_auth_key == auth_key)) {
		auth_key->node->node_dhc.parent_auth_key = NULL;
	}
	bzero(auth_key, sizeof (emlxs_auth_key_t));
	kmem_free(auth_key, sizeof (emlxs_auth_key_t));

	return;

} /* emlxs_auth_key_destroy() */


/* auth_lock must be held */
static void
emlxs_auth_key_read(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	char **arrayp;
	emlxs_auth_key_t auth_key;
	emlxs_auth_key_t *auth_key2;
	uint32_t cnt;
	uint32_t rval;
	char buffer[64];
	char *prop_str;
	uint32_t i;

	/* Check for the per adapter setting */
	(void) snprintf(buffer, sizeof (buffer), "%s%d-auth-keys", DRIVER_NAME,
	    hba->ddiinst);
	cnt = 0;
	arrayp = NULL;
	rval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba->dip,
	    (DDI_PROP_DONTPASS),
	    buffer, &arrayp, &cnt);

	if ((rval != DDI_PROP_SUCCESS) || !cnt || !arrayp) {
		/* Check for the global setting */
		cnt = 0;
		arrayp = NULL;
		rval = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba->dip,
		    (DDI_PROP_DONTPASS),
		    "auth-keys", &arrayp, &cnt);
	}
	if ((rval != DDI_PROP_SUCCESS) || !cnt || !arrayp) {
		return;
	}
	for (i = 0; i < cnt; i++) {
		prop_str = arrayp[i];
		if (prop_str == NULL) {
			break;
		}
		/* parse the string */
		if (emlxs_auth_key_parse(hba, &auth_key, prop_str) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_msg,
			    "Error parsing auth_keys property. entry=%d", i);
			continue;
		}
		auth_key2 = emlxs_auth_key_create(hba,
		    (uint8_t *)&auth_key.local_entity,
		    (uint8_t *)&auth_key.remote_entity);

		if (!auth_key2) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_msg,
			    "Out of memory parsing auth_keys property. %d",
			    i);
			return;
		}
		auth_key.next = auth_key2->next;
		auth_key.prev = auth_key2->prev;
		bcopy((uint8_t *)&auth_key,
		    (uint8_t *)auth_key2, sizeof (emlxs_auth_key_t));
	}

	return;

} /* emlxs_auth_key_read() */


/* auth_lock must be held */
static uint32_t
emlxs_auth_key_parse(
	emlxs_hba_t *hba,
	emlxs_auth_key_t *auth_key,
	char *prop_str)
{
	emlxs_port_t *port = &PPORT;
	uint32_t errors = 0;
	uint32_t c1;
	uint8_t *np;
	uint32_t j;
	uint32_t sum;
	char *s;

	s = prop_str;
	bzero(auth_key, sizeof (emlxs_auth_key_t));

	/* Read local wwpn */
	np = (uint8_t *)&auth_key->local_entity;
	for (j = 0; j < 8; j++) {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = ((c1 - '0') << 4);
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = ((c1 - 'a' + 10) << 4);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = ((c1 - 'A' + 10) << 4);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid LWWPN found. %d %c",
			    j, c1);
			errors++;
		}

		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum |= (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum |= (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum |= (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid LWWPN found. %d %c",
			    j, c1);
			errors++;
		}

		*np++ = (uint8_t)sum;
	}

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Cfg err: Invalid delimiter after LWWPN.");
		goto out;
	}
	/* Read remote wwpn */
	np = (uint8_t *)&auth_key->remote_entity;
	for (j = 0; j < 8; j++) {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = ((c1 - '0') << 4);
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = ((c1 - 'a' + 10) << 4);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = ((c1 - 'A' + 10) << 4);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid RWWPN found.%d %c",
			    j, c1);
			errors++;
		}

		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum |= (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum |= (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum |= (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid RWWPN found. %d %c",
			    j, c1);
			errors++;
		}

		*np++ = (uint8_t)sum;
	}

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Cfg err: Invalid delimiter after RWWPN.");
		goto out;
	}
	/* Read lpwd type (%x) */
	sum = 0;
	do {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = (sum << 4) + (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = (sum << 4) + (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = (sum << 4) + (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid lpwd type found. %c %d",
			    c1, sum);

			errors++;
		}

	} while (*s != ':' && *s != 0);
	auth_key->local_password_type = (uint16_t)sum;

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Cfg err: Invalid delimiter after lpwd type.");
		goto out;
	}
	/* Read lpwd */
	np = (uint8_t *)&auth_key->local_password;
	j = 0;
	switch (auth_key->local_password_type) {
	case 1:	/* ACSII */
		while (*s != ':' && *s != 0) {
			*np++ = *s++;
			j++;
		}
		break;

	case 2:	/* Hex */
		do {
			c1 = *s++;
			if ((c1 >= '0') && (c1 <= '9')) {
				sum = ((c1 - '0') << 4);
			} else if ((c1 >= 'a') && (c1 <= 'f')) {
				sum = ((c1 - 'a' + 10) << 4);
			} else if ((c1 >= 'A') && (c1 <= 'F')) {
				sum = ((c1 - 'A' + 10) << 4);
			} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid lpwd found. %d %c",
			    j, c1);
				errors++;
			}

			c1 = *s++;
			if ((c1 >= '0') && (c1 <= '9')) {
				sum |= (c1 - '0');
			} else if ((c1 >= 'a') && (c1 <= 'f')) {
				sum |= (c1 - 'a' + 10);
			} else if ((c1 >= 'A') && (c1 <= 'F')) {
				sum |= (c1 - 'A' + 10);
			} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid lpwd found. %d %c",
			    j, c1);
				errors++;
			}

			*np++ = (uint8_t)sum;
			j++;

		} while (*s != ':' && *s != 0);

		break;

	case 0:	/* Ignore */
	case 3:	/* Ignore */
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Config error: Invalid lpwd type found. type=%x",
		    auth_key->local_password_type);

		errors++;
		goto out;
	}
	auth_key->local_password_length = (uint16_t)j;

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Config error: Invalid delimiter after lpwd.");
		goto out;
	}
	/* Read rpwd type (%x) */
	sum = 0;
	do {
		c1 = *s++;
		if ((c1 >= '0') && (c1 <= '9')) {
			sum = (sum << 4) + (c1 - '0');
		} else if ((c1 >= 'a') && (c1 <= 'f')) {
			sum = (sum << 4) + (c1 - 'a' + 10);
		} else if ((c1 >= 'A') && (c1 <= 'F')) {
			sum = (sum << 4) + (c1 - 'A' + 10);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Config error: Invalid rpwd type found. %c %d",
			    c1, sum);

			errors++;
		}

	} while (*s != ':' && *s != 0);
	auth_key->remote_password_type = (uint16_t)sum;

	if (*s++ != ':') {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Config error: Invalid delimiter after rpwd type.");
		goto out;
	}
	/* Read rpwd */
	np = (uint8_t *)&auth_key->remote_password;
	j = 0;
	switch (auth_key->remote_password_type) {
	case 1:	/* ACSII */
		while (*s != ':' && *s != 0) {
			*np++ = *s++;
			j++;
		}
		break;

	case 2:	/* Hex */
		do {
			c1 = *s++;
			if ((c1 >= '0') && (c1 <= '9')) {
				sum = ((c1 - '0') << 4);
			} else if ((c1 >= 'a') && (c1 <= 'f')) {
				sum = ((c1 - 'a' + 10) << 4);
			} else if ((c1 >= 'A') && (c1 <= 'F')) {
				sum = ((c1 - 'A' + 10) << 4);
			} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid rpwd found. %d %c",
			    j, c1);
				errors++;
			}

			c1 = *s++;
			if ((c1 >= '0') && (c1 <= '9')) {
				sum |= (c1 - '0');
			} else if ((c1 >= 'a') && (c1 <= 'f')) {
				sum |= (c1 - 'a' + 10);
			} else if ((c1 >= 'A') && (c1 <= 'F')) {
				sum |= (c1 - 'A' + 10);
			} else {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_attach_debug_msg,
			    "Cfg err: Invalid rpwd found. %d %c",
			    j, c1);
				errors++;
			}

			*np++ = (uint8_t)sum;
			j++;

		} while (*s != ':' && *s != 0);

		break;

	case 0:	/* Ignore */
	case 3:	/* Ignore */
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_debug_msg,
		    "Cfg error: Invalid rpwd type found. type=%x",
		    auth_key->remote_password_type);

		errors++;
		goto out;
	}
	auth_key->remote_password_length = (uint16_t)j;

	if (errors) {
		goto out;
	}
	/* Verify values */
	if (auth_key->local_password_type == 0 ||
	    auth_key->local_password_type > 3 ||
	    auth_key->local_password_length == 0) {

		auth_key->local_password_type = 3;
		auth_key->local_password_length = 0;
		bzero(auth_key->local_password,
		    sizeof (auth_key->local_password));
	}
	if (auth_key->remote_password_type == 0 ||
	    auth_key->remote_password_type > 3 ||
	    auth_key->remote_password_length == 0) {

		auth_key->remote_password_type = 3;
		auth_key->remote_password_length = 0;
		bzero(auth_key->remote_password,
		    sizeof (auth_key->remote_password));
	}
	/* Display entry */
	emlxs_auth_key_print(hba, auth_key);

out:
	if (errors) {
		bzero(auth_key, sizeof (emlxs_auth_key_t));
		return (0);
	}
	return (1);

} /* emlxs_auth_key_parse() */


/* ************************** AUTH DFCLIB SUPPORT *********************** */

/* Provides DFC support for emlxs_dfc_init_auth() */
extern uint32_t
emlxs_dhc_init_auth(emlxs_hba_t *hba, uint8_t *lwwpn, uint8_t *rwwpn)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	NODELIST *ndlp;
	uint32_t vpi;
	char s_wwpn[64];

	/* Return is authentication is not enabled */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "dhc_init_auth. Auth disabled.");

		return (DFC_AUTH_AUTHENTICATION_DISABLED);
	}
	/* Scan for lwwpn match */
	for (vpi = 0; vpi < MAX_VPORTS; vpi++) {
		port = &VPORT(vpi);

		if (!(port->flag & EMLXS_PORT_BOUND)) {
			continue;
		}
		if (bcmp((uint8_t *)&port->wwpn, lwwpn, 8) == 0) {
			break;
		}
	}

	if (vpi == MAX_VPORTS) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg,
		    "dhc_init_auth: lwwpn not found. %s",
		    emlxs_wwn_xlate(s_wwpn, sizeof (s_wwpn), lwwpn));

		return (DFC_AUTH_WWN_NOT_FOUND);
	}
	if (bcmp(rwwpn, emlxs_fabric_wwn, 8) == 0) {
		/* Scan for fabric node */
		if ((ndlp = emlxs_node_find_did(port, FABRIC_DID, 1)) == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "dhc_init_auth: fabric node not found.");

			return (DFC_AUTH_WWN_NOT_FOUND);
		}
	} else {
		/* Scan for rwwpn match */
		if ((ndlp = emlxs_node_find_wwpn(port, rwwpn, 1)) == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "dhc_init_auth: rwwpn not found. %s",
			    emlxs_wwn_xlate(s_wwpn, sizeof (s_wwpn), rwwpn));

			return (DFC_AUTH_WWN_NOT_FOUND);
		}
	}

	if ((ndlp->nlp_DID != FABRIC_DID) &&
	    ((port->port_dhc.state != ELX_FABRIC_AUTH_SUCCESS))) {
		return (DFC_IO_ERROR);
	}
	if (ndlp->node_dhc.state >= NODE_STATE_AUTH_NEGOTIATE_ISSUE) {
		return (DFC_AUTH_AUTHENTICATION_GOINGON);
	}
	if (ndlp->node_dhc.state == NODE_STATE_AUTH_SUCCESS) {
		ndlp->node_dhc.nlp_reauth_status = NLP_HOST_REAUTH_IN_PROGRESS;
	}
	/* Attempt to start authentication */
	if (emlxs_dhc_auth_start(port, ndlp, NULL, NULL) != 0) {
		return (DFC_IO_ERROR);
	}
	return (0);

} /* emlxs_dhc_init_auth() */


/* Provides DFC support for emlxs_dfc_get_auth_cfg() */
extern uint32_t
emlxs_dhc_get_auth_cfg(emlxs_hba_t *hba, dfc_fcsp_config_t *fcsp_cfg)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	char s_lwwpn[64];
	char s_rwwpn[64];
	emlxs_auth_cfg_t *auth_cfg;
	uint32_t i;

	/* Return is authentication is not enabled */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "dhc_get_auth_cfg. Auth disabled.");

		return (DFC_AUTH_AUTHENTICATION_DISABLED);
	}
	mutex_enter(&hba->auth_lock);

	auth_cfg = emlxs_auth_cfg_get(hba,
	    (uint8_t *)&fcsp_cfg->lwwpn, (uint8_t *)&fcsp_cfg->rwwpn);

	if (!auth_cfg) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg,
		    "dhc_get_auth_cfg: entry not found. %s:%s",
		    emlxs_wwn_xlate(s_lwwpn, sizeof (s_lwwpn),
		    (uint8_t *)&fcsp_cfg->lwwpn),
		    emlxs_wwn_xlate(s_rwwpn, sizeof (s_rwwpn),
		    (uint8_t *)&fcsp_cfg->rwwpn));

		mutex_exit(&hba->auth_lock);

		return (DFC_AUTH_NOT_CONFIGURED);
	}
	fcsp_cfg->auth_tov = auth_cfg->authentication_timeout;
	fcsp_cfg->auth_mode = auth_cfg->authentication_mode;
	fcsp_cfg->auth_bidir = auth_cfg->bidirectional;

	for (i = 0; i < 4; i++) {
		fcsp_cfg->type_priority[i] =
		    auth_cfg->authentication_type_priority[i];
		fcsp_cfg->hash_priority[i] =
		    auth_cfg->hash_priority[i];
	}

	for (i = 0; i < 8; i++) {
		fcsp_cfg->group_priority[i] = auth_cfg->dh_group_priority[i];
	}

	fcsp_cfg->reauth_tov = auth_cfg->reauthenticate_time_interval;

	mutex_exit(&hba->auth_lock);

	return (0);

} /* emlxs_dhc_get_auth_cfg() */


/* Provides DFC support for emlxs_dfc_set_auth_cfg() */
extern uint32_t
emlxs_dhc_add_auth_cfg(
	emlxs_hba_t *hba,
	dfc_fcsp_config_t *fcsp_cfg,
	dfc_password_t *dfc_pwd)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	emlxs_auth_cfg_t *auth_cfg;
	emlxs_auth_key_t *auth_key;
	uint32_t i;
	NODELIST *ndlp;

	/* Return if authentication is not enabled */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "dhc_add_auth_cfg. Auth disabled.");

		return (DFC_AUTH_AUTHENTICATION_DISABLED);
	}
	mutex_enter(&hba->auth_lock);

	auth_key = emlxs_auth_key_get(hba,
	    (uint8_t *)&fcsp_cfg->lwwpn, (uint8_t *)&fcsp_cfg->rwwpn);

	if (auth_key &&
	    (auth_key->local_password_type == PASSWORD_TYPE_ASCII ||
	    auth_key->local_password_type == PASSWORD_TYPE_BINARY)) {

		/* Verify local password */
		if ((auth_key->local_password_length != dfc_pwd->length) ||
		    (auth_key->local_password_type != dfc_pwd->type) ||
		    bcmp(dfc_pwd->password, auth_key->local_password,
		    dfc_pwd->length)) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "dhc_add_auth_cfg: Invalid local password.");

			mutex_exit(&hba->auth_lock);

			return (DFC_AUTH_COMPARE_FAILED);
		}
	}
	/* Create entry */
	auth_cfg = emlxs_auth_cfg_create(hba,
	    (uint8_t *)&fcsp_cfg->lwwpn,
	    (uint8_t *)&fcsp_cfg->rwwpn);

	if (!auth_cfg) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg,
		    "dhc_add_auth_cfg: Out of memory.");

		mutex_exit(&hba->auth_lock);

		return (DFC_SYSRES_ERROR);
	}
	/* Init entry */
	auth_cfg->authentication_timeout = fcsp_cfg->auth_tov;
	auth_cfg->authentication_mode = fcsp_cfg->auth_mode;
	auth_cfg->bidirectional = fcsp_cfg->auth_bidir;

	for (i = 0; i < 4; i++) {
		auth_cfg->authentication_type_priority[i] =
		    fcsp_cfg->type_priority[i];
		auth_cfg->hash_priority[i] =
		    fcsp_cfg->hash_priority[i];
	}

	for (i = 0; i < 8; i++) {
		auth_cfg->dh_group_priority[i] = fcsp_cfg->group_priority[i];
	}

	auth_cfg->reauthenticate_time_interval = fcsp_cfg->reauth_tov;

	emlxs_auth_cfg_print(hba, auth_cfg);

	/* Cancel old reauth to restart the new one if necessary */

	/* Scan for lwwpn match */
	for (i = 0; i < MAX_VPORTS; i++) {
		port = &VPORT(i);

		if (!(port->flag & EMLXS_PORT_BOUND)) {
			continue;
		}
		if (bcmp((uint8_t *)&fcsp_cfg->lwwpn,
		    (uint8_t *)&port->wwpn, 8)) {
			continue;
		}
		/* Port match found */

		if (bcmp((uint8_t *)&fcsp_cfg->rwwpn,
		    emlxs_fabric_wwn, 8) == 0) {
			/* Scan for fabric node */
			if ((ndlp = emlxs_node_find_did(port,
			    FABRIC_DID, 1)) == NULL) {
				break;
			}
		} else {
			/* Scan for rwwpn match */
			if ((ndlp = emlxs_node_find_wwpn(port,
			    (uint8_t *)&fcsp_cfg->rwwpn, 1)) == NULL) {
				break;
			}
		}

		emlxs_dhc_set_reauth_time(port, ndlp, ENABLE);

		break;
	}

	mutex_exit(&hba->auth_lock);

	return (0);

} /* emlxs_dhc_add_auth_cfg() */


/* Provides DFC support for emlxs_dfc_set_auth_cfg() */
extern uint32_t
emlxs_dhc_delete_auth_cfg(
	emlxs_hba_t *hba,
	dfc_fcsp_config_t *fcsp_cfg,
	dfc_password_t *dfc_pwd)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	char s_lwwpn[64];
	char s_rwwpn[64];
	emlxs_auth_key_t *auth_key;
	emlxs_auth_cfg_t *auth_cfg;

	/* Return is authentication is not enabled */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "dhc_delete_auth_cfg. Auth disabled.");

		return (DFC_AUTH_AUTHENTICATION_DISABLED);
	}
	mutex_enter(&hba->auth_lock);

	auth_key = emlxs_auth_key_get(hba,
	    (uint8_t *)&fcsp_cfg->lwwpn,
	    (uint8_t *)&fcsp_cfg->rwwpn);

	if (auth_key &&
	    (auth_key->local_password_type == PASSWORD_TYPE_ASCII ||
	    auth_key->local_password_type ==
	    PASSWORD_TYPE_BINARY)) {
		/* Verify local password */
		if ((auth_key->local_password_length != dfc_pwd->length) ||
		    (auth_key->local_password_type != dfc_pwd->type) ||
		    bcmp(dfc_pwd->password,
		    auth_key->local_password,
		    dfc_pwd->length)) {

			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "dhc_delete_auth_cfg: Ivld local pwd.");

			mutex_exit(&hba->auth_lock);

			return (DFC_AUTH_COMPARE_FAILED);
		}
	}
	auth_cfg = emlxs_auth_cfg_get(hba,
	    (uint8_t *)&fcsp_cfg->lwwpn, (uint8_t *)&fcsp_cfg->rwwpn);

	if (!auth_cfg) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg,
		    "dhc_delete_auth_cfg: entry not found. %s:%s",
		    emlxs_wwn_xlate(s_lwwpn, sizeof (s_lwwpn),
		    (uint8_t *)&fcsp_cfg->lwwpn),
		    emlxs_wwn_xlate(s_rwwpn, sizeof (s_rwwpn),
		    (uint8_t *)&fcsp_cfg->rwwpn));

		mutex_exit(&hba->auth_lock);

		return (DFC_AUTH_WWN_NOT_FOUND);
	}
	/* Destroy cfg entry */
	emlxs_auth_cfg_destroy(hba, auth_cfg);

	/* Destroy pwd entry */
	emlxs_auth_key_destroy(hba, auth_key);

	mutex_exit(&hba->auth_lock);

	return (0);

} /* emlxs_dhc_delete_auth_cfg() */


/* Provides DFC support for emlxs_dfc_get_auth_key() */
extern uint32_t
emlxs_dhc_get_auth_key(emlxs_hba_t *hba, dfc_auth_password_t *dfc_auth_pwd)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	char s_lwwpn[64];
	char s_rwwpn[64];
	emlxs_auth_key_t *auth_key;

	/* Return is authentication is not enabled */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "dhc_get_auth_key. Auth disabled.");

		return (DFC_AUTH_AUTHENTICATION_DISABLED);
	}
	mutex_enter(&hba->auth_lock);

	auth_key = emlxs_auth_key_get(hba,
	    (uint8_t *)&dfc_auth_pwd->lwwpn,
	    (uint8_t *)&dfc_auth_pwd->rwwpn);

	if (!auth_key) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_dfc_error_msg,
		    "dhc_get_auth_key: entry not found. %s:%s",
		    emlxs_wwn_xlate(s_lwwpn, sizeof (s_lwwpn),
		    (uint8_t *)&dfc_auth_pwd->lwwpn),
		    emlxs_wwn_xlate(s_rwwpn, sizeof (s_rwwpn),
		    (uint8_t *)&dfc_auth_pwd->rwwpn));

		mutex_exit(&hba->auth_lock);

		return (DFC_AUTH_NOT_CONFIGURED);
	}
	dfc_auth_pwd->lpw.length = auth_key->local_password_length;
	dfc_auth_pwd->lpw.type = auth_key->local_password_type;
	/*
	 * bcopy(auth_key->local_password, dfc_auth_pwd->lpw.password,
	 * dfc_auth_pwd->lpw.length);
	 */

	dfc_auth_pwd->rpw.length = auth_key->remote_password_length;
	dfc_auth_pwd->rpw.type = auth_key->remote_password_type;
	/*
	 * bcopy(auth_key->remote_password, dfc_auth_pwd->rpw.password,
	 * dfc_auth_pwd->rpw.length);
	 */

	dfc_auth_pwd->lpw_new.length = auth_key->local_password_length;
	dfc_auth_pwd->lpw_new.type = auth_key->local_password_type;
	/*
	 * bcopy(auth_key->local_password, dfc_auth_pwd->lpw_new.password,
	 * dfc_auth_pwd->lpw_new.length);
	 */

	dfc_auth_pwd->rpw_new.length = auth_key->remote_password_length;
	dfc_auth_pwd->rpw_new.type = auth_key->remote_password_type;
	/*
	 * bcopy(auth_key->remote_password, dfc_auth_pwd->rpw_new.password,
	 * dfc_auth_pwd->rpw_new.length);
	 */

	mutex_exit(&hba->auth_lock);

	return (0);

} /* emlxs_dhc_get_auth_key() */


/* Provides DFC support for emlxs_dfc_set_auth_key() */
extern uint32_t
emlxs_dhc_set_auth_key(emlxs_hba_t *hba, dfc_auth_password_t *dfc_pwd)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	emlxs_auth_key_t *auth_key;
	uint32_t length;

	/* Return is authentication is not enabled */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "dhc_set_auth_key. Auth disabled.");

		return (DFC_AUTH_AUTHENTICATION_DISABLED);
	}

	/* Check to make sure localpwd does not equal to remotepwd */
	/* if they are given in the same time, if not, see below  */
	if ((dfc_pwd->lpw_new.type == PASSWORD_TYPE_ASCII ||
	    dfc_pwd->lpw_new.type == PASSWORD_TYPE_BINARY) &&
	    (dfc_pwd->rpw_new.type == PASSWORD_TYPE_ASCII ||
	    dfc_pwd->rpw_new.type == PASSWORD_TYPE_BINARY)) {
		if (bcmp(dfc_pwd->lpw_new.password,
		    dfc_pwd->rpw_new.password,
		    dfc_pwd->lpw_new.length) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_fcsp_debug_msg,
			    "dhc_set_auth_key. nlpwd==nrpwd");

			return (DFC_AUTH_LOCAL_REMOTE_PWD_EQUAL);
		}
	}

	mutex_enter(&hba->auth_lock);

	auth_key = emlxs_auth_key_get(hba,
	    (uint8_t *)&dfc_pwd->lwwpn,
	    (uint8_t *)&dfc_pwd->rwwpn);

	/* If entry does not exist, then create entry */
	if (!auth_key) {
		auth_key = emlxs_auth_key_create(hba,
		    (uint8_t *)&dfc_pwd->lwwpn,
		    (uint8_t *)&dfc_pwd->rwwpn);

		if (!auth_key) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "dhc_set_auth_key: Out of memory.");

			mutex_exit(&hba->auth_lock);

			return (DFC_SYSRES_ERROR);
		}
	}

	/* Check if a new local password is provided */
	if (dfc_pwd->lpw_new.type == PASSWORD_TYPE_ASCII ||
	    dfc_pwd->lpw_new.type == PASSWORD_TYPE_BINARY) {
		/* Check if current password should be checked */
		if (auth_key->local_password_type == PASSWORD_TYPE_ASCII ||
		    auth_key->local_password_type == PASSWORD_TYPE_BINARY) {
			/* Verify current local password */
			if ((auth_key->local_password_length !=
			    dfc_pwd->lpw.length) ||
			    (auth_key->local_password_type !=
			    dfc_pwd->lpw.type) ||
			    bcmp(dfc_pwd->lpw.password,
			    auth_key->local_password,
			    dfc_pwd->lpw.length)) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "dhc_set_auth_key: Invalid local password.");

				mutex_exit(&hba->auth_lock);

				return (DFC_AUTH_COMPARE_FAILED);
			}
		}

		/*
		 * Make sure the new local pwd is not equal to the current
		 * remote pwd if any
		 */
		if (auth_key->remote_password_type == PASSWORD_TYPE_ASCII ||
		    auth_key->remote_password_type == PASSWORD_TYPE_BINARY) {
			if ((auth_key->remote_password_length ==
			    dfc_pwd->lpw_new.length) &&
			    (bcmp(dfc_pwd->lpw_new.password,
			    auth_key->remote_password,
			    dfc_pwd->lpw_new.length) == 0)) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "dhc_set_auth_key: nlpwd==crpwd");

				mutex_exit(&hba->auth_lock);

				return (DFC_AUTH_LOCAL_REMOTE_PWD_EQUAL);
			}
		}
		/* Update local entry */
		auth_key->local_password_length = dfc_pwd->lpw_new.length;
		auth_key->local_password_type = dfc_pwd->lpw_new.type;
		bzero(auth_key->local_password,
		    sizeof (auth_key->local_password));
		length = min(dfc_pwd->lpw_new.length,
		    sizeof (auth_key->local_password));
		bcopy(dfc_pwd->lpw_new.password,
		    auth_key->local_password, length);
	}
	/* Check if a new remote password is provided */
	if (dfc_pwd->rpw_new.type == PASSWORD_TYPE_ASCII ||
	    dfc_pwd->rpw_new.type == PASSWORD_TYPE_BINARY) {
		/* Check if current password should be checked */
		if (auth_key->remote_password_type == PASSWORD_TYPE_ASCII ||
		    auth_key->remote_password_type == PASSWORD_TYPE_BINARY) {
			/* Verify current remote password */
			if ((auth_key->remote_password_length !=
			    dfc_pwd->rpw.length) ||
			    (auth_key->remote_password_type !=
			    dfc_pwd->rpw.type) ||
			    bcmp(dfc_pwd->rpw.password,
			    auth_key->remote_password,
			    dfc_pwd->rpw.length)) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "dhc_set_auth_key: Invalid remote password.");

				mutex_exit(&hba->auth_lock);

				return (DFC_AUTH_COMPARE_FAILED);
			}
		}

		/*
		 * Make sure the new remote pwd is not equal to the current
		 * local pwd if any
		 */
		if (auth_key->local_password_type == PASSWORD_TYPE_ASCII ||
		    auth_key->local_password_type == PASSWORD_TYPE_BINARY) {
			if ((auth_key->local_password_length ==
			    dfc_pwd->rpw_new.length) &&
			    (bcmp(dfc_pwd->rpw_new.password,
			    auth_key->local_password,
			    dfc_pwd->rpw_new.length) == 0)) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_dfc_error_msg,
			    "dhc_set_auth_key: nrpwd==clpwd");

				mutex_exit(&hba->auth_lock);

				return (DFC_AUTH_LOCAL_REMOTE_PWD_EQUAL);
			}
		}
		/* Update remote entry */
		auth_key->remote_password_length = dfc_pwd->rpw_new.length;
		auth_key->remote_password_type = dfc_pwd->rpw_new.type;
		bzero(auth_key->remote_password,
		    sizeof (auth_key->remote_password));
		length = min(dfc_pwd->rpw_new.length, 128);
		bcopy(dfc_pwd->rpw_new.password,
		    auth_key->remote_password, length);
	}
	/* Update dfc local entry */
	dfc_pwd->lpw.length = auth_key->local_password_length;
	dfc_pwd->lpw.type = auth_key->local_password_type;
	bzero(dfc_pwd->lpw.password, sizeof (dfc_pwd->lpw.password));
	length = min(auth_key->local_password_length,
	    sizeof (dfc_pwd->lpw.password));
	bcopy(auth_key->local_password, dfc_pwd->lpw.password, length);

	/* Update dfc remote entry */
	dfc_pwd->rpw.length = auth_key->remote_password_length;
	dfc_pwd->rpw.type = auth_key->remote_password_type;
	bzero(dfc_pwd->rpw.password, sizeof (dfc_pwd->rpw.password));
	length = min(auth_key->remote_password_length,
	    sizeof (dfc_pwd->rpw.password));
	bcopy(auth_key->remote_password, dfc_pwd->rpw.password, length);

	emlxs_auth_key_print(hba, auth_key);

	mutex_exit(&hba->auth_lock);

	return (0);

} /* emlxs_dhc_set_auth_key() */


/* Provides DFC support for emlxs_dfc_get_auth_status() */
extern uint32_t
emlxs_dhc_get_auth_status(emlxs_hba_t *hba, dfc_auth_status_t *fcsp_status)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	char s_lwwpn[64];
	char s_rwwpn[64];
	emlxs_auth_cfg_t *auth_cfg;
	dfc_auth_status_t *auth_status;
	NODELIST *ndlp;
	uint32_t rc;
	time_t auth_time;
	uint32_t update;

	/* Return is authentication is not enabled */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcsp_debug_msg,
		    "dhc_get_auth_status. Auth disabled.");

		return (DFC_AUTH_AUTHENTICATION_DISABLED);
	}
	mutex_enter(&hba->auth_lock);

	auth_cfg = emlxs_auth_cfg_get(hba, (uint8_t *)&fcsp_status->lwwpn,
	    (uint8_t *)&fcsp_status->rwwpn);

	if (!auth_cfg) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_dfc_error_msg,
		    "dhc_get_auth_status: entry not found. %s:%s",
		    emlxs_wwn_xlate(s_lwwpn, sizeof (s_lwwpn),
		    (uint8_t *)&fcsp_status->lwwpn),
		    emlxs_wwn_xlate(s_rwwpn, sizeof (s_rwwpn),
		    (uint8_t *)&fcsp_status->rwwpn));

		mutex_exit(&hba->auth_lock);

		return (DFC_AUTH_NOT_CONFIGURED);
	}
	if (bcmp((uint8_t *)&fcsp_status->rwwpn,
	    (uint8_t *)emlxs_fabric_wwn, 8) == 0) {
		auth_status = &port->port_dhc.auth_status;
		auth_time = port->port_dhc.auth_time;
		ndlp = emlxs_node_find_did(port, FABRIC_DID, 1);
	} else {
		auth_status = &auth_cfg->auth_status;
		auth_time = auth_cfg->auth_time;
		ndlp = auth_cfg->node;
	}

	update = 0;

	/* Check if node is still available */
	if (ndlp && ndlp->nlp_active) {
		emlxs_dhc_status(port, ndlp, 0, 0);
		update = 1;
	} else {
		rc = DFC_AUTH_WWN_NOT_FOUND;
	}


	if (update) {
		fcsp_status->auth_state = auth_status->auth_state;
		fcsp_status->auth_failReason = auth_status->auth_failReason;
		fcsp_status->type_priority = auth_status->type_priority;
		fcsp_status->group_priority = auth_status->group_priority;
		fcsp_status->hash_priority = auth_status->hash_priority;
		fcsp_status->localAuth = auth_status->localAuth;
		fcsp_status->remoteAuth = auth_status->remoteAuth;
		fcsp_status->time_from_last_auth = DRV_TIME - auth_time;
		fcsp_status->time_until_next_auth =
		    auth_status->time_until_next_auth;

		rc = 0;
	} else {
		rc = DFC_AUTH_WWN_NOT_FOUND;
	}

	mutex_exit(&hba->auth_lock);

	return (rc);

} /* emlxs_dhc_get_auth_status() */


/* Provides DFC support for emlxs_dfc_get_auth_list() */
/* auth_lock must be held when calling. */
/* fcsp_cfg must be large enough to hold hba->auth_cfg_count entries */
extern uint32_t
emlxs_dhc_get_auth_cfg_table(emlxs_hba_t *hba, dfc_fcsp_config_t *fcsp_cfg)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	emlxs_auth_cfg_t *auth_cfg;
	uint32_t i;

	/* Return if authentication is not enabled */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "dhc_get_auth_cfg_table. Auth disabled.");

		return (DFC_AUTH_AUTHENTICATION_DISABLED);
	}
	for (auth_cfg = hba->auth_cfg.next;
	    auth_cfg != &hba->auth_cfg;
	    auth_cfg = auth_cfg->next) {
		bcopy((uint8_t *)&auth_cfg->local_entity,
		    (uint8_t *)&fcsp_cfg->lwwpn, 8);
		bcopy((uint8_t *)&auth_cfg->remote_entity,
		    (uint8_t *)&fcsp_cfg->rwwpn, 8);

		fcsp_cfg->auth_tov = auth_cfg->authentication_timeout;
		fcsp_cfg->auth_mode = auth_cfg->authentication_mode;
		fcsp_cfg->auth_bidir = auth_cfg->bidirectional;

		for (i = 0; i < 4; i++) {
			fcsp_cfg->type_priority[i] =
			    auth_cfg->authentication_type_priority[i];
			fcsp_cfg->hash_priority[i] =
			    auth_cfg->hash_priority[i];
		}

		for (i = 0; i < 8; i++) {
			fcsp_cfg->group_priority[i] =
			    auth_cfg->dh_group_priority[i];
		}

		fcsp_cfg->reauth_tov = auth_cfg->reauthenticate_time_interval;

		fcsp_cfg++;
	}

	return (0);

} /* emlxs_dhc_get_auth_cfg_table() */



/* Provides DFC support for emlxs_dfc_get_auth_list() */
/* auth_lock must be held when calling. */
/* auth_pwd must be large enough to hold hba->auth_key_count entries */
extern uint32_t
emlxs_dhc_get_auth_key_table(emlxs_hba_t *hba, dfc_auth_password_t *auth_pwd)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	emlxs_auth_key_t *auth_key;

	/* Return if authentication is not enabled */
	if (cfg[CFG_AUTH_ENABLE].current == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcsp_debug_msg,
		    "dhc_get_auth_key_table. Auth disabled.");

		return (DFC_AUTH_AUTHENTICATION_DISABLED);
	}
	for (auth_key = hba->auth_key.next;
	    auth_key != &hba->auth_key;
	    auth_key = auth_key->next) {
		bcopy((uint8_t *)&auth_key->local_entity,
		    (uint8_t *)&auth_pwd->lwwpn, 8);
		bcopy((uint8_t *)&auth_key->remote_entity,
		    (uint8_t *)&auth_pwd->rwwpn, 8);

		auth_pwd->lpw.length = auth_key->local_password_length;
		auth_pwd->lpw.type = auth_key->local_password_type;
		/*
		 * bcopy(auth_key->local_password, auth_pwd->lpw.password,
		 * auth_pwd->lpw.length);
		 */

		auth_pwd->rpw.length = auth_key->remote_password_length;
		auth_pwd->rpw.type = auth_key->remote_password_type;
		/*
		 * bcopy(auth_key->remote_password, auth_pwd->rpw.password,
		 * auth_pwd->rpw.length);
		 */

		auth_pwd->lpw_new.length = auth_key->local_password_length;
		auth_pwd->lpw_new.type = auth_key->local_password_type;
		/*
		 * bcopy(auth_key->local_password,
		 * auth_pwd->lpw_new.password, auth_pwd->lpw_new.length);
		 */

		auth_pwd->rpw_new.length = auth_key->remote_password_length;
		auth_pwd->rpw_new.type = auth_key->remote_password_type;
		/*
		 * bcopy(auth_key->remote_password,
		 * auth_pwd->rpw_new.password, auth_pwd->rpw_new.length);
		 */

		auth_pwd++;
	}

	return (0);

} /* emlxs_dhc_get_auth_key_table() */

#endif	/* DHCHAP_SUPPORT */
