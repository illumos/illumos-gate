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

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/sysmacros.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/idm/idm.h>
#include <sys/idm/idm_text.h>

#include "iscsit.h"
#include "iscsit_auth.h"

static kv_status_t
iscsit_select_auth(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
auth_propose_chap(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
auth_chap_select_alg(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
auth_chap_recv_n(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
auth_chap_recv_r(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
auth_chap_recv_i(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
auth_chap_recv_c(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
iscsit_auth_propose(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
iscsit_auth_expect_key(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
auth_chap_expect_r(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
auth_chap_done(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
iscsit_auth_gen_challenge(iscsit_conn_t *ict);

static kv_status_t
iscsit_auth_gen_response(iscsit_conn_t *ict);

typedef struct {
	iscsit_auth_phase_t	phase;
	iscsikey_id_t		kv_id;
	iscsit_auth_handler_t	handler;
} auth_phase_entry_t;

/*
 * This table defines all authentication phases which have valid
 * handler. The entries which have a non-zero key index are for
 * a key/value pair handling when a key/value is being received,
 * the rest of entries are for target checking the authentication
 * phase after all key/value pair(s) are handled.
 */
static const auth_phase_entry_t	apet[] = {
	/* by key */
	{ AP_AM_UNDECIDED,	KI_AUTH_METHOD,	iscsit_select_auth },
	{ AP_AM_PROPOSED,	KI_CHAP_A,	auth_propose_chap  },

	{ AP_CHAP_A_WAITING,	KI_CHAP_A,	auth_chap_select_alg },
	{ AP_CHAP_R_WAITING,	KI_CHAP_N,	auth_chap_recv_n },
	{ AP_CHAP_R_WAITING,	KI_CHAP_R,	auth_chap_recv_r },
	{ AP_CHAP_R_WAITING,	KI_CHAP_I,	auth_chap_recv_i },
	{ AP_CHAP_R_WAITING,	KI_CHAP_C,	auth_chap_recv_c },
	{ AP_CHAP_R_RCVD,	KI_CHAP_N,	auth_chap_recv_n },
	{ AP_CHAP_R_RCVD,	KI_CHAP_R,	auth_chap_recv_r },
	{ AP_CHAP_R_RCVD,	KI_CHAP_I,	auth_chap_recv_i },
	{ AP_CHAP_R_RCVD,	KI_CHAP_C,	auth_chap_recv_c },

	/* by target */
	{ AP_AM_UNDECIDED,	0,		iscsit_auth_propose },
	{ AP_AM_DECIDED,	0,		iscsit_auth_expect_key },

	{ AP_CHAP_A_RCVD,	0,		auth_chap_expect_r },
	{ AP_CHAP_R_RCVD,	0,		auth_chap_done }
};

typedef struct {
	iscsit_auth_method_t	am_id;
	char			*am_name;
} auth_id_name_t;

/*
 * a table of mapping from the authentication index to name.
 */
static const auth_id_name_t aint[] = {
	{ AM_CHAP,	"CHAP" },
	{ AM_NONE,	"None" },
	/* { AM_KRB5,	"KRB5" }, */	/* Not supported */
	/* { AM_SPKM1,	"SPKM1" }, */	/* Not supported */
	/* { AM_SPKM2,	"SPKM2" }, */	/* Not supported */
	/* { AM_SRP,	"SRP" },  */	/* Not supported */
};

#define	ARRAY_LENGTH(ARRAY)	(sizeof (ARRAY) / sizeof (ARRAY[0]))

/*
 * get the authentication method name for the method id.
 */
static const char *
am_id_to_name(int id)
{
	int			i;
	const auth_id_name_t	*p;
	i = 0;
	while (i < ARRAY_LENGTH(aint)) {
		p = &(aint[i]);
		if (id == p->am_id) {
			return (p->am_name);
		}
		i ++;
	}

	return (NULL);
}

/*
 * Look for an apporiate function handler which is defined for
 * current authentication phase and matches the key which is
 * being handled. The key index is passed in as zero when it
 * is looking for an handler for checking the authentication phase
 * after all security keys are handled.
 */
iscsit_auth_handler_t
iscsit_auth_get_handler(iscsit_auth_client_t *client, iscsikey_id_t kv_id)
{
	iscsit_auth_phase_t		phase = client->phase;
	int				i;
	const auth_phase_entry_t	*p;

	i = 0;
	p = NULL;
	while (i < ARRAY_LENGTH(apet)) {
		p = &(apet[i]);
		if (phase == p->phase &&
		    kv_id == p->kv_id) {
			return (p->handler);
		}
		i ++;
	}

	/* No handler can be found, it must be an invalid requst. */
	return (NULL);
}

/*
 * Select an authentication method from a list of values proposed
 * by initiator. After a valid method is selected, shift the
 * authentication phase to AP_AM_DECIDED.
 */
static kv_status_t
iscsit_select_auth(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	conn_auth_t		*auth = &lsm->icl_auth;
	iscsit_auth_method_t	*am_list = &auth->ca_method_valid_list[0];
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;
	int			nvrc;
	kv_status_t		kvrc;
	nvpair_t		*am_choice;
	char			*am;
	const char		*am_name;
	const char		*text;
	iscsit_auth_method_t	am_id;
	int			i;

	client->phase = AP_AM_DECIDED;

	/* select a valid authentication method */
	am_choice = idm_get_next_listvalue(nvp, NULL);
	while (am_choice != NULL) {
		nvrc = nvpair_value_string(am_choice, &am);
		ASSERT(nvrc == 0);

		i = 0;
		am_id = am_list[i];
		while (am_id != 0) {
			am_name = am_id_to_name(am_id);
			if (strcasecmp(am, am_name) == 0) {
				text = am;
				goto am_decided;
			}
			i++;
			am_id = am_list[i];
		}
		am_choice = idm_get_next_listvalue(nvp, am_choice);
	}

	/* none of authentication method is valid */
	am_id = 0;
	text = ISCSI_TEXT_REJECT;

am_decided:
	client->negotiatedMethod = am_id;
	/* add the selected method to the response nvlist */
	nvrc = nvlist_add_string(lsm->icl_response_nvlist,
	    ikvx->ik_key_name, text);
	kvrc = idm_nvstat_to_kvstat(nvrc);

	return (kvrc);
}

/*
 * Initiator chooses to use CHAP after target proposed a list of
 * authentication method. Set the authentication method to CHAP and
 * continue on chap authentication phase.
 */
static kv_status_t
auth_propose_chap(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;

	client->negotiatedMethod = AM_CHAP;
	client->phase = AP_AM_DECIDED;

	return (auth_chap_select_alg(ict, nvp, ikvx));
}

/*
 * Select a CHAP algorithm from a list of values proposed by
 * initiator and shift the authentication phase to AP_CHAP_A_RCVD.
 */
static kv_status_t
auth_chap_select_alg(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;
	int			nvrc, rc;
	kv_status_t		kvrc;
	nvpair_t		*alg_choice;
	char			*alg_string;
	uint64_t		alg;
	const char		*text;

	client->phase = AP_CHAP_A_RCVD;

	alg_choice = idm_get_next_listvalue(nvp, NULL);
	while (alg_choice != NULL) {
		nvrc = nvpair_value_string(alg_choice, &alg_string);
		ASSERT(nvrc == 0);
		rc = ddi_strtoull(alg_string, NULL, 0, (u_longlong_t *)&alg);
		if (rc == 0 && alg == 5) {
			/* only MD5 is supported */
			text = alg_string;
			goto alg_selected;
		}

		alg_choice = idm_get_next_listvalue(nvp, alg_choice);
	}

	/* none of algorithm is selected */
	alg = 0;
	text = ISCSI_TEXT_REJECT;

alg_selected:
	/* save the selected algorithm or zero for none is selected */
	client_set_numeric_data(
	    &client->recvKeyBlock,
	    AKT_CHAP_A,
	    (uint32_t)alg);

	/* add the selected algorithm to the response nvlist */
	nvrc = nvlist_add_string(lsm->icl_response_nvlist,
	    ikvx->ik_key_name, text);
	if (alg == 0) {
		kvrc = KV_AUTH_FAILED; /* No algorithm selected */
	} else {
		kvrc = idm_nvstat_to_kvstat(nvrc);
		if (kvrc == 0) {
			kvrc = iscsit_auth_gen_challenge(ict);
		}
	}

	return (kvrc);
}

/*
 * Validate and save the the chap name which is sent by initiator
 * and shift the authentication phase to AP_CHAP_R_RCVD.
 *
 * Note: the CHAP_N, CHAP_R, optionally CHAP_I and CHAP_C key/value
 * pairs need to be received in one packet, we handle each of them
 * separately, in order to track the authentication phase, we set
 * the authentication phase to AP_CHAP_R_RCVD once one of them is
 * handled. So both of AP_CHAP_R_WAITING and AP_CHAP_R_RCVD phases
 * are valid for these keys. The function auth_chap_done is going
 * to detect if any of these keys is missing.
 */

/*ARGSUSED*/
static kv_status_t
auth_chap_recv_n(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;
	int			nvrc;
	char			*chap_name;

	nvrc = nvpair_value_string(nvp, &chap_name);
	ASSERT(nvrc == 0);

	client_set_string_data(&client->recvKeyBlock,
	    AKT_CHAP_N,
	    chap_name);

	client->phase = AP_CHAP_R_RCVD;

	return (KV_HANDLED);
}

/*
 * Validate and save the the chap response which is sent by initiator
 * and shift the authentication phase to AP_CHAP_R_RCVD.
 *
 * Note: see function auth_chap_recv_n.
 */

/*ARGSUSED*/
static kv_status_t
auth_chap_recv_r(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;
	int			nvrc;
	unsigned char		*chap_resp;
	uint_t			len;

	nvrc = nvpair_value_byte_array(nvp, &chap_resp, &len);
	ASSERT(nvrc == 0);

	client_set_binary_data(&client->recvKeyBlock,
	    AKT_CHAP_R,
	    chap_resp, len);

	client->phase = AP_CHAP_R_RCVD;

	return (KV_HANDLED);
}

/*
 * Validate and save the the chap identifier which is sent by initiator
 * and shift the authentication phase to AP_CHAP_R_RCVD.
 *
 * Note: see function auth_chap_recv_n.
 */

/*ARGSUSED*/
static kv_status_t
auth_chap_recv_i(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;
	int			nvrc;
	uint64_t		chap_id;

	nvrc = nvpair_value_uint64(nvp, &chap_id);
	ASSERT(nvrc == 0);

	client_set_numeric_data(&client->recvKeyBlock,
	    AKT_CHAP_I,
	    chap_id);

	client->phase = AP_CHAP_R_RCVD;

	return (KV_HANDLED);
}

/*
 * Validate and save the the chap challenge which is sent by initiator
 * and shift the authentication phase to AP_CHAP_R_RCVD.
 *
 * Note: see function auth_chap_recv_n.
 */

/*ARGSUSED*/
static kv_status_t
auth_chap_recv_c(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;
	int			nvrc;
	unsigned char		*chap_challenge;
	uint_t			len;

	nvrc = nvpair_value_byte_array(nvp, &chap_challenge, &len);
	ASSERT(nvrc == 0);

	client_set_binary_data(
	    &client->recvKeyBlock,
	    AKT_CHAP_C,
	    chap_challenge, len);

	client->phase = AP_CHAP_R_RCVD;

	return (KV_HANDLED);
}

/*
 * Shift the authentication phase to AP_CHAP_R_WAITING after target
 * has successfully selected a chap algorithm.
 */

/*ARGSUSED*/
static kv_status_t
auth_chap_expect_r(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;

	uint32_t		alg;

	client_get_numeric_data(&client->recvKeyBlock,
	    AKT_CHAP_A,
	    &alg);

	if (alg != 0) {
		client->phase = AP_CHAP_R_WAITING;
	} else {
		/* none of proposed algorithm is supported or understood. */
		client->phase = AP_CHAP_A_WAITING;
	}

	return (KV_HANDLED);
}

/*
 * Initiator does not propose security negotiation, target needs to
 * verify if we can bypass the security negotiation phase or propose
 * a security negotiation for the initiator.
 */

/*ARGSUSED*/
static kv_status_t
iscsit_auth_propose(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	conn_auth_t		*auth = &lsm->icl_auth;
	iscsit_auth_method_t	*am_list = &auth->ca_method_valid_list[0];
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;

	int			nvrc;
	kv_status_t		kvrc;
	const char		*am_name;

	if (am_list[0] == AM_NONE || am_list[0] == 0) {
		lsm->icl_auth_pass = 1;
	}

	if (lsm->icl_auth_pass == 0) {
		/*
		 * It should be noted that the negotiation might also
		 * be directed by the target if the initiator does
		 * support security, but is not ready to direct the
		 * negotiation (propose options).
		 * - RFC3720 section 5.3.2.
		 */
		am_name = am_id_to_name(am_list[0]);
		nvrc = nvlist_add_string(
		    lsm->icl_response_nvlist,
		    "AuthMethod", am_name);
		kvrc = idm_nvstat_to_kvstat(nvrc);

		client->phase = AP_AM_PROPOSED;
	} else {
		kvrc = KV_HANDLED;

		client->phase = AP_DONE;
	}

	return (kvrc);
}

/*
 * Shift the authentication phase according to the authentication
 * method once it is selected.
 */

/*ARGSUSED*/
static kv_status_t
iscsit_auth_expect_key(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;

	if (client->negotiatedMethod != 0) {
		/* Shift security negotiation phase. */
		switch (client->negotiatedMethod) {
		case AM_CHAP:
			client->phase = AP_CHAP_A_WAITING;
			break;
		case AM_NONE:
			client->phase = AP_DONE;
			lsm->icl_auth_pass = 1;
			break;
		default:
			ASSERT(0);
			break;
		}
	} else {
		/* None of proposed method is supported or understood. */
		client->phase = AP_AM_UNDECIDED;
	}

	return (KV_HANDLED);
}

/*
 * The last step of the chap authentication. We will validate the
 * chap parameters we received and authenticate the client here.
 */

/*ARGSUSED*/
static kv_status_t
auth_chap_done(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;
	kv_status_t		kvrc = KV_HANDLED;

	conn_auth_t		*auth = &lsm->icl_auth;
	char			*username_in;

	uint32_t		chap_id;
	unsigned char		*chap_challenge;
	unsigned int		challenge_len;
	char			*chap_name;
	unsigned char		*chap_resp;
	unsigned int		resp_len;

	int			bi_auth;

	username_in = auth->ca_ini_chapuser;
	if (username_in[0] == '\0')
		return (KV_AUTH_FAILED);

	/*
	 * Check if we have received a valid list of response keys.
	 */
	if (!client_auth_key_present(&client->recvKeyBlock, AKT_CHAP_N) ||
	    !client_auth_key_present(&client->recvKeyBlock, AKT_CHAP_R) ||
	    ((bi_auth =
	    client_auth_key_present(&client->recvKeyBlock, AKT_CHAP_I)) ^
	    client_auth_key_present(&client->recvKeyBlock, AKT_CHAP_C))) {
		return (KV_MISSING_FIELDS);
	}

	client->phase = AP_DONE;

	client_get_string_data(&client->recvKeyBlock,
	    AKT_CHAP_N,
	    &chap_name);

	/* check username */
	if (strcmp(username_in, chap_name) != 0) {
		return (KV_AUTH_FAILED);
	}

	client_get_numeric_data(&client->sendKeyBlock,
	    AKT_CHAP_I,
	    &chap_id);

	client_get_binary_data(&client->sendKeyBlock,
	    AKT_CHAP_C,
	    &chap_challenge, &challenge_len);

	client_get_binary_data(&client->recvKeyBlock,
	    AKT_CHAP_R,
	    &chap_resp, &resp_len);

	if (iscsit_verify_chap_resp(lsm,
	    chap_id, chap_challenge, challenge_len,
	    chap_resp, resp_len) != ISCSI_AUTH_PASSED) {
		return (KV_AUTH_FAILED);
	}

	/* bi-direction authentication is required */
	if (bi_auth != 0) {
		kvrc = iscsit_auth_gen_response(ict);
	}

	lsm->icl_auth_pass = 1;

	return (kvrc);
}

static kv_status_t
iscsit_auth_gen_challenge(iscsit_conn_t *ict)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;
	int			nvrc;
	kv_status_t		kvrc;

	unsigned char		idData[1];
	unsigned char		*bin;
	int			len;

	auth_random_set_data(idData, 1);
	client_set_numeric_data(&client->sendKeyBlock,
	    AKT_CHAP_I,
	    idData[0]);

	/* send chap identifier */
	nvrc = nvlist_add_uint64(
	    lsm->icl_response_nvlist,
	    "CHAP_I", idData[0]);
	kvrc = idm_nvstat_to_kvstat(nvrc);
	if (kvrc != 0) {
		return (kvrc);
	}

	bin = &(client->auth_send_binary_block.largeBinary[0]);
	len = iscsitAuthChapResponseLength;
	auth_random_set_data(bin, len);
	client_set_binary_data(&client->sendKeyBlock,
	    AKT_CHAP_C,
	    bin, len);

	/* send chap challenge */
	nvrc = nvlist_add_byte_array(
	    lsm->icl_response_nvlist,
	    "CHAP_C", bin, len);
	kvrc = idm_nvstat_to_kvstat(nvrc);

	return (kvrc);
}

static kv_status_t
iscsit_auth_gen_response(iscsit_conn_t *ict)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;
	int			nvrc;
	kv_status_t		kvrc;

	conn_auth_t		*auth = &lsm->icl_auth;
	char			*tgt_username;
	uint8_t			*tgt_password;
	int			tgt_password_length;

	uint32_t		chap_id;
	unsigned char		*chap_challenge;
	unsigned int		challenge_len;
	uchar_t			resp[iscsitAuthChapResponseLength];

	tgt_username = auth->ca_tgt_chapuser;
	tgt_password = auth->ca_tgt_chapsecret;
	tgt_password_length = auth->ca_tgt_chapsecretlen;

	/*
	 * We can't know in advance whether the initiator will attempt
	 * mutual authentication, so now we need to check whether we
	 * have a target CHAP secret configured.
	 */
	if (tgt_password_length == 0) {
		return (KV_AUTH_FAILED);
	}

	client_get_numeric_data(&client->recvKeyBlock,
	    AKT_CHAP_I,
	    &chap_id);

	client_get_binary_data(&client->recvKeyBlock,
	    AKT_CHAP_C,
	    &chap_challenge, &challenge_len);

	client_compute_chap_resp(
	    &resp[0],
	    chap_id,
	    tgt_password, tgt_password_length,
	    chap_challenge, challenge_len);

	nvrc = nvlist_add_string(
	    lsm->icl_response_nvlist,
	    "CHAP_N", tgt_username);

	if (nvrc == 0) {
		nvrc = nvlist_add_byte_array(
		    lsm->icl_response_nvlist,
		    "CHAP_R", resp, sizeof (resp));
	}
	kvrc = idm_nvstat_to_kvstat(nvrc);

	return (kvrc);
}
