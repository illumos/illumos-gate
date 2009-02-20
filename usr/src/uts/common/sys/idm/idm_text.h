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
#ifndef _IDM_TEXT_H_
#define	_IDM_TEXT_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/idm/idm_impl.h>

/*
 * Numerical identifiers for iSCSI name-value pair keys (just so that
 * we can use case statements to handle a particular key-value pair
 * after we find it in idm_kvpair_xlate).
 *
 * We want to use a bitmask to keep track of negotiated key-value pairs
 * so keep this enum under 64 values -- or spend some time reworking the
 * login code.
 */
typedef enum {
	KI_AUTH_METHOD = 1,
	KI_KRB_AP_REQ,
	KI_KRB_AP_REP,

	/* SPKM */
	KI_SPKM_REQ,
	KI_SPKM_ERROR,
	KI_SPKM_REP_TI,
	KI_SPKM_REP_IT,

	/*
	 * SRP
	 */
	KI_SRP_U,
	KI_TARGET_AUTH,
	KI_SRP_GROUP,
	KI_SRP_A,
	KI_SRP_B,
	KI_SRP_M,
	KI_SRM_HM,

	/*
	 * CHAP
	 */
	KI_CHAP_A,
	KI_CHAP_I,
	KI_CHAP_C,
	KI_CHAP_N,
	KI_CHAP_R,


	/*
	 * ISCSI Operational Parameter Keys
	 */
	KI_HEADER_DIGEST,
	KI_DATA_DIGEST,
	KI_MAX_CONNECTIONS,
	KI_SEND_TARGETS,
	KI_TARGET_NAME,
	KI_INITIATOR_NAME,
	KI_TARGET_ALIAS,
	KI_INITIATOR_ALIAS,
	KI_TARGET_ADDRESS,
	KI_TARGET_PORTAL_GROUP_TAG,
	KI_INITIAL_R2T,
	KI_IMMEDIATE_DATA,
	KI_MAX_RECV_DATA_SEGMENT_LENGTH,
	KI_MAX_BURST_LENGTH,
	KI_FIRST_BURST_LENGTH,
	KI_DEFAULT_TIME_2_WAIT,
	KI_DEFAULT_TIME_2_RETAIN,
	KI_MAX_OUTSTANDING_R2T,
	KI_DATA_PDU_IN_ORDER,
	KI_DATA_SEQUENCE_IN_ORDER,
	KI_ERROR_RECOVERY_LEVEL,
	KI_SESSION_TYPE,
	KI_OFMARKER,
	KI_OFMARKERINT,
	KI_IFMARKER,
	KI_IFMARKERINT,

	/*
	 * iSER-specific keys
	 */
	KI_RDMA_EXTENSIONS,
	KI_TARGET_RECV_DATA_SEGMENT_LENGTH,
	KI_INITIATOR_RECV_DATA_SEGMENT_LENGTH,
	KI_MAX_OUTSTANDING_UNEXPECTED_PDUS,

	/*
	 * End of list marker, no keys below here.
	 */
	KI_MAX_KEY
} iscsikey_id_t;

/* Numerical types for iSCSI name-value pair values */
typedef enum {
	KT_TEXT,
	KT_ISCSI_NAME,
	KT_ISCSI_LOCAL_NAME,
	KT_BOOLEAN,
	KT_NUMERICAL, /* Hex or decimal constant */
	KT_LARGE_NUMERICAL, /* Hex, decimal or Base64 constant */
	KT_NUMERIC_RANGE,
	KT_REGULAR_BINARY, /* Hex, decimal, base64 not longer than 64 bits */
	KT_LARGE_BINARY, /* Hex, decimal, base64 longer than 64 bites */
	KT_BINARY,	/* Regular binary or large binary */
	KT_SIMPLE,
	KT_LIST_OF_VALUES
} idmkey_type_t;

typedef struct {
	iscsikey_id_t		ik_key_id;
	char			*ik_key_name;
	idmkey_type_t		ik_idm_type; /* RFC type */
	boolean_t		ik_declarative;
} idm_kv_xlate_t;

const idm_kv_xlate_t *
idm_lookup_kv_xlate(const char *key, int keylen);

int
idm_nvlist_add_keyvalue(nvlist_t *nvl, char *key, int keylen, char *value);

int
idm_textbuf_to_nvlist(nvlist_t *nvl, char **textbuf, int *textbuflen);

int
idm_textbuf_to_firstfraglen(void *textbuf, int textbuflen);

int
idm_nvlist_to_textbuf(nvlist_t *nvl, char **textbuf, int *textbuflen,
    int *tblen_required);

kv_status_t
idm_nvstat_to_kvstat(int nvrc);

void
idm_kvstat_to_error(kv_status_t kvrc, uint8_t *class, uint8_t *detail);

int
idm_nvlist_add_id(nvlist_t *nvl, iscsikey_id_t kv_id, char *value);

nvpair_t *
idm_get_next_listvalue(nvpair_t *value_list, nvpair_t *curr_nvp);

char *
idm_id_to_name(iscsikey_id_t kv_id);

char *
idm_nvpair_value_to_textbuf(nvpair_t *nvp);

idm_status_t
idm_pdu_list_to_nvlist(list_t *pdu_list, nvlist_t **nvlist,
    uint8_t *error_detail);

void *
idm_nvlist_to_itextbuf(nvlist_t *nvl);

char *
idm_pdu_init_text_data(idm_pdu_t *pdu, void *arg,
    int max_xfer_len, char *bufptr, int *transit);

void
idm_itextbuf_free(void *arg);

#ifdef	__cplusplus
}
#endif

#endif /* _IDM_TEXT_H_ */
