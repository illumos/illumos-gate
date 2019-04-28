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

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>

#include <sys/iscsi_protocol.h>
#include <sys/idm/idm.h>
#include <sys/idm/idm_text.h>


extern int
iscsi_base64_str_to_binary(char *hstr, int hstr_len,
    uint8_t *binary, int binary_buf_len, int *out_len);


static const char idm_hex_to_ascii[] = "0123456789abcdefABCDEF";

static const idm_kv_xlate_t idm_kvpair_xlate[] = {
	/*
	 * iSCSI Security Text Keys and Authentication Methods
	 */

	{ KI_AUTH_METHOD, "AuthMethod", KT_LIST_OF_VALUES, B_FALSE },
	/*
	 * For values with RFC comments we need to read the RFC to see
	 * what type is appropriate.  For now just treat the value as
	 * text.
	 */

	/* Kerberos */
	{ KI_KRB_AP_REQ, "KRB_AP_REQ", KT_TEXT /* RFC1510 */, B_TRUE},
	{ KI_KRB_AP_REP, "KRB_AP_REP", KT_TEXT /* RFC1510 */, B_TRUE},

	/* SPKM */
	{ KI_SPKM_REQ, "SPKM_REQ", KT_TEXT /* RFC2025 */, B_TRUE},
	{ KI_SPKM_ERROR, "SPKM_ERROR", KT_TEXT /* RFC2025 */, B_TRUE},
	{ KI_SPKM_REP_TI, "SPKM_REP_TI", KT_TEXT /* RFC2025 */, B_TRUE},
	{ KI_SPKM_REP_IT, "SPKM_REP_IT", KT_TEXT /* RFC2025 */, B_TRUE},

	/*
	 * SRP
	 * U, s, A, B, M, and H(A | M | K) are defined in [RFC2945]
	 */
	{ KI_SRP_U, "SRP_U", KT_TEXT /* <U> */, B_TRUE},
	{ KI_TARGET_AUTH, "TargetAuth", KT_BOOLEAN, B_TRUE},
	{ KI_SRP_GROUP, "SRP_GROUP", KT_LIST_OF_VALUES /* <G1,..> */, B_FALSE},
	{ KI_SRP_A, "SRP_A", KT_TEXT /* <A> */, B_TRUE},
	{ KI_SRP_B, "SRP_B", KT_TEXT /* <B> */, B_TRUE},
	{ KI_SRP_M, "SRP_M", KT_TEXT /* <M> */, B_TRUE},
	{ KI_SRM_HM, "SRP_HM", KT_TEXT /* <H(A | M | K)> */, B_TRUE},

	/*
	 * CHAP
	 */
	{ KI_CHAP_A, "CHAP_A", KT_LIST_OF_VALUES /* <A1,A2,..> */, B_FALSE },
	{ KI_CHAP_I, "CHAP_I", KT_NUMERICAL /* <I> */, B_TRUE },
	{ KI_CHAP_C, "CHAP_C", KT_BINARY /* <C> */, B_TRUE },
	{ KI_CHAP_N, "CHAP_N", KT_TEXT /* <N> */, B_TRUE },
	{ KI_CHAP_R, "CHAP_R", KT_BINARY /* <N> */, B_TRUE },


	/*
	 * ISCSI Operational Parameter Keys
	 */
	{ KI_HEADER_DIGEST, "HeaderDigest", KT_LIST_OF_VALUES, B_FALSE },
	{ KI_DATA_DIGEST, "DataDigest", KT_LIST_OF_VALUES, B_FALSE },
	{ KI_MAX_CONNECTIONS, "MaxConnections", KT_NUMERICAL, B_FALSE },
	{ KI_SEND_TARGETS, "SendTargets", KT_TEXT, B_FALSE },
	{ KI_TARGET_NAME, "TargetName", KT_ISCSI_NAME, B_TRUE},
	{ KI_INITIATOR_NAME, "InitiatorName", KT_ISCSI_NAME, B_TRUE},
	{ KI_TARGET_ALIAS, "TargetAlias", KT_ISCSI_LOCAL_NAME, B_TRUE},
	{ KI_INITIATOR_ALIAS, "InitiatorAlias", KT_ISCSI_LOCAL_NAME, B_TRUE},
	{ KI_TARGET_ADDRESS, "TargetAddress", KT_TEXT, B_TRUE},
	{ KI_TARGET_PORTAL_GROUP_TAG, "TargetPortalGroupTag",
	    KT_NUMERICAL, B_TRUE },
	{ KI_INITIAL_R2T, "InitialR2T", KT_BOOLEAN, B_FALSE },
	{ KI_IMMEDIATE_DATA, "ImmediateData", KT_BOOLEAN, B_FALSE },
	{ KI_MAX_RECV_DATA_SEGMENT_LENGTH, "MaxRecvDataSegmentLength",
	    KT_NUMERICAL /* 512 to 2^24 - 1 */, B_TRUE },
	{ KI_MAX_BURST_LENGTH, "MaxBurstLength",
	    KT_NUMERICAL /* 512 to 2^24 - 1 */, B_FALSE },
	{ KI_FIRST_BURST_LENGTH, "FirstBurstLength",
	    KT_NUMERICAL /* 512 to 2^24 - 1 */, B_FALSE },
	{ KI_DEFAULT_TIME_2_WAIT, "DefaultTime2Wait",
	    KT_NUMERICAL /* 0 to 2600 */, B_FALSE },
	{ KI_DEFAULT_TIME_2_RETAIN, "DefaultTime2Retain",
	    KT_NUMERICAL /* 0 to 2600 */, B_FALSE },
	{ KI_MAX_OUTSTANDING_R2T, "MaxOutstandingR2T",
	    KT_NUMERICAL /* 1 to 65535 */, B_FALSE },
	{ KI_DATA_PDU_IN_ORDER, "DataPDUInOrder", KT_BOOLEAN, B_FALSE },
	{ KI_DATA_SEQUENCE_IN_ORDER, "DataSequenceInOrder",
	    KT_BOOLEAN, B_FALSE },
	{ KI_ERROR_RECOVERY_LEVEL, "ErrorRecoveryLevel",
	    KT_NUMERICAL /* 0 to 2 */, B_FALSE },
	{ KI_SESSION_TYPE, "SessionType", KT_TEXT, B_TRUE },
	{ KI_OFMARKER, "OFMarker", KT_BOOLEAN, B_FALSE },
	{ KI_OFMARKERINT, "OFMarkerInt", KT_NUMERIC_RANGE, B_FALSE },
	{ KI_IFMARKER, "IFMarker", KT_BOOLEAN, B_FALSE },
	{ KI_IFMARKERINT, "IFMarkerInt", KT_NUMERIC_RANGE, B_FALSE },

	/*
	 * iSER-specific keys
	 */
	{ KI_RDMA_EXTENSIONS, "RDMAExtensions", KT_BOOLEAN, B_FALSE },
	{ KI_TARGET_RECV_DATA_SEGMENT_LENGTH, "TargetRecvDataSegmentLength",
	    KT_NUMERICAL /* 512 to 2^24 - 1 */, B_FALSE },
	{ KI_INITIATOR_RECV_DATA_SEGMENT_LENGTH,
	    "InitiatorRecvDataSegmentLength",
	    KT_NUMERICAL /* 512 to 2^24 - 1 */, B_FALSE },
	{ KI_MAX_OUTSTANDING_UNEXPECTED_PDUS, "MaxOutstandingUnexpectedPDUs",
	    KT_NUMERICAL /* 2 to 2^32 - 1 | 0 */, B_TRUE },

	/*
	 * Table terminator. The type KT_TEXT will allow the response
	 * value of "NotUnderstood".
	 */
	{ KI_MAX_KEY, NULL, KT_TEXT, B_TRUE } /* Terminator */
};


#define	TEXTBUF_CHUNKSIZE 8192

typedef struct {
	char	*itb_mem;
	int	itb_offset;
	int	itb_mem_len;
} idm_textbuf_t;

/*
 * Ignore all but the following keys during security negotiation
 *
 * SessionType
 * InitiatorName
 * TargetName
 * TargetAddress
 * InitiatorAlias
 * TargetAlias
 * TargetPortalGroupTag
 * AuthMethod and associated auth keys
 */

static int idm_keyvalue_get_next(char **tb_scan, int *tb_len,
    char **key, int *keylen, char **value);

static int idm_nvlist_add_kv(nvlist_t *nvl, const idm_kv_xlate_t *ikvx,
    char *value);

static int idm_nvlist_add_string(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value);

static int idm_nvlist_add_boolean(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value);

static int idm_nvlist_add_binary(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value);

static int idm_nvlist_add_large_numerical(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value);

static int idm_nvlist_add_numerical(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value);

static int idm_nvlist_add_numeric_range(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value);

static int idm_nvlist_add_list_of_values(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value);

static int idm_itextbuf_add_nvpair(nvpair_t *nvp, idm_textbuf_t *itb);

static int idm_itextbuf_add_string(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb);

static int idm_itextbuf_add_boolean(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb);

static int idm_itextbuf_add_binary(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb);

static int idm_itextbuf_add_large_numerical(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb);

static int idm_itextbuf_add_numerical(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb);

static int idm_itextbuf_add_numeric_range(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb);

static int idm_itextbuf_add_list_of_values(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb);

static void textbuf_memcpy(idm_textbuf_t *itb, void *mem, int mem_len);

static void textbuf_strcpy(idm_textbuf_t *itb, char *str);

static void textbuf_append_char(idm_textbuf_t *itb, char c);

static void textbuf_terminate_kvpair(idm_textbuf_t *itb);

static int idm_ascii_to_hex(char *enc_hex_byte, uint8_t *bin_val);

static int idm_base16_str_to_binary(char *hstr, int hstr_len,
    uint8_t *binary, int binary_length);

static size_t idm_strcspn(const char *string, const char *charset);

static size_t idm_strnlen(const char *str, size_t maxlen);

/*
 * Processes all whole iSCSI name-value pairs in a text buffer and adds
 * a corresponding Solaris nvpair_t to the provided nvlist.  If the last
 * iSCSI name-value pair in textbuf is truncated (which can occur when
 * the request spans multiple PDU's) then upon return textbuf will
 * point to the truncated iSCSI name-value pair in the buffer and
 * textbuflen will contain the remaining bytes in the buffer.  The
 * caller can save off this fragment of the iSCSI name-value pair for
 * use when the next PDU in the request arrives.
 *
 * textbuflen includes the trailing 0x00!
 */

int
idm_textbuf_to_nvlist(nvlist_t *nvl, char **textbuf, int *textbuflen)
{
	int rc = 0;
	char *tbscan, *key, *value;
	int tblen, keylen;

	tbscan = *textbuf;
	tblen = *textbuflen;

	for (;;) {
		if ((rc = idm_keyvalue_get_next(&tbscan, &tblen,
		    &key, &keylen, &value)) != 0) {
			/* There was a problem reading the key/value pair */
			break;
		}

		if ((rc = idm_nvlist_add_keyvalue(nvl,
		    key, keylen, value)) != 0) {
			/* Something was wrong with either the key or value */
			break;
		}

		if (tblen == 0) {
			/* End of text buffer */
			break;
		}
	}

	*textbuf = tbscan;
	*textbuflen = tblen;

	return (rc);
}

/*
 * If a test buffer starts with an ISCSI name-value pair fragment (a
 * continuation from a previous buffer) return the length of the fragment
 * contained in this buffer.  We do not handle name-value pairs that span
 * more than two buffers so if this buffer does not contain the remainder
 * of the name value pair the function will return 0.  If the first
 * name-value pair in the buffer is complete the functionw will return 0.
 */
int
idm_textbuf_to_firstfraglen(void *textbuf, int textbuflen)
{
	return (idm_strnlen(textbuf, textbuflen));
}

static int
idm_keyvalue_get_next(char **tb_scan, int *tb_len,
    char **key, int *keylen, char **value)
{
	/*
	 * Caller doesn't need "valuelen" returned since "value" will
	 * always be a NULL-terminated string.
	 */
	size_t total_len, valuelen;

	/*
	 * How many bytes to the first '\0'?  This represents the total
	 * length of our iSCSI key/value pair.
	 */
	total_len = idm_strnlen(*tb_scan, *tb_len);
	if (total_len == *tb_len) {
		/*
		 * No '\0', perhaps this key/value pair is continued in
		 * another buffer
		 */
		return (E2BIG);
	}

	/*
	 * Found NULL, so this is a possible key-value pair.  At
	 * the same time we've validated that there is actually a
	 * NULL in this string so it's safe to use regular
	 * string functions (i.e. strcpy instead of strncpy)
	 */
	*key = *tb_scan;
	*keylen = idm_strcspn(*tb_scan, "=");

	if (*keylen == total_len) {
		/* No '=', bad format */
		return (EINVAL);
	}

	*tb_scan += *keylen + 1; /* Skip the '=' */
	*tb_len -= *keylen + 1;

	/*
	 * The remaining text after the '=' is the value
	 */
	*value = *tb_scan;
	valuelen = total_len - (*keylen + 1);

	*tb_scan += valuelen + 1; /* Skip the '\0' */
	*tb_len -= valuelen + 1;

	return (0);
}

const idm_kv_xlate_t *
idm_lookup_kv_xlate(const char *key, int keylen)
{
	const idm_kv_xlate_t *ikvx = &idm_kvpair_xlate[0];

	/*
	 * Look for a matching key value in the key/value pair table.
	 * The matching entry in the table will tell us how to encode
	 * the key and value in the nvlist.  If we don't recognize
	 * the key then we will simply encode it in string format.
	 * The login or text request code can generate the appropriate
	 * "not understood" resposne.
	 */
	while (ikvx->ik_key_id != KI_MAX_KEY) {
		/*
		 * Compare strings.  "key" is not NULL-terminated so
		 * use strncmp.  Since we are using strncmp we
		 * need to check that the lengths match, otherwise
		 * we might unintentionally lookup "TargetAddress"
		 * with a key of "Target" (or something similar).
		 *
		 * "value" is NULL-terminated so we can use it as
		 * a regular string.
		 */
		if ((strncmp(ikvx->ik_key_name, key, keylen) == 0) &&
		    (strlen(ikvx->ik_key_name) == keylen)) {
			/* Exit the loop since we found a match */
			break;
		}

		/* No match, look at the next entry */
		ikvx++;
	}

	return (ikvx);
}

static int
idm_nvlist_add_kv(nvlist_t *nvl,  const idm_kv_xlate_t *ikvx, char *value)
{
	int rc;

	switch (ikvx->ik_idm_type) {
	case KT_TEXT:
	case KT_SIMPLE:
	case KT_ISCSI_NAME:
	case KT_ISCSI_LOCAL_NAME:
		rc = idm_nvlist_add_string(nvl, ikvx, value);
		break;
	case KT_BOOLEAN:
		rc = idm_nvlist_add_boolean(nvl, ikvx, value);
		break;
	case KT_REGULAR_BINARY:
	case KT_LARGE_BINARY:
	case KT_BINARY:
		rc = idm_nvlist_add_binary(nvl, ikvx, value);
		break;
	case KT_LARGE_NUMERICAL:
		rc = idm_nvlist_add_large_numerical(nvl, ikvx,
		    value);
		break;
	case KT_NUMERICAL:
		rc = idm_nvlist_add_numerical(nvl, ikvx,
		    value);
		break;
	case KT_NUMERIC_RANGE:
		rc = idm_nvlist_add_numeric_range(nvl, ikvx,
		    value);
		break;
	case KT_LIST_OF_VALUES:
		rc = idm_nvlist_add_list_of_values(nvl, ikvx,
		    value);
		break;
	default:
		ASSERT(0); /* This should never happen */
		break;
	}
	if (rc != 0) {
		/* could be one of the text constants */
		rc = idm_nvlist_add_string(nvl, ikvx, value);
	}

	return (rc);
}

static int
idm_nvlist_add_string(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value)
{
	return (nvlist_add_string(nvl, ikvx->ik_key_name, value));
}

static int
idm_nvlist_add_boolean(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value)
{
	int rc;
	boolean_t bool_val;

	if (strcasecmp(value, "Yes") == 0) {
		bool_val = B_TRUE;
	} else if (strcasecmp(value, "No") == 0) {
		bool_val = B_FALSE;
	} else {
		return (EINVAL);
	}

	rc = nvlist_add_boolean_value(nvl, ikvx->ik_key_name, bool_val);

	return (rc);
}

static boolean_t
kv_is_hex(char *value)
{
	return ((strncmp(value, "0x", strlen("0x")) == 0) ||
	    (strncmp(value, "0X", strlen("0X")) == 0));
}

static boolean_t
kv_is_base64(char *value)
{
	return ((strncmp(value, "0b", strlen("0b")) == 0) ||
	    (strncmp(value, "0B", strlen("0B")) == 0));
}


static int
idm_nvlist_add_binary(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value)
{
	int		rc;
	int		value_length;
	uint64_t	uint64_value;
	int		binary_length;
	uchar_t		*binary_array;

	/*
	 * A binary value can be either decimal, hex or base64.  If it's
	 * decimal then the encoded string must be less than 64 bits in
	 * length (8 characters).  In all cases we will convert the
	 * included value to a byte array starting with the MSB.  The
	 * assumption is that values meant to be treated as integers will
	 * use the "numerical" and "large numerical" types.
	 */
	if (kv_is_hex(value)) {
		value += strlen("0x");
		value_length = strlen(value);
		binary_length = (value_length + 1) / 2;
		binary_array = kmem_alloc(binary_length, KM_SLEEP);

		if (idm_base16_str_to_binary(value, value_length,
		    binary_array, binary_length) != 0) {
			kmem_free(binary_array, binary_length);
			return (EINVAL);
		}

		rc = nvlist_add_byte_array(nvl, ikvx->ik_key_name,
		    binary_array, binary_length);

		kmem_free(binary_array, binary_length);

		return (rc);

	} else if (kv_is_base64(value)) {
		value += strlen("0b");
		value_length = strlen(value);
		binary_array = kmem_alloc(value_length, KM_NOSLEEP);
		if (binary_array == NULL) {
			return (ENOMEM);
		}

		if (iscsi_base64_str_to_binary(value, value_length,
		    binary_array, value_length, &binary_length) != 0) {
			kmem_free(binary_array, value_length);
			return (EINVAL);
		}

		rc = nvlist_add_byte_array(nvl, ikvx->ik_key_name,
		    binary_array, binary_length);

		kmem_free(binary_array, value_length);

		return (rc);
	} else {
		/*
		 * Decimal value (not permitted for "large-binary_value" so
		 * it must be smaller than 64 bits.  It's not really
		 * clear from the RFC what a decimal-binary-value might
		 * represent but presumably it should be treated the same
		 * as a hex or base64 value.  Therefore we'll convert it
		 * to an array of bytes.
		 */
		if ((rc = ddi_strtoull(value, NULL, 0,
		    (u_longlong_t *)&uint64_value)) != 0)
			return (rc);

		rc = nvlist_add_byte_array(nvl, ikvx->ik_key_name,
		    (uint8_t *)&uint64_value, sizeof (uint64_value));

		return (rc);
	}

	/* NOTREACHED */
}


static int
idm_nvlist_add_large_numerical(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value)
{
	/*
	 * A "large numerical" value can be larger than 64-bits.  Since
	 * there is no upper bound on the size of the value, we will
	 * punt and store it in string form.  We could also potentially
	 * treat the value as binary data.
	 */
	return (nvlist_add_string(nvl, ikvx->ik_key_name, value));
}


static int
idm_nvlist_add_numerical(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value)
{
	int rc;
	uint64_t uint64_value;

	/*
	 * "Numerical" values in the iSCSI standard are up to 64-bits wide.
	 * On a 32-bit system we could see an overflow here during conversion.
	 * This shouldn't happen with real-world values for the current
	 * iSCSI parameters of "numerical" type.
	 */
	rc = ddi_strtoull(value, NULL, 0, (u_longlong_t *)&uint64_value);
	if (rc == 0) {
		rc = nvlist_add_uint64(nvl, ikvx->ik_key_name, uint64_value);
	}

	return (rc);
}


static int
idm_nvlist_add_numeric_range(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *range)
{
	nvlist_t *range_nvl;
	char *val_scan = range;
	uint64_t start_val, end_val;
	int val_len, range_len;
	int rc;

	/* We'll store the range an an nvlist with two values */
	rc = nvlist_alloc(&range_nvl, NV_UNIQUE_NAME, KM_NOSLEEP);
	if (rc != 0) {
		return (rc);
	}

	/*
	 * We expect idm_keyvalue_get_next to ensure the string is
	 * terminated
	 */
	range_len = strlen(range);

	/*
	 * Find range separator
	 */
	val_len = idm_strcspn(val_scan, "~");

	if (val_len == range_len) {
		/* invalid range */
		nvlist_free(range_nvl);
		return (EINVAL);
	}

	/*
	 * Start value
	 */
	*(val_scan + val_len + 1) = '\0';
	rc = ddi_strtoull(val_scan, NULL, 0, (u_longlong_t *)&start_val);
	if (rc == 0) {
		rc = nvlist_add_uint64(range_nvl, "start", start_val);
	}
	if (rc != 0) {
		nvlist_free(range_nvl);
		return (rc);
	}

	/*
	 * End value
	 */
	val_scan += val_len + 1;
	rc = ddi_strtoull(val_scan, NULL, 0, (u_longlong_t *)&end_val);
	if (rc == 0) {
		rc = nvlist_add_uint64(range_nvl, "start", end_val);
	}
	if (rc != 0) {
		nvlist_free(range_nvl);
		return (rc);
	}

	/*
	 * Now add the "range" nvlist to the main nvlist
	 */
	rc = nvlist_add_nvlist(nvl, ikvx->ik_key_name, range_nvl);
	if (rc != 0) {
		nvlist_free(range_nvl);
		return (rc);
	}

	nvlist_free(range_nvl);
	return (0);
}


static int
idm_nvlist_add_list_of_values(nvlist_t *nvl,
    const idm_kv_xlate_t *ikvx, char *value_list)
{
	char value_name[8];
	nvlist_t *value_list_nvl;
	char *val_scan = value_list;
	int value_index = 0;
	int val_len, val_list_len;
	int rc;

	rc = nvlist_alloc(&value_list_nvl, NV_UNIQUE_NAME, KM_NOSLEEP);
	if (rc != 0) {
		return (rc);
	}

	/*
	 * We expect idm_keyvalue_get_next to ensure the string is
	 * terminated
	 */
	val_list_len = strlen(value_list);
	if (val_list_len == 0) {
		nvlist_free(value_list_nvl);
		return (EINVAL);
	}

	for (;;) {
		(void) snprintf(value_name, 8, "value%d", value_index);

		val_len = idm_strcspn(val_scan, ",");

		if (*(val_scan + val_len) != '\0') {
			*(val_scan + val_len) = '\0';
		}
		rc = nvlist_add_string(value_list_nvl, value_name, val_scan);
		if (rc != 0) {
			nvlist_free(value_list_nvl);
			return (rc);
		}

		/*
		 * Move to next value, see if we're at the end of the value
		 * list
		 */
		val_scan += val_len + 1;
		if (val_scan == value_list + val_list_len + 1) {
			break;
		}

		value_index++;
	}

	rc = nvlist_add_nvlist(nvl, ikvx->ik_key_name, value_list_nvl);
	if (rc != 0) {
		nvlist_free(value_list_nvl);
		return (rc);
	}

	nvlist_free(value_list_nvl);
	return (0);
}

/*
 * Convert an nvlist containing standard iSCSI key names and values into
 * a text buffer with properly formatted iSCSI key-value pairs ready to
 * transmit on the wire.  *textbuf should be NULL and will be set to point
 * the resulting text buffer.
 */

int
idm_nvlist_to_textbuf(nvlist_t *nvl, char **textbuf, int *textbuflen,
    int *validlen)
{
	int rc = 0;
	nvpair_t *nvp = NULL;
	idm_textbuf_t itb;

	bzero(&itb, sizeof (itb));

	for (;;) {
		nvp = nvlist_next_nvpair(nvl, nvp);

		if (nvp == NULL) {
			/* Last nvpair in nvlist, we're done */
			break;
		}

		if ((rc = idm_itextbuf_add_nvpair(nvp, &itb)) != 0) {
			/* There was a problem building the key/value pair */
			break;
		}
	}

	*textbuf = itb.itb_mem;
	*textbuflen = itb.itb_mem_len;
	*validlen = itb.itb_offset;

	return (rc);
}

static int
idm_itextbuf_add_nvpair(nvpair_t *nvp,
    idm_textbuf_t *itb)
{
	int rc = 0;
	char *key;
	const idm_kv_xlate_t *ikvx;

	key = nvpair_name(nvp);

	ikvx = idm_lookup_kv_xlate(key, strlen(key));

	/*
	 * Any key supplied by the initiator that is not in our table
	 * will be responded to with the string value "NotUnderstood".
	 * An example is a vendor specific key.
	 */
	ASSERT((ikvx->ik_key_id != KI_MAX_KEY) ||
	    (nvpair_type(nvp) == DATA_TYPE_STRING));

	/*
	 * Look for a matching key value in the key/value pair table.
	 * The matching entry in the table will tell us how to encode
	 * the key and value in the nvlist.
	 */
	switch (ikvx->ik_idm_type) {
	case KT_TEXT:
	case KT_SIMPLE:
	case KT_ISCSI_NAME:
	case KT_ISCSI_LOCAL_NAME:
		rc = idm_itextbuf_add_string(nvp, ikvx, itb);
		break;
	case KT_BOOLEAN:
		rc = idm_itextbuf_add_boolean(nvp, ikvx, itb);
		break;
	case KT_REGULAR_BINARY:
	case KT_LARGE_BINARY:
	case KT_BINARY:
		rc = idm_itextbuf_add_binary(nvp, ikvx, itb);
		break;
	case KT_LARGE_NUMERICAL:
		rc = idm_itextbuf_add_large_numerical(nvp, ikvx, itb);
		break;
	case KT_NUMERICAL:
		rc = idm_itextbuf_add_numerical(nvp, ikvx, itb);
		break;
	case KT_NUMERIC_RANGE:
		rc = idm_itextbuf_add_numeric_range(nvp, ikvx, itb);
		break;
	case KT_LIST_OF_VALUES:
		rc = idm_itextbuf_add_list_of_values(nvp, ikvx, itb);
		break;
	default:
		ASSERT(0); /* This should never happen */
		break;
	}

	return (rc);
}

/* ARGSUSED */
static int
idm_itextbuf_add_string(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb)
{
	char	*key_name;
	char	*value;
	int	rc;

	/* Start with the key name */
	key_name = nvpair_name(nvp);
	textbuf_strcpy(itb, key_name);

	/* Add separator */
	textbuf_append_char(itb, '=');

	/* Add value */
	rc = nvpair_value_string(nvp, &value);
	ASSERT(rc == 0);
	textbuf_strcpy(itb, value);

	/* Add trailing 0x00 */
	textbuf_terminate_kvpair(itb);

	return (0);
}


/* ARGSUSED */
static int
idm_itextbuf_add_boolean(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb)
{
	char		*key_name;
	boolean_t	value;
	int	rc;

	/* Start with the key name */
	key_name = nvpair_name(nvp);
	textbuf_strcpy(itb, key_name);

	/* Add separator */
	textbuf_append_char(itb, '=');

	/* Add value */
	rc = nvpair_value_boolean_value(nvp, &value);
	ASSERT(rc == 0);
	textbuf_strcpy(itb, value ? "Yes" : "No");

	/* Add trailing 0x00 */
	textbuf_terminate_kvpair(itb);

	return (0);
}

/* ARGSUSED */
static int
idm_itextbuf_add_binary(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb)
{
	char		*key_name;
	unsigned char	*value;
	unsigned int	len;
	unsigned long	n;
	int	rc;

	/* Start with the key name */
	key_name = nvpair_name(nvp);
	textbuf_strcpy(itb, key_name);

	/* Add separator */
	textbuf_append_char(itb, '=');

	/* Add value */
	rc = nvpair_value_byte_array(nvp, &value, &len);
	ASSERT(rc == 0);

	textbuf_strcpy(itb, "0x");

	while (len > 0) {
		n = *value++;
		len--;

		textbuf_append_char(itb, idm_hex_to_ascii[(n >> 4) & 0xf]);
		textbuf_append_char(itb, idm_hex_to_ascii[n & 0xf]);
	}

	/* Add trailing 0x00 */
	textbuf_terminate_kvpair(itb);

	return (0);
}

/* ARGSUSED */
static int
idm_itextbuf_add_large_numerical(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb)
{
	ASSERT(0);
	return (0);
}

/* ARGSUSED */
static int
idm_itextbuf_add_numerical(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb)
{
	char		*key_name;
	uint64_t	value;
	int	rc;
	char		str[16];

	/* Start with the key name */
	key_name = nvpair_name(nvp);
	textbuf_strcpy(itb, key_name);

	/* Add separator */
	textbuf_append_char(itb, '=');

	/* Add value */
	rc = nvpair_value_uint64(nvp, &value);
	ASSERT(rc == 0);
	(void) sprintf(str, "%llu", (u_longlong_t)value);
	textbuf_strcpy(itb, str);

	/* Add trailing 0x00 */
	textbuf_terminate_kvpair(itb);

	return (0);
}

/* ARGSUSED */
static int
idm_itextbuf_add_numeric_range(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb)
{
	ASSERT(0);
	return (0);
}

/* ARGSUSED */
static int
idm_itextbuf_add_list_of_values(nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx, idm_textbuf_t *itb)
{
	char		*key_name;
	nvpair_t	*vchoice = NULL;
	char		*vchoice_string = NULL;
	int		rc;

	/* Start with the key name */
	key_name = nvpair_name(nvp);
	textbuf_strcpy(itb, key_name);

	/* Add separator */
	textbuf_append_char(itb, '=');

	/* Add value choices */
	vchoice = idm_get_next_listvalue(nvp, NULL);
	while (vchoice != NULL) {
		rc = nvpair_value_string(vchoice, &vchoice_string);
		ASSERT(rc == 0);
		textbuf_strcpy(itb, vchoice_string);
		vchoice = idm_get_next_listvalue(nvp, vchoice);
		if (vchoice != NULL) {
			/* Add ',' between choices */
			textbuf_append_char(itb, ',');
		}
	}

	/* Add trailing 0x00 */
	textbuf_terminate_kvpair(itb);

	return (0);
}


static void
textbuf_makeroom(idm_textbuf_t *itb, int size)
{
	char	*new_mem;
	int	new_mem_len;

	if (itb->itb_mem == NULL) {
		itb->itb_mem_len = MAX(TEXTBUF_CHUNKSIZE, size);
		itb->itb_mem = kmem_alloc(itb->itb_mem_len, KM_SLEEP);
	} else if ((itb->itb_offset + size) > itb->itb_mem_len) {
		new_mem_len = itb->itb_mem_len + MAX(TEXTBUF_CHUNKSIZE, size);
		new_mem = kmem_alloc(new_mem_len, KM_SLEEP);
		bcopy(itb->itb_mem, new_mem, itb->itb_mem_len);
		kmem_free(itb->itb_mem, itb->itb_mem_len);
		itb->itb_mem = new_mem;
		itb->itb_mem_len = new_mem_len;
	}
}

static void
textbuf_memcpy(idm_textbuf_t *itb, void *mem, int mem_len)
{
	textbuf_makeroom(itb, mem_len);
	(void) memcpy(itb->itb_mem + itb->itb_offset, mem, mem_len);
	itb->itb_offset += mem_len;
}

static void
textbuf_strcpy(idm_textbuf_t *itb, char *str)
{
	textbuf_memcpy(itb, str, strlen(str));
}

static void
textbuf_append_char(idm_textbuf_t *itb, char c)
{
	textbuf_makeroom(itb, sizeof (char));
	*(itb->itb_mem + itb->itb_offset) = c;
	itb->itb_offset++;
}

static void
textbuf_terminate_kvpair(idm_textbuf_t *itb)
{
	textbuf_append_char(itb, '\0');
}

static int
idm_ascii_to_hex(char *enc_hex_byte, uint8_t *bin_val)
{
	uint8_t nibble1, nibble2;
	char enc_char = *enc_hex_byte;

	if (enc_char >= '0' && enc_char <= '9') {
		nibble1 = (enc_char - '0');
	} else if (enc_char >= 'A' && enc_char <= 'F') {
		nibble1 = (0xA + (enc_char - 'A'));
	} else if (enc_char >= 'a' && enc_char <= 'f') {
		nibble1 = (0xA + (enc_char - 'a'));
	} else {
		return (EINVAL);
	}

	enc_hex_byte++;
	enc_char = *enc_hex_byte;

	if (enc_char >= '0' && enc_char <= '9') {
		nibble2 = (enc_char - '0');
	} else if (enc_char >= 'A' && enc_char <= 'F') {
		nibble2 = (0xA + (enc_char - 'A'));
	} else if (enc_char >= 'a' && enc_char <= 'f') {
		nibble2 = (0xA + (enc_char - 'a'));
	} else {
		return (EINVAL);
	}

	*bin_val = (nibble1 << 4) | nibble2;

	return (0);
}


static int idm_base16_str_to_binary(char *hstr, int hstr_len,
    uint8_t *binary_array, int binary_length)
{
	char	tmpstr[2];
	uchar_t *binary_scan;

	binary_scan = binary_array;

	/*
	 * If the length of the encoded ascii hex value is a multiple
	 * of two then every two ascii characters correspond to a hex
	 * byte.  If the length of the value is not a multiple of two
	 * then the first character is the first hex byte and then for
	 * the remaining of the string every two ascii characters
	 * correspond to a hex byte
	 */
	if ((hstr_len % 2) != 0) {

		tmpstr[0] = '0';
		tmpstr[1] = *hstr;

		if (idm_ascii_to_hex(tmpstr, binary_scan) != 0) {
			return (EINVAL);
		}

		hstr++;
		binary_scan++;
	}

	while (binary_scan != binary_array + binary_length) {
		if (idm_ascii_to_hex(hstr, binary_scan) != 0) {
			return (EINVAL);
		}

		hstr += 2;
		binary_scan++;
	}

	return (0);
}

static size_t
idm_strnlen(const char *str, size_t maxlen)
{
	const char *ptr;

	ptr = memchr(str, 0, maxlen);
	if (ptr == NULL)
		return (maxlen);

	return ((uintptr_t)ptr - (uintptr_t)str);
}


size_t
idm_strcspn(const char *string, const char *charset)
{
	const char *p, *q;

	for (q = string; *q != '\0'; ++q) {
		for (p = charset; *p != '\0' && *p != *q; )
			p++;
		if (*p != '\0') {
			break;
		}
	}
	return ((uintptr_t)q - (uintptr_t)string);
}

/*
 * We allow a list of choices to be represented as a single nvpair
 * (list with one value choice), or as an nvlist with a single nvpair
 * (also a list with on value choice), or as an nvlist with multiple
 * nvpairs (a list with multiple value choices).  This function implements
 * the "get next" functionality regardless of the choice list structure.
 *
 * nvpair_t's that contain choices are always strings.
 */
nvpair_t *
idm_get_next_listvalue(nvpair_t *value_list, nvpair_t *curr_nvp)
{
	nvpair_t	*result;
	nvlist_t	*nvl;
	int		nvrc;
	data_type_t	nvp_type;

	nvp_type = nvpair_type(value_list);

	switch (nvp_type) {
	case DATA_TYPE_NVLIST:
		nvrc = nvpair_value_nvlist(value_list, &nvl);
		ASSERT(nvrc == 0);
		result = nvlist_next_nvpair(nvl, curr_nvp);
		break;
	case DATA_TYPE_STRING:
		/* Single choice */
		if (curr_nvp == NULL) {
			result = value_list;
		} else {
			result = NULL;
		}
		break;
	default:
		ASSERT(0); /* Malformed choice list */
		result = NULL;
		break;
	}

	return (result);
}

kv_status_t
idm_nvstat_to_kvstat(int nvrc)
{
	kv_status_t result;
	switch (nvrc) {
	case 0:
		result = KV_HANDLED;
		break;
	case ENOMEM:
		result = KV_NO_RESOURCES;
		break;
	case EINVAL:
		result = KV_VALUE_ERROR;
		break;
	case EFAULT:
	case ENOTSUP:
	default:
		result = KV_INTERNAL_ERROR;
		break;
	}

	return (result);
}

void
idm_kvstat_to_error(kv_status_t kvrc, uint8_t *class, uint8_t *detail)
{
	switch (kvrc) {
	case KV_HANDLED:
	case KV_HANDLED_NO_TRANSIT:
		*class = ISCSI_STATUS_CLASS_SUCCESS;
		*detail = ISCSI_LOGIN_STATUS_ACCEPT;
		break;
	case KV_UNHANDLED:
	case KV_TARGET_ONLY:
		/* protocol error */
		*class = ISCSI_STATUS_CLASS_INITIATOR_ERR;
		*detail = ISCSI_LOGIN_STATUS_INVALID_REQUEST;
		break;
	case KV_VALUE_ERROR:
		/* invalid value */
		*class = ISCSI_STATUS_CLASS_INITIATOR_ERR;
		*detail = ISCSI_LOGIN_STATUS_INIT_ERR;
		break;
	case KV_NO_RESOURCES:
		/* no memory */
		*class = ISCSI_STATUS_CLASS_TARGET_ERR;
		*detail = ISCSI_LOGIN_STATUS_NO_RESOURCES;
		break;
	case KV_MISSING_FIELDS:
		/* key/value pair(s) missing */
		*class = ISCSI_STATUS_CLASS_INITIATOR_ERR;
		*detail = ISCSI_LOGIN_STATUS_MISSING_FIELDS;
		break;
	case KV_AUTH_FAILED:
		/* authentication failed */
		*class = ISCSI_STATUS_CLASS_INITIATOR_ERR;
		*detail = ISCSI_LOGIN_STATUS_AUTH_FAILED;
		break;
	default:
		/* target error */
		*class = ISCSI_STATUS_CLASS_TARGET_ERR;
		*detail = ISCSI_LOGIN_STATUS_TARGET_ERROR;
		break;
	}
}

int
idm_nvlist_add_keyvalue(nvlist_t *nvl,
    char *key, int keylen, char *value)
{
	const idm_kv_xlate_t *ikvx;

	ikvx = idm_lookup_kv_xlate(key, keylen);

	if (ikvx->ik_key_id == KI_MAX_KEY) {
		char *nkey;
		int rc;
		size_t len;

		/*
		 * key is not a NULL terminated string, so create one
		 */
		len = (size_t)(keylen+1);
		nkey = kmem_zalloc(len, KM_SLEEP);
		(void) strncpy(nkey, key, len-1);
		rc = nvlist_add_string(nvl, nkey, value);
		kmem_free(nkey, len);
		return (rc);
	}

	return (idm_nvlist_add_kv(nvl, ikvx, value));
}

int
idm_nvlist_add_id(nvlist_t *nvl, iscsikey_id_t kv_id, char *value)
{
	int i;
	for (i = 0; i < KI_MAX_KEY; i++) {
		if (idm_kvpair_xlate[i].ik_key_id == kv_id) {
			return
			    (idm_nvlist_add_kv(nvl,
			    &idm_kvpair_xlate[i], value));
		}
	}
	return (EFAULT);
}

char *
idm_id_to_name(iscsikey_id_t kv_id)
{
	int i;
	for (i = 0; i < KI_MAX_KEY; i++) {
		if (idm_kvpair_xlate[i].ik_key_id == kv_id) {
			return (idm_kvpair_xlate[i].ik_key_name);
		}
	}
	return (NULL);
}

/*
 * return the value in a buffer that must be freed by the caller
 */
char *
idm_nvpair_value_to_textbuf(nvpair_t *nvp)
{
	int rv, len;
	idm_textbuf_t itb;
	char *str;

	bzero(&itb, sizeof (itb));
	rv = idm_itextbuf_add_nvpair(nvp, &itb);
	if (rv != 0)
		return (NULL);
	str = kmem_alloc(itb.itb_mem_len, KM_SLEEP);
	len = idm_strcspn(itb.itb_mem, "=");
	if (len > strlen(itb.itb_mem)) {
		kmem_free(itb.itb_mem, itb.itb_mem_len);
		return (NULL);
	}
	(void) strcpy(str, &itb.itb_mem[len+1]);
	/* free the allocation done in idm_textbuf_add_nvpair */
	kmem_free(itb.itb_mem, itb.itb_mem_len);
	return (str);
}

/*
 * build an iscsi text buffer - the memory gets freed in
 * idm_itextbuf_free
 */
void *
idm_nvlist_to_itextbuf(nvlist_t *nvl)
{
	idm_textbuf_t *itb;
	char		*textbuf;
	int		validlen, textbuflen;

	if (idm_nvlist_to_textbuf(nvl, &textbuf, &textbuflen,
	    &validlen) != IDM_STATUS_SUCCESS) {
		return (NULL);
	}
	itb = kmem_zalloc(sizeof (idm_textbuf_t), KM_SLEEP);
	ASSERT(itb != NULL);
	itb->itb_mem = textbuf;
	itb->itb_mem_len = textbuflen;
	itb->itb_offset = validlen;
	return ((void *)itb);
}

/*
 * Copy as much of the text buffer as will fit in the pdu.
 * The first call to this routine should send
 * a NULL bufptr. Subsequent calls send in the buffer returned.
 * Call this routine until the string returned is NULL
 */
char *
idm_pdu_init_text_data(idm_pdu_t *pdu, void *arg,
    int max_xfer_len, char *bufptr, int *transit)
{
	char		*start_ptr, *end_ptr, *ptr;
	idm_textbuf_t	*itb = arg;
	iscsi_hdr_t	*ihp = pdu->isp_hdr;
	int		send = 0;

	ASSERT(itb != NULL);
	ASSERT(pdu != NULL);
	ASSERT(transit != NULL);
	if (bufptr == NULL) {
		/* first call - check the length */
		if (itb->itb_offset <= max_xfer_len) {
			/*
			 * the entire text buffer fits in the pdu
			 */
			bcopy((uint8_t *)itb->itb_mem, pdu->isp_data,
			    (size_t)itb->itb_offset);
			pdu->isp_datalen = itb->itb_offset;
			ihp->flags &= ~ISCSI_FLAG_TEXT_CONTINUE;
			*transit = 1;
			return (NULL);
		}
		/* we have more data than will fit in one pdu */
		start_ptr = itb->itb_mem;
		end_ptr = &itb->itb_mem[max_xfer_len - 1];

	} else {
		uint_t len;

		len =  (uintptr_t)&itb->itb_mem[itb->itb_offset] -
		    (uintptr_t)bufptr;
		if (len <= max_xfer_len) {
			/*
			 * the remaining text fits in the pdu
			 */
			bcopy(bufptr, pdu->isp_data, (size_t)len);
			pdu->isp_datalen = len;
			ihp->flags &= ~ISCSI_FLAG_TEXT_CONTINUE;
			*transit = 1;
			return (NULL);
		}
		/* we still have more data then will fit in one pdu */
		start_ptr = bufptr;
		end_ptr = &bufptr[max_xfer_len - 1];
	}
	/* break after key, after =, after the value or after '\0' */
	ptr = end_ptr;
	if (end_ptr + 1 <= &itb->itb_mem[itb->itb_offset]) {
		/* if next char is an '=' or '\0' send it */
		if (*(end_ptr + 1) == '=' || *(end_ptr + 1) == '\0') {
			send = 1;
		}
	}
	if (!send) {
		while (*ptr != '\0' && *ptr != '=' && ptr != start_ptr) {
			ptr--;
		}
	}
	bcopy(start_ptr, pdu->isp_data,
	    ((uintptr_t)ptr - (uintptr_t)start_ptr) + 1);
	pdu->isp_datalen = ((uintptr_t)ptr - (uintptr_t)start_ptr) + 1;
	ihp->flags |= ISCSI_FLAG_TEXT_CONTINUE;
	*transit = 0;
	return (++ptr);
}

void
idm_itextbuf_free(void *arg)
{
	idm_textbuf_t	*itb = arg;
	ASSERT(itb != NULL);
	kmem_free(itb->itb_mem, itb->itb_mem_len);
	kmem_free(itb, sizeof (idm_textbuf_t));
}

/*
 * Allocate an nvlist and poputlate with key=value from the pdu list.
 * NOTE: caller must free the list
 */
idm_status_t
idm_pdu_list_to_nvlist(list_t *pdu_list, nvlist_t **nvlist,
    uint8_t *error_detail)
{
	idm_pdu_t		*pdu, *next_pdu;
	boolean_t		split_kv = B_FALSE;
	char			*textbuf, *leftover_textbuf = NULL;
	int			textbuflen, leftover_textbuflen = 0;
	char			*split_kvbuf;
	int			split_kvbuflen, cont_fraglen;
	iscsi_login_hdr_t	*lh;
	int			rc;
	int			ret = IDM_STATUS_SUCCESS;

	*error_detail = ISCSI_LOGIN_STATUS_ACCEPT;
	/* Allocate a new nvlist for request key/value pairs */
	rc = nvlist_alloc(nvlist, NV_UNIQUE_NAME,
	    KM_NOSLEEP);
	if (rc != 0) {
		*error_detail = ISCSI_LOGIN_STATUS_NO_RESOURCES;
		ret = IDM_STATUS_FAIL;
		goto cleanup;
	}

	/*
	 * A login request can be split across multiple PDU's.  The state
	 * machine has collected all the PDU's that make up this login request
	 * and assembled them on the "icl_pdu_list" queue.  Process each PDU
	 * and convert the text keywords to nvlist form.
	 */
	pdu = list_head(pdu_list);
	while (pdu != NULL) {
		next_pdu = list_next(pdu_list, pdu);

		lh = (iscsi_login_hdr_t *)pdu->isp_hdr;

		textbuf = (char *)pdu->isp_data;
		textbuflen = pdu->isp_datalen;
		if (textbuflen == 0) {
			/* This shouldn't really happen but it could.. */
			list_remove(pdu_list, pdu);
			idm_pdu_complete(pdu, IDM_STATUS_SUCCESS);
			pdu = next_pdu;
			continue;
		}

		/*
		 * If we encountered a split key-value pair on the last
		 * PDU then handle it now by grabbing the remainder of the
		 * key-value pair from the next PDU and splicing them
		 * together.  Obviously on the first PDU this will never
		 * happen.
		 */
		if (split_kv) {
			cont_fraglen = idm_textbuf_to_firstfraglen(textbuf,
			    textbuflen);
			if (cont_fraglen == pdu->isp_datalen) {
				/*
				 * This key-value pair spans more than two
				 * PDU's.  We don't handle this.
				 */
				*error_detail = ISCSI_LOGIN_STATUS_TARGET_ERROR;
				ret = IDM_STATUS_FAIL;
				goto cleanup;
			}

			split_kvbuflen = leftover_textbuflen + cont_fraglen;
			split_kvbuf = kmem_alloc(split_kvbuflen, KM_NOSLEEP);
			if (split_kvbuf == NULL) {
				*error_detail = ISCSI_LOGIN_STATUS_NO_RESOURCES;
				ret = IDM_STATUS_FAIL;
				goto cleanup;
			}

			bcopy(leftover_textbuf, split_kvbuf,
			    leftover_textbuflen);
			bcopy(textbuf,
			    (uint8_t *)split_kvbuf + leftover_textbuflen,
			    cont_fraglen);


			if (idm_textbuf_to_nvlist(*nvlist,
			    &split_kvbuf, &split_kvbuflen) != 0) {
				/*
				 * Need to handle E2BIG case, indicating that
				 * a key-value pair is split across multiple
				 * PDU's.
				 */
				kmem_free(split_kvbuf, split_kvbuflen);

				*error_detail = ISCSI_LOGIN_STATUS_TARGET_ERROR;
				ret = IDM_STATUS_FAIL;
				goto cleanup;
			}

			ASSERT(split_kvbuflen != 0);
			kmem_free(split_kvbuf, split_kvbuflen);

			/* Now handle the remainder of the PDU as normal */
			textbuf += (cont_fraglen + 1);
			textbuflen -= (cont_fraglen + 1);
		}

		/*
		 * Convert each key-value pair in the text buffer to nvlist
		 * format.  If the list has already been created the nvpair
		 * elements will be added on to the existing list.  Otherwise
		 * a new nvlist will be created.
		 */
		if (idm_textbuf_to_nvlist(*nvlist,
		    &textbuf, &textbuflen) != 0) {

			*error_detail = ISCSI_LOGIN_STATUS_TARGET_ERROR;
			ret = IDM_STATUS_FAIL;
			goto cleanup;
		}

		ASSERT(
		    ((lh->flags & ISCSI_FLAG_LOGIN_CONTINUE) &&
		    (next_pdu != NULL)) ||
		    (!(lh->flags & ISCSI_FLAG_LOGIN_CONTINUE) &&
		    (next_pdu == NULL)));

		if ((lh->flags & ISCSI_FLAG_LOGIN_CONTINUE) &
		    (textbuflen != 0)) {
			/*
			 * Key-value pair is split over two PDU's.  We
			 * assume it willl never be split over more than
			 * two PDU's.
			 */
			split_kv = B_TRUE;
			leftover_textbuf = textbuf;
			leftover_textbuflen = textbuflen;
		} else {
			split_kv = B_FALSE;
			if (textbuflen != 0) {
				/*
				 * Incomplete keyword but no additional
				 * PDU's.  This is a malformed login
				 * request.
				 */
				*error_detail =
				    ISCSI_LOGIN_STATUS_INVALID_REQUEST;
				ret = IDM_STATUS_FAIL;
				goto cleanup;
			}
		}

		list_remove(pdu_list, pdu);
		idm_pdu_complete(pdu, IDM_STATUS_SUCCESS);
		pdu = next_pdu;
	}

cleanup:

	/*
	 * Free any remaining PDUs on the list. This will only
	 * happen if there were errors encountered during
	 * processing of the textbuf.
	 */
	pdu = list_head(pdu_list);
	while (pdu != NULL) {
		next_pdu = list_next(pdu_list, pdu);
		list_remove(pdu_list, pdu);
		idm_pdu_complete(pdu, IDM_STATUS_SUCCESS);
		pdu = next_pdu;
	}

	/*
	 * If there were no errors, we have a complete nvlist representing
	 * all the iSCSI key-value pairs in the login request PDU's
	 * that make up this request.
	 */
	return (ret);
}
