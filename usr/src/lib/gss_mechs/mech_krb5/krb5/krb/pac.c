/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * lib/krb5/krb/pac.c
 *
 * Copyright 2008 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

#include "k5-int.h"
#include "k5-utf8.h"

/* draft-brezak-win2k-krb-authz-00 */

/*
 * A PAC consists of a sequence of PAC_INFO_BUFFERs, preceeded by
 * a PACTYPE header. Decoding the contents of the buffers is left
 * to the application (notwithstanding signature verification).
 */

/*
 * SUNW17PACresync
 * These should eventually go to k5-platform.h or equiv.
 */
static inline unsigned short
load_16_le (const void *cvp)
{
    const unsigned char *p = cvp;
#if defined(__GNUC__) && defined(K5_LE)
    return GET(16,p);
#elif defined(__GNUC__) && defined(K5_BE) && defined(SWAP16)
    return GETSWAPPED(16,p);
#else
    return (p[0] | (p[1] << 8));
#endif
}

static inline unsigned int
load_32_le (const void *cvp)
{
    const unsigned char *p = cvp;
#if defined(__GNUC__) && defined(K5_LE)
    return GET(32,p);
#elif defined(__GNUC__) && defined(K5_BE) && defined(SWAP32)
    return GETSWAPPED(32,p);
#else
    return (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
#endif
}
static inline UINT64_TYPE
load_64_le (const void *cvp)
{
    const unsigned char *p = cvp;
#if defined(__GNUC__) && defined(K5_LE)
    return GET(64,p);
#elif defined(__GNUC__) && defined(K5_BE) && defined(SWAP64)
    return GETSWAPPED(64,p);
#else
    return ((UINT64_TYPE)load_32_le(p+4) << 32) | load_32_le(p);
#endif
}

static inline void
store_16_le (unsigned int val, void *vp)
{
    unsigned char *p = vp;
#if defined(__GNUC__) && defined(K5_LE)
    PUT(16,p,val);
#elif defined(__GNUC__) && defined(K5_BE) && defined(SWAP16)
    PUTSWAPPED(16,p,val);
#else
    p[1] = (val >>  8) & 0xff;
    p[0] = (val      ) & 0xff;
#endif
}

static inline void
store_32_le (unsigned int val, void *vp)
{
    unsigned char *p = vp;
#if defined(__GNUC__) && defined(K5_LE)
    PUT(32,p,val);
#elif defined(__GNUC__) && defined(K5_BE) && defined(SWAP32)
    PUTSWAPPED(32,p,val);
#else
    p[3] = (val >> 24) & 0xff;
    p[2] = (val >> 16) & 0xff;
    p[1] = (val >>  8) & 0xff;
    p[0] = (val      ) & 0xff;
#endif
}
static inline void
store_64_le (UINT64_TYPE val, void *vp)
{
    unsigned char *p = vp;
#if defined(__GNUC__) && defined(K5_LE)
    PUT(64,p,val);
#elif defined(__GNUC__) && defined(K5_BE) && defined(SWAP64)
    PUTSWAPPED(64,p,val);
#else
    p[7] = (unsigned char)((val >> 56) & 0xff);
    p[6] = (unsigned char)((val >> 48) & 0xff);
    p[5] = (unsigned char)((val >> 40) & 0xff);
    p[4] = (unsigned char)((val >> 32) & 0xff);
    p[3] = (unsigned char)((val >> 24) & 0xff);
    p[2] = (unsigned char)((val >> 16) & 0xff);
    p[1] = (unsigned char)((val >>  8) & 0xff);
    p[0] = (unsigned char)((val      ) & 0xff);
#endif
}


typedef struct _PAC_INFO_BUFFER {
    krb5_ui_4 ulType;
    krb5_ui_4 cbBufferSize;
    krb5_ui_8 Offset;
} PAC_INFO_BUFFER;

#define PAC_INFO_BUFFER_LENGTH	16

/* ulType */
#define PAC_LOGON_INFO		1
#define PAC_SERVER_CHECKSUM	6
#define PAC_PRIVSVR_CHECKSUM	7
#define PAC_CLIENT_INFO		10

typedef struct _PACTYPE {
    krb5_ui_4 cBuffers;
    krb5_ui_4 Version;
    PAC_INFO_BUFFER Buffers[1];
} PACTYPE;

#define PAC_ALIGNMENT		    8
#define PACTYPE_LENGTH		    8U
#define PAC_SIGNATURE_DATA_LENGTH   4U
#define PAC_CLIENT_INFO_LENGTH	    10U

#define NT_TIME_EPOCH		    11644473600LL

struct krb5_pac_data {
    PACTYPE *pac;	/* PAC header + info buffer array */
    krb5_data data;	/* PAC data (including uninitialised header) */
};

static krb5_error_code
k5_pac_locate_buffer(krb5_context context,
		     const krb5_pac pac,
		     krb5_ui_4 type,
		     krb5_data *data);

/*
 * Add a buffer to the provided PAC and update header.
 */
static krb5_error_code
k5_pac_add_buffer(krb5_context context,
		  krb5_pac pac,
		  krb5_ui_4 type,
		  const krb5_data *data,
		  krb5_boolean zerofill,
		  krb5_data *out_data)
{
    PACTYPE *header;
    size_t header_len, i, pad = 0;
    char *pac_data;

    assert((data->data == NULL) == zerofill);

    /* Check there isn't already a buffer of this type */
    if (k5_pac_locate_buffer(context, pac, type, NULL) == 0) {
	/* Solaris Kerberos */
	krb5_set_error_message(context, EINVAL,
			    "Duplicate PAC buffer of type %d",
			    type);
	return EINVAL;
    }

    header = (PACTYPE *)realloc(pac->pac,
				sizeof(PACTYPE) +
				(pac->pac->cBuffers * sizeof(PAC_INFO_BUFFER)));
    if (header == NULL) {
	return ENOMEM;
    }
    pac->pac = header;

    header_len = PACTYPE_LENGTH + (pac->pac->cBuffers * PAC_INFO_BUFFER_LENGTH);

    if (data->length % PAC_ALIGNMENT)
	pad = PAC_ALIGNMENT - (data->length % PAC_ALIGNMENT);

    pac_data = realloc(pac->data.data,
		       pac->data.length + PAC_INFO_BUFFER_LENGTH + data->length + pad);
    if (pac_data == NULL) {
	return ENOMEM;
    }
    pac->data.data = pac_data;

    /* Update offsets of existing buffers */
    for (i = 0; i < pac->pac->cBuffers; i++)
	pac->pac->Buffers[i].Offset += PAC_INFO_BUFFER_LENGTH;

    /* Make room for new PAC_INFO_BUFFER */
    memmove(pac->data.data + header_len + PAC_INFO_BUFFER_LENGTH,
	    pac->data.data + header_len,
	    pac->data.length - header_len);
    memset(pac->data.data + header_len, 0, PAC_INFO_BUFFER_LENGTH);

    /* Initialise new PAC_INFO_BUFFER */
    pac->pac->Buffers[i].ulType = type;
    pac->pac->Buffers[i].cbBufferSize = data->length;
    pac->pac->Buffers[i].Offset = pac->data.length + PAC_INFO_BUFFER_LENGTH;
    assert((pac->pac->Buffers[i].Offset % PAC_ALIGNMENT) == 0);

    /* Copy in new PAC data and zero padding bytes */
    if (zerofill)
	memset(pac->data.data + pac->pac->Buffers[i].Offset, 0, data->length);
    else
	memcpy(pac->data.data + pac->pac->Buffers[i].Offset, data->data, data->length);

    memset(pac->data.data + pac->pac->Buffers[i].Offset + data->length, 0, pad);

    pac->pac->cBuffers++;
    pac->data.length += PAC_INFO_BUFFER_LENGTH + data->length + pad;

    if (out_data != NULL) {
	out_data->data = pac->data.data + pac->pac->Buffers[i].Offset;
	out_data->length = data->length;
    }

    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_pac_add_buffer(krb5_context context,
		    krb5_pac pac,
		    krb5_ui_4 type,
		    const krb5_data *data)
{
    return k5_pac_add_buffer(context, pac, type, data, FALSE, NULL);
}

/*
 * Free a PAC
 */
void KRB5_CALLCONV
krb5_pac_free(krb5_context context,
	      krb5_pac pac)
{
    if (pac != NULL) {
	if (pac->data.data != NULL) {
	    memset(pac->data.data, 0, pac->data.length);
	    free(pac->data.data);
	}
	if (pac->pac != NULL)
	    free(pac->pac);
	memset(pac, 0, sizeof(*pac));
	free(pac);
    }
}

static krb5_error_code
k5_pac_locate_buffer(krb5_context context,
		     const krb5_pac pac,
		     krb5_ui_4 type,
		     krb5_data *data)
{
    PAC_INFO_BUFFER *buffer = NULL;
    size_t i;

    if (pac == NULL) {
	/* Solaris Kerberos */
	krb5_set_error_message(context, EINVAL,
			    "Invalid argument 'pac' is NULL");
	return EINVAL;
    }

    for (i = 0; i < pac->pac->cBuffers; i++) {
	if (pac->pac->Buffers[i].ulType == type) {
	    if (buffer == NULL)
		buffer = &pac->pac->Buffers[i];
	    else {
	        /* Solaris Kerberos */
	        krb5_set_error_message(context, EINVAL,
				    "Invalid buffer found looping thru PAC buffers (type=%d, i=%d)",
				    type, i);
		return EINVAL;
	    }
	}
    }

    if (buffer == NULL) {
	/* Solaris Kerberos */
	krb5_set_error_message(context, ENOENT,
			    "No PAC buffer found (type=%d)",
			    type);

	return ENOENT;
    }

    assert(buffer->Offset + buffer->cbBufferSize <= pac->data.length);

    if (data != NULL) {
	data->length = buffer->cbBufferSize;
	data->data = pac->data.data + buffer->Offset;
    }

    return 0;
}

/*
 * Find a buffer and copy data into output
 */
krb5_error_code KRB5_CALLCONV
krb5_pac_get_buffer(krb5_context context,
		    krb5_pac pac,
		    krb5_ui_4 type,
		    krb5_data *data)
{
    krb5_data d;
    krb5_error_code ret;

    ret = k5_pac_locate_buffer(context, pac, type, &d);
    if (ret != 0)
	return ret;

    data->data = malloc(d.length);
    if (data->data == NULL)
	return ENOMEM;

    data->length = d.length;
    memcpy(data->data, d.data, d.length);

    return 0;
}

/*
 * Return an array of the types of data in the PAC
 */
krb5_error_code KRB5_CALLCONV
krb5_pac_get_types(krb5_context context,
		   krb5_pac pac,
		   size_t *len,
		   krb5_ui_4 **types)
{
    size_t i;

    *types = (krb5_ui_4 *)malloc(pac->pac->cBuffers * sizeof(krb5_ui_4));
    if (*types == NULL)
	return ENOMEM;

    *len = pac->pac->cBuffers;

    for (i = 0; i < pac->pac->cBuffers; i++)
	(*types)[i] = pac->pac->Buffers[i].ulType;

    return 0;
}

/*
 * Initialize PAC
 */
krb5_error_code KRB5_CALLCONV
krb5_pac_init(krb5_context context,
	      krb5_pac *ppac)
{
    krb5_pac pac;

    pac = (krb5_pac)malloc(sizeof(*pac));
    if (pac == NULL)
	return ENOMEM;

    pac->pac = (PACTYPE *)malloc(sizeof(PACTYPE));
    if (pac->pac == NULL) {
	free( pac);
	return ENOMEM;
    }

    pac->pac->cBuffers = 0;
    pac->pac->Version = 0;

    pac->data.length = PACTYPE_LENGTH;
    pac->data.data = calloc(1, pac->data.length);
    if (pac->data.data == NULL) {
	krb5_pac_free(context, pac);
	return ENOMEM;
    }

    *ppac = pac;

    return 0;
}

/*
 * Parse the supplied data into the PAC allocated by this function
 */
krb5_error_code KRB5_CALLCONV
krb5_pac_parse(krb5_context context,
	       const void *ptr,
	       size_t len,
	       krb5_pac *ppac)
{
    krb5_error_code ret;
    size_t i;
    const unsigned char *p = (const unsigned char *)ptr;
    krb5_pac pac;
    size_t header_len;
    krb5_ui_4 cbuffers, version;

    *ppac = NULL;

    if (len < PACTYPE_LENGTH) {
	/* Solaris Kerberos */
	krb5_set_error_message(context, ERANGE,
			    "PAC type length is out of range (len=%d)",
			    len);
	return ERANGE;
    }

    cbuffers = load_32_le(p);
    p += 4;
    version = load_32_le(p);
    p += 4;

    if (version != 0) {
	/* Solaris Kerberos */
	krb5_set_error_message(context, EINVAL,
			    "Invalid PAC version is %d, should be 0",
			    version);
	return EINVAL;
    }

    header_len = PACTYPE_LENGTH + (cbuffers * PAC_INFO_BUFFER_LENGTH);
    if (len < header_len) {
	/* Solaris Kerberos */
	krb5_set_error_message(context, ERANGE,
			    "PAC header len (%d) out of range",
			    len);
	return ERANGE;
    }

    ret = krb5_pac_init(context, &pac);
    if (ret != 0)
	return ret;

    pac->pac = (PACTYPE *)realloc(pac->pac,
	sizeof(PACTYPE) + ((cbuffers - 1) * sizeof(PAC_INFO_BUFFER)));
    if (pac->pac == NULL) {
	krb5_pac_free(context, pac);
	return ENOMEM;
    }

    pac->pac->cBuffers = cbuffers;
    pac->pac->Version = version;

    for (i = 0; i < pac->pac->cBuffers; i++) {
	PAC_INFO_BUFFER *buffer = &pac->pac->Buffers[i];

	buffer->ulType = load_32_le(p);
	p += 4;
	buffer->cbBufferSize = load_32_le(p);
	p += 4;
	buffer->Offset = load_64_le(p);
	p += 8;

	if (buffer->Offset % PAC_ALIGNMENT) {
	    krb5_pac_free(context, pac);
	    /* Solaris Kerberos */
	    krb5_set_error_message(context, EINVAL,
				"PAC buffer offset mis-aligned");
	    return EINVAL;
	}
	if (buffer->Offset < header_len ||
	    buffer->Offset + buffer->cbBufferSize > len) {
	    krb5_pac_free(context, pac);
	    /* Solaris Kerberos */
	    krb5_set_error_message(context, ERANGE,
				"PAC offset is out of range");
	    return ERANGE;
	}
    }

    pac->data.data = realloc(pac->data.data, len);
    if (pac->data.data == NULL) {
	krb5_pac_free(context, pac);
	return ENOMEM;
    }
    memcpy(pac->data.data, ptr, len);

    pac->data.length = len;

    *ppac = pac;

    return 0;
}

static krb5_error_code
k5_time_to_seconds_since_1970(krb5_context context, krb5_int64 ntTime, krb5_timestamp *elapsedSeconds)
{
    krb5_ui_8 abstime;

    ntTime /= 10000000;

    abstime = ntTime > 0 ? ntTime - NT_TIME_EPOCH : -ntTime;

    if (abstime > KRB5_INT32_MAX) {
	return ERANGE;
    }

    *elapsedSeconds = abstime;

    return 0;
}

static krb5_error_code
k5_seconds_since_1970_to_time(krb5_timestamp elapsedSeconds, krb5_ui_8 *ntTime)
{
    *ntTime = elapsedSeconds;

    if (elapsedSeconds > 0)
	*ntTime += NT_TIME_EPOCH;

    *ntTime *= 10000000;

    return 0;
}

static krb5_error_code
k5_pac_validate_client(krb5_context context,
		       const krb5_pac pac,
		       krb5_timestamp authtime,
		       krb5_const_principal principal)
{
    krb5_error_code ret;
    krb5_data client_info;
    char *pac_princname;
    unsigned char *p;
    krb5_timestamp pac_authtime;
    krb5_ui_2 pac_princname_length;
    krb5_int64 pac_nt_authtime;
    krb5_principal pac_principal;

    ret = k5_pac_locate_buffer(context, pac, PAC_CLIENT_INFO, &client_info);
    if (ret != 0)
	return ret;

    if (client_info.length < PAC_CLIENT_INFO_LENGTH) {
	/* Solaris Kerberos */
	krb5_set_error_message(context, ERANGE,
			    "PAC client info length out of range",
			    client_info.length);
	return ERANGE;
    }

    p = (unsigned char *)client_info.data;
    pac_nt_authtime = load_64_le(p);
    p += 8;
    pac_princname_length = load_16_le(p);
    p += 2;

    ret = k5_time_to_seconds_since_1970(context, pac_nt_authtime, &pac_authtime);
    if (ret != 0)
	return ret;

    if (client_info.length < PAC_CLIENT_INFO_LENGTH + pac_princname_length ||
        pac_princname_length % 2) {
	/* Solaris Kerberos */
	krb5_set_error_message(context, ERANGE,
			    "PAC client info length is out of range");
	return ERANGE;
    }

    ret = krb5int_ucs2lecs_to_utf8s(p, (size_t)pac_princname_length / 2, &pac_princname, NULL);
    if (ret != 0)
	return ret;

    ret = krb5_parse_name_flags(context, pac_princname, 0, &pac_principal);
    if (ret != 0) {
	free(pac_princname);
	return ret;
    }


    if (pac_authtime != authtime) {
	/* Solaris Kerberos */
	char timestring[17];
	char pac_timestring[17];
	char fill = ' ';
	int err, pac_err;
	/* Need better ret code here but don't see one */
	ret = KRB5KRB_AP_WRONG_PRINC;
	err = krb5_timestamp_to_sfstring(pac_authtime,
					timestring,
					sizeof (timestring), &fill);
	pac_err = krb5_timestamp_to_sfstring(pac_authtime,
					pac_timestring,
					    sizeof (pac_timestring), &fill);
	if (pac_princname && !err && !pac_err) {
	    krb5_set_error_message(context, ret,
				"PAC verify fail: PAC authtime '%s' does not match authtime '%s'.  PAC principal is '%s'",
				pac_timestring, timestring, pac_princname);
	}
    } else if (krb5_principal_compare(context, pac_principal, principal) == FALSE) {
	/* Solaris Kerberos */
	char *p_name = NULL;
	krb5_error_code perr;
	ret = KRB5KRB_AP_WRONG_PRINC;
	perr = krb5_unparse_name(context, principal, &p_name);
	if (pac_princname && !perr) {
	    krb5_set_error_message(context, ret,
				"Wrong principal in request: PAC verify: Principal in PAC is '%s' and does not match '%s'",
				pac_princname, p_name);
	}
	if (p_name)
	    krb5_free_unparsed_name(context, p_name);
    }

    free(pac_princname);
    krb5_free_principal(context, pac_principal);

    return ret;
}

static krb5_error_code
k5_pac_zero_signature(krb5_context context,
		      const krb5_pac pac,
		      krb5_ui_4 type,
		      krb5_data *data)
{
    PAC_INFO_BUFFER *buffer = NULL;
    size_t i;

    assert(type == PAC_SERVER_CHECKSUM || type == PAC_PRIVSVR_CHECKSUM);
    assert(data->length >= pac->data.length);

    for (i = 0; i < pac->pac->cBuffers; i++) {
	if (pac->pac->Buffers[i].ulType == type) {
	    buffer = &pac->pac->Buffers[i];
	    break;
	}
    }

    if (buffer == NULL) {
	/* Solaris Kerberos */
	krb5_set_error_message(context, ENOENT,
			    "No PAC buffer found (type=%d)",
			    type);
	return ENOENT;
    }

    if (buffer->Offset + buffer->cbBufferSize > pac->data.length) {
	return ERANGE;
    }

    if (buffer->cbBufferSize < PAC_SIGNATURE_DATA_LENGTH) {
	return KRB5_BAD_MSIZE;
    }

    /* Zero out the data portion of the checksum only */
    memset(data->data + buffer->Offset + PAC_SIGNATURE_DATA_LENGTH,
	   0,
	   buffer->cbBufferSize - PAC_SIGNATURE_DATA_LENGTH);

    return 0;
}

static krb5_error_code
k5_pac_verify_server_checksum(krb5_context context,
			      const krb5_pac pac,
			      const krb5_keyblock *server)
{
    krb5_error_code ret;
    krb5_data pac_data; /* PAC with zeroed checksums */
    krb5_checksum checksum;
    krb5_data checksum_data;
    krb5_boolean valid;
    krb5_octet *p;

    ret = k5_pac_locate_buffer(context, pac, PAC_SERVER_CHECKSUM, &checksum_data);
    if (ret != 0)
	return ret;

    if (checksum_data.length < PAC_SIGNATURE_DATA_LENGTH) {
	return KRB5_BAD_MSIZE;
    }

    p = (krb5_octet *)checksum_data.data;
    checksum.checksum_type = load_32_le(p);
    checksum.length = checksum_data.length - PAC_SIGNATURE_DATA_LENGTH;
    checksum.contents = p + PAC_SIGNATURE_DATA_LENGTH;

    pac_data.length = pac->data.length;
    pac_data.data = malloc(pac->data.length);
    if (pac_data.data == NULL)
	return ENOMEM;

    memcpy(pac_data.data, pac->data.data, pac->data.length);

    /* Zero out both checksum buffers */
    ret = k5_pac_zero_signature(context, pac, PAC_SERVER_CHECKSUM, &pac_data);
    if (ret != 0) {
	free(pac_data.data);
	return ret;
    }

    ret = k5_pac_zero_signature(context, pac, PAC_PRIVSVR_CHECKSUM, &pac_data);
    if (ret != 0) {
	free(pac_data.data);
	return ret;
    }

    ret = krb5_c_verify_checksum(context, server, KRB5_KEYUSAGE_APP_DATA_CKSUM,
				 &pac_data, &checksum, &valid);
    if (ret != 0) {
        free(pac_data.data);
	return ret;
    }

    if (valid == FALSE) {
	ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	/* Solaris Kerberos */
	krb5_set_error_message(context, ret,
			    "Decrypt integrity check failed for PAC");
    }

    free(pac_data.data); /* SUNW17PACresync - mem leak fix */
    return ret;
}

static krb5_error_code
k5_pac_verify_kdc_checksum(krb5_context context,
			   const krb5_pac pac,
			   const krb5_keyblock *privsvr)
{
    krb5_error_code ret;
    krb5_data server_checksum, privsvr_checksum;
    krb5_checksum checksum;
    krb5_boolean valid;
    krb5_octet *p;

    ret = k5_pac_locate_buffer(context, pac, PAC_PRIVSVR_CHECKSUM, &privsvr_checksum);
    if (ret != 0)
	return ret;

    if (privsvr_checksum.length < PAC_SIGNATURE_DATA_LENGTH) {
	return KRB5_BAD_MSIZE;
    }

    ret = k5_pac_locate_buffer(context, pac, PAC_SERVER_CHECKSUM, &server_checksum);
    if (ret != 0)
	return ret;

    if (server_checksum.length < PAC_SIGNATURE_DATA_LENGTH) {
	return KRB5_BAD_MSIZE;
    }

    p = (krb5_octet *)privsvr_checksum.data;
    checksum.checksum_type = load_32_le(p);
    checksum.length = privsvr_checksum.length - PAC_SIGNATURE_DATA_LENGTH;
    checksum.contents = p + PAC_SIGNATURE_DATA_LENGTH;

    server_checksum.data += PAC_SIGNATURE_DATA_LENGTH;
    server_checksum.length -= PAC_SIGNATURE_DATA_LENGTH;

    ret = krb5_c_verify_checksum(context, privsvr, KRB5_KEYUSAGE_APP_DATA_CKSUM,
				 &server_checksum, &checksum, &valid);
    if (ret != 0)
	return ret;

    if (valid == FALSE) {
	ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	/* Solaris Kerberos */
	krb5_set_error_message(context, ret,
			    "Decrypt integrity check failed for PAC");
    }

    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_pac_verify(krb5_context context,
		const krb5_pac pac,
		krb5_timestamp authtime,
		krb5_const_principal principal,
		const krb5_keyblock *server,
		const krb5_keyblock *privsvr)
{
    krb5_error_code ret;

    if (server == NULL) {
	return EINVAL;
    }

    ret = k5_pac_verify_server_checksum(context, pac, server);
    if (ret != 0)
	return ret;

    if (privsvr != NULL) {
	ret = k5_pac_verify_kdc_checksum(context, pac, privsvr);
	if (ret != 0)
	    return ret;
    }

    if (principal != NULL) {
	ret = k5_pac_validate_client(context, pac, authtime, principal);
	if (ret != 0)
	    return ret;
    }

    return 0;
}

static krb5_error_code
k5_insert_client_info(krb5_context context,
		      krb5_pac pac,
		      krb5_timestamp authtime,
		      krb5_const_principal principal)
{
    krb5_error_code ret;
    krb5_data client_info;
    char *princ_name_utf8 = NULL;
    unsigned char *princ_name_ucs2 = NULL, *p;
    size_t princ_name_ucs2_len = 0;
    krb5_ui_8 nt_authtime;

    /* If we already have a CLIENT_INFO buffer, then just validate it */
    if (k5_pac_locate_buffer(context, pac, PAC_CLIENT_INFO, &client_info) == 0) {
	return k5_pac_validate_client(context, pac, authtime, principal);
    }

    ret = krb5_unparse_name_flags(context, principal,
				  KRB5_PRINCIPAL_UNPARSE_NO_REALM, &princ_name_utf8);
    if (ret != 0)
	goto cleanup;

    ret = krb5int_utf8s_to_ucs2les(princ_name_utf8,
				   &princ_name_ucs2,
				   &princ_name_ucs2_len);
    if (ret != 0)
	goto cleanup;

    client_info.length = PAC_CLIENT_INFO_LENGTH + princ_name_ucs2_len;
    client_info.data = NULL;

    ret = k5_pac_add_buffer(context, pac, PAC_CLIENT_INFO, &client_info, TRUE, &client_info);
    if (ret != 0)
	goto cleanup;

    p = (unsigned char *)client_info.data;

    /* copy in authtime converted to a 64-bit NT time */
    k5_seconds_since_1970_to_time(authtime, &nt_authtime);
    store_64_le(nt_authtime, p);
    p += 8;

    /* copy in number of UCS-2 characters in principal name */
    store_16_le(princ_name_ucs2_len, p);
    p += 2;

    /* copy in principal name */
    memcpy(p, princ_name_ucs2, princ_name_ucs2_len);

cleanup:
    if (princ_name_utf8 != NULL)
	free(princ_name_utf8);
    if (princ_name_ucs2 != NULL)
	free(princ_name_ucs2);

    return ret;
}

static krb5_error_code
k5_insert_checksum(krb5_context context,
		   krb5_pac pac,
		   krb5_ui_4 type,
		   const krb5_keyblock *key,
		   krb5_cksumtype *cksumtype)
{
    krb5_error_code ret;
    size_t len;
    krb5_data cksumdata;

    ret = krb5int_c_mandatory_cksumtype(context, key->enctype, cksumtype);
    if (ret != 0)
	return ret;

    ret = krb5_c_checksum_length(context, *cksumtype, &len);
    if (ret != 0)
	return ret;

    ret = k5_pac_locate_buffer(context, pac, type, &cksumdata);
    if (ret == 0) {
	/* If we're resigning PAC, make sure we can fit checksum into existing buffer */
	if (cksumdata.length != PAC_SIGNATURE_DATA_LENGTH + len) {
	    return ERANGE;
	}

	memset(cksumdata.data, 0, cksumdata.length);
    } else {
	/* Add a zero filled buffer */
	cksumdata.length = PAC_SIGNATURE_DATA_LENGTH + len;
	cksumdata.data = NULL;

	ret = k5_pac_add_buffer(context, pac, type, &cksumdata, TRUE, &cksumdata);
	if (ret != 0)
	    return ret;
    }

    /* Encode checksum type into buffer */
    store_32_le((krb5_ui_4)*cksumtype, cksumdata.data);

    return 0;
}

/* in-place encoding of PAC header */
static krb5_error_code
k5_pac_encode_header(krb5_context context, krb5_pac pac)
{
    size_t i;
    unsigned char *p;
    size_t header_len;

    header_len = PACTYPE_LENGTH + (pac->pac->cBuffers * PAC_INFO_BUFFER_LENGTH);
    assert(pac->data.length >= header_len);

    p = (unsigned char *)pac->data.data;

    store_32_le(pac->pac->cBuffers, p);
    p += 4;
    store_32_le(pac->pac->Version, p);
    p += 4;

    for (i = 0; i < pac->pac->cBuffers; i++) {
	PAC_INFO_BUFFER *buffer = &pac->pac->Buffers[i];

	store_32_le(buffer->ulType, p);
	p += 4;
	store_32_le(buffer->cbBufferSize, p);
	p += 4;
	store_64_le(buffer->Offset, p);
	p += 8;

	assert((buffer->Offset % PAC_ALIGNMENT) == 0);
	assert(buffer->Offset + buffer->cbBufferSize <= pac->data.length);
	assert(buffer->Offset >= header_len);

	if (buffer->Offset % PAC_ALIGNMENT ||
	    buffer->Offset + buffer->cbBufferSize > pac->data.length ||
	    buffer->Offset < header_len) {
	    return ERANGE;
	}
    }

    return 0;
}


#if 0
/*
 * SUNW17PACresync
 * We don't have the new MIT iov interfaces yet and don't need them yet.
 * We'll need this for full 1.7 resync.
 */
krb5_error_code KRB5_CALLCONV
krb5int_pac_sign(krb5_context context,
		 krb5_pac pac,
		 krb5_timestamp authtime,
		 krb5_const_principal principal,
		 const krb5_keyblock *server_key,
		 const krb5_keyblock *privsvr_key,
		 krb5_data *data)
{
    krb5_error_code ret;
    krb5_data server_cksum, privsvr_cksum;
    krb5_cksumtype server_cksumtype, privsvr_cksumtype;
    krb5_crypto_iov iov[2];

    data->length = 0;
    data->data = NULL;

    if (principal != NULL) {
	ret = k5_insert_client_info(context, pac, authtime, principal);
	if (ret != 0)
	    return ret;
    }

    /* Create zeroed buffers for both checksums */
    ret = k5_insert_checksum(context, pac, PAC_SERVER_CHECKSUM,
			     server_key, &server_cksumtype);
    if (ret != 0)
	return ret;

    ret = k5_insert_checksum(context, pac, PAC_PRIVSVR_CHECKSUM,
			     privsvr_key, &privsvr_cksumtype);
    if (ret != 0)
	return ret;

    /* Now, encode the PAC header so that the checksums will include it */
    ret = k5_pac_encode_header(context, pac);
    if (ret != 0)
	return ret;

    /* Generate the server checksum over the entire PAC */
    ret = k5_pac_locate_buffer(context, pac, PAC_SERVER_CHECKSUM, &server_cksum);
    if (ret != 0)
	return ret;

    assert(server_cksum.length > PAC_SIGNATURE_DATA_LENGTH);

    iov[0].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[0].data = pac->data;

    iov[1].flags = KRB5_CRYPTO_TYPE_CHECKSUM;
    iov[1].data.data = server_cksum.data + PAC_SIGNATURE_DATA_LENGTH;
    iov[1].data.length = server_cksum.length - PAC_SIGNATURE_DATA_LENGTH;

    ret = krb5_c_make_checksum_iov(context, server_cksumtype,
				   server_key, KRB5_KEYUSAGE_APP_DATA_CKSUM,
				   iov, sizeof(iov)/sizeof(iov[0]));
    if (ret != 0)
	return ret;

    /* Generate the privsvr checksum over the server checksum buffer */
    ret = k5_pac_locate_buffer(context, pac, PAC_PRIVSVR_CHECKSUM, &privsvr_cksum);
    if (ret != 0)
	return ret;

    assert(privsvr_cksum.length > PAC_SIGNATURE_DATA_LENGTH);

    iov[0].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[0].data.data = server_cksum.data + PAC_SIGNATURE_DATA_LENGTH;
    iov[0].data.length = server_cksum.length - PAC_SIGNATURE_DATA_LENGTH;

    iov[1].flags = KRB5_CRYPTO_TYPE_CHECKSUM;
    iov[1].data.data = privsvr_cksum.data + PAC_SIGNATURE_DATA_LENGTH;
    iov[1].data.length = privsvr_cksum.length - PAC_SIGNATURE_DATA_LENGTH;

    ret = krb5_c_make_checksum_iov(context, privsvr_cksumtype,
				   privsvr_key, KRB5_KEYUSAGE_APP_DATA_CKSUM,
				   iov, sizeof(iov)/sizeof(iov[0]));
    if (ret != 0)
	return ret;

    data->data = malloc(pac->data.length);
    if (data->data == NULL)
	return ENOMEM;

    data->length = pac->data.length;

    memcpy(data->data, pac->data.data, pac->data.length);
    memset(pac->data.data, 0, PACTYPE_LENGTH + (pac->pac->cBuffers * PAC_INFO_BUFFER_LENGTH));

    return 0;
}
#endif

