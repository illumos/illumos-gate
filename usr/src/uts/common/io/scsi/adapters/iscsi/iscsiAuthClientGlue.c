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
 * Copyright 2000 by Cisco Systems, Inc.  All rights reserved.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * iSCSI Pseudo HBA Driver
 */

#include <sys/random.h>

#include "chap.h"
#include "iscsi.h"
#include <sys/iscsi_protocol.h>
#include "iscsiAuthClient.h"
#include "persistent.h"

/*
 * Authenticate a target's CHAP response.
 *
 * username - Incoming username from the the target.
 * responseData - Incoming response data from the target.
 */
int
iscsiAuthClientChapAuthRequest(IscsiAuthClient *client,
    char *username, unsigned int id, uchar_t *challengeData,
    unsigned int challengeLength, uchar_t *responseData,
    unsigned int responseLength)
{
	iscsi_sess_t		*isp = (iscsi_sess_t *)client->userHandle;
	IscsiAuthMd5Context	context;
	uchar_t			verifyData[16];
	iscsi_radius_props_t p_radius_cfg;

	if (isp == NULL) {
		return (iscsiAuthStatusFail);
	}

	/*
	 * the expected credentials are in the session
	 */
	if (strcmp(username, isp->sess_auth.username_in) != 0) {
		cmn_err(CE_WARN, "iscsi session(%u) failed authentication, "
		    "received incorrect username from target",
		    isp->sess_oid);
		return (iscsiAuthStatusFail);
	}

	/* Check if RADIUS access is enabled */
	if (persistent_radius_get(&p_radius_cfg) == ISCSI_NVFILE_SUCCESS &&
	    p_radius_cfg.r_radius_access == B_TRUE) {
		chap_validation_status_type chap_valid_status;
		int authStatus;
		RADIUS_CONFIG radius_cfg;

		if (p_radius_cfg.r_radius_config_valid == B_FALSE) {
			/*
			 * Radius enabled but configuration invalid -
			 * invalid condition
			 */
			return (iscsiAuthStatusFail);
		}

		/* Use RADIUS server to authentication target */
		if (p_radius_cfg.r_insize == sizeof (in_addr_t)) {
			/* IPv4 */
			radius_cfg.rad_svr_addr.i_addr.in4.s_addr =
			    p_radius_cfg.r_addr.u_in4.s_addr;
			radius_cfg.rad_svr_addr.i_insize
			    = sizeof (in_addr_t);
		} else if (p_radius_cfg.r_insize == sizeof (in6_addr_t)) {
			/* IPv6 */
			bcopy(p_radius_cfg.r_addr.u_in6.s6_addr,
			    radius_cfg.rad_svr_addr.i_addr.in6.s6_addr,
			    16);
			radius_cfg.rad_svr_addr.i_insize = sizeof (in6_addr_t);
		} else {
			return (iscsiAuthStatusFail);
		}

		radius_cfg.rad_svr_port = p_radius_cfg.r_port;
		bcopy(p_radius_cfg.r_shared_secret,
		    radius_cfg.rad_svr_shared_secret,
		    MAX_RAD_SHARED_SECRET_LEN);
		radius_cfg.rad_svr_shared_secret_len =
		    p_radius_cfg.r_shared_secret_len;

		/* Entry point to the CHAP authentication module. */
		chap_valid_status = chap_validate_tgt(
		    isp->sess_auth.username_in,
		    isp->sess_auth.username,
		    challengeData,
		    challengeLength,
		    responseData,
		    responseLength,
		    id,
		    RADIUS_AUTHENTICATION,
		    (void *)&radius_cfg);

		switch (chap_valid_status) {
			case CHAP_VALIDATION_PASSED:
				authStatus = iscsiAuthStatusPass;
				break;
			case CHAP_VALIDATION_INVALID_RESPONSE:
				authStatus = iscsiAuthStatusFail;
				break;
			case CHAP_VALIDATION_DUP_SECRET:
				authStatus = iscsiAuthStatusFail;
				break;
			case CHAP_VALIDATION_RADIUS_ACCESS_ERROR:
				authStatus = iscsiAuthStatusFail;
				break;
			case CHAP_VALIDATION_BAD_RADIUS_SECRET:
				authStatus = iscsiAuthStatusFail;
				break;
			default:
				authStatus = iscsiAuthStatusFail;
				break;
		}
		return (authStatus);
	} else {
		/* Use target secret (if defined) to authenticate target */
		if ((isp->sess_auth.password_length_in < 1) ||
		    (isp->sess_auth.password_in[0] == '\0')) {
			/* No target secret defined - invalid condition */
			return (iscsiAuthStatusFail);
		}

		/*
		 * challenge length is I->T, and shouldn't need to
		 * be checked
		 */
		if (responseLength != sizeof (verifyData)) {
			cmn_err(CE_WARN, "iscsi session(%u) failed "
			    "authentication, received incorrect CHAP response "
			    "from target", isp->sess_oid);
			return (iscsiAuthStatusFail);
		}

		iscsiAuthMd5Init(&context);

		/*
		 * id byte
		 */
		verifyData[0] = id;
		iscsiAuthMd5Update(&context, verifyData, 1);

		/*
		 * shared secret
		 */
		iscsiAuthMd5Update(&context,
		    (uchar_t *)isp->sess_auth.password_in,
		    isp->sess_auth.password_length_in);

		/*
		 * challenge value
		 */
		iscsiAuthMd5Update(&context,
		    (uchar_t *)challengeData,
		    challengeLength);

		iscsiAuthMd5Final(verifyData, &context);

		if (bcmp(responseData, verifyData,
		    sizeof (verifyData)) == 0) {
			return (iscsiAuthStatusPass);
		}

		cmn_err(CE_WARN, "iscsi session(%u) failed authentication, "
		    "received incorrect CHAP response from target",
		    isp->sess_oid);
	}

	return (iscsiAuthStatusFail);
}

/* ARGSUSED */
void
iscsiAuthClientChapAuthCancel(IscsiAuthClient * client)
{
}


int
iscsiAuthClientTextToNumber(const char *text, unsigned long *pNumber)
{
	char *pEnd;
	unsigned long number;

	if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
		if (ddi_strtoul(text + 2, &pEnd, 16, &number) != 0) {
			return (1); /* Error */
		}
	} else {
		if (ddi_strtoul(text, &pEnd, 10, &number) != 0) {
			return (1); /* Error */
		}
	}

	if (*text != '\0' && *pEnd == '\0') {
		*pNumber = number;
		return (0);	/* No error */
	} else {
		return (1);	/* Error */
	}
}

/* ARGSUSED */
void
iscsiAuthClientNumberToText(unsigned long number, char *text,
    unsigned int length)
{
	(void) sprintf(text, "%lu", number);
}


void
iscsiAuthRandomSetData(uchar_t *data, unsigned int length)
{
	(void) random_get_pseudo_bytes(data, length);
}


void
iscsiAuthMd5Init(IscsiAuthMd5Context * context)
{
	MD5Init(context);
}


void
iscsiAuthMd5Update(IscsiAuthMd5Context *context, uchar_t *data,
    unsigned int length)
{
	MD5Update(context, data, length);
}


void
iscsiAuthMd5Final(uchar_t *hash, IscsiAuthMd5Context *context)
{
	MD5Final(hash, context);
}


int
iscsiAuthClientData(uchar_t *outData, unsigned int *outLength,
    uchar_t *inData, unsigned int inLength)
{
	if (*outLength < inLength) {
		return (1);	/* error */
	}
	bcopy(inData, outData, inLength);
	*outLength = inLength;
	return (0);		/* no error */
}
