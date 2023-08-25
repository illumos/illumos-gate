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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *  glue routine gss_display_status
 *
 */

#include <mechglueP.h>
#include "gssapiP_generic.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <libintl.h>
#include <errno.h>
#include <syslog.h>
#ifndef TEXT_DOMAIN
#error TEXT_DOMAIN not defined
#endif

/* local function */
static OM_uint32 displayMajor(OM_uint32, OM_uint32 *, gss_buffer_t);


OM_uint32
gss_display_status(minor_status,
			status_value,
			status_type,
			req_mech_type,
			message_context,
			status_string)

OM_uint32 *minor_status;
OM_uint32 status_value;
int status_type;
const gss_OID req_mech_type;
OM_uint32 *message_context;
gss_buffer_t status_string;
{
	gss_OID			mech_type = (gss_OID) req_mech_type;
	gss_mechanism		mech;
	gss_OID_desc		m_oid = { 0, 0 };

	if (minor_status != NULL)
		*minor_status = 0;

	if (status_string != GSS_C_NO_BUFFER) {
		status_string->length = 0;
		status_string->value = NULL;
	}

	if (minor_status == NULL ||
	    message_context == NULL ||
	    status_string == GSS_C_NO_BUFFER)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* we handle major status codes, and the mechs do the minor */
	if (status_type == GSS_C_GSS_CODE)
		return (displayMajor(status_value, message_context,
				status_string));

	/*
	 * must be the minor status - let mechs do the work
	 * select the appropriate underlying mechanism routine and
	 * call it.
	 */

	/* In this version, we only handle status codes that have been
	   mapped to a flat numbering space.  Look up the value we got
	   passed.  If it's not found, complain.  */
	if (status_value == 0) {
		status_string->value = strdup("Unknown error");
		if (status_string->value == NULL) {
			*minor_status = ENOMEM;
			map_errcode(minor_status);
			return GSS_S_FAILURE;
		}
		status_string->length = strlen(status_string->value);
		*message_context = 0;
		*minor_status = 0;
		return GSS_S_COMPLETE;
	}
	{
		int err;
	        OM_uint32 m_status = 0, status;

		err = gssint_mecherrmap_get(status_value, &m_oid, &m_status);
		if (err) {
			*minor_status = err;
			map_errcode(minor_status);
			return GSS_S_BAD_STATUS;
		}

		if (m_oid.length == 0) {
			/* Magic flag for com_err values.  */
			status = gssint_g_display_com_err_status(minor_status,
							m_status,
							status_string);
			if (status != GSS_S_COMPLETE)
				map_errcode(minor_status);
			return status;
		}
		mech_type = &m_oid;
		status_value = m_status;
	}

	mech = __gss_get_mechanism(mech_type);

	if (mech && mech->gss_display_status) {
		OM_uint32 r;

		if (mech_type == GSS_C_NULL_OID)
			mech_type = &mech->mech_type;

		r = mech->gss_display_status(mech->context, minor_status,
				status_value, status_type, mech_type,
				message_context, status_string);
		/* How's this for weird?  If we get an error returning the
		mechanism-specific error code, we save away the
		mechanism-specific error code describing the error.  */
		if (r != GSS_S_COMPLETE)
			map_error(minor_status, mech);
		return r;
	}

	if (!mech)
		return (GSS_S_BAD_MECH);

	return (GSS_S_UNAVAILABLE);
} /* gss_display_status */


/*
 * function to map the major error codes
 * it uses case statements so that the strings could be wrapped by gettext
 * msgCtxt is interpreted as:
 *	0 - first call
 *	1 - routine error
 *	>= 2 - the supplementary error code bit shifted by 1
 */
static OM_uint32
displayMajor(status, msgCtxt, outStr)
OM_uint32 status;
OM_uint32 *msgCtxt;
gss_buffer_t outStr;
{
	OM_uint32 oneVal, mask = 0x1, currErr;
	char *errStr = NULL;
	int i, haveErr = 0;

	/* take care of the success value first */
	if (status == GSS_S_COMPLETE)
		errStr = dgettext(TEXT_DOMAIN,
				"The routine completed successfully");
	else if (*msgCtxt == 0 && (oneVal = GSS_CALLING_ERROR(status))) {
		switch (oneVal) {
		case GSS_S_CALL_INACCESSIBLE_READ:
			errStr = dgettext(TEXT_DOMAIN,
					"A required input parameter"
					" could not be read");
			break;

		case GSS_S_CALL_INACCESSIBLE_WRITE:
			errStr = dgettext(TEXT_DOMAIN,
					"A required output parameter"
					" could not be written");
			break;

		case GSS_S_CALL_BAD_STRUCTURE:
			errStr = dgettext(TEXT_DOMAIN,
					"A parameter was malformed");
			break;

		default:
			errStr = dgettext(TEXT_DOMAIN,
					"An invalid status code was supplied");
			break;
		}

		/* we now need to determine new value of msgCtxt */
		if (GSS_ROUTINE_ERROR(status))
			*msgCtxt = 1;
		else if ((oneVal = GSS_SUPPLEMENTARY_INFO(status)) != 0)
			*msgCtxt = (OM_uint32)(oneVal << 1);
		else
			*msgCtxt = 0;

	} else if ((*msgCtxt == 0 || *msgCtxt == 1) &&
		(oneVal = GSS_ROUTINE_ERROR(status))) {
		switch (oneVal) {
		case GSS_S_BAD_MECH:
			errStr = dgettext(TEXT_DOMAIN,
					"An unsupported mechanism"
					" was requested");
			break;

		case GSS_S_BAD_NAME:
			errStr = dgettext(TEXT_DOMAIN,
					"An invalid name was supplied");
			break;

		case GSS_S_BAD_NAMETYPE:
			errStr = dgettext(TEXT_DOMAIN,
					"A supplied name was of an"
					" unsupported type");
			break;

		case GSS_S_BAD_BINDINGS:
			errStr = dgettext(TEXT_DOMAIN,
					"Incorrect channel bindings"
					" were supplied");
			break;

		case GSS_S_BAD_SIG: /* same as GSS_S_BAD_MIC: */
			errStr = dgettext(TEXT_DOMAIN,
					"A token had an invalid Message"
					" Integrity Check (MIC)");
			break;

		case GSS_S_NO_CRED:
			errStr = dgettext(TEXT_DOMAIN,
					"No credentials were supplied, or the"
					" credentials were unavailable or"
					" inaccessible");
			break;

		case GSS_S_NO_CONTEXT:
			errStr = dgettext(TEXT_DOMAIN,
					"No context has been established");
			break;

		case GSS_S_DEFECTIVE_TOKEN:
			errStr = dgettext(TEXT_DOMAIN,
					"Invalid token was supplied");
			break;

		case GSS_S_DEFECTIVE_CREDENTIAL:
			errStr = dgettext(TEXT_DOMAIN,
					"Invalid credential was supplied");
			break;

		case GSS_S_CREDENTIALS_EXPIRED:
			errStr = dgettext(TEXT_DOMAIN,
					"The referenced credential has"
					" expired");
			break;

		case GSS_S_CONTEXT_EXPIRED:
			errStr = dgettext(TEXT_DOMAIN,
					"The referenced context has expired");
			break;

		case GSS_S_FAILURE:
			errStr = dgettext(TEXT_DOMAIN,
					"Unspecified GSS failure.  Minor code"
					" may provide more information");
			break;

		case GSS_S_BAD_QOP:
			errStr = dgettext(TEXT_DOMAIN,
					"The quality-of-protection (QOP) "
					"requested could not be provided");
			break;

		case GSS_S_UNAUTHORIZED:
			errStr = dgettext(TEXT_DOMAIN,
					"The operation is forbidden by local"
					" security policy");
			break;

		case GSS_S_UNAVAILABLE:
			errStr = dgettext(TEXT_DOMAIN,
					"The operation or option is not"
					" available or unsupported");
			break;

		case GSS_S_DUPLICATE_ELEMENT:
			errStr = dgettext(TEXT_DOMAIN,
					"The requested credential element"
					" already exists");
			break;

		case GSS_S_NAME_NOT_MN:
			errStr = dgettext(TEXT_DOMAIN,
					"The provided name was not mechanism"
					" specific (MN)");
			break;

		case GSS_S_BAD_STATUS:
		default:
			errStr = dgettext(TEXT_DOMAIN,
					"An invalid status code was supplied");
		}

		/* we must determine if the caller should call us again */
		if ((oneVal = GSS_SUPPLEMENTARY_INFO(status)) != 0)
			*msgCtxt = (OM_uint32)(oneVal << 1);
		else
			*msgCtxt = 0;

	} else if ((*msgCtxt == 0 || *msgCtxt >= 2) &&
		(oneVal = GSS_SUPPLEMENTARY_INFO(status))) {
		/*
		 * if msgCtxt is not 0, then it should encode
		 * the supplementary error code we should be printing
		 */
		if (*msgCtxt >= 2)
			oneVal = (OM_uint32) (*msgCtxt) >> 1;
		else
			oneVal = GSS_SUPPLEMENTARY_INFO(status);

		/* we display the errors LSB first */
		for (i = 0; i < 16; i++) {
			if (oneVal & mask) {
				haveErr = 1;
				break;
			}
			mask <<= 1;
		}

		/* isolate the bit or if not found set to illegal value */
		if (haveErr)
			currErr = oneVal & mask;
		else
			currErr = 1 << 17; /* illegal value */

		switch (currErr) {
		case GSS_S_CONTINUE_NEEDED:
			errStr = dgettext(TEXT_DOMAIN,
					"The routine must be called again to"
					" complete its function");
			break;

		case GSS_S_DUPLICATE_TOKEN:
			errStr = dgettext(TEXT_DOMAIN,
					"The token was a duplicate of an"
					" earlier token");
			break;

		case GSS_S_OLD_TOKEN:
			errStr = dgettext(TEXT_DOMAIN,
					"The token's validity period"
					" has expired");
			break;

		case GSS_S_UNSEQ_TOKEN:
			errStr = dgettext(TEXT_DOMAIN,
					"A later token has already been"
					" processed");
			break;

		case GSS_S_GAP_TOKEN:
			errStr = dgettext(TEXT_DOMAIN,
					"An expected per-message token was"
					" not received");
			break;

		default:
			errStr = dgettext(TEXT_DOMAIN,
					"An invalid status code was supplied");
		}

		/*
		 * we must check if there is any other supplementary errors
		 * if found, then turn off current bit, and store next value
		 * in msgCtxt shifted by 1 bit
		 */
		if (!haveErr)
			*msgCtxt = 0;
		else if (GSS_SUPPLEMENTARY_INFO(oneVal) ^ mask)
			*msgCtxt = (OM_uint32)
				((GSS_SUPPLEMENTARY_INFO(oneVal) ^ mask) << 1);
		else
			*msgCtxt = 0;
	}

	if (errStr == NULL)
		errStr = dgettext(TEXT_DOMAIN,
				"An invalid status code was supplied");

	/* now copy the status code and return to caller */
	outStr->length = strlen(errStr);
	outStr->value = strdup(errStr);
	if (outStr->value == NULL) {
		outStr->length = 0;
		return (GSS_S_FAILURE);
	}

	return (GSS_S_COMPLETE);
} /* displayMajor */
