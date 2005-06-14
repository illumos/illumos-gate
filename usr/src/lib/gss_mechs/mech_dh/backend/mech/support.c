/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	support.c
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include <locale.h>

#include "dh_gssapi.h"

/*
 * __dh_gss_display_status: This is the routine that implements
 * gss_display_status for Diffie-Hellman mechanism. Note we will
 * return failure if the status_type parameter is GSS_C_GSS_CODE
 * since libgss should handle the mechanism independent codes.
 */
OM_uint32
__dh_gss_display_status(void *ctx, /* Per mechanism context */
			OM_uint32 *minor, /* This mechanism's status */
			OM_uint32 status_value, /* The value to dispaly */
			int status_type, /* Shoud alway be GSS_C_MECH_COE */
			gss_OID mech, /* Our OID or GSS_C_NO_OID */
			OM_uint32* mesg_ctx, /* Message context for continues */
			gss_buffer_t  status_str /* The displayed output */)
{
	char *str;
	OM_uint32 major = GSS_S_COMPLETE;

	if (!minor)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);
	*minor = DH_SUCCESS;

	if (!mesg_ctx)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* We only have one message per status value */
	*mesg_ctx = 0;


	/*
	 * If status_type equals GSS_C_GSS_CODE, we'll return
	 * GSS_S_FAILURE. This status type is handled by the caller,
	 * libgss, since it is mechanism independent. We should never see
	 * this. If the status type does not equal GSS_C_MECH_CODE and
	 * does not equal GSS_C_GSS_CODE we return GSS_S_BAD_STATUS as per
	 * spec.
	 */

	if (status_type != GSS_C_MECH_CODE)
		return ((status_type == GSS_C_GSS_CODE ?
			GSS_S_FAILURE : GSS_S_BAD_STATUS));

	if (mech != GSS_C_NO_OID &&
	    !__OID_equal(((dh_context_t)ctx)->mech, mech))
		return (GSS_S_BAD_MECH);

	/* Convert the DH status value to an internationalize string */
	switch (status_value) {
	case DH_SUCCESS:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Success");
		break;
	case DH_NOMEM_FAILURE:
		str = dgettext(TEXT_DOMAIN, "mech_dh: No memory");
		break;
	case DH_ENCODE_FAILURE:
		str = dgettext(TEXT_DOMAIN,
			    "mech_dh: Could not encode token");
		break;
	case DH_DECODE_FAILURE:
		str = dgettext(TEXT_DOMAIN,
			    "mech_dh: Could not decode token");
		break;
	case DH_BADARG_FAILURE:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Bad argument");
		break;
	case DH_CIPHER_FAILURE:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Cipher failure");
		break;
	case DH_VERIFIER_FAILURE:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Verifier failure");
		break;
	case DH_SESSION_CIPHER_FAILURE:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Session cipher failure");
		break;
	case DH_NO_SECRET:
		str = dgettext(TEXT_DOMAIN, "mech_dh: No secret key");
		break;
	case DH_NO_PRINCIPAL:
		str = dgettext(TEXT_DOMAIN, "mech_dh: No principal");
		break;
	case DH_NOT_LOCAL:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Not local principal");
		break;
	case DH_UNKNOWN_QOP:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Unkown QOP");
		break;
	case DH_VERIFIER_MISMATCH:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Verifier mismatch");
		break;
	case DH_NO_SUCH_USER:
		str = dgettext(TEXT_DOMAIN, "mech_dh: No such user");
		break;
	case DH_NETNAME_FAILURE:
		str = dgettext(TEXT_DOMAIN,
			    "mech_dh: Could not generate netname");
		break;
	case DH_BAD_CRED:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Invalid credential");
		break;
	case DH_BAD_CONTEXT:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Invalid GSS context");
		break;
	case DH_PROTO_MISMATCH:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Diffie-Hellman protocol "
			    "mismatch");
		break;
	default:
		str = dgettext(TEXT_DOMAIN, "mech_dh: Invalid or "
			    "unknown error");
		major = GSS_S_BAD_STATUS;
		break;
	}

	/* Copy the string to the output */
	status_str->value = strdup(str);
	if (status_str == 0) {
		*minor = DH_NOMEM_FAILURE;
		return (GSS_S_FAILURE);
	}
	status_str->length = strlen(str);

	/* Return the GSS status of GSS_S_COMPLETE or GSS_S_BAD_STATUS */
	return (major);
}


/*
 * This function is completely implemented in libgss. Its entry point is
 * set to NULL in dhmech.c
 */
/*
 * OM_uint32
 * __dh_gss_indicate_mechs(void *ctx, OM_uint32 *minor, gss_OID_set *mechs)
 * {
 *	return (GSS_S_UNAVAILABLE);
 * }
 */
