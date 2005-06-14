/*
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
const char *
k5g_error_table(long errorno) {

switch (errorno) {
	case 0:
		return(dgettext(TEXT_DOMAIN,
			"Principal in credential cache does not match desired name"));
	case 1:
		return(dgettext(TEXT_DOMAIN,
			"No principal in keytab matches desired name"));
	case 2:
		return(dgettext(TEXT_DOMAIN,
			"Credential cache has no TGT"));
	case 3:
		return(dgettext(TEXT_DOMAIN,
			"Authenticator has no subkey"));
	case 4:
		return(dgettext(TEXT_DOMAIN,
			"Context is already fully established"));
	case 5:
		return(dgettext(TEXT_DOMAIN,
			"Unknown signature type in token"));
	case 6:
		return(dgettext(TEXT_DOMAIN,
			"Invalid field length in token"));
	case 7:
		return(dgettext(TEXT_DOMAIN,
			"Attempt to use incomplete security context"));
	case 8:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_gss_ctx_id_t"));
	case 9:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_gss_cred_id_t"));
	case 10:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic number for krb5_gss_enc_desc"));
	case 11:
		return(dgettext(TEXT_DOMAIN,
			"Sequence number in token is corrupt"));
	case 12:
		return(dgettext(TEXT_DOMAIN,
			"Credential cache is empty"));
	case 13:
		return(dgettext(TEXT_DOMAIN,
			"Acceptor and Initiator share no checksum types"));
	default:
		return("unknown error");
	}
}
