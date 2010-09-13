/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
const char *
ggss_error_table(long errorno) {

switch (errorno) {
	case 0:
		return (dgettext(TEXT_DOMAIN,
			"No @ in SERVICE-NAME name string"));
	case 1:
		return (dgettext(TEXT_DOMAIN,
			"STRING-UID-NAME contains nondigits"));
	case 2:
		return (dgettext(TEXT_DOMAIN,
			"UID does not resolve to username"));
	case 3:
		return (dgettext(TEXT_DOMAIN,
			"Validation error"));
	case 4:
		return (dgettext(TEXT_DOMAIN,
			"Couldn't allocate gss_buffer_t data"));
	case 5:
		return (dgettext(TEXT_DOMAIN,
			"Message context invalid"));
	case 6:
		return (dgettext(TEXT_DOMAIN,
			"Buffer is the wrong size"));
	case 7:
		return (dgettext(TEXT_DOMAIN,
			"Credential usage type is unknown"));
	case 8:
		return (dgettext(TEXT_DOMAIN,
			"Unknown quality of protection specified"));
	case 9:
		return (dgettext(TEXT_DOMAIN,
			"Local host name could not be determined"));
	case 10:
		return (dgettext(TEXT_DOMAIN,
			"Hostname in SERVICE-NAME string could not be"
			" canonicalized"));
	case 11:
		return (dgettext(TEXT_DOMAIN,
			"Mechanism is incorrect"));
	case 12:
		return (dgettext(TEXT_DOMAIN,
			"Token header is malformed or corrupt"));
	case 13:
		return (dgettext(TEXT_DOMAIN,
			"Packet was replayed in wrong direction"));
	case 14:
		return (dgettext(TEXT_DOMAIN,
			"Token is missing data"));
	case 15:
		return (dgettext(TEXT_DOMAIN,
			"Token was reflected"));
	case 16:
		return (dgettext(TEXT_DOMAIN,
			"Received token ID does not match expected token ID"));
	case 17:
		return (dgettext(TEXT_DOMAIN,
			"The given credential's usage does not match the"
			" requested usage"));
	case 18:
		return (dgettext(TEXT_DOMAIN,
			"Storing of acceptor credentials is not supported by"
			" the mechanism"));
	case 19:
		return (dgettext(TEXT_DOMAIN,
			"Storing of non-default credentials is not supported by"
			" the mechanism"));
	default:
		return ("unknown error");
	}
}
