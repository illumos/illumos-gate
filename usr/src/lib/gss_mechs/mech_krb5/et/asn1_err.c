/*
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
const char *
asn1_error_table(long errorno) {

switch (errorno) {
	case 0:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 failed call to system time library"));
	case 1:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 structure is missing a required field"));
	case 2:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 unexpected field number"));
	case 3:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 type numbers are inconsistent"));
	case 4:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 value too large"));
	case 5:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 encoding ended unexpectedly"));
	case 6:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 identifier doesn't match expected value"));
	case 7:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 length doesn't match expected value"));
	case 8:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 badly-formatted encoding"));
	case 9:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 parse error"));
	case 10:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 bad return from gmtime"));
	case 11:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 non-constructed indefinite encoding"));
	case 12:
		return(dgettext(TEXT_DOMAIN,
			"ASN.1 missing expected EOC"));
	default:
		return("unknown error");
	}
}
