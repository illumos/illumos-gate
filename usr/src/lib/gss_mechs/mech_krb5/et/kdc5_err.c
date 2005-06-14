/*
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
 
#include <locale.h>
const char *
kdc5_error_table(long errorno) {

switch (errorno) {
	case 0:
		return(
			"$Id: kdc5_err.etv 5.4 1995/11/03 21:52:00 eichin Exp $");
	case 1:
		return(dgettext(TEXT_DOMAIN,
			"No server port found"));
	case 2:
		return(dgettext(TEXT_DOMAIN,
			"Network not initialized"));
	case 3:
		return(dgettext(TEXT_DOMAIN,
			"Short write while sending response"));
	default:
		return("unknown error");
	}
}
