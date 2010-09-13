/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

void
initialize_adb_error_table(void) {
}

#include <locale.h>
const char *
adb_error_table(long errorno) {

switch (errorno) {
	case 0:
		return (dgettext(TEXT_DOMAIN,
			"No Error"));
	case 1:
		return (dgettext(TEXT_DOMAIN,
			"Principal or policy already exists"));
	case 2:
		return (dgettext(TEXT_DOMAIN,
			"Principal or policy does not exist"));
	case 3:
		return (dgettext(TEXT_DOMAIN,
			"Database not initialized"));
	case 4:
		return (dgettext(TEXT_DOMAIN,
			"Invalid policy name"));
	case 5:
		return (dgettext(TEXT_DOMAIN,
			"Invalid principal name"));
	case 6:
		return (dgettext(TEXT_DOMAIN,
			"Database inconsistency detected"));
	case 7:
		return (dgettext(TEXT_DOMAIN,
			"XDR encoding error"));
	case 8:
		return (dgettext(TEXT_DOMAIN,
			"Failure!"));
	case 9:
		return (dgettext(TEXT_DOMAIN,
			"Bad lock mode"));
	case 10:
		return (dgettext(TEXT_DOMAIN,
			"Cannot lock database"));
	case 11:
		return (dgettext(TEXT_DOMAIN,
			"Database not locked"));
	case 12:
		return (dgettext(TEXT_DOMAIN,
			"KADM5 administration database lock file missing"));
	case 13:
		return (dgettext(TEXT_DOMAIN,
			"Insufficient permission to lock file"));
	default:
		return ("unknown error");
	}
}
