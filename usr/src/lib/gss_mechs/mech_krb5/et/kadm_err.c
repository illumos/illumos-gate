/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
const char *
ovk_error_table(long errorno) {

switch (errorno) {
	case 0:
		return(dgettext(TEXT_DOMAIN,
			"Operation failed for unspecified reason"));
	case 1:
		return(dgettext(TEXT_DOMAIN,
			"Operation requires ``get'' privilege"));
	case 2:
		return(dgettext(TEXT_DOMAIN,
			"Operation requires ``add'' privilege"));
	case 3:
		return(dgettext(TEXT_DOMAIN,
			"Operation requires ``modify'' privilege"));
	case 4:
		return(dgettext(TEXT_DOMAIN,
			"Operation requires ``delete'' privilege"));
	case 5:
		return(dgettext(TEXT_DOMAIN,
			"Insufficient authorization for operation"));
	case 6:
		return(dgettext(TEXT_DOMAIN,
			"Database inconsistency detected"));
	case 7:
		return(dgettext(TEXT_DOMAIN,
			"Principal or policy already exists"));
	case 8:
		return(dgettext(TEXT_DOMAIN,
			"Communication failure with server"));
	case 9:
		return(dgettext(TEXT_DOMAIN,
			"No administration server found for realm"));
	case 10:
		return(dgettext(TEXT_DOMAIN,
			"Password history principal key version mismatch"));
	case 11:
		return(dgettext(TEXT_DOMAIN,
			"Connection to server not initialized"));
	case 12:
		return(dgettext(TEXT_DOMAIN,
			"Principal does not exist"));
	case 13:
		return(dgettext(TEXT_DOMAIN,
			"Policy does not exist"));
	case 14:
		return(dgettext(TEXT_DOMAIN,
			"Invalid field mask for operation"));
	case 15:
		return(dgettext(TEXT_DOMAIN,
			"Invalid number of character classes"));
	case 16:
		return(dgettext(TEXT_DOMAIN,
			"Invalid password length"));
	case 17:
		return(dgettext(TEXT_DOMAIN,
			"Illegal policy name"));
	case 18:
		return(dgettext(TEXT_DOMAIN,
			"Illegal principal name"));
	case 19:
		return(dgettext(TEXT_DOMAIN,
			"Invalid auxillary attributes"));
	case 20:
		return(dgettext(TEXT_DOMAIN,
			"Invalid password history count"));
	case 21:
		return(dgettext(TEXT_DOMAIN,
			"Password minimum life is greater than password maximum life"));
	case 22:
		return(dgettext(TEXT_DOMAIN,
			"Password is too short"));
	case 23:
		return(dgettext(TEXT_DOMAIN,
			"Password does not contain enough character classes"));
	case 24:
		return(dgettext(TEXT_DOMAIN,
			"Password is in the password dictionary"));
	case 25:
		return(dgettext(TEXT_DOMAIN,
			"Cannot reuse password"));
	case 26:
		return(dgettext(TEXT_DOMAIN,
			"Current password's minimum life has not expired"));
	case 27:
		return(dgettext(TEXT_DOMAIN,
			"Policy is in use"));
	case 28:
		return(dgettext(TEXT_DOMAIN,
			"Connection to server already initialized"));
	case 29:
		return(dgettext(TEXT_DOMAIN,
			"Incorrect password"));
	case 30:
		return(dgettext(TEXT_DOMAIN,
			"Cannot change protected principal"));
	case 31:
		return(dgettext(TEXT_DOMAIN,
			"Programmer error! Bad Admin server handle"));
	case 32:
		return(dgettext(TEXT_DOMAIN,
			"Programmer error! Bad API structure version"));
	case 33:
		return(dgettext(TEXT_DOMAIN,
			"API structure version specified by application is no longer supported (to fix, recompile application against current KADM5 API header files and libraries)"));
	case 34:
		return(dgettext(TEXT_DOMAIN,
			"API structure version specified by application is unknown to libraries (to fix, obtain current KADM5 API header files and libraries and recompile application)"));
	case 35:
		return(dgettext(TEXT_DOMAIN,
			"Programmer error! Bad API version"));
	case 36:
		return(dgettext(TEXT_DOMAIN,
			"API version specified by application is no longer supported by libraries (to fix, update application to adhere to current API version and recompile)"));
	case 37:
		return(dgettext(TEXT_DOMAIN,
			"API version specified by application is no longer supported by server (to fix, update application to adhere to current API version and recompile)"));
	case 38:
		return(dgettext(TEXT_DOMAIN,
			"API version specified by application is unknown to libraries (to fix, obtain current KADM5 API header files and libraries and recompile application)"));
	case 39:
		return(dgettext(TEXT_DOMAIN,
			"API version specified by application is unknown to server (to fix, obtain and install newest KADM5 Admin Server)"));
	case 40:
		return(dgettext(TEXT_DOMAIN,
			"Database error! Required KADM5 principal missing"));
	case 41:
		return(dgettext(TEXT_DOMAIN,
			"The salt type of the specified principal does not support renaming"));
	case 42:
		return(dgettext(TEXT_DOMAIN,
			"Illegal configuration parameter for remote KADM5 client"));
	case 43:
		return(dgettext(TEXT_DOMAIN,
			"Illegal configuration parameter for local KADM5 client"));
	case 44:
		return(dgettext(TEXT_DOMAIN,
			"Operation requires ``list'' privilege"));
	case 45:
		return(dgettext(TEXT_DOMAIN,
			"Operation requires ``change-password'' privilege"));
	case 46:
		return(dgettext(TEXT_DOMAIN,
			"GSS-API (or Kerberos) error"));
	case 47:
		return(dgettext(TEXT_DOMAIN,
			"Programmer error! Illegal tagged data list type"));
	case 48:
		return(dgettext(TEXT_DOMAIN,
			"Required parameters in kdc.conf missing"));
	case 49:
		return(dgettext(TEXT_DOMAIN,
			"Bad krb5 admin server hostname"));
	case 50:
		return(dgettext(TEXT_DOMAIN,
			"Operation requires ``set-key'' privilege"));
	case 51:
		return(dgettext(TEXT_DOMAIN,
			"Multiple values for single or folded enctype"));
	case 52:
		return(dgettext(TEXT_DOMAIN,
			"Invalid enctype for setv4key"));
	case 53:
		return(dgettext(TEXT_DOMAIN,
			"Mismatched enctypes for setkey3"));
	case 54:
		return(dgettext(TEXT_DOMAIN,
			" RPC client cannot encode arguments."));
	case 55:
		return(dgettext(TEXT_DOMAIN,
			" RPC server cannot decode arguments."));
	default:
		return("unknown error");
	}
}
