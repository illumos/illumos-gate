/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
 
#include <locale.h>
const char *
kpws_error_table(long errorno) {

switch (errorno) {
	case 0:
		return(dgettext(TEXT_DOMAIN,
			"Usage: kpasswd [principal_name]."));
	case 1:
		return(dgettext(TEXT_DOMAIN,
			"Kerberos principal name %s is not recognized."));
	case 2:
		return(dgettext(TEXT_DOMAIN,
			"while reading principal name from credential cache."));
	case 3:
		return(dgettext(TEXT_DOMAIN,
			"Old Kerberos password is incorrect. Please try again."));
	case 4:
		return(dgettext(TEXT_DOMAIN,
			"Cannot establish a session with the Kerberos "
			"administrative server for realm %s. %s."));
	case 5:
		return(dgettext(TEXT_DOMAIN,
			"New passwords do not match - password not changed.\n"));
	case 6:
		return(dgettext(TEXT_DOMAIN,
			"Kerberos password changed.\n"));
	case 7:
		return(dgettext(TEXT_DOMAIN,
			"Password not changed."));
	case 8:
		return(dgettext(TEXT_DOMAIN,
			"when parsing name %s."));
	case 9:
		return(dgettext(TEXT_DOMAIN,
			"when unparsing name."));
	case 10:
		return(dgettext(TEXT_DOMAIN,
			"Unable to identify user from password file."));
	case 11:
		return(dgettext(TEXT_DOMAIN,
			"Changing password for %s."));
	case 12:
		return(dgettext(TEXT_DOMAIN,
			"Old password"));
	case 13:
		return(dgettext(TEXT_DOMAIN,
			"while reading new password."));
	case 14:
		return(dgettext(TEXT_DOMAIN,
			"You must type a password. "
			"Passwords must be at least one character long."));
	case 15:
		return(dgettext(TEXT_DOMAIN,
			"while trying to change password."));
	case 16:
		return(dgettext(TEXT_DOMAIN,
			"while closing session with admin server and "
		"destroying tickets."));
	case 17:
		return(dgettext(TEXT_DOMAIN,
			"while freeing admin principal entry"));
	case 18:
		return(dgettext(TEXT_DOMAIN,
			"while freeing admin policy entry"));
	case 19:
		return(dgettext(TEXT_DOMAIN,
			"Could not get password policy information for principal %s."));
	case 20:
		return(dgettext(TEXT_DOMAIN,
			"%s's password is controlled by the policy %s which\n"
		"requires a minimum of %u characters from at least %u classes \n"
		"(the five classes are lowercase, uppercase, numbers, punctuation,\n"
		"and all other characters)."));
	default:
		return("unknown error");
	}
}
