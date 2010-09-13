/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
const char *
ovku_error_table(long errorno) {

switch (errorno) {
	case 0:
		return (dgettext(TEXT_DOMAIN,
			"while getting policy info.\n"));
	case 1:
		return (dgettext(TEXT_DOMAIN,
			"while getting principal info.\n"));
	case 2:
		return (dgettext(TEXT_DOMAIN,
			"New passwords do not match - password not "
				"changed.\n"));
	case 3:
		return (dgettext(TEXT_DOMAIN,
			"New password"));
	case 4:
		return (dgettext(TEXT_DOMAIN,
			"New password (again)"));
	case 5:
		return (dgettext(TEXT_DOMAIN,
			"You must type a password. Passwords"
			"must be at least one character long.\n"));
	case 6:
		return (dgettext(TEXT_DOMAIN,
			"yet no policy set!  Contact your "
			"system security administrator.\n"));
	case 7:
		return (dgettext(TEXT_DOMAIN,
			"Password changed.\n"));
	case 8:
		return (dgettext(TEXT_DOMAIN,
			"New password was found in a "
				"dictionary of possible passwords "
				"and therefore may be easily "
				"guessed.\nPlease choose another "
				"password.\nSee "
				"the kpasswd man page for help in "
				"choosing a "
				"good password.\n"));
	case 9:
		return (dgettext(TEXT_DOMAIN,
			"Password not changed.\n"));
	case 10:
		return (dgettext(TEXT_DOMAIN,
			"New password is too short.\nPlease "
				"choose a "
				"password which is at least %d "
				"characters long.\n"));
	case 11:
		return (dgettext(TEXT_DOMAIN,
			"New password does not have enough "
				"character classes.\nThe character "
				"classes are:\n"
				"	- lower-case letters,\n"
				"	- upper-case letters,\n"
				"	- digits,\n"
				"	- punctuation, and\n"
				"	- all "
				"other characters (e.g., control characters).\n"
				"Please choose a password with at least %d "
				"character classes.\n"));
	case 12:
		return (dgettext(TEXT_DOMAIN,
			"Password cannot be changed because it was "
				"changed too recently.\nPlease wait until %s "
				"before you change it.\nIf you need to change "
				"your password before then, "
				"contact your system "
				"security administrator.\n"));
	case 13:
		return (dgettext(TEXT_DOMAIN,
			"New password was used previously."
				" Please choose "
				"a different password.\n"));
	case 14:
		return (dgettext(TEXT_DOMAIN,
			"while trying to change password.\n"));
	case 15:
		return (dgettext(TEXT_DOMAIN,
			"while reading new password.\n"));
	default:
		return ("unknown error");
	}
}
