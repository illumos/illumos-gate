/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
const char *
prof_error_table(long errorno) {

switch (errorno) {
	case 0:
		return(dgettext(TEXT_DOMAIN,
			"Profile version 0.0"));
	case 1:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic value in profile_node"));
	case 2:
		return(dgettext(TEXT_DOMAIN,
			"Profile section not found"));
	case 3:
		return(dgettext(TEXT_DOMAIN,
			"Profile relation not found"));
	case 4:
		return(dgettext(TEXT_DOMAIN,
			"Attempt to add a relation to node which is not a section"));
	case 5:
		return(dgettext(TEXT_DOMAIN,
			"A profile section header has a non-zero value"));
	case 6:
		return(dgettext(TEXT_DOMAIN,
			"Bad linked list in profile structures"));
	case 7:
		return(dgettext(TEXT_DOMAIN,
			"Bad group level in profile structures"));
	case 8:
		return(dgettext(TEXT_DOMAIN,
			"Bad parent pointer in profile structures"));
	case 9:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic value in profile iterator"));
	case 10:
		return(dgettext(TEXT_DOMAIN,
			"Can't set value on section node"));
	case 11:
		return(dgettext(TEXT_DOMAIN,
			"Invalid argument passed to profile library"));
	case 12:
		return(dgettext(TEXT_DOMAIN,
			"Attempt to modify read-only profile"));
	case 13:
		return(dgettext(TEXT_DOMAIN,
			"Profile section header not at top level"));
	case 14:
		return(dgettext(TEXT_DOMAIN,
			"Syntax error in profile section header"));
	case 15:
		return(dgettext(TEXT_DOMAIN,
			"Syntax error in profile relation"));
	case 16:
		return(dgettext(TEXT_DOMAIN,
			"Extra closing brace in profile"));
	case 17:
		return(dgettext(TEXT_DOMAIN,
			"Missing open brace in profile"));
	case 18:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic value in profile_t"));
	case 19:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic value in profile_section_t"));
	case 20:
		return(dgettext(TEXT_DOMAIN,
			"Iteration through all top level section not supported"));
	case 21:
		return(dgettext(TEXT_DOMAIN,
			"Invalid profile_section object"));
	case 22:
		return(dgettext(TEXT_DOMAIN,
			"No more sections"));
	case 23:
		return(dgettext(TEXT_DOMAIN,
			"Bad nameset passed to query routine"));
	case 24:
		return(dgettext(TEXT_DOMAIN,
			"No profile file open"));
	case 25:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic value in profile_file_t"));
	case 26:
		return(dgettext(TEXT_DOMAIN,
			"Couldn't open profile file"));
	case 27:
		return(dgettext(TEXT_DOMAIN,
			"Section already exists"));
	case 28:
		return(dgettext(TEXT_DOMAIN,
			"Invalid boolean value"));
	case 29:
		return(dgettext(TEXT_DOMAIN,
			"Invalid integer value"));
	case 30:
		return(dgettext(TEXT_DOMAIN,
			"Bad magic value in profile_file_data_t"));
	default:
		return("unknown error");
	}
}
