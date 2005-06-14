/*
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
 
#include <locale.h>
const char *
imp_error_table(long errorno) {

switch (errorno) {
	case 0:
		return(dgettext(TEXT_DOMAIN,
			"Successfully imported %d record%s.n"));
	case 1:
		return(dgettext(TEXT_DOMAIN,
			"Input not recognized as database dump"));
	case 2:
		return(dgettext(TEXT_DOMAIN,
			"Bad token in dump file."));
	case 3:
		return(dgettext(TEXT_DOMAIN,
			"Bad version in dump file"));
	case 4:
		return(dgettext(TEXT_DOMAIN,
			"Defective record encountered: "));
	case 5:
		return(dgettext(TEXT_DOMAIN,
			"Truncated input file detected."));
	case 6:
		return(dgettext(TEXT_DOMAIN,
			"Import of dump failed"));
	case 7:
		return(dgettext(TEXT_DOMAIN,
			"Mismatched record count: %d record%s indicated %d record%s scanned"));
	case 8:
		return(dgettext(TEXT_DOMAIN,
			"Number of records imported does not match count"));
	case 9:
		return(dgettext(TEXT_DOMAIN,
			"Unknown command line option.nUsage: ovsec_adm_import [filename]"));
	case 10:
		return(dgettext(TEXT_DOMAIN,
			"Warning -- continuing to import will overwrite existing databases!"));
	case 11:
		return(dgettext(TEXT_DOMAIN,
			"Database rename Failed!!"));
	case 12:
		return(dgettext(TEXT_DOMAIN,
			"Extra data after footer is ignored."));
	case 13:
		return(dgettext(TEXT_DOMAIN,
			"Proceed <y|n>?"));
	case 14:
		return(dgettext(TEXT_DOMAIN,
			"while opening input file"));
	case 15:
		return(dgettext(TEXT_DOMAIN,
			"while importing databases"));
	case 16:
		return(dgettext(TEXT_DOMAIN,
			"cannot open /dev/tty!!"));
	case 17:
		return(dgettext(TEXT_DOMAIN,
			"while opening databases"));
	case 18:
		return(dgettext(TEXT_DOMAIN,
			"while acquiring permanent lock"));
	case 19:
		return(dgettext(TEXT_DOMAIN,
			"while releasing permanent lock"));
	case 20:
		return(dgettext(TEXT_DOMAIN,
			"while closing databases"));
	case 21:
		return("");
	case 22:
		return("s");
	case 23:
		return(dgettext(TEXT_DOMAIN,
			"while retrieving configuration parameters"));
	default:
		return("unknown error");
	}
}
