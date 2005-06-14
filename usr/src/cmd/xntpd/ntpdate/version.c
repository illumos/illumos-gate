/*
 * Copyright 1996, 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * version file for ntpdate
 */
#include <config.h>

#define	PATCH   ""

const char *Version = "ntpdate "
    PROTOCOL_VER "-" VERSION "+" VENDOR PATCH " %E% %U% (%I%)";
