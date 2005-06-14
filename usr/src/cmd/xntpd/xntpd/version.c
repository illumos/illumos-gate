/*
 * Copyright 1996, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * version file for xntpd
 */

#include <config.h>

#define	PATCH   ""

const char *Version = "xntpd "
    PROTOCOL_VER "-" VERSION "+" VENDOR PATCH " %E% %U% (%I%)";
