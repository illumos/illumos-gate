/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * version file for xntpd
 */

#include <config.h>

#define	PATCH   ""

const char *Version = "xntpd "
    PROTOCOL_VER "-" VERSION "+" VENDOR PATCH " 03/08/29 16:23:05 (1.4)";
