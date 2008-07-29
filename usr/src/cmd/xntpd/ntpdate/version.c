/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * version file for ntpdate
 */
#include <config.h>

#define	PATCH   ""

const char *Version = "ntpdate "
    PROTOCOL_VER "-" VERSION "+" VENDOR PATCH " 03/06/05 23:16:45 (1.4)";
