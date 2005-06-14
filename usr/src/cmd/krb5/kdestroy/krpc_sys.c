/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <rpc/types.h>
#include <sys/vfs.h>
#include <sys/errno.h>
#include <rpc/auth.h>
#include <rpc/rpcsys.h>
#include <rpc/rpcsec_gss.h>


int
krpc_sys(int cmd, void *args)
{


	return (_rpcsys(cmd, args));

}
