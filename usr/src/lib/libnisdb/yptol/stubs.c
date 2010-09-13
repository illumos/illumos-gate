/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * DESCRIPTION:	The N2L system is dependent on a number of utility functions
 *		supplied by NIS object code (under cmd/ypcmd). When libnisdb
 *		is loaded by executable other than those built under
 *		cmd/ypcmd (e.g. the NIS+ executables) these would be
 *		undefined. To prevent this happening the stubs in this file
 *		contain weak definitions on these functions. In the NIS case
 *		these weak definitions will be overridden by the real ones.
 *
 *		The functions in this file will never be called. NIS will have
 *		overridden them and nothing else should call yptol. If they are
 *		called then there is a bug in the build system.
 *
 *		Note : This is not elegant but it is a way of dealing with
 *		preexisting code structure.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <syslog.h>
#include <sys/mman.h>
#include <thread.h>
#include <synch.h>
#include <ndbm.h>
#include "ypsym.h"
#include "shim.h"
#include "../ldap_util.h"


/*
 * FUNCTION :	disaster()
 *
 * DESCRIPTION:	Called if the stubs is accidentally called.
 */
void
disaster()
{
	logmsg(MSG_NOTIMECHECK, LOG_ERR, "YPTOL stub called. This indicates"
						" a serious build error");
}

#pragma weak lock_core
int
lock_core(int hashval)
{
	disaster();
	return (0);
}

#pragma weak unlock_core
int
unlock_core(int hashval)
{
	disaster();
	return (0);
}

#pragma weak lock_map
int
lock_map(char *mapname)
{
	disaster();
	return (0);
}

#pragma weak unlock_map
int
unlock_map(char *mapname)
{
	disaster();
	return (0);
}

#pragma weak init_lock_map
bool
init_lock_map()
{
	disaster();
	return (FALSE);
}

#pragma weak hash
int
hash(char *s)
{
	disaster();
	return (0);
}

#pragma weak rename_map
bool
rename_map(char *from, char *to, bool_t secure_map)
{
	disaster();
	return (FALSE);
}

#pragma weak delete_map
bool
delete_map(char *name)
{
	disaster();
	return (FALSE);
}

#pragma weak single
#pragma weak nogecos
#pragma weak noshell
#pragma weak nopw
#pragma weak mflag
int single, nogecos, noshell, nopw, mflag;

#pragma weak validloginshell
bool_t
validloginshell(char *sh, char *arg, int priv)
{
	disaster();
	return (0);
}

#pragma weak validstr
int
validstr(char *str, size_t size)
{
	disaster();
	return (0);
}
