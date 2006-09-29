/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <pwd.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/door.h>
#include <errno.h>
#include <fcntl.h>
#include <synch.h>
#include <getxby_door.h>
#include "nss.h"

#ifdef PIC

struct hostent *
_door_gethostbyname_r(const char *name, struct hostent *result, char *buffer,
	int buflen, int *h_errnop)
{
	return ((struct hostent *)_switch_gethostbyname_r(name,
		    result, buffer, buflen, h_errnop));
}

struct hostent *
_door_gethostbyaddr_r(const char *addr, int length, int type,
	struct hostent *result, char *buffer, int buflen, int *h_errnop)
{
	return ((struct hostent *)_switch_gethostbyaddr_r(addr,
		    length, type, result, buffer, buflen, h_errnop));
}

#endif /* PIC */
