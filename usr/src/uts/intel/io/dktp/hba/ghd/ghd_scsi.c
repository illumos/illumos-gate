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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/byteorder.h>


/*
 * functions to convert between host format and scsi format
 */
void
scsi_htos_3byte(unchar *ap, ulong nav)
{
	*(ushort *)ap = (ushort)(((nav & 0xff0000) >> 16) | (nav & 0xff00));
	ap[2] = (unchar)nav;
}

void
scsi_htos_long(unchar *ap, ulong niv)
{
	*(ulong *)ap = htonl(niv);
}

void
scsi_htos_short(unchar *ap, ushort nsv)
{
	*(ushort *)ap = htons(nsv);
}

ulong
scsi_stoh_3byte(unchar *ap)
{
	register ulong av = *(ulong *)ap;

	return (((av & 0xff) << 16) | (av & 0xff00) | ((av & 0xff0000) >> 16));
}

ulong
scsi_stoh_long(ulong ai)
{
	return (ntohl(ai));
}

ushort
scsi_stoh_short(ushort as)
{
	return (ntohs(as));
}
