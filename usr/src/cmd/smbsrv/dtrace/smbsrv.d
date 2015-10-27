#!/usr/sbin/dtrace -s
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Developer dtrace program for smbsrv
 * Usage: dtrace -s smbsrv.d
 */

#pragma D option flowindent

self int trace;
self int mask;

/*
 * Trace almost everything
 */
fbt:smbsrv::entry
{
	self->trace++;
}

/*
 * If traced and not masked, print entry/return
 */
fbt:smbsrv::entry
/self->trace > 0 && self->mask == 0/
{
	printf("\t0x%x", arg0);
	printf("\t0x%x", arg1);
	printf("\t0x%x", arg2);
	printf("\t0x%x", arg3);
	printf("\t0x%x", arg4);
	printf("\t0x%x", arg5);
}

/*
 * Mask (don't print) all function calls below these functions.
 * These make many boring, repetitive function calls like
 * smb_mbtowc, mbc_marshal_...
 */
fbt::smb_mbc_vdecodef:entry,
fbt::smb_mbc_vencodef:entry,
fbt::smb_msgbuf_decode:entry,
fbt::smb_msgbuf_encode:entry,
fbt::smb_strlwr:entry,
fbt::smb_strupr:entry,
fbt::smb_wcequiv_strlen:entry
{
	self->mask++;
}

/*
 * Now inverses of above, unwind order.
 */

fbt::smb_mbc_vdecodef:return,
fbt::smb_mbc_vencodef:return,
fbt::smb_msgbuf_decode:return,
fbt::smb_msgbuf_encode:return,
fbt::smb_strlwr:return,
fbt::smb_strupr:return,
fbt::smb_wcequiv_strlen:return
{
	self->mask--;
}

fbt:smbsrv::return
/self->trace > 0 && self->mask == 0/
{
	printf("\t0x%x", arg1);
}

fbt:smbsrv::return
{
	self->trace--;
}
