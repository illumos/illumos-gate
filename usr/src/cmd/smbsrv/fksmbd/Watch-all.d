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
 * User-level dtrace for fksmbd
 * Usage: dtrace -s Watch-all.d -p $PID
 */

#pragma D option flowindent

self int trace;
self int mask;

/*
 * Trace almost everything
 */
pid$target:fksmbd::entry,
pid$target:libfksmbsrv.so.1::entry,
pid$target:libmlsvc.so.1::entry,
pid$target:libmlrpc.so.1::entry,
pid$target:libsmbns.so.1::entry,
pid$target:libsmb.so.1::entry
{
  self->trace++;
}

/*
 * If traced and not masked, print entry/return
 */
pid$target:fksmbd::entry,
pid$target:libfksmbsrv.so.1::entry,
pid$target:libmlsvc.so.1::entry,
pid$target:libmlrpc.so.1::entry,
pid$target:libsmbns.so.1::entry,
pid$target:libsmb.so.1::entry
/self->trace > 0 && self->mask == 0/
{
  printf("\t0x%x", arg0);
  printf("\t0x%x", arg1);
  printf("\t0x%x", arg2);
  printf("\t0x%x", arg3);
}

/*
 * Mask (don't print) all function calls below these functions.
 * These make many boring, repetitive function calls like
 * smb_mbtowc, mbc_marshal_...
 */
pid$target::fop__getxvattr:entry,
pid$target::fop__setxvattr:entry,
pid$target::smb_mbc_vdecodef:entry,
pid$target::smb_mbc_vencodef:entry,
pid$target::smb_msgbuf_decode:entry,
pid$target::smb_msgbuf_encode:entry,
pid$target::smb_strlwr:entry,
pid$target::smb_strupr:entry,
pid$target::smb_wcequiv_strlen:entry
{
  self->mask++;
}

/*
 * Now inverses of above, unwind order.
 */

pid$target::fop__getxvattr:return,
pid$target::fop__setxvattr:return,
pid$target::smb_mbc_vdecodef:return,
pid$target::smb_mbc_vencodef:return,
pid$target::smb_msgbuf_decode:return,
pid$target::smb_msgbuf_encode:return,
pid$target::smb_strlwr:return,
pid$target::smb_strupr:return,
pid$target::smb_wcequiv_strlen:return
{
  self->mask--;
}

pid$target:fksmbd::return,
pid$target:libfksmbsrv.so.1::return,
pid$target:libmlsvc.so.1::return,
pid$target:libmlrpc.so.1::return,
pid$target:libsmbns.so.1::return,
pid$target:libsmb.so.1::return
/self->trace > 0 && self->mask == 0/
{
  printf("\t0x%x", arg1);
}

pid$target:fksmbd::return,
pid$target:libfksmbsrv.so.1::return,
pid$target:libmlsvc.so.1::return,
pid$target:libmlrpc.so.1::return,
pid$target:libsmbns.so.1::return,
pid$target:libsmb.so.1::return
{
  self->trace--;
}
