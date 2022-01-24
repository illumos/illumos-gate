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
 * Copyright 2019 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This dtrace script shows how to track down the owners of locks
 * that prevent I/O in filesystems with mandatory locking enabled
 * (eg. ZFS with nbmand=on).  This script is not in any way specific
 * to SMB, but this problem is most often seen when SMB is in use
 * because SMB requires mandatory locking semantics.
 *
 * Run this script, eg. dtrace -s nbl-conflict.d
 * taking note of these fields in the dtrace output:
 *	conflict_lock:  .l_sysid .l_pid
 *	conflict_shrlock: .s_sysid .s_pid
 *
 * The sysid values tell you if a local or remote owner has the
 * lock or share preventing I/O, and the pid tells which process.
 */

sdt::nbl_lock_conflict:conflict_lock
{
	this->lock = (lock_descriptor_t *)arg0;
	print(this->lock->l_flock);
}

sdt::nbl_share_conflict:conflict_shrlock
{
	this->shrl = (struct shrlock *)arg0;
	print(*(this->shrl));
}

/*
 * The above probe action in nbl_share_conflict shows conflicts
 * with read/write operations (eg. from the NFS server).
 * This probe action shows share reservation conflicts at open.
 * (Remove this if you're only interested in I/O conflicts.)
 */
sdt::add_share:conflict_shrlock
{
	this->shrl = (struct shrlock *)arg0;
	print(*(this->shrl));
}
