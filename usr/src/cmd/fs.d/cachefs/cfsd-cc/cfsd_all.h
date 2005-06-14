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
// ------------------------------------------------------------
//
//			all.h
//
// Include file for the cfsd_all class.
//

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#ifndef CFSD_ALL
#define	CFSD_ALL

class cfsd_all {
private:
	RWCString		 i_machname;		// machine name
	RWTPtrDlist<cfsd_cache>  i_cachelist;		// list of caches
	mutex_t			 i_lock;		// synchronizing lock
	int			 i_nextcacheid;		// for cache ids
	int			 i_modify;		// changed when modified
	// cfsd_hoard		*i_hoardp;		// hoarding class

public:
	cfsd_all();
	~cfsd_all();

	const char *all_machname();

	void all_lock();
	void all_unlock();

	int all_nextcacheid() { return i_nextcacheid++; }
	int all_modify() { return i_modify; }

	size_t all_cachelist_entries();
	cfsd_cache *all_cachelist_at(size_t index);
	void all_cachelist_add(cfsd_cache *cachep);
	cfsd_cache *all_cachelist_find(const char *namep);

	// cfsd_hoard *all_hoard() { return al_hoardp; }
	// void all_hoard(cfsd_hoard *hoardp) { al_hoardp = hoardp; }

	void all_cachefstab_update();
};


#endif /* CFSD_ALL */
