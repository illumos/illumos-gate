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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <time.h>
#include <rpcsvc/nis.h>
#include "nis_proc.h"
#include <nis_servlist.h>
#include <ldap_util.h>

int
beginTransaction(void) {
	return (begin_transaction(nis_local_principal()));
}

int
endTransaction(int xid, nis_object *dirObj) {
	int	ret, master;

	/* Are we the master for the directory ? */
	if (dirObj != 0 && dirObj->zo_data.zo_type == NIS_DIRECTORY_OBJ &&
			dirObj->DI_data.do_servers.do_servers_len > 1 &&
			nis_isserving(dirObj) == 1) {
		master = 1;
	} else {
		master = 0;
	}

	/*
	 * End the trans.log operation. If we're the master, we also
	 * modify the update time cache, otherwise not.
	 */
	ret = end_transaction_x(xid, master);

	/*
	 * If we're the master, and there are replicas, make a note to
	 * ping them.
	 */
	if (master) {
		ulong_t	ttime = last_update(dirObj->DI_data.do_name);

		add_pingitem(dirObj, ttime, &ping_list);
	}

	return (ret);
}

extern void	flush_local_dircache(nis_name name);

int
addUpdate(log_entry_t type, char *name, int numAttr, nis_attr *attr,
		nis_object *obj, nis_object *oldDir, uint32_t ttime) {
	log_entry	le;
	__nis_buffer_t	b = {0, 0};
	char		*myself = "addUpdate";

	if (name == 0 || obj == 0)
		return (-1);

	/* Supply current time for log entry, if the caller specified zero */
	if (ttime == 0)
		ttime = time(0);

	le.le_time = ttime;
	le.le_type = type;
	le.le_princp = nis_local_principal();
	le.le_name = name;
	le.le_attrs.le_attrs_val = attr;
	le.le_attrs.le_attrs_len = numAttr;
	le.le_object = *obj;

	add_update(&le);

	/* Flush the relevant caches */
	switch (obj->zo_data.zo_type) {
	case NIS_DIRECTORY_OBJ:
		/*
		 * Since flush_dircache() looks for a new version in the
		 * directory cache (assuming it's been flushed by the update,
		 * which doesn't happen in our case), we first need to flush
		 * the rpc.nisd dir cache.
		 */
		flush_local_dircache(obj->DI_data.do_name);
		flush_dircache(obj->DI_data.do_name, &obj->DI_data);
		/*
		 * If an old (pre-mod) directory object was supplied, and
		 * we were the master for that object, tell all replicas
		 * (of the old incarnation) to flush it from their caches.
		 */
		if (oldDir != 0 && nis_isserving(oldDir) == 1) {
			nis_taglist	taglist;
			nis_tag		tags;

			tags.tag_type = TAG_DCACHE_ONE_REFRESH;
			tags.tag_val = oldDir->DI_data.do_name;
			taglist.tags.tags_len = 1;
			taglist.tags.tags_val = &tags;
			(void) nis_mcast_tags(&oldDir->DI_data, &taglist);
		}
		break;
	case NIS_TABLE_OBJ:
		bp2buf(myself, &b, "%s.%s", obj->zo_name, obj->zo_domain);
		if (b.len > 0) {
			flush_tablecache(b.buf);
			free(b.buf);
		}
		break;
	case NIS_GROUP_OBJ:
		bp2buf(myself, &b, "%s.%s", obj->zo_name, obj->zo_domain);
		if (b.len > 0) {
			flush_groupcache(b.buf);
			free(b.buf);
		}
	default:
		break;
	}

	multival_invalidate(obj);

	return (0);
}
