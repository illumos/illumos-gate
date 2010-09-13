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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include "libelf.h"
#include "decl.h"
#include "msg.h"


Elf_Data *
elf_rawdata(Elf_Scn * scn, Elf_Data * data)
{
	Dnode *		d = (Dnode *)data;
	Dnode *		raw;
	Elf_Data *	rc;
	Elf *		elf;

	if (scn == 0)
		return (0);
	elf = scn->s_elf;
	READLOCKS(elf, scn)
	if ((scn->s_myflags & SF_READY) == 0) {
		UPGRADELOCKS(elf, scn)
		if ((scn->s_myflags & SF_READY) == 0)
			(void) _elf_cookscn(scn);
		DOWNGRADELOCKS(elf, scn)
	}

	if (d == 0)
		d = scn->s_hdnode;
	else
		d = d->db_next;

	if (d == 0) {
		READUNLOCKS(elf, scn)
		return (0);
	}

	if (d->db_scn != scn) {
		_elf_seterr(EREQ_DATA, 0);
		READUNLOCKS(elf, scn)
		return (0);
	}

	/*
	 * The data may come from a previously constructed Dbuf,
	 * from the file's raw memory image, or the file system.
	 * "Empty" regions get an empty buffer.
	 */

	if (d->db_raw != 0) {
		rc = &d->db_raw->db_data;
		READUNLOCKS(elf, scn)
		return (rc);
	}

	if ((raw = _elf_dnode()) == 0)  {
		READUNLOCKS(elf, scn)
		return (0);
	}
	raw->db_myflags |= DBF_READY;
	if ((d->db_off == 0) || (d->db_fsz == 0)) {
		d->db_raw = raw;
		raw->db_data.d_size = d->db_shsz;
		rc = &raw->db_data;
		READUNLOCKS(elf, scn)
		return (rc);
	}

	/*
	 * validate the region
	 */

	if ((d->db_off < 0) ||
	    (d->db_off >= elf->ed_fsz) ||
	    (elf->ed_fsz - d->db_off < d->db_fsz)) {
		_elf_seterr(EFMT_DATA, 0);
		free(raw);
		READUNLOCKS(elf, scn)
		return (0);
	}
	raw->db_data.d_size = d->db_fsz;
	if (elf->ed_raw != 0) {
		raw->db_data.d_buf = (Elf_Void *)(elf->ed_raw + d->db_off);
		d->db_raw = raw;
		rc = &raw->db_data;
		READUNLOCKS(elf, scn)
		return (rc);
	}
	raw->db_buf = (Elf_Void *)_elf_read(elf->ed_fd,
	    elf->ed_baseoff + d->db_off, d->db_fsz);
	if (raw->db_buf == 0) {
		free(raw);
		READUNLOCKS(elf, scn)
		return (0);
	}
	raw->db_data.d_buf = raw->db_buf;
	d->db_raw = raw;
	rc = &raw->db_data;
	READUNLOCKS(elf, scn)
	return (rc);
}
