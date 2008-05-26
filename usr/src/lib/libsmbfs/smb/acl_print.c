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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Print an NT Security Descriptor (SD) and its sub-components.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/acl.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/byteorder.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <umem.h>
#include <idmap.h>

#include <sys/fs/smbfs_ioctl.h>

#include <netsmb/smb_lib.h>
#include <netsmb/smbfs_acl.h>
#include <netsmb/smbfs_isec.h>

static void
fprint_sid(FILE *fp, i_ntsid_t *sid)
{
	static char sidbuf[256];

	if (sid == NULL) {
		fprintf(fp, "(null)\n");
		return;
	}

	if (smbfs_sid2str(sid, sidbuf, sizeof (sidbuf), NULL) < 0)
		fprintf(fp, "(error)\n");
	else
		fprintf(fp, "%s\n", sidbuf);
}

static void
fprint_ntace(FILE *fp, i_ntace_t *ace)
{
	if (ace == NULL) {
		fprintf(fp, "  (null)\n");
		return;
	}

	/* ACEs are always printed in a list, so indent by 2. */
	fprintf(fp, "  ace_type=%d ace_flags=0x%x ace_rights=0x%x\n",
	    ace->ace_type, ace->ace_flags, ace->ace_rights);
	/* Show the SID as a "continuation" line. */
	fprintf(fp, "    ace_sid: ");
	fprint_sid(fp, ace->ace_sid);
}

static void
fprint_ntacl(FILE *fp, i_ntacl_t *acl)
{
	int i;

	if (acl == NULL) {
		fprintf(fp, "(null)\n");
		return;
	}

	fprintf(fp, "acl_rev=%d acl_acecount=%d\n",
	    acl->acl_revision, acl->acl_acecount);
	for (i = 0; i < acl->acl_acecount; i++)
		fprint_ntace(fp, acl->acl_acevec[i]);
}

void
smbfs_acl_print_sd(FILE *fp, i_ntsd_t *sd)
{

	fprintf(fp, "sd_rev=%d, flags=0x%x\n",
	    sd->sd_revision, sd->sd_flags);
	fprintf(fp, "owner: ");
	fprint_sid(fp, sd->sd_owner);
	fprintf(fp, "group: ");
	fprint_sid(fp, sd->sd_group);
	fprintf(fp, "sacl: ");
	fprint_ntacl(fp, sd->sd_sacl);
	fprintf(fp, "dacl: ");
	fprint_ntacl(fp, sd->sd_dacl);
}
