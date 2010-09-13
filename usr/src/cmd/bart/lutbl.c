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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dirent.h>
#include <fnmatch.h>
#include "bart.h"


struct cmd_keyword {
	char    *ck_name;
	void    (*ck_func)(void);
};

static struct attr_keyword attr_keywords[] = {
	{ ALL_KEYWORD,	~0 },
	{ CONTENTS_KEYWORD,	ATTR_CONTENTS },
	{ TYPE_KEYWORD,	ATTR_TYPE },
	{ SIZE_KEYWORD,	ATTR_SIZE },
	{ MODE_KEYWORD,	ATTR_MODE },
	{ ACL_KEYWORD,	ATTR_ACL },
	{ UID_KEYWORD,	ATTR_UID },
	{ GID_KEYWORD,	ATTR_GID },
	{ MTIME_KEYWORD,	ATTR_MTIME },
	{ LNMTIME_KEYWORD,	ATTR_LNMTIME },
	{ DIRMTIME_KEYWORD,	ATTR_DIRMTIME },
	{ DEST_KEYWORD,	ATTR_DEST },
	{ DEVNODE_KEYWORD,	ATTR_DEVNODE },
	{ ADD_KEYWORD,	ATTR_ADD },
	{ DELETE_KEYWORD,	ATTR_DELETE },
	{ NULL }
};

struct attr_keyword *
attr_keylookup(char *word)
{
	struct attr_keyword	*akp;

	for (akp = attr_keywords; ; akp++) {
		if (akp->ak_name == NULL)
			break;
		if (strcasecmp(word, akp->ak_name) == 0)
			return (akp);
	}
	return (NULL);
}
