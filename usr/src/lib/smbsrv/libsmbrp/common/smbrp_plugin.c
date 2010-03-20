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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * SMB plugin for reparse point operations.
 * For more details refer to section 5.4 of PSARC/2009/387
 */

#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <syslog.h>
#include "rp_plugin.h"

#include <smbsrv/smb_dfs.h>

static char *smb_rpo_service_type(void);
static boolean_t smb_rpo_supports_svc(const char *);
static int smb_rpo_deref(const char *, const char *, char *, size_t *);
static int smb_rpo_form(const char *, const char *, char *, size_t *);

struct rp_plugin_ops rp_plugin_ops = {
	RP_PLUGIN_V1,
	NULL,			/* rpo_init */
	NULL,			/* rpo_fini */
	smb_rpo_service_type,
	smb_rpo_supports_svc,
	smb_rpo_form,
	smb_rpo_deref
};

/*
 * Reports supported service type
 */
static char *
smb_rpo_service_type(void)
{
	return (DFS_REPARSE_SVCTYPE);
}

/*
 * Determines whether this plugin supports the given service type
 */
static boolean_t
smb_rpo_supports_svc(const char *svc_type)
{
	if (svc_type == NULL)
		return (B_FALSE);

	if (strncasecmp(svc_type, DFS_REPARSE_SVCTYPE,
	    strlen(DFS_REPARSE_SVCTYPE)) == 0)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Accepts the service-specific item from the reparse point and returns the
 * service-specific data requested.  The caller specifies the size of the
 * buffer provided via *bufsz; the routine will fail with EOVERFLOW if
 * the results will not fit in the buffer, in which case, *bufsz will
 * contain the number of bytes needed to hold the results.
 *
 * Currently, there is no transformation is needed to data stored in
 * a reparse point for DFS, so 'buf' will contain the same data as
 * 'svc_data'.
 */
static int
smb_rpo_deref(const char *svc_type, const char *svc_data, char *buf,
    size_t *bufsz)
{
	int slen;

	if ((!svc_type) || (!svc_data) || (!buf) || (!bufsz))
		return (EINVAL);

	if (strcasecmp(svc_type, DFS_REPARSE_SVCTYPE) != 0)
		return (ENOTSUP);

	slen = strlen(svc_data) + 1;

	if (slen > *bufsz) {
		*bufsz = slen;
		return (EOVERFLOW);
	}

	(void) strlcpy(buf, svc_data, *bufsz);

	return (0);
}

/*
 * Returns a string with the appropriate service-specific syntax to create
 * a reparse point of the given svc_type, using the string from the
 * reparse_add() call as part of the string.
 */
static int
smb_rpo_form(const char *svc_type, const char *svc_data, char *buf,
    size_t *bufsz)
{
	int slen;

	if ((!svc_type) || (!svc_data) || (!buf) || (!bufsz))
		return (EINVAL);

	slen = strlen(svc_data) + 1;

	if (slen > *bufsz) {
		*bufsz = slen;
		return (EOVERFLOW);
	}

	(void) strlcpy(buf, svc_data, *bufsz);

	return (0);
}
