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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This is an extract from usr/src/common/smbsrv/smb_sid.c,
 * with functions renamed as part of a tentative plan for convergence.
 */
#ifndef _KERNEL
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <syslog.h>
#else /* _KERNEL */
#include <sys/types.h>
#include <sys/sunddi.h>
#endif /* _KERNEL */

#include <sidutil.h>

/*
 * sid_len
 *
 * Returns the number of bytes required to hold the sid.
 */
int
sid_len(sid_t *sid)
{
	if (sid == NULL)
		return (0);

	return (sizeof (sid_t) - sizeof (uint32_t)
	    + (sid->sid_subauthcnt * sizeof (uint32_t)));
}

/*
 * sid_tostr
 *
 * Fill in the passed buffer with the string form of the given
 * binary sid.
 */
void
sid_tostr(sid_t *sid, char *strsid)
{
	char *p = strsid;
	int i;

	if (sid == NULL || strsid == NULL)
		return;

	(void) sprintf(p, "S-%d-", sid->sid_revision);
	while (*p)
		p++;

	for (i = 0; i < NT_SID_AUTH_MAX; ++i) {
		if (sid->sid_authority[i] != 0 || i == NT_SID_AUTH_MAX - 1) {
			(void) sprintf(p, "%d", sid->sid_authority[i]);
			while (*p)
				p++;
		}
	}

	for (i = 0; i < sid->sid_subauthcnt && i < NT_SID_SUBAUTH_MAX; ++i) {
		(void) sprintf(p, "-%u", sid->sid_subauth[i]);
		while (*p)
			p++;
	}
}

/*
 * sid_fromstr
 *
 * Converts a SID in string form to a SID structure. There are lots of
 * simplifying assumptions in here. The memory for the SID is allocated
 * as if it was the largest possible SID; the caller is responsible for
 * freeing the memory when it is no longer required. We assume that the
 * string starts with "S-1-" and that the authority is held in the last
 * byte, which should be okay for most situations. It also assumes the
 * sub-authorities are in decimal format.
 *
 * On success, a pointer to a SID is returned. Otherwise a null pointer
 * is returned.
 */
sid_t *
sid_fromstr(char *sidstr)
{
	sid_t *sid;
	char *p;
	int size;
	uint8_t i;

	if (sidstr == NULL)
		return (NULL);

	if (strncmp(sidstr, "S-1-", 4) != 0)
		return (NULL);

	size = sizeof (sid_t) + (NT_SID_SUBAUTH_MAX * sizeof (uint32_t));

	if ((sid = malloc(size)) == NULL)
		return (NULL);

	bzero(sid, size);
	sid->sid_revision = NT_SID_REVISION;
	sid->sid_authority[5] = atoi(&sidstr[4]);

	for (i = 0, p = &sidstr[5]; i < NT_SID_SUBAUTH_MAX && *p; ++i) {
		while (*p && *p == '-')
			++p;

		if (*p < '0' || *p > '9') {
			free(sid);
			return (NULL);
		}

		sid->sid_subauth[i] = strtoul(p, NULL, 10);

		while (*p && *p != '-')
			++p;
	}

	sid->sid_subauthcnt = i;
	return (sid);
}

void
sid_free(sid_t *sid)
{
#ifdef _KERNEL
	if (sid == NULL)
		return;

	kmem_free(sid, sid_len(sid));
#else
	free(sid);
#endif
}

void
sid_to_le(sid_t *sid)
{
	int i;

	for (i = 0; i < sid->sid_subauthcnt && i < NT_SID_SUBAUTH_MAX; ++i) {
		uint32_t v = sid->sid_subauth[i];
		uint8_t *p = (uint8_t *)&sid->sid_subauth[i];

		p[0] = v & 0xff;
		p[1] = (v >> 8) & 0xff;
		p[2] = (v >> 16) & 0xff;
		p[3] = (v >> 24) & 0xff;
	}
}

void
sid_from_le(sid_t *sid)
{
	int i;

	for (i = 0; i < sid->sid_subauthcnt && i < NT_SID_SUBAUTH_MAX; ++i) {
		uint32_t v;
		uint8_t *p = (uint8_t *)&sid->sid_subauth[i];

		v = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);

		sid->sid_subauth[i] = v;
	}
}
