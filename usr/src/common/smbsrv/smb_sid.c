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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * NT Security Identifier (SID) library functions.
 */

#ifndef _KERNEL
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <syslog.h>
#include <smbsrv/libsmb.h>
#else /* _KERNEL */
#include <sys/types.h>
#include <sys/sunddi.h>
#endif /* _KERNEL */

#include <smbsrv/alloc.h>
#include <smbsrv/ntsid.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smbinfo.h>


/*
 * nt_sid_is_valid
 *
 * Check that a sid is valid. The checking is minimal: check the pointer
 * is valid and that the revision and sub-authority count is legal.
 * Returns 1 if the sid appears to be valid. Otherwise 0.
 */
int
nt_sid_is_valid(nt_sid_t *sid)
{
	if (sid == 0)
		return (0);

	return (sid->Revision == NT_SID_REVISION &&
	    sid->SubAuthCount < NT_SID_SUBAUTH_MAX) ? 1 : 0;
}


/*
 * nt_sid_length
 *
 * Returns the number of bytes required to hold the sid.
 */
int
nt_sid_length(nt_sid_t *sid)
{
	if (sid == 0)
		return (0);

	return (sizeof (nt_sid_t) - sizeof (DWORD)
	    + (sid->SubAuthCount * sizeof (DWORD)));
}


/*
 * nt_sid_dup
 *
 * Make a duplicate of the specified sid. The memory for the new sid is
 * allocated using malloc so the caller should call free when it is no
 * longer required. A pointer to the new sid is returned.
 */
nt_sid_t *
nt_sid_dup(nt_sid_t *sid)
{
	nt_sid_t *new_sid;
	int size;
	int i;

	if (sid == 0)
		return (0);

	size = sizeof (nt_sid_t)
	    + (sid->SubAuthCount * sizeof (DWORD))
	    + sizeof (DWORD);

	if ((new_sid = MEM_MALLOC("libnt", size)) == 0)
		return (0);

	(void) memcpy(new_sid, sid, sizeof (nt_sid_t));

	for (i = 0; i < sid->SubAuthCount && i < NT_SID_SUBAUTH_MAX; ++i)
		new_sid->SubAuthority[i] = sid->SubAuthority[i];

	return (new_sid);
}


/*
 * nt_sid_splice
 *
 * Make a full user sid from the domain sid and the user relative id
 * (rid). The memory for the new sid is allocated using malloc so the
 * caller should call free when it is no longer required. A pointer
 * to the new sid is returned.
 */
nt_sid_t *
nt_sid_splice(nt_sid_t *domain_sid, DWORD rid)
{
	nt_sid_t *sid;
	int size;
	int i;

	if (domain_sid == 0)
		return (0);

	size = sizeof (nt_sid_t)
	    + (domain_sid->SubAuthCount * sizeof (DWORD))
	    + sizeof (DWORD);

	if ((sid = MEM_MALLOC("libnt", size)) == 0)
		return (0);

	(void) memcpy(sid, domain_sid, sizeof (nt_sid_t));

	for (i = 0; i < sid->SubAuthCount && i < NT_SID_SUBAUTH_MAX; ++i)
		sid->SubAuthority[i] = domain_sid->SubAuthority[i];

	sid->SubAuthority[i] = rid;
	++sid->SubAuthCount;
	return (sid);
}


/*
 * nt_sid_get_rid
 *
 * Return the Relative Id (RID) from the specified SID. It is the
 * caller's responsibility to ensure that this is an appropriate SID.
 * All we do here is return the last sub-authority from the SID.
 */
int
nt_sid_get_rid(nt_sid_t *sid, DWORD *rid)
{
	if (!nt_sid_is_valid(sid))
		return (-1);

	if (sid->SubAuthCount == 0) {
		return (-1);
	}

	if (rid)
		*rid = sid->SubAuthority[sid->SubAuthCount - 1];
	return (0);
}


/*
 * nt_sid_split
 *
 * Take a full user sid and split it into the domain sid and the user
 * relative id (rid). The original sid is modified in place - use
 * nt_sid_dup before calling this function to preserve the original SID.
 */
int
nt_sid_split(nt_sid_t *sid, DWORD *rid)
{
	if (!nt_sid_is_valid(sid)) {
		return (-1);
	}

	if (sid->SubAuthCount == 0) {
		return (-1);
	}

	--sid->SubAuthCount;
	if (rid)
		*rid = sid->SubAuthority[sid->SubAuthCount];
	return (0);
}


/*
 * nt_sid_gen_null_sid
 *
 * This function allocates a SID structure and initializes it as the
 * well-known Null SID (S-1-0-0). A pointer to the SID is returned.
 * As the memory for this structure is obtained via malloc, it is the
 * caller's responsibility to free the memory when it is no longer
 * required. If malloc fails, a null pointer is returned.
 */
nt_sid_t *
nt_sid_gen_null_sid(void)
{
	nt_sid_t *sid;
	int size;

	size = sizeof (nt_sid_t) + sizeof (DWORD);

	if ((sid = MEM_MALLOC("libnt", size)) == 0) {
		return (0);
	}

	sid->Revision = 1;
	sid->SubAuthCount = 1;
	return (sid);
}


/*
 * nt_sid_is_equal
 *
 * Compare two SIDs and return a boolean result. The checks are ordered
 * such that components that are more likely to differ are checked
 * first. For example, after checking that the SIDs contain the same
 * SubAuthCount, we check the sub-authorities in reverse order because
 * the RID is the most likely differentiator between two SIDs, i.e.
 * they are probably going to be in the same domain.
 *
 * Returns 1 if the SIDs are equal. Otherwise returns 0.
 */
int
nt_sid_is_equal(nt_sid_t *sid1, nt_sid_t *sid2)
{
	int i;

	if (sid1 == 0 || sid2 == 0)
		return (0);

	if (sid1->SubAuthCount != sid2->SubAuthCount ||
	    sid1->Revision != sid2->Revision)
		return (0);

	for (i = sid1->SubAuthCount - 1; i >= 0; --i)
		if (sid1->SubAuthority[i] != sid2->SubAuthority[i])
			return (0);

	if (bcmp(&sid1->Authority, &sid2->Authority, NT_SID_AUTH_MAX))
		return (0);

	return (1);
}

/*
 * nt_sid_is_indomain
 *
 * Check if given SID is in given domain.
 * Returns 1 on success. Otherwise returns 0.
 */
int
nt_sid_is_indomain(nt_sid_t *domain_sid, nt_sid_t *sid)
{
	int i;

	if (sid == 0 || domain_sid == 0) {
		return (0);
	}

	if (domain_sid->Revision != sid->Revision ||
	    sid->SubAuthCount < domain_sid->SubAuthCount)
		return (0);

	for (i = domain_sid->SubAuthCount - 1; i >= 0; --i)
		if (domain_sid->SubAuthority[i] != sid->SubAuthority[i])
			return (0);

	if (bcmp(&domain_sid->Authority, &sid->Authority, NT_SID_AUTH_MAX))
		return (0);

	return (1);
}

#ifndef _KERNEL
/*
 * nt_sid_is_local
 *
 * Check a SID to see if it belongs to the local domain. This is almost
 * the same as checking that two SIDs are equal except that we don't
 * care if the specified SID contains extra sub-authorities. We're only
 * interested in the domain part.
 *
 * Returns 1 if the SIDs are equal. Otherwise returns 0.
 */
int
nt_sid_is_local(nt_sid_t *sid)
{
	nt_sid_t *local_sid;

	local_sid = nt_domain_local_sid();
	return (nt_sid_is_indomain(local_sid, sid));
}

/*
 * nt_sid_is_builtin
 *
 * Check a SID to see if it belongs to the builtin domain.
 * Returns 1 if the SID is a builtin SID. Otherwise returns 0.
 */
int
nt_sid_is_builtin(nt_sid_t *sid)
{
	nt_domain_t *domain;

	domain = nt_domain_lookupbytype(NT_DOMAIN_BUILTIN);
	if (domain == 0)
		return (0);
	return (nt_sid_is_indomain(domain->sid, sid));
}
#endif /* _KERNEL */

/*
 * nt_sid_is_domain_equal
 *
 * Compare two SIDs's domain and return a boolean result.
 *
 * Returns 1 if the domain SID are the same. Otherwise returns 0.
 */
int
nt_sid_is_domain_equal(nt_sid_t *pSid1, nt_sid_t *pSid2)
{
	int		i, n;

	if (pSid1->Revision != pSid2->Revision)
		return (0);

	if (pSid1->SubAuthCount != pSid2->SubAuthCount)
		return (0);

	if (bcmp(pSid1->Authority, pSid2->Authority, NT_SID_AUTH_MAX) != 0)
		return (0);

	n = pSid1->SubAuthCount;

	n -= 1;		/* don't compare last SubAuthority[] (aka RID) */

	for (i = 0; i < n; i++)
		if (pSid1->SubAuthority[i] != pSid2->SubAuthority[i])
			return (0);

	return (1);
}

/*
 * nt_sid_logf
 *
 * Format a sid and write it to the system log. See nt_sid_format
 * for format information.
 */
void
nt_sid_logf(nt_sid_t *sid)
{
	char *s;

	if ((s = nt_sid_format(sid)) == 0)
		return;

	MEM_FREE("libnt", s);
}


/*
 * nt_sid_format
 *
 * Format a sid and return it as a string. The memory for the string is
 * allocated using malloc so the caller should call free when it is no
 * longer required. A pointer to the string is returned.
 */
char *
nt_sid_format(nt_sid_t *sid)
{
	int i;
	char *fmtbuf;
	char *p;

	if (sid == 0)
		return (0);

	if ((fmtbuf = MEM_MALLOC("libnt", NT_SID_FMTBUF_SIZE)) == 0)
		return (0);

	p = fmtbuf;
	(void) sprintf(p, "S-%d-", sid->Revision);
	while (*p)
		++p;

	for (i = 0; i < NT_SID_AUTH_MAX; ++i) {
		if (sid->Authority[i] != 0 || i == NT_SID_AUTH_MAX - 1)	{
			(void) sprintf(p, "%d", sid->Authority[i]);
			while (*p)
				++p;
		}
	}

	for (i = 0; i < sid->SubAuthCount && i < NT_SID_SUBAUTH_MAX; ++i) {
		(void) sprintf(p, "-%u", sid->SubAuthority[i]);
		while (*p)
			++p;
	}

	return (fmtbuf);
}

/*
 * nt_sid_format2
 *
 * Format a sid and return it in the passed buffer.
 */
void
nt_sid_format2(nt_sid_t *sid, char *fmtbuf)
{
	int i;
	char *p;

	if (sid == 0 || fmtbuf == 0)
		return;

	p = fmtbuf;
	(void) sprintf(p, "S-%d-", sid->Revision);
	while (*p)
		++p;

	for (i = 0; i < NT_SID_AUTH_MAX; ++i) {
		if (sid->Authority[i] != 0 || i == NT_SID_AUTH_MAX - 1) {
			(void) sprintf(p, "%d", sid->Authority[i]);
			while (*p)
				++p;
		}
	}

	for (i = 0; i < sid->SubAuthCount && i < NT_SID_SUBAUTH_MAX; ++i) {
		(void) sprintf(p, "-%u", sid->SubAuthority[i]);
		while (*p)
			++p;
	}
}

/*
 * nt_sid_strtosid
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
 *
 * XXX this function may have endian issues
 */
nt_sid_t *
nt_sid_strtosid(char *sidstr)
{
	nt_sid_t *sid;
	char *p;
	int size;
	BYTE i;
#ifdef _KERNEL
	long sua;
#endif /* _KERNEL */

	if (sidstr == 0) {
		return (0);
	}

	if (strncmp(sidstr, "S-1-", 4) != 0) {
		return (0);
	}

	size = sizeof (nt_sid_t) + (NT_SID_SUBAUTH_MAX * sizeof (DWORD));

	if ((sid = MEM_MALLOC("libnt", size)) == 0) {
		return (0);
	}

	bzero(sid, size);
	sid->Revision = NT_SID_REVISION;
#ifndef _KERNEL
	sid->Authority[5] = atoi(&sidstr[4]);
#else /* _KERNEL */
	sua = 0;
	/* XXX Why are we treating sua as a long/unsigned long? */
	(void) ddi_strtoul(&sidstr[4], 0, 10, (unsigned long *)&sua);
	sid->Authority[5] = (BYTE)sua;
#endif /* _KERNEL */

	for (i = 0, p = &sidstr[5]; i < NT_SID_SUBAUTH_MAX && *p; ++i) {
		while (*p && *p == '-')
			++p;

		if (*p < '0' || *p > '9') {
			MEM_FREE("libnt", sid);
			return (0);
		}

#ifndef _KERNEL
		sid->SubAuthority[i] = strtoul(p, 0, 10);
#else /* _KERNEL */
		sua = 0;
		(void) ddi_strtoul(p, 0, 10, (unsigned long *)&sua);
		sid->SubAuthority[i] = (DWORD)sua;
#endif /* _KERNEL */

		while (*p && *p != '-')
			++p;
	}

	sid->SubAuthCount = i;
	return (sid);
}


/*
 * nt_sid_name_use
 *
 * Returns the text name for a SID_NAME_USE value. The SID_NAME_USE
 * provides the context for a SID, i.e. the type of resource to which
 * it refers.
 */
char *
nt_sid_name_use(unsigned int snu_id)
{
	static char *snu_name[] = {
		"SidTypeSidPrefix",
		"SidTypeUser",
		"SidTypeGroup",
		"SidTypeDomain",
		"SidTypeAlias",
		"SidTypeWellKnownGroup",
		"SidTypeDeletedAccount",
		"SidTypeInvalid",
		"SidTypeUnknown"
	};

	if (snu_id < ((sizeof (snu_name)/sizeof (snu_name[0]))))
		return (snu_name[snu_id]);
	else {
		return (snu_name[SidTypeUnknown]);
	}
}


/*
 * nt_sid_copy
 *
 * Copy information of srcsid to dessid. The buffer should be allocated
 * for dessid before passing to this function. The size of buffer for
 * dessid should be specified in the buflen.
 *
 * Returns total bytes of information copied. If there is an error, 0
 * will be returned.
 */
int
nt_sid_copy(nt_sid_t *dessid, nt_sid_t *srcsid, unsigned buflen)
{
	unsigned		n_bytes;

	if (!dessid || !srcsid)
		return (0);

	n_bytes = nt_sid_length(srcsid);
	if (n_bytes > buflen)
		return (0);

	bcopy((char *)srcsid, (char *)dessid, n_bytes);

	return (n_bytes);
}
