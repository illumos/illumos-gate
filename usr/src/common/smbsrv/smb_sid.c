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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <syslog.h>
#else	/* !_KERNEL && !_FAKE_KERNEL */
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#endif	/* !_KERNEL && !_FAKE_KERNEL */

#include <smbsrv/smb_sid.h>

static smb_sid_t *smb_sid_alloc(size_t);

/*
 * smb_sid_isvalid
 *
 * Performs a minimal SID validation.
 */
boolean_t
smb_sid_isvalid(smb_sid_t *sid)
{
	if (sid == NULL)
		return (B_FALSE);

	return ((sid->sid_revision == NT_SID_REVISION) &&
	    (sid->sid_subauthcnt < NT_SID_SUBAUTH_MAX));
}

/*
 * smb_sid_len
 *
 * Returns the number of bytes required to hold the sid.
 */
int
smb_sid_len(smb_sid_t *sid)
{
	if (sid == NULL)
		return (0);

	return (sizeof (smb_sid_t) - sizeof (uint32_t)
	    + (sid->sid_subauthcnt * sizeof (uint32_t)));
}

/*
 * smb_sid_dup
 *
 * Make a duplicate of the specified sid. The memory for the new sid
 * should be freed by calling smb_sid_free().
 * A pointer to the new sid is returned.
 */
smb_sid_t *
smb_sid_dup(smb_sid_t *sid)
{
	smb_sid_t *new_sid;
	int size;

	if (sid == NULL)
		return (NULL);

	size = smb_sid_len(sid);
	if ((new_sid = smb_sid_alloc(size)) == NULL)
		return (NULL);

	bcopy(sid, new_sid, size);
	return (new_sid);
}


/*
 * smb_sid_splice
 *
 * Make a full sid from a domain sid and a relative id (rid).
 * The memory for the result sid should be freed by calling
 * smb_sid_free(). A pointer to the new sid is returned.
 */
smb_sid_t *
smb_sid_splice(smb_sid_t *domain_sid, uint32_t rid)
{
	smb_sid_t *sid;
	int size;

	if (domain_sid == NULL)
		return (NULL);

	size = smb_sid_len(domain_sid);
	if ((sid = smb_sid_alloc(size + sizeof (rid))) == NULL)
		return (NULL);

	bcopy(domain_sid, sid, size);

	sid->sid_subauth[domain_sid->sid_subauthcnt] = rid;
	++sid->sid_subauthcnt;

	return (sid);
}

/*
 * smb_sid_getrid
 *
 * Return the Relative Id (RID) of the specified SID. It is the
 * caller's responsibility to ensure that this is an appropriate SID.
 * All we do here is return the last sub-authority from the SID.
 */
int
smb_sid_getrid(smb_sid_t *sid, uint32_t *rid)
{
	if (!smb_sid_isvalid(sid) || (rid == NULL) ||
	    (sid->sid_subauthcnt == 0))
		return (-1);

	*rid = sid->sid_subauth[sid->sid_subauthcnt - 1];
	return (0);
}

/*
 * smb_sid_split
 *
 * Take a full sid and split it into a domain sid and a relative id (rid).
 * The domain SID is allocated and a pointer to it will be returned. The
 * RID value is passed back in 'rid' arg if it's not NULL. The allocated
 * memory for the domain SID must be freed by caller.
 */
smb_sid_t *
smb_sid_split(smb_sid_t *sid, uint32_t *rid)
{
	smb_sid_t *domsid;
	int size;

	if (!smb_sid_isvalid(sid) || (sid->sid_subauthcnt == 0))
		return (NULL);

	/* We will reduce sid_subauthcnt by one. */
	size = smb_sid_len(sid) - sizeof (uint32_t);
	if ((domsid = smb_sid_alloc(size)) == NULL)
		return (NULL);

	bcopy(sid, domsid, size);
	domsid->sid_subauthcnt = sid->sid_subauthcnt - 1;

	if (rid)
		*rid = domsid->sid_subauth[domsid->sid_subauthcnt];

	return (domsid);
}

/*
 * smb_sid_splitstr
 *
 * Takes a full sid in string form and split it into a domain sid and a
 * relative id (rid).
 *
 * IMPORTANT: The original sid is modified in place. This function assumes
 * given SID is in valid string format.
 */
int
smb_sid_splitstr(char *strsid, uint32_t *rid)
{
	char *p;

	if ((p = strrchr(strsid, '-')) == NULL)
		return (-1);

	*p++ = '\0';
	if (rid) {
#if defined(_KERNEL) || defined(_FAKE_KERNEL)
		unsigned long sua = 0;
		(void) ddi_strtoul(p, NULL, 10, &sua);
		*rid = (uint32_t)sua;
#else
		*rid = strtoul(p, NULL, 10);
#endif
	}

	return (0);
}

/*
 * smb_sid_cmp
 *
 * Compare two SIDs and return a boolean result. The checks are ordered
 * such that components that are more likely to differ are checked
 * first. For example, after checking that the SIDs contain the same
 * sid_subauthcnt, we check the sub-authorities in reverse order because
 * the RID is the most likely differentiator between two SIDs, i.e.
 * they are probably going to be in the same domain.
 */
boolean_t
smb_sid_cmp(smb_sid_t *sid1, smb_sid_t *sid2)
{
	int i;

	if (sid1 == NULL || sid2 == NULL)
		return (B_FALSE);

	if (sid1->sid_subauthcnt != sid2->sid_subauthcnt ||
	    sid1->sid_revision != sid2->sid_revision)
		return (B_FALSE);

	for (i = sid1->sid_subauthcnt - 1; i >= 0; --i)
		if (sid1->sid_subauth[i] != sid2->sid_subauth[i])
			return (B_FALSE);

	if (bcmp(&sid1->sid_authority, &sid2->sid_authority, NT_SID_AUTH_MAX))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * smb_sid_indomain
 *
 * Check if given SID is in given domain.
 */
boolean_t
smb_sid_indomain(smb_sid_t *domain_sid, smb_sid_t *sid)
{
	int i;

	if (sid == NULL || domain_sid == NULL)
		return (B_FALSE);

	if (domain_sid->sid_revision != sid->sid_revision ||
	    sid->sid_subauthcnt < domain_sid->sid_subauthcnt)
		return (B_FALSE);

	for (i = domain_sid->sid_subauthcnt - 1; i >= 0; --i)
		if (domain_sid->sid_subauth[i] != sid->sid_subauth[i])
			return (B_FALSE);

	if (bcmp(&domain_sid->sid_authority, &sid->sid_authority,
	    NT_SID_AUTH_MAX))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * smb_sid_tostr
 *
 * Fill in the passed buffer with the string form of the given
 * binary sid.
 */
void
smb_sid_tostr(const smb_sid_t *sid, char *strsid)
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
 * smb_sid_fromstr
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
#if defined(_KERNEL) || defined(_FAKE_KERNEL)
smb_sid_t *
smb_sid_fromstr(const char *sidstr)
{
	smb_sid_t *sid;
	smb_sid_t *retsid;
	const char *p;
	int size;
	uint8_t i;
	unsigned long sua;

	if (sidstr == NULL)
		return (NULL);

	if (strncmp(sidstr, "S-1-", 4) != 0)
		return (NULL);

	size = sizeof (smb_sid_t) + (NT_SID_SUBAUTH_MAX * sizeof (uint32_t));
	sid = kmem_zalloc(size, KM_SLEEP);

	sid->sid_revision = NT_SID_REVISION;
	sua = 0;
	(void) ddi_strtoul(&sidstr[4], 0, 10, &sua);
	sid->sid_authority[5] = (uint8_t)sua;

	for (i = 0, p = &sidstr[5]; i < NT_SID_SUBAUTH_MAX && *p; ++i) {
		while (*p && *p == '-')
			++p;

		if (*p < '0' || *p > '9') {
			kmem_free(sid, size);
			return (NULL);
		}

		sua = 0;
		(void) ddi_strtoul(p, 0, 10, &sua);
		sid->sid_subauth[i] = (uint32_t)sua;

		while (*p && *p != '-')
			++p;
	}

	sid->sid_subauthcnt = i;
	retsid = smb_sid_dup(sid);
	kmem_free(sid, size);

	return (retsid);
}
#else /* _KERNEL */
smb_sid_t *
smb_sid_fromstr(const char *sidstr)
{
	smb_sid_t *sid;
	const char *p;
	int size;
	uint8_t i;

	if (sidstr == NULL)
		return (NULL);

	if (strncmp(sidstr, "S-1-", 4) != 0)
		return (NULL);

	size = sizeof (smb_sid_t) + (NT_SID_SUBAUTH_MAX * sizeof (uint32_t));

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
#endif /* _KERNEL */

/*
 * smb_sid_type2str
 *
 * Returns the text name for a SID_NAME_USE value. The SID_NAME_USE
 * provides the context for a SID, i.e. the type of resource to which
 * it refers.
 */
char *
smb_sid_type2str(uint16_t snu_id)
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
		"SidTypeUnknown",
		"SidTypeComputer",
		"SidTypeLabel"
	};

	if (snu_id < ((sizeof (snu_name)/sizeof (snu_name[0]))))
		return (snu_name[snu_id]);

	return (snu_name[SidTypeUnknown]);
}

static smb_sid_t *
smb_sid_alloc(size_t size)
{
	smb_sid_t *sid;
#if defined(_KERNEL) || defined(_FAKE_KERNEL)
	sid = kmem_alloc(size, KM_SLEEP);
#else
	sid = malloc(size);
#endif
	return (sid);
}

void
smb_sid_free(smb_sid_t *sid)
{
#if defined(_KERNEL) || defined(_FAKE_KERNEL)
	if (sid == NULL)
		return;

	kmem_free(sid, smb_sid_len(sid));
#else
	free(sid);
#endif
}
