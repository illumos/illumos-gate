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
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Test usr/src/common/smbsrv/smb_sid.c with large SIDs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <smbsrv/smb_sid.h>
#include <limits.h>

void
test_sid(const char *sidstr, uint8_t idauth, const uint32_t *subauths,
    size_t subauth_cnt)
{
	char newstr[1024];
	smb_sid_t *sid;
	int i;

	sid = smb_sid_fromstr(sidstr);
	if (!smb_sid_isvalid(sid)) {
		fprintf(stderr, "SID %s not valid: %p\n", sidstr, sid);
		exit(1);
	}

	smb_sid_tostr(sid, newstr);

	if (strncmp(sidstr, newstr, sizeof (newstr)) != 0) {
		fprintf(stderr, "SID %s did not match decoded SID %s\n",
		    sidstr, newstr);
		exit(5);
	}

	if (subauths == NULL) {
		smb_sid_free(sid);
		return;
	}

	if (sid->sid_authority[5] != idauth) {
		fprintf(stderr, "Wrong SID authority %u (expected %u): %s\n",
		    sid->sid_authority, idauth, sidstr);
		exit(2);
	}

	if (sid->sid_subauthcnt != subauth_cnt) {
		fprintf(stderr, "Wrong subauthcnt %u (expected %u): %s\n",
		    sid->sid_subauthcnt, subauth_cnt, sidstr);
		exit(3);
	}

	for (i = 0; i < subauth_cnt; i++) {
		if (sid->sid_subauth[i] != subauths[i]) {
			fprintf(stderr,
			    "Wrong subauthcnt %u (expected %u): %s\n",
			    sid->sid_subauthcnt, subauth_cnt, sidstr);
			exit(4);
		}
	}

	smb_sid_free(sid);
}

int
main(int argc, char *argv[])
{
	char sid[1024];
	uint32_t subauths[NT_SID_SUBAUTH_MAX];
	size_t len = sizeof (sid);
	int off = 0;
	int i, idauth;

	if (argc > 1) {
		test_sid(argv[1], 0, NULL, 0);
		goto out;
	}

	for (idauth = 2; idauth <= UINT8_MAX; idauth += 11) {
		off = snprintf(&sid[0], len, "S-1-%u", idauth);
		for (i = 0; i < NT_SID_SUBAUTH_MAX; i++) {
			subauths[i] = arc4random();
			off += snprintf(&sid[off], len - off,
			    "-%u", subauths[i]);
		}
		test_sid(sid, idauth, subauths, NT_SID_SUBAUTH_MAX);
	}

out:
	printf("success!\n");
	return (0);
}
