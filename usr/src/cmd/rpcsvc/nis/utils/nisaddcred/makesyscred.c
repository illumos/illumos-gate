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
 * makesyscred.c
 *
 * This module makes the "AUTH_SYS" credential and stores it in the credential
 * table.
 */

#include <stdio.h>
#include <pwd.h>
#include <rpcsvc/nis.h>
#include "nisaddcred.h"

extern char *strchr();

int
make_sys_cred(np, p, d, flavor)
	char	*np;
	char	*p;
	char	*d;
	char	*flavor;	/* Ignored. */
{
	nis_result	*res;
	nis_object	*obj = init_entry();
	uid_t		uid;
	gid_t		gid;
	int		grplist[32];
	int		ngrps, i;
	struct passwd	*pw;
	char		sysname[32],
			*s,
			luid[16],
			lgids[64],
			buf[16],
			pname[1024],
			tname[1024];
	nis_error	err;

	uid = atoi(p);

	if ((uid != geteuid()) && (geteuid() != 0)) {
		fprintf(stderr, "must be root to add anothers credentials.\n");
		return (0);
	}

	s = strchr(p, ',');
	if (! s) {
		fprintf(stderr, "badly formed AUTH_SYS principal name.\n");
		return (0);
	}
	s++;
	gid = atoi(s);

	pw = getpwuid(uid);
	if (! pw) {
		/*
		 * If NIS+ is the name service for the passwd data,
		 * maybe this answer came from an out of date replica
		 * server.  So lets try the NIS+ Master server.
		 */
		pw = getpwuid_nisplus_master(uid, &err);
		if (pw == NULL) {
			if (err == NIS_NOTFOUND)
				fprintf(stderr,
					"%s: no password entry for uid %d\n",
							program_name, uid);
			else
				fprintf(stderr,
		"%s: could not get the password entry for uid %d: %s\n",
					program_name, uid, nis_sperrno(err));
			return (0);
		}
	}

	ENTRY_VAL(obj, 0) = np;
	ENTRY_LEN(obj, 0) = strlen(np) + 1;

	ENTRY_VAL(obj, 1) = "SYS";
	ENTRY_LEN(obj, 1) = 4;

	ENTRY_VAL(obj, 2) = p;
	ENTRY_LEN(obj, 2) = strlen(p)+1;

	if ((uid != geteuid()) && (pw->pw_uid != uid)) {
		ngrps = initgroups(pw->pw_name, pw->pw_gid);
		if (ngrps == -1) {
			perror("initgroups:");
			return (0);
		}
	}
	ngrps = getgroups(32, grplist);
	if (ngrps == -1) {
		perror("getgroups:");
		return (0);
	}

	lgids[0] = '\0';
	for (i = 0; i < ngrps; i++) {
		if (i+1 < ngrps)
			sprintf(buf, "%d,", grplist[i]);
		else
			sprintf(buf, "%d", grplist[i]);
		strcat(lgids, buf);
	}

	ENTRY_VAL(obj, 3) = lgids;
	ENTRY_LEN(obj, 3) = strlen(lgids) + 1;

	ENTRY_VAL(obj, 4) = "";	/* no private data */
	ENTRY_LEN(obj, 4) = 0;

	sprintf(tname, "%s.%s", CRED_TABLE, d);
	obj->zo_owner = pname;
	obj->zo_domain = d;
	res = nis_add_entry(tname, obj, 0);
	switch (res->status) {
	case NIS_TRYAGAIN :
		fprintf(stderr, "NIS+ server busy, try again later.\n");
		i = 0;
		break;
	case NIS_PERMISSION :
		fprintf(stderr,
		    "Insufficent permission to update/create credentials\n");
		i = 0;
		break;
	case NIS_SUCCESS :
		i = 1;
		break;
	default :
		fprintf(stderr, "Error creating credential, NIS+ error %s\n",
						nis_sperrno(res->status));
		break;
	}
	nis_freeresult(res);
	return (i);
}

char *
get_sys_cred(char *domain, /* Ignored. */
	     char *flavor) /* Ignored. */
{
	static char myname[64];
	struct passwd	*pw;
	int		uid;
	nis_error	err;

	uid = geteuid();
	pw = getpwuid(uid);
	if (! pw) {
		/*
		 * If NIS+ is the name service for the passwd data,
		 * maybe this answer came from an out of date replica
		 * server.  So lets try the NIS+ Master server.
		 */
		pw = getpwuid_nisplus_master(uid, &err);
		if (pw == NULL) {
			if (err == NIS_NOTFOUND)
				fprintf(stderr,
					"%s: no password entry for uid %d\n",
							program_name, uid);
			else
				fprintf(stderr,
		"%s: could not get the password entry for uid %d: %s\n",
					program_name, uid, nis_sperrno(err));
			return (NULL);
		}
	}

	sprintf(myname, "%d,%d", pw->pw_uid, pw->pw_gid);
	return (myname);
}
