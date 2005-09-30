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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nisgrpadm.c
 *
 * This program allows the system administrator to create and administer
 * groups within the NIS+ namespace.
 *
 */

#include <stdio.h>
#include <string.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>

extern int	optind, opterr;
extern char	*optarg;
extern nis_object nis_default_obj;

extern nis_name __nis_map_group_r();
extern bool_t nis_verifycred();

enum op_types {NONE, DELETE, CREATE, ADD, REMOVE, LIST, TEST};

static ulong_t master = 0;

bool_t
nis_verifydomain(n)
	nis_name	n;
{
	nis_result	*res;
	int		err;
	char		dname[NIS_MAXNAMELEN];

	sprintf(dname, "cred.org_dir.%s", n);
	res = nis_lookup(dname, master);
	err = (res->status == NIS_SUCCESS);
	nis_freeresult(res);
	return (err);
}



/*
 * temp_nis_verifygroup(group)
 *
 * Verify the existence of the named group. This is a duplicate of
 * nis_verifygroup API call.
 * This duplication was necessitated by the fact that nis_verifygroup does not
 * accept a 'flags' argument to force it to go to the master server.
 * Refer to bugid 1092089 and rfe 1102245.
 *
 */
nis_error
temp_nis_verifygroup(group)
	nis_name	group;	/* NIS group name */
{
	nis_name	grpname;
	nis_result	*res;
	nis_error	result;
	char		namebuf[NIS_MAXNAMELEN];

	grpname = __nis_map_group_r(group, namebuf, sizeof (namebuf));
	res = nis_lookup(grpname, master | FOLLOW_LINKS);
	if ((res->status == NIS_SUCCESS) || (res->status == NIS_S_SUCCESS)) {
		if (__type_of(res->objects.objects_val) == NIS_GROUP_OBJ)
			result = NIS_SUCCESS;
		else
			result = NIS_BADOBJECT;
	} else
		result = res->status;
	nis_freeresult(res);
	return (result);
}




bool_t
verify_principal(name)
	nis_name	name;
{
	ulong_t	flags;

	if (name[0] == '-')
		name++;
	if (name[0] == '@')
		return (temp_nis_verifygroup(&name[1]) == NIS_SUCCESS);
	if (name[0] == '*') {
		if (name[1] == '.')
			return (nis_verifydomain(&name[2]));
		else
			return (FALSE);
	}
	/*
	 * Only if a random NIS+ server does not know about this, do we
	 * force a connection to the Master server to avoid overloading it.
	 */
	flags = (ulong_t)(USE_DGRAM | FOLLOW_LINKS | FOLLOW_PATH);
	return (nis_verifycred(name, flags) ? TRUE :
		nis_verifycred(name, (ulong_t)(flags | MASTER_ONLY)));
}

void
usage()
{
	fprintf(stderr,
		"usage: nisgrpadm -a | -r | -t [-s] group princpal ...\n");
	fprintf(stderr,
		"       nisgrpadm -d | -l [-M] [-s] group\n");
	fprintf(stderr,
		"       nisgrpadm -c [ -D defaults] [-M] [-s] group\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	char		*defstr = 0;
	enum op_types	op = NONE;
	int		silent = 0;
	int		c;
	nis_error	s, pstatus = NIS_SUCCESS, ostatus = NIS_SUCCESS;
	char		*grpname = NULL, *princp = NULL;
	nis_name	*grplist, *plist = 0, *p;
	char		buf[NIS_MAXNAMELEN], *grponame;
	nis_result	*gres;
	int		grpnm, found, i;
	nis_name	*grpml;

	while ((c = getopt(argc, argv, "artcdlsMD:")) != -1) {
		switch (c) {
		case 'D':
			defstr = optarg;
			break;
		case 'M':
			master = MASTER_ONLY;
			break;
		case 'd':
			if (op != NONE) {
				fprintf(stderr,
		"c, d, a, r, t, and l options are mutually exclusive.\n");
				usage();
			}
			op = DELETE;
			break;
		case 'c':
			if (op != NONE) {
				fprintf(stderr,
		"c, d, a, r, t, and l options are mutually exclusive.\n");
				usage();
			}
			op = CREATE;
			break;
		case 'a':
			if (op != NONE) {
				fprintf(stderr,
		"c, d, a, r, t, and l options are mutually exclusive.\n");
				usage();
			}
			op = ADD;
			break;
		case 'r':
			if (op != NONE) {
				fprintf(stderr,
		"c, d, a, r, t, and l options are mutually exclusive.\n");
				usage();
			}
			op = REMOVE;
			break;
		case 't':
			if (op != NONE) {
				fprintf(stderr,
		"c, d, a, r, t, and l options are mutually exclusive.\n");
				usage();
			}
			op = TEST;
			break;
		case 'l':
			if (op != NONE) {
				fprintf(stderr,
		"c, d, a, r, t, and l options are mutually exclusive.\n");
				usage();
			}
			op = LIST;
			break;
		case 's':
			silent = 1;
			break;
		default:
			usage();
		}
	}

	if (op == NONE)
		usage();

	if (optind == argc) {
		fprintf(stderr, "Missing group name.\n");
		usage();
	}
	grpname = argv[optind++];

	if (!nis_defaults_init(defstr))
		exit(1);
	if ((op == CREATE) || (op == DELETE)) {
		if (grpname[strlen(grpname)-1] != '.') {
			fprintf(stderr,
				"Group name must be fully qualified.\n");
			exit(NIS_BADNAME);
		}
	} else {
		/*
		 * Get the group name using psuedo expand name magic
		 */
		if ((grplist = nis_getnames(grpname)) == 0) {
			nis_perror(NIS_NOMEMORY, "nisgrpadm");
			exit(NIS_NOMEMORY);
		}
		for (p = grplist; *p; p++)
			if (temp_nis_verifygroup(*p) == NIS_SUCCESS)
				break;
		if (*p == 0) {
			if (!silent)
				fprintf(stderr,
					"Group \"%s\" not found.\n",
					grpname);
			exit(NIS_NOTFOUND);
		}
		grpname = *p;
	}

	switch (op) {
	case DELETE:
		s = nis_destroygroup(grpname);
		if (!silent) {
			if (s == NIS_SUCCESS)
				printf("Group \"%s\" destroyed.\n",
				    grpname);
			else {
				fprintf(stderr,
					"Unable to destroy group \"%s\": %s\n",
					grpname,
					nis_sperrno(s));
			}
		}
		exit(s);

	case CREATE:
		s = __nis_creategroup_obj(grpname, 0, &nis_default_obj);
		if (!silent) {
			if (s == NIS_SUCCESS)
				printf("Group \"%s\" created.\n",
				    grpname);
			else {
				fprintf(stderr,
					"Unable to create group \"%s\": %s\n",
					grpname,
					nis_sperrno(s));
			}
		}
		exit(s);

	case LIST:
		if (!silent)
			nis_print_group_entry(grpname);
		exit(NIS_SUCCESS);
	}

	if (optind == argc) {
		fprintf(stderr, "Missing principal name(s).\n");
		usage();
	}

	/*
	 * Get the group object so we can do prefix matching on partial
	 * principal names.  temp_nis_verifygroup() has already read and
	 * verified the group (too bad we have to look it up again) so
	 * this shouldn't fail.
	 */
	if (op == REMOVE) {
		grponame = __nis_map_group_r(grpname, buf, sizeof (buf));
		gres = nis_lookup(grponame, master | FOLLOW_LINKS);
		if (gres->status != NIS_SUCCESS) {
			if (!silent)
				nis_perror(gres->status,
					    "Can't read group object");
			exit(gres->status);
		}
		grpnm = NIS_RES_OBJECT(gres)->GR_data.gr_members.gr_members_len;
		grpml = NIS_RES_OBJECT(gres)->GR_data.gr_members.gr_members_val;
	}

	while (optind < argc) {

		princp = argv[optind++];

		if (op == REMOVE) {
			/*
			 * If the principal name isn't fully qualified,
			 * look for a unique prefix match in the group
			 * membership list.
			 */
			if (princp[strlen(princp)-1] != '.') {
				for (found = -1, i = 0; i < grpnm; i++) {
					if (strncasecmp(princp,
							grpml[i],
							strlen(princp)) == 0) {
						if (found >= 0 && !silent) {
							fprintf(stderr,
		"Principal \"%s\" not unique, please use full name.\n",
								princp);
							found = -2;
							break;
						} else
							found = i;
					}
				}
				if (found < 0) {
					pstatus = NIS_NOTFOUND;
					if (found == -1 && !silent)
						fprintf(stderr,
				"Principal \"%s\" not found in group.\n",
							princp);
					continue;
				}
				princp = grpml[found];
			}
		} else {
			/*
			 * Get the principal name using psuedo expand name
			 * magic
			 */
			if (plist)
				nis_freenames(plist);
			if ((plist = nis_getnames(princp)) == 0) {
				nis_perror(NIS_NOMEMORY, "nisgrpadm");
				exit(NIS_NOMEMORY);
			}
			for (p = plist; *p; p++)
				if (verify_principal(*p))
					break;
			if (*p == 0) {
				pstatus = NIS_NOTFOUND;
				if (!silent)
					fprintf(stderr,
					"Principal \"%s\" not found.\n",
						princp);
				continue;
			}
			princp = *p;
		}

		switch (op) {
		case ADD:
			s = nis_addmember(princp, grpname);
			if (ostatus == NIS_SUCCESS)
				ostatus = s;
			if (!silent) {
				if (s == NIS_SUCCESS)
					printf(
					"Added \"%s\" to group \"%s\".\n",
						princp, grpname);
				else {
					fprintf(stderr,
				"Unable to add \"%s\" to group \"%s\": %s\n",
						princp, grpname,
						nis_sperrno(s));
				}
			}
			break;

		case REMOVE:
			s = nis_removemember(princp, grpname);
			if (ostatus == NIS_SUCCESS)
				ostatus = s;
			if (!silent) {
				if (s == NIS_SUCCESS)
					printf(
					"Removed \"%s\" from group \"%s\".\n",
					princp, grpname);
				else {
					fprintf(stderr,
			"Unable to remove \"%s\" from group \"%s\": %s\n",
						princp, grpname,
						nis_sperrno(s));
				}
			}
			break;

		case TEST:
			s = nis_ismember(princp, grpname);
			if (!s && ostatus == NIS_SUCCESS)
				ostatus = NIS_NOTFOUND;
			if (!silent) {
				if (s)
					printf(
					"\"%s\" is a member of group \"%s\".\n",
						princp, grpname);
				else
					printf(
				"\"%s\" is not a member of group \"%s\".\n",
					princp, grpname);
			}
			break;
		}
	}

	if (ostatus == NIS_SUCCESS)
		return (pstatus);
	else
		return (ostatus);
}
