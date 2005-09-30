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
 * nischmod.c
 *
 * nis+ object chmod/chown/chgrp/chttl utility
 */

#include <stdio.h>
#include <string.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <stdlib.h>

extern int 	optind;
extern char	*optarg;

extern bool_t nis_verifycred();

#define	CMD_CHMOD 0
#define	CMD_CHOWN 1
#define	CMD_CHGRP 2
#define	CMD_CHTTL 3

int cmdnum;
char *cmdname;

void
usage()
{
	char *str;

	switch (cmdnum) {
	case CMD_CHMOD:
		str = "mode";
		break;
	case CMD_CHOWN:
		str = "owner";
		break;
	case CMD_CHGRP:
		str = "group";
		break;
	case CMD_CHTTL:
		str = "ttl";
		break;
	}

	fprintf(stderr, "usage: %s [-LPAf] %s name ...\n",
		cmdname, str);
	exit(1);
}


void
change_object(obj, udata)
	nis_object *obj;
	void *udata;
{
	switch (cmdnum) {
	case CMD_CHMOD:
		parse_rights(&(obj->zo_access), (char *)udata);
		break;
	case CMD_CHOWN:
		obj->zo_owner = (nis_name)udata;
		break;
	case CMD_CHGRP:
		obj->zo_group = (nis_name)udata;
		break;
	case CMD_CHTTL:
		obj->zo_ttl = *(ulong_t *)udata;
		if (obj->zo_data.zo_type == NIS_DIRECTORY_OBJ)
			obj->DI_data.do_ttl = *(ulong_t *)udata;
		break;
	}
}


static char force = 0;
static int error = 0;

static int
change_entry(name, ent, udata)
	nis_name 	name;
	nis_object	*ent;
	void		*udata;
{
	nis_object	newobj;
	nis_result	*res;

	newobj = *ent;
	change_object(&newobj, udata);
	res = nis_modify_entry(name, &newobj, MOD_SAMEOBJ);
	if (res->status != NIS_SUCCESS) {
		if (!force) {
			nis_perror(res->status, "can't modify entry");
			error = 1;
		}
	}
	nis_freeresult(res);
	return (0);
}


int
main(int argc, char *argv[])
{
	int c;
	char **plist, **p;
	ulong_t flinks = 0, fpath = 0, allres = 0;
	char *name;
	void *udata;
	uint_t	x;
	int bad_name;
	nis_result *ores, *mres;
	char oname[NIS_MAXNAMELEN];
	nis_object newobj;

	if (cmdname = strrchr(argv[0], '/'))
		cmdname++;
	else
		cmdname = argv[0];

	if (strcmp(cmdname, "nischmod") == 0)
		cmdnum = CMD_CHMOD;
	else if (strcmp(cmdname, "nischown") == 0)
		cmdnum = CMD_CHOWN;
	else if (strcmp(cmdname, "nischgrp") == 0)
		cmdnum = CMD_CHGRP;
	else if (strcmp(cmdname, "nischttl") == 0)
		cmdnum = CMD_CHTTL;
	else {
		fprintf(stderr, "%s: bad command.\n", cmdname);
		exit(1);
	}

	while ((c = getopt(argc, argv, "LPAf")) != -1) {
		switch (c) {
		case 'L':
			flinks = FOLLOW_LINKS;
			break;
		case 'P':
			fpath = FOLLOW_PATH;
			break;
		case 'A':
			allres = ALL_RESULTS;
			break;
		case 'f':
			force = 1;
			break;
		default:
			usage();
		}
	}

	if (argc - optind < 2)
		usage();

	switch (cmdnum) {
	case CMD_CHMOD:
		/*
		 * attempt to parse the access rights first
		 */
		udata = argv[optind++];
		if (!parse_rights(&x, udata)) {
			fprintf(stderr, "Can't parse access rights \"%s\"\n",
					argv[optind-1]);
			usage();
		}
		break;
	case CMD_CHOWN:
		/*
		 * get the principal name using psuedo expand name
		 * magic
		 */
		udata = argv[optind++];
		if ((plist = nis_getnames(udata)) == 0) {
			/* Could be either no mem or more likely bad name */
			nis_perror(NIS_BADNAME, udata);
			exit(1);
		}
		for (p = plist; *p; p++) {
			ulong_t flags;
			/*
			 * First try to verify through regular means and only
			 * if that fails, then try the Master server.
			 */
			flags = (ulong_t)(USE_DGRAM|FOLLOW_LINKS|FOLLOW_PATH);
			if (nis_verifycred(*p, flags) ||
			    nis_verifycred(*p, (ulong_t)(flags | MASTER_ONLY)))
				break;
		}
		if (*p == 0) {
			if (!force) {
				fprintf(stderr,
					"%s: principal not found\n",
					udata);
				exit(1);
			} else if (
				((char *)udata)[strlen((char *)udata)-1] != '.')
				exit(0);
		} else
			udata = *p;
		break;
	case CMD_CHGRP:
		/*
		 * get the group name using psuedo expand name magic
		 */
		udata = argv[optind++];
		if ((plist = nis_getnames(udata)) == 0) {
			/* Could be either no mem or more likely bad name */
			nis_perror(NIS_BADNAME, udata);
			exit(1);
		}
		for (p = plist; *p; p++)
			if (nis_verifygroup(*p) == NIS_SUCCESS)
				break;
		if (*p == 0) {
			if (!force) {
				fprintf(stderr,
					"%s: group not found\n",
					udata);
				exit(1);
			} else if (
				((char *)udata)[strlen((char *)udata)-1] != '.')
				exit(0);
		} else
			udata = *p;
		break;
	case CMD_CHTTL:
		if (!parse_time(&x, argv[optind++])) {
			fprintf(stderr, "can't parse time \"%s\"\n",
					argv[optind-1]);
			usage();
		}
		udata = &x;
		break;
	}

	while (argc > optind) {
		name = argv[optind++];

		/*
		 * Get the object using expand name magic.
		 */
		if (*name == '[') {
			ores = nis_list(name,
			    fpath|allres|FOLLOW_LINKS|MASTER_ONLY|EXPAND_NAME,
					change_entry, udata);
			if (ores->status != NIS_CBRESULTS &&
			    ores->status != NIS_NOTFOUND) {
				if (!force) {
					nis_perror(ores->status, name);
					error = 1;
				}
			}
		} else {
			ores = nis_lookup(name, flinks|MASTER_ONLY|EXPAND_NAME);
			if (ores->status != NIS_SUCCESS) {
				if (!force) {
					nis_perror(ores->status, name);
					error = 1;
				}
				goto loop;
			}

			/*
			 * Construct the name for the object that we found.
			 */
			bad_name = (snprintf(oname, sizeof (oname), "%s.",
					ores->objects.objects_val[0].zo_name)
						>= sizeof (oname));
			if (!bad_name &&
			    *(ores->objects.objects_val[0].zo_domain) != '.')
				bad_name = (strlcat(oname,
					ores->objects.objects_val[0].zo_domain,
					sizeof (oname)) >= sizeof (oname));

			if (bad_name) {
				if (!force) {
					fprintf(stderr, "%s: ", oname);
					nis_perror(NIS_BADNAME,
						"can't modify object");
					error = 1;
				}
				goto loop;
			}

			/*
			 * Modify the object.
			 */
			newobj = ores->objects.objects_val[0];
			change_object(&newobj, udata);
			mres = nis_modify(oname, &newobj);
			if (mres->status != NIS_SUCCESS) {
				if (!force) {
					fprintf(stderr, "%s: ", oname);
					nis_perror(mres->status,
						"can't modify object");
					error = 1;
				}
			}
			nis_freeresult(mres);
		}

	loop:
		nis_freeresult(ores);
	}

	return (error);
}
