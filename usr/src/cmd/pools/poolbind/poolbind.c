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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * poolbind - bind processes, tasks, and projects to pools, and query process
 * pool bindings
 */

#include <libgen.h>
#include <pool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <locale.h>
#include <libintl.h>

#include <sys/procset.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <project.h>
#include <zone.h>

#include "utils.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	eFLAG	0x1
#define	iFLAG	0x2
#define	pFLAG	0x4
#define	qFLAG	0x8
#define	QFLAG	0x10

static const char OPTS[] = "Qei:p:q";
static struct {
	idtype_t idtype;
	char *str;
} idtypes[] = {
	{ P_PID, "pid" },
	{ P_TASKID, "taskid" },
	{ P_PROJID, "projid" },
	{ P_PROJID, "project" },
	{ P_ZONEID, "zoneid" },
	{ -1, NULL }
};

int error = E_PO_SUCCESS;

void exec_cmd(char *, char *[]);
void process_ids(char *, uint_t, idtype_t, char *, int, char *[]);

void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("Usage:\n"
	    "    poolbind -p pool_name -e command [arguments...]\n"
	    "    poolbind -p pool_name "
	    "[-i pid | -i taskid | -i projid | -i zoneid] id ...\n"
	    "    poolbind -q pid ...\n"
	    "    poolbind -Q pid ... \n"));
	exit(E_USAGE);
}

int
print_resource_binding(const char *type, pid_t pid)
{
	char *resource_name;

	if ((resource_name = pool_get_resource_binding(type, pid)) == NULL)
		warn(gettext("getting '%s' binding for %d: %s\n"), type,
		    (int)pid, get_errstr());
	else
		(void) printf("%d\t%s\t%s\n", (int)pid, type, resource_name);
	free(resource_name);
	return (PO_SUCCESS);
}

int
main(int argc, char *argv[])
{
	int c;
	int i;
	idtype_t idtype = P_PID;
	char *idstr = "pid";
	char *pool_name = NULL;
	uint_t flags = 0;
	int status;

	(void) getpname(argv[0]);
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, OPTS)) != EOF) {
		switch (c) {
		case 'Q':
			if (flags & (qFLAG | iFLAG | pFLAG))
				usage();
			flags |= QFLAG;
			break;
		case 'e':
			if (flags & (iFLAG | qFLAG | QFLAG))
				usage();
			flags |= eFLAG;
			break;
		case 'i':
			for (i = 0; idtypes[i].str != NULL; i++) {
				if (strcmp(optarg, idtypes[i].str) == 0) {
					idtype = idtypes[i].idtype;
					idstr = idtypes[i].str;
					break;
				}
			}
			if ((flags & (iFLAG | qFLAG | QFLAG)) ||
			    idtypes[i].str == NULL)
				usage();
			flags |= iFLAG;
			break;
		case 'p':
			if (flags & (pFLAG | qFLAG | QFLAG))
				usage();
			flags |= pFLAG;
			pool_name = optarg;
			break;
		case 'q':
			if (flags & (pFLAG | iFLAG | QFLAG))
				usage();
			flags |= qFLAG;
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (flags & eFLAG && pool_name == NULL)
		usage();
	if (argc < 1 || (flags & (pFLAG | qFLAG | QFLAG)) == 0)
		usage();

	/*
	 * Check to see that the pools facility is enabled
	 */
	if (pool_get_status(&status) != PO_SUCCESS)
		die((ERR_OPEN_DYNAMIC), get_errstr());
	if (status == POOL_DISABLED)
		die((ERR_OPEN_DYNAMIC), strerror(ENOTACTIVE));

	if (flags & eFLAG)
		exec_cmd(pool_name, argv);
		/*NOTREACHED*/
	else
		process_ids(pool_name, flags, idtype, idstr, argc, argv);

	return (error);
}

void
exec_cmd(char *pool_name, char *argv[])
{
	if (pool_set_binding(pool_name, P_PID, getpid()) != PO_SUCCESS) {
		warn(gettext("binding to pool '%s': %s\n"), pool_name,
		    get_errstr());
		error = E_ERROR;
		return;
	}

	if (execvp(argv[0], argv) == -1)
		die(gettext("exec of %s failed"), argv[0]);
	/*NOTREACHED*/
}

void
process_ids(char *pool_name, uint_t flags, idtype_t idtype, char *idstr,
    int argc, char *argv[])
{
	int i;
	id_t id;

	for (i = 0; i < argc; i++) {
		char *endp;
		char *poolname;

		errno = 0;
		id = (id_t)strtol(argv[i], &endp, 10);
		if (errno != 0 ||
		    (endp && endp != argv[i] + strlen(argv[i])) ||
		    (idtype == P_ZONEID &&
		    getzonenamebyid(id, NULL, 0) == -1)) {
			/*
			 * The string does not completely parse to
			 * an integer, or it represents an invalid
			 * zone id.
			 */

			/*
			 * It must be a project or zone name.
			 */
			if (idtype == P_ZONEID) {
				if (zone_get_id(argv[i], &id) != 0) {
					warn(gettext("invalid zone '%s'\n"),
					    argv[i]);
					error = E_ERROR;
					continue;
				}
				/* make sure the zone is booted */
				if (id == -1) {
					warn(gettext("zone '%s' is not "
					    "active\n"), argv[i]);
					error = E_ERROR;
					continue;
				}
			} else if (idtype == P_PROJID) {
				if ((id = getprojidbyname(argv[i])) < 0) {
					warn(gettext("failed to get project "
					    "id for project: '%s'"), argv[i]);
					error = E_ERROR;
					continue;
				}
			} else {
				warn(gettext("invalid %s '%s'\n"),
				    idstr, argv[i]);
				error = E_ERROR;
				continue;
			}
		}

		if (flags & pFLAG) {
			if (pool_set_binding(pool_name, idtype, id) !=
			    PO_SUCCESS) {
				warn(gettext("binding %s %ld to pool '%s': "
				    "%s\n"), idstr, id, pool_name,
				    get_errstr());
				error = E_ERROR;
			}
			continue;
		}

		if (flags & qFLAG) {
			if ((poolname = pool_get_binding(id)) == NULL) {
				warn(gettext("couldn't determine binding for "
				    "pid %ld: %s\n"), id, get_errstr());
				error = E_ERROR;
			} else {
				(void) printf("%ld\t%s\n", id, poolname);
				free(poolname);
			}
		}
		if (flags & QFLAG) {
			uint_t j, count;
			const char **resource_types;
			(void) pool_resource_type_list(NULL, &count);

			if ((resource_types = malloc(count *
			    sizeof (const char *))) == NULL) {
				warn(gettext("couldn't allocate query memory "
				    "for pid %ld: %s\n"), id, get_errstr());
				error = E_ERROR;
			}
			(void) pool_resource_type_list(resource_types, &count);

			for (j = 0; j < count; j++)
				(void) print_resource_binding(resource_types[j],
				    (pid_t)id);
			free(resource_types);
		}
	}
}
