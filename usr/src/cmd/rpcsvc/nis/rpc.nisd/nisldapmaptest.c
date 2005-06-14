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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>
#include <malloc.h>

#include <lber.h>
#include <ldap.h>

#include <sys/param.h>
#include <rpcsvc/nis.h>
#include "nis_proc.h"
#include "nis_ldap.h"

#include "ldap_util.h"
#include "ldap_structs.h"
#include "ldap_print.h"
#include "ldap_attr.h"
#include "ldap_nisdbquery.h"
#include "ldap_ruleval.h"
#include "ldap_op.h"
#include "ldap_map.h"
#include "ldap_nisplus.h"

#include "nis_parse_ldap_conf.h"


/* Avoid having to link in nis_cleanup.o */
void
do_cleanup(cleanup *stuff) {
}

/* Parser assumes existence of 'verbose' */
int	verbose = 0;
/* ... as well as 'cons' */
FILE	*cons = stdout;

/* 'justTesting' means we can live with some fudging */
int	justTesting = 0;

/* 'setColumnsDuringConfig' is OK for us */
int	setColumnsDuringConfig = 1;


void
usage(char *prog) {
	fprintf(stderr,
		"Usage: %s [ -s | -r | -d ] ", prog);
	fprintf(stderr, "[ -l | -t table ] [ -v ] ");
	fprintf(stderr, "[ -i ] [ -o ] ");
	fprintf(stderr, "[ -m conffile ] ");
	fprintf(stderr, "[ -x attr=val ... ] ");
	fprintf(stderr, "[ col=val ...]\n");
}

int
main(int argc, char *argv[]) {

	int			ret, i, j, numVals, numEntries = 0, nq = 0;
	__nis_table_mapping_t	*t;
	db_query		**q, **qr;
	int			modify = 0, delete = 0, list = 0, asObj = 0;
	char			*myself = "main";
	char			*table = 0;
	int			freeTable = 0;
	char			*ldapConfFile = 0;
	char			**ldapCLA = 0;
	int			numLA = 0;
	int			c, saveVerbose;
	__nis_obj_attr_t	*attr;
	entry_obj		**ea = 0;
	int			numEa;

	while ((c = getopt(argc, argv, "srdlviom:x:t:")) != -1) {
		switch (c) {
		case 's':
			/* Search */
			modify = 0;
			delete = 0;
			break;
		case 'r':
			/* Replace/Modify/Add */
			modify = 1;
			delete = 0;
			break;
		case 'd':
			/* Delete */
			modify = 0;
			delete = 1;
			break;
		case 'l':
			/* List parser structures */
			list = 1;
			break;
		case 'v':
			/* Verbose mode */
			verbose = 1;
			break;
		case 'i':
			/*
			 * Allow fudging (i.e., guessing) at information
			 * that can't be retrieved (such as column names).
			 */
			justTesting = 1;
			break;
		case 'o':
			/* Work on object; affects tables */
			asObj = 1;
			break;
		case 'm':
			/* Config file name */
			ldapConfFile = optarg;
			break;
		case 'x':
			/* Attribute assignment */
			ldapCLA = realloc(ldapCLA,
					(numLA + 2) * sizeof (ldapCLA[0]));
			if (ldapCLA == 0) {
				fprintf(stderr,
				"Out of memory. realloc(%d) => NULL\n",
					(numLA + 2) * sizeof (ldapCLA[0]));
				return (-1);
			}
			ldapCLA[numLA++] = optarg;
			ldapCLA[numLA] = 0;
			break;
		case 't':
			/* NIS+ object */
			table = optarg;
			break;
		case '?':
		default:
			usage(argv[0]);
			return (-1);
		}
	}

	/*
	 * Make /var/nis our CWD, so that config files without a dir
	 * path get the correct default.
	 */
#define	OURCWD	"/var/nis"
	if (chdir(OURCWD) != 0) {
		fprintf(stderr, "Failure setting CWD to ");
		perror(OURCWD);
	}

	/*
	 * If 'verbose' is on, the parser spits out a listing of the
	 * mapping config file. However, since nisldapmaptest has an
	 * option specifically for that purpose, we unset 'verbose'
	 * while parsing.
	 */
	saveVerbose = verbose;
	verbose = 0;
	ret = parseConfig(ldapCLA, ldapConfFile);
	verbose = saveVerbose;
	if (ret == 1) {
		fprintf(stderr, "Mapping inactive\n");
		return (1);
	} else if (ret != 0) {
		fprintf(stderr, "Parse error for \"%s\" => %d\n",
			ldapConfFile ? ldapConfFile :
				"/var/nis/NIS+LDAPmapping",
			ret);
		return (ret);
	}

	if (list) {
		/* Don't bother locking the table for traversal */
		for (t = (__nis_table_mapping_t *)ldapMappingList.first;
			t != 0;
			t = (__nis_table_mapping_t *)t->item.nxt_item) {
			__nis_table_mapping_t	*m;
			for (m = t; m != 0; m = m->next) {
				printTableMapping(m);
				printbuf();
			}
		}
	}

	if (table != 0) {
		int	len = 0;
		char	*objPath = 0;

		table = fullObjName(F, table);
		if (table != 0) {
			freeTable = 1;
			len = strlen(table);
			objPath = calloc(1, len + MAXPATHLEN + 1);
		}
		if (table == 0 || objPath == 0 ||
				internal_table_name(table, objPath) == 0) {
			fprintf(stderr,
			"Unable to obtain internal object name for \"%s\"\n",
				table);
			if (freeTable)
				free(table);
			return (-1);
		}
		t = __nis_find_item_mt(objPath, &ldapMappingList, 1, 0);
		if (t == 0) {
			fprintf(stderr, "No mapping for \"%s\" (%s)\n",
				table, NIL(objPath));
			if (objPath != 0)
				free(objPath);
			if (freeTable)
				free(table);
			return (-1);
		}
		if (objPath != 0)
			free(objPath);
	} else {
		if (list)
			exit(0);
		usage(argv[0]);
		exit(-1);
	}

	if (asObj || t->objType != NIS_TABLE_OBJ) {
		char		*op;
		nis_object	*no = 0;

		/*
		 * Work on object (even if it's a table); ignore excess
		 * arguments
		 */
		if (modify) {
			ret = objToLDAP(t, 0, 0, 0);
			op = "objToLDAP";
		} else if (delete) {
			ret = deleteLDAPobj(t);
			op = "deleteLDAPobj";
		} else {
			ret = objFromLDAP(t, &no, &ea, &numEa);
			op = "objFromLDAP";
		}
		if (ret == LDAP_SUCCESS) {
			if (no != 0) {
				nis_print_object(no);
				if (no->zo_data.zo_type == NIS_DIRECTORY_OBJ &&
						ea != 0) {
					p2buf(myself, "Directory entries:\n");
					for (i = 0; i < numEa; i++) {
						p2buf(myself, "\t");
						sc2buf(myself,
			ea[i]->en_cols.en_cols_val[1].ec_value.ec_value_val,
			ea[i]->en_cols.en_cols_val[1].ec_value.ec_value_len);
						p2buf(myself, "\n");
					}
				}
				nis_destroy_object(no);
			}
			if (ea != 0)
				freeEntryObjArray(ea, numEa);
		} else {
			p2buf(myself, "%s(\"%s\") => %d (%s)\n",
				op, t->objName, ret,
				ldap_err2string(ret));
		}
		printbuf();
	} else if (optind < argc) {
		__nis_rule_value_t	*rv = 0;
		int			nv = 0;
		__nis_obj_attr_t	**attr = 0;
		/*
		 * Non-option arguments specify column names/values in
		 * "name=value" format.
		 */
		q = createQuery(argc-optind, &argv[optind], t,
			(modify || delete) ? &rv : 0, &nv);
		if (q == 0) {
			p2buf(myself, "Unable to create LDAP %s parameters\n",
				modify ? "modify" :
					(delete ? "delete" : "search"));
			if (freeTable)
				free(table);
			exit(-1);
		}
		if (modify) {
			ret = mapToLDAP(t, nv, 0, q, rv, 0, 0);
			if (ret != LDAP_SUCCESS) {
				p2buf(myself,
					"mapToLDAP(<modify>) => %d (%s)\n",
					ret, ldap_err2string(ret));
			}
		} else if (delete) {
			ret = mapToLDAP(t, nv, q, 0, rv, 0, 0);
			if (ret != LDAP_SUCCESS) {
				p2buf(myself,
					"mapToLDAP(<delete>) => %d (%s)\n",
					ret, ldap_err2string(ret));
			}
		} else {
			qr = mapFromLDAP(t, q[0], &nq, 0, &ret, &attr);
			if (qr != 0) {
				for (i = 0; i < nq; i++) {
					printQuery(qr[i], t);
					printbuf();
					freeQuery(qr[i]);
					if (attr != 0) {
						printObjAttr(attr[i]);
					}
				}
				free(qr);
				freeObjAttr(attr, nq);
			} else if (ret != LDAP_SUCCESS) {
				p2buf(myself,
					"mapFromLDAP() => %d (%s)\n",
					ret, ldap_err2string(ret));
			}
		}
		for (i = 0; i < nv; i++)
			freeQuery(q[i]);
		freeRuleValue(rv, nv);
		printbuf();
	} else if (!modify && !delete) {
		__nis_obj_attr_t	**attr = 0;
		/* Enumeration */
		qr = mapFromLDAP(t, 0, &nq, 0, &ret, &attr);
		if (qr != 0) {
			for (i = 0; i < nq; i++) {
				printQuery(qr[i], t);
				printbuf();
				freeQuery(qr[i]);
				if (attr != 0) {
					printObjAttr(attr[i]);
				}
			}
			freeObjAttr(attr, nq);
			free(qr);
		} else if (ret != LDAP_SUCCESS) {
			p2buf(myself,
				"mapFromLDAP() => %d (%s)\n",
				ret, ldap_err2string(ret));
		}
		printbuf();
	} else {
		usage(argv[0]);
	}

	if (freeTable)
		free(table);
	if (t != 0)
		__nis_release_item(t, &ldapMappingList, 1);

	if (numMisaligned > 0)
		fprintf(stderr, "numMisaligned = %d\n", numMisaligned);

	return (0);
}

/*
 * As long as we're single-threaded, we need a private version of
 * assertExclusive that always returns success.
 */
int
assertExclusive(void *unused) {
	return (1);
}
