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
 * prophist - property history utility
 *
 * 1.  Description
 *
 * During the development of smf(5), a set of service manifests were delivered
 * that required subsequent changes.  The bulk of these changes are in ON,
 * although additional consolidations may possess one or two manifests that are
 * affected.  These incorrect values need to be smoothed into a correct
 * configuration surface for subsequent automatic merge technology to be
 * introduced safely.  The mechanism is the combination of this utility with a
 * set of "property history" files.
 *
 * /var/svc/profile/prophist.SUNWcsr is delivered as an immutable file by the
 * SUNWcsr packages.  prophist.SUNWcsr covers the entire ON consolidation, for
 * the purposes of collecting in one place what is essentially a temporary
 * construct.  Other consolidations should deliver /var/svc/profile/prophist.*
 * files.
 *
 * The processing of the property history files occurs in
 * svc:/system/manifest-import:default.  Each prophist.* file is checked against
 * its hashed value in smf/manifest using the "hash" subcommand.  If a change is
 * detected, the prophist.* file is sourced.  These operations are carried out
 * prior to any manifest being imported.
 *
 * 2.  Interface
 *
 * prophist presents a subcommand style interface, with various suboptions to
 * each subcommand:
 *
 * prophist delete -e FMRI -g pg [-p prop]
 * prophist upgrade -e FMRI -g pg -p prop -n newval oldval ...
 * prophist overwrite -e FMRI -g pg -p prop -n newval
 * prophist hash file
 *
 * The hash subcommand signals that a file requires processing using an exit
 * status of 3.  Otherwise, exit statuses of 0, 1, and 2 have their conventional
 * meaning.
 *
 * 3.  Limitations
 *
 * The present implementation has no support for multiply-valued properties.
 * Manipulation of such properties should be done using a svccfg(1M) invocation
 * in the appropriate prophist.* file.
 */

#include <sys/types.h>

#include <assert.h>
#include <libintl.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <manifest_hash.h>

#define	OPTIONS_STR	"e:g:n:p:"

static int o_delete;
static int o_hash;
static int o_overwrite;

static char *entity;
static char *pgrp_name;
static char *prop_name;
static char *new_value;

static scf_handle_t *hndl;
static scf_service_t *svc;
static scf_instance_t *inst;
static scf_snapshot_t *snap;
static scf_snaplevel_t *level;
static scf_propertygroup_t *pg;
static scf_property_t *prop;
static scf_value_t *value;
static scf_iter_t *iter;
static scf_transaction_t *tx;
static scf_transaction_entry_t *entry;

static scf_type_t ptype;

static char *valbuf;
static ssize_t valbuf_sz;

#define	LG_BUFSIZ	1024		/* larger than a property name */
static char namebuf[LG_BUFSIZ];

static void
usage()
{
	(void) fprintf(stderr, gettext(
	    "Usage:"
	    "\tprophist hash file\n"
	    "\tprophist delete -e FMRI -g pg [-p prop]\n"
	    "\tprophist overwrite -e FMRI -g pg -p prop -n newval\n"
	    "\tprophist upgrade -e FMRI -g pg -p prop -n newval oldval "
	    "...\n"));
	exit(UU_EXIT_USAGE);
}

static void
ready_scf_objects()
{
	if ((hndl = scf_handle_create(SCF_VERSION)) == NULL)
		uu_die(gettext("handle creation failed: %s\n"),
		    scf_strerror(scf_error()));

	if (scf_handle_bind(hndl) != 0)
		uu_die(gettext("handle bind failed: %s\n"),
		    scf_strerror(scf_error()));

	svc = scf_service_create(hndl);
	inst = scf_instance_create(hndl);
	snap = scf_snapshot_create(hndl);
	level = scf_snaplevel_create(hndl);
	pg = scf_pg_create(hndl);
	prop = scf_property_create(hndl);
	value = scf_value_create(hndl);
	iter = scf_iter_create(hndl);
	tx = scf_transaction_create(hndl);
	entry = scf_entry_create(hndl);

	if (svc == NULL ||
	    inst == NULL ||
	    snap == NULL ||
	    level == NULL ||
	    pg == NULL ||
	    prop == NULL ||
	    value == NULL ||
	    iter == NULL ||
	    tx == NULL ||
	    entry == NULL)
		uu_die(gettext("object creation failed: %s\n"),
		    scf_strerror(scf_error()));

	valbuf_sz = 4096;
	valbuf = malloc(valbuf_sz);
	if (valbuf == NULL)
		uu_die(gettext("value buffer allocation failed"));
}

static int
hash(char *arg)
{
	char *pname;
	char *errstr;
	int ret;
	uchar_t hash[MHASH_SIZE];

	ready_scf_objects();

	switch (ret = mhash_test_file(hndl, arg, 0, &pname, hash)) {
	case MHASH_RECONCILED:
		/* Equivalent hash already stored. */
		return (0);
	case MHASH_NEWFILE:
		/* Hash differs. */
		break;
	case MHASH_FAILURE:
		uu_die(gettext("mhash_test_file() failed"));
	default:
		uu_die(gettext("unknown return value (%d) from "
		    "mhash_test_file()"), ret);
	}

	if (mhash_store_entry(hndl, pname, arg, hash, &errstr)) {
		if (errstr)
			uu_die(errstr);
		else
			uu_die(gettext("Unknown error from "
			    "mhash_store_entry()\n"));
	}

	return (3);
}

static int
delete_prop(scf_propertygroup_t *pg, char *prop_name)
{
	if (scf_transaction_start(tx, pg) != 0)
		uu_die(gettext("transaction start failed: %s\n"),
		    scf_strerror(scf_error()));
	if (scf_transaction_property_delete(tx, entry, prop_name) != 0)
		uu_die(gettext("transaction property delete failed: %s\n"),
		    scf_strerror(scf_error()));
	if (scf_transaction_commit(tx) != 1)
		return (1);

	return (0);
}

/*
 * Returns 1 if target property group or property not found.
 */
static int
delete_pg_or_prop(scf_iter_t *pg_iter, char *pgrp_name, char *prop_name)
{
	while (scf_iter_next_pg(pg_iter, pg) > 0) {
		if (scf_pg_get_name(pg, namebuf, LG_BUFSIZ) == -1)
			continue;

		if (strcmp(namebuf, pgrp_name) != 0)
			continue;

		if (prop_name != NULL)
			return (delete_prop(pg, prop_name));

		if (scf_pg_delete(pg) != 0)
			uu_die(gettext("property group delete failed: %s\n"),
			    scf_strerror(scf_error()));

		return (0);
	}

	return (1);
}

/*
 * Remove property group or property from both service and instance.
 */
static int
delete(char *entity, char *pgrp_name, char *prop_name)
{
	ready_scf_objects();

	if (scf_handle_decode_fmri(hndl, entity, NULL, svc, inst, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) == 0) {
		(void) scf_iter_instance_pgs(iter, inst);
		return (delete_pg_or_prop(iter, pgrp_name, prop_name));
	}

	if (scf_handle_decode_fmri(hndl, entity, NULL, svc, NULL, NULL,
	    NULL, SCF_DECODE_FMRI_EXACT) == 0) {
		(void) scf_iter_service_pgs(iter, svc);
		return (delete_pg_or_prop(iter, pgrp_name, prop_name));
	}

	uu_die(gettext("%s not decoded: %s\n"), entity,
	    scf_strerror(scf_error()));

	/*NOTREACHED*/
}

static void
replace_value(scf_propertygroup_t *pg, char *prop_name, char *new_value)
{
	int result;
	int ret;

	do {
		if (scf_pg_update(pg) == -1)
			uu_die(gettext("property group update failed: %s\n"),
			    scf_strerror(scf_error()));
		if (scf_transaction_start(tx, pg) != SCF_SUCCESS) {
			if (scf_error() == SCF_ERROR_PERMISSION_DENIED)
				uu_die(gettext("permission denied\n"));

			uu_die(gettext("transaction start failed: %s\n"),
			    scf_strerror(scf_error()));
		}

		ret = scf_pg_get_property(pg, prop_name, prop);
		if (ret == SCF_SUCCESS) {
			if (scf_property_type(prop, &ptype) != SCF_SUCCESS)
				uu_die(gettext("couldn't get property type\n"));
			if (scf_transaction_property_change_type(tx, entry,
			    prop_name, ptype) == -1)
				uu_die(gettext("couldn't change entry\n"));
		} else if (scf_error() == SCF_ERROR_INVALID_ARGUMENT) {
			uu_die(gettext("illegal property name\n"));
		} else {
			uu_die(gettext("property fetch failed\n"));
		}

		if (scf_value_set_from_string(value, ptype,
		    (const char *)new_value) != 0) {
			assert(scf_error() == SCF_ERROR_INVALID_ARGUMENT);
			uu_die(gettext("Invalid \"%s\" value \"%s\".\n"),
			    scf_type_to_string(ptype), new_value);
		}

		ret = scf_entry_add_value(entry, value);
		if (ret != SCF_SUCCESS)
			uu_die(gettext("scf_entry_add_value failed: %s\n"),
			    scf_strerror(scf_error()));

		assert(ret == SCF_SUCCESS);

		result = scf_transaction_commit(tx);

		scf_transaction_reset(tx);
		scf_entry_destroy_children(entry);
	} while (result == 0);

	if (result < 0) {
		if (scf_error() != SCF_ERROR_PERMISSION_DENIED)
			uu_die(gettext("transaction commit failed: %s\n"),
			    scf_strerror(scf_error()));

		uu_die(gettext("permission denied\n"));
	}
}

static scf_propertygroup_t *
get_pg(char *entity, char *pgrp_name, char *prop_name)
{
	scf_propertygroup_t *targetpg;

	ready_scf_objects();

	if (scf_handle_decode_fmri(hndl, entity, NULL, svc, inst, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) == 0) {
		/*
		 * 1.  Working at the instance level.  The instance level
		 * contains one special case:  general/enabled is active in the
		 * current version, and its value in snapshots is not relevant.
		 * Otherwise, pull from running snapshot.
		 */
		if (strcmp(pgrp_name, "general") == 0 &&
		    strcmp(prop_name, "enabled") == 0) {
			if (scf_instance_get_pg(inst, pgrp_name, pg) == 0)
				return (pg);

			uu_die(gettext("property group %s not available: %s\n"),
			    pgrp_name, scf_strerror(scf_error()));
		}

		if (scf_instance_get_snapshot(inst, "running", snap) == -1) {
			if (scf_instance_get_pg(inst, pgrp_name, pg) == 0)
				return (pg);

			uu_die(gettext("property group %s not available: %s\n"),
			    pgrp_name, scf_strerror(scf_error()));
		}

		if (scf_snapshot_get_base_snaplevel(snap, level) != 0)
			uu_die(gettext("base snaplevel not available: %s\n"),
			    scf_strerror(scf_error()));

		if (scf_snaplevel_get_pg(level, pgrp_name, pg) == -1)
			uu_die(gettext("property group %s not available: %s\n"),
			    pgrp_name, scf_strerror(scf_error()));

		targetpg = scf_pg_create(hndl);
		if (scf_instance_get_pg(inst, pgrp_name, targetpg) == -1)
			uu_die(gettext("property group %s not available: %s\n"),
			    pgrp_name, scf_strerror(scf_error()));

		return (targetpg);
	}

	if (scf_handle_decode_fmri(hndl, entity, NULL, svc, NULL, NULL,
	    NULL, SCF_DECODE_FMRI_EXACT) == 0) {
		/*
		 * 2.  Working at the service level.
		 */
		if (scf_service_get_pg(svc, pgrp_name, pg) == 0)
			return (pg);

		uu_die(gettext("property group %s not available: %s\n"),
		    pgrp_name, scf_strerror(scf_error()));
	}

	/*
	 * 3.  Cannot decode either instance or service exactly.
	 */
	uu_die(gettext("%s not decoded: %s\n"), entity,
	    scf_strerror(scf_error()));

	/*NOTREACHED*/
}

static int
upgrade(char *entity, char *pgrp_name, char *prop_name, char *new_value,
    int argc, char *argv[], int optind)
{
	int replace = 0;
	int vals = 0;
	scf_propertygroup_t *targetpg;

	targetpg = get_pg(entity, pgrp_name, prop_name);

	if (scf_pg_get_property(targetpg, prop_name, prop) != 0)
		uu_die(gettext("property %s/%s not available: %s\n"), pgrp_name,
		    prop_name, scf_strerror(scf_error()));

	if (scf_iter_property_values(iter, prop) != 0)
		uu_die(gettext("could not establish value iterator: %s\n"),
		    scf_strerror(scf_error()));

	while (scf_iter_next_value(iter, value) == 1) {
		if (scf_value_get_as_string(value, valbuf, valbuf_sz) < 0)
			uu_die(gettext("string value get failed: %s\n"),
			    scf_strerror(scf_error()));

		for (; optind < argc; optind++)
			if (strcmp(valbuf, argv[optind]) == 0) {
				replace = 1;
				break;
			}

		vals++;
		if (vals > 1)
			uu_die(gettext("too many values to upgrade\n"));
	}

	if (replace)
		replace_value(targetpg, prop_name, new_value);

	return (0);
}

static int
overwrite(char *entity, char *pgrp_name, char *prop_name, char *new_value)
{
	scf_propertygroup_t *targetpg;

	targetpg = get_pg(entity, pgrp_name, prop_name);

	if (scf_pg_get_property(targetpg, prop_name, prop) != 0)
		uu_die(gettext("property %s/%s not available: %s\n"), pgrp_name,
		    prop_name, scf_strerror(scf_error()));

	replace_value(targetpg, prop_name, new_value);

	return (0);
}

int
main(int argc, char *argv[])
{
	int c;

	if (argc < 2)
		usage();

	if (strcmp(argv[1], "hash") == 0)
		o_hash = 1;
	else if (strcmp(argv[1], "delete") == 0)
		o_delete = 1;
	else if (strcmp(argv[1], "overwrite") == 0)
		o_overwrite = 1;
	else if (strcmp(argv[1], "upgrade") != 0)
		usage();

	(void) uu_setpname(argv[0]);

	argv++;
	argc--;

	while ((c = getopt(argc, argv, OPTIONS_STR)) != EOF) {
		switch (c) {
		case 'e':
			entity = optarg;
			break;
		case 'g':
			pgrp_name = optarg;
			break;
		case 'n':
			new_value = optarg;
			break;
		case 'p':
			prop_name = optarg;
			break;
		case '?':
		default:
			usage();
			break;
		}
	}

	if (o_hash) {
		if (entity != NULL ||
		    pgrp_name != NULL ||
		    prop_name != NULL ||
		    new_value != NULL)
			usage();

		return (hash(argv[optind]));
	}

	if (entity == NULL)
		usage();

	if (o_delete) {
		if (pgrp_name == NULL ||
		    new_value != NULL ||
		    optind < argc)
			usage();

		return (delete(entity, pgrp_name, prop_name));
	}

	if (pgrp_name == NULL || prop_name == NULL || new_value == NULL)
		usage();

	if (o_overwrite)
		return (overwrite(entity, pgrp_name, prop_name, new_value));

	if (optind >= argc)
		usage();

	return (upgrade(entity, pgrp_name, prop_name, new_value, argc, argv,
	    optind));
}
