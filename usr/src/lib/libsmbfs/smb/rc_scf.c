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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Support functions for getting things libsmbfs needs
 * from the SMF configuration (using libscf).
 */

#include <sys/types.h>
#include <sys/queue.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <libscf.h>

#include <cflib.h>
#include "rcfile_priv.h"

#define	IDMAP_SERVICE_FMRI		"svc:/system/idmap"
#define	IDMAP_PG_NAME			"config"
#define	MACHINE_UUID			"machine_uuid"

#define	SMBC_DEFAULT_INSTANCE_FMRI	"svc:/network/smb/client:default"

scf_handle_t *_scf_handle_create_and_bind(scf_version_t ver);

/*
 * Get the "machine_uuid" from idmap, as a string (allocated)
 */
char *
cf_get_client_uuid(void)
{
	char val_buf[64];
	char *ret = NULL;

	scf_handle_t		*h = NULL;
	scf_service_t		*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t		*prop = NULL;
	scf_value_t		*val = NULL;

	if ((h = _scf_handle_create_and_bind(SCF_VERSION)) == NULL)
		goto out;

	if ((svc = scf_service_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL)
		goto out;

	if (scf_handle_decode_fmri(h, IDMAP_SERVICE_FMRI,
	    NULL, svc, NULL, NULL, NULL, 0) == -1)
		goto out;


	if (scf_service_get_pg(svc, IDMAP_PG_NAME, pg) != 0)
		goto out;
	if (scf_pg_get_property(pg, MACHINE_UUID, prop) != 0)
		goto out;
	if (scf_property_get_value(prop, val) != 0)
		goto out;
	if (scf_value_get_as_string(val, val_buf, sizeof (val_buf)) < 0)
		goto out;

	ret = strdup(val_buf);

out:
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_service_destroy(svc);

	if (h != NULL)
		scf_handle_destroy(h);

	return (ret);
}

/*
 * Get the output of "sharectl get smbfs" into a file, without an
 * actual fork/exec of sharectl.
 *
 * Each section of the smbfs settings are represented as an SMF
 * property group with an "S-" prefix and a UUID, and the section
 * name itself a property which can have a more flexible name than
 * a property group name can have.
 */
int
rc_scf_get_sharectl(FILE *fp)
{
	char sect_name[256];
	char prop_name[256];
	char val_buf[1024];

	scf_handle_t		*h = NULL;
	scf_service_t		*svc = NULL;
	scf_instance_t		*inst = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t		*prop = NULL;
	scf_value_t		*val = NULL;
	scf_iter_t		*pgiter = NULL;
	scf_iter_t		*propiter = NULL;
	scf_iter_t		*valiter = NULL;
	int ret = -1;

	if ((h = _scf_handle_create_and_bind(SCF_VERSION)) == NULL)
		goto out;

	if ((svc = scf_service_create(h)) == NULL ||
	    (inst = scf_instance_create(h)) == NULL ||
	    (pgiter = scf_iter_create(h)) == NULL ||
	    (propiter = scf_iter_create(h)) == NULL ||
	    (valiter = scf_iter_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL)
		goto out;

	if (scf_handle_decode_fmri(h, SMBC_DEFAULT_INSTANCE_FMRI,
	    NULL, svc, inst, NULL, NULL, 0) == -1)
		goto out;

	if (scf_iter_instance_pgs_composed(pgiter, inst, NULL) == -1)
		goto out;
	while ((ret = scf_iter_next_pg(pgiter, pg)) == 1) {
		/*
		 * Using prop_name array for pg name temporarily.
		 * Skip any property groups names other than "S-*".
		 */
		if (scf_pg_get_name(pg, prop_name, sizeof (prop_name)) < 0)
			continue;
		if (strncmp(prop_name, "S-", 2) != 0)
			continue;

		/*
		 * Get the "section" name, which is a property of
		 * this property group.
		 */
		if (scf_pg_get_property(pg, "section", prop) != 0)
			continue;
		if (scf_property_get_value(prop, val) != 0)
			continue;
		if (scf_value_get_as_string(val, sect_name,
		    sizeof (sect_name)) < 0)
			continue;

		/*
		 * Have an S-* property group with a "section" name.
		 * Print the section start.
		 */
		fprintf(fp, "[%s]\n", sect_name);

		/*
		 * Now print the remaining properties in this PG,
		 * but skip the special "section" (name) prop.
		 */
		if (scf_iter_pg_properties(propiter, pg) == -1)
			goto out;
		while ((ret = scf_iter_next_property(propiter, prop)) == 1) {

			if (scf_property_get_name(prop, prop_name,
			    sizeof (prop_name)) < 0)
				continue;

			/* Skip the "section" prop. now */
			if (strcmp(prop_name, "section") == 0)
				continue;

			if (scf_property_get_value(prop, val) != 0)
				continue;

			if (scf_value_get_as_string(val, val_buf,
			    sizeof (val_buf)) < 0)
				continue;

			fprintf(fp, "%s=%s\n", prop_name, val_buf);
		}
	}
	ret = 0;

out:
	fflush(fp);

	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_iter_destroy(valiter);
	scf_iter_destroy(propiter);
	scf_iter_destroy(pgiter);
	scf_instance_destroy(inst);
	scf_service_destroy(svc);

	if (h != NULL)
		scf_handle_destroy(h);

	return (ret);
}

/*
 * Simple test wrapper.  Compile with:
 * cc -o rc_scf_test -I.. -DTEST_MAIN rc_scf.c -lscf
 */
#ifdef	TEST_MAIN
int
main(int argc, char **arv)
{
	char *s;
	int rc;

	rc = rc_scf_get_sharectl(stdout);
	printf("# rc=%d\n", rc);
	return (0);
}
#endif	/* TEST_MAIN */
