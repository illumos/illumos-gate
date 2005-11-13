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

#include <libscf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include "ksslcfg.h"

void
usage_delete(boolean_t do_print)
{
	if (do_print)
		(void) fprintf(stderr, gettext("Usage:\n"));
	(void) fprintf(stderr,
	    "ksslcfg delete [-v] [<server_address>] <server_port>\n");
}

#define	DEFAULT_TIMEOUT	60000000
#define	INIT_WAIT_USECS	50000

void
wait_till_to(char *fmri)
{
	char *state;
	useconds_t max;
	useconds_t usecs;
	uint64_t *cp = NULL;
	scf_simple_prop_t *sp = NULL;

	max = DEFAULT_TIMEOUT;

	if (((sp = scf_simple_prop_get(NULL, fmri, "stop",
	    SCF_PROPERTY_TIMEOUT)) != NULL) &&
	    ((cp = scf_simple_prop_next_count(sp)) != NULL) && (*cp != 0))
		max = (*cp) * 1000000;	/* convert to usecs */

	if (sp != NULL)
		scf_simple_prop_free(sp);

	for (usecs = INIT_WAIT_USECS; max > 0; max -= usecs) {
		/* incremental wait */
		usecs *= 2;
		usecs = (usecs > max) ? max : usecs;

		(void) usleep(usecs);

		/* Check state after the wait */
		if ((state = smf_get_state(fmri)) != NULL) {
			if (strcmp(state, "disabled") == 0)
				return;
		}
	}

	(void) fprintf(stderr, gettext("Warning: delete %s timed out.\n"),
	    fmri);
}

int
delete_instance(const char *instance_name)
{
	int status = FAILURE;
	char *buf;
	boolean_t errflag = B_FALSE;
	ssize_t max_fmri_len;
	scf_scope_t *scope;
	scf_service_t *svc;
	scf_handle_t *handle;
	scf_instance_t *instance;

	handle = scf_handle_create(SCF_VERSION);
	if (handle == NULL) {
		errflag = B_TRUE;
		KSSL_DEBUG("scf_handle_create failed: %s\n",
		    scf_strerror(scf_error()));
		goto out1;
	}
	KSSL_DEBUG("scf_handle_create succeeded\n");

	if (scf_handle_bind(handle) == -1) {
		errflag = B_TRUE;
		KSSL_DEBUG("scf_handle_bind failed: %s\n",
		    scf_strerror(scf_error()));
		goto out1;
	}
	KSSL_DEBUG("scf_handle_bind succeeded\n");

	if ((scope = scf_scope_create(handle)) == NULL) {
		errflag = B_TRUE;
		KSSL_DEBUG("scf_scope_create failed: %s\n",
		    scf_strerror(scf_error()));
		goto out2;
	}
	KSSL_DEBUG("scf_scope_create succeeded\n");

	if ((svc = scf_service_create(handle)) == NULL) {
		errflag = B_TRUE;
		KSSL_DEBUG("scf_service_create failed: %s\n",
		    scf_strerror(scf_error()));
		goto out3;
	}
	KSSL_DEBUG("scf_service_create succeeded\n");

	if (scf_handle_get_scope(handle, SCF_SCOPE_LOCAL, scope) == -1) {
		errflag = B_TRUE;
		KSSL_DEBUG("scf_handle_get_scope failed: %s\n",
		    scf_strerror(scf_error()));
		goto out4;
	}
	KSSL_DEBUG("scf_handle_get_scope succeeded\n");

	if (scf_scope_get_service(scope, SERVICE_NAME, svc) < 0) {
		scf_error_t scf_errnum = scf_error();

		if (scf_errnum != SCF_ERROR_NOT_FOUND) {
			errflag = B_TRUE;
			KSSL_DEBUG(
			    "ERROR scf_scope_get_service failed: %s\n",
			    scf_strerror(scf_errnum));
		}
		goto out4;
	} else {
		KSSL_DEBUG("scf_scope_get_service succeeded\n");
	}

	instance = scf_instance_create(handle);
	if (instance == NULL) {
		errflag = B_TRUE;
		KSSL_DEBUG("scf_instance_create failed: %s\n",
		    scf_strerror(scf_error()));
		goto out4;
	}

	if (scf_service_get_instance(svc, instance_name, instance) != 0) {
		scf_error_t scf_errnum = scf_error();

		if (scf_errnum == SCF_ERROR_NOT_FOUND) {
			status = SUCCESS;
		} else {
			errflag = B_TRUE;
			KSSL_DEBUG(
			    "ERROR scf_scope_get_service failed: %s\n",
			    scf_strerror(scf_errnum));
		}
		scf_instance_destroy(instance);
		goto out4;
	}

	max_fmri_len = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	if ((buf = malloc(max_fmri_len + 1)) == NULL)
		goto out4;

	if (scf_instance_to_fmri(instance, buf, max_fmri_len + 1) > 0) {
		char *state;

		KSSL_DEBUG("instance_fmri=%s\n", buf);
		state = smf_get_state(buf);
		if (state)
			KSSL_DEBUG("state=%s\n", state);
		if (state && strcmp(state, "online") == 0) {
			if (smf_disable_instance(buf, 0) != 0) {
				errflag = B_TRUE;
				KSSL_DEBUG(
				    "smf_disable_instance failed: %s\n",
				    scf_strerror(scf_error()));
			} else {
				/*
				 * Wait for some time till timeout to avoid
				 * a race with scf_instance_delete() below.
				 */
				wait_till_to(buf);
			}
		}
	}

	if (scf_instance_delete(instance) != 0) {
		errflag = B_TRUE;
		KSSL_DEBUG(
		    "ERROR scf_instance_delete failed: %s\n",
		    scf_strerror(scf_error()));
		goto out4;
	} else {
		KSSL_DEBUG("deleted %s\n", instance_name);
	}

	status = SUCCESS;

out4:
	scf_service_destroy(svc);
out3:
	scf_scope_destroy(scope);
out2:
	(void) scf_handle_unbind(handle);
out1:
	if (handle != NULL)
		scf_handle_destroy(handle);
	if (errflag)
		(void) fprintf(stderr, gettext(
		    "Unexpected fatal libscf error: %s.  Exiting.\n"),
		    scf_strerror(scf_error()));
	return (status);
}

int
do_delete(int argc, char *argv[])
{
	char c;
	int status, len, pcnt;
	char address_port[MAX_ADRPORT_LEN + 1];
	char *instance_name;

	if (argc < 3) {
		goto err;
	}

	argc -= 1;
	argv += 1;

	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			verbose = B_TRUE;
			break;
		default:
			goto err;
		}
	}

	pcnt = argc - optind;
	if (pcnt == 1) {
		if (strlen(argv[optind]) < MAX_ADRPORT_LEN) {
			(void) strcpy(address_port, argv[optind]);
		} else {
			(void) fprintf(stderr, gettext(
			    "argument too long -- %s\n"),
			    argv[optind]);
			return (FAILURE);
		}
	} else if (pcnt == 2) {
		if ((len = strlen(argv[optind])) +
		    (strlen(argv[optind + 1])) < MAX_ADRPORT_LEN) {
			(void) strcpy(address_port, argv[optind]);
			address_port[len] = ' ';
			(void) strcpy(address_port + len + 1, argv[optind + 1]);
		} else {
			(void) fprintf(stderr, gettext(
			    "arguments too long -- %s %s\n"),
			    argv[optind], argv[optind + 1]);
			return (FAILURE);
		}
	} else {
		goto err;
	}

	instance_name = create_instance_name(address_port, NULL, B_FALSE);
	if (instance_name == NULL) {
		return (FAILURE);
	}

	KSSL_DEBUG("instance_name=%s\n", instance_name);
	status = delete_instance(instance_name);
	free(instance_name);

	return (status);

err:
	usage_delete(B_TRUE);
	return (ERROR_USAGE);
}
