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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include "startd.h"

/*
 * The service deathrow mechanism addresses the problem of removing services
 * from a non accessible SMF repository. In this case, we can't simply use the
 * "SVCCFG_REPOSITORY=$ROOT/etc/svc/repository.db svccfg delete service_fmri"
 * command as the alternate repository format is not committed and could be
 * incompatible with the local SMF commands version.
 *
 * The idea is to manage a file (/etc/svc/deathrow) on the alternate root
 * directory that lists the FMRIs that need to disappear from the repository
 * when the system that uses this root directory boots up.
 * r.manifest and i.manifest update the file /etc/svc/deathrow in the alternate
 * root case.
 *
 * When svc.startd daemon launches, it first reads the /etc/svc/deathrow file
 * and for all FMRIs listed in this file, the service is not configured and
 * dependencies on it are forced satisfied (during svc.startd init time only).
 *
 * Than manifest-import service will actually, as first task, delete the
 * unconfigured services found in the /etc/svc/deathrow file and the
 * manifest hash entry from the repository.
 *
 */

#define	SVC_DEATHROW_FILE	"/etc/svc/deathrow"

/*
 * These data structures are unprotected because they
 * are modified by a single thread, at startup time.
 * After initialization, these data structures are
 * used only in read mode, thus requiring no protection.
 */

/* list of deathrow fmris, created from the file SVC_DEATHROW_FILE */
typedef struct deathrow {
    char *fmri;
    uu_list_node_t deathrow_link;
} deathrow_t;

static uu_list_pool_t *deathrow_pool;
static uu_list_t *deathrow_list;

static boolean_t deathrow_handling_status = B_FALSE;

static deathrow_t *fmri_in_deathrow_internal(const char *);
static void deathrow_add(const char *);

static void
deathrow_handling_start()
{
	assert(deathrow_handling_status == B_FALSE);
	deathrow_handling_status = B_TRUE;
}

static void
deathrow_handling_stop()
{
	assert(deathrow_handling_status == B_TRUE);
	deathrow_handling_status = B_FALSE;
}

void
deathrow_init()
{
	FILE *file;
	char *line;
	char *fmri;
	char *manifest;
	char *pkgname;
	size_t line_size, sz;
	unsigned int line_parsed = 0;

	log_framework(LOG_DEBUG, "Deathrow init\n");

	while ((file = fopen(SVC_DEATHROW_FILE, "r")) == NULL) {
		if (errno == EINTR) {
			continue;
		}
		if (errno != ENOENT) {
			log_framework(LOG_ERR,
			    "Deathrow not processed. "
			    "Error opening file (%s): %s\n",
			    SVC_DEATHROW_FILE, strerror(errno));
		}
		return;
	}

	deathrow_pool = uu_list_pool_create("deathrow",
	    sizeof (deathrow_t), offsetof(deathrow_t, deathrow_link),
	    NULL, UU_LIST_POOL_DEBUG);
	if (deathrow_pool == NULL) {
		uu_die("deathrow_init couldn't create deathrow_pool");
	}

	deathrow_list = uu_list_create(deathrow_pool,  deathrow_list, 0);
	if (deathrow_list == NULL) {
		uu_die("deathrow_init couldn't create deathrow_list");
	}

	/*
	 * A deathrow file line looks like:
	 * <fmri>< ><manifest path>< ><package name><\n>
	 * (field separator is a space character)
	 */
	line_size = max_scf_fmri_size + 3 + MAXPATHLEN + MAXNAMELEN;
	line = (char *)startd_alloc(line_size);
	*line = '\0';

	while (fgets(line, line_size, file) != NULL) {
		line_parsed++;
		fmri = NULL;
		manifest = NULL;
		pkgname = NULL;
		sz = strlen(line);
		if (sz > 0) {
			/* remove linefeed */
			if (line[sz - 1] == '\n') {
				line[sz - 1] = '\0';
			}
			manifest = strchr(line, ' ');
			if (manifest != NULL) {
				fmri = line;
				*manifest = '\0';
				manifest++;
				pkgname = strchr(manifest, ' ');
				if (pkgname != NULL) {
					*pkgname = '\0';
					pkgname++;
				}
			}
		}
		if (fmri != NULL && strlen(fmri) > 0 &&
		    strlen(fmri) < max_scf_fmri_size &&
		    manifest != NULL && strlen(manifest) > 0 &&
		    pkgname != NULL && strlen(pkgname) > 0) {
			log_framework(LOG_DEBUG,
			    "Deathrow parser <%s><%s><%s>\n",
			    fmri, manifest, pkgname);
			if (fmri_in_deathrow_internal(fmri) == NULL) {
				/* fmri is not in list, add fmri */
				deathrow_add(fmri);
			}
		} else {
			log_framework(LOG_ERR,
			    "Deathrow error processing file (%s). "
			    "Skipping line %u.\n",
			    SVC_DEATHROW_FILE, line_parsed);
		}
		*line = '\0';
	}
	startd_free(line, line_size);
	(void) fclose(file);

	if (uu_list_first(deathrow_list) != NULL) {
		deathrow_handling_start();
	}
}

void
deathrow_fini()
{
	deathrow_t *d;
	void *cookie = NULL;

	if (deathrow_handling_status == B_FALSE) {
		log_framework(LOG_DEBUG, "Deathrow fini\n");
		return;
	}
	deathrow_handling_stop();

	while ((d = uu_list_teardown(deathrow_list, &cookie)) != NULL) {
		startd_free(d->fmri, strlen(d->fmri) + 1);
		startd_free(d, sizeof (deathrow_t));
	}

	uu_list_destroy(deathrow_list);
	uu_list_pool_destroy(deathrow_pool);
	deathrow_pool = NULL;
	deathrow_list = NULL;
	log_framework(LOG_DEBUG, "Deathrow fini\n");
}

static void
deathrow_add(const char *fmri)
{
	deathrow_t *d;

	assert(fmri != NULL);

	d = startd_alloc(sizeof (deathrow_t));
	d->fmri = startd_alloc(strlen(fmri) + 1);
	(void) strcpy(d->fmri, fmri);
	uu_list_node_init(d, &d->deathrow_link, deathrow_pool);
	(void) uu_list_insert_after(deathrow_list, NULL, d);

	log_framework(LOG_DEBUG, "Deathrow added <%s>\n", d->fmri);
}

static deathrow_t *
fmri_in_deathrow_internal(const char *fmri)
{
	deathrow_t *d;

	assert(fmri != NULL);
	assert(deathrow_pool != NULL);
	assert(deathrow_list != NULL);

	for ((d = uu_list_first(deathrow_list)); d != NULL;
	    d = uu_list_next(deathrow_list, d)) {
		if (strcmp(fmri, d->fmri) == 0) {
			return (d);
		}
	}
	return (NULL);
}

boolean_t
is_fmri_in_deathrow(const char *fmri)
{
	if (deathrow_handling_status == B_FALSE) {
		return (B_FALSE);
	}
	return ((fmri_in_deathrow_internal(fmri) != NULL) ? B_TRUE : B_FALSE);
}
