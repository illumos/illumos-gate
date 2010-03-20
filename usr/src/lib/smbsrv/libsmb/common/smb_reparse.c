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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <sys/fs_reparse.h>
#include <smbsrv/libsmb.h>

#include <syslog.h>

static int smb_reparse_init(const char *, nvlist_t **);
static void smb_reparse_free(nvlist_t *);
static int smb_reparse_set(const char *, nvlist_t *);

/*
 * Checks the status of the object specified by 'path'
 *
 * Returns 0 and fills 'stat' with the proper status on
 * success, otherwise returns an error code.
 */
int
smb_reparse_stat(const char *path, uint32_t *stat)
{
	struct stat statbuf;
	char symbuf[MAXREPARSELEN];
	int rptaglen;

	if (lstat(path, &statbuf) != 0) {
		if (errno == ENOENT) {
			*stat = SMB_REPARSE_NOTFOUND;
			return (0);
		}
		return (errno);
	}

	if ((statbuf.st_mode & S_IFMT) != S_IFLNK) {
		*stat = SMB_REPARSE_NOTREPARSE;
		return (0);
	}

	bzero(symbuf, MAXREPARSELEN);
	if (readlink(path, symbuf, MAXREPARSELEN) == -1)
		return (errno);

	rptaglen = strlen(FS_REPARSE_TAG_STR);
	if (strncmp(symbuf, FS_REPARSE_TAG_STR, rptaglen) != 0)
		*stat = SMB_REPARSE_NOTREPARSE;
	else
		*stat = SMB_REPARSE_ISREPARSE;

	return (0);
}

/*
 * If the reparse point specified by the path already exists
 * it is updated by given service type and its data. Update means
 * that if such service type does not already exist, it is added
 * otherwise it is overwritten by given data.
 *
 * If the reparse point does not exist, one is created with given
 * service type and its data.
 */
int
smb_reparse_svcadd(const char *path, const char *svctype, const char *svcdata)
{
	nvlist_t *nvl;
	int rc;

	if ((rc = smb_reparse_init(path, &nvl)) != 0)
		return (rc);

	if ((rc = reparse_add(nvl, svctype, svcdata)) != 0) {
		smb_reparse_free(nvl);
		return (rc);
	}

	rc = smb_reparse_set(path, nvl);
	smb_reparse_free(nvl);

	return (rc);
}

/*
 * Removes the entry for the given service type from the
 * specified reparse point. If there is no service entry
 * left, the reparse point object will be deleted.
 */
int
smb_reparse_svcdel(const char *path, const char *svctype)
{
	nvlist_t *nvl;
	int rc;

	if ((rc = smb_reparse_init(path, &nvl)) != 0)
		return (rc);

	if ((rc = reparse_remove(nvl, svctype)) != 0) {
		smb_reparse_free(nvl);
		return (rc);
	}

	if (nvlist_next_nvpair(nvl, NULL) == NULL) {
		/* list is empty remove the object */
		rc = reparse_delete(path);
		if ((rc != 0) && (rc == ENOENT))
			rc = 0;
	} else {
		rc = smb_reparse_set(path, nvl);
	}

	smb_reparse_free(nvl);
	return (rc);
}

/*
 * Obtains data of the given service type from the specified
 * reparse point. Function allocates the memory needed to hold
 * the service data so the caller must free this memory by
 * calling free().
 *
 * If 'svcdata' is NULL, successful return means that the reparse
 * point contains a record for the given service type.
 */
int
smb_reparse_svcget(const char *path, const char *svctype, char **svcdata)
{
	nvlist_t *nvl;
	nvpair_t *nvp;
	char *stype, *sdata;
	int rc;

	if ((rc = smb_reparse_init(path, &nvl)) != 0)
		return (rc);

	rc = ENODATA;
	nvp = nvlist_next_nvpair(nvl, NULL);

	while (nvp != NULL) {
		stype = nvpair_name(nvp);

		if ((stype != NULL) && (strcasecmp(stype, svctype) == 0)) {
			if ((rc = nvpair_value_string(nvp, &sdata)) != 0)
				break;

			if (svcdata != NULL) {
				if ((*svcdata = strdup(sdata)) == NULL)
					rc = ENOMEM;
			}

			rc = 0;
			break;
		}
		nvp = nvlist_next_nvpair(nvl, nvp);
	}

	smb_reparse_free(nvl);
	return (rc);
}

/*
 * Initializes the given nvpair list.
 *
 * This function assumes that the object specified by this path
 * is a reparse point, so it does not do any verification.
 *
 * If specified reparse point does not exist the function
 * returns successfully with an empty nvpair list.
 *
 * If the object exists and readlink is successful then nvpair
 * list is polulated with the reparse service information, otherwise
 * an error code is returned.
 */
static int
smb_reparse_init(const char *path, nvlist_t **nvl)
{
	char rp_data[MAXREPARSELEN];
	int rc;

	if ((*nvl = reparse_init()) == NULL)
		return (ENOMEM);

	bzero(rp_data, MAXREPARSELEN);
	if ((rc = readlink(path, rp_data, MAXREPARSELEN)) == -1) {
		if (errno == ENOENT)
			return (0);

		reparse_free(*nvl);
		return (errno);
	}

	if ((rc = reparse_parse(rp_data, *nvl)) != 0) {
		reparse_free(*nvl);
		return (rc);
	}

	return (0);
}

/*
 * Frees given nvlist
 */
static void
smb_reparse_free(nvlist_t *nvl)
{
	reparse_free(nvl);
}

/*
 * Create a reparse point with given services in the passed
 * nvlist. If the reparse point already exists, it will be
 * deleted and a new one with the given data is created.
 */
static int
smb_reparse_set(const char *path, nvlist_t *nvl)
{
	char *rp_data;
	int rc;

	if ((rc = reparse_unparse(nvl, &rp_data)) != 0)
		return (rc);

	rc = reparse_delete(path);
	if ((rc != 0) && (rc != ENOENT)) {
		free(rp_data);
		return (rc);
	}

	rc = reparse_create(path, rp_data);
	free(rp_data);

	return (rc);
}
