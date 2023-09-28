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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * The primary role of this file is to obtain a list of manifests that are
 * located in a specified directory or one of its subdirectories.  The
 * find_manifests() function provides this service, and
 * free_manifest_array() is used to free the memory associated with the
 * returned list.
 *
 * The find_manifests() function can return an array consisting of all the
 * .xml files in the directory and its subdirectories.  Alternatively,
 * find_manifests() can be asked to only return new manifests based on the
 * return of mhash_test_file().  The list that is returned is an array of
 * pointers to manifest_info structures.
 *
 * Implementation Notes:
 * ====================
 * This module makes use of the nftw(3C) function to scan the directory.
 * nftw() calls a processing function for every file that it finds.
 * Unfortunately, nftw does not allow us to pass in any structure pointers
 * to the processing function, and that makes it hard to accumulate a list.
 * Thus, we will use the thread specific data area to hold data that must
 * be retained between calls to the processing function.  This will allow
 * this module to be used in multi-threaded applications if the need
 * arises.
 */

#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <libscf.h>
#include <libuutil.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "manifest_find.h"
#include "manifest_hash.h"

#define	MAX_DEPTH	24

/* Thread specific data */
typedef struct mftsd {
	manifest_info_t ** tsd_array;	/* Array of manifest_info structs */
	int		tsd_count;	/* Number items in list */
	int		tsd_max;	/* Number of pointers allocated */
					/* at tsd_array. */
	int		tsd_flags;	/* Check flags for hash and extension */
	scf_handle_t	*tsd_hndl;	/* Handle for libscf. */
} mftsd_t;

static pthread_key_t tsd_key = PTHREAD_ONCE_KEY_NP;

/*
 * Add the manifest info consisting of filename (fn), hash property name
 * (pname) and hash to the array at tsd_array.  If necessary, realloc()
 * will be called to increase the size of the buffer at tsd_array.
 *
 * Returns 0 on success and -1 on failure.  If a failure occurs, errno will
 * be set.
 */
static int
add_pointer(mftsd_t *tsdp, const char *fn, const char *pname, uchar_t *hash)
{
	manifest_info_t *info;
	manifest_info_t **newblock;
	int new_max;

	if (tsdp->tsd_count >= (tsdp->tsd_max - 1)) {
		/* Need more memory. */
		new_max = (tsdp->tsd_max == 0) ? 16 : 2 * tsdp->tsd_max;
		newblock = realloc(tsdp->tsd_array,
		    new_max * sizeof (*tsdp->tsd_array));
		if (newblock == NULL)
			return (-1);
		tsdp->tsd_array = newblock;
		/* NULL terminate list in case allocations fail below. */
		*(tsdp->tsd_array + tsdp->tsd_count) = NULL;
		tsdp->tsd_max = new_max;
	}
	info = uu_zalloc(sizeof (*info));
	if (info == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	info->mi_path = uu_strdup(fn);
	if (info->mi_path == NULL) {
		uu_free(info);
		errno = ENOMEM;
		return (-1);
	}
	info->mi_prop = pname;
	if (hash != NULL)
		(void) memcpy(info->mi_hash, hash, MHASH_SIZE);
	*(tsdp->tsd_array + tsdp->tsd_count) = info;
	tsdp->tsd_count++;

	/* NULL terminate the list. */
	*(tsdp->tsd_array + tsdp->tsd_count) = NULL;

	return (0);
}

/*
 * If necessary initialize the thread specific data key at tsd_key, and
 * allocate a mftsd_t structure to hold our thread specific data.  Upon
 * success, the address the thread specific data is returned.  On failure,
 * NULL is returned and errno is set.
 */
static mftsd_t *
get_thread_specific_data()
{
	mftsd_t *tsdp;

	if (pthread_key_create_once_np(&tsd_key, NULL) != 0)
		return (NULL);
	tsdp = (mftsd_t *)pthread_getspecific(tsd_key);
	if (tsdp == NULL) {
		/*
		 * First time for this thread.  We need to allocate memory
		 * for our thread specific data.
		 */
		tsdp = uu_zalloc(sizeof (*tsdp));
		if (tsdp == NULL) {
			errno = ENOMEM;
			return (NULL);
		}
		errno = pthread_setspecific(tsd_key, tsdp);
		if (errno != 0) {
			/*
			 * EINVAL means that our key is invalid, which
			 * would be a coding error.
			 */
			assert(errno != EINVAL);
			return (NULL);
		}
	}
	return (tsdp);
}

/*
 * This function is called by nftw(3C) every time that it finds an object
 * in a directory of interest.  If the object is a file, process() checks
 * to see if it is a service bundle file by insuring that it has a .xml
 * extension.
 *
 * If the file is a service bundle file, and the CHECKHASH flag is set process()
 * calls mhash_test_file() to see if it is a new bundle.  Bundle file data
 * for selected bundles is added to tsd_array in our thread specific data.
 *
 * Assume given file is a manifest unless BUNDLE_PROF flag is set to indicate
 * it's a profile. For profile bundles, call mhash_test_file() with the
 * appropriate argument.
 *
 * The CHECKEXT flag may be set if this was not a directory search request
 * but a single service bundle file check that was determined by the caller to
 * be found based not on the extension of the file.
 */
/*ARGSUSED*/
static int
process(const char *fn, const struct stat *sp, int ftw_type,
    struct FTW *ftws)
{
	int is_profile;
	char *suffix_match;
	uchar_t hash[MHASH_SIZE];
	char *pname;
	mftsd_t *tsdp;

	if (ftw_type != FTW_F)
		return (0);

	tsdp = get_thread_specific_data();
	if (tsdp == NULL)
		return (-1);

	/*
	 * Only check the extension on the file when
	 * requested.
	 */
	if (tsdp->tsd_flags & CHECKEXT) {
		suffix_match = strstr(fn, ".xml");
		if (suffix_match == NULL || strcmp(suffix_match, ".xml") != 0)
			return (0);
	}

	if (tsdp->tsd_flags & CHECKHASH) {
		is_profile = (tsdp->tsd_flags & BUNDLE_PROF) ? 1 : 0;
		if (mhash_test_file(tsdp->tsd_hndl, fn, is_profile, &pname,
		    hash) == MHASH_NEWFILE) {
			return (add_pointer(tsdp, fn, pname, hash));
		}
	} else {
		return (add_pointer(tsdp, fn, NULL, NULL));
	}

	return (0);
}

/*
 * This function returns a pointer to an array of manifest_info_t pointers.
 * There is one manifest_info_t pointer for each service bundle file in the
 * directory, dir, that satifies the selection criteria.  The array is
 * returned to arrayp.  The array will be terminated with a NULL pointer.
 * It is the responsibility of the caller to free the memory associated
 * with the array by calling free_manifest_array().
 *
 * flags :
 * 	0x1 - CHECKHASH - do the hash check and only return bundle
 * 	files that do not have a hash entry in the smf/manifest table
 * 	or the hash value has changed due to the bundle file having
 * 	been modified.  If not set then all service bundle files found
 * 	are returned, regardless of the hash status.
 *
 * 	0x2 - CHECKEXT - Check the extension of the file is .xml
 *
 * On success a count of the number of selected bundles is returned.
 * Note, however, that *arrayp will be set to NULL if the selection is
 * empty, and a count of 0 will be returned.  In the case of failure, -1
 * will be returned and errno will be set.
 *
 * This function takes a repository handle argument from the caller and saves
 * that handle in a thread specific data structure. The thread specific
 * repository handle is used in process() to communicate with the appropriate
 * repository. Thus callers should take care of thread safety with respect to
 * the repository handle. Currently, the two callers of find_manifests are both
 * single threaded, i.e. svccfg and mfstscan, so thread safety not an issue.
 */
int
find_manifests(scf_handle_t *hndl, const char *dir,
    manifest_info_t ***arrayp, int flags)
{
	mftsd_t *tsdp;
	int status = -1;
	int count;

	tsdp = get_thread_specific_data();
	if (tsdp == NULL)
		return (-1);

	tsdp->tsd_flags = flags;

	if (tsdp->tsd_flags & CHECKHASH) {
		tsdp->tsd_hndl = hndl;
	}

	if (nftw(dir, process, MAX_DEPTH, FTW_MOUNT) == 0) {
		status = 0;
	}

	if (status == 0) {
		*arrayp = tsdp->tsd_array;
		count = tsdp->tsd_count;
	} else {
		*arrayp = NULL;
		free_manifest_array(tsdp->tsd_array);
		count = -1;
	}

	/* Reset thread specific data. */
	(void) memset(tsdp, 0, sizeof (*tsdp));

	return (count);
}

/*
 * Free the memory associated with the array of manifest_info structures.
 */
void
free_manifest_array(manifest_info_t **array)
{
	manifest_info_t **entry;
	manifest_info_t *info;

	if (array == NULL)
		return;

	for (entry = array; *entry != NULL; entry++) {
		info = *entry;
		uu_free((void *) info->mi_path);
		uu_free((void *) info->mi_prop);
		uu_free(info);
	}

	/*
	 * Array is allocated with realloc(3C), so it must be freed with
	 * free(3c) rather than uu_free().
	 */
	free(array);
}
