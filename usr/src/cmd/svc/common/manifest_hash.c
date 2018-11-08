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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */


#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <libscf.h>
#include <libuutil.h>
#include <limits.h>
#include <md5.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <manifest_hash.h>

/*
 * Translate a file name to property name.  Return an allocated string or NULL
 * if realpath() fails. If deathrow is true, realpath() is skipped. This
 * allows to return the property name even if the file doesn't exist.
 */
char *
mhash_filename_to_propname(const char *in, boolean_t deathrow)
{
	char *out, *cp, *base;
	size_t len, piece_len;
	size_t base_sz = 0;

	out = uu_zalloc(PATH_MAX + 1);
	if (deathrow) {
		/* used only for service deathrow handling */
		if (strlcpy(out, in, PATH_MAX + 1) >= (PATH_MAX + 1)) {
			uu_free(out);
			return (NULL);
		}
	} else {
		if (realpath(in, out) == NULL) {
			uu_free(out);
			return (NULL);
		}
	}

	base = getenv("PKG_INSTALL_ROOT");

	/*
	 * We copy-shift over the basedir and the leading slash, since it's
	 * not relevant to when we boot with this repository.
	 */

	if (base != NULL && strncmp(out, base, strlen(base)) == 0)
		base_sz = strlen(base);

	cp = out + base_sz;
	if (*cp == '/')
		cp++;
	(void) memmove(out, cp, strlen(cp) + 1);

	len = strlen(out);
	if (len > scf_limit(SCF_LIMIT_MAX_NAME_LENGTH)) {
		/* Use the first half and the second half. */
		piece_len = (scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) - 3) / 2;

		(void) strncpy(out + piece_len, "__", 2);

		(void) memmove(out + piece_len + 2, out + (len - piece_len),
		    piece_len + 1);
	}

	/*
	 * Translate non-property characters to '_', first making sure that
	 * we don't begin with '_'.
	 */

	if (!isalpha(*out))
		*out = 'A';

	for (cp = out + 1; *cp != '\0'; ++cp) {
		if (!(isalnum(*cp) || *cp == '_' || *cp == '-'))
			*cp = '_';
	}

	return (out);
}

int
mhash_retrieve_entry(scf_handle_t *hndl, const char *name, uchar_t *hash,
    apply_action_t *action)
{
	scf_scope_t *scope;
	scf_service_t *svc;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *val;
	scf_error_t err;
	ssize_t szret;
	int result = 0;

	if (action)
		*action = APPLY_NONE;

	/*
	 * In this implementation the hash for name is the opaque value of
	 * svc:/MHASH_SVC/:properties/name/MHASH_PROP
	 */

	if ((scope = scf_scope_create(hndl)) == NULL ||
	    (svc = scf_service_create(hndl)) == NULL ||
	    (pg = scf_pg_create(hndl)) == NULL ||
	    (prop = scf_property_create(hndl)) == NULL ||
	    (val = scf_value_create(hndl)) == NULL) {
		result = -1;
		goto out;
	}

	if (scf_handle_get_local_scope(hndl, scope) < 0) {
		result = -1;
		goto out;
	}

	if (scf_scope_get_service(scope, MHASH_SVC, svc) < 0) {
		result = -1;
		goto out;
	}

	if (scf_service_get_pg(svc, name, pg) != SCF_SUCCESS) {
		result = -1;
		goto out;
	}

	if (scf_pg_get_property(pg, MHASH_PROP, prop) != SCF_SUCCESS) {
		result = -1;
		goto out;
	}

	if (scf_property_get_value(prop, val) != SCF_SUCCESS) {
		result = -1;
		goto out;
	}

	szret = scf_value_get_opaque(val, hash, MHASH_SIZE);
	if (szret < 0) {
		result = -1;
		goto out;
	}

	/*
	 * Make sure that the old hash is returned with
	 * remainder of the bytes zeroed.
	 */
	if (szret == MHASH_SIZE_OLD) {
		(void) memset(hash + MHASH_SIZE_OLD, 0,
		    MHASH_SIZE - MHASH_SIZE_OLD);
	} else if (szret != MHASH_SIZE) {
		scf_value_destroy(val);
		result = -1;
		goto out;
	}

	/*
	 * If caller has requested the apply_last property, read the
	 * property if it exists.
	 */
	if (action != NULL) {
		uint8_t apply_value;

		if (scf_pg_get_property(pg, MHASH_APPLY_PROP, prop) !=
		    SCF_SUCCESS) {
			err = scf_error();
			if ((err != SCF_ERROR_DELETED) &&
			    (err != SCF_ERROR_NOT_FOUND)) {
				result = -1;
			}
			goto out;
		}
		if (scf_property_get_value(prop, val) != SCF_SUCCESS) {
			err = scf_error();
			if ((err != SCF_ERROR_DELETED) &&
			    (err != SCF_ERROR_NOT_FOUND)) {
				result = -1;
			}
			goto out;
		}
		if (scf_value_get_boolean(val, &apply_value) != SCF_SUCCESS) {
			result = -1;
			goto out;
		}
		if (apply_value)
			*action = APPLY_LATE;
	}

out:
	(void) scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_service_destroy(svc);
	scf_scope_destroy(scope);

	return (result);
}

int
mhash_store_entry(scf_handle_t *hndl, const char *name, const char *fname,
    uchar_t *hash, apply_action_t apply_late, char **errstr)
{
	scf_scope_t *scope = NULL;
	scf_service_t *svc = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *aval = NULL;
	scf_value_t *val = NULL;
	scf_value_t *fval = NULL;
	scf_transaction_t *tx = NULL;
	scf_transaction_entry_t *ae = NULL;
	scf_transaction_entry_t *e = NULL;
	scf_transaction_entry_t *fe = NULL;
	scf_error_t err;
	int ret, result = 0;
	char *base;
	size_t base_sz = 0;

	int i;

	if ((scope = scf_scope_create(hndl)) == NULL ||
	    (svc = scf_service_create(hndl)) == NULL ||
	    (pg = scf_pg_create(hndl)) == NULL ||
	    (prop = scf_property_create(hndl)) == NULL) {
		if (errstr != NULL)
			*errstr = gettext("Could not create scf objects");
		result = -1;
		goto out;
	}

	if (scf_handle_get_local_scope(hndl, scope) != SCF_SUCCESS) {
		if (errstr != NULL)
			*errstr = gettext("Could not get local scope");
		result = -1;
		goto out;
	}

	for (i = 0; i < 5; ++i) {

		if (scf_scope_get_service(scope, MHASH_SVC, svc) ==
		    SCF_SUCCESS)
			break;

		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			if (errstr != NULL)
				*errstr = gettext("Could not get manifest hash "
				    "service");
			result = -1;
			goto out;
		}

		if (scf_scope_add_service(scope, MHASH_SVC, svc) ==
		    SCF_SUCCESS)
			break;

		err = scf_error();

		if (err == SCF_ERROR_EXISTS)
			/* Try again. */
			continue;
		else if (err == SCF_ERROR_PERMISSION_DENIED) {
			if (errstr != NULL)
				*errstr = gettext("Could not store file hash: "
				    "permission denied.\n");
			result = -1;
			goto out;
		}

		if (errstr != NULL)
			*errstr = gettext("Could not add manifest hash "
			    "service");
		result = -1;
		goto out;
	}

	if (i == 5) {
		if (errstr != NULL)
			*errstr = gettext("Could not store file hash: "
			    "service addition contention.\n");
		result = -1;
		goto out;
	}

	for (i = 0; i < 5; ++i) {
		if (scf_service_get_pg(svc, name, pg) == SCF_SUCCESS)
			break;

		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			if (errstr != NULL)
				*errstr = gettext("Could not get service's "
				    "hash record)");
			result = -1;
			goto out;
		}

		if (scf_service_add_pg(svc, name, MHASH_PG_TYPE,
		    MHASH_PG_FLAGS, pg) == SCF_SUCCESS)
			break;

		err = scf_error();

		if (err == SCF_ERROR_EXISTS)
			/* Try again. */
			continue;
		else if (err == SCF_ERROR_PERMISSION_DENIED) {
			if (errstr != NULL)
				*errstr = gettext("Could not store file hash: "
				    "permission denied.\n");
			result = -1;
			goto out;
		}

		if (errstr != NULL)
			*errstr = gettext("Could not store file hash");
		result = -1;
		goto out;
	}
	if (i == 5) {
		if (errstr != NULL)
			*errstr = gettext("Could not store file hash: "
			    "property group addition contention.\n");
		result = -1;
		goto out;
	}

	if ((e = scf_entry_create(hndl)) == NULL ||
	    (val = scf_value_create(hndl)) == NULL ||
	    (fe = scf_entry_create(hndl)) == NULL ||
	    (fval = scf_value_create(hndl)) == NULL ||
	    (ae = scf_entry_create(hndl)) == NULL ||
	    (aval = scf_value_create(hndl)) == NULL) {
		if (errstr != NULL)
			*errstr = gettext("Could not store file hash: "
			    "permission denied.\n");
		result = -1;
		goto out;
	}

	/*
	 * Remove any PKG_INSTALL_ROOT from the manifest filename so that it
	 * points to the correct location following installation.
	 */
	base = getenv("PKG_INSTALL_ROOT");
	if (base != NULL && strncmp(fname, base, strlen(base)) == 0)
		base_sz = strlen(base);

	ret = scf_value_set_opaque(val, hash, MHASH_SIZE);
	assert(ret == SCF_SUCCESS);
	ret = scf_value_set_astring(fval, fname + base_sz);
	assert(ret == SCF_SUCCESS);
	if (apply_late == APPLY_LATE) {
		scf_value_set_boolean(aval, 1);
	}

	tx = scf_transaction_create(hndl);
	if (tx == NULL) {
		if (errstr != NULL)
			*errstr = gettext("Could not create transaction");
		result = -1;
		goto out;
	}

	do {
		if (scf_pg_update(pg) == -1) {
			if (errstr != NULL)
				*errstr = gettext("Could not update hash "
				    "entry");
			result = -1;
			goto out;
		}
		if (scf_transaction_start(tx, pg) != SCF_SUCCESS) {
			if (scf_error() != SCF_ERROR_PERMISSION_DENIED) {
				if (errstr != NULL)
					*errstr = gettext("Could not start "
					    "hash transaction.\n");
				result = -1;
				goto out;
			}

			if (errstr != NULL)
				*errstr = gettext("Could not store file hash: "
				    "permission denied.\n");
			result = -1;

			scf_transaction_destroy(tx);
			(void) scf_entry_destroy(e);
			goto out;
		}

		if (scf_transaction_property_new(tx, e, MHASH_PROP,
		    SCF_TYPE_OPAQUE) != SCF_SUCCESS &&
		    scf_transaction_property_change_type(tx, e, MHASH_PROP,
		    SCF_TYPE_OPAQUE) != SCF_SUCCESS) {
			if (errstr != NULL)
				*errstr = gettext("Could not modify hash "
				    "entry");
			result = -1;
			goto out;
		}

		ret = scf_entry_add_value(e, val);
		assert(ret == SCF_SUCCESS);

		if (scf_transaction_property_new(tx, fe, MHASH_FILE_PROP,
		    SCF_TYPE_ASTRING) != SCF_SUCCESS &&
		    scf_transaction_property_change_type(tx, fe,
		    MHASH_FILE_PROP, SCF_TYPE_ASTRING) != SCF_SUCCESS) {
			if (errstr != NULL)
				*errstr = gettext("Could not modify file "
				    "entry");
			result = -1;
			goto out;
		}

		ret = scf_entry_add_value(fe, fval);
		assert(ret == SCF_SUCCESS);

		switch (apply_late) {
		case APPLY_NONE:
			if (scf_transaction_property_delete(tx, ae,
			    MHASH_APPLY_PROP) != 0) {
				err = scf_error();
				if ((err != SCF_ERROR_DELETED) &&
				    (err != SCF_ERROR_NOT_FOUND)) {
					if (errstr != NULL) {
						*errstr = gettext("Could not "
						    "delete apply_late "
						    "property");
					}
					result = -1;
					goto out;
				}
			}
			break;
		case APPLY_LATE:
			if ((scf_transaction_property_new(tx, ae,
			    MHASH_APPLY_PROP,
			    SCF_TYPE_BOOLEAN) != SCF_SUCCESS) &&
			    (scf_transaction_property_change_type(tx, ae,
			    MHASH_APPLY_PROP, SCF_TYPE_BOOLEAN) !=
			    SCF_SUCCESS)) {
				if (errstr != NULL) {
					*errstr = gettext("Could not modify "
					    "apply_late property");
				}
				result = -1;
				goto out;
			}

			ret = scf_entry_add_value(ae, aval);
			assert(ret == SCF_SUCCESS);
			break;
		default:
			abort();
		};

		ret = scf_transaction_commit(tx);

		if (ret == 0)
			scf_transaction_reset(tx);
	} while (ret == 0);

	if (ret < 0) {
		if (scf_error() != SCF_ERROR_PERMISSION_DENIED) {
			if (errstr != NULL)
				*errstr = gettext("Could not store file hash: "
				    "permission denied.\n");
			result = -1;
			goto out;
		}

		if (errstr != NULL)
			*errstr = gettext("Could not commit transaction");
		result = -1;
	}

	scf_transaction_destroy(tx);
	(void) scf_entry_destroy(e);
	(void) scf_entry_destroy(fe);
	(void) scf_entry_destroy(ae);

out:
	(void) scf_value_destroy(val);
	(void) scf_value_destroy(fval);
	(void) scf_value_destroy(aval);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_service_destroy(svc);
	scf_scope_destroy(scope);

	return (result);
}

/*
 * Generate the md5 hash of a file; manifest files are smallish
 * so we can read them in one gulp.
 */
static int
md5_hash_file(const char *file, off64_t sz, uchar_t *hash)
{
	char *buf;
	int fd;
	ssize_t res;
	int ret;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return (-1);

	buf = malloc(sz);
	if (buf == NULL) {
		(void) close(fd);
		return (-1);
	}

	res = read(fd, buf, (size_t)sz);

	(void) close(fd);

	if (res == sz) {
		ret = 0;
		md5_calc(hash, (uchar_t *)buf, (unsigned int) sz);
	} else {
		ret = -1;
	}

	free(buf);
	return (ret);
}

/*
 * int mhash_test_file(scf_handle_t *, const char *, uint_t, char **, uchar_t *)
 *   Test the given filename against the hashed metadata in the repository.
 *   The behaviours for import and apply are slightly different.  For imports,
 *   if the hash value is absent or different, then the import operation
 *   continues.  For profile application, the operation continues only if the
 *   hash value for the file is absent.
 *
 *   We keep two hashes: one which can be quickly test: the metadata hash,
 *   and one which is more expensive to test: the file contents hash.
 *
 *   If either hash matches, the file does not need to be re-read.
 *   If only one of the hashes matches, a side effect of this function
 *   is to store the newly computed hash.
 *   If neither hash matches, the hash computed for the new file is returned
 *   and not stored.
 *
 *   Return values:
 *	MHASH_NEWFILE	- the file no longer matches the hash or no hash existed
 *			  ONLY in this case we return the new file's hash.
 *	MHASH_FAILURE	- an internal error occurred, or the file was not found.
 *	MHASH_RECONCILED- based on the metadata/file hash, the file does
 *			  not need to be re-read; if necessary,
 *			  the hash was upgraded or reconciled.
 *
 * NOTE: no hash is returned UNLESS MHASH_NEWFILE is returned.
 */
int
mhash_test_file(scf_handle_t *hndl, const char *file, uint_t is_profile,
    char **pnamep, uchar_t *hashbuf)
{
	apply_action_t action;
	boolean_t do_hash;
	struct stat64 st;
	char *cp;
	char *data;
	uchar_t stored_hash[MHASH_SIZE];
	uchar_t hash[MHASH_SIZE];
	char *pname;
	int ret;
	int hashash;
	int metahashok = 0;

	if (pnamep)
		*pnamep = NULL;

	/*
	 * In the case where we are doing automated imports, we reduce the UID,
	 * the GID, the size, and the mtime into a string (to eliminate
	 * endianness) which we then make opaque as a single MD5 digest.
	 *
	 * The previous hash was composed of the inode number, the UID, the file
	 * size, and the mtime.  This formulation was found to be insufficiently
	 * portable for use in highly replicated deployments.  The current
	 * algorithm will allow matches of this "v1" hash, but always returns
	 * the effective "v2" hash, such that updates result in the more
	 * portable hash being used.
	 *
	 * An unwanted side effect of a hash based solely on the file
	 * meta data is the fact that we pay no attention to the contents
	 * which may remain the same despite meta data changes.  This happens
	 * with (live) upgrades.  We extend the V2 hash with an additional
	 * digest of the file contents and the code retrieving the hash
	 * from the repository zero fills the remainder so we can detect
	 * it is missing.
	 *
	 * If the the V2 digest matches, we check for the presence of
	 * the contents digest and compute and store it if missing.
	 *
	 * If the V2 digest doesn't match but we also have a non-zero
	 * file hash, we match the file content digest.  If it matches,
	 * we compute and store the new complete hash so that later
	 * checks will find the meta data digest correct.
	 *
	 * If the above matches fail and the V1 hash doesn't match either,
	 * we consider the test to have failed, implying that some aspect
	 * of the manifest has changed.
	 */

	cp = getenv("SVCCFG_CHECKHASH");
	do_hash = (cp != NULL && *cp != '\0');
	if (!do_hash) {
		return (MHASH_NEWFILE);
	}

	pname = mhash_filename_to_propname(file, B_FALSE);
	if (pname == NULL)
		return (MHASH_FAILURE);

	hashash = mhash_retrieve_entry(hndl, pname, stored_hash, &action) == 0;
	if (is_profile == 0) {
		/* Actions other than APPLY_NONE are restricted to profiles. */
		assert(action == APPLY_NONE);
	}

	/*
	 * As a general rule, we do not reread a profile.  The exception to
	 * this rule is when we are running as part of the manifest import
	 * service and the apply_late property is set to true.
	 */
	if (hashash && is_profile) {
		cp = getenv("SMF_FMRI");
		if ((cp == NULL) ||
		    (strcmp(cp, SCF_INSTANCE_MI) != 0) ||
		    (action != APPLY_LATE)) {
			uu_free(pname);
			return (MHASH_RECONCILED);
		}
	}

	/*
	 * No hash and not interested in one, then don't bother computing it.
	 * We also skip returning the property name in that case.
	 */
	if (!hashash && hashbuf == NULL) {
		uu_free(pname);
		return (MHASH_NEWFILE);
	}

	do {
		ret = stat64(file, &st);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		uu_free(pname);
		return (MHASH_FAILURE);
	}

	data = uu_msprintf(MHASH_FORMAT_V2, st.st_uid, st.st_gid,
	    st.st_size, st.st_mtime);
	if (data == NULL) {
		uu_free(pname);
		return (MHASH_FAILURE);
	}

	(void) memset(hash, 0, MHASH_SIZE);
	md5_calc(hash, (uchar_t *)data, strlen(data));

	uu_free(data);

	/*
	 * Verify the meta data hash.
	 */
	if (hashash && memcmp(hash, stored_hash, MD5_DIGEST_LENGTH) == 0) {
		int i;

		metahashok = 1;
		/*
		 * The metadata hash matches; now we see if there was a
		 * content hash; if not, we will continue on and compute and
		 * store the updated hash.
		 * If there was no content hash, mhash_retrieve_entry()
		 * will have zero filled it.
		 */
		for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
			if (stored_hash[MD5_DIGEST_LENGTH+i] != 0) {
				if (action == APPLY_LATE) {
					if (pnamep != NULL)
						*pnamep = pname;
					ret = MHASH_NEWFILE;
				} else {
					uu_free(pname);
					ret = MHASH_RECONCILED;
				}
				return (ret);
			}
		}
	}

	/*
	 * Compute the file hash as we can no longer avoid having to know it.
	 * Note: from this point on "hash" contains the full, current, hash.
	 */
	if (md5_hash_file(file, st.st_size, &hash[MHASH_SIZE_OLD]) != 0) {
		uu_free(pname);
		return (MHASH_FAILURE);
	}
	if (hashash) {
		uchar_t hash_v1[MHASH_SIZE_OLD];

		if (metahashok ||
		    memcmp(&hash[MHASH_SIZE_OLD], &stored_hash[MHASH_SIZE_OLD],
		    MD5_DIGEST_LENGTH) == 0) {

			/*
			 * Reconcile entry: we get here when either the
			 * meta data hash matches or the content hash matches;
			 * we then update the database with the complete
			 * new hash so we can be a bit quicker next time.
			 */
			(void) mhash_store_entry(hndl, pname, file, hash,
			    APPLY_NONE, NULL);
			if (action == APPLY_LATE) {
				if (pnamep != NULL)
					*pnamep = pname;
				ret = MHASH_NEWFILE;
			} else {
				uu_free(pname);
				ret = MHASH_RECONCILED;
			}
			return (ret);
		}

		/*
		 * No match on V2 hash or file content; compare V1 hash.
		 */
		data = uu_msprintf(MHASH_FORMAT_V1, st.st_ino, st.st_uid,
		    st.st_size, st.st_mtime);
		if (data == NULL) {
			uu_free(pname);
			return (MHASH_FAILURE);
		}

		md5_calc(hash_v1, (uchar_t *)data, strlen(data));

		uu_free(data);

		if (memcmp(hash_v1, stored_hash, MD5_DIGEST_LENGTH) == 0) {
			/*
			 * Update the new entry so we don't have to go through
			 * all this trouble next time.
			 */
			(void) mhash_store_entry(hndl, pname, file, hash,
			    APPLY_NONE, NULL);
			uu_free(pname);
			return (MHASH_RECONCILED);
		}
	}

	if (pnamep != NULL)
		*pnamep = pname;
	else
		uu_free(pname);

	if (hashbuf != NULL)
		(void) memcpy(hashbuf, hash, MHASH_SIZE);

	return (MHASH_NEWFILE);
}
