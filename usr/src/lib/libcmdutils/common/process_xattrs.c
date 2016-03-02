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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include "libcmdutils.h"


/*
 * Gets file descriptors of attribute directories for source and target
 * attribute files
 */
int
get_attrdirs(int indfd, int outdfd, char *attrfile, int *sfd, int *tfd)
{
	int	pwdfd;
	int	fd1;
	int	fd2;

	pwdfd = open(".", O_RDONLY);
	if ((pwdfd != -1) && (fchdir(indfd) == 0)) {
		if ((fd1 = attropen(attrfile, ".", O_RDONLY)) == -1) {
			(void) fchdir(pwdfd);
			(void) close(pwdfd);
			return (1);
		}
		*sfd = fd1;
	} else {
		(void) fchdir(pwdfd);
		(void) close(pwdfd);
		return (1);
	}
	if (fchdir(outdfd) == 0) {
		if ((fd2 = attropen(attrfile, ".", O_RDONLY)) == -1) {
			(void) fchdir(pwdfd);
			(void) close(pwdfd);
			return (1);
		}
		*tfd = fd2;
	} else {
		(void) fchdir(pwdfd);
		(void) close(pwdfd);
		return (1);
	}
	(void) fchdir(pwdfd);
	return (0);
}

/*
 * mv_xattrs - Copies the content of the extended attribute files. Then
 * 	moves the extended system attributes from the input attribute files
 *      to the target attribute files. Moves the extended system attributes
 *	from source to the target file. This function returns 0 on success
 *	and nonzero on error.
 */
int
mv_xattrs(char *cmd, char *infile, char *outfile, int sattr, int silent)
{
	int srcfd = -1;
	int indfd = -1;
	int outdfd = -1;
	int tmpfd = -1;
	int sattrfd = -1;
	int tattrfd = -1;
	int asfd = -1;
	int atfd = -1;
	DIR *dirp = NULL;
	struct dirent *dp = NULL;
	char *etext = NULL;
	struct stat st1;
	struct stat st2;
	nvlist_t *response = NULL;
	nvlist_t *res = NULL;

	if ((srcfd = open(infile, O_RDONLY)) == -1) {
		etext = dgettext(TEXT_DOMAIN, "cannot open source");
		goto error;
	}
	if (sattr)
		response = sysattr_list(cmd, srcfd, infile);

	if ((indfd = openat(srcfd, ".", O_RDONLY|O_XATTR)) == -1) {
		etext = dgettext(TEXT_DOMAIN, "cannot openat source");
		goto error;
	}
	if ((outdfd = attropen(outfile, ".", O_RDONLY)) == -1) {
		etext = dgettext(TEXT_DOMAIN, "cannot attropen target");
		goto error;
	}
	if ((tmpfd = dup(indfd)) == -1) {
		etext = dgettext(TEXT_DOMAIN, "cannot dup descriptor");
		goto error;

	}
	if ((dirp = fdopendir(tmpfd)) == NULL) {
		etext = dgettext(TEXT_DOMAIN, "cannot access source");
		goto error;
	}
	while ((dp = readdir(dirp)) != NULL) {
		if ((dp->d_name[0] == '.' && dp->d_name[1] == '\0') ||
		    (dp->d_name[0] == '.' && dp->d_name[1] == '.' &&
		    dp->d_name[2] == '\0') ||
		    (sysattr_type(dp->d_name) == _RO_SATTR) ||
		    (sysattr_type(dp->d_name) == _RW_SATTR))
			continue;

		if ((sattrfd = openat(indfd, dp->d_name,
		    O_RDONLY)) == -1) {
			etext = dgettext(TEXT_DOMAIN,
			    "cannot open src attribute file");
			goto error;
		}
		if (fstat(sattrfd, &st1) < 0) {
			etext = dgettext(TEXT_DOMAIN,
			    "could not stat attribute file");
			goto error;
		}
		if ((tattrfd = openat(outdfd, dp->d_name,
		    O_RDWR|O_CREAT|O_TRUNC, st1.st_mode)) == -1) {
			etext = dgettext(TEXT_DOMAIN,
			    "cannot open target attribute file");
			goto error;
		}
		if (fstat(tattrfd, &st2) < 0) {
			etext = dgettext(TEXT_DOMAIN,
			    "could not stat attribute file");
			goto error;
		}
		if (writefile(sattrfd, tattrfd, infile, outfile, dp->d_name,
		    dp->d_name, &st1, &st2) != 0) {
			etext = dgettext(TEXT_DOMAIN,
			    "failed to copy extended attribute "
			    "from source to target");
			goto error;
		}

		errno = 0;
		if (sattr) {
			/*
			 * Gets non default extended system attributes from
			 * source to copy to target.
			 */
			if (dp->d_name != NULL)
				res = sysattr_list(cmd, sattrfd, dp->d_name);

			if (res != NULL &&
			    get_attrdirs(indfd, outdfd, dp->d_name, &asfd,
			    &atfd) != 0) {
				etext = dgettext(TEXT_DOMAIN,
				    "Failed to open attribute files");
				goto error;
			}
			/*
			 * Copy extended system attribute from source
			 * attribute file to target attribute file
			 */
			if (res != NULL &&
			    (renameat(asfd, VIEW_READWRITE, atfd,
			    VIEW_READWRITE) != 0)) {
				if (errno == EPERM)
					etext = dgettext(TEXT_DOMAIN,
					    "Permission denied -"
					    "failed to move system attribute");
				else
					etext = dgettext(TEXT_DOMAIN,
					    "failed to move extended "
					    "system attribute");
				goto error;
			}
		}
		if (sattrfd != -1)
			(void) close(sattrfd);
		if (tattrfd != -1)
			(void) close(tattrfd);
		if (asfd != -1)
			(void) close(asfd);
		if (atfd != -1)
			(void) close(atfd);
		if (res != NULL) {
			nvlist_free(res);
			res = NULL;
		}
	}
	errno = 0;
	/* Copy extended system attribute from source to target */

	if (response != NULL) {
		if (renameat(indfd, VIEW_READWRITE, outdfd,
		    VIEW_READWRITE) == 0)
			goto done;

		if (errno == EPERM)
			etext = dgettext(TEXT_DOMAIN, "Permission denied");
		else
			etext = dgettext(TEXT_DOMAIN,
			    "failed to move system attribute");
	}
error:
	nvlist_free(res);
	if (silent == 0 && etext != NULL) {
		if (!sattr)
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "%s: %s: cannot move extended attributes, "),
			    cmd, infile);
		else
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "%s: %s: cannot move extended system "
			    "attributes, "), cmd, infile);
		perror(etext);
	}
done:
	if (dirp)
		(void) closedir(dirp);
	if (sattrfd != -1)
		(void) close(sattrfd);
	if (tattrfd != -1)
		(void) close(tattrfd);
	if (asfd != -1)
		(void) close(asfd);
	if (atfd != -1)
		(void) close(atfd);
	if (indfd != -1)
		(void) close(indfd);
	if (outdfd != -1)
		(void) close(outdfd);
	nvlist_free(response);
	if (etext != NULL)
		return (1);
	else
		return (0);
}

/*
 * The function returns non default extended system attribute list
 * associated with 'fname' and returns NULL when an error has occured
 * or when only extended system attributes other than archive,
 * av_modified or crtime are set.
 *
 * The function returns system attribute list for the following cases:
 *
 *	- any extended system attribute other than the default attributes
 *	  ('archive', 'av_modified' and 'crtime') is set
 *	- nvlist has NULL name string
 *	- nvpair has data type of 'nvlist'
 *	- default data type.
 */

nvlist_t *
sysattr_list(char *cmd, int fd, char *fname)
{
	boolean_t	value;
	data_type_t	type;
	nvlist_t	*response;
	nvpair_t	*pair;
	f_attr_t	fattr;
	char		*name;

	if (fgetattr(fd, XATTR_VIEW_READWRITE, &response) != 0) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "%s: %s: fgetattr failed\n"),
		    cmd, fname);
		return (NULL);
	}
	pair = NULL;
	while ((pair = nvlist_next_nvpair(response, pair)) != NULL) {

		name = nvpair_name(pair);

		if (name != NULL)
			fattr = name_to_attr(name);
		else
			return (response);

		type = nvpair_type(pair);
		switch (type) {
			case DATA_TYPE_BOOLEAN_VALUE:
				if (nvpair_value_boolean_value(pair,
				    &value) != 0) {
					(void) fprintf(stderr,
					    dgettext(TEXT_DOMAIN, "%s "
					    "nvpair_value_boolean_value "
					    "failed\n"), cmd);
					continue;
				}
				if (value && fattr != F_ARCHIVE &&
				    fattr != F_AV_MODIFIED)
					return (response);
				break;
			case DATA_TYPE_UINT64_ARRAY:
				if (fattr != F_CRTIME)
					return (response);
				break;
			case DATA_TYPE_NVLIST:
			default:
				return (response);
		}
	}
	nvlist_free(response);
	return (NULL);
}
