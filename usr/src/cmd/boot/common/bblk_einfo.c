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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "bblk_einfo.h"
#include "boot_utils.h"

bblk_hash_t	bblk_no_hash = {BBLK_NO_HASH, 0, "(no hash)", NULL};
bblk_hash_t	bblk_md5_hash = {BBLK_HASH_MD5, 0x10, "MD5", md5_calc};

bblk_hash_t	*bblk_hash_list[BBLK_HASH_TOT] = {
	&bblk_no_hash,
	&bblk_md5_hash
};

/*
 * einfo_compare_dotted_version()
 * Compares two strings with an arbitrary long number of dot-separated numbers.
 * Returns:	0  - if the version numbers are equal
 *		1  - if str1 version number is more recent than str2
 *		2  - if str2 version number is more recent than str1
 *		-1 - if an error occurred
 *
 * Comparison is done field by field, by retrieving an unsigned integer value,
 * (missing fields are assumed as 0, but explict zeroes take precedence) so:
 *   4.1.2.11 > 4.1.2.2 > 4.1.2.0 > 4.1.2
 *
 * where ">" means "more recent than".
 */
static int
einfo_compare_dotted_version(const char *str1, const char *str2)
{
	int		retval = 0;
	char		*verstr1, *verstr2, *freeptr1, *freeptr2;
	char		*parsep1, *parsep2;
	unsigned int	val_str1, val_str2;

	freeptr1 = verstr1 = strdup(str1);
	freeptr2 = verstr2 = strdup(str2);
	if (verstr1 == NULL || verstr2 == NULL) {
		retval = -1;
		goto out;
	}

	while (verstr1 != NULL && verstr2 != NULL) {
		parsep1 = strsep(&verstr1, ".");
		parsep2 = strsep(&verstr2, ".");

		val_str1 = atoi(parsep1);
		val_str2 = atoi(parsep2);

		if (val_str1 > val_str2) {
			retval = 1;
			goto out;
		}

		if (val_str2 > val_str1) {
			retval = 2;
			goto out;
		}
	}

	/* Common portion of the version string is equal. */
	if (verstr1 == NULL && verstr2 != NULL)
		retval = 2;
	if (verstr2 == NULL && verstr1 != NULL)
		retval = 1;

out:
	free(freeptr1);
	free(freeptr2);
	return (retval);
}

/*
 * einfo_compare_timestamps()
 * Currently, timestamp is in %Y%m%dT%H%M%SZ format in UTC, which means that
 * we can simply do a lexicographic comparison to know which one is the most
 * recent.
 *
 * Returns:   0  - if timestamps coincide
 *            1  - if the timestamp in str1 is more recent
 *            2  - if the timestamp in str2 is more recent
 */
static int
einfo_compare_timestamps(const char *str1, const char *str2)
{
	int	retval;

	retval = strcmp(str1, str2);
	if (retval > 0)
		retval = 1;
	if (retval < 0)
		retval = 2;

	return (retval);
}

/*
 * einfo_compare_version()
 * Given two extended versions, compare the two and returns which one is more
 * "recent". Comparison is based on dotted version number fields and a
 * timestamp.
 *
 * Returns:    -1   - on error
 *              0   - if the two versions coincide
 *              1   - if the version in str1 is more recent
 *              2   - if the version in str2 is more recent
 */
static int
einfo_compare_version(const char *str1, const char *str2)
{
	int	retval = 0;
	char	*verstr1, *verstr2, *freeptr1, *freeptr2;
	char	*parsep1, *parsep2;

	freeptr1 = verstr1 = strdup(str1);
	freeptr2 = verstr2 = strdup(str2);
	if (verstr1 == NULL || verstr2 == NULL) {
		retval = -1;
		goto out;
	}

	parsep1 = verstr1;
	parsep2 = verstr2;

	while (parsep1 != NULL && parsep2 != NULL) {
		parsep1 = strsep(&verstr1, ",:-");
		parsep2 = strsep(&verstr2, ",:-");

		/* verstr1 or verstr2 will be NULL before parsep1 or parsep2. */
		if (verstr1 == NULL || verstr2 == NULL) {
			retval = einfo_compare_timestamps(parsep1, parsep2);
			goto out;
		}

		retval = einfo_compare_dotted_version(parsep1, parsep2);
		if (retval == 0)
			continue;
		else
			goto out;
	}
out:
	free(freeptr1);
	free(freeptr2);
	return (retval);
}

/*
 * print_einfo()
 *
 * Print the extended information contained into the pointed structure.
 * 'bufsize' specifies the real size of the structure, since str_off and
 * hash_off need to point somewhere past the header.
 */
void
print_einfo(uint8_t flags, bblk_einfo_t *einfo, unsigned long bufsize)
{
	int		i = 0;
	char		*version;
	boolean_t	has_hash = B_FALSE;
	unsigned char	*hash = NULL;

	if (einfo->str_off + einfo->str_size > bufsize) {
		(void) fprintf(stdout, gettext("String offset %d is beyond the "
		    "buffer size\n"), einfo->str_off);
		return;
	}

	version = (char *)einfo + einfo->str_off;
	if (einfo->hash_type != BBLK_NO_HASH &&
	    einfo->hash_type < BBLK_HASH_TOT) {
		if (einfo->hash_off + einfo->hash_size > bufsize) {
			(void) fprintf(stdout, gettext("Warning: hashing "
			    "present but hash offset %d is beyond the buffer "
			    "size\n"), einfo->hash_off);
			has_hash = B_FALSE;
		} else {
			hash = (unsigned char *)einfo + einfo->hash_off;
			has_hash = B_TRUE;
		}
	}

	if (flags & EINFO_PRINT_HEADER) {
		(void) fprintf(stdout, "Boot Block Extended Info Header:\n");
		(void) fprintf(stdout, "\tmagic: ");
		for (i = 0; i < EINFO_MAGIC_SIZE; i++)
			(void) fprintf(stdout, "%c", einfo->magic[i]);
		(void) fprintf(stdout, "\n");
		(void) fprintf(stdout, "\tversion: %d\n", einfo->version);
		(void) fprintf(stdout, "\tflags: %x\n", einfo->flags);
		(void) fprintf(stdout, "\textended version string offset: %d\n",
		    einfo->str_off);
		(void) fprintf(stdout, "\textended version string size: %d\n",
		    einfo->str_size);
		(void) fprintf(stdout, "\thashing type: %d (%s)\n",
		    einfo->hash_type, has_hash ?
		    bblk_hash_list[einfo->hash_type]->name : "nil");
		(void) fprintf(stdout, "\thash offset: %d\n", einfo->hash_off);
		(void) fprintf(stdout, "\thash size: %d\n", einfo->hash_size);
	}

	if (flags & EINFO_EASY_PARSE) {
		(void) fprintf(stdout, "%s\n", version);
	} else {
		(void) fprintf(stdout, "Extended version string: %s\n",
		    version);
		if (has_hash) {
			(void) fprintf(stdout, "%s hash: ",
			    bblk_hash_list[einfo->hash_type]->name);
		} else {
			(void) fprintf(stdout, "No hashing available\n");
		}
	}

	if (has_hash) {
		for (i = 0; i < einfo->hash_size; i++) {
			(void) fprintf(stdout, "%02x", hash[i]);
		}
		(void) fprintf(stdout, "\n");
	}
}

static int
compute_hash(bblk_hs_t *hs, unsigned char *dest, bblk_hash_t *hash)
{
	if (hs == NULL || dest == NULL || hash == NULL)
		return (-1);

	hash->compute_hash(dest, hs->src_buf, hs->src_size);
	return (0);
}

int
prepare_and_write_einfo(unsigned char *dest, char *infostr, bblk_hs_t *hs,
    uint32_t maxsize, uint32_t *used_space)
{
	uint16_t	hash_size;
	uint32_t	hash_off;
	unsigned char	*data;
	bblk_einfo_t	*einfo = (bblk_einfo_t *)dest;
	bblk_hash_t	*hashinfo = bblk_hash_list[BBLK_DEFAULT_HASH];

	/*
	 * 'dest' might be both containing the buffer we want to hash and
	 * containing our einfo structure: delay any update of it after the
	 * hashing has been calculated.
	 */
	hash_size = hashinfo->size;
	hash_off = sizeof (bblk_einfo_t);

	if (hash_off + hash_size > maxsize) {
		(void) fprintf(stderr, gettext("Unable to add extended info, "
		    "not enough space\n"));
		return (-1);
	}

	data = dest + hash_off;
	if (compute_hash(hs, data, hashinfo) < 0) {
		(void) fprintf(stderr, gettext("%s hash operation failed\n"),
		    hashinfo->name);
		einfo->hash_type = bblk_no_hash.type;
		einfo->hash_size = bblk_no_hash.size;
	} else {
		einfo->hash_type = hashinfo->type;
		einfo->hash_size = hashinfo->size;
	}

	(void) memcpy(einfo->magic, EINFO_MAGIC, EINFO_MAGIC_SIZE);
	einfo->version = BBLK_EINFO_VERSION;
	einfo->flags = 0;
	einfo->hash_off = hash_off;
	einfo->hash_size = hash_size;
	einfo->str_off = einfo->hash_off + einfo->hash_size + 1;

	if (infostr == NULL) {
		(void) fprintf(stderr, gettext("Unable to add extended info, "
		    "string is empty\n"));
		return (-1);
	}
	einfo->str_size = strlen(infostr);

	if (einfo->str_off + einfo->str_size > maxsize) {
		(void) fprintf(stderr, gettext("Unable to add extended info, "
		    "not enough space\n"));
		return (-1);
	}

	data = dest + einfo->str_off;
	(void) memcpy(data, infostr, einfo->str_size);
	*used_space = einfo->str_off + einfo->str_size;

	return (0);
}

/*
 * einfo_should_update()
 * Given information on the boot block currently on disk (disk_einfo) and
 * information on the supplied boot block (hs for hashing, verstr as the
 * associated version string) decide if an update of the on-disk boot block
 * is necessary or not.
 */
boolean_t
einfo_should_update(bblk_einfo_t *disk_einfo, bblk_hs_t *hs, char *verstr)
{
	bblk_hash_t	*hashing;
	unsigned char	*disk_hash;
	unsigned char	*local_hash;
	char		*disk_version;
	int		retval;

	if (disk_einfo == NULL)
		return (B_TRUE);

	if (memcmp(disk_einfo->magic, EINFO_MAGIC, EINFO_MAGIC_SIZE) != 0)
		return (B_TRUE);

	if (disk_einfo->version < BBLK_EINFO_VERSION)
		return (B_TRUE);

	disk_version = einfo_get_string(disk_einfo);
	retval = einfo_compare_version(verstr, disk_version);
	/*
	 * If something goes wrong or if the on-disk version is more recent
	 * do not update the bootblock.
	 */
	if (retval == -1 || retval == 2)
		return (B_FALSE);

	/*
	 * If we got here it means that the two version strings are either
	 * equal or the new bootblk binary is more recent. In order to save
	 * some needless writes let's use the hash to determine if an update
	 * is really necessary.
	 */
	if (disk_einfo->hash_type == bblk_no_hash.type)
		return (B_TRUE);

	if (disk_einfo->hash_type >= BBLK_HASH_TOT)
		return (B_TRUE);

	hashing = bblk_hash_list[disk_einfo->hash_type];

	local_hash = malloc(hashing->size);
	if (local_hash == NULL)
		return (B_TRUE);

	/*
	 * Failure in computing the hash may mean something wrong
	 * with the boot block file. Better be conservative here.
	 */
	if (compute_hash(hs, local_hash, hashing) < 0) {
		free(local_hash);
		return (B_FALSE);
	}

	disk_hash = (unsigned char *)einfo_get_hash(disk_einfo);

	if (memcmp(local_hash, disk_hash, disk_einfo->hash_size) == 0) {
		free(local_hash);
		return (B_FALSE);
	}

	free(local_hash);
	return (B_TRUE);
}

char *
einfo_get_string(bblk_einfo_t *einfo)
{
	if (einfo == NULL)
		return (NULL);

	return ((char *)einfo + einfo->str_off);
}

char *
einfo_get_hash(bblk_einfo_t *einfo)
{
	if (einfo == NULL)
		return (NULL);

	return ((char *)einfo + einfo->hash_off);
}
