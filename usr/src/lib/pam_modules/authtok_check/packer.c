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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "packer.h"

/*
 * This file steers the creation of the Crack Dictionary Database.
 * Based on a list of source dictionaries specified by the administrator,
 * we create the Database by sorting each dictionary (in memory, one at
 * a time), writing the sorted result to a temporary file, and merging
 * all the temporary files into the Database.
 *
 * The current implementation has a number of limitations
 *   - each single source dictionary has to fit in memory
 *   - each single source dictionary has to be smaller than 2GByte
 *   - each single source dictionary can only hold up to 4GB words
 * None of these seem real, practical, problems to me.
 *
 * All of this is meant to be run by one thread per host. The caller is
 * responsible for locking things appropriately (as make_dict_database
 * in dict.c does).
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Stuff used for sorting the dictionary */
static char	*buf;		/* used to hold the source dictionary */
static uint_t	*offsets;	/* array of word-offsets into "buf" */
static uint_t	off_idx = 0;	/* first free index in offsets array */
static size_t	off_size = 0;	/* offsets array size */

/* stuff to keep track of the temporary files */
#define	FNAME_TEMPLATE	"/var/tmp/authtok_check.XXXXXX"
#define	MAXTMP		64
static FILE	*tmpfp[MAXTMP];	/* FILE *'s to (unlinked) temporary files */
static int	tmpfp_idx = 0;	/* points to first free entry in tmpfp */

#define	MODNAME "pam_authtok_check::packer"

/*
 * int writeout(void)
 *
 * Write the sorted wordlist to disk. We create a temporary file
 * (in /var/tmp), and immediately unlink() it. We keep an open
 * FILE pointer to it in tmpfp[] for later use.
 *
 * returns 0 on success, -1 on failure (can't create file/output failure).
 */
int
writeout(void)
{
	int i = 0;
	char tmpname[sizeof (FNAME_TEMPLATE)];
	int fd;

	if (tmpfp_idx == MAXTMP) {
		syslog(LOG_ERR, MODNAME ": too many temporary "
		    "files (maximum %d exceeded)", MAXTMP);
		return (-1);
	}

	(void) strcpy(tmpname, FNAME_TEMPLATE);
	if ((fd = mkstemp(tmpname)) == -1) {
		syslog(LOG_ERR, MODNAME ": mkstemp() failed: %s\n",
		    strerror(errno));
		return (-1);
	}
	(void) unlink(tmpname);

	if ((tmpfp[tmpfp_idx] = fdopen(fd, "w+F")) == NULL) {
		syslog(LOG_ERR, MODNAME ": fdopen failed: %s",
		    strerror(errno));
		(void) close(fd);
		return (-1);
	}

	/* write words to file */
	while (i < off_idx) {
		if (fprintf(tmpfp[tmpfp_idx], "%s\n", &buf[offsets[i++]]) < 0) {
			syslog(LOG_ERR, MODNAME ": write to file failed: %s",
			    strerror(errno));
			(void) close(fd);
			return (-1);
		}
	}

	/* we have one extra tmpfp */
	tmpfp_idx++;

	return (0);
}

/*
 * int insert_word(int off)
 *
 * insert an offset into the offsets-array. If the offsets-array is out of
 * space, we allocate additional space (in CHUNKs)
 *
 * returns 0 on success, -1 on failure (out of memory)
 */
int
insert_word(int off)
{
#define	CHUNK 10000

	if (off_idx == off_size) {
		uint_t *tmp;
		off_size += CHUNK;
		tmp = realloc(offsets, sizeof (uint_t) * off_size);
		if (tmp == NULL) {
			syslog(LOG_ERR, MODNAME ": out of memory");
			free(offsets);
			off_idx = off_size = 0;
			offsets = NULL;
			return (-1);
		}
		offsets = tmp;
	}

	offsets[off_idx++] = off;
	return (0);
}

/*
 * translate(buf, size)
 *
 * perform "tr '[A-Z]' '[a-z]' | tr -cd '\012[a-z][0-9]'" on the
 * words in "buf" and insert each of them into the offsets-array.
 * We refrain from using 'isupper' and 'islower' to keep this strictly
 * ASCII-only, as is the original Cracklib code.
 *
 * returns 0 on success, -1 on failure (failure of insert_word)
 */
int
translate(char *buf, size_t size)
{
	char *p, *q, *e;
	char c;
	int wordstart;

	e = &buf[size];

	wordstart = 0;
	for (p = buf, q = buf; q < e; q++) {
		c = *q;
		if (c >= 'A' && c <= 'Z') {
			*(p++) = tolower(c);
		} else if (c == '\n') {
			*(p++) = '\0';
			/*
			 * make sure we only insert words consisting of
			 * MAXWORDLEN-1 bytes or less
			 */
			if (p-&buf[wordstart] > MAXWORDLEN)
				buf[wordstart+MAXWORDLEN-1] = '\0';
			if (insert_word(wordstart) != 0)
				return (-1);
			wordstart = p-buf;
		} else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			*(p++) = c;
		}
	}
	return (0);
}

/*
 * int compare(a, b)
 *
 * helper-routine used for quicksort. we compate two words in the
 * buffer, one start starts at index "a", and the other one that starts
 * at index "b"
 */
int
compare(const void *a, const void *b)
{
	int idx_a = *(uint_t *)a, idx_b = *(uint_t *)b;

	return (strcmp(&buf[idx_a], &buf[idx_b]));
}

/*
 *
 * int sort_file(fname)
 *
 * We sort the file in memory: we read the dictionary file, translate all
 * newlines to '\0's, all uppercase ASCII characters to lowercase characters
 * and removing all characters but '[a-z][0-9]'.
 * We maintain an array of offsets into the buffer where each word starts
 * and sort this array using qsort().
 *
 * This implements the original cracklib code that did an execl of
 *    sh -c "/usr/bin/cat <list of files> |
 *       /usr/bin/tr '[A-Z]' '[a-z]' | /usr/bin/tr -cd '\012[a-z][0-9]' |
 *       sort -o tmfpfile
 *
 * returns 0 on success, -1 on failure.
 */
int
sort_file(char *fname)
{
	int fd;
	struct stat statbuf;
	ssize_t n;
	int ret = -1;

	if ((fd = open(fname, O_RDONLY)) == -1) {
		syslog(LOG_ERR, MODNAME ": failed to open %s: %s",
		    fname, strerror(errno));
		return (-1);
	}

	if (fstat(fd, &statbuf) == -1) {
		syslog(LOG_ERR, MODNAME ": fstat() failed (%s)",
		    strerror(errno));
		(void) close(fd);
		return (-1);
	}
	if ((buf = malloc(statbuf.st_size + 1)) == NULL) {
		syslog(LOG_ERR, MODNAME ": out of memory");
		goto error;
	}

	n = read(fd, buf, statbuf.st_size);

	if (n == -1) {
		if (errno == EINVAL)
			syslog(LOG_ERR, MODNAME ": %s is too big. "
			    "Split the file into smaller files.", fname);
		else
			syslog(LOG_ERR, MODNAME ": read failed: %s",
			    strerror(errno));
		goto error;
	}

	if (translate(buf, n) == 0) {
		qsort((void *)offsets, off_idx, sizeof (int), compare);

		if (writeout() == 0)
			ret = 0;
	}

error:
	(void) close(fd);

	if (buf != NULL)
		free(buf);
	if (offsets != NULL)
		free(offsets);
	offsets = NULL;
	off_size = 0;
	off_idx = 0;
	return (ret);
}

/*
 * We merge the temporary files created by previous calls to sort_file()
 * and insert the thus sorted words into the cracklib database
 *
 * returns 0 on success, -1 on failure.
 */
int
merge_files(PWDICT *pwp)
{
	int ti;
	char *words[MAXTMP];
	char lastword[MAXWORDLEN];
	int choice;

	lastword[0] = '\0';

	for (ti = 0; ti < tmpfp_idx; ti++)
		if ((words[ti] = malloc(MAXWORDLEN)) == NULL) {
			while (--ti >= 0)
				free(words[ti]);
			return (-1);
		}

	/*
	 * we read the first word of each of the temp-files into words[].
	 */
	for (ti = 0; ti < tmpfp_idx; ti++) {
		(void) fseek(tmpfp[ti], 0, SEEK_SET);
		(void) fgets(words[ti], MAXWORDLEN, tmpfp[ti]);
		words[ti][MAXWORDLEN-1] = '\0';
	}

	/*
	 * next, we emit the word that comes first (lexicographically),
	 * and replace that word with a new word from the file it
	 * came from. If the file is exhausted, we close the fp and
	 * swap the fp with the last fp in tmpfp[].
	 * we then decrease tmpfp_idx and continue with what's left until
	 * we run out of open FILE pointers.
	 */
	while (tmpfp_idx != 0) {
		choice = 0;

		for (ti = 1; ti < tmpfp_idx; ti++)
			if (strcmp(words[choice], words[ti]) > 0)
				choice = ti;
		/* Insert word in Cracklib database */
		(void) Chomp(words[choice]);
		if (words[choice][0] != '\0' &&
		    strcmp(lastword, words[choice]) != 0) {
			(void) PutPW(pwp, words[choice]);
			(void) strncpy(lastword, words[choice], MAXWORDLEN);
		}

		if (fgets(words[choice], MAXWORDLEN, tmpfp[choice]) == NULL) {
			(void) fclose(tmpfp[choice]);
			tmpfp[choice] = tmpfp[tmpfp_idx - 1];
			tmpfp_idx--;
		} else
			words[choice][MAXWORDLEN-1] = '\0';
	}
	return (0);
}

/*
 * int packer(list)
 *
 * sort all dictionaries in "list", and feed the words into the Crack
 * Password Database.
 *
 * returns 0 on sucess, -1 on failure.
 */
int
packer(char *list, char *path)
{
	PWDICT *pwp;
	char *listcopy, *fname;
	int ret = 0;

	if ((listcopy = strdup(list)) == NULL) {
		syslog(LOG_ERR, MODNAME ": out of memory");
		return (-1);
	}

	if (!(pwp = PWOpen(path, "wF")))
		return (-1);

	fname = strtok(listcopy, " \t,");
	while (ret == 0 && fname != NULL) {
		if ((ret = sort_file(fname)) == 0)
			fname = strtok(NULL, " \t,");
	}
	free(listcopy);

	if (ret == 0)
		ret = merge_files(pwp);

	(void) PWClose(pwp);

	return (ret);
}
