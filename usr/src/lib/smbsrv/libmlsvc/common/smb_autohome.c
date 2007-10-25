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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <sys/stat.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smbinfo.h>

#define	SMB_AUTOHOME_KEYSIZ	128
#define	SMB_AUTOHOME_MAXARG	4
#define	SMB_AUTOHOME_BUFSIZ	2048

typedef struct smb_autohome_info {
	struct smb_autohome_info *magic1;
	FILE *fp;
	smb_autohome_t autohome;
	char buf[SMB_AUTOHOME_BUFSIZ];
	char *argv[SMB_AUTOHOME_MAXARG];
	int lineno;
	struct smb_autohome_info *magic2;
} smb_autohome_info_t;

static smb_autohome_info_t smb_ai;

static smb_autohome_t *smb_autohome_make_entry(smb_autohome_info_t *);
static char *smb_autohome_keysub(const char *, char *, int);
static smb_autohome_info_t *smb_autohome_getinfo(void);

/*
 * Add an autohome share.  See smb_autohome(4) for details.
 *
 * If share directory contains backslash path separators, they will
 * be converted to forward slash to support NT/DOS path style for
 * autohome shares.
 *
 * Returns 0 on success or -1 to indicate an error.
 */
int
smb_autohome_add(const char *username)
{
	lmshare_info_t si;
	char *sharename;
	smb_autohome_t *ai;

	if (username == NULL)
		return (-1);

	if ((sharename = strdup(username)) == NULL)
		return (-1);

	if ((ai = smb_autohome_lookup(sharename)) == NULL) {
		free(sharename);
		return (0);
	}

	(void) memset(&si, 0, sizeof (lmshare_info_t));
	(void) strlcpy(si.directory, ai->ah_path, MAXPATHLEN);
	(void) strsubst(si.directory, '\\', '/');
	(void) strlcpy(si.container, ai->ah_container, MAXPATHLEN);

	if (lmshare_is_dir(si.directory) == 0) {
		free(sharename);
		return (0);
	}

	if (lmshare_exists(sharename) != 0) {
		(void) lmshare_getinfo(sharename, &si);
		if (!(si.mode & LMSHRM_TRANS)) {
			free(sharename);
			return (0);
		}
	} else {
		(void) strcpy(si.share_name, sharename);
		si.mode = LMSHRM_TRANS;
	}

	(void) lmshare_add(&si, 0);
	free(sharename);
	return (0);
}

/*
 * Remove an autohome share.
 *
 * Returns 0 on success or -1 to indicate an error.
 */
int
smb_autohome_remove(const char *username)
{
	lmshare_info_t si;
	char *sharename;

	if (username == NULL)
		return (-1);

	if ((sharename = strdup(username)) == NULL)
		return (-1);

	if (lmshare_getinfo(sharename, &si) == NERR_Success) {
		if (si.mode & LMSHRM_TRANS) {
			(void) lmshare_delete(sharename, 0);
		}
	}

	free(sharename);
	return (0);
}

/*
 * Find out if a share is an autohome share.
 *
 * Returns 1 if the share is an autohome share.
 * Otherwise returns 0.
 */
int
smb_is_autohome(const lmshare_info_t *si)
{
	if (si && (si->mode & LMSHRM_TRANS) &&
	    (lmshare_is_restricted((char *)si->share_name) == 0)) {
		return (1);
	}

	return (0);
}

/*
 * Search the autohome database for the specified name. The name cannot
 * be an empty string or begin with * or +.
 * 1. Search the file for the specified name.
 * 2. Check for the wildcard rule and, if present, treat it as a match.
 * 3. Check for the nsswitch rule and, if present, lookup the name
 *    via the name services. Note that the nsswitch rule will never
 *    be applied if the wildcard rule is present.
 *
 * Returns a pointer to the entry on success or null on failure.
 */
smb_autohome_t *
smb_autohome_lookup(const char *name)
{
	struct passwd *pw;
	smb_autohome_t *ah = 0;

	if (name == NULL)
		return (NULL);

	if (*name == '\0' || *name == '*' || *name == '+')
		return (NULL);

	smb_autohome_setent();

	while ((ah = smb_autohome_getent(name)) != NULL) {
		if (strcasecmp(ah->ah_name, name) == 0)
			break;
	}

	if (ah == NULL) {
		smb_autohome_setent();

		while ((ah = smb_autohome_getent(name)) != NULL) {
			if (strcasecmp(ah->ah_name, "*") == 0) {
				ah->ah_name = (char *)name;
				break;
			}
		}
	}

	if (ah == NULL) {
		smb_autohome_setent();

		while ((ah = smb_autohome_getent("+nsswitch")) != NULL) {
			if (strcasecmp("+nsswitch", ah->ah_name) != 0)
				continue;
			if ((pw = getpwnam(name)) == NULL) {
				ah = 0;
				break;
			}

			ah->ah_name = pw->pw_name;

			if (ah->ah_path)
				ah->ah_container = ah->ah_path;

			ah->ah_path = pw->pw_dir;
			break;
		}
	}

	smb_autohome_endent();
	return (ah);
}

/*
 * Open or rewind the autohome database.
 */
void
smb_autohome_setent(void)
{
	smb_autohome_info_t *si;
	char *mappath;
	char filename[MAXNAMELEN];

	if ((si = smb_autohome_getinfo()) != 0) {
		(void) fseek(si->fp, 0L, SEEK_SET);
		si->lineno = 0;
		return;
	}

	if ((si = &smb_ai) == 0)
		return;

	smb_config_rdlock();
	if ((mappath = smb_config_get(SMB_CI_AUTOHOME_MAP)) == NULL)
		mappath = SMB_AUTOHOME_PATH;
	(void) snprintf(filename, MAXNAMELEN, "%s/%s", mappath,
	    SMB_AUTOHOME_FILE);
	smb_config_unlock();

	if ((si->fp = fopen(filename, "r")) == NULL)
		return;

	si->magic1 = si;
	si->magic2 = si;
	si->lineno = 0;
}

/*
 * Close the autohome database and invalidate the autohome info.
 * We can't zero the whole info structure because the application
 * should still have access to the data after the file is closed.
 */
void
smb_autohome_endent(void)
{
	smb_autohome_info_t *si;

	if ((si = smb_autohome_getinfo()) != 0) {
		(void) fclose(si->fp);
		si->fp = 0;
		si->magic1 = 0;
		si->magic2 = 0;
	}
}

/*
 * Return the next entry in the autohome database, opening the file
 * if necessary.  Returns null on EOF or error.
 *
 * Note that we are not looking for the specified name. The name is
 * only used for key substitution, so that the caller sees the entry
 * in expanded form.
 */
smb_autohome_t *
smb_autohome_getent(const char *name)
{
	smb_autohome_info_t *si;
	char *bp;

	if ((si = smb_autohome_getinfo()) == 0) {
		smb_autohome_setent();

		if ((si = smb_autohome_getinfo()) == 0)
			return (0);
	}

	/*
	 * Find the next non-comment, non-empty line.
	 * Anything after a # is a comment and can be discarded.
	 * Discard a newline to avoid it being included in the parsing
	 * that follows.
	 * Leading and training whitespace is discarded, and replicated
	 * whitespace is compressed to simplify the token parsing,
	 * although strsep() deals with that better than strtok().
	 */
	do {
		if (fgets(si->buf, SMB_AUTOHOME_BUFSIZ, si->fp) == 0)
			return (0);

		++si->lineno;

		if ((bp = strpbrk(si->buf, "#\r\n")) != 0)
			*bp = '\0';

		(void) trim_whitespace(si->buf);
		bp = strcanon(si->buf, " \t");
	} while (*bp == '\0');

	(void) smb_autohome_keysub(name, si->buf, SMB_AUTOHOME_BUFSIZ);
	return (smb_autohome_make_entry(si));
}

/*
 * Set up an autohome entry from the line buffer. The line should just
 * contain tokens separated by single whitespace. The line format is:
 *	<username> <home-dir-path> <ADS container>
 */
static smb_autohome_t *
smb_autohome_make_entry(smb_autohome_info_t *si)
{
	char *bp;
	int i;

	bp = si->buf;

	for (i = 0; i < SMB_AUTOHOME_MAXARG; ++i)
		si->argv[i] = 0;

	for (i = 0; i < SMB_AUTOHOME_MAXARG; ++i) {
		do {
			if ((si->argv[i] = strsep((char **)&bp, " \t")) == 0)
				break;
		} while (*(si->argv[i]) == '\0');

		if (si->argv[i] == 0)
			break;
	}

	if ((si->autohome.ah_name = si->argv[0]) == NULL) {
		/*
		 * Sanity check: the name could be an empty
		 * string but it can't be a null pointer.
		 */
		return (0);
	}

	if ((si->autohome.ah_path = si->argv[1]) == NULL)
		si->autohome.ah_path = "";

	if ((si->autohome.ah_container = si->argv[2]) == NULL)
		si->autohome.ah_container = "";

	return (&si->autohome);
}

/*
 * Substitute the ? and & map keys.
 * ? is replaced by the first character of the name
 * & is replaced by the whole name.
 */
static char *
smb_autohome_keysub(const char *name, char *buf, int buflen)
{
	char key[SMB_AUTOHOME_KEYSIZ];
	char *ampersand;
	char *tmp;

	(void) strlcpy(key, buf, SMB_AUTOHOME_KEYSIZ);

	if ((tmp = strpbrk(key, " \t")) == NULL)
		return (NULL);

	*tmp = '\0';

	if (strcmp(key, "*") == 0 && name != NULL)
		(void) strlcpy(key, name, SMB_AUTOHOME_KEYSIZ);

	(void) strsubst(buf, '?', *key);

	while ((ampersand = strchr(buf, '&')) != NULL) {
		if ((tmp = strdup(ampersand + 1)) == NULL)
			return (0);

		(void) strlcpy(ampersand, key, buflen);
		(void) strlcat(ampersand, tmp, buflen);
		free(tmp);
	}

	return (buf);
}

/*
 * Get a pointer to the context buffer and validate it.
 */
static smb_autohome_info_t *
smb_autohome_getinfo(void)
{
	smb_autohome_info_t *si;

	if ((si = &smb_ai) == 0)
		return (0);

	if ((si->magic1 == si) && (si->magic2 == si) && (si->fp != NULL))
		return (si);

	return (0);
}
