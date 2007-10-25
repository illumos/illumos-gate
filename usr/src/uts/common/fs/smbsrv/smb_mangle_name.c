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

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <smbsrv/string.h>
#include <smbsrv/ctype.h>
#include <smbsrv/smb_i18n.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

static int smb_match_unknown(char *name, char *pattern);
static int smb_is_reserved_dos_name(char *name);
static int smb_match_reserved(char *name, char *rsrv);

/*
 * smb_match_name
 *
 * This function will mangle the "name" field and save the resulted
 * shortname to the "shortname" field and 8.3 name to "name83" field.
 * The three fields, "name", "shortname" and "name83" will then be
 * sent for pattern match with "pattern" field.
 *
 * The 0 is returned when the name is a reserved dos name, no match
 * for the pattern or any type of failure. The 1 is returned when
 * there is a match.
 */
int
smb_match_name(ino64_t fileid, char *name, char *shortname,
    char *name83, char *pattern, int ignore_case)
{
	int rc = 0;
	int force;

	/* Leading or trailing dots are disallowed */
	if (smb_is_reserved_dos_name(name))
		return (0);

	for (force = 0; (force < 2 && rc == 0); force++) {
		(void) smb_mangle_name(fileid, name, shortname, name83, force);

		rc = smb_match_ci(pattern, name);

		/* If no match, check for shortname (if any) */

		if (rc == 0 && strchr(pattern, '~'))
			if (*shortname != 0)
				rc = smb_match_ci(pattern, shortname);

		/*
		 * Sigh... DOS Shells use short name
		 * interchangeably with long case sensitive
		 * names. So check that too...
		 */
		if ((rc == 0) && !ignore_case)
			rc = smb_match83(pattern, name83);

		/*
		 * Still not found and potentially a premangled name...
		 * Check to see if the butt-head programmer is
		 * assuming that we mangle names in the same manner
		 * as NT...
		 */
		if (rc == 0)
			rc = smb_match_unknown(name, pattern);
	}

	return (rc);
}

/*
 * smb_match_unknown
 *
 * I couldn't figure out what the assumptions of this peice of
 * code about the format of pattern and name are and so how
 * it's trying to match them.  I just cleaned it up a little bit!
 *
 * If anybody could figure out what this is doing, please put
 * comment here and change the function's name!
 */
static int
smb_match_unknown(char *name, char *pattern)
{
	int rc;
	char nc, pc;
	char *np, *pp;

	rc = 0;
	if (utf8_isstrupr(pattern) <= 0)
		return (rc);

	np = name;
	pp = pattern;

	pc = *pattern;
	while ((nc = *np++) != 0) {
		if (nc == ' ')
			continue;

		nc = mts_toupper(nc);
		if ((pc = *pp++) != nc)
			break;
	}

	if ((pc == '~') &&
	    (pp != (pattern + 1)) &&
	    ((pc = *pp++) != 0)) {
		while (mts_isdigit(pc))
			pc = *pp++;

		if (pc == '.') {
			while ((nc = *np++) != 0) {
				if (nc == '.')
					break;
			}

			while ((nc = *np++) != 0) {
				nc = mts_toupper(nc);
				if ((pc = *pp++) != nc)
					break;
			}
		}

		if (pc == 0)
			rc = 1;
	}

	return (rc);
}

/*
 * smb_match_reserved
 *
 * Checks if the given name matches given
 * DOS reserved name prefix.
 *
 * Returns 1 if match, 0 otherwise
 */
static int
smb_match_reserved(char *name, char *rsrv)
{
	char ch;

	int len = strlen(rsrv);
	return (!utf8_strncasecmp(rsrv, name, len) &&
	    ((ch = *(name + len)) == 0 || ch == '.'));
}

/*
 * smb_is_reserved_dos_name
 *
 * This function checks if the name is a reserved dos name.
 *
 * The function returns 1 when the name is a reserved dos name;
 * otherwise, it returns 0.
 */
static int
smb_is_reserved_dos_name(char *name)
{
	char	ch;

	/*
	 * Eliminate all names reserved by DOS and Windows.
	 */
	ch = mts_toupper(*name);

	switch (ch) {
	case 'A':
		if (smb_match_reserved(name, "AUX"))
			return (1);
		break;

	case 'C':
		if (smb_match_reserved(name, "CLOCK$") ||
		    smb_match_reserved(name, "COM1") ||
		    smb_match_reserved(name, "COM2") ||
		    smb_match_reserved(name, "COM3") ||
		    smb_match_reserved(name, "COM4") ||
		    smb_match_reserved(name, "CON")) {
			return (1);
		}

		break;

	case 'L':
		if ((utf8_strncasecmp("LPT1", name, 4) == 0) ||
		    (utf8_strncasecmp("LPT2", name, 4) == 0) ||
		    (utf8_strncasecmp("LPT3", name, 4) == 0))
			return (1);
		break;

	case 'N':
		if (smb_match_reserved(name, "NUL"))
			return (1);
		break;

	case 'P':
		if (smb_match_reserved(name, "PRN"))
			return (1);
	}

	/*
	 * If the server is configured to support Catia Version 5
	 * deployments, any filename that contains backslash will
	 * have already been translated to the UTF-8 encoding of
	 * Latin Small Letter Y with Diaeresis. Thus, the check
	 * for backslash in the filename is not necessary.
	 */
#ifdef CATIA_SUPPORT
	/* XXX Catia support */
	if ((get_caps() & NFCAPS_CATIA) == 0) {
		while (*name != 0) {
			if (*name == '\\')
				return (1);
			name++;
		}
	}
#endif /* CATIA_SUPPORT */

	return (0);
}

/*
 * Characters we don't allow in DOS file names.
 * If a filename contains any of these chars, it should
 * get mangled.
 *
 * '.' is also an invalid DOS char but since it's a special
 * case it doesn't appear in the list.
 */
static char *invalid_dos_chars =
	"\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017"
	"\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037"
	" \"/\\:|<>*?";

/*
 * According to MSKB article #142982, Windows deletes invalid chars and
 * spaces from file name in mangling process; and invalid chars include:
 * ."/\[]:;=,
 *
 * But some of these chars and some other chars (e.g. +) are replaced
 * with underscore (_). They are introduced here as special chars.
 */
static char *special_chars = "[];=,+";

#define	isinvalid(c)	(strchr(invalid_dos_chars, c) || (c & 0x80))

/*
 * smb_needs_mangle
 *
 * Determines whether the given name needs to get mangled.
 *
 * Here are the (known) rules:
 *
 *	1st char is dot (.)
 *	name length > 12 chars
 *	# dots > 1
 *	# dots == 0 and length > 8
 *	# dots == 1 and name isn't 8.3
 *	contains illegal chars
 */
int
smb_needs_mangle(char *name, char **dot_pos)
{
	int len, ndots;
	char *namep;
	char *last_dot;

	/*
	 * Returning (1) for these cases forces consistency with how
	 * these names are treated (smb_mangle_name() will produce an 8.3 name
	 * for these)
	 */
	if ((strcmp(name, ".") == 0) || (strcmp(name, "..") == 0))
		return (1);

	/* skip the leading dots (if any) */
	for (namep = name; *namep == '.'; namep++)
		;

	len = ndots = 0;
	last_dot = 0;
	for (; *namep; namep++) {
		len++;
		if (*namep == '.') {
			/* keep the position of last dot */
			last_dot = namep;
			ndots++;
		}
	}
	*dot_pos = last_dot;

	/* Windows mangles names like .a, .abc, or .abcd */
	if (*name == '.')
		return (1);

	if (len > 12)
		return (1);

	switch (ndots) {
	case 0:
		/* no dot */
		if (len > 8)
			return (1);
		break;

	case 1:
		/* just one dot */
		/*LINTED E_PTR_DIFF_OVERFLOW*/
		if (((last_dot - name) > 8) ||		/* name length > 8 */
		    (strlen(last_dot + 1) > 3))		/* extention > 3 */
			return (1);
		break;

	default:
		/* more than one dot */
		return (1);
	}

	for (namep = name; *namep; namep++) {
		if (!mts_isascii(*namep) ||
		    strchr(special_chars, *namep) ||
		    strchr(invalid_dos_chars, *namep))
			return (1);
	}

	return (0);
}

/*
 * smb_needs_shortname
 *
 * Determine whether a shortname should be generated for a file name that is
 * already in 8.3 format.
 *
 * Paramters:
 *   name - original file name
 *
 * Return:
 *   1 - Shortname is required to be generated.
 *   0 - No shortname needs to be generated.
 *
 * Note
 * =======
 * Windows NT server:       shortname is created only if either
 *                          the filename or extension portion of
 *                          a file is made up of mixed case.
 * Windows 2000 server:     shortname is not created regardless
 *                          of the case.
 * Windows 2003 server:     [Same as Windows NT server.]
 *
 * StorEdge will conform to the rule used by Windows NT/2003 server.
 *
 * For instance:
 *    File      | Create shortname?
 * ================================
 *  nf.txt      | N
 *  NF.TXT      | N
 *  NF.txt      | N
 *  nf          | N
 *  NF          | N
 *  nF.txt      | Y
 *  nf.TxT      | Y
 *  Nf          | Y
 *  nF          | Y
 *
 */
static int
smb_needs_shortname(char *name)
{
	char buf[9];
	int len;
	int create = 0;
	const char *dot_pos = 0;

	dot_pos = strrchr(name, '.');
	/*LINTED E_PTRDIFF_OVERFLOW*/
	len = (!dot_pos) ? strlen(name) : (dot_pos - name);
	/* First, examine the name portion of the file */
	if (len) {
		(void) snprintf(buf, len + 1, "%s", name);
		/* if the name contains both lower and upper cases */
		if (utf8_isstrupr(buf) == 0 && utf8_isstrlwr(buf) == 0) {
			/* create shortname */
			create = 1;
		} else 	if (dot_pos) {
			/* Next, examine the extension portion of the file */
			(void) snprintf(buf, sizeof (buf), "%s", dot_pos + 1);
			/*
			 * if the extension contains both lower and upper
			 * cases
			 */
			if (utf8_isstrupr(buf) == 0 && utf8_isstrlwr(buf) == 0)
				/* create shortname */
				create = 1;
		}
	}

	return (create);
}

/*
 * smb_mangle_char
 *
 * If given char is an invalid DOS character or it's not an
 * ascii char, it should be deleted from mangled and 8.3 name.
 *
 * If given char is one of special chars, it should be replaced
 * with '_'.
 *
 * Otherwise just make it upper case.
 */
static unsigned char
smb_mangle_char(unsigned char ch)
{
	if (isinvalid(ch))
		return (0);

	if (strchr(special_chars, ch))
		return ('_');

	return (mts_toupper(ch));
}

/*
 * smb_generate_mangle
 *
 * Generates a mangle string which contains
 * at least 2 (considering fileid cannot be 0)
 * and at most 7 chars.
 *
 * Returns the number of chars in the generated mangle.
 */
static int
smb_generate_mangle(ino64_t fileid, unsigned char *mangle_buf)
{
	/*
	 * 36**6 = 2176782336: more than enough to express inodes in 6
	 * chars
	 */
	static char *base36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	unsigned char *manglep = mangle_buf;

	for (*manglep++ = '~'; fileid > 0; fileid /= 36)
		*manglep++ = base36[fileid % 36];
	*manglep = 0;

	/*LINTED E_PTRDIFF_OVERFLOW*/
	return (manglep - mangle_buf);
}

/*
 * smb_maybe_mangled_name
 *
 * returns true if the passed name can possibly be a mangled name.
 * mangled names should be valid dos file names hence less than 12 characters
 * long and should contain at least one tilde character.
 *
 * note that this function can be further enhanced to check for invalid
 * dos characters/character patterns (such as "file..1.c") but this version
 * should be sufficient in most cases.
 */
int
smb_maybe_mangled_name(char *name)
{
	int i, has_tilde = 0;

	for (i = 0; *name && (i < 12); i++, name++) {
		if ((*name == '~') && (i < 8))
			has_tilde = 1;

		if (*name == '.' && has_tilde == 0)
			return (0);
	}

	return ((*name == 0) && has_tilde);
}

/*
 * smb_mangle_name
 *
 * Microsoft knowledge base article #142982 describes how Windows
 * generates 8.3 filenames from long file names. Some other details
 * can be found in article #114816.
 *
 * The function first checks to see whether the given name needs mangling.
 * If not, and the force parameter is not set, then no mangling is done,
 * but both the shortname (if needed) and the 8.3 name are produced and
 * returned.
 *
 * If the "force" parameter is set (as will be the case for case-insensitive
 * collisions), then the name will be mangled.
 *
 * Whenever mangling is needed, both the shortname and the 8.3 names are
 * produced and returned.
 *
 * For example, the xxx.xy in 8.3 format will be "xxx     .xy ".
 */

int smb_mangle_name(
	ino64_t fileid,		/* inode number to generate unique mangle */
	char *name,		/* original file name */
	char *shortname,	/* mangled name (if applicable) */
	char *name83,		/* (mangled) name in 8.3 format */
	int force)		/* force mangling even if mangling is not */
				/* needed according to standard algorithm */
{
	int avail;
	unsigned char ch;
	unsigned char mangle_buf[8];
	unsigned char *namep;
	unsigned char *manglep;
	unsigned char *out_short;
	unsigned char *out_83;
	char *dot_pos = NULL;

	/*
	 * NOTE:
	 * This function used to consider filename case
	 * in order to mangle. I removed those checks.
	 */

	*shortname = *name83 = 0;

	/* Allow dot and dot dot up front */
	if (strcmp(name, ".") == 0) {
		/* no shortname */
		(void) strcpy(name83, ".       .   ");
		return (1);
	}

	if (strcmp(name, "..") == 0) {
		/* no shortname */
		(void) strcpy(name83, "..      .   ");
		return (1);
	}

	out_short = (unsigned char *)shortname;
	out_83 = (unsigned char *)name83;

	if ((smb_needs_mangle(name, &dot_pos) == 0) && (force == 0)) {
		/* no mangle */

		/* check if shortname is required or not */
		if (smb_needs_shortname(name)) {
			namep = (unsigned char *)name;
			while (*namep)
				*out_short++ = mts_toupper(*namep++);
			*out_short = '\0';
		}

		out_83 = (unsigned char *)name83;
		(void) strcpy((char *)out_83, "        .   ");
		while (*name && *name != '.')
			*out_83++ = mts_toupper(*name++);

		if (*name == '.') {
			/* copy extension */
			name++;
			out_83 = (unsigned char *)name83 + 9;
			while (*name)
				*out_83++ = mts_toupper(*name++);
		}
		return (1);
	}

	avail = 8 - smb_generate_mangle(fileid, mangle_buf);

	/*
	 * generated mangle part has always less than 8 chars, so
	 * use the chars before the first dot in filename
	 * and try to generate a full 8 char name.
	 */

	/* skip the leading dots (if any) */
	for (namep = (unsigned char *)name; *namep == '.'; namep++)
		;

	for (; avail && *namep && (*namep != '.'); namep++) {
		ch = smb_mangle_char(*namep);
		if (ch == 0)
			continue;
		*out_short++ = *out_83++ = ch;
		avail--;
	}

	/* Copy in mangled part */
	manglep = mangle_buf;

	while (*manglep)
		*out_short++ = *out_83++ = *(manglep++);

	/* Pad any leftover in 8.3 name with spaces */
	while (avail--)
		*out_83++ = ' ';

	/* Work on extension now */
	avail = 3;
	*out_83++ = '.';
	if (dot_pos) {
		namep = (unsigned char *)dot_pos + 1;
		if (*namep != 0) {
			*out_short++ = '.';
			for (; avail && *namep; namep++) {
				ch = smb_mangle_char(*namep);
				if (ch == 0)
					continue;

				*out_short++ = *out_83++ = ch;
				avail--;
			}
		}
	}

	while (avail--)
		*out_83++ = ' ';

	*out_short = *out_83 = '\0';

	return (1);
}

/*
 * smb_unmangle_name
 *
 * Given a mangled name, try to find the real file name as it appears
 * in the directory entry. If the name does not contain a ~, it is most
 * likely not a mangled name but the caller can still try to get the
 * actual on-disk name by setting the "od" parameter.
 *
 * Returns 0 if a name has been returned in real_name. There are three
 * possible scenarios:
 *  1. Name did not contain a ~ and "od" was not set, in which
 *     case, real_name contains name.
 *  2. Name did not contain a ~ and "od" was set, in which
 *     case, real_name contains the actual directory entry name.
 *  3. Name did contain a ~, in which case, name was mangled and
 *     real_name contains the actual directory entry name.
 *
 * EINVAL: a parameter was invalid.
 * ENOENT: an unmangled name could not be found.
 */

int
smb_unmangle_name(struct smb_request *sr, cred_t *cred, smb_node_t *dir_node,
	char *name, char *real_name, int realname_size, char *shortname,
	char *name83, int od)
{
	int err;
	int len;
	int force = 0;
	ino64_t inode;
	uint32_t cookie;
	struct smb_node *snode = NULL;
	smb_attr_t ret_attr;
	char *dot_pos = NULL;
	char *readdir_name;
	char *shortp;
	char xxx[MANGLE_NAMELEN];

	if (dir_node == NULL || name == NULL || real_name == NULL ||
	    realname_size == 0)
		return (EINVAL);

	*real_name = '\0';
	snode = NULL;

	if (smb_maybe_mangled_name(name) == 0) {
		if (od == 0) {
			(void) strlcpy(real_name, name, realname_size);
			return (0);
		}

		err = smb_fsop_lookup(sr, cred, 0, sr->tid_tree->t_snode,
		    dir_node, name, &snode, &ret_attr, NULL, NULL);

		if (err != 0)
			return (err);

		(void) strlcpy(real_name, snode->od_name, realname_size);
		smb_node_release(snode);
		return (0);
	}

	if (shortname == 0)
		shortname = xxx;
	if (name83 == 0)
		name83 = xxx;

	cookie = 0;

	readdir_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	snode = NULL;
	while (cookie != 0x7FFFFFFF) {

		len = realname_size - 1;

		err = smb_fsop_readdir(sr, cred, dir_node, &cookie,
		    readdir_name, &len, &inode, NULL, &snode, &ret_attr);

		if (err || (cookie == 0x7FFFFFFF))
			break;

		readdir_name[len] = 0;

		/*
		 * smb_fsop_readdir() may return a mangled name if the
		 * name has a case collision.
		 *
		 * If readdir_name is not a mangled name, we mangle
		 * readdir_name to see if it will match the name the
		 * client passed in.
		 *
		 * If smb_needs_mangle() does not succeed, we try again
		 * using the force flag.  It is possible that the client
		 * is using a mangled name that resulted from a prior
		 * case collision which no longer exists in the directory.
		 * smb_needs_mangle(), with the force flag, will produce
		 * a mangled name regardless of whether the name passed in
		 * meets standard DOS criteria for name mangling.
		 */

		if (smb_maybe_mangled_name(readdir_name)) {
			shortp = readdir_name;
		} else {
			if (smb_needs_mangle(readdir_name, &dot_pos) == 0)
				force = 1;
			(void) smb_mangle_name(inode, readdir_name, shortname,
			    name83, force);
			shortp = shortname;
		}

		if (utf8_strcasecmp(name, shortp) == 0) {
			kmem_free(readdir_name, MAXNAMELEN);
			(void) strlcpy(real_name, snode->od_name,
			    realname_size);

			smb_node_release(snode);

			return (0);
		} else {
			smb_node_release(snode);
			snode = NULL;
		}
	}

	kmem_free(readdir_name, MAXNAMELEN);

	return (ENOENT);
}
