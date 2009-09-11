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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <smbsrv/string.h>
#include <smbsrv/ctype.h>
#include <smbsrv/smb_i18n.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

#define	SMB_NAME83_BASELEN	8
#define	SMB_NAME83_LEN		12

/*
 * Characters we don't allow in DOS file names.
 * If a filename contains any of these chars, it should get mangled.
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

static int smb_match_unknown(char *name, char *pattern);
static boolean_t smb_is_reserved_dos_name(const char *name);

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
smb_match_name(ino64_t fileid, char *name, char *pattern, boolean_t ignore_case)
{
	int rc = 0;
	int force;
	char name83[SMB_SHORTNAMELEN];
	char shortname[SMB_SHORTNAMELEN];

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
 * Return true if name contains characters that are invalid in a file
 * name or it is a reserved DOS device name.  Otherwise, returns false.
 *
 * Control characters (values 0 - 31) and the following characters are
 * invalid:
 *	< > : " / \ | ? *
 */
boolean_t
smb_is_invalid_filename(const char *name)
{
	const char *p;

	if ((p = strpbrk(name, invalid_dos_chars)) != NULL) {
		if (*p != ' ')
			return (B_TRUE);
	}

	return (smb_is_reserved_dos_name(name));
}

/*
 * smb_is_reserved_dos_name
 *
 * This function checks if the name is a reserved DOS device name.
 * The device name should not be followed immediately by an extension,
 * for example, NUL.txt.
 */
static boolean_t
smb_is_reserved_dos_name(const char *name)
{
	static char *cnames[] = { "CLOCK$", "COM1", "COM2", "COM3", "COM4",
		"COM5", "COM6", "COM7", "COM8", "COM9", "CON" };
	static char *lnames[] = { "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
		"LPT6", "LPT7", "LPT8", "LPT9" };
	static char *others[] = { "AUX", "NUL", "PRN" };
	char	**reserved;
	char	ch;
	int	n_reserved;
	int	len;
	int	i;

	ch = mts_toupper(*name);

	switch (ch) {
	case 'A':
	case 'N':
	case 'P':
		reserved = others;
		n_reserved = sizeof (others) / sizeof (others[0]);
		break;
	case 'C':
		reserved = cnames;
		n_reserved = sizeof (cnames) / sizeof (cnames[0]);
		break;
	case 'L':
		reserved = lnames;
		n_reserved = sizeof (lnames) / sizeof (lnames[0]);
		break;
	default:
		return (B_FALSE);
	}

	for (i  = 0; i < n_reserved; ++i) {
		len = strlen(reserved[i]);

		if (utf8_strncasecmp(reserved[i], name, len) == 0) {
			ch = *(name + len);
			if ((ch == '\0') || (ch == '.'))
				return (B_TRUE);
		}
	}

	return (B_FALSE);
}

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
 * Generate a mangle string containing at least 2 characters and at most
 * (buflen - 1) characters.  Note: fid cannot be 0.
 *
 * Returns the number of chars in the generated mangle.
 */
static int
smb_generate_mangle(uint64_t fid, unsigned char *buf, size_t buflen)
{
	static char *base36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	unsigned char *p = buf;
	int i;

	if (fid == 0)
		fid = (uint64_t)-1;

	*p++ = '~';
	for (i = 2; (i < buflen) && (fid > 0); fid /= 36, ++i)
		*p++ = base36[fid % 36];
	*p = '\0';

	return (i - 1);
}

/*
 * smb_maybe_mangled_name
 *
 * Mangled names should be valid DOS file names: less than 12 characters
 * long, contain at least one tilde character and conform to an 8.3 name
 * format.
 *
 * Returns true if the name looks like a mangled name.
 */
int
smb_maybe_mangled_name(char *name)
{
	const char *p;
	boolean_t has_tilde = B_FALSE;
	int ndots = 0;
	int i;

	for (p = name, i = 0; (*p != '\0') && (i < SMB_NAME83_LEN); i++, p++) {
		if ((strchr(special_chars, *p) != NULL) ||
		    (strchr(invalid_dos_chars, *p) != NULL))
			return (B_FALSE);

		if (*p == '.') {
			if ((++ndots) > 1)
				return (B_FALSE);
		}

		if ((*p == '~') && (i < SMB_NAME83_BASELEN))
			has_tilde = B_TRUE;

		if (*p == '.' && !has_tilde)
			return (B_FALSE);
	}

	return ((*p == 0) && has_tilde);
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
	int avail, len;
	unsigned char ch;
	unsigned char mangle_buf[SMB_NAME83_BASELEN];
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

	len = smb_generate_mangle(fileid, mangle_buf, SMB_NAME83_BASELEN);
	avail = SMB_NAME83_BASELEN - len;

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
 * in the directory entry.
 *
 * smb_unmangle_name should only be called on names for which
 * smb_maybe_mangled_name() is true
 *
 * File systems which support VFSFT_EDIRENT_FLAGS will return the
 * directory entries as a buffer of edirent_t structure. Others will
 * return a buffer of dirent64_t structures. A union is used for the
 * the pointer into the buffer (bufptr, edp and dp).
 * The ed_name/d_name is NULL terminated by the file system.
 *
 * Returns:
 *   0       - SUCCESS. Unmangled name is returned in namebuf.
 *   EINVAL  - a parameter was invalid.
 *   ENOTDIR - dnode is not a directory node.
 *   ENOENT  - an unmangled name could not be found.
 */
#define	SMB_UNMANGLE_BUFSIZE	(4 * 1024)
int
smb_unmangle_name(smb_node_t *dnode, char *name, char *namebuf,
    int buflen, uint32_t flags)
{
	int		err, eof, bufsize, reclen;
	uint64_t	offset;
	ino64_t		ino;
	boolean_t	is_edp;
	char		*namep, *buf;
	char		shortname[SMB_SHORTNAMELEN];
	char		name83[SMB_SHORTNAMELEN];
	vnode_t		*vp;
	union {
		char		*bufptr;
		edirent_t	*edp;
		dirent64_t	*dp;
	} u;
#define	bufptr	u.bufptr
#define	edp		u.edp
#define	dp		u.dp

	if (dnode == NULL || name == NULL || namebuf == NULL || buflen == 0)
		return (EINVAL);

	ASSERT(smb_maybe_mangled_name(name) != 0);

	vp = dnode->vp;
	if (vp->v_type != VDIR)
		return (ENOTDIR);

	*namebuf = '\0';
	is_edp = vfs_has_feature(vp->v_vfsp, VFSFT_DIRENTFLAGS);

	buf = kmem_alloc(SMB_UNMANGLE_BUFSIZE, KM_SLEEP);
	bufsize = SMB_UNMANGLE_BUFSIZE;
	offset = 0;

	while ((err = smb_vop_readdir(vp, offset, buf, &bufsize,
	    &eof, flags, kcred)) == 0) {
		if (bufsize == 0) {
			err = ENOENT;
			break;
		}

		bufptr = buf;
		reclen = 0;

		while ((bufptr += reclen) < buf + bufsize) {
			if (is_edp) {
				reclen = edp->ed_reclen;
				offset = edp->ed_off;
				ino = edp->ed_ino;
				namep = edp->ed_name;
			} else {
				reclen = dp->d_reclen;
				offset = dp->d_off;
				ino = dp->d_ino;
				namep = dp->d_name;
			}

			(void) smb_mangle_name(ino, namep,
			    shortname, name83, 1);

			if (utf8_strcasecmp(name, shortname) == 0) {
				(void) strlcpy(namebuf, namep, buflen);
				kmem_free(buf, SMB_UNMANGLE_BUFSIZE);
				return (0);
			}
		}

		if (eof) {
			err = ENOENT;
			break;
		}

		bufsize = SMB_UNMANGLE_BUFSIZE;
	}

	kmem_free(buf, SMB_UNMANGLE_BUFSIZE);
	return (err);
}
