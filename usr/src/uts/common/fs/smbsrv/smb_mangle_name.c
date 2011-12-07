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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <smbsrv/string.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>

/*
 * Characters we don't allow in DOS file names.
 * If a filename contains any of these chars, it should get mangled.
 *
 * '.' is also an invalid DOS char but since it's a special
 * case it doesn't appear in the list.
 */
static const char invalid_dos_chars[] =
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
static const char special_chars[] = "[];=,+";

#define	isinvalid(c)	(strchr(invalid_dos_chars, c) || (c & 0x80))

static int smb_generate_mangle(uint64_t, char *, size_t);
static char smb_mangle_char(char);

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
boolean_t
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

	ch = smb_toupper(*name);

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

		if (smb_strcasecmp(reserved[i], name, len) == 0) {
			ch = *(name + len);
			if ((ch == '\0') || (ch == '.'))
				return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * smb_needs_mangled
 *
 * A name needs to be mangled if any of the following are true:
 * - the first character is dot (.) and the name is not "." or ".."
 * - the name contains illegal or special charsacter
 * - the name name length > 12
 * - the number of dots == 0 and length > 8
 * - the number of dots > 1
 * - the number of dots == 1 and name is not 8.3
 */
boolean_t
smb_needs_mangled(const char *name)
{
	int len, extlen, ndots;
	const char *p;
	const char *last_dot;

	if ((strcmp(name, ".") == 0) || (strcmp(name, "..") == 0))
		return (B_FALSE);

	if (*name == '.')
		return (B_TRUE);

	len = 0;
	ndots = 0;
	last_dot = NULL;
	for (p = name; *p != '\0'; ++p) {
		if (smb_iscntrl(*p) ||
		    (strchr(special_chars, *p) != NULL) ||
		    (strchr(invalid_dos_chars, *p)) != NULL)
			return (B_TRUE);

		if (*p == '.') {
			++ndots;
			last_dot = p;
		}
		++len;
	}

	if ((len > SMB_NAME83_LEN) ||
	    (ndots == 0 && len > SMB_NAME83_BASELEN) ||
	    (ndots > 1)) {
		return (B_TRUE);
	}

	if (last_dot != NULL) {
		extlen = strlen(last_dot + 1);
		if ((extlen == 0) || (extlen > SMB_NAME83_EXTLEN))
			return (B_TRUE);

		if ((len - extlen - 1) > SMB_NAME83_BASELEN)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * smb_mangle_char
 *
 * If c is an invalid DOS character or non-ascii, it should
 * not be used in the mangled name. We return -1 to indicate
 * an invalid character.
 *
 * If c is a special chars, it should be replaced with '_'.
 *
 * Otherwise c is returned as uppercase.
 */
static char
smb_mangle_char(char c)
{
	if (isinvalid(c))
		return (-1);

	if (strchr(special_chars, c))
		return ('_');

	return (smb_toupper(c));
}

/*
 * smb_generate_mangle
 *
 * Generate a mangle string containing at least 2 characters and
 * at most (buflen - 1) characters.
 *
 * Returns the number of chars in the generated mangle.
 */
static int
smb_generate_mangle(uint64_t fid, char *buf, size_t buflen)
{
	static char *base36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char *p = buf;
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
 * smb_maybe_mangled
 *
 * Mangled names should be valid DOS file names: less than 12 characters
 * long, contain at least one tilde character and conform to an 8.3 name
 * format.
 *
 * Returns true if the name looks like a mangled name.
 */
boolean_t
smb_maybe_mangled(char *name)
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

	return ((*p == '\0') && has_tilde);
}

/*
 * smb_mangle
 *
 * Microsoft knowledge base article #142982 describes how Windows
 * generates 8.3 filenames from long file names. Some other details
 * can be found in article #114816.
 *
 * This function will mangle the name whether mangling is required
 * or not. Callers should use smb_needs_mangled() to determine whether
 * mangling is required.
 *
 * name		original file name
 * fid		inode number to generate unique mangle
 * buf		output buffer (buflen bytes) to contain mangled name
 */
void
smb_mangle(const char *name, ino64_t fid, char *buf, size_t buflen)
{
	int i, avail;
	const char *p;
	char c;
	char *pbuf;
	char mangle_buf[SMB_NAME83_BASELEN];

	ASSERT(name && buf && (buflen >= SMB_SHORTNAMELEN));

	avail = SMB_NAME83_BASELEN -
	    smb_generate_mangle(fid, mangle_buf, SMB_NAME83_BASELEN);
	name += strspn(name, ".");

	/*
	 * Copy up to avail characters from the base part of name
	 * to buf then append the generated mangle string.
	 */
	p = name;
	pbuf = buf;
	for (i = 0; (i < avail) && (*p != '\0') && (*p != '.'); ++i, ++p) {
		if ((c = smb_mangle_char(*p)) == -1)
			continue;
		*pbuf++ = c;
	}
	*pbuf = '\0';
	(void) strlcat(pbuf, mangle_buf, SMB_NAME83_BASELEN);
	pbuf = strchr(pbuf, '\0');

	/*
	 * Find the last dot in the name. If there is a dot and an
	 * extension, append '.' and up to SMB_NAME83_EXTLEN extension
	 * characters to the mangled name.
	 */
	if (((p = strrchr(name, '.')) != NULL) && (*(++p) != '\0')) {
		*pbuf++ = '.';
		for (i = 0; (i < SMB_NAME83_EXTLEN) && (*p != '\0'); ++i, ++p) {
			if ((c = smb_mangle_char(*p)) == -1)
				continue;
			*pbuf++ = c;
		}
	}

	*pbuf = '\0';
}

/*
 * smb_unmangle
 *
 * Given a mangled name, try to find the real file name as it appears
 * in the directory entry.
 *
 * smb_unmangle should only be called on names for which
 * smb_maybe_mangled() is true
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
smb_unmangle(smb_node_t *dnode, char *name, char *namebuf,
    int buflen, uint32_t flags)
{
	int		err, eof, bufsize, reclen;
	uint64_t	offset;
	ino64_t		ino;
	boolean_t	is_edp;
	char		*namep, *buf;
	char		shortname[SMB_SHORTNAMELEN];
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

	ASSERT(smb_maybe_mangled(name) == B_TRUE);

	if (!smb_node_is_dir(dnode))
		return (ENOTDIR);

	vp = dnode->vp;
	*namebuf = '\0';
	is_edp = vfs_has_feature(vp->v_vfsp, VFSFT_DIRENTFLAGS);

	buf = kmem_alloc(SMB_UNMANGLE_BUFSIZE, KM_SLEEP);
	bufsize = SMB_UNMANGLE_BUFSIZE;
	offset = 0;

	while ((err = smb_vop_readdir(vp, offset, buf, &bufsize,
	    &eof, flags, zone_kcred())) == 0) {
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

			/* skip non utf8 filename */
			if (u8_validate(namep, strlen(namep), NULL,
			    U8_VALIDATE_ENTIRE, &err) < 0)
				continue;

			smb_mangle(namep, ino, shortname, SMB_SHORTNAMELEN);

			if (smb_strcasecmp(name, shortname, 0) == 0) {
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
