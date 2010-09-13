/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 1.3 */

/*LINTLIBRARY*/
/* The real crypt is now _crypt.  This version performs automatic
 * authentication via pwauth for special password entries, or simply
 * calls _crypt for the usual case.
 */

char *
crypt(pw, salt)
char	*pw, *salt;
{
	static char *iobuf;
	extern char *_crypt();
	extern char *malloc();

	if (iobuf == 0) {
		iobuf = malloc((unsigned)16);
		if (iobuf == 0)
			return (0);
	}
	/* handle the case where the password is really in passwd.adjunct.
	 * In this case, the salt will start with "##".  We should call
	 * passauth to determine if pw is valid.  If so, we should return
	 * the salt, and otherwise return NULL.  If salt does not start with
	 * "##", crypt will act in the normal fashion.
	 */
	if (salt[0] == '#' && salt[1] == '#') {
		if (pwdauth(salt+2, pw) == 0)
			strcpy(iobuf, salt);
		else
			iobuf[0] = '\0';
		return(iobuf);
	}
	/* handle the case where the password is really in group.adjunct.
	 * In this case, the salt will start with "#$".  We should call
	 * grpauth to determine if pw is valid.  If so, we should return
	 * the salt, and otherwise return NULL.  If salt does not start with
	 * "#$", crypt will act in the normal fashion.
	 */
	if (salt[0] == '#' && salt[1] == '$') {
		if (grpauth(salt+2, pw) == 0)
			strcpy(iobuf, salt);
		else
			iobuf[0] = '\0';
		return(iobuf);
	}
	return (_crypt(pw, salt));
}
