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

#ifndef _ST_PATHNAME_H
#define	_ST_PATHNAME_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Pathname structure.
 * System calls which operate on path names gather the
 * pathname from system call into this structure and reduce
 * it by peeling off translated components.  If a symbolic
 * link is encountered the new pathname to be translated
 * is also assembled in this structure.
 */

struct st_pathname {
	char	*pn_buf;		/* underlying storage */
	char	*pn_path;		/* remaining pathname */
	uint_t	pn_pathlen;		/* remaining length */
};

#define	PN_STRIP 0x00		/* Strip next component off pn */
#define	PN_PEEK	0x01  		/* Only peek at next pn component */
#define	stpn_peekcomponent(PNP, COMP) stpn_getcomponent(PNP, COMP, PN_PEEK)
#define	stpn_stripcomponent(PNP, COMP) stpn_getcomponent(PNP, COMP, PN_STRIP)

#define	stpn_peekchar(PNP) 	(((PNP)->pn_pathlen != 0) ? \
				    *((PNP)->pn_path) : (char)0)
#define	stpn_pathleft(PNP)	((PNP)->pn_pathlen)
#define	stpn_getpath(PNP)		((PNP)->pn_path)
#define	stpn_copy(PNP1, PNP2)	(stpn_set(PNP2, stpn_getpath(PNP1)))

extern int	stpn_alloc();		/* allocate buffer for pathname */
extern int	stpn_get();		/* allocate buf and copy path into it */
extern int	stpn_set();		/* set pathname to string */
extern int	stpn_combine();		/* combine to pathnames (for symlink) */
extern int	stpn_getcomponent();	/* get next component of pathname */
extern void	stpn_skipslash();		/* skip over slashes */
extern void	stpn_free();		/* free pathname buffer */

#ifdef	__cplusplus
}
#endif

#endif /* _ST_PATHNAME_H */
