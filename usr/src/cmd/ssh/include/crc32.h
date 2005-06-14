/*	$OpenBSD: crc32.h,v 1.13 2002/03/04 17:27:39 stevesk Exp $	*/

#ifndef	_CRC32_H
#define	_CRC32_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1992 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for computing 32-bit CRC.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

u_int	 ssh_crc32(const u_char *, u_int);

#ifdef __cplusplus
}
#endif

#endif /* _CRC32_H */
