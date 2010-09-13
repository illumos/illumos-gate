/*	$OpenBSD: readpass.h,v 1.7 2002/03/26 15:58:46 markus Exp $	*/

#ifndef	_READPASS_H
#define	_READPASS_H

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS          0x0008

char	*read_passphrase(const char *, int);
int	ask_permission(const char *, ...)
    __attribute__((format(printf, 1, 2)));
int	read_keyfile_line(FILE *, const char *, char *, size_t, u_long *);

#ifdef __cplusplus
}
#endif

#endif /* _READPASS_H */
