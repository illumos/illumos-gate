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
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MISC_H
#define	_MISC_H

/*	$OpenBSD: misc.h,v 1.12 2002/03/19 10:49:35 markus Exp $	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

char	*chop(char *);
char	*strdelim(char **);
void	 set_nonblock(int);
void	 unset_nonblock(int);
void	 set_nodelay(int);
int	 a2port(const char *);
char	*cleanhostname(char *);
char	*colon(char *);
long	 convtime(const char *);
char	*tohex(const void *, size_t);
void	 sanitise_stdfd(void);
int	 get_yes_no_flag(int *option, const char *arg, const char *filename,
		    int linenum, int active);

struct passwd	*pwcopy(struct passwd *);
void		 pwfree(struct passwd **);

typedef struct arglist arglist;
struct arglist {
	char    **list;
	int     num;
	int     nalloc;
};
void	 addargs(arglist *, char *, ...) __attribute__((format(printf, 2, 3)));
void	 replacearg(arglist *, u_int, char *, ...)
	     __attribute__((format(printf, 3, 4)));
void	 freeargs(arglist *);

/* wrapper for signal interface */
typedef void (*mysig_t)(int);
mysig_t mysignal(int sig, mysig_t act);

/* Functions to extract or store big-endian words of various sizes */
u_int64_t	get_u64(const void *)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
u_int32_t	get_u32(const void *)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
u_int16_t	get_u16(const void *)
    __attribute__((__bounded__( __minbytes__, 1, 2)));
void		put_u64(void *, u_int64_t)
    __attribute__((__bounded__( __minbytes__, 1, 8)));
void		put_u32(void *, u_int32_t)
    __attribute__((__bounded__( __minbytes__, 1, 4)));
void		put_u16(void *, u_int16_t)
    __attribute__((__bounded__( __minbytes__, 1, 2)));

#ifdef __cplusplus
}
#endif

#endif /* _MISC_H */
