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

#ifndef	_MISC_H
#define	_MISC_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains declarations pertaining to the miscellaneous routines.
 */
#include <setjmp.h>
#include <termios.h>

/*
 * Define macros bzero and bcopy for convenience
 */
#ifndef	bzero
#define	bzero(p, n)		(void) memset((p), 0, (n))
#endif
#ifndef	bcopy
#define	bcopy(src, dst, n)	(void) memcpy((dst), (src), (n))
#endif
#ifndef	bcmp
#define	bcmp(p1, p2, n)		memcmp((p1), (p2), (n))
#endif

/*
 * Minimum and maximum macros
 */
#ifndef min
#define	min(x, y)	((x) < (y) ? (x) : (y))
#endif	/* min */
#ifndef max
#define	max(x, y)	((x) > (y) ? (x) : (y))
#endif	/* max */

/*
 * This defines the structure of a saved environment.  It consists of the
 * environment itself, a pointer to the next environment on the stack, and
 * flags to tell whether the environment is active, etc.
 */
struct env {
	jmp_buf env;				/* environment buf */
	struct	env *ptr;			/* ptr to next on list */
	char	flags;				/* flags */
};
extern	struct env *current_env;
/*
 * This macro saves the current environment in the given structure and
 * pushes the structure onto our enivornment stack.  It initializes the
 * flags to zero (inactive).
 */
#define	saveenv(x)	{ \
			x.ptr = current_env; \
			current_env = &x; \
			(void) setjmp(x.env); \
			x.flags = 0; \
			}
/*
 * This macro marks the environment on the top of the stack active.  It
 * assumes that there is an environment on the stack.
 */
#define	useenv()	(current_env->flags |= ENV_USE)
/*
 * This macro marks the environment on the top of the stack inactive.  It
 * assumes that there is an environment on the stack.
 */
#define	unuseenv()	(current_env->flags &= ~ENV_USE)
/*
 * This macro pops an environment off the top of the stack.  It
 * assumes that there is an environment on the stack.
 */
#define	clearenv()	(current_env = current_env->ptr)
/*
 * These are the flags for the environment struct.
 */
#define	ENV_USE		0x01			/* active */
#define	ENV_CRITICAL	0x02			/* in critical zone */
#define	ENV_ABORT	0x04			/* abort pending */

/*
 * This structure is used to keep track of the state of the tty.  This
 * is necessary because some of the commands turn off echoing.
 */
struct ttystate {
	struct termios	ttystate;		/* buffer for ioctls */
	int		ttyflags;		/* changes to tty state */
	int		ttyfile;		/* file for ioctls */
	int		vmin;			/* min read satisfier */
	int		vtime;			/* read timing */
};

/*
 * ttyflags - changes we can make to the tty state.
 */
#define	TTY_ECHO_OFF	0x01			/* turned echo off */
#define	TTY_CBREAK_ON	0x02			/* turned cbreak on */

/*
 * This is the number lines assumed for the tty.  It is designed to work
 * on terminals as well as sun monitors.
 */
#define	TTY_LINES	24

/*
 * format parameter to dump()
 */
#define	HEX_ONLY	0			/* print hex only */
#define	HEX_ASCII	1			/* hex and ascii */


/*
 *	Prototypes for ANSI C
 */
void	*zalloc(int count);
void	*rezalloc(void *ptr, int count);
void	destroy_data(char *data);
int	check(char *question);
void	cmdabort(int sig);
void	onsusp(int sig);
void	onalarm(int sig);
void	fullabort(void) __NORETURN;
void	enter_critical(void);
void	exit_critical(void);
void	echo_off(void);
void	echo_on(void);
void	charmode_on(void);
void	charmode_off(void);
char	*alloc_string(char *s);
char	**build_argvlist(char **, int *, int *, char *);
int	conventional_name(char *name);

#if defined(_FIRMWARE_NEEDS_FDISK)
int	fdisk_physical_name(char *name);
#endif	/* defined(_FIRMWARE_NEEDS_FDISK) */

int	whole_disk_name(char *name);
int	canonical_name(char *name);
int	canonical4x_name(char *name);
void	canonicalize_name(char *dst, char *src);
int	match_substr(char *s1, char *s2);
void	dump(char *, caddr_t, int, int);
float	bn2mb(uint64_t);
diskaddr_t	mb2bn(float);
float	bn2gb(uint64_t);
float	bn2tb(uint64_t);
diskaddr_t	gb2bn(float);
int	get_tty_lines();


/*
 * Macro to handle internal programming errors that
 * should "never happen".
 */
#define	impossible(msg)	{err_print("Internal error: file %s, line %d: %s\n", \
				__FILE__, __LINE__, msg); \
			fullabort(); }


extern	char	*confirm_list[];

/*
 * This defines the size of the blind selection verfication prompt
 */

#define	BLIND_SELECT_VER_PROMPT	(43 + MAXNAMELEN)

#ifdef	__cplusplus
}
#endif

#endif	/* _MISC_H */
