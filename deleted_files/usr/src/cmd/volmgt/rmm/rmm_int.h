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
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef __RMM_INT_H
#define	__RMM_INT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/types.h>
#include <regex.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct ident_list {
	char	*i_type;		/* name of file system */
	char	*i_dsoname;		/* name of the shared object */
	char	**i_media;		/* list of appropriate media */
	bool_t	(*i_ident)(int, char *, int *, int);
};


#define	A_PREMOUNT	0x01	/* execute action before mounting */

struct action_list {
	int		a_flag;		/* behavior flag */
	char		*a_dsoname;	/* name of the shared object */
	char		*a_media;	/* appropriate media */
	int		a_argc;		/* argc of action arg list */
	char		**a_argv;	/* argv of action arg list */
	bool_t		(*a_action)(struct action_arg **, int, char **);
};


/* "mount" fs types (go in ma_key) */
#define	MA_UFS		0x1000
#define	MA_HSFS		0x2000
#define	MA_PCFS		0x4000
#define	MA_UDFS		0x8000

#define	MA_FS_ANY	(MA_UFS|MA_HSFS|MA_PCFS|MA_UDFS) /* all FS(s) */


/* command keys (go in ma_key) */
#define	MA_FSCK		0x010
#define	MA_MOUNT	0x020
#define	MA_SHARE	0x040

#define	MA_CMD_MASK	(MA_FSCK|MA_MOUNT|MA_SHARE)

/* command flags (go in ma_key) */
#define	MA_READONLY	0x001	/* mount readonly (default is rw) */

struct mount_args {
	char	*ma_namere;	/* regular expression */
	regex_t	ma_re;		/* compiled regular expression */
	u_int	ma_key;		/* command flags */
	char	*ma_options;	/* command options */
};

extern char	*rmm_dsodir;	/* directory for DSO */
extern char	*rmm_config;	/* config file path */
extern int	rmm_debug;	/* debug flag */

extern char	*prog_name;	/* name of the program */
extern pid_t	prog_pid;	/* pid of the program */

extern struct ident_list 	**ident_list;
extern struct action_list 	**action_list;
extern struct mount_args	**cmd_args[3];

/*
 * command indices
 * These are just convenient labels for the indices of the mount_args
 * data type.  The values must be consistent with the declaration of
 * mount_args, so any changes must be coordinated with changes to that
 * type.
 */
#define	CMD_FSCK	0
#define	CMD_MOUNT	1
#define	CMD_SHARE	2

void			*dso_load(char *, char *, int);
void			dprintf(const char *fmt, ...);
char			*rawpath(char *);
void			config_read(void);
char			*sh_to_regex(char *);
char			*getmntpoint(char *);
int			makepath(char *, mode_t);
bool_t			fs_supported(char *, struct mount_args *);
void			get_mountpath(char *, char *, char *);

#define	MAX_ARGC	300
#define	MAX_IDENTS	100
#define	MAX_ACTIONS	500
#define	MAX_MOUNTS	100

#define	NULLC		'\0'

#ifdef	__cplusplus
}
#endif

#endif /* __RMM_INT_H */
