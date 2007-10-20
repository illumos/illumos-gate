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

#ifndef _PMCONFIG_H
#define	_PMCONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/cpr.h>
#include <sys/pm.h>
#include <strings.h>
#include <limits.h>
#include <libintl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>


#define	LINEARG(an)		*(line_args + an)
#define	LINELEN			80
#define	MOREARGS		4

#define	ESTAR_VNONE		0
#define	ESTAR_V2		'2'
#define	ESTAR_V3		'3'

#define	LPAREN			'('
#define	RPAREN			')'

#define	MDEBUG			0
#define	MEXIT			1
#define	MERR			-1

/*
 * return values from handler routines;
 * chosen to match syscall return values
 */
#define	NOUP			-1
#define	OKUP			0

#define	DFLT_THOLD		0.04


struct perm_update {
	int	perm;			/* cpr or pm permission */
	int	update;			/* flag updates from cpr/pm data */
	char	*set;			/* "cpr" or "pm" */
};
typedef struct perm_update prmup_t;


struct cinfo {
	char	*keyword;		/* keyword string */
	int	(*handler)(void);	/* keyword handler routine */
	prmup_t	*status;		/* permission and update status */
	char	*cmt;			/* config file comment */
	short	argc;			/* config line arg count */
	uint8_t	any;			/* 0: match argc, 1: at least argc */
	uint8_t	alt;			/* conf line OK from an alt source */
};
typedef struct cinfo cinfo_t;

typedef void (*vact_t)(char *, size_t, cinfo_t *);

/* Suspend/Resume flags */
extern int whitelist_only;
extern int verify;

/*
 * "conf.c"
 */
extern prmup_t cpr_status, pm_status;
extern struct cprconfig new_cc;
extern struct stat def_info;
extern char estar_vers;
extern int pm_fd, ua_err;
extern uid_t ruid;
extern int def_src;
extern void mesg(int, char *, ...);

/*
 * "parse.c"
 */
extern int lineno;
extern char **line_args;
extern void lookup_estar_vers(void);
extern void lookup_perms(void);
extern void parse_conf_file(char *, vact_t);

/*
 * handlers.c
 */
extern int S3_helper(char *, char *, int, int, char *, char *, int *, int);
extern int S3sup(void);
extern int autoS3(void);
extern int autopm(void);
extern int autosd(void);
extern int cpupm(void);
extern int cputhr(void);
extern int ddprop(void);
extern int devdep(void);
extern int devthr(void);
extern int dreads(void);
extern int idlechk(void);
extern int loadavg(void);
extern int nfsreq(void);
extern int sfpath(void);
extern int systhr(void);
extern int tchars(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _PMCONFIG_H */
