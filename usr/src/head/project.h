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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _PROJECT_H
#define	_PROJECT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PROJF_PATH	"/etc/project"	/* pathname of the "project" file */
#define	PROJNAME_MAX	64		/* maximum project name size */
#define	PROJECT_BUFSZ	4096		/* default buffer size */

#define	SETPROJ_ERR_TASK	(-1)	/* error creating new task */
#define	SETPROJ_ERR_POOL	(-2)	/* error binding to pool */

struct project {
	char	*pj_name;	/* name of the project */
	projid_t pj_projid;	/* numerical project id */
	char	*pj_comment;	/* project description */
	char	**pj_users;	/* vector of pointers to project user names */
	char	**pj_groups;	/* vector of pointers to project group names */
	char	*pj_attr;	/* project attributes string */
};

extern void setprojent(void);
extern void endprojent(void);
extern struct project *getprojent(struct project *, void *, size_t);
extern struct project *getprojbyname(const char *,
    struct project *, void *, size_t);
extern struct project *getprojbyid(projid_t, struct project *, void *, size_t);
extern struct project *getdefaultproj(const char *,
    struct project *, void *, size_t);
extern struct project *fgetprojent(FILE *, struct project *, void *, size_t);
extern int inproj(const char *, const char *, void *, size_t);
extern projid_t getprojidbyname(const char *);

extern projid_t getprojid(void);

extern projid_t setproject(const char *, const char *, int);
extern int project_walk(int (*)(projid_t, void *), void *);

#ifdef	__cplusplus
}
#endif

#endif /* _PROJECT_H */
