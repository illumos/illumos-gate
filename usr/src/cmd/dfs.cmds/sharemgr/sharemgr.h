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

#ifndef _SHAREMGR_H
#define	_SHAREMGR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif
#include <libshare.h>

/*
 * shareadm internal interfaces
 */

typedef enum {
	USAGE_ADD_SHARE,
	USAGE_CREATE,
	USAGE_DELETE,
	USAGE_DISABLE,
	USAGE_ENABLE,
	USAGE_LIST,
	USAGE_MOVE_SHARE,
	USAGE_REMOVE_SHARE,
	USAGE_SET,
	USAGE_SET_SECURITY,
	USAGE_SET_SHARE,
	USAGE_SHOW,
	USAGE_SHARE,
	USAGE_START,
	USAGE_STOP,
	USAGE_UNSET,
	USAGE_UNSET_SECURITY,
	USAGE_UNSHARE
} sa_usage_t;

/* sharectl specific usage message values */
typedef enum {
	USAGE_CTL_GET,
	USAGE_CTL_SET,
	USAGE_CTL_STATUS,
	USAGE_CTL_DELSECT
} sc_usage_t;

typedef struct sa_command {
	char	*cmdname;
	int	flags;
	int	(*cmdfunc)(sa_handle_t, int, int, char **);
	int	cmdidx;
	int	priv;	/* requires RBAC authorizations */
} sa_command_t;

#define	CMD_ALIAS	0x0001
#define	CMD_NODISPLAY	0x0002	/* don't display command */

#define	SVC_AUTH_VALUE	"value_authorization"
#define	SVC_AUTH_ACTION	"action_authorization"
#define	SVC_SET		0x01 /* need value permissions */
#define	SVC_ACTION	0x02 /* need action permissions */

#define	ZFS_SHAREALL	"/usr/sbin/zfs share -a nfs"

/*
 * functions/values for manipulating options
 */
#define	OPT_ADD_OK		0
#define	OPT_ADD_SYNTAX		-1
#define	OPT_ADD_SECURITY	-2
#define	OPT_ADD_PROPERTY	-3
#define	OPT_ADD_MEMORY		-4

/* option list structure */
struct options {
	struct options *next;
	char *optname;
	char *optvalue;
};

/* general list structure */
struct list {
	struct list *next;
	void *item;
	void *itemdata;
	char *proto;
};

/* shareutil entry points */
extern int add_opt(struct options **, char *, int);


#ifdef	__cplusplus
}
#endif

#endif /* _SHAREMGR_H */
