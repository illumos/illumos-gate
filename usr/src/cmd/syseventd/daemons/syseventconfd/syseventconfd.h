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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYSEVENTCONFD_H
#define	_SYSEVENTCONFD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * debug levels
 */
#define	DBG_EXEC	1	/* path and args for each fork/exec */
#define	DBG_EVENTS	2	/* received events */
#define	DBG_CHILD	3	/* child exit status */
#define	DBG_EXEC_ARGS	4	/* more detail on exec args */


/*
 * list of cmds received from syseventd/sysevent_conf_mod
 */
struct cmd {
	nvlist_t	*cmd_nvlist;
	struct cmd	*cmd_next;
	struct cmd	*cmd_taiL;
};


/*
 * Structures for building arbitarily long strings and argument lists
 */
typedef struct arg {
	char	**arg_args;
	int	arg_nargs;
	int	arg_alloc;
	int	arg_hint;
} arg_t;

typedef struct str {
	char	*s_str;
	int	s_len;
	int	s_alloc;
	int	s_hint;
} str_t;


/*
 * Prototypes
 */
static void event_handler(sysevent_t *event);
static void exec_cmd(struct cmd *cmd);
static void sigwait_thr(void);
static void reapchild(int sig);
static void flt_handler(int sig);
static void syserrmsg(char *message, ...);
static void printmsg(int level, char *message, ...);
static void set_root_dir(char *dir);
static void usage(void);
static arg_t *init_arglist(int hint);
static void free_arglist(arg_t *arglist);
static int add_arg(arg_t *arglist, char *arg);
static char *next_arg(char **cpp);
static struct cmd *alloc_cmd(nvlist_t *nvlist);
static void free_cmd(struct cmd *cmd);
static void *sc_malloc(size_t n);
static void *sc_realloc(void *p, size_t n);
static sysevent_handle_t *open_channel(void);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYSEVENTCONFD_H */
