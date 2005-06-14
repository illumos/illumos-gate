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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CFGA_SBD_H
#define	_CFGA_SBD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	DEVDIR	"/devices"

#ifdef	SBD_DEBUG
#define	DBG	dbg
void dbg(char *, ...);
#else
#define	DBG
#endif

typedef struct {
	int flags;
	int code;
	char *mid;
	char *platform;
	int skip;
	int err;
} ap_opts_t;

/*
 * Command options.
 *
 * Some of the options are provided for testing purpose and
 * will not published (e.g. err,code,mid).
 */
#define	OPT_UNASSIGN		0
#define	OPT_SKIP		1
#define	OPT_PARSABLE		2
#define	OPT_NOPOWEROFF		3
#define	OPT_CODE		4
#define	OPT_MID			5
#define	OPT_ERR			6
#define	OPT_PLATFORM		7
#define	OPT_SIM			8
#define	OPT_SUSPEND_OK		9
#define	OPT_LIST_ALL		29
#define	OPT_FORCE		30
#define	OPT_VERBOSE		31

#define	ap_getopt(a, o)	((a)->opts.flags &  ((uint_t)1 << (o)))
#define	ap_setopt(a, o)	((a)->opts.flags |= ((uint_t)1 << (o)))

typedef enum {
	AP_NONE = 0,
	AP_BOARD,
	AP_CPU,
	AP_MEM,
	AP_IO,
	AP_CMP
} ap_target_t;

#define	AP_NCLASS	6

/*
 * Attachment point descriptor.
 *
 * All commands are processed as follows:
 *
 * . allocate a command descriptor
 * . parse the physical ap_id
 * . parse the command and its options.
 * . sequence if necessary (state change commands)
 * . execute
 *
 */
typedef struct {
	int fd;
	int bnum;
	int cnum;
	int ncm;
	int inst;
	int norcm;
	int statonly;
	const char *class;
	const char *apid;
	char *drv;
	char *path;
	char *target;
	char *minor;
	char *cid;
	char *cname;
	char *options;
	char **errstring;
	ap_opts_t opts;
	ap_target_t tgt;
	struct cfga_msg *msgp;
	struct cfga_confirm *confp;
	void *ctl;
	void *stat;
	void *cmstat;
	void *rcm;
} apd_t;

/*
 * Command definitions.
 *
 * The command order is significant.  The sequenced (-c) commands
 * are sorted in execution order. The configure command starts from
 * assign and ends with online.  The disconnect command starts
 * from offline and goes to unassign.  Steps in the sequencing may
 * be optionally skipped.
 */
#define	CMD_ASSIGN		0
#define	CMD_POWERON		1
#define	CMD_TEST		2
#define	CMD_CONNECT		3
#define	CMD_CONFIGURE		4
#define	CMD_RCM_ONLINE		5
#define	CMD_RCM_CAP_ADD		6
#define	CMD_SUSPEND_CHECK	7
#define	CMD_RCM_SUSPEND		8
#define	CMD_RCM_CAP_DEL		9
#define	CMD_RCM_OFFLINE		10
#define	CMD_UNCONFIGURE		11
#define	CMD_RCM_REMOVE		12
#define	CMD_RCM_CAP_NOTIFY	13
#define	CMD_DISCONNECT		14
#define	CMD_POWEROFF		15
#define	CMD_UNASSIGN		16
#define	CMD_RCM_RESUME		17
#define	CMD_STATUS		18
#define	CMD_GETNCM		19
#define	CMD_PASSTHRU		20
#define	CMD_HELP		21
#define	CMD_ERRTEST		22
#define	CMD_NONE		23

/*
 * Error messages.
 */
#define	ERR_CMD_INVAL		0
#define	ERR_CMD_FAIL		1
#define	ERR_CMD_NACK		2
#define	ERR_CMD_NOTSUPP		3
#define	ERR_CMD_ABORT		4
#define	ERR_OPT_INVAL		5
#define	ERR_OPT_NOVAL		6
#define	ERR_OPT_VAL		7
#define	ERR_OPT_BADVAL		8
#define	ERR_AP_INVAL		9
#define	ERR_CM_INVAL		10
#define	ERR_TRANS_INVAL		11
#define	ERR_SIG_CHANGE		12
#define	ERR_RCM_HANDLE		13
#define	ERR_RCM_CMD		14
#define	ERR_RCM_INFO		15
#define	ERR_LIB_OPEN		16
#define	ERR_LIB_SYM		17
#define	ERR_STAT		18
#define	ERR_NOMEM		19
#define	ERR_PLUGIN		20
#define	ERR_NONE		21

#define	MSG_ISSUE		0
#define	MSG_SKIP		1
#define	MSG_SUSPEND		2
#define	MSG_ABORT		3
#define	MSG_DONE		4
#define	MSG_FAIL		5
#define	MSG_NORCM		6
#define	MSG_NONE		7

#define	s_free(x)	(((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)
#define	str_valid(p)	((p) != NULL && *(p) != '\0')
#define	mask(x)		((uint_t)1 << (x))

#define	CM_DFLT		-1	/* default (current) component */

int ap_cnt(apd_t *);
int ap_parse(apd_t *, const char *);
int ap_confirm(apd_t *);
int ap_state_cmd(cfga_cmd_t, int *);
int ap_symid(apd_t *, char *, char *, size_t);
char *ap_sys_err(apd_t *, char **);
char *ap_cmd_name(int);
char *ap_opt_name(int);
char *ap_logid(apd_t *, char *);
void ap_err(apd_t *, ...);
void ap_msg(apd_t *, ...);
void ap_info(apd_t *, cfga_info_t, ap_target_t);
void ap_init(apd_t *, cfga_list_data_t *);
void ap_state(apd_t *, cfga_stat_t *, cfga_stat_t *);
cfga_err_t ap_stat(apd_t *a, int);
cfga_err_t ap_ioctl(apd_t *, int);
cfga_err_t ap_help(struct cfga_msg *, const char *, cfga_flags_t);
cfga_err_t ap_cmd_exec(apd_t *, int);
cfga_err_t ap_cmd_seq(apd_t *, int);
cfga_err_t ap_suspend_query(apd_t *, int, int *);
cfga_err_t ap_platopts_check(apd_t *, int, int);
cfga_err_t ap_cmd_parse(apd_t *, const char *, const char *, int *);
cfga_err_t ap_test_err(apd_t *, const char *);

int ap_cm_capacity(apd_t *, int, void *, int *, cfga_stat_t *);
int ap_cm_ncap(apd_t *, int);
void ap_cm_id(apd_t *, int, char *, size_t);
void ap_cm_init(apd_t *, cfga_list_data_t *, int);
char *ap_cm_devpath(apd_t *, int);
ap_target_t ap_cm_type(apd_t *, int);

cfga_err_t ap_rcm_init(apd_t *);
void ap_rcm_fini(apd_t *);
cfga_err_t ap_rcm_ctl(apd_t *, int);
int ap_rcm_info(apd_t *, char **);

apd_t *apd_alloc(const char *, cfga_flags_t, char **,
	struct cfga_msg *, struct cfga_confirm *);
void apd_free(apd_t *a);
cfga_err_t apd_init(apd_t *, int);

int debugging();

#ifdef __cplusplus
}
#endif

#endif	/* _CFGA_SBD_H */
