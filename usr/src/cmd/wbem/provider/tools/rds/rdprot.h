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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_RDPROT_H
#define	_RDPROT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <strings.h>
#include <sys/utsname.h>

#include "rdimpl.h"

#define	offsetof(s, m)  ((size_t)(&(((s *)0)->m)))

/* some maximal values */
#define	P_MAXLEN	80
#define	P_MAXKEY	20
#define	P_MAXVAL	59
#define	MAX_RETRIES 	20

/* Tags definitions */

#define	PROTM "@RDS-MAG@"
#define	RDERR "RDERR"
#define	PROTV "PROTV"
#define	LISTT "LISTT"
#define	LISTN "LISTN"
#define	ELEMN "ELEMN"
#define	ELMID "ELMID"
#define	FILDN "FILDN"
#define	PROMPT "@RDS@>"
#define	PROMPT_OK ""
#define	PROMPT_WHAT " ?"
#define	CRETURN		"\n"

#define	PROT_VERSION 100

/* list types */
#define	L_PRC_SI 1
#define	L_USR_SI 2
#define	L_PRJ_SI 3
#define	L_AC_USR 4
#define	L_AC_PRJ 5
#define	L_SYSTEM 6
#define	L_LWP	 8
#define	L_LWP__I 9
#define	L_LWP__U 10

#define	CMD_EMPTY 0
#define	CMD_GETALL   	"-pUuJjS"
#define	CMD_GETPL	"-p"
#define	CMD_GETUL	"-u"
#define	CMD_GETAUL	"-U"
#define	CMD_GETJL	"-j"
#define	CMD_GETAJL	"-J"
#define	CMD_GETASL	"-S"
#define	CMD_SETINTERVAL "-i100"
#define	CMD_ALIVE 	"alive"
#define	CMD_EXIT  	"exit"

extern int open_prot(int fd, char *rw);
extern void close_prot(void);
extern void wr_error(char *err);
extern int wr_phead(void);
extern int wr_lshead(int n);
extern int wr_lhead(int type, int n);
extern int wr_element(int stubidx, char *src, char *elemid);
extern int wr_ctrl(int code);
extern int wr_prompt(char *code);
extern int wr_string(char *code);
extern int wr_value(char *key, int64_t v);
extern int skip_line(void);
extern int r_phead(void);
extern int r_lshead();
extern int r_lhead(int *type);
extern int r_element(char *src, char *elemid);
extern int64_t r_value(char *key);
extern int r_ctrl(void);
extern char *r_cmd(void);

extern char rderr[];

typedef struct {
	int (* format)(int, char *, char *, int);
	size_t   off;
} info_t;

typedef struct {
	char *key;
	info_t info;
} kv_pair_t;

typedef struct {
	int size;
	kv_pair_t *stub;
} stub_t;

typedef struct {
	int32_t pr_pid;
	int32_t pr_lwpid;
	int32_t pr_pctcpu;
	int64_t	pr_time_tv_sec;
	int64_t	pr_time_tv_nsec;
	int32_t pr_bindpset;
} lwpinfo_t;

typedef struct {
	int command;
} cmd_t;

#ifdef	__cplusplus
}
#endif

#endif /* _RDPROT_H */
