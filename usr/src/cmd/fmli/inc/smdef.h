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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.6 */

struct atom {
	struct atom		*next;
	char			*address;
	char			*info;
};

struct supalias {
	int spec;
	int where;
	char *lname;
	char *fname;
	struct atom *atom_list;
	struct supalias *next;
	struct supalias *pre;
};

#define ATOM		struct atom
#define SEPARATOR	':'
#define SEMI		';'
#define MAXADDRS	1024

#ifndef TYPE_BOOL
/* curses.h also  does a typedef bool */
#ifndef _CURSES_H
#define TYPE_BOOL
typedef char          bool;
#endif
#endif

#ifndef TRUE
#define TRUE		1
#define FALSE		0
#endif
#define SUBJECT 1
#define ADDRS 2
#define NOSTORE 4
#define EDITED 8
#define CALL 16
#define READIN 32
#define AUTOSEND 64

#define alloc(Q)	(Q *) calloc(1, sizeof(Q))

#define SEPLINE ":::::::::::::::::::::::::::::::::::::::::::::::"
/*#define EPICSEND 1*/
/*#define POSTSEND 0*/
#define TO 1				/* TO field */
#define CC 2				/* CC field */
#define BEGIN	1
#define NEXT	2
#define PRV	3
#define	PNUM	4
/*#define EMPFAIL -1*/
#define CALLMEMO 0
#define SENDMAIL 1
#define CALENDAR 2
#define FIND 3
#define REPLY 1
#define RET_RECEIPT 2
#define	MAXSUB		300
#define MAXATTS	10
struct msg_head {	/* message header structure */
	char *filename;
	char *linkname;
	FILE *fp;
	struct supalias to[1];
	struct supalias cc[1];
	struct supalias bc[1];
	char subj[MAXSUB];
	char *msg_type;
	struct oeh atts[MAXATTS];
	int noatts;
	char *phone;
	char *mark;
	char *caller;
	int rec;
	char *mailto;
	char *paperto;
	char *replyid;
	time_t send_time;	/* EFT abs k16 */
	int flag;
	int attlen;
	int annot;
};
/* "No send" codes */
#define NS_ADDR		0
#define NS_ATTACH	1
#define NS_MSG		2
#define NS_GEN		3
struct addrlist {
	char *name;
	char *line2;
	char *address;
	bool pick_flg;
};
