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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 */

#ifndef	_INC_H
#define	_INC_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <time.h>
#include <locale.h>
#include <ar.h>
#include <libelf.h>
#include "sgs.h"
#include "msg.h"

#define	CHUNK		500
#define	SYMCHUNK	1000
#define	SNAME		16
#define	ROUNDUP(x)	(((x) + 1) & ~1)

#define	DATESIZE	60	 /*  sizeof (struct ar_hdr)  */

typedef struct arfile ARFILE;
typedef ARFILE *ARFILEP;

/*
 * Per-member state, help on listhead/listend list.
 */
struct arfile {
	char		ar_name[SNAME];	/* info from archive member header */
	time_t		ar_date;
	int		ar_uid;
	int		ar_gid;
	unsigned long	ar_mode;
	size_t		ar_size;
	char    	*ar_longname;
	char    	*ar_rawname;
	Elf 		*ar_elf;	/* My elf descriptor */
	char		*ar_pathname;
	char		*ar_contents;
	size_t		ar_offset;	/* The member offset */
	unsigned char	ar_flag;
	unsigned char	ar_padding;	/* # padding bytes following data */
	ARFILE		*ar_next;	/* Next member in linked list or NULL */
};

/*
 * Command function. There is one of these for each operation
 * ar can perform (r, x, etc).
 */
struct cmd_info;
typedef void Cmd_func(struct cmd_info *);

/* Command information block */
typedef struct cmd_info {
	char		*arnam;		/* Archive file name */
	int		afd;		/* fd for the archive file */
	Elf		*arf;		/* Elf descriptor for the archive */
	char		*ponam;		/* Position Name (-a, -b/-i) */
	char		**namv;		/* Member names from command line */
	int		namc;		/* # of member names in namv */
	int		opt_flgs;	/* options */
	Cmd_func	*comfun;	/* function to carry out command */
	int		modified;	/* Set if need to write archive */
} Cmd_info;

/*
 * options (Cmd_info opt_flgs)
 */
#define	a_FLAG	0x00000001
#define	b_FLAG	0x00000002
#define	c_FLAG	0x00000004
#define	C_FLAG	0x00000008
#define	d_FLAG	0x00000010
#define	m_FLAG	0x00000020
#define	p_FLAG	0x00000040
#define	q_FLAG	0x00000080
#define	r_FLAG	0x00000100
#define	s_FLAG	0x00000200
#define	S_FLAG	0x00000400
#define	t_FLAG	0x00000800
#define	T_FLAG	0x00001000
#define	u_FLAG	0x00002000
#define	v_FLAG	0x00004000
#define	x_FLAG	0x00008000
#define	z_FLAG	0x00010000

/*
 * Member flags (ARFILE ar_flag)
 */
#define	F_ELFRAW	0x01		/* ar_contents data via elf_rawfile */
#define	F_CLASS32	0x02		/* ELFCLASS32 */
#define	F_CLASS64	0x04		/* ELFCLASS64 */

/*
 * Function prototypes
 */
Cmd_func	qcmd;
Cmd_func	rcmd;
Cmd_func	dcmd;
Cmd_func	xcmd;
Cmd_func	pcmd;
Cmd_func	mcmd;
Cmd_func	tcmd;

extern ARFILE	*listhead, *listend;

extern	void	establish_sighandler(void (*)());
extern	int	getaf(Cmd_info *);
extern	ARFILE	*getfile(Cmd_info *);
extern	ARFILE	*newfile(void);
extern	char	*trim(char *);
extern	void	writefile(Cmd_info *cmd_info);


#endif	/* _INC_H */
