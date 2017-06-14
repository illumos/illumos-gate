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
/*	  All Rights Reserved	*/


#ifndef	_VALTOOLS_H
#define	_VALTOOLS_H

#ifdef	__cplusplus
extern "C" {
#endif

struct _choice_ {
	char *token;
	char *text;
	struct _choice_ *next;
};

struct _menu_ {
	char	*label;
	int	attr;
	short	longest;
	short	nchoices;
	struct _choice_
		*choice;
	char	**invis;
};

typedef struct _menu_ CKMENU;

#define	P_ABSOLUTE	0x0001
#define	P_RELATIVE	0x0002
#define	P_EXIST		0x0004
#define	P_NEXIST	0x0008
#define	P_REG		0x0010
#define	P_DIR		0x0020
#define	P_BLK		0x0040
#define	P_CHR		0x0080
#define	P_NONZERO	0x0100
#define	P_READ		0x0200
#define	P_WRITE		0x0400
#define	P_EXEC		0x0800
#define	P_CREAT		0x1000

#define	CKUNNUM		0x01
#define	CKALPHA		0x02
#define	CKONEFLAG	0x04

#ifdef	__cplusplus
}
#endif

#endif	/* _VALTOOLS_H */
