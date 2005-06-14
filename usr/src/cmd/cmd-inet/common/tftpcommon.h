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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TFTPCOMMON_H
#define	_TFTPCOMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Defines and function declarations common to tftp and in.tftpd.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <arpa/tftp.h>

#define	MIN_BLKSIZE	8			/* RFC 2348 */
#define	MAX_BLKSIZE	65464			/* RFC 2348 */
#define	MIN_TIMEOUT	1			/* RFC 2349 */
#define	MAX_TIMEOUT	255			/* RFC 2349 */
#define	PKTSIZE		(MAX_BLKSIZE + 4)	/* DATA packet max size */
#define	MAX_OPTVAL_LEN	32			/* Option value max length */

/* Format when printing an off_t */
#if _FILE_OFFSET_BITS == 64
#define	OFF_T_FMT	"%lld"
#else
#define	OFF_T_FMT	"%ld"
#endif

typedef union {
	struct tftphdr	tb_hdr;
	char		tb_data[PKTSIZE];
} tftpbuf;

struct errmsg {
	int	e_code;
	char	*e_msg;
};
extern struct errmsg	errmsgs[];

/* Declarations for shared functions in tftpsubs.c */
extern struct tftphdr	*w_init(void);
extern struct tftphdr	*r_init(void);
extern int		readit(FILE *, struct tftphdr **, int);
extern void		read_ahead(FILE *, int);
extern int		writeit(FILE *, struct tftphdr **, int, int);
extern int		write_behind(FILE *, int);
extern int		synchnet(int);
extern char		*next_field(const char *, const char *);
extern void		print_options(FILE *, char *, int);
extern void		cancel_alarm(void);

#ifdef __cplusplus
}
#endif

#endif /* _TFTPCOMMON_H */
