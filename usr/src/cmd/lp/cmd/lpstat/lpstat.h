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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/

#include <sys/types.h>
#include <time.h>

#define	DESTMAX	14	/* max length of destination name */
#define	SEQLEN	8	/* max length of sequence number */
#define	IDSIZE	DESTMAX+SEQLEN+1	/* maximum length of request id */
#define	LOGMAX	15	/* maximum length of logname */
#define	OSIZE	7
#define SZ_DATE_BUFF 100	/* size of conversion buff for dates */

#define INQ_UNKNOWN	-1
#define INQ_ACCEPT	0
#define INQ_PRINTER	1
#define INQ_STORE	2
#define INQ_USER	3

#define V_LONG		0x0001
#define V_BITS		0x0002
#define V_RANK		0x0004
#define V_MODULES	0x0008

#define BITPRINT(S,B) \
	if ((S)&(B)) { (void)printf("%s%s",sep,#B); sep = "|"; }

typedef struct mounted {
	char			*name,
				**printers;
	struct mounted		*forward;
}			MOUNTED;

void		add_mounted ( char * , char * , char * );
void		def ( void );
void		do_accept ( char ** );
void		do_charset ( char ** );
void		do_class ( char ** );
void		do_device ( char ** );
void		do_form ( char ** );
void		do_paper ( char ** );
void		do_printer ( char ** );
void		do_request ( char ** );
void		do_user ( char ** );
void		done ( int );
void		parse ( int , char ** );
void		putoline(char *, char *, char *, long, time_t, int, char *,
			char *, char *, int);
void		putpline(char *, int, char *, time_t, char *, char *, char *);
void		putqline(char *, int, time_t, char *);
void		putppline ( char * ,  char *);
void		running ( void );
void		send_message ( int , ... );
void		startup ( void );

int		output ( int );
int		printer_configured ( void );

#if	defined(_LP_PRINTERS_H)
char **		get_charsets ( PRINTER * , int );
#endif

extern int		exit_rc;
extern int		inquire_type;
extern int		D;
extern int		remote_cmd;
extern int		scheduler_active;

extern char		*alllist[];

extern unsigned int	verbosity;

extern MOUNTED		*mounted_forms;
extern MOUNTED		*mounted_pwheels;
