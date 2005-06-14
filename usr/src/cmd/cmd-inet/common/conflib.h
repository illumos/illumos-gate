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

#ifndef _CONFLIB_H
#define	_CONFLIB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * conflib.h -- Prototypes and defines for conflib.c
 * WARNING:  This code assumes that an int is 32 bits.
 */

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Static lengths of values. */
#define	MAX_LABEL_LEN 256
#define	MAX_SECTION_LEN 256
#define	MAX_VALUE_LEN 256
#define	MAX_FILENAME_LEN 256

/* Error string readable by external programs */
#define	ERROR_SUBSTRING_LEN 256
#define	ERROR_STRING_LEN (MAX_FILENAME_LEN + ERROR_SUBSTRING_LEN)
extern char ErrorString[];

/*
 * Check if OS has defined true or false.  This code is portable between
 * several OSs.
 */
#ifndef TRUE
#define	TRUE 1
#define	FALSE 0
#endif


/* these are shared between mipagent and mipagentconfig */

/* IPsec flags - what's in place to protect datagrams to/from an agent peer. */
#define	IPSEC_REQUEST_AH		0x01	/* regRequest using AH */
#define	IPSEC_REQUEST_ESP		0x02	/* regRequest using ESP */
#define	IPSEC_REPLY_AH			0x04	/* regReply using AH */
#define	IPSEC_REPLY_ESP			0x08	/* regReply using ESP */
#define	IPSEC_TUNNEL_AH			0x10	/* forward tunnel using AH */
#define	IPSEC_TUNNEL_ESP		0x20	/* forward tunnel using ESP */
#define	IPSEC_REVERSE_TUNNEL_AH		0x40	/* reverse tunnel using AH */
#define	IPSEC_REVERSE_TUNNEL_ESP	0x80	/* reverse tunnel using ESP */

/* useful combinations */
#define	IPSEC_REQUEST_BOTH	(IPSEC_REQUEST_AH | IPSEC_REQUEST_ESP)
#define	IPSEC_REPLY_BOTH	(IPSEC_REPLY_AH | IPSEC_REPLY_ESP)
#define	IPSEC_TUNNEL_BOTH	(IPSEC_TUNNEL_AH | IPSEC_TUNNEL_ESP)
#define	IPSEC_REVERSE_TUNNEL_BOTH \
			(IPSEC_REVERSE_TUNNEL_AH | IPSEC_REVERSE_TUNNEL_ESP)

/* useful for checking if there's a policy that should be invoked */
#define	IPSEC_REQUEST_ANY(x)	((x) & (IPSEC_REQUEST_BOTH))
#define	IPSEC_REPLY_ANY(x)	((x) & (IPSEC_REPLY_BOTH))
#define	IPSEC_TUNNEL_ANY(x)	((x) & (IPSEC_TUNNEL_BOTH))
#define	IPSEC_REVERSE_TUNNEL_ANY(x) ((x) & (IPSEC_REVERSE_TUNNEL_BOTH))

/* useful for checking when user is requesting something that's not offered */
#define	IPSEC_ANY_AH(x)	((x) & (IPSEC_REQUEST_AH |\
				IPSEC_REPLY_AH |\
				IPSEC_TUNNEL_AH |\
				IPSEC_REVERSE_TUNNEL_AH))

#define	IPSEC_ANY_ESP(x)	((x) & (IPSEC_REQUEST_ESP |\
					IPSEC_REPLY_ESP |\
					IPSEC_TUNNEL_ESP |\
					IPSEC_REVERSE_TUNNEL_ESP))

/* how policies are deliniated in CONF_FILE_NAME */
#define	IPSP_SEPARATOR	":"

/* these functions are necessary to share IPsec functionality */
int parseIPsecProps(char *, ipsec_req_t *);
boolean_t isIPsecPolicyValid(char *, ipsec_req_t *);

/* These functions mimic the Windows(tm) equivilants */
int WritePrivateProfileString(char *, char *, char *, char *);
int WritePrivateProfileInt(char *, char *, int, char *);
int GetPrivateProfileString(char *, char *, char *, char *, int, char *);
int GetPrivateProfileInt(char *, char *, int, char *);

/* These functions were necessary for extra usability */
char *IniListSections(char *, int *, int *);
int DeletePrivateProfileLabel(char *, char *, char *);
int DeletePrivateProfileSection(char *, char *);

#ifdef __cplusplus
}
#endif

#endif /* _CONFLIB_H */
