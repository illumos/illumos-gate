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

#ifndef _DHCP_SVC_CONFOPT_H
#define	_DHCP_SVC_CONFOPT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Contains SMI-private interfaces to /etc/inet/dhcpsvc.conf file. DO NOT SHIP!
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	DHCP_CONFOPT_FILE		"/etc/inet/dhcpsvc.conf"

enum dhcp_confopt {
	DHCP_END,			/* final entry, must be 0 */
	DHCP_KEY,			/* key / value form */
	DHCP_COMMENT			/* comment form */
};

/*
 * Records in the /etc/inet/dhcpsvc.conf file are of key=value form. Comments
 * begin a line with '#', and end with newline (\n). See dhcpsvc(4) for more
 * details. This structure is used to represent them within a program.
 */

typedef struct {
	enum dhcp_confopt	co_type;
	char			*co_key;	/* identifier */
	char			*co_value;	/* data */
} dhcp_confopt_t;
#define	co_comment		co_key		/* key doubles as comment */

extern int	add_dsvc_conf(dhcp_confopt_t **, const char *, const char *);
extern int	read_dsvc_conf(dhcp_confopt_t **);
extern int	replace_dsvc_conf(dhcp_confopt_t **, const char *,
			const char *);
extern int	write_dsvc_conf(dhcp_confopt_t *, mode_t);
extern void	free_dsvc_conf(dhcp_confopt_t *);
extern int	delete_dsvc_conf(void);
extern int	query_dsvc_conf(dhcp_confopt_t *, const char *, char **);

#ifdef	__cplusplus
}
#endif

#endif	/* !_DHCP_SVC_CONFOPT_H */
