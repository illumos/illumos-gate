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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _ADAPTOR_H
#define	_ADAPTOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The API used by the BSD print protocol adaptor to glue the front end
 * request receiving code to the back end request fufilling code.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	ADAPTOR_PATH "/etc/print/bsd-adaptor,/usr/lib/print/bsd-adaptor"
#define	NS_KEY_ADAPTOR_PATH	"spooling-type-path"
#define	NS_KEY_ADAPTOR_NAME	"spooling-type"
#define	CASCADE			"cascade"
#define	LPSCHED			"lpsched"

extern	int  adaptor_available(const char *printer);
extern	int  adaptor_spooler_available(const char *printer);
extern	int  adaptor_spooler_accepting_jobs(const char *printer);
extern  int  adaptor_client_access(const char *printer, const char *host);
extern  int  adaptor_restart_printer(const char *printer);
extern  char *adaptor_temp_dir(const char *printer, const char *host);
extern  int  adaptor_submit_job(const char *printer, const char *host,
				char *cf, char **df_list);
extern  int  adaptor_show_queue(const char *printer, FILE *ofp,
				const int type, char **list);
extern  int  adaptor_cancel_job(const char *printer, FILE *ofp,
				const char *user, const char *host,
				char **list);

#ifdef __cplusplus
}
#endif

#endif /* _ADAPTOR_H */
