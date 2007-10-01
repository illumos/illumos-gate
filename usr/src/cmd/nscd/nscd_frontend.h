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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NSCD_FRONTEND_H
#define	_NSCD_FRONTEND_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "cache.h"

#define	NSCD_N2NBUF_MAXLEN	1024 * 8
#define	NSCD_PHDR_MAXLEN	1024 * 8
#define	NSCD_LOOKUP_BUFSIZE	1024 * 16
#define	NSCD_DOORBUF_MAXLEN	1024 * 512
#define	NSCD_PHDR_LEN(hdrp)	((hdrp)->data_off)
#define	NSCD_DATA_LEN(hdrp)	((hdrp)->data_len)

#define	NSCD_ALLOC_LOOKUP_BUFFER(bufp, bufsiz, hdrp, space, spsiz)  \
	if ((hdrp)->pbufsiz <= spsiz) { \
		(void) memcpy(space, (hdrp), NSCD_PHDR_LEN((hdrp))); \
		bufp = space; \
		bufsiz = spsiz; \
		hdrp = (nss_pheader_t *)(void *)space; \
		(hdrp)->pbufsiz = bufsiz; \
		(hdrp)->data_len = bufsiz - (hdrp)->data_off; \
	} else { \
		(bufp) = NULL; \
		bufsiz = (hdrp)->pbufsiz; \
		if (bufsiz > spsiz) \
			bufsiz = NSCD_DOORBUF_MAXLEN; \
		(bufp) = alloca(bufsiz); \
		if ((bufp) != NULL) { \
			(void) memcpy((bufp), (hdrp), NSCD_PHDR_LEN(hdrp)); \
			(hdrp) = (nss_pheader_t *)(void *)(bufp); \
			(hdrp)->pbufsiz = bufsiz; \
			(hdrp)->data_len = bufsiz - (hdrp)->data_off; \
		} else { \
			NSCD_SET_STATUS((hdrp), NSS_ERROR, ENOMEM); \
			(void) door_return((char *)(hdrp), \
				NSCD_PHDR_LEN(hdrp), NULL, 0); \
		} \
	}

#define	NSCD_SET_RETURN_ARG(hdrp, arg_size)  \
	if (NSCD_STATUS_IS_OK((nss_pheader_t *)(hdrp))) \
		arg_size = NSCD_PHDR_LEN(hdrp) + (NSCD_DATA_LEN(hdrp) > 0 ? \
		NSCD_DATA_LEN(hdrp) + 1 : 0); \
	else \
		arg_size = NSCD_PHDR_LEN(hdrp);

/* prototypes */
uid_t _nscd_get_client_euid();
int _nscd_check_client_read_priv();
int _nscd_setup_server(char *execname, char **argv);
int _nscd_setup_child_server(int did);
int _nscd_get_clearance(sema_t *sema);
int _nscd_release_clearance(sema_t *sema);
void _nscd_init_cache_sema(sema_t *sema, char *cache_name);
nscd_rc_t _nscd_alloc_frontend_cfg();
void _nscd_APP_check_cred(void *buf, pid_t *pidp, char *dc_str,
	int log_comp, int log_level);
void _nscd_restart_if_cfgfile_changed();
#ifdef	__cplusplus
}
#endif

#endif	/* _NSCD_FRONTEND_H */
