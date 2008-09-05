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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_USBA_USBA_DEVDB_H
#define	_SYS_USBA_USBA_DEVDB_H


#ifdef	__cplusplus
extern "C" {
#endif

typedef struct usba_configrec {
	char	*selection;
	int	idVendor, idProduct, cfg_index;
	char	*serialno;
	char	*pathname;
	char	*driver;
} usba_configrec_t;

usba_configrec_t *usba_devdb_get_user_preferences(int, int, char *, char *);
int 		usba_devdb_refresh();

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USBA_USBA_DEVDB_H */
