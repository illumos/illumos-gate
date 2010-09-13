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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DEVID_H
#define	_DEVID_H

#ifndef	_KERNEL
#include <sys/types.h>
#endif	/* _KERNEL */

#include <sys/sunddi.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct devid_nmlist {
	char 	*devname;
	dev_t	dev;
} devid_nmlist_t;

extern int	devid_get(int fd, ddi_devid_t *retdevid);
extern void	devid_free(ddi_devid_t devid);
extern int	devid_get_minor_name(int fd, char **retminor_name);
extern size_t	devid_sizeof(ddi_devid_t devid);
extern int	devid_compare(ddi_devid_t devid1, ddi_devid_t devid2);
extern int	devid_deviceid_to_nmlist(char *search_path, ddi_devid_t devid,
		    char *minor_name, devid_nmlist_t **retlist);
extern void	devid_free_nmlist(devid_nmlist_t *list);
extern int	devid_valid(ddi_devid_t devid);
extern char	*devid_str_encode(ddi_devid_t devid, char *minor_name);
extern int	devid_str_decode(char *devidstr,
		    ddi_devid_t *retdevid, char **retminor_name);
extern void	devid_str_free(char *devidstr);

#ifdef	__cplusplus
}
#endif

#endif	/* _DEVID_H */
