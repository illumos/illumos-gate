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

#ifndef _LIBDLLINK_H
#define	_LIBDLLINK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file includes strcutures, macros and routines used by general
 * link administration, which applies not limited to one specific
 * type of link.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mac.h>
#include <libdladm.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dladm_attr {
	char		da_dev[MAXNAMELEN];
	uint_t		da_max_sdu;
	uint16_t	da_vid;
} dladm_attr_t;

/*
 * Maximum size of secobj value. Note that it should not be greater than
 * DLD_SECOBJ_VAL_MAX.
 */
#define	DLADM_SECOBJ_VAL_MAX	256

/*
 * Maximum size of secobj name. Note that it should not be greater than
 * DLD_SECOBJ_NAME_MAX.
 */
#define	DLADM_SECOBJ_NAME_MAX	32

#define	DLADM_PROP_VAL_MAX	25

#define		DLADM_SECOBJ_CLASS_WEP	0
#define		DLADM_SECOBJ_CLASS_WPA	1
typedef int	dladm_secobj_class_t;

typedef void (dladm_walkcb_t)(void *, const char *);

extern int	dladm_walk(dladm_walkcb_t *, void *);
extern int	dladm_mac_walk(void (*fn)(void *, const char *), void *);
extern int	dladm_info(const char *, dladm_attr_t *);
extern int	dladm_hold_link(const char *, zoneid_t, boolean_t);
extern int	dladm_rele_link(const char *, zoneid_t, boolean_t);

extern dladm_status_t	dladm_set_prop(const char *, const char *,
			    char **, uint_t, uint_t, char **);
extern dladm_status_t	dladm_get_prop(const char *, dladm_prop_type_t,
			    const char *, char **, uint_t *);
extern dladm_status_t	dladm_walk_prop(const char *, void *,
			    boolean_t (*)(void *, const char *));
extern dladm_status_t	dladm_set_secobj(const char *, dladm_secobj_class_t,
			    uint8_t *, uint_t, uint_t);
extern dladm_status_t	dladm_get_secobj(const char *, dladm_secobj_class_t *,
			    uint8_t *, uint_t *, uint_t);
extern dladm_status_t	dladm_unset_secobj(const char *, uint_t);
extern dladm_status_t	dladm_walk_secobj(void *,
			    boolean_t (*)(void *, const char *), uint_t);

extern const char	*dladm_linkstate2str(link_state_t, char *);
extern const char	*dladm_linkduplex2str(link_duplex_t, char *);
extern const char	*dladm_secobjclass2str(dladm_secobj_class_t, char *);
extern dladm_status_t	dladm_str2secobjclass(const char *,
			    dladm_secobj_class_t *);

extern dladm_status_t	dladm_init_linkprop(void);
extern dladm_status_t	dladm_init_secobj(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLLINK_H */
