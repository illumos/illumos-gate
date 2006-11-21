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

#ifndef _LIBDLADM_H
#define	_LIBDLADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/dls.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dladm_attr {
	char		da_dev[MAXNAMELEN];
	uint_t		da_max_sdu;
	uint16_t	da_vid;
} dladm_attr_t;

#define	DLADM_STRSIZE		256
#define	DLADM_SECOBJ_VAL_MAX	256
#define	DLADM_PROP_VAL_MAX	256
#define	DLADM_OPT_TEMP		0x00000001
#define	DLADM_OPT_CREATE	0x00000002
#define	DLADM_OPT_PERSIST	0x00000004

typedef enum {
	DLADM_STATUS_OK = 0,
	DLADM_STATUS_BADARG,
	DLADM_STATUS_FAILED,
	DLADM_STATUS_TOOSMALL,
	DLADM_STATUS_NOTSUP,
	DLADM_STATUS_NOTFOUND,
	DLADM_STATUS_BADVAL,
	DLADM_STATUS_NOMEM,
	DLADM_STATUS_EXIST,
	DLADM_STATUS_LINKINVAL,
	DLADM_STATUS_PROPRDONLY,
	DLADM_STATUS_BADVALCNT,
	DLADM_STATUS_DBNOTFOUND,
	DLADM_STATUS_DENIED,
	DLADM_STATUS_IOERR
} dladm_status_t;

typedef enum {
	DLADM_PROP_VAL_CURRENT = 1,
	DLADM_PROP_VAL_DEFAULT,
	DLADM_PROP_VAL_MODIFIABLE,
	DLADM_PROP_VAL_PERSISTENT
} dladm_prop_type_t;

#define		DLADM_SECOBJ_CLASS_WEP	0
typedef int	dladm_secobj_class_t;

typedef void (dladm_walkcb_t)(void *, const char *);

extern int	dladm_walk(dladm_walkcb_t *, void *);
extern int	dladm_walk_vlan(dladm_walkcb_t *, void *, const char *);
extern int	dladm_info(const char *, dladm_attr_t *);

extern dladm_status_t	dladm_set_prop(const char *, const char *,
			    char **, uint_t, uint_t);
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

extern const char	*dladm_status2str(dladm_status_t, char *);
extern const char	*dladm_secobjclass2str(dladm_secobj_class_t, char *);
extern dladm_status_t	dladm_str2secobjclass(const char *,
			    dladm_secobj_class_t *);

extern dladm_status_t	dladm_init_linkprop(void);
extern dladm_status_t	dladm_init_secobj(void);
extern dladm_status_t	dladm_set_rootdir(const char *rootdir);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLADM_H */
