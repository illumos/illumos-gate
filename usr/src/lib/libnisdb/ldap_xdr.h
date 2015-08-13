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
 * Copyright 2015 Gary Mills
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_LDAP_XDR_H
#define	_LDAP_XDR_H

#include <rpcsvc/nis.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Structure used to hide flag/counter from rpcgen */
typedef struct {
	long	flag;
} __nisdb_flag_t;

/* Structure used to hide pointers from rpcgen */
typedef struct {
	void	*ptr;
} __nisdb_ptr_t;

/* Exported functions */
bool_t		xdr_nis_name_abbrev(XDR *xdrs, nis_name	*namep,
			nis_name domainname);
bool_t		xdr_nis_fetus_object(XDR *xdrs, nis_object *objp,
			nis_object *tobj);
entry_obj	*makePseudoEntryObj(nis_object *obj, entry_obj *eo,
				nis_object *tobj);
nis_object	*unmakePseudoEntryObj(entry_obj *e, nis_object *tobj);
void		*xdrNisObject(nis_object *obj, entry_obj **ea, int numEa,
			int *xdrLenP);
nis_object	*unXdrNisObject(void *buf, int bufLen, entry_obj ***eaP,
			int *numEaP);
void		freeEntryObjArray(entry_obj **ea, int numEa);
bool_t		sameNisPlusObj(nis_object *o1, nis_object *o2);
bool_t		sameNisPlusPseudoObj(nis_object *o1, entry_obj *e2);
bool_t		xdr___nisdb_rwlock_t(XDR *, void *);
bool_t		xdr___nisdb_flag_t(XDR *, void *);
bool_t		xdr___nisdb_ptr_t(XDR *, void *);
bool_t		xdr___nis_table_mapping_t(XDR *, void *);

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _LDAP_XDR_H */
