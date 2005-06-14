/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_LDAPTOOL_SASL_H
#define	_LDAPTOOL_SASL_H

/*
 * Include file for ldaptool routines for SASL
 */

void *ldaptool_set_sasl_defaults ( LDAP *ld, char *mech, char *authid, char *username, char *passwd, char *realm ); 
int ldaptool_sasl_interact ( LDAP *ld, unsigned flags, void *defaults, void *p );
#endif	/* _LDAPTOOL_SASL_H */
