/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SOLARISPRIV_H
#define	_SOLARISPRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * solaris-priv.h - items not exposed to outside but used by solaris clients
 * of ldap
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Well-behaved extensions private to solaris OS  will use option values
 * between 0x3000 and 0x3FFF inclusive.
 */
#define	LDAP_OPT_SOLARIS_EXTENSION_BASE 0x3000  /* to 0x3FFF inclusive */

/*
 * Option to install "SKIP a data base" dns routines
 */
#define	LDAP_X_OPT_DNS_SKIPDB	(LDAP_OPT_SOLARIS_EXTENSION_BASE + 0x0F01)


#ifdef __cplusplus
}
#endif

#endif /* _SOLARISPRIV_H */
