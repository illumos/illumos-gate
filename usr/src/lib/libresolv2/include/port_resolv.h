/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PORT_RESOLV_H
#define	_PORT_RESOLV_H

#ifdef	__cplusplus
extern "C" {
#endif

/* RES_NSID has the same value as RES_NO_NIBBLE, which has been deleted  */
#define	RES_NSID	0x00040000	/* request name server ID */

/* RES_DEFAULT has a new value in libbind-6.0 */
#undef RES_DEFAULT
#define	RES_DEFAULT	(RES_RECURSE | RES_DEFNAMES | \
	RES_DNSRCH | RES_NO_NIBBLE2)

#ifndef __ultrix__
u_int16_t	_getshort __P((const uchar_t *));
u_int32_t	_getlong __P((const uchar_t *));
#endif

/* rename functions so they can be wrapped (see sunw/sunw_wrappers.c */
#define	p_option isc_p_option
const char *p_option(ulong_t option);
#define	p_secstodate isc_p_secstodate
char *p_secstodate(ulong_t secs);

/* prevent namespace pollution */
#define	res_protocolnumber	__res_protocolnumber
#define	res_servicenumber	__res_servicenumber



#ifdef	__cplusplus
}
#endif

#endif /* _PORT_RESOLV_H */
