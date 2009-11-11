/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <port_before.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <port_after.h>

#undef p_option
/* extern const char * isc_p_option(); */
const char *p_option(uint_t option) {
	return (isc_p_option((ulong_t)option));
}
#pragma weak	__p_option		=	p_option

#undef p_secstodate
/* extern char * isc_p_secstodate (); */
char *p_secstodate(uint_t secs) {
	return (isc_p_secstodate((ulong_t)secs));
}
#pragma weak	__p_secstodate		=	p_secstodate
