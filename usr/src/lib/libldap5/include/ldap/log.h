#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _LLOG_H
#define _LLOG_H


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <nl_types.h>
#include <limits.h>
#include <syslog.h>
#include <portable.h>



/* Log levels */

/* slapd values */
#define LDAP_DEBUG_TRACE        0x001
#define LDAP_DEBUG_PACKETS      0x002
#define LDAP_DEBUG_ARGS         0x004
#define LDAP_DEBUG_CONNS        0x008
#define LDAP_DEBUG_BER          0x010
#define LDAP_DEBUG_FILTER       0x020
#define LDAP_DEBUG_CONFIG       0x040
#define LDAP_DEBUG_ACL          0x080
#define LDAP_DEBUG_STATS        0x100
#define LDAP_DEBUG_STATS2       0x200
#define LDAP_DEBUG_SHELL        0x400
#define LDAP_DEBUG_PARSE        0x800
/* More values for http gateway */
#define LDAP_DEBUG_GWAY		0x1000
#define LDAP_DEBUG_GWAYMORE	0x2000
/* Generic values */
#define LDAP_DEBUG_ANY		0xffff

nl_catd	sundscat;
extern nl_catd	slapdcat;
extern void 	ldaplogconfig(char * logf, int size);
extern void	ldaplogconfigf(FILE *fd);
extern void	ldaploginit(char *name, 
			int facility);
extern void	ldaploginitlevel(char *name, 
			    int facility,
			    int log_level);
extern void 	ldaplog(int level,char *fmt,...);

#define Statslog( level, fmt, connid, opid, arg1, arg2, arg3 )  \
{ \
	if ( log_debug & level ) \
		fprintf( stderr, fmt, connid, opid, arg1, arg2, arg3 );\
	if ( log_syslog & level ) \
		ldaplog( level, fmt, connid, opid, arg1, arg2, arg3 ); \
}
#endif /* _LLOG_H */



