/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * File chamged to fit with Sun Standards
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1994 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef _CONFIG_H
#define _CONFIG_H

/*
 * config.h for LDAP -- edit this file to customize LDAP client behavior.
 * NO platform-specific definitions should be placed in this file.
 * Note that this is NOT used by the LDAP or LBER libraries.
 */

/*
 * SHARED DEFINITIONS - things you should change
 */
	/* default ldap host */
#define LDAPHOST	"localhost"
	/* default place to start searching */
#define DEFAULT_BASE	"c=US"

/*********************************************************************
 *                                                                   *
 * You probably do not need to edit anything below this point        *
 *                                                                   *
 *********************************************************************/

/*
 * SHARED DEFINITIONS - other things you can change
 */
	/* default attribute to use when sorting entries, NULL => sort by DN */
#define SORT_ATTR	NULL
	/* default count of DN components to show in entry displays */
#define DEFAULT_RDNCOUNT	2
	/* default config file locations */
#define FILTERFILE	"/etc/opt/SUNWconn/ldap/current/ldapfilter.conf"
#define TEMPLATEFILE	"/etc/opt/SUNWconn/ldap/current/ldaptemplates.conf"
#define SEARCHFILE	"/etc/opt/SUNWconn/ldap/current/ldapsearchprefs.conf"
#define FRIENDLYFILE	"/etc/opt/SUNWconn/ldap/current/ldapfriendly"

/*
 * FINGER DEFINITIONS
 */
	/* who to bind as */
#define FINGER_BINDDN		NULL
	/* where to search */
#define FINGER_BASE		DEFAULT_BASE
	/* banner to print */
#define FINGER_BANNER		"X.500 Finger Service...\r\n"
	/* who to report errors to */
#define FINGER_ERRORS		"your local system administrator"
	/* what to say if no matches are found */
#define FINGER_NOMATCH		"Search failed to find anything.\r\n"
	/* what to say if the service may be unavailable */
#define FINGER_UNAVAILABLE	\
"The X.500 service may be temporarily unavailable.\r\n\
Please try again later.\r\n"
	/* printed if a match has no email address - for disptmp default */
#define FINGER_NOEMAIL1	"None registered in this service."
#define FINGER_NOEMAIL2	NULL
#define FINGER_NOEMAIL	{ FINGER_NOEMAIL1, FINGER_NOEMAIL2, NULL }
	/* maximum number of matches returned */
#define FINGER_SIZELIMIT	50
	/* max number of hits displayed in full before a list is presented */
#define FINGER_LISTLIMIT	1
	/* what to exec for "finger @host" */
#define FINGER_CMD		"/usr/ucb/finger"
	/* how to treat aliases when searching */
#define FINGER_DEREF		LDAP_DEREF_FINDING
	/* attribute to use when sorting results */
#define FINGER_SORT_ATTR	SORT_ATTR
	/* enable ufn support */
#define FINGER_UFN
	/* timeout for searches */
#define FINGER_TIMEOUT		60
	/* number of DN components to show in entry displays */
#define FINGER_RDNCOUNT		DEFAULT_RDNCOUNT	

/*
 * GO500 GOPHER GATEWAY DEFINITIONS
 */
	/* who to bind as */
#define GO500_BINDDN	NULL
	/* where to search */
#define GO500_BASE	DEFAULT_BASE
	/* port on which to listen */
#define GO500_PORT	5555
	/* how to handle aliases */
#define GO500_DEREF	LDAP_DEREF_FINDING
	/* attribute to use when sorting results */
#define GO500_SORT_ATTR	SORT_ATTR
	/* timeout for searches */
#define GO500_TIMEOUT	180
	/* enable ufn support */
#define GO500_UFN
	/*
	 * only set and uncomment this if your hostname() does not return
	 * a fully qualified hostname
	 */
/* #define GO500_HOSTNAME	"fully.qualified.hostname.here" */
	/* number of DN components to show in entry displays */
#define GO500_RDNCOUNT		DEFAULT_RDNCOUNT	

/*
 * GO500GW GOPHER GATEWAY DEFINITIONS
 */
	/* who to bind as */
#define GO500GW_BINDDN		NULL
	/* where the helpfile lives */
#define GO500GW_HELPFILE	"go500gw.help"
	/* port on which to listen */
#define GO500GW_PORT		7777
	/* timeout on all searches */
#define GO500GW_TIMEOUT		180
	/* enable ufn support */
#define GO500GW_UFN
	/* attribute to use when sorting results */
#define GO500GW_SORT_ATTR	SORT_ATTR
	/*
	 * only set and uncomment this if your hostname() does not return
	 * a fully qualified hostname
	 */
/* #define GO500GW_HOSTNAME	"fully.qualified.hostname.here" */
	/* number of DN components to show in entry displays */
#define GO500GW_RDNCOUNT	DEFAULT_RDNCOUNT	

/*
 * RCPT500 MAIL RESPONDER GATEWAY DEFINITIONS
 */
	/* who to bind as */
#define RCPT500_BINDDN		NULL
	/* where the helpfile lives */
#define RCPT500_HELPFILE	"rcpt500.help"
	/* maximum number of matches returned */
#define RCPT500_SIZELIMIT	50
	/* address replies will appear to come from */
#define RCPT500_FROM		"\"X.500 Query Program\" <X500-Query>"
	/* command that will accept an RFC822 message text on standard
	   input, and send it.  sendmail -t does this nicely. */
#define RCPT500_PIPEMAILCMD	"/usr/lib/sendmail -t"
        /* where to search */
#define RCPT500_BASE             DEFAULT_BASE
	/* attribute to use when sorting results */
#define RCPT500_SORT_ATTR	SORT_ATTR
	/* max number of hits displayed in full before a list is presented */
#define RCPT500_LISTLIMIT	1
	/* enable ufn support */
#define RCPT500_UFN
	/* number of DN components to show in entry displays */
#define RCPT500_RDNCOUNT	DEFAULT_RDNCOUNT	

/*
 * LDAPSEARCH TOOL
 */
	/* who to bind as */
#define LDAPSEARCH_BINDDN	NULL
	/* search base */
#define LDAPSEARCH_BASE		DEFAULT_BASE

/*
 * LDAPMODIFY TOOL
 */
	/* who to bind as */
#define LDAPMODIFY_BINDDN	NULL
	/* search base */
#define LDAPMODIFY_BASE		DEFAULT_BASE

/*
 * LDAPDELETE TOOL
 */
	/* who to bind as */
#define LDAPDELETE_BINDDN	NULL
	/* search base */
#define LDAPDELETE_BASE		DEFAULT_BASE

/*
 * LDAPMODRDN TOOL
 */
	/* who to bind as */
#define LDAPMODRDN_BINDDN	NULL
	/* search base */
#define LDAPMODRDN_BASE		DEFAULT_BASE

/*
 * MAIL500 MAILER DEFINITIONS
 */
	/* who to bind as */
#define MAIL500_BINDDN		NULL
	/* max number of ambiguous matches reported */
#define MAIL500_MAXAMBIGUOUS	10
	/* max subscribers allowed (size limit when searching for them ) */
#define MAIL500_MAXGROUPMEMBERS	LDAP_NO_LIMIT
	/* timeout for all searches */
#define MAIL500_TIMEOUT		180
	/* sendmail location - mail500 needs to exec this */
#define MAIL500_SENDMAIL	"/usr/lib/sendmail"

/*
 * UD DEFINITIONS
 */
	/* ud configuration file */
#define UD_CONFIG_FILE		"/etc/opt/SUNWconn/ldap/current/ud.conf"
	/* default editor */
#define UD_DEFAULT_EDITOR	"/usr/ucb/vi"
	/* default bbasename of user config file */
#define UD_USER_CONFIG_FILE	".udrc"
	/* default user to bind as */
#define UD_BINDDN		NULL
	/* default password to bind with */
#define UD_PASSWD		NULL
	/* default search base */
#define UD_BASE			DEFAULT_BASE
	/* default base where groups are created */
#define UD_WHERE_GROUPS_ARE_CREATED	""
	/* default base below which all groups live */
#define UD_WHERE_ALL_GROUPS_LIVE	""

/*
 * FAX500 DEFINITIONS
 */
	/* what to bind as */
#define FAX_BINDDN	NULL
	/* how long to wait for searches */
#define FAX_TIMEOUT		180
	/* maximum number of ambiguous matches reported */
#define FAX_MAXAMBIGUOUS	10
	/* maximum number of members allowed */
#define FAX_MAXMEMBERS		LDAP_NO_LIMIT
	/* program to send mail */
#define FAX_SENDMAIL		"/usr/lib/sendmail"

/*
 * RP500 DEFINITIONS
 */
	/* what to bind as */
#define RP_BINDDN	NULL
	/* prefix to add to non-fully-qualified numbers */
#define RP_PHONEPREFIX	""

/*
 * SLAPD DEFINITIONS
 */
	/* location of the default slapd config file */
#define SLAPD_DEFAULT_CONFIGFILE	"/etc/opt/SUNWconn/ldap/current/slapd.conf"
	/* default sizelimit on number of entries from a search */
#define SLAPD_DEFAULT_SIZELIMIT		10000
	/* default timelimit to spend on a search */
#define SLAPD_DEFAULT_TIMELIMIT		3600
	/* location of the slapd pid file */
#define SLAPD_PIDFILE			"/var/opt/SUNWconn/ldap/log/slapd.pid"
	/* location of the slapd args file */
#define SLAPD_ARGSFILE			"/var/opt/SUNWconn/ldap/log/slapd.args"
	/* dn of the special "monitor" entry */
#define SLAPD_MONITOR_DN		"cn=monitor"
	/* dn of the special "config" entry */
#define SLAPD_CONFIG_DN			"cn=config"
	/* minimum max ids that a single index entry can map to in ldbm */
#define SLAPD_LDBM_MIN_MAXIDS		4000

#endif /* _CONFIG_H */
