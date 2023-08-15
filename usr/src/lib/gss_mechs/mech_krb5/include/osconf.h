/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * include/krb5/stock/osconf.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * Site- and OS- dependant configuration.
 */

#ifndef KRB5_OSCONF__
#define KRB5_OSCONF__

#if !defined(_WIN32)
    /* Don't try to pull in autoconf.h for Windows, since it's not used */
#ifndef KRB5_AUTOCONF__
#define KRB5_AUTOCONF__
#include "autoconf.h"
#endif
#endif

#if defined(__MACH__) && defined(__APPLE__)
# include <TargetConditionals.h>
#endif

#if defined(_WIN32)
#define DEFAULT_PROFILE_FILENAME "krb5.ini"
#define	DEFAULT_LNAME_FILENAME	"/aname"
#define	DEFAULT_KEYTAB_NAME	"FILE:%s\\krb5kt"
#else /* !_WINDOWS */
#if TARGET_OS_MAC
#define DEFAULT_SECURE_PROFILE_PATH "/Library/Preferences/edu.mit.Kerberos:/etc/krb5.conf:@SYSCONFDIR/krb5.conf"
#define DEFAULT_PROFILE_PATH        ("~/Library/Preferences/edu.mit.Kerberos" ":" DEFAULT_SECURE_PROFILE_PATH)
#define KRB5_PLUGIN_BUNDLE_DIR       "/System/Library/KerberosPlugins/KerberosFrameworkPlugins"
#define KDB5_PLUGIN_BUNDLE_DIR       "/System/Library/KerberosPlugins/KerberosDatabasePlugins"
#else
/* Solaris Kerberos */
#define DEFAULT_SECURE_PROFILE_PATH	"/etc/krb5/krb5.conf"
#define DEFAULT_PROFILE_PATH        DEFAULT_SECURE_PROFILE_PATH
#endif
/* Solaris Kerberos */
#define	DEFAULT_KEYTAB_NAME	"FILE:/etc/krb5/krb5.keytab"
#endif /* _WINDOWS  */

/* Solaris Kerberos: default for where ldap bind passwds stored */
#define DEF_SERVICE_PASSWD_FILE "/var/krb5/service_passwd"

/* Solaris Kerberos */
#define DEFAULT_KDB_FILE    "/var/krb5/principal"
#define	DEFAULT_KEYFILE_STUB	"/var/krb5/.k5."
#define KRB5_DEFAULT_ADMIN_ACL	"/etc/krb5/krb5_adm.acl"

#define	DEFAULT_ADMIN_ACL	"@LOCALSTATEDIR/krb5kdc/kadm_old.acl"

/* Location of KDC profile */
/* Solaris Kerberos */
#define	DEFAULT_KDC_PROFILE	"/etc/krb5/kdc.conf"
#define	KDC_PROFILE_ENV		"KRB5_KDC_PROFILE"

#if TARGET_OS_MAC
#define DEFAULT_KDB_LIB_PATH	{ KDB5_PLUGIN_BUNDLE_DIR, "@MODULEDIR/kdb", NULL }
#else
/* Solaris Kerberos */
#define DEFAULT_KDB_LIB_PATH	{ "/usr/lib/krb5", NULL }
#endif

/*
 * SUNW14resync
 * MIT 1.4 has changed to ENCTYPE_DES3_CBC_SHA1 but we stick with the old one
 * for backward compat.
 */
#define DEFAULT_KDC_ENCTYPE	ENCTYPE_DES_CBC_CRC
#define	KDCRCACHE		"dfl:krb5kdc_rcache"

#define KDC_PORTNAME		"kerberos" /* for /etc/services or equiv. */
#define KDC_SECONDARY_PORTNAME	"kerberos-sec" /* For backwards */
					    /* compatibility with */
					    /* port 750 clients */

#define KRB5_DEFAULT_PORT	88
#define KRB5_DEFAULT_SEC_PORT	750

#define DEFAULT_KPASSWD_PORT	464
#define KPASSWD_PORTNAME "kpasswd"

#define DEFAULT_KDC_UDP_PORTLIST "88,750"
/* Solaris Kerberos: enabled TCP by default on port 88 */
#define DEFAULT_KDC_TCP_PORTLIST	"88"

/* Solaris Kerberos: control # of kdc tcp connection */
#define	DEFAULT_KDC_TCP_CONNECTIONS	30
#define	MIN_KDC_TCP_CONNECTIONS	10

/*
 * Defaults for the KADM5 admin system.
 */
/* Solaris Kerberos */
#define DEFAULT_KADM5_KEYTAB	"/etc/krb5/kadm5.keytab"
#define DEFAULT_KADM5_ACL_FILE	"/etc/krb5/kadm5.acl"
#define DEFAULT_KADM5_PORT	749 /* assigned by IANA */

#define MAX_DGRAM_SIZE	4096
#define MAX_SKDC_TIMEOUT 30
#define SKDC_TIMEOUT_SHIFT 2		/* left shift of timeout for backoff */
#define SKDC_TIMEOUT_1 1		/* seconds for first timeout */

#define KRB5_ENV_CCNAME	"KRB5CCNAME"

/*
 * krb5 slave support follows
 */

/* Solaris Kerberos */
#define KPROP_DEFAULT_FILE "/var/krb5/slave_datatrans"
#define KPROPD_DEFAULT_FILE "/var/krb5/from_master"
#define KPROPD_DEFAULT_KDB5_UTIL "/usr/sbin/kdb5_util"
#define KPROPD_DEFAULT_KDB5_EDIT "/usr/sbin/kdb5_edit"
#define KPROPD_DEFAULT_KRB_DB DEFAULT_KDB_FILE
#define KPROPD_ACL_FILE "/etc/krb5/kpropd.acl"

#endif /* KRB5_OSCONF__ */
