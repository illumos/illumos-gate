/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Least privilege support functions.
 */

#include "config.h"

#ifdef SOLARIS_PRIVS
#include <priv.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
#endif /* SOLARIS_PRIVS */

#include "proto.h"

#ifdef SOLARIS_PRIVS
/* When ununitialized, this indicates we still have all privs */
static priv_set_t *uprivs;
#endif /* SOLARIS_PRIVS */

#ifdef SOLARIS_PRIVS
#ifdef PRIVS_DEBUG
static void print_privs(priv_ptype_t which, const char *str)
{
    priv_set_t *privset;
    char *privstr;

    if ((privset = priv_allocset()) == NULL)
	return;

    (void) getppriv(which, privset);
    privstr = priv_set_to_str(privset, ',', PRIV_STR_SHORT);
    syslog(LOG_DEBUG, "%s: %s", str, privstr);
    free(privstr);
    priv_freeset(privset);
}
#endif /* PRIVS_DEBUG */

static void priv_on(const char *priv)
{
    /* no need to add the privilege if already have it */
    if (uprivs == NULL || priv_ismember(uprivs, priv))
	return;

    if (priv_set(PRIV_ON, PRIV_EFFECTIVE, priv, NULL) == -1)
	syslog(LOG_ERR, "priv_set: error adding privilege %s: %m", priv);
}

static void priv_off(const char *priv)
{
    /* don't remove the privilege if already had it */
    if (uprivs == NULL || priv_ismember(uprivs, priv))
	return;

    if (priv_set(PRIV_OFF, PRIV_EFFECTIVE, priv, NULL) == -1)
	syslog(LOG_ERR, "priv_set: error removing privilege %s: %m", priv);
}
#endif /* SOLARIS_PRIVS */

/*
 * init_privs() is called after a user has logged in to drop from the
 * permitted privilege set those privileges which are no longer required.
 */
/*ARGSUSED*/
void init_privs(const char *username)
{
#ifdef SOLARIS_PRIVS
    uid_t euid = geteuid();
    priv_set_t *pset1, *pset2;

    /*
     * The FTP server runs with the inheritable set and the limit set
     * filled in through user_attr (or with default values of basic and all).
     * The privileges available to the user at login, is an intersection
     * of both those sets.  The only way to limit the root user is by
     * changing the limit set, not by changing the I set.
     */
    if ((pset1 = priv_allocset()) == NULL ||
	(uprivs = priv_allocset()) == NULL ||
	(pset2 = priv_allocset()) == NULL) {
	    syslog(LOG_ERR, "priv_allocset failed: %m");
	    dologout(1);
    }
    if (getppriv(PRIV_LIMIT, pset1) == -1) {
	syslog(LOG_ERR, "getppriv(limit) failed: %m");
	dologout(1);
    }
    if (getppriv(euid == 0 ? PRIV_PERMITTED : PRIV_INHERITABLE, pset2) == -1) {
	syslog(LOG_ERR, "getppriv() failed: %m");
	dologout(1);
    }

    /* Compute the permitted set after login. */
    priv_intersect(pset2, pset1);

    /*
     * Set the permitted privilege set to the allowable privileges plus
     * those required after init_privs() is called. Keep note of which
     * effective privileges we already had in uprivs so we don't turn
     * them off.
     */
    priv_emptyset(pset2);
    (void) priv_addset(pset2, PRIV_PROC_SETID);
    (void) priv_addset(pset2, PRIV_NET_PRIVADDR);
    (void) priv_addset(pset2, PRIV_FILE_DAC_READ);
    (void) priv_addset(pset2, PRIV_FILE_DAC_SEARCH);
    (void) priv_addset(pset2, PRIV_FILE_CHOWN);

    priv_copyset(pset2, uprivs);
    priv_intersect(pset1, uprivs);

    /* Now, set the effective privileges. */
    if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pset1) == -1) {
	syslog(LOG_ERR,
	    "unable to set privileges for %s: setppriv(effective): %m",
	    username);
	dologout(1);
    }

#if defined(SOLARIS_BSM_AUDIT) && !defined(SOLARIS_NO_AUDIT_FTPD_LOGOUT)
    /* needed for audit_ftpd_logout() */
    (void) priv_addset(pset1, PRIV_PROC_AUDIT);
#endif
    /* And set the permitted, adding ftpd's required privileges in the mix. */
    priv_union(pset2, pset1);
    if (setppriv(PRIV_SET, PRIV_PERMITTED, pset1) == -1) {
	syslog(LOG_ERR,
	    "unable to set privileges for %s: setppriv(permitted): %m",
	    username);
	dologout(1);
    }
    /*
     * setppriv() has made us privilege aware, so the effective privileges
     * are no longer modified by user ID changes.
     */
    priv_freeset(pset1);
    priv_freeset(pset2);

    /* set the real, effective and saved group ID's */
    setid_priv_on(0);
    if (setgid(getegid()) != 0) {
	syslog(LOG_ERR, "setgid(%d) failed: %m", getegid());
	setid_priv_off(euid);
	dologout(1);
    }
    /*
     * Set the real and effective user ID's, leaving the saved user ID set
     * to 0 so seteuid(0) succeeds.
     */
    (void) seteuid(0);
    if (setreuid(euid, -1) != 0) {
	syslog(LOG_ERR, "setreuid(%d, -1) failed: %m", euid);
	setid_priv_off(euid);
	dologout(1);
    }
    setid_priv_off(euid);
    if (seteuid(euid) != 0) {
	syslog(LOG_ERR, "seteuid(%d) failed: %m", euid);
	dologout(1);
    }

#ifdef PRIVS_DEBUG
    print_privs(PRIV_EFFECTIVE, "effective privilege set");
    print_privs(PRIV_PERMITTED, "permitted privilege set");
    print_privs(PRIV_INHERITABLE, "inheritable privilege set");
    print_privs(PRIV_LIMIT, "limit privilege set");
#endif /* PRIVS_DEBUG */
#endif /* SOLARIS_PRIVS */
}

/* allow a process to bind to a privileged port */
/*ARGSUSED*/
void port_priv_on(uid_t uid)
{
    delay_signaling();
#ifdef SOLARIS_PRIVS
    priv_on(PRIV_NET_PRIVADDR);
#else
    (void) seteuid(uid);
#endif
}

/*ARGSUSED*/
void port_priv_off(uid_t uid)
{
#ifdef SOLARIS_PRIVS
    priv_off(PRIV_NET_PRIVADDR);
#else
    (void) seteuid(uid);
#endif
    enable_signaling();
}

/* allow a process to read any file or directory and to search any directory */
void access_priv_on(uid_t uid)
{
    delay_signaling();
#ifdef SOLARIS_PRIVS
    priv_on(PRIV_FILE_DAC_READ);
    priv_on(PRIV_FILE_DAC_SEARCH);
#endif
    /* necessary on Solaris for access over NFS */
    (void) seteuid(uid);
}

void access_priv_off(uid_t uid)
{
#ifdef SOLARIS_PRIVS
    priv_off(PRIV_FILE_DAC_READ);
    priv_off(PRIV_FILE_DAC_SEARCH);
#endif
    (void) seteuid(uid);
    enable_signaling();
}

/* allow a process to set its user IDs and group IDs */
/*ARGSUSED*/
void setid_priv_on(uid_t uid)
{
    delay_signaling();
#ifdef SOLARIS_PRIVS
    priv_on(PRIV_PROC_SETID);
#else
    (void) seteuid(uid);
#endif
}

/*ARGSUSED*/
void setid_priv_off(uid_t uid)
{
#ifdef SOLARIS_PRIVS
    priv_off(PRIV_PROC_SETID);
#else
    (void) seteuid(uid);
#endif
    enable_signaling();
}

/* allow a process to change the ownership of files and directories */
void chown_priv_on(uid_t uid)
{
    delay_signaling();
#ifdef SOLARIS_PRIVS
    priv_on(PRIV_FILE_CHOWN);
#endif
    /* necessary on Solaris for chown over NFS */
    (void) seteuid(uid);
}

void chown_priv_off(uid_t uid)
{
#ifdef SOLARIS_PRIVS
    priv_off(PRIV_FILE_CHOWN);
#endif
    (void) seteuid(uid);
    enable_signaling();
}
