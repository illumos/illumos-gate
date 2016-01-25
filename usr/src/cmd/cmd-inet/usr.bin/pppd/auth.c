/*
 * auth.c - PPP authentication and phase control.
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1993 The Australian National University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the Australian National University.  The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
#define RCSID	"$Id: auth.c,v 1.65 2000/04/15 01:27:10 masputra Exp $"

/* Pull in crypt() definition. */
#define __EXTENSIONS__

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <utmp.h>
#include <fcntl.h>
#if defined(_PATH_LASTLOG) && (defined(_linux_) || defined(__linux__))
#include <lastlog.h>
#endif

#if defined(_linux_) || defined(__linux__)
#include <crypt.h>
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Backward compatibility with old Makefiles */
#if defined(USE_PAM) && !defined(ALLOW_PAM)
#define ALLOW_PAM
#endif

#ifdef ALLOW_PAM
#include <security/pam_appl.h>
#endif

#ifdef HAS_SHADOW
#include <shadow.h>
#ifndef PW_PPP
#define PW_PPP PW_LOGIN
#endif
#endif

#include "pppd.h"
#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"
#include "upap.h"
#include "chap.h"
#ifdef CBCP_SUPPORT
#include "cbcp.h"
#endif
#include "pathnames.h"

#if !defined(lint) && !defined(_lint)
static const char rcsid[] = RCSID;
#endif

/* Bits in scan_authfile return value */
#define NONWILD_SERVER	1
#define NONWILD_CLIENT	2

#define ISWILD(word)	(word[0] == '*' && word[1] == '\0')

/* The name by which the peer authenticated itself to us. */
char peer_authname[MAXNAMELEN];

/* Records which authentication operations haven't completed yet. */
static int auth_pending[NUM_PPP];

/* Set if we have successfully called plogin() */
static int logged_in;

/* List of addresses which the peer may use. */
static struct permitted_ip *addresses[NUM_PPP];

/* Wordlist giving addresses which the peer may use
   without authenticating itself. */
static struct wordlist *noauth_addrs;

/* Extra options to apply, from the secrets file entry for the peer. */
static struct wordlist *extra_options;

/* Source of those extra options. */
static const char *extra_opt_filename;
static int extra_opt_line;

/* Number of network protocols which we have opened. */
static int num_np_open;

/* Number of network protocols which have come up. */
static int num_np_up;

/* Set if we got the contents of passwd[] from the pap-secrets file. */
static int passwd_from_file;

/* Set if we require authentication only because we have a default route. */
static bool default_auth;

/* Hook to enable a plugin to control the idle time limit */
int (*idle_time_hook) __P((struct ppp_idle *)) = NULL;

/* Hook for a plugin to say whether we can possibly authenticate any peer */
int (*pap_check_hook) __P((void)) = NULL;

/* Hook for a plugin to check the PAP user and password */
int (*pap_auth_hook) __P((char *user, char *passwd, char **msgp,
			  struct wordlist **paddrs,
			  struct wordlist **popts)) = NULL;

/* Hook for a plugin to know about the PAP user logout */
void (*pap_logout_hook) __P((void)) = NULL;

/* Hook for a plugin to get the PAP password for authenticating us */
int (*pap_passwd_hook) __P((char *user, char *passwd)) = NULL;

/*
 * This is used to ensure that we don't start an auth-up/down
 * script while one is already running.
 */
enum script_state {
    s_down,
    s_up
};

static enum script_state auth_state = s_down;
static enum script_state auth_script_state = s_down;
static pid_t auth_script_pid = 0;

/*
 * This is set by scan_authfile if a client matches, but server doesn't
 * (possible configuration error).
 */
static char scan_server_match_failed[MAXWORDLEN];

/*
 * Option variables.
 */
bool uselogin = 0;		/* Use /etc/passwd for checking PAP */
bool cryptpap = 0;		/* Passwords in pap-secrets are encrypted */
bool refuse_pap = 0;		/* Don't wanna auth. ourselves with PAP */
bool refuse_chap = 0;		/* Don't wanna auth. ourselves with CHAP */
bool usehostname = 0;		/* Use hostname for our_name */
bool auth_required = 0;		/* Always require authentication from peer */
bool allow_any_ip = 0;		/* Allow peer to use any IP address */
bool explicit_remote = 0;	/* User specified explicit remote name */
char remote_name[MAXNAMELEN];	/* Peer's name for authentication */

#ifdef CHAPMS
bool refuse_mschap = 0;		/* Don't wanna auth. ourself with MS-CHAPv1 */
#else
bool refuse_mschap = 1;		/* Never auth. ourself with MS-CHAPv1 */
#endif
#ifdef CHAPMSV2
bool refuse_mschapv2 = 0;	/* Don't wanna auth. ourself with MS-CHAPv2 */
#else
bool refuse_mschapv2 = 1;	/* Never auth. ourself with MS-CHAPv2 */
#endif

#ifdef USE_PAM
bool use_pam = 1;		/* Enable use of PAM by default */
#else
bool use_pam = 0;		/* Disable use of PAM by default */
#endif

/* Bits in auth_pending[] */
#define PAP_WITHPEER	1
#define PAP_PEER	2
#define CHAP_WITHPEER	4
#define CHAP_PEER	8

/* Prototypes for procedures local to this file. */

static void network_phase __P((int));
static void check_idle __P((void *));
static void connect_time_expired __P((void *));
static int  plogin __P((char *, char *, char **));
static void plogout __P((void));
static int  null_login __P((int));
static int  get_pap_passwd __P((char *));
static int  have_pap_secret __P((int *));
static int  have_chap_secret __P((char *, char *, int, int *));
static int  ip_addr_check __P((u_int32_t, struct permitted_ip *));
static int  scan_authfile __P((FILE *, char *, char *, char *,
			       struct wordlist **, struct wordlist **,
			       char *));
static void free_wordlist __P((struct wordlist *));
static void auth_script __P((char *));
static void auth_script_done __P((void *, int));
static void set_allowed_addrs __P((int, struct wordlist *, struct wordlist *));
static int  some_ip_ok __P((struct wordlist *));
static int  setupapfile __P((char **, option_t *));
static int  privgroup __P((char **, option_t *));
static int  set_noauth_addr __P((char **, option_t *));
static void check_access __P((FILE *, char *));

/*
 * Authentication-related options.
 */
option_t auth_options[] = {
    { "require-pap", o_bool, &lcp_wantoptions[0].neg_upap,
      "Require PAP authentication from peer", 1, &auth_required },
    { "+pap", o_bool, &lcp_wantoptions[0].neg_upap,
      "Require PAP authentication from peer", 1, &auth_required },
    { "refuse-pap", o_bool, &refuse_pap,
      "Don't agree to auth to peer with PAP", 1 },
    { "-pap", o_bool, &refuse_pap,
      "Don't allow PAP authentication with peer", 1 },
    { "require-chap", o_bool, &lcp_wantoptions[0].neg_chap,
      "Require CHAP authentication from peer", 1, &auth_required },
    { "+chap", o_bool, &lcp_wantoptions[0].neg_chap,
      "Require CHAP authentication from peer", 1, &auth_required },
    { "refuse-chap", o_bool, &refuse_chap,
      "Don't agree to auth to peer with CHAP", 1 },
    { "-chap", o_bool, &refuse_chap,
      "Don't allow CHAP authentication with peer", 1 },
    { "name", o_string, our_name,
      "Set local name for authentication",
      OPT_PRIV|OPT_STATIC, NULL, MAXNAMELEN },
    { "user", o_string, user,
      "Set name for auth with peer", OPT_STATIC, NULL, MAXNAMELEN },
    { "usehostname", o_bool, &usehostname,
      "Must use hostname for authentication", 1 },
    { "remotename", o_string, remote_name,
      "Set remote name for authentication", OPT_STATIC,
      &explicit_remote, MAXNAMELEN },
    { "auth", o_bool, &auth_required,
      "Require authentication from peer", 1 },
    { "noauth", o_bool, &auth_required,
      "Don't require peer to authenticate", OPT_PRIV, &allow_any_ip },
    {  "login", o_bool, &uselogin,
      "Use system password database for PAP", 1 },
    { "papcrypt", o_bool, &cryptpap,
      "PAP passwords are encrypted", 1 },
    { "+ua", o_special, (void *)setupapfile,
      "Get PAP user and password from file" },
    { "password", o_string, passwd,
      "Password for authenticating us to the peer", OPT_STATIC,
      NULL, MAXSECRETLEN },
    { "privgroup", o_special, (void *)privgroup,
      "Allow group members to use privileged options", OPT_PRIV },
    { "allow-ip", o_special, (void *)set_noauth_addr,
      "Set peer IP address(es) usable without authentication",
      OPT_PRIV },
#ifdef CHAPMS
    { "require-mschap", o_bool, &lcp_wantoptions[0].neg_mschap,
      "Require MS-CHAPv1 authentication from peer", 1, &auth_required },
    { "refuse-mschap", o_bool, &refuse_mschap,
      "Don't agree to authenticate to peer with MS-CHAPv1", 1 },
#endif
#ifdef CHAPMSV2
    { "require-mschapv2", o_bool, &lcp_wantoptions[0].neg_mschapv2,
      "Require MS-CHAPv2 authentication from peer", 1, &auth_required },
    { "refuse-mschapv2", o_bool, &refuse_mschapv2,
      "Don't agree to authenticate to peer with MS-CHAPv2", 1 },
#endif
#ifdef ALLOW_PAM
    { "pam", o_bool, &use_pam,
      "Enable use of Pluggable Authentication Modules", OPT_PRIV|1 },
    { "nopam", o_bool, &use_pam,
      "Disable use of Pluggable Authentication Modules", OPT_PRIV|0 },
#endif
    { NULL }
};

/*
 * setupapfile - specifies UPAP info for authenticating with peer.
 */
/*ARGSUSED*/
static int
setupapfile(argv, opt)
    char **argv;
    option_t *opt;
{
    FILE * ufile;
    int l;

    lcp_allowoptions[0].neg_upap = 1;

    /* open user info file */
    (void) seteuid(getuid());
    ufile = fopen(*argv, "r");
    (void) seteuid(0);
    if (ufile == NULL) {
	option_error("unable to open user login data file %s", *argv);
	return 0;
    }
    check_access(ufile, *argv);

    /* get username */
    if (fgets(user, MAXNAMELEN - 1, ufile) == NULL
	|| fgets(passwd, MAXSECRETLEN - 1, ufile) == NULL){
	option_error("unable to read user login data file %s", *argv);
	return 0;
    }
    (void) fclose(ufile);

    /* get rid of newlines */
    l = strlen(user);
    if (l > 0 && user[l-1] == '\n')
	user[l-1] = '\0';
    l = strlen(passwd);
    if (l > 0 && passwd[l-1] == '\n')
	passwd[l-1] = '\0';

    return (1);
}


/*
 * privgroup - allow members of the group to have privileged access.
 */
/*ARGSUSED*/
static int
privgroup(argv, opt)
    char **argv;
    option_t *opt;
{
    struct group *g;
    int i;

    g = getgrnam(*argv);
    if (g == NULL) {
	option_error("group %s is unknown", *argv);
	return 0;
    }
    for (i = 0; i < ngroups; ++i) {
	if (groups[i] == g->gr_gid) {
	    privileged = 1;
	    break;
	}
    }
    return 1;
}


/*
 * set_noauth_addr - set address(es) that can be used without authentication.
 * Equivalent to specifying an entry like `"" * "" addr' in pap-secrets.
 */
/*ARGSUSED*/
static int
set_noauth_addr(argv, opt)
    char **argv;
    option_t *opt;
{
    char *addr = *argv;
    int l = strlen(addr);
    struct wordlist *wp;

    wp = (struct wordlist *) malloc(sizeof(struct wordlist) + l + 1);
    if (wp == NULL)
	novm("allow-ip argument");
    wp->word = (char *) (wp + 1);
    wp->next = noauth_addrs;
    (void) strcpy(wp->word, addr);
    noauth_addrs = wp;
    return 1;
}

/*
 * An Open on LCP has requested a change from Dead to Establish phase.
 * Do what's necessary to bring the physical layer up.
 */
/*ARGSUSED*/
void
link_required(unit)
    int unit;
{
}

/*
 * LCP has terminated the link; go to the Dead phase and take the
 * physical layer down.
 */
/*ARGSUSED*/
void
link_terminated(unit)
    int unit;
{
    const char *pn1, *pn2;

    if (phase == PHASE_DEAD)
	return;
    if (pap_logout_hook != NULL) {
	(*pap_logout_hook)();
    } else {
	if (logged_in)
	    plogout();
    }
    new_phase(PHASE_DEAD);
    if (peer_nak_auth) {
	if ((pn1 = protocol_name(nak_auth_orig)) == NULL)
	    pn1 = "?";
	if ((pn2 = protocol_name(nak_auth_proto)) == NULL)
	    pn2 = "?";
	warn("Peer sent Configure-Nak for 0x%x (%s) to suggest 0x%x (%s)",
	    nak_auth_orig, pn1, nak_auth_proto, pn2);
    }
    if (unsolicited_nak_auth) {
	if ((pn1 = protocol_name(unsolicit_auth_proto)) == NULL)
	    pn1 = "?";
	warn("Peer unexpectedly asked us to authenticate with 0x%x (%s)",
	    unsolicit_auth_proto, pn1);
    }
    if (peer_reject_auth) {
	if ((pn1 = protocol_name(reject_auth_proto)) == NULL)
	    pn1 = "?";
	warn("Peer rejected our demand for 0x%x (%s)",
	    reject_auth_proto, pn1);
    }
    if (naked_peers_auth) {
	if ((pn1 = protocol_name(naked_auth_orig)) == NULL)
	    pn1 = "?";
	if ((pn2 = protocol_name(naked_auth_proto)) == NULL)
	    pn2 = "?";
	warn("We set Configure-Nak for 0x%x (%s) to suggest 0x%x (%s)",
	    naked_auth_orig, pn1, naked_auth_proto, pn2);
    }
    if (rejected_peers_auth) {
	if ((pn1 = protocol_name(rejected_auth_proto)) == NULL)
	    pn1 = "?";
	warn("We rejected the peer's demand for 0x%x (%s)",
	    rejected_auth_proto, pn1);
    }

    peer_nak_auth = unsolicited_nak_auth = peer_reject_auth =
	rejected_peers_auth = naked_peers_auth = 0;
    nak_auth_proto = nak_auth_orig = unsolicit_auth_proto = reject_auth_proto =
	rejected_auth_proto = naked_auth_orig = naked_auth_proto = 0;
    notice("Connection terminated.");
}

/*
 * LCP has gone down; it will either die or try to re-establish.
 */
void
link_down(unit)
    int unit;
{
    int i;
    struct protent *protp;

    auth_state = s_down;
    if (auth_script_state == s_up && auth_script_pid == 0) {
	update_link_stats(unit);
	auth_script_state = s_down;
	auth_script(_PATH_AUTHDOWN);
    }
    for (i = 0; (protp = protocols[i]) != NULL; ++i) {
	if (!protp->enabled_flag)
	    continue;
        if (protp->protocol != PPP_LCP && protp->lowerdown != NULL)
	    (*protp->lowerdown)(unit);
        if (protp->protocol < 0xC000 && protp->close != NULL)
	    (*protp->close)(unit, "LCP down");
    }
    num_np_open = 0;
    num_np_up = 0;
    if (phase != PHASE_DEAD)
	new_phase(PHASE_TERMINATE);
}

/*
 * The link is established.
 * Proceed to the Dead, Authenticate or Network phase as appropriate.
 */
void
link_established(unit)
    int unit;
{
    int auth;
    lcp_options *wo = &lcp_wantoptions[unit];
    lcp_options *go = &lcp_gotoptions[unit];
    lcp_options *ho = &lcp_hisoptions[unit];
    int i;
    struct protent *protp;

    /*
     * Tell higher-level protocols that LCP is up.
     */
    for (i = 0; (protp = protocols[i]) != NULL; ++i)
        if (protp->protocol != PPP_LCP && protp->enabled_flag
	    && protp->lowerup != NULL)
	    (*protp->lowerup)(unit);

    if (auth_required && !(go->neg_chap || go->neg_mschap ||
	go->neg_mschapv2 || go->neg_upap)) {
	/*
	 * We wanted the peer to authenticate itself, and it refused:
	 * if we have some address(es) it can use without auth, fine,
	 * otherwise treat it as though it authenticated with PAP using
	 * a username * of "" and a password of "".  If that's not OK,
	 * boot it out.
	 */
	if (noauth_addrs != NULL) {
	    set_allowed_addrs(unit, noauth_addrs, NULL);
	} else if (!wo->neg_upap || !null_login(unit)) {
	    warn("peer refused to authenticate: terminating link");
	    lcp_close(unit, "peer refused to authenticate");
	    status = EXIT_PEER_AUTH_FAILED;
	    return;
	}
    }

    new_phase(PHASE_AUTHENTICATE);
    auth = 0;
    if (go->neg_chap || go->neg_mschap || go->neg_mschapv2) {
	if (go->neg_chap) {
	    if (debug)
		dbglog("Authenticating peer with standard CHAP");
	    go->chap_mdtype = CHAP_DIGEST_MD5;
	} else if (go->neg_mschap) {
	    if (debug)
		dbglog("Authenticating peer with MS-CHAPv1");
	    go->chap_mdtype = CHAP_MICROSOFT;
	} else {
	    if (debug)
		dbglog("Authenticating peer with MS-CHAPv2");
	    go->chap_mdtype = CHAP_MICROSOFT_V2;
	}
	ChapAuthPeer(unit, our_name, go->chap_mdtype);
	auth |= CHAP_PEER;
    } else if (go->neg_upap) {
	if (debug)
	    dbglog("Authenticating peer with PAP");
	upap_authpeer(unit);
	auth |= PAP_PEER;
    }
    if (ho->neg_chap || ho->neg_mschap || ho->neg_mschapv2) {
	switch (ho->chap_mdtype) {
	case CHAP_DIGEST_MD5:
	    if (debug)
		dbglog("Authenticating to peer with standard CHAP");
	    break;
	case CHAP_MICROSOFT:
	    if (debug)
		dbglog("Authenticating to peer with MS-CHAPv1");
	    break;
	case CHAP_MICROSOFT_V2:
	    if (debug)
		dbglog("Authenticating to peer with MS-CHAPv2");
	    break;
	default:
	    if (debug)
		dbglog("Authenticating to peer with CHAP 0x%x", ho->chap_mdtype);
	    break;
	}
	ChapAuthWithPeer(unit, user, ho->chap_mdtype);
	auth |= CHAP_WITHPEER;
    } else if (ho->neg_upap) {
	if (passwd[0] == '\0') {
	    passwd_from_file = 1;
	    if (!get_pap_passwd(passwd))
		error("No secret found for PAP login");
	}
	if (debug)
	    dbglog("Authenticating to peer with PAP");
	upap_authwithpeer(unit, user, passwd);
	auth |= PAP_WITHPEER;
    }
    auth_pending[unit] = auth;

    if (!auth)
	network_phase(unit);
}

/*
 * Proceed to the network phase.
 */
static void
network_phase(unit)
    int unit;
{
    lcp_options *go = &lcp_gotoptions[unit];

    /*
     * If the peer had to authenticate, run the auth-up script now.
     */
    if (go->neg_chap || go->neg_mschap || go->neg_mschapv2 || go->neg_upap) {
	auth_state = s_up;
	if (auth_script_state == s_down && auth_script_pid == 0) {
	    auth_script_state = s_up;
	    auth_script(_PATH_AUTHUP);
	}
    }

    /*
     * Process extra options from the secrets file
     */
    if (extra_options != NULL) {
	option_source = (char *)extra_opt_filename;
	option_line = extra_opt_line;
	(void) options_from_list(extra_options, 1);
	free_wordlist(extra_options);
	extra_options = NULL;
    }

#ifdef CBCP_SUPPORT
    /*
     * If we negotiated callback, do it now.
     */
    if (go->neg_cbcp) {
	new_phase(PHASE_CALLBACK);
	(*cbcp_protent.open)(unit);
	return;
    }
#endif

    start_networks();
}

void
start_networks()
{
    int i;
    struct protent *protp;

    new_phase(PHASE_NETWORK);

#ifdef HAVE_MULTILINK
    if (multilink) {
	if (mp_join_bundle()) {
	    if (updetach && !nodetach)
		detach();
	    return;
	}
    }
#endif /* HAVE_MULTILINK */

#if 0
    if (!demand)
	set_filters(&pass_filter, &active_filter);
#endif
    for (i = 0; (protp = protocols[i]) != NULL; ++i)
        if (protp->protocol < 0xC000 && protp->enabled_flag
	    && protp->open != NULL) {
	    (*protp->open)(0);
	    if (protp->protocol != PPP_CCP)
		++num_np_open;
	}

    if (num_np_open == 0)
	/* nothing to do */
	lcp_close(0, "No network protocols running");
}

/*
 * The peer has failed to authenticate himself using `protocol'.
 */
/*ARGSUSED*/
void
auth_peer_fail(unit, protocol)
    int unit, protocol;
{
    /*
     * Authentication failure: take the link down
     */
    lcp_close(unit, "Authentication failed");
    status = EXIT_PEER_AUTH_FAILED;
}

/*
 * The peer has been successfully authenticated using `protocol'.
 */
void
auth_peer_success(unit, protocol, name, namelen)
    int unit, protocol;
    char *name;
    int namelen;
{
    int bit;

    switch (protocol) {
    case PPP_CHAP:
	bit = CHAP_PEER;
	break;
    case PPP_PAP:
	bit = PAP_PEER;
	break;
    default:
	warn("auth_peer_success: unknown protocol %x", protocol);
	return;
    }

    /*
     * Save the authenticated name of the peer for later.
     */
    if (namelen > sizeof(peer_authname) - 1)
	namelen = sizeof(peer_authname) - 1;
    BCOPY(name, peer_authname, namelen);
    peer_authname[namelen] = '\0';
    script_setenv("PEERNAME", peer_authname, 0);

    /*
     * If there is no more authentication still to be done,
     * proceed to the network (or callback) phase.
     */
    if ((auth_pending[unit] &= ~bit) == 0)
        network_phase(unit);
}

/*
 * We have failed to authenticate ourselves to the peer using `protocol'.
 */
/*ARGSUSED*/
void
auth_withpeer_fail(unit, protocol)
    int unit, protocol;
{
    if (passwd_from_file)
	BZERO(passwd, MAXSECRETLEN);
    /*
     * We've failed to authenticate ourselves to our peer.
     * Some servers keep sending CHAP challenges, but there
     * is no point in persisting without any way to get updated
     * authentication secrets.
     */
    lcp_close(unit, "Failed to authenticate ourselves to peer");
    status = EXIT_AUTH_TOPEER_FAILED;
}

/*
 * We have successfully authenticated ourselves with the peer using `protocol'.
 */
void
auth_withpeer_success(unit, protocol)
    int unit, protocol;
{
    int bit;

    switch (protocol) {
    case PPP_CHAP:
	bit = CHAP_WITHPEER;
	break;
    case PPP_PAP:
	if (passwd_from_file)
	    BZERO(passwd, MAXSECRETLEN);
	bit = PAP_WITHPEER;
	break;
    default:
	warn("auth_withpeer_success: unknown protocol %x", protocol);
	bit = 0;
    }

    /*
     * If there is no more authentication still being done,
     * proceed to the network (or callback) phase.
     */
    if ((auth_pending[unit] &= ~bit) == 0)
	network_phase(unit);
}


/*
 * np_up - a network protocol has come up.
 */
/*ARGSUSED*/
void
np_up(unit, proto)
    int unit, proto;
{
    int tlim;

    if (num_np_up == 0) {
	/*
	 * At this point we consider that the link has come up successfully.
	 */
	status = EXIT_OK;
	unsuccess = 0;

	peer_nak_auth = unsolicited_nak_auth = peer_reject_auth =
	    rejected_peers_auth = naked_peers_auth = 0;
	nak_auth_proto = nak_auth_orig = unsolicit_auth_proto = 
	    reject_auth_proto = rejected_auth_proto = naked_auth_orig =
	    naked_auth_proto = 0;

	new_phase(PHASE_RUNNING);

	if (idle_time_hook != NULL)
	    tlim = (*idle_time_hook)(NULL);
	else
	    tlim = idle_time_limit;
	if (tlim > 0)
	    TIMEOUT(check_idle, NULL, tlim);

	/*
	 * Set a timeout to close the connection once the maximum
	 * connect time has expired.
	 */
	if (maxconnect > 0) {
	    TIMEOUT(connect_time_expired, &lcp_fsm[unit], maxconnect);

	    /*
	     * Tell LCP to send Time-Remaining packets.  One should be
	     * sent out now, at maxconnect-300, at maxconnect-120, and
	     * again at maxconnect-30.
	     */
	    lcp_settimeremaining(unit, maxconnect, maxconnect);
	    if (maxconnect > 300)
		lcp_settimeremaining(unit, maxconnect, 300);
	    if (maxconnect > 120)
		lcp_settimeremaining(unit, maxconnect, 120);
	    if (maxconnect > 30)
		lcp_settimeremaining(unit, maxconnect, 30);
	}

	/*
	 * Detach now, if the updetach option was given.
	 */
	if (updetach && !nodetach)
	    detach();
    }
    ++num_np_up;
}

/*
 * np_down - a network protocol has gone down.
 */
/*ARGSUSED*/
void
np_down(unit, proto)
    int unit, proto;
{
    if (--num_np_up == 0) {
	UNTIMEOUT(check_idle, NULL);
	new_phase(PHASE_NETWORK);
    }
}

/*
 * np_finished - a network protocol has finished using the link.
 */
/*ARGSUSED*/
void
np_finished(unit, proto)
    int unit, proto;
{
    if (--num_np_open <= 0) {
	/* no further use for the link: shut up shop. */
	lcp_close(0, "No network protocols running");
    }
}

/*
 * check_idle - check whether the link has been idle for long
 * enough that we can shut it down.
 */
/*ARGSUSED*/
static void
check_idle(arg)
    void *arg;
{
    struct ppp_idle idle;
    time_t itime;
    int tlim;

    if (!get_idle_time(0, &idle))
	return;
    if (idle_time_hook != NULL) {
	tlim = (*idle_time_hook)(&idle);
    } else {
	itime = MIN(idle.xmit_idle, idle.recv_idle);
	tlim = idle_time_limit - itime;
    }
    if (tlim <= 0) {
	/* link is idle: shut it down. */
	notice("Terminating connection due to lack of activity.");
	lcp_close(0, "Link inactive");
	need_holdoff = 0;
	status = EXIT_IDLE_TIMEOUT;
    } else {
	TIMEOUT(check_idle, NULL, tlim);
    }
}

/*
 * connect_time_expired - log a message and close the connection.
 */
/*ARGSUSED*/
static void
connect_time_expired(arg)
    void *arg;
{
    fsm *f = (fsm *)arg;

    info("Connect time expired");
    lcp_close(f->unit, "Connect time expired");	/* Close connection */
    status = EXIT_CONNECT_TIME;
}

/*
 * auth_check_options - called to check authentication options.
 */
void
auth_check_options()
{
    lcp_options *wo = &lcp_wantoptions[0];
    int can_auth;
    int lacks_ip;

    /* Default our_name to hostname, and user to our_name */
    if (our_name[0] == '\0' || usehostname)
	(void) strlcpy(our_name, hostname, sizeof(our_name));
    if (user[0] == '\0')
	(void) strlcpy(user, our_name, sizeof(user));

    /*
     * If we have a default route, require the peer to authenticate
     * unless the noauth option was given or the real user is root.
     */
    if (!auth_required && !allow_any_ip && have_route_to(0) && !privileged) {
	auth_required = 1;
	default_auth = 1;
    }

    /* If authentication is required, ask peer for CHAP or PAP. */
    if (auth_required) {
	if (!wo->neg_chap && !wo->neg_mschap && !wo->neg_mschapv2 &&
	    !wo->neg_upap) {
	    wo->neg_chap = 1;
#ifdef CHAPMS
	    wo->neg_mschap = 1;
#endif
#ifdef CHAPMSV2
	    wo->neg_mschapv2 = 1;
#endif
	    wo->chap_mdtype = CHAP_DIGEST_MD5;
	    wo->neg_upap = 1;
	}
    } else {
	wo->neg_chap = 0;
	wo->neg_mschap = 0;
	wo->neg_mschapv2 = 0;
	wo->neg_upap = 0;
    }

    /*
     * Check whether we have appropriate secrets to use
     * to authenticate the peer.
     */
    lacks_ip = 0;
    can_auth = wo->neg_upap && (uselogin || have_pap_secret(&lacks_ip));
    if (!can_auth && (wo->neg_chap || wo->neg_mschap || wo->neg_mschapv2)) {
	can_auth = have_chap_secret((explicit_remote? remote_name: NULL),
				    our_name, 1, &lacks_ip);
    }

    if (auth_required && !can_auth && noauth_addrs == NULL) {
	if (default_auth) {
	    option_error(
"By default the remote system is required to authenticate itself");
	    option_error(
"(because this system has a default route to the Internet)");
	} else if (explicit_remote)
	    option_error(
"The remote system (%s) is required to authenticate itself",
			 remote_name);
	else
	    option_error(
"The remote system is required to authenticate itself");
	option_error(
"but I couldn't find any suitable secret (password) for it to use to do so.");
	if (lacks_ip)
	    option_error(
"(None of the available passwords would let it use an IP address.)");

	exit(1);
    }
}

/*
 * auth_reset - called when LCP is starting negotiations to recheck
 * authentication options, i.e. whether we have appropriate secrets
 * to use for authenticating ourselves and/or the peer.
 */
void
auth_reset(unit)
    int unit;
{
    lcp_options *go = &lcp_gotoptions[unit];
    lcp_options *ao = &lcp_allowoptions[unit];
    int havesecret;

    ao->neg_upap = !refuse_pap && (passwd[0] != '\0' || get_pap_passwd(NULL));

    havesecret = passwd[0] != '\0' ||
	have_chap_secret(user, (explicit_remote? remote_name: NULL), 0, NULL);
    ao->neg_chap = !refuse_chap && havesecret;
    ao->neg_mschap = !refuse_mschap && havesecret;
    ao->neg_mschapv2 = !refuse_mschapv2 && havesecret;
    if (ao->neg_chap)
	ao->chap_mdtype = CHAP_DIGEST_MD5;
    else if (ao->neg_mschap)
	ao->chap_mdtype = CHAP_MICROSOFT;
    else
	ao->chap_mdtype = CHAP_MICROSOFT_V2;

    if (go->neg_upap && !uselogin && !have_pap_secret(NULL))
	go->neg_upap = 0;
    if (go->neg_chap || go->neg_mschap || go->neg_mschapv2) {
	havesecret = have_chap_secret((explicit_remote? remote_name: NULL),
		our_name, 1, NULL);
	if (!havesecret)
	    go->neg_chap = go->neg_mschap = go->neg_mschapv2 = 0;
	else if (go->neg_chap)
	    go->chap_mdtype = CHAP_DIGEST_MD5;
	else if (go->neg_mschap)
	    go->chap_mdtype = CHAP_MICROSOFT;
	else
	    go->chap_mdtype = CHAP_MICROSOFT_V2;
    }
}


/*
 * check_passwd - Check the user name and passwd against the PAP secrets
 * file.  If requested, also check against the system password database,
 * and login the user if OK.
 *
 * returns:
 *	UPAP_AUTHNAK: Authentication failed.
 *	UPAP_AUTHACK: Authentication succeeded.
 * In either case, msg points to an appropriate message.
 */
int
check_passwd(unit, auser, userlen, apasswd, passwdlen, msg)
    int unit;
    char *auser;
    int userlen;
    char *apasswd;
    int passwdlen;
    char **msg;
{
    int ret;
    char *filename;
    FILE *f;
    struct wordlist *addrs = NULL, *opts = NULL;
    char passwd[256], user[256];
    char secret[MAXWORDLEN];
    static int attempts = 0;

    /*
     * Make copies of apasswd and auser, then null-terminate them.
     * If there are unprintable characters in the password, make
     * them visible.
     */
    (void) slprintf(passwd, sizeof(passwd), "%.*v", passwdlen, apasswd);
    (void) slprintf(user, sizeof(user), "%.*v", userlen, auser);
    *msg = "";

    /*
     * Check if a plugin wants to handle this.
     */
    if (pap_auth_hook != NULL) {
	/* Set a default and allow the plug-in to change it. */
	extra_opt_filename = "plugin";
	extra_opt_line = 0;
	ret = (*pap_auth_hook)(user, passwd, msg, &addrs, &opts);
	if (ret >= 0) {
	    if (ret > 0)
		set_allowed_addrs(unit, addrs, opts);
	    BZERO(passwd, sizeof(passwd));
	    if (addrs != NULL)
		free_wordlist(addrs);
	    return ret? UPAP_AUTHACK: UPAP_AUTHNAK;
	}
    }

    /*
     * Open the file of pap secrets and scan for a suitable secret
     * for authenticating this user.
     */
    filename = _PATH_UPAPFILE;
    addrs = opts = NULL;
    ret = UPAP_AUTHNAK;
    f = fopen(filename, "r");
    if (f == NULL) {
	error("Can't open PAP password file %s: %m", filename);

    } else {
	check_access(f, filename);
	if (scan_authfile(f, user, our_name, secret, &addrs, &opts, filename) < 0) {
	    warn("no PAP secret found for %s", user);
	    if (scan_server_match_failed[0] != '\0')
		warn("possible configuration error: local name is %q, but "
		    "found %q instead", our_name, scan_server_match_failed);
	} else if (secret[0] != '\0') {
	    /* password given in pap-secrets - must match */
	    if ((!cryptpap && strcmp(passwd, secret) == 0)
		|| strcmp(crypt(passwd, secret), secret) == 0)
		ret = UPAP_AUTHACK;
	    else
		warn("PAP authentication failure for %s", user);
	} else if (uselogin) {
	    /* empty password in pap-secrets and login option */
	    ret = plogin(user, passwd, msg);
	    if (ret == UPAP_AUTHNAK)
		warn("PAP login failure for %s", user);
	} else {
	    /* empty password in pap-secrets and login option not used */
	    ret = UPAP_AUTHACK;
	}
	(void) fclose(f);
    }

    if (ret == UPAP_AUTHNAK) {
        if (**msg == '\0')
	    *msg = "Login incorrect";
	/*
	 * Frustrate passwd stealer programs.
	 * Allow 10 tries, but start backing off after 3 (stolen from login).
	 * On 10'th, drop the connection.
	 */
	if (attempts++ >= 10) {
	    warn("%d LOGIN FAILURES ON %s, %s", attempts, devnam, user);
	    lcp_close(unit, "login failed");
	}
	if (attempts > 3)
	    (void) sleep((u_int) (attempts - 3) * 5);
	if (opts != NULL)
	    free_wordlist(opts);

    } else {
	attempts = 0;			/* Reset count */
	if (**msg == '\0')
	    *msg = "Login ok";
	set_allowed_addrs(unit, addrs, opts);
    }

    if (addrs != NULL)
	free_wordlist(addrs);
    BZERO(passwd, sizeof(passwd));
    BZERO(secret, sizeof(secret));

    return ret;
}

/*
 * This function is needed for PAM.
 */

#ifdef ALLOW_PAM
/* Static variables used to communicate between the conversation function
 * and the server_login function 
 */
static char *PAM_username;
static char *PAM_password;
static int PAM_error = 0;
static pam_handle_t *pamh = NULL;

/* PAM conversation function
 * Here we assume (for now, at least) that echo on means login name, and
 * echo off means password.
 */

/*ARGSUSED*/
static int PAM_conv (int num_msg,
#ifndef SOL2
    const
#endif
    struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    int replies = 0;
    struct pam_response *reply = NULL;

#define COPY_STRING(s) (s) ? strdup(s) : NULL

    reply = malloc(sizeof(struct pam_response) * num_msg);
    if (reply == NULL)
	return PAM_CONV_ERR;

    for (replies = 0; replies < num_msg; replies++) {
        switch (msg[replies]->msg_style) {
            case PAM_PROMPT_ECHO_ON:
                reply[replies].resp_retcode = PAM_SUCCESS;
                reply[replies].resp = COPY_STRING(PAM_username);
                /* PAM frees resp */
                break;
            case PAM_PROMPT_ECHO_OFF:
                reply[replies].resp_retcode = PAM_SUCCESS;
                reply[replies].resp = COPY_STRING(PAM_password);
                /* PAM frees resp */
                break;
            case PAM_TEXT_INFO:
                /* fall through */
            case PAM_ERROR_MSG:
                /* ignore it, but pam still wants a NULL response... */
                reply[replies].resp_retcode = PAM_SUCCESS;
                reply[replies].resp = NULL;
                break;
            default:       
                /* Must be an error of some sort... */
                free (reply);
                PAM_error = 1;
                return PAM_CONV_ERR;
        }
    }
    *resp = reply;     
    return PAM_SUCCESS;
}

static struct pam_conv PAM_conversation = {
	PAM_conv, NULL
};
#endif  /* ALLOW_PAM */

/*
 * plogin - Check the user name and password against the system
 * password database, and login the user if OK.
 *
 * returns:
 *	UPAP_AUTHNAK: Login failed.
 *	UPAP_AUTHACK: Login succeeded.
 * In either case, msg points to an appropriate message.
 */

static int
plogin(user, passwd, msg)
    char *user;
    char *passwd;
    char **msg;
{
    char *tty;
#ifdef HAS_SHADOW
    struct spwd *spwd;
#endif
    struct passwd *pw = NULL;

#ifdef ALLOW_PAM
    int pam_error;

    if (use_pam) {
	if (debug)
	    dbglog("using PAM for user authentication");
	pam_error = pam_start ("ppp", user, &PAM_conversation, &pamh);
	if (pam_error != PAM_SUCCESS) {
	    *msg = (char *) pam_strerror (pamh, pam_error);
	    reopen_log();
	    return UPAP_AUTHNAK;
	}
	/*
	 * Define the fields for the credential validation
	 */

	PAM_username = user;
	PAM_password = passwd;
	PAM_error = 0;
	/* this might be useful to some modules; required for Solaris */
	tty = devnam;
	if (*tty == '\0')
	    tty = ppp_devnam;
	(void) pam_set_item(pamh, PAM_TTY, tty);
#ifdef PAM_RHOST
	(void) pam_set_item(pamh, PAM_RHOST, "");
#endif

	/*
	 * Validate the user
	 */
	pam_error = pam_authenticate (pamh, PAM_SILENT);
	if (pam_error == PAM_SUCCESS && !PAM_error) {    
	    pam_error = pam_acct_mgmt (pamh, PAM_SILENT);
	    if (pam_error == PAM_SUCCESS)
		(void) pam_open_session (pamh, PAM_SILENT);
	}

	*msg = (char *) pam_strerror (pamh, pam_error);

	/*
	 * Clean up the mess
	 */
	reopen_log();	/* apparently the PAM stuff does closelog() */
	PAM_username = NULL;
	PAM_password = NULL;
	if (pam_error != PAM_SUCCESS)
	    return UPAP_AUTHNAK;
    } else
#endif /* ALLOW_PAM */

    {
	if (debug) {
#ifdef HAS_SHADOW
	    dbglog("using passwd/shadow for user authentication");
#else
	    dbglog("using passwd for user authentication");
#endif
	}
/*
 * Use the non-PAM methods directly
 */

	pw = getpwnam(user);

	endpwent();
	if (pw == NULL)
	    return (UPAP_AUTHNAK);

#ifdef HAS_SHADOW
	spwd = getspnam(user);
	endspent();
	if (spwd != NULL) {
	    /* check the age of the password entry */
	    long now = time(NULL) / 86400L;

	    if ((spwd->sp_expire > 0 && now >= spwd->sp_expire)
		|| ((spwd->sp_max >= 0 && spwd->sp_max < 10000)
		&& spwd->sp_lstchg >= 0
		&& now >= spwd->sp_lstchg + spwd->sp_max)) {
		warn("Password for %s has expired", user);
		return (UPAP_AUTHNAK);
	    }
	    pw->pw_passwd = spwd->sp_pwdp;
	}
#endif

    /*
     * If no passwd, don't let them login.
     */
	if (pw->pw_passwd == NULL || strlen(pw->pw_passwd) < 2 ||
	    strcmp(crypt(passwd, pw->pw_passwd), pw->pw_passwd) != 0)
	    return (UPAP_AUTHNAK);
    }

    /*
     * Write a wtmp entry for this user.
     */

    tty = devnam;
    if (strncmp(tty, "/dev/", 5) == 0)
	tty += 5;
    logwtmp(tty, user, remote_name);		/* Add wtmp login entry */

#ifdef _PATH_LASTLOG
    if (!use_pam && pw != (struct passwd *)NULL) {
	struct lastlog ll;
	int fd;

	if ((fd = open(_PATH_LASTLOG, O_RDWR, 0)) >= 0) {
	   (void)lseek(fd, (off_t)(pw->pw_uid * sizeof(ll)), SEEK_SET);
	    BZERO((void *)&ll, sizeof(ll));
	    (void)time(&ll.ll_time);
	    (void)strncpy(ll.ll_line, tty, sizeof(ll.ll_line));
	    (void)write(fd, (char *)&ll, sizeof(ll));
	    (void)close(fd);
	}
    }
#endif /* _PATH_LASTLOG */

    info("user %s logged in", user);
    logged_in = 1;

    return (UPAP_AUTHACK);
}

/*
 * plogout - Logout the user.
 */
static void
plogout()
{
    char *tty;

#ifdef ALLOW_PAM
    int pam_error;

    if (use_pam) {
	if (pamh != NULL) {
	    pam_error = pam_close_session (pamh, PAM_SILENT);
	    (void) pam_end (pamh, pam_error);
	    pamh = NULL;
	}
	/* Apparently the pam stuff does closelog(). */
	reopen_log();
    } else
#endif /* ALLOW_PAM */   

    {
	tty = devnam;
	if (strncmp(tty, "/dev/", 5) == 0)
	    tty += 5;
	/* Wipe out utmp logout entry */
	logwtmp(tty, "", "");
    }
    logged_in = 0;
}


/*
 * null_login - Check if a username of "" and a password of "" are
 * acceptable, and iff so, set the list of acceptable IP addresses
 * and return 1.
 */
static int
null_login(unit)
    int unit;
{
    char *filename;
    FILE *f;
    int i, ret;
    struct wordlist *addrs, *opts;
    char secret[MAXWORDLEN];

    /*
     * Open the file of pap secrets and scan for a suitable secret.
     */
    filename = _PATH_UPAPFILE;
    addrs = NULL;
    f = fopen(filename, "r");
    if (f == NULL)
	return 0;
    check_access(f, filename);

    i = scan_authfile(f, "", our_name, secret, &addrs, &opts, filename);
    ret = i >= 0 && secret[0] == '\0';
    BZERO(secret, sizeof(secret));

    if (ret)
	set_allowed_addrs(unit, addrs, opts);
    else if (opts != NULL)
	free_wordlist(opts);
    if (addrs != NULL)
	free_wordlist(addrs);

    (void) fclose(f);
    return ret;
}


/*
 * get_pap_passwd - get a password for authenticating ourselves with
 * our peer using PAP.  Returns 1 on success, 0 if no suitable password
 * could be found.
 * Assumes passwd points to MAXSECRETLEN bytes of space (if non-null).
 */
static int
get_pap_passwd(passwd)
    char *passwd;
{
    char *filename;
    FILE *f;
    int ret;
    char secret[MAXWORDLEN];

    /*
     * Check whether a plugin wants to supply this.
     */
    if (pap_passwd_hook != NULL) {
	ret = (*pap_passwd_hook)(user, passwd);
	if (ret >= 0)
	    return ret;
    }

    filename = _PATH_UPAPFILE;
    f = fopen(filename, "r");
    if (f == NULL)
	return 0;
    check_access(f, filename);
    ret = scan_authfile(f, user,
			(remote_name[0] != '\0' ? remote_name: NULL),
			secret, NULL, NULL, filename);
    (void) fclose(f);
    if (ret < 0)
	return 0;
    if (passwd != NULL)
	(void) strlcpy(passwd, secret, MAXSECRETLEN);
    BZERO(secret, sizeof(secret));
    return 1;
}


/*
 * have_pap_secret - check whether we have a PAP file with any
 * secrets that we could possibly use for authenticating the peer.
 */
static int
have_pap_secret(lacks_ipp)
    int *lacks_ipp;
{
    FILE *f;
    int ret;
    char *filename;
    struct wordlist *addrs;

    /* let the plugin decide, if there is one */
    if (pap_check_hook != NULL) {
	ret = (*pap_check_hook)();
	if (ret >= 0)
	    return ret;
    }

    filename = _PATH_UPAPFILE;
    f = fopen(filename, "r");
    if (f == NULL)
	return 0;

    ret = scan_authfile(f, (explicit_remote? remote_name: NULL), our_name,
			NULL, &addrs, NULL, filename);
    (void) fclose(f);
    if (ret >= 0 && !some_ip_ok(addrs)) {
	if (lacks_ipp != NULL)
	    *lacks_ipp = 1;
	ret = -1;
    }
    if (addrs != NULL)
	free_wordlist(addrs);

    return ret >= 0;
}


/*
 * have_chap_secret - check whether we have a CHAP file with a secret
 * that we could possibly use for authenticating `client' on `server'.
 * Either or both can be the null string, meaning we don't know the
 * identity yet.
 */
static int
have_chap_secret(client, server, need_ip, lacks_ipp)
    char *client;
    char *server;
    int need_ip;
    int *lacks_ipp;
{
    FILE *f;
    int ret;
    char *filename;
    struct wordlist *addrs;

    filename = _PATH_CHAPFILE;
    f = fopen(filename, "r");
    if (f == NULL)
	return 0;

    if (client != NULL && client[0] == '\0')
	client = NULL;
    if (server != NULL && server[0] == '\0')
	server = NULL;

    ret = scan_authfile(f, client, server, NULL, &addrs, NULL, filename);
    (void) fclose(f);
    if (ret >= 0 && need_ip && !some_ip_ok(addrs)) {
	if (lacks_ipp != NULL)
	    *lacks_ipp = 1;
	ret = -1;
    }
    if (addrs != NULL)
	free_wordlist(addrs);

    return ret >= 0;
}


/*
 * get_secret - open the CHAP secret file and return the secret
 * for authenticating the given client on the given server.
 *
 *	"am_server" means that we're the authenticator (demanding
 *	identity from the peer).
 *
 *	"!am_server" means that we're the authenticatee (supplying
 *	identity to the peer).
 */
int
get_secret(unit, client, server, secret, secret_len, am_server)
    int unit;
    char *client;
    char *server;
    char *secret;
    int *secret_len;
    int am_server;
{
    FILE *f;
    int ret, len;
    char *filename;
    struct wordlist *addrs, *opts;
    char secbuf[MAXWORDLEN];

    /*
     * Support the 'password' option on authenticatee only in order to
     * avoid obvious security problem (authenticator and authenticatee
     * within a given implementation must never share secrets).
     */
    if (!am_server && passwd[0] != '\0') {
	(void) strlcpy(secbuf, passwd, sizeof(secbuf));
    } else {
	filename = _PATH_CHAPFILE;
	addrs = NULL;
	secbuf[0] = '\0';

	f = fopen(filename, "r");
	if (f == NULL) {
	    error("Can't open chap secret file %s: %m", filename);
	    return 0;
	}
	check_access(f, filename);

	ret = scan_authfile(f, client, server, secbuf, &addrs, &opts,
	    filename);
	(void) fclose(f);
	if (ret < 0) {
	    if (scan_server_match_failed[0] != '\0')
		warn("possible configuration error: local name is %q, but "
		    "found %q instead", our_name, scan_server_match_failed);
	    return 0;
	}

	/* Only the authenticator cares about limiting peer addresses. */
	if (am_server)
	    set_allowed_addrs(unit, addrs, opts);
	else if (opts != NULL)
	    free_wordlist(opts);
	if (addrs != NULL)
	    free_wordlist(addrs);
    }

    len = strlen(secbuf);
    if (len > MAXSECRETLEN) {
	error("Secret for %s on %s is too long", client, server);
	len = MAXSECRETLEN;
    }
    /* Do not leave a temporary copy of the secret on the stack. */
    BCOPY(secbuf, secret, len);
    BZERO(secbuf, sizeof(secbuf));
    *secret_len = len;

    return 1;
}

/*
 * set_allowed_addrs() - set the list of allowed addresses.
 * The caller must also look for `--' indicating options to apply for
 * this peer and leaves the following words in extra_options.
 */
static void
set_allowed_addrs(unit, addrs, opts)
    int unit;
    struct wordlist *addrs;
    struct wordlist *opts;
{
    int n;
    struct wordlist *ap, **pap;
    struct permitted_ip *ip;
    char *ptr_word, *ptr_mask;
    struct hostent *hp;
    struct netent *np;
    u_int32_t a, mask, newmask, ah, offset;
    struct ipcp_options *wo = &ipcp_wantoptions[unit];
    u_int32_t suggested_ip = 0;
    int err_num;

    if (addresses[unit] != NULL)
	free(addresses[unit]);
    addresses[unit] = NULL;
    if (extra_options != NULL)
	free_wordlist(extra_options);
    extra_options = opts;

    /*
     * Count the number of IP addresses given.
     */
    for (n = 0, pap = &addrs; (ap = *pap) != NULL; pap = &ap->next)
	++n;
    if (n == 0)
	return;
    ip = (struct permitted_ip *) malloc((n + 1) * sizeof(struct permitted_ip));
    if (ip == NULL)
	return;

    n = 0;
    for (ap = addrs; ap != NULL; ap = ap->next) {
	/* "-" means no addresses authorized, "*" means any address allowed */
	ptr_word = ap->word;
	if (strcmp(ptr_word, "-") == 0)
	    break;
	if (strcmp(ptr_word, "*") == 0) {
	    ip[n].permit = 1;
	    ip[n].base = ip[n].mask = 0;
	    ++n;
	    break;
	}

	ip[n].permit = 1;
	if (*ptr_word == '!') {
	    ip[n].permit = 0;
	    ++ptr_word;
	}

	mask = ~ (u_int32_t) 0;
	offset = 0;
	ptr_mask = strchr (ptr_word, '/');
	if (ptr_mask != NULL) {
	    int bit_count;
	    char *endp;

	    bit_count = (int) strtol (ptr_mask+1, &endp, 10);
	    if (bit_count <= 0 || bit_count > 32) {
		warn("invalid address length %v in authorized address list",
		     ptr_mask+1);
		continue;
	    }
	    bit_count = 32 - bit_count;	/* # bits in host part */
	    if (*endp == '+') {
		offset = ifunit + 1;
		++endp;
	    }
	    if (*endp != '\0') {
		warn("invalid address length syntax: %v", ptr_mask+1);
		continue;
	    }
	    *ptr_mask = '\0';
	    mask <<= bit_count;
	}

	/* Try to interpret value as host name or numeric address first */
	hp = getipnodebyname(ptr_word, AF_INET, 0, &err_num);
	if (hp != NULL) {
	    (void) memcpy(&a, hp->h_addr, sizeof(a));
	    freehostent(hp);
	} else {
	    char *cp = ptr_word + strlen(ptr_word);
	    if (cp > ptr_word)
		cp--;
	    if (*cp == '+') {
		offset = ifunit + 1;
		*cp = '\0';
	    }
	    np = getnetbyname (ptr_word);
	    if (np != NULL && np->n_addrtype == AF_INET) {
		ah = np->n_net;
		newmask = (u_int32_t)~0;
		if ((ah & 0xff000000ul) == 0)
		    ah <<= 8, newmask <<= 8;
		if ((ah & 0xff000000ul) == 0)
		    ah <<= 8, newmask <<= 8;
		if ((ah & 0xff000000ul) == 0)
		    ah <<= 8, newmask <<= 8;
		if (ptr_mask == NULL)
		    mask = newmask;
		a = htonl(ah);
	    }
	}

	if (ptr_mask != NULL)
	    *ptr_mask = '/';

	if (a == (u_int32_t)-1L) {
	    warn("unknown host %s in auth. address list", ap->word);
	    continue;
	}
	if (offset != 0) {
	    if (offset >= ~mask) {
		warn("interface unit %d too large for subnet %v",
		     ifunit, ptr_word);
		continue;
	    }
	    a = htonl((ntohl(a) & mask) + offset);
	    mask = ~(u_int32_t)0;
	}
	ip[n].mask = htonl(mask);
	ip[n].base = a & ip[n].mask;
	++n;
	if (~mask == 0 && suggested_ip == 0)
	    suggested_ip = a;
    }

    /* Sentinel value at end of list */
    ip[n].permit = 0;		/* make the last entry forbid all addresses */
    ip[n].base = 0;		/* to terminate the list */
    ip[n].mask = 0;

    addresses[unit] = ip;

    /*
     * If the address given for the peer isn't authorized, or if
     * the user hasn't given one, AND there is an authorized address
     * which is a single host, then use that if we find one.
     */
    if (suggested_ip != 0
	&& (wo->hisaddr == 0 || !auth_ip_addr(unit, wo->hisaddr)))
	wo->hisaddr = suggested_ip;
}

/*
 * auth_ip_addr - check whether the peer is authorized to use
 * a given IP address.  Returns 1 if authorized, 0 otherwise.
 */
int
auth_ip_addr(unit, addr)
    int unit;
    u_int32_t addr;
{
    int ok;

    /* don't allow loopback or multicast address */
    if (bad_ip_adrs(addr))
	return 0;

    if (addresses[unit] != NULL) {
	ok = ip_addr_check(addr, addresses[unit]);
	if (ok >= 0)
	    return ok;
    }
    if (auth_required)
	return 0;		/* no addresses authorized */
    return allow_any_ip || privileged || !have_route_to(addr);
}

static int
ip_addr_check(addr, addrs)
    u_int32_t addr;
    struct permitted_ip *addrs;
{
    /* This loop is safe because of the sentinel value in set_allowed_addrs */
    for (; ; ++addrs)
	if ((addr & addrs->mask) == addrs->base)
	    return addrs->permit;
}

/*
 * bad_ip_adrs - return 1 if the IP address is one we don't want
 * to use, such as an address in the loopback net or a multicast address.
 * addr is in network byte order.
 */
int
bad_ip_adrs(addr)
    u_int32_t addr;
{
    addr = ntohl(addr);
    return 
#ifndef ALLOW_127_NET
	(addr >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET ||
#endif
#ifndef ALLOW_0_NET
	((addr >> IN_CLASSA_NSHIFT) == 0 && addr != 0) ||
#endif
	IN_MULTICAST(addr);
}

/*
 * some_ip_ok - check a wordlist to see if it authorizes any
 * IP address(es).
 */
static int
some_ip_ok(addrs)
    struct wordlist *addrs;
{
    for (; addrs != NULL; addrs = addrs->next) {
	if (addrs->word[0] == '-')
	    break;
	if (addrs->word[0] != '!')
	    return 1;		/* some IP address is allowed */
    }
    return 0;
}

/*
 * check_access - complain if a secret file has too-liberal permissions.
 */
static void
check_access(f, filename)
    FILE *f;
    char *filename;
{
    struct stat sbuf;

    if (fstat(fileno(f), &sbuf) < 0) {
	warn("cannot stat secret file %s: %m", filename);
    } else if ((sbuf.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
	warn("Warning - secret file %s has world and/or group access",
	     filename);
    }
}


/*
 * scan_authfile - Scan an authorization file for a secret suitable
 * for authenticating `client' on `server'.  The return value is -1 if
 * no secret is found, otherwise >= 0.  The return value has
 * NONWILD_CLIENT set if the secret didn't have "*" for the client,
 * and NONWILD_SERVER set if the secret didn't have "*" for the
 * server.

 * Any following words on the line up to a "--" (i.e. address
 * authorization info) are placed in a wordlist and returned in
 * *addrs.  Any following words (extra options) are placed in a
 * wordlist and returned in *opts.  If opts is NULL, these are just
 * discarded.  Otherwise, the extra_opt_* variables are set to
 * indicate the source of the options.
 *
 * We assume secret is NULL or points to MAXWORDLEN bytes of space.
 */
static int
scan_authfile(f, client, server, secret, addrs, opts, filename)
    FILE *f;
    char *client;
    char *server;
    char *secret;
    struct wordlist **addrs;
    struct wordlist **opts;
    char *filename;
{
    int newline, xxx, sline;
    int got_flag, best_flag;
    FILE *sf;
    struct wordlist *ap, *addr_list, *alist, **app;
    char word[MAXWORDLEN];
    char atfile[MAXWORDLEN];
    char lsecret[MAXWORDLEN];

    scan_server_match_failed[0] = '\0';

    if (addrs != NULL)
	*addrs = NULL;
    if (opts != NULL)
	*opts = NULL;
    addr_list = NULL;
    option_line = 0;
    if (!getword(f, word, &newline, filename)) {
	if (debug)
	    dbglog("%s is apparently empty", filename);
	return -1;		/* file is empty??? */
    }
    newline = 1;
    best_flag = -1;
    for (;;) {
	/*
	 * Skip until we find a word at the start of a line.
	 */
	while (!newline && getword(f, word, &newline, filename))
	    ;
	if (!newline)
	    break;		/* got to end of file */

	sline = option_line;
	/*
	 * Got a client - check if it's a match or a wildcard.
	 */
	got_flag = 0;
	if (client != NULL && strcmp(word, client) != 0 && !ISWILD(word)) {
	    newline = 0;
	    continue;
	}
	if (!ISWILD(word))
	    got_flag = NONWILD_CLIENT;

	/*
	 * Now get a server and check if it matches.
	 */
	if (!getword(f, word, &newline, filename))
	    break;
	if (newline)
	    continue;
	if (!ISWILD(word)) {
	    if (server != NULL && strcmp(word, server) != 0) {
		(void) strcpy(scan_server_match_failed, word);
		continue;
	    }
	    got_flag |= NONWILD_SERVER;
	}

	/*
	 * Got some sort of a match - see if it's better than what
	 * we have already.
	 */
	if (got_flag <= best_flag)
	    continue;

	/*
	 * Get the secret.
	 */
	if (!getword(f, word, &newline, filename))
	    break;
	if (newline)
	    continue;

	/*
	 * Special syntax: @filename means read secret from file.
	 * Because the secrets files are modifiable only by root,
	 * it's safe to open this file as root.  One small addition --
	 * if open fails, we try as the regular user; just in case
	 * it's over NFS and not root-equivalent.
	 */
	if (word[0] == '@') {
	    (void) strlcpy(atfile, word+1, sizeof(atfile));
	    if ((sf = fopen(atfile, "r")) == NULL) {
		(void) seteuid(getuid());
		sf = fopen(atfile, "r");
		(void) seteuid(0);
	    }
	    if (sf == NULL) {
		warn("can't open indirect secret file %s: %m", atfile);
		continue;
	    }
	    check_access(sf, atfile);
	    if (!getword(sf, word, &xxx, atfile)) {
		warn("no secret in indirect secret file %s", atfile);
		(void) fclose(sf);
		continue;
	    }
	    (void) fclose(sf);
	}
	if (secret != NULL)
	    (void) strlcpy(lsecret, word, sizeof(lsecret));

	/*
	 * Now read address authorization info and make a wordlist.
	 */
	app = &alist;
	for (;;) {
	    if (!getword(f, word, &newline, filename) || newline)
		break;
	    ap = (struct wordlist *) malloc(sizeof(struct wordlist));
	    if (ap == NULL)
		novm("authorized addresses");
	    ap->word = strdup(word);
	    if (ap->word == NULL)
		novm("authorized addresses");
	    *app = ap;
	    app = &ap->next;
	}
	*app = NULL;

	/*
	 * This is the best so far; remember it.
	 */
	best_flag = got_flag;
	if (addr_list != NULL)
	    free_wordlist(addr_list);
	addr_list = alist;
	if (secret != NULL)
	    (void) strlcpy(secret, lsecret, MAXWORDLEN);

	if (opts != NULL) {
	    extra_opt_filename = filename;
	    extra_opt_line = sline;
	}

	if (!newline)
	    break;
    }

    /* scan for a -- word indicating the start of options */
    for (app = &addr_list; (ap = *app) != NULL; app = &ap->next)
	if (strcmp(ap->word, "--") == 0)
	    break;
    /* ap = start of options */
    if (ap != NULL) {
	ap = ap->next;		/* first option */
	free(*app);			/* free the "--" word */
	*app = NULL;		/* terminate addr list */
    }
    if (opts != NULL)
	*opts = ap;
    else if (ap != NULL)
	free_wordlist(ap);
    if (addrs != NULL)
	*addrs = addr_list;
    else if (addr_list != NULL)
	free_wordlist(addr_list);

    return best_flag;
}

/*
 * free_wordlist - release memory allocated for a wordlist.
 */
static void
free_wordlist(wp)
    struct wordlist *wp;
{
    struct wordlist *next;

    while (wp != NULL) {
	next = wp->next;
	free(wp);
	wp = next;
    }
}

/*
 * auth_script_done - called when the auth-up or auth-down script
 * has finished.
 */
/*ARGSUSED*/
static void
auth_script_done(arg, status)
    void *arg;
    int status;
{
    auth_script_pid = 0;
    switch (auth_script_state) {
    case s_up:
	if (auth_state == s_down) {
	    auth_script_state = s_down;
	    auth_script(_PATH_AUTHDOWN);
	}
	break;
    case s_down:
	if (auth_state == s_up) {
	    auth_script_state = s_up;
	    auth_script(_PATH_AUTHUP);
	}
	break;
    }
}

/*
 * auth_script - execute a script with arguments
 * interface-name peer-name real-user tty speed
 */
static void
auth_script(script)
    char *script;
{
    char strspeed[32];
    struct passwd *pw;
    char struid[32];
    char *user_name;
    char *argv[8];

    if ((pw = getpwuid(getuid())) != NULL && pw->pw_name != NULL)
	user_name = pw->pw_name;
    else {
	(void) slprintf(struid, sizeof(struid), "%d", getuid());
	user_name = struid;
    }
    (void) slprintf(strspeed, sizeof(strspeed), "%d", baud_rate);

    argv[0] = script;
    argv[1] = ifname;
    argv[2] = peer_authname;
    argv[3] = user_name;
    argv[4] = devnam;
    argv[5] = strspeed;
    argv[6] = NULL;

    auth_script_pid = run_program(script, argv, 0, auth_script_done, NULL);
}
