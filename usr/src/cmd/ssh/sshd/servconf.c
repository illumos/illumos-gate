/*
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Joyent, Inc.  All rights reserved.
 */

#include "includes.h"
RCSID("$OpenBSD: servconf.c,v 1.115 2002/09/04 18:52:42 stevesk Exp $");

#ifdef HAVE_DEFOPEN
#include <deflt.h>
#endif /* HAVE_DEFOPEN */

#if defined(KRB4)
#include <krb.h>
#endif
#if defined(KRB5)
#ifdef HEIMDAL
#include <krb.h>
#else
/* Bodge - but then, so is using the kerberos IV KEYFILE to get a Kerberos V
 * keytab */
#define KEYFILE "/etc/krb5.keytab"
#endif
#endif
#ifdef AFS
#include <kafs.h>
#endif

#include "ssh.h"
#include "log.h"
#include "buffer.h"
#include "servconf.h"
#include "xmalloc.h"
#include "compat.h"
#include "pathnames.h"
#include "tildexpand.h"
#include "misc.h"
#include "cipher.h"
#include "kex.h"
#include "mac.h"
#include "auth.h"
#include "match.h"
#include "groupaccess.h"

static void add_listen_addr(ServerOptions *, char *, u_short);
static void add_one_listen_addr(ServerOptions *, char *, u_short);

extern Buffer cfg;

/* AF_UNSPEC or AF_INET or AF_INET6 */
extern int IPv4or6;

/*
 * Initializes the server options to their initial (unset) values. Some of those
 * that stay unset after the command line options and configuration files are
 * read are set to their default values in fill_default_server_options().
 */
void
initialize_server_options(ServerOptions *options)
{
	(void) memset(options, 0, sizeof(*options));

	/* Standard Options */
	options->num_ports = 0;
	options->ports_from_cmdline = 0;
	options->listen_addrs = NULL;
	options->num_host_key_files = 0;
	options->pid_file = NULL;
	options->server_key_bits = -1;
	options->login_grace_time = -1;
	options->key_regeneration_time = -1;
	options->permit_root_login = PERMIT_NOT_SET;
	options->ignore_rhosts = -1;
	options->ignore_user_known_hosts = -1;
	options->print_motd = -1;
	options->print_lastlog = -1;
	options->x11_forwarding = -1;
	options->x11_display_offset = -1;
	options->x11_use_localhost = -1;
	options->xauth_location = NULL;
	options->strict_modes = -1;
	options->keepalives = -1;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->rhosts_authentication = -1;
	options->rhosts_rsa_authentication = -1;
	options->hostbased_authentication = -1;
	options->hostbased_uses_name_from_packet_only = -1;
	options->rsa_authentication = -1;
	options->pubkey_authentication = -1;
#ifdef GSSAPI
	options->gss_authentication = -1;
	options->gss_keyex = -1;
	options->gss_store_creds = -1;
	options->gss_use_session_ccache = -1;
	options->gss_cleanup_creds = -1;
#endif
#if defined(KRB4) || defined(KRB5)
	options->kerberos_authentication = -1;
	options->kerberos_or_local_passwd = -1;
	options->kerberos_ticket_cleanup = -1;
#endif
#if defined(AFS) || defined(KRB5)
	options->kerberos_tgt_passing = -1;
#endif
#ifdef AFS
	options->afs_token_passing = -1;
#endif
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->challenge_response_authentication = -1;
	options->pam_authentication_via_kbd_int = -1;
	options->permit_empty_passwd = -1;
	options->permit_user_env = -1;
	options->compression = -1;
	options->allow_tcp_forwarding = -1;
	options->num_allow_users = 0;
	options->num_deny_users = 0;
	options->num_allow_groups = 0;
	options->num_deny_groups = 0;
	options->ciphers = NULL;
	options->macs = NULL;
	options->protocol = SSH_PROTO_UNKNOWN;
	options->gateway_ports = -1;
	options->num_subsystems = 0;
	options->max_startups_begin = -1;
	options->max_startups_rate = -1;
	options->max_startups = -1;
	options->banner = NULL;
	options->verify_reverse_mapping = -1;
	options->client_alive_interval = -1;
	options->client_alive_count_max = -1;
	options->authorized_keys_file = NULL;
	options->authorized_keys_file2 = NULL;

	options->max_auth_tries = -1;
	options->max_auth_tries_log = -1;

	options->max_init_auth_tries = -1;
	options->max_init_auth_tries_log = -1;

	options->lookup_client_hostnames = -1;
	options->use_openssl_engine = -1;
	options->chroot_directory = NULL;
	options->pre_userauth_hook = NULL;
	options->pam_service_name = NULL;
	options->pam_service_prefix = NULL;
}

#ifdef HAVE_DEFOPEN
/*
 * Reads /etc/default/login and defaults several ServerOptions:
 *
 * PermitRootLogin
 * PermitEmptyPasswords
 * LoginGraceTime
 *
 * CONSOLE=*      -> PermitRootLogin=without-password
 * #CONSOLE=*     -> PermitRootLogin=yes
 *
 * PASSREQ=YES    -> PermitEmptyPasswords=no
 * PASSREQ=NO     -> PermitEmptyPasswords=yes
 * #PASSREQ=*     -> PermitEmptyPasswords=no
 *
 * TIMEOUT=<secs> -> LoginGraceTime=<secs>
 * #TIMEOUT=<secs> -> LoginGraceTime=300
 */
static
void
deflt_fill_default_server_options(ServerOptions *options)
{
	int	flags;
	char	*ptr;

	if (defopen(_PATH_DEFAULT_LOGIN))
		return;

	/* Ignore case */
	flags = defcntl(DC_GETFLAGS, 0);
	TURNOFF(flags, DC_CASE);
	(void) defcntl(DC_SETFLAGS, flags);

	if (options->permit_root_login == PERMIT_NOT_SET &&
	    (ptr = defread("CONSOLE=")) != NULL)
		options->permit_root_login = PERMIT_NO_PASSWD;

	if (options->permit_empty_passwd == -1 &&
	    (ptr = defread("PASSREQ=")) != NULL) {
		if (strcasecmp("YES", ptr) == 0)
			options->permit_empty_passwd = 0;
		else if (strcasecmp("NO", ptr) == 0)
			options->permit_empty_passwd = 1;
	}

	if (options->max_init_auth_tries == -1 &&
	    (ptr = defread("RETRIES=")) != NULL) {
		options->max_init_auth_tries = atoi(ptr);
	}

	if (options->max_init_auth_tries_log == -1 &&
	    (ptr = defread("SYSLOG_FAILED_LOGINS=")) != NULL) {
		options->max_init_auth_tries_log = atoi(ptr);
	}

	if (options->login_grace_time == -1) {
		if ((ptr = defread("TIMEOUT=")) != NULL)
			options->login_grace_time = (unsigned)atoi(ptr);
		else
			options->login_grace_time = 300;
	}

	(void) defopen((char *)NULL);
}
#endif /* HAVE_DEFOPEN */

void
fill_default_server_options(ServerOptions *options)
{

#ifdef HAVE_DEFOPEN
	deflt_fill_default_server_options(options);
#endif /* HAVE_DEFOPEN */

	/* Standard Options */
	if (options->protocol == SSH_PROTO_UNKNOWN)
		options->protocol = SSH_PROTO_1|SSH_PROTO_2;
	if (options->num_host_key_files == 0) {
		/* fill default hostkeys for protocols */
		if (options->protocol & SSH_PROTO_1)
			options->host_key_files[options->num_host_key_files++] =
			    _PATH_HOST_KEY_FILE;
#ifndef GSSAPI
		/* With GSS keyex we can run v2 w/ no host keys */
		if (options->protocol & SSH_PROTO_2) {
			options->host_key_files[options->num_host_key_files++] =
			    _PATH_HOST_RSA_KEY_FILE;
			options->host_key_files[options->num_host_key_files++] =
			    _PATH_HOST_DSA_KEY_FILE;
		}
#endif /* GSSAPI */
	}
	if (options->num_ports == 0)
		options->ports[options->num_ports++] = SSH_DEFAULT_PORT;
	if (options->listen_addrs == NULL)
		add_listen_addr(options, NULL, 0);
	if (options->pid_file == NULL)
		options->pid_file = _PATH_SSH_DAEMON_PID_FILE;
	if (options->server_key_bits == -1)
		options->server_key_bits = 768;
	if (options->login_grace_time == -1)
		options->login_grace_time = 120;
	if (options->key_regeneration_time == -1)
		options->key_regeneration_time = 3600;
	if (options->permit_root_login == PERMIT_NOT_SET)
		options->permit_root_login = PERMIT_YES;
	if (options->ignore_rhosts == -1)
		options->ignore_rhosts = 1;
	if (options->ignore_user_known_hosts == -1)
		options->ignore_user_known_hosts = 0;
	if (options->print_motd == -1)
		options->print_motd = 1;
	if (options->print_lastlog == -1)
		options->print_lastlog = 1;
	if (options->x11_forwarding == -1)
		options->x11_forwarding = 1;
	if (options->x11_display_offset == -1)
		options->x11_display_offset = 10;
	if (options->x11_use_localhost == -1)
		options->x11_use_localhost = 1;
	if (options->xauth_location == NULL)
		options->xauth_location = _PATH_XAUTH;
	if (options->strict_modes == -1)
		options->strict_modes = 1;
	if (options->keepalives == -1)
		options->keepalives = 1;
	if (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	if (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	if (options->rhosts_authentication == -1)
		options->rhosts_authentication = 0;
	if (options->rhosts_rsa_authentication == -1)
		options->rhosts_rsa_authentication = 0;
	if (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	if (options->hostbased_uses_name_from_packet_only == -1)
		options->hostbased_uses_name_from_packet_only = 0;
	if (options->rsa_authentication == -1)
		options->rsa_authentication = 1;
	if (options->pubkey_authentication == -1)
		options->pubkey_authentication = 1;
#ifdef GSSAPI
	if (options->gss_authentication == -1)
		options->gss_authentication = 1;
	if (options->gss_keyex == -1)
		options->gss_keyex = 1;
	if (options->gss_store_creds == -1)
		options->gss_store_creds = 1;
	if (options->gss_use_session_ccache == -1)
		options->gss_use_session_ccache = 1;
	if (options->gss_cleanup_creds == -1)
		options->gss_cleanup_creds = 1;
#endif
#if defined(KRB4) || defined(KRB5)
	if (options->kerberos_authentication == -1)
		options->kerberos_authentication = 0;
	if (options->kerberos_or_local_passwd == -1)
		options->kerberos_or_local_passwd = 1;
	if (options->kerberos_ticket_cleanup == -1)
		options->kerberos_ticket_cleanup = 1;
#endif
#if defined(AFS) || defined(KRB5)
	if (options->kerberos_tgt_passing == -1)
		options->kerberos_tgt_passing = 0;
#endif
#ifdef AFS
	if (options->afs_token_passing == -1)
		options->afs_token_passing = 0;
#endif
	if (options->password_authentication == -1)
		options->password_authentication = 1;
	/*
	 * options->pam_authentication_via_kbd_int has intentionally no default
	 * value since we do not need it.
	 */
	if (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	if (options->challenge_response_authentication == -1)
		options->challenge_response_authentication = 1;
	if (options->permit_empty_passwd == -1)
		options->permit_empty_passwd = 0;
	if (options->permit_user_env == -1)
		options->permit_user_env = 0;
	if (options->compression == -1)
		options->compression = 1;
	if (options->allow_tcp_forwarding == -1)
		options->allow_tcp_forwarding = 1;
	if (options->gateway_ports == -1)
		options->gateway_ports = 0;
	if (options->max_startups == -1)
		options->max_startups = 10;
	if (options->max_startups_rate == -1)
		options->max_startups_rate = 100;		/* 100% */
	if (options->max_startups_begin == -1)
		options->max_startups_begin = options->max_startups;
	if (options->verify_reverse_mapping == -1)
		options->verify_reverse_mapping = 0;
	if (options->client_alive_interval == -1)
		options->client_alive_interval = 0;
	if (options->client_alive_count_max == -1)
		options->client_alive_count_max = 3;
	if (options->authorized_keys_file2 == NULL) {
		/* authorized_keys_file2 falls back to authorized_keys_file */
		if (options->authorized_keys_file != NULL)
			options->authorized_keys_file2 = options->authorized_keys_file;
		else
			options->authorized_keys_file2 = _PATH_SSH_USER_PERMITTED_KEYS2;
	}
	if (options->authorized_keys_file == NULL)
		options->authorized_keys_file = _PATH_SSH_USER_PERMITTED_KEYS;

	if (options->max_auth_tries == -1)
		options->max_auth_tries = AUTH_FAIL_MAX;
	if (options->max_auth_tries_log == -1)
		options->max_auth_tries_log = options->max_auth_tries / 2;

	if (options->max_init_auth_tries == -1)
		options->max_init_auth_tries = AUTH_FAIL_MAX;
	if (options->max_init_auth_tries_log == -1)
		options->max_init_auth_tries_log = options->max_init_auth_tries / 2;

	if (options->lookup_client_hostnames == -1)
		options->lookup_client_hostnames = 1;
	if (options->use_openssl_engine == -1)
		options->use_openssl_engine = 1;
	if (options->pam_service_prefix == NULL)
		options->pam_service_prefix = _SSH_PAM_SERVICE_PREFIX;
	if (options->pam_service_name == NULL)
		options->pam_service_name = NULL;
}

/* Keyword tokens. */
typedef enum {
	sBadOption,		/* == unknown option */
	/* Portable-specific options */
	sPAMAuthenticationViaKbdInt,
	/* Standard Options */
	sPort, sHostKeyFile, sServerKeyBits, sLoginGraceTime, sKeyRegenerationTime,
	sPermitRootLogin, sLogFacility, sLogLevel,
	sRhostsAuthentication, sRhostsRSAAuthentication, sRSAAuthentication,
#ifdef GSSAPI
	sGssAuthentication, sGssKeyEx, sGssStoreDelegCreds,
	sGssUseSessionCredCache, sGssCleanupCreds,
#endif /* GSSAPI */
#if defined(KRB4) || defined(KRB5)
	sKerberosAuthentication, sKerberosOrLocalPasswd, sKerberosTicketCleanup,
#endif
#if defined(AFS) || defined(KRB5)
	sKerberosTgtPassing,
#endif
#ifdef AFS
	sAFSTokenPassing,
#endif
	sChallengeResponseAuthentication,
	sPasswordAuthentication, sKbdInteractiveAuthentication, sListenAddress,
	sPrintMotd, sPrintLastLog, sIgnoreRhosts,
	sX11Forwarding, sX11DisplayOffset, sX11UseLocalhost,
	sStrictModes, sEmptyPasswd, sKeepAlives,
	sPermitUserEnvironment, sUseLogin, sAllowTcpForwarding, sCompression,
	sAllowUsers, sDenyUsers, sAllowGroups, sDenyGroups,
	sIgnoreUserKnownHosts, sCiphers, sMacs, sProtocol, sPidFile,
	sGatewayPorts, sPubkeyAuthentication, sXAuthLocation, sSubsystem, sMaxStartups,
	sBanner, sVerifyReverseMapping, sHostbasedAuthentication,
	sHostbasedUsesNameFromPacketOnly, sClientAliveInterval,
	sClientAliveCountMax, sAuthorizedKeysFile, sAuthorizedKeysFile2,
	sMaxAuthTries, sMaxAuthTriesLog, sUsePrivilegeSeparation,
	sLookupClientHostnames, sUseOpenSSLEngine, sChrootDirectory,
	sPreUserauthHook, sMatch, sPAMServicePrefix, sPAMServiceName,
	sDeprecated
} ServerOpCodes;

#define SSHCFG_GLOBAL	0x01	/* allowed in main section of sshd_config */
#define SSHCFG_MATCH	0x02	/* allowed inside a Match section */
#define SSHCFG_ALL	(SSHCFG_GLOBAL|SSHCFG_MATCH)

/* Textual representation of the tokens. */
static struct {
	const char *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	/* Portable-specific options */
	{ "PAMAuthenticationViaKbdInt", sPAMAuthenticationViaKbdInt, SSHCFG_GLOBAL },
	/* Standard Options */
	{ "port", sPort, SSHCFG_GLOBAL },
	{ "hostkey", sHostKeyFile, SSHCFG_GLOBAL },
	{ "hostdsakey", sHostKeyFile, SSHCFG_GLOBAL },			/* alias */
	{ "pidfile", sPidFile, SSHCFG_GLOBAL },
	{ "serverkeybits", sServerKeyBits, SSHCFG_GLOBAL },
	{ "logingracetime", sLoginGraceTime, SSHCFG_GLOBAL },
	{ "keyregenerationinterval", sKeyRegenerationTime, SSHCFG_GLOBAL },
	{ "permitrootlogin", sPermitRootLogin, SSHCFG_ALL },
	{ "syslogfacility", sLogFacility, SSHCFG_GLOBAL },
	{ "loglevel", sLogLevel, SSHCFG_GLOBAL },
	{ "rhostsauthentication", sRhostsAuthentication, SSHCFG_GLOBAL },
	{ "rhostsrsaauthentication", sRhostsRSAAuthentication, SSHCFG_ALL },
	{ "hostbasedauthentication", sHostbasedAuthentication, SSHCFG_ALL },
	{ "hostbasedusesnamefrompacketonly", sHostbasedUsesNameFromPacketOnly },
	{ "rsaauthentication", sRSAAuthentication, SSHCFG_ALL },
	{ "pubkeyauthentication", sPubkeyAuthentication, SSHCFG_ALL },
	{ "dsaauthentication", sPubkeyAuthentication, SSHCFG_GLOBAL },	/* alias */
#ifdef GSSAPI
	{ "gssapiauthentication", sGssAuthentication, SSHCFG_ALL },
	{ "gssapikeyexchange", sGssKeyEx,   SSHCFG_GLOBAL },
	{ "gssapistoredelegatedcredentials", sGssStoreDelegCreds, SSHCFG_GLOBAL },
	{ "gssauthentication", sGssAuthentication, SSHCFG_GLOBAL },	/* alias */
	{ "gsskeyex", sGssKeyEx, SSHCFG_GLOBAL },	/* alias */
	{ "gssstoredelegcreds", sGssStoreDelegCreds, SSHCFG_GLOBAL },	/* alias */
#ifndef SUNW_GSSAPI
	{ "gssusesessionccache", sGssUseSessionCredCache, SSHCFG_GLOBAL },
	{ "gssusesessioncredcache", sGssUseSessionCredCache, SSHCFG_GLOBAL },
	{ "gsscleanupcreds", sGssCleanupCreds, SSHCFG_GLOBAL },
#endif /* SUNW_GSSAPI */
#endif
#if defined(KRB4) || defined(KRB5)
	{ "kerberosauthentication", sKerberosAuthentication, SSHCFG_ALL },
	{ "kerberosorlocalpasswd", sKerberosOrLocalPasswd, SSHCFG_GLOBAL },
	{ "kerberosticketcleanup", sKerberosTicketCleanup, SSHCFG_GLOBAL },
#endif
#if defined(AFS) || defined(KRB5)
	{ "kerberostgtpassing", sKerberosTgtPassing, SSHCFG_GLOBAL },
#endif
#ifdef AFS
	{ "afstokenpassing", sAFSTokenPassing, SSHCFG_GLOBAL },
#endif
	{ "passwordauthentication", sPasswordAuthentication, SSHCFG_ALL },
	{ "kbdinteractiveauthentication", sKbdInteractiveAuthentication, SSHCFG_ALL },
	{ "challengeresponseauthentication", sChallengeResponseAuthentication, SSHCFG_GLOBAL },
	{ "skeyauthentication", sChallengeResponseAuthentication, SSHCFG_GLOBAL }, /* alias */
	{ "checkmail", sDeprecated, SSHCFG_GLOBAL },
	{ "listenaddress", sListenAddress, SSHCFG_GLOBAL },
	{ "printmotd", sPrintMotd, SSHCFG_GLOBAL },
	{ "printlastlog", sPrintLastLog, SSHCFG_GLOBAL },
	{ "ignorerhosts", sIgnoreRhosts, SSHCFG_GLOBAL },
	{ "ignoreuserknownhosts", sIgnoreUserKnownHosts, SSHCFG_GLOBAL },
	{ "x11forwarding", sX11Forwarding, SSHCFG_ALL },
	{ "x11displayoffset", sX11DisplayOffset, SSHCFG_ALL },
	{ "x11uselocalhost", sX11UseLocalhost, SSHCFG_ALL },
	{ "xauthlocation", sXAuthLocation, SSHCFG_GLOBAL },
	{ "strictmodes", sStrictModes, SSHCFG_GLOBAL },
	{ "permitemptypasswords", sEmptyPasswd, SSHCFG_ALL },
	{ "permituserenvironment", sPermitUserEnvironment, SSHCFG_GLOBAL },
	{ "uselogin", sUseLogin, SSHCFG_GLOBAL },
	{ "compression", sCompression, SSHCFG_GLOBAL },
	{ "tcpkeepalive", sKeepAlives, SSHCFG_GLOBAL },
	{ "keepalive", sKeepAlives, SSHCFG_GLOBAL },		/* obsolete */
	{ "allowtcpforwarding", sAllowTcpForwarding, SSHCFG_ALL },
	{ "allowusers", sAllowUsers, SSHCFG_GLOBAL },
	{ "denyusers", sDenyUsers, SSHCFG_GLOBAL },
	{ "allowgroups", sAllowGroups, SSHCFG_GLOBAL },
	{ "denygroups", sDenyGroups, SSHCFG_GLOBAL },
	{ "ciphers", sCiphers, SSHCFG_GLOBAL },
	{ "macs", sMacs, SSHCFG_GLOBAL},
	{ "protocol", sProtocol,SSHCFG_GLOBAL },
	{ "gatewayports", sGatewayPorts, SSHCFG_ALL },
	{ "subsystem", sSubsystem, SSHCFG_GLOBAL},
	{ "maxstartups", sMaxStartups, SSHCFG_GLOBAL },
	{ "banner", sBanner, SSHCFG_ALL },
	{ "verifyreversemapping", sVerifyReverseMapping, SSHCFG_GLOBAL },
	{ "reversemappingcheck", sVerifyReverseMapping,SSHCFG_GLOBAL },
	{ "clientaliveinterval", sClientAliveInterval, SSHCFG_GLOBAL },
	{ "clientalivecountmax", sClientAliveCountMax, SSHCFG_GLOBAL },
	{ "authorizedkeysfile", sAuthorizedKeysFile, SSHCFG_GLOBAL },
	{ "authorizedkeysfile2", sAuthorizedKeysFile2, SSHCFG_GLOBAL },
	{ "maxauthtries", sMaxAuthTries, SSHCFG_ALL },
	{ "maxauthtrieslog", sMaxAuthTriesLog, SSHCFG_GLOBAL },
	{ "useprivilegeseparation", sUsePrivilegeSeparation, SSHCFG_GLOBAL },
	{ "lookupclienthostnames", sLookupClientHostnames, SSHCFG_GLOBAL },
	{ "useopensslengine", sUseOpenSSLEngine, SSHCFG_GLOBAL },
	{ "chrootdirectory", sChrootDirectory, SSHCFG_ALL },
	{ "preuserauthhook", sPreUserauthHook, SSHCFG_ALL},
	{ "match", sMatch, SSHCFG_ALL },
	{ "pamserviceprefix", sPAMServicePrefix, SSHCFG_GLOBAL },
	{ "pamservicename", sPAMServiceName, SSHCFG_GLOBAL },

	{ NULL, sBadOption, 0 }
};

/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

static ServerOpCodes
parse_token(const char *cp, const char *filename,
	    int linenum, u_int *flags)
{
	u_int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			return keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	return sBadOption;
}

static void
add_listen_addr(ServerOptions *options, char *addr, u_short port)
{
	int i;

	if (options->num_ports == 0)
		options->ports[options->num_ports++] = SSH_DEFAULT_PORT;
	if (port == 0)
		for (i = 0; i < options->num_ports; i++)
			add_one_listen_addr(options, addr, options->ports[i]);
	else
		add_one_listen_addr(options, addr, port);
}

static void
add_one_listen_addr(ServerOptions *options, char *addr, u_short port)
{
	struct addrinfo hints, *ai, *aitop;
	char strport[NI_MAXSERV];
	int gaierr;

	(void) memset(&hints, 0, sizeof(hints));
	hints.ai_family = IPv4or6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == NULL) ? AI_PASSIVE : 0;
	(void) snprintf(strport, sizeof strport, "%u", port);
	if ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    gai_strerror(gaierr));
	for (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs;
	options->listen_addrs = aitop;
}

/*
 * The strategy for the Match blocks is that the config file is parsed twice.
 *
 * The first time is at startup.  activep is initialized to 1 and the
 * directives in the global context are processed and acted on.  Hitting a
 * Match directive unsets activep and the directives inside the block are
 * checked for syntax only.
 *
 * The second time is after a connection has been established but before
 * authentication.  activep is initialized to 2 and global config directives
 * are ignored since they have already been processed.  If the criteria in a
 * Match block is met, activep is set and the subsequent directives
 * processed and actioned until EOF or another Match block unsets it.  Any
 * options set are copied into the main server config.
 *
 * Potential additions/improvements:
 *  - Add Match support for pre-kex directives, eg Protocol, Ciphers.
 *
 *  - Add a Tag directive (idea from David Leonard) ala pf, eg:
 *	Match Address 192.168.0.*
 *		Tag trusted
 *	Match Group wheel
 *		Tag trusted
 *	Match Tag trusted
 *		AllowTcpForwarding yes
 *		GatewayPorts clientspecified
 *		[...]
 *
 *  - Add a PermittedChannelRequests directive
 *	Match Group shell
 *		PermittedChannelRequests session,forwarded-tcpip
 */

static int
match_cfg_line_group(const char *grps, int line, const char *user)
{
	int result = 0;
	struct passwd *pw;

	if (user == NULL)
		goto out;

	if ((pw = getpwnam(user)) == NULL) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", line, user);
	} else if (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, line);
	} else if (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, line);
	} else {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, line);
		result = 1;
	}
out:
	ga_free();
	return result;
}

static int
match_cfg_line(char **condition, int line, const char *user, const char *host,
    const char *address)
{
	int result = 1;
	char *arg, *attrib, *cp = *condition;
	size_t len;

	if (user == NULL)
		debug3("checking syntax for 'Match %s'", cp);
	else
		debug3("checking match for '%s' user %s host %s addr %s", cp,
		    user ? user : "(null)", host ? host : "(null)",
		    address ? address : "(null)");

	while ((attrib = strdelim(&cp)) != NULL && *attrib != '\0') {
		if ((arg = strdelim(&cp)) == NULL || *arg == '\0') {
			error("Missing Match criteria for %s", attrib);
			return -1;
		}
		len = strlen(arg);
		if (strcasecmp(attrib, "user") == 0) {
			if (!user) {
				result = 0;
				continue;
			}
			if (match_pattern_list(user, arg, len, 0) != 1)
				result = 0;
			else
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", user, arg, line);
		} else if (strcasecmp(attrib, "group") == 0) {
			switch (match_cfg_line_group(arg, line, user)) {
			case -1:
				return -1;
			case 0:
				result = 0;
			}
		} else if (strcasecmp(attrib, "host") == 0) {
			if (!host) {
				result = 0;
				continue;
			}
			if (match_hostname(host, arg, len) != 1)
				result = 0;
			else
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", host, arg, line);
		} else if (strcasecmp(attrib, "address") == 0) {
			switch (addr_match_list(address, arg)) {
			case 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", address, arg, line);
				break;
			case 0:
			case -1:
				result = 0;
				break;
			case -2:
				return -1;
			}
		} else {
			error("Unsupported Match attribute %s", attrib);
			return -1;
		}
	}
	if (user != NULL)
		debug3("match %sfound", result ? "" : "not ");
	*condition = cp;
	return result;
}

#define WHITESPACE " \t\r\n"

int
process_server_config_line(ServerOptions *options, char *line,
    const char *filename, int linenum, int *activep, const char *user,
    const char *host, const char *address)
{
	char *cp, **charptr, *arg, *p;
	int cmdline = 0, *intptr, value, n;
	ServerOpCodes opcode;
	u_int i, flags = 0;
	size_t len;

	cp = line;
	arg = strdelim(&cp);
	/* Ignore leading whitespace */
	if (*arg == '\0')
		arg = strdelim(&cp);
	if (!arg || !*arg || *arg == '#')
		return 0;
	intptr = NULL;
	charptr = NULL;
	opcode = parse_token(arg, filename, linenum, &flags);

	if (activep == NULL) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	if (*activep && opcode != sMatch)
		debug3("%s:%d setting %s %s", filename, linenum, arg, cp);
	if (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		if (user == NULL) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, arg);
		} else { /* this is a directive we have already processed */
			while (arg)
				arg = strdelim(&cp);
			return 0;
		}
	}

	switch (opcode) {
	/* Portable-specific options */
	case sPAMAuthenticationViaKbdInt:
		log("%s line %d: PAMAuthenticationViaKbdInt has been "
		    "deprecated. You should use KbdInteractiveAuthentication "
		    "instead (which defaults to \"yes\").", filename, linenum);
		intptr = &options->pam_authentication_via_kbd_int;
		goto parse_flag;

	/* Standard Options */
	case sBadOption:
		return -1;
	case sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		if (options->ports_from_cmdline)
			return 0;
		if (options->listen_addrs != NULL)
			fatal("%s line %d: ports must be specified before "
			    "ListenAddress.", filename, linenum);
		if (options->num_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->num_ports++] = a2port(arg);
		if (options->ports[options->num_ports-1] == 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		break;

	case sServerKeyBits:
		intptr = &options->server_key_bits;
parse_int:
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: missing integer value.",
			    filename, linenum);
		value = atoi(arg);
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case sLoginGraceTime:
		intptr = &options->login_grace_time;
parse_time:
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		if ((value = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		if (*intptr == -1)
			*intptr = value;
		break;

	case sKeyRegenerationTime:
		intptr = &options->key_regeneration_time;
		goto parse_time;

	case sListenAddress:
		arg = strdelim(&cp);
		if (!arg || *arg == '\0' || strncmp(arg, "[]", 2) == 0)
			fatal("%s line %d: missing inet addr.",
			    filename, linenum);
		if (*arg == '[') {
			if ((p = strchr(arg, ']')) == NULL)
				fatal("%s line %d: bad ipv6 inet addr usage.",
				    filename, linenum);
			arg++;
			(void) memmove(p, p+1, strlen(p+1)+1);
		} else if (((p = strchr(arg, ':')) == NULL) ||
			    (strchr(p+1, ':') != NULL)) {
			add_listen_addr(options, arg, 0);
			break;
		}
		if (*p == ':') {
			u_short port;

			p++;
			if (*p == '\0')
				fatal("%s line %d: bad inet addr:port usage.",
				    filename, linenum);
			else {
				*(p-1) = '\0';
				if ((port = a2port(p)) == 0)
					fatal("%s line %d: bad port number.",
					    filename, linenum);
				add_listen_addr(options, arg, port);
			}
		} else if (*p == '\0')
			add_listen_addr(options, arg, 0);
		else
			fatal("%s line %d: bad inet addr usage.",
			    filename, linenum);
		break;

	case sHostKeyFile:
		intptr = &options->num_host_key_files;
		if (*intptr >= MAX_HOSTKEYS)
			fatal("%s line %d: too many host keys specified (max %d).",
			    filename, linenum, MAX_HOSTKEYS);
		charptr = &options->host_key_files[*intptr];
parse_filename:
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		if (*activep && *charptr == NULL) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			if (intptr != NULL)
				*intptr = *intptr + 1;
		}
		break;

	case sPidFile:
		charptr = &options->pid_file;
		goto parse_filename;

	case sPermitRootLogin:
		intptr = &options->permit_root_login;
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: missing yes/"
			    "without-password/forced-commands-only/no "
			    "argument.", filename, linenum);
		value = 0;	/* silence compiler */
		if (strcmp(arg, "without-password") == 0)
			value = PERMIT_NO_PASSWD;
		else if (strcmp(arg, "forced-commands-only") == 0)
			value = PERMIT_FORCED_ONLY;
		else if (strcmp(arg, "yes") == 0)
			value = PERMIT_YES;
		else if (strcmp(arg, "no") == 0)
			value = PERMIT_NO;
		else
			fatal("%s line %d: Bad yes/"
			    "without-password/forced-commands-only/no "
			    "argument: %s", filename, linenum, arg);
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
parse_flag:
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: missing yes/no argument.",
			    filename, linenum);
		value = 0;	/* silence compiler */
		if (strcmp(arg, "yes") == 0)
			value = 1;
		else if (strcmp(arg, "no") == 0)
			value = 0;
		else
			fatal("%s line %d: Bad yes/no argument: %s",
				filename, linenum, arg);
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
		goto parse_flag;

	case sRhostsAuthentication:
		intptr = &options->rhosts_authentication;
		goto parse_flag;

	case sRhostsRSAAuthentication:
		intptr = &options->rhosts_rsa_authentication;
		goto parse_flag;

	case sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		goto parse_flag;

	case sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		goto parse_flag;

	case sRSAAuthentication:
		intptr = &options->rsa_authentication;
		goto parse_flag;

	case sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		goto parse_flag;
#ifdef GSSAPI
	case sGssAuthentication:
		intptr = &options->gss_authentication;
		goto parse_flag;
	case sGssKeyEx:
		intptr = &options->gss_keyex;
		goto parse_flag;
	case sGssStoreDelegCreds:
		intptr = &options->gss_keyex;
		goto parse_flag;
#ifndef SUNW_GSSAPI
	case sGssUseSessionCredCache:
		intptr = &options->gss_use_session_ccache;
		goto parse_flag;
	case sGssCleanupCreds:
		intptr = &options->gss_cleanup_creds;
		goto parse_flag;
#endif /* SUNW_GSSAPI */
#endif /* GSSAPI */
#if defined(KRB4) || defined(KRB5)
	case sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		goto parse_flag;

	case sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		goto parse_flag;

	case sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		goto parse_flag;
#endif
#if defined(AFS) || defined(KRB5)
	case sKerberosTgtPassing:
		intptr = &options->kerberos_tgt_passing;
		goto parse_flag;
#endif
#ifdef AFS
	case sAFSTokenPassing:
		intptr = &options->afs_token_passing;
		goto parse_flag;
#endif

	case sPasswordAuthentication:
		intptr = &options->password_authentication;
		goto parse_flag;

	case sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		goto parse_flag;

	case sChallengeResponseAuthentication:
		intptr = &options->challenge_response_authentication;
		goto parse_flag;

	case sPrintMotd:
		intptr = &options->print_motd;
		goto parse_flag;

	case sPrintLastLog:
		log("%s line %d: ignoring PrintLastLog option value."
		    " This option is always on.", filename, linenum);
		while (arg)
			arg = strdelim(&cp);
		break;

	case sX11Forwarding:
		intptr = &options->x11_forwarding;
		goto parse_flag;

	case sX11DisplayOffset:
		intptr = &options->x11_display_offset;
		goto parse_int;

	case sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		goto parse_flag;

	case sXAuthLocation:
		charptr = &options->xauth_location;
		goto parse_filename;

	case sStrictModes:
		intptr = &options->strict_modes;
		goto parse_flag;

	case sKeepAlives:
		intptr = &options->keepalives;
		goto parse_flag;

	case sEmptyPasswd:
		intptr = &options->permit_empty_passwd;
		goto parse_flag;

	case sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		goto parse_flag;

	case sUseLogin:
		log("%s line %d: ignoring UseLogin option value."
		    " This option is always off.", filename, linenum);
		while (arg)
			arg = strdelim(&cp);
		break;

	case sCompression:
		intptr = &options->compression;
		goto parse_flag;

	case sGatewayPorts:
		intptr = &options->gateway_ports;
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: missing yes/no/clientspecified "
			    "argument.", filename, linenum);
		value = 0;	/* silence compiler */
		if (strcmp(arg, "clientspecified") == 0)
			value = 2;
		else if (strcmp(arg, "yes") == 0)
			value = 1;
		else if (strcmp(arg, "no") == 0)
			value = 0;
		else
			fatal("%s line %d: Bad yes/no/clientspecified "
			    "argument: %s", filename, linenum, arg);
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case sVerifyReverseMapping:
		intptr = &options->verify_reverse_mapping;
		goto parse_flag;

	case sLogFacility:
		intptr = (int *) &options->log_facility;
		arg = strdelim(&cp);
		value = log_facility_number(arg);
		if (value == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		if (*intptr == -1)
			*intptr = (SyslogFacility) value;
		break;

	case sLogLevel:
		intptr = (int *) &options->log_level;
		arg = strdelim(&cp);
		value = log_level_number(arg);
		if (value == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		if (*intptr == -1)
			*intptr = (LogLevel) value;
		break;

	case sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		goto parse_flag;

	case sUsePrivilegeSeparation:
		log("%s line %d: ignoring UsePrivilegeSeparation option value."
		    " This option is always on.", filename, linenum);
		while (arg)
			arg = strdelim(&cp);
		break;

	case sAllowUsers:
		while (((arg = strdelim(&cp)) != NULL) && *arg != '\0') {
			if (options->num_allow_users >= MAX_ALLOW_USERS)
				fatal("%s line %d: too many allow users.",
				    filename, linenum);
			options->allow_users[options->num_allow_users++] =
			    xstrdup(arg);
		}
		break;

	case sDenyUsers:
		while (((arg = strdelim(&cp)) != NULL) && *arg != '\0') {
			if (options->num_deny_users >= MAX_DENY_USERS)
				fatal( "%s line %d: too many deny users.",
				    filename, linenum);
			options->deny_users[options->num_deny_users++] =
			    xstrdup(arg);
		}
		break;

	case sAllowGroups:
		while (((arg = strdelim(&cp)) != NULL) && *arg != '\0') {
			if (options->num_allow_groups >= MAX_ALLOW_GROUPS)
				fatal("%s line %d: too many allow groups.",
				    filename, linenum);
			options->allow_groups[options->num_allow_groups++] =
			    xstrdup(arg);
		}
		break;

	case sDenyGroups:
		while (((arg = strdelim(&cp)) != NULL) && *arg != '\0') {
			if (options->num_deny_groups >= MAX_DENY_GROUPS)
				fatal("%s line %d: too many deny groups.",
				    filename, linenum);
			options->deny_groups[options->num_deny_groups++] = xstrdup(arg);
		}
		break;

	case sCiphers:
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.", filename, linenum);
		if (!ciphers_valid(arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		if (options->ciphers == NULL)
			options->ciphers = xstrdup(arg);
		break;

	case sMacs:
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.", filename, linenum);
		if (!mac_valid(arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		if (options->macs == NULL)
			options->macs = xstrdup(arg);
		break;

	case sProtocol:
		intptr = &options->protocol;
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.", filename, linenum);
		value = proto_spec(arg);
		if (value == SSH_PROTO_UNKNOWN)
			fatal("%s line %d: Bad protocol spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		if (*intptr == SSH_PROTO_UNKNOWN)
			*intptr = value;
		break;

	case sSubsystem:
		if (options->num_subsystems >= MAX_SUBSYSTEMS) {
			fatal("%s line %d: too many subsystems defined.",
			    filename, linenum);
		}
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: Missing subsystem name.",
			    filename, linenum);
		if (!*activep) {
			arg = strdelim(&cp);
			break;
		}
		for (i = 0; i < options->num_subsystems; i++)
			if (strcmp(arg, options->subsystem_name[i]) == 0)
				fatal("%s line %d: Subsystem '%s' already defined.",
				    filename, linenum, arg);
		options->subsystem_name[options->num_subsystems] = xstrdup(arg);
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: Missing subsystem command.",
			    filename, linenum);
		options->subsystem_command[options->num_subsystems] = xstrdup(arg);

		/*
		 * Collect arguments (separate to executable), including the
		 * name of the executable, in a way that is easier to parse
		 * later.
		 */
		p = xstrdup(arg);
		len = strlen(p) + 1;
		while ((arg = strdelim(&cp)) != NULL && *arg != '\0') {
			len += 1 + strlen(arg);
			p = xrealloc(p, len);
			strlcat(p, " ", len);
			strlcat(p, arg, len);
		}
		options->subsystem_args[options->num_subsystems] = p;
		options->num_subsystems++;
		break;

	case sMaxStartups:
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: Missing MaxStartups spec.",
			    filename, linenum);
		if ((n = sscanf(arg, "%d:%d:%d",
		    &options->max_startups_begin,
		    &options->max_startups_rate,
		    &options->max_startups)) == 3) {
			if (options->max_startups_begin >
			    options->max_startups ||
			    options->max_startups_rate > 100 ||
			    options->max_startups_rate < 1)
				fatal("%s line %d: Illegal MaxStartups spec.",
				    filename, linenum);
		} else if (n != 1)
			fatal("%s line %d: Illegal MaxStartups spec.",
			    filename, linenum);
		else
			options->max_startups = options->max_startups_begin;
		break;

	case sBanner:
		charptr = &options->banner;
		goto parse_filename;
	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	case sAuthorizedKeysFile:
	case sAuthorizedKeysFile2:
		charptr = (opcode == sAuthorizedKeysFile) ?
		    &options->authorized_keys_file :
		    &options->authorized_keys_file2;
		goto parse_filename;

	case sClientAliveInterval:
		intptr = &options->client_alive_interval;
		goto parse_time;

	case sClientAliveCountMax:
		intptr = &options->client_alive_count_max;
		goto parse_int;

	case sMaxAuthTries:
		intptr = &options->max_auth_tries;
		goto parse_int;

	case sMaxAuthTriesLog:
		intptr = &options->max_auth_tries_log;
		goto parse_int;

	case sLookupClientHostnames:
		intptr = &options->lookup_client_hostnames;
		goto parse_flag;

	case sUseOpenSSLEngine:
		intptr = &options->use_openssl_engine;
		goto parse_flag;

	case sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = strdelim(&cp);
		if (arg == NULL || *arg == '\0')
			fatal("%s line %d: missing directory name for "
			    "ChrootDirectory.", filename, linenum);
		if (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		break;

	case sPreUserauthHook:
		charptr = &options->pre_userauth_hook;
		goto parse_filename;

	case sMatch:
		if (cmdline)
			fatal("Match directive not supported as a command-line "
			   "option");
		value = match_cfg_line(&cp, linenum, user, host, address);
		if (value < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = value;
		break;

	case sDeprecated:
		log("%s line %d: Deprecated option %s",
		    filename, linenum, arg);
		while (arg)
		    arg = strdelim(&cp);
		break;

	case sPAMServicePrefix:
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		if (options->pam_service_name != NULL)
			fatal("%s line %d: PAMServiceName and PAMServicePrefix "
			    "are mutually exclusive.", filename, linenum);
		if (options->pam_service_prefix == NULL)
			options->pam_service_prefix = xstrdup(arg);
		break;

	case sPAMServiceName:
		arg = strdelim(&cp);
		if (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		if (options->pam_service_prefix != NULL)
			fatal("%s line %d: PAMServiceName and PAMServicePrefix "
			    "are mutually exclusive.", filename, linenum);
		if (options->pam_service_name == NULL)
			options->pam_service_name = xstrdup(arg);
		break;

	default:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, arg, opcode);
	}
	if ((arg = strdelim(&cp)) != NULL && *arg != '\0')
		fatal("%s line %d: garbage at end of line; \"%.200s\".",
		    filename, linenum, arg);
	return 0;
}


/* Reads the server configuration file. */

void
load_server_config(const char *filename, Buffer *conf)
{
	char line[1024], *cp;
	FILE *f;

	debug2("%s: filename %s", __func__, filename);
	if ((f = fopen(filename, "r")) == NULL) {
		perror(filename);
		exit(1);
	}
	buffer_clear(conf);
	while (fgets(line, sizeof(line), f)) {
		/*
		 * Trim out comments and strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		if ((cp = strchr(line, '#')) != NULL)
			memcpy(cp, "\n", 2);
		cp = line + strspn(line, " \t\r");

		buffer_append(conf, cp, strlen(cp));
	}
	buffer_append(conf, "\0", 1);
	fclose(f);
	debug2("%s: done config len = %d", __func__, buffer_len(conf));
}

void
parse_server_match_config(ServerOptions *options, const char *user,
    const char *host, const char *address)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", &cfg, user, host, address);
	copy_set_server_options(options, &mo, 0);
}



/* Helper macros */
#define M_CP_INTOPT(n) do {\
	if (src->n != -1) \
		dst->n = src->n; \
} while (0)
#define M_CP_STROPT(n) do {\
	if (src->n != NULL) { \
		if (dst->n != NULL) \
			xfree(dst->n); \
		dst->n = src->n; \
	} \
} while(0)

/*
 * Copy any supported values that are set.
 *
 * If the preauth flag is set, we do not bother copying the the string or
 * array values that are not used pre-authentication, because any that we
 * do use must be explictly sent in mm_getpwnamallow().
 */
void
copy_set_server_options(ServerOptions *dst, ServerOptions *src, int preauth)
{
	M_CP_INTOPT(password_authentication);
	M_CP_INTOPT(gss_authentication);
	M_CP_INTOPT(rsa_authentication);
	M_CP_INTOPT(pubkey_authentication);
	M_CP_INTOPT(hostbased_authentication);
	M_CP_INTOPT(kbd_interactive_authentication);
	M_CP_INTOPT(permit_root_login);
	M_CP_INTOPT(permit_empty_passwd);
	M_CP_INTOPT(allow_tcp_forwarding);
	M_CP_INTOPT(gateway_ports);
	M_CP_INTOPT(x11_display_offset);
	M_CP_INTOPT(x11_forwarding);
	M_CP_INTOPT(x11_use_localhost);
	M_CP_INTOPT(max_auth_tries);
	M_CP_STROPT(banner);

	if (preauth)
		return;
	M_CP_STROPT(chroot_directory);
}

#undef M_CP_INTOPT
#undef M_CP_STROPT

void
parse_server_config(ServerOptions *options, const char *filename, Buffer *conf,
    const char *user, const char *host, const char *address)
{
	int active, linenum, bad_options = 0;
	char *cp, *obuf, *cbuf;

	debug2("%s: config %s len %d", __func__, filename, buffer_len(conf));

	obuf = cbuf = xstrdup(buffer_ptr(conf));
	active = user ? 0 : 1;
	linenum = 1;
	while ((cp = strsep(&cbuf, "\n")) != NULL) {
		if (process_server_config_line(options, cp, filename,
		    linenum++, &active, user, host, address) != 0)
			bad_options++;
	}
	xfree(obuf);
	if (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}


/*
 * Note that "none" is a special path having the same affect on sshd
 * configuration as not specifying ChrootDirectory at all.
 */
int
chroot_requested(char *chroot_directory)
{
	return (chroot_directory != NULL &&
	    strcasecmp(chroot_directory, "none") != 0);
}
