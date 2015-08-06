/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2015 Gary Mills
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * DESCRIPTION: This is the N2L equivalent of changepasswd.c. The traditional
 *		version modifies the NIS source files and then initiates a
 *		ypmake to make the maps and push them.
 *
 *		For N2L there are no source files and the policy is that the
 *		definitive information is that contained in the DIT. Old
 *		information is read from LDAP. Assuming	this authenticates, and
 *		the change is acceptable, this information is modified and
 *		written back to LDAP.
 *
 *		Related map entries are then found and 	updated finally
 *		yppushes of the changed maps are initiated. Since the
 *		definitive information has already correctly been updated the
 *		code is tolerant of some errors during this operation.
 *
 *		What was previously in the maps is irrelevant.
 *
 *		Some less than perfect code (like inline constants for
 *		return values and a few globals) is retained from the original.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <pwd.h>
#include <signal.h>
#include <crypt.h>
#include <rpc/rpc.h>
#include <rpcsvc/yppasswd.h>
#include <utmpx.h>
#include <shadow.h>

#include <ndbm.h>
/* DO NOT INCLUDE SHIM_HOOKS.H */
#include "shim.h"
#include "yptol.h"
#include "../ldap_util.h"

/*
 * Undocumented external function in libnsl
 */
extern int  getdomainname(char *, int);

/* Constants */
#define	CRYPTPWSIZE CRYPT_MAXCIPHERTEXTLEN
#define	STRSIZE 100
#define	FINGERSIZE (4 * STRSIZE - 4)
#define	SHELLSIZE (STRSIZE - 2)

#define	UTUSERLEN (sizeof (((struct utmpx *)0)->ut_user))
#define	COLON_CHAR ':'

/*
 * Path to DBM files. This is only required for N2L mode. Traditional mode
 * works with the source files and uses the NIS Makefile to generate the maps.
 * Seems to be hard coded in the rest of NIS so same is done here.
 */
#define	YPDBPATH "/var/yp"

/* Names of password and adjunct mappings. Used to access DIT */
#define	BYNAME ".byname"
#define	BYUID ".byuid"
#define	BYGID ".bygid"
#define	PASSWD_MAPPING "passwd" BYNAME
#define	PASSWD_ADJUNCT_MAPPING "passwd.adjunct" BYNAME
#define	AGEING_MAPPING "ageing" BYNAME

/* Bitmasks used in list of fields to change */
#define	CNG_PASSWD 	0x0001
#define	CNG_SH		0x0002
#define	CNG_GECOS	0x0004

/* Globals :-( */
extern int single, nogecos, noshell, nopw, mflag;

/*
 * Structure for containing the information is currently in the DIT. This is
 * similar to the passwd structure defined in getpwent(3C) apart from.
 *
 * 1. Since GID and UID are never changed they are not converted to integers.
 * 2. There are extra fields to hold adjunct information.
 * 3. There are extra fields to hold widely used information.
 */
struct passwd_entry {
	char 	*pw_name;
	char 	*pw_passwd;
	char	*pw_uid;
	char	*pw_gid;
	char	*pw_gecos;
	char	*pw_dir;
	char	*pw_shell;
	char	*adjunct_tail;	/* Tail of adjunct entry (opaque) */
	bool_t	adjunct;	/* Flag indicating if DIT has adjunct info */
	char	*pwd_str;	/* New password string */
	char	*adjunct_str;	/* New adjunct string */
};

/* Prototypes */
extern bool_t validloginshell(char *sh, char *arg, int);
extern int    validstr(char *str, size_t size);

suc_code write_shadow_info(char *, struct spwd *);
int put_new_info(struct passwd_entry *, char *);
char *create_pwd_str(struct passwd_entry *, bool_t);
int proc_domain(struct yppasswd *, bool_t, char *);
int proc_request(struct yppasswd *, struct passwd_entry *, bool_t, char *);
int modify_ent(struct yppasswd *, struct passwd_entry *t, bool_t, char *);
int get_change_list(struct yppasswd *, struct passwd_entry *);
struct passwd_entry *get_old_info(char *, char *);
static char *get_next_token(char *, char **, char *);
void free_pwd_entry(struct passwd_entry *);
struct spwd *get_old_shadow(char *, char *);
suc_code decode_shadow_entry(datum *, struct spwd *);
void free_shadow_entry(struct spwd *);
int proc_maps(char *, struct passwd_entry *);
int proc_map_list(char **, char *, struct passwd_entry *, bool_t);
int update_single_map(char *, struct passwd_entry *, bool_t);
bool_t strend(char *s1, char *s2);

/*
 * FUNCTION:	shim_changepasswd()
 *
 * DESCRIPTION:	N2L version of changepasswd(). When this is called 'useshadow'
 *		etc. will have been set up but are meaningless. We work out
 *		what to change based on information from the DIT.
 *
 * INPUTS:	Identical to changepasswd()
 *
 * OUTPUTS:	Identical to changepasswd()
 */
void
shim_changepasswd(SVCXPRT *transp)
{
	struct yppasswd yppwd;
	bool_t	root_on_master = FALSE;
	char domain[MAXNETNAMELEN+1];
	char **domain_list;
	int dom_count, i;

	int	ret, ans = 2;	/* Answer codes */

	/* Clean out yppwd ... maybe we don't trust RPC */
	memset(&yppwd, 0, sizeof (struct yppasswd));

	/* Get the RPC args */
	if (!svc_getargs(transp, xdr_yppasswd, (caddr_t)&yppwd)) {
		svcerr_decode(transp);
		return;
	}

	/* Perform basic validation */
	if ((!validstr(yppwd.newpw.pw_passwd, CRYPTPWSIZE)) ||
		(!validstr(yppwd.newpw.pw_name, UTUSERLEN)) ||
		(!validstr(yppwd.newpw.pw_gecos, FINGERSIZE)) ||
		(!validstr(yppwd.newpw.pw_shell, SHELLSIZE))) {
		svcerr_decode(transp);
		return;
	}

	/*
	 * Special case: root on the master server can change other
	 * users' passwords without first entering the old password.
	 * We need to ensure that this is indeed root on the master
	 * server. (bug 1253949)
	 */
	if (strcmp(transp->xp_netid, "ticlts") == 0) {
		svc_local_cred_t cred;
		if (!svc_get_local_cred(transp, &cred)) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Couldn't get local user credentials");
		} else if (cred.ruid == 0)
			root_on_master = TRUE;
	}

	/*
	 * Get the domain name. This is tricky because a N2L server may be
	 * handling multiple domains. There is nothing in the request to
	 * indicate which one we are trying to change a passwd for. First
	 * we try to get a list of password related domains from the mapping
	 * file.
	 */
	if (0 !=
	    (dom_count = get_mapping_yppasswdd_domain_list(&domain_list))) {
		/* Got a domain list ... process all the domains */
		for (i = 0; i < dom_count; i ++) {
			ret = proc_domain(&yppwd, root_on_master,
								domain_list[i]);

			/* If one has worked don't care if others fail */
			if (0 != ans)
				ans = ret;
		}
	}
	else
	{
		/*
		 * There was no domain list in the mapping file. The
		 * traditional version of this code calls ypmake which picks
		 * up the domain returned by getdomainname(). Fall back to the
		 * same mechanism.
		 */
		if (0 > getdomainname(domain, MAXNETNAMELEN+1)) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Could not get any domain info");
		} else {
			/* Got one domain ... process it. */
			ans = proc_domain(&yppwd, root_on_master, domain);
		}
	}

	/* Send reply packet */
	if (!svc_sendreply(transp, xdr_int, (char *)&ans))
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
						"could not reply to RPC call");
}

/*
 * FUNCTION : 	proc_domain()
 *
 * DESCRIPTION:	Process a request for one domain
 *
 * GIVEN :	Pointer to the request.
 *		Root on master flag
 *		Domain
 *
 * OUTPUTS :	Answer code for reply
 */
int
proc_domain(struct yppasswd *yppwd, bool_t root_on_master, char *domain)
{
	struct passwd_entry *old_pwd;
	char	*p;
	int ans = 2;

	/* security hole fix from original source */
	for (p = yppwd->newpw.pw_name; (*p != '\0'); p++)
		if ((*p == ':') || !(isprint(*p)))
			*p = '$';	/* you lose buckwheat */
	for (p = yppwd->newpw.pw_passwd; (*p != '\0'); p++)
		if ((*p == ':') || !(isprint(*p)))
			*p = '$';	/* you lose buckwheat */

	/* Get old info from DIT for this domain */
	old_pwd = get_old_info(yppwd->newpw.pw_name, domain);
	if (NULL ==  old_pwd) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Could not get old information for %s in "
				"domain %s", yppwd->newpw.pw_name, domain);
		return (ans);
	}

	/* Have a request that can be replied to */
	ans = proc_request(yppwd, old_pwd, root_on_master, domain);
	free_pwd_entry(old_pwd);

	return (ans);
}

/*
 * FUNCTION :	proc_request()
 *
 * DESCRIPTION:	Process a request
 *
 * GIVEN :	Pointer to the request.
 *		Pointer to old information from LDAP
 *		Root on master flag
 *		Domain
 *
 * OUTPUTS :	Answer code for reply
 */
int
proc_request(struct yppasswd *yppwd, struct passwd_entry *old_pwd,
					bool_t root_on_master, char *domain)
{
	struct sigaction sa, osa1, osa2, osa3;
	int	ans;

	/* Authenticate */
	if ((0 != strcmp(crypt(yppwd->oldpass, old_pwd->pw_passwd),
				old_pwd->pw_passwd)) && !root_on_master) {
		logmsg(MSG_NOTIMECHECK, LOG_NOTICE, "Passwd incorrect %s",
						yppwd->newpw.pw_name);
		return (7);
	}

	/* Work out what we have to change and change it */
	ans = modify_ent(yppwd, old_pwd, root_on_master, domain);
	if (0 != ans)
		return (ans);

	/*
	 * Generate passwd and adjunct map entries. This creates extra
	 * malloced strings in old_pwd. These will be freed when
	 * free_pwd_entry() is called to free up the rest of the structure.
	 */
	old_pwd->pwd_str = create_pwd_str(old_pwd, FALSE);
	if (NULL == old_pwd->pwd_str) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Could not create passwd entry");
		return (2);
	}
	if (old_pwd->adjunct) {
		old_pwd->adjunct_str = create_pwd_str(old_pwd, TRUE);
		if (NULL == old_pwd->adjunct_str) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Could not create adjunct entry");
			return (2);
		}
	} else {
		old_pwd->adjunct_str = NULL;
	}

	/* Put the information back to DIT */
	ans = put_new_info(old_pwd, domain);
	if (0 != ans) {
		return (ans);
	}

	/* Are going to be forking pushes, set up signals */
	memset(&sa, 0, sizeof (struct sigaction));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGTSTP, &sa, (struct sigaction *)0);
	sigaction(SIGHUP,  &sa, &osa1);
	sigaction(SIGINT,  &sa, &osa2);
	sigaction(SIGQUIT, &sa, &osa3);

	/* Update and push all the maps */
	ans = proc_maps(domain, old_pwd);

	/* Tidy up signals */
	sigaction(SIGHUP,  &osa1, (struct sigaction *)0);
	sigaction(SIGINT,  &osa2, (struct sigaction *)0);
	sigaction(SIGQUIT, &osa3, (struct sigaction *)0);

	return (ans);
}

/*
 * FUNCTION:	proc_maps()
 *
 * DESCRIPTION: Gets all the map lists and processes them.
 *
 * INPUTS:	Domain name
 *		New info to write into maps
 *
 * OUTPUT :	Answer code
 */
int
proc_maps(char *domain, struct passwd_entry *pwd)
{
	char	**map_list; 	/* Array of passwd or adjunct maps */
	int	ans = 0;

	/* Get list of passwd maps from mapping file */
	map_list = get_passwd_list(FALSE, domain);
	if (map_list != NULL) {
		/* Process list of passwd maps */
		ans = proc_map_list(map_list, domain, pwd, FALSE);
		free_passwd_list(map_list);
		if (0 != ans)
			return (ans);
	}

	/*
	 * If we get here either there were no passwd maps or there were
	 * some and they were processed successfully. Either case is good
	 * continue and process passwd.adjunct maps.
	 */

	/* Get list of adjunct maps from mapping file */
	map_list = get_passwd_list(TRUE, domain);
	if (map_list != NULL) {
		/*
		 * Process list of adjunct maps. If the required information
		 * is not present in LDAP then the updates attempts will log
		 * an error. No need to make the check here
		 */
		ans = proc_map_list(map_list, domain, pwd, TRUE);
		free_passwd_list(map_list);
	}

	return (ans);
}

/*
 * FUNCTION:	proc_map_list()
 *
 * DESCRIPTION: Finds entries in one list of map that need to be updated.
 *		updates them and writes them back.
 *
 * INPUTS:	Null terminated list of maps to process.
 *		Domain name
 *		Information to write (including user name)
 *		Flag indicating if this is the adjunct list
 *
 * OUTPUTS:	An error code
 */
int
proc_map_list(char **map_list, char *domain,
				struct passwd_entry *pwd, bool_t adjunct_flag)
{
	char 	*myself = "proc_map_list";
	char	*map_name;
	char	cmdbuf[BUFSIZ];
	int	map_name_len = 0;
	int	index, ans = 0;

	/* If this is a adjunct list check LDAP had some adjunct info */
	if ((adjunct_flag) && (!pwd->adjunct)) {
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"Have adjunct map list but no adjunct data in DIT");
		/* Not a disaster */
		return (0);
	}

	/* Allocate enough buffer to take longest map name */
	for (index = 0; map_list[index] != NULL; index ++)
		if (map_name_len < strlen(map_list[index]))
			map_name_len = strlen(map_list[index]);
	map_name_len += strlen(YPDBPATH);
	map_name_len += strlen(NTOL_PREFIX);
	map_name_len += strlen(domain);
	map_name_len += 3;
	if (NULL == (map_name = am(myself, map_name_len))) {
		logmsg(MSG_NOMEM, LOG_ERR, "Could not alloc map name");
		return (2);
	}

	/* For all maps in list */
	for (index = 0; map_list[index] != NULL; index ++) {

		/* Generate full map name */
		strcpy(map_name, YPDBPATH);
		add_separator(map_name);
		strcat(map_name, domain);
		add_separator(map_name);
		strcat(map_name, NTOL_PREFIX);
		strcat(map_name, map_list[index]);

		if (0 != (ans = update_single_map(map_name, pwd, adjunct_flag)))
			break;
	}

	/* Done with full map path */
	sfree(map_name);

	/*
	 * If (ans != 0) then one more maps have failed. LDAP has however been
	 * updates. This is the definitive source for information there is no
	 * need to unwind. (This was probably due to maps that were already
	 * corrupt).
	 */

	/*
	 * If it all worked fork off push operations for the maps. Since we
	 * want the map to end up with it's traditional name on the slave send
	 * the name without its LDAP_ prefix. The slave will call ypxfrd
	 * which, since it is running in N2L mode, will put the prefix back on
	 * before reading the file.
	 */
	if (mflag && (0 == ans)) {
		for (index = 0; (map_name = map_list[index]) != NULL;
								index ++) {
			if (fork() == 0) {
				/*
				 * Define full path to yppush. Probably also
				 * best for security.
				 */
				strcpy(cmdbuf, "/usr/lib/netsvc/yp/yppush ");
				strcat(cmdbuf, map_name);
				if (0 > system(cmdbuf))
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
						"Could not initiate yppush");
				exit(0);
			}
		}
	}
	return (ans);
}

/*
 * FUNCTION :	update_single_map()
 *
 * DESCRIPTION:	Updates one map. This is messy because we want to lock the map
 *		to prevent other processes from updating it at the same time.
 *		This mandates that we open it using the shim. When we
 *		write to it however we DO NOT want to write through to LDAP
 *		i.e. do not want to use the shim.
 *
 *		Solution : Do not include shim_hooks.h but call the shim
 *		versions of dbm_functions explicitly where needed.
 *
 * INPUT :	Full name of map
 *		Information to write (including user name)
 *		Flag indicating if this is an adjunct map.
 *
 * OUTPUT :	Answer code
 *
 */
int
update_single_map(char *map_name, struct passwd_entry *pwd, bool_t adjunct_flag)
{
	DBM	*map;
	int	res;
	datum	data, key;

	/* Set up data */
	if (adjunct_flag)
		data.dptr = pwd->adjunct_str;
	else
		data.dptr = pwd->pwd_str;
	data.dsize = strlen(data.dptr);

	/* Set up key dependent on which type of map this is */
	key.dptr = NULL;
	if (strend(map_name, BYNAME))
		key.dptr = pwd->pw_name;
	if (strend(map_name, BYUID))
		key.dptr = pwd->pw_uid;
	if (strend(map_name, BYGID))
		key.dptr = pwd->pw_gid;

	if (NULL == key.dptr) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Unrecognized map type %s", map_name);
		return (0);		/* Next map */
	}
	key.dsize = strlen(key.dptr);

	/* Open the map */
	map = shim_dbm_open(map_name, O_RDWR, 0600);
	if (NULL == map) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "Could not open %s", map_name);
		return (0);		/* Next map */
	}

	/* Lock map for update. Painful and may block but have to do it */
	if (SUCCESS != lock_map_update((map_ctrl *)map)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Could not lock map %s for update", map_name);
		shim_dbm_close(map);
		return (2);
	}

	/* Do the update use simple DBM operation */
	res = dbm_store(((map_ctrl *)map)->entries, key, data, DBM_REPLACE);

	/* update entry TTL. If we fail not a problem will just timeout early */
	update_entry_ttl((map_ctrl *)map, &key, TTL_RAND);

	/*
	 * Map has been modified so update YP_LAST_MODIFIED. In the vanilla
	 * NIS case this would have been done by the ypmake done after updating
	 * the passwd source file. If this fails not a great problem the map
	 */
	if (FAILURE == update_timestamp(((map_ctrl *)map)->entries)) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR, "Could not update "
			"YP_LAST_MODIFIED %s will not be pushed this time",
			map_name);
	}

	/*
	 * Possibly should hold the lock until after push is complete
	 * but this could deadlock if client is slow and ypxfrd also
	 * decides to do an update.
	 */
	unlock_map_update((map_ctrl *)map);

	/* Close the map */
	shim_dbm_close(map);

	if (0 != res) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Could not update map %s", map_name);
		return (2);
	}

	return (0);
}

/*
 * FUNCTION :	strend()
 *
 * DESCRIPTION:	Determines if one string ends with another.
 */
bool_t
strend(char *s1, char *s2)
{
	int len_dif;

	len_dif = strlen(s1) - strlen(s2);
	if (0 > len_dif)
		return (FALSE);
	if (0 == strcmp(s1 + len_dif, s2))
		return (TRUE);
	return (FALSE);
}

/*
 * FUNCTION:	modify_ent()
 *
 * DESCRIPTION: Modify an entry to reflect a request.
 *
 * INPUT:	Pointer to the request.
 *		Pointer to the entry to modify.
 *		Flag indication if we are root on master
 *		Domain
 *
 * OUTPUT:	Error code
 */
int
modify_ent(struct yppasswd *yppwd, struct passwd_entry *old_ent,
					bool_t root_on_master, char *domain)
{
	int change_list;
	struct spwd *shadow;
	time_t now;

	/* Get list of changes */
	change_list = get_change_list(yppwd, old_ent);

	if (!change_list) {
		logmsg(MSG_NOTIMECHECK, LOG_NOTICE,
				"No change for %s", yppwd->newpw.pw_name);
		return (3);
	}

	/* Check that the shell we have been given is acceptable. */
	if ((change_list & CNG_SH) && (!validloginshell(old_ent->pw_shell,
					yppwd->newpw.pw_shell, root_on_master)))
		return (2);

	/*
	 * If changing the password do any aging checks.
	 * Since there are no shadow maps this is done by accessing
	 * attributes in the DIT via the mapping system.
	 */
	if (change_list & CNG_PASSWD) {

		/* Try to get shadow information */
		shadow = get_old_shadow(yppwd->newpw.pw_name, domain);

		/* If there is shadow information make password aging checks */
		if (NULL != shadow) {
			now = DAY_NOW;
			/* password aging - bug for bug compatibility */
			if (shadow->sp_max != -1) {
				if (now < shadow->sp_lstchg + shadow->sp_min) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Sorry: < %ld days since "
					"the last change", shadow->sp_min);
					free_shadow_entry(shadow);
					return (2);
				}
		}

			/* Update time of change */
			shadow->sp_lstchg = now;

			/* Write it back */
			write_shadow_info(domain, shadow);

			free_shadow_entry(shadow);
		}
	}

	/* Make changes to old entity */
	if (change_list & CNG_GECOS) {
		if (NULL != old_ent->pw_gecos)
			sfree(old_ent->pw_gecos);
		old_ent->pw_gecos = strdup(yppwd->newpw.pw_gecos);
		if (NULL == old_ent->pw_gecos) {
			logmsg(MSG_NOMEM, LOG_ERR, "Could not allocate gecos");
			return (2);
		}
	}

	if (change_list & CNG_SH) {
		if (NULL != old_ent->pw_shell)
			sfree(old_ent->pw_shell);
		old_ent->pw_shell = strdup(yppwd->newpw.pw_shell);
		if (NULL == old_ent->pw_shell) {
			logmsg(MSG_NOMEM, LOG_ERR, "Could not allocate shell");
			return (2);
		}
	}

	if (change_list & CNG_PASSWD) {
		if (NULL != old_ent->pw_passwd)
			sfree(old_ent->pw_passwd);
		old_ent->pw_passwd = strdup(yppwd->newpw.pw_passwd);
		if (NULL == old_ent->pw_passwd) {
			logmsg(MSG_NOMEM, LOG_ERR, "Could not allocate passwd");
			return (2);
		}
	}

	return (0);
}

/*
 * FUNCTION :	get_change_list()
 *
 * DESCRIPTION:	Works out what we have to change.
 *
 * INPUTS :	Request.
 *		Structure containing current state of entry
 *
 * OUTPUTS :	A bitmask signaling what to change. (Implemented in this
 *		way to make it easy to pass between functions).
 */
int
get_change_list(struct yppasswd *yppwd, struct passwd_entry *old_ent)
{
	int list = 0;
	char *p;

	p = yppwd->newpw.pw_passwd;
	if ((!nopw) &&
		p && *p &&
		!(*p++ == '#' && *p++ == '#' &&
		(strcmp(p, old_ent->pw_name) == 0)) &&
		(strcmp(crypt(old_ent->pw_passwd,
			yppwd->newpw.pw_passwd), yppwd->newpw.pw_passwd) != 0))
		list |= CNG_PASSWD;

	if ((NULL != old_ent->pw_shell) &&
		(!noshell) &&
		(strcmp(old_ent->pw_shell, yppwd->newpw.pw_shell) != 0)) {
		if (single)
			list = 0;
		list |= CNG_SH;
	}

	if ((NULL != old_ent->pw_gecos) &&
		(!nogecos) &&
		(strcmp(old_ent->pw_gecos, yppwd->newpw.pw_gecos) != 0)) {
		if (single)
			list = 0;
		list |= CNG_GECOS;
	}

	return (list);
}

/*
 * FUNCTION :	decode_pwd_entry()
 *
 * DESCRIPTION:	Pulls apart a password entry. Because the password entry has
 *		come from the mapping system it can be assumed to be correctly
 *		formatted and relatively simple parsing can be done.
 *
 *		Substrings are put into malloced memory. Caller to free.
 *
 *		For adjunct files most of it is left empty.
 *
 *		It would be nice to use getpwent and friends for this work but
 *		these only seem to exist for files and it seems excessive to
 *		create a temporary file for this operation.
 *
 * INPUTS:	Pointer to datum containing password string.
 *		Pointer to structure in which to return results
 *		Flag indicating if we are decoding passwd or passwd.adjunct
 *
 * OUTPUTS:	SUCCESS = Decoded successfully
 *		FAILURE = Not decoded successfully. Caller to tidy up.
 */
suc_code
decode_pwd_entry(datum *data, struct passwd_entry *pwd, bool_t adjunct)
{
	char *myself = "decode_pwd_entry";
	char *p, *str_end, *temp;

	/* Work out last location in string */
	str_end = data->dptr + data->dsize;

	/* Name */
	if (NULL == (p = get_next_token(data->dptr, &temp, str_end)))
		return (FAILURE);
	if (adjunct) {
		/* If we found an adjunct version this is the one to use */
		if (NULL != pwd->pw_name)
			sfree(pwd->pw_name);
	}
	pwd->pw_name = temp;

	/* Password */
	if (NULL == (p = get_next_token(p, &temp, str_end)))
		return (FAILURE);
	if (adjunct) {
		/* If we found an adjunct version this is the one to use */
		if (NULL != pwd->pw_passwd)
			sfree(pwd->pw_passwd);
	}
	pwd->pw_passwd = temp;

	if (adjunct) {
		/* Store adjunct information in opaque string */
		pwd->adjunct_tail = am(myself, str_end - p + 1);
		if (NULL == pwd->adjunct_tail)
			return (FAILURE);
		strncpy(pwd->adjunct_tail, p, str_end - p);
		pwd->adjunct_tail[str_end - p] = '\0';

		/* Remember that LDAP contained adjunct data */
		pwd->adjunct = TRUE;
		return (SUCCESS);
	}

	/* If we get here not adjunct. Decode rest of passwd */

	/* UID */
	if (NULL == (p = get_next_token(p, &(pwd->pw_uid), str_end)))
		return (FAILURE);

	/* GID */
	if (NULL == (p = get_next_token(p, &(pwd->pw_gid), str_end)))
		return (FAILURE);

	/* Gecos */
	if (NULL == (p = get_next_token(p, &(pwd->pw_gecos), str_end)))
		return (FAILURE);

	/* Home dir */
	if (NULL == (p = get_next_token(p, &(pwd->pw_dir), str_end)))
		return (FAILURE);

	/* Shell may not be present so don't check return */
	get_next_token(p, &(pwd->pw_shell), str_end);

	if (NULL == pwd->pw_shell)
		return (FAILURE);

	return (SUCCESS);
}

/*
 * FUNCTION :	get_next_token()
 *
 * DESCRIPTION:	Gets the next token from a string upto the next colon or the
 *		end of the string. The duplicates this token into malloced
 *		memory removing any spaces.
 *
 * INPUTS :	String to search for token. NOT NULL TERMINATED
 *		Location to return result (NULL if result not required)
 *		Last location in string
 *
 * OUTPUT :	Pointer into the string immediately after the token.
 *		NULL if end of string reached or error.
 */
static char *
get_next_token(char *str, char **op, char *str_end)
{
	char *myself = "get_next_token";
	char *p, *tok_start, *tok_end;

	p = str;
	/* Skip leading whitespace */
	while (' ' == *p)
		p++;
	tok_start = p;
	tok_end = p;

	while ((str_end + 1 != p) && (COLON_CHAR != *p)) {
		if (' ' != *p)
			tok_end = p;
		p++;
	}

	/* Required string is now between start and end */
	if (NULL != op) {
		*op = am(myself, tok_end - tok_start + 2);
		if (NULL == *op) {
			logmsg(MSG_NOMEM, LOG_ERR,
					"Could not alloc memory for token");
			return (NULL);
		}
		strncpy(*op, tok_start, tok_end - tok_start + 1);

		/* Terminate token */
		(*op)[tok_end - tok_start + 1] = '\0';

	}

	/* Check if we reached the end of the input string */
	if ('\0' == *p)
		return (NULL);

	/* There is some more */
	p++;
	return (p);
}

/*
 * FUNCTION :	free_pwd_entry()
 *
 * DESCRIPTION:	Frees up a pwd_entry structure and its contents.
 *
 * INPUTS:	Pointer to the structure to free.
 *
 * OUTPUT:	Nothing
 */
void
free_pwd_entry(struct passwd_entry *pwd)
{
	/* Free up strings */
	if (NULL != pwd->pw_name)
		sfree(pwd->pw_name);

	if (NULL != pwd->pw_passwd)
		sfree(pwd->pw_passwd);

	if (NULL != pwd->pw_gecos)
		sfree(pwd->pw_gecos);

	if (NULL != pwd->pw_shell)
		sfree(pwd->pw_shell);

	if (NULL != pwd->pw_dir)
		sfree(pwd->pw_dir);

	if (NULL != pwd->adjunct_tail)
		sfree(pwd->adjunct_tail);

	if (NULL != pwd->pwd_str)
		sfree(pwd->pwd_str);

	if (NULL != pwd->adjunct_str)
		sfree(pwd->adjunct_str);

	/* Free up structure */
	sfree(pwd);
}

/*
 * FUNCTION :	create_pwd_str()
 *
 * DESCRIPTION:	Builds up a new password entity string from a passwd structure.
 *
 * INPUTS :	Structure containing password details
 *		Flag indicating if we should create an adjunct or passwd string.
 *
 * OUTPUTS :	String in malloced memory (to be freed by caller).
 *		NULL on failure.
 */
char *
create_pwd_str(struct passwd_entry *pwd, bool_t adjunct)
{
	char *myself = "create_pwd_str";
	char *s;
	int len;

	/* Separator string so we can strcat separator onto things */
	char sep_str[2] = {COLON_CHAR, '\0'};

	/* Work out the size */
	len = strlen(pwd->pw_name) + 1;
	len += strlen(pwd->pw_passwd) + 1;
	if (adjunct) {
		len += strlen(pwd->adjunct_tail) + 1;
	} else {
		len += strlen(pwd->pw_uid) + 1;
		len += strlen(pwd->pw_gid) + 1;
		len += strlen(pwd->pw_gecos) + 1;
		len += strlen(pwd->pw_dir) + 1;
		len += strlen(pwd->pw_shell) + 1;
	}

	/* Allocate some memory for it */
	s = am(myself, len);
	if (NULL == s)
		return (NULL);

	strcpy(s, pwd->pw_name);
	strcat(s, sep_str);
	if (!adjunct) {
		/* Build up a passwd string */

		/* If LDAP contains adjunct info then passwd is 'x' */
		if (pwd->adjunct) {
			strcat(s, "##");
			strcat(s,  pwd->pw_name);
		} else {
			strcat(s, pwd->pw_passwd);
		}
		strcat(s, sep_str);
		strcat(s, pwd->pw_uid);
		strcat(s, sep_str);
		strcat(s, pwd->pw_gid);
		strcat(s, sep_str);
		strcat(s, pwd->pw_gecos);
		strcat(s, sep_str);
		strcat(s, pwd->pw_dir);
		strcat(s, sep_str);
		strcat(s, pwd->pw_shell);
	} else {
		/* Build up a passwd_adjunct string */
		strcat(s, pwd->pw_passwd);
		strcat(s, sep_str);
		strcat(s, pwd->adjunct_tail);
	}

	return (s);
}

/*
 * FUNCTION:	get_old_info()
 *
 * DESCRIPTION:	Gets as much information as possible from LDAP about one user.
 *
 *		This goes through the mapping system. This is messy because
 *		them mapping system will build up a password entry from the
 *		contents of the DIT. We then have to parse this to recover
 *		it's individual fields.
 *
 * INPUT:	Pointer to user name
 *		Domain
 *
 * OUTPUT:	The info in malloced space. To be freed by caller.
 *		NULL on failure.
 */
struct passwd_entry *
get_old_info(char *name, char *domain)
{
	char *myself = "get_old_info";
	struct passwd_entry *old_passwd;
	datum	key, data;
	suc_code res;

	/* Get the password entry */
	key.dptr = name;
	key.dsize = strlen(key.dptr);
	read_from_dit(PASSWD_MAPPING, domain, &key, &data);
	if (NULL == data.dptr) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Could not read old pwd for %s", name);
		return (NULL);
	}

	/* Pull password apart */
	old_passwd = am(myself, sizeof (struct passwd_entry));
	if (NULL == old_passwd) {
		logmsg(MSG_NOMEM, LOG_ERR, "Could not alloc for pwd decode");
		sfree(data.dptr);
		return (NULL);
	}

	/* No data yet */
	old_passwd->pw_name = NULL;
	old_passwd->pw_passwd = NULL;
	old_passwd->pw_uid = NULL;
	old_passwd->pw_gid = NULL;
	old_passwd->pw_gecos = NULL;
	old_passwd->pw_dir = NULL;
	old_passwd->pw_shell = NULL;
	old_passwd->adjunct_tail = NULL;
	old_passwd->pwd_str = NULL;
	old_passwd->adjunct_str = NULL;
	old_passwd->adjunct = FALSE;

	res = decode_pwd_entry(&data, old_passwd, FALSE);
	sfree(data.dptr);
	if (SUCCESS != res) {
		free_pwd_entry(old_passwd);
		return (NULL);
	}

	/* Try to get the adjunct entry */
	read_from_dit(PASSWD_ADJUNCT_MAPPING, domain, &key, &data);
	if (NULL == data.dptr) {
		/* Fine just no adjunct data */
		old_passwd->adjunct = FALSE;
	} else {
		res = decode_pwd_entry(&data, old_passwd, TRUE);
		sfree(data.dptr);
		if (SUCCESS != res) {
			free_pwd_entry(old_passwd);
			return (NULL);
		}
	}

	return (old_passwd);
}

/*
 * FUNCTION :	put_new_info()
 *
 * DESCRIPTION:	Generates new map strings and puts them back to LDAP
 *
 * INPUTS:	Info to put back
 *		Domain
 *
 * OUTPUT:	Answer code.
 */
int
put_new_info(struct passwd_entry *pwd, char *domain)
{
	datum	key, data;

	/* Write it back to LDAP */
	data.dptr = pwd->pwd_str;
	data.dsize = strlen(data.dptr);
	key.dptr = pwd->pw_name;
	key.dsize = strlen(key.dptr);
	if (SUCCESS != write_to_dit(PASSWD_MAPPING, domain, key, data,
								TRUE, FALSE))
		return (2);


	/* If DIT contains adjunct information do the same for adjunct */
	if (pwd->adjunct) {
		data.dptr = pwd->adjunct_str;
		data.dsize = strlen(data.dptr);
		key.dptr = pwd->pw_name;
		key.dsize = strlen(key.dptr);
		if (SUCCESS != write_to_dit(PASSWD_ADJUNCT_MAPPING, domain,
						key, data, TRUE, FALSE))
			return (2);
	}

	return (0);

}

/*
 * FUNCTION :   get_old_shadow()
 *
 * DESCRIPTION :Extracts and decodes shadow information from the DIT
 *		See also comments under decode_pwd_entry().
 *
 * INPUTS :     User name
 *		Domain name
 *
 * OUTPUT :     Shadow information in malloced memory. To be freed by caller.
 */
struct spwd *
get_old_shadow(char *name, char *domain)
{
	char *myself = "get_old_shadow";
	struct spwd *sp;
	datum key, data;
	suc_code res;

	/* Get the info */
	key.dptr = name;
	key.dsize = strlen(key.dptr);	/* Len excluding terminator */
	read_from_dit(AGEING_MAPPING, domain, &key, &data);

	if (NULL == data.dptr) {
		/* OK just have no shadow info in DIT */
		return (NULL);
	}

	/* Pull shadow apart */
	if (NULL == (sp = am(myself, sizeof (struct spwd)))) {
		logmsg(MSG_NOMEM, LOG_ERR,
					"Could not alloc for shadow decode");
		sfree(data.dptr);
		return (NULL);
	}
	sp->sp_namp = NULL;
	sp->sp_pwdp = NULL;

	res = decode_shadow_entry(&data, sp);
	sfree(data.dptr);
	if (SUCCESS != res) {
		free_shadow_entry(sp);
		return (NULL);
	}

	return (sp);
}

/*
 * FUNCTION :	decode_shadow_entry()
 *
 * DESCRIPTION:	Pulls apart ageing information. For convenience this is stored
 *		in a partially filled spwd structure.
 *
 *		SEE COMMENTS FOR decode_pwd_entry()
 */
suc_code
decode_shadow_entry(datum *data, struct spwd *sp)
{
	char *p, *str_end, *temp;

	/* Work out last location in string */
	str_end = data->dptr + data->dsize;

	/* Name */
	if (NULL == (p = get_next_token(data->dptr, &(sp->sp_namp), str_end)))
		return (FAILURE);

	/* date of last change */
	if (NULL == (p = get_next_token(p, &temp, str_end)))
		return (FAILURE);
	sp->sp_lstchg = atoi(temp);

	/* min days to passwd change */
	if (NULL == (p = get_next_token(p, &temp, str_end)))
		return (FAILURE);
	sp->sp_min = atoi(temp);

	/* max days to passwd change */
	if (NULL == (p = get_next_token(p, &temp, str_end)))
		return (FAILURE);
	sp->sp_max = atoi(temp);

	/* warning period */
	if (NULL == (p = get_next_token(p, &temp, str_end)))
		return (FAILURE);
	sp->sp_warn = atoi(temp);

	/* max days inactive */
	if (NULL == (p = get_next_token(p, &temp, str_end)))
		return (FAILURE);
	sp->sp_inact = atoi(temp);

	/* account expiry date */
	if (NULL == (p = get_next_token(p, &temp, str_end)))
		return (FAILURE);
	sp->sp_expire = atoi(temp);

	/* flag  */
	if (NULL != (p = get_next_token(p, &temp, str_end)))
		return (FAILURE);
	sp->sp_flag = atoi(temp);

	return (SUCCESS);
}

/*
 * FUNCTION :	write_shadow_info()
 *
 * DESCRIPTION:	Writes shadow information back to the DIT.
 *
 * INPUTS :	Domain
 *		Information to write
 *
 * OUTPUT :	Success code
 *
 */
suc_code
write_shadow_info(char *domain, struct spwd *sp)
{
	char *myself = "write_shadow_info";
	datum key, data;
	char *str;
	suc_code res;
	int len;

	/* Work out how long string will be */
	len = strlen(sp->sp_namp) + 1;

	/*
	 * Bit crude but if we assume 1 byte is 3 decimal characters
	 * will get enough buffer for the longs and some spare.
	 */
	len += 7 * (3 * sizeof (long) + 1);

	/* Allocate some memory */
	str = am(myself, len);
	if (NULL == str) {
		logmsg(MSG_NOMEM, LOG_ERR, "Could not aloc for shadow write");
		return (FAILURE);
	}

	/* Build up shadow string */
	sprintf(str, "%s%c%d%c%d%c%d%c%d%c%d%c%d%c%d",
		sp->sp_namp, COLON_CHAR,
		sp->sp_lstchg, COLON_CHAR,
		sp->sp_min, COLON_CHAR,
		sp->sp_max, COLON_CHAR,
		sp->sp_warn, COLON_CHAR,
		sp->sp_inact, COLON_CHAR,
		sp->sp_expire, COLON_CHAR,
		sp->sp_flag);

	/* Write it */
	data.dptr = str;
	data.dsize = strlen(data.dptr);
	key.dptr = sp->sp_namp;
	key.dsize = strlen(key.dptr);
	res = write_to_dit(AGEING_MAPPING, domain, key, data, TRUE, FALSE);

	sfree(str);
	return (res);
}

/*
 * FUNCTION :	free_shadow_entry()
 *
 * DESCRIPTION:	Frees up a shadow information structure
 *
 * INPUTS :	Structure to free
 *
 * OUTPUTS :	Nothing
 */
void
free_shadow_entry(struct spwd *spwd)
{
	if (NULL != spwd->sp_namp)
		sfree(spwd->sp_namp);

	if (NULL != spwd->sp_pwdp)
		sfree(spwd->sp_pwdp);

	/* No need to free numerics */

	/* Free up structure */
	sfree(spwd);
}
