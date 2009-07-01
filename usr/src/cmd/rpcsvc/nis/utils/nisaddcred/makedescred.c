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
 *	makedescred.c
 *
 *	Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*
 * makedescred.c
 *
 * Make a "AUTH_DES" credential. This is the old secure rpc credentials from
 * SunOS 4.0 and Vanilla System V release 4.0.
 */


#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <ctype.h>
#include <nsswitch.h>
#include <netdb.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nispasswd.h>
#include <rpcsvc/nis_dhext.h>
#include <rpc/key_prot.h>
#include "nisaddcred.h"
#include <assert.h>

extern char *getpass();
extern char *crypt();
extern void __gen_dhkeys(char *, char *, char *);
extern int add_cred_obj(nis_object *, char *);
extern int  check_switch_policy(char *, char *, struct __nsw_switchconfig *,
				char *, char *);
extern nis_error cred_exists(char *, char *, char *);
extern char *get_password(uid_t, int, char *, char *);
extern int is_switch_policy(struct __nsw_switchconfig *, char *);
extern int key_setnet(struct key_netstarg *arg);
extern int make_dhext_cred(char *, char *, char *, char *);
extern int modify_cred_obj(nis_object *, char *);
extern int no_switch_policy(struct __nsw_switchconfig *);
extern int sanity_checks(char *, char *, char *, char *);
extern char *switch_policy_str(struct __nsw_switchconfig *);
extern void write_rootkey(char *, char *, keylen_t, algtype_t);
extern int xencrypt(char *, char *);

static const char *OPSYS = "unix";
#define	OPSYS_LEN 4

/* ************************ switch functions *************************** */

/*	NSW_NOTSUCCESS  NSW_NOTFOUND   NSW_UNAVAIL    NSW_TRYAGAIN */
#define	DEF_ACTION {__NSW_RETURN, __NSW_RETURN, __NSW_CONTINUE, __NSW_CONTINUE}


/* ***************************** keylogin stuff *************************** */
int
keylogin_des(char *netname, char *secret)
{
	struct key_netstarg netst;

	netst.st_pub_key[0] = 0;
	(void) memcpy(netst.st_priv_key, secret, HEXKEYBYTES);
	netst.st_netname = netname;

#ifdef NFS_AUTH
	nra.authtype = AUTH_DES;	/* only revoke DES creds */
	nra.uid = getuid();		/* use the real uid */
	if (_nfssys(NFS_REVAUTH, &nra) < 0) {
		perror("Warning: NFS credentials not destroyed");
		err = 1;
	}
#endif /* NFS_AUTH */


	/* do actual key login */
	if (key_setnet(&netst) < 0) {
		fprintf(stderr, "Could not set %s's secret key\n", netname);
		fprintf(stderr, "May be the keyserv is down?\n");
		return (0);
	}

	return (1);
}


/*
 *	Definitions of the credential table.
 *
 * Column	Name			Contents
 * ------	----			--------
 *   0		cname			nis principal name
 *   1		auth_type		DES
 *   2		auth_name		netname
 *   3		public_auth_data	public key
 *   4		private_auth_data	encrypted secret key with checksum
 */

/*
 * Function for building DES credentials.
 *
 * The domain may be the local domain or some remote domain.
 * 'domain' should be the same as the domain found in netname,
 * which should be the home domain of nis+ principal.
 */


int
make_des_cred_be(char *nis_princ, char *netname, char *domain)
{
	nis_object	*obj = init_entry();
	char 		*pass;
	char		short_pass[DESCREDPASSLEN + 1];
	uid_t		uid;
	char 		public[HEXKEYBYTES + 1];
	char		secret[HEXKEYBYTES + 1];
	char		crypt1[HEXKEYBYTES + KEYCHECKSUMSIZE + 1];
	char		target_host[MAXHOSTNAMELEN+1];
	int		same_host = 0;
	int		status, len, addition;

	if (nis_princ == NULL)
		nis_princ = default_principal(domain);

	if (sanity_checks(nis_princ, netname, domain, "DES") == 0)
		return (0);

	addition = (cred_exists(nis_princ, "DES", domain) == NIS_NOTFOUND);

	/* Extract user/host information from netname */
	if (! isdigit(netname[OPSYS_LEN+1])) {
		uid = 0;  /* root */
		netname2host(netname, target_host, MAXHOSTNAMELEN);
		len = strlen(my_host)-1;   /* ignore trailing dot in my_host */
		if (len == strlen(target_host) &&
		    strncasecmp(target_host, my_host, len) == 0)
			same_host = 1;
	} else {
		uid = (uid_t)atoi(netname+OPSYS_LEN+1);
	}

	pass = get_password(uid, same_host, target_host, domain);
	if (pass == 0)
		return (0);

	(void) strlcpy(short_pass, pass, sizeof (short_pass));
	/* Get password with which to encrypt secret key. */
	(void) printf("%s key pair for %s (%s).\n",
	    addition? "Adding" : "Updating", netname, nis_princ);


	/* Encrypt secret key */
	(void) __gen_dhkeys(public, secret, short_pass);
	(void) memcpy(crypt1, secret, HEXKEYBYTES);
	(void) memcpy(crypt1 + HEXKEYBYTES, secret, KEYCHECKSUMSIZE);
	crypt1[HEXKEYBYTES + KEYCHECKSUMSIZE] = 0;
	xencrypt(crypt1, short_pass);


	/* Now we have a key pair, build up the cred entry */
	ENTRY_VAL(obj, 0) = nis_princ;
	ENTRY_LEN(obj, 0) = strlen(nis_princ) + 1;

	ENTRY_VAL(obj, 1) = "DES";
	ENTRY_LEN(obj, 1) = 4;

	ENTRY_VAL(obj, 2) = netname;
	ENTRY_LEN(obj, 2) = strlen(netname) + 1;

	ENTRY_VAL(obj, 3) = public;
	ENTRY_LEN(obj, 3) = strlen(public) + 1;
#ifdef OLD_MODE
	strcat(ENTRY_VAL(obj, 3), ":");
	ENTRY_LEN(obj, 3)++;
#endif

	ENTRY_VAL(obj, 4) = crypt1;
	ENTRY_LEN(obj, 4) = strlen(crypt1) + 1;

	if (addition) {
		obj->zo_owner = nis_princ;
		obj->zo_group = my_group;
		obj->zo_domain = domain;
		/* owner: r, group: rmcd */
		obj->zo_access = ((NIS_READ_ACC<<16)|
		    (NIS_READ_ACC|NIS_MODIFY_ACC|NIS_CREATE_ACC|
		    NIS_DESTROY_ACC)<<8);
		status = add_cred_obj(obj, domain);
	} else {
		obj->EN_data.en_cols.en_cols_val[3].ec_flags |= EN_MODIFIED;
		obj->EN_data.en_cols.en_cols_val[4].ec_flags |= EN_MODIFIED;
		status = modify_cred_obj(obj, domain);
	}


	/* attempt keylogin if appropriate */
	if (status) {
		if ((uid == my_uid) && ((uid != 0) || same_host))
			keylogin_des(netname, secret);
		if ((uid == 0) && same_host)
			write_rootkey(secret, "des", 192, 0);
	}
	return (status);
}


int
make_des_cred(char *nis_princ, char *netname, char *domain, char *flavor)
{
	mechanism_t	**mechlist;
	int		status = 0;
	int		i = 0;

	if (mechlist = (mechanism_t **)__nis_get_mechanisms(FALSE)) {
		while (mechlist[i]) {
			status = make_dhext_cred(nis_princ, netname,
			    domain,
			    mechlist[i]->alias);
			if (!status)
				return (status);
			i++;
		}
	} else
		status = make_des_cred_be(nis_princ, netname, domain);

	return (status);
}


char *
get_des_cred(domain, flavor)
char *domain;
char *flavor;	/* Ignored. */
{
	int		uid, status;
	static char netname[MAXNETNAMELEN+1];

	uid = my_uid;

	if (uid == 0)
		status = host2netname(netname, (char *)NULL, domain);
	else {
		/* generate netname using uid and domain information. */
		int len;
		len = strlen(domain);
		if ((len + OPSYS_LEN + 3 + MAXIPRINT) > MAXNETNAMELEN) {
			printf("Domain name too long: \"%s\"\n", domain);
			goto not_found;
		}
		(void) sprintf(netname, "%s.%d@%s", OPSYS, uid, domain);
		len = strlen(netname);
		if (netname[len-1] == '.')
			netname[len-1] = '\0';

		status = 1;
	}

	if (status == 1) {
		printf("DES principal name : \"%s\"\n", netname);
		return (netname);
	}

not_found:
	printf("DES principal name for %d not found\n", uid);
	return (NULL);
}
