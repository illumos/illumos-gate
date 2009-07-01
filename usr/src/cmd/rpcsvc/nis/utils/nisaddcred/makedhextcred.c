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
 * Make extended diffie-hellman GSS credential.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <shadow.h>
#include <nsswitch.h>
#include <netdb.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nispasswd.h>
#include <rpcsvc/nis_dhext.h>
#include <rpc/key_prot.h>
#include "nisaddcred.h"

extern char *getpass();
extern char *getpassphrase();
extern char *crypt();
extern int add_cred_obj(nis_object *, char *);
extern nis_error auth_exists(char *, char *, char *, char *);
extern nis_error cred_exists(char *, char *, char *);
extern int keylogin_des(char *, char *);
extern int make_des_cred_be(char *, char *, char *);
extern int modify_cred_obj(nis_object *, char *);

static int force = 1;   /*  Eventually, this will be an option */

static const char *OPSYS = "unix";
#define	OPSYS_LEN 4
#define	ROOTKEY_FILE "/etc/.rootkey"

/* ************************ switch functions *************************** */

/*	NSW_NOTSUCCESS  NSW_NOTFOUND   NSW_UNAVAIL    NSW_TRYAGAIN */
#define	DEF_ACTION {__NSW_RETURN, __NSW_RETURN, __NSW_CONTINUE, __NSW_CONTINUE}

static struct __nsw_lookup lookup_files = {"files", DEF_ACTION, NULL, NULL},
		lookup_nis = {"nis", DEF_ACTION, NULL, &lookup_files};
static struct __nsw_switchconfig publickey_default =
			{0, "publickey", 2, &lookup_nis};


char *
switch_policy_str(struct __nsw_switchconfig *conf)
{
	struct __nsw_lookup *look;
	static char policy[256];
	int previous = 0;

	(void) memset((char *)policy, 0, 256);

	for (look = conf->lookups; look; look = look->next) {
		if (previous)
			(void) strcat(policy, " ");
		strcat(policy, look->service_name);
		previous = 1;
	}

	return (policy);
}


int
no_switch_policy(struct __nsw_switchconfig *conf)
{
	return (conf == NULL || conf->lookups == NULL);
}


int
is_switch_policy(struct __nsw_switchconfig *conf, char *target)
{
	return (conf && conf->lookups &&
	    strcmp(conf->lookups->service_name, target) == 0 &&
	    conf->lookups->next == NULL);
}


int
check_switch_policy(char *policy, char *target_service,
		    struct __nsw_switchconfig *default_conf,
		    char *head_msg, char *tail_msg)
{
	struct __nsw_switchconfig *conf;
	enum __nsw_parse_err perr;
	int policy_correct = 1;

	conf = __nsw_getconfig(policy, &perr);
	if (no_switch_policy(conf)) {
		if (!is_switch_policy(default_conf, target_service)) {
			fprintf(stderr,
			    "\n%s\n There is no publickey entry in %s.\n",
			    head_msg, __NSW_CONFIG_FILE);
			fprintf(stderr,
			" The default publickey policy is \"publickey: %s\".\n",
			    switch_policy_str(default_conf));
			policy_correct = 0;
		}
	} else if (!is_switch_policy(conf, target_service)) {
		fprintf(stderr,
		"\n%s\n The publickey entry in %s is \"publickey: %s\".\n",
		    head_msg, __NSW_CONFIG_FILE,
		    switch_policy_str(conf));
		policy_correct = 0;
	}
	/* should we exit ? */
	if (policy_correct == 0)
		fprintf(stderr,
		" It should be \"publickey: %s\"%s.\n\n",
		    target_service, tail_msg);
	if (conf)
		__nsw_freeconfig(conf);

	return (policy_correct);
}

/* ******************************************************************** */
/* Check that data to be entered makes sense */
int
sanity_checks(char *nis_princ, char *netname, char *domain, char *authtype)
{
	char		netdomainaux[MAXHOSTNAMELEN+1];
	char		*princdomain, *netdomain;

	/* Sanity check 0. Do we have a nis+ principal name to work with? */
	if (nis_princ == NULL) {
		fprintf(stderr,
		    "%s: you must create a \"local\" credential first.\n",
		    program_name);
		fprintf(stderr,
		    "rerun this command as : %s local \n", program_name);
		return (0);
	}

	/* Sanity check 1.  We only deal with one type of netnames. */
	if (strncmp(netname, OPSYS, OPSYS_LEN) != 0) {
		fprintf(stderr, "%s: unrecognized netname type: '%s'.\n",
		    program_name, netname);
		return (0);
	}

	/* Sanity check 2.  Should only add DES cred in home domain. */
	princdomain = nis_domain_of(nis_princ);
	if (strcasecmp(princdomain, domain) != 0) {
		fprintf(stderr,
"%s: domain of principal '%s' does not match destination domain '%s'.\n",
		    program_name, nis_princ, domain);
		fprintf(stderr,
	"Should only add DES credential of principal in its home domain\n");
		return (0);
	}

	/*
	 * Sanity check 3:  Make sure netname's domain same as principal's
	 * and don't have extraneous dot at the end.
	 */
	netdomain = (char *)strchr(netname, '@');
	if (! netdomain) {
		fprintf(stderr, "%s: invalid netname, missing @: '%s'. \n",
		    program_name, netname);
		return (0);
	}
	if (netname[strlen(netname)-1] == '.')
		netname[strlen(netname)-1] = '\0';
	netdomain++; /* skip '@' */
	strcpy(netdomainaux, netdomain);
	strcat(netdomainaux, ".");

	if (strcasecmp(princdomain, netdomainaux) != 0) {
		fprintf(stderr, "%s: domain of netname \"%s\" should "
		    "be same as that of principal \"%s\"\n",
		    program_name, netname, nis_princ);
		return (0);
	}

	/* Check publickey policy and warn user if it is not NIS+ */
	check_switch_policy("publickey", "nisplus", &publickey_default,
	    "WARNING:", " when using NIS+");

	/* Another principal owns same credentials? (exits if that happens) */
	(void) auth_exists(nis_princ, netname, authtype, domain);

	return (1); /* all passed */
}

/* ***************************** keylogin stuff *************************** */
static int
keylogin(char *netname, char *secret, char *flavor,
		keylen_t keylen, algtype_t algtype)
{
	mechanism_t	**mechs;
	int		mcount;

	if (mechs = __nis_get_mechanisms(FALSE)) {
		for (mcount = 0; mechs[mcount]; mcount++) {
			if (keylen == mechs[mcount]->keylen &&
			    algtype == mechs[mcount]->algtype) {
				if (key_setnet_g(netname, secret,
				    mechs[mcount]->keylen,
				    NULL, 0,
				    mechs[mcount]->algtype)
				    < 0) {
					fprintf(stderr,
					"Could not set %s's %s secret key\n",
					    netname, flavor);
					fprintf(stderr,
					"May be the keyserv is down?\n");
					return (0);
				}
			}
		}
	} else {
		if (keylen == 192 && algtype == 0)
			return (keylogin_des(netname, secret));
	}
	return (1);
}

/*
 * fgets is broken in that if it reads a NUL character it will always return
 * EOF.  This replacement can deal with NULs
 */
static char *
fgets_ignorenul(char *s, int n, FILE *stream)
{
	int fildes = fileno(stream);
	int i = 0;
	int rs = 0;
	char c;

	if (fildes < 0)
		return (NULL);

	while (i < n - 1) {
		rs = read(fildes, &c, 1);
		switch (rs) {
		case 1:
			break;
		case 0:
			/* EOF */
			if (i > 0)
				s[i] = '\0';
			return (NULL);
			break;
		default:
			return (NULL);
		}
		switch (c) {
		case '\0':
			break;
		case '\n':
			s[i] = c;
			s[++i] = '\0';
			return (s);
		default:
		if (c != '\0')
			s[i++] = c;
		}
	}
	s[i] = '\0';
	return (s);
}

#define	ROOTKEY_FILE_BACKUP	"/etc/.rootkey.bak"
/* Should last until 16384-bit DH keys */
#define	MAXROOTKEY_LINE_LEN	4224
#define	MAXROOTKEY_LEN		4096

/* write unencrypted secret key into root key file */
void
write_rootkey(char *secret, char *flavor, keylen_t keylen, algtype_t algtype)
{
	char		line[MAXROOTKEY_LINE_LEN];
	char		keyent[MAXROOTKEY_LEN];
	algtype_t	atent;
	int		rootfd, bakfd, hexkeybytes;
	bool_t		lineone = TRUE;
	bool_t		gotit = FALSE;
	FILE		*rootfile, *bakfile;

	unlink(ROOTKEY_FILE_BACKUP);
	if ((rename(ROOTKEY_FILE, ROOTKEY_FILE_BACKUP)) < 0) {
		if ((bakfd = creat(ROOTKEY_FILE_BACKUP, 0600)) < 0) {
			perror("Could not create /etc/.rootkey.bak");
			goto rootkey_err;
		}
		close(bakfd);
	}

	if ((rootfd = open(ROOTKEY_FILE, O_WRONLY+O_CREAT, 0600)) < 0) {
		perror("Could not open /etc/.rootkey for writing");
		fprintf(stderr,
		    "Attempting to restore original /etc/.rootkey\n");
		rename(ROOTKEY_FILE_BACKUP, ROOTKEY_FILE);
		goto rootkey_err;
	}
	if (!(rootfile = fdopen(rootfd, "w"))) {
		perror("Could not open /etc/.rootkey for writing");
		fprintf(stderr,
		    "Attempting to restore original /etc/.rootkey\n");
		close(rootfd);
		unlink(ROOTKEY_FILE);
		rename(ROOTKEY_FILE_BACKUP, ROOTKEY_FILE);
		goto rootkey_err;
	}
	if (!(bakfile = fopen(ROOTKEY_FILE_BACKUP, "r"))) {
		perror("Could not open /etc/.rootkey.bak for reading");
		fprintf(stderr,
		    "Attempting to restore original /etc/.rootkey\n");
		fclose(rootfile);
		unlink(ROOTKEY_FILE);
		rename(ROOTKEY_FILE_BACKUP, ROOTKEY_FILE);
		goto rootkey_err;
	}

	hexkeybytes = ((keylen + 7) / 8) * 2;

	while (fgets_ignorenul(line, MAXROOTKEY_LINE_LEN, bakfile)) {
		sscanf(line, "%s %d", keyent, &atent);
		/*
		 * 192-bit keys always go on the first line
		 */
		if (lineone) {
			lineone = FALSE;
			if (keylen == 192) {
				gotit = TRUE;
				fprintf(rootfile, "%s\n", secret);
			} else
				fprintf(rootfile, "%s", line);
			fflush(rootfile);
		} else {
			if ((strlen(keyent) == hexkeybytes) &&
			    (atent == algtype)) {
				/*
				 * Silently remove lines with the same
				 * keylen/algtype
				 */
				if (gotit)
					continue;
				else
					gotit = TRUE;

				fprintf(rootfile, "%s %d\n", secret, algtype);
			} else
				fprintf(rootfile, "%s", line);
			fflush(rootfile);
		}
	}

	/* Append key to rootkey file */
	if (!gotit) {
		if (keylen == 192)
			fprintf(rootfile, "%s\n", secret);
		else {
			if (lineone)
				fprintf(rootfile, "\n");
			fprintf(rootfile, "%s %d\n", secret, algtype);
		}
	}
	fflush(rootfile);
	fclose(rootfile);
	fclose(bakfile);
	unlink(ROOTKEY_FILE_BACKUP);
	return;

rootkey_err:
	fprintf(stderr, "WARNING: Could not write %s key to /etc/.rootkey\n",
	    flavor);
}


char *
get_password(uid_t uid, int same_host, char *target_host, char *domain)
{
	static char	password[256];
	char		prompt[256];
	char		*encrypted_password, *login_password = NULL, *pass;
	struct passwd	*pw;
	int passwords_matched = 0;
	struct passwd	*domain_getpwuid();
	struct spwd	*domain_getspnam();

	struct spwd *spw;

	/* ignore password checking when the -l option is used */
	if (nispasswd[0] != '\0')
		return (nispasswd);

	if (uid == 0) {
		if (same_host) {
			/*
			 *  The root user is never in the NIS+
			 *  data base.  Get it locally.
			 */
			pw = getpwuid(0);
			if (! pw) {
				fprintf(stderr,
			"%s: unable to locate password record for uid %d\n",
				    program_name, uid);
				return (0);
			}
			spw = getspnam(pw->pw_name);
			if (!spw) {
				fprintf(stderr,
			"%s: unable to locate password record for uid 0\n",
				    program_name);
				return (0);
			}
			login_password = spw->sp_pwdp;
		}
	} else {
		pw = domain_getpwuid(domain, uid);
		if (pw) {
			/* get password from shadow */
			spw = domain_getspnam(domain, pw->pw_name);
			if (spw) {
				login_password = spw->sp_pwdp;
			}
		} else {
			return (0);
		}
	}

	if ((uid == my_uid) && ((uid != 0) || same_host))
		sprintf(prompt, "Enter login password:");
	else if (uid == 0) {
		sprintf(prompt, "Enter %s's root login password:",
		    target_host);
	} else
		sprintf(prompt, "Enter %s's login password:",
		    pw->pw_name);
	pass = getpassphrase(prompt);
	if (strlen(pass) == 0) {
		(void) fprintf(stderr, "%s: Password unchanged.\n",
		    program_name);
		return (0);
	}
	strcpy(password, pass);


	/* Verify that password supplied matches login password */
	if (login_password && (strlen(login_password) != 0)) {
		encrypted_password = crypt(password, login_password);
		if (strcmp(encrypted_password, login_password) == 0)
			passwords_matched = 1;
		else {
			fprintf(stderr,
			"%s: %s: password differs from login password.\n",
			    program_name, force? "WARNING" : "ERROR");
			if (!force)
				return (0);
		}
	}

	/* Check for mis-typed password */
	if (!passwords_matched) {
		pass = getpassphrase("Retype password:");
		if (strcmp(password, pass) != 0) {
			(void) fprintf(stderr, "%s: password incorrect.\n",
			    program_name);
			return (0);
		}
	}

	return (password);
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
make_dhext_cred(nis_princ, netname, domain, flavor)
	char	*nis_princ;	/* NIS+ principal name 		*/
	char	*netname;	/* AUTH_DES netname 	*/
	char	*domain;	/* Domain name			*/
	char	*flavor;	/* Mech alias */
{
	nis_object	*obj = init_entry();
	uid_t		uid;
	static char	*pass;
	char		*public, *secret, *crypt1;
	char		short_pass[DESCREDPASSLEN + 1];
	char		authtype[MECH_MAXATNAME];
	char		target_host[MAXHOSTNAMELEN+1];
	int		same_host = 0;
	int		status, len, addition;
	keylen_t	kl;
	algtype_t	at;
	size_t		hexkeybytes;

	if (nis_princ == NULL)
		nis_princ = default_principal(domain);

	if (strcmp(flavor, "dh192-0") == 0)
		return (make_des_cred_be(nis_princ, netname, domain));

	__nis_mechalias2authtype(flavor, authtype, MECH_MAXATNAME);

	if (__nis_translate_mechanism(flavor, &kl, &at) == -1)
		goto badstatus;

	if (sanity_checks(nis_princ, netname, domain, authtype) == 0)
		goto badstatus;

	addition = (cred_exists(nis_princ, authtype, domain) == NIS_NOTFOUND);

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

	if (!pass)
		pass = get_password(uid, same_host, target_host, domain);
	if (!pass)
		goto badstatus;

	(void) strlcpy(short_pass, pass, sizeof (short_pass));

	/* Get password with which to encrypt secret key. */
	(void) printf("%s %s key pair for %s (%s).\n",
			addition? "Adding" : "Updating", flavor,
			netname, nis_princ);

	hexkeybytes = ((kl + 7) / 8) * 2;
	if (!(public = (char *)malloc(hexkeybytes + 1)))
	    goto badstatus;
	if (!(secret = (char *)malloc(hexkeybytes + 1)))
	    goto badstatus;

	/* Encrypt secret key */
	if (!(__gen_dhkeys_g(public, secret, kl, at, short_pass)))
		goto badstatus;
	if (!(xencrypt_g(secret, kl, at, short_pass, netname, &crypt1, TRUE)))
		goto badstatus;

	/* Now we have a key pair, build up the cred entry */
	ENTRY_VAL(obj, 0) = nis_princ;
	ENTRY_LEN(obj, 0) = strlen(nis_princ) + 1;

	ENTRY_VAL(obj, 1) = authtype;
	ENTRY_LEN(obj, 1) = strlen(authtype) + 1;

	ENTRY_VAL(obj, 2) = netname;
	ENTRY_LEN(obj, 2) = strlen(netname) + 1;

	ENTRY_VAL(obj, 3) = public;
	ENTRY_LEN(obj, 3) = strlen(public) + 1;

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
			keylogin(netname, secret, flavor, kl, at);
		if ((uid == 0) && same_host)
			write_rootkey(secret, flavor, kl, at);
	}

	goto cleanup;
badstatus:
	status = 0;

cleanup:

	return (status);
}


char *
get_dhext_cred(char *domain, char *flavor)
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
