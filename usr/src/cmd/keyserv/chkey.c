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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <sys/types.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_dhext.h>
#include <rpcsvc/ypclnt.h>
#include <nsswitch.h>

#define	PK_FILES	1
#define	PK_YP		2
#define	PK_NISPLUS	3
#define	PK_LDAP		4

#define	CURMECH		mechs[mcount]

static char	CRED_TABLE[] = "cred.org_dir";
static char	PKMAP[] = "publickey.byname";
static char	PKFILE[] = "/etc/publickey";
#define	MAXHOSTNAMELEN	256

#define	ROOTKEY_FILE		"/etc/.rootkey"
#define	ROOTKEY_FILE_BACKUP	"/etc/.rootkey.bak"
#define	MAXROOTKEY_LINE_LEN	4224	/* Good upto 16384-bit keys */
#define	MAXROOTKEY_LEN		4096

/* Should last up to 16384-bit keys */
#define	MAXPKENTLEN	8500

bool_t		makenew = TRUE;   /* Make new keys or reencrypt existing */
bool_t		specmech = FALSE; /* Specific mechs requested */
bool_t		force = FALSE;
int		dest_service = 0; /* To which nameservice do we store key(s) */

char		*program_name;

mechanism_t	**mechs = NULL;   /* List of DH mechanisms */
char		**plist = NULL;	  /* List of public key(s) */
char		**slist = NULL;	  /* List of secret key(s) */
char		**clist = NULL;   /* List of encrypted secret key(s) */
int		numspecmech = 0;  /* Number of mechanisms specified */

struct passwd	*pw = NULL;	  /* passwd entry of user */
struct spwd	*spw = NULL;	  /* shadow entry of user */

char		*netname = NULL;  /* RPC netname of user */
char		local_domain[MAXNETNAMELEN + 1];
char		*sec_domain = NULL;

char		**rpc_pws = NULL; /* List of S-RPC passwords */
int		rpc_pw_count = 0; /* Number of passwords entered by user */
char		*login_pw = NULL; /* Unencrypted login password */

static int add_cred_obj(nis_object *, char *);
static nis_error auth_exists(char *, char *, char *, char *);
static void cmp_passwd();
static nis_error cred_exists(const char *, const char *, const char *);
static void encryptkeys();
static void error_msg();
static char *fgets_ignorenul();
static void getpublics();
static void getrpcpws();
static void getsecrets();
static void initkeylist(bool_t);
static void keylogin(keylen_t, algtype_t);
static void keylogin_des();
static void makenewkeys();
static int modify_cred_obj(nis_object *, char *);
static int nisplus_update(nis_name, char *, char *, char *);
static int sanity_checks(char *, char *, char *);
static void storekeys();
static void usage();
static void write_rootkey();

extern char *get_nisplus_principal(char *, uid_t);
extern nis_object *init_entry();
extern int get_pk_source(char *);
extern int localupdate(char *, char *, uint_t, char *);
extern int xencrypt();
extern int xencrypt_g();
extern int __gen_dhkeys();
extern int key_setnet();
extern int key_setnet_g();
extern int key_secretkey_is_set_g();
extern int __getnetnamebyuid();
extern int getdomainname();
extern int ldap_update(char *, char *, char *, char *, char *);


static void
error_msg()
{
	if (sec_domain && *sec_domain &&
	    strcasecmp(sec_domain, local_domain)) {
		fprintf(stderr,
"The system default domain '%s' is different from the Secure RPC\n\
domain %s where the key is stored.  The Secure RPC domainname is\n\
defined by the directory object stored in the /var/nis/NIS_COLD_START file.\n\
If you need to change this Secure RPC domainname, please use the nisinit(1M)\n\
command with the `-k` option.\n", local_domain, sec_domain);
		exit(1);
	}
}


static void
usage()
{
	fprintf(stderr, "usage: %s [-p] [-s ldap | nisplus | nis | files] \n",
		program_name);
	exit(1);
}


/* Encrypt secret key(s) with login_pw */
static void
encryptkeys()
{
	int	mcount, ccount = 0;

	if (mechs) {
		for (mcount = 0; CURMECH; mcount++) {
			char		*crypt = NULL;

			if (!xencrypt_g(slist[mcount], CURMECH->keylen,
					CURMECH->algtype, login_pw, netname,
					&crypt, TRUE)) {
				/* Could not crypt key */
				crypt = NULL;
			} else
				ccount++;
			clist[mcount] = crypt;
		}
	} else {
		char		*crypt = NULL;

		if (!(crypt =
			(char *)malloc(HEXKEYBYTES + KEYCHECKSUMSIZE + 1))) {
			fprintf(stderr, "%s: Malloc failure.\n", program_name);
			exit(1);
		}

		memcpy(crypt, slist[0], HEXKEYBYTES);
		memcpy(crypt + HEXKEYBYTES, slist[0], KEYCHECKSUMSIZE);
		crypt[HEXKEYBYTES + KEYCHECKSUMSIZE] = 0;
		xencrypt(crypt, login_pw);

		clist[0] = crypt;
		ccount++;
	}

	if (!ccount) {
		fprintf(stderr, "%s: Could not encrypt any secret keys.\n",
			program_name);
		exit(1);
	}
}


/* Initialize the array of public, secret, and encrypted secret keys */
static void
initkeylist(bool_t nomech)
{
	int		mcount;

	if (!nomech) {
		assert(mechs && mechs[0]);
		for (mcount = 0; CURMECH; mcount++);
	} else
		mcount = 1;

	if (!(plist = (char **)malloc(sizeof (char *) * mcount))) {
		fprintf(stderr, "%s: Malloc failure.\n", program_name);
		exit(1);
	}
	if (!(slist = (char **)malloc(sizeof (char *) * mcount))) {
		fprintf(stderr, "%s: Malloc failure.\n", program_name);
		exit(1);
	}
	if (!(clist = (char **)malloc(sizeof (char *) * mcount))) {
		fprintf(stderr, "%s: Malloc failure.\n", program_name);
		exit(1);
	}
}


/* Retrieve public key(s) */
static void
getpublics()
{
	int		mcount;
	int		pcount = 0;

	if (mechs) {
		for (mcount = 0; CURMECH; mcount++) {
			char		*public;
			size_t		hexkeylen;

			hexkeylen = ((CURMECH->keylen / 8) * 2) + 1;
			if (!(public = (char *)malloc(hexkeylen))) {
				fprintf(stderr, "%s: Malloc failure.\n",
					program_name);
				exit(1);
			}
			if (!getpublickey_g(netname, CURMECH->keylen,
					    CURMECH->algtype, public,
					    hexkeylen)) {
				/* Could not get public key */
				fprintf(stderr,
					"Could not get %s public key.\n",
					VALID_ALIAS(CURMECH->alias) ?
					CURMECH->alias : "");
				free(public);
				public = NULL;
			} else
				pcount++;

			plist[mcount] = public;
		}
	} else {
		char		*public;

		if (!(public = (char *)malloc(HEXKEYBYTES + 1))) {
			fprintf(stderr, "%s: Malloc failure.\n", program_name);
			exit(1);
		}
		if (!getpublickey(netname, public)) {
			free(public);
			public = NULL;
		} else
			pcount++;

		plist[0] = public;
	}

	if (!pcount) {
		fprintf(stderr, "%s: cannot get any public keys for %s.\n",
			program_name, pw->pw_name);
		error_msg();
		fprintf(stderr,
	"Make sure that the public keys are stored in the domain %s.\n",
			local_domain);
		exit(1);
	}
}


/* Generate a new set of public/secret key pair(s) */
static void
makenewkeys()
{
	int		mcount;

	if (mechs) {
		for (mcount = 0; CURMECH; mcount++) {
			char		*public, *secret;
			size_t		hexkeylen;

			if (slist[mcount])
				free(slist[mcount]);

			hexkeylen = ((CURMECH->keylen / 8) * 2) + 1;

			if (!(public = malloc(hexkeylen))) {
				fprintf(stderr, "%s: Malloc failure.\n",
					program_name);
				exit(1);
			}
			if (!(secret = malloc(hexkeylen))) {
				fprintf(stderr, "%s: Malloc failure.\n",
					program_name);
				exit(1);
			}

			if (!(__gen_dhkeys_g(public, secret, CURMECH->keylen,
					CURMECH->algtype, login_pw))) {
				/* Could not generate key pair */
				fprintf(stderr,
				"WARNING  Could not generate key pair %s\n",
					VALID_ALIAS(CURMECH->alias) ?
					CURMECH->alias : "");
				free(public);
				free(secret);
				public = NULL;
				secret = NULL;
			}

			plist[mcount] = public;
			slist[mcount] = secret;
		}
	} else {
		char		*public, *secret;
		if (slist[0])
			free(slist[0]);

		if (!(public = malloc(HEXKEYBYTES + 1))) {
			fprintf(stderr, "%s: Malloc failure.\n", program_name);
			exit(1);
		}
		if (!(secret = malloc(HEXKEYBYTES + 1))) {
			fprintf(stderr, "%s: Malloc failure.\n", program_name);
			exit(1);
		}

		__gen_dhkeys(public, secret, login_pw);

		plist[0] = public;
		slist[0] = secret;
	}
}


/*
 * Make sure that the entered Secure-RPC password(s) match the login
 * password
 */
static void
cmp_passwd()
{
	char	baseprompt[] = "Please enter the login password for";
	char	prompt[BUFSIZ];
	char	*en_login_pw = spw->sp_pwdp;
	char	*try_en_login_pw;
	bool_t	pwmatch = FALSE;
	int	done = 0, tries = 0, pcount;

	snprintf(prompt, BUFSIZ, "%s %s:", baseprompt, pw->pw_name);

	if (en_login_pw && (strlen(en_login_pw) != 0)) {
		for (pcount = 0; pcount < rpc_pw_count; pcount++) {
			char	*try_en_rpc_pw;

			try_en_rpc_pw = crypt(rpc_pws[pcount], en_login_pw);
			if (strcmp(try_en_rpc_pw, en_login_pw) == 0) {
				login_pw = rpc_pws[pcount];
				pwmatch = TRUE;
				break;
			}
		}
		if (!pwmatch) {
			/* pw don't match */
			while (!done) {
				/* ask for the pw */
				login_pw = getpass(prompt);
				if (login_pw && strlen(login_pw)) {
					/* pw was not empty */
					try_en_login_pw = crypt(login_pw,
								en_login_pw);
					/* compare the pw's */
					if (!(strcmp(try_en_login_pw,
							en_login_pw))) {
						/* pw was correct */
						return;
					} else {
						/* pw was wrong */
						if (tries++) {
							/* Sorry */
							fprintf(stderr,
								"Sorry.\n");
							exit(1);
						} else {
							/* Try again */
							snprintf(prompt,
									BUFSIZ,
							"Try again. %s %s:",
								baseprompt,
								pw->pw_name);
						}
					}
				} else {
					/* pw was empty */
					if (tries++) {
						/* Unchanged */
						fprintf(stderr,
					"%s: key-pair(s) unchanged for %s.\n",
							program_name,
							pw->pw_name);
						exit(1);
					} else {
						/* Need a password */
						snprintf(prompt, BUFSIZ,
						"Need a password. %s %s:",
								baseprompt,
								pw->pw_name);
					}
				}
			}
		}
		/* pw match */
		return;
	} else {
		/* no pw found */
		fprintf(stderr,
		"%s: no passwd found for %s in the shadow passwd entry.\n",
			program_name, pw->pw_name);
		exit(1);
	}
}


/* Prompt the user for a Secure-RPC password and store it in a cache. */
static void
getrpcpws(char *flavor)
{
	char		*cur_pw = NULL;
	char		prompt[BUFSIZ + 1];

	if (flavor)
		snprintf(prompt, BUFSIZ,
			"Please enter the %s Secure-RPC password for %s:",
			flavor, pw->pw_name);
	else
		snprintf(prompt, BUFSIZ,
				"Please enter the Secure-RPC password for %s:",
				pw->pw_name);

	cur_pw = getpass(prompt);
	if (!cur_pw) {
		/* No changes */
		fprintf(stderr, "%s: key-pair(s) unchanged for %s.\n",
			program_name, pw->pw_name);
		exit(1);
	}

	rpc_pw_count++;
	if (!(rpc_pws =
		(char **)realloc(rpc_pws, sizeof (char *) * rpc_pw_count))) {
		fprintf(stderr, "%s: Realloc failure.\n", program_name);
		exit(1);
	}
rpc_pws[rpc_pw_count - 1] = cur_pw;
}


/* Retrieve the secret key(s) for the user and attempt to decrypt them */
static void
getsecrets()
{
	int		mcount, scount = 0;
	int		tries = 0;

	getrpcpws(NULL);

	if (mechs) {
		for (mcount = 0; CURMECH; mcount++) {
			char		*secret;
			int		pcount;
			size_t		hexkeylen;

			hexkeylen = ((CURMECH->keylen / 8) * 2) + 1;
			if (!(secret = (char *)calloc(hexkeylen,
							sizeof (char)))) {
				fprintf(stderr, "%s: Malloc failure.\n",
					program_name);
				exit(1);
			}

			for (pcount = 0; pcount < rpc_pw_count; pcount++) {
				if (!getsecretkey_g(netname, CURMECH->keylen,
						    CURMECH->algtype, secret,
						    hexkeylen,
						    rpc_pws[pcount]))
					continue;

				if (secret[0] == 0)
					continue;
				else
					break;
			}

			tries = 0;
		getsecrets_tryagain_g:
			if (secret[0] == 0) {
				if (!tries) {
					/*
					 * No existing pw can decrypt
					 * secret key
					 */
					getrpcpws(CURMECH->alias);
					if (!getsecretkey_g(netname,
							    CURMECH->keylen,
							    CURMECH->algtype,
							    secret,
							    hexkeylen,
							    rpc_pws[pcount])) {
						/*
						 * Could not retreive
						 * secret key, abort
						 */
						free(secret);
						secret = NULL;
						goto getsecrets_abort;
					}

					if (secret[0] == 0) {
						/* Still no go, ask again */
						free(rpc_pws[pcount]);
						rpc_pw_count--;
						tries++;
						printf("Try again. ");
						fflush(stdout);
						goto getsecrets_tryagain_g;
					} else
						scount++;
				} else {
					fprintf(stderr,
					"%s: key-pair unchanged for %s.\n",
						program_name, pw->pw_name);
					exit(1);
				}
			} else
				scount++;

		getsecrets_abort:
			slist[mcount] = secret;
		}
	} else {
		char		*secret = NULL;

		if (!(secret = (char *)malloc(HEXKEYBYTES + 1))) {
			fprintf(stderr, "%s: Malloc failure.\n", program_name);
			exit(1);
		}
	getsecrets_tryagain:
		if (!getsecretkey(netname, secret, rpc_pws[0])) {
			fprintf(stderr,
				"%s: could not get secret key for '%s'\n",
				program_name, netname);
			exit(1);
		}

		if (secret[0] == 0) {
			if (!tries) {
				free(rpc_pws[0]);
				rpc_pw_count = 0;
				tries++;
				printf("Try again. ");
				fflush(stdout);
				getrpcpws(NULL);
				goto getsecrets_tryagain;
			} else {
				fprintf(stderr,
					"%s: key-pair unchanged for %s.\n",
					program_name, pw->pw_name);
				exit(1);
			}
		}

		slist[0] = secret;
		return;
	}

	if (!scount) {
		(void) fprintf(stderr,
		"%s: could not get nor decrypt any secret keys for '%s'\n",
					program_name, netname);
		error_msg();
		exit(1);
	}
}


/* Register AUTH_DES secret key with keyserv */
static void
keylogin_des()
{
	char			*secret = slist[0];
	struct key_netstarg	netst;

	/*
	 * try to revoke the existing key/credentials, assuming
	 * one exists.  this will effectively mark "stale" any
	 * cached credientials...
	 */
	if (key_setsecret(secret) < 0) {
		return;
	}

#ifdef NFS_AUTH
	/*
	 * it looks like a credential already existed, so try and
	 * revoke any lingering Secure-NFS privledges.
	 */

	nra.authtype = AUTH_DES;
	nra.uid = getuid();

	if (_nfssys(NFS_REVAUTH, &nra) < 0)
		perror("Warning: NFS credentials not destroyed");
#endif /* NFS_AUTH */

	memcpy(netst.st_priv_key, secret, HEXKEYBYTES);

	netst.st_pub_key[0] = '\0';
	netst.st_netname = strdup(netname);

	/* do actual key login */
	if (key_setnet(&netst) < 0) {
		fprintf(stderr, "Could not set %s's secret key\n", netname);
		fprintf(stderr, "May be the keyserv is down?\n");
	}
}


/* Register a secret key with the keyserv */
static void
keylogin(keylen_t keylen, algtype_t algtype)
{
	int	mcount;

	if (mechs) {
		for (mcount = 0; CURMECH; mcount++) {
			if (keylen == CURMECH->keylen &&
			    algtype == CURMECH->algtype) {
				if (key_setnet_g(netname, slist[mcount],
							CURMECH->keylen,
							NULL, 0,
							CURMECH->algtype)
				    < 0)
					fprintf(stderr,
					"Could not set %s's %s secret key\n",
						netname,
					VALID_ALIAS(CURMECH->alias) ?
						CURMECH->alias : "");
			}
		}
	} else {
		if (keylen == 192 && algtype == 0)
			keylogin_des();
	}
}


/*
 * fgets is "broken" in that if it reads a NUL character it will
 * always return EOF for all reads, even when there is data left in
 * the file.  This replacement can deal with NUL's in a calm, rational
 * manner.
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


/* Write unencrypted secret key into root key file */
static void
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
		if (sscanf(line, "%s %d", keyent, &atent) < 2) {
			/*
			 * No encryption algorithm found in the file
			 * (atent) so default to DES.
			 */
			atent = AUTH_DES_ALGTYPE;
		}
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


/* Returns 0 if check fails; 1 if successful. */
static int
sanity_checks(char *nis_princ, char *domain, char *authtype)
{
	char	netdomainaux[MAXHOSTNAMELEN+1];
	char	*princdomain, *netdomain;
	int	len;

	/* Sanity check 0. Do we have a nis+ principal name to work with? */
	if (nis_princ == NULL) {
		(void) fprintf(stderr,
		"%s: you must create a \"LOCAL\" credential for '%s' first.\n",
			program_name, netname);
		(void) fprintf(stderr, "\tSee nisaddcred(1).\n");
		return (0);
	}

	/* Sanity check 0.5.  NIS+ principal names must be dotted. */
	len = strlen(nis_princ);
	if (nis_princ[len-1] != '.') {
		(void) fprintf(stderr,
		"%s: invalid principal name: '%s' (forgot ending dot?).\n",
			program_name, nis_princ);
		return (0);
	}

	/* Sanity check 1.  We only deal with one type of netnames. */
	if (strncmp(netname, "unix", 4) != 0) {
		(void) fprintf(stderr,
			"%s: unrecognized netname type: '%s'.\n",
			program_name, netname);
		return (0);
	}

	/* Sanity check 2.  Should only add DES cred in home domain. */
	princdomain = nis_domain_of(nis_princ);
	if (strcasecmp(princdomain, domain) != 0) {
		(void) fprintf(stderr,
"%s: domain of principal '%s' does not match destination domain '%s'.\n",
			program_name, nis_princ, domain);
		(void) fprintf(stderr,
	"Should only add DES credential of principal in its home domain\n");
		return (0);
	}

	/*
	 * Sanity check 3:  Make sure netname's domain same as principal's
	 * and don't have extraneous dot at the end.
	 */
	netdomain = (char *)strchr(netname, '@');
	if (! netdomain || netname[strlen(netname)-1] == '.') {
		(void) fprintf(stderr, "%s: invalid netname: '%s'. \n",
			program_name, netname);
		return (0);
	}
	netdomain++; /* skip '@' */

	if (strlcpy(netdomainaux, netdomain, sizeof (netdomainaux)) >=
	    sizeof (netdomainaux)) {
		(void) fprintf(stderr, "%s: net domain name %s is too long\n",
			    program_name, netdomain);
		return (0);
	}

	if (netdomainaux[strlen(netdomainaux) - 1] != '.') {
		if (strlcat(netdomainaux, ".", sizeof (netdomainaux)) >=
		    sizeof (netdomainaux)) {
			(void) fprintf(stderr,
				    "%s: net domain name %s is too long\n",
				    program_name, netdomainaux);
			return (0);
		}
	}

	if (strcasecmp(princdomain, netdomainaux) != 0) {
		(void) fprintf(stderr,
	"%s: domain of netname %s should be same as that of principal %s\n",
			program_name, netname, nis_princ);
		return (0);
	}

	/* Another principal owns same credentials? (exits if that happens) */
	(void) auth_exists(nis_princ, netname, authtype, domain);

	return (1); /* all passed */
}


/* Store new key information in the specified name service */
static void
storekeys()
{
	int		mcount, ucount = 0;
	char		*ypmaster, *ypdomain = NULL, pkent[MAXPKENTLEN];
	nis_name	nis_princ;


	/* Setup */
	switch (dest_service) {
	case PK_LDAP:
		break;
	case PK_NISPLUS:
		nis_princ = get_nisplus_principal(nis_local_directory(),
							geteuid());
		break;
	case PK_YP:
		yp_get_default_domain(&ypdomain);
		if (yp_master(ypdomain, PKMAP, &ypmaster) != 0) {
			fprintf(stderr,
			"%s: cannot find master of NIS publickey database\n",
				program_name);
			exit(1);
		}
		fprintf(stdout,
			"Sending key change request to %s ...\n", ypmaster);
		break;
	case PK_FILES:
		if (geteuid() != 0) {
			fprintf(stderr,
		"%s: non-root users cannot change their key-pair in %s\n",
				program_name, PKFILE);
			exit(1);
		}
		break;
	default:
		fprintf(stderr,
			"could not update; database %d unknown\n",
			dest_service);
		exit(1);
	}

	if (mechs) {
		for (mcount = 0; CURMECH; mcount++) {
			char		authtype[MECH_MAXATNAME];

			if (!plist[mcount] && !clist[mcount])
				continue;

			__nis_mechalias2authtype(CURMECH->alias, authtype,
							MECH_MAXATNAME);
			if (!authtype) {
				fprintf(stderr,
				"Could not generate auth_type for %s.\n",
					CURMECH->alias);
				continue;
			}

			snprintf(pkent, MAXPKENTLEN, "%s:%s:%d",
					plist[mcount], clist[mcount],
					CURMECH->algtype);

			switch (dest_service) {
			case PK_LDAP:
				if (ldap_update(CURMECH->alias, netname,
						plist[mcount], clist[mcount],
						login_pw))
					fprintf(stderr,
			"%s: unable to update %s key in LDAP database\n",
						program_name, authtype);
				else
					ucount++;
				break;

			case PK_NISPLUS:
				if (nisplus_update(nis_princ,
							authtype,
							plist[mcount],
							clist[mcount]))
					fprintf(stderr,
			"%s: unable to update %s key in nisplus database\n",
						program_name, authtype);
				else
					ucount++;
				break;

			case PK_YP:
				/* Should never get here. */
				break;

			case PK_FILES:
				/* Should never get here. */
				break;
			}
		}
	} else {
		int	status = 0;

		assert(plist[0] && clist[0]);
		snprintf(pkent, MAXPKENTLEN, "%s:%s", plist[0], clist[0]);

		switch (dest_service) {
		case PK_LDAP:
			if (ldap_update("dh192-0", netname,
					plist[0], clist[0],
					login_pw)) {
				fprintf(stderr,
			"%s: unable to update %s key in LDAP database\n",
					program_name);
				exit(1);
			}
			break;

		case PK_NISPLUS:
			assert(plist[0] && clist[0]);
			if (nisplus_update(nis_princ,
						AUTH_DES_AUTH_TYPE,
						plist[0],
						clist[0])) {
					fprintf(stderr,
			"%s: unable to update nisplus database\n",
						program_name);
					exit(1);
			}
			break;

		case PK_YP:
			if (status = yp_update(ypdomain, PKMAP,
						YPOP_STORE, netname,
						strlen(netname), pkent,
						strlen(pkent))) {
				fprintf(stderr,
				"%s: unable to update NIS database (%u): %s\n",
					program_name, status,
					yperr_string(status));
				exit(1);
			}
			break;

		case PK_FILES:
			if (localupdate(netname, PKFILE, YPOP_STORE, pkent)) {
				fprintf(stderr,
			"%s: hence, unable to update publickey database\n",
					program_name);
				exit(1);
			}
			break;

		default:
			/* Should never get here */
			assert(0);
		}
		return;
	}
	if (!ucount) {
		fprintf(stderr, "%s: unable to update any key-pairs for %s.\n",
			program_name, pw->pw_name);
		exit(1);
	}
}

/* Check that someone else don't have the same auth information already */
static
nis_error
auth_exists(char *princname, char *auth_name, char *auth_type, char *domain)
{
	char sname[NIS_MAXNAMELEN+1];
	nis_result	*res;
	nis_error status;
	char *foundprinc;

	(void) sprintf(sname, "[auth_name=%s,auth_type=%s],%s.%s",
		auth_name, auth_type, CRED_TABLE, domain);
	if (sname[strlen(sname)-1] != '.')
		strcat(sname, ".");
	/* Don't want FOLLOW_PATH here */
	res = nis_list(sname,
		MASTER_ONLY+USE_DGRAM+NO_AUTHINFO+FOLLOW_LINKS,
		NULL, NULL);

	status = res->status;
	switch (res->status) {
	case NIS_NOTFOUND:
		break;
	case NIS_TRYAGAIN:
		(void) fprintf(stderr,
			"%s: NIS+ server busy, try again later.\n",
			program_name);
		exit(1);
		break;
	case NIS_PERMISSION:
		(void) fprintf(stderr,
		"%s: insufficient permission to look up old credentials.\n",
			program_name);
		exit(1);
		break;
	case NIS_SUCCESS:
		foundprinc = ENTRY_VAL(res->objects.objects_val, 0);
		if (nis_dir_cmp(foundprinc, princname) != SAME_NAME) {
			(void) fprintf(stderr,
	"%s: %s credentials with auth_name '%s' already belong to '%s'.\n",
			program_name, auth_type, auth_name, foundprinc);
			exit(1);
		}
		break;
	default:
		(void) fprintf(stderr,
			"%s: error looking at cred table, NIS+ error: %s\n",
			program_name, nis_sperrno(res->status));
		exit(1);
	}
	nis_freeresult(res);
	return (status);
}


/* Check whether this principal already has this type of credentials */
static nis_error
cred_exists(const char *nisprinc, const char *flavor, const char *domain)
{
	char sname[NIS_MAXNAMELEN+1];
	nis_result	*res;
	nis_error status;

	snprintf(sname, NIS_MAXNAMELEN,
			"[cname=\"%s\",auth_type=%s],%s.%s",
			nisprinc, flavor, CRED_TABLE, domain);
	if (sname[strlen(sname)-1] != '.')
		strcat(sname, ".");

	/* Don't want FOLLOW_PATH here */
	res = nis_list(sname,
				MASTER_ONLY+USE_DGRAM+NO_AUTHINFO+FOLLOW_LINKS,
				NULL, NULL);

	status = res->status;
	switch (status) {
	case NIS_NOTFOUND:
		break;
	case NIS_TRYAGAIN:
		fprintf(stderr,
			"%s: NIS+ server busy, try again later.\n",
			program_name);
		exit(1);
		break;
	case NIS_PERMISSION:
		(void) fprintf(stderr,
		"%s: insufficient permission to look at credentials table\n",
			program_name);
		exit(1);
		break;
	case NIS_SUCCESS:
	case NIS_S_SUCCESS:
		break;
	default:
		(void) fprintf(stderr,
			"%s: error looking at cred table, NIS+ error: %s\n",
			program_name, nis_sperrno(res->status));
		exit(1);
	}
	nis_freeresult(res);
	return (status);
}


static int
modify_cred_obj(nis_object *obj, char *domain)
{
	int status = 0;
	char sname[NIS_MAXNAMELEN+1];
	nis_result	*res;

	(void) sprintf(sname, "%s.%s", CRED_TABLE, domain);
	res = nis_modify_entry(sname, obj, 0);
	switch (res->status) {
	case NIS_TRYAGAIN:
		(void) fprintf(stderr,
			"%s: NIS+ server busy, try again later.\n",
			program_name);
		exit(1);
		break;
	case NIS_PERMISSION:
		(void) fprintf(stderr,
			"%s: insufficient permission to update credentials.\n",
			program_name);
		exit(1);
		break;
	case NIS_SUCCESS:
		status = 1;
		break;
	default:
		(void) fprintf(stderr,
			"%s: error modifying credential, NIS+ error: %s.\n",
			program_name, nis_sperrno(res->status));
		exit(1);
	}
	nis_freeresult(res);
	return (status);
}


static int
add_cred_obj(nis_object *obj, char *domain)
{
	int status = 0;
	char sname[NIS_MAXNAMELEN+1];
	nis_result	*res;

	/* Assume check for cred_exists performed already */

	(void) sprintf(sname, "%s.%s", CRED_TABLE, domain);
	res = nis_add_entry(sname, obj, 0);
	switch (res->status) {
	case NIS_TRYAGAIN:
		(void) fprintf(stderr,
			"%s: NIS+ server busy, try again later.\n",
			program_name);
		exit(1);
		break;
	case NIS_PERMISSION:
		(void) fprintf(stderr,
			"%s: insufficient permission to update credentials.\n",
			program_name);
		exit(1);
		break;
	case NIS_SUCCESS:
		status = 1;
		break;
	default:
		(void) fprintf(stderr,
			"%s: error creating credential, NIS+ error: %s.\n",
			program_name, nis_sperrno(res->status));
		exit(1);
	}
	nis_freeresult(res);
	return (status);
}


/* Update NIS+ table with new key information */
static int
nisplus_update(nis_name nis_princ, char *authtype, char *public, char *crypt)
{
	nis_object	*obj = init_entry();
	int		status;
	bool_t		addition;
	char		cmpdomain[MAXHOSTNAMELEN + 1];
	char		*userdomain, *domain;

	if (!(userdomain = strchr(netname, '@'))) {
		fprintf(stderr, "%s: invalid netname: '%s'.\n",
			program_name, netname);
		exit(1);
	}
	userdomain++;

	if (strlcpy(cmpdomain, userdomain, sizeof (cmpdomain)) >=
	    sizeof (cmpdomain)) {
		(void) fprintf(stderr,
			    "%s: net domain name %s is too long\n",
			    program_name, cmpdomain);
			exit(1);
	}

	if (cmpdomain[strlen(cmpdomain) - 1] != '.') {
		if (strlcat(cmpdomain, ".", sizeof (cmpdomain)) >=
		    sizeof (cmpdomain)) {
			(void) fprintf(stderr,
				    "%s: net domain name %s is too long\n",
				    program_name, cmpdomain);
			exit(1);
		}
	}

	domain = nis_domain_of(nis_princ);
	if (strcasecmp(domain, cmpdomain) != 0)
		domain = nis_local_directory();

	if (!sanity_checks(nis_princ, domain, authtype))
		exit(1);

	addition = (cred_exists(nis_princ, authtype, domain) == NIS_NOTFOUND);

	ENTRY_VAL(obj, 0) = nis_princ;
	ENTRY_LEN(obj, 0) = strlen(nis_princ) + 1;

	ENTRY_VAL(obj, 1) = authtype;
	ENTRY_LEN(obj, 1) = strlen(authtype) + 1;

	ENTRY_VAL(obj, 2) = netname;
	ENTRY_LEN(obj, 2) = strlen(netname) + 1;

	ENTRY_VAL(obj, 3) = public;
	ENTRY_LEN(obj, 3) = strlen(public) + 1;

	ENTRY_VAL(obj, 4) = crypt;
	ENTRY_LEN(obj, 4) = strlen(crypt) + 1;

	if (addition) {
		obj->zo_owner = nis_princ;
		obj->zo_group = nis_local_group();
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
	return (status == 1 ? 0 : 1);
}


void
addmechtolist(char *mechtype)
{
	mechanism_t	**realmechlist;
	int		i;

	if (realmechlist = __nis_get_mechanisms(FALSE)) {
		/* Match requested mech with list */
		for (i = 0; realmechlist[i]; i++) {
			if (realmechlist[i]->alias)
				if (strcmp(realmechlist[i]->alias, mechtype)
				    == 0) {
					/*
					 * Match, add it to the mechs.
					 * Don't worry about qop or
					 * secserv since they are not
					 * used by chkey.
					 */
					numspecmech++;
					if ((mechs =
						(mechanism_t **)realloc(mechs,
				sizeof (mechanism_t *) * (numspecmech + 1))) ==
					    NULL) {
						perror("Can not change keys");
						exit(1);
					}

					if ((mechs[numspecmech - 1] =
		(mechanism_t *)malloc(sizeof (mechanism_t))) == NULL) {
						perror("Can not change keys");
						exit(1);
					}
					if (realmechlist[i]->mechname)
					mechs[numspecmech - 1]->mechname =
					strdup(realmechlist[i]->mechname);
					if (realmechlist[i]->alias)
					mechs[numspecmech - 1]->alias =
						strdup(realmechlist[i]->alias);
					mechs[numspecmech - 1]->keylen =
						realmechlist[i]->keylen;
					mechs[numspecmech - 1]->algtype =
						realmechlist[i]->algtype;
					mechs[numspecmech] = NULL;
					__nis_release_mechanisms(realmechlist);
					return;
				}
		}

		fprintf(stderr,
		"WARNING: Mechanism '%s' not configured, skipping...\n",
			mechtype);
		__nis_release_mechanisms(realmechlist);
		return;
	}
	fprintf(stderr,
		"WARNING: Mechanism '%s' not configured, skipping...\n",
		mechtype);
}


int
main(int argc, char **argv)
{
	int		c, mcount;
	uid_t		uid;
	uid_t		orig_euid;
	char		*service = NULL;
	program_name = argv[0];

	mechs = __nis_get_mechanisms(FALSE);

	while ((c = getopt(argc, argv, "fps:m:")) != -1) {
		switch (c) {
		case 'f':
			/*
			 * Not documented as of on1093.
			 * Temporarily supported
			 */
			force++;
			break;
		case 'p':
			makenew = FALSE;
			break;
		case 's':
			if (!service)
				service = strdup(optarg);
			else
				usage();
			break;
		case 'm':
			if (mechs && specmech == FALSE) {
				__nis_release_mechanisms(mechs);
				mechs = NULL;
			}
			specmech = TRUE;
			addmechtolist(optarg);
			break;
		default:
			usage();
		}
	}

	if (optind < argc)
		usage();

	dest_service = get_pk_source(service);

	if (!(netname = malloc(MAXNETNAMELEN + 1))) {
		fprintf(stderr, "%s: Malloc failure.\n", program_name);
		exit(1);
	}
	if (!__getnetnamebyuid(netname, uid = getuid())) {
		fprintf(stderr, "%s: cannot generate netname for uid %d\n",
			program_name, uid);
		exit(1);
	}
	sec_domain = strdup(strchr(netname, '@') + 1);
	getdomainname(local_domain, MAXNETNAMELEN);

	if (makenew)
		fprintf(stdout, "Generating new key for '%s'.\n", netname);
	else
		fprintf(stdout, "Reencrypting key for '%s'.\n", netname);

	if (mechs) {
		if (dest_service == PK_YP || dest_service == PK_FILES) {
			fprintf(stderr,
		"%s: can not add non-DES public keys to %s, skipping.\n",
				program_name, service);
			__nis_release_mechanisms(mechs);
			mechs = NULL;
			initkeylist(TRUE);
		} else
			initkeylist(FALSE);
	} else
		initkeylist(TRUE);

	uid = getuid();
	orig_euid = geteuid();

	/* Get password information */
	if ((pw = getpwuid(uid)) == NULL) {
		fprintf(stderr,
			"%s: Can not find passwd information for %d.\n",
			program_name, uid);
		exit(1);
	}

	/* Set eUID to user */
	seteuid(uid);

	/* Obtain a list of decrypted secret keys */
	getsecrets();

	/* Keylogin user if not already done */
	if (mechs) {
		int mcount;

		for (mcount = 0; CURMECH; mcount++) {
			keylen_t	keylen = CURMECH->keylen;
			algtype_t	algtype = CURMECH->algtype;

			if (!key_secretkey_is_set_g(keylen, algtype) &&
			    slist[mcount]) {
				keylogin(CURMECH->keylen, CURMECH->algtype);
				if ((uid == 0) && (makenew == FALSE))
					write_rootkey(slist[mcount],
					VALID_ALIAS(CURMECH->alias) ?
							CURMECH->alias :
							"",
							keylen, algtype);
			}
		}
	} else {
		assert(slist[0]);
		if (!key_secretkey_is_set()) {
			keylogin_des();
			if ((uid == 0) && (makenew == FALSE))
				write_rootkey(slist[0], "des", 192, 0);
		}
	}

	/* Set eUID back to root */
	(void) seteuid(orig_euid);

	/*
	 * Call getspnam() after the keylogin has been done so we have
	 * the best chance of having read access to the encrypted pw.
	 *
	 * The eUID must be 0 for the getspnam() so the name service
	 * switch can handle the following eUID sensitive cases:
	 *
	 *	files/compat:	read /etc/shadow
	 *
	 *	nisplus:	try to read the encrypted pw as the root
	 *			principal and if that fails, and if the
	 *			user's secret key is set, seteuid(user)
	 *			and retry the read.
	 */
	if ((spw = getspnam(pw->pw_name)) == 0) {

		/* Set eUID back to user */
		(void) seteuid(uid);

		(void) fprintf(stderr,
			"%s: cannot find shadow entry for %s.\n",
			program_name, pw->pw_name);
		exit(1);
	}

	/* Set eUID back to user */
	(void) seteuid(uid);

	if (strcmp(spw->sp_pwdp, NOPWDRTR) == 0) {
		(void) fprintf(stderr,
		"%s: do not have read access to the passwd field for %s\n",
				program_name, pw->pw_name);
		exit(1);
	}

	/*
	 * force will be only supported for a while
	 * 	-- it is NOT documented as of s1093
	 */
	if (force) {
		char	*prompt = "Please enter New password:";

		login_pw = getpass(prompt);
		if (!login_pw || !(strlen(login_pw))) {
			fprintf(stderr, "%s: key-pair(s) unchanged for %s.\n",
				program_name, pw->pw_name);
			exit(1);
		}
	} else {
		/*
		 * Reconsile rpc_pws and login_pw.
		 *
		 * This function will either return with login_pw == rpc_pw
		 * (and thus, the new pw to encrypt keys) or it will exit.
		 */
		cmp_passwd();
	}

	if (makenew)
		makenewkeys();
	else
		getpublics();

	encryptkeys();

	storekeys();

	if (makenew) {
		if (uid == 0) {
			if (mechs) {
				for (mcount = 0; CURMECH; mcount++) {
					if (!slist[mcount])
						continue;
					write_rootkey(slist[mcount],
							CURMECH->alias,
							CURMECH->keylen,
							CURMECH->algtype);
				}
			} else {
				assert(slist[0]);
				write_rootkey(slist[0], "des", 192, 0);
			}
		}
		if (mechs) {
			for (mcount = 0; CURMECH; mcount++)
				keylogin(CURMECH->keylen,
						CURMECH->algtype);
		} else
			keylogin_des();
	}
	return (0);
}
