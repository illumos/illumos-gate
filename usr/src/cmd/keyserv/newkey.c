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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * Administrative tool to add a new user to the publickey database
 */
#include <stdio.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include <rpc/key_prot.h>
#include <rpcsvc/ypclnt.h>
#include <sys/wait.h>
#include <netdb.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <string.h>
#include <sys/resource.h>
#include <netdir.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nispasswd.h>

#define	MAXMAPNAMELEN	256
#define	MAXPASSWD	256	/* max significant characters in password */

#define	PK_FILES	1
#define	PK_YP		2
#define	PK_NISPLUS	3
#define	PK_LDAP		4

extern	int optind;
extern	char *optarg;
extern	char *get_nisplus_principal();
extern	int __getnetnamebyuid();
extern  int self_check(char *name);

#define	local_host(host_name)	self_check(host_name)

char	*program_name;
int		pk_database;
static	char	*get_password();
static	char *basename();
static	char SHELL[] = "/bin/sh";
static	char YPDBPATH[] = "/var/yp";
static	char PKMAP[] = "publickey.byname";
static	char UPDATEFILE[] = "updaters";
static	char PKFILE[] = "/etc/publickey";
static	void usage(void);

int
main(int argc, char *argv[])
{
	char	name[MAXNETNAMELEN + 1];
	char	public[HEXKEYBYTES + 1];
	char	secret[HEXKEYBYTES + 1];
	char	crypt1[HEXKEYBYTES + KEYCHECKSUMSIZE + 1];
	int	status;
	char	*pass, *target_host = NULL,
	    *username = NULL, *pk_service = NULL;
	char	short_pass[DESCREDPASSLEN + 1];
	struct passwd	*pw;
	NCONF_HANDLE	*nc_handle;
	struct	netconfig *nconf;
	struct	nd_hostserv service;
	struct	nd_addrlist *addrs;
	bool_t	validhost;
	uid_t	uid;
	int	c;
	char	*nprinc = NULL;  /* nisplus principal name */
	char	host_pname[NIS_MAXNAMELEN];

	program_name = argv[0];
	while ((c = getopt(argc, argv, "s:u:h:")) != -1) {
		switch (c) {
		case 's':
			if (pk_service == NULL)
				pk_service = optarg;
			else
				usage();
			break;
		case 'u':
			if (username || target_host)
				usage();
			username = optarg;
			break;
		case 'h':
			if (username || target_host)
				usage();
			target_host = optarg;
			break;
		default:
			usage();
		}
	}

	if (optind < argc || (username == 0 && target_host == 0)) {
		usage();
	}

	if ((pk_database = get_pk_source(pk_service)) == 0)
		usage();

	if (geteuid() != 0) {
		(void) fprintf(stderr, "Must be superuser to run %s\n",
		    program_name);
		exit(1);
	}

	if (username) {
		pw = getpwnam(username);
		if (pw == NULL) {
			(void) fprintf(stderr, "%s: unknown user: '%s'\n",
			    program_name, username);
			exit(1);
		}
		uid = pw->pw_uid;
		if (uid == 0) {
			if (! getnetname(name)) {
				(void) fprintf(stderr,
			"%s: could not get the equivalent netname for %s\n",
				    program_name, username);
				usage();
			}
			if (pk_database == PK_NISPLUS)
				target_host = nis_local_host();
			else {
				if (gethostname(host_pname, NIS_MAXNAMELEN)
				    < 0) {
					(void) fprintf(stderr,
				"%s: could not get the hostname for %s\n",
					    program_name, username);
					usage();
				}
				target_host = host_pname;
			}
		}
		if (__getnetnamebyuid(name, uid) == 0) {
			(void) fprintf(stderr,
			"%s: could not get the equivalent netname for %s\n",
			    program_name, username);
			usage();
		}
		if (pk_database == PK_NISPLUS)
			nprinc = get_nisplus_principal(nis_local_directory(),
			    uid);
	} else {
		/* -h hostname option */
		service.h_host = target_host;
		service.h_serv = NULL;
		validhost = FALSE;
		/* verify if this is a valid hostname */
		nc_handle = setnetconfig();
		if (nc_handle == NULL) {
			/* fails to open netconfig file */
			(void) fprintf(stderr,
			"%s: failed in routine setnetconfig()\n",
			    program_name);
			exit(2);
		}
		while (nconf = getnetconfig(nc_handle)) {
			/* check to see if hostname exists for this transport */
			if ((netdir_getbyname(nconf, &service, &addrs) == 0) &&
			    (addrs->n_cnt != 0)) {
				/* at least one valid address */
				validhost = TRUE;
				break;
			}
		}
		endnetconfig(nc_handle);
		if (!validhost) {
			(void) fprintf(stderr, "%s: unknown host: %s\n",
			    program_name, target_host);
			exit(1);
		}
		(void) host2netname(name, target_host, (char *)NULL);
		if (pk_database == PK_NISPLUS) {
			if (target_host[strlen(target_host) - 1] != '.') {
				sprintf(host_pname, "%s.%s",
				    target_host, nis_local_directory());
				nprinc = host_pname;
			} else
				nprinc = target_host;
		}
		uid = 0;
	}

	(void) fprintf(stdout, "Adding new key for %s.\n", name);
	pass = get_password(uid, target_host, username);

	if (pass == NULL)
		exit(1);

	(void) strlcpy(short_pass, pass, sizeof (short_pass));
	(void) __gen_dhkeys(public, secret, short_pass);

	(void) memcpy(crypt1, secret, HEXKEYBYTES);
	(void) memcpy(crypt1 + HEXKEYBYTES, secret, KEYCHECKSUMSIZE);
	crypt1[HEXKEYBYTES + KEYCHECKSUMSIZE] = 0;
	xencrypt(crypt1, short_pass);

	if (status = setpublicmap(name, public, crypt1, pk_database,
	    nprinc, short_pass)) {
		switch (pk_database) {
		case PK_YP:
			(void) fprintf(stderr,
			    "%s: unable to update NIS database (%u): %s\n",
			    program_name, status,
			    yperr_string(status));
			break;
		case PK_FILES:
			(void) fprintf(stderr,
			    "%s: hence, unable to update publickey database\n",
			    program_name);
			break;
		case PK_NISPLUS:
			(void) fprintf(stderr,
			    "%s: unable to update nisplus database\n",
			    program_name);
			break;
		default:
			(void) fprintf(stderr,
			    "%s: could not update unknown database: %d\n",
			    program_name, pk_database);
		}
		exit(1);
	}
	return (0);
}

/*
 * Set the entry in the public key file
 */
int
setpublicmap(name, public, secret, database, nis_princ, pw)
	int database;
	char *name;
	char *public;
	char *secret;
	nis_name nis_princ;
	char *pw;
{
	char pkent[HEXKEYBYTES + HEXKEYBYTES + KEYCHECKSUMSIZE + 2];
	char *domain = NULL;
	char *master = NULL;
	char hostname[MAXHOSTNAMELEN+1];

	(void) sprintf(pkent, "%s:%s", public, secret);
	switch (database) {
	case PK_YP:
		/* check that we're on the master server */
		(void) yp_get_default_domain(&domain);
		if (yp_master(domain, PKMAP, &master) != 0) {
			(void) fprintf(stderr,
			"%s: cannot find master of NIS publickey database\n",
				program_name);
			exit(1);
		}
		if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
			(void) fprintf(stderr,
				"%s: cannot find my own host name\n",
				program_name);
			exit(1);
		}
		if (strcmp(master, hostname) != 0) {
			(void) fprintf(stderr,
			"%s: can only be used on NIS master machine '%s'\n",
				program_name, master);
			exit(1);
		}

		if (chdir(YPDBPATH) < 0) {
			(void) fprintf(stderr, "%s: cannot chdir to %s",
			program_name, YPDBPATH);
		}
		(void) fprintf(stdout,
			"Please wait for the database to get updated ...\n");
		return (mapupdate(name, PKMAP, YPOP_STORE, pkent));
	case PK_FILES:
		return (localupdate(name, PKFILE, YPOP_STORE, pkent));
	case PK_NISPLUS:
		return (nisplus_update(name, public, secret, nis_princ));
	case PK_LDAP:
		return (ldap_update("dh192-0", name, public, secret, pw));
	default:
		break;
	}
	return (1);
}

void
usage(void)
{
	(void) fprintf(stderr,
	    "usage:\t%s -u username [-s ldap | nisplus | nis | files]\n",
	    program_name);
	(void) fprintf(stderr,
	    "\t%s -h hostname [-s ldap | nisplus | nis | files]\n",
	    program_name);
	exit(1);
}

/*
 * The parameters passed into the routine get_password and the
 * return values are as follows:
 * If the -h flag was specified on the command line:
 * (a) username is null
 * (b) target_host is non-null
 * (c) uid is 0
 * (d) the login password of root on target_host is returned
 *
 * If the -u flag was specified on the command line:
 * (a) username is non-null
 * (b) target_host is null in all cases except when username is root;
 *	in that case target_host is set to the local host
 * (c) uid is set to the username's uid
 * (d) the login password of the user <username> is returned
 */
static char *
get_password(uid, target_host, username)
uid_t	uid;
char	*target_host;
char	*username;
{
	static	char	password[MAXPASSWD+1];
	char		prompt[MAXPASSWD+MAXHOSTNAMELEN+64];
	char		*encrypted_password,
			*login_password = NULL,
			*pass = NULL;
	struct	passwd	*pw;
	struct	spwd	*spw;

	if ((username != 0) ||
	    (target_host != 0) && (local_host(target_host))) {

	/*
	 * "-u username" or "-h localhost" was specified on the
	 * command line
	 */

	pw = getpwuid(uid);

	if (! pw) {
		(void) fprintf(stderr,
			"%s: unable to locate password record for uid %d\n",
			program_name, uid);
		return (0);
	}
	spw = getspnam(pw->pw_name);
	if (spw)
		login_password = spw->sp_pwdp;

	if (! login_password || (strlen(login_password) == 0)) {
		(void) fprintf(stderr,
			"%s: unable to locate shadow password record for %s\n",
			program_name, pw->pw_name);
		return (0);
	}

	if (uid == 0) {
		(void) sprintf(prompt, "Enter local root login password:");
	} else
	    (void) sprintf(prompt, "Enter %s's login password:",
		pw->pw_name);

	pass = getpassphrase(prompt);
	if (pass && strlen(pass) == 0) {
		(void) fprintf(stderr, "%s: Invalid password.\n",
			program_name);
		return (0);
	}
	strcpy(password, pass);
	encrypted_password = crypt(password, login_password);

	/* Verify that password supplied matches login password */
	if (strcmp(encrypted_password, login_password) != 0) {
		/*
		 * Give another chance for typo
		 */
		pass = getpassphrase("Please retype password:");
	    if (pass && strlen(pass) == 0) {
		(void) fprintf(stderr, "%s: Invalid password.\n",
			program_name);
		return (0);
	    }
	    strcpy(password, pass);
	    encrypted_password = crypt(password, login_password);
	    if (strcmp(encrypted_password, login_password) != 0) {
		    (void) fprintf(stderr,
			"%s: ERROR, invalid password.\n",
			program_name);
		    return (0);
	    }
	}
	} else {
		/*
		 * "-h remotehost" was specified on the command line
		 *
		 * Since we cannot verify the root password of the remote
		 * host we have to trust what the user inputs. We can,
		 * however, reduce the possibility of an  error by prompting
		 * the user to enter the target host's password twice and
		 * comparing those two. We can also authenticate the
		 * user to be root by checking the real uid.
		 */

		if (getuid() != 0) {
			(void) fprintf(stderr, "Must be superuser to run %s\n",
			    program_name);
			return (0);
		}

		(void) sprintf(prompt,
		    "Enter %s's root login password:",
		    target_host);
		pass = getpassphrase(prompt);
		if (!pass) {
			(void) fprintf(stderr,
			    "%s: getpass failed.\n",
			    program_name);
			return (0);
		}
		if (!*pass) {
			(void) fprintf(stderr,
			    "%s: Invalid root password.\n",
			    program_name);
			return (0);
		}
		strcpy(password, pass);

		/*
		 * Now re-enter the password and compare it to the
		 * one just read.
		 */
		(void) sprintf(prompt,
		    "Please confirm %s's root login password:",
		    target_host);
		pass = getpassphrase(prompt);
		if (!pass) {
			(void) fprintf(stderr,
			    "%s: getpass failed.\n",
			    program_name);
			return (0);
		}
		if (!*pass) {
			(void) fprintf(stderr,
			    "%s: Invalid root password.\n",
			    program_name);
			return (0);
		}
		if (strcmp(pass, password) != 0) {
			(void) fprintf(stderr,
			    "%s: Password Incorrect.\n",
			    program_name);
			return (0);
		}
	}

	return (password);
}
