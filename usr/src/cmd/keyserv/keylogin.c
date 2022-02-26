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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
 * Set secret key on local machine
 */
#include <stdio.h>
#include <rpc/rpc.h>
#include <rpc/key_prot.h>
#include <nfs/nfs.h>				/* to revoke existing creds */
#include <nfs/nfssys.h>
#include <string.h>
#include <rpcsvc/nis_dhext.h>

#define	ROOTKEY_FILE "/etc/.rootkey"
#define	ROOTKEY_FILE_BACKUP	"/etc/.rootkey.bak"
/* Should last until 16384-bit DH keys */
#define	MAXROOTKEY_LINE_LEN	4224
#define	MAXROOTKEY_LEN		4096

extern int key_setnet_g();

static void logout_curr_key();
static int mkrootkey;

static char *sec_domain = NULL;
static char local_domain[MAXNETNAMELEN + 1];

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


/* write unencrypted secret key into root key file */
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
		(void) rename(ROOTKEY_FILE_BACKUP, ROOTKEY_FILE);
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
		(void) fclose(rootfile);
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
			(void) fflush(rootfile);
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
			(void) fflush(rootfile);
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
	(void) fflush(rootfile);
	fclose(rootfile);
	fclose(bakfile);
	unlink(ROOTKEY_FILE_BACKUP);
	if (keylen == 192)
		fprintf(stderr, "Wrote secret key into %s\n", ROOTKEY_FILE);
	else
		fprintf(stderr, "Wrote %s key into %s\n", flavor,
			ROOTKEY_FILE);
	return;

rootkey_err:
	fprintf(stderr, "WARNING: Could not write %s key to /etc/.rootkey\n",
		flavor);
}

/* Perform AUTH_DES keylogin */
static int
oldkeylogin(char *fullname, char *pass)
{
	char			secret[HEXKEYBYTES+1];
	struct key_netstarg	netst;

		if (getsecretkey(fullname, secret, pass) == 0) {
			fprintf(stderr, "Could not find %s's secret key\n",
				fullname);
			if (sec_domain && *sec_domain &&
				strcasecmp(sec_domain, local_domain)) {
				fprintf(stderr,
"The system default domain '%s' is different from the Secure RPC\n\
domain %s where the key is stored.  The Secure RPC domainname is\n\
defined by the directory object stored in the /var/nis/NIS_COLD_START file.\n\
If you need to change this Secure RPC domainname, please use the nisinit(8)\n\
command with the `-k` option.\n", local_domain, sec_domain);
			} else {
				fprintf(stderr,
		"Make sure the secret key is stored in domain %s\n",
				local_domain);
			}
			return (1);
		}

		if (secret[0] == 0) {
			fprintf(stderr, "Password incorrect for %s\n",
				fullname);
			return (1);
		}
		/* revoke any existing (lingering) credentials... */
		logout_curr_key();

		memcpy(netst.st_priv_key, secret, HEXKEYBYTES);
		memset(secret, 0, HEXKEYBYTES);

		netst.st_pub_key[0] = 0;
		netst.st_netname = strdup(fullname);

		/* do actual key login */
		if (key_setnet(&netst) < 0) {
			fprintf(stderr, "Could not set %s's secret key\n",
				fullname);
			fprintf(stderr, "May be the keyserv is down?\n");
			if (mkrootkey == 0)   /* nothing else to do */
				return (1);
		}

		/* write unencrypted secret key into root key file */
		if (mkrootkey)
			write_rootkey(netst.st_priv_key, "des", 192, 0);

		return (0);
}

/*
 * Revokes the existing credentials for Secure-RPC and Secure-NFS.
 * This should only be called if the user entered the correct password;
 * sorta like the way "su" doesn't force a login if you enter the wrong
 * password.
 */

static void
logout_curr_key()
{
	static char		secret[HEXKEYBYTES + 1];
	struct nfs_revauth_args	nra;

	/*
	 * try to revoke the existing key/credentials, assuming
	 * one exists.  this will effectively mark "stale" any
	 * cached credientials...
	 */
	if (key_setsecret(secret) < 0) {
		return;
	}

	/*
	 * it looks like a credential already existed, so try and
	 * revoke any lingering Secure-NFS privledges.
	 */

	nra.authtype = AUTH_DES;
	nra.uid = getuid();

	(void) _nfssys(NFS_REVAUTH, &nra);
}

void
usage(cmd)
	char *cmd;
{
	fprintf(stderr, "usage: %s [-r]\n", cmd);
	exit(1);
}


int
main(int argc, char *argv[])
{
	char		secret[4096];
	char		fullname[MAXNETNAMELEN + 1];
	char		*getpass();
	char		*pass;
	int		i = 0;
	mechanism_t	**mechlist;

	if (argc == 1)
		mkrootkey = 0;
	else if (argc == 2 && (strcmp(argv[1], "-r") == 0)) {
		if (geteuid() != 0) {
			fprintf(stderr, "Must be root to use -r option.\n");
			exit(1);
		}
		mkrootkey = 1;
	} else
		usage(argv[0]);

	if (getnetname(fullname) == 0) {
		fprintf(stderr, "Could not generate netname\n");
		exit(1);
	}
	sec_domain = strdup(strchr(fullname, '@') + 1);
	getdomainname(local_domain, MAXNETNAMELEN);

	if (!(pass = getpass("Password:")))
		exit(1);

	if (mechlist = __nis_get_mechanisms(FALSE)) {
		while (mechlist[i]) {
			char		*alias;

			if (AUTH_DES_COMPAT_CHK(mechlist[i])) {
				(void) oldkeylogin(fullname, pass);
				i++;
				continue;
			}

			if (VALID_ALIAS(mechlist[i]->alias))
				alias = mechlist[i]->alias;
			else
				alias = "";

			if (getsecretkey_g(fullname, mechlist[i]->keylen,
						mechlist[i]->algtype, secret,
						(((mechlist[i]->keylen / 7) +
						8) * 2) + 1, pass) == 0) {
				fprintf(stderr,
				"WARNING: Could not find %s's %s secret key\n",
					fullname, alias);
				i++;
				continue;
			}

			if (secret[0] == 0) {
				fprintf(stderr,
				    "Password incorrect for %s's %s key.\n",
					fullname, alias);
				i++;
				continue;
			}

			if (key_setnet_g(fullname, secret,
						mechlist[i]->keylen, NULL, 0,
						mechlist[i]->algtype) < 0) {
				fprintf(stderr,
				"Could not set %s's %s secret key\n",
					fullname, alias);
				fprintf(stderr,
					"May be the keyserv is down?\n");
				exit(1);
			}

			if (mkrootkey)
				write_rootkey(secret, mechlist[i]->alias,
						mechlist[i]->keylen,
						mechlist[i]->algtype);
			i++;
		}
	} else
		exit(oldkeylogin(fullname, pass));

	return (0);
}
