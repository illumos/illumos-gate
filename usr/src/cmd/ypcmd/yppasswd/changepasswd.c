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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Beware those who enter here.
 * The logic may appear hairy, but it's been ARCed.
 * See /shared/sac/PSARC/1995/122/mail
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
#include <shadow.h>
#include <signal.h>
#include <crypt.h>
#include <rpc/rpc.h>
#include <rpcsvc/yppasswd.h>
#include <utmpx.h>
#include <nss_dbdefs.h>

#define	STRSIZE 100
#define	FINGERSIZE (4 * STRSIZE - 4)
#define	SHELLSIZE (STRSIZE - 2)
#define	UTUSERLEN (sizeof (((struct utmpx *)0)->ut_user))

/* Prototypes */
extern bool_t validloginshell(char *sh, char *arg, int);
extern int    validstr(char *str, size_t size);
extern int yplckpwdf();
extern int ypulckpwdf();

static char *
cryptoldpasswd(char *oldpass, char *salt, char *acctname)
{
	char *oldpass_crypt = NULL;

	if ((oldpass_crypt = crypt(oldpass, salt)) == NULL) {
		if (errno == EINVAL) {
			syslog(LOG_ERR,
			    "yppasswdd: password not changed for \"%s\" - "
			    "crypt module not supported on the master\n",
			    acctname);
		} else {
			syslog(LOG_ERR,
			    "yppasswdd: password not changed for \"%s\" - "
			    "%s\n", acctname, strerror(errno));
		}
	}
	return (oldpass_crypt);
}

void
changepasswd(SVCXPRT *transp)
{
	/*
	 * Put these numeric constants into const variables so
	 *   a) they're visible in a debugger
	 *   b) the compiler can play it's cool games with em
	 */
	static const int cryptpwsize = CRYPT_MAXCIPHERTEXTLEN;
	static const int fingersize = FINGERSIZE;
	static const int shellsize = SHELLSIZE;

	struct yppasswd yppwd;
	struct passwd newpw, opwd;
	struct spwd ospwd;
	struct sigaction sa, osa1, osa2, osa3;
	struct stat pwstat, spstat, adjstat;
	char *oldpass_crypt = NULL;

	char newpasswdfile[FILENAME_MAX];
	char newshadowfile[FILENAME_MAX];
	char newadjunctfile[FILENAME_MAX];
	char tmppasswdfile[FILENAME_MAX];
	char tmpshadowfile[FILENAME_MAX];
	char tmpadjunctfile[FILENAME_MAX];
	char pwbuf[NSS_LINELEN_PASSWD], spbuf[NSS_LINELEN_SHADOW];
	char adjbuf[BUFSIZ+1], adjbuf_new[BUFSIZ+1], cmdbuf[BUFSIZ];
	char adj_encrypt[CRYPT_MAXCIPHERTEXTLEN + 1];
	/*
	 * The adj_crypt_* pointers are used to point into adjbuf
	 * NOT adj_encrypt
	 */
	char *adj_crypt_begin, *adj_crypt_end;
	char name[UTUSERLEN + sizeof (":")];
	char *p;

	FILE *opwfp = NULL, *ospfp = NULL, *oadjfp = NULL,
	    *npwfp = NULL, *nspfp = NULL, *nadjfp = NULL;
	int npwfd = -1, nspfd = -1, nadjfd = -1;

	int i, ans, chsh, chpw, chgecos, namelen;
	int gotadjunct = 0, gotshadow = 0, gotpasswd = 0;
	int doneflag = 0, root_on_master = 0;
	pid_t retval;

	time_t now;

	long pwpos = 0, sppos = 0;

	/* Globals :-( */
	extern int single, nogecos, noshell, nopw, mflag, Mstart, Argc;
	extern char **Argv;
	extern char passwd_file[], shadow_file[], adjunct_file[];
	extern int useadjunct;
	extern int useshadow;

	/* Clean out yppwd */
	memset(&yppwd, 0, sizeof (struct yppasswd));

	/* Get the RPC args */
	if (!svc_getargs(transp, xdr_yppasswd, (caddr_t)&yppwd)) {
		svcerr_decode(transp);
		return;
	}

	/* Perform basic validation */
	if (/* (!validstr(yppwd.oldpass, PWSIZE)) || */ /* see PR:nis/38 */
	    (!validstr(yppwd.newpw.pw_passwd, cryptpwsize)) ||
	    (!validstr(yppwd.newpw.pw_name, UTUSERLEN)) ||
	    (!validstr(yppwd.newpw.pw_gecos, fingersize)) ||
	    (!validstr(yppwd.newpw.pw_shell, shellsize))) {
		svcerr_decode(transp);
		return;
	}

	/*
	 * Special case: root on the master server can change other users'
	 * passwords without first entering the old password.  We need to
	 * ensure that this is indeed root on the master server. (bug 1253949)
	 */
	if (strcmp(transp->xp_netid, "ticlts") == 0) {
		svc_local_cred_t cred;
		if (!svc_get_local_cred(transp, &cred)) {
			syslog(LOG_ERR, "yppasswdd: Couldn't get "
			    "local user credentials.\n");
		} else if (cred.ruid == 0)
			root_on_master = 1;
	}

	newpw = yppwd.newpw;
	strcpy(name, newpw.pw_name);
	strcat(name, ":");
	namelen = strlen(name);
	ans = 2;
	chsh = chpw = chgecos = 0;

	/* Get all the filenames straight */
	strcpy(newpasswdfile, passwd_file);
	strcat(newpasswdfile, ".ptmp");
	strcpy(newshadowfile, shadow_file);
	strcat(newshadowfile, ".ptmp");
	strcpy(newadjunctfile, adjunct_file);
	strcat(newadjunctfile, ".ptmp");

	memset(&sa, 0, sizeof (struct sigaction));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGTSTP, &sa, (struct sigaction *)0);
	sigaction(SIGHUP,  &sa, &osa1);
	sigaction(SIGINT,  &sa, &osa2);
	sigaction(SIGQUIT, &sa, &osa3);

	/* Lock, then open the passwd and shadow files */

	if (yplckpwdf() < 0) {
		syslog(LOG_ERR,
		    "yppasswdd: Password file(s) busy. "
		    "Try again later.\n");
		ans = 8;
		goto cleanup;
	}

	if ((opwfp = fopen(passwd_file, "r")) == NULL) {
		syslog(LOG_ERR, "yppasswdd: Could not open %s\n", passwd_file);
		goto cleanup;
	}

	fstat(fileno(opwfp), &pwstat);

	if (useshadow) {
		if ((ospfp = fopen(shadow_file, "r")) == NULL) {
			syslog(LOG_ERR,
			    "yppasswdd: Could not open %s\n", shadow_file);
			goto cleanup;
		}

		fstat(fileno(ospfp), &spstat);
	}

	if (useadjunct) {
		if ((oadjfp = fopen(adjunct_file, "r")) == NULL) {
			syslog(LOG_ERR,
			    "yppasswdd: Could not open %s\n",
			    adjunct_file);
			goto cleanup;
		}

		fstat(fileno(oadjfp), &adjstat);
	}

	/*
	 * Open the new passwd and shadow tmp files,
	 * first with open and then create a FILE * with fdopen()
	 */
	if ((npwfd = open(newpasswdfile, O_WRONLY | O_CREAT | O_EXCL,
	    pwstat.st_mode)) < 0) {
		if (errno == EEXIST) {
			syslog(LOG_WARNING,
			    "yppasswdd: passwd file busy - try again\n");
			ans = 8;
		} else {
			syslog(LOG_ERR, "yppasswdd: %s: %m",
			    newpasswdfile);
			ans = 9;
		}
		goto cleanup;
	}

	fchown(npwfd, pwstat.st_uid, pwstat.st_gid);

	if ((npwfp = fdopen(npwfd, "w")) == NULL) {
		syslog(LOG_ERR,
		    "yppasswdd: fdopen() on %s failed\n", newpasswdfile);
		goto cleanup;
	}

	if (useshadow) {
		if ((nspfd = open(newshadowfile, O_WRONLY | O_CREAT | O_EXCL,
		    spstat.st_mode)) < 0) {
			if (errno == EEXIST) {
				syslog(LOG_WARNING,
				    "yppasswdd: shadow file busy - try "
				    "again\n");
				ans = 8;
			} else {
				syslog(LOG_ERR, "yppasswdd: %s: %m",
				    newshadowfile);
				ans = 9;
			}
			goto cleanup;
		}

		fchown(nspfd, spstat.st_uid, spstat.st_gid);

		if ((nspfp = fdopen(nspfd, "w")) == NULL) {
			syslog(LOG_ERR,
			    "yppasswdd: fdopen() on %s failed\n",
			    newshadowfile);
			goto cleanup;
		}
	}

	if (useadjunct) {
		if ((nadjfd = open(newadjunctfile, O_WRONLY | O_CREAT | O_EXCL,
		    adjstat.st_mode)) < 0) {
			if (errno == EEXIST) {
				syslog(LOG_WARNING,
				    "yppasswdd: adjunct file busy - try "
				    "again\n");
				ans = 8;
			} else {
				syslog(LOG_ERR, "yppasswdd: %s: %m",
				    newadjunctfile);
				ans = 9;
			}
			goto cleanup;
		}

		fchown(nadjfd, adjstat.st_uid, adjstat.st_gid);

		if ((nadjfp = fdopen(nadjfd, "w")) == NULL) {
			syslog(LOG_ERR,
			    "yppasswdd: fdopen() on %s failed\n",
			    newadjunctfile);
			goto cleanup;
		}
	}

	/*
	 * The following code may not seem all that elegant, but my
	 * interpretation of the man pages relating to the passwd and
	 * shadow files would seem to indicate that there is no guarantee
	 * that the entries contained in those files will be in the same
	 * order...
	 *
	 * So here's the high level overview:
	 *
	 *    Loop through the passwd file reading in lines and writing them
	 *    out to the new file UNTIL we get to the correct entry.
	 *    IF we have a shadow file, loop through it reading in lines and
	 *    writing them out to the new file UNTIL we get to the correct
	 *    entry. IF we have an adjunct file, loop through it reading in
	 *    lines and writing them out to the new file UNTIL we get to the
	 *    correct entry.
	 *
	 *    Figure out what's changing, contruct the new passwd, shadow,
	 *    and adjunct entries and spit em out to the temp files.
	 *    At this point, set the done flag and leap back into the loop(s)
	 *    until you're finished with the files and then leap to the
	 *    section that installs the new files.
	 */

loop_in_files:
	/* While we find things in the passwd file */
	while (fgets(pwbuf, NSS_LINELEN_PASSWD, opwfp)) {

		/*
		 * Is this the passwd entry we want?
		 * If not, then write it out to the new passwd temp file
		 * and remember our position.
		 */
		if (doneflag || strncmp(name, pwbuf, namelen)) {
			if (fputs(pwbuf, npwfp) == EOF) {
				syslog(LOG_ERR,
				    "yppasswdd: write to passwd file "
				    "failed.\n");
				goto cleanup;
			}
			pwpos = ftell(opwfp);
			continue;
		}
		gotpasswd = 1;
		break;
	}

	/* no match */
	if (!gotpasswd) {
		syslog(LOG_ERR, "yppasswdd: user %s does not exist\n", name);
		goto cleanup;
	}

	/* While we find things in the shadow file */
	while (useshadow && fgets(spbuf, NSS_LINELEN_SHADOW, ospfp)) {

		/*
		 * Is this the shadow entry that we want?
		 * If not, write it out to the new shadow temp file
		 * and remember our position.
		 */
		if (doneflag || strncmp(name, spbuf, namelen)) {
			if (fputs(spbuf, nspfp) == EOF) {
				syslog(LOG_ERR,
				    "yppasswdd: write to shadow file "
				    "failed.\n");
				goto cleanup;
			}
			sppos = ftell(ospfp);
			continue;
		}
		gotshadow = 1;
		break;
	}

	/* While we find things in the adjunct file */
	while (useadjunct && fgets(adjbuf, BUFSIZ, oadjfp)) {

		/*
		 * is this the adjunct entry that we want?
		 * If not, write it out to the new temp file
		 * and remember our position.
		 */
		if (doneflag || strncmp(name, adjbuf, namelen)) {
			if (fputs(adjbuf, nadjfp) == EOF) {
				syslog(LOG_ERR,
				    "yppasswdd: write to adjunct file "
				    "failed.\n");
				goto cleanup;
			}
			continue;
		}
		gotadjunct = 1;
		break;
	}

	if (doneflag)
		goto install_files;

	if (useshadow && !gotshadow) {
		syslog(LOG_ERR, "yppasswdd: no passwd in shadow for %s\n",
		    newpw.pw_name);
		ans = 4;
		goto cleanup;
	}
	if (useadjunct && !gotadjunct) {
		syslog(LOG_ERR, "yppasswdd: no passwd in adjunct for %s\n",
		    newpw.pw_name);
		ans = 4;
		goto cleanup;
	}

	/*
	 * Now that we've read in the correct passwd AND
	 * shadow lines, we'll rewind to the beginning of
	 * those lines and let the fget*ent() calls do
	 * the work.  Since we are only working with the
	 * first two fields of the adjunct entry, leave
	 * it as a char array.
	 */
	fseek(opwfp, pwpos, SEEK_SET);
	opwd  = *fgetpwent(opwfp);

	if (useshadow) {
		fseek(ospfp, sppos, SEEK_SET);
		ospwd = *fgetspent(ospfp);
	}

	oldpass_crypt = cryptoldpasswd(yppwd.oldpass, newpw.pw_passwd,
	    newpw.pw_name);
	if (oldpass_crypt == NULL) {
		ans = 3;
		goto cleanup;
	}
	p = newpw.pw_passwd;
	if ((!nopw) &&
	    p && *p &&
	    !((*p++ == '#') && (*p++ == '#') &&
	    (strcmp(p, opwd.pw_name) == 0)) &&
	    (strcmp(oldpass_crypt, newpw.pw_passwd) != 0))
		chpw = 1;
	oldpass_crypt = NULL;

	if ((!noshell) && (strcmp(opwd.pw_shell, newpw.pw_shell) != 0)) {
		if (single)
			chpw = 0;
		chsh = 1;
	}

	if ((!nogecos) && (strcmp(opwd.pw_gecos, newpw.pw_gecos) != 0)) {
		if (single) {
			chpw = 0;
			chsh = 0;
		}
		chgecos = 1;
	}

	if (!(chpw + chsh + chgecos)) {
		syslog(LOG_NOTICE, "yppasswdd: no change for %s\n",
		    newpw.pw_name);
		ans = 3;
		goto cleanup;
	}

	if (useshadow && !root_on_master) {
		oldpass_crypt = cryptoldpasswd(yppwd.oldpass, ospwd.sp_pwdp,
		    newpw.pw_name);
		if (oldpass_crypt == NULL)
			goto cleanup;
		if (ospwd.sp_pwdp && *ospwd.sp_pwdp &&
		    (strcmp(oldpass_crypt, ospwd.sp_pwdp) != 0)) {

			syslog(LOG_NOTICE, "yppasswdd: passwd incorrect\n",
			    newpw.pw_name);
			ans = 7;
			goto cleanup;
		}
	} else if (useadjunct) {
		/*
		 * Clear the adj_encrypt array.  Extract the encrypted passwd
		 * into adj_encrypt by setting adj_crypt_begin and
		 * adj_crypt_end to point at the first character of the
		 * encrypted passwd and the first character following the
		 * encrypted passwd in adjbuf, respectively, and copy the
		 * stuff between (there may not be anything) into adj_ecrypt.
		 * Then, check that adj_encrypt contains something and that
		 * the old passwd is correct.
		 */
		memset(adj_encrypt, 0, sizeof (adj_encrypt));
		adj_crypt_begin = adjbuf + namelen;
		adj_crypt_end = strchr(adj_crypt_begin, ':');
		strncpy(adj_encrypt, adj_crypt_begin,
		    adj_crypt_end - adj_crypt_begin);
		oldpass_crypt = cryptoldpasswd(yppwd.oldpass, adj_encrypt,
		    newpw.pw_name);
		if (oldpass_crypt == NULL)
			goto cleanup;
		if (!root_on_master && *adj_encrypt &&
		    (strcmp(oldpass_crypt, adj_encrypt) != 0)) {

			syslog(LOG_NOTICE, "yppasswdd: passwd incorrect\n",
			    newpw.pw_name);
			ans = 7;
			goto cleanup;
		}
	} else {
		oldpass_crypt = cryptoldpasswd(yppwd.oldpass, opwd.pw_passwd,
		    newpw.pw_name);
		if (oldpass_crypt == NULL)
			goto cleanup;
		if (!root_on_master && opwd.pw_passwd && *opwd.pw_passwd &&
		    (strcmp(oldpass_crypt, opwd.pw_passwd) != 0)) {

			syslog(LOG_NOTICE, "yppasswdd: passwd incorrect\n",
			    newpw.pw_name);
			ans = 7;
			goto cleanup;
		}
	}

#ifdef DEBUG
	printf("%d %d %d\n", chsh, chgecos, chpw);

	printf("%s %s %s\n",
	    yppwd.newpw.pw_shell,
	    yppwd.newpw.pw_gecos,
	    yppwd.newpw.pw_passwd);

	printf("%s %s %s\n",
	    opwd.pw_shell,
	    opwd.pw_gecos,
	    ospwd.sp_pwdp);
#endif

	if (chsh &&
	    !validloginshell(opwd.pw_shell, newpw.pw_shell, root_on_master)) {
		goto cleanup;
	}

	/* security hole fix from original source */
	for (p = newpw.pw_name; (*p != '\0'); p++)
		if ((*p == ':') || !(isprint(*p)))
			*p = '$';	/* you lose buckwheat */
	for (p = newpw.pw_passwd; (*p != '\0'); p++)
		if ((*p == ':') || !(isprint(*p)))
			*p = '$';	/* you lose buckwheat */

	if (chgecos)
		opwd.pw_gecos = newpw.pw_gecos;

	if (chsh)
		opwd.pw_shell = newpw.pw_shell;

	/*
	 * If we're changing the shell or gecos fields and we're
	 * using a shadow or adjunct file or not changing the passwd
	 * then go ahead and update the passwd file.  The case where
	 * the passwd is being changed and we are not using a shadow
	 * or adjunct file is handled later.
	 */
	if ((chsh || chgecos) && (useshadow || useadjunct || !chpw) &&
	    putpwent(&opwd, npwfp)) {

		syslog(LOG_ERR, "yppasswdd: putpwent failed: %s\n",
		    passwd_file);
		goto cleanup;
	}

	if (chpw) {
		if (useshadow) {
			ospwd.sp_pwdp = newpw.pw_passwd;
			now = DAY_NOW;
			/* password aging - bug for bug compatibility */
			if (ospwd.sp_max != -1) {
				if (now < ospwd.sp_lstchg + ospwd.sp_min) {
					syslog(LOG_ERR,
					    "yppasswdd: Sorry: < %ld days "
					    "since the last change.\n",
					    ospwd.sp_min);
					goto cleanup;
				}
			}
			ospwd.sp_lstchg = now;
			if (putspent(&ospwd, nspfp)) {
				syslog(LOG_ERR,
				    "yppasswdd: putspent failed: %s\n",
				    shadow_file);
				goto cleanup;
			}
		} else if (useadjunct) {
			sprintf(adjbuf_new,
			    "%s%s%s", name, newpw.pw_passwd, adj_crypt_end);
			if (fputs(adjbuf_new, nadjfp) == EOF) {
				syslog(LOG_ERR,
				    "yppasswdd: write to adjunct failed: %s\n",
				    adjunct_file);
				goto cleanup;
			}
		} else {
			opwd.pw_passwd = newpw.pw_passwd;
			if (putpwent(&opwd, npwfp)) {
				syslog(LOG_ERR,
				    "yppasswdd: putpwent failed: %s\n",
				    passwd_file);
				goto cleanup;
			}
		}
	}

	if (!doneflag) {
		doneflag = 1;
		goto loop_in_files;
	}

install_files:
	/*
	 * Critical section, nothing special needs to be done since we
	 * hold exclusive access to the *.ptmp files
	 */
	fflush(npwfp);
	if (useshadow)
		fflush(nspfp);
	if (useadjunct)
		fflush(nadjfp);

	strcpy(tmppasswdfile, passwd_file);
	strcat(tmppasswdfile, "-");
	if (useshadow) {
		strcpy(tmpshadowfile, shadow_file);
		strcat(tmpshadowfile, "-");
	}
	if (useadjunct) {
		strcpy(tmpadjunctfile, adjunct_file);
		strcat(tmpadjunctfile, "-");
	}

	if ((!useshadow && !useadjunct) || (chsh || chgecos)) {
		if (rename(passwd_file, tmppasswdfile) < 0) {
			syslog(LOG_CRIT, "yppasswdd: failed to backup "
			    "passwd file: %m");
			goto cleanup;
		} else {
			if (rename(newpasswdfile, passwd_file) < 0) {
				syslog(LOG_CRIT,
				    "yppasswdd: failed to mv passwd: %m");
				if (rename(tmppasswdfile, passwd_file) < 0) {
					syslog(LOG_CRIT,
					    "yppasswdd: failed to restore "
					    "backup of passwd file: %m");
				}
				goto cleanup;
			}
		}
	}

	if (useshadow && chpw) {
		if (rename(shadow_file, tmpshadowfile) < 0) {
			syslog(LOG_CRIT, "yppasswdd: failed to back up "
			    "shadow file: %m");
			if (rename(tmppasswdfile, passwd_file) < 0) {
				syslog(LOG_CRIT,
				    "yppasswdd: failed to restore "
				    "backup of passwd file: %m");
			}
			goto cleanup;
		} else {
			if (rename(newshadowfile, shadow_file) < 0) {
				syslog(LOG_CRIT,
				    "yppasswdd: failed to mv shadow: %m");
				if (rename(tmpshadowfile, shadow_file) < 0) {
					syslog(LOG_CRIT,
					    "yppasswdd: failed to restore "
					    "backup of shadow file: %m");
				}
				if (rename(tmppasswdfile, passwd_file) < 0) {
					syslog(LOG_CRIT,
					    "yppasswdd: failed to restore "
					    "backup of passwd file: %m");
				}
				goto cleanup;
			}
		}
	} else if (useadjunct && chpw) {
		if (rename(adjunct_file, tmpadjunctfile) < 0) {
			syslog(LOG_CRIT, "yppasswdd: failed to back up "
			    "adjunct file: %m");
			if (rename(tmppasswdfile, passwd_file) < 0) {
				syslog(LOG_CRIT,
				    "yppasswdd: failed to restore backup "
				    "of passwd: %m");
			}
			goto cleanup;
		} else {
			if (rename(newadjunctfile, adjunct_file) < 0) {
				syslog(LOG_CRIT,
				    "yppassdd: failed to mv adjunct: %m");
				if (rename(tmppasswdfile, passwd_file) < 0) {
					syslog(LOG_CRIT,
					    "yppasswdd: failed to restore "
					    "backup of passwd file: %m");
				}
				if (rename(tmpadjunctfile, adjunct_file) < 0) {
					syslog(LOG_CRIT,
					    "yppasswdd: failed to restore "
					    "backup of adjunct file: %m");
				}
				goto cleanup;
			}
		}
	}

	if (doneflag)
		ans = 0;
	/* End critical section */

	/*
	 *  Here we have come only after the new files have been successfully
	 * renamed to original files. At this point, the temp files would still
	 * be existing we need to remove them from the /etc directory
	 */
	unlink(tmppasswdfile);
	if (useshadow)
		unlink(tmpshadowfile);
	if (useadjunct)
		unlink(tmpadjunctfile);

cleanup:

	/* If we don't have opwfp, then we didn't do anything */
	if (opwfp) {
		fclose(opwfp);

		if (ospfp) {
			fclose(ospfp);
		}

		if (oadjfp) {
			fclose(oadjfp);
		}

		unlink(newpasswdfile);
		/* These tests are cheaper than failing syscalls */
		if (useshadow)
			unlink(newshadowfile);
		if (useadjunct)
			unlink(newadjunctfile);

		if (npwfp) {
			fclose(npwfp);

			if (nspfp) {
				fclose(nspfp);
			}
			if (nadjfp) {
				fclose(nadjfp);
			}
		}
	}

	ypulckpwdf();

	if (doneflag && mflag) {
		retval = fork();
		if (retval < 0) {
			syslog(LOG_ERR, "yppasswdd: Fork failed %m");
		} else if (retval == 0) {
			strcpy(cmdbuf, "/usr/ccs/bin/make");
			for (i = Mstart + 1; i < Argc; i++) {
				strcat(cmdbuf, " ");
				strcat(cmdbuf, Argv[i]);
			}

#ifdef DEBUG
			syslog(LOG_ERR, "yppasswdd: about to "
			    "execute %s\n", cmdbuf);
#else
			if (yplckpwdf() < 0) {
				syslog(LOG_ERR, "yppasswdd: Couldn't get the "
				    "lock to update the maps");
			} else {
				setpgrp();
				system(cmdbuf);
				ypulckpwdf();
			}
#endif
			exit(0);
		}
	}

	sigaction(SIGHUP,  &osa1, (struct sigaction *)0);
	sigaction(SIGINT,  &osa2, (struct sigaction *)0);
	sigaction(SIGQUIT, &osa3, (struct sigaction *)0);

	if (!svc_sendreply(transp, xdr_int, (char *)&ans))
		syslog(LOG_WARNING,
		    "yppasswdd: couldn\'t reply to RPC call\n");
}
