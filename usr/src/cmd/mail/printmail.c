/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mail.h"
/*
 *	Print mail entries
 */
void
printmail()
{
	static char pn[] = "printmail";
	int	flg, curlet, showlet, k, print, aret, stret, rc;
	int	nsmbox = 0;	/* 1 ==> mailbox is in non-standard place */
	int	sav_j = -1;
	char	*p, *getarg();
	struct	stat stbuf;
	struct	stat *stbufp;
	int ttyf = isatty(1) ? TTY : ORDINARY;
	char	readbuf[LSIZE];	/* holds user's response in interactive mode */
	char	*resp;
	gid_t	savedegid;

	stbufp = &stbuf;

	/*
	 *	create working directory mbox name
	 */
	if ((hmbox = malloc(strlen(home) + strlen(mbox) + 1)) == NULL) {
		errmsg(E_MBOX, "");
		return;
	}
	cat(hmbox, home, mbox);

	/*
	 *	If we are not using an alternate mailfile, then get
	 *	the $MAIL value and build the filename for the mailfile.
	 *	If $MAIL is set, but is NOT the 'standard' place, then
	 *	use it but set flgf to circumvent :saved processing.
	 */
	if (!flgf) {
		if ((p = malloc(strlen(maildir) + strlen(my_name) + 1))
								== NULL) {
			errmsg(E_MEM, "");
			return;
		}
		cat(p, maildir, my_name);
		if (((mailfile = getenv("MAIL")) == NULL) ||
		    (strlen(mailfile) == 0)) {
			/* $MAIL not set, use standard path to mailfile */
			mailfile = p;
		} else {
			if (strcmp(mailfile, p) != 0) {
			    flgf = 1;
			    nsmbox = 1;
			    Dout(pn, 0, "$MAIL ('%s') != standard path\n",
				mailfile);
			    Dout("", 0, "\tSetting flgf to 1.\n");
			}
			free(p);
		}
	}

	/*
	 *	Get ACCESS and MODIFICATION times of mailfile BEFORE we
	 *	use it. This allows us to put them back when we are
	 *	done. If we didn't, the shell would think NEW mail had
	 *	arrived since the file times would have changed.
	 */
	stret = CERROR;
	if (access(mailfile, A_EXIST) == A_OK) {
		if ((stret = stat(mailfile, stbufp)) != A_OK) {
			errmsg(E_FILE, "Cannot stat mailfile");
			return;
		}
		mf_gid = stbufp->st_gid;
		mf_uid = stbufp->st_uid;
		utimep->actime = stbufp->st_atime;
		utimep->modtime = stbufp->st_mtime;
		file_size = stbufp->st_size;
	}

	/* Open the file as the real gid */
	savedegid = getegid();
	(void) setegid(getgid());
	malf = fopen(mailfile, "r");
	(void) setegid(savedegid);
	/*
	 *	stat succeeded, but we cannot access the mailfile
	 */
	if (stret == CSUCCESS && malf == NULL) {
		char buf[MAXFILENAME+50];
		(void) snprintf(buf, sizeof (buf),
		    "Invalid permissions on %s", mailfile);
		errmsg(E_PERM, buf);
		return;
	} else
	/*
	 *	using an alternate mailfile, but we failed on access
	 */
	if (!nsmbox && flgf && (malf == NULL)) {
		errmsg(E_FILE, "Cannot open mailfile");
		return;
	}
	/*
	 *	we failed to access OR the file is empty
	 */
	else if ((malf == NULL) || (stbuf.st_size == 0)) {
		if (!flge && !flgE) {
			printf("No mail.\n");
		}
		error = E_FLGE;
		Dout(pn, 0, "error set to %d\n", error);
		return;
	}
	if (flge)
		return;

	if (flgE) {
		if (utimep->modtime < utimep->actime) {
			error = E_FLGE_OM;
			Dout(pn, 0, "error set to %d\n", error);
		}
		return;
	}
	/*
	 *	Secure the mailfile to guarantee integrity
	 */
	lock(my_name);

	/*
	 *	copy mail to temp file and mark each letter in the
	 *	let array --- mailfile is still locked !!!
	 */
	mktmp();
	copymt(malf, tmpf);
	onlet = nlet;
	fclose(malf);
	fclose(tmpf);
	unlock();	/* All done, OK to unlock now */
	tmpf = doopen(lettmp, "r+", E_TMP);
	changed = 0;
	print = 1;
	curlet = 0;
	while (curlet < nlet) {
		/*
		 *	reverse order ?
		 */
		showlet = flgr ? curlet : nlet - curlet - 1;

		if (setjmp(sjbuf) == 0 && print != 0) {
				/* -h says to print the headers first */
				if (flgh) {
					gethead(showlet, 0);
					flgh = 0;	/* Only once */
					/* set letter # to invalid # */
					curlet--;
					showlet =
					    flgr ? curlet : nlet - curlet - 1;
				} else {
					if (showlet != sav_j) {
						/* Looking at new message. */
						/* Reset flag to override */
						/* non-display of binary */
						/* contents */
						sav_j = showlet;
						pflg = 0;
						Pflg = flgP;
					}
					copylet(showlet, stdout, ttyf);
				}
		}

		/*
		 *	print only
		 */
		if (flgp) {
			curlet++;
			continue;
		}
		/*
		 *	Interactive
		 */
		interactive = 1;
		setjmp(sjbuf);
		stat(mailfile, stbufp);
		if (stbufp->st_size != file_size) {
			/*
			 *	New mail has arrived, load it
			 */
			k = nlet;
			lock(my_name);
			malf = doopen(mailfile, "r", E_FILE);
			fclose(tmpf);
			tmpf = doopen(lettmp, "a", E_TMP);
			fseek(malf, let[nlet].adr, 0);
			copymt(malf, tmpf);
			file_size = stbufp->st_size;
			fclose(malf);
			fclose(tmpf);
			unlock();
			tmpf = doopen(lettmp, "r+", E_TMP);
			if (++k < nlet)
				printf("New mail loaded into letters %d - %d\n",
				    k, nlet);
			else
				printf("New mail loaded into letter %d\n",
				    nlet);
		}

		/* read the command */
		printf("? ");
		fflush(stdout);
		fflush(stderr);
		if (fgets(readbuf, sizeof (readbuf), stdin) == NULL) break;
		resp = readbuf;
		while (*resp == ' ' || *resp == '\t') resp++;
		print = 1;
		Dout(pn, 0, "resp = '%s'\n", resp);
		if ((rc = atoi(resp)) != 0) {
			if (!validmsg(rc)) print = 0;
			else curlet = flgr ? rc - 1 : nlet - rc;
		} else switch (resp[0]) {
			default:
				printf("Usage:\n");
			/*
			 *	help
			 */
			case '?':
				print = 0;
				for (rc = 0; help[rc]; rc++)
					printf("%s", help[rc]);
				break;
			/*
			 *	print message number of current message
			 */
			case '#':
				print = 0;
				if ((showlet == nlet) || (showlet < 0)) {
					printf("No message selected yet.\n");
				} else {
					printf("Current message number is %d\n",
					    showlet+1);
				}
				break;
			/*
			 *	headers
			 */
			case 'h':
				print = 0;
				if (resp[2] != 'd' &&
				    resp[2] != 'a' &&
				    (rc = getnumbr(resp+1)) > 0) {
					showlet = rc - 1;
					curlet = flgr ? rc - 1 : nlet - rc- 1;
				}
				if (rc == -1 && resp[2] != 'a' &&
				    resp[2] != 'd')
					break;
				if (resp[2] == 'a') rc = 1;
				else if (resp[2] == 'd') rc = 2;
					else rc = 0;

/*
 *				if (!validmsg(showlet)) break;
 */
				gethead(showlet, rc);
				break;
			/*
			 *	skip entry
			 */
			case '+':
			case 'n':
			case '\n':
				curlet++;
				break;
			case 'P':
				Pflg++;
				break;
			case 'p':
				pflg++;
				break;
			case 'x':
				changed = 0;
			case 'q':
				goto donep;
			/*
			 *	Previous entry
			 */
			case '^':
			case '-':
				if (--curlet < 0) curlet = 0;
				break;
			/*
			 *	Save in file without header
			 */
			case 'y':
			case 'w':
			/*
			 *	Save mail with header
			 */
			case 's':
				print = 0;
				if (!validmsg(curlet)) break;
				if (resp[1] == '\n' || resp[1] == '\0') {
					cat(resp+1, hmbox, "");
				} else if (resp[1] != ' ') {
					printf("Invalid command\n");
					break;
				}
				umask(umsave);
				flg = 0;
				if (getarg(lfil, resp + 1) == NULL) {
					cat(resp + 1, hmbox, "");
				}
				malf = (FILE *)NULL;
				p = resp + 1;
				while ((p = getarg(lfil, p)) != NULL) {
					if (flg) {
					    fprintf(stderr,
						"%s: File '%s' skipped\n",
						program, lfil);
					    continue;
					}
					malf = NULL;
					if ((aret = legal(lfil))) {
						malf = fopen(lfil, "a");
					}
					if ((malf == NULL) || (aret == 0)) {
					    fprintf(stderr,
						"%s: Cannot append to %s\n",
						program, lfil);
					    flg++;
					} else if (aret == 2) {
						chown(lfil, my_euid, my_gid);
					}
					if (!flg &&
					    copylet(showlet, malf, resp[0] ==
					    's'? ORDINARY: ZAP) == FALSE) {
						fprintf(stderr,
					    "%s: Cannot save mail to '%s'\n",
						    program, lfil);
						flg++;
					} else
						Dout(pn, 0, "!saved\n");
					if (malf != (FILE *)NULL) {
						fclose(malf);
					}
				}
				umask(7);
				if (!flg) {
					setletr(showlet, resp[0]);
					print = 1;
					curlet++;
				}
				break;
			/*
			 *	Reply to a letter
			 */
			case 'r':
				print = 0;
				if (!validmsg(curlet)) break;
				replying = 1;
				for (k = 1; resp[k] == ' ' || resp[k] == '\t';
				    ++k);
				resp[strlen(resp)-1] = '\0';
				(void) strlcpy(m_sendto, resp+k,
				    sizeof (m_sendto));
				goback(showlet);
				replying = 0;
				setletr(showlet, resp[0]);
				break;
			/*
			 *	Undelete
			 */
			case 'u':
				print = 0;
				if ((k = getnumbr(resp+1)) <= 0) k = showlet;
				else k--;
				if (!validmsg(k)) break;
				setletr(k, ' ');
				break;
			/*
			 *	Mail letter to someone else
			 */
			case 'm':
				{
				reciplist list;
				print = 0;
				if (!validmsg(curlet)) break;
				new_reciplist(&list);
				flg = 0;
				k = 0;
				if (substr(resp, " -") != -1 ||
					substr(resp, "\t-") != -1) {
					printf("Only users may be specified\n");
					break;
				}
				p = resp + 1;
				while ((p = getarg(lfil, p)) != NULL) {
					char *env;
					if (lfil[0] == '$') {
						if (!(env = getenv(&lfil[1]))) {
							fprintf(stderr,
				"%s: %s has no value or is not exported.\n",
							    program, lfil);
							flg++;
						} else
							add_recip(&list, env,
							    FALSE);
						k++;
					} else if (lfil[0] != '\0') {
						add_recip(&list, lfil, FALSE);
						k++;
					}
				}
				(void) strlcpy(Rpath, my_name, sizeof (Rpath));
				sending = TRUE;
				flg += sendlist(&list, showlet, 0);
				sending = FALSE;
				if (k) {
					if (!flg) {
						setletr(showlet, 'm');
						print = 1;
						curlet++;
					}
				} else
					printf("Invalid command\n");
				del_reciplist(&list);
				break;
				}
			/*
			 *	Read new letters
			 */
			case 'a':
				if (onlet == nlet) {
					printf("No new mail\n");
					print = 0;
					break;
				}
				curlet = 0;
				print = 1;
				break;
			/*
			 *	Escape to shell
			 */
			case '!':
				systm(resp + 1);
				printf("!\n");
				print = 0;
				break;
			/*
			 *	Delete an entry
			 */
			case 'd':
				print = 0;
				k = 0;
				if (strncmp("dq", resp, 2) != SAME &&
					strncmp("dp", resp, 2) != SAME)
					if ((k = getnumbr(resp+1)) == -1) break;
				if (k == 0) {
					k = showlet;
					if (!validmsg(curlet)) break;
					print = 1;
					curlet++;
				} else	k--;

				setletr(k, 'd');
				if (resp[1] == 'p') print = 1;
				else if (resp[1] == 'q') goto donep;
				break;
		}
	}
	/*
	 *	Copy updated mailfile back
	 */
donep:
	if (changed) {
		copyback();
		stamp();
	}
}
