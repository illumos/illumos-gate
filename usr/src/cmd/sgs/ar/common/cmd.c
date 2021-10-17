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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2021 Oxide Computer Company
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 */

/*
 * Incompatible Archive Header
 *
 * The archive file member header used in SunOS 4.1 archive files and
 * Solaris archive files are incompatible. The header file is:
 *	/usr/include/ar.h, struct ar_hdr.
 * The member ar_name[] in Solaris comforms with Standard and the
 * member name terminates with '/'. The SunOS's member does not terminate
 * with '/' character. A bug 4046054 was filed:
 *	The ar command in Solaris 2.5.1 is incompatible with archives
 *	created on 4.x.
 *
 * To handle archive files created in SunOS 4.1 system on Solaris, the
 * following changes were made:
 *
 *	1. file.c/writefile()
 *		Before writing each member files into the output
 *		archive file, ar_name[] is checked. If it is NULL,
 *		it means that the original archive header for this
 *		member was incompatible with Solaris format.
 *
 *		The original Solaris ar command ended up having
 *		NULL name for the header. The change here uses the
 *		ar_rawname, which is much closer to the original
 *		name.
 *
 *	2. cmd.c
 *		For the p command, the code used to use only ar_longname
 *		to seach the matching name. The member is set to NULL
 *		if the archive member header was incompatible.
 *		The ar_rawname is also used to find the matching member name.
 *
 *		For commands to update the archive file, we do not
 *		use ar_rawname, and just use the ar_longname. The commands are
 *		r (replace), m (modify the position) and d (delete).
 */

#include "inc.h"

/*
 * Forward Declarations
 */
static void	ar_select(int *, unsigned long);
static void	cleanup(Cmd_info *);
static int	create_extract(ARFILE *, int, int, Cmd_info *);
static char	*match(char *, Cmd_info *);
static void	mesg(int, char *, Cmd_info *);
static void	movefil(ARFILE *, struct stat *);
static FILE	*stats(char *, struct stat *);

/*
 * Commands
 */
void
rcmd(Cmd_info *cmd_info)
{
	FILE		*f;
	ARFILE		*fileptr;
	ARFILE		*abifile = NULL;
	ARFILE		*backptr = NULL;
	ARFILE		*endptr;
	ARFILE		*moved_files;
	ARFILE		*prev_entry, *new_listhead, *new_listend;
	int		deleted;
	struct stat	stbuf;
	char		*gfile;

	new_listhead  = NULL;
	new_listend   = NULL;
	prev_entry    = NULL;

	for (fileptr = getfile(cmd_info);
	    fileptr; fileptr = getfile(cmd_info)) {
		deleted = 0;
		if (!abifile && cmd_info->ponam &&
		    strcmp(fileptr->ar_longname, cmd_info->ponam) == 0)
			abifile = fileptr;
		else if (!abifile)
			backptr = fileptr;

		if (cmd_info->namc == 0 ||
		    (gfile = match(fileptr->ar_longname, cmd_info)) != NULL) {
			/*
			 * NOTE:
			 *	Refer to "Incompatible Archive Header"
			 *	blocked comment at the beginning of this file.
			 */
			f = stats(gfile, &stbuf); /* gfile is set by match */
			if (f == NULL) {
				if (cmd_info->namc) {
					int err = errno;
					(void) fprintf(stderr,
					    MSG_INTL(MSG_SYS_OPEN),
					    gfile, strerror(err));
				}
				/*
				 * Created
				 */
				mesg('c', gfile, cmd_info);
			} else {
				if ((cmd_info->opt_flgs & u_FLAG) &&
				    stbuf.st_mtime <= fileptr->ar_date) {
					(void) fclose(f);
					continue;
				}
				/*
				 * Replaced
				 */
				mesg('r', fileptr->ar_longname, cmd_info);
				movefil(fileptr, &stbuf);
				/*
				 * Clear the previous contents.
				 */
				if (fileptr->ar_flag & F_ELFRAW) {
					/*
					 * clear ar_elf
					 */
					(void) elf_end(fileptr->ar_elf);
					fileptr->ar_elf = 0;
				}
				/* clear 'ar_flag' */
				fileptr->ar_flag &= ~F_ELFRAW;

				/*
				 * Defer reading contents until needed, and
				 * then use an in-kernel file-to-file transfer
				 * to avoid excessive in-process memory use.
				 */
				fileptr->ar_contents = NULL;

				if (fileptr->ar_pathname != NULL)
					free(fileptr->ar_pathname);
				if ((fileptr->ar_pathname =
				    malloc(strlen(gfile) + 1)) == NULL) {
					int err = errno;
					(void) fprintf(stderr,
					    MSG_INTL(MSG_MALLOC),
					    strerror(err));
					exit(1);
				}

				(void) strcpy(fileptr->ar_pathname, gfile);
				(void) fclose(f);

				if (cmd_info->ponam && (abifile != fileptr)) {
					deleted = 1;
					/* remove from archive list */
					if (prev_entry != NULL)
						prev_entry->ar_next = NULL;
					else
						listhead = NULL;
					listend = prev_entry;

					/* add to moved list */
					if (new_listhead == NULL)
						new_listhead = fileptr;
					else
						new_listend->ar_next = fileptr;
					new_listend = fileptr;
				}
				cmd_info->modified++;
			}
		}
		else
			/*
			 * Unchaged
			 */
			mesg('u', fileptr->ar_longname, cmd_info);

		if (deleted)
			deleted = 0;
		else
			prev_entry = fileptr;
	}

	endptr = listend;
	cleanup(cmd_info);
	if (cmd_info->ponam && endptr &&
	    (((moved_files = endptr->ar_next) != NULL) || new_listhead)) {
		if (!abifile) {
			(void) fprintf(stderr, MSG_INTL(MSG_NOT_FOUND_POSNAM),
			    cmd_info->ponam);
			exit(2);
		}
		endptr->ar_next = NULL;

		/*
		 * link new/moved files into archive entry list...
		 * 1: prepend newlist to moved/appended list
		 */
		if (new_listhead) {
			if (!moved_files)
				listend = new_listend;
			new_listend->ar_next = moved_files;
			moved_files = new_listhead;
		}
		/* 2: insert at appropriate position... */
		if (cmd_info->opt_flgs & b_FLAG)
			abifile = backptr;
		if (abifile) {
			listend->ar_next = abifile->ar_next;
			abifile->ar_next = moved_files;
		} else {
			listend->ar_next = listhead;
			listhead = moved_files;
		}
		listend = endptr;
	} else if (cmd_info->ponam && !abifile)
		(void) fprintf(stderr, MSG_INTL(MSG_NOT_FOUND_POSNAM),
		    cmd_info->ponam);
}

void
dcmd(Cmd_info *cmd_info)
{
	ARFILE	*fptr;
	ARFILE *backptr = NULL;

	for (fptr = getfile(cmd_info); fptr; fptr = getfile(cmd_info)) {
		if (match(fptr->ar_longname, cmd_info) != NULL) {
			/*
			 * NOTE:
			 *	Refer to "Incompatible Archive Header"
			 *	blocked comment at the beginning of this file.
			 */

			/*
			 * Deleted
			 */
			mesg('d', fptr->ar_longname, cmd_info);
			if (backptr == NULL) {
				listhead = NULL;
				listend = NULL;
			} else {
				backptr->ar_next = NULL;
				listend = backptr;
			}
			cmd_info->modified = 1;
		} else {
			/*
			 * Unchaged
			 */
			mesg('u', fptr->ar_longname, cmd_info);
			backptr = fptr;
		}
	}
}

void
xcmd(Cmd_info *cmd_info)
{
	int	f;
	ARFILE	*next;
	int	rawname = 0;
	long	f_len = 0;

	/*
	 * If -T is specified, get the maximum file name length.
	 */
	if (cmd_info->opt_flgs & T_FLAG) {
		f_len = pathconf(MSG_ORIG(MSG_STR_PERIOD), _PC_NAME_MAX);
		if (f_len == -1) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_PATHCONF),
			    strerror(err));
			exit(1);
		}
	}
	for (next = getfile(cmd_info); next; next = getfile(cmd_info)) {
		if ((next->ar_longname[0] == 0) && (next->ar_rawname[0] != 0))
			rawname = 1;
		if (cmd_info->namc == 0 ||
		    match(next->ar_longname, cmd_info) != NULL ||
		    match(next->ar_rawname, cmd_info) != NULL) {
			/*
			 * NOTE:
			 *	Refer to "Incompatible Archive Header"
			 *	blocked comment at the beginning of this file.
			 */
			f = create_extract(next, rawname, f_len, cmd_info);
			if (f >= 0) {
				if (rawname) {
					/*
					 * eXtracted
					 */
					mesg('x', next->ar_rawname, cmd_info);
					if (write(f, next->ar_contents,
					    (unsigned)next->ar_size) !=
					    next->ar_size) {
						int err = errno;
						(void) fprintf(stderr,
						    MSG_INTL(MSG_SYS_WRITE),
						    next->ar_rawname,
						    strerror(err));
						exit(1);
					}
				} else {
					/*
					 * eXtracted
					 */
					mesg('x', next->ar_longname, cmd_info);
					if (write(f, next->ar_contents,
					    (unsigned)next->ar_size) !=
					    next->ar_size) {
						int err = errno;
						(void) fprintf(stderr,
						    MSG_INTL(MSG_SYS_WRITE),
						    next->ar_longname,
						    strerror(err));
						exit(1);
					}
				}
				(void) close(f);
			} else
				exit(1);
		}
		rawname = 0;
	} /* for */
}

void
pcmd(Cmd_info *cmd_info)
{
	ARFILE	*next;

	for (next = getfile(cmd_info); next; next = getfile(cmd_info)) {
		if (cmd_info->namc == 0 ||
		    match(next->ar_longname, cmd_info) != NULL ||
		    match(next->ar_rawname, cmd_info) != NULL) {
			/*
			 * NOTE:
			 *	Refer to "Incompatible Archive Header"
			 *	blocked comment at the beginning of this file.
			 */
			if (cmd_info->opt_flgs & v_FLAG) {
				(void) fprintf(stdout,
				    MSG_ORIG(MSG_FMT_P_TITLE),
				    next->ar_longname);
				(void) fflush(stdout);
			}
			(void) fwrite(next->ar_contents, sizeof (char),
			    next->ar_size, stdout);
		}
	}
}

void
mcmd(Cmd_info *cmd_info)
{
	ARFILE	*fileptr;
	ARFILE	*abifile = NULL;
	ARFILE	*tmphead = NULL;
	ARFILE	*tmpend = NULL;
	ARFILE	*backptr1 = NULL;
	ARFILE	*backptr2 = NULL;

	for (fileptr = getfile(cmd_info);
	    fileptr; fileptr = getfile(cmd_info)) {
		if (match(fileptr->ar_longname, cmd_info) != NULL) {
			/*
			 * position Modified
			 */
			mesg('m', fileptr->ar_longname, cmd_info);
			if (tmphead)
				tmpend->ar_next = fileptr;
			else
				tmphead = fileptr;
			tmpend = fileptr;
			if (backptr1) {
				listend = backptr1;
				listend->ar_next = NULL;
			}
			else
				listhead = NULL;
			continue;
		}
		/*
		 * position Unchaged
		 */
		mesg('u', fileptr->ar_longname, cmd_info);
		backptr1 = fileptr;
		if (cmd_info->ponam && !abifile) {
			if (strcmp(fileptr->ar_longname, cmd_info->ponam) == 0)
				abifile = fileptr;
			else
				backptr2 = fileptr;
		}
	}

	if (!tmphead)
		return;

	if (!cmd_info->ponam)
		listend->ar_next = tmphead;
	else {
		if (!abifile) {
			(void) fprintf(stderr, MSG_INTL(MSG_NOT_FOUND_POSNAM),
			    cmd_info->ponam);
			exit(2);
		}
		if (cmd_info->opt_flgs & b_FLAG)
			abifile = backptr2;
		if (abifile) {
			tmpend->ar_next = abifile->ar_next;
			abifile->ar_next = tmphead;
		} else {
			tmphead->ar_next = listhead;
			listhead = tmphead;
		}
	}
	(cmd_info->modified)++;
}

void
tcmd(Cmd_info *cmd_info)
{
	ARFILE	*next;
	int	**mp;
	char   buf[DATESIZE];
	int m1[] = {1, S_IRUSR, 'r', '-'};
	int m2[] = {1, S_IWUSR, 'w', '-'};
	int m3[] = {2, S_ISUID, 's', S_IXUSR, 'x', '-'};
	int m4[] = {1, S_IRGRP, 'r', '-'};
	int m5[] = {1, S_IWGRP, 'w', '-'};
	int m6[] = {2, S_ISGID, 's', S_IXGRP, 'x', '-'};
	int m7[] = {1, S_IROTH, 'r', '-'};
	int m8[] = {1, S_IWOTH, 'w', '-'};
	int m9[] = {2, S_ISVTX, 't', S_IXOTH, 'x', '-'};
	int *m[10];

	m[0] = m1;
	m[1] = m2;
	m[2] = m3;
	m[3] = m4;
	m[4] = m5;
	m[5] = m6;
	m[6] = m7;
	m[7] = m8;
	m[8] = m9;
	m[9] = 0;

	for (next = getfile(cmd_info); next; next = getfile(cmd_info)) {
		if (cmd_info->namc == 0 ||
		    match(next->ar_longname, cmd_info) != NULL ||
		    match(next->ar_rawname, cmd_info) != NULL) {
			/*
			 * NOTE:
			 *	Refer to "Incompatible Archive Header"
			 *	blocked comment at the beginning of this file.
			 */
			if ((cmd_info->opt_flgs & (t_FLAG | v_FLAG)) ==
			    (t_FLAG | v_FLAG)) {
				for (mp = &m[0]; mp < &m[9]; )
					ar_select(*mp++, next->ar_mode);

				(void) fprintf(stdout, MSG_ORIG(MSG_FMT_T_IDSZ),
				    next->ar_uid, next->ar_gid,
				    EC_XWORD(next->ar_size));
				if ((strftime(buf,
				    DATESIZE, MSG_ORIG(MSG_FMT_T_DATE),
				    localtime(&(next->ar_date)))) == 0) {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_LOCALTIME));
					exit(1);
				}
				(void) fprintf(stdout,
				    MSG_ORIG(MSG_FMT_SPSTRSP), buf);
			}
			if (cmd_info->opt_flgs & t_FLAG) {
				if ((next->ar_longname[0] == 0) &&
				    (next->ar_rawname[0] != 0)) {
					(void) fprintf(stdout,
					    MSG_ORIG(MSG_FMT_STRNL),
					    trim(next->ar_rawname));
				} else {
					(void) fprintf(stdout,
					    MSG_ORIG(MSG_FMT_STRNL),
					    trim(next->ar_longname));
				}
			}
		}
	}
}

void
qcmd(Cmd_info *cmd_info)
{
	ARFILE *fptr;

	if (cmd_info->opt_flgs & (a_FLAG | b_FLAG)) {
		(void) fprintf(stderr, MSG_INTL(MSG_USAGE_Q_BAD_ARG));
		exit(1);
	}
	for (fptr = getfile(cmd_info); fptr; fptr = getfile(cmd_info))
		;
	cleanup(cmd_info);
}

/*
 * Supplementary functions
 */
static char *
match(char *file, Cmd_info *cmd_info)
{
	int i;

	for (i = 0; i < cmd_info->namc; i++) {
		if (cmd_info->namv[i] == 0)
			continue;
		if (strcmp(trim(cmd_info->namv[i]), file) == 0) {
			file = cmd_info->namv[i];
			cmd_info->namv[i] = 0;
			return (file);
		}
	}
	return (NULL);
}

/*
 * puts the file which was in the list in the linked list
 */
static void
cleanup(Cmd_info *cmd_info)
{
	int i;
	FILE	*f;
	ARFILE	*fileptr;
	struct stat stbuf;

	for (i = 0; i < cmd_info->namc; i++) {
		if (cmd_info->namv[i] == 0)
			continue;
		/*
		 * Appended
		 */
		mesg('a', cmd_info->namv[i], cmd_info);
		f = stats(cmd_info->namv[i], &stbuf);
		if (f == NULL) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
			    cmd_info->namv[i], strerror(err));
		} else {
			fileptr = newfile();
			/* if short name */
			(void) strncpy(fileptr->ar_name,
			    trim(cmd_info->namv[i]), SNAME);

			if ((fileptr->ar_longname =
			    malloc(strlen(trim(cmd_info->namv[i])) + 1)) ==
			    NULL) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_MALLOC),
				    strerror(err));
				exit(1);
			}

			(void) strcpy(fileptr->ar_longname,
			    trim(cmd_info->namv[i]));

			if ((fileptr->ar_pathname =
			    malloc(strlen(cmd_info->namv[i]) + 1)) == NULL) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_MALLOC),
				    strerror(err));
				exit(1);
			}

			(void) strcpy(fileptr->ar_pathname, cmd_info->namv[i]);

			movefil(fileptr, &stbuf);

			/* clear 'ar_flag' */
			fileptr->ar_flag &= ~F_ELFRAW;

			/*
			 * Defer reading contents until needed, and then use
			 * an in-kernel file-to-file transfer to avoid
			 * excessive in-process memory use.
			 */
			fileptr->ar_contents = NULL;

			(void) fclose(f);
			(cmd_info->modified)++;
			cmd_info->namv[i] = 0;
		}
	}
}

/*
 * insert the file 'file' into the temporary file
 */
static void
movefil(ARFILE *fileptr, struct stat *stbuf)
{
	fileptr->ar_size = stbuf->st_size;
	fileptr->ar_date = stbuf->st_mtime;
	fileptr->ar_mode = stbuf->st_mode;

	/*
	 * The format of an 'ar' file includes a 6 character
	 * decimal string to contain the uid.
	 *
	 * If the uid or gid is too big to fit, then set it to
	 * nobody (for want of a better value).  Clear the
	 * setuid/setgid bits in the mode to avoid setuid nobody
	 * or setgid nobody files unexpectedly coming into existence.
	 */
	if ((fileptr->ar_uid = stbuf->st_uid) > 999999) {
		fileptr->ar_uid = UID_NOBODY;
		if (S_ISREG(fileptr->ar_mode))
			fileptr->ar_mode &= ~S_ISUID;
	}
	if ((fileptr->ar_gid = stbuf->st_gid) > 999999) {
		fileptr->ar_gid = GID_NOBODY;
		if (S_ISREG(fileptr->ar_mode))
			fileptr->ar_mode &= ~S_ISGID;
	}
}

static FILE *
stats(char *file, struct stat *stbuf)
{
	FILE *f;

	f = fopen(file, MSG_ORIG(MSG_STR_LCR));
	if (f == NULL)
		return (f);
	if (stat(file, stbuf) < 0) {
		(void) fclose(f);
		return (NULL);
	}
	return (f);
}

/*
 * Used by xcmd()
 */
int
create_extract(ARFILE *a, int rawname, int f_len, Cmd_info *cmd_info)
{

	int f;
	char *f_name;
	char *dup = NULL;
	if (rawname)
		f_name = a->ar_rawname;
	else
		f_name = a->ar_longname;

	/*
	 * If -T is specified, check the file length.
	 */
	if (cmd_info->opt_flgs & T_FLAG) {
		int len;
		len = strlen(f_name);
		if (f_len <= len) {
			dup = malloc(f_len+1);
			if (dup == NULL) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_MALLOC),
				    strerror(err));
				exit(1);
			}
			(void) strncpy(dup, f_name, f_len);
		}
		f_name = dup;
	}

	/*
	 * Bug 4052067 - If a file to be extracted has the same
	 * filename as the archive, the archive gets overwritten
	 * which can lead to a corrupted archive or worse, a ufs
	 * deadlock because libelf has mmap'ed the archive!  We
	 * can't rely on strcmp() to test for this case because
	 * the archive could be prefixed with a partial or full
	 * path (and we could be using the rawname from the archive)
	 * This means we have to do the same thing we did for mv,
	 * which is to explicitly check if the file we would extract
	 * to is identical to the archive.  Because part of this
	 * test is essentially what the -C flag does, I've merged
	 * the code together.
	 */
	if (access(f_name, F_OK) != -1) {
		struct stat s1, s2;

		/*
		 * If -C is specified, this is an error anyway
		 */
		if (cmd_info->opt_flgs & C_FLAG) {
			(void) fprintf(stderr, MSG_INTL(MSG_OVERRIDE_WARN),
			    f_name);
			if (dup != NULL)
				free(dup);
			return (-1);
		}

		/*
		 * Okay, -C wasn't specified.  However, now we do
		 * the check to see if the archive would be overwritten
		 * by extracting this file.  stat() both objects and
		 * test to see if their identical.
		 */
		if ((stat(f_name, &s1) == 0) &&
		    (stat(cmd_info->arnam, &s2) == 0)) {

			if ((s1.st_dev == s2.st_dev) &&
			    (s1.st_ino == s2.st_ino)) {

				(void) fprintf(stderr,
				    MSG_INTL(MSG_OVERRIDE_WARN), f_name);
				if (dup != NULL)
					free(dup);
				return (-1);
			}
		}
	}

	/*
	 * Okay to create extraction file...
	 */
	f = creat(f_name, (mode_t)a->ar_mode & 0777);
	if (f < 0) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN), f_name,
		    strerror(err));
		/*
		 * Created
		 */
		mesg('c', f_name, cmd_info);
	}
	if (dup)
		free(dup);
	return (f);
}

static void
mesg(int c, char *file, Cmd_info *cmd_info)
{
#ifdef XPG4
	/*
	 * XPG4 does not have any message defined for
	 * 'c' operation.
	 * In fact, XPG only defines messages for
	 *	d, r, a and x at the present. (03/05/'96)
	 */
	if (c == 'c' || c == 'u' || c == 'm')
		return;
#endif
	/*
	 * If 'u' is passed, convert it to 'c'.
	 * 'u' makes more sense since the operation did not
	 * do anything, Unchanged, but 'c' has been used so
	 * I do no want to break the compatibility at this moment.
	 * (03/05/'96).
	 */
	if (c == 'u')
		c = 'c';
	if (cmd_info->opt_flgs & v_FLAG)
		if (c != 'c')
			(void) fprintf(stdout, MSG_ORIG(MSG_FMT_FILE), c, file);
}

static void
ar_select(int *pairp, unsigned long mode)
{
	int n, *ap;

	ap = pairp;
	n = *ap++;
	while (--n >= 0 && (mode & *ap++) == 0)
		ap++;
	(void) putchar(*ap);
}
