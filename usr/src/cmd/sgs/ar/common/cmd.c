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
/*
 *	Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Incompatible Archive Header
 *
 * The archive file member header used in SunOS 4.1 archive files and
 * Solaris archive files are incompatible. The header file is:
 * 	/usr/include/ar.h, struct ar_hdr.
 * The member ar_name[] in Solaris comforms with Standard and the
 * member name terminates with '/'. The SunOS's member does not terminate
 * with '/' character. A bug 4046054 was filed:
 * 	The ar command in Solaris 2.5.1 is incompatible with archives
 * 	created on 4.x.
 *
 * To handle archive files created in SunOS 4.1 system on Solaris, the
 * following changes were made:
 *
 * 	1. file.c/writefile()
 * 		Before writing each member files into the output
 * 		archive file, ar_name[] is checked. If it is NULL,
 * 		it means that the original archive header for this
 * 		member was incompatible with Solaris format.
 *
 * 		The original Solaris ar command ended up having
 * 		NULL name for the header. The change here uses the
 * 		ar_rawname, which is much closer to the original
 * 		name.
 *
 * 	2. cmd.c
 * 		For the p command, the code used to use only ar_longname
 * 		to seach the matching name. The member is set to NULL
 * 		if the archive member header was incompatible.
 * 		The ar_rawname is also used to find the matching member name.
 *
 * 		For commands to update the archive file, we do not
 * 		use ar_rawname, and just use the ar_longname. The commands are
 * 		r (replace), m (modify the position) and d (delete).
 */

#include "inc.h"
#include "extern.h"

/*
 * Function prototypes
 */
static char *match(char *, Cmd_info *);

static void cleanup(Cmd_info *);
static void movefil(ARFILE *, struct stat *);
static void mesg(int, char *, Cmd_info *);
static void ar_select(int *, unsigned long);

static FILE *stats(char *, struct stat *);

static int create_extract(ARFILE *, int, int, Cmd_info *);

/*
 * Commands
 */
int
rcmd(Cmd_info *cmd_info)
{
	FILE *f;
	ARFILE *fileptr;
	ARFILE	*abifile = NULL;
	ARFILE	*backptr = NULL;
	ARFILE	*endptr;
	ARFILE	*moved_files;
	ARFILE  *prev_entry, *new_listhead, *new_listend;
	int	deleted;
	struct stat stbuf;
	char *gfile;

	new_listhead  = NULL;
	new_listend   = NULL;
	prev_entry    = NULL;

	for (fileptr = getfile(cmd_info);
	    fileptr; fileptr = getfile(cmd_info)) {
		deleted = 0;
		if (!abifile && cmd_info-> ponam &&
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
				if (cmd_info->namc)
					error_message(SYS_OPEN_ERROR,
					    SYSTEM_ERROR, strerror(errno),
					    gfile);
				/*
				 * Created
				 */
				mesg('c', gfile, cmd_info);
			} else {
				if (opt_FLAG(cmd_info, u_FLAG) &&
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
				if (fileptr->ar_flag & F_MALLOCED)
					free(fileptr->ar_contents);
				else if (fileptr->ar_flag & F_ELFRAW) {
					/*
					 * clear ar_elf
					 */
					(void) elf_end(fileptr->ar_elf);
					fileptr->ar_elf = 0;
				}
				/* clear 'ar_flag' */
				fileptr->ar_flag &=
				    ~(F_ELFRAW | F_MMAPED | F_MALLOCED);
				if ((cmd_info->OPT_flgs & M_FLAG) == 0) {
					if ((cmd_info->bytes_in_mem +
					    stbuf.st_size)
					    < AR_MAX_BYTES_IN_MEM) {
						if ((fileptr->ar_contents =
						    malloc(ROUNDUP(
						    stbuf.st_size))) == NULL) {
							error_message(
							    MALLOC_ERROR,
							    PLAIN_ERROR,
							    (char *)0);
							exit(1);
						}
						fileptr->ar_flag &=
						    ~(F_ELFRAW | F_MMAPED);
						fileptr->ar_flag |= F_MALLOCED;
						if (fread(fileptr->ar_contents,
						    sizeof (char),
						    stbuf.st_size, f) !=
						    stbuf.st_size) {
							error_message(
							    SYS_READ_ERROR,
							    SYSTEM_ERROR,
							    strerror(errno),
							    fileptr->
							    ar_longname);
							exit(1);
						}
						cmd_info->bytes_in_mem +=
						    stbuf.st_size;
					}
				} else {
					if ((fileptr->ar_contents = (char *)
					    mmap(0, stbuf.st_size,
					    PROT_READ,
					    MAP_SHARED,
					    fileno(f), 0)) == (char *)-1) {
						error_message(MALLOC_ERROR,
						    PLAIN_ERROR, (char *)0);
						exit(1);
					}
					fileptr->ar_flag &=
					    ~(F_ELFRAW | F_MALLOCED);
					fileptr->ar_flag |= F_MMAPED;
				}
				if (fileptr->ar_pathname != NULL)
					free(fileptr->ar_pathname);
				if ((fileptr->ar_pathname =
				    malloc(strlen(gfile) + 1)) == NULL) {
					error_message(MALLOC_ERROR,
					    PLAIN_ERROR, (char *)0);
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
			error_message(NOT_FOUND_02_ERROR,
			    PLAIN_ERROR, (char *)0, cmd_info->ponam);
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
		if (opt_FLAG(cmd_info, b_FLAG))
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
		error_message(NOT_FOUND_02_ERROR,
		    PLAIN_ERROR, (char *)0, cmd_info->ponam);
	return (0);
}

int
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
	return (0);
}

int
xcmd(Cmd_info *cmd_info)
{
	int f;
	ARFILE *next;
	int rawname = 0;
	int f_len = 0;

	/*
	 * If -T is specified, get the maximum file name length.
	 */
	if (cmd_info->OPT_flgs & T_FLAG) {
		f_len = pathconf(".", _PC_NAME_MAX);
		if (f_len == -1) {
			error_message(PATHCONF_ERROR,
			    SYSTEM_ERROR, strerror(errno));
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
						error_message(SYS_WRITE_ERROR,
						    SYSTEM_ERROR,
						    strerror(errno),
						    next->ar_rawname);
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
						error_message(SYS_WRITE_ERROR,
						    SYSTEM_ERROR,
						    strerror(errno),
						    next->ar_longname);
						exit(1);
					}
				}
				(void) close(f);
			} else
				exit(1);
		}
		rawname = 0;
	} /* for */
	return (0);
}

int
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
			if (opt_FLAG(cmd_info, v_FLAG)) {
				(void) fprintf(stdout,
				    "\n<%s>\n\n", next->ar_longname);
				(void) fflush(stdout);
			}
			(void) fwrite(next->ar_contents, sizeof (char),
			    next->ar_size, stdout);
		}
	}
	return (0);
}

int
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
		return (1);

	if (!cmd_info->ponam)
		listend->ar_next = tmphead;
	else {
		if (!abifile) {
			error_message(NOT_FOUND_02_ERROR,
			    PLAIN_ERROR, (char *)0, cmd_info->ponam);
			exit(2);
		}
		if (opt_FLAG(cmd_info, b_FLAG))
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
	return (0);
}

int
tcmd(Cmd_info *cmd_info)
{
	ARFILE	*next;
	int	**mp;
	char   buf[DATESIZE];
	int m1[] = {1, ROWN, 'r', '-'};
	int m2[] = {1, WOWN, 'w', '-'};
	int m3[] = {2, SUID, 's', XOWN, 'x', '-'};
	int m4[] = {1, RGRP, 'r', '-'};
	int m5[] = {1, WGRP, 'w', '-'};
	int m6[] = {2, SGID, 's', XGRP, 'x', '-'};
	int m7[] = {1, ROTH, 'r', '-'};
	int m8[] = {1, WOTH, 'w', '-'};
	int m9[] = {2, STXT, 't', XOTH, 'x', '-'};
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
			if (opt_FLAG(cmd_info, v_FLAG)) {
				for (mp = &m[0]; mp < &m[9]; )
					ar_select(*mp++, next->ar_mode);

				(void) fprintf(stdout, "%6d/%6d", next->ar_uid,
				    next->ar_gid);
				(void) fprintf(stdout, "%7ld", next->ar_size);
				if ((strftime(buf,
				    DATESIZE,
				    "%b %e %H:%M %Y",
				    localtime(&(next->ar_date)))) == 0) {
					error_message(LOCALTIME_ERROR,
					    PLAIN_ERROR, (char *)0);
					exit(1);
				}
				(void) fprintf(stdout, " %s ", buf);
			}
			if ((next->ar_longname[0] == 0) &&
			    (next->ar_rawname[0] != 0))
				(void) fprintf(stdout,
				    "%s\n", trim(next->ar_rawname));
			else
				(void) fprintf(stdout,
				    "%s\n", trim(next->ar_longname));
		}
	} /* for */
	return (0);
}

int
qcmd(Cmd_info *cmd_info)
{
	ARFILE *fptr;

	if (opt_FLAG(cmd_info, a_FLAG) || opt_FLAG(cmd_info, b_FLAG)) {
		error_message(USAGE_05_ERROR,
		    PLAIN_ERROR, (char *)0);
		exit(1);
	}
	for (fptr = getfile(cmd_info); fptr; fptr = getfile(cmd_info))
		;
	cleanup(cmd_info);
	return (0);
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
		if (f == NULL)
			error_message(SYS_OPEN_ERROR,
			    SYSTEM_ERROR, strerror(errno), cmd_info->namv[i]);
		else {
			fileptr = newfile();
			/* if short name */
			(void) strncpy(fileptr->ar_name,
			    trim(cmd_info->namv[i]), SNAME);

			if ((fileptr->ar_longname =
			    malloc(strlen(trim(cmd_info->namv[i])) + 1)) ==
			    NULL) {
				error_message(MALLOC_ERROR,
				    PLAIN_ERROR, (char *)0);
				exit(1);
			}

			(void) strcpy(fileptr->ar_longname,
			    trim(cmd_info->namv[i]));

			if ((fileptr->ar_pathname =
			    malloc(strlen(cmd_info->namv[i]) + 1)) == NULL) {
				error_message(MALLOC_ERROR,
				    PLAIN_ERROR, (char *)0);
				exit(1);
			}

			(void) strcpy(fileptr->ar_pathname, cmd_info->namv[i]);

			movefil(fileptr, &stbuf);

			/* clear 'ar_flag' */
			fileptr->ar_flag &= ~(F_ELFRAW | F_MMAPED | F_MALLOCED);

			if ((cmd_info->OPT_flgs & M_FLAG) == 0) {
				if ((cmd_info->bytes_in_mem + stbuf.st_size) <
				    AR_MAX_BYTES_IN_MEM) {
					fileptr->ar_flag &=
					    ~(F_ELFRAW | F_MMAPED);
					fileptr->ar_flag |= F_MALLOCED;
					if ((fileptr->ar_contents =
					    malloc(ROUNDUP(stbuf.st_size))) ==
					    NULL) {
						error_message(MALLOC_ERROR,
						    PLAIN_ERROR, (char *)0);
						exit(1);
					}
					if (fread(fileptr->ar_contents,
					    sizeof (char), stbuf.st_size,
					    f) != stbuf.st_size) {
						error_message(SYS_READ_ERROR,
						    SYSTEM_ERROR,
						    strerror(errno),
						    fileptr->ar_longname);
						exit(1);
					}
					cmd_info->bytes_in_mem += stbuf.st_size;
				}
			} else {
				fileptr->ar_flag &= ~(F_ELFRAW | F_MALLOCED);
				fileptr->ar_flag |= F_MMAPED;
				if ((fileptr->ar_contents =
				    (char *)mmap(0, stbuf.st_size, PROT_READ,
				    MAP_SHARED, fileno(f), 0)) == (char *)-1) {
					error_message(MALLOC_ERROR,
					    PLAIN_ERROR, (char *)0);
					exit(1);
				}
			}
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

	f = fopen(file, "r");
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
	if (cmd_info->OPT_flgs & T_FLAG) {
		int len;
		len = strlen(f_name);
		if (f_len <= len) {
			dup = malloc(f_len+1);
			if (dup == NULL) {
				error_message(MALLOC_ERROR,
				    PLAIN_ERROR, (char *)0);
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
		if (cmd_info->OPT_flgs & C_FLAG) {
			if (dup != NULL)
				free(dup);
			error_message(OVERRIDE_WARN_ERROR,
			    PLAIN_ERROR, (char *)0, f_name);
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

				if (dup != NULL)
					free(dup);
				error_message(OVERRIDE_WARN_ERROR,
				    PLAIN_ERROR, (char *)0, f_name);
				return (-1);
			}
		}
	}

	/*
	 * Okay to create extraction file...
	 */
	f = creat(f_name, (mode_t)a->ar_mode & 0777);
	if (f < 0) {
		error_message(SYS_CREATE_01_ERROR,
		    SYSTEM_ERROR, strerror(errno), f_name);
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
	if (opt_FLAG(cmd_info, v_FLAG))
		if (c != 'c')
			(void) fprintf(stdout, "%c - %s\n", c, file);
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
