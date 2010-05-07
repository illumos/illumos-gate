/*
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/****************************************************************************  
 
  Copyright (c) 1999,2000 WU-FTPD Development Group.  
  All rights reserved.
  
  Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994
    The Regents of the University of California.
  Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.
  Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.
  Portions Copyright (c) 1989 Massachusetts Institute of Technology.
  Portions Copyright (c) 1998 Sendmail, Inc.
  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.
  Portions Copyright (c) 1997 by Stan Barber.
  Portions Copyright (c) 1997 by Kent Landfield.
  Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997
    Free Software Foundation, Inc.  
 
  Use and distribution of this software and its source code are governed 
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").
 
  If you did not receive a copy of the license, it may be obtained online
  at http://www.wu-ftpd.org/license.html.
 
  $Id: extensions.c,v 1.48 2000/07/01 18:17:38 wuftpd Exp $
 
****************************************************************************/
#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif

#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#include <sys/time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif
#include <pwd.h>
#include <setjmp.h>
#include <grp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>

#ifdef HAVE_SYS_FS_UFS_QUOTA_H
#include <sys/fs/ufs_quota.h>
#elif defined(HAVE_UFS_UFS_QUOTA_H)
#include <ufs/ufs/quota.h>
#elif defined(HAVE_UFS_QUOTA_H)
#include <ufs/quota.h>
#elif defined(HAVE_SYS_MNTENT_H)
#include <sys/mntent.h>
#elif defined(HAVE_SYS_MNTTAB_H)
#include <sys/mnttab.h>
#endif

#if defined(HAVE_STATVFS)
#include <sys/statvfs.h>
#elif defined(HAVE_SYS_VFS)
#include <sys/vfs.h>
#elif defined(HAVE_SYS_MOUNT)
#include <sys/mount.h>
#endif

#include <arpa/ftp.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include "pathnames.h"
#include "extensions.h"
#include "wu_fnmatch.h"
#include "proto.h"

#if defined(HAVE_FTW)
#include <ftw.h>
#else
#include "support/ftw.h"
#endif

#ifdef QUOTA
struct dqblk quota;
char *time_quota(long curstate, long softlimit, long timelimit, char *timeleft);
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#if defined(HAVE_REGEX) && defined(SVR4) && ! (defined(NO_LIBGEN))
#include <libgen.h>
#endif

extern int type, transflag, ftwflag, authenticated, autospout_free, data,
    pdata, anonymous, guest;
extern char chroot_path[], guestpw[];

#ifdef TRANSFER_COUNT
extern off_t data_count_in;
extern off_t data_count_out;
#ifdef TRANSFER_LIMIT  
extern off_t data_limit_raw_in;
extern off_t data_limit_raw_out;
extern off_t data_limit_raw_total;
extern off_t data_limit_data_in;  
extern off_t data_limit_data_out; 
extern off_t data_limit_data_total;
#ifdef RATIO /* 1998/08/06 K.Wakui */
#define TRUNC_KB(n)   ((n)/1024+(((n)%1024)?1:0))
extern time_t	login_time;
extern time_t	limit_time;
extern off_t    total_free_dl;
extern int      upload_download_rate;
#endif /* RATIO */
#endif
#endif

#ifdef OTHER_PASSWD
#include "getpwnam.h"
extern char _path_passwd[];
#endif

#ifdef LOG_FAILED
extern char the_user[];
#endif

extern char *globerr, remotehost[];
#ifdef THROUGHPUT
extern char remoteaddr[];
#endif

#ifndef HAVE_REGEX
char *re_comp(const char *regex);
int re_exec(const char *p1);
#endif

char shuttime[30], denytime[30], disctime[30];

FILE *dout;

time_t newer_time;

int show_fullinfo;

/* This always was a bug, because neither st_size nor time_t were required to
   be compatible with int, but needs fixing properly for C9X. */

/* Some systems use one format, some another.  This takes care of the garbage */
/* Do the system specific stuff only if we aren't autoconfed */
#if !defined(L_FORMAT)
#if (defined(BSD) && (BSD >= 199103)) && !defined(LONGOFF_T)
#define L_FORMAT "qd"
#else
#define L_FORMAT "d"
#endif
#endif
#if !defined(T_FORMAT)
#define T_FORMAT "d"
#endif
#if !defined(PW_UID_FORMAT)
#define PW_UID_FORMAT "d"
#endif
#if !defined(GR_GID_FORMAT)
#define GR_GID_FORMAT "d"
#endif

int snprintf(char *str, size_t count, const char *fmt,...);

#ifdef SITE_NEWER
int check_newer(const char *path, const struct stat *st, int flag)
{
    if (st->st_mtime > newer_time) {
	if (show_fullinfo != 0) {
	    if (flag == FTW_F || flag == FTW_D) {
		fprintf(dout, "%s %" L_FORMAT " %" T_FORMAT " %s\n",
			flag == FTW_F ? "F" : "D",
			st->st_size, st->st_mtime, path);
	    }
	}
	else if (flag == FTW_F)
	    fprintf(dout, "%s\n", path);
    }

    /* When an ABOR has been received (which sets ftwflag > 1) return a
     * non-zero value which causes ftw to stop tree traversal and return. 
     */

    return (ftwflag > 1 ? 1 : 0);
}
#endif

#if defined(HAVE_STATVFS)
long getSize(char *s)
{
    struct statvfs buf;

    if (statvfs(s, &buf) != 0)
	return (0);

    return (buf.f_bavail * buf.f_frsize / 1024);
}
#elif defined(HAVE_SYS_VFS) || defined (HAVE_SYS_MOUNT)
long getSize(char *s)
{
    struct statfs buf;

    if (statfs(s, &buf) != 0)
	return (0);

    return (buf.f_bavail * buf.f_bsize / 1024);
}
#endif

/*************************************************************************/
/* FUNCTION  : msg_massage                                               */
/* PURPOSE   : Scan a message line for magic cookies, replacing them as  */
/*             needed.                                                   */
/* ARGUMENTS : pointer input and output buffers                          */
/*************************************************************************/

void msg_massage(const char *inbuf, char *outbuf, size_t outlen)
{
    const char *inptr = inbuf;
    char *outptr = outbuf;
#ifdef QUOTA
    char timeleft[80];
#endif
    char buffer[MAXPATHLEN];
    time_t curtime;
    int limit;
#ifndef LOG_FAILED
    extern struct passwd *pw;
#endif
    struct aclmember *entry;

#ifdef VIRTUAL
    extern int virtual_mode;
    extern int virtual_ftpaccess;
    extern char virtual_email[];
#endif
    extern char hostname[];
    extern char authuser[];

    (void) acl_getclass(buffer);
    limit = acl_getlimit(buffer, NULL);

    while ((outlen > 1) && (*inptr != '\0')) {
	if (*inptr != '%') {
	    *outptr++ = *inptr;
	    outlen -= 1;
	}
	else {
	    entry = NULL;
	    switch (*++inptr) {
	    case 'E':
#ifdef VIRTUAL
		if (virtual_mode && !virtual_ftpaccess && virtual_email[0] != '\0')
		    snprintf(outptr, outlen, "%s", virtual_email);
		else
#endif
		if ((getaclentry("email", &entry)) && ARG0)
		    snprintf(outptr, outlen, "%s", ARG0);
		else
		    *outptr = '\0';
		break;

	    case 'N':
		snprintf(outptr, outlen, "%d", acl_countusers(buffer));
		break;

	    case 'M':
		if (limit == -1)
		    strncpy(outptr, "unlimited", outlen);
		else
		    snprintf(outptr, outlen, "%d", limit);
		break;

	    case 'T':
		(void) time(&curtime);
		strncpy(outptr, ctime(&curtime), outlen);
		if (outlen > 24)
		    *(outptr + 24) = '\0';
		break;

	    case 'F':
#if defined(HAVE_STATVFS) || defined(HAVE_SYS_VFS) || defined(HAVE_SYS_MOUNT)
		snprintf(outptr, outlen, "%lu", (long) getSize("."));
#else
		*outptr = '\0';
#endif
		break;

	    case 'C':
#ifdef HAVE_GETCWD
		(void) getcwd(outptr, outlen);
#else
#error	wu-ftpd on this platform has security deficiencies!!!
		(void) getwd(outptr);
#endif
		break;

	    case 'R':
		strncpy(outptr, remotehost, outlen);
		break;

	    case 'L':
		strncpy(outptr, hostname, outlen);
		break;

	    case 'U':
		if (xferdone && anonymous)
		    strncpy(outptr, guestpw, outlen);
		else
#ifdef LOG_FAILED
		    strncpy(outptr, the_user, outlen);
#else /* LOG_FAILED */
		    strncpy(outptr,
			    (pw == NULL) ? "[unknown]" : pw->pw_name, outlen);
#endif /* LOG_FAILED */
		break;

	    case 's':
		strncpy(outptr, shuttime, outlen);
		if (outlen > 24)
		    *(outptr + 24) = '\0';
		break;

	    case 'd':
		strncpy(outptr, disctime, outlen);
		if (outlen > 24)
		    *(outptr + 24) = '\0';
		break;

	    case 'r':
		strncpy(outptr, denytime, outlen);
		if (outlen > 24)
		    *(outptr + 24) = '\0';
		break;

/* KH : cookie %u for RFC931 name */
	    case 'u':
		if (authenticated)
		    strncpy(outptr, authuser, outlen);
		else {
		    if (xferdone)
			snprintf(outptr, outlen, "%c", '*');
		    else
			strncpy(outptr, "[unknown]", outlen);
		}
		break;

#ifdef QUOTA
	    case 'B':
#ifdef QUOTA_BLOCKS		/* 1024-blocks instead of 512-blocks */
		snprintf(outptr, outlen, "%ld", quota.dqb_bhardlimit % 2 ?
			 (long) (quota.dqb_bhardlimit / 2 + 1) : (long) (quota.dqb_bhardlimit / 2));
#else
		snprintf(outptr, outlen, "%ld", (long) quota.dqb_bhardlimit);
#endif
		break;

	    case 'b':
#ifdef QUOTA_BLOCKS		/* 1024-blocks instead of 512-blocks */
		snprintf(outptr, outlen, "%ld", quota.dqb_bsoftlimit % 2 ?
			 (long) (quota.dqb_bsoftlimit / 2 + 1) : (long) (quota.dqb_bsoftlimit / 2));
#else
		snprintf(outptr, outlen, "%ld", (long) quota.dqb_bsoftlimit);
#endif
		break;

	    case 'Q':
#ifdef QUOTA_BLOCKS		/* 1024-blocks instead of 512-blocks */
		snprintf(outptr, outlen, "%ld", quota.dqb_curblocks % 2 ?
			 (long) (quota.dqb_curblocks / 2 + 1) : (long) (quota.dqb_curblocks / 2));
#else
		snprintf(outptr, outlen, "%ld", quota.dqb_curblocks);
#endif
		break;

	    case 'I':
#if defined(QUOTA_INODE)
		snprintf(outptr, outlen, "%d", quota.dqb_ihardlimit);
#else
		snprintf(outptr, outlen, "%ld", (long) quota.dqb_fhardlimit);
#endif
		break;

	    case 'i':
#if defined(QUOTA_INODE)
		snprintf(outptr, outlen, "%d", quota.dqb_isoftlimit);
#else
		snprintf(outptr, outlen, "%ld", (long) quota.dqb_fsoftlimit);
#endif
		break;

	    case 'q':
#if defined(QUOTA_INODE)
		snprintf(outptr, outlen, "%d", quota.dqb_curinodes);
#else
		snprintf(outptr, outlen, "%ld", (long) quota.dqb_curfiles);
#endif
		break;

	    case 'H':
		time_quota(quota.dqb_curblocks, quota.dqb_bsoftlimit,
#if defined(QUOTA_INODE)
			   quota.dqb_btime, timeleft);
#else
			   quota.dqb_btimelimit, timeleft);
#endif
		strncpy(outptr, timeleft, outlen);
		break;

	    case 'h':
#if defined(QUOTA_INODE)
		time_quota(quota.dqb_curinodes, quota.dqb_isoftlimit,
			   quota.dqb_itime, timeleft);
#else
		time_quota(quota.dqb_curfiles, quota.dqb_fsoftlimit,
			   quota.dqb_ftimelimit, timeleft);
#endif
		strncpy(outptr, timeleft, outlen);
		break;
#endif /* QUOTA */

	    case '%':
		*outptr++ = '%';
		outlen -= 1;
		*outptr = '\0';
		break;

#ifdef TRANSFER_COUNT
#ifdef TRANSFER_LIMIT
#ifdef RATIO
            case 'x':
                switch (*++inptr) {
                case 'u':       /* upload bytes */
                    sprintf(outptr,"%" L_FORMAT, TRUNC_KB(data_count_in) );
                    break;
                case 'd':       /* download bytes */
                    sprintf(outptr,"%" L_FORMAT, TRUNC_KB(data_count_out) );
                    break;
                case 'R':       /* rate 1:n */
                    if( upload_download_rate > 0 ) {
                        sprintf(outptr,"%d", upload_download_rate );
                    }
                    else {
                        strcpy(outptr,"free");
                    }
                    break;
                case 'c':       /* credit bytes */
                    if( upload_download_rate > 0 ) {
                        off_t credit=( data_count_in * upload_download_rate) - (data_count_out - total_free_dl);
                        sprintf(outptr,"%" L_FORMAT, TRUNC_KB(credit) );
                    }
                    else {
                        strcpy(outptr,"unlimited");
                    }
                    break;
                case 'T':       /* time limit (minutes) */
                    if( limit_time > 0 ) {
                        sprintf(outptr,"%d", limit_time );
                    }
                    else {
                        strcpy(outptr,"unlimited");
                    }
                    break;
                case 'E':       /* elapsed time from loggedin (minutes) */
                    sprintf(outptr,"%d", (time(NULL)-login_time)/60 );
                    break;
                case 'L':       /* times left until force logout (minutes) */
                    if( limit_time > 0 ) {
                        sprintf(outptr,"%d", limit_time-(time(NULL)-login_time)/60 );
                    }
                    else {
                        strcpy(outptr,"unlimited");
                    }
                    break;
                case 'U':       /* upload limit */
		    if( data_limit_raw_in > 0 ) {
			sprintf(outptr,"%" L_FORMAT, TRUNC_KB(data_limit_raw_in));
		    }
		    else if( data_limit_data_in > 0 ) {
			sprintf(outptr,"%" L_FORMAT, TRUNC_KB(data_limit_data_in));
		    }
		    else if( data_limit_raw_total > 0 ) {
			sprintf(outptr,"%" L_FORMAT, TRUNC_KB(data_limit_raw_total));
		    }
		    else if( data_limit_data_total > 0 ) {
			sprintf(outptr,"%" L_FORMAT, TRUNC_KB(data_limit_data_total));
		    }
		    else {
			strcpy(outptr, "unlimited");
		    }
                    break;
                case 'D':       /* download limit */
		    if( data_limit_raw_out > 0 ) {
			sprintf(outptr,"%" L_FORMAT, TRUNC_KB(data_limit_raw_out));
		    }
		    else if( data_limit_data_out > 0 ) {
			sprintf(outptr,"%" L_FORMAT, TRUNC_KB(data_limit_data_out));
		    }
		    else if( data_limit_raw_total > 0 ) {
			sprintf(outptr,"%" L_FORMAT, TRUNC_KB(data_limit_raw_total));
		    }
		    else if( data_limit_data_total > 0 ) {
			sprintf(outptr,"%" L_FORMAT, TRUNC_KB(data_limit_data_total));
		    }
		    else {
			strcpy(outptr, "unlimited");
		    }
                    break;
                default:
                    strcpy(outptr,"%??");
                    break;
                }
                break;
#endif /* RATIO */
#endif
#endif
		/* File transfer logging (xferlog) */
		case 'X':
		    if (xferdone) {  /* only if a transfer has just occurred */
			switch (*++inptr) {
			case 't':
			    snprintf(outptr, outlen, "%d", xfervalues.transfer_time);
			    break;
			case 's':
			    snprintf(outptr, outlen, "%" L_FORMAT, xfervalues.filesize);
			    break;
			case 'n':
			    snprintf(outptr, outlen, "%" L_FORMAT, xfervalues.transfer_bytes);
			    break;
			case 'P': /* absolute pathname */
			    /* FALLTHROUGH */
			case 'p': /* chroot-relative pathname */
			{
			    char namebuf[MAXPATHLEN];
			    int loop;

			    if (*inptr == 'P')
				wu_realpath(xfervalues.filename, namebuf, chroot_path);
			    else
				fb_realpath(xfervalues.filename, namebuf);
			    for (loop = 0; namebuf[loop]; loop++) {
				if (isspace(namebuf[loop]) || iscntrl(namebuf[loop]))
				    namebuf[loop] = '_';
			    }
			    snprintf(outptr, outlen, "%s", namebuf);
			    break;
			}
			case 'y':
			    snprintf(outptr, outlen, "%c", xfervalues.transfer_type);
			    break;
			case 'f':
			    snprintf(outptr, outlen, "%s", xfervalues.special_action);
			    break;
			case 'd':
			    snprintf(outptr, outlen, "%c", xfervalues.transfer_direction);
			    break;
			case 'm':
			    snprintf(outptr, outlen, "%c", xfervalues.access_mode);
			    break;
			case 'a':
			    snprintf(outptr, outlen, "%d", xfervalues.auth);
			    break;
			case 'r':
			    snprintf(outptr, outlen, "%" L_FORMAT, xfervalues.restart_offset);
			    break;
			case 'c':
			    snprintf(outptr, outlen, "%c", xfervalues.completion);
			    break;
			default:
			    snprintf(outptr, outlen, "%%X%c", *inptr);
			    break;
			}
		    }
		    else
			snprintf(outptr, outlen, "%%%c", *inptr);
		    break;

	    default:
		*outptr++ = '%';
		outlen -= 1;
		if (outlen > 1) {
		    *outptr++ = *inptr;
		    outlen -= 1;
		}
		*outptr = '\0';
		break;
	    }
	    outptr[outlen - 1] = '\0';
	    while (*outptr) {
		outptr++;
		outlen -= 1;
	    }
	}
	inptr++;
    }
    if (outlen > 0)
	*outptr = '\0';
}

/*************************************************************************/
/* FUNCTION  : cwd_beenhere                                              */
/* PURPOSE   : Return 1 if the user has already visited this directory   */
/*             via C_WD.                                                 */
/* ARGUMENTS : a power-of-two directory function code (README, MESSAGE)  */
/*************************************************************************/

int cwd_beenhere(int dircode)
{
    struct dirlist {
	struct dirlist *next;
	int dircode;
	char dirname[1];
    };

    static struct dirlist *head = NULL;
    struct dirlist *curptr;
    char cwd[MAXPATHLEN];

    (void) fb_realpath(".", cwd);

    for (curptr = head; curptr != NULL; curptr = curptr->next)
	if (strcmp(curptr->dirname, cwd) == 0) {
	    if (!(curptr->dircode & dircode)) {
		curptr->dircode |= dircode;
		return (0);
	    }
	    return (1);
	}
    curptr = (struct dirlist *) malloc(strlen(cwd) + 1 + sizeof(struct dirlist));

    if (curptr != NULL) {
	curptr->next = head;
	head = curptr;
	curptr->dircode = dircode;
	strcpy(curptr->dirname, cwd);
    }
    return (0);
}

/*************************************************************************/
/* FUNCTION  : show_banner                                               */
/* PURPOSE   : Display a banner on the user's terminal before login      */
/* ARGUMENTS : reply code to use                                         */
/*************************************************************************/

void show_banner(int msgcode)
{
    char *crptr, linebuf[1024], outbuf[1024];
    struct aclmember *entry = NULL;
    FILE *infile;

#ifdef VIRTUAL
    extern int virtual_mode;
    extern int virtual_ftpaccess;
    extern char virtual_banner[];

    if (virtual_mode && !virtual_ftpaccess) {
	infile = fopen(virtual_banner, "r");
	if (infile) {
	    while (fgets(linebuf, sizeof(linebuf), infile) != NULL) {
		if ((crptr = strchr(linebuf, '\n')) != NULL)
		    *crptr = '\0';
		msg_massage(linebuf, outbuf, sizeof(outbuf));
		lreply(msgcode, "%s", outbuf);
	    }
	    fclose(infile);
#ifndef NO_SUCKING_NEWLINES
	    lreply(msgcode, "");
#endif
	}
    }
    else {
#endif
	/* banner <path> */
	while (getaclentry("banner", &entry)) {
	    if (!ARG0)
		continue;
	    infile = fopen(ARG0, "r");
	    if (infile) {
		while (fgets(linebuf, sizeof(linebuf), infile) != NULL) {
		    if ((crptr = strchr(linebuf, '\n')) != NULL)
			*crptr = '\0';
		    msg_massage(linebuf, outbuf, sizeof(outbuf));
		    lreply(msgcode, "%s", outbuf);
		}
		fclose(infile);
#ifndef NO_SUCKING_NEWLINES
		lreply(msgcode, "");
#endif
	    }
	}
#ifdef VIRTUAL
    }
#endif
}
/*************************************************************************/
/* FUNCTION  : show_message                                              */
/* PURPOSE   : Display a message on the user's terminal if the current   */
/*             conditions are right                                      */
/* ARGUMENTS : reply code to use, LOG_IN|CMD                             */
/*************************************************************************/

void show_message(int msgcode, int mode)
{
    char *crptr, linebuf[1024], outbuf[1024], class[MAXPATHLEN], cwd[MAXPATHLEN];
    int show, which;
    struct aclmember *entry = NULL;
    FILE *infile;

    if (mode == C_WD && cwd_beenhere(1) != 0)
	return;

#ifdef HAVE_GETCWD
    (void) getcwd(cwd, MAXPATHLEN - 1);
#else
    (void) getwd(cwd);
#endif
    (void) acl_getclass(class);

    /* message <path> [<when> [<class>]] */
    while (getaclentry("message", &entry)) {
	if (!ARG0)
	    continue;
	show = 0;

	if (mode == LOG_IN && (!ARG1 || !strcasecmp(ARG1, "login")))
	    if (!ARG2)
		show++;
	    else {
		for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		    if (strcasecmp(class, ARG[which]) == 0)
			show++;
	    }
	if (mode == C_WD && ARG1 && !strncasecmp(ARG1, "cwd=", 4) &&
	    (!strcmp((ARG1) + 4, cwd) || *(ARG1 + 4) == '*' ||
	     !wu_fnmatch((ARG1) + 4, cwd, FNM_PATHNAME)))
	    if (!ARG2)
		show++;
	    else {
		for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		    if (strcasecmp(class, ARG[which]) == 0)
			show++;
	    }
	if (show && (int) strlen(ARG0) > 0) {
	    infile = fopen(ARG0, "r");
	    if (infile) {
		while (fgets(linebuf, sizeof(linebuf), infile) != NULL) {
		    if ((crptr = strchr(linebuf, '\n')) != NULL)
			*crptr = '\0';
		    msg_massage(linebuf, outbuf, sizeof(outbuf));
		    lreply(msgcode, "%s", outbuf);
		}
		fclose(infile);
#ifndef NO_SUCKING_NEWLINES
		lreply(msgcode, "");
#endif
	    }
	}
    }
}

/*************************************************************************/
/* FUNCTION  : show_readme                                               */
/* PURPOSE   : Display a message about a README file to the user if the  */
/*             current conditions are right                              */
/* ARGUMENTS : pointer to ACL buffer, reply code, LOG_IN|C_WD            */
/*************************************************************************/

void show_readme(int code, int mode)
{
    char **filelist, **sfilelist, class[MAXPATHLEN], cwd[MAXPATHLEN];
    int show, which, days;
    time_t clock;

    struct stat buf;
    struct tm *tp;
    struct aclmember *entry = NULL;

    if (cwd_beenhere(2) != 0)
	return;

#ifdef HAVE_GETCWD
    (void) getcwd(cwd, MAXPATHLEN - 1);
#else
    (void) getwd(cwd);
#endif
    (void) acl_getclass(class);

    /* readme  <path> {<when>} */
    while (getaclentry("readme", &entry)) {
	if (!ARG0)
	    continue;
	show = 0;

	if (mode == LOG_IN && (!ARG1 || !strcasecmp(ARG1, "login")))
	    if (!ARG2)
		show++;
	    else {
		for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		    if (strcasecmp(class, ARG[which]) == 0)
			show++;
	    }
	if (mode == C_WD && ARG1 && !strncasecmp(ARG1, "cwd=", 4)
	    && (!strcmp((ARG1) + 4, cwd) || *(ARG1 + 4) == '*' ||
		!wu_fnmatch((ARG1) + 4, cwd, FNM_PATHNAME)))
	    if (!ARG2)
		show++;
	    else {
		for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		    if (strcasecmp(class, ARG[which]) == 0)
			show++;
	    }
	if (show) {
	    globerr = NULL;
	    filelist = ftpglob(ARG0, B_TRUE);
	    sfilelist = filelist;	/* save to free later */
	    if (!globerr) {
		while (filelist && *filelist) {
		    errno = 0;
		    if (!stat(*filelist, &buf) &&
			(buf.st_mode & S_IFMT) == S_IFREG) {
			lreply(code, "Please read the file %s", *filelist);
			(void) time(&clock);
			tp = localtime(&clock);
			days = 365 * tp->tm_year + tp->tm_yday;
			tp = localtime((time_t *) & buf.st_mtime);
			days -= 365 * tp->tm_year + tp->tm_yday;
/*
   if (days == 0) {
   lreply(code, "  it was last modified on %.24s - Today",
   ctime((time_t *)&buf.st_mtime));
   } else {
 */
			lreply(code,
			   "  it was last modified on %.24s - %d day%s ago",
			       ctime((time_t *) & buf.st_mtime), days, days == 1 ? "" : "s");
/*
   }
 */
		    }
		    filelist++;
		}
	    }
	    if (sfilelist) {
		blkfree(sfilelist);
		free((char *) sfilelist);
	    }
	}
    }
}

/*************************************************************************/
/* FUNCTION  : deny_badxfertype                                          */
/* PURPOSE   : If user is in ASCII transfer mode and tries to retrieve a */
/*             binary file, abort transfer and display appropriate error */
/* ARGUMENTS : message code to use for denial, path of file to check for */
/*             binary contents or NULL to assume binary file             */
/*************************************************************************/

int deny_badasciixfer(int msgcode, char *filepath)
{

    if (type == TYPE_A && !*filepath) {
	reply(msgcode, "This is a BINARY file, using ASCII mode to transfer will corrupt it.");
	return (1);
    }
    /* The hooks are here to prevent transfers of actual binary files, not
     * just TAR or COMPRESS mode files... */
    return (0);
}

/*************************************************************************/
/* FUNCTION  : is_shutdown                                               */
/* PURPOSE   : Check to see if the server is shutting down, if it is     */
/*             arrange for the shutdown message to be sent in the next   */
/*             reply to the user                                         */
/* ARGUMENTS : whether to arrange for a shutdown message to be sent, new */
/*             or existing connection                                    */
/* RETURNS   : 1 if shutting down, 0 if not                              */
/*************************************************************************/

int is_shutdown(int quiet, int new)
{
    static struct tm tmbuf;
    static struct stat s_last;
    static time_t last = 0, shut, deny, disc;
    static int valid;
    static char text[2048];
    struct stat s_cur;

    extern char *autospout, Shutdown[];

    FILE *fp;

    int deny_off, disc_off;

    time_t curtime = time(NULL);

    char buf[1024], linebuf[1024];

    if (Shutdown[0] == '\0' || stat(Shutdown, &s_cur))
	return (0);

    if (s_last.st_mtime != s_cur.st_mtime) {
	valid = 0;

	fp = fopen(Shutdown, "r");
	if (fp == NULL)
	    return (0);
	s_last = s_cur;
	fgets(buf, sizeof(buf), fp);
	if (sscanf(buf, "%d %d %d %d %d %ld %ld", &tmbuf.tm_year, &tmbuf.tm_mon,
	&tmbuf.tm_mday, &tmbuf.tm_hour, &tmbuf.tm_min, &deny, &disc) != 7) {
	    (void) fclose(fp);
	    return (0);
	}
	valid = 1;
	deny_off = 3600 * (deny / 100) + 60 * (deny % 100);
	disc_off = 3600 * (disc / 100) + 60 * (disc % 100);

	tmbuf.tm_year -= 1900;
	tmbuf.tm_isdst = -1;
	shut = mktime(&tmbuf);
	strcpy(shuttime, ctime(&shut));

	disc = shut - disc_off;
	strcpy(disctime, ctime(&disc));

	deny = shut - deny_off;
	strcpy(denytime, ctime(&deny));

	text[0] = '\0';

	while (fgets(buf, sizeof(buf), fp) != NULL) {
	    msg_massage(buf, linebuf, sizeof(linebuf));
	    if ((strlen(text) + strlen(linebuf)) < sizeof(text))
		strcat(text, linebuf);
	}

	(void) fclose(fp);
    }
    if (!valid)
	return (0);

    /* if last == 0, then is_shutdown() only called with quiet == 1 so far */
    if (last == 0 && !quiet) {
	autospout = text;	/* warn them for the first time */
	autospout_free = 0;
	last = curtime;
    }
    /* if a new connection and past deny time, tell caller to drop 'em */
    if (new && curtime > deny)
	return (1);

    /* if past disconnect time, tell caller to drop 'em */
    if (curtime > disc)
	return (1);

    /* if less than 60 seconds to disconnection, warn 'em continuously */
    if (curtime > (disc - 60) && !quiet) {
	autospout = text;
	autospout_free = 0;
	last = curtime;
    }
    /* if less than 15 minutes to disconnection, warn 'em every 5 mins */
    if (curtime > (disc - 60 * 15)) {
	if ((curtime - last) > (60 * 5) && !quiet) {
	    autospout = text;
	    autospout_free = 0;
	    last = curtime;
	}
    }
    /* if less than 24 hours to disconnection, warn 'em every 30 mins */
    if (curtime < (disc - 24 * 60 * 60) && !quiet) {
	if ((curtime - last) > (60 * 30)) {
	    autospout = text;
	    autospout_free = 0;
	    last = curtime;
	}
    }
    /* if more than 24 hours to disconnection, warn 'em every 60 mins */
    if (curtime > (disc - 24 * 60 * 60) && !quiet) {
	if ((curtime - last) >= (24 * 60 * 60)) {
	    autospout = text;
	    autospout_free = 0;
	    last = curtime;
	}
    }
    return (0);
}

#ifdef SITE_NEWER
void newer(char *date, char *path, int showlots)
{
    struct tm tm;

    if (sscanf(date, "%04d%02d%02d%02d%02d%02d",
	       &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
	       &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {

	tm.tm_year -= 1900;
	tm.tm_mon--;
	tm.tm_isdst = -1;
	newer_time = mktime(&tm);
	dout = dataconn("file list", (off_t) - 1, "w");

	if (dout != NULL) {
	    /* As ftw allocates storage it needs a chance to cleanup, setting
	     * ftwflag prevents myoob from calling longjmp, incrementing
	     * ftwflag instead which causes check_newer to return non-zero
	     * which makes ftw return. */
	    ftwflag = 1;
	    transflag++;
	    show_fullinfo = showlots;
#if defined(HAVE_FTW)
	    ftw(path, check_newer, -1);
#else
	    treewalk(path, check_newer, -1, NULL);
#endif

	    /* don't send a reply if myoob has already replied */
	    if (ftwflag == 1) {
		if (ferror(dout) != 0)
		    perror_reply(550, "Data connection");
		else
		    reply(226, "Transfer complete.");
	    }

	    (void) fclose(dout);
	    data = -1;
	    pdata = -1;
	    transflag = 0;
	    ftwflag = 0;
	}
    }
    else
	reply(501, "Bad DATE format");
}
#endif

int type_match(char *typelist)
{
    char *start, *p;
    int len;

    if (typelist == NULL)
	return (0);

    for (p = start = typelist; *start != '\0'; start = p) {
	while (*p != '\0' && *p != ',')
	    p++;
	len = p - start;
	if (*p != '\0')
	    p++;
	if (len == 9 && anonymous && strncasecmp(start, "anonymous", 9) == 0)
	    return (1);
	if (len == 5 && guest && strncasecmp(start, "guest", 5) == 0)
	    return (1);
	if (len == 4 && !guest && !anonymous &&
	    strncasecmp(start, "real", 4) == 0)
	    return (1);

	if (len > 6 && strncasecmp(start, "class=", 6) == 0) {
	    char class[1024];

	    if ((acl_getclass(class) == 1) && (strlen(class) == len - 6) &&
		(strncasecmp(start + 6, class, len - 6) == 0))
		return (1);
	}
    }
    return (0);
}

int path_compare(char *p1, char *p2)
{
    if ((strcmp(p1, "*") == 0) || (wu_fnmatch(p1, p2, FNM_PATHNAME) == 0))	/* 0 means they matched */
	return (strlen(p1));
    else
	return (-2);
}

void expand_id(void)
{
    char class[1024];
    struct aclmember *entry = NULL;
    (void) acl_getclass(class);
    while (getaclentry("upload", &entry)) {
	char *q;
	int i = 0;
	int options = 1;
	int classfound = 0;
	int classmatched = 0;
	while (options
	       && (i < MAXARGS)
	       && ((q = entry->arg[i]) != (char *) NULL)
	       && (q[0] != '\0')) {
	    if (strcasecmp(q, "absolute") == 0)
		i++;
	    else if (strcasecmp(q, "relative") == 0)
		i++;
	    else if (strncasecmp(q, "class=", 6) == 0) {
		i++;
		classfound = 1;
		if (strcasecmp(q + 6, class) == 0)
		    classmatched = 1;
	    }
	    else if (strcmp(q, "-") == 0) {
		i++;
		options = 0;
	    }
	    else
		options = 0;
	}
	if (!classfound || classmatched) {
	    char buf[BUFSIZ];
	    /*
	       *  UID
	     */
	    if (((i + 3) < MAXARGS)
		&& ((q = entry->arg[i + 3]) != (char *) NULL)
		&& (q[0] != '\0')
		&& (strcmp(q, "*") != 0)) {
		if (q[0] == '%')
		    sprintf(buf, "%s", q + 1);
		else {
		    struct passwd *pwent = getpwnam(q);
		    if (pwent)
			sprintf(buf, "%" PW_UID_FORMAT, pwent->pw_uid);
		    else
			sprintf(buf, "%d", 0);
		}
		entry->arg[i + 3] = (char *) malloc(strlen(buf) + 1);
		if (entry->arg[i + 3] == NULL) {
		    syslog(LOG_ERR, "calloc error in expand_id");
		    dologout(1);
		}
		strcpy(entry->arg[i + 3], buf);
	    }
	    /*
	       *  GID
	     */
	    if (((i + 4) < MAXARGS)
		&& ((q = entry->arg[i + 4]) != (char *) NULL)
		&& (q[0] != '\0')
		&& (strcmp(q, "*") != 0)) {
		if (q[0] == '%')
		    sprintf(buf, "%s", q + 1);
		else {
		    struct group *grent = getgrnam(q);
		    if (grent)
			sprintf(buf, "%" GR_GID_FORMAT, grent->gr_gid);
		    else
			sprintf(buf, "%d", 0);
		    endgrent();
		}
		entry->arg[i + 4] = (char *) malloc(strlen(buf) + 1);
		if (entry->arg[i + 4] == NULL) {
		    syslog(LOG_ERR, "calloc error in expand_id");
		    dologout(1);
		}
		strcpy(entry->arg[i + 4], buf);
	    }
	}
    }
}

int fn_check(char *name)
{
    /* check to see if this is a valid file name... path-filter <type>
     * <message_file> <allowed_charset> <disallowed> */

    struct aclmember *entry = NULL;
    int j;
    char *path;
#if ! defined(HAVE_REGEXEC)
    char *sp;
#endif

#ifdef M_UNIX
#ifdef HAVE_REGEX
    char *regp;
#endif
#endif

#ifdef HAVE_REGEXEC
    regex_t regexbuf;
    regmatch_t regmatchbuf;
    int rval;
#endif

#ifdef LINUX
    re_syntax_options = RE_SYNTAX_POSIX_EXTENDED;
#endif

    while (getaclentry("path-filter", &entry) && ARG0 != NULL) {
	if (type_match(ARG0) && ARG1 && ARG2) {

	    /*
	     * check *only* the basename
	     */

	    if ((path = strrchr(name, '/')))
		++path;
	    else
		path = name;

	    /* is it in the allowed character set? */
#if defined(HAVE_REGEXEC)
	    if (regcomp(&regexbuf, ARG2, REG_EXTENDED) != 0) {
		reply(550, "HAVE_REGEX error");
#elif defined(HAVE_REGEX)
		if ((sp = regcmp(ARG2, (char *) 0)) == NULL) {
		    reply(550, "HAVE_REGEX error");
#else
	    if ((sp = re_comp(ARG2)) != 0) {
		perror_reply(550, sp);
#endif
		return (0);
	    }
#if defined(HAVE_REGEXEC)
	    rval = regexec(&regexbuf, path, 1, &regmatchbuf, 0);
	    regfree(&regexbuf);
	    if (rval != 0) {
#elif defined(HAVE_REGEX)
#ifdef M_UNIX
		regp = regex(sp, path);
		free(sp);
		if (regp == NULL) {
#else
		if ((regex(sp, path)) == NULL) {
#endif
#else
	    if ((re_exec(path)) != 1) {
#endif
		pr_mesg(550, ARG1);
		reply(550, "%s: Permission denied on server. (Filename (accept))", name);
		return (0);
	    }
	    /* is it in any of the disallowed regexps */

	    for (j = 3; j < MAXARGS; ++j) {
		/* ARGj == entry->arg[j] */
		if (entry->arg[j]) {
#if defined(HAVE_REGEXEC)
		    if (regcomp(&regexbuf, entry->arg[j], REG_EXTENDED) != 0) {
			reply(550, "HAVE_REGEX error");
#elif defined(HAVE_REGEX)
			if ((sp = regcmp(entry->arg[j], (char *) 0)) == NULL) {
			    reply(550, "HAVE_REGEX error");
#else
		    if ((sp = re_comp(entry->arg[j])) != 0) {
			perror_reply(550, sp);
#endif
			return (0);
		    }
#if defined(HAVE_REGEXEC)
		    rval = regexec(&regexbuf, path, 1, &regmatchbuf, 0);
		    regfree(&regexbuf);
		    if (rval == 0) {
#elif defined(HAVE_REGEX)
#ifdef M_UNIX
			regp = regex(sp, path);
			free(sp);
			if (regp != NULL) {
#else
			if ((regex(sp, path)) != NULL) {
#endif
#else
		    if ((re_exec(path)) == 1) {
#endif
			pr_mesg(550, ARG1);
			reply(550, "%s: Permission denied on server. (Filename (deny))", name);
			return (0);
		    }
		}
	    }
	}
    }
    return (1);
}

int dir_check(char *name, uid_t * uid, gid_t * gid, int *d_mode, int *valid)
{
    struct aclmember *entry = NULL;
    int match_value = -1;
    char *ap2 = NULL;
    char *ap3 = NULL;
    char *ap4 = NULL;
    char *ap5 = NULL;
    char *ap6 = NULL;
    char *ap7 = NULL;
    char cwdir[MAXPATHLEN];
    char *pwdir;
    char abspwdir[MAXPATHLEN];
    char relpwdir[MAXPATHLEN];
    char path[MAXPATHLEN];
    char *sp;
    struct stat stbuf;
    int stat_result = -1;
    char class[1024];
    extern char *home;

    (void) acl_getclass(class);

    *valid = 0;
    /* what's our current directory? */

    /* XXX We could use dynamic RAM to store this path, but I'd rather just bail
       out with an error. The rest of wu is so crufy that a long path might
       just blow up later */

    if ((strlen(name) + 1) > sizeof(path)) {
	perror_reply(550, "Path too long");
	return (-1);
    }

    strcpy(path, name);
    sp = strrchr(path, '/');
    if (sp)
	*sp = '\0';
    else
	strcpy(path, ".");

    if ((fb_realpath(path, cwdir)) == NULL) {
	perror_reply(550, "Could not determine cwdir");
	return (-1);
    }

    if ((fb_realpath(home, relpwdir)) == NULL) {
	perror_reply(550, "Could not determine pwdir");
	return (-1);
    }

    if ((wu_realpath(home, abspwdir, chroot_path)) == NULL) {
	perror_reply(550, "Could not determine pwdir");
	return (-1);
    }

    while (getaclentry("upload", &entry)) {
	char *q;
	int i = 0;
	int options = 1;
	int classfound = 0;
	int classmatched = 0;
	pwdir = abspwdir;
	while (options
	       && (i < MAXARGS)
	       && ((q = entry->arg[i]) != (char *) NULL)
	       && (q[0] != '\0')) {
	    if (strcasecmp(q, "absolute") == 0) {
		i++;
		pwdir = abspwdir;
	    }
	    else if (strcasecmp(q, "relative") == 0) {
		i++;
		pwdir = relpwdir;
	    }
	    else if (strncasecmp(q, "class=", 6) == 0) {
		i++;
		classfound = 1;
		if (strcasecmp(q + 6, class) == 0)
		    classmatched = 1;
	    }
	    else if (strcmp(q, "-") == 0) {
		i++;
		options = 0;
	    }
	    else
		options = 0;
	}
	if (!classfound || classmatched) {
	    int j;
	    if (((i + 1) < MAXARGS)
		&& ((q = entry->arg[i]) != (char *) NULL)
		&& (q[0] != '\0')
		&& (0 < path_compare(q, pwdir))
		&& ((j = path_compare(entry->arg[i + 1], cwdir)) >= match_value)) {
		match_value = j;

		ap2 = NULL;
		if (((i + 2) < MAXARGS)
		    && ((q = entry->arg[i + 2]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap2 = q;

		ap3 = NULL;
		if (((i + 3) < MAXARGS)
		    && ((q = entry->arg[i + 3]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap3 = q;

		ap4 = NULL;
		if (((i + 4) < MAXARGS)
		    && ((q = entry->arg[i + 4]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap4 = q;

		ap5 = NULL;
		if (((i + 5) < MAXARGS)
		    && ((q = entry->arg[i + 5]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap5 = q;

		ap6 = NULL;
		if (((i + 6) < MAXARGS)
		    && ((q = entry->arg[i + 6]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap6 = q;

		ap7 = NULL;
		if (((i + 7) < MAXARGS)
		    && ((q = entry->arg[i + 7]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap7 = q;
	    }
	}
    }

    if (anonymous && (match_value < 0)) {
	reply(550, "%s: Permission denied on server. (Upload dirs)", name);
	return (0);
    }
    if ((ap2 && !strcasecmp(ap2, "no"))
	|| (ap3 && !strcasecmp(ap3, "nodirs"))
	|| (ap6 && !strcasecmp(ap6, "nodirs"))) {
	reply(550, "%s: Permission denied on server. (Upload dirs)", name);
	return (0);
    }
    if ((ap3 && *ap3 == '*') || (ap4 && *ap4 == '*'))
	stat_result = stat(path, &stbuf);
    if (ap3) {
	if ((ap3[0] != '*') || (ap3[1] != '\0'))
	    *uid = atoi(ap3);	/* the uid  */
	else if (stat_result == 0)
	    *uid = stbuf.st_uid;
    }
    if (ap4) {
	if ((ap4[0] != '*') || (ap4[1] != '\0'))
	    *gid = atoi(ap4);	/* the gid */
	else if (stat_result == 0)
	    *gid = stbuf.st_gid;
    }
    if (ap7) {
	sscanf(ap7, "%o", d_mode);
	*valid = 1;
    }
    else if (ap5) {
	sscanf(ap5, "%o", d_mode);
	if (*d_mode & 0600)
	    *d_mode |= 0100;
	if (*d_mode & 0060)
	    *d_mode |= 0010;
	if (*d_mode & 0006)
	    *d_mode |= 0001;
	*valid = 1;
    }
    return (1);
}

int upl_check(char *name, uid_t * uid, gid_t * gid, int *f_mode, int *valid)
{
    int match_value = -1;
    char cwdir[MAXPATHLEN];
    char *pwdir;
    char abspwdir[MAXPATHLEN];
    char relpwdir[MAXPATHLEN];
    char path[MAXPATHLEN];
    char *sp;
    struct stat stbuf;
    int stat_result = -1;
    char *ap2 = NULL;
    char *ap3 = NULL;
    char *ap4 = NULL;
    char *ap5 = NULL;
    struct aclmember *entry = NULL;
    char class[1024];
    extern char *home;

    *valid = 0;
    (void) acl_getclass(class);

    /* what's our current directory? */

    /* XXX We could use dynamic RAM to store this path, but I'd rather just bail
       out with an error. The rest of wu is so crufy that a long path might
       just blow up later */

    if ((strlen(name) + 1) > sizeof(path)) {
	perror_reply(553, "Path too long");
	return (-1);
    }

    strcpy(path, name);
    sp = strrchr(path, '/');
    if (sp)
	*sp = '\0';
    else
	strcpy(path, ".");

    if ((fb_realpath(path, cwdir)) == NULL) {
	perror_reply(553, "Could not determine cwdir");
	return (-1);
    }

    if ((wu_realpath(home, abspwdir, chroot_path)) == NULL) {
	perror_reply(553, "Could not determine pwdir");
	return (-1);
    }

    if ((fb_realpath(home, relpwdir)) == NULL) {
	perror_reply(553, "Could not determine pwdir");
	return (-1);
    }

    /*
       *  we are doing a "best match"... ..so we keep track of what "match
       *  value" we have received so far...
     */
    while (getaclentry("upload", &entry)) {
	char *q;
	int i = 0;
	int options = 1;
	int classfound = 0;
	int classmatched = 0;
	pwdir = abspwdir;
	while (options
	       && (i < MAXARGS)
	       && ((q = entry->arg[i]) != (char *) NULL)
	       && (q[0] != '\0')) {
	    if (strcasecmp(q, "absolute") == 0) {
		i++;
		pwdir = abspwdir;
	    }
	    else if (strcasecmp(q, "relative") == 0) {
		i++;
		pwdir = relpwdir;
	    }
	    else if (strncasecmp(q, "class=", 6) == 0) {
		i++;
		classfound = 1;
		if (strcasecmp(q + 6, class) == 0)
		    classmatched = 1;
	    }
	    else if (strcmp(q, "-") == 0) {
		i++;
		options = 0;
	    }
	    else
		options = 0;
	}
	if (!classfound || classmatched) {
	    int j;
	    if (((i + 1) < MAXARGS)
		&& ((q = entry->arg[i]) != (char *) NULL)
		&& (q[0] != '\0')
		&& (0 < path_compare(q, pwdir))
		&& ((j = path_compare(entry->arg[i + 1], cwdir)) >= match_value)) {
		match_value = j;

		ap2 = NULL;
		if (((i + 2) < MAXARGS)
		    && ((q = entry->arg[i + 2]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap2 = q;

		ap3 = NULL;
		if (((i + 3) < MAXARGS)
		    && ((q = entry->arg[i + 3]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap3 = q;

		ap4 = NULL;
		if (((i + 4) < MAXARGS)
		    && ((q = entry->arg[i + 4]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap4 = q;

		ap5 = NULL;
		if (((i + 5) < MAXARGS)
		    && ((q = entry->arg[i + 5]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap5 = q;
	    }
	}
    }

    if (ap3
	&& ((!strcasecmp("dirs", ap3))
	    || (!strcasecmp("nodirs", ap3))))
	ap3 = NULL;

    /*
       *  if we did get matches ... else don't do any of this stuff
     */
    if (match_value >= 0) {
	if (!strcasecmp(ap2, "yes")) {
	    if ((ap3 && *ap3 == '*') || (ap4 && *ap4 == '*'))
		stat_result = stat(path, &stbuf);
	    if (ap3) {
		if ((ap3[0] != '*') || (ap3[1] != '\0'))
		    *uid = atoi(ap3);	/* the uid  */
		else if (stat_result == 0)
		    *uid = stbuf.st_uid;
	    }
	    if (ap4) {
		if ((ap4[0] != '*') || (ap4[1] != '\0'))
		    *gid = atoi(ap4);	/* the gid  */
		else if (stat_result == 0)
		    *gid = stbuf.st_gid;
		*valid = 1;
	    }
	    if (ap5)
		sscanf(ap5, "%o", f_mode);	/* the mode */
	}
	else {
	    reply(553, "%s: Permission denied on server. (Upload)", name);
	    return (-1);
	}
    }
    else {
	/*
	   *  upload defaults to "permitted"
	 */
	/* Not if anonymous */
	if (anonymous) {
	    reply(553, "%s: Permission denied on server. (Upload)", name);
	    return (-1);
	}
	return (1);
    }

    return (match_value);
}

int del_check(char *name)
{
    int pdelete = (anonymous ? 0 : 1);
    struct aclmember *entry = NULL;

    while (getaclentry("delete", &entry) && ARG0 && ARG1 != NULL) {
	if (type_match(ARG1))
	    if (anonymous) {
		if (*ARG0 == 'y')
		    pdelete = 1;
	    }
	    else if (*ARG0 == 'n')
		pdelete = 0;
    }

/* H* fix: no deletion, period. You put a file here, I get to look at it. */
#ifdef PARANOID
    pdelete = 0;
#endif

    if (!pdelete) {
	reply(553, "%s: Permission denied on server. (Delete)", name);
	return (0);
    }
    else {
	return (1);
    }
}

/* The following is from the Debian add-ons. */

#define lbasename(x) (strrchr(x,'/')?1+strrchr(x,'/'):x)

int regexmatch(char *name, char *rgexp)
{

#ifdef M_UNIX
#ifdef HAVE_REGEX
    char *regp;
#endif
#endif

#ifdef HAVE_REGEXEC
    regex_t regexbuf;
    regmatch_t regmatchbuf;
    int rval;
#else
    char *sp;
#endif

#if defined(HAVE_REGEXEC)
    if (regcomp(&regexbuf, rgexp, REG_EXTENDED) != 0) {
	reply(553, "HAVE_REGEX error");
#elif defined(HAVE_REGEX)
	if ((sp = regcmp(rgexp, (char *) 0)) == NULL) {
	    reply(553, "HAVE_REGEX error");
#else
    if ((sp = re_comp(rgexp)) != 0) {
	perror_reply(553, sp);
#endif
	return (0);
    }

#if defined(HAVE_REGEXEC)
    rval = regexec(&regexbuf, name, 1, &regmatchbuf, 0);
    regfree(&regexbuf);
    if (rval != 0) {
#elif defined(HAVE_REGEX)
#ifdef M_UNIX
	regp = regex(sp, name);
	free(sp);
	if (regp == NULL) {
#else
	if ((regex(sp, name)) == NULL) {
#endif
#else
    if ((re_exec(name)) != 1) {
#endif
	return (0);
    }
    return (1);
}

static int allow_retrieve(char *name)
{
    char realname[MAXPATHLEN + 1];
    char localname[MAXPATHLEN + 1];
    char *whichname;
    int i;
    struct aclmember *entry = NULL;
    char *p, *q;
    int options;
    int classfound;
    int classmatched;
    char class[1024];

    (void) acl_getclass(class);
    if ((name == (char *) NULL)
	|| (*name == '\0'))
	return 0;
    fb_realpath(name, localname);
    wu_realpath(name, realname, chroot_path);
    while (getaclentry("allow-retrieve", &entry)) {
	whichname = realname;
	i = 0;
	options = 1;
	classfound = 0;
	classmatched = 0;
	while (options
	       && (i < MAXARGS)
	       && ((q = entry->arg[i]) != (char *) NULL)
	       && (q[0] != '\0')) {
	    if (strcasecmp(q, "absolute") == 0) {
		i++;
		whichname = realname;
	    }
	    else if (strcasecmp(q, "relative") == 0) {
		i++;
		whichname = localname;
	    }
	    else if (strncasecmp(q, "class=", 6) == 0) {
		i++;
		classfound = 1;
		if (strcasecmp(q + 6, class) == 0)
		    classmatched = 1;
	    }
	    else if (strcmp(q, "-") == 0) {
		i++;
		options = 0;
	    }
	    else
		options = 0;
	}
	if (!classfound || classmatched) {
	    for (; (i < MAXARGS) && ((q = entry->arg[i]) != (char *) NULL) && (q[0] != '\0'); i++) {
		p = (q[0] == '/') ? whichname : lbasename(whichname);
		if (!wu_fnmatch(q, p, FNM_PATHNAME | FNM_LEADING_DIR)) {
		    return 1;
		}
	    }
	}
    }
    return 0;
}

int checknoretrieve(char *name)
{
    char realname[MAXPATHLEN + 1];
    char localname[MAXPATHLEN + 1];
    char *whichname;
    int i;
    struct aclmember *entry = NULL;
    char *p, *q;
    int options;
    int classfound;
    int classmatched;
    char class[1024];

    extern struct passwd *pw;
    extern char *remoteident;

    (void) acl_getclass(class);
    if ((name == (char *) NULL)
	|| (*name == '\0'))
	return 0;
    fb_realpath(name, localname);
    wu_realpath(name, realname, chroot_path);
    while (getaclentry("noretrieve", &entry)) {
	whichname = realname;
	i = 0;
	options = 1;
	classfound = 0;
	classmatched = 0;
	while (options
	       && (i < MAXARGS)
	       && ((q = entry->arg[i]) != (char *) NULL)
	       && (q[0] != '\0')) {
	    if (strcasecmp(q, "absolute") == 0) {
		i++;
		whichname = realname;
	    }
	    else if (strcasecmp(q, "relative") == 0) {
		i++;
		whichname = localname;
	    }
	    else if (strncasecmp(q, "class=", 6) == 0) {
		i++;
		classfound = 1;
		if (strcasecmp(q + 6, class) == 0)
		    classmatched = 1;
	    }
	    else if (strcmp(q, "-") == 0) {
		i++;
		options = 0;
	    }
	    else
		options = 0;
	}
	if (!classfound || classmatched) {
	    for (; (i < MAXARGS) && ((q = entry->arg[i]) != (char *) NULL) && (q[0] != '\0'); i++) {
		p = (q[0] == '/') ? whichname : lbasename(whichname);
		if (!wu_fnmatch(q, p, FNM_PATHNAME | FNM_LEADING_DIR)) {
		    if (!allow_retrieve(name)) {
			reply(550, "%s is marked unretrievable", localname);
			return 1;
		    }
		}
	    }
	}
    }
    return 0;
}

#ifdef QUOTA

#ifndef MNTMAXSTR
#define MNTMAXSTR 2048		/* And hope it's enough */
#endif

#ifdef QUOTA_DEVICE

int path_to_device(char *pathname, char *result)
{
    FILE *fp;
#ifdef HAS_OLDSTYLE_GETMNTENT
    struct mnttab static_mp;
    struct mnttab *mp = &static_mp;
#else
    struct mntent *mp;
#endif
    struct mount_ent {
	char mnt_fsname[MNTMAXSTR], mnt_dir[MNTMAXSTR];
	struct mount_ent *next;
    } mountent;
    struct mount_ent *current, *start, *new;
    char path[1024], mnt_dir[1024], *pos;
    int flag = 1;

    start = current = NULL;
#ifdef HAS_OLDSTYLE_GETMNTENT
    fp = fopen(MNTTAB, "r");
#else
    fp = setmntent(MNTTAB, "r");
#endif
    if (fp == NULL)
	return 0;
#ifdef HAS_OLDSTYLE_GETMNTENT
    while (getmntent(fp, &static_mp) == 0)
#else
    while (mp = getmntent(fp))
#endif
    {
	if (!(new = (struct mount_ent *) malloc(sizeof(mountent)))) {
	    perror("malloc");
	    flag = 0;
	    break;
	}

	if (!start)
	    start = current = new;
	else
	    current = current->next = new;

#ifdef HAS_OLDSTYLE_GETMNTENT
	strncpy(current->mnt_fsname, mp->mnt_special, strlen(mp->mnt_special) + 1);
	strncpy(current->mnt_dir, mp->mnt_mountp, strlen(mp->mnt_mountp) + 1);
#else
	strncpy(current->mnt_fsname, mp->mnt_fsname, strlen(mp->mnt_fsname) + 1);
	strncpy(current->mnt_dir, mp->mnt_dir, strlen(mp->mnt_dir) + 1);
#endif
    }
#ifdef HAS_OLDSTYLE_GETMNTENT
    fclose(fp);
#else
    endmntent(fp);
#endif
    current->next = NULL;

    wu_realpath(pathname, path, chroot_path);

    while (*path && flag) {
	current = start;
	while (current && flag) {
	    if (strcmp(current->mnt_dir, "swap")) {
		wu_realpath(current->mnt_dir, mnt_dir, chroot_path);
		if (!strcmp(mnt_dir, path)) {
		    flag = 0;
		    /* no support for remote quota yet */
		    if (!strchr(current->mnt_fsname, ':'))
			strcpy(result, current->mnt_fsname);
		}
	    }
	    current = current->next;
	}
	if (!((pos = strrchr(path, '/')) - path) && strlen(path) > 1)
	    strcpy(path, "/");
	else
	    path[pos - path] = '\0';
    }
    while (current) {
	new = current->next;
	free(current);
	current = new;
    }
    return 1;
}
#endif

void get_quota(char *fs, int uid)
{
    char mnt_fsname[MNTMAXSTR];
#ifdef HAS_NO_QUOTACTL
    int dirfd;
    struct quotctl qp;
#endif

    /*
     * Getting file system quota information can take a noticeable amount
     * of time, so only get quota information for specified users.
     * quota-info <uid-range> [<uid-range> ...]
     */
    if (!uid_match("quota-info", uid))
	return;

#ifdef HAS_NO_QUOTACTL
    if (path_to_device(fs, mnt_fsname)) {
	dirfd = open(fs, O_RDONLY);
	qp.op = Q_GETQUOTA;
	qp.uid = uid;
	qp.addr = (char *) &quota;
	ioctl(dirfd, Q_QUOTACTL, &qp);
	close(dirfd);
    }
#else
#ifdef QUOTA_DEVICE

    if (path_to_device(fs, mnt_fsname))
#ifdef QCMD
	quotactl(QCMD(Q_GETQUOTA, USRQUOTA), mnt_fsname, uid, (char *) &quota);
#else
	quotactl(Q_GETQUOTA, mnt_fsname, uid, (char *) &quota);
#endif
#else
    quotactl(fs, QCMD(Q_GETQUOTA, USRQUOTA), uid, (char *) &quota);
#endif
#endif /* HAS_NO_QUOTACTL */
}

char *time_quota(long curstate, long softlimit, long timelimit, char *timeleft)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    if (softlimit && curstate >= softlimit) {
	if (timelimit == 0) {
	    strcpy(timeleft, "NOT STARTED");
	}
	else if (timelimit > tv.tv_sec) {
	    fmttime(timeleft, timelimit - tv.tv_sec);
	}
	else {
	    strcpy(timeleft, "EXPIRED");
	}
    }
    else {
	timeleft[0] = '\0';
    }
    return (timeleft);
}

void fmttime(char *buf, register long time)
{
    int i;
    static struct {
	int c_secs;		/* conversion units in secs */
	char *c_str;		/* unit string */
    } cunits[] = {
	{
	    60 *60 * 24 * 28, "months"
	} ,
	{
	    60 *60 * 24 * 7, "weeks"
	} ,
	{
	    60 *60 * 24, "days"
	} ,
	{
	    60 *60, "hours"
	} ,
	{
	    60, "mins"
	} ,
	{
	    1, "secs"
	}
    };

    if (time <= 0) {
	strcpy(buf, "EXPIRED");
	return;
    }
    for (i = 0; i < sizeof(cunits) / sizeof(cunits[0]); i++) {
	if (time >= cunits[i].c_secs)
	    break;
    }
    sprintf(buf, "%.1f %s", (double) time / cunits[i].c_secs, cunits[i].c_str);
}

#endif

#ifdef THROUGHPUT

int file_compare(char *patterns, char *file)
{
    char buf[MAXPATHLEN+1];
    char *cp;
    char *cp2;
    int i;
    int matches = 0;

    strncpy(buf, patterns, sizeof(buf) - 1);
    buf[sizeof(buf) - 2] = '\0';
    i = strlen(buf);
    buf[i++] = ',';
    buf[i++] = '\0';

    cp = buf;
    while ((cp2 = strchr(cp, ',')) != NULL) {
	*cp2++ = '\0';
	if (wu_fnmatch(cp, file, FNM_PATHNAME) == 0) {
	    matches = 1;
	    break;
	}
	cp = cp2;
    }
    return matches;
}

int remote_compare(char *patterns)
{
    char buf[MAXPATHLEN+1];
    char *cp;
    char *cp2;
    int i;
    int matches = 0;

    strncpy(buf, patterns, sizeof(buf) - 1);
    buf[sizeof(buf) - 2] = '\0';
    i = strlen(buf);
    buf[i++] = ',';
    buf[i++] = '\0';

    cp = buf;
    while ((cp2 = strchr(cp, ',')) != NULL) {
	*cp2++ = '\0';
	if (hostmatch(cp, remoteaddr, remotehost)) {
	    matches = 1;
	    break;
	}
	cp = cp2;
    }
    return matches;
}

void throughput_calc(char *name, int *bps, double *bpsmult)
{
    int match_value = -1;
    char cwdir[MAXPATHLEN];
    char pwdir[MAXPATHLEN];
    char path[MAXPATHLEN];
    char file[MAXPATHLEN];
    char *ap3 = NULL, *ap4 = NULL;
    struct aclmember *entry = NULL;
    extern char *home;
    char *sp;
    int i;

    /* default is maximum throughput */
    *bps = -1;
    *bpsmult = 1.0;

    /* XXX We could use dynamic RAM to store this path, but I'd rather just bail
       out with an error. The rest of wu is so crufy that a long path might
       just blow up later */

    if ((strlen(name) + 1) > sizeof(path)) {
	return;
    }

    /* what's our current directory? */
    strcpy(path, name);
    if ((sp = strrchr(path, '/')))
	*sp = '\0';
    else
	strcpy(path, ".");
    if ((sp = strrchr(name, '/')))
	strcpy(file, sp + 1);
    else
	strcpy(file, name);
    if ((fb_realpath(path, cwdir)) == NULL) {
	return;
    }

    wu_realpath(home, pwdir, chroot_path);

    /* find best matching entry */
    while (getaclentry("throughput", &entry) && ARG0 && ARG1 && ARG2 && ARG3 && ARG4 && ARG5 != NULL) {
	if ((0 < path_compare(ARG0, pwdir))
	    && ((i = path_compare(ARG1, cwdir)) >= match_value)
	    ) {
	    if (file_compare(ARG2, file)) {
		if (remote_compare(ARG5)) {
		    match_value = i;
		    ap3 = ARG3;
		    ap4 = ARG4;
		}
	    }
	}
    }

    /* if we did get matches */
    if (match_value >= 0) {
	if (strcasecmp(ap3, "oo") == 0)
	    *bps = -1;
	else
	    *bps = atoi(ap3);
	if (strcmp(ap4, "-") == 0)
	    *bpsmult = 1.0;
	else
	    *bpsmult = atof(ap4);
    }
    return;
}

void throughput_adjust(char *name)
{
    int match_value = -1;
    char pwdir[MAXPATHLEN];
    char cwdir[MAXPATHLEN];
    char path[MAXPATHLEN];
    char file[MAXPATHLEN];
    char buf[MAXPATHLEN];
    char *ap3 = NULL, *ap4 = NULL;
    char **pap;
    struct aclmember *entry = NULL;
    extern char *home;
    char *sp;
    int i;

    /* XXX We could use dynamic RAM to store this path, but I'd rather just bail
       out with an error. The rest of wu is so crufy that a long path might
       just blow up later */

    if ((strlen(name) + 1) > sizeof(path)) {
	return;
    }

    /* what's our current directory? */
    strcpy(path, name);
    if ((sp = strrchr(path, '/')))
	*sp = '\0';
    else
	strcpy(path, ".");
    if ((sp = strrchr(name, '/')))
	strcpy(file, sp + 1);
    else
	strcpy(file, name);
    if ((fb_realpath(path, cwdir)) == NULL) {
	return;
    }

    wu_realpath(home, pwdir, chroot_path);

    /* find best matching entry */
    while (getaclentry("throughput", &entry) && ARG0 && ARG1 && ARG2 && ARG3 && ARG4 && ARG5 != NULL) {
	if ((0 < path_compare(ARG0, pwdir))
	    && ((i = path_compare(ARG1, cwdir)) >= match_value)
	    ) {
	    if (file_compare(ARG2, file)) {
		if (remote_compare(ARG5)) {
		    match_value = i;
		    ap3 = ARG3;
		    pap = ARG;
		    ap4 = ARG4;
		}
	    }
	}
    }

    /* if we did get matches */
    if (match_value >= 0) {
	if (strcasecmp(ap3, "oo") != 0) {
	    if (strcmp(ap4, "-") != 0) {
		sprintf(buf, "%.0f", atoi(ap3) * atof(ap4));
		pap[3] = (char *) malloc(strlen(buf) + 1);
		if (pap[3] == NULL) {
		    syslog(LOG_ERR, "malloc error in throughput_adjust");
		    dologout(1);
		}
		/* Use ARG6 to keep track of malloced memory */
		if (pap[6])
		    free(pap[6]);
		pap[6] = pap[3];
		strcpy(pap[3], buf);
	    }
	}
    }
    return;
}

#endif

#ifdef SOLARIS_2
static int CheckMethod = 1;
#else
static int CheckMethod = 0;
#endif

void SetCheckMethod(const char *method)
{
    if ((strcasecmp(method, "md5") == 0)
	|| (strcasecmp(method, "rfc1321") == 0))
	CheckMethod = 0;
    else if ((strcasecmp(method, "crc") == 0)
	     || (strcasecmp(method, "posix") == 0))
	CheckMethod = 1;
    else {
	reply(500, "Unrecognized checksum method");
	return;
    }
    switch (CheckMethod) {
    default:
	reply(200, "Checksum method is now: MD5 (RFC1321)");
	break;
    case 1:
	reply(200, "Checksum method is now: CRC (POSIX)");
	break;
    }
}

void ShowCheckMethod(void)
{
    switch (CheckMethod) {
    default:
	reply(200, "Current checksum method: MD5 (RFC1321)");
	break;
    case 1:
	reply(200, "Current checksum method: CRC (POSIX)");
	break;
    }
}

void CheckSum(char *pathname)
{
    char *cmd;
    char buf[MAXPATHLEN];
    FILE *cmdf;
    struct stat st;

    if (stat(pathname, &st) == 0) {
	if ((st.st_mode & S_IFMT) != S_IFREG) {
	    reply(500, "%s: not a plain file.", pathname);
	    return;
	}
    }
    else {
	perror_reply(550, pathname);
	return;
    }

    switch (CheckMethod) {
    default:
	cmd = "/bin/md5sum";
	break;
    case 1:
	cmd = "/bin/cksum";
	break;
    }

    if (strlen(cmd) + 1 + strlen(pathname) + 1 > sizeof(buf)) {
	reply(500, "Pathname too long");
	return;
    }
    sprintf(buf, "%s %s", cmd, pathname);

    cmdf = ftpd_popen(buf, "r", 0);
    if (!cmdf) {
	perror_reply(550, cmd);
    }
    else {
	if (fgets(buf, sizeof buf, cmdf)) {
	    char *crptr = strchr(buf, '\n');
	    if (crptr != NULL)
		*crptr = '\0';
	    reply(200, "%s", buf);
	}
	ftpd_pclose(cmdf);
    }
}

void CheckSumLastFile(void)
{
    extern char LastFileTransferred[];

    if (LastFileTransferred[0] == '\0')
	reply(500, "Nothing transferred yet");
    else
	CheckSum(LastFileTransferred);
}
