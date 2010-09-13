#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* config.h.  Generated automatically by configure.  */
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
 
  $Id: config.h.in,v 1.15 2000/07/01 17:42:15 wuftpd Exp $
 
****************************************************************************/

/* 
 * Top level config file... These values will be adjusted by autoconf.
 * $Id: config.h.in,v 1.15 2000/07/01 17:42:15 wuftpd Exp $
 */

/*
 * allow "upload" keyword in ftpaccess
 */

#define UPLOAD 1

/*
 * allow "overwrite" keyword in ftpaccess.
 */

#define OVERWRITE 1

/*
 * allow "allow/deny" for individual users.
 */

#define HOST_ACCESS 1

/*
 * log failed login attempts
 */

#define LOG_FAILED 1

/*
 * log login attempts that fail because of class connection
 * limits.  Busy servers may want to prevent this logging
 * since it can fill up the log file and put a high load on
 * syslog.
 */
#define LOG_TOOMANY 1

/*
 * allow use of private file.  (for site group and site gpass)
 * NO_PRIVATE
 * Define this if you don't want to use the private authentication databases.
 */

/* #undef NO_PRIVATE */

/*
 * Try once more on failed DNS lookups (to allow far away connections 
 * which might resolve slowly)
 */

/* #undef DNS_TRYAGAIN */

/*
 * ANON_ONLY 
 * Permit only anonymous logins... disables all other type
 * See FIXES-2.4-HOBBIT for more information on this option.
 */

/* #undef ANON_ONLY */

/*
 * PARANOID
 * Disable "questionable" functions
 * See FIXES-2.4-HOBBIT for more information on this option.
 */

/* #undef PARANOID */

/*
 * SKEY
 * Add SKEY support -- REQUIRES SKEY libraries
 * See FIXES-2.4-HOBBIT for more information on this option.
 */

/* #undef SKEY */

/*
 * OPIE
 * One-time Passwords In Everything (OPIE)
 * Add OPIE support -- REQUIRES OPIE libraries
 */

#if !defined (LINUX)		/* Linux autodetects OPIE */
/* #undef OPIE */
#endif

/*
 * ALTERNATE_CD
 * Causes "cd ~" to return the chroot-relative directory instead of the
 * real directory.
 */
#define ALTERNATE_CD 1

/*
 * UNRESTRICTED_CHMOD
 * If defined, any valid value for the mode will be accepted.
 * Otherwise, only values between 0 and 777 are accepted.
 */
/* #undef UNRESTRICTED_CHMOD */

/*
 * USE_RFC931
 * Define this if you want to use RFC 931 'authentication' - this improves
 * the logging at the cost of a possible slight delay in connection.
 */
/* #undef USE_RFC931 */

/*
 * BUFFER_SIZE
 * You can specify the buffer size for binary transfers; the defaults
 * are often far too small for efficiency.
 */
/* #undef BUFFER_SIZE */

/*
 * If you want to specify the syslog facility, you should modify CFLAGS in
 * the appropriate src/makefile/Makefile.*.
 */

/* If you want to set the paths where the configuration files, pids and logs
 * are stored, you should inspect src/pathnames.h and modify the appropriate
 * src/config/config.*.
 */

/*
 * RATIO
 * Support for Upload/Download ratios (may download x bytes for uploading 1 byte)
 */
/* #undef RATIO */

/*
 * OTHER_PASSWD
 * Support for using alternative passwd/shadow files
 */
#define OTHER_PASSWD 1

/*
 * DAEMON
 * If ftpd called with -D then run as a standalone daemon listing on the
 * ftp port.   This can speed up ftpd response as all ftpd then needs to
 * do is fork off a copy to handle an incoming request.  Under inetd 
 * a new copy has to be opened and exec'd.
 */
#define DAEMON 1

/*
 * MAX_BACKLOG
 * Only used in DAEMON mode.
 * This is second parameter to listen.  It defines the number of incoming
 * processes to allow to backlog, prior to being accept() processing them,
 * before rejecting.
 */
#define MAX_BACKLOG 100

/*
 * MAPPING_CHDIR
 * Keep track of the path the user has chdir'd into and respond with
 * that to pwd commands.  This is to avoid having the absolue disk
 * path returned.  This helps avoid returning dirs like '.1/fred'
 * when lots of disks make up the ftp area.
 */

#define MAPPING_CHDIR 1

/*
 * THROUGHPUT
 * Keep track of total throughput for the user and limit if required.
 */

#define THROUGHPUT 1

/*
 * TRANSFER_COUNT
 * Keep track of total bytes for statistics.
 */

#define TRANSFER_COUNT 1

/*
 * TRANSFER_LIMIT
 * Limit file and bytes transferred in a session.
 */

#define TRANSFER_LIMIT 1

/*
 * NO_SUCKING_NEWLINES
 * Don't suppress some extra blank lines on messages and banners.
 */

/* #undef NO_SUCKING_NEWLINES */

/*
 * HELP_CRACKERS
 * Define this to help crackers break into your system by letting them
 * figure out which user names exist to guess passwords on.
 */

/* #undef HELP_CRACKERS */

/*
 * VERBOSE_ERROR_LOGING
 * Log all problems with USER and PASS as well as all rejected commands
 * and denied uploads/downloads.
 */

#define VERBOSE_ERROR_LOGING 1

/*
 * IGNORE_NOOP
 * Undefine this to let NOOP reset the idle timeout.
 */

#define IGNORE_NOOP 1

/*
 * CLOSED_VIRTUAL_SERVER
 * Undefine this to allow real and non-owner guests to log in on a virutal server's address.
 */
#define CLOSED_VIRTUAL_SERVER 1

/*
 * Some people don't like PASV and want to disable it.  Whatever.
 * PORT can be abused to attack other hosts.  Let's give the option to
 * disable one or the other.  We'll ignore DISABLE_PASV if you defined
 * DISABLE_PORT (hey, you gotta have at least one!).
 */
/* #undef DISABLE_PORT */
/* #undef DISABLE_PASV */

/*
 * Define this to suppress messages about PID locks causing the daemon to
 * sleep.  This should only be needed at busy sites.
 */
#define NO_PID_SLEEP_MSGS 1

/*
 * Define this to require the remove end of a PASV connection to have the
 * same IP as the control connection.  This limits, but does not eliminate,
 * the risk of PASV port race stealing the connection.  It also is non-RFC
 * compliant, so it may cause problems for some client sites.
 */
#define FIGHT_PASV_PORT_RACE 1

/*
 * Define this to completely disable anonymous FTP access.
 */
/* #undef NO_ANONYMOUS_ACCESS */

/*
 * Define this to have an ls command compiled into the daemon. That way you
 * don't need to put statically linked ls's into every chroot directory.
 */
/* #undef INTERNAL_LS */

/*
 * Define this if you want the internal ls to display UIDs/GIDs rather than
 * user/group names. This is faster, but doesn't look as nice.
 */
/* #undef LS_NUMERIC_UIDS */

/*
 * Define this if you want to hide setuid bits in the internal ls
 * this might be a good idea for security.
 */
#define HIDE_SETUID 1

/*
 * Define this if you want to support virtual servers
 */
#define VIRTUAL 1

/*
 * Define this if you want to be able to receive mail on anonymous
 * uploads
 */
#define MAIL_ADMIN 1

/*
 * Config files in /etc by default
 */
#define USE_ETC 1

/*
 * Define this to support quota mechanisms...
 */
#define QUOTA 1

/*
 * The intention of SITE NEWER was to enable mirrors to quickly determine which
 * files have changed since the last run. Since most mirror packages wish to
 * work with all daemons (not just wu-ftpd), and since SITE NEWER is a wu-ftpd
 * only feature, they don't use the feature. Therefore there seems little
 * reason to continue to support it.
 *
 * Define this to support SITE NEWER and SITE MINFO.
 */
/* #undef SITE_NEWER */

/*
 * Define this to revert the NLST command to showing directories.
 *
 * This will cause mget to have errors when it attempts to RETR the
 * directory name (which is not a RETRievable object) but will revert
 * the NLST command enough to quell complains from Solaris command-
 * line FTP client users.
 */
#define NLST_SHOWS_DIRS 1
