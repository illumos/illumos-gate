/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/****************************************************************************  
 
  Copyright (c) 1999,2000,2001 WU-FTPD Development Group.  
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
 
  $Id: ftpd.c,v 1.111 2000/07/01 18:17:39 wuftpd Exp $
 
****************************************************************************/
/* FTP server. */
#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/wait.h>

#ifdef AIX
#include <sys/id.h>
#include <sys/priv.h>
#include <netinet/if_ether.h>
#include <net/if_dl.h>
#endif

#ifdef AUX
#include <compat.h>
#endif

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#define FTP_NAMES
#include <arpa/ftp.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <setjmp.h>
#include <errno.h>
#include <string.h>
#ifdef INTERNAL_LS
#ifdef HAVE_GLOB_H
#include <glob.h>
#else
#include <wuftpd_glob.h>
#endif
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#include <sys/stat.h>

#define VA_LOCAL_DECL	va_list ap;
#define VA_START(f)	va_start(ap, f)
#define VA_END		va_end(ap)

#include "proto.h"

#ifdef HAVE_UFS_QUOTA_H
#include <ufs/quota.h>
#endif
#ifdef HAVE_SYS_FS_UFS_QUOTA_H
#include <sys/fs/ufs_quota.h>
#endif

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

#ifdef HAVE_SYS_SENDFILE_H
#include <sys/sendfile.h>
#endif

#include "conversions.h"
#include "extensions.h"

#ifdef SHADOW_PASSWORD
#include <shadow.h>
#endif

#include "pathnames.h"

#ifdef M_UNIX
#include <arpa/nameser.h>
#include <resolv.h>
#endif

#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif

#ifdef HAVE_SYSINFO
#include <sys/systeminfo.h>
#endif

#ifdef KERBEROS
#include <sys/types.h>
#include <auth.h>
#include <krb.h>
#endif

#ifdef ULTRIX_AUTH
#include <auth.h>
#include <sys/svcinfo.h>
#endif

#ifndef HAVE_LSTAT
#define lstat stat
#endif

#ifdef AFS_AUTH
#include <afs/stds.h>
#include <afs/kautils.h>
#endif

#ifdef DCE_AUTH
#include <dce/rpc.h>
#include <dce/sec_login.h>
#include <dce/dce_error.h>
#endif


#ifdef HAVE_DIRENT_H
#include <dirent.h>
#else
#include <sys/dir.h>
#endif

#if defined(USE_LONGJMP)
#define wu_longjmp(x, y)	longjmp((x), (y))
#define wu_setjmp(x)		setjmp(x)
#ifndef JMP_BUF
#define JMP_BUF			jmp_buf
#endif
#else
#define wu_longjmp(x, y)	siglongjmp((x), (y))
#define wu_setjmp(x)		sigsetjmp((x), 1)
#ifndef JMP_BUF
#define JMP_BUF			sigjmp_buf
#endif
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64	/* may be too big */
#endif

#ifndef TRUE
#define  TRUE   1
#endif

#ifndef FALSE
#define  FALSE  !TRUE
#endif

#ifdef MAIL_ADMIN
#define MAILSERVERS 10
#define INCMAILS 10
int mailservers = 0;
char *mailserver[MAILSERVERS];
int incmails = 0;
char *incmail[INCMAILS];
char *mailfrom;
char *email(char *full_address);
FILE *SockOpen(char *host, int clientPort);
char *SockGets(FILE *sockfp, char *buf, int len);
int SockWrite(char *buf, int size, int nels, FILE *sockfp);
int SockPrintf(FILE *sockfp, char *format,...);
int SockPuts(FILE *sockfp, char *buf);
int Reply(FILE *sockfp);
int Send(FILE *sockfp, char *format,...);
#endif /* MAIL_ADMIN */

#if defined(_SCO_DS) && !defined(SIGURG)
#define SIGURG	SIGUSR1
#endif

/* File containing login names NOT to be used on this machine. Commonly used
 * to disallow uucp. */
extern int errno;

extern char *ctime(const time_t *);
#ifndef NO_CRYPT_PROTO
extern char *crypt(const char *, const char *);
#endif

extern char version[];
extern char *home;		/* pointer to home directory for glob */
extern char cbuf[];
extern off_t restart_point;
extern int yyerrorcalled;

struct SOCKSTORAGE ctrl_addr;
struct SOCKSTORAGE data_source;
struct SOCKSTORAGE data_dest;
struct SOCKSTORAGE his_addr;
struct SOCKSTORAGE pasv_addr;
struct SOCKSTORAGE vect_addr;
int route_vectored = 0;
int passive_port_min = 1024;
int passive_port_max = 65535;
int restricted_user = 0;
unsigned short data_port = 0;

#ifdef INET6
int ctrl_v4mapped = 0;
int epsv_all = 0;
int listen_v4 = 0;	/* when set, listen on IPv4 socket in standalone mode */
#endif

#ifdef VIRTUAL
char virtual_root[MAXPATHLEN];
char virtual_banner[MAXPATHLEN];
char virtual_email[MAXPATHLEN];

char virtual_hostname[MAXHOSTNAMELEN];
char virtual_address[MAXHOSTNAMELEN];

extern int virtual_mode;
extern int virtual_ftpaccess;
#endif

#ifdef QUOTA
extern struct dqblk quota;
#endif

#if defined(USE_GSS)
#include "gssutil.h"

extern gss_info_t gss_info;

int allow_ccc = 0;
int ccc_ok = 0;
extern char *cur_auth_type;
#endif /* USE_GSS */

int data;
jmp_buf errcatch;
JMP_BUF urgcatch;
int logged_in = 0;
struct passwd *pw;
char chroot_path[MAXPATHLEN];
int debug = 0;
int disable_rfc931 = 0;
extern unsigned int timeout_idle;
extern unsigned int timeout_maxidle;
extern unsigned int timeout_data;
extern unsigned int timeout_accept;
extern unsigned int timeout_connect;

/* previously defaulted to 1, and -l or -L set them to 1, so that there was
   no way to turn them *off*!  Changed so that the manpage reflects common
   sense.  -L is way noisy; -l we'll change to be "just right".  _H */
int logging = 0;
int log_commands = 0;
int log_security = 0;
int syslogmsg = 0;
static int wtmp_logging = 1;

#ifdef SECUREOSF
#define SecureWare		/* Does this mean it works for all SecureWare? */
#endif

#ifdef HPUX_10_TRUSTED
#include <hpsecurity.h>
#endif

#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
#include <prot.h>
#endif

int anonymous = 1;
int guest;
int type;
int form;
int stru;			/* avoid C keyword */
int mode;
int usedefault = 1;		/* for data transfers */
int pdata = -1;			/* for passive mode */
int transflag;
int ftwflag;
off_t file_size;
off_t byte_count;
int TCPwindowsize = 0;		/* 0 = use system default */
size_t sendbufsz;		/* buffer size to use when sending data */
size_t recvbufsz;		/* buffer size to use when receiving data */

#ifdef TRANSFER_COUNT
off_t data_count_total = 0;	/* total number of data bytes */
off_t data_count_in = 0;
off_t data_count_out = 0;
off_t byte_count_total = 0;	/* total number of general traffic */
off_t byte_count_in = 0;
off_t byte_count_out = 0;
int file_count_total = 0;	/* total number of data files */
int file_count_in = 0;
int file_count_out = 0;
int xfer_count_total = 0;	/* total number of transfers */
int xfer_count_in = 0;
int xfer_count_out = 0;
#ifdef TRANSFER_LIMIT
int file_limit_raw_in = 0;
int file_limit_raw_out = 0;
int file_limit_raw_total = 0;
int file_limit_data_in = 0;
int file_limit_data_out = 0;
int file_limit_data_total = 0;
off_t data_limit_raw_in = 0;
off_t data_limit_raw_out = 0;
off_t data_limit_raw_total = 0;
off_t data_limit_data_in = 0;
off_t data_limit_data_out = 0;
off_t data_limit_data_total = 0;
#ifdef RATIO /* 1998/08/04 K.Wakui */
#define TRUNC_KB(n)   ((n)/1024+(((n)%1024)?1:0))
off_t   total_free_dl = 0;
int     upload_download_rate = 0;
int     freefile;
int     is_downloadfree( char * );
#endif /* RATIO */
#endif
#endif

int retrieve_is_data = 1;	/* !0=data, 0=general traffic -- for 'ls' */
char LastFileTransferred[MAXPATHLEN] = "";

static char *RootDirectory = NULL;

#if !defined(CMASK) || CMASK == 0
#undef CMASK
#define CMASK 022
#endif
mode_t defumask = CMASK;	/* default umask value */
#ifdef ALTERNATE_CD
char defhome[] = "/";
#endif
char tmpline[7];
char hostname[MAXHOSTNAMELEN];
char remotehost[MAXHOSTNAMELEN];
char remoteaddr[MAXHOSTNAMELEN];
char *remoteident = "[nowhere yet]";
int rhlookup = TRUE;		/* when TRUE lookup the remote hosts name */

#if defined(SOLARIS_2) && !defined(NAME_SERVICE_DOOR)
#define NAME_SERVICE_DOOR "/var/run/name_service_door"
#endif

#if defined(SOLARIS_2)
int close_nsdoor(void *cb_data, int fd);
void cleanup_nscd();
#endif

/* log failures         27-apr-93 ehk/bm */
#define MAXUSERNAMELEN	256
char the_user[MAXUSERNAMELEN];

/* Access control and logging passwords */
/* OFF by default.  _H */
int use_accessfile = 0;
char guestpw[MAXHOSTNAMELEN];
char privatepw[MAXHOSTNAMELEN];
int nameserved = 0;
extern char authuser[];
extern int authenticated;
extern int keepalive;

/* File transfer logging (xferlog) */
int xferlog = 0;
int log_outbound_xfers = 0;
int log_incoming_xfers = 0;
char logfile[MAXPATHLEN];

/* Allow use of lreply(); this is here since some older FTP clients don't
 * support continuation messages.  In violation of the RFCs... */
int dolreplies = 1;

/* Spontaneous reply text.  To be sent along with next reply to user */
char *autospout = NULL;
int autospout_free = 0;

/* allowed on-the-fly file manipulations (compress, tar) */
int mangleopts = 0;

/* number of login failures before attempts are logged and FTP *EXITS* */
int lgi_failure_threshold = 5;

/* Timeout intervals for retrying connections to hosts that don't accept PORT
 * cmds.  This is a kludge, but given the problems with TCP... */
#define SWAITMAX    90		/* wait at most 90 seconds */
#define SWAITINT    5		/* interval between retries */

int swaitmax = SWAITMAX;
int swaitint = SWAITINT;

SIGNAL_TYPE lostconn(int sig);
SIGNAL_TYPE randomsig(int sig);
SIGNAL_TYPE myoob(int sig);
FILE *getdatasock(char *mode);
FILE *dataconn(char *name, off_t size, char *mode);
void setproctitle(const char *fmt,...);
void initsetproctitle(int, char **, char **);
void reply(int, char *fmt,...);
void lreply(int, char *fmt,...);

#ifndef HAVE_VSNPRINTF
extern int vsnprintf(char *, size_t, const char *, va_list);
#endif

#ifndef HAVE_SNPRINTF
extern int snprintf(char *, size_t, const char *,...);
#endif

#ifdef NEED_SIGFIX
extern sigset_t block_sigmask;	/* defined in sigfix.c */
#endif

char proctitle[BUFSIZ];		/* initial part of title */

#if defined(SKEY) && defined(OPIE)
#error YOU SHOULD NOT HAVE BOTH SKEY AND OPIE DEFINED!!!!!
#endif

#ifdef SKEY
#include <skey.h>
int pwok = 0;
#endif

#ifdef OPIE
#include <opie.h>
int pwok = 0;
int af_pwok = 0;
struct opie opiestate;
#endif

#ifdef KERBEROS
void init_krb();
void end_krb();
char krb_ticket_name[100];
#endif /* KERBEROS */

#ifdef ULTRIX_AUTH
int ultrix_check_pass(char *passwd, char *xpasswd);
#endif

#ifdef USE_PAM
#if defined(ULTRIX_AUTH) || defined(SECUREOSF) || defined(KERBEROS) || defined(SKEY) || defined (OPIE) || defined (BSD_AUTH)
#error No other auth methods are allowed with PAM.
#endif
#include <security/pam_appl.h>
static int pam_check_pass(char *user, char *passwd);
pam_handle_t *pamh;
#endif

#ifndef INTERNAL_LS
/* ls program commands and options for lreplies on and off */
char ls_long[BUFSIZ * 2];
char ls_short[BUFSIZ * 2];
char ls_plain[BUFSIZ * 2];
#endif

#define FTPD_OPTS	":4aAdiIlLoP:qQr:t:T:u:vVwWxX"
#if defined(DAEMON)
#  define DAEMON_OPTS	"p:sS"
#else /* !(defined(DAEMON)) */
#  define DAEMON_OPTS
#endif /* !(defined(DAEMON)) */
#if defined(USE_GSS)
#  define GSS_OPTS	"CK"
#else /* !(defined(USE_GSS)) */
#  define GSS_OPTS
#endif /* !(defined(USE_GSS)) */

/* Some systems use one format, some another.  This takes care of the garbage */
#ifndef L_FORMAT		/* Autoconf detects this... */
#if (defined(BSD) && (BSD >= 199103)) && !defined(LONGOFF_T)
#define L_FORMAT "qd"
#else
#ifdef _AIX42
#define L_FORMAT "lld"
#else
#ifdef SOLARIS_2
#define L_FORMAT "ld"
#else
#define L_FORMAT "d"
#endif
#endif
#endif
#endif

#ifdef DAEMON
int be_daemon = 0;		/* Run standalone? */
int daemon_port = 0;
static void do_daemon(void);
#endif
int Bypass_PID_Files = 0;

#ifdef OTHER_PASSWD
#include "getpwnam.h"
char _path_passwd[MAXPATHLEN];
#ifdef SHADOW_PASSWORD
char _path_shadow[MAXPATHLEN];
#endif
#endif
#if defined(USE_PAM) && defined(OTHER_PASSWD)
int use_pam = 1;
#else
int use_pam = 0;
#endif

void print_copyright(void);
char *mapping_getcwd(char *path, size_t size);

void dolog(struct SOCKSTORAGE *);

#ifdef THROUGHPUT
extern void throughput_calc(char *, int *, double *);
extern void throughput_adjust(char *);
#endif

time_t login_time;
time_t limit_time = 0;

int regexmatch(char *name, char *rgexp);

int pasv_allowed(char *remoteaddr);
int port_allowed(char *remoteaddr);

#if sparc && !__svr4__
int fclose(FILE *);
#endif

static SIGNAL_TYPE alarm_signal(int sig)
{
}

static FILE *draconian_FILE = NULL;

static SIGNAL_TYPE draconian_alarm_signal(int sig)
{
    if (draconian_FILE != NULL) {
	fclose(draconian_FILE);
	draconian_FILE = NULL;
    }
    (void) signal(SIGALRM, draconian_alarm_signal);
}

static void socket_flush_wait(FILE *file)
{
    static int flushwait = TRUE;
    static int first_time = TRUE;
    char c;
    int set;
    int fd = fileno(file);
    int serrno = errno;
    struct aclmember *entry;

    if (first_time) {
	entry = NULL;
	/* flush-wait yes|no [typelist] */
	while (getaclentry("flush-wait", &entry)) {
	    if (!ARG0)
		continue;
	    if (strcasecmp(ARG0, "yes") == 0)
		set = TRUE;
	    else if (strcasecmp(ARG0, "no") == 0)
		set = FALSE;
	    else
		continue;

	    if (!ARG1)
		flushwait = set;
	    else if (type_match(ARG1)) {
		flushwait = set;
		break;
	    }
	}
	first_time = FALSE;
    }
    if (flushwait) {
	if (draconian_FILE != NULL)
	    shutdown(fd, 1);
	if (draconian_FILE != NULL)
	    read(fd, &c, 1);
    }
    errno = serrno;
/*
 * GAL - the read() here should be checked to ensure it returned 0 (indicating
 * EOF) or -1 (an error occurred).  Anything else (real data) is a protocol
 * error.
 */
}

static int IPClassOfService(const char *type)
{
    int ipcos = -1, value;
    char *endp;
    struct aclmember *entry = NULL;

    /* ipcos control|data <value> [<typelist>] */
    while (getaclentry("ipcos", &entry)) {
	if (ARG0 && ARG1) {
	    if (strcasecmp(type, ARG0) == 0) {
		if (!ARG2) {
		    errno = 0;
		    value = (int) strtol(ARG1, &endp, 0);
		    if ((errno == 0) && (value >= 0) && (*endp == '\0'))
			ipcos = value;
		}
		else if (type_match(ARG2)) {
		    errno = 0;
		    value = (int) strtol(ARG1, &endp, 0);
		    if ((errno == 0) && (value >= 0) && (*endp == '\0')) {
			ipcos = value;
			break;
		    }
		}
	    }
	}
    }
    return ipcos;
}

int main(int argc, char **argv, char **envp)
{
#if defined(UNIXWARE) || defined(AIX)
    size_t addrlen;
#else
    int addrlen;
#endif
    int on = 1;
    int cos;
    int c;
#ifndef INTERNAL_LS
    int which;
#endif
    extern int optopt;
    extern char *optarg;
    char *hp;
    struct aclmember *entry;
#ifdef VIRTUAL
#if defined(UNIXWARE) || defined(AIX)
    size_t virtual_len;
#else
    int virtual_len;
#endif
    struct SOCKSTORAGE virtual_addr;
#endif
    struct servent *serv;

#ifdef AUX
    setcompat(COMPAT_POSIX | COMPAT_BSDSETUGID);
#endif

    closelog();
#ifdef FACILITY
    openlog("ftpd", LOG_PID | LOG_NDELAY, FACILITY);
#else
    openlog("ftpd", LOG_PID);
#endif

#ifdef SecureWare
    setluid(1);			/* make sure there is a valid luid */
    set_auth_parameters(argc, argv);
    setreuid(0, 0);
#endif
#if defined(M_UNIX) && !defined(_M_UNIX)
    res_init();			/* bug in old (1.1.1) resolver     */
    _res.retrans = 20;		/* because of fake syslog in 3.2.2 */
    setlogmask(LOG_UPTO(LOG_INFO));
#endif

    while ((c = getopt(argc, argv, FTPD_OPTS DAEMON_OPTS GSS_OPTS)) != -1) {
	switch (c) {

	case '4':
#ifdef INET6
	    listen_v4 = 1;
#endif
	    break;

	case 'a':
	    use_accessfile = 1;
	    break;

	case 'A':
	    use_accessfile = 0;
	    break;

	case 'v':
	    debug = 1;
	    break;

	case 'd':
	    debug = 1;
	    break;

#if defined(USE_GSS)
	case 'C':
	    gss_info.want_creds = 1;
	    break;

	case 'K':
	    gss_info.must_gss_auth = 1;
	    break;
#endif /* USE_GSS */

	case 'l':
	    logging = 1;
	    break;

	case 'L':
	    log_commands = 3;
	    break;

	case 'i':
	    log_incoming_xfers = 3;
	    break;

	case 'I':
	    disable_rfc931 = 1;
	    break;

	case 'o':
	    log_outbound_xfers = 3;
	    break;

	case 'q':
	    Bypass_PID_Files = 0;
	    break;

	case 'Q':
	    Bypass_PID_Files = 1;
	    break;

	case 'r':
	    if ((optarg != NULL) && (optarg[0] != '\0')) {
		RootDirectory = malloc(strlen(optarg) + 1);
		if (RootDirectory != NULL)
		    strcpy(RootDirectory, optarg);
	    }
	    break;

	case 'P':
	    data_port = htons(atoi(optarg));
	    break;

#ifdef DAEMON
	case 'p':
	    daemon_port = atoi(optarg);
	    break;

	case 's':
	    be_daemon = 1;
	    break;

	case 'S':
	    be_daemon = 2;
	    break;
#endif /* DAEMON */

	case 't':
	    timeout_idle = atoi(optarg);
	    if (timeout_maxidle < timeout_idle)
		timeout_maxidle = timeout_idle;
	    break;

	case 'T':
	    timeout_maxidle = atoi(optarg);
	    if (timeout_idle > timeout_maxidle)
		timeout_idle = timeout_maxidle;
	    break;

	case 'u':
	    {
		unsigned int val = 0;

		while (*optarg && *optarg >= '0' && *optarg <= '7')
		    val = val * 8 + *optarg++ - '0';
		if (*optarg || val > 0777)
		    syslog(LOG_ERR, "bad value for -u");
		else
		    defumask = val;
		break;
	    }

	case 'V':
	    print_copyright();
	    exit(0);
	    /* NOTREACHED */
	case 'w':
	    wtmp_logging = 1;
	    break;

	case 'W':
	    wtmp_logging = 0;
	    break;

	case 'x':
	    syslogmsg = 2;
	    break;

	case 'X':
	    syslogmsg = 1;
	    break;

	case ':':
	    syslog(LOG_ERR, "option -%c requires an argument", optopt);
	    break;

	default:
	    syslog(LOG_ERR, "unknown option -%c ignored", optopt);
	    break;
	}
    }
    initsetproctitle(argc, argv, envp);
    (void) freopen(_PATH_DEVNULL, "w", stderr);

    /* Checking for random signals ... */
#ifdef NEED_SIGFIX
    sigemptyset(&block_sigmask);
#endif
#ifndef SIG_DEBUG
#ifdef SIGHUP
    (void) signal(SIGHUP, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGHUP);
#endif
#endif
#ifdef SIGINT
    (void) signal(SIGINT, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGINT);
#endif
#endif
#ifdef SIGQUIT
    (void) signal(SIGQUIT, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGQUIT);
#endif
#endif
#ifdef SIGILL
    (void) signal(SIGILL, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGILL);
#endif
#endif
#ifdef SIGTRAP
    (void) signal(SIGTRAP, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGTRAP);
#endif
#endif
#ifdef SIGIOT
    (void) signal(SIGIOT, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGIOT);
#endif
#endif
#ifdef SIGEMT
    (void) signal(SIGEMT, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGEMT);
#endif
#endif
#ifdef SIGFPE
    (void) signal(SIGFPE, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGFPE);
#endif
#endif
#ifdef SIGKILL
    (void) signal(SIGKILL, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGKILL);
#endif
#endif
#ifdef SIGBUS
    (void) signal(SIGBUS, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGBUS);
#endif
#endif
#ifdef SIGSEGV
    (void) signal(SIGSEGV, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGSEGV);
#endif
#endif
#ifdef SIGSYS
    (void) signal(SIGSYS, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGSYS);
#endif
#endif
#ifdef SIGALRM
    (void) signal(SIGALRM, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGALRM);
#endif
#endif
#ifdef SIGSTOP
    (void) signal(SIGSTOP, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGSTOP);
#endif
#endif
#ifdef SIGTSTP
    (void) signal(SIGTSTP, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGTSTP);
#endif
#endif
#ifdef SIGTTIN
    (void) signal(SIGTTIN, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGTTIN);
#endif
#endif
#ifdef SIGTTOU
    (void) signal(SIGTTOU, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGTTOU);
#endif
#endif
#ifdef SIGIO
    (void) signal(SIGIO, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGIO);
#endif
#endif
#ifdef SIGXCPU
    (void) signal(SIGXCPU, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGXCPU);
#endif
#endif
#ifdef SIGXFSZ
    (void) signal(SIGXFSZ, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGXFSZ);
#endif
#endif
#ifdef SIGWINCH
    (void) signal(SIGWINCH, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGWINCH);
#endif
#endif
#ifdef SIGVTALRM
    (void) signal(SIGVTALRM, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGVTALRM);
#endif
#endif
#ifdef SIGPROF
    (void) signal(SIGPROF, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGPROF);
#endif
#endif
#ifdef SIGUSR1
    (void) signal(SIGUSR1, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGUSR1);
#endif
#endif
#ifdef SIGUSR2
    (void) signal(SIGUSR2, randomsig);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGUSR2);
#endif
#endif

#ifdef SIGPIPE
    (void) signal(SIGPIPE, lostconn);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGPIPE);
#endif
#endif
#ifdef SIGCHLD
    (void) signal(SIGCHLD, SIG_IGN);
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGCHLD);
#endif
#endif

#ifdef SIGURG
    if (signal(SIGURG, myoob) == SIG_ERR)
	syslog(LOG_ERR, "signal: %m");
#ifdef NEED_SIGFIX
    sigaddset(&block_sigmask, SIGURG);
#endif
#endif
#endif /* SIG_DEBUG */

#ifdef VIRTUAL
    virtual_root[0] = '\0';
    virtual_banner[0] = '\0';
#endif

    setup_paths();

#ifdef OTHER_PASSWD
    strcpy(_path_passwd, "/etc/passwd");
#ifdef SHADOW_PASSWORD
    strcpy(_path_shadow, "/etc/shadow");
#endif
#endif

    access_init();

#ifdef DAEMON
    if (be_daemon != 0)
	do_daemon();
    else {
#endif
	addrlen = sizeof(his_addr);
	if (getpeername(0, (struct sockaddr *) &his_addr, &addrlen) < 0) {
	    syslog(LOG_ERR, "getpeername: %m");
#ifndef DEBUG
	    exit(1);
#endif
	}
#ifdef DAEMON
    }
#endif
    addrlen = sizeof(ctrl_addr);
    if (getsockname(0, (struct sockaddr *) &ctrl_addr, &addrlen) < 0) {
	syslog(LOG_ERR, "getsockname: %m");
#ifndef DEBUG
	exit(1);
#endif
    }
    /* Sanity check */
    if ((SOCK_FAMILY(ctrl_addr) != AF_INET)
#ifdef INET6
        && (SOCK_FAMILY(ctrl_addr) != AF_INET6)
#endif
	) {
	syslog(LOG_ERR, "control connection address family (%d) not supported.",
	       SOCK_FAMILY(ctrl_addr));
#ifndef DEBUG
	exit(1);
#endif
    }
#ifdef SOLARIS_BSM_AUDIT
    /* Set audit characteristics */
    if (audit_settid(0)) {
	syslog(LOG_ERR, "audit failure");
	exit(1);
    }
#endif
#ifdef INET6
    /* IP_TOS is an IPv4 socket option */
    if (SOCK_FAMILY(ctrl_addr) == AF_INET)
#endif
    if ((cos = IPClassOfService("control")) >= 0) {
	if (setsockopt(0, IPPROTO_IP, IP_TOS, (char *) &cos, sizeof(int)) < 0)
	    syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
    }

#ifdef TCP_NODELAY
    /*
     * Disable Nagle on the control channel so that we don't have to wait
     * for peer's ACK before issuing our next reply.
     */
    if (setsockopt(0, IPPROTO_TCP, TCP_NODELAY, &on, sizeof (on)) < 0)
	syslog(LOG_WARNING, "control setsockopt TCP_NODELAY: %m");
#endif

    if (keepalive)
	if (setsockopt(0, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on)) < 0)
	    syslog(LOG_ERR, "setsockopt SO_KEEPALIVE %m");

    /* Try to handle urgent data inline */
#ifdef SO_OOBINLINE
    if (setsockopt(0, SOL_SOCKET, SO_OOBINLINE, (char *) &on, sizeof(int)) < 0)
	    syslog(LOG_ERR, "setsockopt (SO_OOBINLINE): %m");
#endif

#ifdef  F_SETOWN
    if (fcntl(fileno(stdin), F_SETOWN, getpid()) == -1)
	syslog(LOG_ERR, "fcntl F_SETOWN: %m");
#elif defined(SIOCSPGRP)
    {
	int pid;
	pid = getpid();
	if (ioctl(fileno(stdin), SIOCSPGRP, &pid) == -1)
	    syslog(LOG_ERR, "ioctl SIOCSPGRP: %m");
    }
#endif

#ifdef INET6
    if ((SOCK_FAMILY(ctrl_addr) == AF_INET6) &&
	IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)&(ctrl_addr))->sin6_addr))
	ctrl_v4mapped = 1;
#endif

    if (data_port == 0) {
	serv = getservbyname("ftp-data", "tcp");
	if (serv != NULL)
	    data_port = serv->s_port;
	else
	    data_port = htons(ntohs(SOCK_PORT(ctrl_addr)) - 1);
    }

    if (RootDirectory != NULL) {
	if ((chroot(RootDirectory) < 0)
	    || (chdir("/") < 0)) {
	    syslog(LOG_ERR, "Cannot chroot to initial directory, aborting.");
	    exit(1);
	}
    }

    load_timeouts();

    /* set resolver options */
    set_res_options();

    dolog(&his_addr);
    /* Set up default state */
    data = -1;
    type = TYPE_A;
    form = FORM_N;
    stru = STRU_F;
    mode = MODE_S;
    tmpline[0] = '\0';
    yyerrorcalled = 0;

    entry = (struct aclmember *) NULL;
    if ((getaclentry("hostname", &entry)) && ARG0) {
	(void) strncpy(hostname, ARG0, sizeof(hostname));
	hostname[sizeof(hostname) - 1] = '\0';
    }
    else {
#ifdef HAVE_SYSINFO
	sysinfo(SI_HOSTNAME, hostname, sizeof(hostname));
#else
	(void) gethostname(hostname, sizeof(hostname));
#endif
/* set the FQDN here */
	hp = wu_gethostbyname(hostname);
	if (hp) {
	    (void) strncpy(hostname, hp, sizeof(hostname));
	    hostname[sizeof(hostname) - 1] = '\0';
	}
    }
    route_vectored = routevector();
    conv_init();

#ifdef MAIL_ADMIN
    incmails = 0;
    mailfrom = NULL;
#endif /* MAIL_ADMIN */
#ifdef VIRTUAL
    /*
       ** If virtual_mode is set at this point then an alternate ftpaccess
       ** is in use.  Otherwise we need to check the Master ftpaccess file
       ** to see if the site is only using the "virtual" directives to
       ** specify virtual site directives.
       **
       ** In this manner an admin can put a virtual site in the ftpservers
       ** file if they need expanded configuration support or can use the
       ** minimal root/banner/logfile if they do not need any more than that.
     */

    if (virtual_mode) {
	/* Get the root of the virtual server directory */
	entry = (struct aclmember *) NULL;
	if (getaclentry("root", &entry)) {
	    if (ARG0)
		strcpy(virtual_root, ARG0);
	}

	/* Get the logfile to use */
	entry = (struct aclmember *) NULL;
	if (getaclentry("logfile", &entry)) {
	    if (ARG0)
		strcpy(logfile, ARG0);
	}
    }
    else {
	virtual_hostname[0] = '\0';
	virtual_address[0] = '\0';
	virtual_len = sizeof(virtual_addr);
	if (getsockname(0, (struct sockaddr *) &virtual_addr, &virtual_len) == 0) {
	    strcpy(virtual_address, inet_stop(&virtual_addr));
	    wu_gethostbyaddr(&virtual_addr, virtual_hostname, sizeof(virtual_hostname));
	    entry = (struct aclmember *) NULL;
	    while (getaclentry("virtual", &entry)) {
		if (!ARG0 || !ARG1 || !ARG2)
		    continue;
		if (hostmatch(ARG0, virtual_address, virtual_hostname)) {
		    if (!strcasecmp(ARG1, "root")) {
			if (debug)
			    syslog(LOG_DEBUG, "VirtualFTP Connect to: %s [%s]",
				   virtual_hostname, virtual_address);
			virtual_mode = 1;
			strncpy(virtual_root, ARG2, sizeof(virtual_root));
			virtual_root[sizeof(virtual_root) - 1] = '\0';
			/* reset hostname to this virtual name */
			(void) strcpy(hostname, virtual_hostname);
			virtual_email[0] = '\0';
		    }
		    if (!strcasecmp(ARG1, "banner")) {
			strncpy(virtual_banner, ARG2, sizeof(virtual_banner));
			virtual_banner[sizeof(virtual_banner) - 1] = '\0';
		    }
		    if (!strcasecmp(ARG1, "logfile")) {
			strncpy(logfile, ARG2, sizeof(logfile));
			logfile[sizeof(logfile) - 1] = '\0';
		    }
		    if (!strcasecmp(ARG1, "hostname")) {
			strncpy(hostname, ARG2, sizeof(hostname));
			hostname[sizeof(hostname) - 1] = '\0';
		    }
		    if (!strcasecmp(ARG1, "email")) {
			strncpy(virtual_email, ARG2, sizeof(virtual_email));
			virtual_email[sizeof(virtual_email) - 1] = '\0';
		    }
#ifdef OTHER_PASSWD
		    if (!strcasecmp(ARG1, "passwd")) {
			strncpy(_path_passwd, ARG2, sizeof(_path_passwd));
			_path_passwd[sizeof(_path_passwd) - 1] = '\0';
#ifdef USE_PAM
			use_pam = 0;
#endif
		    }
#ifdef SHADOW_PASSWORD
		    if (!strcasecmp(ARG1, "shadow")) {
			strncpy(_path_shadow, ARG2, sizeof(_path_shadow));
			_path_shadow[sizeof(_path_shadow) - 1] = '\0';
#ifdef USE_PAM
			use_pam = 0;
#endif
		    }
#endif
#endif
#ifdef MAIL_ADMIN
		    if (mailfrom == NULL)
			if (!strcasecmp(ARG1, "mailfrom")) {
			    mailfrom = strdup(ARG2);
			}
		    if (!strcasecmp(ARG1, "incmail")) {
			if (incmails < INCMAILS)
			    incmail[incmails++] = strdup(ARG2);
		    }
#endif
		}
	    }
	    if (!virtual_mode) {
		entry = (struct aclmember *) NULL;
		while (getaclentry("defaultserver", &entry)) {
		    if (!ARG0 || !ARG1)
			continue;
#ifdef MAIL_ADMIN
		    if (mailfrom == NULL)
			if (!strcasecmp(ARG0, "mailfrom")) {
			    mailfrom = strdup(ARG1);
			}
		    if (!strcasecmp(ARG0, "incmail")) {
			if (incmails < INCMAILS)
			    incmail[incmails++] = strdup(ARG1);
		    }
#endif
		}
	    }
	}
    }

#ifdef VIRTUAL_DEBUG
    lreply(220, "_path_ftpaccess == %s", _path_ftpaccess);
    lreply(220, "_path_ftpusers == %s", _path_ftpusers);
    lreply(220, "_path_ftphosts == %s", _path_ftphosts);
    lreply(220, "_path_private == %s", _path_private);
    lreply(220, "_path_cvt == %s", _path_cvt);
    if (virtual_mode) {
	if (virtual_ftpaccess)
	    lreply(220, "VIRTUAL Mode: Using %s specific %s access file",
		   hostname, _path_ftpaccess);
	else
	    lreply(220, "VIRTUAL Mode: Using Master access file %s",
		   _path_ftpaccess);

	lreply(220, "virtual_root == %s", virtual_root);
	if (!virtual_ftpaccess)
	    lreply(220, "virtual_banner == %s", virtual_banner);
    }
    lreply(220, "logfile == %s", logfile);
#endif
#endif

    if (is_shutdown(1, 1) != 0) {
	syslog(LOG_INFO, "connection refused (server shut down) from %s",
	       remoteident);
	reply(500, "%s FTP server shut down -- please try again later.",
	      hostname);
	exit(0);
    }

#ifdef OPIE
    af_pwok = opieaccessfile(remotehost);
#endif

    /* check permitted access based on name and address lookup of remote host */
    if (!check_rhost_reverse()) {
	exit(0);
    }
    if (!check_rhost_matches()) {
	exit(0);
    }

    show_banner(220);

#ifndef INTERNAL_LS
    entry = (struct aclmember *) NULL;
    if (getaclentry("lslong", &entry) && ARG0 && (int) strlen(ARG0) > 0) {
	strcpy(ls_long, ARG0);
	for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
	    strcat(ls_long, " ");
	    strcat(ls_long, ARG[which]);
	}
    }
    else {
#if defined(SVR4) || defined(ISC)
#if defined(AIX) || defined(SOLARIS_2)
	strcpy(ls_long, "/bin/ls -lA");
#else
	strcpy(ls_long, "/bin/ls -la");
#endif
#else
	strcpy(ls_long, "/bin/ls -lgA");
#endif
    }
    strcat(ls_long, " %s");

    entry = (struct aclmember *) NULL;
    if (getaclentry("lsshort", &entry) && ARG0 && (int) strlen(ARG0) > 0) {
	strcpy(ls_short, ARG0);
	for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
	    strcat(ls_short, " ");
	    strcat(ls_short, ARG[which]);
	}
    }
    else {
#if defined(SVR4) || defined(ISC)
#if defined(AIX) || defined(SOLARIS_2)
	strcpy(ls_short, "/bin/ls -lA");
#else
	strcpy(ls_short, "/bin/ls -la");

#endif
#else
	strcpy(ls_short, "/bin/ls -lgA");
#endif
    }
    strcat(ls_short, " %s");

    entry = (struct aclmember *) NULL;
    if (getaclentry("lsplain", &entry) && ARG0 && (int) strlen(ARG0) > 0) {
	strcpy(ls_plain, ARG0);
	for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
	    strcat(ls_plain, " ");
	    strcat(ls_plain, ARG[which]);
	}
    }
    else
	strcpy(ls_plain, "/bin/ls");
    strcat(ls_plain, " %s");
#endif /* ! INTERNAL_LS */
#ifdef MAIL_ADMIN
    mailservers = 0;
    entry = (struct aclmember *) NULL;
    while (getaclentry("mailserver", &entry) && ARG0 && mailservers < MAILSERVERS)
	mailserver[mailservers++] = strdup(ARG0);
    if (mailservers == 0)
	mailserver[mailservers++] = strdup("localhost");
    if (incmails == 0) {
	entry = (struct aclmember *) NULL;
	while (getaclentry("incmail", &entry) && ARG0 && incmails < INCMAILS)
	    incmail[incmails++] = strdup(ARG0);
    }
    if (mailfrom == NULL) {
	entry = (struct aclmember *) NULL;
	if (getaclentry("mailfrom", &entry) && ARG0)
	    mailfrom = strdup(ARG0);
	else
	    mailfrom = strdup("wu-ftpd");
    }
#endif /* MAIL_ADMIN */
    {
#define OUTPUT_LEN (BUFSIZ * 2)
	int version_option = 0;
	char output_text[OUTPUT_LEN + 1];
	int which;

	entry = NULL;
	if (getaclentry("greeting", &entry) && ARG0) {
	    if (!strcasecmp(ARG0, "full"))
		version_option = 0;
	    else if (!strcasecmp(ARG0, "text") && ARG1)
		version_option = 3;
	    else if (!strcasecmp(ARG0, "terse"))
		version_option = 2;
	    else if (!strcasecmp(ARG0, "brief"))
		version_option = 1;
	}
	switch (version_option) {
	default:
	    reply(220, "%s FTP server (%s) ready.", hostname, version);
	    break;
	case 1:
	    reply(220, "%s FTP server ready.", hostname);
	    break;
	case 2:
	    reply(220, "FTP server ready.");
	    break;
	case 3:
	    output_text[0] = '\0';
	    for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
		if (which > 1)
		    (void) strlcat(output_text, " ", sizeof(output_text));
		(void) strlcat(output_text, ARG[which], sizeof(output_text));
	    }
	    reply(220, "%s", output_text);
	    break;
	}
    }
    (void) setjmp(errcatch);

    for (;;)
	(void) yyparse();
    /* NOTREACHED */
}


SIGNAL_TYPE randomsig(int sig)
{
#ifdef HAVE_SIGLIST
    syslog(LOG_ERR, "exiting on signal %d: %s", sig, sys_siglist[sig]);
#else
    syslog(LOG_ERR, "exiting on signal %d", sig);
#endif
    chdir("/");
    signal(SIGIOT, SIG_DFL);
    signal(SIGILL, SIG_DFL);
    exit(1);
    /* dologout(-1); *//* NOTREACHED */
}

SIGNAL_TYPE lostconn(int sig)
{
#ifdef VERBOSE_ERROR_LOGING
    syslog(LOG_INFO, "lost connection to %s", remoteident);
#else
    if (debug)
	syslog(LOG_DEBUG, "lost connection to %s", remoteident);
#endif
    dologout(-1);
}

static char ttyline[20];

#ifdef MAPPING_CHDIR
/* Keep track of the path the user has chdir'd into and respond with
 * that to pwd commands.  This is to avoid having the absolue disk
 * path returned, which I want to avoid.
 */
char mapped_path[MAXPATHLEN] = "/";

#if !defined(HAVE_GETCWD)
char *mapping_getwd(char *path)
{
    strcpy(path, mapped_path);
    return path;
}
#endif /* !defined(HAVE_GETCWD) */ 

char *mapping_getcwd(char *path, size_t size)
{
    (void) strlcpy(path, mapped_path, size);
    return path;
}

/* Make these globals rather than local to mapping_chdir to avoid stack overflow */
char pathspace[MAXPATHLEN];
char old_mapped_path[MAXPATHLEN];

void do_elem(char *dir)
{
    /* . */
    if (dir[0] == '.' && dir[1] == '\0') {
	/* ignore it */
	return;
    }

    /* .. */
    if (dir[0] == '.' && dir[1] == '.' && dir[2] == '\0') {
	char *last;
	/* lop the last directory off the path */
	if ((last = strrchr(mapped_path, '/'))) {
	    /* If start of pathname leave the / */
	    if (last == mapped_path)
		last++;
	    *last = '\0';
	}
	return;
    }

    /* append the dir part with a leading / unless at root */
    if (!(mapped_path[0] == '/' && mapped_path[1] == '\0'))
	(void) strlcat(mapped_path, "/", sizeof(mapped_path));
    (void) strlcat(mapped_path, dir, sizeof(mapped_path));
}

int mapping_chdir(char *orig_path)
{
    int ret;
    char *sl, *path;

    (void) strlcpy(old_mapped_path, mapped_path, sizeof(old_mapped_path));
    (void) strlcpy(pathspace, orig_path, sizeof(pathspace));
    path = pathspace;

    /* / at start of path, set the start of the mapped_path to / */
    if (path[0] == '/') {
	mapped_path[0] = '/';
	mapped_path[1] = '\0';
	path++;
    }

    while ((sl = strchr(path, '/'))) {
	char *dir;
	dir = path;
	*sl = '\0';
	path = sl + 1;
	if (*dir)
	    do_elem(dir);
	if (*path == '\0')
	    break;
    }
    if (*path)
	do_elem(path);

    if ((ret = chdir(mapped_path)) < 0) {
	(void) strlcpy(mapped_path, old_mapped_path, sizeof(mapped_path));
    }

    return ret;
}
/* From now on use the mapping version */

#define chdir(d) mapping_chdir(d)
#define getwd(d) mapping_getwd(d)
#define getcwd(d,u) mapping_getcwd((d),(u))

#endif /* MAPPING_CHDIR */

/* Helper function for sgetpwnam(). */
char *sgetsave(char *s)
{
    char *new;

    new = (char *) malloc(strlen(s) + 1);

    if (new == NULL) {
	perror_reply(421, "Local resource failure: malloc");
	dologout(1);
	/* NOTREACHED */
    }
    (void) strcpy(new, s);
    return (new);
}

/* Save the result of a getpwnam.  Used for USER command, since the data
 * returned must not be clobbered by any other command (e.g., globbing). */
struct passwd *sgetpwnam(char *name)
{
    static struct passwd save;
    register struct passwd *p;
#ifdef M_UNIX
    struct passwd *ret = (struct passwd *) NULL;
#endif
    char *sgetsave(char *s);
#ifdef KERBEROS
    register struct authorization *q;
#endif /* KERBEROS */

#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
    struct pr_passwd *pr;
#endif

#ifdef KERBEROS
    init_krb();
    q = getauthuid(p->pw_uid);
    end_krb();
#endif /* KERBEROS */

#ifdef M_UNIX
#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
    if ((pr = getprpwnam(name)) == NULL)
	goto DONE;
#endif /* SecureWare || HPUX_10_TRUSTED */
#ifdef OTHER_PASSWD
    if ((p = bero_getpwnam(name, _path_passwd)) == NULL)
#else
    if ((p = getpwnam(name)) == NULL)
#endif
	goto DONE;
#else /* M_UNIX */
#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
    if ((pr = getprpwnam(name)) == NULL)
	return ((struct passwd *) pr);
#endif /* SecureWare || HPUX_10_TRUSTED */
#ifdef OTHER_PASSWD
    if ((p = bero_getpwnam(name, _path_passwd)) == NULL)
#else
    if ((p = getpwnam(name)) == NULL)
#endif
	return (p);
#endif /* M_UNIX */

    if (save.pw_name)
	free(save.pw_name);
    if (save.pw_gecos)
	free(save.pw_gecos);
    if (save.pw_dir)
	free(save.pw_dir);
    if (save.pw_shell)
	free(save.pw_shell);
    if (save.pw_passwd)
	free(save.pw_passwd);

    save = *p;

    save.pw_name = sgetsave(p->pw_name);

#ifdef KERBEROS
    save.pw_passwd = sgetsave(q->a_password);
#elif defined(SecureWare) || defined(HPUX_10_TRUSTED)
    if (pr->uflg.fg_encrypt && pr->ufld.fd_encrypt && *pr->ufld.fd_encrypt)
	save.pw_passwd = sgetsave(pr->ufld.fd_encrypt);
    else
	save.pw_passwd = sgetsave("");
#else
    save.pw_passwd = sgetsave(p->pw_passwd);
#endif
#ifdef SHADOW_PASSWORD
    if (p && (p->pw_passwd==NULL || strlen(p->pw_passwd)<8)) {
	struct spwd *spw;
#ifdef OTHER_PASSWD
	if ((spw = bero_getspnam(p->pw_name, _path_shadow)) != NULL) {
#else
	setspent();
	if ((spw = getspnam(p->pw_name)) != NULL) {
#endif
	    int expired = 0;
	    /*XXX Does this work on all Shadow Password Implementations? */
	    /* it is supposed to work on Solaris 2.x */
	    time_t now;
	    long today;

	    now = time((time_t *) 0);
	    today = now / (60 * 60 * 24);

	    if ((spw->sp_expire > 0) && (spw->sp_expire < today))
		expired++;
	    if ((spw->sp_max > 0) && (spw->sp_lstchg > 0) &&
		(spw->sp_lstchg + spw->sp_max < today))
		expired++;
	    free(save.pw_passwd);
	    save.pw_passwd = sgetsave(expired ? "" : spw->sp_pwdp);
	}
/* Don't overwrite the password if the shadow read fails, getpwnam() is NIS
   aware but getspnam() is not. */
/* Shadow passwords are optional on Linux.  --marekm */
#if !defined(LINUX) && !defined(UNIXWARE)
	else {
	    free(save.pw_passwd);
	    save.pw_passwd = sgetsave("");
	}
#endif
/* marekm's fix for linux proc file system shadow passwd exposure problem */
#ifndef OTHER_PASSWD
	endspent();
#endif
    }
#endif
    save.pw_gecos = sgetsave(p->pw_gecos);
    save.pw_dir = sgetsave(p->pw_dir);
    save.pw_shell = sgetsave(p->pw_shell);
#ifdef M_UNIX
    ret = &save;
  DONE:
    endpwent();
#endif
#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
    endprpwent();
#endif
#ifdef M_UNIX
    return (ret);
#else
    return (&save);
#endif
}
#if defined(SKEY) && !defined(__NetBSD__)
/*
 * From Wietse Venema, Eindhoven University of Technology. 
 */
/* skey_challenge - additional password prompt stuff */

char *skey_challenge(char *name, struct passwd *pwd, int pwok)
{
    static char buf[128];
    char sbuf[40];
    struct skey skey;

    /* Display s/key challenge where appropriate. */

    if (pwd == NULL || skeychallenge(&skey, pwd->pw_name, sbuf))
	sprintf(buf, "Password required for %s.", name);
    else
	sprintf(buf, "%s %s for %s.", sbuf,
		pwok ? "allowed" : "required", name);
    return (buf);
}
#endif

int login_attempts;		/* number of failed login attempts */
int askpasswd;			/* had user command, ask for passwd */
#ifndef HELP_CRACKERS
int DenyLoginAfterPassword;
char DelayedMessageFile[MAXPATHLEN];
extern void pr_mesg(int msgcode, char *msgfile);
#endif

#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
static int defaultserver_allow(const char *username)
{
    struct aclmember *entry = NULL;
    int which;

    while (getaclentry("defaultserver", &entry))
	if (ARG0 && !strcasecmp(ARG0, "allow"))
	    for (which = 1; (which < MAXARGS) && ARG[which]; which++)
		if (!strcasecmp(username, ARG[which]) || !strcmp("*", ARG[which]))
		    return (1);
    return (0);
}

static int defaultserver_deny(const char *username)
{
    struct aclmember *entry = NULL;
    int which;

    while (getaclentry("defaultserver", &entry))
	if (ARG0 && !strcasecmp(ARG0, "deny"))
	    for (which = 1; (which < MAXARGS) && ARG[which]; which++)
		if (!strcasecmp(username, ARG[which]) || !strcmp("*", ARG[which]))
		    return (1);
    return (0);
}

static int defaultserver_private(void)
{
    struct aclmember *entry = NULL;

    while (getaclentry("defaultserver", &entry))
	if (ARG0 && !strcasecmp(ARG0, "private"))
	    return (1);
    return (0);
}
#endif

/* USER command. Sets global passwd pointer pw if named account exists and is
 * acceptable; sets askpasswd if a PASS command is expected.  If logged in
 * previously, need to reset state.  If name is "ftp" or "anonymous", the
 * name is not in the ftpusers file, and ftp account exists, set anonymous and
 * pw, then just return.  If account doesn't exist, ask for passwd anyway.
 * Otherwise, check user requesting login privileges.  Disallow anyone who
 * does not have a standard shell as returned by getusershell().  Disallow
 * anyone mentioned in the ftpusers file to allow people such as root and
 * uucp to be avoided. */

/*
   char *getusershell();
 */
void user(char *name)
{
    char *cp;
    char *shell;
#ifdef	BSD_AUTH
    char *auth;
#endif
#if defined(USE_GSS)
    int gss_need_passwd = 1;
#endif

/* H* fix: if we're logged in at all, we can't log in again. */
    if (logged_in) {
#ifdef VERBOSE_ERROR_LOGING
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (already logged in as %s) FROM %s, %s",
	       pw->pw_name, remoteident, name);
#endif
	reply(530, "Already logged in.");
	return;
    }
#ifndef HELP_CRACKERS
    askpasswd = 1;
    DenyLoginAfterPassword = 0;
    DelayedMessageFile[0] = '\0';
#endif
#ifdef	BSD_AUTH
    if ((auth = strchr(name, ':')))
	*auth++ = 0;
#endif

#ifdef HOST_ACCESS		/* 19-Mar-93    BM              */
    if (!rhost_ok(name, remotehost, remoteaddr)) {
#ifndef HELP_CRACKERS
	DenyLoginAfterPassword = 1;
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (name in %s) FROM %s, %s",
	       _path_ftphosts, remoteident, name);
#else
	reply(530, "User %s access denied.", name);
	syslog(LOG_NOTICE,
	       "FTP LOGIN REFUSED (name in %s) FROM %s, %s",
	       _path_ftphosts, remoteident, name);
	return;
#endif
    }
#endif

    strncpy(the_user, name, MAXUSERNAMELEN - 1);

    anonymous = 0;
    guest = 0;

    if (!strcasecmp(name, "ftp") || !strcasecmp(name, "anonymous")) {
	struct aclmember *entry = NULL;
	int machineok = 1;
	char guestservername[MAXHOSTNAMELEN];
	guestservername[0] = '\0';

#ifdef NO_ANONYMOUS_ACCESS
	reply(530, "Anonymous FTP access denied.");
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (anonymous ftp not supported) FROM %s, %s",
	       remoteident, name);
	return;
#else
#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
	if (!virtual_mode && defaultserver_private()) {
#ifndef HELP_CRACKERS
	    DenyLoginAfterPassword = 1;
	    syslog(LOG_NOTICE, "FTP LOGIN REFUSED (anonymous ftp denied on default server) FROM %s, %s",
		   remoteident, name);
#else
	    reply(530, "User %s access denied.", name);
	    syslog(LOG_NOTICE,
		   "FTP LOGIN REFUSED (anonymous ftp denied on default server) FROM %s, %s",
		   remoteident, name);
	    return;
#endif
	}
#endif
	if (checkuser("ftp") || checkuser("anonymous")) {
#ifndef HELP_CRACKERS
	    DenyLoginAfterPassword = 1;
	    syslog(LOG_NOTICE, "FTP LOGIN REFUSED (ftp in %s) FROM %s, %s",
		   _path_ftpusers, remoteident, name);
#else
	    reply(530, "User %s access denied.", name);
	    syslog(LOG_NOTICE,
		   "FTP LOGIN REFUSED (ftp in %s) FROM %s, %s",
		   _path_ftpusers, remoteident, name);
	    return;
#endif

	    /*
	       ** Algorithm used:
	       ** - if no "guestserver" directive is present,
	       **     anonymous access is allowed, for backward compatibility.
	       ** - if a "guestserver" directive is present,
	       **     anonymous access is restricted to the machines listed,
	       **     usually the machine whose CNAME on the current domain
	       **     is "ftp"...
	       **
	       ** the format of the "guestserver" line is
	       ** guestserver [<machine1> [<machineN>]]
	       ** that is, "guestserver" will forbid anonymous access on all machines
	       ** while "guestserver ftp inf" will allow anonymous access on
	       ** the two machines whose CNAMES are "ftp.enst.fr" and "inf.enst.fr".
	       **
	       ** if anonymous access is denied on the current machine,
	       ** the user will be asked to use the first machine listed (if any)
	       ** on the "guestserver" line instead:
	       ** 530- Guest login not allowed on this machine,
	       **      connect to ftp.enst.fr instead.
	       **
	       ** -- <Nicolas.Pioch@enst.fr>
	     */
	}
	else if (getaclentry("guestserver", &entry)) {
	    char *tmphost;

	    /*
	       ** if a "guestserver" line is present,
	       ** default is not to allow guest logins
	     */
	    machineok = 0;

	    if (hostname[0]
		&& ((tmphost = wu_gethostbyname(hostname)))) {

		/*
		   ** hostname is the only first part of the FQDN
		   ** this may or may not correspond to the h_name value
		   ** (machines with more than one IP#, CNAMEs...)
		   ** -> need to fix that, calling gethostbyname on hostname
		   **
		   ** WARNING!
		   ** for SunOS 4.x, you need to have a working resolver in the libc
		   ** for CNAMES to work properly.
		   ** If you don't, add "-lresolv" to the libraries before compiling!
		 */
		char dns_localhost[MAXHOSTNAMELEN];
		int machinecount;

		strncpy(dns_localhost, tmphost, sizeof(dns_localhost));
		dns_localhost[sizeof(dns_localhost) - 1] = '\0';

		for (machinecount = 0;
		     (machinecount < MAXARGS) && entry->arg[machinecount];
		     machinecount++) {

		    if ((tmphost = wu_gethostbyname(entry->arg[machinecount]))) {
			/*
			   ** remember the name of the first machine for redirection
			 */

			if (!machinecount) {
			    strncpy(guestservername, entry->arg[machinecount],
				    sizeof(guestservername));
			    guestservername[sizeof(guestservername) - 1] = '\0';
			}

			if (!strcasecmp(tmphost, dns_localhost)) {
			    machineok++;
			    break;
			}
		    }
		}
	    }
	}
	if (!machineok) {
	    if (guestservername[0])
		reply(530,
		      "Guest login not allowed on this machine, connect to %s instead.",
		      guestservername);
	    else
		reply(530,
		      "Guest login not allowed on this machine.");
	    syslog(LOG_NOTICE,
	    "FTP LOGIN REFUSED (localhost not in guestservers) FROM %s, %s",
		   remoteident, name);
	    /* End of the big patch -- Nap */

	    dologout(0);
	}
	else if ((pw = sgetpwnam("ftp")) != NULL) {
	    anonymous = 1;	/* for the access_ok call */
	    if (access_ok(530) < 1) {
#ifndef HELP_CRACKERS
		DenyLoginAfterPassword = 1;
		syslog(LOG_NOTICE, "FTP LOGIN REFUSED (access denied) FROM %s, %s",
		       remoteident, name);
		reply(331, "Guest login ok, send your complete e-mail address as password.");
#else
		reply(530, "User %s access denied.", name);
		syslog(LOG_NOTICE,
		       "FTP LOGIN REFUSED (access denied) FROM %s, %s",
		       remoteident, name);
		dologout(0);
#endif
	    }
	    else {
		askpasswd = 1;
/* H* fix: obey use_accessfile a little better.  This way, things set on the
   command line [like xferlog stuff] don't get stupidly overridden.
   XXX: all these checks maybe should be in acl.c and access.c */
		if (use_accessfile)
		    acl_setfunctions();
		reply(331, "Guest login ok, send your complete e-mail address as password.");
	    }
	}
	else {
#ifndef HELP_CRACKERS
	    DenyLoginAfterPassword = 1;
	    reply(331, "Guest login ok, send your complete e-mail address as password.");
	    syslog(LOG_NOTICE, "FTP LOGIN REFUSED (ftp not in /etc/passwd) FROM %s, %s",
		   remoteident, name);
#else
	    reply(530, "User %s unknown.", name);
	    syslog(LOG_NOTICE,
		   "FTP LOGIN REFUSED (ftp not in /etc/passwd) FROM %s, %s",
		   remoteident, name);
#endif
#ifdef SOLARIS_BSM_AUDIT
	    audit_ftpd_no_anon();
#endif
	}
	return;
#endif
    }
#ifdef ANON_ONLY
/* H* fix: define the above to completely DISABLE logins by real users,
   despite ftpusers, shells, or any of that rot.  You can always hang your
   "real" server off some other port, and access-control it. */

    else {			/* "ftp" or "anon" -- MARK your conditionals, okay?! */
#ifndef HELP_CRACKERS
	DenyLoginAfterPassword = 1;
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (not anonymous) FROM %s, %s",
	       remoteident, name);
	reply(331, "Password required for %s.", name);
#else
	reply(530, "User %s unknown.", name);
	syslog(LOG_NOTICE,
	       "FTP LOGIN REFUSED (not anonymous) FROM %s, %s",
	       remoteident, name);
#endif
	return;
    }
/* fall here if username okay in any case */
#endif /* ANON_ONLY */

#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
    if (!virtual_mode && defaultserver_deny(name) && !defaultserver_allow(name)) {
#ifndef HELP_CRACKERS
	DenyLoginAfterPassword = 1;
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (ftp denied on default server) FROM %s, %s",
	       remoteident, name);
#else
	reply(530, "User %s access denied.", name);
	syslog(LOG_NOTICE,
	     "FTP LOGIN REFUSED (ftp denied on default server) FROM %s, %s",
	       remoteident, name);
	return;
#endif
    }
#endif

#if defined(USE_GSS)
    if (gss_info.must_gss_auth &&
	(!IS_GSSAUTH(cur_auth_type) ||
	!(gss_info.authstate & GSS_ADAT_DONE))) {
	reply(530, "Must perform authentication before identifying USER.");
	return;
    }
#endif /* USE_GSS */

    if ((pw = sgetpwnam(name)) != NULL) {
	if ((denieduid(pw->pw_uid) && !alloweduid(pw->pw_uid))
	    || (deniedgid(pw->pw_gid) && !allowedgid(pw->pw_gid))) {
#ifndef HELP_CRACKERS
	    DenyLoginAfterPassword = 1;
	    syslog(LOG_NOTICE, "FTP LOGIN REFUSED (username in denied-uid) FROM %s, %s",
		   remoteident, name);
	    reply(331, "Password required for %s.", name);
#else
	    reply(530, "User %s access denied.", name);
	    syslog(LOG_NOTICE,
		   "FTP LOGIN REFUSED (username in denied-uid) FROM %s, %s",
		   remoteident, name);
#endif
	    return;
	}
#if defined(USE_GSS)
	if (IS_GSSAUTH(cur_auth_type) &&
	    (gss_info.authstate & GSS_ADAT_DONE)) {
	    char buf[BUFSIZ];

	    if (gss_user(pw))
		gss_info.authstate |= GSS_USER_DONE;

	    if (gss_info.must_gss_auth &&
		!GSSUSERAUTH_OK(gss_info)) {
		reply(530, "User %s access denied", name);
		if (logging)
		    syslog(LOG_NOTICE, "FTP GSSAPI LOGIN REFUSED FROM %s, %s",
			remoteident, name);
		pw = NULL;
		return;
	    }
	    /*
	     * If GSSAPI user auth failed, or it succeeded but creds were
	     * not forwarded as required, prompt for password.
	     */
	    gss_need_passwd = !GSSUSERAUTH_OK(gss_info) ||
		(GSSUSERAUTH_OK(gss_info) &&
		(gss_info.want_creds && !gss_info.have_creds));
	    if (gss_need_passwd) {
		snprintf(buf, sizeof(buf),
		    "GSSAPI user %s is authorized as %s password required",
		    gss_info.display_name, name);
		reply(331, "%s", buf);
		askpasswd = 1;
		syslog(LOG_DEBUG, "%s", buf);
		return;
	    }
	}
#endif /* defined(USE_GSS) */

#if !defined(USE_PAM) || (defined(USE_PAM) && defined(OTHER_PASSWD)) || defined(SOLARIS_2)	/* PAM should be doing these checks, not ftpd */
#if defined(USE_PAM) && !defined(SOLARIS_2)
	if(!use_pam) {
#endif
	if ((shell = pw->pw_shell) == NULL || *shell == 0)
	    shell = _PATH_BSHELL;
	while ((cp = getusershell()) != NULL)
	    if (strcmp(cp, shell) == 0)
		break;
	endusershell();
	if (cp == NULL || checkuser(name)) {
#ifndef HELP_CRACKERS
	    DenyLoginAfterPassword = 1;
	    if (cp == NULL)
		syslog(LOG_NOTICE, "FTP LOGIN REFUSED (shell not in /etc/shells) FROM %s, %s", remoteident, name);
	    else
		syslog(LOG_NOTICE, "FTP LOGIN REFUSED (username in %s) FROM %s, %s", _path_ftpusers, remoteident, name);
	    reply(331, "Password required for %s.", name);
#else
	    reply(530, "User %s access denied.", name);
	    if (cp == NULL)
		syslog(LOG_NOTICE, "FTP LOGIN REFUSED (shell not in /etc/shells) FROM %s, %s", remoteident, name);
	    else
		syslog(LOG_NOTICE, "FTP LOGIN REFUSED (username in %s) FROM %s, %s", _path_ftpusers, remoteident, name);
#endif /* HELP_CRACKERS */
	    pw = (struct passwd *) NULL;
	    return;
	}
#if defined(USE_PAM) && !defined(SOLARIS_2)
	} /* if(!use_pam) */
#endif
#endif /* !USE_PAM || (USE_PAM && OTHER_PASSWD) || SOLARIS_2 */
	/* if user is a member of any of the guestgroups, cause a chroot() */
	/* after they log in successfully                                  */
	if (use_accessfile) {	/* see above.  _H */
	    guest = acl_guestgroup(pw);
	    if (guest && acl_realgroup(pw))
		guest = 0;
	}
    }
    if (access_ok(530) < 1) {
#ifndef HELP_CRACKERS
	DenyLoginAfterPassword = 1;
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (access denied) FROM %s, %s",
	       remoteident, name);
	reply(331, "Password required for %s.", name);
#else
	reply(530, "User %s access denied.", name);
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (access denied) FROM %s, %s",
	       remoteident, name);
#endif
	return;
    }
    else if (use_accessfile)	/* see above.  _H */
	acl_setfunctions();

#ifdef	BSD_AUTH
    if ((cp = start_auth(auth, name, pw)) != NULL) {
	char *s;

	for (;;) {
	    s = strsep(&cp, "\n");
	    if (cp == NULL || *cp == '\0')
		break;
	    lreply(331, "%s", s);
	}
	reply(331, "%s", s);
    }
    else {
#endif /* BSD_AUTH */
#ifdef SKEY
#ifndef __NetBSD__
#ifdef SKEY_NAME
	/* this is the old way, but freebsd uses it */
	pwok = skeyaccess(name, NULL, remotehost, remoteaddr);
#else
	/* this is the new way */
	pwok = skeyaccess(pw, NULL, remotehost, remoteaddr);
#endif /* SKEY_NAME */
	reply(331, "%s", skey_challenge(name, pw, pwok));
#else
	if (skey_haskey(name) == 0) {
	    char *myskey;

	    myskey = skey_keyinfo(name);
	    reply(331, "Password [%s] required for %s.",
		  myskey ? myskey : "error getting challenge", name);
	}
	else
	    reply(331, "Password required for %s.", name);
#endif /* __NetBSD__ */
#else
#ifdef OPIE
	{
	    char prompt[OPIE_CHALLENGE_MAX + 1];
	    opiechallenge(&opiestate, name, prompt);

	    if (askpasswd == -1) {
		syslog(LOG_WARNING, "Invalid FTP user name %s attempted from %s", name, remotehost);
		pwok = 0;
	    }
	    else
		pwok = af_pwok && opiealways(pw->pw_dir);
	    reply(331, "Response to %s %s for %s.",
		  prompt, pwok ? "requested" : "required", name);
	}
#else /* !SKEY */

#if defined(USE_GSS)
	if (GSSUSERAUTH_OK(gss_info) && !gss_need_passwd) {
	    /*
	     * We got this far, we are allowing the GSSAPI authentication
	     * to succeed without further passwd prompting.  Jump
	     * to "pass" processing.
	     */
	    askpasswd = 0;
	    logged_in = 1;
	    pass("");
	    return;
	}
#endif /* defined(USE_GSS) */
	reply(331, "Password required for %s.", name);
#endif /* OPIE */
#endif /* SKEY */
#ifdef	BSD_AUTH
    }
#endif /* BSD_AUTH */

    askpasswd = 1;
    /* Delay before reading passwd after first failed attempt to slow down
     * passwd-guessing programs. */
    if (login_attempts) {
	enable_signaling();	/* we can allow signals once again: kinch */
	sleep((unsigned) login_attempts);
    }
    return;
}

/* Check if a user is in the ftpusers file */
int checkuser(char *name)
{
    register FILE *fd;
    register char *p;
    char line[BUFSIZ];

#ifdef SOLARIS_ETC_FTPUSERS
    static int etc_ftpusers = 0;

    if (etc_ftpusers) {
	strcpy(_path_ftpusers, _PATH_FTPUSERS);
	etc_ftpusers = 0;
    }
retry:
#endif
    if ((fd = fopen(_path_ftpusers, "r")) != NULL) {
	while (fgets(line, sizeof(line), fd) != NULL)
	    if ((p = strchr(line, '\n')) != NULL) {
		*p = '\0';
		if (line[0] == '#')
		    continue;
		if (strcasecmp(line, name) == 0) {
		    (void) fclose(fd);
#ifdef SOLARIS_BSM_AUDIT
		    audit_ftpd_excluded(name);
#endif
#ifdef SOLARIS_ETC_FTPUSERS
		    if (etc_ftpusers)
			syslog(LOG_NOTICE, "%s is deprecated, use %s instead", _path_ftpusers, _PATH_FTPUSERS);
#endif
		    return (1);
		}
	    }
	(void) fclose(fd);
    }
#ifdef SOLARIS_ETC_FTPUSERS
    if (!etc_ftpusers && (strcmp(_path_ftpusers, _PATH_FTPUSERS) == 0)) {
	strcpy(_path_ftpusers, "/etc/ftpusers");
	etc_ftpusers = 1;
	goto retry;
    }
#endif
    return (0);
}

int uid_match(char *keyword, uid_t uid)
{
    struct aclmember *entry = NULL;
    int which;
    char *ptr;
    struct passwd *pw;

    /*
     * keyword <uid-range> [<uid-range> ...]
     *
     * uid-range may be a username or begin with '%' and be treated as numeric:
     *   %<uid>       A single numeric UID
     *   %<uid>+      All UIDs greater or equal to UID
     *   %<uid>-      All UIDs greater or equal to UID
     *   %-<uid>      All UIDs less or equal to UID
     *   %<uid>-<uid> All UIDs between the two (inclusive)
     *   *            All UIDs
     */
    while (getaclentry(keyword, &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
		    if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
			if (uid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (uid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (uid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (uid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
#ifdef OTHER_PASSWD
		pw = bero_getpwnam(ARG[which], _path_passwd);
#else
		pw = getpwnam(ARG[which]);
#endif
		if (pw && (uid == pw->pw_uid))
		    return (1);
	    }
	}
    }
    return (0);
}

int gid_match(char *keyword, gid_t gid, char *username)
{
    struct aclmember *entry = NULL;
    int which;
    char *ptr;
    struct group *grp;
    char **member;

    /*
     * keyword <gid-range> [<gid-range> ...]
     *
     * gid-range may be a groupname or begin with '%' and be treated as numeric:
     *   %<gid>       A single GID
     *   %<gid>+      All GIDs greater or equal to GID
     *   %<gid>-      All GIDs greater or equal to GID
     *   %-<gid>      All GIDs less or equal to GID
     *   %<gid>-<gid> All GIDs between the two (inclusive)
     *   *            All GIDs
     */
    while (getaclentry(keyword, &entry)) {
	for (which = 0; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcmp(ARG[which], "*"))
		return (1);
	    if (ARG[which][0] == '%') {
		if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
		    if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
			if (gid == strtoul(ARG[which] + 1, NULL, 0))
			    return (1);
		    }
		    else {
			*ptr++ = '\0';
			if ((ARG[which][1] == '\0')
			    || (gid >= strtoul(ARG[which] + 1, NULL, 0))) {
			    *--ptr = '+';
			    return (1);
			}
			*--ptr = '+';
		    }
		}
		else {
		    *ptr++ = '\0';
		    if (((ARG[which][1] == '\0')
			 || (gid >= strtoul(ARG[which] + 1, NULL, 0)))
			&& ((*ptr == '\0')
			    || (gid <= strtoul(ptr, NULL, 0)))) {
			*--ptr = '-';
			return (1);
		    }
		    *--ptr = '-';
		}
	    }
	    else {
		if ((grp = getgrnam(ARG[which]))) {
		    if (gid == grp->gr_gid)
			return (1);
		    if (username) {
			for (member = grp->gr_mem; *member; member++)
			    if (!strcasecmp(*member, username))
				return (1);
		    }
		}
	    }
	}
    }
    return (0);
}

int denieduid(uid_t uid)
{
    return uid_match("deny-uid", uid);
}

int alloweduid(uid_t uid)
{
    return uid_match("allow-uid", uid);
}

int deniedgid(gid_t gid)
{
    return gid_match("deny-gid", gid, NULL);
}

int allowedgid(gid_t gid)
{
    return gid_match("allow-gid", gid, NULL);
}

/* Terminate login as previous user, if any, resetting state; used when USER
 * command is given or login fails. */

void end_login(void)
{
    delay_signaling();		/* we can't allow any signals while euid==0: kinch */
    (void) seteuid((uid_t) 0);
    if (logged_in) {
	if (wtmp_logging)
	    wu_logwtmp(ttyline, pw->pw_name, remotehost, 0);
#ifdef USE_PAM
	if (!anonymous && pamh) {
	    (void) pam_close_session(pamh, 0);
	    (void) pam_end(pamh, PAM_SUCCESS); 
	    pamh = (pam_handle_t *)0;
	}
#endif
    }
    pw = NULL;
#ifdef AFS_AUTH
    ktc_ForgetAllTokens();
#endif
    logged_in = 0;
    anonymous = 0;
    guest = 0;
}

int validate_eaddr(char *eaddr)
{
    int i, host, state;

    for (i = host = state = 0; eaddr[i] != '\0'; i++) {
	switch (eaddr[i]) {
	case '.':
	    if (!host)
		return 0;
	    if (state == 2)
		state = 3;
	    host = 0;
	    break;
	case '@':
	    if (!host || state > 1 || !strncasecmp("ftp", eaddr + i - host, host))
		return 0;
	    state = 2;
	    host = 0;
	    break;
	case '!':
	case '%':
	    if (!host || state > 1)
		return 0;
	    state = 1;
	    host = 0;
	    break;
	case '-':
	    break;
	default:
	    host++;
	}
    }
    if (((state == 3) && host > 1) || ((state == 1) && host > 1))
	return 1;
    else
	return 0;
}


#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
static int AllowVirtualUser(const char *username)
{
    struct aclmember *entry = NULL;
    int which;

    while (getaclentry("virtual", &entry))
	if (ARG0 && hostmatch(ARG0, virtual_address, virtual_hostname)
	    && ARG1 && !strcasecmp(ARG1, "allow"))
	    for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		if (!strcasecmp(username, ARG[which]) || !strcmp("*", ARG[which]))
		    return (1);
    return (0);
}

static int DenyVirtualUser(const char *username)
{
    struct aclmember *entry = NULL;
    int which;

    while (getaclentry("virtual", &entry))
	if (ARG0 && hostmatch(ARG0, virtual_address, virtual_hostname)
	    && ARG1 && !strcasecmp(ARG1, "deny"))
	    for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		if (!strcasecmp(username, ARG[which]) || !strcmp("*", ARG[which]))
		    return (1);
    return (0);
}

static int DenyVirtualAnonymous(void)
{
    struct aclmember *entry = NULL;

    while (getaclentry("virtual", &entry))
	if (ARG0 && hostmatch(ARG0, virtual_address, virtual_hostname)
	    && ARG1 && !strcasecmp(ARG1, "private"))
	    return (1);
    return (0);
}
#endif

void pass(char *passwd)
{

#if !defined(USE_PAM) || (defined(USE_PAM) && defined(OTHER_PASSWD))
    char *xpasswd, *salt;
#endif

    int passwarn = 0;
    int rval = 1;
    int success_code = 230;
    int cos;

#ifdef SECUREOSF
    struct pr_passwd *pr;
    int crypt_alg = 0;
#endif

#ifdef BSD_AUTH
    extern int ext_auth;
    extern char *check_auth();
#endif

#ifdef ULTRIX_AUTH
    int numfails;
#endif /* ULTRIX_AUTH */

#ifdef HAS_PW_EXPIRE
    int set_expired = FALSE;
#endif 

#ifdef AFS_AUTH
    char *reason;
#endif /* AFS_AUTH */

#ifdef DCE_AUTH
    sec_passwd_rec_t pwr;
    sec_login_handle_t lhdl;
    boolean32 rstpwd;
    sec_login_auth_src_t asrc;
    error_status_t status;
#endif /* DCE_AUTH */

#if defined(USE_GSS)
    /*
     * LOGIC:
     *   If [ the user presented GSSAPI creds and was authorized ]
     *      jump down past the password validation code.
     */
    if (GSSUSERAUTH_OK(gss_info) && logged_in) {
	/*
	 * We could reply(202, "PASS command superfluous.") here, but
	 * allow this for compat with some clients.
	 */
	success_code = 232;
	goto pwd_validation_done;
    }
#endif /* defined(USE_GSS) */

    if (logged_in || askpasswd == 0) {
#ifdef VERBOSE_ERROR_LOGING
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED (PASS before USER) FROM %s",
	       remoteident);
#endif
	reply(503, "Login with USER first.");
	return;
    }
    askpasswd = 0;

    /* Disable lreply() if the first character of the password is '-' since
     * some hosts don't understand continuation messages and hang... */

    if (*passwd == '-')
	dolreplies = 0;
    else
	dolreplies = 1;
/* ******** REGULAR/GUEST USER PASSWORD PROCESSING ********** */
    if (!anonymous) {		/* "ftp" is only account allowed no password */
#ifndef HELP_CRACKERS
	if (DenyLoginAfterPassword) {
	    pr_mesg(530, DelayedMessageFile);
	    reply(530, "Login incorrect.");
#ifdef SOLARIS_BSM_AUDIT
	    audit_ftpd_failure(the_user);
#endif
	    acl_remove();
	    pw = NULL;
	    if (++login_attempts >= lgi_failure_threshold) {
		syslog(LOG_NOTICE, "repeated login failures from %s",
		       remoteident);
		exit(0);
	    }
	    return;
	}
#endif
	if (*passwd == '-')
	    passwd++;
#ifdef USE_PAM
#ifdef OTHER_PASSWD
	if (use_pam
#if defined(USE_GSS)
	    && !GSSUSERAUTH_OK(gss_info)
#endif
	) {
#endif
	/* PAM authentication
	 * If PAM authenticates a user we know nothing about on the local
	 * system, use the generic guest account credentials. We should make
	 * this somehow a configurable item somewhere; later more on that.
	 *
	 * For now assume the guest (not anonymous) identity, so the site
	 * admins can still differentiate between the truw anonymous user and
	 * a little bit more special ones. Otherwise he wouldn't go the extra
	 * mile to have a different user database, right?
	 *              --gaftonc */
	if (pam_check_pass(the_user, passwd)) {
	    rval = 0;
	    if (pw == NULL) {
		/* assume guest account identity */
		pw = sgetpwnam("ftp");
		anonymous = 0;
		guest = 1;
		/* even go as far as... */
		if (pw != NULL && pw->pw_name != NULL) {
		    free(pw->pw_name);
		    pw->pw_name = sgetsave(the_user);
		}
	    }
	}
#ifdef OTHER_PASSWD
	} else {
#endif
#endif /* USE_PAM */
#if !defined(USE_PAM) || (defined(USE_PAM) && defined(OTHER_PASSWD))
#ifdef BSD_AUTH
	if (ext_auth) {
	    if ((salt = check_auth(the_user, passwd))) {
		reply(530, "%s", salt);
#ifdef LOG_FAILED		/* 27-Apr-93      EHK/BM          */
		/*
		 * To avoid logging passwords mistakenly entered as
		 * usernames, only log the names of users which exist.
		 */
		syslog(LOG_INFO, "failed login from %s, %s", remoteident,
		       (pw == NULL) ? "[unknown]" : the_user);
#endif /* LOG_FAILED */
		acl_remove();
		pw = NULL;
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s",
			   remoteident);
		    exit(0);
		}
		return;
	    }
	}
	else {
#endif /* BSD_AUTH */
	    *guestpw = '\0';
	    if (pw == NULL)
		salt = "xx";
	    else
#ifndef OPIE
		salt = pw->pw_passwd;
#ifdef SECUREOSF
	    if ((pr = getprpwnam(pw->pw_name)) != NULL) {
		if (pr->uflg.fg_newcrypt)
		    crypt_alg = pr->ufld.fd_newcrypt;
		else if (pr->sflg.fg_newcrypt)
		    crypt_alg = pr->sfld.fd_newcrypt;
		else
		    crypt_alg = 0;
	    }
	    else
		crypt_alg = 0;

	    xpasswd = dispcrypt(passwd, salt, crypt_alg);
#elif defined(SecureWare) || defined(HPUX_10_TRUSTED)
	    xpasswd = bigcrypt(passwd, salt);
#elif defined(KERBEROS)
	    xpasswd = crypt16(passwd, salt);
#elif defined(SKEY)
#ifndef __NetBSD__
	    xpasswd = skey_crypt(passwd, salt, pw, pwok);
	    pwok = 0;
#else
	    if ((pw != NULL) && (pw->pw_name != NULL) && skey_haskey(pw->pw_name) == 0 &&
		skey_passcheck(pw->pw_name, passwd) != -1)
		xpasswd = pw->pw_passwd;
	    else
		xpasswd = crypt(passwd, salt);
#endif
#else /* !SKEY */
	    xpasswd = crypt(passwd, salt);
#endif /* SKEY */
#else /* OPIE */
	    if (!opieverify(&opiestate, passwd))
		rval = 0;
	    xpasswd = crypt(passwd, pw->pw_passwd);
#endif /* OPIE */
#ifdef ULTRIX_AUTH
	    if ((numfails = ultrix_check_pass(passwd, xpasswd)) >= 0) {
#else
	    if (pw != NULL) {
#ifdef AFS_AUTH
		if (strcmp(pw->pw_passwd, "X") == 0)
		    if (ka_UserAuthenticateGeneral(KA_USERAUTH_VERSION | KA_USERAUTH_DOSETPAG, pw->pw_name, "", 0, passwd, 0, 0, 0, &reason) == 0)
			rval = 0;
		    else
			printf("230-AFS: %s", reason);
		else
#endif /* AFS_AUTH */
		    /* The strcmp does not catch null passwords! */
#ifdef HAS_PW_EXPIRE
		    if(pw->pw_expire != NULL) {
			if(pw->pw_expire && time(NULL) >= pw->pw_expire) {
			    set_expired = TRUE;
			} 
		    }
#endif
			    
		    if (*pw->pw_passwd != '\0' &&
#ifdef HAS_PW_EXPIRE
			!set_expired &&
#endif
			strcmp(xpasswd, pw->pw_passwd) == 0) {
#endif
		    rval = 0;
		}
#ifdef DCE_AUTH
#ifndef ALWAYS_TRY_DCE
		else
#endif /* ALWAYS_TRY_DCE */
		{
		    sec_login_setup_identity((unsigned_char_p_t) pw->pw_name, sec_login_no_flags, &lhdl, &status);
		    if (status == error_status_ok) {
			printf("230-sec_login_setup_identity OK\n");
			pwr.key.tagged_union.plain = (idl_char *) passwd;
			pwr.key.key_type = sec_passwd_plain;
			pwr.pepper = 0;
			pwr.version_number = sec_passwd_c_version_none;
			/* validate password with login context */
			sec_login_valid_and_cert_ident(lhdl, &pwr, &rstpwd, &asrc, &status);
			if (!rstpwd && (asrc == sec_login_auth_src_network) && (status == error_status_ok)) {
			    printf("230-sec_login_valid_and_cert_ident OK\n");
			    sec_login_set_context(lhdl, &status);
			    printf("230-sec_login_set_context finished\n");
			    if (status != error_status_ok) {
				int pstatus;
				dce_error_string_t s;
				printf("230-Error status: %d:\n", status);
				dce_error_inq_text(status, s, &pstatus);
				printf("230-%s\n", s);
				fflush(stderr);
				sec_login_purge_context(lhdl, &status);
			    }
			    else {
				/*sec_login_get_pwent(lhdl, &pw, &status); */
				rval = 0;
			    }
			}
		    }
		}
#endif /* DCE_AUTH */
	    }
#ifdef USE_PAM
	    }
#endif
#endif /* !USE_PAM  || (USE_PAM && OTHER_PASSWD) */
	    if (rval) {
		reply(530, "Login incorrect.");

#ifdef LOG_FAILED		/* 27-Apr-93    EHK/BM             */
/* H* add-on: yell about attempts to use the trojan.  This may alarm you
   if you're "stringsing" the binary and you see "NULL" pop out in just
   about the same place as it would have in 2.2c! */
		if (!strcasecmp(passwd, "NULL"))
		    syslog(LOG_NOTICE, "REFUSED \"NULL\" from %s, %s",
			   remoteident, the_user);
		else {
		    /*
		     * To avoid logging passwords mistakenly entered as
		     * usernames, only log the names of users which exist.
		     */
		    syslog(LOG_INFO, "failed login from %s, %s", remoteident,
			   (pw == NULL) ? "[unknown]" : the_user);
		}
#endif
#ifdef SOLARIS_BSM_AUDIT
		audit_ftpd_failure(the_user);
#endif
		acl_remove();

		pw = NULL;
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s",
			   remoteident);
		    exit(0);
		}
		return;
	    }
#ifdef	BSD_AUTH
	}
#endif
/* ANONYMOUS USER PROCESSING STARTS HERE */
    }
    else {
	char *pwin, *pwout = guestpw;
	struct aclmember *entry = NULL;
	int valid;
	int enforce = 0;

	if (getaclentry("passwd-check", &entry) &&
	    ARG0 && strcasecmp(ARG0, "none")) {

	    if (!strcasecmp(ARG0, "rfc822"))
		valid = validate_eaddr(passwd);
	    else if (!strcasecmp(ARG0, "trivial"))
		valid = (strchr(passwd, '@') == NULL) ? 0 : 1;
	    else
		valid = 1;
	    if (ARG1 && !strcasecmp(ARG1, "enforce"))
		enforce = 1;
	    /* Block off "default" responses like mozilla@ and IE30User@
	     * (at the administrator's discretion).  --AC
	     */
	    entry = NULL;
	    while (getaclentry("deny-email", &entry)) {
		if (ARG0
		    && ((strcasecmp(passwd, ARG0) == 0)
			|| regexmatch(passwd, ARG0)
			|| ((*passwd == '-')
			    && ((strcasecmp(passwd + 1, ARG0) == 0)
				|| regexmatch(passwd + 1, ARG0))))) {
		    valid = 0;
		    break;
		}
	    }
	    if (!valid && enforce) {
		lreply(530, "The response '%s' is not valid", passwd);
		lreply(530, "Please use your e-mail address as your password");
		lreply(530, "   for example: %s@%s%s",
		       authenticated ? authuser : "joe", remotehost,
		       strchr(remotehost, '.') ? "" : ".network");
		reply(530, "Login incorrect.");
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP ACCESS REFUSED (anonymous password not rfc822) from %s",
		       remoteident);
#endif
#ifdef SOLARIS_BSM_AUDIT
		audit_ftpd_bad_pw(the_user);
#endif
		acl_remove();
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s",
			   remoteident);
		    exit(0);
		}
		return;
	    }
	    else if (!valid)
		passwarn = 1;
	}
	if (!*passwd) {
	    strcpy(guestpw, "[none_given]");
	}
	else {
	    int cnt = sizeof(guestpw) - 2;

	    for (pwin = passwd; *pwin && cnt--; pwin++)
		if (!isgraph(*pwin))
		    *pwout++ = '_';
		else
		    *pwout++ = *pwin;
	}
#ifndef HELP_CRACKERS
	if (DenyLoginAfterPassword) {
	    pr_mesg(530, DelayedMessageFile);
	    reply(530, "Login incorrect.");
#ifdef SOLARIS_BSM_AUDIT
	    audit_ftpd_failure(the_user);
#endif
	    acl_remove();
	    pw = NULL;
	    if (++login_attempts >= lgi_failure_threshold) {
		syslog(LOG_NOTICE, "repeated login failures from %s",
		       remoteident);
		exit(0);
	    }
	    return;
	}
#endif
    }

#if defined(USE_GSS)
pwd_validation_done:
#endif /* USE_GSS */
    /* if logging is enabled, open logfile before chroot or set group ID */
    if ((log_outbound_xfers || log_incoming_xfers) && (syslogmsg != 1)) {
	mode_t oldmask;
	oldmask = umask(0);
	xferlog = open(logfile, O_WRONLY | O_APPEND | O_CREAT, 0640);
	(void) umask(oldmask);
	if (xferlog < 0) {
	    syslog(LOG_ERR, "cannot open logfile %s: %s", logfile,
		   strerror(errno));
	    xferlog = 0;
	}
    }

#ifdef DEBUG
/* I had a lot of trouble getting xferlog working, because of two factors:
   acl_setfunctions making stupid assumptions, and sprintf LOSING.  _H */
/* 
 * Actually, sprintf was not losing, but the rules changed... next release
 * this will be fixed the correct way, but right now, it works well enough
 * -- sob 
 */
    syslog(LOG_INFO, "-i %d,-o %d,xferlog %s: %d",
	   log_incoming_xfers, log_outbound_xfers, logfile, xferlog);
#endif
    enable_signaling();		/* we can allow signals once again: kinch */
    /* if autogroup command applies to user's class change pw->pw_gid */
    if (anonymous && use_accessfile) {	/* see above.  _H */
	(void) acl_autogroup(pw);
	guest = acl_guestgroup(pw);	/* the new group may be a guest */
	if (guest && acl_realgroup(pw))
	    guest = 0;
	anonymous = !guest;
    }
/* END AUTHENTICATION */

/* SET GROUP ID STARTS HERE */
#ifndef AIX
    (void) setegid((gid_t) pw->pw_gid);
#else
    (void) setgid((gid_t) pw->pw_gid);
#endif
    (void) initgroups(pw->pw_name, pw->pw_gid);
#ifdef DEBUG
    syslog(LOG_DEBUG, "initgroups has been called");
#endif
/* WTMP PROCESSING STARTS HERE */
    if (wtmp_logging) {
	/* open wtmp before chroot */
#if ((defined(BSD) && (BSD >= 199103)) || defined(sun))
	(void) sprintf(ttyline, "ftp%ld", (long) getpid());
#else
	(void) sprintf(ttyline, "ftpd%d", getpid());
#endif
#ifdef DEBUG
	syslog(LOG_DEBUG, "about to call wtmp");
#endif
	wu_logwtmp(ttyline, pw->pw_name, remotehost, 1);
    }
    logged_in = 1;

    expand_id();

#ifdef QUOTA
    memset(&quota, 0, sizeof(quota));
    get_quota(pw->pw_dir, pw->pw_uid);
#endif

    restricted_user = 0;
    if (!anonymous)
	if ((restricteduid(pw->pw_uid) && !unrestricteduid(pw->pw_uid))
	    || (restrictedgid(pw->pw_gid) && !unrestrictedgid(pw->pw_gid)))
	    restricted_user = 1;
    if (anonymous || guest) {
	char *sp;
	/* We MUST do a chdir() after the chroot. Otherwise the old current
	 * directory will be accessible as "." outside the new root! */
#ifdef ALTERNATE_CD
	home = defhome;
#endif
#ifdef VIRTUAL
	if (virtual_mode && !guest) {
#ifdef CLOSED_VIRTUAL_SERVER
	    if (DenyVirtualAnonymous()) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (virtual host anonymous access denied) for %s",
		       remoteident);
#endif
		reply(530, "Login incorrect.");
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s", remoteident);
		    dologout(0);
		}
		goto bad;
	    }
#endif
	    /* Anonymous user in virtual_mode */
	    if (pw->pw_dir)
		free(pw->pw_dir);
	    pw->pw_dir = sgetsave(virtual_root);
	}
	else
#endif

	    /*
	       *  New chroot logic.
	       *
	       *  If VIRTUAL is supported, the chroot for anonymous users on the
	       *  virtual host has already been determined.  Otherwise the logic
	       *  below applies:
	       *
	       *  If this is an anonymous user, the chroot directory is determined
	       *  by the "anonymous-root" clause and the home directory is taken
	       *  from the etc/passwd file found after chroot'ing.
	       *
	       *  If this a guest user, the chroot directory is determined by the
	       *  "guest-root" clause and the home directory is taken from the
	       *  etc/passwd file found after chroot'ing.
	       *
	       *  The effect of this logic is that the entire chroot environment
	       *  is under the control of the ftpaccess file and the supporting
	       *  files in the ftp environment.  The system-wide passwd file is
	       *  used only to authenticate the user.
	     */

	{
	    struct aclmember *entry = NULL;
	    char *root_path = NULL;

	    if (anonymous) {
		char class[BUFSIZ];

		(void) acl_getclass(class);
		while (getaclentry("anonymous-root", &entry) && ARG0) {
		    if (!ARG1) {
			if (!root_path)
			    root_path = ARG0;
		    }
		    else {
			int which;

			for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
			    if (!strcmp(ARG[which], "*")) {
				if (!root_path)
				    root_path = ARG0;
			    }
			    else {
				if (!strcasecmp(ARG[which], class))
				    root_path = ARG0;
			    }
			}
		    }
		}
	    }
	    else {		/* (guest) */
		while (getaclentry("guest-root", &entry) && ARG0) {
		    if (!ARG1) {
			if (!root_path)
			    root_path = ARG0;
		    }
		    else {
			int which;
			char *ptr;

			for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
			    if (!strcmp(ARG[which], "*")) {
				if (!root_path)
				    root_path = ARG0;
			    }
			    else {
				if (ARG[which][0] == '%') {
				    if ((ptr = strchr(ARG[which] + 1, '-')) == NULL) {
					if ((ptr = strchr(ARG[which] + 1, '+')) == NULL) {
					    if (pw->pw_uid == strtoul(ARG[which] + 1, NULL, 0))
						root_path = ARG0;
					}
					else {
					    *ptr++ = '\0';
					    if ((ARG[which][1] == '\0')
						|| (pw->pw_uid >= strtoul(ARG[which] + 1, NULL, 0)))
						root_path = ARG0;
					    *--ptr = '+';
					}
				    }
				    else {
					*ptr++ = '\0';
					if (((ARG[which][1] == '\0')
					     || (pw->pw_uid >= strtoul(ARG[which] + 1, NULL, 0)))
					    && ((*ptr == '\0')
						|| (pw->pw_uid <= strtoul(ptr, NULL, 0))))
					    root_path = ARG0;
					*--ptr = '-';
				    }
				}
				else {
#ifdef OTHER_PASSWD
				    struct passwd *guest_pw = bero_getpwnam(ARG[which], _path_passwd);
#else
				    struct passwd *guest_pw = getpwnam(ARG[which]);
#endif
				    if (guest_pw && (pw->pw_uid == guest_pw->pw_uid))
					root_path = ARG0;
				}
			    }
			}
		    }
		}
	    }

	    if (root_path) {
		struct passwd *chroot_pw = NULL;

#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
		if (virtual_mode && strcmp(root_path, virtual_root) && !(AllowVirtualUser(pw->pw_name) && !DenyVirtualUser(pw->pw_name))) {
#ifdef VERBOSE_ERROR_LOGING
		    syslog(LOG_NOTICE, "FTP LOGIN FAILED (virtual host access denied) for %s, %s",
			   remoteident, pw->pw_name);
#endif
		    reply(530, "Login incorrect.");
		    if (++login_attempts >= lgi_failure_threshold) {
			syslog(LOG_NOTICE, "repeated login failures from %s", remoteident);
			dologout(0);
		    }
		    goto bad;
		}
#endif
		(void) strncpy(chroot_path, root_path, sizeof(chroot_path));
		chroot_path[sizeof(chroot_path) - 1] = '\0';
		if (pw->pw_dir)
		    free(pw->pw_dir);
		pw->pw_dir = sgetsave(chroot_path);
#if defined(SOLARIS_2)
		cleanup_nscd();
#endif
		if (chroot(root_path) < 0 || chdir("/") < 0) {
#ifdef VERBOSE_ERROR_LOGING
		    syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot set guest privileges) for %s, %s",
			   remoteident, pw->pw_name);
#endif
		    reply(530, "Can't set guest privileges.");
		    goto bad;
		}
#ifdef OTHER_PASSWD
		if ((chroot_pw = bero_getpwuid(pw->pw_uid, _path_passwd)) != NULL)
#else
		if ((chroot_pw = getpwuid(pw->pw_uid)) != NULL)
#endif
		    if (chdir(chroot_pw->pw_dir) >= 0)
			home = sgetsave(chroot_pw->pw_dir);
		goto slimy_hack;	/* onea these days I'll make this structured code, honest ... */
	    }
	}

	/* determine root and home directory */

	if ((sp = strstr(pw->pw_dir, "/./")) == NULL) {
	    (void) strncpy(chroot_path, pw->pw_dir, sizeof(chroot_path));
	    chroot_path[sizeof(chroot_path) - 1] = '\0';
#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
	    if (virtual_mode && strcmp(chroot_path, virtual_root) && !(AllowVirtualUser(pw->pw_name) && !DenyVirtualUser(pw->pw_name))) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (virtual host access denied) for %s, %s",
		       remoteident, pw->pw_name);
#endif
		reply(530, "Login incorrect.");
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s", remoteident);
		    dologout(0);
		}
		goto bad;
	    }
#endif
#if defined(SOLARIS_2)
	    cleanup_nscd();
#endif
	    if (chroot(pw->pw_dir) < 0 || chdir("/") < 0) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot set guest privileges) for %s, %s",
		       remoteident, pw->pw_name);
#endif
		reply(530, "Can't set guest privileges.");
		goto bad;
	    }
	}
	else {
	    *sp++ = '\0';
	    (void) strncpy(chroot_path, pw->pw_dir, sizeof(chroot_path));
	    chroot_path[sizeof(chroot_path) - 1] = '\0';
#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
	    if (virtual_mode && strcmp(chroot_path, virtual_root) && !(AllowVirtualUser(pw->pw_name) && !DenyVirtualUser(pw->pw_name))) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (virtual host access denied) for %s, %s",
		       remoteident, pw->pw_name);
#endif
		reply(530, "Login incorrect.");
		if (++login_attempts >= lgi_failure_threshold) {
		    syslog(LOG_NOTICE, "repeated login failures from %s", remoteident);
		    dologout(0);
		}
		goto bad;
	    }
#endif
#if defined(SOLARIS_2)
	    cleanup_nscd();
#endif
	    if (chroot(pw->pw_dir) < 0 || chdir(++sp) < 0) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot set guest privileges) for %s, %s",
		       remoteident, pw->pw_name);
#endif
		reply(550, "Can't set guest privileges.");
		goto bad;
	    }
#ifdef ALTERNATE_CD
	    home = sp;
#endif
	}
      slimy_hack:
	/* shut up you stupid compiler! */  {
	    int i = 0;
	    i++;
	}
    }
#if defined(VIRTUAL) && defined(CLOSED_VIRTUAL_SERVER)
    else if (virtual_mode && !(AllowVirtualUser(pw->pw_name) && !DenyVirtualUser(pw->pw_name))) {
#ifdef VERBOSE_ERROR_LOGING
	syslog(LOG_NOTICE, "FTP LOGIN FAILED (virtual host access denied) for %s, %s",
	       remoteident, pw->pw_name);
#endif
	reply(530, "Login incorrect.");
	if (++login_attempts >= lgi_failure_threshold) {
	    syslog(LOG_NOTICE, "repeated login failures from %s", remoteident);
	    dologout(0);
	}
	goto bad;
    }
#endif
#ifdef AIX
    {
	/* AIX 3 lossage.  Don't ask.  It's undocumented.  */
	priv_t priv;

	priv.pv_priv[0] = 0;
	priv.pv_priv[1] = 0;
/*       setgroups(NULL, NULL); */
	if (setpriv(PRIV_SET | PRIV_INHERITED | PRIV_EFFECTIVE | PRIV_BEQUEATH,
		    &priv, sizeof(priv_t)) < 0 ||
	    setuidx(ID_REAL | ID_EFFECTIVE, (uid_t) pw->pw_uid) < 0 ||
	    seteuid((uid_t) pw->pw_uid) < 0) {
#ifdef VERBOSE_ERROR_LOGING
	    syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot set uid) for %s, %s",
		   remoteident, pw->pw_name);
#endif
	    reply(530, "Can't set uid (AIX3).");
	    goto bad;
	}
    }
#ifdef UID_DEBUG
    lreply(success_code, "ruid=%d, euid=%d, suid=%d, luid=%d", getuidx(ID_REAL),
	   getuidx(ID_EFFECTIVE), getuidx(ID_SAVED), getuidx(ID_LOGIN));
    lreply(success_code, "rgid=%d, egid=%d, sgid=%d, lgid=%d", getgidx(ID_REAL),
	   getgidx(ID_EFFECTIVE), getgidx(ID_SAVED), getgidx(ID_LOGIN));
#endif
#else /* AIX */
#ifdef HAVE_SETREUID
    if (setreuid(-1, (uid_t) pw->pw_uid) < 0) {
#else
    if (seteuid((uid_t) pw->pw_uid) < 0) {
#endif
#ifdef VERBOSE_ERROR_LOGING
	syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot set uid) for %s, %s",
	       remoteident, pw->pw_name);
#endif
	reply(530, "Can't set uid.");
	goto bad;
    }
#endif /* AIX */
    if (!anonymous && !guest) {
	if (chdir(pw->pw_dir) < 0) {
#ifdef PARANOID
#ifdef VERBOSE_ERROR_LOGING
	    syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot chdir) for %s, %s",
		   remoteident, pw->pw_name);
#endif
	    reply(530, "User %s: can't change directory to %s.",
		  pw->pw_name, pw->pw_dir);
	    goto bad;
#else /* PARANOID */
	    if (restricted_user || chdir("/") < 0) {
#ifdef VERBOSE_ERROR_LOGING
		syslog(LOG_NOTICE, "FTP LOGIN FAILED (cannot chdir) for %s, %s",
		       remoteident, pw->pw_name);
#endif
		reply(530, "User %s: can't change directory to %s.",
		      pw->pw_name, pw->pw_dir);
		goto bad;
	    }
	    else {
		lreply(success_code, "No directory! Logging in with home=/");
#ifdef ALTERNATE_CD
		home = defhome;
#endif
	    }
#endif /* PARANOID */
	}
    }

    if (passwarn) {
	lreply(success_code, "The response '%s' is not valid", passwd);
	lreply(success_code,
	       "Next time please use your e-mail address as your password");
	lreply(success_code, "   for example: %s@%s%s",
	       authenticated ? authuser : "joe", remotehost,
	       strchr(remotehost, '.') ? "" : ".network");
    }

    login_attempts = 0;		/* this time successful */

    /* following two lines were inside the next scope... */

    show_message(success_code, LOG_IN);
    show_message(success_code, C_WD);
    show_readme(success_code, LOG_IN);
    show_readme(success_code, C_WD);

#ifdef ULTRIX_AUTH
    if (!anonymous && numfails > 0) {
	lreply(success_code,
	   "There have been %d unsuccessful login attempts on your account",
	       numfails);
    }
#endif /* ULTRIX_AUTH */

    (void) is_shutdown(0, 0);	/* display any shutdown messages now */

    if (anonymous) {

	reply(success_code, "Guest login ok, access restrictions apply.");
	sprintf(proctitle, "%s: anonymous/%.*s", remotehost,
		(int) (sizeof(proctitle) - sizeof(remotehost) -
		       sizeof(": anonymous/")), passwd);
	setproctitle("%s", proctitle);
	if (logging)
	    syslog(LOG_INFO, "ANONYMOUS FTP LOGIN FROM %s, %s",
		   remoteident, passwd);
    }
    else {
	reply(success_code, "User %s logged in.%s", pw->pw_name, guest ?
	      "  Access restrictions apply." : "");
	sprintf(proctitle, "%s: %s", remotehost, pw->pw_name);
	setproctitle("%s", proctitle);
	if (logging)
	    syslog(LOG_INFO, "FTP LOGIN FROM %s, %s", remoteident, pw->pw_name);
/* H* mod: if non-anonymous user, copy it to "authuser" so everyone can
   see it, since whoever he was @foreign-host is now largely irrelevant.
   NMM mod: no, it isn't!  Think about accounting for the transfers from or
   to a shared account. */
	/* strcpy (authuser, pw->pw_name); */
    }				/* anonymous */
#ifdef ALTERNATE_CD
    if (!home)
#endif
	home = pw->pw_dir;	/* home dir for globbing */
    (void) umask(defumask);
    time(&login_time);
    {
	struct aclmember *entry;
	entry = NULL;
	while (getaclentry("limit-time", &entry) && ARG0 && ARG1)
	    if ((anonymous && strcasecmp(ARG0, "anonymous") == 0)
		|| (guest && strcasecmp(ARG0, "guest") == 0)
		|| ((guest | anonymous) && strcmp(ARG0, "*") == 0))
		limit_time = strtoul(ARG1, NULL, 0);
    }

    /* Need to reset here as user type/class now known */
#ifdef INET6
    /* IP_TOS is an IPv4 socket option */
    if (SOCK_FAMILY(ctrl_addr) == AF_INET)
#endif
    if ((cos = IPClassOfService("control")) >= 0) {
	if (setsockopt(0, IPPROTO_IP, IP_TOS, (char *) &cos, sizeof(int)) < 0)
	    syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
    }

#ifdef SOLARIS_BSM_AUDIT
    audit_ftpd_success(the_user);
#endif
    init_privs(pw->pw_name);
    return;
  bad:
    /* Forget all about it... */
    if (xferlog)
	close(xferlog);
    xferlog = 0;
    acl_remove();
#ifdef SOLARIS_BSM_AUDIT
    audit_ftpd_failure(the_user);
#endif
    end_login();
    return;
}

int restricteduid(uid_t uid)
{
    return uid_match("restricted-uid", uid);
}

int unrestricteduid(uid_t uid)
{
    return uid_match("unrestricted-uid", uid);
}

int restrictedgid(gid_t gid)
{
    return gid_match("restricted-gid", gid, NULL);
}

int unrestrictedgid(gid_t gid)
{
    return gid_match("unrestricted-gid", gid, NULL);
}

char *opt_string(int options)
{
    static char buf[100];
    char *ptr = buf;

    if ((options & O_COMPRESS) != 0)	/* debian fixes: NULL -> 0 */
	*ptr++ = 'C';
    if ((options & O_TAR) != 0)
	*ptr++ = 'T';
    if ((options & O_UNCOMPRESS) != 0)
	*ptr++ = 'U';
    if (options == 0)
	*ptr++ = '_';
    *ptr++ = '\0';
    return (buf);
}

#ifdef INTERNAL_LS
char *rpad(char *s, unsigned int len)
{
    char *a;
    a = (char *) malloc(len + 1);
    memset(a, ' ', len);
    a[len] = 0;
    if (strlen(s) <= len)
	memcpy(a, s, strlen(s));
    else
	strncpy(a, s, len);
    return a;
}

char *ls_file(const char *file, int nameonly, char remove_path, char classify)
{
    static const char month[12][4] =
    {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    char *permissions;
    struct stat s;
    struct tm *t;
    char *ls_entry;
    char *owner, *ownerg;
    char *rpowner, *rpownerg;
    char *link;
#ifndef LS_NUMERIC_UIDS
    struct passwd *pw;
    struct group *gr;
#endif
    link = NULL;
    owner = NULL;
    ownerg = NULL;
    if (lstat(file, &s) != 0)	/* File doesn't exist, or is not readable by user */
	return NULL;
    ls_entry = (char *) malloc(312);
    memset(ls_entry, 0, 312);
    permissions = strdup("----------");
    if (S_ISLNK(s.st_mode)) {
	permissions[0] = 'l';
	if (classify)
	    classify = '@';
    }
    else if (S_ISDIR(s.st_mode)) {
	permissions[0] = 'd';
	if (classify)
	    classify = '/';
    }
    else if (S_ISBLK(s.st_mode))
	permissions[0] = 'b';
    else if (S_ISCHR(s.st_mode))
	permissions[0] = 'c';
    else if (S_ISFIFO(s.st_mode)) {
	permissions[0] = 'p';
	if (classify == 1)
	    classify = '=';
    }
#ifdef S_ISSOCK
    else if (S_ISSOCK(s.st_mode))
	permissions[0] = 's';
#endif
    if ((s.st_mode & S_IRUSR) == S_IRUSR)
	permissions[1] = 'r';
    if ((s.st_mode & S_IWUSR) == S_IWUSR)
	permissions[2] = 'w';
    if ((s.st_mode & S_IXUSR) == S_IXUSR) {
	permissions[3] = 'x';
	if (classify == 1)
	    classify = '*';
#ifndef HIDE_SETUID
	if ((s.st_mode & S_ISUID) == S_ISUID)
	    permissions[3] = 's';
#endif
    }
#ifndef HIDE_SETUID
    else if ((s.st_mode & S_ISUID) == S_ISUID)
	permissions[3] = 'S';
#endif
    if ((s.st_mode & S_IRGRP) == S_IRGRP)
	permissions[4] = 'r';
    if ((s.st_mode & S_IWGRP) == S_IWGRP)
	permissions[5] = 'w';
    if ((s.st_mode & S_IXGRP) == S_IXGRP) {
	permissions[6] = 'x';
	if (classify == 1)
	    classify = '*';
#ifndef HIDE_SETUID
	if ((s.st_mode & S_ISGID) == S_ISGID)
	    permissions[6] = 's';
#endif
    }
#ifndef HIDE_SETUID
    else if ((s.st_mode & S_ISGID) == S_ISGID)
	permissions[6] = 'S';
#endif
    if ((s.st_mode & S_IROTH) == S_IROTH)
	permissions[7] = 'r';
    if ((s.st_mode & S_IWOTH) == S_IWOTH)
	permissions[8] = 'w';
    if ((s.st_mode & S_IXOTH) == S_IXOTH) {
	permissions[9] = 'x';
	if (classify == 1)
	    classify = '*';
#ifndef HIDE_SETUID
	if ((s.st_mode & S_ISVTX) == S_ISVTX)
	    permissions[9] = 't';
#endif
    }
#ifndef HIDE_SETUID
    else if ((s.st_mode & S_ISVTX) == S_ISVTX)
	permissions[9] = 'T';
#endif
    t = localtime(&s.st_mtime);
#ifndef LS_NUMERIC_UIDS
#ifdef OTHER_PASSWD
    pw = bero_getpwuid(s.st_uid, _path_passwd);
#else
    pw = getpwuid(s.st_uid);
#endif
    if (pw != NULL)
	owner = strdup(pw->pw_name);
    gr = getgrgid(s.st_gid);
    if (gr != NULL)
	ownerg = strdup(gr->gr_name);
#endif
    if (owner == NULL) {	/* Can't figure out username (or don't want to) */
	if (s.st_uid == 0)
	    owner = strdup("root");
	else {
	    owner = (char *) malloc(9);
	    memset(owner, 0, 9);
#ifdef SOLARIS_2
	    snprintf(owner, 8, "%lu", s.st_uid);
#else
	    snprintf(owner, 8, "%u", s.st_uid);
#endif
	}
    }
    if (ownerg == NULL) {	/* Can't figure out groupname (or don't want to) */
	if (s.st_gid == 0)
	    ownerg = strdup("root");
	else {
	    ownerg = (char *) malloc(9);
	    memset(ownerg, 0, 9);
#ifdef SOLARIS_2
	    snprintf(ownerg, 8, "%lu", s.st_gid);
#else
	    snprintf(ownerg, 8, "%u", s.st_gid);
#endif
	}
    }

#ifdef HAVE_LSTAT
    if (S_ISLNK(s.st_mode)) {
	link = (char *) malloc(MAXPATHLEN);
	memset(link, 0, MAXPATHLEN);
	if (readlink(file, link, MAXPATHLEN) == -1) {
	    free(link);
	    link = NULL;
	}
    }
#endif

    if (remove_path != 0 && strchr(file, '/'))
	file = strrchr(file, '/') + 1;

    rpowner = rpad(owner, 8);
    rpownerg = rpad(ownerg, 8);

#ifdef SOLARIS_2
#define N_FORMAT "lu"
#else
#if defined(__FreeBSD__) || defined(__bsdi__)
#define N_FORMAT "u"
#else
#define N_FORMAT "u"
#endif
#endif

    if (nameonly) {
	sprintf(ls_entry, "%s", file);
	if (link != NULL)
	    free(link);
    }
    else {
	if ((time(NULL) - s.st_mtime) > 6307200) {	/* File is older than 6 months */
	    if (link == NULL)
		snprintf(ls_entry, 311, "%s %3" N_FORMAT " %s %s %8" L_FORMAT " %s %2u %5u %s", permissions, s.st_nlink, rpowner, rpownerg, s.st_size, month[t->tm_mon], t->tm_mday, 1900 + t->tm_year, file);
	    else {
		snprintf(ls_entry, 311, "%s %3" N_FORMAT " %s %s %8" L_FORMAT " %s %2u %5u %s -> %s", permissions, s.st_nlink, rpowner, rpownerg, s.st_size, month[t->tm_mon], t->tm_mday, 1900 + t->tm_year, file, link);
		free(link);
	    }
	}
	else if (link == NULL)
	    snprintf(ls_entry, 311, "%s %3" N_FORMAT " %s %s %8" L_FORMAT " %s %2u %02u:%02u %s", permissions, s.st_nlink, rpowner, rpownerg, s.st_size, month[t->tm_mon], t->tm_mday, t->tm_hour, t->tm_min, file);
	else {
	    snprintf(ls_entry, 311, "%s %3" N_FORMAT " %s %s %8" L_FORMAT " %s %2u %02u:%02u %s -> %s", permissions, s.st_nlink, rpowner, rpownerg, s.st_size, month[t->tm_mon], t->tm_mday, t->tm_hour, t->tm_min, file, link);
	    free(link);
	}
    }
    free(rpowner);
    free(rpownerg);
    free(owner);
    free(ownerg);
    if (classify > 1)
	sprintf(ls_entry + strlen(ls_entry), "%c", classify);
    strcat(ls_entry, "\r\n");
    free(permissions);
    return ls_entry;
}

void ls_dir(char *d, char ls_a, char ls_F, char ls_l, char ls_R, char omit_total, FILE *out)
{
    int total;
    char *realdir;		/* fixed up value to pass to glob() */
    char **subdirs;		/* Subdirs to be scanned for ls -R  */
    int numSubdirs = 0;
    glob_t g;
    char isDir;			/* 0: d is a file; 1: d is some files; 2: d is dir */
    struct stat s;
    char *dirlist;
    unsigned long dl_size, dl_used;
    char *c;
    char *lsentry;
    int i;
#ifndef GLOB_PERIOD
    char *dperiod;
#endif

    isDir = 0;
    realdir = (char *) malloc(strlen(d) + 3);
    memset(realdir, 0, strlen(d) + 3);
    strcpy(realdir, d);
    if (strcmp(realdir, ".") == 0)
	realdir[0] = '*';
    if (strcmp(realdir + strlen(realdir) - 2, "/.") == 0)
	realdir[strlen(realdir) - 1] = '*';
    if (realdir[strlen(realdir) - 1] == '/')
	strcat(realdir, "*");
    if (strchr(realdir, '*') || strchr(realdir, '?'))
	isDir = 1;
    if (strcmp(realdir, "*") == 0 || strcmp(realdir + strlen(realdir) - 2, "/*") == 0)
	isDir = 2;
    else {
	if (lstat(realdir, &s) == 0) {
	    if (S_ISDIR(s.st_mode)) {
		strcat(realdir, "/*");
		isDir = 2;
	    }
	}
    }

    if (isDir == 0) {
	if (ls_l) {
	    lsentry = ls_file(realdir, 0, 0, ls_F);
	    if (lsentry != NULL) {
		if (draconian_FILE != NULL) {
		    (void) signal(SIGALRM, draconian_alarm_signal);
		    alarm(timeout_data);
#if defined(USE_GSS)
		    sec_fprintf(out, "%s", lsentry);
#else
		    fputs(lsentry, out);
#endif /* defined(USE_GSS) */
		    (void) signal(SIGALRM, SIG_DFL);
		}
		free(lsentry);
	    }
	}
	else {
	    if (draconian_FILE != NULL) {
		(void) signal(SIGALRM, draconian_alarm_signal);
		alarm(timeout_data);
#if defined(USE_GSS)
		sec_fprintf(out, "%s", realdir);
#else
		fputs(realdir, out);
#endif /* defined(USE_GSS) */
		(void) signal(SIGALRM, SIG_DFL);
	    }
	}
	free(realdir);
    }
    else {
	if (ls_R) {
	    numSubdirs = 0;
	    subdirs = (char **) malloc(200 * sizeof(char *));
	    memset(subdirs, 0, 200 * sizeof(char *));
	}

	dl_size = 65536;
	dirlist = (char *) malloc(65536);
	memset(dirlist, 0, 65536);
	dl_used = 0;

	total = 0;
	memset(&g, 0, sizeof(g));
	if (ls_a) {
#ifdef GLOB_PERIOD
	    if (glob(realdir, GLOB_ERR | GLOB_PERIOD, NULL, &g) != 0)
		g.gl_pathc = 0;
#else
	    dperiod = (char *) malloc(strlen(realdir) + 2);
	    memset(dperiod, 0, strlen(realdir) + 2);
	    strcpy(dperiod, ".");
	    strcat(dperiod, realdir);
	    if (glob(dperiod, GLOB_ERR, NULL, &g) != 0)
		g.gl_pathc = 0;
	    glob(realdir, GLOB_ERR | GLOB_APPEND, NULL, &g);
	    free(dperiod);
#endif
	}
	else if (glob(realdir, GLOB_ERR, NULL, &g) != 0)
	    g.gl_pathc = 0;
	free(realdir);
	for (i = 0; i < g.gl_pathc; i++) {
	    c = g.gl_pathv[i];
	    if (lstat(c, &s) != -1) {
		if (ls_l) {
		    total += s.st_blocks;
		    lsentry = ls_file(c, 0, 1, ls_F);
		    if (lsentry != NULL) {
			/* This can actually happen even though the lstat() worked - 
			   if someone deletes the file between the lstat() and ls_file()
			   calls. Unlikely, but better safe than sorry... */
			int flag = snprintf(dirlist + dl_used, dl_size - dl_used, "%s", lsentry);
			dl_used += (flag == -1 ? dl_size - dl_used : flag);
			free(lsentry);
		    }
		}
		else {
		    int flag;
		    lsentry = ls_file(c, 1, 1, ls_F);
		    if (lsentry != NULL) {
		        flag = snprintf(dirlist + dl_used, dl_size - dl_used, "%s", lsentry);
		        dl_used += (flag == -1 ? dl_size - dl_used : flag);
			free(lsentry);
		    }
		}
		if ((ls_R != 0) && (S_ISDIR(s.st_mode))
		    && (strcmp(c, "..") != 0) && (strcmp(c, ".") != 0)
		&& !(strlen(c) > 3 && strcmp(c + strlen(c) - 3, "/..") == 0)
		    && !(strlen(c) > 2 && strcmp(c + strlen(c) - 2, "/.") == 0)) {
		    subdirs[numSubdirs++] = strdup(c);
		    if ((numSubdirs % 200) == 0)
			subdirs = (char **) realloc(subdirs, (numSubdirs + 200) * sizeof(char *));
		}
	    }
	    if (dl_used + 512 >= dl_size) {
		dl_size += 65536;
		dirlist = (char *) realloc(dirlist, dl_size);
	    }
	}
	globfree(&g);
	if (ls_l && isDir == 2 && omit_total == 0) {
	    if (draconian_FILE != NULL) {
		(void) signal(SIGALRM, draconian_alarm_signal);
		alarm(timeout_data);
#if defined(USE_GSS)
		sec_fprintf(out, "total %u\r\n", total);
#else
		fprintf(out, "total %u\r\n", total);
#endif /* defined(USE_GSS) */
	    }
	}
	if (draconian_FILE != NULL) {
	    (void) signal(SIGALRM, draconian_alarm_signal);
	    alarm(timeout_data);
#if defined(USE_GSS)
	    sec_fprintf(out, "%s", dirlist);
#else
	    fputs(dirlist, out);
#endif /* defined(USE_GSS) */
	}
	free(dirlist);
	if (ls_R) {
	    for (i = 0; i < numSubdirs; i++) {
		if (draconian_FILE != NULL) {
		    (void) signal(SIGALRM, draconian_alarm_signal);
		    alarm(timeout_data);
#if defined(USE_GSS)
		    sec_fprintf(out, "\r\n%s:\r\n", subdirs[i]);
#else
		    fprintf(out, "\r\n%s:\r\n", subdirs[i]);
#endif /* defined(USE_GSS) */
		    ls_dir(subdirs[i], ls_a, ls_F, ls_l, ls_R, 0, out);
		}
		free(subdirs[i]);
	    }
	    free(subdirs);
	}
    }
}

void ls(char *file, char nlst)
{
    FILE *out;
    char free_file = 0;
    char ls_l = 0, ls_a = 0, ls_R = 0, ls_F = 0;

    if (nlst == 0)
	ls_l = 1;		/* LIST defaults to ls -l */
    if (file == NULL) {
	file = strdup(".");
	free_file = 1;
    }
    if (strcmp(file, "*") == 0)
	file[0] = '.';

    if (file[0] == '-') {	/* options... */
	if (strchr(file, ' ') == 0) {
	    if (strchr(file, 'l'))
		ls_l = 1;
	    if (strchr(file, 'a'))
		ls_a = 1;
	    if (strchr(file, 'R'))
		ls_R = 1;
	    if (strchr(file, 'F'))
		ls_F = 1;
	    file = strdup(".");
	    free_file = 1;
	}
	else {
	    if (strchr(file, 'l') != NULL && strchr(file, 'l') < strchr(file, ' '))
		ls_l = 1;
	    if (strchr(file, 'a') != NULL && strchr(file, 'a') < strchr(file, ' '))
		ls_a = 1;
	    if (strchr(file, 'R') != NULL && strchr(file, 'R') < strchr(file, ' '))
		ls_R = 1;
	    if (strchr(file, 'F') != NULL && strchr(file, 'F') < strchr(file, ' '))
		ls_F = 1;
	    file = strchr(file, ' ');
	}
    }
    while (file[0] == ' ')	/* ignore additional whitespaces between parameters */
	file++;
    if (strlen(file) == 0) {
	file = strdup(".");
	free_file = 1;
    }

    out = dataconn("directory listing", -1, "w");
    draconian_FILE = out;

    transflag++;

    fixpath(file);
    if (file[0] == '\0') {
	if (free_file != 0)
	    free(file);
	file = strdup(".");
	free_file = 1;
    }

    ls_dir(file, ls_a, ls_F, ls_l, ls_R, 0, out);
    data = -1;
    pdata = -1;
    if (draconian_FILE != NULL) {
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
#if defined(USE_GSS)
	if (sec_fflush(out) < 0) {
	    draconian_FILE = NULL;
	    alarm(0);
	    transflag = 0;
	    perror_reply(550, "Data connection");
	    fclose(out);
	    goto ls_done;
	}
#else
	fflush(out);
#endif /* defined(USE_GSS) */
    }
    if (draconian_FILE != NULL) {
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
	socket_flush_wait(out);
    }
    if (draconian_FILE != NULL) {
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
	fclose(out);
	draconian_FILE = NULL;
    }
    alarm(0);
    transflag = 0;
    reply(226, "Transfer complete.");
  ls_done:
    if (free_file != 0)
	free(file);
}
#endif /* INTERNAL_LS */

void retrieve(char *cmd, char *name)
{
    FILE *fin = NULL, *dout;
    struct stat st, junk;
    int (*closefunc) () = NULL;
    int options = 0;
    int ThisRetrieveIsData = retrieve_is_data;
    time_t start_time = time(NULL);
    char *logname;
    char namebuf[MAXPATHLEN];
    char fnbuf[MAXPATHLEN];
    static int TransferComplete;	/* static as retrieve can call itself */
    struct convert *cptr;
    char realname[MAXPATHLEN];
    int stat_ret = -1;
    size_t buffersize;

    TransferComplete = 0;
    wu_realpath(name, realname, chroot_path);

    if (cmd == NULL && (stat_ret = stat(name, &st)) == 0)
	/* there isn't a command and the file exists */
	if (use_accessfile && checknoretrieve(name)) {	/* see above.  _H */
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to download %s (noretrieve)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to download %s (noretrieve)",
			   pw->pw_name, remoteident, realname);
	    return;
	}

#ifdef TRANSFER_COUNT
#ifdef TRANSFER_LIMIT
    if (retrieve_is_data)
	if (((file_limit_data_out > 0) && (file_count_out >= file_limit_data_out))
	    || ((file_limit_data_total > 0) && (file_count_total >= file_limit_data_total))
	    || ((data_limit_data_out > 0) && (data_count_out >= data_limit_data_out))
	    || ((data_limit_data_total > 0) && (data_count_total >= data_limit_data_total))) {
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to retrieve %s (Transfer limits exceeded)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to retrieve %s (Transfer limits exceeded)",
			   pw->pw_name, remoteident, realname);
	    reply(553, "Permission denied on server. (Transfer limits exceeded)");
	    return;
	}
    if (((file_limit_raw_out > 0) && (xfer_count_out >= file_limit_raw_out))
	|| ((file_limit_raw_total > 0) && (xfer_count_total >= file_limit_raw_total))
	|| ((data_limit_raw_out > 0) && (byte_count_out >= data_limit_raw_out))
	|| ((data_limit_raw_total > 0) && (byte_count_total >= data_limit_raw_total))) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to retrieve %s (Transfer limits exceeded)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to retrieve %s (Transfer limits exceeded)",
		       pw->pw_name, remoteident, realname);
	reply(553, "Permission denied on server. (Transfer limits exceeded)");
	return;
    }
#ifdef RATIO
    if (retrieve_is_data && (upload_download_rate > 0) )
	if( freefile = is_downloadfree(name) ) {
	    syslog(LOG_INFO, "%s is download free.", name );
	}
	else {
	    if ((cmd == NULL) && ((data_count_in * upload_download_rate) < (data_count_out - total_free_dl))) {
		reply(550, "%s: Upload/Download ratio exceeded", name);
		goto done;
	    }
	}
#endif /* RATIO */
#endif
#endif

    logname = (char *) NULL;
    if (cmd == NULL && stat_ret != 0) {		/* file does not exist */
	char *ptr;

	for (cptr = cvtptr; cptr != NULL; cptr = cptr->next) {
	    if (!(mangleopts & O_COMPRESS) && (cptr->options & O_COMPRESS))
		continue;
	    if (!(mangleopts & O_UNCOMPRESS) && (cptr->options & O_UNCOMPRESS))
		continue;
	    if (!(mangleopts & O_TAR) && (cptr->options & O_TAR))
		continue;

	    if ((cptr->stripfix) && (cptr->postfix)) {
		int pfxlen = strlen(cptr->postfix);
		int sfxlen = strlen(cptr->stripfix);
		int namelen = strlen(name);

		if (namelen <= pfxlen)
		    continue;
		if (((namelen - pfxlen + sfxlen) >= sizeof(fnbuf)) ||
		    (namelen >= sizeof(fnbuf)))
		    continue;

		(void) strcpy(fnbuf, name);
		if (strcmp(fnbuf + namelen - pfxlen, cptr->postfix))
		    continue;
		*(fnbuf + namelen - pfxlen) = '\0';
		(void) strcat(fnbuf, cptr->stripfix);
		if (stat(fnbuf, &st) != 0)
		    continue;
	    }
	    else if (cptr->postfix) {
		int pfxlen = strlen(cptr->postfix);
		int namelen = strlen(name);

		if ((namelen <= pfxlen) || (namelen >= sizeof(fnbuf)))
		    continue;
		(void) strcpy(fnbuf, name);
		if (strcmp(fnbuf + namelen - pfxlen, cptr->postfix))
		    continue;
		*(fnbuf + namelen - pfxlen) = (char) NULL;
		if (stat(fnbuf, &st) != 0)
		    continue;
	    }
	    else if (cptr->stripfix) {
		if (strlen(name) + strlen(cptr->stripfix) >= sizeof(fnbuf))
		    continue;
		(void) strcpy(fnbuf, name);
		(void) strcat(fnbuf, cptr->stripfix);
		if (stat(fnbuf, &st) != 0)
		    continue;
	    }
	    else {
		continue;
	    }

	    if (S_ISDIR(st.st_mode)) {
		if (!cptr->types || !(cptr->types & T_DIR)) {
		    reply(550, "Cannot %s directories.", cptr->name);
		    return;
		}
		if ((cptr->options & O_TAR)) {
		    strcpy(namebuf, fnbuf);
		    if (strlcat(namebuf, "/.notar", sizeof(namebuf)) >=
			sizeof(namebuf))
			continue;
		    if (stat(namebuf, &junk) == 0) {
			if (log_security)
			    if (anonymous)
				syslog(LOG_NOTICE, "anonymous(%s) of %s tried to tar %s (.notar)",
				       guestpw, remoteident, realname);
			    else
				syslog(LOG_NOTICE, "%s of %s tried to tar %s (.notar)",
				       pw->pw_name, remoteident, realname);
			reply(550, "Sorry, you may not TAR that directory.");
			return;
		    }
		}
	    }
/* XXX: checknoretrieve() test is weak in that if I can't get /etc/passwd
   but I can tar /etc or /, I still win.  Be careful out there... _H*
   but you could put .notar in / and /etc and stop that ! */
	    if (use_accessfile && checknoretrieve(fnbuf)) {
		if (log_security)
		    if (anonymous)
			syslog(LOG_NOTICE, "anonymous(%s) of %s tried to download %s (noretrieve)",
			       guestpw, remoteident, realname);
		    else
			syslog(LOG_NOTICE, "%s of %s tried to download %s (noretrieve)",
			       pw->pw_name, remoteident, realname);
		return;
	    }

	    if (S_ISREG(st.st_mode) && (!cptr->types || (cptr->types & T_REG) == 0)) {
		reply(550, "Cannot %s plain files.", cptr->name);
		return;
	    }
	    if (S_ISREG(st.st_mode) != 0 && S_ISDIR(st.st_mode) != 0) {
		reply(550, "Cannot %s special files.", cptr->name);
		return;
	    }
	    if ((!cptr->types || !(cptr->types & T_ASCII)) && deny_badasciixfer(550, ""))
		return;

	    logname = &fnbuf[0];
	    options |= cptr->options;

	    strcpy(namebuf, cptr->external_cmd);
	    if ((ptr = strchr(namebuf, ' ')) != NULL)
		*ptr = '\0';
	    if (stat(namebuf, &junk) != 0) {
		syslog(LOG_ERR, "external command %s not found", namebuf);
		reply(550,
		"Local error: conversion program not found. Cannot %s file.",
		      cptr->name);
		return;
	    }
	    (void) retrieve(cptr->external_cmd, logname);

	    goto logresults;	/* transfer of converted file completed */
	}
    }

    if (cmd == NULL) {		/* no command */
	fin = fopen(name, "r"), closefunc = fclose;
	st.st_size = 0;
    }
    else {			/* run command */
	static char line[BUFSIZ];

	(void) snprintf(line, sizeof(line), cmd, name), name = line;
	fin = ftpd_popen(line, "r", 1), closefunc = ftpd_pclose;
	st.st_size = -1;
#ifdef HAVE_ST_BLKSIZE
	st.st_blksize = BUFSIZ;
#endif
    }
    if (fin == NULL) {
	if (errno != 0)
	    perror_reply(550, name);
	if ((errno == EACCES) || (errno == EPERM))
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to download %s (file permissions)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to download %s (file permissions)",
			   pw->pw_name, remoteident, realname);
	return;
    }
    if (cmd == NULL &&
	(fstat(fileno(fin), &st) < 0 || (st.st_mode & S_IFMT) != S_IFREG)) {
	reply(550, "%s: not a plain file.", name);
	goto done;
    }
    if (restart_point) {
	if (type == TYPE_A) {
	    register int c;
	    off_t i;

	    i = 0;
	    while (i++ < restart_point) {
		if ((c = getc(fin)) == EOF) {
		    perror_reply(550, name);
		    goto done;
		}
		if (c == '\n')
		    i++;
	    }
	}
	else if (lseek(fileno(fin), restart_point, SEEK_SET) < 0) {
	    perror_reply(550, name);
	    goto done;
	}
    }

    dout = dataconn(name, st.st_size, "w");
    if (dout == NULL)
	goto done;

    if (sendbufsz > 0) {
	buffersize = sendbufsz;
    }
    else {
#ifdef BUFFER_SIZE
	buffersize = BUFFER_SIZE;
#elif HAVE_ST_BLKSIZE
	buffersize = st.st_blksize * 2;
#else
	buffersize = BUFSIZ * 16;
#endif
    }

#ifdef THROUGHPUT
    TransferComplete = send_data(name, fin, dout, buffersize);
#else
    TransferComplete = send_data(fin, dout, buffersize);
#endif
#ifdef SIGPIPE
    (void) signal(SIGPIPE, SIG_IGN);
#endif
    (void) fclose(dout);
#ifdef SIGPIPE
    (void) signal(SIGPIPE, lostconn);
#endif

  logresults:
    if (ThisRetrieveIsData)
	fb_realpath((logname != NULL) ? logname : name, LastFileTransferred);

    if (log_outbound_xfers && (xferlog || syslogmsg) && (cmd == NULL)) {
	char msg[MAXXFERSTRLEN];	/* see extensions.h */
	int xfertime = time(NULL) - start_time;
	size_t msglen;

	if (!xfertime)
	    xfertime++;

	/* Gather transfer statistics */
	xfervalues.filename = (logname != NULL) ? logname : name;
	xfervalues.filesize = st.st_size;
	xfervalues.transfer_bytes = byte_count;
	xfervalues.transfer_direction = 'o';
	xfervalues.transfer_type = (type == TYPE_A) ? 'a' : 'b';
	xfervalues.transfer_time = xfertime;
	xfervalues.restart_offset = restart_point;
	strlcpy(xfervalues.special_action, opt_string(options), MAXSPACTCHARS);
	xfervalues.access_mode = anonymous ? 'a' : (guest ? 'g' : 'r');
	xfervalues.auth = authenticated;
	xfervalues.completion = TransferComplete ? 'c' : 'i';

	xferdone = 1;
	msg_massage(xferlog_format, msg, sizeof(msg));
	xferdone = 0;

	/* Ensure msg always ends with '\n' */
	msglen = strlen(msg);
	if (msglen == sizeof(msg) - 1) {
	    msg[sizeof(msg) - 2] = '\n';
	    msg[sizeof(msg) - 1] = '\0';
	}
	else {
	    msg[msglen] = '\n';
	    msg[msglen + 1] = '\0';
	}

	if (syslogmsg != 1)
	    write(xferlog, msg, strlen(msg));
	if (syslogmsg != 0) {
	    char *msgp = msg;
	    /*
	     * To preserve the behavior when the xferlog format was fixed, skip
	     * over the time string if the message starts with the local time.
	     */
	    if (strncmp(xferlog_format, "%T ", 3) == 0)
		msgp += 25;
	    syslog(LOG_INFO, "xferlog (send): %s", msgp);
	}
    }
    data = -1;
    pdata = -1;
  done:
    if (closefunc)
	(*closefunc) (fin);
}

void store(char *name, char *mode, int unique)
{
    FILE *fout, *din;
    struct stat st;
    int TransferIncomplete = 1;
    char *gunique(char *local);
    time_t start_time = time(NULL);

    struct aclmember *entry = NULL;

    int fdout;
    char realname[MAXPATHLEN];

#ifdef OVERWRITE
    int overwrite = 1;
    int exists = 0;

#endif /* OVERWRITE */

    int open_flags = 0;

#ifdef UPLOAD
    mode_t oldmask;
    uid_t uid;
    gid_t gid;
    uid_t oldid;
    int f_mode = -1, match_value = -1;
    int valid = 0;
    int ret, serrno;
    open_flags = (O_RDWR | O_CREAT |
		  ((mode != NULL && *mode == 'a') ? O_APPEND : O_TRUNC));
#endif /* UPLOAD */

    wu_realpath(name, realname, chroot_path);

#ifdef TRANSFER_COUNT
#ifdef TRANSFER_LIMIT
    if (((file_limit_data_in > 0) && (file_count_in >= file_limit_data_in))
	|| ((file_limit_data_total > 0) && (file_count_total >= file_limit_data_total))
      || ((data_limit_data_in > 0) && (data_count_in >= data_limit_data_in))
	|| ((data_limit_data_total > 0) && (data_count_total >= data_limit_data_total))) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to upload %s (Transfer limits exceeded)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to upload %s (Transfer limits exceeded)",
		       pw->pw_name, remoteident, realname);
	reply(553, "Permission denied on server. (Transfer limits exceeded)");
	return;
    }
    if (((file_limit_raw_in > 0) && (xfer_count_in >= file_limit_raw_in))
	|| ((file_limit_raw_total > 0) && (xfer_count_total >= file_limit_raw_total))
	|| ((data_limit_raw_in > 0) && (byte_count_in >= data_limit_raw_in))
	|| ((data_limit_raw_total > 0) && (byte_count_total >= data_limit_raw_total))) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to upload %s (Transfer limits exceeded)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to upload %s (Transfer limits exceeded)",
		       pw->pw_name, remoteident, realname);
	reply(553, "Permission denied on server. (Transfer limits exceeded)");
	return;
    }
#endif
#endif

    if (unique && stat(name, &st) == 0 &&
	(name = gunique(name)) == NULL)
	return;

    /*
     * check the filename, is it legal?
     */
    if ((fn_check(name)) <= 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to upload \"%s\" (path-filter)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to upload \"%s\" (path-filter)",
		       pw->pw_name, remoteident, realname);
	return;
    }

#ifdef OVERWRITE
    /* if overwrite permission denied and file exists... then deny the user
     * permission to write the file. */
    while (getaclentry("overwrite", &entry) && ARG0 && ARG1 != NULL) {
	if (type_match(ARG1))
	    if (strcasecmp(ARG0, "yes") != 0) {
		overwrite = 0;
		open_flags |= O_EXCL;
	    }
    }

#ifdef PARANOID
    overwrite = 0;
#endif
    if (!stat(name, &st))
	exists = 1;

    if (!overwrite && exists) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to overwrite %s",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to overwrite %s",
		       pw->pw_name, remoteident, realname);
	reply(553, "%s: Permission denied on server. (Overwrite)", name);
	return;
    }
#endif /* OVERWRITE */

#ifdef UPLOAD
    if ((match_value = upl_check(name, &uid, &gid, &f_mode, &valid)) < 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to upload %s (upload denied)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to upload %s (upload denied)",
		       pw->pw_name, remoteident, realname);
	return;
    }

    /* do not truncate the file if we are restarting */
    if (restart_point)
	open_flags &= ~O_TRUNC;

    /* if the user has an explicit new file mode, than open the file using
     * that mode.  We must take care to not let the umask affect the file
     * mode.
     * 
     * else open the file and let the default umask determine the file mode. */
    if (f_mode >= 0) {
	oldmask = umask(0000);
	fdout = open(name, open_flags, f_mode);
	umask(oldmask);
    }
    else
	fdout = open(name, open_flags, 0666);

    if (fdout < 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to upload %s (permissions)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to upload %s (permissions)",
		       pw->pw_name, remoteident, realname);
	perror_reply(553, name);
	return;
    }
    /* if we have a uid and gid, then use them. */

#ifdef OVERWRITE
    if (!exists)
#endif
	if (valid > 0) {
	    oldid = geteuid();
	    if (uid != 0)
		(void) seteuid((uid_t) uid);
	    if ((uid == 0) || ((fchown(fdout, uid, gid)) < 0)) {
		chown_priv_on(0);
		ret = fchown(fdout, uid, gid);
		serrno = errno;
		chown_priv_off(oldid);
		if (ret < 0) {
		    errno = serrno;
		    perror_reply(550, "fchown");
		    return;
		}
	    }
	    else
		(void) seteuid(oldid);
	}
#endif /* UPLOAD */

    if (restart_point && (open_flags & O_APPEND) == 0)
	mode = "r+";

#ifdef UPLOAD
    fout = fdopen(fdout, mode);
#else
    fout = fopen(name, mode);
#endif /* UPLOAD */

    if (fout == NULL) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to upload %s (permissions)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to upload %s (permissions)",
		       pw->pw_name, remoteident, realname);
	perror_reply(553, name);
	return;
    }
    if (restart_point && (open_flags & O_APPEND) == 0) {
	if (type == TYPE_A) {
	    register int c;
	    off_t i;

	    i = 0;
	    while (i++ < restart_point) {
		if ((c = getc(fout)) == EOF) {
		    perror_reply(550, name);
		    goto done;
		}
		if (c == '\n')
		    i++;
	    }
	    /* We must do this seek to "current" position because we are
	     * changing from reading to writing. */
#if _FILE_OFFSET_BITS == 64
	    if (fseeko(fout, 0L, SEEK_CUR) < 0) {
#else
	    if (fseek(fout, 0L, SEEK_CUR) < 0) {
#endif
		perror_reply(550, name);
		goto done;
	    }
	}
	else if (lseek(fileno(fout), restart_point, SEEK_SET) < 0) {
	    perror_reply(550, name);
	    goto done;
	}
    }
    din = dataconn(name, (off_t) - 1, "r");
    if (din == NULL)
	goto done;
    TransferIncomplete = receive_data(din, fout);

    if (fstat(fileno(fout), &st) != 0) {
	/* shouldn't fail, but just in case */
	st.st_size = -1;
    }
    (void) fclose(din);
    if (TransferIncomplete == 0) {
	if (unique)
	    reply(226, "Transfer complete (unique file name:%s).", name);
	else
	    reply(226, "Transfer complete.");
    }

    fb_realpath(name, LastFileTransferred);

#ifdef MAIL_ADMIN
    if (anonymous && incmails > 0) {
	FILE *sck = NULL;

	unsigned char temp = 0, temp2 = 0;
	char pathname[MAXPATHLEN];
	while ((temp < mailservers) && (sck == NULL))
	    sck = SockOpen(mailserver[temp++], 25);
	if (sck == NULL) {
	    syslog(LOG_ERR, "Can't connect to a mailserver.");
	    goto mailfail;
	}
	if (Reply(sck) != 220) {
	    syslog(LOG_ERR, "Mailserver failed to initiate contact.");
	    goto mailfail;
	}
	if (Send(sck, "HELO localhost\r\n") != 250) {
	    syslog(LOG_ERR, "Mailserver doesn't understand HELO.");
	    goto mailfail;
	}
	if (Send(sck, "MAIL FROM: <%s>\r\n", email(mailfrom)) != 250) {
	    syslog(LOG_ERR, "Mailserver didn't accept MAIL FROM.");
	    goto mailfail;
	}
	for (temp = 0; temp < incmails; temp++) {
	    if (Send(sck, "RCPT TO: <%s>\r\n", email(incmail[temp])) == 250)
		temp2++;
	}
	if (temp2 == 0) {
	    syslog(LOG_ERR, "Mailserver didn't accept any RCPT TO.");
	    goto mailfail;
	}
	if (Send(sck, "DATA\r\n") != 354) {
	    syslog(LOG_ERR, "Mailserver didn't accept DATA.");
	    goto mailfail;
	}
	SockPrintf(sck, "From: wu-ftpd <%s>\r\n", mailfrom);
	SockPrintf(sck, "Subject: New file uploaded: %s\r\n\r\n", name);
	fb_realpath(name, pathname);
	SockPrintf(sck, "%s uploaded %s from %s.\r\nFile size is %" L_FORMAT ".\r\nPlease move the file where it belongs.\r\n", guestpw, pathname, remotehost, st.st_size);
	if (Send(sck, ".\r\n") != 250)
	    syslog(LOG_ERR, "Message rejected by mailserver.");
	if (Send(sck, "QUIT\r\n") != 221)
	    syslog(LOG_ERR, "Mailserver didn't accept QUIT.");
      mailfail:
	if (sck != NULL)
	    fclose(sck);
    }
#endif /* MAIL_ADMIN */

    if (log_incoming_xfers && (xferlog || syslogmsg)) {
	char msg[MAXXFERSTRLEN];	/* see extensions.h */
	int xfertime = time(NULL) - start_time;
	size_t msglen;

	if (!xfertime)
	    xfertime++;

	/* Gather transfer statistics */
	xfervalues.filename = name;
	xfervalues.filesize = st.st_size;
	xfervalues.transfer_bytes = byte_count;
	xfervalues.transfer_direction = 'i';
	xfervalues.transfer_type = (type == TYPE_A) ? 'a' : 'b';
	xfervalues.transfer_time = xfertime;
	xfervalues.restart_offset = restart_point;
	strlcpy(xfervalues.special_action, opt_string(0), MAXSPACTCHARS);
	xfervalues.access_mode = anonymous ? 'a' : (guest ? 'g' : 'r');
	xfervalues.auth = authenticated;
	xfervalues.completion = TransferIncomplete ? 'i' : 'c';

	xferdone = 1;
	msg_massage(xferlog_format, msg, sizeof(msg));
	xferdone = 0;

	/* Ensure msg always ends with '\n' */
	msglen = strlen(msg);
	if (msglen == sizeof(msg) - 1) {
	    msg[sizeof(msg) - 2] = '\n';
	    msg[sizeof(msg) - 1] = '\0';
	}
	else {
	    msg[msglen] = '\n';
	    msg[msglen + 1] = '\0';
	}

	if (syslogmsg != 1)
	    write(xferlog, msg, strlen(msg));
	if (syslogmsg != 0) {
	    char *msgp = msg;
	    /*
	     * To preserve the behavior when the xferlog format was fixed, skip
	     * over the time string if the message starts with the local time.
	     */
	    if (strncmp(xferlog_format, "%T ", 3) == 0)
		msgp += 25;
	    syslog(LOG_INFO, "xferlog (recv): %s", msgp);
	}
    }
    data = -1;
    pdata = -1;
  done:
    (void) fclose(fout);
}

FILE *getdatasock(char *mode)
{
    int s, on = 1, tries;

    if (data >= 0)
	return (fdopen(data, mode));
    port_priv_on(0);
    s = socket(SOCK_FAMILY(data_dest), SOCK_STREAM, 0);
    if (s < 0)
	goto bad;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
		   (char *) &on, sizeof(on)) < 0)
	goto bad;
    if (keepalive)
	(void) setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on));
    if (TCPwindowsize)
	(void) setsockopt(s, SOL_SOCKET, (*mode == 'w' ? SO_SNDBUF : SO_RCVBUF),
			  (char *) &TCPwindowsize, sizeof(TCPwindowsize));
    /* anchor socket to avoid multi-homing problems */
#ifdef INET6
    if (SOCK_FAMILY(data_dest) == SOCK_FAMILY(ctrl_addr))
	data_source = ctrl_addr;
    else if ((SOCK_FAMILY(data_dest) == AF_INET) && ctrl_v4mapped) {
	struct sockaddr_in6 *ctrl_sin6 = (struct sockaddr_in6 *)&ctrl_addr;
	struct sockaddr_in *data_sin = (struct sockaddr_in *)&data_source;

	SET_SOCK_FAMILY(data_source, AF_INET);
	memcpy(&data_sin->sin_addr, &ctrl_sin6->sin6_addr.s6_addr[12],
	       sizeof(struct in_addr));
    }
    else {
	memset(&data_source, 0, sizeof(struct sockaddr_in6));
	SET_SOCK_FAMILY(data_source, SOCK_FAMILY(data_dest));
	SET_SOCK_ADDR_ANY(data_source);
    }
#else
    data_source = ctrl_addr;
#endif
    SET_SOCK_PORT(data_source, data_port);

#if defined(VIRTUAL) && defined(CANT_BIND)	/* can't bind to virtual address */
    SET_SOCK_ADDR_ANY(data_source);
#endif
    for (tries = 1;; tries++) {
	if (bind(s, (struct sockaddr *) &data_source, SOCK_LEN(data_source)) >= 0)
	    break;
	if (errno != EADDRINUSE || tries > 10)
	    goto bad;
	sleep(tries);
    }
#if defined(M_UNIX) && !defined(_M_UNIX)	/* bug in old TCP/IP release */
    {
	struct linger li;
	li.l_onoff = 1;
	li.l_linger = 900;
	if (setsockopt(s, SOL_SOCKET, SO_LINGER,
		       (char *) &li, sizeof(struct linger)) < 0) {
	    syslog(LOG_WARNING, "setsockopt (SO_LINGER): %m");
	    goto bad;
	}
    }
#endif
    port_priv_off((uid_t) pw->pw_uid);

#ifdef INET6
    /* IP_TOS is an IPv4 socket option */
    if (SOCK_FAMILY(data_source) == AF_INET)
#endif
    if ((on = IPClassOfService("data")) >= 0) {
	if (setsockopt(s, IPPROTO_IP, IP_TOS, (char *) &on, sizeof(int)) < 0)
	    syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
    }
#ifdef TCP_NOPUSH
    /*
     * Turn off push flag to keep sender TCP from sending short packets
     * at the boundaries of each write().  Should probably do a SO_SNDBUF
     * to set the send buffer size as well, but that may not be desirable
     * in heavy-load situations.
     */
    on = 1;
    if (setsockopt(s, IPPROTO_TCP, TCP_NOPUSH, (char *) &on, sizeof on) < 0)
	syslog(LOG_WARNING, "setsockopt (TCP_NOPUSH): %m");
#endif

    return (fdopen(s, mode));
  bad:
    on = errno;			/* hold errno for return */
    port_priv_off((uid_t) pw->pw_uid);
    if (s != -1)
	(void) close(s);
    errno = on;
    return (NULL);
}

FILE *dataconn(char *name, off_t size, char *mode)
{
    char sizebuf[32];
    FILE *file;
    int retry = 0;
    int on = 1;
    int cval, serrno;
    int cos;
#ifdef THROUGHPUT
    int bps;
    double bpsmult;
#endif

    file_size = size;
    byte_count = 0;
    if (size != (off_t) - 1)
	(void) sprintf(sizebuf, " (%" L_FORMAT " bytes)", size);
    else
	(void) strcpy(sizebuf, "");
    if (pdata >= 0) {
	struct SOCKSTORAGE from;
	char dataaddr[MAXHOSTNAMELEN];
#if defined(UNIXWARE) || defined(AIX)
	size_t fromlen = sizeof(from);
#else
	int fromlen = sizeof(from);
#endif
	int s;
#ifdef FD_ZERO
	int rv;
#endif

	if (keepalive)
	    (void) setsockopt(pdata, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on));
	if (TCPwindowsize)
	    (void) setsockopt(pdata, SOL_SOCKET, (*mode == 'w' ? SO_SNDBUF : SO_RCVBUF),
			    (char *) &TCPwindowsize, sizeof(TCPwindowsize));
#ifdef FD_ZERO
	do {
	    struct timeval timeout;
	    fd_set set;

	    FD_ZERO(&set);
	    FD_SET(pdata, &set);

	    timeout.tv_usec = 0;
	    timeout.tv_sec = timeout_accept;
#ifdef HPUX_SELECT
	    rv = select(pdata + 1, (int *) &set, NULL, NULL, &timeout);
#else
	    rv = select(pdata + 1, &set, (fd_set *) 0, (fd_set *) 0,
			(struct timeval *) &timeout);
#endif
	} while ((rv == -1) && (errno == EINTR));
	if ((rv != -1) && (rv != 0))
	    s = accept(pdata, (struct sockaddr *) &from, &fromlen);
	else
	    s = -1;
#else /* FD_ZERO */
	(void) signal(SIGALRM, alarm_signal);
	alarm(timeout_accept);
	s = accept(pdata, (struct sockaddr *) &from, &fromlen);
	alarm(0);
#endif
	if (s == -1) {
	    reply(425, "Can't open data connection.");
	    (void) close(pdata);
	    pdata = -1;
	    return (NULL);
	}
	(void) close(pdata);
	pdata = s;
#ifdef INET6
	/* IP_TOS is an IPv4 socket option */
	if (SOCK_FAMILY(from) == AF_INET)
#endif
	if ((cos = IPClassOfService("data")) >= 0)
	    (void) setsockopt(s, IPPROTO_IP, IP_TOS, (char *)&cos, sizeof(int));
	(void) strncpy(dataaddr, inet_stop(&from), sizeof(dataaddr));
	if (!pasv_allowed(dataaddr))
	    if (strcasecmp(dataaddr, remoteaddr) != 0) {
		/* 
		 * This will log when data connection comes from an address different
		 * than the control connection.
		 */
#ifdef FIGHT_PASV_PORT_RACE
		syslog(LOG_ERR, "%s of %s: data connect from %s for %s%s",
		       anonymous ? guestpw : pw->pw_name, remoteident,
		       dataaddr, name, sizebuf);
		reply(425, "Possible PASV port theft, cannot open data connection.");
		(void) close(pdata);
		pdata = -1;
		return (NULL);
#else
		syslog(LOG_NOTICE, "%s of %s: data connect from %s for %s%s",
		       anonymous ? guestpw : pw->pw_name, remoteident,
		       dataaddr, name, sizebuf);
#endif
	    }
#ifdef THROUGHPUT
	throughput_calc(name, &bps, &bpsmult);
	if (bps != -1) {
	    lreply(150, "Opening %s mode data connection for %s%s.",
		   type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
	    reply(150, "Restricting network throughput to %d bytes/s.", bps);
	}
	else
#endif
	    reply(150, "Opening %s mode data connection for %s%s.",
		  type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
	return (fdopen(pdata, mode));
    }
    if (data >= 0) {
	reply(125, "Using existing data connection for %s%s.",
	      name, sizebuf);
	usedefault = 1;
	return (fdopen(data, mode));
    }
    if (usedefault)
	data_dest = his_addr;
    if (SOCK_PORT(data_dest) == 0) {
	reply(500, "Can't build data connection: no PORT specified");
	return (NULL);
    }
    usedefault = 1;
    do {
	file = getdatasock(mode);
	if (file == NULL) {
	    reply(425, "Can't create data socket (%s,%d): %s.",
		  inet_stop(&data_source), ntohs(SOCK_PORT(data_source)),
			    strerror(errno));
	    return (NULL);
	}
	data = fileno(file);
	(void) signal(SIGALRM, alarm_signal);
	alarm(timeout_connect);
	cval = connect(data, (struct sockaddr *) &data_dest,
		       SOCK_LEN(data_dest));
	serrno = errno;
	alarm(0);
	if (cval == -1) {
	    /*
	     * When connect fails, the state of the socket is unspecified so
	     * it should be closed and a new socket created for each connection
	     * attempt. This also prevents denial of service problems when
	     * running on operating systems that only allow one non-connected
	     * socket bound to the same local address.
	     */
	    (void) fclose(file);
	    data = -1;
	    errno = serrno;
	    if ((errno == EADDRINUSE || errno == EINTR) && retry < swaitmax) {
		sleep((unsigned) swaitint);
		retry += swaitint;
	    }
	    else {
		perror_reply(425, "Can't build data connection");
		return (NULL);
	    }
	}
    } while (cval == -1);
    if (keepalive)
	(void) setsockopt(data, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on));
    if (TCPwindowsize)
	(void) setsockopt(data, SOL_SOCKET, (*mode == 'w' ? SO_SNDBUF : SO_RCVBUF),
			  (char *) &TCPwindowsize, sizeof(TCPwindowsize));
#ifdef THROUGHPUT
    throughput_calc(name, &bps, &bpsmult);
    if (bps != -1) {
	lreply(150, "Opening %s mode data connection for %s%s.",
	       type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
	reply(150, "Restricting network throughput to %d bytes/s.", bps);
    }
    else
#endif
	reply(150, "Opening %s mode data connection for %s%s.",
	      type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
    return (file);
}

/* Tranfer the contents of "instr" to "outstr" peer using the appropriate
 * encapsulation of the data subject to Mode, Structure, and Type.
 *
 * NB: Form isn't handled. */

int
#ifdef THROUGHPUT
    send_data(char *name, FILE *instr, FILE *outstr, size_t blksize)
#else
    send_data(FILE *instr, FILE *outstr, size_t blksize)
#endif
{
    register int c, cnt = 0;
    static char *buf;
    int netfd, filefd;
#ifdef THROUGHPUT
    int bps;
    double bpsmult;
    time_t t1, t2;
#endif
#ifdef SENDFILE
    int use_sf = 0;
    size_t xferred;
    struct stat st;
    struct sendfilevec sfv;
#endif

    buf = NULL;
    if (wu_setjmp(urgcatch)) {
	draconian_FILE = NULL;
	alarm(0);
	transflag = 0;
#ifdef SIGPIPE
	(void) signal(SIGPIPE, lostconn);
#endif
	if (buf)
	    (void) free(buf);
	retrieve_is_data = 1;
	return (0);
    }
    transflag++;

#ifdef THROUGHPUT
    throughput_calc(name, &bps, &bpsmult);
#endif

    switch (type) {

    case TYPE_A:
#ifdef SIGPIPE
	/*
	 * Ignore SIGPIPE while sending data, necessary so lostconn() isn't
	 * called if we write to the data connection after the client has
	 * closed it.
	 */
	(void) signal(SIGPIPE, SIG_IGN);
#endif
	draconian_FILE = outstr;
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
#ifdef THROUGHPUT
	if (bps != -1)
	    t1 = time(NULL);
#endif
	while ((draconian_FILE != NULL) && ((c = getc(instr)) != EOF)) {
	    if (++byte_count % 4096 == 0)
		alarm(timeout_data);
	    if (c == '\n') {
		if (ferror(outstr))
		    goto data_err;
		if (++byte_count % 4096 == 0)
		    alarm(timeout_data);
#if defined(USE_GSS)
		if (sec_putc('\r', outstr) != '\r')
		    goto data_err;
#else
		(void) putc('\r', outstr);
#endif
#ifdef TRANSFER_COUNT
		if (retrieve_is_data) {
		    data_count_total++;
		    data_count_out++;
		}
		byte_count_total++;
		byte_count_out++;
#endif
	    }
#if defined(USE_GSS)
	    if (sec_putc(c, outstr) != c)
		goto data_err;
#else
	    (void) putc(c, outstr);
#endif

#ifdef TRANSFER_COUNT
	    if (retrieve_is_data) {
		data_count_total++;
		data_count_out++;
	    }
	    byte_count_total++;
	    byte_count_out++;
#endif
#ifdef THROUGHPUT
	    if (bps > 0 && (byte_count % bps) == 0) {
		t2 = time(NULL);
		if (t2 == t1)
		    sleep(1);
		t1 = time(NULL);
	    }
#endif
	}
#ifdef THROUGHPUT
	if (bps != -1)
	    throughput_adjust(name);
#endif
	if (draconian_FILE != NULL) {
	    alarm(timeout_data);
#if defined(USE_GSS)
	    if (sec_fflush(outstr) < 0)
		goto data_err;
#else
	    fflush(outstr);
#endif /* defined(USE_GSS) */
	}
	if (draconian_FILE != NULL) {
	    alarm(timeout_data);
	    socket_flush_wait(outstr);
	}
	transflag = 0;
	if (ferror(instr))
	    goto file_err;
	if ((draconian_FILE == NULL) || ferror(outstr))
	    goto data_err;
	draconian_FILE = NULL;
	alarm(0);
#ifdef SIGPIPE
	(void) signal(SIGPIPE, lostconn);
#endif
	reply(226, "Transfer complete.");
#ifdef TRANSFER_COUNT
	if (retrieve_is_data) {
	    file_count_total++;
	    file_count_out++;
	}
	xfer_count_total++;
	xfer_count_out++;
#endif
	retrieve_is_data = 1;
	return (1);

    case TYPE_I:
    case TYPE_L:
#ifdef THROUGHPUT
	if (bps != -1)
	    blksize = bps;
#endif
	netfd = fileno(outstr);
	filefd = fileno(instr);
#ifdef SENDFILE
	/* check the input file is a regular file */
	if ((fstat(filefd, &st) == 0) && ((st.st_mode & S_IFMT) == S_IFREG)) {
#if defined(USE_GSS)
	    if (gss_info.data_prot == PROT_C || !IS_GSSAUTH(cur_auth_type) ||
		!(gss_info.authstate & GSS_ADAT_DONE))
#endif /* defined(USE_GSS) */
	    {
		use_sf = 1;
		/*
		 * Use a private sfv_flag SFV_NOWAIT to tell sendfilev(),
		 * when zero-copy is enabled, not to wait for all data to be
		 * ACKed before returning. This is important for throughput
		 * performance when sendfilev() is called to send small piece
		 * at a time.
		 */
		sfv.sfv_flag = SFV_NOWAIT;
		sfv.sfv_fd = filefd;
		sfv.sfv_off = restart_point;
		sfv.sfv_len = blksize;
	    }
	}
	if (use_sf == 0)
#endif
	if ((buf = (char *) malloc(blksize)) == NULL) {
	    transflag = 0;
	    perror_reply(451, "Local resource failure: malloc");
	    retrieve_is_data = 1;
	    return (0);
	}
#ifdef SIGPIPE
	/*
	 * Ignore SIGPIPE while sending data, necessary so lostconn() isn't
	 * called if we write to the data connection after the client has
	 * closed it.
	 */
	(void) signal(SIGPIPE, SIG_IGN);
#endif
	draconian_FILE = outstr;
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
#ifdef THROUGHPUT
	if (bps != -1)
	    t1 = time(NULL);
#endif
	while ((draconian_FILE != NULL) && (
#ifdef SENDFILE
	       (use_sf && (cnt = sendfilev(netfd, &sfv, 1, &xferred)) > 0)
	       || (!use_sf &&
#endif
		   ((cnt = read(filefd, buf, blksize)) > 0 &&
#if defined(USE_GSS)
		    sec_write(netfd, buf, cnt) == cnt)
#else
		    write(netfd, buf, cnt) == cnt)
#endif /* defined(USE_GSS) */
#ifdef SENDFILE
		  )
#endif
	)) {
	    alarm(timeout_data);
#ifdef SENDFILE
	    sfv.sfv_off += cnt;
#endif
	    byte_count += cnt;
#ifdef TRANSFER_COUNT
	    if (retrieve_is_data) {
#ifdef RATIO
		if( freefile ) {
		    total_free_dl += cnt;
		}
#endif /* RATIO */
		data_count_total += cnt;
		data_count_out += cnt;
	    }
	    byte_count_total += cnt;
	    byte_count_out += cnt;
#endif
#ifdef THROUGHPUT
	    if (bps != -1) {
		t2 = time(NULL);
		if (t2 == t1)
		    sleep(1);
		t1 = time(NULL);
	    }
#endif /* THROUGHPUT */
	}
#ifdef THROUGHPUT
	if (bps != -1)
	    throughput_adjust(name);
#endif
#if defined(USE_GSS)
	if (sec_fflush(outstr) < 0)
	    goto data_err;
#endif
	transflag = 0;
	if (buf)
	    (void) free(buf);
	if (draconian_FILE != NULL) {
	    alarm(timeout_data);
	    socket_flush_wait(outstr);
	}
	if (cnt != 0) {
#ifdef SENDFILE
	    if (use_sf && cnt < 0 && errno == EPIPE)
		goto data_err;
#endif
	    if (cnt < 0)
		goto file_err;
	    goto data_err;
	}
	if (draconian_FILE == NULL)
	    goto data_err;
	draconian_FILE = NULL;
	alarm(0);
#ifdef SIGPIPE
	(void) signal(SIGPIPE, lostconn);
#endif
	reply(226, "Transfer complete.");
#ifdef TRANSFER_COUNT
	if (retrieve_is_data) {
	    file_count_total++;
	    file_count_out++;
	}
	xfer_count_total++;
	xfer_count_out++;
#endif
	retrieve_is_data = 1;
	return (1);
    default:
	transflag = 0;
	reply(550, "Unimplemented TYPE %d in send_data", type);
	retrieve_is_data = 1;
	return (0);
    }

  data_err:
    draconian_FILE = NULL;
    alarm(0);
    transflag = 0;
#ifdef SIGPIPE
    (void) signal(SIGPIPE, lostconn);
#endif
    perror_reply(426, "Data connection");
    retrieve_is_data = 1;
    return (0);

  file_err:
    draconian_FILE = NULL;
    alarm(0);
    transflag = 0;
#ifdef SIGPIPE
    (void) signal(SIGPIPE, lostconn);
#endif
    perror_reply(551, "Error on input file");
    retrieve_is_data = 1;
    return (0);
}

/* Transfer data from peer to "outstr" using the appropriate encapulation of
 * the data subject to Mode, Structure, and Type.
 *
 * N.B.: Form isn't handled. */

int receive_data(FILE *instr, FILE *outstr)
{
    register int c;
    int rcnt = 0, n = 0, bare_lfs = 0;
    static char *buf;
    int netfd, filefd, wcnt;
#ifdef BUFFER_SIZE
    size_t buffer_size = BUFFER_SIZE;
#else
    size_t buffer_size = BUFSIZ * 16;
#endif

    buf = NULL;
    if (wu_setjmp(urgcatch)) {
	alarm(0);
	transflag = 0;
	if (buf)
	    (void) free(buf);
	return (-1);
    }
    transflag++;
    switch (type) {

    case TYPE_I:
    case TYPE_L:
#if defined(USE_GSS)
	if (GSSUSERAUTH_OK(gss_info))
	    buffer_size = gss_getinbufsz();
	else
#endif
	if (recvbufsz > 0)
	    buffer_size = recvbufsz;
	if ((buf = (char *) malloc(buffer_size)) == NULL) {
	    transflag = 0;
	    perror_reply(451, "Local resource failure: malloc");
	    return (-1);
	}
	netfd = fileno(instr);
	filefd = fileno(outstr);
	draconian_FILE = instr;
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);

	while ((draconian_FILE != NULL) &&
#if defined(USE_GSS)
	    (rcnt = sec_read(netfd, buf, buffer_size)) > 0) {
#else
	    (rcnt = read(netfd, buf, buffer_size)) > 0) {
#endif
	    for (wcnt = 0; wcnt < rcnt; wcnt += n) {
		if ((n = write(filefd, &buf[wcnt], rcnt - wcnt)) == -1)
		    break;
	    }
	    byte_count += wcnt;
#ifdef TRANSFER_COUNT
	    data_count_total += wcnt;
	    data_count_in += wcnt;
	    byte_count_total += wcnt;
	    byte_count_in += wcnt;
#endif
	    if (n == -1)
		break;
	    alarm(timeout_data);
	}
	transflag = 0;
	(void) free(buf);
	if ((rcnt == -1) || (draconian_FILE == NULL))
	    goto data_err;
	if (n == -1)
	    goto file_err;
	draconian_FILE = NULL;
	alarm(0);
#ifdef TRANSFER_COUNT
	file_count_total++;
	file_count_in++;
	xfer_count_total++;
	xfer_count_in++;
#endif
	return (0);

    case TYPE_E:
	reply(553, "TYPE E not implemented.");
	transflag = 0;
	return (-1);

    case TYPE_A:
	draconian_FILE = instr;
	(void) signal(SIGALRM, draconian_alarm_signal);
	alarm(timeout_data);
	while ((draconian_FILE != NULL) &&
#if defined(USE_GSS)
	    ((c = sec_getc(instr)) != EOF)
#else
	    ((c = getc(instr)) != EOF)
#endif
	) {
	    if (++byte_count % 4096 == 0)
		alarm(timeout_data);
	    if (c == '\n')
		bare_lfs++;
	    while (c == '\r') {
		if (ferror(outstr))
		    goto file_err;
		alarm(timeout_data);
		if (draconian_FILE != NULL) {
#if defined(USE_GSS)
		    if ((c = sec_getc(instr)) != '\n')
#else
		    if ((c = getc(instr)) != '\n')
#endif
			(void) putc('\r', outstr);
#ifdef TRANSFER_COUNT
		    data_count_total++;
		    data_count_in++;
		    byte_count_total++;
		    byte_count_in++;
#endif
		    if (c == EOF)	/* null byte fix, noid@cyborg.larc.nasa.gov */
			goto contin2;
		    if (++byte_count % 4096 == 0)
			alarm(timeout_data);
		}
	    }
	    (void) putc(c, outstr);
#ifdef TRANSFER_COUNT
	    data_count_total++;
	    data_count_in++;
	    byte_count_total++;
	    byte_count_in++;
#endif
	  contin2:;
	}
	fflush(outstr);
	if ((draconian_FILE == NULL) || ferror(instr))
	    goto data_err;
	if (ferror(outstr))
	    goto file_err;
	transflag = 0;
	draconian_FILE = NULL;
	alarm(0);
	if (bare_lfs) {
	    lreply(226, "WARNING! %d bare linefeeds received in ASCII mode", bare_lfs);
	    lreply(0, "   File may not have transferred correctly.");
	}
#ifdef TRANSFER_COUNT
	file_count_total++;
	file_count_in++;
	xfer_count_total++;
	xfer_count_in++;
#endif
	return (0);
    default:
	reply(550, "Unimplemented TYPE %d in receive_data", type);
	transflag = 0;
	return (-1);
    }

  data_err:
    draconian_FILE = NULL;
    alarm(0);
    transflag = 0;
    perror_reply(426, "Data Connection");
    return (-1);

  file_err:
    draconian_FILE = NULL;
    alarm(0);
    transflag = 0;
    perror_reply(452, "Error writing file");
    return (-1);
}

void statfilecmd(char *filename)
{
#ifndef INTERNAL_LS
    char line[BUFSIZ * 2], *ptr;
    FILE *fin;
    int c;
#endif /* ! INTERNAL_LS */

    fixpath(filename);
    if (filename[0] == '\0')
	filename = ".";
#ifndef INTERNAL_LS
    if (anonymous && dolreplies)
	(void) snprintf(line, sizeof(line), ls_long, filename);
    else
	(void) snprintf(line, sizeof(line), ls_short, filename);
    fin = ftpd_popen(line, "r", 0);
#endif /* ! INTERNAL_LS */
    lreply(213, "status of %s:", filename);
#ifndef INTERNAL_LS
    /*
       while ((c = getc(fin)) != EOF) {
       if (c == '\n') {
       if (ferror(stdout)) {
       perror_reply(421, "control connection");
       (void) ftpd_pclose(fin);
       dologout(1);
       / * NOTREACHED * /
       }
       if (ferror(fin)) {
       perror_reply(551, filename);
       (void) ftpd_pclose(fin);
       return;
       }
       (void) putc('\r', stdout);
       }
       (void) putc(c, stdout);
       }
     */
    while (fgets(line, sizeof(line), fin) != NULL) {
	if ((ptr = strchr(line, '\n')))		/* clip out unnecessary newline */
	    *ptr = '\0';
	lreply(0, "%s", line);
    }
    (void) ftpd_pclose(fin);
#else /* INTERNAL_LS */
    ls_dir(filename, 1, 0, 1, 0, 1, stdout);
#endif /* INTERNAL_LS */
    reply(213, "End of Status");
}

void statcmd(void)
{
    struct SOCKSTORAGE *sin;
    u_char *a, *p;
    unsigned short port;
#ifdef INET6
    int isv4 = 0;
#endif

    lreply(211, "%s FTP server status:", hostname);
    lreply(0, "     %s", version);
    if (nameserved)
	lreply(0, "     Connected to %s (%s)", remotehost, remoteaddr);
    else
	lreply(0, "     Connected to %s", remotehost);

    if (logged_in) {
	if (anonymous)
	    lreply(0, "     Logged in anonymously");
	else
	    lreply(0, "     Logged in as %s", pw->pw_name);
    }
    else if (askpasswd)
	lreply(0, "     Waiting for password");
    else
	lreply(0, "     Waiting for user name");

    if (type == TYPE_L)
#ifdef NBBY
	lreply(0, "     TYPE: %s %d; STRUcture: %s; transfer MODE: %s",
	       typenames[type], NBBY, strunames[stru], modenames[mode]);
#else
	lreply(0, "     TYPE: %s %d; STRUcture: %s; transfer MODE: %s",
	       typenames[type], bytesize, strunames[stru], modenames[mode]);
#endif /* NBBY */
    else
	lreply(0, "     TYPE: %s%s%s; STRUcture: %s; transfer MODE: %s",
	       typenames[type], (type == TYPE_A || type == TYPE_E) ?
	       ", FORM: " : "", (type == TYPE_A || type == TYPE_E) ?
	       formnames[form] : "", strunames[stru], modenames[mode]);
    if (data != -1)
	lreply(0, "     Data connection open");
    else if (pdata != -1 || usedefault == 0) {
	if (usedefault == 0) {
	    sin = &data_dest;
	    port = SOCK_PORT(data_dest);
	}
	else {
	    port = SOCK_PORT(pasv_addr);
	    if (route_vectored)
		sin = &vect_addr;
	    else
		sin = &pasv_addr;
	}
	a = (u_char *) SOCK_ADDR(*sin);
	p = (u_char *) &port;
#define UC(b) (((int) b) & 0xff)
#ifdef INET6
	if (SOCK_FAMILY(*sin) == AF_INET)
	    isv4 = 1;
	else if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)sin)->sin6_addr))
	{
	    isv4 = 1;
	    a += 12; /* move to the IPv4 part of an IPv4-mapped IPv6 address */
	}
	if (epsv_all)
	    lreply(0, "     EPSV only mode (EPSV ALL)");
	if (isv4 && !epsv_all)
#endif
	    lreply(0, "     %s (%d,%d,%d,%d,%d,%d)",
		   usedefault == 0 ? "PORT" : "PASV",
		   UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
#ifdef INET6
	lreply(0, "     %s (|%d|%s|%d|)", usedefault == 0 ? "EPRT" : "EPSV",
	       isv4 ? 1 : 2, inet_stop(sin), ntohs(port));
	if (!epsv_all)
	    if (isv4)
		lreply(0, "     %s (4,4,%d,%d,%d,%d,2,%d,%d)",
		       usedefault == 0 ? "LPRT" : "LPSV",
		       UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]),
		       UC(p[0]), UC(p[1]));
	    else
		lreply(0, "     %s (6,16,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,"
		       "%d,%d,%d,%d,2,%d,%d)",
		       usedefault == 0 ? "LPRT" : "LPSV",
		       UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]),
		       UC(a[4]), UC(a[5]), UC(a[6]), UC(a[7]),
		       UC(a[8]), UC(a[9]), UC(a[10]), UC(a[11]),
		       UC(a[12]), UC(a[13]), UC(a[14]), UC(a[15]),
		       UC(p[0]), UC(p[1]));
#endif
#undef UC
    }
    else
	lreply(0, "     No data connection");
#ifdef TRANSFER_COUNT
    lreply(0, "     %" L_FORMAT " data bytes received in %d files", data_count_in, file_count_in);
    lreply(0, "     %" L_FORMAT " data bytes transmitted in %d files", data_count_out, file_count_out);
    lreply(0, "     %" L_FORMAT " data bytes total in %d files", data_count_total, file_count_total);
    lreply(0, "     %" L_FORMAT " traffic bytes received in %d transfers", byte_count_in, xfer_count_in);
    lreply(0, "     %" L_FORMAT " traffic bytes transmitted in %d transfers", byte_count_out, xfer_count_out);
    lreply(0, "     %" L_FORMAT " traffic bytes total in %d transfers", byte_count_total, xfer_count_total);
#endif
    reply(211, "End of status");
}

void fatal(char *s)
{
    reply(451, "Error in server: %s\n", s);
    reply(221, "Closing connection due to server error.");
    dologout(0);
    /* NOTREACHED */
}

#define USE_REPLY_NOTFMT	(1<<1)	/* fmt is not a printf fmt (KLUDGE) */
#define USE_REPLY_LONG		(1<<2)	/* this is a long reply; use a - */

void vreply(long flags, int n, char *fmt, va_list ap)
{
    char buf[BUFSIZ * 16];

    flags &= USE_REPLY_NOTFMT | USE_REPLY_LONG;

    if (n)	/* if numeric is 0, don't output one; use n==0 in place of printf's */
	sprintf(buf, "%03d%c", n, flags & USE_REPLY_LONG ? '-' : ' ');

    /* This is somewhat of a kludge for autospout.  I personally think that
     * autospout should be done differently, but that's not my department. -Kev
     */
    if (flags & USE_REPLY_NOTFMT)
	snprintf(buf + (n ? 4 : 0), n ? sizeof(buf) - 4 : sizeof(buf), "%s", fmt);
    else
	vsnprintf(buf + (n ? 4 : 0), n ? sizeof(buf) - 4 : sizeof(buf), fmt, ap);

#if defined(USE_GSS)
    if (IS_GSSAUTH(cur_auth_type) &&
	(gss_info.authstate & GSS_ADAT_DONE) &&
	gss_info.ctrl_prot != PROT_C) {
	if (buf[strlen(buf)-1] != '\n')
		strlcat(buf, "\r\n", sizeof(buf));
	(void) sec_reply(buf, sizeof(buf), n);
    }
#endif

    if (debug)			/* debugging output :) */
	syslog(LOG_DEBUG, "<--- %s", buf);

    /* Yes, you want the debugging output before the client output; wrapping
     * stuff goes here, you see, and you want to log the cleartext and send
     * the wrapped text to the client.
     */

    printf("%s\r\n", buf);	/* and send it to the client */
#ifdef TRANSFER_COUNT
    byte_count_total += strlen(buf);
    byte_count_out += strlen(buf);
#endif
    /*
     * We dont need to worry about "sec_fflush" here since "sec_reply"
     * already wrapped the reply if necessary.
     */
    fflush(stdout);
}

void reply(int n, char *fmt,...)
{
    VA_LOCAL_DECL

	if (autospout != NULL) {	/* deal with the autospout stuff... */
	char *p, *ptr = autospout;

	while (*ptr) {
	    if ((p = strchr(ptr, '\n')) != NULL)	/* step through line by line */
		*p = '\0';

	    /* send a line...(note that this overrides dolreplies!) */
	    vreply(USE_REPLY_LONG | USE_REPLY_NOTFMT, n, ptr, ap);

	    if (p)
		ptr = p + 1;	/* set to the next line... (\0 is handled in the while) */
	    else
		break;		/* oh, we're done; drop out of the loop */
	}

	if (autospout_free) {	/* free autospout if necessary */
	    (void) free(autospout);
	    autospout_free = 0;
	}
	autospout = 0;		/* clear the autospout */
    }

    VA_START(fmt);

    /* send the reply */
    vreply(0L, n, fmt, ap);

    VA_END;
}

void lreply(int n, char *fmt,...)
{
    VA_LOCAL_DECL

    if (!dolreplies)	/* prohibited from doing long replies? */
	return;

    VA_START(fmt);

    /* send the reply */
    vreply(USE_REPLY_LONG, n, fmt, ap);

    VA_END;
}

void ack(char *s)
{
    reply(250, "%s command successful.", s);
}

void nack(char *s)
{
    reply(502, "%s command not implemented.", s);
}

void yyerror(char *s)
{
    char *cp;
    if (s == NULL || yyerrorcalled != 0)
	return;
    if ((cp = strchr(cbuf, '\n')) != NULL)
	*cp = '\0';
    reply(500, "'%s': command not understood.", cbuf);
    yyerrorcalled = 1;
    return;
}

void delete(char *name)
{
    struct stat st;
    char realname[MAXPATHLEN];

    /*
     * delete permission?
     */

    wu_realpath(name, realname, chroot_path);

    if ((del_check(name)) == 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to delete %s",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to delete %s",
		       pw->pw_name, remoteident, realname);
	return;
    }

    if (lstat(name, &st) < 0) {
	perror_reply(550, name);
	return;
    }
    if ((st.st_mode & S_IFMT) == S_IFDIR) {
	uid_t uid;
	gid_t gid;
	int d_mode;
	int valid;

	/*
	 * check the directory, can we rmdir here?
	 */
	if ((dir_check(name, &uid, &gid, &d_mode, &valid)) <= 0) {
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to delete directory %s",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to delete directory %s",
			   pw->pw_name, remoteident, realname);
	    return;
	}

	if (rmdir(name) < 0) {
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to delete directory %s (permissions)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to delete directory %s (permissions)",
			   pw->pw_name, remoteident, realname);
	    perror_reply(550, name);
	    return;
	}
	goto done;
    }
    if (unlink(name) < 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to delete %s (permissions)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to delete %s (permissions)",
		       pw->pw_name, remoteident, realname);
	perror_reply(550, name);
	return;
    }
  done:
    {
	char path[MAXPATHLEN];

	wu_realpath(name, path, chroot_path);

	if (log_security)
	    if ((st.st_mode & S_IFMT) == S_IFDIR)
		if (anonymous) {
		    syslog(LOG_NOTICE, "%s of %s deleted directory %s", guestpw, remoteident, path);
		}
		else {
		    syslog(LOG_NOTICE, "%s of %s deleted directory %s", pw->pw_name,
			   remoteident, path);
		}
	    else if (anonymous) {
		syslog(LOG_NOTICE, "%s of %s deleted %s", guestpw,
		       remoteident, path);
	    }
	    else {
		syslog(LOG_NOTICE, "%s of %s deleted %s", pw->pw_name,
		       remoteident, path);
	    }
    }

    ack("DELE");
}

void cwd(char *path)
{
    struct aclmember *entry = NULL;
    char cdpath[MAXPATHLEN];

    if (chdir(path) < 0) {
	/* alias checking */
	while (getaclentry("alias", &entry) && ARG0 && ARG1 != NULL) {
	    if (!strcasecmp(ARG0, path)) {
		if (chdir(ARG1) < 0)
		    perror_reply(550, path);
		else {
		    show_message(250, C_WD);
		    show_readme(250, C_WD);
		    ack("CWD");
		}
		return;
	    }
	}
	/* check for "cdpath" directories. */
	entry = (struct aclmember *) NULL;
	while (getaclentry("cdpath", &entry) && ARG0 != NULL) {
	    snprintf(cdpath, sizeof cdpath, "%s/%s", ARG0, path);
	    if (chdir(cdpath) >= 0) {
		show_message(250, C_WD);
		show_readme(250, C_WD);
		ack("CWD");
		return;
	    }
	}
	perror_reply(550, path);
    }
    else {
	show_message(250, C_WD);
	show_readme(250, C_WD);
	ack("CWD");
    }
}

void makedir(char *name)
{
    uid_t uid;
    gid_t gid;
    int d_mode;
    mode_t oldumask;
    int valid;
    int ret, serrno;
    uid_t oldid;
    char path[MAXPATHLEN + 1];	/* for realpath() later  - cky */
    char realname[MAXPATHLEN];

    wu_realpath(name, realname, chroot_path);
    /*
     * check the directory, can we mkdir here?
     */
    if ((dir_check(name, &uid, &gid, &d_mode, &valid)) <= 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to create directory %s",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to create directory %s",
		       pw->pw_name, remoteident, realname);
	return;
    }

    /*
     * check the filename, is it legal?
     */
    if ((fn_check(name)) <= 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to create directory %s (path-filter)",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to create directory %s (path-filter)",
		       pw->pw_name, remoteident, realname);
	return;
    }

    oldumask = umask(0000);
    if (valid <= 0) {
	d_mode = 0777;
	umask(oldumask);
    }

    if (mkdir(name, d_mode) < 0) {
	if (errno == EEXIST) {
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to create directory %s (exists)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to create directory %s (exists)",
			   pw->pw_name, remoteident, realname);
	    fb_realpath(name, path);
	    reply(521, "\"%s\" directory exists", path);
	}
	else {
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to create directory %s (permissions)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to create directory %s (permissions)",
			   pw->pw_name, remoteident, realname);
	    perror_reply(550, name);
	}
	umask(oldumask);
	return;
    }
    umask(oldumask);
    if (valid > 0) {
	oldid = geteuid();
	if (uid != 0)
	    (void) seteuid((uid_t) uid);
	if ((uid == 0) || ((chown(name, uid, gid)) < 0)) {
	    chown_priv_on(0);
	    ret = chown(name, uid, gid);
	    serrno = errno;
	    chown_priv_off(oldid);
	    if (ret < 0) {
		errno = serrno;
		perror_reply(550, "chown");
		return;
	    }
	}
	else
	    (void) seteuid(oldid);
    }
    wu_realpath(name, path, chroot_path);
    if (log_security)
	if (anonymous) {
	    syslog(LOG_NOTICE, "%s of %s created directory %s", guestpw, remoteident, path);
	}
	else {
	    syslog(LOG_NOTICE, "%s of %s created directory %s", pw->pw_name,
		   remoteident, path);
	}
    fb_realpath(name, path);
    /* According to RFC 959:
     *   The 257 reply to the MKD command must always contain the
     *   absolute pathname of the created directory.
     * This is implemented here using similar code to the PWD command.
     * XXX - still need to do `quote-doubling'.
     */
    reply(257, "\"%s\" new directory created.", path);
}

void removedir(char *name)
{
    uid_t uid;
    gid_t gid;
    int d_mode;
    int valid;
    char realname[MAXPATHLEN];

    wu_realpath(name, realname, chroot_path);

    /*
     * delete permission?
     */

    if ((del_check(name)) == 0)
	return;
    /*
     * check the directory, can we rmdir here?
     */
    if ((dir_check(name, &uid, &gid, &d_mode, &valid)) <= 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to remove directory %s",
		       guestpw, remoteident, realname);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to remove directory %s",
		       pw->pw_name, remoteident, realname);
	return;
    }

    if (rmdir(name) < 0) {
	if (errno == EBUSY)
	    perror_reply(450, name);
	else {
	    if (log_security)
		if (anonymous)
		    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to remove directory %s (permissions)",
			   guestpw, remoteident, realname);
		else
		    syslog(LOG_NOTICE, "%s of %s tried to remove directory %s (permissions)",
			   pw->pw_name, remoteident, realname);
	    perror_reply(550, name);
	}
    }
    else {
	char path[MAXPATHLEN];

	wu_realpath(name, path, chroot_path);

	if (log_security)
	    if (anonymous) {
		syslog(LOG_NOTICE, "%s of %s deleted directory %s", guestpw, remoteident, path);
	    }
	    else {
		syslog(LOG_NOTICE, "%s of %s deleted directory %s", pw->pw_name,
		       remoteident, path);
	    }
	ack("RMD");
    }
}

void pwd(void)
{
    char path[MAXPATHLEN + 1];
    char rhome[MAXPATHLEN + 1];
    char *rpath = path;		/* Path to return to client */
    int pathlen;
#ifndef MAPPING_CHDIR
#ifdef HAVE_GETCWD
    extern char *getcwd();
#else
    extern char *getwd(char *);
#endif
#endif /* MAPPING_CHDIR */

#ifdef HAVE_GETCWD
    if (getcwd(path, MAXPATHLEN) == (char *) NULL)
#else
    if (getwd(path) == (char *) NULL)
#endif
/* Dink!  If you couldn't get the path and the buffer is now likely to
   be undefined, why are you trying to PRINT it?!  _H*
   reply(550, "%s.", path); */
    {
	fb_realpath(".", path);	/* realpath_on_steroids can deal */
    }
    /* relative to home directory if restricted_user */
    if (restricted_user) {
	/*
	 * Re-adjust real path because previous call to getXwd() did
	 * not resolve symlink.
	 */
	fb_realpath(".", path);
	fb_realpath(home, rhome);
	pathlen = strlen(rhome);
	if (pathlen && rhome[pathlen - 1] == '/')
	    pathlen--;
	rpath = rpath + pathlen;
	if (!*rpath)
	    strcpy(rpath, "/");
    }
    reply(257, "\"%s\" is current directory.", rpath);
}

char *renamefrom(char *name)
{
    struct stat st;

    if (lstat(name, &st) < 0) {
	perror_reply(550, name);
	return ((char *) 0);
    }
    reply(350, "File exists, ready for destination name");
    return (name);
}

void renamecmd(char *from, char *to)
{
    int allowed = (anonymous ? 0 : 1);
    char realfrom[MAXPATHLEN];
    char realto[MAXPATHLEN];
    struct aclmember *entry = NULL;
#ifdef PARANOID
    struct stat st;
#endif
    wu_realpath(from, realfrom, chroot_path);
    wu_realpath(to, realto, chroot_path);
    /*
     * check the filename, is it legal?
     */
    if ((fn_check(to)) == 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to rename %s to \"%s\" (path-filter)",
		       guestpw, remoteident, realfrom, realto);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to rename %s to \"%s\" (path-filter)",
		       pw->pw_name, remoteident, realfrom, realto);
	return;
    }

    /* 
     * if rename permission denied and file exists... then deny the user
     * permission to rename the file. 
     */
    while (getaclentry("rename", &entry) && ARG0 && ARG1 != NULL) {
	if (type_match(ARG1))
	    if (anonymous) {
		if (*ARG0 == 'y')
		    allowed = 1;
	    }
	    else if (*ARG0 == 'n')
		allowed = 0;
    }
    if (!allowed) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to rename %s to %s",
		       guestpw, remoteident, realfrom, realto);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to rename %s to %s",
		       pw->pw_name, remoteident, realfrom, realto);
	reply(553, "%s: Permission denied on server. (rename)", from);
	return;
    }


#ifdef PARANOID
/* Almost forgot about this.  Don't allow renaming TO existing files --
   otherwise someone can rename "trivial" to "warez", and "warez" is gone!
   XXX: This part really should do the same "overwrite" check as store(). */
    if (!stat(to, &st)) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to rename %s to %s",
		       guestpw, remoteident, realfrom, realto);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to rename %s to %s",
		       pw->pw_name, remoteident, realfrom, realto);
	reply(550, "%s: Permission denied on server. (rename)", to);
	return;
    }
#endif
    if (rename(from, to) < 0) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to rename %s to %s",
		       guestpw, remoteident, realfrom, realto);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to rename %s to %s",
		       pw->pw_name, remoteident, realfrom, realto);
	perror_reply(550, "rename");
    }
    else {
	char frompath[MAXPATHLEN];
	char topath[MAXPATHLEN];

	wu_realpath(from, frompath, chroot_path);
	wu_realpath(to, topath, chroot_path);

	if (log_security)
	    if (anonymous) {
		syslog(LOG_NOTICE, "%s of %s renamed %s to %s", guestpw, remoteident, frompath, topath);
	    }
	    else {
		syslog(LOG_NOTICE, "%s of %s renamed %s to %s", pw->pw_name,
		       remoteident, frompath, topath);
	    }
	ack("RNTO");
    }
}

void dolog(struct SOCKSTORAGE *sin)
{
    char *blah;
    int rval;

    blah = inet_stop(sin);
    (void) strncpy(remoteaddr, blah, sizeof(remoteaddr));
    nameserved = 0;
    (void) strncpy(remotehost, remoteaddr, sizeof(remotehost));

    rhlookup = rhostlookup(remoteaddr);
    if (rhlookup) {
	if (!strcasecmp(remoteaddr, "0.0.0.0")) {
	    nameserved = 1;
	    strncpy(remotehost, "localhost", sizeof(remotehost));
	}
	else {
#ifdef DNS_TRYAGAIN
	    int num_dns_tries = 0;
	    /*
	     * 27-Apr-93    EHK/BM
	     * far away connections might take some time to get their IP address
	     * resolved. That's why we try again -- maybe our DNS cache has the
	     * PTR-RR now. This code is sloppy. Far better is to check what the
	     * resolver returned so that in case of error, there's no need to
	     * try again.
	     */
  dns_again:
#endif /* DNS_TRYAGAIN */

	    rval = wu_gethostbyaddr(sin, remotehost, sizeof(remotehost));

#ifdef DNS_TRYAGAIN
	    if (!rval && ++num_dns_tries <= 1) {
		sleep(3);
		goto dns_again;		/* try DNS lookup once more     */
	    }
#endif /* DNS_TRYAGAIN */

	    if (rval)
		nameserved = 1;
	}
    }

    remotehost[sizeof(remotehost) - 1] = '\0';
    sprintf(proctitle, "%s: connected", remotehost);
    setproctitle("%s", proctitle);

    wu_authenticate();
/* Create a composite source identification string, to improve the logging
 * when RFC 931 is being used. */
    {
	int n = 20 + strlen(remotehost) + strlen(remoteaddr) +
	(authenticated ? strlen(authuser + 5) : 0);
	if ((remoteident = malloc(n)) == NULL) {
	    syslog(LOG_ERR, "malloc: %m");
#ifndef DEBUG
	    exit(1);
#endif
	}
	else if (authenticated)
	    sprintf(remoteident, "%s @ %s [%s]",
		    authuser, remotehost, remoteaddr);
	else
	    sprintf(remoteident, "%s [%s]", remotehost, remoteaddr);
    }
#ifdef DAEMON
    if (be_daemon && logging)
	syslog(LOG_INFO, "connection from %s", remoteident);
#else
#if 0				/* this is redundant unless the caller doesn't do *anything*, and
				   tcpd will pick it up and deal with it better anyways. _H */
    if (logging)
	syslog(LOG_INFO, "connection from %s", remoteident);
#endif
#endif
}

/* Record logout in wtmp file and exit with supplied status. */

void dologout(int status)
{
    /*
     * Prevent reception of SIGURG from resulting in a resumption
     * back to the main program loop.
     */
    transflag = 0;

    /*
     * Cancel any pending alarm request, reception of SIGALRM would cause
     * dologout() to be called again from the SIGALRM handler toolong().
     */
    (void) alarm(0);

    if (logged_in) {
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
#if defined(SOLARIS_BSM_AUDIT) && !defined(SOLARIS_NO_AUDIT_FTPD_LOGOUT)
	audit_ftpd_logout();
#endif
	(void) seteuid((uid_t) 0);
	if (wtmp_logging)
	    wu_logwtmp(ttyline, pw->pw_name, remotehost, 0);
#ifdef USE_PAM
	if (!anonymous && pamh) {
	    (void) pam_close_session(pamh, 0);
	    (void) pam_end(pamh, PAM_SUCCESS); 
	    pamh = (pam_handle_t *)0;
	}
#endif
    }
    if (logging)
	syslog(LOG_INFO, "FTP session closed");
    if (xferlog)
	close(xferlog);
    acl_remove();
    if (data >= 0)
	close(data);
    if (pdata >= 0)
	close(pdata);
#ifdef AFS_AUTH
    ktc_ForgetAllTokens();
#endif
    /* beware of flushing buffers after a SIGPIPE */
    _exit(status);
}

SIGNAL_TYPE myoob(int sig)
{
    char *cp;
#ifdef SIGPIPE
    void (*pipe_handler)();
#endif

    /* only process if transfer occurring */
    if (!transflag) {
#ifdef SIGURG
	(void) signal(SIGURG, myoob);
#endif
	return;
    }
#ifdef SIGPIPE
    pipe_handler = signal(SIGPIPE, lostconn);
#endif
    cp = tmpline;
    if (wu_getline(cp, sizeof(tmpline) - 1, stdin) == NULL) {
	reply(221, "You could at least say goodbye.");
	dologout(0);
    }
    upper(cp);
    if (strcasecmp(cp, "ABOR\r\n") == 0) {
	tmpline[0] = '\0';
	reply(426, "Transfer aborted. Data connection closed.");
	reply(226, "Abort successful");
#ifdef SIGPIPE
	(void) signal(SIGPIPE, pipe_handler);
#endif
#ifdef SIGURG
	(void) signal(SIGURG, myoob);
#endif
	if (ftwflag > 0) {
	    ftwflag++;
	    return;
	}
	wu_longjmp(urgcatch, 1);
    }
    if (strcasecmp(cp, "STAT\r\n") == 0) {
	tmpline[0] = '\0';
	if (file_size != (off_t) - 1)
	    reply(213, "Status: %" L_FORMAT " of %" L_FORMAT " bytes transferred",
		  byte_count, file_size);
	else
	    reply(213, "Status: %" L_FORMAT " bytes transferred", byte_count);
    }
#ifdef SIGPIPE
    (void) signal(SIGPIPE, pipe_handler);
#endif
#ifdef SIGURG
    (void) signal(SIGURG, myoob);
#endif
}

/* Note: a response of 425 is not mentioned as a possible response to the
 * PASV command in RFC959. However, it has been blessed as a legitimate
 * response by Jon Postel in a telephone conversation with Rick Adams on 25
 * Jan 89. */

void passive(int passive_mode, int proto)
{
    /* First prime number after 2^n where 4 <= n <= 16 */
    static int primes[] = {17,37,67,131,257,521,1031,2053,4099,8209,16411,32771,65537,0};
    static int prime = 0;
    static int range;
#if defined(UNIXWARE) || defined(AIX)
    size_t len;
#else
    int len;
#endif
    int bind_error, serrno;
    int on = 1;
    int i, j, inc, val;
    unsigned short port;
    register char *p, *a;
    struct SOCKSTORAGE *reply_addr;
    struct timeval tv;
#ifdef INET6
    int isv4 = 0;
#endif

/* H* fix: if we already *have* a passive socket, close it first.  Prevents
   a whole variety of entertaining clogging attacks. */
    if (pdata >= 0) {
	close(pdata);
	pdata = -1;
    }
    if (!logged_in) {
	reply(530, "Login with USER first.");
	return;
    }
#ifdef INET6
    switch (proto) {
    case 0:
	if ((passive_mode == TYPE_PASV) && (SOCK_FAMILY(ctrl_addr) == AF_INET6)
	    && !ctrl_v4mapped) {
	    reply(501, "Network protocol mismatch");
	    return;
	}
	else
	    pasv_addr = ctrl_addr;
	break;
    case 1:
	if (SOCK_FAMILY(ctrl_addr) == AF_INET)
	    pasv_addr = ctrl_addr;
	else if (ctrl_v4mapped) {
	    struct sockaddr_in6 *ctrl_sin6 = (struct sockaddr_in6 *)&ctrl_addr;
	    struct sockaddr_in *pasv_sin = (struct sockaddr_in *)&pasv_addr;

	    SET_SOCK_FAMILY(pasv_addr, AF_INET);
	    memcpy(&pasv_sin->sin_addr, &ctrl_sin6->sin6_addr.s6_addr[12],
		   sizeof(struct in_addr));
	}
	else {
	    reply(522, "Network protocol mismatch, use (2)");
	    return;
	}
	break;
    case 2:
	if ((SOCK_FAMILY(ctrl_addr) == AF_INET6) && !ctrl_v4mapped)
	    pasv_addr = ctrl_addr;
	else {
	    reply(522, "Network protocol mismatch, use (1)");
	    return;
	}
	break;
    default:
	reply(522, "Network protocol not supported, use (1,2)");
	return;
    }
#else
    pasv_addr = ctrl_addr;
#endif

    if (passive_port_min == 0 && passive_port_max == 0) {
	/* let the kernel allocate the port */
	SET_SOCK_PORT(pasv_addr, 0);
    }
    else if (prime == 0) {
	range = passive_port_max - passive_port_min + 1;

	/* find the first prime greater than the range in the primes list */
	for (i = 0; primes[i] != 0 && range >= primes[i]; i++)
	    ;
	/* shouldn't happen, but check just in case */
	if (primes[i] == 0) {
	    syslog(LOG_ERR, "passive ports range too large %d-%d", passive_port_min, passive_port_max);
	    /* let the kernel allocate the port */
	    SET_SOCK_PORT(pasv_addr, 0);
	}
	else
	    prime = primes[i];
    }
    len = SOCK_LEN(pasv_addr);

    port_priv_on(0);	/* necessary as port can be < 1024 */
    pdata = socket(SOCK_FAMILY(pasv_addr), SOCK_STREAM, 0);
    if (pdata < 0) {
	serrno = errno;
	port_priv_off((uid_t) pw->pw_uid);
	errno = serrno;
	perror_reply(425, "Can't open passive connection");
	return;
    }
    if (keepalive)
	(void) setsockopt(pdata, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on));
    if (TCPwindowsize) {
	(void) setsockopt(pdata, SOL_SOCKET, SO_SNDBUF, (char *) &TCPwindowsize, sizeof(TCPwindowsize));
	(void) setsockopt(pdata, SOL_SOCKET, SO_RCVBUF, (char *) &TCPwindowsize, sizeof(TCPwindowsize));
    }

    bind_error = -1;
    errno = EADDRINUSE;

    /* try each port in the specified range a maximum of 3 times */
    for (i = 0; i < 3 && bind_error != 0 && \
	((errno == EADDRINUSE) || (errno == EACCES)); i++) {
	if (i > 0)
	    sleep(i);
	if (SOCK_PORT(pasv_addr) == 0)
	    bind_error = bind(pdata, (struct sockaddr *) &pasv_addr, len);
	else {
	    gettimeofday(&tv, NULL);
	    srand(tv.tv_usec + tv.tv_sec);
	    inc = 1 + (int) ((1.0 * (prime - 1) * rand()) / (RAND_MAX + 1.0));
	    val = (int) ((1.0 * range * rand()) / (RAND_MAX + 1.0));
	    /*
	     * Using the modulus operator with a prime number allows us to
	     * try each port in the range once.
	     */
	    for (j = 0; j < range && bind_error != 0 && \
		((errno == EADDRINUSE) || (errno == EACCES)); j++) {
		while ((val = ((val + inc) % prime)) >= range)
		    ;
		SET_SOCK_PORT(pasv_addr, htons(val + passive_port_min));
		bind_error = bind(pdata, (struct sockaddr *) &pasv_addr, len);
	    }
	}
    }
    serrno = errno;
    port_priv_off((uid_t) pw->pw_uid);
    if (bind_error != 0) {
	errno = serrno;
	goto pasv_error;
    }

    /* if the kernel allocated the port, find out which one */
    if ((SOCK_PORT(pasv_addr) == 0) &&
	(getsockname(pdata, (struct sockaddr *) &pasv_addr, &len) < 0))
	goto pasv_error;

    if (listen(pdata, 1) < 0)
	goto pasv_error;
    usedefault = 1;
    if (route_vectored)
	reply_addr = &vect_addr;
    else
	reply_addr = &pasv_addr;
    a = (char *) SOCK_ADDR(*reply_addr);
    port = SOCK_PORT(pasv_addr);
    p = (char *) &port;

#define UC(b) (((int) b) & 0xff)

    if (debug) {
	char *s = calloc(128 + strlen(remoteident), sizeof(char));
	if (s) {
	    int i = ntohs(port);
	    sprintf(s, "PASV port %i assigned to %s", i, remoteident);
	    syslog(LOG_DEBUG, "%s", s);
	    free(s);
	}
    }
#ifdef INET6
    if (SOCK_FAMILY(*reply_addr) == AF_INET)
	isv4 = 1;
    else if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)reply_addr)->sin6_addr)) {
	    isv4 = 1;
	    a += 12; /* move to the IPv4 part of an IPv4-mapped IPv6 address */
    }
    switch (passive_mode) {
    case TYPE_PASV:
	reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
	      UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
	return;
    case TYPE_EPSV:
	reply(229, "Entering Extended Passive Mode (|||%d|)", ntohs(port));
	return;
    case TYPE_LPSV:
	if (isv4) {
	    reply(228, "Entering Long Passive Mode "
		  "(%d,%d,%d,%d,%d,%d,%d,%d,%d)",
		  4, 4, UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]),
		  2, UC(p[0]), UC(p[1]));
	}
	else {
	    reply(228, "Entering Long Passive Mode "
		  "(%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,"
		  "%d,%d,%d,%d,%d)", 6, 16,
		  UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]),
		  UC(a[4]), UC(a[5]), UC(a[6]), UC(a[7]),
		  UC(a[8]), UC(a[9]), UC(a[10]), UC(a[11]),
		  UC(a[12]), UC(a[13]), UC(a[14]), UC(a[15]),
		  2, UC(p[0]), UC(p[1]));
	}
	return;
     }
#else
    reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", UC(a[0]),
	  UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
    return;
#endif /* INET6 */

  pasv_error:
    perror_reply(425, "Can't open passive connection");
    (void) close(pdata);
    pdata = -1;
    if (debug) {
	char *s = calloc(128 + strlen(remoteident), sizeof(char));
	if (s) {
	    sprintf(s, "PASV port assignment assigned for %s", remoteident);
	    syslog(LOG_DEBUG, "%s", s);
	    free(s);
	}
    }
    return;
}

/*
 * Generate unique name for file with basename "local". The file named
 * "local" is already known to exist. Generates failure reply on error. 
 */
char *gunique(char *local)
{
    static char new[MAXPATHLEN];
    struct stat st;
    char *cp = strrchr(local, '/');
    int count = 0;

    if (cp)
	*cp = '\0';
    if (stat(cp ? local : ".", &st) < 0) {
	perror_reply(553, cp ? local : ".");
	return ((char *) 0);
    }
    if (cp)
	*cp = '/';
    (void) strncpy(new, local, (sizeof new) - 3);
    new[sizeof(new) - 3] = '\0';
    cp = new + strlen(new);
    *cp++ = '.';
    for (count = 1; count < 100; count++) {
	if (count == 10) {
	    cp -= 2;
	    *cp++ = '.';
	}
	(void) sprintf(cp, "%d", count);
	if (stat(new, &st) < 0)
	    return (new);
    }
    reply(452, "Unique file name cannot be created.");
    return ((char *) 0);
}

/* Format and send reply containing system error number. */

void perror_reply(int code, char *string)
{
    /*
     * If restricted user and string starts with home dir path, strip it off
     * and return only the relative path.
     */
    if (restricted_user && (home != NULL) && (home[0] != '\0')) {
	size_t len = strlen (home);
	if (strncmp (home, string, len) == 0) {
	    if (string[len - 1] == '/')
		string += len - 1;
	    else if (string[len] == '/')
		string += len;
	    else if (string[len] == '\0')
		string = "/";
	}
    }
    reply(code, "%s: %s.", string, strerror(errno));
}

static char *onefile[] =
{"", 0};

extern char **ftpglob(register char *v, boolean_t check_ncargs);
extern char *globerr;

void send_file_list(char *whichfiles)
{
    /* static so not clobbered by longjmp(), volatile would also work */
    static FILE *dout;
    static DIR *dirp;
    static char **sdirlist;
    static char *wildcard = NULL;

    struct stat st;

    register char **dirlist, *dirname;
    int simple = 0;
    int statret;
    /* This is ANSI/ISO C .. strpbrk should be in <string.h> which we've 
       ** already included so we don't need the following line.  'sides, it 
       ** breaks the GNU EGCS C compiler
       ** extern char *strpbrk(const char *, const char *);
     */

#ifdef TRANSFER_COUNT
#ifdef TRANSFER_LIMIT
    if (((file_limit_raw_out > 0) && (xfer_count_out >= file_limit_raw_out))
	|| ((file_limit_raw_total > 0) && (xfer_count_total >= file_limit_raw_total))
     || ((data_limit_raw_out > 0) && (byte_count_out >= data_limit_raw_out))
	|| ((data_limit_raw_total > 0) && (byte_count_total >= data_limit_raw_total))) {
	if (log_security)
	    if (anonymous)
		syslog(LOG_NOTICE, "anonymous(%s) of %s tried to list files (Transfer limits exceeded)",
		       guestpw, remoteident);
	    else
		syslog(LOG_NOTICE, "%s of %s tried to list files (Transfer limits exceeded)",
		       pw->pw_name, remoteident);
	reply(553, "Permission denied on server. (Transfer limits exceeded)");
	return;
    }
#endif
#endif

    draconian_FILE = NULL;
    dout = NULL;
    dirp = NULL;
    sdirlist = NULL;
    wildcard = NULL;
    if (strpbrk(whichfiles, "~{[*?") == NULL) {
	if (whichfiles[0] == '\0') {
	    wildcard = strdup("*");
	    if (wildcard == NULL) {
		reply(550, "Memory allocation error");
		goto globfree;
	    }
	    whichfiles = wildcard;
	}
	else {
	    if (statret=stat(whichfiles, &st) < 0)
	       statret=lstat(whichfiles, &st); /* Check if it's a dangling symlink */
	    if (statret >= 0) {
	       if ((st.st_mode & S_IFMT) == S_IFDIR) {
		   wildcard = malloc(strlen(whichfiles) + 3);
		   if (wildcard == NULL) {
		       reply(550, "Memory allocation error");
		       goto globfree;
		   }
		   strcpy(wildcard, whichfiles);
		   strcat(wildcard, "/*");
		   whichfiles = wildcard;
	       }
	    }
	}
    }
    if (strpbrk(whichfiles, "~{[*?") != NULL) {
	globerr = NULL;
	dirlist = ftpglob(whichfiles, B_FALSE);
	sdirlist = dirlist;	/* save to free later */
	if (globerr != NULL) {
	    reply(550, "%s", globerr);
	    goto globfree;
	}
	else if (dirlist == NULL) {
	    errno = ENOENT;
	    perror_reply(550, whichfiles);
	    goto globfree;
	}
    }
    else {
	onefile[0] = whichfiles;
	dirlist = onefile;
	simple = 1;
    }

    if (wu_setjmp(urgcatch)) {
	transflag = 0;
	if (dout != NULL)
	    (void) fclose(dout);
	if (dirp != NULL)
	    (void) closedir(dirp);
	data = -1;
	pdata = -1;
	goto globfree;
    }
    while ((dirname = *dirlist++) != NULL) {
	statret=stat(dirname, &st);
	if (statret < 0)
	   statret=lstat(dirname, &st); /* Could be a dangling symlink */
	if (statret < 0) {
	    /* If user typed "ls -l", etc, and the client used NLST, do what
	     * the user meant. */
	    if (dirname[0] == '-' && *dirlist == NULL && transflag == 0) {
		retrieve_is_data = 0;
#ifndef INTERNAL_LS
		retrieve(ls_plain, dirname);
#else
		ls(dirname, 1);
#endif
		retrieve_is_data = 1;
		goto globfree;
	    }
	    perror_reply(550, dirname);
	    if (dout != NULL) {
		(void) fclose(dout);
		transflag = 0;
		data = -1;
		pdata = -1;
	    }
	    goto globfree;
	}
#ifndef NLST_SHOWS_DIRS
	if ((st.st_mode & S_IFMT) != S_IFDIR)
#endif
	{
	    if (dout == NULL) {
		dout = dataconn("file list", (off_t) - 1, "w");
		if (dout == NULL)
		    goto globfree;
		transflag++;
		draconian_FILE = dout;
	    }
	    if (draconian_FILE != NULL) {
		(void) signal(SIGALRM, draconian_alarm_signal);
		alarm(timeout_data);
#if defined(USE_GSS)
		(void) sec_fprintf(dout, "%s%s\n", dirname,
				type == TYPE_A ? "\r" : "");
#else
		fprintf(dout, "%s%s\n", dirname,
			type == TYPE_A ? "\r" : "");
#endif /* USE_GSS */
	    }
	    byte_count += strlen(dirname) + 1;
#ifdef TRANSFER_COUNT
	    byte_count_total += strlen(dirname) + 1;
	    byte_count_out += strlen(dirname) + 1;
	    if (type == TYPE_A) {
		byte_count_total++;
		byte_count_out++;
	    }
#endif
	}
    }

    if (dout != NULL) {
	if (draconian_FILE != NULL) {
	    (void) signal(SIGALRM, draconian_alarm_signal);
	    alarm(timeout_data);
#if defined(USE_GSS)
	    if (sec_fflush(dout) < 0) {
		alarm(0);
		perror_reply(550, "Data connection");
		goto sfl_cleanup; /* send file list cleanup */
	    }
#else
	    fflush(dout);
#endif /* USE_GSS */
	}
	if (draconian_FILE != NULL) {
	    (void) signal(SIGALRM, draconian_alarm_signal);
	    alarm(timeout_data);
	    socket_flush_wait(dout);
	}
    }
    if (dout == NULL)
	reply(550, "No files found.");
    else if ((draconian_FILE == NULL) || ferror(dout) != 0) {
	alarm(0);
	perror_reply(550, "Data connection");
    }
    else {
#ifdef TRANSFER_COUNT
	xfer_count_total++;
	xfer_count_out++;
#endif
	alarm(0);
	reply(226, "Transfer complete.");
    }
  sfl_cleanup:
    transflag = 0;
    if ((dout != NULL) && (draconian_FILE != NULL))
	(void) fclose(dout);
    data = -1;
    pdata = -1;
  globfree:
    if (wildcard != NULL) {
	free(wildcard);
	wildcard = NULL;
    }
    if (sdirlist) {
	blkfree(sdirlist);
	free((char *) sdirlist);
    }
}

/*
   **  SETPROCTITLE -- set process title for ps
   **
   **   Parameters:
   **           fmt -- a printf style format string.
   **           a, b, c -- possible parameters to fmt.
   **
   **   Returns:
   **           none.
   **
   **   Side Effects:
   **           Clobbers argv of our main procedure so ps(1) will
   **           display the title.
 */

#define SPT_NONE	0	/* don't use it at all */
#define SPT_REUSEARGV	1	/* cover argv with title information */
#define SPT_BUILTIN	2	/* use libc builtin */
#define SPT_PSTAT	3	/* use pstat(PSTAT_SETCMD, ...) */
#define SPT_PSSTRINGS	4	/* use PS_STRINGS->... */
#define SPT_SYSMIPS	5	/* use sysmips() supported by NEWS-OS 6 */
#define SPT_SCO		6	/* write kernel u. area */
#define SPT_CHANGEARGV	7	/* write our own strings into argv[] */
#define MAXLINE      2048	/* max line length for setproctitle */
#define SPACELEFT(buf, ptr)  (sizeof buf - ((ptr) - buf))

#ifndef SPT_TYPE
#define SPT_TYPE	SPT_REUSEARGV
#endif

#if SPT_TYPE != SPT_NONE && SPT_TYPE != SPT_BUILTIN

#if SPT_TYPE == SPT_PSTAT
#include <sys/pstat.h>
#endif
#if SPT_TYPE == SPT_PSSTRINGS
#include <machine/vmparam.h>
#include <sys/exec.h>
#ifndef PS_STRINGS		/* hmmmm....  apparently not available after all */
#undef SPT_TYPE
#define SPT_TYPE	SPT_REUSEARGV
#else
#ifndef NKPDE			/* FreeBSD 2.0 */
#define NKPDE 63
typedef unsigned int *pt_entry_t;
#endif
#endif
#endif

#if SPT_TYPE == SPT_PSSTRINGS || SPT_TYPE == SPT_CHANGEARGV
#define SETPROC_STATIC	static
#else
#define SETPROC_STATIC
#endif

#if SPT_TYPE == SPT_SYSMIPS
#include <sys/sysmips.h>
#include <sys/sysnews.h>
#endif

#if SPT_TYPE == SPT_SCO
#ifdef UNIXWARE
#include <sys/exec.h>
#include <sys/ksym.h>
#include <sys/proc.h>
#include <sys/user.h>
#else /* UNIXWARE */
#include <sys/immu.h>
#include <sys/dir.h>
#include <sys/user.h>
#include <sys/fs/s5param.h>
#endif /* UNIXWARE */
#if PSARGSZ > MAXLINE
#define SPT_BUFSIZE	PSARGSZ
#endif
#ifndef _PATH_KMEM
#define _PATH_KMEM	"/dev/kmem"
#endif /* _PATH_KMEM */
#endif /* SPT_SCO */

#ifndef SPT_PADCHAR
#define SPT_PADCHAR	' '
#endif

#ifndef SPT_BUFSIZE
#define SPT_BUFSIZE	MAXLINE
#endif

#endif /* SPT_TYPE != SPT_NONE && SPT_TYPE != SPT_BUILTIN */

#if SPT_TYPE == SPT_REUSEARGV || SPT_TYPE == SPT_CHANGEARGV
char **Argv = NULL;		/* pointer to argument vector */
#endif

#if SPT_TYPE == SPT_REUSEARGV
char *LastArgv = NULL;		/* end of argv */
#endif

/*
   **  Pointers for setproctitle.
   **   This allows "ps" listings to give more useful information.
 */
void initsetproctitle(argc, argv, envp)
     int argc;
     char **argv;
     char **envp;
{
#if SPT_TYPE == SPT_REUSEARGV
    register int i, envpsize = 0;
    char **newenviron;
    extern char **environ;

    /*
       **  Save start and extent of argv for setproctitle.
     */

    LastArgv = argv[argc - 1] + strlen(argv[argc - 1]);
    if (envp != NULL) {
	/*
	   **  Move the environment so setproctitle can use the space at
	   **  the top of memory.
	 */
	for (i = 0; envp[i] != NULL; i++)
	    envpsize += strlen(envp[i]) + 1;
	newenviron = (char **) malloc(sizeof(char *) * (i + 1));
	if (newenviron) {
	    int err = 0;
	    for (i = 0; envp[i] != NULL; i++) {
		if ((newenviron[i] = strdup(envp[i])) == NULL) {
		    err = 1;
		    break;
		}
	    }
	    if (err) {
		for (i = 0; newenviron[i] != NULL; i++)
		    free(newenviron[i]);
		free(newenviron);
		i = 0;
	    }
	    else {
		newenviron[i] = NULL;
		environ = newenviron;
	    }
	}
	else {
	    i = 0;
	}

	/*
	   **  Find the last environment variable within wu-ftpd's
	   **  process memory area.
	 */
	while (i > 0 && (envp[i - 1] < argv[0] ||
		    envp[i - 1] > (argv[argc - 1] + strlen(argv[argc - 1]) +
				   1 + envpsize)))
	    i--;

	if (i > 0)
	    LastArgv = envp[i - 1] + strlen(envp[i - 1]);
    }
#endif /* SPT_TYPE == SPT_REUSEARGV */

#if SPT_TYPE == SPT_REUSEARGV || SPT_TYPE == SPT_CHANGEARGV
    Argv = argv;
#endif
}


#if SPT_TYPE != SPT_BUILTIN

/*VARARGS1 */
void setproctitle(const char *fmt,...)
{
#if SPT_TYPE != SPT_NONE
    register char *p;
    register int i;
    SETPROC_STATIC char buf[SPT_BUFSIZE];
    VA_LOCAL_DECL
#if SPT_TYPE == SPT_PSTAT
	union pstun pst;
#endif
#if SPT_TYPE == SPT_SCO
    static off_t seek_off;
    static int kmemfd = -1;
    static int kmempid = -1;
#ifdef UNIXWARE
    off_t offset;
    void *ptr;
    struct mioc_rksym rks;
#endif /* UNIXWARE */
#endif /* SPT_SCO */

    p = buf;

    /* print ftpd: heading for grep */
    (void) strcpy(p, "ftpd: ");
    p += strlen(p);

    /* print the argument string */
    VA_START(fmt);
    (void) vsnprintf(p, SPACELEFT(buf, p), fmt, ap);
    VA_END;

    i = strlen(buf);

#if SPT_TYPE == SPT_PSTAT
    pst.pst_command = buf;
    pstat(PSTAT_SETCMD, pst, i, 0, 0);
#endif
#if SPT_TYPE == SPT_PSSTRINGS
    PS_STRINGS->ps_nargvstr = 1;
    PS_STRINGS->ps_argvstr = buf;
#endif
#if SPT_TYPE == SPT_SYSMIPS
    sysmips(SONY_SYSNEWS, NEWS_SETPSARGS, buf);
#endif
#if SPT_TYPE == SPT_SCO
    if (kmemfd < 0 || kmempid != getpid()) {
	if (kmemfd >= 0)
	    close(kmemfd);
	if ((kmemfd = open(_PATH_KMEM, O_RDWR, 0)) < 0)
	    return;
	(void) fcntl(kmemfd, F_SETFD, 1);
	kmempid = getpid();
#ifdef UNIXWARE
	seek_off = 0;
	rks.mirk_symname = "upointer";
	rks.mirk_buf = &ptr;
	rks.mirk_buflen = sizeof(ptr);
	if (ioctl(kmemfd, MIOC_READKSYM, &rks) < 0)
	    return;
	offset = (off_t) ptr + (off_t) & ((struct user *) 0)->u_procp;
	if (lseek(kmemfd, offset, SEEK_SET) != offset)
	    return;
	if (read(kmemfd, &ptr, sizeof(ptr)) != sizeof(ptr))
	    return;
	offset = (off_t) ptr + (off_t) & ((struct proc *) 0)->p_execinfo;
	if (lseek(kmemfd, offset, SEEK_SET) != offset)
	    return;
	if (read(kmemfd, &ptr, sizeof(ptr)) != sizeof(ptr))
	    return;
	seek_off = (off_t) ptr + (off_t) ((struct execinfo *) 0)->ei_psargs;
#else /* UNIXWARE */
	seek_off = UVUBLK + (off_t) & ((struct user *) 0)->u_psargs;
#endif /* UNIXWARE */
    }
#ifdef UNIXWARE
    if (seek_off == 0)
	return;
#endif /* UNIXWARE */
    buf[PSARGSZ - 1] = '\0';
    if (lseek(kmemfd, (off_t) seek_off, SEEK_SET) == seek_off)
	(void) write(kmemfd, buf, PSARGSZ);
#endif /* SPT_SCO */
#if SPT_TYPE == SPT_REUSEARGV
    if (i > LastArgv - Argv[0] - 2) {
	i = LastArgv - Argv[0] - 2;
	buf[i] = '\0';
    }
    (void) strcpy(Argv[0], buf);
    p = &Argv[0][i];
    while (p < LastArgv)
	*p++ = SPT_PADCHAR;
    Argv[1] = NULL;
#endif
#if SPT_TYPE == SPT_CHANGEARGV
    Argv[0] = buf;
    Argv[1] = 0;
#endif
#endif /* SPT_TYPE != SPT_NONE */
}

#endif /* SPT_TYPE != SPT_BUILTIN */

#ifdef KERBEROS
/* thanks to gshapiro@wpi.wpi.edu for the following kerberosities */

void init_krb()
{
    char hostname[100];

#ifdef HAVE_SYSINFO
    if (sysinfo(SI_HOSTNAME, hostname, sizeof(hostname)) < 0) {
	perror("sysinfo");
#else
    if (gethostname(hostname, sizeof(hostname)) < 0) {
	perror("gethostname");
#endif
	exit(1);
    }
    if (strchr(hostname, '.'))
	*(strchr(hostname, '.')) = 0;

    sprintf(krb_ticket_name, "/var/dss/kerberos/tkt/tkt.%d", getpid());
    krb_set_tkt_string(krb_ticket_name);

    config_auth();

    if (krb_svc_init("hesiod", hostname, (char *) NULL, 0, (char *) NULL,
		     (char *) NULL) != KSUCCESS) {
	fprintf(stderr, "Couldn't initialize Kerberos\n");
	exit(1);
    }
}

void end_krb()
{
    unlink(krb_ticket_name);
}

#endif /* KERBEROS */

#ifdef ULTRIX_AUTH
static int ultrix_check_pass(char *passwd, char *xpasswd)
{
    struct svcinfo *svp;
    int auth_status;

    if ((svp = getsvc()) == (struct svcinfo *) NULL) {
	syslog(LOG_WARNING, "getsvc() failed in ultrix_check_pass");
	return -1;
    }
    if (pw == (struct passwd *) NULL) {
	return -1;
    }
    if (((svp->svcauth.seclevel == SEC_UPGRADE) &&
	 (!strcmp(pw->pw_passwd, "*")))
	|| (svp->svcauth.seclevel == SEC_ENHANCED)) {
	if ((auth_status = authenticate_user(pw, passwd, "/dev/ttypXX")) >= 0) {
	    /* Indicate successful validation */
	    return auth_status;
	}
	if (auth_status < 0 && errno == EPERM) {
	    /* Log some information about the failed login attempt. */
	    switch (abs(auth_status)) {
	    case A_EBADPASS:
		break;
	    case A_ESOFTEXP:
		syslog(LOG_NOTICE, "password will expire soon for user %s",
		       pw->pw_name);
		break;
	    case A_EHARDEXP:
		syslog(LOG_NOTICE, "password has expired for user %s",
		       pw->pw_name);
		break;
	    case A_ENOLOGIN:
		syslog(LOG_NOTICE, "user %s attempted login to disabled acct",
		       pw->pw_name);
		break;
	    }
	}
    }
    else {
	if ((*pw->pw_passwd != '\0') && (!strcmp(xpasswd, pw->pw_passwd))) {
	    /* passwd in /etc/passwd isn't empty && encrypted passwd matches */
	    return 0;
	}
    }
    return -1;
}
#endif /* ULTRIX_AUTH */

#ifdef USE_PAM
/* This is rather an abuse of PAM, but the FTP protocol doesn't allow much
 * flexibility here.  :-(
 */

/* Static variables used to communicate between the conversation function
 * and the server_login function
 */
static char *PAM_password;

/* PAM conversation function
 * Here we assume (for now, at least) that echo on means login name, and
 * echo off means password.
 */
#ifdef SOLARIS_2
/* Workaround bug 4430970/4413889 which causes a compiler warning, necessary
 * as usr/src/Makefile.master now includes "-errwarn=%all".
 */
static int PAM_conv(int num_msg, struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
#else
static int PAM_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
#endif
{
    int replies = 0;
    struct pam_response *reply = NULL;

#define COPY_STRING(s) (s) ? strdup(s) : NULL

    reply = malloc(sizeof(struct pam_response) * num_msg);
    if (!reply)
	return PAM_CONV_ERR;

    for (replies = 0; replies < num_msg; replies++) {
	switch (msg[replies]->msg_style) {
	case PAM_PROMPT_ECHO_ON:
	    return PAM_CONV_ERR;
	    break;
	case PAM_PROMPT_ECHO_OFF:
	    reply[replies].resp_retcode = PAM_SUCCESS;
	    reply[replies].resp = COPY_STRING(PAM_password);
	    /* PAM frees resp */
	    break;
	case PAM_TEXT_INFO:
	    /* ignore it... */
	    reply[replies].resp_retcode = PAM_SUCCESS;
	    reply[replies].resp = NULL;
	    break;
	case PAM_ERROR_MSG:
	    /* ignore it... */
	    reply[replies].resp_retcode = PAM_SUCCESS;
	    reply[replies].resp = NULL;
	    break;
	default:
	    /* Must be an error of some sort... */
	    return PAM_CONV_ERR;
	}
    }
    *resp = reply;
    return PAM_SUCCESS;
}
static struct pam_conv PAM_conversation =
{
    &PAM_conv,
    NULL
};

static int pam_check_pass(char *user, char *passwd)
{
    char tty[20];
    int pam_session = 0;

    /* Now use PAM to do authentication and session logging. Bail out if
     * there are any errors. Since this is a limited protocol, and an even
     * more limited function within a server speaking this protocol, we
     * can't be as verbose as would otherwise make sense.
     */
    PAM_password = passwd;
    pamh = (pam_handle_t *)0;
    if (pam_start("ftp", user, &PAM_conversation, &pamh) != PAM_SUCCESS)
	return 0;

#if ((defined(BSD) && (BSD >= 199103)) || defined(sun))
    (void) sprintf(tty, "/dev/ftp%ld", (long) getpid());
#else
    (void) sprintf(tty, "/dev/ftpd%d", getpid());
#endif

    if (pam_set_item(pamh, PAM_TTY, tty) != PAM_SUCCESS)
	goto pam_fail;
    if (pam_set_item(pamh, PAM_RHOST, remotehost) != PAM_SUCCESS)
	goto pam_fail;
    if (pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK) != PAM_SUCCESS) {
#ifdef SOLARIS_BSM_AUDIT
	audit_ftpd_bad_pw(user);
#endif
	goto pam_fail;
    }
    if (pam_acct_mgmt(pamh, 0) != PAM_SUCCESS) {
#ifdef SOLARIS_BSM_AUDIT
	audit_ftpd_bad_pw(user);
#endif
	goto pam_fail;
    }
    if (pam_open_session(pamh, 0) != PAM_SUCCESS)
	goto pam_fail;
    pam_session = 1;
#ifdef PAM_ESTABLISH_CRED
    if (pam_setcred(pamh, PAM_ESTABLISH_CRED) != PAM_SUCCESS)
	goto pam_fail;
#else
    if (pam_setcred(pamh, PAM_CRED_ESTABLISH) != PAM_SUCCESS)
	goto pam_fail;
#endif
    /* If this point is reached, the user has been authenticated. */
    return 1;

pam_fail:
    if (pam_session)
	(void) pam_close_session(pamh, 0);
    (void) pam_end(pamh, 0);
    pamh = (pam_handle_t *)0;
    return 0;
}
#endif

#ifdef DAEMON

#ifdef INET6
static struct in6_addr acl_DaemonAddress6(void)
{
    struct in6_addr rv = in6addr_any;
    struct aclmember *entry = NULL;

    if (getaclentry("daemonaddress", &entry) && ARG0) {
	if (inet_pton6(ARG0, &rv) != 1)
	    rv = in6addr_any;
    }
    return rv;
}
#endif /* INET6 */
static unsigned long int acl_DaemonAddress(void)
{
    unsigned long int rv = INADDR_ANY;
    struct aclmember *entry = NULL;

    if (getaclentry("daemonaddress", &entry) && ARG0) {
	rv = inet_addr(ARG0);
	if (rv == -1)
	    rv = INADDR_ANY;
    }
    return rv;
}

/* I am running as a standalone daemon (not under inetd) */
static void do_daemon(void)
{
    struct SOCKSTORAGE server;
    struct servent *serv;
    int pgrp;
    int lsock;
    int one = 1;
    FILE *pidfile;
    int i;
#if defined(UNIXWARE) || defined(AIX)
    size_t addrlen;
#else
    int addrlen;
#endif

    /* Some of this is "borrowed" from inn - lots of it isn't */

    if (be_daemon == 2) {
	/* Fork - so I'm not the owner of the process group any more */
	i = fork();
	if (i < 0) {
	    syslog(LOG_ERR, "cant fork %m");
	    exit(1);
	}
	/* No need for the parent any more */
	if (i > 0)
	    exit(0);

#ifdef NO_SETSID
	pgrp = setpgrp(0, getpid());
#else
	pgrp = setsid();
#endif
	if (pgrp < 0) {
	    syslog(LOG_ERR, "cannot daemonise: %m");
	    exit(1);
	}
    }

    if (!Bypass_PID_Files)
	if ((pidfile = fopen(_PATH_FTPD_PID, "w"))) {
	    fprintf(pidfile, "%ld\n", (long) getpid());
	    fclose(pidfile);
	}
	else {
	    syslog(LOG_ERR, "Cannot write pidfile: %m");
	}

    /* Close off all file descriptors and reopen syslog */
    if (be_daemon == 2) {
	closelog();
	closefds(0);
	(void) open(_PATH_DEVNULL, O_RDWR);
	(void) dup2(0, 1);
	/* junk stderr */
	(void) freopen(_PATH_DEVNULL, "w", stderr);

#ifdef FACILITY
	openlog("ftpd", LOG_PID | LOG_NDELAY, FACILITY);
#else
	openlog("ftpd", LOG_PID);
#endif
    }

    if (RootDirectory != NULL) {
	if ((chroot(RootDirectory) < 0)
	    || (chdir("/") < 0)) {
	    syslog(LOG_ERR, "Cannot chroot to initial directory, aborting.");
	    exit(1);
	}
	free(RootDirectory);
	RootDirectory = NULL;
    }

    if (!use_accessfile)
	syslog(LOG_WARNING, "FTP server started without ftpaccess file");

    syslog(LOG_INFO, "FTP server (%s) ready.", version);

    /* Create a socket to listen on */
#ifdef INET6
    if (listen_v4 == 0)
	lsock = socket(AF_INET6, SOCK_STREAM, 0);
    else
#endif
    lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (lsock < 0) {
	syslog(LOG_ERR, "Cannot create socket to listen on: %m");
	exit(1);
    }
    if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) < 0) {
	syslog(LOG_ERR, "Cannot set SO_REUSEADDR option: %m");
	exit(1);
    }
    if (keepalive)
	(void) setsockopt(lsock, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, sizeof(one));

#ifdef INET6
    if (listen_v4 == 0) {
	struct sockaddr_in6 *server_sin6 = (struct sockaddr_in6 *)&server;

	memset(&server, 0, sizeof(struct sockaddr_in6));
	server_sin6->sin6_family = AF_INET6;
	server_sin6->sin6_addr = acl_DaemonAddress6();
    }
    else {
	struct sockaddr_in *server_sin = (struct sockaddr_in *)&server;

	server_sin->sin_family = AF_INET;
	server_sin->sin_addr.s_addr = acl_DaemonAddress();
    }
#else
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = acl_DaemonAddress();
#endif
    if (daemon_port == 0) {
	if (!(serv = getservbyname("ftp", "tcp"))) {
	    syslog(LOG_ERR, "Cannot find service ftp: %m");
	    exit(1);
	}
	SET_SOCK_PORT(server, serv->s_port);
	daemon_port = ntohs(serv->s_port);
    }
    else
	SET_SOCK_PORT(server, htons(daemon_port));

    if (bind(lsock, (struct sockaddr *) &server, SOCK_LEN(server)) < 0) {
	syslog(LOG_ERR, "Cannot bind socket: %m");
	exit(1);
    }

    listen(lsock, MAX_BACKLOG);

    sprintf(proctitle, "accepting connections on port %i", daemon_port);
    setproctitle("%s", proctitle);

    while (1) {
	int pid;
	int msgsock;

	addrlen = sizeof(his_addr);
	msgsock = accept(lsock, (struct sockaddr *) &his_addr, &addrlen);
	if (msgsock < 0) {
	    int severity = LOG_ERR;

	    if (errno == EINTR || errno == ECONNABORTED)
		severity = LOG_INFO;
	    syslog(severity, "Accept failed: %m");
	    sleep(1);
	    continue;
	}

	/* Fork off a handler */
	pid = fork();
	if (pid < 0) {
	    syslog(LOG_ERR, "failed to fork: %m");
	    close(msgsock);
	    sleep(1);
	    continue;
	}
	if (pid == 0) {
	    /* I am that forked off child */
	    /* Only parent needs lsock */
	    close(lsock);
	    closelog();
	    /* Make sure that stdin/stdout are the new socket */
	    dup2(msgsock, 0);
	    dup2(msgsock, 1);
	    if (msgsock != 0 && msgsock != 1)
		close(msgsock);
#ifdef FACILITY
	    openlog("ftpd", LOG_PID | LOG_NDELAY, FACILITY);
#else
	    openlog("ftpd", LOG_PID);
#endif
	    setup_paths();
	    access_init();
	    return;
	}

	/* I am the parent */
	close(msgsock);

	/* Quick check to see if any of the forked off children have
	 * terminated. */
	while ((pid = waitpid((pid_t) -1, (int *) 0, WNOHANG)) > 0) {
	    /* A child has finished */
	}

	access_init();
    }
}

#endif /* DAEMON */

#ifdef RATIO
int is_downloadfree(char *fname)
{
    char        rpath[MAXPATHLEN];
    char	class[BUFSIZ];
    char        *cp;
    int		which;
    struct aclmember *entry = NULL;

    if( wu_realpath(fname,rpath,chroot_path) == NULL )
        return 0;

    (void) acl_getclass(class);

    if (debug)
	syslog(LOG_DEBUG, "class: %s, fname: %s, rpath: %s", class, fname, rpath);

    while( getaclentry("dl-free-dir",&entry) ) {
        if( ARG0 == NULL )
            continue;
        if( strncmp(rpath,ARG0,strlen(ARG0)) == 0 ) {
	    if( ARG1 == NULL )
		return 1;
	    else for(which = 1; (which < MAXARGS) && ARG[which]; which++) {
		if( strcmp(class,ARG[which]) == 0 )
		    return 1;
	    }
        }
    }
    while( getaclentry("dl-free",&entry) ) {
        if( ARG0 == NULL )
            continue;
        if( *(ARG0) != '/' ) {  /* compare basename */
            if( (cp = strrchr(rpath,'/')) == NULL ) {
                cp = rpath;
            }
            else {
                ++cp;
            }
            if( strcmp(cp,ARG0) == 0 ) {
		if( ARG1 == NULL )
		    return 1;
		else for(which = 1; (which < MAXARGS) && ARG[which]; which++) {
		    if( strcmp(class,ARG[which]) == 0 )
		    return 1;
		}
            }
        }
        else {  /* compare real path */
            if( strcmp(rpath,ARG0) == 0 ) {
		if( ARG1 == NULL )
		    return 1;
		else for(which = 1; (which < MAXARGS) && ARG[which] ; which++) {
		    if( strcmp(class,ARG[which]) == 0 )
		    return 1;
		}
            }
        }
    }
    return 0;
}
#endif /* RATIO */

int pasv_allowed(char *remoteaddr)
{
    char class[MAXPATHLEN];
    int which;
    struct aclmember *entry = NULL;
    (void) acl_getclass(class);
    while (getaclentry("pasv-allow", &entry)) {
	if ((ARG0 != NULL) && (strcasecmp(class, ARG0) == 0))
	    for (which = 1; (which < MAXARGS) && (ARG[which] != NULL); which++) {
		if (hostmatch(ARG[which], remoteaddr, NULL))
		    return 1;
	    }
    }
    return 0;
}

int port_allowed(char *remoteaddr)
{
    char class[MAXPATHLEN];
    int which;
    struct aclmember *entry = NULL;
    (void) acl_getclass(class);
    while (getaclentry("port-allow", &entry)) {
	if ((ARG0 != NULL) && (strcasecmp(class, ARG0) == 0))
	    for (which = 1; (which < MAXARGS) && (ARG[which] != NULL); which++) {
		if (hostmatch(ARG[which], remoteaddr, NULL))
		    return 1;
	    }
    }
    return 0;
}

#ifdef MAIL_ADMIN
char *email(char *full_address)
{
    /* Get the plain address part from an e-mail address
       (i.e. remove realname) */

    static char *email_buf = NULL;
    char *addr, *ptr;

    if (email_buf != NULL)
	free(email_buf);

    email_buf = (char *) malloc(strlen(full_address) + 1);
    addr = email_buf;
    memset(addr, 0, strlen(full_address) + 1);
    strcpy(addr, full_address);

    /* Realname <user@host> type address */
    if ((ptr = (char *) strchr(addr, '<')) != NULL) {
	addr = ++ptr;
	if ((ptr = (char *) strchr(addr, '>')) != NULL)
	    *ptr = '\0';
    }

    /* user@host (Realname) type address */
    if (((char *) strchr(addr, ' ')) != NULL)
	addr[strchr(addr, ' ') - addr] = '\0';

    return addr;
}

FILE *SockOpen(char *host, int clientPort)
{
    int sock;
    unsigned long inaddr;
    struct sockaddr_in ad;
    FILE *fp;
#ifdef INET6
    struct sockaddr_in6 ad6;
    struct addrinfo hints, *result, *res;
    int af = AF_INET;
#else
    struct hostent *hp;
#endif

    memset(&ad, 0, sizeof(ad));
    ad.sin_family = AF_INET;

#ifdef INET6
    memset(&ad6, 0, sizeof(ad6));
    ad6.sin6_family = AF_INET6;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = PF_UNSPEC;

    if (getaddrinfo(host, NULL, &hints, &result) != 0)
	return (FILE *) NULL;

    for (res = result; res; res = res->ai_next) {
	af = res->ai_family;
	if (af == AF_INET)
	    memcpy(&ad.sin_addr, &((struct sockaddr_in *)res->ai_addr)->sin_addr, sizeof(struct in_addr));
	else if (af == AF_INET6)
	    memcpy(&ad6.sin6_addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, sizeof(struct in6_addr));
	else
	    continue;

	if (af == AF_INET6) {
	    ad6.sin6_port = htons(clientPort);
	    sock = socket(AF_INET6, SOCK_STREAM, 0);
	    if (sock < 0)
		continue;
	    if (connect(sock, (struct sockaddr *) &ad6, sizeof(ad6)) != -1)
		break;
	    close(sock);
	}
	else {
	    ad.sin_port = htons(clientPort);
	    sock = socket(AF_INET, SOCK_STREAM, 0);
	    if (sock < 0)
		continue;
	    if (connect(sock, (struct sockaddr *) &ad, sizeof(ad)) != -1)
		break;
	    close(sock);
	}
    }
    freeaddrinfo(result);
    if (!res)
	return (FILE *) NULL;
#else
    inaddr = inet_addr(host);
    if (inaddr != (unsigned long) -1)
	memcpy(&ad.sin_addr, &inaddr, sizeof(inaddr));
    else {
	hp = gethostbyname(host);
	if (hp == NULL)
	    return (FILE *) NULL;
	memcpy(&ad.sin_addr, hp->h_addr, hp->h_length);
    }
    ad.sin_port = htons(clientPort);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
	return (FILE *) NULL;
    if (connect(sock, (struct sockaddr *) &ad, sizeof(ad)) < 0) {
	close(sock);
	return (FILE *) NULL;
    }
#endif /* INET6 */

    fp = fdopen(sock, "r+");
    setvbuf(fp, NULL, _IOLBF, 2048);
    return (fp);
}

int SockPrintf(FILE *sockfp, char *format,...)
{
    va_list ap;
    char buf[16384];

    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    buf[sizeof(buf) - 1] = '\0';
    va_end(ap);
    return SockWrite(buf, 1, strlen(buf), sockfp);
}

int SockWrite(char *buf, int size, int len, FILE *sockfp)
{
    return (fwrite(buf, size, len, sockfp));
}

char *SockGets(FILE *sockfp, char *buf, int len)
{
    return (fgets(buf, len, sockfp));
}

int SockPuts(FILE *sockfp, char *buf)
{
    int rc;

    if ((rc = SockWrite(buf, 1, strlen(buf), sockfp)))
	return rc;
    return SockWrite("\r\n", 1, 2, sockfp);
}

int Reply(FILE *sockfp)
{
    char *reply, *rec, *separator;
    int ret = 0;

    if ((reply = (char *) malloc(BUFSIZ)) == NULL)
	return ret;
    memset(reply, 0, 1024);
    do {
	rec = SockGets(sockfp, reply, BUFSIZ);
	if (rec != NULL) {
	    ret = strtol(reply, &separator, 10);
	}
	else
	    ret = 250;
    } while ((rec != NULL) && (separator[0] != ' '));
    free(reply);
    fflush(sockfp);	/* Solaris bug: need to clear buf before fwrite() */
    return ret;
}

int Send(FILE *sockfp, char *format,...)
{
    va_list ap;
    char buf[16384];

    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    buf[sizeof(buf) - 1] = '\0';
    va_end(ap);
    SockWrite(buf, 1, strlen(buf), sockfp);
    return Reply(sockfp);
}
#endif /* MAIL_ADMIN */


/*
 * fixpath
 *
 * In principal, this is similar to realpath() or the mapping chdir function.
 * It removes unnecessary path components.  We do this to put a stop to
 * attempts to cause a memory starvation DoS.
 *
 */

void fixpath(char *path)
{
    int abs = 0;
    char *in;
    char *out;

    if (*path == '/') {
	abs = 1;
	path++;
    }
    else if (*path == '~') {
	do
	    path++;
	while ((*path != '\0') && (*path != '/'));
	if (*path == '/')
	    path++;
    }
    in = path;
    out = path;
    while (*in != '\0') {
	if (*in == '/')
	    in++;
	else if ((in[0] == '.') && ((in[1] == '/') || (in[1] == '\0'))) {
	    in++;
	    if (*in == '/')
		in++;
	}
	else if ((in[0] == '.') && (in[1] == '.') && ((in[2] == '/') || (in[2] == '\0'))) {
	    if (out == path) {
		if (abs) {
		    in++;
		    in++;
		    if (*in == '/')
			in++;
		}
		else {
		    *out++ = *in++;
		    *out++ = *in++;
		    if (*in == '/')
			*out++ = *in++;
		    path = out;
		}
	    }
	    else {
		out--;
		while ((out != path) && (*--out != '/'));
		in++;
		in++;
		if (*in == '/')
		    in++;
	    }
	}
	else {
	    do
		*out++ = *in++;
	    while ((*in != '\0') && (*in != '/'));
	    if (*in == '/')
		*out++ = *in++;
	}
    }
    *out = '\0';
}

#if defined(SOLARIS_2)

/* Callback function to cleanup_nscd()'s fdwalk().
 * If "fd" has the same inode, device as nscd door
 * it returns 1 otherwise it returns 0.
 */
int close_nsdoor(void *cb_data, int fd)
{
    struct stat fd_buf;
    struct stat *nsdoor_buf = (struct stat *) cb_data;

    if (fstat(fd, &fd_buf) != 0) {
	return (0);
    }

    if ((nsdoor_buf->st_dev == fd_buf.st_dev) && 
	(nsdoor_buf->st_ino == fd_buf.st_ino)) {
	close(fd);
	return (1);
    }

    return (0);
}

/* Walk through the list of open file descriptors
 * of the ftp dameon and find the nscd door fd and
 * close it.
 */
void cleanup_nscd()
{
    struct stat nsdoor_buf;

    if (stat(NAME_SERVICE_DOOR, &nsdoor_buf) == 0) {
	fdwalk(close_nsdoor, &nsdoor_buf);
    }
}

#endif
