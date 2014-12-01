/*
 * options.c - handles option processing for PPP.
 *
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#define RCSID	"$Id: options.c,v 1.74 2000/04/15 01:27:13 masputra Exp $"

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <netdb.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef PLUGIN
#include <dlfcn.h>
#endif /* PLUGIN */
#ifdef PPP_FILTER
#include <pcap.h>
#include <pcap-int.h>	/* XXX: To get struct pcap */
#endif /* PPP_FILTER */

#include "pppd.h"
#include "pathnames.h"
#include "patchlevel.h"
#include "fsm.h"
#include "lcp.h"
#include "ipcp.h"

#if defined(ultrix) || defined(NeXT)
char *strdup __P((char *));
#endif

#if !defined(lint) && !defined(_lint)
static const char rcsid[] = RCSID;
#endif

/*
 * Option variables and default values.
 */
#ifdef PPP_FILTER
int	dflag = 0;		/* Tell libpcap we want debugging */
#endif /* PPP_FILTER */
int	debug = 0;		/* Debug flag */
int	kdebugflag = 0;		/* Tell kernel to print debug messages */
int	default_device = 1;	/* Using /dev/tty or equivalent */
char	devnam[MAXPATHLEN];	/* Device name */
int	crtscts = 0;		/* Use hardware flow control */
bool	modem = 1;		/* Use modem control lines */
int	inspeed = 0;		/* Input/Output speed requested */
u_int32_t netmask = 0;		/* IP netmask to set on interface */
bool	lockflag = 0;		/* Create lock file to lock the serial dev */
bool	nodetach = 0;		/* Don't detach from controlling tty */
bool	updetach = 0;		/* Detach once link is up */
char	*initializer = NULL;	/* Script to initialize physical link */
char	*connect_script = NULL;	/* Script to establish physical link */
char	*disconnect_script = NULL; /* Script to disestablish physical link */
char	*welcomer = NULL;	/* Script to run after phys link estab. */
char	*ptycommand = NULL;	/* Command to run on other side of pty */
int	maxconnect = 0;		/* Maximum connect time */
char	user[MAXNAMELEN];	/* Username for PAP */
char	passwd[MAXSECRETLEN];	/* Password for PAP */
bool	persist = 0;		/* Reopen link after it goes down */
char	our_name[MAXNAMELEN];	/* Our name for authentication purposes */
bool	demand = 0;		/* do dial-on-demand */
char	*ipparam = NULL;	/* Extra parameter for ip up/down scripts */
int	idle_time_limit = 0;	/* Disconnect if idle for this many seconds */
int	holdoff = 30;		/* # seconds to pause before reconnecting */
bool	holdoff_specified;	/* true if a holdoff value has been given */
bool	notty = 0;		/* Stdin/out is not a tty */
char	*pty_socket = NULL;	/* Socket to connect to pty */
char	*record_file = NULL;	/* File to record chars sent/received */
int	using_pty = 0;
bool	sync_serial = 0;	/* Device is synchronous serial device */
int	log_to_fd = 1;		/* send log messages to this fd too */
int	maxfail = 10;		/* max # of unsuccessful connection attempts */
char	linkname[MAXPATHLEN];	/* logical name for link */
bool	tune_kernel;		/* may alter kernel settings */
int	connect_delay = 1000;	/* wait this many ms after connect script */
int	max_data_rate;		/* max bytes/sec through charshunt */
int	req_unit = -1;		/* requested interface unit */
bool	multilink = 0;		/* Enable multilink operation */
char	*bundle_name = NULL;	/* bundle name for multilink */
bool	direct_tty = 0;		/* use standard input directly; not a tty */

/* Maximum depth of include files; prevents looping. */
#define	MAXFILENESTING	10

struct option_info initializer_info;
struct option_info connect_script_info;
struct option_info disconnect_script_info;
struct option_info welcomer_info;
struct option_info devnam_info;
struct option_info ptycommand_info;
struct option_info ipsrc_info;
struct option_info ipdst_info;
struct option_info speed_info;

#ifdef PPP_FILTER
struct	bpf_program pass_filter;/* Filter program for packets to pass */
struct	bpf_program active_filter; /* Filter program for link-active pkts */
pcap_t  pc;			/* Fake struct pcap so we can compile expr */
#endif /* PPP_FILTER */

char *current_option;		/* the name of the option being parsed */
bool privileged_option;		/* set iff the current option came from root */
char *option_source = NULL;	/* string saying where the option came from */
int option_line = 0;		/* line number in file */
bool log_to_file;		/* log_to_fd is a file opened by us */
bool log_to_specific_fd;	/* log_to_fd was specified by user option */

/*
 * Prototypes.
 */
static int setdevname __P((char *));
static int setipaddr __P((char *));
static int setspeed __P((char *));
static int noopt __P((char **, option_t *));
static int setdomain __P((char **, option_t *));
static int setnetmask __P((char **, option_t *));
static int setxonxoff __P((char **, option_t *));
static int readfile __P((char **, option_t *));
static int callfile __P((char **, option_t *));
static int showversion __P((char **, option_t *));
static int showhelp __P((char **, option_t *));
static int showalloptions __P((char **, option_t *));
static void usage __P((void));
static int setlogfile __P((char **, option_t *));
#ifdef PLUGIN
static int loadplugin __P((char **, option_t *));
#endif
#ifdef PPP_FILTER
static int setpassfilter __P((char **, option_t *));
static int setactivefilter __P((char **, option_t *));
#endif /* PPP_FILTER */
static option_t *find_option __P((char *name));
static int process_option __P((option_t *opt, char **argv, int sline));
static int n_arguments __P((option_t *opt));
static int number_option __P((char *str, u_int32_t *valp, int base));
static u_int32_t opt_hash __P((const void *key));
static int opt_compare __P((const void *p1, const void *p2));

typedef struct _opt_t {
    option_t	*p;
} opt_t;

typedef struct _hashentry_t {
    struct _hashentry_t	*next;
    opt_t		opt;
} hashentry_t;

/*
 * A prime number describing the size of hash table.
 */
#define	OPTHASH_TBLSIZE	101

/*
 * Chained hash table containing pointers to available options.
 */
static hashentry_t *hash_tbl[OPTHASH_TBLSIZE] = { NULL };

/*
 * Total number of entries in the hash table.
 */
int hash_tblcnt = 0;

/*
 * Valid arguments.
 */
option_t general_options[] = {
    { "debug", o_int, &debug,
      "Increase debugging level", OPT_INC|OPT_NOARG|1 },
    { "-d", o_int, &debug,
      "Increase debugging level", OPT_INC|OPT_NOARG|1 },
    { "kdebug", o_int, &kdebugflag,
      "Set kernel driver debug level" },
    { "nodetach", o_bool, &nodetach,
      "Don't detach from controlling tty", 1 },
    { "-detach", o_bool, &nodetach,
      "Don't detach from controlling tty", 1 },
    { "updetach", o_bool, &updetach,
      "Detach from controlling tty once link is up", 1 },
    { "holdoff", o_int, &holdoff,
      "Set time in seconds before retrying connection" },
    { "idle", o_int, &idle_time_limit,
      "Set time in seconds before disconnecting idle link" },
    { "lock", o_bool, &lockflag,
      "Lock serial device with UUCP-style lock file", 1 },
    { "-all", o_special_noarg, (void *)noopt,
      "Don't request/allow any LCP or IPCP options (useless)" },
    { "init", o_string, &initializer,
      "A program to initialize the device",
      OPT_A2INFO | OPT_PRIVFIX, &initializer_info },
    { "connect", o_string, &connect_script,
      "A program to set up a connection",
      OPT_A2INFO | OPT_PRIVFIX, &connect_script_info },
    { "disconnect", o_string, &disconnect_script,
      "Program to disconnect serial device",
      OPT_A2INFO | OPT_PRIVFIX, &disconnect_script_info },
    { "welcome", o_string, &welcomer,
      "Script to welcome client",
      OPT_A2INFO | OPT_PRIVFIX, &welcomer_info },
    { "pty", o_string, &ptycommand,
      "Script to run on pseudo-tty master side",
      OPT_A2INFO | OPT_PRIVFIX | OPT_DEVNAM, &ptycommand_info },
    { "notty", o_bool, &notty,
      "Input/output is not a tty", OPT_DEVNAM | 1 },
    { "directtty", o_bool, &direct_tty,
      "Use standard input as tty without checking", OPT_DEVNAM | 1 },
    { "socket", o_string, &pty_socket,
      "Send and receive over socket, arg is host:port", OPT_DEVNAM },
    { "record", o_string, &record_file,
      "Record characters sent/received to file" },
    { "maxconnect", o_int, &maxconnect,
      "Set connection time limit", OPT_LLIMIT|OPT_NOINCR|OPT_ZEROINF },
    { "crtscts", o_int, &crtscts,
      "Set hardware (RTS/CTS) flow control", OPT_NOARG|OPT_VAL(1) },
    { "nocrtscts", o_int, &crtscts,
      "Disable hardware flow control", OPT_NOARG|OPT_VAL(-1) },
    { "-crtscts", o_int, &crtscts,
      "Disable hardware flow control", OPT_NOARG|OPT_VAL(-1) },
    { "cdtrcts", o_int, &crtscts,
      "Set alternate hardware (DTR/CTS) flow control", OPT_NOARG|OPT_VAL(2) },
    { "nocdtrcts", o_int, &crtscts,
      "Disable hardware flow control", OPT_NOARG|OPT_VAL(-1) },
    { "xonxoff", o_special_noarg, (void *)setxonxoff,
      "Set software (XON/XOFF) flow control" },
    { "domain", o_special, (void *)setdomain,
      "Add given domain name to hostname" },
    { "netmask", o_special, (void *)setnetmask,
      "set netmask" },
    { "modem", o_bool, &modem,
      "Use modem control lines", 1 },
    { "local", o_bool, &modem,
      "Don't use modem control lines" },
    { "file", o_special, (void *)readfile,
      "Take options from a file", OPT_PREPASS },
    { "call", o_special, (void *)callfile,
      "Take options from a privileged file", OPT_PREPASS },
    { "persist", o_bool, &persist,
      "Keep on reopening connection after close", 1 },
    { "nopersist", o_bool, &persist,
      "Turn off persist option" },
    { "demand", o_bool, &demand,
      "Dial on demand", OPT_INITONLY | 1, &persist },
    { "--version", o_special_noarg, (void *)showversion,
      "Show version number" },
    { "--help", o_special_noarg, (void *)showhelp,
      "Show brief listing of options" },
    { "-h", o_special_noarg, (void *)showhelp,
      "Show brief listing of options" },
    { "options", o_special_noarg, (void *)showalloptions,
      "Show full listing of options" },
    { "sync", o_bool, &sync_serial,
      "Use synchronous HDLC serial encoding", 1 },
    { "logfd", o_int, &log_to_fd,
      "Send log messages to this file descriptor",
      0, &log_to_specific_fd },
    { "logfile", o_special, (void *)setlogfile,
      "Append log messages to this file" },
    { "nolog", o_int, &log_to_fd,
      "Don't send log messages to any file",
      OPT_NOARG | OPT_VAL(-1) },
    { "nologfd", o_int, &log_to_fd,
      "Don't send log messages to any file descriptor",
      OPT_NOARG | OPT_VAL(-1) },
    { "linkname", o_string, linkname,
      "Set logical name for link",
      OPT_PRIV|OPT_STATIC, NULL, MAXPATHLEN },
    { "maxfail", o_int, &maxfail,
      "Number of unsuccessful connection attempts to allow" },
    { "ktune", o_bool, &tune_kernel,
      "Alter kernel settings as necessary", 1 },
    { "noktune", o_bool, &tune_kernel,
      "Don't alter kernel settings", 0 },
    { "connect-delay", o_int, &connect_delay,
      "Maximum wait time (msec) after connect script finishes" },
    { "datarate", o_int, &max_data_rate,
      "Max data rate in bytes/sec for pty, notty, or record" },
    { "unit", o_int, &req_unit,
      "PPP interface unit number to use if possible", OPT_LLIMIT, 0, 0 },
#ifdef HAVE_MULTILINK
    { "multilink", o_bool, &multilink,
      "Enable multilink operation", 1 },
    { "nomultilink", o_bool, &multilink,
      "Disable multilink operation", 0 },
    { "mp", o_bool, &multilink,
      "Enable multilink operation", 1 },
    { "nomp", o_bool, &multilink,
      "Disable multilink operation", 0 },
    { "bundle", o_string, &bundle_name,
      "Bundle name for multilink" },
#endif /* HAVE_MULTILINK */
#ifdef PLUGIN
    { "plugin", o_special, (void *)loadplugin,
      "Load a plug-in module into pppd", OPT_PRIV },
#endif /* PLUGIN */
#ifdef PPP_FILTER
    { "pdebug", o_int, &dflag,
      "libpcap debugging" },
    { "pass-filter", o_special, setpassfilter,
      "set filter for packets to pass" },
    { "active-filter", o_special, setactivefilter,
      "set filter for active pkts" },
#endif /* PPP_FILTER */
    { NULL }
};

/*
 * This string gets printed out when "options" is given on the command
 * line.  Following this string, all of the available options and
 * their descriptions are printed out as well.  Certain options which
 * are not available as part of the option_t structure are placed in
 * the "dummy" option structure.
 */
static const char pre_allopt_string[] = "\
pppd version %s.%d%s\n\
Usage: %s [ options ], where options are:\n\n\
";

/* Do not call add_options() on this structure */
static option_t dummy_options[] = {
    { "<device>", o_special_noarg, NULL,
      "Communicate over the named device" },
    { "<speed>", o_special_noarg, NULL,
      "Set the baud rate to <speed>" },
    { "[<loc>]:[<rem>]", o_special_noarg, NULL,
      "Set the local and/or remote interface IP addresses" },
    { NULL }
};

static const char post_allopt_string[] = "\
\n\
Notes:\
\t<n>\tinteger type argument\n\
\t<s>\tstring type argument\n\
\t<r>\tspecial type argument\n\
\t(!)\tprivileged option available only when pppd is executed by root\n\
\t\tor when found in the privileged option files (/etc/ppp/options,\n\
\t\t/etc/ppp/options.ttyname, /etc/ppp/peers/name, or following\n\
\t\t\"--\" in /etc/ppp/pap-secrets or /etc/ppp/chap-secrets).\n\
\t(#)\tdisabled option\n\
\n\
Please see the pppd man page for details.\n";

/*
 * parse_args - parse a string of arguments from the command line.  If prepass
 * is true, we are scanning for the device name and only processing a few
 * options, so error messages are suppressed.  Returns 1 upon successful
 * processing of options, and 0 otherwise.
 */
int
parse_args(argc, argv)
    int argc;
    char **argv;
{
    char *arg;
    option_t *opt;
    int ret;

    privileged_option = privileged;
    option_source = "command line";
    option_line = 0;
    while (argc > 0) {
	arg = *argv++;
	--argc;

	/*
	 * First check to see if it's a known option name.  If so, parse the
	 * argument(s) and set the option.
	 */
	opt = find_option(arg);
	if (opt != NULL) {
	    int n = n_arguments(opt);
	    if (argc < n) {
		option_error("too few parameters for option '%s'", arg);
		return (0);
	    }
	    current_option = arg;
	    if (!process_option(opt, argv, 0))
		return (0);
	    argc -= n;
	    argv += n;
	    continue;
	}

	/*
	 * Maybe a tty name, speed or IP address ?
	 */
	if (((ret = setdevname(arg)) == 0) &&
	    ((ret = setspeed(arg)) == 0) &&
	    ((ret = setipaddr(arg)) == 0) && !prepass) {
	    option_error("unrecognized option '%s'", arg);
	    usage();
	    return (0);
	}
	if (ret < 0)	/* error */
	    return (0);
    }
    return (1);
}

/*
 * options_from_file - read a string of options from a file, and
 * interpret them.  Returns 1 upon successful processing of options,
 * and 0 otherwise.
 */
int
options_from_file
#ifdef __STDC__
    (char *filename, bool must_exist, bool check_prot, bool priv)
#else
    (filename, must_exist, check_prot, priv)
    char *filename;
    bool must_exist;
    bool check_prot;
    bool priv;
#endif
{
    FILE *f;
    int i, newline, ret, err;
    option_t *opt;
    bool oldpriv;
    int oldline, sline;
    char *oldsource;
    char *argv[MAXARGS];
    char args[MAXARGS][MAXWORDLEN];
    char cmd[MAXWORDLEN];
    static bool firsterr = 1;
    static int nestlevel = 0;

    if (nestlevel >= MAXFILENESTING) {
	option_error("file nesting too deep");
	return (0);
    }
    if (check_prot)
	(void) seteuid(getuid());
    errno = 0;
    f = fopen(filename, "r");
    err = errno;
    if (check_prot)
	(void) seteuid(0);
    if (f == NULL) {
	if (!must_exist && err == ENOENT)
	    return (1);
	errno = err;
	option_error("Can't open options file %s: %m", filename);
	return (0);
    }

    nestlevel++;
    oldpriv = privileged_option;
    privileged_option = priv;
    oldsource = option_source;
    /*
     * strdup() is used here because the pointer might refer to the
     * caller's automatic (stack) storage, and the option_info array
     * records the source file name.
     */
    option_source = strdup(filename);
    oldline = option_line;
    option_line = 1;
    if (option_source == NULL)
	option_source = "file";
    ret = 0;
    while (getword(f, cmd, &newline, filename)) {
	sline = option_line;
	/*
	 * First see if it's a command.
	 */
	opt = find_option(cmd);
	if (opt != NULL) {
	    int n = n_arguments(opt);
	    for (i = 0; i < n; ++i) {
		if (!getword(f, args[i], &newline, filename)) {
		    option_error("too few parameters for option '%s'", cmd);
		    goto err;
		}
		argv[i] = args[i];
	    }
	    current_option = cmd;
	    if ((opt->flags & OPT_DEVEQUIV) && devnam_fixed) {
		option_error("the '%s' option may not be used here", cmd);
		goto err;
	    }
	    if (!process_option(opt, argv, sline))
		goto err;
	    continue;
	}

	/*
	 * Maybe a tty name, speed or IP address ?
	 */
	if (((i = setdevname(cmd)) == 0) &&
	    ((i = setspeed(cmd)) == 0) &&
	    ((i = setipaddr(cmd)) == 0)) {
	    option_error("unrecognized option '%s'", cmd);
	    goto err;
	}
	if (i < 0)		/* error */
	    goto err;
    }
    ret = 1;

err:
    (void) fclose(f);
    /* We assume here that we abort all processing on the first error. */
    if (firsterr)
	firsterr = 0;
    else if (!prepass && !ret)
	option_error("error in included file");
    /*
     * Cannot free option_source because it might be referenced in one
     * or more option_info structures now.
     */
    privileged_option = oldpriv;
    option_source = oldsource;
    option_line = oldline;
    nestlevel--;
    return (ret);
}

/*
 * options_from_user - see if the user has a ~/.ppprc file, and if so,
 * interpret options from it.  Returns 1 upon successful processing of
 * options, and 0 otherwise.
 */
int
options_from_user()
{
    char *user, *path, *file;
    int ret;
    struct passwd *pw;
    size_t pl;

    pw = getpwuid(getuid());
    if (pw == NULL || (user = pw->pw_dir) == NULL || user[0] == '\0')
	return (1);
    file = _PATH_USEROPT;
    pl = strlen(user) + strlen(file) + 2;
    path = malloc(pl);
    if (path == NULL)
	novm("init file name");
    (void) slprintf(path, pl, "%s/%s", user, file);
    ret = options_from_file(path, 0, 1, privileged);
    free(path);
    return (ret);
}

/*
 * options_for_tty - see if an options file exists for the serial device, and
 * if so, interpret options from it.  Returns 1 upon successful processing of
 * options, and 0 otherwise.
 */
int
options_for_tty()
{
    char *dev, *path, *p;
    int ret;
    size_t pl;

    dev = devnam;
    if (strncmp(dev, "/dev/", 5) == 0)
	dev += 5;
    if (dev[0] == '\0' || strcmp(dev, "tty") == 0)
	return (1);		/* don't look for /etc/ppp/options.tty */
    pl = strlen(_PATH_TTYOPT) + strlen(dev) + 1;
    path = malloc(pl);
    if (path == NULL)
	novm("tty init file name");
    (void) slprintf(path, pl, "%s%s", _PATH_TTYOPT, dev);
    /* Turn slashes into dots, for Solaris case (e.g. /dev/term/a) */
    for (p = path + strlen(_PATH_TTYOPT); *p != '\0'; ++p)
	if (*p == '/')
	    *p = '.';
    ret = options_from_file(path, 0, 0, 1);
    free(path);
    return (ret);
}

/*
 * options_from_list - process a string of options in a wordlist.  Returns 1
 * upon successful processing of options, and 0 otherwise.
 */
int
options_from_list
#ifdef __STDC__
    (struct wordlist *w, bool priv)
#else
    (w, priv)
    struct wordlist *w;
    bool priv;
#endif
{
    char *argv[MAXARGS];
    option_t *opt;
    int i, ret = 0;

    privileged_option = priv;

    /* Caller is expected to set option_source and option_line. */

    while (w != NULL) {
	/*
	 * First see if it's a command.
	 */
	opt = find_option(w->word);
	if (opt != NULL) {
	    int n = n_arguments(opt);
	    struct wordlist *w0 = w;
	    for (i = 0; i < n; ++i) {
		w = w->next;
		if (w == NULL) {
		    option_error("too few parameters for option '%s'",
			w0->word);
		    goto err;
		}
		argv[i] = w->word;
	    }
	    current_option = w0->word;
	    if (!process_option(opt, argv, option_line))
		goto err;
	    continue;
	}

	/*
	 * Options from the {p,ch}ap-secrets files can't change the device
	 * name nor the speed.  Therefore, calls to setdevname() and
	 * setspeed() were removed.
	 */
	if ((i = setipaddr(w->word)) == 0) {
	    option_error("unrecognized option '%s'", w->word);
	    goto err;
	}
	if (i < 0)		/* error */
	    goto err;
    }
    ret = 1;

err:
    return (ret);
}

/*
 * find_option - scan the option lists for the various protocols looking for an
 * entry with the given name.  Returns a pointer to the matching option_t
 * structure upon successful processing of options, and NULL otherwise.
 */
static option_t *
find_option(name)
    char *name;
{
    hashentry_t *bucket;

    bucket = hash_tbl[opt_hash(name)];
    for (; bucket != NULL; bucket = bucket->next) {
	if (bucket->opt.p->name != NULL) {
	    if ((strcmp(bucket->opt.p->name, name) == 0) &&
		!(bucket->opt.p->flags & OPT_DISABLE)) {
		return (bucket->opt.p);
	    }
	}
    }
    return (NULL);
}

/*
 * process_option - process one new-style option (something other than a
 * port name, bit rate, or IP address).  Returns 1 upon successful
 * processing of options, and 0 otherwise.
 */
static int
process_option(opt, argv, sline)
    option_t *opt;
    char **argv;
    int sline;
{
    u_int32_t v;
    int iv, a;
    char *sv;
    int (*parser) __P((char **, option_t *));

    if ((opt->flags & OPT_PREPASS) == 0 && prepass)
	return (1);
    if ((opt->flags & OPT_INITONLY) && phase != PHASE_INITIALIZE) {
	option_error("it's too late to use the '%s' option", opt->name);
	return (0);
    }
    if ((opt->flags & OPT_PRIV) && !privileged_option) {
	option_error("using the '%s' option requires root privilege",
	    opt->name);
	return (0);
    }
    if ((opt->flags & OPT_ENABLE) && !privileged_option &&
	*(bool *)(opt->addr2) == 0) {
	option_error("'%s' option is disabled", opt->name);
	return (0);
    }
    if ((opt->flags & OPT_PRIVFIX) && !privileged_option) {
	struct option_info *ip = (struct option_info *) opt->addr2;
	if ((ip != NULL) && ip->priv) {
	    option_error("'%s' option cannot be overridden", opt->name);
	    return (0);
	}
    }

    switch (opt->type) {
    case o_bool:
	v = opt->flags & OPT_VALUE;
	*(bool *)(opt->addr) = (v != 0);
	if ((opt->addr2 != NULL) && (opt->flags & OPT_A2COPY))
	    *(bool *)(opt->addr2) = (v != 0);
	break;

    case o_int:
	iv = 0;
	if ((opt->flags & OPT_NOARG) == 0) {
	    if (!int_option(*argv, &iv))
		return (0);
	    if ((((opt->flags & OPT_LLIMIT) && (iv < opt->lower_limit)) ||
		((opt->flags & OPT_ULIMIT) && (iv > opt->upper_limit))) &&
		!((opt->flags & OPT_ZEROOK) && (iv == 0))) {
		char *zok = (opt->flags & OPT_ZEROOK) ? " zero or" : "";
		switch (opt->flags & OPT_LIMITS) {
		case OPT_LLIMIT:
		    option_error("%s value must be%s >= %d",
				 opt->name, zok, opt->lower_limit);
		    break;
		case OPT_ULIMIT:
		    option_error("%s value must be%s <= %d",
				 opt->name, zok, opt->upper_limit);
		    break;
		case OPT_LIMITS:
		    option_error("%s value must be%s between %d and %d",
				opt->name, zok, opt->lower_limit, opt->upper_limit);
		    break;
		}
		return (0);
	    }
	}
	a = opt->flags & OPT_VALUE;
	if (a >= 128)
	    a -= 256;		/* sign extend */
	iv += a;
	if (opt->flags & OPT_INC)
	    iv += *(int *)(opt->addr);
	if ((opt->flags & OPT_NOINCR) && !privileged_option) {
	    int oldv = *(int *)(opt->addr);

	    if ((opt->flags & OPT_ZEROINF) && (iv == 0)) {
		if (oldv > 0) {
		    option_error("%s value cannot be set to infinity; limited to %d",
			opt->name, oldv);
		    return (0);
		}
	    } else if (iv > oldv) {
		option_error("%s value cannot be increased beyond %d",
		    opt->name, oldv);
		return (0);
	    }
	}
	*(int *)(opt->addr) = iv;
	if ((opt->addr2 != NULL) && (opt->flags & OPT_A2COPY))
	    *(int *)(opt->addr2) = iv;
	break;

    case o_uint32:
	if (opt->flags & OPT_NOARG) {
	    v = opt->flags & OPT_VALUE;
	} else if (!number_option(*argv, &v, 16))
	    return (0);
	if (opt->flags & OPT_OR)
	    v |= *(u_int32_t *)(opt->addr);
	*(u_int32_t *)(opt->addr) = v;
	if ((opt->addr2 != NULL) && (opt->flags & OPT_A2COPY))
	    *(u_int32_t *)(opt->addr2) = v;
	break;

    case o_string:
	if (opt->flags & OPT_STATIC) {
	    (void) strlcpy((char *)(opt->addr), *argv, opt->upper_limit);
	    if ((opt->addr2 != NULL) && (opt->flags & OPT_A2COPY)) {
		(void) strlcpy((char *)(opt->addr2), *argv, opt->upper_limit);
	    }
	} else {
	    sv = strdup(*argv);
	    if (sv == NULL)
		novm("option argument");
	    *(char **)(opt->addr) = sv;
	    if (opt->addr2 != NULL && (opt->flags & OPT_A2COPY))
		*(char **)(opt->addr2) = sv;
	}
	break;

    case o_special_noarg:
    case o_special:
	parser = (int (*) __P((char **, option_t *))) opt->addr;
	if (!(*parser)(argv, opt))
	    return (0);
	break;
    }

    if (opt->addr2 != NULL) {
	if (opt->flags & OPT_A2INFO) {
	    struct option_info *ip = (struct option_info *) opt->addr2;
	    ip->priv = privileged_option;
	    ip->source = option_source;
	    ip->line = sline;
	} else if ((opt->flags & (OPT_A2COPY|OPT_ENABLE)) == 0)
	    *(bool *)(opt->addr2) = 1;
    }

    return (1);
}

/*
 * n_arguments - tell how many arguments an option takes.  Returns 1 upon
 * successful processing of options, and 0 otherwise.
 */
static int
n_arguments(opt)
    option_t *opt;
{
    return ((opt->type == o_bool || opt->type == o_special_noarg ||
	    (opt->flags & OPT_NOARG)) ? 0 : 1);
}

/*
 * opt_hash - a hash function that works quite well for strings.  Returns
 * the hash key of the supplied string.
 */
static u_int32_t
opt_hash(key)
    const void *key;
{
    register const char *ptr;
    register u_int32_t val;

    val = 0;
    ptr = key;
    while (*ptr != '\0') {
	int tmp;
	val = (val << 4) + (*ptr);
	tmp = val & 0xf0000000;
	if (tmp) {
	    val ^= (tmp >> 24);
	    val ^= tmp;
	}
	ptr++;
    }
    return (val % OPTHASH_TBLSIZE);
}

/*
 * add_options - add a list of options to the chained hash table.
 * Also detect duplicate options, and if found, disable the older
 * definition and log it as an error.
 */
void
add_options(opt)
    option_t *opt;
{
    register option_t *sopt;
    register hashentry_t *bucket;
    register u_int32_t loc;
    hashentry_t *he;

    /* fill hash-table */
    for (sopt = opt; sopt->name != NULL; ++sopt, hash_tblcnt++) {

	/* first, allocate a hash entry */
	he = (hashentry_t *)malloc(sizeof(*he));
	if (he == NULL) {
	    novm("option hash table entry");
	}
	he->opt.p = sopt;
	he->next = NULL;

	/*
	 * fill the chained hash table and take care of any collisions or
	 * duplicate items.
	 */
	loc = opt_hash(sopt->name);
	bucket = hash_tbl[loc];
	if (bucket != NULL) {
	    for (;;) {
		if (!(bucket->opt.p->flags & OPT_DISABLE) &&
		    strcmp(sopt->name, bucket->opt.p->name) == 0) {
		    info("option '%s' redefined; old definition disabled",
			sopt->name);
		    bucket->opt.p->flags |= OPT_DISABLE;
		}
		if (bucket->next == NULL)
		    break;
		bucket = bucket->next;
	    }
	    bucket->next = he;
	} else {
	    hash_tbl[loc] = he;
	}
    }
}

/*
 * remove_option - disable an option.  Returns the option_t structure
 * of the disabled option, or NULL if the option name is invalid or if
 * the option has already been disabled.
 */
option_t *
remove_option(name)
    char *name;
{
    option_t *opt;

    if ((opt = find_option(name)) != NULL) {
	opt->flags |= OPT_DISABLE;
    }
    return (opt);
}

/*
 * opt_compare - a compare function supplied to the quicksort routine.
 * Returns an integer less than, equal to, or greater than zero to indicate
 * if the first argument is considered less than, equal to, or greater
 * than the second argument.
 */
static int
opt_compare(p1, p2)
    const void *p1;
    const void *p2;
{
    opt_t *o1 = (opt_t *)p1;
    opt_t *o2 = (opt_t *)p2;

    return (strcmp(o1->p->name, o2->p->name));
}

/*ARGSUSED*/
static int
showalloptions(argv, topt)
    char **argv;
    option_t *topt;
{
#define	MAXOPTSTRLEN	257
#define	PRINTOPTIONS()	{					\
    (void) slprintf(opt_str, sizeof(opt_str), "%s", opt->name);	\
    if ((opt->type == o_int || opt->type == o_uint32) &&	\
	!(opt->flags & OPT_NOARG)) {				\
	(void) strlcat(opt_str, " <n>", sizeof(opt_str));	\
    } else if (opt->type == o_string) {				\
	(void) strlcat(opt_str, " <s>", sizeof(opt_str));	\
    } else if (opt->type == o_special) {			\
	(void) strlcat(opt_str, " <r>", sizeof(opt_str));	\
    }								\
    if (opt->flags & OPT_PRIV) {				\
	(void) strlcat(opt_str, " (!)", sizeof(opt_str));	\
    } else if (opt->flags & OPT_DISABLE) {			\
	(void) strlcat(opt_str, " (#)", sizeof(opt_str));	\
    }								\
    (void) printf("%-26s%s\n", opt_str, opt->description);	\
}

    char opt_str[MAXOPTSTRLEN];
    option_t *opt;
    hashentry_t *bucket;
    int i, sofar;
    opt_t *sopt;

    if (phase != PHASE_INITIALIZE) {
	return (0);
    }
    (void) printf(pre_allopt_string, VERSION, PATCHLEVEL, IMPLEMENTATION,
	progname);
    for (opt = dummy_options; opt->name != NULL; ++opt) {
	PRINTOPTIONS();
    }

    sopt = malloc(sizeof(*sopt) * hash_tblcnt);
    if (sopt == NULL) {
	novm("sorted option table");
    }

    sofar = 0;
    for (i = 0; i < OPTHASH_TBLSIZE; i++) {
	for (bucket = hash_tbl[i]; bucket != NULL; bucket = bucket->next) {
	    if (sofar >= hash_tblcnt) {
		fatal("options hash table corrupted; size mismatch");
	    }
	    sopt[sofar++].p = bucket->opt.p;
	}
    }

    qsort((void *)sopt, sofar, sizeof(sopt[0]), opt_compare);
    for (i = 0; i < sofar; i++) {
	opt = sopt[i].p;
	PRINTOPTIONS();
    }

    (void) printf(post_allopt_string);
    (void) free(sopt);

#undef	MAXOPTSTRLEN
#undef	PRINTOPTIONS
    return (0);
}

/*
 * usage - print out a message telling how to use the program.
 * This string gets printed out when either "--help" or an invalid option
 * is specified.
 */
static void
usage()
{
	static const char usage_string[] = "\
pppd version %s.%d%s\n\
Usage: %s [ options ], where options are:\n\
\t<device>\tCommunicate over the named device\n\
\t<speed>\t\tSet the baud rate to <speed>\n\
\t<loc>:<rem>\tSet the local and/or remote interface IP\n\
\t\t\taddresses.  Either one may be omitted.\n\
\tnoauth\t\tDon't require authentication from peer\n\
\tconnect <p>\tInvoke shell command <p> to set up the serial line\n\
\tdefaultroute\tAdd default route through interface\n\
Use \"%s options\" or \"man pppd\" for more options.\n\
";

    if (phase == PHASE_INITIALIZE)
	(void) fprintf(stderr, usage_string, VERSION, PATCHLEVEL,
	    IMPLEMENTATION, progname, progname);
}

/*
 * showhelp - print out usage message and exit program upon success, or
 * return 0 otherwise.
 */
/*ARGSUSED*/
static int
showhelp(argv, opt)
    char **argv;
    option_t *opt;
{
    if (phase == PHASE_INITIALIZE) {
	usage();
	exit(0);
    }
    return (0);
}

/*
 * showversion - print out the version number and exit program  upon success,
 * or return 0 otherwise.
 */
/*ARGSUSED*/
static int
showversion(argv, opt)
    char **argv;
    option_t *opt;
{
    if (phase == PHASE_INITIALIZE) {
	(void) fprintf(stderr, "pppd version %s.%d%s\n", VERSION, PATCHLEVEL,
	    IMPLEMENTATION);
	exit(0);
    }
    return (0);
}

/*
 * option_error - print a message about an error in an option.  The message is
 * logged, and also sent to stderr if phase == PHASE_INITIALIZE.
 */
void
option_error __V((char *fmt, ...))
{
    va_list args;
    char buf[256];
    int i, err;

#if defined(__STDC__)
    va_start(args, fmt);
#else
    char *fmt;
    va_start(args);
    fmt = va_arg(args, char *);
#endif
    if (prepass) {
	va_end(args);
	return;
    }
    err = errno;
    if (option_source == NULL) {
	i = 0;
    } else if (option_line <= 0) {
	(void) strlcpy(buf, option_source, sizeof (buf));
	i = strlen(buf);
    } else {
	i = slprintf(buf, sizeof(buf), "%s:%d", option_source, option_line);
    }
    if (i != 0) {
	(void) strlcat(buf, ": ", sizeof (buf));
	i += 2;
    }
    errno = err;
    (void) vslprintf(buf + i, sizeof (buf) - i, fmt, args);
    va_end(args);
    if ((phase == PHASE_INITIALIZE) && !detached)
	(void) fprintf(stderr, "%s: %s\n", progname, buf);
    syslog(LOG_ERR, "%s", buf);
}

/*
 * getword - read a word from a file.  Words are delimited by white-space or by
 * quotes (" or ').  Quotes, white-space and \ may be escaped with \.
 * \<newline> is ignored.  Returns 1 upon successful processing of options,
 * and 0 otherwise.
 */
int
getword(f, word, newlinep, filename)
    FILE *f;
    char *word;
    int *newlinep;
    char *filename;
{
    int c, len, escape;
    int quoted, comment;
    int value, digit, got, n;

#define isoctal(c) ((c) >= '0' && (c) < '8')

    *newlinep = 0;
    len = 0;
    escape = 0;
    comment = 0;

    /*
     * First skip white-space and comments.
     */
    for (;;) {
	c = getc(f);
	if (c == EOF)
	    break;

	/*
	 * A newline means the end of a comment; backslash-newline
	 * is ignored.  Note that we cannot have escape && comment.
	 */
	if (c == '\n') {
	    option_line++;
	    if (!escape) {
		*newlinep = 1;
		comment = 0;
	    } else
		escape = 0;
	    continue;
	}

	/*
	 * Ignore characters other than newline in a comment.
	 */
	if (comment)
	    continue;

	/*
	 * If this character is escaped, we have a word start.
	 */
	if (escape)
	    break;

	/*
	 * If this is the escape character, look at the next character.
	 */
	if (c == '\\') {
	    escape = 1;
	    continue;
	}

	/*
	 * If this is the start of a comment, ignore the rest of the line.
	 */
	if (c == '#') {
	    comment = 1;
	    continue;
	}

	/*
	 * A non-whitespace character is the start of a word.
	 */
	if (!isspace(c))
	    break;
    }

    /*
     * Save the delimiter for quoted strings.
     */
    if (!escape && (c == '"' || c == '\'')) {
        quoted = c;
	c = getc(f);
    } else
        quoted = 0;

    /*
     * Process characters until the end of the word.
     */
    while (c != EOF) {
	if (escape) {
	    /*
	     * This character is escaped: backslash-newline is ignored,
	     * various other characters indicate particular values
	     * as for C backslash-escapes.
	     */
	    escape = 0;
	    if (c == '\n') {
	        c = getc(f);
		continue;
	    }

	    got = 0;
	    switch (c) {
	    case 'a':
		value = '\a';
		break;
	    case 'b':
		value = '\b';
		break;
	    case 'f':
		value = '\f';
		break;
	    case 'n':
		value = '\n';
		break;
	    case 'r':
		value = '\r';
		break;
	    case 's':
		value = ' ';
		break;
	    case 't':
		value = '\t';
		break;

	    default:
		if (isoctal(c)) {
		    /*
		     * \ddd octal sequence
		     */
		    value = 0;
		    for (n = 0; n < 3 && isoctal(c); ++n) {
			value = (value << 3) + (c & 07);
			c = getc(f);
		    }
		    got = 1;
		    break;
		}

		if (c == 'x') {
		    /*
		     * \x<hex_string> sequence
		     */
		    value = 0;
		    c = getc(f);
		    for (n = 0; n < 2 && isxdigit(c); ++n) {
			digit = (islower(c) ? toupper(c) : c) - '0';
			if (digit > 10 || digit < 0)	/* allow non-ASCII */
			    digit += '0' + 10 - 'A';
			value = (value << 4) + digit;
			c = getc (f);
		    }
		    got = 1;
		    break;
		}

		/*
		 * Otherwise the character stands for itself.
		 */
		value = c;
		break;
	    }

	    /*
	     * Store the resulting character for the escape sequence.
	     */
	    if (len < MAXWORDLEN) {
		word[len] = value;
		++len;
	    }

	    if (!got)
		c = getc(f);
	    continue;

	}

	/*
	 * Not escaped: see if we've reached the end of the word.
	 */
	if (quoted) {
	    if (c == quoted)
		break;
	} else {
	    if (isspace(c) || c == '#') {
		(void) ungetc (c, f);
		break;
	    }
	}

	/*
	 * Backslash starts an escape sequence.
	 */
	if (c == '\\') {
	    escape = 1;
	    c = getc(f);
	    continue;
	}

	/*
	 * An ordinary character: store it in the word and get another.
	 */
	if (len < MAXWORDLEN) {
	    word[len] = c;
	    ++len;
	}

	c = getc(f);
    }

    /*
     * End of the word: check for errors.
     */
    if (c == EOF) {
	if (ferror(f)) {
	    if (errno == 0)
		errno = EIO;
	    option_error("Error reading %s: %m", filename);
	    die(1);
	}
	/*
	 * If len is zero, then we didn't find a word before the
	 * end of the file.
	 */
	if (len == 0)
	    return (0);
    }

    /*
     * Warn if the word was too long, and append a terminating null.
     */
    if (len >= MAXWORDLEN) {
	option_error("warning: word in file %s too long (%.20s...)",
		     filename, word);
	len = MAXWORDLEN - 1;
    }
    word[len] = '\0';

    return (1);

#undef isoctal

}

/*
 * number_option - parse an unsigned numeric parameter for an option.
 * Returns 1 upon successful processing of options, and 0 otherwise.
 */
static int
number_option(str, valp, base)
    char *str;
    u_int32_t *valp;
    int base;
{
    char *ptr;

    *valp = strtoul(str, &ptr, base);
    if (ptr == str || *ptr != '\0') {
	option_error("invalid numeric parameter '%s' for '%s' option",
		     str, current_option);
	return (0);
    }
    return (1);
}

/*
 * save_source - store option source, line, and privilege into an
 * option_info structure.
 */
void
save_source(info)
    struct option_info *info;
{
    info->priv = privileged_option;
    info->source = option_source;
    info->line = option_line;
}

/*
 * set_source - set option source, line, and privilege from an
 * option_info structure.
 */
void
set_source(info)
    struct option_info *info;
{
    privileged_option = info->priv;
    option_source = info->source;
    option_line = info->line;
}

/*
 * name_source - return string containing option source and line.  Can
 * be used as part of an option_error call.
 */
const char *
name_source(info)
    struct option_info *info;
{
    static char buf[MAXPATHLEN];

    if (info->source == NULL)
	return "none";
    if (info->line <= 0)
	return info->source;
    (void) slprintf(buf, sizeof (buf), "%s:%d", info->source, info->line);
    return (const char *)buf;
}

/*
 * int_option - like number_option, but valp is int *, the base is assumed to
 * be 0, and *valp is not changed if there is an error.  Returns 1 upon
 * successful processing of options, and 0 otherwise.
 */
int
int_option(str, valp)
    char *str;
    int *valp;
{
    u_int32_t v;

    if (!number_option(str, &v, 0))
	return (0);
    *valp = (int) v;
    return (1);
}


/*
 * The following procedures parse options.
 */

/*
 * readfile - take commands from a file.
 */
/*ARGSUSED*/
static int
readfile(argv, opt)
    char **argv;
    option_t *opt;
{
    return (options_from_file(*argv, 1, 1, privileged_option));
}

/*
 * callfile - take commands from /etc/ppp/peers/<name>.  Name may not contain
 * /../, start with / or ../, or end in /.  Returns 1 upon successful
 * processing of options, and 0 otherwise.
 */
/*ARGSUSED*/
static int
callfile(argv, opt)
    char **argv;
    option_t *opt;
{
    char *fname, *arg, *p;
    int l, ok;

    arg = *argv;
    ok = 1;
    if (arg[0] == '/' || arg[0] == '\0')
	ok = 0;
    else {
	for (p = arg; *p != '\0'; ) {
	    if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0')) {
		ok = 0;
		break;
	    }
	    while (*p != '/' && *p != '\0')
		++p;
	    if (*p == '/')
		++p;
	}
    }
    if (!ok) {
	option_error("call option value may not contain .. or start with /");
	return (0);
    }

    l = strlen(arg) + strlen(_PATH_PEERFILES) + 1;
    if ((fname = (char *) malloc(l)) == NULL)
	novm("call file name");
    (void) slprintf(fname, l, "%s%s", _PATH_PEERFILES, arg);

    ok = options_from_file(fname, 1, 1, 1);

    free(fname);
    return (ok);
}

#ifdef PPP_FILTER
/*
 * setpdebug - set libpcap debugging level.  Returns 1 upon successful
 * processing of options, and 0 otherwise.
 */
static int
setpdebug(argv)
    char **argv;
{
    return (int_option(*argv, &dflag));
}

/*
 * setpassfilter - set the pass filter for packets.  Returns 1 upon successful
 * processing of options, and 0 otherwise.
 */
/*ARGSUSED*/
static int
setpassfilter(argv, opt)
    char **argv;
    option_t *opt;
{
    pc.linktype = DLT_PPP;
    pc.snapshot = PPP_HDRLEN;

    if (pcap_compile(&pc, &pass_filter, *argv, 1, netmask) == 0)
	return (1);
    option_error("error in pass-filter expression: %s\n", pcap_geterr(&pc));
    return (0);
}

/*
 * setactivefilter - set the active filter for packets.  Returns 1 upon
 * successful processing of options, and 0 otherwise.
 */
/*ARGSUSED*/
static int
setactivefilter(argv, opt)
    char **argv;
    option_t *opt;
{
    pc.linktype = DLT_PPP;
    pc.snapshot = PPP_HDRLEN;

    if (pcap_compile(&pc, &active_filter, *argv, 1, netmask) == 0)
	return (1);
    option_error("error in active-filter expression: %s\n", pcap_geterr(&pc));
    return (0);
}
#endif /* PPP_FILTER */

/*
 * noopt - disable all options.  Returns 1 upon successful processing of
 * options, and 0 otherwise.
 */
/*ARGSUSED*/
static int
noopt(argv, opt)
    char **argv;
    option_t *opt;
{
    BZERO((char *) &lcp_wantoptions[0], sizeof (struct lcp_options));
    BZERO((char *) &lcp_allowoptions[0], sizeof (struct lcp_options));
    BZERO((char *) &ipcp_wantoptions[0], sizeof (struct ipcp_options));
    BZERO((char *) &ipcp_allowoptions[0], sizeof (struct ipcp_options));

    return (1);
}

/*
 * setdomain - set domain name to append to hostname.  Returns 1 upon
 * successful processing of options, and 0 otherwise.
 */
/*ARGSUSED*/
static int
setdomain(argv, opt)
    char **argv;
    option_t *opt;
{
    if (!privileged_option) {
	option_error("using the domain option requires root privilege");
	return (0);
    }
    (void) gethostname(hostname, MAXHOSTNAMELEN+1);
    if (**argv != '\0') {
	if (**argv != '.')
	    (void) strncat(hostname, ".", MAXHOSTNAMELEN - strlen(hostname));
	(void) strncat(hostname, *argv, MAXHOSTNAMELEN - strlen(hostname));
    }
    hostname[MAXHOSTNAMELEN] = '\0';
    return (1);
}


/*
 * setspeed - set the speed.  Returns 1 upon successful processing of options,
 * and 0 otherwise.
 */
static int
setspeed(arg)
    char *arg;
{
    char *ptr;
    int spd;

    if (prepass)
	return (1);
    spd = strtol(arg, &ptr, 0);
    if (ptr == arg || *ptr != '\0' || spd <= 0)
	return (0);
    inspeed = spd;
    save_source(&speed_info);
    return (1);
}


/*
 * setdevname - set the device name.  Returns 1 upon successful processing of
 * options, 0 when the device does not exist, and -1 when an error is
 * encountered.
 */
static int
setdevname(cp)
    char *cp;
{
    struct stat statbuf;
    char dev[MAXPATHLEN];

    if (*cp == '\0')
	return (0);

    if (strncmp("/dev/", cp, 5) != 0) {
	(void) strlcpy(dev, "/dev/", sizeof(dev));
	(void) strlcat(dev, cp, sizeof(dev));
	cp = dev;
    }

    /*
     * Check if there is a character device by this name.
     */
    if (stat(cp, &statbuf) < 0) {
	if (errno == ENOENT) {
	    return (0);
	}
	option_error("Couldn't stat '%s': %m", cp);
	return (-1);
    }
    if (!S_ISCHR(statbuf.st_mode)) {
	option_error("'%s' is not a character device", cp);
	return (-1);
    }

    if (phase != PHASE_INITIALIZE) {
	option_error("device name cannot be changed after initialization");
	return (-1);
    } else if (devnam_fixed) {
	option_error("per-tty options file may not specify device name");
	return (-1);
    }

    if (devnam_info.priv && !privileged_option) {
	option_error("device name %s from %s cannot be overridden",
	    devnam, name_source(&devnam_info));
	return (-1);
    }

    (void) strlcpy(devnam, cp, sizeof(devnam));
    devstat = statbuf;
    default_device = 0;
    save_source(&devnam_info);

    return (1);
}


/*
 * setipaddr - set the IP address.  Returns 1 upon successful processing of
 * options, 0 when the argument does not contain a `:', and -1 for error.
 */
static int
setipaddr(arg)
    char *arg;
{
    struct hostent *hp;
    char *colon;
    u_int32_t local, remote;
    ipcp_options *wo = &ipcp_wantoptions[0];

    /*
     * IP address pair separated by ":".
     */
    if ((colon = strchr(arg, ':')) == NULL)
	return (0);
    if (prepass)
	return (1);

    /*
     * If colon first character, then no local addr.
     */
    if (colon != arg) {
	*colon = '\0';
	if ((local = inet_addr(arg)) == (u_int32_t) -1) {
	    if ((hp = gethostbyname(arg)) == NULL) {
		option_error("unknown host: %s", arg);
		return (-1);
	    } else {
		BCOPY(hp->h_addr, &local, sizeof(local));
	    }
	}
	if (bad_ip_adrs(local)) {
	    option_error("bad local IP address %I", local);
	    return (-1);
	}
	if (local != 0) {
	    save_source(&ipsrc_info);
	    wo->ouraddr = local;
	}
	*colon = ':';
    }

    /*
     * If colon last character, then no remote addr.
     */
    if (*++colon != '\0') {
	if ((remote = inet_addr(colon)) == (u_int32_t) -1) {
	    if ((hp = gethostbyname(colon)) == NULL) {
		option_error("unknown host: %s", colon);
		return (-1);
	    } else {
		BCOPY(hp->h_addr, &remote, sizeof(remote));
		if (remote_name[0] == '\0')
		    (void) strlcpy(remote_name, colon, sizeof(remote_name));
	    }
	}
	if (bad_ip_adrs(remote)) {
	    option_error("bad remote IP address %I", remote);
	    return (-1);
	}
	if (remote != 0) {
	    save_source(&ipdst_info);
	    wo->hisaddr = remote;
	}
    }

    return (1);
}


/*
 * setnetmask - set the netmask to be used on the interface.  Returns 1 upon
 * successful processing of options, and 0 otherwise.
 */
/*ARGSUSED*/
static int
setnetmask(argv, opt)
    char **argv;
    option_t *opt;
{
    u_int32_t mask;
    int n;
    char *p;

    /*
     * Unfortunately, if we use inet_addr, we can't tell whether
     * a result of all 1s is an error or a valid 255.255.255.255.
     */
    p = *argv;
    n = parse_dotted_ip(p, &mask);

    mask = htonl(mask);

    if (n == 0 || p[n] != 0 || (netmask & ~mask) != 0) {
	option_error("invalid netmask value '%s'", *argv);
	return (0);
    }

    netmask = mask;
    return (1);
}

/*
 * parse_dotted_ip - parse and convert the IP address string to make
 * sure it conforms to the dotted notation.  Returns the length of
 * processed characters upon success, and 0 otherwise.  If successful,
 * the converted IP address number is stored in vp, in the host byte
 * order.
 */
int
parse_dotted_ip(cp, vp)
    register char *cp;
    u_int32_t *vp;
{
    register u_int32_t val, base, n;
    register char c;
    char *cp0 = cp;
    u_char parts[3], *pp = parts;

    if ((*cp == '\0') || (vp == NULL))
	return (0);			/* disallow null string in cp */
    *vp = 0;
again:
    /*
     * Collect number up to ``.''.  Values are specified as for C:
     *	    0x=hex, 0=octal, other=decimal.
     */
    val = 0; base = 10;
    if (*cp == '0') {
	if (*++cp == 'x' || *cp == 'X')
	    base = 16, cp++;
	else
	    base = 8;
    }
    while ((c = *cp) != '\0') {
	if (isdigit(c)) {
	    if ((c - '0') >= base)
		break;
	    val = (val * base) + (c - '0');
	    cp++;
	    continue;
	}
	if (base == 16 && isxdigit(c)) {
	    val = (val << 4) + (c + 10 - (islower(c) ? 'a' : 'A'));
	    cp++;
	    continue;
	}
	break;
    }
    if (*cp == '.') {
	/*
	 * Internet format:
	 *	a.b.c.d
	 *	a.b.c	(with c treated as 16-bits)
	 *	a.b	(with b treated as 24 bits)
	 */
	if ((pp >= parts + 3) || (val > 0xff)) {
	    return (0);
	}
	*pp++ = (u_char)val;
	cp++;
	goto again;
    }
    /*
     * Check for trailing characters.
     */
    if (*cp != '\0' && !isspace(*cp)) {
	return (0);
    }
    /*
     * Concoct the address according to the number of parts specified.
     */
    n = pp - parts;
    switch (n) {
    case 0:				/* a -- 32 bits */
	break;
    case 1:				/* a.b -- 8.24 bits */
	if (val > 0xffffff)
	    return (0);
	val |= parts[0] << 24;
	break;
    case 2:				/* a.b.c -- 8.8.16 bits */
	if (val > 0xffff)
	    return (0);
	val |= (parts[0] << 24) | (parts[1] << 16);
	break;
    case 3:				/* a.b.c.d -- 8.8.8.8 bits */
	if (val > 0xff)
	    return (0);
	val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
	break;
    default:
	return (0);
    }
    *vp = val;
    return (cp - cp0);
}

/*
 * setxonxoff - modify the asyncmap to include escaping XON and XOFF
 * characters used for software flow control.  Returns 1 upon successful
 * processing of options, and 0 otherwise.
 */
/*ARGSUSED*/
static int
setxonxoff(argv, opt)
    char **argv;
    option_t *opt;
{
    int xonxoff = 0x000A0000;

    lcp_wantoptions[0].neg_asyncmap = 1;
    lcp_wantoptions[0].asyncmap |= xonxoff;	/* escape ^S and ^Q */
    lcp_allowoptions[0].asyncmap |= xonxoff;
    xmit_accm[0][0] |= xonxoff;
    xmit_accm[0][4] |= xonxoff;		/* escape 0x91 and 0x93 as well */

    crtscts = -2;
    return (1);
}

/*
 * setlogfile - open (or create) a file used for logging purposes.  Returns 1
 * upon success, and 0 otherwise.
 */
/*ARGSUSED*/
static int
setlogfile(argv, opt)
    char **argv;
    option_t *opt;
{
    int fd, err;

    if (!privileged_option)
	(void) seteuid(getuid());
    fd = open(*argv, O_WRONLY | O_APPEND | O_CREAT | O_EXCL, 0644);
    if (fd < 0 && errno == EEXIST)
	fd = open(*argv, O_WRONLY | O_APPEND);
    err = errno;
    if (!privileged_option)
	(void) seteuid(0);
    if (fd < 0) {
	errno = err;
	option_error("Can't open log file %s: %m", *argv);
	return (0);
    }
    if (log_to_file && log_to_fd >= 0)
	(void) close(log_to_fd);
    log_to_fd = fd;
    log_to_file = 1;
    early_log = 0;
    return (1);
}

#ifdef PLUGIN
/*
 * loadplugin - load and initialize the plugin.  Returns 1 upon successful
 * processing of the plugin, and 0 otherwise.
 */
/*ARGSUSED*/
static int
loadplugin(argv, opt)
    char **argv;
    option_t *opt;
{
    char *arg = *argv;
    void *handle;
    const char *err;
    void (*init) __P((void));

    handle = dlopen(arg, RTLD_GLOBAL | RTLD_NOW);
    if (handle == NULL) {
	err = dlerror();
	if (err != NULL)
	    option_error("%s", err);
	option_error("Couldn't load plugin %s", arg);
	return (0);
    }
    init = (void (*)(void))dlsym(handle, "plugin_init");
    if (init == NULL) {
	option_error("%s has no initialization entry point", arg);
	(void) dlclose(handle);
	return (0);
    }
    info("Plugin %s loaded.", arg);
    (*init)();
    return (1);
}
#endif /* PLUGIN */
