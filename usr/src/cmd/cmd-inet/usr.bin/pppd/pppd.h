/*
 * pppd.h - PPP daemon global declarations.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
 *
 * $Id: pppd.h,v 1.54 2000/04/15 10:10:25 paulus Exp $
 */

#ifndef __PPPD_H__
#define __PPPD_H__

#include <stdio.h>		/* for FILE */
#include <limits.h>		/* for NGROUPS_MAX */
#include <sys/param.h>		/* for MAXPATHLEN and BSD4_4, if defined */
#include <sys/types.h>		/* for u_int32_t, if defined */
#include <sys/time.h>		/* for struct timeval */
#include <net/ppp_defs.h>

#if defined(__STDC__)
#include <stdarg.h>
#define __V(x)	x
#else
#include <varargs.h>
#define __V(x)	(va_alist) va_dcl
#define const
#define volatile
#endif /* __STDC__ */

#ifdef INET6
#include "eui64.h"
#endif /* INET6 */

#ifdef HAVE_MULTILINK
#include "tdb.h"
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Limits.
 */
#define NUM_PPP		1	/* One PPP interface supported (per process) */
#define MAXWORDLEN	1024	/* max length of word in file (incl null) */
#define MAXARGS		1	/* max # args to a command */
#define MAXNAMELEN	256	/* max length of name for auth */
#define MAXSECRETLEN	256	/* max length of password or secret */

#ifndef MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN	MAXNAMELEN  /* max length of hostname */
#endif /* MAXHOSTNAMELEN */

/*
 * If this evaluates non-zero, then sifup() must be called before
 * sifaddr().
 */
#if (defined(SVR4) && (defined(SNI) || defined(__USLC__)))
#define SIFUPFIRST (1)
#else
#define SIFUPFIRST (0)
#endif

/*
 * If this evaluates non-zero, then sif6up() must be called before
 * sif6addr().
 */
#if (defined(__linux__) || \
	(defined(SVR4) && (defined(SNI) || defined(__USLC__))))
#define SIF6UPFIRST (1)
#else
#define SIF6UPFIRST (0)
#endif

/*
 * Option descriptor structure.
 */
typedef unsigned char	bool;

enum opt_type {
	o_special_noarg = 0,
	o_special = 1,
	o_bool,
	o_int,
	o_uint32,
	o_string
};

typedef struct {
	char	*name;		/* name of the option */
	enum opt_type type;
	void	*addr;
	char	*description;
	int	flags;
	void	*addr2;
	int	upper_limit;
	int	lower_limit;
} option_t;

/*
 * Values for flags.
 */
#define OPT_VALUE	0xff	/* mask for presupplied value */
#define OPT_HEX		0x100	/* int option is in hex */
#define OPT_NOARG	0x200	/* option doesn't take argument */
#define OPT_OR		0x400	/* OR in argument to value */
#define OPT_INC		0x800	/* increment value */
#define OPT_PRIV	0x1000	/* privileged option */
#define OPT_STATIC	0x2000	/* string option goes into static array */
#define OPT_LLIMIT	0x4000	/* check value against lower limit */
#define OPT_ULIMIT	0x8000	/* check value against upper limit */
#define OPT_LIMITS	(OPT_LLIMIT|OPT_ULIMIT)
#define OPT_ZEROOK	0x10000	/* 0 value is OK even if not within limits */
#define OPT_NOINCR	0x20000	/* value mustn't be increased */
#define OPT_ZEROINF	0x40000	/* with OPT_NOINCR, 0 == infinity */
#define	OPT_DISABLE	0x80000	/* ignore option */
#define OPT_A2INFO	0x100000 /* addr2 -> option_info to update */
#define OPT_A2COPY	0x200000 /* addr2 -> second location to rcv value */
#define OPT_ENABLE	0x400000 /* use *addr2 as enable for option */
#define OPT_PRIVFIX	0x800000 /* can't be overridden if noauth */
#define OPT_PREPASS	0x1000000 /* do this opt in pre-pass to find device */
#define OPT_INITONLY	0x2000000 /* option can only be set in init phase */
#define OPT_DEVEQUIV	0x4000000 /* equiv to device name */
#define OPT_DEVNAM	(OPT_PREPASS | OPT_INITONLY | OPT_DEVEQUIV)

#define OPT_VAL(x)	((x) & OPT_VALUE)

#ifndef GIDSET_TYPE
#define GIDSET_TYPE	gid_t
#endif /* GIDSET_TYPE */

/*
 * Structure representing a list of permitted IP addresses.
 */
struct permitted_ip {
    int		permit;		/* 1 = permit, 0 = forbid */
    u_int32_t	base;		/* match if (addr & mask) == base */
    u_int32_t	mask;		/* base and mask are in network byte order */
};

/*
 * Unfortunately, the linux kernel driver uses a different structure
 * for statistics from the rest of the ports.
 * This structure serves as a common representation for the bits
 * pppd needs.
 */
struct pppd_stats {
    ppp_counter_t	bytes_in;
    ppp_counter_t	bytes_out;
    ppp_counter_t	pkts_in;
    ppp_counter_t	pkts_out;
};

/*
 * Used for storing a sequence of words.  Usually malloced.
 */
struct wordlist {
    struct wordlist	*next;
    char		*word;
};

/*
 * Global variables.
 */
extern bool	hungup;		/* Physical layer has disconnected */
extern int	ifunit;		/* Interface unit number */
extern char	ifname[32];	/* Interface name */
extern int	ttyfd;		/* Serial device file descriptor */
extern char	hostname[];	/* Our hostname */
extern u_char	outpacket_buf[]; /* Buffer for outgoing packets */
extern int	phase;		/* Current state of link - see values below */
extern int	baud_rate;	/* Current link speed in bits/sec */
extern char	*progname;	/* Name of this program */
extern int	redirect_stderr;/* Connector's stderr should go to file */
extern char	peer_authname[];/* Authenticated name of peer */
extern bool	privileged;	/* We were run by real-uid root */
extern bool	need_holdoff;	/* Need holdoff period after link terminates */
extern char	**script_env;	/* Environment variables for scripts */
extern bool	detached;	/* Have detached from controlling tty */
extern GIDSET_TYPE groups[NGROUPS_MAX];	/* groups the user is in */
extern int	ngroups;	/* How many groups valid in groups */
extern struct pppd_stats link_stats; /* byte/packet counts etc. for link */
extern bool	link_stats_valid; /* set if link_stats is valid */
extern int	link_connect_time; /* time the link was up for */
extern int	using_pty;	/* using pty as device (notty or pty opt.) */
extern int	log_to_fd;	/* logging to this fd as well as syslog */
extern bool	log_to_file;	/* log_to_fd is a file */
extern bool	log_to_specific_fd;	/* log_to_fd was specified by user */
extern char	*no_ppp_msg;	/* message to print if ppp not in kernel */
extern volatile int status;	/* exit status for pppd */
extern int	devnam_fixed;	/* can no longer change devnam */
extern int	unsuccess;	/* # unsuccessful connection attempts */
extern int	do_callback;	/* set if we want to do callback next */
extern int	doing_callback;	/* set if this is a callback */
extern u_char	nak_buffer[];	/* where we construct a nak packet */
extern u_char	inpacket_buf[];	/* buffer for incoming packet */
extern bool	direct_tty;	/* use standard input directly; not a tty */
extern int	absmax_mru;	/* absolute maximum link (not i/f) MRU */
extern int	absmax_mtu;	/* absolute maximum link (not i/f) MTU */
extern int	pty_slave;	/* slave side of PTY, if any */
extern bool	early_log;	/* avoid logging to stdout */

/*
 * Values for do_callback and doing_callback.
 */
#define CALLBACK_DIALIN		1	/* we are expecting the call back */
#define CALLBACK_DIALOUT	2	/* we are dialling out to call back */

/*
 * Variables set by command-line options.
 */
extern int	debug;		/* Debug flag */
extern int	kdebugflag;	/* Tell kernel to print debug messages */
extern int	default_device;	/* Using /dev/tty or equivalent */
extern char	devnam[MAXPATHLEN];	/* Device name */
extern char	ppp_devnam[MAXPATHLEN];	/* Device name (might be pty) */
extern int	crtscts;	/* Use hardware flow control */
extern bool	modem;		/* Use modem control lines */
extern int	inspeed;	/* Input/Output speed requested */
extern u_int32_t netmask;	/* IP netmask to set on interface */
extern bool	lockflag;	/* Create lock file to lock the serial dev */
extern bool	nodetach;	/* Don't detach from controlling tty */
extern bool	updetach;	/* Detach from controlling tty when link up */
extern char	*initializer;	/* Script to initialize physical link */
extern char	*connect_script; /* Script to establish physical link */
extern char	*disconnect_script; /* Script to disestablish physical link */
extern char	*welcomer;	/* Script to welcome client after connection */
extern char	*ptycommand;	/* Command to run on other side of pty */
extern int	maxconnect;	/* Maximum connect time (seconds) */
extern char	user[MAXNAMELEN];/* Our name for authenticating ourselves */
extern char	passwd[MAXSECRETLEN];	/* Password for PAP or CHAP */
extern bool	auth_required;	/* Peer is required to authenticate */
extern bool	persist;	/* Reopen link after it goes down */
extern bool	uselogin;	/* Use /etc/passwd for checking PAP */
extern char	our_name[MAXNAMELEN];/* Our name for authentication purposes */
extern char	remote_name[MAXNAMELEN]; /* Peer's name for authentication */
extern bool	explicit_remote;/* remote_name specified with remotename opt */
extern bool	demand;		/* Do dial-on-demand */
extern char	*ipparam;	/* Extra parameter for ip up/down scripts */
extern bool	cryptpap;	/* Others' PAP passwords are encrypted */
extern int	idle_time_limit;/* Shut down link if idle for this long */
extern int	holdoff;	/* Dead time before restarting */
extern bool	holdoff_specified; /* true if user gave a holdoff value */
extern bool	notty;		/* Stdin/out is not a tty */
extern char	*pty_socket;	/* Socket to connect to pty */
extern char	*record_file;	/* File to record chars sent/received */
extern bool	sync_serial;	/* Device is synchronous serial device */
extern int	maxfail;	/* Max # of unsuccessful connection attempts */
extern char	linkname[MAXPATHLEN]; /* logical name for link */
extern bool	tune_kernel;	/* May alter kernel settings as necessary */
extern int	connect_delay;	/* Time to delay after connect script */
extern int	max_data_rate;	/* max bytes/sec through charshunt */
extern int	req_unit;	/* interface unit number to use */
extern bool	multilink;	/* enable multilink operation */
extern bool	noendpoint;	/* don't send or accept endpt. discrim. */
extern char	*bundle_name;	/* bundle name for multilink */

#ifdef HAVE_MULTILINK
extern TDB_CONTEXT *pppdb;	/* handle to multilink database context */
extern char	db_key[];	/* multilink database key */
#endif

#ifdef PPP_FILTER
extern struct	bpf_program pass_filter;   /* Filter for pkts to pass */
extern struct	bpf_program active_filter; /* Filter for link-active pkts */
#endif /* PPP_FILTER */

#ifdef MSLANMAN
extern bool	ms_lanman;	/* Use LanMan password instead of NT */
				/* Has meaning only with MS-CHAP challenges */
#endif /* MXLANMAN */

extern char *current_option;	/* the name of the option being parsed */
extern bool privileged_option;	/* set iff the current option came from root */
extern char *option_source;	/* string saying where the option came from */
extern int option_line;		/*   and from which line in the file */
extern bool already_ppp;	/* device is already in PPP mode */
extern bool prepass;		/* Doing pre-pass to find device name */
extern struct stat devstat;	/* Result of stat() on device */

extern bool peer_nak_auth;	/* Peer sent nak for our auth request */
extern u_short nak_auth_orig;	/* Auth proto peer naked */
extern u_short nak_auth_proto;	/* Auth proto peer suggested instead */
extern bool unsolicited_nak_auth; /* Peer asked us to authenticate */
extern u_short unsolicit_auth_proto; /* Auth proto peer wants */
extern bool peer_reject_auth;	/* Peer sent reject for auth */
extern u_short reject_auth_proto; /* Protocol that peer rejected */
extern bool rejected_peers_auth; /* We sent a reject to the peer */
extern u_short rejected_auth_proto; /* Protocol that peer wanted to use */
extern bool naked_peers_auth;	/* We sent a nak to the peer */
extern u_short naked_auth_orig;	/* Protocol that we wanted to use */
extern u_short naked_auth_proto; /* Protocol that peer wants us to use */

/*
 * Values for phase.
 */
#define PHASE_DEAD		0	/* RFC 1661; link terminated */
#define PHASE_INITIALIZE	1	/* execution begins */
#define PHASE_INITIALIZED	2	/* options ok; entering main loop */
#define PHASE_SERIALCONN	3	/* connecting to peer */
#define PHASE_CONNECTED		4	/* connecting to peer */
#define PHASE_DORMANT		5	/* waiting for demand-dial trigger */
#define PHASE_ESTABLISH		6	/* RFC 1661; LCP negotiation begins */
#define PHASE_AUTHENTICATE	7	/* RFC 1661; authentication begins */
#define PHASE_CALLBACK		8	/* negotiating for callback */
#define PHASE_NETWORK		9	/* RFC 1661; NCP negotiation begins */
#define PHASE_RUNNING		10	/* first NCP went to Opened state */
#define PHASE_TERMINATE		11	/* RFC 1661; LCP left Opened state */
#define PHASE_DISCONNECT	12	/* running disconnect script */
#define PHASE_HOLDOFF		13	/* waiting before restart */
#define PHASE_CALLINGBACK	14	/* calling back */
#define	PHASE_EXIT		15	/* execution ends */

#define	PHASE__NAMES \
	"Dead", "Initialize", "Initialized", "Serialconn", "Connected", \
	"Dormant", "Establish", "Authenticate", "Callback", "Network", \
	"Running", "Terminate", "Disconnect", "Holdoff", "Callingback", \
	"Exit"

/*
 * The following struct gives the addresses of procedures to call
 * for a particular protocol.
 */
struct protent {
    u_short protocol;		/* PPP protocol number */
    /* Initialization procedure */
    void (*init) __P((int unit));
    /* Process a received packet */
    void (*input) __P((int unit, u_char *pkt, int len));
    /* Process a received protocol-reject */
    void (*protrej) __P((int unit));
    /* Lower layer has come up */
    void (*lowerup) __P((int unit));
    /* Lower layer has gone down */
    void (*lowerdown) __P((int unit));
    /* Open the protocol */
    void (*open) __P((int unit));
    /* Close the protocol */
    void (*close) __P((int unit, char *reason));
    /* Print a packet in readable form */
    int  (*printpkt) __P((u_char *pkt, int len,
			  void (*printer) __P((void *, const char *, ...)),
			  void *arg));
    /* Process a received data packet */
    void (*datainput) __P((int unit, u_char *pkt, int len));
    bool enabled_flag;		/* 0 iff protocol is disabled */
    char *name;			/* Text name of protocol */
    char *data_name;		/* Text name of corresponding data protocol */
    option_t *options;		/* List of command-line options */
    /* Check requested options, assign defaults */
    void (*check_options) __P((void));
    /* Configure interface for demand-dial */
    int  (*demand_conf) __P((int unit));
    /* Say whether to bring up link for this pkt */
    int  (*active_pkt) __P((u_char *pkt, int len));
    /* Print current status to file or syslog (if strptr == NULL) */
    void (*print_stat) __P((int unit, FILE *strptr));
};

/*
 * This structure is used to store information about certain
 * options, such as where the option value came from (/etc/ppp/options,
 * command line, etc.) and whether it came from a privileged source.
 */
struct option_info {
    bool    priv;		/* was value set by sysadmin? */
    char    *source;		/* where option came from */
    int	    line;		/* line number where the option came from */
};

extern struct option_info devnam_info;
extern struct option_info initializer_info;
extern struct option_info connect_script_info;
extern struct option_info disconnect_script_info;
extern struct option_info welcomer_info;
extern struct option_info ptycommand_info;
extern struct option_info ipsrc_info;
extern struct option_info ipdst_info;
extern struct option_info speed_info;

/*
 * Table of pointers to supported protocols.
 */
extern struct protent *protocols[];

/*
 * Prototypes.
 */

/*
 * Procedures exported from main.c.
 */
extern void set_ifunit __P((int));  /* set stuff that depends on ifunit */
extern void detach __P((void));	    /* Detach from controlling tty */
extern void die __P((int));	    /* Cleanup and exit */
extern void quit __P((void));	    /* like die(1) */
extern void novm __P((char *));	    /* Say we ran out of memory, and die */
extern void timeout __P((void (*func)(void *), void *arg, int t));
				/* Call func(arg) after t seconds */
extern void untimeout __P((void (*func)(void *), void *arg));
				/* Cancel call to func(arg) */
extern pid_t run_program __P((char *prog, char **args, int must_exist,
    void (*done)(void *, int), void *arg));
				/* Run program prog with args in child */
extern void reopen_log __P((void)); /* (re)open the connection to syslog */
extern void update_link_stats __P((int)); /* Get stats at link termination */
/* set script env var */
extern void script_setenv __P((const char *, const char *, int));
extern void script_unsetenv __P((const char *));  /* unset script env var */
extern const char *script_getenv __P((const char *var));
extern void new_phase __P((int));   /* signal start of new phase */
extern void print_ncpstate __P((int, FILE *));	/* prints NCP state */
extern const char *protocol_name __P((int proto));	/* canonical name */
extern const char *phase_name __P((int phaseval));

/*
 * Procedures exported from utils.c.
 */
extern void log_packet __P((u_char *, int, const char *, int));
				/* Format a packet and log it with syslog */
extern void print_string __P((char *, int, void (*)(void *, const char *, ...),
    void *));			/* Format a string for output */
extern int slprintf __P((char *, int, const char *, ...));  /* sprintf++ */
extern int vslprintf __P((char *, int, const char *, va_list));/* vsprintf++ */
extern size_t strlcpy __P((char *, const char *, size_t));  /* safe strcpy */
extern size_t strlcat __P((char *, const char *, size_t));  /* safe strncpy */
extern void dbglog __P((const char *, ...));/* log a debug message */
extern void info __P((const char *, ...));  /* log an informational message */
extern void notice __P((const char *, ...));/* log a notice-level message */
extern void warn __P((const char *, ...));  /* log a warning message */
extern void error __P((const char *, ...)); /* log an error message */
extern void fatal __P((const char *, ...));
				/* log an error message and die(1) */
extern const char *code_name __P((int code, int shortflag));
				/* Code to string */
extern int flprintf __P((FILE *, const char *, ...));  /* fprintf++ */
extern size_t strllen __P((const char *, size_t)); /* safe strlen */
extern const char *signal_name __P((int signum));

/*
 * Procedures exported from auth.c
 */
extern void link_required __P((int));	/* we are starting to use the link */
extern void link_terminated __P((int));	/* we are finished with the link */
extern void link_down __P((int));
				/* the LCP layer has left the Opened state */
extern void link_established __P((int)); /* the link is up; authenticate now */
extern void start_networks __P((void));
				/* start all the network control protos */
extern void np_up __P((int, int));	/* a network protocol has come up */
extern void np_down __P((int, int));	/* a network protocol has gone down */
extern void np_finished __P((int, int));
				/* a network protocol no longer needs link */
extern void auth_peer_fail __P((int, int));
				/* peer failed to authenticate itself */
extern void auth_peer_success __P((int, int, char *, int));
				/* peer successfully authenticated itself */
extern void auth_withpeer_fail __P((int, int));
				/* we failed to authenticate ourselves */
extern void auth_withpeer_success __P((int, int));
				/* we successfully authenticated ourselves */
extern void auth_check_options __P((void));
				/* check authentication options supplied */
extern void auth_reset __P((int));
				/* check what secrets we have */
extern int  check_passwd __P((int, char *, int, char *, int, char **));
				/* Check peer-supplied username/password */
extern int  get_secret __P((int, char *, char *, char *, int *, int));
				/* get "secret" for chap */
extern int  auth_ip_addr __P((int, u_int32_t));
				/* check if IP address is authorized */
extern int  bad_ip_adrs __P((u_int32_t));
				/* check if IP address is unreasonable */

/*
 * Procedures exported from demand.c
 */
extern void demand_conf __P((void));
				/* config interface(s) for demand-dial */
extern void demand_block __P((void));	/* set all NPs to queue up packets */
extern void demand_unblock __P((void)); /* set all NPs to pass packets */
extern void demand_discard __P((void)); /* set all NPs to discard packets */
extern void demand_rexmit __P((int));	/* retransmit saved frames for an NP */
extern int  loop_chars __P((unsigned char *, int));
				/* process chars from loopback */
extern int  loop_frame __P((unsigned char *, int));
				/* should we bring link up? */

/*
 * Procedures exported from multilink.c
 */
extern void mp_check_options __P((void)); /* Check multilink-related options */
extern int  mp_join_bundle __P((void));
				/* join our link to an appropriate bundle */
/*
 * Procedures exported from sys-*.c
 */
extern void sys_init __P((bool));   /* Do system-dependent initialization */
extern void sys_cleanup __P((void)); /* Restore system state before exiting */
extern int  sys_check_options __P((void)); /* Check options specified */
extern void sys_options __P((void));	/* add or remove system options */
extern void sys_close __P((void));  /* Clean up in a child before execing */
extern int  ppp_available __P((void));
				/* Test whether ppp kernel support exists */
extern int  get_pty __P((int *, int *, char *, int));
				/* Get pty master/slave */
extern int  open_ppp_loopback __P((void));
				/* Open loopback for demand-dialling */
extern int  establish_ppp __P((int));
				/* Turn serial port into a ppp interface */
extern void restore_loop __P((void));
				/* Transfer ppp unit back to loopback */
extern void disestablish_ppp __P((int));
				/* Restore port to normal operation */
extern void make_new_bundle __P((int, int, int, int)); /* Create new bundle */
extern int  bundle_attach __P((int)); /* Attach link to existing bundle */
extern void cfg_bundle __P((int, int, int, int));
				/* Configure existing bundle */
extern void clean_check __P((void));	/* Check if line was 8-bit clean */
extern void set_up_tty __P((int, int));
				/* Set up port's speed, parameters, etc. */
extern void restore_tty __P((int)); /* Restore port's original parameters */
extern void setdtr __P((int, int)); /* Raise or lower port's DTR line */
extern void output __P((int, u_char *, int)); /* Output a PPP packet */
extern void wait_input __P((struct timeval *));
				/* Wait for input, with timeout */
extern void add_fd __P((int));	/* Add fd to set to wait for */
extern void remove_fd __P((int));   /* Remove fd from set to wait for */
extern int  read_packet __P((u_char *)); /* Read PPP packet */
extern int  get_loop_output __P((void)); /* Read pkts from loopback */
extern void ppp_send_config __P((int, int, u_int32_t, int, int));
				/* Configure i/f transmit parameters */
extern void ppp_set_xaccm __P((int, ext_accm));
				/* Set extended transmit ACCM */
extern void ppp_recv_config __P((int, int, u_int32_t, int, int));
				/* Configure i/f receive parameters */
#ifdef NEGOTIATE_FCS
extern void ppp_send_fcs __P((int unit, int fcstype));
extern void ppp_recv_fcs __P((int unit, int fcstype));
#endif /* NEGOTIATE_FCS */
#ifdef MUX_FRAME
extern void ppp_send_muxoption __P((int ,u_int32_t));
extern void ppp_recv_muxoption __P((int ,u_int32_t));
#endif /* MUX_FRAME */
extern int  ccp_test __P((int, u_char *, int, int));
				/* Test support for compression scheme */
#ifdef COMP_TUNE
extern void ccp_tune __P((int, int));	/* Tune compression effort level */
#endif /* COMP_TUNE */
extern void ccp_flags_set __P((int, int, int));
				/* Set kernel CCP state */
extern int ccp_fatal_error __P((int));
				/* Test for fatal decomp error in kernel */
extern int get_idle_time __P((int, struct ppp_idle *));
				/* Find out how long link has been idle */
extern int get_ppp_stats __P((int, struct pppd_stats *));
				/* Return link statistics */
extern int sifvjcomp __P((int, int, int, int));
				/* Configure VJ TCP header compression */
extern int sifup __P((int));	/* Configure i/f up for one protocol */
extern int sifnpmode __P((int u, int proto, enum NPmode mode));
				/* Set mode for handling packets for proto */
extern int sifdown __P((int));	/* Configure i/f down for one protocol */
extern int sifaddr __P((int, u_int32_t, u_int32_t, u_int32_t));
				/* Configure IPv4 addresses for i/f */
extern int cifaddr __P((int, u_int32_t, u_int32_t));
				/* Reset i/f IP addresses */

extern void sys_block_proto __P((uint16_t));
extern void sys_unblock_proto __P((uint16_t));

#ifdef INET6
extern int sif6addr __P((int, eui64_t, eui64_t));
				/* Configure IPv6 addresses for i/f */
extern int cif6addr __P((int, eui64_t, eui64_t));
				/* Remove an IPv6 address from i/f */
#endif /* INET6 */
extern int sifdefaultroute __P((int, u_int32_t, u_int32_t));
				/* Create default route through i/f */
extern int cifdefaultroute __P((int, u_int32_t, u_int32_t));
				/* Delete default route through i/f */
extern int sifproxyarp __P((int unit, u_int32_t addr, int flag));
				/* Add proxy ARP entry for peer */
extern int cifproxyarp __P((int unit, u_int32_t addr));
				/* Delete proxy ARP entry for peer */
extern u_int32_t GetMask __P((u_int32_t));
				/* Get appropriate netmask for address */
extern int lock __P((char *));	/* Create lock file for device */
extern int relock __P((int));	/* Rewrite lock file with new pid */
extern void unlock __P((void));	/* Delete previously-created lock file */
extern void logwtmp __P((const char *, const char *, const char *));
				/* Write entry to wtmp file */
extern int get_host_seed __P((void));
				/* Get host-dependent random number seed */
extern int have_route_to __P((u_int32_t)); /* Check if route to addr exists */
#ifdef PPP_FILTER
extern int set_filters __P((struct bpf_program *pass,
    struct bpf_program *active));
				/* Set filter programs in kernel */
#endif /* PPP_FILTER */
#ifdef IPX_CHANGE
extern int sipxfaddr __P((int, unsigned long, unsigned char *));
extern int cipxfaddr __P((int));
#endif /* IPX_CHANGE */
extern int get_if_hwaddr __P((u_char *addr, int msize, char *name));
extern int get_first_hwaddr __P((u_char *addr, int msize));
#if defined(INET6) && defined(SOL2)
extern int ether_to_eui64 __P((eui64_t *p_eui64));
extern int sif6up __P((int unit));
extern int sif6down __P((int unit));
extern int sif6mtu __P((int mtu));
extern int sif6flags __P((u_int32_t flags, int set));
#endif /* INET6 && SOL2*/
#if defined(INET6) && !defined(SOL2)
#define sif6up sifup
#endif
extern int sifmtu __P((int mtu));
extern int siflags __P((u_int32_t flags, int set));
extern void sys_ifname __P((void));
extern void sys_print_state __P((FILE *strptr));
extern int sys_extra_fd __P((void));

/*
 * Procedures exported from options.c
 */
extern int parse_args __P((int argc, char **argv));
	/* Parse options from arguments given */
extern int options_from_file __P((char *filename, bool must_exist,
    bool check_prot, bool privileged));
	/* Parse options from an options file */
extern int options_from_user __P((void));
	/* Parse options from user's .ppprc */
extern int options_for_tty __P((void));
	/* Parse options from /etc/ppp/options.tty */
extern int options_from_list __P((struct wordlist *, bool privileged));
	/* Parse options from a wordlist */
extern int getword __P((FILE *f, char *word, int *newlinep, char *filename));
	/* Read a word from a file */
extern void option_error __P((char *fmt, ...));
	/* Print an error message about an option */
extern int int_option __P((char *, int *));
	/* Simplified number_option for decimal ints */
extern void add_options __P((option_t *));
	/* Add extra options */
extern int parse_dotted_ip __P((char *, u_int32_t *));
	/* Parse dotted IP notation */
extern option_t *remove_option __P((char *));
	/* Remove (disable) an option */
extern void save_source __P((struct option_info *));
	/* Save the source information (where an option comes from) */
extern void set_source __P((struct option_info *));
	/* Set the source (for logging option errors detected after parsing) */
extern const char *name_source __P((struct option_info *));
	/* Return a string containing the option source and line number */

/*
 * Hooks to enable plugins to change various things.
 */
extern int (*new_phase_hook) __P((int new, int old));
extern int (*idle_time_hook) __P((struct ppp_idle *));
extern int (*holdoff_hook) __P((void));
extern int (*pap_check_hook) __P((void));
extern int (*pap_auth_hook) __P((char *user, char *passwd, char **msgp,
    struct wordlist **paddrs, struct wordlist **popts));
extern void (*pap_logout_hook) __P((void));
extern int (*pap_passwd_hook) __P((char *user, char *passwd));
extern void (*ip_up_hook) __P((void));
extern void (*ip_down_hook) __P((void));
extern int (*check_options_hook) __P((uid_t uid));
/* extern int (*attach_device_hook) __P((uid_t uid, char *devnam)); */
extern int (*updown_script_hook) __P((const char ***argsp));
struct strbuf;	/* forward declaration */
extern int (*sys_read_packet_hook) __P((int retv, struct strbuf *ctrl,
    struct strbuf *data, int flags));
extern void (*device_pipe_hook) __P((int pipefd));

/*
 * Inline versions of get/put char/short/long.
 * Pointer is advanced; we assume that both arguments
 * are lvalues and will already be in registers.
 * cp MUST be u_char *.
 */
#define GETCHAR(c, cp) { \
	(c) = *(cp)++; \
}
#define PUTCHAR(c, cp) { \
	*(cp)++ = (u_char) (c); \
}


#define GETSHORT(s, cp) { \
	(s) = *(cp)++ << 8; \
	(s) |= *(cp)++; \
}
#define PUTSHORT(s, cp) { \
	*(cp)++ = (u_char) ((s) >> 8); \
	*(cp)++ = (u_char) (s); \
}

#define GETLONG(l, cp) { \
	(l) = *(cp)++ << 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; \
}
#define PUTLONG(l, cp) { \
	*(cp)++ = (u_char) ((l) >> 24); \
	*(cp)++ = (u_char) ((l) >> 16); \
	*(cp)++ = (u_char) ((l) >> 8); \
	*(cp)++ = (u_char) (l); \
}

/*
 * For values that are kept internally in network byte order.
 */
#define GETNLONG(l, cp) { \
	u_int32_t getnlong_val; \
	getnlong_val = *(cp)++ << 8; \
	getnlong_val |= *(cp)++; getnlong_val <<= 8; \
	getnlong_val |= *(cp)++; getnlong_val <<= 8; \
	getnlong_val |= *(cp)++; \
	(l) = htonl(getnlong_val); \
}
#define PUTNLONG(l, cp) { \
	u_int32_t putnlong_val = ntohl(l); \
	*(cp)++ = (u_char) (putnlong_val >> 24); \
	*(cp)++ = (u_char) (putnlong_val >> 16); \
	*(cp)++ = (u_char) (putnlong_val >> 8); \
	*(cp)++ = (u_char) putnlong_val; \
}

#define INCPTR(n, cp)	((cp) += (n))
#define DECPTR(n, cp)	((cp) -= (n))

/*
 * System dependent definitions for user-level 4.3BSD UNIX implementation.
 */

#define TIMEOUT(r, f, t)	timeout((r), (f), (t))
#define UNTIMEOUT(r, f)		untimeout((r), (f))

#ifndef SOL2
#define BCOPY(s, d, l)		memcpy(d, s, l)
#define BZERO(s, n)		memset(s, 0, n)
#else
#include <strings.h>
#define BCOPY			bcopy
#define BZERO			bzero
#endif

#define PRINTMSG(m, l)		{ info("Remote message: %0.*v", l, m); }

/*
 * MAKEHEADER - Add Header fields to a packet.
 */
#define MAKEHEADER(p, t) { \
    PUTCHAR(PPP_ALLSTATIONS, p); \
    PUTCHAR(PPP_UI, p); \
    PUTSHORT(t, p); }

/*
 * Exit status values.
 */
#define EXIT_OK			0
#define EXIT_FATAL_ERROR	1
#define EXIT_OPTION_ERROR	2
#define EXIT_NOT_ROOT		3
#define EXIT_NO_KERNEL_SUPPORT	4
#define EXIT_USER_REQUEST	5
#define EXIT_LOCK_FAILED	6
#define EXIT_OPEN_FAILED	7
#define EXIT_CONNECT_FAILED	8
#define EXIT_PTYCMD_FAILED	9
#define EXIT_NEGOTIATION_FAILED	10
#define EXIT_PEER_AUTH_FAILED	11
#define EXIT_IDLE_TIMEOUT	12
#define EXIT_CONNECT_TIME	13
#define EXIT_CALLBACK		14
#define EXIT_PEER_DEAD		15
#define EXIT_HANGUP		16
#define EXIT_LOOPBACK		17
#define EXIT_INIT_FAILED	18
#define EXIT_AUTH_TOPEER_FAILED	19

/*
 * Character shunt constants.
 */
#define	MAXLEVELMINSIZE		100

/*
 * Debug macros.  Slightly useful for finding bugs in pppd, not particularly
 * useful for finding out why your connection isn't being established.
 */
#ifdef DEBUGALL
#define DEBUGMAIN	1
#define DEBUGSYS	1
#define DEBUGLCP	1
#define DEBUGIPCP	1
#define DEBUGIPV6CP	1
#define DEBUGCHAP	1
#define DEBUGIPXCP	1
#define LOG_PPP		LOG_LOCAL2	/* Log here when debugging all */
#endif /* DEBUGALL */

#ifndef LOG_PPP			/* we use LOG_DAEMON for syslog by default */
#define LOG_PPP LOG_DAEMON
#endif /* LOG_PPP */

#ifdef DEBUGMAIN
#define MAINDEBUG(x)	if (debug) dbglog x
#else
#define MAINDEBUG(x)	((void) 0)
#endif /* DEBUGMAIN */

#ifdef DEBUGSYS
#define SYSDEBUG(x)	if (debug) dbglog x
#else
#define SYSDEBUG(x)	((void) 0)
#endif /* DEBUGSYS */

#ifdef DEBUGLCP
#define LCPDEBUG(x)	if (debug) dbglog x
#else
#define LCPDEBUG(x)	((void) 0)
#endif /* DEBUGLCP */

#ifdef DEBUGIPCP
#define IPCPDEBUG(x)	if (debug) dbglog x
#else
#define IPCPDEBUG(x)	((void) 0)
#endif /* DEBUGIPCP */

#ifdef DEBUGIPV6CP
#define IPV6CPDEBUG(x)  if (debug) dbglog x
#else
#define IPV6CPDEBUG(x)	((void) 0)
#endif /* DEBUGIPV6CP */

#ifdef DEBUGCHAP
#define CHAPDEBUG(x)	if (debug) dbglog x
#else
#define CHAPDEBUG(x)	((void) 0)
#endif /* DEBUGCHAP */

#ifdef DEBUGIPXCP
#define IPXCPDEBUG(x)	if (debug) dbglog x
#else
#define IPXCPDEBUG(x)	((void) 0)
#endif /* DEBUGIPXCP */

#ifndef SIGTYPE
#if defined(sun) || defined(SYSV) || defined(POSIX_SOURCE)
#define SIGTYPE void
#else
#define SIGTYPE int
#endif /* defined(sun) || defined(SYSV) || defined(POSIX_SOURCE) */
#endif /* SIGTYPE */

#ifndef MIN
#define MIN(a, b)	((a) < (b)? (a): (b))
#endif /* MIN */

#ifndef MAX
#define MAX(a, b)	((a) > (b)? (a): (b))
#endif /* MAX */

#ifndef Dim
#define Dim(x)		(sizeof (x) / sizeof (*(x)))
#endif /* Dim */

#ifndef NBBY
#define NBBY 8
#endif /* NBBY */

#ifndef isset
#define isset(arr, val)	(((u_char *)(arr))[(val)/NBBY] & (1<<((val)%NBBY)))
#endif /* isset */

#ifndef setbit
#define setbit(arr, val) (((u_char *)(arr))[(val)/NBBY] |= (1<<((val)%NBBY)))
#endif /* setbit */

#define IP_HDRLEN	20	/* bytes */
#define IP_OFFMASK	0x1fff
#define TCP_HDRLEN	20

/*
 * We use these macros because the IP header may be at an odd address,
 * and some compilers might use word loads to get th_off or ip_hl.
 */

#define net_short(x)	(((x)[0] << 8) + (x)[1])
#define	native_long(x)	(htonl((net_short(x) << 16) + \
			net_short((unsigned char *)(x) + 2)))
#define get_ipv(x)	((((unsigned char *)(x))[0] >> 4) & 0xF)
#define get_iphl(x)	(((unsigned char *)(x))[0] & 0xF)
#define	get_iplen(x)	net_short((unsigned char *)(x) + 2)
#define get_ipoff(x)	net_short((unsigned char *)(x) + 6)
#define get_ipproto(x)	(((unsigned char *)(x))[9])
#define	get_ipsrc(x)	native_long((unsigned char *)(x) + 12)
#define	get_ipdst(x)	native_long((unsigned char *)(x) + 16)
#define get_ip6nh(x)	(((unsigned char *)(x))[6])
#define get_ip6src(x)	(((unsigned char *)(x))+8)
#define get_ip6dst(x)	(((unsigned char *)(x))+24)
/* Ports for both UDP and TCP are first */
#define	get_sport(x)	net_short(x)
#define	get_dport(x)	net_short((unsigned char *)(x) + 2)
#define get_tcpoff(x)	(((unsigned char *)(x))[12] >> 4)
#define get_tcpflags(x)	(((unsigned char *)(x))[13])

/* Check for RFC 1918 (local use) addresses */
#define LOCAL_IP_ADDR(addr)						  \
	(((addr) & 0xff000000) == 0x0a000000 ||		/* 10.x.x.x */	  \
	 ((addr) & 0xfff00000) == 0xac100000 ||		/* 172.16.x.x */  \
	 ((addr) & 0xffff0000) == 0xc0a80000)		/* 192.168.x.x */

#ifdef	__cplusplus
}
#endif

#endif /* __PPPD_H__ */
