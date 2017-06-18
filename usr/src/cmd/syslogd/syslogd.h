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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 1983,1984,1985,1986,1987,1988,1989  AT&T.
 * All rights reserved.
 *
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_SYSLOGD_H
#define	_SYSLOGD_H

#ifdef	__cplusplus
extern "C" {
#endif

	struct utmpx dummy;	/* for sizeof ut_user, ut_line */

/*
 * Various constants & tunable values for syslogd
 */
#define	DEBUGFILE 	"/var/adm/syslog.debug"
#define	MAXLINE		1024		/* maximum line length */
#define	DEFUPRI		(LOG_USER|LOG_INFO)
#define	DEFSPRI		(LOG_KERN|LOG_CRIT)
#define	MARKCOUNT	3		/* ratio of minor to major marks */
#define	UNAMESZ		(sizeof (dummy.ut_user)) /* length of a login name */
#define	UDEVSZ		(sizeof (dummy.ut_line)) /* length of login dev name */
#define	MAXUNAMES	20		/* maximum number of user names */
#define	Q_HIGHWATER_MARK 10000		/* max outstanding msgs per file */
#define	NOPRI		0x10		/* the "no priority" priority */
#define	LOG_MARK	(LOG_NFACILITIES << 3)	/* mark "facility" */

/*
 * host_list_t structure contains a list of hostnames for a given address
 */
typedef	struct	host_list {
	int	hl_cnt;			/* number of hl_hosts entries */
	char	**hl_hosts;		/* hostnames */
	pthread_mutex_t hl_mutex;	/* protects this structs members */
	int	hl_refcnt;		/* reference count */
} host_list_t;

/*
 * host_info_t structure contains address information for a host
 * from which we received a message.
 */
typedef struct host_info {
	struct netconfig *ncp;
	struct netbuf addr;
} host_info_t;

/*
 * statistics structure attached to each filed for debugging
 */
typedef struct filed_stats {
	int	flag;			/* flag word */
	int	total;			/* total messages logged */
	int	dups;			/* duplicate messages */
	int 	cantfwd;		/* can't forward */
	int	errs;			/* write errors */
} filed_stats_t;


/*
 * internal representation of a log message. Includes all routing & bookkeeping
 * information for the message. created in the system & network poll routines,
 * and passed among the various processing threads as necessary
 */

typedef struct log_message {
	pthread_mutex_t msg_mutex;	/* protects this structs members */
	int refcnt;			/* message reference count */
	int pri;			/* message priority */
	int flags;			/* misc flags */
	time_t ts;			/* timestamp */
	host_list_t *hlp;		/* ptr to host list struct */
	void *ptr;			/* for anonymous use */
	char msg[MAXLINE+1];		/* the message itself */
} log_message_t;

/*
 * format of a saved message. For each active file we are logging
 * we save the last message and the current message, to make it
 * possible to suppress duplicates on a per file basis. Earlier
 * syslogd's used a global buffer for duplicate checking, so
 * strict per file duplicate suppression was not always possible.
 */
typedef struct saved_msg {
	int pri;
	int flags;
	time_t time;
	char host[SYS_NMLN+1];
	char msg[MAXLINE+1];
} saved_message_t;


/*
 * Flags to logmsg().
 */

#define	IGN_CONS	0x001		/* don't print on console */
#define	IGN_FILE	0x002		/* don't write to log file */
#define	SYNC_FILE	0x004		/* do fsync on file after printing */
#define	NOCOPY		0x008		/* don't suppress duplicate messages */
#define	ADDDATE		0x010		/* add a date to the message */
#define	MARK		0x020		/* this message is a mark */
#define	LOGSYNC		0x040		/* nightly log update message */
#define	NETWORK		0x100		/* message came from the net */
#define	SHUTDOWN	0x200		/* internal shutdown message */
#define	FLUSHMSG	0x400		/* internal flush message */

/*
 * This structure represents the files that will have log
 * copies printed.  There is one instance of this for each
 * file that is being logged to.
 */
struct filed {
	pthread_mutex_t filed_mutex;	/* protects this filed */
	pthread_t f_thread;		/* thread that handles this file */
	dataq_t f_queue;		/* queue of messages for this file */
	int f_queue_count;		/* count of messages on the queue */
	int f_prev_queue_count;		/* prev count of msgs on the queue */
	short	f_type;			/* entry type, see below */
	short	f_orig_type;		/* save entry type */
	int	f_file;			/* file descriptor */
	int	f_msgflag;		/* message disposition */
	filed_stats_t f_stat;		/* statistics */
	saved_message_t f_prevmsg;	/* previous message */
	saved_message_t f_current;	/* current message */
	int	f_prevcount;		/* message repeat count */
	uchar_t	f_pmask[LOG_NFACILITIES+1];	/* priority mask */
	union {
		char	f_uname[MAXUNAMES][SYS_NMLN + 1];
		struct {
			char	f_hname[SYS_NMLN + 1];
			struct netbuf	f_addr;
		} f_forw;		/* forwarding address */
		char	f_fname[MAXPATHLEN + 1];
	} f_un;
};

/* values for f_type */
#define	F_UNUSED	0		/* unused entry */
#define	F_FILE		1		/* regular file */
#define	F_TTY		2		/* terminal */
#define	F_CONSOLE	3		/* console terminal */
#define	F_FORW		4		/* remote machine */
#define	F_USERS		5		/* list of users */
#define	F_WALL		6		/* everyone logged on */

/*
 * values for logit routine
 */
#define	CURRENT		0		/* print current message */
#define	SAVED		1		/* print saved message */
/*
 * values for f_msgflag
 */
#define	CURRENT_VALID	0x01		/* new message is good */
#define	OLD_VALID	0x02		/* old message is valid */

/*
 * code translation struct for use in processing config file
 */
struct code {
	char	*c_name;
	int	c_val;
};

/*
 * structure describing a message to be sent to the wall thread.
 * the thread id and attributes are stored in the structure
 * passed to the thread, and the thread is created detached.
 */
typedef struct wall_device {
	pthread_t thread;
	pthread_attr_t thread_attr;
	char dev[PATH_MAX + 1];
	char msg[MAXLINE+1];
	char ut_name[sizeof (dummy.ut_name)];
} walldev_t;

/*
 * hostname caching struct to reduce hostname name lookup.
 */
struct hostname_cache {
	struct hostname_cache *next;
	struct netbuf addr;
	struct netconfig *ncp;
	host_list_t *h;
	time_t expire;
};

#define	DEF_HNC_SIZE	2037
#define	DEF_HNC_TTL	1200	/* 20 minutes */
#define	MAX_BUCKETS	30

/*
 * function prototypes
 */
int main(int argc, char **argv);
static void usage(void);
static void untty(void);
static void formatnet(struct netbuf *nbp, log_message_t *mp);
static void formatsys(struct log_ctl *lp, char *msg, int sync);
static void *logmsg(void *ap);
static void wallmsg(struct filed *f, char *from, char *msg);
static host_list_t *cvthname(struct netbuf *nbp, struct netconfig *ncp, char *);
static void set_flush_msg(struct filed *f);
static void flushmsg(int flags);
void logerror(const char *type, ...);
static void init(void);
static void conf_init(void);
static void cfline(char *line, int lineno, struct filed *f);
static int decode(char *name, struct code *codetab);
static int ismyaddr(struct netbuf *nbp);
static void getnets(void);
static int addnet(struct netconfig *ncp, struct netbuf *nbp);
static void bindnet(void);
static int logforward(struct filed *f, char *ebuf, size_t elen);
static int amiloghost(void);
static int same_addr(struct netbuf *, struct netbuf *);
static void prepare_sys_poll(void);
static void *sys_poll(void *ap);
static void getkmsg(int);
static void *net_poll(void *ap);
static log_message_t *new_msg(void);
static void free_msg(log_message_t *lm);
static int logmymsg(int pri, char *msg, int flags, int);
static void *logit(void *ap);
static void freehl(host_list_t *h);
static int filed_init(struct filed *h);
static void copy_msg(struct filed *f);
static void dumpstats(int fd);
static void filter_string(char *orig, char *new, size_t max);
static int openklog(char *name, int mode);
static void writemsg(int selection, struct filed *f);
static void *writetodev(void *ap);
static int shutdown_msg(void);
static void server(void *, char *, size_t, door_desc_t *, uint_t);
static void *create_door_thr(void *);
static void door_server_pool(door_info_t *);
static char *alloc_stacks(int);
static void dealloc_stacks(int);
static int checkm4(void);
static void filed_destroy(struct filed *f);
static void open_door(void);
static void close_door(void);
static void delete_doorfiles(void);
static void signull(int, siginfo_t *, void *);
static int putctrlc(int, char **, size_t *, size_t);
static size_t findnl_bkwd(const char *, const size_t);
static size_t copynl_frwd(char *, const size_t, const char *, const size_t);
static size_t copy_frwd(char *, const size_t, const char *, const size_t);
static void logerror_format(const char *, char *, va_list);
static int logerror_to_console(int, const char *);
static void properties(void);
static void shutdown_input(void);
static void *hostname_lookup(void *);
static void reconfigure(void);
static void disable_errorlog(void);
static void enable_errorlog(void);

static void hnc_init(int);
static host_list_t *hnc_lookup(struct netbuf *,
		    struct netconfig *, int *);
static void hnc_register(struct netbuf *,
		    struct netconfig *, host_list_t *, int);
static void hnc_unreg(struct hostname_cache **);
static int addr_hash(struct netbuf *nbp);


#ifdef	__cplusplus
}
#endif

#endif /* _SYSLOGD_H */
