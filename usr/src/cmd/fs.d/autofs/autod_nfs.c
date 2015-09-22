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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <syslog.h>
#include <string.h>
#include <deflt.h>
#include <kstat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/signal.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/fstyp.h>
#include <sys/fsid.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netconfig.h>
#include <netdir.h>
#include <errno.h>
#define	NFSCLIENT
#include <nfs/nfs.h>
#include <nfs/mount.h>
#include <rpcsvc/mount.h>
#include <rpc/nettype.h>
#include <locale.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <thread.h>
#include <limits.h>
#include <nss_dbdefs.h>			/* for NSS_BUFLEN_HOSTS */
#include <nfs/nfs_sec.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <assert.h>
#include <nfs/nfs_clnt.h>
#include <rpcsvc/nfs4_prot.h>
#include <nfs/nfs4.h>
#define	NO_RDDIR_CACHE
#include "automount.h"
#include "replica.h"
#include "nfs_subr.h"
#include "webnfs.h"
#include "nfs_resolve.h"
#include <sys/sockio.h>
#include <net/if.h>
#include <rpcsvc/daemon_utils.h>
#include <pwd.h>
#include <strings.h>
#include <tsol/label.h>
#include <zone.h>
#include <limits.h>
#include <libscf.h>
#include <libshare.h>
#include "smfcfg.h"

extern void set_nfsv4_ephemeral_mount_to(void);

extern char *nfs_get_qop_name();
extern AUTH *nfs_create_ah();
extern enum snego_stat nfs_sec_nego();

#define	MAXHOSTS	512

/*
 * host cache states
 */
#define	NOHOST		0
#define	GOODHOST	1
#define	DEADHOST	2

#define	NFS_ARGS_EXTB_secdata(args, secdata) \
	{ (args).nfs_args_ext = NFS_ARGS_EXTB, \
	(args).nfs_ext_u.nfs_extB.secdata = secdata; }

struct cache_entry {
	struct	cache_entry *cache_next;
	char	*cache_host;
	time_t	cache_time;
	int	cache_state;
	rpcvers_t cache_reqvers;
	rpcvers_t cache_outvers;
	char	*cache_proto;
};

struct mfs_snego_t {
	int sec_opt;
	bool_t snego_done;
	char *nfs_flavor;
	seconfig_t nfs_sec;
};
typedef struct mfs_snego_t mfs_snego_t;

static struct cache_entry *cache_head = NULL;
rwlock_t cache_lock;	/* protect the cache chain */

static enum nfsstat nfsmount(struct mapfs *, char *, char *, int, uid_t,
	action_list *);
static int is_nfs_port(char *);

static void netbuf_free(struct netbuf *);
static int get_pathconf(CLIENT *, char *, char *, struct pathcnf **, int);
static struct mapfs *enum_servers(struct mapent *, char *);
static struct mapfs *get_mysubnet_servers(struct mapfs *);
static int subnet_test(int af, struct sioc_addrreq *);
static	struct	netbuf *get_addr(char *, rpcprog_t, rpcvers_t,
	struct netconfig **, char *, ushort_t, struct t_info *);

static	struct	netbuf *get_pubfh(char *, rpcvers_t, mfs_snego_t *,
	struct netconfig **, char *, ushort_t, struct t_info *, caddr_t *,
	bool_t, char *);

static int create_homedir(const char *, const char *);

enum type_of_stuff {
	SERVER_ADDR = 0,
	SERVER_PING = 1,
	SERVER_FH = 2
};

static void *get_server_netinfo(enum type_of_stuff, char *, rpcprog_t,
	rpcvers_t, mfs_snego_t *, struct netconfig **, char *, ushort_t,
	struct t_info *, caddr_t *, bool_t, char *, enum clnt_stat *);
static void *get_netconfig_info(enum type_of_stuff, char *, rpcprog_t,
	rpcvers_t, struct netconfig *, ushort_t, struct t_info *,
	struct t_bind *, caddr_t *, bool_t, char *, enum clnt_stat *,
	mfs_snego_t *);
static void *get_server_addrorping(char *, rpcprog_t, rpcvers_t,
	struct netconfig *, ushort_t, struct t_info *, struct t_bind *,
	caddr_t *, bool_t, char *, enum clnt_stat *, int);
static void *get_server_fh(char *, rpcprog_t, rpcvers_t, mfs_snego_t *,
	struct netconfig *, ushort_t, struct t_info *, struct t_bind *,
	caddr_t *, bool_t, char *, enum clnt_stat *);

struct mapfs *add_mfs(struct mapfs *, int, struct mapfs **, struct mapfs **);
void free_mfs(struct mapfs *);
static void dump_mfs(struct mapfs *, char *, int);
static char *dump_distance(struct mapfs *);
static void cache_free(struct cache_entry *);
static int cache_check(char *, rpcvers_t *, char *);
static void cache_enter(char *, rpcvers_t, rpcvers_t, char *, int);
void destroy_auth_client_handle(CLIENT *cl);

#ifdef CACHE_DEBUG
static void trace_host_cache();
static void trace_portmap_cache();
#endif /* CACHE_DEBUG */

static int rpc_timeout = 20;

#ifdef CACHE_DEBUG
/*
 * host cache counters. These variables do not need to be protected
 * by mutex's. They have been added to measure the utility of the
 * goodhost/deadhost cache in the lazy hierarchical mounting scheme.
 */
static int host_cache_accesses = 0;
static int host_cache_lookups = 0;
static int deadhost_cache_hits = 0;
static int goodhost_cache_hits = 0;

/*
 * portmap cache counters. These variables do not need to be protected
 * by mutex's. They have been added to measure the utility of the portmap
 * cache in the lazy hierarchical mounting scheme.
 */
static int portmap_cache_accesses = 0;
static int portmap_cache_lookups = 0;
static int portmap_cache_hits = 0;
#endif /* CACHE_DEBUG */

/*
 * There are the defaults (range) for the client when determining
 * which NFS version to use when probing the server (see above).
 * These will only be used when the vers mount option is not used and
 * these may be reset if /etc/default/nfs is configured to do so.
 */
static rpcvers_t vers_max_default = NFS_VERSMAX_DEFAULT;
static rpcvers_t vers_min_default = NFS_VERSMIN_DEFAULT;

/*
 * list of support services needed
 */
static char	*service_list[] = { STATD, LOCKD, NULL };
static char	*service_list_v4[] = { STATD, LOCKD, NFS4CBD, NFSMAPID, NULL };

static void read_default_nfs(void);
static int is_v4_mount(char *);
static void start_nfs4cbd(void);

int
mount_nfs(
	struct mapent *me,
	char *mntpnt,
	char *prevhost,
	int overlay,
	uid_t uid,
	action_list **alpp)
{
	struct mapfs *mfs, *mp;
	int err = -1;
	action_list *alp;
	char *dir;


	alp = *alpp;

	read_default_nfs();

	mfs = enum_servers(me, prevhost);
	if (mfs == NULL)
		return (ENOENT);

	/*
	 * Try loopback if we have something on localhost; if nothing
	 * works, we will fall back to NFS
	 */
	if (is_nfs_port(me->map_mntopts)) {
		for (mp = mfs; mp; mp = mp->mfs_next) {
			if (self_check(mp->mfs_host)) {
				err = loopbackmount(mp->mfs_dir,
				    mntpnt, me->map_mntopts, overlay);
				if (err) {
					mp->mfs_ignore = 1;
				} else {
					/*
					 * Free action_list if there
					 * is one as it is not needed.
					 * Make sure to set alpp to null
					 * so caller doesn't try to free it
					 * again.
					 */
					if (*alpp) {
						free(*alpp);
						*alpp = NULL;
					}
					break;
				}
			}
		}
	}
	if (err) {
		dir = strdup(mfs->mfs_dir);
		err = nfsmount(mfs, mntpnt, me->map_mntopts,
		    overlay, uid, alp);
		if (err && trace > 1) {
			trace_prt(1, "  Couldn't mount %s:%s, err=%d\n",
			    mfs->mfs_host ? mfs->mfs_host : "",
			    mfs->mfs_dir ? mfs->mfs_dir : dir, err);
		}
		free(dir);
	}
	free_mfs(mfs);
	return (err);
}


/*
 * Using the new ioctl SIOCTONLINK to determine if a host is on the same
 * subnet. Remove the old network, subnet check.
 */

static struct mapfs *
get_mysubnet_servers(struct mapfs *mfs_in)
{
	int s;
	struct mapfs *mfs, *p, *mfs_head = NULL, *mfs_tail = NULL;

	struct netconfig *nconf;
	NCONF_HANDLE *nc = NULL;
	struct nd_hostserv hs;
	struct nd_addrlist *retaddrs;
	struct netbuf *nb;
	struct sioc_addrreq areq;
	int res;
	int af;
	int i;
	int sa_size;

	hs.h_serv = "rpcbind";

	for (mfs = mfs_in; mfs; mfs = mfs->mfs_next) {
		nc = setnetconfig();

		while (nconf = getnetconfig(nc)) {

			/*
			 * Care about INET family only. proto_done flag
			 * indicates if we have already covered this
			 * protocol family. If so skip it
			 */
			if (((strcmp(nconf->nc_protofmly, NC_INET6) == 0) ||
			    (strcmp(nconf->nc_protofmly, NC_INET) == 0)) &&
			    (nconf->nc_semantics == NC_TPI_CLTS)) {
			} else
				continue;

			hs.h_host = mfs->mfs_host;

			if (netdir_getbyname(nconf, &hs, &retaddrs) != ND_OK)
				continue;

			/*
			 * For each host address see if it's on our
			 * local subnet.
			 */

			if (strcmp(nconf->nc_protofmly, NC_INET6) == 0)
				af = AF_INET6;
			else
				af = AF_INET;
			nb = retaddrs->n_addrs;
			for (i = 0; i < retaddrs->n_cnt; i++, nb++) {
				memset(&areq.sa_addr, 0, sizeof (areq.sa_addr));
				memcpy(&areq.sa_addr, nb->buf, MIN(nb->len,
				    sizeof (areq.sa_addr)));
				if (res = subnet_test(af, &areq)) {
					p = add_mfs(mfs, DIST_MYNET,
					    &mfs_head, &mfs_tail);
					if (!p) {
						netdir_free(retaddrs,
						    ND_ADDRLIST);
						endnetconfig(nc);
						return (NULL);
					}
					break;
				}
			}  /* end of every host */
			if (trace > 2) {
				trace_prt(1, "get_mysubnet_servers: host=%s "
				    "netid=%s res=%s\n", mfs->mfs_host,
				    nconf->nc_netid, res == 1?"SUC":"FAIL");
			}

			netdir_free(retaddrs, ND_ADDRLIST);
		} /* end of while */

		endnetconfig(nc);

	} /* end of every map */

	return (mfs_head);

}

int
subnet_test(int af, struct sioc_addrreq *areq)
{
	int s;

	if ((s = socket(af, SOCK_DGRAM, 0)) < 0) {
		return (0);
	}

	areq->sa_res = -1;

	if (ioctl(s, SIOCTONLINK, (caddr_t)areq) < 0) {
		syslog(LOG_ERR, "subnet_test:SIOCTONLINK failed");
		return (0);
	}
	close(s);
	if (areq->sa_res == 1)
		return (1);
	else
		return (0);


}

/*
 * ping a bunch of hosts at once and sort by who responds first
 */
static struct mapfs *
sort_servers(struct mapfs *mfs_in, int timeout)
{
	struct mapfs *m1 = NULL;
	enum clnt_stat clnt_stat;

	if (!mfs_in)
		return (NULL);

	clnt_stat = nfs_cast(mfs_in, &m1, timeout);

	if (!m1) {
		char buff[2048] = {'\0'};

		for (m1 = mfs_in; m1; m1 = m1->mfs_next) {
			(void) strcat(buff, m1->mfs_host);
			if (m1->mfs_next)
				(void) strcat(buff, ",");
		}

		syslog(LOG_ERR, "servers %s not responding: %s",
		    buff, clnt_sperrno(clnt_stat));
	}

	return (m1);
}

/*
 * Add a mapfs entry to the list described by *mfs_head and *mfs_tail,
 * provided it is not marked "ignored" and isn't a dupe of ones we've
 * already seen.
 */
struct mapfs *
add_mfs(struct mapfs *mfs, int distance, struct mapfs **mfs_head,
	struct mapfs **mfs_tail)
{
	struct mapfs *tmp, *new;

	for (tmp = *mfs_head; tmp; tmp = tmp->mfs_next)
		if ((strcmp(tmp->mfs_host, mfs->mfs_host) == 0 &&
		    strcmp(tmp->mfs_dir, mfs->mfs_dir) == 0) ||
		    mfs->mfs_ignore)
			return (*mfs_head);
	new = (struct mapfs *)malloc(sizeof (struct mapfs));
	if (!new) {
		syslog(LOG_ERR, "Memory allocation failed: %m");
		return (NULL);
	}
	bcopy(mfs, new, sizeof (struct mapfs));
	new->mfs_next = NULL;
	if (distance)
		new->mfs_distance = distance;
	if (!*mfs_head)
		*mfs_tail = *mfs_head = new;
	else {
		(*mfs_tail)->mfs_next = new;
		*mfs_tail = new;
	}
	return (*mfs_head);
}

static void
dump_mfs(struct mapfs *mfs, char *message, int level)
{
	struct mapfs *m1;

	if (trace <= level)
		return;

	trace_prt(1, "%s", message);
	if (!mfs) {
		trace_prt(0, "mfs is null\n");
		return;
	}
	for (m1 = mfs; m1; m1 = m1->mfs_next)
		trace_prt(0, "%s[%s] ", m1->mfs_host, dump_distance(m1));
	trace_prt(0, "\n");
}

static char *
dump_distance(struct mapfs *mfs)
{
	switch (mfs->mfs_distance) {
	case 0:			return ("zero");
	case DIST_SELF:		return ("self");
	case DIST_MYSUB:	return ("mysub");
	case DIST_MYNET:	return ("mynet");
	case DIST_OTHER:	return ("other");
	default:		return ("other");
	}
}

/*
 * Walk linked list "raw", building a new list consisting of members
 * NOT found in list "filter", returning the result.
 */
static struct mapfs *
filter_mfs(struct mapfs *raw, struct mapfs *filter)
{
	struct mapfs *mfs, *p, *mfs_head = NULL, *mfs_tail = NULL;
	int skip;

	if (!raw)
		return (NULL);
	for (mfs = raw; mfs; mfs = mfs->mfs_next) {
		for (skip = 0, p = filter; p; p = p->mfs_next) {
			if (strcmp(p->mfs_host, mfs->mfs_host) == 0 &&
			    strcmp(p->mfs_dir, mfs->mfs_dir) == 0) {
				skip = 1;
				break;
			}
		}
		if (skip)
			continue;
		p = add_mfs(mfs, 0, &mfs_head, &mfs_tail);
		if (!p)
			return (NULL);
	}
	return (mfs_head);
}

/*
 * Walk a linked list of mapfs structs, freeing each member.
 */
void
free_mfs(struct mapfs *mfs)
{
	struct mapfs *tmp;

	while (mfs) {
		tmp = mfs->mfs_next;
		free(mfs);
		mfs = tmp;
	}
}

/*
 * New code for NFS client failover: we need to carry and sort
 * lists of server possibilities rather than return a single
 * entry.  It preserves previous behaviour of sorting first by
 * locality (loopback-or-preferred/subnet/net/other) and then
 * by ping times.  We'll short-circuit this process when we
 * have ENOUGH or more entries.
 */
static struct mapfs *
enum_servers(struct mapent *me, char *preferred)
{
	struct mapfs *p, *m1, *m2, *mfs_head = NULL, *mfs_tail = NULL;

	/*
	 * Short-circuit for simple cases.
	 */
	if (!me->map_fs->mfs_next) {
		p = add_mfs(me->map_fs, DIST_OTHER, &mfs_head, &mfs_tail);
		if (!p)
			return (NULL);
		return (mfs_head);
	}

	dump_mfs(me->map_fs, "	enum_servers: mapent: ", 2);

	/*
	 * get addresses & see if any are myself
	 * or were mounted from previously in a
	 * hierarchical mount.
	 */
	if (trace > 2)
		trace_prt(1, "	enum_servers: looking for pref/self\n");
	for (m1 = me->map_fs; m1; m1 = m1->mfs_next) {
		if (m1->mfs_ignore)
			continue;
		if (self_check(m1->mfs_host) ||
		    strcmp(m1->mfs_host, preferred) == 0) {
			p = add_mfs(m1, DIST_SELF, &mfs_head, &mfs_tail);
			if (!p)
				return (NULL);
		}
	}
	if (trace > 2 && m1)
		trace_prt(1, "	enum_servers: pref/self found, %s\n",
		    m1->mfs_host);

	/*
	 * look for entries on this subnet
	 */
	dump_mfs(m1, "	enum_servers: input of get_mysubnet_servers: ", 2);
	m1 = get_mysubnet_servers(me->map_fs);
	dump_mfs(m1, "	enum_servers: output of get_mysubnet_servers: ", 3);
	if (m1 && m1->mfs_next) {
		m2 = sort_servers(m1, rpc_timeout / 2);
		dump_mfs(m2, "	enum_servers: output of sort_servers: ", 3);
		free_mfs(m1);
		m1 = m2;
	}

	for (m2 = m1; m2; m2 = m2->mfs_next) {
		p = add_mfs(m2, 0, &mfs_head, &mfs_tail);
		if (!p)
			return (NULL);
	}
	if (m1)
		free_mfs(m1);

	/*
	 * add the rest of the entries at the end
	 */
	m1 = filter_mfs(me->map_fs, mfs_head);
	dump_mfs(m1, "	enum_servers: etc: output of filter_mfs: ", 3);
	m2 = sort_servers(m1, rpc_timeout / 2);
	dump_mfs(m2, "	enum_servers: etc: output of sort_servers: ", 3);
	if (m1)
		free_mfs(m1);
	m1 = m2;
	for (m2 = m1; m2; m2 = m2->mfs_next) {
		p = add_mfs(m2, DIST_OTHER, &mfs_head, &mfs_tail);
		if (!p)
			return (NULL);
	}
	if (m1)
		free_mfs(m1);

done:
	dump_mfs(mfs_head, "  enum_servers: output: ", 1);
	return (mfs_head);
}

static enum nfsstat
nfsmount(
	struct mapfs *mfs_in,
	char *mntpnt, char *opts,
	int overlay,
	uid_t uid,
	action_list *alp)
{
	CLIENT *cl;
	char remname[MAXPATHLEN], *mnttabtext = NULL;
	char mopts[MAX_MNTOPT_STR];
	char netname[MAXNETNAMELEN+1];
	char	*mntopts = NULL;
	int mnttabcnt = 0;
	int loglevel;
	struct mnttab m;
	struct nfs_args *argp = NULL, *head = NULL, *tail = NULL,
	    *prevhead, *prevtail;
	int flags;
	struct fhstatus fhs;
	struct timeval timeout;
	enum clnt_stat rpc_stat;
	enum nfsstat status;
	struct stat stbuf;
	struct netconfig *nconf;
	rpcvers_t vers, versmin; /* used to negotiate nfs version in pingnfs */
				/* and mount version with mountd */
	rpcvers_t outvers;	/* final version to be used during mount() */
	rpcvers_t nfsvers;	/* version in map options, 0 if not there */
	rpcvers_t mountversmax;	/* tracks the max mountvers during retries */

	/* used to negotiate nfs version using webnfs */
	rpcvers_t pubvers, pubversmin, pubversmax;
	int posix;
	struct nd_addrlist *retaddrs;
	struct mountres3 res3;
	nfs_fh3 fh3;
	char *fstype;
	int count, i;
	char scerror_msg[MAXMSGLEN];
	int *auths;
	int delay;
	int retries;
	char *nfs_proto = NULL;
	uint_t nfs_port = 0;
	char *p, *host, *rhost, *dir;
	struct mapfs *mfs = NULL;
	int error, last_error = 0;
	int replicated;
	int entries = 0;
	int v2cnt = 0, v3cnt = 0, v4cnt = 0;
	int v2near = 0, v3near = 0, v4near = 0;
	int skipentry = 0;
	char *nfs_flavor;
	seconfig_t nfs_sec;
	int sec_opt, scerror;
	struct sec_data *secdata;
	int secflags;
	struct netbuf *syncaddr;
	bool_t	use_pubfh;
	ushort_t thisport;
	int got_val;
	mfs_snego_t mfssnego_init, mfssnego;

	dump_mfs(mfs_in, "  nfsmount: input: ", 2);
	replicated = (mfs_in->mfs_next != NULL);
	m.mnt_mntopts = opts;
	if (replicated && hasmntopt(&m, MNTOPT_SOFT)) {
		if (verbose)
			syslog(LOG_WARNING,
		    "mount on %s is soft and will not be replicated.", mntpnt);
		replicated = 0;
	}
	if (replicated && !hasmntopt(&m, MNTOPT_RO)) {
		if (verbose)
			syslog(LOG_WARNING,
		    "mount on %s is not read-only and will not be replicated.",
			    mntpnt);
		replicated = 0;
	}
	if (replicated)
		loglevel = LOG_WARNING;
	else
		loglevel = LOG_ERR;

	if (trace > 1) {
		if (replicated)
			trace_prt(1, "	nfsmount: replicated mount on %s %s:\n",
			    mntpnt, opts);
		else
			trace_prt(1, "	nfsmount: standard mount on %s %s:\n",
			    mntpnt, opts);
		for (mfs = mfs_in; mfs; mfs = mfs->mfs_next)
			trace_prt(1, "	  %s:%s\n",
			    mfs->mfs_host, mfs->mfs_dir);
	}

	/*
	 * Make sure mountpoint is safe to mount on
	 */
	if (lstat(mntpnt, &stbuf) < 0) {
		syslog(LOG_ERR, "Couldn't stat %s: %m", mntpnt);
		return (NFSERR_NOENT);
	}

	/*
	 * Get protocol specified in options list, if any.
	 */
	if ((str_opt(&m, "proto", &nfs_proto)) == -1) {
		return (NFSERR_NOENT);
	}

	/*
	 * Get port specified in options list, if any.
	 */
	got_val = nopt(&m, MNTOPT_PORT, (int *)&nfs_port);
	if (!got_val)
		nfs_port = 0;	/* "unspecified" */
	if (nfs_port > USHRT_MAX) {
		syslog(LOG_ERR, "%s: invalid port number %d", mntpnt, nfs_port);
		return (NFSERR_NOENT);
	}

	/*
	 * Set mount(2) flags here, outside of the loop.
	 */
	flags = MS_OPTIONSTR;
	flags |= (hasmntopt(&m, MNTOPT_RO) == NULL) ? 0 : MS_RDONLY;
	flags |= (hasmntopt(&m, MNTOPT_NOSUID) == NULL) ? 0 : MS_NOSUID;
	flags |= overlay ? MS_OVERLAY : 0;
	if (mntpnt[strlen(mntpnt) - 1] != ' ')
		/* direct mount point without offsets */
		flags |= MS_OVERLAY;

	use_pubfh = (hasmntopt(&m, MNTOPT_PUBLIC) == NULL) ? FALSE : TRUE;

	(void) memset(&mfssnego_init, 0, sizeof (mfs_snego_t));
	if (hasmntopt(&m, MNTOPT_SECURE) != NULL) {
		if (++mfssnego_init.sec_opt > 1) {
			syslog(loglevel,
			    "conflicting security options");
			return (NFSERR_IO);
		}
		if (nfs_getseconfig_byname("dh", &mfssnego_init.nfs_sec)) {
			syslog(loglevel,
			    "error getting dh information from %s",
			    NFSSEC_CONF);
			return (NFSERR_IO);
		}
	}

	if (hasmntopt(&m, MNTOPT_SEC) != NULL) {
		if ((str_opt(&m, MNTOPT_SEC,
		    &mfssnego_init.nfs_flavor)) == -1) {
			syslog(LOG_ERR, "nfsmount: no memory");
			return (NFSERR_IO);
		}
	}

	if (mfssnego_init.nfs_flavor) {
		if (++mfssnego_init.sec_opt > 1) {
			syslog(loglevel,
			    "conflicting security options");
			free(mfssnego_init.nfs_flavor);
			return (NFSERR_IO);
		}
		if (nfs_getseconfig_byname(mfssnego_init.nfs_flavor,
		    &mfssnego_init.nfs_sec)) {
			syslog(loglevel,
			    "error getting %s information from %s",
			    mfssnego_init.nfs_flavor, NFSSEC_CONF);
			free(mfssnego_init.nfs_flavor);
			return (NFSERR_IO);
		}
		free(mfssnego_init.nfs_flavor);
	}

nextentry:
	skipentry = 0;

	got_val = nopt(&m, MNTOPT_VERS, (int *)&nfsvers);
	if (!got_val)
		nfsvers = 0;	/* "unspecified" */
	if (set_versrange(nfsvers, &vers, &versmin) != 0) {
		syslog(LOG_ERR, "Incorrect NFS version specified for %s",
		    mntpnt);
		last_error = NFSERR_NOENT;
		goto ret;
	}

	if (nfsvers != 0) {
		pubversmax = pubversmin = nfsvers;
	} else {
		pubversmax = vers;
		pubversmin = versmin;
	}

	/*
	 * Walk the whole list, pinging and collecting version
	 * info so that we can make sure the mount will be
	 * homogeneous with respect to version.
	 *
	 * If we have a version preference, this is easy; we'll
	 * just reject anything that doesn't match.
	 *
	 * If not, we want to try to provide the best compromise
	 * that considers proximity, preference for a higher version,
	 * sorted order, and number of replicas.  We will count
	 * the number of V2 and V3 replicas and also the number
	 * which are "near", i.e. the localhost or on the same
	 * subnet.
	 */
	for (mfs = mfs_in; mfs; mfs = mfs->mfs_next) {


		if (mfs->mfs_ignore)
			continue;

		/*
		 * If the host is '[a:d:d:r:e:s:s'],
		 * only use 'a:d:d:r:e:s:s' for communication
		 */
		host = strdup(mfs->mfs_host);
		if (host == NULL) {
			syslog(LOG_ERR, "nfsmount: no memory");
			last_error = NFSERR_IO;
			goto out;
		}
		unbracket(&host);

		(void) memcpy(&mfssnego, &mfssnego_init, sizeof (mfs_snego_t));

		if (use_pubfh == TRUE || mfs->mfs_flags & MFS_URL) {
			char *path;

			if (nfs_port != 0 && mfs->mfs_port != 0 &&
			    nfs_port != mfs->mfs_port) {

				syslog(LOG_ERR, "nfsmount: port (%u) in nfs URL"
				    " not the same as port (%d) in port "
				    "option\n", mfs->mfs_port, nfs_port);
				last_error = NFSERR_IO;
				goto out;

			} else if (nfs_port != 0)
				thisport = nfs_port;
			else
				thisport = mfs->mfs_port;

			dir = mfs->mfs_dir;

			if ((mfs->mfs_flags & MFS_URL) == 0) {
				path = malloc(strlen(dir) + 2);
				if (path == NULL) {
					syslog(LOG_ERR, "nfsmount: no memory");
					last_error = NFSERR_IO;
					goto out;
				}
				path[0] = (char)WNL_NATIVEPATH;
				(void) strcpy(&path[1], dir);
			} else {
				path = dir;
			}

			argp = (struct nfs_args *)
			    malloc(sizeof (struct nfs_args));

			if (!argp) {
				if (path != dir)
					free(path);
				syslog(LOG_ERR, "nfsmount: no memory");
				last_error = NFSERR_IO;
				goto out;
			}
			(void) memset(argp, 0, sizeof (*argp));

			/*
			 * RDMA support
			 * By now Mount argument struct has been allocated,
			 * either a pub_fh path will be taken or the regular
			 * one. So here if a protocol was specified and it
			 * was not rdma we let it be, else we set DO_RDMA.
			 * If no proto was there we advise on trying RDMA.
			 */
			if (nfs_proto) {
				if (strcmp(nfs_proto, "rdma") == 0) {
					free(nfs_proto);
					nfs_proto = NULL;
					argp->flags |= NFSMNT_DORDMA;
				}
			} else
				argp->flags |= NFSMNT_TRYRDMA;

			for (pubvers = pubversmax; pubvers >= pubversmin;
			    pubvers--) {

				nconf = NULL;
				argp->addr = get_pubfh(host, pubvers, &mfssnego,
				    &nconf, nfs_proto, thisport, NULL,
				    &argp->fh, TRUE, path);

				if (argp->addr != NULL)
					break;

				if (nconf != NULL)
					freenetconfigent(nconf);
			}

			if (path != dir)
				free(path);

			if (argp->addr != NULL) {

				/*
				 * The use of llock option for NFSv4
				 * mounts is not required since file
				 * locking is included within the protocol
				 */
				if (pubvers != NFS_V4)
					argp->flags |= NFSMNT_LLOCK;

				argp->flags |= NFSMNT_PUBLIC;

				vers = pubvers;
				mfs->mfs_args = argp;
				mfs->mfs_version = pubvers;
				mfs->mfs_nconf = nconf;
				mfs->mfs_flags |= MFS_FH_VIA_WEBNFS;

			} else {
				free(argp);

				/*
				 * If -public was specified, give up
				 * on this entry now.
				 */
				if (use_pubfh == TRUE) {
					syslog(loglevel,
					    "%s: no public file handle support",
					    host);
					last_error = NFSERR_NOENT;
					mfs->mfs_ignore = 1;
					continue;
				}

				/*
				 * Back off to a conventional mount.
				 *
				 * URL's can contain escape characters. Get
				 * rid of them.
				 */
				path = malloc(strlen(dir) + 2);

				if (path == NULL) {
					syslog(LOG_ERR, "nfsmount: no memory");
					last_error = NFSERR_IO;
					goto out;
				}

				strcpy(path, dir);
				URLparse(path);
				mfs->mfs_dir = path;
				mfs->mfs_flags |= MFS_ALLOC_DIR;
				mfs->mfs_flags &= ~MFS_URL;
			}
		}

		if ((mfs->mfs_flags & MFS_FH_VIA_WEBNFS) ==  0) {
			i = pingnfs(host, get_retry(opts) + 1, &vers, versmin,
			    0, FALSE, NULL, nfs_proto);
			if (i != RPC_SUCCESS) {
				if (i == RPC_PROGVERSMISMATCH) {
					syslog(loglevel, "server %s: NFS "
					    "protocol version mismatch",
					    host);
				} else {
					syslog(loglevel, "server %s not "
					    "responding", host);
				}
				mfs->mfs_ignore = 1;
				last_error = NFSERR_NOENT;
				continue;
			}
			if (nfsvers != 0 && nfsvers != vers) {
				if (nfs_proto == NULL)
					syslog(loglevel,
					    "NFS version %d "
					    "not supported by %s",
					    nfsvers, host);
				else
					syslog(loglevel,
					    "NFS version %d "
					    "with proto %s "
					    "not supported by %s",
					    nfsvers, nfs_proto, host);
				mfs->mfs_ignore = 1;
				last_error = NFSERR_NOENT;
				continue;
			}
		}

		free(host);

		switch (vers) {
		case NFS_V4: v4cnt++; break;
		case NFS_V3: v3cnt++; break;
		case NFS_VERSION: v2cnt++; break;
		default: break;
		}

		/*
		 * It's not clear how useful this stuff is if
		 * we are using webnfs across the internet, but it
		 * can't hurt.
		 */
		if (mfs->mfs_distance &&
		    mfs->mfs_distance <= DIST_MYSUB) {
			switch (vers) {
			case NFS_V4: v4near++; break;
			case NFS_V3: v3near++; break;
			case NFS_VERSION: v2near++; break;
			default: break;
			}
		}

		/*
		 * If the mount is not replicated, we don't want to
		 * ping every entry, so we'll stop here.  This means
		 * that we may have to go back to "nextentry" above
		 * to consider another entry if we can't get
		 * all the way to mount(2) with this one.
		 */
		if (!replicated)
			break;

	}

	if (nfsvers == 0) {
		/*
		 * Choose the NFS version.
		 * We prefer higher versions, but will choose a one-
		 * version downgrade in service if we can use a local
		 * network interface and avoid a router.
		 */
		if (v4cnt && v4cnt >= v3cnt && (v4near || !v3near))
			nfsvers = NFS_V4;
		else if (v3cnt && v3cnt >= v2cnt && (v3near || !v2near))
			nfsvers = NFS_V3;
		else
			nfsvers = NFS_VERSION;
		if (trace > 2)
			trace_prt(1,
		    "  nfsmount: v4=%d[%d]v3=%d[%d],v2=%d[%d] => v%d.\n",
			    v4cnt, v4near, v3cnt, v3near,
			    v2cnt, v2near, nfsvers);
	}

	/*
	 * Since we don't support different NFS versions in replicated
	 * mounts, set fstype now.
	 * Also take the opportunity to set
	 * the mount protocol version as appropriate.
	 */
	switch (nfsvers) {
	case NFS_V4:
		fstype = MNTTYPE_NFS4;
		break;
	case NFS_V3:
		fstype = MNTTYPE_NFS3;
		if (use_pubfh == FALSE) {
			mountversmax = MOUNTVERS3;
			versmin = MOUNTVERS3;
		}
		break;
	case NFS_VERSION:
		fstype = MNTTYPE_NFS;
		if (use_pubfh == FALSE) {
			mountversmax = MOUNTVERS_POSIX;
			versmin = MOUNTVERS;
		}
		break;
	}

	/*
	 * Our goal here is to evaluate each of several possible
	 * replicas and try to come up with a list we can hand
	 * to mount(2).  If we don't have a valid "head" at the
	 * end of this process, it means we have rejected all
	 * potential server:/path tuples.  We will fail quietly
	 * in front of mount(2), and will have printed errors
	 * where we found them.
	 * XXX - do option work outside loop w careful design
	 * XXX - use macro for error condition free handling
	 */
	for (mfs = mfs_in; mfs; mfs = mfs->mfs_next) {

		/*
		 * Initialize retry and delay values on a per-server basis.
		 */
		retries = get_retry(opts);
		delay = INITDELAY;
retry:
		if (mfs->mfs_ignore)
			continue;

		/*
		 * If we don't have a fh yet, and if this is not a replicated
		 * mount, we haven't done a pingnfs() on the next entry,
		 * so we don't know if the next entry is up or if it
		 * supports an NFS version we like.  So if we had a problem
		 * with an entry, we need to go back and run through some new
		 * code.
		 */
		if ((mfs->mfs_flags & MFS_FH_VIA_WEBNFS) == 0 &&
		    !replicated && skipentry)
			goto nextentry;

		vers = mountversmax;
		host = mfs->mfs_host;
		dir = mfs->mfs_dir;

		/*
		 * Remember the possible '[a:d:d:r:e:s:s]' as the address to be
		 * later passed to mount(2) and used in the mnttab line, but
		 * only use 'a:d:d:r:e:s:s' for communication
		 */
		rhost = strdup(host);
		if (rhost == NULL) {
			syslog(LOG_ERR, "nfsmount: no memory");
			last_error = NFSERR_IO;
			goto out;
		}
		unbracket(&host);

		(void) sprintf(remname, "%s:%s", rhost, dir);
		if (trace > 4 && replicated)
			trace_prt(1, "	nfsmount: examining %s\n", remname);

		if (mfs->mfs_args == NULL) {

			/*
			 * Allocate nfs_args structure
			 */
			argp = (struct nfs_args *)
			    malloc(sizeof (struct nfs_args));

			if (!argp) {
				syslog(LOG_ERR, "nfsmount: no memory");
				last_error = NFSERR_IO;
				goto out;
			}

			(void) memset(argp, 0, sizeof (*argp));

			/*
			 * RDMA support
			 * By now Mount argument struct has been allocated,
			 * either a pub_fh path will be taken or the regular
			 * one. So here if a protocol was specified and it
			 * was not rdma we let it be, else we set DO_RDMA.
			 * If no proto was there we advise on trying RDMA.
			 */
			if (nfs_proto) {
				if (strcmp(nfs_proto, "rdma") == 0) {
					free(nfs_proto);
					nfs_proto = NULL;
					argp->flags |= NFSMNT_DORDMA;
				}
			} else
				argp->flags |= NFSMNT_TRYRDMA;
		} else {
			argp = mfs->mfs_args;
			mfs->mfs_args = NULL;

			/*
			 * Skip entry if we already have file handle but the
			 * NFS version is wrong.
			 */
			if ((mfs->mfs_flags & MFS_FH_VIA_WEBNFS) &&
			    mfs->mfs_version != nfsvers) {

				free(argp);
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			}
		}

		prevhead = head;
		prevtail = tail;
		if (!head)
			head = tail = argp;
		else
			tail = tail->nfs_ext_u.nfs_extB.next = argp;

		/*
		 * WebNFS and NFSv4 behave similarly in that they
		 * don't use the mount protocol.  Therefore, avoid
		 * mount protocol like things when version 4 is being
		 * used.
		 */
		if ((mfs->mfs_flags & MFS_FH_VIA_WEBNFS) == 0 &&
		    nfsvers != NFS_V4) {
			timeout.tv_usec = 0;
			timeout.tv_sec = rpc_timeout;
			rpc_stat = RPC_TIMEDOUT;

			/* Create the client handle. */

			if (trace > 1) {
				trace_prt(1,
				    "  nfsmount: Get mount version: request "
				    "vers=%d min=%d\n", vers, versmin);
			}

			while ((cl = clnt_create_vers(host, MOUNTPROG, &outvers,
			    versmin, vers, "udp")) == NULL) {
				if (trace > 4) {
					trace_prt(1,
					    "  nfsmount: Can't get mount "
					    "version: rpcerr=%d\n",
					    rpc_createerr.cf_stat);
				}
				if (rpc_createerr.cf_stat == RPC_UNKNOWNHOST ||
				    rpc_createerr.cf_stat == RPC_TIMEDOUT)
					break;

			/*
			 * backoff and return lower version to retry the ping.
			 * XXX we should be more careful and handle
			 * RPC_PROGVERSMISMATCH here, because that error
			 * is handled in clnt_create_vers(). It's not done to
			 * stay in sync with the nfs mount command.
			 */
				vers--;
				if (vers < versmin)
					break;
				if (trace > 4) {
					trace_prt(1,
					    "  nfsmount: Try version=%d\n",
					    vers);
				}
			}

			if (cl == NULL) {
				free(argp);
				head = prevhead;
				tail = prevtail;
				if (tail)
					tail->nfs_ext_u.nfs_extB.next = NULL;
				last_error = NFSERR_NOENT;

				if (rpc_createerr.cf_stat != RPC_UNKNOWNHOST &&
				    rpc_createerr.cf_stat !=
				    RPC_PROGVERSMISMATCH &&
				    retries-- > 0) {
					DELAY(delay);
					goto retry;
				}

				syslog(loglevel, "%s %s", host,
				    clnt_spcreateerror(
				    "server not responding"));
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			}
			if (trace > 1) {
				trace_prt(1,
				    "	nfsmount: mount version=%d\n", outvers);
			}
#ifdef MALLOC_DEBUG
			add_alloc("CLNT_HANDLE", cl, 0, __FILE__, __LINE__);
			add_alloc("AUTH_HANDLE", cl->cl_auth, 0,
			    __FILE__, __LINE__);
#endif

			if (__clnt_bindresvport(cl) < 0) {
				free(argp);
				head = prevhead;
				tail = prevtail;
				if (tail)
					tail->nfs_ext_u.nfs_extB.next = NULL;
				last_error = NFSERR_NOENT;

				if (retries-- > 0) {
					destroy_auth_client_handle(cl);
					DELAY(delay);
					goto retry;
				}

				syslog(loglevel, "mount %s: %s", host,
				    "Couldn't bind to reserved port");
				destroy_auth_client_handle(cl);
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			}

#ifdef MALLOC_DEBUG
			drop_alloc("AUTH_HANDLE", cl->cl_auth,
			    __FILE__, __LINE__);
#endif
			AUTH_DESTROY(cl->cl_auth);
			if ((cl->cl_auth = authsys_create_default()) == NULL) {
				free(argp);
				head = prevhead;
				tail = prevtail;
				if (tail)
					tail->nfs_ext_u.nfs_extB.next = NULL;
				last_error = NFSERR_NOENT;

				if (retries-- > 0) {
					destroy_auth_client_handle(cl);
					DELAY(delay);
					goto retry;
				}

				syslog(loglevel, "mount %s: %s", host,
				    "Failed creating default auth handle");
				destroy_auth_client_handle(cl);
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			}
#ifdef MALLOC_DEBUG
			add_alloc("AUTH_HANDLE", cl->cl_auth, 0,
			    __FILE__, __LINE__);
#endif
		} else
			cl = NULL;

		/*
		 * set security options
		 */
		sec_opt = 0;
		(void) memset(&nfs_sec, 0, sizeof (nfs_sec));
		if (hasmntopt(&m, MNTOPT_SECURE) != NULL) {
			if (++sec_opt > 1) {
				syslog(loglevel,
				    "conflicting security options for %s",
				    remname);
				free(argp);
				head = prevhead;
				tail = prevtail;
				if (tail)
					tail->nfs_ext_u.nfs_extB.next = NULL;
				last_error = NFSERR_IO;
				destroy_auth_client_handle(cl);
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			}
			if (nfs_getseconfig_byname("dh", &nfs_sec)) {
				syslog(loglevel,
				    "error getting dh information from %s",
				    NFSSEC_CONF);
				free(argp);
				head = prevhead;
				tail = prevtail;
				if (tail)
					tail->nfs_ext_u.nfs_extB.next = NULL;
				last_error = NFSERR_IO;
				destroy_auth_client_handle(cl);
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			}
		}

		nfs_flavor = NULL;
		if (hasmntopt(&m, MNTOPT_SEC) != NULL) {
			if ((str_opt(&m, MNTOPT_SEC, &nfs_flavor)) == -1) {
				syslog(LOG_ERR, "nfsmount: no memory");
				last_error = NFSERR_IO;
				destroy_auth_client_handle(cl);
				goto out;
			}
		}

		if (nfs_flavor) {
			if (++sec_opt > 1) {
				syslog(loglevel,
				    "conflicting security options for %s",
				    remname);
				free(nfs_flavor);
				free(argp);
				head = prevhead;
				tail = prevtail;
				if (tail)
					tail->nfs_ext_u.nfs_extB.next = NULL;
				last_error = NFSERR_IO;
				destroy_auth_client_handle(cl);
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			}
			if (nfs_getseconfig_byname(nfs_flavor, &nfs_sec)) {
				syslog(loglevel,
				    "error getting %s information from %s",
				    nfs_flavor, NFSSEC_CONF);
				free(nfs_flavor);
				free(argp);
				head = prevhead;
				tail = prevtail;
				if (tail)
					tail->nfs_ext_u.nfs_extB.next = NULL;
				last_error = NFSERR_IO;
				destroy_auth_client_handle(cl);
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			}
			free(nfs_flavor);
		}

		posix = (nfsvers != NFS_V4 &&
		    hasmntopt(&m, MNTOPT_POSIX) != NULL) ? 1 : 0;

		if ((mfs->mfs_flags & MFS_FH_VIA_WEBNFS) == 0 &&
		    nfsvers != NFS_V4) {
			bool_t give_up_on_mnt;
			bool_t got_mnt_error;
		/*
		 * If we started with a URL, if first byte of path is not "/",
		 * then the mount will likely fail, so we should try again
		 * with a prepended "/".
		 */
			if (mfs->mfs_flags & MFS_ALLOC_DIR && *dir != '/')
				give_up_on_mnt = FALSE;
			else
				give_up_on_mnt = TRUE;

			got_mnt_error = FALSE;

try_mnt_slash:
			if (got_mnt_error == TRUE) {
				int i, l;

				give_up_on_mnt = TRUE;
				l = strlen(dir);

				/*
				 * Insert a "/" to front of mfs_dir.
				 */
				for (i = l; i > 0; i--)
					dir[i] = dir[i-1];

				dir[0] = '/';
			}

			/* Get fhandle of remote path from server's mountd */

			switch (outvers) {
			case MOUNTVERS:
				if (posix) {
					free(argp);
					head = prevhead;
					tail = prevtail;
					if (tail)
						tail->nfs_ext_u.nfs_extB.next =
						    NULL;
					last_error = NFSERR_NOENT;
					syslog(loglevel,
					    "can't get posix info for %s",
					    host);
					destroy_auth_client_handle(cl);
					skipentry = 1;
					mfs->mfs_ignore = 1;
					continue;
				}
		    /* FALLTHRU */
			case MOUNTVERS_POSIX:
				if (nfsvers == NFS_V3) {
					free(argp);
					head = prevhead;
					tail = prevtail;
					if (tail)
						tail->nfs_ext_u.nfs_extB.next =
						    NULL;
					last_error = NFSERR_NOENT;
					syslog(loglevel,
					    "%s doesn't support NFS Version 3",
					    host);
					destroy_auth_client_handle(cl);
					skipentry = 1;
					mfs->mfs_ignore = 1;
					continue;
				}
				rpc_stat = clnt_call(cl, MOUNTPROC_MNT,
				    xdr_dirpath, (caddr_t)&dir,
				    xdr_fhstatus, (caddr_t)&fhs, timeout);
				if (rpc_stat != RPC_SUCCESS) {

					if (give_up_on_mnt == FALSE) {
						got_mnt_error = TRUE;
						goto try_mnt_slash;
					}

				/*
				 * Given the way "clnt_sperror" works, the "%s"
				 * immediately following the "not responding"
				 * is correct.
				 */
					free(argp);
					head = prevhead;
					tail = prevtail;
					if (tail)
						tail->nfs_ext_u.nfs_extB.next =
						    NULL;
					last_error = NFSERR_NOENT;

					if (retries-- > 0) {
						destroy_auth_client_handle(cl);
						DELAY(delay);
						goto retry;
					}

					if (trace > 3) {
						trace_prt(1,
						    "  nfsmount: mount RPC "
						    "failed for %s\n",
						    host);
					}
					syslog(loglevel,
					    "%s server not responding%s",
					    host, clnt_sperror(cl, ""));
					destroy_auth_client_handle(cl);
					skipentry = 1;
					mfs->mfs_ignore = 1;
					continue;
				}
				if ((errno = fhs.fhs_status) != MNT_OK)  {

					if (give_up_on_mnt == FALSE) {
						got_mnt_error = TRUE;
						goto try_mnt_slash;
					}

					free(argp);
					head = prevhead;
					tail = prevtail;
					if (tail)
						tail->nfs_ext_u.nfs_extB.next =
						    NULL;
					if (errno == EACCES) {
						status = NFSERR_ACCES;
					} else {
						syslog(loglevel, "%s: %m",
						    host);
						status = NFSERR_IO;
					}
					if (trace > 3) {
						trace_prt(1,
						    "  nfsmount: mount RPC gave"
						    " %d for %s:%s\n",
						    errno, host, dir);
					}
					last_error = status;
					destroy_auth_client_handle(cl);
					skipentry = 1;
					mfs->mfs_ignore = 1;
					continue;
				}
				argp->fh = malloc((sizeof (fhandle)));
				if (!argp->fh) {
					syslog(LOG_ERR, "nfsmount: no memory");
					last_error = NFSERR_IO;
					destroy_auth_client_handle(cl);
					goto out;
				}
				(void) memcpy(argp->fh,
				    &fhs.fhstatus_u.fhs_fhandle,
				    sizeof (fhandle));
				break;
			case MOUNTVERS3:
				posix = 0;
				(void) memset((char *)&res3, '\0',
				    sizeof (res3));
				rpc_stat = clnt_call(cl, MOUNTPROC_MNT,
				    xdr_dirpath, (caddr_t)&dir,
				    xdr_mountres3, (caddr_t)&res3, timeout);
				if (rpc_stat != RPC_SUCCESS) {

					if (give_up_on_mnt == FALSE) {
						got_mnt_error = TRUE;
						goto try_mnt_slash;
					}

				/*
				 * Given the way "clnt_sperror" works, the "%s"
				 * immediately following the "not responding"
				 * is correct.
				 */
					free(argp);
					head = prevhead;
					tail = prevtail;
					if (tail)
						tail->nfs_ext_u.nfs_extB.next =
						    NULL;
					last_error = NFSERR_NOENT;

					if (retries-- > 0) {
						destroy_auth_client_handle(cl);
						DELAY(delay);
						goto retry;
					}

					if (trace > 3) {
						trace_prt(1,
						    "  nfsmount: mount RPC "
						    "failed for %s\n",
						    host);
					}
					syslog(loglevel,
					    "%s server not responding%s",
					    remname, clnt_sperror(cl, ""));
					destroy_auth_client_handle(cl);
					skipentry = 1;
					mfs->mfs_ignore = 1;
					continue;
				}
				if ((errno = res3.fhs_status) != MNT_OK)  {

					if (give_up_on_mnt == FALSE) {
						got_mnt_error = TRUE;
						goto try_mnt_slash;
					}

					free(argp);
					head = prevhead;
					tail = prevtail;
					if (tail)
						tail->nfs_ext_u.nfs_extB.next =
						    NULL;
					if (errno == EACCES) {
						status = NFSERR_ACCES;
					} else {
						syslog(loglevel, "%s: %m",
						    remname);
						status = NFSERR_IO;
					}
					if (trace > 3) {
						trace_prt(1,
						    "  nfsmount: mount RPC gave"
						    " %d for %s:%s\n",
						    errno, host, dir);
					}
					last_error = status;
					destroy_auth_client_handle(cl);
					skipentry = 1;
					mfs->mfs_ignore = 1;
					continue;
				}

			/*
			 *  Negotiate the security flavor for nfs_mount
			 */
				auths = res3.mountres3_u.mountinfo.
				    auth_flavors.auth_flavors_val;
				count = res3.mountres3_u.mountinfo.
				    auth_flavors.auth_flavors_len;

				if (sec_opt) {
					for (i = 0; i < count; i++)
						if (auths[i] ==
						    nfs_sec.sc_nfsnum) {
							break;
						}
					if (i >= count) {
						syslog(LOG_ERR,
						    "%s: does not support "
						    "security \"%s\"\n",
						    remname, nfs_sec.sc_name);
						clnt_freeres(cl, xdr_mountres3,
						    (caddr_t)&res3);
						free(argp);
						head = prevhead;
						tail = prevtail;
						if (tail)
							tail->nfs_ext_u.
							    nfs_extB.next =
							    NULL;
						last_error = NFSERR_IO;
						destroy_auth_client_handle(cl);
						skipentry = 1;
						mfs->mfs_ignore = 1;
						continue;
					}
				} else if (count > 0) {
					for (i = 0; i < count; i++) {
						if (!(scerror =
						    nfs_getseconfig_bynumber(
						    auths[i], &nfs_sec))) {
							sec_opt++;
							break;
						}
					}
					if (i >= count) {
						if (nfs_syslog_scerr(scerror,
						    scerror_msg)
						    != -1) {
							syslog(LOG_ERR,
							    "%s cannot be "
							    "mounted because it"
							    " is shared with "
							    "security flavor %d"
							    " which %s",
							    remname,
							    auths[i-1],
							    scerror_msg);
						}
						clnt_freeres(cl, xdr_mountres3,
						    (caddr_t)&res3);
						free(argp);
						head = prevhead;
						tail = prevtail;
						if (tail)
							tail->nfs_ext_u.
							    nfs_extB.next =
							    NULL;
						last_error = NFSERR_IO;
						destroy_auth_client_handle(cl);
						skipentry = 1;
						mfs->mfs_ignore = 1;
						continue;
						}
				}

				fh3.fh3_length =
				    res3.mountres3_u.mountinfo.fhandle.
				    fhandle3_len;
				(void) memcpy(fh3.fh3_u.data,
				    res3.mountres3_u.mountinfo.fhandle.
				    fhandle3_val,
				    fh3.fh3_length);
				clnt_freeres(cl, xdr_mountres3,
				    (caddr_t)&res3);
				argp->fh = malloc(sizeof (nfs_fh3));
				if (!argp->fh) {
					syslog(LOG_ERR, "nfsmount: no memory");
					last_error = NFSERR_IO;
					destroy_auth_client_handle(cl);
					goto out;
				}
				(void) memcpy(argp->fh, &fh3, sizeof (nfs_fh3));
				break;
			default:
				free(argp);
				head = prevhead;
				tail = prevtail;
				if (tail)
					tail->nfs_ext_u.nfs_extB.next = NULL;
				last_error = NFSERR_NOENT;
				syslog(loglevel,
				    "unknown MOUNT version %ld on %s",
				    vers, remname);
				destroy_auth_client_handle(cl);
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			} /* switch */
		}
		if (nfsvers == NFS_V4) {
			argp->fh = strdup(dir);
			if (argp->fh == NULL) {
				syslog(LOG_ERR, "nfsmount: no memory");
				last_error = NFSERR_IO;
				goto out;
			}
		}

		if (trace > 4)
			trace_prt(1, "	nfsmount: have %s filehandle for %s\n",
			    fstype, remname);

		argp->flags |= NFSMNT_NEWARGS;
		argp->flags |= NFSMNT_INT;	/* default is "intr" */
		argp->flags |= NFSMNT_HOSTNAME;
		argp->hostname = strdup(host);
		if (argp->hostname == NULL) {
			syslog(LOG_ERR, "nfsmount: no memory");
			last_error = NFSERR_IO;
			goto out;
		}

		/*
		 * In this case, we want NFSv4 to behave like
		 * non-WebNFS so that we get the server address.
		 */
		if ((mfs->mfs_flags & MFS_FH_VIA_WEBNFS) == 0) {
			nconf = NULL;

			if (nfs_port != 0)
				thisport = nfs_port;
			else
				thisport = mfs->mfs_port;

			/*
			 * For NFSv4, we want to avoid rpcbind, so call
			 * get_server_netinfo() directly to tell it that
			 * we want to go "direct_to_server".  Otherwise,
			 * do what has always been done.
			 */
			if (nfsvers == NFS_V4) {
				enum clnt_stat cstat;

				argp->addr = get_server_netinfo(SERVER_ADDR,
				    host, NFS_PROGRAM, nfsvers, NULL,
				    &nconf, nfs_proto, thisport, NULL,
				    NULL, TRUE, NULL, &cstat);
			} else {
				argp->addr = get_addr(host, NFS_PROGRAM,
				    nfsvers, &nconf, nfs_proto,
				    thisport, NULL);
			}

			if (argp->addr == NULL) {
				if (argp->hostname)
					free(argp->hostname);
				free(argp->fh);
				free(argp);
				head = prevhead;
				tail = prevtail;
				if (tail)
					tail->nfs_ext_u.nfs_extB.next = NULL;
				last_error = NFSERR_NOENT;

				if (retries-- > 0) {
					destroy_auth_client_handle(cl);
					DELAY(delay);
					goto retry;
				}

				syslog(loglevel, "%s: no NFS service", host);
				destroy_auth_client_handle(cl);
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			}
			if (trace > 4)
				trace_prt(1,
				    "\tnfsmount: have net address for %s\n",
				    remname);

		} else {
			nconf = mfs->mfs_nconf;
			mfs->mfs_nconf = NULL;
		}

		argp->flags |= NFSMNT_KNCONF;
		argp->knconf = get_knconf(nconf);
		if (argp->knconf == NULL) {
			netbuf_free(argp->addr);
			freenetconfigent(nconf);
			if (argp->hostname)
				free(argp->hostname);
			free(argp->fh);
			free(argp);
			head = prevhead;
			tail = prevtail;
			if (tail)
				tail->nfs_ext_u.nfs_extB.next = NULL;
			last_error = NFSERR_NOSPC;
			destroy_auth_client_handle(cl);
			skipentry = 1;
			mfs->mfs_ignore = 1;
			continue;
		}
		if (trace > 4)
			trace_prt(1,
			    "\tnfsmount: have net config for %s\n",
			    remname);

		if (hasmntopt(&m, MNTOPT_SOFT) != NULL) {
			argp->flags |= NFSMNT_SOFT;
		}
		if (hasmntopt(&m, MNTOPT_NOINTR) != NULL) {
			argp->flags &= ~(NFSMNT_INT);
		}
		if (hasmntopt(&m, MNTOPT_NOAC) != NULL) {
			argp->flags |= NFSMNT_NOAC;
		}
		if (hasmntopt(&m, MNTOPT_NOCTO) != NULL) {
			argp->flags |= NFSMNT_NOCTO;
		}
		if (hasmntopt(&m, MNTOPT_FORCEDIRECTIO) != NULL) {
			argp->flags |= NFSMNT_DIRECTIO;
		}
		if (hasmntopt(&m, MNTOPT_NOFORCEDIRECTIO) != NULL) {
			argp->flags &= ~(NFSMNT_DIRECTIO);
		}

		/*
		 * Set up security data for argp->nfs_ext_u.nfs_extB.secdata.
		 */
		if (mfssnego.snego_done) {
			memcpy(&nfs_sec, &mfssnego.nfs_sec,
			    sizeof (seconfig_t));
		} else if (!sec_opt) {
			/*
			 * Get default security mode.
			 */
			if (nfs_getseconfig_default(&nfs_sec)) {
				syslog(loglevel,
				    "error getting default security entry\n");
				free_knconf(argp->knconf);
				netbuf_free(argp->addr);
				freenetconfigent(nconf);
				if (argp->hostname)
					free(argp->hostname);
				free(argp->fh);
				free(argp);
				head = prevhead;
				tail = prevtail;
				if (tail)
					tail->nfs_ext_u.nfs_extB.next = NULL;
				last_error = NFSERR_NOSPC;
				destroy_auth_client_handle(cl);
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			}
			argp->flags |= NFSMNT_SECDEFAULT;
		}

		/*
		 * For AUTH_DH
		 * get the network address for the time service on
		 * the server.	If an RPC based time service is
		 * not available then try the IP time service.
		 *
		 * Eventurally, we want to move this code to nfs_clnt_secdata()
		 * when autod_nfs.c and mount.c can share the same
		 * get_the_addr/get_netconfig_info routine.
		 */
		secflags = 0;
		syncaddr = NULL;
		retaddrs = NULL;

		if (nfs_sec.sc_rpcnum == AUTH_DH || nfsvers == NFS_V4) {
		/*
		 * If not using the public fh and not NFS_V4, we can try
		 * talking RPCBIND. Otherwise, assume that firewalls
		 * prevent us from doing that.
		 */
			if ((mfs->mfs_flags & MFS_FH_VIA_WEBNFS) == 0 &&
			    nfsvers != NFS_V4) {
				enum clnt_stat cstat;
				syncaddr = get_server_netinfo(SERVER_ADDR,
				    host, RPCBPROG, RPCBVERS, NULL, &nconf,
				    NULL, 0, NULL, NULL, FALSE, NULL, &cstat);
			}

			if (syncaddr != NULL) {
				/* for flags in sec_data */
				secflags |= AUTH_F_RPCTIMESYNC;
			} else {
				struct nd_hostserv hs;
				int error;

				hs.h_host = host;
				hs.h_serv = "timserver";
				error = netdir_getbyname(nconf, &hs, &retaddrs);

				if (error != ND_OK &&
				    nfs_sec.sc_rpcnum == AUTH_DH) {
					syslog(loglevel,
					    "%s: secure: no time service\n",
					    host);
					free_knconf(argp->knconf);
					netbuf_free(argp->addr);
					freenetconfigent(nconf);
					if (argp->hostname)
						free(argp->hostname);
					free(argp->fh);
					free(argp);
					head = prevhead;
					tail = prevtail;
					if (tail)
						tail->nfs_ext_u.nfs_extB.next =
						    NULL;
					last_error = NFSERR_IO;
					destroy_auth_client_handle(cl);
					skipentry = 1;
					mfs->mfs_ignore = 1;
					continue;
				}

				if (error == ND_OK)
					syncaddr = retaddrs->n_addrs;

			/*
			 * For potential usage by NFS V4 when AUTH_DH
			 * is negotiated via SECINFO in the kernel.
			 */
				if (nfsvers == NFS_V4 && syncaddr &&
				    host2netname(netname, host, NULL)) {
					argp->syncaddr =
					    malloc(sizeof (struct netbuf));
					argp->syncaddr->buf =
					    malloc(syncaddr->len);
					(void) memcpy(argp->syncaddr->buf,
					    syncaddr->buf, syncaddr->len);
					argp->syncaddr->len = syncaddr->len;
					argp->syncaddr->maxlen =
					    syncaddr->maxlen;
					argp->netname = strdup(netname);
					argp->flags |= NFSMNT_SECURE;
				}
			} /* syncaddr */
		} /* AUTH_DH */

		/*
		 * TSOL notes: automountd in tsol extension
		 * has "read down" capability, i.e. we allow
		 * a user to trigger an nfs mount into a lower
		 * labeled zone. We achieve this by always having
		 * root issue the mount request so that the
		 * lookup ops can go past /zone/<zone_name>
		 * on the server side.
		 */
		if (is_system_labeled())
			nfs_sec.sc_uid = (uid_t)0;
		else
			nfs_sec.sc_uid = uid;
		/*
		 * If AUTH_DH is a chosen flavor now, its data will be stored
		 * in the sec_data structure via nfs_clnt_secdata().
		 */
		if (!(secdata = nfs_clnt_secdata(&nfs_sec, host, argp->knconf,
		    syncaddr, secflags))) {
			syslog(LOG_ERR,
			    "errors constructing security related data\n");
			if (secflags & AUTH_F_RPCTIMESYNC)
				netbuf_free(syncaddr);
			else if (retaddrs)
				netdir_free(retaddrs, ND_ADDRLIST);
			if (argp->syncaddr)
				netbuf_free(argp->syncaddr);
			if (argp->netname)
				free(argp->netname);
			if (argp->hostname)
				free(argp->hostname);
			free_knconf(argp->knconf);
			netbuf_free(argp->addr);
			freenetconfigent(nconf);
			free(argp->fh);
			free(argp);
			head = prevhead;
			tail = prevtail;
			if (tail)
				tail->nfs_ext_u.nfs_extB.next = NULL;
			last_error = NFSERR_IO;
			destroy_auth_client_handle(cl);
			skipentry = 1;
			mfs->mfs_ignore = 1;
			continue;
		}
		NFS_ARGS_EXTB_secdata(*argp, secdata);
		/* end of security stuff */

		if (trace > 4)
			trace_prt(1,
			    "  nfsmount: have secure info for %s\n", remname);

		if (hasmntopt(&m, MNTOPT_GRPID) != NULL) {
			argp->flags |= NFSMNT_GRPID;
		}
		if (nopt(&m, MNTOPT_RSIZE, &argp->rsize)) {
			argp->flags |= NFSMNT_RSIZE;
		}
		if (nopt(&m, MNTOPT_WSIZE, &argp->wsize)) {
			argp->flags |= NFSMNT_WSIZE;
		}
		if (nopt(&m, MNTOPT_TIMEO, &argp->timeo)) {
			argp->flags |= NFSMNT_TIMEO;
		}
		if (nopt(&m, MNTOPT_RETRANS, &argp->retrans)) {
			argp->flags |= NFSMNT_RETRANS;
		}
		if (nopt(&m, MNTOPT_ACTIMEO, &argp->acregmax)) {
			argp->flags |= NFSMNT_ACREGMAX;
			argp->flags |= NFSMNT_ACDIRMAX;
			argp->flags |= NFSMNT_ACDIRMIN;
			argp->flags |= NFSMNT_ACREGMIN;
			argp->acdirmin = argp->acregmin = argp->acdirmax
			    = argp->acregmax;
		} else {
			if (nopt(&m, MNTOPT_ACREGMIN, &argp->acregmin)) {
				argp->flags |= NFSMNT_ACREGMIN;
			}
			if (nopt(&m, MNTOPT_ACREGMAX, &argp->acregmax)) {
				argp->flags |= NFSMNT_ACREGMAX;
			}
			if (nopt(&m, MNTOPT_ACDIRMIN, &argp->acdirmin)) {
				argp->flags |= NFSMNT_ACDIRMIN;
			}
			if (nopt(&m, MNTOPT_ACDIRMAX, &argp->acdirmax)) {
				argp->flags |= NFSMNT_ACDIRMAX;
			}
		}

		if (posix) {
			argp->pathconf = NULL;
			if (error = get_pathconf(cl, dir, remname,
			    &argp->pathconf, retries)) {
				if (secflags & AUTH_F_RPCTIMESYNC)
					netbuf_free(syncaddr);
				else if (retaddrs)
					netdir_free(retaddrs, ND_ADDRLIST);
				free_knconf(argp->knconf);
				netbuf_free(argp->addr);
				freenetconfigent(nconf);
				nfs_free_secdata(
				    argp->nfs_ext_u.nfs_extB.secdata);
				if (argp->syncaddr)
					netbuf_free(argp->syncaddr);
				if (argp->netname)
					free(argp->netname);
				if (argp->hostname)
					free(argp->hostname);
				free(argp->fh);
				free(argp);
				head = prevhead;
				tail = prevtail;
				if (tail)
					tail->nfs_ext_u.nfs_extB.next = NULL;
				last_error = NFSERR_IO;

				if (error == RET_RETRY && retries-- > 0) {
					destroy_auth_client_handle(cl);
					DELAY(delay);
					goto retry;
				}

				destroy_auth_client_handle(cl);
				skipentry = 1;
				mfs->mfs_ignore = 1;
				continue;
			}
			argp->flags |= NFSMNT_POSIX;
			if (trace > 4)
				trace_prt(1,
				    "  nfsmount: have pathconf for %s\n",
				    remname);
		}

		/*
		 * free loop-specific data structures
		 */
		destroy_auth_client_handle(cl);
		freenetconfigent(nconf);
		if (secflags & AUTH_F_RPCTIMESYNC)
			netbuf_free(syncaddr);
		else if (retaddrs)
			netdir_free(retaddrs, ND_ADDRLIST);

		/*
		 * Decide whether to use remote host's lockd or local locking.
		 * If we are using the public fh, we've already turned
		 * LLOCK on.
		 */
		if (hasmntopt(&m, MNTOPT_LLOCK))
			argp->flags |= NFSMNT_LLOCK;
		if (!(argp->flags & NFSMNT_LLOCK) && nfsvers == NFS_VERSION &&
		    remote_lock(host, argp->fh)) {
			syslog(loglevel, "No network locking on %s : "
			"contact admin to install server change", host);
			argp->flags |= NFSMNT_LLOCK;
		}

		/*
		 * Build a string for /etc/mnttab.
		 * If possible, coalesce strings with same 'dir' info.
		 */
		if ((mfs->mfs_flags & MFS_URL) == 0) {
			char *tmp;

			if (mnttabcnt) {
				p = strrchr(mnttabtext, (int)':');
				if (!p || strcmp(p+1, dir) != 0) {
					mnttabcnt += strlen(remname) + 2;
				} else {
					*p = '\0';
					mnttabcnt += strlen(rhost) + 2;
				}
				if ((tmp = realloc(mnttabtext,
				    mnttabcnt)) != NULL) {
					mnttabtext = tmp;
					strcat(mnttabtext, ",");
				} else {
					free(mnttabtext);
					mnttabtext = NULL;
				}
			} else {
				mnttabcnt = strlen(remname) + 1;
				if ((mnttabtext = malloc(mnttabcnt)) != NULL)
					mnttabtext[0] = '\0';
			}

			if (mnttabtext != NULL)
				strcat(mnttabtext, remname);

		} else {
			char *tmp;
			int more_cnt = 0;
			char sport[16];

			more_cnt += strlen("nfs://");
			more_cnt += strlen(mfs->mfs_host);

			if (mfs->mfs_port != 0) {
				(void) sprintf(sport, ":%u", mfs->mfs_port);
			} else
				sport[0] = '\0';

			more_cnt += strlen(sport);
			more_cnt += 1; /* "/" */
			more_cnt += strlen(mfs->mfs_dir);

			if (mnttabcnt) {
				more_cnt += 1; /* "," */
				mnttabcnt += more_cnt;

				if ((tmp = realloc(mnttabtext,
				    mnttabcnt)) != NULL) {
					mnttabtext = tmp;
					strcat(mnttabtext, ",");
				} else {
					free(mnttabtext);
					mnttabtext = NULL;
				}
			} else {
				mnttabcnt = more_cnt + 1;
				if ((mnttabtext = malloc(mnttabcnt)) != NULL)
					mnttabtext[0] = '\0';
			}

			if (mnttabtext != NULL) {
				strcat(mnttabtext, "nfs://");
				strcat(mnttabtext, mfs->mfs_host);
				strcat(mnttabtext, sport);
				strcat(mnttabtext, "/");
				strcat(mnttabtext, mfs->mfs_dir);
			}
		}

		if (!mnttabtext) {
			syslog(LOG_ERR, "nfsmount: no memory");
			last_error = NFSERR_IO;
			goto out;
		}

		/*
		 * At least one entry, can call mount(2).
		 */
		entries++;

		/*
		 * If replication was defeated, don't do more work
		 */
		if (!replicated)
			break;
	}


	/*
	 * Did we get through all possibilities without success?
	 */
	if (!entries)
		goto out;

	/* Make "xattr" the default if "noxattr" is not specified. */
	strcpy(mopts, opts);
	if (!hasmntopt(&m, MNTOPT_NOXATTR) && !hasmntopt(&m, MNTOPT_XATTR)) {
		if (strlen(mopts) > 0)
			strcat(mopts, ",");
		strcat(mopts, "xattr");
	}

	/*
	 * enable services as needed.
	 */
	{
		char **sl;

		if (strcmp(fstype, MNTTYPE_NFS4) == 0)
			sl = service_list_v4;
		else
			sl = service_list;

		(void) _check_services(sl);
	}

	/*
	 * Whew; do the mount, at last.
	 */
	if (trace > 1) {
		trace_prt(1, "	mount %s %s (%s)\n", mnttabtext, mntpnt, mopts);
	}

	/*
	 * About to do a nfs mount, make sure the mount_to is set for
	 * potential ephemeral mounts with NFSv4.
	 */
	set_nfsv4_ephemeral_mount_to();

	/*
	 * If no action list pointer then do the mount, otherwise
	 * build the actions list pointer with the mount information.
	 * so the mount can be done in the kernel.
	 */
	if (alp == NULL) {
		if (mount(mnttabtext, mntpnt, flags | MS_DATA, fstype,
		    head, sizeof (*head), mopts, MAX_MNTOPT_STR) < 0) {
			if (trace > 1)
				trace_prt(1, "	Mount of %s on %s: %d\n",
				    mnttabtext, mntpnt, errno);
			if (errno != EBUSY || verbose)
				syslog(LOG_ERR,
				"Mount of %s on %s: %m", mnttabtext, mntpnt);
			last_error = NFSERR_IO;
			goto out;
		}

		last_error = NFS_OK;
		if (stat(mntpnt, &stbuf) == 0) {
			if (trace > 1) {
				trace_prt(1, "	mount %s dev=%x rdev=%x OK\n",
				    mnttabtext, stbuf.st_dev, stbuf.st_rdev);
			}
		} else {
			if (trace > 1) {
				trace_prt(1, "	mount %s OK\n", mnttabtext);
				trace_prt(1, "	stat of %s failed\n", mntpnt);
			}

		}
	} else {
		alp->action.action = AUTOFS_MOUNT_RQ;
		alp->action.action_list_entry_u.mounta.spec =
		    strdup(mnttabtext);
		alp->action.action_list_entry_u.mounta.dir = strdup(mntpnt);
		alp->action.action_list_entry_u.mounta.flags =
		    flags | MS_DATA;
		alp->action.action_list_entry_u.mounta.fstype =
		    strdup(fstype);
		alp->action.action_list_entry_u.mounta.dataptr = (char *)head;
		alp->action.action_list_entry_u.mounta.datalen =
		    sizeof (*head);
		mntopts = malloc(strlen(mopts) + 1);
		strcpy(mntopts, mopts);
		mntopts[strlen(mopts)] = '\0';
		alp->action.action_list_entry_u.mounta.optptr = mntopts;
		alp->action.action_list_entry_u.mounta.optlen =
		    strlen(mntopts) + 1;
		last_error = NFS_OK;
		goto ret;
	}

out:
	argp = head;
	while (argp) {
		if (argp->pathconf)
			free(argp->pathconf);
		free_knconf(argp->knconf);
		netbuf_free(argp->addr);
		if (argp->syncaddr)
			netbuf_free(argp->syncaddr);
		if (argp->netname) {
			free(argp->netname);
		}
		if (argp->hostname)
			free(argp->hostname);
		nfs_free_secdata(argp->nfs_ext_u.nfs_extB.secdata);
		free(argp->fh);
		head = argp;
		argp = argp->nfs_ext_u.nfs_extB.next;
		free(head);
	}
ret:
	if (nfs_proto)
		free(nfs_proto);
	if (mnttabtext)
		free(mnttabtext);

	for (mfs = mfs_in; mfs; mfs = mfs->mfs_next) {

		if (mfs->mfs_flags & MFS_ALLOC_DIR) {
			free(mfs->mfs_dir);
			mfs->mfs_dir = NULL;
			mfs->mfs_flags &= ~MFS_ALLOC_DIR;
		}

		if (mfs->mfs_args != NULL && alp == NULL) {
			free(mfs->mfs_args);
			mfs->mfs_args = NULL;
		}

		if (mfs->mfs_nconf != NULL) {
			freenetconfigent(mfs->mfs_nconf);
			mfs->mfs_nconf = NULL;
		}
	}

	return (last_error);
}

/*
 * get_pathconf(cl, path, fsname, pcnf, cretries)
 * ugliness that requires that ppathcnf and pathcnf stay consistent
 * cretries is a copy of retries used to determine when to syslog
 * on retry situations.
 */
static int
get_pathconf(CLIENT *cl, char *path, char *fsname, struct pathcnf **pcnf,
	int cretries)
{
	struct ppathcnf *p = NULL;
	enum clnt_stat rpc_stat;
	struct timeval timeout;

	p = (struct ppathcnf *)malloc(sizeof (struct ppathcnf));
	if (p == NULL) {
		syslog(LOG_ERR, "get_pathconf: Out of memory");
		return (RET_ERR);
	}
	memset((caddr_t)p, 0, sizeof (struct ppathcnf));

	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
	rpc_stat = clnt_call(cl, MOUNTPROC_PATHCONF,
	    xdr_dirpath, (caddr_t)&path, xdr_ppathcnf, (caddr_t)p, timeout);
	if (rpc_stat != RPC_SUCCESS) {
		if (cretries-- <= 0) {
			syslog(LOG_ERR,
			    "get_pathconf: %s: server not responding: %s",
			    fsname, clnt_sperror(cl, ""));
		}
		free(p);
		return (RET_RETRY);
	}
	if (_PC_ISSET(_PC_ERROR, p->pc_mask)) {
		syslog(LOG_ERR, "get_pathconf: no info for %s", fsname);
		free(p);
		return (RET_ERR);
	}
	*pcnf = (struct pathcnf *)p;
	return (RET_OK);
}

void
netbuf_free(nb)
	struct netbuf *nb;
{
	if (nb == NULL)
		return;
	if (nb->buf)
		free(nb->buf);
	free(nb);
}

#define	SMALL_HOSTNAME		20
#define	SMALL_PROTONAME		10
#define	SMALL_PROTOFMLYNAME		10

struct portmap_cache {
	int cache_prog;
	int cache_vers;
	time_t cache_time;
	char cache_small_hosts[SMALL_HOSTNAME + 1];
	char *cache_hostname;
	char *cache_proto;
	char *cache_protofmly;
	char cache_small_protofmly[SMALL_PROTOFMLYNAME + 1];
	char cache_small_proto[SMALL_PROTONAME + 1];
	struct netbuf cache_srv_addr;
	struct portmap_cache *cache_prev, *cache_next;
};

rwlock_t portmap_cache_lock;
static int portmap_cache_valid_time = 30;
struct portmap_cache *portmap_cache_head, *portmap_cache_tail;

#ifdef MALLOC_DEBUG
void
portmap_cache_flush()
{
	struct  portmap_cache *next = NULL, *cp;

	(void) rw_wrlock(&portmap_cache_lock);
	for (cp = portmap_cache_head; cp; cp = cp->cache_next) {
		if (cp->cache_hostname != NULL &&
		    cp->cache_hostname !=
		    cp->cache_small_hosts)
			free(cp->cache_hostname);
		if (cp->cache_proto != NULL &&
		    cp->cache_proto !=
		    cp->cache_small_proto)
			free(cp->cache_proto);
		if (cp->cache_srv_addr.buf != NULL)
			free(cp->cache_srv_addr.buf);
		next = cp->cache_next;
		free(cp);
	}
	portmap_cache_head = NULL;
	portmap_cache_tail = NULL;
	(void) rw_unlock(&portmap_cache_lock);
}
#endif

/*
 * Returns 1 if the entry is found in the cache, 0 otherwise.
 */
static int
portmap_cache_lookup(hostname, prog, vers, nconf, addrp)
	char *hostname;
	rpcprog_t prog;
	rpcvers_t vers;
	struct netconfig *nconf;
	struct netbuf *addrp;
{
	struct	portmap_cache *cachep, *prev, *next = NULL, *cp;
	int	retval = 0;

	timenow = time(NULL);

	(void) rw_rdlock(&portmap_cache_lock);

	/*
	 * Increment the portmap cache counters for # accesses and lookups
	 * Use a smaller factor (100 vs 1000 for the host cache) since
	 * initial analysis shows this cache is looked up 10% that of the
	 * host cache.
	 */
#ifdef CACHE_DEBUG
	portmap_cache_accesses++;
	portmap_cache_lookups++;
	if ((portmap_cache_lookups%100) == 0)
		trace_portmap_cache();
#endif /* CACHE_DEBUG */

	for (cachep = portmap_cache_head; cachep;
		cachep = cachep->cache_next) {
		if (timenow > cachep->cache_time) {
			/*
			 * We stumbled across an entry in the cache which
			 * has timed out. Free up all the entries that
			 * were added before it, which will positionally
			 * be after this entry. And adjust neighboring
			 * pointers.
			 * When we drop the lock and re-acquire it, we
			 * need to start from the beginning.
			 */
			(void) rw_unlock(&portmap_cache_lock);
			(void) rw_wrlock(&portmap_cache_lock);
			for (cp = portmap_cache_head;
				cp && (cp->cache_time >= timenow);
				cp = cp->cache_next)
				;
			if (cp == NULL)
				goto done;
			/*
			 * Adjust the link of the predecessor.
			 * Make the tail point to the new last entry.
			 */
			prev = cp->cache_prev;
			if (prev == NULL) {
				portmap_cache_head = NULL;
				portmap_cache_tail = NULL;
			} else {
				prev->cache_next = NULL;
				portmap_cache_tail = prev;
			}
			for (; cp; cp = next) {
				if (cp->cache_hostname != NULL &&
				    cp->cache_hostname !=
				    cp->cache_small_hosts)
					free(cp->cache_hostname);
				if (cp->cache_proto != NULL &&
				    cp->cache_proto !=
				    cp->cache_small_proto)
					free(cp->cache_proto);
				if (cp->cache_srv_addr.buf != NULL)
					free(cp->cache_srv_addr.buf);
				next = cp->cache_next;
				free(cp);
			}
			goto done;
		}
		if (cachep->cache_hostname == NULL ||
		    prog != cachep->cache_prog || vers != cachep->cache_vers ||
		    strcmp(nconf->nc_proto, cachep->cache_proto) != 0 ||
		    strcmp(nconf->nc_protofmly, cachep->cache_protofmly) != 0 ||
		    strcmp(hostname, cachep->cache_hostname) != 0)
			continue;
		/*
		 * Cache Hit.
		 */
#ifdef CACHE_DEBUG
		portmap_cache_hits++;	/* up portmap cache hit counter */
#endif /* CACHE_DEBUG */
		addrp->len = cachep->cache_srv_addr.len;
		memcpy(addrp->buf, cachep->cache_srv_addr.buf, addrp->len);
		retval = 1;
		break;
	}
done:
	(void) rw_unlock(&portmap_cache_lock);
	return (retval);
}

static void
portmap_cache_enter(hostname, prog, vers, nconf, addrp)
	char *hostname;
	rpcprog_t prog;
	rpcvers_t vers;
	struct netconfig *nconf;
	struct netbuf *addrp;
{
	struct portmap_cache *cachep;
	int protofmlylen;
	int protolen, hostnamelen;

	timenow = time(NULL);

	cachep = malloc(sizeof (struct portmap_cache));
	if (cachep == NULL)
		return;
	memset((char *)cachep, 0, sizeof (*cachep));

	hostnamelen = strlen(hostname);
	if (hostnamelen <= SMALL_HOSTNAME)
		cachep->cache_hostname = cachep->cache_small_hosts;
	else {
		cachep->cache_hostname = malloc(hostnamelen + 1);
		if (cachep->cache_hostname == NULL)
			goto nomem;
	}
	strcpy(cachep->cache_hostname, hostname);
	protolen = strlen(nconf->nc_proto);
	if (protolen <= SMALL_PROTONAME)
		cachep->cache_proto = cachep->cache_small_proto;
	else {
		cachep->cache_proto = malloc(protolen + 1);
		if (cachep->cache_proto == NULL)
			goto nomem;
	}
	protofmlylen = strlen(nconf->nc_protofmly);
	if (protofmlylen <= SMALL_PROTOFMLYNAME)
		cachep->cache_protofmly = cachep->cache_small_protofmly;
	else {
		cachep->cache_protofmly = malloc(protofmlylen + 1);
		if (cachep->cache_protofmly == NULL)
			goto nomem;
	}

	strcpy(cachep->cache_proto, nconf->nc_proto);
	cachep->cache_prog = prog;
	cachep->cache_vers = vers;
	cachep->cache_time = timenow + portmap_cache_valid_time;
	cachep->cache_srv_addr.len = addrp->len;
	cachep->cache_srv_addr.buf = malloc(addrp->len);
	if (cachep->cache_srv_addr.buf == NULL)
		goto nomem;
	memcpy(cachep->cache_srv_addr.buf, addrp->buf, addrp->maxlen);
	cachep->cache_prev = NULL;
	(void) rw_wrlock(&portmap_cache_lock);
	/*
	 * There's a window in which we could have multiple threads making
	 * the same cache entry. This can be avoided by walking the cache
	 * once again here to check and see if there are duplicate entries
	 * (after grabbing the write lock). This isn't fatal and I'm not
	 * going to bother with this.
	 */
#ifdef CACHE_DEBUG
	portmap_cache_accesses++;	/* up portmap cache access counter */
#endif /* CACHE_DEBUG */
	cachep->cache_next = portmap_cache_head;
	if (portmap_cache_head != NULL)
		portmap_cache_head->cache_prev = cachep;
	portmap_cache_head = cachep;
	(void) rw_unlock(&portmap_cache_lock);
	return;

nomem:
	syslog(LOG_ERR, "portmap_cache_enter: Memory allocation failed");
	if (cachep->cache_srv_addr.buf)
		free(cachep->cache_srv_addr.buf);
	if (cachep->cache_proto && protolen > SMALL_PROTONAME)
		free(cachep->cache_proto);
	if (cachep->cache_hostname && hostnamelen > SMALL_HOSTNAME)
		free(cachep->cache_hostname);
	if (cachep->cache_protofmly && protofmlylen > SMALL_PROTOFMLYNAME)
		free(cachep->cache_protofmly);
	if (cachep)
		free(cachep);
	cachep = NULL;
}

static int
get_cached_srv_addr(char *hostname, rpcprog_t prog, rpcvers_t vers,
	struct netconfig *nconf, struct netbuf *addrp)
{
	if (portmap_cache_lookup(hostname, prog, vers, nconf, addrp))
		return (1);
	if (rpcb_getaddr(prog, vers, nconf, addrp, hostname) == 0)
		return (0);
	portmap_cache_enter(hostname, prog, vers, nconf, addrp);
	return (1);
}

/*
 * Get a network address on "hostname" for program "prog"
 * with version "vers".  If the port number is specified (non zero)
 * then try for a TCP/UDP transport and set the port number of the
 * resulting IP address.
 *
 * If the address of a netconfig pointer was passed and
 * if it's not null, use it as the netconfig otherwise
 * assign the address of the netconfig that was used to
 * establish contact with the service.
 *
 * tinfo argument is for matching the get_addr() defined in
 * ../nfs/mount/mount.c
 */

static struct netbuf *
get_addr(char *hostname, rpcprog_t prog, rpcvers_t vers,
	struct netconfig **nconfp, char *proto, ushort_t port,
	struct t_info *tinfo)

{
	enum clnt_stat cstat;

	return (get_server_netinfo(SERVER_ADDR, hostname, prog, vers, NULL,
		nconfp, proto, port, tinfo, NULL, FALSE, NULL, &cstat));
}

static struct netbuf *
get_pubfh(char *hostname, rpcvers_t vers, mfs_snego_t *mfssnego,
	struct netconfig **nconfp, char *proto, ushort_t port,
	struct t_info *tinfo, caddr_t *fhp, bool_t get_pubfh, char *fspath)
{
	enum clnt_stat cstat;

	return (get_server_netinfo(SERVER_FH, hostname, NFS_PROGRAM, vers,
	    mfssnego, nconfp, proto, port, tinfo, fhp, get_pubfh, fspath,
	    &cstat));
}

static enum clnt_stat
get_ping(char *hostname, rpcprog_t prog, rpcvers_t vers,
	struct netconfig **nconfp, ushort_t port, bool_t direct_to_server)
{
	enum clnt_stat cstat;

	(void) get_server_netinfo(SERVER_PING, hostname, prog,
	    vers, NULL, nconfp, NULL, port, NULL, NULL,
	    direct_to_server, NULL, &cstat);

	return (cstat);
}

void *
get_server_netinfo(
	enum type_of_stuff type_of_stuff,
	char *hostname,
	rpcprog_t prog,
	rpcvers_t vers,
	mfs_snego_t *mfssnego,
	struct netconfig **nconfp,
	char *proto,
	ushort_t port,			/* may be zero */
	struct t_info *tinfo,
	caddr_t *fhp,
	bool_t direct_to_server,
	char *fspath,
	enum clnt_stat *cstatp)
{
	struct netbuf *nb = NULL;
	struct netconfig *nconf = NULL;
	NCONF_HANDLE *nc = NULL;
	int error = 0;
	int fd = 0;
	struct t_bind *tbind = NULL;
	int nthtry = FIRST_TRY;

	if (nconfp && *nconfp) {
		return (get_netconfig_info(type_of_stuff, hostname,
		    prog, vers, nconf, port, tinfo, tbind, fhp,
		    direct_to_server, fspath, cstatp, mfssnego));
	}

	/*
	 * No nconf passed in.
	 *
	 * Try to get a nconf from /etc/netconfig.
	 * First choice is COTS, second is CLTS unless proto
	 * is specified.  When we retry, we reset the
	 * netconfig list, so that we search the whole list
	 * for the next choice.
	 */
	if ((nc = setnetpath()) == NULL)
		goto done;

	/*
	 * If proto is specified, then only search for the match,
	 * otherwise try COTS first, if failed, then try CLTS.
	 */
	if (proto) {
		while ((nconf = getnetpath(nc)) != NULL) {
			if (strcmp(nconf->nc_proto, proto))
				continue;
			/*
			 * If the port number is specified then TCP/UDP
			 * is needed. Otherwise any cots/clts will do.
			 */
			if (port)  {
				if ((strcmp(nconf->nc_protofmly, NC_INET) &&
				    strcmp(nconf->nc_protofmly, NC_INET6)) ||
				    (strcmp(nconf->nc_proto, NC_TCP) &&
				    strcmp(nconf->nc_proto, NC_UDP)))
					continue;
			}
			nb = get_netconfig_info(type_of_stuff, hostname,
			    prog, vers, nconf, port, tinfo, tbind, fhp,
			    direct_to_server, fspath, cstatp, mfssnego);
			if (*cstatp == RPC_SUCCESS)
				break;

			assert(nb == NULL);

		}
		if (nconf == NULL)
			goto done;
	} else {
retry:
		while ((nconf = getnetpath(nc)) != NULL) {
			if (nconf->nc_flag & NC_VISIBLE) {
				if (nthtry == FIRST_TRY) {
					if ((nconf->nc_semantics ==
					    NC_TPI_COTS_ORD) ||
					    (nconf->nc_semantics ==
					    NC_TPI_COTS)) {
						if (port == 0)
							break;
						if ((strcmp(nconf->nc_protofmly,
						    NC_INET) == 0 ||
						    strcmp(nconf->nc_protofmly,
						    NC_INET6) == 0) &&
						    (strcmp(nconf->nc_proto,
						    NC_TCP) == 0))
							break;
					}
				}
				if (nthtry == SECOND_TRY) {
					if (nconf->nc_semantics ==
					    NC_TPI_CLTS) {
						if (port == 0)
							break;
						if ((strcmp(nconf->nc_protofmly,
						    NC_INET) == 0 ||
						    strcmp(nconf->nc_protofmly,
						    NC_INET6) == 0) &&
						    (strcmp(nconf->nc_proto,
						    NC_UDP) == 0))
							break;
					}
				}
			}
		}

		if (nconf == NULL) {
			if (++nthtry <= MNT_PREF_LISTLEN) {
				endnetpath(nc);
				if ((nc = setnetpath()) == NULL)
					goto done;
				goto retry;
			} else
				goto done;
		} else {
			nb = get_netconfig_info(type_of_stuff, hostname,
			    prog, vers, nconf, port, tinfo, tbind, fhp,
			    direct_to_server, fspath, cstatp, mfssnego);
			if (*cstatp != RPC_SUCCESS)
				/*
				 * Continue the same search path in the
				 * netconfig db until no more matched nconf
				 * (nconf == NULL).
				 */
				goto retry;
		}
	}

	/*
	 * Got nconf and nb.  Now dup the netconfig structure (nconf)
	 * and return it thru nconfp.
	 */
	if (nconf != NULL) {
		if ((*nconfp = getnetconfigent(nconf->nc_netid)) == NULL) {
			syslog(LOG_ERR, "no memory\n");
			free(nb);
			nb = NULL;
		}
	} else {
		*nconfp = NULL;
	}
done:
	if (nc)
		endnetpath(nc);
	return (nb);
}

void *
get_server_fh(char *hostname, rpcprog_t	prog, rpcvers_t	vers,
	mfs_snego_t *mfssnego, struct netconfig *nconf, ushort_t port,
	struct t_info *tinfo, struct t_bind *tbind, caddr_t *fhp,
	bool_t direct_to_server, char *fspath, enum clnt_stat *cstat)
{
	AUTH *ah = NULL;
	AUTH *new_ah = NULL;
	struct snego_t	snego;
	enum clnt_stat cs = RPC_TIMEDOUT;
	struct timeval tv;
	bool_t file_handle = 1;
	enum snego_stat sec;
	CLIENT *cl = NULL;
	int fd = -1;
	struct netbuf *nb = NULL;

	if (direct_to_server != TRUE)
		return (NULL);

	if (prog == NFS_PROGRAM && vers == NFS_V4)
		if (strncasecmp(nconf->nc_proto, NC_UDP, strlen(NC_UDP)) == 0)
			goto done;

	if ((fd = t_open(nconf->nc_device, O_RDWR, tinfo)) < 0)
		goto done;

	/* LINTED pointer alignment */
	if ((tbind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR)) == NULL)
		goto done;

	if (setup_nb_parms(nconf, tbind, tinfo, hostname, fd,
	    direct_to_server, port, prog, vers, file_handle) < 0) {
		goto done;
	}

	cl = clnt_tli_create(fd, nconf, &tbind->addr, prog, vers, 0, 0);
	if (cl == NULL)
		goto done;

	ah = authsys_create_default();
	if (ah != NULL) {
#ifdef MALLOC_DEBUG
		drop_alloc("AUTH_HANDLE", cl->cl_auth,
		    __FILE__, __LINE__);
#endif
		AUTH_DESTROY(cl->cl_auth);
		cl->cl_auth = ah;
#ifdef MALLOC_DEBUG
		add_alloc("AUTH_HANDLE", cl->cl_auth, 0,
		    __FILE__, __LINE__);
#endif
	}

	if (!mfssnego->snego_done && vers != NFS_V4) {
		/*
		 * negotiate sec flavor.
		 */
		snego.cnt = 0;
		if ((sec = nfs_sec_nego(vers, cl, fspath, &snego)) ==
		    SNEGO_SUCCESS) {
			int jj;

			/*
			 * check if server supports the one
			 * specified in the sec= option.
			 */
			if (mfssnego->sec_opt) {
				for (jj = 0; jj < snego.cnt; jj++) {
					if (snego.array[jj] ==
					    mfssnego->nfs_sec.sc_nfsnum) {
						mfssnego->snego_done = TRUE;
						break;
					}
				}
			}

			/*
			 * find a common sec flavor
			 */
			if (!mfssnego->snego_done) {
				for (jj = 0; jj < snego.cnt; jj++) {
					if (!nfs_getseconfig_bynumber(
					    snego.array[jj],
					    &mfssnego->nfs_sec)) {
						mfssnego->snego_done = TRUE;
						break;
					}
				}
			}
			if (!mfssnego->snego_done)
				goto done;
			/*
			 * Now that the flavor has been
			 * negotiated, get the fh.
			 *
			 * First, create an auth handle using the negotiated
			 * sec flavor in the next lookup to
			 * fetch the filehandle.
			 */
			new_ah = nfs_create_ah(cl, hostname,
			    &mfssnego->nfs_sec);
			if (new_ah  == NULL)
				goto done;
#ifdef MALLOC_DEBUG
			drop_alloc("AUTH_HANDLE", cl->cl_auth,
			    __FILE__, __LINE__);
#endif
			AUTH_DESTROY(cl->cl_auth);
			cl->cl_auth = new_ah;
#ifdef MALLOC_DEBUG
			add_alloc("AUTH_HANDLE", cl->cl_auth, 0,
			    __FILE__, __LINE__);
#endif
		} else if (sec == SNEGO_ARRAY_TOO_SMALL ||
		    sec == SNEGO_FAILURE) {
			goto done;
		}
	}

	switch (vers) {
	case NFS_VERSION:
		{
		wnl_diropargs arg;
		wnl_diropres res;

		memset((char *)&arg.dir, 0, sizeof (wnl_fh));
		memset((char *)&res, 0, sizeof (wnl_diropres));
		arg.name = fspath;
		if (wnlproc_lookup_2(&arg, &res, cl) !=
		    RPC_SUCCESS || res.status != WNL_OK)
			goto done;
		*fhp = malloc(sizeof (wnl_fh));

		if (*fhp == NULL) {
			syslog(LOG_ERR, "no memory\n");
			goto done;
		}

		memcpy((char *)*fhp,
		    (char *)&res.wnl_diropres_u.wnl_diropres.file,
		    sizeof (wnl_fh));
		cs = RPC_SUCCESS;
		}
		break;
	case NFS_V3:
		{
		WNL_LOOKUP3args arg;
		WNL_LOOKUP3res res;
		nfs_fh3 *fh3p;

		memset((char *)&arg.what.dir, 0, sizeof (wnl_fh3));
		memset((char *)&res, 0, sizeof (WNL_LOOKUP3res));
		arg.what.name = fspath;
		if (wnlproc3_lookup_3(&arg, &res, cl) !=
		    RPC_SUCCESS || res.status != WNL3_OK)
			goto done;

		fh3p = (nfs_fh3 *)malloc(sizeof (*fh3p));

		if (fh3p == NULL) {
			syslog(LOG_ERR, "no memory\n");
			goto done;
		}

		fh3p->fh3_length =
		    res.WNL_LOOKUP3res_u.res_ok.object.data.data_len;
		memcpy(fh3p->fh3_u.data,
		    res.WNL_LOOKUP3res_u.res_ok.object.data.data_val,
		    fh3p->fh3_length);

		*fhp = (caddr_t)fh3p;

		cs = RPC_SUCCESS;
		}
		break;
	case NFS_V4:
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		cs = clnt_call(cl, NULLPROC, xdr_void, 0,
		    xdr_void, 0, tv);
		if (cs != RPC_SUCCESS)
			goto done;

		*fhp = strdup(fspath);
		if (fhp == NULL) {
			cs = RPC_SYSTEMERROR;
			goto done;
		}
		break;
	}
	nb = (struct netbuf *)malloc(sizeof (struct netbuf));
	if (nb == NULL) {
		syslog(LOG_ERR, "no memory\n");
		cs = RPC_SYSTEMERROR;
		goto done;
	}
	nb->buf = (char *)malloc(tbind->addr.maxlen);
	if (nb->buf == NULL) {
		syslog(LOG_ERR, "no memory\n");
		free(nb);
		nb = NULL;
		cs = RPC_SYSTEMERROR;
		goto done;
	}
	(void) memcpy(nb->buf, tbind->addr.buf, tbind->addr.len);
	nb->len = tbind->addr.len;
	nb->maxlen = tbind->addr.maxlen;
done:
	if (cstat != NULL)
		*cstat = cs;
	destroy_auth_client_handle(cl);
	cleanup_tli_parms(tbind, fd);
	return (nb);
}

/*
 * Sends a null call to the remote host's (NFS program, versp). versp
 * may be "NULL" in which case the default maximum version is used.
 * Upon return, versp contains the maximum version supported iff versp!= NULL.
 */
enum clnt_stat
pingnfs(
	char *hostpart,
	int attempts,
	rpcvers_t *versp,
	rpcvers_t versmin,
	ushort_t port,			/* may be zero */
	bool_t usepub,
	char *path,
	char *proto)
{
	CLIENT *cl = NULL;
	struct timeval rpc_to_new = {15, 0};
	static struct timeval rpc_rtrans_new = {-1, -1};
	enum clnt_stat clnt_stat;
	int i, j;
	rpcvers_t versmax;	/* maximum version to try against server */
	rpcvers_t outvers;	/* version supported by host on last call */
	rpcvers_t vers_to_try;	/* to try different versions against host */
	char *hostname;
	struct netconfig *nconf;

	hostname = strdup(hostpart);
	if (hostname == NULL) {
		return (RPC_SYSTEMERROR);
	}
	unbracket(&hostname);

	if (path != NULL && strcmp(hostname, "nfs") == 0 &&
	    strncmp(path, "//", 2) == 0) {
		char *sport;

		hostname = strdup(path+2);

		if (hostname == NULL)
			return (RPC_SYSTEMERROR);

		path = strchr(hostname, '/');

		/*
		 * This cannot happen. If it does, give up
		 * on the ping as this is obviously a corrupt
		 * entry.
		 */
		if (path == NULL) {
			free(hostname);
			return (RPC_SUCCESS);
		}

		/*
		 * Probable end point of host string.
		 */
		*path = '\0';

		sport = strchr(hostname, ':');

		if (sport != NULL && sport < path) {

			/*
			 * Actual end point of host string.
			 */
			*sport = '\0';
			port = htons((ushort_t)atoi(sport+1));
		}

		usepub = TRUE;
	}

	/* Pick up the default versions and then set them appropriately */
	if (versp) {
		versmax = *versp;
		/* use versmin passed in */
	} else {
		read_default_nfs();
		set_versrange(0, &versmax, &versmin);
	}

	if (proto &&
	    strncasecmp(proto, NC_UDP, strlen(NC_UDP)) == 0 &&
	    versmax == NFS_V4) {
		if (versmin == NFS_V4) {
			if (versp) {
				*versp = versmax - 1;
				return (RPC_SUCCESS);
			}
			return (RPC_PROGUNAVAIL);
		} else {
			versmax--;
		}
	}

	if (versp)
		*versp = versmax;

	switch (cache_check(hostname, versp, proto)) {
	case GOODHOST:
		if (hostname != hostpart)
			free(hostname);
		return (RPC_SUCCESS);
	case DEADHOST:
		if (hostname != hostpart)
			free(hostname);
		return (RPC_TIMEDOUT);
	case NOHOST:
	default:
		break;
	}

	/*
	 * XXX The retransmission time rpcbrmttime is a global defined
	 * in the rpc library (rpcb_clnt.c). We use (and like) the default
	 * value of 15 sec in the rpc library. The code below is to protect
	 * us in case it changes. This need not be done under a lock since
	 * any # of threads entering this function will get the same
	 * retransmission value.
	 */
	if (rpc_rtrans_new.tv_sec == -1 && rpc_rtrans_new.tv_usec == -1) {
		__rpc_control(CLCR_GET_RPCB_RMTTIME, (char *)&rpc_rtrans_new);
		if (rpc_rtrans_new.tv_sec != 15 && rpc_rtrans_new.tv_sec != 0)
			if (trace > 1)
				trace_prt(1, "RPC library rttimer changed\n");
	}

	/*
	 * XXX Manipulate the total timeout to get the number of
	 * desired retransmissions. This code is heavily dependant on
	 * the RPC backoff mechanism in clnt_dg_call (clnt_dg.c).
	 */
	for (i = 0, j = rpc_rtrans_new.tv_sec; i < attempts-1; i++) {
		if (j < RPC_MAX_BACKOFF)
			j *= 2;
		else
			j = RPC_MAX_BACKOFF;
		rpc_to_new.tv_sec += j;
	}

	vers_to_try = versmax;

	/*
	 * check the host's version within the timeout
	 */
	if (trace > 1)
		trace_prt(1, "	ping: %s timeout=%ld request vers=%d min=%d\n",
		    hostname, rpc_to_new.tv_sec, versmax, versmin);

	if (usepub == FALSE) {
		do {
			/*
			 * If NFSv4, then we do the same thing as is used
			 * for public filehandles so that we avoid rpcbind
			 */
			if (vers_to_try == NFS_V4) {
				if (trace > 4) {
				trace_prt(1, "  pingnfs: Trying ping via "
				    "\"circuit_v\"\n");
				}

				cl = clnt_create_service_timed(hostname, "nfs",
				    NFS_PROGRAM, vers_to_try,
				    port, "circuit_v", &rpc_to_new);
				if (cl != NULL) {
					outvers = vers_to_try;
					break;
				}
				if (trace > 4) {
					trace_prt(1,
					    "  pingnfs: Can't ping via "
					    "\"circuit_v\" %s: RPC error=%d\n",
					    hostname, rpc_createerr.cf_stat);
				}

			} else {
				cl = clnt_create_vers_timed(hostname,
				    NFS_PROGRAM, &outvers, versmin, vers_to_try,
				    "datagram_v", &rpc_to_new);
				if (cl != NULL)
					break;
				if (trace > 4) {
					trace_prt(1,
					    "  pingnfs: Can't ping via "
					    "\"datagram_v\"%s: RPC error=%d\n",
					    hostname, rpc_createerr.cf_stat);
				}
				if (rpc_createerr.cf_stat == RPC_UNKNOWNHOST ||
				    rpc_createerr.cf_stat == RPC_TIMEDOUT)
					break;
				if (rpc_createerr.cf_stat ==
				    RPC_PROGNOTREGISTERED) {
					if (trace > 4) {
						trace_prt(1,
						    "  pingnfs: Trying ping "
						    "via \"circuit_v\"\n");
					}
					cl = clnt_create_vers_timed(hostname,
					    NFS_PROGRAM, &outvers,
					    versmin, vers_to_try,
					    "circuit_v", &rpc_to_new);
					if (cl != NULL)
						break;
					if (trace > 4) {
						trace_prt(1,
						    "  pingnfs: Can't ping "
						    "via \"circuit_v\" %s: "
						    "RPC error=%d\n",
						    hostname,
						    rpc_createerr.cf_stat);
					}
				}
			}

		/*
		 * backoff and return lower version to retry the ping.
		 * XXX we should be more careful and handle
		 * RPC_PROGVERSMISMATCH here, because that error is handled
		 * in clnt_create_vers(). It's not done to stay in sync
		 * with the nfs mount command.
		 */
			vers_to_try--;
			if (vers_to_try < versmin)
				break;
			if (versp != NULL) {	/* recheck the cache */
				*versp = vers_to_try;
				if (trace > 4) {
					trace_prt(1,
					    "  pingnfs: check cache: vers=%d\n",
					    *versp);
				}
				switch (cache_check(hostname, versp, proto)) {
				case GOODHOST:
					if (hostname != hostpart)
						free(hostname);
					return (RPC_SUCCESS);
				case DEADHOST:
					if (hostname != hostpart)
						free(hostname);
					return (RPC_TIMEDOUT);
				case NOHOST:
				default:
					break;
				}
			}
			if (trace > 4) {
				trace_prt(1, "  pingnfs: Try version=%d\n",
				    vers_to_try);
			}
		} while (cl == NULL);


		if (cl == NULL) {
			if (verbose)
				syslog(LOG_ERR, "pingnfs: %s%s",
				    hostname, clnt_spcreateerror(""));
			clnt_stat = rpc_createerr.cf_stat;
		} else {
			clnt_destroy(cl);
			clnt_stat = RPC_SUCCESS;
		}

	} else {
		for (vers_to_try = versmax; vers_to_try >= versmin;
		    vers_to_try--) {

			nconf = NULL;

			if (trace > 4) {
				trace_prt(1, "  pingnfs: Try version=%d "
				    "using get_ping()\n", vers_to_try);
			}

			clnt_stat = get_ping(hostname, NFS_PROGRAM,
			    vers_to_try, &nconf, port, TRUE);

			if (nconf != NULL)
				freenetconfigent(nconf);

			if (clnt_stat == RPC_SUCCESS) {
				outvers = vers_to_try;
				break;
			}
		}
	}

	if (trace > 1)
		clnt_stat == RPC_SUCCESS ?
		    trace_prt(1, "	pingnfs OK: nfs version=%d\n", outvers):
		    trace_prt(1, "	pingnfs FAIL: can't get nfs version\n");

	if (clnt_stat == RPC_SUCCESS) {
		cache_enter(hostname, versmax, outvers, proto, GOODHOST);
		if (versp != NULL)
			*versp = outvers;
	} else
		cache_enter(hostname, versmax, versmax, proto, DEADHOST);

	if (hostpart != hostname)
		free(hostname);

	return (clnt_stat);
}

#define	MNTTYPE_LOFS	"lofs"

int
loopbackmount(fsname, dir, mntopts, overlay)
	char *fsname;		/* Directory being mounted */
	char *dir;		/* Directory being mounted on */
	char *mntopts;
	int overlay;
{
	struct mnttab mnt;
	int flags = 0;
	char fstype[] = MNTTYPE_LOFS;
	int dirlen;
	struct stat st;
	char optbuf[MAX_MNTOPT_STR];

	dirlen = strlen(dir);
	if (dir[dirlen-1] == ' ')
		dirlen--;

	if (dirlen == strlen(fsname) &&
		strncmp(fsname, dir, dirlen) == 0) {
		syslog(LOG_ERR,
			"Mount of %s on %s would result in deadlock, aborted\n",
			fsname, dir);
		return (RET_ERR);
	}
	mnt.mnt_mntopts = mntopts;
	if (hasmntopt(&mnt, MNTOPT_RO) != NULL)
		flags |= MS_RDONLY;

	(void) strlcpy(optbuf, mntopts, sizeof (optbuf));

	if (overlay)
		flags |= MS_OVERLAY;

	if (trace > 1)
		trace_prt(1,
			"  loopbackmount: fsname=%s, dir=%s, flags=%d\n",
			fsname, dir, flags);

	if (is_system_labeled()) {
		if (create_homedir((const char *)fsname,
		    (const char *)dir) == 0) {
			return (NFSERR_NOENT);
		}
	}

	if (mount(fsname, dir, flags | MS_DATA | MS_OPTIONSTR, fstype,
	    NULL, 0, optbuf, sizeof (optbuf)) < 0) {
		syslog(LOG_ERR, "Mount of %s on %s: %m", fsname, dir);
		return (RET_ERR);
	}

	if (stat(dir, &st) == 0) {
		if (trace > 1) {
			trace_prt(1,
			    "  loopbackmount of %s on %s dev=%x rdev=%x OK\n",
			    fsname, dir, st.st_dev, st.st_rdev);
		}
	} else {
		if (trace > 1) {
			trace_prt(1,
			    "  loopbackmount of %s on %s OK\n", fsname, dir);
			trace_prt(1, "	stat of %s failed\n", dir);
		}
	}

	return (0);
}

/*
 * Look for the value of a numeric option of the form foo=x.  If found, set
 * *valp to the value and return non-zero.  If not found or the option is
 * malformed, return zero.
 */

int
nopt(mnt, opt, valp)
	struct mnttab *mnt;
	char *opt;
	int *valp;			/* OUT */
{
	char *equal;
	char *str;

	/*
	 * We should never get a null pointer, but if we do, it's better to
	 * ignore the option than to dump core.
	 */

	if (valp == NULL) {
		syslog(LOG_DEBUG, "null pointer for %s option", opt);
		return (0);
	}

	if (str = hasmntopt(mnt, opt)) {
		if (equal = strchr(str, '=')) {
			*valp = atoi(&equal[1]);
			return (1);
		} else {
			syslog(LOG_ERR, "Bad numeric option '%s'", str);
		}
	}
	return (0);
}

int
nfsunmount(mnt)
	struct mnttab *mnt;
{
	struct timeval timeout;
	CLIENT *cl;
	enum clnt_stat rpc_stat;
	char *host, *path;
	struct replica *list;
	int i, count = 0;
	int isv4mount = is_v4_mount(mnt->mnt_mountp);

	if (trace > 1)
		trace_prt(1, "	nfsunmount: umount %s\n", mnt->mnt_mountp);

	if (umount(mnt->mnt_mountp) < 0) {
		if (trace > 1)
			trace_prt(1, "	nfsunmount: umount %s FAILED\n",
				mnt->mnt_mountp);
		if (errno)
			return (errno);
	}

	/*
	 * If this is a NFSv4 mount, the mount protocol was not used
	 * so we just return.
	 */
	if (isv4mount) {
		if (trace > 1)
			trace_prt(1, "	nfsunmount: umount %s OK\n",
				mnt->mnt_mountp);
		return (0);
	}

	/*
	 * If mounted with -o public, then no need to contact server
	 * because mount protocol was not used.
	 */
	if (hasmntopt(mnt, MNTOPT_PUBLIC) != NULL) {
		return (0);
	}

	/*
	 * The rest of this code is advisory to the server.
	 * If it fails return success anyway.
	 */

	list = parse_replica(mnt->mnt_special, &count);
	if (!list) {
		if (count >= 0)
			syslog(LOG_ERR,
			    "Memory allocation failed: %m");
		return (ENOMEM);
	}

	for (i = 0; i < count; i++) {

		host = list[i].host;
		path = list[i].path;

		/*
		 * Skip file systems mounted using WebNFS, because mount
		 * protocol was not used.
		 */
		if (strcmp(host, "nfs") == 0 && strncmp(path, "//", 2) == 0)
			continue;

		cl = clnt_create(host, MOUNTPROG, MOUNTVERS, "datagram_v");
		if (cl == NULL)
			break;
#ifdef MALLOC_DEBUG
		add_alloc("CLNT_HANDLE", cl, 0, __FILE__, __LINE__);
		add_alloc("AUTH_HANDLE", cl->cl_auth, 0,
			__FILE__, __LINE__);
#endif
		if (__clnt_bindresvport(cl) < 0) {
			if (verbose)
				syslog(LOG_ERR, "umount %s:%s: %s",
					host, path,
					"Couldn't bind to reserved port");
			destroy_auth_client_handle(cl);
			continue;
		}
#ifdef MALLOC_DEBUG
		drop_alloc("AUTH_HANDLE", cl->cl_auth, __FILE__, __LINE__);
#endif
		AUTH_DESTROY(cl->cl_auth);
		if ((cl->cl_auth = authsys_create_default()) == NULL) {
			if (verbose)
				syslog(LOG_ERR, "umount %s:%s: %s",
					host, path,
					"Failed creating default auth handle");
			destroy_auth_client_handle(cl);
			continue;
		}
#ifdef MALLOC_DEBUG
		add_alloc("AUTH_HANDLE", cl->cl_auth, 0, __FILE__, __LINE__);
#endif
		timeout.tv_usec = 0;
		timeout.tv_sec = 5;
		rpc_stat = clnt_call(cl, MOUNTPROC_UMNT, xdr_dirpath,
			    (caddr_t)&path, xdr_void, (char *)NULL, timeout);
		if (verbose && rpc_stat != RPC_SUCCESS)
			syslog(LOG_ERR, "%s: %s",
				host, clnt_sperror(cl, "unmount"));
		destroy_auth_client_handle(cl);
	}

	free_replica(list, count);

	if (trace > 1)
		trace_prt(1, "	nfsunmount: umount %s OK\n", mnt->mnt_mountp);

done:
	return (0);
}

/*
 * Put a new entry in the cache chain by prepending it to the front.
 * If there isn't enough memory then just give up.
 */
static void
cache_enter(host, reqvers, outvers, proto, state)
	char *host;
	rpcvers_t reqvers;
	rpcvers_t outvers;
	char *proto;
	int state;
{
	struct cache_entry *entry;
	int cache_time = 30;	/* sec */

	timenow = time(NULL);

	entry = (struct cache_entry *)malloc(sizeof (struct cache_entry));
	if (entry == NULL)
		return;
	(void) memset((caddr_t)entry, 0, sizeof (struct cache_entry));
	entry->cache_host = strdup(host);
	if (entry->cache_host == NULL) {
		cache_free(entry);
		return;
	}
	entry->cache_reqvers = reqvers;
	entry->cache_outvers = outvers;
	entry->cache_proto = (proto == NULL ? NULL : strdup(proto));
	entry->cache_state = state;
	entry->cache_time = timenow + cache_time;
	(void) rw_wrlock(&cache_lock);
#ifdef CACHE_DEBUG
	host_cache_accesses++;		/* up host cache access counter */
#endif /* CACHE DEBUG */
	entry->cache_next = cache_head;
	cache_head = entry;
	(void) rw_unlock(&cache_lock);
}

static int
cache_check(host, versp, proto)
	char *host;
	rpcvers_t *versp;
	char *proto;
{
	int state = NOHOST;
	struct cache_entry *ce, *prev;

	timenow = time(NULL);

	(void) rw_rdlock(&cache_lock);

#ifdef CACHE_DEBUG
	/* Increment the lookup and access counters for the host cache */
	host_cache_accesses++;
	host_cache_lookups++;
	if ((host_cache_lookups%1000) == 0)
		trace_host_cache();
#endif /* CACHE DEBUG */

	for (ce = cache_head; ce; ce = ce->cache_next) {
		if (timenow > ce->cache_time) {
			(void) rw_unlock(&cache_lock);
			(void) rw_wrlock(&cache_lock);
			for (prev = NULL, ce = cache_head; ce;
				prev = ce, ce = ce->cache_next) {
				if (timenow > ce->cache_time) {
					cache_free(ce);
					if (prev)
						prev->cache_next = NULL;
					else
						cache_head = NULL;
					break;
				}
			}
			(void) rw_unlock(&cache_lock);
			return (state);
		}
		if (strcmp(host, ce->cache_host) != 0)
			continue;
		if ((proto == NULL && ce->cache_proto != NULL) ||
		    (proto != NULL && ce->cache_proto == NULL))
			continue;
		if (proto != NULL &&
		    strcmp(proto, ce->cache_proto) != 0)
			continue;

		if (versp == NULL ||
			(versp != NULL && *versp == ce->cache_reqvers) ||
			(versp != NULL && *versp == ce->cache_outvers)) {
				if (versp != NULL)
					*versp = ce->cache_outvers;
				state = ce->cache_state;

				/* increment the host cache hit counters */
#ifdef CACHE_DEBUG
				if (state == GOODHOST)
					goodhost_cache_hits++;
				if (state == DEADHOST)
					deadhost_cache_hits++;
#endif /* CACHE_DEBUG */
				(void) rw_unlock(&cache_lock);
				return (state);
		}
	}
	(void) rw_unlock(&cache_lock);
	return (state);
}

/*
 * Free a cache entry and all entries
 * further down the chain since they
 * will also be expired.
 */
static void
cache_free(entry)
	struct cache_entry *entry;
{
	struct cache_entry *ce, *next = NULL;

	for (ce = entry; ce; ce = next) {
		if (ce->cache_host)
			free(ce->cache_host);
		if (ce->cache_proto)
			free(ce->cache_proto);
		next = ce->cache_next;
		free(ce);
	}
}

#ifdef MALLOC_DEBUG
void
cache_flush()
{
	(void) rw_wrlock(&cache_lock);
	cache_free(cache_head);
	cache_head = NULL;
	(void) rw_unlock(&cache_lock);
}

void
flush_caches()
{
	mutex_lock(&cleanup_lock);
	cond_signal(&cleanup_start_cv);
	(void) cond_wait(&cleanup_done_cv, &cleanup_lock);
	mutex_unlock(&cleanup_lock);
	cache_flush();
	portmap_cache_flush();
}
#endif

/*
 * Returns 1, if port option is NFS_PORT or
 *	nfsd is running on the port given
 * Returns 0, if both port is not NFS_PORT and nfsd is not
 *	running on the port.
 */

static int
is_nfs_port(char *opts)
{
	struct mnttab m;
	uint_t nfs_port = 0;
	struct servent sv;
	char buf[256];
	int got_port;

	m.mnt_mntopts = opts;

	/*
	 * Get port specified in options list, if any.
	 */
	got_port = nopt(&m, MNTOPT_PORT, (int *)&nfs_port);

	/*
	 * if no port specified or it is same as NFS_PORT return nfs
	 * To use any other daemon the port number should be different
	 */
	if (!got_port || nfs_port == NFS_PORT)
		return (1);
	/*
	 * If daemon is nfsd, return nfs
	 */
	if (getservbyport_r(nfs_port, NULL, &sv, buf, 256) == &sv &&
	    strcmp(sv.s_name, "nfsd") == 0)
		return (1);

	/*
	 * daemon is not nfs
	 */
	return (0);
}


/*
 * destroy_auth_client_handle(cl)
 * destroys the created client handle
 */
void
destroy_auth_client_handle(CLIENT *cl)
{
	if (cl) {
		if (cl->cl_auth) {
#ifdef MALLOC_DEBUG
			drop_alloc("AUTH_HANDLE", cl->cl_auth,
			    __FILE__, __LINE__);
#endif
			AUTH_DESTROY(cl->cl_auth);
			cl->cl_auth = NULL;
		}
#ifdef MALLOC_DEBUG
		drop_alloc("CLNT_HANDLE", cl,
		    __FILE__, __LINE__);
#endif
		clnt_destroy(cl);
	}
}


/*
 * Attempt to figure out which version of NFS to use in pingnfs().  If
 * the version number was specified (i.e., non-zero), then use it.
 * Otherwise, default to the compiled-in default or the default as set
 * by the /etc/default/nfs configuration (as read by read_default().
 */
int
set_versrange(rpcvers_t nfsvers, rpcvers_t *vers, rpcvers_t *versmin)
{
	switch (nfsvers) {
	case 0:
		*vers = vers_max_default;
		*versmin = vers_min_default;
		break;
	case NFS_V4:
		*vers = NFS_V4;
		*versmin = NFS_V4;
		break;
	case NFS_V3:
		*vers = NFS_V3;
		*versmin = NFS_V3;
		break;
	case NFS_VERSION:
		*vers = NFS_VERSION;		/* version 2 */
		*versmin = NFS_VERSMIN;		/* version 2 */
		break;
	default:
		return (-1);
	}
	return (0);
}

#ifdef CACHE_DEBUG
/*
 * trace_portmap_cache()
 * traces the portmap cache values at desired points
 */
static void
trace_portmap_cache()
{
	syslog(LOG_ERR, "portmap_cache: accesses=%d lookups=%d hits=%d\n",
	    portmap_cache_accesses, portmap_cache_lookups,
	    portmap_cache_hits);
}

/*
 * trace_host_cache()
 * traces the host cache values at desired points
 */
static void
trace_host_cache()
{
	syslog(LOG_ERR,
	    "host_cache: accesses=%d lookups=%d deadhits=%d goodhits=%d\n",
	    host_cache_accesses, host_cache_lookups, deadhost_cache_hits,
	    goodhost_cache_hits);
}
#endif /* CACHE_DEBUG */

/*
 * Read the NFS SMF properties to determine if the
 * client has been configured for a new min/max for the NFS version to
 * use.
 */

#define	SVC_NFS_CLIENT	"svc:/network/nfs/client"

static void
read_default_nfs(void)
{
	static time_t lastread = 0;
	struct stat buf;
	char defval[4];
	int errno, bufsz;
	int tmp, ret = 0;

	bufsz = 4;
	ret = nfs_smf_get_prop("client_versmin", defval, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, SVC_NFS_CLIENT, &bufsz);
	if (ret == SA_OK) {
		errno = 0;
		tmp = strtol(defval, (char **)NULL, 10);
		if (errno == 0) {
			vers_min_default = tmp;
		}
	}

	bufsz = 4;
	ret = nfs_smf_get_prop("client_versmax", defval, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, SVC_NFS_CLIENT, &bufsz);
	if (ret == SA_OK) {
		errno = 0;
		tmp = strtol(defval, (char **)NULL, 10);
		if (errno == 0) {
			vers_max_default = tmp;
		}
	}

	lastread = buf.st_mtime;

	/*
	 * Quick sanity check on the values picked up from the
	 * defaults file.  Make sure that a mistake wasn't
	 * made that will confuse things later on.
	 * If so, reset to compiled-in defaults
	 */
	if (vers_min_default > vers_max_default ||
	    vers_min_default < NFS_VERSMIN ||
	    vers_max_default > NFS_VERSMAX) {
		if (trace > 1) {
			trace_prt(1,
	"  read_default: version minimum/maximum incorrectly configured\n");
			trace_prt(1,
"  read_default: config is min=%d, max%d. Resetting to min=%d, max%d\n",
			    vers_min_default, vers_max_default,
			    NFS_VERSMIN_DEFAULT,
			    NFS_VERSMAX_DEFAULT);
		}
		vers_min_default = NFS_VERSMIN_DEFAULT;
		vers_max_default = NFS_VERSMAX_DEFAULT;
	}
}

/*
 *  Find the mnttab entry that corresponds to "name".
 *  We're not sure what the name represents: either
 *  a mountpoint name, or a special name (server:/path).
 *  Return the last entry in the file that matches.
 */
static struct extmnttab *
mnttab_find(dirname)
	char *dirname;
{
	FILE *fp;
	struct extmnttab mnt;
	struct extmnttab *res = NULL;

	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		if (trace > 1)
			trace_prt(1, "	mnttab_find: unable to open mnttab\n");
		return (NULL);
	}
	while (getextmntent(fp, &mnt, sizeof (struct extmnttab)) == 0) {
		if (strcmp(mnt.mnt_mountp, dirname) == 0 ||
		    strcmp(mnt.mnt_special, dirname) == 0) {
			if (res)
				fsfreemnttab(res);
			res = fsdupmnttab(&mnt);
		}
	}

	resetmnttab(fp);
	fclose(fp);
	if (res == NULL) {
		if (trace > 1)
			trace_prt(1, "	mnttab_find: unable to find %s\n",
				dirname);
	}
	return (res);
}

/*
 * This function's behavior is taken from nfsstat.
 * Trying to determine what NFS version was used for the mount.
 */
static int
is_v4_mount(char *mntpath)
{
	kstat_ctl_t *kc = NULL;		/* libkstat cookie */
	kstat_t *ksp;
	ulong_t fsid;
	struct mntinfo_kstat mik;
	struct extmnttab *mntp;
	uint_t mnt_minor;

	if ((mntp = mnttab_find(mntpath)) == NULL)
		return (FALSE);

	/* save the minor number and free the struct so we don't forget */
	mnt_minor = mntp->mnt_minor;
	fsfreemnttab(mntp);

	if ((kc = kstat_open()) == NULL)
		return (FALSE);

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if (ksp->ks_type != KSTAT_TYPE_RAW)
			continue;
		if (strcmp(ksp->ks_module, "nfs") != 0)
			continue;
		if (strcmp(ksp->ks_name, "mntinfo") != 0)
			continue;
		if (mnt_minor != ksp->ks_instance)
			continue;

		if (kstat_read(kc, ksp, &mik) == -1)
			continue;

		(void) kstat_close(kc);
		if (mik.mik_vers == 4)
			return (TRUE);
		else
			return (FALSE);
	}
	(void) kstat_close(kc);

	return (FALSE);
}

static int
create_homedir(const char *src, const char *dst) {

	struct stat stbuf;
	char *dst_username;
	struct passwd *pwd, pwds;
	char buf_pwd[NSS_BUFLEN_PASSWD];
	int homedir_len;
	int dst_dir_len;
	int src_dir_len;

	if (trace > 1)
		trace_prt(1, "entered create_homedir\n");

	if (stat(src, &stbuf) == 0) {
		if (trace > 1)
			trace_prt(1, "src exists\n");
		return (1);
	}

	dst_username = strrchr(dst, '/');
	if (dst_username) {
		dst_username++; /* Skip over slash */
		pwd = getpwnam_r(dst_username, &pwds, buf_pwd,
		    sizeof (buf_pwd));
		if (pwd == NULL) {
			return (0);
		}
	} else {
		return (0);
	}

	homedir_len = strlen(pwd->pw_dir);
	dst_dir_len = strlen(dst) - homedir_len;
	src_dir_len = strlen(src) - homedir_len;

	/* Check that the paths are in the same zone */
	if (src_dir_len < dst_dir_len ||
	    (strncmp(dst, src, dst_dir_len) != 0)) {
		if (trace > 1)
			trace_prt(1, "	paths don't match\n");
		return (0);
	}
	/* Check that mountpoint is an auto_home entry */
	if (dst_dir_len < 0 ||
	    (strcmp(pwd->pw_dir, dst + dst_dir_len) != 0)) {
		return (0);
	}

	/* Check that source is an home directory entry */
	if (src_dir_len < 0 ||
	    (strcmp(pwd->pw_dir, src + src_dir_len) != 0)) {
		if (trace > 1)
			trace_prt(1, "	homedir (2) doesn't match %s\n",
		src+src_dir_len);
		return (0);
	}

	if (mkdir(src,
	    S_IRUSR | S_IWUSR | S_IXUSR | S_IXGRP | S_IXOTH) == -1) {
		if (trace > 1) {
			trace_prt(1, "	Couldn't mkdir %s\n", src);
		}
		return (0);
	}

	if (chown(src, pwd->pw_uid, pwd->pw_gid) == -1) {
		unlink(src);
		return (0);
	}

	/* Created new home directory for the user */
	return (1);
}

void
free_nfs_args(struct nfs_args *argp)
{
	struct nfs_args *oldp;
	while (argp) {
		if (argp->pathconf)
			free(argp->pathconf);
		if (argp->knconf)
			free_knconf(argp->knconf);
		if (argp->addr)
			netbuf_free(argp->addr);
		if (argp->syncaddr)
			netbuf_free(argp->syncaddr);
		if (argp->netname)
			free(argp->netname);
		if (argp->hostname)
			free(argp->hostname);
		if (argp->nfs_ext_u.nfs_extB.secdata)
			nfs_free_secdata(argp->nfs_ext_u.nfs_extB.secdata);
		if (argp->fh)
			free(argp->fh);
		if (argp->nfs_ext_u.nfs_extA.secdata) {
			sec_data_t	*sd;
			sd = argp->nfs_ext_u.nfs_extA.secdata;
			if (sd == NULL)
				break;
			switch (sd->rpcflavor) {
			case AUTH_NONE:
			case AUTH_UNIX:
			case AUTH_LOOPBACK:
				break;
			case AUTH_DES:
			{
				dh_k4_clntdata_t	*dhk4;
				dhk4 = (dh_k4_clntdata_t *)sd->data;
				if (dhk4 == NULL)
					break;
				if (dhk4->syncaddr.buf)
					free(dhk4->syncaddr.buf);
				if (dhk4->knconf->knc_protofmly)
					free(dhk4->knconf->knc_protofmly);
				if (dhk4->knconf->knc_proto)
					free(dhk4->knconf->knc_proto);
				if (dhk4->knconf)
					free(dhk4->knconf);
				if (dhk4->netname)
					free(dhk4->netname);
				free(dhk4);
				break;
			}
			case RPCSEC_GSS:
			{
				gss_clntdata_t	*gss;
				gss = (gss_clntdata_t *)sd->data;
				if (gss == NULL)
					break;
				if (gss->mechanism.elements)
					free(gss->mechanism.elements);
				free(gss);
				break;
			}
			}
		}
		oldp = argp;
		if (argp->nfs_args_ext == NFS_ARGS_EXTB)
			argp = argp->nfs_ext_u.nfs_extB.next;
		else
			argp = NULL;
		free(oldp);
	}
}

void *
get_netconfig_info(enum type_of_stuff type_of_stuff, char *hostname,
	rpcprog_t prog, rpcvers_t vers, struct netconfig *nconf,
	ushort_t port, struct t_info *tinfo, struct t_bind *tbind,
	caddr_t *fhp, bool_t direct_to_server, char *fspath,
	enum clnt_stat *cstat, mfs_snego_t *mfssnego)
{
	struct netconfig *nb = NULL;
	int ping_server = 0;


	if (nconf == NULL)
		return (NULL);

	switch (type_of_stuff) {
	case SERVER_FH:
		nb = get_server_fh(hostname, prog, vers, mfssnego,
		    nconf, port, tinfo, tbind, fhp, direct_to_server,
		    fspath, cstat);
		break;
	case SERVER_PING:
		ping_server = 1;
	case SERVER_ADDR:
		nb = get_server_addrorping(hostname, prog, vers,
		    nconf, port, tinfo, tbind, fhp, direct_to_server,
		    fspath, cstat, ping_server);
		break;
	default:
		assert(nb != NULL);
	}
	return (nb);
}

/*
 * Get the server address or can we ping it or not.
 * Check the portmap cache first for server address.
 * If no entries there, ping the server with a NULLPROC rpc.
 */
void *
get_server_addrorping(char *hostname, rpcprog_t prog, rpcvers_t vers,
	struct netconfig *nconf, ushort_t port, struct t_info *tinfo,
	struct t_bind *tbind, caddr_t *fhp, bool_t direct_to_server,
	char *fspath, enum clnt_stat *cstat, int ping_server)
{
	struct timeval tv;
	enum clnt_stat cs = RPC_TIMEDOUT;
	struct netbuf *nb = NULL;
	CLIENT *cl = NULL;
	int fd = -1;

	if (prog == NFS_PROGRAM && vers == NFS_V4)
		if (strncasecmp(nconf->nc_proto, NC_UDP, strlen(NC_UDP)) == 0)
			goto done;

	if ((fd = t_open(nconf->nc_device, O_RDWR, tinfo)) < 0) {
		goto done;
	}

	/* LINTED pointer alignment */
	if ((tbind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR))
	    == NULL) {
		goto done;
	}

	if (direct_to_server != TRUE) {
		if (!ping_server) {
			if (get_cached_srv_addr(hostname, prog, vers,
			    nconf, &tbind->addr) == 0)
				goto done;
		} else {
			if (port == 0)
				goto done;
		}
	}
	if (setup_nb_parms(nconf, tbind, tinfo, hostname,
	    fd, direct_to_server, port, prog, vers, 0) < 0)
		goto done;

	if (port || (direct_to_server == TRUE)) {
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		cl = clnt_tli_create(fd, nconf, &tbind->addr,
		    prog, vers, 0, 0);
		if (cl == NULL)
			goto done;

		cs = clnt_call(cl, NULLPROC, xdr_void, 0,
		    xdr_void, 0, tv);
		if (cs != RPC_SUCCESS) {
			syslog(LOG_ERR, "error is %d", cs);
			goto done;
		}
	}
	if (!ping_server) {
		nb = (struct netbuf *)malloc(sizeof (struct netbuf));
		if (nb == NULL) {
			syslog(LOG_ERR, "no memory\n");
			goto done;
		}
		nb->buf = (char *)malloc(tbind->addr.maxlen);
		if (nb->buf == NULL) {
			syslog(LOG_ERR, "no memory\n");
			free(nb);
			nb = NULL;
			goto done;
		}
		(void) memcpy(nb->buf, tbind->addr.buf, tbind->addr.len);
		nb->len = tbind->addr.len;
		nb->maxlen = tbind->addr.maxlen;
		cs = RPC_SUCCESS;
	}
done:
	destroy_auth_client_handle(cl);
	cleanup_tli_parms(tbind, fd);
	*cstat = cs;
	return (nb);
}
