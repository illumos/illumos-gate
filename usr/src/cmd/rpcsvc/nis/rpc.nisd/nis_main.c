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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nis_main.c
 *
 * This is the main() module for the NIS+ service. It is compiled separately
 * so that the service can parse certain options and initialize the database
 * before starting up.
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include <syslog.h>
#include <signal.h>
#include <ucontext.h>
#include <time.h>
#include <string.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_db.h>
#include <dirent.h>
#include "nis_svc.h"
#include "nis_proc.h"
#include "log.h"
#include <stropts.h>
#include <poll.h>
#include <limits.h>
#include <rpcsvc/nis_dhext.h>
#include <ldap_parse.h>
#include <ldap_util.h>
#include <values.h>
#include <unistd.h>


/* Default size for the RPC credential cache */
#define	CRED_CACHESZ_DEF	1024

#ifdef MEM_DEBUG
extern void init_malloc();
extern void xdump();
#endif

FILE	*cons = NULL;
extern int (*__clear_directory_ptr)(nis_name);
extern int clear_directory(nis_name);

#define	invalid_directory	(__nis_get_tsd()->invalid_directory)

/* Defined in nis_log_common.c */
extern int need_checkpoint; /* The log is "dirty"    */
extern pid_t master_pid;	/* Master PROCESS id */

int _rpcsvcdirty;
int max_children 	= 128;  /* Very large number 			*/
int secure_level 	= 2;	/* Security level 2 = max supported  	*/
int force_checkpoint	= 0;	/* Set when we wish to force a c.p. op	*/
int checkpoint_all	= 0;	/* Set when we wish to cp entire db	*/
int readonly		= 0;	/* When true the service is "read only" */
int readonly_pid	= 0;	/* Our child who is watching out for us */
int hup_received	= 0;	/* To tell us when to exit 		*/
int auth_verbose	= 0;	/* Messages on auth info		*/
int resolv_pid		= 0;	/* Resolv server pid 			*/
CLIENT *resolv_client	= NULL; /* Resolv client handle			*/
char *resolv_tp	= "ticots";	/* Resolv netid used on resolv_setup()  */
struct timeval start_time;	/* Time service started running.	*/
extern unsigned long __maxloglen; /* maximum transaction log size */
unsigned int heap_start;	/* sbrk(0) at start of time */

extern uint_t	next_refresh;	/* next time to re-load dot file */

#ifdef DEBUG
int debug		= 1;
#else
int debug		= 0;
#endif

struct upd_log	*nis_log;	/* Pointer to the mmap'd log.   	*/

extern int optind, opterr;
extern char *optarg;

extern nis_object* get_root_object();
extern cp_result *do_checkpoint();

extern void nis_prog_svc();
extern void ypprog_svc();
extern void ypprog_1();

/* routines for update timestamp cache */
extern void init_updatetime();

extern void		*__nis_lock_db_directory(nis_name, int, int *, char *);
extern int		__nis_ulock_db_directory(nis_name, int, int, char *);
extern db_status	db_defer(nis_name);
extern db_status	db_commit(nis_name);
extern db_status	db_rollback(nis_name);

/*
 * Global state variables, these variables contain information about the
 * state of the server.
 */
int verbose = 0;		/* Verbose mode, LOG_INFO messages are 	*/
				/* generated for most functions.	*/
int root_server = 0;		/* TRUE if this server is a root server	*/
int static_root = 0;		/* TRUE if the network is partitioned.	*/
int emulate_yp	= FALSE;	/* NIS compat mode or not		*/
int resolv_flag	= 0;		/* Resolv on no host match		*/
int tflag	= FALSE;	/* command-line option 't'		*/
NIS_HASH_TABLE ping_list = NIS_HASH_TABLE_MT_INIT;
				/* List of directory names that need to */
				/* be notified of updates		*/
int ping_pid	= 0;		/* Pinger pid for pinger process	*/
NIS_HASH_TABLE upd_list = NIS_HASH_TABLE_MT_INIT;
				/* List of directory names that have    */
				/* pending updates 			*/
ulong_t cp_time = 0;		/* Time of last checkpoint		*/
NIS_HASH_TABLE checkpoint_list = NIS_HASH_TABLE_MT_INIT;
				/* List of directory names that have    */
				/* pending checkpoint 			*/

static void
timetodie(proc)
int	proc;
{
	hup_received = 1;
}

void
check_updaters()
{
	ping_item	*pp, *nxt;
	int		pid;
	ulong_t		lu, curtime = ~0UL;
	struct sigaction sigactn;
	int		pending_updates = 0;
	struct timeval	tp;
	NIS_HASH_TABLE	tmpupd;
	ping_item	*tmppp;

	/* Check if any item on the list is due for update */
	if (gettimeofday(&tp, 0) != -1) {
		curtime = tp.tv_sec;
		__nis_init_hash_table(&tmpupd, 0);
		LOCK_LIST(&upd_list, "check_updaters(upd_list)");
		for (pp = (ping_item *)(upd_list.first); pp != 0; pp = nxt) {
			nxt = (ping_item *)(pp->item.nxt_item);
			if (pp->utime <= curtime) {
				pending_updates = 1;
				/* Save a copy on the local list */
				tmppp = malloc(sizeof (*tmppp));
				if (tmppp != NULL) {
					/* Copy pointers OK */
					*tmppp = *pp;
					(void) __nis_insert_item_mt(tmppp,
								&tmpupd, 0);
				}
#ifdef	NIS_MT_DEBUG
				else {
					abort();
				}
#endif	/* NIS_MT_DEBUG */
			}
		}
		ULOCK_LIST(&upd_list, "check_updaters(upd_list)");
		if (!pending_updates) {
			if (verbose)
				syslog(LOG_INFO,
					"check_updaters: no pending updates");
			return;
		}
	}

	if (cons)
		fprintf(cons, "check_updaters : starting resync\n");
	if (verbose) {
		syslog(LOG_INFO, "check_updaters: Starting resync.");
	}
	for (pp = (ping_item *)(tmpupd.first); pp; pp = nxt) {
		nxt = (ping_item *)(pp->item.nxt_item);
		lu = last_update(pp->item.name);
		if (cons)
			fprintf(cons, "check_updaters : update %s\n",
				pp->item.name);
		if ((pp->mtime > lu) && (pp->utime <= curtime)) {
			if (replica_update(pp)) {
				tmppp = nis_remove_item(pp->item.name,
							&upd_list);
				if (tmppp != NULL) {
					XFREE(tmppp->item.name);
					if (tmppp->obj)
						nis_destroy_object(tmppp->obj);
					XFREE(tmppp);
				}
				/* The 'tmpupd' list is purged later */
			} else {
				/*
				 * No use continuously retrying, so backoff
				 * exponentially.
				 */
				tmppp = pp;
				pp = __nis_find_item_mt(pp->item.name,
						&upd_list, -1, NULL);
				if (pp != NULL) {
				if (curtime != ~0UL)
					pp->utime = curtime + pp->delta;
				pp->delta *= 2;
				if (pp->delta > MAX_UPD_LIST_TIME_INCR) {
					pp->delta = MAX_UPD_LIST_TIME_INCR;
					if (cons)
						fprintf(cons,
				"check_updaters: unable to resync %s\n",
							pp->item.name);
					syslog(LOG_WARNING,
				"check_updaters: unable to resync %s",
						pp->item.name);
				}
					(void) __nis_release_item(pp, &upd_list,
									-1);
				}
				pp = tmppp;
			}
		} else if (pp->mtime <= lu) {
			tmppp = nis_remove_item(pp->item.name, &upd_list);
			if (tmppp != NULL) {
				XFREE(tmppp->item.name);
				if (tmppp->obj)
					nis_destroy_object(tmppp->obj);
				XFREE(tmppp);
			}
		}
	}
	/*
	 * We just copied the 'item.name' and 'obj' pointers for the
	 * elements in the 'tmpupd' list, so we only need to free the
	 * list elements themselves.
	 */
	for (pp = (ping_item *)tmpupd.first; pp != NULL; pp = tmppp) {
		tmppp = (ping_item *)pp->item.nxt_item;
		free(pp);
	}
}

void
check_pingers()
{
	ping_item	*pp, *nxt;
	struct timeval	ctime;

	LOCK_LIST(&ping_list, "check_pingers(ping_list)");
	if (ping_list.first == NULL) {
		ULOCK_LIST(&ping_list, "check_pingers(ping_list)");
		return;
	}

	gettimeofday(&ctime, 0);
	if (cons)
		fprintf(cons, "check_pingers : \n");
	for (pp = (ping_item *)ping_list.first; pp; pp = nxt) {
		/* save next pointer in case we remove it */
		nxt = (ping_item *)(pp->item.nxt_item);

		if ((pp->mtime + updateBatchingTimeout()) > ctime.tv_sec)
			continue;

		if (verbose && cons)
			fprintf(cons, "check_pingers: ping %s\n",
				pp->item.name);

/*
 *	A successful return from ping_replicas() means that
 *	a ping request has been sent to the replicas. It does
 *	not ensures that replica has indeed received the ping
 *	request.
 */
		nis_remove_item(pp->item.name, &ping_list);
		if (!ping_replicas(pp))
			nis_insert_item((NIS_HASH_ITEM *)pp, &ping_list);
	}
	ULOCK_LIST(&ping_list, "check_pingers(ping_list)");
}

#include <netconfig.h>

extern int	__rpc_bindresvport_ipv6(int, struct sockaddr *, int *, int,
					char *);

/*
 * A modified version of svc_tp_create().  The difference is that
 * nis_svc_tp_create() will try to bind to a privilege port if the
 * the server is to emulate YP and it's using the INET[6] protocol family.
 *
 * The high level interface to svc_tli_create().
 * It tries to create a server for "nconf" and registers the service
 * with the rpcbind. It calls svc_tli_create();
 */
static SVCXPRT *
nis_svc_tp_create(dispatch, prognum, versnum, nconf)
	void (*dispatch)();	/* Dispatch function */
	ulong_t prognum;	/* Program number */
	ulong_t versnum;	/* Version number */
	struct netconfig *nconf; /* Netconfig structure for the network */
{
	SVCXPRT *xprt;
	int	fd;
	struct t_info tinfo;

	if (nconf == (struct netconfig *)NULL) {
		(void) syslog(LOG_ERR,
	"nis_svc_tp_create: invalid netconfig structure for prog %d vers %d",
				prognum, versnum);
		return ((SVCXPRT *)NULL);
	}
	fd = RPC_ANYFD;
	if ((emulate_yp) && (strcmp(nconf->nc_protofmly, NC_INET) == 0 ||
				strcmp(nconf->nc_protofmly, NC_INET6) == 0)) {
		fd = t_open(nconf->nc_device, O_RDWR, &tinfo);
		if (fd == -1) {
			(void) syslog(LOG_ERR,
			"nis_svc_tp_create: could not open connection for %s",
					nconf->nc_netid);
			return ((SVCXPRT *)NULL);
		}
		if (__rpc_bindresvport_ipv6(fd, (struct sockaddr *)NULL,
						(int *)NULL, 8,
						nconf->nc_protofmly) == -1) {
			(void) t_close(fd);
			fd = RPC_ANYFD;
		}
	}
	xprt = svc_tli_create(fd, nconf, (struct t_bind *)NULL, 0, 0);
	if (xprt == (SVCXPRT *)NULL) {
		return ((SVCXPRT *)NULL);
	}
	(void) rpcb_unset(prognum, versnum, nconf);
	if (svc_reg(xprt, prognum, versnum, dispatch, nconf) == FALSE) {
		(void) syslog(LOG_ERR,
		"nis_svc_tp_create: Could not register prog %d vers %d on %s",
				prognum, versnum, nconf->nc_netid);
		SVC_DESTROY(xprt);
		return ((SVCXPRT *)NULL);
	}
	return (xprt);
}

/*
 * Modified version of 'svc_create' that maintains list of handles.
 * The only difference between this and svc_create is that
 * 1.	nis_svc_create maintains the list of handles created so that they
 *	can be reused later for re-registeration.
 *	This is required for nis_put_offline.
 * 2.	nis_svc_create uses the public netconfig interfaces, instead of
 *	 private rpc interfaces.
 */
struct xlist {
	SVCXPRT *xprt;		/* Server handle */
	struct xlist *next;	/* Next item */
};

/*
 * Note: nis_xprtlist is only used in nis_svc_create() and nis_svc_reg()
 *	 below. Since nis_svc_create() is used only in the initial,
 *	 single-threaded, phase of the rpc.nisd, no synchronization is
 *	 needed.
 */

/* A link list of all the handles */
static struct xlist *nis_xprtlist = (struct xlist *)NULL;

static int
nis_svc_create(dispatch, prognum, versnum, target_nc_flag)
	void (*dispatch)();	/* Dispatch function */
	ulong_t prognum;	/* Program number */
	ulong_t versnum;	/* Version number */
	unsigned target_nc_flag;  /* value of netconfig flag */
{
	struct xlist *l;
	int num = 0;
	SVCXPRT *xprt;
	struct netconfig *nconf;
	NCONF_HANDLE *handle;

	if ((handle = setnetconfig()) == NULL) {
		(void) syslog(LOG_ERR,
			"nis_svc_create: could not get netconfig information");
		return (0);
	}
	while (nconf = getnetconfig(handle)) {
		if (!(nconf->nc_flag & target_nc_flag))
			continue;
		for (l = nis_xprtlist; l; l = l->next) {
			if (strcmp(l->xprt->xp_netid, nconf->nc_netid) == 0) {
				/* Found an old one, use it */
				(void) rpcb_unset(prognum, versnum, nconf);
				if (svc_reg(l->xprt, prognum, versnum,
					dispatch, nconf) == FALSE)
					(void) syslog(LOG_ERR,
		"nis_svc_create: could not register prog %d vers %d on %s",
					prognum, versnum, nconf->nc_netid);
				else
					num++;
				break;
			}
		}
		if (l == (struct xlist *)NULL) {
			/* It was not found. Now create a new one */
			xprt = nis_svc_tp_create(dispatch, prognum,
							versnum, nconf);
			if (xprt) {
				l = (struct xlist *)malloc(sizeof (*l));
				if (l == (struct xlist *)NULL) {
					(void) syslog(LOG_ERR,
						"nis_svc_create: no memory");
					return (0);
				}
				l->xprt = xprt;
				l->next = nis_xprtlist;
				nis_xprtlist = l;
				num++;
			}
		}
	}
	endnetconfig(handle);
	/*
	 * In case of num == 0; the error messages are generated by the
	 * underlying layers; and hence not needed here.
	 */
	return (num);
}

/*
 * Establish resync service for the specified directory, per the
 * nisplusLDAPresyncService and nisplusLDAPdumpError configuration
 * attributes.
 */
db_status
nis_put_offline(nis_name dirname, bool_t fullDump)
{
	db_status	stat = DB_SUCCESS;

	switch (ldapConfig.resyncService) {

	case directory_locked:
		if (!fullDump) {
			/* Write lock the specified directory */
			if (__nis_lock_db_directory(dirname, -1, 0, dirname) ==
					NULL) {
				if (verbose)
					syslog(LOG_ERR,
			"nis_put_offline: Error locking \"%s\"", dirname);
#ifdef	NIS_MT_DEBUG
				abort();
#endif	/* NIS_MT_DEBUG */
			}
			break;
		}
		/* Else, if full dump, fall through to 'from_copy' */

	case from_copy:
		/*
		 * Defer changes for the directory.
		 */
		stat = db_defer(dirname);
		break;

	case from_live:
		/* Nothing to do */
		break;

	default:
#ifdef	NIS_MT_DEBUG
		abort();
#endif	/* NIS_MT_DEBUG */
		stat = DB_INTERNAL_ERROR;
		break;
	}

	return (stat);
}

/*
 * Resume full service for specified directory
 */
db_status
nis_put_online(nis_name dirname, __nis_defer_t commitAction, bool_t fullDump)
{
	char		*dirl, *curdir, *nxtdir;
	int		ret = 1;
	db_status	stat = DB_SUCCESS;

	switch (ldapConfig.resyncService) {

	case directory_locked:
		if (!fullDump) {
			/* Unlock the directory */
			if (!__nis_ulock_db_directory(dirname, -1, 0,
					dirname)) {
				if (verbose)
					syslog(LOG_ERR,
			"nis_put_online: Error unlocking \"%s\"", dirname);
#ifdef	NIS_MT_DEBUG
				abort();
#endif	/* NIS_MT_DEBUG */
			}
			break;
		}
		/* Else, if full dump, fall through to 'from_copy' */

	case from_copy:
		/* Commit or rollback */
		if (commitAction == d_commit)
			stat = db_commit(dirname);
		else if (commitAction == d_rollback)
			stat = db_rollback(dirname);
		else {
			stat = DB_BADQUERY;
#ifdef	NIS_MT_DEBUG
			abort();
#endif	/* NIS_MT_DEBUG */
		}
		break;

	case from_live:
		/* Nothing to do */
		break;

	default:
#ifdef	NIS_MT_DEBUG
		abort();
#endif	/* NIS_MT_DEBUG */
		break;
	}

	return (stat);
}

static void
update_cache_data(nis_object* root_obj)
{
	/* make sure the cache data is accurate */
	writeColdStartFile(&(root_obj->DI_data));
	__nis_CacheRestart();
}

static void
print_options()
{
	fprintf(stderr, "Options supported by this version :\n");
	fprintf(stderr, "\th - print this help message.\n");
	fprintf(stderr, "\tC - open diagnostic channel on /dev/console\n");
	fprintf(stderr, "\tF - force checkpoint at startup time\n");
	fprintf(stderr, "\tA - authentication verbose messages\n");
	fprintf(stderr, "\tL [n] - Max load (n) of child processes\n");
	fprintf(stderr, "\tf - force registration even if program # in use\n");
	fprintf(stderr, "\tv - enable verbose mode\n");
	fprintf(stderr, "\tY - emulate NIS (YP) service\n");
	fprintf(stderr, "\tB - emulate NIS (YP) dns resolver service\n");
	fprintf(stderr, "\tt netid - use netid as transport for resolver\n");
	fprintf(stderr, "\td [dictionary] - user defined dictionary\n");
	fprintf(stderr, "\tS [n] - Security level (n) 0,1, or 2\n");
	fprintf(stderr, "\tD - debug mode (don't fork)\n");
	fprintf(stderr, "\tc - checkpoint time in seconds (ignored)\n");
	fprintf(stderr, "\tT n - Size of transaction log in megabytes\n");
	fprintf(stderr, "\tm file - Name of LDAP mapping config file\n");
	fprintf(stderr, "\tx attr=val - Configuration attribute name/value\n");
	fprintf(stderr, "\tz n - Maximum rpc record size in bytes (>= %d)\n",
		RPC_MAXDATASIZE);
	exit(0);
}

/*
 * Loop thru mech list from security conf file and set
 * the RPC GSS service name(s).  Stop processing list if
 * the classic AUTH_DES compat entry is encountered.
 */
static void
set_rpc_gss_svc_names()
{
	mechanism_t **mechs;

	if (mechs = __nis_get_mechanisms(FALSE)) {
		int		slen;
		mechanism_t	**mpp;
		char		svc_name[NIS_MAXNAMELEN+1];
		char		*lh = nis_local_host();

		if (! lh) {
			syslog(LOG_ERR,
		"can't set RPC GSS service name:  can't get local host name");
			__nis_release_mechanisms(mechs);
			return;
		}

		/* '@' + NUL = 2 */
		if (strlen(lh) + strlen(NIS_SVCNAME_NISD) + 2 >
							sizeof (svc_name)) {
			syslog(LOG_ERR,
		"can't set RPC GSS service name:  svc_name bufsize too small");
			__nis_release_mechanisms(mechs);
			return;
		}
		/* service names are of the form svc@server.dom */
		(void) sprintf(svc_name, "%s@%s", NIS_SVCNAME_NISD, lh);
		/* remove trailing '.' */
		slen = strlen(svc_name);
		if (svc_name[slen - 1] == '.')
			svc_name[slen - 1] = '\0';

		for (mpp = mechs; *mpp; mpp++) {
			mechanism_t *mp = *mpp;

			if (AUTH_DES_COMPAT_CHK(mp))
				break;

			if (! VALID_MECH_ENTRY(mp)) {
				syslog(LOG_ERR,
					"%s: invalid mechanism entry name '%s'",
					NIS_SEC_CF_PATHNAME,
					mp->mechname ? mp->mechname : "NULL");
				continue;
			}

			if (rpc_gss_set_svc_name(svc_name, mp->mechname,
							0, NIS_PROG,
							NIS_VERSION)) {
				if (verbose)
					syslog(LOG_INFO,
				"RPC GSS service name for mech '%s' set",
						mp->mechname);
			} else {
				if (secure_level > 1) {
					rpc_gss_error_t	err;

					rpc_gss_get_error(&err);
					syslog(LOG_ERR,
"can't set RPC GSS svc name '%s' for mech '%s': RPC GSS err = %d, sys err = %d",
						svc_name, mp->mechname,
						err.rpc_gss_error,
						err.system_error);
				} else {
					if (verbose)
						syslog(LOG_INFO,
				"can't set RPC GSS service name for mech '%s'",
								mp->mechname);
				}
			}
		}
		__nis_release_mechanisms(mechs);
		return;
	}
}

int
main(int argc, char *argv[])
{
	int			status = 0, i, c;
	nis_object		*rootobj;
	char			buf[80];
	char			logname[80];
	struct stat 		s;
	char			*dict = NULL;
	int			pid;
	int			force = 0, mb;
	struct rlimit		rl;
	int			open_console = 0;
	struct sigaction	sigactn;
	bool_t			massage_dict;
	sigset_t		new_mask;
	int			sig_recvd;
	int cred_cache = 0;
	int rpc_irtimeout = -1;
	int			concurrency = -1;
	char			*ldapConfFile = 0;
	char			**ldapCLA = 0;
	int			numLA = 0;

	/*
	 * increase the internal RPC server cache size to 1024.
	 * If it fails to increase, then just use the default (=128).
	 */

	int connmaxrec = -1;
	int fdlmtremove = 8192;

	/*
	 *  We cannot use the shared directory cache yet (possible
	 *  deadlock), so we start up the local cache.
	 */
	(void) __nis_CacheLocalInit(&next_refresh);

	/* Set number of file descriptors to unlimited */

	if (!rpc_control(RPC_SVC_USE_POLLFD, &fdlmtremove)) {
		syslog(LOG_ERR,
			"unable to set RPC file descriptors to unlimited");
	}


	/*
	 * __clear_directory_ptr is a global defined in libnsl.
	 * We need to set this here so that clear_directory() be called from
	 * within nis_dump. This is part of the servers serving stale data
	 * bug fix. See 1179965.
	 */
	__clear_directory_ptr = &clear_directory;

	/*
	 *  Make sure that files created by stdio do not have
	 *  extra permission.  We allow group read, but we don't
	 *  allow world to read or write.  We disallow write for
	 *  obvious reasons, but also disallow read so that
	 *  tables can't be read by world (thus bypassing the
	 *  NIS+ access controls.
	 */
	(void) umask(027);

	heap_start = (unsigned int) sbrk(0); /* before any allocs */

	/*
	 * Process the command line arguments
	 */
	opterr = 0;
	chdir("/var/nis");
	while ((c = getopt(argc, argv, "hCFDAL:fvYBS:rd:T:t:p:i:n:m:x:z:")) !=
		-1) {
		switch (c) {
			case 'h' : /* internal help screen */
				print_options();
				break;
			case 'T' :
				mb = atoi(optarg);
				if ((mb < 4) || (mb > 129)) {
					fprintf(stderr, "Illegal log size.\n");
					exit(1);
				}
				__maxloglen = mb * 1024 * 1024;
				break;

			case 'C' :
				open_console++;
				break;
			case 'F' :
				force_checkpoint = TRUE;
				need_checkpoint = TRUE;
				break;
			case 'A' :
				auth_verbose++;
				break;
			case 'Y' :
				emulate_yp = TRUE;
				break;
			case 'B' :
				resolv_flag = TRUE;
				break;
			case 't' :
				tflag = TRUE;
				resolv_tp = optarg;
				break;
			case 'v' :
				verbose = 1;
				break;
			case 'd' :
				dict = optarg;
				break;
			case 'S' :
				secure_level = atoi(optarg);
				break;
			case 'r' :
				/* obsolete option */
				root_server = -1;
				fprintf(stderr,
"The -r option is obsolete and no longer necessary for root servers.\n");
				break;
			case 'f' :
				force = TRUE;
				break;
			case 'p' :
				cred_cache = atoi(optarg);
				if ((cred_cache < 128) || (cred_cache > 8192)) {
				fprintf(stderr,
					"Illegal credential cache size.\n");
				exit(1);
				}
				break;
			case 'i' :
				rpc_irtimeout = atoi(optarg);
				if (rpc_irtimeout < 0) {
				fprintf(stderr,
					"Illegal rpc inter-record timeout.\n");
				exit(1);
				}
				break;
			case 'L' :
				max_children = atoi(optarg);
				if (max_children <= 0) {
					fprintf(stderr, "Illegal load value\n");
					exit(1);
				}
				break;
			case 'z' :
				connmaxrec = atoi(optarg);
				break;
			case 'D' :
				debug = 1;
				break;
			case 'n':
				concurrency = atoi(optarg);
				break;
			case 'm':
				/* Config file name */
				ldapConfFile = optarg;
				break;
			case 'x':
				/* Attribute assignment */
				ldapCLA = realloc(ldapCLA,
					(numLA + 2) * sizeof (ldapCLA[0]));
				if (ldapCLA == 0) {
					fprintf(stderr,
					"Out of memory. realloc(%d) => NULL\n",
						(numLA+2)*sizeof (ldapCLA[0]));
					exit(1);
				}
				ldapCLA[numLA++] = optarg;
				ldapCLA[numLA] = 0;
				break;
			case '?' :
				fprintf(stderr,
	"usage: rpc.nisd [ -ACDFhlv ] [ -Y [ -B [ -t netid ]]]\n");
				fprintf(stderr,
	"\t[ -d dictionary ] [ -L load ] [ -S level ]\n");
				fprintf(stderr, "\t[ -m file ] "
				"[ -x attr=val] [ -z max record size]\n");
				exit(1);
		}
	}

	/*
	 * The "emulate YP" option can be requested on the command line
	 * or in the defaults file; command-line option overrides the
	 * file.  The value from the defaults file (ENABLE_NIS_YP_EMULATION=),
	 * obtained via parseConfig above, only needs to be checked if
	 * command-line option -Y is NOT used.
	 */
	if (emulate_yp == FALSE)
		emulate_yp = ldapConfig.emulate_yp;

	/* Complete syntax checking now that defaults are processed. */
	if (resolv_flag == TRUE) {
		if (emulate_yp == FALSE) {
			fprintf(stderr,
			    "Option -B requires option -Y also.\n");
			exit(1);
		}
	}
	if (tflag == TRUE) {
		if (resolv_flag == FALSE) {
			fprintf(stderr,
			    "Option -t requires options -Y and -B also.\n");
			exit(1);
		}
	}

	if (! debug)  {
		switch (fork()) {
		case -1:
			fprintf(stderr, "Couldn't fork a process exiting.\n");
			exit(1);
		case 0:
			break;
		default:
			exit(0);
		}

		closelog();
		closefrom(0);
		(void) open("/dev/null", O_RDONLY);
		(void) open("/dev/null", O_WRONLY);
		(void) dup(1);
		pid = setsid();
		openlog("nisd", LOG_PID+LOG_NOWAIT, LOG_DAEMON);
	}

#ifdef MEM_DEBUG
	init_xmalloc();
#endif
	if (open_console == 1)
		cons = fopen("/dev/console", "w");
	else if (open_console > 1)
		cons = stdout;
	syslog(LOG_INFO, "NIS+ service started.");
	gettimeofday(&start_time, 0);
	master_pid = getpid();
	if (verbose)
		syslog(LOG_INFO, "verbose mode set.");

	if (!cred_cache)
		cred_cache = CRED_CACHESZ_DEF;
	/* set the credential cache size */
	if (!__rpc_control(CLCR_SET_CRED_CACHE_SZ, &cred_cache))
		syslog(LOG_ERR,
			"rpc.nisd: cannot set credential cache size to %d",
				cred_cache);
	else
		if (verbose)
			syslog(LOG_INFO,
				"rpc.nisd: credential cache size set to %d",
					cred_cache);

	/* set RPC inter-record timeout */
	if (rpc_irtimeout >= 0)
		if (!rpc_control(RPC_SVC_IRTIMEOUT_SET, &rpc_irtimeout))
			syslog(LOG_ERR,
				"rpc.nisd: cannot set ir timeout to %d",
					rpc_irtimeout);
		else
			if (verbose)
				syslog(LOG_INFO,
				"rpc.nisd: ir timeout set to %d seconds",
					rpc_irtimeout);

	/* Parse LDAP mapping config */
	{
		int	stat = parseConfig(ldapCLA, ldapConfFile);
		if (stat == 1) {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"NIS+/LDAP mapping inactive");
		} else if (stat != 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"Aborting after NIS+/LDAP mapping parse error");
			exit(1);
		} else {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"NIS+/LDAP mapping parsed and initialized");
		}
	}

	/*
	 * The database functions use stdio.  Since we know
	 * the database routines are fileno() safe, we enable
	 * large file descriptors.
	 */
	(void) enable_extended_FILE_stdio(-1, -1);

	rl.rlim_cur = RLIM_INFINITY;
	rl.rlim_max = RLIM_INFINITY;
	(void) setrlimit(RLIMIT_NOFILE, &rl);

	if (nis_local_directory() == NULL) {
		if (debug)
			fprintf(stderr, "NIS+ Directory not set. Exiting.\n");
		else
			syslog(LOG_ERR, "NIS+ Directory not set. Exiting.");
		exit(1);
	}

	if (debug) {
		fprintf(stderr, "NIS+ Server startup.\n");
	}

	/*
	 * Set non-blocking mode, and establish maximum record size,
	 * for connection oriented RPC transports.
	 */
	{
		/* If not set via the '-z' option, use the attribute value */
		if (connmaxrec == -1)
			connmaxrec = ldapConfig.maxRPCRecordSize;

		if (connmaxrec < RPC_MAXDATASIZE) {
			syslog(LOG_WARNING,
				"Illegal max rpc record size specified %d, "
				"setting to default %d",
				connmaxrec, RPC_MAXDATASIZE);
			connmaxrec = RPC_MAXDATASIZE;
		}
		if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &connmaxrec)) {
			syslog(LOG_WARNING,
				"unable to set maximum RPC record size of %d",
				connmaxrec);
		}
	}

	/* Establish number of RPC service threads */
	{
		int	mtmode = RPC_SVC_MT_AUTO;

		/* If not set via the '-n' option, use the attribute value */
		if (concurrency < 0)
			concurrency = ldapConfig.numberOfServiceThreads;

		/* Zero means three plus number of processors available */
		if (concurrency <= 0) {
			long	numprc;
			/*
			 * If the requested functionality isn't available,
			 * sysconf(3C) returns -1 and leaves errno unchanged.
			 * Hence, establish a good default errno.
			 */
			errno = ENOTSUP;
			numprc = sysconf(_SC_NPROCESSORS_ONLN);
			if (numprc <= 0) {
				syslog(LOG_WARNING,
					"Unable to determine number of "
					"processors on-line; assuming one: %m");
				numprc = 1;
			}
			concurrency = 3 + numprc;
		}

		if (!rpc_control(RPC_SVC_MTMODE_SET, &mtmode)) {
			syslog(LOG_WARNING, "Could not set RPC auto MT mode");
		}
		if (!rpc_control(RPC_SVC_THRMAX_SET, &concurrency)) {
			syslog(LOG_WARNING,
				"Could not set RPC concurrency = %d",
				concurrency);
		}
	}

	/*
	 * Fix for bug #1248972 - Block SIGCHLD in the parent
	 * thread, so all subsequent threads will inherit the
	 * same signal mask - i.e. block SIGCHLD.
	 */
	(void) sigemptyset(&new_mask);
	(void) sigaddset(&new_mask, SIGCHLD);
	(void) thr_sigsetmask(SIG_BLOCK, &new_mask, NULL);

	if (debug) {
		fprintf(stderr, "Database initialization ...\n");
	}

	/*
	 * We're still single-threaded, so no need to acquire the
	 * 'setup_resolv' lock.
	 */
	if (resolv_flag)
		setup_resolv(&resolv_flag, &resolv_pid,
					&resolv_client, resolv_tp, 0);

	massage_dict = FALSE;
	if (!dict) {
		if (stat(nis_old_data(NULL), &s) == -1) { /* No old */
			if (stat(nis_data(NULL), &s) == -1) { /* No New */
				if (errno == ENOENT) {
					strcpy(buf, nis_data(NULL));
					if (mkdir(buf, 0700)) {
						perror("rpc.nisd");
						syslog(LOG_ERR,
			"rpc.nisd: Unable to create NIS+ directory %s", buf);
						exit(1);
					}
				} else {
					perror("rpc.nisd");
					syslog(LOG_ERR,
			"rpc.nisd: unable to stat NIS+ directory %s.", buf);
					exit(1);
				}
			}
			strcpy(buf, nis_data(NULL));
		} else if (stat(nis_data(NULL), &s) != -1) { /* Old and New */
			/*
			 * Handle the case for a host called data:
			 * 	- ONly the transaction log needs to be
			 *		renamed.
			 *	- the dict has already been massaged and
			 *		named correctly.
			 */
			if (strcmp(NIS_DIR,
					nis_leaf_of(nis_local_host())) == 0) {
				char	oldstr[NIS_MAXNAMELEN];
				char	newstr[NIS_MAXNAMELEN];

				sprintf(oldstr, "%s.log", nis_old_data(NULL));
				strcpy(newstr, LOG_FILE);
				if (rename(oldstr, newstr) == -1) {
					syslog(LOG_ERR,
				"Unable to rename NIS+ transaction log.");
					exit(1);
				}
				strcpy(buf, nis_data(NULL));
				dict = buf;
				/* No need to massage dict */
			} else {
				syslog(LOG_ERR,
				"Old and new dir structures cannot coexist.");
				exit(1);
			}
		} else { /* Old, No New => massage dict. */
			massage_dict = TRUE;
			strcpy(buf, nis_old_data(NULL));
		}
		strcat(buf, ".dict");
		dict = buf;
	}
	if (debug)
		fprintf(stderr, "Dictionary is %s\n", buf);
	status = db_initialize(dict);
	if (status == 0) {
		if (debug)
			fprintf(stderr, "Unable to initialize %s\n", buf);
		else
			syslog(LOG_ERR, "Unable to initialize %s", buf);
		exit(1);
	}

	/*
	 * Now, rename the `hostname` directory if necessary
	 * and massage the dictionary file. This must be done
	 * _after_ the dictionary has been initialiazed. Remember,
	 * the dictionary would have been initialized with dict name
	 * based on the old structure.
	 *
	 */
	if (massage_dict) {
		char	oldbuf[NIS_MAXNAMELEN], newbuf[NIS_MAXNAMELEN];
		char	oldstr[NIS_MAXNAMELEN];
		char	newstr[NIS_MAXNAMELEN];
		char	newdict[NIS_MAXNAMELEN];


		/* Massage the dictionary file */
		sprintf(oldbuf, "/%s/", nis_leaf_of(nis_local_host()));
		__make_legal(oldbuf);
		sprintf(newbuf, "/%s/", NIS_DIR);
		sprintf(newdict, "%s.dict", nis_data(NULL));
		if (db_massage_dict(newdict, oldbuf, newbuf) != DB_SUCCESS) {
			syslog(LOG_ERR,
				"Unable to change database dictionary.");
			exit(1);
		}


		/*
		 * Now, rename the old structure. This includes the following:
		 * 	- directory containing the tables.
		 * We don't worry about the dictionary file and its log
		 * since db_massage_dict() will take care of that for us.
		 * We also don't worry about the dictionary  log file, since
		 * db_massage_dict() will checkpoint before it makes any
		 * changes.
		 *
		 * However, we do need to change the NIS+ transaction log.
		 */
		strcpy(oldstr, nis_old_data(NULL));
		strcpy(newstr, nis_data(NULL));
		if (rename(oldstr, newstr) == -1) {
			syslog(LOG_ERR,
				"Unable to rename directory structure.");
			exit(1);
		}
		sprintf(oldstr, "%s.log", nis_old_data(NULL));
		strcpy(newstr, LOG_FILE);
		if (rename(oldstr, newstr) == -1) {
			syslog(LOG_ERR,
				"Unable to rename NIS+ transaction log.");
			exit(1);
		}
		/* Now, reinitialize the dictionary */
		status = db_initialize(newdict);
		if (status == 0) {
			if (debug)
				fprintf(stderr,
				"Unable to REinitialize %s\n", newdict);
			else
				syslog(LOG_ERR, "Unable to initialize %s",
								newdict);
			exit(1);
		}
	}
	rootobj = get_root_object();
	if (rootobj)
		root_server = 1;
	else if (root_server == -1) {
		/* if -r option is specified in the command line */
		root_server = 0;
		fprintf(stderr,
		"No root object present; running as non-root server.\n");
	}

	if (root_server) {
		update_cache_data(rootobj);  /* must do after detach */
		if (verbose)
			syslog(LOG_INFO, "Service running as root server.");
		if (we_serve(&(rootobj->DI_data), MASTER_ONLY) &&
		    !verify_table_exists(__nis_rpc_domain()))
			exit(1);
		nis_destroy_object(rootobj); /* free; not needed anymore */
	}

	if (debug) {
		fprintf(stderr, "... database initialization complete.\n");
		fprintf(stderr, "Transaction log initialization ...\n");
	}

	if (! status)
		syslog(LOG_ERR, "WARNING: Dictionary not initialized!");

	sprintf(logname, "%s", LOG_FILE);
	if (map_log(logname, FNISD)) {
		if (debug)
			fprintf(stderr, "Transaction log corrupt. Exiting.\n");
		else
			syslog(LOG_ERR, "Transaction log corrupt. Exiting.");
		exit(1);
	}

	/* initialize the timestamp cache table */
	init_updatetime();

	if (debug) {
		fprintf(stderr, "... transaction log initialized.\n");
	}

	/* Initialize in-core list of directories served by this server */
	(void) nis_server_control(SERVING_LIST, DIR_INITLIST, NULL);

	/*
	 * If we crashed during update, directory_invalid will contain
	 * the name of the invalidated directory; otherwise, it will
	 * be NULL.  (map_log sets this)
	 */
	if (invalid_directory) {
		nis_object id[1], *invdir = id;
		struct ticks t[1];
		ping_item dummy_ping[1];
		int drastic_measures = 0;

		syslog(LOG_WARNING,
		"directory %s corrupted during update; attempting recovery",
			invalid_directory);
		clear_directory(invalid_directory);
		/* forge a ping item; fill just enought for replica_update */
		if (__directory_object(invalid_directory, t, 0, &invdir) !=
		    NIS_SUCCESS) {
			syslog(LOG_WARNING,
		"recovery for %s failed; couldn't get directory object",
				invalid_directory);
			drastic_measures = 1;
		} else {
			dummy_ping->item.name = invalid_directory;
			dummy_ping->mtime = 0;
			dummy_ping->obj = invdir;
			if (!replica_update(dummy_ping)) {
				syslog(LOG_WARNING,
				"recovery for %s failed; couldn't resync",
					invalid_directory);
				/*
				 * replica_update will also have invalidated
				 * this directory, but just to be sure...
				 */
				drastic_measures = 1;
			}
		}

		if (drastic_measures) {
			syslog(LOG_WARNING,
			"Forcing resync by setting update time to 0 for %s",
				invalid_directory);
			syslog(LOG_WARNING,
				"You may need to restore from backup");
			make_stamp(invalid_directory, 0);
		} else
			syslog(LOG_WARNING,
			"Recovery for %s completed", invalid_directory);
	}

	/* Up-/down-load data to/from LDAP */
	i = loadLDAPdata();
	if (i != 0) {
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"Exiting after LDAP data load");
		exit(i > 0 ? 0 : 1);
	}

	/* rpc registration */
	if (debug) {
		fprintf(stderr, "RPC program registration ...\n");
	}

	rpcb_unset(NIS_PROG, NIS_VERSION, NULL);
	if (emulate_yp) {
		rpcb_unset(YPPROG, YPVERS, NULL);
		rpcb_unset(YPPROG, YPVERS_ORIG, NULL);
	}
	i = nis_svc_create(nis_prog_svc, NIS_PROG, NIS_VERSION, NC_VISIBLE);
	if (! i)
		exit(1);
	else if (verbose)
		syslog(LOG_INFO, "NIS+ service listening on %d transports.", i);
	if (emulate_yp) {
		i = nis_svc_create(ypprog_svc, YPPROG, YPVERS, NC_VISIBLE);
		if (! i)
			exit(1);
		else if (verbose)
			syslog(LOG_INFO,
				"NIS service listening on %d transports.", i);
		i = nis_svc_create(ypprog_1, YPPROG, YPVERS_ORIG, NC_VISIBLE);
		if (! i)
			exit(1);
		else if (verbose)
			syslog(LOG_INFO, "Created %d YPVERS_ORIG handles.", i);
	}

	set_rpc_gss_svc_names();

	__svc_nisplus_enable_timestamps();

	if (debug) {
		fprintf(stderr, "... RPC registration complete.\n");
		fprintf(stderr, "Service starting.\n");
	}

	{
		pthread_t	servloop_thread;
		pthread_attr_t	attr;
		int		stat;

		(void) pthread_attr_init(&attr);
		if ((stat = pthread_create(&servloop_thread, &attr,
						servloop, 0)) != 0) {
			syslog(LOG_ERR,
				"error %d creating servloop thread; exiting",
				stat);
			if (cons || debug)
				fprintf(stderr,
				"error %d creating servloop thread; exiting\n",
					stat);
			exit(1);
		}
		(void) pthread_attr_destroy(&attr);

		if (cons || debug)
			fprintf(stderr,
				"servloop thread started; ready to roll...\n");

		svc_run();
		/* Not reached */
	}

	return (0);
}

int
__rpcsec_gss_is_server()
{
	return (1);
}
