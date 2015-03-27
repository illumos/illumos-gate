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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <rpc/rpc.h>
#include <rpcsvc/sm_inter.h>
#include <rpcsvc/nsm_addr.h>
#include <memory.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netdir.h>
#include <synch.h>
#include <thread.h>
#include <ifaddrs.h>
#include <errno.h>
#include <assert.h>
#include "sm_statd.h"

static int local_state;		/* fake local sm state */
				/* client name-to-address translation table */
static name_addr_entry_t *name_addr = NULL;


#define	LOGHOST "loghost"

static void delete_mon(char *mon_name, my_id *my_idp);
static void insert_mon(mon *monp);
static void pr_mon(char *);
static int statd_call_lockd(mon *monp, int state);
static int hostname_eq(char *host1, char *host2);
static char *get_system_id(char *hostname);
static void add_aliases(struct hostent *phost);
static void *thr_send_notice(void *);
static void delete_onemon(char *mon_name, my_id *my_idp,
				mon_entry **monitor_q);
static void send_notice(char *mon_name, int state);
static void add_to_host_array(char *host);
static int in_host_array(char *host);
static void pr_name_addr(name_addr_entry_t *name_addr);

extern int self_check(char *hostname);
extern struct lifconf *getmyaddrs(void);

/* ARGSUSED */
void
sm_stat_svc(sm_name *namep, sm_stat_res *resp)
{

	if (debug)
		(void) printf("proc sm_stat: mon_name = %s\n",
		    namep->mon_name);

	resp->res_stat = stat_succ;
	resp->state = LOCAL_STATE;
}

/* ARGSUSED */
void
sm_mon_svc(mon *monp, sm_stat_res *resp)
{
	mon_id *monidp;
	monidp = &monp->mon_id;

	rw_rdlock(&thr_rwlock);
	if (debug) {
		(void) printf("proc sm_mon: mon_name = %s, id = %d\n",
		    monidp->mon_name, *((int *)monp->priv));
		pr_mon(monp->mon_id.mon_name);
	}

	/* only monitor other hosts */
	if (self_check(monp->mon_id.mon_name) == 0) {
		/* store monitor request into monitor_q */
		insert_mon(monp);
	}

	pr_mon(monp->mon_id.mon_name);
	resp->res_stat = stat_succ;
	resp->state = local_state;
	rw_unlock(&thr_rwlock);
}

/* ARGSUSED */
void
sm_unmon_svc(mon_id *monidp, sm_stat *resp)
{
	rw_rdlock(&thr_rwlock);
	if (debug) {
		(void) printf(
		    "proc sm_unmon: mon_name = %s, [%s, %d, %d, %d]\n",
		    monidp->mon_name, monidp->my_id.my_name,
		    monidp->my_id.my_prog, monidp->my_id.my_vers,
		    monidp->my_id.my_proc);
		pr_mon(monidp->mon_name);
	}

	delete_mon(monidp->mon_name, &monidp->my_id);
	pr_mon(monidp->mon_name);
	resp->state = local_state;
	rw_unlock(&thr_rwlock);
}

/* ARGSUSED */
void
sm_unmon_all_svc(my_id *myidp, sm_stat *resp)
{
	rw_rdlock(&thr_rwlock);
	if (debug)
		(void) printf("proc sm_unmon_all: [%s, %d, %d, %d]\n",
		    myidp->my_name,
		    myidp->my_prog, myidp->my_vers,
		    myidp->my_proc);
	delete_mon(NULL, myidp);
	pr_mon(NULL);
	resp->state = local_state;
	rw_unlock(&thr_rwlock);
}

/*
 * Notifies lockd specified by name that state has changed for this server.
 */
void
sm_notify_svc(stat_chge *ntfp)
{
	rw_rdlock(&thr_rwlock);
	if (debug)
		(void) printf("sm_notify: %s state =%d\n",
		    ntfp->mon_name, ntfp->state);
	send_notice(ntfp->mon_name, ntfp->state);
	rw_unlock(&thr_rwlock);
}

/* ARGSUSED */
void
sm_simu_crash_svc(void *myidp)
{
	int i;
	struct mon_entry *monitor_q;
	int found = 0;

	if (debug)
		(void) printf("proc sm_simu_crash\n");

	/* Only one crash should be running at a time. */
	mutex_lock(&crash_lock);
	if (in_crash != 0) {
		mutex_unlock(&crash_lock);
		return;
	}
	in_crash = 1;
	mutex_unlock(&crash_lock);

	for (i = 0; i < MAX_HASHSIZE; i++) {
		mutex_lock(&mon_table[i].lock);
		monitor_q = mon_table[i].sm_monhdp;
		if (monitor_q != NULL) {
			mutex_unlock(&mon_table[i].lock);
			found = 1;
			break;
		}
		mutex_unlock(&mon_table[i].lock);
	}
	/*
	 * If there are entries found in the monitor table,
	 * initiate a crash, else zero out the in_crash variable.
	 */
	if (found) {
		mutex_lock(&crash_lock);
		die = 1;
		/* Signal sm_try() thread if sleeping. */
		cond_signal(&retrywait);
		mutex_unlock(&crash_lock);
		rw_wrlock(&thr_rwlock);
		sm_crash();
		rw_unlock(&thr_rwlock);
	} else {
		mutex_lock(&crash_lock);
		in_crash = 0;
		mutex_unlock(&crash_lock);
	}
}

/* ARGSUSED */
void
nsmaddrproc1_reg(reg1args *regargs, reg1res *regresp)
{
	nsm_addr_res status;
	name_addr_entry_t *entry;
	char *tmp_n_bytes;
	addr_entry_t *addr;

	rw_rdlock(&thr_rwlock);
	if (debug) {
		int i;

		(void) printf("nap1_reg: fam= %d, name= %s, len= %d\n",
		    regargs->family, regargs->name, regargs->address.n_len);
		(void) printf("address is: ");
		for (i = 0; i < regargs->address.n_len; i++) {
			(void) printf("%d.",
			    (unsigned char)regargs->address.n_bytes[i]);
		}
		(void) printf("\n");
	}

	/*
	 * Locate the entry with the name in the NSM_ADDR_REG request if
	 * it exists.  If it doesn't, create a new entry to hold this name.
	 * The first time through this code, name_addr starts out as NULL.
	 */
	mutex_lock(&name_addrlock);
	for (entry = name_addr; entry; entry = entry->next) {
		if (strcmp(regargs->name, entry->name) == 0) {
			if (debug) {
				(void) printf("nap1_reg: matched name %s\n",
				    entry->name);
			}
			break;
		}
	}

	if (entry == NULL) {
		entry = (name_addr_entry_t *)malloc(sizeof (*entry));
		if (entry == NULL) {
			if (debug) {
				(void) printf(
				"nsmaddrproc1_reg: no memory for entry\n");
			}
			status = nsm_addr_fail;
			goto done;
		}

		entry->name = strdup(regargs->name);
		if (entry->name == NULL) {
			if (debug) {
				(void) printf(
				"nsmaddrproc1_reg: no memory for name\n");
			}
			free(entry);
			status = nsm_addr_fail;
			goto done;
		}
		entry->addresses = NULL;

		/*
		 * Link the new entry onto the *head* of the name_addr
		 * table.
		 *
		 * Note: there is code below in the address maintenance
		 * section that assumes this behavior.
		 */
		entry->next = name_addr;
		name_addr = entry;
	}

	/*
	 * Try to match the address in the request; if it doesn't match,
	 * add it to the entry's address list.
	 */
	for (addr = entry->addresses; addr; addr = addr->next) {
		if (addr->family == (sa_family_t)regargs->family &&
		    addr->ah.n_len == regargs->address.n_len &&
		    memcmp(addr->ah.n_bytes, regargs->address.n_bytes,
		    addr->ah.n_len) == 0) {
			if (debug) {
				int i;

				(void) printf("nap1_reg: matched addr ");
				for (i = 0; i < addr->ah.n_len; i++) {
					(void) printf("%d.",
					    (unsigned char)addr->ah.n_bytes[i]);
				}
				(void) printf(" family %d for name %s\n",
				    addr->family, entry->name);
			}
			break;
		}
	}

	if (addr == NULL) {
		addr = (addr_entry_t *)malloc(sizeof (*addr));
		tmp_n_bytes = (char *)malloc(regargs->address.n_len);
		if (addr == NULL || tmp_n_bytes == NULL) {
			if (debug) {
				(void) printf("nap1_reg: no memory for addr\n");
			}

			/*
			 * If this name entry was just newly made in the
			 * table, back it out now that we can't register
			 * an address with it anyway.
			 *
			 * Note: we are making an assumption about how
			 * names are added to (the head of) name_addr here.
			 */
			if (entry == name_addr && entry->addresses == NULL) {
				name_addr = name_addr->next;
				free(entry->name);
				free(entry);
				if (tmp_n_bytes)
					free(tmp_n_bytes);
				if (addr)
					free(addr);
				status = nsm_addr_fail;
				goto done;
			}
		}

		/*
		 * Note:  this check for address family assumes that we
		 *	  will get something different here someday for
		 *	  other supported address types, such as IPv6.
		 */
		addr->ah.n_len = regargs->address.n_len;
		addr->ah.n_bytes = tmp_n_bytes;
		addr->family = regargs->family;
		if (debug) {
			if ((addr->family != AF_INET) &&
			    (addr->family != AF_INET6)) {
				(void) printf(
				    "nap1_reg: unknown addr family %d\n",
				    addr->family);
			}
		}
		(void) memcpy(addr->ah.n_bytes, regargs->address.n_bytes,
		    addr->ah.n_len);

		addr->next = entry->addresses;
		entry->addresses = addr;
	}

	status = nsm_addr_succ;

done:
	regresp->status = status;
	if (debug) {
		pr_name_addr(name_addr);
	}
	mutex_unlock(&name_addrlock);
	rw_unlock(&thr_rwlock);
}

/*
 * Insert an entry into the monitor_q.  Space for the entry is allocated
 * here.  It is then filled in from the information passed in.
 */
static void
insert_mon(mon *monp)
{
	mon_entry *new, *found;
	my_id *my_idp, *nl_idp;
	mon_entry *monitor_q;
	unsigned int hash;
	name_addr_entry_t *entry;
	addr_entry_t *addr;

	/* Allocate entry for new */
	if ((new = (mon_entry *) malloc(sizeof (mon_entry))) == 0) {
		syslog(LOG_ERR,
		    "statd: insert_mon: malloc error on mon %s (id=%d)\n",
		    monp->mon_id.mon_name, *((int *)monp->priv));
		return;
	}

	/* Initialize and copy contents of monp to new */
	(void) memset(new, 0, sizeof (mon_entry));
	(void) memcpy(&new->id, monp, sizeof (mon));

	/* Allocate entry for new mon_name */
	if ((new->id.mon_id.mon_name = strdup(monp->mon_id.mon_name)) == 0) {
		syslog(LOG_ERR,
		    "statd: insert_mon: malloc error on mon %s (id=%d)\n",
		    monp->mon_id.mon_name, *((int *)monp->priv));
		free(new);
		return;
	}


	/* Allocate entry for new my_name */
	if ((new->id.mon_id.my_id.my_name =
	    strdup(monp->mon_id.my_id.my_name)) == 0) {
		syslog(LOG_ERR,
		    "statd: insert_mon: malloc error on mon %s (id=%d)\n",
		    monp->mon_id.mon_name, *((int *)monp->priv));
		free(new->id.mon_id.mon_name);
		free(new);
		return;
	}

	if (debug)
		(void) printf("add_mon(%x) %s (id=%d)\n",
		    (int)new, new->id.mon_id.mon_name, *((int *)new->id.priv));

	/*
	 * Record the name, and all addresses which have been registered
	 * for this name, in the filesystem name space.
	 */
	record_name(new->id.mon_id.mon_name, 1);
	if (regfiles_only == 0) {
		mutex_lock(&name_addrlock);
		for (entry = name_addr; entry; entry = entry->next) {
			if (strcmp(new->id.mon_id.mon_name, entry->name) != 0) {
				continue;
			}

			for (addr = entry->addresses; addr; addr = addr->next) {
				record_addr(new->id.mon_id.mon_name,
				    addr->family, &addr->ah);
			}
			break;
		}
		mutex_unlock(&name_addrlock);
	}

	SMHASH(new->id.mon_id.mon_name, hash);
	mutex_lock(&mon_table[hash].lock);
	monitor_q = mon_table[hash].sm_monhdp;

	/* If mon_table hash list is empty. */
	if (monitor_q == NULL) {
		if (debug)
			(void) printf("\nAdding to monitor_q hash %d\n", hash);
		new->nxt = new->prev = NULL;
		mon_table[hash].sm_monhdp = new;
		mutex_unlock(&mon_table[hash].lock);
		return;
	} else {
		found = 0;
		my_idp = &new->id.mon_id.my_id;
		while (monitor_q != NULL)  {
			/*
			 * This list is searched sequentially for the
			 * tuple (hostname, prog, vers, proc). The tuples
			 * are inserted in the beginning of the monitor_q,
			 * if the hostname is not already present in the list.
			 * If the hostname is found in the list, the incoming
			 * tuple is inserted just after all the tuples with the
			 * same hostname. However, if the tuple matches exactly
			 * with an entry in the list, space allocated for the
			 * new entry is released and nothing is inserted in the
			 * list.
			 */

			if (str_cmp_unqual_hostname(
			    monitor_q->id.mon_id.mon_name,
			    new->id.mon_id.mon_name) == 0) {
				/* found */
				nl_idp = &monitor_q->id.mon_id.my_id;
				if ((str_cmp_unqual_hostname(my_idp->my_name,
				    nl_idp->my_name) == 0) &&
				    my_idp->my_prog == nl_idp->my_prog &&
				    my_idp->my_vers == nl_idp->my_vers &&
				    my_idp->my_proc == nl_idp->my_proc) {
					/*
					 * already exists an identical one,
					 * release the space allocated for the
					 * mon_entry
					 */
					free(new->id.mon_id.mon_name);
					free(new->id.mon_id.my_id.my_name);
					free(new);
					mutex_unlock(&mon_table[hash].lock);
					return;
				} else {
					/*
					 * mark the last callback that is
					 * not matching; new is inserted
					 * after this
					 */
					found = monitor_q;
				}
			} else if (found)
				break;
			monitor_q = monitor_q->nxt;
		}
		if (found) {
			/*
			 * insert just after the entry having matching tuple.
			 */
			new->nxt = found->nxt;
			new->prev = found;
			if (found->nxt != NULL)
				found->nxt->prev = new;
			found->nxt = new;
		} else {
			/*
			 * not found, insert in front of list.
			 */
			new->nxt = mon_table[hash].sm_monhdp;
			new->prev = (mon_entry *) NULL;
			if (new->nxt != (mon_entry *) NULL)
				new->nxt->prev = new;
			mon_table[hash].sm_monhdp = new;
		}
		mutex_unlock(&mon_table[hash].lock);
		return;
	}
}

/*
 * Deletes a specific monitor name or deletes all monitors with same id
 * in hash table.
 */
static void
delete_mon(char *mon_name, my_id *my_idp)
{
	unsigned int hash;

	if (mon_name != NULL) {
		record_name(mon_name, 0);
		SMHASH(mon_name, hash);
		mutex_lock(&mon_table[hash].lock);
		delete_onemon(mon_name, my_idp, &mon_table[hash].sm_monhdp);
		mutex_unlock(&mon_table[hash].lock);
	} else {
		for (hash = 0; hash < MAX_HASHSIZE; hash++) {
			mutex_lock(&mon_table[hash].lock);
			delete_onemon(mon_name, my_idp,
			    &mon_table[hash].sm_monhdp);
			mutex_unlock(&mon_table[hash].lock);
		}
	}
}

/*
 * Deletes a monitor in list.
 * IF mon_name is NULL, delete all mon_names that have the same id,
 * else delete specific monitor.
 */
void
delete_onemon(char *mon_name, my_id *my_idp, mon_entry **monitor_q)
{

	mon_entry *next, *nl;
	my_id *nl_idp;

	next = *monitor_q;
	while ((nl = next) != NULL) {
		next = next->nxt;
		if (mon_name == NULL || (mon_name != NULL &&
		    str_cmp_unqual_hostname(nl->id.mon_id.mon_name,
		    mon_name) == 0)) {
			nl_idp = &nl->id.mon_id.my_id;
			if ((str_cmp_unqual_hostname(my_idp->my_name,
			    nl_idp->my_name) == 0) &&
			    my_idp->my_prog == nl_idp->my_prog &&
			    my_idp->my_vers == nl_idp->my_vers &&
			    my_idp->my_proc == nl_idp->my_proc) {
				/* found */
				if (debug)
					(void) printf("delete_mon(%x): %s\n",
					    (int)nl, mon_name ?
					    mon_name : "<NULL>");
				/*
				 * Remove the monitor name from the
				 * record_q, if id matches.
				 */
				record_name(nl->id.mon_id.mon_name, 0);
				/* if nl is not the first entry on list */
				if (nl->prev != NULL)
					nl->prev->nxt = nl->nxt;
				else {
					*monitor_q = nl->nxt;
				}
				if (nl->nxt != NULL)
					nl->nxt->prev = nl->prev;
				free(nl->id.mon_id.mon_name);
				free(nl_idp->my_name);
				free(nl);
			}
		} /* end of if mon */
	}

}
/*
 * Notify lockd of host specified by mon_name that the specified state
 * has changed.
 */
static void
send_notice(char *mon_name, int state)
{
	struct mon_entry *next;
	mon_entry *monitor_q;
	unsigned int hash;
	moninfo_t *minfop;
	mon *monp;

	SMHASH(mon_name, hash);
	mutex_lock(&mon_table[hash].lock);
	monitor_q = mon_table[hash].sm_monhdp;

	next = monitor_q;
	while (next != NULL) {
		if (hostname_eq(next->id.mon_id.mon_name, mon_name)) {
			monp = &next->id;
			/*
			 * Prepare the minfop structure to pass to
			 * thr_create(). This structure is a copy of
			 * mon info and state.
			 */
			if ((minfop =
			    (moninfo_t *)xmalloc(sizeof (moninfo_t))) != NULL) {
				(void) memcpy(&minfop->id, monp, sizeof (mon));
				/* Allocate entry for mon_name */
				if ((minfop->id.mon_id.mon_name =
				    strdup(monp->mon_id.mon_name)) == 0) {
					syslog(LOG_ERR, "statd: send_notice: "
					    "malloc error on mon %s (id=%d)\n",
					    monp->mon_id.mon_name,
					    *((int *)monp->priv));
					free(minfop);
					continue;
				}
				/* Allocate entry for my_name */
				if ((minfop->id.mon_id.my_id.my_name =
				    strdup(monp->mon_id.my_id.my_name)) == 0) {
					syslog(LOG_ERR, "statd: send_notice: "
					    "malloc error on mon %s (id=%d)\n",
					    monp->mon_id.mon_name,
					    *((int *)monp->priv));
					free(minfop->id.mon_id.mon_name);
					free(minfop);
					continue;
				}
				minfop->state = state;
				/*
				 * Create detached threads to process each host
				 * to notify.  If error, print out msg, free
				 * resources and continue.
				 */
				if (thr_create(NULL, NULL, thr_send_notice,
				    minfop, THR_DETACHED, NULL)) {
					syslog(LOG_ERR, "statd: unable to "
					    "create thread to send_notice to "
					    "%s.\n", mon_name);
					free(minfop->id.mon_id.mon_name);
					free(minfop->id.mon_id.my_id.my_name);
					free(minfop);
					continue;
				}
			}
		}
		next = next->nxt;
	}
	mutex_unlock(&mon_table[hash].lock);
}

/*
 * Work thread created to do the actual statd_call_lockd
 */
static void *
thr_send_notice(void *arg)
{
	moninfo_t *minfop;

	minfop = (moninfo_t *)arg;
	if (statd_call_lockd(&minfop->id, minfop->state) == -1) {
		if (debug && minfop->id.mon_id.mon_name)
			(void) printf("problem with notifying %s failure, "
			    "give up\n", minfop->id.mon_id.mon_name);
	} else {
		if (debug)
			(void) printf("send_notice: %s, %d notified.\n",
			    minfop->id.mon_id.mon_name, minfop->state);
	}

	free(minfop->id.mon_id.mon_name);
	free(minfop->id.mon_id.my_id.my_name);
	free(minfop);

	thr_exit((void *) 0);
#ifdef lint
	/*NOTREACHED*/
	return ((void *)0);
#endif
}

/*
 * Contact lockd specified by monp.
 */
static int
statd_call_lockd(mon *monp, int state)
{
	enum clnt_stat clnt_stat;
	struct timeval tottimeout;
	struct sm_status stat;
	my_id *my_idp;
	char *mon_name;
	int i;
	int rc = 0;
	CLIENT *clnt;

	mon_name = monp->mon_id.mon_name;
	my_idp = &monp->mon_id.my_id;
	(void) memset(&stat, 0, sizeof (stat));
	stat.mon_name = mon_name;
	stat.state = state;
	for (i = 0; i < 16; i++) {
		stat.priv[i] = monp->priv[i];
	}
	if (debug)
		(void) printf("statd_call_lockd: %s state = %d\n",
		    stat.mon_name, stat.state);

	tottimeout.tv_sec = SM_RPC_TIMEOUT;
	tottimeout.tv_usec = 0;

	clnt = create_client(my_idp->my_name, my_idp->my_prog, my_idp->my_vers,
	    "ticotsord", &tottimeout);
	if (clnt == NULL) {
		return (-1);
	}

	clnt_stat = clnt_call(clnt, my_idp->my_proc, xdr_sm_status,
	    (char *)&stat, xdr_void, NULL, tottimeout);
	if (debug) {
		(void) printf("clnt_stat=%s(%d)\n",
		    clnt_sperrno(clnt_stat), clnt_stat);
	}
	if (clnt_stat != (int)RPC_SUCCESS) {
		syslog(LOG_WARNING,
		    "statd: cannot talk to lockd at %s, %s(%d)\n",
		    my_idp->my_name, clnt_sperrno(clnt_stat), clnt_stat);
		rc = -1;
	}

	clnt_destroy(clnt);
	return (rc);

}

/*
 * Client handle created.
 */
CLIENT *
create_client(char *host, int prognum, int versnum, char *netid,
    struct timeval *utimeout)
{
	int		fd;
	struct timeval	timeout;
	CLIENT		*client;
	struct t_info	tinfo;

	if (netid == NULL) {
		client = clnt_create_timed(host, prognum, versnum,
		    "netpath", utimeout);
	} else {
		struct netconfig *nconf;

		nconf = getnetconfigent(netid);
		if (nconf == NULL) {
			return (NULL);
		}

		client = clnt_tp_create_timed(host, prognum, versnum, nconf,
		    utimeout);

		freenetconfigent(nconf);
	}

	if (client == NULL) {
		return (NULL);
	}

	(void) CLNT_CONTROL(client, CLGET_FD, (caddr_t)&fd);
	if (t_getinfo(fd, &tinfo) != -1) {
		if (tinfo.servtype == T_CLTS) {
			/*
			 * Set time outs for connectionless case
			 */
			timeout.tv_usec = 0;
			timeout.tv_sec = SM_CLTS_TIMEOUT;
			(void) CLNT_CONTROL(client,
			    CLSET_RETRY_TIMEOUT, (caddr_t)&timeout);
		}
	} else
		return (NULL);

	return (client);
}

/*
 * ONLY for debugging.
 * Debug messages which prints out the monitor table information.
 * If name is specified, just print out the hash list corresponding
 * to name, otherwise print out the entire monitor table.
 */
static void
pr_mon(char *name)
{
	mon_entry *nl;
	int hash;

	if (!debug)
		return;

	/* print all */
	if (name == NULL) {
		for (hash = 0; hash < MAX_HASHSIZE; hash++) {
			mutex_lock(&mon_table[hash].lock);
			nl = mon_table[hash].sm_monhdp;
			if (nl == NULL) {
				(void) printf(
				    "*****monitor_q = NULL hash %d\n", hash);
				mutex_unlock(&mon_table[hash].lock);
				continue;
			}
			(void) printf("*****monitor_q:\n ");
			while (nl != NULL) {
				(void) printf("%s:(%x), ",
				    nl->id.mon_id.mon_name, (int)nl);
				nl = nl->nxt;
			}
			mutex_unlock(&mon_table[hash].lock);
			(void) printf("\n");
		}
	} else { /* print one hash list */
		SMHASH(name, hash);
		mutex_lock(&mon_table[hash].lock);
		nl = mon_table[hash].sm_monhdp;
		if (nl == NULL) {
			(void) printf("*****monitor_q = NULL hash %d\n", hash);
		} else {
			(void) printf("*****monitor_q:\n ");
			while (nl != NULL) {
				(void) printf("%s:(%x), ",
				    nl->id.mon_id.mon_name, (int)nl);
				nl = nl->nxt;
			}
			(void) printf("\n");
		}
		mutex_unlock(&mon_table[hash].lock);
	}
}

/*
 * Only for debugging.
 * Dump the host name-to-address translation table passed in `name_addr'.
 */
static void
pr_name_addr(name_addr_entry_t *name_addr)
{
	name_addr_entry_t *entry;
	addr_entry_t *addr;
	struct in_addr ipv4_addr;
	char *ipv6_addr;
	char abuf[INET6_ADDRSTRLEN];

	assert(MUTEX_HELD(&name_addrlock));
	(void) printf("name-to-address translation table:\n");
	for (entry = name_addr; entry != NULL; entry = entry->next) {
		(void) printf("\t%s: ",
		    (entry->name ? entry->name : "(null)"));
		for (addr = entry->addresses; addr; addr = addr->next) {
			switch (addr->family) {
			case AF_INET:
				ipv4_addr = *(struct in_addr *)addr->ah.n_bytes;
				(void) printf(" %s (fam %d)",
				    inet_ntoa(ipv4_addr), addr->family);
				break;
			case AF_INET6:
				ipv6_addr = (char *)addr->ah.n_bytes;
				(void) printf(" %s (fam %d)",
				    inet_ntop(addr->family, ipv6_addr, abuf,
				    sizeof (abuf)), addr->family);
				break;
			default:
				return;
			}
		}
		printf("\n");
	}
}

/*
 * First, try to compare the hostnames as strings.  If the hostnames does not
 * match we might deal with the hostname aliases.  In this case two different
 * aliases for the same machine don't match each other when using strcmp.  To
 * deal with this, the hostnames must be translated into some sort of universal
 * identifier.  These identifiers can be compared.  Universal network addresses
 * are currently used for this identifier because it is general and easy to do.
 * Other schemes are possible and this routine could be converted if required.
 *
 * If it can't find an address for some reason, 0 is returned.
 */
static int
hostname_eq(char *host1, char *host2)
{
	char *sysid1;
	char *sysid2;
	int rv;

	/* Compare hostnames as strings */
	if (host1 != NULL && host2 != NULL && strcmp(host1, host2) == 0)
		return (1);

	/* Try harder if hostnames do not match */
	sysid1 = get_system_id(host1);
	sysid2 = get_system_id(host2);
	if ((sysid1 == NULL) || (sysid2 == NULL))
		rv = 0;
	else
		rv = (strcmp(sysid1, sysid2) == 0);
	free(sysid1);
	free(sysid2);
	return (rv);
}

/*
 * Convert a hostname character string into its network address.
 * A network address is found by searching through all the entries
 * in /etc/netconfig and doing a netdir_getbyname() for each inet
 * entry found.  The netbuf structure returned is converted into
 * a universal address format.
 *
 * If a NULL hostname is given, then the name of the current host
 * is used.  If the hostname doesn't map to an address, a NULL
 * pointer is returned.
 *
 * N.B. the character string returned is allocated in taddr2uaddr()
 * and should be freed by the caller using free().
 */
static char *
get_system_id(char *hostname)
{
	void *hp;
	struct netconfig *ncp;
	struct nd_hostserv service;
	struct nd_addrlist *addrs;
	char *uaddr;
	int rv;

	if (hostname == NULL)
		service.h_host = HOST_SELF;
	else
		service.h_host = hostname;
	service.h_serv = NULL;
	hp = setnetconfig();
	if (hp == (void *) NULL) {
		return (NULL);
	}
	while ((ncp = getnetconfig(hp)) != NULL) {
		if ((strcmp(ncp->nc_protofmly, NC_INET) == 0) ||
		    (strcmp(ncp->nc_protofmly, NC_INET6) == 0)) {
			addrs = NULL;
			rv = netdir_getbyname(ncp, &service, &addrs);
			if (rv != 0) {
				continue;
			}
			if (addrs) {
				uaddr = taddr2uaddr(ncp, addrs->n_addrs);
				netdir_free(addrs, ND_ADDRLIST);
				endnetconfig(hp);
				return (uaddr);
			}
		}
		else
			continue;
	}
	endnetconfig(hp);
	return (NULL);
}

void
merge_hosts(void)
{
	struct lifconf *lifc = NULL;
	int sock = -1;
	struct lifreq *lifrp;
	struct lifreq lifr;
	int n;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr_storage *sa;
	int af;
	struct hostent *phost;
	char *addr;
	size_t alen;
	int errnum;

	/*
	 * This function will enumerate all the interfaces for
	 * this platform, then get the hostent for each i/f.
	 * With the hostent structure, we can get all of the
	 * aliases for the i/f. Then we'll merge all the aliases
	 * with the existing host_name[] list to come up with
	 * all of the known names for each interface. This solves
	 * the problem of a multi-homed host not knowing which
	 * name to publish when statd is started. All the aliases
	 * will be stored in the array, host_name.
	 *
	 * NOTE: Even though we will use all of the aliases we
	 * can get from the i/f hostent, the receiving statd
	 * will still need to handle aliases with hostname_eq.
	 * This is because the sender's aliases may not match
	 * those of the receiver.
	 */
	lifc = getmyaddrs();
	if (lifc == NULL) {
		goto finish;
	}
	lifrp = lifc->lifc_req;
	for (n = lifc->lifc_len / sizeof (struct lifreq); n > 0; n--, lifrp++) {

		(void) strncpy(lifr.lifr_name, lifrp->lifr_name,
		    sizeof (lifr.lifr_name));

		af = lifrp->lifr_addr.ss_family;
		sock = socket(af, SOCK_DGRAM, 0);
		if (sock == -1) {
			syslog(LOG_ERR, "statd: socket failed\n");
			goto finish;
		}

		/* If it's the loopback interface, ignore */
		if (ioctl(sock, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
			syslog(LOG_ERR,
			    "statd: SIOCGLIFFLAGS failed, error: %m\n");
			goto finish;
		}
		if (lifr.lifr_flags & IFF_LOOPBACK)
			continue;

		if (ioctl(sock, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
			syslog(LOG_ERR,
			    "statd: SIOCGLIFADDR failed, error: %m\n");
			goto finish;
		}
		sa = (struct sockaddr_storage *)&(lifr.lifr_addr);

		if (sa->ss_family == AF_INET) {
			sin = (struct sockaddr_in *)&lifr.lifr_addr;
			addr = (char *)(&sin->sin_addr);
			alen = sizeof (struct in_addr);
		} else if (sa->ss_family == AF_INET6) {
			sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
			addr = (char *)(&sin6->sin6_addr);
			alen = sizeof (struct in6_addr);
		} else {
			syslog(LOG_WARNING,
			    "unexpected address family (%d)",
			    sa->ss_family);
			continue;
		}

		phost = getipnodebyaddr(addr, alen, sa->ss_family, &errnum);

		if (phost)
			add_aliases(phost);
	}
	/*
	 * Now, just in case we didn't get them all byaddr,
	 * let's look by name.
	 */
	phost = getipnodebyname(hostname, AF_INET6, AI_ALL, &errnum);

	if (phost)
		add_aliases(phost);

finish:
	if (sock != -1)
		(void) close(sock);
	if (lifc) {
		free(lifc->lifc_buf);
		free(lifc);
	}
}

/*
 * add_aliases traverses a hostent alias list, compares
 * the aliases to the contents of host_name, and if an
 * alias is not already present, adds it to host_name[].
 */

static void
add_aliases(struct hostent *phost)
{
	char **aliases;

	if (!in_host_array(phost->h_name)) {
		add_to_host_array(phost->h_name);
	}

	if (phost->h_aliases == NULL)
		return;			/* no aliases to register */

	for (aliases = phost->h_aliases; *aliases != NULL; aliases++) {
		if (!in_host_array(*aliases)) {
			add_to_host_array(*aliases);
		}
	}
}

/*
 * in_host_array checks if the given hostname exists in the host_name
 * array. Returns 0 if the host doesn't exist, and 1 if it does exist
 */
static int
in_host_array(char *host)
{
	int i;

	if (debug)
		(void) printf("%s ", host);

	if ((strcmp(hostname, host) == 0) || (strcmp(LOGHOST, host) == 0))
		return (1);

	for (i = 0; i < addrix; i++) {
		if (strcmp(host_name[i], host) == 0)
			return (1);
	}

	return (0);
}

/*
 * add_to_host_array adds a hostname to the host_name array. But if
 * the array is already full, then it first reallocates the array with
 * HOST_NAME_INCR extra elements. If the realloc fails, then it does
 * nothing and leaves host_name the way it was previous to the call.
 */
static void
add_to_host_array(char *host) {

	void *new_block = NULL;

	/* Make sure we don't overrun host_name. */
	if (addrix >= host_name_count) {
		host_name_count += HOST_NAME_INCR;
		new_block = realloc((void *)host_name,
				    host_name_count*sizeof (char *));
		if (new_block != NULL)
			host_name = new_block;
		else {
			host_name_count -= HOST_NAME_INCR;
			return;
		}
	}

	if ((host_name[addrix] = strdup(host)) != NULL)
		addrix++;
}

/*
 * Compares the unqualified hostnames for hosts. Returns 0 if the
 * names match, and 1 if the names fail to match.
 */
int
str_cmp_unqual_hostname(char *rawname1, char *rawname2)
{
	size_t unq_len1, unq_len2;
	char *domain;

	if (debug) {
		(void) printf("str_cmp_unqual: rawname1= %s, rawname2= %s\n",
		    rawname1, rawname2);
	}

	unq_len1 = strcspn(rawname1, ".");
	unq_len2 = strcspn(rawname2, ".");
	domain = strchr(rawname1, '.');
	if (domain != NULL) {
		if ((strncmp(rawname1, SM_ADDR_IPV4, unq_len1) == 0) ||
		    (strncmp(rawname1, SM_ADDR_IPV6, unq_len1) == 0))
		return (1);
	}

	if ((unq_len1 == unq_len2) &&
	    (strncmp(rawname1, rawname2, unq_len1) == 0)) {
		return (0);
	}

	return (1);
}

/*
 * Compares <family>.<address-specifier> ASCII names for hosts.  Returns
 * 0 if the addresses match, and 1 if the addresses fail to match.
 * If the args are indeed specifiers, they should look like this:
 *
 *	ipv4.192.9.200.1 or ipv6.::C009:C801
 */
int
str_cmp_address_specifier(char *specifier1, char *specifier2)
{
	size_t unq_len1, unq_len2;
	char *rawaddr1, *rawaddr2;
	int af1, af2, len;

	if (debug) {
		(void) printf("str_cmp_addr: specifier1= %s, specifier2= %s\n",
		    specifier1, specifier2);
	}

	/*
	 * Verify that:
	 *	1. The family tokens match;
	 *	2. The IP addresses following the `.' are legal; and
	 *	3. These addresses match.
	 */
	unq_len1 = strcspn(specifier1, ".");
	unq_len2 = strcspn(specifier2, ".");
	rawaddr1 = strchr(specifier1, '.');
	rawaddr2 = strchr(specifier2, '.');

	if (strncmp(specifier1, SM_ADDR_IPV4, unq_len1) == 0) {
		af1 = AF_INET;
		len = 4;
	} else if (strncmp(specifier1, SM_ADDR_IPV6, unq_len1) == 0) {
		af1 = AF_INET6;
		len = 16;
	}
	else
		return (1);

	if (strncmp(specifier2, SM_ADDR_IPV4, unq_len2) == 0)
		af2 = AF_INET;
	else if (strncmp(specifier2, SM_ADDR_IPV6, unq_len2) == 0)
		af2 = AF_INET6;
	else
		return (1);

	if (af1 != af2)
		return (1);

	if (rawaddr1 != NULL && rawaddr2 != NULL) {
		char dst1[16];
		char dst2[16];
		++rawaddr1;
		++rawaddr2;

		if (inet_pton(af1, rawaddr1, dst1) == 1 &&
		    inet_pton(af2, rawaddr1, dst2) == 1 &&
		    memcmp(dst1, dst2, len) == 0) {
			return (0);
		}
	}
	return (1);
}

/*
 * Add IP address strings to the host_name list.
 */
void
merge_ips(void)
{
	struct ifaddrs *ifap, *cifap;
	int error;

	error = getifaddrs(&ifap);
	if (error) {
		syslog(LOG_WARNING, "getifaddrs error: '%s'",
		    strerror(errno));
		return;
	}

	for (cifap = ifap; cifap != NULL; cifap = cifap->ifa_next) {
		struct sockaddr *sa = cifap->ifa_addr;
		char addr_str[INET6_ADDRSTRLEN];
		void *addr = NULL;

		switch (sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;

			/* Skip loopback addresses. */
			if (sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
				continue;
			}

			addr = &sin->sin_addr;
			break;
		}

		case AF_INET6: {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

			/* Skip loopback addresses. */
			if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) {
				continue;
			}

			addr = &sin6->sin6_addr;
			break;
		}

		default:
			syslog(LOG_WARNING, "Unknown address family %d for "
			    "interface %s", sa->sa_family, cifap->ifa_name);
			continue;
		}

		if (inet_ntop(sa->sa_family, addr, addr_str, sizeof (addr_str))
		    == NULL) {
			syslog(LOG_WARNING, "Failed to convert address into "
			    "string representation for interface '%s' "
			    "address family %d", cifap->ifa_name,
			    sa->sa_family);
			continue;
		}

		if (!in_host_array(addr_str)) {
			add_to_host_array(addr_str);
		}
	}

	freeifaddrs(ifap);
}
