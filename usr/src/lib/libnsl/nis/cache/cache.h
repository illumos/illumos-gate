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

#ifndef	_CACHE_H
#define	_CACHE_H


#ifdef __cplusplus
extern "C" {
#endif


#include <stdlib.h>
#include "../gen/nis_local.h"
#include "../gen/nis_clnt.h"

#define	CLIENT_FILE	"/var/nis/client_info"

#define	PREF_ALL_VAL	0
#define	PREF_ONLY_VAL	1
#define	PREF_ALL	"all"
#define	PREF_ONLY	"pref_only"
#define	PREF_SRVR	"pref_srvr"
#define	PREF_TYPE	"pref_type"

#define	ONE_HOUR	(1 * 60 * 60)

// Semaphores for cache manager
#define	NIS_SEM_W_KEY 100303	// key for the writer semaphore
#define	NIS_W_NSEMS   1		// number of semaphores in the writer array

// in the writer array
#define	NIS_SEM_MGR_UP   0	// is the cache manager running?

#define	SEM_OWNER_READ	0400
#define	SEM_OWNER_ALTER	0200
#define	SEM_GROUP_READ	0040
#define	SEM_GROUP_ALTER	0020
#define	SEM_OTHER_READ	0004
#define	SEM_OTHER_ALTER	0002

extern int __nis_debuglevel;

struct HostEnt {
	char *name;
	char *interface;
	int rank;
	HostEnt *next;
};

class HostList {
    public:
	HostList();
	~HostList();
	void addHost(char *name, char *interface, int rank);
	int checkHost(char *value, char *interface, int *rank);
	int matchHost(char *name, char *uaddr, int *rank);
	int serves(directory_obj *dobj);
	int dumpList(FILE *fp);
	void addOption(int value);
	void dumpOption(FILE *fp);
	void deleteBackupList();
	void deleteList();
	void backupList();
	void restoreList();

	int pref_option;

	void *operator new(size_t bytes) { return calloc(1, bytes); }
	void operator delete(void *arg) { free(arg); }
    private:
	HostEnt *entries, *old_entries;
	int	old_pref_option;
};

class NisCache {
    public:
	NisCache();
	~NisCache();

	// This set of routines is the primary interface to the
	// cache classes.  The NisCache class provides default
	// implementations of them.  The derived classes override
	// them if necessary.

	virtual int okay();
	virtual nis_error searchDir(char *dname,
		    nis_bound_directory **binding, int near);
	virtual nis_error bindReplica(char *dname,
		    nis_bound_directory **binding);
	virtual nis_error bindMaster(char *dname,
		    nis_bound_directory **binding);
	virtual nis_error bindServer(nis_server *srv, int nsrv,
		    nis_bound_directory **binding);
	virtual int refreshBinding(nis_bound_directory *binding);
	virtual int refreshAddress(nis_bound_endpoint *bep);
	virtual int refreshCallback(nis_bound_endpoint *bep);
	virtual bool_t readColdStart();
	virtual bool_t readServerColdStart(uint32_t *exp_time);
	virtual void print();

	virtual void addBinding(nis_bound_directory *binding);
	virtual void removeBinding(nis_bound_directory *binding);

	virtual void activeAdd(nis_active_endpoint *act);
	virtual void activeRemove(endpoint *ep, int all);
	virtual int activeCheck(endpoint *ep);
	virtual int activeGet(endpoint *ep, nis_active_endpoint **act);

	virtual int getStaleEntries(nis_bound_directory ***binding);
	virtual int getAllEntries(nis_bound_directory ***binding);
	virtual int getAllActive(nis_active_endpoint ***actlist);
	virtual void addAddresses(nis_bound_directory *binding);
	virtual uint32_t loadPreferredServers();
	virtual uint32_t refreshCache();
	virtual int checkUp();

	virtual int resetBinding(nis_bound_directory *binding);


	// This is a set of helper routines for derived classes to
	// use.

	void printBinding(nis_bound_directory *binding);
	void printBinding_exptime(nis_bound_directory *binding,
							uint32_t exptime);
	void printActive(nis_active_endpoint *act);
	nis_error loadDirectory(char *dname);
	nis_error loadDirectory(char *dname, int force_finddir);
	nis_active_endpoint *activeDup(nis_active_endpoint *src);
	void activeFree(nis_active_endpoint *act);
	void *packBinding(nis_bound_directory *binding, int *len);
	nis_bound_directory *unpackBinding(void *data, int len);
	void *packActive(nis_active_endpoint *act, int *len);
	nis_active_endpoint *unpackActive(void *data, int len);
	void sortServers(nis_bound_directory *binding);
	nis_error pingServers(nis_server *srv, int nsrv, int quick);
	uint32_t expireTime(uint32_t ttl);
	int nextGeneration();
	void rerankServers();
	void writePreference(FILE *fp);
	void mergePreference(char *value);
	void mergeOption(const char *value);
	void resetPreference();
	void backupPreference();
	void delBackupPref();
	void restorePreference();
	uint32_t loadDotFile();

	nis_error createBinding(fd_result *res);
	nis_error createBinding(directory_obj *res);

	char *coldStartDir();

	// We define a new and delete routine so that we don't
	// depend on libC at run time.

	void *operator new(size_t bytes) { return calloc(1, bytes); }
	void operator delete(void *arg) { free(arg); }

    private:
	mutex_t gen_lock;
	int gen;
	char *cold_start_dir;
	HostList prefer;

	void extractAddresses(nis_bound_directory *binding);
	void printDirectorySpecial(directory_obj *dobj);
	int rankServer(nis_server *srv, endpoint *ep, void *local_interfaces);
};

#ifdef	__cplusplus
}
#endif

#endif	/* _CACHE_H */
