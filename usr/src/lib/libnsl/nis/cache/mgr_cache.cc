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

#include "mt.h"
#include "mgr_cache.h"
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "nis_cache.h"

NisMgrCache::NisMgrCache(nis_error &err, int discardOldCache)
	: NisMappedCache(err, 1, discardOldCache)
{
	config_interval = CONFIG_WAIT;
	ping_time = expireTime(PING_WAIT);
	config_time = expireTime(config_interval);
	refresh_time = expireTime(MIN_REFRESH_WAIT);
}

NisMgrCache::~NisMgrCache()
{
	markDown();
}

void
NisMgrCache::start()
{
	(void) loadPreferredServers();
	(void) readColdStart();
}

uint32_t
NisMgrCache::nextTime()
{
	uint32_t next_time;
	struct timeval now;
	uint32_t ret_value;

	/* figure out how long until the next timer goes off */
	next_time = refresh_time;
	if (ping_time < next_time)
		next_time = ping_time;
	if (config_time < next_time)
		next_time = config_time;
	if (next_time == 0)
		return (MIN_REFRESH_WAIT);

	(void) gettimeofday(&now, NULL);

	ret_value = next_time - (uint32_t) now.tv_sec;
	if (ret_value == 0)
		ret_value = MIN_REFRESH_WAIT;
	return (ret_value);
}



uint32_t
NisMgrCache::timers()
{
	struct timeval now;
	int rt;

	(void) gettimeofday(&now, NULL);
	if (now.tv_sec >= refresh_time) {
		refresh();
		rt = nextStale();
		if (rt < MIN_REFRESH_WAIT)
			refresh_time = (uint32_t)now.tv_sec + MIN_REFRESH_WAIT;
		else
			refresh_time = (uint32_t)now.tv_sec + rt;
	}
	if (now.tv_sec >= ping_time) {
		ping();
		ping_time = expireTime(PING_WAIT);
	}

	if (now.tv_sec >= config_time) {
		config_time = config();
	}

	return (nextTime());
}


/*
 * Reload the server information.
 */
uint32_t
NisMgrCache::config()
{
	uint32_t ll;

	backupPreference();
	if (config_time = loadLocalFile()) {
		ll = writeDotFile();
		delBackupPref();
		rerankServers();
		ping();
		ping_time = expireTime(PING_WAIT);
		return (ll);
	}
	if (config_time = loadNisTable()) {
		ll = writeDotFile();
		delBackupPref();
		rerankServers();
		ping();
		ping_time = expireTime(PING_WAIT);
		return (ll);
	}

	/*
	 * Failed to load preferred info from both the local file and
	 * NIS+ table.  Keep the current list for now.
	 */
	syslog(LOG_ERR,
	"Failed to load the new preferred server info. Reusing current list.");
	restorePreference();
	return (0);
}


uint32_t
NisMgrCache::refreshCache()
{
	config_time = config();
	return (nextTime());

}

/*
 *  Reload all stale entries.  We only remove a cache entry if we
 *  get a definitive answer that says the directory no longer
 *  exists.  We keep the cache entry if we get other errors on the
 *  assumption that out-of-date information is better than no
 *  information at all.
 *
 *  It might make more sense to only do one of them if the cache manager
 *  is single-threaded.
 */
void
NisMgrCache::refresh()
{
	int i;
	int n;
	nis_error err;
	nis_bound_directory **bindings;

	n = getStaleEntries(&bindings);
	for (i = 0; i < n; i++) {
		refreshBinding(bindings[i]);
		nis_free_binding(bindings[i]);
	}
	free(bindings);
}

void
NisMgrCache::ping()
{
	int i;
	int n;
	nis_server *srv;
	int nsrv;
	nis_bound_directory **bindings;

	n = getAllEntries(&bindings);
	for (i = 0; i < n; i++) {
		srv = bindings[i]->dobj.do_servers.do_servers_val;
		nsrv = bindings[i]->dobj.do_servers.do_servers_len;
		(void) pingServers(srv, nsrv, 0);
		nis_free_binding(bindings[i]);
	}
	free(bindings);
}

int
NisMgrCache::checkUp()
{
	/* Since I am the CacheManager, this function always returns true */
	return (TRUE);
}

uint32_t
NisMgrCache::writeDotFile()
{
	FILE *fp;
	char tempName[MAXPATHLEN+1];

	(void) sprintf(tempName, "%s.tmp", DOT_FILE);
	fp = fopen(tempName, "wF");
	if (fp == NULL)
		return (0);

	(void) fprintf(fp, "%u\n", config_time);
	writePreference(fp);
	(void) fclose(fp);
	if (rename(tempName, DOT_FILE) == -1) {
		(void) unlink(tempName);
		syslog(LOG_ERR, "cannot rename %s file", DOT_FILE);
		return (0);
	}
	return (config_time);
}



void
NisMgrCache::parse_info(char *info, char **srvr, char **option)
{
	char *p, *buf;
	int l;

	*srvr = *option = NULL;
	if (info == NULL || *info == '\0')
		return;

	while (*info) {
		while (*info && isspace(*info))
			info++;
		if (*info == '\0')
			break;
		p = info;
		while (*info && !isspace(*info))
			info++;
		if (strncasecmp(p, PREF_SRVR, strlen(PREF_SRVR)) == 0) {
			/* preferred server info */
			p = p + strlen(PREF_SRVR);
			if (*p != '=' || *srvr != NULL)
				continue;
			p++;
			l = info - p;
			buf = (char *) malloc((l + 1) * sizeof (char));
			if (buf == NULL) {
				syslog(LOG_ERR, "parse_info: out of memory");
				break;
			}
			(void) strncpy(buf, p, l);
			buf[l] = '\0';
			*srvr = buf;
		} else if (strncasecmp(p, PREF_TYPE, strlen(PREF_TYPE)) == 0) {
			/* preferred type info */
			p = p + strlen(PREF_TYPE);
			if (*p != '=' || *option != NULL)
				continue;
			p++;
			l = info - p;
			buf = (char *) malloc((l + 1) * sizeof (char));
			if (buf == NULL) {
				syslog(LOG_ERR, "parse_info: out of memory");
				break;
			}
			(void) strncpy(buf, p, l);
			buf[l] = '\0';
			*option = buf;
		}
	}
}



char *
NisMgrCache::get_line(FILE *fp)
{
	char *p;
	int len, cont = 0;
	char *value = NULL;
	char buf[1024];

	while ((p = fgets(buf, sizeof (buf), fp)) != NULL) {
		cont = 0;
		len = strlen(p);
		if ((len - 1 >= 0) && (p[len - 1] == '\n'))
			p[len - 1] = '\0';
		if ((len - 2 >= 0) && (p[len - 2] == '\\')) {
			cont = 1;
			p[len - 2] = '\0';
		}

		if (value == NULL) {
			value = strdup(p);
			if (value == NULL) {
				syslog(LOG_ERR, "get_line: out of memory");
				return (NULL);
			}
		} else {
			value = (char *)realloc(value, strlen(value) + len + 2);
			if (value == NULL) {
				syslog(LOG_ERR, "get_line: out of memory");
				return (NULL);
			}
			while (*p && isspace(*p))
				p++;
			(void) strcat(value, p);
		}
		if (!cont)
			break;  /* complete line */
	}
	return (value);
}



uint32_t
NisMgrCache::loadLocalFile()
{
	FILE *fp;
	char *value = NULL, *client = NULL, *srvr = NULL;
	char *option = NULL, *info = NULL, *p = NULL;
	char hosts[256];
	int hostfound = 0;
	void *local = NULL;
	int n = 0, i;
	struct in_addr	in4addr_loopback;

	/* For IPv4, we want the loopback net, not the loopback address */
	in4addr_loopback.s_addr = IN_LOOPBACKNET << IN_CLASSA_NSHIFT;

	fp = fopen(CLIENT_FILE, "rF");
	if (fp == NULL)
		return (0);

	if (gethostname(hosts, 256)) {
		syslog(LOG_ERR, "loadLocalFile: gethostname failed [errno=%d]",
				errno);
		(void) fclose(fp);
		return (0);
	}

	local = __inet_get_local_interfaces();

	while ((value = get_line(fp)) != NULL) {
		srvr = NULL;
		option = NULL;
		client = value;
		p = value;
		while (*p && !isspace(*p))
			p++;
		if (*p == '\0') {
			free(value);
			continue;
		}

		*p++ = '\0';
		while (*p && isspace(*p))
			p++;
		info = p;
		if (strncasecmp(client, hosts, strlen(hosts)) == 0) {
			/*
			 * If hostfound not already set, set hostfound and
			 * reset the preferred server info to remove all
			 * subnet specific entries.
			 * This will skip the search by subnet.
			 */
			if (!hostfound) {
				resetPreference();
				hostfound = 1;
			}
		} else if (hostfound) {
			/* don't check subnet entries */
			free(value);
			continue;
		} else {
			/* Assume subnet entry; check if it is a local subnet */
			sa_family_t	af;
			struct in_addr	in4;
			struct in6_addr	in6;
			void		*addr;

			af =  (strchr(client, ':') != 0) ? AF_INET6 : AF_INET;
			if (af == AF_INET6 &&
				strlen(client) < INET6_ADDRSTRLEN) {
				addr = (void *)&in6;
			} else if (strlen(client) < INET_ADDRSTRLEN) {
				addr = (void *)&in4;
			} else {
				/* Don't know what kind of address this is */
				free(value);
				continue;
			}
			if (inet_pton(af, client, addr) != 1) {
				free(value);
				continue;
			}
			if ((af == AF_INET6 && IN6_IS_ADDR_LOOPBACK(&in6)) ||
				(af == AF_INET && in4.s_addr ==
						in4addr_loopback.s_addr)) {
				free(value);
				continue;
			}
			if (!__inet_address_is_local_af(local, af, addr)) {
				free(value);
				continue;
			}
		}
		parse_info(info, &srvr, &option);
		mergePreference(srvr);
		mergeOption(option);
		if (srvr != NULL)
			free(srvr);
		if (option != NULL)
			free(option);
		free(value);
	}

	if (local) {
		__inet_free_local_interfaces(local);
	}
	(void) fclose(fp);
	config_interval = CONFIG_WAIT;
	return (expireTime(config_interval));
}



uint32_t
NisMgrCache::loadNisTable()
{
	int i;
	int n;
	int old_format;
	char *subnet, host[256];
	void *local;
	nis_result *res = NULL;
	nis_object *obj;
	char name[NIS_MAXNAMELEN];
	char *p_srvr = NULL, *p_type = NULL;
	uint32_t ttl;

	(void) sprintf(name, "client_info.org_dir.%s", nis_local_directory());
	res = nis_lookup(name, FOLLOW_LINKS|FOLLOW_PATH);
	if (res == NULL) {
		syslog(LOG_ERR, "out of memory");
		return (0);
	}
	if (res->status != NIS_SUCCESS) {
		/* table does not exist */
		nis_freeresult(res);
		config_interval = CONFIG_WAIT;
		return (expireTime(config_interval));
	}

	obj = res->objects.objects_val;
	ttl = obj->zo_ttl;	/* use tables TTL */
	if (obj->TA_data.ta_cols.ta_cols_len == 2)
		old_format = 1;	/* need old format for back compat */
	else
		old_format = 0;
	nis_freeresult(res);
	res = NULL;

	/*
	 * lookup in the client_info table based on the
	 * the host name first.
	 */
	if (gethostname(host, 256)) {
		syslog(LOG_ERR, "gethostname() failed [errno=%d]",
			errno);
		return (0);
	}
	if (old_format)
		(void) sprintf(name, "[client=%s],client_info.org_dir.%s",
			host, nis_local_directory());
	else	/* new format */
		(void) sprintf(name,
		    "[client=%s,attr=%s],client_info.org_dir.%s",
		    host, PREF_SRVR, nis_local_directory());

	res = nis_list(name, FOLLOW_LINKS|FOLLOW_PATH, 0, 0);
	if (res == NULL) {
		syslog(LOG_ERR, "out of memory");
		return (0);
	}

	if (res->status == NIS_SUCCESS) {
		obj = res->objects.objects_val;
		if (old_format)
			parse_info(ENTRY_VAL(obj, 1), &p_srvr, &p_type);
		else {		/* new format */
			p_srvr = ENTRY_VAL(obj, 2);
			p_type = ENTRY_VAL(obj, 3);
		}
		mergePreference(p_srvr);
		mergeOption(p_type);
		if (old_format) {
			if (p_srvr)
				free(p_srvr);
			if (p_type)
				free(p_type);
		}
		nis_freeresult(res);
		config_interval = ttl;
		return (expireTime(ttl));
	} else
		nis_freeresult(res);

	/*
	 * no host specific entries found.  Now try looking up subnet
	 * entries.
	 */
	local = __inet_get_local_interfaces();
	if (local == NULL)
		return (0);

	n = __inet_address_count(local);
	for (i = 0; i < n; i++) {
		subnet = __inet_get_networka(local, i);
		if (strcmp(subnet, "127.0.0.0") == 0 ||
			strcmp(subnet, "::1") == 0) {
			free(subnet);
			continue;
		}
		if (old_format)
			(void) sprintf(name,
			    "[client=%s],client_info.org_dir.%s",
			    subnet, nis_local_directory());
		else	/* new format */
			(void) sprintf(name,
				"[client=%s,attr=%s],client_info.org_dir.%s",
				subnet, PREF_SRVR, nis_local_directory());
		res = nis_list(name, FOLLOW_LINKS|FOLLOW_PATH, 0, 0);
		free((void *)subnet);
		if (res == NULL) {
			syslog(LOG_ERR, "out of memory");
			__inet_free_local_interfaces(local);
			return (0);
		} else if (res->status != NIS_SUCCESS) {
			nis_freeresult(res);
			continue;
		}

		obj = res->objects.objects_val;
		if (old_format)
			parse_info(ENTRY_VAL(obj, 1), &p_srvr, &p_type);
		else {		/* new format */
			p_srvr = ENTRY_VAL(obj, 2);
			p_type = ENTRY_VAL(obj, 3);
		}
		mergePreference(p_srvr);
		mergeOption(p_type);
		if (old_format) {
			if (p_srvr)
				free(p_srvr);
			if (p_type)
				free(p_type);
		}
		nis_freeresult(res);
	}
	__inet_free_local_interfaces(local);
	config_interval = ttl;
	return (expireTime(ttl));
}



uint32_t
NisMgrCache::loadPreferredServers()
{
	extern char *__nis_prefsrv;

	/*
	 * read from the "dot" file first.  If successful, no need to
	 * look at the local client_info file and table.
	 */
	if (config_time = loadDotFile())
		return (config_time);

	/*
	 * read from the local client_info file.  If file is found and
	 * not empty, no need to look at the client_info table.
	 */
	if (config_time = loadLocalFile()) {
		(void) writeDotFile();
		return (config_time);
	}

	/*
	 * read from the NIS+ table.
	 */
	if (config_time = loadNisTable()) {
		(void) writeDotFile();
		return (config_time);
	}

	return (0);
}
