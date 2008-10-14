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


#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/mnttab.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>

#include <locale.h>
#include <langinfo.h>
#include <libintl.h>
#include <stdarg.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/utsname.h>

#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/rdc_ioctl.h>
#include <sys/nsctl/rdc_prot.h>

#include <sys/nsctl/cfg.h>
#include <sys/nsctl/cfg_cluster.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#include "rdcadm.h"

/*
 * Special re-use of sndrboot to fix SNDR set IDs during post-patch processing
 */
#define	RDC_CMD_FIXSETIDS	0xFEEDFACE

/*
 * config file user level Dual copy pair structure
 */
typedef struct _sd_dual_pair {
	char fhost[MAX_RDC_HOST_SIZE];	/* Hostname for primary device */
	char fnetaddr[RDC_MAXADDR];	/* Host netaddr for primary device */
	char ffile[NSC_MAXPATH];	/* Primary device */
	char fbitmap[NSC_MAXPATH];	/* Primary bitmap device */
	char thost[MAX_RDC_HOST_SIZE];	/* Hostname for secondary device */
	char tnetaddr[RDC_MAXADDR];	/* Host netaddr for secondary device */
	char tfile[NSC_MAXPATH];	/* Secondary device */
	char tbitmap[NSC_MAXPATH];	/* Secondary bitmap device */
	char directfile[NSC_MAXPATH];	/* Local FCAL direct IO volume */
	char diskqueue[NSC_MAXPATH];	/* Disk Queue volume */
	char group[NSC_MAXPATH];	/* Group name */
	char lhost[MAX_RDC_HOST_SIZE];  /* Logical hostname for cluster */
	int  doasync;			/* Device is in sync/async mode */
	int  setid;			/* unique setid of this set */
} _sd_dual_pair_t;

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <rpc/rpc_com.h>
#include <rpc/rpc.h>

#include <sys/nsctl/librdc.h>

char *ctag = NULL;

int parseopts(int, char **, int *);
static int rdc_operation(char *, char *, char *, char *, char *, char *, int,
    char *, char *, char *, int, char *, int setid);
static int read_libcfg(int);
static void usage(void);

extern char *basename(char *);

int rdc_maxsets;
static _sd_dual_pair_t *pair_list;
char *program;

struct netbuf svaddr;
struct netbuf *svp;
struct netconfig nconf;
struct netconfig *conf;
struct knetconfig knconf;
static int clustered = 0;
static int proto_test = 0;

#ifdef lint
int
sndrboot_lintmain(int argc, char *argv[])
#else
int
main(int argc, char *argv[])
#endif
{
	char fromhost[MAX_RDC_HOST_SIZE];
	char tohost[MAX_RDC_HOST_SIZE];
	char fromfile[NSC_MAXPATH];
	char tofile[NSC_MAXPATH];
	char frombitmap[NSC_MAXPATH];
	char tobitmap[NSC_MAXPATH];
	char directfile[NSC_MAXPATH];
	char diskqueue[NSC_MAXPATH];
	char group[NSC_MAXPATH];
	char lhost[MAX_RDC_HOST_SIZE];
	int pairs;
	int pid;
	int flag = 0;
	int doasync;
	int rc;
	char *required;
	int setid;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("rdc");

	program = basename(argv[0]);

	rc = rdc_check_release(&required);
	if (rc < 0) {
		rdc_err(NULL,
		    gettext("unable to determine the current "
		    "Solaris release: %s\n"), strerror(errno));
	} else if (rc == FALSE) {
		rdc_err(NULL,
		    gettext("incorrect Solaris release (requires %s)\n"),
		    required);
	}

	rdc_maxsets = rdc_get_maxsets();
	if (rdc_maxsets == -1) {
		spcs_log("sndr", NULL,
		    gettext("%s unable to get maxsets value from kernel"),
		    program);

		rdc_err(NULL,
		    gettext("unable to get maxsets value from kernel"));
	}

	pair_list = calloc(rdc_maxsets, sizeof (*pair_list));
	if (pair_list == NULL) {
		rdc_err(NULL,
		    gettext(
			"unable to allocate pair_list"
			" array for %d sets"),
			rdc_maxsets);
	}

	if (parseopts(argc, argv, &flag))
		return (1);
	pairs = read_libcfg(flag);

	if (flag == RDC_CMD_FIXSETIDS) {
		if (pairs) {
			spcs_log("sndr", NULL, gettext("Fixed %d Remote Mirror"
				    " set IDs"), pairs);
#ifdef DEBUG
			rdc_warn(NULL, gettext("Fixed %d Remote Mirror set "
				    "IDs"), pairs);
#endif
		}
		return (0);
	}

	if (pairs == 0) {
#ifdef DEBUG
		rdc_err(NULL,
		    gettext("Config contains no dual copy sets"));
#else
		return (0);
#endif
	}

	while (pairs--) {
		pid = fork();
		if (pid == -1) {		/* error forking */
			perror("fork");
			continue;
		}

		if (pid > 0)		/* this is parent process */
			continue;

/*
 * At this point, this is the child process.  Do the operation
 */

		strncpy(fromfile,
			pair_list[pairs].ffile, NSC_MAXPATH);
		strncpy(tofile,
			pair_list[pairs].tfile, NSC_MAXPATH);
		strncpy(frombitmap,
			pair_list[pairs].fbitmap, NSC_MAXPATH);
		strncpy(fromhost,
			pair_list[pairs].fhost, MAX_RDC_HOST_SIZE);
		strncpy(tohost,
			pair_list[pairs].thost, MAX_RDC_HOST_SIZE);
		strncpy(tobitmap,
			pair_list[pairs].tbitmap, NSC_MAXPATH);
		strncpy(directfile,
			pair_list[pairs].directfile, NSC_MAXPATH);
		strncpy(diskqueue,
			pair_list[pairs].diskqueue, NSC_MAXPATH);
		strncpy(group,
			pair_list[pairs].group, NSC_MAXPATH);
		strncpy(lhost,
			pair_list[pairs].lhost, MAX_RDC_HOST_SIZE);

		doasync = pair_list[pairs].doasync;
		setid = pair_list[pairs].setid;
		if (rdc_operation(fromhost, fromfile, frombitmap,
		    tohost, tofile, tobitmap, flag, directfile, group,
		    diskqueue, doasync, lhost, setid)
		    < 0) {
			exit(255);
		}

		exit(0);
	}

	while ((wait((int *)0) > 0))
		;
	return (0);
}

static int
rdc_operation(fromhost, fromfile, frombitmap, tohost, tofile,
    tobitmap, flag, directfile, group, diskqueue, doasync,
    lhost, setid)
char *fromhost, *fromfile, *frombitmap;
char *tohost, *tofile, *tobitmap;
int flag, doasync;
char *directfile;
char *group, *diskqueue;
int setid;
char *lhost;
{
	const int getaddr = (flag == RDC_CMD_RESUME);
	const int rpcbind = !getaddr;
	rdc_config_t parms;
	int ret;
	spcs_s_info_t ustatus;
	struct hostent *hp;
	char fromname[MAXHOSTNAMELEN], toname[MAXHOSTNAMELEN];
	struct t_info tinfo;
	int i;

	conf = &nconf;
	bzero(&fromname, MAXHOSTNAMELEN);
	bzero(&toname, MAXHOSTNAMELEN);

	hp = gethost_byname(fromhost);
	if (hp == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s gethost_byname failed for %s"),
		    program, fromhost);
	}
	if (strcmp(hp->h_name, fromhost) == 0)
		strncpy(fromname, hp->h_name, MAXHOSTNAMELEN);
	else {
	for (i = 0; hp->h_aliases[i] != NULL; i++) {
		if (strcmp(hp->h_aliases[i], fromhost) == 0)
			strncpy(fromname, hp->h_aliases[i], MAXHOSTNAMELEN);
		}
	}
	if (fromname[0] == '\0') {
		spcs_log("sndr", NULL,
		    gettext("%s host %s is not local"),
		    program, fromhost);
		rdc_err(NULL, gettext("Host %s is not local"),
		    fromhost);
	}
	hp = gethost_byname(tohost);
	if (hp == NULL) {
		spcs_log("sndr", NULL,
		    gettext("%s gethost_byname failed for %s"),
		    program, tohost);
	}
	if (strcmp(hp->h_name, tohost) == 0)
		strncpy(toname, hp->h_name, MAXHOSTNAMELEN);
	else {
	for (i = 0; hp->h_aliases[i] != NULL; i++) {
		if (strcmp(hp->h_aliases[i], tohost) == 0)
			strncpy(toname, hp->h_aliases[i], MAXHOSTNAMELEN);
		}
	}
	if (toname[0] == '\0') {
		spcs_log("sndr", NULL,
		    gettext("%s host %s is not local"),
		    program, tohost);
		rdc_err(NULL, gettext("Host %s is not local"),
		    tohost);
	}

	if (self_check(fromname) && self_check(toname)) {
		spcs_log("sndr", NULL,
		    gettext("%s Both %s and %s are local"),
		    program, fromhost, tohost);
		rdc_err(NULL, gettext("Both %s and %s are local"),
		    fromhost, tohost);
	}

	/*
	 * Now build up the address for each host including port and transport
	 */
	if (getaddr) {
		svp = get_addr(toname, RDC_PROGRAM, RDC_VERS_MIN,
			&conf, proto_test?NC_UDP: NULL, "rdc", &tinfo, rpcbind);

		if (svp == NULL) {
#ifdef DEBUG
			(void) printf("get_addr failed for Ver 4 %s\n", toname);
#endif
			spcs_log("sndr", NULL,
			    gettext("%s get_addr failed for Ver 4"),
			    program);
			return (-1);
		}
		svaddr = *svp;
	} else {
		bzero(&svaddr, sizeof (svaddr));
	}

	parms.rdc_set->secondary.addr.len = svaddr.len;
	parms.rdc_set->secondary.addr.maxlen = svaddr.maxlen;
	parms.rdc_set->secondary.addr.buf = (void *)svaddr.buf;

#ifdef DEBUG_ADDR
	(void) fprintf(stderr,
		"secondary buf %x len %d\n", svaddr.buf, svaddr.len);

	for (i = 0; i < svaddr.len; i++)
		(void) printf("%u ", svaddr.buf[i]);
	(void) printf("\n");
#endif

	if (getaddr) {
		svp = get_addr(fromname, RDC_PROGRAM, RDC_VERS_MIN,
			&conf, proto_test?NC_UDP: NULL, "rdc", &tinfo, rpcbind);
		if (svp == NULL) {
#ifdef DEBUG
			(void) printf("get_addr failed for Ver 4 %s\n",
			    fromname);
#endif
			return (-1);
		}
		svaddr = *svp;
	} else {
		;
		/*EMPTY*/
	}
	parms.rdc_set->primary.addr.len = svaddr.len;
	parms.rdc_set->primary.addr.maxlen = svaddr.maxlen;
	parms.rdc_set->primary.addr.buf =
				(void *)svaddr.buf;

#ifdef DEBUG_ADDR
	(void) fprintf(stderr, "primary buf %x len %d\n",
	    svaddr.buf, svaddr.len);
	for (i = 0; i < svaddr.len; i++)
		(void) printf("%u ", svaddr.buf[i]);
	(void) printf("\n");
#endif

	if (getaddr) {
		(void) convert_nconf_to_knconf(conf, &knconf);
#ifdef DEBUG_ADDR
		(void) printf("knconf %x %s %s %x\n", knconf.knc_semantics,
		    knconf.knc_protofmly, knconf.knc_proto, knconf.knc_rdev);
#endif
		parms.rdc_set->netconfig = &knconf;
	} else {
		parms.rdc_set->netconfig = NULL;
	}
	if (!clustered && !self_check(fromname) && !self_check(toname)) {
		spcs_log("sndr", NULL,
		    gettext("%s Neither %s nor %s is local"),
		    program, fromhost, tohost);
		rdc_err(NULL, gettext("Neither %s nor %s is local"),
		    fromhost, tohost);
	}
	strncpy(parms.rdc_set->primary.intf, fromhost, MAX_RDC_HOST_SIZE);
	strncpy(parms.rdc_set->primary.file, fromfile, NSC_MAXPATH);
	strncpy(parms.rdc_set->primary.bitmap, frombitmap, NSC_MAXPATH);

	strncpy(parms.rdc_set->secondary.intf, tohost, MAX_RDC_HOST_SIZE);
	strncpy(parms.rdc_set->secondary.file, tofile, NSC_MAXPATH);
	strncpy(parms.rdc_set->secondary.bitmap, tobitmap, NSC_MAXPATH);

	strncpy(parms.rdc_set->group_name, group, NSC_MAXPATH);
	strncpy(parms.rdc_set->disk_queue, diskqueue, NSC_MAXPATH);

	parms.rdc_set->maxqfbas = maxqfbas;
	parms.rdc_set->maxqitems = maxqitems;
	parms.rdc_set->autosync = autosync;
	parms.rdc_set->asyncthr = asyncthr;
	parms.rdc_set->setid = setid;

	/* gethostid(3c) is defined to return a 32bit value */
	parms.rdc_set->syshostid = (int32_t)gethostid();

	parms.command = 0;
	parms.options = 0;
	parms.command = flag;

	if (flag == RDC_CMD_RESUME) {
		if (doasync)
			parms.options |= RDC_OPT_ASYNC;
		else
			parms.options |= RDC_OPT_SYNC;
	}
	if (clustered) {
		if (!ctag)
			goto noconfig;
		if (strcmp(ctag, "-") == 0)
			goto noconfig;

#ifdef DEBUG
		(void) fprintf(stderr, "logical hostname: %s\n", lhost);
#endif

		if (strcmp(lhost, fromname) == 0) {
			parms.options |= RDC_OPT_PRIMARY;
			strncpy(parms.rdc_set->direct_file, directfile,
				NSC_MAXPATH);

		} else {
			parms.options |= RDC_OPT_SECONDARY;
			parms.rdc_set->direct_file[0] = 0; /* no fcal direct */
		}
	} else {
noconfig:
		/*
		 * If not clustered, don't resume sndr sets with lhost
		 */
		if ((flag == RDC_CMD_RESUME) && lhost && strlen(lhost))
			return (0);

		if (self_check(fromname)) {
			parms.options |= RDC_OPT_PRIMARY;
			strncpy(parms.rdc_set->direct_file, directfile,
				NSC_MAXPATH);
		} else {
			parms.options |= RDC_OPT_SECONDARY;
			parms.rdc_set->direct_file[0] = 0; /* no fcal direct */
		}
	}

	ustatus = spcs_s_ucreate();

	errno = 0;
	ret = RDC_IOCTL(RDC_CONFIG, &parms, NULL, 0, 0, 0, ustatus);
	if (ret != SPCS_S_OK) {

		/* Surpress error messages for suspend on cluster elements */
		if ((flag == RDC_CMD_SUSPEND) && (errno == RDC_EALREADY) &&
			!clustered && lhost && strlen(lhost)) {
			spcs_s_ufree(&ustatus);
			return (0);
		}

		(void) fprintf(stderr,
			gettext("Remote Mirror: %s %s %s %s %s %s\n"),
			fromhost, fromfile,
			frombitmap, tohost, tofile, tobitmap);

		if (errno == RDC_EEINVAL) {
			spcs_log("sndr", NULL,
			    gettext("%s %s %s %s %s %s %s %s\n%s"),
			    program, rdc_decode_flag(flag, parms.options),
			    fromhost, fromfile, frombitmap,
			    tohost, tofile, tobitmap,
			    gettext("invalid command option"));
			rdc_err(&ustatus,
			    gettext("Remote Mirror: invalid command option "
				    "'%s'"), rdc_decode_flag(flag,
				    parms.options));
		} else {
			spcs_log("sndr", &ustatus,
			    gettext("%s %s %s %s %s %s %s %s"),
			    program, rdc_decode_flag(flag, parms.options),
			    fromhost, fromfile, frombitmap,
			    tohost, tofile, tobitmap);
			rdc_err(&ustatus, 0);
		}
	}

	spcs_log("sndr", NULL,
	    gettext("%s %s %s %s %s %s %s %s\nSuccessful"),
	    program, rdc_decode_flag(flag, parms.options),
	    fromhost, fromfile, frombitmap, tohost, tofile, tobitmap);

	spcs_s_ufree(&ustatus);
	return (0);
}
/*
 * assign setid's to any existing
 * sets without setids, making sure of course NOT to re-use a setid
 */
int
update_setids(CFGFILE *cfg, int *no_id, int highest)
{
	int setid;
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	char *ctag;

	/* If in a Sun Cluster, SetIDs need to have a ctag */
	if ((ctag = cfg_get_resource(cfg)) != NULL) {
		ctag = strdup(ctag);
		cfg_resource(cfg, "setid-ctag");
	}

	/*
	 * Paranoia. IF there are any sets with setids, we don't
	 * want to re-use their number.
	 */
	if (highest > get_new_cfg_setid(cfg)) {
		bzero(&buf, sizeof (buf));
		(void) sprintf(buf, "%d", highest);
		if (cfg_put_cstring(cfg, "setid.set1.value", buf,
		    sizeof (buf)) < 0)
			rdc_warn(NULL, gettext("sndrboot: Unable to store "
			    "new setid"));
	}

	for (setid = 0; no_id[setid]; setid++) {
		bzero(&buf, sizeof (buf));
		bzero(&key, sizeof (key));
		(void) sprintf(buf, "%d", get_new_cfg_setid(cfg));
		(void) sprintf(key, "sndr.set%d.options", no_id[setid]);
		if (cfg_put_options(cfg, CFG_SEC_CONF, key, "setid", buf) < 0)
			rdc_warn(NULL, gettext("sndrboot: Unable to store "
			    "unique setid"));

		pair_list[no_id[setid] - 1].setid = atoi(buf);
	}

	/* Restore old ctag if in a Sun Cluster */
	if (ctag) {
		cfg_resource(cfg, ctag);
		free(ctag);
	}

	if (cfg_commit(cfg) < 0)
		rdc_err(NULL, gettext("sndrboot: Failed to commit setids"));

	return (setid);
}

/*
 * this is called when the option lghn is no available in libdscfg
 * that should only happen on an upgrade.
 * cfg write lock must be held across this function
 */
char *
get_lghn(CFGFILE *cfg, char *ctag, int setnum, int flag)
{
	FILE *pipe;
	char rsgrp[SCCONF_MAXSTRINGLEN];
	char cmd[SCCONF_MAXSTRINGLEN];
	static char lhostname[MAX_RDC_HOST_SIZE];
	char key[CFG_MAX_KEY];
	int rc;

	if (ctag == NULL)
		goto fail;

	bzero(&lhostname, sizeof (lhostname));

	(void) sprintf(rsgrp, "%s-stor-rg", ctag);
/* BEGIN CSTYLED */
	rc = snprintf(cmd, SCCONF_MAXSTRINGLEN,
	    "/usr/cluster/bin/scrgadm -pvv | fgrep HostnameList \
| fgrep %s | fgrep value | awk -F: '{ print $4 }'", rsgrp);
/* END CSTYLED */

	if (rc < 0) {
		rdc_err(NULL, gettext("Error getting scrgadm output"));
	}

	pipe = popen(cmd, "r");

	if (pipe == NULL) {
		rdc_err(NULL, gettext("Error opening pipe"));
	}
	rc = fscanf(pipe, "%s", lhostname);
	(void) pclose(pipe);

	if (rc != 1) {
		rdc_err(NULL, gettext("Unable to get logical host"));
	}

	/* not really failing, but suspend does not have the config lock */
	if (flag == RDC_CMD_SUSPEND)
		goto fail;

	bzero(&key, sizeof (key));
	(void) snprintf(key, sizeof (key), "sndr.set%d.options", setnum);
	if (cfg_put_options(cfg, CFG_SEC_CONF, key, "lghn", lhostname) < 0)
		rdc_warn(NULL, gettext("sndrboot: Unable to store logical "
		    "host name in configuration database"));

	if (cfg_commit(cfg) < 0)
		rdc_err(NULL,
		    gettext("sndrboot: Failed to commit logical host name"));

fail:
	return (lhostname);

}

/*
 * read_libcfg()
 *
 * DESCRIPTION: Read the relevant config info via libcfg
 *
 * Outputs:
 *	int i			Number of pairs of devices
 *
 * Side Effects: The 0 to i-1 entries in the pair_list are filled.
 *
 */
static int
read_libcfg(int flag)
{
	char fromhost[MAX_RDC_HOST_SIZE];
	char fromfile[NSC_MAXPATH];
	char frombitmap[NSC_MAXPATH];
	char tohost[MAX_RDC_HOST_SIZE];
	char tofile[NSC_MAXPATH];
	char tobitmap[NSC_MAXPATH];
	char directfile[NSC_MAXPATH];
	char diskqueue[NSC_MAXPATH];
	char group[NSC_MAXPATH];
	char lhost[MAX_RDC_HOST_SIZE];
	char sync[16];
	char setid[64];
	int doasync;
	CFGFILE *cfg;
	int i, j = 0;
	int rc;
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	char dummy[NSC_MAXPATH];
	int setnumber;
	int numsets;
	int highest = 0;
	char lghn[5];
	int *no_id;


	if ((cfg = cfg_open("")) == NULL)
		rdc_err(NULL, gettext("Error opening config"));

	/*
	 * If RDC_CMD_FIXSETIDS, we were called during post-patch install
	 * Acquire a write-lock on the cfg_lock(), so the code can attempt
	 * to fix setIDs
	 */
	if (flag == RDC_CMD_FIXSETIDS) {
		if (!cfg_lock(cfg, CFG_WRLOCK))
			rdc_err(NULL, gettext("Error write locking config"));
		cfg_resource(cfg, NULL);
	} else {
		if (!cfg_lock(cfg, CFG_RDLOCK))
			rdc_err(NULL, gettext("Error locking config"));
		cfg_resource(cfg, ctag);
	}

	if ((numsets = cfg_get_num_entries(cfg, "sndr")) < 0)
		rdc_err(NULL, gettext("Unable to get set info from config"));

	no_id = (int *)calloc(numsets + 1, sizeof (int));
	if (!no_id)
		rdc_err(NULL, gettext("No memory"));


	(void) snprintf(lghn, sizeof (lghn), "lghn");

	for (i = 0; i < rdc_maxsets; i++) {
		setnumber = i + 1;

		bzero(buf, CFG_MAX_BUF);
		(void) snprintf(key, sizeof (key), "sndr.set%d", setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;

		rc = sscanf(buf, "%s %s %s %s %s %s %s %s %s %s %s %s",
		    fromhost, fromfile, frombitmap, tohost, tofile, tobitmap,
			directfile, sync, group, dummy, dummy, diskqueue);
		if (rc != 12)
			rdc_err(NULL, gettext("cfg input error (%d)"), rc);

		if (strcmp(directfile, "ip") == 0)
			strcpy(directfile, "");

		if (strcmp(group, "-") == 0)
			strcpy(group, "");

		if (strcmp(diskqueue, "-") == 0)
			strcpy(diskqueue, "");

		(void) snprintf(key, sizeof (key),
			"sndr.set%d.options", setnumber);

		if (cfg_get_single_option(cfg, CFG_SEC_CONF, key,
			lghn, lhost, MAX_RDC_HOST_SIZE) < 0)
			strcpy(lhost,
			    get_lghn(cfg, ctag, setnumber, flag));

		if (strcmp(sync, "sync") == 0)
			doasync = 0;
		else if (strcmp(sync, "async") == 0)
			doasync = 1;
		else {
			cfg_close(cfg);
			rdc_err(NULL,
			    gettext("Set %s:%s neither sync nor async"),
			    tohost, tofile);
		}

		strncpy(pair_list[i].fhost, fromhost,
			MAX_RDC_HOST_SIZE);
		strncpy(pair_list[i].ffile, fromfile, NSC_MAXPATH);
		strncpy(pair_list[i].fbitmap, frombitmap, NSC_MAXPATH);
		strncpy(pair_list[i].thost, tohost, MAX_RDC_HOST_SIZE);
		strncpy(pair_list[i].tfile, tofile, NSC_MAXPATH);
		strncpy(pair_list[i].tbitmap, tobitmap, NSC_MAXPATH);
		strncpy(pair_list[i].directfile, directfile,
			NSC_MAXPATH);
		strncpy(pair_list[i].diskqueue, diskqueue,
			NSC_MAXPATH);
		strncpy(pair_list[i].group, group, NSC_MAXPATH);
		strncpy(pair_list[i].lhost, lhost, MAX_RDC_HOST_SIZE);
		pair_list[i].doasync = doasync;

		if (cfg_get_single_option(cfg, CFG_SEC_CONF, key, "setid",
		    setid, sizeof (setid)) < 0) {
			no_id[j++] = setnumber;
		}
		pair_list[i].setid = atoi(setid);

		if (pair_list[i].setid > highest)
			highest = pair_list[i].setid;

		if (gethost_netaddrs(fromhost, tohost,
		    (char *)pair_list[i].fnetaddr,
		    (char *)pair_list[i].tnetaddr) < 0) {
			cfg_close(cfg);
			spcs_log("sndr", NULL,
			    gettext("%s unable to determine IP addresses "
			    "for hosts %s %s"), program, fromhost, tohost);
			rdc_err(NULL, gettext("unable to determine IP "
			    "addresses for hosts %s, %s"), fromhost, tohost);
		}
	}
	/*
	 * fix any lost set ids if possible, also deal with upgrade
	 */
	if (j > 0 && flag == RDC_CMD_FIXSETIDS) {
		(void) update_setids(cfg, no_id, highest);
		i = j;	/* Set number of fixups */
	}
	free(no_id);
	cfg_close(cfg);
	return (i);
}


int
parseopts(argc, argv, flag)
int argc;
char **argv;
int *flag;
{
	int  errflag = 0;
	char c;
	char inval = 0;
#ifdef DEBUG
	while ((c = getopt(argc, argv, "C:Urs")) != -1) {
#else
	while ((c = getopt(argc, argv, "C:rs")) != -1) {
#endif
		switch (c) {
		case 'C':
			clustered = TRUE;
			ctag = optarg;
			break;
#ifdef DEBUG
		case 'U':
			proto_test = 1;
			break;
#endif
		case 'r':
			if (*flag)
				inval = 1;
			*flag = RDC_CMD_RESUME;
			break;
		case 's':
			if (*flag)
				inval = 1;
			*flag = RDC_CMD_SUSPEND;
			break;
		case '?':
			errflag++;
		}
	}

	/*
	 * Special fix to address no SetIds in AVS 3.1 to 3.2 install + patch
	 * Adjust set IDs, if someone invokes the following invalid command
	 *
	 *	/use/sbin/sndrboot -C post-patch-setids -r -s
	 *
	 * Command will be called in post-install of the patch containing fix
	 *
	 */
	if (clustered && (strcmp(ctag, "post-patch-setids") == 0) &&
	    *flag && inval) {
		*flag = RDC_CMD_FIXSETIDS;
		return (0);
	}

	if (inval) {
		rdc_warn(NULL, gettext("Invalid argument combination"));
		errflag = 1;
	}

	if (!*flag || errflag) {
		usage();
		return (-1);
	}

	return (0);
}

static void
usage()
{
	(void) fprintf(stderr, gettext("usage:\n"));
	(void) fprintf(stderr,
		gettext("\t%s -r [-C tag]\t\t"
			"resume\n"), program);

	(void) fprintf(stderr,
		gettext("\t%s -s [-C tag]\t\t"
			"suspend\n"), program);
}
