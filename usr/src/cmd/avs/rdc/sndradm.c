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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <values.h>
#include <limits.h>
#include <fcntl.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include <locale.h>
#include <langinfo.h>
#include <libintl.h>
#include <stdarg.h>
#include <netdb.h>
#include <ctype.h>

#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/rdc_ioctl.h>
#include <sys/nsctl/rdc_prot.h>

#include <sys/nsctl/cfg.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <rpc/rpc_com.h>
#include <rpc/rpc.h>

#include <sys/nsctl/librdc.h>
#include <sys/nsctl/nsc_hash.h>

#include "rdcadm.h"

/*
 * support for the special cluster tag "local" to be used with -C in a
 * cluster for local volumes.
 */

#define	RDC_LOCAL_TAG    "local"

typedef struct volcount_s {
	int count;
} volcount_t;
hash_node_t **volhash = NULL;

/*
 * rdc_islocal is only pertinent while creating the pairs array.
 * after all the pairs are set, its value is useless, retaining
 * the last value it was set to.
 * its only reason in life is to suppress an error message in 2
 * places where the inappropriate becomes appropriate (a supplied
 * ctag which does not match an implied one cfg_dgame()). This
 * happens when  C "local" is supplied. It is then used to make an
 * error message clearer. A
 * gettext("set %s does not match", rdc_islocal < 1?dga:dgb) situation
 */
static int rdc_islocal = 0;

char *program;

#define	min(a, b)	((a) > (b) ? (b) : (a))

static	char place_holder[] = "-";	/* cfg place holder value */

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
	char group[NSC_MAXPATH];	/* Group name */
	char ctag[MAX_RDC_HOST_SIZE];	/* Cluster resource name tag */
	char diskqueue[NSC_MAXPATH];	/* Disk Queue volume */
	int  doasync;			/* Device is in sync/async mode */
} _sd_dual_pair_t;

#define	EXTRA_ARGS	6	/* g grp C ctag q diskqueue */

static int rdc_operation(
    CFGFILE *, char *, char *, char *, char *, char *, char *,
    int, int, char *, char *, char *, char *, int *, int);
int read_config(int, char *, char *, char *);
static int read_libcfg(int, char *, char *);
int prompt_user(int, int);
static void rdc_check_dgislocal(char *);
void process_clocal(char *);
static void usage(void);
void q_usage(int);
static void load_rdc_vols(CFGFILE *);
static void unload_rdc_vols();
static int perform_autosv();
static void different_devs(char *, char *);
static void validate_name(CFGFILE *, char *);
static void set_autosync(int, char *, char *, char *);
static int autosync_is_on(char *tohost, char *tofile);
static void enable_autosync(char *fhost, char *ffile, char *thost, char *tfile);
static void checkgfields(CFGFILE *, int, char *, char *, char *, char *,
    char *, char *, char *, char *, char *);
static void checkgfield(CFGFILE *, int, char *, char *, char *);
static int rdc_bitmapset(char *, char *, char *, int, nsc_off_t);
static int parse_cfg_buf(char *, _sd_dual_pair_t *, char *);
static void verify_groupname(char *grp);
extern char *basename(char *);

int rdc_maxsets;
static _sd_dual_pair_t *pair_list;

struct netbuf svaddr;
struct netbuf *svp;
struct netconfig nconf;
struct netconfig *conf;
struct knetconfig knconf;

static char *reconfig_pbitmap = NULL;
static char *reconfig_sbitmap = NULL;
#ifdef _RDC_CAMPUS
static char *reconfig_direct = NULL;
#endif
static char *reconfig_group = NULL;
static char reconfig_ctag[MAX_RDC_HOST_SIZE];
static int reconfig_doasync = -1;

static int clustered = 0;
static int proto_test = 0;
int allow_role = 0;


static char *
rdc_print_state(rdc_set_t *urdc)
{
	if (!urdc)
		return ("");

	if (urdc->sync_flags & RDC_VOL_FAILED)
		return (gettext("volume failed"));
	else if (urdc->sync_flags & RDC_FCAL_FAILED)
		return (gettext("fcal failed"));
	else if (urdc->bmap_flags & RDC_BMP_FAILED)
		return (gettext("bitmap failed"));
	else if (urdc->flags & RDC_DISKQ_FAILED)
		return (gettext("disk queue failed"));
	else if (urdc->flags & RDC_LOGGING) {
		if (urdc->sync_flags & RDC_SYNC_NEEDED)
			return (gettext("need sync"));
		else if (urdc->sync_flags & RDC_RSYNC_NEEDED)
			return (gettext("need reverse sync"));
		else if (urdc->flags & RDC_QUEUING)
			return (gettext("queuing"));
		else
			return (gettext("logging"));
	} else if ((urdc->flags & RDC_SLAVE) && (urdc->flags & RDC_SYNCING)) {
		if (urdc->flags & RDC_PRIMARY)
			return (gettext("reverse syncing"));
		else
			return (gettext("syncing"));
	} else if (urdc->flags & RDC_SYNCING) {
		if (urdc->flags & RDC_PRIMARY)
			return (gettext("syncing"));
		else
			return (gettext("reverse syncing"));
	}

	return (gettext("replicating"));
}


static int
rdc_print(int file_format, int verbose, char *group_arg, char *ctag_arg,
    char *user_shost, char *user_sdev, CFGFILE *cfgp)
{
	rdc_status_t *rdc_status;
	spcs_s_info_t ustatus;
	rdc_set_t *urdc;
	size_t size;
	int i, rc, max;
	char *tohost, *tofile;
	_sd_dual_pair_t pair;
	char *tmptohost = pair.thost;
	char *tmptofile = pair.tfile;
	char *fromhost = pair.fhost;
	char *fromfile = pair.ffile;
	char *frombitmap = pair.fbitmap;
	char *tobitmap = pair.tbitmap;
	char *directfile = pair.directfile;
	char *group = pair.group;
	char *diskqueue = pair.diskqueue;
	char *ctag = pair.ctag;
	CFGFILE *cfg;
	int j;
	int setnumber;
	char key[CFG_MAX_KEY];
	char buf[CFG_MAX_BUF];
	char sync[16];
	int match, found;

	size = sizeof (rdc_status_t) + (sizeof (rdc_set_t) * (rdc_maxsets - 1));
	match = (user_shost != NULL || user_sdev != NULL);
	found = 0;

	if (user_shost == NULL && user_sdev != NULL)
		user_shost = "";
	else if (user_shost != NULL && user_sdev == NULL)
		user_sdev = "";

	rdc_status = malloc(size);
	if (!rdc_status) {
		rdc_err(NULL,
			gettext("unable to allocate %ld bytes"), size);
	}

	rdc_status->nset = rdc_maxsets;
	ustatus = spcs_s_ucreate();

	rc = RDC_IOCTL(RDC_STATUS, rdc_status, 0, 0, 0, 0, ustatus);
	if (rc == SPCS_S_ERROR) {
		rdc_err(&ustatus, gettext("statistics error"));
	}

	spcs_s_ufree(&ustatus);

	max = min(rdc_status->nset, rdc_maxsets);

	if (cfgp != NULL) {
		cfg = cfgp;
		cfg_rewind(cfg, CFG_SEC_CONF);
	} else {
		if ((cfg = cfg_open(NULL)) == NULL)
			rdc_err(NULL,
			    gettext("unable to access configuration"));

		if (!cfg_lock(cfg, CFG_RDLOCK))
			rdc_err(NULL, gettext("unable to lock configuration"));
	}

	for (i = 0; i < max; i++) {
		urdc = &rdc_status->rdc_set[i];

		if (!(urdc->flags & RDC_ENABLED))
			continue;

		if (match &&
		    (strcmp(user_shost, urdc->secondary.intf) != 0 ||
		    strcmp(user_sdev, urdc->secondary.file) != 0))
			continue;

		tohost = urdc->secondary.intf;
		tofile = urdc->secondary.file;
		found = 1;

		/* get sndr entries until shost, sfile match */
		for (j = 0; j < rdc_maxsets; j++) {
			setnumber = j + 1;
			(void) snprintf(key, sizeof (key),
			    "sndr.set%d", setnumber);
			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
				break;
			}

			if (parse_cfg_buf(buf, &pair, NULL))
				rdc_err(NULL, gettext("cfg input error"));

			if (strcmp(tmptofile, tofile) != 0)
				continue;
			if (strcmp(tmptohost, tohost) != 0)
				continue;

			if (pair.doasync == 0)
				(void) strcpy(sync, "sync");
			else
				(void) strcpy(sync, "async");

			/* Got the matching entry */

			break;
		}

		if (j == rdc_maxsets)
			continue;	/* not found in config */

		if (strcmp(group_arg, "") != 0 &&
		    strncmp(group_arg, group, NSC_MAXPATH) != 0)
			continue;

		if (strcmp(ctag_arg, "") != 0 &&
		    strncmp(ctag_arg, ctag, MAX_RDC_HOST_SIZE) != 0)
			continue;

		if (file_format) {
			(void) printf("%s %s %s %s %s %s %s %s",
			    fromhost, fromfile, frombitmap,
			    tohost, tofile, tobitmap,
			    directfile, sync);
			if (strlen(group) != 0)
				(void) printf(" g %s", group);
			if ((strlen(ctag) != 0) && (ctag[0] != '-'))
				(void) printf(" C %s", ctag);
			if (strlen(diskqueue) != 0)
				(void) printf(" q %s", diskqueue);
			(void) printf("\n");
			continue;
		}

		if (strcmp(group_arg, "") != 0 &&
		    strncmp(group_arg, urdc->group_name, NSC_MAXPATH) != 0)
			continue;

		if (!(urdc->flags & RDC_PRIMARY)) {
			(void) printf(gettext("%s\t<-\t%s:%s\n"),
			    urdc->secondary.file, urdc->primary.intf,
			    urdc->primary.file);
		} else {
			(void) printf(gettext("%s\t->\t%s:%s\n"),
			    urdc->primary.file, urdc->secondary.intf,
			    urdc->secondary.file);
		}
		if (!verbose)
			continue;

		if (urdc->autosync)
			(void) printf(gettext("autosync: on"));
		else
			(void) printf(gettext("autosync: off"));

		(void) printf(gettext(", max q writes: %lld"), urdc->maxqitems);
		(void) printf(gettext(", max q fbas: %lld"), urdc->maxqfbas);
		(void) printf(gettext(", async threads: %d"),
			urdc->asyncthr);
		(void) printf(gettext(", mode: %s"),
			pair.doasync ? "async" : "sync");

		if (strlen(urdc->group_name) != 0)
			(void) printf(gettext(", group: %s"), urdc->group_name);
		if ((strlen(ctag) != 0) && (ctag[0] != '-'))
			(void) printf(gettext(", ctag: %s"), ctag);
		if (strlen(urdc->disk_queue) != 0) {
			(void) printf(gettext(", %s diskqueue: %s"),
			(urdc->flags & RDC_QNOBLOCK) ? gettext("non blocking") :
			gettext("blocking"), urdc->disk_queue);
		}

		(void) printf(gettext(", state: %s"), rdc_print_state(urdc));
		(void) printf(gettext("\n"));

	}

	if (!cfgp)
		cfg_close(cfg);

	free(rdc_status);

	if (match && !found) {
		rdc_warn(NULL, gettext("unable to find set %s:%s"),
		    user_shost, user_sdev);
	}

	return (0);
}


int
parse_extras(int argc, char *args[], int i)
{
	int gflag = 0;
	int Cflag = 0;
	int qflag = 0;
	int j;

	(void) strcpy(pair_list[i].ctag, "");
	(void) strcpy(pair_list[i].group, "");
	(void) strcpy(pair_list[i].diskqueue, "");

	if (argc == 0)
		return (0);

	if (argc != 2 && argc != 4 && argc != 6)
		return (-1);

	for (j = 0; j < argc; j += 2) {
		if (strcmp(args[j], "g") == 0) {
			if (gflag)
				return (-1);
			(void) strncpy(pair_list[i].group, args[j + 1],
			    NSC_MAXPATH);
			gflag = 1;
		}
		if (strcmp(args[j], "C") == 0) {
			if (!clustered)
				return (-1);
			if (Cflag)
				return (-1);
			(void) strncpy(pair_list[i].ctag, args[j + 1],
			    MAX_RDC_HOST_SIZE);
			process_clocal(pair_list[i].ctag);
			Cflag = 1;
		}
		if (strcmp(args[j], "q") == 0) {
			if (qflag)
				return (-1);
			(void) strncpy(pair_list[i].diskqueue, args[j + 1],
			    NSC_MAXPATH);
			qflag = 1;
		}
	}

	return (0);
}

static int
parse_cfg_buf(char *buf, _sd_dual_pair_t *pair, char *lghn)
{
	int rc = 0;
	char sync[16];
	char options[64], *p, *q;
	int len;

	rc = sscanf(buf, "%s %s %s %s %s %s %s %s %s %s %s %s", pair->fhost,
		pair->ffile, pair->fbitmap, pair->thost, pair->tfile,
		pair->tbitmap, pair->directfile, sync, pair->group,
		pair->ctag, options, pair->diskqueue);

	if (rc != 12)
		rdc_err(NULL, gettext("cfg input error"));

	if (strcmp(pair->diskqueue, place_holder) == 0)
		(void) strcpy(pair->diskqueue, "");

	if (strcmp(pair->group, place_holder) == 0)
		(void) strcpy(pair->group, "");

	if (strcmp(sync, "sync") == 0)
		pair->doasync = 0;
	else if (strcmp(sync, "async") == 0)
		pair->doasync = 1;
	else {
		rdc_err(NULL,
		    gettext("set %s:%s neither sync nor async"),
		    pair->thost, pair->tfile);
	}

	if (lghn && (p = strstr(options, "lghn="))) {
		p += 5;
		q = strchr(p, ';');
		if (q) {
			/* LINTED p & q limited to options[64] */
			len = q - p;
		} else {
			len = strlen(p);
		}
		(void) strncpy(lghn, p, len);
		lghn[len] = '\0';
	} else if (lghn) {
		*lghn = '\0';
	}

	return (0);
}

static int
ctag_check(char *fromhost, char *fromfile, char *frombitmap, char *tohost,
    char *tofile, char *tobitmap, char *ctag, char *diskq)
{
	char *file_dgname;
	char *bmp_dgname;
	char *que_dgname;
	char *localfile;
	char file_buf[MAX_RDC_HOST_SIZE];
	char bmp_buf[MAX_RDC_HOST_SIZE];
	char que_buf[NSC_MAXPATH];
	int is_primary;
	struct hostent *hp;
	char fromname[MAXHOSTNAMELEN], toname[MAXHOSTNAMELEN];

	if (!clustered)
		return (0);

	hp = gethost_byname(fromhost);
	(void) strncpy(fromname, hp->h_name, MAXHOSTNAMELEN);
	hp = gethost_byname(tohost);
	(void) strncpy(toname, hp->h_name, MAXHOSTNAMELEN);
	if (!self_check(fromname) && !self_check(toname)) {
		/*
		 * If we could get a list of logical hosts on this cluster
		 * then we could print something intelligent about where
		 * the volume is mastered. For now, just print some babble
		 * about the fact that we have no idea.
		 */
			rdc_err(NULL,
				gettext("either %s:%s or %s:%s is not local"),
					fromhost, fromfile, tohost, tofile);
	}

	is_primary = self_check(fromname);

	/*
	 * If implicit disk group name and no ctag specified by user,
	 * we set the ctag to it.
	 * If implicit disk group name, it must match any supplied ctag.
	 */
	localfile = is_primary ? fromfile : tofile;
	file_dgname = cfg_dgname(localfile, file_buf, sizeof (file_buf));
	if (file_dgname && strlen(file_dgname))
		rdc_check_dgislocal(file_dgname);

	/*
	 * Autogenerate a ctag, if not "-C local" or no "-C " specified
	 */
	if (!rdc_islocal && !strlen(ctag) && file_dgname && strlen(file_dgname))
		(void) strncpy(ctag, file_dgname, MAX_RDC_HOST_SIZE);

	/*
	 * making an exception here for users giving the "local"tag
	 * this overrides this error message. (rdc_islocal ! = 1)
	 */
	if (!rdc_islocal && strlen(ctag) &&
	    file_dgname && strlen(file_dgname) &&
	    strncmp(ctag, file_dgname, MAX_RDC_HOST_SIZE)) {
		rdc_warn(NULL, gettext("ctag \"%s\" does not "
		    "match disk group name \"%s\" of volume %s"), ctag,
		    file_dgname, localfile);
		return (-1);
	}

	/*
	 * Do we have a non-volume managed disk without -C local specified?
	 */
	if (!rdc_islocal && (!file_dgname || !strlen(file_dgname))) {
		rdc_err(NULL, gettext("volume \"%s\" is not part"
		    " of a disk group,\nplease specify resource ctag\n"),
		    localfile);
	}

	/*
	 * Do we have a volume managed disk with -C local?
	 */
	if (rdc_islocal && file_dgname && (strlen(file_dgname) > 0)) {
		rdc_err(NULL, gettext(
			"volume \"%s\" is part of a disk group\n"), localfile);
	}

	/*
	 * Local bitmap must also have same ctag.
	 */
	localfile = is_primary ? frombitmap : tobitmap;
	bmp_dgname = cfg_dgname(localfile, bmp_buf, sizeof (bmp_buf));
	if (bmp_dgname && strlen(bmp_dgname))
		rdc_check_dgislocal(bmp_dgname);

	/*
	 * Assure that if the primary has a device group, so must the bitmap
	 */
	if ((file_dgname && strlen(file_dgname)) &&
	    (!bmp_dgname || !strlen(bmp_dgname))) {
		rdc_warn(NULL, gettext("bitmap %s is not in disk group \"%s\""),
			localfile, rdc_islocal < 1?file_dgname:ctag);
		return (-1);
	}

	/*
	 * Assure that if the if there is a ctag, it must match the bitmap
	 */
	if (!rdc_islocal && strlen(ctag) &&
	    bmp_dgname && strlen(bmp_dgname) &&
	    strncmp(ctag, bmp_dgname, MAX_RDC_HOST_SIZE)) {
		rdc_warn(NULL, gettext("ctag \"%s\" does not "
		    "match disk group name \"%s\" of bitmap %s"), ctag,
		    bmp_dgname, localfile);
		return (-1);
	}

	/*
	 * If this is the SNDR primary and there is a local disk queue
	 */
	if (is_primary && diskq[0]) {

		/*
		 * Local disk queue must also have same ctag.
		 */
		que_dgname = cfg_dgname(diskq, que_buf, sizeof (que_buf));
		if (que_dgname && strlen(que_dgname))
			rdc_check_dgislocal(que_dgname);

		/*
		 * Assure that if the primary has a device group, so must
		 * the disk queue
		 */
		if ((file_dgname && strlen(file_dgname)) &&
		    (!que_dgname || !strlen(que_dgname))) {
			rdc_warn(NULL, gettext("disk queue %s is not in disk "
			    "group \"%s\""), diskq,
			    rdc_islocal < 1?file_dgname:ctag);
			return (-1);
		}

		/*
		 * Assure that if the if there is a ctag, it must match
		 * the disk queue
		 */
		if (!rdc_islocal && strlen(ctag) &&
		    que_dgname && strlen(que_dgname) &&
		    strncmp(ctag, que_dgname, MAX_RDC_HOST_SIZE)) {
			rdc_warn(NULL, gettext("ctag \"%s\" does not "
			    "match disk group name \"%s\" of disk queue %s"),
			    ctag, que_dgname, diskq);
			return (-1);
		}
	}

	return (0);
}

#define	DISKQ_OKAY	0
#define	DISKQ_FAIL	1
#define	DISKQ_REWRITEG	2
/*
 * check that newq is compatable with the groups current disk queue.
 * Newq is incompatable if it is set and the groups queue is set and the queues
 * are different.
 *
 * if newq is not set but should be, it will be set to the correct value.
 * returns:
 *	DISK_REWRITEG entire group needs to take new value of disk_queue
 *	DISKQ_OKAY newq contains a value that matches the group.
 *	DISKQ_FAIL disk queues are incompatible.
 */
static int
check_diskqueue(CFGFILE *cfg, char *newq, char *newgroup)
{
	int i, setnumber;
	_sd_dual_pair_t pair;
	char *group = pair.group;
	char *diskqueue = pair.diskqueue;
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	int open_cfg = cfg == NULL ? 1 : 0;


	if (newgroup == NULL || *newgroup == '\0') {
		if (*newq == '\0')
			return (DISKQ_OKAY);	/* okay,  */
		newgroup = "--nomatch--";
	}

	if (open_cfg) {
		if ((cfg = cfg_open(NULL)) == NULL)
			rdc_err(NULL,
			    gettext("unable to access configuration"));
		if (!cfg_lock(cfg, CFG_RDLOCK))
			rdc_err(NULL, gettext("unable to lock configuration"));
	}

	/*CSTYLED*/
	for (i = 0; ; i++) {
		setnumber = i + 1;
		(void) snprintf(key, sizeof (key), "sndr.set%d", setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		/*
		 * I think this is quicker than
		 * having to double dip into the config
		 */
		if (parse_cfg_buf(buf, &pair, NULL))
			rdc_err(NULL, gettext("cfg input error"));

		if (strncmp(group, newgroup, NSC_MAXPATH) != 0) {
			if (((strncmp(diskqueue, newq, NSC_MAXPATH) == 0)) &&
			    (diskqueue[0] != '\0')) {
				if (open_cfg)
					cfg_close(cfg);
				return (DISKQ_FAIL);
			}
			continue;
		}
		if (*newq == '\0') {
			if (diskqueue[0] != '\0')
				(void) strncpy(newq, diskqueue, NSC_MAXPATH);
			if (open_cfg)
				cfg_close(cfg);
			return (DISKQ_OKAY);	/* okay,  */
		}

		if (open_cfg)
			cfg_close(cfg);
		if (diskqueue[0] == '\0')	/* no queue here */
			return (DISKQ_REWRITEG);
		return (strncmp(diskqueue, newq, NSC_MAXPATH)
		    == 0 ? DISKQ_OKAY : DISKQ_FAIL);
	}
	if (open_cfg)
		cfg_close(cfg);
	return (DISKQ_OKAY);
}


int
pair_diskqueue_check(int newpair)
{
	int i, j;
	int rc;

	for (i = 0; i < newpair; i++) {
		if (strcmp(pair_list[i].group, pair_list[newpair].group) != 0)
			continue;
		if (strcmp(pair_list[i].diskqueue, pair_list[newpair].diskqueue)
		    == 0)
			return (DISKQ_OKAY); /* matches existing group */
		if ((pair_list[newpair].group[0] != '\0') &&
		    (pair_list[newpair].diskqueue[0] != '\0') &&
		    (pair_list[i].diskqueue[0] != '\0')) {
			rdc_warn(NULL,
			    gettext("disk queue %s does not match %s "
			    "skipping set"), pair_list[newpair].diskqueue,
			    pair_list[i].diskqueue);
			return (DISKQ_FAIL);
		}

		if ((strcmp(pair_list[newpair].diskqueue, "") == 0) &&
		    pair_list[newpair].group[0] != '\0') {
			(void) strncpy(pair_list[newpair].diskqueue,
			    pair_list[i].diskqueue, NSC_MAXPATH);
			return (DISKQ_OKAY); /* changed to existing group que */
		}
		if (strcmp(pair_list[i].diskqueue, "") == 0) {
			for (j = 0; j < newpair; j++) {
				if ((pair_list[j].group[0] != '\0') &&
				    (strncmp(pair_list[j].group,
				    pair_list[newpair].group,
				    NSC_MAXPATH) == 0)) {
					(void) strncpy(pair_list[j].diskqueue,
					    pair_list[newpair].diskqueue,
					    NSC_MAXPATH);
				}
			}
			return (DISKQ_OKAY);
		}
		break; /* no problem with pair_list sets */

	}

	/* now check with already configured sets */
	rc = check_diskqueue(NULL, pair_list[newpair].diskqueue,
	    pair_list[newpair].group);
	if (rc == DISKQ_REWRITEG) {
		for (i = 0; i < newpair; i++) {
			if (strcmp(pair_list[i].group,
			    pair_list[newpair].group) != 0)
				continue;

			(void) strncpy(pair_list[i].diskqueue,
			    pair_list[newpair].diskqueue, NSC_MAXPATH);
		}
	}
	return (rc);
}

int
ii_set_exists(CFGFILE *cfg, char *ma, char *sh, char *bm)
{
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	char master[NSC_MAXPATH];
	char shadow[NSC_MAXPATH];
	char bitmap[NSC_MAXPATH];
	int i;

	for (i = 1; ; i++) {
		(void) snprintf(key, sizeof (key), "ii.set%d", i);
		bzero(&master, sizeof (master));
		bzero(&shadow, sizeof (shadow));
		bzero(&bitmap, sizeof (bitmap));
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		(void) sscanf(buf, "%s %s %s", master, shadow, bitmap);
		if (strcmp(master, ma) != 0)
			continue;
		if (strcmp(shadow, sh) != 0)
			continue;
		if (strcmp(bitmap, bm) != 0)
			continue;
		return (1);
	}
	return (0);
}

void
rdc_ii_config(int argc, char **argv)
{
	char *master;
	char *shadow;
	char *bitmap;
	char c;
	CFGFILE *cfg;
	int i;
	int setnumber;
	char key[CFG_MAX_KEY];
	char buf[CFG_MAX_BUF];
	int found;
	int sev;

	/* Parse the rest of the arguments to see what to do */

	if (argc - optind != 4) {
		usage();
		exit(1);
	}

	c = *argv[optind];
	switch (c) {
	case 'd':
		/* Delete an ndr_ii entry */

		master = argv[++optind];
		shadow = argv[++optind];
		bitmap = argv[++optind];

		if ((cfg = cfg_open(NULL)) == NULL)
			rdc_err(NULL,
			    gettext("unable to access configuration"));
		if (!cfg_lock(cfg, CFG_WRLOCK))
			rdc_err(NULL, gettext("unable to lock configuration"));

		found = 0;
		/* get ndr_ii entries until a match is found */
		/*CSTYLED*/
		for (i = 0; ; i++) {
			setnumber = i + 1;

			(void) snprintf(key, sizeof (key),
			    "ndr_ii.set%d.secondary",
			    setnumber);
			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
				break;
			if (strcmp(buf, master) != 0)
				continue;

			/* Got a matching entry */

			(void) snprintf(key, sizeof (key),
			    "ndr_ii.set%d.shadow",
			    setnumber);
			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
				break;
			if (strcmp(buf, shadow) != 0)
				continue;

			(void) snprintf(key, sizeof (key),
			    "ndr_ii.set%d.bitmap",
			    setnumber);
			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
				break;
			if (strcmp(buf, bitmap) != 0)
				continue;

			(void) snprintf(key, sizeof (key),
			    "ndr_ii.set%d", setnumber);
			if (cfg_put_cstring(cfg, key, NULL, 0) < 0) {
				rdc_warn(NULL,
				    gettext("unable to remove \"%s\" "
				    "from configuration storage: %s"),
				    key, cfg_error(&sev));
				} else {
					if (cfg_commit(cfg) < 0)
					    rdc_err(NULL,
						gettext("ndr_ii set %s %s %s "
						    "not deconfigured."),
						    master, shadow, bitmap);
					else
					    spcs_log("sndr", NULL,
						gettext("ndr_ii set %s %s %s "
						    "has been deconfigured."),
						    master, shadow, bitmap);
				}
			found = 1;
			break;
		}

		if (!found) {
			rdc_err(NULL,
			    gettext("did not find matching ndr_ii "
			    "entry for %s %s %s"), master, shadow, bitmap);
		}

		cfg_close(cfg);

		break;

	case 'a':
		/* Add an ndr_ii entry */

		master = argv[++optind];
		shadow = argv[++optind];
		bitmap = argv[++optind];

		if ((cfg = cfg_open(NULL)) == NULL)
			rdc_err(NULL,
			    gettext("unable to access configuration"));
		if (!cfg_lock(cfg, CFG_WRLOCK))
			rdc_err(NULL, gettext("unable to lock configuration"));

		found = 0;
		/* get ndr_ii entries in case a match is found */
		/*CSTYLED*/
		for (i = 0; ; i++) {
			setnumber = i + 1;

			(void) snprintf(key, sizeof (key),
			    "ndr_ii.set%d.secondary",
			    setnumber);
			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
				break;
			if (strcmp(buf, master) == 0) {
				rdc_err(NULL,
				    gettext("found matching ndr_ii "
				    "entry for %s"), master);
			}
		}
		/*
		 * check to see if this is using a sndr bitmap.
		 * kind of a courtesy check, as the ii copy would fail anyway
		 * excepting the case where they had actually configured
		 * ii/sndr that way, in which case they are broken
		 * before we get here
		 */
		/*CSTYLED*/
		for (i = 0; ; i++) {
			setnumber = i + 1;

			/*
			 * Checking local bitmaps
			 */
			(void) snprintf(key, sizeof (key), "sndr.set%d.phost",
			    setnumber);

			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
				break;
			if (self_check(buf)) {
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.pbitmap",
				    setnumber);
			} else {
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.sbitmap",
				    setnumber);
			}

			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
				break;

			if ((strcmp(buf, bitmap) == 0) ||
			    (strcmp(buf, master) == 0) ||
			    (strcmp(buf, shadow) == 0)) {
				rdc_err(NULL,
				    gettext("%s is already configured "
				    "as a Remote Mirror bitmap"), buf);
			}
		}
		if (!ii_set_exists(cfg, master, shadow, bitmap)) {
			rdc_warn(NULL, gettext("Point-in-Time Copy set "
			    "%s %s %s is not already configured. Remote "
			    "Mirror will attempt to configure this set when "
			    "a sync is issued to it.  The results of that "
			    "operation will be in /var/adm/ds.log"),
			    master, shadow, bitmap);
			spcs_log("sndr", NULL, gettext("Point-in-Time Copy set "
			    "%s %s %s is not already configured. Remote "
			    "Mirror will attempt to configure this set when "
			    "a sync is issued to it.  The results of that "
			    "operation will be in /var/adm/ds.log"),
			    master, shadow, bitmap);
		} else {
			spcs_log("sndr", NULL, gettext("ndr_ii set "
			    "%s %s %s has been configured."),
			    master, shadow, bitmap);
		}

		/*
		 * Prior to insertion in ndr_ii entry, if in a Sun Cluster
		 * assure device groups are the same and cluster tag is set
		 */
		if (clustered && !rdc_islocal) {
			char mst_dg[NSC_MAXPATH] = {0};
			char shd_dg[NSC_MAXPATH] = {0};
			char bmp_dg[NSC_MAXPATH] = {0};

			if (!(cfg_dgname(master, mst_dg, sizeof (mst_dg)) &&
			    cfg_dgname(shadow, shd_dg, sizeof (shd_dg)) &&
			    cfg_dgname(bitmap, bmp_dg, sizeof (bmp_dg))))
				rdc_warn(NULL, gettext("ndr_ii: %s %s %s are "
				    "not in a device group"),
				    master, shadow, bitmap);
			else if (strcmp(mst_dg, bmp_dg) ||
				strcmp(mst_dg, shd_dg))
				rdc_warn(NULL, gettext("ndr_ii: %s %s %s are "
				    "not in different device groups"),
				    master, shadow, bitmap);
			else {
				cfg_resource(cfg, shd_dg);
				(void) snprintf(buf, sizeof (buf),
				    "%s %s %s update %s",
				    master, shadow, bitmap, shd_dg);
			}
		} else {
			(void) snprintf(buf, sizeof (buf), "%s %s %s update",
				master, shadow, bitmap);
		}

		if ((cfg_put_cstring(cfg, "ndr_ii", buf, strlen(buf)) < 0) ||
		    (cfg_commit(cfg) < 0))
			rdc_warn(NULL, gettext("unable to add \"%s\" to "
				"configuration storage: %s"),
				buf, cfg_error(&sev));

		cfg_close(cfg);

		break;

	default:
		usage();
		exit(1);
	}
}

void
check_rdcbitmap(int cmd, char *hostp, char *bmp)
{
	int i;
	CFGFILE *cfg;
	int entries;
	char **entry;
	char *host, *pri, *sec, *sbm, *bit, *mas, *sha, *ovr;
	char *shost, *buf, *que;

	if ((cfg = cfg_open(NULL)) == NULL)
		rdc_err(NULL,
		    gettext("unable to access configuration"));
	if (!cfg_lock(cfg, CFG_RDLOCK))
		rdc_err(NULL, gettext("unable to lock configuration"));

	/*
	 * look into II config to see if this is being used elsewhere
	 */
	entry = NULL;
	entries = cfg_get_section(cfg, &entry, "ii");
	for (i = 0; i < entries; i++) {
		buf = entry[i];

		mas = strtok(buf, " ");		/* master */
		sha = strtok(NULL, " ");	/* shadow */
		bit = strtok(NULL, " ");	/* bitmap */
		(void) strtok(NULL, " ");	/* mode */
		ovr = strtok(NULL, " ");	/* overflow */

		/*
		 * got master, shadow, overflow, and bitmap, now compare
		 */
		if ((strcmp(bmp, mas) == 0) ||
		    (strcmp(bmp, sha) == 0) ||
		    (strcmp(bmp, ovr) == 0) ||
		    (strcmp(bmp, bit) == 0)) {
			rdc_err(NULL,
			    gettext("bitmap %s is in use by"
			    " Point-in-Time Copy"), bmp);
		}
		free(buf);
	}
	if (entries)
		free(entry);


	/*
	 * and last but not least, make sure sndr is not using vol for anything
	 */
	entry = NULL;
	entries = cfg_get_section(cfg, &entry, "sndr");
	for (i = 0; i < entries; i++) {
		buf = entry[i];

		/*
		 * I think this is quicker than
		 * having to double dip into the config
		 */
		host = strtok(buf, " ");	/* phost */
		pri = strtok(NULL, " ");	/* primary */
		bit = strtok(NULL, " ");	/* pbitmap */
		shost = strtok(NULL, " ");	/* shost */
		sec = strtok(NULL, " ");	/* secondary */
		sbm = strtok(NULL, " ");	/* sbitmap */
		(void) strtok(NULL, " ");	/* type */
		(void) strtok(NULL, " ");	/* mode */
		(void) strtok(NULL, " ");	/* group */
		(void) strtok(NULL, " ");	/* cnode */
		(void) strtok(NULL, " ");	/* options */
		que = strtok(NULL, " ");	/* diskq */

		if (cmd == RDC_CMD_ENABLE) {
			if (self_check(host)) {
				if ((strcmp(bmp, pri) == 0) ||
				    (strcmp(bmp, que) == 0) ||
				    (strcmp(bmp, bit) == 0)) {
					rdc_err(NULL,
					    gettext("bitmap %s is already "
					    "in use by StorEdge Network Data "
					    "Replicator"), bmp);
				}
			} else {
				if ((strcmp(bmp, sec) == 0) ||
				    (strcmp(bmp, sbm) == 0)) {
					rdc_err(NULL,
					    gettext("bitmap %s is already "
					    "in use by StorEdge Network Data "
					    "Replicator"), bmp);
				}
			}
		} else if (cmd == RDC_CMD_RECONFIG) {

			/*
			 * read this logic 1000 times and consider
			 * multi homed, one to many, many to one (marketing)
			 * etc, etc, before changing
			 */
			if (self_check(hostp)) {
				if (self_check(host)) {
					if ((strcmp(bmp, pri) == 0) ||
					    (strcmp(bmp, que) == 0) ||
					    (strcmp(bmp, bit) == 0)) {
						rdc_err(NULL,
						gettext("bitmap %s is already "
						"in use by StorEdge Network "
						"Data Replicator"), bmp);
					}
				} else {
					if ((strcmp(hostp, shost) == 0) &&
					    (strcmp(bmp, sec) == 0) ||
					    (strcmp(bmp, sbm) == 0)) {
						rdc_err(NULL,
						gettext("bitmap %s is already "
						"in use by StorEdge Network "
						"Data Replicator"), bmp);

					}
				}
			} else { /* self_check(hostp) failed */
				if (self_check(host)) {
					if ((strcmp(shost, hostp) == 0) &&
					    (strcmp(bmp, sec) == 0) ||
					    (strcmp(bmp, sbm) == 0)) {
						rdc_err(NULL,
						gettext("bitmap %s is already "
						"in use by StorEdge Network "
						"Data Replicator"), bmp);
					}
				} else {
					if ((strcmp(host, hostp) == 0) &&
					    (strcmp(bmp, pri) == 0) ||
					    (strcmp(bmp, que) == 0) ||
					    (strcmp(bmp, bit) == 0)) {
						rdc_err(NULL,
						gettext("bitmap %s is already "
						"in use by StorEdge Network "
						"Data Replicator"), bmp);
					}
				}
			}

		}

		free(buf);
	}
	cfg_close(cfg);

	if (entries)
		free(entry);
}
int
check_intrange(char *arg) {
	int i;

	for (i = 0; i < strlen(arg); i++) {
		if (arg[i] < '0' || arg[i] > '9') {
			rdc_warn(NULL, "not a valid number, must be a "
			    "decimal between 1 and %d", MAXINT);
			return (0);
		}
	}
	errno = 0;
	i = (int)strtol(arg, NULL, 10);
	if ((errno) || (i < 1) || (i > MAXINT)) {
		rdc_warn(NULL, "not a valid number, must be a decimal "
		    "between 1 and %d", MAXINT);
		return (0);
	}
	return (1);
}

void
rewrite_group_diskqueue(CFGFILE *cfg, _sd_dual_pair_t *pair, char *diskqueue)
{
	int set;
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	_sd_dual_pair_t tmpair;

	for (set = 1; /*CSTYLED*/; set++) {
		bzero(buf, CFG_MAX_BUF);
		bzero(&tmpair, sizeof (tmpair));

		(void) snprintf(key, sizeof (key), "sndr.set%d", set);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
			break;
		}
		if (parse_cfg_buf(buf, &tmpair, NULL))
			continue;
		if (pair->group && pair->group[0]) {
			if (strcmp(pair->group, tmpair.group) != 0)
				continue; /* not the group we want */

		} else { /* no group specified */
			if (strcmp(pair->thost, tmpair.thost) != 0)
				continue;
			if (strcmp(pair->tfile, tmpair.tfile) != 0)
				continue;
		}

		(void) sprintf(key, "sndr.set%d.diskq", set);

		if (cfg_put_cstring(cfg, key, diskqueue,
		    strlen(diskqueue)) < 0) {
			perror(cfg_error(NULL));
		}
	}
}

void
diskq_subcmd(int subcmd, char *qvol, char *group_arg, char *ctag_arg,
    char *tohost_arg, char *tofile_arg)
{
	int found = 0;
	int setnumber = 0;
	char key[CFG_MAX_KEY];
	char buf[CFG_MAX_BUF];
	int i;
	int rc;
	int option = 0;
	_sd_dual_pair_t pair;
	CFGFILE *cfg;
	char *ctag = NULL;
	int resourced = 0;

	if ((cfg = cfg_open(NULL)) == NULL)
		rdc_err(NULL,
		    gettext("unable to access configuration"));

	if (!cfg_lock(cfg, CFG_WRLOCK))
		rdc_err(NULL,
		    gettext("unable to lock configuration"));

redo:
	if (cfg_load_svols(cfg) < 0 ||
	    cfg_load_dsvols(cfg) < 0 ||
	    cfg_load_shadows(cfg) < 0)
		rdc_err(NULL,
		    gettext("Unable to parse config filer"));
	load_rdc_vols(cfg);

	/*CSTYLED*/
	for (i = 0; i < rdc_maxsets;) {
		setnumber++;

		bzero(buf, CFG_MAX_BUF);
		(void) snprintf(key, sizeof (key),
		    "sndr.set%d", setnumber);
		rc = cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF);
		if (rc < 0)
			break;
		if (parse_cfg_buf(buf, &pair, NULL))
			continue;

		if (strlen(group_arg) == 0) {
			if (strcmp(tohost_arg, pair.thost) == 0 &&
			    strcmp(tofile_arg, pair.tfile) == 0) {
				(void) strcpy(group_arg, pair.group);
				found = 1;
				break;
			}

		} else {
			if (strcmp(group_arg, pair.group) == 0) {
				found = 1;
				break;
			}
		}
	}

	if (!found) {
		if (strlen(group_arg) == 0) {
			rdc_err(NULL,
			    gettext("Unable to find %s:%s in "
			    "configuration storage"),
			    tohost_arg, tofile_arg);
		} else {
			rdc_err(NULL,
			    gettext("Unable to find group %s in "
			    "configuration storage"), group_arg);
		}
	}
	if (!resourced && strlen(pair.ctag)) { /* uh-oh... */
		cfg_unload_svols(cfg);
		cfg_unload_dsvols(cfg);
		cfg_unload_shadows(cfg);
		unload_rdc_vols();
		cfg_resource(cfg, pair.ctag);
		ctag = strdup(pair.ctag);
		resourced = 1;
		setnumber = 0;
		goto redo;
	}

	if (clustered && !rdc_islocal) {
		if (strcmp(ctag_arg, "") &&
		    strncmp(ctag_arg, pair.ctag, MAX_RDC_HOST_SIZE))
			rdc_warn(NULL, gettext("ctags %s and %s "
			    "do not match, proceeding with operation based "
			    "on existing set information"), ctag_arg, ctag);
	}
	switch (subcmd) {
	case RDC_CMD_ADDQ:
		if (clustered && (ctag_check(pair.fhost, pair.ffile,
		    pair.fbitmap, pair.thost, pair.tfile, pair.tbitmap,
		    pair.ctag, qvol) < 0))
			exit(1);

		if (strlen(pair.diskqueue) > 0) {
			rdc_err(NULL, gettext("Remote Mirror set already "
			    "has a disk queue"));
		}
		if (check_diskqueue(cfg, qvol, group_arg) == DISKQ_FAIL) {
			rdc_err(NULL,
			    gettext("diskqueue %s is incompatible"), qvol);
		}
		if (rdc_operation(cfg, pair.fhost, pair.ffile, pair.fbitmap,
		    pair.thost, pair.tfile, pair.tbitmap, subcmd, 0,
		    pair.directfile, pair.group, pair.ctag, qvol, &pair.doasync,
		    0) < 0) {
			if (cfg_vol_disable(cfg, qvol, ctag, "sndr") < 0)
				rdc_warn(NULL, gettext("Failed to remove disk "
				    "queue [%s] from configuration"), qvol);
			rdc_err(NULL, gettext("Add disk queue operation "
			    "failed"));
		}
		if (nsc_lookup(volhash, qvol) == NULL) {
			if (cfg_vol_enable(cfg, qvol, ctag, "sndr") < 0) {
				rdc_err(NULL, gettext("Add disk queue "
					"operation failed"));
			}
		}
		rewrite_group_diskqueue(cfg, &pair, qvol);

		spcs_log("sndr", NULL, gettext("Remote Mirror: added "
		    "diskqueue %s to set %s:%s and its group"), qvol,
		    pair.thost, pair.tfile);
		break;
	case RDC_OPT_FORCE_QINIT:
		if (strlen(pair.diskqueue) == 0) {
			rdc_err(NULL, gettext("Remote Mirror set does not "
			    "have a disk queue"));
		}
		subcmd = RDC_CMD_INITQ;
		option = RDC_OPT_FORCE_QINIT;
		if (rdc_operation(cfg, pair.fhost, pair.ffile, pair.fbitmap,
		    pair.thost, pair.tfile, pair.tbitmap, subcmd, option,
		    pair.directfile, pair.group, pair.ctag, qvol, &pair.doasync,
		    0) < 0) {
			exit(1);
		}
		break;
	case RDC_CMD_INITQ:
		if (strlen(pair.diskqueue) == 0) {
			rdc_err(NULL, gettext("Remote Mirror set does not "
			    "have a disk queue"));
		}
		if (rdc_operation(cfg, pair.fhost, pair.ffile, pair.fbitmap,
		    pair.thost, pair.tfile, pair.tbitmap, subcmd, 0,
		    pair.directfile, pair.group, pair.ctag, qvol, &pair.doasync,
		    0) < 0) {
			exit(1);
		}
		break;
	case RDC_CMD_REMQ:
		if (strlen(pair.diskqueue) == 0) {
			rdc_err(NULL, gettext("Remote Mirror set does not "
			    "have a disk queue"));
		}
		if (rdc_operation(cfg, pair.fhost, pair.ffile, pair.fbitmap,
		    pair.thost, pair.tfile, pair.tbitmap, subcmd, 0,
		    pair.directfile, pair.group, pair.ctag, qvol, &pair.doasync,
		    0) < 0) {
			exit(1);
		}
		if (cfg_vol_disable(cfg, pair.diskqueue, ctag, "sndr") < 0)
			rdc_warn(NULL, gettext("Failed to remove disk queue "
				"[%s] from configuration"), pair.diskqueue);
		rewrite_group_diskqueue(cfg, &pair, place_holder);

		spcs_log("sndr", NULL, gettext("Remote Mirror: removed "
		    "diskqueue from set %s:%s and its group"), pair.thost,
		    pair.tfile);
		break;
	case RDC_CMD_KILLQ:
		if (strlen(pair.diskqueue) == 0) {
			rdc_err(NULL, gettext("Remote Mirror set does not "
			    "have a disk queue"));
		}
		if (rdc_operation(cfg, pair.fhost, pair.ffile, pair.fbitmap,
		    pair.thost, pair.tfile, pair.tbitmap, subcmd, 0,
		    pair.directfile, pair.group, pair.ctag, qvol, &pair.doasync,
		    0) < 0) {
			rdc_err(NULL, gettext("Failed to remove disk queue"));
		}
		if (cfg_vol_disable(cfg, pair.diskqueue, ctag, "sndr") < 0)
			rdc_warn(NULL, gettext("Failed to remove disk queue "
				"[%s] from configuration"), pair.diskqueue);

		rewrite_group_diskqueue(cfg, &pair, place_holder);

		spcs_log("sndr", NULL, gettext("Remote Mirror: forcibly "
		    "removed diskqueue from set %s:%s and its group "),
		    pair.thost, pair.tfile);
		break;
	case RDC_CMD_REPQ:
		if (clustered && (ctag_check(pair.fhost, pair.ffile,
		    pair.fbitmap, pair.thost, pair.tfile, pair.tbitmap,
		    pair.ctag, qvol) < 0))
			exit(1);

		if (strlen(pair.diskqueue) == 0) {
			rdc_err(NULL, gettext("Remote Mirror set does not "
			    "have a disk queue"));
		}
		if (rdc_operation(cfg, pair.fhost, pair.ffile, pair.fbitmap,
		    pair.thost, pair.tfile, pair.tbitmap, RDC_CMD_REMQ, 0,
		    pair.directfile, pair.group, pair.ctag, qvol, &pair.doasync,
		    0) < 0) {
			rdc_err(NULL, gettext("Failed to remove disk queue"));
		}
		if (cfg_vol_disable(cfg, pair.diskqueue, ctag, "sndr") < 0)
			rdc_warn(NULL, gettext("Failed to remove disk queue "
				"[%s] from configuration"), pair.diskqueue);

		rewrite_group_diskqueue(cfg, &pair, place_holder);

		/* commit here, enable may fail */
		if (cfg_commit(cfg) < 0) {
			rdc_err(NULL, gettext("commit replace disk queue %s "
				"with %s failed"), pair.diskqueue, qvol);
		}

		if (check_diskqueue(cfg, qvol, group_arg) == DISKQ_FAIL) {
			rdc_err(NULL,
			    gettext("cannot replace disk queue %s with %s"),
			    pair.diskqueue, qvol);
		}
		if (rdc_operation(cfg, pair.fhost, pair.ffile, pair.fbitmap,
		    pair.thost, pair.tfile, pair.tbitmap, RDC_CMD_ADDQ, 0,
		    pair.directfile, pair.group, pair.ctag, qvol, &pair.doasync,
		    0) < 0) {
			if (cfg_vol_disable(cfg, qvol, ctag, "sndr") < 0)
				rdc_warn(NULL, gettext("Failed to remove disk "
				    "queue [%s] from configuration"), qvol);
			rdc_err(NULL, gettext("Failed to add new disk queue"));
		}
		if (nsc_lookup(volhash, qvol) == NULL)
			if (cfg_vol_enable(cfg, qvol, ctag, "sndr") < 0) {
				rdc_err(NULL, gettext("Replace disk queue "
					"operation failed"));
			}

		rewrite_group_diskqueue(cfg, &pair, qvol);

		spcs_log("sndr", NULL, gettext("Remote Mirror: replaced "
		    "diskqueue for set %s:%s and its group with %s"),
		    pair.thost, pair.tfile, qvol);
		break;
	}

	cfg_unload_svols(cfg);
	cfg_unload_dsvols(cfg);
	cfg_unload_shadows(cfg);
	unload_rdc_vols();

	if (cfg_commit(cfg) < 0)
		rdc_err(NULL, gettext("commit failed on disk queue operation"));

	cfg_close(cfg);
	if (ctag)
		free(ctag);
}
void
spcslog_sync(rdcconfig_t *sets, int start, int type)
{
	rdcconfig_t *setp = sets;

	while (setp) {
		if (start) {
			spcs_log("sndr", NULL,
			    gettext("%s %s %s %s %s %s %s %s\nSync Started"),
			    program, rdc_decode_flag(RDC_CMD_COPY, type),
			    setp->phost, setp->pfile, setp->pbmp,
			    setp->shost, setp->sfile, setp->sbmp);
		} else {
			spcs_log("sndr", NULL,
			    gettext("%s %s %s %s %s %s %s %s\nSync Ended"),
			    program, rdc_decode_flag(RDC_CMD_COPY, type),
			    setp->phost, setp->pfile, setp->pbmp,
			    setp->shost, setp->sfile, setp->sbmp);
		}
		setp = setp->next;
	}
}

void
spcslog_tunable(char *shost, char *svol)
{
	if (qblock == RDC_OPT_SET_QNOBLOCK)
		spcs_log("sndr", NULL, gettext("diskqueue "
		    "set to non blocking for %s:%s and any members "
		    "of it's group"), shost, svol);
	else if (qblock == RDC_OPT_CLR_QNOBLOCK)
		spcs_log("sndr", NULL, gettext("diskqueue "
		    "set to blocking for %s:%s and any members "
		    "of it's group"), shost, svol);

	if (maxqfbas)
		spcs_log("sndr", NULL, gettext("maxqfbas set to %d for %s:%s"),
		    maxqfbas, shost, svol);
	if (maxqitems)
		spcs_log("sndr", NULL, gettext("maxwrites set to %d for %s:%s"),
		    maxqitems, shost, svol);
	if (asyncthr)
		spcs_log("sndr", NULL, gettext("%d async threads configured "
		    "for %s:%s"), asyncthr, shost, svol);
}

int
set_qblock(char *blockarg)
{
	if (strcmp(blockarg, "block") == 0)
		qblock = RDC_OPT_CLR_QNOBLOCK;
	else if (strcmp(blockarg, "noblock") == 0)
		qblock = RDC_OPT_SET_QNOBLOCK;
	else
		return (1);

	return (0);
}

static void
rdc_force_disable(CFGFILE *cfg, char *phost, char *pvol, char *pbmp,
    char *shost, char *svol, char *sbmp, char *ctag, char *lhname)
{
	rdc_config_t parms;
	spcs_s_info_t ustatus;
	volcount_t *vc;
	char *datavol = NULL;
	char *bmpvol = NULL;
	int on_pri = 0;
	int on_sec = 0;

	/* are we on the primary or secondary host? */
	if (ctag && *ctag && *lhname) {
		if (strcmp(phost, lhname) == 0) {
			on_pri = 1;
		} else if (strcmp(shost, lhname) == 0) {
			on_sec = 1;
		}
	} else if (self_check(phost)) {
		on_pri = 1;
	} else if (self_check(shost)) {
		on_sec = 1;
	}

	if (on_pri) {
		datavol = pvol;
		bmpvol = pbmp;
	} else if (on_sec) {
		datavol = svol;
		bmpvol = sbmp;
	} else {
		rdc_err(NULL, gettext("Unable to determine whether current "
		    "node is primary or secondary"));
	}

	/* set up parms structure */
	parms.command = RDC_CMD_DISABLE;
	(void) strncpy(parms.rdc_set->primary.intf, phost, MAX_RDC_HOST_SIZE);
	(void) strncpy(parms.rdc_set->primary.file, pvol, NSC_MAXPATH);
	(void) strncpy(parms.rdc_set->secondary.intf, shost, MAX_RDC_HOST_SIZE);
	(void) strncpy(parms.rdc_set->secondary.file, svol, NSC_MAXPATH);
	ustatus = spcs_s_ucreate();
	parms.options = RDC_OPT_FORCE_DISABLE;

	/*
	 * We are now going to 'force' the kernel to disable the set.  By
	 * setting the RDC_OPT_FORCE_DISABLE flag, the kernel will bypass some
	 * of the checks that are normally done when attempting to disable
	 * a set.  We need to do this force option in a cluster environment
	 * when the logical hostname for the primary or secondary volume
	 * is no longer available.
	 */
	spcs_log("sndr", NULL, "%s sndradm -d %s %s %s %s %s %s",
	    gettext("FORCE DISABLE"), phost, pvol, pbmp, shost, svol, sbmp);
	rdc_warn(NULL, gettext("Forcing set disable"));
	if (RDC_IOCTL(RDC_CONFIG, &parms, 0, 0, 0, 0, ustatus) != SPCS_S_OK)
		rdc_warn(&ustatus, gettext("set %s:%s not enabled in kernel"),
		    shost, svol);

	/* if we get to this point, then a set was disabled.  try sv-disable */
	vc = nsc_lookup(volhash, datavol);
	if (vc && (1 == vc->count))
		if (cfg_vol_disable(cfg, datavol, ctag, "sndr") < 0)
			rdc_warn(NULL, gettext("Failed to remove data volume "
			    "[%s] from configuration"), datavol);
	vc = nsc_lookup(volhash, bmpvol);
	if (vc && (1 == vc->count))
		if (cfg_vol_disable(cfg, bmpvol, ctag, "sndr") < 0)
			rdc_warn(NULL, gettext("Failed to remove bitmap "
			    "[%s] from configuration"), bmpvol);
}

void
check_rdcsecondary(char *secondary)
{
	int i;
	CFGFILE *cfg;
	int entries;
	char **entry;
	char *sha;
	char *buf;

	if ((cfg = cfg_open(NULL)) == NULL)
		rdc_err(NULL,
		    gettext("error opening config"));
	if (!cfg_lock(cfg, CFG_RDLOCK))
		rdc_err(NULL, gettext("error locking config"));

	entry = NULL;
	entries = cfg_get_section(cfg, &entry, "ii");
	for (i = 0; i < entries; i++) {
		buf = entry[i];

		(void) strtok(buf, " ");	/* master */
		sha = strtok(NULL, " ");	/* shadow */
		if (strcmp(secondary, sha) == 0) {
			rdc_err(NULL,
			    gettext("secondary %s is in use by"
			    " Point-in-Time Copy"), secondary);
		}
		free(buf);
	}
	if (entries)
		free(entry);
	cfg_close(cfg);
}

int
main(int argc, char *argv[])
{
	char config_file[FILENAME_MAX];
	char fromhost[MAX_RDC_HOST_SIZE];
	char tohost[MAX_RDC_HOST_SIZE];
	char fromfile[NSC_MAXPATH];
	char tofile[NSC_MAXPATH];
	char frombitmap[NSC_MAXPATH];
	char tobitmap[NSC_MAXPATH];
	char directfile[NSC_MAXPATH];
	char group[NSC_MAXPATH];
	char ctag[MAX_RDC_HOST_SIZE];
	char options_cfg[CFG_MAX_BUF];
	char fromnetaddr[RDC_MAXADDR];
	char tonetaddr[RDC_MAXADDR];
	char tmphost[MAX_RDC_HOST_SIZE];
	char tmpfile[NSC_MAXPATH];
	char tmpbitmap[NSC_MAXPATH];
	char diskqueue[NSC_MAXPATH];
	char lhname[MAX_RDC_HOST_SIZE];
	char mode[16];
	rdc_version_t rdc_version;
	int pairs;
	int pid;
	int flag = 0;
	int fflag = 0;
	int reverse = 0;
	int nflag = 0;
	int iflag = 0;
	int doasync;
	int pflag = 0;
	int vflag = 0;
	int verbose = 0;
	int errflag = 0;
	int cfgflag = 0;
	int cfg_success;
	int Iflag = 0;
	char c;
	char inval = 0;
	int found;
	int rc;
	int geflag = 0;
	int qflag = 0;
	char *qarg;
	int Bflag = 0;
	char *bitfile;
	CFGFILE *cfg = NULL;
	int i;
	int setnumber;
	char key[CFG_MAX_KEY];
	char buf[CFG_MAX_BUF];
	char ctag_arg[MAX_RDC_HOST_SIZE];
	char group_arg[NSC_MAXPATH];
	int file_format = 0;
	int sev;
	int diskq_group = DISKQ_OKAY;
	int extra_argc;
	char *ctag_p, *group_p, *diskqueue_p;
	char *required;
	char *role_env;
	int checksetfields = -1;
	nsc_off_t boffset = 0;
	int oflag = 0;
	rdcconfig_t *sets = NULL;
	rdcconfig_t *sets_p = NULL;
	rdc_rc_t *rclist = NULL;
	rdc_rc_t *rcp = NULL;
	int host_not_found = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("rdc");
	role_env = getenv("SNDR_ROLE_REVERSE");
	if (role_env && strcmp(role_env, "sndr_allow_reverse") == 0)
		allow_role = 1;

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

	if ((clustered = cfg_iscluster()) < 0) {
		rdc_err(NULL, gettext("unable to ascertain environment"));
	}

	(void) strcpy(ctag_arg, "");
	(void) strcpy(group_arg, "");
	bzero(ctag, MAX_RDC_HOST_SIZE);
	bzero(reconfig_ctag, MAX_RDC_HOST_SIZE);
	bzero(diskqueue, NSC_MAXPATH);

	rdc_maxsets = rdc_get_maxsets();
	if (rdc_maxsets == -1) {
		rdc_err(NULL,
		    gettext("unable to get maxsets value from kernel"));
	}

	pair_list = calloc(rdc_maxsets, sizeof (*pair_list));
	if (pair_list == NULL) {
		rdc_err(NULL,
		    gettext("unable to allocate pair_list array for %d sets"),
		    rdc_maxsets);
	}

	bzero(group, sizeof (group));
	bzero(diskqueue, sizeof (diskqueue));
	qblock = 0;

	while ((c =
#ifdef DEBUG
	    getopt(argc, argv, "A:B:C:D:EF:HIO:PRUW:a:bdef:g:hilmno:pq:rsuvw"))
#else
	    getopt(argc, argv, "A:B:C:D:EF:HIO:PRUW:a:bdef:g:hilmno:pq:rsuvw"))
#endif
	    != -1) {
		switch (c) {
		case 'B':
			if (!allow_role || flag) {
				inval = 1;
				break;
			}
			bitfile = optarg;
			Bflag = 1;
			flag = RDC_BITMAPOP;
			break;
		case 'H':
			/* 'h' was already assigned */
			if (flag)
				inval = 1;
			flag = RDC_CMD_HEALTH;
			break;
		case 'I':
			/* List or edit ndr_ii configuration entries */
			Iflag = 1;
			break;
		case 'R':
			if (flag)
				inval = 1;
			flag = RDC_CMD_RECONFIG;
			break;
#ifdef DEBUG
		case 'U':		/* UDP support */
			proto_test = 1;
			break;
#endif
		case 'F':
			if (flag && flag != RDC_CMD_TUNABLE)
				inval = 1;
			flag = RDC_CMD_TUNABLE;

			if (check_intrange(optarg))
				maxqfbas = atoi(optarg);
			else
				exit(1);

			break;
		case 'W':
			if (flag && flag != RDC_CMD_TUNABLE)
				inval = 1;
			flag = RDC_CMD_TUNABLE;

			if (check_intrange(optarg))
				maxqitems = atoi(optarg);
			else
				exit(1);

			break;
		case 'A':
			if (flag && flag != RDC_CMD_TUNABLE)
				inval = 1;
			flag = RDC_CMD_TUNABLE;

			if (check_intrange(optarg))
				asyncthr = atoi(optarg);
			else
				exit(1);

			break;
		case 'D':
			if (flag && flag != RDC_CMD_TUNABLE)
				inval = 1;
			flag = RDC_CMD_TUNABLE;

			if (set_qblock(optarg)) {
				usage();
				exit(1);
			}
			iflag |= qblock;
			break;
		case 'a':
			if (flag && flag != RDC_CMD_TUNABLE)
				inval = 1;
			flag = RDC_CMD_TUNABLE;
			if (strcmp(optarg, "off") == 0)
				autosync = AUTOSYNC_OFF;
			else if (strcmp(optarg, "on") == 0)
				autosync = AUTOSYNC_ON;
			else
				inval = 1;
			break;
		case 'C':
			if (clustered) {
				(void) strncpy(ctag_arg, optarg,
				    MAX_RDC_HOST_SIZE);
				process_clocal(ctag_arg);
			} else
				inval = 1;
			break;
		case 'g':
			if (flag == RDC_CMD_ENABLE)
				inval = 1;
			geflag = 1;
			(void) strncpy(group_arg, optarg, NSC_MAXPATH);
			verify_groupname(group_arg);
			break;
		case 'b':
			/* ignore */
			break;
		case 'n':
			nflag = 1;
			break;
		case 'd':
			if (flag)
				inval = 1;
			flag = RDC_CMD_DISABLE;
			break;
		case 'e':
			if (flag || geflag)
				inval = 1;
			flag = RDC_CMD_ENABLE;
			iflag |= RDC_OPT_SETBMP;
			break;
		case 'E':
			if (flag)
				inval = 1;
			flag = RDC_CMD_ENABLE;
			iflag |= RDC_OPT_CLRBMP;
			break;
		case 'f':
			fflag = 1;
			(void) strcpy(config_file, optarg);
			break;
		case 'h':
			usage();
			exit(0);
			break;
		case 'l':
			if (flag)
				inval = 1;
			flag = RDC_CMD_LOG;
			break;
		case 'm':
			if (flag)
				inval = 1;
			flag = RDC_CMD_COPY;
			iflag |= RDC_OPT_FULL;
			break;
		case 'O':
		case 'o':

			if (!allow_role || oflag) {
				inval = 1;
				break;
			}
			if (c == 'o') {
				oflag = RDC_BITMAPOR;
			} else {
				oflag = RDC_BITMAPSET;
			}
			boffset = strtoull(optarg, NULL, 0);
			break;
		case 'P':
			if (flag)
				inval = 1;
			pflag = 1;
			verbose = 1;
			break;
		case 'p':
			if (flag)
				inval = 1;
			pflag = 1;
			break;
		case 'q':
			if (flag)
				inval = 1;
			flag = RDC_CMD_INITQ;
			qflag = optind;
			qarg = optarg;
			break;
		case 'i':
			if (flag)
				inval = 1;
			pflag = 1;
			file_format = 1;
			break;
		case 'r':
			reverse = 1;
			iflag |= RDC_OPT_REVERSE;
			break;
		case 's':
			if (flag)
				inval = 1;
			flag = RDC_CMD_STATUS;
			nflag = 1;	/* No prompt for a status */
			break;
		case 'u':
			if (flag)
				inval = 1;
			flag = RDC_CMD_COPY;
			iflag |= RDC_OPT_UPDATE;
			break;
		case 'v':
			if (flag)
				inval = 1;
			pflag = 1;
			vflag = 1;
			break;
		case 'w':
			if (flag)
				inval = 1;
			flag = RDC_CMD_WAIT;
			break;
		case '?':
			errflag++;
		}
	}

	if (inval || ((flag != RDC_BITMAPOP) && oflag)) {
		rdc_warn(NULL, gettext("invalid argument combination"));
		errflag = 1;
	}

	if (flag && Iflag) {
		/* Mutually incompatible */
		usage();
		exit(1);
	}

	if (Iflag) {
		rdc_ii_config(argc, argv);
		exit(0);
	}

	if (vflag) {
		spcs_s_info_t ustatus;

		ustatus = spcs_s_ucreate();
		rc = RDC_IOCTL(RDC_VERSION, &rdc_version, 0, 0, 0, 0, ustatus);
		if (rc == SPCS_S_ERROR) {
			rdc_err(&ustatus, gettext("statistics error"));
		}
		spcs_s_ufree(&ustatus);
#ifdef DEBUG
		(void) printf(gettext("Remote Mirror version %d.%d.%d.%d\n"),
		    rdc_version.major, rdc_version.minor,
		    rdc_version.micro, rdc_version.baseline);
#else
		if (rdc_version.micro) {
			(void) printf(gettext(
			    "Remote Mirror version %d.%d.%d\n"),
			    rdc_version.major,
			    rdc_version.minor,
			    rdc_version.micro);
		} else {
			(void) printf(gettext("Remote Mirror version %d.%d\n"),
			    rdc_version.major, rdc_version.minor);
		}
#endif
		exit(0);
	}

	if (!(flag || pflag) || errflag) {
		usage();
		exit(1);
	}

	if (pflag && !fflag && (argc - optind) == 0) {
		/* print with no set specified */
		exit(rdc_print(file_format, verbose,
		    group_arg, ctag_arg, NULL, NULL, NULL));
	}

	if (qflag) {	/* change disk queue setting */
		int	subcmd = 0;
		int	offset = 0;
		char	*ptr;
		char	*qvol;
		char	tohost_arg[MAX_RDC_HOST_SIZE];
		char	tofile_arg[NSC_MAXPATH];

		if (strcmp("a", qarg) == 0) {
			subcmd = RDC_CMD_ADDQ;
			offset = 1;
		} else if (strcmp("d", qarg) == 0) {
			subcmd = RDC_CMD_REMQ;
			offset = 0;
		} else if (strcmp("r", qarg) == 0) {
			subcmd = RDC_CMD_REPQ;
			offset = 1;
		} else {
			rdc_warn(NULL, " %s Invalid qopt", qarg);
			q_usage(1);
			exit(1);
		}
		if (strlen(group_arg) == 0) {
			/* pick out single set as shost:svol */
			ptr = strtok(argv[qflag + offset], ":");
			if (ptr)
				(void) strncpy(tohost_arg, ptr,
				    MAX_RDC_HOST_SIZE);
			else {
				rdc_warn(NULL, gettext("Bad host specified"));
				q_usage(1);
				exit(1);
			}
			ptr = strtok(NULL, ":");
			if (ptr)
				(void) strncpy(tofile_arg, ptr, NSC_MAXPATH);
			else {
				rdc_warn(NULL, gettext("Bad set specified"));
				q_usage(1);
				exit(1);
			}
		}

		qvol = argv[qflag];
		if ((qvol == NULL) && (subcmd != RDC_CMD_REMQ)) {
			rdc_warn(NULL, gettext("missing queue volume"));
			q_usage(1);
			exit(1);
		}
		diskq_subcmd(subcmd, qvol, group_arg, ctag_arg,
		    tohost_arg, tofile_arg);
		exit(0);
	}

	if (flag == RDC_CMD_RECONFIG && !fflag) {
		/* See what is to be reconfigured */
		if (argc - optind == 0)
			flag = RDC_CMD_RESET;
		else {
			if (argc - optind < 2) {
				usage();
				exit(1);
			}
			c = *argv[optind++];
			if (argv[optind -1][1] != '\0') {
				usage();
				exit(2);
			}
			switch (c) {
			case 'b':
				if (argc - optind < 2) {
					usage();
					exit(1);
				}
				if (*argv[optind] == 'p')
					reconfig_pbitmap = argv[++optind];
				else if (*argv[optind] == 's')
					reconfig_sbitmap = argv[++optind];
				else {
					usage();
					exit(1);
				}
				optind++;
				break;
#ifdef _RDC_CAMPUS
			case 'd':
				reconfig_direct = argv[optind++];
				break;
#endif
			case 'g':
				reconfig_group = argv[optind++];
				verify_groupname(reconfig_group);
				break;
			case 'C':
				if (clustered) {
					(void) strncpy(reconfig_ctag,
					    argv[optind++], MAX_RDC_HOST_SIZE);
					process_clocal(reconfig_ctag);
				} else {
					usage();
					exit(1);
				}
				break;
			case 'm':
				if (strcmp(argv[optind], "sync") == 0)
					reconfig_doasync = 0;
				else if (strcmp(argv[optind], "async") == 0)
					reconfig_doasync = 1;
				else {
					usage();
					exit(1);
				}
				optind++;
				break;
			case 'r':
				if (allow_role) {
					iflag |= RDC_OPT_REVERSE_ROLE;
					break;
				}
				/* FALLTHROUGH */
			default:
				usage();
				exit(1);
			}
		}
	}
	if (fflag) {
		checksetfields = 1;
		if ((argc - optind) != 0) {
			usage();
			exit(1);
		}
	} else {
		if ((argc - optind) == 0) {
			/* Use libcfg to figure out what to operate on */
			cfgflag = 1;
#ifdef DEBUG
			rdc_warn(NULL, gettext("using current config"));
#endif
			checksetfields = 0;
		} else {
			if ((argc - optind) < 8 && (argc - optind) != 1) {
				usage();
				exit(1);
			}
		}
	}

	if (cfgflag) {
		if (flag == RDC_CMD_ADDQ ||
		    flag == RDC_CMD_REMQ ||
		    flag == RDC_CMD_KILLQ ||
		    flag == RDC_CMD_INITQ) {
			rdc_err(NULL, gettext("can not use current config "
			    "for disk queue operations"));
		}
	} else if (fflag) {
		if (flag == RDC_CMD_ADDQ ||
		    flag == RDC_CMD_REMQ ||
		    flag == RDC_CMD_KILLQ ||
		    flag == RDC_CMD_INITQ) {
			rdc_err(NULL, gettext("can not use a config file "
			    "for disk queue operations"));
		}
	}
	if (cfgflag) {
		if (flag == RDC_CMD_ENABLE) {
			rdc_err(NULL, gettext("can not use current config "
			    "for enable command"));
		}
		if ((flag == RDC_CMD_RECONFIG) && (reconfig_pbitmap ||
		    reconfig_sbitmap)) {
			rdc_err(NULL, gettext("can not use current config "
			    "for bitmap reconfiguration"));
		}
		if (flag == RDC_BITMAPOP) {
			rdc_err(NULL, gettext("can not use current config "
			    "for bitmap set command"));
		}
		pairs = read_libcfg(flag, group_arg, ctag_arg);
		if (pairs == 0) {
			(void) fprintf(stderr,
			    gettext("no matching Remote Mirror sets found "
			    "in config\n"));
			exit(1);
		}
	} else if (!fflag) {
		/*
		 *	Format is either:
		 *
		 * tohost:tofile
		 *
		 *	or something like this for example:
		 *
		 * fromhost fromfile frombitmap tohost tofile tobitmap ip sync
		 *	g group C ctag
		 */

		if (argc - optind == 1) {
			char tohost_arg[MAX_RDC_HOST_SIZE];
			char tofile_arg[NSC_MAXPATH];
			char *ptr;

			checksetfields = 0;
			if (flag == RDC_CMD_ENABLE) {
				rdc_err(NULL,
				    gettext("must specify full set details for "
				    "enable command"));
			}
			ptr = strtok(argv[optind], ":");
			if (ptr)
				(void) strncpy(tohost_arg, ptr,
				    MAX_RDC_HOST_SIZE);
			else {
				rdc_err(NULL, gettext("Bad host specified"));
			}
			ptr = strtok(NULL, ":");
			if (ptr)
				(void) strncpy(tofile_arg, ptr, NSC_MAXPATH);
			else {
				rdc_err(NULL, gettext("Bad set specified"));
			}

			/* Now look up tohost:tofile via libcfg */

			if ((cfg = cfg_open(NULL)) == NULL)
				rdc_err(NULL,
				    gettext("unable to access configuration"));

			if (!cfg_lock(cfg, CFG_RDLOCK))
				rdc_err(NULL,
				    gettext("unable to lock configuration"));

			setnumber = 0;
			found = 0;
			/*CSTYLED*/
			for (i = 0; i < rdc_maxsets;) {
				setnumber++;

				bzero(buf, CFG_MAX_BUF);
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d", setnumber);
				rc = cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF);
				if (rc < 0)
					break;

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.shost", setnumber);
				(void) cfg_get_cstring(cfg, key, tohost,
				    sizeof (tohost));
				if (strncmp(tohost, tohost_arg, NSC_MAXPATH))
					continue;

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.secondary", setnumber);
				(void) cfg_get_cstring(cfg, key, tofile,
				    sizeof (tofile));
				if (strncmp(tofile, tofile_arg, NSC_MAXPATH))
					continue;

				found = 1;

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.phost", setnumber);
				(void) cfg_get_cstring(cfg, key, fromhost,
				    sizeof (fromhost));

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.primary", setnumber);
				(void) cfg_get_cstring(cfg, key, fromfile,
				    sizeof (fromfile));

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.pbitmap", setnumber);
				(void) cfg_get_cstring(cfg, key, frombitmap,
				    sizeof (frombitmap));

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.sbitmap", setnumber);
				(void) cfg_get_cstring(cfg, key, tobitmap,
				    sizeof (tobitmap));

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.type", setnumber);
				(void) cfg_get_cstring(cfg, key, directfile,
				    sizeof (directfile));
				if (strcmp(directfile, "ip") == 0)
					(void) strcpy(directfile, "");

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.mode", setnumber);
				(void) cfg_get_cstring(
				    cfg, key, mode, sizeof (mode));

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.group", setnumber);
				(void) cfg_get_cstring(cfg, key, group,
				    sizeof (group));
				if (strcmp(group_arg, "") &&
				    strncmp(group_arg, group, NSC_MAXPATH))
					continue;
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.cnode", setnumber);
				(void) cfg_get_cstring(
				    cfg, key, ctag, sizeof (ctag));
				if ((strlen(ctag_arg) > 0) &&
				    (strcmp(ctag_arg, ctag) != 0))
					rdc_err(NULL,
					    gettext("ctags %s and %s "
					    "do not match"), ctag_arg, ctag);

				if (strcmp(mode, "sync") == 0)
					doasync = 0;
				else if (strcmp(mode, "async") == 0)
					doasync = 1;
				else {
					rdc_err(NULL,
					    gettext("set %s:%s neither sync "
					    "nor async"), tohost, tofile);
				}
				break;
			}
			cfg_close(cfg);
			if (!found) {
				rdc_err(NULL,
				    gettext("set %s:%s not found in config"),
				    tohost_arg, tofile_arg);
			}
		} else {
			checksetfields = 1;
			(void) strncpy(fromhost, argv[optind],
			    MAX_RDC_HOST_SIZE);
			(void) strncpy(fromfile, argv[optind+1], NSC_MAXPATH);
			(void) strncpy(frombitmap, argv[optind+2], NSC_MAXPATH);
			(void) strncpy(tohost, argv[optind+3],
			    MAX_RDC_HOST_SIZE);
			(void) strncpy(tofile, argv[optind+4], NSC_MAXPATH);
			(void) strncpy(tobitmap, argv[optind+5], NSC_MAXPATH);

			/* Check the length of entries from the command line */
			if ((fromhost[MAX_RDC_HOST_SIZE - 1] != '\0') ||
			    (tohost[MAX_RDC_HOST_SIZE - 1] != '\0')) {
				rdc_err(NULL,
				    gettext("hostname is longer than %d "
				    "characters\n"), (MAX_RDC_HOST_SIZE - 1));
			}

			/* Check if it's ip address -- not allowed */
			if ((inet_addr(fromhost) != (in_addr_t)(-1)) ||
			    (inet_addr(tohost) != (in_addr_t)(-1))) {
				rdc_err(NULL, gettext(
				    "The hostname specified is invalid.\n"
				    "See 'man inet(3SOCKET)'"));
			}

			if ((fromfile[NSC_MAXPATH - 1] != '\0') ||
			    (tofile[NSC_MAXPATH - 1] != '\0') ||
			    (frombitmap[NSC_MAXPATH - 1] != '\0') ||
			    (tobitmap[NSC_MAXPATH - 1] != '\0')) {
				rdc_err(NULL, gettext("device name is longer "
				"than %d characters\n"), (NSC_MAXPATH - 1));
			}
#ifdef _RDC_CAMPUS
			if (argv[optind+6][0] == '/') {
				/* FCAL directio */
				(void) strncpy(directfile, argv[optind+6],
				    NSC_MAXPATH);
			} else if (strcmp(argv[optind+6], "ip") != 0) {
#else
			if (strcmp(argv[optind+6], "ip") != 0) {
#endif
				usage();
				exit(1);
			} else
				(void) strcpy(directfile, "ip");

			if (strcmp(argv[optind+7], "sync") == 0)
				doasync = 0;
			else if (strcmp(argv[optind+7], "async") == 0)
				doasync = 1;
			else {
				usage();
				exit(1);
			}

			/*
			 * At this point, we could have a set which is
			 * clustered, but neither a 'C ctag' or '-C ctag' has
			 * been specified. To avoid clobbering the ctag if a
			 * dscfg operation is done in the future, we should get
			 * the ctag out of the config at this point. To do this,
			 * set the cluster resource filter to NULL to look at
			 * all sets in the config, pulling out the ctag for the
			 * set matching shost:svol. If the set is not found,
			 * fail here. Note, we skip this set on an enable as the
			 * set is not yet in the config, so no need to waste
			 * time.
			 */
			if ((argc - optind == 8) && clustered &&
			    (flag != RDC_CMD_ENABLE)) {
				int setnumber;
				char key[CFG_MAX_KEY];

				if ((cfg = cfg_open(NULL)) == NULL) {
				    rdc_err(NULL,
				    gettext("unable to access configuration"));
				}
				if (!cfg_lock(cfg, CFG_RDLOCK)) {
				    rdc_err(NULL,
				    gettext("unable to lock configuration"));
				}

				cfg_resource(cfg, NULL);

				if ((setnumber =
				    find_setnumber_in_libcfg(cfg, NULL, tohost,
				    tofile)) < 0) {
					cfg_close(cfg);
					rdc_err(NULL,
					    gettext("unable to find Remote "
					    "Mirror set "
					    "%s:%s in config"),
					    tohost, tofile);
				}

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.cnode", setnumber);
				if (cfg_get_cstring(cfg, key, ctag_arg,
				    MAX_RDC_HOST_SIZE) < 0) {
					cfg_close(cfg);
					rdc_err(NULL,
					    gettext("unable to determine ctag "
					    "for Remote Mirror set %s:%s"),
					    tohost, tofile);
				}

				rdc_islocal = strcmp(ctag_arg, "-") ? 0 : 1;

				cfg_close(cfg);
			}

			extra_argc = argc - optind;
			if (extra_argc < 8 || extra_argc > 14 ||
			    extra_argc % 2 != 0) {
				usage();
				exit(1);
			}

			/*
			 * Loop through all of the extra arguments specified
			 * on the command line, setting the appropriate values
			 * for valid entries. If an unrecognized argument is
			 * detected, abort with error. Note: This hack should be
			 * removed and we should not accept these entries as
			 * arguments, they should be passed in as switches.
			 */
			for (i = (8 + optind); i < argc; i += 2) {
				/* string case statement */
				if (strcmp(argv[i], "g") == 0) {
				    (void) strncpy(group, argv[i + 1],
				        NSC_MAXPATH);
				    if (group[NSC_MAXPATH - 1] != '\0') {
					rdc_err(NULL, gettext("group name is "
					"longer than %d characters\n"),
					(NSC_MAXPATH - 1));
				    }
				} else if (strcmp(argv[i], "C") == 0) {
				    if (!clustered) {
					usage();
					exit(1);
				    }
				    (void) strncpy(ctag, argv[i + 1],
					    MAX_RDC_HOST_SIZE);

				    if (ctag[MAX_RDC_HOST_SIZE - 1] != '\0') {
					rdc_err(NULL, gettext("cluster name "
					"is longer than %d characters\n"),
					(MAX_RDC_HOST_SIZE - 1));
				    }
				    process_clocal(ctag);

				/*
				 * well here is something.
				 * what if they went sndradm -C local
				 * host a b host a b ip sync C foobar?
				 * they might be confused
				 * lets stop them if ctag_arg and ctag
				 * don't match and forgive if they are
				 * the same, below also.
				 */
				    if ((strlen(ctag_arg) > 0) &&
					(strcmp(ctag_arg, ctag) != 0)) {
					    rdc_err(NULL, gettext("ctags "
						"%s and %s do not match "),
						ctag_arg, ctag);

				    }
				} else if (strcmp(argv[i], "q") == 0) {
				    (void) strncpy(diskqueue, argv[i + 1],
					    NSC_MAXPATH);
				    if (diskqueue[NSC_MAXPATH - 1] != '\0') {
					rdc_err(NULL, gettext("diskq name is "
					"longer than %d characters\n"),
					(NSC_MAXPATH - 1));
				    }
				} else {
					/* Unrecognized argument */
					usage();
					exit(1);
				}
			}
		}

		/*
		 * Are we able to determine the existance of either
		 * of these host addresses?
		 */
		if (gethost_netaddrs(fromhost, tohost,
		    (char *)&fromnetaddr, (char *)&tonetaddr) < 0) {
			(void) fprintf(stderr, "\n");
			rdc_warn(NULL, gettext("unable to determine IP "
				"addresses for either host %s or host %s"),
				fromhost, tohost);

			if (flag != RDC_CMD_DISABLE)
				exit(1);
			else
				host_not_found = 1;
		}

		/*
		 * Are we running on neither host?
		 */
		if (!self_check(fromhost) && !self_check(tohost)) {
			if (flag == RDC_CMD_DISABLE) {
			(void) fprintf(stderr, "\n");
			rdc_warn(NULL, gettext("Not running on either host "
				"%s or host %s"), fromhost, tohost);
			host_not_found = 1;
			}
		}

		/*
		 * at this point, hopfully it is safe to say that
		 * if a ctag was supplied via -C tag it is safe to
		 * move it from ctag_arg to ctag. If it was passed in
		 * at the end and the beginning of the cli, it must
		 * match, as per checks above. if it was not passed
		 * in at the end, but at the beginning, we can deal.
		 * this should handle the case of shost:svol.
		 * which is the main reason for this.
		 *
		 * there are 3 cases: passed in by cli, checked just above.
		 * using libdscfg, you must pass in -C tag to have
		 * ctag_check pass.
		 * finally a file. same rules as libdscfg.
		 */
		if ((strlen(ctag) == 0) && (strlen(ctag_arg) > 0))
			(void) strcpy(ctag, ctag_arg);

		if (flag == RDC_CMD_RECONFIG) {
			if (reconfig_pbitmap) {
				(void) strncpy(frombitmap, reconfig_pbitmap,
				    NSC_MAXPATH);
				check_rdcbitmap(flag, fromhost, frombitmap);
			}
			if (reconfig_sbitmap) {
				(void) strncpy(tobitmap, reconfig_sbitmap,
				    NSC_MAXPATH);
				check_rdcbitmap(flag, tohost, tobitmap);
			}
#ifdef _RDC_CAMPUS
			if (reconfig_direct)
				(void) strncpy(directfile, reconfig_direct,
				    NSC_MAXPATH);
#endif
			if (reconfig_group)
				(void) strncpy(group, reconfig_group,
				    NSC_MAXPATH);

			if (strlen(reconfig_ctag) > 0)
				(void) strncpy(ctag, reconfig_ctag,
				    MAX_RDC_HOST_SIZE);
			if (reconfig_doasync != -1)
				doasync = reconfig_doasync;
		}

		if (flag == RDC_CMD_ENABLE || flag == RDC_CMD_RECONFIG) {
			if (ctag_check(fromhost, fromfile, frombitmap,
			    tohost, tofile, tobitmap, ctag, diskqueue) < 0)
				exit(1);
			if ((diskq_group = check_diskqueue(NULL, diskqueue,
			    group)) == DISKQ_FAIL) {
				rdc_err(NULL, gettext("disk queue %s is "
				    "incompatible with existing queue"),
				    diskqueue);
			}

		}
		pairs = 1;
	} else {
		pairs = read_config(flag, config_file, group_arg, ctag_arg);
		if (pairs == 0) {
			rdc_err(NULL, gettext("%s contains no "
			    "matching Remote Mirror sets"), config_file);
		}
	}

	if (!nflag && !pflag && prompt_user(flag, iflag) == -1)
		exit(1);

	while (pairs--) {

		if (cfgflag || fflag) {
			(void) strncpy(fromfile, pair_list[pairs].ffile,
			    NSC_MAXPATH);
			(void) strncpy(tofile, pair_list[pairs].tfile,
			    NSC_MAXPATH);
			(void) strncpy(frombitmap, pair_list[pairs].fbitmap,
			    NSC_MAXPATH);
			(void) strncpy(fromhost,
			    pair_list[pairs].fhost, MAX_RDC_HOST_SIZE);
			(void) strncpy(tohost, pair_list[pairs].thost,
			    MAX_RDC_HOST_SIZE);
			(void) strncpy(tobitmap, pair_list[pairs].tbitmap,
			    NSC_MAXPATH);
			(void) strncpy(directfile, pair_list[pairs].directfile,
			    NSC_MAXPATH);
			(void) strncpy(group, pair_list[pairs].group,
			    NSC_MAXPATH);
			(void) strncpy(ctag, pair_list[pairs].ctag,
			    MAX_RDC_HOST_SIZE);
			(void) strncpy(diskqueue, pair_list[pairs].diskqueue,
			    NSC_MAXPATH);

			bcopy(pair_list[pairs].fnetaddr, fromnetaddr,
			    RDC_MAXADDR);
			bcopy(pair_list[pairs].tnetaddr, tonetaddr,
			    RDC_MAXADDR);

			doasync = pair_list[pairs].doasync;
		}

		if (pflag) {
			static int first = 1;

			if (first) {
				if ((cfg = cfg_open(NULL)) == NULL)
				    rdc_err(NULL,
				    gettext("unable to access configuration"));

				if (!cfg_lock(cfg, CFG_RDLOCK))
				    rdc_err(NULL,
				    gettext("unable to lock configuration"));

				first = 0;
			}

			(void) rdc_print(file_format, verbose,
			    group_arg, ctag_arg, tohost, tofile, cfg);

			if (pairs == 0) {
				cfg_close(cfg);
				exit(0);
			}

			/* short circuit the rest of the command loop */
			continue;
		}
		if (Bflag) {
			int ret;
			ret = rdc_bitmapset(tohost, tofile, bitfile, oflag,
			    boffset);
			exit(ret);
		}
		if ((fflag || cfgflag) && flag == RDC_CMD_RECONFIG) {
			char orig_fbmp[MAXHOSTNAMELEN];
			char orig_tbmp[MAXHOSTNAMELEN];
			int ret;
			rdc_config_t parms;
			spcs_s_info_t ustatus;

			parms.command = RDC_CMD_STATUS;
			parms.rdc_set->netconfig = NULL;
			(void) strncpy(parms.rdc_set->primary.intf, fromhost,
			    MAX_RDC_HOST_SIZE);
			(void) strncpy(parms.rdc_set->secondary.intf, tohost,
			    MAX_RDC_HOST_SIZE);
			(void) strncpy(parms.rdc_set->primary.file, fromfile,
			    NSC_MAXPATH);
			(void) strncpy(parms.rdc_set->secondary.file, tofile,
			    NSC_MAXPATH);
			ustatus = spcs_s_ucreate();
			ret = RDC_IOCTL(RDC_CONFIG, &parms,
			    NULL, 0, 0, 0, ustatus);
			if (ret != SPCS_S_OK) {
				rdc_err(NULL, gettext("unable to get set status"
				    " before reconfig operation"));
			}
			(void) strncpy(orig_fbmp, parms.rdc_set->primary.bitmap,
			    NSC_MAXPATH);
			(void) strncpy(orig_tbmp,
			    parms.rdc_set->secondary.bitmap, NSC_MAXPATH);

			if (strncmp(orig_fbmp, frombitmap, NSC_MAXPATH) != 0)
				check_rdcbitmap(flag, fromhost, frombitmap);
			if (strncmp(orig_tbmp, tobitmap, NSC_MAXPATH) != 0)
				check_rdcbitmap(flag, tohost, tobitmap);
			spcs_s_ufree(&ustatus);

		}
		/*
		 * take a peek in the config to see if
		 * the bitmap is being used elsewhere
		 */
		if (flag == RDC_CMD_ENABLE) {
			struct stat stb;
			/*
			 * just for fun, lets see if some silly person
			 * specified the same vol and bitmap
			 */
			if ((strcmp(fromfile, frombitmap) == 0) ||
			    (strcmp(tofile, tobitmap) == 0))
				rdc_err(NULL, gettext("volumes and bitmaps"
				    " must not match"));
			if (self_check(fromhost)) {
				check_rdcbitmap(flag, fromhost, frombitmap);
				if (stat(fromfile, &stb) != 0) {
					rdc_err(NULL,
					gettext("unable to access %s: %s"),
					fromfile, strerror(errno));
				}
				if (!S_ISCHR(stb.st_mode)) {
					rdc_err(NULL,
					gettext("%s is not a character device"),
					fromfile);
				}
			} else { /* on the secondary */
				check_rdcbitmap(flag, tohost, tobitmap);
				/* extra check for secondary vol */
				check_rdcsecondary(tofile);
				if (stat(tofile, &stb) != 0) {
					rdc_err(NULL,
					gettext("unable to access %s: %s"),
					tofile, strerror(errno));
				}
				if (!S_ISCHR(stb.st_mode)) {
					rdc_err(NULL,
					gettext("%s is not a character device"),
					tofile);
				}
			}

		}

		if (flag == RDC_CMD_ENABLE || flag == RDC_CMD_DISABLE ||
		    flag == RDC_CMD_RECONFIG) {
			if ((cfg = cfg_open(NULL)) == NULL)
				rdc_err(NULL,
				    gettext("unable to access configuration"));

			if (!cfg_lock(cfg, CFG_WRLOCK))
				rdc_err(NULL,
				    gettext("unable to lock configuration"));

			cfg_resource(cfg, clustered ? ctag : NULL);
		} else
			cfg = NULL;

		if (cfg && perform_autosv() &&
		    (flag == RDC_CMD_ENABLE || flag == RDC_CMD_DISABLE ||
		    flag == RDC_CMD_RECONFIG)) {
			if (cfg_load_svols(cfg) < 0 ||
			    cfg_load_dsvols(cfg) < 0 ||
			    cfg_load_shadows(cfg) < 0)
				rdc_err(NULL,
				    gettext("Unable to parse config filer"));
			load_rdc_vols(cfg);
		}
		cfg_success = (cfg == NULL);
		if (cfg && flag == RDC_CMD_ENABLE) {
			/* Enabled, so add the set via libcfg */

			/* Build a new sndr entry and put it */
			group_p = *group? group : place_holder;
			diskqueue_p = *diskqueue? diskqueue : place_holder;

			if ((diskqueue_p == place_holder) &&
			    (group_p != place_holder)) {
				get_group_diskq(cfg, group_p, diskqueue);
				if (*diskqueue)
					diskqueue_p = diskqueue;
			}

			/*
			 * format in pconfig is:
			 *	phost.primary.pbitmap.shost.secondary.
			 *	sbitmap.type.mode.group.cnode.options.diskq
			 */
			(void) snprintf(buf, sizeof (buf),
			    "%s %s %s %s %s %s %s %s %s %s - %s",
			    fromhost, fromfile, frombitmap, tohost, tofile,
			    tobitmap, directfile,
			    doasync? "async" : "sync", group_p,
			    clustered? ctag : "-", diskqueue_p);

			if (cfg_put_cstring(cfg, "sndr", buf, strlen(buf)) < 0)
				rdc_warn(NULL,
				    gettext("unable to add \"%s\" to "
				    "configuration storage: %s"),
				    buf, cfg_error(&sev));
			setnumber = find_setnumber_in_libcfg(cfg, clustered?
			    ctag : NULL, tohost, tofile);
			if (setnumber < 0)
				rdc_warn(NULL,
				    gettext("unable to add \"%s\" to "
				    "configuration storage: %s"),
				    diskqueue_p, cfg_error(&sev));

			else
				cfg_success = 1;

			/* Add cluster aware info */
			if (clustered && !rdc_islocal) {
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.options", setnumber);
				if (self_check(fromhost)) {
					if (cfg_put_options(cfg, CFG_SEC_CONF,
					    key, "lghn", fromhost) < 0) {
						rdc_err(NULL,
						    gettext("unable to add "
						    "\"%s\" to configuration "
						    "storage: %s"),
						    fromhost, cfg_error(&sev));
					}
				} else if (self_check(tohost)) {
					if (cfg_put_options(cfg, CFG_SEC_CONF,
					    key, "lghn", tohost) < 0) {
						rdc_err(NULL,
						    gettext("unable to add "
						    "\"%s\" to configuration "
						    "storage: %s"),
						    fromhost, cfg_error(&sev));
					}
				}
			}
		} else if (cfg && flag == RDC_CMD_DISABLE) {
			found = 0;
			/* Disabled, so delete the set via libcfg */

			/* get sndr entries until shost, sfile match */
			for (i = 0; i < rdc_maxsets; i++) {
				setnumber = i + 1;
				(void) snprintf(key, sizeof (key), "sndr.set%d",
				    setnumber);
				if (cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF) < 0) {
					break;
				}
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.secondary", setnumber);
				if (cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF) < 0)
					break;
				if (strcmp(buf, tofile) != 0)
					continue;
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.shost",
				    setnumber);
				if (cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF) < 0)
					break;
				if (strcmp(buf, tohost) != 0)
					continue;
				found = 1;
#ifdef DEBUG
				if (checksetfields == -1) {
					rdc_err(NULL,
					    gettext("checksetfields not set"));
				}
#endif
				if (checksetfields) {
					checkgfields(cfg, setnumber, fromhost,
					    fromfile, frombitmap, tobitmap,
					    directfile, (doasync == 1)
					    ? "async" : "sync", group, ctag,
					    diskqueue);
				}

				/* perform cluster specific options */
				if (clustered) {
					/* get the logical host, if set */
					(void) snprintf(key, sizeof (key),
					    "sndr.set%d.options", setnumber);
					(void) cfg_get_single_option(cfg,
						CFG_SEC_CONF, key, "lghn",
						lhname, MAX_RDC_HOST_SIZE);

					/* figure out the cluster tag, if any */
					(void) snprintf(key, sizeof (key),
					    "sndr.set%d.cnode", setnumber);
					if (cfg_get_cstring(cfg, key, buf,
					    CFG_MAX_BUF) < 0)
						break;
					if (strcmp(buf, ctag))
						rdc_err(NULL, gettext("ctags %s"
						    " and %s do not match"),
						    buf, ctag);
				} else {
					*lhname = '\0';
					*ctag = '\0';
				}

				/* figure out the disk queue, if any */
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.diskq",
				    setnumber);
				if (cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF) < 0)
					break;
				if (strlen(buf) > 0) {
					(void) strncpy(diskqueue, buf,
					    NSC_MAXPATH);
				} else {
					*diskqueue = '\0';
				}
				(void) snprintf(key, sizeof (key), "sndr.set%d",
				    setnumber);
				if (cfg_put_cstring(cfg, key, NULL, 0) < 0)
					rdc_warn(NULL,
					    gettext("unable to remove \"%s\" "
					    "from configuration storage: %s"),
					    buf, cfg_error(&sev));
				else
					cfg_success = 1;
				break;
			}
			if (found == 0) {
				rdc_err(NULL,
				    gettext("Unable to find %s:%s in "
				    "configuration storage"),
				    tohost, tofile);
			}
			if (host_not_found) {
				rdc_force_disable(cfg, fromhost, fromfile,
				    frombitmap, tohost, tofile, tobitmap, ctag,
				    lhname);
				if (cfg_commit(cfg) < 0)
					rdc_err(NULL, gettext("commit on "
						"force disable failed"));
				cfg_close(cfg);
				return (0);
			}
		} else if (cfg && flag == RDC_CMD_RECONFIG) {
			/* Update relevant cfg record */

			cfg_resource(cfg, NULL);

			/* get sndr entries until shost, sfile match */
			for (i = 0; i < rdc_maxsets; i++) {
				setnumber = i + 1;
				(void) snprintf(key, sizeof (key), "sndr.set%d",
				    setnumber);
				if (cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF) < 0) {
					break;
				}
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.secondary", setnumber);
				if (cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF) < 0)
					break;
				if (strcmp(buf, tofile) != 0)
					continue;
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.shost",
				    setnumber);
				if (cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF) < 0)
					break;
				if (strcmp(buf, tohost) != 0)
					continue;
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.cnode",
				    setnumber);
				if (cfg_get_cstring(cfg, key, buf,
				    CFG_MAX_BUF) < 0)
					break;
				if (reconfig_ctag[0] == '\0')
					(void) strncpy(ctag, buf,
					    sizeof (ctag));
				if (doasync)
					(void) strcpy(mode, "async");
				else
					(void) strcpy(mode, "sync");
				if (strcmp(directfile, "") == 0)
					(void) strcpy(directfile, "ip");

				group_p = strlen(group) > 0 ? group :
				    place_holder;

				/*
				 * if we are reconfigging out altogether,
				 * get rid of the diskqueue
				 */
				if (group_p == place_holder)
					diskqueue_p = place_holder;
				else
					diskqueue_p = strlen(diskqueue) > 0 ?
					    diskqueue : place_holder;

				/*
				 * do a little diskq dance here for reconfigs
				 * that did not specify the diskqueue whilst
				 * reconfigging ...
				 */
				if ((diskqueue_p == place_holder) &&
				    (group_p != place_holder)) {
					get_group_diskq(cfg, group_p,
					    diskqueue);
					diskqueue_p = strlen(diskqueue) > 0 ?
					    diskqueue : place_holder;
				}

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.options", setnumber);
				if (cfg_get_cstring(cfg, key, options_cfg,
				    CFG_MAX_BUF) < 0) {
					break;
				}

				ctag_p = strlen(ctag) > 0 ?
				    ctag : place_holder;
				(void) snprintf(buf, sizeof (buf),
				    "%s %s %s %s %s %s %s %s %s %s %s %s",
				    fromhost, fromfile, frombitmap,
				    tohost, tofile, tobitmap,
				    directfile, mode, group_p,
				    ctag_p, options_cfg, diskqueue_p);

				(void) snprintf(key, sizeof (key), "sndr.set%d",
				    setnumber);
				if (cfg_put_cstring(cfg, key, buf,
				    strlen(buf)) < 0)
					rdc_warn(NULL,
					    gettext("unable to update \"%s\" "
					    "in configuration storage: %s"),
					    buf, cfg_error(&sev));
				else
					cfg_success = 1;
				break;
			}
		}

		if (cfg_success) {
			if (cfg && perform_autosv()) {
				if (self_check(fromhost)) {
				    if (diskqueue[0] &&
					(strcmp(diskqueue, fromfile) == 0) ||
					(strcmp(diskqueue, frombitmap) == 0)) {
						rdc_err(NULL, gettext("disk "
						    "queue volume %s must not "
						    "match any primary Remote "
						    "Mirror volume or bitmap"),
						    diskqueue);
				    }

				    if (diskqueue[0]) {
					different_devs(fromfile, diskqueue);
					different_devs(frombitmap, diskqueue);
					validate_name(cfg, diskqueue);
				    }
				    different_devs(fromfile, frombitmap);
				    validate_name(cfg, fromfile);
				    validate_name(cfg, frombitmap);
				} else {
				    different_devs(tofile, tobitmap);
				    validate_name(cfg, tofile);
				    validate_name(cfg, tobitmap);
				}
			}
			/*
			 * okay, if the command is sync, just build
			 * a list of rdcconfig_t's after the pairs--
			 * loop is done, we will pass this list to
			 * librdc to multithread the syncs (after
			 * forking off a daemonish type process
			 * that waits for the libcall to complete
			 * ints of interest:
			 * flag ie RDC_CMD_COPY, iflag RDC_OPT_UPDATE,
			 * reverse RDC_OPT_REVERSE, RDC_OPT_FORWARD
			 * if necessary, turn autosync back on
			 */
			if (flag == RDC_CMD_COPY) {
				if (autosync_is_on(tohost, tofile) ==
				    AUTOSYNC_ON)
					enable_autosync(fromhost, fromfile,
					    tohost, tofile);

				if (sets == NULL) {
					sets_p = sets =
					    rdc_alloc_config(fromhost, fromfile,
					    frombitmap, tohost, tofile,
					    tobitmap, "mode", "group", "ctag",
					    "options", 0);

					if (sets_p == NULL) {
						rdc_err(NULL,
						gettext("rdc config alloc"
						"failed %s"), rdc_error(NULL));
					}
					continue;
				}

				sets_p = sets_p->next =
				    rdc_alloc_config(fromhost, fromfile,
				    frombitmap, tohost, tofile, tobitmap,
				    "mode", "group", "ctag", "options", 0);

				if (sets_p == NULL) {
					rdc_err(NULL, gettext("rdc config alloc"
					"failed %s"), rdc_error(NULL));
				}
				continue;
			}

			/*
			 * block incoming signals until after the possible
			 * cfg_commit is done
			 */
			block_sigs();
			if (rdc_operation(cfg, fromhost, fromfile, frombitmap,
			    tohost, tofile, tobitmap, flag, iflag, directfile,
			    group, ctag, diskqueue, &doasync, reverse) < 0) {
				;
				/*EMPTY*/
			} else if (cfg) {
				if (diskq_group == DISKQ_REWRITEG) {
					rewrite_group_diskqueue(cfg,
					    &pair_list[pairs], diskqueue);
				}
				if (perform_autosv() &&
				    (flag == RDC_CMD_ENABLE ||
				    flag == RDC_CMD_DISABLE ||
				    flag == RDC_CMD_RECONFIG)) {
					unload_rdc_vols();
					cfg_unload_shadows();
					cfg_unload_dsvols();
					cfg_unload_svols();
				}
				if ((iflag & RDC_OPT_REVERSE_ROLE) != 0 &&
					allow_role) {
					bzero(tmphost, MAX_RDC_HOST_SIZE);
					bzero(tmpfile, NSC_MAXPATH);
					bzero(tmpbitmap, NSC_MAXPATH);
					(void) strncpy(tmphost, fromhost,
						MAX_RDC_HOST_SIZE);
					(void) strncpy(tmpfile, fromfile,
					    NSC_MAXPATH);
					(void) strncpy(tmpbitmap, frombitmap,
					    NSC_MAXPATH);

					(void) strncpy(fromhost, tohost,
					    MAX_RDC_HOST_SIZE);
					(void) strncpy(fromfile, tofile,
					    NSC_MAXPATH);
					(void) strncpy(frombitmap, tobitmap,
					    NSC_MAXPATH);

					(void) strncpy(tohost, tmphost,
					    MAX_RDC_HOST_SIZE);
					(void) strncpy(tofile, tmpfile,
					    NSC_MAXPATH);
					(void) strncpy(tobitmap, tmpbitmap,
					    NSC_MAXPATH);
					group_p = strlen(group) > 0 ? group :
					    place_holder;
					diskqueue_p = strlen(diskqueue) > 0 ?
					    diskqueue : place_holder;
					ctag_p = strlen(ctag) > 0 ?
					    ctag : place_holder;
					(void) snprintf(buf, sizeof (buf), "%s "
					    "%s %s %s %s %s %s %s %s %s %s %s",
					    fromhost, fromfile, frombitmap,
					    tohost, tofile, tobitmap,
					    directfile, mode, group_p,
					    ctag_p, options_cfg, diskqueue_p);

					(void) snprintf(key, sizeof (key),
						"sndr.set%d", setnumber);
					if (cfg_put_cstring(cfg, key, buf,
						strlen(buf)) < 0)
						rdc_err(NULL,
					    gettext("unable to update \"%s\" "
						"in configuration storage: %s"),
						    buf, cfg_error(&sev));
				}
				if (cfg_commit(cfg) < 0) {
					rdc_err(NULL, gettext("commit on role "
					"reversal failed"));
				}
			}
			unblock_sigs();
		}

		if (cfg) {
			cfg_close(cfg);
		}

	}
	if (flag == RDC_CMD_COPY) {
		pid = fork();
		if (pid == -1) {		/* error forking */
			perror("fork");
			exit(1);
		}
	} else {
		exit(0);
	}
	if (pid > 0) /* parent process */
		exit(0);

	spcslog_sync(sets, 1, iflag);
	if (iflag & RDC_OPT_REVERSE) {
		if (iflag & RDC_OPT_UPDATE)
			rclist = rdc_ursync(sets);
		else
			rclist = rdc_rsync(sets);
	} else if (iflag & RDC_OPT_UPDATE) {
		rclist = rdc_usync(sets);
	} else
		rclist = rdc_fsync(sets);

	rcp = rclist;
	while (rcp) {
		if (rcp->rc < 0) {
			/* rclist->msg has already been gettext'd */
			(void) fprintf(stderr,
			    gettext("Remote Mirror: %s %s %s %s %s %s\n"),
			    rcp->set.phost, rcp->set.pfile, rcp->set.pbmp,
			    rcp->set.shost, rcp->set.sfile, rcp->set.sbmp);
			rdc_warn(NULL, "%s", rcp->msg);
			spcs_log("sndr", NULL, "%s", rcp->msg);
		}
		rcp = rcp->next;
	}

	spcslog_sync(sets, 0, iflag);

	if (sets)
		rdc_free_config(sets, RDC_FREEALL);
	if (rclist)
		rdc_free_rclist(rclist);

	return (0);
}
/*
 * process_clocal()
 * pre: a non null string
 * post: if the string is "local"
 * then it is converted to "-"
 * and rdc_islocal is set to 1
 * if not rdc_islocal set to 0
 */
void
process_clocal(char *ctag)
{
	/*
	 * Check for the special cluster tag and convert into the
	 * internal representation.
	 */

	if (ctag != NULL && strcmp(ctag, RDC_LOCAL_TAG) == 0) {
		(void) strcpy(ctag, "-");
		rdc_islocal = 1;
	} else {
		rdc_islocal = 0;
	}
}

static void
rdc_check_dgislocal(char *dgname)
{
	char *othernode;
	int rc;

	/*
	 * check where this disk service is mastered
	 */

	rc = cfg_dgname_islocal(dgname, &othernode);
	if (rc < 0) {
		rdc_err(NULL, gettext("unable to find "
		    "disk service, %s: %s"), dgname, strerror(errno));
	}

	if (rc == 0) {
		rdc_err(NULL, gettext("disk service, %s, is "
		    "active on node \"%s\"\nPlease re-issue "
		    "the command on that node"), dgname, othernode);
	}
}

static void
different_devs(char *dev1, char *dev2)
{
	struct stat buf1, buf2;

	if (stat(dev1, &buf1) < 0) {
		spcs_log("sndr", NULL, gettext("Remote Mirror: can't stat %s"),
		    dev1);
		rdc_err(NULL, gettext("Remote Mirror: can't stat %s"), dev1);
	}
	if (stat(dev2, &buf2) < 0) {
		spcs_log("sndr", NULL, gettext("Remote Mirror: can't stat %s"),
		    dev2);
		rdc_err(NULL, gettext("Remote Mirror: can't stat %s"), dev2);
	}
	if (buf1.st_rdev == buf2.st_rdev) {
		spcs_log("sndr", NULL, gettext("Remote Mirror: '%s' and '%s' "
		    "refer to the same device"), dev1, dev2);
		rdc_err(NULL, gettext("Remote Mirror: '%s' and '%s' refer to "
		    "the same device"), dev1, dev2);
	}
}

static void
validate_name(CFGFILE *cfg, char *vol)
{
	char *altname;
	int rc;

	if (!cfg) {
		rdc_err(NULL, gettext("Remote Mirror: null cfg ptr in "
		    "validate_name"));
	}

	rc = cfg_get_canonical_name(cfg, vol, &altname);
	if (rc < 0) {
		spcs_log("sndr", NULL, gettext("Remote Mirror: unable to parse "
		    "config file\n"));
		rdc_err(NULL, gettext("Remote Mirror: unable to parse config "
		    "file\n"));
	}
	if (rc) {
		spcs_log("sndr", NULL, gettext("Remote Mirror: '%s': already "
		    "configured as '%s'"), vol, altname);
		rdc_err(NULL, gettext("Remote Mirror: The volume '%s' has been "
		    "configured previously as '%s'.  Re-enter command with "
		    "the latter name."), vol, altname);
	}
}

/*
 * Add the autosync value to the option field for the sndr set specified by
 * tohost:tofile.
 *
 * ASSUMPTIONS:
 *      - cfg file is available to take a write lock.
 *      - set is already configured in dscfg
 *
 * INPUTS:
 *      autosync_val - value to set autosync to
 *      tohost - secondary host
 *      tofile - secondary volume
 *
 * OUTPUTS:
 *      none.
 *
 */
static void
set_autosync(int autosync_val, char *tohost, char *tofile, char *ctag)
{
	CFGFILE *cfg;
	char key[CFG_MAX_KEY], buf[CFG_MAX_BUF];
	char tag[CFG_MAX_BUF], val[CFG_MAX_BUF];
	char auto_tag[CFG_MAX_BUF];
	_sd_dual_pair_t pair;
	_sd_dual_pair_t tmpair;
	int setnumber, options = 0, already_set = 0, cfg_success = 0;
	int set;

	/* verify valid autosync request */
	if ((autosync_val != AUTOSYNC_ON) && (autosync_val != AUTOSYNC_OFF)) {
#ifdef DEBUG
		rdc_warn(NULL,
		    gettext("set_autosync called with improper value"));
#endif
		return;
	}

	if ((cfg = cfg_open(NULL)) == NULL) {
		rdc_err(NULL, gettext("unable to access configuration"));
	}
	if (!cfg_lock(cfg, CFG_WRLOCK)) {
		rdc_err(NULL, gettext("unable to lock configuration"));
	}

	if (clustered) {
		cfg_resource(cfg, ctag);
	} else {
		cfg_resource(cfg, NULL);
	}

	/* find set number in config */
	if ((setnumber = find_setnumber_in_libcfg(cfg, clustered? ctag : NULL,
	    tohost, tofile)) < 0) {
		cfg_close(cfg);
		rdc_err(NULL, gettext("unable to find Remote Mirror set %s:%s: "
		    "in config"), tohost, tofile);
	}
	(void) snprintf(key, sizeof (key), "sndr.set%d.options", setnumber);
	(void) snprintf(auto_tag, sizeof (auto_tag), "auto");

	/* Check if there are any options already set, including ours */
	if (cfg_get_options(cfg, CFG_SEC_CONF, key, tag, CFG_MAX_BUF, val,
	    CFG_MAX_BUF) >= 0) {
		options = 1;

		do {
			if (strcmp(tag, auto_tag) == 0) {
				already_set = 1;
			}
		} while (cfg_get_options(cfg, CFG_SEC_CONF, NULL, tag,
		    CFG_MAX_BUF, val, CFG_MAX_BUF) >= 0);
	}

	/* options already exist, edit ours out */
	if (options && already_set) {
		char *p, *q;
		int need_to_clear_buf = 1;

		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
			rdc_err(NULL, gettext("unable to get options field "
			    "for Remote Mirror set %s:%s"), tohost, tofile);
		}

		/* parse out our options, all of the form "auto=" */
		p = strdup(buf);
		bzero(buf, sizeof (buf));

		q = strtok(p, ";");
		do {
			/* if another tag/value exists, keep it */
			if (strncmp(auto_tag, q, 4) != 0) {
				(void) strcat(buf, q);
				(void) strcat(buf, ";");
				need_to_clear_buf = 0;
			}
		} while (q = strtok(NULL, ";"));
		free(p);

		/* if we were the only option, clear the field */
		if (need_to_clear_buf) {
			(void) strcat(buf, "-");
		}

		if (cfg_put_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
			rdc_err(NULL, gettext("unable to clear autosync value "
			    "in config for Remote Mirror set %s:%s"), tohost,
			    tofile);
		} else {
			cfg_success = 1;
		}
	}

	/* autosync is not present in options field, add if on is requested */
	if (autosync_val == AUTOSYNC_ON) {
		if (cfg_put_options(cfg, CFG_SEC_CONF, key, auto_tag, "on")
		    < 0) {
			rdc_err(NULL, gettext("unable to update autosync value "
			    "in config for Remote Mirror set %s:%s"), tohost,
			    tofile);
		} else {
			cfg_success = 1;
		}
	}
	/* if we are in a group, update any other sets in the same group */
	do {
		bzero(&pair, sizeof (pair));
		bzero(buf, CFG_MAX_BUF);

		(void) snprintf(key, sizeof (key), "sndr.set%d", setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
			break;
		}
		if (parse_cfg_buf(buf, &pair, NULL))
			break;
		if (pair.group == NULL)	/* not in a group */
			break;
		if (!pair.group[0])
			break;			/* not in a group */
		for (set = 1; /*CSTYLED*/; set++) {
			if (set == setnumber)
				continue;
			bzero(buf, CFG_MAX_BUF);
			options = 0;
			already_set = 0;

			(void) snprintf(key, sizeof (key), "sndr.set%d", set);
			if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
				break;	/* last set processed */
			}
			bzero(&tmpair, sizeof (tmpair));
			if (parse_cfg_buf(buf, &tmpair, NULL))
				break;
			if (strcmp(pair.group, tmpair.group) != 0)
				continue; /* not the group we want */

			(void) snprintf(key, sizeof (key), "sndr.set%d.options",
				set);
			/*
			 * Check if there are any options already set,
			 * including ours
			 */
			if (cfg_get_options(cfg, CFG_SEC_CONF, key, tag,
				CFG_MAX_BUF, val, CFG_MAX_BUF) >= 0) {
				options = 1;

				do {
					if (strcmp(tag, auto_tag) == 0) {
						already_set = 1;
					}
				} while (cfg_get_options(cfg, CFG_SEC_CONF,
					NULL, tag, CFG_MAX_BUF, val,
					CFG_MAX_BUF) >= 0);
			}

			/* options already exist, edit ours out */
			if (options && already_set) {
				char *p, *q;
				int need_to_clear_buf = 1;

				if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF)
				    < 0) {
					rdc_err(NULL, gettext("unable to get "
					"options field for Remote Mirror set "
					"%s:%s"), tmpair.thost, tmpair.tfile);
				}

				/*
				 * parse out our options, all of the
				 * form "auto="
				 */
				p = strdup(buf);
				bzero(buf, sizeof (buf));

				q = strtok(p, ";");
				do {
					/*
					 * if another tag/value exists,
					 * keep it
					 */
					if (strncmp(auto_tag, q, 4) != 0) {
						(void) strcat(buf, q);
						(void) strcat(buf, ";");
						need_to_clear_buf = 0;
					}
				} while (q = strtok(NULL, ";"));
				free(p);

				/*
				 * if we were the only option,
				 * clear the field
				 */
				if (need_to_clear_buf) {
					(void) strcat(buf, "-");
				}

				if (cfg_put_cstring(cfg, key, buf, CFG_MAX_BUF)
					< 0) {
					rdc_err(NULL, gettext("unable to clear "
						"autosync value in config for "
						"Remote Mirror set %s:%s"),
						tmpair.thost, tmpair.tfile);
					cfg_success = 0;
				}
			}

			/*
			 * autosync is not present in options field,
			 * add if on is requested
			 */
			if (autosync_val == AUTOSYNC_ON) {
				if (cfg_put_options(cfg, CFG_SEC_CONF, key,
					auto_tag, "on") < 0) {
					rdc_err(NULL, gettext("unable to update"
					    " autosync value in config for "
					    "Remote Mirror set %s:%s"),
					    tmpair.thost,
					    tmpair.tfile);
					cfg_success = 0;
				}
			}
		}

	/* CONSTCOND */
	} while (0);
	if (cfg_success) {
		if (cfg_commit(cfg) < 0) {
		    rdc_err(NULL, gettext("commit on role reversal failed"));
		}
	}

	cfg_close(cfg);
}

/*
 * Check to see if autosync is on for set specified by tohost:tofile.
 *
 * ASSUMPTIONS:
 *      config is available to take a read lock against it.
 *
 * INPUTS:
 *      tohost - secondary host
 *      tofile - secondary volume
 *
 * OUTPUTS:
 *     -1 error
 *      AUTOSYNC_ON if autosync is on
 *      AUTOSYNC_OFF if autosync is off
 */
static int
autosync_is_on(char *tohost, char *tofile)
{
	CFGFILE *cfg;
	int setnumber, autosync_val = AUTOSYNC_OFF;
	char key[CFG_MAX_KEY];
	char tag[CFG_MAX_BUF], val[CFG_MAX_BUF];

	if ((cfg = cfg_open(NULL)) == NULL) {
		rdc_err(NULL, gettext("unable to access configuration"));
	}

	if (!cfg_lock(cfg, CFG_RDLOCK)) {
		cfg_close(cfg);
		rdc_err(NULL, gettext("unable to lock configuration"));
	}

	if ((setnumber = find_setnumber_in_libcfg(cfg, NULL, tohost, tofile)) <
	    0) {
		cfg_close(cfg);
		rdc_err(NULL, gettext("cannot find Remote Mirror set %s:%s in "
		    "config"), tohost, tofile);
	}

	(void) snprintf(key, CFG_MAX_KEY, "sndr.set%d.options", setnumber);
	if (cfg_get_options(cfg, CFG_SEC_CONF, key, tag, CFG_MAX_BUF, val,
	    CFG_MAX_BUF) >= 0) {
		do {
			if (strcmp(tag, "auto") == 0) {
				if (strcmp(val, "on") == 0) {
					autosync_val = AUTOSYNC_ON;
				}
				break;
			}
		} while (cfg_get_options(cfg, CFG_SEC_CONF, NULL, tag,
		    CFG_MAX_BUF, val, CFG_MAX_BUF) >= 0);
	}

	cfg_close(cfg);
	return (autosync_val);
}

void
enable_autosync(char *fhost, char *ffile, char *thost, char *tfile)
{
	rdc_config_t parms;
	spcs_s_info_t ustat;
	rdc_addr_t *p;

	ustat = spcs_s_ucreate();
	parms.command = RDC_CMD_TUNABLE;

	p = &parms.rdc_set[0].primary;
	(void) strncpy(p->intf, fhost, MAX_RDC_HOST_SIZE);
	(void) strncpy(p->file, ffile, MAX_RDC_HOST_SIZE);

	p = &parms.rdc_set[0].secondary;
	(void) strncpy(p->intf, thost, NSC_MAXPATH);
	(void) strncpy(p->file, tfile, NSC_MAXPATH);

	parms.rdc_set[0].autosync = 1;
	parms.rdc_set[0].maxqfbas = -1;
	parms.rdc_set[0].maxqitems = -1;
	parms.rdc_set[0].asyncthr = -1;
	parms.rdc_set[0].netconfig = NULL;

	if ((RDC_IOCTL(RDC_CONFIG, &parms, NULL, 0, 0, 0, ustat)) !=
	    SPCS_S_OK) {
		rdc_warn(&ustat, gettext("failed to update autosync for"
		    " Remote Mirror set %s:%s"), thost, tfile);
		spcs_log("sndr", &ustat, gettext("failed to update autosync for"
		    " Remote Mirror set %s:%s"), thost, tfile);
	}
	spcs_s_ufree(&ustat);
}

static int
rdc_operation(CFGFILE *cfg, char *fromhost, char *fromfile, char *frombitmap,
    char *tohost, char *tofile, char *tobitmap,
    int flag, int iflag,
    char *directfile, char *group, char *ctag, char *diskqueue,
    int *doasync, int reverse)
{
	const int getaddr = (flag == RDC_CMD_ENABLE);
	const int rpcbind = !getaddr;
	rdc_config_t parms;
	int ret;
	spcs_s_info_t ustatus;
	struct hostent *hp;
	char fromname[MAXHOSTNAMELEN], toname[MAXHOSTNAMELEN];
	char orig_fbmp[MAXHOSTNAMELEN], orig_tbmp[MAXHOSTNAMELEN];
	char orig_diskq[NSC_MAXPATH];
	struct t_info tinfo;
	int success = 1;
	int autosync_toggle_needed = 0;
	char *vol1, *vol2, *vol3;

	conf = &nconf;

	hp = gethost_byname(fromhost);
	(void) strncpy(fromname, hp->h_name, MAXHOSTNAMELEN);
	hp = gethost_byname(tohost);
	(void) strncpy(toname, hp->h_name, MAXHOSTNAMELEN);

	if (self_check(fromname) && self_check(toname)) {
		rdc_err(NULL, gettext("both %s and %s are local"),
		    fromhost, tohost);
	}

	/* we have to find out what to sv disable after reconfig */
	if (flag == RDC_CMD_RECONFIG) {

		parms.command = RDC_CMD_STATUS;
		parms.rdc_set->netconfig = NULL;
		(void) strncpy(parms.rdc_set->primary.intf, fromhost,
		    MAX_RDC_HOST_SIZE);
		(void) strncpy(parms.rdc_set->secondary.intf, tohost,
		    MAX_RDC_HOST_SIZE);
		(void) strncpy(parms.rdc_set->primary.file, fromfile,
		    NSC_MAXPATH);
		(void) strncpy(parms.rdc_set->secondary.file, tofile,
		    NSC_MAXPATH);
		ustatus = spcs_s_ucreate();
		ret = RDC_IOCTL(RDC_CONFIG, &parms,
		    NULL, 0, 0, 0, ustatus);
		if (ret != SPCS_S_OK) {
			rdc_err(NULL, gettext("unable to get set status"
			    " before reconfig operation"));
		}
		(void) strncpy(orig_fbmp, parms.rdc_set->primary.bitmap,
		    NSC_MAXPATH);
		(void) strncpy(orig_tbmp, parms.rdc_set->secondary.bitmap,
		    NSC_MAXPATH);
		(void) strncpy(orig_diskq, parms.rdc_set->disk_queue,
		    NSC_MAXPATH);
	}

	/*
	 * another terrible addition, if we are reconfigging mode
	 * and not logging, just give up.
	 */
	if ((reconfig_doasync != -1) &&
	    (!(parms.rdc_set->flags & RDC_LOGGING))) {
		rdc_err(NULL, gettext("cannot reconfigure sync/async, "
		    "Remote Mirror set not logging"));
		spcs_log("sndr", NULL, gettext("cannot reconfigure sync/async, "
		    "Remote Mirror set not logging"));
	}

	/*
	 * Now build up the address for each host including port and transport
	 */
	if (getaddr) {
		svp = get_addr(toname, RDC_PROGRAM, RDC_VERS_MIN,
			&conf, proto_test ? NC_UDP:NULL, "rdc", &tinfo,
			rpcbind);

		if (svp == NULL) {
			rdc_warn(NULL, gettext("unable to determine network "
			    "information for %s"), toname);
#ifdef DEBUG
			(void) printf("get_addr failed for Ver 4 %s\n", toname);
#endif
			return (-1);
		}
		svaddr = *svp;
	} else {
		bzero(&svaddr, sizeof (svaddr));
	}

	parms.rdc_set->secondary.addr.len = svaddr.len;
	parms.rdc_set->secondary.addr.maxlen =
					svaddr.maxlen;
	parms.rdc_set->secondary.addr.buf =
					(void *)svaddr.buf;

#ifdef DEBUG_ADDR
	(void) fprintf(stderr, "secondary buf %x len %d\n",
	    svaddr.buf, svaddr.len);

	for (i = 0; i < svaddr.len; i++)
		(void) printf("%u ", svaddr.buf[i]);
	(void) printf("\n");
#endif

	if (getaddr) {
		svp = get_addr(fromname, RDC_PROGRAM, RDC_VERS_MIN,
			&conf, proto_test ? NC_UDP: NULL, "rdc", &tinfo,
			rpcbind);
		if (svp == NULL) {
#ifdef DEBUG
			(void) printf("get_addr failed for Ver 4 %s\n",
				fromname);
#endif
			return (-1);
		}
		svaddr = *svp;
	}

	parms.rdc_set->primary.addr.len = svaddr.len;
	parms.rdc_set->primary.addr.maxlen = svaddr.maxlen;
	parms.rdc_set->primary.addr.buf = (void *)svaddr.buf;

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

	if (!self_check(fromname) && !self_check(toname)) {
		if (!clustered)
			rdc_err(NULL, gettext("neither %s nor %s is local"),
				fromhost, tohost);
		else {
		/*
		 * IF we could get a list of logical hosts on this cluster
		 * Then we could print something intelligent about where
		 * the volume is mastered. For now, just print some babble
		 * about the fact that we have no idea.
		 */
			rdc_err(NULL,
				gettext("either %s:%s or %s:%s is not local"),
					fromhost, fromfile, tohost, tofile);
		}
	}

	(void) strncpy(parms.rdc_set->primary.intf, fromhost,
	    MAX_RDC_HOST_SIZE);
	(void) strncpy(parms.rdc_set->primary.file, fromfile, NSC_MAXPATH);
	(void) strncpy(parms.rdc_set->primary.bitmap, frombitmap, NSC_MAXPATH);

	(void) strncpy(parms.rdc_set->secondary.intf, tohost,
	    MAX_RDC_HOST_SIZE);
	(void) strncpy(parms.rdc_set->secondary.file, tofile, NSC_MAXPATH);
	(void) strncpy(parms.rdc_set->secondary.bitmap, tobitmap, NSC_MAXPATH);

	if ((group == NULL) || ((strcmp(group, "-")) == 0))
		parms.rdc_set->group_name[0] = 0;
	else
		(void) strncpy(parms.rdc_set->group_name, group, NSC_MAXPATH);

	if (self_check(tohost) &&
	    (strlen(diskqueue) > 0) && (diskqueue[0] != '-'))
		if ((flag == RDC_CMD_ENABLE) || (flag == RDC_CMD_ADDQ))
			rdc_err(NULL, gettext("enabling disk queue on a Remote"
			    " Mirror secondary is not allowed (%s)"),
			    diskqueue);

	if ((diskqueue == NULL) || ((strcmp(diskqueue, "-")) == 0))
		parms.rdc_set->disk_queue[0] = 0;
	else
		(void) strncpy(parms.rdc_set->disk_queue, diskqueue,
		    NSC_MAXPATH);

	parms.rdc_set->maxqfbas = maxqfbas;
	parms.rdc_set->maxqitems = maxqitems;
	parms.rdc_set->asyncthr = asyncthr;
	/* set up the permanent set id for this set */
	if (flag == RDC_CMD_ENABLE) {
		char key[CFG_MAX_KEY];
		char setid[64];
		int set;
		parms.rdc_set->setid = get_new_cfg_setid(cfg);
		if (parms.rdc_set->setid <= 0) {
			rdc_err(NULL, gettext("unable to obtain unique set id "
			    "for %s:%s"), tohost, tofile);
		}
		if ((set = find_setnumber_in_libcfg(cfg, clustered? ctag : NULL,
		    tohost, tofile)) < 0) {
			rdc_err(NULL, gettext("unable to store unique set id"
			    " for %s:%s"), tohost, tofile);
		}
		(void) snprintf(key, sizeof (key), "sndr.set%d.options", set);
		(void) snprintf(setid, sizeof (setid), "%d",
		    parms.rdc_set->setid);

		if (cfg_put_options(cfg, CFG_SEC_CONF, key, "setid",
		    setid) < 0) {
			rdc_err(NULL, gettext("unable to store unique set "
			    "id for %s:%s: %s"), tohost, tofile,
			    gettext(cfg_error(NULL)));
		}
	} else if (flag != RDC_CMD_DISABLE) { /* set already gone from cfg */
		parms.rdc_set->setid = get_cfg_setid(cfg, ctag, tohost, tofile);
		if (parms.rdc_set->setid <= 0) {
			rdc_err(NULL, gettext("unable to obtain unique set id "
			    "for %s:%s"), tohost, tofile);
		}
	}

	/*
	 * Always set autosync flag to default so nothing gets messed up. If
	 * we are doing an autosync operation, it'll all get taken care of
	 * then.
	 */
	parms.rdc_set->autosync = AUTOSYNC;


	/* gethostid(3c) is defined to return a 32bit value */
	parms.rdc_set->syshostid = (int32_t)gethostid();

	parms.command = 0;
	parms.options = iflag;
	parms.command = flag;
	if (flag == RDC_CMD_ENABLE || flag == RDC_CMD_RECONFIG) {
		if (*doasync)
			parms.options |= RDC_OPT_ASYNC;
		else
			parms.options |= RDC_OPT_SYNC;
	} else if (flag == RDC_CMD_COPY) {
		if (reverse)
			parms.options |= RDC_OPT_REVERSE;
		else
			parms.options |= RDC_OPT_FORWARD;
	}

	if (self_check(fromname)) {
		if (flag == RDC_CMD_COPY && reverse && mounted(fromfile))
			rdc_err(NULL, gettext("can not start reverse sync"
			    " as a file system is mounted on %s"),
			    fromfile);
		parms.options |= RDC_OPT_PRIMARY;
		if (strcmp(directfile, "ip") == 0)
			parms.rdc_set->direct_file[0] = 0; /* no directfile */
		else
			(void) strncpy(parms.rdc_set->direct_file, directfile,
			    NSC_MAXPATH);
	} else {
		parms.options |= RDC_OPT_SECONDARY;
		parms.rdc_set->direct_file[0] = 0;	/* no fcal directio */
	}

	if ((asyncthr || maxqitems || maxqfbas || qblock) &&
	    (parms.options & RDC_OPT_SECONDARY)) {
		rdc_err(NULL, gettext("changing queue parameters may "
		    " only be done on a primary Remote Mirror host"));
		spcs_log("sndr", NULL, gettext("changing queue parameters may "
		    " only be done on a primary Remote Mirror host"));

	}

	ustatus = spcs_s_ucreate();

	if (flag == RDC_CMD_COPY) {
		parms.command = RDC_CMD_STATUS;
		ret = RDC_IOCTL(RDC_CONFIG, &parms, NULL, 0, 0, 0, ustatus);
		if ((ret != SPCS_S_OK) ||
		    !(parms.rdc_set->flags & RDC_LOGGING)) {
			rdc_err(NULL, gettext("can not start sync"
			    " as Remote Mirror set %s:%s is not logging"),
			    tohost, tofile);
		}
		spcs_log("sndr", NULL,
		    gettext("%s %s %s %s %s %s %s %s\nStarting"),
		    program, rdc_decode_flag(flag, parms.options),
		    fromhost, fromfile, frombitmap,
		    tohost, tofile, tobitmap);
		parms.command = RDC_CMD_COPY;
	}

	if ((flag == RDC_CMD_COPY) &&
	    (autosync_is_on(tohost, tofile) == AUTOSYNC_ON)) {
	/* check if autosync needs to be turned on when doing a copy/update */
		parms.rdc_set->autosync = AUTOSYNC_ON;
		autosync_toggle_needed = 1;
	} else if ((flag == RDC_CMD_LOG) &&
		(autosync_is_on(tohost, tofile) == AUTOSYNC_ON)) {
	/* check if autosync needs to be turned off when going to logging */
		parms.rdc_set->autosync = AUTOSYNC_OFF;
		autosync_toggle_needed = 1;
	} else if (((autosync == AUTOSYNC_ON) || (autosync == AUTOSYNC_OFF)) &&
	    (flag == RDC_CMD_TUNABLE)) {
		/*
		 * Request to change the autosync value. cfg file will be
		 * available at this point. If autosync request is to turn off,
		 * mark off in both the config and the kernel regardless of
		 * the state of the set. If the request is to turn autosync on,
		 * set in the kernel if the set is not in logging mode.
		 *
		 * XXX
		 *	If the set is in logging mode because of a network
		 *	failure, we will not know. Therefore, a manual update
		 *	will have to be issued to enable autosync in the
		 *	kernel.
		 * XXX
		 */
		set_autosync(autosync, tohost, tofile, ctag);

		if (autosync == AUTOSYNC_OFF) {
			parms.rdc_set->autosync = AUTOSYNC_OFF;
		} else if (autosync == AUTOSYNC_ON) {
			parms.command = RDC_CMD_STATUS;
			ret = RDC_IOCTL(RDC_CONFIG, &parms, NULL, 0, 0, 0,
			    ustatus);
			if (ret != SPCS_S_OK) {
				rdc_err(NULL, gettext("can not determine "
				    "status of Remote Mirror set %s:%s"),
				    tohost, tofile);
			}

			/* need to reset the tunables after a status ioctl */
			parms.rdc_set->autosync = autosync;
			parms.rdc_set->maxqfbas = maxqfbas;
			parms.rdc_set->maxqitems = maxqitems;
			parms.rdc_set->asyncthr = asyncthr;

			/*
			 * if in logging mode, just update config, kernel will
			 * be updated with the next copy/update request.
			 */
			if (parms.rdc_set->flags & RDC_LOGGING) {
				parms.rdc_set->autosync = AUTOSYNC;
			} else {
				parms.rdc_set->autosync = AUTOSYNC_ON;
			}

			parms.command = flag;
		}
	}

	if (autosync_toggle_needed) {
		parms.command = RDC_CMD_TUNABLE;
		ret = RDC_IOCTL(RDC_CONFIG, &parms, NULL, 0, 0, 0, ustatus);
		if (ret != SPCS_S_OK) {
			spcs_log("sndr", NULL, gettext("failed to update "
			    "autosync for Remote Mirror set %s:%s"), tohost,
			    tofile);
			rdc_err(NULL, gettext("failed to update autosync for "
			    "Remote Mirror set %s:%s"), tohost, tofile);
		}
		/* reset command and default autosync flags */
		parms.rdc_set->autosync = AUTOSYNC;
		parms.command = flag;
	}

	errno = 0;
	ret = RDC_IOCTL(RDC_CONFIG, &parms, NULL, 0, 0, 0, ustatus);
	if ((ret != SPCS_S_OK) && (flag != RDC_CMD_HEALTH)) {
		(void) fprintf(stderr,
			gettext("Remote Mirror: %s %s %s %s %s %s\n"),
			fromhost, fromfile,
			frombitmap, tohost, tofile, tobitmap);

		if (errno == RDC_EEINVAL) {
			spcs_log("sndr", NULL,
			    "%s %s %s %s %s %s %s %s\n%s",
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
			    "%s %s %s %s %s %s %s %s",
			    program, rdc_decode_flag(flag, parms.options),
			    fromhost, fromfile, frombitmap,
			    tohost, tofile, tobitmap);
			if ((flag == RDC_CMD_RECONFIG) &&
			    (!(iflag & RDC_OPT_REVERSE_ROLE))) {
				success = 0;
				rdc_warn(&ustatus, 0);
			} else
				rdc_err(&ustatus, 0);
		}
	}
	if ((flag == RDC_CMD_RECONFIG) && (iflag & RDC_OPT_REVERSE_ROLE) == 0) {
		parms.command = RDC_CMD_STATUS;
		if (RDC_IOCTL(RDC_CONFIG, &parms, NULL, 0, 0, 0, ustatus) ==
			SPCS_S_OK) {
			char shostbuf[CFG_MAX_BUF];
			char svolbuf[CFG_MAX_BUF];
			char key[CFG_MAX_KEY];
			int i, numels;
			int cfgsuccess = 1;

			/*
			 * okeydoke, at this point we could have a reconfig
			 * gone bad. libdscfg does not know about this.
			 * parms contains the kernel picture, and we know
			 * what we tried to reconfig. find out where it went
			 * wrong, find the set in libdscfg, update it. We'll
			 * issue a warning, then return 0 (eventually).
			 * this will allow libdscfg to be committed with the
			 * good info. got it?
			 * BTW: the only time we can run into this multiple
			 * reconfig attempt failure is IF we reconfig from file
			 * and some thing goes wrong with one of the reconfigs
			 */

			/* find the set in libdscfg */

			numels = cfg_get_num_entries(cfg, "sndr");
			/* yes, numels could be -1 */
			for (i = 1; i < numels; i++) {
				bzero(shostbuf, sizeof (shostbuf));
				bzero(svolbuf, sizeof (svolbuf));
				bzero(key, sizeof (key));

				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.shost", i);

				(void) cfg_get_cstring(cfg, key, &shostbuf,
				    sizeof (shostbuf));
				if (strncmp(shostbuf, tohost, sizeof (tohost)))
					continue;

				bzero(key, sizeof (key));
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.secondary", i);
				(void) cfg_get_cstring(cfg, key, &svolbuf,
				    sizeof (svolbuf));
				if (strncmp(svolbuf, tofile, NSC_MAXPATH))
					continue;
				break;

				/*
				 * found it, now i contains the set offset.
				 * i, being the variable, not bad english.
				 */

			}
			/* shouldn't happen */
			if ((numels < 1) || (i > numels)) {
				rdc_warn(NULL, gettext("unable to retrieve "
				    "set from configuration database"));
				/*
				 * yuck. but indents are pushing the envelope
				 * we should not be updating config
				 * if we did not find the entry
				 * the error will have to do
				 */
				cfgsuccess = 0;
				goto notfound;
			}

			/*
			 * now, put all the correct names back for errors etc.
			 * also, sock them into dscfg, if the the config was a
			 * success for one, it will be a redundant but harmless
			 */

			/*
			 * we could not have reconfigged mode if we
			 * are not logging, AND the kernel CAN return
			 * sync as the status of an async set if it is
			 * currently syncing.. Hence the flags & RDC_LOGGING
			 */
			if (parms.rdc_set->flags & RDC_LOGGING) {
				bzero(key, sizeof (key));
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.mode", i);
				if (parms.rdc_set->flags & RDC_ASYNC) {
					*doasync = 1;
					if (cfg_put_cstring(cfg, key, "async",
					    strlen("async")) < 0) {
						cfgsuccess = 0;
					}

				} else {
					*doasync = 0;
					if (cfg_put_cstring(cfg, key, "sync",
					    strlen("sync")) < 0) {
						cfgsuccess = 0;
					}
				}
			}
#ifdef _RDC_CAMPUS
			if (*parms.rdc_set->direct_file) {
				(void) strncpy(directfile,
				    parms.rdc_set->direct_file, NSC_MAXPATH);
				bzero(key, sizeof (key));
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.type", i);
				if (cfg_put_cstring(cfg, key, directfile,
				    strlen(directfile)) < 0)
					cfgsuccess = 0;
			} else {
				(void) strncpy(directfile, "-", NSC_MAXPATH);
				bzero(key, sizeof (key));
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.type", i);
				if (cfg_put_cstring(cfg, key, directfile,
				    strlen(directfile)) < 0)
					cfgsuccess = 0;
			}
#endif

			if (*parms.rdc_set->group_name) {
				(void) strncpy(group, parms.rdc_set->group_name,
				    NSC_MAXPATH);
				bzero(key, sizeof (key));
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.group", i);
				if (cfg_put_cstring(cfg, key, group,
				    strlen(group)) < 0)
					cfgsuccess = 0;

			} else {
				(void) strncpy(group, "-", NSC_MAXPATH);
				bzero(key, sizeof (key));
				(void) snprintf(key, sizeof (key),
				    "sndr.set%d.group", i);
				if (cfg_put_cstring(cfg, key, group,
				    strlen(group)) < 0)
					cfgsuccess = 0;
			}

			if (*parms.rdc_set->disk_queue) {
				(void) strncpy(diskqueue,
				    parms.rdc_set->disk_queue, NSC_MAXPATH);
			} else {
				(void) strncpy(diskqueue, "-", NSC_MAXPATH);
			}
			bzero(key, sizeof (key));
			(void) snprintf(key, sizeof (key),
			    "sndr.set%d.diskq", i);
			if (cfg_put_cstring(cfg, key, diskqueue,
			    strlen(diskqueue)) < 0)
				cfgsuccess = 0;

			(void) strncpy(frombitmap,
			    parms.rdc_set->primary.bitmap, NSC_MAXPATH);
			bzero(key, sizeof (key));
			(void) snprintf(key, sizeof (key),
			    "sndr.set%d.pbitmap", i);
			if (cfg_put_cstring(cfg, key, frombitmap,
			    strlen(frombitmap)) < 0)
				cfgsuccess = 0;

			(void) strncpy(tobitmap,
			    parms.rdc_set->secondary.bitmap, NSC_MAXPATH);
			bzero(key, sizeof (key));
			(void) snprintf(key, sizeof (key),
			    "sndr.set%d.sbitmap", i);
			if (cfg_put_cstring(cfg, key, tobitmap,
			    strlen(tobitmap)) < 0)
				cfgsuccess = 0;

			bzero(key, sizeof (key));
			(void) snprintf(key, sizeof (key),
			    "sndr.set%d.cnode", i);
			if (clustered)
				if (cfg_put_cstring(cfg, key, ctag,
				    strlen(ctag)) < 0)
					cfgsuccess = 0;
notfound:
			if (cfgsuccess == 0) {
				rdc_warn(NULL, gettext("unable to update "
				    "configuration storage"));
			}
		} else {
			spcs_log("sndr", NULL,
				"%s %s %s %s %s %s %s %s\n%s",
				program, rdc_decode_flag(flag, parms.options),
				fromhost, fromfile, frombitmap,
				tohost, tofile, tobitmap,
				gettext("unable to update config file"));
			rdc_err(&ustatus,
				gettext("Remote Mirror: unable to update "
				    "config file"));

		}
	}

	if (flag == RDC_CMD_HEALTH && errno == 0) {
		(void) fprintf(stderr,
			gettext("Remote Mirror: %s %s %s %s %s %s\n"),
			fromhost, fromfile,
			frombitmap, tohost, tofile, tobitmap);

		if (ret == RDC_ACTIVE)
			(void) fprintf(stderr, "Active\n");
		else if (ret == RDC_INACTIVE)
			(void) fprintf(stderr, "Inactive\n");
		else
			(void) fprintf(stderr, "Unknown\n");
	} else if (ret != SPCS_S_OK) {
		if (errno == RDC_EEINVAL) {
			spcs_log("sndr", NULL,
			    "%s %s %s %s %s %s %s %s\n%s",
			    program, rdc_decode_flag(flag, parms.options),
			    fromhost, fromfile, frombitmap,
			    tohost, tofile, tobitmap,
			    gettext("invalid command option"));
			rdc_err(&ustatus,
			    gettext("Remote Mirror: invalid command option "
				    "'%s'"),
			    rdc_decode_flag(flag, parms.options));
		}
	}
	if (flag == RDC_CMD_STATUS) {
		(void) fprintf(stderr,
			gettext("Remote Mirror: %s %s %s %s %s %s\n"),
			fromhost, fromfile,
			frombitmap, tohost, tofile, tobitmap);
		(void) fprintf(stderr, "flags 0x%x\n", parms.rdc_set->flags |
		    parms.rdc_set->sync_flags | parms.rdc_set->bmap_flags);
	} else if (success) {
		spcs_log("sndr", NULL,
		    gettext("%s %s %s %s %s %s %s %s\nSuccessful"),
		    program, rdc_decode_flag(flag, parms.options),
		    fromhost, fromfile, frombitmap,
		    tohost, tofile, tobitmap);
		if (flag == RDC_CMD_TUNABLE)
			spcslog_tunable(tohost, tofile);
	}

	if (cfg && perform_autosv()) {
		spcs_s_ufree(&ustatus);
		/* figure out which are the local volumes */
		if (parms.options & RDC_OPT_PRIMARY) {
			vol1 = fromfile;
			vol2 = frombitmap;
			if ((diskqueue && diskqueue[0]) &&
			    (strncmp(diskqueue, "-", 1) != 0))
				vol3 = diskqueue;
			else
				vol3 = NULL;
		} else {
			vol1 = tofile;
			vol2 = tobitmap;
			vol3 = NULL;
			if ((flag == RDC_CMD_ENABLE) &&
			    (strlen(diskqueue) > 0) &&
			    (strncmp(diskqueue, "-", 1)) != 0) {
				rdc_warn(NULL,
				    gettext("enabling a disk queue on a "
				    "Remote Mirror secondary is not allowed. "
				    "(%s) ignored"), diskqueue);
			}
		}

		if (flag == RDC_CMD_ENABLE) {
			ustatus = spcs_s_ucreate();
			/*
			 * SV-enable all local volumes
			 * if the sv_enables fail, disable the sndr vols
			 * that we just enabled
			 * and return -1 so the cfg_commit() won't happen
			 */

			if (nsc_lookup(volhash, vol1) == NULL) {
				if (cfg_vol_enable(cfg, vol1, ctag, "sndr")
				    < 0) {
					spcs_log("sndr", NULL,
					    "sv enable failed for %s, "
					    "disabling Remote Mirror set %s:%s",
					    vol1, tohost, tofile);
					/*
					 * warn here, but we are going to exit
					 * we want to catch any errors on the
					 * way down, then exit
					 */

					rdc_warn(NULL,
					    "unable to sv enable %s\n"
					    "disabling Remote Mirror set %s:%s",
					    vol1, tohost, tofile);

					parms.command = RDC_CMD_DISABLE;
					ret = RDC_IOCTL(RDC_CONFIG, &parms,
					    NULL, 0, 0, 0, ustatus);
					if (ret != SPCS_S_OK) {
						(void) fprintf(stderr,
						    gettext("Remote Mirror:"
						    " %s %s %s %s %s %s\n"),
						    fromhost, fromfile,
						    frombitmap, tohost, tofile,
						    tobitmap);
						spcs_log("sndr", &ustatus,
						"%s %s %s %s %s %s %s %s",
						program,
						rdc_decode_flag(parms.command,
						parms.options),
						fromhost,
						fromfile, frombitmap,
						tohost, tofile, tobitmap);
						rdc_err(&ustatus, 0);
					}
					/*
					 * ok, we should've reported any errs
					 * exit explictly
					 */
					exit(1);

				}
			}
			if (vol2 && nsc_lookup(volhash, vol2) == NULL) {
				if (cfg_vol_enable(cfg, vol2, ctag, "sndr")
				    < 0) {
					spcs_log("sndr", NULL,
					    "sv enable failed for %s, "
					    "disabling Remote Mirror set %s:%s",
					    vol1, tohost, tofile);
					/*
					 * warn here, but we are going to exit
					 * we want to catch any errors on the
					 * way down, then exit
					 */

					rdc_warn(NULL,
					    "unable to sv enable %s\n"
					    "disabling Remote Mirror set %s:%s",
					    vol2, tohost, tofile);

					parms.command = RDC_CMD_DISABLE;
					ret = RDC_IOCTL(RDC_CONFIG, &parms,
					    NULL, 0, 0, 0, ustatus);
					if (ret != SPCS_S_OK) {
						(void) fprintf(stderr,
						    gettext("Remote Mirror:"
						    " %s %s %s %s %s %s\n"),
						    fromhost, fromfile,
						    frombitmap, tohost, tofile,
						    tobitmap);
						spcs_log("sndr", &ustatus,
						"%s %s %s %s %s %s %s %s",
						program,
						rdc_decode_flag(parms.command,
						parms.options),
						fromhost,
						fromfile, frombitmap,
						tohost, tofile, tobitmap);
						rdc_err(&ustatus, 0);
					}
					/*
					 * ok, we should've reported any errs
					 * exit explictly
					 */
					exit(1);

				}
			}

			if (vol3 && nsc_lookup(volhash, diskqueue) == NULL) {
				if (cfg_vol_enable(cfg, diskqueue, ctag, "sndr")
				    < 0) {
					spcs_log("sndr", NULL,
					    "sv enable failed for %s, "
					    "disabling Remote Mirror set %s:%s",
					    diskqueue, tohost, tofile);
					if (cfg_vol_disable(cfg, vol1, ctag,
						"sndr") < 0)
					    rdc_warn(NULL, gettext("Failed to "
					    "remove volume [%s] from "
					    "configuration"), vol1);
					if (cfg_vol_disable(cfg, vol2, ctag,
						"sndr") < 0)
					    rdc_warn(NULL, gettext("Failed to "
					    "remove volume [%s] from "
					    "configuration"), vol2);

					/*
					 * warn here, but we are going to exit
					 * we want to catch any errors on the
					 * way down, then exit
					 */

					rdc_warn(NULL,
					    "unable to sv enable %s\n"
					    "disabling Remote Mirror set %s:%s",
					    diskqueue, tohost, tofile);

					parms.command = RDC_CMD_DISABLE;
					ret = RDC_IOCTL(RDC_CONFIG, &parms,
					    NULL, 0, 0, 0, ustatus);
					if (ret != SPCS_S_OK) {
						(void) fprintf(stderr,
						    gettext("Remote Mirror:"
						    " %s %s %s %s %s %s\n"),
						    fromhost, fromfile,
						    frombitmap, tohost, tofile,
						    tobitmap);
						spcs_log("sndr", &ustatus,
						"%s %s %s %s %s %s %s %s",
						program,
						rdc_decode_flag(parms.command,
						parms.options),
						fromhost,
						fromfile, frombitmap,
						tohost, tofile, tobitmap);
						rdc_err(&ustatus, 0);
					}
					/*
					 * ok, we should've reported any errs
					 * exit explictly
					 */
					exit(1);

				}
			}
		} else if (flag == RDC_CMD_DISABLE) {
			/*
			 * If we're no longer using a volume, SV-disable it
			 */
			volcount_t *vc;

			vc = nsc_lookup(volhash, vol1);
			if (vc && (1 == vc->count)) {
				if (cfg_vol_disable(cfg, vol1, ctag, "sndr")
				    < 0)
					rdc_warn(NULL, gettext("Failed to "
					    "remove volume [%s] from "
					    "configuration"), vol1);

			} else if (!vc) {
				rdc_warn(NULL,
				    gettext("Unable to find %s in config"),
				    vol1);
			}

			if (vol2) {
				vc = nsc_lookup(volhash, vol2);
				if (vc && (1 == vc->count)) {
					if (cfg_vol_disable(cfg, vol2, ctag,
						"sndr") < 0)
					rdc_warn(NULL, gettext("Failed to "
					    "remove volume [%s] from "
					    "configuration"), vol2);
				} else if (!vc) {
					rdc_warn(NULL, gettext("Unable to find"
					    " %s in config"), vol2);
				}
			}

			if (diskqueue != NULL && strlen(diskqueue) > 0) {
				vc = nsc_lookup(volhash, diskqueue);
				if (vc && (1 == vc->count)) {
				if (cfg_vol_disable(cfg, diskqueue, ctag,
					"sndr") < 0)
					rdc_warn(NULL, gettext("Failed to "
					    "remove disk queue [%s] from "
					    "configuration"), diskqueue);
				} else if (!vc) {
					rdc_warn(NULL, gettext("Unable to find"
					    " %s in config"), diskqueue);
				}
			}
		/* WARNING about to go to 4 space indenting */
		} else if (flag == RDC_CMD_RECONFIG) {
			volcount_t *vc;
			/* disable ex-bitmaps, enable new bitmaps */
			if (parms.options & RDC_OPT_PRIMARY) {
			    if (strcmp(orig_fbmp, frombitmap) != 0) {
				vc = nsc_lookup(volhash, orig_fbmp);
				if (vc && (vc->count == 1)) {
				    if (cfg_vol_disable(cfg, orig_fbmp, ctag,
					"sndr") < 0)
					rdc_warn(NULL, gettext("Failed to "
					    "remove bitmap [%s] from "
					    "configuration"), orig_fbmp);
				} else if (!vc) {
				    rdc_warn(NULL, gettext("Unable to find "
				    "%s in config"), orig_fbmp);
				}
				if (nsc_lookup(volhash, frombitmap) == NULL) {
				    if (cfg_vol_enable(cfg, frombitmap, ctag,
					"sndr") < 0) {
					spcs_log("sndr", NULL,
					    "reconfig sv enable failed for %s, "
					    "disabling Remote Mirror set %s:%s",
					    frombitmap, tohost, tofile);
					rdc_warn(NULL,
					    "unable to sv enable %s\n"
					    "disabling Remote Mirror set %s:%s",
					    frombitmap, tohost, tofile);
					parms.command = RDC_CMD_DISABLE;
					ret = RDC_IOCTL(RDC_CONFIG, &parms,
					    NULL, 0, 0, 0, ustatus);
					if (ret != SPCS_S_OK) {
					    (void) fprintf(stderr,
						gettext("Remote Mirror:"
						" %s %s %s %s %s %s\n"),
						fromhost, fromfile,
						frombitmap, tohost, tofile,
						tobitmap);
					    spcs_log("sndr", &ustatus,
						"%s %s %s %s %s %s %s %s",
						program,
						rdc_decode_flag(parms.command,
						parms.options),
						fromhost,
						fromfile, frombitmap,
						tohost, tofile, tobitmap);
						rdc_warn(&ustatus, 0);
					}
					exit(1);
				    }
				}
			    } else if ((orig_diskq[0] != '\0') &&
					(strcmp(orig_diskq, diskqueue) != 0)) {
				vc = nsc_lookup(volhash, orig_diskq);
				if (vc && (vc->count == 1)) {
				    if (cfg_vol_disable(cfg, orig_diskq, ctag,
					"sndr") < 0)
					rdc_warn(NULL, gettext("Failed to "
					    "remove disk queue [%s] from "
					    "configuration"), orig_diskq);
				} else if (!vc) {
				    rdc_warn(NULL, gettext("Unable to find "
					"%s in config"), orig_diskq);
				}
				if (vol3 &&
				    (nsc_lookup(volhash, diskqueue) == NULL)) {
				    if (cfg_vol_enable(cfg, diskqueue, ctag,
					"sndr") < 0) {
					spcs_log("sndr", NULL, "reconfig sv "
					    "enable of diskqueue %s failed, "
					    "disabling Remote Mirror set %s:%s",
					    diskqueue, tohost, tofile);
					rdc_warn(NULL, "reconfig sv "
					    "enable of diskqueue %s failed."
					    "disabling Remote Mirror set %s:%s",
					    diskqueue, tohost, tofile);
					parms.command = RDC_CMD_DISABLE;
					ret = RDC_IOCTL(RDC_CONFIG, &parms,
					    NULL, 0, 0, 0, ustatus);
					if (ret != SPCS_S_OK) {
					    (void) fprintf(stderr,
						gettext("Remote Mirror:"
						" %s %s %s %s %s %s\n"),
						fromhost, fromfile,
						frombitmap, tohost, tofile,
						tobitmap);
					    spcs_log("sndr", &ustatus,
						"%s %s %s %s %s %s %s %s",
						program,
						rdc_decode_flag(parms.command,
						parms.options),
						fromhost,
						fromfile, frombitmap,
						tohost, tofile, tobitmap);
						rdc_warn(&ustatus, 0);
					}
					exit(1);
				    }
				}
			    }
			} else if (flag != RDC_OPT_PRIMARY) {
			    if (strcmp(orig_tbmp, tobitmap) != 0) {
				vc = nsc_lookup(volhash, orig_tbmp);
				if (vc && (vc->count == 1)) {
				    if (cfg_vol_disable(cfg, orig_tbmp, ctag,
					"sndr") < 0)
					rdc_warn(NULL, gettext("Failed to "
					    "remove bitmap [%s] from "
					    "configuration"), orig_tbmp);
				} else if (!vc) {
				    rdc_warn(NULL,
				    gettext("Unable to find %s in config"),
				    orig_tbmp);
				}
				if (nsc_lookup(volhash, tobitmap) == NULL) {
				    if (cfg_vol_enable(cfg, tobitmap, ctag,
					"sndr") < 0) {
					spcs_log("sndr", NULL,
					    "reconfig sv enable failed for %s, "
					"disabling Remote Mirror set %s:%s",
					tobitmap, tohost, tofile);
					rdc_warn(NULL,
					    "unable to sv enable %s\n"
					    "disabling Remote Mirror set %s:%s",
					    tobitmap, tohost, tofile);
					parms.command = RDC_CMD_DISABLE;
					ret = RDC_IOCTL(RDC_CONFIG, &parms,
					    NULL, 0, 0, 0, ustatus);
					if (ret != SPCS_S_OK) {
					    (void) fprintf(stderr,
						gettext("Remote Mirror:"
						" %s %s %s %s %s %s\n"),
						fromhost, fromfile,
						frombitmap, tohost, tofile,
						tobitmap);
					    spcs_log("sndr", &ustatus,
						"%s %s %s %s %s %s %s %s",
						program,
						rdc_decode_flag(parms.command,
						parms.options),
						fromhost, fromfile, frombitmap,
						tohost, tofile, tobitmap);
						rdc_warn(&ustatus, 0);
					}
					exit(1);
				    }
				}
			    }
			}
		/* END 4 space indenting */
		}
	}
	spcs_s_ufree(&ustatus);

	return (0);
}


/*
 * read_config()
 *
 * DESCRIPTION: Read the lines in a configuration file and return the
 *		pairs of devices to be mirrored/enabled/disabled/updated.
 *		The format for the configuration file is as follows:
 *
 *		fromhost fromfile frombitmap tohost tofile tobitmap
 *
 *		where fromfile is the primary device which is local to the
 *		fromhost subsystem, tofile is the secondary device which is
 *		local to the tohost subsystem, and type is 1 if the device
 *		a simckd device or 0 otherwise.  Any line preceeded by a '#'
 *		is considered to be a comment.
 *
 * Inputs:
 *	char *config_file	Name of configuration file for rdcadm
 *
 * Outputs:
 *	int i			Number of pairs of devices
 *
 * Side Effects: The 0 to i-1 entries in the pair_list are filled.
 *
 */

int
read_config(int flag, char *config_file, char *group_arg, char *ctag_arg)
{
	int ret;
	char dsk_flagstr[NSC_MAXPATH];
	char line[1024], tmp_line[1024];
	char fromhost[MAX_RDC_HOST_SIZE];
	char fromfile[NSC_MAXPATH];
	char frombitmap[NSC_MAXPATH];
	char tohost[MAX_RDC_HOST_SIZE];
	char tofile[NSC_MAXPATH];
	char tobitmap[NSC_MAXPATH];
	char directfile[NSC_MAXPATH];
	char sync[16];
	int doasync;
	FILE *fp;
	int i, j;
	char *extra_args[EXTRA_ARGS];
	char *tmp, *split_str = " \t\n";

	for (j = 0; j < EXTRA_ARGS; j++)
		extra_args[j] = malloc(NSC_MAXPATH);

	if (!(fp = fopen(config_file, "r"))) {
		rdc_err(NULL, gettext("error opening %s"), config_file);
	}

	i = 0;
	while (fgets(line, sizeof (line), fp)) {
		if (line[0] == '#')  /* this is a comment */
			continue;

		ret = 0;
		(void) strcpy(tmp_line, line);

		if ((tmp = strtok(tmp_line, split_str)) != NULL) {
			if (strlen(tmp) >= MAX_RDC_HOST_SIZE) {
			    (void) printf(gettext("hostname is longer than %d "
				"characters\n"), (MAX_RDC_HOST_SIZE - 1));
			    continue;
			}
			(void) strncpy(fromhost, tmp, (MAX_RDC_HOST_SIZE - 1));
			fromhost[(MAX_RDC_HOST_SIZE - 1)] = '\0';
			ret++;
		}
		if ((tmp = strtok(NULL, split_str)) != NULL) {
			if (strlen(tmp) >= NSC_MAXPATH) {
			    (void) printf(gettext(
				"device name is longer than %d "
				"characters\n"), (NSC_MAXPATH - 1));
			    continue;
			}
			(void) strncpy(fromfile, tmp, (NSC_MAXPATH - 1));
			fromfile[(NSC_MAXPATH - 1)] = '\0';
			ret++;
		}
		if ((tmp = strtok(NULL, split_str)) != NULL) {
			if (strlen(tmp) >= NSC_MAXPATH) {
			    (void) printf(gettext(
				"device name is longer than %d "
				"characters\n"), (NSC_MAXPATH - 1));
			    continue;
			}
			(void) strncpy(frombitmap, tmp, (NSC_MAXPATH - 1));
			frombitmap[(NSC_MAXPATH - 1)] = '\0';
			ret++;
		}
		if ((tmp = strtok(NULL, split_str)) != NULL) {
			if (strlen(tmp) >= MAX_RDC_HOST_SIZE) {
			    (void) printf(gettext(
				"hostname is longer than %d "
				"characters\n"), (MAX_RDC_HOST_SIZE - 1));
			    continue;
			}
			(void) strncpy(tohost, tmp, (MAX_RDC_HOST_SIZE - 1));
			tohost[(MAX_RDC_HOST_SIZE - 1)] = '\0';
			ret++;
		}
		if ((tmp = strtok(NULL, split_str)) != NULL) {
			if (strlen(tmp) >= NSC_MAXPATH) {
			    (void) printf(gettext(
				"device name is longer than %d "
				"characters\n"), (NSC_MAXPATH - 1));
			    continue;
			}
			(void) strncpy(tofile, tmp, (NSC_MAXPATH - 1));
			tofile[(NSC_MAXPATH - 1)] = '\0';
			ret++;
		}
		if ((tmp = strtok(NULL, split_str)) != NULL) {
			if (strlen(tmp) >= NSC_MAXPATH) {
			    (void) printf(gettext(
				"device name is longer than %d "
				"characters\n"), (NSC_MAXPATH - 1));
			    continue;
			}
			(void) strncpy(tobitmap, tmp, (NSC_MAXPATH - 1));
			tobitmap[(NSC_MAXPATH - 1)] = '\0';
			ret++;
		}
		if ((tmp = strtok(NULL, split_str)) != NULL) {
			(void) strncpy(dsk_flagstr, tmp, 15);
			dsk_flagstr[15] = '\0';
			ret++;
		}
		if ((tmp = strtok(NULL, split_str)) != NULL) {
			(void) strncpy(sync, tmp, 15);
			sync[15] = '\0';
			ret++;
		}
		for (j = 0; j < EXTRA_ARGS; j++) {
			if ((tmp = strtok(NULL, split_str)) != NULL) {
				(void) strncpy(extra_args[j], tmp,
				    (NSC_MAXPATH - 1));
				extra_args[j][(NSC_MAXPATH - 1)] = '\0';
				ret++;
			}
		}

		if (ret == 0) /* this is a blank line */
			continue;

		if (ret < 8) {
			(void) fclose(fp);
			rdc_warn(NULL,
			    gettext("invalid format in %s"), config_file);
			rdc_err(NULL, "%s", line);
		}

		if (i >= rdc_maxsets) {
			(void) fclose(fp);
			rdc_err(NULL,
			    gettext("number of Remote Mirror sets exceeds %d"),
			    rdc_maxsets);
		}

#ifdef _RDC_CAMPUS
		if (dsk_flagstr[0] == '/') {
			/* fcal directio */
			(void) strncpy(directfile, dsk_flagstr, NSC_MAXPATH);
		} else if (strcmp(dsk_flagstr, "ip") != 0) {
#else
		if (strcmp(dsk_flagstr, "ip") != 0) {
#endif
			(void) fclose(fp);
			rdc_err(NULL,
#ifdef _RDC_CAMPUS
			    gettext("ip/fcal specification missing"));
#else
			    gettext("ip specification missing"));
#endif
		} else
			(void) strcpy(directfile, "ip");

		if (strcmp(sync, "sync") == 0)
			doasync = 0;
		else if (strcmp(sync, "async") == 0)
			doasync = 1;
		else {
			(void) fclose(fp);
			rdc_err(NULL,
			    gettext("sync/async specification missing"));
		}
		(void) strncpy(pair_list[i].fhost, fromhost, MAX_RDC_HOST_SIZE);
		(void) strncpy(pair_list[i].ffile, fromfile, NSC_MAXPATH);
		(void) strncpy(pair_list[i].fbitmap, frombitmap, NSC_MAXPATH);
		(void) strncpy(pair_list[i].thost, tohost, MAX_RDC_HOST_SIZE);
		(void) strncpy(pair_list[i].tfile, tofile, NSC_MAXPATH);
		(void) strncpy(pair_list[i].tbitmap, tobitmap, NSC_MAXPATH);
		(void) strncpy(pair_list[i].directfile, directfile,
		    NSC_MAXPATH);
		pair_list[i].doasync = doasync;

		if (gethost_netaddrs(fromhost, tohost,
		    (char *)pair_list[i].fnetaddr,
		    (char *)pair_list[i].tnetaddr) < 0) {
			(void) fclose(fp);
			rdc_err(NULL, gettext("unable to determine IP "
			    "addresses for hosts %s, %s"), fromhost, tohost);
		}

		if (parse_extras(ret - 8, extra_args, i) < 0) {
			(void) fclose(fp);
			rdc_err(NULL, gettext("illegal option in:\n%s"),
			    line);
		}

		if (flag == RDC_CMD_ENABLE || flag == RDC_CMD_RECONFIG) {
			if (ctag_check(fromhost, fromfile, frombitmap,
			    tohost, tofile, tobitmap, pair_list[i].ctag,
			    pair_list[i].diskqueue) < 0)
				continue; /* Ignore illegal sets */
			if (pair_diskqueue_check(i))
				continue; /* ignore sets with incorrect diskq */
		}

		/* Filter according to ctag and group arguments */
		if (strcmp(ctag_arg, "") &&
		    strncmp(ctag_arg, pair_list[i].ctag,
		    MAX_RDC_HOST_SIZE))
			continue;
		if (strcmp(group_arg, "") &&
		    strncmp(group_arg, pair_list[i].group, NSC_MAXPATH))
			continue;

		i++;
	}
	(void) fclose(fp);
	for (j = 0; j < EXTRA_ARGS; j++)
		free(extra_args[j]);
	return (i);
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
read_libcfg(int flag, char *group_arg, char *ctag_arg)
{
	int rc;
	CFGFILE *cfg;
	int i;
	_sd_dual_pair_t *pairp;
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	int setnumber;

	if ((cfg = cfg_open(NULL)) == NULL)
		rdc_err(NULL, gettext("unable to access configuration"));

	if (!cfg_lock(cfg, CFG_RDLOCK))
		rdc_err(NULL, gettext("unable to lock configuration"));

	if (strcmp(ctag_arg, ""))
		cfg_resource(cfg, ctag_arg);
	else {
		cfg_resource(cfg, NULL);
	}

	setnumber = 0;
	/*CSTYLED*/
	for (i = 0; i < rdc_maxsets;) {
		setnumber++;

		bzero(buf, CFG_MAX_BUF);
		(void) snprintf(key, sizeof (key), "sndr.set%d", setnumber);
		rc = cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF);
		if (rc < 0)
			break;

		pairp = &pair_list[i];
		if (parse_cfg_buf(buf, pairp, NULL))
			continue;

		if (strcmp(group_arg, "") &&
		    strncmp(group_arg, pairp->group, NSC_MAXPATH))
			    continue;

		if (flag == RDC_CMD_RECONFIG) {
			if (reconfig_pbitmap)
				(void) strncpy(pairp->fbitmap, reconfig_pbitmap,
				    NSC_MAXPATH);
			if (reconfig_sbitmap)
				(void) strncpy(pairp->tbitmap, reconfig_sbitmap,
				    NSC_MAXPATH);
#ifdef _RDC_CAMPUS
			if (reconfig_direct)
				(void) strncpy(directfile, reconfig_direct,
				    NSC_MAXPATH);
#endif
			if (reconfig_group)
				(void) strncpy(pairp->group, reconfig_group,
				    NSC_MAXPATH);

			if (strlen(reconfig_ctag) > 0)
				(void) strncpy(pairp->ctag, reconfig_ctag,
				    MAX_RDC_HOST_SIZE);

			if (reconfig_doasync != -1)
				pairp->doasync = reconfig_doasync;
		}


		if (ctag_check(pairp->fhost, pairp->ffile,
		    pairp->fbitmap, pairp->thost, pairp->tfile,
		    pairp->tbitmap, pairp->ctag, pairp->diskqueue) < 0)
			continue; /* Ignore illegal sets */

		if (gethost_netaddrs(pairp->fhost, pairp->thost,
		    (char *)pairp->fnetaddr,
		    (char *)pairp->tnetaddr) < 0) {
			rdc_err(NULL, gettext("unable to determine IP "
			    "addresses for hosts %s, %s"), pairp->fhost,
			    pairp->thost);
		}

		i++;
	}

	cfg_close(cfg);
	return (i);
}

void
q_usage(int prhdr)
{
	if (prhdr)
		(void) fprintf(stderr, gettext("disk queue usage:\n"));

	(void) fprintf(stderr,
	    gettext("\t%s -g <group> -q a <vol>\t\tadd disk queue to "
	    "group\n"), program);
	(void) fprintf(stderr,
	    gettext("\t%s -g <group> -q d \t\tremove disk queue from"
	    " group\n"), program);
	(void) fprintf(stderr,
	    gettext("\t%s -g <group> -q r <newvol>\treplace disk queue for a"
	    " group\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s -q a <vol> <shost>:<sdev>\tadd disk queue to "
	    "a set\n"), program);
	(void) fprintf(stderr,
	    gettext("\t%s -q d <shost>:<sdev>\t\tremove disk queue from "
	    "a set\n"), program);
	(void) fprintf(stderr,
	    gettext("\t%s -q r <newvol> <shost>:<sdev>\treplace disk queue for "
	    "a set\n"), program);

}

static void
usage()
{
	(void) fprintf(stderr, gettext("usage:\n"));

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -a {on | off} [set]\t"
	    "set autosync\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -A <asyncthr> [set]\t"
	    "set the number of asynchronous\n\t\t\t\t\t\tthreads\n"),
	    program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -d [set]\t\t\t"
	    "disable\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -e [set]\t\t\t"
	    "enable with bits in bitmap set\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -E [set]\t\t\t"
	    "enable with bits in bitmap clear\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -F <maxqfbas> [set]\t"
	    "set maximum fbas to queue\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -D {block | noblock} [set]\t"
	    "set disk queue blocking mode\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -H [set]\t\t\t"
	    "report link health\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s -h\t\t\t\tusage message\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s -I a <master> <shadow> <bitmap>\t"
	    "add ndr_ii config entry\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s -I d <master> <shadow> <bitmap>\t"
	    "delete ndr_ii config entry\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -i [set]\t\t\t"
	    "print sets in config file format\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -l [set]\t\t\t"
	    "enter logging mode\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -m [set]\t\t\t"
	    "full sync\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -m -r [set]\t\t"
	    "full reverse sync\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -P [set]\t\t\t"
	    "print sets verbose\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -p [set]\t\t\t"
	    "print sets\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -R\t\t\t"
	    "reset error conditions\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -R b p <bitmap> [set]\t"
	    "reconfig primary bitmap\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -R b s <bitmap> [set]\t"
	    "reconfig secondary bitmap\n"), program);

	if (clustered)
		(void) fprintf(stderr,
		    gettext("\t%s [opts] -R C <ctag> [set]\t"
		    "reconfig cluster tag\n"), program);

#ifdef _RDC_CAMPUS
	(void) fprintf(stderr,
	    gettext("\t%s [opts] -R d <pathname> [set]\t"
	    "reconfig campus direct file\n"), program);
#endif

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -R -f <volset-file> \t"
	    "reconfig from file\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -R g <group> [set]\t"
	    "reconfig group\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -R m {sync|async} [set]\t"
	    "reconfig mode\n"), program);

	if (allow_role)
		(void) fprintf(stderr,
		    gettext("\t%s [opts] -R r [set]\t\t"
		    "reverse roles\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -u [set]\t\t\t"
	    "update sync\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -u -r [set]\t\t"
	    "update reverse sync\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s -v\t\t\t\tdisplay version\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -W <maxwrites> [set]\t"
	    "set maximum writes to queue\n"), program);

	(void) fprintf(stderr,
	    gettext("\t%s [opts] -w [set]\t\t\t"
	    "wait\n"), program);
	q_usage(0);

	(void) fprintf(stderr, gettext("\nopts:\n"));
	(void) fprintf(stderr, gettext("\t-n\t\tnon-interactive mode "
	    "(not valid for print operations)\n"));
	(void) fprintf(stderr, gettext(
	    "\t-g <group>\toperate on sets in group only "
	    "(not valid for enable\n\t\t\toperations)\n"));
	if (clustered)
		(void) fprintf(stderr,
			gettext("\t-C <ctag>\tignore sets not in cluster ctag "
		"(not valid for enable\n\t\t\toperations)\n"));

	(void) fprintf(stderr, gettext("\nset:\n"));
	if (clustered)
		(void) fprintf(stderr,
		    gettext("\t<phost> <pdev> <pbmp> "
#ifdef _RDC_CAMPUS
		    "<shost> <sdev> <sbmp> {ip | <directfile>} "
#else
		    "<shost> <sdev> <sbmp> ip "
#endif
		    "\\\n\t\t{sync | async} [g <group>] [q <qdev>] "
		    "[C <ctag>]\n"));
	else
		(void) fprintf(stderr,
		    gettext("\t<phost> <pdev> <pbmp> "
#ifdef _RDC_CAMPUS
		    "<shost> <sdev> <sbmp> {ip | <directfile>} "
#else
		    "<shost> <sdev> <sbmp> ip "
#endif
		    "\\\n\t\t{sync | async} [g <group>] [q <qdev>]\n"));
	(void) fprintf(stderr,
	    gettext("\t<shost>:<sdev>\t\t"
	    "operate on set matching shost and sdev\n"));
	(void) fprintf(stderr,
	    gettext("\t-f volset-file\t\t"
	    "operate on all sets specified in config file\n"
	    "\t\t\t\tnote: not valid for single set operations. See\n"
	    "\t\t\t\t%s(1RDC).\n"), program);
	(void) fprintf(stderr,
	    gettext("\t<no arg>\t\toperate on all configured sets\n"));
}

int
prompt_user(int flag, int options)
{
	int c;

	switch (flag) {
	case RDC_CMD_DISABLE:
		(void) printf(gettext("Disable Remote Mirror? (Y/N) [N]: "));
		break;
	case RDC_CMD_ENABLE:
		(void) printf(gettext("Enable Remote Mirror? (Y/N) [N]: "));
		break;
	case RDC_CMD_HEALTH:
		(void) printf(gettext("Report Remote Mirror link health? (Y/N)"
		    "[N]: "));
		break;
	case RDC_CMD_COPY:
		if (options & RDC_OPT_FULL) {
			if (options & RDC_OPT_REVERSE)
				(void) printf(gettext("Overwrite primary with"
				    " secondary? (Y/N) [N]: "));
			else
				(void) printf(gettext("Overwrite secondary with"
				    " primary? (Y/N) [N]: "));
		} else {
			if (options & RDC_OPT_REVERSE)
				(void) printf(gettext("Refresh primary with"
				    " secondary? (Y/N) [N]: "));
			else
				(void) printf(gettext("Refresh secondary with"
				    " primary? (Y/N) [N]: "));
		}
		break;
	case RDC_CMD_RECONFIG:
		(void) printf(gettext(
		    "Perform Remote Mirror reconfiguration? (Y/N) [N]: "));
		break;
	case RDC_CMD_RESET:
		(void) printf(gettext("Perform Remote Mirror reset? (Y/N) "
		    "[N]: "));
		break;
	case RDC_CMD_TUNABLE:
		(void) printf(gettext("Change Remote Mirror tunable? (Y/N) "
		    "[N]: "));
		break;
	case RDC_CMD_LOG:
		(void) printf(gettext(
		    "Put Remote Mirror into logging mode? (Y/N) [N]: "));
		break;
	case RDC_CMD_WAIT:
		(void) printf(gettext(
		    "Wait for Remote Mirror sync completion? (Y/N) [N]: "));
		break;
	default:
		(void) printf(gettext("Perform Remote Mirror operation? (Y/N) "
		    "[N]: "));
	}

	c = getchar();
	if ((c != 'y') && (c != 'Y')) {
		(void) printf("\n");
		return (-1);
	}
	return (0);
}

static void
load_rdc_vols(CFGFILE *cfg)
{
	int set;
	char key[ CFG_MAX_KEY ];
	char buf[ CFG_MAX_BUF ];
	_sd_dual_pair_t pair;
	char *vol, *bmp;
	char *host1 = pair.fhost, *host2 = pair.thost;
	char *diskqueue = pair.diskqueue;
	volcount_t *volcount;
	char lghn[ MAX_RDC_HOST_SIZE ];

	if (volhash) {
		return;
	}

	cfg_rewind(cfg, CFG_SEC_CONF);
	volhash = nsc_create_hash();
	for (set = 1; /*CSTYLED*/; set++) {
		(void) snprintf(key, CFG_MAX_KEY, "sndr.set%d", set);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF)) {
			break;
		}

		if (parse_cfg_buf(buf, &pair, lghn))
			continue;
		vol = pair.ffile;
		bmp = pair.fbitmap;

		/* use lghn if possible */
		if (*lghn) {
			if (strcmp(host2, lghn) == 0) {
				vol = pair.tfile;
				bmp = pair.tbitmap;
			}
		} else if (!self_check(host1)) {
			/* next one had better be ours */
			vol = pair.tfile;
			bmp = pair.tbitmap;

			if (!self_check(host2)) {
				rdc_warn(NULL,
				    gettext("config error: neither %s nor %s"
				    " is localhost"), host1, host2);
				continue;
			}
		}

		/* primary vol may be used more than once */
		volcount = (volcount_t *)nsc_lookup(volhash, vol);
		if (volcount) {
			volcount->count++;
		} else {
			volcount = (volcount_t *)malloc(sizeof (volcount_t));
			volcount->count = 1;
			(void) nsc_insert_node(volhash, volcount, vol);
		}

		/* bitmap ought to be only used once */
		volcount = (volcount_t *)nsc_lookup(volhash, bmp);
		if (volcount) {
			/* argh */
			volcount->count++;
		} else {
			volcount = (volcount_t *)malloc(sizeof (volcount_t));
			volcount->count = 1;
			(void) nsc_insert_node(volhash, volcount, bmp);
		}

		if (strcmp(diskqueue, place_holder) == 0)
			continue;
		/* diskqueue vol may be used more than once */
		volcount = (volcount_t *)nsc_lookup(volhash, diskqueue);
		if (volcount) {
			volcount->count++;
		} else {
			volcount = (volcount_t *)malloc(sizeof (volcount_t));
			volcount->count = 1;
			(void) nsc_insert_node(volhash, volcount, diskqueue);
		}
	}
}

static void
unload_rdc_vols()
{
	nsc_remove_all(volhash, free);
	volhash = 0;
}

static int
perform_autosv()
{
	if (!clustered) {
		return (1);
	} else {
		return (cfg_issuncluster());
	}
}

/*
 * Check the user supplied fields against those in the dscfg for
 * this set.
 * Never returns on an error.
 */
static void
checkgfields(CFGFILE *cfg, int setnumber, char *fromhost, char *fromfile,
    char *frombitmap, char *tobitmap, char *type, char *mode, char *group,
    char *ctag, char *diskq)
{
	if (fromhost[0])
		checkgfield(cfg, setnumber, "phost",
		    gettext("primary host"), fromhost);
	if (fromfile[0])
		checkgfield(cfg, setnumber, "primary",
		    gettext("primary volume"), fromfile);
	if (frombitmap[0])
		checkgfield(cfg, setnumber, "pbitmap",
		    gettext("primary bitmap"), frombitmap);
	if (tobitmap[0])
		checkgfield(cfg, setnumber, "sbitmap",
		    gettext("secondary bitmap"), tobitmap);
	if (type[0])
		checkgfield(cfg, setnumber, "type",
		    gettext("type of connection"), type);
	if (mode[0])
		checkgfield(cfg, setnumber, "mode",
		    gettext("mode of connection"), mode);
	if (group[0])
		checkgfield(cfg, setnumber, "group",
		    gettext("group"), group);
	if (ctag[0])
		checkgfield(cfg, setnumber, "cnode",
		    gettext("cluster tag"), ctag);
	if (diskq[0])
		checkgfield(cfg, setnumber, "diskq",
		    gettext("disk queue volume"), diskq);
}

/*
 * Check the 'fname' field in the dscfg file for set number 'setnumber'
 * If it does not match the user's data, 'data', then print the error
 * message using the friendly field name 'ufield'.
 * Never returns on an error.
 */
static void
checkgfield(CFGFILE *cfg, int setnumber, char *fname, char *ufield, char *data)
{
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];

	(void) snprintf(key, sizeof (key), "sndr.set%d.%s", setnumber, fname);
	if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
		rdc_err(NULL, gettext("unable to fetch data for key %s"),
		    key);
	}
	if (strcmp(buf, data) != 0) {
		rdc_err(NULL,
		    gettext("the value specified for the %s field is not\nthe "
		    "same as that contained within the configuration storage "
		    "file for this set.\nYou specified \"%s\" "
		    "expected \"%s\"."),
		    ufield, data, buf);
	}
}

/*
 * load and send the contents of the bitmap file to the kernel.
 */
static int
rdc_bitmapset(char *tohost, char *tofile, char *bitmap, int op,
    nsc_off_t offset)
{
	rdc_bitmap_op_t bmop;
	int fd;
	void *buffer;
	int buffersz;
	struct stat s;
	int n;
	int ret;
	/*
	 * open bitmap file for reading.
	 */
	if ((fd = open(bitmap, O_RDONLY)) < 0) {
		rdc_warn(NULL, gettext("Unable to open bitmap file %s"),
		    bitmap);
		return (1);
	}
	(void) fstat(fd, &s);

	if (S_ISREG(s.st_mode) == 0) {
		rdc_warn(NULL, gettext("Bitmap %s is not a regular file"),
		    bitmap);
		(void) close(fd);
		return (1);
	}

	if (op == 0) {
		op = RDC_BITMAPOR;
	}
	/*
	 * use the file size to allocate buffer. This
	 * size should be a multiple of FBA, but don't check
	 * it here.
	 */
	buffersz = s.st_size;
	buffer = malloc(buffersz);
	if (buffer == NULL) {
		rdc_warn(NULL, gettext("Unable to allocate %d bytes "
		    "for bitmap file %s"), buffersz, bitmap);
		(void) close(fd);
		return (1);
	}
	n = read(fd, buffer, buffersz);
	(void) close(fd);
	if (n != buffersz) {
		rdc_warn(NULL, gettext("Unable to read the bitmap file, "
		    "read returned %d instead of %d"),
		    n, buffersz);
		free(buffer);
		return (1);
	}
	bmop.offset = offset;
	bmop.op = op;
	(void) strncpy(bmop.sechost, tohost, MAX_RDC_HOST_SIZE);
	(void) strncpy(bmop.secfile, tofile, NSC_MAXPATH);
	bmop.len = buffersz;
	bmop.addr = (unsigned long)buffer;
	ret = rdc_ioctl_simple(RDC_BITMAPOP, &bmop);
	free(buffer);
	if (ret < 0) {
		rdc_warn(NULL, gettext("Setting bitmap ioctl failed for set "
		    "%s:%s"), tohost, tofile);

		switch (errno) {
		case EIO:
			rdc_warn(NULL, gettext("One of the sets is not "
			    "enabled"));
			break;
		case ENXIO:
			rdc_warn(NULL, gettext("One of the sets is not "
			    "logging"));
			break;
		default:
			break;
		}
	} else {
		ret = 0;
	}
	if (ret)
		ret = 1;
	return (ret);
}

/*
 * verify_groupname: Check the group name for the following rules:
 *	1. The name does not start with a '-'
 *	2. The name does not contain any space characters as defined by
 *	   isspace(3C).
 *
 * If either of these rules are broken, error immediately.
 */
static void
verify_groupname(char *grp)
{
	int i;

	if (grp[0] == '-') {
		rdc_err(NULL, gettext("group name cannot start with a '-'"));
	}

	for (i = 0; grp[i] != '\0'; i++) {
		if (isspace(grp[i])) {
			rdc_err(NULL, gettext("group name cannot contain a "
			    "space"));
		}
	}
}
