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
#include <stdio.h>
#include <sys/mnttab.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>

#include <locale.h>
#include <langinfo.h>
#include <libintl.h>
#include <stdarg.h>
#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/rdc_ioctl.h>
#include <sys/nsctl/rdc_prot.h>

#include <sys/nsctl/cfg.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_errors.h>

#include "rdcadm.h"


int maxqfbas = MAXQFBAS;
int maxqitems = MAXQITEMS;
int autosync = AUTOSYNC;
int asyncthr = ASYNCTHR;
int qblock = QBLOCK;

int
mounted(char *device)
{
	char target[NSC_MAXPATH];
	struct mnttab mntref;
	struct mnttab mntent;
	FILE *mntfp;
	int rdsk;
	char *s;
	int i;

	rdsk = i = 0;
	for (s = target; i < NSC_MAXPATH && (*s = *device++); i++) {
		if (*s == 'r' && rdsk == 0 && strncmp(device, "dsk/", 4) == 0)
			rdsk = 1;
		else
			s++;
	}
	*s = '\0';

	mntref.mnt_special = target;
	mntref.mnt_mountp = NULL;
	mntref.mnt_fstype = NULL;
	mntref.mnt_mntopts = NULL;
	mntref.mnt_time = NULL;

	mntfp = fopen(MNTTAB, "r");

	if (mntfp == NULL) {
		rdc_warn(NULL,
			gettext("can not check volume %s against mount table"),
			mntref.mnt_special);
		/* Assume the worst, that it is mounted */
		return (1);
	}

	if (getmntany(mntfp, &mntent, &mntref) != -1) {
		/* found something before EOF */
		(void) fclose(mntfp);
		return (1);
	}

	(void) fclose(mntfp);
	return (0);
}


/* Needs to match parsing code in rdcboot.c and rdcadm.c */
char *
rdc_decode_flag(int flag, int options)
{
	static char str[32];

	switch (flag) {
	case (RDC_CMD_COPY):
		if (options & RDC_OPT_FULL)
			strcpy(str, "-m");
		else
			strcpy(str, "-u");
		if (options & RDC_OPT_REVERSE)
			strcat(str, " -r");
		break;

	case (RDC_CMD_DISABLE):
		strcpy(str, "-d");
		break;

	case (RDC_CMD_ENABLE):
		if (options & RDC_OPT_SETBMP)
			strcpy(str, "-e");
		else
			strcpy(str, "-E");
		break;

	case (RDC_CMD_LOG):
		strcpy(str, "-l");
		break;

	case (RDC_CMD_HEALTH):
		strcpy(str, "-H");
		break;

	case (RDC_CMD_WAIT):
		strcpy(str, "-w");
		break;

	case (RDC_CMD_RECONFIG):
		strcpy(str, "-R ...");
		break;

	case (RDC_CMD_TUNABLE):
		strcpy(str, "");
		if (maxqfbas != MAXQFBAS)
			strcat(str, " -F");
		if (maxqitems != MAXQITEMS)
			strcat(str, " -W");
		if (autosync != AUTOSYNC)
			strcat(str, " -a");
		if (asyncthr != ASYNCTHR)
			strcat(str, " -A");
		if (qblock != QBLOCK)
			strcat(str, " -D");
		break;

	case (RDC_CMD_SUSPEND):
		strcpy(str, "-s");
		break;

	case (RDC_CMD_RESUME):
		strcpy(str, "-r");
		break;

	case (RDC_CMD_RESET):
		strcpy(str, "-R");
		break;

	case (RDC_CMD_ADDQ):
		strcpy(str, "-q a");
		break;

	case (RDC_CMD_REMQ):
		strcpy(str, "-q d");
		break;

	case (RDC_CMD_REPQ):
		strcpy(str, "-q r");
		break;

	default:
		strcpy(str, gettext("unknown"));
		break;
	}

	return (str);
}


static void
rdc_msg(char *prefix, spcs_s_info_t *status, char *string, va_list ap)
{
	if (status) {
		(void) fprintf(stderr, "Remote Mirror: %s\n", prefix);
		spcs_s_report(*status, stderr);
	} else {
		(void) fprintf(stderr, "%s: %s: ", program, prefix);
	}

	if (string && *string != '\0') {
		(void) vfprintf(stderr, string, ap);
	}

	(void) fprintf(stderr, "\n");
}

void
rdc_err(spcs_s_info_t *status, char *string, ...)
{
	va_list ap;
	va_start(ap, string);

	rdc_msg(gettext("Error"), status, string, ap);

	va_end(ap);
	exit(1);
}

void
rdc_warn(spcs_s_info_t *status, char *string, ...)
{
	va_list ap;
	va_start(ap, string);

	rdc_msg(gettext("warning"), status, string, ap);

	va_end(ap);
}

int
rdc_get_maxsets(void)
{
	rdc_status_t rdc_status;
	spcs_s_info_t ustatus;
	int rc;

	rdc_status.nset = 0;
	ustatus = spcs_s_ucreate();

	rc = RDC_IOCTL(RDC_STATUS, &rdc_status, 0, 0, 0, 0, ustatus);
	if (rc == SPCS_S_ERROR) {
		rdc_err(&ustatus, gettext("statistics error"));
	}

	spcs_s_ufree(&ustatus);
	return (rdc_status.maxsets);
}

/*
 * Look up a set in libcfg to find the setnumber.
 *
 * ASSUMPTIONS:
 *      - a valid cfg handle
 *
 * INPUTS:
 *      cfg - cfg handle
 *      tohost - secondary hostname
 *      tofile - secondary volume
 *
 * OUTPUTS:
 *      set number if found, otherwise -1 for an error
 */
int
find_setnumber_in_libcfg(CFGFILE *cfg, char *ctag, char *tohost, char *tofile)
{
	int setnumber;
	int entries, rc;
	char *buf, *secondary, *shost;
	char **entry;
	char *cnode;
	int offset = 0;

	if (cfg == NULL) {
#ifdef DEBUG
		rdc_warn(NULL, "cfg is NULL while looking up set number");
#endif
		return (-1);
	}

	entries = cfg_get_section(cfg, &entry, "sndr");

	rc = -1;
	for (setnumber = 1; setnumber <= entries; setnumber++) {
		buf = entry[setnumber - 1];

		(void) strtok(buf, " ");	/* phost */
		(void) strtok(NULL, " ");	/* primary */
		(void) strtok(NULL, " ");	/* pbitmap */
		shost = strtok(NULL, " ");
		secondary = strtok(NULL, " ");

		if (ctag && *ctag) {
			(void) strtok(NULL, " ");	/* sbitmap */
			(void) strtok(NULL, " ");	/* type */
			(void) strtok(NULL, " ");	/* mode */
			(void) strtok(NULL, " ");	/* group */
			cnode = strtok(NULL, " ");

			if (ctag && strcmp(cnode, ctag) != 0) {
				/* filter this out */
				++offset;
				continue;
			}
		}

		/* Check secondary volume name first, will get less hits */
		if (strcmp(secondary, tofile) != 0) {
			free(buf);
			continue;
		}

		if (strcmp(shost, tohost) == 0) {
			free(buf);
			rc = setnumber - offset;
			break;
		}

		free(buf);
	}

	while (setnumber < entries)
		free(entry[setnumber++]);
	if (entries)
		free(entry);

	return (rc);
}

void
get_group_diskq(CFGFILE *cfg, char *group, char *diskq)
{
	int i;
	char key[CFG_MAX_KEY];
	char buf[CFG_MAX_BUF];

	if (*group == '\0')
		return;
	for (i = 1; ; i++) {
		bzero(&key, sizeof (key));
		bzero(&buf, sizeof (buf));
		(void) sprintf(key, "sndr.set%d.group", i);
		if (cfg_get_cstring(cfg, key, &buf, sizeof (buf)) < 0)
			break;
		if (strncmp(group, buf, sizeof (buf)) == 0) {
			(void) sprintf(key, "sndr.set%d.diskq", i);
			if (cfg_get_cstring(cfg, key, diskq, CFG_MAX_BUF) < 0) {
				rdc_warn(NULL, gettext("unable to retrieve "
				    "group %s's disk queue"), group);
			}
		}
	}
}

int
get_cfg_setid(CFGFILE *cfg, char *ctag, char *tohost, char *tofile)
{
	int setnum = 0;
	int close_cfg = 0;
	char key[CFG_MAX_KEY];
	char setid[64];

	if (cfg == NULL) {
		close_cfg = 1;
		if ((cfg = cfg_open(NULL)) == NULL) {
			return (-1); /* message printed by caller */
		}
		if (!cfg_lock(cfg, CFG_RDLOCK)) {
			cfg_close(cfg);
			return (-1);
		}
	}
	setnum = find_setnumber_in_libcfg(cfg, ctag, tohost, tofile);
	if (setnum < 0)
		return (setnum);

	(void) snprintf(key, CFG_MAX_KEY, "sndr.set%d.options", setnum);
	if (cfg_get_single_option(cfg, CFG_SEC_CONF, key, "setid",
		    setid, sizeof (setid)) < 0) {
		if (close_cfg)
			cfg_close(cfg);

		spcs_log("sndr", NULL,
		    gettext("%s unable to get unique setid "
		    "for %s:%s"), program, tohost, tofile);
		return (-1);

	}
	if (close_cfg)
		cfg_close(cfg);

	return (atoi(setid));

}

int
get_new_cfg_setid(CFGFILE *cfg)
{
	int setid;
	char buf[CFG_MAX_BUF];
	char *ctag;

	/* If in a Sun Cluster, SetIDs need to have a ctag */
	if ((ctag = cfg_get_resource(cfg)) != NULL) {
		ctag = strdup(ctag);
		cfg_resource(cfg, "setid-ctag");
	}

	if (cfg_get_cstring(cfg, "setid.set1.value", buf, CFG_MAX_BUF) < 0) {
		setid = 1;
		if (cfg_put_cstring(cfg, "setid", "1", CFG_MAX_BUF) < 0) {
			rdc_err(NULL, "Unable to store new setid");
		}
	} else {
		setid = atoi(buf);
		setid++;
		if (setid <= 0) {
			setid = 1;
		}
	}

	bzero(&buf, CFG_MAX_BUF);
	(void) snprintf(buf, sizeof (buf), "%d", setid);
	if (cfg_put_cstring(cfg, "setid.set1.value", buf, CFG_MAX_BUF) < 0) {
		rdc_err(NULL, "Unable to store new setid");
	}

	/* Restore old ctag if in a Sun Cluster */
	if (ctag) {
		cfg_resource(cfg, ctag);
		free(ctag);
	}

	return (setid);
}

sigset_t origmask;

void
block_sigs(void)
{
	sigset_t allsigs;

	sigfillset(&allsigs);
	if (sigprocmask(SIG_BLOCK, &allsigs, &origmask) < 0)
		rdc_warn(NULL, gettext("Unable to block signals"));
}

void
unblock_sigs(void)
{
	if (sigprocmask(SIG_SETMASK, &origmask, NULL) < 0)
		rdc_warn(NULL, gettext("Unable to unblock signals"));

}
