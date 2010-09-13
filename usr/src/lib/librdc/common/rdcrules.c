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
#include <sys/utsname.h>
#include <sys/mdb_modapi.h>
#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <libintl.h>
#include <sys/stream.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <thread.h>
#include <pthread.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_s_impl.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/rdc_ioctl.h>
#include <sys/nsctl/rdc_prot.h>
#include <sys/nsctl/librdc.h>
#include <sys/nsctl/rdcerr.h>
#include <sys/nsctl/cfg.h>

#include <sys/unistat/spcs_dtrinkets.h>
#include <sys/unistat/spcs_etrinkets.h>

#include <sys/socket.h>
#include <sys/mnttab.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <rpc/rpc_com.h>
#include <rpc/rpc.h>

#define	RDC_LOCAL_TAG	"local"

/*
 * bitmap_in_use
 * return 1 if in use
 * return 0 if not in use
 * return -1 on error
 */

int
bitmap_in_use(int cmd, char *hostp, char *bmp)
{
	int i, setnumber;
	CFGFILE *cfg;
	char host[CFG_MAX_BUF];
	char shost[CFG_MAX_BUF];
	char pri[CFG_MAX_BUF]; /* rdc primary vol */
	char sec[CFG_MAX_BUF]; /* rdc secondary vol */
	char sbm[CFG_MAX_BUF]; /* rdc secondary bitmap */
	char bit[CFG_MAX_BUF]; /* a bitmap */
	char mas[CFG_MAX_BUF]; /* II master */
	char sha[CFG_MAX_BUF]; /* II shadow */
	char mod[CFG_MAX_BUF]; /* II mode */
	char ovr[CFG_MAX_BUF]; /* II overflow */
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	int rc;
	int ret = 0;


	if ((cfg = cfg_open(NULL)) == NULL) {
		rdc_set_error(NULL, RDC_DSCFG, 0, NULL);
		return (-1);
	}
	if (!cfg_lock(cfg, CFG_RDLOCK)) {
		rdc_set_error(NULL, RDC_DSCFG, 0, NULL);
		cfg_close(cfg);
		return (-1);
	}

	/*
	 * look into II config to see if this is being used elsewhere
	 */
	/*CSTYLED*/
	for (i = 0; ; i++) {
		setnumber = i + 1;
		snprintf(key, sizeof (key), "ii.set%d", setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;

		rc = sscanf(buf, "%s %s %s %s %s", mas, sha, bit, mod, ovr);
		if (rc != 5) {
			rdc_set_error(NULL, RDC_OS, 0, NULL);
			    ret = -1;
			    goto done;
		}

		/*
		 * got master shadow bitmap, now compare
		 */
		if ((strcmp(bmp, mas) == 0) ||
		    (strcmp(bmp, sha) == 0) ||
		    (strcmp(bmp, bit) == 0) ||
		    (strcmp(bmp, ovr) == 0)) {
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
			    "bitmap %s is in use by"
			    "Point-in-Time Copy", bmp);
			ret = 1;
			goto done;
		}
	}
	/*
	 * and last but not least, make sure sndr is not using vol for anything
	 */
	/*CSTYLED*/
	for (i = 0; ; i++) {
		setnumber = i + 1;
		snprintf(key, sizeof (key), "sndr.set%d", setnumber);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0)
			break;
		/*
		 * I think this is quicker than
		 * having to double dip into the config
		 */
		(void) sscanf(buf, "%s %s %s %s %s %s", host, pri, bit,
		    shost, sec, sbm);
		if (cmd == RDC_CMD_ENABLE) {
			if (self_check(host)) {
				if ((strcmp(bmp, pri) == 0) ||
				    (strcmp(bmp, bit) == 0)) {
					rdc_set_error(NULL, RDC_INTERNAL,
					    RDC_NONFATAL, dgettext("librdc",
					    "bitmap %s is in use by %s"),
					    bmp, RDC_NAME_DU_JOUR);


				    ret = 1;
				    goto done;
				}
			} else {
				if ((strcmp(bmp, sec) == 0) ||
				    (strcmp(bmp, sbm) == 0)) {
					rdc_set_error(NULL, RDC_INTERNAL,
					    RDC_NONFATAL, dgettext("librdc",
					    "bitmap %s is in use by %s"),
					    bmp, RDC_NAME_DU_JOUR);
				    ret = 1;
				    goto done;
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
					    (strcmp(bmp, bit) == 0)) {
						rdc_set_error(NULL,
						    RDC_INTERNAL, RDC_NONFATAL,
						    dgettext("librdc", "bitmap"
						    " %s is in use by %s"),
						    bmp, RDC_NAME_DU_JOUR);
						ret = 1;
						goto done;
					}
				} else {
					if ((strcmp(hostp, shost) == 0) &&
					    (strcmp(bmp, sec) == 0) ||
					    (strcmp(bmp, sbm) == 0)) {
						rdc_set_error(NULL,
						    RDC_INTERNAL, RDC_NONFATAL,
						    dgettext("librdc", "bitmap"
						    " %s is in use by %s"),
						    bmp, RDC_NAME_DU_JOUR);
						ret = 1;
						goto done;
					}
				}
			} else { /* self_check(hostp) failed */
				if (self_check(host)) {
					if ((strcmp(shost, hostp) == 0) &&
					    (strcmp(bmp, sec) == 0) ||
					    (strcmp(bmp, sbm) == 0)) {
						rdc_set_error(NULL,
						    RDC_INTERNAL, RDC_NONFATAL,
						    dgettext("librdc", "bitmap"
						    " %s is in use by %s"),
						    bmp, RDC_NAME_DU_JOUR);
						ret = 1;
						goto done;
					}
				} else {
					if ((strcmp(host, hostp) == 0) &&
					    (strcmp(bmp, pri) == 0) ||
					    (strcmp(bmp, bit) == 0)) {
						rdc_set_error(NULL,
						    RDC_INTERNAL, RDC_NONFATAL,
						    dgettext("librdc", "bitmap"
						    " %s is in use by %s"),
						    bmp, RDC_NAME_DU_JOUR);
						ret = 1;
						goto done;
					}
				}
			}

		}

	}
done:
	cfg_close(cfg);
	return (ret);

}

int
check_dgislocal(char *dgname)
{
	char *othernode;
	int rc;

	/*
	 * check where this disk service is mastered
	 */

	rc = cfg_dgname_islocal(dgname, &othernode);
	if (rc < 0) {
		rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
		    gettext("unable to find "
		    "disk service, %s: %s"), dgname, strerror(errno));
		    return (-1);
	}

	if (rc == 0) {
		rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
		    gettext("disk service, %s, is "
		    "active on node \"%s\"\nPlease re-issue "
		    "the command on that node"), dgname, othernode);
		    return (-1);
	}
	return (DCMD_OK);
}

int
ctag_check(rdcconfig_t *rdc)
{
	char *file_dgname;
	char *bmp_dgname;
	char *fromhost, *tohost;
	char *fromfile, *tofile;
	char *frombitmap, *tobitmap;
	char *localfile;
	char *ctag;
	char file_buf[MAX_RDC_HOST_SIZE];
	char bmp_buf[MAX_RDC_HOST_SIZE];
	int is_primary;
	int islocal = 0;
	struct hostent *hp;
	char fromname[MAXHOSTNAMELEN], toname[MAXHOSTNAMELEN];

	fromhost = rdc->phost;
	fromfile = rdc->pfile;
	frombitmap = rdc->pbmp;
	tohost = rdc->shost;
	tofile = rdc->sfile;
	tobitmap = rdc->sbmp;
	ctag = rdc->ctag;

	/*
	 * Check for the special (local) cluster tag
	 */
	if (!cfg_iscluster())
		return (0);

	if (ctag != NULL && strcmp(rdc->ctag, RDC_LOCAL_TAG) == 0) {
		strcpy(rdc->ctag, "-");
		islocal = TRUE;
	} else {
		islocal = FALSE;
	}

	hp = gethost_byname(fromhost);
	strncpy(fromname, hp->h_name, MAXHOSTNAMELEN);
	hp = gethost_byname(tohost);
	strncpy(toname, hp->h_name, MAXHOSTNAMELEN);
	if (!self_check(fromname) && !self_check(toname)) {
		/*
		 * If we could get a list of logical hosts on this cluster
		 * then we could print something intelligent about where
		 * the volume is mastered. For now, just print some babble
		 * about the fact that we have no idea.
		 */
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
				gettext("either %s:%s or %s:%s is not local"),
					fromhost, fromfile, tohost, tofile);
			return (-1);
	}

	is_primary = self_check(fromname);

	/*
	 * If implicit disk group name and no ctag specified by user,
	 * we set the ctag to it.
	 * If implicit disk group name, it must match any supplied ctag.
	 */
	if (is_primary)
		localfile = fromfile;
	else
		localfile = tofile;
	file_dgname = cfg_dgname(localfile, file_buf, sizeof (file_buf));
	if (file_dgname != NULL && file_dgname[0] != '\0')
		if (check_dgislocal(file_dgname) < 0) {
			/* errors already set */
			return (-1);
		}

	if (strlen(ctag) == 0 && file_dgname && strlen(file_dgname))
		strncpy(ctag, file_dgname, MAX_RDC_HOST_SIZE);

	/*
	 * making an exception here for users giving the "local"tag
	 * this overrides this error message. (rdc_islocal ! = 1)
	 */
	if (strlen(ctag) != 0 && file_dgname && islocal != 1 &&
	    strlen(file_dgname) != 0 &&
	    strncmp(ctag, file_dgname, MAX_RDC_HOST_SIZE) != 0) {
		rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
		    gettext("ctag \"%s\" does not "
		    "match disk group name \"%s\" of volume %s"), ctag,
		    file_dgname, localfile);
		return (-1);
	}
	if ((file_dgname == NULL) || ((strlen(ctag) == 0) &&
	    (strlen(file_dgname) == 0))) {
		/*
		 * we must have a non-volume managed disk here
		 * so ask for a tag and get out
		 */
		rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
		    gettext("volume \"%s\" is not part"
		    " of a disk group,\nplease specify resource ctag\n"),
		    localfile);

	}

	/*
	 * Local bitmap must also have same ctag.
	 */
	if (is_primary)
		localfile = frombitmap;
	else
		localfile = tobitmap;
	bmp_dgname = cfg_dgname(localfile, bmp_buf, sizeof (bmp_buf));
	if (bmp_dgname != NULL && bmp_dgname[0] != '\0')
		if (check_dgislocal(bmp_dgname) < 0) {
			/* error already set */
			return (-1);
		}

	if (file_dgname && strlen(file_dgname) != 0) {
		/* File is in a real disk group */
		if ((bmp_dgname == NULL) || (strlen(bmp_dgname) == 0)) {
			/* Bitmap is not in a real disk group */
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
			    gettext("bitmap %s is not in disk group \"%s\""),
			    localfile, islocal < 1?file_dgname:ctag);
			return (-1);
		}
	}
	if (strlen(ctag) != 0 && bmp_dgname && islocal != 1 &&
	    strlen(bmp_dgname) != 0 &&
	    strncmp(ctag, bmp_dgname, MAX_RDC_HOST_SIZE) != 0) {
		rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
		    gettext("ctag \"%s\" does not "
		    "match disk group name \"%s\" of bitmap %s"),
		    ctag, bmp_dgname, localfile);
		return (-1);
	}

	return (0);
}
int
mounted(char *device)
{
	char target[NSC_MAXPATH];
	struct mnttab mntref;
	struct mnttab mntent;
	FILE *mntfp;
	int rdsk;
	char *s;
	int rc;
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
		/* Assume the worst, that it is mounted */
		return (1);
	}

	if ((rc = getmntany(mntfp, &mntent, &mntref)) != -1) {
		/* found something before EOF */
		fclose(mntfp);
		return (1);
	}

	fclose(mntfp);
	return (0);
}

int
can_enable(rdcconfig_t *rdc)
{
	struct stat stb;

	if ((strcmp(rdc->pfile, rdc->pbmp) == 0) ||
	    (strcmp(rdc->sfile, rdc->sbmp) == 0)) {
		rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
		dgettext("librdc", "volumes and bitmaps must not match"));
		return (0);
	}
	if (ctag_check(rdc) < 0) {
		/* rdc_error should already be set */
		return (0);
	}

	if (self_check(rdc->phost)) {
		if (stat(rdc->pfile, &stb) != 0) {
			rdc_set_error(NULL, RDC_OS, RDC_FATAL, NULL);
			return (0);
		}
		if (!S_ISCHR(stb.st_mode)) {
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
			    dgettext("librdc", "%s is not a character device"),
			    rdc->pfile);
			return (0);
		}
		return (rdc->persist ?
		    !bitmap_in_use(RDC_CMD_ENABLE, rdc->phost, rdc->pbmp) : 1);
	} else { /* on the secondary */
		if (stat(rdc->sfile, &stb) != 0) {
			rdc_set_error(NULL, RDC_OS, 0,
			    dgettext("librdc", "unable to access %s: %s"),
			    rdc->sfile, strerror(errno));
		}
		if (!S_ISCHR(stb.st_mode)) {
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
			    dgettext("librdc",
			    "%s is not a character device"), rdc->sfile);
		}
		return (rdc->persist ?
		    !bitmap_in_use(RDC_CMD_ENABLE, rdc->shost, rdc->sbmp) : 1);
	}
}

int
can_reconfig_pbmp(rdcconfig_t *rdc, char *bmp)
{
	if (!rdc->persist)
		return (0);

	return (!bitmap_in_use(RDC_CMD_RECONFIG, rdc->phost, bmp));
}

int
can_reconfig_sbmp(rdcconfig_t *rdc, char *bmp)
{
	if (!rdc->persist)
		return (0);

	return (!bitmap_in_use(RDC_CMD_RECONFIG, rdc->shost, bmp));
}

rdc_rc_t *
cant_rsync(rdcconfig_t *rdc)
{
	rdc_rc_t *rc;

	if (mounted(rdc->pfile)) {
		rc = new_rc();
		if (rc == NULL)
			return (NULL);
		strncpy(rc->set.phost, rdc->phost, MAX_RDC_HOST_SIZE);
		strncpy(rc->set.pfile, rdc->pfile, NSC_MAXPATH);
		strncpy(rc->set.pbmp, rdc->pbmp, NSC_MAXPATH);
		strncpy(rc->set.shost, rdc->shost, MAX_RDC_HOST_SIZE);
		strncpy(rc->set.sfile, rdc->sfile, NSC_MAXPATH);
		strncpy(rc->set.sbmp, rdc->sbmp, NSC_MAXPATH);

		rc->rc = -1;

		rdc_set_error(NULL, RDC_INTERNAL, 0, "unable to sync %s volume"
		    " is currently mounted", rdc->pfile);
		strncpy(rc->msg, rdc_error(NULL), RDC_ERR_SIZE);

		return (rc);
	}
	return (NULL);
}
