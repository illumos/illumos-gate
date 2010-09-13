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
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdio.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <stdlib.h>

#include <sys/nsctl/rdcerr.h>
#include <sys/nsctl/rdc_ioctl.h>
#include <sys/nsctl/librdc.h>
#include <sys/nsctl/cfg.h>
#include <sys/nsctl/nsc_hash.h>
#include <sys/nsctl/sv.h>

#include <sys/unistat/spcs_dtrinkets.h>
#include <sys/unistat/spcs_etrinkets.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_s_impl.h>
#include <sys/unistat/spcs_errors.h>

typedef struct volcount_s {
	int count;
} volcount_t;

hash_node_t **volhash = NULL;

char *
config2buf(char *buf, rdcconfig_t *rdc)
{
	snprintf(buf, CFG_MAX_BUF, "%s %s %s %s %s %s %s %s %s %s %s",
	    rdc->phost, rdc->pfile, rdc->pbmp, rdc->shost, rdc->sfile,
	    rdc->sbmp, rdc->direct, rdc->mode, rdc->group ? rdc->group : "",
	    rdc->ctag ? rdc->ctag : "", rdc->options ? rdc->options : "");
	return (buf);

}

/*
 * SV type functions.
 */

static void
load_rdc_vols(CFGFILE *cfg)
{
	int set;
	char key[ CFG_MAX_KEY ];
	char buf[ CFG_MAX_BUF ];
	char *vol, *bmp, *host1, *host2;
	volcount_t *volcount;

	if (volhash) {
		return;
	}

	cfg_rewind(cfg, CFG_SEC_CONF);
	volhash = nsc_create_hash();
	for (set = 1; /*CSTYLED*/; set++) {
		snprintf(key, CFG_MAX_KEY, "sndr.set%d", set);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF)) {
			break;
		}

		host1 = strtok(buf, " ");
		vol = strtok(NULL, " ");
		bmp = strtok(NULL, " ");

		if (!self_check(host1)) {
			/* next one had better be ours */
			host2 = strtok(NULL, " ");
			vol = strtok(NULL, " ");
			bmp = strtok(NULL, " ");

			if (!self_check(host2)) {
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
			nsc_insert_node(volhash, volcount, vol);
		}

		/* bitmap ought to be only used once */
		volcount = (volcount_t *)nsc_lookup(volhash, bmp);
		if (volcount) {
			/* argh */
			volcount->count++;
		} else {
			volcount = (volcount_t *)malloc(sizeof (volcount_t));
			volcount->count = 1;
			nsc_insert_node(volhash, volcount, bmp);
		}
	}
}

int
sv_enable_one_nocfg(char *vol)
{
	struct stat sb;
	sv_conf_t svc;
	int fd;

	bzero(&svc, sizeof (svc));
	if (stat(vol, &sb) != 0) {
		rdc_set_error(NULL, RDC_OS, 0, "unable to stat %s", vol);
		return (-1);
	}
	if (!S_ISCHR(sb.st_mode)) {
		rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL, "%s is not"
		    " a character device", vol);
		return (-1);
	}

	svc.svc_major = major(sb.st_rdev);
	svc.svc_minor = minor(sb.st_rdev);
	strncpy(svc.svc_path, vol, sizeof (svc.svc_path));

	fd = open(SV_DEVICE, O_RDONLY);
	if (fd < 0) {
		rdc_set_error(NULL, RDC_OS, 0, 0);
		return (-1);
	}

	svc.svc_flag = (NSC_DEVICE | NSC_CACHE);
	svc.svc_error = spcs_s_ucreate();

	if (ioctl(fd, SVIOC_ENABLE, &svc) < 0) {
		if (errno != SV_EENABLED) {
			rdc_set_error(&svc.svc_error, RDC_INTERNAL,
			    RDC_NONFATAL, 0);
			return (-1);
		}
	}

	spcs_log("sv", NULL, gettext("enabled %s"), svc.svc_path);

	close(fd);
	return (1);
}

int
sv_enable_nocfg(rdcconfig_t *rdc)
{
	struct stat stbv;
	struct stat stbb;
	sv_conf_t svcv;
	sv_conf_t svcb;
	char	vol[NSC_MAXPATH];
	char	bmp[NSC_MAXPATH];
	int fd = -1;


	if (self_check(rdc->phost)) {
		strncpy(vol, rdc->pfile, NSC_MAXPATH);
		strncpy(bmp, rdc->pbmp, NSC_MAXPATH);
	} else {
		strncpy(vol, rdc->sfile, NSC_MAXPATH);
		strncpy(bmp, rdc->sbmp, NSC_MAXPATH);
	}

	bzero(&svcv, sizeof (svcv));
	bzero(&svcb, sizeof (svcb));

	if ((stat(vol, &stbv) != 0) || (stat(bmp, &stbb) != 0))
		return (-1);

	if ((!S_ISCHR(stbv.st_mode)) || (!S_ISCHR(stbb.st_mode)))
		return (-1);

	svcv.svc_major = major(stbv.st_rdev);
	svcb.svc_minor = minor(stbb.st_rdev);

	strncpy(svcv.svc_path, vol, sizeof (svcv.svc_path));
	strncpy(svcb.svc_path, bmp, sizeof (svcb.svc_path));

	fd = open(SV_DEVICE, O_RDONLY);
	if (fd < 0)
		return (-1);

	/* SV enable the volume */
	svcv.svc_flag = (NSC_DEVICE | NSC_CACHE);
	svcv.svc_error = spcs_s_ucreate();

	if (ioctl(fd, SVIOC_ENABLE, &svcv) < 0) {
		if (errno != SV_EENABLED) {
			spcs_log("sv", &svcv.svc_error,
			    gettext("unable to enable %s"),
			    svcv.svc_path);
			spcs_s_ufree(&svcv.svc_error);
			return (-1);
		}
	}

	/* SV enable the bitmap disable the vol on error */
	svcb.svc_flag = (NSC_DEVICE | NSC_CACHE);
	svcb.svc_error = spcs_s_ucreate();

	if (ioctl(fd, SVIOC_ENABLE, &svcb) < 0) {
		if (errno != SV_EENABLED) {
			spcs_log("sv", &svcb.svc_error,
			    gettext("unable to enable %s"),
			    svcb.svc_path);
			if (ioctl(fd, SVIOC_DISABLE, &svcv) < 0)
				spcs_log("sv", &svcv.svc_error,
				    gettext("unable to disable %s"),
				    svcv.svc_path);

			spcs_s_ufree(&svcv.svc_error);
			spcs_s_ufree(&svcb.svc_error);
			return (-1);
		}
	}


	spcs_log("sv", NULL, gettext("enabled %s"), svcv.svc_path);
	spcs_log("sv", NULL, gettext("enabled %s"), svcb.svc_path);
	spcs_s_ufree(&svcv.svc_error);
	spcs_s_ufree(&svcb.svc_error);


	if (fd >= 0)
		(void) close(fd);

	return (1);
}

int
do_autosv_enable(CFGFILE *cfg, rdcconfig_t *rdc)
{
	char vol[NSC_MAXPATH];
	char bmp[NSC_MAXPATH];

	cfg_load_svols(cfg);
	cfg_load_dsvols(cfg);
	cfg_load_shadows(cfg);
	load_rdc_vols(cfg);

	if (self_check(rdc->phost)) {
		strncpy(vol, rdc->pfile, NSC_MAXPATH);
		strncpy(bmp, rdc->pbmp, NSC_MAXPATH);
	} else {
		strncpy(vol, rdc->sfile, NSC_MAXPATH);
		strncpy(bmp, rdc->sbmp, NSC_MAXPATH);
	}
	if (nsc_lookup(volhash, vol) == NULL) {
		if (cfg_vol_enable(cfg, vol, rdc->ctag, "sndr") < 0) {
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
			    "auto sv enable failed for %s", vol);
			return (-1);
		}
	}
	if (nsc_lookup(volhash, bmp) == NULL) {
		if (cfg_vol_enable(cfg, bmp, rdc->ctag, "sndr") < 0) {
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
			    "auto sv enable failed for %s", vol);
			return (-1);
		}
	}

	nsc_remove_all(volhash, free);
	volhash = NULL;

	cfg_unload_shadows();
	cfg_unload_dsvols();
	cfg_unload_svols();

	return (1);
}

int
do_autosv_disable(CFGFILE *cfg, rdcconfig_t *rdc)
{
	char vol[NSC_MAXPATH];
	char bmp[NSC_MAXPATH];
	volcount_t *vc;

	cfg_load_svols(cfg);
	cfg_load_dsvols(cfg);
	cfg_load_shadows(cfg);
	load_rdc_vols(cfg);

	if (self_check(rdc->phost)) {
		strncpy(vol, rdc->pfile, NSC_MAXPATH);
		strncpy(bmp, rdc->pbmp, NSC_MAXPATH);
	} else {
		strncpy(vol, rdc->sfile, NSC_MAXPATH);
		strncpy(bmp, rdc->sbmp, NSC_MAXPATH);
	}

	vc = nsc_lookup(volhash, vol);
	if (vc && (vc->count == 1)) {
		if (cfg_vol_disable(cfg, vol, rdc->ctag, "sndr") < 0)
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
				"auto sv disable failed for %s", vol);
	} else if (!vc) {
		rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
		    "Unable to find %s in config", vol);
	}
	vc = nsc_lookup(volhash, bmp);
	if (vc && (vc->count == 1)) {
		if (cfg_vol_disable(cfg, bmp, rdc->ctag, "sndr") < 0)
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
				"auto sv disable failed for %s", bmp);

	} else if (!vc) {
		rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
		    "Unable to find %s in config", bmp);
	}

	return (1);

}

/*
 * do sv enables for the appropriate vol
 * and bitmap. If called without persistance
 * it will follow a chain and sv enable all
 * otherwise, it will enable only the one
 * set.
 */
int
sv_enable(CFGFILE *cfg, rdcconfig_t *rdcs)
{
	rdcconfig_t *rdcp = NULL;

	rdcp = rdcs;
	if (!rdcp->persist) {

		return (sv_enable_nocfg(rdcp));

	} else if (cfg == NULL) {

		return (-1);

	}

	do_autosv_enable(cfg, rdcp);

	return (1);
}

int
sv_disable(CFGFILE *cfg, rdcconfig_t *rdcs)
{
	rdcconfig_t *rdcp;

	rdcp = rdcs;
	if (!rdcp->persist) { /* don't disable */

		return (1);

	} else if (cfg == NULL) {

		return (-1);

	}

	do_autosv_disable(cfg, rdcp);

	return (1);

}

/*
 * disable the appropriate bitmap in rdc
 * and replace it with bitmap
 */
int
sv_reconfig(CFGFILE *cfg, rdcconfig_t *rdc, char *oldbmp, char *newbmp)
{
	rdcconfig_t *rdcp;
	int fail = 0;

	rdcp = rdc;
	if (!rdcp->persist) { /* just enable, don't disable */

		sv_enable_one_nocfg(newbmp);

	} else if (rdcp->persist) { /* do sv disable and enable */
		volcount_t *vc;

		cfg_load_svols(cfg);
		cfg_load_dsvols(cfg);
		cfg_load_shadows(cfg);
		load_rdc_vols(cfg);

		vc = (volcount_t *)nsc_lookup(volhash, oldbmp);
		if (vc && (vc->count == 1)) {
			if (cfg_vol_disable(cfg, oldbmp, rdc->ctag, "sndr") < 0)
				rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
				    "auto sv disable failed for %s", oldbmp);

		}
		if (nsc_lookup(volhash, newbmp) == NULL) {
			if (cfg_vol_enable(cfg,
			    newbmp, rdc->ctag, "sndr") < 0) {

				rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
				    "auto sv enable failed for %s", newbmp);
				fail++;
			}
		}
		nsc_remove_all(volhash, free);
		volhash = NULL;

		cfg_unload_shadows();
		cfg_unload_dsvols();
		cfg_unload_svols();
		if (fail)
			return (-1);

	}
	return (1);

}

/*
 * SNDR functions
 */

/*
 * add_to_rdc_cfg
 * this adds the successfully created rdc sets to libdscfg,
 * also, as auto_sv stuff is part of libdscfg, it does the
 * auto_sv stuff and enables the correct volumes
 */
int
add_to_rdc_cfg(rdcconfig_t *rdcs)
{
	CFGFILE *cfg;
	rdcconfig_t *rdcp;
	char *buf;


	buf = calloc(CFG_MAX_BUF, sizeof (char));
	if (!buf) {
		rdc_set_error(NULL, RDC_OS, RDC_FATAL, NULL);
		return (NULL);
	}

	if ((cfg = cfg_open(NULL)) == NULL) {
		rdc_set_error(NULL, RDC_DSCFG, 0, 0);
		return (-1);
	}
	if ((cfg_lock(cfg, CFG_WRLOCK)) < 0) {
		rdc_set_error(NULL, RDC_DSCFG, 0, 0);
		return (-1);
	}

	rdcp = rdcs;
	while (rdcp)  {
		buf = config2buf(buf, rdcp);
		if ((sv_enable(cfg, rdcp) < 0) ||
		    (cfg_put_cstring(cfg, "sndr", buf, CFG_MAX_BUF) < 0)) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			free(buf);
			return (-1);
		}
		rdcp = rdcp->next;
	}
	if (!cfg_commit(cfg)) {
		rdc_set_error(NULL, RDC_DSCFG, 0, NULL);
		return (-1);
	}

	cfg_close(cfg);

	return (0);
}

int
cfg_lookup(CFGFILE *cfg, char *shost, char *sfile)
{
	char buf[CFG_MAX_BUF];
	char key[CFG_MAX_KEY];
	int setnum;
	int numsets = 0;

	numsets = cfg_get_num_entries(cfg, "sndr");
	for (setnum = 1; setnum <= numsets; setnum++) {
		bzero(key, CFG_MAX_KEY);
		snprintf(key, CFG_MAX_KEY, "sndr.set%d.shost", setnum);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			return (-1);
		}
		if (strncmp(buf, shost, strlen(shost)))
			continue;

		bzero(key, CFG_MAX_KEY);
		snprintf(key, CFG_MAX_KEY, "sndr.set%d.secondary", setnum);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			return (-1);
		}
		if (strncmp(buf, sfile, strlen(sfile)))
			continue;
		break;
	}
	return (setnum);
}

void
remove_from_rdc_cfg(rdcconfig_t *rdcs)
{
	CFGFILE *cfg;
	rdcconfig_t *rdcp;
	char key[CFG_MAX_KEY];

	rdcp = rdcs;
	cfg = cfg_open(NULL);
	cfg_lock(cfg, CFG_WRLOCK);

	while (rdcp) {
		snprintf(key, CFG_MAX_KEY, "sndr.set%d",
		    cfg_lookup(cfg, rdcp->shost, rdcp->sfile));
		if ((sv_disable(cfg, rdcp) < 0) ||
		    (cfg_put_cstring(cfg, key, NULL, 0)) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
		}

		rdcp = rdcp->next;
	}
	cfg_commit(cfg);
	cfg_close(cfg);
}
/*ARGSUSED*/
int
replace_entry(int offset, char *entry)
{
	return (1);
}

/*
 * this will set the value at "field" in dscfg to the
 * value contained in entry.
 * for things like bitmap reconfigs, only pass one rdc
 * not a chain
 */
int
replace_cfgfield(rdcconfig_t *rdc, char *field, char *entry)
{
	CFGFILE *cfg;
	rdcconfig_t *rdcp;
	char key[CFG_MAX_KEY];
	char newentry[CFG_MAX_BUF];
	char oldbmp[CFG_MAX_BUF];
	int setnum;
	int ispbmp = 0;
	int issbmp = 0;

	if (strncmp(field, "pbitmap", NSC_MAXPATH) == 0)
		ispbmp++;
	if (strncmp(field, "sbitmap", NSC_MAXPATH) == 0)
		issbmp++;

	bzero(newentry, sizeof (newentry));
	if (!entry || strlen(entry) == 0)
		*newentry = '-';
	else
		strncpy(newentry, entry, CFG_MAX_BUF);


	if ((cfg = cfg_open(NULL)) == NULL) {
		rdc_set_error(NULL, RDC_DSCFG, 0, 0);
		return (-1);
	}
	if ((cfg_lock(cfg, CFG_WRLOCK)) < 0) {
		rdc_set_error(NULL, RDC_DSCFG, 0, 0);
		return (-1);
	}

	rdcp = rdc;
	while (rdcp) {
		if ((setnum = cfg_lookup(cfg, rdcp->shost, rdcp->sfile)) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			return (-1);
		}
		snprintf(key, CFG_MAX_KEY, "sndr.set%d.%s", setnum, field);
		if (!((ispbmp || issbmp) &&
		    (cfg_get_cstring(cfg, key, oldbmp, CFG_MAX_BUF)) == 0)) {
			rdc_set_error(NULL, RDC_DSCFG, 0, "unable to get %s",
			    key);
		}
		if (((ispbmp && self_check(rdcp->phost)) ||
		    (issbmp && self_check(rdcp->shost))) &&
		    (sv_reconfig(cfg, rdcp, oldbmp, newentry) < 0)) {
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
			    "unable to sv reconfig %s to %s", oldbmp, newentry);
			return (-1);
		}

		if ((cfg_put_cstring(cfg, key, newentry, CFG_MAX_BUF)) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			return (-1);
		}
		rdcp = rdcp->next;
	}
	cfg_commit(cfg);
	cfg_close(cfg);
	return (1);
}

/*
 * reverse_in_cfg
 * used by RDC_OPT_REVERSE_ROLE
 * swaps primary info and secondary info
 */
int
reverse_in_cfg(rdcconfig_t *rdc)
{
	CFGFILE *cfg;
	rdcconfig_t *rdcp = NULL;
	char key[CFG_MAX_KEY];
	int setnum;

	if ((cfg = cfg_open(NULL)) == NULL) {
		rdc_set_error(NULL, RDC_DSCFG, 0, 0);
		return (-1);
	}
	if ((cfg_lock(cfg, CFG_WRLOCK)) < 0) {
		rdc_set_error(NULL, RDC_DSCFG, 0, 0);
		return (-1);
	}

	rdcp = rdc;
	while (rdcp) {
		if ((setnum = cfg_lookup(cfg, rdcp->shost, rdcp->sfile)) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			goto badconfig;
		}
		bzero(key, CFG_MAX_KEY);
		snprintf(key, CFG_MAX_KEY, "sndr.set%d.phost", setnum);
		if ((cfg_put_cstring(cfg, key, rdcp->shost, CFG_MAX_BUF)) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			goto badconfig;
		}
		bzero(key, CFG_MAX_KEY);
		snprintf(key, CFG_MAX_KEY, "sndr.set%d.primary", setnum);
		if ((cfg_put_cstring(cfg, key, rdcp->sfile, CFG_MAX_BUF)) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			goto badconfig;
		}
		bzero(key, CFG_MAX_KEY);
		snprintf(key, CFG_MAX_KEY, "sndr.set%d.pbitmap", setnum);
		if ((cfg_put_cstring(cfg, key, rdcp->sbmp, CFG_MAX_BUF)) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			goto badconfig;
		}
		bzero(key, CFG_MAX_KEY);
		snprintf(key, CFG_MAX_KEY, "sndr.set%d.shost", setnum);
		if ((cfg_put_cstring(cfg, key, rdcp->phost, CFG_MAX_BUF)) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			goto badconfig;
		}
		bzero(key, CFG_MAX_KEY);
		snprintf(key, CFG_MAX_KEY, "sndr.set%d.secondary", setnum);
		if ((cfg_put_cstring(cfg, key, rdcp->pfile, CFG_MAX_BUF)) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			goto badconfig;
		}
		bzero(key, CFG_MAX_KEY);
		snprintf(key, CFG_MAX_KEY, "sndr.set%d.sbitmap", setnum);
		if ((cfg_put_cstring(cfg, key, rdcp->pbmp, CFG_MAX_BUF)) < 0) {
			rdc_set_error(NULL, RDC_DSCFG, 0, 0);
			goto badconfig;
		}
		rdcp = rdcp->next;
	}
	if (!cfg_commit(cfg)) {
		cfg_close(cfg);
		return (-1);
	}
	cfg_close(cfg);
	return (0);

badconfig:
	cfg_close(cfg);
	return (-1);
}
