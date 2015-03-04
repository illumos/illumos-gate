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
 * Copyright 2015 Gary Mills
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "pmconfig.h"
#include <sys/mkdev.h>
#include <sys/syslog.h>
#include <sys/openpromio.h>
#include <sys/mnttab.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/pm.h>
#include <kstat.h>
#include <sys/smbios.h>
#include <libzfs.h>


#define	STRCPYLIM(dst, src, str) strcpy_limit(dst, src, sizeof (dst), str)
#define	LASTBYTE(str) (str + strlen(str) - 1)

static char nerr_fmt[] = "number is out of range (%s)\n";
static char alloc_fmt[] = "cannot allocate space for \"%s\", %s\n";
static char set_thresh_fmt[] = "error setting threshold(s) for \"%s\", %s\n";
static char bad_thresh_fmt[] = "bad threshold(s)\n";
static char stat_fmt[] = "cannot stat \"%s\", %s\n";
static char always_on[] = "always-on";

#define	PM_DEFAULT_ALGORITHM -1
/*
 * When lines in a config file (usually "/etc/power.conf") start with
 * a recognized keyword, a "handler" routine is called for specific
 * CPR or PM -related action(s).  Each routine returns a status code
 * indicating whether all tasks were successful; if any errors occured,
 * future CPR or PM updates are skipped.  Following are the handler
 * routines for all keywords:
 */


static char pm_cmd_string[32];

static char *
pm_map(int cmd)
{
	pm_req_t req;

	req.value = cmd;
	req.data = (void *)pm_cmd_string;
	req.datasize = sizeof (pm_cmd_string);

	if (ioctl(pm_fd, PM_GET_CMD_NAME, &req) < 0) {
		perror(gettext("PM_GET_CMD_NAME failed:"));
		return ("??");
	}
	return (pm_cmd_string);
}

static int
isonlist(char *listname, const char *man, const char *prod)
{
	pm_searchargs_t sl;
	int ret;

	sl.pms_listname = listname;
	sl.pms_manufacturer = (char *)man;
	sl.pms_product = (char *)prod;
	ret = ioctl(pm_fd, PM_SEARCH_LIST, &sl);
	mesg(MDEBUG, "PM_SEARCH_LIST %s for %s,%s returns %d\n",
	    listname, man, prod, ret);
	return (ret == 0);
}

static int
do_ioctl(int ioctl_cmd, char *keyword, char *behavior, int suppress)
{
	mesg(MDEBUG, "doing ioctl %s for %s ", pm_map(ioctl_cmd), keyword);
	if (ioctl(pm_fd, ioctl_cmd, NULL) == -1) {
		int suppressed = suppress == -1 || suppress == errno;
		if (!suppressed) {
			mesg(MERR, "%s %s failed, %s\n", keyword, behavior,
			    strerror(errno));
			return (NOUP);
		} else {
			mesg(MDEBUG, "%s %s failed, %s\n", keyword, behavior,
			    strerror(errno));
			return (OKUP);
		}
	}
	mesg(MDEBUG, "succeeded\n");
	return (OKUP);
}

/*
 * Check for valid cpupm behavior and communicate it to the kernel.
 */
int
cpupm(void)
{
	struct bmtoc {
		char *behavior;
		char *mode;
		int cmd;
		int Errno;
	};

	static struct bmtoc bmlist[] = {
		"disable",	"\0",		PM_STOP_CPUPM,		EINVAL,
		"enable",	"poll-mode",	PM_START_CPUPM_POLL,	EBUSY,
		"enable",	"event-mode",	PM_START_CPUPM_EV,	EBUSY,
		"enable",	"\0",		PM_START_CPUPM,		EBUSY,
		NULL,		0,		0,			0
	};
	struct bmtoc *bp;
	char *behavior;
	char *mode;

	behavior = LINEARG(1);
	if ((mode = LINEARG(2)) == NULL)
		mode = "\0";

	for (bp = bmlist; bp->cmd; bp++) {
		if (strcmp(behavior, bp->behavior) == 0 &&
		    strcmp(mode, bp->mode) == 0) {
			break;
		}
	}
	if (bp->cmd == 0) {
		if (LINEARG(2) == NULL) {
			mesg(MERR, "invalid cpupm behavior \"%s\"\n", behavior);
		} else {
			mesg(MERR, "invalid cpupm behavior \"%s %s\"\n",
			    behavior, mode);
		}
		return (NOUP);
	}
	if (ioctl(pm_fd, bp->cmd, NULL) == -1 && errno != bp->Errno) {
		mesg(MERR, "cpupm %s failed, %s\n",
		    behavior, strerror(errno));
		return (NOUP);
	}
	return (OKUP);
}

/*
 * Check for valid cpu_deep_idle option and communicate it to the kernel.
 */
int
cpuidle(void)
{
	struct btoc {
		char *behavior;
		int cmd;
		int Errno;
	};
	static struct btoc blist[] = {
		"disable",	PM_DISABLE_CPU_DEEP_IDLE, EINVAL,
		"enable",	PM_ENABLE_CPU_DEEP_IDLE, EBUSY,
		"default",	PM_DEFAULT_CPU_DEEP_IDLE, EBUSY,
		NULL,		0, 0
	};
	struct btoc *bp;
	char *behavior;

	for (behavior = LINEARG(1), bp = blist; bp->cmd; bp++) {
		if (strcmp(behavior, bp->behavior) == 0)
			break;
	}
	if (bp->cmd == 0) {
		mesg(MERR, "invalid cpu_deep_idle behavior \"%s\"\n", behavior);
		return (NOUP);
	}
	if (ioctl(pm_fd, bp->cmd, NULL) == -1 && errno != bp->Errno) {
		mesg(MERR, "cpu_deep_idle %s failed, %s\n",
		    behavior, strerror(errno));
		return (NOUP);
	}
	return (OKUP);
}

/*
 * Two decisions are identical except for the list names and ioctl commands
 * inputs: whitelist, blacklist, yes, no
 * if (! ("S3" kstat exists))
 *	return (no)
 * if (SystemInformation.Manufacturer == "Sun Microsystems" &&
 *    (Pref_PM_Profile == Workstation || Pref_PM_Profile == Desktop)) {
 *	if (platform on blacklist)
 *		return (no)
 *	return (yes)
 * } else {
 *	if (platform on whitelist)
 *		return (yes)
 *	return (no)
 * }
 */

int
S3_helper(char *whitelist, char *blacklist, int yes, int no, char *keyword,
	char *behavior, int *didyes, int suppress)
{
	int oflags = SMB_O_NOCKSUM | SMB_O_NOVERS;
	smbios_hdl_t *shp;
	smbios_system_t sys;
	id_t id;
	int ret;
	kstat_ctl_t *kc;
	kstat_t *ksp;
	kstat_named_t *dp;
	smbios_info_t info;
	int preferred_pm_profile = 0;
	char yesstr[32], nostr[32];	/* DEBUG */

	*didyes = 0;

	(void) strncpy(yesstr, pm_map(yes), sizeof (yesstr));
	(void) strncpy(nostr, pm_map(no), sizeof (nostr));
	mesg(MDEBUG, "S3_helper(%s, %s, %s, %s, %s, %s)\n", whitelist,
	    blacklist, yesstr, nostr, keyword, behavior);
	if ((kc = kstat_open()) == NULL) {
		mesg(MDEBUG, "kstat_open failed\n");
		return (OKUP);
	}
	ksp = kstat_lookup(kc, "acpi", -1, "acpi");
	if (ksp == NULL) {
		mesg(MDEBUG, "kstat_lookup 'acpi', -1, 'acpi' failed\n");
		(void) kstat_close(kc);
		return (OKUP);
	}
	(void) kstat_read(kc, ksp,  NULL);
	dp = kstat_data_lookup(ksp, "S3");
	if (dp == NULL || dp->value.l == 0) {
		mesg(MDEBUG, "kstat_data_lookup 'S3' fails\n");
		if (dp != NULL)
			mesg(MDEBUG, "value.l %lx\n", dp->value.l);
		(void) kstat_close(kc);
		return (do_ioctl(no, keyword, behavior, suppress));
	}
	mesg(MDEBUG, "kstat indicates S3 support (%lx)\n", dp->value.l);

	if (!whitelist_only) {
		/*
		 * We still have an ACPI ksp, search it again for
		 * 'preferred_pm_profile' (needs to be valid if we don't
		 * aren't only using a whitelist).
		 */
		dp = kstat_data_lookup(ksp, "preferred_pm_profile");
		if (dp == NULL) {
			mesg(MDEBUG, "kstat_data_lookup 'ppmp fails\n");
			(void) kstat_close(kc);
			return (do_ioctl(no, keyword, behavior, suppress));
		}
		mesg(MDEBUG, "kstat indicates preferred_pm_profile is %lx\n",
		    dp->value.l);
		preferred_pm_profile = dp->value.l;
	}
	(void) kstat_close(kc);

	if ((shp = smbios_open(NULL,
	    SMB_VERSION, oflags, &ret)) == NULL) {
		/* we promised not to complain */
		/* we bail leaving it to the kernel default */
		mesg(MDEBUG, "smbios_open failed %d\n", errno);
		return (OKUP);
	}
	if ((id = smbios_info_system(shp, &sys)) == SMB_ERR) {
		mesg(MDEBUG, "smbios_info_system failed %d\n", errno);
		smbios_close(shp);
		return (OKUP);
	}
	if (smbios_info_common(shp, id, &info) == SMB_ERR) {
		mesg(MDEBUG, "smbios_info_common failed %d\n", errno);
		smbios_close(shp);
		return (OKUP);
	}
	mesg(MDEBUG, "Manufacturer: %s\n", info.smbi_manufacturer);
	mesg(MDEBUG, "Product: %s\n", info.smbi_product);
	smbios_close(shp);

	if (!whitelist_only) {
#define	PPP_DESKTOP 1
#define	PPP_WORKSTATION 3
		if (strcmp(info.smbi_manufacturer, "Sun Microsystems") == 0 &&
		    (preferred_pm_profile == PPP_DESKTOP ||
		    preferred_pm_profile == PPP_WORKSTATION)) {
			if (isonlist(blacklist,
			    info.smbi_manufacturer, info.smbi_product)) {
				return (do_ioctl(no, keyword, behavior,
				    suppress));
			} else {
				ret = do_ioctl(yes, keyword, behavior,
				    suppress);
				*didyes = (ret == OKUP);
				return (ret);
			}
		}
	}
	if (isonlist(whitelist,
	    info.smbi_manufacturer, info.smbi_product)) {
		ret = do_ioctl(yes, keyword, behavior, suppress);
		*didyes = (ret == OKUP);
		return (ret);
	} else {
		return (do_ioctl(no, keyword, behavior, suppress));
	}
}

int
S3sup(void)	/* S3-support keyword handler */
{
	struct btoc {
		char *behavior;
		int cmd;
	};
	static struct btoc blist[] = {
		"default",	PM_DEFAULT_ALGORITHM,
		"enable",	PM_ENABLE_S3,
		"disable",	PM_DISABLE_S3,
		NULL,		0
	};
	struct btoc *bp;
	char *behavior;
	int dontcare;

	for (behavior = LINEARG(1), bp = blist; bp->cmd; bp++) {
		if (strcmp(behavior, bp->behavior) == 0)
			break;
	}
	if (bp->cmd == 0) {
		mesg(MERR, "invalid S3-support behavior \"%s\"\n", behavior);
		return (NOUP);
	}


	switch (bp->cmd) {

	case PM_ENABLE_S3:
	case PM_DISABLE_S3:
		return (do_ioctl(bp->cmd, "S3-support", behavior, EBUSY));

	case PM_DEFAULT_ALGORITHM:
		/*
		 * we suppress errors in the "default" case because we
		 * already did an invisible default call, so we know we'll
		 * get EBUSY
		 */
		return (S3_helper("S3-support-enable", "S3-support-disable",
		    PM_ENABLE_S3, PM_DISABLE_S3, "S3-support", behavior,
		    &dontcare, EBUSY));

	default:
		mesg(MERR, "S3-support %s failed, %s\n", behavior,
		    strerror(errno));
		return (NOUP);
	}
}

/*
 * Check for valid autoS3 behavior and save after ioctl success.
 */
int
autoS3(void)
{
	struct btoc {
		char *behavior;
		int cmd;
	};
	static struct btoc blist[] = {
		"default",	PM_DEFAULT_ALGORITHM,
		"disable",	PM_STOP_AUTOS3,
		"enable",	PM_START_AUTOS3,
		NULL,		0
	};
	struct btoc *bp;
	char *behavior;
	int dontcare;

	for (behavior = LINEARG(1), bp = blist; bp->cmd; bp++) {
		if (strcmp(behavior, bp->behavior) == 0)
			break;
	}
	if (bp->cmd == 0) {
		mesg(MERR, "invalid autoS3 behavior \"%s\"\n", behavior);
		return (NOUP);
	}

	switch (bp->cmd) {
	default:
		mesg(MERR, "autoS3 %s failed, %s\n",
		    behavior, strerror(errno));
		mesg(MDEBUG, "unknown command\n", bp->cmd);
		return (OKUP);

	case PM_STOP_AUTOS3:
	case PM_START_AUTOS3:
		return (do_ioctl(bp->cmd, "autoS3", behavior, EBUSY));

	case PM_DEFAULT_ALGORITHM:
		return (S3_helper("S3-autoenable", "S3-autodisable",
		    PM_START_AUTOS3, PM_STOP_AUTOS3, "autoS3", behavior,
		    &dontcare, EBUSY));
	}
}


/*
 * Check for valid autopm behavior and save after ioctl success.
 */
int
autopm(void)
{
	struct btoc {
		char *behavior;
		int cmd, Errno, isdef;
	};
	static struct btoc blist[] = {
		"default",	PM_START_PM,	-1,	1,
		"disable",	PM_STOP_PM,	EINVAL,	0,
		"enable",	PM_START_PM,	EBUSY,	0,
		NULL,		0,		0,	0,
	};
	struct btoc *bp;
	char *behavior;

	for (behavior = LINEARG(1), bp = blist; bp->cmd; bp++) {
		if (strcmp(behavior, bp->behavior) == 0)
			break;
	}
	if (bp->cmd == 0) {
		mesg(MERR, "invalid autopm behavior \"%s\"\n", behavior);
		return (NOUP);
	}

	/*
	 * for "default" behavior, do not enable autopm if not ESTAR_V3
	 */
#if defined(__sparc)
	if (!bp->isdef || (estar_vers == ESTAR_V3)) {
		if (ioctl(pm_fd, bp->cmd, NULL) == -1 && errno != bp->Errno) {
			mesg(MERR, "autopm %s failed, %s\n",
			    behavior, strerror(errno));
			return (NOUP);
		}
	}
	(void) strcpy(new_cc.apm_behavior, behavior);
	return (OKUP);
#endif
#if defined(__x86)
	if (!bp->isdef) {
		if (ioctl(pm_fd, bp->cmd, NULL) == -1 && errno != bp->Errno) {
			mesg(MERR, "autopm %s failed, %s\n",
			    behavior, strerror(errno));
			return (NOUP);
		}
		mesg(MDEBUG, "autopm %s succeeded\n", behavior);

		return (OKUP);
	} else {
		int didenable;
		int ret = S3_helper("autopm-enable", "autopm-disable",
		    PM_START_PM, PM_STOP_PM, "autopm", behavior, &didenable,
		    bp->Errno);
		if (didenable) {
			/* tell powerd to attach all devices */
			new_cc.is_autopm_default = 1;
			(void) strcpy(new_cc.apm_behavior, behavior);
		}
		return (ret);
	}
#endif
}


static int
gethm(char *src, int *hour, int *min)
{
	if (sscanf(src, "%d:%d", hour, min) != 2) {
		mesg(MERR, "bad time format (%s)\n", src);
		return (-1);
	}
	return (0);
}


static void
strcpy_limit(char *dst, char *src, size_t limit, char *info)
{
	if (strlcpy(dst, src, limit) >= limit)
		mesg(MEXIT, "%s is too long (%s)\n", info, src);
}


/*
 * Convert autoshutdown idle and start/finish times;
 * check and record autoshutdown behavior.
 */
int
autosd(void)
{
	char **bp, *behavior;
	char *unrec = gettext("unrecognized autoshutdown behavior");
	static char *blist[] = {
		"autowakeup", "default", "noshutdown",
		"shutdown", "unconfigured", NULL
	};

	new_cc.as_idle = atoi(LINEARG(1));
	if (gethm(LINEARG(2), &new_cc.as_sh, &new_cc.as_sm) ||
	    gethm(LINEARG(3), &new_cc.as_fh, &new_cc.as_fm))
		return (NOUP);
	mesg(MDEBUG, "idle %d, start %d:%02d, finish %d:%02d\n",
	    new_cc.as_idle, new_cc.as_sh, new_cc.as_sm,
	    new_cc.as_fh, new_cc.as_fm);

	for (behavior = LINEARG(4), bp = blist; *bp; bp++) {
		if (strcmp(behavior, *bp) == 0)
			break;
	}
	if (*bp == NULL) {
		mesg(MERR, "%s: \"%s\"\n", unrec, behavior);
		return (NOUP);
	}
	STRCPYLIM(new_cc.as_behavior, *bp, unrec);
	return (OKUP);
}


/*
 * Check for a real device and try to resolve to a full path.
 * The orig/resolved path may be modified into a prom pathname,
 * and an allocated copy of the result is stored at *destp;
 * the caller will need to free that space.  Returns 1 for any
 * error, otherwise 0; also sets *errp after an alloc error.
 */
static int
devpath(char **destp, char *src, int *errp)
{
	struct stat stbuf;
	char buf[PATH_MAX];
	char *cp, *dstr;
	int devok, dcs = 0;
	size_t len;

	/*
	 * When there's a real device, try to resolve the path
	 * and trim the leading "/devices" component.
	 */
	if ((devok = (stat(src, &stbuf) == 0 && stbuf.st_rdev)) != 0) {
		if (realpath(src, buf) == NULL) {
			mesg(MERR, "realpath cannot resolve \"%s\"\n",
			    src, strerror(errno));
			return (1);
		}
		src = buf;
		dstr = "/devices";
		len = strlen(dstr);
		dcs = (strncmp(src, dstr, len) == 0);
		if (dcs)
			src += len;
	} else
		mesg(MDEBUG, stat_fmt, src, strerror(errno));

	/*
	 * When the path has ":anything", display an error for
	 * a non-device or truncate a resolved+modifed path.
	 */
	if ((cp = strchr(src, ':')) != NULL) {
		if (devok == 0) {
			mesg(MERR, "physical path may not contain "
			    "a minor string (%s)\n", src);
			return (1);
		} else if (dcs)
			*cp = '\0';
	}

	if ((*destp = strdup(src)) == NULL) {
		*errp = NOUP;
		mesg(MERR, alloc_fmt, src, strerror(errno));
	}
	return (*destp == NULL);
}


/*
 * Call pm ioctl request(s) to set property/device dependencies.
 */
static int
dev_dep_common(int isprop)
{
	int cmd, argn, upval = OKUP;
	char *src, *first, **destp;
	pm_req_t pmreq;

	bzero(&pmreq, sizeof (pmreq));
	src = LINEARG(1);
	if (isprop) {
		cmd = PM_ADD_DEPENDENT_PROPERTY;
		first = NULL;
		pmreq.pmreq_kept = src;
	} else {
		cmd = PM_ADD_DEPENDENT;
		if (devpath(&first, src, &upval))
			return (upval);
		pmreq.pmreq_kept = first;
	}
	destp = &pmreq.pmreq_keeper;

	/*
	 * Now loop through any dependents.
	 */
	for (argn = 2; (src = LINEARG(argn)) != NULL; argn++) {
		if (devpath(destp, src, &upval)) {
			if (upval != OKUP)
				return (upval);
			break;
		}
		if ((upval = ioctl(pm_fd, cmd, &pmreq)) == -1) {
			mesg(MDEBUG, "pm ioctl, cmd %d, errno %d\n"
			    "kept \"%s\", keeper \"%s\"\n",
			    cmd, errno, pmreq.pmreq_kept, pmreq.pmreq_keeper);
			mesg(MERR, "cannot set \"%s\" dependency "
			    "for \"%s\", %s\n", pmreq.pmreq_keeper,
			    pmreq.pmreq_kept, strerror(errno));
		}
		free(*destp);
		*destp = NULL;
		if (upval != OKUP)
			break;
	}

	free(first);
	return (upval);
}


int
ddprop(void)
{
	return (dev_dep_common(1));
}


int
devdep(void)
{
	return (dev_dep_common(0));
}


/*
 * Convert a numeric string (with a possible trailing scaling byte)
 * into an integer.  Returns a converted value and *nerrp unchanged,
 * or 0 with *nerrp set to 1 for a conversion error.
 */
static int
get_scaled_value(char *str, int *nerrp)
{
	longlong_t svalue = 0, factor = 1;
	char *sp;

	errno = 0;
	svalue = strtol(str, &sp, 0);
	if (errno || (*str != '-' && (*str < '0' || *str > '9')))
		*nerrp = 1;
	else if (sp && *sp != '\0') {
		if (*sp == 'h')
			factor = 3600;
		else if (*sp == 'm')
			factor = 60;
		else if (*sp != 's')
			*nerrp = 1;
	}
	/* any bytes following sp are ignored */

	if (*nerrp == 0) {
		svalue *= factor;
		if (svalue < INT_MIN || svalue > INT_MAX)
			*nerrp = 1;
	}
	if (*nerrp)
		mesg(MERR, nerr_fmt, str);
	mesg(MDEBUG, "got scaled value %d\n", (int)svalue);
	return ((int)svalue);
}


/*
 * Increment the count of threshold values,
 * reallocate *vlistp and append another element.
 * Returns 1 on error, otherwise 0.
 */
static int
vlist_append(int **vlistp, int *vcntp, int value)
{
	(*vcntp)++;
	if ((*vlistp = realloc(*vlistp, *vcntp * sizeof (**vlistp))) != NULL)
		*(*vlistp + *vcntp - 1) = value;
	else
		mesg(MERR, alloc_fmt, "threshold list", strerror(errno));
	return (*vlistp == NULL);
}


/*
 * Convert a single threshold string or paren groups of thresh's as
 * described below.  All thresh's are saved to an allocated list at
 * *vlistp; the caller will need to free that space.  On return:
 * *vcntp is the count of the vlist array, and vlist is either
 * a single thresh or N groups of thresh's with a trailing zero:
 * (cnt_1 thr_1a thr_1b [...]) ... (cnt_N thr_Na thr_Nb [...]) 0.
 * Returns 0 when all conversions were OK, and 1 for any syntax,
 * conversion, or alloc error.
 */
static int
get_thresh(int **vlistp, int *vcntp)
{
	int argn, value, gci = 0, grp_cnt = 0, paren = 0, nerr = 0;
	char *rp, *src;

	for (argn = 2; (src = LINEARG(argn)) != NULL; argn++) {
		if (*src == LPAREN) {
			gci = *vcntp;
			if ((nerr = vlist_append(vlistp, vcntp, 0)) != 0)
				break;
			paren = 1;
			src++;
		}
		if (*(rp = LASTBYTE(src)) == RPAREN) {
			if (paren) {
				grp_cnt = *vcntp - gci;
				*(*vlistp + gci) = grp_cnt;
				paren = 0;
				*rp = '\0';
			} else {
				nerr = 1;
				break;
			}
		}

		value = get_scaled_value(src, &nerr);
		if (nerr || (nerr = vlist_append(vlistp, vcntp, value)))
			break;
	}

	if (nerr == 0 && grp_cnt)
		nerr = vlist_append(vlistp, vcntp, 0);
	return (nerr);
}


/*
 * Set device thresholds from (3) formats:
 * 	path	"always-on"
 * 	path	time-spec: [0-9]+[{h,m,s}]
 *	path	(ts1 ts2 ...)+
 */
int
devthr(void)
{
	int cmd, upval = OKUP, nthresh = 0, *vlist = NULL;
	pm_req_t pmreq;

	bzero(&pmreq, sizeof (pmreq));
	if (devpath(&pmreq.physpath, LINEARG(1), &upval))
		return (upval);

	if (strcmp(LINEARG(2), always_on) == 0) {
		cmd = PM_SET_DEVICE_THRESHOLD;
		pmreq.value = INT_MAX;
	} else if (get_thresh(&vlist, &nthresh)) {
		mesg(MERR, bad_thresh_fmt);
		upval = NOUP;
	} else if (nthresh == 1) {
		pmreq.value = *vlist;
		cmd = PM_SET_DEVICE_THRESHOLD;
	} else {
		pmreq.data = vlist;
		pmreq.datasize = (nthresh * sizeof (*vlist));
		cmd = PM_SET_COMPONENT_THRESHOLDS;
	}

	if (upval != NOUP && (upval = ioctl(pm_fd, cmd, &pmreq)) == -1)
		mesg(MERR, set_thresh_fmt, pmreq.physpath, strerror(errno));

	free(vlist);
	free(pmreq.physpath);
	return (upval);
}


static int
scan_int(char *src, int *dst)
{
	long lval;

	errno = 0;

	lval = strtol(LINEARG(1), NULL, 0);
	if (errno || lval > INT_MAX || lval < 0) {
		mesg(MERR, nerr_fmt, src);
		return (NOUP);
	}

	*dst = (int)lval;
	return (OKUP);
}

static int
scan_float(char *src, float *dst)
{
	float fval;

	errno = 0;

	fval = strtof(src, NULL);
	if (errno || fval < 0.0) {
		mesg(MERR, nerr_fmt, src);
		return (NOUP);
	}

	*dst = fval;
	return (OKUP);
}


int
dreads(void)
{
	return (scan_int(LINEARG(1), &new_cc.diskreads_thold));
}


/*
 * Set pathname for idlecheck;
 * an overflowed pathname is treated as a fatal error.
 */
int
idlechk(void)
{
	STRCPYLIM(new_cc.idlecheck_path, LINEARG(1), "idle path");
	return (OKUP);
}


int
loadavg(void)
{
	return (scan_float(LINEARG(1), &new_cc.loadaverage_thold));
}


int
nfsreq(void)
{
	return (scan_int(LINEARG(1), &new_cc.nfsreqs_thold));
}

#ifdef sparc
static char open_fmt[] = "cannot open \"%s\", %s\n";

/*
 * Verify the filesystem type for a regular statefile is "ufs"
 * or verify a block device is not in use as a mounted filesytem.
 * Returns 1 if any error, otherwise 0.
 */
static int
check_mount(char *sfile, dev_t sfdev, int ufs)
{
	char *src, *err_fmt = NULL, *mnttab = MNTTAB;
	int rgent, match = 0;
	struct mnttab zroot = { 0 };
	struct mnttab entry;
	struct extmnttab ent;
	FILE *fp;

	if ((fp = fopen(mnttab, "r")) == NULL) {
		mesg(MERR, open_fmt, mnttab, strerror(errno));
		return (1);
	}

	if (ufs) {
		zroot.mnt_mountp = "/";
		zroot.mnt_fstype = "zfs";
		if (getmntany(fp, &entry, &zroot) == 0) {
			err_fmt = "ufs statefile with zfs root is not"
			    " supported\n";
			mesg(MERR, err_fmt, sfile);
			(void) fclose(fp);
			return (1);
		}
		resetmnttab(fp);
	}
	/*
	 * Search for a matching dev_t;
	 * ignore non-ufs filesystems for a regular statefile.
	 */
	while ((rgent = getextmntent(fp, &ent, sizeof (ent))) != -1) {
		if (rgent > 0) {
			mesg(MERR, "error reading \"%s\"\n", mnttab);
			(void) fclose(fp);
			return (1);
		} else if (ufs && strcmp(ent.mnt_fstype, "ufs"))
			continue;
		else if (makedev(ent.mnt_major, ent.mnt_minor) == sfdev) {
			match = 1;
			break;
		}
	}

	/*
	 * No match is needed for a block device statefile,
	 * a match is needed for a regular statefile.
	 */
	if (match == 0) {
		if (new_cc.cf_type != CFT_UFS)
			STRCPYLIM(new_cc.cf_devfs, sfile, "block statefile");
		else
			err_fmt = "cannot find ufs mount point for \"%s\"\n";
	} else if (new_cc.cf_type == CFT_UFS) {
		STRCPYLIM(new_cc.cf_fs, ent.mnt_mountp, "mnt entry");
		STRCPYLIM(new_cc.cf_devfs, ent.mnt_special, "mnt special");
		while (*(sfile + 1) == '/') sfile++;
		src = sfile + strlen(ent.mnt_mountp);
		while (*src == '/') src++;
		STRCPYLIM(new_cc.cf_path, src, "statefile path");
	} else
		err_fmt = "statefile device \"%s\" is a mounted filesystem\n";
	(void) fclose(fp);
	if (err_fmt)
		mesg(MERR, err_fmt, sfile);
	return (err_fmt != NULL);
}


/*
 * Convert a Unix device to a prom device and save on success,
 * log any ioctl/conversion error.
 */
static int
utop(char *fs_name, char *prom_name)
{
	union obpbuf {
		char	buf[OBP_MAXPATHLEN + sizeof (uint_t)];
		struct	openpromio oppio;
	};
	union obpbuf oppbuf;
	struct openpromio *opp;
	char *promdev = "/dev/openprom";
	int fd, upval;

	if ((fd = open(promdev, O_RDONLY)) == -1) {
		mesg(MERR, open_fmt, promdev, strerror(errno));
		return (NOUP);
	}

	opp = &oppbuf.oppio;
	opp->oprom_size = OBP_MAXPATHLEN;
	strcpy_limit(opp->oprom_array, fs_name,
	    OBP_MAXPATHLEN, "statefile device");
	upval = ioctl(fd, OPROMDEV2PROMNAME, opp);
	(void) close(fd);
	if (upval == OKUP) {
		strcpy_limit(prom_name, opp->oprom_array, OBP_MAXPATHLEN,
		    "prom device");
	} else {
		openlog("pmconfig", 0, LOG_DAEMON);
		syslog(LOG_NOTICE,
		    gettext("cannot convert \"%s\" to prom device"),
		    fs_name);
		closelog();
	}

	return (upval);
}

/*
 * given the path to a zvol, return the cXtYdZ name
 * returns < 0 on error, 0 if it isn't a zvol, > 1 on success
 */
static int
ztop(char *arg, char *diskname)
{
	zpool_handle_t *zpool_handle;
	nvlist_t *config, *nvroot;
	nvlist_t **child;
	uint_t children;
	libzfs_handle_t *lzfs;
	char *vname;
	char *p;
	char pool_name[MAXPATHLEN];

	if (strncmp(arg, "/dev/zvol/dsk/", 14)) {
		return (0);
	}
	arg += 14;
	(void) strncpy(pool_name, arg, MAXPATHLEN);
	if ((p = strchr(pool_name, '/')) != NULL)
		*p = '\0';
	STRCPYLIM(new_cc.cf_fs, p + 1, "statefile path");

	if ((lzfs = libzfs_init()) == NULL) {
		mesg(MERR, "failed to initialize ZFS library\n");
		return (-1);
	}
	if ((zpool_handle = zpool_open(lzfs, pool_name)) == NULL) {
		mesg(MERR, "couldn't open pool '%s'\n", pool_name);
		libzfs_fini(lzfs);
		return (-1);
	}
	config = zpool_get_config(zpool_handle, NULL);
	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) != 0) {
		zpool_close(zpool_handle);
		libzfs_fini(lzfs);
		return (-1);
	}
	verify(nvlist_lookup_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0);
	if (children != 1) {
		mesg(MERR, "expected one vdev, got %d\n", children);
		zpool_close(zpool_handle);
		libzfs_fini(lzfs);
		return (-1);
	}
	vname = zpool_vdev_name(lzfs, zpool_handle, child[0], B_FALSE);
	if (vname == NULL) {
		mesg(MERR, "couldn't determine vdev name\n");
		zpool_close(zpool_handle);
		libzfs_fini(lzfs);
		return (-1);
	}
	(void) strcpy(diskname, "/dev/dsk/");
	(void) strcat(diskname, vname);
	free(vname);
	zpool_close(zpool_handle);
	libzfs_fini(lzfs);
	return (1);
}

/*
 * returns NULL if the slice is good (e.g. does not start at block
 * zero, or a string describing the error if it doesn't
 */
static boolean_t
is_good_slice(char *sfile, char **err)
{
	int fd, rc;
	struct vtoc vtoc;
	dk_gpt_t *gpt;
	char rdskname[MAXPATHLEN];
	char *x, *y;

	*err = NULL;
	/* convert from dsk to rdsk */
	STRCPYLIM(rdskname, sfile, "disk name");
	x = strstr(rdskname, "dsk/");
	y = strstr(sfile, "dsk/");
	if (x != NULL) {
		*x++ = 'r';
		(void) strcpy(x, y);
	}

	if ((fd = open(rdskname, O_RDONLY)) == -1) {
		*err = "could not open '%s'\n";
	} else if ((rc = read_vtoc(fd, &vtoc)) >= 0) {
		/*
		 * we got a slice number; now check the block
		 * number where the slice starts
		 */
		if (vtoc.v_part[rc].p_start < 2)
			*err = "using '%s' would clobber the disk label\n";
		(void) close(fd);
		return (*err ? B_FALSE : B_TRUE);
	} else if ((rc == VT_ENOTSUP) &&
	    (efi_alloc_and_read(fd, &gpt)) >= 0) {
		/* EFI slices don't clobber the disk label */
		free(gpt);
		(void) close(fd);
		return (B_TRUE);
	} else
		*err = "could not read partition table from '%s'\n";
	return (B_FALSE);
}

/*
 * Check for a valid statefile pathname, inode and mount status.
 */
int
sfpath(void)
{
	static int statefile;
	char *err_fmt = NULL;
	char *sfile, *sp, ch;
	char diskname[256];
	struct stat stbuf;
	int dir = 0;
	dev_t dev = NODEV;

	if (statefile) {
		mesg(MERR, "ignored redundant statefile entry\n");
		return (OKUP);
	} else if (ua_err) {
		if (ua_err != ENOTSUP)
			mesg(MERR, "uadmin(A_FREEZE, A_CHECK, 0): %s\n",
			    strerror(ua_err));
		return (NOUP);
	}

	/*
	 * Check for an absolute path and trim any trailing '/'.
	 */
	sfile = LINEARG(1);
	if (*sfile != '/') {
		mesg(MERR, "statefile requires an absolute path\n");
		return (NOUP);
	}
	for (sp = sfile + strlen(sfile) - 1; sp > sfile && *sp == '/'; sp--)
		*sp = '\0';

	/*
	 * If the statefile doesn't exist, the leading path must be a dir.
	 */
	if (stat(sfile, &stbuf) == -1) {
		if (errno == ENOENT) {
			dir = 1;
			if ((sp = strrchr(sfile, '/')) == sfile)
				sp++;
			ch = *sp;
			*sp = '\0';
			if (stat(sfile, &stbuf) == -1)
				err_fmt = stat_fmt;
			*sp = ch;
		} else
			err_fmt = stat_fmt;
		if (err_fmt) {
			mesg(MERR, err_fmt, sfile, strerror(errno));
			return (NOUP);
		}
	}

	/*
	 * Check for regular/dir/block types, set cf_type and dev.
	 */
	if (S_ISREG(stbuf.st_mode) || (dir && S_ISDIR(stbuf.st_mode))) {
		new_cc.cf_type = CFT_UFS;
		dev = stbuf.st_dev;
	} else if (S_ISBLK(stbuf.st_mode)) {
		if (is_good_slice(sfile, &err_fmt)) {
			switch (ztop(sfile, diskname)) {
				case 1:
					new_cc.cf_type = CFT_ZVOL;
					break;
				case 0:
					new_cc.cf_type = CFT_SPEC;
					break;
				case -1:
				default:
					return (NOUP);
			}
			dev = stbuf.st_rdev;
		}
	} else
		err_fmt = "bad file type for \"%s\"\n"
		    "statefile must be a regular file or block device\n";
	if (err_fmt) {
		mesg(MERR, err_fmt, sfile);
		return (NOUP);
	}
	if (check_mount(sfile, dev, (new_cc.cf_type == CFT_UFS)))
		return (NOUP);
	if (new_cc.cf_type == CFT_ZVOL) {
		if (utop(diskname, new_cc.cf_dev_prom))
			return (NOUP);
	} else if (utop(new_cc.cf_devfs, new_cc.cf_dev_prom)) {
		return (NOUP);
	}
	new_cc.cf_magic = CPR_CONFIG_MAGIC;
	statefile = 1;
	return (OKUP);
}
#endif /* sparc */


/*
 * Common function to set a system or cpu threshold.
 */
static int
cmnthr(int req)
{
	int value, nerr = 0, upval = OKUP;
	char *thresh = LINEARG(1);

	if (strcmp(thresh, always_on) == 0)
		value = INT_MAX;
	else if ((value = get_scaled_value(thresh, &nerr)) < 0 || nerr) {
		mesg(MERR, "%s must be a positive value\n", LINEARG(0));
		upval = NOUP;
	}
	if (upval == OKUP)
		(void) ioctl(pm_fd, req, value);
	return (upval);
}


/*
 * Try setting system threshold.
 */
int
systhr(void)
{
	return (cmnthr(PM_SET_SYSTEM_THRESHOLD));
}


/*
 * Try setting cpu threshold.
 */
int
cputhr(void)
{
	return (cmnthr(PM_SET_CPU_THRESHOLD));
}


int
tchars(void)
{
	return (scan_int(LINEARG(1), &new_cc.ttychars_thold));
}
