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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <regex.h>
#include <devfsadm.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <syslog.h>
#include <bsm/devalloc.h>
#include <sys/audio.h>
#include <sys/soundcard.h>
#include <unistd.h>

#define	MAX_AUDIO_LINK 100
#define	RE_SIZE 64

extern int system_labeled;

static void check_audio_link(char *secondary_link,
    const char *primary_link_format);

static int audio_process(di_minor_t minor, di_node_t node);
static int sndstat_process(di_minor_t minor, di_node_t node);

static devfsadm_create_t audio_cbt[] = {
	{ "audio", "ddi_audio", NULL,
	    TYPE_EXACT, ILEVEL_0, audio_process
	},
	{ "pseudo", "ddi_pseudo", "audio",
	    TYPE_EXACT|DRV_EXACT, ILEVEL_0, sndstat_process
	},
};

DEVFSADM_CREATE_INIT_V0(audio_cbt);

/*
 * the following can't be one big RE with a bunch of alterations "|"
 * because recurse_dev_re() would not work.
 */
static devfsadm_remove_t audio_remove_cbt[] = {
	/*
	 * Secondary links.
	 */

	/* /dev/audio, /dev/audioctl, /dev/dsp */
	{ "audio", "^audio$",
	    RM_POST|RM_HOT|RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "audio", "^audioctl$",
	    RM_POST|RM_HOT|RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "audio", "^dsp$",
	    RM_POST|RM_HOT|RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "audio", "^mixer",
	    RM_POST|RM_HOT|RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "audio", "^sndstat$",
	    RM_PRE|RM_HOT|RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "audio", "^mixer[0-9]+$",
	    RM_POST|RM_HOT|RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "audio", "^dsp[0-9]+$",
	    RM_POST|RM_HOT|RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "audio", "^sound/[0-9]+$",
	    RM_POST|RM_HOT|RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
	{ "audio", "^sound/[0-9]+ctl$",
	    RM_POST|RM_HOT|RM_ALWAYS, ILEVEL_0, devfsadm_rm_all
	},
};

DEVFSADM_REMOVE_INIT_V0(audio_remove_cbt);

int
minor_fini(void)
{
	check_audio_link("audio", "sound/%d");
	check_audio_link("audioctl", "sound/%dctl");
	check_audio_link("dsp", "dsp%d");
	return (DEVFSADM_SUCCESS);
}


#define	COPYSUB(to, from, pm, pos) (void) strncpy(to, &from[pm[pos].rm_so], \
		    pm[pos].rm_eo - pm[pos].rm_so); \
		    to[pm[pos].rm_eo - pm[pos].rm_so] = 0;

static void
send_number(long num)
{
	char		buf[PATH_MAX+1];

	/*
	 * This is not safe with -r.
	 */
	if (strcmp(devfsadm_root_path(), "/") != 0)
		return;

	(void) snprintf(buf, sizeof (buf), "/dev/mixer%ld", num);
	if (device_exists(buf)) {
		int	fd;

		if ((fd = open(buf, O_RDWR)) < 0)
			return;

		(void) ioctl(fd, SNDCTL_SUN_SEND_NUMBER, &num);
		(void) close(fd);
		devfsadm_print(CHATTY_MID,
		    "sent devnum audio %ld to %s\n", num, buf);
	}
}

static int
sndstat_process(di_minor_t minor, di_node_t node)
{
	char *mn;

	mn = di_minor_name(minor);

	/*
	 * "Special" handling for /dev/sndstat and /dev/mixer.
	 */
	if (strcmp(mn, "sound,sndstat0") == 0) {
		(void) devfsadm_mklink("sndstat", node, minor, 0);
		(void) devfsadm_secondary_link("mixer", "sndstat", 0);
	}

	return (DEVFSADM_CONTINUE);
}

/*
 * This function is called for every audio node.
 * Calls enumerate to assign a logical unit id, and then
 * devfsadm_mklink to make the link.
 */
static int
audio_process(di_minor_t minor, di_node_t node)
{
	int flags = 0;
	char devpath[PATH_MAX + 1];
	char newpath[PATH_MAX + 1];
	char *buf;
	char *mn;
	char *tmp;
	char *ep;
	char re_string[RE_SIZE+1];
	devfsadm_enumerate_t rules[1] = {NULL};
	char base[PATH_MAX + 1];
	char linksrc[PATH_MAX + 1];
	char linkdst[PATH_MAX + 1];
	long num;
	long inst;
	int i;
	char *driver;

	if (system_labeled)
		flags = DA_ADD|DA_AUDIO;

	mn = di_minor_name(minor);

	if ((tmp = di_devfs_path(node)) == NULL) {
		return (DEVFSADM_CONTINUE);
	}
	(void) snprintf(devpath, sizeof (devpath), "%s:%s", tmp, mn);
	di_devfs_path_free(tmp);

	if (strncmp(mn, "sound,", sizeof ("sound,") - 1) != 0) {
		devfsadm_errprint("SUNW_audio_link: "
		    "can't find match for'%s'\n", mn);
		return (DEVFSADM_CONTINUE);
	}

	/* strlen("sound,") */
	(void) strlcpy(base, mn + 6, sizeof (base));
	mn = base;

	driver = di_driver_name(node);

	/* if driver name override in minor name */
	if ((tmp = strchr(mn, ',')) != NULL) {
		driver = mn;
		*tmp = '\0';
		mn = tmp + 1;
	}

	/* skip past "audio" portion of the minor name */
	if (strncmp(mn, "audio", sizeof ("audio") - 1) == 0) {
		mn += sizeof ("audio") - 1;
	}

	/* parse the instance number */
	for (i = strlen(mn); i; i--) {
		if (!isdigit(mn[i - 1]))
			break;
	}
	inst = strtol(mn + i, &ep, 10);
	mn[i] = 0;	/* lop off the instance number */

	/*
	 * First we create a node with the driver under /dev/sound.
	 * Note that "instance numbers" used by the audio framework
	 * are guaranteed to be unique for each driver.
	 */
	(void) snprintf(newpath, sizeof (newpath), "sound/%s:%d%s",
	    driver, inst, mn);
	(void) devfsadm_mklink(newpath, node, minor, flags);

	/*
	 * The rest of this logic is a gross simplification that is
	 * made possible by the fact that each audio node will have
	 * several different minors associated with it.  Rather than
	 * processing each node separately, we just create the links
	 * all at once.
	 *
	 * This reduces the chances of the various links being out of
	 * sync with each other.
	 */
	if (strcmp(mn, "mixer") != 0) {
		return (DEVFSADM_CONTINUE);
	}

	/*
	 * Its the control node, so create the various
	 * secondary links.
	 */

	/*
	 * We want a match against the physical path
	 * without the minor name component.
	 */
	(void) snprintf(re_string, RE_SIZE, "%s", "^mixer([0-9]+)");
	rules[0].re = re_string;
	rules[0].subexp = 1;
	rules[0].flags = MATCH_ALL;

	/*
	 * enumerate finds the logical audio id, and stuffs
	 * it in buf
	 */
	(void) strlcpy(devpath, newpath, sizeof (devpath));
	if (devfsadm_enumerate_int(devpath, 0, &buf, rules, 1)) {
		return (DEVFSADM_CONTINUE);
	}
	num = strtol(buf, &ep, 10);
	free(buf);

	/* /dev/sound/0 */
	(void) snprintf(linksrc, sizeof (linksrc), "sound/%s:%ld",
	    driver, inst);
	(void) snprintf(linkdst, sizeof (linkdst), "sound/%ld", num);
	(void) devfsadm_secondary_link(linkdst, linksrc, flags);

	(void) snprintf(linksrc, sizeof (linksrc), "sound/%s:%ldctl",
	    driver, inst);
	(void) snprintf(linkdst, sizeof (linkdst), "sound/%ldctl", num);
	(void) devfsadm_secondary_link(linkdst, linksrc, flags);

	(void) snprintf(linksrc, sizeof (linksrc), "sound/%s:%lddsp",
	    driver, inst);
	(void) snprintf(linkdst, sizeof (linkdst), "dsp%ld", num);
	(void) devfsadm_secondary_link(linkdst, linksrc, flags);

	(void) snprintf(linksrc, sizeof (linksrc), "sound/%s:%ldmixer",
	    driver, inst);
	(void) snprintf(linkdst, sizeof (linkdst), "mixer%ld", num);
	(void) devfsadm_secondary_link(linkdst, linksrc, flags);

	/* Send control number */
	send_number(num);

	return (DEVFSADM_CONTINUE);
}

static void
check_audio_link(char *secondary, const char *primary_format)
{
	char primary[PATH_MAX + 1];
	int i;
	int flags = 0;

	/* if link is present, return */
	if (devfsadm_link_valid(secondary) == DEVFSADM_TRUE) {
		return;
	}

	if (system_labeled)
		flags = DA_ADD|DA_AUDIO;

	for (i = 0; i < MAX_AUDIO_LINK; i++) {
		(void) sprintf(primary, primary_format, i);
		if (devfsadm_link_valid(primary) == DEVFSADM_TRUE) {
			/* we read link to get it to the master "real" link */
			(void) devfsadm_secondary_link(secondary,
			    primary, flags);
			break;
		}
	}
}
