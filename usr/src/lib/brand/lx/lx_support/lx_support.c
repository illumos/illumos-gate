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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * lx_support is a small cli utility used to perform some brand-specific
 * tasks when booting, halting, or verifying a zone.  This utility is not
 * intended to be called by users - it is intended to be invoked by the
 * zones utilities.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <sys/ioccom.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>

#include <libzonecfg.h>
#include <sys/lx_audio.h>
#include <sys/lx_brand.h>

static void lxs_err(char *msg, ...) __NORETURN;
static void usage(void) __NORETURN;

#define	CP_CMD		"/usr/bin/cp"
#define	MOUNT_CMD	"/sbin/mount"

#define	LXA_AUDIO_DEV		"/dev/brand/lx/audio_devctl"
#define	INTSTRLEN		32
#define	KVSTRLEN		10

static char *bname = NULL;
static char *zonename = NULL;
static char *zoneroot = NULL;

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

static void
lxs_err(char *msg, ...)
{
	char	buf[1024];
	va_list	ap;

	va_start(ap, msg);
	/*LINTED*/
	(void) vsnprintf(buf, sizeof (buf), msg, ap);
	va_end(ap);

	(void) printf("%s error: %s\n", bname, buf);

	exit(1);
	/*NOTREACHED*/
}

/*
 * The Linux init(1M) command requires communication over the /dev/initctl
 * FIFO.  Since any attempt to create a file in /dev will fail, we must
 * create it here.
 */
static void
lxs_make_initctl()
{
	char		cmdbuf[ARG_MAX];
	char		path[MAXPATHLEN];
	char		special[MAXPATHLEN];
	struct stat	buf;
	int		err;

	if (snprintf(special, sizeof (special), "%s/dev/initctl", zoneroot) >=
	    sizeof (special))
		lxs_err("%s: %s", gettext("Failed to create /dev/initctl"),
		    gettext("zoneroot is too long"));

	if (snprintf(path, sizeof (path), "%s/root/dev/initctl", zoneroot) >=
	    sizeof (path))
		lxs_err("%s: %s", gettext("Failed to create /dev/initctl"),
		    gettext("zoneroot is too long"));

	/* create the actual fifo as <zoneroot>/dev/initctl */
	if (stat(special, &buf) != 0) {
		err = errno;
		if (err != ENOENT)
			lxs_err("%s: %s",
			    gettext("Failed to create /dev/initctl"),
			    strerror(err));
		if (mkfifo(special, 0644) < 0) {
			err = errno;
			lxs_err("%s: %s",
			    gettext("Failed to create /dev/initctl"),
			    strerror(err));
		}
	} else {
		if ((buf.st_mode & S_IFIFO) == 0)
			lxs_err("%s: %s",
			    gettext("Failed to create /dev/initctl"),
			    gettext("It already exists, and is not a FIFO."));
	}

	/*
	 * now lofs mount the <zoneroot>/dev/initctl fifo onto
	 * <zoneroot>/root/dev/initctl
	 */
	if (snprintf(cmdbuf, sizeof (cmdbuf), "%s -F lofs %s %s", MOUNT_CMD,
	    special, path) >= sizeof (cmdbuf))
		lxs_err("%s: %s", gettext("Failed to lofs mount /dev/initctl"),
		    gettext("zoneroot is too long"));

	if (system(cmdbuf) < 0) {
		err = errno;
		lxs_err("%s: %s", gettext("Failed to lofs mount /dev/initctl"),
		    strerror(err));
	}
}

/*
 * fsck gets really confused when run inside a zone.  Removing this file
 * prevents it from running
 */
static void
lxs_remove_autofsck()
{
	char	path[MAXPATHLEN];
	int	err;

	if (snprintf(path, MAXPATHLEN, "%s/root/.autofsck", zoneroot) >=
	    MAXPATHLEN)
		lxs_err("%s: %s", gettext("Failed to remove /.autofsck"),
		    gettext("zoneroot is too long"));

	if (unlink(path) < 0) {
		err = errno;
		if (err != ENOENT)
			lxs_err("%s: %s",
			    gettext("Failed to remove /.autofsck"),
			    strerror(err));
	}
}

/*
 * Extract any lx-supported attributes from the zone configuration file.
 */
static void
lxs_getattrs(zone_dochandle_t zdh, boolean_t *restart, boolean_t *audio,
    char **idev, char **odev, char **kvers)
{
	struct zone_attrtab	attrtab;
	int			err;

	/* initialize the attribute iterator */
	if (zonecfg_setattrent(zdh) != Z_OK) {
		zonecfg_fini_handle(zdh);
		lxs_err(gettext("error accessing zone configuration"));
	}

	*idev = (char *)malloc(INTSTRLEN);
	*odev = (char *)malloc(INTSTRLEN);
	*kvers = (char *)malloc(KVSTRLEN);
	if (*idev == NULL || *odev == NULL || *kvers == NULL)
		lxs_err(gettext("out of memory"));

	*audio = B_FALSE;
	*restart = B_FALSE;
	bzero(*idev, INTSTRLEN);
	bzero(*odev, INTSTRLEN);
	bzero(*kvers, KVSTRLEN);
	while ((err = zonecfg_getattrent(zdh, &attrtab)) == Z_OK) {
		if ((strcmp(attrtab.zone_attr_name, "init-restart") == 0) &&
		    (zonecfg_get_attr_boolean(&attrtab, restart) != Z_OK))
			lxs_err(gettext("invalid type for zone attribute: %s"),
			    attrtab.zone_attr_name);
		if ((strcmp(attrtab.zone_attr_name, "audio") == 0) &&
		    (zonecfg_get_attr_boolean(&attrtab, audio) != Z_OK))
			lxs_err(gettext("invalid type for zone attribute: %s"),
			    attrtab.zone_attr_name);
		if ((strcmp(attrtab.zone_attr_name, "audio-inputdev") == 0) &&
		    (zonecfg_get_attr_string(&attrtab, *idev,
		    INTSTRLEN) != Z_OK))
			lxs_err(gettext("invalid type for zone attribute: %s"),
			    attrtab.zone_attr_name);
		if ((strcmp(attrtab.zone_attr_name, "audio-outputdev") == 0) &&
		    (zonecfg_get_attr_string(&attrtab, *odev,
		    INTSTRLEN) != Z_OK))
			lxs_err(gettext("invalid type for zone attribute: %s"),
			    attrtab.zone_attr_name);
		if ((strcmp(attrtab.zone_attr_name, "kernel-version") == 0) &&
		    (zonecfg_get_attr_string(&attrtab, *kvers,
		    KVSTRLEN) != Z_OK))
			lxs_err(gettext("invalid type for zone attribute: %s"),
			    attrtab.zone_attr_name);
	}

	if (strlen(*kvers) == 0) {
		free(*kvers);
		*kvers = NULL;
	}

	/* some kind of error while looking up attributes */
	if (err != Z_NO_ENTRY)
		lxs_err(gettext("error accessing zone configuration"));
}

static int
lxs_iodev_ok(char *dev)
{
	int i, j;

	if ((j = strlen(dev)) == 0)
		return (1);
	if (strcmp(dev, "default") == 0)
		return (1);
	if (strcmp(dev, "none") == 0)
		return (1);
	for (i = 0; i < j; i++) {
		if (!isdigit(dev[i]))
			return (0);
	}
	return (1);
}

/*
 * The audio configuration settings are read from the zone configuration
 * file.  Audio configuration is specified via the following attributes
 * (settable via zonecfg):
 * 	attr name: audio
 * 	attr type: boolean
 *
 * 	attr name: audio-inputdev
 * 	attr type: string
 * 	attr values: "none" | [0-9]+
 *
 * 	attr name: audio-outputdev
 * 	attr type: string
 * 	attr values: "none" | [0-9]+
 *
 * The user can enable linux brand audio device (ie /dev/dsp and /dev/mixer)
 * for a zone by setting the "audio" attribute to true.  (The absence of
 * this attribute leads to an assumed value of false.)
 *
 * If the "audio" attribute is set to true and "audio-inputdev" and
 * "audio-outputdev" are not set, then when a linux applications access
 * audio devices these access will be mapped to the system default audio
 * device, ie /dev/audio and/dev/audioctl.
 *
 * If "audio-inputdev" is set to none, then audio input will be disabled.
 * If "audio-inputdev" is set to an integer, then when a Linux application
 * attempts to access audio devices these access will be mapped to
 * /dev/sound/<audio-inputdev attribute value>.  The same behavior will
 * apply to the "audio-outputdev" attribute for linux audio output
 * device accesses.
 *
 * If "audio-inputdev" or "audio-outputdev" exist but the audio attribute
 * is missing (or set to false) audio will not be enabled for the zone.
 */
static void
lxs_init_audio(char *idev, char *odev)
{
	int			err, fd;
	lxa_zone_reg_t		lxa_zr;

	/* sanity check the input and output device properties */
	if (!lxs_iodev_ok(idev))
		lxs_err(gettext("invalid value for zone attribute: %s"),
		    "audio-inputdev");

	if (!lxs_iodev_ok(odev))
		lxs_err(gettext("invalid value for zone attribute: %s"),
		    "audio-outputdev");

	/* initialize the zone name in the ioctl request */
	bzero(&lxa_zr, sizeof (lxa_zr));
	(void) strlcpy(lxa_zr.lxa_zr_zone_name, zonename,
	    sizeof (lxa_zr.lxa_zr_zone_name));

	/* initialize the input device property in the ioctl request */
	(void) strlcpy(lxa_zr.lxa_zr_inputdev, idev,
	    sizeof (lxa_zr.lxa_zr_inputdev));
	if (lxa_zr.lxa_zr_inputdev[0] == '\0') {
		/*
		 * if no input device was specified, set the input device
		 * to "default"
		 */
		(void) strlcpy(lxa_zr.lxa_zr_inputdev, "default",
		    sizeof (lxa_zr.lxa_zr_inputdev));
	}

	/* initialize the output device property in the ioctl request */
	(void) strlcpy(lxa_zr.lxa_zr_outputdev, odev,
	    sizeof (lxa_zr.lxa_zr_outputdev));
	if (lxa_zr.lxa_zr_outputdev[0] == '\0') {
		/*
		 * if no output device was specified, set the output device
		 * to "default"
		 */
		(void) strlcpy(lxa_zr.lxa_zr_outputdev, "default",
		    sizeof (lxa_zr.lxa_zr_outputdev));
	}

	/* open the audio device control node */
	if ((fd = open(LXA_AUDIO_DEV, O_RDWR)) < 0)
		lxs_err(gettext("error accessing lx_audio device"));

	/* enable audio for this zone */
	err = ioctl(fd, LXA_IOC_ZONE_REG, &lxa_zr);
	(void) close(fd);
	if (err != 0)
		lxs_err(gettext("error configuring lx_audio device"));
}

static int
lxs_boot()
{
	zoneid_t	zoneid;
	zone_dochandle_t zdh;
	boolean_t	audio, restart;
	char		*idev, *odev, *kvers;

	lxs_make_initctl();
	lxs_remove_autofsck();

	if ((zdh = zonecfg_init_handle()) == NULL)
		lxs_err(gettext("unable to initialize zone handle"));

	if (zonecfg_get_handle((char *)zonename, zdh) != Z_OK) {
		zonecfg_fini_handle(zdh);
		lxs_err(gettext("unable to load zone configuration"));
	}

	/* Extract any relevant attributes from the config file. */
	lxs_getattrs(zdh, &restart, &audio, &idev, &odev, &kvers);
	zonecfg_fini_handle(zdh);

	/* Configure the zone's audio support (if any). */
	if (audio == B_TRUE)
		lxs_init_audio(idev, odev);

	/*
	 * Let the kernel know whether or not this zone's init process
	 * should be automatically restarted on its death.
	 */
	if ((zoneid = getzoneidbyname(zonename)) < 0)
		lxs_err(gettext("unable to get zoneid"));
	if (zone_setattr(zoneid, LX_ATTR_RESTART_INIT, &restart,
	    sizeof (boolean_t)) == -1)
		lxs_err(gettext("error setting zone's restart_init property"));

	if (kvers != NULL) {
		/* Backward compatability with incomplete version attr */
		if (strcmp(kvers, "2.4") == 0) {
			kvers = "2.4.21";
		} else if (strcmp(kvers, "2.6") == 0) {
			kvers = "2.6.18";
		}

		if (zone_setattr(zoneid, LX_KERN_VERSION_NUM, kvers,
		    strlen(kvers)) < 0)
			lxs_err(gettext("unable to set kernel version"));
	}

	return (0);
}

static int
lxs_halt()
{
	lxa_zone_reg_t	lxa_zr;
	int		fd, rv;

	/*
	 * We don't bother to check if audio is configured for this zone
	 * before issuing a request to unconfigure it.  There's no real
	 * reason to do this, it would require looking up the xml zone and
	 * brand configuration information (which could have been changed
	 * since the zone was booted), and it would involve more library
	 * calls there by increasing chances for failure.
	 */

	/* initialize the zone name in the ioctl request */
	bzero(&lxa_zr, sizeof (lxa_zr));
	(void) strlcpy(lxa_zr.lxa_zr_zone_name, zonename,
	    sizeof (lxa_zr.lxa_zr_zone_name));

	/* open the audio device control node */
	if ((fd = open(LXA_AUDIO_DEV, O_RDWR)) < 0)
		lxs_err(gettext("error accessing lx_audio device"));

	/*
	 * disable audio for this zone
	 *
	 * we ignore ENOENT errors here because it's possible that
	 * audio is not configured for this zone.  (either it was
	 * already unconfigured or someone could have added the
	 * audio resource to this zone after it was booted.)
	 */
	rv = ioctl(fd, LXA_IOC_ZONE_UNREG, &lxa_zr);
	(void) close(fd);
	if ((rv == 0) || (errno == ENOENT))
		return (0);
	lxs_err(gettext("error unconfiguring lx_audio device: %s"),
	    strerror(errno));
	/*NOTREACHED*/
	return (0);
}

static int
lxs_verify(char *xmlfile)
{
	zone_dochandle_t	handle;
	boolean_t		audio, restart;
	char			*idev, *odev, *kvers;
	char			hostidp[HW_HOSTID_LEN];
	zone_iptype_t		iptype;

	if ((handle = zonecfg_init_handle()) == NULL)
		lxs_err(gettext("internal libzonecfg.so.1 error"), 0);

	if (zonecfg_get_xml_handle(xmlfile, handle) != Z_OK) {
		zonecfg_fini_handle(handle);
		lxs_err(gettext("zonecfg provided an invalid XML file"));
	}

	/*
	 * Check to see whether the zone has hostid emulation enabled.
	 */
	if (zonecfg_get_hostid(handle, hostidp, sizeof (hostidp)) == Z_OK) {
		zonecfg_fini_handle(handle);
		lxs_err(gettext("lx zones do not support hostid emulation"));
	}

	/*
	 * Only exclusive stack is supported.
	 */
	if (zonecfg_get_iptype(handle, &iptype) != Z_OK ||
	    iptype != ZS_EXCLUSIVE) {
		zonecfg_fini_handle(handle);
		lxs_err(gettext("lx zones do not support shared IP stacks"));
	}

	/* Extract any relevant attributes from the config file. */
	lxs_getattrs(handle, &restart, &audio, &idev, &odev, &kvers);
	zonecfg_fini_handle(handle);

	if (audio) {
		/* sanity check the input and output device properties */
		if (!lxs_iodev_ok(idev))
			lxs_err(gettext("invalid value for zone attribute: %s"),
			    "audio-inputdev");

		if (!lxs_iodev_ok(odev))
			lxs_err(gettext("invalid value for zone attribute: %s"),
			    "audio-outputdev");
	}
	if (kvers) {
		if (strlen(kvers) > (LX_VERS_MAX - 1) ||
		    (strncmp(kvers, "2.4", 3) != 0 &&
		    strncmp(kvers, "2.6", 3) != 0 &&
		    strncmp(kvers, "3.", 2) != 0))
			lxs_err(gettext("invalid value for zone attribute: %s"),
			    "kernel-version");
	}
	return (0);
}

static void
usage()
{

	(void) fprintf(stderr,
	    gettext("usage:\t%s boot <zoneroot> <zonename>\n"), bname);
	(void) fprintf(stderr,
	    gettext("      \t%s halt <zoneroot> <zonename>\n"), bname);
	(void) fprintf(stderr,
	    gettext("      \t%s verify <xml file>\n\n"), bname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	bname = basename(argv[0]);

	if (argc < 3)
		usage();

	if (strcmp(argv[1], "boot") == 0) {
		if (argc != 4)
			lxs_err(gettext("usage: %s %s <zoneroot> <zonename>"),
			    bname, argv[1]);
		zoneroot = argv[2];
		zonename = argv[3];
		return (lxs_boot());
	}

	if (strcmp(argv[1], "halt") == 0) {
		if (argc != 4)
			lxs_err(gettext("usage: %s %s <zoneroot> <zonename>"),
			    bname, argv[1]);
		zoneroot = argv[2];
		zonename = argv[3];
		return (lxs_halt());
	}

	if (strcmp(argv[1], "verify") == 0) {
		if (argc != 3)
			lxs_err(gettext("usage: %s verify <xml file>"),
			    bname);
		return (lxs_verify(argv[2]));
	}

	usage();
	/*NOTREACHED*/
}
