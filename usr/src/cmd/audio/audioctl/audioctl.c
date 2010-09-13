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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <locale.h>
#include <libintl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/soundcard.h>
#include <libdevinfo.h>

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif

#define	_(s)	gettext(s)

#define	MAXLINE	1024

#define	AUDIO_CTRL_STEREO_LEFT(v)	((uint8_t)((v) & 0xff))
#define	AUDIO_CTRL_STEREO_RIGHT(v)	((uint8_t)(((v) >> 8) & 0xff))
#define	AUDIO_CTRL_STEREO_VAL(l, r)	(((l) & 0xff) | (((r) & 0xff) << 8))

/*
 * These are borrowed from sys/audio/audio_common.h, where the values
 * are protected by _KERNEL.
 */
#define	AUDIO_MN_TYPE_NBITS	(4)
#define	AUDIO_MN_TYPE_MASK	((1U << AUDIO_MN_TYPE_NBITS) - 1)
#define	AUDIO_MINOR_MIXER	(0)


/*
 * Column display information
 * All are related to the types enumerated in col_t and any change should be
 * reflected in the corresponding indices and offsets for all the variables
 * accordingly.  Most tweaks to the display can be done by adjusting the
 * values here.
 */

/* types of columns displayed */
typedef enum { COL_DV = 0, COL_NM, COL_VAL, COL_SEL} col_t;

/* corresponding sizes of columns; does not include trailing null */
#define	COL_DV_SZ	16
#define	COL_NM_SZ	24
#define	COL_VAL_SZ	10
#define	COL_SEL_SZ	20
#define	COL_MAX_SZ	64

/* corresponding sizes of columns, indexed by col_t value */
static int col_sz[] = {
	COL_DV_SZ, COL_NM_SZ, COL_VAL_SZ, COL_SEL_SZ
};

/* used by callers of the printing function */
typedef struct col_prt {
	char *col_dv;
	char *col_nm;
	char *col_val;
	char *col_sel;
} col_prt_t;

/* columns displayed in order with vopt = 0 */
static int col_dpy[] = {COL_NM, COL_VAL};
static int col_dpy_len = sizeof (col_dpy) / sizeof (*col_dpy);

/* tells the printing function what members to use; follows col_dpy[] */
static size_t col_dpy_prt[] = {
	offsetof(col_prt_t, col_nm),
	offsetof(col_prt_t, col_val),
};

/* columns displayed in order with vopt = 1 */
static int col_dpy_vopt[] = { COL_DV, COL_NM, COL_VAL, COL_SEL};
static int col_dpy_vopt_len = sizeof (col_dpy_vopt) / sizeof (*col_dpy_vopt);

/* tells the printing function what members to use; follows col_dpy_vopt[] */
static size_t col_dpy_prt_vopt[] = {
	offsetof(col_prt_t, col_dv),
	offsetof(col_prt_t, col_nm),
	offsetof(col_prt_t, col_val),
	offsetof(col_prt_t, col_sel)
};

/* columns displayed in order with tofile = 1 */
static int col_dpy_tofile[] = { COL_NM, COL_VAL};
static int col_dpy_tofile_len = sizeof (col_dpy_tofile) /
    sizeof (*col_dpy_tofile);

/* tells the printing function what members to use; follows col_dpy_tofile[] */
static size_t col_dpy_prt_tofile[] = {
	offsetof(col_prt_t, col_nm),
	offsetof(col_prt_t, col_val)
};


/*
 * mixer and control accounting
 */

typedef struct cinfo {
	oss_mixext ci;
	oss_mixer_enuminfo *enump;
} cinfo_t;

typedef struct device {
	oss_card_info	card;
	oss_mixerinfo	mixer;

	int		cmax;
	cinfo_t		*controls;

	int		mfd;
	dev_t		devt;

	struct device	*nextp;
} device_t;

static device_t	*devices = NULL;

/*PRINTFLIKE1*/
static void
msg(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
static void
warn(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void
free_device(device_t *d)
{
	int		i;
	device_t	**dpp;

	dpp = &devices;
	while ((*dpp) && ((*dpp) != d)) {
		dpp = &((*dpp)->nextp);
	}
	if (*dpp) {
		*dpp = d->nextp;
	}
	for (i = 0; i < d->cmax; i++) {
		if (d->controls[i].enump != NULL)
			free(d->controls[i].enump);
	}

	if (d->mfd >= 0)
		(void) close(d->mfd);

	free(d);
}

static void
free_devices(void)
{
	device_t *d = devices;

	while ((d = devices) != NULL) {
		free_device(d);
	}

	devices = NULL;
}


/*
 * adds to the end of global devices and returns a pointer to the new entry
 */
static device_t *
alloc_device(void)
{
	device_t *p;
	device_t *d = calloc(1, sizeof (*d));

	d->card.card = -1;
	d->mixer.dev = -1;
	d->mfd = -1;

	if (devices == NULL) {
		devices = d;
	} else {
		for (p = devices; p->nextp != NULL; p = p->nextp) {}

		p->nextp = d;
	}
	return (d);
}


/*
 * cinfop->enump needs to be present
 * idx should be: >= 0 to < cinfop->ci.maxvalue
 */
static char *
get_enum_str(cinfo_t *cinfop, int idx)
{
	int sz = sizeof (*cinfop->ci.enum_present) * 8;

	if (cinfop->ci.enum_present[idx / sz] & (1 << (idx % sz)))
		return (cinfop->enump->strings + cinfop->enump->strindex[idx]);

	return (NULL);
}


/*
 * caller fills in d->mixer.devnode; func fills in the rest
 */
static int
get_device_info(device_t *d)
{
	int fd = -1;
	int i;
	cinfo_t *ci;

	if ((fd = open(d->mixer.devnode, O_RDWR)) < 0) {
		perror(_("Error opening device"));
		return (errno);
	}
	d->mfd = fd;

	d->cmax = -1;
	if (ioctl(fd, SNDCTL_MIX_NREXT, &d->cmax) < 0) {
		perror(_("Error getting control count"));
		return (errno);
	}

	d->controls = calloc(d->cmax, sizeof (*d->controls));

	for (i = 0; i < d->cmax; i++) {
		ci = &d->controls[i];

		ci->ci.dev = -1;
		ci->ci.ctrl = i;

		if (ioctl(fd, SNDCTL_MIX_EXTINFO, &ci->ci) < 0) {
			perror(_("Error getting control info"));
			return (errno);
		}

		if (ci->ci.type == MIXT_ENUM) {
			ci->enump = calloc(1, sizeof (*ci->enump));
			ci->enump->dev = -1;
			ci->enump->ctrl = ci->ci.ctrl;

			if (ioctl(fd, SNDCTL_MIX_ENUMINFO, ci->enump) < 0) {
				perror(_("Error getting enum info"));
				return (errno);
			}
		}
	}

	return (0);
}


static int
load_devices(void)
{
	int rv = -1;
	int fd = -1;
	int i;
	oss_sysinfo si;
	device_t *d;

	if (devices != NULL) {
		/* already loaded */
		return (0);
	}

	if ((fd = open("/dev/mixer", O_RDWR)) < 0) {
		rv = errno;
		warn(_("Error opening mixer\n"));
		goto OUT;
	}

	if (ioctl(fd, SNDCTL_SYSINFO, &si) < 0) {
		rv = errno;
		perror(_("Error getting system information"));
		goto OUT;
	}

	for (i = 0; i < si.nummixers; i++) {

		struct stat sbuf;

		d = alloc_device();
		d->mixer.dev = i;

		if (ioctl(fd, SNDCTL_MIXERINFO, &d->mixer) != 0) {
			continue;
		}

		d->card.card = d->mixer.card_number;

		if ((ioctl(fd, SNDCTL_CARDINFO, &d->card) != 0) ||
		    (stat(d->mixer.devnode, &sbuf) != 0) ||
		    ((sbuf.st_mode & S_IFCHR) == 0)) {
			warn(_("Device present: %s\n"), d->mixer.devnode);
			free_device(d);
			continue;
		}
		d->devt = makedev(major(sbuf.st_rdev),
		    minor(sbuf.st_rdev) & ~(AUDIO_MN_TYPE_MASK));

		if ((rv = get_device_info(d)) != 0) {
			free_device(d);
			goto OUT;
		}
	}

	rv = 0;

OUT:
	if (fd >= 0)
		(void) close(fd);
	return (rv);
}


static int
ctype_valid(int type)
{
	switch (type) {
	case MIXT_ONOFF:
	case MIXT_ENUM:
	case MIXT_MONOSLIDER:
	case MIXT_STEREOSLIDER:
		return (1);
	default:
		return (0);
	}
}


static void
print_control_line(FILE *sfp, col_prt_t *colp, int vopt)
{
	int i;
	size_t *col_prtp;
	int *col_dpyp;
	int col_cnt;
	int col_type;
	int width;
	char *colstr;
	char cbuf[COL_MAX_SZ + 1];
	char line[128];
	char *colsep =  " ";

	if (sfp != NULL) {
		col_prtp = col_dpy_prt_tofile;
		col_dpyp = col_dpy_tofile;
		col_cnt = col_dpy_tofile_len;
	} else if (vopt) {
		col_prtp = col_dpy_prt_vopt;
		col_dpyp = col_dpy_vopt;
		col_cnt = col_dpy_vopt_len;
	} else {
		col_prtp = col_dpy_prt;
		col_dpyp = col_dpy;
		col_cnt = col_dpy_len;
	}

	line[0] = '\0';

	for (i = 0; i < col_cnt; i++) {
		col_type = col_dpyp[i];
		width = col_sz[col_type];
		colstr = *(char **)(((size_t)colp) + col_prtp[i]);

		(void) snprintf(cbuf, sizeof (cbuf), "%- *s",
		    width > 0 ? width : 1,
		    (colstr == NULL) ? "" : colstr);

		(void) strlcat(line, cbuf, sizeof (line));
		if (i < col_cnt - 1)
			(void) strlcat(line, colsep, sizeof (line));
	}

	(void) fprintf(sfp ? sfp : stdout, "%s\n", line);
}


static void
print_header(FILE *sfp, int vopt)
{
	col_prt_t col;

	if (sfp) {
		col.col_nm = _("#CONTROL");
		col.col_val = _("VALUE");
	} else {
		col.col_dv = _("DEVICE");
		col.col_nm = _("CONTROL");
		col.col_val = _("VALUE");
		col.col_sel = _("POSSIBLE");
	}
	print_control_line(sfp, &col, vopt);
}


static int
print_control(FILE *sfp, device_t *d, cinfo_t *cinfop, int vopt)
{
	int mfd = d->mfd;
	char *devnm = d->card.shortname;
	oss_mixer_value cval;
	char *str;
	int i;
	int idx = -1;
	int rv = -1;
	char valbuf[COL_VAL_SZ + 1];
	char selbuf[COL_SEL_SZ + 1];
	col_prt_t col;

	cval.dev = -1;
	cval.ctrl = cinfop->ci.ctrl;

	if (ctype_valid(cinfop->ci.type)) {
		if (ioctl(mfd, SNDCTL_MIX_READ, &cval) < 0) {
			rv = errno;
			perror(_("Error reading control\n"));
			return (rv);
		}
	} else {
		return (0);
	}

	/*
	 * convert the control value into a string
	 */
	switch (cinfop->ci.type) {
	case MIXT_ONOFF:
		(void) snprintf(valbuf, sizeof (valbuf), "%s",
		    cval.value ? _("on") : _("off"));
		break;

	case MIXT_MONOSLIDER:
		(void) snprintf(valbuf, sizeof (valbuf), "%d",
		    cval.value & 0xff);
		break;

	case MIXT_STEREOSLIDER:
		(void) snprintf(valbuf, sizeof (valbuf), "%d:%d",
		    (int)AUDIO_CTRL_STEREO_LEFT(cval.value),
		    (int)AUDIO_CTRL_STEREO_RIGHT(cval.value));
		break;

	case MIXT_ENUM:
		str = get_enum_str(cinfop, cval.value);
		if (str == NULL) {
			warn(_("Bad enum index %d for control '%s'\n"),
			    cval.value, cinfop->ci.extname);
			return (EINVAL);
		}

		(void) snprintf(valbuf, sizeof (valbuf), "%s", str);
		break;

	default:
		return (0);
	}

	/*
	 * possible control values (range/selection)
	 */
	switch (cinfop->ci.type) {
	case MIXT_ONOFF:
		(void) snprintf(selbuf, sizeof (selbuf), _("on,off"));
		break;

	case MIXT_MONOSLIDER:
		(void) snprintf(selbuf, sizeof (selbuf), "%d-%d",
		    cinfop->ci.minvalue, cinfop->ci.maxvalue);
		break;
	case MIXT_STEREOSLIDER:
		(void) snprintf(selbuf, sizeof (selbuf), "%d-%d:%d-%d",
		    cinfop->ci.minvalue, cinfop->ci.maxvalue,
		    cinfop->ci.minvalue, cinfop->ci.maxvalue);
		break;

	case MIXT_ENUM:
		/*
		 * display the first choice on the same line, then display
		 * the rest on multiple lines
		 */
		selbuf[0] = 0;
		for (i = 0; i < cinfop->ci.maxvalue; i++) {
			str = get_enum_str(cinfop, i);
			if (str == NULL)
				continue;

			if ((strlen(str) + 1 + strlen(selbuf)) >=
			    sizeof (selbuf)) {
				break;
			}
			if (strlen(selbuf)) {
				(void) strlcat(selbuf, ",", sizeof (selbuf));
			}

			(void) strlcat(selbuf, str, sizeof (selbuf));
		}
		idx = i;
		break;

	default:
		(void) snprintf(selbuf, sizeof (selbuf), "-");
	}

	col.col_dv = devnm;
	col.col_nm = strlen(cinfop->ci.extname) ?
	    cinfop->ci.extname : cinfop->ci.id;
	while (strchr(col.col_nm, '_') != NULL) {
		col.col_nm = strchr(col.col_nm, '_') + 1;
	}
	col.col_val = valbuf;
	col.col_sel = selbuf;
	print_control_line(sfp, &col, vopt);

	/* non-verbose mode prints don't display the enum values */
	if ((!vopt) || (sfp != NULL)) {
		return (0);
	}

	/* print leftover enum value selections */
	while ((idx >= 0) && (idx < cinfop->ci.maxvalue)) {
		selbuf[0] = 0;
		for (i = idx; i < cinfop->ci.maxvalue; i++) {
			str = get_enum_str(cinfop, i);
			if (str == NULL)
				continue;

			if ((strlen(str) + 1 + strlen(selbuf)) >=
			    sizeof (selbuf)) {
				break;
			}
			if (strlen(selbuf)) {
				(void) strlcat(selbuf, ",", sizeof (selbuf));
			}

			(void) strlcat(selbuf, str, sizeof (selbuf));
		}
		idx = i;
		col.col_dv = NULL;
		col.col_nm = NULL;
		col.col_val = NULL;
		col.col_sel = selbuf;
		print_control_line(sfp, &col, vopt);
	}

	return (0);
}


static int
set_device_control(device_t *d, cinfo_t *cinfop, char *wstr, int vopt)
{
	int mfd = d->mfd;
	oss_mixer_value cval;
	int wlen = strlen(wstr);
	int lval, rval;
	char *lstr, *rstr;
	char *str;
	int i;
	int rv = -1;

	cval.dev = -1;
	cval.ctrl = cinfop->ci.ctrl;
	cval.value = 0;

	switch (cinfop->ci.type) {
	case MIXT_ONOFF:
		cval.value = (strncmp(_("on"), wstr, wlen) == 0) ? 1 : 0;
		break;

	case MIXT_MONOSLIDER:
		cval.value = atoi(wstr);
		break;

	case MIXT_STEREOSLIDER:
		lstr = wstr;
		rstr = strchr(wstr, ':');
		if (rstr != NULL) {
			*rstr = '\0';
			rstr++;

			rval = atoi(rstr);
			lval = atoi(lstr);

			rstr--;
			*rstr = ':';
		} else {
			lval = atoi(lstr);
			rval = lval;
		}

		cval.value = AUDIO_CTRL_STEREO_VAL(lval, rval);
		break;

	case MIXT_ENUM:
		for (i = 0; i < cinfop->ci.maxvalue; i++) {
			str = get_enum_str(cinfop, i);
			if (str == NULL)
				continue;

			if (strncmp(wstr, str, wlen) == 0) {
				cval.value = i;
				break;
			}
		}

		if (i >= cinfop->ci.maxvalue) {
			warn(_("Invalid enumeration value\n"));
			return (EINVAL);
		}
		break;

	default:
		warn(_("Unsupported control type: %d\n"), cinfop->ci.type);
		return (EINVAL);
	}

	if (vopt) {
		msg(_("%s: '%s' set to '%s'\n"), d->card.shortname,
		    cinfop->ci.extname, wstr);
	}

	if (ioctl(mfd, SNDCTL_MIX_WRITE, &cval) < 0) {
		rv = errno;
		perror(_("Error writing control"));
		return (rv);
	}

	rv = 0;
	return (rv);
}


static void
help(void)
{
#define	HELP_STR	_(						\
"audioctl list-devices\n"						\
"	list all audio devices\n"					\
"\n"									\
"audioctl show-device [ -v ] [ -d <device> ]\n"				\
"	display information about an audio device\n"			\
"\n"									\
"audioctl show-control [ -v ] [ -d <device> ] [ <control> ... ]\n"	\
"	get the value of a specific control (all if not specified)\n"	\
"\n"									\
"audioctl set-control [ -v ] [ -d <device> ] <control> <value>\n"	\
"	set the value of a specific control\n"				\
"\n"									\
"audioctl save-controls [ -d <device> ] [ -f ] <file>\n"		\
"	save all control settings for the device to a file\n"		\
"\n"									\
"audioctl load-controls [ -d <device> ] <file>\n"			\
"	restore previously saved control settings to device\n"		\
"\n"									\
"audioctl help\n"							\
"	show this message.\n")

	(void) fprintf(stderr, HELP_STR);
}

dev_t
device_devt(char *name)
{
	struct stat	sbuf;

	if ((stat(name, &sbuf) != 0) ||
	    ((sbuf.st_mode & S_IFCHR) == 0)) {
		/* Not a device node! */
		return (0);
	}

	return (makedev(major(sbuf.st_rdev),
	    minor(sbuf.st_rdev) & ~(AUDIO_MN_TYPE_MASK)));
}

static device_t *
find_device(char *name)
{
	dev_t		devt;
	device_t	*d;

	/*
	 * User may have specified:
	 *
	 * /dev/dsp[<num>]
	 * /dev/mixer[<num>]
	 * /dev/audio[<num>9]
	 * /dev/audioctl[<num>]
	 * /dev/sound/<num>{,ctl,dsp,mixer}
	 * /dev/sound/<driver>:<num>{,ctl,dsp,mixer}
	 *
	 * We can canonicalize these by looking at the dev_t though.
	 */

	if (load_devices() != 0) {
		return (NULL);
	}

	if (name == NULL)
		name = getenv("AUDIODEV");

	if ((name == NULL) ||
	    (strcmp(name, "/dev/mixer") == 0)) {
		/* /dev/mixer node doesn't point to real hw */
		name = "/dev/dsp";
	}

	if (*name == '/') {
		/* if we have a full path, convert to the devt */
		if ((devt = device_devt(name)) == 0) {
			warn(_("No such audio device.\n"));
			return (NULL);
		}
		name = NULL;
	}

	for (d = devices; d != NULL; d = d->nextp) {
		oss_card_info *card = &d->card;

		if ((name) && (strcmp(name, card->shortname) == 0)) {
			return (d);
		}
		if (devt == d->devt) {
			return (d);
		}
	}

	warn(_("No such audio device.\n"));
	return (NULL);
}

int
do_list_devices(int argc, char **argv)
{
	int		optc;
	int		verbose = 0;
	device_t	*d;

	while ((optc = getopt(argc, argv, "v")) != EOF) {
		switch (optc) {
		case 'v':
			verbose++;
			break;
		default:
			help();
			return (-1);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0) {
		help();
		return (-1);
	}

	if (load_devices() != 0) {
		return (-1);
	}

	for (d = devices; d != NULL; d = d->nextp) {

		if ((d->mixer.enabled == 0) && (!verbose))
			continue;

		if (verbose) {
			msg(_("%s (%s)\n"), d->card.shortname,
			    d->mixer.devnode);
		} else {
			msg(_("%s\n"), d->card.shortname);
		}
	}

	return (0);
}

int
do_show_device(int argc, char **argv)
{
	int		optc;
	char		*devname = NULL;
	device_t	*d;

	while ((optc = getopt(argc, argv, "d:v")) != EOF) {
		switch (optc) {
		case 'd':
			devname = optarg;
			break;
		case 'v':
			break;
		default:
			help();
			return (-1);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0) {
		help();
		return (-1);
	}

	if ((d = find_device(devname)) == NULL) {
		return (ENODEV);
	}

	msg(_("Device: %s\n"), d->mixer.devnode);
	msg(_("  Name    = %s\n"), d->card.shortname);
	msg(_("  Config  = %s\n"), d->card.longname);

	if (strlen(d->card.hw_info)) {
		msg(_("  HW Info = %s"), d->card.hw_info);
	}

	return (0);
}

int
do_show_control(int argc, char **argv)
{
	int		optc;
	int		rval = 0;
	int		verbose = 0;
	device_t	*d;
	char		*devname = NULL;
	int		i;
	int		j;
	int		rv;
	char		*n;
	cinfo_t		*cinfop;

	while ((optc = getopt(argc, argv, "d:v")) != EOF) {
		switch (optc) {
		case 'd':
			devname = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			help();
			return (-1);
		}
	}
	argc -= optind;
	argv += optind;

	if ((d = find_device(devname)) == NULL) {
		return (ENODEV);
	}

	print_header(NULL, verbose);
	if (argc == 0) {
		/* do them all! */
		for (i = 0; i < d->cmax; i++) {

			cinfop = &d->controls[i];
			rv = print_control(NULL, d, cinfop, verbose);
			rval = rval ? rval : rv;
		}
		return (rval);
	}

	for (i = 0; i < argc; i++) {
		for (j = 0; j < d->cmax; j++) {
			cinfop = &d->controls[j];
			n = strrchr(cinfop->ci.extname, '_');
			n = n ? n + 1 : cinfop->ci.extname;
			if (strcmp(argv[i], n) == 0) {
				rv = print_control(NULL, d, cinfop, verbose);
				rval = rval ? rval : rv;
				break;
			}
		}
		/* Didn't find requested control */
		if (j == d->cmax) {
			warn(_("No such control: %s\n"), argv[i]);
			rval = rval ? rval : ENODEV;
		}
	}

	return (rval);
}

int
do_set_control(int argc, char **argv)
{
	int		optc;
	int		rval = 0;
	int		verbose = 0;
	device_t	*d;
	char		*devname = NULL;
	char		*cname;
	char		*value;
	int		i;
	int		found;
	int		rv;
	char		*n;
	cinfo_t		*cinfop;

	while ((optc = getopt(argc, argv, "d:v")) != EOF) {
		switch (optc) {
		case 'd':
			devname = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			help();
			return (-1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2) {
		help();
		return (-1);
	}
	cname = argv[0];
	value = argv[1];

	if ((d = find_device(devname)) == NULL) {
		return (ENODEV);
	}

	for (i = 0, found = 0; i < d->cmax; i++) {
		cinfop = &d->controls[i];
		n = strrchr(cinfop->ci.extname, '_');
		n = n ? n + 1 : cinfop->ci.extname;
		if (strcmp(cname, n) != 0) {
			continue;
		}
		found = 1;
		rv = set_device_control(d, cinfop, value, verbose);
		rval = rval ? rval : rv;
	}
	if (!found) {
		warn(_("No such control: %s\n"), cname);
	}

	return (rval);
}

int
do_save_controls(int argc, char **argv)
{
	int		optc;
	int		rval = 0;
	device_t	*d;
	char		*devname = NULL;
	char		*fname;
	int		i;
	int		rv;
	cinfo_t		*cinfop;
	FILE		*fp;
	int		fd;
	int		mode;

	mode = O_WRONLY | O_CREAT | O_EXCL;

	while ((optc = getopt(argc, argv, "d:f")) != EOF) {
		switch (optc) {
		case 'd':
			devname = optarg;
			break;
		case 'f':
			mode &= ~O_EXCL;
			mode |= O_TRUNC;
			break;
		default:
			help();
			return (-1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		help();
		return (-1);
	}
	fname = argv[0];

	if ((d = find_device(devname)) == NULL) {
		return (ENODEV);
	}

	if ((fd = open(fname, mode, 0666)) < 0) {
		perror(_("Failed to create file"));
		return (errno);
	}

	if ((fp = fdopen(fd, "w")) == NULL) {
		perror(_("Unable to open file\n"));
		(void) close(fd);
		(void) unlink(fname);
		return (errno);
	}

	(void) fprintf(fp, "# Device: %s\n", d->mixer.devnode);
	(void) fprintf(fp, "# Name    = %s\n", d->card.shortname);
	(void) fprintf(fp, "# Config  = %s\n", d->card.longname);

	if (strlen(d->card.hw_info)) {
		(void) fprintf(fp, "# HW Info = %s", d->card.hw_info);
	}
	(void) fprintf(fp, "#\n");

	print_header(fp, 0);

	for (i = 0; i < d->cmax; i++) {
		cinfop = &d->controls[i];
		rv = print_control(fp, d, cinfop, 0);
		rval = rval ? rval : rv;
	}

	(void) fclose(fp);

	return (rval);
}

int
do_load_controls(int argc, char **argv)
{
	int	optc;
	int	rval = 0;
	device_t	*d;
	char		*devname = NULL;
	char	*fname;
	char	*cname;
	char	*value;
	int	i;
	int	rv;
	cinfo_t	*cinfop;
	FILE	*fp;
	char	linebuf[MAXLINE];
	int	lineno = 0;
	int	found;

	while ((optc = getopt(argc, argv, "d:")) != EOF) {
		switch (optc) {
		case 'd':
			devname = optarg;
			break;
		default:
			help();
			return (-1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		help();
		return (-1);
	}
	fname = argv[0];

	if ((d = find_device(devname)) == NULL) {
		return (ENODEV);
	}

	if ((fp = fopen(fname, "r")) == NULL) {
		perror(_("Unable to open file"));
		return (errno);
	}

	while (fgets(linebuf, sizeof (linebuf), fp) != NULL) {
		lineno++;
		if (linebuf[strlen(linebuf) - 1] != '\n') {
			warn(_("Warning: line too long at line %d\n"), lineno);
			/* read in the rest of the line and discard it */
			while (fgets(linebuf, sizeof (linebuf), fp) != NULL &&
			    (linebuf[strlen(linebuf) - 1] != '\n')) {
				continue;
			}
			continue;
		}

		/* we have a good line ... */
		cname = strtok(linebuf, " \t\n");
		/* skip comments and blank lines */
		if ((cname == NULL) || (cname[0] == '#')) {
			continue;
		}
		value = strtok(NULL, " \t\n");
		if ((value == NULL) || (*cname == 0)) {
			warn(_("Warning: missing value at line %d\n"), lineno);
			continue;
		}

		for (i = 0, found = 0; i < d->cmax; i++) {
			/* save and restore requires an exact match */
			cinfop = &d->controls[i];
			if (strcmp(cinfop->ci.extname, cname) != 0) {
				continue;
			}
			found = 1;
			rv = set_device_control(d, cinfop, value, 0);
			rval = rval ? rval : rv;
		}
		if (!found) {
			warn(_("No such control: %s\n"), cname);
		}
	}
	(void) fclose(fp);

	return (rval);
}

int
mixer_walker(di_devlink_t dlink, void *arg)
{
	const char	*link;
	int		num;
	int		fd;
	int		verbose = *(int *)arg;
	int		num_offset;

	num_offset = sizeof ("/dev/mixer") - 1;

	link = di_devlink_path(dlink);

	if ((link == NULL) ||
	    (strncmp(link, "/dev/mixer", num_offset) != 0) ||
	    (!isdigit(link[num_offset]))) {
		return (DI_WALK_CONTINUE);
	}

	num = atoi(link + num_offset);
	if ((fd = open(link, O_RDWR)) < 0) {
		if (verbose) {
			if (errno == ENOENT) {
				msg(_("Device %s not present.\n"), link);
			} else {
				msg(_("Unable to open device %s: %s\n"),
				    link, strerror(errno));
			}
		}
		return (DI_WALK_CONTINUE);
	}

	if (verbose) {
		msg(_("Initializing link %s: "), link);
	}
	if (ioctl(fd, SNDCTL_SUN_SEND_NUMBER, &num) != 0) {
		if (verbose) {
			msg(_("failed: %s\n"), strerror(errno));
		}
	} else {
		if (verbose) {
			msg(_("done.\n"));
		}
	}
	(void) close(fd);
	return (DI_WALK_CONTINUE);
}

int
do_init_devices(int argc, char **argv)
{
	int			optc;
	di_devlink_handle_t	dlh;
	int			verbose = 0;

	while ((optc = getopt(argc, argv, "v")) != EOF) {
		switch (optc) {
		case 'v':
			verbose = 1;
			break;
		default:
			help();
			return (-1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0) {
		help();
		return (-1);
	}

	dlh = di_devlink_init(NULL, 0);
	if (dlh == NULL) {
		perror(_("Unable to initialize devlink handle"));
		return (-1);
	}

	if (di_devlink_walk(dlh, "^mixer", NULL, 0, &verbose,
	    mixer_walker) != 0) {
		perror(_("Unable to walk devlinks"));
		return (-1);
	}
	return (0);
}

int
main(int argc, char **argv)
{
	int rv = 0;
	int opt;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((opt = getopt(argc, argv, "h")) != EOF) {
		switch (opt) {
		case 'h':
			help();
			rv = 0;
			goto OUT;
		default:
			rv = EINVAL;
			break;
		}
	}

	if (rv) {
		goto OUT;
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		help();
		rv = EINVAL;
	} else if (strcmp(argv[0], "help") == 0) {
		help();
		rv = 0;
	} else if (strcmp(argv[0], "list-devices") == 0) {
		rv = do_list_devices(argc, argv);
	} else if (strcmp(argv[0], "show-device") == 0) {
		rv = do_show_device(argc, argv);
	} else if (strcmp(argv[0], "show-control") == 0) {
		rv = do_show_control(argc, argv);
	} else if (strcmp(argv[0], "set-control") == 0) {
		rv = do_set_control(argc, argv);
	} else if (strcmp(argv[0], "load-controls") == 0) {
		rv = do_load_controls(argc, argv);
	} else if (strcmp(argv[0], "save-controls") == 0) {
		rv = do_save_controls(argc, argv);
	} else if (strcmp(argv[0], "init-devices") == 0) {
		rv = do_init_devices(argc, argv);
	} else {
		help();
		rv = EINVAL;
	}

OUT:
	free_devices();
	return (rv);
}
