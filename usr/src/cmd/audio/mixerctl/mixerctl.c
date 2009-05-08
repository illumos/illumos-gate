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
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/soundcard.h>

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif

#define	_(s)	gettext(s)

#ifndef PATH_MAX
#define	PATH_MAX	1024
#endif

#define	AUDIO_CTRL_STEREO_LEFT(v)	((uint8_t)((v) & 0xff))
#define	AUDIO_CTRL_STEREO_RIGHT(v)	((uint8_t)(((v) >> 8) & 0xff))
#define	AUDIO_CTRL_STEREO_VAL(l, r)	(((l) & 0xff) | (((r) & 0xff) << 8))


/*
 * Column display information
 * All are related to the types enumerated in col_t and any change should be
 * reflected in the corresponding indices and offsets for all the variables
 * accordingly.  Most tweaks to the display can be done by adjusting the
 * values here.
 */

/* types of columns displayed */
typedef enum { COL_DV = 0, COL_NM, COL_VAL, COL_TYP, COL_SEL} col_t;

/* corresponding sizes of columns; does not include trailing null */
#define	COL_DV_SZ	16
#define	COL_NM_SZ	24
#define	COL_VAL_SZ	10
#define	COL_TYP_SZ	8
#define	COL_SEL_SZ	20
#define	COL_MAX_SZ	64

/* corresponding sizes of columns, indexed by col_t value */
static int col_sz[] = {
	COL_DV_SZ, COL_NM_SZ, COL_VAL_SZ, COL_TYP_SZ, COL_SEL_SZ
};

/* used by callers of the printing function */
typedef struct col_prt {
	char *col_dv;
	char *col_nm;
	char *col_val;
	char *col_typ;
	char *col_sel;
} col_prt_t;

/* columns displayed in order with vopt = 0 */
static int col_dpy[] = {COL_DV, COL_NM, COL_VAL, COL_SEL};
static int col_dpy_len = sizeof (col_dpy) / sizeof (*col_dpy);

/* tells the printing function what members to use; follows col_dpy[] */
static size_t col_dpy_prt[] = {
	offsetof(col_prt_t, col_dv),
	offsetof(col_prt_t, col_nm),
	offsetof(col_prt_t, col_val),
	offsetof(col_prt_t, col_sel)
};

/* columns displayed in order with vopt = 1 */
static int col_dpy_vopt[] = { COL_NM, COL_VAL, COL_TYP, COL_SEL};
static int col_dpy_vopt_len = sizeof (col_dpy_vopt) / sizeof (*col_dpy_vopt);

/* tells the printing function what members to use; follows col_dpy_vopt[] */
static size_t col_dpy_prt_vopt[] = {
	offsetof(col_prt_t, col_nm),
	offsetof(col_prt_t, col_val),
	offsetof(col_prt_t, col_typ),
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

typedef struct mlist {
	oss_card_info cdi;
	oss_mixerinfo mi;

	int cmax;
	cinfo_t *controls;

	int mfd;

	struct mlist *nextp;
} mlist_t;


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
mixers_free(mlist_t **mlistpp)
{
	mlist_t *mlp = *mlistpp;
	mlist_t *nextp;
	int i;

	while (mlp != NULL) {
		nextp = mlp->nextp;

		for (i = 0; i < mlp->cmax; i++) {
			if (mlp->controls[i].enump != NULL)
				free(mlp->controls[i].enump);
		}

		if (mlp->mfd >= 0)
			(void) close(mlp->mfd);

		free(mlp);
		mlp = nextp;
	}

	*mlistpp = NULL;
}


/*
 * adds to the end of mlistpp and returns a pointer to the new entry
 */
static mlist_t *
mlist_addnew(mlist_t **mlistpp)
{
	mlist_t *p;
	mlist_t *mlp = calloc(1, sizeof (*mlp));

	mlp->cdi.card = -1;
	mlp->mi.dev = -1;
	mlp->mfd = -1;

	if (*mlistpp == NULL)
		*mlistpp = mlp;
	else {
		for (p = *mlistpp; p->nextp != NULL; p = p->nextp) {}

		p->nextp = mlp;
	}
	return (mlp);
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
 * caller fills in mlistp->mi.devnode; func fills in the rest
 */
static int
mlist_getinfo(mlist_t *mlistp)
{
	int mfd = -1;
	int rv = -1;
	int i;
	char *mpath = mlistp->mi.devnode;
	cinfo_t *cinfop;

	mfd = open(mpath, O_RDWR);
	if (mfd < 0) {
		rv = errno;
		perror(_("Error opening mixer"));
		goto OUT;
	}
	mlistp->mfd = mfd;

	if (ioctl(mfd, SNDCTL_CARDINFO, &mlistp->cdi) < 0) {
		rv = errno;
		perror(_("Error getting card info"));
		goto OUT;
	}

	mlistp->cmax = -1;
	if (ioctl(mfd, SNDCTL_MIX_NREXT, &mlistp->cmax) < 0) {
		rv = errno;
		perror(_("Error getting control count"));
		goto OUT;
	}

	mlistp->controls = calloc(mlistp->cmax, sizeof (*mlistp->controls));

	for (i = 0; i < mlistp->cmax; i++) {
		cinfop = &mlistp->controls[i];

		cinfop->ci.dev = -1;
		cinfop->ci.ctrl = i;

		if (ioctl(mfd, SNDCTL_MIX_EXTINFO, &cinfop->ci) < 0) {
			rv = errno;
			perror(_("Error getting control info"));
			goto OUT;
		}

		if (cinfop->ci.type == MIXT_ENUM) {
			cinfop->enump = calloc(1, sizeof (*cinfop->enump));
			cinfop->enump->dev = -1;
			cinfop->enump->ctrl = cinfop->ci.ctrl;

			if (ioctl(mfd, SNDCTL_MIX_ENUMINFO,
			    cinfop->enump) < 0) {
				rv = errno;
				perror(_("Error getting enum info"));
				goto OUT;
			}
		}
	}

	rv = 0;

OUT:
	if (rv != 0) {
		(void) close(mfd);
		mlistp->mfd = -1;
	}
	return (rv);
}


static int
mixers_getinfo(char *devname, mlist_t **mlistpp)
{
	int rv = -1;
	int fd = -1;
	int i;
	oss_sysinfo si;
	oss_mixerinfo mi;
	mlist_t *mlp;
	char *mdef;

	mdef = devname ? devname : "/dev/mixer";

	if ((fd = open(mdef, O_RDWR)) < 0) {
		rv = errno;
		warn(_("Error opening mixer\n"));
		goto OUT;
	}

	if (devname == NULL) {
		if (ioctl(fd, SNDCTL_SYSINFO, &si) < 0) {
			rv = errno;
			perror(_("Error getting system information"));
			goto OUT;
		}

		for (i = 0; i < si.nummixers; i++) {
			mi.dev = i;
			if (ioctl(fd, SNDCTL_MIXERINFO, &mi) != 0)
				continue;

			mi.dev = -1;
			mlp = mlist_addnew(mlistpp);
			mlp->mi = mi;

			rv = mlist_getinfo(mlp);
			if (rv != 0)
				goto OUT;
		}
	} else {
		mi.dev = -1;
		if (ioctl(fd, SNDCTL_MIXERINFO, &mi) != 0) {
			rv = errno;
			perror(_("Error getting mixer information"));
			goto OUT;
		}
		mi.dev = -1;
		mlp = mlist_addnew(mlistpp);
		mlp->mi = mi;

		rv = mlist_getinfo(mlp);
		if (rv != 0)
			goto OUT;
	}

	rv = 0;

OUT:
	if (fd >= 0)
		(void) close(fd);
	return (rv);
}


static void
mixers_prt_mlist(FILE *sfp, int tofile, mlist_t *mlistp)
{
	oss_card_info *cdip = &mlistp->cdi;

	if (tofile) {
		(void) fprintf(sfp, "# Device: %s\n", mlistp->mi.devnode);
		(void) fprintf(sfp, "# Name    = %s\n", cdip->shortname);
		(void) fprintf(sfp, "# Config  = %s\n", cdip->longname);

		if (strlen(cdip->hw_info)) {
			(void) fprintf(sfp, "# HW Info = %s",
			    cdip->hw_info);
		}

		(void) fprintf(sfp, "#\n");
	} else {
		msg(_("Device: %s\n"), mlistp->mi.devnode);
		msg(_("  Name    = %s\n"), cdip->shortname);
		msg(_("  Config  = %s\n"), cdip->longname);

		if (strlen(cdip->hw_info)) {
			msg(_("  HW Info = %s"), cdip->hw_info);
		}

		msg("\n");
	}
}


static char *
ctype_str(int type)
{
	switch (type) {
	case MIXT_DEVROOT:
		return (_("root"));
	case MIXT_ONOFF:
		return (_("boolean"));
	case MIXT_ENUM:
		return (_("enum"));
	case MIXT_MONOSLIDER:
		return (_("mono"));
	case MIXT_STEREOSLIDER:
		return (_("stereo"));
	case MIXT_MARKER:
		return (_("marker"));
	case MIXT_GROUP:
		return (_("group"));
	default:
		return (_("unknown"));
	}
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
mixers_prt_ctl_line(FILE *sfp, int tofile, col_prt_t *colp, int vopt)
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

	if (tofile) {
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

	(void) fprintf(sfp, "%s\n", line);
}


static void
mixers_prt_ctl_hdr(FILE *sfp, int tofile, int vopt)
{
	col_prt_t col;

	if (tofile) {
		col.col_nm = _("#CONTROL");
		col.col_val = _("VALUE");
	} else {
		col.col_dv = _("DEVICE");
		col.col_nm = _("CONTROL");
		col.col_val = _("VALUE");
		col.col_typ = _("TYPE");
		col.col_sel = _("POSSIBLE");
	}
	mixers_prt_ctl_line(sfp, tofile, &col, vopt);
}


static int
mixers_prt_cinfo(FILE *sfp, int tofile, mlist_t *mlistp, cinfo_t *cinfop,
    int vopt)
{
	int mfd = mlistp->mfd;
	char *devnm = mlistp->cdi.shortname;
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
		/* if verbose, then continue to display the "pseudo" ctrls */
		if (vopt < 2 || tofile)
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
		(void) snprintf(valbuf, sizeof (valbuf), "-");
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
	col.col_typ = ctype_str(cinfop->ci.type);
	col.col_sel = selbuf;
	mixers_prt_ctl_line(sfp, tofile, &col, vopt);

	/* print leftover enum value selections */
	while ((!tofile) && (idx >= 0) && (idx < cinfop->ci.maxvalue)) {
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
		col.col_typ = NULL;
		col.col_sel = selbuf;
		mixers_prt_ctl_line(sfp, tofile, &col, vopt);
	}

	return (0);
}


static int
mixers_prt_controls(FILE *sfp, int tofile, mlist_t *mlistp, char *cname,
    int vopt)
{
	cinfo_t *cinfop;
	char *n;
	int i;
	int rv;
	int rval = 0;

	for (i = 0; i < mlistp->cmax; i++) {
		cinfop = &mlistp->controls[i];

		n = cinfop->ci.extname;
		while (strchr(n, '_') != NULL) {
			n = strchr(n, '_') + 1;
		}
		if (cname != NULL && strcmp(cname, n) != 0)
			continue;

		rv = mixers_prt_cinfo(sfp, tofile, mlistp, cinfop, vopt);
		if (rv != 0)
			rval = rv;
	}

	return (rval);
}


static int
mixers_sav_prt(FILE *sfp, int tofile, mlist_t *mlistp, char *cname,
    int eopt, int lopt, int vopt)
{
	mlist_t *mlp;
	int rv;
	int rval = 0;

	for (mlp = mlistp; mlp != NULL; mlp = mlp->nextp) {

		if ((mlp->mi.enabled == 0) && (vopt == NULL))
			continue;

		if ((lopt) || (vopt) || (tofile))
			mixers_prt_mlist(sfp, tofile, mlp);

		if (eopt)
			msg(_("Audio mixer for %s is enabled\n"),
			    mlp->mi.devnode);

		if ((lopt || eopt) && !tofile)
			continue;

		if ((mlistp->cmax > 0) && (vopt || (mlp == mlistp)))
			mixers_prt_ctl_hdr(sfp, tofile, vopt);
		rv = mixers_prt_controls(sfp, tofile, mlp, cname, vopt);
		if (rv != 0)
			rval = rv;

		if (vopt)
			msg("\n");
	}

	return (rval);
}

static int
mixers_save(mlist_t *mlistp, char *sstr, int ovopt, int vopt)
{
	FILE		*sfp;
	int		fp;
	int		retval;
	int		mode;

	mode = O_WRONLY | O_CREAT | (ovopt ? O_TRUNC : O_EXCL);

	if ((fp = open(sstr, mode, 0666)) < 0) {
		retval = errno;
		perror(_("Failed to create file"));
		return (retval);
	}

	sfp = fdopen(fp, "w");
	if (sfp == NULL)
		return (errno);
	retval = mixers_sav_prt(sfp, 1, mlistp, NULL, 0, 0, vopt);
	if (fclose(sfp))
		return (errno);
	return (retval);
}

static int
mixers_set_cinfo(mlist_t *mlistp, cinfo_t *cinfop, char *wstr, int vopt)
{
	int mfd = mlistp->mfd;
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
			warn(_("Invalid enumeration value"));
			return (EINVAL);
		}
		break;

	default:
		warn(_("Unsupported control type\n"));
		return (EINVAL);
	}

	if (vopt) {
		msg(_("%s: '%s' set to '%s'\n"), mlistp->cdi.shortname,
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


static int
mixers_set_controls(mlist_t *mlistp, char *cname, char *wstr, int vopt)
{
	cinfo_t *cinfop;
	char	*n;
	int i;
	int rv;
	int rval = 0;

	/*
	 * Note errors that occur but continue on to the next control;
	 * XXX
	 * we allow multiple controls with the same name
	 */
	for (i = 0; i < mlistp->cmax; i++) {
		cinfop = &mlistp->controls[i];
		n = cinfop->ci.extname;
		while (strchr(n, '_') != NULL) {
			n = strchr(n, '_') + 1;
		}
		if (cname != NULL && strcmp(cname, n) != 0)
			continue;

		rv = mixers_set_cinfo(mlistp, cinfop, wstr, vopt);
		if (rv != 0)
			rval = rv;
	}

	return (rval);
}


static int
mixers_set(mlist_t *mlistp, char *cname, char *wstr, int vopt)
{
	mlist_t *mlp;
	int rv;
	int rval = 0;

	/*
	 * Note errors that occur but continue on to the next mixer; this is
	 * to allow us to specify a single control to set on all mixers,
	 * if such a control is available on the mixer
	 */
	for (mlp = mlistp; mlp != NULL; mlp = mlp->nextp) {

		rv = mixers_set_controls(mlp, cname, wstr, vopt);
		if (rv != 0)
			rval = rv;
	}

	return (rval);
}

static int
mixers_restore(mlist_t *mlistp, char *sstr, int vopt)
{
	FILE	*sfp;
	int	retval = 0;
	int	rv;
	int	lineno = 0;
	char	linebuf[PATH_MAX];
	char	*col_nm, *col_val;

	sfp = fopen(sstr, "r");
	if (sfp == NULL)
		return (errno);

	while (fgets(linebuf, sizeof (linebuf), sfp) != NULL) {
		lineno++;
		if (linebuf[strlen(linebuf) - 1] != '\n') {
			warn(_("Warning: line too long at line %d\n"), lineno);
			/* read in the rest of the line and discard it */
			while (fgets(linebuf, sizeof (linebuf), sfp) != NULL &&
			    (linebuf[strlen(linebuf) - 1] != '\n')) {
				continue;
			}
			continue;
		}
		/* now we have a good line ... */
		col_nm = strtok(linebuf, " \t\n");
		/* skip comments and blank lines */
		if ((col_nm == NULL) || (col_nm[0] == '#')) {
			continue;
		}
		col_val = strtok(NULL, " \t\n");
		if ((col_val == NULL) || (*col_val == 0)) {
			warn(_("Warning: missing value at line %d\n"), lineno);
			continue;
		}

		rv = mixers_set(mlistp, col_nm, col_val, vopt);
		if (rv)
			retval = rv;
	}

	if (fclose(sfp))
		return (errno);
	return (retval);
}


static void
help(void)
{
#define	HELP_STR	_(						\
"mixerctl [ -d <device> | -a ] [ -f ] [ -s <file> | -r <file> ]\n"	\
"mixerctl [ -d <device> | -a ] [ -Civ ]\n"				\
"mixerctl [ -d <device> | -a ] [ -v ] -c <ctrl> [ -w <value> ]\n"	\
"\n"									\
"	-d	<device> = audio device path\n"				\
"	-s	<file> = save control settings to file\n"		\
"	-r	<file> = restore control settings from file\n"		\
"	-f	force overwrite of existing control settings file\n"	\
"	-a	process all audio devices\n"				\
"	-C	dump all audio controls\n"				\
"	-i	list audio device info\n"				\
"	-v	verbose output; also affects output for -w;\n"		\
"		multiple uses increase verbosity\n"			\
"	-c	<ctrl> = control name\n"				\
"	-w	<value> = control value\n"				\
"		{integer} for mono; {integer:integer} for stereo;\n"	\
"		{string} for enum; {on|off} for boolean\n"		\
"\n"									\
"	without arguments, device info for all devices will be listed\n")

	(void) fprintf(stderr, HELP_STR);
}


#define	strstarts(s, prefix)	strncmp(s, prefix, strlen(prefix))

int
main(int argc, char **argv)
{
	int rv = -1;
	int opt;
	char *dstr = NULL;
	char *cstr = NULL;
	char *wstr = NULL;
	char *sstr = NULL;
	int aopt = 0;
	int iopt = 0;
	int vopt = 0;
	int eopt = 0;
	int oopt = 0;
	int Copt = 0;
	int sopt = 0;
	int ropt = 0;
	int ovopt = 0;
	mlist_t *mlistp = NULL;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((opt = getopt(argc, argv, "Cd:c:w:fs:r:ivhaeo")) != EOF) {
		switch (opt) {
		case 'C':
			Copt++;
			break;
		case 'a':
			aopt++;
			break;
		case 'e':
			eopt++;
			break;
		case 'f':
			ovopt++;
			break;
		case 'o':
			oopt++;
			break;
		case 'd':
			dstr = optarg;
			break;

		case 'c':
			cstr = strdup(optarg);
			break;
		case 'w':
			wstr = strdup(optarg);
			break;
		case 's':
			sopt++;
			sstr = strdup(optarg);
			break;
		case 'r':
			ropt++;
			sstr = strdup(optarg);
			break;
		case 'i':
			iopt++;
			break;
		case 'v':
			vopt++;
			break;
		case 'h':
			help();
			rv = 0;
			goto OUT;
		default:
			help();
			rv = EINVAL;
			goto OUT;
		}
	}

	if (((eopt || oopt) && (Copt || sopt || ropt)) ||
	    (Copt && cstr) ||
	    ((Copt || cstr) && (sopt || ropt)) ||
	    (aopt && dstr) ||
	    (sopt && ropt)) {
		warn(_("Illegal combination of options.\n"));
		rv = EINVAL;
		goto OUT;
	}

	if ((Copt) && (dstr == NULL)) {
		/* asume -a when dumping controls with -C */
		aopt++;
	}

	if ((!aopt) && (dstr == NULL)) {
		/* if no mixer specified, assume a default */
		dstr = getenv("AUDIODEV");
		if (dstr == NULL) {
			dstr = "/dev/audio";
		}
	}

	if (oopt) {
		/* legacy option, nuke it */
		warn(_("Cannot disable audio mixer\n"));
		rv = EINVAL;
		goto OUT;
	}

	if (dstr != NULL) {
		char	scratch[MAXPATHLEN + 1];
		char	*s;
		char *bn;
		int num = -1;
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
		 * We want to deal only with SADA names though.
		 */

		if (strcmp(dstr, "/dev/mixer") == 0) {
			/* /dev/mixer node doesn't point to real hw */
			dstr = "/dev/dsp";
		}
		if ((bn = strrchr(dstr, '/')) != NULL) {
			bn++;
		} else {
			bn = dstr;
		}
		if ((strstarts(dstr, "/dev/sound/") == 0) &&
		    ((strrchr(dstr, ':')) != NULL)) {
			char	*colon;
			int	n;

			(void) strlcpy(scratch, dstr, sizeof (scratch));
			colon = strrchr(scratch, ':');
			colon++;
			n = atoi(colon);
			*colon = '\0';
			(void) snprintf(colon,
			    sizeof (scratch) - strlen(scratch), "%dmixer", n);

			dstr = strdup(scratch);

		} else if ((strcmp(dstr, "/dev/audio") == 0) ||
		    (strcmp(dstr, "/dev/audioctl") == 0) ||
		    (strcmp(dstr, "/dev/dsp") == 0)) {
			/*
			 * "default" device, read the link,
			 * ensuring NULL termination.
			 */
			if (readlink(dstr, scratch, MAXPATHLEN) >= 0) {
				scratch[MAXPATHLEN] = 0;
				if ((s = strchr(scratch, '/')) != NULL) {
					num = atoi(s + 1);
				}
			}

		} else if ((strstarts(dstr, "/dev/sound/") == 0) &&
		    (isdigit(bn[0]))) {
			num = atoi(bn);
		}
		if (num >= 0) {
			/* Convert SADA name to OSS name */
			(void) snprintf(scratch, sizeof (scratch),
			    "/dev/mixer%d", num);
			dstr = strdup(scratch);
		} else {
			dstr = strdup(dstr);
		}
	}

	if (wstr != NULL && cstr == NULL) {
		warn(_("Control value specified without name\n"));
		rv = EINVAL;
		goto OUT;
	}

	if ((cstr == NULL) && (Copt == 0) && (eopt == 0) &&
	    (ropt == 0) && (sopt == 0)) {
		iopt = 1;
	}

	rv = mixers_getinfo(dstr, &mlistp);
	if (rv != 0)
		goto OUT;

	if (wstr != NULL) {
		rv = mixers_set(mlistp, cstr, wstr, vopt);
		goto OUT;
	}

	if (ropt) {
		rv = mixers_restore(mlistp, sstr, vopt);
		goto OUT;
	}

	if (sopt) {
		rv = mixers_save(mlistp, sstr, ovopt, vopt);
		goto OUT;
	}

	rv = mixers_sav_prt(stdout, 0, mlistp, cstr, eopt, iopt, vopt);
	if (rv != 0)
		goto OUT;

	rv = 0;

OUT:
	if (dstr != NULL)
		free(dstr);
	if (cstr != NULL)
		free(cstr);
	if (wstr != NULL)
		free(wstr);
	if (sstr != NULL)
		free(sstr);

	mixers_free(&mlistp);
	return (rv);
}
