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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <libdevinfo.h>
#include <errno.h>
#include <libintl.h>
#define	CFGA_PLUGIN_LIB
#include <config_admin.h>
#include "ap.h"
#include <sys/obpdefs.h>
#include <sys/processor.h>
#include <sys/stat.h>
#include <sys/sbd_ioctl.h>
#include <sys/int_fmtio.h>

static cfga_err_t
ap_getncm(apd_t *a, sbd_comp_type_t type, int *ncm)
{
	sbd_ioctl_arg_t *ctl;
	sbd_getncm_cmd_t *cp;

	if (a->fd == -1 || a->ctl == NULL)
		return (CFGA_LIB_ERROR);

	ctl = (sbd_ioctl_arg_t *)a->ctl;
	ctl->ic_type = type;
	ctl->ic_name[0] = '\0';
	ctl->ic_unit = 0;
	ctl->i_len = 0;
	ctl->i_opts = NULL;

	DBG("ioctl(%d SBD_CMD_GETNCM, 0x%p)\n", a->fd, (void *)ctl);

	if (ioctl(a->fd, SBD_CMD_GETNCM, ctl) == -1) {
		ap_err(a, ERR_CMD_FAIL, CMD_GETNCM);
		return (CFGA_ERROR);
	}

	cp = &ctl->i_cmd.cmd_getncm;

	DBG("ncm(%d)=%d\n", type, cp->g_ncm);

	if (ncm)
		*ncm = cp->g_ncm;

	return (CFGA_OK);
}

cfga_err_t
ap_stat(apd_t *a, int all)
{
	int fd;
	int ncm;
	int select;
	int stsize;
	int oflag;
	sbd_stat_cmd_t *sc;
	sbd_ioctl_arg_t *ctl;
	cfga_err_t rc;
	sbd_stat_t *new_stat;

	rc = CFGA_LIB_ERROR;

	DBG("ap_stat(%s)\n", a->path);

	/* Open the file descriptor if not already open */
	if (a->fd == -1) {
		DBG("open(%s)\n", a->path);
		if (a->statonly != 0)
			oflag = O_RDONLY;
		else
			oflag = O_RDWR;
		if ((fd = open(a->path, oflag, 0)) == -1) {
			ap_err(a, ERR_AP_INVAL);
			return (rc);
		}
		a->fd = fd;
	} else {
		fd = a->fd;
	}

	if (a->ctl == NULL && (a->ctl = calloc(1, sizeof (*ctl))) == NULL) {
		ap_err(a, ERR_CMD_FAIL, CMD_STATUS);
		return (rc);
	}

	if (a->tgt == AP_BOARD) {
		/*
		 * The status target is the board. If we need to
		 * return component data (to support the -a option),
		 * get the number of components on the board.
		 */
		select = 0;
		if (all) {
			cfga_err_t r;
			r = ap_getncm(a, SBD_COMP_NONE, &ncm);
			if (r != CFGA_OK) {
				return (r);
			}
		} else {
			ncm = 0;
		}
	} else {
		select = 1;
		ncm = 1;
	}

	DBG("ncm=%d\n", ncm);

	a->ncm = ncm;

	/*
	 * The status structure contains space for one component;
	 * add the space for the other components if necessary.
	 */
	stsize = sizeof (sbd_stat_t);
	if (ncm > 1)
		stsize += ((ncm - 1) * sizeof (sbd_dev_stat_t));

	if ((new_stat = realloc(a->stat, stsize)) == NULL) {
		ap_err(a, ERR_CMD_FAIL, CMD_STATUS);
		return (rc);
	}

	a->stat = new_stat;


	ctl = (sbd_ioctl_arg_t *)a->ctl;
	ctl->i_len = 0;
	ctl->i_opts = NULL;
	ctl->ic_type = SBD_COMP_NONE;
	if (all)
		ctl->i_flags |= SBD_FLAG_ALLCMP;
	sc = &ctl->i_cmd.cmd_stat;
	sc->s_statp = (caddr_t)a->stat;
	sc->s_nbytes = stsize;

	if (select) {
		/*
		 * The target is a specific component.  Pass its
		 * name and unit number to the driver.  Set its
		 * type to UNKNOWN since the plugin does not know
		 * the type of the component specified by the user.
		 */
		ctl->ic_type = SBD_COMP_UNKNOWN;
		ctl->ic_unit = a->cnum;
		(void) strcpy(ctl->ic_name, a->cname);
	}

	DBG("ioctl(%d SBD_CMD_STATUS, sc=0x%p sz=%d flags=%d",
	    fd, (void *)sc->s_statp, sc->s_nbytes, ctl->i_flags);
	if (select)
		DBG(" cname=<%s> cnum=%d", a->cname, a->cnum);
	DBG(")\n");

	if (ioctl(fd, SBD_CMD_STATUS, ctl) == -1) {
		ap_err(a, ERR_CMD_FAIL, CMD_STATUS);
		rc = CFGA_ERROR;
	} else
		rc = CFGA_OK;

	DBG("ap_stat()=%d\n", rc);

	return (rc);
}

/*
 * Convert a component to a target type.
 */
static ap_target_t
ap_cm_tgt(sbd_comp_type_t type)
{
	ap_target_t c;

	switch (type) {
	case SBD_COMP_CPU:
		c = AP_CPU;
		break;
	case SBD_COMP_MEM:
		c = AP_MEM;
		break;
	case SBD_COMP_IO:
		c = AP_IO;
		break;
	case SBD_COMP_CMP:
		c = AP_CMP;
		break;
	default:
		c = AP_NONE;
		break;
	}

	return (c);
}

cfga_err_t
apd_init(apd_t *a, int all)
{
	int i;
	char *cn, *dn;
	sbd_stat_t *st;
	sbd_dev_stat_t *dst;
	cfga_err_t rc;

	/*
	 * Ideally, for board operations (other than status) it is not
	 * necessary to issue the STATUS ioctl.  The call however allows a
	 * final sanity check to ensure that the board number returned
	 * by the driver matches the plugin's notion of the board number
	 * as extracted from the ap_id.  If this check is not desirable,
	 * we can change the code to issue the status call only when
	 * necessary.  Note that for component operations, we need to do
	 * the STATUS in order to figure out the component type and
	 * validate the command/options accordingly. XXX
	 */
	if ((rc = ap_stat(a, all)) != CFGA_OK) {
		ap_err(a, ERR_AP_INVAL);
		return (rc);
	}

	st = (sbd_stat_t *)a->stat;

	/*
	 * Set the component count to the returned stat count.
	 */
	if (a->ncm > st->s_nstat) {

		DBG("ncm=%d nstat=%d (truncated)\n", a->ncm, st->s_nstat);

		a->ncm = st->s_nstat;
	}

	if (a->tgt == AP_BOARD) {

		DBG("tgt=%d\n", a->tgt);

		/*
		 * Initialize the RCM module here so that it can record
		 * the initial state of the capacity information.
		 */
		rc = ap_rcm_init(a);

		return (rc);
	}

	a->tgt = AP_NONE;
	cn = a->cname;

	DBG("cname=<%s> cunit=<%d>\n", a->cname, a->cnum);

	for (dst = st->s_stat, i = 0; i < st->s_nstat; i++, dst++) {

		DBG("ds_name,ds_unit,ds_type=<%s,%d,%d> ",
		    dst->ds_name, dst->ds_unit, dst->ds_type);

		if (dst->ds_unit != a->cnum)
			continue;

		/*
		 * Consider the names matched if they are either
		 * both absent or the same. It is conceivable that
		 * a NULL component name be considered valid
		 * by the driver.
		 */
		dn = dst->ds_name;

		if ((dn == NULL && cn == NULL) ||
		    (dn != NULL && cn != NULL && strcmp(dn, cn) == 0)) {
			a->tgt = ap_cm_tgt(dst->ds_type);
			a->cmstat = (void *)dst;

			DBG("found ");

			break;
		}
	}

	DBG("tgt=%d\n", a->tgt);

	if (a->tgt == AP_NONE) {
		ap_err(a, ERR_CM_INVAL, a->cid);
		return (CFGA_INVAL);
	}

	/*
	 * Initialize the RCM module here so that it can record
	 * the initial state of the capacity information.
	 */
	rc = ap_rcm_init(a);

	return (rc);
}

void
apd_free(apd_t *a)
{
	if (a == NULL)
		return;

	ap_rcm_fini(a);

	if (a->fd != -1)
		(void) close(a->fd);

	s_free(a->options);
	s_free(a->path);
	s_free(a->drv);
	s_free(a->target);
	s_free(a->cname);
	s_free(a->ctl);
	s_free(a->stat);

	free(a);
}

apd_t *
apd_alloc(const char *ap_id, cfga_flags_t flags, char **errstring,
	struct cfga_msg *msgp, struct cfga_confirm *confp)
{
	apd_t *a;

	if ((a = calloc(1, sizeof (*a))) == NULL)
		return (NULL);

	if (errstring != NULL)
		*errstring = NULL;

	a->fd = -1;
	a->errstring = errstring;
	a->msgp = msgp;
	a->confp = confp;
	a->class = "sbd";

	if (flags & CFGA_FLAG_LIST_ALL)
		ap_setopt(a, OPT_LIST_ALL);
	if (flags & CFGA_FLAG_FORCE)
		ap_setopt(a, OPT_FORCE);
	if (flags & CFGA_FLAG_VERBOSE)
		ap_setopt(a, OPT_VERBOSE);

	if (ap_id == NULL || ap_parse(a, ap_id) == 0)
		return (a);

	apd_free(a);
	return (NULL);
}

/*
 * The type field is defined to be parsable by cfgadm(8): It
 * must not contain white space characters. This function
 * converts white space to underscore.
 */

static void
parsable_strncpy(char *op, const char *ip, size_t n)
{
	char c;

	while (n-- > 0) {
		c = *ip++;
		if (isspace(c))
			c = '_';
		*op++ = c;
		if (c == '\0')
			break;
	}
}

void
ap_init(apd_t *a, cfga_list_data_t *ap)
{
	sbd_stat_t *st;

	st = (sbd_stat_t *)a->stat;

	DBG("ap_init bd=%d rs=%d os=%d type=<%s>\n",
	    a->bnum, st->s_rstate, st->s_ostate, st->s_type);

	parsable_strncpy(ap->ap_type, st->s_type, sizeof (ap->ap_type));
	ap->ap_r_state = (cfga_stat_t)st->s_rstate;
	ap->ap_o_state = (cfga_stat_t)st->s_ostate;
	ap->ap_cond = (cfga_cond_t)st->s_cond;
	ap->ap_busy = (cfga_busy_t)st->s_busy;
	ap->ap_status_time = st->s_time;
	ap_info(a, ap->ap_info, AP_BOARD);
}

typedef struct {
	int cmd;
	int ioc;
} ap_ioc_t;

static ap_ioc_t
ap_iocs[] =  {
	{CMD_ASSIGN,	  SBD_CMD_ASSIGN	},
	{CMD_POWERON,	  SBD_CMD_POWERON	},
	{CMD_TEST,	  SBD_CMD_TEST		},
	{CMD_CONNECT,	  SBD_CMD_CONNECT	},
	{CMD_CONFIGURE,	  SBD_CMD_CONFIGURE	},
	{CMD_UNCONFIGURE, SBD_CMD_UNCONFIGURE	},
	{CMD_DISCONNECT,  SBD_CMD_DISCONNECT	},
	{CMD_POWEROFF,	  SBD_CMD_POWEROFF	},
	{CMD_STATUS,	  SBD_CMD_STATUS	},
	{CMD_GETNCM,	  SBD_CMD_GETNCM	},
	{CMD_UNASSIGN,	  SBD_CMD_UNASSIGN	},
	{CMD_PASSTHRU,	  SBD_CMD_PASSTHRU	},
	{CMD_NONE,	  0			}
};

static int
ap_ioc(int cmd)
{
	ap_ioc_t *acp;

	DBG("ap_ioc(%d)\n", cmd);

	for (acp = ap_iocs; acp->cmd != CMD_NONE; acp++)
		if (acp->cmd == cmd)
			break;

	DBG("ap_ioc(%d)=0x%x\n", cmd, acp->ioc);

	return (acp->ioc);
}

cfga_err_t
ap_suspend_query(apd_t *a, int cmd, int *check)
{
	int ioc;
	sbd_dev_stat_t *dst;

	/*
	 * See if the a quiesce operation is required for
	 * this command for any of the components.  If the
	 * command does not map to an ioctl, then there is
	 * nothing to do.
	 */
	if ((ioc = ap_ioc(cmd)) == 0)
		return (CFGA_OK);
	else if (a->tgt == AP_BOARD) {
		int i;

		dst = ((sbd_stat_t *)a->stat)->s_stat;

		/*
		 * See if any component requires a
		 * OS suspension for this command.
		 */
		for (i = 0; i < a->ncm; i++, dst++)
			if (SBD_CHECK_SUSPEND(ioc, dst->ds_suspend))
				(*check)++;
	} else {
		dst = (sbd_dev_stat_t *)a->cmstat;
		if (SBD_CHECK_SUSPEND(ioc, dst->ds_suspend))
				(*check)++;
	}

	return (CFGA_OK);
}

cfga_err_t
ap_platopts_check(apd_t *a, int first, int last)
{
	int c;
	uint_t platopts;
	sbd_stat_t *stat;
	ap_opts_t *opts;

	opts = &a->opts;
	stat = (sbd_stat_t *)a->stat;
	platopts = stat->s_platopts;


	/*
	 * If there are no platform options set then there
	 * is no need to check this operation
	 */
	if (opts->platform == NULL)
		return (CFGA_OK);

	/*
	 * Check if any of the steps in the sequence
	 * allows for a platform option
	 */
	for (c = first; c <= last; c++)
		/*
		 * If the platopt is set it means that the platform does not
		 * support options for this cmd
		 */
		if (SBD_CHECK_PLATOPTS(ap_ioc(c), platopts) == 0) {
			return (CFGA_OK);
		}

	ap_err(a, ERR_OPT_INVAL, opts->platform);

	return (CFGA_INVAL);
}

cfga_err_t
ap_ioctl(apd_t *a, int cmd)
{
	int ioc;
	sbd_ioctl_arg_t *ctl;

	if (a->ctl == NULL && (a->ctl = calloc(1, sizeof (*ctl))) == NULL) {
		ap_err(a, ERR_CMD_FAIL, cmd);
		return (CFGA_LIB_ERROR);
	}

	ap_msg(a, MSG_ISSUE, cmd, a->target);

	ctl = (sbd_ioctl_arg_t *)a->ctl;
	ctl->i_flags = 0;
	ctl->i_len = 0;
	ctl->i_opts = NULL;

	if (ap_getopt(a, OPT_FORCE))
		ctl->i_flags |= SBD_FLAG_FORCE;
	if (ap_getopt(a, OPT_SUSPEND_OK))
		ctl->i_flags |= SBD_FLAG_QUIESCE_OKAY;

	if (a->tgt == AP_BOARD)
		ctl->ic_type = SBD_COMP_NONE;
	else {
		ctl->ic_type = SBD_COMP_UNKNOWN;
		ctl->ic_unit = a->cnum;
		(void) strcpy(ctl->ic_name, a->cname);
	}

	if (!(ioc = ap_ioc(cmd))) {
		ap_err(a, ERR_CMD_FAIL, cmd);
		return (CFGA_LIB_ERROR);
	}

	/*
	 * If this is a passthru command, pass all of its
	 * options; otherwise, pass all options after the
	 * platform keyword.
	 */
	if (cmd == CMD_PASSTHRU)
		ctl->i_opts = a->options;
	else {
		/*
		 * Only pass the platform option to the cmds that the platform
		 * has specified as ok
		 */
		sbd_stat_t *stat;

		stat = (sbd_stat_t *)a->stat;
		if (SBD_CHECK_PLATOPTS(ioc, stat->s_platopts) == 0)
			ctl->i_opts = a->opts.platform;
	}

	if (ctl->i_opts != NULL)
		ctl->i_len = strlen(ctl->i_opts) + 1;

	DBG("i_opts=%s\n", ctl->i_opts ? ctl->i_opts : "NULL");
	DBG("i_flags=0x%x\n", ctl->i_flags);

	if (ap_getopt(a, OPT_SIM)) {
		ap_msg(a, MSG_DONE, cmd, a->target);
		return (CFGA_OK);
	}

	if (ioctl(a->fd, ioc, ctl) == -1) {
		ap_err(a, ERR_CMD_FAIL, cmd);
		return (CFGA_ERROR);
	}
	ap_msg(a, MSG_DONE, cmd, a->target);

	return (CFGA_OK);
}

/*
 * Return the error string corresponding to a given error code.
 * String table and error code sets are provided by sbd_etab.  This data
 * structure is automatically generated at compile time from the error
 * code and message text information in sbd_ioctl.h.
 */
static char *
mod_estr(int code)
{
	int i;
	char *s;
	extern sbd_etab_t sbd_etab[];
	extern int sbd_etab_len;

	s = NULL;

	for (i = 0; i < sbd_etab_len; i++) {
		sbd_etab_t *eptr = &sbd_etab[i];

		if ((code >= eptr->t_base) && (code <= eptr->t_bnd)) {
			int index;
			char **t_text;

			/*
			 * Found it. Just extract the string
			 */
			index = code - eptr->t_base;
			t_text = eptr->t_text;
			s = strdup(t_text[index]);
			break;
		}
	}

	if (i == sbd_etab_len) {
		char buf[32];

		(void) snprintf(buf, sizeof (buf), "error %d", code);
		s = strdup(buf);
	}

	return (s);
}

char *
ap_sys_err(apd_t *a, char **rp)
{
	int code;
	char *p;
	char *rsc;

	sbd_ioctl_arg_t *ctl = (sbd_ioctl_arg_t *)a->ctl;

	/*
	 * The driver sets the errno to EIO if it returns
	 * more detailed error info via e_code.  In all
	 * other cases, use standard error text.
	 */
	if (ctl == NULL || errno != EIO) {
		if ((p = strerror(errno)) != NULL)
			p = strdup(p);
		return (p);
	}

	code = ctl->ie_code;
	rsc = ctl->ie_rsc;

	if (code)
		p = mod_estr(code);
	else if ((p = strerror(errno)) != NULL)
		p = strdup(p);

	if (*rsc != '\0' && rp != NULL)
		*rp = strdup(rsc);

	return (p);
}

/*
 * cfgadm -o err=plugin-err,cmd=name,code=ecode -x errtest ap_id.
 */
cfga_err_t
ap_test_err(apd_t *a, const char *options)
{
	int err;
	int cmd;
	ap_opts_t *opts;
	sbd_ioctl_arg_t ctl;

	opts = &a->opts;
	err = opts->err;
	cmd = CMD_DISCONNECT;

	DBG("ap_test_err(%d %d)\n", opts->code, opts->err);

	switch (err) {
	case ERR_CMD_INVAL:
		ap_err(a, err, ap_cmd_name(cmd));
		break;
	case ERR_CMD_NOTSUPP:
		ap_err(a, err, cmd);
		break;
	case ERR_CMD_FAIL:
		errno = EIO;
		ctl.i_err.e_code = opts->code;
		*ctl.i_err.e_rsc = '\0';
		a->ctl = &ctl;
		ap_err(a, err, cmd);
		a->ctl = NULL;
		break;
	case ERR_OPT_INVAL:
		ap_err(a, err, options);
		break;
	case ERR_OPT_NOVAL:
		ap_err(a, err, options);
		break;
	case ERR_AP_INVAL:
		ap_err(a, err);
		break;
	case ERR_CM_INVAL:
		ap_err(a, err, a->cid);
		break;
	case ERR_TRANS_INVAL:
		ap_err(a, ERR_TRANS_INVAL, cmd);
		break;
	}

	return (CFGA_LIB_ERROR);
}

static char *
ap_help_topics[] = {
	"\nSbd specific commands/options:\n\n",
	"\tcfgadm [-o parsable] -l ap_id\n",
	"\tcfgadm [-o unassign|nopoweroff] -c disconnect ap_id\n",
	"\tcfgadm -t ap_id\n",
	"\tcfgadm -x assign ap_id\n",
	"\tcfgadm -x unassign ap_id\n",
	"\tcfgadm -x poweron ap_id\n",
	"\tcfgadm -x poweroff ap_id\n",
	NULL
};

/*ARGSUSED*/
cfga_err_t
ap_help(struct cfga_msg *msgp, const char *options, cfga_flags_t flags)
{
	int len;
	char **p;
	char *q;

	if (msgp == NULL || msgp->message_routine == NULL)
		return (CFGA_OK);

	for (p = ap_help_topics; *p != NULL; p++) {
		if ((len = strlen(*p)) == 0)
			continue;
		if ((q = (char *)calloc(len + 1, 1)) == NULL)
			continue;
		(void) strcpy(q, *p);
		(*msgp->message_routine)(msgp->appdata_ptr, q);
		free(q);
	}

	return (CFGA_OK);
}

static char *
ap_dev_type(sbd_dev_stat_t *dst)
{
	char *type;

	switch (dst->ds_type) {
	case SBD_COMP_CPU:
		type = "cpu";
		break;
	case SBD_COMP_MEM:
		type = "memory";
		break;
	case SBD_COMP_IO:
		type = "io";
		break;
	case SBD_COMP_CMP:
		type = "cpu";
		break;
	default:
		type = "other";
		break;
	}

	DBG("ap_dev_type(%d)=%s\n", dst->ds_type, type);

	return (type);
}

static sbd_dev_stat_t *
ap_cm_stat(apd_t *a, int seq)
{
	sbd_stat_t *st;

	if (seq == CM_DFLT)
		return (a->cmstat);

	st = (sbd_stat_t *)a->stat;
	return (st->s_stat + seq);
}

char *
ap_cm_devpath(apd_t *a, int seq)
{
	int len;
	char *path;
	char *devpath;
	sbd_io_stat_t *dst;


	/*
	 * If no component sequence number is provided
	 * default to the current target component.
	 * Assume an io component so that we can get
	 * the path if the component is indeed of type io.
	 */
	if (seq == CM_DFLT)
		dst = (sbd_io_stat_t *)a->cmstat;
	else {
		sbd_stat_t *st;
		st = (sbd_stat_t *)a->stat;
		dst = (sbd_io_stat_t *)st->s_stat + seq;
	}

	if (dst->is_type != SBD_COMP_IO)
		path = NULL;
	else
		path = dst->is_pathname;

	if (str_valid(path)) {
		len = strlen(DEVDIR) + strlen(path) + 1;

		if ((devpath = calloc(1, len)) == NULL)
			return (NULL);

		(void) snprintf(devpath, len, "%s%s", DEVDIR, path);
	} else
		devpath = NULL;

	DBG("ap_cm_path(%d)=%s\n", seq, devpath ? devpath : "");

	return (devpath);
}

void
ap_cm_id(apd_t *a, int seq, char *id, size_t bufsize)
{
	int unit;
	char *name;
	sbd_dev_stat_t *dst;

	dst = ap_cm_stat(a, seq);

	unit = dst->ds_unit;
	name = dst->ds_name;

	/*
	 * If the component has a unit number,
	 * add it to the id, otherwise just use
	 * the component's name.
	 */
	if (unit == -1)
		(void) snprintf(id, bufsize, "%s", name);
	else
		(void) snprintf(id, bufsize, "%s%d", name, unit);

	DBG("ap_cm_id(%d)=%s\n", seq, id);
}

/*
 * Convert a component to a target type.
 */
ap_target_t
ap_cm_type(apd_t *a, int seq)
{
	ap_target_t c;
	sbd_dev_stat_t *dst;

	dst = ap_cm_stat(a, seq);

	switch (dst->ds_type) {
	case SBD_COMP_CPU:
		c = AP_CPU;
		break;
	case SBD_COMP_MEM:
		c = AP_MEM;
		break;
	case SBD_COMP_IO:
		c = AP_IO;
		break;
	case SBD_COMP_CMP:
		c = AP_CMP;
		break;
	default:
		c = AP_NONE;
		break;
	}

	return (c);
}

int
ap_cm_ncap(apd_t *a, int seq)
{
	sbd_dev_stat_t	*dst;
	int		ncap;

	dst = ap_cm_stat(a, seq);

	switch (dst->ds_type) {
	case SBD_COMP_CPU:
	case SBD_COMP_MEM:
	case SBD_COMP_IO:
		ncap = 1;
		break;
	case SBD_COMP_CMP:
		ncap = ((sbd_cmp_stat_t *)dst)->ps_ncores;
		break;
	default:
		ncap = 0;
		break;
	}

	return (ncap);
}

int
ap_cm_capacity(apd_t *a, int seq, void *cap, int *ncap, cfga_stat_t *ostate)
{
	int i;
	sbd_dev_stat_t *dst;
	cfga_stat_t os;

	if (cap == NULL)
		return (0);

	dst = ap_cm_stat(a, seq);
	os = (cfga_stat_t)dst->ds_ostate;
	if (os != CFGA_STAT_CONFIGURED && os != CFGA_STAT_UNCONFIGURED)
		return (0);
	if (ostate)
		*ostate = os;

	*ncap = 1;

	switch (dst->ds_type) {
	case SBD_COMP_CPU: {
		sbd_cpu_stat_t *cpu = (sbd_cpu_stat_t *)dst;
		*((processorid_t *)cap) = cpu->cs_cpuid;
		break;
	}
	case SBD_COMP_MEM: {
		sbd_mem_stat_t *mem = (sbd_mem_stat_t *)dst;
		*((long *)cap) = mem->ms_totpages;
		break;
	}
	case SBD_COMP_CMP: {
		sbd_cmp_stat_t	*cmp = (sbd_cmp_stat_t *)dst;
		processorid_t	*cpuid;

		cpuid = (processorid_t *)cap;
		for (i = 0; i < cmp->ps_ncores; i++) {
			cpuid[i] = cmp->ps_cpuid[i];
		}

		*ncap = cmp->ps_ncores;
		break;
	}
	default:
		return (0);
	}

	DBG("ap_cm_capacity(%d)=(", seq);
	for (i = 0; i < *ncap; i++) {
		DBG("%d ", ((int *)cap)[i]);
	}
	DBG("%d)\n", *ostate);

	return (1);
}

void
ap_cm_init(apd_t *a, cfga_list_data_t *ap, int seq)
{
	char *type;
	sbd_stat_t *st;
	sbd_dev_stat_t *dst;

	st = (sbd_stat_t *)a->stat;
	dst = st->s_stat + seq;
	type = ap_dev_type(dst);

	a->cmstat = (void *)dst;

	DBG("ap_cm_init bd=%d rs=%d os=%d type=<%s> seq=%d\n",
	    a->bnum, st->s_rstate, dst->ds_ostate, type, seq);

	(void) strncpy(ap->ap_type, type, sizeof (ap->ap_type));
	ap->ap_r_state = (cfga_stat_t)st->s_rstate;
	ap->ap_o_state = (cfga_stat_t)dst->ds_ostate;
	ap->ap_cond = (cfga_cond_t)dst->ds_cond;
	ap->ap_busy = (cfga_busy_t)dst->ds_busy;
	ap->ap_status_time = dst->ds_time;
	ap_info(a, ap->ap_info, ap_cm_tgt(dst->ds_type));
}

void
ap_state(apd_t *a, cfga_stat_t *rs, cfga_stat_t *os)
{
	sbd_stat_t *st;
	sbd_dev_stat_t *dst;

	st = (sbd_stat_t *)a->stat;
	dst = (sbd_dev_stat_t *)a->cmstat;

	if (rs != NULL) {
		if (a->tgt == AP_NONE)
			*rs = CFGA_STAT_NONE;
		else
			*rs = (cfga_stat_t)st->s_rstate;
	}

	if (os != NULL) {
		if (a->tgt == AP_NONE)
			*os = CFGA_STAT_NONE;
		else if (a->tgt == AP_BOARD)
			*os = (cfga_stat_t)st->s_ostate;
		else
			*os = (cfga_stat_t)dst->ds_ostate;
	}
}

#define	BI_POWERED		0
#define	BI_ASSIGNED		1

static const char *
binfo[] = {
	"powered-on",
	", assigned"
};

static const char *
binfo_parsable[] = {
	"powered-on",
	" assigned"
};

static void
bd_info(apd_t *a, cfga_info_t info, int parsable)
{
	int i;
	int nsep;
	const char **p;
	sbd_stat_t *st;
	char *end = &info[sizeof (cfga_info_t)];

	DBG("bd_info(%p)\n", (void *)info);

	st = (sbd_stat_t *)a->stat;

	if (parsable) {
		p = binfo_parsable;
		nsep = 1;
	} else {
		p = binfo;
		nsep = 2;
	}

	i = nsep;

	if (st->s_power) {
		info += snprintf(info, end - info, p[BI_POWERED]);
		i = 0;
	}
	if (st->s_assigned)
		info += snprintf(info, end - info, p[BI_ASSIGNED] + i);
}

#define	CI_CPUID		0
#define	CI_SPEED		1
#define	CI_ECACHE		2

static const char *
cpuinfo[] = {
	"cpuid %d",
	", speed %d MHz",
	", ecache %d MBytes"
};

static const char *
cpuinfo_parsable[] = {
	"cpuid=%d",
	" speed=%d",
	" ecache=%d"
};

static void
cpu_info(apd_t *a, cfga_info_t info, int parsable)
{
	const char **p;
	sbd_cpu_stat_t *dst;
	char *end = &info[sizeof (cfga_info_t)];

	DBG("cpu_info(%p)\n", (void *)info);

	dst = (sbd_cpu_stat_t *)a->cmstat;

	if (parsable)
		p = cpuinfo_parsable;
	else
		p = cpuinfo;

	info += snprintf(info, end - info, p[CI_CPUID], dst->cs_cpuid);
	info += snprintf(info, end - info, p[CI_SPEED], dst->cs_speed);
	info += snprintf(info, end - info, p[CI_ECACHE], dst->cs_ecache);
}

#define	MI_ADDRESS		0
#define	MI_SIZE			1
#define	MI_PERMANENT		2
#define	MI_UNCONFIGURABLE	3
#define	MI_SOURCE		4
#define	MI_TARGET		5
#define	MI_DELETED		6
#define	MI_REMAINING		7
#define	MI_INTERLEAVE		8

static const char *
meminfo_nonparsable[] = {
	"base address 0x%" PRIx64,
	", %lu KBytes total",
	", %lu KBytes permanent",
	", unconfigurable",
	", memory delete requested on %s",
	", memory delete in progress on %s",
	", %lu KBytes deleted",
	", %lu KBytes remaining",
	", inter board interleave"
};

static const char *
meminfo_parsable[] = {
	"address=0x%" PRIx64,
	" size=%lu",
	" permanent=%lu",
	" unconfigurable",
	" source=%s",
	" target=%s",
	" deleted=%lu",
	" remaining=%lu",
	" inter-board-interleave"
};


#define	_K1	1024

/*
 * This function assumes pagesize > 1024 and that
 * pagesize is a multiple of 1024.
 */
static ulong_t
pages_to_kbytes(uint_t pgs)
{
	long pagesize;

	pagesize = sysconf(_SC_PAGESIZE);
	return (pgs * (pagesize / _K1));
}

static uint64_t
pages_to_bytes(uint_t pgs)
{
	long pagesize;

	pagesize = sysconf(_SC_PAGESIZE);
	return ((uint64_t)pgs * pagesize);
}

static void
mem_info(apd_t *a, cfga_info_t info, int parsable)
{
	const char **p;
	sbd_mem_stat_t *dst;
	int want_progress;
	char *end = &info[sizeof (cfga_info_t)];

	DBG("mem_info(%p)\n", (void *)info);

	dst = (sbd_mem_stat_t *)a->cmstat;

	if (parsable)
		p = meminfo_parsable;
	else
		p = meminfo_nonparsable;

	info += snprintf(info, end - info, p[MI_ADDRESS],
	    pages_to_bytes(dst->ms_basepfn));
	info += snprintf(info, end - info, p[MI_SIZE],
	    pages_to_kbytes(dst->ms_totpages));

	if (dst->ms_noreloc_pages)
		info += snprintf(info, end - info, p[MI_PERMANENT],
		    pages_to_kbytes(dst->ms_noreloc_pages));
	if (!dst->ms_cage_enabled)
		info += snprintf(info, end - info, p[MI_UNCONFIGURABLE]);
	if (dst->ms_interleave)
		info += snprintf(info, end - info, p[MI_INTERLEAVE]);

	/*
	 * If there is a valid peer physical ap_id specified,
	 * convert it to a logical id.
	 */
	want_progress = 0;
	if (str_valid(dst->ms_peer_ap_id)) {
		char *cm;
		char *peer;
		char physid[MAXPATHLEN];
		char logid[MAXPATHLEN];

		(void) snprintf(physid, sizeof (physid), "%s%s",
		    DEVDIR, dst->ms_peer_ap_id);

		/*
		 * Save the component portion of the physid and
		 * add it back after converting to logical format.
		 */
		if ((cm = strstr(physid, "::")) != NULL) {
			*cm = '\0';
			cm += 2;
		}

		/* attempt to resolve to symlink */
		if (ap_symid(a, physid, logid, sizeof (logid)) == 0)
			peer = logid;
		else
			peer = physid;

		if (dst->ms_peer_is_target) {
			info += snprintf(info, end - info, p[MI_TARGET], peer);
			if (cm)
				info += snprintf(info, end - info, "::%s", cm);
			want_progress = 1;
		} else {
			info += snprintf(info, end - info, p[MI_SOURCE], peer);
			if (cm)
				info += snprintf(info, end - info, "::%s", cm);
		}
	}
	if (want_progress ||
	    (dst->ms_detpages != 0 && dst->ms_detpages != dst->ms_totpages)) {
		info += snprintf(info, end - info, p[MI_DELETED],
		    pages_to_kbytes(dst->ms_detpages));
		info += snprintf(info, end - info, p[MI_REMAINING],
		    pages_to_kbytes(dst->ms_totpages -
		    dst->ms_detpages));
	}
}

#define	II_DEVICE		0
#define	II_REFERENCED		1

static const char *
ioinfo[] = {
	"device %s",
	", referenced"
};

static const char *
ioinfo_parsable[] = {
	"device=%s",
	" referenced"
};

static void
io_info(apd_t *a, cfga_info_t info, int parsable)
{
	const char **p;
	sbd_io_stat_t *dst;
	char *end = &info[sizeof (cfga_info_t)];

	dst = (sbd_io_stat_t *)a->cmstat;

	if (parsable)
		p = ioinfo_parsable;
	else
		p = ioinfo;

	info += snprintf(info, end - info, p[II_DEVICE], dst->is_pathname);
	if (dst->is_referenced)
		info += snprintf(info, end - info, p[II_REFERENCED]);
}

#define	PI_CPUID		0
#define	PI_CPUID_PAIR		1
#define	PI_CPUID_CONT		2
#define	PI_CPUID_LAST		3
#define	PI_SPEED		4
#define	PI_ECACHE		5

static const char *
cmpinfo[] = {
	"cpuid %d",
	" and %d",
	", %d",
	", and %d",
	", speed %d MHz",
	", ecache %d MBytes"
};

static const char *
cmpinfo_parsable[] = {
	"cpuid=%d",
	",%d",
	",%d",
	",%d",
	" speed=%d",
	" ecache=%d"
};

static void
cmp_info(apd_t *a, cfga_info_t info, int parsable)
{
	int		i;
	int		last;
	const char	**p;
	sbd_cmp_stat_t	*dst;
	char *end = &info[sizeof (cfga_info_t)];

	DBG("cmp_info(%p)\n", (void *)info);

	dst = (sbd_cmp_stat_t *)a->cmstat;

	if (parsable)
		p = cmpinfo_parsable;
	else
		p = cmpinfo;

	/* Print the first cpuid */
	info += snprintf(info, end - info, p[PI_CPUID], dst->ps_cpuid[0]);

	/*
	 * Print the middle cpuids, if necessary. Stop before
	 * the last one, since printing the last cpuid is a
	 * special case for the non parsable form.
	 */
	for (i = 1; i < (dst->ps_ncores - 1); i++) {
		info += snprintf(info, end - info, p[PI_CPUID_CONT],
		    dst->ps_cpuid[i]);
	}

	/* Print the last cpuid, if necessary */
	if (dst->ps_ncores > 1) {
		last = (dst->ps_ncores == 2) ? PI_CPUID_PAIR : PI_CPUID_LAST;
		info += snprintf(info, end - info,
		    dgettext(TEXT_DOMAIN, p[last]), dst->ps_cpuid[i]);
	}

	info += snprintf(info, end - info, p[PI_SPEED], dst->ps_speed);
	info += snprintf(info, end - info, p[PI_ECACHE], dst->ps_ecache);
}

void
ap_info(apd_t *a, cfga_info_t info, ap_target_t tgt)
{
	int parsable = ap_getopt(a, OPT_PARSABLE);

	DBG("ap_info(%p, %d)\n", (void *)info, parsable);

	switch (tgt) {
	case AP_BOARD:
		bd_info(a, info, parsable);
		break;
	case AP_CPU:
		cpu_info(a, info, parsable);
		break;
	case AP_MEM:
		mem_info(a, info, parsable);
		break;
	case AP_IO:
		io_info(a, info, parsable);
		break;
	case AP_CMP:
		cmp_info(a, info, parsable);
		break;
	default:
		break;
	}
}
