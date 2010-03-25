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

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <macros.h>
#include <dirent.h>
#include <libgen.h>
#include <libdevinfo.h>
#define	CFGA_PLUGIN_LIB
#include <config_admin.h>
#include "ap.h"

/*ARGSUSED0*/
int
ap_symid(apd_t *a, char *apid, char *symid, size_t bufsize)
{
	int n;
	int rc;
	char path[MAXPATHLEN];
	char *p;
	DIR *dirp;
	struct dirent *dp;

	*symid = '\0';
	n = sprintf(path, "/dev/cfg/");
	rc = -1;

	if ((dirp = opendir(path)) == NULL)
		return (rc);

	p = path + n;

	while ((dp = readdir(dirp)) != NULL) {
		char buf[MAXPATHLEN];
		char *cp;
		size_t len;

		*p = '\0';
		(void) strcat(path, dp->d_name);
		if ((len = readlink(path, buf, sizeof (buf))) == (size_t)-1)
			continue;
		buf[len] = '\0';

		len = strlen("../");
		cp = buf;
		while (strncmp(cp, "../", len) == 0)
			cp += len;
		if (cp != buf)
			cp--;	/* Get the '/' */

		if (strcmp(cp, apid) == 0) {
			(void) snprintf(symid, bufsize, "%s", dp->d_name);
			rc = 0;
			break;
		}
	}

	(void) closedir(dirp);
	return (rc);
}

char *
ap_logid(apd_t *a, char *apid)
{
	int n;
	char *buf;

	if ((buf = calloc(1, MAXPATHLEN)) == NULL)
		return (NULL);

	/*
	 * Look for a symlink.  On any error, fallback to
	 * driver and instance based logical ap_ids.
	 */
	if (ap_symid(a, apid, buf, MAXPATHLEN) == 0)
		n = strlen(buf);
	else
		n = snprintf(buf, MAXPATHLEN, "%s%d:%s",
		    a->drv, a->inst, a->minor);
	/*
	 * Append the dynamic portion, if any.
	 */
	if (a->cid != NULL)
		(void) snprintf(&buf[n], MAXPATHLEN - n, "::%s", a->cid);

	return (buf);
}

int
ap_parse(apd_t *a, const char *ap_id)
{
	int i;
	int rc;
	int phys;
	char c;
	char *s;
	char *p;
	char *q;
	char *base;
	int len;
	char *t;

	if (a == NULL)
		return (-1);

	a->cnum = -1;
	a->bnum = -1;
	a->inst = -1;
	a->apid = ap_id;
	rc = ERR_NONE;

	if (!str_valid(ap_id)) {
		rc = ERR_AP_INVAL;
		goto done;
	}

	if ((a->path = strdup(ap_id)) == NULL) {
		rc = ERR_NOMEM;
		goto done;
	}

	/*
	 * For a physical ap_id, look only at the base part.
	 * For a logical/symbolic one, use the entire ap_id.
	 */
	if (strncmp(a->path, DEVDIR, strlen(DEVDIR)) == 0) {
		phys = 1;
		base = strrchr((const char *)a->path, '/') + 1;
	} else {
		phys = 0;
		base = a->path;
		if ((a->target = strdup(a->path)) == NULL) {
			rc = ERR_NOMEM;
			goto done;
		}
	}

	if ((s = strchr(base, ':')) == NULL || s[1] == ':') {
		/*
		 * No ':' found, or got a '::'.  If this is a physical
		 * ap_id, it must have a minor separtor ':' which must
		 * appear before the dynamic part (starting with '::').
		 * For a symbolic ap_id, skip looking for driver/minor
		 * names.
		 */
		if (phys) {
			rc = ERR_AP_INVAL;
			goto done;
		} else
			s = base;
	} else {
		/*
		 * Look for driver name/instance only up to the first ':',
		 * i.e. up to the minor node name.
		 */
		*s = '\0';

		if ((p = strchr(base, '@')) != NULL) {
			/*
			 * Get the driver name/instance.
			 */
			*p = '\0';
			if ((a->drv = strdup(base)) == NULL) {
				rc = ERR_NOMEM;
				goto done;
			}
			*p++ = '@';

			i = strtol(p, &q, 10);
			if (q > p)
				a->inst = i;
		}

		*s++ = ':';
		a->minor = s;
	}

	/*
	 * Need to go to the end of the string before the :: if any
	 * If the string is null then we are done
	 */
	t = strstr(s, "::");
	if (t != NULL)
		len = strlen(t);
	else
		len = 0;

	s += (strlen(s) - len);

	p = s;

	if (*p == '\0')
		a->tgt = AP_BOARD;
	else if (strncmp(p, "::", 2) != 0) {
		rc = ERR_AP_INVAL;
		goto done;
	} else {
		/*
		 * Save the component id.
		 */
		*p++ = '\0';
		*p++ = '\0';
		a->cid = p;
	}

	/*
	 * Get the operation target, e.g. slot0, slot0::cpu0.
	 * At this point, a->path points to the /devices path
	 * minus the dynamic part, for a physical ap_id. In
	 * the case of a logical ap_id, the target is already
	 * initialized above.
	 */
	if (phys != 0 && (a->target = ap_logid(a, a->path)) == NULL) {
		rc = ERR_NOMEM;
		goto done;
	}

	if (a->tgt == AP_BOARD)
		goto done;

	while ((*p != '\0') && !isdigit(*p))
		p++;

	/*
	 * Get the component unit number, if present.
	 */
	i = strtol(p, &s, 10);
	/*
	 * There must be no characters after the unit number.
	 */
	if (*s != '\0') {
		rc = ERR_CM_INVAL;
		goto done;
	}
	if (s > p) {
		/*
		 * Disallow leading zeroes, e.g. cpu00, cpu01, cpu001.
		 * If there are 2 or more digits and the first is a zero,
		 * we fail.
		 */
		if ((s-p) >= 2 && *p == '0') {
			rc = ERR_CM_INVAL;
			goto done;
		}
		a->cnum = i;
	}

	c = *p;
	*p = '\0';
	if ((a->cname = strdup(a->cid)) == NULL)
		rc = ERR_NOMEM;
	*p = c;
done:
	switch (rc) {
	case ERR_NONE:
		break;
	case ERR_CM_INVAL:
		ap_err(a, ERR_CM_INVAL, a->cid);
		break;
	default:
		ap_err(a, rc);
		break;
	}

	DBG("path=<%s> ", a->path ? a->path : "");
	DBG("drv=<%s> inst=%d minor=<%s> ",
	    a->drv ? a->drv : "", a->inst, a->minor ? a->minor : "");
	DBG("target=<%s>\n", a->target ? a->target : "");
	DBG("cid=<%s> ", a->cid ? a->cid : "");
	DBG("cname=<%s> ", a->cname ? a->cname : "");
	DBG("cnum=%d\n", a->cnum);
	DBG("tgt=%d opts=%x\n", a->tgt, a->opts.flags);

	return (rc == ERR_NONE? 0 :  -1);
}

/*
 * Command table.
 *
 * The first set of commands in the table are in sequencing order,
 * for example, the first group starts with assign and ends with
 * configure.  command sequencer relies on this ordering.
 */
static char *
ap_cmd_names[] = {
	"assign",
	"poweron",
	"test",
	"connect",
	"configure",
	"notify online",
	"notify add capacity",
	"suspend check",
	"request suspend",
	"request delete capacity",
	"request offline",
	"unconfigure",
	"notify remove",
	"notify capacity change",
	"disconnect",
	"poweroff",
	"unassign",
	"notify resume",
	"status",
	"getncm",
	"passthru",
	"help",
	"errtest",
	NULL
};

char *
ap_cmd_name(int i)
{
	return (ap_cmd_names[min(i, CMD_NONE)]);
}

static char *
ap_opt_names[] = {
	"unassign",
	"skip",
	"parsable",
	"nopoweroff",
	"code",
	"mid",
	"err",
	"platform",
	"sim",
	NULL
};

char *
ap_opt_name(int i)
{
	return (ap_opt_names[i]);
}

/*
 * Command descriptor.
 *
 * Each command has a (command) mask specifying the AP target classes
 * it operates on, e.g. the assign command applies only to boards.
 * In addition each AP target class has a separate option mask specifying
 * which command options are valid for that target class.
 * A global value mask specifies which options require values.
 */
typedef struct {
	int cmd;
	uint_t cmask;
	uint_t omask[AP_NCLASS];
} ap_cmd_t;

/*
 * Command option definitions.
 */
#define	SHFT(i)	((uint_t)1 << (i))
#define	NULOPT	0
#define	ALLOPT	0xffffffff
#define	CMNOPT	(SHFT(OPT_VERBOSE)|SHFT(OPT_PLATFORM)|SHFT(OPT_SIM))
#define	CMFOPT	(CMNOPT|SHFT(OPT_FORCE))
#define	STSOPT	(CMNOPT|SHFT(OPT_PARSABLE))
#define	BRDDCN	(CMNOPT|SHFT(OPT_UNASSIGN)|SHFT(OPT_NOPOWEROFF))

#define	BRD	SHFT(AP_BOARD)
#define	BIO	SHFT(AP_BOARD)|SHFT(AP_IO)
#define	ALL	(BRD|SHFT(AP_CPU)|SHFT(AP_MEM)|SHFT(AP_IO)|SHFT(AP_CMP))

static ap_cmd_t
ap_cmds[] = {
	/*
	 *	cmd		cmd	 board	 cpu	 mem	 io	cmp
	 *			cmask	 omask	 omask   omask   omask	omask
	 */
	{CMD_ASSIGN,		BRD, 0, CMNOPT, NULOPT, NULOPT, NULOPT, NULOPT},
	{CMD_UNASSIGN,		BRD, 0, CMNOPT, NULOPT, NULOPT, NULOPT, NULOPT},
	{CMD_POWERON,		BRD, 0, CMNOPT, NULOPT, NULOPT, NULOPT, NULOPT},
	{CMD_POWEROFF,		BRD, 0, CMNOPT, NULOPT, NULOPT, NULOPT, NULOPT},
	{CMD_CONNECT,		BRD, 0, CMFOPT, NULOPT, NULOPT, NULOPT, NULOPT},
	{CMD_DISCONNECT,	BRD, 0, BRDDCN, NULOPT, NULOPT, NULOPT, NULOPT},
	{CMD_CONFIGURE,		ALL, 0, CMNOPT, CMNOPT, CMNOPT, CMNOPT, CMNOPT},
	{CMD_UNCONFIGURE,	ALL, 0, CMFOPT, CMFOPT, CMFOPT, CMFOPT, CMNOPT},
	{CMD_RCM_OFFLINE,	BIO, 0, CMNOPT, CMNOPT, CMNOPT, CMNOPT, CMNOPT},
	{CMD_RCM_ONLINE,	BIO, 0, CMNOPT, CMNOPT, CMNOPT, CMNOPT, CMNOPT},
	{CMD_RCM_SUSPEND,	BIO, 0, CMNOPT, CMNOPT, CMNOPT, CMNOPT, CMNOPT},
	{CMD_RCM_RESUME,	BIO, 0, CMNOPT, CMNOPT, CMNOPT, CMNOPT, CMNOPT},
	{CMD_RCM_CAP_ADD,	BIO, 0, CMNOPT, CMNOPT, CMNOPT, CMNOPT, CMNOPT},
	{CMD_RCM_CAP_DEL,	BIO, 0, CMNOPT, CMNOPT, CMNOPT, CMNOPT, CMNOPT},
	{CMD_RCM_CAP_NOTIFY,	BIO, 0, CMNOPT, CMNOPT, CMNOPT, CMNOPT, CMNOPT},
	{CMD_RCM_REMOVE,	BIO, 0, CMNOPT, CMNOPT, CMNOPT, CMNOPT, CMNOPT},
	{CMD_TEST,		BRD, 0, CMFOPT, NULOPT, NULOPT, NULOPT, NULOPT},
	{CMD_STATUS,		ALL, 0, STSOPT, STSOPT, STSOPT, STSOPT, STSOPT},
	{CMD_GETNCM,		BRD, 0, CMNOPT, NULOPT, NULOPT, NULOPT, NULOPT},
	{CMD_PASSTHRU,		ALL, 0, CMNOPT, CMNOPT, CMNOPT, CMNOPT, CMNOPT},
	{CMD_HELP,		ALL, 0, CMNOPT, CMNOPT, CMNOPT, CMNOPT, CMNOPT},
	{CMD_ERRTEST,		ALL, 0, ALLOPT, ALLOPT, ALLOPT, ALLOPT, ALLOPT},
	{CMD_NONE,		0,   0,	0,	0,	0,	0,	0    }
};

/*
 * Global mask for options that require values.
 */
#define	AP_VMASK (\
	SHFT(OPT_CODE)|SHFT(OPT_MID)|SHFT(OPT_ERR)| \
	SHFT(OPT_PLATFORM)|SHFT(OPT_SKIP))

#if SBD_DEBUG
void
ap_cmds_dump()
{
	int i;
	ap_cmd_t *acp;

	dbg("vmask=0x%x\n", AP_VMASK);
	dbg("%23s%5s%5s%9s%9s%9s%9s%9s\n",
	    "cmd", "msk", "none", "brd", "cpu", "mem", "io", "cmp");

	for (acp = ap_cmds; acp->cmd != CMD_NONE; acp++) {
		dbg("%23s%5x%5x", ap_cmd_name(acp->cmd), acp->cmask,
		    acp->omask[AP_NONE]);
		for (i = AP_BOARD; i < AP_NCLASS; i++) {
			dbg("%9x", acp->omask[i]);
		}
		dbg("\n");
	}
}
#endif

int
ap_state_cmd(cfga_cmd_t i, int *cmd)
{
	int c;
	int rc;

	rc = CFGA_OK;

	switch (i) {
	case CFGA_CMD_CONNECT:
		c = CMD_CONNECT;
		break;
	case CFGA_CMD_DISCONNECT:
		c = CMD_DISCONNECT;
		break;
	case CFGA_CMD_CONFIGURE:
		c = CMD_CONFIGURE;
		break;
	case CFGA_CMD_UNCONFIGURE:
		c = CMD_UNCONFIGURE;
		break;
	case CFGA_CMD_LOAD:
	case CFGA_CMD_UNLOAD:
		rc = CFGA_OPNOTSUPP;
		c = CMD_NONE;
		break;
	default:
		rc = CFGA_INVAL;
		c = CMD_NONE;
		break;
	}

	*cmd = c;

	return (rc);
}

static int
ap_cmd(char *name)
{
	int i;
	char **p;

	if (name == NULL)
		return (CMD_NONE);

	for (i = 0, p = ap_cmd_names; *p != NULL; p++, i++)
		if (strcmp(*p, name) == 0)
			break;
	if (*p == NULL)
		i = CMD_NONE;

	return (i);
}

static int
ap_opt_parse(apd_t *a, ap_cmd_t *acp, const char *options)
{
	char *optstr;
	ap_opts_t *opts;

	/*
	 * Set default values.
	 */
	opts = &a->opts;
	opts->mid = (char *)a->class;
	opts->err = ERR_CMD_FAIL;

	if (options == NULL)
		return (0);

	if ((optstr = strdup(options)) == NULL) {
		ap_err(a, ERR_NOMEM);
		return (-1);
	}

	a->options = optstr;

	if (acp->cmd == CMD_PASSTHRU)
		return (0);

	while (*optstr != '\0') {
		int i;
		int opt;
		int omask;
		char *p;
		char *value;
		char *optname;

		value = NULL;
		opt = getsubopt(&optstr, ap_opt_names, &value);

		DBG("opt=%d\n", opt);

		if (opt == -1) {
			ap_err(a, ERR_OPT_INVAL, value);
			return (-1);
		}

		optname = ap_opt_names[opt];
		omask = acp->omask[a->tgt];

		i = mask(opt) & omask;

		DBG("tgt=%d opt=%x omask=%x\n", a->tgt, mask(opt), omask);

		if (i == 0) {
			ap_err(a, ERR_OPT_INVAL, optname);
			return (-1);
		}

		/*
		 * Check whether the option requires a value.
		 */
		i = mask(opt) & AP_VMASK;
		if (i != 0 && value == NULL) {
			ap_err(a, ERR_OPT_NOVAL, optname);
			return (-1);
		} else if (i == 0 && value != NULL) {
			ap_err(a, ERR_OPT_VAL, optname);
			return (-1);
		}

		if (value == NULL)
			assert(opt != OPT_CODE);	/* XXX prefix */

		/*
		 * Set the options's value.
		 */
		switch (opt) {
		case OPT_SIM:
		case OPT_PARSABLE:
		case OPT_UNASSIGN:
			break;
		case OPT_CODE:
			i = strtol(value, &p, 10);
			if (p > value)
				opts->code = i;
			break;
		case OPT_MID:
			opts->mid = value;
			break;
		case OPT_ERR:
			i = strtol(value, &p, 10);
			if (p > value)
				opts->err = i;
			break;
		case OPT_NOPOWEROFF:
			i = ap_cmd("poweroff");
			opts->skip |= mask(i);
			break;
		case OPT_SKIP:	/* for debugging */
			/*
			 * The skip value may be a ':' separated
			 * list of steps (commands) to be skipped
			 * during sequencing.
			 */
			for (p = strtok(value, ":"); p != NULL;
			    p = strtok(NULL, ":")) {
				if ((i = ap_cmd(p)) == CMD_NONE) {
					ap_err(a, ERR_CMD_INVAL, p);
					return (-1);
				}
				opts->skip |= mask(i);
			}
			break;
		case OPT_PLATFORM:
			opts->platform = value;
			break;
		default:
			ap_err(a, ERR_OPT_INVAL, optname);
			return (-1);
		}

		ap_setopt(a, opt);
	}

	return (0);
}

static ap_cmd_t *
ap_cmdp(int cmd)
{
	ap_cmd_t *acp;

	for (acp = ap_cmds; acp->cmd != CMD_NONE; acp++)
		if (acp->cmd == cmd)
			break;

	if (acp->cmd == CMD_NONE)
		return (NULL);

	return (acp);
}

cfga_err_t
ap_cmd_parse(apd_t *a, const char *f, const char *options, int *cmd)
{
	int c;
	int all;
	int tgt;
	int target;
	ap_cmd_t *acp;
	cfga_err_t rc;

#ifdef	_SBD_DEBUG
	ap_cmds_dump();
#endif

	rc = CFGA_INVAL;

	if ((c = ap_cmd((char *)f)) == CMD_NONE ||
	    (acp = ap_cmdp(c)) == NULL) {
		ap_err(a, ERR_CMD_INVAL, f);
		return (rc);
	}

	/*
	 * Change a->statonly to 1, if the case is CMD_STATUS.  We are only
	 * wanting to read the devices and no more
	 */
	/*
	 * Get the status for all components if either the list all
	 * option being specified or if we are configuring/unconfiguring
	 * the board.  The latter is needed for the RCM interface.
	 */
	switch (c) {
	case CMD_STATUS:
		all = ap_getopt(a, OPT_LIST_ALL);
		a->statonly = 1;
		break;
	case CMD_CONFIGURE:
	case CMD_UNCONFIGURE:
	case CMD_CONNECT:
	case CMD_DISCONNECT:
		all = (a->tgt == AP_BOARD);
		a->statonly = 0;
		break;
	default:
		all = 0;
		a->statonly = 0;
		break;
	}

	if ((rc = apd_init(a, all)) != CFGA_OK)
		return (rc);

	rc = CFGA_INVAL;

	/*
	 * Get the target here in case it is a component in which
	 * case its type is known after the initialization.
	 */
	tgt = a->tgt;
	target = mask(tgt);

	DBG("cmd=%s(%d) tmask=0x%x cmask=0x%x omask=0x%x\n",
	    ap_cmd_name(c), c, target, acp->cmask, acp->omask[tgt]);

	if ((acp->cmask & target) == 0)
		ap_err(a, ERR_CMD_NOTSUPP, c);
	else if (options != NULL && acp->omask[tgt] == 0)
		ap_err(a, ERR_OPT_INVAL, options);
	else if (ap_opt_parse(a, acp, options) != -1) {
		if (c == CMD_STATUS)
			rc = ap_platopts_check(a, c, c);
		else
			rc = CFGA_OK;
	}

	if (cmd)
		*cmd = c;

	return (rc);
}

int
ap_cnt(apd_t *a)
{
	int cnt;

	if ((a->tgt == AP_BOARD) && ap_getopt(a, OPT_LIST_ALL))
		cnt = a->ncm + 1;
	else
		cnt = 1;

	return (cnt);
}
