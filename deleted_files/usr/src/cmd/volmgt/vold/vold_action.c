/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdlib.h>
#include	<string.h>
#include	<pwd.h>
#include	<sys/types.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<sys/mnttab.h>
#include	<sys/resource.h>
#include	<regex.h>
#include	<errno.h>
#include	"vold.h"

/*
 * Declarations of externally defined functions
 */
extern bool_t		medium_mount_mode(dev_t, char *);


/*
 * Volume Daemon action support.
 */

typedef struct action {
	struct action	*a_next;	/* linked list pointer */
	char		*a_re;		/* original regex */
	regex_t		a_recmp;	/* complied regex */
	actprog_t	*a_prog;	/* program and args to execute */
} action_t;

static action_t	*insert = NULL;
static action_t	*eject = NULL;
static action_t	*notify = NULL;
static action_t	*aerror = NULL;
static action_t *remount = NULL;

struct q 	reapq;

char *actnames[] = {
	"",
	"insert",
	"eject",
	"notify",
	"error",
	"remount",
	"close",
};



/*
 * length of buffer used to create environment variables
 */

#define	VOLD_ENVBUFLEN	512

/*
 * length of buffer for printing numbers
 */

#define	VOLD_NUMBUFLEN	512

int
action(uint_t act, vol_t *v)
{
	static void	action_reaper(uint_t, vol_t *, pid_t, char *);
	static int	action_exec(uint_t, actprog_t *, vol_t *);
	struct vnwrap	*vw, *ovw;
	action_t	*a, **list;
	char		*path;
	int		nacts;
	int		re_ret;
	struct devs	*dp;

#ifdef	DEBUG
	debug(10, "action: entering for vol %s (act %s)\n",
	    v->v_obj.o_name, actnames[act]);
#endif

	switch (act) {
	case ACT_NOTIFY:
		list = &notify;
		break;
	case ACT_INSERT:
		list = &insert;
		break;
	case ACT_EJECT:
		list = &eject;
		break;
	case ACT_ERROR:
		list = &aerror;
		break;
	case ACT_REMOUNT:
		list = &remount;
		break;
	case ACT_CLOSE:
		list = &eject;
		break;
	default:
		warning(gettext("action: unknown action %d\n"), act);
		return (0);
	}

	ovw = node_findnode(v->v_obj.o_id, FN_ANY, FN_ANY, FN_ANY);
	if (ovw == NULL) {
		debug(1, "action: couldn't find any vn's for %s\n",
			v->v_obj.o_name);

		if (act == ACT_EJECT || act == ACT_CLOSE) {
			action_reaper(act, v, 0, "internal error");
		}
		return (0);
	}

	nacts = 0;
	debug(1, "action: %s on volume %s\n", actnames[act],
	    v->v_obj.o_name);
	for (vw = ovw; vw != NULL; vw = vw->vw_next) {
		path = path_make(vw->vw_node);
		for (a = *list; a; a = a->a_next) {
			debug(6, "action: regexec(%s, %s)\n", a->a_re, path);
			if ((re_ret = regexec(&a->a_recmp, path, 0, NULL,
			    0)) == REG_OK) {
				a->a_prog->ap_matched = path;
				if (action_exec(act, a->a_prog, v) == 0)
					nacts++;
			} else if (re_ret != REG_NOMATCH) {
				debug(1,
			"action: can't compare RE \"%s\" to \"%s\" (ret %d)\n",
				    a->a_re, path, re_ret);
			}
		}
		free(path);
	}
	node_findnode_free(ovw);

	if (act != ACT_NOTIFY) {
		if ((dp = dev_getdp(v->v_basedev)) != NULL)
			dp->dp_asynctask += nacts;
	}
	return (nacts);
}


/*
 * Add a new action
 */
bool_t
action_new(uint_t act, char *re, struct actprog *ap)
{
	action_t	*a, **list;
	int		regcomp_ret;

	switch (act) {
	case ACT_NOTIFY:
		list = &notify;
		break;
	case ACT_INSERT:
		list = &insert;
		break;
	case ACT_EJECT:
		list = &eject;
		break;
	case ACT_ERROR:
		list = &aerror;
		break;
	case ACT_REMOUNT:
		list = &remount;
		break;
	default:
		warning(gettext("action_new: unknown action %d\n"), act);
		return (FALSE);
	}

	a = (action_t *)calloc(1, sizeof (action_t));

	/* compile the regular expression */
	if ((regcomp_ret = regcomp(&a->a_recmp, re, REG_NOSUB)) != REG_OK) {
		debug(1, "action_new: can't compile RE \"%s\" (ret = %d)\n",
		    re, regcomp_ret);
		free(a);
		return (FALSE);
	}

	/* stick it on our list */
	if (*list == NULL) {
		*list = a;
	} else {
		a->a_next = *list;
		*list = a;
	}
	a->a_re = strdup(re);
	a->a_prog = ap;
	return (TRUE);
}


/*
 * Remove all actions.
 */

static void
flush_one_list(action_t **pa)
{
	action_t	*a;
	action_t	*a_next;
	actprog_t	*ap;
	int		i;

	for (a = *pa; a != NULL; a = a_next) {
		a_next = a->a_next;
		regfree(&a->a_recmp);
		free(a->a_re);
		ap = a->a_prog;
		free(a);
		free(ap->ap_prog);
		if (ap->ap_args != NULL) {
			for (i = 0; ap->ap_args[i]; i++) {
				free(ap->ap_args[i]);
			}
			free(ap->ap_args);
		}
		free(ap);
	}
	*pa = NULL;
}

void
action_flush(void)
{
	/* flush 'insert' events */
	flush_one_list(&insert);

	/* flush 'notify' events */
	flush_one_list(&notify);

	/* flush 'eject' events */
	flush_one_list(&eject);

	/* flush 'action error' events */
	flush_one_list(&aerror);

	/* flush 'action remount' events */
	flush_one_list(&remount);
}


static void
action_reaper(uint_t act, vol_t *v, pid_t pid, char *hint)
{
	struct reap *r;

	r = vold_calloc(1, sizeof (struct reap));
	r->r_v = v;
	r->r_act = act;
	r->r_pid = pid;
	r->r_hint = vold_strdup(hint);
	r->r_dev = v->v_basedev;
	INSQUE(reapq, r);
}


static int
action_exec(uint_t act, actprog_t *ap, vol_t *v)
{
	static void	action_buildenv(uint_t, actprog_t *, vol_t *);
	pid_t		pid;
	struct rlimit	rlim;
	extern int 	errno;

	debug(1, "action_exec: \"%s\" on \"%s\", prog=\"%s\"\n",
	    actnames[act], v->v_obj.o_name, ap->ap_prog);

	if (act == ACT_EJECT || act == ACT_CLOSE) {
		/* about to launch an ejection action */
		v->v_eject++;
	}

	if ((pid = fork1()) == 0) {
		/* child */

		/*
		 * The getrlimit/setrlimit stuff is here to support
		 * the execution of binaries running in BCP mode.
		 * Since the daemon increases the number of available
		 * file descriptors, they need to be reset here or it
		 * screws up old binaries that couldn't support as many
		 * fd's.
		 */
		getrlimit(RLIMIT_NOFILE, &rlim);
		rlim.rlim_cur = original_nofile;
		if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
			perror("vold; setrlimit");
		}

		action_buildenv(act, ap, v);
		(void) setgid(ap->ap_gid);
		(void) setuid(ap->ap_uid);
#ifdef DEBUG_EXECS
		(void) debug(1, "execing %s, pid = %d, uid = %d, args = '%s'\n",
			ap->ap_prog, getpid(), ap->ap_uid, ap->ap_args);
#endif
		(void) execv(ap->ap_prog, ap->ap_args);
		(void) debug(1, "exec failed on %s, errno %d\n",
				ap->ap_prog, errno);
		exit(0);
	} else if (pid == -1) {
		if (act == ACT_EJECT || act == ACT_CLOSE)
			v->v_eject--;
		warning(gettext("action_exec: couldn't exec %s; %m\n"),
		    ap->ap_prog);
		return (1);
	} else {
		action_reaper(act, v, pid, ap->ap_prog);
	}
	return (0);
}

static void
action_buildenv(uint_t act, actprog_t *ap, vol_t *v)
{
	extern char	*dev_getpath(dev_t);
	static void	vol_putenv(char *);
	char		namebuf[VOLD_ENVBUFLEN+1];
	char		tmpbuf[VOLD_NUMBUFLEN+1];
	struct passwd	*pw;
	char		*user;
	char		*symname;

	/*
	 * Since we only do this in the child,
	 * we don't worry about losing the memory we're
	 * about to allocate.
	 */

	if (act == ACT_CLOSE)
		act = ACT_EJECT;

	(void) snprintf(namebuf, sizeof (namebuf),
		"VOLUME_ACTION=%s", actnames[act]);
	vol_putenv(strdup(namebuf));

	(void) snprintf(namebuf, sizeof (namebuf),
		"VOLUME_PATH=%s", ap->ap_matched);
	vol_putenv(strdup(namebuf));

	(void) snprintf(namebuf, sizeof (namebuf),
		"VOLUME_NAME=%s", obj_basepath(&v->v_obj));
	vol_putenv(strdup(namebuf));

	switch (v->v_fstype) {
		case V_HSFS:
			(void) snprintf(namebuf, sizeof (namebuf),
				"VOLUME_FSTYPE=%s", "HSFS");
			break;

		case V_PCFS:
			(void) snprintf(namebuf, sizeof (namebuf),
				"VOLUME_FSTYPE=%s", "PCFS");
			break;

		case V_UDFS:
			(void) snprintf(namebuf, sizeof (namebuf),
				"VOLUME_FSTYPE=%s", "UDFS");
			break;

		case V_UFS:
			(void) snprintf(namebuf, sizeof (namebuf),
				"VOLUME_FSTYPE=%s", "UFS");
			break;

		default:
			(void) snprintf(namebuf, sizeof (namebuf),
				"VOLUME_FSTYPE=%s", "UNKNOWN");
			debug(3, "%s[%d]: Unknown file system type\n",
					__FILE__, __LINE__);

	}

	vol_putenv(strdup(namebuf));

	/*
	 * mount mode can be one of the following
	 * rw: read write
	 * ro: read only
	 * pp: password protected (can't mount)
	 * pw: password protected for write only (mount ro)
	 */
	(void) snprintf(namebuf, sizeof (namebuf),
		"VOLUME_MOUNT_MODE=%s", v->v_mount_mode);
	vol_putenv(strdup(namebuf));

	if ((v->v_fstype == V_PCFS) &&
		((v->v_parts == 1) || (v->v_parts != 0)) &&
		/* do not use pcfs id for floppies */
		(strcmp(v->v_mtype, FLOPPY_MTYPE) != 0)) {
		/*
		 * we have pcfs with fdisk,
		 */
		(void) snprintf(namebuf, sizeof (namebuf),
			"VOLUME_PCFS_ID=%s", v->v_pcfs_part_id);
	} else {

		/*
		 * Must create VOLUME_PCFS_ID as null to be sure a previous
		 * value is not around for rmmount
		 */
		(void) snprintf(namebuf, sizeof (namebuf), "VOLUME_PCFS_ID=");
	}
	vol_putenv(strdup(namebuf));

	if (act == ACT_EJECT || act == ACT_INSERT || act == ACT_REMOUNT) {
		(void) snprintf(namebuf, sizeof (namebuf),
			"VOLUME_DEVICE=%s", dev_getpath(v->v_basedev));
		vol_putenv(strdup(namebuf));
		if ((symname = dev_symname(v->v_basedev)) != NULL) {
			(void) snprintf(namebuf, sizeof (namebuf),
				"VOLUME_SYMDEV=%s", symname);
			vol_putenv(strdup(namebuf));
		} else {
			vol_putenv("VOLUME_SYMDEV=");
		}
	} else {
		vol_putenv("VOLUME_DEVICE=");
		vol_putenv("VOLUME_SYMDEV=");
	}

	if (act == ACT_EJECT || act == ACT_NOTIFY) {
		if ((pw = getpwuid(v->v_clue.c_uid)) != NULL) {
			user = pw->pw_name;
		} else {
			(void) snprintf(tmpbuf, sizeof (tmpbuf),
				"%ld", v->v_clue.c_uid);
			user = tmpbuf;
		}

		(void) snprintf(namebuf, sizeof (namebuf),
			"VOLUME_USER=%s", user);
		vol_putenv(strdup(namebuf));

#ifdef	VOLMGT_DEV_TO_TTY_WORKED
		/*
		 * Converting a dev_t into a path name is a very
		 * expensive operation, so we only do it if the
		 * user has told us to by sticking the maptty
		 * flag on his action.
		 */
		if (ap->ap_maptty) {
			(void) snprintf(namebuf, sizeof (namebuf),
				"VOLUME_USERTTY=%s", devtotty(v->v_clue.c_tty));
			vol_putenv(strdup(namebuf));
		} else {
			vol_putenv("VOLUME_USERTTY=");
		}
#else	/* VOLMGT_DEV_TO_TTY_WORKED */
		/* devtotty() has some bugs right now */
		(void) snprintf(namebuf, sizeof (namebuf),
			"VOLUME_USERTTY=0x%lx", v->v_clue.c_tty);
		vol_putenv(strdup(namebuf));
#endif	/* VOLMGT_DEV_TO_TTY_WORKED */
	} else {
		vol_putenv("VOLUME_USER=");
		vol_putenv("VOLUME_USERTTY=");
	}
	(void) snprintf(namebuf, sizeof (namebuf),
		"VOLUME_MEDIATYPE=%s", v->v_mtype);
	vol_putenv(strdup(namebuf));
	if (v->v_ej_force == TRUE) {
		vol_putenv("VOLUME_FORCEDEJECT=true");
	} else {
		vol_putenv("VOLUME_FORCEDEJECT=false");
	}
}


static void
vol_putenv(char *env_str)
{
#ifdef	DEBUG
	debug(9, "vol_putenv: \"%s\"\n", env_str);
#endif
	(void) putenv(env_str);
}
