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

/*
 * PICL daemon
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include <alloca.h>
#include <errno.h>
#include <assert.h>
#include <stropts.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <synch.h>
#include <door.h>
#include <sys/door.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <syslog.h>
#include <poll.h>
#include <limits.h>
#include <picl.h>
#include "picl2door.h"
#include <picltree.h>
#include "ptree_impl.h"

/*
 * Log text messages
 */
#define	MUST_BE_ROOT	gettext("this program must be run as root\n")
#define	CD_ROOT_FAILED	gettext("chdir to root failed\n")
#define	INIT_FAILED	gettext("ptree initialization failed\n")
#define	DAEMON_RUNNING	gettext("PICL daemon already running\n")
#define	DOOR_FAILED	gettext("Failed creating picld door\n")
#define	SIGACT_FAILED	\
		gettext("Failed to install signal handler for %s: %s\n")

/*
 * Constants
 */
#define	PICLD				"picld"
#define	DOS_PICL_REQUESTS_LIMIT		10000
#define	SLIDING_INTERVAL_MILLISECONDS	1000
#define	PICLD_MAJOR_REV			0x1
#define	PICLD_MINOR_REV			0x0
#define	DOS_SLEEPTIME_MS		1000
#define	MAX_POOL_SIZE			_POSIX_THREAD_THREADS_MAX
#define	MAX_CONCURRENT_WAITS	(_POSIX_THREAD_THREADS_MAX - 2)
#define	MAX_USER_WAITS			4

/*
 * Macros
 */
#define	PICLD_VERSION(x, y)	((x << 8) | y)
#define	PICL_CLIENT_REV(x)	(x & 0xff)
#define	MILLI_TO_NANO(x)	(x * 1000000)

extern	char	**environ;

/*
 * Module Variables
 */
static	int		logflag = 1;
static	int		doreinit = 0;
static	int		door_id = -1;
static	pthread_mutex_t door_mutex = PTHREAD_MUTEX_INITIALIZER;
static	pthread_cond_t door_cv = PTHREAD_COND_INITIALIZER;
static  int		service_requests = 0;
static	hrtime_t	orig_time;
static	hrtime_t	sliding_interval_ms;
static	uint32_t	dos_req_limit;
static	uint32_t	dos_ms;
static	pthread_mutex_t	dos_mutex = PTHREAD_MUTEX_INITIALIZER;
static	rwlock_t	init_lk;
static	int pool_count = 0;
static	pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;
static	pthread_mutex_t	wait_req_mutex = PTHREAD_MUTEX_INITIALIZER;
static	int wait_count = 0;
static	struct {
	uid_t uid;
	int count;
} user_count[MAX_CONCURRENT_WAITS];

/*
 * This returns an error message to libpicl
 */
static void
picld_return_error(picl_callnumber_t cnum, picl_errno_t err)
{
	picl_reterror_t	ret_error;

	ret_error.cnum = PICL_CNUM_ERROR;
	ret_error.in_cnum = cnum;
	ret_error.errnum = err;
	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret_error, sizeof (picl_reterror_t), NULL,
	    0);
}

/*
 * picld_init is called when a picl_initialize request is received
 */
static void
picld_init(picl_service_t *req)
{
	picl_retinit_t	ret_init;
	int	clmajrev;

	clmajrev = PICL_CLIENT_REV(req->req_init.clrev);

	if (clmajrev < PICL_VERSION_1)
		picld_return_error(req->req_init.cnum, PICL_NOTSUPPORTED);

	ret_init.cnum = req->req_init.cnum;
	ret_init.rev = PICLD_VERSION(PICLD_MAJOR_REV, PICLD_MINOR_REV);

	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret_init, sizeof (picl_retinit_t), NULL, 0);
}

/*
 * picld_fini is called when a picl_shutdown request is received
 */
static void
picld_fini(picl_service_t *in)
{
	picl_retfini_t	ret;

	ret.cnum = in->req_fini.cnum;

	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retfini_t), NULL, 0);
}

static void
picld_ping(picl_service_t *in)
{
	picl_retping_t	ret;

	ret.cnum = in->req_ping.cnum;

	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retping_t), NULL, 0);
}

static int
check_user(uid_t uid)
{
	int i;
	uid_t tmp_uid;
	int free_idx = -1;

	if (uid == 0)
		return (PICL_SUCCESS);
	for (i = 0; i < MAX_CONCURRENT_WAITS; i++) {
		if ((tmp_uid = user_count[i].uid) == uid) {
			if (user_count[i].count == MAX_USER_WAITS)
				return (PICL_FAILURE);
			user_count[i].count++;
			return (PICL_SUCCESS);
		}
		if ((free_idx == -1) && (tmp_uid == 0))
			free_idx = i;
	}
	if (free_idx != -1) {
		user_count[free_idx].uid = uid;
		user_count[free_idx].count = 1;
		return (PICL_SUCCESS);
	}
	return (PICL_FAILURE);
}

static void
done_user(uid_t uid)
{
	int i;

	if (uid == 0)
		return;
	for (i = 0; i < MAX_CONCURRENT_WAITS; i++) {
		if (user_count[i].uid == uid) {
			if (--user_count[i].count == 0)
				user_count[i].uid = 0;
			return;
		}
	}
}

static int
enter_picld_wait(uid_t uid)
{
	int	rv;

	if (pthread_mutex_lock(&wait_req_mutex) != 0)
		return (PICL_FAILURE);
	if ((wait_count < MAX_CONCURRENT_WAITS) &&
	    (check_user(uid) == PICL_SUCCESS)) {
		rv = PICL_SUCCESS;
		wait_count++;
	} else {
		rv = PICL_FAILURE;
	}
	(void) pthread_mutex_unlock(&wait_req_mutex);
	return (rv);
}

static void
exit_picld_wait(uid_t uid)
{
	(void) pthread_mutex_lock(&wait_req_mutex);
	done_user(uid);
	wait_count--;
	(void) pthread_mutex_unlock(&wait_req_mutex);
}

/*
 * picld_wait is called when a picl_wait request is received
 */
static void
picld_wait(picl_service_t *in)
{
	picl_retwait_t	ret;
	int		err;
	ucred_t	*puc = NULL;
	uid_t uid;

	ret.cnum = in->req_wait.cnum;
	if (door_ucred(&puc) != 0)
		ret.retcode = PICL_FAILURE;
	else {
		uid = ucred_geteuid(puc);
		if (enter_picld_wait(uid) == PICL_FAILURE)
			ret.retcode = PICL_FAILURE;
		else {
			err = xptree_refresh_notify(in->req_wait.secs);
			ret.retcode = err;
			exit_picld_wait(uid);
		}
		ucred_free(puc);
	}
	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retwait_t), NULL, 0);
}

/*
 * This function returns the handle of the root node of the PICL tree
 */
static void
picld_getroot(picl_service_t *in)
{
	picl_retroot_t	ret;
	int		err;

	ret.cnum = PICL_CNUM_GETROOT;
	err = ptree_get_root(&ret.rnode);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);
	cvt_ptree2picl(&ret.rnode);
	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retroot_t), NULL, 0);
}

/*
 * This function returns the value of the PICL property
 */
static void
picld_get_attrval(picl_service_t *in)
{
	picl_retattrval_t	*ret;
	int			err;
	size_t			vbufsize;
	size_t			len;
	door_cred_t		cred;
	picl_prophdl_t		ptreeh;
	ptree_propinfo_t	pinfo;

	if (door_cred(&cred) < 0)
		picld_return_error(in->in.cnum, PICL_FAILURE);

	err = cvt_picl2ptree(in->req_attrval.attr, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	err = ptree_get_propinfo(ptreeh, &pinfo);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	if (!(pinfo.piclinfo.accessmode & PICL_READ))
		picld_return_error(in->in.cnum, PICL_NOTREADABLE);

	vbufsize = pinfo.piclinfo.size;
	vbufsize = MIN((size_t)in->req_attrval.bufsize, vbufsize);

	len = sizeof (picl_retattrval_t) + vbufsize;
	ret = alloca(len);
	if (ret == NULL)
		picld_return_error(in->in.cnum, PICL_FAILURE);
	ret->cnum = PICL_CNUM_GETATTRVAL;
	ret->attr = in->req_attrval.attr;
	ret->nbytes = (uint32_t)vbufsize;
	err = xptree_get_propval_with_cred(ptreeh, ret->ret_buf, vbufsize,
	    cred);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	/*
	 * adjust returned bytes for charstrings
	 */
	if (pinfo.piclinfo.type == PICL_PTYPE_CHARSTRING)
		ret->nbytes = (uint32_t)strlen(ret->ret_buf) + 1;

	/*
	 * convert handle values to picl handles
	 */
	if ((pinfo.piclinfo.type == PICL_PTYPE_TABLE) ||
	    (pinfo.piclinfo.type == PICL_PTYPE_REFERENCE))
		cvt_ptree2picl(&ret->ret_nodeh);
	(void) rw_unlock(&init_lk);
	(void) door_return((char *)ret, sizeof (picl_retattrval_t) +
	    (size_t)ret->nbytes, NULL, 0);
}

/*
 * This function returns the value of the PICL property specified by
 * its name.
 */
static void
picld_get_attrval_by_name(picl_service_t *in)
{
	picl_retattrvalbyname_t	*ret;
	int			err;
	size_t			vbufsize;
	size_t			len;
	door_cred_t		cred;
	picl_nodehdl_t		ptreeh;
	ptree_propinfo_t	pinfo;

	if (door_cred(&cred) < 0)
		picld_return_error(in->in.cnum, PICL_FAILURE);

	err = cvt_picl2ptree(in->req_attrvalbyname.nodeh, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	err = xptree_get_propinfo_by_name(ptreeh,
	    in->req_attrvalbyname.propname, &pinfo);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	if (!(pinfo.piclinfo.accessmode & PICL_READ))
		picld_return_error(in->in.cnum, PICL_NOTREADABLE);

	/*
	 * allocate the minimum of piclinfo.size and input bufsize
	 */
	vbufsize = pinfo.piclinfo.size;
	vbufsize = MIN((size_t)in->req_attrvalbyname.bufsize, vbufsize);
	len = sizeof (picl_retattrvalbyname_t) + vbufsize;
	ret = alloca(len);
	if (ret == NULL)
		picld_return_error(in->in.cnum, PICL_FAILURE);
	ret->cnum = PICL_CNUM_GETATTRVALBYNAME;
	ret->nodeh = in->req_attrvalbyname.nodeh;
	(void) strcpy(ret->propname, in->req_attrvalbyname.propname);
	ret->nbytes = (uint32_t)vbufsize;

	err = xptree_get_propval_by_name_with_cred(ptreeh,
	    in->req_attrvalbyname.propname, ret->ret_buf, vbufsize,
	    cred);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);
	/*
	 * adjust returned value size for charstrings
	 */
	if (pinfo.piclinfo.type == PICL_PTYPE_CHARSTRING)
		ret->nbytes = (uint32_t)strlen(ret->ret_buf) + 1;

	if ((pinfo.piclinfo.type == PICL_PTYPE_TABLE) ||
	    (pinfo.piclinfo.type == PICL_PTYPE_REFERENCE))
		cvt_ptree2picl(&ret->ret_nodeh);

	(void) rw_unlock(&init_lk);
	(void) door_return((char *)ret, sizeof (picl_retattrvalbyname_t) +
	    (size_t)ret->nbytes, NULL, 0);
}

/*
 * This function sets a property value
 */
static void
picld_set_attrval(picl_service_t *in)
{
	picl_retsetattrval_t	ret;
	int			err;
	door_cred_t		cred;
	picl_prophdl_t		ptreeh;
	ptree_propinfo_t	pinfo;

	if (door_cred(&cred) < 0)
		picld_return_error(in->in.cnum, PICL_FAILURE);

	err = cvt_picl2ptree(in->req_setattrval.attr, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	err = ptree_get_propinfo(ptreeh, &pinfo);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	if (!(pinfo.piclinfo.accessmode & PICL_WRITE))
		picld_return_error(in->in.cnum, PICL_NOTWRITABLE);
	/*
	 * For non-volatile prop, only super user can set its value.
	 */
	if (!(pinfo.piclinfo.accessmode & PICL_VOLATILE) &&
	    (cred.dc_euid != SUPER_USER))
		picld_return_error(in->in.cnum, PICL_PERMDENIED);

	ret.cnum = PICL_CNUM_SETATTRVAL;
	ret.attr = in->req_setattrval.attr;

	err = xptree_update_propval_with_cred(ptreeh, in->req_setattrval.valbuf,
	    (size_t)in->req_setattrval.bufsize, cred);

	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retsetattrval_t), NULL,
	    0);
}

/*
 * This function sets the value of a property specified by its name.
 */
static void
picld_set_attrval_by_name(picl_service_t *in)
{
	picl_retsetattrvalbyname_t	ret;
	int				err;
	door_cred_t			cred;
	picl_prophdl_t			ptreeh;
	ptree_propinfo_t		pinfo;

	if (door_cred(&cred) < 0)
		picld_return_error(in->in.cnum, PICL_FAILURE);

	err = cvt_picl2ptree(in->req_setattrvalbyname.nodeh, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	err = xptree_get_propinfo_by_name(ptreeh,
	    in->req_setattrvalbyname.propname, &pinfo);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	if (!(pinfo.piclinfo.accessmode & PICL_WRITE))
		picld_return_error(in->in.cnum, PICL_NOTWRITABLE);

	/*
	 * For non-volatile prop, only super user can set its value.
	 */
	if (!(pinfo.piclinfo.accessmode & PICL_VOLATILE) &&
	    (cred.dc_euid != SUPER_USER))
		picld_return_error(in->in.cnum, PICL_PERMDENIED);

	ret.cnum = PICL_CNUM_SETATTRVALBYNAME;
	ret.nodeh = in->req_setattrvalbyname.nodeh;
	(void) strcpy(ret.propname, in->req_setattrvalbyname.propname);

	err = xptree_update_propval_by_name_with_cred(ptreeh,
	    in->req_setattrvalbyname.propname,
	    in->req_setattrvalbyname.valbuf,
	    (size_t)in->req_setattrvalbyname.bufsize,
	    cred);

	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retsetattrvalbyname_t),
	    NULL, 0);
}

/*
 * This function returns the property information
 */
static void
picld_get_attrinfo(picl_service_t *in)
{
	picl_retattrinfo_t	ret;
	int			err;
	ptree_propinfo_t	pinfo;
	picl_prophdl_t		ptreeh;

	err = cvt_picl2ptree(in->req_attrinfo.attr, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	ret.cnum = PICL_CNUM_GETATTRINFO;
	ret.attr = in->req_attrinfo.attr;

	err = ptree_get_propinfo(ptreeh, &pinfo);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	ret.type = pinfo.piclinfo.type;
	ret.accessmode = pinfo.piclinfo.accessmode;
	ret.size = (uint32_t)pinfo.piclinfo.size;
	(void) strcpy(ret.name, pinfo.piclinfo.name);
	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retattrinfo_t), NULL, 0);
}

/*
 * This function returns the node's first property handle
 */
static void
picld_get_first_attr(picl_service_t *in)
{
	picl_retfirstattr_t	ret;
	int			err;
	picl_prophdl_t		ptreeh;

	err = cvt_picl2ptree(in->req_firstattr.nodeh, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	ret.cnum = PICL_CNUM_GETFIRSTATTR;
	ret.nodeh = in->req_firstattr.nodeh;

	err = ptree_get_first_prop(ptreeh, &ret.attr);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);
	cvt_ptree2picl(&ret.attr);
	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retfirstattr_t), NULL, 0);
}

/*
 * This function returns the next property handle in list
 */
static void
picld_get_next_attr(picl_service_t *in)
{
	picl_retnextattr_t	ret;
	int			err;
	picl_prophdl_t		ptreeh;

	err = cvt_picl2ptree(in->req_nextattr.attr, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	ret.cnum = PICL_CNUM_GETNEXTATTR;
	ret.attr = in->req_nextattr.attr;

	err = ptree_get_next_prop(ptreeh, &ret.nextattr);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	cvt_ptree2picl(&ret.nextattr);

	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retnextattr_t), NULL, 0);
}

/*
 * This function returns the handle of a property specified by its name
 */
static void
picld_get_attr_by_name(picl_service_t *in)
{
	picl_retattrbyname_t	ret;
	int			err;
	picl_prophdl_t		ptreeh;

	err = cvt_picl2ptree(in->req_attrbyname.nodeh, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	ret.cnum = PICL_CNUM_GETATTRBYNAME;
	ret.nodeh = in->req_attrbyname.nodeh;
	(void) strcpy(ret.propname, in->req_attrbyname.propname);

	err = ptree_get_prop_by_name(ptreeh, ret.propname, &ret.attr);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	cvt_ptree2picl(&ret.attr);
	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retattrbyname_t), NULL,
	    0);
}

/*
 * This function gets the next property on the same row in the table
 */
static void
picld_get_attr_by_row(picl_service_t *in)
{
	picl_retattrbyrow_t	ret;
	int			err;
	picl_prophdl_t		ptreeh;

	err = cvt_picl2ptree(in->req_attrbyrow.attr, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	ret.cnum = PICL_CNUM_GETATTRBYROW;
	ret.attr = in->req_attrbyrow.attr;

	err = ptree_get_next_by_row(ptreeh, &ret.rowattr);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);
	cvt_ptree2picl(&ret.rowattr);

	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retattrbyrow_t), NULL, 0);
}

/*
 * This function returns the handle of the next property in the same column
 * of the table.
 */
static void
picld_get_attr_by_col(picl_service_t *in)
{
	picl_retattrbycol_t	ret;
	int			err;
	picl_prophdl_t		ptreeh;

	err = cvt_picl2ptree(in->req_attrbycol.attr, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	ret.cnum = PICL_CNUM_GETATTRBYCOL;
	ret.attr = in->req_attrbycol.attr;

	err = ptree_get_next_by_col(ptreeh, &ret.colattr);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	cvt_ptree2picl(&ret.colattr);

	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (picl_retattrbycol_t), NULL, 0);
}

/*
 * This function finds the node in the PICLTREE that matches the given
 * criteria and returns its handle.
 */
static void
picld_find_node(picl_service_t *in)
{
	picl_retfindnode_t	ret;
	int			err;
	picl_nodehdl_t		ptreeh;

	err = cvt_picl2ptree(in->req_findnode.nodeh, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	ret.cnum = PICL_CNUM_FINDNODE;

	err = ptree_find_node(ptreeh, in->req_findnode.propname,
	    in->req_findnode.ptype, in->req_findnode.valbuf,
	    in->req_findnode.valsize, &ret.rnodeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	cvt_ptree2picl(&ret.rnodeh);

	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (ret), NULL, 0);
}

/*
 * This function finds the property/node that corresponds to the given path
 * and returns its handle
 */
static void
picld_get_node_by_path(picl_service_t *in)
{
	picl_retnodebypath_t	ret;
	int			err;

	ret.cnum = PICL_CNUM_NODEBYPATH;
	err = ptree_get_node_by_path(in->req_nodebypath.pathbuf, &ret.nodeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);
	cvt_ptree2picl(&ret.nodeh);
	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (ret), NULL, 0);
}

/*
 * This function returns finds the frutree parent node for a given node
 * and returns its handle
 */
static void
picld_get_frutree_parent(picl_service_t *in)
{
	picl_retfruparent_t	ret;
	int			err;
	picl_nodehdl_t		ptreeh;

	err = cvt_picl2ptree(in->req_fruparent.devh, &ptreeh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);

	ret.cnum = PICL_CNUM_FRUTREEPARENT;

	err = ptree_get_frutree_parent(ptreeh, &ret.fruh);
	if (err != PICL_SUCCESS)
		picld_return_error(in->in.cnum, err);
	cvt_ptree2picl(&ret.fruh);

	(void) rw_unlock(&init_lk);
	(void) door_return((char *)&ret, sizeof (ret), NULL, 0);
}

/*
 * This function is called when an unknown client request is received.
 */
static void
picld_unknown_service(picl_service_t *in)
{
	picld_return_error(in->in.cnum, PICL_UNKNOWNSERVICE);
}

static void
check_denial_of_service(int cnum)
{
	hrtime_t	window;
	hrtime_t	current;
	int		dos_flag;

	current = gethrtime();
	dos_flag = 0;

	if (pthread_mutex_lock(&dos_mutex) != 0)
		picld_return_error(cnum, PICL_FAILURE);

	++service_requests;
	window = current - orig_time;
	if (window > MILLI_TO_NANO(sliding_interval_ms)) {
		orig_time = current;
		service_requests = 1;
	}

	if (service_requests > dos_req_limit)
		dos_flag = 1;

	if (pthread_mutex_unlock(&dos_mutex) != 0)
		picld_return_error(cnum, PICL_FAILURE);

	if (dos_flag)
		(void) poll(NULL, 0, dos_ms);
}

/* ARGSUSED */
static void
picld_door_handler(void *cookie, char *argp, size_t asize,
    door_desc_t *dp, uint_t n_desc)
{
	picl_service_t  *req;

	/*LINTED*/
	req = (picl_service_t *)argp;

	if (req == NULL)
		(void) door_return((char *)req, 0, NULL, 0);

	check_denial_of_service(req->in.cnum);

	(void) rw_rdlock(&init_lk);
	switch (req->in.cnum) {	/* client call number */
	case PICL_CNUM_INIT:
		/*LINTED*/
		picld_init((picl_service_t *)argp);
		break;
	case PICL_CNUM_FINI:
		/*LINTED*/
		picld_fini((picl_service_t *)argp);
		break;
	case PICL_CNUM_GETROOT:
		/*LINTED*/
		picld_getroot((picl_service_t *)argp);
		break;
	case PICL_CNUM_GETATTRVAL:
		/*LINTED*/
		picld_get_attrval((picl_service_t *)argp);
		break;
	case PICL_CNUM_GETATTRVALBYNAME:
		/*LINTED*/
		picld_get_attrval_by_name((picl_service_t *)argp);
		break;
	case PICL_CNUM_GETATTRINFO:
		/*LINTED*/
		picld_get_attrinfo((picl_service_t *)argp);
		break;
	case PICL_CNUM_GETFIRSTATTR:
		/*LINTED*/
		picld_get_first_attr((picl_service_t *)argp);
		break;
	case PICL_CNUM_GETNEXTATTR:
		/*LINTED*/
		picld_get_next_attr((picl_service_t *)argp);
		break;
	case PICL_CNUM_GETATTRBYNAME:
		/*LINTED*/
		picld_get_attr_by_name((picl_service_t *)argp);
		break;
	case PICL_CNUM_GETATTRBYROW:
		/*LINTED*/
		picld_get_attr_by_row((picl_service_t *)argp);
		break;
	case PICL_CNUM_GETATTRBYCOL:
		/*LINTED*/
		picld_get_attr_by_col((picl_service_t *)argp);
		break;
	case PICL_CNUM_SETATTRVAL:
		/*LINTED*/
		picld_set_attrval((picl_service_t *)argp);
		break;
	case PICL_CNUM_SETATTRVALBYNAME:
		/*LINTED*/
		picld_set_attrval_by_name((picl_service_t *)argp);
		break;
	case PICL_CNUM_PING:
		/*LINTED*/
		picld_ping((picl_service_t *)argp);
		break;
	case PICL_CNUM_WAIT:
		/*LINTED*/
		picld_wait((picl_service_t *)argp);
		break;
	case PICL_CNUM_FINDNODE:
		/*LINTED*/
		picld_find_node((picl_service_t *)argp);
		break;
	case PICL_CNUM_NODEBYPATH:
		/*LINTED*/
		picld_get_node_by_path((picl_service_t *)argp);
		break;
	case PICL_CNUM_FRUTREEPARENT:
		/*LINTED*/
		picld_get_frutree_parent((picl_service_t *)argp);
		break;
	default:
		/*LINTED*/
		picld_unknown_service((picl_service_t *)argp);
		break;
	};
	/*NOTREACHED*/
}

/* ARGSUSED */
static void
hup_handler(int sig, siginfo_t *siginfo, void *sigctx)
{
	doreinit = 1;
}

/*
 * "ping" to see if a daemon is already running
 */
static int
daemon_exists(void)
{
	door_arg_t	darg;
	picl_reqping_t	req_ping;
	picl_retping_t	ret_ping;
	int		doorh;
	door_info_t	dinfo;

	doorh = open(PICLD_DOOR, O_RDONLY);
	if (doorh < 0)
		return (0);

	if (door_info(doorh, &dinfo) < 0) {
		(void) close(doorh);
		return (0);
	}

	if ((dinfo.di_attributes & DOOR_REVOKED) ||
	    (dinfo.di_data != (uintptr_t)PICLD_DOOR_COOKIE)) {
		(void) close(doorh);
		return (0);
	}

	if (dinfo.di_target != getpid()) {
		(void) close(doorh);
		return (1);
	}

	req_ping.cnum = PICL_CNUM_PING;

	darg.data_ptr = (char *)&req_ping;
	darg.data_size = sizeof (picl_reqping_t);
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = (char *)&ret_ping;
	darg.rsize = sizeof (picl_retping_t);

	if (door_call(doorh, &darg) < 0) {
		(void) close(doorh);
		return (0);
	}

	(void) close(doorh);
	return (1);
}

/*
 * picld_create_server_thread - binds the running thread to the private
 * door pool, and sets the required cancellation state.
 */
/* ARGSUSED */
static void *
picld_create_server_thread(void *arg)
{
	/*
	 * wait for door descriptor to be initialized
	 */
	(void) pthread_mutex_lock(&door_mutex);
	while (door_id == -1) {
		(void) pthread_cond_wait(&door_cv, &door_mutex);
	}
	(void) pthread_mutex_unlock(&door_mutex);

	/*
	 * Bind this thread to the door's private thread pool
	 */
	if (door_bind(door_id) < 0) {
		perror("door_bind");
	}

	/*
	 * Disable thread cancellation mechanism
	 */
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	(void) door_return(NULL, 0, NULL, 0); /* wait for door invocation */
	return (NULL);
}

/*
 * picld_server_create_fn - creates threads for the private door pool
 *
 */
/* ARGSUSED */
static void
picld_server_create_fn(door_info_t *dip)
{
	pthread_attr_t attr;

	/*
	 * For the non-private pool do nothing. It's used for events which are
	 * single threaded anyway. The single thread servicing that pool is
	 * created when the event plugin creates its door. Note that the event
	 * plugin runs before setup_door instantiates picld_server_create_fn as
	 * the new create_proc so the door library default create_proc is used.
	 */
	if (dip == NULL)
		return;

	(void) pthread_mutex_lock(&pool_mutex);
	if (pool_count < MAX_POOL_SIZE) {
		(void) pthread_attr_init(&attr);
		(void) pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
		(void) pthread_attr_setdetachstate(&attr,
		    PTHREAD_CREATE_DETACHED);
		if (pthread_create(NULL, &attr, picld_create_server_thread,
		    NULL)) {
			perror("pthread_create");
		} else {
			pool_count++;
		}
	}
	(void) pthread_mutex_unlock(&pool_mutex);
}

/*
 * Create the picld door
 */
static int
setup_door(void)
{
	struct stat	stbuf;

	(void) door_server_create(picld_server_create_fn);
	(void) pthread_mutex_lock(&door_mutex);
	/*
	 * Create the door
	 */
	door_id = door_create(picld_door_handler, PICLD_DOOR_COOKIE,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL | DOOR_PRIVATE);

	if (door_id < 0) {
		(void) pthread_mutex_unlock(&door_mutex);
		return (-1);
	} else {
		(void) pthread_cond_signal(&door_cv);
		(void) pthread_mutex_unlock(&door_mutex);
	}

	if (stat(PICLD_DOOR, &stbuf) < 0) {
		int newfd;
		mode_t old_mask;
		/* ensure that the door file is world-readable */
		old_mask = umask(0);
		newfd = creat(PICLD_DOOR, 0444);
		/* restore the file mode creation mask */
		(void) umask(old_mask);
		if (newfd < 0)
			return (-1);
		(void) close(newfd);
	}

	if (fattach(door_id, PICLD_DOOR) < 0) {
		if ((errno != EBUSY) ||
		    (fdetach(PICLD_DOOR) < 0) ||
		    (fattach(door_id, PICLD_DOOR) < 0))
			return (-1);
	}
	return (0);
}

/*
 * Main function of picl daemon
 */
int
main(int argc, char **argv)
{
	struct	sigaction	act;
	int			c;
	sigset_t		ublk;


	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (getuid() != 0) {
		syslog(LOG_CRIT, MUST_BE_ROOT);
		return (0);
	}

	(void) rwlock_init(&init_lk, USYNC_THREAD, NULL);
	doreinit = 0;
	logflag = 1;
	dos_req_limit = DOS_PICL_REQUESTS_LIMIT;
	sliding_interval_ms = SLIDING_INTERVAL_MILLISECONDS;
	dos_ms = DOS_SLEEPTIME_MS;
	verbose_level = 0;

	/*
	 * parse arguments
	 */
	while ((c = getopt(argc, argv, "is:t:l:r:v:d:")) != EOF) {
		switch (c) {
		case 'd':
			dos_ms = strtol(optarg, (char **)NULL, 0);
			break;
		case 'i':
			logflag = 0;
			break;
		case 's':
			sliding_interval_ms = strtoll(optarg, (char **)NULL, 0);
			break;
		case 't':
			dos_req_limit = strtol(optarg, (char **)NULL, 0);
			break;
		case 'v':
			verbose_level = strtol(optarg, (char **)NULL, 0);
			logflag = 0;
			break;
		default:
			break;
		}
	}

	orig_time = gethrtime();

	/*
	 * is there a daemon already running?
	 */

	if (daemon_exists()) {
		syslog(LOG_CRIT, DAEMON_RUNNING);
		exit(1);
	}

	/*
	 * Mask off/block SIGALRM signal so that the environmental plug-in
	 * (piclenvd) can use it to simulate sleep() without being affected
	 * by time being set back. No other PICL plug-in should use SIGALRM
	 * or alarm() for now.
	 */
	(void) sigemptyset(&ublk);
	(void) sigaddset(&ublk, SIGALRM);
	(void) sigprocmask(SIG_BLOCK, &ublk, NULL);

	/*
	 * Ignore SIGHUP until all the initialization is done.
	 */
	act.sa_handler = SIG_IGN;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGHUP, &act, NULL) == -1)
		syslog(LOG_ERR, SIGACT_FAILED, strsignal(SIGHUP),
		    strerror(errno));

	if (logflag != 0) {	/* daemonize */
		pid_t pid;

		pid = fork();
		if (pid < 0)
			exit(1);
		if (pid > 0)
			/* parent */
			exit(0);

		/* child */
		if (chdir("/") == -1) {
			syslog(LOG_CRIT, CD_ROOT_FAILED);
			exit(1);
		}

		(void) setsid();
		closefrom(0);
		(void) open("/dev/null", O_RDWR, 0);
		(void) dup2(STDIN_FILENO, STDOUT_FILENO);
		(void) dup2(STDIN_FILENO, STDERR_FILENO);
		openlog(PICLD, LOG_PID, LOG_DAEMON);
	}

	/*
	 * Initialize the PICL Tree
	 */
	if (xptree_initialize(0) != PICL_SUCCESS) {
		syslog(LOG_CRIT, INIT_FAILED);
		exit(1);
	}

	if (setup_door()) {
		syslog(LOG_CRIT, DOOR_FAILED);
		exit(1);
	}

	/*
	 * setup signal handlers for post-init
	 */
	act.sa_sigaction = hup_handler;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGHUP, &act, NULL) == -1)
		syslog(LOG_ERR, SIGACT_FAILED, strsignal(SIGHUP),
		    strerror(errno));

	/*
	 * wait for requests
	 */
	for (;;) {
		(void) pause();
		if (doreinit) {
			/*
			 * Block SIGHUP during reinitialization.
			 * Also mask off/block SIGALRM signal so that the
			 * environmental plug-in (piclenvd) can use it to
			 * simulate sleep() without being affected by time
			 * being set back. No ohter PICL plug-in should use
			 * SIGALRM or alarm() for now.
			 */
			(void) sigemptyset(&ublk);
			(void) sigaddset(&ublk, SIGHUP);
			(void) sigaddset(&ublk, SIGALRM);
			(void) sigprocmask(SIG_BLOCK, &ublk, NULL);
			(void) sigdelset(&ublk, SIGALRM);
			doreinit = 0;
			(void) rw_wrlock(&init_lk);
			xptree_destroy();
			(void) xptree_reinitialize();
			(void) rw_unlock(&init_lk);
			(void) sigprocmask(SIG_UNBLOCK, &ublk, NULL);
		}
	}
}
