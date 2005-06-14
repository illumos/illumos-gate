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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module implements the PICL Interface used by PICL clients
 * to access services of the PICL daemon
 *
 * Locking Strategy
 * A single reader/writer lock (icl_lock) protects the access to the interface
 * to the picl daemon, and the reference count, refcnt, variable.
 * A reader lock is obtained to send a request to the daemon.
 * A writer lock is obtained to initialize, reinitialize, or shutdown
 * the interface.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <fcntl.h>
#include <libintl.h>
#include <errno.h>
#include <sys/mman.h>
#include <door.h>
#include <sys/door.h>
#include <sys/time.h>
#include <assert.h>
#include <synch.h>
#include <limits.h>
#include <picl.h>
#include "picl2door.h"

/*
 * Module variables
 */
static	int		door_handle = -1;
static	uint32_t	refcnt = 0;
static	rwlock_t	picl_lock = DEFAULTRWLOCK;

static	char 		*picl_errmsg[] = {
	"No error",
	"General system failure",
	"Daemon not responding",
	"Unknown PICL service",
	"Session not initialized",
	"Invalid arguments",
	"Argument too big",
	"Property not found",
	"Not a table property handle",
	"Not a node handle",
	"Not a property handle",
	"End of property list",
	"Property already exists",
	"Property not writable",
	"Insufficient permissions",
	"Invalid handle",
	"Stale handle",
	"Unsupported version",
	"Wait timed out",
	"Attempting to destroy before delete",
	"PICL Tree is busy",
	"Already has a parent",
	"Property name is reserved",
	"Invalid reference value",
	"Continue tree walk",
	"Terminate tree walk",
	"Node not found",
	"Not enough space available",
	"Property not readable",
	"Property value unavailable"
};

#define	N_ERRORS 		(sizeof (picl_errmsg)/sizeof (picl_errmsg[0]))
#define	SEND_REQ_TRYCOUNT	1

/*
 * This function sends the client request to the daemon using a door call.
 * If door_handle is -1, it returns PICL_NOTINITIALIZED.
 * If the door_call fails, it returns PICL_NORESPONSE. Otherwise, it
 * checks the response from the daemon for error. If an error is returned
 * this function returns the error code returned and unmaps any
 * memory mapped by the door call. For successful results, the caller is
 * responsible to unmap the mapped memory after retrieving the results.
 *
 * This function does not attempt to reinitialize the interface if the
 * initial door_call fails. It is called from handshake() , shutdown()
 * and trysend_req() routines.
 */
static int
post_req(door_arg_t *dargp, void *data_ptr, size_t data_size,
    door_desc_t *desc_ptr, uint_t desc_num, void *rbuf, size_t rsize)
{
	int		err;
	picl_service_t	*ret;
	int		req_cnum;

	req_cnum = ((picl_service_t *)data_ptr)->in.cnum;
	dargp->data_ptr = data_ptr;
	dargp->data_size = data_size;
	dargp->desc_ptr = desc_ptr;
	dargp->desc_num = desc_num;
	dargp->rbuf = rbuf;
	dargp->rsize = rsize;

	if (door_call(door_handle, dargp) < 0)
		return (PICL_NORESPONSE);

	/*LINTED*/
	ret = (picl_service_t *)dargp->rbuf;
	if (ret->in.cnum == req_cnum)
		return (PICL_SUCCESS);
	else if ((ret->in.cnum == PICL_CNUM_ERROR) &&
	    (ret->ret_error.in_cnum == req_cnum))
		err = ret->ret_error.errnum;
	else
	    err = PICL_UNKNOWNSERVICE;
	if (dargp->rbuf != rbuf)
		(void) munmap(dargp->rbuf, dargp->rsize);
	return (err);
}

/*
 * This function posts an INIT message to the daemon to
 * verify communication channel.
 */
static int
handshake(void)
{
	int		err;
	door_arg_t	darg;
	picl_reqinit_t	req;
	picl_retinit_t	outargs;

	req.cnum = PICL_CNUM_INIT;
	req.clrev = PICL_VERSION_1;

	if ((err = post_req(&darg, &req, sizeof (picl_reqinit_t), NULL,
	    0, &outargs, sizeof (picl_retinit_t))) != PICL_SUCCESS)
		return (err);

	if (darg.rbuf != (char *)&outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (PICL_SUCCESS);
}

/*
 * This function calls post_req() to make door_call and reinitializes
 * the interface is post_req() fails.
 */
static int
trysend_req(door_arg_t *dargp, void *data_ptr, size_t data_size,
    door_desc_t *desc_ptr, uint_t desc_num, void *rbuf, size_t rsize,
	unsigned int trycount)
{
	int	err;
	int	write_locked;

	write_locked = 0;
	(void) rw_rdlock(&picl_lock);
	if (refcnt == 0) {
		(void) rw_unlock(&picl_lock);	/* read unlock */
		return (PICL_NOTINITIALIZED);
	}

	while ((err = post_req(dargp, data_ptr, data_size, desc_ptr, desc_num,
	    rbuf, rsize)) == PICL_NORESPONSE) {
		if (trycount == 0)	/* no more retry */
			break;

		if (write_locked == 1) {	/* close and open door */
			(void) close(door_handle);
			if ((door_handle = open(PICLD_DOOR, O_RDONLY)) < 0) {
				err = PICL_NORESPONSE;
				break;
			}
			--trycount;
			continue;
		}
		/*
		 * Upgrade read to a write lock
		 */
		(void) rw_unlock(&picl_lock);
		(void) rw_wrlock(&picl_lock);

		/*
		 * if picl_shutdown happens during lock upgrade
		 */
		if (refcnt == 0) {
			err =  PICL_NOTINITIALIZED;
			break;
		}
		write_locked = 1;
		continue;
	}
	(void) rw_unlock(&picl_lock);	/* read or write unlock */
	return (err);
}

/*
 * Initialize the PICL interface
 * Increment the reference count.
 */
int
picl_initialize(void)
{
	int	err;

	(void) rw_wrlock(&picl_lock);
	if (refcnt > 0) {		/* previously initialized */
		err = handshake();
		if (err == PICL_SUCCESS) {
			++refcnt;
			(void) rw_unlock(&picl_lock);	/* write unlock */
			return (err);
		}
		if (err != PICL_NORESPONSE) {
			(void) rw_unlock(&picl_lock);	/* write unlock */
			return (err);
		}
		(void) close(door_handle);	/* close bad door */
	}

	/*
	 * Open picld door and initialize door_handle
	 */
	if ((door_handle = open(PICLD_DOOR, O_RDONLY)) < 0) {
		(void) rw_unlock(&picl_lock); /* write unlock */
		return (PICL_NORESPONSE);
	}

	err = handshake();
	if (err != PICL_SUCCESS)
		(void) close(door_handle);
	else
		++refcnt;
	(void) rw_unlock(&picl_lock);	/* write unlock */
	return (err);
}

/*
 * Shutdown the PICL interface
 * Decrement the reference count and close the door_handle if refcnt is zero
 */
int
picl_shutdown(void)
{
	int		err;
	door_arg_t	darg;
	picl_reqfini_t	req_fini;
	picl_retfini_t	outargs;

	(void) rw_wrlock(&picl_lock);	/* write lock */
	if (refcnt == 0) {
		(void) rw_unlock(&picl_lock);	/* write unlock */
		return (PICL_NOTINITIALIZED);
	}
	req_fini.cnum = PICL_CNUM_FINI;
	err = post_req(&darg, &req_fini, sizeof (picl_reqfini_t),
	    NULL, 0, &outargs, sizeof (picl_retfini_t));
	--refcnt;
	if (refcnt == 0)
		(void) close(door_handle);
	(void) rw_unlock(&picl_lock);	/* write unlock */
	if (err != PICL_SUCCESS)
		return (err);
	if (darg.rbuf != (char *)&outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (PICL_SUCCESS);
}

/*
 * This function waits for the specified number of seconds for a PICL
 * tree refresh.
 */
int
picl_wait(unsigned int secs)
{
	door_arg_t	darg;
	picl_reqwait_t	req_wait;
	picl_retwait_t	outargs;
	picl_service_t	*ret;
	int		err;

	req_wait.cnum = PICL_CNUM_WAIT;
	req_wait.secs = secs;
	err = trysend_req(&darg, &req_wait, sizeof (picl_reqwait_t),
	    NULL, 0, &outargs, sizeof (picl_retwait_t), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	err = ret->ret_wait.retcode;
	if (darg.rbuf != (char *)&outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (err);
}

/*
 * This function copies the handle of the root node of the PICL tree into
 * the buffer <rooth>
 */
int
picl_get_root(picl_nodehdl_t *rooth)
{
	door_arg_t	darg;
	picl_reqroot_t	req_root;
	picl_retroot_t	outargs;
	picl_service_t	*ret;
	int	err;

	req_root.cnum = PICL_CNUM_GETROOT;
	err = trysend_req(&darg, &req_root, sizeof (picl_reqroot_t), NULL,
	    0, &outargs, sizeof (picl_retroot_t), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);
	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	*rooth = ret->ret_root.rnode;
	if (darg.rbuf != (char *)&outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (PICL_SUCCESS);
}

/*
 * This function copies the value of the property specified by its handle
 * into the buffer <valbuf>.
 */
int
picl_get_propval(picl_prophdl_t proph, void *valbuf, size_t nbytes)
{
	door_arg_t		darg;
	picl_reqattrval_t	req_attrval;
	picl_service_t		*ret;
	picl_retattrval_t	*outargs;
	int			err;

	req_attrval.cnum = PICL_CNUM_GETATTRVAL;
	req_attrval.attr = proph;
	req_attrval.bufsize = (uint32_t)nbytes;
	if ((size_t)req_attrval.bufsize != nbytes)
		return (PICL_VALUETOOBIG);
	outargs = alloca(sizeof (picl_retattrval_t) + nbytes);

	err = trysend_req(&darg, &req_attrval, sizeof (picl_reqattrval_t),
	    NULL, 0, outargs, sizeof (picl_retattrval_t) + nbytes,
	    SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	if (ret->ret_attrval.nbytes > (uint32_t)nbytes)
		err = PICL_VALUETOOBIG;
	else
		(void) memcpy(valbuf, ret->ret_attrval.ret_buf,
		    (size_t)ret->ret_attrval.nbytes);
	if (darg.rbuf != (char *)outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (err);
}

/*
 * This function copies the value of the property specified by its
 * name into the buffer <valbuf>
 */
int
picl_get_propval_by_name(picl_nodehdl_t nodeh, const char *propname,
    void *valbuf, size_t nbytes)
{
	door_arg_t		darg;
	picl_reqattrvalbyname_t	req_attrvalbyname;
	picl_service_t		*ret;
	picl_retattrvalbyname_t	*outargs;
	int			err;

	req_attrvalbyname.cnum = PICL_CNUM_GETATTRVALBYNAME;
	req_attrvalbyname.nodeh = nodeh;
	(void) strcpy(req_attrvalbyname.propname, propname);
	req_attrvalbyname.bufsize = (uint32_t)nbytes;
	if ((size_t)req_attrvalbyname.bufsize != nbytes)
		return (PICL_VALUETOOBIG);
	outargs = alloca(sizeof (picl_retattrvalbyname_t) + nbytes);

	err = trysend_req(&darg, &req_attrvalbyname,
	    sizeof (picl_reqattrvalbyname_t), NULL, 0, outargs,
	    sizeof (picl_retattrvalbyname_t) + nbytes, SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	if (ret->ret_attrvalbyname.nbytes > (uint32_t)nbytes)
		err = PICL_VALUETOOBIG;
	else
		(void) memcpy(valbuf, ret->ret_attrvalbyname.ret_buf,
		    (size_t)ret->ret_attrvalbyname.nbytes);
	if (darg.rbuf != (char *)outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (err);
}

/*
 * This function sets the value of the property specified by its
 * handle with the value specified in <valbuf>.
 */
int
picl_set_propval(picl_prophdl_t proph, void *valbuf, size_t nbytes)
{
	door_arg_t		darg;
	picl_reqsetattrval_t	ret_setattrval;
	picl_reqsetattrval_t	*inargs;
	int			err;

	if (nbytes >= (size_t)PICL_PROPSIZE_MAX)
		return (PICL_VALUETOOBIG);

	inargs = alloca(sizeof (picl_reqsetattrval_t) + nbytes);
	inargs->cnum = PICL_CNUM_SETATTRVAL;
	inargs->attr = proph;
	inargs->bufsize = (uint32_t)nbytes;
	if ((size_t)inargs->bufsize != nbytes)
		return (PICL_VALUETOOBIG);
	(void) memcpy(inargs->valbuf, valbuf, nbytes);

	err = trysend_req(&darg, inargs, sizeof (picl_reqsetattrval_t) +
	    nbytes, NULL, 0, &ret_setattrval,
	    sizeof (picl_retsetattrval_t), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	if (darg.rbuf != (char *)&ret_setattrval)
		(void) munmap(darg.rbuf, darg.rsize);
	return (PICL_SUCCESS);
}

/*
 * This function sets the value of the property specified by its
 * name with the value given in <valbuf>
 */
int
picl_set_propval_by_name(picl_nodehdl_t nodeh, const char *propname,
    void *valbuf, size_t nbytes)
{
	door_arg_t			darg;
	picl_retsetattrvalbyname_t	ret_setattrvalbyname;
	picl_reqsetattrvalbyname_t	*inargs;
	int				err;

	if (nbytes >= (size_t)PICL_PROPSIZE_MAX)
		return (PICL_VALUETOOBIG);

	inargs = alloca(sizeof (picl_reqsetattrvalbyname_t) + nbytes);
	inargs->cnum = PICL_CNUM_SETATTRVALBYNAME;
	inargs->nodeh = nodeh;
	(void) strcpy(inargs->propname, propname);
	inargs->bufsize = (uint32_t)nbytes;
	if ((size_t)inargs->bufsize != nbytes)
		return (PICL_VALUETOOBIG);
	(void) memcpy(inargs->valbuf, valbuf, nbytes);

	err = trysend_req(&darg, inargs,
	    sizeof (picl_reqsetattrvalbyname_t) + nbytes, NULL, 0,
	    &ret_setattrvalbyname, sizeof (picl_retsetattrvalbyname_t),
	    SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	if (darg.rbuf != (char *)&ret_setattrvalbyname)
		(void) munmap(darg.rbuf, darg.rsize);
	return (PICL_SUCCESS);
}

/*
 * This function copies the information of the specified property
 * into <pinfo>
 */
int
picl_get_propinfo(picl_prophdl_t proph, picl_propinfo_t *pinfo)
{
	door_arg_t		darg;
	picl_reqattrinfo_t	req_attrinfo;
	picl_service_t		*ret;
	picl_retattrinfo_t	outargs;
	int			err;

	req_attrinfo.cnum = PICL_CNUM_GETATTRINFO;
	req_attrinfo.attr = proph;

	err = trysend_req(&darg, &req_attrinfo,
	    sizeof (picl_reqattrinfo_t), NULL, 0, &outargs,
	    sizeof (picl_retattrinfo_t), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	pinfo->type = ret->ret_attrinfo.type;
	pinfo->accessmode = ret->ret_attrinfo.accessmode;
	pinfo->size = (size_t)ret->ret_attrinfo.size;
	(void) strcpy(pinfo->name, ret->ret_attrinfo.name);
	if (darg.rbuf != (char *)&outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (PICL_SUCCESS);
}

/*
 * This function copies the handle of the first property of a node into
 * <proph>
 */
int
picl_get_first_prop(picl_nodehdl_t nodeh, picl_prophdl_t *proph)
{
	door_arg_t		darg;
	picl_reqfirstattr_t	req_firstattr;
	picl_service_t		*ret;
	picl_retfirstattr_t	outargs;
	int			err;

	req_firstattr.cnum = PICL_CNUM_GETFIRSTATTR;
	req_firstattr.nodeh = nodeh;

	err = trysend_req(&darg, &req_firstattr,
	    sizeof (picl_reqfirstattr_t), NULL, 0, &outargs,
	    sizeof (picl_retfirstattr_t), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	*proph = ret->ret_firstattr.attr;
	if (darg.rbuf != (char *)&outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (PICL_SUCCESS);
}

/*
 * This function copies the handle of the next property in list
 * into <nextprop>.
 */
int
picl_get_next_prop(picl_prophdl_t proph, picl_prophdl_t *nextprop)
{
	door_arg_t		darg;
	picl_reqnextattr_t	req_nextattr;
	picl_service_t		*ret;
	picl_retnextattr_t	outargs;
	int			err;


	req_nextattr.cnum = PICL_CNUM_GETNEXTATTR;
	req_nextattr.attr = proph;

	err = trysend_req(&darg, &req_nextattr,
	    sizeof (picl_reqnextattr_t), NULL, 0,  &outargs,
	    sizeof (picl_retnextattr_t), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	*nextprop = ret->ret_nextattr.nextattr;
	if (darg.rbuf != (char *)&outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (PICL_SUCCESS);
}

/*
 * This function copies the handle of the property specified by its
 * name into <proph>.
 */
int
picl_get_prop_by_name(picl_nodehdl_t nodeh, const char *name,
    picl_prophdl_t *proph)
{
	door_arg_t		darg;
	picl_reqattrbyname_t	req_attrbyname;
	picl_service_t		*ret;
	picl_retattrbyname_t	outargs;
	int			err;

	req_attrbyname.cnum = PICL_CNUM_GETATTRBYNAME;
	req_attrbyname.nodeh = nodeh;
	(void) strcpy(req_attrbyname.propname, name);

	err = trysend_req(&darg, &req_attrbyname,
	    sizeof (picl_reqattrbyname_t), NULL, 0, &outargs,
	    sizeof (picl_retattrbyname_t), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	*proph = ret->ret_attrbyname.attr;
	if (darg.rbuf != (char *)&outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (PICL_SUCCESS);
}

/*
 * This function copies the handle of the next property on the same
 * row of the table into <rowproph>.
 * When proph is the table handle, the handle of the property that is
 * in first row and first column is copied.
 */
int
picl_get_next_by_row(picl_prophdl_t proph, picl_prophdl_t *rowproph)
{
	door_arg_t		darg;
	picl_reqattrbyrow_t	req_attrbyrow;
	picl_service_t		*ret;
	picl_retattrbyrow_t	outargs;
	int			err;

	req_attrbyrow.cnum = PICL_CNUM_GETATTRBYROW;
	req_attrbyrow.attr = proph;

	err = trysend_req(&darg, &req_attrbyrow,
	    sizeof (picl_reqattrbyrow_t), NULL, 0, &outargs,
	    sizeof (picl_retattrbyrow_t), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	*rowproph = ret->ret_attrbyrow.rowattr;
	if (darg.rbuf != (char *)&outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (PICL_SUCCESS);
}

/*
 * This function copies the handle of the next property on the same
 * column of the table into <colproph>.
 * When proph is the table handle, the handle of the property that is
 * in the first row and first column is copied.
 */
int
picl_get_next_by_col(picl_prophdl_t proph, picl_prophdl_t *colproph)
{
	door_arg_t		darg;
	picl_reqattrbycol_t	req_attrbycol;
	picl_service_t		*ret;
	picl_retattrbycol_t	outargs;
	int			err;

	req_attrbycol.cnum = PICL_CNUM_GETATTRBYCOL;
	req_attrbycol.attr = proph;

	err = trysend_req(&darg, (char *)&req_attrbycol,
	    sizeof (picl_reqattrbycol_t), NULL, 0, (char *)&outargs,
	    sizeof (picl_retattrbycol_t), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	*colproph = ret->ret_attrbycol.colattr;
	if (darg.rbuf != (char *)&outargs)
		(void) munmap(darg.rbuf, darg.rsize);
	return (PICL_SUCCESS);
}

/*
 * This function returns the picl error messages corresponding to the
 * error number.
 */
char *
picl_strerror(int err)
{
	if ((err < N_ERRORS) && (err >= 0)) {
		return (gettext(picl_errmsg[err]));
	}
	return ((char *)NULL);
}

/*
 * recursively visit all nodes
 */
static int
do_walk(picl_nodehdl_t rooth, const char *classname,
    void *c_args, int (*callback_fn)(picl_nodehdl_t hdl, void *args))
{
	int		err;
	picl_nodehdl_t	chdh;
	char		classval[PICL_CLASSNAMELEN_MAX];

	err = picl_get_propval_by_name(rooth, PICL_PROP_CHILD, &chdh,
	    sizeof (chdh));
	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(chdh, PICL_PROP_CLASSNAME,
		    classval, sizeof (classval));
		if (err != PICL_SUCCESS)
			return (err);

		if ((classname == NULL) || (strcmp(classname, classval) == 0)) {
			err = callback_fn(chdh, c_args);
			if (err != PICL_WALK_CONTINUE)
				return (err);
		}

		if ((err = do_walk(chdh, classname, c_args, callback_fn)) !=
		    PICL_WALK_CONTINUE)
			return (err);

		err = picl_get_propval_by_name(chdh, PICL_PROP_PEER, &chdh,
		    sizeof (chdh));
	}
	if (err == PICL_PROPNOTFOUND)	/* end of a branch */
		return (PICL_WALK_CONTINUE);
	return (err);

}

/*
 * This function walks the tree by class and invokes the callback
 * function on class name matches.
 */
int
picl_walk_tree_by_class(picl_nodehdl_t rooth, const char *classname,
    void *c_args, int (*callback_fn)(picl_nodehdl_t hdl, void *args))
{
	int		err;

	if (callback_fn == NULL)
		return (PICL_INVALIDARG);
	err = do_walk(rooth, classname, c_args, callback_fn);
	if ((err == PICL_WALK_CONTINUE) || (err == PICL_WALK_TERMINATE))
		return (PICL_SUCCESS);
	return (err);
}

/*
 * This function gets propinfo and prop handle of the named property
 */
int
picl_get_propinfo_by_name(picl_nodehdl_t nodeh, const char *prop_name,
    picl_propinfo_t *pinfo, picl_prophdl_t *proph)
{
	int		err;
	picl_prophdl_t	tmpproph;
	picl_propinfo_t	tmppinfo;

	err = picl_get_prop_by_name(nodeh, prop_name, &tmpproph);
	if (err != PICL_SUCCESS)
		return (err);

	err = picl_get_propinfo(tmpproph, &tmppinfo);
	if (err != PICL_SUCCESS)
		return (err);

	*proph = tmpproph;
	*pinfo = tmppinfo;
	return (PICL_SUCCESS);
}

int
picl_get_node_by_path(const char *piclpath, picl_nodehdl_t *nodeh)
{
	door_arg_t		darg;
	picl_reqnodebypath_t	req;
	picl_retnodebypath_t	out;
	picl_service_t		*ret;
	int	err;

	req.cnum = PICL_CNUM_NODEBYPATH;
	req.psize = PATH_MAX;
	if (strlen(piclpath) >= PATH_MAX)
		return (PICL_VALUETOOBIG);
	(void) strncpy(req.pathbuf, piclpath, PATH_MAX);

	err = trysend_req(&darg, &req, sizeof (req), NULL, 0, &out,
	    sizeof (out), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	*nodeh = ret->ret_nodebypath.nodeh;
	if (darg.rbuf != (char *)&out)
		(void) munmap(darg.rbuf, darg.rsize);
	return (err);
}

int
picl_find_node(picl_nodehdl_t rooth, char *pname, picl_prop_type_t ptype,
    void *pval, size_t valsize, picl_nodehdl_t *retnodeh)
{
	door_arg_t		darg;
	picl_reqfindnode_t	*req;
	picl_service_t		*ret;
	picl_retfindnode_t	out;
	int			err;

	req = alloca(sizeof (picl_reqfindnode_t) + valsize);
	req->cnum = PICL_CNUM_FINDNODE;
	req->nodeh = rooth;
	if (strlen(pname) >= PICL_PROPNAMELEN_MAX)
		return (PICL_VALUETOOBIG);
	(void) strncpy(req->propname, pname, PICL_PROPNAMELEN_MAX);
	req->ptype = ptype;
	req->valsize = (uint32_t)valsize;
	if ((size_t)req->valsize != valsize)
		return (PICL_VALUETOOBIG);
	(void) memcpy(req->valbuf, pval, valsize);

	err = trysend_req(&darg, req, sizeof (picl_reqfindnode_t) + valsize,
	    NULL, 0, &out, sizeof (out), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	*retnodeh = ret->ret_findnode.rnodeh;
	if (darg.rbuf != (char *)&out)
		(void) munmap(darg.rbuf, darg.rsize);
	return (err);
}

int
picl_get_frutree_parent(picl_nodehdl_t devh, picl_nodehdl_t *fruh)
{
	door_arg_t		darg;
	picl_reqfruparent_t	req;
	picl_retfruparent_t	out;
	picl_service_t		*ret;
	int			err;

	req.cnum = PICL_CNUM_FRUTREEPARENT;
	req.devh = devh;

	err = trysend_req(&darg, &req, sizeof (req), NULL, 0, &out,
	    sizeof (out), SEND_REQ_TRYCOUNT);
	if (err != PICL_SUCCESS)
		return (err);

	/*LINTED*/
	ret = (picl_service_t *)darg.rbuf;
	*fruh = ret->ret_fruparent.fruh;
	if (darg.rbuf != (char *)&out)
		(void) munmap(darg.rbuf, darg.rsize);
	return (err);
}
