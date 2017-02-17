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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/rsm/rsm_common.h>
#include <sys/rsm/rsmpi.h>
#include <sys/rsm/rsmpi_driver.h>

/* lint -w2 */
static struct modlmisc modlmisc = {
	&mod_miscops, "RSMOPS module",
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static kmutex_t rsmops_lock;

static rsmops_drv_t *rsmops_drv_head = NULL;

static int rsmops_threads_started = 0;

int
_init(void)
{
	int	err;

	mutex_init(&rsmops_lock, NULL, MUTEX_DEFAULT, NULL);

	if ((err = mod_install(&modlinkage)) != 0)
		mutex_destroy(&rsmops_lock);

	return (err);
}

int
_fini(void)
{
	int	err;

	mutex_enter(&rsmops_lock);
	if (rsmops_drv_head) {
		/* Somebody is still registered with us - we cannot unload */
		mutex_exit(&rsmops_lock);
		return (EBUSY);
	}
	if (rsmops_threads_started) {
		/*
		 * Some threads have been started.  We do not have any
		 * well-supported way of checking whether they have all
		 * exited.  For now, fail attempt to unload if we have
		 * ever started any threads.  This is overkill, but ...
		 */
		mutex_exit(&rsmops_lock);
		return (EBUSY);
	}
	mutex_exit(&rsmops_lock);

	if ((err = mod_remove(&modlinkage)) == 0)
		mutex_destroy(&rsmops_lock);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
rsmops_thread_entry(rsmops_drv_t *p_drv)
{
	/* p_drv->ctrl_cnt has already been increased by the time we get here */
	ASSERT(p_drv->drv.rsm_thread_entry_pt);

	/* call the driver with the thread */
	(*(p_drv->drv.rsm_thread_entry_pt))(p_drv->drv.drv_name);

	/* thread has returned */
	mutex_enter(&rsmops_lock);
	p_drv->ctrl_cnt--;
	mutex_exit(&rsmops_lock);
}

/* This is expected to be called from the driver's init function */
int
rsm_register_driver(rsmops_registry_t *p_registry)
{
	rsmops_drv_t **pp_tail;
	rsmops_drv_t *p;

	if (p_registry->rsm_version > RSM_VERSION) {
		/* The driver is up-rev than me.  Fail attempt to register */
		return (RSMERR_BAD_DRIVER_VERSION);
	}

	/*
	 * RSM_VERSION: Since this is the first version, there cannot be any
	 * down-rev drivers - this will be an issue in the future
	 */
	if (p_registry->rsm_version != RSM_VERSION)
		return (RSMERR_BAD_DRIVER_VERSION);

	mutex_enter(&rsmops_lock);
	/* First, search that this driver is not already registered */
	pp_tail = &rsmops_drv_head;
	while (*pp_tail) {
		if (strcmp((*pp_tail)->drv.drv_name, p_registry->drv_name)
		    == 0) {
			mutex_exit(&rsmops_lock);
			return (RSMERR_DRIVER_NAME_IN_USE);
		}
		pp_tail = &((*pp_tail)->next);
	}

	p = kmem_alloc(sizeof (rsmops_drv_t), KM_SLEEP);
	p->drv = *p_registry;	/* copy entire rsmops_registry_t structure */
	p->next = NULL;
	p->ctrl_cnt = 0;
	p->ctrl_head = NULL;

	if (p->drv.rsm_thread_entry_pt) {
		/* thread entry point is defined - we need to create a thread */
		extern  pri_t   minclsyspri;

		p->ctrl_cnt++;	/* bump up the count right now */
		p->thread_id = thread_create(NULL, 0, rsmops_thread_entry,
		    p, 0, &p0, TS_RUN, minclsyspri);
		rsmops_threads_started++;
	} else
		p->thread_id = NULL;

	*pp_tail = p;
	mutex_exit(&rsmops_lock);
	return (RSM_SUCCESS);
}

/*
 * This is expected to be called from the driver's fini function
 * if this function returns EBUSY, the driver is supposed to fail
 * its own fini operation
 */
int
rsm_unregister_driver(rsmops_registry_t *p_registry)
{
	rsmops_drv_t **pp_tail;
	rsmops_drv_t *p;

	mutex_enter(&rsmops_lock);

	/* Search for the driver */
	pp_tail = &rsmops_drv_head;
	while (*pp_tail) {
		if (strcmp((*pp_tail)->drv.drv_name, p_registry->drv_name)) {
			pp_tail = &((*pp_tail)->next);
			continue;
		}
		/* check ref count - if somebody is using it, return EBUSY */
		if ((*pp_tail)->ctrl_cnt) {
			mutex_exit(&rsmops_lock);
			return (RSMERR_CTLRS_REGISTERED);
		}
		/* Nobody is using it - we can allow the unregister to happen */
		p = *pp_tail;

		/* Stomp the guy out of our linked list */
		*pp_tail = (*pp_tail)->next;

		/* release the memory */
		kmem_free(p, sizeof (rsmops_drv_t));

		mutex_exit(&rsmops_lock);
		return (RSM_SUCCESS);
	}

	/* Could not find the guy */
	mutex_exit(&rsmops_lock);
	return (RSMERR_DRIVER_NOT_REGISTERED);
}

/* Should be called holding the rsmops_lock mutex */
static rsmops_drv_t *
find_rsmpi_driver(const char *name)
{
	rsmops_drv_t *p_rsmops_list;

	ASSERT(MUTEX_HELD(&rsmops_lock));
	/* the name is of the form "sci", "wci" etc */

	for (p_rsmops_list = rsmops_drv_head; p_rsmops_list != NULL;
	    p_rsmops_list = p_rsmops_list->next) {

		if (strcmp(name, p_rsmops_list->drv.drv_name) == 0) {
			return (p_rsmops_list);
		}
	}
	return (NULL);
}


/* Should be called holding the rsmops_lock mutex */
static rsmops_ctrl_t *
find_rsmpi_controller(const char *name, uint_t number)
{
	rsmops_drv_t *p_drv;
	rsmops_ctrl_t *p;

	ASSERT(MUTEX_HELD(&rsmops_lock));

	if ((p_drv = find_rsmpi_driver(name)) == NULL)
		return (NULL);

	for (p = p_drv->ctrl_head; p != NULL; p = p->next) {
		ASSERT(p->p_drv == p_drv);
		if (p->number == number)
			return (p);
	}
	return (NULL);
}

/* Should be called holding the rsmops_lock mutex */
static rsmops_ctrl_t *
find_rsmpi_controller_handle(rsm_controller_handle_t cntlr_handle)
{
	rsmops_drv_t *p_drv;
	rsmops_ctrl_t *p;

	ASSERT(MUTEX_HELD(&rsmops_lock));

	for (p_drv = rsmops_drv_head; p_drv != NULL; p_drv = p_drv->next) {
		for (p = p_drv->ctrl_head; p != NULL; p = p->next) {
			if (p->handle == cntlr_handle)
				return (p);
		}
	}

	return (NULL);
}

static vnode_t *
rsmops_device_open(const char *major_name, const minor_t minor_num);

int
rsm_get_controller(const char *name, uint_t number,
    rsm_controller_object_t *controller, uint_t version)
{
	rsmops_ctrl_t *p_ctrl;
	rsmops_drv_t *p_drv;
	vnode_t *vp;
	int error;
	int (*rsm_get_controller_handler)
	    (const char *name, uint_t number,
	    rsm_controller_object_t *pcontroller, uint_t version);

	mutex_enter(&rsmops_lock);

	/* check if the controller is already registered */
	if ((p_ctrl = find_rsmpi_controller(name, number)) == NULL) {
		/*
		 * controller is not registered.  We should try to load it
		 * First check if the driver is registered
		 */
		if ((p_drv = find_rsmpi_driver(name)) == NULL) {
			/* Cannot find the driver.  Try to load it */
			mutex_exit(&rsmops_lock);
			if ((error = modload("drv", (char *)name)) == -1) {
				return (RSMERR_CTLR_NOT_PRESENT);
			}
			mutex_enter(&rsmops_lock);
			if ((p_drv = find_rsmpi_driver(name)) == NULL) {
				mutex_exit(&rsmops_lock);
				/*
				 * Cannot find yet - maybe the driver we loaded
				 * was not a RSMPI driver at all.  We'll just
				 * fail this call.
				 */
				return (RSMERR_CTLR_NOT_PRESENT);
			}
		}
		ASSERT(p_drv);
		p_ctrl = find_rsmpi_controller(name, number);
		if (p_ctrl == NULL) {
			/*
			 * controller is not registered.
			 * try to do a VOP_OPEN to force it to get registered
			 */
			mutex_exit(&rsmops_lock);
			vp = rsmops_device_open(name, number);
			mutex_enter(&rsmops_lock);
			if (vp != NULL) {
				(void) VOP_CLOSE(vp, FREAD|FWRITE, 0, 0,
				    CRED(), NULL);
				VN_RELE(vp);
			}
			p_ctrl = find_rsmpi_controller(name, number);
			if (p_ctrl == NULL) {
				mutex_exit(&rsmops_lock);
				return (RSMERR_CTLR_NOT_PRESENT);
			}
		}
		ASSERT(p_ctrl);
	} else {
		p_drv = p_ctrl->p_drv;
	}
	ASSERT(p_drv);
	ASSERT(p_drv == p_ctrl->p_drv);

	rsm_get_controller_handler = p_drv->drv.rsm_get_controller_handler;
	/*
	 * Increase the refcnt right now, so that attempts to deregister
	 * while we are using this entry will fail
	 */
	p_ctrl->refcnt++;
	mutex_exit(&rsmops_lock);

	error = (*rsm_get_controller_handler)(name, number, controller,
	    version);
	if (error != RSM_SUCCESS) {
		/* We failed - drop the refcnt back */
		mutex_enter(&rsmops_lock);
		/*
		 * Even though we had released the global lock, we can
		 * guarantee that p_ctrl is still meaningful (and has not
		 * been deregistered, freed whatever) because we were holding
		 * refcnt on it.  So, it is okay to just use p_ctrl here
		 * after re-acquiring the global lock
		 */
		p_ctrl->refcnt--;
		mutex_exit(&rsmops_lock);
	} else {
		/*
		 * Initialize the controller handle field
		 */
		mutex_enter(&rsmops_lock);
		if ((p_ctrl = find_rsmpi_controller(name, number)) == NULL) {
			mutex_exit(&rsmops_lock);
			return (RSMERR_CTLR_NOT_PRESENT);
		}

		p_ctrl->handle = controller->handle;
		mutex_exit(&rsmops_lock);
	}
	return (error);
}

int
rsm_release_controller(const char *name, uint_t number,
    rsm_controller_object_t *controller)
{
	rsmops_ctrl_t *p_ctrl;
	rsmops_drv_t *p_drv;
	int error;
	int (*releaser)(const char *name, uint_t number,
	    rsm_controller_object_t *controller);

	mutex_enter(&rsmops_lock);

	if ((p_ctrl = find_rsmpi_controller(name, number)) == NULL) {
		mutex_exit(&rsmops_lock);
		return (RSMERR_CTLR_NOT_PRESENT);
	}
	p_drv = find_rsmpi_driver(name);
	ASSERT(p_drv);	/* If we found controller, there MUST be a driver */

	/* Found the appropriate driver.  Forward the call to it */
	releaser = p_drv->drv.rsm_release_controller_handler;
	mutex_exit(&rsmops_lock);

	error = (*releaser)(name, number, controller);
	if (error == RSM_SUCCESS) {
		mutex_enter(&rsmops_lock);
		p_ctrl->refcnt--;
		mutex_exit(&rsmops_lock);
	}
	return (error);
}

/* This is expected to be called from the driver's attach function */
int
rsm_register_controller(const char *name, uint_t number,
    rsm_controller_attr_t *attrp)
{
	rsmops_drv_t *p_drv;
	rsmops_ctrl_t *p_ctrl;

	if (strlen(name) > MAX_DRVNAME)
		return (RSMERR_NAME_TOO_LONG);

	mutex_enter(&rsmops_lock);

	/* Check if the driver is registered with us */
	p_drv = find_rsmpi_driver(name);
	if (p_drv == NULL) {
		/*
		 * Hey! Driver is not registered, but we are getting a
		 * controller ??
		 */
		mutex_exit(&rsmops_lock);
		return (RSMERR_DRIVER_NOT_REGISTERED);
	}

	/* Check if the controller is already registered with us */
	p_ctrl = find_rsmpi_controller(name, number);
	if (p_ctrl) {
		/* already registered */
		mutex_exit(&rsmops_lock);
		return (RSMERR_CTLR_ALREADY_REGISTERED);
	}

	/* WAIT: sanity check - verify that the dip matches up to name,number */

	p_ctrl = kmem_alloc(sizeof (rsmops_ctrl_t), KM_SLEEP);

	/* bump up controller count on the driver */
	p_drv->ctrl_cnt++;

	p_ctrl->p_drv = p_drv;	/* setup the back pointer */
	p_ctrl->number = number;
	p_ctrl->refcnt = 0;
	p_ctrl->attrp = attrp;
	p_ctrl->handle = NULL;

	/* Now link to head of list */
	p_ctrl->next = p_drv->ctrl_head;
	p_drv->ctrl_head = p_ctrl;

	mutex_exit(&rsmops_lock);

	return (RSM_SUCCESS);
}

/*
 * This is expected to be called from the driver's detach function
 * if this function returns EBUSY, the driver is supposed to fail
 * its own detach operation
 */
int
rsm_unregister_controller(const char *name, uint_t number)
{
	rsmops_drv_t *p_drv;
	rsmops_ctrl_t **p_prev;
	rsmops_ctrl_t *found;

	mutex_enter(&rsmops_lock);

	/* Check if the driver is registered with us */
	p_drv = find_rsmpi_driver(name);
	if (p_drv == NULL) {
		/* Hey!  Driver is not registered */
		mutex_exit(&rsmops_lock);
		return (RSMERR_DRIVER_NOT_REGISTERED);
	}

	/* Search for the controller in the list */
	for (p_prev = &p_drv->ctrl_head; *p_prev; p_prev = &((*p_prev)->next)) {
		if ((*p_prev)->number == number) {
			/* Found the controller.  Check if it is busy */
			found = *p_prev;

			if (found->refcnt) {
				/* Controller is busy -  handles outstanding */
				mutex_exit(&rsmops_lock);
				return (RSMERR_CTLR_IN_USE);
			}
			/* unlink it out */
			*p_prev = found->next;
			/* bump down controller count on the driver */
			p_drv->ctrl_cnt--;

			mutex_exit(&rsmops_lock);
			kmem_free(found, sizeof (rsmops_ctrl_t));
			return (RSM_SUCCESS);
		}
	}
	mutex_exit(&rsmops_lock);
	/* Could not find the right controller */
	return (RSMERR_CTLR_NOT_REGISTERED);
}


/*
 * This opens and closes the appropriate device with minor number -
 * hopefully, it will cause the driver to attach and register a controller
 * with us
 */
static vnode_t *
rsmops_device_open(const char *major_name, const minor_t minor_num)
{
	major_t maj;
	vnode_t *vp;
	int ret;

	if (minor_num == (minor_t)-1) {
		return (NULL);
	}

	maj = ddi_name_to_major((char *)major_name);
	if (maj == (major_t)-1) {
		return (NULL);
	}

	vp = makespecvp(makedevice(maj, minor_num), VCHR);

	ret = VOP_OPEN(&vp, FREAD|FWRITE, CRED(), NULL);
	if (ret == 0) {
		return (vp);
	} else {
		VN_RELE(vp);
		return (NULL);
	}
}

/*
 * Attributes for controller identified by the handle are returned
 * via *attrp. Modifications of attributes is prohibited by client!
 */
int
rsm_get_controller_attr(rsm_controller_handle_t handle,
    rsm_controller_attr_t **attrp)
{

	rsmops_ctrl_t *p_ctrl;

	if (handle == NULL)
		return (RSMERR_BAD_CTLR_HNDL);

	mutex_enter(&rsmops_lock);

	/* find controller */
	if ((p_ctrl = find_rsmpi_controller_handle(handle)) == NULL) {
		/* can't supply attributes for invalid controller */
		mutex_exit(&rsmops_lock);
		return (RSMERR_BAD_CTLR_HNDL);
	}
	*attrp =  p_ctrl->attrp;
	mutex_exit(&rsmops_lock);

	return (RSM_SUCCESS);
}
