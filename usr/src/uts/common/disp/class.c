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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/class.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/procset.h>
#include <sys/modctl.h>
#include <sys/disp.h>
#include <sys/sysmacros.h>
#include <sys/schedctl.h>

static int getcidbyname_locked(char *, id_t *);

/*
 * Allocate a cid given a class name if one is not already allocated.
 * Returns 0 if the cid was already exists or if the allocation of a new
 * cid was successful. Nonzero return indicates error.
 */
int
alloc_cid(char *clname, id_t *cidp)
{
	sclass_t *clp;

	ASSERT(MUTEX_HELD(&class_lock));

	/*
	 * If the clname doesn't already have a cid, allocate one.
	 */
	if (getcidbyname_locked(clname, cidp) != 0) {
		/*
		 * Allocate a class entry and a lock for it.
		 */
		for (clp = sclass; clp < &sclass[nclass]; clp++)
			if (clp->cl_name[0] == '\0' && clp->cl_lock == NULL)
				break;

		if (clp == &sclass[nclass]) {
			return (ENOSPC);
		}
		*cidp = clp - &sclass[0];
		clp->cl_lock = kmem_alloc(sizeof (krwlock_t), KM_SLEEP);
		clp->cl_name = kmem_alloc(strlen(clname) + 1, KM_SLEEP);
		(void) strcpy(clp->cl_name, clname);
		rw_init(clp->cl_lock, NULL, RW_DEFAULT, NULL);
	}

	/*
	 * At this point, *cidp will contain the index into the class
	 * array for the given class name.
	 */
	return (0);
}

int
scheduler_load(char *clname, sclass_t *clp)
{
	int rv = 0;
	char *tmp = clname + 1;

	/* Check if class name is  "",  ".",  ".."  or  "`"  */
	if (*clname == '\0' || *clname == '`' || (*clname == '.' && *tmp == '\0') ||
	    (*clname == '.' && *tmp == '.' && *(++tmp) == '\0'))
		return (EINVAL);

	if (LOADABLE_SCHED(clp)) {
		rw_enter(clp->cl_lock, RW_READER);
		if (!SCHED_INSTALLED(clp)) {
			rw_exit(clp->cl_lock);
			if (modload("sched", clname) == -1)
				return (EINVAL);
			rw_enter(clp->cl_lock, RW_READER);
			/* did we really load a scheduling class? */
			if (!SCHED_INSTALLED(clp))
				rv = EINVAL;
		}
		rw_exit(clp->cl_lock);
	}
	return (rv);
}

/*
 * Get class ID given class name.
 */
int
getcid(char *clname, id_t *cidp)
{
	sclass_t *clp;
	int retval;

	mutex_enter(&class_lock);
	if ((retval = alloc_cid(clname, cidp)) == 0) {
		clp = &sclass[*cidp];
		clp->cl_count++;

		/*
		 * If it returns zero, it's loaded & locked
		 * or we found a statically installed scheduler
		 * module.
		 * If it returns EINVAL, modload() failed when
		 * it tried to load the module.
		 */
		mutex_exit(&class_lock);
		retval = scheduler_load(clname, clp);
		mutex_enter(&class_lock);

		clp->cl_count--;
		if (retval != 0 && clp->cl_count == 0) {
			/* last guy out of scheduler_load frees the storage */
			kmem_free(clp->cl_name, strlen(clname) + 1);
			kmem_free(clp->cl_lock, sizeof (krwlock_t));
			clp->cl_name = "";
			clp->cl_lock = (krwlock_t *)NULL;
		}
	}
	mutex_exit(&class_lock);
	return (retval);

}

static int
getcidbyname_locked(char *clname, id_t *cidp)
{
	sclass_t *clp;

	ASSERT(MUTEX_HELD(&class_lock));

	if (*clname == NULL)
		return (EINVAL);

	for (clp = &sclass[0]; clp < &sclass[nclass]; clp++) {
		if (strcmp(clp->cl_name, clname) == 0) {
			*cidp = clp - &sclass[0];
			return (0);
		}
	}
	return (EINVAL);
}

/*
 * Lookup a module by name.
 */
int
getcidbyname(char *clname, id_t *cidp)
{
	int retval;

	mutex_enter(&class_lock);
	retval = getcidbyname_locked(clname, cidp);
	mutex_exit(&class_lock);

	return (retval);
}

/*
 * Get the scheduling parameters of the thread pointed to by
 * tp into the buffer pointed to by parmsp.
 */
void
parmsget(kthread_t *tp, pcparms_t *parmsp)
{
	parmsp->pc_cid = tp->t_cid;
	CL_PARMSGET(tp, parmsp->pc_clparms);
}


/*
 * Check the validity of the scheduling parameters in the buffer
 * pointed to by parmsp.
 * Note that the format of the parameters may be changed by class
 * specific code which we call.
 */
int
parmsin(pcparms_t *parmsp, pc_vaparms_t *vaparmsp)
{
	if (parmsp->pc_cid >= loaded_classes || parmsp->pc_cid < 1)
		return (EINVAL);

	/*
	 * Call the class specific routine to validate class
	 * specific parameters.
	 * The input parameters are either in a pcparms structure (PC_SETPARMS)
	 * or in a variable parameter structure (PC_SETXPARMS). In the
	 * 'PC_SETPARMS' case vaparmsp is a NULL pointer and a CL_PARMSIN()
	 * routine gets the parameter. Otherwise vaparmsp points to a variable
	 * parameter structure and a CL_VAPARMSIN() routine gets the parameter.
	 */
	if (vaparmsp != NULL)
		return (CL_VAPARMSIN(&sclass[parmsp->pc_cid],
		    parmsp->pc_clparms, vaparmsp));
	else
		return (CL_PARMSIN(&sclass[parmsp->pc_cid],
		    parmsp->pc_clparms));
}


/*
 * Call the class specific code to do the required processing
 * before the scheduling parameters are copied out to the user.
 * Note that the format of the parameters may be changed by the
 * class specific code.
 */
int
parmsout(pcparms_t *parmsp, pc_vaparms_t *vaparmsp)
{
	return (CL_PARMSOUT(&sclass[parmsp->pc_cid], parmsp->pc_clparms,
	    vaparmsp));
}


/*
 * Set the scheduling parameters of the thread pointed to by
 * targtp to those specified in the pcparms structure pointed
 * to by parmsp.  If reqtp is non-NULL it points to the thread
 * that initiated the request for the parameter change and indicates
 * that our caller wants us to verify that the requesting thread
 * has the appropriate permissions.
 */
int
parmsset(pcparms_t *parmsp, kthread_t *targtp)
{
	caddr_t	clprocp;
	int	error;
	cred_t	*reqpcredp;
	proc_t	*reqpp = ttoproc(curthread);
	proc_t	*targpp = ttoproc(targtp);
	id_t	oldcid;

	ASSERT(MUTEX_HELD(&pidlock));
	ASSERT(MUTEX_HELD(&targpp->p_lock));
	if (reqpp != NULL) {
		mutex_enter(&reqpp->p_crlock);
		crhold(reqpcredp = reqpp->p_cred);
		mutex_exit(&reqpp->p_crlock);

		/*
		 * Check basic permissions.
		 */
		if (!prochasprocperm(targpp, reqpp, reqpcredp)) {
			crfree(reqpcredp);
			return (EPERM);
		}
	} else {
		reqpcredp = NULL;
	}

	if (parmsp->pc_cid != targtp->t_cid) {
		void	*bufp = NULL;
		/*
		 * Target thread must change to new class.
		 */
		clprocp = (caddr_t)targtp->t_cldata;
		oldcid  = targtp->t_cid;

		/*
		 * Purpose: allow scheduling class to veto moves
		 * to other classes. All the classes, except FSS,
		 * do nothing except returning 0.
		 */
		error = CL_CANEXIT(targtp, reqpcredp);
		if (error) {
			/*
			 * Not allowed to leave the class, so return error.
			 */
			crfree(reqpcredp);
			return (error);
		} else {
			/*
			 * Pre-allocate scheduling class data.
			 */
			if (CL_ALLOC(&bufp, parmsp->pc_cid, KM_NOSLEEP) != 0) {
				error = ENOMEM; /* no memory available */
				crfree(reqpcredp);
				return (error);
			} else {
				error = CL_ENTERCLASS(targtp, parmsp->pc_cid,
				    parmsp->pc_clparms, reqpcredp, bufp);
				crfree(reqpcredp);
				if (error) {
					CL_FREE(parmsp->pc_cid, bufp);
					return (error);
				}
			}
		}
		CL_EXITCLASS(oldcid, clprocp);
	} else {

		/*
		 * Not changing class
		 */
		error = CL_PARMSSET(targtp, parmsp->pc_clparms,
		    curthread->t_cid, reqpcredp);
		crfree(reqpcredp);
		if (error)
			return (error);
	}
	schedctl_set_cidpri(targtp);
	return (0);
}


/*
 * Copy all selected class parameters to the user.
 * The parameters are specified by a key.
 */
int
vaparmsout(char *classp, pcparms_t *prmsp, pc_vaparms_t *vaparmsp,
    uio_seg_t seg)
{
	char	*clname;

	ASSERT(MUTEX_NOT_HELD(&curproc->p_lock));

	if (classp != NULL)
		return (CL_VAPARMSOUT(&sclass[prmsp->pc_cid],
		    prmsp->pc_clparms, vaparmsp));

	switch (vaparmsp->pc_vaparmscnt) {
	case 0:
		return (0);
	case 1:
		break;
	default:
		return (EINVAL);
	}

	if (vaparmsp->pc_parms[0].pc_key != PC_KY_CLNAME)
		return (EINVAL);

	clname = sclass[prmsp->pc_cid].cl_name;
	if ((seg == UIO_USERSPACE ? copyout : kcopy)(clname,
	    (void *)(uintptr_t)vaparmsp->pc_parms[0].pc_parm,
	    MIN(strlen(clname) + 1, PC_CLNMSZ)))
		return (EFAULT);

	return (0);
}
