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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * Niagara 2 Random Number Generator (RNG) driver
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/param.h>
#include <sys/cpuvar.h>
#include <sys/disp.h>
#include <sys/hsvc.h>
#include <sys/machsystm.h>
#include <sys/hypervisor_api.h>
#include <sys/n2rng.h>

static int	n2rng_attach(dev_info_t *, ddi_attach_cmd_t);
static int	n2rng_detach(dev_info_t *, ddi_detach_cmd_t);
static int	n2rng_suspend(n2rng_t *);
static int	n2rng_resume(n2rng_t *);
static uint64_t sticks_per_usec(void);
u_longlong_t	gettick(void);
static int	n2rng_init_ctl(n2rng_t *);
static void	n2rng_uninit_ctl(n2rng_t *);
static int	n2rng_config(n2rng_t *);
static void	n2rng_config_task(void * targ);

/*
 * Device operations.
 */

static struct dev_ops devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	nodev,			/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	n2rng_attach,		/* devo_attach */
	n2rng_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	NULL,			/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	ddi_power,		/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * Module linkage.
 */
static struct modldrv modldrv = {
	&mod_driverops,			/* drv_modops */
	"N2 RNG Driver",		/* drv_linkinfo */
	&devops,			/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,			/* ml_rev */
	&modldrv,			/* ml_linkage */
	NULL
};

/*
 * Driver globals Soft state.
 */
static void	*n2rng_softstate = NULL;

/*
 * Hypervisor NCS services information.
 */
static boolean_t ncs_hsvc_available = B_FALSE;

#define	NVERSIONS	2

/*
 * HV API versions supported by this driver.
 */
static hsvc_info_t ncs_hsvc[NVERSIONS] = {
	{ HSVC_REV_1, NULL, HSVC_GROUP_RNG, 2, 0, DRIVER },	/* v2.0 */
	{ HSVC_REV_1, NULL, HSVC_GROUP_RNG, 1, 0, DRIVER },	/* v1.0 */
};
int	ncs_version_index;	/* index into ncs_hsvc[] */

/*
 * DDI entry points.
 */
int
_init(void)
{
	int	rv;

	rv = ddi_soft_state_init(&n2rng_softstate, sizeof (n2rng_t), 1);
	if (rv != 0) {
		/* this should *never* happen! */
		return (rv);
	}

	if ((rv = mod_install(&modlinkage)) != 0) {
		/* cleanup here */
		ddi_soft_state_fini(&n2rng_softstate);
		return (rv);
	}

	return (0);
}

int
_fini(void)
{
	int	rv;

	rv = mod_remove(&modlinkage);
	if (rv == 0) {
		/* cleanup here */
		ddi_soft_state_fini(&n2rng_softstate);
	}

	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
n2rng_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	n2rng_t		*n2rng = NULL;
	int		instance;
	int		rv;
	int		version;
	uint64_t	ncs_minor_ver;

	instance = ddi_get_instance(dip);
	DBG1(NULL, DENTRY, "n2rng_attach called, instance %d", instance);
	/*
	 * Only instance 0 of n2rng driver is allowed.
	 */
	if (instance != 0) {
		n2rng_diperror(dip, "only one instance (0) allowed");
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_RESUME:
		n2rng = (n2rng_t *)ddi_get_soft_state(n2rng_softstate,
		    instance);
		if (n2rng == NULL) {
			n2rng_diperror(dip, "no soft state in attach");
			return (DDI_FAILURE);
		}
		return (n2rng_resume(n2rng));

	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	rv = ddi_soft_state_zalloc(n2rng_softstate, instance);
	if (rv != DDI_SUCCESS) {
		n2rng_diperror(dip, "unable to allocate soft state");
		return (DDI_FAILURE);
	}
	n2rng = (n2rng_t *)ddi_get_soft_state(n2rng_softstate, instance);
	ASSERT(n2rng != NULL);
	n2rng->n_dip = dip;

	mutex_init(&n2rng->n_lock, NULL, MUTEX_DRIVER, NULL);
	n2rng->n_flags = 0;
	n2rng->n_timeout_id = 0;
	n2rng->n_sticks_per_usec = sticks_per_usec();

	/* Determine binding type */
	n2rng->n_binding_name = ddi_binding_name(dip);
	if (strncmp(n2rng->n_binding_name, N2RNG_BINDNAME_N2,
	    strlen(N2RNG_BINDNAME_N2)) == 0) {
		/*
		 * Niagara 2
		 */
		n2rng->n_binding = N2RNG_CPU_N2;
	} else if (strncmp(n2rng->n_binding_name, N2RNG_BINDNAME_VF,
	    strlen(N2RNG_BINDNAME_VF)) == 0) {
		/*
		 * Victoria Falls
		 */
		n2rng->n_binding = N2RNG_CPU_VF;
	} else if (strncmp(n2rng->n_binding_name, N2RNG_BINDNAME_KT,
	    strlen(N2RNG_BINDNAME_KT)) == 0) {
		/*
		 * Rainbow Falls
		 */
		n2rng->n_binding = N2RNG_CPU_KT;
	} else {
		n2rng_diperror(dip,
		    "unable to determine n2rng (cpu) binding (%s)",
		    n2rng->n_binding_name);
		goto errorexit;
	}
	DBG1(n2rng, DCHATTY, "n2rng_attach: n2rng->n_binding_name = %s",
	    n2rng->n_binding_name);

	/* Negotiate HV api version number */
	for (version = 0; version < NVERSIONS; version++) {
		rv = hsvc_register(&ncs_hsvc[version], &ncs_minor_ver);
		if (rv == 0)
			break;

		DBG4(n2rng, DCHATTY, "n2rng_attach: grp: 0x%lx, maj: %ld, "
		    "min: %ld, errno: %d", ncs_hsvc[version].hsvc_group,
		    ncs_hsvc[version].hsvc_major,
		    ncs_hsvc[version].hsvc_minor, rv);
	}
	if (version == NVERSIONS) {
		for (version = 0; version < NVERSIONS; version++) {
			cmn_err(CE_WARN,
			    "%s: cannot negotiate hypervisor services "
			    "group: 0x%lx major: %ld minor: %ld errno: %d",
			    ncs_hsvc[version].hsvc_modname,
			    ncs_hsvc[version].hsvc_group,
			    ncs_hsvc[version].hsvc_major,
			    ncs_hsvc[version].hsvc_minor, rv);
		}
		goto errorexit;
	}
	ncs_version_index = version;
	ncs_hsvc_available = B_TRUE;
	DBG2(n2rng, DATTACH, "n2rng_attach: ncs api version (%ld.%ld)",
	    ncs_hsvc[ncs_version_index].hsvc_major, ncs_minor_ver);
	n2rng->n_hvapi_major_version = ncs_hsvc[ncs_version_index].hsvc_major;
	n2rng->n_hvapi_minor_version = (uint_t)ncs_minor_ver;

	/*
	 * Verify that we are running version 2.0 or later api on multiple
	 * rng systems.
	 */
	if ((n2rng->n_binding != N2RNG_CPU_N2) &&
	    (n2rng->n_hvapi_major_version < 2)) {
		cmn_err(CE_NOTE, "n2rng: Incompatible hyperviser api "
		    "version %d.%d detected", n2rng->n_hvapi_major_version,
		    n2rng->n_hvapi_minor_version);
	}

	/* Initialize ctl structure if runnning in the control domain */
	if (n2rng_init_ctl(n2rng) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "n2rng: unable to initialize rng "
		    "control structures");
		goto errorexit;
	}

	/* Allocate single thread task queue for rng diags and registration */
	n2rng->n_taskq = ddi_taskq_create(dip, "n2rng_taskq", 1,
	    TASKQ_DEFAULTPRI, 0);

	if (n2rng->n_taskq == NULL) {
		n2rng_diperror(dip, "ddi_taskq_create() failed");
		goto errorexit;
	}

	/* Dispatch task to configure the RNG and register with KCF */
	if (ddi_taskq_dispatch(n2rng->n_taskq, n2rng_config_task,
	    (void *)n2rng, DDI_SLEEP) != DDI_SUCCESS) {
		n2rng_diperror(dip, "ddi_taskq_dispatch() failed");
		goto errorexit;
	}

	return (DDI_SUCCESS);

errorexit:
	/* Wait for pending config tasks to complete and delete the taskq */
	if (n2rng->n_taskq != NULL) {
		ddi_taskq_destroy(n2rng->n_taskq);
		n2rng->n_taskq = NULL;
	}

	n2rng_uninit_ctl(n2rng);

	(void) n2rng_uninit(n2rng);

	if (ncs_hsvc_available == B_TRUE) {
		(void) hsvc_unregister(&ncs_hsvc[ncs_version_index]);
		ncs_hsvc_available = B_FALSE;
	}

	mutex_destroy(&n2rng->n_lock);
	ddi_soft_state_free(n2rng_softstate, instance);

	return (DDI_FAILURE);
}

static int
n2rng_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	int		rv;
	n2rng_t		*n2rng;
	timeout_id_t	tid;

	instance = ddi_get_instance(dip);
	n2rng = (n2rng_t *)ddi_get_soft_state(n2rng_softstate, instance);
	if (n2rng == NULL) {
		n2rng_diperror(dip, "no soft state in detach");
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_SUSPEND:
		return (n2rng_suspend(n2rng));
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	/* Destroy task queue first to insure configuration has completed */
	if (n2rng->n_taskq != NULL) {
		ddi_taskq_destroy(n2rng->n_taskq);
		n2rng->n_taskq = NULL;
	}

	/* Untimeout pending config retry operations */
	mutex_enter(&n2rng->n_lock);
	tid = n2rng->n_timeout_id;
	n2rng->n_timeout_id = 0;
	mutex_exit(&n2rng->n_lock);
	if (tid) {
		DBG1(n2rng, DCHATTY, "n2rng_detach: untimeout pending retry "
		    "id = %x", tid);
		(void) untimeout(tid);
	}

	n2rng_uninit_ctl(n2rng);

	/* unregister with KCF---also tears down FIPS state */
	rv = n2rng_uninit(n2rng) ? DDI_FAILURE : DDI_SUCCESS;

	if (ncs_hsvc_available == B_TRUE) {
		(void) hsvc_unregister(&ncs_hsvc[ncs_version_index]);
		ncs_hsvc_available = B_FALSE;
	}

	mutex_destroy(&n2rng->n_lock);
	ddi_soft_state_free(n2rng_softstate, instance);

	return (rv);
}

/*ARGSUSED*/
static int
n2rng_suspend(n2rng_t *n2rng)
{
	/* unregister with KCF---also tears down FIPS state */
	if (n2rng_uninit(n2rng) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "n2rng: unable to unregister from KCF");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
n2rng_resume(n2rng_t *n2rng)
{
	/* Assume clock is same speed and all data structures are intact */

	/* Re-configure the RNG hardware and register with KCF */
	return (n2rng_config(n2rng));
}

/*
 * Map hypervisor error code to solaris. Only
 * H_ENORADDR, H_EBADALIGN, H_EWOULDBLOCK, and EIO
 * are meaningful to this device. Any other error
 * codes are mapped EINVAL.
 */
int
n2rng_herr2kerr(uint64_t hv_errcode)
{
	int	s_errcode;

	switch (hv_errcode) {
	case H_EWOULDBLOCK:
		s_errcode = EWOULDBLOCK;
		break;
	case H_EIO:
		s_errcode = EIO;
		break;
	case H_EBUSY:
		s_errcode = EBUSY;
		break;
	case H_EOK:
		s_errcode = 0;
		break;
	case H_ENOACCESS:
		s_errcode = EPERM;
		break;
	case H_ENORADDR:
	case H_EBADALIGN:
	default:
		s_errcode = EINVAL;
		break;
	}
	return (s_errcode);
}

/*
 * Waits approximately delay_sticks counts of the stick register.
 * Times shorter than one sys clock tick (10ms on most systems) are
 * done by busy waiting.
 */
void
cyclesleep(n2rng_t *n2rng, uint64_t delay_sticks)
{
	uint64_t	end_stick = gettick() + delay_sticks;
	int64_t		sticks_to_wait;
	clock_t		sys_ticks_to_wait;
	clock_t		usecs_to_wait;

	/*CONSTCOND*/
	while (1) {
		sticks_to_wait = end_stick - gettick();
		if (sticks_to_wait <= 0) {
			return;
		}

		usecs_to_wait = sticks_to_wait / n2rng->n_sticks_per_usec;
		sys_ticks_to_wait = drv_usectohz(usecs_to_wait);

		if (sys_ticks_to_wait > 0) {
			/* sleep */
			delay(sys_ticks_to_wait);
		} else if (usecs_to_wait > 0) {
			/* busy wait */
			drv_usecwait(usecs_to_wait);
		}
	}
}

static void
log_internal_errors(uint64_t hverr, char *fname)
{
	switch (hverr) {
	case H_EBADALIGN:
		cmn_err(CE_WARN,
		    "n2rng: internal alignment "
		    "problem");
		break;
	case H_ENORADDR:
		cmn_err(CE_WARN, "n2rng: internal "
		    "invalid address");
		break;
	case H_ENOACCESS:
		cmn_err(CE_WARN, "n2rng: access failure");
		break;
	case H_EWOULDBLOCK:
		cmn_err(CE_WARN, "n2rng: hardware busy");
		break;
	default:
		cmn_err(CE_NOTE,
		    "n2rng: %s "
		    "unexpectedly "
		    "returned hverr %ld", fname, hverr);
		break;
	}
}

/*
 * Collects a buffer full of bits, using the specified setup. numbytes
 * must be a multiple of 8. If a sub-operation fails with EIO (handle
 * mismatch), returns EIO.  If collect_setupp is NULL, the current
 * setup is used.  If exit_setupp is NULL, the control configuratin
 * and state are not set at exit.  WARNING: the buffer must be 8-byte
 * aligned and in contiguous physical addresses.  Contiguousness is
 * not checked!
 */
int
n2rng_collect_diag_bits(n2rng_t *n2rng, int rngid,
    n2rng_setup_t *collect_setupp, void *buffer, int numbytes,
    n2rng_setup_t *exit_setupp, uint64_t exitstate)
{
	int		rv;
	int		override_rv = 0;
	uint64_t	hverr;
	int		i;
	uint64_t	tdelta;
	n2rng_setup_t	setupbuffer[2];
	n2rng_setup_t	*setupcontigp;
	uint64_t	setupphys;
	int		numchunks;
	boolean_t	rnglooping;
	int		busycount = 0;
	int		blockcount = 0;

	if (numbytes % sizeof (uint64_t)) {
		return (EINVAL);
	}

	if ((uint64_t)buffer % sizeof (uint64_t) != 0) {
		return (EINVAL);
	}

	numchunks = ((numbytes / sizeof (uint64_t)) + RNG_DIAG_CHUNK_SIZE - 1)
	    / RNG_DIAG_CHUNK_SIZE;
	/*
	 * Use setupbuffer[0] if it is contiguous, otherwise
	 * setupbuffer[1].
	 */
	setupcontigp = &setupbuffer[
	    CONTIGUOUS(&setupbuffer[0], n2rng_setup_t) ? 0 : 1];
	setupphys = va_to_pa(setupcontigp);

	/*
	 * If a non-null collect_setupp pointer has been provided,
	 * push the specified setup into the hardware.
	 */
	if (collect_setupp != NULL) {
		/* copy the specified state to the aligned buffer */
		*setupcontigp = *collect_setupp;
		rnglooping = B_TRUE;
		while (rnglooping) {
			hverr = n2rng_ctl_write(n2rng, rngid, setupphys,
			    CTL_STATE_HEALTHCHECK,
			    n2rng->n_ctl_data->n_watchdog_cycles, &tdelta);
			rv = n2rng_herr2kerr(hverr);
			switch (hverr) {
			case H_EOK:
				rnglooping = B_FALSE;
				break;
			case H_EIO: /* control yanked from us */
			case H_ENOACCESS: /* We are not control domain */
				return (rv);
			case H_EWOULDBLOCK:
				/* Data currently not available, try again */
				if (++blockcount > RNG_MAX_BLOCK_ATTEMPTS) {
					DBG1(n2rng, DHEALTH,
					    "n2rng_collect_diag_bits(1) : "
					    "exceeded block count of %d",
					    RNG_MAX_BLOCK_ATTEMPTS);
					return (rv);
				} else {
					cyclesleep(n2rng, tdelta);
				}
				break;
			case H_EBUSY:
				/*
				 * A control write is already in progress.
				 * Note: This shouldn't happen since
				 * n2rng_ctl_write() waits for the
				 * write to complete.
				 */
				if (++busycount > RNG_MAX_BUSY_ATTEMPTS) {
					DBG1(n2rng, DHEALTH,
					    "n2rng_collect_diag_bits(1): "
					    "exceeded busy count of %d",
					    RNG_MAX_BUSY_ATTEMPTS);
					return (rv);
				} else {
					delay(RNG_RETRY_BUSY_DELAY);
				}
				break;
			default:
				log_internal_errors(hverr, "hv_rng_ctl_write");
				override_rv = rv;
				goto restore_state;
			}
		} /* while (rnglooping) */
	} /* if (collect_setupp != NULL) */

	/* If the caller asks for some bytes, collect the data */
	if (numbytes > 0) {
		for (i = 0; i < numchunks; i++) {
			size_t thisnumbytes = (i == numchunks - 1) ?
			    numbytes - i * (RNG_DIAG_CHUNK_SIZE *
			    sizeof (uint64_t)) :
			    RNG_DIAG_CHUNK_SIZE * sizeof (uint64_t);

			/* try until we successfully read a word of data */
			rnglooping = B_TRUE;
			busycount = 0;
			blockcount = 0;
			while (rnglooping) {
				hverr = n2rng_data_read_diag(n2rng, rngid,
				    va_to_pa((uint64_t *)buffer +
				    RNG_DIAG_CHUNK_SIZE * i),
				    thisnumbytes, &tdelta);
				rv = n2rng_herr2kerr(hverr);
				switch (hverr) {
				case H_EOK:
					rnglooping = B_FALSE;
					break;
				case H_EIO:
				case H_ENOACCESS:
					return (rv);
				case H_EWOULDBLOCK:
					/* Data not available, try again */
					if (++blockcount >
					    RNG_MAX_BLOCK_ATTEMPTS) {
						DBG1(n2rng, DHEALTH,
						    "n2rng_collect_diag_bits"
						    "(2): exceeded block count"
						    " of %d",
						    RNG_MAX_BLOCK_ATTEMPTS);
						return (rv);
					} else {
						cyclesleep(n2rng, tdelta);
					}
					break;
				default:
					log_internal_errors(hverr,
					    "hv_rng_data_read_diag");
					override_rv = rv;
					goto restore_state;
				}
			} /* while (!rnglooping) */
		} /* for */
	}

restore_state:

	/* restore the preferred configuration and set exit state */
	if (exit_setupp != NULL) {

		*setupcontigp = *exit_setupp;
		rnglooping = B_TRUE;
		busycount = 0;
		blockcount = 0;
		while (rnglooping) {
			hverr = n2rng_ctl_write(n2rng, rngid, setupphys,
			    exitstate, n2rng->n_ctl_data->n_watchdog_cycles,
			    &tdelta);
			rv = n2rng_herr2kerr(hverr);
			switch (hverr) {
			case H_EOK:
			case H_EIO: /* control yanked from us */
			case H_EINVAL: /* some external error, probably */
			case H_ENOACCESS: /* We are not control domain */
				rnglooping = B_FALSE;
				break;
			case H_EWOULDBLOCK:
				/* Data currently not available, try again */
				if (++blockcount > RNG_MAX_BLOCK_ATTEMPTS) {
					DBG1(n2rng, DHEALTH,
					    "n2rng_collect_diag_bits(3): "
					    "exceeded block count of %d",
					    RNG_MAX_BLOCK_ATTEMPTS);
					return (rv);
				} else {
					cyclesleep(n2rng, tdelta);
				}
				break;
			case H_EBUSY:
				/*
				 * A control write is already in progress.
				 * Note: This shouldn't happen since
				 * n2rng_ctl_write() waits for the
				 * write to complete.
				 */
				if (++busycount > RNG_MAX_BUSY_ATTEMPTS) {
					DBG1(n2rng, DHEALTH,
					    "n2rng_collect_diag_bits(3): "
					    "exceeded busy count of %d",
					    RNG_MAX_BUSY_ATTEMPTS);
					return (rv);
				} else {
					delay(RNG_RETRY_BUSY_DELAY);
				}
				break;
			default:
				rnglooping = B_FALSE;
				log_internal_errors(hverr, "hv_rng_ctl_write");
				break;
			}
		} /* while */
	} /* if */

	/*
	 * override_rv takes care of the case where we abort becuase
	 * of some error, but still want to restore the peferred state
	 * and return the first error, even if other error occur.
	 */
	return (override_rv ? override_rv : rv);
}

int
n2rng_getentropy(n2rng_t *n2rng, void *buffer, size_t size)
{
	int		i, rv = 0;  /* so it works if size is zero */
	uint64_t	hverr;
	uint64_t	*buffer_w = (uint64_t *)buffer;
	int		num_w = size / sizeof (uint64_t);
	uint64_t	randval;
	uint64_t	randvalphys = va_to_pa(&randval);
	uint64_t	tdelta;
	int		failcount = 0;
	int		blockcount = 0;
	boolean_t	rnglooping;

	for (i = 0; i < num_w; i++) {
		rnglooping = B_TRUE;
		while (rnglooping) {
			hverr = hv_rng_data_read(randvalphys, &tdelta);
			rv = n2rng_herr2kerr(hverr);
			switch (hverr) {
			case H_EOK:
				buffer_w[i] = randval;
				failcount = 0;
				rnglooping = B_FALSE;
				break;
			case H_EIO:
				/*
				 * Either a health check is in progress, or
				 * the watchdog timer has expired while running
				 * hv api version 2.0 or higher with health
				 * checks enabled.
				 */
				if (n2rng->n_hvapi_major_version < 2) {
					/*
					 * A health check is in progress.
					 * Wait RNG_RETRY_HLCHK_USECS and fail
					 * after RNG_MAX_DATA_READ_ATTEMPTS
					 * failures.
					 */
					if (++failcount >
					    RNG_MAX_DATA_READ_ATTEMPTS) {
						DBG2(n2rng, DHEALTH,
						    "n2rng_getentropy: exceeded"
						    "EIO count of %d on cpu %d",
						    RNG_MAX_DATA_READ_ATTEMPTS,
						    CPU->cpu_id);
						goto exitpoint;
					} else {
						delay(drv_usectohz
						    (RNG_RETRY_HLCHK_USECS));
					}
				} else {
					/*
					 * Just return the error. If a flurry of
					 * random data requests happen to occur
					 * during a health check, there are
					 * multiple levels of defense:
					 * - 2.0 HV provides random data pool
					 * - FIPS algorithm tolerates failures
					 * - Software failover
					 * - Automatic configuration retries
					 * - Hardware failover on some systems
					 */
					goto exitpoint;
				}
				break;
			case H_EWOULDBLOCK:
				/* Data currently not available, try again */
				if (++blockcount > RNG_MAX_BLOCK_ATTEMPTS) {
					DBG1(n2rng, DHEALTH,
					    "n2rng_getentropy: "
					    "exceeded block count of %d",
					    RNG_MAX_BLOCK_ATTEMPTS);
					goto exitpoint;
				} else {
					cyclesleep(n2rng, tdelta);
				}
				break;
			default:
				log_internal_errors(hverr, "hv_rng_data_read");
				goto exitpoint;
			}
		} /* while */
	} /* for */

exitpoint:
	return (rv);
}

uint64_t
n2rng_ctl_read(n2rng_t *n2rng, int rngid, uint64_t ctlregs_pa, uint64_t *state,
    uint64_t *tdelta, uint64_t *wdelta)
{
	uint64_t	rv;
	uint64_t	wstatus;

	/* Call correct hv function based on api version */
	if (n2rng->n_hvapi_major_version == 2) {
		rv = hv_rng_ctl_read_v2(ctlregs_pa, (uint64_t)rngid, state,
		    tdelta, wdelta, &wstatus);
		if (rv == 0) {
			rv = wstatus;
		}
	} else {
		rv = hv_rng_ctl_read(ctlregs_pa, state, tdelta);
		*wdelta = 0;
	}

	return (rv);
}

uint64_t
n2rng_ctl_wait(n2rng_t *n2rng, int rngid)
{
	uint64_t	state;
	uint64_t	tdelta;
	uint64_t	wdelta;
	uint64_t	wstatus;
	boolean_t	rnglooping = B_TRUE;
	uint64_t	rv;
	n2rng_setup_t	setupbuffer[2];
	n2rng_setup_t	*setupcontigp;
	uint64_t	setupphys;
	int		busycount = 0;
	int		blockcount = 0;

	/*
	 * Use setupbuffer[0] if it is contiguous, otherwise
	 * setupbuffer[1].
	 */
	setupcontigp = &setupbuffer[
	    CONTIGUOUS(&setupbuffer[0], n2rng_setup_t) ? 0 : 1];
	setupphys = va_to_pa(setupcontigp);

	while (rnglooping) {
		rv = hv_rng_ctl_read_v2(setupphys, (uint64_t)rngid, &state,
		    &tdelta, &wdelta, &wstatus);
		switch (rv) {
		case H_EOK:
			rv = wstatus;
			rnglooping = B_FALSE;
			break;
		case H_EWOULDBLOCK:
			/* Data currently not available, try again */
			if (++blockcount > RNG_MAX_BLOCK_ATTEMPTS) {
				DBG1(n2rng, DHEALTH, "n2rng_ctl_wait: "
				    "exceeded block count of %d",
				    RNG_MAX_BLOCK_ATTEMPTS);
				return (rv);
			} else {
				cyclesleep(n2rng, tdelta);
			}
			break;
		case H_EBUSY:
			/* Control write still pending, try again */
			if (++busycount > RNG_MAX_BUSY_ATTEMPTS) {
				DBG1(n2rng, DHEALTH, "n2rng_ctl_wait: "
				    "exceeded busy count of %d",
				    RNG_MAX_BUSY_ATTEMPTS);
				return (rv);
			} else {
				delay(RNG_RETRY_BUSY_DELAY);
			}
			break;
		default:
			log_internal_errors(rv, "n2rng_ctl_wait");
			rnglooping = B_FALSE;
		}
	} /* while (rnglooping) */

	return (rv);
}

uint64_t
n2rng_ctl_write(n2rng_t *n2rng, int rngid, uint64_t ctlregs_pa,
    uint64_t newstate, uint64_t wtimeout, uint64_t *tdelta)
{
	uint64_t	rv;

	/* Call correct hv function based on api version */
	if (n2rng->n_hvapi_major_version == 2) {
		rv = hv_rng_ctl_write_v2(ctlregs_pa, newstate, wtimeout,
		    (uint64_t)rngid);
		if (rv == H_EOK) {
			/* Wait for control registers to be written */
			rv = n2rng_ctl_wait(n2rng, rngid);
		}
		*tdelta = RNG_DEFAULT_ACCUMULATE_CYCLES;
	} else {
		rv = hv_rng_ctl_write(ctlregs_pa, newstate, wtimeout, tdelta);
	}

	return (rv);
}

uint64_t
n2rng_data_read_diag(n2rng_t *n2rng, int rngid, uint64_t data_pa,
    size_t  datalen, uint64_t *tdelta)
{
	uint64_t	rv;

	/* Call correct hv function based on api version */
	if (n2rng->n_hvapi_major_version == 2) {
		rv = hv_rng_data_read_diag_v2(data_pa, datalen,
		    (uint64_t)rngid, tdelta);
		if (*tdelta == 0) {
			*tdelta = RNG_DEFAULT_ACCUMULATE_CYCLES;
		}
	} else {
		rv = hv_rng_data_read_diag(data_pa, datalen, tdelta);
	}

	return (rv);
}

uint64_t
n2rng_check_ctl_access(n2rng_t *n2rng)
{
	uint64_t	rv;
	uint64_t	unused_64;

	/* Call correct hv function based on api version */
	if (n2rng->n_hvapi_major_version == 2) {
		/*
		 * Attempt to read control registers with invalid ID and data
		 * just to see if we get an access error
		 */
		rv = hv_rng_ctl_read_v2(0, N2RNG_INVALID_ID,
		    &unused_64, &unused_64, &unused_64, &unused_64);
	} else {
		rv = hv_rng_get_diag_control();
	}

	return (rv);
}

/*
 * n2rng_config_retry()
 *
 * Schedule a timed call to n2rng_config() if one is not already pending
 */
void
n2rng_config_retry(n2rng_t *n2rng, clock_t seconds)
{
	mutex_enter(&n2rng->n_lock);
	/* Check if a config retry is already pending */
	if (n2rng->n_timeout_id) {
		DBG1(n2rng, DCFG, "n2rng_config_retry: retry pending "
		    "id = %x", n2rng->n_timeout_id);
	} else {
		n2rng->n_timeout_id = timeout(n2rng_config_task,
		    (void *)n2rng, drv_usectohz(seconds * SECOND));
		DBG2(n2rng, DCFG, "n2rng_config_retry: retry scheduled in "
		    "%d seconds, id = %x", seconds, n2rng->n_timeout_id);
	}
	mutex_exit(&n2rng->n_lock);
}

static uint64_t
sticks_per_usec(void)
{
	uint64_t starttick = gettick();
	hrtime_t starttime = gethrtime();
	uint64_t endtick;
	hrtime_t endtime;

	delay(2);

	endtick = gettick();
	endtime = gethrtime();

	return ((1000 * (endtick - starttick)) / (endtime - starttime));
}

static int
n2rng_init_ctl(n2rng_t *n2rng)
{
	int		rv;
	int		hverr;
	rng_entry_t	*rng;
	int		rngid;
	int		blockcount = 0;

	n2rng->n_ctl_data = NULL;

	/* Attempt to gain diagnostic control */
	do {
		hverr = n2rng_check_ctl_access(n2rng);
		rv = n2rng_herr2kerr(hverr);
		if ((hverr == H_EWOULDBLOCK) &&
		    (++blockcount > RNG_MAX_BUSY_ATTEMPTS)) {
			DBG1(n2rng, DHEALTH, "n2rng_int_ctl: exceeded busy "
			    "count of %d", RNG_MAX_BUSY_ATTEMPTS);
			return (rv);
		} else {
			delay(RNG_RETRY_BUSY_DELAY);
		}
	} while (hverr == H_EWOULDBLOCK);

	/*
	 * If attempt fails with EPERM, the driver is not running in the
	 * control domain
	 */
	if (rv == EPERM) {
		DBG0(n2rng, DATTACH,
		    "n2rng_init_ctl: Running in guest domain");
		return (DDI_SUCCESS);
	}

	/* Allocate control stucture only used in control domain */
	n2rng->n_ctl_data = kmem_alloc(sizeof (rng_ctl_data_t), KM_SLEEP);
	n2rng->n_ctl_data->n_num_rngs_online = 0;

	/*
	 * If running with an API version less than 2.0 default to one rng.
	 * Otherwise get number of rngs from device properties.
	 */
	if (n2rng->n_hvapi_major_version < 2) {
		n2rng->n_ctl_data->n_num_rngs = 1;
	} else {
		n2rng->n_ctl_data->n_num_rngs =
		    ddi_getprop(DDI_DEV_T_ANY, n2rng->n_dip,
		    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
		    N2RNG_PROP_NUM_UNITS, 0);
		if (n2rng->n_ctl_data->n_num_rngs == 0) {
			cmn_err(CE_WARN, "n2rng: %s property not found",
			    N2RNG_PROP_NUM_UNITS);
			return (DDI_FAILURE);
		}
	}

	/* Allocate space for all rng entries */
	n2rng->n_ctl_data->n_rngs =
	    kmem_zalloc(n2rng->n_ctl_data->n_num_rngs *
	    sizeof (rng_entry_t), KM_SLEEP);

	/* Get accumulate cycles from .conf file. */
	n2rng->n_ctl_data->n_accumulate_cycles =
	    ddi_getprop(DDI_DEV_T_ANY, n2rng->n_dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "acc_cycles",
	    RNG_DEFAULT_ACCUMULATE_CYCLES);

	/* Get health check frequency from .conf file */
	n2rng->n_ctl_data->n_hc_secs = ddi_getprop(DDI_DEV_T_ANY, n2rng->n_dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "hc_seconds",
	    RNG_DEFAULT_HC_SECS);

	/* API versions prior to 2.0 do not support health checks */
	if ((n2rng->n_hvapi_major_version < 2) &&
	    (n2rng->n_ctl_data->n_hc_secs > 0)) {
		cmn_err(CE_WARN, "n2rng: Hyperviser api "
		    "version %d.%d does not support health checks",
		    n2rng->n_hvapi_major_version,
		    n2rng->n_hvapi_minor_version);
		n2rng->n_ctl_data->n_hc_secs = 0;
	}


	/* Calculate watchdog timeout value */
	if (n2rng->n_ctl_data->n_hc_secs <= 0) {
		n2rng->n_ctl_data->n_watchdog_cycles = 0;
	} else {
		n2rng->n_ctl_data->n_watchdog_cycles =
		    ((uint64_t)(RNG_EXTRA_WATCHDOG_SECS) +
		    n2rng->n_ctl_data->n_hc_secs) *
		    n2rng->n_sticks_per_usec * 1000000;
	}

	/*
	 * Set some plausible state into the preferred configuration.
	 * The intent is that the health check will immediately overwrite it.
	 */
	for (rngid = 0; rngid < n2rng->n_ctl_data->n_num_rngs; rngid++) {

		rng = &n2rng->n_ctl_data->n_rngs[rngid];

		rng->n_preferred_config.ctlwds[0].word = 0;
		rng->n_preferred_config.ctlwds[0].fields.rnc_anlg_sel =
		    N2RNG_NOANALOGOUT;
		rng->n_preferred_config.ctlwds[0].fields.rnc_cnt =
		    RNG_DEFAULT_ACCUMULATE_CYCLES;
		rng->n_preferred_config.ctlwds[0].fields.rnc_mode =
		    RNG_MODE_NORMAL;
		rng->n_preferred_config.ctlwds[1].word =
		    rng->n_preferred_config.ctlwds[0].word;
		rng->n_preferred_config.ctlwds[2].word =
		    rng->n_preferred_config.ctlwds[0].word;
		rng->n_preferred_config.ctlwds[3].word =
		    rng->n_preferred_config.ctlwds[0].word;
		rng->n_preferred_config.ctlwds[0].fields.rnc_vcoctl = 1;
		rng->n_preferred_config.ctlwds[0].fields.rnc_selbits = 1;
		rng->n_preferred_config.ctlwds[1].fields.rnc_vcoctl = 2;
		rng->n_preferred_config.ctlwds[1].fields.rnc_selbits = 2;
		rng->n_preferred_config.ctlwds[2].fields.rnc_vcoctl = 3;
		rng->n_preferred_config.ctlwds[2].fields.rnc_selbits = 4;
		rng->n_preferred_config.ctlwds[3].fields.rnc_vcoctl = 0;
		rng->n_preferred_config.ctlwds[3].fields.rnc_selbits = 7;
	}

	n2rng_setcontrol(n2rng);
	DBG2(n2rng, DATTACH,
	    "n2rng_init_ctl: Running in control domain with %d rng device%s",
	    n2rng->n_ctl_data->n_num_rngs,
	    (n2rng->n_ctl_data->n_num_rngs == 1) ? "" : "s");
	DBG2(n2rng, DCFG,
	    "n2rng_init_ctl: n_sticks_per_usec = %ld, n_hc_secs = %d",
	    n2rng->n_sticks_per_usec,
	    n2rng->n_ctl_data->n_hc_secs);
	DBG2(n2rng, DCFG,
	    "n2rng_init_ctl: n_watchdog_cycles = %ld, "
	    "n_accumulate_cycles = %ld", n2rng->n_ctl_data->n_watchdog_cycles,
	    n2rng->n_ctl_data->n_accumulate_cycles);

	return (DDI_SUCCESS);
}

static void
n2rng_uninit_ctl(n2rng_t *n2rng)
{
	if (n2rng->n_ctl_data) {
		if (n2rng->n_ctl_data->n_num_rngs) {
			kmem_free(n2rng->n_ctl_data->n_rngs,
			    n2rng->n_ctl_data->n_num_rngs *
			    sizeof (rng_entry_t));
			n2rng->n_ctl_data->n_rngs = NULL;
			n2rng->n_ctl_data->n_num_rngs = 0;
		}
		kmem_free(n2rng->n_ctl_data, sizeof (rng_ctl_data_t));
		n2rng->n_ctl_data = NULL;
	}
}


/*
 * n2rng_config_test()
 *
 * Attempt read random data to see if the rng is configured.
 */
int
n2rng_config_test(n2rng_t *n2rng)
{
	int		rv = 0;
	uint64_t	hverr;
	uint64_t	randval = 0;
	uint64_t	randvalphys = va_to_pa(&randval);
	uint64_t	tdelta;
	int		failcount = 0;
	int		blockcount = 0;
	boolean_t	rnglooping = B_TRUE;

	while (rnglooping) {
		hverr = hv_rng_data_read(randvalphys, &tdelta);
		rv = n2rng_herr2kerr(hverr);
		switch (hverr) {
		case H_EOK:
			failcount = 0;
			rnglooping = B_FALSE;
			break;
		case H_EIO:
			/*
			 * A health check is in progress.
			 * Wait RNG_RETRY_HLCHK_USECS and fail
			 * after RNG_MAX_DATA_READ_ATTEMPTS
			 * failures.
			 */
			if (++failcount > RNG_MAX_DATA_READ_ATTEMPTS) {
				goto exitpoint;
			} else {
				delay(drv_usectohz(RNG_RETRY_HLCHK_USECS));
			}
			break;
		case H_EWOULDBLOCK:
			/* Data currently not available, try again */
			if (++blockcount > RNG_MAX_BLOCK_ATTEMPTS) {
				DBG1(n2rng, DHEALTH, "n2rng_config_test: "
				    "exceeded block count of %d",
				    RNG_MAX_BLOCK_ATTEMPTS);
				goto exitpoint;
			} else {
				cyclesleep(n2rng, tdelta);
			}
			break;
		case H_ENOACCESS:
			/* An rng error has occured during health check */
			goto exitpoint;
		default:
			log_internal_errors(hverr, "hv_rng_data_read");
			goto exitpoint;
		}
	} /* while */

exitpoint:
	return (rv);
}

/*
 * n2rng_config()
 *
 * Run health check on the RNG hardware
 * Configure the RNG hardware
 * Register with crypto framework
 */
static int
n2rng_config(n2rng_t *n2rng)
{
	int		rv;
	rng_entry_t	*rng;
	int		rngid;

	/*
	 * Run health checks and configure rngs if running in control domain,
	 * otherwise just check if at least one rng is available.
	 */
	if (n2rng_iscontrol(n2rng)) {

		for (rngid = 0; rngid < n2rng->n_ctl_data->n_num_rngs;
		    rngid++) {

			rng = &n2rng->n_ctl_data->n_rngs[rngid];

			/* Only test rngs that have not already failed */
			if (rng->n_rng_state == CTL_STATE_ERROR) {
				continue;
			}

			if ((n2rng->n_binding == N2RNG_CPU_VF) &&
			    (n2rng->n_hvapi_major_version < 2)) {
				/*
				 * Since api versions prior to 2.0 do not
				 * support multiple rngs, bind to the current
				 * processor for the entire health check
				 * process.
				 */
				thread_affinity_set(curthread, CPU_CURRENT);
				DBG1(n2rng, DCFG, "n2rng_config: "
				    "Configuring single rng from cpu %d",
				    CPU->cpu_id);
				rv = n2rng_do_health_check(n2rng, rngid);
				thread_affinity_clear(curthread);
			} else {
				rv = n2rng_do_health_check(n2rng, rngid);
			}

			switch (rv) {
			case 0:
				/*
				 * Successful, increment online count if
				 * necessary
				 */
				DBG1(n2rng, DCFG, "n2rng_config: rng(%d) "
				    "passed health checks", rngid);
				if (rng->n_rng_state != CTL_STATE_CONFIGURED) {
					rng->n_rng_state =
					    CTL_STATE_CONFIGURED;
					n2rng->n_ctl_data->n_num_rngs_online++;
				}
				break;
			default:
				/*
				 * Health checks failed, decrement online
				 * count if necessary
				 */
				cmn_err(CE_WARN, "n2rng: rng(%d) "
				    "failed health checks", rngid);
				if (rng->n_rng_state == CTL_STATE_CONFIGURED) {
					n2rng->n_ctl_data->n_num_rngs_online--;
				}
				rng->n_rng_state = CTL_STATE_ERROR;
				break;
			}
		}
		DBG2(n2rng, DCFG, "n2rng_config: %d rng%s online",
		    n2rng->n_ctl_data->n_num_rngs_online,
		    (n2rng->n_ctl_data->n_num_rngs_online == 1) ? "" : "s");

		/* Check if all rngs have failed */
		if (n2rng->n_ctl_data->n_num_rngs_online == 0) {
			cmn_err(CE_WARN, "n2rng: %d RNG device%s failed",
			    n2rng->n_ctl_data->n_num_rngs,
			    (n2rng->n_ctl_data->n_num_rngs == 1) ? "" : "s");
			goto errorexit;
		} else {
			n2rng_setconfigured(n2rng);
		}
	} else {
		/* Running in guest domain, just check if rng is configured */
		rv = n2rng_config_test(n2rng);
		switch (rv) {
		case 0:
			n2rng_setconfigured(n2rng);
			break;
		case EIO:
			/* Don't set configured to force a retry */
			break;
		default:
			goto errorexit;
		}
	}

	/*
	 * Initialize FIPS state and register with KCF if we have at least one
	 * RNG configured.  Otherwise schedule a retry if all rngs have not
	 * failed.
	 */
	if (n2rng_isconfigured(n2rng)) {

		if (n2rng_init(n2rng) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "n2rng: unable to register with KCF");
			goto errorexit;
		}

		/*
		 * Schedule a retry if running in the control domain and a
		 * health check time has been specified.
		 */
		if (n2rng_iscontrol(n2rng) &&
		    (n2rng->n_ctl_data->n_hc_secs > 0)) {
			n2rng_config_retry(n2rng,
			    n2rng->n_ctl_data->n_hc_secs);
		}
	} else if (!n2rng_isfailed(n2rng)) {
		/* Schedule a retry if one is not already pending */
		n2rng_config_retry(n2rng, RNG_CFG_RETRY_SECS);
	}
	return (DDI_SUCCESS);

errorexit:
	/* Unregister from kCF if we are registered */
	(void) n2rng_unregister_provider(n2rng);
	n2rng_setfailed(n2rng);
	cmn_err(CE_WARN, "n2rng: hardware failure detected");
	return (DDI_FAILURE);
}

/*
 * n2rng_config_task()
 *
 * Call n2rng_config() from the task queue or after a timeout, ignore result.
 */
static void
n2rng_config_task(void *targ)
{
	n2rng_t *n2rng = (n2rng_t *)targ;

	mutex_enter(&n2rng->n_lock);
	n2rng->n_timeout_id = 0;
	mutex_exit(&n2rng->n_lock);
	(void) n2rng_config(n2rng);
}
