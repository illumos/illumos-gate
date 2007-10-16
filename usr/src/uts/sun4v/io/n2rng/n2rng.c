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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
int	n2rng_herr2kerr(uint64_t);
int	n2rng_logic_test(n2rng_t *);
int	n2rng_noise_gen_test_set(void);
int	n2rng_init(n2rng_t *n2rng);
int	n2rng_uninit(n2rng_t *n2rng);

static uint64_t sticks_per_usec(void);
u_longlong_t gettick(void);

static void n2rng_config_task(void * targ);

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
	ddi_power		/* devo_power */
};

/*
 * Module linkage.
 */
static struct modldrv modldrv = {
	&mod_driverops,			/* drv_modops */
	"N2 RNG Driver v%I%",		/* drv_linkinfo */
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
 * Hypervisor RNG information.
 */
static uint64_t	rng_min_ver;	/* negotiated RNG API minor version */
static boolean_t rng_hsvc_available = B_FALSE;

static hsvc_info_t rng_hsvc = {
	HSVC_REV_1, NULL, HSVC_GROUP_RNG, RNG_MAJOR_VER,
	RNG_MINOR_VER, "n2rng"
};

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

	instance = ddi_get_instance(dip);
	DBG1(NULL, DATTACH, "n2rng_attach called, instance %d", instance);
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

	mutex_init(&n2rng->n_health_check_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((rv = hsvc_register(&rng_hsvc, &rng_min_ver)) != 0) {
		cmn_err(CE_WARN, "%s: cannot negotiate hypervisor services "
		    "group: 0x%lx major: 0x%lx minor: 0x%lx errno: %d",
		    rng_hsvc.hsvc_modname, rng_hsvc.hsvc_group,
		    rng_hsvc.hsvc_major, rng_hsvc.hsvc_minor, rv);
		ddi_soft_state_free(n2rng_softstate, instance);
		mutex_destroy(&n2rng->n_health_check_mutex);
		return (DDI_FAILURE);
	}
	rng_hsvc_available = B_TRUE;

	/* Allocate single thread task queue for rng diags and registration */
	n2rng->n_taskq = ddi_taskq_create(dip, "n2rng_taskq", 1,
	    TASKQ_DEFAULTPRI, 0);

	if (n2rng->n_taskq == NULL) {
		n2rng_diperror(dip, "ddi_taskq_create() failed");
		goto errorexit;
	}

	/* No locking, but it is okay */
	n2rng->n_sticks_per_usec = sticks_per_usec();
	/*
	 * The first product will likely be around 4 billion, so we
	 * use uint64_t to avoid integer overflow.
	 */
	n2rng->n_anlg_settle_cycles = (uint64_t)RNG_CTL_SETTLE_NS *
	    n2rng->n_sticks_per_usec / 1000;

	/*
	 * Set some plausible state into the preferred
	 * configuration. The intent is that the health check, below,
	 * will immediately overwrite it.  If we are not in a control
	 * domain, this stuff will have no effect.
	 */
	n2rng->n_preferred_config.ctlwds[0].word = 0;
	n2rng->n_preferred_config.ctlwds[0].fields.rnc_anlg_sel =
	    N2RNG_NOANALOGOUT;
	n2rng->n_preferred_config.ctlwds[0].fields.rnc_cnt =
	    RNG_DEFAULT_ACCUMULATE_CYCLES;
	n2rng->n_preferred_config.ctlwds[0].fields.rnc_mode =
	    RNG_MODE_NORMAL;
	n2rng->n_preferred_config.ctlwds[1].word =
	    n2rng->n_preferred_config.ctlwds[0].word;
	n2rng->n_preferred_config.ctlwds[2].word =
	    n2rng->n_preferred_config.ctlwds[0].word;
	n2rng->n_preferred_config.ctlwds[3].word =
	    n2rng->n_preferred_config.ctlwds[0].word;
	n2rng->n_preferred_config.ctlwds[0].fields.rnc_vcoctl = 1;
	n2rng->n_preferred_config.ctlwds[0].fields.rnc_selbits = 1;
	n2rng->n_preferred_config.ctlwds[1].fields.rnc_vcoctl = 2;
	n2rng->n_preferred_config.ctlwds[1].fields.rnc_selbits = 2;
	n2rng->n_preferred_config.ctlwds[2].fields.rnc_vcoctl = 3;
	n2rng->n_preferred_config.ctlwds[2].fields.rnc_selbits = 4;
	n2rng->n_preferred_config.ctlwds[3].fields.rnc_vcoctl = 0;
	n2rng->n_preferred_config.ctlwds[3].fields.rnc_selbits = 7;

	/* Dispatch task to configure the RNG and register with KCF */
	if (ddi_taskq_dispatch(n2rng->n_taskq, n2rng_config_task,
	    (void *)n2rng, DDI_SLEEP) != DDI_SUCCESS) {
		n2rng_diperror(dip, "ddi_taskq_dispatch() failed");
		goto errorexit;
	}

	return (DDI_SUCCESS);

errorexit:
	if (rng_hsvc_available == B_TRUE) {
		(void) hsvc_unregister(&rng_hsvc);
		rng_hsvc_available = B_FALSE;
	}

	if (n2rng->n_taskq != NULL) {
		ddi_taskq_destroy(n2rng->n_taskq);
		n2rng->n_taskq = NULL;
	}

	mutex_destroy(&n2rng->n_health_check_mutex);
	ddi_soft_state_free(n2rng_softstate, instance);

	return (DDI_FAILURE);
}

static int
n2rng_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	int		rv;
	n2rng_t		*n2rng;

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

	/* unregister with KCF---also tears down FIPS state */
	rv = n2rng_uninit(n2rng) ? DDI_FAILURE : DDI_SUCCESS;

	if (rng_hsvc_available == B_TRUE) {
		(void) hsvc_unregister(&rng_hsvc);
		rng_hsvc_available = B_FALSE;
	}

	mutex_destroy(&n2rng->n_health_check_mutex);

	ddi_soft_state_free(n2rng_softstate, instance);

	return (rv);
}

/*ARGSUSED*/
static int
n2rng_suspend(n2rng_t *n2rng)
{
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
n2rng_resume(n2rng_t *n2rng)
{
	int		rv;

	/* assume clock is same speed, all data structures intact.  */
	rv = n2rng_do_health_check(n2rng);
	switch (rv) {
	case 0:
	case EPERM:
		break;
	default:
		cmn_err(CE_WARN, "n2rng: n2rng_resume: health check failed. "
		    "Unregistering from encryption framework");
		n2rng->n_flags |= N2RNG_FAILED;
		(void) n2rng_uninit(n2rng);
		break;
	}

	return (DDI_SUCCESS);
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
	case H_ENORADDR:
	case H_EBADALIGN:
	case H_EIO:
		s_errcode = EIO;
		break;
	case H_EOK:
		s_errcode = 0;
		break;
	case H_ENOACCESS:
		s_errcode = EPERM;
		break;
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
n2rng_collect_diag_bits(n2rng_t *n2rng, n2rng_setup_t *collect_setupp,
    void *buffer, int numbytes, n2rng_setup_t *exit_setupp,
    uint64_t exitstate)
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
			hverr = hv_rng_ctl_write(setupphys,
			    CTL_STATE_HEALTHCHECK,
			    n2rng->n_anlg_settle_cycles, &tdelta);
			rv = n2rng_herr2kerr(hverr);
			switch (hverr) {
			case 0:
				rnglooping = B_FALSE;
				break;
			case H_EIO: /* control yanked from us */
			case H_ENOACCESS: /* We are not control domain */
				return (rv);
			case H_EWOULDBLOCK:
				cyclesleep(n2rng, tdelta);
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
			while (rnglooping) {
				hverr = hv_rng_data_read_diag(
				    va_to_pa((uint64_t *)buffer +
				    RNG_DIAG_CHUNK_SIZE * i),
				    thisnumbytes, &tdelta);
				rv = n2rng_herr2kerr(hverr);
				switch (hverr) {
				case 0:
					rnglooping = B_FALSE;
					break;
				case H_EIO:
				case H_ENOACCESS:
					return (rv);
				case H_EWOULDBLOCK:
					cyclesleep(n2rng, tdelta);
					break;
				default:
					log_internal_errors(hverr,
					    "hv_rng_data_read_diag");
					override_rv = rv;
					goto restore_state;
				}
			} /* while (!rnglooping) */
		} /* for */
	} /* if */

restore_state:

	/* restore the preferred configuration and set exit state */
	if (exit_setupp != NULL) {

		*setupcontigp = *exit_setupp;
		rnglooping = B_TRUE;
		while (rnglooping) {
			hverr = hv_rng_ctl_write(setupphys, exitstate,
			    n2rng->n_anlg_settle_cycles, &tdelta);
			rv = n2rng_herr2kerr(hverr);
			switch (hverr) {
			case 0:
			case H_EIO: /* control yanked from us */
			case H_EINVAL: /* some external error, probably */
			case H_ENOACCESS: /* We are not control domain */
				rnglooping = B_FALSE;
				break;
			case H_EWOULDBLOCK:
				cyclesleep(n2rng, tdelta);
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
				 * A health check is in progress.
				 * Wait RNG_RETRY_HLCHK_USECS and fail
				 * after RNG_MAX_DATA_READ_ATTEMPTS
				 * failures.
				 */
				if (++failcount > RNG_MAX_DATA_READ_ATTEMPTS) {
					goto exitpoint;
				} else {
					delay(drv_usectohz(
					    RNG_RETRY_HLCHK_USECS));
				}
				break;
			case H_EWOULDBLOCK:
				cyclesleep(n2rng, tdelta);
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

/*
 * n2rng_config_task()
 *
 * Runs health checks on the RNG hardware
 * Configures the RNG hardware
 * Registers with crypto framework if successful.
 */
static void
n2rng_config_task(void * targ)
{
	int		rv;
	n2rng_t		*n2rng = (n2rng_t *)targ;

	thread_affinity_set(curthread, CPU_CURRENT);
	rv = n2rng_do_health_check(n2rng);
	thread_affinity_clear(curthread);

	switch (rv) {
	case 0:
		/* We are a control domain.  Success. */
		break;
	case EPERM:
		/* We must not be a control domain, declare success. */
		rv = 0;
		break;
	default:
		goto errorexit;
	}

	/* Register with KCF and initialize FIPS state */
	rv = n2rng_init(n2rng);
	if (rv != DDI_SUCCESS) {
		goto errorexit;
	}

	n2rng->n_flags &= ~N2RNG_FAILED;
	return;

errorexit:
	cmn_err(CE_WARN, "n2rng_config_task: RNG configuration failed");
	n2rng->n_flags |= N2RNG_FAILED;
}
