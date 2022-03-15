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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Fault Management for Device Drivers
 *
 * Device drivers wishing to participate in fault management may do so by
 * first initializing their fault management state and capabilties via
 * ddi_fm_init(). If the system supports the requested FM capabilities,
 * the IO framework will intialize FM state and return a bit mask of the
 * requested capabilities.
 *
 * If the system does not support the requested FM capabilities,
 * the device driver must behave in accordance with the programming semantics
 * defined below for the capabilities returned from ddi_fm_init().
 * ddi_fm_init() must be called at attach(9E) time and ddi_fm_fini() must be
 * called from detach(9E) to perform FM clean-up.
 *
 * Driver Fault Management Capabilities
 *
 * DDI_FM_NOT_CAPABLE
 *
 *	This is the default fault management capability for drivers.  Drivers
 *	that implement no fault management capabilites or do not participate
 *	in fault management activities have their FM capability bitmask set
 *	to 0.
 *
 * DDI_FM_EREPORT_CAPABLE
 *
 *	When this capability bit is set, drivers are expected to generate error
 *	report events via ddi_ereport_post() for the associated faults
 *	that are diagnosed by the IO fault manager DE.  ddi_ereport_post()
 *	may be called in any context subject to the constraints specified
 *	by the interrupt iblock cookie	returned during initialization.
 *
 *	Error reports resulting from hardware component specific and common IO
 *	fault and driver defects must be accompanied by an Eversholt fault
 *	tree (.eft) by the Solaris fault manager (fmd(8)) for
 *	diagnosis.
 *
 * DDI_FM_ERRCB_CAPABLE
 *
 *	Device drivers are expected to implement and register an error
 *	handler callback function.  ddi_fm_handler_register() and
 *	ddi_fm_handler_unregister() must be
 *	called in passive kernel context, typically during an attach(9E)
 *	or detach(9E) operation.  When called by the FM IO framework,
 *	the callback function should check for error conditions for the
 *	hardware and software under its control.  All detected errors
 *	should have ereport events generated for them.
 *
 *	Upon completion of the error handler callback, the driver should
 *	return one of the following values:
 *
 *	#define DDI_FM_OK - no error was detected
 *	#define DDI_FM_FATAL - a fatal error was detected
 *	#define DDI_FM_NONFATAL - a non-fatal error was detected
 *	#define DDI_FM_UNKNOWN - the error status is unknown
 *
 *	To insure single threaded access to error handling callbacks,
 *	the device driver may use i_ddi_fm_handler_enter() and
 *	i_ddi_fm_handler_exit() when entering and exiting the callback.
 *
 * DDI_FM_ACCCHK_CAPABLE/DDI_FM_DMACHK_CAPABLE
 *
 *	Device drivers are expected to set-up access and DMA handles
 *	with FM-specific attributes designed to allow nexus parent
 *	drivers to flag any errors seen during subsequent IO transactions.
 *	Drivers must set the devacc_attr_acc_flag member of their
 *	ddi_device_acc_attr_t structures to DDI_FLAGERR_ACC or DDI_CAUTIOUS_ACC.
 *	For DMA transactions, driver must set the dma_attr_flags of
 *	their ddi_dma_attr_t structures to DDI_DMA_FLAGERR.
 *
 *	Upon completion of an IO transaction, device drivers are expected
 *	to check the status of host-side hardware access and device-side
 *	dma completions by calling ddi_acc_err_check() or ddi_dma_err_check()
 *	respectively. If the handle is associated with an error detected by
 *	the nexus parent or FM IO framework, ddi_fm_error_t data (status, ena
 *	and error expectation) is returned.  If status of DDI_FM_NONFATAL or
 *	DDI_FM_FATAL is returned, the ena is valid and the expectation flag
 *	will be set to 1 if the error was unexpected (i.e. not the result
 *	of a peek or poke type operation).
 *
 *	ddi_acc_err_check() and ddi_dma_err_check() may be called in any
 *	context	subject to the constraints specified by the interrupt
 *	iblock cookie returned during initialization.
 *
 *	Device drivers should generate an access (DDI_FM_IO_ACC) or dma
 *	(DDI_FM_IO_DMA) data path error report if DDI_FM_NONFATAL or
 *	DDI_FM_FATAL is returned.
 *
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/kmem.h>
#include <sys/nvpair.h>
#include <sys/fm/protocol.h>
#include <sys/ndifm.h>
#include <sys/ddifm.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_isa.h>
#include <sys/spl.h>
#include <sys/varargs.h>
#include <sys/systm.h>
#include <sys/disp.h>
#include <sys/atomic.h>
#include <sys/errorq_impl.h>
#include <sys/kobj.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

#define	ERPT_CLASS_SZ	sizeof (DDI_IO_CLASS) + sizeof (FM_EREPORT_CLASS) + \
			    DDI_MAX_ERPT_CLASS + 2
/* Globals */
int default_dmacache_sz = DEFAULT_DMACACHE_SZ;
int default_acccache_sz = DEFAULT_ACCCACHE_SZ;
int ddi_system_fmcap = 0;

static struct i_ddi_fmkstat ddifm_kstat_template = {
	{"erpt_dropped", KSTAT_DATA_UINT64 },
	{"fm_cache_miss", KSTAT_DATA_UINT64 },
	{"fm_cache_full", KSTAT_DATA_UINT64 },
	{"acc_err", KSTAT_DATA_UINT64 },
	{"dma_err", KSTAT_DATA_UINT64 }
};

/*
 * Update the service state following the detection of an
 * error.
 */
void
ddi_fm_service_impact(dev_info_t *dip, int svc_impact)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	ena = fm_ena_generate(0, FM_ENA_FMT1);
	mutex_enter(&(DEVI(dip)->devi_lock));
	if (!DEVI_IS_DEVICE_OFFLINE(dip)) {
		switch (svc_impact) {
		case DDI_SERVICE_LOST:
			DEVI_SET_DEVICE_DOWN(dip);
			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    DDI_FM_SERVICE_IMPACT, DDI_FM_SERVICE_LOST);
			ddi_fm_ereport_post(dip, buf, ena, DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    NULL);
			break;
		case DDI_SERVICE_DEGRADED:
			DEVI_SET_DEVICE_DEGRADED(dip);
			if (DEVI_IS_DEVICE_DEGRADED(dip)) {
				(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
				    DDI_FM_SERVICE_IMPACT,
				    DDI_FM_SERVICE_DEGRADED);
				ddi_fm_ereport_post(dip, buf, ena, DDI_NOSLEEP,
				    FM_VERSION, DATA_TYPE_UINT8,
				    FM_EREPORT_VERS0, NULL);
			} else if (DEVI_IS_DEVICE_DOWN(dip)) {
				(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
				    DDI_FM_SERVICE_IMPACT,
				    DDI_FM_SERVICE_LOST);
				ddi_fm_ereport_post(dip, buf, ena, DDI_NOSLEEP,
				    FM_VERSION, DATA_TYPE_UINT8,
				    FM_EREPORT_VERS0, NULL);
			}
			break;
		case DDI_SERVICE_RESTORED:
			DEVI_SET_DEVICE_UP(dip);
			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    DDI_FM_SERVICE_IMPACT, DDI_FM_SERVICE_RESTORED);
			ddi_fm_ereport_post(dip, buf, ena, DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    NULL);
			break;
		case DDI_SERVICE_UNAFFECTED:
			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
			    DDI_FM_SERVICE_IMPACT, DDI_FM_SERVICE_UNAFFECTED);
			ddi_fm_ereport_post(dip, buf, ena, DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    NULL);
			break;
		default:
			break;
		}
	}
	mutex_exit(&(DEVI(dip)->devi_lock));
}

void
i_ddi_drv_ereport_post(dev_info_t *dip, const char *error_class,
    nvlist_t *errp, int sflag)
{
	int i;
	int depth;
	char classp[DDI_DVR_MAX_CLASS];
	caddr_t stkp;
	char *buf;
	char **stkpp;
	char *sym;
	pc_t stack[DDI_FM_STKDEPTH];
	ulong_t off;
	dev_info_t *root_dip = ddi_root_node();

	if (!DDI_FM_EREPORT_CAP(ddi_fm_capable(root_dip)))
		return;

	(void) snprintf(classp, DDI_DVR_MAX_CLASS, "%s%s", DVR_ERPT,
	    error_class);

	if (sflag == DDI_SLEEP) {
		depth = getpcstack(stack, DDI_FM_STKDEPTH);

		/* Allocate array of char * for nvlist payload */
		stkpp = (char **)kmem_alloc(depth * sizeof (char *), KM_SLEEP);

		/*
		 * Allocate temporary 64-bit aligned buffer for stack
		 * symbol strings
		 */
		buf = kmem_alloc(depth * DDI_FM_SYM_SZ, KM_SLEEP);

		stkp = buf;
		for (i = 0; i < depth; ++i) {
			sym = kobj_getsymname(stack[i], &off);
			(void) snprintf(stkp, DDI_FM_SYM_SZ,
			    "\t%s+%lx\n", sym ? sym : "?", off);
			stkpp[i] = stkp;
			stkp += DDI_FM_SYM_SZ;
		}

		if (errp)
			ddi_fm_ereport_post(root_dip,
			    classp, fm_ena_generate(0, FM_ENA_FMT1), sflag,
			    FM_VERSION, DATA_TYPE_UINT8, 0,
			    DVR_NAME, DATA_TYPE_STRING, ddi_driver_name(dip),
			    DVR_STACK_DEPTH, DATA_TYPE_UINT32, depth,
			    DVR_STACK, DATA_TYPE_STRING_ARRAY, depth, stkpp,
			    DVR_ERR_SPECIFIC, DATA_TYPE_NVLIST, errp, NULL);
		else
			ddi_fm_ereport_post(root_dip,
			    classp, fm_ena_generate(0, FM_ENA_FMT1), sflag,
			    FM_VERSION, DATA_TYPE_UINT8, 0,
			    DVR_NAME, DATA_TYPE_STRING, ddi_driver_name(dip),
			    DVR_STACK_DEPTH, DATA_TYPE_UINT32, depth,
			    DVR_STACK, DATA_TYPE_STRING_ARRAY, depth, stkpp,
			    NULL);

		kmem_free(stkpp, depth * sizeof (char *));
		kmem_free(buf, depth * DDI_FM_SYM_SZ);

	} else {
		if (errp)
			ddi_fm_ereport_post(root_dip,
			    classp, fm_ena_generate(0, FM_ENA_FMT1), sflag,
			    FM_VERSION, DATA_TYPE_UINT8, 0,
			    DVR_NAME, DATA_TYPE_STRING, ddi_driver_name(dip),
			    DVR_ERR_SPECIFIC, DATA_TYPE_NVLIST, errp, NULL);
		else
			ddi_fm_ereport_post(root_dip,
			    classp, fm_ena_generate(0, FM_ENA_FMT1), sflag,
			    FM_VERSION, DATA_TYPE_UINT8, 0,
			    DVR_NAME, DATA_TYPE_STRING, ddi_driver_name(dip),
			    NULL);
	}
}

/*
 * fm_dev_ereport_postv: Common consolidation private interface to
 * post a device tree oriented dev_scheme ereport. The device tree is
 * composed of the following entities: devinfo nodes, minor nodes, and
 * pathinfo nodes. All entities are associated with some devinfo node,
 * either directly or indirectly. The intended devinfo node association
 * for the ereport is communicated by the 'dip' argument. A minor node,
 * an entity below 'dip', is represented by a non-null 'minor_name'
 * argument. An application specific caller, like scsi_fm_ereport_post,
 * can override the devinfo path with a pathinfo path via a non-null
 * 'devpath' argument - in this case 'dip' is the MPXIO client node and
 * devpath should be the path through the pHCI devinfo node to the
 * pathinfo node.
 *
 * This interface also allows the caller to decide if the error being
 * reported is know to be associated with a specific device identity
 * via the 'devid' argument. The caller needs to control wether the
 * devid appears as an authority in the FMRI because for some types of
 * errors, like transport errors, the identity of the device on the
 * other end of the transport is not guaranteed to be the current
 * identity of the dip. For transport errors the caller should specify
 * a NULL devid, even when there is a valid devid associated with the dip.
 *
 * The ddi_fm_ereport_post() implementation calls this interface with
 * just a dip: devpath, minor_name, and devid are all NULL. The
 * scsi_fm_ereport_post() implementation may call this interface with
 * non-null devpath, minor_name, and devid arguments depending on
 * wether MPXIO is enabled, and wether a transport or non-transport
 * error is being posted.
 *
 * Additional event payload is specified via the varargs plist and, if
 * not NULL, the nvlist passed in (such an nvlist will be merged into
 * the payload; the caller is responsible for freeing this nvlist).
 * Do not specify any high-level protocol event member names as part of the
 * payload - eg no payload to be named "class", "version", "detector" etc
 * or they will replace the members we construct here.
 *
 * The 'target-port-l0id' argument is SCSI specific. It is used
 * by SCSI enumeration code when a devid is unavailable. If non-NULL
 * the property-value becomes part of the ereport detector. The value
 * specified might match one of the target-port-l0ids values of a
 * libtopo disk chassis node. When libtopo finds a disk with a guaranteed
 * unique wWWN target-port of a single-lun 'real' disk, it can add
 * the target-port value to the libtopo disk chassis node target-port-l0ids
 * string array property. Kernel code has no idea if this type of
 * libtopo chassis node exists, or if matching will in fact occur.
 */
void
fm_dev_ereport_postv(dev_info_t *dip, dev_info_t *eqdip,
    const char *devpath, const char *minor_name, const char *devid,
    const char *tpl0, const char *error_class, uint64_t ena, int sflag,
    nvlist_t *pl, va_list ap)
{
	nv_alloc_t		*nva = NULL;
	struct i_ddi_fmhdl	*fmhdl = NULL;
	errorq_elem_t		*eqep;
	nvlist_t		*ereport = NULL;
	nvlist_t		*detector = NULL;
	char			*name;
	data_type_t		type;
	uint8_t			version;
	char			class[ERPT_CLASS_SZ];
	char			path[MAXPATHLEN];

	ASSERT(ap != NULL);	/* must supply at least ereport version */
	ASSERT(dip && eqdip && error_class);

	/*
	 * This interface should be called with a fm_capable eqdip. The
	 * ddi_fm_ereport_post* interfaces call with eqdip == dip,
	 * ndi_fm_ereport_post* interfaces call with eqdip == ddi_parent(dip).
	 */
	if (!DDI_FM_EREPORT_CAP(ddi_fm_capable(eqdip)))
		goto err;

	/* get ereport nvlist handle */
	if ((sflag == DDI_SLEEP) && !panicstr) {
		/*
		 * Driver defect - should not call with DDI_SLEEP while in
		 * interrupt context.
		 */
		if (servicing_interrupt()) {
			i_ddi_drv_ereport_post(dip, DVR_ECONTEXT, NULL, sflag);
			goto err;
		}

		/* Use normal interfaces to allocate memory. */
		if ((ereport = fm_nvlist_create(NULL)) == NULL)
			goto err;
		ASSERT(nva == NULL);
	} else {
		/* Use errorq interfaces to avoid memory allocation. */
		fmhdl = DEVI(eqdip)->devi_fmhdl;
		ASSERT(fmhdl);
		eqep = errorq_reserve(fmhdl->fh_errorq);
		if (eqep == NULL)
			goto err;

		ereport = errorq_elem_nvl(fmhdl->fh_errorq, eqep);
		nva = errorq_elem_nva(fmhdl->fh_errorq, eqep);
		ASSERT(nva);
	}
	ASSERT(ereport);

	/*
	 * Form parts of an ereport:
	 *	A: version
	 *	B: error_class
	 *	C: ena
	 *	D: detector	(path and optional devid authority)
	 *	E: payload
	 *
	 * A: ereport version: first payload tuple must be the version.
	 */
	name = va_arg(ap, char *);
	type = va_arg(ap, data_type_t);
	version = va_arg(ap, uint_t);
	if ((strcmp(name, FM_VERSION) != 0) || (type != DATA_TYPE_UINT8)) {
		i_ddi_drv_ereport_post(dip, DVR_EVER, NULL, sflag);
		goto err;
	}

	/* B: ereport error_class: add "io." prefix to class. */
	(void) snprintf(class, ERPT_CLASS_SZ, "%s.%s",
	    DDI_IO_CLASS, error_class);

	/* C: ereport ena: if not passed in, generate new ena. */
	if (ena == 0)
		ena = fm_ena_generate(0, FM_ENA_FMT1);

	/* D: detector: form dev scheme fmri with path and devid. */
	if (devpath) {
		(void) strlcpy(path, devpath, sizeof (path));
	} else {
		/* derive devpath from dip */
		if (dip == ddi_root_node())
			(void) strcpy(path, "/");
		else
			(void) ddi_pathname(dip, path);
	}
	if (minor_name) {
		(void) strlcat(path, ":", sizeof (path));
		(void) strlcat(path, minor_name, sizeof (path));
	}
	detector = fm_nvlist_create(nva);
	fm_fmri_dev_set(detector, FM_DEV_SCHEME_VERSION, NULL, path,
	    devid, tpl0);

	/* Pull parts of ereport together into ereport. */
	fm_ereport_set(ereport, version, class, ena, detector, NULL);

	/* Merge any preconstructed payload into the event. */
	if (pl)
		(void) nvlist_merge(ereport, pl, 0);

	/* Add any remaining (after version) varargs payload to ereport. */
	name = va_arg(ap, char *);
	(void) i_fm_payload_set(ereport, name, ap);

	/* Post the ereport. */
	if (nva)
		errorq_commit(fmhdl->fh_errorq, eqep, ERRORQ_ASYNC);
	else
		fm_ereport_post(ereport, EVCH_SLEEP);
	goto out;

	/* Count errors as drops. */
err:	if (fmhdl)
		atomic_inc_64(&fmhdl->fh_kstat.fek_erpt_dropped.value.ui64);

	/* Free up nvlists if normal interfaces were used to allocate memory */
out:	if (ereport && (nva == NULL))
		fm_nvlist_destroy(ereport, FM_NVA_FREE);
	if (detector && (nva == NULL))
		fm_nvlist_destroy(detector, FM_NVA_FREE);
}

/*
 * Generate an error report for consumption by the Solaris Fault Manager,
 * fmd(8).  Valid ereport classes are defined in /usr/include/sys/fm/io.
 *
 * The ENA should be set if this error is a result of an error status
 * returned from ddi_dma_err_check() or ddi_acc_err_check().  Otherwise,
 * an ENA value of 0 is appropriate.
 *
 * If sflag == DDI_NOSLEEP, ddi_fm_ereport_post () may be called
 * from user, kernel, interrupt or high-interrupt context.  Otherwise,
 * ddi_fm_ereport_post() must be called from user or kernel context.
 *
 * The ndi_interfaces are provided for use by nexus drivers to post
 * ereports about children who may not themselves be fm_capable.
 *
 * All interfaces end up in the common fm_dev_ereport_postv code above.
 */
void
ddi_fm_ereport_post(dev_info_t *dip,
    const char *error_class, uint64_t ena, int sflag, ...)
{
	va_list ap;

	ASSERT(dip && error_class);
	va_start(ap, sflag);
	fm_dev_ereport_postv(dip, dip, NULL, NULL, NULL, NULL,
	    error_class, ena, sflag, NULL, ap);
	va_end(ap);
}

void
ndi_fm_ereport_post(dev_info_t *dip,
    const char *error_class, uint64_t ena, int sflag, ...)
{
	va_list ap;

	ASSERT(dip && error_class && (sflag == DDI_SLEEP));
	va_start(ap, sflag);
	fm_dev_ereport_postv(dip, ddi_get_parent(dip), NULL, NULL, NULL, NULL,
	    error_class, ena, sflag, NULL, ap);
	va_end(ap);
}

/*
 * Driver error handling entry.  Prevents multiple simultaneous calls into
 * driver error handling callback.
 *
 * May be called from a context consistent with the iblock_cookie returned
 * in ddi_fm_init().
 */
void
i_ddi_fm_handler_enter(dev_info_t *dip)
{
	struct i_ddi_fmhdl *hdl = DEVI(dip)->devi_fmhdl;

	mutex_enter(&hdl->fh_lock);
	hdl->fh_lock_owner = curthread;
}

/*
 * Driver error handling exit.
 *
 * May be called from a context consistent with the iblock_cookie returned
 * in ddi_fm_init().
 */
void
i_ddi_fm_handler_exit(dev_info_t *dip)
{
	struct i_ddi_fmhdl *hdl = DEVI(dip)->devi_fmhdl;

	hdl->fh_lock_owner = NULL;
	mutex_exit(&hdl->fh_lock);
}

boolean_t
i_ddi_fm_handler_owned(dev_info_t *dip)
{
	struct i_ddi_fmhdl *hdl = DEVI(dip)->devi_fmhdl;

	return (hdl->fh_lock_owner == curthread);
}

/*
 * Register a fault manager error handler for this device instance
 *
 * This function must be called from a driver's attach(9E) routine.
 */
void
ddi_fm_handler_register(dev_info_t *dip, ddi_err_func_t handler,
    void *impl_data)
{
	dev_info_t *pdip;
	struct i_ddi_fmhdl *pfmhdl;
	struct i_ddi_errhdl *new_eh;
	struct i_ddi_fmtgt *tgt;

	/*
	 * Check for proper calling context.
	 * The DDI configuration framework does not support
	 * DR states to allow checking for proper invocation
	 * from a DDI_ATTACH or DDI_RESUME.  This limits context checking
	 * to interrupt only.
	 */
	if (servicing_interrupt()) {
		i_ddi_drv_ereport_post(dip, DVR_ECONTEXT, NULL, DDI_NOSLEEP);
		return;
	}

	if (dip == ddi_root_node())
		pdip = dip;
	else
		pdip = (dev_info_t *)DEVI(dip)->devi_parent;

	ASSERT(pdip);

	if (!(DDI_FM_ERRCB_CAP(ddi_fm_capable(dip)) &&
	    DDI_FM_ERRCB_CAP(ddi_fm_capable(pdip)))) {
		i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL, DDI_SLEEP);
		return;
	}

	new_eh = kmem_zalloc(sizeof (struct i_ddi_errhdl), KM_SLEEP);
	new_eh->eh_func = handler;
	new_eh->eh_impl = impl_data;

	/* Add dip to parent's target list of registered error handlers */
	tgt = kmem_alloc(sizeof (struct i_ddi_fmtgt), KM_SLEEP);
	tgt->ft_dip = dip;
	tgt->ft_errhdl = new_eh;

	i_ddi_fm_handler_enter(pdip);
	pfmhdl = DEVI(pdip)->devi_fmhdl;
	ASSERT(pfmhdl);
	tgt->ft_next = pfmhdl->fh_tgts;
	pfmhdl->fh_tgts = tgt;
	i_ddi_fm_handler_exit(pdip);
}

/*
 * Unregister a fault manager error handler for this device instance
 *
 * This function must be called from a drivers attach(9E) or detach(9E)
 * routine.
 */
void
ddi_fm_handler_unregister(dev_info_t *dip)
{
	dev_info_t *pdip;
	struct i_ddi_fmhdl *pfmhdl;
	struct i_ddi_fmtgt *tgt, **ptgt;

	/*
	 * Check for proper calling context.
	 * The DDI configuration framework does not support
	 * DR states to allow checking for proper invocation
	 * from a DDI_DETACH or DDI_SUSPEND.  This limits context checking
	 * to interrupt only.
	 */
	if (servicing_interrupt()) {
		i_ddi_drv_ereport_post(dip, DVR_ECONTEXT, NULL, DDI_NOSLEEP);
		return;
	}

	if (dip == ddi_root_node())
		pdip = dip;
	else
		pdip = (dev_info_t *)DEVI(dip)->devi_parent;

	ASSERT(pdip);

	if (!(DDI_FM_ERRCB_CAP(ddi_fm_capable(dip)) &&
	    DDI_FM_ERRCB_CAP(ddi_fm_capable(pdip)))) {
		i_ddi_drv_ereport_post(dip, DVR_EFMCAP, NULL, DDI_SLEEP);
		return;
	}

	i_ddi_fm_handler_enter(pdip);
	pfmhdl = DEVI(pdip)->devi_fmhdl;
	ASSERT(pfmhdl);
	ptgt = &pfmhdl->fh_tgts;
	for (tgt = pfmhdl->fh_tgts; tgt != NULL; tgt = tgt->ft_next) {
		if (dip == tgt->ft_dip) {
			*ptgt = tgt->ft_next;
			kmem_free(tgt->ft_errhdl, sizeof (struct i_ddi_errhdl));
			kmem_free(tgt, sizeof (struct i_ddi_fmtgt));
			break;
		}
		ptgt = &tgt->ft_next;
	}
	i_ddi_fm_handler_exit(pdip);


}

/*
 * Initialize Fault Management capabilities for this device instance (dip).
 * When called with the following capabilities, data structures neccessary
 * for fault management activities are allocated and initialized.
 *
 *	DDI_FM_EREPORT_CAPABLE - initialize ereport errorq and ereport
 *				capable driver property.
 *
 *	DDI_FM_ERRCB_CAPABLE - check with parent for ability to register
 *				an error handler.
 *
 *	DDI_FM_ACCCHK_CAPABLE - initialize access handle cache and acc-chk
 *				driver property
 *
 *	DDI_FM_DMACHK_CAPABLE - initialize dma handle cache and dma-chk
 *				driver property
 *
 * A driver's FM capability level may not exceed that of its parent or
 * system-wide FM capability.  The available capability level for this
 * device instance is returned in *fmcap.
 *
 * This function must be called from a driver's attach(9E) entry point.
 */
void
ddi_fm_init(dev_info_t *dip, int *fmcap, ddi_iblock_cookie_t *ibcp)
{
	struct dev_info *devi = DEVI(dip);
	struct i_ddi_fmhdl *fmhdl;
	ddi_iblock_cookie_t ibc;
	int pcap, newcap = DDI_FM_NOT_CAPABLE;

	if (!DEVI_IS_ATTACHING(dip)) {
		i_ddi_drv_ereport_post(dip, DVR_ECONTEXT, NULL, DDI_NOSLEEP);
		*fmcap = DDI_FM_NOT_CAPABLE;
		return;
	}

	if (DDI_FM_DEFAULT_CAP(*fmcap))
		return;

	/*
	 * Check parent for supported FM level
	 * and correct error handling PIL
	 */
	if (dip != ddi_root_node()) {

		/*
		 * Initialize the default ibc.  The parent may change it
		 * depending upon its capabilities.
		 */
		ibc = (ddi_iblock_cookie_t)ipltospl(FM_ERR_PIL);

		pcap = i_ndi_busop_fm_init(dip, *fmcap, &ibc);
	} else {
		pcap = *fmcap;
		ibc = *ibcp;
	}

	/* Initialize the per-device instance FM handle */
	fmhdl = kmem_zalloc(sizeof (struct i_ddi_fmhdl), KM_SLEEP);

	if ((fmhdl->fh_ksp = kstat_create((char *)ddi_driver_name(dip),
	    ddi_get_instance(dip), "fm", "misc",
	    KSTAT_TYPE_NAMED, sizeof (struct i_ddi_fmkstat) /
	    sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL)) == NULL) {
		mutex_destroy(&fmhdl->fh_lock);
		kmem_free(fmhdl, sizeof (struct i_ddi_fmhdl));
		*fmcap = DDI_FM_NOT_CAPABLE;
		return;
	}

	bcopy(&ddifm_kstat_template, &fmhdl->fh_kstat,
	    sizeof (struct i_ddi_fmkstat));
	fmhdl->fh_ksp->ks_data = &fmhdl->fh_kstat;
	fmhdl->fh_ksp->ks_private = fmhdl;
	kstat_install(fmhdl->fh_ksp);

	fmhdl->fh_dma_cache = NULL;
	fmhdl->fh_acc_cache = NULL;
	fmhdl->fh_tgts = NULL;
	fmhdl->fh_dip = dip;
	fmhdl->fh_ibc = ibc;
	mutex_init(&fmhdl->fh_lock, NULL, MUTEX_DRIVER, fmhdl->fh_ibc);
	devi->devi_fmhdl = fmhdl;

	/*
	 * Initialize support for ereport generation
	 */
	if (DDI_FM_EREPORT_CAP(*fmcap) && DDI_FM_EREPORT_CAP(pcap)) {
		fmhdl->fh_errorq = ereport_errorq;
		if (ddi_getprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
		    "fm-ereport-capable", 0) == 0)
			(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP, "fm-ereport-capable", NULL, 0);

		newcap |= DDI_FM_EREPORT_CAPABLE;
	}

	/*
	 * Need cooperation of the parent for error handling
	 */

	if (DDI_FM_ERRCB_CAP(*fmcap) && DDI_FM_ERRCB_CAP(pcap)) {
		if (ddi_getprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
		    "fm-errcb-capable", 0) == 0)
			(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP, "fm-errcb-capable", NULL, 0);

		newcap |= DDI_FM_ERRCB_CAPABLE;
	}

	/*
	 * Support for DMA and Access error handling
	 */

	if (DDI_FM_DMA_ERR_CAP(*fmcap) && DDI_FM_DMA_ERR_CAP(pcap)) {
		i_ndi_fmc_create(&fmhdl->fh_dma_cache, 2, ibc);

		/* Set-up dma chk capability prop */
		if (ddi_getprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
		    "fm-dmachk-capable", 0) == 0)
			(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP, "fm-dmachk-capable", NULL, 0);

		newcap |= DDI_FM_DMACHK_CAPABLE;
	}

	if (DDI_FM_ACC_ERR_CAP(*fmcap) && DDI_FM_ACC_ERR_CAP(pcap)) {
		i_ndi_fmc_create(&fmhdl->fh_acc_cache, 2, ibc);
		/* Set-up dma chk capability prop */
		if (ddi_getprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
		    "fm-accchk-capable", 0) == 0)
			(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP, "fm-accchk-capable", NULL, 0);

		newcap |= DDI_FM_ACCCHK_CAPABLE;
	}

	/*
	 * Return the capability support available
	 * to this driver instance
	 */
	fmhdl->fh_cap = newcap;
	*fmcap = newcap;

	if (ibcp != NULL)
		*ibcp = ibc;
}

/*
 * Finalize Fault Management activities for this device instance.
 * Outstanding IO transaction must be completed prior to calling
 * this routine.  All previously allocated resources and error handler
 * registration are cleared and deallocated.
 *
 * This function must be called from a driver's detach(9E) entry point.
 */
void
ddi_fm_fini(dev_info_t *dip)
{
	struct i_ddi_fmhdl *fmhdl = DEVI(dip)->devi_fmhdl;

	ASSERT(fmhdl);

	if (!(DEVI_IS_DETACHING(dip) || DEVI_IS_ATTACHING(dip))) {
		i_ddi_drv_ereport_post(dip, DVR_ECONTEXT, NULL, DDI_NOSLEEP);
		return;
	}

	kstat_delete(fmhdl->fh_ksp);

	if (DDI_FM_EREPORT_CAP(fmhdl->fh_cap)) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
		    "fm-ereport-capable");
	}

	if (dip != ddi_root_node()) {
		if (DDI_FM_ERRCB_CAP(fmhdl->fh_cap)) {
			ddi_fm_handler_unregister(dip);
			(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
			    "fm-errcb-capable");
		}

		if (DDI_FM_DMA_ERR_CAP(fmhdl->fh_cap) ||
		    DDI_FM_ACC_ERR_CAP(fmhdl->fh_cap)) {
			if (fmhdl->fh_dma_cache != NULL) {
				i_ndi_fmc_destroy(fmhdl->fh_dma_cache);
				(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
				    "fm-dmachk-capable");
			}
			if (fmhdl->fh_acc_cache != NULL) {
				i_ndi_fmc_destroy(fmhdl->fh_acc_cache);
				(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
				    "fm-accachk-capable");
			}
		}

		i_ndi_busop_fm_fini(dip);
	}

	kmem_free(fmhdl, sizeof (struct i_ddi_fmhdl));
	DEVI(dip)->devi_fmhdl = NULL;
}

/*
 * Return the fault management capability level for this device instance.
 *
 * This function may be called from user, kernel, or interrupt context.
 */
int
ddi_fm_capable(dev_info_t *dip)
{
	struct i_ddi_fmhdl *fmhdl = DEVI(dip)->devi_fmhdl;

	if (fmhdl == NULL)
		return (DDI_FM_NOT_CAPABLE);

	return (fmhdl->fh_cap);
}

/*
 * Routines to set and get error information for/from an access or dma handle
 *
 * These routines may be called from user, kernel, and interrupt contexts.
 */

static void
ddi_fm_acc_err_get_fail(ddi_acc_handle_t handle)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	i_ddi_drv_ereport_post(hp->ah_dip, DVR_EVER, NULL, DDI_NOSLEEP);
	cmn_err(CE_PANIC, "ddi_fm_acc_err_get: Invalid driver version\n");
}

void
ddi_fm_acc_err_get(ddi_acc_handle_t handle, ddi_fm_error_t *de, int version)
{
	ndi_err_t *errp;

	if (handle == NULL)
		return;

	if (version != DDI_FME_VER0 && version != DDI_FME_VER1) {
		ddi_fm_acc_err_get_fail(handle);
		return;
	}

	errp = ((ddi_acc_impl_t *)handle)->ahi_err;
	if (errp->err_status == DDI_FM_OK) {
		if (de->fme_status != DDI_FM_OK)
			de->fme_status = DDI_FM_OK;
		return;
	}
	de->fme_status = errp->err_status;
	de->fme_ena = errp->err_ena;
	de->fme_flag = errp->err_expected;
	de->fme_acc_handle = handle;
}

void
ddi_fm_dma_err_get_fail(ddi_dma_handle_t handle)
{
	i_ddi_drv_ereport_post(((ddi_dma_impl_t *)handle)->dmai_rdip,
	    DVR_EVER, NULL, DDI_NOSLEEP);
	cmn_err(CE_PANIC, "ddi_fm_dma_err_get: Invalid driver version\n");
}

void
ddi_fm_dma_err_get(ddi_dma_handle_t handle, ddi_fm_error_t *de, int version)
{
	ndi_err_t *errp;

	if (handle == NULL)
		return;

	if (version != DDI_FME_VER0 && version != DDI_FME_VER1) {
		ddi_fm_dma_err_get_fail(handle);
		return;
	}

	errp = &((ddi_dma_impl_t *)handle)->dmai_error;

	if (errp->err_status == DDI_FM_OK) {
		if (de->fme_status != DDI_FM_OK)
			de->fme_status = DDI_FM_OK;
		return;
	}
	de->fme_status = errp->err_status;
	de->fme_ena = errp->err_ena;
	de->fme_flag = errp->err_expected;
	de->fme_dma_handle = handle;
}

void
ddi_fm_acc_err_clear_fail(ddi_acc_handle_t handle)
{
	ddi_acc_hdl_t *hp = impl_acc_hdl_get(handle);

	i_ddi_drv_ereport_post(hp->ah_dip, DVR_EVER, NULL, DDI_NOSLEEP);
	cmn_err(CE_PANIC, "ddi_fm_acc_err_clear: Invalid driver version\n");
}

void
ddi_fm_acc_err_clear(ddi_acc_handle_t handle, int version)
{
	ndi_err_t *errp;

	if (handle == NULL)
		return;

	if (version != DDI_FME_VER0 && version != DDI_FME_VER1) {
		ddi_fm_acc_err_clear_fail(handle);
		return;
	}

	errp = ((ddi_acc_impl_t *)handle)->ahi_err;
	errp->err_status = DDI_FM_OK;
	errp->err_ena = 0;
	errp->err_expected = DDI_FM_ERR_UNEXPECTED;
}

void
ddi_fm_dma_err_clear_fail(ddi_dma_handle_t handle)
{
	i_ddi_drv_ereport_post(((ddi_dma_impl_t *)handle)->dmai_rdip,
	    DVR_EVER, NULL, DDI_NOSLEEP);
	cmn_err(CE_PANIC, "ddi_fm_dma_err_clear: Invalid driver version\n");
}

void
ddi_fm_dma_err_clear(ddi_dma_handle_t handle, int version)
{
	ndi_err_t *errp;

	if (handle == NULL)
		return;

	if (version != DDI_FME_VER0 && version != DDI_FME_VER1) {
		ddi_fm_dma_err_clear_fail(handle);
		return;
	}

	errp = &((ddi_dma_impl_t *)handle)->dmai_error;

	errp->err_status = DDI_FM_OK;
	errp->err_ena = 0;
	errp->err_expected = DDI_FM_ERR_UNEXPECTED;
}

void
i_ddi_fm_acc_err_set(ddi_acc_handle_t handle, uint64_t ena, int status,
    int flag)
{
	ddi_acc_hdl_t *hdlp = impl_acc_hdl_get(handle);
	ddi_acc_impl_t *i_hdlp = (ddi_acc_impl_t *)handle;
	struct i_ddi_fmhdl *fmhdl = DEVI(hdlp->ah_dip)->devi_fmhdl;

	i_hdlp->ahi_err->err_ena = ena;
	i_hdlp->ahi_err->err_status = status;
	i_hdlp->ahi_err->err_expected = flag;
	atomic_inc_64(&fmhdl->fh_kstat.fek_acc_err.value.ui64);
}

void
i_ddi_fm_dma_err_set(ddi_dma_handle_t handle, uint64_t ena, int status,
    int flag)
{
	ddi_dma_impl_t *hdlp = (ddi_dma_impl_t *)handle;
	struct i_ddi_fmhdl *fmhdl = DEVI(hdlp->dmai_rdip)->devi_fmhdl;

	hdlp->dmai_error.err_ena = ena;
	hdlp->dmai_error.err_status = status;
	hdlp->dmai_error.err_expected = flag;
	atomic_inc_64(&fmhdl->fh_kstat.fek_dma_err.value.ui64);
}

ddi_fmcompare_t
i_ddi_fm_acc_err_cf_get(ddi_acc_handle_t handle)
{
	ddi_acc_impl_t *i_hdlp = (ddi_acc_impl_t *)handle;

	return (i_hdlp->ahi_err->err_cf);
}

ddi_fmcompare_t
i_ddi_fm_dma_err_cf_get(ddi_dma_handle_t handle)
{
	ddi_dma_impl_t *hdlp = (ddi_dma_impl_t *)handle;

	return (hdlp->dmai_error.err_cf);
}
