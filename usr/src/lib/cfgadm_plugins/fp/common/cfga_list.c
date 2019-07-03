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


#include "cfga_fp.h"
#include <sys/fibre-channel/impl/fc_error.h>

/* Structure for walking the tree */
typedef struct {
	apid_t		*apidp;
	char		*xport_logp;
	ldata_list_t	*listp;
	fpcfga_cmd_t	cmd;
	cfga_stat_t	chld_config;
	cfga_type_t	xport_type;
	cfga_stat_t	xport_rstate;
	fpcfga_ret_t	ret;
	int		l_errno;
} fpcfga_list_t;

typedef struct {
	uint_t itype;
	const char *ntype;
	const char *name;
} fpcfga_devtype_t;

#define	ERR_INQ_DTYPE	0xff

/* The TYPE field is parseable and should not contain spaces */
#define	FP_FC_PORT_TYPE		"fc"
#define	FP_FC_PORT_ERROR	"fc-error"
#define	FP_FC_FABRIC_PORT_TYPE	"fc-fabric"
#define	FP_FC_PUBLIC_PORT_TYPE	"fc-public"
#define	FP_FC_PRIVATE_PORT_TYPE	"fc-private"
#define	FP_FC_PT_TO_PT_PORT_TYPE	"fc-pt_to_pt"

/* Indicates no plag passing */
#define	NO_FLAG			0

/* defines for retry algorithm */
#define	OPEN_RETRY_COUNT	5
#define	OPEN_RETRY_INTERVAL	10000 /* 1/100 of a sec. */
#define	IOCTL_RETRY_COUNT	5
#define	IOCTL_RETRY_INTERVAL	5000000 /* 5 sec */

/* define for fcp scsi passthru wait */
#define	FCP_SCSI_CMD_TIMEOUT	10

/* define for fcp pseudo node */
#define	FCP_PATH	"/devices/pseudo/fcp@0:fcp"

/* Function prototypes */
static fpcfga_ret_t postprocess_list_data(const ldata_list_t *listp,
    fpcfga_cmd_t cmd, cfga_stat_t chld_config, int *np, uint_t flags);
static int stat_fc_dev(di_node_t node, void *arg);
static int stat_FCP_dev(di_node_t node, void *arg);
static fpcfga_ret_t do_stat_fca_xport(fpcfga_list_t *lap, int limited_stat,
	HBA_PORTATTRIBUTES portAttrs);
static int get_xport_state(di_node_t node, void *arg);

static fpcfga_ret_t do_stat_fc_dev(const di_node_t node, const char *nodepath,
    fpcfga_list_t *lap, int limited_stat);
static fpcfga_ret_t do_stat_FCP_dev(const di_node_t node, const char *nodepath,
    fpcfga_list_t *lap, int limited_stat);
static cfga_stat_t xport_devinfo_to_recep_state(uint_t xport_di_state);
static cfga_stat_t dev_devinfo_to_occupant_state(uint_t dev_di_state);
static void get_hw_info(di_node_t node, cfga_list_data_t *clp);
static const char *get_device_type(di_node_t);
static fpcfga_ret_t init_ldata_for_accessible_dev(const char *dyncomp,
	uchar_t inq_type, fpcfga_list_t *lap);
static fpcfga_ret_t init_ldata_for_accessible_FCP_dev(const char *port_wwn,
	int num_luns, struct report_lun_resp *resp_buf,
	fpcfga_list_t *larg, int *l_errnop);
static fpcfga_ret_t is_dyn_ap_on_ldata_list(const char *port_wwn,
	const ldata_list_t *listp, ldata_list_t **matchldpp, int *l_errno);
static fpcfga_ret_t is_FCP_dev_ap_on_ldata_list(const char *port_wwn,
	const int lun_num, ldata_list_t *ldatap, ldata_list_t **matchldpp);

static fpcfga_ret_t init_ldata_for_mpath_dev(di_path_t path, char *port_wwn,
	int *l_errnop, fpcfga_list_t *lap);
static fpcfga_ret_t insert_ldata_to_ldatalist(const char *port_wwn,
	int *lun_nump, ldata_list_t *listp, ldata_list_t **ldatapp);
static fpcfga_ret_t insert_fc_dev_ldata(const char *port_wwn,
	ldata_list_t *listp, ldata_list_t **ldatapp);
static fpcfga_ret_t insert_FCP_dev_ldata(const char *port_wwn, int lun_num,
	ldata_list_t *listp, ldata_list_t **ldatapp);
static int stat_path_info_fc_dev(di_node_t root, fpcfga_list_t	*lap,
	int *l_errnop);
static int stat_path_info_FCP_dev(di_node_t root, fpcfga_list_t	*lap,
	int *l_errnop);
static fpcfga_ret_t get_accessible_FCP_dev_ldata(const char *dyncomp,
	fpcfga_list_t *lap, int *l_errnop);
static fpcfga_ret_t get_standard_inq_data(const char *xport_phys,
	const char *dyncomp, uchar_t *lun_num, struct scsi_inquiry **inq_buf,
	int *l_errnop);
static void init_fcp_scsi_cmd(struct fcp_scsi_cmd *fscsi, uchar_t *lun_num,
	la_wwn_t *pwwn, void *scmdbuf, size_t scmdbuf_len, void *respbuf,
	size_t respbuf_len, void *sensebuf, size_t sensebuf_len);
static fpcfga_ret_t issue_fcp_scsi_cmd(const char *xport_phys,
	struct fcp_scsi_cmd *fscsi, int *l_errnop);
static uchar_t get_inq_dtype(char *xport_phys, char *dyncomp, HBA_HANDLE handle,
    HBA_PORTATTRIBUTES *portAttrs, HBA_PORTATTRIBUTES *discPortAttrs);

static fpcfga_devtype_t device_list[] = {
	{ DTYPE_DIRECT,		DDI_NT_BLOCK_CHAN,	"disk"},
	{ DTYPE_DIRECT,		DDI_NT_BLOCK,		"disk"},
	{ DTYPE_DIRECT,		DDI_NT_BLOCK_WWN,	"disk"},
	{ DTYPE_DIRECT,		DDI_NT_BLOCK_FABRIC,	"disk"},
	{ DTYPE_SEQUENTIAL,	DDI_NT_TAPE,		"tape"},
	{ DTYPE_PRINTER,	NULL,			"printer"},
	{ DTYPE_PROCESSOR,	NULL,			"processor"},
	{ DTYPE_WORM,		NULL,			"WORM"},
	{ DTYPE_RODIRECT,	DDI_NT_CD_CHAN,		"CD-ROM"},
	{ DTYPE_RODIRECT,	DDI_NT_CD,		"CD-ROM"},
	{ DTYPE_SCANNER,	NULL,			"scanner"},
	{ DTYPE_OPTICAL,	NULL,			"optical"},
	{ DTYPE_CHANGER,	NULL,			"med-changer"},
	{ DTYPE_COMM,		NULL,			"comm-device"},
	{ DTYPE_ARRAY_CTRL,	NULL,			"array-ctrl"},
	{ DTYPE_ESI,		NULL,			"ESI"},
	/*
	 * This has to be the LAST entry for DTYPE_UNKNOWN_INDEX.
	 * Add entries before this.
	 */
	{ DTYPE_UNKNOWN,	NULL,			"unknown"}
};

#define	N_DEVICE_TYPES	(sizeof (device_list) / sizeof (device_list[0]))

#define	DTYPE_UNKNOWN_INDEX	(N_DEVICE_TYPES - 1)

/*
 * Main routine for list operation.
 * It calls various routines to consturct ldata list and
 * postprocess the list data.
 *
 * Overall algorithm:
 * Get the device list on input hba port and construct ldata list for
 * accesible devices.
 * Stat hba port and devices through walking the device tree.
 * Verify the validity of the list data.
 */
fpcfga_ret_t
do_list(
	apid_t *apidp,
	fpcfga_cmd_t cmd,
	ldata_list_t **llpp,
	int *nelemp,
	char **errstring)
{
	int		n = -1, l_errno = 0, limited_stat;
	walkarg_t	walkarg;
	fpcfga_list_t	larg = {NULL};
	fpcfga_ret_t	ret;
	la_wwn_t	pwwn;
	char		*dyncomp = NULL;
	HBA_HANDLE	handle;
	HBA_PORTATTRIBUTES	portAttrs;
	HBA_PORTATTRIBUTES	discPortAttrs;
	HBA_STATUS		status;
	int			portIndex, discIndex;
	int			retry;
	uchar_t			inq_dtype;

	if (*llpp != NULL || *nelemp != 0) {
		return (FPCFGA_ERR);
	}

	/* Create the hba logid (also base component of logical ap_id) */
	ret = make_xport_logid(apidp->xport_phys, &larg.xport_logp, &l_errno);
	if (ret != FPCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_LIST, 0);
		return (FPCFGA_ERR);
	}

	assert(larg.xport_logp != NULL);

	larg.cmd = cmd;
	larg.apidp = apidp;
	larg.xport_rstate = CFGA_STAT_NONE;

	if ((ret = findMatchingAdapterPort(larg.apidp->xport_phys, &handle,
	    &portIndex, &portAttrs, errstring)) != FPCFGA_OK) {
	    S_FREE(larg.xport_logp);
	    return (ret);
	}

	/*
	 * If stating a specific device, we will do limited stat on fca port.
	 * otherwise full stat on fca part is required.
	 * If stating a specific device we don't know if it exists or is
	 * configured yet.  larg.ret is set to apid noexist for do_stat_dev.
	 * otherwise larg.ret is set to ok initially.
	 */
	if (larg.cmd == FPCFGA_STAT_FC_DEV) {
		limited_stat = 1;		/* for do_stat_fca_xport */
		larg.ret = FPCFGA_APID_NOEXIST; /* for stat_fc_dev	*/
	} else {
		limited_stat = 0;		/* for do_stat_fca_xport */
		larg.ret = FPCFGA_OK;		/* for stat_fc_dev	*/
	}

	/* For all list commands, the fca port needs to be stat'ed */
	if ((ret = do_stat_fca_xport(&larg, limited_stat,
		portAttrs)) != FPCFGA_OK) {
		cfga_err(errstring, larg.l_errno, ERR_LIST, 0);
		list_free(&larg.listp);
		S_FREE(larg.xport_logp);
		HBA_CloseAdapter(handle);
		HBA_FreeLibrary();
		return (ret);
	}

#ifdef DEBUG
	if (limited_stat) {
		assert(larg.listp == NULL);
	} else {
		assert(larg.listp != NULL);
	}
#endif
	/*
	 * If stat'ing a FCA port or ALL, we have the bus stat data at
	 * this point.
	 * Assume that the bus has no configured children.
	 */
	larg.chld_config = CFGA_STAT_UNCONFIGURED;

	switch (larg.cmd) {
	case FPCFGA_STAT_FC_DEV:
		/* la_wwn_t has uchar_t raw_wwn[8] thus no need to free. */
		if (cvt_dyncomp_to_lawwn(apidp->dyncomp, &pwwn) != 0) {
			cfga_err(errstring, 0, ERR_LIST, 0);
			list_free(&larg.listp);
			S_FREE(larg.xport_logp);
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (FPCFGA_LIB_ERR);
		}
		/*
		 * if the dyncomp exists on disco ports construct list_data
		 * otherwise return FPCFGA_APID_NOEXIST.
		 */
		retry = 0;
		do {
		    status = getPortAttrsByWWN(handle,
			*((HBA_WWN *)(&pwwn)), &discPortAttrs);
		    if (status == HBA_STATUS_ERROR_STALE_DATA) {
			/* get Port Attributes again after refresh. */
			HBA_RefreshInformation(handle);
		    } else {
			break; /* either okay or some other error */
		    }
		} while (retry++ < HBA_MAX_RETRIES);

		if (status == HBA_STATUS_OK) {
			/*
			 * if dyncomp found in disco ports
			 * construct  ldata_list and return.
			 * otherwise continue to stat on dev tree with
			 * larg.ret set to access_ok which informs stat_fc_dev
			 * the existence of device on disco ports.
			 *
			 * if path is null that guatantees the node is not
			 * configured.  if node is detached the path
			 * is incomplete and not usable for further
			 * operations like uscsi_inq so take care of it here.
			 */
			inq_dtype = get_inq_dtype(apidp->xport_phys,
			    apidp->dyncomp, handle, &portAttrs, &discPortAttrs);

			if (init_ldata_for_accessible_dev(apidp->dyncomp,
				inq_dtype, &larg) != FPCFGA_OK) {
				cfga_err(errstring, larg.l_errno,
					ERR_LIST, 0);
				list_free(&larg.listp);
				S_FREE(larg.xport_logp);
				HBA_CloseAdapter(handle);
				HBA_FreeLibrary();
				return (FPCFGA_LIB_ERR);
			}
			if (apidp->lunlist == NULL) {
				n = 0;
				if (postprocess_list_data(
					larg.listp, cmd,
					larg.chld_config, &n, NO_FLAG) !=
					FPCFGA_OK) {
					cfga_err(errstring,
					larg.l_errno, ERR_LIST, 0);
					list_free(&larg.listp);
					S_FREE(larg.xport_logp);
					HBA_CloseAdapter(handle);
					HBA_FreeLibrary();
					return (FPCFGA_LIB_ERR);
				}
				*nelemp = n;
				*llpp = larg.listp;
				S_FREE(larg.xport_logp);
				HBA_CloseAdapter(handle);
				HBA_FreeLibrary();
				return (FPCFGA_OK);
			}
			larg.ret = FPCFGA_ACCESS_OK;
		} else if (status == HBA_STATUS_ERROR_ILLEGAL_WWN) {
			/*
			 * path indicates if the node exists in dev tree.
			 * if not found in dev tree return apid no exist.
			 * otherwise continue to stat with larg.ret set to
			 * apid_noexist.
			 */
			if (apidp->lunlist == NULL) {
				list_free(&larg.listp);
				S_FREE(larg.xport_logp);
				HBA_CloseAdapter(handle);
				HBA_FreeLibrary();
				return (FPCFGA_APID_NOEXIST);
			}
		} else { /* any error */
			/*
			 * path indicates if the node exists in dev tree.
			 * if not found in dev tree return lib error.
			 * otherwise continue to stat with larg.ret set to
			 * apid_noexist.
			 */
			if (apidp->lunlist == NULL) {
				cfga_err(errstring, 0, ERR_FC_GET_DEVLIST, 0);
				list_free(&larg.listp);
				S_FREE(larg.xport_logp);
				HBA_CloseAdapter(handle);
				HBA_FreeLibrary();
				return (FPCFGA_LIB_ERR);
			}
		}
		break;
	case FPCFGA_STAT_ALL:
		/*
		 * for each dev in disco ports, create a ldata_list element.
		 * if if no disco ports found, continue to stat on devinfo tree
		 * to see if any node exist on the fca port.
		 */
		for (discIndex = 0;
			discIndex < portAttrs.NumberofDiscoveredPorts;
			discIndex++) {
		    if (getDiscPortAttrs(handle, portIndex,
			discIndex, &discPortAttrs)) {
			/* Move on to the next target */
			continue;
		    }
		    memcpy(&pwwn, &discPortAttrs.PortWWN, sizeof (la_wwn_t));
		    cvt_lawwn_to_dyncomp(&pwwn, &dyncomp, &l_errno);
		    if (dyncomp == NULL) {
			cfga_err(errstring, l_errno, ERR_LIST, 0);
			list_free(&larg.listp);
			S_FREE(larg.xport_logp);
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (FPCFGA_LIB_ERR);
		    }
		    inq_dtype = get_inq_dtype(apidp->xport_phys, dyncomp,
			handle, &portAttrs, &discPortAttrs);

		    if ((ret = init_ldata_for_accessible_dev(
			    dyncomp, inq_dtype, &larg)) != FPCFGA_OK) {
			S_FREE(dyncomp);
			cfga_err(errstring, larg.l_errno, ERR_LIST, 0);
				list_free(&larg.listp);
			S_FREE(larg.xport_logp);
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (FPCFGA_LIB_ERR);
		    }
		    S_FREE(dyncomp);
		}
		break;
	default:
		break;
	}

	/* we need to stat at least 1 device for all commands */
	if (apidp->flags == FLAG_DEVINFO_FORCE) {
		walkarg.flags = FLAG_DEVINFO_FORCE;
	} else {
		walkarg.flags = 0;
	}

	walkarg.flags |= FLAG_PATH_INFO_WALK;
	walkarg.walkmode.node_args.flags = DI_WALK_CLDFIRST;
	walkarg.walkmode.node_args.fcn = stat_fc_dev;

	/*
	 * Subtree is ALWAYS rooted at the HBA (not at the device) as
	 * otherwise deadlock may occur if bus is disconnected.
	 *
	 * DINFOPROP was sufficient on apidp->xport_phys prior to the support
	 * on scsi_vhci child node.  In order to get the link between
	 * scsi_vhci node and path info node the snap shot of the
	 * the whole device tree is required with DINFOCPYALL | DINFOPATH flag.
	 */
	ret = walk_tree(apidp->xport_phys, &larg, DINFOCPYALL | DINFOPATH,
			&walkarg, FPCFGA_WALK_NODE, &larg.l_errno);

	/*
	 * ret from walk_tree is either FPCFGA_OK or FPCFGA_ERR.
	 * larg.ret is used to detect other errors. Make sure larg.ret
	 * is set to a correct error.
	 */
	if (ret != FPCFGA_OK || (ret = larg.ret) != FPCFGA_OK) {
		if (ret != FPCFGA_APID_NOEXIST) {
			cfga_err(errstring, larg.l_errno, ERR_LIST, 0);
		}
		/* if larg.ret = FPCFGA_APID_NOEXIST; */
		goto out;
	}

	assert(larg.listp != NULL);

	n = 0;
	ret = postprocess_list_data(larg.listp, cmd, larg.chld_config, &n,
		NO_FLAG);
	if (ret != FPCFGA_OK) {
		cfga_err(errstring, 0, ERR_LIST, 0);
		ret = FPCFGA_LIB_ERR;
		goto out;
	}

	*nelemp = n;
	*llpp = larg.listp;
	ret = FPCFGA_OK;
	/* FALLTHROUGH */
out:
	if (ret != FPCFGA_OK) list_free(&larg.listp);
	S_FREE(larg.xport_logp);
	HBA_CloseAdapter(handle);
	HBA_FreeLibrary();
	return (ret);
}

/*
 * Main routine for list operation when show_FCP_dev option is given.
 * It calls various routines to consturct ldata list and
 * postprocess the list data.
 *
 * The difference between do_list() and do_list_FCP_dev() is to
 * process FCP SCSI LUN data list via uscsi report lun operation and
 * stat lun level instead of port WWN based target level.
 * The rest of logic is same.
 *
 * Overall algorithm:
 * Get the device list on input hba port and construct ldata list for
 * accesible devices.
 * For each configured device, USCSI report lun is issued and ldata list
 * with FCP device level(LUN) information is created.
 * Stat hba port and LUN devices through walking the device tree.
 * Verify the validity of the list data.
 */
fpcfga_ret_t
do_list_FCP_dev(
	const char *ap_id,
	uint_t flags,
	fpcfga_cmd_t cmd,
	ldata_list_t **llpp,
	int *nelemp,
	char **errstring)
{
	int		n = -1, l_errno = 0, limited_stat, len;
	walkarg_t	walkarg;
	fpcfga_list_t	larg = {NULL};
	fpcfga_ret_t	ret;
	la_wwn_t	pwwn;
	char		*xport_phys = NULL, *dyn = NULL, *dyncomp = NULL,
			*lun_dyn = NULL;
	apid_t		apid_con = {NULL};
	HBA_HANDLE	handle;
	HBA_PORTATTRIBUTES	portAttrs;
	HBA_PORTATTRIBUTES	discPortAttrs;
	HBA_STATUS		status;
	int			portIndex, discIndex;
	int			retry;
	uint64_t		lun = 0;
	struct scsi_inquiry inq;
	struct scsi_extended_sense sense;
	HBA_UINT8		scsiStatus;
	uint32_t		inquirySize = sizeof (inq),
				senseSize = sizeof (sense);

	if (*llpp != NULL || *nelemp != 0) {
		return (FPCFGA_ERR);
	}

	if ((xport_phys = pathdup(ap_id, &l_errno)) == NULL) {
		cfga_err(errstring, l_errno, ERR_OP_FAILED, 0);
		return (FPCFGA_LIB_ERR);
	}

	/* Extract the base(hba) and dynamic(device) component if any */
	if ((dyn = GET_DYN(xport_phys)) != NULL) {
		len = strlen(DYN_TO_DYNCOMP(dyn)) + 1;
		dyncomp = calloc(1, len);
		if (dyncomp == NULL) {
			cfga_err(errstring, errno, ERR_OP_FAILED, 0);
			S_FREE(xport_phys);
			return (FPCFGA_LIB_ERR);
		}

		(void) strcpy(dyncomp, DYN_TO_DYNCOMP(dyn));
		/* Remove the dynamic component from the base. */
		*dyn = '\0';
		/* if lun dyncomp exists delete it */
		if ((lun_dyn = GET_LUN_DYN(dyncomp)) != NULL) {
			*lun_dyn = '\0';
		}
	}

	apid_con.xport_phys = xport_phys;
	apid_con.dyncomp = dyncomp;
	apid_con.flags = flags;

	larg.apidp = &apid_con;

	/* Create the hba logid (also base component of logical ap_id) */
	ret = make_xport_logid(larg.apidp->xport_phys, &larg.xport_logp,
		&l_errno);
	if (ret != FPCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_LIST, 0);
		S_FREE(larg.apidp->xport_phys);
		S_FREE(larg.apidp->dyncomp);
		return (FPCFGA_ERR);
	}

	assert(larg.xport_logp != NULL);

	larg.cmd = cmd;
	larg.xport_rstate = CFGA_STAT_NONE;

	if ((ret = findMatchingAdapterPort(larg.apidp->xport_phys, &handle,
	    &portIndex, &portAttrs, errstring)) != FPCFGA_OK) {
	    S_FREE(larg.xport_logp);
	    S_FREE(larg.apidp->dyncomp);
	    return (ret);
	}

	/*
	 * If stating a specific device, we will do limited stat on fca port.
	 * otherwise full stat on fca part is required.
	 * If stating a specific device we don't know if it exists or is
	 * configured yet.  larg.ret is set to apid noexist for do_stat_dev.
	 * otherwise larg.ret is set to ok initially.
	 */
	if (larg.cmd == FPCFGA_STAT_FC_DEV) {
		limited_stat = 1;		/* for do_stat_fca_xport */
		larg.ret = FPCFGA_APID_NOEXIST; /* for stat_fc_dev	*/
	} else {
		limited_stat = 0;		/* for do_stat_fca_xport */
		larg.ret = FPCFGA_OK;		/* for stat_fc_dev	*/
	}

	/* For all list commands, the fca port needs to be stat'ed */
	if ((ret = do_stat_fca_xport(&larg, limited_stat,
		portAttrs)) != FPCFGA_OK) {
		cfga_err(errstring, larg.l_errno, ERR_LIST, 0);
		list_free(&larg.listp);
		S_FREE(larg.xport_logp);
		S_FREE(larg.apidp->xport_phys);
		S_FREE(larg.apidp->dyncomp);
		HBA_CloseAdapter(handle);
		HBA_FreeLibrary();
		return (ret);
	}

	/*
	 * If stat'ing a FCA port or ALL, we have the bus stat data at
	 * this point.
	 * Assume that the bus has no configured children.
	 */
	larg.chld_config = CFGA_STAT_UNCONFIGURED;

	switch (larg.cmd) {
	case FPCFGA_STAT_FC_DEV:
		/* la_wwn_t has uchar_t raw_wwn[8] thus no need to free. */
		if (cvt_dyncomp_to_lawwn(larg.apidp->dyncomp, &pwwn) != 0) {
			cfga_err(errstring, 0, ERR_LIST, 0);
			list_free(&larg.listp);
			S_FREE(larg.xport_logp);
			S_FREE(larg.apidp->xport_phys);
			S_FREE(larg.apidp->dyncomp);
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (FPCFGA_LIB_ERR);
		}
		/*
		 * if the dyncomp exists on disco ports construct list_data
		 * otherwise return FPCFGA_APID_NOEXIST.
		 */
		retry = 0;
		do {
		    status = getPortAttrsByWWN(handle,
			*((HBA_WWN *)(&pwwn)), &discPortAttrs);
		    if (status == HBA_STATUS_ERROR_STALE_DATA) {
			/* get Port Attributes again after refresh. */
			HBA_RefreshInformation(handle);
		    } else {
			break; /* either okay or some other error */
		    }
		} while (retry++ < HBA_MAX_RETRIES);

		if (status == HBA_STATUS_OK) {
			/*
			 * if dyncomp exists only in dev list
			 * construct  ldata_list and return.
			 * otherwise continue to stat on dev tree with
			 * larg.ret set to access_ok which informs stat_fc_dev
			 * the existence of device on dev_list.
			 *
			 * if path is null that guatantees the node is not
			 * configured.  if node is detached the path
			 * is incomplete and not usable for further
			 * operations like uscsi_inq so take care of it here.
			 */
			status = HBA_ScsiInquiryV2(handle, portAttrs.PortWWN,
				    discPortAttrs.PortWWN, lun, 0, 0,
				    &inq, &inquirySize, &scsiStatus,
				    &sense, &senseSize);
			if (status == HBA_STATUS_OK) {
				inq.inq_dtype = inq.inq_dtype & DTYPE_MASK;
			} else if (status == HBA_STATUS_ERROR_NOT_A_TARGET) {
				inq.inq_dtype = DTYPE_UNKNOWN;
			} else {
			    inq.inq_dtype = ERR_INQ_DTYPE;
			}

			if (init_ldata_for_accessible_dev(larg.apidp->dyncomp,
				inq.inq_dtype, &larg) != FPCFGA_OK) {
				cfga_err(errstring, larg.l_errno,
					ERR_LIST, 0);
				list_free(&larg.listp);
				S_FREE(larg.xport_logp);
				S_FREE(larg.apidp->xport_phys);
				S_FREE(larg.apidp->dyncomp);
				HBA_CloseAdapter(handle);
				HBA_FreeLibrary();
				return (FPCFGA_LIB_ERR);
			}
			if ((ret = get_accessible_FCP_dev_ldata(
					larg.apidp->dyncomp, &larg, &l_errno))
					!= FPCFGA_OK) {
				cfga_err(errstring, larg.l_errno, ERR_LIST, 0);
				list_free(&larg.listp);
				S_FREE(larg.xport_logp);
				S_FREE(larg.apidp->xport_phys);
				S_FREE(larg.apidp->dyncomp);
				HBA_CloseAdapter(handle);
				HBA_FreeLibrary();
				return (FPCFGA_LIB_ERR);
			} else {
				/* continue to stat dev with access okay. */
				larg.ret = FPCFGA_ACCESS_OK;
			}
		} else if (status == HBA_STATUS_ERROR_ILLEGAL_WWN) {
			/*
			 * path indicates if the node exists in dev tree.
			 * if not found in dev tree return apid no exist.
			 * otherwise continue to stat with larg.ret set to
			 * apid_noexist.
			 */
			if (larg.apidp->lunlist == NULL) {
				list_free(&larg.listp);
				S_FREE(larg.xport_logp);
				HBA_CloseAdapter(handle);
				HBA_FreeLibrary();
				return (FPCFGA_APID_NOEXIST);
			}
		} else {	/* not found or any error */
			/*
			 * continue to stat dev with larg.ret set to
			 * apid_noexist.
			 */
			larg.ret = FPCFGA_APID_NOEXIST;
		}
		break;
	case FPCFGA_STAT_ALL:
		/*
		 * for each dev in disco ports, create a ldata_list element.
		 * if if no disco ports found, continue to stat on devinfo tree
		 * to see if any node exist on the fca port.
		 */
		for (discIndex = 0;
			discIndex < portAttrs.NumberofDiscoveredPorts;
			discIndex++) {
		    if (getDiscPortAttrs(handle, portIndex,
			discIndex, &discPortAttrs)) {
			/* Move on to the next target */
			continue;
		    }
		    memcpy(&pwwn, &discPortAttrs.PortWWN, sizeof (la_wwn_t));
		    cvt_lawwn_to_dyncomp(&pwwn, &dyncomp, &l_errno);
		    if (dyncomp == NULL) {
			cfga_err(errstring, l_errno, ERR_LIST, 0);
			list_free(&larg.listp);
			S_FREE(larg.xport_logp);
			S_FREE(larg.apidp->xport_phys);
			S_FREE(larg.apidp->dyncomp);
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (FPCFGA_LIB_ERR);
		    }
		    status = HBA_ScsiInquiryV2(handle, portAttrs.PortWWN,
			    discPortAttrs.PortWWN, lun, 0, 0,
			    &inq, &inquirySize, &scsiStatus,
			    &sense, &senseSize);
		    if (status == HBA_STATUS_OK) {
			    inq.inq_dtype = inq.inq_dtype & DTYPE_MASK;
		    } else if (status == HBA_STATUS_ERROR_NOT_A_TARGET) {
			    inq.inq_dtype = DTYPE_UNKNOWN;
		    } else {
			    inq.inq_dtype = ERR_INQ_DTYPE;
		    }
		    if ((ret = init_ldata_for_accessible_dev(
			    dyncomp, inq.inq_dtype, &larg)) != FPCFGA_OK) {
			S_FREE(dyncomp);
			cfga_err(errstring, larg.l_errno, ERR_LIST, 0);
			list_free(&larg.listp);
			S_FREE(larg.xport_logp);
			S_FREE(larg.apidp->xport_phys);
			S_FREE(larg.apidp->dyncomp);
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (FPCFGA_LIB_ERR);
		    }
		    if ((ret = get_accessible_FCP_dev_ldata(
			dyncomp, &larg, &l_errno)) != FPCFGA_OK) {
			S_FREE(dyncomp);
			cfga_err(errstring, larg.l_errno, ERR_LIST, 0);
			list_free(&larg.listp);
			S_FREE(larg.xport_logp);
			S_FREE(larg.apidp->xport_phys);
			S_FREE(larg.apidp->dyncomp);
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (ret);
		    }
		    S_FREE(dyncomp);
		}
		break;
	/* default: continue */
	}

	/* we need to stat at least 1 device for all commands */
	if ((larg.apidp->flags & FLAG_DEVINFO_FORCE) == FLAG_DEVINFO_FORCE) {
		walkarg.flags = FLAG_DEVINFO_FORCE;
	} else {
		walkarg.flags = 0;
	}

	walkarg.flags |= FLAG_PATH_INFO_WALK;
	walkarg.walkmode.node_args.flags = DI_WALK_CLDFIRST;
	walkarg.walkmode.node_args.fcn = stat_FCP_dev;

	/*
	 * Subtree is ALWAYS rooted at the HBA (not at the device) as
	 * otherwise deadlock may occur if bus is disconnected.
	 *
	 * DINFOPROP was sufficient on apidp->xport_phys prior to the support
	 * on scsi_vhci child node.  In order to get the link between
	 * scsi_vhci node and path info node the snap shot of the
	 * the whole device tree is required with DINFOCPYALL | DINFOPATH flag.
	 */
	ret = walk_tree(larg.apidp->xport_phys, &larg, DINFOCPYALL | DINFOPATH,
			&walkarg, FPCFGA_WALK_NODE, &larg.l_errno);

	/*
	 * ret from walk_tree is either FPCFGA_OK or FPCFGA_ERR.
	 * larg.ret is used to detect other errors. Make sure larg.ret
	 * is set to a correct error.
	 */
	if (ret != FPCFGA_OK || (ret = larg.ret) != FPCFGA_OK) {
		if (ret != FPCFGA_APID_NOEXIST) {
			cfga_err(errstring, larg.l_errno, ERR_LIST, 0);
		}
		/* if larg.ret = FPCFGA_APID_NOEXIST return. */
		list_free(&larg.listp);
		S_FREE(larg.xport_logp);
		S_FREE(larg.apidp->xport_phys);
		S_FREE(larg.apidp->dyncomp);
		HBA_CloseAdapter(handle);
		HBA_FreeLibrary();
		return (ret);
	}

	assert(larg.listp != NULL);

	n = 0;
	ret = postprocess_list_data(larg.listp, cmd, larg.chld_config, &n,
			flags);
	if (ret != FPCFGA_OK) {
		cfga_err(errstring, 0, ERR_LIST, 0);
		list_free(&larg.listp);
		S_FREE(larg.xport_logp);
		S_FREE(larg.apidp->xport_phys);
		S_FREE(larg.apidp->dyncomp);
		HBA_CloseAdapter(handle);
		HBA_FreeLibrary();
		return (FPCFGA_LIB_ERR);
	}

	*nelemp = n;
	*llpp = larg.listp;
	ret = FPCFGA_OK;
	S_FREE(larg.xport_logp);
	S_FREE(larg.apidp->xport_phys);
	S_FREE(larg.apidp->dyncomp);
	HBA_CloseAdapter(handle);
	HBA_FreeLibrary();
	return (FPCFGA_OK);
}

/*
 * This routine returns initialize struct fcp_ioctl.
 */
static void
init_fcp_scsi_cmd(
	struct fcp_scsi_cmd *fscsi,
	uchar_t *lun_num,
	la_wwn_t *pwwn,
	void *scmdbuf,
	size_t scmdbuf_len,
	void *respbuf,
	size_t respbuf_len,
	void *sensebuf,
	size_t sensebuf_len)
{
	memset(fscsi, 0, sizeof (struct fcp_scsi_cmd));
	memset(scmdbuf, 0, scmdbuf_len);
	memcpy(fscsi->scsi_fc_pwwn.raw_wwn, pwwn, sizeof (u_longlong_t));
	fscsi->scsi_fc_rspcode = 0;
	fscsi->scsi_flags = FCP_SCSI_READ;
	fscsi->scsi_timeout = FCP_SCSI_CMD_TIMEOUT;  /* second */
	fscsi->scsi_cdbbufaddr = (caddr_t)scmdbuf;
	fscsi->scsi_cdblen = scmdbuf_len;
	fscsi->scsi_bufaddr = (caddr_t)respbuf;
	fscsi->scsi_buflen = respbuf_len;
	fscsi->scsi_bufresid = 0;
	fscsi->scsi_bufstatus = 0;
	fscsi->scsi_rqbufaddr = (caddr_t)sensebuf;
	fscsi->scsi_rqlen = sensebuf_len;
	fscsi->scsi_rqresid = 0;
	memcpy(&fscsi->scsi_lun, lun_num, sizeof (fscsi->scsi_lun));
}

/*
 * This routine returns issues FCP_TGT_SEND_SCSI
 */
static fpcfga_ret_t
issue_fcp_scsi_cmd(
	const char *xport_phys,
	struct fcp_scsi_cmd *fscsi,
	int *l_errnop)
{
	struct stat	stbuf;
	int fcp_fd, retry, rv;

	if (stat(xport_phys, &stbuf) < 0) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	fscsi->scsi_fc_port_num = (uint32_t)minor(stbuf.st_rdev);
	fcp_fd = open(FCP_PATH, O_RDONLY | O_NDELAY);
	retry = 0;
	while (fcp_fd < 0 && retry++ < OPEN_RETRY_COUNT && (
		errno == EBUSY || errno == EAGAIN)) {
		(void) usleep(OPEN_RETRY_INTERVAL);
		fcp_fd = open(FCP_PATH, O_RDONLY|O_NDELAY);
	}
	if (fcp_fd < 0) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	rv = ioctl(fcp_fd, FCP_TGT_SEND_SCSI, fscsi);
	retry = 0;
	while ((rv != 0 && retry++ < IOCTL_RETRY_COUNT &&
			(errno == EBUSY || errno == EAGAIN)) ||
			(retry++ < IOCTL_RETRY_COUNT &&
			((uchar_t)fscsi->scsi_bufstatus & STATUS_MASK)
			== STATUS_BUSY)) {
		(void) usleep(IOCTL_RETRY_INTERVAL);
		rv = ioctl(fcp_fd, FCP_TGT_SEND_SCSI, fscsi);
	}
	close(fcp_fd);

	if (fscsi->scsi_fc_status == FC_DEVICE_NOT_TGT) {
		return (FPCFGA_FCP_SEND_SCSI_DEV_NOT_TGT);
	} else if (rv != 0 || fscsi->scsi_bufstatus != 0) {
		*l_errnop = errno;
		return (FPCFGA_FCP_TGT_SEND_SCSI_FAILED);
	}
	return (FPCFGA_OK);
}

/*
 * This routine returns standard inq data for
 * a target represented by dyncomp.
 *
 * Calls FCP passthru ioctl FCP_TGT_SEND_SCSI to get inquiry data.
 *
 * Caller should free the *inq_buf.
 */
static fpcfga_ret_t
get_standard_inq_data(
	const char *xport_phys,
	const char *dyncomp,
	uchar_t *lun_num,
	struct scsi_inquiry **inq_buf,
	int *l_errnop)
{
	struct fcp_scsi_cmd	fscsi;
	struct scsi_extended_sense sensebuf;
	union scsi_cdb  scsi_inq_req;
	la_wwn_t	pwwn;
	int 	alloc_len;
	fpcfga_ret_t ret;


	alloc_len = sizeof (struct scsi_inquiry);
	if ((*inq_buf = (struct scsi_inquiry *)calloc(1, alloc_len)) == NULL) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	if (cvt_dyncomp_to_lawwn(dyncomp, &pwwn) != 0) {
		return (FPCFGA_LIB_ERR);
	}

	init_fcp_scsi_cmd(&fscsi, lun_num, &pwwn, &scsi_inq_req,
		sizeof (scsi_inq_req), *inq_buf, alloc_len, &sensebuf,
		sizeof (struct scsi_extended_sense));
	scsi_inq_req.scc_cmd = SCMD_INQUIRY;
	scsi_inq_req.g0_count0 = sizeof (struct scsi_inquiry);

	if ((ret = issue_fcp_scsi_cmd(xport_phys, &fscsi, l_errnop))
			!= FPCFGA_OK) {
		S_FREE(*inq_buf);
		return (ret);
	}

	return (FPCFGA_OK);
}

/*
 * This routine returns report lun data and number of luns found
 * on a target represented by dyncomp.
 *
 * Calls FCP passthru ioctl FCP_TGT_SEND_SCSI to get report lun data.
 *
 * Caller should free the *resp_buf when FPCFGA_OK is returned.
 */
fpcfga_ret_t
get_report_lun_data(
	const char *xport_phys,
	const char *dyncomp,
	int *num_luns,
	report_lun_resp_t **resp_buf,
	struct scsi_extended_sense *sensebuf,
	int *l_errnop)
{
	struct fcp_scsi_cmd	fscsi;
	union scsi_cdb  scsi_rl_req;
	la_wwn_t	pwwn;
	int 	alloc_len;
	fpcfga_ret_t 	ret;
	uchar_t		lun_data[SAM_LUN_SIZE];

	alloc_len = sizeof (struct report_lun_resp);
	if ((*resp_buf = (report_lun_resp_t *)calloc(1, alloc_len)) == NULL) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	if (cvt_dyncomp_to_lawwn(dyncomp, &pwwn) != 0) {
		S_FREE(*resp_buf);
		return (FPCFGA_LIB_ERR);
	}

	/* sending to LUN 0 so initializing lun_data buffer to be 0 */
	memset(lun_data, 0, sizeof (lun_data));
	init_fcp_scsi_cmd(&fscsi, lun_data, &pwwn, &scsi_rl_req,
	    sizeof (scsi_rl_req), *resp_buf, alloc_len, sensebuf,
	    sizeof (struct scsi_extended_sense));
	scsi_rl_req.scc_cmd = FP_SCMD_REPORT_LUN;
	FORMG5COUNT(&scsi_rl_req, alloc_len);

	if ((ret = issue_fcp_scsi_cmd(xport_phys, &fscsi, l_errnop))
			!= FPCFGA_OK) {
		S_FREE(*resp_buf);
		return (ret);
	}

	if (ntohl((*resp_buf)->num_lun) >
		(sizeof (struct report_lun_resp) - REPORT_LUN_HDR_SIZE)) {
		alloc_len = (*resp_buf)->num_lun + REPORT_LUN_HDR_SIZE;
		S_FREE(*resp_buf);
		if ((*resp_buf = (report_lun_resp_t *)calloc(1, alloc_len))
		    == NULL) {
			*l_errnop = errno;
			return (FPCFGA_LIB_ERR);
		}
		(void) memset((char *)*resp_buf, 0, alloc_len);
		FORMG5COUNT(&scsi_rl_req, alloc_len);

		fscsi.scsi_bufaddr = (caddr_t)*resp_buf;
		fscsi.scsi_buflen = alloc_len;

		if ((ret = issue_fcp_scsi_cmd(xport_phys, &fscsi, l_errnop))
				!= FPCFGA_OK) {
			S_FREE(*resp_buf);
			return (ret);
		}
	}

	/* num_lun represent number of luns * 8. */
	*num_luns = ntohl((*resp_buf)->num_lun) >> 3;

	return (FPCFGA_OK);
}

/*
 * Routine for consturct ldata list for each FCP SCSI LUN device
 * for a discovered target device.
 * It calls get_report_lun_data to get report lun data and
 * construct ldata list per each lun.
 *
 * It is called only when show_FCP_dev option is given.
 *
 * Overall algorithm:
 * Get the report lun data thru FCP passthru ioctl.
 * Call init_ldata_for_accessible_FCP_dev to process the report LUN data.
 * For each LUN found standard inquiry is issued to get device type.
 */
static fpcfga_ret_t
get_accessible_FCP_dev_ldata(
	const char *dyncomp,
	fpcfga_list_t *lap,
	int *l_errnop)
{
	report_lun_resp_t	    *resp_buf;
	struct scsi_extended_sense  sense;
	int			    num_luns;
	fpcfga_ret_t		    ret;

	memset(&sense, 0, sizeof (sense));
	if ((ret = get_report_lun_data(lap->apidp->xport_phys, dyncomp,
		&num_luns, &resp_buf, &sense, l_errnop)) != FPCFGA_OK) {
		/*
		 * when report lun data fails then return FPCFGA_OK thus
		 * keep the ldata for the target which is acquired previously.
		 * For remote hba node this will be normal.
		 * For a target error may already be detected through
		 * FCP_TGT_INQ.
		 */
		if ((ret == FPCFGA_FCP_TGT_SEND_SCSI_FAILED) ||
		    (ret == FPCFGA_FCP_SEND_SCSI_DEV_NOT_TGT)) {
			ret = FPCFGA_OK;
		}
		return (ret);
	}

	if (num_luns > 0) {
		ret = init_ldata_for_accessible_FCP_dev(
			dyncomp, num_luns, resp_buf, lap, l_errnop);
	} else {
		/*
		 * proceed with to stat if no lun found.
		 * This will make the target apid will be kept.
		 */
		ret = FPCFGA_OK;
	}

	S_FREE(resp_buf);
	return (ret);
}

/*
 * Routine for checking validity of ldata list based on input argumemnt.
 * Set the occupant state of hba port if the list is valid.
 */
static fpcfga_ret_t
postprocess_list_data(
	const ldata_list_t *listp,
	fpcfga_cmd_t cmd,
	cfga_stat_t chld_config,
	int *np,
	uint_t flags)
{
	ldata_list_t *tmplp = NULL;
	cfga_list_data_t *xport_ldatap = NULL;
	int i;


	*np = 0;

	if (listp == NULL) {
		return (FPCFGA_ERR);
	}

	tmplp = (ldata_list_t *)listp;
	for (i = 0; tmplp != NULL; tmplp = tmplp->next) {
		i++;
		if (GET_DYN(tmplp->ldata.ap_phys_id) == NULL) {
			/* A bus stat data */
			assert(GET_DYN(tmplp->ldata.ap_log_id) == NULL);
			xport_ldatap = &tmplp->ldata;
#ifdef DEBUG
		} else {
			assert(GET_DYN(tmplp->ldata.ap_log_id) != NULL);
#endif
		}
	}

	switch (cmd) {
	case FPCFGA_STAT_FC_DEV:
		if ((flags & FLAG_FCP_DEV) == FLAG_FCP_DEV) {
			if (i < 1 || xport_ldatap != NULL) {
				return (FPCFGA_LIB_ERR);
			}
		} else {
			if (i != 1 || xport_ldatap != NULL) {
				return (FPCFGA_LIB_ERR);
			}
		}
		break;
	case FPCFGA_STAT_FCA_PORT:
		if (i != 1 || xport_ldatap == NULL) {
			return (FPCFGA_LIB_ERR);
		}
		break;
	case FPCFGA_STAT_ALL:
		if (i < 1 || xport_ldatap == NULL) {
			return (FPCFGA_LIB_ERR);
		}
		break;
	default:
		return (FPCFGA_LIB_ERR);
	}

	*np = i;

	/* Fill in the occupant (child) state. */
	if (xport_ldatap != NULL) {
		xport_ldatap->ap_o_state = chld_config;
	}
	return (FPCFGA_OK);
}

/*
 * Routine for checking each target device found in device tree.
 * When the matching port WWN dev is found from the accessble ldata list
 * the target device is updated with configured ostate.
 *
 * Overall algorithm:
 * Parse the device tree to find configured devices which matches with
 * list argument.  If cmd is stat on a specific target device it
 * matches port WWN and continues to further processing.  If cmd is
 * stat on hba port all the device target under the hba are processed.
 */
static int
stat_fc_dev(di_node_t node, void *arg)
{
	fpcfga_list_t *lap = NULL;
	char *devfsp = NULL, *nodepath = NULL;
	size_t len = 0;
	int limited_stat = 0, match_minor, rv;
	fpcfga_ret_t ret;
	di_prop_t prop = DI_PROP_NIL;
	uchar_t	*port_wwn_data;
	char	port_wwn[WWN_SIZE*2+1];
	int	count;

	lap = (fpcfga_list_t *)arg;

	/*
	 * Skip partial nodes
	 *
	 * This checking is from the scsi plug-in and will be deleted for
	 * fp plug-in. The node will be processed for fp even if it is
	 * in driver detached state. From fp perspective the node is configured
	 * as long as the node is not in offline or down state.
	 * scsi plug-in considers the known state when it is offlined
	 * regradless of driver detached state or when it is not in driver
	 * detached state like normal state.
	 * If the node is only in driver detached state it is considered as
	 * unknown state.
	 *
	 * if (!known_state(node) && (lap->cmd != FPCFGA_STAT_FC_DEV)) {
	 *	return (DI_WALK_CONTINUE);
	 *
	 */

	devfsp = di_devfs_path(node);
	if (devfsp == NULL) {
		rv = DI_WALK_CONTINUE;
		goto out;
	}

	len = strlen(DEVICES_DIR) + strlen(devfsp) + 1;

	nodepath = calloc(1, len);
	if (nodepath == NULL) {
		lap->l_errno = errno;
		lap->ret = FPCFGA_LIB_ERR;
		rv = DI_WALK_TERMINATE;
		goto out;
	}

	(void) snprintf(nodepath, len, "%s%s", DEVICES_DIR, devfsp);

	/* Skip node if it is HBA */
	match_minor = 0;
	if (!dev_cmp(lap->apidp->xport_phys, nodepath, match_minor)) {
		rv = DI_WALK_CONTINUE;
		goto out;
	}

	/* If stat'ing a specific device, is this node that device */
	if (lap->cmd == FPCFGA_STAT_FC_DEV) {
		/* checks port wwn property to find a match */
		while ((prop = di_prop_next(node, prop))
					!= DI_PROP_NIL) {
			if ((strcmp(PORT_WWN_PROP,
				di_prop_name(prop)) == 0) &&
				(di_prop_type(prop) ==
					DI_PROP_TYPE_BYTE)) {
				break;
			}
		}

		if (prop != DI_PROP_NIL) {
			count = di_prop_bytes(prop, &port_wwn_data);
			if (count != WWN_SIZE) {
				lap->ret = FPCFGA_LIB_ERR;
				rv = DI_WALK_TERMINATE;
				goto out;
			}
			(void) sprintf(port_wwn, "%016llx",
				(wwnConversion(port_wwn_data)));
			/*
			 * port wwn doesn't match contine to walk
			 * if match call do_stat_fc_dev.
			 */
			if (strncmp(port_wwn, lap->apidp->dyncomp,
					WWN_SIZE*2)) {
				rv = DI_WALK_CONTINUE;
				goto out;
			}
		} else {
			rv = DI_WALK_CONTINUE;
			goto out;
		}
	}

	/*
	 * If stat'ing a xport only, we look at device nodes only to get
	 * xport configuration status. So a limited stat will suffice.
	 */
	if (lap->cmd == FPCFGA_STAT_FCA_PORT) {
		limited_stat = 1;
	} else {
		limited_stat = 0;
	}

	/*
	 * Ignore errors if stat'ing a bus or listing all
	 */
	ret = do_stat_fc_dev(node, nodepath, lap, limited_stat);
	if (ret != FPCFGA_OK) {
		if (lap->cmd == FPCFGA_STAT_FC_DEV) {
			lap->ret = ret;
			rv = DI_WALK_TERMINATE;
		} else {
			rv = DI_WALK_CONTINUE;
		}
		goto out;
	}

	/* Are we done ? */
	rv = DI_WALK_CONTINUE;
	if (lap->cmd == FPCFGA_STAT_FCA_PORT &&
	    lap->chld_config == CFGA_STAT_CONFIGURED) {
		rv = DI_WALK_TERMINATE;
	} else if (lap->cmd == FPCFGA_STAT_FC_DEV) {
		/*
		 * If stat'ing a specific device, we are done at this point.
		 */
		rv = DI_WALK_TERMINATE;
	}

	/*FALLTHRU*/
out:
	S_FREE(nodepath);
	if (devfsp != NULL) di_devfs_path_free(devfsp);
	return (rv);
}

/*
 * Routine for checking each FCP SCSI LUN device found in device tree.
 * When the matching port WWN and LUN are found from the accessble ldata list
 * the FCP SCSI LUN is updated with configured ostate.
 *
 * Overall algorithm:
 * Parse the device tree to find configured devices which matches with
 * list argument.  If cmd is stat on a specific target device it
 * matches port WWN and continues to further processing.  If cmd is
 * stat on hba port all the FCP SCSI LUN under the hba are processed.
 */
static int
stat_FCP_dev(di_node_t node, void *arg)
{
	fpcfga_list_t *lap = NULL;
	char *devfsp = NULL, *nodepath = NULL;
	size_t len = 0;
	int limited_stat = 0, match_minor, rv, di_ret;
	fpcfga_ret_t ret;
	uchar_t	*port_wwn_data;
	char	port_wwn[WWN_SIZE*2+1];

	lap = (fpcfga_list_t *)arg;

	devfsp = di_devfs_path(node);
	if (devfsp == NULL) {
		rv = DI_WALK_CONTINUE;
		goto out;
	}

	len = strlen(DEVICES_DIR) + strlen(devfsp) + 1;

	nodepath = calloc(1, len);
	if (nodepath == NULL) {
		lap->l_errno = errno;
		lap->ret = FPCFGA_LIB_ERR;
		rv = DI_WALK_TERMINATE;
		goto out;
	}

	(void) snprintf(nodepath, len, "%s%s", DEVICES_DIR, devfsp);

	/* Skip node if it is HBA */
	match_minor = 0;
	if (!dev_cmp(lap->apidp->xport_phys, nodepath, match_minor)) {
		rv = DI_WALK_CONTINUE;
		goto out;
	}

	/* If stat'ing a specific device, is this node that device */
	if (lap->cmd == FPCFGA_STAT_FC_DEV) {
		/* checks port wwn property to find a match */
		di_ret = di_prop_lookup_bytes(DDI_DEV_T_ANY, node,
			PORT_WWN_PROP, &port_wwn_data);
		if (di_ret == -1) {
			rv = DI_WALK_CONTINUE;
			goto out;
		} else {
			(void) sprintf(port_wwn, "%016llx",
				(wwnConversion(port_wwn_data)));
			/*
			 * port wwn doesn't match contine to walk
			 * if match call do_stat_FCP_dev.
			 */
			if (strncmp(port_wwn, lap->apidp->dyncomp,
					WWN_SIZE*2)) {
				rv = DI_WALK_CONTINUE;
				goto out;
			}
		}
	}

	/*
	 * If stat'ing a xport only, we look at device nodes only to get
	 * xport configuration status. So a limited stat will suffice.
	 */
	if (lap->cmd == FPCFGA_STAT_FCA_PORT) {
		limited_stat = 1;
	} else {
		limited_stat = 0;
	}

	/*
	 * Ignore errors if stat'ing a bus or listing all
	 */
	ret = do_stat_FCP_dev(node, nodepath, lap, limited_stat);
	if (ret != FPCFGA_OK) {
		rv = DI_WALK_CONTINUE;
		goto out;
	}

	/* Are we done ? */
	rv = DI_WALK_CONTINUE;
	if (lap->cmd == FPCFGA_STAT_FCA_PORT &&
	    lap->chld_config == CFGA_STAT_CONFIGURED) {
		rv = DI_WALK_TERMINATE;
	}

	/*FALLTHRU*/
out:
	S_FREE(nodepath);
	if (devfsp != NULL) di_devfs_path_free(devfsp);
	return (rv);
}

static fpcfga_ret_t
do_stat_fca_xport(fpcfga_list_t *lap, int limited_stat,
	HBA_PORTATTRIBUTES portAttrs)
{
	cfga_list_data_t *clp = NULL;
	ldata_list_t *listp = NULL;
	int l_errno = 0;
	uint_t devinfo_state = 0;
	walkarg_t walkarg;
	fpcfga_ret_t ret;
	cfga_cond_t cond = CFGA_COND_UNKNOWN;

	assert(lap->xport_logp != NULL);

	/* Get xport state */
	if (lap->apidp->flags == FLAG_DEVINFO_FORCE) {
		walkarg.flags = FLAG_DEVINFO_FORCE;
	} else {
		walkarg.flags = 0;
	}
	walkarg.walkmode.node_args.flags = 0;
	walkarg.walkmode.node_args.fcn = get_xport_state;

	ret = walk_tree(lap->apidp->xport_phys, &devinfo_state,
		DINFOCPYALL | DINFOPATH, &walkarg, FPCFGA_WALK_NODE, &l_errno);
	if (ret == FPCFGA_OK) {
		lap->xport_rstate = xport_devinfo_to_recep_state(devinfo_state);
	} else {
		lap->xport_rstate = CFGA_STAT_NONE;
	}

	/*
	 * Get topology works okay even if the fp port is connected
	 * to a switch and no devices connected to the switch.
	 * In this case the list will only shows fp port info without
	 * any device listed.
	 */
	switch (portAttrs.PortType) {
		case HBA_PORTTYPE_NLPORT:
			(void) snprintf(lap->xport_type,
				sizeof (lap->xport_type), "%s",
				FP_FC_PUBLIC_PORT_TYPE);
			break;
		case HBA_PORTTYPE_NPORT:
			(void) snprintf(lap->xport_type,
				sizeof (lap->xport_type), "%s",
				FP_FC_FABRIC_PORT_TYPE);
			break;
		case HBA_PORTTYPE_LPORT:
			(void) snprintf(lap->xport_type,
				sizeof (lap->xport_type), "%s",
				FP_FC_PRIVATE_PORT_TYPE);
			break;
		case HBA_PORTTYPE_PTP:
			(void) snprintf(lap->xport_type,
				sizeof (lap->xport_type), "%s",
				FP_FC_PT_TO_PT_PORT_TYPE);
			break;
		/*
		 * HBA_PORTTYPE_UNKNOWN means nothing is connected
		 */
		case HBA_PORTTYPE_UNKNOWN:
			(void) snprintf(lap->xport_type,
				sizeof (lap->xport_type), "%s",
				FP_FC_PORT_TYPE);
			break;
		/* NOT_PRESENT, OTHER, FPORT, FLPORT */
		default:
			(void) snprintf(lap->xport_type,
				sizeof (lap->xport_type), "%s",
				FP_FC_PORT_TYPE);
			cond = CFGA_COND_FAILED;
			break;
	}

	if (limited_stat) {
		/* We only want to know bus(receptacle) connect status */
		return (FPCFGA_OK);
	}

	listp = calloc(1, sizeof (ldata_list_t));
	if (listp == NULL) {
		lap->l_errno = errno;
		return (FPCFGA_LIB_ERR);
	}

	clp = &listp->ldata;

	(void) snprintf(clp->ap_log_id, sizeof (clp->ap_log_id), "%s",
	    lap->xport_logp);
	(void) snprintf(clp->ap_phys_id, sizeof (clp->ap_phys_id), "%s",
	    lap->apidp->xport_phys);

	clp->ap_class[0] = '\0';	/* Filled by libcfgadm */
	clp->ap_r_state = lap->xport_rstate;
	clp->ap_o_state = lap->chld_config;
	clp->ap_cond = cond;
	clp->ap_busy = 0;
	clp->ap_status_time = (time_t)-1;
	clp->ap_info[0] = '\0';
	(void) strncpy(clp->ap_type, lap->xport_type, sizeof (clp->ap_type));

	/* Link it in.  lap->listp is NULL originally. */
	listp->next = lap->listp;
	/* lap->listp now gets cfga_list_data for the fca port. */
	lap->listp = listp;

	return (FPCFGA_OK);
}


static int
get_xport_state(di_node_t node, void *arg)
{
	uint_t *di_statep = (uint_t *)arg;

	*di_statep = di_state(node);

	return (DI_WALK_TERMINATE);
}

/*
 * Routine for updating ldata list based on the state of device node.
 * When no matching accessible ldata is found a new ldata is created
 * with proper state information.
 *
 * Overall algorithm:
 * If the device node is online and the matching ldata is found
 * the target device is updated with configued and unknown condition.
 * If the device node is offline or down and the matching ldata is found
 * the target device is updated with configued and unusable condition.
 * If the device node is online but the matching ldata is not found
 * the target device is created with configued and failing condition.
 * If the device node is offline or down and the matching ldata is not found
 * the target device is created with configued and unusable condition.
 */
static fpcfga_ret_t
do_stat_fc_dev(
	const di_node_t node,
	const char *nodepath,
	fpcfga_list_t *lap,
	int limited_stat)
{
	uint_t dctl_state = 0, devinfo_state = 0;
	char *dyncomp = NULL;
	cfga_list_data_t *clp = NULL;
	cfga_busy_t busy;
	ldata_list_t *listp = NULL;
	ldata_list_t *matchldp = NULL;
	int l_errno = 0;
	cfga_stat_t ostate;
	cfga_cond_t cond;
	fpcfga_ret_t ret;

	assert(lap->apidp->xport_phys != NULL);
	assert(lap->xport_logp != NULL);

	cond = CFGA_COND_UNKNOWN;

	devinfo_state = di_state(node);
	ostate = dev_devinfo_to_occupant_state(devinfo_state);

	/*
	 * NOTE: The framework cannot currently detect layered driver
	 * opens, so the busy indicator is not very reliable. Also,
	 * non-root users will not be able to determine busy
	 * status (libdevice needs root permissions).
	 * This should probably be fixed by adding a DI_BUSY to the di_state()
	 * routine in libdevinfo.
	 */
	if (devctl_cmd(nodepath, FPCFGA_DEV_GETSTATE, &dctl_state,
	    &l_errno) == FPCFGA_OK) {
		busy = ((dctl_state & DEVICE_BUSY) == DEVICE_BUSY) ? 1 : 0;
	} else {
		busy = 0;
	}

	/* We only want to know device config state */
	if (limited_stat) {
		if (((strcmp(lap->xport_type, FP_FC_FABRIC_PORT_TYPE) == 0) ||
			strcmp(lap->xport_type, FP_FC_PUBLIC_PORT_TYPE) == 0)) {
			lap->chld_config = CFGA_STAT_CONFIGURED;
		} else {
			if (ostate != CFGA_STAT_UNCONFIGURED) {
				lap->chld_config = CFGA_STAT_CONFIGURED;
			}
		}
		return (FPCFGA_OK);
	}

	/*
	 * If child device is configured, see if it is accessible also
	 * for FPCFGA_STAT_FC_DEV cmd.
	 */
	if (lap->cmd == FPCFGA_STAT_FC_DEV) {
		switch (ostate) {
		case CFGA_STAT_CONFIGURED:
			/*
			 * if configured and not accessble, the device is
			 * till be displayed with failing condition.
			 * return code should be FPCFGA_OK to display it.
			 */
		case CFGA_STAT_NONE:
			/*
			 * If not unconfigured and not attached
			 * the state is set to CFGA_STAT_NONE currently.
			 * This is okay for the detached node due to
			 * the driver being unloaded.
			 * May need to define another state to
			 * isolate the detached only state.
			 *
			 * handle the same way as configured.
			 */
			if (lap->ret != FPCFGA_ACCESS_OK) {
				cond = CFGA_COND_FAILING;
			}
			lap->chld_config = CFGA_STAT_CONFIGURED;
			break;
		case CFGA_STAT_UNCONFIGURED:
			/*
			 * if unconfigured - offline or down,
			 * set to cond to unusable regardless of accessibility.
			 * This behavior needs to be examined further.
			 * When the device is not accessible the node
			 * may get offline or down. In that case failing
			 * cond may make more sense.
			 * In anycase the ostate will be set to configured
			 * configured.
			 */
			cond = CFGA_COND_UNUSABLE;
			/*
			 * For fabric port the fca port is considered as
			 * configured since user configured previously
			 * for any existing node.  Otherwise when the
			 * device was accessible, the hba is considered as
			 * configured.
			 */
			if (((strcmp(lap->xport_type,
				FP_FC_PUBLIC_PORT_TYPE) == 0) ||
				(strcmp(lap->xport_type,
				FP_FC_FABRIC_PORT_TYPE) == 0)) ||
				(lap->ret == FPCFGA_ACCESS_OK)) {
				lap->chld_config = CFGA_STAT_CONFIGURED;
			} else {
				lap->ret = FPCFGA_APID_NOEXIST;
				return (FPCFGA_OK);
			}
			break;
		default:
			break;
		}

		/* if device found in disco ports, ldata already created. */
		if (lap->ret == FPCFGA_ACCESS_OK) {
			/*
			 * if cond is not changed then don't update
			 * condition to keep the previous condition.
			 */
			if (cond != CFGA_COND_UNKNOWN) {
				lap->listp->ldata.ap_cond = cond;
			}
			lap->listp->ldata.ap_o_state = CFGA_STAT_CONFIGURED;
			lap->listp->ldata.ap_busy = busy;
			lap->ret = FPCFGA_OK;
			return (FPCFGA_OK);
		}
	}

	/*
	 * if cmd is stat all check ldata list
	 * to see if the node exist on the dev list.  Otherwise create
	 * the list element.
	 */
	if (lap->cmd == FPCFGA_STAT_ALL) {
		if (lap->listp != NULL) {
			if ((ret = make_dyncomp_from_dinode(node,
					&dyncomp, &l_errno)) != FPCFGA_OK) {
				return (ret);
			}
			ret = is_dyn_ap_on_ldata_list(dyncomp, lap->listp,
					&matchldp, &l_errno);
			switch (ret) {
			case FPCFGA_ACCESS_OK:
				/* node exists so set ostate to configured. */
				lap->chld_config = CFGA_STAT_CONFIGURED;
				matchldp->ldata.ap_o_state =
					CFGA_STAT_CONFIGURED;
				matchldp->ldata.ap_busy = busy;
				clp = &matchldp->ldata;
				switch (ostate) {
				case CFGA_STAT_CONFIGURED:
				/*
				 * If not unconfigured and not attached
				 * the state is set to CFGA_STAT_NONE currently.
				 * This is okay for the detached node due to
				 * the driver being unloaded.
				 * May need to define another state to
				 * isolate the detached only state.
				 */
				case CFGA_STAT_NONE:
					/* update ap_type and ap_info */
					get_hw_info(node, clp);
					break;
				/*
				 * node is offline or down.
				 * set cond to unusable.
				 */
				case CFGA_STAT_UNCONFIGURED:
					/*
					 * if cond is not unknown
					 * we already set the cond from
					 * a different node with the same
					 * port WWN or initial probing
					 * was failed so don't update again.
					 */
					if (matchldp->ldata.ap_cond ==
						CFGA_COND_UNKNOWN) {
						matchldp->ldata.ap_cond =
						CFGA_COND_UNUSABLE;
					}
					break;
				default:
					break;
				}
				/* node found in ldata list so just return. */
				lap->ret = FPCFGA_OK;
				S_FREE(dyncomp);
				return (FPCFGA_OK);
			case FPCFGA_LIB_ERR:
				lap->l_errno = l_errno;
				S_FREE(dyncomp);
				return (ret);
			case FPCFGA_APID_NOACCESS:
				switch (ostate) {
				/* node is attached but not in dev list */
				case CFGA_STAT_CONFIGURED:
				case CFGA_STAT_NONE:
					lap->chld_config = CFGA_STAT_CONFIGURED;
					cond = CFGA_COND_FAILING;
					break;
				/*
				 * node is offline or down.
				 * set cond to unusable.
				 */
				case CFGA_STAT_UNCONFIGURED:
					/*
					 * For fabric port the fca port is
					 * considered as configured since user
					 * configured previously for any
					 * existing node.
					 */
					cond = CFGA_COND_UNUSABLE;
					if ((strcmp(lap->xport_type,
						FP_FC_PUBLIC_PORT_TYPE) == 0) ||
						(strcmp(lap->xport_type,
						FP_FC_FABRIC_PORT_TYPE) == 0)) {
						lap->chld_config =
						CFGA_STAT_CONFIGURED;
					} else {
						lap->ret = FPCFGA_OK;
						S_FREE(dyncomp);
						return (FPCFGA_OK);
					}
					break;
				default:
				/*
				 * continue to create ldata_list struct for
				 * this node
				 */
					break;
				}
			default:
				break;
			}
		} else {
			/*
			 * dev_list is null so there is no accessible dev.
			 * set the cond and continue to create ldata.
			 */
			switch (ostate) {
			case CFGA_STAT_CONFIGURED:
			case CFGA_STAT_NONE:
				cond = CFGA_COND_FAILING;
				lap->chld_config = CFGA_STAT_CONFIGURED;
				break;
			/*
			 * node is offline or down.
			 * set cond to unusable.
			 */
			case CFGA_STAT_UNCONFIGURED:
				cond = CFGA_COND_UNUSABLE;
				/*
				 * For fabric port the fca port is
				 * considered as configured since user
				 * configured previously for any
				 * existing node.
				 */
				if ((strcmp(lap->xport_type,
					FP_FC_PUBLIC_PORT_TYPE) == 0) ||
					(strcmp(lap->xport_type,
					FP_FC_FABRIC_PORT_TYPE) == 0)) {
					lap->chld_config =
					CFGA_STAT_CONFIGURED;
				} else {
					lap->ret = FPCFGA_OK;
					S_FREE(dyncomp);
					return (FPCFGA_OK);
				}
				break;
			default:
				break;
			}
		}
	}

	listp = calloc(1, sizeof (ldata_list_t));
	if (listp == NULL) {
		lap->l_errno = errno;
		S_FREE(dyncomp);
		return (FPCFGA_LIB_ERR);
	}

	clp = &listp->ldata;

	/* Create the dynamic component. */
	if (dyncomp == NULL) {
		ret = make_dyncomp_from_dinode(node, &dyncomp, &l_errno);
		if (ret != FPCFGA_OK) {
			S_FREE(listp);
			return (ret);
		}
	}

	/* Create logical and physical ap_id */
	(void) snprintf(clp->ap_log_id, sizeof (clp->ap_log_id), "%s%s%s",
	    lap->xport_logp, DYN_SEP, dyncomp);

	(void) snprintf(clp->ap_phys_id, sizeof (clp->ap_phys_id), "%s%s%s",
	    lap->apidp->xport_phys, DYN_SEP, dyncomp);

	S_FREE(dyncomp);

	clp->ap_class[0] = '\0'; /* Filled in by libcfgadm */
	clp->ap_r_state = lap->xport_rstate;
	/* set to ostate to configured and set cond with info. */
	clp->ap_o_state = CFGA_STAT_CONFIGURED;
	clp->ap_cond = cond;
	clp->ap_busy = busy;
	clp->ap_status_time = (time_t)-1;

	/* get ap_type and ap_info. */
	get_hw_info(node, clp);

	/* Link it in */
	listp->next = lap->listp;
	lap->listp = listp;

	lap->ret = FPCFGA_OK;
	return (FPCFGA_OK);
}

/*
 * Wrapper routine for handling path info.
 *
 * When show_FCP_dev option is given stat_path_info_FCP_dev() is called.
 * Otherwise stat_path_info_fc_dev() is called.
 */
int
stat_path_info_node(
	di_node_t 	root,
	void 		*arg,
	int 		*l_errnop)
{
	fpcfga_list_t *lap = NULL;

	lap = (fpcfga_list_t *)arg;
	if ((lap->apidp->flags & (FLAG_FCP_DEV)) == FLAG_FCP_DEV) {
		return (stat_path_info_FCP_dev(root, lap, l_errnop));
	} else {
		return (stat_path_info_fc_dev(root, lap, l_errnop));
	}
}

/*
 * Routine for updating ldata list based on the state of path info node.
 * When no matching accessible ldata is found a new ldata is created
 * with proper state information.
 *
 * Overall algorithm:
 * If the path info node is not offline and the matching ldata is found
 * the target device is updated with configued and unknown condition.
 * If the path info node is offline or failed and the matching ldata is found
 * the target device is updated with configued and unusable condition.
 * If the path info node is online but the matching ldata is not found
 * the target device is created with configued and failing condition.
 * If the path info is offline or failed and the matching ldata is not found
 * the target device is created with configued and unusable condition.
 */
static int
stat_path_info_fc_dev(
	di_node_t 	root,
	fpcfga_list_t	*lap,
	int 		*l_errnop)
{
	ldata_list_t *matchldp = NULL;
	di_path_t path = DI_PATH_NIL;
	uchar_t		*port_wwn_data;
	char		port_wwn[WWN_SIZE*2+1];
	int		count;
	fpcfga_ret_t 	ret;
	di_path_state_t	pstate;

	if (root == DI_NODE_NIL) {
		return (FPCFGA_LIB_ERR);
	}

	/*
	 * if stat on a specific dev and walk_node found it okay
	 * then just return ok.
	 */
	if ((lap->cmd == FPCFGA_STAT_FC_DEV) && (lap->ret == FPCFGA_OK)) {
		return (FPCFGA_OK);
	}

	/*
	 * if stat on a fca xport and chld_config is set
	 * then just return ok.
	 */
	if ((lap->cmd == FPCFGA_STAT_FCA_PORT) &&
				(lap->chld_config == CFGA_STAT_CONFIGURED)) {
		return (FPCFGA_OK);
	}

	/*
	 * when there is no path_info node return FPCFGA_OK.
	 * That way the result from walk_node shall be maintained.
	 */
	if ((path = di_path_next_client(root, path)) == DI_PATH_NIL) {
		/*
		 * if the dev was in dev list but not found
		 * return OK to indicate is not configured.
		 */
		if (lap->ret == FPCFGA_ACCESS_OK) {
			lap->ret = FPCFGA_OK;
		}
		return (FPCFGA_OK);
	}

	/* if stat on fca port return. */
	if (lap->cmd == FPCFGA_STAT_FCA_PORT) {
		if (((strcmp(lap->xport_type, FP_FC_FABRIC_PORT_TYPE) == 0) ||
			strcmp(lap->xport_type, FP_FC_PUBLIC_PORT_TYPE) == 0)) {
			lap->chld_config = CFGA_STAT_CONFIGURED;
			return (FPCFGA_OK);
		} else {
			if ((pstate = di_path_state(path)) !=
				DI_PATH_STATE_OFFLINE) {
				lap->chld_config = CFGA_STAT_CONFIGURED;
				return (FPCFGA_OK);
			}
		}
	}
	/*
	 * now parse the path info node.
	 */
	do {
		count = di_path_prop_lookup_bytes(path, PORT_WWN_PROP,
			&port_wwn_data);
		if (count != WWN_SIZE) {
			ret = FPCFGA_LIB_ERR;
			break;
		}

		(void) sprintf(port_wwn, "%016llx",
			(wwnConversion(port_wwn_data)));
		switch (lap->cmd) {
		case FPCFGA_STAT_FC_DEV:
			/* if no match contine to the next path info node. */
			if (strncmp(port_wwn, lap->apidp->dyncomp,
					WWN_SIZE*2)) {
				break;
			}
			/* if device in dev_list, ldata already created. */
			if (lap->ret == FPCFGA_ACCESS_OK) {
				lap->listp->ldata.ap_o_state =
					CFGA_STAT_CONFIGURED;
				if (((pstate = di_path_state(path)) ==
					DI_PATH_STATE_OFFLINE) ||
					(pstate == DI_PATH_STATE_FAULT)) {
					lap->listp->ldata.ap_cond =
							CFGA_COND_UNUSABLE;
				}
				lap->ret = FPCFGA_OK;
				return (FPCFGA_OK);
			} else {
				if ((strcmp(lap->xport_type,
					FP_FC_PUBLIC_PORT_TYPE) == 0) ||
					(strcmp(lap->xport_type,
					FP_FC_FABRIC_PORT_TYPE) == 0)) {
					lap->chld_config = CFGA_STAT_CONFIGURED;
					return (init_ldata_for_mpath_dev(
						path, port_wwn, l_errnop, lap));
				} else {
					if ((di_path_state(path)) !=
						DI_PATH_STATE_OFFLINE) {
					    return (init_ldata_for_mpath_dev(
						path, port_wwn, l_errnop, lap));
					} else {
					    lap->ret = FPCFGA_APID_NOEXIST;
					    return (FPCFGA_OK);
					}
				}
			}
		case FPCFGA_STAT_ALL:
			/* check if there is list data. */
			if (lap->listp != NULL) {
				ret = is_dyn_ap_on_ldata_list(port_wwn,
					lap->listp, &matchldp, l_errnop);
				if (ret == FPCFGA_ACCESS_OK) {
					lap->chld_config = CFGA_STAT_CONFIGURED;
					matchldp->ldata.ap_o_state =
							CFGA_STAT_CONFIGURED;
					/*
					 * Update the condition as unusable
					 * if the pathinfo state is failed
					 * or offline.
					 */
					if (((pstate = di_path_state(path)) ==
						DI_PATH_STATE_OFFLINE) ||
						(pstate ==
							DI_PATH_STATE_FAULT)) {
						matchldp->ldata.ap_cond =
							CFGA_COND_UNUSABLE;
					}
					break;
				} else if (ret == FPCFGA_LIB_ERR) {
					lap->l_errno = *l_errnop;
					return (ret);
				}
			}
			/*
			 * now create ldata for this particular path info node.
			 * if port top is private loop and pathinfo is in
			 * in offline state don't include to ldata list.
			 */
			if (((strcmp(lap->xport_type,
				FP_FC_PUBLIC_PORT_TYPE) == 0) ||
				(strcmp(lap->xport_type,
					FP_FC_FABRIC_PORT_TYPE) == 0)) ||
				(di_path_state(path) !=
					DI_PATH_STATE_OFFLINE)) {
				lap->chld_config = CFGA_STAT_CONFIGURED;
				ret = init_ldata_for_mpath_dev(
					path, port_wwn, l_errnop, lap);
				if (ret != FPCFGA_OK) {
					return (ret);
				}
			}
			break;
		case FPCFGA_STAT_FCA_PORT:
			if (di_path_state(path) != DI_PATH_STATE_OFFLINE) {
				lap->chld_config = CFGA_STAT_CONFIGURED;
				return (FPCFGA_OK);
			}
		}
		path = di_path_next_client(root, path);
	} while (path != DI_PATH_NIL);

	return (FPCFGA_OK);

}

/*
 * Routine for updating ldata list based on the state of path info node.
 * When no matching accessible ldata is found a new ldata is created
 * with proper state information.
 *
 * The difference from stat_path_info_fc_dev() is
 * to handle FCP SCSI LUN information. Otherwise overall algorithm is
 * same.
 *
 * Overall algorithm:
 * If the path info node is not offline and the matching ldata is found
 * the target device is updated with configued and unknown condition.
 * If the path info node is offline or failed and the matching ldata is found
 * the target device is updated with configued and unusable condition.
 * If the path info node is online but the matching ldata is not found
 * the target device is created with configued and failing condition.
 * If the path info is offline or failed and the matching ldata is not found
 * the target device is created with configued and unusable condition.
 */
static int
stat_path_info_FCP_dev(
	di_node_t 	root,
	fpcfga_list_t	*lap,
	int 		*l_errnop)
{
	ldata_list_t	*matchldp = NULL, *listp = NULL;
	cfga_list_data_t	*clp;
	di_path_t	path = DI_PATH_NIL;
	di_node_t	client_node = DI_NODE_NIL;
	char		*port_wwn = NULL, *nodepath = NULL;
	int		*lun_nump;
	fpcfga_ret_t 	ldata_ret;
	di_path_state_t	pstate;
	cfga_busy_t	busy;
	uint_t		dctl_state = 0;

	if (root == DI_NODE_NIL) {
		return (FPCFGA_LIB_ERR);
	}

	/*
	 * if stat on a fca xport and chld_config is set
	 * then just return ok.
	 */
	if ((lap->cmd == FPCFGA_STAT_FCA_PORT) &&
				(lap->chld_config == CFGA_STAT_CONFIGURED)) {
		return (FPCFGA_OK);
	}
	/*
	 * when there is no path_info node return FPCFGA_OK.
	 * That way the result from walk_node shall be maintained.
	 */
	if ((path = di_path_next_client(root, path)) == DI_PATH_NIL) {
		/*
		 * if the dev was in dev list but not found
		 * return ok.
		 */
		if (lap->ret == FPCFGA_ACCESS_OK) {
			lap->ret = FPCFGA_OK;
		}
		return (FPCFGA_OK);
	}
	/*
	 * If stat on fca port and port topology is fabric return here.
	 * If not fabric return only when path state is not offfline.
	 * The other cases are handbled below.
	 */
	if (lap->cmd == FPCFGA_STAT_FCA_PORT) {
		if (((strcmp(lap->xport_type, FP_FC_FABRIC_PORT_TYPE) == 0) ||
			strcmp(lap->xport_type, FP_FC_PUBLIC_PORT_TYPE) == 0)) {
			lap->chld_config = CFGA_STAT_CONFIGURED;
			return (FPCFGA_OK);
		} else {
			if ((pstate = di_path_state(path)) !=
				DI_PATH_STATE_OFFLINE) {
				lap->chld_config = CFGA_STAT_CONFIGURED;
				return (FPCFGA_OK);
			}
		}
	}
	/*
	 * now parse the path info node.
	 */
	do {
		switch (lap->cmd) {
		case FPCFGA_STAT_FC_DEV:
			if ((make_portwwn_luncomp_from_pinode(path, &port_wwn,
				&lun_nump, l_errnop)) != FPCFGA_OK) {
				return (FPCFGA_LIB_ERR);
			}

			if ((ldata_ret = is_FCP_dev_ap_on_ldata_list(port_wwn,
				*lun_nump, lap->listp, &matchldp))
				== FPCFGA_LIB_ERR) {
				S_FREE(port_wwn);
				return (ldata_ret);
			}

			if (ldata_ret == FPCFGA_ACCESS_OK) {
				lap->chld_config = CFGA_STAT_CONFIGURED;
				matchldp->ldata.ap_o_state =
						CFGA_STAT_CONFIGURED;
				/*
				 * Update the condition as unusable
				 * if the pathinfo state is failed
				 * or offline.
				 */
				if (((pstate = di_path_state(path)) ==
					DI_PATH_STATE_OFFLINE) ||
					(pstate == DI_PATH_STATE_FAULT)) {
					matchldp->ldata.ap_cond =
							CFGA_COND_UNUSABLE;
				}
				lap->ret = FPCFGA_OK;
				break;
			}

			if (strncmp(port_wwn, lap->apidp->dyncomp, WWN_SIZE*2)
					!= 0) {
				break;
			}
			/*
			 * now create ldata for this particular path info node.
			 * if port top is private loop and pathinfo is in
			 * in offline state don't include to ldata list.
			 */
			if (((strcmp(lap->xport_type,
				FP_FC_PUBLIC_PORT_TYPE) == 0) ||
				(strcmp(lap->xport_type,
					FP_FC_FABRIC_PORT_TYPE) == 0)) ||
				(di_path_state(path) !=
					DI_PATH_STATE_OFFLINE)) {
			    lap->chld_config = CFGA_STAT_CONFIGURED;
				/* create ldata for this pi node. */
			    client_node = di_path_client_node(path);
			    if (client_node == DI_NODE_NIL) {
				*l_errnop = errno;
				S_FREE(port_wwn);
				return (FPCFGA_LIB_ERR);
			    }
			    if ((construct_nodepath_from_dinode(
				client_node, &nodepath, l_errnop))
					!= FPCFGA_OK) {
				S_FREE(port_wwn);
				return (FPCFGA_LIB_ERR);
			    }

			    listp = calloc(1, sizeof (ldata_list_t));
			    if (listp == NULL) {
				S_FREE(port_wwn);
				S_FREE(nodepath);
				lap->l_errno = errno;
				return (FPCFGA_LIB_ERR);
			    }

			    clp = &listp->ldata;

			    /* Create logical and physical ap_id */
			    (void) snprintf(clp->ap_log_id,
				sizeof (clp->ap_log_id), "%s%s%s%s%d",
				lap->xport_logp, DYN_SEP, port_wwn,
				LUN_COMP_SEP, *lun_nump);
			    (void) snprintf(clp->ap_phys_id,
				sizeof (clp->ap_phys_id), "%s%s%s%s%d",
				lap->apidp->xport_phys, DYN_SEP, port_wwn,
				LUN_COMP_SEP, *lun_nump);
				/*
				 * We reached here since FCP dev is not found
				 * in ldata list but path info node exists.
				 *
				 * Update the condition as failing
				 * if the pathinfo state was normal.
				 * Update the condition as unusable
				 * if the pathinfo state is failed
				 * or offline.
				 */
			    clp->ap_class[0] = '\0'; /* Filled by libcfgadm */
			    clp->ap_o_state = CFGA_STAT_CONFIGURED;
			    if (((pstate = di_path_state(path))
					== DI_PATH_STATE_OFFLINE) ||
				(pstate == DI_PATH_STATE_FAULT)) {
				clp->ap_cond = CFGA_COND_UNUSABLE;
			    } else {
				clp->ap_cond = CFGA_COND_FAILING;
			    }
			    clp->ap_r_state = lap->xport_rstate;
			    clp->ap_info[0] = '\0';
				/* update ap_type and ap_info */
			    get_hw_info(client_node, clp);
			    if (devctl_cmd(nodepath, FPCFGA_DEV_GETSTATE,
				&dctl_state, l_errnop) == FPCFGA_OK) {
				busy = ((dctl_state & DEVICE_BUSY)
					== DEVICE_BUSY) ? 1 : 0;
			    } else {
				busy = 0;
			    }
			    clp->ap_busy = busy;
			    clp->ap_status_time = (time_t)-1;

			    (void) insert_ldata_to_ldatalist(port_wwn,
				lun_nump, listp, &(lap->listp));
			}
			break;
		case FPCFGA_STAT_ALL:
			if ((make_portwwn_luncomp_from_pinode(path, &port_wwn,
				&lun_nump, l_errnop)) != FPCFGA_OK) {
				return (FPCFGA_LIB_ERR);
			}

			if ((ldata_ret = is_FCP_dev_ap_on_ldata_list(port_wwn,
				*lun_nump, lap->listp, &matchldp))
				== FPCFGA_LIB_ERR) {
				S_FREE(port_wwn);
				return (ldata_ret);
			}

			if (ldata_ret == FPCFGA_ACCESS_OK) {
				lap->chld_config = CFGA_STAT_CONFIGURED;
				matchldp->ldata.ap_o_state =
						CFGA_STAT_CONFIGURED;
				/*
				 * Update the condition as unusable
				 * if the pathinfo state is failed
				 * or offline.
				 */
				if (((pstate = di_path_state(path)) ==
					DI_PATH_STATE_OFFLINE) ||
					(pstate == DI_PATH_STATE_FAULT)) {
					matchldp->ldata.ap_cond =
							CFGA_COND_UNUSABLE;
				}
				break;
			}
			/*
			 * now create ldata for this particular path info node.
			 * if port top is private loop and pathinfo is in
			 * in offline state don't include to ldata list.
			 */
			if (((strcmp(lap->xport_type,
				FP_FC_PUBLIC_PORT_TYPE) == 0) ||
				(strcmp(lap->xport_type,
					FP_FC_FABRIC_PORT_TYPE) == 0)) ||
				(di_path_state(path) !=
					DI_PATH_STATE_OFFLINE)) {
			    lap->chld_config = CFGA_STAT_CONFIGURED;
				/* create ldata for this pi node. */
			    client_node = di_path_client_node(path);
			    if (client_node == DI_NODE_NIL) {
				*l_errnop = errno;
				S_FREE(port_wwn);
				return (FPCFGA_LIB_ERR);
			    }
			    if ((construct_nodepath_from_dinode(
				client_node, &nodepath, l_errnop))
					!= FPCFGA_OK) {
				S_FREE(port_wwn);
				return (FPCFGA_LIB_ERR);
			    }

			    listp = calloc(1, sizeof (ldata_list_t));
			    if (listp == NULL) {
				S_FREE(port_wwn);
				S_FREE(nodepath);
				lap->l_errno = errno;
				return (FPCFGA_LIB_ERR);
			    }

			    clp = &listp->ldata;

			    /* Create logical and physical ap_id */
			    (void) snprintf(clp->ap_log_id,
				sizeof (clp->ap_log_id), "%s%s%s%s%d",
				lap->xport_logp, DYN_SEP, port_wwn,
				LUN_COMP_SEP, *lun_nump);
			    (void) snprintf(clp->ap_phys_id,
				sizeof (clp->ap_phys_id), "%s%s%s%s%d",
				lap->apidp->xport_phys, DYN_SEP, port_wwn,
				LUN_COMP_SEP, *lun_nump);
				/*
				 * We reached here since FCP dev is not found
				 * in ldata list but path info node exists.
				 *
				 * Update the condition as failing
				 * if the pathinfo state was normal.
				 * Update the condition as unusable
				 * if the pathinfo state is failed
				 * or offline.
				 */
			    clp->ap_class[0] = '\0'; /* Filled by libcfgadm */
			    clp->ap_o_state = CFGA_STAT_CONFIGURED;
			    if (((pstate = di_path_state(path))
					== DI_PATH_STATE_OFFLINE) ||
				(pstate == DI_PATH_STATE_FAULT)) {
				clp->ap_cond = CFGA_COND_UNUSABLE;
			    } else {
				clp->ap_cond = CFGA_COND_FAILING;
			    }
			    clp->ap_r_state = lap->xport_rstate;
			    clp->ap_info[0] = '\0';
				/* update ap_type and ap_info */
			    get_hw_info(client_node, clp);
			    if (devctl_cmd(nodepath, FPCFGA_DEV_GETSTATE,
				&dctl_state, l_errnop) == FPCFGA_OK) {
				busy = ((dctl_state & DEVICE_BUSY)
					== DEVICE_BUSY) ? 1 : 0;
			    } else {
				busy = 0;
			    }
			    clp->ap_busy = busy;
			    clp->ap_status_time = (time_t)-1;

			    (void) insert_ldata_to_ldatalist(port_wwn,
				lun_nump, listp, &(lap->listp));
			}
			break;
		case FPCFGA_STAT_FCA_PORT:
			if (di_path_state(path) != DI_PATH_STATE_OFFLINE) {
				lap->chld_config = CFGA_STAT_CONFIGURED;
				lap->ret = FPCFGA_OK;
				return (FPCFGA_OK);
			}
		}
		path = di_path_next_client(root, path);
	} while (path != DI_PATH_NIL);

	lap->ret = FPCFGA_OK;
	S_FREE(port_wwn);
	S_FREE(nodepath);
	return (FPCFGA_OK);

}

/*
 * Routine for updating ldata list based on the state of device node.
 * When no matching accessible ldata is found a new ldata is created
 * with proper state information.
 *
 * The difference from do_stat_fc_dev() is
 * to handle FCP SCSI LUN information. Otherwise overall algorithm is
 * same.
 *
 * Overall algorithm:
 * If the device node is online and the matching ldata is found
 * the target device is updated with configued and unknown condition.
 * If the device node is offline or down and the matching ldata is found
 * the target device is updated with configued and unusable condition.
 * If the device node is online but the matching ldata is not found
 * the target device is created with configued and failing condition.
 * If the device node is offline or down and the matching ldata is not found
 * the target device is created with configued and unusable condition.
 */
static fpcfga_ret_t
do_stat_FCP_dev(
	const di_node_t node,
	const char *nodepath,
	fpcfga_list_t *lap,
	int limited_stat)
{
	uint_t dctl_state = 0, devinfo_state = 0;
	char *port_wwn = NULL;
	cfga_list_data_t *clp = NULL;
	cfga_busy_t busy;
	ldata_list_t *listp = NULL;
	ldata_list_t *matchldp = NULL;
	int l_errno = 0, *lun_nump;
	cfga_stat_t ostate;
	cfga_cond_t cond;
	fpcfga_ret_t ldata_ret;

	assert(lap->apidp->xport_phys != NULL);
	assert(lap->xport_logp != NULL);

	cond = CFGA_COND_UNKNOWN;

	devinfo_state = di_state(node);
	ostate = dev_devinfo_to_occupant_state(devinfo_state);

	/*
	 * NOTE: The devctl framework cannot currently detect layered driver
	 * opens, so the busy indicator is not very reliable. Also,
	 * non-root users will not be able to determine busy
	 * status (libdevice needs root permissions).
	 * This should probably be fixed by adding a DI_BUSY to the di_state()
	 * routine in libdevinfo.
	 */
	if (devctl_cmd(nodepath, FPCFGA_DEV_GETSTATE, &dctl_state,
	    &l_errno) == FPCFGA_OK) {
		busy = ((dctl_state & DEVICE_BUSY) == DEVICE_BUSY) ? 1 : 0;
	} else {
		busy = 0;
	}

	/* We only want to know device config state */
	if (limited_stat) {
		if (((strcmp(lap->xport_type, FP_FC_FABRIC_PORT_TYPE) == 0) ||
			strcmp(lap->xport_type, FP_FC_PUBLIC_PORT_TYPE) == 0)) {
			lap->chld_config = CFGA_STAT_CONFIGURED;
		} else {
			if (ostate != CFGA_STAT_UNCONFIGURED) {
				lap->chld_config = CFGA_STAT_CONFIGURED;
			}
		}
		return (FPCFGA_OK);
	}

	/*
	 * If child device is configured, see if it is accessible also
	 * for FPCFGA_STAT_FC_DEV cmd.
	 */
	if ((make_portwwn_luncomp_from_dinode(node, &port_wwn, &lun_nump,
			&l_errno)) != FPCFGA_OK) {
		lap->l_errno = l_errno;
		return (FPCFGA_LIB_ERR);
	}

	if ((ldata_ret = is_FCP_dev_ap_on_ldata_list(port_wwn, *lun_nump,
			lap->listp, &matchldp)) == FPCFGA_LIB_ERR) {
		lap->l_errno = l_errno;
		S_FREE(port_wwn);
		return (ldata_ret);
	}

	if (lap->cmd == FPCFGA_STAT_FC_DEV) {
		switch (ostate) {
		case CFGA_STAT_CONFIGURED:
			/*
			 * if configured and not accessble, the device is
			 * till be displayed with failing condition.
			 * return code should be FPCFGA_OK to display it.
			 */
		case CFGA_STAT_NONE:
			/*
			 * If not unconfigured and not attached
			 * the state is set to CFGA_STAT_NONE currently.
			 * This is okay for the detached node due to
			 * the driver being unloaded.
			 * May need to define another state to
			 * isolate the detached only state.
			 *
			 * handle the same way as configured.
			 */
			if (ldata_ret != FPCFGA_ACCESS_OK) {
				cond = CFGA_COND_FAILING;
			}
			lap->chld_config = CFGA_STAT_CONFIGURED;
			break;
		case CFGA_STAT_UNCONFIGURED:
			/*
			 * if unconfigured - offline or down,
			 * set to cond to unusable regardless of accessibility.
			 * This behavior needs to be examined further.
			 * When the device is not accessible the node
			 * may get offline or down. In that case failing
			 * cond may make more sense.
			 * In anycase the ostate will be set to configured
			 * configured.
			 */
			cond = CFGA_COND_UNUSABLE;
			/*
			 * For fabric port the fca port is considered as
			 * configured since user configured previously
			 * for any existing node.  Otherwise when the
			 * device was accessible, the hba is considered as
			 * configured.
			 */
			if (((strcmp(lap->xport_type,
				FP_FC_PUBLIC_PORT_TYPE) == 0) ||
				(strcmp(lap->xport_type,
				FP_FC_FABRIC_PORT_TYPE) == 0)) ||
				(lap->ret == FPCFGA_ACCESS_OK)) {
				lap->chld_config = CFGA_STAT_CONFIGURED;
			} else {
				/*
				 * if lap->ret is okay there is at least
				 * one matching ldata exist.  Need to keep
				 * okay ret to display the matching ones.
				 */
				if (lap->ret != FPCFGA_OK) {
					lap->ret = FPCFGA_APID_NOEXIST;
				}
				S_FREE(port_wwn);
				return (FPCFGA_OK);
			}
			break;
		default:
			break;
		}

		/* if device found in dev_list, ldata already created. */
		if (ldata_ret == FPCFGA_ACCESS_OK) {
			/*
			 * if cond is not changed then don't update
			 * condition to keep any condtion
			 * from initial discovery. If the initial
			 * cond was failed the same condition will be kept.
			 */
			if (cond != CFGA_COND_UNKNOWN) {
				matchldp->ldata.ap_cond = cond;
			}
			matchldp->ldata.ap_o_state = CFGA_STAT_CONFIGURED;
			matchldp->ldata.ap_busy = busy;
			/* update ap_info via inquiry */
			clp = &matchldp->ldata;
			/* update ap_type and ap_info */
			get_hw_info(node, clp);
			lap->ret = FPCFGA_OK;
			S_FREE(port_wwn);
			return (FPCFGA_OK);
		}
	}

	/*
	 * if cmd is stat all check ldata list
	 * to see if the node exist on the dev list.  Otherwise create
	 * the list element.
	 */
	if (lap->cmd == FPCFGA_STAT_ALL) {
		switch (ldata_ret) {
		case FPCFGA_ACCESS_OK:
			/* node exists so set ostate to configured. */
			lap->chld_config = CFGA_STAT_CONFIGURED;
			matchldp->ldata.ap_o_state =
				CFGA_STAT_CONFIGURED;
			matchldp->ldata.ap_busy = busy;
			clp = &matchldp->ldata;
			switch (ostate) {
			case CFGA_STAT_CONFIGURED:
			/*
			 * If not unconfigured and not attached
			 * the state is set to CFGA_STAT_NONE currently.
			 * This is okay for the detached node due to
			 * the driver being unloaded.
			 * May need to define another state to
			 * isolate the detached only state.
			 */
			case CFGA_STAT_NONE:
				/* update ap_type and ap_info */
				get_hw_info(node, clp);
				break;
			/*
			 * node is offline or down.
			 * set cond to unusable.
			 */
			case CFGA_STAT_UNCONFIGURED:
				/*
				 * if cond is not unknown
				 * initial probing was failed
				 * so don't update again.
				 */
				if (matchldp->ldata.ap_cond ==
					CFGA_COND_UNKNOWN) {
					matchldp->ldata.ap_cond =
					CFGA_COND_UNUSABLE;
				}
				break;
			default:
				break;
			}
			/* node found in ldata list so just return. */
			lap->ret = FPCFGA_OK;
			S_FREE(port_wwn);
			return (FPCFGA_OK);
		case FPCFGA_APID_NOACCESS:
			switch (ostate) {
			/* node is attached but not in dev list */
			case CFGA_STAT_CONFIGURED:
			case CFGA_STAT_NONE:
				lap->chld_config = CFGA_STAT_CONFIGURED;
				cond = CFGA_COND_FAILING;
				break;
			/*
			 * node is offline or down.
			 * set cond to unusable.
			 */
			case CFGA_STAT_UNCONFIGURED:
				/*
				 * For fabric port the fca port is
				 * considered as configured since user
				 * configured previously for any
				 * existing node.
				 */
				cond = CFGA_COND_UNUSABLE;
				if ((strcmp(lap->xport_type,
					FP_FC_PUBLIC_PORT_TYPE) == 0) ||
					(strcmp(lap->xport_type,
					FP_FC_FABRIC_PORT_TYPE) == 0)) {
					lap->chld_config =
					CFGA_STAT_CONFIGURED;
				} else {
					lap->ret = FPCFGA_OK;
					S_FREE(port_wwn);
					return (FPCFGA_OK);
				}
				break;
			default:
			/*
			 * continue to create ldata_list struct for
			 * this node
			 */
				break;
			}
		default:
			break;
		}
	}

	listp = calloc(1, sizeof (ldata_list_t));
	if (listp == NULL) {
		lap->l_errno = errno;
		S_FREE(port_wwn);
		return (FPCFGA_LIB_ERR);
	}

	clp = &listp->ldata;

	/* Create logical and physical ap_id */
	(void) snprintf(clp->ap_log_id, sizeof (clp->ap_log_id),
		"%s%s%s%s%d", lap->xport_logp, DYN_SEP, port_wwn,
		LUN_COMP_SEP, *lun_nump);
	(void) snprintf(clp->ap_phys_id, sizeof (clp->ap_phys_id),
		"%s%s%s%s%d", lap->apidp->xport_phys, DYN_SEP, port_wwn,
		LUN_COMP_SEP, *lun_nump);
	clp->ap_class[0] = '\0'; /* Filled in by libcfgadm */
	clp->ap_r_state = lap->xport_rstate;
	clp->ap_o_state = CFGA_STAT_CONFIGURED;
	clp->ap_cond = cond;
	clp->ap_busy = busy;
	clp->ap_status_time = (time_t)-1;
	clp->ap_info[0] = '\0';

	get_hw_info(node, clp);

	(void) insert_ldata_to_ldatalist(port_wwn, lun_nump, listp,
		&(lap->listp));

	lap->ret = FPCFGA_OK;
	S_FREE(port_wwn);
	return (FPCFGA_OK);
}

/*
 * Searches the ldata_list to find if the the input port_wwn exist.
 *
 * Input:  port_wwn, ldata_list.
 * Return value: FPCFGA_APID_NOACCESS if not found on ldata_list.
 *		 FPCFGA_ACCESS_OK if found on ldata_list.
 */
static fpcfga_ret_t
is_dyn_ap_on_ldata_list(const char *port_wwn, const ldata_list_t *listp,
			ldata_list_t **matchldpp, int *l_errnop)
{
	char		*dyn = NULL, *dyncomp = NULL;
	int		len;
	ldata_list_t	*tmplp;
	fpcfga_ret_t 	ret;


	ret = FPCFGA_APID_NOACCESS;

	tmplp = (ldata_list_t *)listp;
	while (tmplp != NULL) {
		if ((dyn = GET_DYN(tmplp->ldata.ap_phys_id)) != NULL) {
			len = strlen(DYN_TO_DYNCOMP(dyn)) + 1;
			dyncomp = calloc(1, len);
			if (dyncomp == NULL) {
				*l_errnop = errno;
				ret = FPCFGA_LIB_ERR;
				break;
			}
			(void) strcpy(dyncomp, DYN_TO_DYNCOMP(dyn));
			if (!(strncmp(port_wwn, dyncomp, WWN_SIZE*2))) {
				*matchldpp = tmplp;
				S_FREE(dyncomp);
				ret = FPCFGA_ACCESS_OK;
				break;
			}
			S_FREE(dyncomp);
		}
		tmplp = tmplp->next;
	}

	return (ret);
}

/*
 * Searches the ldata_list to find if the the input port_wwn and lun exist.
 *
 * Input:  port_wwn, ldata_list.
 * Return value: FPCFGA_APID_NOACCESS if not found on ldata_list.
 *		 FPCFGA_ACCESS_OK if found on ldata_list.
 */
static fpcfga_ret_t
is_FCP_dev_ap_on_ldata_list(const char *port_wwn, const int lun_num,
			ldata_list_t *ldatap,
			ldata_list_t **matchldpp)
{
	ldata_list_t *curlp = NULL;
	char *dyn = NULL, *dyncomp = NULL;
	char *lun_dyn = NULL, *lunp = NULL;
	int ldata_lun;
	fpcfga_ret_t ret;

	/*
	 * if there is no list data just return the FCP dev list.
	 * Normally this should not occur since list data should
	 * be created through discoveredPort list.
	 */
	ret = FPCFGA_APID_NOACCESS;
	if (ldatap == NULL) {
		return (ret);
	}

	dyn = GET_DYN(ldatap->ldata.ap_phys_id);
	if (dyn != NULL) dyncomp = DYN_TO_DYNCOMP(dyn);
	if ((dyncomp != NULL) &&
			(strncmp(dyncomp, port_wwn, WWN_SIZE*2) == 0)) {
		lun_dyn = GET_LUN_DYN(dyncomp);
		if (lun_dyn != NULL) {
			lunp = LUN_DYN_TO_LUNCOMP(lun_dyn);
			if ((ldata_lun = atoi(lunp)) == lun_num) {
				*matchldpp = ldatap;
				return (FPCFGA_ACCESS_OK);
			} else if (ldata_lun > lun_num) {
				return (ret);
			}
			/* else continue */
		} else {
			/* we have match without lun comp. */
			*matchldpp = ldatap;
			return (FPCFGA_ACCESS_OK);
		}
	}

	curlp = ldatap->next;

	dyn = dyncomp = NULL;
	lun_dyn = lunp = NULL;
	while (curlp != NULL) {
		dyn = GET_DYN(curlp->ldata.ap_phys_id);
		if (dyn != NULL) dyncomp = DYN_TO_DYNCOMP(dyn);
		if ((dyncomp != NULL) &&
				(strncmp(dyncomp, port_wwn, WWN_SIZE*2) == 0)) {
			lun_dyn = GET_LUN_DYN(dyncomp);
			if (lun_dyn != NULL) {
				lunp = LUN_DYN_TO_LUNCOMP(lun_dyn);
				if ((ldata_lun = atoi(lunp)) == lun_num) {
					*matchldpp = curlp;
					return (FPCFGA_ACCESS_OK);
				} else if (ldata_lun > lun_num) {
					return (ret);
				}
				/* else continue */
			} else {
				/* we have match without lun comp. */
				*matchldpp = curlp;
				return (FPCFGA_ACCESS_OK);
			}
		}
		dyn = dyncomp = NULL;
		lun_dyn = lunp = NULL;
		curlp = curlp->next;
	}

	return (ret);

}

/*
 * This routine is called when a pathinfo without matching pwwn in dev_list
 * is found.
 */
static fpcfga_ret_t
init_ldata_for_mpath_dev(di_path_t path, char *pwwn, int *l_errnop,
	fpcfga_list_t *lap)
{
	ldata_list_t *listp = NULL;
	cfga_list_data_t *clp = NULL;
	size_t		devlen;
	char		*devpath;
	di_node_t	client_node = DI_NODE_NIL;
	uint_t 		dctl_state = 0;
	cfga_busy_t 	busy;
	char		*client_path;
	di_path_state_t	pstate;

	/* get the client node path */
	if (path == DI_PATH_NIL) {
		return (FPCFGA_LIB_ERR);
	}
	client_node = di_path_client_node(path);
	if (client_node == DI_NODE_NIL) {
		return (FPCFGA_LIB_ERR);
	}
	if ((client_path = di_devfs_path(client_node)) == NULL) {
		return (FPCFGA_LIB_ERR);
	}
	devlen = strlen(DEVICES_DIR) + strlen(client_path) + 1;
	devpath = calloc(1, devlen);
	if (devpath == NULL) {
		di_devfs_path_free(client_path);
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}
	(void) snprintf(devpath, devlen, "%s%s", DEVICES_DIR, client_path);

	/* now need to create ldata for this dev */
	listp = calloc(1, sizeof (ldata_list_t));
	if (listp == NULL) {
		di_devfs_path_free(client_path);
		S_FREE(devpath);
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	clp = &listp->ldata;

	/* Create logical and physical ap_id */
	(void) snprintf(clp->ap_log_id, sizeof (clp->ap_log_id), "%s%s%s",
			lap->xport_logp, DYN_SEP, pwwn);
	(void) snprintf(clp->ap_phys_id, sizeof (clp->ap_phys_id), "%s%s%s",
			lap->apidp->xport_phys, DYN_SEP, pwwn);

	/* Filled in by libcfgadm */
	clp->ap_class[0] = '\0'; /* Filled by libcfgadm */
	clp->ap_r_state = lap->xport_rstate;
	/* set to ostate to configured. */
	clp->ap_o_state = CFGA_STAT_CONFIGURED;
	/*
	 * This routine is called when a port WWN is not found in dev list
	 * but path info node exists.
	 *
	 * Update the condition as failing if the pathinfo state was normal.
	 * Update the condition as unusable if the pathinfo state is failed
	 * or offline.
	 */
	if (((pstate = di_path_state(path)) == DI_PATH_STATE_OFFLINE) ||
			(pstate == DI_PATH_STATE_FAULT)) {
		clp->ap_cond = CFGA_COND_UNUSABLE;
	} else {
		clp->ap_cond = CFGA_COND_FAILING;
	}
	clp->ap_status_time = (time_t)-1;
	/* update ap_type and ap_info */
	get_hw_info(client_node, clp);

	if (devctl_cmd(devpath, FPCFGA_DEV_GETSTATE,
		&dctl_state, l_errnop) == FPCFGA_OK) {
		busy = ((dctl_state & DEVICE_BUSY) == DEVICE_BUSY) ? 1 : 0;
	} else {
		busy = 0;
	}
	clp->ap_busy = busy;
	/* Link it in */
	listp->next = lap->listp;
	lap->listp = listp;

	di_devfs_path_free(client_path);
	S_FREE(devpath);

	/* now return with ok status with ldata. */
	lap->ret = FPCFGA_OK;
	return (FPCFGA_OK);
}

/*
 * Initialize the cfga_list_data struct for an accessible device
 * from g_get_dev_list().
 *
 * Input:  fca port ldata.
 * Output: device cfga_list_data.
 *
 */
static fpcfga_ret_t
init_ldata_for_accessible_dev(const char *dyncomp, uchar_t inq_type,
							fpcfga_list_t *lap)
{
	ldata_list_t *listp = NULL;
	cfga_list_data_t *clp = NULL;
	int i;

	listp = calloc(1, sizeof (ldata_list_t));
	if (listp == NULL) {
		lap->l_errno = errno;
		return (FPCFGA_LIB_ERR);
	}

	clp = &listp->ldata;

	assert(dyncomp != NULL);

	/* Create logical and physical ap_id */
	(void) snprintf(clp->ap_log_id, sizeof (clp->ap_log_id), "%s%s%s",
		lap->xport_logp, DYN_SEP, dyncomp);

	(void) snprintf(clp->ap_phys_id, sizeof (clp->ap_phys_id), "%s%s%s",
		lap->apidp->xport_phys, DYN_SEP, dyncomp);

	clp->ap_class[0] = '\0'; /* Filled in by libcfgadm */
	clp->ap_r_state = lap->xport_rstate;
	clp->ap_o_state = CFGA_STAT_UNCONFIGURED;
	clp->ap_cond = CFGA_COND_UNKNOWN;
	clp->ap_busy = 0;
	clp->ap_status_time = (time_t)-1;
	clp->ap_info[0] = '\0';
	for (i = 0; i < N_DEVICE_TYPES; i++) {
		if (inq_type == device_list[i].itype) {
			(void) snprintf(clp->ap_type, sizeof (clp->ap_type),
			"%s", (char *)device_list[i].name);
		break;
		}
	}
	if (i == N_DEVICE_TYPES) {
		if (inq_type == ERR_INQ_DTYPE) {
			clp->ap_cond = CFGA_COND_FAILED;
			snprintf(clp->ap_type, sizeof (clp->ap_type), "%s",
			    (char *)GET_MSG_STR(ERR_UNAVAILABLE));
		} else {
			(void) snprintf(clp->ap_type, sizeof (clp->ap_type),
				"%s", "unknown");
		}
	}

	/* Link it in */
	(void) insert_ldata_to_ldatalist(dyncomp, NULL, listp, &(lap->listp));

	return (FPCFGA_OK);
}

/*
 * Initialize the cfga_list_data struct for an accessible FCP SCSI LUN device
 * from the report lun data.
 *
 * Input:  fca port ldata. report lun info
 * Output: device cfga_list_data.
 *
 */
static fpcfga_ret_t
init_ldata_for_accessible_FCP_dev(
	const char *port_wwn,
	int num_luns,
	struct report_lun_resp *resp_buf,
	fpcfga_list_t	*lap,
	int *l_errnop)
{
	ldata_list_t *listp = NULL, *listp_start = NULL, *listp_end = NULL,
		*prevlp = NULL, *curlp = NULL, *matchp_start = NULL,
		*matchp_end = NULL;
	cfga_list_data_t *clp = NULL;
	char *dyn = NULL, *dyncomp = NULL;
	uchar_t *lun_string;
	uint16_t lun_num;
	int i, j, str_ret;
	fpcfga_ret_t ret;
	char dtype[CFGA_TYPE_LEN];
	struct scsi_inquiry *inq_buf;
	uchar_t	peri_qual;
	cfga_cond_t cond = CFGA_COND_UNKNOWN;
	uchar_t lun_num_raw[SAM_LUN_SIZE];

	/* when number of lun is 0 it is not an error. so just return ok. */
	if (num_luns == 0) {
		return (FPCFGA_OK);
	}

	for (i = 0; i < num_luns; i++) {
	    lun_string = (uchar_t *)&(resp_buf->lun_string[i]);
	    memcpy(lun_num_raw, lun_string, sizeof (lun_num_raw));
	    if ((ret = get_standard_inq_data(lap->apidp->xport_phys, port_wwn,
		lun_num_raw, &inq_buf, l_errnop))
		!= FPCFGA_OK) {
		if (ret == FPCFGA_FCP_TGT_SEND_SCSI_FAILED) {
			(void) strlcpy(dtype,
			(char *)GET_MSG_STR(ERR_UNAVAILABLE), CFGA_TYPE_LEN);
			cond = CFGA_COND_FAILED;
		} else {
			S_FREE(inq_buf);
			return (FPCFGA_LIB_ERR);
		}
	    } else {
		peri_qual = inq_buf->inq_dtype & FP_PERI_QUAL_MASK;
		/*
		 * peripheral qualifier is not 0 so the device node should not
		 * included in the ldata list. There should not be a device
		 * node for the lun either.
		 */
		if (peri_qual != DPQ_POSSIBLE) {
			S_FREE(inq_buf);
			continue;
		}
		*dtype = '\0';
		for (j = 0; j < N_DEVICE_TYPES; j++) {
		    if ((inq_buf->inq_dtype & DTYPE_MASK)
				== device_list[j].itype) {
			(void) strlcpy(dtype, (char *)device_list[j].name,
					CFGA_TYPE_LEN);
			break;
		    }
		}
		if (*dtype == '\0') {
			(void) strlcpy(dtype,
				(char *)device_list[DTYPE_UNKNOWN_INDEX].name,
				CFGA_TYPE_LEN);
		}
	    }
		/*
		 * Followed FCP driver for getting lun number from report
		 * lun data.
		 * According to SAM-2 there are multiple address method for
		 * FCP SCIS LUN.  Logincal unit addressing, peripheral device
		 * addressing, flat space addressing, and extended logical
		 * unit addressing.
		 *
		 * as of 11/2001 FCP supports logical unit addressing and
		 * peripheral device addressing even thoough 3 defined.
		 * SSFCP_LUN_ADDRESSING 0x80
		 * SSFCP_PD_ADDRESSING 0x00
		 * SSFCP_VOLUME_ADDRESSING 0x40
		 *
		 * the menthod below is used by FCP when (lun_string[0] & 0xC0)
		 * is either SSFCP_LUN_ADDRESSING or SSFCP_PD_ADDRESSING mode.
		 */
	    lun_num = ((lun_string[0] & 0x3F) << 8) | lun_string[1];
	    listp = calloc(1, sizeof (ldata_list_t));
	    if (listp == NULL) {
		*l_errnop = errno;
		list_free(&listp_start);
		return (FPCFGA_LIB_ERR);
	    }

	    clp = &listp->ldata;
		/* Create logical and physical ap_id */
	    (void) snprintf(clp->ap_log_id, sizeof (clp->ap_log_id),
		"%s%s%s%s%d", lap->xport_logp, DYN_SEP, port_wwn,
		LUN_COMP_SEP, lun_num);
	    (void) snprintf(clp->ap_phys_id, sizeof (clp->ap_phys_id),
		"%s%s%s%s%d", lap->apidp->xport_phys, DYN_SEP, port_wwn,
		LUN_COMP_SEP, lun_num);
	    (void) strncpy(clp->ap_type, dtype, strlen(dtype));
	    clp->ap_class[0] = '\0'; /* Filled in by libcfgadm */
	    clp->ap_r_state = lap->xport_rstate;
	    clp->ap_o_state = CFGA_STAT_UNCONFIGURED;
	    clp->ap_cond = cond;
	    clp->ap_busy = 0;
	    clp->ap_status_time = (time_t)-1;
	    clp->ap_info[0] = '\0';
	    if (listp_start == NULL) {
		listp_start = listp;
	    } else {
		if ((ret = insert_FCP_dev_ldata(
			port_wwn, lun_num, listp,
			&listp_start)) != FPCFGA_OK) {
			list_free(&listp_start);
			return (ret);
		}
	    }
	    listp = NULL;
	    S_FREE(inq_buf);
	}

	/*
	 * list data can be null when device peripheral qualifier is not 0
	 * for any luns.  Return ok to continue.
	 */
	if (listp_start == NULL) {
		return (FPCFGA_OK);
	}
	/*
	 * get the end of list for later uses.
	 */
	curlp = listp_start->next;
	prevlp = listp_start;
	while (curlp) {
		prevlp = curlp;
		curlp = curlp->next;
	}
	listp_end = prevlp;

	/*
	 * if there is no list data just return the FCP dev list.
	 * Normally this should not occur since list data should
	 * be created through g_get_dev_list().
	 */
	if (lap->listp == NULL) {
		lap->listp = listp_start;
		for (listp = listp_start; listp != NULL; listp = listp->next) {
			listp->ldata.ap_cond = CFGA_COND_FAILING;
		}
		return (FPCFGA_OK);
	}

	dyn = GET_DYN(lap->listp->ldata.ap_phys_id);
	if ((dyn != NULL) && ((dyncomp = DYN_TO_DYNCOMP(dyn)) != NULL)) {
		if ((str_ret = strncmp(dyncomp, port_wwn, WWN_SIZE*2)) == 0) {
			matchp_start = matchp_end = lap->listp;
			while (matchp_end->next != NULL) {
				dyn = GET_DYN(
					matchp_end->next->ldata.ap_phys_id);
				if ((dyn != NULL) &&
				((dyncomp = DYN_TO_DYNCOMP(dyn)) != NULL)) {
					if ((str_ret = strncmp(dyncomp,
						port_wwn, WWN_SIZE*2)) == 0) {
						matchp_end = matchp_end->next;
					} else {
						break;
					}
				} else {
					break;
				}
			}
			/* fillup inqdtype */
			for (listp = listp_start; listp != NULL;
					listp = listp->next) {
				listp->ldata.ap_cond =
					lap->listp->ldata.ap_cond;
			}
			/* link the new elem of lap->listp. */
			listp_end->next = matchp_end->next;
			/* free the one matching wwn. */
			matchp_end->next = NULL;
			list_free(&matchp_start);
			/* link lap->listp to listp_start. */
			lap->listp = listp_start;
			return (FPCFGA_OK);
		} else if (str_ret > 0) {
			for (listp = listp_start; listp != NULL;
					listp = listp->next) {
				listp->ldata.ap_cond = CFGA_COND_FAILING;
			}
			listp_end->next = lap->listp->next;
			lap->listp = listp_start;
			return (FPCFGA_OK);
		}
	}

	prevlp = lap->listp;
	curlp = lap->listp->next;

	dyn = dyncomp = NULL;
	while (curlp != NULL) {
		dyn = GET_DYN(curlp->ldata.ap_phys_id);
		if ((dyn != NULL) &&
			((dyncomp = DYN_TO_DYNCOMP(dyn)) != NULL)) {
			if ((str_ret = strncmp(dyncomp, port_wwn,
					WWN_SIZE*2)) == 0) {
				matchp_start = matchp_end = curlp;
				while (matchp_end->next != NULL) {
					dyn = GET_DYN(
					matchp_end->next->ldata.ap_phys_id);
					if ((dyn != NULL) &&
						((dyncomp = DYN_TO_DYNCOMP(dyn))
						!= NULL)) {
						if ((str_ret = strncmp(dyncomp,
							port_wwn, WWN_SIZE*2))
							== 0) {
							matchp_end =
							matchp_end->next;
						} else {
							break;
						}
					} else {
						break;
					}
				}
				for (listp = listp_start; listp != NULL;
						listp = listp->next) {
				    listp->ldata.ap_cond = curlp->ldata.ap_cond;
				}
				/* link the next elem to listp_end. */
				listp_end->next = matchp_end->next;
				/* link prevlp to listp_start to drop curlp. */
				prevlp->next = listp_start;
				/* free matching pwwn elem. */
				matchp_end->next = NULL;
				list_free(&matchp_start);
				return (FPCFGA_OK);
			} else if (str_ret > 0) {
				for (listp = listp_start; listp != NULL;
						listp = listp->next) {
					/*
					 * Dev not found from accessible
					 * fc dev list but the node should
					 * exist. Set to failing cond now
					 * and check the node state later.
					 */
				    listp->ldata.ap_cond = CFGA_COND_FAILING;
				}
				/* keep the cur elem by linking to list_end. */
				listp_end->next = curlp;
				prevlp->next = listp_start;
				return (FPCFGA_OK);
			}
		}
		dyn = dyncomp = NULL;
		prevlp = curlp;
		curlp = curlp->next;
	}

	prevlp->next = listp_start;
	for (listp = listp_start; listp != NULL; listp = listp->next) {
		listp->ldata.ap_cond = CFGA_COND_FAILING;
	}

	return (FPCFGA_OK);

}

/* fill in device type, vid, pid from properties */
static void
get_hw_info(di_node_t node, cfga_list_data_t *clp)
{
	char *cp = NULL;
	char *inq_vid, *inq_pid;
	int i;

	/*
	 * if the type is not previously assigned with valid SCSI device type
	 * check devinfo to find the type.
	 * once device is configured it should have a valid device type.
	 * device node is configured but no valid device type is found
	 * the type will be set to unavailable.
	 */
	if (clp->ap_type != NULL) {
		/*
		 * if the type is not one of defined SCSI device type
		 * check devinfo to find the type.
		 *
		 * Note: unknown type is not a valid device type.
		 *	It is added in to the device list table to provide
		 *	constant string of "unknown".
		 */
	    for (i = 0; i < (N_DEVICE_TYPES -1); i++) {
		if (strncmp((char *)clp->ap_type, (char *)device_list[i].name,
			sizeof (clp->ap_type)) == 0) {
			break;
		}
	    }
	    if (i == (N_DEVICE_TYPES - 1)) {
		cp = (char *)get_device_type(node);
		if (cp == NULL) {
			cp = (char *)GET_MSG_STR(ERR_UNAVAILABLE);
		}
		(void) snprintf(clp->ap_type, sizeof (clp->ap_type), "%s",
			S_STR(cp));
	    }
	} else {
		cp = (char *)get_device_type(node);
		if (cp == NULL) {
			cp = (char *)GET_MSG_STR(ERR_UNAVAILABLE);
		}
		(void) snprintf(clp->ap_type, sizeof (clp->ap_type), "%s",
			S_STR(cp));
	}

	/*
	 * Fill in vendor and product ID.
	 */
	if ((di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    "inquiry-product-id", &inq_pid) == 1) &&
	    (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    "inquiry-vendor-id", &inq_vid) == 1)) {
		(void) snprintf(clp->ap_info, sizeof (clp->ap_info),
		    "%s %s", inq_vid, inq_pid);
	}
}

/*
 * Get dtype from "inquiry-device-type" property. If not present,
 * derive it from minor node type
 */
static const char *
get_device_type(di_node_t node)
{
	char *name = NULL;
	int *inq_dtype;
	int i;

	if (node == DI_NODE_NIL) {
		return (NULL);
	}

	/* first, derive type based on inquiry property */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "inquiry-device-type",
	    &inq_dtype) != -1) {
		int itype = (*inq_dtype) & DTYPE_MASK;

		for (i = 0; i < N_DEVICE_TYPES; i++) {
			if (itype == device_list[i].itype) {
				name = (char *)device_list[i].name;
				break;
			}
		}
		/*
		 * when found to be unknown type, set name to null to check
		 * device minor node type.
		 */
		if (i == (N_DEVICE_TYPES - 1)) {
			name = NULL;
		}
	}

	/* if property fails, use minor nodetype */
	if (name == NULL) {
		char *nodetype;
		di_minor_t minor = di_minor_next(node, DI_MINOR_NIL);

		if ((minor != DI_MINOR_NIL) &&
		    ((nodetype = di_minor_nodetype(minor)) != NULL)) {
			for (i = 0; i < N_DEVICE_TYPES; i++) {
				if (device_list[i].ntype &&
				    (strcmp(nodetype, device_list[i].ntype)
				    == 0)) {
					name = (char *)device_list[i].name;
					break;
				}
			}
		}
	}

	return (name);
}

/* Transform list data to stat data */
fpcfga_ret_t
list_ext_postprocess(
	ldata_list_t		**llpp,
	int			nelem,
	cfga_list_data_t	**ap_id_list,
	int			*nlistp,
	char			**errstring)
{
	cfga_list_data_t *ldatap = NULL;
	ldata_list_t *tmplp = NULL;
	int i = -1;

	*ap_id_list = NULL;
	*nlistp = 0;

	if (*llpp == NULL || nelem < 0) {
		return (FPCFGA_LIB_ERR);
	}

	if (nelem == 0) {
		return (FPCFGA_APID_NOEXIST);
	}

	ldatap = calloc(nelem, sizeof (cfga_list_data_t));
	if (ldatap == NULL) {
		cfga_err(errstring, errno, ERR_LIST, 0);
		return (FPCFGA_LIB_ERR);
	}

	/* Extract the list_data structures from the linked list */
	tmplp = *llpp;
	for (i = 0; i < nelem && tmplp != NULL; i++) {
		ldatap[i] = tmplp->ldata;
		tmplp = tmplp->next;
	}

	if (i < nelem || tmplp != NULL) {
		S_FREE(ldatap);
		return (FPCFGA_LIB_ERR);
	}

	*nlistp = nelem;
	*ap_id_list = ldatap;

	return (FPCFGA_OK);
}

/*
 * Convert bus state to receptacle state
 */
static cfga_stat_t
xport_devinfo_to_recep_state(uint_t xport_di_state)
{
	cfga_stat_t rs;

	switch (xport_di_state) {
	case DI_BUS_QUIESCED:
	case DI_BUS_DOWN:
		rs = CFGA_STAT_DISCONNECTED;
		break;
	/*
	 * NOTE: An explicit flag for active should probably be added to
	 * libdevinfo.
	 */
	default:
		rs = CFGA_STAT_CONNECTED;
		break;
	}

	return (rs);
}

/*
 * Convert device state to occupant state
 * if driver is attached the node is configured.
 * if offline or down the node is unconfigured.
 * if only driver detached it is none state which is treated the same
 * way as configured state.
 */
static cfga_stat_t
dev_devinfo_to_occupant_state(uint_t dev_di_state)
{
	/* Driver attached ? */
	if ((dev_di_state & DI_DRIVER_DETACHED) != DI_DRIVER_DETACHED) {
		return (CFGA_STAT_CONFIGURED);
	}

	if ((dev_di_state & DI_DEVICE_OFFLINE) == DI_DEVICE_OFFLINE ||
	    (dev_di_state & DI_DEVICE_DOWN) == DI_DEVICE_DOWN) {
		return (CFGA_STAT_UNCONFIGURED);
	} else {
		return (CFGA_STAT_NONE);
	}
}

/*
 * Wrapper routine for inserting ldata to make an sorted ldata list.
 *
 * When show_FCP_dev option is given insert_FCP_dev_ldata() is called.
 * Otherwise insert_fc_dev_ldata() is called.
 */
static fpcfga_ret_t
insert_ldata_to_ldatalist(
	const char *port_wwn,
	int *lun_nump,
	ldata_list_t *listp,
	ldata_list_t **ldatapp)
{

	if (lun_nump == NULL) {
		return (insert_fc_dev_ldata(port_wwn, listp, ldatapp));
	} else {
		return
		(insert_FCP_dev_ldata(port_wwn, *lun_nump, listp, ldatapp));
	}
}

/*
 * Insert an input ldata to ldata list to make sorted ldata list.
 */
static fpcfga_ret_t
insert_fc_dev_ldata(
	const char *port_wwn,
	ldata_list_t *listp,
	ldata_list_t **ldatapp)
{
	ldata_list_t *prevlp = NULL, *curlp = NULL;
	char *dyn = NULL, *dyncomp = NULL;

	if (*ldatapp == NULL) {
		*ldatapp = listp;
		return (FPCFGA_OK);
	}

	dyn = GET_DYN((*ldatapp)->ldata.ap_phys_id);
	if (dyn != NULL) dyncomp = DYN_TO_DYNCOMP(dyn);
	if ((dyncomp != NULL) &&
		(strncmp(dyncomp, port_wwn, WWN_SIZE*2) >= 0)) {
			listp->next = *ldatapp;
			*ldatapp = listp;
			return (FPCFGA_OK);
	}
	/* else continue */

	prevlp = *ldatapp;
	curlp = (*ldatapp)->next;

	dyn = dyncomp = NULL;
	while (curlp != NULL) {
		dyn = GET_DYN(curlp->ldata.ap_phys_id);
		if (dyn != NULL) dyncomp = DYN_TO_DYNCOMP(dyn);
		if ((dyncomp != NULL) &&
				(strncmp(dyncomp, port_wwn, WWN_SIZE*2) >= 0)) {
			listp->next = prevlp->next;
			prevlp->next = listp;
			return (FPCFGA_OK);
		}
		dyn = dyncomp = NULL;
		prevlp = curlp;
		curlp = curlp->next;
	}

	/* add the ldata to the end of the list. */
	prevlp->next = listp;
	return (FPCFGA_OK);
}

/*
 * Insert an input ldata to ldata list to make sorted ldata list.
 */
static fpcfga_ret_t
insert_FCP_dev_ldata(
	const char *port_wwn,
	int lun_num,
	ldata_list_t *listp,
	ldata_list_t **ldatapp)
{
	ldata_list_t *prevlp = NULL, *curlp = NULL;
	char *dyn = NULL, *dyncomp = NULL;
	char *lun_dyn = NULL, *lunp = NULL;

	if (*ldatapp == NULL) {
		*ldatapp = listp;
		return (FPCFGA_OK);
	}

	dyn = GET_DYN((*ldatapp)->ldata.ap_phys_id);
	if (dyn != NULL) dyncomp = DYN_TO_DYNCOMP(dyn);
	if ((dyncomp != NULL) &&
		(strncmp(dyncomp, port_wwn, WWN_SIZE*2) == 0)) {
		lun_dyn = GET_LUN_DYN(dyncomp);
		if (lun_dyn != NULL) {
			lunp = LUN_DYN_TO_LUNCOMP(lun_dyn);
			if ((atoi(lunp)) >= lun_num) {
				listp->next = *ldatapp;
				*ldatapp = listp;
				return (FPCFGA_OK);
			}
		}
	} else if ((dyncomp != NULL) &&
			(strncmp(dyncomp, port_wwn, WWN_SIZE*2) > 0)) {
		listp->next = *ldatapp;
		*ldatapp = listp;
		return (FPCFGA_OK);
	}

	prevlp = *ldatapp;
	curlp = (*ldatapp)->next;

	dyn = dyncomp = NULL;
	lun_dyn = lunp = NULL;
	while (curlp != NULL) {
		dyn = GET_DYN(curlp->ldata.ap_phys_id);
		if (dyn != NULL) dyncomp = DYN_TO_DYNCOMP(dyn);

		if ((dyncomp != NULL) &&
				(strncmp(dyncomp, port_wwn, WWN_SIZE*2) == 0)) {
			lun_dyn = GET_LUN_DYN(dyncomp);
			if (lun_dyn != NULL) {
				lunp = LUN_DYN_TO_LUNCOMP(lun_dyn);
				if ((atoi(lunp)) >= lun_num) {
					listp->next = prevlp->next;
					prevlp->next = listp;
					return (FPCFGA_OK);
				}
			}
			/* else continue */
		} else if ((dyncomp != NULL) &&
				(strncmp(dyncomp, port_wwn, WWN_SIZE*2) > 0)) {
			listp->next = prevlp->next;
			prevlp->next = listp;
			return (FPCFGA_OK);
		}
		/* else continue */

		dyn = dyncomp = NULL;
		lun_dyn = lunp = NULL;
		prevlp = curlp;
		curlp = curlp->next;
	}

	/* add the ldata to the end of the list. */
	prevlp->next = listp;
	return (FPCFGA_OK);
}

/*
 * This function will return the dtype for the given device
 * It will first issue a report lun to lun 0 and then it will issue a SCSI
 * Inquiry to the first lun returned by report luns.
 *
 * If everything is successful, the dtype will be returned with the peri
 * qualifier masked out.
 *
 * If either the report lun or the scsi inquiry fails, we will first check
 * the return status.  If the return status is SCSI_DEVICE_NOT_TGT, then
 * we will assume this is a remote HBA and return an UNKNOWN DTYPE
 * for all other failures, we will return a dtype of ERR_INQ_DTYPE
 */
static uchar_t
get_inq_dtype(char *xport_phys, char *dyncomp, HBA_HANDLE handle,
    HBA_PORTATTRIBUTES *portAttrs, HBA_PORTATTRIBUTES *discPortAttrs) {
	HBA_STATUS		    status;
	report_lun_resp_t	    *resp_buf;
	int			    num_luns = 0, ret, l_errno;
	uchar_t			    *lun_string;
	uint64_t		    lun = 0;
	struct scsi_inquiry	    inq;
	struct scsi_extended_sense  sense;
	HBA_UINT8		    scsiStatus;
	uint32_t		    inquirySize = sizeof (inq);
	uint32_t		    senseSize = sizeof (sense);

	memset(&inq, 0, sizeof (inq));
	memset(&sense, 0, sizeof (sense));
	if ((ret = get_report_lun_data(xport_phys, dyncomp,
			    &num_luns, &resp_buf, &sense, &l_errno))
	    != FPCFGA_OK) {
		/*
		 * Checking the sense key data as well as the additional
		 * sense key.  The SES Node is not required to repond
		 * to Report LUN.  In the case of Minnow, the SES node
		 * returns with KEY_ILLEGAL_REQUEST and the additional
		 * sense key of 0x20.  In this case we will blindly
		 * send the SCSI Inquiry call to lun 0
		 *
		 * if we get any other error we will set the inq_type
		 * appropriately
		 */
		if ((sense.es_key == KEY_ILLEGAL_REQUEST) &&
		    (sense.es_add_code == 0x20)) {
			lun = 0;
		} else {
			if (ret == FPCFGA_FCP_SEND_SCSI_DEV_NOT_TGT) {
				inq.inq_dtype = DTYPE_UNKNOWN;
			} else {
				inq.inq_dtype = ERR_INQ_DTYPE;
			}
			return (inq.inq_dtype);
		}
	} else {
		/* send the inquiry to the first lun */
		lun_string = (uchar_t *)&(resp_buf->lun_string[0]);
		memcpy(&lun, lun_string, sizeof (lun));
		S_FREE(resp_buf);
	}

	memset(&sense, 0, sizeof (sense));
	status = HBA_ScsiInquiryV2(handle,
	    portAttrs->PortWWN, discPortAttrs->PortWWN, lun, 0, 0,
	    &inq, &inquirySize, &scsiStatus, &sense, &senseSize);
	if (status == HBA_STATUS_OK) {
		inq.inq_dtype = inq.inq_dtype & DTYPE_MASK;
	} else if (status == HBA_STATUS_ERROR_NOT_A_TARGET) {
		inq.inq_dtype = DTYPE_UNKNOWN;
	} else {
		inq.inq_dtype = ERR_INQ_DTYPE;
	}
	return (inq.inq_dtype);
}
