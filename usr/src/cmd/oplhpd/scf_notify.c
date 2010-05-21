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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <config_admin.h>
#include <strings.h>
#include <syslog.h>
#include <libsysevent.h>
#include <libdevinfo.h>
#include <libnvpair.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysevent/dr.h>
#include <sys/scfd/opcioif.h>


/* Macros */
#define	SCF_DEV_DIR  "/devices"	/* device base dir */



/*
 * Connection for SCF driver
 */

/* Check the availability of SCF driver */
static int	scfdrv_enable = 0;


/* Device for SCF Driver */
#define	SCFIOCDEV	"/devices/pseudo/scfd@200:rasctl"
#define	SCFRETRY	10
#define	SCFIOCWAIT	3
#define	SCFDATA_DEV_INFO	32
#define	SCFDATA_APID    1054

/*
 * Data for XSCF
 * Note the size of the ap_id must be SCFDATA_APID for proper data alignment
 * for the ioctl. The SCF has a corresponding data structure which is matched
 * here.
 */
typedef struct {
	char		ap_id[SCFDATA_APID];
	uint8_t		ioua;
	uint8_t		vflag;
	uint32_t	r_state;
	uint32_t	o_state;
	uint64_t	tstamp;
	char		dev_name[SCFDATA_DEV_INFO];
	char		dev_model[SCFDATA_DEV_INFO];
} scf_slotinfo_t;

/*
 * Data for scf notification of state changes.
 * pci_name is an ap_id phys path for the hot pluggable pci device.
 * r_state is the recepticle state.
 * o_state is the occupant state.
 * cache_fmri_str is a string representation of an fmri in the rsrc cache.
 * fmri_asru_str is the asru for an fmri which is found in the topology.
 * found is a boolean indicating whether the device was found in the topology.
 */
typedef struct {
	char		pci_name[MAXPATHLEN];
	uint32_t	r_state;
	uint32_t	o_state;
} pci_notify_t;

/*
 * Function Prototypes
 */
void scf_get_slotinfo(char *ap_id, cfga_stat_t *o_state,
		cfga_stat_t *r_state);
static int scf_get_pci_name(const char *ap_phys_id, char *pci_name);
static int scf_get_devinfo(char *dev_name, char *dev_model,
		const char *pci_name);
void notify_scf_of_hotplug(sysevent_t *ev);


/*
 * Error report utility for libcfgadm functions
 */
void
config_error(cfga_err_t err, const char *func_name, const char *errstr,
    const char *ap_id)
{
	const char *ep;

	ep = config_strerror(err);
	if (ep == NULL) {
		ep = "configuration administration unknown error";
	}

	if (errstr != NULL && *errstr != '\0') {
		syslog(LOG_DEBUG, "%s: %s (%s), ap_id = %s\n",
		    func_name, ep, errstr, ap_id);
	} else {
		syslog(LOG_DEBUG, "%s: %s , ap_id = %s\n",
		    func_name, ep, ap_id);
	}

}

/*
 * Get the slot status.
 */
void
scf_get_slotinfo(char *ap_pid, cfga_stat_t *r_state, cfga_stat_t *o_state)
{
	cfga_err_t		rv;		/* return value */
	cfga_list_data_t	*stat = NULL;	/* slot info. */
	int			nlist;		/* number of slot */
	char			*errstr = NULL;	/* error code */

	/*
	 * Get the attachment point information.
	 */
	rv = config_list_ext(1, (char *const *)&ap_pid, &stat, &nlist, NULL,
	    NULL, &errstr, 0);

	if (rv != CFGA_OK) {
		config_error(rv, "config_list_ext", errstr, ap_pid);
		goto out;
	}
	assert(nlist == 1);

	syslog(LOG_DEBUG, "\n"
	    "ap_log_id       = %.*s\n"
	    "ap_phys_id      = %.*s\n"
	    "ap_r_state      = %d\n"
	    "ap_o_state      = %d\n"
	    "ap_cond         = %d\n"
	    "ap_busy         = %6d\n"
	    "ap_status_time  = %s"
	    "ap_info         = %.*s\n"
	    "ap_type         = %.*s\n",
	    sizeof (stat->ap_log_id), stat->ap_log_id,
	    sizeof (stat->ap_phys_id), stat->ap_phys_id,
	    stat->ap_r_state,
	    stat->ap_o_state,
	    stat->ap_cond,
	    stat->ap_busy,
	    asctime(localtime(&stat->ap_status_time)),
	    sizeof (stat->ap_info), stat->ap_info,
	    sizeof (stat->ap_type), stat->ap_type);

	/* Copy the slot status. */
	*r_state = stat->ap_r_state;
	*o_state = stat->ap_o_state;

out:
	if (stat) {
		free(stat);
	}

	if (errstr) {
		free(errstr);
	}
}


/*
 * Get the pci_name
 */
static int
scf_get_pci_name(const char *ap_phys_id, char *pci_name)
{
	char		*pci_name_ptr;  /* pci node name pointer */
	char		*ap_lid_ptr;    /* logical ap_id pointer */

	int		devices_len;	/* "/device" length */
	int		pci_name_len;	/* pci node name length */
	int		ap_lid_len;	/* logical ap_id pointer */


	/*
	 * Pick pci node name up from physical ap_id string.
	 * "/devices/pci@XX,YYYYYY:PCI#ZZ"
	 */

	/* Check the length of physical ap_id string */
	if (strlen(ap_phys_id) >= MAXPATHLEN) {
		return (-1); /* changed */
	}

	/* Check the pci node name start, which is after "/devices". */
	if (strncmp(SCF_DEV_DIR, ap_phys_id, strlen(SCF_DEV_DIR)) == 0) {
		devices_len = strlen(SCF_DEV_DIR);
	} else {
		devices_len = 0;
	}
	/* Check the pci node name end, which is before ":". */
	if ((ap_lid_ptr = strchr(ap_phys_id, ':')) == NULL) {
		ap_lid_len = 0;
	} else {
		ap_lid_len = strlen(ap_lid_ptr);
	}

	/*
	 * Get the head of pci node name string.
	 * Get the length of pci node name string.
	 */
	pci_name_ptr = (char *)ap_phys_id + devices_len;
	pci_name_len = strlen(ap_phys_id) - devices_len - ap_lid_len;

	/* Copy the pci node name. */
	(void) strncpy(pci_name, pci_name_ptr, pci_name_len);
	pci_name[pci_name_len] = '\0';

	syslog(LOG_DEBUG, "pci device path = %s\n", pci_name);

	return (0);

}


/*
 * Get the property of name and model.
 */
static int
scf_get_devinfo(char *dev_name, char *dev_model, const char *pci_name)
{
	char		*tmp;		/* tmp */
	unsigned int    devid, funcid;  /* bus addr */
	unsigned int    sdevid, sfuncid; /* sibling bus addr */

	di_node_t	pci_node;	/* pci device node */
	di_node_t	child_node;	/* child level node */
	di_node_t	ap_node;	/* hotplugged node */

	pci_node = ap_node = DI_NODE_NIL;


	/*
	 * Take the snap shot of device node configuration,
	 * to get the names of node and model.
	 */
	if ((pci_node = di_init(pci_name, DINFOCPYALL)) == DI_NODE_NIL) {
		syslog(LOG_NOTICE,
		    "Could not get dev info snapshot. errno=%d\n",
		    errno);
		return (-1); /* changed */
	}

	/*
	 * The new child under pci node should be added. Then the
	 * device and model names should be passed, which is in the
	 * node with the minimum bus address.
	 *
	 * - Move to the child node level.
	 * - Search the node with the minimum bus addrress in the
	 *   sibling list.
	 */
	if ((child_node = di_child_node(pci_node)) == DI_NODE_NIL) {
		syslog(LOG_NOTICE, "No slot device in snapshot\n");
		goto out;
	}

	ap_node = child_node;
	if ((tmp = di_bus_addr(child_node)) != NULL) {
		if (sscanf(tmp, "%x,%x", &devid, &funcid) != 2) {
			funcid = 0;
			if (sscanf(tmp, "%x", &devid) != 1) {
				devid = 0;
				syslog(LOG_DEBUG,
				    "no bus addrress on device\n");
				goto one_child;
			}
		}
	}

	while ((child_node = di_sibling_node(child_node)) != NULL) {
		if ((tmp = di_bus_addr(child_node)) == NULL) {
			ap_node = child_node;
			break;
		}

		if (sscanf(tmp, "%x,%x", &sdevid, &sfuncid) == 2) {
			/*
			 * We do need to update the child node
			 *   Case 1. devid > sdevid
			 *   Case 2. devid == sdevid && funcid > sfuncid
			 */
			if ((devid > sdevid) || ((devid == sdevid) &&
			    (funcid > sfuncid))) {
				ap_node = child_node;
				devid   = sdevid;
				funcid  = sfuncid;
			}

		} else if (sscanf(tmp, "%x", &sdevid) == 1) {
			/*
			 * We do need to update the child node
			 *   Case 1. devid >= sdevid
			 */
			if (devid >= sdevid) {
				ap_node = child_node;
				devid   = sdevid;
				funcid  = 0;
			}

		} else {
			ap_node = child_node;
			break;
		}
	}

one_child:
	/*
	 * Get the name and model properties.
	 */
	tmp = di_node_name(ap_node);
	if (tmp != NULL) {
		(void) strlcpy((char *)dev_name, tmp, SCFDATA_DEV_INFO);
	}

	tmp = NULL;
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, ap_node, "model", &tmp) > 0) {
		if (tmp != NULL) {
			(void) strlcpy((char *)dev_model, tmp,
			    SCFDATA_DEV_INFO);
		}
	}

	syslog(LOG_DEBUG, "device: %s@%x,%x [model: %s]\n",
	    dev_name, devid, funcid, dev_model);

out:
	di_fini(pci_node);
	return (0); /* added */
}


void
notify_scf_of_hotplug(sysevent_t *ev)
{
	int		rc;			/* return code */

	/* For libsysevent */
	char		*vendor = NULL;		/* event vendor */
	char		*publisher = NULL;	/* event publisher */
	nvlist_t	*ev_attr_list = NULL;	/* attribute */

	/* For libcfgadm */
	char		*ap_id = NULL;		/* attachment point */
	cfga_stat_t	r_state, o_state;	/* slot status */

	/* For libdevinfo */
	char		dev_name[SCFDATA_DEV_INFO];	/* name property */
	char		dev_model[SCFDATA_DEV_INFO];	/* model property */

	/* Data for SCF */
	pci_notify_t pci_notify_dev_info;
	scfsetphpinfo_t scfdata;
	scf_slotinfo_t  sdata;
	time_t sec;			/* hotplug event current time */
	int		fd, retry = 0;


	/*
	 * Initialization
	 */
	r_state = o_state = 0;
	dev_name[0] = dev_model[0] = '\0';
	(void) memset((void *)&pci_notify_dev_info, 0, sizeof (pci_notify_t));

	/* Get the current time when event picked up. */
	sec = time(NULL);

	/*
	 * Check the vendor and publisher name of event.
	 */
	vendor = sysevent_get_vendor_name(ev);
	publisher = sysevent_get_pub_name(ev);
	/* Check the vendor is "SUNW" */
	if (strncmp("SUNW", vendor, strlen("SUNW")) != 0) {
		/* Just return when not from SUNW */
		syslog(LOG_DEBUG, "Event is not a SUNW vendor event\n");
		goto out;
	}

	/* Enough to check "px" and "pcieb" at the beginning of string */
	if (strncmp("px", publisher, strlen("px")) != 0 &&
	    strncmp("pcieb", publisher, strlen("pcieb")) != 0) {
		/* Just return when not px event */
		syslog(LOG_DEBUG, "Event is not a px publisher event\n");
		goto out;
	}

	/*
	 * Get attribute values of attachment point.
	 */
	if (sysevent_get_attr_list(ev, &ev_attr_list) != 0) {
		/* could not get attribute list */
		syslog(LOG_DEBUG, "Could not get attribute list\n");
		goto out;
	}
	if (nvlist_lookup_string(ev_attr_list, DR_AP_ID, &ap_id) != 0) {
		/* could not find the attribute from the list */
		syslog(LOG_DEBUG, "Could not get ap_id in attribute list\n");
		goto out;
	}

	if (ap_id == NULL || strlen(ap_id) == 0) {
		syslog(LOG_DEBUG, "ap_id is NULL\n");
		goto out;
	} else {
		/*
		 * Get the slot status.
		 */
		syslog(LOG_DEBUG, "ap_id = %s\n", ap_id);
		scf_get_slotinfo(ap_id, &r_state, &o_state);
	}

	syslog(LOG_DEBUG, "r_state = %d\n", r_state);
	syslog(LOG_DEBUG, "o_state = %d\n", o_state);

	/*
	 * Get the pci name which is needed for both the configure and
	 * unconfigure.
	 */
	rc = scf_get_pci_name(ap_id, (char *)pci_notify_dev_info.pci_name);
	if (rc != 0) {
		goto out;
	}

	/*
	 * Event for configure case only,
	 * Get the name and model property
	 */
	if (o_state == CFGA_STAT_CONFIGURED) {
		rc = scf_get_devinfo(dev_name, dev_model,
		    (char *)pci_notify_dev_info.pci_name);
		if (rc != 0) {
			goto out;
		}
	}
	/*
	 * Copy the data for SCF.
	 * Initialize Data passed to SCF Driver.
	 */
	(void) memset(scfdata.buf, 0, sizeof (scfdata.buf));

	/*
	 * Set Data passed to SCF Driver.
	 */
	scfdata.size = sizeof (scf_slotinfo_t);
	(void) strlcpy(sdata.ap_id, ap_id, sizeof (sdata.ap_id));

	sdata.vflag = (uint8_t)0x80;
	sdata.r_state  = (uint32_t)r_state;
	sdata.o_state  = (uint32_t)o_state;
	sdata.tstamp   = (uint64_t)sec;
	(void) strlcpy(sdata.dev_name, dev_name, sizeof (dev_name));
	(void) strlcpy(sdata.dev_model, dev_model, sizeof (sdata.dev_model));

	(void) memcpy((void *)&(scfdata.buf), (void *)&sdata,
	    sizeof (scf_slotinfo_t));

	pci_notify_dev_info.r_state	= (uint32_t)r_state;
	pci_notify_dev_info.o_state	= (uint32_t)o_state;

	if (!scfdrv_enable) {
		scfdrv_enable = 1;

		/*
		 * Pass data to SCF driver by ioctl.
		 */
		if ((fd = open(SCFIOCDEV, O_WRONLY)) < 0) {
			syslog(LOG_ERR, "open %s fail", SCFIOCDEV);
			scfdrv_enable = 0;
			goto out;
		}

		while (ioctl(fd, SCFIOCSETPHPINFO, scfdata) < 0) {
			/* retry a few times for EBUSY and EIO */
			if ((++retry <= SCFRETRY) &&
			    ((errno == EBUSY) || (errno == EIO))) {
				(void) sleep(SCFIOCWAIT);
				continue;
			}

			syslog(LOG_ERR, "SCFIOCSETPHPINFO failed: %s.",
			    strerror(errno));
			break;
		}

		(void) close(fd);
		scfdrv_enable = 0;
	}

out:
	if (vendor != NULL) {
		free(vendor);
	}
	if (publisher != NULL) {
		free(publisher);
	}

	if (ev_attr_list != NULL) {
		nvlist_free(ev_attr_list);
	}

}
