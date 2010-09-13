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

#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <printAttrs.h>
#include <smhbaapi.h>

#define	TABLEN	2
typedef struct inputArgs {
	int 		wwnCount;
	char 		**wwn_argv;
	uint64_t 	portWWN;
	char		*hbaName;
	int		pflag;
	int		*wwn_flag;
} inputArg_t;

typedef struct tgt_mapping {
	SMHBA_SCSIENTRY	tgtentry;
	uchar_t		inq_vid[8];
	uchar_t		inq_pid[16];
	uchar_t		inq_dtype;
	struct tgt_mapping *next;
}tgt_mapping;

/*
 * Remote port tree node structure.
 */
typedef struct smhba_rp_tree {
	SMHBA_PORTATTRIBUTES	portattr;
	SMHBA_SAS_PORT		sasattr;
	tgt_mapping		*first_entry;
	int			printed;
	struct smhba_rp_tree	*parent;
	struct smhba_rp_tree	*child;
	struct smhba_rp_tree	*sibling;
}rp_tree_t;

/*
 * Report LUN data structure.
 */
struct lun {
	uchar_t	val[8];
};

typedef struct rep_luns_rsp {
	uint32_t    length;
	uint32_t    rsrvd;
	struct lun  lun[1];
} rep_luns_rsp_t;

/*
 * The following flag is used for printing HBA header on-demand.
 */
static int g_printHBA = 0;

/*
 * The following structure is for sorted output of HBA and HBA Port.
 */
typedef struct _sas_elem {
	char	name[256];
	int	index;
}sas_elem_t;

/*
 * The following two functions are for generating hierachy of expander
 * subcommand.
 */
static int
sas_rp_tree_insert(rp_tree_t **rproot, rp_tree_t *rpnode);
static int
sas_rp_tree_print(HBA_HANDLE handle, char *adapterName,
    HBA_UINT32 portIndex, SMHBA_PORTATTRIBUTES *port,
    rp_tree_t *rpnode, inputArg_t *input, int gident,
    int *printPort);
static int
sas_rp_tree_print_desc(HBA_HANDLE handle, HBA_UINT32 portIndex,
    SMHBA_PORTATTRIBUTES *port, rp_tree_t *desc,
    inputArg_t *input, int lident, int gident);
static int
sas_print_rpnode(inputArg_t *input,
    rp_tree_t *rpnode, int lident, int gident);
static void sas_rp_tree_free(rp_tree_t *rproot);

typedef int (*processPortFunc)(HBA_HANDLE handle, char *adapterName,
    HBA_UINT32 portIndex, SMHBA_PORTATTRIBUTES *port,
    SMHBA_ADAPTERATTRIBUTES *attrs, inputArg_t *input);

static int processHBA(inputArg_t *input,
    processPortFunc processPort);

static int isPortWWNInArgv(inputArg_t *input, PHBA_WWN pWWN);
static int isStringInArgv(inputArg_t *input, const char *adapterName);
static boolean_t compareLUName(char *cmdArg, char *osName);
static discoveredDevice *LUList = NULL;
static targetPortList_t *gTargetPortList = NULL;

/* processes for hanlding local HBA info */
static int handleHBA(SMHBA_ADAPTERATTRIBUTES *attrs, inputArg_t *input,
    int numberOfPorts, const char *adapterName);
static int handleHBAPort(HBA_HANDLE handle, char *adapterName,
    HBA_UINT32 portIndex, SMHBA_PORTATTRIBUTES *port,
    SMHBA_ADAPTERATTRIBUTES *attrs, inputArg_t *input);
static int processHBAPortPhyInfo(HBA_HANDLE handle, HBA_UINT32 portIndex,
    SMHBA_PORTATTRIBUTES *port, int pflag);
static int processHBAPortPhyStat(HBA_HANDLE handle, HBA_UINT32 portIndex,
    int phyIndex, PSMHBA_SAS_PHY phyattrs, int pflag);

/* process for handling expander info */
static int handleExpander(HBA_HANDLE handle, char *adapterName,
    HBA_UINT32 portIndex, SMHBA_PORTATTRIBUTES *port,
    SMHBA_ADAPTERATTRIBUTES *attrs, inputArg_t *input);

/* process for handling target port info */
static int handleTargetPort(HBA_HANDLE handle, char *adapterName,
    HBA_UINT32 portIndex, SMHBA_PORTATTRIBUTES *port,
    SMHBA_ADAPTERATTRIBUTES *attrs, inputArg_t *input);

/* process for handling logical unit info */
static int handleLogicalUnit(HBA_HANDLE handle, char *adapterName,
    HBA_UINT32 portIndex, SMHBA_PORTATTRIBUTES *port,
    SMHBA_ADAPTERATTRIBUTES *attrs, inputArg_t *input);

/* process for target port SCSI processing */
static int
searchTargetPortMappingData(HBA_HANDLE handle, HBA_UINT32 portIndex,
    SMHBA_PORTATTRIBUTES *port, SMHBA_SAS_PORT *sasattr,
    struct targetPortConfig *configData);

/* process for target port config processing */
static int searchTargetPort(HBA_HANDLE handle, HBA_UINT32 portIndex,
    SMHBA_PORTATTRIBUTES *port, SMHBA_PORTATTRIBUTES *targetattr,
    SMHBA_SAS_PORT *sasattr, int pflag);

/* process for logical-unit config processing */
static int
searchDevice(PSMHBA_SCSIENTRY entryP, HBA_HANDLE handle, HBA_WWN hbaPortWWN,
    HBA_WWN domainPortWWN, char *portName, int pflag);

/* get domain port out of hba-port phy attr. */
HBA_STATUS get_domainPort(HBA_HANDLE handle,
    int portindex, PSMHBA_PORTATTRIBUTES port,
    HBA_WWN *pdomainPort);

static int
sas_name_comp(const char *name1, const char *name2);
static void
sas_elem_sort(sas_elem_t *array, int nelem);

/*
 * function for hba subcommand
 *
 * Arguments:
 *	wwnCount - count of the number of WWNs in wwn_argv
 *	    if wwnCount > 0, then we will only print information for
 *		the hba ports listed in wwn_argv
 *	    if wwnCount == 0, then we will print information on all hba ports
 *	wwn_argv - argument array of hba port WWNs
 *	options - any options specified by the caller
 *
 * returns:
 *	0	if successful
 *	>0	otherwise
 */
int
sas_util_list_hba(int hbaCount, char **hba_argv, cmdOptions_t *options)
{
	HBA_STATUS		status;
	int			processHBA_flags = 0;
	inputArg_t		input;
	int 			err_cnt = 0;

	/* process each of the options */
	for (; options->optval; options++) {
		switch (options->optval) {
		case 'v':
			processHBA_flags |= PRINT_VERBOSE;
			break;
		default:
			break;
		}
	}

	if ((status = HBA_LoadLibrary()) != HBA_STATUS_OK) {
		(void *) fprintf(stderr, "%s %s\n",
		    gettext("Failed to load SM-HBA libraries."
		    "Reason:"), getHBAStatus(status));
		err_cnt++;
		return (err_cnt);
	}

	(void *) memset(&input, 0, sizeof (input));
	/* utilize wwnCount and wwn_argv for hbaCount and hba_argv */
	input.wwnCount = hbaCount;
	input.wwn_argv = hba_argv;
	input.pflag = processHBA_flags;

	/*
	 * Process and filter for every local hba,
	 * when the hba is not specificed, print all hba(s).
	 */
	err_cnt += processHBA(&input, NULL);

	(void) HBA_FreeLibrary();

	return (err_cnt);
}

/*
 * function for hba-port subcommand
 *
 * Arguments:
 *	wwnCount - count of the number of WWNs in wwn_argv
 *	    if wwnCount > 0, then we will only print information for
 *		the hba ports listed in wwn_argv
 *	    if wwnCount == 0, then we will print information on all hba ports
 *	wwn_argv - argument array of hba port WWNs
 *	options - any options specified by the caller
 *
 * returns:
 *	0	if successful
 *	>0	otherwise
 */
int
sas_util_list_hbaport(int wwnCount, char **wwn_argv, cmdOptions_t *options)
{
	HBA_STATUS		status;
	int			processHBA_flags = 0;
	inputArg_t		input;
	int 			err_cnt = 0;
	char			hbaName[256] = {'\0'};

	/* process each of the options */
	for (; options->optval; options++) {
		switch (options->optval) {
		case 'a':
			(void *) strlcpy(hbaName,
			    options->optarg, sizeof (hbaName));
			break;
		case 'y':
			processHBA_flags |= PRINT_PHY;
			break;
		case 'l':
			processHBA_flags |= PRINT_PHY_LINKSTAT;
			break;
		case 'v':
			processHBA_flags |= PRINT_VERBOSE;
			break;
		default:
			break;
		}
	}

	if ((status = HBA_LoadLibrary()) != HBA_STATUS_OK) {
		(void *) fprintf(stderr, "%s %s\n",
		    gettext("Failed to load SM-HBA libraries."
		    "Reason:"), getHBAStatus(status));
		err_cnt++;
		return (err_cnt);
	}

	(void *) memset(&input, 0, sizeof (input));
	input.wwnCount = wwnCount;
	input.wwn_argv = wwn_argv;
	input.hbaName = hbaName;
	input.pflag = processHBA_flags;

	/*
	 * Process and filter for every local hba-port,
	 * when the hba-port is not specificed, print all hba-port(s).
	 */
	err_cnt += processHBA(&input, handleHBAPort);

	(void) HBA_FreeLibrary();

	return (err_cnt);
}

/*
 * function for expander subcommand
 *
 * Arguments:
 *	wwnCount - the number of Remote Port SAS Address in wwn_argv
 *	    if wwnCount == 0, then print information on all
 *		expander devices.
 *	    if wwnCount > 0, then print information for the exapnders
 *		given in wwn_argv.
 *	wwn_argv - array of WWNs
 *	options - options specified by the caller
 *
 * returns:
 *	0	if successful
 *	>0	otherwise
 */
int
sas_util_list_expander(int wwnCount, char **wwn_argv, cmdOptions_t *options)
{
	HBA_STATUS		status;
	int			processHBA_flags = 0;
	char			hbaPort[MAXPATHLEN + 1] = {0};
	inputArg_t		input;
	int			err_cnt = 0;

	/* process each of the options */
	for (; options->optval; options++) {
		switch (options->optval) {
		case 'p':
			(void) strlcpy(hbaPort, options->optarg,
			    sizeof (hbaPort));
			break;
		case 't':
			processHBA_flags |= PRINT_TARGET_PORT;
			break;
		case 'v':
			processHBA_flags |= PRINT_VERBOSE;
			break;
		default:
			break;
		}
	}

	if ((status = HBA_LoadLibrary()) != HBA_STATUS_OK) {
		(void *) fprintf(stderr, "%s %s\n",
		    gettext("Failed to load SM-HBA libraries."
		    "Reason:"), getHBAStatus(status));
		err_cnt++;
		return (err_cnt);
	}

	(void *) memset(&input, 0, sizeof (input));
	input.wwnCount = wwnCount;
	input.wwn_argv = wwn_argv;
	input.pflag = processHBA_flags;
	input.hbaName = hbaPort;

	/*
	 * Process and filter for every hba-port,
	 * when the hba-port is not specificed, print all hba-port(s).
	 */
	err_cnt += processHBA(&input, handleExpander);

	(void) HBA_FreeLibrary();

	return (err_cnt);
}

/*
 * function for target-port subcommand
 *
 * Arguments:
 *	wwnCount - the number of Remote Port SAS Address in wwn_argv
 *	    if wwnCount == 0, then print information on all
 *		target ports.
 *	    if wwnCount > 0, then print information for the target ports
 *		given in wwn_argv.
 *	wwn_argv - array of WWNs
 *	options - options specified by the caller
 *
 * returns:
 *	0	if successful
 *	>0	otherwise
 */
int
sas_util_list_targetport(int tpCount, char **tpArgv, cmdOptions_t *options)
{
	HBA_STATUS		status;
	int			processHBA_flags = 0;
	int			tp, tpFound;
	inputArg_t		input;
	targetPortList_t	*tpListWalk;
	int			err_cnt = 0;
	uint64_t		tmpAddr;

	/* process each of the options */
	for (; options->optval; options++) {
		switch (options->optval) {
		case 's':
			processHBA_flags |= PRINT_TARGET_SCSI;
			break;
		case 'v':
			processHBA_flags |= PRINT_VERBOSE;
			break;
		default:
			break;
		}
	}

	if ((status = HBA_LoadLibrary()) != HBA_STATUS_OK) {
		(void *) fprintf(stderr, "%s %s\n",
		    gettext("Failed to load SM-HBA libraries."
		    "Reason:"), getHBAStatus(status));
		err_cnt++;
		return (err_cnt);
	}

	(void *) memset(&input, 0, sizeof (input));
	input.wwnCount = tpCount;
	input.wwn_argv = tpArgv;
	input.pflag = processHBA_flags;

	/*
	 * Process and filter for every hba-port,
	 * when the hba-port is not specificed, print all hba-port(s).
	 */
	err_cnt += processHBA(&input, handleTargetPort);

	if (tpCount == 0) {
		/* list all target port */
		for (tpListWalk = gTargetPortList; tpListWalk != NULL;
		    tpListWalk = tpListWalk->next) {
			err_cnt += printTargetPortInfo(tpListWalk, input.pflag);
		}
	} else {
		/*
		 * When operands provided, we should set the error code
		 * only if there are issues related with the operands.
		 */
		err_cnt = 0;
		/*
		 * list any paths not found first
		 * this gives the user cleaner output
		 */
		for (tp = 0; tp < tpCount; tp++) {
			errno = 0;
			tmpAddr = strtoull(tpArgv[tp], NULL, 16);
			if ((tmpAddr == 0) && (errno != 0)) {
				err_cnt++;
				continue;
			}
			for (tpListWalk = gTargetPortList, tpFound = B_FALSE;
			    tpListWalk != NULL;
			    tpListWalk = tpListWalk->next) {
				if (wwnConversion(tpListWalk->sasattr.
				    LocalSASAddress.wwn) == tmpAddr) {
					tpFound = B_TRUE;
					break;
				}
			}
			if (tpFound == B_FALSE) {
				(void *) fprintf(stderr,
				    "Error: Target Port %s Not Found \n",
				    tpArgv[tp]);
				err_cnt++;
			}
		}
		/* list all paths requested in order requested */
		for (tp = 0; tp < tpCount; tp++) {
			errno = 0;
			tmpAddr = strtoull(tpArgv[tp], NULL, 16);
			if ((tmpAddr == 0) && (errno != 0)) {
				continue;
			}
			for (tpListWalk = gTargetPortList, tpFound = B_FALSE;
			    tpListWalk != NULL;
			    tpListWalk = tpListWalk->next) {
				if (wwnConversion(tpListWalk->sasattr.
				    LocalSASAddress.wwn) == tmpAddr) {
					err_cnt += printTargetPortInfo(
					    tpListWalk,
					    processHBA_flags);
				}
			}
		}
	}
	(void) HBA_FreeLibrary();
	return (err_cnt);
}
/*
 * This function will enumerate all the hba and hba ports,
 * call the callback function to proceed with futher process.
 *
 * Arguments:
 *	input - contains all the input parameters.
 *	processPort - a callback function when handling each port.
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    >0		error has occured
 */
static int
processHBA(inputArg_t *input, processPortFunc processPort)
{
	int			numAdapters = 0;
	int			matchedHBAs = 0;
	int			matchedHBAPorts = 0;
	int			hbaPortExist = 0;
	HBA_STATUS		status;
	HBA_HANDLE		handle;
	HBA_UINT32		numberOfPorts = 0;
	int			portIndex = 0;
	HBA_PORTTYPE		porttype;
	SMHBA_LIBRARYATTRIBUTES libattrs;
	SMHBA_ADAPTERATTRIBUTES	attrs;
	SMHBA_PORTATTRIBUTES	port;
	SMHBA_SAS_PORT		sasattrs;
	int			i, sum, ret = 0;
	int			remote_avail = 0;
	int			local_avail = 0;
	sas_elem_t		*adpt_array = NULL;
	sas_elem_t		*port_array = NULL;

	numAdapters = HBA_GetNumberOfAdapters();
	if (numAdapters == 0) {
		(void *) fprintf(stderr, "%s\n",
		    gettext("Error: No Adapters Found."));
		return (++ret);
	}

	/*
	 * To deal with mismatching HBA/HBA Port/Expander Port, we need an
	 * array of flags for each operands.
	 */
	if (input->wwnCount && (processPort != handleTargetPort) &&
	    (processPort != handleLogicalUnit)) {
		input->wwn_flag = calloc(input->wwnCount, sizeof (int));
		if (input->wwn_flag == NULL) {
			(void *) fprintf(stderr, "%s\n",
			    gettext("No enough memory on heap"));
			return (++ret);
		}
	}

	adpt_array = calloc(numAdapters, sizeof (sas_elem_t));
	if (adpt_array == NULL) {
		(void *) fprintf(stderr, "%s\n",
		    gettext("No enough memory on heap"));
		if (input->wwn_flag) {
			free(input->wwn_flag);
			input->wwn_flag = NULL;
		}
		return (++ret);
	}
	for (i = 0; i < numAdapters; i++) {
		status =
		    SMHBA_GetVendorLibraryAttributes(i, &libattrs);
		/*
		 * If we get SAS incompatible library warning here,
		 * just skip the following steps.
		 */
		if (status != 1) {
			continue;
		}
		status = HBA_GetAdapterName(i, adpt_array[i].name);
		if (status != HBA_STATUS_OK) {
			(void *) fprintf(stderr, "%s %d %s %s\n",
			    gettext("Error: Failed to get the name for"
			    " HBA index"),
			    i, gettext("Reason:"),
			    getHBAStatus(status));
			ret++;
			continue;
		}
		adpt_array[i].index = i;
	}
	/* Sort the HBA Name in place. */
	sas_elem_sort(adpt_array, numAdapters);

	for (i = 0; i < numAdapters; i++) {
		int times = 0;
		if (adpt_array[i].name[0] != '\0') {
			if ((handle = HBA_OpenAdapter(adpt_array[i].name))
			    == 0) {
				(void *) fprintf(stderr, "%s %s.\n",
				    gettext("Error: Failed to open adapter"),
				    adpt_array[i].name);
				ret++;
				continue;
			}
		} else {
			continue;
		}

		/*
		 * We need to support an adapter without hba port.
		 * So get attributes anyway.
		 */
		(void *) memset(&attrs, 0, sizeof (attrs));
		status = SMHBA_GetAdapterAttributes(handle, &attrs);
		while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
		    status == HBA_STATUS_ERROR_BUSY) &&
		    times++ < HBA_MAX_RETRIES) {
			(void) sleep(1);
			status = SMHBA_GetAdapterAttributes(handle,
			    &attrs);
		}
		if (status != HBA_STATUS_OK) {
			(void *) fprintf(stderr, "%s %s %s %s\n",
			    gettext("Error: Failed to get attributes"
			    " for HBA "), adpt_array[i].name,
			    gettext("Reason:"),
			    getHBAStatus(status));

			HBA_CloseAdapter(handle);
			ret++;
			continue;
		}

		status = SMHBA_GetNumberOfPorts(handle, &numberOfPorts);
		if (status != HBA_STATUS_OK) {
			(void *) fprintf(stderr, "%s %s %s %s\n",
			    gettext("Error: Failed to get number of ports "
			    "for HBA"), adpt_array[i].name,
			    gettext("Reason:"),
			    getHBAStatus(status));
			HBA_CloseAdapter(handle);
			ret++;
			continue;
		}

		/*
		 * Deal with each subcommand for hba filter here,
		 * processPort is NULL for hba subcommand.
		 */
		if (processPort == NULL) {
			matchedHBAs += handleHBA(&attrs, input,
			    numberOfPorts, adpt_array[i].name);
			HBA_CloseAdapter(handle);
			continue;
		} else if (processPort == handleHBAPort) {
			if (input->hbaName[0] != '\0') {
				if (strcmp(input->hbaName,
				    adpt_array[i].name) == 0) {
					matchedHBAs++;
				} else {
					continue;
				}
			} else {
				matchedHBAs++;
			}
		} else {
			matchedHBAs++;
		}

		/*
		 * In order to have a sorted output for HBA Port, we should
		 * do the sorting before moving on.
		 */
		if (numberOfPorts) {
			port_array = calloc(numberOfPorts, sizeof (sas_elem_t));
		}
		for (portIndex = 0; portIndex < numberOfPorts; portIndex++) {
			if ((status = SMHBA_GetPortType(handle,
			    portIndex, &porttype)) != HBA_STATUS_OK) {
				(void *) fprintf(stderr, "%s %s %s %s\n",
				    gettext("Failed to get adapter port type "
				    "for HBA"), adpt_array[i].name,
				    gettext("Reason:"),
				    getHBAStatus(status));
				ret++;
				continue;
			}
			if (porttype != HBA_PORTTYPE_SASDEVICE) {
				/* skip any non-sas hba port */
				continue;
			}
			(void *) memset(&port, 0, sizeof (port));
			(void *) memset(&sasattrs, 0, sizeof (sasattrs));
			port.PortSpecificAttribute.SASPort = &sasattrs;
			if ((status = SMHBA_GetAdapterPortAttributes(
			    handle, portIndex, &port)) != HBA_STATUS_OK) {
				/*
				 * Not able to get port attributes.
				 * print out error message and
				 * move on to the next port
				 */
				(void *) fprintf(stderr, "%s %s %s %d %s %s\n",
				    gettext("Error: Failed to get port "
				    "attributes for HBA"), adpt_array[i].name,
				    gettext("port index"), portIndex,
				    gettext("Reason:"),
				    getHBAStatus(status));
				ret++;
				continue;
			}
			(void) strlcpy(port_array[portIndex].name,
			    port.OSDeviceName,
			    sizeof (port_array[portIndex].name));
			port_array[portIndex].index = portIndex;
		}
		/* Sort the HBA Port Name here. */
		if (port_array) {
			sas_elem_sort(port_array, numberOfPorts);
		}
		/*
		 * Sum up the local hba ports available.
		 */
		local_avail += numberOfPorts;

		/*
		 * Clear g_printHBA flag for expander subcommand.
		 */
		g_printHBA = 0;

		/* process each port on the given adapter */
		for (portIndex = 0;
		    portIndex < numberOfPorts;
		    portIndex++) {
			/*
			 * We only handle the port which is valid.
			 */
			if (port_array[portIndex].name[0] == '\0') {
				continue;
			}
			(void *) memset(&port, 0, sizeof (port));
			(void *) memset(&sasattrs, 0, sizeof (sasattrs));
			port.PortSpecificAttribute.SASPort = &sasattrs;

			(void) SMHBA_GetAdapterPortAttributes(handle,
			    port_array[portIndex].index, &port);

			/*
			 * We have different things to do for the three
			 * sub-commands here.
			 */
			if (processPort == handleHBAPort) {
				/*
				 * For hba-port, we will check whether the
				 * specified hba port exist first.
				 * But if no hba port specified, we should
				 * by pass this check(just let hbaPortExist
				 * be 1).
				 */
				if (input->wwnCount > 0) {
					if (isStringInArgv(input,
					    port.OSDeviceName)) {
						hbaPortExist = 1;
						if (g_printHBA == 0) {
							(void *) fprintf(stdout,
							    "%s %s\n",
							    "HBA Name:",
							    adpt_array[i].name);
							g_printHBA = 1;
						}
					}
				} else {
					hbaPortExist = 1;
					if (g_printHBA == 0) {
						(void *) fprintf(stdout,
						    "%s %s\n",
						    "HBA Name:",
						    adpt_array[i].name);
						g_printHBA = 1;
					}
				}
			}

			if (processPort == handleExpander) {
				/*
				 * For expander device, input->hbaName is
				 * the hba port name specified on the
				 * command line(with -p option).
				 */
				if (input->hbaName[0] != '\0') {
					if (strcmp(input->hbaName,
					    port.OSDeviceName) == 0)
						hbaPortExist = 1;
				} else
					hbaPortExist = 1;
			}

			if (processPort == handleTargetPort) {
				/*
				 * For target port, we don't need to check the
				 * hba port address, so let it go here.
				 */
				hbaPortExist = 1;
			}

			if (processPort == handleLogicalUnit) {
				/*
				 * For lu, we don't need to check the hba
				 * port address, so let it go here.
				 */
				hbaPortExist = 1;
			}

			if (hbaPortExist) {
				if (port.PortSpecificAttribute.SASPort->
				    NumberofDiscoveredPorts) {
					remote_avail++;
				}
				ret += (*processPort)(handle,
				    adpt_array[i].name,
				    port_array[portIndex].index, &port,
				    &attrs, input);
				/*
				 * We should reset the hbaPortExist flag
				 * here for next round of check and count
				 * for the machedHBAPorts.
				 */
				hbaPortExist = 0;
				matchedHBAPorts++;
			}
		}
		if (port_array) {
			free(port_array);
			port_array = NULL;
		}
		HBA_CloseAdapter(handle);
	}
	if (adpt_array) {
		free(adpt_array);
		adpt_array = NULL;
	}

	/*
	 * When we are here, we have traversed all the hba and hba ports.
	 */
	if (matchedHBAs == 0) {
		(void *) fprintf(stderr, "%s\n",
		    gettext("Error: Matching HBA not found."));
		if (input->wwn_flag) {
			free(input->wwn_flag);
			input->wwn_flag = NULL;
		}
		return (++ret);
	} else if (processPort == NULL) {
		/*
		 * processPort == NULL signifies hba subcommand.
		 * If enter here, it means we have at least one matching
		 * hba, we need to check if there are mismatching ones.
		 */
		for (i = 0; i < input->wwnCount; i++) {
			if (input->wwn_flag[i] == 0) {
				(void *) fprintf(stderr, "%s %s %s\n",
				    gettext("Error: HBA"),
				    input->wwn_argv[i],
				    gettext("not found."));
				ret++;
			}
		}
	} else {
		if (local_avail > 0 && matchedHBAPorts == 0) {
			(void *) fprintf(stderr, "%s\n",
			    gettext("Error: Matching HBA Port "
			    "not found."));
			if (input->wwn_flag) {
				free(input->wwn_flag);
				input->wwn_flag = NULL;
			}
			return (++ret);
		} else if (local_avail == 0) {
			(void *) fprintf(stderr, "%s\n",
			    gettext("Error: No HBA Port Configured."));
			if (input->wwn_flag) {
				free(input->wwn_flag);
				input->wwn_flag = NULL;
			}
			return (++ret);
		} else if (processPort == handleHBAPort) {
			/*
			 * If enter here, we have at least one HBA port
			 * matched. For hba-port subcommand, we shall check
			 * whether there are operands mismatching.
			 */
			for (i = 0; i < input->wwnCount; i++) {
				if (input->wwn_flag[i] == 0) {
					(void *) fprintf(stderr, "%s %s %s\n",
					    gettext("Error: HBA Port"),
					    input->wwn_argv[i],
					    gettext("not found."));
					ret++;
				}
			}
		}
	}

	/*
	 * For expander subcommand, we need to check if the
	 * specified sas address(ese) exist (none/partial/all).
	 */
	if (processPort == handleExpander) {
		if (input->wwnCount > 0) {
			sum = 0;
			for (i = 0; i < input->wwnCount; i++) {
				sum += input->wwn_flag[i];
			}
			/*
			 * If sum is zero, it means that for all the given
			 * operands matching count is zero. So none of the
			 * specified SAS address exist actually.
			 */
			if (sum == 0) {
				(void *) fprintf(stderr, gettext("Error: "
				    "Matching SAS Address not found.\n"));
				free(input->wwn_flag);
				input->wwn_flag = NULL;
				return (++ret);
			}

			/*
			 * If we get here, it means that some of the specified
			 * sas address exist, we will know through looping the
			 * wwn_flag array.
			 */
			for (i = 0; i < input->wwnCount; i++) {
				if (input->wwn_flag[i] == 0) {
					(void *) fprintf(stderr, "%s %s %s\n",
					    gettext("Error: SAS Address"),
					    input->wwn_argv[i],
					    gettext("not found."));
					ret++;
				}
			}
		}
		/* even if no remote port is found it is not an error. */
	}
	if (input->wwn_flag) {
		free(input->wwn_flag);
		input->wwn_flag = NULL;
	}
	return (ret);
}

/*
 * This function will handle the phy stuff for hba-port subcommand.
 *
 * Arguments:
 *      handle - handle to hba port.
 *      portIndex - the index of hba port currently being processed.
 *      port - pointer to hba port attributes.
 *      pflag - options user specified.
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    >0		error has occured
 */
static int
processHBAPortPhyInfo(HBA_HANDLE handle, HBA_UINT32 portIndex,
    SMHBA_PORTATTRIBUTES *port, int pflag)
{
	int 		phyIndex = 0, err_cnt = 0;
	HBA_UINT32	numphys = 0;
	HBA_STATUS	status = 0;
	SMHBA_SAS_PHY	phyattrs;

	if (port == NULL)
		return (++err_cnt);

	numphys = port->PortSpecificAttribute.SASPort->NumberofPhys;
	if (numphys == 0)
		return (0);

	if ((pflag & PRINT_PHY) || (pflag & PRINT_PHY_LINKSTAT))
		(void *) fprintf(stdout, "%s\n", "    Phy Information:");
	else
		return (0);


	for (phyIndex = 0; phyIndex < numphys; phyIndex++) {
		(void *) memset(&phyattrs, 0, sizeof (phyattrs));
		status = SMHBA_GetSASPhyAttributes(
		    handle, portIndex, phyIndex, &phyattrs);
		if (status != HBA_STATUS_OK) {
			(void *) fprintf(stderr, "%s %d %s %s\n",
			    gettext("Failed to get SAS Phy attributes"
			    "phyIndex"), phyIndex,
			    gettext("Reason:"),
			    getHBAStatus(status));
			err_cnt++;
			continue;
		}
		if (pflag & PRINT_PHY)
			printHBAPortPhyInfo(&phyattrs);
		if (pflag & PRINT_PHY_LINKSTAT)
			err_cnt += processHBAPortPhyStat(handle,
			    portIndex, phyIndex, &phyattrs, pflag);
	}
	return (err_cnt);
}

/*
 * This function will handle the phy stuff for hba-port subcommand.
 *
 * Arguments:
 *      handle - handle to hba port.
 *      portIndex - the index of hba port currently being processed.
 *      port - pointer to hba port attributes.
 *      pflag - options user specified.
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    >0		error has occured
 */
static int
processHBAPortPhyStat(HBA_HANDLE handle, HBA_UINT32 portIndex, int phyIndex,
    PSMHBA_SAS_PHY phyattrs, int pflag)
{
	HBA_STATUS		status = 0;
	SMHBA_PHYSTATISTICS	phystat;
	SMHBA_SASPHYSTATISTICS	sasphystat;

	if ((pflag & PRINT_PHY) == 0) {
		(void *) fprintf(stdout, "%s %d\n",
		    "      Identifier:", phyattrs->PhyIdentifier);
	}

	(void *) memset(&phystat, 0, sizeof (phystat));
	(void *) memset(&sasphystat, 0, sizeof (sasphystat));
	phystat.SASPhyStatistics = &sasphystat;
	status = SMHBA_GetPhyStatistics(handle, portIndex, phyIndex, &phystat);
	if (status != HBA_STATUS_OK) {
		(void *) fprintf(stdout, "%s\n",
		    "        Link Error Statistics:");
		(void *) fprintf(stderr, "%s\n",
		    gettext("            Failed to retrieve Link "
		    "Error Statistics!"));
		return (1);
	}
	printHBAPortPhyStatistics(phystat.SASPhyStatistics);
	return (0);
}

/*
 * Check whether the pWWN exist in the WWNs list which specified by user.
 *
 * Arguments:
 *	input - contains all the input parameters.
 *	pWWN - pointer to the hba port sas address.
 *
 *  Return Value:
 *	    1		true, the pWWN exist in the sas address list specified.
 *	    0		false.
 */
static int
isPortWWNInArgv(inputArg_t *input, PHBA_WWN pWWN)
{
	int 		port_wwn_counter = 0;
	int		portfound = 0;
	uint64_t	hbaWWN;

	/* list only ports given in wwn_argv */
	for (port_wwn_counter = 0;
	    port_wwn_counter < input->wwnCount;
	    port_wwn_counter++) {
		hbaWWN = strtoull(input->wwn_argv[port_wwn_counter], NULL,
		    16);
		if (hbaWWN == 0 && errno != 0)
			continue;
		if (wwnConversion(pWWN->wwn) == hbaWWN) {
			if (input->wwn_flag) {
				input->wwn_flag[port_wwn_counter]++;
			}
			portfound = 1;
		}
	}
	return (portfound);
}

/*
 * Check whether the string value exists in the input list,
 * which specified by user.
 *
 * Arguments:
 *	input - contains all the input parameters.
 *	stringName - could be hba adapter name
 *	                      hba-port name.
 *
 *  Return Value:
 *	    1		true, the HBA exists in the list specified.
 *	    0		false.
 */
static int
isStringInArgv(inputArg_t *input, const char *stringName)
{
	int 		counter = 0;
	int		found = 0;

	/* list only hba(s) given in wwn_argv */
	for (counter = 0;
	    counter < input->wwnCount;
	    counter++) {
		if (strcmp(input->wwn_argv[counter],
		    stringName) == 0) {
			if (input->wwn_flag)
				input->wwn_flag[counter]++;
			found = 1;
		}
	}
	return (found);
}

/*
 * Callback function for hba subcommand.
 *
 * Arguments:
 *      attrs - pointer to adapter attributes currently being processed.
 *	input - contains all the input parameters.
 *	numberOfPorts - number of ports of this HBA.
 *
 *  Return Value:
 *  	matching number
 */
static int handleHBA(SMHBA_ADAPTERATTRIBUTES *attrs, inputArg_t *input,
    int numberOfPorts, const char *adapterName)
{
	int matchingHBA = 1;

	if (input->wwnCount == 0) {
		printHBAInfo(attrs, input->pflag, numberOfPorts, adapterName);
	} else {
		if (isStringInArgv(input, adapterName)) {
			printHBAInfo(attrs,
			    input->pflag, numberOfPorts, adapterName);
		} else {
			matchingHBA = 0;
		}
	}

	return (matchingHBA);
}

/*
 * Callback function for hba-port subcommand.
 *
 * Arguments:
 *      handle - handle to hba port.
 *      portIndex - the index of hba port currently being processed.
 *      port - pointer to hba port attributes.
 *      attrs - pointer to adapter attributes currently being processed.
 *	input - contains all the input parameters.
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    >0		error has occured
 */
/*ARGSUSED*/
static int handleHBAPort(HBA_HANDLE handle, char *adapterName,
    HBA_UINT32 portIndex, SMHBA_PORTATTRIBUTES *port,
    SMHBA_ADAPTERATTRIBUTES *attrs, inputArg_t *input)
{
	int ret = 0;
	printHBAPortInfo(port, attrs, input->pflag);
	ret = processHBAPortPhyInfo(handle, portIndex, port, input->pflag);
	return (ret);
}

/*
 * Callback function for expander subcommand.
 *
 * Arguments:
 *      handle - handle to hba port.
 *      portIndex - the index of hba port currently being processed.
 *      port - pointer to hba port attributes.
 *      attrs - pointer to adapter attributes currently being processed.
 *	input - contains all the input parameters.
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    >0		error has occured
 */
/*ARGSUSED*/
static int handleExpander(HBA_HANDLE handle, char *adapterName,
    HBA_UINT32 portIndex, SMHBA_PORTATTRIBUTES *port,
    SMHBA_ADAPTERATTRIBUTES *attrs, inputArg_t *input)
{
	SMHBA_PORTATTRIBUTES	attr;
	SMHBA_SAS_PORT		sasport;
	HBA_STATUS		status;
	int			ret = 0;
	int			i, numberOfRP;
	rp_tree_t		*rpnode;
	rp_tree_t		*rproot = NULL;
	rp_tree_t		*unsolved_head = NULL;
	rp_tree_t		*unsolved_tail = NULL;
	rp_tree_t		*unsolved_sentinel = NULL;
	int			printPort = 0;
	int			numberOfEXP = 0;
	int			unsolved_inserted = 0;
	int			unsolved_left = 0;
	int			disco_port_fail = 0;
	boolean_t		firstPrinted = B_FALSE;

	(void *) memset(&attr, 0, sizeof (attr));
	(void *) memset(&sasport, 0, sizeof (sasport));
	attr.PortSpecificAttribute.SASPort = &sasport;

	/*
	 * Retrive all expander device from this hba port first.
	 */
	if ((numberOfRP = port->PortSpecificAttribute.SASPort->
	    NumberofDiscoveredPorts) == 0) {
		/* no remote port. just return 0. */
		return (ret);
	}

	for (i = 0; i < numberOfRP; i++) {
		rpnode = calloc(1, sizeof (rp_tree_t));
		rpnode->portattr.PortSpecificAttribute.SASPort =
		    &rpnode->sasattr;
		status = SMHBA_GetDiscoveredPortAttributes(handle,
		    portIndex, i, &rpnode->portattr);
		if (status != HBA_STATUS_OK) {
			disco_port_fail++;
			free(rpnode);
			ret++;
			continue;
		}

		if (rpnode->portattr.PortType == HBA_PORTTYPE_SASEXPANDER) {
			numberOfEXP++;
		}
		/*
		 * We will try to insert this expander device and target
		 * ports into the topology tree. If we failed, we can chain
		 * them together and try again when we have all the
		 * discovered port information in hands.
		 */
		if (rproot == NULL && memcmp(port->
		    PortSpecificAttribute.SASPort->LocalSASAddress.wwn,
		    rpnode->sasattr.AttachedSASAddress.wwn,
		    sizeof (HBA_WWN)) == 0) {
			/*
			 * The root node of tree should
			 * be set up first.
			 */
			rproot = rpnode;
		} else {
			/*
			 * If we can not set up the root node of
			 * the tree or we failed to insert
			 * the disocvered port node, queue it up then.
			 */
			if (rproot == NULL ||
			    sas_rp_tree_insert(&rproot, rpnode) != 0) {
				if (unsolved_head == NULL) {
					unsolved_head = rpnode;
					unsolved_tail = rpnode;
				} else {
					rpnode->sibling = unsolved_head;
					unsolved_head = rpnode;
				}
			}
		}
	}

	if (disco_port_fail) {
		(void *) fprintf(stderr, "%s %d %s %s\n",
		    gettext("Error: Failed to get attributes for"),
		    disco_port_fail,
		    gettext("connected ports of HBA port"),
		    port->OSDeviceName);
	}

	/* no expander found.  No need further processing. */
	if (numberOfEXP == 0) {
		while (unsolved_head) {
			unsolved_tail =
			    unsolved_head->sibling;
			free(unsolved_head);
			unsolved_head = unsolved_tail;
		}
		if (rproot) sas_rp_tree_free(rproot);
		return (ret);
	}

	/*
	 * When we're here, we should already have all information,
	 * now we try again to insert them into the topology tree.
	 * unsolved_head is the pointer which point to the head of
	 * unsolved rpnode linked list.
	 * unsolved_tail is the pointer which point to the tail of
	 * unsolved rpnode linked list.
	 * unsolved_sentinel is for insertion failure detection.
	 * When we're trying to insert the rpnodes from unsolved
	 * linked list, it may happen that some of the rpnodes can
	 * not be inserted no matter how many times we loop through
	 * this linked list. So we use unsolved_sentinel to identify
	 * the tail of last round of scanning, and unsolved_inserted
	 * which is a counter will be used to count how many rpnodes
	 * have been inserted from last round, if it is zero, which
	 * means that we can not insert rpnodes into rptree any more,
	 * and we should stop and deallocate the memory they occupied.
	 */
	unsolved_sentinel = unsolved_tail;
	while (unsolved_head) {
		rpnode = unsolved_head;
		unsolved_head = unsolved_head->sibling;
		if (unsolved_head == NULL)
			unsolved_tail = NULL;
		rpnode->sibling = NULL;
		if (sas_rp_tree_insert(&rproot, rpnode) != 0) {
			unsolved_tail->sibling = rpnode;
			unsolved_tail = rpnode;
			if (rpnode == unsolved_sentinel) {
				/*
				 * We just scanned one round for the
				 * unsolved list. Check to see whether we
				 * have nodes inserted, if none, we should
				 * break in case of an indefinite loop.
				 */
				if (unsolved_inserted == 0) {
					/*
					 * Indicate there is unhandled node.
					 * Chain free the whole unsolved
					 * list here.
					 */
					unsolved_left++;
					break;
				} else {
					unsolved_inserted = 0;
					unsolved_sentinel = unsolved_tail;
				}
			}
		} else {
			/*
			 * We just inserted one rpnode, increment the
			 * unsolved_inserted counter. We will utilize this
			 * counter to detect an indefinite insertion loop.
			 */
			unsolved_inserted++;
		}
	}

	/* check if there is left out discovered ports. */
	if (unsolved_left) {
		ret++;
		(void *) fprintf(stderr, "%s %s\n",
		    gettext("Error: Failed to establish expander topology on"),
		    port->OSDeviceName);
		(void *) fprintf(stderr, "%s\n",
		    gettext("       Folowing port(s) are unresolved."));
		while (unsolved_head) {
			unsolved_tail =
			    unsolved_head->sibling;
			(void *) fprintf(stderr, "%s%016llx ",
			    firstPrinted ? "" : "\t",
			    wwnConversion(unsolved_head->sasattr.
			    LocalSASAddress.wwn));
			if (firstPrinted == B_FALSE) firstPrinted = B_TRUE;
			free(unsolved_head);
			unsolved_head = unsolved_tail;
		}
		(void *) fprintf(stderr, "\n");
		/* still print what we have */
		ret += sas_rp_tree_print(handle, adapterName, portIndex,
		    port, rproot, input, 2 * TABLEN, &printPort);
	} else {
		ret += sas_rp_tree_print(handle, adapterName, portIndex,
		    port, rproot, input, 2 * TABLEN, &printPort);
	}

	if (rproot) sas_rp_tree_free(rproot);

	return (ret);
}

/*
 * Callback function for target-port subcommand.
 *
 * Arguments:
 *      handle - handle to hba port.
 *      portIndex - the index of hba port currently being processed.
 *      port - pointer to hba port attributes.
 *      attrs - pointer to adapter attributes currently being processed.
 *	input - contains all the input parameters.
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    >0		error has occured
 */
/*ARGSUSED*/
static int handleTargetPort(HBA_HANDLE handle, char *adapterName,
    HBA_UINT32 portIndex, SMHBA_PORTATTRIBUTES *port,
    SMHBA_ADAPTERATTRIBUTES *attrs, inputArg_t *input)
{
	HBA_STATUS		status;
	SMHBA_PORTATTRIBUTES	targetattr;
	SMHBA_SAS_PORT		sasattr;
	int			i;
	int			ret = 0;
	int			disco_port_fail = 0;

	targetattr.PortSpecificAttribute.SASPort = &sasattr;

	for (i = 0; i < port->PortSpecificAttribute.SASPort->
	    NumberofDiscoveredPorts; i++) {
		status = SMHBA_GetDiscoveredPortAttributes(handle,
		    portIndex, i, &targetattr);
		if (status != HBA_STATUS_OK) {
			disco_port_fail++;
		} else {
			/* skip expander device */
			if (targetattr.PortType != HBA_PORTTYPE_SASEXPANDER) {
				ret += searchTargetPort(handle, portIndex, port,
				    &targetattr, &sasattr, input->pflag);
			}
		}
	}

	if (disco_port_fail) {
		ret++;
		(void *) fprintf(stderr, "%s %d %s %s\n",
		    gettext("Error: Failed to get attributes for"),
		    disco_port_fail,
		    gettext("connected ports of HBA port"),
		    port->OSDeviceName);
	}
	return (ret);
}

/*
 * ****************************************************************************
 *
 * compareLUName -
 * 	compare names directly and also check if disk namees match with
 *	different slice number or /devices path are speicified and matches.
 *
 * cmdArg	- first string to compare
 * osName	- os name from attributes
 *
 * returns 	B_TRUE if the strings match either directly or via devid
 *		B_FALSE otherwise
 *
 * ****************************************************************************
 */
static boolean_t
compareLUName(char *cmdArg, char *osName)
{

	boolean_t	isSame = B_FALSE;
	char		dev1[MAXPATHLEN], dev2[MAXPATHLEN];
	char		*ch1, *ch2;

	if (strcmp(cmdArg, osName) == 0) {
		isSame = B_TRUE;
	} else {
		/* user input didn't match, try to  match the core of args. */
		(void) strlcpy(dev1, cmdArg, MAXPATHLEN);
		(void) strlcpy(dev2, osName, MAXPATHLEN);
		/* is this /devices path */
		if (((ch1 = strrchr(dev1, ',')) != NULL) &&
		    ((ch2 = strrchr(dev2, ',')) != NULL)) {
			*ch1 = *ch2 = '\0';
			if (strcmp(dev1, dev2) == 0) {
				isSame = B_TRUE;
			}
		/* is this a /dev link */
		} else if ((strncmp(dev1, "/dev/", 5) == 0) &&
		    (strncmp(dev2, "/dev/", 5) == 0)) {
			if ((strstr(dev1, "dsk") != NULL) &&
			    ((strstr(dev2, "dsk") != NULL))) {
				/* if it is disk link */
				if (((ch1 = strrchr(dev1, 's')) != NULL) &&
				    ((ch2 = strrchr(dev2, 's')) != NULL)) {
					*ch1 = *ch2 = '\0';
					if (strcmp(dev1, dev2) == 0) {
						isSame = B_TRUE;
					}
				}
			} else {
				/* other dev links */
				if (strcmp(dev1, dev2) == 0) {
					isSame = B_TRUE;
				}
			}
		}
	} /* compare */

	return (isSame);
}

/*
 * Process logical-unit(lu) subcommand.
 *
 * Arguments:
 *      luCount - number of OS device name(s) specified by user.
 *      luArgv - array of OS device name(s) specified by user.
 *      options - all the options specified by user.
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    >0		error has occured
 */
int
sas_util_list_logicalunit(int luCount, char **luArgv, cmdOptions_t *options)
{
	HBA_STATUS		status;
	int			processHBA_flags = 0;
	int			lu;
	boolean_t		pathFound;
	boolean_t		verbose;
	inputArg_t		input;
	discoveredDevice	*LUListWalk = NULL;
	int			err_cnt = 0;

	for (; options->optval; options++) {
		if (options->optval == 'v') {
			processHBA_flags |= PRINT_VERBOSE;
		}
	}

	/* HBA_LoadLibrary() */
	if ((status = HBA_LoadLibrary()) != HBA_STATUS_OK) {
		(void *) fprintf(stderr, "%s %s\n",
		    gettext("Failed to load SM-HBA libraries."
		    "Reason:"), getHBAStatus(status));
		err_cnt++;
		return (err_cnt);
	}

	(void *) memset(&input, 0, sizeof (input));
	input.pflag = processHBA_flags;
	input.wwnCount = luCount;
	input.wwn_argv = luArgv;

	err_cnt += processHBA(&input, handleLogicalUnit);
	verbose = (input.pflag & PRINT_VERBOSE) ? B_TRUE : B_FALSE;

	if (luCount == 0) {
		/* list all paths */
		for (LUListWalk = LUList; LUListWalk != NULL;
		    LUListWalk = LUListWalk->next) {
			err_cnt += printOSDeviceNameInfo(LUListWalk, verbose);
		}
	} else {
		/*
		 * When operands provided, we should set the error code
		 * only if there are issues related with the operands.
		 */
		err_cnt = 0;
		/*
		 * list any paths not found first
		 * this gives the user cleaner output
		 */
		for (lu = 0; lu < luCount; lu++) {
			for (LUListWalk = LUList, pathFound = B_FALSE;
			    LUListWalk != NULL;
			    LUListWalk = LUListWalk->next) {
				if (compareLUName(luArgv[lu],
				    LUListWalk->OSDeviceName)) {
					pathFound = B_TRUE;
					break;
				}
			}
			if (pathFound == B_FALSE) {
				(void *) fprintf(stderr,
				    "Error: Logical Unit %s Not Found \n",
				    luArgv[lu]);
				err_cnt++;
			}
		}
		/* list all paths requested in order requested */
		for (lu = 0; lu < luCount; lu++) {
			for (LUListWalk = LUList; LUListWalk != NULL;
			    LUListWalk = LUListWalk->next) {
				if (compareLUName(luArgv[lu],
				    LUListWalk->OSDeviceName)) {
					err_cnt += printOSDeviceNameInfo(
					    LUListWalk,
					    verbose);
				}
			}
		}
	}
	(void) HBA_FreeLibrary();
	return (err_cnt);
}

/*
 * Callback function for logical-unit(lu) subcommand.
 *
 * Arguments:
 *      handle - handle to hba port.
 *      portIndex - the index of hba port currently being processed.
 *      port - pointer to hba port attributes.
 *      attrs - pointer to adapter attributes currently being processed.
 *	input - contains all the input parameters.
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    >0		error has occured
 */
/*ARGSUSED*/
static int handleLogicalUnit(HBA_HANDLE handle, char *adapterName,
    HBA_UINT32 portIndex, SMHBA_PORTATTRIBUTES *port,
    SMHBA_ADAPTERATTRIBUTES *attrs, inputArg_t *input)
{
	HBA_STATUS		status;
	SMHBA_TARGETMAPPING	*map;
	HBA_WWN			hbaPortWWN, domainPortWWN;
	char			*portName = NULL;
	int			numentries;
	int			count = 0;
	int			ret = 0;

	hbaPortWWN = port->PortSpecificAttribute.SASPort->LocalSASAddress;
	portName = port->OSDeviceName;

	status = get_domainPort(handle, portIndex, port, &domainPortWWN);
	switch (status) {
		case HBA_STATUS_OK:
			break;
		case HBA_STATUS_ERROR_NOT_SUPPORTED:
			/* don't increase error flag for no phy configuration */
			return (ret);
		case HBA_STATUS_ERROR:
		default:
			return (++ret);
	}

	if ((map = calloc(1, sizeof (*map))) == NULL) {
		(void *) fprintf(stderr, "%s\n",
		    gettext("No enough memory on heap."));
		return (++ret);
	}
	map->NumberOfEntries = 1;

	/*
	 * First, we need to get the target mapping data from this hba
	 * port.
	 */
	status = SMHBA_GetTargetMapping(handle,
	    hbaPortWWN, domainPortWWN, map);

	if (status == HBA_STATUS_ERROR_MORE_DATA) {
		numentries = map->NumberOfEntries;
		free(map);
		map = calloc(1, sizeof (HBA_UINT32) +
		    (numentries * sizeof (SMHBA_SCSIENTRY)));
		if (map == NULL) {
			(void *) fprintf(stderr, "%s\n",
			    gettext("No enough memory on heap."));
			return (++ret);
		}
		map->NumberOfEntries = numentries;
		status = SMHBA_GetTargetMapping(handle,
		    hbaPortWWN, domainPortWWN, map);
	}

	if (status != HBA_STATUS_OK) {
		(void *) fprintf(stderr, "%s %016llx %s %s\n",
		    gettext("Error: Failed to get SCSI mapping data for "
		    "the HBA port"), wwnConversion(hbaPortWWN.wwn),
		    gettext("Reason:"),
		    getHBAStatus(status));
		free(map);
		return (++ret);
	}

	/*
	 * By iterating each entry of the targetmapping data, we will
	 * construct a global list of logical unit.
	 */
	for (count = 0; count < map->NumberOfEntries; count++) {
		ret += searchDevice(
		    &(map->entry[count]), handle, hbaPortWWN, domainPortWWN,
		    portName, input->pflag);
	}
	free(map);
	return (ret);
}

/*
 * Search the matching targetmapping data for given target port and SAM LUN
 *	and return target mapping data if found.
 *
 * Arguments:
 *      handle - handle to hba port.
 *      portIndex - hba port index
 *      port - hba port attributes.
 *      targetportWWN - target port SAS address.
 *      domainportWWN - domain port SAS address.
 *      domainportttr - target port SAS attributes.
 *      samLUN - samLUN from report LUNs data.
 *      data - matching target mapping data.
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    >0		error has occured
 */
static int
searchTargetPortMappingData(HBA_HANDLE handle, HBA_UINT32 portIndex,
    SMHBA_PORTATTRIBUTES *port, SMHBA_SAS_PORT *sasattr,
    struct targetPortConfig *configData)
{
	int			ret = 0;
	HBA_STATUS		status;
	SMHBA_TARGETMAPPING	*map = NULL;
	HBA_WWN			hbaPortWWN, domainPortWWN;
	int			numentries, count;
	targetPortMappingData_t	*TPMapData;
	struct scsi_inquiry	inq;
	struct scsi_extended_sense  sense;
	HBA_UINT32		responseSize, senseSize = 0;
	uchar_t			rawLUNs[DEFAULT_LUN_LENGTH], *lun_string;
	HBA_UINT8		scsiStatus;
	rep_luns_rsp_t		*lun_resp;
	int			lunNum, numberOfLun, lunCount;
	uint32_t		lunlength, tmp_lunlength;
	uint64_t		sasLUN;
	SMHBA_SCSILUN		smhbaLUN;

	hbaPortWWN = port->PortSpecificAttribute.SASPort->
	    LocalSASAddress;

	status = get_domainPort(handle, portIndex, port, &domainPortWWN);
	if (status == HBA_STATUS_OK) {
		if ((map = calloc(1, sizeof (*map))) == NULL) {
			(void *) fprintf(stderr, "%s\n",
			gettext("No enough memory on heap."));
			return (++ret);
		}
		map->NumberOfEntries = 1;

		status = SMHBA_GetTargetMapping(handle, hbaPortWWN,
		    domainPortWWN, map);

		if (status == HBA_STATUS_ERROR_MORE_DATA) {
			numentries = map->NumberOfEntries;
			free(map);
			map = calloc(1, sizeof (HBA_UINT32) +
			    (numentries * sizeof (SMHBA_SCSIENTRY)));
			if (map == NULL) {
				(void *) fprintf(stderr, "%s\n",
				    gettext("No enough memory on heap."));
				return (++ret);
			}
			map->NumberOfEntries = numentries;
			status = SMHBA_GetTargetMapping(handle,
			    hbaPortWWN, domainPortWWN, map);
		}

		if (status != HBA_STATUS_OK) {
			/* continue to build mapping data based SCSI info */
			ret++;
			free(map);
			map = NULL;
		}
	}

	/*
	 * Get report lun data.
	 */
	responseSize = DEFAULT_LUN_LENGTH;
	senseSize = sizeof (struct scsi_extended_sense);
	(void) memset(&sense, 0, sizeof (sense));
	status = SMHBA_ScsiReportLUNs(
	    handle,
	    hbaPortWWN,
	    sasattr->LocalSASAddress,
	    domainPortWWN,
	    (void *)rawLUNs,
	    &responseSize,
	    &scsiStatus,
	    (void *) &sense, &senseSize);

	/*
	 * if HBA_STATUS_ERROR_NOT_A_TARGET is return, we can assume this is
	 * a remote HBA and move on
	 */
	if (status != HBA_STATUS_OK) {
		configData->reportLUNsFailed = B_TRUE;
		if (map != NULL) {
			/*
			 * Let's search mapping data and indicate that Report
			 * LUNs failed.
			 */
			for (count = 0; count < map->NumberOfEntries; count++) {
				if (memcmp(map->entry[count].PortLun.
				    PortWWN.wwn, sasattr->LocalSASAddress.wwn,
				    sizeof (HBA_WWN)) == 0) {
					/* allocate mapping data for each LUN */
					TPMapData = calloc(1,
					    sizeof (targetPortMappingData_t));
					if (TPMapData == NULL) {
						(void *) fprintf(stderr, "%s\n",
						    gettext("No enough "
						    "memory."));
						free(map);
						return (++ret);
					}
					TPMapData->mappingExist = B_TRUE;
					TPMapData->osLUN =
					    map->entry[count].ScsiId.ScsiOSLun;
					(void) strlcpy(TPMapData->osDeviceName,
					    map->entry[count].ScsiId.
					    OSDeviceName,
					    sizeof (TPMapData->osDeviceName));
					TPMapData->inq_vid[0] = '\0';
					TPMapData->inq_pid[0] = '\0';
					TPMapData->inq_dtype = DTYPE_UNKNOWN;
					if (configData->map == NULL) {
						configData->map = TPMapData;
					} else {
						TPMapData->next =
						    configData->map->next;
						configData->map = TPMapData;
					}
				}
			}
		}
		(void) free(map);
		return (++ret);
	}
	lun_resp = (rep_luns_rsp_t *)((void *)rawLUNs);
	(void) memcpy(&tmp_lunlength, &(lun_resp->length),
	    sizeof (tmp_lunlength));
	lunlength = ntohl(tmp_lunlength);
	(void) memcpy(&numberOfLun, &lunlength, sizeof (numberOfLun));
	for (lunCount = 0; lunCount < (numberOfLun / 8); lunCount++) {
		/* allocate mapping data for each LUN */
		TPMapData = calloc(1,
		    sizeof (targetPortMappingData_t));
		if (TPMapData == NULL) {
			(void *) fprintf(stderr, "%s\n",
			    gettext("No enough memory."));
			free(map);
			return (++ret);
		}

		(void) memcpy(&TPMapData->reportLUN, lun_resp->
		    lun[lunCount].val, sizeof (SMHBA_SCSILUN));

		/*
		 * now issue standard inquiry to get Vendor
		 * and product information
		 */
		responseSize = sizeof (struct scsi_inquiry);
		senseSize = sizeof (struct scsi_extended_sense);
		(void) memset(&inq, 0, sizeof (struct scsi_inquiry));
		(void) memset(&sense, 0, sizeof (sense));
		sasLUN = ntohll(wwnConversion(lun_resp->lun[lunCount].val));
		(void) memcpy(&smhbaLUN, &sasLUN, sizeof (SMHBA_SCSILUN));
		status = SMHBA_ScsiInquiry(
		    handle,
		    hbaPortWWN,
		    sasattr->LocalSASAddress,
		    domainPortWWN,
		    smhbaLUN,
		    0,
		    0,
		    (void *) &inq, &responseSize,
		    &scsiStatus,
		    (void *) &sense, &senseSize);
		if (status != HBA_STATUS_OK) {
			TPMapData->inq_vid[0] = '\0';
			TPMapData->inq_pid[0] = '\0';
			TPMapData->inq_dtype = DTYPE_UNKNOWN;
			/* indicate that inquiry for this lun is failed */
			TPMapData->inquiryFailed = B_TRUE;
		} else {
			(void *) memcpy(TPMapData->inq_vid, inq.inq_vid,
			    sizeof (TPMapData->inq_vid));
			(void *) memcpy(TPMapData->inq_pid, inq.inq_pid,
			    sizeof (TPMapData->inq_pid));
			TPMapData->inq_dtype = inq.inq_dtype;
		}

		if (map != NULL) {
			for (count = 0; count < map->NumberOfEntries; count++) {
				if ((memcmp(map->entry[count].PortLun.
				    PortWWN.wwn, sasattr->LocalSASAddress.wwn,
				    sizeof (HBA_WWN)) == 0) &&
				    (memcmp(&(map->entry[count].PortLun.
				    TargetLun), &smhbaLUN,
				    sizeof (SMHBA_SCSILUN))
				    == 0)) {
					TPMapData->mappingExist = B_TRUE;
					TPMapData->osLUN =
					    map->entry[count].ScsiId.ScsiOSLun;
					(void) strlcpy(TPMapData->osDeviceName,
					    map->entry[count].ScsiId.
					    OSDeviceName,
					    sizeof (TPMapData->osDeviceName));
					break;
				}
			}
			if (count == map->NumberOfEntries) {
				TPMapData->osDeviceName[0] = '\0';
				lun_string = lun_resp->lun[lunCount].val;
				lunNum = ((lun_string[0] & 0x3F) << 8) |
				    lun_string[1];
				TPMapData->osLUN = lunNum;
			}
		} else {
		/* Not able to get any target mapping information */
			TPMapData->osDeviceName[0] = '\0';
			lun_string = lun_resp->lun[lunCount].val;
			lunNum = ((lun_string[0] & 0x3F) << 8) |
			    lun_string[1];
			TPMapData->osLUN = lunNum;
		}

		if (configData->map == NULL) {
			configData->map = TPMapData;
		} else {
			TPMapData->next = configData->map->next;
			configData->map = TPMapData;
		}
	}
	free(map);
	return (ret);
}

/*
 * Search the discovered LUs and construct the global LU list.
 *
 * Arguments:
 *      handle - handle to hba port.
 *      portIndex - hba port index
 *      port - hba port attributes.
 *      targetattr - target port attributes.
 *      sasattr - target port SAS attributes.
 *      pflag - options the user specified.
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    >0		error has occured
 */
static int
searchTargetPort(HBA_HANDLE handle, HBA_UINT32 portIndex,
    SMHBA_PORTATTRIBUTES *port, SMHBA_PORTATTRIBUTES *targetattr,
    SMHBA_SAS_PORT *sasattr, int pflag)
{
	int			ret = 0;
	HBA_WWN			expander;
	HBA_WWN			domainPortWWN;
	targetPortList_t 	*discoveredTP, *newTP;
	targetPortConfig_t	*TPConfig, *newConfig, *prevConfig;
	boolean_t		foundTP = B_FALSE;
	boolean_t		foundConfig = B_FALSE;
	int			status;
	SMHBA_PORTATTRIBUTES	tgtattr;
	SMHBA_SAS_PORT		tgtsasport;
	int			expanderValid = 0;

	status = get_domainPort(handle, portIndex, port, &domainPortWWN);
	switch (status) {
		case HBA_STATUS_OK:
			break;
		case HBA_STATUS_ERROR_NOT_SUPPORTED:
			/* don't increase error flag for no phy configuration */
			return (ret);
		case HBA_STATUS_ERROR:
		default:
			return (++ret);
	}

	/*
	 * First, we will iterate the already constructed target port
	 * list to see whether there is a target port already exist with
	 * matching target port SAS address.
	 */
	for (discoveredTP = gTargetPortList; discoveredTP != NULL;
	    discoveredTP = discoveredTP->next) {
		if (memcmp((void *)sasattr->LocalSASAddress.wwn,
		    (void *)discoveredTP->sasattr.LocalSASAddress.wwn,
		    sizeof (HBA_WWN)) == 0) {
			/*
			 * if the target port exist and
			 * verbose is not set, just return
			 */
			if (((pflag & PRINT_VERBOSE) == 0) &&
			    ((pflag & PRINT_TARGET_SCSI) == 0)) {
				return (ret);
			}
			foundTP = B_TRUE;
			break;
		}
	}

	if (foundTP == B_TRUE) {
		/*
		 * If there is a target port already exist, we should
		 * add more information on the target port to construct the
		 * whole topology.
		 * Here we will check whether the current hba port name
		 * has already been added.
		 */
		/* first get the expander SAS address compare */
		if (memcmp((void *)port->PortSpecificAttribute.SASPort->
		    LocalSASAddress.wwn, (void *)sasattr->
		    AttachedSASAddress.wwn, sizeof (HBA_WWN)) == 0) {
			/* NO expander */
			(void) memset((void *)expander.wwn, 0,
			    sizeof (HBA_WWN));
			expanderValid = 1;
		} else {
			if (wwnConversion(sasattr->AttachedSASAddress.wwn)
			    != 0) {
				/* expander exist.  We should verify it.  */
				(void) memcpy((void *)expander.wwn,
				    (void *)sasattr->AttachedSASAddress.wwn,
				    sizeof (HBA_WWN));

				(void *) memset(&tgtattr, 0, sizeof (tgtattr));
				(void *) memset(&tgtsasport, 0,
				    sizeof (tgtsasport));
				tgtattr.PortSpecificAttribute.SASPort
				    = &tgtsasport;
				status = SMHBA_GetPortAttributesByWWN(handle,
				    sasattr->AttachedSASAddress, domainPortWWN,
				    &tgtattr);
				if (status == HBA_STATUS_OK && tgtattr.PortType
				    == HBA_PORTTYPE_SASEXPANDER) {
					expanderValid = 1;
				}
			}
		}

		for (TPConfig = discoveredTP->configEntry,
		    foundConfig = B_FALSE; TPConfig != NULL;
		    TPConfig = TPConfig->next) {
			if ((strcmp(TPConfig->hbaPortName,
			    port->OSDeviceName) == 0) &&
			    (memcmp((void *)expander.wwn, (void *)TPConfig->
			    expanderSASAddr.wwn,
			    sizeof (HBA_WWN)) == 0)) {
				foundConfig = B_TRUE;
				break;
			}
		}

		/*
		 * If we get here, it means that it is a new hba port/exapnder
		 * sas address for this discovered target port.
		 */
		if (foundConfig == B_FALSE) {
			newConfig = (targetPortConfig_t *)calloc(1,
			    sizeof (targetPortConfig_t));
			if (newConfig == NULL) {
				(void *) fprintf(stderr,
				    "%s\n", strerror(errno));
				return (++ret);
			}

			(void) strlcpy(newConfig->hbaPortName, port->
			    OSDeviceName, sizeof (newConfig->hbaPortName));
			(void) memcpy((void *)newConfig->expanderSASAddr.wwn,
			    (void *)expander.wwn, sizeof (HBA_WWN));
			newConfig->expanderValid = expanderValid;
			if (discoveredTP->configEntry == NULL) {
				discoveredTP->configEntry = newConfig;
			} else {
				TPConfig = discoveredTP->configEntry;
				prevConfig = TPConfig;
				while (TPConfig != NULL &&
				    sas_name_comp(newConfig->hbaPortName,
				    TPConfig->hbaPortName) > 0) {
					prevConfig = TPConfig;
					TPConfig = TPConfig->next;
				}
				if (TPConfig == prevConfig) {
					/* Should be inserted in the head. */
					newConfig->next = TPConfig;
					discoveredTP->configEntry = newConfig;
				} else {
					newConfig->next = TPConfig;
					prevConfig->next = newConfig;
				}
			}
			/* if scsi option is not set return */
			if ((pflag & PRINT_TARGET_SCSI) == 0) {
				return (0);
			} else {
				return (searchTargetPortMappingData(
				    handle, portIndex, port,
				    sasattr, newConfig));
			}
		}
	} else {
		/*
		 * Here we got a new target port which has not ever exist
		 * in our global target port list. So add it to the list.
		 * list.
		 */
		newTP = (targetPortList_t *)calloc(1,
		    sizeof (targetPortList_t));

		if (newTP == NULL) {
			(void *) fprintf(stderr, "%s\n", strerror(errno));
			return (++ret);
		}

		(void) memcpy((void *)&newTP->targetattr, (void *)targetattr,
		    sizeof (SMHBA_PORTATTRIBUTES));
		(void) memcpy((void *)&newTP->sasattr, (void *)sasattr,
		    sizeof (SMHBA_SAS_PORT));

		newConfig = (targetPortConfig_t *)calloc(1,
		    sizeof (targetPortConfig_t));

		if (newConfig == NULL) {
			(void *) fprintf(stderr, "%s\n", strerror(errno));
			free(newTP);
			return (++ret);
		}

		(void) strlcpy(newConfig->hbaPortName, port->OSDeviceName,
		    sizeof (newConfig->hbaPortName));
		if (memcmp((void *)port->PortSpecificAttribute.SASPort->
		    LocalSASAddress.wwn, (void *)sasattr->
		    AttachedSASAddress.wwn, sizeof (HBA_WWN)) == 0) {
			/* NO expander */
			(void) memset((void *)newConfig->expanderSASAddr.wwn,
			    0, sizeof (HBA_WWN));
		} else {
			/* expander exist.  We should verify it. */
			(void) memcpy((void *)newConfig->expanderSASAddr.wwn,
			    (void *)sasattr->AttachedSASAddress.wwn,
			    sizeof (HBA_WWN));

			(void *) memset(&tgtattr, 0, sizeof (tgtattr));
			(void *) memset(&tgtsasport, 0, sizeof (tgtsasport));
			tgtattr.PortSpecificAttribute.SASPort = &tgtsasport;
			status = SMHBA_GetPortAttributesByWWN(handle,
			    sasattr->AttachedSASAddress, domainPortWWN,
			    &tgtattr);
			if (status == HBA_STATUS_OK && tgtattr.PortType ==
			    HBA_PORTTYPE_SASEXPANDER) {
				expanderValid = 1;
			}
			newConfig->expanderValid = expanderValid;
		}

		newTP->configEntry = newConfig;

		newTP->next = gTargetPortList; /* insert at head */
		gTargetPortList = newTP; /* set new head */

		/* if scsi option is not set return */
		if ((pflag & PRINT_TARGET_SCSI) == 0) {
			return (0);
		} else {
			return (searchTargetPortMappingData(
			    handle, portIndex, port, sasattr, newConfig));
		}
	}
	return (ret);
}

/*
 * Search the discovered LUs and construct the global LU list.
 *
 * Arguments:
 *      entryP - one of the target mapping data.
 *      handle - handle to hba port.
 *      hbaPortWWN - hba port sas address.
 *      domainPortWWN - domain port WWN for this sas domain.
 *      portName - HBA port OS Device Name.
 *      pflag - options the user specified.
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    >0		error has occured
 */
static int
searchDevice(PSMHBA_SCSIENTRY entryP,
    HBA_HANDLE handle, HBA_WWN hbaPortWWN, HBA_WWN domainPortWWN,
    char *portName, int pflag)
{
	HBA_STATUS		status;
	int			ret = 0;
	discoveredDevice 	*discoveredLU, *newDevice;
	portList		*portElem, *newPort, *prevElem;
	tgtPortWWNList 		*newTgtWWN, *TgtWWNList;
	boolean_t		foundDevice = B_FALSE;
	boolean_t		foundPort = B_FALSE;
	struct scsi_inquiry	inq;
	HBA_UINT32		responseSize, senseSize = 0;
	HBA_UINT8		inq_status;
	SMHBA_SCSILUN		smhbaLUN;
	struct scsi_extended_sense sense;

	/* if OSDeviceName is not set, we don't need to search */
	if (entryP->ScsiId.OSDeviceName[0] == '\0') {
		return (ret);
	}

	/*
	 * First, we will iterate the already constructed discovered LU
	 * list to see whether there is a LU already exist with the same OS
	 * device name as current target mapping data entry.
	 */
	for (discoveredLU = LUList; discoveredLU != NULL;
	    discoveredLU = discoveredLU->next) {
		if (strcmp(entryP->ScsiId.OSDeviceName,
		    discoveredLU->OSDeviceName) == 0) {
			/*
			 * if there is existing OS Device Name and
			 * verbose is not set, just return
			 */
			if ((pflag & PRINT_VERBOSE) == 0) {
				return (ret);
			}
			foundDevice = B_TRUE;
			break;
		}
	}

	if (foundDevice == B_TRUE) {
		/*
		 * If there is a discovered LU already exist, we should
		 * add more information on this LU to construct the whole
		 * topology.
		 * Here we will check whether the current hba port has
		 * already been added.
		 */
		for (portElem = discoveredLU->HBAPortList,
		    foundPort = B_FALSE;  portElem != NULL;
		    portElem = portElem->next) {
			if (strcmp(portElem->portName,
			    portName) == 0) {
				foundPort = B_TRUE;
				break;
			}
		}

		/*
		 * If we get here, it means that it is a new hba port name
		 * for this discovered LU.
		 */
		if (foundPort == B_FALSE) {
			newPort = (portList *)calloc(1, sizeof (portList));
			if (newPort == NULL) {
				(void *) fprintf(stderr,
				    "%s\n", strerror(errno));
				return (++ret);
			}
			(void) strlcpy(newPort->portName, portName,
			    sizeof (newPort->portName));

			portElem = discoveredLU->HBAPortList;
			prevElem = portElem;
			while (portElem != NULL &&
			    sas_name_comp(newPort->portName, portElem->portName)
			    > 0) {
				prevElem = portElem;
				portElem = portElem->next;
			}
			if (portElem == prevElem) {
				/* Insert in the head of list. */
				newPort->next = portElem;
				discoveredLU->HBAPortList = newPort;
			} else {
				newPort->next = portElem;
				prevElem->next = newPort;
			}
			/* add Target Port */
			newPort->tgtPortWWN = (tgtPortWWNList *)calloc(1,
			    sizeof (tgtPortWWNList));
			if (newPort->tgtPortWWN == NULL) {
				(void *) fprintf(stderr,
				    "%s\n", strerror(errno));
				return (++ret);
			}
			(void *) memcpy((void *)&(newPort->tgtPortWWN->portWWN),
			    (void *)&(entryP->PortLun.PortWWN),
			    sizeof (HBA_WWN));
			/* Set LUN data */
			newPort->tgtPortWWN->scsiOSLun =
			    entryP->ScsiId.ScsiOSLun;
		} else {
			/*
			 * Otherwise, we just need to add the target port
			 * sas address information.
			 */
			for (TgtWWNList = portElem->tgtPortWWN;
			    TgtWWNList != NULL;
			    TgtWWNList = TgtWWNList->next) {
				if (memcmp(&TgtWWNList->portWWN,
				    &entryP->PortLun.PortWWN,
				    sizeof (HBA_WWN)) == 0)
					return (0);
			}
			/* add it to existing */
			newTgtWWN = (tgtPortWWNList *)calloc(1,
			    sizeof (tgtPortWWNList));
			if (newTgtWWN == NULL) {
				(void *) fprintf(stderr,
				    "%s\n", strerror(errno));
				return (++ret);
			}
			/* insert at head */
			newTgtWWN->next = portElem->tgtPortWWN;
			portElem->tgtPortWWN = newTgtWWN;
			(void *) memcpy((void *)&(newTgtWWN->portWWN),
			    (void *)&(entryP->PortLun.PortWWN),
			    sizeof (HBA_WWN));
			/* Set LUN data */
			newTgtWWN->scsiOSLun =
			    entryP->ScsiId.ScsiOSLun;
		}
	} else {
		/*
		 * Here we got a new discovered LU which has not ever exist
		 * in our global LU list. So add it into our global LU
		 * list.
		 */
		newDevice = (discoveredDevice *)calloc(1,
		    sizeof (discoveredDevice));

		if (newDevice == NULL) {
			(void *) fprintf(stderr, "%s\n", strerror(errno));
			return (++ret);
		}
		newDevice->next = LUList; /* insert at head */
		LUList = newDevice; /* set new head */

		/* copy device name */
		(void *) strlcpy(newDevice->OSDeviceName,
		    entryP->ScsiId.OSDeviceName,
		    sizeof (newDevice->OSDeviceName));

		/* if verbose is not set return */
		if ((pflag & PRINT_VERBOSE) == 0) {
			return (0);
		}

		/* copy WWN data */
		newDevice->HBAPortList = (portList *)calloc(1,
		    sizeof (portList));
		if (newDevice->HBAPortList == NULL) {
			(void *) fprintf(stderr, "%s\n", strerror(errno));
			return (++ret);
		}
		(void) strlcpy(newDevice->HBAPortList->portName,
		    portName, sizeof (newDevice->HBAPortList->portName));

		newDevice->HBAPortList->tgtPortWWN =
		    (tgtPortWWNList *)calloc(1, sizeof (tgtPortWWNList));
		if (newDevice->HBAPortList->tgtPortWWN == NULL) {
			(void *) fprintf(stderr, "%s\n", strerror(errno));
			return (++ret);
		}

		(void *) memcpy((void *)&(newDevice->HBAPortList->\
		    tgtPortWWN->portWWN),
		    (void *)&(entryP->PortLun.PortWWN),
		    sizeof (HBA_WWN));
		newDevice->HBAPortList->tgtPortWWN->scsiOSLun =
		    entryP->ScsiId.ScsiOSLun;

		responseSize = sizeof (struct scsi_inquiry);
		senseSize = sizeof (struct scsi_extended_sense);
		(void *) memset(&inq, 0, sizeof (struct scsi_inquiry));
		(void *) memset(&sense, 0, sizeof (sense));
		(void *) memcpy(&smhbaLUN, &entryP->PortLun.TargetLun,
		    sizeof (smhbaLUN));

		/*
		 * Retrieve the VPD data for the newly found discovered LU.
		 */
		status = SMHBA_ScsiInquiry(
		    handle,
		    hbaPortWWN,
		    entryP->PortLun.PortWWN,
		    domainPortWWN,
		    smhbaLUN,
		    0,
		    0,
		    (void *) &inq, &responseSize,
		    &inq_status,
		    (void *) &sense, &senseSize);

		if (status != HBA_STATUS_OK) {
			/* init VID/PID/dType as '\0' */
			newDevice->VID[0] = '\0';
			newDevice->PID[0] = '\0';
			newDevice->dType = DTYPE_UNKNOWN;
			/* initialize inq status */
			newDevice->inquiryFailed = B_TRUE;
			ret++;
		} else {
			(void *) memcpy(newDevice->VID, inq.inq_vid,
			    sizeof (newDevice->VID));
			(void *) memcpy(newDevice->PID, inq.inq_pid,
			    sizeof (newDevice->PID));
			newDevice->dType = inq.inq_dtype;
			/* initialize inq status */
			newDevice->inquiryFailed = B_FALSE;
		}
	}
	return (ret);
}

/*
 * Function we use to insert a newly discovered port.
 * Return:
 * 	0 - success
 * 	>0 - failed
 */
static int
sas_rp_tree_insert(rp_tree_t **rproot,
    rp_tree_t *rpnode)
{
	HBA_UINT8 *wwn1, *wwn2, *wwn3;
	rp_tree_t *node_ptr;
	int ret = 0;

	if (rproot == NULL) {
		(void *) fprintf(stderr, "%s\n",
		    gettext("Error: NULL rproot"));
		return (1);
	}

	if (rpnode == NULL) {
		(void *) fprintf(stderr, "%s\n",
		    gettext("Error: NULL rpnode"));
		return (1);
	}

	if (*rproot == NULL) {
		*rproot = rpnode;
		return (0);
	}

	wwn1 = (*rproot)->sasattr.LocalSASAddress.wwn;
	wwn2 = (*rproot)->sasattr.AttachedSASAddress.wwn;
	wwn3 = rpnode->sasattr.AttachedSASAddress.wwn;

	/*
	 * If the attched sas address is equal to the local sas address,
	 * then this should be a child node of current root node.
	 */
	if (memcmp(wwn1, wwn3, sizeof (HBA_WWN)) == 0) {
		(void) sas_rp_tree_insert(&(*rproot)->child, rpnode);
		rpnode->parent = *rproot;
	} else if (memcmp(wwn2, wwn3, sizeof (HBA_WWN)) == 0) {
		/*
		 * If the attached sas address is equal to the attached sas
		 * address of current root node, then this should be a
		 * sibling node.
		 * Insert the SAS/SATA Device at the head of sibling list.
		 */
		if (rpnode->portattr.PortType != HBA_PORTTYPE_SASEXPANDER) {
			rpnode->sibling = *rproot;
			*rproot = rpnode;
		} else {
			/*
			 * Insert the SAS Expander at the tail of sibling
			 * list.
			 */
			node_ptr = *rproot;
			while (node_ptr->sibling != NULL)
				node_ptr = node_ptr->sibling;
			node_ptr->sibling = rpnode;
		}
		rpnode->parent = (*rproot)->parent;
	} else {
		/*
		 * If enter here, we should first try to insert the discovered
		 * port node into the child sub-tree, then try to insert to the
		 * sibling sub-trees. If we failed to insert the discovered
		 * port node, return 1. The caller will queue this node
		 * up and retry insertion later.
		 */
		if ((*rproot)->child) {
			ret = sas_rp_tree_insert(&(*rproot)->child, rpnode);
		}
		if ((*rproot)->child == NULL || ret != 0) {
			if ((*rproot)->sibling) {
				ret = sas_rp_tree_insert(&(*rproot)->sibling,
				    rpnode);
			} else
				ret = 1;
		}
		return (ret);
	}
	return (0);
}

/*
 * Function which will print out the whole disocvered port topology.
 * Here we use the Preorder Traversal algorithm.
 * The indentation rules are:
 * 	1 * TABLEN - for attributes
 * 	2 * TABLEN - for next tier target port/expander
 */
static int
sas_rp_tree_print(HBA_HANDLE handle, char *adapterName,
    HBA_UINT32 portIndex, SMHBA_PORTATTRIBUTES *port,
    rp_tree_t *rpnode, inputArg_t *input,
    int gident, int *printPort)
{
	int ret = 0, lident;

	if (rpnode == NULL)
		return (ret);
	lident = gident;

	/*
	 * We assume that all the nodes are disocvered ports(sas device or
	 * expander).
	 */
	if (input->wwnCount > 0) {
		/* Adjust local indentation if a discovered port specified. */
		lident = 2 * TABLEN;
		/*
		 * Check whether current node match one of the specified
		 * SAS addresses.
		 */
		if ((rpnode->portattr.PortType != HBA_PORTTYPE_SASEXPANDER) ||
		    !isPortWWNInArgv(input,
		    &rpnode->sasattr.LocalSASAddress)) {
			/*
			 * Step down to child tree first.
			 */
			ret += sas_rp_tree_print(handle, adapterName,
			    portIndex, port, rpnode->child, input,
			    gident + 2 * TABLEN, printPort);
			/*
			 * Then check the sibling tree.
			 */
			ret += sas_rp_tree_print(handle, adapterName,
			    portIndex, port, rpnode->sibling, input,
			    gident, printPort);
			return (ret);
		}
	}

	if ((rpnode->portattr.PortType == HBA_PORTTYPE_SASEXPANDER) ||
	    (input->pflag & PRINT_TARGET_PORT)) {
		/*
		 * We should print the header(HBA Name + HBA Port Name)
		 * on-demand. It means that, if we have expander device
		 * address specified on the command line, we should print
		 * the header once we find a matching one. Or we will
		 * print the header from the beginning of the output.
		 */
		if (g_printHBA == 0) {
			(void *) fprintf(stdout, "%s %s\n",
			    "HBA Name:", adapterName);
			g_printHBA = 1;
		}

		if (*printPort == 0) {
			(void *) fprintf(stdout, "%s%s %s\n",
			    getIndentSpaces(TABLEN),
			    "HBA Port Name:", port->OSDeviceName);
			*printPort = 1;
		}
		ret += sas_print_rpnode(input, rpnode, lident, gident);
	}

	/*
	 * If operands provided with "-t" option specified, we will print
	 * the immediate child nodes information under the expander.
	 */
	if (input->pflag & PRINT_TARGET_PORT) {
		/* no operand. ignore the option. */
		if (input->wwnCount > 0) {
			if (rpnode->portattr.PortType ==
			    HBA_PORTTYPE_SASEXPANDER) {
				ret += sas_rp_tree_print_desc(handle,
				    portIndex, port, rpnode->child,
				    input,
				    lident + 2 * TABLEN,
				    gident + 2 * TABLEN);
			}
		}
	}

	/*
	 * Here we use DFS(Depth First Search) algorithm to traverse the
	 * whole tree.
	 */
	ret += sas_rp_tree_print(handle, adapterName,
	    portIndex, port, rpnode->child, input,
	    gident + 2 * TABLEN, printPort);
	ret += sas_rp_tree_print(handle, adapterName,
	    portIndex, port, rpnode->sibling, input,
	    gident, printPort);
	return (ret);
}

/*
 * Function which will destroy the whole discovered port tree.
 * Here we use the Postorder Traversal algorithm.
 */
static void sas_rp_tree_free(rp_tree_t *rproot)
{
	tgt_mapping *cur, *next;

	if (rproot == NULL)
		return;

	/*
	 * Free child tree first.
	 */
	if (rproot->child) {
		sas_rp_tree_free(rproot->child);
	}

	/*
	 * Free sibling trees then.
	 */
	if (rproot->sibling) {
		sas_rp_tree_free(rproot->sibling);
	}

	/*
	 * Free root node at last.
	 */
	cur = rproot->first_entry;
	while (cur != NULL) {
		next = cur->next;
		free(cur);
		cur = next;
	}
	free(rproot);
}

/*
 * Function used to print out all the descendant nodes.
 * handle - handle to HBA.
 * port - port attributes of current HBA port.
 * desc - the root node of a subtree which will be processed.
 * input - input argument.
 * lident - local indentation for shifting indentation.
 * gident - global indentation, can also be used to obtain Tier number.
 */
/*ARGSUSED*/
static int
sas_rp_tree_print_desc(HBA_HANDLE handle, HBA_UINT32 portIndex,
    SMHBA_PORTATTRIBUTES *port, rp_tree_t *desc,
    inputArg_t *input, int lident, int gident)
{
	int ret = 0;
	rp_tree_t   *rp_node;

	if (desc == NULL)
		return (ret);
	/*
	 * Walk through the subtree of desc by Pre-Order Traversal Algo.
	 */
	for (rp_node = desc; rp_node !=	NULL; rp_node = rp_node->sibling) {
		ret += sas_print_rpnode(input, rp_node, lident, gident);
	}

	return (ret);
}

/*
 * Function used to print the information of specified SAS address.
 * handle - handle to a HBA.
 * port - port attributes of a HBA port.
 * rpnode - discovered port which will be processed.
 * lident - local indentation used for shifting indentation.
 * gident - global indentation used for calculating "Tier" number.
 */
static int
sas_print_rpnode(inputArg_t *input,
    rp_tree_t *rpnode, int lident, int gident)
{
	int ret = 0;

	if (rpnode->portattr.PortType == HBA_PORTTYPE_SASEXPANDER) {
		(void *) fprintf(stdout, "%s%s(Tier %d): %016llx\n",
		    getIndentSpaces(lident),
		    "Expander SAS Address",
		    gident / (2 * TABLEN),
		    wwnConversion(rpnode->sasattr.LocalSASAddress.wwn));
	} else {
		(void *) fprintf(stdout, "%s%s %016llx\n",
		    getIndentSpaces(lident),
		    "Target Port SAS Address:",
		    wwnConversion(rpnode->sasattr.LocalSASAddress.wwn));
	}
	if (input->pflag & PRINT_VERBOSE) {
		if (rpnode->portattr.PortType != HBA_PORTTYPE_SASEXPANDER) {
			(void *) fprintf(stdout, "%s%s %s\n",
			    getIndentSpaces(TABLEN + lident),
			    "Type:",
			    getStateString(rpnode->portattr.PortType,
			    porttype_string));
		} else {
			(void *) fprintf(stdout, "%s%s %s\n",
			    getIndentSpaces(TABLEN + lident),
			    "OS Device Name:",
			    rpnode->portattr.OSDeviceName);
			(void *) fprintf(stdout, "%s%s %s\n",
			    getIndentSpaces(TABLEN + lident),
			    "State: ",
			    getStateString(rpnode->portattr.PortState,
			    portstate_string));
		}
	}
	rpnode->printed = 1;
	return (ret);
}

/*
 * Function used to get the correct domainPortWWN as needed by some of the
 * SMHBA APIs.
 * handle - handle to a HBA.
 * portIndex - index to locate the port.
 * port - pointer to the structure holding port attributes.
 * pdomainPort - pointer to the buffer holding domainPortWWN.
 */
HBA_STATUS
get_domainPort(HBA_HANDLE handle,
    int portIndex, PSMHBA_PORTATTRIBUTES port,
    HBA_WWN *pdomainPort)
{
	HBA_STATUS status;
	PSMHBA_SAS_PORT sasport;
	SMHBA_SAS_PHY phyattr;

	sasport = port->PortSpecificAttribute.SASPort;
	(void *) memset(pdomainPort, 0, sizeof (HBA_WWN));
	/*
	 * Since iport can exist without any phys,
	 * sasinfo hba-port -v has indicated numberOfPhys;
	 * if there is no phys within the hba, just return OK.
	 */
	if (sasport->NumberofPhys > 0) {
		status = SMHBA_GetSASPhyAttributes(handle, portIndex,
		    0, &phyattr);
		if (status != HBA_STATUS_OK)
			return (status);
		(void *) memcpy(pdomainPort, &phyattr.domainPortWWN,
		    sizeof (HBA_WWN));
	} else {
		/* return not supported for no phy configured */
		return (HBA_STATUS_ERROR_NOT_SUPPORTED);
	}
	return (HBA_STATUS_OK);
}

/*
 * Comparison function for comparing names possibly ending with digits.
 * Return:
 * 	<0 - name1 is less than name2.
 * 	0 - name1 is equal with name2.
 * 	>0 - name1 is more than name2.
 */
static int
sas_name_comp(const char *name1, const char *name2)
{
	int i = 0;

	if (name1 == name2)
		return (0);

	while ((name1[i] == name2[i]) && (name1[i] != '\0'))
		i++;

	/* If neither of name1[i] and name2[i] is '\0'. */
	if (isdigit(name1[i]) && isdigit(name2[i]))
		return (atoi(&name1[i]) - atoi(&name2[i]));

	/* One of name1[i] and name2[i] is not digit. */
	return (name1[i] - name2[i]);
}
/*
 * Comparison function for sorting HBA/HBA Port.
 * arg1 - first argument of type sas_elem_t.
 * arg2 - second argument of type sas_elem_t.
 * Return:
 * 	<0 - arg1 is less than arg2.
 * 	0 - arg1 is equal with arg2.
 * 	>0 - arg1 is more than arg2.
 */
static int
sas_elem_compare(const void *arg1, const void *arg2)
{
	sas_elem_t *p1, *p2;
	p1 = (sas_elem_t *)arg1;
	p2 = (sas_elem_t *)arg2;
	return (sas_name_comp(p1->name, p2->name));
}

/*
 * Sorting function for HBA/HBA Port output.
 * array - elements array of type sas_elem_t.
 * nelem - number of elements in array of type sas_elem_t.
 */
static void
sas_elem_sort(sas_elem_t *array, int nelem)
{
	qsort((void *)array, nelem, sizeof (sas_elem_t), sas_elem_compare);
}
