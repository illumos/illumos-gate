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



#include "HBAPort.h"
#include "Exceptions.h"
#include "Trace.h"
#include <iostream>
#include <iomanip>
#include <cerrno>
#include <cstring>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <dirent.h>
#include <libdevinfo.h>

using namespace std;

/**
 * Standard definition for general topology lookup (See T11 FC-FS)
 */
const int HBAPort::RNID_GENERAL_TOPOLOGY_DATA_FORMAT = 0xDF;
const uint8_t HBAPort::HBA_NPIV_PORT_MAX = UCHAR_MAX;

/**
 * @memo	    Construct a new default HBA Port
 */
HBAPort::HBAPort() {
}

/**
 * @memo	    Compare two HBA ports for equality
 * @return	    TRUE if both ports are the same
 * @return	    FALSE if the ports are different
 *
 * @doc		    Comparison is based on Node WWN, Port WWN and path
 */
bool HBAPort::operator==(HBAPort &comp) {
	return (this->getPortWWN() == comp.getPortWWN() &&
		this->getNodeWWN() == comp.getNodeWWN() &&
		this->getPath() == comp.getPath());
}

/**
 * @memo	    Validate that the port is still present in the system
 * @exception	    UnavailableException if the port is not present
 *
 * @doc		    If the port is still present on the system, the routine
 *		    will return normally.  If the port is not present
 *		    an exception will be thrown.
 */
void HBAPort::validatePresent() {
	Trace log("HBAPort::validatePresent");
	string path = getPath();
	struct stat sbuf;
	if (stat(path.c_str(), &sbuf) == -1) {
	    if (errno == ENOENT) {
		throw UnavailableException();
	    } else {
		log.debug("Unable to stat %s: %s", path.c_str(),
			strerror(errno));
		throw InternalError();
	    }
	}
}


/*
 * structure for di_devlink_walk
 */
typedef struct walk_devlink {
	char *path;
	size_t len;
	char **linkpp;
} walk_devlink_t;

/**
 * @memo	    callback funtion for di_devlink_walk
 * @postcondition   Find matching /dev link for the given path argument.
 * @param	    devlink element and callback function argument.
 *
 * @doc		    The input path is expected to not have "/devices".
 */
extern "C" int
get_devlink(di_devlink_t devlink, void *arg) {
	Trace log("get_devlink");
	walk_devlink_t *warg = (walk_devlink_t *)arg;

	/*
	 * When path is specified, it doesn't have minor
	 * name. Therefore, the ../.. prefixes needs to be stripped.
	 */
	if (warg->path) {
		// di_devlink_content contains /devices
		char *content = (char *)di_devlink_content(devlink);
		char *start = strstr(content, "/devices");

		if (start == NULL ||
		    strncmp(start, warg->path, warg->len) != 0 ||
		    // make it sure the device path has minor name
		    start[warg->len] != ':')
			return (DI_WALK_CONTINUE);
	}

	*(warg->linkpp) = strdup(di_devlink_path(devlink));
	return (DI_WALK_TERMINATE);
}

/**
 * @memo	    Convert /devices paths to /dev sym-link paths.
 * @postcondition   The mapping buffer OSDeviceName paths will be
 *		    converted to short names.
 * @param	    mappings The target mappings data to convert to
 *		    short names
 *
 * @doc		    If no link
 * is found, the long path is left as is.
 * Note: The NumberOfEntries field MUST not be greater than the size
 * of the array passed in.
 */
void HBAPort::convertToShortNames(PHBA_FCPTARGETMAPPINGV2 mappings) {
	Trace log("HBAPort::convertToShortNames");
	di_devlink_handle_t hdl;
	walk_devlink_t warg;
	char *minor_path, *devlinkp;

	if ((hdl = di_devlink_init(NULL, 0)) == NULL) {
	    log.internalError("di_devlink_init failed. Errno:%d", errno);
	    // no need to check further, just return here.
	    return;
	}

	for (int j = 0; j < mappings->NumberOfEntries; j++) {
	    if (strchr(mappings->entry[j].ScsiId.OSDeviceName, ':')) {
		// search link for minor node
		minor_path = mappings->entry[j].ScsiId.OSDeviceName;
		if (strstr(minor_path, "/devices") != NULL) {
		    minor_path = mappings->entry[j].ScsiId.OSDeviceName +
			strlen("/devices");
		} else {
		    minor_path = mappings->entry[j].ScsiId.OSDeviceName;
		}
		warg.path = NULL;
	    } else {
		minor_path = NULL;
		if (strstr(mappings->entry[j].ScsiId.OSDeviceName,
		    "/devices") != NULL) {
		    warg.len = strlen (mappings->entry[j].ScsiId.OSDeviceName) -
			    strlen ("/devices");
		    warg.path = mappings->entry[j].ScsiId.OSDeviceName +
			    strlen ("/devices");
		} else {
		    warg.len = strlen(mappings->entry[j].ScsiId.OSDeviceName);
		    warg.path = mappings->entry[j].ScsiId.OSDeviceName;
		}
	    }

	    devlinkp = NULL;
	    warg.linkpp = &devlinkp;
	    (void) di_devlink_walk(hdl, NULL, minor_path, DI_PRIMARY_LINK,
		(void *)&warg, get_devlink);

	    if (devlinkp != NULL) {
		snprintf(mappings->entry[j].ScsiId.OSDeviceName,
		    sizeof (mappings->entry[j].ScsiId.OSDeviceName),
		    "%s", devlinkp);
		free(devlinkp);
	    } // else leave OSDeviceName alone.

	}

	di_devlink_fini(&hdl);

}

/*
 * Finds controller path for a give device path.
 *
 * Return vale: controller path.
 */
string HBAPort::lookupControllerPath(string path) {
	Trace log("lookupControllerPath");
	DIR	    *dp;
	char    buf[MAXPATHLEN];
	char    node[MAXPATHLEN];
	struct dirent **dirpp, *dirp;
	const char    dir[] = "/dev/cfg";
	ssize_t	    count;
	uchar_t *dir_buf = new uchar_t[sizeof (struct dirent) + MAXPATHLEN];

	if ((dp = opendir(dir)) == NULL) {
	    string tmp = "Unable to open ";
	    tmp += dir;
	    tmp += "to find controller number.";
	    delete[] (dir_buf);
	    throw IOError(tmp);
	}

	dirp = (struct dirent *) dir_buf;
	dirpp = &dirp;
	while ((readdir_r(dp, dirp, dirpp)) == 0  && dirp != NULL) {
	    if (strcmp(dirp->d_name, ".") == 0 ||
		    strcmp(dirp->d_name, "..") == 0) {
		continue;
	    }
	    sprintf(node, "%s/%s", dir, dirp->d_name);
	    if ((count = readlink(node,buf,sizeof(buf)))) {
		buf[count] = '\0';
		if (strstr(buf, path.c_str())) {
		    string cfg_path = dir;
		    cfg_path += "/";
		    cfg_path += dirp->d_name;
		    closedir(dp);
		    delete[] (dir_buf);
		    return (cfg_path);
		}
	    }
	}

	closedir(dp);
	delete[] (dir_buf);
	throw InternalError("Unable to find controller path");
}

void HBAPort::addPort(HBANPIVPort *port) {
	Trace log("HBAPort::addPort");
	lock();
	// support hba with up to UCHAR_MAX number of ports.
	if (npivportsByIndex.size() + 1 > HBA_NPIV_PORT_MAX) {
		unlock();
		throw InternalError("HBA NPIV Port count exceeds max number of ports");
	}

	try {
		npivportsByWWN[port->getPortWWN()] = port;
		npivportsByIndex.insert(npivportsByIndex.end(), port);
		unlock();
	} catch (...) {
		unlock();
		throw;
	}
}

HBANPIVPort* HBAPort::getPort(uint64_t wwn) {
	Trace log("HBAPort::getPort");
	HBANPIVPort *port = NULL;

	lock();
	try {
		if (npivportsByWWN.find(wwn) == npivportsByWWN.end()) {
			throw IllegalWWNException();
		}
		port = npivportsByWWN[wwn];
		unlock();
		return (port);
	} catch (...) {
		unlock();
		throw;
	}
}

HBANPIVPort* HBAPort::getPortByIndex(int index) {
	Trace log("HBAPort::getPortByIndex");
	lock();
	try {
		if (index >= npivportsByIndex.size() || index < 0) {
			throw IllegalIndexException();
		}
		HBANPIVPort *tmp = npivportsByIndex[index];
		unlock();
		return (tmp);
	} catch (...) {
		unlock();
		throw;
	}
}

