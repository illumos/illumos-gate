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


#include "HBANPIVPort.h"
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
 * @memo            Construct a new default HBA Port
 * @version         1.7
 */
HBANPIVPort::HBANPIVPort() {
}

/**
 * @memo            Compare two HBA ports for equality
 * @return          TRUE if both ports are the same
 * @return          FALSE if the ports are different
 * @version         1.7
 *
 * @doc             Comparison is based on Node WWN, Port WWN and path
 */
bool HBANPIVPort::operator==(HBANPIVPort &comp) {
	return (this->getPortWWN() == comp.getPortWWN() &&
	    this->getNodeWWN() == comp.getNodeWWN());
}

/*
 * Finds controller path for a give device path.
 *
 * Return vale: controller path.
 */
string HBANPIVPort::lookupControllerPath(string path) {
	Trace log("lookupControllerPath");
	DIR	*dp;
	char	buf[MAXPATHLEN];
	char	node[MAXPATHLEN];
	struct dirent	**dirpp, *dirp;
	const char	dir[] = "/dev/cfg";
	ssize_t	count;
	uchar_t	*dir_buf = new uchar_t[sizeof (struct dirent) + MAXPATHLEN];

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

