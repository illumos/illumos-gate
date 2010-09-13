/*******************************************************************************
 * Copyright (C) 2004-2008 Intel Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corp. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "iatshareddata.h"
#include "ATVersion.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <climits>
#include <cerrno>
#include <fstream>
#include <dirent.h>

#define AT_VERSION_ARGUMENT "--version"
#define AT_VERSION_MAXSIZE 40
#define AT_APPNAME_MAXSIZE 15
#define ATstr(s) ATname(s)
#define ATname(s) #s
#define AT_VERSION_OUT_FORMAT "Version: %." ATstr(AT_VERSION_MAXSIZE) "s\n"
#define AT_VERSION_SCAN_FORMAT "Version: %" ATstr(AT_VERSION_MAXSIZE) "s"
#define AT_PIDFILE_NAME_FORMAT IATSTATERUNDIR "/%." ATstr(AT_APPNAME_MAXSIZE) "s.pid"
#define AT_DEF_PIDFILE_NAME_FORMAT "/var/run/%." ATstr(AT_APPNAME_MAXSIZE) "s.pid"
#define AT_PROCSTAT_NAME_FORMAT "Name:\t%" ATstr(AT_APPNAME_MAXSIZE) "s\n"

const std::string ATVersion::appSearchPath =
    "PATH='/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin' && ";

bool ATVersion::ShowVersionIfArg(int argc, const char **argv, const char *versionStr)
{
	if (1 < argc) {
		for (int i = 1; i < argc; i++) {
			if (0 == strncmp(argv[i], AT_VERSION_ARGUMENT, strlen(AT_VERSION_ARGUMENT))) {
				fprintf(stdout, AT_VERSION_OUT_FORMAT, versionStr);
				return true;
			}
		}
	}
	return false;
}

bool ATVersion::GetAppVersion(const char *appName, std::string &version)
{
	std::list<unsigned long> pids;

	version = "";
	if (IsAppRunning(appName, pids)) {
		for (std::list<unsigned long>::iterator iter = pids.begin(); iter != pids.end(); iter++) {
			std::string path = GetAppPathByPid(*iter);
			if (!path.empty()) {
				version = GetProcessVersion(path);
				return true;
			}
		}
	}
	version = GetProcessVersion(ATVersion::appSearchPath + appName);
	if (version.empty()) {
		version = GetProcessVersion(appName);
	}
	return false;
}

std::string ATVersion::GetProcessVersion(std::string cmd)
{
	if (cmd.empty()) {
		return "";
	}

	FILE *fp = popen((cmd + " " AT_VERSION_ARGUMENT " 2>/dev/null").c_str(), "r");
	if (fp) {
		char buf[AT_VERSION_MAXSIZE + 1];
		int res = fscanf(fp, AT_VERSION_SCAN_FORMAT, buf);
		buf[AT_VERSION_MAXSIZE] = '\0';
		pclose(fp);
		if (1 == res) {
			return buf;
		}
	}
	return "";
}

bool ATVersion::IsAppRunning(const char *appName, std::list<unsigned long> &pids)
{
	struct  dirent **namelist;
	FILE   *stat;
	char    name_str[AT_APPNAME_MAXSIZE + 1];
	int     num_entries;
	char    status_path[256];
	unsigned long pid;
	unsigned long selfpid = 0;
	bool    res = false;
	int     ret;

	pids.clear();

	memset(status_path, '\0', sizeof(status_path));
	snprintf(status_path, sizeof(status_path), AT_PIDFILE_NAME_FORMAT, appName);
	std::ifstream pidf(status_path);
	if (pidf.is_open()) {
		pidf >> pid;
		pidf.close();
		if (!(GetAppPathByPid(pid).empty())) {
			pids.push_back(pid);
			return true;
		}
	}

	memset(status_path, '\0', sizeof(status_path));
	snprintf(status_path, sizeof(status_path), AT_DEF_PIDFILE_NAME_FORMAT, appName);
	pidf.open(status_path);
	if (pidf.is_open()) {
		pidf >> pid;
		pidf.close();
		if (!(GetAppPathByPid(pid).empty())) {
			pids.push_back(pid);
			return true;
		}
	}

	num_entries = scandir("/proc", &namelist, 0, alphasort);
	if (num_entries < 0) {
		return false;
	}

	memset(status_path, '\0', sizeof(status_path));
	if (-1 != readlink("/proc/self", status_path, sizeof(status_path))) {
		selfpid = std::atol(status_path);
	}

	while (num_entries--) {
		char *pidstr = namelist[num_entries]->d_name;
		if ((pidstr) && (pidstr[0] > '0') && (pidstr[0] <= '9')) {
			pid = std::atol(pidstr);
			if (pid != selfpid) {
				/* for process name we check the 'status' entry */
				memset(status_path, '\0', sizeof(status_path));
				snprintf(status_path, sizeof(status_path), "/proc/%lu/status", pid);
				if (NULL != (stat = fopen(status_path, "r"))) {
					memset(name_str, '\0', sizeof(name_str));
					ret = fscanf(stat, AT_PROCSTAT_NAME_FORMAT, name_str);
					fclose(stat);
					if ((1 == ret) && (strncmp(name_str, appName, 15) == 0)) {
						pids.push_back(pid);
						res = true;
					}
				}
			}
		}
		free(namelist[num_entries]);
	}
	free(namelist);

	return res;
}


std::string ATVersion::GetAppPathByPid(unsigned long pid)
{
	char path[256];
	char exe_buf[PATH_MAX];

	memset(path, '\0', sizeof(path));
	snprintf(path, sizeof(path), "/proc/%lu/exe", pid);
	memset(exe_buf, '\0', PATH_MAX);
	if (-1 == readlink(path, exe_buf, PATH_MAX)) {
		return "";
	}

	if (NULL != strstr(exe_buf, " (deleted)")) {
		return "";
	}

	return exe_buf;
}

