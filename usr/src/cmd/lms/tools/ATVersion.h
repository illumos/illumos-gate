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

#ifndef _AT_VERSION_TOOL_H_
#define _AT_VERSION_TOOL_H_

#include <string>
#include <list>

class ATVersion
{
public:
	/**
	function check if user requested version information to be displayed on std output
	and show version number
	@param argc Argument count
	@param argv Argument array
	@param versionStr Version string to be displayed
	@return bool true if version user requested version to be displayed
		     false if version information was not displayed
	*/
	static bool ShowVersionIfArg(int argc, const char **argv, const char *versionStr);

	/**
	function gets application version - if target application uses this class to show version
	@param appName application name
	@param version string returning version or empty string if version not determined
	@return true - if application is running, false - if not.
	*/
	static bool GetAppVersion(const char *appName, std::string &version);

	/**
	function gets process version - if target application uses this class to show version
	@param cmd path to application
	@return string version or empty string if version not determined
	*/
	static std::string GetProcessVersion(std::string cmd);

	/**
	Checks if an application is running in the system.
	@param app_name Application binary name (not including path).
	@param pids returned list of pids of searched application
	@return true - if application is running, false - if not.
	*/
	static bool IsAppRunning(const char *app_name, std::list<unsigned long> &pids);

	/**
	Returns path associated with application with given PID. Note that to access this information for all processes
	the function must be called with elevated privileges.
	@param pid PID of application of interest.
	@return Application path if possible.
		Empty string if access is not possbile.
		NULL if the application isn't runnig.
	*/
	static std::string GetAppPathByPid(unsigned long pid);

	static const std::string appSearchPath;
};

#endif /* _AT_VERSION_TOOL_H_ */
