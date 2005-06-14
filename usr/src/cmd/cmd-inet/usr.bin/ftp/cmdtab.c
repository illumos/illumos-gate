/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved  	*/

/*
 *	University Copyright- Copyright (c) 1982, 1986, 1988
 *	The Regents of the University of California
 *	All Rights Reserved
 *
 *	University Acknowledgment- Portions of this document are derived from
 *	software developed by the University of California, Berkeley, and its
 *	contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ftp_var.h"

/*
 * User FTP -- Command Tables.
 */

static char	accounthelp[] =	"send account command to remote server";
static char	appendhelp[] =	"append to a file";
static char	asciihelp[] =	"set ascii transfer type";
static char	beephelp[] =	"beep when command completed";
static char	binaryhelp[] =	"set binary transfer type";
static char	casehelp[] =	"toggle mget upper/lower case id mapping";
static char	ccchelp[] =	"set clear protection level for commands";
static char	cdhelp[] =	"change remote working directory";
static char	cduphelp[] = 	"change remote working directory to parent "
				"directory";
static char	clearhelp[] =	"set clear protection level for data";
static char	connecthelp[] =	"connect to remote tftp";
static char	crhelp[] =	"toggle carriage return stripping on ascii "
				"gets";
static char	deletehelp[] =	"delete remote file";
static char	debughelp[] =	"toggle/set debugging mode";
static char	dirhelp[] =	"list contents of remote directory";
static char	disconhelp[] =	"terminate ftp session";
static char	domachelp[] = 	"execute macro";
static char	formhelp[] =	"set file transfer format";
static char	globhelp[] =	"toggle metacharacter expansion of local file "
				"names";
static char	hashhelp[] =	"toggle printing `#' for each buffer "
				"transferred";
static char	helphelp[] =	"print local help information";
static char	lcdhelp[] =	"change local working directory";
static char	lshelp[] =	"display contents of remote directory";
static char	macdefhelp[] =  "define a macro";
static char	mdeletehelp[] =	"delete multiple files";
static char	mdirhelp[] =	"list contents of multiple remote directories";
static char	mechhelp[] =	"set mechanism type";
static char	mgethelp[] =	"get multiple files";
static char	mkdirhelp[] =	"make directory on the remote machine";
static char	mlshelp[] =	"nlist contents of multiple remote directories";
static char	modehelp[] =	"set file transfer mode";
static char	mputhelp[] =	"send multiple files";
static char	nlisthelp[] =	"nlist contents of remote directory";
static char	nmaphelp[] =	"set templates for default file name mapping";
static char	ntranshelp[] =	"set translation table for default file name "
				"mapping";
static char	passivehelp[] =	"toggle passive transfer mode";
static char	porthelp[] =	"toggle use of PORT cmd for each data "
				"connection";
static char	privatehelp[] =	"set private protection level for data";
static char	prompthelp[] =	"force interactive prompting on multiple "
				"commands";
static char	protecthelp[] =	"set protection level for data";
static char	proxyhelp[] =	"issue command on alternate connection";
static char	pwdhelp[] =	"print working directory on remote machine";
static char	quithelp[] =	"terminate ftp session and exit";
static char	quotehelp[] =	"send arbitrary ftp command";
static char	receivehelp[] =	"receive file";
static char	regethelp[] =	"get file restarting at end of local file";
static char	remotehelp[] =	"get help from remote server";
static char	renamehelp[] =	"rename file";
static char	resethelp[] =	"clear queued command replies";
static char	restarthelp[] =	"restart file transfer at bytecount";
static char	rmdirhelp[] =	"remove directory on the remote machine";
static char	runiquehelp[] = "toggle store unique for local files";
static char	safehelp[] =	"set safe protection level for data";
static char	sendhelp[] =	"send one file";
static char	shellhelp[] =	"escape to the shell";
static char	sitehelp[] =	"send site specific command to remote server\n"
				"\t\tTry \"remotehelp site\" or \"site help\" "
				"for more information";
static char	statushelp[] =	"show current status";
static char	structhelp[] =	"set file transfer structure";
static char	suniquehelp[] = "toggle store unique on remote machine";
static char	tenexhelp[] =	"set tenex file transfer type";
static char	tracehelp[] =	"toggle packet tracing";
static char	typehelp[] =	"set file transfer type";
static char	userhelp[] =	"send new user information";
static char	verbosehelp[] =	"toggle verbose mode";
static char	windowhelp[] =	"set TCP window size for the data connection";

/*
 * NOTE : The BUFSIZE defined in ftp_var.h includes MAXCMDLEN chars to
 * accomodate the longest command in the cmdtab[] defined below.
 * If anyone plans to add a new command that is longer than the MAXCMDLEN
 * make sure to update it in ftp_var.h.
 */

struct cmd cmdtab[] = {
	{ "!",		shellhelp,	0,	0,	0,	shell },
	{ "$",		domachelp,	1,	0,	0,	domacro },
	{ "account",	accounthelp,	0,	1,	1,	account},
	{ "append",	appendhelp,	1,	1,	1,	put },
	{ "ascii",	asciihelp,	0,	1,	1,	setascii },
	{ "bell",	beephelp,	0,	0,	0,	setbell },
	{ "binary",	binaryhelp,	0,	1,	1,	setbinary },
	{ "bye",	quithelp,	0,	0,	0,	quit },
	{ "case",	casehelp,	0,	0,	1,	setcase },

	{ "ccc",	ccchelp,	0,	1,	1,	ccc },

	{ "cd",		cdhelp,		0,	1,	1,	cd },
	{ "cdup",	cduphelp,	0,	1,	1,	cdup },

	{ "clear",	clearhelp,	0,	1,	1,	setclear },

	{ "close",	disconhelp,	0,	1,	1,	disconnect },
	{ "cr",		crhelp,		0,	0,	0,	setcr },
	{ "delete",	deletehelp,	0,	1,	1,	delete },
	{ "debug",	debughelp,	0,	0,	0,	setdebug },
	{ "dir",	dirhelp,	1,	1,	1,	ls },
	{ "disconnect",	disconhelp,	0,	1,	1,	disconnect },
	{ "form",	formhelp,	0,	1,	1,	setform },
	{ "get",	receivehelp,	1,	1,	1,	get },
	{ "glob",	globhelp,	0,	0,	0,	setglob },
	{ "hash",	hashhelp,	0,	0,	0,	sethash },
	{ "help",	helphelp,	0,	0,	1,	help },
	{ "lcd",	lcdhelp,	0,	0,	0,	lcd },
	{ "ls",		lshelp,		1,	1,	1,	ls },
	{ "macdef",	macdefhelp,	0,	0,	0,	macdef },
	{ "mdelete",	mdeletehelp,	1,	1,	1,	mdelete },
	{ "mdir",	mdirhelp,	1,	1,	1,	mls },

	{ "mechanism",	mechhelp,	1,	0,	1,	setmech },

	{ "mget",	mgethelp,	1,	1,	1,	mget },
	{ "mkdir",	mkdirhelp,	0,	1,	1,	makedir },
	{ "mls",	mlshelp,	1,	1,	1,	mls },
	{ "mode",	modehelp,	0,	1,	1,	setmode },
	{ "mput",	mputhelp,	1,	1,	1,	mput },
	{ "nlist",	nlisthelp,	1,	1,	1,	ls },
	{ "nmap",	nmaphelp,	0,	0,	1,	setnmap },
	{ "ntrans",	ntranshelp,	0,	0,	1,	setntrans },
	{ "open",	connecthelp,	0,	0,	1,	setpeer },
	{ "passive",	passivehelp,	0,	0,	0,	setpassive },

	{ "private",	privatehelp,	0,	1,	1,	setprivate },

	{ "prompt",	prompthelp,	0,	0,	0,	setprompt },

	{ "protect",	protecthelp,	0,	1,	1,	setdlevel },

	{ "proxy",	proxyhelp,	0,	0,	1,	doproxy },
	{ "put",	sendhelp,	1,	1,	1,	put },
	{ "pwd",	pwdhelp,	0,	1,	1,	pwd },
	{ "quit",	quithelp,	0,	0,	0,	quit },
	{ "quote",	quotehelp,	1,	1,	1,	quote },
	{ "recv",	receivehelp,	1,	1,	1,	get },
	{ "reget",	regethelp,	1,	1,	1,	reget },
	{ "remotehelp",	remotehelp,	0,	1,	1,	rmthelp },
	{ "rename",	renamehelp,	0,	1,	1,	renamefile },
	{ "reset",	resethelp,	0,	1,	1,	reset },
	{ "restart",	restarthelp,	1,	1,	1,	restart },
	{ "rmdir",	rmdirhelp,	0,	1,	1,	removedir },
	{ "runique",	runiquehelp,	0,	0,	1,	setrunique },

	{ "safe",	safehelp,	0,	1,	1,	setsafe },

	{ "send",	sendhelp,	1,	1,	1,	put },
	{ "sendport",	porthelp,	0,	0,	0,	setport },
	{ "site",	sitehelp,	0,	1,	1,	site },
	{ "status",	statushelp,	0,	0,	1,	status },
	{ "struct",	structhelp,	0,	1,	1,	setstruct },
	{ "sunique",	suniquehelp,	0,	0,	1,	setsunique },
	{ "tcpwindow",	windowhelp,	0,	0,	0,	settcpwindow },
	{ "tenex",	tenexhelp,	0,	1,	1,	settenex },
	{ "trace",	tracehelp,	0,	0,	0,	settrace },
	{ "type",	typehelp,	0,	1,	1,	settype },
	{ "user",	userhelp,	0,	1,	1,	user },
	{ "verbose",	verbosehelp,	0,	0,	0,	setverbose },
	{ "?",		helphelp,	0,	0,	1,	help },
	{ 0 },
};

int	NCMDS = (sizeof (cmdtab) / sizeof (cmdtab[0])) - 1;
