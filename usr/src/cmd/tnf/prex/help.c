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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#include <stdio.h>
#include <strings.h>
#include "expr.h"
#include "y.tab.h"

#define	NUMHELPTOPICS	6
static char *helptopics[NUMHELPTOPICS] = {
	"intro", "functions", "kernel_mode", "probe_spec", "processes",
	"set_spec" };
static char *helptopicstrings[NUMHELPTOPICS] = {
/* help intro */
"Introduction to prex\n"
"\n"
"prex is used to control probes in a target process, or in the kernel.\n"
"If you are reading this help text, you have sucessfully invoked prex,\n"
"by either connecting to an existing process (prex -p), a new\n"
"process (prex myprogram), or to the kernel (prex -k).\n"
"\n"
"Most often, the user will want to enable some probes in the target,\n"
"continue the target - either to completion, or until the target is\n"
"interrupted - and then exit from prex to perform analysis on the resulting\n"
"tracefile.  An ascii dump of the tracefile can be obtained using the\n"
"tnfdump(1) command.\n"
"\n"
"The tracefile can be found in /tmp/trace-<pid> by default, or in a location\n"
"of your choice, if you specify the -o option when you invoke prex.\n"
"You can query the name of the current trace file by using the command.\n"
"list tracefile.\n"
"\n"
"Upon invocation, prex reads commands from the files ~/.prexrc and\n"
"./.prexrc (in that order).  The \"source\" command may be used to take\n"
"commands from an arbitrary file or set of files.\n"
"\n"
"Help is available for a variety of topics, and for each prex command.\n"
"Type help with no arguments for a list of available help topics.\n"
"\n"
"end of help for topic intro\n",
/* help functions */
"Probe Functions\n"
"\n"
"Note - probe functions are not available from kernel mode\n"
"\n"
"It is possible to use prex to connect functions to probe points, such that\n"
"the function is invoked each time a given probe point is hit.  Currently,\n"
"the only function available from prex is the &debug function, which prints\n"
"out the arguments sent in to the probe, as well as the value (if any)\n"
"associated with the sunw%debug attribute in the detail field.\n"
"\n"
"Relevant commands:\n"
"    list fcns                    # list the defined probe functions\n"
"    connect &debug name=myprobe  # attach probe &debug to probe myprobe\n"
"    connect &debug $myset        # attach probe &debug to probes in $myset\n"
"    clear name=myprobe           # disconnect probe functions from myprobe\n"
"    clear $myset                 # disconnect probe functions from $myset\n"
"\n"
"end of help for topic functions\n",
/* help kernel_mode */
"Controlling Kernel Probes\n"
"\n"
"The Solaris kernel is instrumented with a small number of strategically\n"
"placed probes, documented in tnf_kernel_probes(5).  The superuser can\n"
"control these probes by running prex with the \"-k\" option.\n"
"\n"
"In kernel mode, trace output is written to an in-core buffer, rather\n"
"than to a file on disk.  This buffer can be extracted with the tnfxtract(1)\n"
"commmand.  This buffer must be set up before tracing can begin, through the\n"
"use of the \"buffer alloc\" command.  After kernel tracing is complete (and\n"
"after the buffer has been extracted), the buffer can be deallocated from\n"
"prex using the \"buffer dealloc\" command.\n"
"\n"
"As in user mode, kernel probe control is accomplished using the commands\n"
"\"trace\", \"untrace\", \"enable\", and \"disable\".  Additionally, in\n"
"kernel mode, a \"master switch\" is provided to turn all tracing activity\n"
"on or off.  This switch is toggled using the commands \"ktrace on\" and\n"
"\"ktrace off\".  Unlike user mode, where the target is stopped while\n"
"tracing paramaters are manipulated from prex, the kernel does not stop\n"
"running during a tracing session.  Using the \"ktrace\" command, one can\n"
"set up all tracing parameters in advance of a session, without actually\n"
"writing trace records until a \"ktrace on\" command is given.\n"
"\n"
"Kernel mode also provides the ability to limit tracing to those kernel\n"
"probes hit on behalf of a specific user process.  The pfilter command\n"
"is provided to toggle process filtering on or off, and to specify the\n"
"set of processes that comprise the filter.  If pid 0 is a member of the\n"
"filter list, then any threads not associated with a process are included.\n"
"\n"
"Note that after a kernel tracing session, all tracing parameters are left\n"
"as-is.  One should re-enter prex to disable and untrace probes, turn off\n"
"process filtering, and deallocate the in-core trace buffer.\n"
"\n"
"Relevant Commands:\n"
"    buffer alloc 2m    # allocate a 2M in-core buffer\n"
"    enable $all        # enable all kernel probes\n"
"    trace $all         # trace all kernel probes\n"
"    ktrace on          # turn on kernel tracing\n"
"    pfilter add 1234   # add pid 1234 to the filter list\n"
"    pfilter on         # turn on process filtering\n"
"    ktrace off         # turn off kernel tracing\n"
"Also see tnfxtract(1), which is used to extract the in-core trace buffer\n"
"to an on-disk tracefile.\n"
"\n"
"end of help for topic kernel_mode\n",
/* help probe_spec */
"Probe Specification\n"
"\n"
"Many prex commands operate on probes or sets of probes.  Probes are\n"
"specified by a list of space-separated selectors of the form:\n"
"      <attribute>=<value>\n"
"If the \""
"<attribute>=\" is omitted, the attribute defaults to \"keys=\".\n"
"The \""
"<value>\" can be either a string or an ed(1) regular expression\n"
"enclosed in slashes.  Regular expressions in prex are unanchored, meaning\n"
"that any value that contains the given regex as a substring is a valid\n"
"match, regardless of position.  To anchor a regular expression, use \"^\"\n"
"to match the beginning of a line, or \"$\" to match the end of a line.\n"

"If a list of selectors is specified, an OR operation is applied - the\n"
"resulting probe_spec includes probes that match any of the selectors.\n"
"See the prex(1) man page for a complete specification of the accepted\n"
"grammar.\n"
"\n"
"The \"list\" command is used to view available probes in the target,\n"
"and to display their attributes. The \"trace\" and \"untrace\" commands\n"
"determine whether a probe will write a trace record when hit.  The\n"
"\"enable\" and \"disable\" commands indicate whether a probe will perform\n"
"any action (such as a calling a connected function or creating a trace\n"
"record) when hit.   Normally, a probe is enabled and traced for tracing,\n"
"and disabled and untraced otherwise.  It is possible to enable a probe\n"
"with tracing off to get debug output without writing trace records.\n"
"\n"
"Relevant Commands:\n"
"   list probes $all         # list probes in set $all (all probes)\n"
"   list probes file=test.c  # list probes with a specific attribute\n"
"   list 'file' probes $all  # list the file attribute in all probes\n"
"   list probes name=/^thr/  # list probes whose name attribute matches\n"
"                            # the given regular expression\n"
"   list probes name=/^thr/ keys=vm  # list probes matching either selector\n"
"   enable name=/^thr/       # enable probes whose name matches this regex\n"
"   trace $all               # trace all probes\n"
"   untrace $myset           # untrace probes in set $myset\n"
"\n"
"end of help for topic probe_spec\n",
/* help processes */
"Controlling Processes with prex\n"
"\n"
"Prex is used to control probes in a given process, or in the kernel.\n"
"The process which prex is to control is identified as an argument when\n"
"prex is invoked.  If the \"-p"
" <pid>\" switch is used, prex connects to the\n"
"specified process.  Otherwise prex exec's the command supplied at the\n"
"end of its argument list.  In either case, prex stops the target process\n"
"immediately so that the user may set up probe control.\n"
"\n"
"Once probe control is set up (typically using the \"enable\" and \"trace\"\n"
"commands), the process is continued using the \"continue\" command.  Prex\n"
"remains attached to the target, and the user can force the target to\n"
"stop again by typing control-C, at which time additional probe control\n"
"directives may be given.\n"
"\n"
"Upon quitting from prex, the target process is normally resumed if prex\n"
"attached to it, or killed if prex invoked it.  An optional argument may\n"
"be given with the \"quit\" command to explicitly specify whether to kill\n"
"the target, continue it, or leave it suspended.\n"
"\n"
"If the target forks, any probe that the child encounters will be logged to\n"
"the same trace file as the parent.  If the child calls exec, it will no\n"
"longer be traced.\n"
"\n"
"In kernel mode (prex -k), process filtering may be enabled, to limit\n"
"tracing to those kernel probes hit on behalf of a specific process or\n"
"set of processes.  Kernel-mode process filtering is controlled using\n"
"the \"pfilter\" command.\n"
"\n"
"\n"
"Relevant Commands:\n"
"    continue               # continue target (user mode only)\n"
"    Control-C              # stop target (user mode only)\n"
"    quit resume            # quit prex, continue target\n"
"    quit suspend           # quit prex, suspend target\n"
"    quit kill              # quit prex, kill target\n"
"    quit                   # quit prex, default action\n"
"# Note: pfilter commands apply only to kernel mode\n"
"    pfilter                # show pfilter status\n"
"    pfilter on             # turn on process filter mode\n"
"    pfilter off            # turn off process filter mode\n"
"    pfilter add 1234       # add to process filter pid list\n"
"    pfilter delete 1234    # delete from process filter pid list\n"
"\n"
"end of help for topic processes\n",
/* help set_spec */
"Specifying Probe Sets\n"
"\n"
"Prex provides the ability to define named sets of probes to simplify\n"
"commands operating on multiple probes.  The set \"$all\" is predefined,\n"
"as the set of all probes in the target.  A set is defined using the\n"
"\"create\" command, and can be used as an argument to the \"list\",\n"
"\"enable\", \"disable\", \"trace\", \"untrace\", \"connect\" and\n"
"\"clear\" commands.\n"
"\n"
"Relevant Commands:\n"
"    create $myset name=/^thr/        # create a set\n"
"    list probes $myset               # list probes in a set\n"
"    list sets                        # list defined sets\n"
"    enable $myset                    # enable a set of probes\n"
"    trace $myset                     # trace a set of probes\n"
"\n"
"end of help for topic set_spec\n"
};

static char *helpstr_continue =
"\n"
"Usage:  continue\n"
"\n"
"\"continue\" is used to resume execution of the target process.  This\n"
"command is not available in kernel mode, since the kernel is never stopped.\n"
"\n"
"end of help for cmd continue\n";
static char *helpstr_disable =
"\n"
"Usage: disable <probe_spec>|<set_spec>\n"
"\n"
"\"disable\" is used to to turn off all tracing activity associated with a\n"
"probe or a set of probes.\n"
"\n"
"End of help for cmd disable\n";
static char *helpstr_enable=
"\n"
"Usage: enable <probe_spec>|<set_spec>\n"
"\n"
"\"enable\" is used to specify that any activity associated with the probe\n"
"or probes will be performed when the probe is hit.  This includes connected\n"
"probe functions as well as the generation of trace records.  Note that in\n"
"order for a probe to generate a trace record, it must be \"traced\" as well\n"
"as enabled.\n"
"\n"
"End of help for cmd enable\n";
static char *helpstr_help =
"\n"
"Usage: help [<cmd>|<topic>]\n"
"\n"
"\"help\" lists all available help topics when run without any arguments.\n"
"If a valid topic or command-name is supplied as an argument, help text for\n"
"the topic or command is displayed.\n"
"\n"
"End of help for cmd help\n";
static char *helpstr_list =
"\n"
"Usage: list probes <probe_spec>|<set_spec> \n"
"       list <attrs> probes <probe_spec>|<set_spec>\n"
"       list sets\n"
"       list fcns\n"
"       list history\n"
"       list tracefile\n"
"\n"
"\"list\" displays information about currently defined probes, sets, and\n"
"probe functions.  When listing probes, one can limit the output to a\n"
"desired set of attributes by specifying an attribute list as a set of\n"
"strings.  If an attribute is also a reserved word (such as \"trace\", it\n"
"must be enclosed in single quotes.  For example:\n"
"\n"
"       list file 'trace' probes $all\n"
"\n"
"\"list\" history lists the probe control commands history, and\n"
"\"list\" tracefile displays the current trace file name.\n"
"\n"
"End of help for cmd list\n";
static char *helpstr_quit =
"\n"
"Usage: quit\n"
"       quit kill\n"
"       quit resume\n"
"       quit suspend\n"
"\n"
"The \"quit\" command exits prex, leaving the target in a state specified\n"
"by the user, or taking a default action if no instructions are specified.\n"
"An optional argument may be used to indicated that the target should be\n"
"killed, resumed, or left suspended.  If no argument is supplied, then\n"
"prex's default behavior is to resume a process to which it had attached,\n"
"and to kill a process which it had invoked.\n"
"\n"
"End of help for cmd quit\n";
static char *helpstr_source =
"\n"
"Usage: source <filename>\n"
"\n"
"The \"source\" command is used to invoke a set of prex commands stored in\n"
"a file.  A sourced file may in turn source other files.  The files\n"
"~/.prexrc and ./.prexrc are sourced automatically (in that order) when prex\n"
"is invoked, and may be used to store commonly used probe and set\n"
"specifications, or probe control directives.  Commands in sourced files\n"
"may override the effects of commands in previously sourced files.\n"
"\n"
"End of help for cmd source\n";
static char *helpstr_trace =
"\n"
"Usage: trace <probe_spec>|<set_spec>\n"
"\n"
"\"trace\" is used to turn on tracing for the specified probe or probes.\n"
"A \"traced\" probe that is also \"enabled\" will generate a trace record\n"
"when it is hit.\n"
"\n"
"End of help for cmd trace\n";
static char *helpstr_untrace =
"\n"
"Usage: untrace <probe_spec>|<set_spec>\n"
"\n"
"\"untrace\" turns tracing off for the specified probe or probes.  A probe\n"
"will not generate a trace record when it is not traced, although connected\n"
"probe functions will still be invoked as long as a probe is \"enabled\".\n"
"\n"
"End of help for cmd untrace\n";
static char *helpstr_buffer =
"\n"
"Usage: buffer alloc <size>\n"
"       buffer dealloc\n"
"\n"
"Note:  Kernel Mode Only\n"
"\n"
"\"buffer\" allocates or deallocates the in-core buffer used to hold\n"
"kernel trace records.  Size can be specified in kilobytes or megabytes,\n"
"by appending the character 'k' or 'm' to a numeric value (e.g. \"2m\").\n"
"A buffer must be allocated prior to a kernel tracing session.  Once\n"
"allocated, the buffer remains usable until deallocated, even through\n"
"multiple invocations of prex.\n"
"\n"
"Before the buffer is deallocated, data may be extracted to an on-disk\n"
"tracefile using tnfxtract(1).\n"
"\n"
"End of help for cmd buffer\n";
static char *helpstr_ktrace =
"\n"
"Usage: ktrace on\n"
"       ktrace off\n"
"\n"
"Note:  Kernel Mode Only\n"
"\n"
"\"ktrace\" toggles the master switch that indicates whether kernel\n"
"tracing is active or inactive.  Since the kernel cannot be stopped while\n"
"a tracing experiment is set up, \"ktrace\" is provided so that tracing\n"
"can be set up as desired before any trace records are generated\n"
"\n"
"End of help for cmd ktrace\n";
static char *helpstr_pfilter =
"\n"
"Usage: pfilter\n"
"       pfilter on\n"
"       pfilter off\n"
"       pfilter add <pidlist>\n"
"       pfilter delete <pidlist>\n"
"\n"
"Note:  Kernel Mode Only\n"
"\n"
"\"pfilter\" controls process filtering by toggling process-filter mode,\n"
"and maintaining a list of process id's on which to filter.  When process\n"
"filtering mode is on, tracing is limited to the kernel events hit on behalf\n"
"of the processes in the pid list.  Process id 0 is used to represent all\n"
"threads not associated with a process.\n"

"When run without arguments, \"pfilter\" displays the current process-filter\n"
"mode and pid list.  A process filter pid list can be maintained whether\n"
"or not process filter mode is currently active.\n"
"\n"
"A process must exist in order to be added to the pid list, and the pid list\n"
"is automatically updated to delete any processes that no longer exist.  If\n"
"the pid list becomes empty while process filtering is on, prex issues a\n"
"warning.  Process filtering mode is persistent between invocations of prex\n"
"so it should be turned off manually when a tracing experiment is complete.\n"
"\n"
"End of help for cmd pfilter\n";
static char *helpstr_clear =
"\n"
"Usage: clear <probe_spec>|<set_spec>\n"
"\n"
"Note:  Not available in Kernel Mode\n"
"\n"
"\"clear\" disconnects any probe functions that have previously been\n"
"connected to a probe or group of probes using the \"connect\" command.\n"
"The \"clear\" command cannot be used in kernel mode, since probe functions\n"
"are not available for kernel probes.\n"
"\n"
"End of help for cmd clear\n";
static char *helpstr_connect =
"\n"
"Usage: connect <function> <probe_spec>|<set_spec>\n"
"\n"
"Note:  Not available in Kernel Mode\n"
"\n"
"\"connect\" connects a probe function to a probe or group of probes.\n"
"Currently, the only probe function available from prex is \"&debug\", which\n"
"prints out the arguments sent in to the probe, as well as the value (if\n"
"any) associated with the sunw%debug attribute in the detail field.\n"
"In order for a probe function to be invoked, the probe to which the\n"
"function is attached must be \"enabled\", but need not be \"traced\".\n"
"\n"
"The \"clear\" command is available to disconnect a probe function from\n"
"a probe or group of probes.\n"
"\n"
"End of help for cmd connect\n";

static char *helpstr =
"\n"
"Usage: help [topic|command]\n"
"\n"
"Topics\n"
"\tintro         functions    kernel_mode\n"
"\tprobe_spec    processes    set_spec\n"
"\n"
"User and Kernel Mode Commands\n"
"\tdisable       enable       help       list\n"
"\tquit          source       trace      untrace\n"
"\n"
"Additional user-mode-only commands\n"
"\tclear         connect      continue\n"
"\n"
"Additional kernel-mode-only (prex -k) commands\n"
"\tbuffer        ktrace       pfilter\n"
;


static char	*oldhelpstr =
"grammar for non-terminals:\n"
"__________________________\n"
"\n"
"filename ::=	QUOTED_STR\n"
"\n"
"selector_list ::= 	/* empty */ |\n"
"		<selector_list> <selector>\n"
"\n"
"spec_list ::=	/*empty */ |\n"
"		<spec_list> <spec>\n"
"\n"
"selector ::=	<spec>=<spec> |		/* whitespace around '=' optional */\n"
"		<spec>			/* keys attribute is default */\n"
"\n"
"spec ::= 	IDENT |\n"
"		QUOTED_STR |\n"
"		REGEXP\n"
"\n"
"pidlist ::=	<pid> |\n"
"		<pid> ',' <pidlist>\n"
"pid ::=		INT\n"
"\n"
"Reg-exps to match terminals:\n"
"____________________________\n"
"\n"
"IDENT 		= [a-zA-Z_\\.%]{[a-zA-Z0-9_\\.%]}+ \n"
"QUOTED_STR	= '[^\\n']*'		/* any string in single quotes	*/\n"
"REGEXP		= /[^\\n/]/		/* reg-exp's have to be in / /	*/\n"
"INT		= [0-9]+\n"
"\n"
"Commands:\n"
"_________\n"
"\n"
"# set creation and set listing\n"
"create $<set_name> <selector_list>\n"
"list sets				# list the defined sets\n"
"\n"
"# function listing\n"
"list fcns				# list the defined functions.\n"
"\n"
"# commands to connect and disconnect probe functions\n"
"# (not available in kernel mode)\n"
"connect &<fcn_handle> $<set_name>	# eg. connect &debug $all\n"
"connect &<fcn_handle> <selector_list>\n"
"\n"
"# command to disconnect all connected probe functions\n"
"# (not available in kernel mode)\n"
"clear $<set_name>\n"
"clear <selector_list>\n"
"\n"
"# commands to toggle the tracing mode\n"
"trace $<set_name>\n"
"trace <selector_list>\n"
"untrace $<set_name>\n"
"untrace <selector_list>\n"
"\n"
"# commands to enable and disable probes\n"
"enable $<set_name>\n"
"enable <selector_list>\n"
"disable $<set_name>\n"
"disable <selector_list>\n"
"list history		# lists probe control commands issued\n"
"list tracefile		# lists the current trace file name\n"
"\n"
"# commands to list probes or to list values\n"
"list <spec_list> probes $<set_name>	#eg. list probes $all\n"
"list <spec_list> probes <selector_list> #eg. list name probes file=test.c\n"
"list values <spec_list>		# eg. list values keys\n"
"\n"
"# help command\n"
"help\n"
"\n"
"# source a file of prex commands\n"
"source <filename>\n"
"\n"
"# process control - ^C stops target and returns to 'prex>' prompt\n"
"# (In kernel mode, `continue' is a no-op, and 'quit' detaches prex\n"
"# from the kernel.)\n"
"continue		# continues target\n"
"quit kill		# quit prex, kill target\n"
"quit resume		# quit prex, continue target\n"
"quit suspend		# quit prex, leave target suspended\n"
"quit			# quit prex (continue or kill target)\n"
"\n"

"\n"
"# Kernel mode commands\n"
"# \"master switch\" enabling/disabling all tracing\n"
"ktrace on		# Enabled probes will generate trace output\n"
"ktrace off		# All trace output suppressed\n"
"# Create, destroy, or show the size of the kernel trace buffer\n"
"buffer [ alloc [ size ] | dealloc ]\n"
"# Control per-process kernel trace filtering\n"
"pfilter off		# Filtering off:  trace all processes\n"
"pfilter on		# Filtering on:  trace only processes in filter set\n"
"pfilter add <pidlist>		# Add specified process ids to the filter set\n"
"pfilter delete <pidlist>	# Drop specified pids from the filter set\n"
"\n"
;

void
help(void)
{
	(void) fputs(helpstr, stdout);

}				/* end help */

void
help_on_topic(char *topic)
{
	int i;

	if (topic && strlen(topic)) {
		for (i = 0; i < NUMHELPTOPICS; i++)
		if (strcmp(topic, helptopics[i]) == 0)
		    break;
		if (i < NUMHELPTOPICS)
		    fputs(helptopicstrings[i], stdout);
		else {
			printf("No help for %s\n",  topic);
			help();
		}
	}
}


void
help_on_command(int cmd)
{
	switch (cmd) {
	case CONTINUE:
		fputs(helpstr_continue, stdout);
		break;
	case DISABLE:
		fputs(helpstr_disable, stdout);
		break;
	case ENABLE:
		fputs(helpstr_enable, stdout);
		break;
	case HELP:
		fputs(helpstr_help, stdout);
		break;
	case LIST:
		fputs(helpstr_list, stdout);
		break;
	case QUIT:
		fputs(helpstr_quit, stdout);
		break;
	case SOURCE:
		fputs(helpstr_source, stdout);
		break;
	case TRACE:
		fputs(helpstr_trace, stdout);
		break;
	case UNTRACE:
		fputs(helpstr_untrace, stdout);
		break;
	case BUFFER:
		fputs(helpstr_buffer, stdout);
		break;
	case KTRACE:
		fputs(helpstr_ktrace, stdout);
		break;
	case PFILTER:
		fputs(helpstr_pfilter, stdout);
		break;
	case CLEAR:
		fputs(helpstr_clear, stdout);
		break;
	case CONNECT:
		fputs(helpstr_connect, stdout);
		break;
	default:
		fputs("No help for this command\n", stdout);
		break;
	}

}				/* end help */
