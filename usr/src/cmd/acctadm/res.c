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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <libintl.h>
#include <string.h>
#include <sys/acctctl.h>

#include "utils.h"
#include "aconf.h"
#include "res.h"

/*
 * resource names
 */
static ac_resname_t ac_names[] = {
	/*
	 * Process accounting resources
	 */
	{ AC_PROC,	AC_PROC_PID,		"pid"		},
	{ AC_PROC,	AC_PROC_UID,		"uid"		},
	{ AC_PROC,	AC_PROC_GID,		"gid"		},
	{ AC_PROC,	AC_PROC_PROJID,		"projid"	},
	{ AC_PROC,	AC_PROC_TASKID,		"taskid"	},
	{ AC_PROC,	AC_PROC_CPU,		"cpu"		},
	{ AC_PROC,	AC_PROC_TIME,		"time"		},
	{ AC_PROC,	AC_PROC_COMMAND,	"command"	},
	{ AC_PROC,	AC_PROC_TTY,		"tty"		},
	{ AC_PROC,	AC_PROC_HOSTNAME,	"host"		},
	{ AC_PROC,	AC_PROC_MICROSTATE,	"mstate"	},
	{ AC_PROC,	AC_PROC_FLAG,		"flag"		},
	{ AC_PROC,	AC_PROC_ANCPID,		"ancpid"	},
	{ AC_PROC,	AC_PROC_WAIT_STATUS,	"wait-status"	},
	{ AC_PROC,	AC_PROC_ZONENAME,	"zone"		},
	{ AC_PROC,	AC_PROC_MEM,		"memory"	},

	/*
	 * Task accounting resources
	 */
	{ AC_TASK,	AC_TASK_TASKID,		"taskid"	},
	{ AC_TASK,	AC_TASK_PROJID,		"projid"	},
	{ AC_TASK,	AC_TASK_CPU,		"cpu"		},
	{ AC_TASK,	AC_TASK_TIME,		"time"		},
	{ AC_TASK,	AC_TASK_HOSTNAME,	"host"		},
	{ AC_TASK,	AC_TASK_MICROSTATE,	"mstate"	},
	{ AC_TASK,	AC_TASK_ANCTASKID,	"anctaskid"	},
	{ AC_TASK,	AC_TASK_ZONENAME,	"zone"		},

	/*
	 * Flow accounting resources
	 */
	{ AC_FLOW,	AC_FLOW_SADDR,		"saddr"		},
	{ AC_FLOW,	AC_FLOW_DADDR,		"daddr"		},
	{ AC_FLOW,	AC_FLOW_SPORT,		"sport"		},
	{ AC_FLOW,	AC_FLOW_DPORT,		"dport"		},
	{ AC_FLOW,	AC_FLOW_PROTOCOL,	"proto"		},
	{ AC_FLOW,	AC_FLOW_DSFIELD,	"dsfield"	},
	{ AC_FLOW,	AC_FLOW_NBYTES,		"nbytes"	},
	{ AC_FLOW,	AC_FLOW_NPKTS,		"npkts"		},
	{ AC_FLOW,	AC_FLOW_CTIME,		"ctime"		},
	{ AC_FLOW,	AC_FLOW_LSEEN,		"lseen"		},
	{ AC_FLOW,	AC_FLOW_PROJID,		"projid"	},
	{ AC_FLOW,	AC_FLOW_UID,		"uid"		},
	{ AC_FLOW,	AC_FLOW_ANAME,		"action"	},

	/*
	 * These are included for compatibility with old acctadm that
	 * didn't have resource groups for individual accounting types.
	 * It was possible to have resource "pid" enabled for task
	 * accounting even though we couldn't actually track it.
	 */
	{ AC_TASK,	AC_NONE,		"pid"		},
	{ AC_TASK,	AC_NONE,		"uid"		},
	{ AC_TASK,	AC_NONE,		"gid"		},
	{ AC_TASK,	AC_NONE,		"command"	},
	{ AC_TASK,	AC_NONE,		"tty"		},
	{ AC_TASK,	AC_NONE,		"flag"		},

	{ AC_NONE,	AC_NONE,		NULL		}
};

/*
 * resource groups
 */
static ac_group_t ac_groups[] = {
	{ AC_PROC,	"extended",
		{ AC_PROC_PID, AC_PROC_UID, AC_PROC_GID, AC_PROC_CPU,
		AC_PROC_TIME, AC_PROC_COMMAND, AC_PROC_TTY, AC_PROC_PROJID,
		AC_PROC_TASKID, AC_PROC_ANCPID, AC_PROC_WAIT_STATUS,
		AC_PROC_ZONENAME, AC_PROC_FLAG, AC_PROC_MEM,
		AC_PROC_MICROSTATE, AC_NONE } },
	{ AC_PROC,	"basic",
		{ AC_PROC_PID, AC_PROC_UID, AC_PROC_GID, AC_PROC_CPU,
		AC_PROC_TIME, AC_PROC_COMMAND, AC_PROC_TTY, AC_PROC_FLAG,
		AC_NONE } },
	{ AC_TASK,	"extended",
		{ AC_TASK_TASKID, AC_TASK_PROJID, AC_TASK_CPU, AC_TASK_TIME,
		AC_TASK_HOSTNAME, AC_TASK_MICROSTATE, AC_TASK_ANCTASKID,
		AC_TASK_ZONENAME, AC_NONE } },
	{ AC_TASK,	"basic",
		{ AC_TASK_TASKID, AC_TASK_PROJID, AC_TASK_CPU, AC_TASK_TIME,
		AC_NONE } },
	{ AC_FLOW,	"extended",
		{ AC_FLOW_SADDR, AC_FLOW_DADDR, AC_FLOW_SPORT, AC_FLOW_DPORT,
		AC_FLOW_PROTOCOL, AC_FLOW_DSFIELD, AC_FLOW_NBYTES,
		AC_FLOW_NPKTS, AC_FLOW_ANAME, AC_FLOW_CTIME, AC_FLOW_LSEEN,
		AC_FLOW_PROJID, AC_FLOW_UID, AC_NONE } },
	{ AC_FLOW,	"basic",
		{ AC_FLOW_SADDR, AC_FLOW_DADDR, AC_FLOW_SPORT, AC_FLOW_DPORT,
		AC_FLOW_PROTOCOL, AC_FLOW_NBYTES, AC_FLOW_NPKTS, AC_FLOW_ANAME,
		AC_NONE } },
	{ AC_NONE,	NULL,
		{ AC_NONE } }
};

/*
 * this function returns the id of the named resource
 */
static int
name2id(char *name, int type)
{
	ac_resname_t *acname = ac_names;
	while (acname->ar_type != AC_NONE) {
		if (acname->ar_type == type &&
		    strcmp(acname->ar_name, name) == 0) {
			if (acname->ar_id == AC_NONE)
				/*
				 * For compatibility with older versions.
				 */
				return (-1);
			else
				return (acname->ar_id);
		}
		acname++;
	}
	return (0);
}

/*
 * this function gives name of the resource by its id
 */
static char *
id2name(int id, int type)
{
	ac_resname_t *acname = ac_names;
	while (acname->ar_id != AC_NONE) {
		if (acname->ar_type == type &&
		    acname->ar_id == id)
			return (acname->ar_name);
		acname++;
	}
	return (NULL);
}

static void
printgroup(int type)
{
	int r, g, id;

	for (g = 0; ac_groups[g].ag_type != AC_NONE; g++) {
		if (ac_groups[g].ag_type != type)
			continue;
		(void) printf("%-9s", ac_groups[g].ag_name);
		(void) printf("%s", id2name(ac_groups[g].ag_mem[0], type));
		for (r = 1; (id = ac_groups[g].ag_mem[r]) != AC_NONE; r++)
			(void) printf(",%s", id2name(id, type));
		(void) printf("\n");
	}
}


/*
 * this function prints the list of resource groups and their members
 */
void
printgroups(int type)
{
	int header = 0;

	if ((type & AC_PROC) && (type & AC_TASK) && (type & AC_FLOW))
		header = 1;

	if (type & AC_PROC) {
		if (header == 1)
			(void) printf("process:\n");
		printgroup(AC_PROC);
	}
	if (type & AC_TASK) {
		if (header == 1)
			(void) printf("task:\n");
		printgroup(AC_TASK);
	}
	if (type & AC_FLOW) {
		if (header == 1)
			(void) printf("flow:\n");
		printgroup(AC_FLOW);
	}
}

/*
 * this function sets the state of the particular resource
 */
static void
resset(ac_res_t *res, int id, int state)
{
	ac_res_t *resp;
	resp = (ac_res_t *)((uintptr_t)res + (sizeof (ac_res_t) * (id - 1)));
	resp->ar_state = state;
	resp->ar_id = id;
}

/*
 * this function gets the state of the particular resource
 */
static int
resget(ac_res_t *res, int id)
{
	ac_res_t *resp;
	resp = (ac_res_t *)((uintptr_t)res + (sizeof (ac_res_t) * (id - 1)));
	return (resp->ar_state);
}

/*
 * this function converts a string of resources into a buffer which then
 * can be used for acctctl() system call
 */
void
str2buf(ac_res_t *buf, char *str, int state, int type)
{
	int i, j, id, ok;
	char *p, *g, *copy;

	if (strcmp(str, AC_STR_NONE) == 0)
		return;
	/*
	 * Take a lap through str, processing resources, modifying buf copy
	 * as appropriate and making sure that all resource names are valid.
	 */
	if ((copy = malloc(strlen(str) + 1)) == NULL)
		die(gettext("not enough memory\n"));
	(void) memcpy(copy, str, strlen(str) + 1);
	p = strtok(copy, ", ");
	while (p != NULL) {
		/*
		 * check if str contains any resource groups
		 */
		for (ok = 0, i = 0; (g = ac_groups[i].ag_name) != NULL; i++) {
			if (strcmp(p, g) == 0 && ac_groups[i].ag_type == type) {
				for (j = 0; (id = ac_groups[i].ag_mem[j]) !=
				    AC_NONE; j++)
					resset(buf, id, state);
				ok = 1;
				break;
			}
		}
		if (ok == 0) {
			id = name2id(p, type);
			if (id > 0)
				resset(buf, id, state);
			else if (id == 0)
				die(gettext("unknown %s resource: %s\n"),
				    ac_type_name(type), p);
		}
		p = strtok(NULL, ", ");
	}
	free(copy);
}

/*
 * this function converts a buffer into a string of resource names.
 * state (on/off) for resources of interest is selected by the third argument.
 * accounting type is selected by the fourth argument.
 * it is caller's responsibility to free the allocated string buffer.
 */
char *
buf2str(ac_res_t *buffer, size_t bufsz, int state, int type)
{
	int i, j, ok, id;
	char *str, *g;
	ac_res_t *buf, *cur;

	if ((buf = malloc(bufsz)) == NULL ||
	    (str = malloc(MAXRESLEN)) == NULL)
		die(gettext("not enough memory\n"));
	(void) memset(str, 0, MAXRESLEN);
	(void) memcpy(buf, buffer, bufsz);
	/*
	 * check if buf has any resource groups in it
	 */
	for (i = 0; (g = ac_groups[i].ag_name) != NULL; i++) {
		if (ac_groups[i].ag_type != type)
			continue;
		for (j = 0; (id = ac_groups[i].ag_mem[j]) != AC_NONE; j++) {
			ok = 1;
			if (resget(buf, id) != state) {
				ok = 0;
				break;
			}
		}
		if (ok) {	/* buf contains this resource group */
			if (strlen(str) != 0)
				(void) strcat(str, ",");
			(void) strcat(str, g);
			for (j = 0; (id = ac_groups[i].ag_mem[j]) != AC_NONE;
			    j++)
				resset(buf, id,
				    state == AC_ON ? AC_OFF : AC_ON);
			ok = 0;
		}
	}
	/*
	 * browse through the rest of the buf for all remaining resources
	 * that are not a part of any groups
	 */
	for (cur = buf; cur->ar_id != AC_NONE; cur++) {
		if (cur->ar_state == state) {
			if (strlen(str) != 0)
				(void) strcat(str, ",");
			if (id2name(cur->ar_id, type) == NULL)
				die(gettext("unknown %s resource id (%d)\n"),
				    ac_type_name(type), cur->ar_id);
			(void) strcat(str, id2name(cur->ar_id, type));
		}
	}
	if (strlen(str) == 0)
		(void) strcpy(str, AC_STR_NONE);
	free(buf);
	return (str);
}
