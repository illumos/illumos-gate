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
 *
 * Copyright 1997 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

#ifndef _RES_H_
#define _RES_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define RES_NOT_VISIT 0
#define RES_VISIT 1 

#define TYPE_LEGACY_SUB_AGENT   "legacy"
#define POLICY_SPAWN            "spawn"
#define POLICY_LOAD     "load"

/* resouce support */
typedef struct _SapResource{
        struct _SapResource* next_res;
        char *res_name;
        char *dir_file;
        char *personal_file;
        time_t personal_file_time;
        char *sec_file;
        time_t sec_file_time;
        int invoke_mode; /* invoke it and keep it alive */
        char* policy;
	char* type;
	char* user; 
        char *start_cmd;
        Agent* agent;
	int mark; /* flag for visit */
        time_t rsrc_file_time;
} SapResource;

extern SapResource *first_res;
extern SapResource *reconfig_first_res;

extern void resource_list_delete();
extern void trace_resources();
extern SapResource *resource_find_by_agent(Agent* agent);
extern void mark_all_resources_not_visit();
extern SapResource *resource_find_by_name(char* name);
extern void get_file_modify_time(char* filename,time_t *file_time);
extern void resource_free(SapResource *ap);
extern void resource_detach(SapResource *tgt);
extern void merging_resource_list();
extern void resource_handling(SapResource *rp);
extern int ssa_subagent_is_alive(Agent *agent);
extern void delete_pid_rec_list();
extern void delete_agent_from_resource_list(Agent *agent); 
extern void write_pid_file(char* filename);
extern void watch_dog_in_action();
extern void kill_all_pid_rec_list();
extern void kill_part_pid_rec_list();

#endif

