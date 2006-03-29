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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <errno.h>

#include "impl.h"
#include "error.h"
#include "trace.h"
#include "pdu.h"

#include "agent.h"
#include "subtree.h"
#include "session.h"
#include "res.h"
#include "dispatcher.h"
#include "snmprelay_msg.h"
#include <pwd.h>

SapResource *first_res = NULL;
SapResource *reconfig_first_res = NULL;

#define MAX_RES_NAME 128
#define CLOCK_TICK 100

typedef struct _PidRec {
	struct _PidRec *next_pid;
	char res_name[MAX_RES_NAME];
	char agent_name[MAX_RES_NAME];
	int pid;
	int port;
} PidRec;

PidRec *first_pid = NULL;


/****************************************************************/

void mark_all_resources_not_visit()
{
  SapResource *ap;
  for(ap=first_res; ap; ap=ap->next_res)
	ap->mark = RES_NOT_VISIT;
}


void trace_resources()
{
	SapResource *ap;


	trace("RESOURCES:\n");
	for(ap = first_res; ap; ap = ap->next_res)
	{

                trace("\t%Name: %s Dir: %s Personal: %s Sec: %s Policy: %s Type: %s Cmd: %s Agent: %s\n",
                        ap->res_name?ap->res_name:"NO NAME",
			ap->dir_file?ap->dir_file:"",
			ap->personal_file?ap->personal_file:"",
			ap->sec_file?ap->sec_file:"",
			ap->policy?ap->policy:"",
			ap->type?ap->type:"",
			ap->start_cmd?ap->start_cmd:"",
                        ap->agent?(ap->agent->name?ap->agent->name:""):"");

	}
	trace("\n");
}

void resource_detach(SapResource *tgt)
{
  SapResource *sp, *last=NULL;

        if(tgt == NULL) return;
        for(sp = first_res; sp; sp = sp->next_res)
        {
                if(sp == tgt)
                {
                        break;
                }

                last = sp;
        }
	if(sp==NULL) return;

        if(last == NULL)
        {
                first_res = tgt->next_res;
                tgt->next_res = NULL;
        }
        else
        {
                last->next_res = tgt->next_res;
                tgt->next_res = NULL;
        }

}



/****************************************************************/

/* We must invoke subtree_list_delete() before invoking	*/
/* this function because the first_agent_subtree member	*/
/* of the agent structures should be NULL		*/

void resource_list_delete()
{
	SapResource *ap = first_res;
	SapResource *next;


	while(ap)
	{
		next = ap->next_res;

		if(ap->agent)
		  agent_destroy(ap->agent);

		resource_free(ap);

		ap = next;
	}

	first_res = NULL;

	return;
}


/****************************************************************/


void resource_free(SapResource *ap)
{
	if(ap == NULL)
	{
		return;
	}

	/* free the extra element */

        if(ap->res_name) free(ap->res_name);
	if(ap->dir_file) free(ap->dir_file);
	if(ap->personal_file) free(ap->personal_file);
	if(ap->sec_file) free(ap->sec_file);
	if(ap->policy) free(ap->policy);
	if(ap->type) free(ap->type);
	if(ap->start_cmd) free(ap->start_cmd);
	
	free(ap);

	return;
}

SapResource *resource_find_by_agent(Agent* agent)
{
  SapResource *ap;
 
  if(agent == NULL) return NULL;
  for(ap=first_res;ap;ap=ap->next_res){
	if(ap->agent == agent) return ap;
  }	
  return NULL;
}

SapResource *resource_find_by_name(char* name)
{
  SapResource *ap;
  if(name == NULL) return NULL;
  for(ap=first_res;ap;ap=ap->next_res){
	if(ap->res_name!=NULL &&
	   !strcmp(ap->res_name,name)) return ap;
  }
  return NULL;
}

SapResource *resource_find(SapResource *sp)
{
  SapResource *ap;

  if(sp == NULL) return NULL;
  for(ap=first_res;ap;ap=ap->next_res){
	if(resource_cmp(ap,sp)==TRUE) return ap;
  }
  return NULL;
}

static char* expand_file_name(char *dir_name,char* file_name)
{
  static char fullname[256];
  static char dirname[256];

  fullname[0]='\0';
  dirname[0]='\0';
  if(file_name!=NULL){
	if(dir_name!=NULL)
	  sprintf(dirname,"%s/",dir_name);
	sprintf(fullname,"%s%s",dirname,file_name);
  }
  return(fullname);
}

/* if two string are NULL, we treat them as equal */
/* equal return 0, otherwise 1 */
static int string_cmp(char *s1, char *s2)
{
  if( (s1 == NULL && s2 != NULL) ||	
      (s1 != NULL && s2 == NULL) ||
      (s1 != NULL && s2 != NULL 
       && strcmp(s1,s2) ) ) return 1;
  return 0;
}

/* return TRUE same, otherwise FALSE */
/* s1 is the new one, s2 is old one */
int resource_cmp(SapResource *s1, SapResource *s2)
{
  char fullname1[256], *name1;
  char fullname2[256], *name2;
  time_t filetime;

  if(s1 == NULL || s2 == NULL) return FALSE;

  /* res_name may be nil */
  if(s1->res_name != NULL && s2->res_name != NULL &&
     strcmp(s1->res_name, s2->res_name))  return FALSE;

  if(string_cmp(s1->policy,s2->policy) ||
     string_cmp(s1->start_cmd,s2->start_cmd) ||
     string_cmp(s1->type,s2->type)) return FALSE;

  name1 = expand_file_name(s1->dir_file,s1->personal_file); 
  strcpy(fullname1,name1);
  name2 = expand_file_name(s2->dir_file,s2->personal_file); 
  strcpy(fullname2,name2);

  if(strcmp(fullname1,fullname2)) return FALSE;

  /* check the time stamp of the personal file */
  if(fullname1!=NULL)
    get_file_modify_time(fullname1,&filetime);

  /* hack, somehow didnt't initialize */
  if(fullname2!=NULL && s2->personal_file_time==0)
    get_file_modify_time(fullname2,&(s2->personal_file_time));

  if(filetime > s2->personal_file_time) return FALSE;

  return TRUE;

  /* same in name, personal_file, policy, start_cmd, type */
}

void get_file_modify_time(char* filename,time_t *file_time)
{
  struct stat statb;
  int fd;

  *file_time = 0;
  if((fd = open(filename, O_RDONLY)) < 0)
  {
        error(ERR_MSG_OPEN, filename, errno_string());
        return;
  }

  /*
   * get the size of the file
   */
  if(fstat(fd, &statb) < 0)
  {
        error(ERR_MSG_FSTAT, filename, errno_string());
	close(fd);
        return;
   }

   /* file time stamp */
   if(file_time) *file_time = statb.st_mtime;
   close(fd);
}




/****************************************************************/
void resource_handle_child_signal()
{
}

int switch_to_user_id(char *user_name)
{
  struct passwd *sp;

  if(user_name == NULL) return (FALSE);
  sp = getpwnam(user_name);
  if(sp != NULL && sp->pw_uid != 0){
	setgid(sp->pw_gid);
	setuid(sp->pw_uid);
	return TRUE;
  }else{
 	return FALSE;
  }
}

/*
 * try to get a port, 5 times
 */
static int get_a_non_reserved_port()
{
  struct sockaddr_in me;
  socklen_t len;
  int on=1, cnt=0;
  int sd;

  sd = socket(AF_INET,SOCK_DGRAM,0);
  if(sd<0) return 0;
  me.sin_family = AF_INET;
  me.sin_addr.s_addr = INADDR_ANY;

  for(;cnt<5;cnt++){
    me.sin_port = htons(0);
    if(bind(sd,(struct sockaddr*)&me,sizeof(me))!=0)continue;
    len = (socklen_t)sizeof(me);
    if(getsockname(sd,(struct sockaddr*)&me, &len)==-1) continue;
    close(sd);
    return me.sin_port;
  }
  close(sd);
  return 0;
}

/****************************************************************/
Integer  systemUpTime()
{
  struct tms buffer;
  return ((Integer)times(&buffer));
}

static int match_pattern_port(char* pat)
{
 	if(pat==NULL) return FALSE; 
	if(pat[0]=='$' && !strcmp(&pat[1],"PORT")) return TRUE;
	return FALSE;
}
	

int spawn_child(SapResource *res)
{
  pid_t pid;
  static char cmd_full_path[256];
  static char port_str[100];
  static char sec_str[100];
  static char per_str[100];
  char *cmd ;
  static char *cmd_arg[10];
  int num_of_args =0;
  int i, offset, path_len;
  char *sptr, *eptr, *last_ptr;

  if(res->agent == NULL || res->agent->agentExecutable.len == 0) return -1;
  cmd_full_path[0] = '\0';
  port_str[0]='\0';
  sec_str[0]='\0';
  per_str[0]='\0';

  memcpy(cmd_full_path,res->agent->agentExecutable.chars,
	res->agent->agentExecutable.len);
  cmd_full_path[res->agent->agentExecutable.len] = '\0';

  memcpy(sec_str,res->agent->agentConfigFile.chars,
	res->agent->agentConfigFile.len);
  sec_str[res->agent->agentConfigFile.len] = '\0';
  
  if( (eptr=strchr(cmd_full_path,' ')) != NULL)
	path_len = eptr - cmd_full_path;
  else
	path_len = strlen(cmd_full_path);
   
  for(i=path_len-1;i>=0 ;i--){
	if(cmd_full_path[i] == '/') break;
  }
  if(i<0 || i+1>strlen(cmd_full_path)-1) return -1;
  cmd = &cmd_full_path[i+1];

  last_ptr = &cmd_full_path[strlen(cmd_full_path)];

  sprintf(port_str,"%d",res->agent->address.sin_port);

  if( (pid=fork()) < 0){
	exit(1);
  }else if( pid == 0) {
		/* always check for $PORT */
		for(eptr=NULL,sptr=cmd;(eptr=strchr(sptr,' '))!=NULL&&sptr<last_ptr;){
			*eptr = '\0';
			if(match_pattern_port(sptr)==TRUE)
				cmd_arg[num_of_args++] = port_str;
			else
				cmd_arg[num_of_args++] = sptr;
			sptr = eptr+1;
			if(sptr >= last_ptr) break;
		}
		if(sptr==cmd){ /* only one argument */ 
			cmd_arg[num_of_args++] = sptr;
		}else if(sptr < last_ptr){
			/* last argument */
			if(match_pattern_port(sptr)==TRUE)
				cmd_arg[num_of_args++] = port_str;
			else
				cmd_arg[num_of_args++] = sptr;
		}

		if(chdir("/") == -1)
		{
		  error(ERR_MSG_CHDIR,",",errno_string());
		}
          /*setsid();*/
		if(res->user!=NULL)
		  if(switch_to_user_id(res->user)==FALSE) exit(1);
		execv(cmd_full_path,cmd_arg);
		/* if the above function < 0, mark the agent dies */
	exit(1);
  }else{ /* parent */
  	return pid;
  }
  exit(1);
}

PidRec *find_pid_rec_by_res_name(char *name)
{
  PidRec *ap;

  for(ap=first_pid; ap; ap=ap->next_pid)
	if(!strcmp(ap->res_name,name)) return ap;
  return NULL;
}

int res_agent_is_alive(char *res_name)
{
  /* find the res_name in the pid_list, and send a get pdu to it */
  PidRec *pp;
  struct timeval timeout; 
 
  pp = find_pid_rec_by_res_name(res_name);
  if(pp==NULL || pp->port<=0) return FALSE;
 
  /* assume community string is public, 
   *        agent_address is localhost, 
   *        timeout is 5 sec
   */ 
   timeout.tv_sec = 5;
   timeout.tv_usec = 0; 
   return(SSAAgentIsAlive(NULL,pp->port,NULL,&timeout));
}

/******** Resource handling (5-28-96) *********/
void
resource_handling(SapResource *rp)
{
	/*
	*scan the resource list
	*if the policy is legacy then
	*read the personal file for the subagent.
	*spawn the subagent with the given command and the required argument
	*/

	char fullname[1024];
	char dirname[1024];
	char buf[1024];
	static Agent* prev_agent = NULL;
	time_t file_time;
	int error_free, port_num;
	PidRec *pp;

		/* read the config. file */
		if (!rp->personal_file) {
			error("NULL registration_file for %s", rp->start_cmd);
			return;
		}
		error_free = personal_file_reading(rp->dir_file,
			rp->personal_file, &file_time);
		rp->personal_file_time = file_time;
		/*
		* assume that the personal file containing only one
		* subagent, then first_agent will point to the previous
		* formed subagent
		*/
	if (first_agent != NULL && first_agent != prev_agent) {
		dirname[0] = '\0';
		if (rp->dir_file != NULL)
			sprintf(dirname, "%s/", rp->dir_file);
		first_agent->agentStatus = SSA_OPER_STATUS_LOAD;
		rp->agent = first_agent;
		prev_agent = first_agent;

		/* init the res_name as the agentName */

		if (first_agent->agentName.chars != NULL) {
			buf[0] = '\0';
			memcpy(buf, first_agent->agentName.chars,
				first_agent->agentName.len);
			buf[first_agent->agentName.len] = '\0';
			rp->res_name = strdup(buf);
		}

		if (rp->personal_file != NULL) {
			fullname[0] = '\0';
			sprintf(fullname, "%s%s", dirname, rp->personal_file);
			(first_agent->agentPersonalFile).chars =
				(uchar_t *)strdup(fullname);
			(first_agent->agentPersonalFile).len =
				strlen(fullname);
		}

		if (rp->sec_file != NULL) {
			fullname[0] = '\0';
			sprintf(fullname, "%s%s", dirname, rp->sec_file);
			(first_agent->agentConfigFile).chars =
				(uchar_t *)strdup(fullname);
			(first_agent->agentConfigFile).len =
				strlen(fullname);
		}

		if (rp->start_cmd != NULL) {
			fullname[0] = '\0';
			sprintf(fullname, "%s%s", dirname, rp->start_cmd);
			(first_agent->agentExecutable).chars =
				(uchar_t *)strdup(fullname);
			(first_agent->agentExecutable).len =
				strlen(fullname);
		}

		if (rp->policy && (strcmp(rp->policy, POLICY_SPAWN) == 0)) {
		/*
		* check the global flag recovery_on, to decide
		* spawn or not, recovery flag should set then reset
		*/
		if (recovery_on == FALSE || (rp->agent != NULL &&
			res_agent_is_alive(rp->res_name) == FALSE)) {
			/*
			* get the port if not exist
			* and store it in rp and agent
			*/
			if (rp->agent->address.sin_port == 0 ||
				rp->agent->agentPortNumber == 0) {
				port_num = get_a_non_reserved_port();
				rp->agent->agentPortNumber =
				rp->agent->address.sin_port = (short)port_num;
				if (port_num == 0)
				error("can't find a valid port"
					"for the agent %s",
				(first_agent->name? first_agent->name:""));
			}
			first_agent ->agentProcessID = spawn_child(rp);
			first_agent->agentSystemUpTime = systemUpTime();
		} else {
			pp = find_pid_rec_by_res_name(rp->res_name);
			first_agent->agentProcessID = pp->pid;
			if (first_agent->agentPortNumber == 0) {
				first_agent->agentPortNumber =
				first_agent->address.sin_port = (short)pp->port;
			}
		}
		}

		first_agent->agentStatus = SSA_OPER_STATUS_ACTIVE;
		/* activate the agent, subtree, table */
		sync_subtrees_with_agent(first_agent);
		activate_table_for_agent(first_agent);
	}

	if (first_agent == NULL) {
		error_exit("No SNMP agent configured");
	}
}

int ssa_subagent_is_alive(Agent *agent)
{
  struct timeval timeout; 
 
  if(agent==NULL) return FALSE;
  if(agent->agentPortNumber<0) return FALSE;
 
  /*
   * assume community string is public
   */ 
   timeout.tv_sec = 5;
   timeout.tv_usec = 0; 
   return(SSAAgentIsAlive(&agent->address.sin_addr,
	agent->agentPortNumber,NULL,&timeout));
}

void trace_pid_rec()
{
	PidRec *ap;


	trace("PID_REC:\n");
	for(ap = first_pid; ap; ap = ap->next_pid)
	{

                trace("\t%ResName: %s AgentName: %s Pid: %d Port: %d\n",
                        ap->res_name?ap->res_name:"NO-NAME",
			ap->agent_name?ap->agent_name:"NO-NAME",
			ap->pid,ap->port);

	}
	trace("\n");
}

void delete_pid_rec_list()
{
	PidRec *ap = first_pid;
	PidRec *next;


	while(ap)
	{
		next = ap->next_pid;

		free(ap);

		ap = next;
	}

	first_pid = NULL;
}


void read_pid_file(char *filename)
{
  PidRec *pid;
  struct stat statb;
  FILE *file;
  int res=4;

  first_pid = NULL;
  if((file = fopen(filename, "r")) == NULL)
  {
/* file not exist, ignore it
        error(ERR_MSG_OPEN, filename, errno_string());
*/
	return;
  }

  while(res ==4)
  {
  	pid = calloc(1,sizeof(PidRec));
  	if(pid == NULL){ 
		error("malloc() failed");
		fclose(file);
		return;
  	}
        res =fscanf(file,"%s%s%d%d",
	    pid->res_name,pid->agent_name,&(pid->pid),&(pid->port));
	if(res==4){
  	  if(first_pid==NULL){
		pid->next_pid = NULL;
 	   }else{
		pid->next_pid = first_pid;
  	  }
  	  first_pid = pid;
	}else{
		free(pid);
	}
  }
  
}


void
write_pid_file(char *filename)
{
	char name[256];
	FILE *fp;
	SapResource *sp1;

	umask(S_IWGRP | S_IWOTH);
	fp = fopen(filename, "a+");
	if (fp == NULL) {
		error("can't open the file");
		return;
	}
	/* write the tuple { resouce_name, agent_name, pid, port } */
	for (sp1 = first_res; sp1; sp1 = sp1->next_res) {
		if (sp1->policy == NULL || strcmp(sp1->policy, POLICY_SPAWN))
			continue;
		if (sp1->agent == NULL)
			continue;
		if (sp1->agent->agentName.chars != NULL) {
			memcpy(name, sp1->agent->agentName.chars,
				sp1->agent->agentName.len);
			name[sp1->agent->agentName.len] = '\0';
		} else {
			strcpy(name, "UNKNOWN");
		}
		fprintf(fp, "%s %s %d %d\n",
			(sp1->res_name != NULL ? sp1->res_name: "UNKNOWN"),
			name,
			sp1->agent->agentProcessID,
			sp1->agent->agentPortNumber);
	}
fclose(fp);
}

/*
 * Add the port number and pid of relay agent to
 * /var/snmp/snmpdx.st file
 */
void
write_pid_file1(char *filename)
{
	struct stat buf;
	char name[256];
	FILE *fp;
	Subtree *sp;

	sprintf(name, "%s.old", filename);
	if (filename == NULL)
		return;
	if (stat(filename, &buf) == 0) {
		if (rename(filename, name) == -1)
			error("can't save the pid file");
	}

	umask(S_IWGRP | S_IWOTH);
	fp = fopen(filename, "w");
	if (fp == NULL) {
		error("can't open the file");
		return;
	}
	for (sp = first_subtree; sp; sp = sp->next_subtree) {
		if (sp->agent) {
			if (strcmp(sp->agent->name, "relay-agent") == 0) {
				fprintf(fp, "%s %s %d %d\n",
					sp->agent->name,
					sp->agent->name,
					sp->agent->agentProcessID,
					sp->agent->address.sin_port);
			}
		}
	}
fclose(fp);
}

void merging_resource_list()
{
  SapResource* sp, *match_sp, *next;
  SapResource* merge_res_list=NULL;
  int port_num;

  /* scan the reconfig list, find same name resource,
     if found, see difference, */
  sp=reconfig_first_res;
  while(sp){
    next = sp->next_res;
    if(sp!=NULL) match_sp = resource_find(sp);
    if(match_sp != NULL){
	/* exists before */
	resource_detach(match_sp);
	if(resource_cmp(sp,match_sp)==TRUE){
	  /* no need to reread the personal file */
	  /* spawn process ? */
	  resource_free(sp);
	  if(match_sp->policy && !strcmp(match_sp->policy,POLICY_SPAWN)){
		if(match_sp->agent!=NULL && 
		   ssa_subagent_is_alive(match_sp->agent) == FALSE)
		{
			/* get the port if not exist 
			 * and store it in rp and agent */
		  if(match_sp->agent->address.sin_port == 0 ||
		     match_sp->agent->agentPortNumber ==0){
			port_num = get_a_non_reserved_port();
			match_sp->agent->agentPortNumber =
			match_sp->agent->address.sin_port = (short)port_num;
		  }
	  	  match_sp->agent->agentProcessID = spawn_child(match_sp);
		  match_sp->agent->agentSystemUpTime = systemUpTime();
		}
	  }
	  sp=match_sp;
	}else{
	  /* new info for the agent */
	  if(match_sp->agent!=NULL)
	  	agent_destroy(match_sp->agent);
	   if(match_sp->policy && !strcmp(match_sp->policy,POLICY_SPAWN)){
		kill(match_sp->agent->agentProcessID,SIGTERM);
	   }
	   resource_free(match_sp);
	   resource_handling(sp);
	}
    }else{
	/* non-exist resource */
	resource_handling(sp);
    }
    if(merge_res_list==NULL){
	sp->next_res = NULL;
    }else{
	sp->next_res = merge_res_list;
    }
    merge_res_list = sp;
	
    sp=next;
  }

  resource_list_delete();
  first_res = merge_res_list;
  
  /* update the PID file */
}

void  delete_agent_from_resource_list(Agent *agent)
{
  SapResource *sp, *last=NULL;

  if(agent==NULL) return;
  for(sp=first_res; sp; sp=sp->next_res)
  {
	if(sp->agent == agent) break;
  	last = sp;
  }
  if(sp==NULL) return;
  if(last==NULL)
  {
	first_res = sp->next_res;
	sp->next_res = NULL;
  }else{
	last->next_res = sp->next_res;
	sp->next_res = NULL;
  }
  resource_free(sp); 
}


int watch_dog_time_is_up(Agent *agent,int elapse_time)
{
  if(agent==NULL || agent->agentWatchDogTime==0) return FALSE;
  if(elapse_time >= agent->agentWatchDogTime) return TRUE;
  return FALSE;
}



void watch_dog_in_action()
{
  SapResource *rp;
  int port_num;
  static int start_time=0;
  static int end_time=0;
  int time_diff;
  static struct tms buffer;

  if(any_outstanding_session()==TRUE) return;
  end_time = times(&buffer);
  time_diff = (end_time - start_time)/CLOCK_TICK;

  for(rp=first_res;rp;rp=rp->next_res){
	  if(rp->policy && !strcmp(rp->policy,POLICY_SPAWN)){
		if (rp->agent == NULL) {
		    if (trace_level > 0)
			trace("watch_dog: repopulating agent %s\n", rp->res_name);
		    /* the agent was probably deleted by the timeout mechanism */
		    resource_handling(rp);
		    sync_agent_acl(rp->agent);
		}
		if(rp->agent != NULL && 
		   watch_dog_time_is_up(rp->agent,time_diff) &&
		   ssa_subagent_is_alive(rp->agent)==FALSE)
		{
			/* get the port if not exist 
			 * and store it in rp and agent */
			if(rp->agent->address.sin_port == 0 ||
			   rp->agent->agentPortNumber ==0){
				port_num = get_a_non_reserved_port();
				rp->agent->agentPortNumber =
				rp->agent->address.sin_port = (short)port_num;
				if(port_num==0)
				  error("can't find a valid port for the agent %s",(rp->agent->name? rp->agent->name:""));
			}
                        if (!already_bound_port(rp->agent->agentPortNumber)) {
				rp->agent ->agentProcessID = spawn_child(rp);
				if (trace_level > 0)
					trace("watch_dog: restart agent %s pid %d\n", rp->res_name, rp->agent->agentProcessID);
				rp->agent->agentSystemUpTime = systemUpTime();
                        }
		}
	}
  }
  start_time = end_time;
}

int already_bound_port(int port_num) {

int socket_handle;
struct sockaddr_in in_addr;
char errmsg[100];

     socket_handle = socket(AF_INET,SOCK_DGRAM,0) ;
     if (socket_handle < 0) {
        error("Unable to open Datagram Socket error = %d",errno);
        return 0;
     }
     in_addr.sin_addr.s_addr = htonl(INADDR_ANY) ;
     in_addr.sin_family = AF_INET;
     in_addr.sin_port = htons(port_num);
     memset(in_addr.sin_zero,0,8 );

     if (bind(socket_handle,(struct sockaddr *)&in_addr, sizeof(struct sockaddr))) {
            close(socket_handle);
            return 1;
     }else {
            close(socket_handle);
            return 0;
     }


}

void kill_all_pid_rec_list()
{
	PidRec *ap;
	Agent *ag;
	struct timeval timeout;

   	timeout.tv_sec = 5;
  	timeout.tv_usec = 0; 

	for(ap=first_pid;ap;ap=ap->next_pid){
	  if(ap->agent_name != NULL &&
	     SSAAgentIsAlive(NULL,ap->port,NULL,&timeout)==TRUE){
			kill(ap->pid,SIGTERM);
	     		if(SSAAgentIsAlive(NULL,ap->port,NULL,&timeout)==TRUE)
				kill(ap->pid,SIGKILL);
	  }
	}
}

void kill_part_pid_rec_list()
{
	PidRec *ap;
	Agent *ag;
	struct timeval timeout;

   	timeout.tv_sec = 5;
  	timeout.tv_usec = 0; 

	for(ap=first_pid;ap;ap=ap->next_pid){
	  if(ap->agent_name != NULL &&
	     agent_find_by_name(ap->agent_name) == NULL &&
	     SSAAgentIsAlive(NULL,ap->port,NULL,&timeout)==TRUE){
			kill(ap->pid,SIGTERM);
	  }
	}
}
