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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "impl.h"
#include "error.h"
#include "trace.h"
#include "asn1.h"
#include "snmp.h"
#include "trap.h"

#include "agent_msg.h"
#include "access.h"

#define WILD_CARD_HOST_NAME	"*"
#define WILD_CARD_ADDRESS 0

#define MAX_BUF_SIZE 256

/***** STATIC VARIABLES *****/

static Manager *first_manager = NULL;
static Community *first_community = NULL;

static EFilter *first_efilter = NULL;

static NameOidPair *first_name_oid_pair = NULL;


void init_manager_set ()
{
	first_community = NULL;	/* TODO: check this out */
	first_manager = NULL;
}

void set_first_manager (Manager *mgr)
{
	first_manager = mgr;
}

Manager * get_curr_manager_set ()
{
	return first_manager;
}

/***********************************************************/

/*
 *	returns	0 if OK
 *		1 if error
 *		-1 if fatal error
 */

Manager* manager_add(char *name, char *error_label)
{
	IPAddress ip_address;
	Manager *new;
	Manager *m;


	error_label[0] = '\0';


	if(name == NULL)
	{
		(void)sprintf(error_label, "BUG: manager_add(): name is NULL");
		return NULL;
	}


	/* skip the ip adx for wild-card host */

	if(strcmp(name,WILD_CARD_HOST_NAME)){
		/* try to find the IP address from the name */
		if(name_to_ip_address(name, &ip_address, error_label))
		{
			return NULL;
		}
	}


	/* checking for dup is on the wild-card host name */


	/* check if this manager does not already exist */
	if(strcmp(name,WILD_CARD_HOST_NAME)){
		for(m = first_manager; m; m = m->next_manager)
		{
			if(ip_address.s_addr == m->ip_address.s_addr)
			{
				(void)sprintf(error_label, ERR_MSG_MANAGER_DUP, name);
				return m;
			}
		}
	}else{
		for(m = first_manager; m; m = m->next_manager)
		{
			if(!strcmp(m->name,name))
			{
				return m;
			}
		}
	}


	/* allocate, initialize and link the new manager */
	new = (Manager *) calloc(1,sizeof(Manager));
	if(new == NULL)
	{
		(void)sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	new->next_manager = NULL;
	new->name = NULL;

	new->name = strdup(name);
	if(new->name == NULL)
	{
		(void)sprintf(error_label, ERR_MSG_ALLOC);
		free(new);
		return NULL;
	}

	/* ip adx for wild-card host should be zero */

	if(strcmp(name,WILD_CARD_HOST_NAME)){
		new->ip_address.s_addr = ip_address.s_addr;
	}else{
		new->ip_address.s_addr = WILD_CARD_ADDRESS;
		
	}

	new->next_manager = first_manager;
	first_manager = new;


	return new;
}

/***********************************************************/

/*
 * returns a pointer to the manager if the request succeeds,
 * otherwise returns NULL
 */

Manager *is_valid_manager(Address *address, Manager **mngr)
{
        Manager *m;

        *mngr = NULL;

        if(address == NULL)
        {
                error("BUG: is_valid_manager(): address is NULL");
                return NULL;
        }

        if(first_manager == NULL)
        {
                return NULL;
        }

        for(m = first_manager; m; m = m->next_manager)
        {
                if(address->sin_addr.s_addr == m->ip_address.s_addr)
                {
                        *mngr = m;
                        return m;
                }
        }

        /* check for wild-card host */
        for(m = first_manager; m; m = m->next_manager)
        {
                if(!strcmp(m->name,WILD_CARD_HOST_NAME)){
                        *mngr = m;
                        return m;
                }
        }

        return m;
}

/***********************************************************/

void delete_manager_list()
{
	Manager *next;


	while(first_manager)
	{
		next = first_manager->next_manager;

		if(first_manager->name)
		{
			free(first_manager->name);
		}

		free(first_manager);

		first_manager = next;
	}

	first_manager = NULL;
}

void manager_list_free(Manager *mngr)
{
	Manager *next;


	while(mngr)
	{
		next = mngr->next_manager;

		if(mngr->name)
		{
			free(mngr->name);
		}

		free(mngr);

		mngr = next;
	}

	mngr = NULL;
}

void sub_member_free(SubMember *mem)
{
  Manager *mngr;

  if(mem==NULL) return;
  mem->count--;
  if(mem->count<0){
  	mngr = mem->first_manager;
  	manager_list_free(mngr);
  	if(mem->community_string != NULL) free(mem->community_string);
  	free(mem);  
  }
}

void sub_group_list_free(SubGroup *group)
{
	SubGroup *next;


	while(group)
	{
		next = group->next_sub_group;

		if(group->first_sub_member != NULL)
		{
			sub_member_free(group->first_sub_member);
		}

		free(group);

		group = next;
	}

}

void trap_slot_list_free(TrapSlot *slot)
{
	TrapSlot *next;


	while(slot)
	{
		next = slot->next_trap_slot;
		if(slot->first_sub_group != NULL)
		{
			sub_group_list_free(slot->first_sub_group);
		}

		free(slot);

		slot = next;
	}

}


void delete_efilter_list()
{
	EFilter *next;


	while(first_efilter)
	{
		next = first_efilter->next_efilter;

		if(first_efilter->name)
		{
			free(first_efilter->name);
		}

		free(first_efilter);

		first_efilter = next;
	}

	first_efilter = NULL;
}

/***********************************************************/

void trace_managers()
{
	Manager *m;
	AccessServer *as;

	trace("MANAGERS:\n");
	trace("---------\n");
	for(m = first_manager; m; m = m->next_manager)
	{
		trace("%-30s %-20s\n",
			m->name,
			!strcmp(m->name,WILD_CARD_HOST_NAME)?
			"0":inet_ntoa(m->ip_address)   );
		for(as=m->first_acc_server;as;as=as->next_acc_server)
			trace_access_server(as);
		
	}
	trace("\n");
}


/***********************************************************/

/*
 *	returns	0 if OK
 *		1 if error
 *		-1 if fatal error
 */

int community_add(char *name, int type, char *error_label)
{
	int ret;
	Community *new;
	Community *c;
	Community *last = NULL;


	error_label[0] = '\0';

	if(name == NULL)
	{
		(void)sprintf(error_label, "BUG: community_add(): name is NULL");
		return -1;
	}

	if(name[0] == '\0')
	{
		(void)sprintf(error_label, "BUG: community_add(): name is empty");
		return -1;
	}

	if( (type != READ_ONLY) && (type != READ_WRITE) )
	{
		(void)sprintf(error_label, "BUG: community_add(): bad type (%d)", type);
		return -1;
	}

	for(c = first_community; c; c = c->next_community)
	{
		ret = strcmp(name, c->name);
		if(ret > 0)
		{
			break;
		}
		else
		if(ret == 0)
		{
			(void)sprintf(error_label, ERR_MSG_COMMUNITY_DUP, name);
			return 1;
		}

		last = c;
	}

	new = (Community *) calloc(1,sizeof(Community));
	if(new == NULL)
	{
		(void)sprintf(error_label, ERR_MSG_ALLOC);
		return -1;
	}
	new->next_community = NULL;
	new->name = NULL;

	new->name = strdup(name);
	if(new->name == NULL)
	{
		(void)sprintf(error_label, ERR_MSG_ALLOC);
		free(new);
		return -1;
	}

	new->type = type;

	if(last)
	{
		last->next_community = new;
	}
	else
	{
		first_community = new;
	}
	new->next_community = c;


	return 0;
}

int get_access_type(Manager *mngr,char *name)
{
  AccessServer *as;
  AccessPolicy *ap;
  Community *comm;
  
  if(name==NULL || mngr==NULL) return NULL;
  for(as=mngr->first_acc_server;as;as=as->next_acc_server)
  {
    if((ap=as->first_acc_policy)!=NULL)
	for(comm=ap->first_community;comm;comm=comm->next_community)
		if(comm->name!=NULL && !strcmp(name,comm->name))
			return ap->access_type;
  }
  return -1;
}


/***********************************************************/

/* returns True or False        */

int is_valid_community(char *name, int type, Manager *mngr)
{
	int access_type;


	if(name == NULL)
	{
		error("BUG: is_valid_community(): name is NULL");
		return False;
	}

	if( (type != GETNEXT_REQ_MSG )
		&& (type != GET_REQ_MSG)
		&& (type != SET_REQ_MSG) )
	{
		error("BUG: is_valid_community(): bad type(0x%x)", type);
		return False;
	}

  	if(mngr==NULL)  return True; /* accept reqs from any hosts */

	if(mngr->first_acc_server!=NULL){
		if( (access_type = get_access_type(mngr,name)) == -1)
			return False;
	}

	if(type != SET_REQ_MSG)
	{
		return True;
	}
	else
	{
		if(access_type == READ_WRITE)
		{
			return True;
		}
		else
		{
			return False;
		}
	}

}


/***********************************************************/

void delete_community_list()
{
	Community *next;


	while(first_community)
	{
		next = first_community->next_community;

		if(first_community->name)
		{
			free(first_community->name);
		}

		free(first_community);

		first_community = next;
	}

	first_community = NULL;
}


/***********************************************************/

void trace_access_server(AccessServer *as)
{
  AccessPolicy *ap;

  if(as==NULL) return;
  if( (ap=as->first_acc_policy)!=NULL )
	trace_access_policy(ap);
}

void trace_access_policy(AccessPolicy *ap)
{
  Community *c;

  if(ap==NULL) return;
  trace("\tCOMMUNITIES(");
  switch(ap->access_type)
  {
	case READ_ONLY:
		trace("%s", "READ_ONLY");
		break;
	case READ_WRITE:
		trace("%s", "READ_WRITE");
		break;
  }
  trace("): ");
  for(c=ap->first_community;c;c=c->next_community)
	trace_communities(c);
  trace("\n");
}

void trace_communities(Community *c)
{


	trace(" %s", c->name);
}


/***********************************************************/
void community_list_free(Community *comm)
{
	Community *next;


	while(comm)
	{
		next = comm->next_community;

		if(comm->name)
		{
			free(comm->name);
		}

		free(comm);

		comm = next;
	}

	comm = NULL;
}

void access_policy_list_delete(AccessPolicy *ap)
{
  if(ap==NULL) return;
  ap->count--;
  if(ap->count<=0){ 
  	free(ap);
  }
}

void access_policy_list_free(AccessPolicy *ap)
{
  if(ap==NULL) return;
  ap->count--;
  if(ap->count<=0){ 
  	community_list_free(ap->first_community);
  	free(ap);
  }
}

void access_server_delete(AccessServer *as)
{
  if(as==NULL) return;
  access_policy_list_delete(as->first_acc_policy);
  free(as);
}

void access_server_free(AccessServer *as)
{
  if(as==NULL) return;
  access_policy_list_free(as->first_acc_policy);
  free(as);
}

void agent_manager_list_free(Manager *mgr)
{
	Manager *nextmgr;
	AccessServer *as, *last=NULL;

	if (mgr == NULL)
		return;

	while(mgr)
	{
		nextmgr = mgr->next_manager;

		as = mgr->first_acc_server;
		while (as) {
			last = as->next_acc_server;
			access_server_delete(as);
			as = last;
		}

		if(mgr->name)
			free(mgr->name);

		free(mgr);

		mgr = nextmgr;
	}

	mgr = NULL;
}

void access_server_add_tail(Manager* mngr, AccessServer *acc_server)
{
  AccessServer *as, *last=NULL;

  if(mngr==NULL || acc_server==NULL) return;
  for(as=mngr->first_acc_server;as;as=as->next_acc_server)
	last = as;

  if(last==NULL){
	mngr->first_acc_server = acc_server;
  }else{
	last->next_acc_server = acc_server;
  }
  acc_server->next_acc_server = NULL;
  acc_server->attached = TRUE;
}

void community_attach(AccessPolicy *ap, Community *comm)
{
  if(ap==NULL || comm==NULL) return;
  if(ap->first_community==NULL)
	ap->first_community = comm;
  else{
	comm->next_community = ap->first_community;
	ap->first_community = comm;
  }
}
  
		
EFilter* efilter_add(char *name, char *error_label)
{
	EFilter *new;
	EFilter *m;


	error_label[0] = '\0';


	if(name == NULL)
	{
		(void)sprintf(error_label, "BUG: efilter_add(): name is NULL");
		return NULL;
	}


	for(m = first_efilter; m; m = m->next_efilter)
	{
		if(!strcmp(m->name,name))
		{
			return m;
		}
	}


	/* allocate, initialize and link the new efilter */
	new = (EFilter *) calloc(1,sizeof(EFilter));
	if(new == NULL)
	{
		(void)sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	new->next_efilter = NULL;
	new->name = NULL;

	new->name = strdup(name);
	if(new->name == NULL)
	{
		(void)sprintf(error_label, ERR_MSG_ALLOC);
		free(new);
		return NULL;
	}

	new->enterprise = enterprise_name_to_oid(new->name);

	new->next_efilter = first_efilter;
	first_efilter = new;

	return new;
}

TrapSlot* trap_slot_add(int num,EFilter *efilter,char *error_label)
{
	TrapSlot *new;
	TrapSlot *m;


	if(efilter==NULL) return NULL;
	if(num < 0)
	{
		(void)sprintf(error_label, "BUG: trap_slot_add(): name is NULL");
		return NULL;
	}


	for(m = efilter->first_trap_slot; m; m = m->next_trap_slot)
	{
		if(m->num == num)
		{
			return m;
		}
	}


	/* allocate, initialize and link the new efilter */
	new = (TrapSlot *) calloc(1,sizeof(TrapSlot));
	if(new == NULL)
	{
		(void)sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	new->num = num;
	new->next_trap_slot = efilter->first_trap_slot;
	efilter->first_trap_slot = new;

	return new;
}

void sub_group_add_tail(TrapSlot *slot, SubGroup *group)
{
  SubGroup *sg, *last =NULL;

  if(slot==NULL || group==NULL) return;
  for(sg=slot->first_sub_group;sg;sg=sg->next_sub_group)
	last = sg;

  if(last==NULL){
	slot->first_sub_group = group;
  }else{
	last->next_sub_group = group;
  }
  group->next_sub_group = NULL;
}

void mem_filter_join(int low, int high,SubMember *mem,EFilter *filter)
{
  /* find the trap slot in the filter */
  /* create subgroup, attach submember to subgroup */
  /* insert subgroup into the trap slot */

  int idx;
  TrapSlot *slot;
  SubGroup *group;

  if(low<0 || high<0 || filter==NULL || mem==NULL) return;
  for(idx=low;idx<=high;idx++){
	slot = trap_slot_add(idx,filter,error_label);
	if(slot==NULL) continue;
	group = calloc(1,sizeof(SubGroup));
	if(group==NULL){
		error("malloc() failed");
	}
        /* The efilter list may contain duplicate entries because
           the agent ACL file may be read several times. This seems
           to be necessary to mantain other functionality in the ACL
           such as specifying managers. The following hack makes sure
           the trap is sent to each host only by not allowing duplicate
           members in an efilter.
        */
        if (slot->first_sub_group == NULL) {	/* always add initial first_sub_group */
		sub_group_add_tail(slot,group);
		group->first_sub_member = mem;
		mem->count++;
        }else {                                 /* at least one sub_group exists  */ 
                if (strcmp(slot->first_sub_group->first_sub_member->first_manager->name,  
                           mem->first_manager->name)) {  /* check for duplicate member */ 
                                  sub_group_add_tail(slot,group);
                                  group->first_sub_member = mem;
                                  mem->count++; 
                } else    /* don't add duplicate  */
                      free(group);
        }
  }
}

static void trace_hosts(Manager *mngr)
{
   Manager *m;

   for(m=mngr;m;m=m->next_manager){
	trace("\t\t%s %s\n",
			m->name,
			inet_ntoa(m->ip_address));
   }
}

static void trace_sub_member(SubMember *mem)
{
  if(mem==NULL) return;
  if(mem->community_string != NULL)
  	trace("\tcommunity-string: %s\n",mem->community_string);
  trace_hosts(mem->first_manager);
}

static void trace_sub_group(SubGroup *group)
{
  if(group==NULL) return;
  trace_sub_member(group->first_sub_member);
}

static void trace_trap_slot(TrapSlot *slot)
{
  SubGroup *group;

  if(slot==NULL) return;
  trace("\ttrap-num=%d",slot->num);
  for(group=slot->first_sub_group;group;group=group->next_sub_group)
  	trace_sub_group(group);
}

void trace_filter()
{
  EFilter *filter;
  TrapSlot *slot;

  trace("#EFILTER:\n");	
  for(filter=first_efilter;filter;filter=filter->next_efilter)
  {
	trace("enterprise=\"%s\"\n",filter->name);
	for(slot=filter->first_trap_slot;slot;slot=slot->next_trap_slot)
		trace_trap_slot(slot);
  }
  trace("\n");
}

/**** Enterprise related functions *****/

void trace_name_oid_pair()
{
  NameOidPair *np;

  trace("NAME_OID_PAIR:\n");
  for(np=first_name_oid_pair;np;np=np->next)
        trace("name: %s oid: %s\n",np->name,SSAOidString(np->oid));
  trace("\n");
}

Oid *enterprise_name_to_oid(char *name)
{
  NameOidPair *np;

  if(name == NULL) return NULL;
  for(np=first_name_oid_pair;np;np=np->next){
        if(np->name!=NULL && !strcmp(name,np->name))
                return np->oid;
  }
  return NULL;
}

static NameOidPair* set_name_and_oid_pair(char *inbuf)
{
        char *str;
        char *name_str, *oid_str;
        Oid  *oid = NULL;
	NameOidPair *np;

        if ((inbuf== NULL) || (inbuf[0]== '#')) return NULL;

        /* first "  for name */
        if ((str = strchr(inbuf, '"')) == NULL) return NULL;
        str++;
        name_str = str;

                /* second " for name */
        if ((str = strchr(str, '"')) == NULL) return NULL;
        *str = '\0';

        str++;
        /* first " for oid_str*/
        if ((str = strchr(str, '"')) == NULL)  return NULL;
        str++;
        oid_str = str;

        /* second " for oid_str*/
        if ((str = strchr(str, '"')) == NULL) return NULL;
        *str = '\0';
        oid = SSAOidStrToOid(oid_str,error_label);

	np = calloc(1,sizeof(NameOidPair));	
	if(np==NULL){
	  error("calloc failed");
	  return NULL;
	}
	np->oid = oid;
	np->name = strdup(name_str);

	if (np->name == NULL) {
		free(np);
		return(NULL);
	}

	return np;
}

static void insert_name_oid_pair(char *name_str,char* oid_str)
{
  char inbuf[MAX_BUF_SIZE];
  NameOidPair *np;

   (void)sprintf(inbuf,"\"%s\"   \"%s\"\n",name_str,oid_str);
   if( (np=set_name_and_oid_pair(inbuf)) != NULL){
		np->next = first_name_oid_pair;
		first_name_oid_pair = np;
   }
}

void load_enterprise_oid(char* filename)
{
  FILE *fd;
  char inbuf[MAX_BUF_SIZE];
  NameOidPair *np;

  if(filename==NULL) return;
  fd = fopen(filename,"r");
  if(fd==NULL){
	error("can open the file %s",filename);
	return;
  }
  while(fgets(inbuf,MAX_BUF_SIZE,fd)){
	if( (np=set_name_and_oid_pair(inbuf)) != NULL){
	/* insert np */
		np->next = first_name_oid_pair;
		first_name_oid_pair = np;
	}
  }
  /* insert a couple of extra name-oid pairs:
	sun, snmp
   */
	insert_name_oid_pair("snmp", "1.3.6.1.2.1.11");
	insert_name_oid_pair("sun", "1.3.6.1.4.1.42.2.1.1");

  (void)fclose(fd);
}

static EFilter* find_efilter(Oid* oid)
{
  EFilter *filter;

  for(filter=first_efilter;filter;filter=filter->next_efilter)
  {
	if(SSAOidCmp(filter->enterprise,oid)==0) return filter;
  }
  return NULL;
}

static TrapSlot* find_trap_slot(int num,EFilter *filter)
{
  TrapSlot *slot;

  for(slot=filter->first_trap_slot;slot;slot=slot->next_trap_slot)
	if(slot->num==num) return slot;
  return NULL;
}

void trap_filter_action(Oid *oid,int generic,int specific,
        uint32_t time_stamp,SNMP_variable *variables)
{
  EFilter *filter;
  TrapSlot *slot;
  SubGroup *group;
  Manager *manager;
  static Subid snmp_subids[] = {1,3,6,1,2,1,11};
  static Oid snmp_oid = {snmp_subids, 7};
  int trap_num;
  IPAddress my_ip_address;

  (void)memset(&my_ip_address, 0, sizeof(IPAddress));

  if(oid==NULL) return;
  if( (filter=find_efilter(oid))==NULL ) return;
  if(SSAOidCmp(oid,&snmp_oid)==0)
	trap_num = generic;
  else
	trap_num = specific;
  if( (slot=find_trap_slot(trap_num,filter))==NULL ) return;
  for(group=slot->first_sub_group;group;group=group->next_sub_group){
	if(group->first_sub_member!=NULL){
	  for(manager=group->first_sub_member->first_manager;manager;
		manager=manager->next_manager){
		trap_send_raw(&(manager->ip_address),my_ip_address,
			group->first_sub_member->community_string,0,
			oid,generic,specific, SNMP_TRAP_PORT,time_stamp,
			variables,error_label);
	  }
	}
  }
}
 
