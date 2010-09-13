/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/***********************************************************
	Copyright 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
/************
 * HISTORY
 * 5-14-96	Jerry Yeung	add request filter
 * 5-28-96      Jerry Yeung     Three phase set protocol(Three Phase)
 * 9-18-96	Jerry Yeung	agent_process has wrong arg.
 ***********/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/times.h>
#include <limits.h>

#include "impl.h"
#include "error.h"
#include "trace.h"
#include "asn1.h"
#include "snmp.h"
#include "pdu.h"
#include "request.h"

#include "snmprelay_msg.h"
#include "agent.h"
#include "subtree.h"
#include "access.h"
#include "session.h"
#include "dispatcher.h"
#include "trap.h"



/***** LOCAL CONSTANTS *****/

#define SESSION_ID_MASK			0xffffff00
#define SESSION_ID_INCREMENT_VALUE	256
#define REQUEST_ID_MASK			0x000000ff
#define	INVALID_ERROR_INDEX		0

/***** LOCAL VARIABLES *****/

Session *first_session = NULL;

static u_long session_id = 0;

static int session_internal_error = FALSE;	/* only used bu session_open() */

/**** Three Phase ****/
static Three_Phase three_phase;


/***** LOCAL FUNCTIONS *****/

static void trace_session(Session *session);
static void trace_request(Request *request);

static Session *session_open(Address *address, SNMP_pdu *pdu);
void session_close(Session *session);

static int session_build_request_list(Session *session, int index, SNMP_variable *variable, Subtree *subtree);
static int session_build_local_sysUptime(Session *session, int index, SNMP_variable *variable);


void session_remove_from_list(Session *session);

void session_free(Session *session);
void request_list_free(Request *request_list);
void request_free(Request *request);

static void session_respond(Session *session);
static void session_respond_error(Session *session, int status, int index);

static Session *session_find(Address *address, u_long request_id);

static int session_send_request(Request *request);

static Request *session_move_request(Request *request, Subtree *subtree);

static int session_timeout_loop(struct timeval *now);

/* (5-14-96) */
static void session_process_response(SNMP_pdu *pdu_read,int doRespondHere);

static int session_send_loopback_request(Request *request,int doRespondHere);

static int community_check(Address * address, Agent* agent, int pdu_type, char * community);

/* These 3 functions are used to prevent oscillations between	*/
/* 2 agents when we try to retreive an empty table		*/
/* Example:							*/
/* 	Suppose that we have a table and the columns		*/
/*	with an index 1.x are supported by agent A and the	*/
/*	columns with an index 2.y are supporeted by agent B	*/
/*	Suppose that in fact this table is empty and we send	*/
/*	send the request Get-Next(columnA)			*/
/*								*/
/*	Here is the sequence:					*/
/*	Get-Next(columnA) on subtree columnA ==> No Such Name	*/
/*	Get-Next(columnA) on subtree columnA.2 ==> No Such Name	*/
/*	Get-Next(columnA) on subtree columnB ==> No Such Name	*/
/*	Get-Next(columnA) on subtree columnB.2 ==> No Such Name	*/
/*	....							*/
/*								*/
/*	That is why we have to register which agents we have 	*/
/*	already visited and not only the last one		*/

static int request_add_visited_agent(Request *request, Agent *agent);
static void agent_list_free(Agent_List *alp);
static int is_in_agent_list(Agent_List *agent_list, Agent *agent);


/************************************************************************/

void trace_sessions()
{
	Session *sp;
	int count = 0;


	trace("SESSIONS:\n");
	trace("---------\n");
	for(sp = first_session; sp; sp = sp->next_session)
	{
		trace("session %d:\n", sp->session_id);

		trace_session(sp);
	
		count++;
	}
	trace("NUMBER OF SESSIONS: %d\n", count);
	trace("\n");
}


/************************************************************************/

static void trace_session(Session *session)
{
	Request *request;


	trace("\taddress:        %s\n",
		address_string(&(session->address)));
	if(trace_level > 2)
	{
		trace("\tn_variables:    %d\n", session->n_variables);
		trace("\to_flags:        0x%x\n", session->o_flags);
		trace("\ti_flags:        0x%x\n", session->i_flags);
	}
	for(request = session->first_request; request; request = request->next_request)
	{
		trace_request(request);
	}
}


/************************************************************************/

static void trace_request(Request *request)
{
	Session *session = request->session;
	Subtree *subtree = request->subtree;
	Agent *agent = NULL;
	SNMP_variable *variable;


	if(subtree)
	{
		agent = subtree->agent;
	}

	trace("\trequest %d:\n", request->request_id);
	if(trace_level > 2)
	{
		trace("\t\tsession:     %d\n", session->session_id);
	}
	trace("\t\tsubtree:     %s\n", (subtree)? SSAOidString(&(subtree->name)): "NULL");
	trace("\t\tvisited agents:\n");
	if(trace_level > 2)
	{
		Agent_List *alp;


		for(alp = request->visited_agent_list; alp; alp = alp->next)
		{
			trace("\t\t\t%s\n", alp->agent->name);
		}
	}
	if(agent)
	{
		trace("\t\tagent:       %s (%s)\n",
			agent->name,
			address_string(&(agent->address)));
	}
	else
	{
		trace("\t\tagent:       %s\n", "NULL");
	}
	if(trace_level > 2)
	{
		trace("\t\tflags:       0x%x\n", request->flags);
	}
	trace("\t\tstate:       %d\n", request->state);
	trace("\t\tvariables:\n");
	for(variable = request->pdu->first_variable; variable; variable = variable->next_variable)
	{
		trace("\t\t\t%s\n", SSAOidString(&(variable->name)));
	}

	if(trace_level > 3)
	{
		trace("\t\ttime:        %s\n", timeval_string(&request->time));
		trace("\t\texpire:      %s\n", timeval_string(&request->expire));
	}
}


/************************************************************************/

/* Three Phase: check for whether multiple agents are involved */
int three_phase_protocol_in_action(SNMP_pdu *pdu)
{
  SNMP_variable *variable;
  int local_access=0;
  int subagent_access=0;
  Subtree* subtree;
  Agent *agent, *prev_agent=NULL;
  
  if( pdu->type != SET_REQ_MSG) return(FALSE);

  for(variable=pdu->first_variable;variable;variable=variable->next_variable){
	subtree=subtree_match(pdu->type,&(variable->name));
	if(subtree != NULL){
		if( (agent=subtree->agent) != NULL){
			if(prev_agent == NULL){
				prev_agent = agent; 
			}else if(prev_agent != agent){
				return(TRUE);
			}
		}
	}
  }
  return(FALSE);
}

int any_outstanding_session()
{
  return(first_session!=NULL ? TRUE: FALSE);
}

int anyOutstandingSetRequestRunning()
{
  Session *s;
  for(s=first_session;s;s=s->next_session){
	if(s->pdu && s->pdu->type == SET_REQ_MSG) return(TRUE);
  }
  return(FALSE);
}


void session_dispatch()
{
	SNMP_pdu *pdu;
	Address address;
	Session *session;
	SNMP_variable *variable;
	static int VersionWarnings = 10 ; 

	pdu = snmp_pdu_receive(clients_sd, &address, error_label);
	if(pdu == NULL)
	{

	  /* To avoid flooding the console and log,  print trace "wrong version" messages */
	  /* after 10 console messages. */
		if (strncmp (error_label, "The message has a wrong version", 31) == 0 && --VersionWarnings >= 0 ) { 
			error(ERR_MSG_PDU_RECEIVED,
				address_string(&address),
				error_label);
		} else {
			trace(ERR_MSG_PDU_RECEIVED,
                                address_string(&address),
                                error_label);
		}
		return;
	}
	if(pdu->type != GET_REQ_MSG
		&& pdu->type != GETNEXT_REQ_MSG
		&& pdu->type != SET_REQ_MSG)
	{
		error("bad PDU type (0x%x) received from %s",
			pdu->type,
			address_string(&address));
		snmp_pdu_free(pdu);
		return;
	}
	if(pdu->first_variable == NULL)
	{
		error("no variable in PDU received from %s",
			address_string(&address));
		snmp_pdu_free(pdu);
		return;
	}


	session = session_find(&address, pdu->request_id);
	if(session)
	{
		if(trace_level > 0)
		{
			trace("!! This request is already being processed by session %d\n\n",
				session->session_id);
		}
		snmp_pdu_free(pdu);
		return;
	}


	/* Three Phase: if the request across multi-subagents
         * create the Three Phase object, pass the pdu from the
         * session->three_phase->cur_pdu
	 */
	if(three_phase_protocol_in_action(pdu)){	
		three_phase.origin_pdu = pdu;
		/* create a corresponding get pdu */
		three_phase.cur_pdu =  snmp_pdu_dup(pdu, error_label);
		if(three_phase.cur_pdu == NULL)
		{
		  error("snmp_pdu_dup() failed: %s",error_label);
		  snmp_pdu_free(pdu);
		  three_phase.origin_pdu = NULL;
		  return;
		}
		three_phase.cur_pdu->type = GET_REQ_MSG;
		/* form a get variable list.
		 * append to the cur_pdu */
	 	for(variable=pdu->first_variable;variable;
		    variable=variable->next_variable){
		  if(snmp_pdu_append_null_variable(three_phase.cur_pdu,
			&(variable->name),error_label) == NULL){
			error("snmp_pdu_append_null_variable() failed: %s",
				error_label);
			snmp_pdu_free(pdu);
		  }
		}
		pdu = three_phase.cur_pdu;
		three_phase.state = PHASE_1;
	}

	session = session_open(&address, pdu);
	if(session == NULL)
	{
		if(session_internal_error == TRUE)
		{
			error("session_open() failed for a pdu received from %s",
				address_string(&address));
		}
		return;
	}


	if(session->i_flags == session->o_flags)
	{
		session_respond(session);
	}


	return;
}

/****** (5-14-96) ****/
int local_agent(Agent *agent)
{
  return(!strcmp(agent->name,relay_agent_name)? 1 : 0);
}

int local_request(Request* request)
{
  Agent* agent;

  if(request && request->subtree){
        agent = request->subtree->agent;
        return( local_agent(agent));
  }
  return(FALSE); /* NOT LOCAL */
}


/************************************************************************/

/*
 *	If this function returns NULL and session_internal_error is
 *	TRUE, an internal error occured.
 *
 *	But if we succeed to answer the SNMP request before the
 *	end of this function, it returns NULL and session_errno
 *	is FALSE.
 *
 *
 *	The pdu must have at least one variable in
 *	its variable list. (This has to be checked before calling
 *	this function)
 *
 *	As the pdu is attached in a session structure,
 *	you must not free the pdu when this function
 *	returns whether the function succeeds or fails.
 */

static Session *session_open(Address *address, SNMP_pdu *pdu)
{
	Session *session;
	SNMP_variable *variable;
	Request *request;
	static Subid ent_subids[] = {1, 3, 6, 1, 4, 1, 42, 2, 1, 1};
	static Oid ent_oid = {ent_subids, 10};
	struct tms buffer;
        u_long time_stamp;




	if(trace_level > 1)
	{
		trace("## Open session %d\n\n", session_id);
	}


	session = (Session *) malloc(sizeof(Session));
	if(session == NULL)
	{
		error("malloc() failed");
		session_internal_error = TRUE;
		return NULL;
	}
	session->next_session = NULL;
	session->pdu = NULL;
	session->first_request = NULL;


	/* session_id */
	session->session_id = session_id;
	session_id = session_id + SESSION_ID_INCREMENT_VALUE;

	/* address */
	memcpy(&(session->address), address, sizeof(Address));

	/* pdu, n_variables, o_falgs, i_flags */
	session->pdu = pdu;
	session->n_variables = 0;
	session->o_flags = 0;
	session->i_flags = 0;


	/* insert session in the session list */
	session->next_session = first_session;
	first_session = session;


	/* build the requests list */
	for(variable = pdu->first_variable; variable; variable = variable->next_variable)
	{
		Subtree *subtree;


		(session->n_variables)++;

		if(session->n_variables > 32)
		{
			error(ERR_MSG_VARBIND_LIMIT);
			session_close(session);
			session_internal_error = TRUE;
			return NULL;
		}

		if( (
			( (pdu->type == GETNEXT_REQ_MSG) && (SSAOidCmp(&(variable->name), &sysUptime_name) == 0) )
				|| 
			( (pdu->type == GET_REQ_MSG) && (SSAOidCmp(&(variable->name), &sysUptime_instance) == 0) ) )
			&&
			(subtree_match(GET_REQ_MSG, &(variable->name)) == NULL) )
		{
			if(session_build_local_sysUptime(session, session->n_variables, variable) == -1)
			{
				error("session_build_local_sysUptime() failed");
				session_close(session);
				session_internal_error = TRUE;
				return NULL;
			}
		}
		else
		{
			subtree = subtree_match(pdu->type, &(variable->name));
			if(subtree == NULL)
			{
				/* session_respond_error() closes the session */
				session_respond_error(session, SNMP_ERR_NOSUCHNAME, session->n_variables);
				session_internal_error = FALSE;
				return NULL;
			}

			if (subtree->agent)
				set_first_manager (subtree->agent->first_manager);
			else
				set_first_manager (NULL);
			if (community_check(address, subtree->agent, pdu->type,
				 pdu->community) == FALSE) {
				    session_respond_error(session,
				    SNMP_ERR_AUTHORIZATIONERROR,
				    session->n_variables);
                                /* send authentication trap after error response */
                                time_stamp = (Integer) times(&buffer);
                                trap_filter_action(&ent_oid,SNMP_TRAP_AUTHFAIL,0,time_stamp,NULL);

/*
				session_close(session);
*/
				session_internal_error = TRUE;
				return NULL;
			}
			if(session_build_request_list(session, session->n_variables, variable, subtree) == -1)
			{
				error("session_build_request_list() failed");
				session_close(session);
				session_internal_error = TRUE;
				return NULL;
			}
		}
	}


	if(trace_level > 1)
	{
		trace_session(session);
		trace("\n");
	}


	/* send the requests */
	for(request = session->first_request; request; request = request->next_request)
	{
		if(request->state == 0) /* request not sent/process yet */
		{
		  	if(local_request(request)){
			  if(session_send_loopback_request(request,FALSE) == -1){
				error("session_send_loopback_request() failed");
				session_close(session);
				session_internal_error = TRUE;
				return NULL;
			  }
			}else if(session_send_request(request) == -1)
			{
				error("session_send_request() failed");
				session_close(session);
				session_internal_error = TRUE;
				return NULL;
			}
		}
	}


	return session;
}


/************************************************************************/

static int session_build_local_sysUptime(Session *session, int index, SNMP_variable *variable)
{
	Request *last_request = NULL;
	Request *request;
	u_long request_id = 0;
	SNMP_value value;
	struct tms buffer;


	for(request = session->first_request; request; request = request->next_request)
	{
		request_id++;
		last_request = request;
	}


	request = (Request *) malloc(sizeof(Request));
	if(request == NULL)
	{
		error("malloc() failed");
		return -1;
	}
	memset(request, 0, sizeof(Request));

	request->session = session;
	request->subtree = NULL;

	request->request_id = request_id;

	request->pdu = snmp_pdu_dup(session->pdu, error_label);
	if(request->pdu == NULL)
	{
		error("snmp_pdu_dup() failed: %s", error_label);
		request_free(request);
		return -1;
	}
	request->pdu->request_id = session->session_id + request->request_id;

	request->pdu->first_variable = snmp_variable_dup(variable, error_label);
	if(request->pdu->first_variable == NULL)
	{
		error("snmp_variable_dup() failed: %s", error_label);
		request_free(request);
		return -1;
	}

	request->flags = (1 << (index - 1));
	
	request->state = 0;

	/* append this request to the request	*/
	/* list of the session			*/
	if(last_request)
	{
		last_request->next_request = request;
	}
	else
	{
		session->first_request = request;
	}

	request->flags =  (1 << (index - 1));


	/* now answer! */
	request->response = snmp_pdu_dup(session->pdu, error_label);
	if(request->response == NULL)
	{
		error("snmp_pdu_dup() failed: %s", error_label);
		return -1;
	}
	request->response->type = GET_RSP_MSG;
	request->response->request_id = session->session_id + request->request_id;

	value.v_integer = (Integer) times(&buffer);
	request->response->first_variable = snmp_typed_variable_new(&sysUptime_instance, TIMETICKS,
		&value, error_label);
	if(request->response->first_variable == NULL)
	{
		error("snmp_typed_variable_new() failed: %s", error_label);
		return -1;
	}

	session->o_flags = session->o_flags | request->flags;

	request->state = REQUEST_COMPLETED;
	session->i_flags = session->i_flags | request->flags;


	return 0;
}


/************************************************************************/

static int session_build_request_list(Session *session, int index, SNMP_variable *variable, Subtree *subtree)
{
	Request *last_request = NULL;
	Request *request;
	u_long request_id = 0;
	SNMP_variable *new_variable;


	if(mode == MODE_GROUP)
	{
		for(request = session->first_request; request; request = request->next_request)
		{
			if(request->subtree && request->subtree->agent == subtree->agent)
			{
				break;
			}

			request_id++;
			last_request = request;
		}
	}
	else	/* MODE_SPLIT */
	{
		for(request = session->first_request; request; request = request->next_request)
		{
			request_id++;
			last_request = request;
		}
	}


	if(request == NULL)
	{
		request = (Request *) malloc(sizeof(Request));
		if(request == NULL)
		{
			error("malloc() failed");
			return -1;
		}
		request->next_request = NULL;
		request->visited_agent_list = NULL;
		request->pdu = NULL;
		request->response = NULL;

		request->session = session;
		request->subtree = subtree;
		if(request_add_visited_agent(request, subtree->agent) == -1)
		{
			request_free(request);
			return -1;
		}

		request->request_id = request_id;

		request->pdu = snmp_pdu_dup(session->pdu, error_label);
		if(request->pdu == NULL)
		{
			error("snmp_pdu_dup() failed: %s", error_label);
			request_free(request);
			return -1;
		}

		request->flags = 0;
		request->state = 0;

		/* append this request to the request	*/
		/* list of the session			*/
		if(last_request)
		{
			last_request->next_request = request;
		}
		else
		{
			session->first_request = request;
		}
	}


	new_variable = snmp_variable_dup(variable, error_label);
	if(new_variable == NULL)
	{
		error("snmp_variable_dup() failed: %s", error_label);
		return -1;
	}

	request->flags = request->flags | (1 << (index - 1));
	

	/* append the new variable to the variable list of request->pdu */
	if(request->pdu->first_variable)
	{
		SNMP_variable *current_variable;
		SNMP_variable *last_variable;

	
		for(current_variable = request->pdu->first_variable; current_variable; current_variable = current_variable->next_variable)
		{
			last_variable = current_variable;
		}
		last_variable->next_variable = new_variable;
	}
	else
	{
		request->pdu->first_variable = new_variable;
	}


	return 0;
}


/************************************************************************/

void session_close(Session *session)
{
	Three_Phase *tp;

	if(trace_level > 1)
	{
		trace("## Close session %d\n\n", session->session_id);
	}

	/* remove it from the session list */
	session_remove_from_list(session);

	/* free the space allocated for the session */
	session_free(session);


	return;
}


/************************************************************************/

void session_list_delete()
{
	Session *sp = first_session;
	Session *next;


	while(sp)
	{
		next = sp->next_session;
	
		session_free(sp);

		sp = next;
	}

	first_session = NULL;
}


/************************************************************************/

void session_remove_from_list(Session *session)
{
	Session *sp;
	Session *osp;


	osp = NULL;
	for(sp = first_session; sp; sp = sp->next_session)
	{
		if(sp == session)
		{
			break;
		}

		osp = sp;
	}

	if(sp == NULL)
	{
		error("session_remove_from_list() : session (0x%x) not found", session);
		return;
	}

	if(osp == NULL)
	{
		first_session = sp->next_session;
	}
	else
	{
		osp->next_session = sp->next_session;
	}


	return;
}


/************************************************************************/

void session_free(Session *session)
{
	if(session == NULL)
	{
		return;
	}

	snmp_pdu_free(session->pdu);

	request_list_free(session->first_request);

	free(session);


	return;
}


/************************************************************************/

void request_list_free(Request *request_list)
{
	Request *next_request;


	while(request_list)
	{
		next_request = request_list->next_request;
		request_free(request_list);
		request_list = next_request;
	}
}


/************************************************************************/

/* This function will send a response and close the session	*/
/* It should be invoked when o_flags == i_flags			 */

static void session_respond(Session *session)
{
	SNMP_variable *first_variable = NULL;
	SNMP_variable *variable;
	SNMP_variable *last_variable;
	Request *request;
	int i;
	SNMP_pdu *response;
	Address address;

	/* Three Phase:
	 * If the session is the three_phase session, basing on the state
  	 * we will have different process:
	 * state is 1: if successful, store the variable list. close the
	 *		 current session. The free the cur_pdu's variable
	 *		 list, attach the variable list from get. 
	 *	 	 change cur_pdu->type=SET_REQ_MSG. create a 
	 *		 new session(session_open) for next state. the pdu 
	 *		 is origin_pdu. 
	 *		 state = PHASE_2;
	 * state is PHASE_2: if successful. follows thru. else close the
	 *		 current session. create a new session with the
	 *		 cur_pdu. wait for response.
	 *		 In addition, send error response to appl.
	 *		 state = PHASE_3;
	 * state is PHASE_3: 
	 *		drop the response.
 	 */

	for(request = session->first_request; request; request = request->next_request)
	{
		if(request->state != REQUEST_COMPLETED)
		{
			error("BUG: session_respond() : session %d - request %d: state is not COMPLETED",
				session->session_id,
				request->request_id);
		}
	}



	/* we will extract the variables from the request->reponse	*/
	/* variable list and append them to the variable list		*/
	/* pointed by first_variable					*/

	for(i = 0; i < session->n_variables; i++)
	{
		for(request = session->first_request; request; request = request->next_request)
		{
			if(request->flags & (1 << i))
			{
				break;
			}
		}

		if(request == NULL)
		{
			error("BUG: session_respond(): request is NULL");
		}

		if(request->response == NULL)
		{
			/* request timeout */
			if(request->subtree != NULL &&
			   request->subtree->agent !=NULL){
				/*request->subtree->agent->numOfFailRequest++*/;
			}

			/* session_respond_error() closes the session */
			session_respond_error(session, SNMP_ERR_NOSUCHNAME, i + 1);
			snmp_variable_list_free(first_variable);
			return;
		}

		if(request->response->error_status != SNMP_ERR_NOERROR)
		{
			int j;
			int index = 0;


			/* find the index in the variables list		*/
			/* of the variable we are currently dealing with*/
			for(j = 0; j <= i; j++)
			{
				if(request->flags & (1<< j))
				{
					index++;
				}
			}

			if(request->response->error_index == index)
			{
				/* session_respond_error() closes the session */
				session_respond_error(session, request->response->error_status, i + 1);
				snmp_variable_list_free(first_variable);
				return;
			}

			/*
			 * error index should not be zero for a non-zero
			 * error status
			 */
			if (request->response->error_index ==
				INVALID_ERROR_INDEX) {
				/* invalid error packet from  sub agent */
				error("session_respond(): the agent %s \
responded with zero error index, on error status : %d \n",
				request->subtree->agent->name,
				request->response->error_status);
				snmp_variable_list_free(first_variable);
				session_close(session);
				return;
			}
			/* we are no more interested in building the	*/
			/* variable list fist_variable			*/
			continue;
		}

		/* remove the first variable from the request->response */
		variable = request->response->first_variable;
		if(variable == NULL)
		{
			error("session_respond(): the agent %s responded with less variables than it was asked",
				request->subtree->agent->name);
			session_close(session);
			return;
		}
		request->response->first_variable = variable->next_variable;

		if(first_variable == NULL)
		{
			first_variable = variable;
			last_variable = variable;
		}
		else
		{
			last_variable->next_variable = variable;
			last_variable = variable;
		}
	} /* for */

	/* Three Phase: save the variable list */
	if(three_phase.state == PHASE_1){
		three_phase.variable = first_variable;
		memcpy(&address,&(session->address),sizeof(Address));
		session_close(session);
		three_phase.cur_pdu = NULL;
		three_phase.state = PHASE_2;
		session_open(&address,three_phase.origin_pdu);
		return;
	}else if(three_phase.state == PHASE_2){
		/* successful*/
		three_phase.state = 0;
		snmp_variable_list_free(three_phase.variable);
		three_phase.variable = NULL;	
		three_phase.origin_pdu = NULL;
		/* follows thru */
	}else if(three_phase.state == PHASE_3){
		/* drop the response */
		session_close(session);
		return;
	}

	response = snmp_pdu_dup(session->pdu, error_label);
	if(response == NULL)
	{
		error("snmp_pdu_dup() failed: %s", error_label);
		/* return ??? */
	}
	response->type = GET_RSP_MSG;
	response->first_variable = first_variable;
	
	if( (response->error_status != SNMP_ERR_NOERROR)
		&& (response->error_status != SNMP_ERR_NOSUCHNAME) )
	{
		error(ERR_MSG_SNMP_ERROR,
			error_status_string(response->error_status), response->error_index,
			address_string(&(session->address)));
	}

	if(snmp_pdu_send(clients_sd, &(session->address), response, error_label))
	{
		error(ERR_MSG_PDU_SEND_BACK,
			address_string(&(session->address)),
			error_label);
		snmp_pdu_free(response);
		session_close(session);
		return;
	}
	snmp_pdu_free(response);
	session_close(session);


	return;
}


/************************************************************************/

/*
 *	This function sends a error response and closes the session
 */

static void session_respond_error(Session *session, int status, int index)
{
	SNMP_pdu *pdu = session->pdu;
	Address address;

	/* Three Phase: if errors occurs with three phase undertaking. 
	 * change the pdu to the three_phase->origin_pdu
	 */
	if(three_phase.state == PHASE_1){
		/* clean up three_phase */
		session->pdu = three_phase.origin_pdu;
		pdu = session->pdu;
		snmp_pdu_free(three_phase.cur_pdu);
		three_phase.cur_pdu = NULL;
		three_phase.origin_pdu = NULL;
		three_phase.state = 0;
	}else if(three_phase.state == PHASE_2){
		/* set fail, the session->pdu pts to origin_pdu */
		three_phase.state = PHASE_3;
		/* rollback */
		memcpy(&address,&(session->address),sizeof(Address));
		three_phase.cur_pdu = snmp_pdu_dup(three_phase.origin_pdu,
					error_label);
		three_phase.origin_pdu = NULL;
		if(three_phase.cur_pdu != NULL){
			three_phase.cur_pdu->first_variable = 
			  three_phase.variable;
			session_open(&address,three_phase.cur_pdu);
			three_phase.cur_pdu = NULL;
		}
	}else if(three_phase.state == PHASE_3){
		/* drop the packet */
		three_phase.state = 0;
		session_close(session);
		return;
	}

	pdu->type = GET_RSP_MSG;
	pdu->error_status = status;
	pdu->error_index = index;

	if (pdu->error_status == SNMP_ERR_AUTHORIZATIONERROR) {
		session_close(session);
		return;
	}

	if( (pdu->error_status != SNMP_ERR_NOERROR)
		&& (pdu->error_status != SNMP_ERR_NOSUCHNAME) )
	{
		error(ERR_MSG_SNMP_ERROR,
			error_status_string(pdu->error_status), pdu->error_index,
			address_string(&(session->address)));
	}

	if(snmp_pdu_send(clients_sd, &(session->address), pdu, error_label))
	{
		error(ERR_MSG_PDU_SEND_BACK,
			address_string(&(session->address)),
			error_label);
		session_close(session);
		return;
	}
	session_close(session);

	return;
}


/************************************************************************/

static Session *session_find(Address *address, u_long request_id)
{
	Session *session;


	for(session = first_session; session; session = session->next_session)
	{
		if( (session->pdu->request_id == request_id)
			&& (session->address.sin_port == address->sin_port)
			&& (session->address.sin_addr.s_addr == address->sin_addr.s_addr) )
		{
			return session;
		}
	}


	return NULL;
}

/* (5-14-96) */
static int session_send_loopback_request(Request *request,int doRespondHere)
{
	Session *session = request->session;
	SNMP_pdu *pdu;
	Subtree *subtree = request->subtree;
	Agent *agent;
	struct timeval tv;
	SNMP_variable *new_variable, *variable;

	gettimeofday(&tv, (struct timezone *) 0);

	if(subtree == NULL || request->pdu == NULL)
	{
		error("BUG: session_send_loopback_request(): subtree is NULL");
		return -1;
	}
	agent = subtree->agent;


	request->time = tv;
	tv.tv_usec = tv.tv_usec + agent->timeout;
	tv.tv_sec = tv.tv_sec + tv.tv_usec / 1000000L;
	tv.tv_usec = tv.tv_usec % 1000000L;
	request->expire = tv;

	session->o_flags = session->o_flags | request->flags;
	request->state = REQUEST_STARTED;
	/* duplicate the pdu */
	pdu = snmp_pdu_dup(request->pdu, error_label);
	pdu->request_id = session->session_id + request->request_id;
        
	for(variable = request->pdu->first_variable; variable; 
	    variable = variable->next_variable)
        {
		new_variable = snmp_variable_dup(variable, error_label);
		if(pdu->first_variable)
		{
			SNMP_variable *current_variable;
			SNMP_variable *last_variable;

			for(current_variable = pdu->first_variable; 
			    current_variable; 
			    current_variable = current_variable->next_variable)
			{
				last_variable = current_variable;
			}
			last_variable->next_variable = new_variable;
		}
		else
		{
			pdu->first_variable = new_variable;
		}
	}

	if (agent_process(&(session->address), pdu) == -1) {
		if (trace_level > 1) {
			trace("local pdu process error \n");
		}
		snmp_pdu_free(pdu);
		return (-1);
	}
	/* pdu stores the response */
   	session_process_response(pdu,doRespondHere);
	
  	return 1;
}

/************************************************************************/

static int session_send_request(Request *request)
{
	Session *session = request->session;
	SNMP_pdu *pdu = request->pdu;
	Subtree *subtree = request->subtree;
	Agent *agent;
	struct timeval tv;


	pdu->request_id = session->session_id + request->request_id;
	gettimeofday(&tv, (struct timezone *) 0);

	if(subtree == NULL)
	{
		error("BUG: session_send_request(): subtree is NULL");
		return -1;
	}
	agent = subtree->agent;

	if(snmp_pdu_send(agents_sd, &(agent->address), pdu, error_label))
	{ 
		error(ERR_MSG_PDU_SEND_TO,
			address_string(&(agent->address)),
			error_label);
		return -1;
	}

	request->time = tv;
	tv.tv_usec = tv.tv_usec + agent->timeout;
	tv.tv_sec = tv.tv_sec + tv.tv_usec / 1000000L;
	tv.tv_usec = tv.tv_usec % 1000000L;
	request->expire = tv;

	session->o_flags = session->o_flags | request->flags;
	request->state = REQUEST_STARTED;


	return 0;
}


/************************************************************************/

static Request *session_move_request(Request *request, Subtree *subtree)
{
	Session *session = request->session;


	if(trace_level > 0)
	{
		trace("!! session %d - request %d: trying another subtree %s supported by %s\n\n",
			session->session_id,
			request->request_id,
			SSAOidString(&(subtree->name)),
			subtree->agent->name);
	}

	request->subtree = subtree;
	
	if (subtree->agent->first_manager != NULL)
		set_first_manager(subtree->agent->first_manager);
	
	if(request_add_visited_agent(request, subtree->agent) == -1)
	{
		error("request_add_visited_agent() failed");
		return NULL;
	}

	if (local_request(request)) {
		if (session_send_loopback_request(request, TRUE) == -1) {
			if (trace_level > 1) {
				trace("session_send_loopback_request() \
failed\n");
			}
			return (NULL);
		}
	} else if(session_send_request(request) == -1) {
		error("session_send_request() failed");
		return NULL;
	}

	return request;
}


/************************************************************************/

void request_free(Request *request)
{
	if(request == NULL)
	{
		return;
	}

	agent_list_free(request->visited_agent_list);

	snmp_pdu_free(request->pdu);

	snmp_pdu_free(request->response);

	free(request);

	return;
}

void trap_processing()
{
	Address address;
	SNMP_pdu *trap_request;
	struct tms buffer;
	u_long time_stamp;

	trap_request = snmp_pdu_receive(trap_sd, &address, error_label);
	if(trap_request == NULL)
	{
		error(ERR_MSG_PDU_RECEIVED,
			address_string(&address),
			error_label);
		return;
	}


	if(trap_request->type != TRP_REQ_MSG)
	{
		error("bad PDU type (0x%x) received from %s",
			trap_request->type,
			address_string(&address));
		snmp_pdu_free(trap_request);
		return;
	}

	/* filter the trap_request */
	/* currently, base on the trap-community names to decide which
	   are the list of target hosts */
	time_stamp = (Integer) times(&buffer);

	/* propagate those traps registered by managers */
	trap_filter_action(&(trap_request->enterprise),
	  trap_request->generic,trap_request->specific,time_stamp,
	  trap_request->first_variable);

	snmp_pdu_free(trap_request);
	return;
}


static Subtree *forward_subtree_match(Subtree *subtree, Oid *name)
{
	Subtree *sp;
	Subtree *last=NULL;
	Subtree *first_valid_subtree;


	if(name == NULL || subtree == NULL || first_subtree == NULL)
	{
		return NULL;
	}

	for(sp = subtree->next_subtree; sp; sp = sp->next_subtree)
	{
	 	/* subtree is invalid skip (vsb)*/
		if(subtree_is_valid(sp)==FALSE) continue;

		if(SSAOidCmp(name, &(sp->name)) >= 0  &&
		   sp->agent !=0 && subtree->agent !=0 &&
		   sp->agent != subtree->agent)
		{
			return sp;
		}

	}


	return last;
}

/************************************************************************/
/* (5-14-96) partition into two functions */
/* pdu_read is not null, this routine is used for local response
   there is a catch the session_respond is skipped, because, it will
   be processed later in the session_open call */

static void session_process_response(SNMP_pdu *pdu_read,int doRespondHere)
{
	Address address;
	SNMP_pdu *response;
	Session *session;
	SNMP_pdu *pdu;
	Subtree *subtree;
	Subtree *sub;
	Request *request;


	if(pdu_read == NULL)
	  response = snmp_pdu_receive(agents_sd, &address, error_label);
	else
	  response = pdu_read;	
	
	if(response == NULL)
	{
		error(ERR_MSG_PDU_RECEIVED,
			address_string(&address),
			error_label);
		return;
	}


	if(response->type != GET_RSP_MSG)
	{
		error("bad PDU type (0x%x) received from %s",
			response->type,
			address_string(&address));
		snmp_pdu_free(response);
		return;
	}


	for(session = first_session; session; session = session->next_session)
	{
		if((response->request_id & SESSION_ID_MASK) == session->session_id)
		{
			break;
		}
	}
	if(session == NULL)
	{
		Agent *agent;


		agent = agent_find(&address);
/*
		error(ERR_MSG_UNKNOWN_FRAGMENT,
			agent? agent->name: "???",
			address_string(&address));
*/
		snmp_pdu_free(response);
		return;
	}


	for(request = session->first_request; request; request = request->next_request)
	{
		if((response->request_id & REQUEST_ID_MASK) == request->request_id)
		{
			break;
		}
	}
	if(request == NULL)
	{
		error("request not found for the session %d for a PDU received from %s",
			session->session_id,
			address_string(&address));
		snmp_pdu_free(response);
		return;
	}
	if(request->state == REQUEST_COMPLETED)
	{
		error("a PDU has been received from %s for session %d - request %d whereas the request is already completed",
			address_string(&address),
			session->session_id,
			request->request_id);
		snmp_pdu_free(response);
		return;
	}
	if(request->response)
	{
		error("BUG: session_read(): response is not NULL");
	}


	pdu = session->pdu;
	subtree = request->subtree;
	if(subtree == NULL)
	{
		error("BUG: session_read(): subtree is NULL");
		snmp_pdu_free(response);
		return;
	}

	if (subtree->agent->numOfFailRequest > 0)
		trace("Agent %s is now OK", subtree->agent->name) ; 
        subtree->agent->numOfFailRequest=0;

	if(pdu->type == GETNEXT_REQ_MSG)
	{
		if( (response->error_status == SNMP_ERR_NOSUCHNAME)
			&& (response->error_index == 1)
			&& (response->first_variable != NULL) )
		{
			if(trace_level > 0)
			{
				trace("!! session %d - request %d: the Get-Next returned No Such Name\n\n",
					session->session_id,
					request->request_id);
			}

			/* Check if another agent supports some */
			/* variables greater than the first one */
			/* of the PDU				*/

			for(sub = subtree->next_subtree; sub; sub = sub->next_subtree)
			{
				/* skip invalid subtree (vsb) */
				if(subtree_is_valid(sub)==FALSE) continue;
				if(!is_in_agent_list(request->visited_agent_list, sub->agent))
				{
					session_move_request(request, sub);
					snmp_pdu_free(response);
					return;
				}
			}
		}
		else
		if( (response->first_variable != NULL)
/*&& ((sub = forward_subtree_match(subtree, &(response->first_variable->name))) != NULL)*/

&& ((sub = subtree_match(GET_REQ_MSG, &(response->first_variable->name))) != NULL)

			&& (sub != subtree) 
&& (SSAOidCmp(&(subtree->name),&(sub->name)) < 0)
/*
&&(sub->agent!=NULL && subtree->agent!=NULL && sub->agent!=subtree->agent)
*/
)
		{
			/* we are in another subtree */

			Subtree *s;


			if(trace_level > 0)
			{	
				trace("!! session %d - request %d: the Get-Next issued in the subtree %s supported by %s",
					session->session_id,
					request->request_id,
					SSAOidString(&(subtree->name)),
					subtree->agent->name);
				trace(" returned a response in the subtree %s supported by %s\n\n",
					SSAOidString(&(sub->name)),
					sub->agent->name);
			}


			/* Is there a subtree supported by another agent between */
			/* subtree and sub ? */

/* 12-19-96 snmpgetnext 
			for(s = subtree->next_subtree; s; s = s->next_subtree)
			{
				if(subtree_is_valid(s)==FALSE) continue;
				if(s == sub)
				{
					break;
				}
*/
		s = sub;

				if(subtree->agent !=  s->agent)
				{
					/* There is a subtree supported by another agent */
					/* between subtree and sub */
					
					session_move_request(request, s);
					snmp_pdu_free(response);
					return;
				}
/*
			}
*/
		}
	}


	/* we consider response a valid response for the request request */
	if(request->response)
	{
		error("BUG: session_read(): request->response is not NULL");
	}
	request->response = response;
	request->state = REQUEST_COMPLETED;
	session->i_flags = session->i_flags | request->flags;


	if(doRespondHere && session->i_flags == session->o_flags)
	{
		session_respond(session);
	}

	return;
}

void session_read()
{
   session_process_response(NULL,TRUE);

}

/************************************************************************/

void session_select_info(struct timeval *timeout)
{
	Session *sp;
	Request *rp;
	struct timeval now, earliest;


	if(first_session == NULL)
	{
		return;
	}

	/* For each request in each session, if it is the	*/
	/* earliest timeout to expire, mark it as lowest.	*/

	timerclear(&earliest);
	for(sp = first_session; sp; sp = sp->next_session)
	{
		for(rp = sp->first_request; rp; rp = rp->next_request)
		{
			if(rp->state == REQUEST_COMPLETED)
			{
				continue;
			}

			if(!timerisset(&earliest) || timercmp(&rp->expire, &earliest, <))
			{
				earliest = rp->expire;
			}
		}
	}


	/* Now find out how much time until the earliest timeout.  This		*/
	/* transforms earliest from an absolute time into a delta time, the	*/
	/* time left until the select should timeout.				*/

	gettimeofday(&now, (struct timezone *)0);
	earliest.tv_sec--;	/* adjust time to make arithmetic easier */
	earliest.tv_usec += 1000000L;
	earliest.tv_sec -= now.tv_sec;
	earliest.tv_usec -= now.tv_usec;
	while (earliest.tv_usec >= 1000000L)
	{
		earliest.tv_usec -= 1000000L;
		earliest.tv_sec += 1;
	}
	if(earliest.tv_sec < 0)
	{
		earliest.tv_sec = 0;
		earliest.tv_usec = 0;
	}

	/* if our delta time is less, reset timeout */
	if(timercmp(&earliest, timeout, <))
	{
		*timeout = earliest;
	}


	return;
}


/************************************************************************/

void session_timeout()
{
	struct timeval now;


	gettimeofday(&now, (struct timezone *)0);

	while(session_timeout_loop(&now) == 1);
	destroy_hanging_agent(); /* destroy one agent at a time */

}


/************************************************************************/

int max_requests = 1000;

static int session_timeout_loop(struct timeval *now)
{
	Session *sp;
	Request *rp;
	int nrequests = 0;


	/* For each session outstanding, check to see if the timeout has expired. */

	for(sp = first_session; sp; sp = sp->next_session)
	{


		for(rp = sp->first_request; rp; rp = rp->next_request)
		{
			nrequests ++;

			if(rp->state == REQUEST_COMPLETED)
			{
				continue;
			}

			if(timercmp(&rp->expire, now, <) || nrequests > max_requests)
			{
				Subtree *subtree = rp->subtree;


				if(subtree == NULL)
				{
					error("BUG: session_timeout_loop(): subtree is NULL");
					/* session_respond_error() closes the session */
					session_respond_error(sp, SNMP_ERR_GENERR, 1);
					return 1;
				}

				if (subtree->agent->numOfFailRequest == 0 )
					trace(ERR_MSG_AGENT_NOT_RESPONDING, subtree->agent->name);
                                subtree->agent->numOfFailRequest++;

				/* this timer has expired */
				if(trace_level > 0)
				{
					trace("!! session %d - request %d: timeout\n\n",
						sp->session_id,
						rp->request_id);
				}

				if(sp->pdu->type == GETNEXT_REQ_MSG)
				{
					/* Check if there is a subtree supported	*/
					/* by another agent after subtree		*/

					Subtree *sub;


					for(sub = subtree->next_subtree; sub; sub = sub->next_subtree)
					{
						if(!is_in_agent_list(rp->visited_agent_list, sub->agent))
						{	
							session_move_request(rp, sub);
							return 1;
						}
					}
				}


				/* No Such Name */
			
				sp->i_flags = sp->i_flags | rp->flags;
				rp->state = REQUEST_COMPLETED;

				if(sp->i_flags == sp->o_flags)
				{
					session_respond(sp);
					return 1;
				}
			}
		}
	}

	return 0;
}


/************************************************************************/

static int request_add_visited_agent(Request *request, Agent *agent)
{
	Agent_List *new;


	if(request == NULL)
	{
		error("BUG: request_add_visited_agent(): request is NULL");
		return -1;
	}

	if(agent == NULL)
	{
		error("BUG: request_add_visited_agent(): agent is NULL");
		return -1;
	}

	new = (Agent_List *) malloc(sizeof(Agent_List));
	if(new == NULL)
	{
		error("malloc() failed");
		return -1;
	}
	new->next = request->visited_agent_list;
	request->visited_agent_list = new;
	new->agent = agent;


	return 0;
}


/************************************************************************/

static void agent_list_free(Agent_List *alp)
{
	Agent_List *next;


	while(alp)
	{
		next = alp->next;
		free(alp);
		alp = next;
	}
}


/************************************************************************/

static int is_in_agent_list(Agent_List *agent_list, Agent *agent)
{
	Agent_List *alp;


	for(alp = agent_list; alp; alp = alp->next)
	{
		if(alp->agent == agent)
		{
			return True;
		}
	}

	return False;
}

int no_outstanding_session_for_the_agent(Agent* ap)
{
  Session *sp;
  Request *rp;

  for(sp = first_session; sp; sp = sp->next_session){
	for(rp = sp->first_request; rp; rp = rp->next_request){
	  if(rp->subtree && rp->subtree->agent==ap)
		return 0;
	}
  }
  
  return 1;
}


static int community_check (Address * address, Agent * agent, int pdu_type, char * community)
{
	Manager *mgr;
	int ret;


	if (agent == NULL) {
		return TRUE;
	}
	if (agent->first_manager == NULL) {
		return TRUE;
	}
	/* check host */
	
	mgr = is_valid_manager(address, &mgr);

	if(mgr == NULL)
	{
                error("community_check(): unauthorized manager (%s)",
                	ip_address_string(&(address->sin_addr)));
                return FALSE;
        }

	if (is_valid_community(community, pdu_type, mgr))
                return TRUE;
	else {
        	error("community_check() : bad community from %s",
               	ip_address_string(&(address->sin_addr)));
		return FALSE;
	}
}
