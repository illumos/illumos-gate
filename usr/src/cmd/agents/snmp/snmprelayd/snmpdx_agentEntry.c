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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <netinet/in.h>

#include "impl.h"
#include "asn1.h"
#include "error.h"
#include "snmp.h"
#include "trap.h"
#include "pdu.h"
#include "node.h"

#include "snmpdx_stub.h"



/***** agentEntry           ********************************/

extern int get_agentEntry(int search_type, AgentEntry_t **agentEntry_data, IndexType *index)
{

	int res;

	*agentEntry_data = (AgentEntry_t*)calloc(1,sizeof(AgentEntry_t));
	if(agentEntry_data == NULL) return SNMP_ERR_GENERR;

	res = get_agentID(
	        search_type,
	        &((*agentEntry_data)->agentID),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_agentStatus(
	        search_type,
	        &((*agentEntry_data)->agentStatus),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_agentTimeOut(
	        search_type,
	        &((*agentEntry_data)->agentTimeOut),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_agentPortNumber(
	        search_type,
	        &((*agentEntry_data)->agentPortNumber),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_agentPersonalFile(
	        search_type,
	        &((*agentEntry_data)->agentPersonalFile),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_agentConfigFile(
	        search_type,
	        &((*agentEntry_data)->agentConfigFile),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_agentExecutable(
	        search_type,
	        &((*agentEntry_data)->agentExecutable),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_agentVersionNum(
	        search_type,
	        &((*agentEntry_data)->agentVersionNum),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_agentProcessID(
	        search_type,
	        &((*agentEntry_data)->agentProcessID),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_agentName(
	        search_type,
	        &((*agentEntry_data)->agentName),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_agentSystemUpTime(
	        search_type,
	        &((*agentEntry_data)->agentSystemUpTime),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_agentWatchDogTime(
	        search_type,
	        &((*agentEntry_data)->agentWatchDogTime),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	 return res;
}


void free_agentEntry(AgentEntry_t *agentEntry)
{
	free_agentPersonalFile(&(agentEntry->agentPersonalFile));
	free_agentConfigFile(&(agentEntry->agentConfigFile));
	free_agentExecutable(&(agentEntry->agentExecutable));
	free_agentVersionNum(&(agentEntry->agentVersionNum));
	free_agentName(&(agentEntry->agentName));
}

int get_agentID(int search_type, Integer *agentID, IndexType *index)
{
	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/*assume that the mib variable has a value of 1 */

	*agentID = 1;
	return SNMP_ERR_NOERROR;
}

int get_agentStatus(int search_type, Integer *agentStatus, IndexType *index)
{
	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/*assume that the mib variable has a value of 1 */

	*agentStatus = 1;
	return SNMP_ERR_NOERROR;
}

int set_agentStatus(int pass, IndexType index, Integer *agentStatus)
{
	switch(pass)
	{
		case FIRST_PASS:

			/* check the existence of the element which */
			/* corresponding to the given index and */
			/* check the validity fo the input value */
			/* if not valid or not exist, */

			return SNMP_ERR_GENERR;

		case SECOND_PASS:

			/* change the following coding, such that */
			/* the input value will be stored in the */
			/* corresponding mib variable of the given */
			/* index */
			printf("The new value is %d\n",agentStatus);
			return SNMP_ERR_NOERROR;
	}
}


int get_agentTimeOut(int search_type, Integer *agentTimeOut, IndexType *index)
{
	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/*assume that the mib variable has a value of 1 */

	*agentTimeOut = 1;
	return SNMP_ERR_NOERROR;
}

int set_agentTimeOut(int pass, IndexType index, Integer *agentTimeOut)
{
	switch(pass)
	{
		case FIRST_PASS:

			/* check the existence of the element which */
			/* corresponding to the given index and */
			/* check the validity fo the input value */
			/* if not valid or not exist, */

			return SNMP_ERR_GENERR;

		case SECOND_PASS:

			/* change the following coding, such that */
			/* the input value will be stored in the */
			/* corresponding mib variable of the given */
			/* index */
			printf("The new value is %d\n",agentTimeOut);
			return SNMP_ERR_NOERROR;
	}
}


int get_agentPortNumber(int search_type, Integer *agentPortNumber, IndexType *index)
{
	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/*assume that the mib variable has a value of 1 */

	*agentPortNumber = 1;
	return SNMP_ERR_NOERROR;
}

int set_agentPortNumber(int pass, IndexType index, Integer *agentPortNumber)
{
	switch(pass)
	{
		case FIRST_PASS:

			/* check the existence of the element which */
			/* corresponding to the given index and */
			/* check the validity fo the input value */
			/* if not valid or not exist, */

			return SNMP_ERR_GENERR;

		case SECOND_PASS:

			/* change the following coding, such that */
			/* the input value will be stored in the */
			/* corresponding mib variable of the given */
			/* index */
			printf("The new value is %d\n",agentPortNumber);
			return SNMP_ERR_NOERROR;
	}
}


int get_agentPersonalFile(int search_type, String *agentPersonalFile, IndexType *index)
{
	u_char *str;
	int len;

	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/* It is required to allocate memory to the pointers */
	/* inside the input argument */
	/* Here, we assume that "hello" is the value of the mib variable */
	/* please change it to the real one */

	len = strlen("hello");
	str = (u_char*)calloc(len,sizeof(char));
	if(str==NULL){
		return SNMP_ERR_GENERR;
	}
	memcpy(str,"hello",len);

	/*fill in the contents of the argument */

	agentPersonalFile->chars = str;
	agentPersonalFile->len = len;
	return SNMP_ERR_NOERROR;
}

int set_agentPersonalFile(int pass, IndexType index, String *agentPersonalFile)
{
	char buf[100];

	switch(pass)
	{
		case FIRST_PASS:

			/* check the existence of the element which */
			/* corresponding to the given index and */
			/* check the validity fo the input value */
			/* if not valid or not exist, */

			return SNMP_ERR_GENERR;

		case SECOND_PASS:

			/* change the following coding, such that */
			/* the input value will be stored in the */
			/* corresponding mib variable of the given */
			/* index */
			memcpy(buf,agentPersonalFile->chars,agentPersonalFile->len);
			buf[agentPersonalFile->len+1] = '\0';
			printf("The new value is %s\n",buf);
			return SNMP_ERR_NOERROR;
	}
}


void free_agentPersonalFile(String *agentPersonalFile)
{
	 if(agentPersonalFile->chars!=NULL && agentPersonalFile->len !=0)
	{
		free(agentPersonalFile->chars);
		agentPersonalFile->len = 0;
	}
}

int get_agentConfigFile(int search_type, String *agentConfigFile, IndexType *index)
{
	u_char *str;
	int len;

	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/* It is required to allocate memory to the pointers */
	/* inside the input argument */
	/* Here, we assume that "hello" is the value of the mib variable */
	/* please change it to the real one */

	len = strlen("hello");
	str = (u_char*)calloc(len,sizeof(char));
	if(str==NULL){
		return SNMP_ERR_GENERR;
	}
	memcpy(str,"hello",len);

	/*fill in the contents of the argument */

	agentConfigFile->chars = str;
	agentConfigFile->len = len;
	return SNMP_ERR_NOERROR;
}

int set_agentConfigFile(int pass, IndexType index, String *agentConfigFile)
{
	char buf[100];

	switch(pass)
	{
		case FIRST_PASS:

			/* check the existence of the element which */
			/* corresponding to the given index and */
			/* check the validity fo the input value */
			/* if not valid or not exist, */

			return SNMP_ERR_GENERR;

		case SECOND_PASS:

			/* change the following coding, such that */
			/* the input value will be stored in the */
			/* corresponding mib variable of the given */
			/* index */
			memcpy(buf,agentConfigFile->chars,agentConfigFile->len);
			buf[agentConfigFile->len+1] = '\0';
			printf("The new value is %s\n",buf);
			return SNMP_ERR_NOERROR;
	}
}


void free_agentConfigFile(String *agentConfigFile)
{
	 if(agentConfigFile->chars!=NULL && agentConfigFile->len !=0)
	{
		free(agentConfigFile->chars);
		agentConfigFile->len = 0;
	}
}

int get_agentExecutable(int search_type, String *agentExecutable, IndexType *index)
{
	u_char *str;
	int len;

	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/* It is required to allocate memory to the pointers */
	/* inside the input argument */
	/* Here, we assume that "hello" is the value of the mib variable */
	/* please change it to the real one */

	len = strlen("hello");
	str = (u_char*)calloc(len,sizeof(char));
	if(str==NULL){
		return SNMP_ERR_GENERR;
	}
	memcpy(str,"hello",len);

	/*fill in the contents of the argument */

	agentExecutable->chars = str;
	agentExecutable->len = len;
	return SNMP_ERR_NOERROR;
}

int set_agentExecutable(int pass, IndexType index, String *agentExecutable)
{
	char buf[100];

	switch(pass)
	{
		case FIRST_PASS:

			/* check the existence of the element which */
			/* corresponding to the given index and */
			/* check the validity fo the input value */
			/* if not valid or not exist, */

			return SNMP_ERR_GENERR;

		case SECOND_PASS:

			/* change the following coding, such that */
			/* the input value will be stored in the */
			/* corresponding mib variable of the given */
			/* index */
			memcpy(buf,agentExecutable->chars,agentExecutable->len);
			buf[agentExecutable->len+1] = '\0';
			printf("The new value is %s\n",buf);
			return SNMP_ERR_NOERROR;
	}
}


void free_agentExecutable(String *agentExecutable)
{
	 if(agentExecutable->chars!=NULL && agentExecutable->len !=0)
	{
		free(agentExecutable->chars);
		agentExecutable->len = 0;
	}
}

int get_agentVersionNum(int search_type, String *agentVersionNum, IndexType *index)
{
	u_char *str;
	int len;

	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/* It is required to allocate memory to the pointers */
	/* inside the input argument */
	/* Here, we assume that "hello" is the value of the mib variable */
	/* please change it to the real one */

	len = strlen("hello");
	str = (u_char*)calloc(len,sizeof(char));
	if(str==NULL){
		return SNMP_ERR_GENERR;
	}
	memcpy(str,"hello",len);

	/*fill in the contents of the argument */

	agentVersionNum->chars = str;
	agentVersionNum->len = len;
	return SNMP_ERR_NOERROR;
}

int set_agentVersionNum(int pass, IndexType index, String *agentVersionNum)
{
	char buf[100];

	switch(pass)
	{
		case FIRST_PASS:

			/* check the existence of the element which */
			/* corresponding to the given index and */
			/* check the validity fo the input value */
			/* if not valid or not exist, */

			return SNMP_ERR_GENERR;

		case SECOND_PASS:

			/* change the following coding, such that */
			/* the input value will be stored in the */
			/* corresponding mib variable of the given */
			/* index */
			memcpy(buf,agentVersionNum->chars,agentVersionNum->len);
			buf[agentVersionNum->len+1] = '\0';
			printf("The new value is %s\n",buf);
			return SNMP_ERR_NOERROR;
	}
}


void free_agentVersionNum(String *agentVersionNum)
{
	 if(agentVersionNum->chars!=NULL && agentVersionNum->len !=0)
	{
		free(agentVersionNum->chars);
		agentVersionNum->len = 0;
	}
}

int get_agentProcessID(int search_type, Integer *agentProcessID, IndexType *index)
{
	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/*assume that the mib variable has a value of 1 */

	*agentProcessID = 1;
	return SNMP_ERR_NOERROR;
}

int set_agentProcessID(int pass, IndexType index, Integer *agentProcessID)
{
	switch(pass)
	{
		case FIRST_PASS:

			/* check the existence of the element which */
			/* corresponding to the given index and */
			/* check the validity fo the input value */
			/* if not valid or not exist, */

			return SNMP_ERR_GENERR;

		case SECOND_PASS:

			/* change the following coding, such that */
			/* the input value will be stored in the */
			/* corresponding mib variable of the given */
			/* index */
			printf("The new value is %d\n",agentProcessID);
			return SNMP_ERR_NOERROR;
	}
}


int get_agentName(int search_type, String *agentName, IndexType *index)
{
	u_char *str;
	int len;

	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/* It is required to allocate memory to the pointers */
	/* inside the input argument */
	/* Here, we assume that "hello" is the value of the mib variable */
	/* please change it to the real one */

	len = strlen("hello");
	str = (u_char*)calloc(len,sizeof(char));
	if(str==NULL){
		return SNMP_ERR_GENERR;
	}
	memcpy(str,"hello",len);

	/*fill in the contents of the argument */

	agentName->chars = str;
	agentName->len = len;
	return SNMP_ERR_NOERROR;
}

int set_agentName(int pass, IndexType index, String *agentName)
{
	char buf[100];

	switch(pass)
	{
		case FIRST_PASS:

			/* check the existence of the element which */
			/* corresponding to the given index and */
			/* check the validity fo the input value */
			/* if not valid or not exist, */

			return SNMP_ERR_GENERR;

		case SECOND_PASS:

			/* change the following coding, such that */
			/* the input value will be stored in the */
			/* corresponding mib variable of the given */
			/* index */
			memcpy(buf,agentName->chars,agentName->len);
			buf[agentName->len+1] = '\0';
			printf("The new value is %s\n",buf);
			return SNMP_ERR_NOERROR;
	}
}


void free_agentName(String *agentName)
{
	 if(agentName->chars!=NULL && agentName->len !=0)
	{
		free(agentName->chars);
		agentName->len = 0;
	}
}

int get_agentSystemUpTime(int search_type, Integer *agentSystemUpTime, IndexType *index)
{
	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/*assume that the mib variable has a value of 1 */

	*agentSystemUpTime = 1;
	return SNMP_ERR_NOERROR;
}

int set_agentSystemUpTime(int pass, IndexType index, Integer *agentSystemUpTime)
{
	switch(pass)
	{
		case FIRST_PASS:

			/* check the existence of the element which */
			/* corresponding to the given index and */
			/* check the validity fo the input value */
			/* if not valid or not exist, */

			return SNMP_ERR_GENERR;

		case SECOND_PASS:

			/* change the following coding, such that */
			/* the input value will be stored in the */
			/* corresponding mib variable of the given */
			/* index */
			printf("The new value is %d\n",agentSystemUpTime);
			return SNMP_ERR_NOERROR;
	}
}


int get_agentWatchDogTime(int search_type, Integer *agentWatchDogTime, IndexType *index)
{
	/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */
	/* this function should modify the index argument to the */
	/* appropriate value */
	switch(search_type)
	{
		case FIRST_ENTRY:
			if(index->type == INTEGER){

				/* assume 1 is the first index */

				index->value[0] = 1;
				index->len = 1;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[0] = 1;
				index->value[1]= 1;
				index->len = 2;
			}
			break;

		case NEXT_ENTRY:
			if(index->type == INTEGER){
				index->value[0]++;
			}else{

				/* index type will be array of integer */
				/* assume that there are two index */

				index->value[index->len-1]++;
			}
			break;

		case EXACT_ENTRY:
			break;
	}

	/*assume that the mib variable has a value of 1 */

	*agentWatchDogTime = 1;
	return SNMP_ERR_NOERROR;
}

int set_agentWatchDogTime(int pass, IndexType index, Integer *agentWatchDogTime)
{
	switch(pass)
	{
		case FIRST_PASS:

			/* check the existence of the element which */
			/* corresponding to the given index and */
			/* check the validity fo the input value */
			/* if not valid or not exist, */

			return SNMP_ERR_GENERR;

		case SECOND_PASS:

			/* change the following coding, such that */
			/* the input value will be stored in the */
			/* corresponding mib variable of the given */
			/* index */
			printf("The new value is %d\n",agentWatchDogTime);
			return SNMP_ERR_NOERROR;
	}
}

