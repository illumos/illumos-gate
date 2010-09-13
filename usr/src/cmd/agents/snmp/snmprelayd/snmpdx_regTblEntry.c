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



/***** regTblEntry          ********************************/

extern int get_regTblEntry(int search_type, RegTblEntry_t **regTblEntry_data, IndexType *index)
{

	int res;

	*regTblEntry_data = (RegTblEntry_t*)calloc(1,sizeof(RegTblEntry_t));
	if(regTblEntry_data == NULL) return SNMP_ERR_GENERR;

	res = get_regTblIndex(
	        search_type,
	        &((*regTblEntry_data)->regTblIndex),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_regTblAgentID(
	        search_type,
	        &((*regTblEntry_data)->regTblAgentID),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_regTblOID(
	        search_type,
	        &((*regTblEntry_data)->regTblOID),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_regTblStartColumn(
	        search_type,
	        &((*regTblEntry_data)->regTblStartColumn),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_regTblEndColumn(
	        search_type,
	        &((*regTblEntry_data)->regTblEndColumn),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_regTblStartRow(
	        search_type,
	        &((*regTblEntry_data)->regTblStartRow),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_regTblEndRow(
	        search_type,
	        &((*regTblEntry_data)->regTblEndRow),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	res = get_regTblStatus(
	        search_type,
	        &((*regTblEntry_data)->regTblStatus),
	        index);
	if(res != SNMP_ERR_NOERROR) return res;

	 return res;
}


void free_regTblEntry(RegTblEntry_t *regTblEntry)
{
	free_regTblOID(&(regTblEntry->regTblOID));
}

int get_regTblIndex(int search_type, Integer *regTblIndex, IndexType *index)
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

	*regTblIndex = 1;
	return SNMP_ERR_NOERROR;
}

int get_regTblAgentID(int search_type, Integer *regTblAgentID, IndexType *index)
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

	*regTblAgentID = 1;
	return SNMP_ERR_NOERROR;
}

int get_regTblOID(int search_type, Oid *regTblOID, IndexType *index)
{
	Subid *sub;
	Subid fake_sub[] = {1,3,6,1,4,1,4,42};
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
	/* Here, we assume that "1.3.6.1.4.1.42" is the value */
	/* of the mib variable */
	/* please change it to the real one */

	/* 1.3.6.1.4.1.42 has 7 number separated by "." */

	len =7 ;
	sub = (Subid*)calloc(len,sizeof(Subid));
	if(sub==NULL) return SNMP_ERR_GENERR;
	memcpy(sub,fake_sub,len*sizeof(Subid));

	/* fill in the contents of the argument */

	regTblOID->subids = sub;
	regTblOID->len = len;
	return SNMP_ERR_NOERROR;
}

int set_regTblOID(int pass, IndexType index, Oid *regTblOID)
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
			printf("The new value is %s\n",SSAOidString(regTblOID));
			return SNMP_ERR_NOERROR;
	}
}


void free_regTblOID(Oid *regTblOID)
{
	 if(regTblOID->subids!=NULL && regTblOID->len !=0)
	{
		free(regTblOID->subids);
		regTblOID->len = 0;
	}
}

int get_regTblStartColumn(int search_type, Integer *regTblStartColumn, IndexType *index)
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

	*regTblStartColumn = 1;
	return SNMP_ERR_NOERROR;
}

int set_regTblStartColumn(int pass, IndexType index, Integer *regTblStartColumn)
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
			printf("The new value is %d\n",regTblStartColumn);
			return SNMP_ERR_NOERROR;
	}
}


int get_regTblEndColumn(int search_type, Integer *regTblEndColumn, IndexType *index)
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

	*regTblEndColumn = 1;
	return SNMP_ERR_NOERROR;
}

int set_regTblEndColumn(int pass, IndexType index, Integer *regTblEndColumn)
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
			printf("The new value is %d\n",regTblEndColumn);
			return SNMP_ERR_NOERROR;
	}
}


int get_regTblStartRow(int search_type, Integer *regTblStartRow, IndexType *index)
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

	*regTblStartRow = 1;
	return SNMP_ERR_NOERROR;
}

int set_regTblStartRow(int pass, IndexType index, Integer *regTblStartRow)
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
			printf("The new value is %d\n",regTblStartRow);
			return SNMP_ERR_NOERROR;
	}
}


int get_regTblEndRow(int search_type, Integer *regTblEndRow, IndexType *index)
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

	*regTblEndRow = 1;
	return SNMP_ERR_NOERROR;
}

int set_regTblEndRow(int pass, IndexType index, Integer *regTblEndRow)
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
			printf("The new value is %d\n",regTblEndRow);
			return SNMP_ERR_NOERROR;
	}
}


int get_regTblStatus(int search_type, Integer *regTblStatus, IndexType *index)
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

	*regTblStatus = 1;
	return SNMP_ERR_NOERROR;
}

int set_regTblStatus(int pass, IndexType index, Integer *regTblStatus)
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
			printf("The new value is %d\n",regTblStatus);
			return SNMP_ERR_NOERROR;
	}
}

