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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "sh_table.h"
#include "subtree.h"

Table *first_table=NULL;
Table *last_table=NULL;

static Subid dst_subids[1024];
static int dst_len;

void trace_tables()
{
        Table *tp;


        trace("TABLES:\n");
        for(tp = first_table; tp; tp = tp->next_table)
        {
                trace("\t%-30s %-30s",
                        tp->agent->name?tp->agent->name:"UNKNOWN",
                        SSAOidString(&(tp->name)));

                trace(" %[%d-%d] [%d-%d] view:%s status:%d\n",
                        tp->first_column_subid,
                        tp->last_column_subid,
/*
                        SSAOidString(&(tp->indexs)),
*/
                        tp->first_index_subid,
                        tp->last_index_subid,
			SSAStringToChar(tp->regTblView),
			tp->regTblStatus);	
/*
        String  regTblView;
        Integer regTblStatus;
*/
        }
        trace("\n");
}
 
	
/****************************************************************/

int is_first_entry(Table *table)
{
	Table *tp;


	for(tp = first_table; tp; tp = tp->next_table)
	{
		if(table == tp)
		{
			continue;
		}

		if(SSAOidCmp(&(tp->name), &(table->name)) == 0)
		{
/*
			if(SSAOidCmp(&(tp->indexs), &(table->indexs)) < 0)
			{
				return False;
			}
*/
			if(tp->first_index_subid < table->first_index_subid)
			{
				return False;
			}
		}
	}
	
	return True;
}


/****************************************************************/

void table_list_delete()
{
	Table *next;

	while(first_table)
	{
		next = first_table->next_table;
		table_free(first_table);
		first_table = next;
	}

	first_table = NULL;
	last_table = NULL;
}


/****************************************************************/

void table_free(Table *tp)
{
	if(tp == NULL)
	{
		return;
	}

	if(tp->name.subids)
	{
		free(tp->name.subids);
	}
	/* free the TblViewString */
	if(tp->regTblView.chars != NULL &&
	   tp->regTblView.len != 0)
		free(tp->regTblView.chars);

/*
	if(tp->indexs.subids)
	{
		free(tp->indexs.subids);
	}
*/

	free(tp);
}

void delete_all_tables_for_agent(Agent *agent)
{
        Table *tp = first_table;
        Table *next, *last = NULL;

        while(tp)
        {
                next = tp->next_table;
                if(tp->agent == agent){
                  if(last == NULL)
                        first_table = next;
                  else
                        last->next_table = next;
                  table_free(tp);
                }else{
                        last = tp;
                }
                tp = next;
        }
        last_table = last;
 
}

void table_detach(Table *tgt)
{
  Table *sp, *last=NULL;

        if(tgt == NULL) return;
        for(sp = first_table; sp; sp = sp->next_table)
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
                first_table = tgt->next_table;
                tgt->next_table = NULL;
        }
        else
        {
                last->next_table = tgt->next_table;
                tgt->next_table = NULL;
        }
}

static int subids_cat(Subid *subids, int len)
{

	if(subids == NULL) return -1;
        memcpy(&(dst_subids[dst_len]), subids, len * sizeof(Subid));
	dst_len += len;
	return 0;
}


static int activate_table_oids(Table *tp, int type)
{
  Subid index;
  Subid one = 1;
  Subid column;
  Subtree *sp;
  TblTag *tbl_tag=NULL;



 for(index = tp->first_index_subid; index <= tp->last_index_subid; index++){
  for(column = tp->first_column_subid; column <= tp->last_column_subid; column++)
  {
    dst_subids[0]='\0';
    dst_len = 0;
    if(subids_cat(tp->name.subids, tp->name.len) == -1)
    {
            return -1;
    }
    if(subids_cat(&one, 1) == -1)
    {
            return -1;
    }
    if(subids_cat(&column, 1) == -1)
    {
            return -1;
    }
    if(subids_cat(&index, 1) == -1)
    {
            return -1;
    }
    /* search , compare and/or replace(purge and add) */
    sp=subtree_find(dst_subids,dst_len);
    if(sp!=NULL) sp->regTreeStatus = type;
  }
 }
  return 0;
}

static int activate_table_col_obj(Table *tp)
{
  Subid one = 1;
  Subid column;
  Subid index;
  Subtree *sp;
  TblTag *tbl_tag=NULL;

  
  for(column = tp->first_column_subid; column <= tp->last_column_subid; column++)
  {
    dst_subids[0]='\0';
    dst_len = 0;
    if(subids_cat(tp->name.subids, tp->name.len) == -1)
    {
            return -1;
    }
     dst_subids[dst_len-1]++;
/*
    if(subids_cat(&one, 1) == -1)
    {
            return -1;
    }
*/
    if(subids_cat(&column, 1) == -1)
    {
            return -1;
    }
    /* search , compare and/or replace(purge and add) */
    sp=subtree_find(dst_subids,dst_len);

    if(sp != NULL && sp->tbl_tag != NULL)
    {
       if(sp->tbl_tag->entry_index > tp->first_index_subid)
            subtree_purge(dst_subids,dst_len);
       else
		continue;
    }
    tbl_tag = (TblTag*)calloc(1,sizeof(TblTag));
    if(tbl_tag != NULL){
      tbl_tag->entry_index = tp->first_index_subid;
      tbl_tag->type = TBL_TAG_TYPE_COL;
      tbl_tag->table = tp;
    }
    if(subtree_add(tp->agent, dst_subids, dst_len,tbl_tag) == -1)
    {   
      sprintf(error_label, "subtree_add() failed for table %s for the agent %s",           SSAOidString(&(tp->name)),
      tp->agent&&tp->agent->name?tp->agent->name:"UNKNOWN");
      dst_subids[0]='\0';
      dst_len = 0;
      if(tbl_tag) free(tbl_tag);
      tbl_tag = NULL;
      return -1;
    }
  }
  return 0;
}

int activate_table(Table *tp)
{
 if( activate_table_oids(tp,SSA_OPER_STATUS_ACTIVE)!=0 ||
     activate_table_col_obj(tp)!=0 ) 
	return -1;
 return 0;
}

int deactivate_table(Table *tp)
{
 if( activate_table_oids(tp,SSA_OPER_STATUS_NOT_IN_SERVICE)!=0 ||
      delete_table_col_obj(tp)!=0 ) return -1;
 return 0;
}

/* whether oid1 is substring of oid2 */
static int is_suboid(Oid* oid1,Oid *oid2)
{
        int min;
        int i;


        if(oid1 == NULL)
        {
                fprintf(stderr, "BUG: SSAOidCmp(): oid1 is NULL");
                return -2;
        }
 
        if(oid2 == NULL)
        {
                fprintf(stderr, "BUG: SSAOidCmp(): oid2 is NULL");
                return -2;
        }
 
        min = MIN(oid1->len, oid2->len);
 
        for(i = 0; i < min; i++)
        {
                if(oid1->subids[i] > oid2->subids[i])
                {
                        return -1;
                }
 
                if(oid1->subids[i] < oid2->subids[i])
                {
                        return -1;
                }
        }
	if(oid1->len <= oid2->len) return 0;
	return -1;
}

static Subtree* get_oid_in_col_container(Subtree* cur_subtree, int *elem_exist)
{
        Subtree *sp;
        int ret;

	*elem_exist = FALSE;
        for(sp = cur_subtree; sp; sp = sp->next_subtree)
        {
		if(sp==cur_subtree) continue;
		ret = is_suboid(&(cur_subtree->name),&(sp->name));
                if(ret == 0)
                {
			*elem_exist = TRUE;
			if(subtree_is_valid(sp)) return sp;
			continue;
                }
        }

        return NULL;

} 

int delete_table_oid(Table *tp)
{
  Subid index;
  Subid one = 1;
  Subid column;
  Subtree *sp;
  TblTag *tbl_tag=NULL;



 for(index = tp->first_index_subid; index <= tp->last_index_subid; index++){
  for(column = tp->first_column_subid; column <= tp->last_column_subid; column++)
  {
    dst_subids[0]='\0';
    dst_len = 0;
    if(subids_cat(tp->name.subids, tp->name.len) == -1)
    {
            return -1;
    }
    if(subids_cat(&one, 1) == -1)
    {
            return -1;
    }
    if(subids_cat(&column, 1) == -1)
    {
            return -1;
    }
    if(subids_cat(&index, 1) == -1)
    {
            return -1;
    }
    if(subtree_purge(dst_subids,dst_len) == FALSE)
	return -1;
  }
 }
  return 0;
}

int delete_table_col_obj(Table *tp)
{
  /* 1. delete the oids from the subtree list.
     2. scan thru the columarn object, if matching the table, delete and
	find a new one for it.
   */
  Subid one = 1;
  Subid column;
  Subid index;
  Subtree *sp, *sp1;
  TblTag *tbl_tag=NULL;
  int elem_exist;

  
  for(column = tp->first_column_subid; column <= tp->last_column_subid; column++)
  {
    dst_subids[0]='\0';
    dst_len = 0;
    if(subids_cat(tp->name.subids, tp->name.len) == -1)
    {
            return -1;
    }
    if(subids_cat(&one, 1) == -1)
    {
            return -1;
    }
    if(subids_cat(&column, 1) == -1)
    {
            return -1;
    }
    /* search , compare and/or replace(purge and add) */
    if((sp=subtree_find(dst_subids,dst_len)) != NULL)
    {
       if(sp->tbl_tag != NULL &&
          sp->tbl_tag->entry_index == tp->first_index_subid &&
	  sp->tbl_tag->table != NULL && sp->tbl_tag->table == tp)
       {
	    sp1 = get_oid_in_col_container(sp,&elem_exist);

            subtree_purge(dst_subids,dst_len);

	    /* find the right table or oid */
	    if( sp1 != NULL &&
		sp1->tbl_tag != NULL && sp1->tbl_tag->table != NULL && 
		sp1->agent != NULL )
	    {
              tbl_tag = (TblTag*)calloc(1,sizeof(TblTag));
              if(tbl_tag != NULL){
                tbl_tag->type = TBL_TAG_TYPE_COL;
                tbl_tag->entry_index = sp1->tbl_tag->table->first_index_subid;
	        tbl_tag->table = sp1->tbl_tag->table;
              }
    	      if(subtree_add(sp1->agent, dst_subids, dst_len,tbl_tag) == -1)
    	      {   
            	sprintf(error_label, "subtree_add() failed for table %s for the agent %s",           
                    SSAOidString(&(sp1->tbl_tag->table->name)),
                    sp1->agent&&sp1->agent->name?sp1->agent->name:"UNKNOWN");
		    dst_subids[0]='\0';
		    dst_len = 0;
            	    if(tbl_tag) free(tbl_tag);
            	    tbl_tag = NULL;
            	    return -1;
    	      }
	   }
       }
    }
  }
  return 0;
}

int delete_table(Table *tp)
{
  if(tp==NULL) return -1;
  /* (mibpatch) don't call the following two lines, when
     the table is mirror, delete the subtree */
  if(tp->mirror_flag==1){
	/* delete the subtree */
     subtree_purge(tp->name.subids,tp->name.len);
  }else{
  	if( delete_table_oid(tp)!= 0 ||
      	delete_table_col_obj(tp)!=0 ) return -1;
  }
  /*destroy the table */
  table_detach(tp);
  table_free(tp);
  return 0;
}

int activate_table_for_agent(Agent* agent)
{
  Table *sp;

  for(sp = first_table; sp; sp = sp->next_table)
  {
	if(sp->agent != NULL && sp->agent == agent){
	  activate_table(sp);
	  sp->regTblStatus = SSA_OPER_STATUS_ACTIVE;
	}
  }
  return 0;
}

int deactivate_table_for_agent(Agent* agent)
{
  Table *sp;

  for(sp = first_table; sp; sp = sp->next_table)
  {
	if(sp->agent != NULL && sp->agent == agent){
	  deactivate_table(sp);
	  sp->regTblStatus = SSA_OPER_STATUS_NOT_IN_SERVICE;
	}
  }
  return 0;
}

void delete_all_table_from_agent(Agent *agent)
{
  Table *sp=first_table;
  Table *next, *last=NULL;

  while(sp)
  {
        next = sp->next_table;

        if(sp->agent != NULL && sp->agent == agent){
                if(last==NULL){
                        first_table = next;
                }else{
                        last->next_table=next;
                }
                if( delete_table_oid(sp)!= 0 ||
                    delete_table_col_obj(sp)!=0 ){
                        error("table deletion error");
                        return ;
                }
                table_free(sp);
        }else{
                last = sp;
        }
        sp = next;
  }
}

void create_mirror_table_from_subtree(Subtree* subtree)
{
  Table *table, *tmp_table, *last_table;

  if(subtree==NULL) return;
  if((table=(Table*)calloc(1,sizeof(Table)))==NULL) return;
  table->regTblStatus = subtree->regTreeStatus;
  table->mirror_flag = 1;
  if(subtree->agent!=NULL){
  	table->regTblIndex = ++subtree->agent->agentTblIndex;
  	table->regTblAgentID = subtree->agent->agentID;
  }
  SSAOidCpy(&(table->name),&(subtree->name),error_label);
  table->agent = subtree->agent;
  subtree->mirror_tag = (struct _MirrorTag *)calloc(1,sizeof(struct _MirrorTag));
  if(subtree->mirror_tag!=NULL) subtree->mirror_tag->table = table;
  
  /* insert the table */
  /* later sort it in order */
  
  if(first_table==NULL){
	first_table = table;
  }else{
	last_table = NULL;
	for(tmp_table=first_table;tmp_table;tmp_table=tmp_table->next_table){
		if(tmp_table->regTblAgentID > table->regTblAgentID ||
		   (tmp_table->regTblAgentID==table->regTblAgentID &&
		    tmp_table->regTblIndex > table->regTblIndex))
			break;
		last_table = tmp_table;
	}
	if(last_table==NULL){
		table->next_table = first_table;
		first_table = table;
	}else{
		table->next_table = last_table->next_table;
		last_table->next_table = table;
	}
  }
}
