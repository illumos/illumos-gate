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

/** HISTORY
 * 5-15-96	Jerry Yeung	replace the Integer to Integer*
 * 5-20-96	Jerry Yeung	add default_sec_config_file
 * 8-23-96	Jerry Yeung	change the default path
 * 8-27-96      Jerry Yeung	change oid_string
 * 9-06-96      Jiten Gaitonde  change cmd line usage
 * 10-21-96	Jerry Yeung	fix template-code
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include "impl.h"
#include "error.h"
#include "asn1.h"

#include "parse.h"

#define OBJECT			1
#define COLUMN			2
#define NODE			3
#define TABLE			4
#define ENTRY			5


#define PRINT_OPEN_BRACKET fprintf(fp, "{\n");
#define PRINT_TAG_OPEN_BRACKET fprintf(fp, "\t{\n");
#define PRINT_CLOSE_BRACKET fprintf(fp, "}\n");
#define PRINT_TAG_CLOSE_BRACKET fprintf(fp, "\t}\n");

#define SET_PRINT_ENTRY_BLOCK \
	fprintf(fp,"\tswitch(pass)\n");\
	fprintf(fp,"\t{\n");\
	fprintf(fp,"\t\tcase FIRST_PASS:\n\n");\
	fprintf(fp,"\t\t\t/* check the existence of the element */\n");\
	fprintf(fp,"\t\t\t/* which corresponds to the given index and */\n");\
	fprintf(fp,"\t\t\t/* check the validity of the input value */\n");\
	fprintf(fp,"\t\t\t/* if not valid or not exist, */\n\n");\
	fprintf(fp,"\t\t\treturn SNMP_ERR_NOERROR;\n\n");\
	fprintf(fp,"\t\tcase SECOND_PASS:\n\n");\
	fprintf(fp,"\t\t\t/* change the following coding, such that */\n");\
	fprintf(fp,"\t\t\t/* the input value will be stored in the */\n");\
	fprintf(fp,"\t\t\t/* corresponding mib variable of the given */\n");\
	fprintf(fp,"\t\t\t/* index */\n");


#define PRINT_GET_STRING_DUMBY_BLOCK \
	fprintf(fp, "\t/* It is required to allocate memory to the pointers */\n"); \
	fprintf(fp, "\t/* inside the input argument */\n"); \
	fprintf(fp, "\t/* Here, we assume that \"hello\" is the value of the mib variable */\n"); \
	fprintf(fp, "\t/* please change it to the real one */\n\n"); \
	fprintf(fp, "\tlen = strlen(\"hello\");\n"); \
	fprintf(fp, "\tstr = (u_char*)calloc(len,sizeof(char));\n");  \
	fprintf(fp, "\tif(str==NULL){\n"); \
	fprintf(fp, "\t\treturn SNMP_ERR_GENERR;\n"); \
	fprintf(fp, "\t}\n"); \
	fprintf(fp, "\tmemcpy(str,\"hello\",len);\n\n"); \
	fprintf(fp, "\t/*fill in the contents of the argument */\n\n"); \
	fprintf(fp, "\t%s->chars = str;\n",current->label); \
	fprintf(fp, "\t%s->len = len;\n",current->label); \
	fprintf(fp, "\treturn SNMP_ERR_NOERROR;\n");

#define PRINT_GET_OID_DUMBY_BLOCK \
	fprintf(fp, "\t/* It is required to allocate memory to the pointers */\n");\
	fprintf(fp, "\t/* inside the input argument */\n");\
	fprintf(fp, "\t/* Here, we assume that \"1.3.6.1.4.1.42\" is the value */\n");\
	fprintf(fp, "\t/* of the mib variable */\n");\
	fprintf(fp, "\t/* please change it to the real one */\n\n");\
	fprintf(fp, "\t/* 1.3.6.1.4.1.42 has 7 number separated by \".\" */\n");\
	fprintf(fp, "\n");\
	fprintf(fp, "\tlen =7 ;\n");\
	fprintf(fp, "\tsub = (Subid*)calloc(len,sizeof(Subid));\n");\
	fprintf(fp, "\tif(sub==NULL) return SNMP_ERR_GENERR;\n");\
	fprintf(fp, "\tmemcpy(sub,fake_sub,len*sizeof(Subid));\n\n");\
	fprintf(fp, "\t/* fill in the contents of the argument */\n\n");\
	fprintf(fp, "\t%s->subids = sub;\n",current->label);\
	fprintf(fp, "\t%s->len = len;\n",current->label);\
	fprintf(fp, "\treturn SNMP_ERR_NOERROR;\n");

#define PRINT_SET_CASE_BLOCK \
	fprintf(fp, "\t\tcase FIRST_PASS:\n");\
	fprintf(fp, "\n");\
	fprintf(fp, "\t\t\t/* check the validity of the input argument */\n");\
	fprintf(fp, "\t\t\t/* if not valid, return SNMP_GEN_ERROR */\n\n");\
	fprintf(fp, "\t\t\treturn SNMP_ERR_NOERROR;\n\n");\
	fprintf(fp, "\t\tcase SECOND_PASS:\n");\
	fprintf(fp, "\t\t\t/* change the following coding, such that */\n");\
	fprintf(fp, "\t\t\t/* the input value will be stored in the */\n");\
	fprintf(fp, "\t\t\t/* corresponding mib variable */\n\n");


#define PRINT_GET_CASE_BLOCK \
	fprintf(fp, "\t/* In the case, the search_type is FIRST_ENTRY or NEXT_ENTRY */\n");\
	fprintf(fp, "\t/* this function should modify the index argument to the */\n");\
	fprintf(fp, "\t/* appropriate value */\n");\
	fprintf(fp, "\tswitch(search_type)\n");\
	fprintf(fp, "\t{\n");\
	fprintf(fp, "\t\tcase FIRST_ENTRY:\n");\
	fprintf(fp, "\t\t\t\t/* assume 1 is the first index */\n\n");\
	fprintf(fp, "\t\t\t\tindex->value[0] = 1;\n");\
	fprintf(fp, "\t\t\t\tindex->len = 1;\n");\
	fprintf(fp, "\t\t\tbreak;\n\n");\
	fprintf(fp, "\t\tcase NEXT_ENTRY:\n");\
	fprintf(fp, "\t\t\t\tindex->value[0]++;\n");\
	fprintf(fp, "\t\t\t\tif(index->value[0]>2)\n");\
	fprintf(fp, "\t\t\t\t\treturn END_OF_TABLE;\n");\
	fprintf(fp, "\t\t\tbreak;\n\n");\
	fprintf(fp, "\t\tcase EXACT_ENTRY:\n");\
	fprintf(fp, "\t\t\tbreak;\n");\
	fprintf(fp, "\t}\n\n");

/* trap support snmp oid */
static Subid snmp_subids[] = { 1,3,6,1,2,1,11,(Subid)-1}; /* -1 is null(hack) */

static char *base_name = NULL;

static struct tree *root = NULL;

extern int    trace_level;

/*************************************************************************/

static FILE* output_file(char* filename);
static void application_end();

static struct tree *find_node(struct tree *current, char *label);
static int get_node_type(struct tree *tp);


static void init_tree_first_pass(struct tree *current, int *index, int *object_index, int *column_index, int *entry_index);
static void init_tree_second_pass(struct tree *current);


static void output_tree_c(struct tree *current);

static void output_extern_function(FILE *fp, struct tree *current);
static void output_extern_trap_function(FILE *fp);
static void output_trap_function_call(FILE *fp);
static void output_trap_structure(FILE *fp);

static void output_subid_table(FILE *fp, struct tree *current, int *subid_index);
static void output_enum_table(FILE *fp, struct tree *current, int *enum_index);
static void output_object_table(FILE *fp, struct tree *current, int *subid_index, int *enum_index, int *size);
static void output_entry_table(FILE *fp, struct tree *current, int *index_index, int *size);
static void output_column_table(FILE *fp, struct tree *current, int *subid_index, int *enum_index, int *size);
static void output_node_table(FILE *fp, struct tree *current, int *size);


static void output_stub_h(struct tree *current);


static void output_stub_c(struct tree *current);
static void output_appl_c(struct tree *current);
static void output_trap_c(struct tree *current);
static void output_entry_function(FILE *fp, struct tree *current);
static void output_single_obj_function(FILE *fp, struct tree *current);


/*************************************************************************/

static void application_end()
{
}


/*************************************************************************/

static void print_usage()
{
	fprintf(stderr, "Usage: mibcodegen -b SubagentName -f mib_1.txt [mib2.txt....] [-h]\n");
        exit(1);
#if 0
	error_exit("Usage: mibcodegen -b SubagentName -f mib_1.txt [mib2.txt....] [-h]");
#endif
}

/* 
 * get the reverse-subid list from the given tree node
 * len stores the number of subids
 */
void get_subid_of_node(struct tree *t, Subid *subids, int *len)
{
  struct tree *parent;

  *len=0 ;
  parent = t;
  while(parent){
 	subids[(*len)++] = parent->subid;
	parent = parent->parent;
  }	
}


/*************************************************************************/

int
main(int argc, char *argv[])
{
	struct node *nodes = NULL;
	int i;
	int node_index;
	int object_index;
	int column_index;
	int entry_index;
        char *filep[50];
        int  filecount,loop=0,mibcoreflag;
        int opt, doit;
        extern char * optarg;
        extern int    optind;


	doit = 0;
        trace_level=filecount=1;
        mibcoreflag=0;
        filep[0] = "/var/snmp/mib/mib_core.txt"; 
	error_init(argv[0], application_end);

        while((opt = getopt(argc, argv, "b:f:h")) != EOF) {
          switch(opt) {
            case 'b':
                      base_name = (char *)strdup(optarg);
                      break;
            case 'f':
                      filep[filecount++] = (char *)strdup(optarg);
                      if (strstr(filep[filecount-1], "mib_core")) 
                           mibcoreflag=1;
			else
				doit=1;
   
                      for(;((argv[optind]!=NULL) && 
                                  (argv[optind][0] != '-'));
                                  optind++) {
                        filep[filecount++] = (char *)strdup(argv[optind+loop]);
                        if (strstr(filep[filecount-1], "mib_core"))
                              mibcoreflag=1;
			else
				doit = 1;
                      }
                      break;
            case 'h':
            default:
                      print_usage();

          }
        } /*end of while*/

        if ((optind != argc) || (!base_name) || (!doit))
           print_usage();


/******
	if(argc < 3)
	{
		print_usage();
	}


	base_name = (char *) malloc(strlen(argv[1]) + 1);
	strcpy(base_name, argv[1]);
*******/

	parse_init();

	for(i = mibcoreflag; i < filecount; i++)
	{
		FILE *fp;
		struct node *n, *last;


		fp = fopen(filep[i], "r");
		if(fp == NULL)
		{
			error("open() failed on %s %s\n\n", filep[i], errno_string());
			print_usage();
		}

		n = parse(fp);
		fclose(fp);

		if(n == NULL)
		{
			error("WARNING : n is NULL for %s", argv[i]);
		}
		else
		{
			if(nodes == NULL)
			{
				nodes = n;
			}
			else
			{
				last = nodes;
				while(last->next)
				{
					last = last->next;
				}
				last->next = n;
			}
		}
	}

		
	root = build_tree(nodes);

	node_index = 0;
	object_index = 0;
	column_index = 0;
	entry_index = 0;
	init_tree_first_pass(root, &node_index, &object_index, &column_index, &entry_index);
	init_tree_second_pass(root);

	output_tree_c(root);
	output_stub_h(root);
	output_stub_c(root);
	output_appl_c(root);
	output_trap_c(root);

	return (0);
}


/*************************************************************************/

/* Possible returned values:			*/
/*	NODE, TABLE, ENTRY, OBJECT, COLUMN	*/

static int get_node_type(struct tree *tp)
{
	if( (tp->type == TYPE_INTEGER)
		|| (tp->type == TYPE_COUNTER)
		|| (tp->type == TYPE_GAUGE)
		|| (tp->type == TYPE_TIMETICKS)
		|| (tp->type == TYPE_OCTETSTR)
		|| (tp->type == TYPE_IPADDR)
		|| (tp->type == TYPE_OPAQUE)
		|| (tp->type == TYPE_OBJID) )
	{
		if(tp->parent->type == TYPE_ENTRY)
		{
			if(tp->parent->parent->type == TYPE_TABLE)
			{
				return COLUMN;
			}
			else
			{
				error_exit("get_node_type(): Inconsistent table definition: %s->%s->%s", tp->label, tp->parent->label, tp->parent->parent->label);
			}
		}
		else
		{
			return OBJECT;
		}
	}
	else
	{
		switch(tp->type)
		{
			case TYPE_TABLE:
				return TABLE;

			case TYPE_ENTRY:
				return ENTRY;

			default:
				return NODE;
		}
	}
     	return NODE; /*lint*/
}


/*************************************************************************/

/* we suppose that the tree is ordered according to the value of subid */

static void init_tree_first_pass(struct tree *current, int *node_index, int *object_index, int *column_index, int *entry_index)
{
	struct tree *tp;
	int node_type;
	struct tree *next;


	/* node_index */
	current->node_index = *node_index;
	(*node_index)++;


	/* node_type, object_index, column_index */
	node_type = get_node_type(current);
	current->node_type = node_type;
	switch(node_type)
	{
		case OBJECT:
			current->object_index = *object_index;
			current->column_index = -1;
			current->entry_index = -1;
			(*object_index)++;
			break;

		case COLUMN:
			current->object_index = -1;
			current->column_index = *column_index;
			current->entry_index = -1;
			(*column_index)++;
			break;

		case NODE:
		case TABLE:
			current->object_index = -1;
			current->column_index = -1;
			current->entry_index = -1;
			break;

		case ENTRY:
			current->object_index = -1;
			current->column_index = -1;
			current->entry_index = *entry_index;
			(*entry_index)++;
			break;

		default:
			error_exit("init_tree_first_pass(): Unknown node type (%d) for node %s",
				node_type, current->label);

	}


	/* next FIRST PASS */
	next = current->child_list;
	if(next)
	{
		/* current is not a leaf of the tree */

		while(next->child_list)
		{
			next = next->child_list;
		}
		current->next = next;
	}
	else
	{
		/* current is a leaf of the tree */

		struct tree *parent;


		parent = current;
		while(parent)
		{
			/* the goal of this loop is to find an ancestor	*/
			/* of current for which the subtree that contains */
			/* current is not the last subtree		*/


			/* is parent the last child? */
			if(parent->next_peer == NULL)
			{
				/* parent is the last child in the child*/
				/* list of its parent, so go one step up*/

				parent = parent->parent;
			}
			else
			{
				/* parent is not the last child in the	*/
				/* child list of its parent		*/

				next = parent->next_peer;
				break;
			}
		}

		if(parent == NULL)
		{
			/* we found the last node of the MIB */

			current->next = NULL;
		}
		else
		{
			while(next->child_list)
			{
				next = next->child_list;
			}
			current->next = next;
		}
	}


	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		init_tree_first_pass(tp, node_index, object_index, column_index, entry_index);
	}
}


/*************************************************************************/

static void init_tree_second_pass(struct tree *current)
{
	struct tree *tp;
	struct tree *next;
	int node_type;
	struct index_list *indexs;


	/* next SECOND PASS */
	next = current->next;
	while(next)
	{
		node_type = get_node_type(next);
		if(node_type == OBJECT || node_type == COLUMN)
		{
			if(next->access & READ_FLAG)
			{
				break;
			}
		}

		next = next->next;
	}
	current->next = next;


	/* consistency of node_type COLUMN, ENTRY, TABLE */
	switch(current->node_type)
	{
		case COLUMN:
			if(current->parent->node_type != ENTRY)
			{
				error_exit("The node type (%d) of %s is not ENTRY although the node type of %s is COLUMN",
					current->parent->node_type,
					current->parent->label,
					current->label);
			}
			if(current->parent->parent->node_type != TABLE)
			{
				error_exit("The node type (%d) of %s is not TABLE although the node type of %s is COLUMN",
					current->parent->parent->node_type,
					current->parent->parent->label,
					current->label);
			}

			if( (current->n_indexs != 0) || ( current->indexs != NULL) )
			{
				error_exit("The node %s of type COLUMN has some INDEXs!",
					current->label);
			}

			break;


		case ENTRY:
			if(current->parent->node_type != TABLE)
			{
				error_exit("The node type (%d) of %s is not TABLE although the node type of %s is ENTRY",
					current->parent->node_type,
					current->parent->label,
					current->label);
			}

			/* n_indexs, indexs */
			if( (current->n_indexs == 0) || ( current->indexs == NULL) )
			{
				error_exit("The node %s of type ENTRY has no INDEX",
					current->label);
			}

			indexs = current->indexs;
			while(indexs)
			{
				indexs->tp = find_node(root, indexs->label);
				if(indexs->tp == NULL)
				{
					error("WARNING: Can't match the INDEX %s of the entry %s",
						indexs->label,
						current->label);
				}
				else
				{
					switch(indexs->tp->type)
					{
						case TYPE_INTEGER:
						case TYPE_COUNTER:
						case TYPE_GAUGE:
						case TYPE_TIMETICKS:
                                                case TYPE_OCTETSTR:
							break;

						default:
							error("WARNING: The agent will not support the INDEX %s whose type %d for the entry %s",
								indexs->tp->label,
								indexs->tp->type,
								current->label);
					}
				}
				indexs = indexs->next;
			}

			break;


		default:
			/* n_indexs, indexs */
			if( (current->n_indexs != 0) || ( current->indexs != NULL) )
			{
				error_exit("The node %s of type %d has some INDEXs!",
					current->label,
					current->node_type);
			}

			break;
	}


	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		init_tree_second_pass(tp);
	}
}


/*************************************************************************/
static void output_extern_trap_function(FILE *fp)
{
  struct trap_item *ip;

  fprintf(fp,"extern int SSAGetTrapPort();\n");
  for(ip=trap_list;ip;ip=ip->next){
	fprintf(fp, "extern int trap_handler_%s();\n",ip->label);
  }
}

static void output_trap_function_call(FILE *fp)
{
	struct trap_item *ip;
	struct tree *tp;
	struct index_list *variables;
	int index;

	for (ip = trap_list; ip; ip = ip->next) {
		for (index = 1, variables = ip->var_list; variables;
			variables = variables->next) {
			if ((variables->tp = find_node(root,
				variables->label)) == NULL)
				error_exit("output_trap_structure(): \
				Unknown variable:%s", variables->label);
			tp = variables->tp;
			if (tp->node_type == COLUMN)
				fprintf(fp,
				"\t\tSSASetVarIndx(\"%s\",%d);\n",
				variables->label, index++);
			}
	fprintf(fp, "\t\tSSASendTrap(\"%s\");\n", ip->label);
	}
}

static void output_extern_function(FILE *fp, struct tree *current)
{
	struct tree *tp;
	struct index_list *indexs;


	switch(current->node_type)
	{
		case OBJECT:
			if(current->access & READ_FLAG)
			{
				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS:
						fprintf(fp, "extern int get_%s(Integer *%s);\n",
							current->label,
							current->label);
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "extern int get_%s(String *%s);\n",
							current->label,
							current->label);
						break;

					case TYPE_OBJID:
						fprintf(fp, "extern int get_%s(Oid *%s);\n",
							current->label,
							current->label);
						break;

					default:
						error_exit("output_extern_function(): Unknown type (%d) for %s",
							current->type,
							current->label);
				}
			}
			if(current->access & WRITE_FLAG)
			{
				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS: /*(5-15-95)*/
						fprintf(fp, "extern int set_%s(int pass, Integer* %s);\n",
							current->label,
							current->label);
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "extern int set_%s(int pass, String *%s);\n",
							current->label,
							current->label);
						break;

					case TYPE_OBJID:
						fprintf(fp, "extern int set_%s(int pass, Oid *%s);\n",
							current->label,
							current->label);
						break;

					default:
						error_exit("output_extern_function(): Unknown type (%d) for %s",
							current->type,
							current->label);
				}
			}

			if( (current->access & READ_FLAG) || (current->access & WRITE_FLAG) )
			{
				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS: /*(5-15-95)*/
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "extern void free_%s(String *%s);\n",
							current->label,
							current->label);
						break;

					case TYPE_OBJID:
						fprintf(fp, "extern void free_%s(Oid *%s);\n",
							current->label,
							current->label);
						break;

					default:
						error_exit("output_extern_function(): Unknown type (%d) for %s",
							current->type,
							current->label);
				}
			}

			break;


		case COLUMN:
			if(current->access & READ_FLAG)
			{
				fprintf(fp, "extern int get_%s(int search_type, ",
					current->label);

				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS: /*(5-15-96)*/
						fprintf(fp, "Integer *%s, ",
							current->label);
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "String *%s, ",
							current->label);
						break;

					case TYPE_OBJID:
						fprintf(fp, "Oid *%s, ",
							current->label);
						break;

					default:
						error_exit("output_extern_function(): Unknown type (%d) for %s",
						current->type,
						current->label);
				}

				indexs = current->parent->indexs;

/* not more ind. index */
 
				if(indexs)
				{
					if(indexs->tp)
					{
						switch(indexs->tp->type)
						{
							case TYPE_INTEGER:
							case TYPE_COUNTER:
							case TYPE_GAUGE:
							case TYPE_TIMETICKS: 
								fprintf(fp, "IndexType *%s);\n",
									"index");
								break;

							case TYPE_OCTETSTR:
							case TYPE_IPADDR:
							case TYPE_OPAQUE:
								fprintf(fp, "IndexType *%s);\n",
									"index");
								break;

							case TYPE_OBJID:
								fprintf(fp, "IndexType *%s);\n",
									"index");
								break;

							default:
								error_exit("output_extern_function(): Unknown type (%d) for %s",
								indexs->tp->type,
								indexs->tp->label);
						}
					}
					else
					{
						error("WARNING: By default, the type of INDEX %s set to INTEGER",
							indexs->label);
						fprintf(fp, "IndexType *%s);\n",
								"index");
					}

					indexs = indexs->next;
				}

				
			}

			if(current->access & WRITE_FLAG)
			{
				fprintf(fp, "extern int set_%s(int pass, ",
					current->label);

				indexs = current->parent->indexs;

/* not more ind. index */
 
				if(indexs)
				{
					if(indexs->tp)
					{
						switch(indexs->tp->type)
						{
							case TYPE_INTEGER:
							case TYPE_COUNTER:
							case TYPE_GAUGE:
							case TYPE_TIMETICKS: 
								fprintf(fp, "IndexType %s, ",
									"index");
								break;

							case TYPE_OCTETSTR:
							case TYPE_IPADDR:
							case TYPE_OPAQUE:
								fprintf(fp, "IndexType %s, ",
									"index");
								break;

							case TYPE_OBJID:
								fprintf(fp, "IndexType %s, ",
									"index");
								break;

							default:
								error_exit("output_extern_function(): Unknown type (%d) for %s",
								indexs->tp->type,
								indexs->tp->label);
						}
					}
					else
					{
						error("WARNING: By default, the type of INDEX %s set to INTEGER",
							indexs->label);
						fprintf(fp, "IndexType %s, ",
								"index");
					}

					indexs = indexs->next;
				}

				
				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS: /*(5-15-96)*/
						fprintf(fp, "Integer *%s);\n",
							current->label);
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "String *%s);\n",
							current->label);
						break;

					case TYPE_OBJID:
						fprintf(fp, "Oid *%s);\n",
							current->label);
						break;

					default:
						error_exit("output_extern_function(): Unknown type (%d) for %s",
						current->type,
						current->label);
				}
			}

			if( (current->access & READ_FLAG) || (current->access & WRITE_FLAG) )
			{
				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS: /*(5-15-95)*/
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "extern void free_%s(String *%s);\n",
							current->label,
							current->label);
						break;

					case TYPE_OBJID:
						fprintf(fp, "extern void free_%s(Oid *%s);\n",
							current->label,
							current->label);
						break;

					default:
						error_exit("output_extern_function(): Unknown type (%d) for %s",
							current->type,
							current->label);
				}
			}

			break;


		case ENTRY:
			fprintf(fp, "extern int get_%s(int search_type, %c%s_t **%s_data",
				current->label,
				toupper(current->label[0]),
				&(current->label[1]),
				current->label);
				

			indexs = current->indexs;

/* no more ind. index */
			if(indexs)
			{
				if(indexs->tp)
				{
					switch(indexs->tp->type)
					{
						case TYPE_INTEGER:
						case TYPE_COUNTER:
						case TYPE_GAUGE:
						case TYPE_TIMETICKS:
							fprintf(fp, ", IndexType *%s",
								"index");
							break;

						case TYPE_OCTETSTR:
						case TYPE_IPADDR:
						case TYPE_OPAQUE:
							fprintf(fp, ", IndexType *%s",
								"index");
							break;

						case TYPE_OBJID:
							fprintf(fp, ", IndexType *%s",
								"index");

						default:
							error_exit("output_extern_function(): Unknown type (%d) for %s",
							indexs->tp->type,
							indexs->tp->label);
					}
				}
				else
				{
					error("WARNING: By default, the type of INDEX %s set to INTEGER",
						indexs->label);
					fprintf(fp, ", IndexType *%s",
							"index");
				}

				indexs = indexs->next;
			}
			fprintf(fp, ");\n");

			fprintf(fp, "extern void free_%s(%c%s_t *%s);\n",
				current->label,
				toupper(current->label[0]),
				&(current->label[1]),
				current->label);
			break;
	}


	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		output_extern_function(fp, tp);
	}
}


/*************************************************************************/

static void output_enum_table(FILE *fp, struct tree *current, int *enum_index)
{
	struct tree *tp;
	struct enum_list *enums;


	for(enums = current->enums; enums; enums = enums->next)
	{
		if(enums->next == NULL)
		{
			fprintf(fp, "/* %6d */ { %17s, \"%s\", %d },\n",
				*enum_index,
				"NULL",
				enums->label,
				enums->value);
		}
		else
		{
			fprintf(fp, "/* %6d */ { &enum_table[%4d], \"%s\", %d },\n",
				*enum_index,
				(*enum_index) + 1,
				enums->label,
				enums->value);
		}
		(*enum_index)++;
	}

	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		output_enum_table(fp, tp, enum_index);
	}
}


/*************************************************************************/

static void output_subid_table(FILE *fp, struct tree *current, int *subid_index)
{
	struct tree *tp;
	struct tree *parent;
	Subid subids[MAX_OID_LEN];
	int len = 0;
	int i;


	if( (current->node_type == OBJECT)
		|| (current->node_type == COLUMN) )
	{
		fprintf(fp, "/* %6d */",
			*subid_index);

		parent = current;
		while(parent)
		{
			subids[len++] = parent->subid;

			parent = parent->parent;
		}
		fprintf(fp, " %d", subids[len - 1]);
		(*subid_index)++;
		for(i = len - 2; i >= 0; i--)
		{
			fprintf(fp, ", %d", subids[i]);
			(*subid_index)++;
		}
		fprintf(fp, ",\n");
	}

	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		output_subid_table(fp, tp, subid_index);
	}
}


/*************************************************************************/

static void output_object_table(FILE *fp, struct tree *current, int *subid_index, int *enum_index, int *size)
{
	struct tree *tp;
	struct tree *parent;
	struct enum_list *enums;
	int len;


	if(current->node_type == OBJECT)
	{
		fprintf(fp, "/* %6d */ {",
			current->object_index);

		/* name */
		len = 0;
		parent = current;
		while(parent)
		{
			len++;

			parent = parent->parent;
		}
		fprintf(fp, " { &subid_table[%d], %d }", *subid_index, len);

		/* asn1_type */
		switch(current->type)
		{
			case TYPE_INTEGER:
				fprintf(fp, ", INTEGER");
				break;

			case TYPE_COUNTER:
				fprintf(fp, ", COUNTER");
				break;

			case TYPE_GAUGE:
				fprintf(fp, ", GAUGE");
				break;

			case TYPE_TIMETICKS:
				fprintf(fp, ", TIMETICKS");
				break;

			case TYPE_OCTETSTR:
				fprintf(fp, ", STRING");
				break;

			case TYPE_IPADDR:
				fprintf(fp, ", IPADDRESS");
				break;

			case TYPE_OPAQUE:
				fprintf(fp, ", OPAQUE");
				break;

			case TYPE_OBJID:
				fprintf(fp, ", OBJID");
				break;

			default:
				fprintf(fp, "ERROR!");
				error_exit("Unknown ASN.1 type (%d) for object %s",
					current->type,
					current->label);
		}

		/* first_enum */
		if(current->enums)
		{
			fprintf(fp, ", &enum_table[%d]", *enum_index);
		}
		else
		{
			fprintf(fp, ", NULL");
		}

		/* access */
		if( (current->access & READ_FLAG) && (current->access & WRITE_FLAG) )
		{
			fprintf(fp, ", READ_FLAG | WRITE_FLAG");
		}
		else
		if( (current->access & READ_FLAG) && !(current->access & WRITE_FLAG) )
		{
			fprintf(fp, ", READ_FLAG");
		}
		else
		if( !(current->access & READ_FLAG) && (current->access & WRITE_FLAG) )
		{
			fprintf(fp, ", WRITE_FLAG");
		}
		else
		{
			fprintf(fp, ", 0");
		}
                /* type for trap fix */

                fprintf(fp, ", 1");

		/* get() */
		if(current->access & READ_FLAG)
		{
			fprintf(fp, ", get_%s", current->label);
		}
		else
		{
			fprintf(fp, ", NULL");
		}

		/* set() */
		if(current->access & WRITE_FLAG)
		{
			fprintf(fp, ", set_%s", current->label);
		}
		else
		{
			fprintf(fp, ", NULL");
		}

		/* dealloc() */
		if( (current->access & READ_FLAG) || (current->access & WRITE_FLAG) )
		{
			switch(current->type)
			{
				case TYPE_INTEGER:
				case TYPE_COUNTER:
				case TYPE_GAUGE:
				case TYPE_TIMETICKS:
					fprintf(fp,",NULL");
					break;
				default:
					fprintf(fp,",free_%s",current->label);
			}
		}
		else
		{
			fprintf(fp,", NULL");
		}


		fprintf(fp, " },\n");


		(*size)++;
	}


	if( (current->node_type == OBJECT)
		|| (current->node_type == COLUMN) )
	{
		parent = current;
		while(parent)
		{
			(*subid_index)++;

			parent = parent->parent;
		}
	}


	for(enums = current->enums; enums; enums = enums->next)
	{
		(*enum_index)++;
	}


	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		output_object_table(fp, tp, subid_index, enum_index, size);
	}
}


/*************************************************************************/

static void output_index_table(FILE *fp, struct tree *current, int *index_index)
{
	struct tree *tp;
	struct index_list *indexs;


	for(indexs = current->indexs; indexs; indexs = indexs->next)
	{
		if(indexs->tp)
		{
			if(indexs->next == NULL)
			{
				fprintf(fp, "/* %6d */ { %17s, \"%s\", %2d, %2d, &node_table[%d] },\n",
					*index_index,
					"NULL",
					indexs->label,
                                        indexs->tp->type,
                                        indexs->tp->oct_str_len,
					indexs->tp->node_index);
			}
			else
			{
				fprintf(fp, "/* %6d */ { &index_table[%4d], \"%s\", %2d, %2d, &node_table[%d] },\n",
					*index_index,
					(*index_index) + 1,
					indexs->label,
                                        indexs->tp->type, 
                                        indexs->tp->oct_str_len,
					indexs->tp->node_index);
			}
		}
		else
		{
			error("WARNING: node pointer for INDEX %s is NULL",
				indexs->label);

			if(indexs->next == NULL)
			{
				fprintf(fp, "/* %6d */ { %17s, \"%s\", %2d, %2d, NULL },\n",
					*index_index,
					"NULL",
					indexs->label,
                                        indexs->tp->type,
                                        indexs->tp->oct_str_len); 
			}
			else
			{
				fprintf(fp, "/* %6d */ { &index_table[%4d], \"%s\", %2d, %2d, NULL },\n",
					*index_index,
					(*index_index) + 1,
					indexs->label,
                                        indexs->tp->type,
                                        indexs->tp->oct_str_len);
			}
		}

		(*index_index)++;
	}

	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		output_index_table(fp, tp, index_index);
	}
}


/*************************************************************************/

static void output_entry_table(FILE *fp, struct tree *current, int *index_index, int *size)
{
	struct tree *tp;


	if(current->node_type == ENTRY)
	{
		struct index_list *indexs;


		fprintf(fp, "/* %6d */ {",
			current->entry_index);

		/* first_index, n_indexs */
		fprintf(fp, " &index_table[%d], %d",
			*index_index,
			current->n_indexs);

		for(indexs = current->indexs; indexs; indexs = indexs->next)
		{
			(*index_index)++;
		}

		/* get() */
		fprintf(fp, ", get_%s", current->label);

		/* dealloc() */
		fprintf(fp, ", free_%s", current->label);

		fprintf(fp, " },\n");


		(*size)++;
	}


	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		output_entry_table(fp, tp, index_index, size);
	}
}


/*************************************************************************/

static void output_column_table(FILE *fp, struct tree *current, int *subid_index, int *enum_index, int *size)
{
	struct tree *tp;
	struct tree *parent;
	struct enum_list *enums;


	if(current->node_type == COLUMN)
	{
		int offset;
		int len;
		struct tree *child;


		fprintf(fp, "/* %6d */ {",
			current->column_index);

		/* name */
		len = 0;
		parent = current;
		while(parent)
		{
			len++;

			parent = parent->parent;
		}
		fprintf(fp, " { &subid_table[%d], %d }", *subid_index, len);

		/* asn1_type */
		switch(current->type)
		{
			case TYPE_INTEGER:
				fprintf(fp, ", INTEGER");
				break;

			case TYPE_COUNTER:
				fprintf(fp, ", COUNTER");
				break;

			case TYPE_GAUGE:
				fprintf(fp, ", GAUGE");
				break;

			case TYPE_TIMETICKS:
				fprintf(fp, ", TIMETICKS");
				break;

			case TYPE_OCTETSTR:
				fprintf(fp, ", STRING");
				break;

			case TYPE_IPADDR:
				fprintf(fp, ", IPADDRESS");
				break;

			case TYPE_OPAQUE:
				fprintf(fp, ", OPAQUE");
				break;

			case TYPE_OBJID:
				fprintf(fp, ", OBJID");
				break;

			default:
				fprintf(fp, "ERROR!");
				error_exit("Unknown ASN.1 type (%d) for object %s",
					current->type,
					current->label);
		}

		/* first_enum */
		if(current->enums)
		{
			fprintf(fp, ", &enum_table[%d]", *enum_index);
		}
		else
		{
			fprintf(fp, ", NULL");
		}

		/* access */
		if( (current->access & READ_FLAG) && (current->access & WRITE_FLAG) )
		{
			fprintf(fp, ", READ_FLAG | WRITE_FLAG");
		}
		else
		if( (current->access & READ_FLAG) && !(current->access & WRITE_FLAG) )
		{
			fprintf(fp, ", READ_FLAG");
		}
		else
		if( !(current->access & READ_FLAG) && (current->access & WRITE_FLAG) )
		{
			fprintf(fp, ", WRITE_FLAG");
		}
		else
		{
			fprintf(fp, ", 0");
		}
                /* type  for trap fix */

                fprintf(fp, ", 2");

               /* get() */

                if(current->access & READ_FLAG)
                {
                        fprintf(fp, ", get_%s", current->label);
                }
                else
                {
                        fprintf(fp, ", NULL");
                }

		/* set() */
		if(current->access & WRITE_FLAG)
		{
			fprintf(fp, ", set_%s", current->label);
		}
		else
		{
			fprintf(fp, ", NULL");
		}

		/* table */
		fprintf(fp, ", &entry_table[%d]", current->parent->entry_index);

		/* offset */
		offset = 0;
		for(child = current->parent->child_list; child != current; child = child->next_peer)
		{
			if( !(child->access & READ_FLAG) )
			{
				continue;
			}

			switch(child->type)
			{
				case TYPE_INTEGER:
				case TYPE_COUNTER:
				case TYPE_GAUGE:
				case TYPE_TIMETICKS:
					offset = offset + sizeof(Integer);
					break;

				case TYPE_OCTETSTR:
				case TYPE_IPADDR:
				case TYPE_OPAQUE:
					offset = offset + sizeof(String);
					break;

				case TYPE_OBJID:
					offset = offset + sizeof(Oid);
					break;

				default:
					error_exit("output_column_table(): Unknown type (%d) for %s",
						child->type,
						child->label);
			}
		}
		fprintf(fp, ", %d", offset);

		fprintf(fp, " },\n");


		(*size)++;
	}


	if( (current->node_type == OBJECT)
		|| (current->node_type == COLUMN) )
	{
		parent = current;
		while(parent)
		{
			(*subid_index)++;

			parent = parent->parent;
		}
	}


	for(enums = current->enums; enums; enums = enums->next)
	{
		(*enum_index)++;
	}


	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		output_column_table(fp, tp, subid_index, enum_index, size);
	}
}


/*************************************************************************/

static void output_node_table(FILE *fp, struct tree *current, int *size)
{
	struct tree *tp;


	fprintf(fp, "/* %6d */ {",
		current->node_index);

	/* parent */
	if(current->parent == NULL)
	{
		fprintf(fp, " %17s", "NULL");
	}
	else
	{
		fprintf(fp, " &node_table[%4d]",
			current->parent->node_index);
	}

	/* first_child */
	if(current->child_list == NULL)
	{
		fprintf(fp, ", %17s", "NULL");
	}
	else
	{
		fprintf(fp, ", &node_table[%4d]",
			current->child_list->node_index);
	}

	/* next_peer */
	if(current->next_peer == NULL)
	{
		fprintf(fp, ", %17s", "NULL");
	}
	else
	{
		fprintf(fp, ", &node_table[%4d]",
			current->next_peer->node_index);
	}

	/* next */
	if(current->next == NULL)
	{
		fprintf(fp, ", %17s", "NULL");
	}
	else
	{
		fprintf(fp, ", &node_table[%4d]",
			current->next->node_index);
	}

	/* label, subid */
	fprintf(fp, ", \"%s\", %d",
		current->label, current->subid);

	/* type, data */
	switch(current->node_type)
	{
		case OBJECT:
			fprintf(fp, ", OBJECT, (void *) &object_table[%d]",
				current->object_index);
			break;

		case COLUMN:
			fprintf(fp, ", COLUMN, (void *) &column_table[%d]",
				current->column_index);
			break;

		case NODE:
		case TABLE:
		case ENTRY:
			fprintf(fp, ", NODE, NULL");
			break;


		default:
			error_exit("Unknown node type (%d) for %s",
				current->type, current->label);
	}

	fprintf(fp, " },\n");


	(*size)++;


	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		output_node_table(fp, tp, size);
	}
}


/*************************************************************************/

static void output_tree_c(struct tree *current)
{
	char pathname[MAXPATHLEN];
	char backup_pathname[MAXPATHLEN];
	struct stat buf;
	FILE *fp;
	int subid_index;
	int enum_index;
	int index_index;
	int size;


	sprintf(pathname, "%s_tree.c", base_name);
	sprintf(backup_pathname, "%s_tree.c.old", base_name);
	trace("Creating %s ...\n", pathname);
	if(stat(pathname, &buf) == 0)
	{
                if(rename(pathname,backup_pathname)==-1){
                  error_exit("The file %s already exists and can't be renamed!", pathname);
                }
	}

	fp = fopen(pathname, "w");
	if(fp == NULL)
	{
		error_exit("Can't open %s %s", pathname, errno_string());
	}

	fprintf(fp, "#include <sys/types.h>\n");
	fprintf(fp, "\n");
	fprintf(fp, "#include \"impl.h\"\n");
	fprintf(fp, "#include \"asn1.h\"\n");
	fprintf(fp, "#include \"node.h\"\n");
	fprintf(fp, "\n");
	fprintf(fp, "#include \"%s_stub.h\"\n", base_name);
	fprintf(fp, "\n");
	fprintf(fp, "\n");



	subid_index = 0;
	fprintf(fp, "Subid subid_table[] = {\n");
	output_subid_table(fp, current, &subid_index);
	fprintf(fp, "0\n");
	fprintf(fp, "};\n");
	fprintf(fp, "int subid_table_size = %d;\n\n", subid_index);

	enum_index = 0;
	fprintf(fp, "Enum enum_table[] = {\n");
	output_enum_table(fp, current, &enum_index);
	fprintf(fp, "{ NULL, NULL, 0 }\n");
	fprintf(fp, "};\n");
	fprintf(fp, "int enum_table_size = %d;\n\n", enum_index);

	subid_index = 0;
	enum_index = 0;
	size = 0;
	fprintf(fp, "Object object_table[] = {\n");
	output_object_table(fp, current, &subid_index, &enum_index, &size);
	fprintf(fp, "{ { NULL, 0}, 0, NULL, 0, NULL, NULL }\n");
	fprintf(fp, "};\n");
	fprintf(fp, "int object_table_size = %d;\n\n", size);

	index_index = 0;
	fprintf(fp, "Index index_table[] = {\n");
	output_index_table(fp, current, &index_index);
	fprintf(fp, "{ NULL, NULL, NULL }\n");
	fprintf(fp, "};\n");
	fprintf(fp, "int index_table_size = %d;\n\n", index_index);

	size = 0;
	index_index = 0;
	fprintf(fp, "Entry entry_table[] = {\n");
	output_entry_table(fp, current, &index_index, &size);
	fprintf(fp, "{ NULL, 0, NULL }\n");
	fprintf(fp, "};\n");
	fprintf(fp, "int entry_table_size = %d;\n\n", size);

	subid_index = 0;
	enum_index = 0;
	size = 0;
	fprintf(fp, "Column column_table[] = {\n");
	output_column_table(fp, current, &subid_index, &enum_index, &size);
	fprintf(fp, "{ { NULL, 0}, 0, NULL, 0, NULL, NULL , 0 }\n");
	fprintf(fp, "};\n");
	fprintf(fp, "int column_table_size = %d;\n\n", size);

	size = 0;
	fprintf(fp, "Node node_table[] = {\n");
	output_node_table(fp, current, &size);
	fprintf(fp, "{ NULL, NULL, NULL, NULL, NULL, 0, 0, NULL }\n");
	fprintf(fp, "};\n");
	fprintf(fp, "int node_table_size = %d;\n\n", size);


	fclose(fp);
}


/*************************************************************************/

static struct tree *find_node(struct tree *current, char *label)
{
	struct tree *tp;
	struct tree *t;


	if(strcmp(current->label, label) == 0)
	{
		return current;
	}

	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		t = find_node(tp, label);
		if(t != NULL)
		{
			return t;
		}
	}

	return NULL;
}


/*************************************************************************/

static void output_structure(FILE *fp, struct tree *current)
{
	struct tree *tp;


	if(current->node_type == ENTRY)
	{
		struct tree *child;


		fprintf(fp, "\n");
		fprintf(fp, "typedef struct _%c%s_t {\n",
			toupper(current->label[0]),
			&(current->label[1]));
		for(child = current->child_list; child; child = child->next_peer)
		{
			if( !(child->access & READ_FLAG) )
			{
				continue;
			}

			switch(child->type)
			{
				case TYPE_INTEGER:
				case TYPE_COUNTER:
				case TYPE_GAUGE:
				case TYPE_TIMETICKS:
					fprintf(fp, "\tInteger %s;\n", child->label);
					break;

				case TYPE_OCTETSTR:
				case TYPE_IPADDR:
				case TYPE_OPAQUE:
					fprintf(fp, "\tString %s;\n", child->label);
					break;

				case TYPE_OBJID:
					fprintf(fp, "\tOid %s;\n", child->label);
					break;

				default:
					error_exit("output_structure(): Unknown type (%d) for %s",
						child->type,
						child->label);
			}
		}
		fprintf(fp, "} %c%s_t;\n",
			toupper(current->label[0]),
			&(current->label[1]));
	}


	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		output_structure(fp, tp);
	}
}


/*************************************************************************/

static void output_stub_h(struct tree *current)
{
	char pathname[MAXPATHLEN];
	char backup_pathname[MAXPATHLEN];
	struct stat buf;
	FILE *fp;
	int i;


	sprintf(pathname, "%s_stub.h", base_name);
	sprintf(backup_pathname, "%s_stub.h.old", base_name);
	trace("Creating %s ...\n", pathname);
	if(stat(pathname, &buf) == 0)
	{
                if(rename(pathname,backup_pathname)==-1){
                  error_exit("The file %s already exists and can't be renamed!", pathname);
                }
	}

	fp = fopen(pathname, "w");
	if(fp == NULL)
	{
		error_exit("Can't open %s %s", pathname, errno_string());
	}

	fprintf(fp, "#ifndef _");
	for(i = 0; base_name[i] != '\0'; i++)
	{
		fprintf(fp, "%c", toupper(base_name[i]));
	}
	fprintf(fp, "_STUB_H_\n");
	fprintf(fp, "#define _");
	for(i = 0; base_name[i] != '\0'; i++)
	{
		fprintf(fp, "%c", toupper(base_name[i]));
	}
	fprintf(fp, "_STUB_H_\n");
	fprintf(fp, "\n");


	output_structure(fp, current);
	fprintf(fp, "\n");

	output_extern_function(fp, current);
	fprintf(fp, "\n");

	output_extern_trap_function(fp);

	fprintf(fp, "#endif\n");

	fclose(fp);
}


/*************************************************************************/

static void get_subids_by_name(Subid *dst,char *oid_name)
{
  struct tree *tp;
  Subid subids[MAX_OID_LEN+1];
  int i,j,len;

  /* find the enterprise_subids */
  if((tp = find_node(root,oid_name)) == NULL)
    fprintf (stderr, "Unknown trap enterprise variable:%s\n",oid_name);
  get_subid_of_node(tp,subids,&len);
  for(j=0,i=len-1;i>=0;i--,j++)
	dst[j] = subids[i];
  dst[j]=(u_long)-1;
}


static void output_trap_structure(FILE *fp)
{
	struct trap_item *ip;
	int i, enterprise_trap;
	struct index_list *var;
	struct tree *tp;
	int numCallItem = 0;
	int numTrapElem = 0;
	int *trapTableMap = NULL;
	int idx, index;
	int variableExist, columnExist = 0;


	for (ip = trap_list; ip; ip = ip->next) {
		numTrapElem++;
		for (var = ip->var_list; var; var = var->next)
			numCallItem++;
	}

	if (numTrapElem > 0) {
		trapTableMap = (int *)malloc(sizeof (int) * (numTrapElem + 10));
		if (!trapTableMap)
			error_exit("malloc failed");
	for (idx = 0; idx < numTrapElem+10; idx++)
		trapTableMap[idx] = -1;
	}

	if (numCallItem > 0)
		fprintf(fp, "struct CallbackItem genCallItem[%d] = {\n",
			numCallItem+10);
	else
		fprintf(fp, "struct CallbackItem genCallItem[%d];\n",
			numCallItem+10);
	numCallItem = 0;
	numTrapElem = 0;
	for (ip = trap_list; ip; ip = ip->next) {
		variableExist = 0;
		trapTableMap[numTrapElem] = numCallItem;
		for (var = ip->var_list; var; var = var->next) {
			variableExist = 1;
			if ((var->tp = find_node(root, var->label)) == NULL)
				error_exit("output_trap_structure():Unknown \
					variable:%s", var->label);
				tp = var->tp;
				if (tp->node_type == OBJECT)
					fprintf(fp, "\t{&object_table[%d],",
					tp->object_index);
				else
					if (tp->node_type == COLUMN) {
					columnExist = 1;
						fprintf(fp,
					"\t{(Object *)&column_table[%d],",
						tp->column_index);
					} else
						error_exit("variable: %s is not\
						individual object", var->label);

			switch (tp->type) { /* only accept object node type */
				case TYPE_INTEGER:
				case TYPE_COUNTER:
				case TYPE_GAUGE:
				case TYPE_TIMETICKS:
					fprintf(fp, "INTEGER,");
					break;
				case TYPE_OCTETSTR:
				case TYPE_IPADDR:
				case TYPE_OPAQUE:
					fprintf(fp, "STRING,");
					break;
				case TYPE_OBJID:
					fprintf(fp, "OBJID,");
					break;
				default:
					error_exit("unknown object type of \
					variable %s", var->label);
			}
		numCallItem++;
		if (var->next)
			fprintf(fp, "%d},\n", numCallItem);
		else
			fprintf(fp, "-1},\n");
		}
		if (variableExist == 0)
			trapTableMap[numTrapElem] = -1;
	numTrapElem++;
	}
	if (numCallItem > 0) fprintf(fp, "};\n");
	fprintf(fp, "int genNumCallItem = %d;\n", numCallItem);

	/* dumby the map */
	if (numTrapElem > 0)
		fprintf(fp, "int genTrapTableMap[%d] = {\n", numTrapElem + 10);
	else
		fprintf(fp, "int genTrapTableMap[%d];\n", numTrapElem + 10);
	for (idx = 0; idx < numTrapElem; idx++) {
		fprintf(fp, "%d,", trapTableMap[idx]);
	}
	if (numTrapElem > 0) fprintf(fp, "};\n");

	fprintf(fp, "int genNumTrapElem = %d;\n", numTrapElem);
	if (numTrapElem > 0)
		fprintf(fp, "struct TrapHndlCxt genTrapBucket[%d] = {\n",
			numTrapElem + 10);
	else
		fprintf(fp, "struct TrapHndlCxt genTrapBucket[%d];\n",
			numTrapElem+10);
	for (ip = trap_list; ip; ip = ip->next) {
		fprintf(fp, "\t{\"%s\",", ip->label);
		if (!strcmp(ip->enterprise_label, "snmp"))
			fprintf(fp, "0,");
		else
			fprintf(fp, "1,");
		if (!strcmp(ip->enterprise_label, "snmp")) {
			for (i = 0; i < 8; i++) {
				ip->enterprise_subids[i] = snmp_subids[i];
			}
		} else {
			get_subids_by_name(ip->enterprise_subids,
				ip->enterprise_label);
		}

		enterprise_trap = FALSE;
		for (i = 0; i < 7; i++) {
			if (ip->enterprise_subids[i] != snmp_subids[i]) {
				enterprise_trap = TRUE;
				break;
			}
		}
		if (enterprise_trap) {
			fprintf(fp, "6,");
			fprintf(fp, "%d},\n", ip->value);
		} else {
			fprintf(fp, "%d,", ip->value);
			fprintf(fp, "0},\n");
		}
	}
	if (numTrapElem > 0) fprintf(fp, "};\n");

/* For arbitrary length enterprise OID in traps - bug 4133978 */
/* Initializing new trap enterprise info which handles arbitrary subids */
	if (numTrapElem > 0)
		fprintf(fp,
	"struct TrapAnyEnterpriseInfo genTrapAnyEnterpriseInfo[%d] = {\n",
		numTrapElem + 10);
	else
		fprintf(fp, "struct TrapAnyEnterpriseInfo \
			genTrapAnyEnterpriseInfo[%d]; \n", numTrapElem + 10);
	for (ip = trap_list; ip; ip = ip->next) {
		fprintf(fp, "\t{");
		for (i = 0; ip->enterprise_subids[i] != -1; i++) {
			fprintf(fp, "%d, ", ip->enterprise_subids[i]);
		}
		fprintf(fp, "(uint32_t)-1},\n");
	}
	if (numTrapElem > 0) fprintf(fp, "};\n");

	if (numTrapElem == 0)
		return;

	fprintf(fp, "struct _CallTrapIndx { \n");
	fprintf(fp, "\tchar name[256];\n");
	fprintf(fp, "\tIndexType *pindex_obj; \n");
	fprintf(fp, "};\n\n");

	fprintf(fp, "struct _Indx { \n");
	fprintf(fp, "\tchar name[256]; \n");
	fprintf(fp, "\tint index; \n");
	fprintf(fp, "};\n\n");

	if (columnExist != 0) {
	index = 0;
	for (ip = trap_list; ip; ip = ip->next) {
		for (var = ip->var_list; var; var = var->next) {
			tp = var->tp;
			if (tp->node_type == COLUMN) {
				index++;
			}
		}
	}

	fprintf(fp, "int numIndxElem = %d; \n", index);
	fprintf(fp, "struct _Indx Indx[%d] = { \n", index);
	for (ip = trap_list; ip; ip = ip->next) {
		for (var = ip->var_list; var; var = var->next) {
			tp = var->tp;
			if (tp->node_type == COLUMN) {
				fprintf(fp, "\t{\"%s\", 0},\n", var->label);
			}
		}
	}
	fprintf(fp, "};\n\n");
	fprintf(fp, "int SSASetVarIndx(char* name, int index)\n{\n");
	fprintf(fp, "\tint i;\n\n");
	fprintf(fp, "\tif (!name) \n");
	fprintf(fp, "\treturn (-1); \n\n");
	fprintf(fp, "\tfor (i = 0; i < numIndxElem; i++) \n");
	fprintf(fp, "\t\tif (!strcmp(name, Indx[i].name)) { \n");
	fprintf(fp, "\t\t\tIndx[i].index = index;\n");
	fprintf(fp, "\t\t\treturn (0);\n");
	fprintf(fp, "\t\t}\n");
	fprintf(fp, "\treturn (-1);\n");
	fprintf(fp, "}\n\n");
	}

	index = 0;
	fprintf(fp, "IndexType TrapIndx[%d] = { \n", numCallItem);
		for (ip = trap_list; ip; ip = ip->next) {
			for (var = ip->var_list; var; var = var->next) {
				tp = var->tp;
				if (tp->node_type == OBJECT)
					fprintf(fp, "\t{0,0,NULL},\n");
				else if (tp->node_type == COLUMN) {
					fprintf(fp,
					"\t{1,1,&Indx[%d].index},\n", index++);
				} else
					error_exit("variable: %s is not \
					individual object", var->label);
			}
		}
	fprintf(fp, "};\n\n");

	fprintf(fp, "struct _CallTrapIndx CallTrapIndx[%d] = {\n", numTrapElem);
		for (idx = 0, ip = trap_list; ip && idx < numTrapElem;
			ip = ip->next, idx++) {
			fprintf(fp, "\t{\"%s\",&TrapIndx[%d]},\n", ip->label,
			trapTableMap[idx]);
		}
	fprintf(fp, "};\n\n");


	if (numTrapElem > 0) {
		fprintf(fp, "int SSASendTrap(char* name)\n");
		fprintf(fp, "{\n");
		fprintf(fp, "\tint i;\n\n");
		fprintf(fp, "\tif (!name) \n");
		fprintf(fp, "\treturn (-1);\n\n");

		fprintf(fp, "\tnumCallItem = genNumCallItem;\n");
		fprintf(fp, "\tnumTrapElem = genNumTrapElem;\n");
		fprintf(fp, "\tcallItem = genCallItem;\n");
		fprintf(fp, "\ttrapTableMap = genTrapTableMap;\n");
		fprintf(fp, "\ttrapBucket = genTrapBucket;\n");
		fprintf(fp,
		"\ttrapAnyEnterpriseInfo = genTrapAnyEnterpriseInfo;\n");
	/* SSASendTrap4 handles tabular column elements - 4519879 */
		fprintf(fp, "\tfor (i = 0; i < numTrapElem; i++) \n");
	fprintf(fp, "\tif (!strcmp(name, CallTrapIndx[i].name)) \n");
	fprintf(fp, "\t\treturn \
	(_SSASendTrap4(name, CallTrapIndx[i].pindex_obj)); \n");
	fprintf(fp, "\treturn (-1); \n");
	fprintf(fp, "}\n");
	}
}


static void output_entry_function(FILE *fp, struct tree *current)
{
	struct tree *tp;
	struct index_list *indexs;
	struct tree *child;
	int first_time_entry_print;


	switch(current->node_type)
	{
		case COLUMN:
			if( !(current->access & WRITE_FLAG) )
			{
				break;
			}
			break;
		case ENTRY:
			/* open a new file */
			fclose(fp);
		        fp = output_file(current->label);
			fprintf(fp, "\n");
			fprintf(fp, "/***** %-20s ********************************/\n",
				current->label);
			break;
	}

	switch(current->node_type)
	{
		case COLUMN:
			if(current->access & READ_FLAG)
			{
				fprintf(fp, "\n");
				fprintf(fp, "int get_%s(int search_type, ",
					current->label);

				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS: /*(5-15-96)*/
						fprintf(fp, "Integer *%s, ",
							current->label);
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "String *%s, ",
							current->label);
						break;

					case TYPE_OBJID:
						fprintf(fp, "Oid *%s, ",
							current->label);
						break;

					default:
						error_exit("output_extern_function(): Unknown type (%d) for %s",
						current->type,
						current->label);
				}

				indexs = current->parent->indexs;

/* not more ind. index */
 
				if(indexs)
				{
					if(indexs->tp)
					{
						switch(indexs->tp->type)
						{
							case TYPE_INTEGER:
							case TYPE_COUNTER:
							case TYPE_GAUGE:
							case TYPE_TIMETICKS: 
								fprintf(fp, "IndexType *%s)\n",
									"index");
								break;

							case TYPE_OCTETSTR:
							case TYPE_IPADDR:
							case TYPE_OPAQUE:
								fprintf(fp, "IndexType *%s)\n",
									"index");
								break;

							case TYPE_OBJID:
								fprintf(fp, "IndexType *%s)\n",
									"index");
								break;

							default:
								error_exit("output_extern_function(): Unknown type (%d) for %s",
								indexs->tp->type,
								indexs->tp->label);
						}
					}
					else
					{
						error("WARNING: By default, the type of INDEX %s set to INTEGER",
							indexs->label);
						fprintf(fp, "IndexType *%s)\n",
								"index");
					}

					indexs = indexs->next;
				}

			PRINT_OPEN_BRACKET

			switch(current->type)
			{ 
						case TYPE_INTEGER:
						case TYPE_COUNTER:
						case TYPE_TIMETICKS: 
						case TYPE_GAUGE:
							PRINT_GET_CASE_BLOCK 
							fprintf(fp,"\t/*assume that the mib variable has a value of 1 */\n\n");
							fprintf(fp,"\t*%s = 1;\n",current->label);
							fprintf(fp,"\treturn SNMP_ERR_NOERROR;\n");
							break;

						case TYPE_OCTETSTR:
						case TYPE_IPADDR:
						case TYPE_OPAQUE:
							fprintf(fp, "\tu_char *str;\n");
							fprintf(fp, "\tint len;\n\n");
							PRINT_GET_CASE_BLOCK 
							PRINT_GET_STRING_DUMBY_BLOCK 
							break;

						case TYPE_OBJID:
							fprintf(fp, "\tSubid *sub;\n");
							fprintf(fp, "\tSubid fake_sub[] = {1,3,6,1,4,1,4,42};\n");
							fprintf(fp, "\tint len;\n\n");
							PRINT_GET_CASE_BLOCK 
							PRINT_GET_OID_DUMBY_BLOCK 
							break;

							default:
								error_exit("output_extern_function(): Unknown type (%d) for %s",
								current->type,
								current->label);
			}

				PRINT_CLOSE_BRACKET
			}

			if(current->access & WRITE_FLAG)
			{
				fprintf(fp, "\n");
				fprintf(fp, "int set_%s(int pass, ",
					current->label);

				indexs = current->parent->indexs;

				/* no more ind. index */
				if(indexs)
				{
					if(indexs->tp)
					{
						switch(indexs->tp->type)
						{
							case TYPE_INTEGER:
							case TYPE_COUNTER:
							case TYPE_GAUGE:
							case TYPE_TIMETICKS:
							case TYPE_OCTETSTR:
							case TYPE_IPADDR:
							case TYPE_OPAQUE:
							case TYPE_OBJID:
								fprintf(fp, "IndexType %s, ",
									"index");
								break;

							default:
								error_exit("output_function(): Unknown type (%d) for %s",
									indexs->tp->type,
								indexs->tp->label);
						}
					}
					else
					{
						error("WARNING: By default, the type of INDEX %s set to INTEGER",
							indexs->label);
						fprintf(fp, "Integer %s, ",
							indexs->label);
					}
					indexs = indexs->next;
				}

				
				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS: /*(5-15-96)*/
						fprintf(fp, "Integer *%s)\n",
							current->label);
						PRINT_OPEN_BRACKET
						SET_PRINT_ENTRY_BLOCK
						fprintf(fp, "\t\t\tprintf(\"The new value is %%d\\n\",%s);\n",current->label);
						fprintf(fp, "\t\t\treturn SNMP_ERR_NOERROR;\n");
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "String *%s)\n",
							current->label);
						PRINT_OPEN_BRACKET
						fprintf(fp, "\tchar buf[100];\n\n");
						SET_PRINT_ENTRY_BLOCK
						fprintf(fp, "\t\t\tmemcpy(buf,%s->chars,%s->len);\n",current->label,current->label);
						fprintf(fp, "\t\t\tbuf[%s->len+1] = '\\0';\n",current->label);
						fprintf(fp, "\t\t\tprintf(\"The new value is %%s\\n\",buf);\n");
						fprintf(fp, "\t\t\treturn SNMP_ERR_NOERROR;\n");
						break;

					case TYPE_OBJID:
						fprintf(fp, "Oid *%s)\n",
							current->label);
						PRINT_OPEN_BRACKET
						SET_PRINT_ENTRY_BLOCK
						fprintf(fp, "\t\t\tprintf(\"The new value is %%s\\n\",SSAOidString(%s));\n",current->label);
						fprintf(fp, "\t\t\treturn SNMP_ERR_NOERROR;\n");
						break;

					default:
						error_exit("output_function(): Unknown type (%d) for %s",
							current->type,
							current->label);
				}
				PRINT_TAG_CLOSE_BRACKET
				PRINT_CLOSE_BRACKET
				fprintf(fp, "\n");
			}

			if( (current->access & READ_FLAG) || (current->access & WRITE_FLAG) )
			{
				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS: /*(5-15-95)*/
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "\n");
						fprintf(fp, "void free_%s(String *%s)\n",
							current->label,
							current->label);
                                		fprintf(fp, "{\n");
                                		fprintf(fp, "\t if(%s->",current->label);
						break;

					case TYPE_OBJID:
						fprintf(fp, "\n");
						fprintf(fp, "void free_%s(Oid *%s)\n",
							current->label,
							current->label);
                                		fprintf(fp, "{\n");
                                		fprintf(fp, "\t if(%s->",current->label);
						break;

					default:
						error_exit("output_extern_function(): Unknown type (%d) for %s",
							current->type,
							current->label);
				}
                                switch(current->type)
                                {
                                        case TYPE_INTEGER:
                                        case TYPE_COUNTER:
                                        case TYPE_GAUGE:
                                        case TYPE_TIMETICKS:
                                                break;
 
                                        case TYPE_OCTETSTR:
                                        case TYPE_IPADDR:
                                        case TYPE_OPAQUE:
                                                fprintf(fp, "chars!=NULL && %s->len !=0)\n",current->label);
						fprintf(fp, "\t{\n");
                                                fprintf(fp, "\t\tfree(%s->chars);\n",current->label);
                                                fprintf(fp,"\t\t%s->len = 0;\n",current->label);
						fprintf(fp, "\t}\n");
                                		fprintf(fp, "}\n");
                                                break;
 
                                        case TYPE_OBJID:
                                                fprintf(fp, "subids!=NULL && %s->len !=0)\n",current->label);
						fprintf(fp, "\t{\n");
                                                fprintf(fp, "\t\tfree(%s->subids);\n",current->label);
                                                fprintf(fp,"\t\t%s->len = 0;\n",current->label);
						fprintf(fp, "\t}\n");
                                		fprintf(fp, "}\n");
                                                break;
 
                                        default:
                                                error_exit("output_function(): Unknown type (%d) for %s",
                                                        current->type,
                                                        current->label);
                                }
			}

			break;


		case ENTRY:
			fprintf(fp, "\n");
			fprintf(fp, "extern int get_%s(int search_type, %c%s_t **%s_data",
				current->label,
				toupper(current->label[0]),
				&(current->label[1]),
				current->label);

			indexs = current->indexs;

/* no more ind. index */
			if(indexs)
			{
				if(indexs->tp)
				{
					switch(indexs->tp->type)
					{
						case TYPE_INTEGER:
						case TYPE_COUNTER:
						case TYPE_GAUGE:
						case TYPE_TIMETICKS:

						case TYPE_OCTETSTR:
						case TYPE_IPADDR:
						case TYPE_OPAQUE:

						case TYPE_OBJID:
							fprintf(fp, ", IndexType *%s",
								"index");
							break;

						default:
							error_exit("output_function(): Unknown type (%d) for %s",
								indexs->tp->type,
								indexs->tp->label);
					}
				}
				else
				{
					error("WARNING: By default, the type of INDEX %s set to INTEGER",
						indexs->label);
					fprintf(fp, ", Integer *%s",
						indexs->label);
				}

				indexs = indexs->next;
			}
			fprintf(fp, ")\n");
			fprintf(fp, "{\n");
			fprintf(fp, "\n");
			fprintf(fp, "\tint res;\n");
			fprintf(fp, "\tIndexType backupIndex, useIndex;\n");
			fprintf(fp, "\tint i;\n");
			fprintf(fp, "\n");
			fprintf(fp, "\t*%s_data = (%c%s_t*)calloc(1,sizeof(%c%s_t));\n",
					current->label,
					toupper(current->label[0]), &(current->label[1]),
					toupper(current->label[0]), &(current->label[1]));
			fprintf(fp,"\tif(%s_data == NULL) return SNMP_ERR_GENERR;\n",current->label);
			fprintf(fp,"\n");
		
				first_time_entry_print = 0;
				for(child = current->child_list; child; child = child->next_peer)
				{
					if(!(child->access & READ_FLAG) )
						continue;

                                	switch(child->type)
                                	{
                                       	 case TYPE_INTEGER:
                                       	 case TYPE_COUNTER:
                                       	 case TYPE_GAUGE:
                                       	 case TYPE_TIMETICKS:
                                       	 case TYPE_OCTETSTR:
                                       	 case TYPE_IPADDR:
                                       	 case TYPE_OPAQUE:
                                        case TYPE_OBJID:
						first_time_entry_print++;
						if(first_time_entry_print==1){
			fprintf(fp, "\n");
			fprintf(fp, "\tbackupIndex.type = index->type;\n");
			fprintf(fp, "\tbackupIndex.len = index->len;\n");
			fprintf(fp, "\tbackupIndex.value = (int*)calloc(index->len,sizeof(int));\n");
			fprintf(fp, "\tfor(i=0;i<index->len;i++)\n");
			fprintf(fp, "\t\tbackupIndex.value[i] = index->value[i];\n");
	fprintf(fp, "\tuseIndex.type = backupIndex.type;\n");
	fprintf(fp, "\tuseIndex.len = backupIndex.len;\n");
	fprintf(fp, "\tuseIndex.value = (int*)calloc(backupIndex.len,sizeof(int));\n");
	fprintf(fp, "\n");
}else{
	fprintf(fp, "\n");
	fprintf(fp, "\tfor(i=0;i<backupIndex.len;i++)\n");
	fprintf(fp, "\t\tuseIndex.value[i] = backupIndex.value[i];\n");
	fprintf(fp, "\n");
}
						fprintf(fp,"\tres = ");
						fprintf(fp,"get_%s(\n",child->label);
						fprintf(fp,"\t        search_type,\n");
						fprintf(fp,"\t        &((*%s_data)->%s),\n",current->label,child->label);
						if(first_time_entry_print==1)
						  fprintf(fp,"\t        index);\n");
						else
						  fprintf(fp,"\t        &useIndex);\n");
						fprintf(fp,"\tif(res != SNMP_ERR_NOERROR){\n"); 
                                                fprintf(fp,"\t\tfree_%s(*%s_data);\n",current->label,current->label);
						fprintf(fp, "\t\t*%s_data=NULL;\n",current->label);
                                                fprintf(fp,"\t\tfree((char *)backupIndex.value);\n");
                                                fprintf(fp,"\t\tfree((char *)useIndex.value);\n");
						fprintf(fp, "\t\treturn res;\n\n");
						fprintf(fp, "\t}\n");

                                                break;

                                        default:
                                                error_exit("output_function(): Unknown type (%d) for %s",
                                                        child->type,
                                                        child->label);
                                	}
				}


                        fprintf(fp,"\t free((char *)backupIndex.value);\n");
                        fprintf(fp,"\t free((char *)useIndex.value);\n");
			fprintf(fp, "\t return res;\n");
			fprintf(fp, "}\n");
			fprintf(fp, "\n");

				fprintf(fp, "\n");
				fprintf(fp, "void free_%s(%c%s_t *%s)\n",
			                current->label, toupper(current->label[0]),
                                        &(current->label[1]), current->label);
                                fprintf(fp, "{\n");
 
                                fprintf(fp,"\tif (%s) {\n", current->label);
	
				for(child = current->child_list; child; child = child->next_peer)
				{
					if(!(child->access & READ_FLAG) )
						continue;

                                	switch(child->type)
                                	{
                                       	 case TYPE_INTEGER:
                                       	 case TYPE_COUNTER:
                                       	 case TYPE_GAUGE:
                                       	 case TYPE_TIMETICKS:
                                       	         break;
 
                                       	 case TYPE_OCTETSTR:
                                       	 case TYPE_IPADDR:
                                       	 case TYPE_OPAQUE:
                                        case TYPE_OBJID:
						fprintf(fp, "\t\tfree_%s(&(%s->%s));\n",
								child->label,
								current->label,child->label);
                                                break;

                                        default:
                                                error_exit("output_function(): Unknown type (%d) for %s",
                                                        child->type,
                                                        child->label);
                                	}
				}
                                fprintf(fp,"\t\tfree(%s);\n",current->label);
                                fprintf(fp,"\t\t%s=NULL;\n",current->label);
                                fprintf(fp,"\t}\n");
                                fprintf(fp, "}\n");
			
			break;
	}


	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		output_entry_function(fp, tp);
	}

}
static void output_single_obj_function(FILE *fp, struct tree *current)
{
	struct tree *tp;


	switch(current->node_type)
	{
		case OBJECT:
			if(current->access & READ_FLAG)
			{
				fprintf(fp, "\n");
				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS:
						fprintf(fp, "int get_%s(Integer *%s)\n",
							current->label,
							current->label);
						PRINT_OPEN_BRACKET
						fprintf(fp, "\t/* assume that the mib variable has a value of 1 */\n\n");
						fprintf(fp, "\t*%s = 1;\n",current->label);
						fprintf(fp, "\treturn SNMP_ERR_NOERROR;\n");
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "int get_%s(String *%s)\n",
							current->label,
							current->label);
						PRINT_OPEN_BRACKET
						fprintf(fp, "\tu_char *str;\n");
						fprintf(fp, "\tint len;\n\n");

						PRINT_GET_STRING_DUMBY_BLOCK 
						
						break;

					case TYPE_OBJID:
						fprintf(fp, "int get_%s(Oid *%s)\n",
							current->label,
							current->label);
						PRINT_OPEN_BRACKET
						fprintf(fp, "\tSubid *sub;\n");
						fprintf(fp, "\tSubid fake_sub[] = {1,3,6,1,4,1,4,42};\n");
						fprintf(fp, "\tint len;\n\n");

						PRINT_GET_OID_DUMBY_BLOCK 

						break;

					deafult:
						error_exit("output_function(): Unknown type (%d) for %s", current->type,
							current->label);
				}
				PRINT_CLOSE_BRACKET
			}

			if(current->access & WRITE_FLAG)
			{
				fprintf(fp, "\n");
				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS: /*(5-15-96)*/
						fprintf(fp, "int set_%s(int pass, Integer *%s)\n",
							current->label,
							current->label);
						PRINT_OPEN_BRACKET
						fprintf(fp, "\tswitch(pass)\n");
						fprintf(fp, "\t{\n");
						PRINT_SET_CASE_BLOCK 
						fprintf(fp, "\t\t\tprintf(\"The new value is %%d\\n\",%s);\n",current->label);
						fprintf(fp, "\t\t\treturn SNMP_ERR_NOERROR;\n");
						fprintf(fp, "\t}\n");
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "int set_%s(int pass, String *%s)\n",
							current->label,
							current->label);
						PRINT_OPEN_BRACKET
						fprintf(fp, "\tchar buf[100];\n\n");
						fprintf(fp, "\tswitch(pass)\n");
						fprintf(fp, "\t{\n");
						PRINT_SET_CASE_BLOCK 
						fprintf(fp, "\t\t\tmemcpy(buf,%s->chars,%s->len);\n",current->label,current->label);
						fprintf(fp, "\t\t\tbuf[%s->len+1] = '\\0';\n",current->label);
						fprintf(fp, "\t\t\tprintf(\"The new value is %%s\\n\",buf);\n");
						fprintf(fp, "\t\t\treturn SNMP_ERR_NOERROR;\n");
						fprintf(fp, "\t}\n");
						break;

					case TYPE_OBJID:
						fprintf(fp, "int set_%s(int pass, Oid *%s)\n",
							current->label,
							current->label);
						PRINT_OPEN_BRACKET
						fprintf(fp, "\tswitch(pass)\n");
						fprintf(fp, "\t{\n");
						PRINT_SET_CASE_BLOCK 
						fprintf(fp, "\t\t\tprintf(\"The new value is %%s\\n\",SSAOidString(%s));\n",current->label);
						fprintf(fp, "\t\t\treturn SNMP_ERR_NOERROR;\n");
						fprintf(fp, "\t}\n");
						break;

					default:
						error_exit("output_function(): Unknown type (%d) for %s", current->type,
							current->label);
				}

				PRINT_CLOSE_BRACKET
				fprintf(fp, "\n");
			}

			if( (current->access & READ_FLAG) || (current->access & WRITE_FLAG) )
			{
				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS:
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "\n");
						fprintf(fp, "void free_%s(String *%s)\n",
							current->label,
							current->label);
						PRINT_OPEN_BRACKET
						fprintf(fp, "\t if(%s->",current->label);
						break;

					case TYPE_OBJID:
						fprintf(fp, "\n");
						fprintf(fp, "void free_%s(Oid *%s)\n",
							current->label,
							current->label);
						PRINT_OPEN_BRACKET
						fprintf(fp, "\t if(%s->",current->label);
						break;

					default:
						error_exit("output_function(): Unknown type (%d) for %s",
							current->type,
							current->label);
				}
				switch(current->type)
				{
					case TYPE_INTEGER:
					case TYPE_COUNTER:
					case TYPE_GAUGE:
					case TYPE_TIMETICKS:
						break;

					case TYPE_OCTETSTR:
					case TYPE_IPADDR:
					case TYPE_OPAQUE:
						fprintf(fp, "chars!=NULL && %s->len !=0)\n",current->label);
						fprintf(fp, "\t{\n");
						fprintf(fp, "\t\tfree(%s->chars);\n",current->label);
						fprintf(fp,"\t\t%s->len = 0;\n",current->label);
						fprintf(fp,"\t}\n");
						PRINT_CLOSE_BRACKET
						break;

					case TYPE_OBJID:
						fprintf(fp, "subids!=NULL && %s->len !=0)\n",current->label);
						fprintf(fp, "\t{\n");
						fprintf(fp, "\t\tfree(%s->subids);\n",current->label);
						fprintf(fp,"\t\t%s->len = 0;\n",current->label);
						fprintf(fp,"\t}\n");
						PRINT_CLOSE_BRACKET
						break;

					default:
						error_exit("output_function(): Unknown type (%d) for %s",
							current->type,
							current->label);
				}
			}
			break;
	}

	for(tp = current->child_list; tp; tp = tp->next_peer)
	{
		output_single_obj_function(fp, tp);
	}

}


/*************************************************************************/
static FILE* output_file(char* filename)
{
	char pathname[MAXPATHLEN];
	char backup_pathname[MAXPATHLEN];
	FILE *fp;
	struct stat buf;


	sprintf(pathname, "%s_%s.c", base_name,filename);
	sprintf(backup_pathname, "%s.%s.c.old", base_name,filename);
	trace("Creating %s ...\n", pathname);
	if(stat(pathname, &buf) == 0)
	{
		if(rename(pathname,backup_pathname)==-1){
		  error_exit("The file %s already exists and can't be renamed!", pathname);
		}
	}

	fp = fopen(pathname, "w");
	if(fp == NULL)
	{
		error_exit("Can't open %s %s", pathname, errno_string());
	}

	fprintf(fp, "#include <sys/types.h>\n");
	fprintf(fp, "#include <netinet/in.h>\n");
	fprintf(fp, "\n");
	fprintf(fp, "#include \"impl.h\"\n");
	fprintf(fp, "#include \"asn1.h\"\n");
	fprintf(fp, "#include \"error.h\"\n");
	fprintf(fp, "#include \"snmp.h\"\n");
	fprintf(fp, "#include \"trap.h\"\n");
	fprintf(fp, "#include \"pdu.h\"\n");
	fprintf(fp, "#include \"node.h\"\n");
	fprintf(fp, "\n");
	fprintf(fp, "#include \"%s_stub.h\"\n", base_name);
	fprintf(fp, "\n");
	fprintf(fp, "\n");

	return(fp);
}

static void output_appl_c(struct tree *current)
{
	FILE *fp;

	fp = output_file("appl");
	fprintf(fp, "/***** GLOBAL VARIABLES *****/\n");
	fprintf(fp, "\n");
	fprintf(fp, "char default_config_file[] = \"/etc/snmp/conf/%s.reg\";\n", base_name);
	fprintf(fp, "char default_sec_config_file[] = \"/etc/snmp/conf/%s.acl\";\n", base_name);
	fprintf(fp, "char default_error_file[] = \"/var/snmp/%sd.log\";\n", base_name);
	fprintf(fp, "\n");
	fprintf(fp, "\n");

	fprintf(fp, "/***********************************************************/\n");
	fprintf(fp, "\n");
	fprintf(fp, "void agent_init()\n");
	fprintf(fp, "{\n");
	fprintf(fp, "}\n");
	fprintf(fp, "\n");
	fprintf(fp, "\n");

	fprintf(fp, "/***********************************************************/\n");
	fprintf(fp, "\n");
	fprintf(fp, "void agent_end()\n");
	fprintf(fp, "{\n");
	fprintf(fp, "}\n");
	fprintf(fp, "\n");
	fprintf(fp, "\n");

	fprintf(fp, "/***********************************************************/\n");
	fprintf(fp, "\n");
	fprintf(fp, "void agent_loop()\n");
	fprintf(fp, "{\n");
	fprintf(fp,"\tint condition=FALSE;\n\n");
 	fprintf(fp,"\tif(condition==TRUE){\n");
	output_trap_function_call(fp);
	fprintf(fp, "\t}\n");
	fprintf(fp, "}\n");
	fprintf(fp, "\n");
	fprintf(fp, "\n");

	fprintf(fp, "/***********************************************************/\n");
	fprintf(fp, "\n");
	fprintf(fp, "void agent_select_info(fd_set *fdset, int *numfds)\n");
	fprintf(fp, "{\n");
	fprintf(fp, "}\n");
	fprintf(fp, "\n");
	fprintf(fp, "\n");

	fprintf(fp, "/***********************************************************/\n");
	fprintf(fp, "\n");
	fprintf(fp, "void agent_select_callback(fd_set *fdset)\n");
	fprintf(fp, "{\n");
	fprintf(fp, "}\n");
	fprintf(fp, "\n");
	fprintf(fp, "\n");

	fprintf(fp,"void main(int argc, char** argv)\n");
	fprintf(fp,"{\n");
	fprintf(fp,"\tSSAMain(argc,argv);\n");
	fprintf(fp,"}\n\n");

	fprintf(fp, "\n");
	fclose(fp);
}

static void output_trap_c(struct tree *current)
{
	FILE *fp;

	fp = output_file("trap");
	output_trap_structure(fp);
	fclose(fp);
}

static void output_stub_c(struct tree *current)
{
	FILE *fp;

	fp = output_file("stub");
	output_single_obj_function(fp, current);
	output_entry_function(fp, current);

	fclose(fp);
}



