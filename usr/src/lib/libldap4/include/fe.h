/*
 *
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _FE_H
#define _FE_H

/*
 * Get context const . Used to retreive info in context : fe_get_ctx
 * Return values depend on requested info :
 */
#define CTX_FENAME	1	/* To get the Front End name */
				/* return value is (char *) */
#define CTX_NBTABLE	2	/* To get the number of sub-section  */
				/* return value is (int *) */
#define CTX_TABLENAME	3	/* To get name(s) of sub section */
				/* return value is (char **) */
#define CTX_TABLEPTR	4	/* To get the ptr to a sub section definition */
				/* return value is (FE_Table *) */
				/* !! This is not a copy */
#define CTX_CUSTOMS	5	/* get customs attributes */
				/*   third parameter is the variable name (char *) */

/*
 * Get Tables const 
 */
#define TABLE_NAME	1	/* table or subsection name, return value is (char *) */
				/*   third parms is null  */
#define TABLE_OBJ_LST	2	/* object class list, return value is (char **)  */
				/*   third parms is null  */
#define TABLE_COM_HLD	3	/* stored ldap, connection return value is (LDAP *) */
#define TABLE_CUSTOMS	4	/* get customs attributes */
				/*   third parameter is the variable name (char *) */
                                /*   return value is an array of string (char **) */
#define TABLE_FEATTR	5	/* to get the attribute definition. If no attribute name */
				/*   is provided to get the list of attributes */
				/*   third parms is the attribute name */
				/*   return a FE_Attr * if attribute name provided */
				/*   return a char ** (null term) if no attribute name provided */

#define TABLE_SUNDSATTR	6	/* idem TABLE_FEATTR but for SunDS definition */

/*
 * Tokens/Attributes 
 */
#define FETABLE		0
#define SUNDSTABLE	1
#define SUNDSATTRLIST	2
#define SUNDSTOKENLIST	3
#define FEATTRLIST	4
#define FETOKENLIST	5
#define FEBUILDLIST	6
#define SUNDSBUILDLIST	7

/*
 * Errors consts
 */
#define NOERROR		0
#define INVALID_PARMS	1
#define VALUE_NOT_FOUND	2
#define CREATE_FAILED	3
#define SYNTAX_ERROR	4

/*
 * SPLIT way
 */
#define LEFT2RIGHT     	0     
#define RIGHT2LEFT	1
/*
 * Data structures
 */

/*
 * This struct is used to run regex with "reg_expression"
 * and assigned values (braelist) with "token" links
 * Functional schema :
 *    step(input,reg_expression)
 *      => token[0] = braslist[0]..braelist[0]
 *	=> token[1] = braslist[1]..braelist[1]
 *	=> ...
 *	=> token[i] = braslist[i]..braelist[i]
 */
typedef struct _reg_mapp {
	char	*reg_expression;	/* Compiled regular expression */
	int	Nbra;			/* nbra result */
	int	NbToken_Defined;	/* Nb tokens defined in reg_expression */
	int	*Token_ID;		/* Tokens place (index) in input value */
} Reg_Map;

/*
 * Tokens definition, including input attribute and number of expressions
 * and link to each rule.
 */
typedef struct _tokens_def {
	int	attr_ID;		/* Attributes ID (in SD or FE Table) */
					/* Used as input in regular expression */
	int	NbRules;		/* Number of expressions seperated by | */
	Reg_Map	**TokenRules;		/* Array of tokens rules */
} Token_Def;

/*
 * Attribute mapping definition. SD attributes are composed of FE attributes and
 * SD tokens. 
 */
typedef struct _attr_mapping {
	char		*AttrName;		/* Attribute Name */
	char		*Expr;			/* Value expression */
	int		AttrStatus;		/* Store several attr's info such as */
						/* Key || Exist || Frozen */
						/* Key is used to generate wizard filter */
						/* Exist is used to generate wizard filter */
						/* Frozen is used control access on attribute */
	int		NbItem;			/* Nb Attributes & Tokens need to build val */
	int		*AttrID;		/* Set of attributes including tokens */
} Attr_Mapping;

/*
 * Builder_map : defined builder expression 
 */
typedef struct _builder_map {
	char		*build_exp;		/* the sentence to build */
	int		NbInput;
	int		*Input_ID;		/* List of attr ID to used as input in semtence */
}Builder_map;
 
/*
 * Data used for split/string2instances/instances2string/exclude functions
 */
typedef struct _builder_fct {
        int             Input_ID;
	char		*value;		/* input data						*/
        char            *prefix;	/* string2instances and reverse : prefix	  	*/
					/* exclude		        : val 2 exclude		*/
	int		Parm_ID;	/* only for exclude funct       : ID of val 2 exclude	*/
        char            *suffix;
        char            *separator;
	int		readIndicator;
} Builder_fct;

/* 
 * Builder tokens : used to build special value (named builder token) from other tokens
 * or input value. They look like ouput attributes, but they allow to apply rules, if
 * input value does exist. They also permit to split input sentence into attribute instances
 */
typedef struct _builder {
        char		*builder_name;
	int		builder_ID;
	int		NbRules;
	int		BuilderType;
	Builder_map	*Mapp;
	Builder_fct     *Fct;
} Build_def;


/*
 * Full definition of table mapping.
 */
typedef struct _table_mapping {
	int		NbTokens;		/* Nb extract tokens defined */
	int		NbAttributes;		/* Nb attributes in the entry */
	int		NbBuilder;		/* Nb builder tokens defined */
	Token_Def	**Tokens_list;		/* Array of tokens needed for translation */
	Build_def	*Build_list;		/* Array of builder tokens */
	Attr_Mapping	**Attr_list;		/* Array of Attributes defined in an entry */
} Table_Mapping;

typedef struct _custo_info {
	char			*InfoName;
	int			NbValues;
	char			**Values;	/* Null terminated array of instance */
} Cust_Info;

typedef struct _sds_com {
	LDAP		*lhd;			/* LDAP communication handle */
	char		**fe_object_list;	/* Array of ObjectClasses (null term list) */
} SDS_Com;

typedef struct _dynrule {
	char	*ResName;			/* Result (or Rule) name			*/
	int	opType;				/* Extrac, Cond, split, str2ins, ins2str,	*/
						/* getrdn, exclude				*/
	int	NbExpr;				/* Nb rules found use only in extract & cond	*/
	int	*NbItems;			/* Nb variable in expression, usefull for	*/
						/* extract and cond. IT's a null terminated	*/
						/* array which contains the Number of var in  	*/
	char	**Expression;			/* The sentence	(make sense only in cond)     	*/
	char	**ConstVal;			/* use when funct parm are const not used for	*/
						/* extract and cond cases			*/
	char	**VarName;			/* Var can be 1)DynRule 2)InputData 3)Common	*/
} DynRule;

typedef struct _fe_table {
	char		*fe_section;		/* Section table name				*/
	int		nb_fe_attr;		/* Nb FE attributes defined			*/
	int		nb_sds_attr;		/* Nb SDS attributes defined			*/
	int		nb_fe_tokens;		/* Nb tokens defined in FE section		*/
	int		nb_sds_tokens;		/* Nb tokens defined in SunDS section		*/ 
	int		nb_cust;		/* Nb custom attributes in common section	*/ 
	int		nb_fe_build;		/* Nb tokens build in FE section		*/
	int		nb_sds_build;		/* Nb tokens build in SUNDS section		*/
	int		nb_dyn_rules;		/* Nb dynamic rules in Dynamic section		*/
	char		**fe_token_list;	/* Array of FE token				*/
	char		**sds_token_list;	/* List of SunDS token				*/
	char		**fe_attr_list;		/* Array of attributes (null term list)		*/
	char		**sds_attr_list;	/* Array of attributes (null term list)		*/
	char		**fe_build_list;	/* Array of FE build				*/
	char		**sds_build_list;	/* List of SunDS build				*/
	Table_Mapping	*sds_schema;		/* SDS attributes definition			*/
	Table_Mapping	*fe_schema;		/* FE attributes definition			*/
	SDS_Com		*comm_items;		/* Communication attributes			*/
	Cust_Info	**custo_info;		/* Customs info					*/
	DynRule		*dyn_rules;		/* Ordered dynamic rules			*/
} FE_Table;

typedef struct _fe_context {
	char		*fe_name;		/* Is it really usefull ?? */
	int		NbSection;		/* Nb section */
	int		NbGlobals;		/* Nb global customs info */
	Cust_Info	**globals;		/* Customs info */
	FE_Table	**fe_section_list;	/* All sub-section in mapping file */
} FE_Context;

/* Entries values definition */
/* Instance values definition */
typedef struct _fe_values {
	int	Length;
	void	*Val;
} FE_Values;

/* Attribute value definition */
typedef struct _fe_attr {
	char		*AttrType;
	int		NbInstance;
	FE_Values	**ValInstances;
} FE_Attr;

/* Full entry definition */
typedef struct _fe_entry {
	char	*DN;
	int	Nb_items;
	FE_Attr	**AttributesArray;
} FE_Entry;

typedef struct _fe_couple {
	char	*Value2Subst;
	char	*SubstValue;
} FE_Couple;

/*
 * libfe.a exported functions 
 */

/*
 * Read config file and create "fe_name" context
 * NB : This init read all tables mapping
 * libldap context use : before all action
 */
extern FE_Context	*fe_ctx_init(char *config_path, char *fe_name);

/*
 * Free All fe context all tables ...
 * libldap context usage : ldap_close
 */
extern int		fe_ctx_free(FE_Context **Ctx);

/*
 * Return the pointer to requested item in context 
 * libldap context usage : before all action
 */
extern void		 *fe_ctx_get(FE_Context *Ctx, int FieldID, void *Value);

/*
 * Search for information from Subsection/Table ? 
 * You can check also Get/Table/Paragraph
 * libldap context usage : ldap_*
 */
extern void		 *fe_table_get(FE_Table *MapTable, int FieldID, void *Void);

/*
 * Set tables item is mainly used for communication items. other information 
 * sets will be forbid
 * libldap context usage : after ldap_open or ldap_bind
 */ 
/*
extern int		  fe_table_set(FE_Table *MapTable, int FieldID, void *Void);
*/
/*
 * You have the attribute name ?! fe_ent_get_attr returns pointer to the requested
 * attributes with instances, status... from a specific entry
 * libldap context usage : after ldap_search
 */
extern FE_Attr		 *fe_ent_get_attr(FE_Table *MapTable, FE_Entry *fe_item, char *AttrName);

/*
 * Create the entry according to the "schema" defined in mapping file for a specific table
 * libladp context usage : before ldap_add
 */
extern FE_Entry		 *fe_ent_create(FE_Table *MapTable, int TableType);

/*
 * Add new attributes in a new entry
 * libladp context usage : before ldap_add
 */
extern FE_Attr           *fe_ent_get_attr(FE_Table *MapTable,FE_Entry *Entry, char *AttrName);

/*
 * Add new instance value 
 * libladp context usage : before ldap_add
 */
extern int		  fe_ent_add_val(FE_Table *MapTable, FE_Attr *attr, int ValLength, void *Val);
extern  FE_Attr		  *fe_ent_add_attr_val(FE_Table *MapTable, FE_Entry *Entry, char *AttrName, int ValLength, void *Val);

/*
 * explode DN into an attributes array 
 * libladp context usage : after ldap_search
 */
extern FE_Attr		**fe_ent_show_dn(FE_Table *MapTable, FE_Entry *Entry);

/*
 *  free entry (including attributes) 
 */
extern void		  fe_ent_free(FE_Entry **Entry);

/*
 * Substitute all vars defined in inputString (with syntax ${varName}) by values found in 
 * fe_couple array. For errors returned check the errors consts upper
 */
extern int		fe_subst(char *inputString, char **outputString, FE_Couple **fe_couple);

/*
 * Split a sentence, add prefix (for each token) and suffix (exept for the last)
 */
extern char		*fe_split(char *inputData, char *Separator, char *Prefix, char *Suffix, int  way );

/* 
 * Dynamic translation, use only definition in dynamic section 
 */
extern char		**fe_dynamic(FE_Table *MapTable, char *Var2stop, char **DynVal);

/*
 * Return the translated attribute. TableType is the original table of AttrName.
 * if translation rules is one to one translation, the function return a copy of translated 
 * attribute name.
 * else the function return a copy of the rules 
 */ 
extern char		**fe_trans_attrName(FE_Table *MapTable, char *AttrName, int TableType);
extern int		*fe_trans_attrID(FE_Table *MapTable, char *AttrName, int TableType);

/*	
 * Return the translated SD entry 
 * libladp context usage : after ldap_search
 */
extern FE_Entry		 *fe_trans_all_sds2fe(FE_Table *MapTable, LDAP *ld, LDAPMessage *sd_entry);

/*
 * Return the translated FE entry
 * libladp context usage : after ldap_search
 */ 
extern LDAPMod		 **fe_trans_all_fe2sds(FE_Table *MapTable, LDAP *ld, FE_Entry *fe_entry);

/*	
 * Close to "fe_trans_all_sds2fe" but output is Entry pointer as defined in SunDS server
 */
extern FE_Entry		*fe_trans_all_sunds2fe(FE_Table *MapTable, Entry *sd_entry);
extern Entry		*fe_trans_all_fe2sunds(FE_Table *MapTable, FE_Entry *fe_entry);

/* An example an example ....
 * Translation from fe to sunds 
 *
 * FE_Context      *MyContext = NULL;
 * FE_Table        *HostTable = NULL;
 * FE_Entry        *fe_entry = NULL;
 * FE_Attr         *fe_attr = NULL;
 * Entry           *lentry = NULL;
 *
 * if((MyContext = fe_ctx_init("..../sunds_map.conf","NIS")) == NULL){
 *	ldaplog(LDAP_DEBUG_CONFIG,"Can't load mapping file\n", 0, 0, 0);
 *	exit(1);
 * }
 * if((HostTable = fe_ctx_get(MyContext,CTX_TABLEPTR,"dummy")) == NULL) 
 * {
 *	ldaplog(LDAP_DEBUG_CONFIG,"Can't retreive HOSTS table\n", 0, 0, 0);
 *	exit(1);
 * } 
 * if((fe_entry = fe_ent_create(HostTable, FETABLE))==NULL)
 * {
 *	ldaplog(LDAP_DEBUG_CONFIG,"Can't create entry\n", 0, 0, 0);
 *	exit(1);
 * }
 * if ((fe_attr = fe_ent_add_attr_val(HostTable, fe_entry, "niskey", 16, "109.107.179.131")) == NULL)
 * {
 *	ldaplog(LDAP_DEBUG_CONFIG,"Can't add attr=%s, val=%s\n", "niskey", "109.107.179.131", 0);
 *	exit(1);
 * } 
 * if((fe_attr = fe_ent_add_attr_val(HostTable, 
 *					fe_entry, 
 *					"NISVALUE", 
 *					strlen("olivaw OLIVAW oLiVaW # regis Host") +1, 
 *					"olivaw OLIVAW oLiVaW # regis Host")) == NULL)
 * {
 *	ldaplog(...);
 *	exit(1);
 * }
 * if((lentry = fe_trans_all_fe2sunds(HostTable, fe_entry)) ==NULL)
 * {
 *	ldaplog(LDAP_DEBUG_CONFIG,".... \n", 0);
 * }
 *
 */

#endif /* _FE_H */




