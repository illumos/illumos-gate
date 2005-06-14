/*
 * Copyright (C) 2002 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */

#include "ipf.h"

#define	PRINTF	(void)printf
#define	FPRINTF	(void)fprintf


iphtable_t *printhash(hp, copyfunc, opts)
iphtable_t *hp;
copyfunc_t copyfunc;
int opts;
{
	iphtent_t *ipep;
	iphtable_t iph;
	int i;

	if ((*copyfunc)((char *)hp, (char *)&iph, sizeof(iph)))
		return NULL;

	if ((opts & OPT_DEBUG) == 0) {
		if ((iph.iph_type & IPHASH_ANON) == IPHASH_ANON)
			PRINTF("# 'anonymous' table\n");
		switch (iph.iph_type & ~IPHASH_ANON)
		{
		case IPHASH_LOOKUP :
			PRINTF("table");
			break;
		case IPHASH_GROUPMAP :
			PRINTF("group-map");
			if (iph.iph_flags & FR_INQUE)
				PRINTF(" in");
			else if (iph.iph_flags & FR_OUTQUE)
				PRINTF(" out");
			else
				PRINTF(" ???");
			break;
		default :
			PRINTF("%#x", iph.iph_type);
			break;
		}
		PRINTF(" role = ");
	} else {
		PRINTF("Hash Table Number: %s", iph.iph_name);
		if ((iph.iph_type & IPHASH_ANON) == IPHASH_ANON)
			PRINTF("(anon)");
		putchar(' ');
		PRINTF("Role: ");
	}

	switch (iph.iph_unit)
	{
	case IPL_LOGNAT :
		PRINTF("nat");
		break;
	case IPL_LOGIPF :
		PRINTF("ipf");
		break;
	case IPL_LOGAUTH :
		PRINTF("auth");
		break;
	case IPL_LOGCOUNT :
		PRINTF("count");
		break;
	default :
		PRINTF("#%d", iph.iph_unit);
		break;
	}

	if ((opts & OPT_DEBUG) == 0) {
		if ((iph.iph_type & ~IPHASH_ANON) == IPHASH_LOOKUP)
			PRINTF(" type = hash");
		PRINTF(" number = %s size = %u",
			iph.iph_name, iph.iph_size);
		if (iph.iph_seed != 0)
			PRINTF(" seed = %lu", iph.iph_seed);
		putchar('\n');
	} else {
		PRINTF(" Type: ");
		switch (iph.iph_type & ~IPHASH_ANON)
		{
		case IPHASH_LOOKUP :
			PRINTF("lookup");
			break;
		case IPHASH_GROUPMAP :
			PRINTF("groupmap Group. %s", iph.iph_name);
			break;
		default :
			break;
		}

		putchar('\n');
		PRINTF("\tSize: %d\tSeed: %lu", iph.iph_size, iph.iph_seed);
		PRINTF("\tRef. Count: %d\tMasks: %d\n", iph.iph_ref,
			iph.iph_masks);
	}

	if ((opts & OPT_DEBUG) != 0) {
		u_32_t m;

		for (i = 0; i < 33; i++) {
			ntomask(4, i, &m);
			if (m & iph.iph_masks)
				PRINTF("Mask: %#x\n", m);
		}
	}

	PRINTF("\t{");

	for (i = 0; i < iph.iph_size; i++)
		for (ipep = iph.iph_table[i]; ipep != NULL; )
			ipep = printhashnode(&iph, ipep, copyfunc, opts);

	PRINTF(" };\n");

	return iph.iph_next;
}
