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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#include "impl.h"
#include "asn1.h"
#include "node.h"

#include "snmpdx_stub.h"


Subid subid_table[] = {
/*      0 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 1,
/*     10 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 2,
/*     20 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 3,
/*     30 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 4,
/*     40 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 5,
/*     50 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 6,
/*     60 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 7,
/*     70 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 1,
/*     82 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 2,
/*     94 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 3,
/*    106 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 4,
/*    118 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 5,
/*    130 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 6,
/*    142 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 7,
/*    154 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 8,
/*    166 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 9,
/*    178 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 10,
/*    190 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 11,
/*    202 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 8, 1, 12,
/*    214 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 9,
/*    224 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 10, 1, 1,
/*    236 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 10, 1, 2,
/*    248 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 10, 1, 3,
/*    260 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 10, 1, 4,
/*    272 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 10, 1, 5,
/*    284 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 10, 1, 6,
/*    296 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 10, 1, 7,
/*    308 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 10, 1, 8,
/*    320 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 11,
/*    330 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 12, 1, 1,
/*    342 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 12, 1, 2,
/*    354 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 12, 1, 3,
/*    366 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 12, 1, 4,
/*    378 */ 1, 3, 6, 1, 4, 1, 42, 2, 15, 13,
0
};
int subid_table_size = 388;

Enum enum_table[] = {
/*      0 */ { &enum_table[   1], "active", 1 },
/*      1 */ { &enum_table[   2], "inactive", 2 },
/*      2 */ { &enum_table[   3], "init", 3 },
/*      3 */ { &enum_table[   4], "load", 4 },
/*      4 */ {              NULL, "destroy", 5 },
/*      5 */ { &enum_table[   6], "active", 1 },
/*      6 */ {              NULL, "inactive", 2 },
/*      7 */ { &enum_table[   8], "active", 1 },
/*      8 */ {              NULL, "inactive", 2 },
{ NULL, NULL, 0 }
};
int enum_table_size = 9;

Object object_table[] = {
/*      0 */ { { &subid_table[0], 10 }, STRING, NULL, READ_FLAG | WRITE_FLAG, 1, get_relayProcessIDFile, set_relayProcessIDFile,free_relayProcessIDFile },
/*      1 */ { { &subid_table[10], 10 }, STRING, NULL, READ_FLAG | WRITE_FLAG, 1, get_relayResourceFile, set_relayResourceFile,free_relayResourceFile },
/*      2 */ { { &subid_table[20], 10 }, STRING, NULL, READ_FLAG | WRITE_FLAG, 1, get_relayPersonalFileDir, set_relayPersonalFileDir,free_relayPersonalFileDir },
/*      3 */ { { &subid_table[30], 10 }, INTEGER, NULL, READ_FLAG, 1, get_relayTrapPort, NULL,NULL },
/*      4 */ { { &subid_table[40], 10 }, STRING, NULL, READ_FLAG | WRITE_FLAG,1, get_relayCheckPoint, set_relayCheckPoint,free_relayCheckPoint },
/*      5 */ { { &subid_table[50], 10 }, INTEGER, NULL, READ_FLAG, 1, get_relayPollInterval, NULL,NULL },
/*      6 */ { { &subid_table[60], 10 }, INTEGER, NULL, READ_FLAG, 1, get_relayMaxAgentTimeOut, NULL,NULL },
/*      7 */ { { &subid_table[214], 10 }, INTEGER, NULL, READ_FLAG | WRITE_FLAG, 1, get_agentTableIndex, set_agentTableIndex,NULL },
/*      8 */ { { &subid_table[320], 10 }, INTEGER, NULL, READ_FLAG, 1, get_regTblTableIndex, NULL,NULL },
/*      9 */ { { &subid_table[378], 10 }, INTEGER, NULL, READ_FLAG, 1, get_regTreeTableIndex, NULL,NULL },
{ { NULL, 0}, 0, NULL, 0, NULL, NULL }
};
int object_table_size = 10;

Index index_table[] = {
/*      0 */ {              NULL, "agentID",3,0, &node_table[28] },
/*      1 */ { &index_table[   2], "regTblAgentID",3,0, &node_table[44] },
/*      2 */ {              NULL, "regTblIndex",3,0, &node_table[43] },
/*      3 */ { &index_table[   4], "regTreeAgentID",3,0, &node_table[55] },
/*      4 */ {              NULL, "regTreeIndex",3,0, &node_table[54] },
{ NULL, NULL, NULL }
};
int index_table_size = 5;

Entry entry_table[] = {
/*      0 */ { &index_table[0], 1, get_agentEntry, free_agentEntry },
/*      1 */ { &index_table[1], 2, get_regTblEntry, free_regTblEntry },
/*      2 */ { &index_table[3], 2, get_regTreeEntry, free_regTreeEntry },
{ NULL, 0, NULL }
};
int entry_table_size = 3;

Column column_table[] = {
/*      0 */ { { &subid_table[70], 12 }, INTEGER, NULL, READ_FLAG, 2, NULL, NULL,  &entry_table[0], 0 },
/*      1 */ { { &subid_table[82], 12 }, INTEGER, &enum_table[0], READ_FLAG | WRITE_FLAG, 2, NULL, set_agentStatus, &entry_table[0], 4 },
/*      2 */ { { &subid_table[94], 12 }, INTEGER, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_agentTimeOut, &entry_table[0], 8 },
/*      3 */ { { &subid_table[106], 12 }, INTEGER, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_agentPortNumber, &entry_table[0], 12 },
/*      4 */ { { &subid_table[118], 12 }, STRING, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_agentPersonalFile, &entry_table[0], 16 },
/*      5 */ { { &subid_table[130], 12 }, STRING, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_agentConfigFile, &entry_table[0], 24 },
/*      6 */ { { &subid_table[142], 12 }, STRING, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_agentExecutable, &entry_table[0], 32 },
/*      7 */ { { &subid_table[154], 12 }, STRING, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_agentVersionNum, &entry_table[0], 40 },
/*      8 */ { { &subid_table[166], 12 }, INTEGER, NULL, READ_FLAG | WRITE_FLAG, 2, NULL,set_agentProcessID, &entry_table[0], 48 },
/*      9 */ { { &subid_table[178], 12 }, STRING, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_agentName, &entry_table[0], 52 },
/*     10 */ { { &subid_table[190], 12 }, TIMETICKS, NULL, READ_FLAG | WRITE_FLAG, 2, NULL,set_agentSystemUpTime, &entry_table[0], 60 },
/*     11 */ { { &subid_table[202], 12 }, INTEGER, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_agentWatchDogTime, &entry_table[0], 64 },
/*     12 */ { { &subid_table[224], 12 }, INTEGER, NULL, READ_FLAG, 2, NULL, NULL, &entry_table[1], 0 },
/*     13 */ { { &subid_table[236], 12 }, INTEGER, NULL, READ_FLAG, 2, NULL, NULL, &entry_table[1], 4 },
/*     14 */ { { &subid_table[248], 12 }, OBJID, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_regTblOID, &entry_table[1], 8 },
/*     15 */ { { &subid_table[260], 12 }, INTEGER, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_regTblStartColumn, &entry_table[1], 16 },
/*     16 */ { { &subid_table[272], 12 }, INTEGER, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_regTblEndColumn, &entry_table[1], 20 },
/*     17 */ { { &subid_table[284], 12 }, INTEGER, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_regTblStartRow, &entry_table[1], 24 },
/*     18 */ { { &subid_table[296], 12 }, INTEGER, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_regTblEndRow, &entry_table[1], 28 },
/*     19 */ { { &subid_table[308], 12 }, INTEGER, &enum_table[5], READ_FLAG | WRITE_FLAG, 2, NULL, set_regTblStatus, &entry_table[1], 32 },
/*     20 */ { { &subid_table[330], 12 }, INTEGER, NULL, READ_FLAG, 2, NULL, NULL, &entry_table[2], 0 },
/*     21 */ { { &subid_table[342], 12 }, INTEGER, NULL, READ_FLAG, 2, NULL, NULL, &entry_table[2], 4 },
/*     22 */ { { &subid_table[354], 12 }, OBJID, NULL, READ_FLAG | WRITE_FLAG, 2, NULL, set_regTreeOID, &entry_table[2], 8 },
/*     23 */ { { &subid_table[366], 12 }, INTEGER, &enum_table[7], READ_FLAG | WRITE_FLAG, 2, NULL, set_regTreeStatus, &entry_table[2], 16 },
{ { NULL, 0}, 0, NULL, 0, NULL, NULL, NULL , 0 }
};
int column_table_size = 24;

Node node_table[] = {
/*      0 */ {              NULL, &node_table[   1],              NULL, &node_table[  19], "iso", 1, NODE, NULL },
/*      1 */ { &node_table[   0], &node_table[   2],              NULL, &node_table[  19], "org", 3, NODE, NULL },
/*      2 */ { &node_table[   1], &node_table[   3],              NULL, &node_table[  19], "dod", 6, NODE, NULL },
/*      3 */ { &node_table[   2], &node_table[   4],              NULL, &node_table[  19], "internet", 1, NODE, NULL },
/*      4 */ { &node_table[   3],              NULL, &node_table[   5], &node_table[  19], "directory", 1, NODE, NULL },
/*      5 */ { &node_table[   3], &node_table[   6], &node_table[   7], &node_table[  19], "mgmt", 2, NODE, NULL },
/*      6 */ { &node_table[   5],              NULL,              NULL, &node_table[  19], "mib-2", 1, NODE, NULL },
/*      7 */ { &node_table[   3],              NULL, &node_table[   8], &node_table[  19], "experimental", 3, NODE, NULL },
/*      8 */ { &node_table[   3], &node_table[   9], &node_table[  61], &node_table[  19], "private", 4, NODE, NULL },
/*      9 */ { &node_table[   8], &node_table[  10],              NULL, &node_table[  19], "enterprises", 1, NODE, NULL },
/*     10 */ { &node_table[   9], &node_table[  11], &node_table[  60], &node_table[  19], "sun", 42, NODE, NULL },
/*     11 */ { &node_table[  10], &node_table[  12], &node_table[  59], &node_table[  19], "products", 2, NODE, NULL },
/*     12 */ { &node_table[  11], &node_table[  13], &node_table[  18], &node_table[  19], "messaging", 8, NODE, NULL },
/*     13 */ { &node_table[  12], &node_table[  14], &node_table[  17], &node_table[  19], "agents", 1, NODE, NULL },
/*     14 */ { &node_table[  13],              NULL, &node_table[  15], &node_table[  19], "snmpx400d", 1, NODE, NULL },
/*     15 */ { &node_table[  13],              NULL, &node_table[  16], &node_table[  19], "snmpxapiad", 2, NODE, NULL },
/*     16 */ { &node_table[  13],              NULL,              NULL, &node_table[  19], "snmpx500d", 3, NODE, NULL },
/*     17 */ { &node_table[  12],              NULL,              NULL, &node_table[  19], "private-mibs", 2, NODE, NULL },
/*     18 */ { &node_table[  11], &node_table[  19],              NULL, &node_table[  19], "relay-agent", 15, NODE, NULL },
/*     19 */ { &node_table[  18],              NULL, &node_table[  20], &node_table[  20], "relayProcessIDFile", 1, OBJECT, (void *) &object_table[0] },
/*     20 */ { &node_table[  18],              NULL, &node_table[  21], &node_table[  21], "relayResourceFile", 2, OBJECT, (void *) &object_table[1] },
/*     21 */ { &node_table[  18],              NULL, &node_table[  22], &node_table[  22], "relayPersonalFileDir", 3, OBJECT, (void *) &object_table[2] },
/*     22 */ { &node_table[  18],              NULL, &node_table[  23], &node_table[  23], "relayTrapPort", 4, OBJECT, (void *) &object_table[3] },
/*     23 */ { &node_table[  18],              NULL, &node_table[  24], &node_table[  24], "relayCheckPoint", 5, OBJECT, (void *) &object_table[4] },
/*     24 */ { &node_table[  18],              NULL, &node_table[  25], &node_table[  25], "relayPollInterval", 6, OBJECT, (void *) &object_table[5] },
/*     25 */ { &node_table[  18],              NULL, &node_table[  26], &node_table[  28], "relayMaxAgentTimeOut", 7, OBJECT, (void *) &object_table[6] },
/*     26 */ { &node_table[  18], &node_table[  27], &node_table[  40], &node_table[  28], "agentTable", 8, NODE, NULL },
/*     27 */ { &node_table[  26], &node_table[  28],              NULL, &node_table[  28], "agentEntry", 1, NODE, NULL },
/*     28 */ { &node_table[  27],              NULL, &node_table[  29], &node_table[  29], "agentID", 1, COLUMN, (void *) &column_table[0] },
/*     29 */ { &node_table[  27],              NULL, &node_table[  30], &node_table[  30], "agentStatus", 2, COLUMN, (void *) &column_table[1] },
/*     30 */ { &node_table[  27],              NULL, &node_table[  31], &node_table[  31], "agentTimeOut", 3, COLUMN, (void *) &column_table[2] },
/*     31 */ { &node_table[  27],              NULL, &node_table[  32], &node_table[  32], "agentPortNumber", 4, COLUMN, (void *) &column_table[3] },
/*     32 */ { &node_table[  27],              NULL, &node_table[  33], &node_table[  33], "agentPersonalFile", 5, COLUMN, (void *) &column_table[4] },
/*     33 */ { &node_table[  27],              NULL, &node_table[  34], &node_table[  34], "agentConfigFile", 6, COLUMN, (void *) &column_table[5] },
/*     34 */ { &node_table[  27],              NULL, &node_table[  35], &node_table[  35], "agentExecutable", 7, COLUMN, (void *) &column_table[6] },
/*     35 */ { &node_table[  27],              NULL, &node_table[  36], &node_table[  36], "agentVersionNum", 8, COLUMN, (void *) &column_table[7] },
/*     36 */ { &node_table[  27],              NULL, &node_table[  37], &node_table[  37], "agentProcessID", 9, COLUMN, (void *) &column_table[8] },
/*     37 */ { &node_table[  27],              NULL, &node_table[  38], &node_table[  38], "agentName", 10, COLUMN, (void *) &column_table[9] },
/*     38 */ { &node_table[  27],              NULL, &node_table[  39], &node_table[  39], "agentSystemUpTime", 11, COLUMN, (void *) &column_table[10] },
/*     39 */ { &node_table[  27],              NULL,              NULL, &node_table[  40], "agentWatchDogTime", 12, COLUMN, (void *) &column_table[11] },
/*     40 */ { &node_table[  18],              NULL, &node_table[  41], &node_table[  43], "agentTableIndex", 9, OBJECT, (void *) &object_table[7] },
/*     41 */ { &node_table[  18], &node_table[  42], &node_table[  51], &node_table[  43], "regTblTable", 10, NODE, NULL },
/*     42 */ { &node_table[  41], &node_table[  43],              NULL, &node_table[  43], "regTblEntry", 1, NODE, NULL },
/*     43 */ { &node_table[  42],              NULL, &node_table[  44], &node_table[  44], "regTblIndex", 1, COLUMN, (void *) &column_table[12] },
/*     44 */ { &node_table[  42],              NULL, &node_table[  45], &node_table[  45], "regTblAgentID", 2, COLUMN, (void *) &column_table[13] },
/*     45 */ { &node_table[  42],              NULL, &node_table[  46], &node_table[  46], "regTblOID", 3, COLUMN, (void *) &column_table[14] },
/*     46 */ { &node_table[  42],              NULL, &node_table[  47], &node_table[  47], "regTblStartColumn", 4, COLUMN, (void *) &column_table[15] },
/*     47 */ { &node_table[  42],              NULL, &node_table[  48], &node_table[  48], "regTblEndColumn", 5, COLUMN, (void *) &column_table[16] },
/*     48 */ { &node_table[  42],              NULL, &node_table[  49], &node_table[  49], "regTblStartRow", 6, COLUMN, (void *) &column_table[17] },
/*     49 */ { &node_table[  42],              NULL, &node_table[  50], &node_table[  50], "regTblEndRow", 7, COLUMN, (void *) &column_table[18] },
/*     50 */ { &node_table[  42],              NULL,              NULL, &node_table[  51], "regTblStatus", 8, COLUMN, (void *) &column_table[19] },
/*     51 */ { &node_table[  18],              NULL, &node_table[  52], &node_table[  54], "regTblTableIndex", 11, OBJECT, (void *) &object_table[8] },
/*     52 */ { &node_table[  18], &node_table[  53], &node_table[  58], &node_table[  54], "regTreeTable", 12, NODE, NULL },
/*     53 */ { &node_table[  52], &node_table[  54],              NULL, &node_table[  54], "regTreeEntry", 1, NODE, NULL },
/*     54 */ { &node_table[  53],              NULL, &node_table[  55], &node_table[  55], "regTreeIndex", 1, COLUMN, (void *) &column_table[20] },
/*     55 */ { &node_table[  53],              NULL, &node_table[  56], &node_table[  56], "regTreeAgentID", 2, COLUMN, (void *) &column_table[21] },
/*     56 */ { &node_table[  53],              NULL, &node_table[  57], &node_table[  57], "regTreeOID", 3, COLUMN, (void *) &column_table[22] },
/*     57 */ { &node_table[  53],              NULL,              NULL, &node_table[  58], "regTreeStatus", 4, COLUMN, (void *) &column_table[23] },
/*     58 */ { &node_table[  18],              NULL,              NULL,              NULL, "regTreeTableIndex", 13, OBJECT, (void *) &object_table[9] },
/*     59 */ { &node_table[  10],              NULL,              NULL,              NULL, "products", 2, NODE, NULL },
/*     60 */ { &node_table[   9],              NULL,              NULL,              NULL, "sun", 42, NODE, NULL },
/*     61 */ { &node_table[   3],              NULL, &node_table[  62],              NULL, "security", 5, NODE, NULL },
/*     62 */ { &node_table[   3], &node_table[  63],              NULL,              NULL, "snmpV2", 6, NODE, NULL },
/*     63 */ { &node_table[  62],              NULL, &node_table[  64],              NULL, "snmpDomains", 1, NODE, NULL },
/*     64 */ { &node_table[  62],              NULL, &node_table[  65],              NULL, "snmpProxys", 2, NODE, NULL },
/*     65 */ { &node_table[  62],              NULL,              NULL,              NULL, "snmpModules", 3, NODE, NULL },
{ NULL, NULL, NULL, NULL, NULL, 0, 0, NULL }
};
int node_table_size = 66;

