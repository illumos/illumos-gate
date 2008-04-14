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
 * Copyright 2008 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FPTEST_H
#define	_FPTEST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

struct LapaGroup {
	int groupType;	/* 1, 2, 3 low/med/high */
	int limLow;		/* starting Lapack size */
	int limHigh;	/* end Lapack size */
	int timeLIM;	/* expected time interval (ms) */
};

/*
 *
 * f\p\t| 100  200   300   400    500     600     700     800     900
 * ======================================================================
 * 1000  1-28 29-49 50-62 63-72  73-81   82-90   91-98   99-105  106-112
 * 1500  1-36 37-64 65-80 81-93  94-106  107-115 116-126 127-134 135-144
 * 2000  1-39 40-70 71-87 88-102 103-114 115-126 127-137 138-148 149-157
 */


/*
 * 1000 = this groups will be used for procs
 * considered to be equivalent with USIII+ 900MHz
 */
static struct LapaGroup LowStressLapaGroup_1000[] = {
{0, 0, 0, 0},
{1, 1, 41, 100}, /* Single+Double  G1 L1 rt=102 */
{1, 42, 67, 100}, /* Single+Double  G1 L2 rt=101 */
{1, 68, 82, 100}, /* Single+Double  G1 L3 rt=105 */
{1, 83, 93, 100}, /* Single+Double  G1 L4 rt=106 */
{1, 94, 102, 100}, /* Single+Double  G1 L5 rt=108 */
{1, 103, 110, 100}, /* Single+Double  G1 L6 rt=114 */
{1, 111, 117, 100}, /* Single+Double  G1 L7 rt=115 */
{1, 118, 123, 100}, /* Single+Double  G1 L8 rt=112 */
{1, 124, 128, 100}, /* Single+Double  G1 L9 rt=101 */
{1, 129, 133, 100}, /* Single+Double  G1 L10 rt=110 */
{1, 134, 138, 100}, /* Single+Double  G1 L11 rt=119 */
{1, 139, 142, 100}, /* Single+Double  G1 L12 rt=102 */
{1, 143, 146, 100}, /* Single+Double  G1 L13 rt=108 */
{1, 147, 150, 100}, /* Single+Double  G1 L14 rt=115 */
{1, 151, 154, 100}, /* Single+Double  G1 L15 rt=121 */
{1, 155, 158, 100}, /* Single+Double  G1 L16 rt=128 */
{1, 159, 161, 100}, /* Single+Double  G1 L17 rt=101 */
{1, 162, 164, 100}, /* Single+Double  G1 L18 rt=105 */
{1, 165, 167, 100}, /* Single+Double  G1 L19 rt=109 */
{1, 168, 170, 100}, /* Single+Double  G1 L20 rt=113 */
{1, 171, 173, 100}, /* Single+Double  G1 L21 rt=118 */
{1, 174, 176, 100}, /* Single+Double  G1 L22 rt=122 */
{1, 177, 179, 100}, /* Single+Double  G1 L23 rt=127 */
{1, 180, 182, 100}, /* Single+Double  G1 L24 rt=131 */
{1, 183, 185, 100}, /* Single+Double  G1 L25 rt=137 */
{1, 186, 188, 100}, /* Single+Double  G1 L26 rt=141 */
{1, 189, 191, 100}, /* Single+Double  G1 L27 rt=146 */
{1, 192, 194, 100}, /* Single+Double  G1 L28 rt=151 */
{1, 195, 198, 200}, /* Single+Double  G1 L29 rt=210 */
{1, 199, 202, 200}, /* Single+Double  G1 L30 rt=220 */
{1, 203, 206, 200}, /* Single+Double  G1 L31 rt=230 */
{1, 207, 210, 200}, /* Single+Double  G1 L32 rt=239 */
{1, 211, 214, 200}, /* Single+Double  G1 L33 rt=249 */
{1, 215, 218, 200}, /* Single+Double  G1 L34 rt=259 */
{1, 219, 221, 200}, /* Single+Double  G1 L35 rt=201 */
{1, 222, 224, 200}, /* Single+Double  G1 L36 rt=207 */
{1, 225, 227, 200}, /* Single+Double  G1 L37 rt=214 */
{1, 228, 230, 200}, /* Single+Double  G1 L38 rt=219 */
{1, 231, 233, 200}, /* Single+Double  G1 L39 rt=226 */
{1, 234, 236, 200}, /* Single+Double  G1 L40 rt=232 */
{1, 237, 239, 200}, /* Single+Double  G1 L41 rt=240 */
{1, 240, 242, 200}, /* Single+Double  G1 L42 rt=244 */
{1, 243, 245, 200}, /* Single+Double  G1 L43 rt=252 */
{1, 246, 248, 200}, /* Single+Double  G1 L44 rt=262 */
{1, 249, 251, 200}, /* Single+Double  G1 L45 rt=269 */
{1, 252, 254, 200}, /* Single+Double  G1 L46 rt=273 */
{1, 255, 257, 200}, /* Single+Double  G1 L47 rt=280 */
{1, 258, 260, 200}, /* Single+Double  G1 L48 rt=287 */
{1, 261, 263, 200}, /* Single+Double  G1 L49 rt=296 */
{1, 264, 266, 300}, /* Single+Double  G1 L50 rt=303 */
{1, 267, 269, 300}, /* Single+Double  G1 L51 rt=311 */
{1, 270, 272, 300}, /* Single+Double  G1 L52 rt=318 */
{1, 273, 275, 300}, /* Single+Double  G1 L53 rt=327 */
{1, 276, 278, 300}, /* Single+Double  G1 L54 rt=333 */
{1, 279, 281, 300}, /* Single+Double  G1 L55 rt=342 */
{1, 282, 284, 300}, /* Single+Double  G1 L56 rt=350 */
{1, 285, 287, 300}, /* Single+Double  G1 L57 rt=361 */
{1, 288, 290, 300}, /* Single+Double  G1 L58 rt=365 */
{1, 291, 293, 300}, /* Single+Double  G1 L59 rt=375 */
{1, 294, 296, 300}, /* Single+Double  G1 L60 rt=383 */
{1, 297, 299, 300}, /* Single+Double  G1 L61 rt=393 */
{1, 300, 302, 300}, /* Single+Double  G1 L62 rt=400 */
{1, 303, 305, 400}, /* Single+Double  G1 L63 rt=409 */
{1, 306, 308, 400}, /* Single+Double  G1 L64 rt=418 */
{1, 309, 311, 400}, /* Single+Double  G1 L65 rt=430 */
{1, 312, 314, 400}, /* Single+Double  G1 L66 rt=438 */
{1, 315, 317, 400}, /* Single+Double  G1 L67 rt=447 */
{1, 318, 320, 400}, /* Single+Double  G1 L68 rt=455 */
{1, 321, 323, 400}, /* Single+Double  G1 L69 rt=468 */
{1, 324, 326, 400}, /* Single+Double  G1 L70 rt=475 */
{1, 327, 329, 400}, /* Single+Double  G1 L71 rt=485 */
{1, 330, 332, 400}, /* Single+Double  G1 L72 rt=496 */
{1, 333, 335, 500}, /* Single+Double  G1 L73 rt=513 */
{1, 336, 338, 500}, /* Single+Double  G1 L74 rt=516 */
{1, 339, 341, 500}, /* Single+Double  G1 L75 rt=526 */
{1, 342, 344, 500}, /* Single+Double  G1 L76 rt=537 */
{1, 345, 347, 500}, /* Single+Double  G1 L77 rt=550 */
{1, 348, 350, 500}, /* Single+Double  G1 L78 rt=557 */
{1, 351, 353, 500}, /* Single+Double  G1 L79 rt=568 */
{1, 354, 356, 500}, /* Single+Double  G1 L80 rt=578 */
{1, 357, 359, 500}, /* Single+Double  G1 L81 rt=594 */
{1, 360, 362, 600}, /* Single+Double  G1 L82 rt=601 */
{1, 363, 365, 600}, /* Single+Double  G1 L83 rt=613 */
{1, 366, 368, 600}, /* Single+Double  G1 L84 rt=624 */
{1, 369, 371, 600}, /* Single+Double  G1 L85 rt=638 */
{1, 372, 374, 600}, /* Single+Double  G1 L86 rt=647 */
{1, 375, 377, 600}, /* Single+Double  G1 L87 rt=664 */
{1, 378, 380, 600}, /* Single+Double  G1 L88 rt=672 */
{1, 381, 383, 600}, /* Single+Double  G1 L89 rt=688 */
{1, 384, 386, 600}, /* Single+Double  G1 L90 rt=696 */
{1, 387, 389, 700}, /* Single+Double  G1 L91 rt=708 */
{1, 390, 392, 700}, /* Single+Double  G1 L92 rt=720 */
{1, 393, 395, 700}, /* Single+Double  G1 L93 rt=737 */
{1, 396, 398, 700}, /* Single+Double  G1 L94 rt=746 */
{1, 399, 401, 700}, /* Single+Double  G1 L95 rt=760 */
{1, 402, 404, 700}, /* Single+Double  G1 L96 rt=774 */
{1, 405, 407, 700}, /* Single+Double  G1 L97 rt=789 */
{1, 408, 410, 700}, /* Single+Double  G1 L98 rt=797 */
{1, 411, 413, 800}, /* Single+Double  G1 L99 rt=810 */
{1, 414, 416, 800}, /* Single+Double  G1 L100 rt=824 */
{1, 417, 419, 800}, /* Single+Double  G1 L101 rt=843 */
{1, 420, 422, 800}, /* Single+Double  G1 L102 rt=850 */
{1, 423, 425, 800}, /* Single+Double  G1 L103 rt=865 */
{1, 426, 428, 800}, /* Single+Double  G1 L104 rt=877 */
{1, 429, 431, 800}, /* Single+Double  G1 L105 rt=900 */
{1, 432, 434, 900}, /* Single+Double  G1 L106 rt=906 */
{1, 435, 437, 900}, /* Single+Double  G1 L107 rt=921 */
{1, 438, 440, 900}, /* Single+Double  G1 L108 rt=938 */
{1, 441, 443, 900}, /* Single+Double  G1 L109 rt=957 */
{1, 444, 446, 900}, /* Single+Double  G1 L110 rt=966 */
{1, 447, 449, 900}, /* Single+Double  G1 L111 rt=983 */
{1, 450, 452, 900}, /* Single+Double  G1 L112 rt=995 */

/* Always is the last one */
{0,  0,  0,  0}
}; /* LowStressLapaGroup_1000 */

/*
 * 1500 = this groups will be used for procs
 * considered to be equivalent with panther 1500MHz
 */
static struct LapaGroup LowStressLapaGroup_1500[] = {
{0, 0, 0, 0},
{1, 1, 61, 100}, /* Single+Double  G1 L1 rt=103 */
{1, 62, 88, 100}, /* Single+Double  G1 L2 rt=105 */
{1, 89, 104, 100}, /* Single+Double  G1 L3 rt=102 */
{1, 105, 117, 100}, /* Single+Double  G1 L4 rt=110 */
{1, 118, 127, 100}, /* Single+Double  G1 L5 rt=104 */
{1, 128, 136, 100}, /* Single+Double  G1 L6 rt=109 */
{1, 137, 144, 100}, /* Single+Double  G1 L7 rt=110 */
{1, 145, 151, 100}, /* Single+Double  G1 L8 rt=108 */
{1, 152, 157, 100}, /* Single+Double  G1 L9 rt=101 */
{1, 158, 163, 100}, /* Single+Double  G1 L10 rt=110 */
{1, 164, 169, 100}, /* Single+Double  G1 L11 rt=118 */
{1, 170, 174, 100}, /* Single+Double  G1 L12 rt=106 */
{1, 175, 179, 100}, /* Single+Double  G1 L13 rt=112 */
{1, 180, 184, 100}, /* Single+Double  G1 L14 rt=119 */
{1, 185, 189, 100}, /* Single+Double  G1 L15 rt=127 */
{1, 190, 193, 100}, /* Single+Double  G1 L16 rt=106 */
{1, 194, 197, 100}, /* Single+Double  G1 L17 rt=112 */
{1, 198, 201, 100}, /* Single+Double  G1 L18 rt=117 */
{1, 202, 205, 100}, /* Single+Double  G1 L19 rt=122 */
{1, 206, 209, 100}, /* Single+Double  G1 L20 rt=127 */
{1, 210, 213, 100}, /* Single+Double  G1 L21 rt=132 */
{1, 214, 216, 100}, /* Single+Double  G1 L22 rt=102 */
{1, 217, 219, 100}, /* Single+Double  G1 L23 rt=106 */
{1, 220, 222, 100}, /* Single+Double  G1 L24 rt=109 */
{1, 223, 225, 100}, /* Single+Double  G1 L25 rt=112 */
{1, 226, 228, 100}, /* Single+Double  G1 L26 rt=115 */
{1, 229, 231, 100}, /* Single+Double  G1 L27 rt=119 */
{1, 232, 234, 100}, /* Single+Double  G1 L28 rt=122 */
{1, 235, 237, 100}, /* Single+Double  G1 L29 rt=125 */
{1, 238, 240, 100}, /* Single+Double  G1 L30 rt=129 */
{1, 241, 243, 100}, /* Single+Double  G1 L31 rt=133 */
{1, 244, 246, 100}, /* Single+Double  G1 L32 rt=136 */
{1, 247, 249, 100}, /* Single+Double  G1 L33 rt=142 */
{1, 250, 252, 100}, /* Single+Double  G1 L34 rt=144 */
{1, 253, 255, 100}, /* Single+Double  G1 L35 rt=148 */
{1, 256, 258, 100}, /* Single+Double  G1 L36 rt=151 */
{1, 259, 262, 200}, /* Single+Double  G1 L37 rt=208 */
{1, 263, 266, 200}, /* Single+Double  G1 L38 rt=215 */
{1, 267, 270, 200}, /* Single+Double  G1 L39 rt=223 */
{1, 271, 274, 200}, /* Single+Double  G1 L40 rt=230 */
{1, 275, 278, 200}, /* Single+Double  G1 L41 rt=237 */
{1, 279, 282, 200}, /* Single+Double  G1 L42 rt=245 */
{1, 283, 286, 200}, /* Single+Double  G1 L43 rt=253 */
{1, 287, 290, 200}, /* Single+Double  G1 L44 rt=260 */
{1, 291, 293, 200}, /* Single+Double  G1 L45 rt=201 */
{1, 294, 296, 200}, /* Single+Double  G1 L46 rt=205 */
{1, 297, 299, 200}, /* Single+Double  G1 L47 rt=210 */
{1, 300, 302, 200}, /* Single+Double  G1 L48 rt=214 */
{1, 303, 305, 200}, /* Single+Double  G1 L49 rt=219 */
{1, 306, 308, 200}, /* Single+Double  G1 L50 rt=223 */
{1, 309, 311, 200}, /* Single+Double  G1 L51 rt=230 */
{1, 312, 314, 200}, /* Single+Double  G1 L52 rt=234 */
{1, 315, 317, 200}, /* Single+Double  G1 L53 rt=239 */
{1, 318, 320, 200}, /* Single+Double  G1 L54 rt=243 */
{1, 321, 323, 200}, /* Single+Double  G1 L55 rt=250 */
{1, 324, 326, 200}, /* Single+Double  G1 L56 rt=254 */
{1, 327, 329, 200}, /* Single+Double  G1 L57 rt=259 */
{1, 330, 332, 200}, /* Single+Double  G1 L58 rt=264 */
{1, 333, 335, 200}, /* Single+Double  G1 L59 rt=274 */
{1, 336, 338, 200}, /* Single+Double  G1 L60 rt=275 */
{1, 339, 341, 200}, /* Single+Double  G1 L61 rt=281 */
{1, 342, 344, 200}, /* Single+Double  G1 L62 rt=286 */
{1, 345, 347, 200}, /* Single+Double  G1 L63 rt=294 */
{1, 348, 350, 200}, /* Single+Double  G1 L64 rt=298 */
{1, 351, 353, 300}, /* Single+Double  G1 L65 rt=303 */
{1, 354, 356, 300}, /* Single+Double  G1 L66 rt=309 */
{1, 357, 359, 300}, /* Single+Double  G1 L67 rt=317 */
{1, 360, 362, 300}, /* Single+Double  G1 L68 rt=320 */
{1, 363, 365, 300}, /* Single+Double  G1 L69 rt=327 */
{1, 366, 368, 300}, /* Single+Double  G1 L70 rt=333 */
{1, 369, 371, 300}, /* Single+Double  G1 L71 rt=342 */
{1, 372, 374, 300}, /* Single+Double  G1 L72 rt=346 */
{1, 375, 377, 300}, /* Single+Double  G1 L73 rt=355 */
{1, 378, 380, 300}, /* Single+Double  G1 L74 rt=359 */
{1, 381, 383, 300}, /* Single+Double  G1 L75 rt=367 */
{1, 384, 386, 300}, /* Single+Double  G1 L76 rt=371 */
{1, 387, 389, 300}, /* Single+Double  G1 L77 rt=378 */
{1, 390, 392, 300}, /* Single+Double  G1 L78 rt=384 */
{1, 393, 395, 300}, /* Single+Double  G1 L79 rt=394 */
{1, 396, 398, 300}, /* Single+Double  G1 L80 rt=398 */
{1, 399, 401, 400}, /* Single+Double  G1 L81 rt=405 */
{1, 402, 404, 400}, /* Single+Double  G1 L82 rt=413 */
{1, 405, 407, 400}, /* Single+Double  G1 L83 rt=421 */
{1, 408, 410, 400}, /* Single+Double  G1 L84 rt=425 */
{1, 411, 413, 400}, /* Single+Double  G1 L85 rt=433 */
{1, 414, 416, 400}, /* Single+Double  G1 L86 rt=440 */
{1, 417, 419, 400}, /* Single+Double  G1 L87 rt=450 */
{1, 420, 422, 400}, /* Single+Double  G1 L88 rt=454 */
{1, 423, 425, 400}, /* Single+Double  G1 L89 rt=461 */
{1, 426, 428, 400}, /* Single+Double  G1 L90 rt=470 */
{1, 429, 431, 400}, /* Single+Double  G1 L91 rt=481 */
{1, 432, 434, 400}, /* Single+Double  G1 L92 rt=484 */
{1, 435, 437, 400}, /* Single+Double  G1 L93 rt=492 */
{1, 438, 440, 500}, /* Single+Double  G1 L94 rt=501 */
{1, 441, 443, 500}, /* Single+Double  G1 L95 rt=512 */
{1, 444, 446, 500}, /* Single+Double  G1 L96 rt=515 */
{1, 447, 449, 500}, /* Single+Double  G1 L97 rt=524 */
{1, 450, 452, 500}, /* Single+Double  G1 L98 rt=531 */
{1, 453, 455, 500}, /* Single+Double  G1 L99 rt=544 */
{1, 456, 458, 500}, /* Single+Double  G1 L100 rt=548 */
{1, 459, 461, 500}, /* Single+Double  G1 L101 rt=557 */
{1, 462, 464, 500}, /* Single+Double  G1 L102 rt=564 */
{1, 465, 467, 500}, /* Single+Double  G1 L103 rt=578 */
{1, 468, 470, 500}, /* Single+Double  G1 L104 rt=582 */
{1, 471, 473, 500}, /* Single+Double  G1 L105 rt=590 */
{1, 474, 476, 500}, /* Single+Double  G1 L106 rt=599 */
{1, 477, 479, 600}, /* Single+Double  G1 L107 rt=611 */
{1, 480, 482, 600}, /* Single+Double  G1 L108 rt=616 */
{1, 483, 485, 600}, /* Single+Double  G1 L109 rt=626 */
{1, 486, 488, 600}, /* Single+Double  G1 L110 rt=634 */
{1, 489, 491, 600}, /* Single+Double  G1 L111 rt=648 */
{1, 492, 494, 600}, /* Single+Double  G1 L112 rt=652 */
{1, 495, 497, 600}, /* Single+Double  G1 L113 rt=662 */
{1, 498, 500, 600}, /* Single+Double  G1 L114 rt=673 */
{1, 501, 503, 600}, /* Single+Double  G1 L115 rt=697 */
{1, 504, 506, 700}, /* Single+Double  G1 L116 rt=718 */
{1, 507, 509, 700}, /* Single+Double  G1 L117 rt=707 */
{1, 510, 512, 700}, /* Single+Double  G1 L118 rt=714 */
{1, 513, 515, 700}, /* Single+Double  G1 L119 rt=730 */
{1, 516, 518, 700}, /* Single+Double  G1 L120 rt=735 */
{1, 519, 521, 700}, /* Single+Double  G1 L121 rt=745 */
{1, 522, 524, 700}, /* Single+Double  G1 L122 rt=756 */
{1, 525, 527, 700}, /* Single+Double  G1 L123 rt=772 */
{1, 528, 530, 700}, /* Single+Double  G1 L124 rt=776 */
{1, 531, 533, 700}, /* Single+Double  G1 L125 rt=789 */
{1, 534, 536, 700}, /* Single+Double  G1 L126 rt=798 */
{1, 537, 539, 800}, /* Single+Double  G1 L127 rt=814 */
{1, 540, 542, 800}, /* Single+Double  G1 L128 rt=820 */
{1, 543, 545, 800}, /* Single+Double  G1 L129 rt=830 */
{1, 546, 548, 800}, /* Single+Double  G1 L130 rt=841 */
{1, 549, 551, 800}, /* Single+Double  G1 L131 rt=856 */
{1, 552, 554, 800}, /* Single+Double  G1 L132 rt=861 */
{1, 555, 557, 800}, /* Single+Double  G1 L133 rt=873 */
{1, 558, 560, 800}, /* Single+Double  G1 L134 rt=883 */
{1, 561, 563, 900}, /* Single+Double  G1 L135 rt=902 */
{1, 564, 566, 900}, /* Single+Double  G1 L136 rt=907 */
{1, 567, 569, 900}, /* Single+Double  G1 L137 rt=922 */
{1, 570, 572, 900}, /* Single+Double  G1 L138 rt=929 */
{1, 573, 575, 900}, /* Single+Double  G1 L139 rt=947 */
{1, 576, 578, 900}, /* Single+Double  G1 L140 rt=954 */
{1, 579, 581, 900}, /* Single+Double  G1 L141 rt=965 */
{1, 582, 584, 900}, /* Single+Double  G1 L142 rt=975 */
{1, 585, 587, 900}, /* Single+Double  G1 L143 rt=994 */
{1, 588, 590, 900}, /* Single+Double  G1 L144 rt=999 */

/* Always is the last one */
{0,  0,  0,  0}
}; /* LowStressLapaGroup_1500 */

/*
 * 2000 = this groups will be used for procs
 * considered to be equivalent with panther 1950MHz
 */
static struct LapaGroup LowStressLapaGroup_2000[] = {
{0, 0, 0, 0},
{1, 1, 82, 100}, /* Single+Double  G1 L1 rt=104 */
{1, 83, 104, 100}, /* Single+Double  G1 L2 rt=104 */
{1, 105, 119, 100}, /* Single+Double  G1 L3 rt=103 */
{1, 120, 131, 100}, /* Single+Double  G1 L4 rt=104 */
{1, 132, 141, 100}, /* Single+Double  G1 L5 rt=103 */
{1, 142, 150, 100}, /* Single+Double  G1 L6 rt=107 */
{1, 151, 158, 100}, /* Single+Double  G1 L7 rt=107 */
{1, 159, 165, 100}, /* Single+Double  G1 L8 rt=104 */
{1, 166, 172, 100}, /* Single+Double  G1 L9 rt=113 */
{1, 173, 178, 100}, /* Single+Double  G1 L10 rt=105 */
{1, 179, 184, 100}, /* Single+Double  G1 L11 rt=113 */
{1, 185, 189, 100}, /* Single+Double  G1 L12 rt=101 */
{1, 190, 194, 100}, /* Single+Double  G1 L13 rt=106 */
{1, 195, 199, 100}, /* Single+Double  G1 L14 rt=113 */
{1, 200, 204, 100}, /* Single+Double  G1 L15 rt=119 */
{1, 205, 209, 100}, /* Single+Double  G1 L16 rt=126 */
{1, 210, 213, 100}, /* Single+Double  G1 L17 rt=105 */
{1, 214, 217, 100}, /* Single+Double  G1 L18 rt=109 */
{1, 218, 221, 100}, /* Single+Double  G1 L19 rt=114 */
{1, 222, 225, 100}, /* Single+Double  G1 L20 rt=118 */
{1, 226, 229, 100}, /* Single+Double  G1 L21 rt=123 */
{1, 230, 233, 100}, /* Single+Double  G1 L22 rt=128 */
{1, 234, 237, 100}, /* Single+Double  G1 L23 rt=133 */
{1, 238, 240, 100}, /* Single+Double  G1 L24 rt=102 */
{1, 241, 243, 100}, /* Single+Double  G1 L25 rt=106 */
{1, 244, 246, 100}, /* Single+Double  G1 L26 rt=108 */
{1, 247, 249, 100}, /* Single+Double  G1 L27 rt=113 */
{1, 250, 252, 100}, /* Single+Double  G1 L28 rt=114 */
{1, 253, 255, 100}, /* Single+Double  G1 L29 rt=118 */
{1, 256, 258, 100}, /* Single+Double  G1 L30 rt=120 */
{1, 259, 261, 100}, /* Single+Double  G1 L31 rt=123 */
{1, 262, 264, 100}, /* Single+Double  G1 L32 rt=126 */
{1, 265, 267, 100}, /* Single+Double  G1 L33 rt=131 */
{1, 268, 270, 100}, /* Single+Double  G1 L34 rt=133 */
{1, 271, 273, 100}, /* Single+Double  G1 L35 rt=136 */
{1, 274, 276, 100}, /* Single+Double  G1 L36 rt=139 */
{1, 277, 279, 100}, /* Single+Double  G1 L37 rt=144 */
{1, 280, 282, 100}, /* Single+Double  G1 L38 rt=146 */
{1, 283, 285, 100}, /* Single+Double  G1 L39 rt=150 */
{1, 286, 289, 200}, /* Single+Double  G1 L40 rt=205 */
{1, 290, 293, 200}, /* Single+Double  G1 L41 rt=212 */
{1, 294, 297, 200}, /* Single+Double  G1 L42 rt=218 */
{1, 298, 301, 200}, /* Single+Double  G1 L43 rt=225 */
{1, 302, 305, 200}, /* Single+Double  G1 L44 rt=231 */
{1, 306, 309, 200}, /* Single+Double  G1 L45 rt=238 */
{1, 310, 313, 200}, /* Single+Double  G1 L46 rt=246 */
{1, 314, 317, 200}, /* Single+Double  G1 L47 rt=253 */
{1, 318, 321, 200}, /* Single+Double  G1 L48 rt=259 */
{1, 322, 325, 200}, /* Single+Double  G1 L49 rt=267 */
{1, 326, 328, 200}, /* Single+Double  G1 L50 rt=204 */
{1, 329, 331, 200}, /* Single+Double  G1 L51 rt=210 */
{1, 332, 334, 200}, /* Single+Double  G1 L52 rt=215 */
{1, 335, 337, 200}, /* Single+Double  G1 L53 rt=218 */
{1, 338, 340, 200}, /* Single+Double  G1 L54 rt=222 */
{1, 341, 343, 200}, /* Single+Double  G1 L55 rt=228 */
{1, 344, 346, 200}, /* Single+Double  G1 L56 rt=230 */
{1, 347, 349, 200}, /* Single+Double  G1 L57 rt=235 */
{1, 350, 352, 200}, /* Single+Double  G1 L58 rt=239 */
{1, 353, 355, 200}, /* Single+Double  G1 L59 rt=246 */
{1, 356, 358, 200}, /* Single+Double  G1 L60 rt=249 */
{1, 359, 361, 200}, /* Single+Double  G1 L61 rt=253 */
{1, 362, 364, 200}, /* Single+Double  G1 L62 rt=258 */
{1, 365, 367, 200}, /* Single+Double  G1 L63 rt=265 */
{1, 368, 370, 200}, /* Single+Double  G1 L64 rt=268 */
{1, 371, 373, 200}, /* Single+Double  G1 L65 rt=273 */
{1, 374, 376, 200}, /* Single+Double  G1 L66 rt=280 */
{1, 377, 379, 200}, /* Single+Double  G1 L67 rt=286 */
{1, 380, 382, 200}, /* Single+Double  G1 L68 rt=288 */
{1, 383, 385, 200}, /* Single+Double  G1 L69 rt=293 */
{1, 386, 388, 200}, /* Single+Double  G1 L70 rt=299 */
{1, 389, 391, 300}, /* Single+Double  G1 L71 rt=306 */
{1, 392, 394, 300}, /* Single+Double  G1 L72 rt=309 */
{1, 395, 397, 300}, /* Single+Double  G1 L73 rt=314 */
{1, 398, 400, 300}, /* Single+Double  G1 L74 rt=320 */
{1, 401, 403, 300}, /* Single+Double  G1 L75 rt=329 */
{1, 404, 406, 300}, /* Single+Double  G1 L76 rt=331 */
{1, 407, 409, 300}, /* Single+Double  G1 L77 rt=336 */
{1, 410, 412, 300}, /* Single+Double  G1 L78 rt=342 */
{1, 413, 415, 300}, /* Single+Double  G1 L79 rt=350 */
{1, 416, 418, 300}, /* Single+Double  G1 L80 rt=353 */
{1, 419, 421, 300}, /* Single+Double  G1 L81 rt=359 */
{1, 422, 424, 300}, /* Single+Double  G1 L82 rt=364 */
{1, 425, 427, 300}, /* Single+Double  G1 L83 rt=373 */
{1, 428, 430, 300}, /* Single+Double  G1 L84 rt=376 */
{1, 431, 433, 300}, /* Single+Double  G1 L85 rt=383 */
{1, 434, 436, 300}, /* Single+Double  G1 L86 rt=389 */
{1, 437, 439, 300}, /* Single+Double  G1 L87 rt=399 */
{1, 440, 442, 400}, /* Single+Double  G1 L88 rt=402 */
{1, 443, 445, 400}, /* Single+Double  G1 L89 rt=408 */
{1, 446, 448, 400}, /* Single+Double  G1 L90 rt=414 */
{1, 449, 451, 400}, /* Single+Double  G1 L91 rt=423 */
{1, 452, 454, 400}, /* Single+Double  G1 L92 rt=427 */
{1, 455, 457, 400}, /* Single+Double  G1 L93 rt=433 */
{1, 458, 460, 400}, /* Single+Double  G1 L94 rt=440 */
{1, 461, 463, 400}, /* Single+Double  G1 L95 rt=450 */
{1, 464, 466, 400}, /* Single+Double  G1 L96 rt=453 */
{1, 467, 469, 400}, /* Single+Double  G1 L97 rt=460 */
{1, 470, 472, 400}, /* Single+Double  G1 L98 rt=467 */
{1, 473, 475, 400}, /* Single+Double  G1 L99 rt=477 */
{1, 476, 478, 400}, /* Single+Double  G1 L100 rt=481 */
{1, 479, 481, 400}, /* Single+Double  G1 L101 rt=487 */
{1, 482, 484, 400}, /* Single+Double  G1 L102 rt=495 */
{1, 485, 487, 500}, /* Single+Double  G1 L103 rt=506 */
{1, 488, 490, 500}, /* Single+Double  G1 L104 rt=508 */
{1, 491, 493, 500}, /* Single+Double  G1 L105 rt=517 */
{1, 494, 496, 500}, /* Single+Double  G1 L106 rt=523 */
{1, 497, 499, 500}, /* Single+Double  G1 L107 rt=536 */
{1, 500, 502, 500}, /* Single+Double  G1 L108 rt=545 */
{1, 503, 505, 500}, /* Single+Double  G1 L109 rt=570 */
{1, 506, 508, 500}, /* Single+Double  G1 L110 rt=561 */
{1, 509, 511, 500}, /* Single+Double  G1 L111 rt=570 */
{1, 512, 514, 500}, /* Single+Double  G1 L112 rt=574 */
{1, 515, 517, 500}, /* Single+Double  G1 L113 rt=582 */
{1, 518, 520, 500}, /* Single+Double  G1 L114 rt=590 */
{1, 521, 523, 600}, /* Single+Double  G1 L115 rt=603 */
{1, 524, 526, 600}, /* Single+Double  G1 L116 rt=608 */
{1, 527, 529, 600}, /* Single+Double  G1 L117 rt=615 */
{1, 530, 532, 600}, /* Single+Double  G1 L118 rt=625 */
{1, 533, 535, 600}, /* Single+Double  G1 L119 rt=638 */
{1, 536, 538, 600}, /* Single+Double  G1 L120 rt=642 */
{1, 539, 541, 600}, /* Single+Double  G1 L121 rt=651 */
{1, 542, 544, 600}, /* Single+Double  G1 L122 rt=659 */
{1, 545, 547, 600}, /* Single+Double  G1 L123 rt=672 */
{1, 548, 550, 600}, /* Single+Double  G1 L124 rt=675 */
{1, 551, 553, 600}, /* Single+Double  G1 L125 rt=684 */
{1, 554, 556, 600}, /* Single+Double  G1 L126 rt=693 */
{1, 557, 559, 700}, /* Single+Double  G1 L127 rt=707 */
{1, 560, 562, 700}, /* Single+Double  G1 L128 rt=712 */
{1, 563, 565, 700}, /* Single+Double  G1 L129 rt=721 */
{1, 566, 568, 700}, /* Single+Double  G1 L130 rt=732 */
{1, 569, 571, 700}, /* Single+Double  G1 L131 rt=745 */
{1, 572, 574, 700}, /* Single+Double  G1 L132 rt=748 */
{1, 575, 577, 700}, /* Single+Double  G1 L133 rt=758 */
{1, 578, 580, 700}, /* Single+Double  G1 L134 rt=768 */
{1, 581, 583, 700}, /* Single+Double  G1 L135 rt=782 */
{1, 584, 586, 700}, /* Single+Double  G1 L136 rt=785 */
{1, 587, 589, 700}, /* Single+Double  G1 L137 rt=795 */
{1, 590, 592, 800}, /* Single+Double  G1 L138 rt=803 */
{1, 593, 595, 800}, /* Single+Double  G1 L139 rt=819 */
{1, 596, 598, 800}, /* Single+Double  G1 L140 rt=821 */
{1, 599, 601, 800}, /* Single+Double  G1 L141 rt=831 */
{1, 602, 604, 800}, /* Single+Double  G1 L142 rt=840 */
{1, 605, 607, 800}, /* Single+Double  G1 L143 rt=858 */
{1, 608, 610, 800}, /* Single+Double  G1 L144 rt=860 */
{1, 611, 613, 800}, /* Single+Double  G1 L145 rt=871 */
{1, 614, 616, 800}, /* Single+Double  G1 L146 rt=880 */
{1, 617, 619, 800}, /* Single+Double  G1 L147 rt=896 */
{1, 620, 622, 800}, /* Single+Double  G1 L148 rt=900 */
{1, 623, 625, 900}, /* Single+Double  G1 L149 rt=911 */
{1, 626, 628, 900}, /* Single+Double  G1 L150 rt=923 */
{1, 629, 631, 900}, /* Single+Double  G1 L151 rt=948 */
{1, 632, 634, 900}, /* Single+Double  G1 L152 rt=955 */
{1, 635, 637, 900}, /* Single+Double  G1 L153 rt=960 */
{1, 638, 640, 900}, /* Single+Double  G1 L154 rt=968 */
{1, 641, 643, 900}, /* Single+Double  G1 L155 rt=985 */
{1, 644, 646, 900}, /* Single+Double  G1 L156 rt=989 */
{1, 647, 649, 900}, /* Single+Double  G1 L157 rt=999 */

/* Always is the last one */
{0,  0,  0,  0}
}; /* LowStressLapaGroup_2000 */

static struct LapaGroup MedStressLapaGroup[] = {
{0, 0, 0, 0},
{2, 1, 153, 1000},    /* G2 L1 */
{2, 154, 192, 1000},  /* G2 L2 */
{2, 193, 219, 1000},  /* G2 L3 */
{2, 220, 240, 1000},  /* G2 L4 */
{2, 241, 258, 1000},  /* G2 L5 */
{2, 259, 274, 1000},  /* G2 L6 */
{2, 275, 288, 1000},  /* G2 L7 */
{2, 289, 301, 1000},  /* G2 L8 */
{2, 302, 313, 1000},  /* G2 L9 */
{2, 314, 324, 1000},  /* G2 L10 */
{2, 325, 334, 1000},  /* G2 L11 */
{2, 335, 343, 1000},  /* G2 L12 */
{2, 344, 352, 1000},  /* G2 L13 */
{2, 353, 361, 1000},  /* G2 L14 */
{2, 362, 369, 1000},  /* G2 L15 */
{2, 370, 377, 1000},  /* G2 L16 */
{2, 378, 384, 1000},  /* G2 L17 */
{2, 385, 391, 1000},  /* G2 L18 */
{2, 392, 398, 1000},  /* G2 L19 */
{2, 399, 405, 1000},  /* G2 L20 */
{2, 406, 411, 1000},  /* G2 L21 */
{2, 412, 417, 1000},  /* G2 L22 */
{2, 418, 423, 1000},  /* G2 L23 */
{2, 424, 429, 1000},  /* G2 L24 */
{2, 430, 435, 1000},  /* G2 L25 */
{2, 436, 441, 1000},  /* G2 L26 */
{2, 442, 446, 1000},  /* G2 L27 */
{2, 447, 451, 1000},  /* G2 L28 */
{2, 452, 456, 1000},  /* G2 L29 */
{2, 457, 461, 1000},  /* G2 L30 */
{2, 462, 466, 1000},  /* G2 L31 */
{2, 467, 471, 1000},  /* G2 L32 */
{2, 472, 476, 1000},  /* G2 L33 */
{2, 477, 481, 1000},  /* G2 L34 */
{2, 482, 486, 1000},  /* G2 L35 */
{2, 487, 490, 1000},  /* G2 L36 */
{2, 491, 494, 1000},  /* G2 L37 */
{2, 495, 498, 1000},  /* G2 L38 */
{2, 499, 502, 1000},  /* G2 L39 */
{2, 503, 506, 1000},  /* G2 L40 */
{2, 507, 510, 1000},  /* G2 L41 */
{2, 511, 514, 1000},  /* G2 L42 */
{2, 515, 518, 1000},  /* G2 L43 */
{2, 519, 522, 1000},  /* G2 L44 */
{2, 523, 526, 1000},  /* G2 L45 */
{2, 527, 530, 1000},  /* G2 L46 */
{2, 531, 534, 1000},  /* G2 L47 */
{2, 535, 538, 1000},  /* G2 L48 */
{2, 539, 542, 1000},  /* G2 L49 */
{2, 543, 546, 1000},  /* G2 L50 */
{2, 547, 549, 1000},  /* G2 L51 */
{2, 550, 552, 1000},  /* G2 L52 */
{2, 553, 555, 1000},  /* G2 L53 */
{2, 556, 558, 1000},  /* G2 L54 */
{2, 559, 561, 1000},  /* G2 L55 */
{2, 562, 564, 1000},  /* G2 L56 */
{2, 565, 567, 1000},  /* G2 L57 */
{2, 568, 570, 1000},  /* G2 L58 */
{2, 571, 573, 1000},  /* G2 L59 */
{2, 574, 576, 1000},  /* G2 L60 */
{2, 577, 579, 1000},  /* G2 L61 */
{2, 580, 582, 1000},  /* G2 L62 */
{2, 583, 585, 1000},  /* G2 L63 */
{2, 586, 588, 1000},  /* G2 L64 */
{2, 589, 591, 1000},  /* G2 L65 */
{2, 592, 594, 1000},  /* G2 L66 */
{2, 595, 597, 1000},  /* G2 L67 */
{2, 598, 600, 1000},  /* G2 L68 */

/* Always is the last one */
{0, 0, 0, 0}

}; /* MedStressLapaGroup */

static struct LapaGroup HighStressLapaGroup[] = {
{0, 0, 0, 0},
{3, 600, 790, 90000},   /* G3 L2 */
{3, 791, 891, 90000},  /* G3 L3 */
{3, 892, 970, 90000},  /* G3 L4 */
{3, 971, 4016, 90000},  /* G3 L5 */

/* Always is the last one */
{0, 0, 0, 0}

}; /* HighStressLapaGroup */
#ifdef __cplusplus
}
#endif

#endif /* _FPTEST_H */
