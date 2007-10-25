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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_NTLOCALE_H
#define	_SMBSRV_NTLOCALE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * NT language and locale identifiers.
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Language IDs.
 *
 * A language ID is a 16 bit value which is the combination of a
 * primary language ID and a secondary language ID. The bits are
 * allocated as follows:
 *
 *      +-----------------------+-------------------------+
 *      |     Sublanguage ID    |   Primary Language ID   |
 *      +-----------------------+-------------------------+
 *       15                   10 9                       0   bit
 *
 * The following two combinations of primary language ID and sub-
 * language ID have special semantics:
 *
 * Primary Language ID   Sublanguage ID      Result
 * -------------------   ---------------     ------------------------
 * LANG_NEUTRAL          SUBLANG_NEUTRAL     Language neutral
 * LANG_NEUTRAL          SUBLANG_DEFAULT     User default language
 * LANG_NEUTRAL          SUBLANG_SYS_DEFAULT System default language
 *
 * Language ID creation/extraction macros:
 * MAKELANGID    - construct language id from a primary language
 *                 id and a sublanguage id.
 * PRIMARYLANGID - extract primary language id from a language id.
 * SUBLANGID     - extract sublanguage id from a language id.
 */
#define	MAKELANGID(p, s)	((((WORD)(s)) << 10) | (WORD)(p))
#define	PRIMARYLANGID(lgid)	((WORD)(lgid) & 0x3ff)
#define	SUBLANGID(lgid)		((WORD)(lgid) >> 10)


/*
 * Primary language IDs.
 */
#define	LANG_NEUTRAL			0x00

#define	LANG_AFRIKAANS			0x36
#define	LANG_ALBANIAN			0x1c
#define	LANG_ARABIC			0x01
#define	LANG_ARMENIAN			0x2b
#define	LANG_ASSAMESE			0x4d
#define	LANG_AZERI			0x2c
#define	LANG_BASQUE			0x2d
#define	LANG_BELARUSIAN			0x23
#define	LANG_BENGALI			0x45
#define	LANG_BULGARIAN			0x02
#define	LANG_CATALAN			0x03
#define	LANG_CHINESE			0x04
#define	LANG_CROATIAN			0x1a
#define	LANG_CZECH			0x05
#define	LANG_DANISH			0x06
#define	LANG_DUTCH			0x13
#define	LANG_ENGLISH			0x09
#define	LANG_ESTONIAN			0x25
#define	LANG_FAEROESE			0x38
#define	LANG_FARSI			0x29
#define	LANG_FINNISH			0x0b
#define	LANG_FRENCH			0x0c
#define	LANG_GEORGIAN			0x37
#define	LANG_GERMAN			0x07
#define	LANG_GREEK			0x08
#define	LANG_GUJARATI			0x47
#define	LANG_HEBREW			0x0d
#define	LANG_HINDI			0x39
#define	LANG_HUNGARIAN			0x0e
#define	LANG_ICELANDIC			0x0f
#define	LANG_INDONESIAN			0x21
#define	LANG_ITALIAN			0x10
#define	LANG_JAPANESE			0x11
#define	LANG_KANNADA			0x4b
#define	LANG_KASHMIRI			0x60
#define	LANG_KAZAK			0x3f
#define	LANG_KONKANI			0x57
#define	LANG_KOREAN			0x12
#define	LANG_LATVIAN			0x26
#define	LANG_LITHUANIAN			0x27
#define	LANG_MACEDONIAN			0x2f
#define	LANG_MALAY			0x3e
#define	LANG_MALAYALAM			0x4c
#define	LANG_MANIPURI			0x58
#define	LANG_MARATHI			0x4e
#define	LANG_NEPALI			0x61
#define	LANG_NORWEGIAN			0x14
#define	LANG_ORIYA			0x48
#define	LANG_POLISH			0x15
#define	LANG_PORTUGUESE			0x16
#define	LANG_PUNJABI			0x46
#define	LANG_ROMANIAN			0x18
#define	LANG_RUSSIAN			0x19
#define	LANG_SANSKRIT			0x4f
#define	LANG_SERBIAN			0x1a
#define	LANG_SINDHI			0x59
#define	LANG_SLOVAK			0x1b
#define	LANG_SLOVENIAN			0x24
#define	LANG_SPANISH			0x0a
#define	LANG_SWAHILI			0x41
#define	LANG_SWEDISH			0x1d
#define	LANG_TAMIL			0x49
#define	LANG_TATAR			0x44
#define	LANG_TELUGU			0x4a
#define	LANG_THAI			0x1e
#define	LANG_TURKISH			0x1f
#define	LANG_UKRAINIAN			0x22
#define	LANG_URDU			0x20
#define	LANG_UZBEK			0x43
#define	LANG_VIETNAMESE			0x2a


/*
 * Sublanguage IDs.
 *
 * The name immediately following SUBLANG_ dictates which primary
 * language ID can be combined with the sub-language ID to form a
 * valid language ID.
 */
#define	SUBLANG_NEUTRAL			0x00	/* language neutral */
#define	SUBLANG_DEFAULT			0x01	/* user default */
#define	SUBLANG_SYS_DEFAULT		0x02	/* system default */

#define	SUBLANG_ARABIC_SAUDI_ARABIA	0x01	/* Arabic (Saudi Arabia) */
#define	SUBLANG_ARABIC_IRAQ		0x02	/* Arabic (Iraq) */
#define	SUBLANG_ARABIC_EGYPT		0x03	/* Arabic (Egypt) */
#define	SUBLANG_ARABIC_LIBYA		0x04	/* Arabic (Libya) */
#define	SUBLANG_ARABIC_ALGERIA		0x05	/* Arabic (Algeria) */
#define	SUBLANG_ARABIC_MOROCCO		0x06	/* Arabic (Morocco) */
#define	SUBLANG_ARABIC_TUNISIA		0x07	/* Arabic (Tunisia) */
#define	SUBLANG_ARABIC_OMAN		0x08	/* Arabic (Oman) */
#define	SUBLANG_ARABIC_YEMEN		0x09	/* Arabic (Yemen) */
#define	SUBLANG_ARABIC_SYRIA		0x0a	/* Arabic (Syria) */
#define	SUBLANG_ARABIC_JORDAN		0x0b	/* Arabic (Jordan) */
#define	SUBLANG_ARABIC_LEBANON		0x0c	/* Arabic (Lebanon) */
#define	SUBLANG_ARABIC_KUWAIT		0x0d	/* Arabic (Kuwait) */
#define	SUBLANG_ARABIC_UAE		0x0e	/* Arabic (U.A.E) */
#define	SUBLANG_ARABIC_BAHRAIN		0x0f	/* Arabic (Bahrain) */
#define	SUBLANG_ARABIC_QATAR		0x10	/* Arabic (Qatar) */
#define	SUBLANG_AZERI_LATIN		0x01	/* Azeri (Latin) */
#define	SUBLANG_AZERI_CYRILLIC		0x02	/* Azeri (Cyrillic) */
#define	SUBLANG_CHINESE_TRADITIONAL	0x01	/* Chinese (Taiwan Region) */
#define	SUBLANG_CHINESE_SIMPLIFIED	0x02	/* Chinese (PR China) */
#define	SUBLANG_CHINESE_HONGKONG	0x03	/* Chinese (Hong Kong) */
#define	SUBLANG_CHINESE_SINGAPORE	0x04	/* Chinese (Singapore) */
#define	SUBLANG_CHINESE_MACAU		0x05	/* Chinese (Macau) */
#define	SUBLANG_DUTCH			0x01	/* Dutch */
#define	SUBLANG_DUTCH_BELGIAN		0x02	/* Dutch (Belgian) */
#define	SUBLANG_ENGLISH_US		0x01	/* English (USA) */
#define	SUBLANG_ENGLISH_UK		0x02	/* English (UK) */
#define	SUBLANG_ENGLISH_AUS		0x03	/* English (Australian) */
#define	SUBLANG_ENGLISH_CAN		0x04	/* English (Canadian) */
#define	SUBLANG_ENGLISH_NZ		0x05	/* English (New Zealand) */
#define	SUBLANG_ENGLISH_EIRE		0x06	/* English (Irish) */
#define	SUBLANG_ENGLISH_SOUTH_AFRICA	0x07	/* English (South Africa) */
#define	SUBLANG_ENGLISH_JAMAICA		0x08	/* English (Jamaica) */
#define	SUBLANG_ENGLISH_CARIBBEAN	0x09	/* English (Caribbean) */
#define	SUBLANG_ENGLISH_BELIZE		0x0a	/* English (Belize) */
#define	SUBLANG_ENGLISH_TRINIDAD	0x0b	/* English (Trinidad) */
#define	SUBLANG_ENGLISH_ZIMBABWE	0x0c	/* English (Zimbabwe) */
#define	SUBLANG_ENGLISH_PHILIPPINES	0x0d	/* English (Philippines) */
#define	SUBLANG_FRENCH			0x01	/* French */
#define	SUBLANG_FRENCH_BELGIAN		0x02	/* French (Belgian) */
#define	SUBLANG_FRENCH_CANADIAN		0x03	/* French (Canadian) */
#define	SUBLANG_FRENCH_SWISS		0x04	/* French (Swiss) */
#define	SUBLANG_FRENCH_LUXEMBOURG	0x05	/* French (Luxembourg) */
#define	SUBLANG_FRENCH_MONACO		0x06	/* French (Monaco) */
#define	SUBLANG_GERMAN			0x01	/* German */
#define	SUBLANG_GERMAN_SWISS		0x02	/* German (Swiss) */
#define	SUBLANG_GERMAN_AUSTRIAN		0x03	/* German (Austrian) */
#define	SUBLANG_GERMAN_LUXEMBOURG	0x04	/* German (Luxembourg) */
#define	SUBLANG_GERMAN_LIECHTENSTEIN	0x05	/* German (Liechtenstein) */
#define	SUBLANG_ITALIAN			0x01	/* Italian */
#define	SUBLANG_ITALIAN_SWISS		0x02	/* Italian (Swiss) */
#define	SUBLANG_KASHMIRI_INDIA		0x02	/* Kashmiri (India) */
#define	SUBLANG_KOREAN			0x01	/* Korean (Extended Wansung) */
#define	SUBLANG_LITHUANIAN		0x01	/* Lithuanian */
#define	SUBLANG_LITHUANIAN_CLASSIC	0x02	/* Lithuanian (Classic) */
#define	SUBLANG_MALAY_MALAYSIA		0x01	/* Malay (Malaysia) */
#define	SUBLANG_MALAY_BRUNEI_DARUSSALAM 0x02	/* Malay (Brunei Darussalam) */
#define	SUBLANG_NEPALI_INDIA		0x02	/* Nepali (India) */
#define	SUBLANG_NORWEGIAN_BOKMAL	0x01	/* Norwegian (Bokmal) */
#define	SUBLANG_NORWEGIAN_NYNORSK	0x02	/* Norwegian (Nynorsk) */
#define	SUBLANG_PORTUGUESE		0x02	/* Portuguese */
#define	SUBLANG_PORTUGUESE_BRAZILIAN	0x01	/* Portuguese (Brazilian) */
#define	SUBLANG_SERBIAN_LATIN		0x02	/* Serbian (Latin) */
#define	SUBLANG_SERBIAN_CYRILLIC	0x03	/* Serbian (Cyrillic) */
#define	SUBLANG_SPANISH			0x01	/* Spanish (Castilian) */
#define	SUBLANG_SPANISH_MEXICAN		0x02	/* Spanish (Mexican) */
#define	SUBLANG_SPANISH_MODERN		0x03	/* Spanish (Modern) */
#define	SUBLANG_SPANISH_GUATEMALA	0x04	/* Spanish (Guatemala) */
#define	SUBLANG_SPANISH_COSTA_RICA	0x05	/* Spanish (Costa Rica) */
#define	SUBLANG_SPANISH_PANAMA		0x06	/* Spanish (Panama) */
#define	SUBLANG_SPANISH_DOMINICAN_REPUBLIC 0x07	/* Spanish (Dom. Republic) */
#define	SUBLANG_SPANISH_VENEZUELA	0x08	/* Spanish (Venezuela) */
#define	SUBLANG_SPANISH_COLOMBIA	0x09	/* Spanish (Colombia) */
#define	SUBLANG_SPANISH_PERU		0x0a	/* Spanish (Peru) */
#define	SUBLANG_SPANISH_ARGENTINA	0x0b	/* Spanish (Argentina) */
#define	SUBLANG_SPANISH_ECUADOR		0x0c	/* Spanish (Ecuador) */
#define	SUBLANG_SPANISH_CHILE		0x0d	/* Spanish (Chile) */
#define	SUBLANG_SPANISH_URUGUAY		0x0e	/* Spanish (Uruguay) */
#define	SUBLANG_SPANISH_PARAGUAY	0x0f	/* Spanish (Paraguay) */
#define	SUBLANG_SPANISH_BOLIVIA		0x10	/* Spanish (Bolivia) */
#define	SUBLANG_SPANISH_EL_SALVADOR	0x11	/* Spanish (El Salvador) */
#define	SUBLANG_SPANISH_HONDURAS	0x12	/* Spanish (Honduras) */
#define	SUBLANG_SPANISH_NICARAGUA	0x13	/* Spanish (Nicaragua) */
#define	SUBLANG_SPANISH_PUERTO_RICO	0x14	/* Spanish (Puerto Rico) */
#define	SUBLANG_SWEDISH			0x01	/* Swedish */
#define	SUBLANG_SWEDISH_FINLAND		0x02	/* Swedish (Finland) */
#define	SUBLANG_URDU_PAKISTAN		0x01	/* Urdu (Pakistan) */
#define	SUBLANG_URDU_INDIA		0x02	/* Urdu (India) */
#define	SUBLANG_UZBEK_LATIN		0x01	/* Uzbek (Latin) */
#define	SUBLANG_UZBEK_CYRILLIC		0x02	/* Uzbek (Cyrillic) */

/*
 * Sorting IDs.
 */
#define	SORT_DEFAULT			0x0	/* sorting default */

#define	SORT_JAPANESE_XJIS		0x0	/* Japanese XJIS order */
#define	SORT_JAPANESE_UNICODE		0x1	/* Japanese Unicode order */

#define	SORT_CHINESE_BIG5		0x0	/* Chinese BIG5 order */
#define	SORT_CHINESE_PRCP		0x0	/* PRC Chinese Phonetic order */
#define	SORT_CHINESE_UNICODE		0x1	/* Chinese Unicode order */
#define	SORT_CHINESE_PRC		0x2	/* PRC Chinese Stroke Count */
						/* order */
#define	SORT_CHINESE_BOPOMOFO		0x3	/* Traditional Chinese */
						/* Bopomofo order */

#define	SORT_KOREAN_KSC			0x0	/* Korean KSC order */
#define	SORT_KOREAN_UNICODE		0x1	/* Korean Unicode order */

#define	SORT_GERMAN_PHONE_BOOK		0x1	/* German Phone Book order */

#define	SORT_HUNGARIAN_DEFAULT		0x0	/* Hungarian Default order */
#define	SORT_HUNGARIAN_TECHNICAL	0x1	/* Hungarian Technical order */

#define	SORT_GEORGIAN_TRADITIONAL	0x0	/* Georgian Traditional order */
#define	SORT_GEORGIAN_MODERN		0x1	/* Georgian Modern order */


/*
 *  A locale ID is a 32 bit value which is the combination of a
 *  language ID, a sort ID, and a reserved area.  The bits are
 *  allocated as follows:
 *
 *       +-------------+---------+-------------------------+
 *       |   Reserved  | Sort ID |      Language ID        |
 *       +-------------+---------+-------------------------+
 *        31         20 19     16 15                      0   bit
 *
 *  Locale ID creation/extraction macros:
 *
 * MAKELCID            - construct the locale id from a language id
 *                       and a sort id.
 * MAKESORTLCID        - construct the locale id from a language id,
 *                       sort id, and sort version.
 * LANGIDFROMLCID      - extract the language id from a locale id.
 * SORTIDFROMLCID      - extract the sort id from a locale id.
 * SORTVERSIONFROMLCID - extract the sort version from a locale id.
 */

#define	NLS_VALID_LOCALE_MASK	0x000fffff

#define	MAKELCID(lgid, srtid)	\
	((DWORD)((((DWORD)((WORD)(srtid))) << 16) | ((DWORD)((WORD)(lgid)))))

#define	MAKESORTLCID(lgid, srtid, ver)	\
	((DWORD)((MAKELCID(lgid, srtid)) | (((DWORD)((WORD)(ver))) << 20)))

#define	LANGIDFROMLCID(lcid)		((WORD)(lcid))
#define	SORTIDFROMLCID(lcid)		((WORD)((((DWORD)(lcid)) >> 16) & 0xf))
#define	SORTVERSIONFROMLCID(lcid)	((WORD)((((DWORD)(lcid)) >> 20) & 0xf))


/*
 * Default System and User IDs for language and locale.
 */
#define	LANG_SYSTEM_DEFAULT	MAKELANGID(LANG_NEUTRAL, SUBLANG_SYS_DEFAULT))
#define	LANG_USER_DEFAULT	(MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT))

#define	LOCALE_SYSTEM_DEFAULT	(MAKELCID(LANG_SYSTEM_DEFAULT, SORT_DEFAULT))
#define	LOCALE_USER_DEFAULT	(MAKELCID(LANG_USER_DEFAULT, SORT_DEFAULT))

#define	LOCALE_NEUTRAL         \
	(MAKELCID(MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), SORT_DEFAULT))


#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_NTLOCALE_H */
