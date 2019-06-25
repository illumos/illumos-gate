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

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <sip.h>

#include "sip_msg.h"
#include "sip_miscdefs.h"
#include "sip_parse_generic.h"
#include "sip_parse_uri.h"


/*
 * Accept = "Accept" HCOLON [ accept-range *(COMMA accept-range) ]
 * accept-range = media-range *(SEMI accept-param)
 * media-range = ("* / *" |  (m-type SLASH "*") | (m-type SLASH m-subtype))
 *		*(SEMI m-param)
 * accept-param = ("q" EQUAL qvalue) | generic-param
 * qvalue = ("0" ["." 0*3DIGIT]) | ("1" ["." 0*3DIGIT])
 * generic-param = token [ EQUAL gen-value]
 * gen-value = token | host | quoted-str
 */
int
sip_parse_acpt_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	if (sip_is_empty_hdr(sip_header))
		return (sip_parse_hdr_empty(sip_header, header));
	return (sip_parse_hdr_parser1(sip_header, header, SIP_SLASH));
}

/*
 * Accept-Encoding = "Accept-Encoding" ":" 1#(codings [ ";" "q" "=" qval])
 * codings = (content-coding | "*")
 * content-coding = token
 */
int
sip_parse_acpt_encode_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * Accept-Language = "Accept-Language" ":" [ lang * (COMMA lang) ]
 * lang = lang-range *(SEMI accept-param)
 * lang-range = ((1*8ALPHA * ("-" 1*8ALPHA)) | "*"
 */
int
sip_parse_acpt_lang_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	if (sip_is_empty_hdr(sip_header))
		return (sip_parse_hdr_empty(sip_header, header));
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * Alert-Info = "Alert-Info" ":" alert-param *(COMMA alert-param)
 * alert-param = LAQUOT absoluteURI RAQUOT * (SEMI generic-param)
 */
int
sip_parse_alert_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser3(sip_header, header, SIP_STR_VAL, B_TRUE));
}

/*
 * Allow = "Allow" ":" method-name1[, method-name2..]
 */
int
sip_parse_allow_header(_sip_header_t *hdr, sip_parsed_header_t **phdr)
{
	sip_parsed_header_t	*parsed_header;
	sip_hdr_value_t		*value = NULL;
	sip_hdr_value_t		*last_value = NULL;
	int			len;
	int			i;
	int			ret;
	boolean_t		multi_value = B_FALSE;

	if ((ret = sip_prim_parsers(hdr, phdr)) != 0)
		return (ret);

	if (*phdr != NULL)
		return (0);

	parsed_header = calloc(1, sizeof (sip_parsed_header_t));
	if (parsed_header == NULL)
		return (ENOMEM);
	parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;
	parsed_header->sip_header = hdr;

	while (hdr->sip_hdr_current < hdr->sip_hdr_end) {
		value = calloc(1, sizeof (sip_hdr_value_t));
		if (value == NULL) {
			sip_free_phdr(parsed_header);
			return (ENOMEM);
		}
		if (last_value != NULL)
			last_value->sip_next_value = value;
		else
			parsed_header->value = (sip_value_t *)value;

		value->sip_value_start = hdr->sip_hdr_current;
		value->sip_value_header = parsed_header;

		if (sip_find_separator(hdr, SIP_COMMA, 0, 0, B_FALSE) == 0) {
			multi_value = B_TRUE;
		}

		len = hdr->sip_hdr_current - value->sip_value_start;
		for (i = 1; i < MAX_SIP_METHODS; i++) {
			if (strncmp(sip_methods[i].name, value->sip_value_start,
			    len) == 0) {
				break;
			}
		}
		if (i >= MAX_SIP_METHODS) {
			value->int_val = 0;
			value->sip_value_state = SIP_VALUE_BAD;
			if (multi_value)
				goto next_val;
			else
				goto end;
		}
		value->int_val = i;
		if (!multi_value)
			goto end;
	next_val:
		if (sip_find_token(hdr, SIP_COMMA) != 0)
			break;
		value->sip_value_end = hdr->sip_hdr_current - 1;
		last_value = value;
		(void) sip_skip_white_space(hdr);
	}

end:
	*phdr = parsed_header;
	return (0);
}


/*
 * Call-Info = "Call-Info" HCOLON info * (COMMA info)
 * info = LAQUOT absoluteURI RAQUOT * (SEMI info-param)
 * info-param = ("purpose" EQUAL ("icon" | "info" | "card" | token)) |
 *		 generic-param
 */
int
sip_parse_callinfo_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser3(sip_header, header, SIP_STR_VAL, B_TRUE));
}

/*
 * Content-Disposition = "Content-Disposition" HCOLON disp-type *
 *			(SEMI disp-param)
 * disp-type = "render" | "session" | "icon" | "alert" | disp-ext-token
 * disp-param = handling-param | generic-param
 * handling-param = "handling" EQUAL("optional" | "required" | other-handling)
 * other-handling = token
 * disp-ext-token = token
 *
 */
int
sip_parse_contentdis_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * Content-Encoding = ("Content-Encoding" | "e") HCOLON content-coding *
 *			(COMMA content-coding)
 */
int
sip_parse_contentencode_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * Content-Language = ("Content-Language" | "l") HCOLON lang-tag *
 *		 (COMMA lang-tag)
 * lang-tag = primary-tag *("-" subtag)
 * prmary-tag = 1*8ALPHA
 * subtag = 1*8ALPHA
 */
int
sip_parse_contentlang_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * Date = "Date" HCOLON SIPdate
 * SIPdate = wkday "," SP date1 SP time SP "GMT"
 * date1 = 2DIGIT SP mnth SP 4DIGIT; day month year
 * time = 2DIGIT ":" 2DIGIT ":" 2DIGIT
 * wkday = "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
 * month = "Jan" | "Feb" etc
 */
int
sip_parse_date_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	sip_parsed_header_t	*parsed_header;
	int			 r;
	sip_hdr_value_t		*value = NULL;

	if ((r = sip_prim_parsers(sip_header, header)) != 0)
		return (r);

	if (*header != NULL)
		return (0);

	parsed_header = calloc(1, sizeof (sip_parsed_header_t));
	if (parsed_header == NULL)
		return (ENOMEM);
	parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;
	parsed_header->sip_header = sip_header;

	value = calloc(1, sizeof (sip_hdr_value_t));
	if (value == NULL) {
		sip_free_phdr(parsed_header);
		return (ENOMEM);
	}
	parsed_header->value = (sip_value_t *)value;

	value->sip_value_start = sip_header->sip_hdr_current;
	value->sip_value_header = parsed_header;
	value->date_wd_ptr = sip_header->sip_hdr_current;
	if (sip_find_token(sip_header, SIP_COMMA) == 0) {
		value->date_wd_len = sip_header->sip_hdr_current -
		    value->date_wd_ptr - 1;
		sip_header->sip_hdr_current++;
		if (sip_skip_white_space(sip_header) != 0) {
			value->sip_value_state = SIP_VALUE_BAD;
			return (EPROTO);
		}
	} else {
		value->sip_value_state = SIP_VALUE_BAD;
		return (EPROTO);
	}

	if (sip_skip_white_space(sip_header) != 0) {
		value->sip_value_state = SIP_VALUE_BAD;
		return (EPROTO);
	}
	r = sip_atoi(sip_header, &value->date_d);
	if (r != 0 || value->date_d < 0 || value->date_d > 31) {
		value->sip_value_state = SIP_VALUE_BAD;
		return (EPROTO);
	}
	if (sip_skip_white_space(sip_header) != 0) {
		value->sip_value_state = SIP_VALUE_BAD;
		return (EPROTO);
	}
	value->date_m_ptr = sip_header->sip_hdr_current;
	if (sip_find_token(sip_header, SIP_SP) == 0) {
		value->date_m_len = sip_header->sip_hdr_current -
		    value->date_m_ptr - 1;
	} else {
		value->sip_value_state = SIP_VALUE_BAD;
		return (EPROTO);
	}

	r = sip_atoi(sip_header, &value->date_y);
	if (r != 0 || value->date_y < 0) {
		value->sip_value_state = SIP_VALUE_BAD;
		return (EPROTO);
	}
	if (sip_skip_white_space(sip_header) != 0) {
		value->sip_value_state = SIP_VALUE_BAD;
		return (EPROTO);
	}
	value->date_t_ptr = sip_header->sip_hdr_current;
	if (sip_find_token(sip_header, SIP_SP) == 0) {
		value->date_t_len = sip_header->sip_hdr_current -
		    value->date_t_ptr - 1;
	} else {
		value->sip_value_state = SIP_VALUE_BAD;
		return (EPROTO);
	}

	value->date_tz_ptr =  sip_header->sip_hdr_current;
	/*
	 * minus 2 to get rid of the CRLF
	 */
	value->date_tz_len = sip_header->sip_hdr_end -
	    sip_header->sip_hdr_current - 2;

	*header = parsed_header;

	sip_header->sip_hdr_parsed = *header;
	return (0);
}

/*
 * Error-Info = "Error-Info" HCOLON error-uri *(COMMA error-uri)
 * error-uri = LAQUOT absoluteURI RAQUOT *(SEMI generic-param)
 */
int
sip_parse_errorinfo_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser3(sip_header, header, SIP_STR_VAL, B_TRUE));
}

/*
 * Expires = "Expires" HCOLON delta-seconds
 */
int
sip_parse_expire_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser2(sip_header, header, SIP_INT_VAL));
}

/*
 * In-Reply-To = "In-Reply-To" HCOLON callid *(COMMA callid)
 */
int
sip_parse_inreplyto_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * RSeq = "RSeq" HCOLON response-num
 */
int
sip_parse_rseq(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	int		r;
	sip_hdr_value_t	*rseq_value;

	r = sip_parse_hdr_parser2(sip_header, header, SIP_INT_VAL);
	/*
	 * Additionally, a value of 0 is bad_value
	 */
	if (sip_header->sip_hdr_parsed != NULL &&
	    sip_header->sip_hdr_parsed->value != NULL) {
		rseq_value = (sip_hdr_value_t *)
		    sip_header->sip_hdr_parsed->value;
		if (rseq_value->int_val == 0)
			rseq_value->sip_value_state = SIP_VALUE_BAD;
	}
	return (r);
}

/*
 * Min-Expires  =  "Min-Expires" HCOLON delta-seconds
 */
int
sip_parse_minexpire_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser2(sip_header, header, SIP_INT_VAL));
}

/*
 * MIME-Version = "MIME-Version" HCOLON 1*DIGIT "." 1*DIGIT
 */
int
sip_parse_mimeversion_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser4(sip_header, header));
}

/*
 * Organization = "Organization" HCOLON [TEXT-UTF8-TRIM]
 */
int
sip_parse_org_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	if (sip_is_empty_hdr(sip_header))
		return (sip_parse_hdr_empty(sip_header, header));
	return (sip_parse_hdr_parser4(sip_header, header));
}

/*
 * Priority = "Priority" HCOLON priority-val
 * priority-val = "emergency" | "urgent" | "normal" | "non-urgent" | other
 * other = token
 */
int
sip_parse_priority_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser4(sip_header, header));
}

/*
 * Reply-To = "Reply-To" HCOLON rplyto-spec
 * rplyto-spec = (name-addr | addr-spec) *(SEMI rplyto-param)
 * rplyto-param = generic-param
 * name-addr = [ display-name ] LAQUOT addr-spec RAQUOT
 * addr-spec = SIP-URI | SIPS-URI | absolute URI
 */
int
sip_parse_replyto_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser3(sip_header, header, SIP_STRS_VAL,
	    B_TRUE));
}

/*
 * PRIVACY = "Privacy" HCOLON priv-value *(COMMA priv-value)
 * priv-value   =   "header" / "session" / "user" / "none" / "critical"
 *                  / token / id
 */
int
sip_parse_privacy_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}


/*
 * Require = "Require" HCOLON option-tag * (COMMA option-tag)
 */
int
sip_parse_require_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * Retry-After = "Retry-After" HCOLON delta-seconds [ comment ] *
 *		(SEMI retry-param)
 * retry-param = "duration" EQUAL delta-seconds
 */
int
sip_parse_retryaft_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	sip_parsed_header_t	*parsed_header;
	sip_hdr_value_t		*value = NULL;
	int			ret;

	if ((ret = sip_prim_parsers(sip_header, header)) != 0)
		return (ret);

	if (*header != NULL)
		return (0);

	parsed_header = calloc(1, sizeof (sip_parsed_header_t));
	if (parsed_header == NULL)
		return (ENOMEM);
	parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;
	parsed_header->sip_header = sip_header;

	value = calloc(1, sizeof (sip_hdr_value_t));
	if (value == NULL) {
		sip_free_phdr(parsed_header);
		return (ENOMEM);
	}

	parsed_header->value = (sip_value_t *)value;
	value->sip_value_start = sip_header->sip_hdr_current;
	value->sip_value_header = parsed_header;

	ret = sip_atoi(sip_header, &(value->intstr_int));
	if (ret != 0)
		value->sip_value_state = SIP_VALUE_BAD;
	if (sip_find_token(sip_header, SIP_LPAR) == 0) {
		value->intstr_str_ptr = sip_header->sip_hdr_current;
		if (sip_find_token(sip_header, SIP_RPAR) == 0) {
			value->intstr_str_len =
			    sip_header->sip_hdr_current -
			    value->intstr_str_ptr - 1;
			if (sip_find_token(sip_header, SIP_SEMI) == 0) {
				sip_header->sip_hdr_current--;
				(void) sip_parse_params(sip_header,
				    &(value->sip_param_list));
			}
		} else {
			value->sip_value_state = SIP_VALUE_BAD;
			return (EPROTO);
		}
	} else {
		value->intstr_str_ptr = NULL;
		value->intstr_str_len = 0;

		/*
		 * from value start, search if parameter list
		 */
		sip_header->sip_hdr_current = value->sip_value_start;
		if (sip_find_token(sip_header, SIP_SEMI) == 0) {
			sip_header->sip_hdr_current--;
			(void) sip_parse_params(sip_header,
			    &(value->sip_param_list));
		}
	}

	*header = parsed_header;
	sip_header->sip_hdr_parsed = *header;
	return (0);
}

/*
 * Server = "Server" HCOLON servel-val *(LWS server-val)
 * servel-val = product|comment
 * product = token [SLASH version]
 * version = token
 * Treated as one single string
 */
int
sip_parse_server_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser4(sip_header, header));
}

/*
 * Subject = ("Subject" | "s")HCOLON [TEXT-UTF8-TRIM]
 */
int
sip_parse_subject_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	if (sip_is_empty_hdr(sip_header))
		return (sip_parse_hdr_empty(sip_header, header));
	return (sip_parse_hdr_parser4(sip_header, header));
}

/*
 * Supported = ("Supported" | "k") HCOLON [option-tag * (COMMA option-tag) ]
 */
int
sip_parse_support_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	if (sip_is_empty_hdr(sip_header))
		return (sip_parse_hdr_empty(sip_header, header));
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * Timestamp = "Timestamp" HCOLON 1*DIGIT ["." *(DIGIT)] [LWS delay]
 */
int
sip_parse_timestamp_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	sip_parsed_header_t	*parsed_header;
	sip_hdr_value_t		*value = NULL;
	int			ret;

	if ((ret = sip_prim_parsers(sip_header, header)) != 0)
		return (ret);

	if (*header != NULL)
		return (0);

	parsed_header = calloc(1, sizeof (sip_parsed_header_t));
	if (parsed_header == NULL)
		return (ENOMEM);
	parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;
	parsed_header->sip_header = sip_header;

	value = calloc(1, sizeof (sip_hdr_value_t));
	if (value == NULL) {
		sip_free_phdr(parsed_header);
		return (ENOMEM);
	}
	parsed_header->value = (sip_value_t *)value;

	value->sip_value_start = sip_header->sip_hdr_current;
	value->sip_value_header = parsed_header;

	if (sip_skip_white_space(sip_header) != 0) {
		value->sip_value_state = SIP_VALUE_BAD;
		return (EPROTO);
	}
	value->strs1_val_ptr = sip_header->sip_hdr_current;

	if (sip_find_white_space(sip_header) == 0) {
		/*
		 * timestamp and delay, timestamp in str1, delay in str2
		 */
		value->strs1_val_len = sip_header->sip_hdr_current -
		    value->strs1_val_ptr;
		(void) sip_skip_white_space(sip_header);

		value->strs2_val_ptr = sip_header->sip_hdr_current;
		if (sip_find_cr(sip_header) != 0) {
			value->sip_value_state = SIP_VALUE_BAD;
			return (EPROTO);
		}
		if (sip_header->sip_hdr_current < value->strs2_val_ptr) {
			value->strs2_val_ptr = NULL;
			value->strs2_val_len = 0;
		} else {
			value->strs2_val_len = sip_header->sip_hdr_current -
			    value->strs2_val_ptr;
		}
	} else {
		/*
		 * no delay information
		 */
		value->strs1_val_len = sip_header->sip_hdr_current
		    - value->strs1_val_ptr;
		value->strs2_val_ptr = NULL;
		value->strs2_val_len = 0;
	}

	*header = parsed_header;
	sip_header->sip_hdr_parsed = *header;

	return (0);
}
/*
 * Unsupported = "Unsupported" HCOLON option-tag * (COMMA option-tag)
 */
int
sip_parse_usupport_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * User-Agent = "User-Agent" HCOLON server-val * (LWS server-val)
 * servel-val = product |comment
 * product = token [SLASH version]
 * version = token
 */
int
sip_parse_useragt_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser4(sip_header, header));
}

/*
 * Warning = "Warning" HCOLON warning-value *(COMMA warning-value)
 * warning-value = warn-code SP warn-agent SP warn-text
 * warn-code = 3DIGIT
 * warn-agent = hostport | pseudonym ;
 *		 the name or pseudonym of the server adding;
 *		 the Warning header, for use in debugging
 * warn-text = quoted-string
 * pseudonym = token
 */
int
sip_parse_warn_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	sip_parsed_header_t	*parsed_header;
	int			ret;
	sip_hdr_value_t		*value = NULL;
	sip_hdr_value_t		*last_value = NULL;

	if ((ret = sip_prim_parsers(sip_header, header)) != 0)
		return (ret);

	if (*header != NULL)
		return (0);

	parsed_header = calloc(1, sizeof (sip_parsed_header_t));
	if (parsed_header == NULL)
		return (ENOMEM);
	parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;
	parsed_header->sip_header = sip_header;

	while (sip_header->sip_hdr_current < sip_header->sip_hdr_end) {
		value = calloc(1, sizeof (sip_hdr_value_t));
		if (value == NULL) {
			sip_free_phdr(parsed_header);
			return (ENOMEM);
		}

		if (last_value != NULL)
			last_value->sip_next_value = value;
		else
			parsed_header->value = (sip_value_t *)value;

		value->sip_value_start = sip_header->sip_hdr_current;
		value->sip_value_header = parsed_header;

		ret = sip_atoi(sip_header, &value->warn_code);
		if (ret != 0 || value->warn_code < 100 ||
		    value->warn_code > 999) {
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_val;
		}
		if (sip_skip_white_space(sip_header) != 0) {
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_val;
		}
		value->warn_agt_ptr = sip_header->sip_hdr_current;

		if (sip_find_token(sip_header, SIP_QUOTE) == 0) {
			/*
			 * get warning agent
			 */
			sip_header->sip_hdr_current--;
			(void) sip_reverse_skip_white_space(sip_header);
			value->warn_agt_len = sip_header->sip_hdr_current -
			    value->warn_agt_ptr - 1;
			if (value->warn_agt_len <= 0) {
				value->warn_agt_ptr = NULL;
				value->sip_value_state = SIP_VALUE_BAD;
			}

			/*
			 * We will have a  SIP_QUOTE here
			 */
			(void) sip_find_token(sip_header, SIP_QUOTE);

			value->warn_text_ptr =  sip_header->sip_hdr_current;
			if (sip_find_token(sip_header, SIP_QUOTE) == 0) {
				value->warn_text_len =
				    sip_header->sip_hdr_current -
				    value->warn_text_ptr - 1;
			} else {
				value->sip_value_state = SIP_VALUE_BAD;
				goto get_next_val;
			}
		} else
			/*
			 * warning text must present
			 */
			value->sip_value_state = SIP_VALUE_BAD;

get_next_val:
		if (sip_find_token(sip_header, SIP_COMMA) != 0)
			break;
		value->sip_value_end = sip_header->sip_hdr_current - 1;
		last_value = value;
		(void) sip_skip_white_space(sip_header);
	}

	*header = parsed_header;

	sip_header->sip_hdr_parsed = *header;
	return (0);
}

/*
 * Parse RAck header
 * "RAck" HCOLON response-num LWS CSeq-num LWS Method
 * response-num  =  1*DIGIT
 * CSeq-num      =  1*DIGIT
 */
int
sip_parse_rack(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	sip_parsed_header_t	*parsed_header;
	sip_hdr_value_t		*rack_value;
	int			len;
	char			*tmp_ptr;
	int			i;
	int			ret;

	if ((ret = sip_prim_parsers(sip_header, header)) != 0)
		return (ret);

	if (*header != NULL)
		return (0);

	parsed_header = calloc(1, sizeof (sip_parsed_header_t));
	if (parsed_header == NULL)
		return (ENOMEM);
	parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;
	parsed_header->sip_header = sip_header;

	parsed_header->value =  calloc(1, sizeof (sip_hdr_value_t));
	if (parsed_header->value == NULL) {
		free(parsed_header);
		return (ENOMEM);
	}
	rack_value = (sip_hdr_value_t *)parsed_header->value;
	rack_value->sip_value_version = SIP_VALUE_VERSION_1;
	rack_value->sip_value_start = sip_header->sip_hdr_current;
	rack_value->sip_value_header = parsed_header;
	if (sip_atoi(sip_header, &rack_value->rack_resp) ||
	    rack_value->rack_resp == 0) {
		rack_value->sip_value_state = SIP_VALUE_BAD;
		rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
		goto rack_parse_done;
	}
	rack_value->sip_value_header = parsed_header;
	/*
	 * Get cseq.
	 */
	if (sip_skip_white_space(sip_header) != 0) {
		rack_value->sip_value_state = SIP_VALUE_BAD;
		rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
		goto rack_parse_done;
	}
	if (sip_atoi(sip_header, &rack_value->rack_cseq)) {
		rack_value->sip_value_state = SIP_VALUE_BAD;
		rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
		goto rack_parse_done;
	}
	/*
	 * Get method.
	 */
	if (sip_skip_white_space(sip_header) != 0) {
		rack_value->sip_value_state = SIP_VALUE_BAD;
		rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
		goto rack_parse_done;
	}

	tmp_ptr = sip_header->sip_hdr_current;
	if (sip_find_white_space(sip_header)) {
		rack_value->sip_value_state = SIP_VALUE_BAD;
		rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
		goto rack_parse_done;
	}

	len = sip_header->sip_hdr_current - tmp_ptr;

	for (i = 1; i < MAX_SIP_METHODS; i++) {
		if (strncmp(sip_methods[i].name, tmp_ptr, len) == 0)
			break;
	}

	if (i >= MAX_SIP_METHODS) {
		rack_value->sip_value_state = SIP_VALUE_BAD;
		rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
		goto rack_parse_done;
	}

	rack_value->rack_method = i;
	rack_value->sip_value_end = sip_header->sip_hdr_current;

rack_parse_done:
	sip_header->sip_hdr_parsed = parsed_header;

	*header = parsed_header;
	return (0);
}

/*
 * Allow  =  "Allow" HCOLON [Method *(COMMA Method)]
 */
int
sip_parse_allow_events_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * Event             =  ( "Event" / "o" ) HCOLON event-type
 *			*( SEMI event-param )
 * event-type        =  event-package *( "." event-template )
 * event-package     =  token-nodot
 * event-template    =  token-nodot
 * token-nodot       =  1*( alphanum / "-"  / "!" / "%" / "*"
 *			/ "_" / "+" / "`" / "'" / "~" )
 * event-param       =  generic-param / ( "id" EQUAL token )
 */
int
sip_parse_event_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * Subscription-State   = "Subscription-State" HCOLON substate-value
 *			*( SEMI subexp-params )
 * substate-value       = "active" / "pending" / "terminated"
 *			/ extension-substate
 * extension-substate   = token
 * subexp-params        =   ("reason" EQUAL event-reason-value)
 *			/ ("expires" EQUAL delta-seconds)*
 *			/ ("retry-after" EQUAL delta-seconds)
 *			/ generic-param
 * event-reason-value   =   "deactivated"
 *				/ "probation"
 *				/ "rejected"
 *				/ "timeout"
 *				/ "giveup"
 *				/ "noresource"
 *				/ event-reason-extension
 * event-reason-extension = token
 */
int
sip_parse_substate_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * Authorization     =  "Authorization" HCOLON credentials
 * credentials       =  ("Digest" LWS digest-response)
 *			/ other-response
 * digest-response   =  dig-resp *(COMMA dig-resp)
 * dig-resp          =  username / realm / nonce / digest-uri
 *			/ dresponse / algorithm / cnonce
 *			/ opaque / message-qop
 *			/ nonce-count / auth-param
 * username          =  "username" EQUAL username-value
 * username-value    =  quoted-string
 * digest-uri        =  "uri" EQUAL LDQUOT digest-uri-value RDQUOT
 * digest-uri-value  =  rquest-uri ; Equal to request-uri as specified
 *			by HTTP/1.1
 * message-qop       =  "qop" EQUAL qop-value
 * cnonce            =  "cnonce" EQUAL cnonce-value
 * cnonce-value      =  nonce-value
 * nonce-count       =  "nc" EQUAL nc-value
 * nc-value          =  8LHEX
 * dresponse         =  "response" EQUAL request-digest
 * request-digest    =  LDQUOT 32LHEX RDQUOT
 * auth-param        =  auth-param-name EQUAL
 *			( token / quoted-string )
 * auth-param-name   =  token
 * other-response    =  auth-scheme LWS auth-param
 *			*(COMMA auth-param)
 * auth-scheme       =  token
 */
int
sip_parse_author_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser5(sip_header, header, B_TRUE));
}

/*
 * Authentication-Info  =  "Authentication-Info" HCOLON ainfo
 *				*(COMMA ainfo)
 * ainfo                =  nextnonce / message-qop
 *				/ response-auth / cnonce
 *				/ nonce-count
 * nextnonce            =  "nextnonce" EQUAL nonce-value
 * response-auth        =  "rspauth" EQUAL response-digest
 * response-digest      =  LDQUOT *LHEX RDQUOT
 *
 */
int
sip_parse_ainfo_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * Proxy-Authenticate  =  "Proxy-Authenticate" HCOLON challenge
 * challenge           =  ("Digest" LWS digest-cln *(COMMA digest-cln))
 *				/ other-challenge
 * other-challenge     =  auth-scheme LWS auth-param
 *				*(COMMA auth-param)
 * digest-cln          =  realm / domain / nonce
 *				/ opaque / stale / algorithm
 *				/ qop-options / auth-param
 * realm               =  "realm" EQUAL realm-value
 * realm-value         =  quoted-string
 * domain              =  "domain" EQUAL LDQUOT URI
 *				*( 1*SP URI ) RDQUOT
 * URI                 =  absoluteURI / abs-path
 * nonce               =  "nonce" EQUAL nonce-value
 * nonce-value         =  quoted-string
 * opaque              =  "opaque" EQUAL quoted-string
 * stale               =  "stale" EQUAL ( "true" / "false" )
 * algorithm           =  "algorithm" EQUAL ( "MD5" / "MD5-sess"
 *			/ token )
 * qop-options         =  "qop" EQUAL LDQUOT qop-value
 *			*("," qop-value) RDQUOT
 * qop-value           =  "auth" / "auth-int" / token
 *
 */
int
sip_parse_pauthen_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser5(sip_header, header, B_TRUE));
}

/*
 * Proxy-Authorization  =  "Proxy-Authorization" HCOLON credentials
 */
int
sip_parse_pauthor_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser5(sip_header, header, B_TRUE));
}

/*
 * Proxy-Require  =  "Proxy-Require" HCOLON option-tag
 *			*(COMMA option-tag)
 * option-tag     =  token
 */
int
sip_parse_preq_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, 0));
}

/*
 * WWW-Authenticate  =  "WWW-Authenticate" HCOLON challenge
 * extension-header  =  header-name HCOLON header-value
 * header-name       =  token
 * header-value      =  *(TEXT-UTF8char / UTF8-CONT / LWS)
 * message-body  =  *OCTET
 *
 */
int
sip_parse_wauthen_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser5(sip_header, header, B_TRUE));
}

/*
 * Call-ID  =  ( "Call-ID" / "i" ) HCOLON callid
 */
int
sip_parse_cid_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser4(sip_header, header));
}

/*
 * CSeq  =  "CSeq" HCOLON 1*DIGIT LWS Method
 */
int
sip_parse_cseq_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	sip_parsed_header_t	*parsed_header;
	sip_hdr_value_t		*cseq_value;
	int			len;
	char			*tmp_ptr;
	int			i;
	int			ret;

	if ((ret = sip_prim_parsers(sip_header, header)) != 0)
		return (ret);

	if (*header != NULL)
		return (0);

	parsed_header = calloc(1, sizeof (sip_parsed_header_t));
	if (parsed_header == NULL)
		return (ENOMEM);
	parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;
	parsed_header->sip_header = sip_header;

	parsed_header->value =  calloc(1, sizeof (sip_hdr_value_t));
	if (parsed_header->value == NULL) {
		free(parsed_header);
		return (ENOMEM);
	}
	cseq_value = (sip_hdr_value_t *)parsed_header->value;
	cseq_value->sip_value_version = SIP_VALUE_VERSION_1;
	cseq_value->sip_value_start = sip_header->sip_hdr_current;
	if (sip_atoi(sip_header, &cseq_value->cseq_num)) {
		cseq_value->sip_value_state = SIP_VALUE_BAD;
		cseq_value->sip_value_end = sip_header->sip_hdr_end - 2;
		goto cseq_parse_done;
	}
	cseq_value->sip_value_header = parsed_header;
	/*
	 * Get method.
	 */
	if (sip_skip_white_space(sip_header) != 0) {
		cseq_value->sip_value_state = SIP_VALUE_BAD;
		cseq_value->sip_value_end = sip_header->sip_hdr_end - 2;
		goto cseq_parse_done;
	}

	tmp_ptr = sip_header->sip_hdr_current;

	if (sip_find_white_space(sip_header)) {
		cseq_value->sip_value_state = SIP_VALUE_BAD;
		cseq_value->sip_value_end = sip_header->sip_hdr_current;
		goto cseq_parse_done;
	}

	len = sip_header->sip_hdr_current - tmp_ptr;

	for (i = 1; i < MAX_SIP_METHODS; i++) {
		if (strncmp(sip_methods[i].name, tmp_ptr, len) == 0)
			break;
	}

	if (i >= MAX_SIP_METHODS) {
		cseq_value->sip_value_state = SIP_VALUE_BAD;
		cseq_value->sip_value_end = sip_header->sip_hdr_current;
		goto cseq_parse_done;
	}

	cseq_value->cseq_method = i;
	cseq_value->sip_value_end = sip_header->sip_hdr_current;
cseq_parse_done:

	sip_header->sip_hdr_parsed = parsed_header;

	*header = parsed_header;
	return (0);
}


/*
 * Via =  ( "Via" / "v" ) HCOLON via-parm *(COMMA via-parm)
 * via-parm          =  sent-protocol LWS sent-by *( SEMI via-params )
 * via-params        =  via-ttl / via-maddr
 *                      / via-received / via-branch
 *                      / via-extension
 * via-ttl           =  "ttl" EQUAL ttl
 * via-maddr         =  "maddr" EQUAL host
 * via-received      =  "received" EQUAL (IPv4address / IPv6address)
 * via-branch        =  "branch" EQUAL token
 * via-extension     =  generic-param
 * sent-protocol     =  protocol-name SLASH protocol-version
 *                      SLASH transport
 * protocol-name     =  "SIP" / token
 * protocol-version  =  token
 * transport         =  "UDP" / "TCP" / "TLS" / "SCTP"
 *                      / other-transport
 * sent-by           =  host [ COLON port ]
 * ttl               =  1*3DIGIT ; 0 to 255
 *
 * There can be multiple via headers we always append the header.
 */
int
sip_parse_via_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	sip_parsed_header_t	*parsed_header;
	int			ret;
	sip_hdr_value_t		*value = NULL;
	sip_hdr_value_t		*last_value = NULL;

	if ((ret = sip_prim_parsers(sip_header, header)) != 0)
		return (ret);

	if (*header != NULL)
		return (0);

	parsed_header = calloc(1, sizeof (sip_parsed_header_t));
	if (parsed_header == NULL)
		return (ENOMEM);
	parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;
	parsed_header->sip_header = sip_header;

	while (sip_header->sip_hdr_current < sip_header->sip_hdr_end) {

		value = calloc(1, sizeof (sip_hdr_value_t));
		if (value == NULL) {
			sip_free_phdr(parsed_header);
			return (ENOMEM);
		}
		if (last_value != NULL)
			last_value->sip_next_value = value;
		else
			parsed_header->value = (sip_value_t *)value;

		value->sip_value_version = SIP_VALUE_VERSION_1;
		value->sip_value_start = sip_header->sip_hdr_current;
		value->sip_value_header = parsed_header;
		value->via_protocol_name.sip_str_ptr =
		    sip_header->sip_hdr_current;

		/*
		 * Check to see if there is a version number
		 */
		if (sip_get_protocol_version(sip_header,
		    &value->via_protocol) != 0) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_phdr(parsed_header);
				return (EPROTO);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_via_value;
		}

		if (sip_find_token(sip_header, SIP_SLASH) != 0) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_phdr(parsed_header);
				return (EPROTO);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_via_value;
		}

		if (sip_skip_white_space(sip_header) != 0) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_phdr(parsed_header);
				return (EPROTO);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_via_value;
		}

		value->via_protocol_transport.sip_str_ptr =
		    sip_header->sip_hdr_current;
		if (sip_find_white_space(sip_header) != 0) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_phdr(parsed_header);
				return (EPROTO);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_via_value;
		}

		value->via_protocol_transport.sip_str_len =
		    sip_header->sip_hdr_current -
		    value->via_protocol_transport.sip_str_ptr;

		if (sip_skip_white_space(sip_header) != 0) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_phdr(parsed_header);
				return (EPROTO);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_via_value;
		}

		value->via_sent_by_host.sip_str_ptr =
		    sip_header->sip_hdr_current;
		if (*sip_header->sip_hdr_current == '[') {
			if (sip_find_token(sip_header, ']')) {
				if (sip_goto_next_value(sip_header) != 0) {
					sip_free_phdr(parsed_header);
					return (EPROTO);
				}
				value->sip_value_state = SIP_VALUE_BAD;
				goto get_next_via_value;
			}
		} else if (sip_find_separator(sip_header, SIP_SEMI, SIP_COMMA,
		    SIP_HCOLON, B_FALSE)) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_phdr(parsed_header);
				return (EPROTO);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_via_value;
		}
		value->via_sent_by_host.sip_str_len =
		    sip_header->sip_hdr_current -
		    value->via_sent_by_host.sip_str_ptr;

		if (sip_skip_white_space(sip_header) != 0) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_phdr(parsed_header);
				return (EPROTO);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_via_value;
		}

		if (*sip_header->sip_hdr_current == SIP_HCOLON) {
			sip_header->sip_hdr_current++;
			/*
			 * We have a port number
			 */
			if (sip_atoi(sip_header, &value->via_sent_by_port) !=
			    0) {
				if (sip_goto_next_value(sip_header) != 0) {
					sip_free_phdr(parsed_header);
					return (EPROTO);
				}
				value->sip_value_state = SIP_VALUE_BAD;
				goto get_next_via_value;
			}

		}

		/*
		 * Do some sanity checking.
		 * This should be replaced by a v4/v6 address check.
		 */
		if (value->via_sent_by_host.sip_str_len == 0 ||
		    (!isalnum(*value->via_sent_by_host.sip_str_ptr) &&
		    *value->via_sent_by_host.sip_str_ptr != '[')) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_phdr(parsed_header);
				return (EPROTO);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_via_value;
		}

		ret = sip_parse_params(sip_header, &value->sip_param_list);
		if (ret == EPROTO) {
			value->sip_value_state = SIP_VALUE_BAD;
		} else if (ret != 0) {
			sip_free_phdr(parsed_header);
			return (ret);
		}
get_next_via_value:
		value->sip_value_end = sip_header->sip_hdr_current;

		if (sip_find_token(sip_header, SIP_COMMA) != 0)
			break;
		last_value = value;
		(void) sip_skip_white_space(sip_header);
	}

	sip_header->sip_hdr_parsed = parsed_header;

	*header = parsed_header;
	return (0);
}

/*
 * Max-Forwards  =  "Max-Forwards" HCOLON 1*DIGIT
 */
int
sip_parse_maxf_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser2(sip_header, header, SIP_INT_VAL));
}

/*
 * Content-Type     =  ( "Content-Type" / "c" ) HCOLON media-type
 * media-type       =  m-type SLASH m-subtype *(SEMI m-parameter)
 * m-type           =  discrete-type / composite-type
 * discrete-type    =  "text" / "image" / "audio" / "video"
 *                     / "application" / extension-token
 * composite-type   =  "message" / "multipart" / extension-token
 * extension-token  =  ietf-token / x-token
 * ietf-token       =  token
 * x-token          =  "x-" token
 * m-subtype        =  extension-token / iana-token
 * iana-token       =  token
 * m-parameter      =  m-attribute EQUAL m-value
 * m-attribute      =  token
 * m-value          =  token / quoted-string
 */
int
sip_parse_ctype_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser1(sip_header, header, SIP_SLASH));
}

/*
 * Content-Length  =  ( "Content-Length" / "l" ) HCOLON 1*DIGIT
 */
int
sip_parse_clen_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser2(sip_header, header, SIP_INT_VAL));
}

/*
 * Generic parser for Contact, From, To, Route and Record-Route headers
 *
 * Contact = ("Contact" / "m" ) HCOLON
 *		( STAR / (contact-param *(COMMA contact-param)))
 * contact-param  =  (name-addr / addr-spec) *(SEMI contact-params)
 * name-addr      =  [ display-name ] LAQUOT addr-spec RAQUOT
 * addr-spec      =  SIP-URI / SIPS-URI / absoluteURI
 * display-name   =  *(token LWS)/ quoted-string
 * contact-params     =  c-p-q / c-p-expires
 *                     / contact-extension
 *
 * From =  ( "From" / "f" ) HCOLON from-spec
 * from-spec = ( name-addr / addr-spec )
 *	*( SEMI from-param )
 * from-param  =  tag-param / generic-param
 * tag-param   =  "tag" EQUAL token
 *
 * To =  ( "To" / "t" ) HCOLON ( name-addr
 *	/ addr-spec ) *( SEMI to-param )
 * to-param  =  tag-param / generic-param
 *
 * Route        =  "Route" HCOLON route-param *(COMMA route-param)
 * route-param  =  name-addr *( SEMI rr-param )
 *
 * Record-Route  =  "Record-Route" HCOLON rec-route *(COMMA rec-route)
 * rec-route     =  name-addr *( SEMI rr-param )
 * rr-param      =  generic-param
 *
 * We could have multiple values for these headers. For the ones that have
 * a display name we will have a LAQUOT/RAQUOT. If we encounter an error
 * when parsing a value, we mark the value as bad and start paring the
 * next value, if present. Before we start parsing the next value, we
 * check for any parameters, if present.
 */
int
sip_parse_cftr_header(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	sip_parsed_header_t	*parsed_header;
	char			*tmp_ptr;
	char			*tmp_ptr_2;
	int			ret;
	sip_hdr_value_t		*value = NULL;
	sip_hdr_value_t		*last_value = NULL;

	if ((ret = sip_prim_parsers(sip_header, header)) != 0)
		return (ret);

	if (*header != NULL)
		return (0);

	parsed_header = calloc(1, sizeof (sip_parsed_header_t));
	if (parsed_header == NULL)
		return (ENOMEM);
	parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;
	parsed_header->sip_header = sip_header;
	while (sip_header->sip_hdr_current < sip_header->sip_hdr_end) {
		boolean_t	quoted_name = B_FALSE;

		value =  calloc(1, sizeof (sip_hdr_value_t));
		if (value == NULL) {
			sip_free_cftr_header(parsed_header);
			return (ENOMEM);
		}
		if (last_value != NULL)
			last_value->sip_next_value = value;
		else
			parsed_header->value = (sip_value_t *)value;
		if (*sip_header->sip_hdr_current == SIP_QUOTE) {
			sip_header->sip_hdr_current++;
			quoted_name = B_TRUE;
		}
		value->sip_value_version = SIP_VALUE_VERSION_1;
		value->sip_value_start = sip_header->sip_hdr_current;
		value->sip_value_header = parsed_header;
		/*
		 * let's see if there is a display name
		 */
		if (*sip_header->sip_hdr_current != SIP_LAQUOT) {

			tmp_ptr = sip_header->sip_hdr_current;
			/*
			 * According to 20.10 '<' may not have a leading
			 * space.
			 */
			if (quoted_name &&
			    sip_find_token(sip_header, SIP_QUOTE) != 0) {
				if (sip_goto_next_value(sip_header) != 0) {
					sip_free_cftr_header(parsed_header);
					return (EPROTO);
				}
				value->sip_value_state = SIP_VALUE_BAD;
				goto get_next_cftr_value;
			} else if (sip_find_separator(sip_header, SIP_SEMI,
			    SIP_LAQUOT, SIP_COMMA, B_TRUE) != 0) {
				/*
				 * only a uri.
				 */
				value->cftr_uri.sip_str_ptr = tmp_ptr;
				value->cftr_uri.sip_str_len =
				    sip_header->sip_hdr_current - tmp_ptr;
				/*
				 * It's an error not to have a uri.
				 */
				if (value->cftr_uri.sip_str_len == 0) {
					if (sip_goto_next_value(sip_header) !=
					    0) {
						sip_free_cftr_header(
						    parsed_header);
						return (EPROTO);
					}
					value->sip_value_state = SIP_VALUE_BAD;
					goto get_next_cftr_value;
				}
				goto get_next_cftr_value;
			}
			/*
			 * This is needed to get rid of leading white spaces of
			 * display name or uri
			 */
			--sip_header->sip_hdr_current;
			(void) sip_reverse_skip_white_space(sip_header);
			++sip_header->sip_hdr_current;
			tmp_ptr_2 = sip_header->sip_hdr_current;
			if (*sip_header->sip_hdr_current == SIP_SP) {
				if (sip_skip_white_space(sip_header) != 0) {
					/*
					 * only a uri.
					 */
					value->cftr_uri.sip_str_ptr = tmp_ptr;
					value->cftr_uri.sip_str_len =
					    tmp_ptr_2 - tmp_ptr;
					/*
					 * It's an error not to have a uri.
					 */
					if (value->cftr_uri.sip_str_len == 0) {
						if (sip_goto_next_value(
						    sip_header) != 0) {
							sip_free_cftr_header(
							    parsed_header);
							return (EPROTO);
						}
						value->sip_value_state =
						    SIP_VALUE_BAD;
						goto get_next_cftr_value;
					}
					goto get_next_cftr_value;
				}
			}

			if (*sip_header->sip_hdr_current != SIP_LAQUOT) {
				/*
				 * No display name here.
				 */
				value->cftr_uri.sip_str_ptr = tmp_ptr;
				value->cftr_uri.sip_str_len = tmp_ptr_2 -
				    tmp_ptr;
				/*
				 * It's an error not to have a uri.
				 */
				if (value->cftr_uri.sip_str_len == 0) {
					if (sip_goto_next_value(sip_header) !=
					    0) {
						sip_free_cftr_header(
						    parsed_header);
						return (EPROTO);
					}
					value->sip_value_state = SIP_VALUE_BAD;
					goto get_next_cftr_value;
				}
				goto get_params;
			}

			value->cftr_name = malloc(sizeof (sip_str_t));
			if (value->cftr_name == NULL) {
				sip_free_cftr_header(parsed_header);
				return (ENOMEM);
			}
			value->cftr_name->sip_str_ptr = tmp_ptr;
			value->cftr_name->sip_str_len = tmp_ptr_2 - tmp_ptr;
			if (quoted_name)
				value->cftr_name->sip_str_len--;
		}

		if (sip_find_token(sip_header, SIP_LAQUOT) != 0) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_cftr_header(parsed_header);
				return (EPROTO);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_cftr_value;
		}

		if (*sip_header->sip_hdr_current == SIP_SP) {
			if (sip_skip_white_space(sip_header) != 0) {
				if (sip_goto_next_value(sip_header) != 0) {
					sip_free_cftr_header(parsed_header);
					return (EPROTO);
				}
				value->sip_value_state = SIP_VALUE_BAD;
				goto get_next_cftr_value;
			}
		}

		tmp_ptr = sip_header->sip_hdr_current;

		if (sip_find_separator(sip_header, SIP_RAQUOT, 0, 0, B_FALSE)) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_cftr_header(parsed_header);
				return (EPROTO);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_cftr_value;
		}

		value->cftr_uri.sip_str_ptr = tmp_ptr;
		value->cftr_uri.sip_str_len =
		    sip_header->sip_hdr_current - tmp_ptr;

		if (sip_find_token(sip_header, SIP_RAQUOT) != 0) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_cftr_header(parsed_header);
				return (EINVAL);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_cftr_value;
		}

		if (value->cftr_uri.sip_str_len <= strlen("<>")) {
			if (sip_goto_next_value(sip_header) != 0) {
				sip_free_cftr_header(parsed_header);
				return (EPROTO);
			}
			value->sip_value_state = SIP_VALUE_BAD;
			goto get_next_cftr_value;
		}

get_params:
		ret = sip_parse_params(sip_header, &value->sip_param_list);
		if (ret == EPROTO) {
			value->sip_value_state = SIP_VALUE_BAD;
		} else if (ret != 0) {
			sip_free_cftr_header(parsed_header);
			return (ret);
		}
get_next_cftr_value:
		value->sip_value_end = sip_header->sip_hdr_current;

		/*
		 * Parse uri
		 */
		if (value->cftr_uri.sip_str_len > 0) {
			int			error;
			uint_t			uri_errflags;
			char			*uri = "*";
			_sip_msg_t		*sip_msg;
			sip_message_type_t	*msg_type;

			value->sip_value_parsed_uri = sip_parse_uri(
			    &value->cftr_uri, &error);
			if (value->sip_value_parsed_uri == NULL) {
				sip_free_cftr_header(parsed_header);
				return (ENOMEM);
			}
			uri_errflags = ((_sip_uri_t *)value->
			    sip_value_parsed_uri)->sip_uri_errflags;
			if (error != 0 || uri_errflags != 0) {
				if ((strcmp(SIP_CONTACT, sip_header->
				    sip_header_functions->header_name) == 0) &&
				    (strncmp(value->cftr_uri.sip_str_ptr, uri,
				    strlen(uri)) == 0) && (strlen(uri) ==
				    value->cftr_uri.sip_str_len)) {
					sip_msg = sip_header->sip_hdr_sipmsg;
					msg_type = sip_msg->sip_msg_req_res;
					if (msg_type->is_request && msg_type->
					    sip_req_method == REGISTER) {
						error = 0;
						((_sip_uri_t *)value->
						    sip_value_parsed_uri)->
						    sip_uri_errflags = 0;
					} else {
						value->sip_value_state =
						    SIP_VALUE_BAD;
					}
				} else {
					value->sip_value_state = SIP_VALUE_BAD;
				}
			}
		}

		(void) sip_find_token(sip_header, SIP_COMMA);
		last_value = value;
		(void) sip_skip_white_space(sip_header);
	}

	sip_header->sip_hdr_parsed = parsed_header;

	*header = parsed_header;
	return (0);
}

/*
 * PAssertedID = "P-Asserted-Identity" HCOLON PAssertedID-value
 *               *(COMMA PAssertedID-value)
 * PAssertedID-value = name-addr / addr-spec
 */
int
sip_parse_passertedid(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser3(sip_header, header, SIP_STRS_VAL,
	    B_TRUE));
}

/*
 * PPreferredID = "P-Preferred-Identity" HCOLON PPreferredID-value
 *               *(COMMA PAssertedID-value)
 * PPreferredID-value = name-addr / addr-spec
 */
int
sip_parse_ppreferredid(_sip_header_t *sip_header, sip_parsed_header_t **header)
{
	return (sip_parse_hdr_parser3(sip_header, header, SIP_STRS_VAL,
	    B_TRUE));
}


/*
 * We don't do anything for a header we don't understand
 */
/* ARGSUSED */
int
sip_parse_unknown_header(_sip_header_t *sip_header,
    sip_parsed_header_t **header)
{
	return (EINVAL);
}
