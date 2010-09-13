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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/**
 * Copyright 1996 Active Software Inc. 
 */

package sunsoft.jws.visual.rt.props;

import java.text.Format;
import java.text.MessageFormat;
import java.util.*;

public class MessageCatalog
{
    
    public MessageCatalog(String domainname, Locale locale)
	{
	    super();
	    this.domainname = domainname;
	    this.locale = locale;
	    try
	    {
		resource = ResourceBundle.getBundle(domainname, locale);
	    }
	    catch (Exception e)
	    {
		e.printStackTrace();
	    }
	}
    
    public MessageCatalog(String domainname)
	{
	    this(domainname, Locale.getDefault());
	}
    
    public String getMessage(String defaultMessage)
	{
	    return getKeyMessage(defaultMessage, defaultMessage);
	}
    
    public String getFormattedMessage(String defaultMessage,
				      Object arg)
	{
	    return getFormattedKeyMessage(defaultMessage, defaultMessage,
					  arg);
	}
    
    public String getFormattedMessage(String defaultMessage,
				      Object arg1, Object arg2)
	{
	    return getFormattedKeyMessage(defaultMessage, defaultMessage,
					  arg1, arg2);
	}
    
    public String getFormattedMessage(String defaultMessage,
				      Object arg1, Object arg2,
				      Object arg3)
	{
	    return getFormattedKeyMessage(defaultMessage, defaultMessage,
					  arg1, arg2, arg3);
	}
    
    public String getFormattedMessage(String defaultMessage,
				      Object arg[])
	{
	    return getFormattedKeyMessage(defaultMessage, defaultMessage,
					  arg);
	}
    
    public String getKeyMessage(String key, String defaultMessage)
	{
	    String result = null;
	    if (resource == null)
		result = defaultMessage;
	    else
		try
		{
		    result = resource.getString(key);
		}
	    catch (MissingResourceException ex)
	    {
		result = defaultMessage;
	    }
	    catch (Exception ex)
	    {
		result = defaultMessage;
	    }
	    return result;
	}
    
    public String getFormattedKeyMessage(String key,
					 String defaultMessage,
					 Object arg)
	{
	    String result = getKeyMessage(key, defaultMessage);
	    Object rarg[] = {
		arg
	    };
	    return new MessageFormat(result).format(rarg);
	}
    
    public String getFormattedKeyMessage(String key,
					 String defaultMessage,
					 Object arg1, Object arg2)
	{
	    String result = getKeyMessage(key, defaultMessage);
	    Object arg[] = {
		arg1, arg2
	    };
	    return new MessageFormat(result).format(arg);
	}
    
    public String getFormattedKeyMessage(String key,
					 String defaultMessage,
					 Object arg1, Object arg2,
					 Object arg3)
	{
	    String result = getKeyMessage(key, defaultMessage);
	    Object arg[] = {
		arg1, arg2, arg3
	    };
	    return new MessageFormat(result).format(arg);
	}
    
    public String getFormattedKeyMessage(String key,
					 String defaultMessage,
					 Object arg[])
	{
	    String result = getKeyMessage(key, defaultMessage);
	    return new MessageFormat(result).format(arg);
	}
    
    public String noTranslation(String message)
	{
	    return message;
	}
    
    public String noTranslation(String message, Object arg1)
	{
	    String result = noTranslation(message);
	    Object arg[] = {
		arg1
	    };
	    return new MessageFormat(result).format(arg);
	}
    
    public String noTranslation(String message, Object arg1,
				Object arg2)
	{
	    String result = noTranslation(message);
	    Object arg[] = {
		arg1, arg2
	    };
	    return new MessageFormat(result).format(arg);
	}
    
    public String noTranslation(String message, Object arg1,
				Object arg2, Object arg3)
	{
	    String result = noTranslation(message);
	    Object arg[] = {
		arg1, arg2, arg3
	    };
	    return new MessageFormat(result).format(arg);
	}
    
    public String noTranslation(String message, Object arg[])
	{
	    String result = noTranslation(message);
	    return new MessageFormat(result).format(arg);
	}
    
    private String domainname;
    private ResourceBundle resource;
    private Locale locale;
}
