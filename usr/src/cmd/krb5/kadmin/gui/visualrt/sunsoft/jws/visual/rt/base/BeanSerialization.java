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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 */

/*
 * @(#) BeanSerialization.java 1.5 - last change made 08/06/97
 */

package sunsoft.jws.visual.rt.base;

import java.io.*;

import sunsoft.jws.visual.rt.encoding.*;

public class BeanSerialization {
    
    final static private boolean debug = false;
    final static private boolean test = false;
    
    static public String serializeObject(Object obj) {
        if (debug) System.out.println(/* NOI18N */"\nserializeObject: entered");
        
        /*
	** serialize the bean
	*/
        
        ByteArrayOutputStream byteOutStrm = new ByteArrayOutputStream();
        try {
            ObjectOutputStream objOutStrm = new ObjectOutputStream(byteOutStrm);
            objOutStrm.writeObject(obj);
            objOutStrm.flush();
        } catch (NotSerializableException ex) {
            // skip it since it is not serializable - not an err
            if (debug) System.out.println(ex.toString());
            return null;
        } catch (Exception ex) {
            throw new VJException(Global.fmtMsg(
		"sunsoft.jws.visual.rt.base.BeanSerialization.serExcpt",
						obj, ex.toString()));
        }
        byte[] buf = byteOutStrm.toByteArray();
        
        if (debug) System.out.println(/* NOI18N */
				      "serializeObject: serialized");
        
        /*
	** encode the string
	*/
        
        UCEncoder encoder = new UCEncoder();
        String str = encoder.encodeBuffer(buf);
        
        if (debug) System.out.println(/* NOI18N */"serializeObject: encoded");
        
        return str;
    }
    
    static public Object deserializeObject(String value, String objName) {
        if (debug) System.out.println(/* NOI18N */
				      "\ndeserializeObject: entered");
        
        if (value == null || value.length() == 0) {
            if (debug) { 
/* JSTYLED */ 
                System.out.println(/* NOI18N */"deserializeObject: value is null");
            }
            return null;
        }
        
        /*
	** decode the string first
	*/
        
        byte buf[] = null;
        try {
            UCDecoder decoder = new UCDecoder();
            buf = decoder.decodeBuffer(value);
        } catch (Exception ex) {
            if (debug) System.out.println(ex.toString());
            throw new VJException(Global.fmtMsg(
		"sunsoft.jws.visual.rt.base.BeanSerialization.decoderExcpt",
						objName));
        }
        if (debug) System.out.println(/* NOI18N */"deserializeObject: decoded");
        
        /*
	** deserialize the object
	*/
        
        Object newBody = null;
        try {
            ByteArrayInputStream byteInStrm = new ByteArrayInputStream(buf);
            ObjectInputStream objInStrm = new ObjectInputStream(byteInStrm);
            newBody = objInStrm.readObject();
        } catch (Exception ex) {
            // ClassNotFoundException   from readObject
            // OptionalDataException    from readObject
            // StreamCorruptedException from ObjectInputStream
            // IOException              from ObjectInputStream
            String errMsg = Global.fmtMsg(
		  "sunsoft.jws.visual.rt.base.BeanSerialization.deserExcpt",
					  objName, ex.toString());
            if (java.beans.Beans.isDesignTime()) {
                DesignerAccess.reportInstantiationError(errMsg);
            }
            else
		{
		    throw new VJException(errMsg);
		}
        }
        if (debug) {
            System.out.println(/* NOI18N */"deserializeObject: deserialized");
        }
        return newBody;
    }
}
