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

package sunsoft.jws.visual.rt.encoding;

import java.io.*;

// Referenced classes of package sunsoft.jws.visual.rt.encoding:
//            CRC16

public class UCEncoder
{
    
    protected int bytesPerAtom()
    {
        return 2;
    }
    
    protected int bytesPerLine()
    {
        return 48;
    }
    
    protected void encodeAtom(OutputStream outStream, byte data[],
			      int offset, int len)
	throws IOException
    {
        byte a = data[offset];
        byte b;
        if (len == 2)
            b = data[offset + 1];
        else
            b = 0;
        crc.update(a);
        if (len == 2)
            crc.update(b);
        outStream.write(map_array[(a >>> 2 & 0x38) + (b >>> 5 & 0x7)]);
        int p1 = 0;
        int p2 = 0;
        for (int i = 1; i < 256; i *= 2)
	    {
		if ((a & i) != 0)
		    p1++;
		if ((b & i) != 0)
		    p2++;
	    }
        
        p1 = (p1 & 0x1) * 32;
        p2 = (p2 & 0x1) * 32;
        outStream.write(map_array[(a & 0x1f) + p1]);
        outStream.write(map_array[(b & 0x1f) + p2]);
    }
    
    protected void encodeLinePrefix(OutputStream outStream, int length)
	throws IOException
    {
        outStream.write(42);
        crc.value = 0;
        tmp[0] = (byte)length;
        tmp[1] = (byte)sequence;
        sequence = sequence + 1 & 0xff;
        encodeAtom(outStream, tmp, 0, 2);
    }
    
    protected void encodeLineSuffix(OutputStream outStream)
	throws IOException
    {
        tmp[0] = (byte)(crc.value >>> 8 & 0xff);
        tmp[1] = (byte)(crc.value & 0xff);
        encodeAtom(outStream, tmp, 0, 2);
        pStream.println();
    }
    
    protected void encodeBufferPrefix(OutputStream a)
	throws IOException
    {
        sequence = 0;
        pStream = new PrintStream(a);
    }
    
    public void encodeBuffer(InputStream inStream,
			     OutputStream outStream)
	throws IOException
    {
        byte tmpbuffer[] = new byte[bytesPerLine()];
        encodeBufferPrefix(outStream);
        int numBytes;
        do
	    {
		numBytes = readFully(inStream, tmpbuffer);
		if (numBytes == -1)
		    break;
		encodeLinePrefix(outStream, numBytes);
		for (int j = 0; j < numBytes; j += bytesPerAtom())
		    if (j + bytesPerAtom() <= numBytes)
			encodeAtom(outStream, tmpbuffer, j, bytesPerAtom());
		    else
			encodeAtom(outStream, tmpbuffer, j, numBytes - j);
            
		encodeLineSuffix(outStream);
	    }
        while (numBytes >= bytesPerLine());
        encodeBufferSuffix(outStream);
    }
    
    protected int readFully(InputStream in, byte buffer[])
	throws IOException
    {
        for (int i = 0; i < buffer.length; i++)
	    {
		int q = in.read();
		if (q == -1)
		    return i;
		buffer[i] = (byte)q;
	    }
        
        return buffer.length;
    }
    
    protected void encodeBufferSuffix(OutputStream outputstream)
	throws IOException
    {
    }
    
    public String encodeBuffer(byte aBuffer[])
    {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        ByteArrayInputStream inStream =
	    new ByteArrayInputStream(aBuffer);
        try
	    {
		encodeBuffer(inStream, outStream);
	    }
        catch (Exception ex)
	    {
		throw new Error("encodeBuffer internal error");
	    }
        return outStream.toString();
    }
    
    public UCEncoder()
    {
        super();
        tmp = new byte[2];
        crc = new CRC16();
    }
    
    private PrintStream pStream;
    private static final byte map_array[] = {
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
        75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
        85, 86, 87, 88, 89, 90, 97, 98, 99, 100,
        101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
        111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
        121, 122, 40, 41
    };
    private int sequence;
    private byte tmp[];
    private CRC16 crc;
    
}
