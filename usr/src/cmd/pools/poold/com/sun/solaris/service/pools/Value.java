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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

package com.sun.solaris.service.pools;

/**
 * The <code>Value</code> class represents a pools value.
 */
public class Value {

	private long _this;

	/**
	 * Constructor. Only for use from native code.
	 * @param pointer A pointer to a C value.
	 */
	private Value(long pointer)
	{
		_this = pointer;
	}

	/**
	 * Constructor
	 * @param name The name of the value.
	 * @throws PoolsException If there is an error whilst
	 * allocating the value.
	 */
	public Value(String name) throws PoolsException
	{
		if ((_this = PoolInternal.pool_value_alloc()) == 0)
			throw new PoolsException();
		setName(name);
	}

	/**
	 * Constructor
	 * @param name The name of the value.
	 * @param value The value of the value.
	 * @throws PoolsException If there is an error whilst
	 * allocating the value.
	 */
	public Value(String name, long value) throws PoolsException
	{
		this(name);
		setValue(value);
	}

	/**
	 * Constructor
	 * @param name The name of the value.
	 * @param value The value of the value.
	 * @param s Indicates if the value is signed or not.
	 * @throws PoolsException If there is an error whilst
	 * allocating the value.
	 */
	public Value(String name, long value, boolean s) throws PoolsException
	{
		this(name);
		setValue(value, s);
	}

	/**
	 * Constructor
	 * @param name The name of the value.
	 * @param value The value of the value.
	 * @throws PoolsException If there is an error whilst
	 * allocating the value.
	 */
	public Value(String name, String value) throws PoolsException
	{
		this(name);
		setValue(value);
	}

	/**
	 * Constructor
	 * @param name The name of the value.
	 * @param value The value of the value.
	 * @throws PoolsException If there is an error whilst
	 * allocating the value.
	 */
	public Value(String name, boolean value) throws PoolsException
	{
		this(name);
		setValue(value);
	}

	/**
	 * Constructor
	 * @param name The name of the value.
	 * @param value The value of the value.
	 * @throws PoolsException If there is an error whilst
	 * allocating the value.
	 */
	public Value(String name, double value) throws PoolsException
	{
		this(name);
		setValue(value);
	}


	private boolean _locked = false;

	/**
	 * Check whether the value is locked or not
	 * @return returns the value of _locked
	 */
	public boolean islocked() throws PoolsException
        {
                return (_locked);
        }

	/**
	 * Lock the value
	 */
	public void lock() throws PoolsException
	{
		_locked = true;
	}

	/**
	 * Unlock the value
	 */
	public void unlock() throws PoolsException
	{
		_locked = false;
	}

	/**
	 * Explicitly reclaim the memory (if not locked)
	 * allocated for this value by the C proxy.
	 */
	public void close()
	{
		if (_locked == false) {
			if (_this != 0) {
				PoolInternal.pool_value_free(_this);
				_this = 0;
			}
		}
	}

	/**
	 * Reclaim the memory allocated for this value by the C
	 * proxy.
	 *
	 * @throws Throwable If freeing this configuration fails.
	 */
	protected void finalize() throws Throwable
	{
		try
		{
			unlock();
			close();
		}
		finally
		{
			super.finalize();
		}
	}

	/**
	 * Name this value.
	 *
	 * @param name The name to set for this value.
	 */
	public void setName(String name)
	{
		PoolInternal.pool_value_set_name(_this, name);
	}

	/**
	 * Set this value to take the supplied signed long value.
	 *
	 * @param value The value to which this value should be set.
	 */
	public void setValue(long value)
	{
		PoolInternal.pool_value_set_int64(_this, value);
	}

	/**
	 * Set this value to take the supplied long value.
	 *
	 * @param value The value to which this value should be set.
	 * @param s Is the value signed or unsigned.
	 */
	public void setValue(long value, boolean s)
	{
		if (s)
			setValue(value);
		PoolInternal.pool_value_set_uint64(_this, value);
	}

	/**
	 * Set this value to take the supplied string value.
	 *
	 * @param value The value to which this value should be set.
	 * @throws PoolsExecption If the setting of the value fails.
	 */
	public void setValue(String value) throws PoolsException
	{
		if (PoolInternal.pool_value_set_string(_this, value) !=
		    PoolInternal.PO_SUCCESS)
			throw new PoolsException();
	}

	/**
	 * Set this value to take the supplied boolean value.
	 *
	 * @param value The value to which this value should be set.
	 */
	public void setValue(boolean value)
	{
		if (value == true)
			PoolInternal.pool_value_set_bool(_this, (short)1);
		else
			PoolInternal.pool_value_set_bool(_this, (short)0);
	}

	/**
	 * Set this value to take the supplied double value.
	 *
	 * @param value The value to which this value should be set.
	 */
	public void setValue(double value)
	{
		PoolInternal.pool_value_set_double(_this, value);
	}

	/**
	 * Returns the name of the value.
	 *
	 * @return the name of the value.
	 */
	public String getName()
	{
		return (PoolInternal.pool_value_get_name(_this));
	}

	/**
	 * Returns the pointer to the native value represented by this
	 * object.
	 *
	 * @return the pointer to the native value represented by this
	 * object.
	 */
	public long getValue()
	{
		return (_this);
	}

	/**
	 * Returns the type of this object.
	 *
	 * @return the type of this object.
	 */
	public int getType()
	{
		return (PoolInternal.pool_value_get_type(_this));
	}

	/**
	 * Returns a string representation of this value.
	 *
	 * @return a string representation of this value.
	 */
	public String toString()
	{
		int type = PoolInternal.pool_value_get_type(_this);

		try {
			if (type == PoolInternal.POC_INT ||
			    type == PoolInternal.POC_UINT)
				return (String.valueOf(getLong()));
			if (type == PoolInternal.POC_STRING)
				return getString();
			if (type == PoolInternal.POC_BOOL)
				return (String.valueOf(getBool()));
			if (type == PoolInternal.POC_DOUBLE)
				return (String.valueOf(getDouble()));
		}
		catch (PoolsException pe) {
			return pe.toString();
		}
		return "";	/* Stop the compiler complaining */
	}

        /**
         * Returns the value as a UnsignedInt64.
         *
         * @return the value as a UnsignedInt64.
         * @throws PoolsException if the value is not an
         * UnsignedInt64.
         */
	public final UnsignedInt64 getUnsignedInt64() throws PoolsException
	{
		return (getUnsignedInt64Value(_this));
	}

        /**
         * Returns the value as a long.
         *
         * @return the value as a long.
         * @throws PoolsException if the value is not a long.
         */
	public final long getLong() throws PoolsException
	{
		return (getLongValue(_this));
	}

        /**
         * Returns the value as a String.
         *
         * @return the value as a String.
         * @throws PoolsException if the value is not a String.
         */
	public final String getString() throws PoolsException
	{
		return (getStringValue(_this));
	}

        /**
         * Returns the value as a boolean.
         *
         * @return the value as a boolean.
         * @throws PoolsException if the value is not a boolean.
         */
	public final boolean getBool() throws PoolsException
	{
		return (getBoolValue(_this));
	}

        /**
         * Returns the value as a double.
         *
         * @return the value as a double.
         * @throws PoolsException if the value is not a double.
         */
	public final double getDouble() throws PoolsException
	{
		return (getDoubleValue(_this));
	}

        /**
         * Returns the value as a UnsignedInt64.
         *
         * @param pointer the native value to be accessed.
         * @return the value as a UnsignedInt64.
         */
	private final static native UnsignedInt64 getUnsignedInt64Value(
	    long pointer);

        /**
         * Returns the value as a long.
         *
         * @param pointer the native value to be accessed.
         * @return the value as a long.
         */
	private final static native long getLongValue(long pointer);

        /**
         * Returns the value as a String.
         *
         * @param pointer the native value to be accessed.
         * @return the value as a String.
         */
	private final static native String getStringValue(long pointer);

        /**
         * Returns the value as a boolean.
         *
         * @param pointer the native value to be accessed.
         * @return the value as a boolean.
         */
	private final static native boolean getBoolValue(long pointer);

        /**
         * Returns the value as a double.
         *
         * @param pointer the native value to be accessed.
         * @return the value as a double.
         */
	private final static native double getDoubleValue(long pointer);
}
