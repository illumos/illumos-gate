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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/**
 * \file KMSAgentLoadBalancer.h
 */

#ifndef KMS_AGENT_LOAD_BALANCER_H
#define KMS_AGENT_LOAD_BALANCER_H
typedef char UTF8_KEYID[2*KMS_KWK_KEY_ID_SIZE+1];

class CAgentLoadBalancer
{
public:

    /**
     *  the load balancer retains a pointer to the specified profile 
     */
    CAgentLoadBalancer(
            KMSClientProfile * const i_pProfile );

    ~CAgentLoadBalancer ();
   
    /**
     *  This method must be called at the top of each agent library transaction.
     *  Responsibilities:
     *  <ul>
     *  <li>clear profile failover attempts
     *  <li>sets transaction start time
     *  <li>performs discovery at the frequency specified in the profile
     *  <li>maintains the status of KMAs within the cluster
     *  </ul>
     *  @return a random KMA from the "available" KMAs within the agent's site
     *      or a random KMA from any of the "available" KMA's if none are available
     *      within the agent's site.  
     *      When operating in FIPS mode then only KMAs that are
     *      FIPS compatible will be selected, see <code>FIPScompatibleKMA</code>.  
     *      Available KMAs
     *      are KMAs that are enabled and responding.  If no FIPS compatible KMAs
     *      are available then <code>NO_FIPS_KMA_AVAILABLE</code> is returned.
     *      When <code>m_iClusterDiscoveryFrequency</code> is set to 0 in the profile
    *       then load balancing and automatic discovery
     *      are disabled so the default KMA is returned.
     */
    int Balance();

    /**
     *  @return a KMA from the cache that has affinity with the specified DataUnitID,
     *  if possible, otherwise return a KMA from <code>Balance</code>.  See
     *  <code>Balance</code> for <code>FIPS_MODE</code> behavior and disabled load balancing.
     */
    int BalanceByDataUnitID(
            const unsigned char * const i_pDataUnitID,
            int i_iDataUnitIDMaxLen );

    /**
     *  @return a KMA from the cache that has affinity with the specified DataUnitKeyID,
     *  if possible, otherwise return a KMA from <code>Balance</code>.  See
     *  <code>Balance</code> for <code>FIPS_MODE</code> behavior and disabled load balancing.
     */
    int BalanceByDataUnitKeyID(
            const unsigned char * const i_pDataUnitKeyID,
            int i_iDataUnitKeyIDMaxLen );

    enum ERRORS
    {
        CLIENT_SIDE_ERROR = -1,
        NO_KMA_AVAILABLE = -2,
        AES_KEY_UNWRAP_ERROR = -3,
        AES_KEY_WRAP_SETUP_ERROR = -4,
        NO_FIPS_KMA_AVAILABLE = -5,
        KWK_NOT_REGISTERED = -6
    };
    
    /**
     *  Makes a failover determination based upon soap error information and profile settings.
     *  Responsibilities:
     *  <ul>
     *  <li>updates the status of the failed KMA within the profile's cluster array
     *  <li>Client Faults - no failover, same KMA will be returned if a Server Busy error 
     *  occurred and
     *  either the transaction timeout has not been exceeded or failover limit has not been exceeded
     *  <li>Server Faults - a failover KMA is chosen if the limit specified set in the profile
     *  has not been exceed
     *  <li>For <code>CLIENT_ERROR_AGENT_KWK_NOT_REGISTERED</code> the KWK is deleted and 
     *  i_iFailedApplianceIndex is returned.  The caller should re-regsiter the
     *  KWK with this appliance.
     *  </ul> 
     *  If all KMAs are disabled or non-responding then give up.
     *  <li>increments profile failover attempts
     *  </ul>
     *  @param i_iFailedApplianceIndex the index within the profile's cluster array of the failed KMA
     *  @param i_pstSoap the gSoap runtime from which error information can be analyzed
     *  @return index of KMA in cluster to failover to, <code>CLIENT_SIDE_ERROR</code> to give up due to client side error, 
     *  <code>NO_KMA_AVAILABLE</code> or <code>NO_FIPS_KMA_AVAILABLE</code> if running in FIPS_MODE
     *  if server error but no KMA to failover to 
     */
    int FailOver(
            int i_iFailedApplianceIndex,
            struct soap *i_pstSoap );
    
    /**
     *  Updates the response status for the specified KMA to responding.  
     */
    void UpdateResponseStatus(int i_iIndex);

    /**
     *   @return HTTPS protocol URL for the KMA referenced by the specified index entry within this
     *   object's cluster array and the specified web service port.
     */
    char* GetHTTPSURL(
            int i_iIndex,
            int i_iPort );
    /**
     *   @return HTTP protocol URL for the KMA referenced by the specified index entry within this
     *   object's cluster array and the specified web service port.
     */
    char* GetHTTPURL(
            int i_iIndex,
            int i_iPort );

    /**
     *    @return the KMA IP address for the specified index entry within this object's cluster 
     *    array.
     */
    char* GetApplianceNetworkAddress(
            int i_iIndex );

    /**
     *    @return the KMA ID for the specified index entry within this 
     *    object's cluster.  Returns -1 if an invalid
     *    index is provided
     */
    Long64 GetKMAID(
            int i_iIndex );

    /**
     *  retrieves the KWKID for a specified KMA in the cluster.
     *  @param i_Index element in this object's KMS cluster as returned by
     *      one of the Balance methods or the Failover method.
     *  @param i_lKMAID the KMAID for which a KWK is desired
     *  @param i_pstSoap non-NULL pointer to an initialized gSoap runtime to be 
     *  used, if necessary, for KWK registration with the KMA.
     *  @param o_pKWKID pointer to UTF8 hex character string to receive the KWKID 
     *  for the specified KMA in the cluster.
     *  @param o_pbClientAESKeyWrapSetupError this arg gets set to true if an
     *  error occurs that is client side related and pertaining to establishment
     *  of the AES Key Wrapping Keys.
     *  If the KMS cluster does not support AES KeyWrap o_pKWKID is set to
     *  a zero-length string.  A new KWK may be registered with the KMA if a value 
     *  has not yet been registered for this instance of CAgentLoadBalancer.
     *  @return TRUE if successful and FALSE otherwise with soap fault available
     *  in the gSoap runtime provided by the caller and io_pIndex set to 
     *  AES_KEY_WRAP_SETUP_ERROR.  Use ServerError() to
     *  determine if failover is appropriate. 
     */
    int GetKWKID(
            int                 i_Index,
            Long64              i_lKMAID,
            struct soap * const i_pstSoap,
            UTF8_KEYID          o_pKWKID,
            bool * const        o_pbClientAESKeyWrapSetupError);
  
    /**
     *  performs AES Key unwrapping according to RFC3394.
     *  @param  io_pIndex Cluster index for KMA that wrapped the key. On error
     *  the cluster index is set to AES_KEY_UNWRAP_ERROR
     *  @param  i_pAESWrappedKey pointer to the wrapped key
     *  @param  o_pPlainTextKey point to buffer to receive unwrapped key
     *  @return true for success, false otherwise and sets *io_pIndex to 
     *  AES_KEY_UNWRAP_ERROR
     */
    bool AESKeyUnwrap (
                       int * const io_pIndex,
                       const WRAPPED_KEY i_pAESWrappedKey,
                       KEY o_pPlainTextKey );
    
    /**
     *  @return true if the KMA referenced by the specified cluster
     *  index supports AES key wrap
     */
    bool AESKeyWrapSupported (
                              int i_iIndex);
    
protected:
    /**
     *  @return the cluster array index of the KMA with the specified IP address
     *  or CLIENT_SIDE_ERROR if the KMA is not responding or not enabled
     */
    int FindIndexByNetworkAddress (
                                   char* i_wsApplianceNetworkAddress);

private:

    /**
     *  Sorts the cluster array ascending by load.
     *  Before sorting, the other site's KMAs' load are added by 0x10000000000 and
     *  the disabled/non-responding/locked KMAs are added by 0x1000000000000 and KMAs
     *  not matching the agent's FIPS setting the load is bumped by 0x100000000000000.
     *  This ensures that KMAs
     *  in the current site are sorted before KMAs in other sites and
     *  disabled/non-responding/locked KMAs are after those enabled KMAs.  When the agent is
     *  in FIPS mode the non-FIPS KMAs are sorted last.
     */
    void KMSClient_SortClusterArray (
                                     KMSClientProfile * const i_pProfile);
    
    static const int MAX_RSA_PUB_KEY_LENGTH = 256;
    int m_iClusterNum;
    
    /**
     *  this array is reinitialized from the profile's Cluster array each time Balance() is called.
     *  Failover() will resort the profile's Cluster array so this array may not
     *  match the sort order in the profile
     */
    KMSClusterEntry m_aCluster[KMS_MAX_CLUSTER_NUM];
    KMSClientProfile *m_pProfile;
    char m_sURL[KMS_MAX_URL+1];
    unsigned int m_iTransactionStartTimeInMilliseconds;
    bool m_bFIPS;
    
    /**
     *  number of elements in KWKEntries
     */
    int m_iKWKEntryNum;

    /**
     *  in a failover scenario, if all KMAs are not responding this
     *  member variable tracks the index into m_aCluster of the last KMA attempted.
     */
    int m_iLastAttemptedWhenNoneResponding;
    
    /**
     *  @return true if the failover limit has been exceeded. If failover
     *  limit of -1 is specified in the profile then always return false.
     */
    bool FailOverLimit(void);
        
    /**
     *  \struct for each KMA used in a profile session there will be
     *  a KWKEntry in KWKEntries.  These values do not persist
     *  beyond a profile session
     */
    struct KWKEntry
    {
        /**
         *  The KMA associated with this KWK.  This KMA
         *  receives the KWK via the KMS_Agent__RegisterAgentKWK()
         *  agent service which returns the KMA assigned value for
         *  m_acKWKID
         */
        Long64      m_lKMAID;
        
        /**
         *  the KeyID for this KWK, provided by the KMA
         */
        UTF8_KEYID      m_acKWKID;
        
        /**
         *  the plaintext value of the AES KWK
         */
        KEY         m_acKWK;
    };
            
    /**
     *  set of KWKEntry ptrs for KMAs used in this profile session.
     */
    struct KWKEntry * m_aKWKEntries[KMS_MAX_CLUSTER_NUM];
    
    /**
     *  retrieve the Key Wrapping Key for a KMA
     *  @param  i_lKMAID KMA identifier, must not be equal to -1 
     *  @return pointer to the KWKEntry for the specified KMAID, NULL
     *  if the entry does not exist
     */
    struct KWKEntry *GetKWK( 
                    Long64 i_lKMAID );
    
    /**
     *  creates a new KWKEntry on the heap and store a ptr to it in an
     *  unused slot in <code>m_aKWKEntries</code>. 
     *  @return NULL on error, otherwise a pointer to the newly
     *  created KWKEntry
     */
    struct KWKEntry *CreateKWK( 
                    Long64              i_lKMAID,
                    struct soap * const i_pstSoap,
                    const char * const  i_sURL,
                    bool * const        o_pbClientAESKeyWrapSetupError);
                    
    /**
     *   free the <code>KWKEntry</code> corresponding to the specified KMA ID
     *   and set the slot it occupied in <code>m_aKWKEntries</code> to NULL. 
     */
    void DeleteKWKEntry(Long64 i_lKMAID);
    
    /**
     *  retrieve the RSA public key to be used for wrapping a KWK
     */
    int GetKWKWrappingKey(
                    struct soap * const i_pstSoap,
                    const char * const  i_sURL,
                    CPublicKey * const  o_opPublicKEK );
    
    /**
     *  register the KWK with a specified KMA and return the KWK ID
     */
    int RegisterKWK( 
                    int                         i_iWrappedKWKSize,
                    const unsigned char * const i_acWrappedKWK, 
                    struct soap * const         i_pstSoap, 
                    const char * const          i_sURL, 
                    UTF8_KEYID                  o_acUTF8KeyID );
    
};

#endif //KMS_AGENT_LOAD_BALANCER_H
