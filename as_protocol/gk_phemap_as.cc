/*
    Group-Key-Phemap - Copyright (C) 2023-2024 Antonio Emmanuele

    This file is part of Group-Key-Phemap.

    Group-Key-Phemap is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    Group-Key-Phemap is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file gk_phemap_as.c
 * @author Antonio Emmanuele antony.35.ae@gmail.com
 * @brief Implementation of the gk phemap protocol for the AS 
 * @date 2023-06-18
 */
#include "gk_phemap_as.h"
#include "stdio.h"
#include "string.h"
#include "assert.h"
#include "math.h"

/**
 * @brief Calculate the sign using sign_key of the buff of size buff_size
 * 
 * @param buff              Buffer containing the datas to sign.
 * @param buff_size         Size of the buff in bytes. 
 * @param sign_key          Key used to sign. 
 * @return private_key_t    Calculated sign.   
 */
static private_key_t keyed_sign(const uint8_t *const buff, const uint32_t buff_size, const private_key_t sign_key );

/**
 * @brief Check if a mex requestor is in the list of phemap ids
 * 
 * @param req_id Id of the requestor
 * @param as Pointer to the AS struct 
 * @return uint8_t 1 if the requestor is in the list, else 0
 */
static inline uint8_t as_check_requestor(const phemap_id_t req_id,AuthServer* const as)
{
    assert(NULL != as);
    for(uint32_t i = 0;i < as->num_auth_devs; i++)
        if(as->auth_devs[i] == req_id)
            return 1;
    return 0;
}

phemap_ret_t gk_as_start_session_cb( AuthServer* const as,uint8_t * rcvd_start,uint8_t pkt_len)
{
    assert(NULL != as);
    assert(NULL != rcvd_start);
    if(rcvd_start[0] != START_SESS || pkt_len < 1 + sizeof(phemap_id_t) + sizeof(puf_resp_t))
    {
#if AS_PC_DBG
        printf("[AS-GK] Malformed start, needs resync rcvd_start %d len %d \n",rcvd_start[0],pkt_len);
#endif
        as->as_state = GK_AS_WAIT_FOR_START_REQ;
        return REINIT;
    }
    phemap_id_t req_id = U8_TO_PHEMAP_ID_BE(&rcvd_start[1]);
    // Check for the requestor id
    if( !as_check_requestor(req_id,as))
    {
#if AS_PC_DBG
        printf("[AS-GK] Req %u  not authenticated \n",req_id);
#endif
        as->as_state = GK_AS_WAIT_FOR_START_REQ;
        return REINIT;
    }
#if AS_PC_DBG
    else
        printf("[AS-GK] Starting sess for  %d \n",req_id);
#endif
    // Authenticate the device
    puf_resp_t link_req  = as_get_next_link(req_id); //ai-1
    puf_resp_t rcvd_link = U8_TO_PUF_BE(&rcvd_start[1+sizeof(phemap_id_t)]); 
    if(link_req != rcvd_link) //  Auth the requestor
    {
#if AS_PC_DBG
        printf("[AS-GK] Authentication failed, needs resync, expected %x rcvd %x   \n",link_req,rcvd_link);
#endif
        as->as_state = GK_AS_WAIT_FOR_START_REQ;
        return REINIT;
    }
    return gk_as_start_session(as);
}

phemap_ret_t gk_as_start_session( AuthServer* const as)
{
    assert(NULL != as);
    as->pk_installed = 0;
    puf_resp_t      auth[as->num_auth_devs]; 
    puf_resp_t      sr_noise[as->num_auth_devs]; 
    private_key_t   partial_key;
    uint8_t m_to_send[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)+2*sizeof(private_key_t)];
    uint16_t i;
    //  Initialize the mex common part 
    m_to_send[0] = START_PK;
    PHEMAP_ID_TO_U8_BE(as->as_id,&m_to_send[1]);
    as->private_key = 0;
    //  Initialize the key parts
    for( i=0;i<as->num_auth_devs;i++)
    {
        //  ai-> NOISE ADDED TO THE KEY
        //  The secret token noise is the same of the key noise !!
        sr_noise[i]     = as_get_next_link(as->auth_devs[i]);          
        //  ai+1 -> PART OF THE KEY 
        as->sr_key[i]   = as_get_next_link(as->auth_devs[i]);          
        //  ai+3 -> Authentication link
        auth[i] = as_get_next_link(as->auth_devs[i]);          
        //  Compose the pk        
        as->private_key ^= as->sr_key[i];
    }
    //  Generate and add the nonce for back and for
    //  security.
    as->session_nonce   =   as_rng_gen();
    as->private_key     ^=  as->session_nonce;
    //  Add the secret token 
    as->secret_token = as_rng_gen();
    //  Generte and send the pkts for devices 
    for( i = 0; i < as->num_auth_devs; i++)
    {
        //  Generate the key for device i
        //  key=xor(keyj, j!=i) 
        partial_key= sr_noise[i] ^ as->private_key ^ as->sr_key[i];
        // append the key part
        PUF_TO_U8_BE(partial_key,&m_to_send[1+sizeof(phemap_id_t)]); 
        // Append the secret token with its noise 
        PUF_TO_U8_BE((sr_noise[i]^as->secret_token),&m_to_send[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)]); 
        // Now sign the mex
        partial_key = keyed_sign(m_to_send,1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),auth[i]);
        // Append the sign
        PUF_TO_U8_BE(partial_key,&m_to_send[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)]);
        // **** Old deprecated
        //  as->as_write_to_device(as->as_id,as->auth_devs[i],m_to_send,1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)+sizeof(private_key_t));
        //  Instead of calling a snd function, write the data into a buffer and write
        //  Copy the buffer into the slot for the specific receiver
        //  Should always be 15 bytes
        memcpy(&as->unicast_tsmt_buff[as->auth_devs[i]],m_to_send,15); 
        //  Assign the first receiver id that must receive the pkt
        as->unicast_tsmt_queue[i]=as->auth_devs[i];
        //  Increase the count of messages into the tsmt queue.
        as->unicast_tsmt_count++;
        as->pending_conf[as->auth_devs[i]] = 1;   // set pending state
    }
    as->pending_count = as->num_auth_devs;
    as->as_state = GK_AS_WAIT_FOR_START_CONF;
    as_start_timer();
    return OK;
}

phemap_ret_t gk_as_conf_cb( AuthServer* const as,uint8_t * rcvd_conf,const uint8_t pkt_len)
{
    //  Check ptrs
    assert(NULL != as);
    assert(NULL != rcvd_conf);
    //  Check expected type and size 
    if(( rcvd_conf[0] != PK_CONF && rcvd_conf[0] != UPDATE_CONF) || pkt_len<1 + sizeof(phemap_id_t) + sizeof(puf_resp_t))
    {
#if AS_PC_DBG
        printf("[AS-GK] Confirmation failed, need reinitialization \n ");
#endif
        as->as_state = GK_AS_WAIT_FOR_START_REQ;
        return REINIT;
    }
    
    // Check if the requestor is in the list of auth devs
    phemap_id_t req_id = U8_TO_PHEMAP_ID_BE(&rcvd_conf[1]);
    if( !as_check_requestor(req_id,as))
    {
#if AS_PC_DBG
        printf("100-GK] Req %u  not authenticated, could not confirm \n",req_id);
#endif
        as->as_state = GK_AS_WAIT_FOR_START_REQ;
        return REINIT;
    }
#if AS_PC_DBG
    else
        printf("[AS-GK %lu] Start confirming for  %u \n",as->as_id,req_id);
#endif

    //  Authenticate the requestor
    puf_resp_t link_req     =   as_get_next_link(req_id);
    puf_resp_t rcvd_link    =   U8_TO_PUF_BE(&rcvd_conf[1+sizeof(phemap_id_t)]);
    if(link_req != rcvd_link)
    {
#if AS_PC_DBG
        printf("[AS-GK] Authentication failed during confirmation, needs resync\n");
#endif
        as->as_state = GK_AS_WAIT_FOR_START_REQ;
        return REINIT;
    }
    if(as->pending_conf[req_id] == 0)
    {
        printf("ERRORE ERRORE ERRORE \n");
        return REINIT;
        //assert(1==0);
    }
    //  set the state as no more pending
    as->pending_conf[req_id] = 0;
    as->pending_count--;
    //  If a new key has been installed add the device to the members of the group.
    if(rcvd_conf[0] ==  PK_CONF)
    {
        as->num_part++;
        as->group_members[req_id] = 1;
    }
    //  If there are no more pending devs and the num parts
    //  is greater than 0 
    if(as->pending_count == 0 && as->num_part > 0)
    {
        as->as_state = GK_AS_WAIT_FOR_UPDATES;
        as_reset_timer();
        //  Set the key as installed
        if(as->pk_installed == 0)
        {
            //printf("[AS %u], key installed \n",as->as_id);
            as->pk_installed = 1;
            return INSTALL_OK;
        }
        else
            return UPDATE_OK;
    }
    //  No more devices, reset the state 
    else if(as->pending_count == 0 && as->num_part == 0)
    {
        //printf("[AS %u], update completed \n",as->as_id);
        as->as_state = GK_AS_WAIT_FOR_START_REQ;
        return UPDATE_OK;
    }
    return OK;
}

// Used to check if all the users are still pending
uint8_t gk_as_is_still_pending(const AuthServer* const as)
{
    assert(NULL != as);
    return as->pending_count == 0;
}

phemap_ret_t  gk_as_remove_cb(AuthServer* const as,uint8_t * rcvd_pkt,const uint8_t pkt_len)
{
    //  Check pkt type and size
    if(rcvd_pkt[0] != END_SESS || pkt_len < 1 + sizeof(puf_resp_t) + sizeof(phemap_id_t))
    {
#if AS_PC_DBG
        printf("[AS-GK] Confirmation failed, need reinitialization \n ");
#endif
        as->as_state = GK_AS_WAIT_FOR_START_REQ;
        return REINIT;
    }

    //Check it the requestor is in the list of auth devs
    phemap_id_t req_id = U8_TO_PHEMAP_ID_BE(&rcvd_pkt[1]);
    if(!as_check_requestor(req_id,as)){
#if AS_PC_DBG
        printf("[AS-GK] Req %u  not authenticated, could not remove \n",req_id);
#endif
        as->as_state = GK_AS_WAIT_FOR_START_REQ;
        return REINIT;
    }
#if AS_PC_DBG
    else
        printf("[AS-GK] Start removing for  %u \n",req_id);
#endif

    // Authenticate the requestor
    puf_resp_t link_req     = as_get_next_link(req_id);
    puf_resp_t rcvd_link    = U8_TO_PUF_BE(&rcvd_pkt[1+sizeof(phemap_id_t)]);
    if(link_req != rcvd_link)
    {
#if AS_PC_DBG
        printf("[AS-GK] Authentication failed during elimination, needs resync\n");
#endif
        as->as_state = GK_AS_WAIT_FOR_START_REQ;
        return REINIT;
    }

    // Send remove updates
    uint8_t m_to_send[1 + sizeof(phemap_id_t)+ 3*sizeof(puf_resp_t)];
    puf_resp_t temp_noise,mex_helper;
    uint16_t idx = 0;
    //  Generate the pkt type and add the puf
    m_to_send[0] = UPDATE_KEY;
    PHEMAP_ID_TO_U8_BE(as->as_id,&m_to_send[1]);
    //  Initialize the list of pending devices for the communication
    as->pending_count = 0;
    //  Save the old nonce for updates
    private_key_t old_nonce = as->session_nonce;
    //  Generate nonce and tokens
    as->session_nonce       =   as_rng_gen();
    as->secret_token        =   as_rng_gen();
    //  The update is composed by the leaving node puf used in the key
    puf_resp_t update_key   =   (as->sr_key[req_id]^old_nonce^as->session_nonce); 
    //  update the private key saved into the AS 
    as->private_key         =   (as->private_key ^ update_key);  
    //  Remove the requestor from the group
    as->group_members[req_id]   =   0;
    //  Decrease the number of group part
    as->num_part--;
    //  For each auth devs
    for(idx=0;idx<as->num_auth_devs;idx++)
    {
        //  If idx is not the leaving dev and is a member of the group
        if(as->auth_devs[idx] != req_id && as->group_members[as->auth_devs[idx]] == 1)
        {
            //  Get the next link for the device, this link
            //  will be used for encrypting the update mex 
            temp_noise =    as_get_next_link(as->auth_devs[idx]);            
            //  Append first the Enc ST USING THE SAME NOISE OF THE KEY
            mex_helper =    mex_helper ^ as->secret_token;
            PUF_TO_U8_BE(mex_helper,&m_to_send[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)]);    
            //  Encrypt the update using the next puf link
            mex_helper  =   temp_noise ^ update_key;                     
            //  append the key update
            PUF_TO_U8_BE(mex_helper,&m_to_send[1 + sizeof(phemap_id_t)]);  
            //  Calculate the pkt sign
            mex_helper = keyed_sign(   m_to_send, 
                                1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),
                                as_get_next_link(as->auth_devs[idx])
                            );
            //  Append the sign
            PUF_TO_U8_BE(mex_helper,&m_to_send[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)]);
            // Protocol  send updates
            //  This should be idx to write to the correct recvr slot
            memcpy(&as->unicast_tsmt_buff[as->auth_devs[idx]],m_to_send,15);   
            //  This should be unicast_tsmt_count because acts as a queue
            as->unicast_tsmt_queue[as->unicast_tsmt_count]=as->auth_devs[idx]; 
            as->unicast_tsmt_count++;
        }
    }
    //  If there are no more nodes reset the state 
    if(as->num_part == 0 && as->pending_count == 0)
    {
#if AS_PC_DBG
        printf("[AS-GK] No one left \n");
#endif
        as->as_state=GK_AS_WAIT_FOR_START_REQ;
    }
#if AS_PC_DBG
    printf("[AS-GK] Ending revoke procedure \n");
#endif
    //  Else do nothing since we're already in WAIT_FOR_UPDATES
    return OK;
}

phemap_ret_t  gk_as_add_cb(AuthServer* const as,const uint8_t * const rcvd_pkt,const uint8_t pkt_len)
{
    //  Check pkt type and size 
    if(rcvd_pkt[0] != START_SESS  || pkt_len < 1 + sizeof(puf_resp_t) + sizeof(phemap_id_t))
    {
#if AS_PC_DBG
        printf("[AS-GK] Confirmation failed, need reinitialization \n ");
#endif
        as->as_state = GK_AS_WAIT_FOR_START_REQ;
        return REINIT;
    }

    //  Check if the req is in the list of auth devs
    phemap_id_t req_id = U8_TO_PHEMAP_ID_BE(&rcvd_pkt[1]);
    if(!as_check_requestor(req_id,as)){
#if AS_PC_DBG
        printf("[AS-GK] Req %u  not authenticated, could not add \n",req_id);
#endif
        as->as_state = GK_AS_WAIT_FOR_START_REQ;  
        return REINIT;
    }

#if AS_PC_DBG
    else
        printf("[AS-GK] Start adding for  %u \n",req_id);
#endif
    //  Authenticate the req
    puf_resp_t link_req     =   as_get_next_link(req_id);
    puf_resp_t rcvd_link    =   U8_TO_PUF_BE(&rcvd_pkt[1+sizeof(phemap_id_t)]);
    if(link_req !=  rcvd_link)
    {
#if AS_PC_DBG
        printf("[AS-GK] Authentication failed during Adding, needs resync\n");
#endif
        as->as_state    =   GK_AS_WAIT_FOR_START_REQ;
        return REINIT;
    }

    uint8_t m_to_send[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)+sizeof(private_key_t)];
    //  Save the noise added to the dev key.
    private_key_t sr_noise  =   as_get_next_link(req_id);    
    //  Save its key part.
    as->sr_key[req_id]      =   as_get_next_link(req_id);  
    //  Save the key used for HMAC
    private_key_t hmac_key  =   as_get_next_link(req_id);
    //  Save the old session nonce              
    private_key_t old_session_nonce = as->session_nonce ;
    //  Generate the new nonce 
    as->session_nonce       =   as_rng_gen();                     
    //  The key update always consists in the difference of session secrets plus the added secret key.
    private_key_t key_update = as->session_nonce ^ old_session_nonce^ as->sr_key[req_id];
    //  Save the old key locally.
    private_key_t old_key    = as->private_key;
    //  Update the PK locally
    as->private_key ^= key_update;
    puf_resp_t mex_helper;
    // Generate the new secret token   
    private_key_t old_secret_token=as->secret_token;  
    as->secret_token=as_rng_gen();
    //  Send add updates
    //  Initialize the mex common parts
    uint16_t idx    =   0;
    m_to_send[0]    =   UPDATE_KEY;
    PHEMAP_ID_TO_U8_BE(as->as_id,&m_to_send[1]);
    //  encryption of the new key with the old key
    mex_helper =   old_key ^ as->private_key;
    //  Append the enc pk 
    PUF_TO_U8_BE(mex_helper,&m_to_send[1+sizeof(phemap_id_t)]); 
    //  Encrypt the new session nonce
    mex_helper =   old_key ^ as->secret_token;
    //  Append the enc s.t.
    PUF_TO_U8_BE(mex_helper,&m_to_send[1+sizeof(phemap_id_t)+sizeof(private_key_t)]); 
    //  Generate the keyed sign
    mex_helper =   keyed_sign(m_to_send,1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),old_secret_token);
    //  Append the keyed sign.
    PUF_TO_U8_BE(mex_helper,&m_to_send[1+sizeof(phemap_id_t)+2*sizeof(private_key_t)]);
    //  BROADCAST *****
    memcpy(as->broadcast_tsmt_buff,m_to_send,15);
    as->broadcast_is_present=1;
    //  Ultimate the update by adding the node
    mex_helper = (as->private_key ^as->sr_key[req_id] ^ sr_noise); 
    //  Construct the pkt for the requestor
    m_to_send[0] = START_PK;
    PHEMAP_ID_TO_U8_BE(as->as_id,&m_to_send[1]);
    //  Append the key
    PUF_TO_U8_BE(mex_helper,&m_to_send[1+sizeof(phemap_id_t)]); 
    //  Append the st with the SAME NOISE USED FOR THE KEY 
    mex_helper = as->secret_token ^ sr_noise;
    // Append the requestor id with ai+2
    PUF_TO_U8_BE(mex_helper,&m_to_send[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)]); 
    // Append to the hash 
    mex_helper = keyed_sign(m_to_send,1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),hmac_key); 
    PUF_TO_U8_BE(mex_helper,&m_to_send[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)]);
    // Protocol send
    //as->as_write_to_device(as->as_id,req_id,m_to_send,1+sizeof(phemap_id_t)+sizeof(private_key_t)+2*sizeof(puf_resp_t));
    //  Instead of calling a snd function, write the data into a buffer and write
    //  Copy the buffer into the slot for the specific receiver
    //  Should always be 15 bytes
    memcpy(&as->unicast_tsmt_buff[req_id],m_to_send,15); 
    //  Assign the first receiver id that must receive the pkt
    as->unicast_tsmt_queue[req_id]=1;
    //  Increase the count of messages into the tsmt queue.
    as->unicast_tsmt_count++;
    //  Should increase the pending count in add cb..
    as->pending_conf[req_id] = 1;
    as->pending_count++;
    as->as_state = GK_AS_WAIT_FOR_START_CONF; // Start confirmation for the adding member
    return OK;
}

phemap_ret_t gk_as_automa(AuthServer*const pAS,uint8_t *pPkt, const uint8_t pktLen)
{
    //  Check the ptrs
    assert(NULL != pAS);
    assert(NULL != pPkt);
    //  Initialize the return value 
    phemap_ret_t toRet = OK;
    //if(pAS->as_id == 0 )
    //printf("[%u] AS rcvd type %u , sender %lu \n ",pAS->as_id, pPkt[0],U8_TO_PHEMAP_ID_BE(&pPkt[1]));
    //  If the pkt size is correct
    if(pktLen > 0)
    {
        //  Switch based on the state
        switch(pAS->as_state){
            //  In case the AS is waiting for intra key conf
            case GK_AS_WAIT_FOR_START_CONF:
                //  Call the font callback
                if(pPkt[0] == PK_CONF)
                {    
                    toRet = gk_as_conf_cb(pAS,pPkt,pktLen);
                }
                //  Any other mex means an incorrect state, supposing there is no buffering system in the simulation
                else
                {
#if AS_PC_DBG
                printf("[GK-AS ] NEEDS REINIT, unexpected message in Conf Resp %u \n ",pPkt[0]);
#endif
                    // In this case we can check the state of the as and maybe reinit only the original caller
                    toRet           = REINIT; 
                    pAS->as_state   = GK_AS_WAIT_FOR_START_REQ;
                }
            break;
            //  In case the AS is waiting for update mexs ( the intra key is installed )
            case GK_AS_WAIT_FOR_UPDATES:
                //  A device wants to leave the session
                if(pPkt[0] == END_SESS)
                    toRet = gk_as_remove_cb(pAS,pPkt,pktLen);
                //  An authenticated device wants to join the group
                else if(pPkt[0] == START_SESS)  
                    toRet = gk_as_add_cb(pAS,pPkt,pktLen);
                else
                { 
                    //  An unexpected mex has been received
                    toRet           = REINIT;
                    pAS->as_state   = GK_AS_WAIT_FOR_START_REQ;
                }
            break;
            default:
                //  The state is not coherent with a state where 
                //  the AS can rcv pkts 
                toRet = REINIT; 
                printf("[GK-AS] AS CORRUPTED STATE %u \n ",pAS->as_state);
                pAS->as_state = GK_AS_WAIT_FOR_START_REQ;
            break;
        }
    }
    //  If there was a problem change the state 
    if(toRet == REINIT)
        pAS->as_state = GK_AS_WAIT_FOR_START_REQ;
#if AS_PC_DBG
    printf("[AS-GK] Returning ... %u \n", toRet);
#endif
    return toRet;
}

// get the next chain link
puf_resp_t as_get_next_link (const phemap_id_t req_id)
{
    (void)req_id;
    return 0xef0000ac;
}

void  __attribute__((weak)) as_start_timer()
{   
    //
}

uint8_t  __attribute__((weak)) as_is_timer_expired()
{   
    //
    return 1;
}

void  __attribute__((weak)) as_reset_timer()
{   
    //
}

void  __attribute__((weak)) as_rng_init()
{

}
uint32_t __attribute__((weak)) as_rng_gen()
{
    return 0x00cafe00;
}

static private_key_t keyed_sign(const uint8_t *const buff, const uint32_t buff_size, const private_key_t sign_key )
{

    uint32_t new_buff_size = ceil(buff_size/sizeof(private_key_t));
    uint32_t idx;
    private_key_t helper,sign = 0;
    
    for(idx = 0;idx < new_buff_size - 1; idx++)
    {
        helper  =   U8_TO_PUF_BE(&buff[idx*sizeof(private_key_t)]);
        sign    ^=  (helper^sign_key);
    }
    // append the last one
    helper  =   (U8_TO_PUF_BE(&buff[(new_buff_size-1)*sizeof(private_key_t)])<<8*(new_buff_size-buff_size));
    sign    ^=  (helper^sign_key);
    return sign;
}
