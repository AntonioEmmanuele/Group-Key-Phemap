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
 * @file    gk_phemap_as.c
 * @author  Antonio Emmanuele antony.35.ae@gmail.com
 * @brief   Implementation of the gk phemap protocol for the LV 
 * @date    2023-08-16
 */

#include "dgk_lv.h"
#include "stdio.h"
#include "stdlib.h"
#include "assert.h"
#include "math.h"
#include "stdlib.h"
#include "string.h"

/*Static function for installing the private key among all the local verifiers */

/**
 * @brief       After (AS->LV) key is installed and (LV->AS) key is installed this function is called to \n
 *              generate the part of group key and send it to the other local verifiers. 
 * @param lv    Local Verifier that is generating the key.
 */
static void LvInstallInterGK(local_verifier_t*const lv);

/**
 * @brief           Callback function used from the LV when it receives an Inter Group key part. 
 * 
 * @param lv            Struct managing the LV. 
 * @param RcvdBuff      Pointer to the rcvd pkt. 
 * @param size          Size of the rcvd pkt.
 * @return phemap_ret_t Op status. 
 */
static phemap_ret_t LvGKPartCB(local_verifier_t* const lv, uint8_t * const RcvdBuff, const uint32_t size);

/**
 * @brief Obtain the next link of the reqId device.
 * 
 * @param reqId         Phemap id of the device from which the carnet must be obtained.
 * @return puf_resp_t   Next link of the carnet. 
 */
static puf_resp_t LvGetNextCarnetLink (const phemap_id_t reqId);

/**
 * @brief Send the new Inter Group key to the devices.
 * 
 * @param lv Local Verifier sending the key.
 */
static void LvSendGroupToDevs(local_verifier_t*const lv);

/**
 * @brief Callback function called when the device receives a packet.
 * 
 * @param lv            Struct managing the LV that received the pkt.
 * @param RcvdBuff      Pointer to the rcvd Buff. 
 * @return phemap_ret_t Op Status. 
 */
static phemap_ret_t LvConfInterGKCB(local_verifier_t *const lv,uint8_t *const RcvdBuff);

/**
 * @brief Function used to sign mexs.
 * 
 * @param buff              Buff containing the pkt to sign.
 * @param buffSize          Size of the pkt to sign.
 * @param signKey           Key that must be used to sign the pkt.
 * @return private_key_t    Sign generated. 
 */
static private_key_t LvKeyedSign(const uint8_t *const buff, const uint32_t buffSize, const private_key_t signKey );

phemap_ret_t lv_as_sender_automa(local_verifier_t* const lv, uint8_t* const RcvdBuff, const uint32_t rcvd_size)
{
    //  Check the inputs
    assert(NULL != lv);  
    assert(NULL != RcvdBuff);
    assert(rcvd_size > 0);
    phemap_ret_t to_ret = REINIT;           
    // Call the authentication server Auth
    to_ret = gk_dev_automa(&lv->lv_dev_role,RcvdBuff,rcvd_size);
    //  in case the installation of the key between LV and Auth server owas successfull 
    //  and the key between devices under the LV has been installed
    //  Then proceed generating the subgroup part of the real global key 
    if(to_ret == INSTALL_OK && lv->lv_as_role.pk_installed == 1)
    {
#if LV_PC_DBG
        printf("LV %u installing InterKey \n", lv->lv_as_role.as_id);
#endif
        LvInstallInterGK(lv);
    }
    return to_ret;
}

phemap_ret_t lv_otherLv_sender_automa(local_verifier_t* const lv, uint8_t* const RcvdBuff, const uint32_t rcvd_size)
{
    assert(NULL != lv);
    assert(NULL != RcvdBuff);
    assert(rcvd_size > 0);
    phemap_ret_t to_ret = REINIT;
    //  If it is a group key pkt 
    if(RcvdBuff[0] == INTER_KEY_INSTALL)    
    {
#if LV_PC_DBG
        if(lv->is_inter_installed == 1 )
            printf("[UPDATE LV %u ]  InterKey Part from : %u \n", lv->lv_as_role.as_id,U8_TO_PHEMAP_ID_BE(&RcvdBuff[1]));
        else
            printf("LV %u  InterKey Part from : %u \n", lv->lv_as_role.as_id,U8_TO_PHEMAP_ID_BE(&RcvdBuff[1]));
#endif
            //  Proceed installing the key 
        to_ret = LvGKPartCB(lv,RcvdBuff,rcvd_size);
    }
    else
    {
        printf(" INcorrect \n");
        assert(1 == 0);
    }
    return to_ret;
}

phemap_ret_t lv_device_sender_automa(local_verifier_t*const lv, uint8_t* const RcvdBuff, const uint32_t rcvd_size)
{
    assert(NULL != lv);
    assert(NULL != RcvdBuff);
    assert(rcvd_size > 0);
    phemap_ret_t to_ret = REINIT;   //  Initialize the return value
    //  Save the old key for calculating updates 
    private_key_t old_key = lv->lv_as_role.private_key;
    to_ret  =   gk_as_automa(&lv->lv_as_role,RcvdBuff,rcvd_size);
#if LV_PC_DBG
    if(to_ret==INSTALL_OK)
        printf("LV %u Dev-Key installed \n",lv->lv_as_role.as_id);
#endif
    //  If the installation was successfull and the key with the AS ( other LV ) has been installed
    //  then proced generating the LV part of the group key 
    if( to_ret == INSTALL_OK && lv->lv_dev_role.is_pk_installed == 1)
    {
#if LV_PC_DBG
        printf("LV %u installing InterKey \n", lv->lv_as_role.as_id);
#endif
        LvInstallInterGK(lv);
    }
    /*
    // If the message was an update request, update the key.
    if( RcvdBuff[0] == END_SESS )
    {
        // If the intra key was updated
#if LV_PC_DBG
        printf("LV %u update completed \n", lv->lv_as_role.as_id);
#endif          
        //  Calculate the update as new_intra_pk - old_intra_pk
        private_key_t update = lv->lv_as_role.private_key ^ old_key;
        //  Remove the old inter session nonce 
        update = update ^ lv->inter_sess_nonce;
        //  Generate the new sess nonce 
        lv->inter_sess_nonce = as_rng_gen();
        //  Add the nonce to the update mex 
        update = update ^ lv->inter_sess_nonce;
        //  Generate the new secret token 
        //  It's just a new value to be xored with the already existing st 
        private_key_t update_st = as_rng_gen();
        lv->group_secret_token  = lv->group_secret_token ^ update_st;
        //  Generate update mex and append them
        uint8_t mex[1+sizeof(phemap_id_t)+3*sizeof(puf_resp_t)];
        
        //  Now generate the pkt for Lvs+
        //  Encrypt the update and st with the intra key of LVS
        private_key_t update_enc    = (update ^ lv->lv_dev_role.pk);
        private_key_t st_enc        = (update_st ^ lv->lv_dev_role.pk);     
        mex[0] = INTER_KEY_INSTALL;
        PHEMAP_ID_TO_U8_BE(lv->lv_as_role.as_id,&mex[1]);
        PUF_TO_U8_BE(update_enc,&mex[1+sizeof(phemap_id_t)]);
        PUF_TO_U8_BE(st_enc,&mex[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)]);
        private_key_t sign = LvKeyedSign(   mex,
                                            1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),
                                            lv->lv_dev_role.secret_token
                                        );
        PUF_TO_U8_BE(sign,&mex[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)]);*/
        /*lv->lv_write_to_others(lv->lv_as_role.as_id,
                                mex,
                                1 + sizeof(phemap_id_t) + 3*sizeof(puf_resp_t));*/
        /*
        //  Now generate the pkt for devices 
        memset(mex,0,1+sizeof(phemap_id_t)+3*sizeof(puf_resp_t));
        //  Encrypt with the dev intra key 
        update_enc  = (update ^ lv->lv_as_role.private_key);
        st_enc      = (update_st ^ lv->lv_as_role.private_key);     
        mex[0]      = LV_SUP_KEY_INSTALL;
        PHEMAP_ID_TO_U8_BE(lv->lv_as_role.as_id,&mex[1]);
        PUF_TO_U8_BE(update_enc,&mex[1+sizeof(phemap_id_t)]);
        PUF_TO_U8_BE(st_enc,&mex[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)]);
        sign = LvKeyedSign  (   mex,
                                1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),
                                lv->lv_as_role.secret_token
                            );      
        PUF_TO_U8_BE(sign,&mex[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)]);
        //  Insert the pending_count as the number of group members
        //  Setup the pending count 
        lv->lv_as_role.pending_count=lv->lv_as_role.num_part;  */
        /*
        //  Broadcast the pkt 
        lv->lv_broad_to_devs(   lv->lv_as_role.as_id,
                                mex,
                                1 + sizeof(phemap_id_t) + 3*sizeof(puf_resp_t)
                            );            
        
    }*/
    return to_ret;
}

void lv_forge_new_inter( 
                local_verifier_t* const lv,
                private_key_t old_Kl
                )
{
    assert(NULL != lv);
    // Evaluate the difference between the old Kl and the new Kl
    // Update the session nonce.
    private_key_t oldNonce = lv->inter_sess_nonce;
    lv->inter_sess_nonce  = as_rng_gen();
    // Update the secret token.
    private_key_t oldSecretToken = lv->group_secret_token;
    lv->group_secret_token ^= as_rng_gen();
    // Generate the update message 
    private_key_t updateMex = old_Kl ^ lv->lv_as_role.private_key ^oldNonce^lv->inter_sess_nonce;
    private_key_t updateStKey = oldSecretToken ^ lv->group_secret_token;
    // Update the key..
    lv->inter_group_key ^= updateMex;
    // Now generate the message for devices..
    uint8_t mex[15];
    mex[0] = LV_SUP_KEY_INSTALL;
    PHEMAP_ID_TO_U8_BE(lv->lv_dev_role.id,&mex[1]);
    private_key_t encKey = lv->lv_as_role.private_key ^ lv->inter_group_key;
    private_key_t encSt = lv->lv_as_role.private_key ^ lv->group_secret_token;
    PUF_TO_U8_BE(encKey,&mex[3]);
    PUF_TO_U8_BE(encSt,&mex[3+sizeof(private_key_t)]);
    //printf(" Token utilizzato %#x ",lv->lv_as_role.secret_token);
    private_key_t sign = LvKeyedSign(mex,3+2*sizeof(puf_resp_t),lv->lv_as_role.secret_token);
    //printf(" Firma calcolata %#x ",sign );
    PUF_TO_U8_BE(sign,&mex[3+2*sizeof(private_key_t)]);
    memcpy(lv->devices_broad_buffer,mex,15);
    lv->device_buff_occupied = 1;
    // Copy the pkt
    mex[0] = INTER_KEY_INSTALL;
    // Now generate the packet for local verifiers.
    encKey = lv->lv_dev_role.pk ^ lv->inter_group_key;
    encSt = lv->lv_dev_role.pk ^ lv->group_secret_token;
    PUF_TO_U8_BE(encKey,&mex[3]);
    PUF_TO_U8_BE(encSt,&mex[3+sizeof(private_key_t)]);
    sign = LvKeyedSign(mex,3+2*sizeof(puf_resp_t),lv->lv_dev_role.secret_token);
    PUF_TO_U8_BE(sign,&mex[3+2*sizeof(private_key_t)]);
    // Copy the pkt
    memcpy(lv->lvs_broad_buffer,mex,15);
    lv->lvs_buff_occupied = 1;
    
}

phemap_ret_t lv_automa(local_verifier_t*const lv, uint8_t* const RcvdBuff, const uint32_t rcvd_size)
{
    assert(NULL != lv);             //  Check the pointer
    phemap_ret_t to_ret = REINIT;   //  Initialize the return value
    //  If the sender is the Authentication Server  
    if(IsAS(lv,U8_TO_PHEMAP_ID_BE(&RcvdBuff[1]))) 
    {
        to_ret = lv_as_sender_automa(lv,RcvdBuff,rcvd_size);
    }
    //  If a device managed by the local verifier is the sender 
    else if (IsDevice(lv,U8_TO_PHEMAP_ID_BE(&RcvdBuff[1])))
    {
        to_ret = lv_device_sender_automa(lv,RcvdBuff,rcvd_size);
    }
    //  If it is a message from another local verifier 
    else if (IsLV(lv,U8_TO_PHEMAP_ID_BE(&RcvdBuff[1])))
    {
        to_ret = lv_otherLv_sender_automa(lv,RcvdBuff,rcvd_size);
    }
    else
    {
        assert(1 == 0);
    }
    return to_ret;
}

uint8_t IsDevice(const local_verifier_t*const lv,const phemap_id_t rcvdId)
{
    uint8_t to_ret = 0;
    for(uint32_t i = 0; i< lv->lv_as_role.num_auth_devs; i++)
    {
        if(lv->lv_as_role.auth_devs[i] == rcvdId)
        {
            to_ret = 1;
            break;
        }
    }
    return to_ret;
}


uint8_t IsLV(const local_verifier_t*const lv,const phemap_id_t rcvdId)
{
    uint8_t to_ret=0;
    for(uint32_t i=0;i<lv->num_lv;i++)
    {
        if(lv->list_of_lv[i]==rcvdId)
        {
            to_ret=1;
            break;
        }
    }
    return to_ret;
}

uint8_t IsAS(const local_verifier_t*const lv,const phemap_id_t rcvdId)
{
    uint8_t to_ret = 0;
    if(lv->lv_dev_role.as_id == rcvdId)
        to_ret=1;
    return to_ret;
}

static void LvInstallInterGK(local_verifier_t*const lv)
{
 
    private_key_t secret_token  =   as_rng_gen();               //  Generate the new secret token 
    private_key_t sess_nonce    =   as_rng_gen();               //  Generate session nonce  
    private_key_t key_part      =   (secret_token               //  Add the secret token for back and for sec
                                    ^lv->lv_as_role.private_key);    
    lv->inter_sess_nonce        =   sess_nonce;                 //  Save the session nonce for this fn
    lv->inter_group_key         ^=  key_part;                   //  Add the newly generated key to the key 
    lv->group_secret_token      ^=  secret_token;               //  Add the newly generated secret token to the secret tokens list 
    key_part                    ^=  lv->lv_dev_role.pk;         //  Encrypt the new key part with the LV private key
    secret_token                ^=  lv->lv_dev_role.pk;         //  Encrypt the new token with the LV private key 
    
    // Generate the Local verifier install mex
    //  TYPE+ID+KEY_PART+SECRET_TOKEN+SIGN
    uint8_t buff[1+sizeof(phemap_id_t)+3*sizeof(puf_resp_t)]; 
    //  Set the type of the mex as INTER_KEY_INSTALL
    buff[0] = INTER_KEY_INSTALL;                                                    
    //  Set the ID of the sender as the ID of the current local verifier   
    PHEMAP_ID_TO_U8_BE(lv->lv_dev_role.id,&buff[1]);                                
    //  Add the part of the key given from the local verifier 
    PUF_TO_U8_BE(key_part,&buff[1+sizeof(phemap_id_t)]);                           
     //  Add the group secret token 
    PUF_TO_U8_BE(lv->group_secret_token,                                           
                &buff[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)]);   
    //  Generate the sign using the LV group secret token  
    key_part=LvKeyedSign( buff, 1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),       
                            lv->lv_dev_role.secret_token);
    //  Append the sign to the mex
    PUF_TO_U8_BE(key_part,&buff[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)]);       
    //  Write the mex to the other LV
    memcpy(lv->lvs_broad_buffer,buff,15);
    lv->lvs_buff_occupied = 1;
    //  Decrease the number of pending operations, for each LV pending ops must be equal to the LV num
    lv->num_install_pending--;   
    //printf("[LV %u ]  Still pending for InterKey: %u \n",lv->lv_as_role.as_id,lv->num_install_pending);
                                                   
    //  If there are no more devices pending because this lv has already received other START_PK
    //  then just send the key to the group
    if(lv->num_install_pending == 0)                                                    
    {
#if LV_PC_DBG 
        printf("[LV %u ] InterGK: %#x InterST: %#x \n",lv->lv_as_role.as_id,lv->inter_group_key,lv->group_secret_token);
#endif
        lv->is_inter_installed = 1;
        LvSendGroupToDevs(lv);
        lv_reset_timer();
    }
}

static phemap_ret_t LvGKPartCB(local_verifier_t* const lv, uint8_t * const RcvdBuff, const uint32_t size)
{
    //  Type and size checks
    if(RcvdBuff[0] != INTER_KEY_INSTALL && size >= 1+sizeof(phemap_id_t)+3*sizeof(puf_resp_t)) 
    {
        printf("Parse error  !\n");

        return CONN_WAIT;
    }
    // Extract the rcvd sign 
    private_key_t rcvd_sign = U8_TO_PUF_BE(&RcvdBuff[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)]);
    //  Check if the rcvd sign is equal to the calculated size
    
    if (rcvd_sign != LvKeyedSign(RcvdBuff,1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),lv->lv_dev_role.secret_token))
    {
        printf("Error receiving the LV key part  !\n");
#if LV_PC_DBG
        printf("Error receiving the LV key part  !");
#endif
        return AUTH_FAILED;
    }
    
    // Add the inter grup key rcvd part decoding the rcvd value with the pk
    lv->inter_group_key     ^=  (U8_TO_PUF_BE(&RcvdBuff[1+sizeof(phemap_id_t)]))^lv->lv_dev_role.pk;
    // Add the inter grup key rcvd part decoding the rcvd value with the pk
    lv->group_secret_token  ^=  (U8_TO_PUF_BE(&RcvdBuff[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)]))^lv->lv_dev_role.pk;
    if( lv -> is_inter_installed == 0)
    {
        lv->num_install_pending--;          //  Decrease the pending count for installation 
        if(lv->num_install_pending == 0)    //  Reset the timer for the installation
        {
#if LV_PC_DBG
            printf("[LV %u ] InterGK: %#x InterST: %#x \n",lv->lv_as_role.as_id,lv->inter_group_key,lv->group_secret_token);
#endif
            // Mark the key as installed 
            lv->is_inter_installed = 1;
            LvSendGroupToDevs(lv);
            lv_reset_timer();
        }
    }
    else
    {
        //  Otherwise just send the up to devs 
        LvSendGroupToDevs(lv);
        //  Should start a tim here 
    }
    return OK;
}

static void LvSendGroupToDevs(local_verifier_t*const lv)
{
    //  TYPE+ID+NEW_KEY_ENC+NEW_SEC_TOK_END+SIGN
    uint8_t mex[1+sizeof(phemap_id_t)+3*sizeof(puf_resp_t)]; 
    //  Type used for downlink comm
    mex[0] = LV_SUP_KEY_INSTALL;
    //  Insert the id of the LV
    PHEMAP_ID_TO_U8_BE(lv->lv_dev_role.id,&mex[1]);
    
    // Encrypted secret key
    PUF_TO_U8_BE(   (lv->inter_group_key^lv->lv_as_role.private_key),
                    &mex[1+sizeof(phemap_id_t)]
                ); 
    //  Encrypted secret token
    PUF_TO_U8_BE(   (lv->group_secret_token^lv->lv_as_role.private_key),
                    &mex[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)]); 
    //  Sign the pkt
    private_key_t sign = LvKeyedSign(mex,1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),lv->lv_as_role.secret_token);
    //  Append the mex 
    PUF_TO_U8_BE(sign,&mex[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)]);
    //  Send the pkt in broad to devs 
    memcpy(lv->devices_broad_buffer,mex,15);
    // Occupy the buffer 
    lv->device_buff_occupied = 1;
}

static puf_resp_t LvGetNextCarnetLink (const phemap_id_t reqId)
{
    (void)reqId;
    return 0xac00001f;
}

static private_key_t LvKeyedSign(const uint8_t *const buff, const uint32_t buffSize, const private_key_t signKey )
{

    uint32_t newBuffSize = ceil(buffSize/sizeof(private_key_t));
    uint32_t idx;
    private_key_t helper,sign=0;
    for(idx = 0; idx < newBuffSize-1;idx++)
    {
        helper  =   U8_TO_PUF_BE(&buff[idx*sizeof(private_key_t)]);
        sign    ^=  (helper^signKey);
    }
    // append the last one
    helper  =   (U8_TO_PUF_BE(&buff[(newBuffSize-1)*sizeof(private_key_t)])<<8*(newBuffSize-buffSize));
    sign    ^=  (helper^signKey);
    return sign;
}

void lv_reset_timer()
{

}