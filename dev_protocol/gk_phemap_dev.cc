/**
 * @file gk_phemap_as.c
 * @author Antonio Emmanuele antony.35.ae@gmail.com
 * @brief Implementation of the gk phemap protocol for the device 
 * @date 2023-06-18
 */
#include "gk_phemap_dev.h"
#include "stdio.h"
#include "assert.h"
#include "math.h"
#include "string.h"

static private_key_t dev_keyed_sign(const uint8_t *const buff, const uint32_t buff_size, const private_key_t sign_key );
phemap_ret_t gk_dev_sup_inst(Device* const dev, const uint8_t* const rcvd_pkt,const uint8_t pkt_len);
/**
 * @brief Function used to create a mex composed MEX_TYPE|SENDER_ID|CHALLENGE 
 * 
 * @param mtype Type of the mex
 * @param id Id of the sender
 * @param mex Pointer to the PREALLOCATED buffer
 */
static inline void forge_simple_mex(const phemap_mex_t mtype,const phemap_id_t id, uint8_t *const mex )
{
    mex[0] = mtype;
    PHEMAP_ID_TO_U8_BE(id,&mex[1]);
    dev_get_next_puf_resp_u8(&mex[1+sizeof(phemap_id_t)]); 
}

// Start group key installation
void gk_dev_start_session(Device* const dev )
{
    uint8_t start_mex[1+sizeof(puf_resp_t)+sizeof(phemap_id_t)];
    forge_simple_mex(START_SESS,dev->id,start_mex);
#if DEV_PC_DBG
    uint32_t snd=U8_TO_PUF_BE(&start_mex[1+sizeof(phemap_id_t)]);
    printf ("[DEVICE] Starting communication with puf  %#x \n" ,snd);
#endif

    // Communication protocol send
    //dev->write_data_to_as(dev->id,start_mex,1+sizeof(puf_resp_t)+sizeof(phemap_id_t));
    memcpy(dev->unicast_tsmt_buff,start_mex,7);
    dev->unicast_is_present=1;
    dev->dev_state = GK_DEV_WAIT_START_PK;
}

// Leave the group
void gk_dev_end_session(Device* const dev)
{
    uint8_t end_mex[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)];
    forge_simple_mex(END_SESS,dev->id,end_mex);
#if DEV_PC_DBG
    uint32_t snd=U8_TO_PUF_BE(&end_mex[1+sizeof(phemap_id_t)]);
    printf ("[DEVICE %u ] Ending communication with puf  %#x \n" ,dev->id,snd);
#endif
    // Communication protocol send
    //dev->write_data_to_as(dev->id,end_mex,1+sizeof(puf_resp_t)+sizeof(phemap_id_t));
    memcpy(dev->unicast_tsmt_buff,end_mex,7);
    dev->unicast_is_present=1;
    dev->dev_state = GK_DEV_WAIT_START_PK;
}


// Cb fun when receiving the response message from the AS
phemap_ret_t gk_dev_startPK_cb(Device* const dev,const uint8_t * const resp_mex,const uint32_t resp_len)
{
    assert( NULL != dev);
    assert( NULL != resp_mex);
    if( resp_mex[0] != START_PK || resp_len <  1 + 3*sizeof(puf_resp_t)+sizeof(phemap_id_t))
    {
#if DEV_PC_DBG
        printf("[GK-DEVICE] MALFORMED GK AS_RESP-> RESINCRONIZAZION NEEDED");
#endif
        dev->dev_state = GK_DEV_WAIT_START_PK;
        return REINIT;
    }
    //  ai  -> noise added to the part of the key
    puf_resp_t noise_key_part       = dev_get_next_puf_resp();    
    //  ai+1-> Part of the key that the node needs to add 
    puf_resp_t key_to_add           = dev_get_next_puf_resp();  
    //  Noise added to the secret token = noise added to the key       
    puf_resp_t noise_secret_token   = noise_key_part; 
    //  ai+2-> Link used for keying
    puf_resp_t link_keyed           = dev_get_next_puf_resp();          
    // Check the sign 
    puf_resp_t rcvd_sign = U8_TO_PUF_BE(&resp_mex[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)]); 
    if(rcvd_sign != dev_keyed_sign(resp_mex,1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),link_keyed)) // Check the signing
    {
#if DEV_PC_DBG
        printf("[GK-DEVICE %u ] AS Authentication failed during response , exp %#x ,calculated %#x \n",dev->id, rcvd_sign,dev_keyed_sign(resp_mex,1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),link_keyed));
#endif
        dev->dev_state = GK_DEV_WAIT_START_PK;
        return REINIT;
    }

    //  Get the pk, remove the noise and install the key part 
    dev->pk = U8_TO_PUF_BE(&resp_mex[1+sizeof(phemap_id_t)])^key_to_add^noise_key_part; 
    //  Get the st and remove its noise
    dev->secret_token = noise_secret_token^(U8_TO_PUF_BE(&resp_mex[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)]));
#if DEV_PC_DBG
        printf("[GK-DEVICE %u] Installed pk %#x secret token %#x \n",dev->id,dev->pk, dev->secret_token);
#endif
    // Generate response
    uint8_t resp[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)];
    forge_simple_mex(PK_CONF,dev->id,resp);
    //dev->write_data_to_as(dev->id,resp,1+sizeof(puf_resp_t)+sizeof(phemap_id_t));
    memcpy(dev->unicast_tsmt_buff,resp,7);
    dev->unicast_is_present=1;
    dev->dev_state          = GK_DEV_WAIT_FOR_UPDATE;
    dev->is_pk_installed    = 1;
    return INSTALL_OK;
}

// Callback for updating private key when receiving a mex
phemap_ret_t gk_dev_update_pk_cb(Device*const dev, const uint8_t * const update_mex,const uint32_t update_len )
{
    if(update_mex[0] != UPDATE_KEY || update_len < 1 + 3*sizeof(puf_resp_t) + sizeof(phemap_id_t))
    {
#if DEV_PC_DBG
        printf("[GK-DEVICE] MALFORMED GK AS_UPDATE-> RESINCRONIZAZION NEEDED");
#endif
        dev->dev_state = GK_DEV_WAIT_START_PK;
        return REINIT;
    }
    phemap_id_t rcvd_id = U8_TO_PHEMAP_ID_BE(&update_mex[1]);
    if(rcvd_id != dev->as_id)
    {
#if DEV_PC_DBG
        printf("[GK-DEVICE %u ] Received id different from as id, rcvd %u \n ",dev->id,rcvd_id);
#endif
        return CONN_WAIT; // Not loose sync
    }
    //  bi for key noise, this is the noise that will be removed from the key
    puf_resp_t key_noise    = dev_get_next_puf_resp(); 
    //  secret_token noise == key noise
    puf_resp_t stok_noise   = key_noise;
    //  bi+1 for MAC 
    puf_resp_t auth     = dev_get_next_puf_resp();        
    private_key_t mac   = dev_keyed_sign(update_mex,1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),auth);
    private_key_t rcvd_mac = U8_TO_PUF_BE(&update_mex[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)]); 
    if(mac != rcvd_mac)
    {
#if DEV_PC_DBG
        printf("[GK-DEVICE] AS Authentication failed during update,  recvd mac %#x exp mac %#x\n",rcvd_mac,mac );
#endif 
        dev->dev_state = GK_DEV_WAIT_START_PK;
        return REINIT;
    }
    private_key_t update = U8_TO_PUF_BE(&update_mex[1+sizeof(phemap_id_t)]);
    //  Get the update and the new st removing the noise 
    dev->pk = dev->pk ^ update ^ key_noise;
    dev->secret_token = (U8_TO_PUF_BE(&update_mex[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)])) ^ stok_noise;
#if DEV_PC_DBG
        printf("[GK-DEVICE %u] Update completed, new pk %#x, new sec key %#x \n",dev->id ,dev->pk,dev->secret_token);
#endif
    dev->dev_state = GK_DEV_WAIT_FOR_UPDATE;
    return OK;
}

phemap_ret_t gk_dev_automa(Device* const dev, uint8_t * const pPkt,const uint32_t pktLen)
{
    assert(NULL != dev);
    assert(NULL != pPkt);
    phemap_ret_t toRet =OK;
    //  In case the pkt size is ok
    if(pktLen > 0)
    {
        toRet = REINIT;
        switch(dev->dev_state)
        {
            //  In this state the dev only waits for start pk
            case GK_DEV_WAIT_START_PK:
                if(pPkt[0] == START_PK)
                    toRet = gk_dev_startPK_cb(dev,pPkt,pktLen);
                else
                {
#if DEV_PC_DBG
                    printf("[GK DEV %u ] Invalid message in start resp  \n ", dev->id);                   
                    for(size_t j = 0; j < pktLen ; j++)
                    {
                        printf(" %#x ",pPkt[j]);
                    }
                    printf("\n");
#endif
                    toRet = REINIT;
                }
            break;
            //  In this state the dev only waits for updates 
            case GK_DEV_WAIT_FOR_UPDATE:
                if( pPkt[0] == UPDATE_KEY)
                    toRet = gk_dev_update_pk_cb(dev,pPkt,pktLen);  
                else if (pPkt[0] == LV_SUP_KEY_INSTALL)
                    toRet = gk_dev_sup_inst(dev,pPkt,pktLen);
                else
                {
#if DEV_PC_DBG
                    printf("[GK DEV %u ] Invalid message in wait for update  %u \n ",dev->id,pPkt[0]);
#endif
                    toRet = REINIT;
                }
            break;
            default:
#if DEV_PC_DBG
                printf("[GK DEV] Invalid state \n ");
#endif  
                toRet = REINIT;
            break;
        }
    }
    if(toRet == REINIT)
        dev->dev_state = GK_DEV_WAIT_START_PK;
    return toRet;
}
// Get the next chain link as an array of u8
void dev_get_next_puf_resp_u8 (uint8_t* const  puf)
{
    puf[0] = 0xac;
    puf[1] = 0x00;
    puf[2] = 0x00;
    puf[3] = 0x1f;
}

// get the next chain link
puf_resp_t dev_get_next_puf_resp ()
{
    uint32_t puf_resp;
    uint8_t p_r[4];
    dev_get_next_puf_resp_u8(p_r);
    puf_resp=U8_TO_PUF_BE(p_r);
    //printf(" RESP %x \n ",puf_resp);
    return puf_resp;
}

void  __attribute__((weak)) dev_start_timer(const phemap_id_t id){
    (void)id;
    printf(" I'm weak :(  \n");
}
uint8_t   __attribute__((weak)) dev_is_timer_expired(const phemap_id_t id){
    (void)id;
    return 1;
}

phemap_ret_t gk_dev_sup_inst(Device* const dev, const uint8_t* const rcvd_pkt,const uint8_t pkt_len)
{
    //printf(" token utilizzato %u \n ", dev->secret_token);
    //  Calculate the sign using 
    puf_resp_t calc_sign = dev_keyed_sign(rcvd_pkt,1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),dev->secret_token);
    //  Check if the calc sign is eq to the rcvd sign
    if((U8_TO_PUF_BE(&rcvd_pkt[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)]))!=calc_sign)
    {
#if DEV_PC_DBG
        printf("DEV %u \n",dev->id);
        printf("RCvd Sign %#x EXP %#x \n",(U8_TO_PUF_BE(&rcvd_pkt[1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t)])),dev_keyed_sign(rcvd_pkt,1+sizeof(phemap_id_t)+2*sizeof(puf_resp_t),dev->secret_token));
#endif
        return REINIT;
    }
    //  Extract and decode the secret token 
    dev->inter_group_tok = U8_TO_PUF_BE(&rcvd_pkt[1+sizeof(phemap_id_t)+sizeof(puf_resp_t)])^dev->pk;
    //  Extract and decode the key 
    dev->inter_group_key = U8_TO_PUF_BE(&rcvd_pkt[1+sizeof(phemap_id_t)])^dev->pk;
#if DEV_PC_DBG
    printf("[GK-DEVICE %u] Inter GK: %u ST %u",dev->id, dev->inter_group_key, dev->inter_group_tok);
#endif
    return OK;
}

private_key_t dev_keyed_sign(const uint8_t *const buff, const uint32_t buff_size, const private_key_t sign_key )
{
    uint32_t new_buff_size = ceil(buff_size/sizeof(private_key_t));
    uint32_t idx;
    private_key_t helper,sign = 0;
    
    for(idx = 0;idx < new_buff_size-1; idx++)
    {
        helper  = U8_TO_PUF_BE(&buff[idx*sizeof(private_key_t)]);
        sign    ^= (helper^sign_key);
    }
    // append the last one
    helper  =   (U8_TO_PUF_BE(&buff[(new_buff_size-1)*sizeof(private_key_t)])<<8*(new_buff_size-buff_size));
    sign    ^=  (helper^sign_key);
    return sign;
}

