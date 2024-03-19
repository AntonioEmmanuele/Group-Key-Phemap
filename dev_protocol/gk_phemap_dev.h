/**
 * @file gk_phemap_dev.h
 * @author Antonio Emmanuele antony.35.ae@gmail.com
 * @brief Exports the functions for the gkPhemap dev protocol
 * @date 2023-06-18
 * 
 * 
 */
#ifndef GK_PHEMAP_DEV_H
#define GK_PHEMAP_DEV_H

#define DEV_PC_DBG 0
#if DEV_PC_DBG
#include "string.h"
#endif
#include "dev_common.h"

/**
 * @typedef State of the gkPheamap Device Authoma representing the next mex for the protocol
 * 
 */
typedef enum{
    GK_DEV_WAIT_START_PK,       /*!< The device is waiting for its pk part*/
    GK_DEV_WAIT_FOR_UPDATE,     /*!< The device has a key installed and is waiting for an update*/
}GK_Dev_State;

/**
 * @typedef Device control struct
 */
typedef struct{
    phemap_id_t id;             /*!< Id of the device*/
    phemap_id_t as_id;          /*!< Id of the Authentication Server */
    private_key_t pk;           /*!< PK installed using the protocol*/
    GK_Dev_State dev_state;     /*!< Current state of the gkPhemap Device protocol*/
    private_key_t secret_token; /*!< Secret key shared from all devices*/
    uint8_t is_pk_installed;    /*!< Checks if the intra group key is installed*/ 
    puf_resp_t inter_group_key; /*!< Inter group Pk*/
    puf_resp_t inter_group_tok; /*!< Intergroup secret token */
    uint8_t    unicast_tsmt_buff[7];
    uint8_t    unicast_is_present;
    /*void (*write_data_to_as)(const phemap_id_t, 
                            const uint8_t* const,
                            const uint32_t);*/
}Device;
/**
 * @brief Function used from a device in order to start a session
 * @param dev Pointer to the device gkPhemap control structure
 * @pre The dev wants to initialize the communication with the group
 * @post The AS sends a private key to the server 
 */
void gk_dev_start_session(Device *const  dev);
/**
 * @brief Function called when the server sends a start PK function
 * @param dev ID of the device
 * @param resp_mex Rcvd pkt
 * @param resp_len Rcvd pkt size
 * @return phemap_ret_t Operation status 
 */
phemap_ret_t gk_dev_startPK_cb( Device *const  dev, const uint8_t * const resp_mex,const uint32_t resp_len);
/**
 * @brief Function called from a group member to leave the group.
 * 
 * @param dev Pointer to the device manager.
 */
void gk_dev_end_session(Device *const  dev);
/**
 * @brief Function called when receiving a group key update from the AS.
 * 
 * @param dev Pointer to the device manager.
 * @param update_mex Message containing the update.
 * @param update_len Rcvd size.
 * @return phemap_ret_t Operation status.
 */
phemap_ret_t gk_dev_update_pk_cb( Device *const  dev,const uint8_t * const update_mex,const uint32_t update_len);
/**
 * @brief Automa function called when receiving a packet.
 * 
 * @param pDev Pointer to device manager.
 * @param pPkt Rcvd message.
 * @param pktLen Rcvd message size.
 * @return phemap_ret_t Operation status.
 */
phemap_ret_t gk_dev_automa(Device* const pDev, uint8_t * const pPkt,const uint32_t pktLen);
/**
 * @brief Callback fn called in DGK when LV shares the key.
 * 
 * @param dev Pointer to device manager.
 * @param rcvd_pkt Rcvd message containing K_g and the identifier of the group ID_G 
 * @param pkt_len Size of the received packet.
 * @return phemap_ret_t Operation status.
 */
phemap_ret_t gk_dev_sup_inst(Device* const dev, const uint8_t* const rcvd_pkt,const uint8_t pkt_len);
/**
 * @brief Obtain the next response of the PUF using the sentinel counter of PHEMAP.
 * 
 * @param puf Pointer to the response. 
 */
void dev_get_next_puf_resp_u8 (uint8_t* const puf);
/**
 * @brief Return the next response of the PUF according to the value in the Q register and on 
 *        the sentinel counter.
 * 
 * @return puf_resp_t Next link of the chain. 
 */
puf_resp_t dev_get_next_puf_resp();
#endif
