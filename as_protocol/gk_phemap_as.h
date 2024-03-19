/**
 * @file gk_phemap_as.h
 * @author Antonio Emmanuele antony.35.ae@gmail.com
 * @brief Function and typed declarated for managing an AS
 * @date 2023-06-18
 * 
 */
#ifndef GK_PHEMAP_AS_H
#define GK_PHEMAP_AS_H

#include "as_common.h"
#define AS_PC_DBG       0
#define MEX_ENQUEUE     1
#define MAX_NUM_AUTH    3000
/**
 * @typedef State of the GK AS
 * 
 */
typedef enum{
    GK_AS_WAIT_FOR_START_REQ,   /*!<In this state the AS only waits for the Start Sess mex,if a reinit is performed then the as should be resetted to this safe state */
    GK_AS_WAIT_FOR_START_CONF,  /*!<In this state the AS only waits for the Confirmation of the server*/
    GK_AS_WAIT_FOR_UPDATES,     /*!<In this state the as waits for end session and updates */
}Gk_AS_State;

/**
 * @brief Handler function for the authentication server
 */
typedef struct{
    phemap_id_t     as_id;                          /*!< Id of the Authentication Server*/
    phemap_id_t     auth_devs[MAX_NUM_AUTH];        /*!< List of synched devices according to phemap protocol*/
    uint16_t        num_auth_devs;                  /*!< Number of actually authenticated devices*/
    uint16_t        num_part;                       /*!< Number of nodes actually in the group*/  
    uint8_t         pending_conf[MAX_NUM_AUTH];     /*!< Bitmap of pending confirmation, if pending_conf[i]==1 means that node with id i hasn't send its own id.*/
    uint16_t        pending_count;                  /*!< Count of pending devices i.e. if its value is 4 it means 4 nodes hasn't send a confirmation yet*/
    private_key_t   sr_key[MAX_NUM_AUTH];           /*!< Part of keys of each node kept for updates */
    Gk_AS_State     as_state;                       /*!< Current state of the AS */
    private_key_t   session_nonce;                  /*!< In order to provide backward and forward security each pk has a nonce added*/
    uint8_t         pk_installed;                       /*!< Flag used to check if the private key is installed.*/              
    private_key_t   private_key;                    /*!< Actual private key.*/
    puf_resp_t      secret_token;                   /*!< Secret token of the intra group. */
    phemap_id_t     group_members[MAX_NUM_AUTH];    /*!< Bitmap for nodes that are part of the intra group key.*/
    uint8_t         unicast_tsmt_buff[MAX_NUM_AUTH][15];
    phemap_id_t     unicast_tsmt_queue[MAX_NUM_AUTH];
    uint32_t        unicast_tsmt_count;
    uint8_t         broadcast_tsmt_buff[MAX_NUM_AUTH];
    uint8_t         broadcast_is_present;
    /*void (*as_write_to_device)( const phemap_id_t,  
                                const phemap_id_t,
                                const uint8_t* const,
                                const uint32_t);*/
}AuthServer;

/**
 * @brief Callback called when a START_SESS_ mex is received from a device
 * @details In order to install a PK a device sends a START_SESS mex and the AS , waiting for a Start Req, sends 
 *          to each device START_PK| AS_ID| NEXT_LINK| PART OF PK and puts itself in the state GK_AS_WAIT_FOR_START_CONF
 * @param as Pointer to the AS data structure
 * @param rcvd_start Start mex received
 * @param pkt_len Size of the mex received 
 * @pre     The AS is in the GK_AS_WAIT_FOR_START_REQ state
 * @post    The AS is in the state GK_AS_WAIT_FOR START_CONF state, GK_AS_WAIT_FOR_START_CONF state.
 *          Each synched mex is inserted into the pending conf array and the pending count 
 * @return phemap_ret_t Operation status 
 */
phemap_ret_t gk_as_start_session_cb( AuthServer* const as,uint8_t * rcvd_start,const uint8_t pkt_len);

/**
 * @brief   Function used from the AS in order to install a pk 
 * @details In order to install a PK the AS sends to each device 
 *          START_PK| AS_ID| NEXT_LINK| PART OF PK and puts itself in the state GK_AS_WAIT_FOR_START_CONF
 * @param as Pointer to the AS data structure
 * @param rcvd_start Start mex received
 * @param pkt_len Size of the mex received 
 * @pre     The AS is in the GK_AS_WAIT_FOR_START_REQ state
 * @post    The AS is in the state GK_AS_WAIT_FOR START_CONF state, GK_AS_WAIT_FOR_START_CONF state.
 *          Each synched mex is inserted into the pending conf array and the pending count 
 * @return phemap_ret_t Operation status 
 */
phemap_ret_t gk_as_start_session( AuthServer* const as);

/**
 * @brief Callback called when a confirmation arrives 
 * @details When the AS is performing an operation it keeps track of the pending ID waiting for their confirmation
 *          messages in order to consider the operation concluded. 
 *          There are two types of confirmation: PK_CONF which is the confirmation that the pk was installed and the 
 *          UPDATE_CONF which is the confirmation that the PK was installed
 * @param as Pointer to the AS DS  
 * @param rcvd_conf pkt received
 * @param pkt_len   Size of the received packet
 * @return phemap_ret_t    Operation status 
 */
phemap_ret_t gk_as_conf_cb( AuthServer* const as,uint8_t * rcvd_conf,const uint8_t pkt_len);
/**
 * @brief CB called when a confirmation mex is received, it can be both a PK_CONF and UPDATE_CONF
 * @param as Pointer to the AS DS
 * @param rcvd_pkt pkt received
 * @param pkt_len   Size of the received packet
 * @return phemap_ret_t  Operation status 
 */
phemap_ret_t  gk_as_add_cb(AuthServer* const as,const uint8_t * const rcvd_pkt,const uint8_t pkt_len);
phemap_ret_t  gk_as_remove_cb(AuthServer* const as,uint8_t * rcvd_pkt,const uint8_t pkt_len);
/**
 * @brief Get the next link of the chain for the specific phemap id 
 * @param id id for which we want to retrieve the key 
 * @return puf_resp_t Operation status
 */
puf_resp_t as_get_next_link(const phemap_id_t  id);
/**
 * @brief Returns true if there is still at least a device that hasn't send yet a conf mex 
 * @details This function is important because it can be used to check if the group is in the middle
 *          of an update in order to avoid inconsistent state situations.
 * @param as Pointer to the AS struct 
 * @return uint8_t 1 if there is still some node pending
 */
uint8_t gk_as_is_still_pending(const AuthServer*as);
/**
 * @brief Implement the gkPhemap protocol automa
 * @details This function should be invoked when a node impersonating the AS receives a mex 
 *          and needs to update the automa without directly 
 * @param pAS  Pointer to the AS struct 
 * @param pPkt Received packet
 * @param pktLen Received packet size
 * @return phemap_ret_t  Operation status 
 */
phemap_ret_t gk_as_automa(AuthServer*const pAS,uint8_t *pPkt, const uint8_t pktLen);
#endif
