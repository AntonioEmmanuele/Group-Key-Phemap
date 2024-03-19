/**
 * @file    dgk_lv.h
 * @author  Antonio Emmanuele ( antony.35.ae@gmail.com)
 * @brief   This file contain definitions for the Local Verifier part of the protocol
 * @date    2023-08-16
 */
#ifndef DGK_LV_H
#define DGK_LV_H
#include "../../as_gk/Protocol/gk_phemap_as.h"
#include "../../dev_gk/Protocol/gk_phemap_dev.h"
#define LV_PC_DBG 0

/**
 * @typedef Struct utilized for managing a local verifier
 * 
 */
typedef struct{
    Device          lv_dev_role;                    /*!< The struct the local verifier uses in order to get the PK witht the AS.*/
    AuthServer      lv_as_role;                     /*!< The struct the local verifier uses in order to distribute the subgroup private key. */
    phemap_id_t     list_of_lv[MAX_NUM_AUTH];       /*!< List of local verifiers connected.*/
    uint16_t        num_lv;                         /*!< Number of local verifiers.*/
    private_key_t   inter_group_key;                /*!< Inter-Group secret key.*/
    private_key_t   inter_sess_nonce;               /*!< Session nonce for the backward and forward security used for this node.*/
    private_key_t   group_secret_token;             /*!< Secret token generated from the mex.*/
    uint16_t        num_install_pending;            /*!< Number of LV from which we're waiting a pkt.*/
    private_key_t   key_part;                       /*!< Part of the key generated from this LV.*/
    uint16_t        is_inter_installed;             /*!< Check if the inter pk is installed in all the nodes */
    uint8_t         devices_broad_buffer[15];       /*!< Buffer used for sending the key and its updates to devices. */
    uint8_t         device_buff_occupied;           /*!< Check if there is a broadcast pkt for devices.*/
    uint8_t         lvs_broad_buffer[15];           /*!< Buffer used for sending the key parts to lvs. */
    uint8_t         lvs_buff_occupied;              /*!< Check if there is a broadcast pkt for lvs.*/
}local_verifier_t;

/**
 * @brief Automa called when the AS is the sender.
 * 
 * @param lv            Struct managing the actual local verifier.
 * @param rcvd_buff     Pointer to the pkt received. 
 * @param rcvd_size     Size of the buff. 
 * @return phemap_ret_t Op stauts. 
 */
phemap_ret_t lv_as_sender_automa(local_verifier_t*const lv, uint8_t* const rcvd_buff, const uint32_t rcvd_size);

/**
 * @brief Automa called when another LV is the sender.
 * 
 * @param lv            Struct managing the actual local verifier.
 * @param rcvd_buff     Pointer to the pkt received. 
 * @param rcvd_size     Size of the buff. 
 * @return phemap_ret_t Op stauts. 
 */
phemap_ret_t lv_otherLv_sender_automa(local_verifier_t*const lv, uint8_t* const rcvd_buff, const uint32_t rcvd_size);

/**
 * @brief Automa called when a device is the sender.
 * 
 * @param lv            Struct managing the actual local verifier.
 * @param rcvd_buff     Pointer to the pkt received. 
 * @param rcvd_size     Size of the buff. 
 * @return phemap_ret_t Op stauts. 
 */
phemap_ret_t lv_device_sender_automa(local_verifier_t*const lv, uint8_t* const rcvd_buff, const uint32_t rcvd_size);

void lv_forge_new_inter( 
                local_verifier_t* const lv,
                private_key_t old_Kl
                );
/**
 * @brief Automa function called when receiving a pkt from the local verifier
 * 
 * @param lv            Struct managing the actual local verifier.
 * @param rcvd_buff     Pointer to the pkt received. 
 * @param rcvd_size     Size of the buff. 
 * @return phemap_ret_t Op stauts. 
 */
phemap_ret_t lv_automa(local_verifier_t*const lv, uint8_t* const rcvd_buff, const uint32_t rcvd_size);

/**
 * @brief Check if rcvdId is the phemap Id of the authentication Server that manages the local verifiers.
 * 
 * @param lv        Pointer to the local verifier manager.
 * @param rcvdId    Phemap Id to check. 
 * @return uint8_t  1 if rcvdId is the AS.
 */
uint8_t IsAS(const local_verifier_t*const lv, const phemap_id_t rcvdId);

/**
 * @brief   Check if rcvdId is the phemap Id of a device under the control of the local verifier
 *          managed from lv struct.
 * 
 * @param lv        Pointer to the local verifier manager.
 * @param rcvdId    Phemap Id to check.
 * @return uint8_t  1 if rcvdId is a dev managed from lv.
 */
uint8_t IsDevice(const local_verifier_t*const lv, const phemap_id_t rcvdId);

/**
 * @brief   Check if rcvdId is the phemap Id of another local verifier.
 * 
 * @param lv        Pointer to the local verifier manager.
 * @param rcvdId    Phemap Id to check.
 * @return uint8_t  1 if rcvdId is a local verifier.
 */
uint8_t IsLV(const local_verifier_t*const lv, const phemap_id_t rcvdId);

void lv_start_timer_ms(uint32_t ms_time) __attribute__((weak));

void lv_reset_timer() __attribute__((weak));

#endif