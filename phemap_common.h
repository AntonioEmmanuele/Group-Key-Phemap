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
 * @file phemap_common.h 
 * @author Antonio Emmanuele antony.35.ae@gmail.com
 * @brief Exports common types,macros and fns for PHEMAP and gkPhemap protocols
 * 
 */
#ifndef PHEMAP_COMMON_H
#define PHEMAP_COMMON_H
#include "inttypes.h"
/**
 * @typedef PUF challenge/response 
 */
typedef uint32_t puf_resp_t ;
/**
 * @typedef PK installed with gkPhemap
 */
typedef uint32_t private_key_t;
/**
 * @typedef Types of phemap mex exchanged, each mex is composed by 
 * @details Each phemap mex is composed of  Mex_Type| PhemapID of the sender | Challenge/responses
 */
typedef enum{
    START_SESS,     /*!< In order to install a key a device sends a start_sess mex START_SESS|DEV_ID|CHALLENGE, this mex is also the mex sent from a newer member
                            when he wants to be added in the group*/
    START_PK,       /*!< Mex sent from the AS after START_SESS containing the PK piece of a device START_PK|AS_ID|CHALLENGE|PK_PART*/
    PK_CONF,        /*!< Mex sent from the Dev to AS to confirm the key installation PK_CONF| DEV_ID| CHALLENGE */
    END_SESS,       /*!< Mex sent from the Dev to AS to exit from the session, the user waits for a confirmation */
    UPDATE_KEY,     /*!< Mex sent from the AS to Dev in order to update the key, UPDATE_KEY|AS_ID|CHALLENGE|UPDATE_PART*/
    UPDATE_CONF,    /*!< Mex sent from the Dev to AS in order to confirm its update of the pk*/
    INSTALL_SEC,    /*!< Special mex used for install secrets*/
    SEC_CONF,       /*!< Confirmation mex for secrets*/
    INTER_KEY_INSTALL,  /*!< Inter Key install mex */  
    LV_SUP_KEY_INSTALL
}phemap_mex_t;
/**
 * @brief Return values of gk and phemap functions
 */
/*!< The SYNC_A contains a wrong challenge i.e. the AS is not correctly authenticated*/ 
typedef enum{
    OK,                 /*!< The operation was successfully terminated*/
    REINIT,
    CHAIN_EXHAUSTED,    /*!< The chain link is exhausted*/
    SYNC_AUTH_FAILED,   /*!< Sync Operation failed because of an authentication fails */
    TIMEOUT_SYNCB,      /*!< Sync B is never received after sending the SYNC_A mex*/ 
    TIMEOUT_SYNC_C,     /*!< Sync B is never received after sending the SYNC_C mex */
    AUTH_FAILED,        /*!< An authentication mex */
    TIMEOUT_AUTH_B,     /*!< A timeout expired waiting for AUTH_B mex*/
    CONN_WAIT,          
    ENROLL_FAILED,
    UPDATE_OK,
    INSTALL_OK,
}phemap_ret_t;

typedef uint16_t phemap_id_t;

#define U8_TO_PUF_BE(buff) ((uint32_t)(*buff)<<24)|((uint32_t)*(buff+1)<<16)|((uint32_t)*(buff+2)<<8)|(uint32_t)*(buff+3)

#define PUF_TO_U8_BE(puf,buff){ \
    *(buff)=puf>>24;            \
    *(buff+1)=puf>>16;          \
    *(buff+2)=puf>>8;           \
    *(buff+3)=puf;              \
}
#define PHEMAP_ID_TO_U8_BE(id,buff){ \
    *(buff)=id>>8;  \
    *(buff+1)=id;   \
}
#define U8_TO_PHEMAP_ID_BE(buff) ((phemap_id_t)(*(buff))<<8)|(phemap_id_t)*(buff+1)
// some mex size..
// ENROLL
#define start_size  1 + sizeof(phemap_id_t) * 2
#define enroll_size  1 + sizeof(phemap_id_t) + sizeof(puf_resp_t)
#define header_size  1 + sizeof(phemap_id_t)
// SYNC 
#define size_syncA 1 + sizeof(phemap_id_t) + sizeof(puf_resp_t) * 3
#define size_syncB 1 + sizeof(phemap_id_t) + sizeof(puf_resp_t) * 2
#define size_syncC 1 + sizeof(phemap_id_t) + sizeof(puf_resp_t) * 2
#define size_auth_DEV 1 + sizeof(phemap_id_t)*2 + sizeof(puf_resp_t)
#define size_auth 1 + sizeof(phemap_id_t) + sizeof(puf_resp_t)

#endif
