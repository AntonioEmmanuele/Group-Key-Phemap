/**
 * @file as_common.h
 * @author Antonio Emmanuele antony.35.ae@gmail.comn
 * @brief Common function used from an AS 
 * @date 2023-06-18
 */
#ifndef AS_COMMON_H
#define AS_COMMON_H
#include "../../phemap_common.h"

void as_start_timer();
uint8_t as_is_timer_expired();
void  as_reset_timer();
//void  as_write_to_device(const phemap_id_t id,const uint8_t *const buff, const uint32_t nBytes);
void as_read_from_dev(const phemap_id_t id, uint8_t *const buff, uint32_t *const nBytes);
void  as_rng_init() ;
uint32_t as_rng_gen();
#endif

