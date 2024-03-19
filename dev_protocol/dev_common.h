#ifndef DEV_COMMON
#define DEV_COMMON
#include "../../phemap_common.h"
void dev_start_timer(const phemap_id_t id);
uint8_t dev_is_timer_expired(const phemap_id_t id);
void  dev_reset_timer(const phemap_id_t id);
void  read_data_from_as(const phemap_id_t id , uint8_t *const buff , uint32_t*const  size);
void  dev_rng_init();
uint32_t dev_rng_gen();
#endif
