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
 * @file as_common.h
 * @author Antonio Emmanuele antony.35.ae@gmail.comn
 * @brief Common function used from an AS 
 * @date 2023-06-18
 */
#ifndef AS_COMMON_H
#define AS_COMMON_H
#include "../phemap_common.h"

void as_start_timer();
uint8_t as_is_timer_expired();
void  as_reset_timer();
//void  as_write_to_device(const phemap_id_t id,const uint8_t *const buff, const uint32_t nBytes);
void as_read_from_dev(const phemap_id_t id, uint8_t *const buff, uint32_t *const nBytes);
void  as_rng_init() ;
uint32_t as_rng_gen();
#endif

