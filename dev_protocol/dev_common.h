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

#ifndef DEV_COMMON
#define DEV_COMMON
#include "../phemap_common.h"
void dev_start_timer(const phemap_id_t id);
uint8_t dev_is_timer_expired(const phemap_id_t id);
void  dev_reset_timer(const phemap_id_t id);
void  read_data_from_as(const phemap_id_t id , uint8_t *const buff , uint32_t*const  size);
void  dev_rng_init();
uint32_t dev_rng_gen();
#endif
