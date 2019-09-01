/*******************************************************************************
*
*  (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#ifndef GLYPH_icon_back_BPP
#define GLYPH_icon_back_WIDTH 14
#define GLYPH_icon_back_HEIGHT 14
#define GLYPH_icon_back_BPP 1
extern
unsigned int const C_icon_back_colors[]
;
extern	
unsigned char const C_icon_back_bitmap[];
#ifdef OS_IO_SEPROXYHAL
#include "os_io_seproxyhal.h"
extern
const bagl_icon_details_t C_icon_back;
#endif // GLYPH_icon_back_BPP
#endif // OS_IO_SEPROXYHAL
#ifndef GLYPH_icon_dashboard_BPP
#define GLYPH_icon_dashboard_WIDTH 14
#define GLYPH_icon_dashboard_HEIGHT 14
#define GLYPH_icon_dashboard_BPP 1
extern
unsigned int const C_icon_dashboard_colors[]
;
extern	
unsigned char const C_icon_dashboard_bitmap[];
#ifdef OS_IO_SEPROXYHAL
#include "os_io_seproxyhal.h"
extern
const bagl_icon_details_t C_icon_dashboard;
#endif // GLYPH_icon_dashboard_BPP
#endif // OS_IO_SEPROXYHAL
