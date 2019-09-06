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

#include "glyphs.h"
unsigned int const C_icon_back_colors[]
 = {
  0x00000000, 
  0x00ffffff, 
};
	
unsigned char const C_icon_back_bitmap[] = {
0xe0, 0x01, 0xfe, 0xc1, 0xfd, 0x38, 0x7f, 0x06, 0xdf, 0x81, 0xff, 0xc4, 0x7f, 0xf3, 0xff, 0xbc, 
  0x1f, 0xe7, 0xe7, 0xf1, 0x3f, 0xf8, 0x07, 0x78, 0x00, };

#ifdef OS_IO_SEPROXYHAL
#include "os_io_seproxyhal.h"
const bagl_icon_details_t C_icon_back = { GLYPH_icon_back_WIDTH, GLYPH_icon_back_HEIGHT, 1, C_icon_back_colors, C_icon_back_bitmap };
#endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_dashboard_colors[]
 = {
  0x00000000, 
  0x00ffffff, 
};
	
unsigned char const C_icon_dashboard_bitmap[] = {
0xe0, 0x01, 0xfe, 0xc1, 0xff, 0x38, 0x70, 0x06, 0xd8, 0x79, 0x7e, 0x9e, 0x9f, 0xe7, 0xe7, 0xb9, 
  0x01, 0xe6, 0xc0, 0xf1, 0x3f, 0xf8, 0x07, 0x78, 0x00, };

#ifdef OS_IO_SEPROXYHAL
#include "os_io_seproxyhal.h"
const bagl_icon_details_t C_icon_dashboard = { GLYPH_icon_dashboard_WIDTH, GLYPH_icon_dashboard_HEIGHT, 1, C_icon_dashboard_colors, C_icon_dashboard_bitmap };
#endif // OS_IO_SEPROXYHAL
