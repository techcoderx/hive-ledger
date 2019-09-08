/*******************************************************************************
*
*  (c) 2016 Ledger
*  (c) 2019 TechCoderX
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

#include <stdbool.h>
#include <stdint.h>
#include "steemKeyUtils.h"
#include "os_io_seproxyhal.h"
#include "os.h"
#include "cx.h"
#include "ux.h"

#define P1_ADDR 0x00
#define P1_PUBKEY 0x01
#define P2_ADDR 0x00
#define P2_PUBKEY 0x01

// Approval UI for public key generation
static const bagl_element_t ui_getPublicKey_approve[] = {
    UI_BACKGROUND(),
    UI_ICON_LEFT(0x01,BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x02,BAGL_GLYPH_ICON_CHECK),
    UI_TEXT_BOLD(0x01,0,12,128,"Get public key"),
    UI_TEXT_BOLD(0x01,0,26,128,"for Steem"),
};

// Approval button click
unsigned int ui_getPublicKey_approve_button(unsigned int button_mask,unsigned int button_mask_counter) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            ui_idle();
            break;
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            ui_idle(); // TODO: Generate Steem public key and compare
            break;
    }
    return 0;
}

// Handle APDU command ID 1
// Approval to generate Steem public key
void handleGetSteemPubKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
    // Sanity checks
    if ((p1 != P1_ADDR) && (p1 != P1_PUBKEY)) THROW(0x6B00);
    if ((p2 != P2_ADDR) && (p2 != P2_PUBKEY)) THROW(0x6B00);

    // Show confirmation
    UX_DISPLAY(ui_getPublicKey_approve,NULL);
}