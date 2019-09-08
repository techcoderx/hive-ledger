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

extern unsigned int ux_step;
extern unsigned int ux_step_count;

// Generate Steem public key from seed and compare
static const SteemPubKeyApproved() {
    // cx_ecfp_256_private_key_t privatekey;
    // os_perso_derive_node_bip32(CX_CURVE_256K1,);
    G_io_apdu_buffer[0] = 0x90;
    G_io_apdu_buffer[1] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX,2);
    PRINTF("Request approved successfully\n");
    ui_idle();
    return 0;
}

// Approval UI for public key generation
static const bagl_element_t ui_getPublicKey_approve[] = {
    UI_BACKGROUND(),
    UI_ICON_LEFT(0x00,BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00,BAGL_GLYPH_ICON_CHECK),
    UI_TEXT_BOLD(0x01,0,12,128,"Generate Steem"),
    UI_TEXT_BOLD(0x01,0,26,128,"Public Key"),
    UI_TEXT(0x02,0,12,128,"User"),
    UI_TEXT_BOLD(0x02,0,26,128,"techcoderx"),
};

// Approval UI preprocessor
unsigned int ui_address_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            }
        }
        return display;
    }
    return 1;
}

// Approval button click
unsigned int ui_getPublicKey_approve_button(unsigned int button_mask,unsigned int button_mask_counter) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            G_io_apdu_buffer[0] = 0x69;
            G_io_apdu_buffer[1] = 0x85;
            ui_idle(); // Cancel
            break;
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            SteemPubKeyApproved(); // TODO: Generate Steem public key and compare
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
    ux_step = 0;
    ux_step_count = 2;
    UX_DISPLAY(ui_getPublicKey_approve,ui_address_prepro);
    *flags |= IO_ASYNCH_REPLY;
}