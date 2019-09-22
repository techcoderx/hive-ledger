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

#include "signHandler.h"
#include "steemUtils.h"
#include "os_io_seproxyhal.h"
#include "os.h"
#include "cx.h"
#include "ux.h"

typedef struct signReqContext_t {
    unsigned int addrIndex;
    char serializedBuffer;
} signReqContext_t;

signReqContext_t signreqctx;

typedef struct transactionContext_t {
    unsigned int txType;
    char txName[];
} transactionContext_t;

transactionContext_t txctx;

extern unsigned int ux_step;
extern unsigned int ux_step_count;

// Forward declaration
void processOps(unsigned int txtype,char serializedDetail[]);

// Confirmation UI
static const bagl_element_t sign_request_confirmation_ui[] = {
    UI_BACKGROUND(),
    UI_ICON_LEFT(0x00,BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00,BAGL_GLYPH_ICON_CHECK),
    UI_TEXT(0x01,0,12,128,"Operation"),
    UI_TEXT_BOLD(0x01,0,26,128,&txctx.txName),
    // UI_TEXT(0x02,0,12,128,)
};

/*
void setarr() {
    sign_request_confirmation_ui[4] = (bagl_element_t)UI_TEXT_BOLD(0x01,0,24,128,&txctx.txName);
}*/

unsigned int sign_request_confirmation_ui_button(unsigned int button_mask,unsigned int button_mask_counter) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            io_exchange_with_code(0x9000,0);
            ui_idle();
            break;
    }
    return 0;
}

void parseTx(uint8_t *serialized) {
    unsigned int currentParsingPos = 22; // Starting from 23rd character
    char hexStr[3];
    strncpy(&hexStr,(char*)serialized + currentParsingPos,2);
    txctx.txType = dualCharHexToInt(hexStr);
    os_memcpy(&txctx.txName,&SteemOperations[txctx.txType],sizeof(SteemOperations[txctx.txType]));
    PRINTF("Transaction Type: %u\n",txctx.txType);

    processOps(txctx.txType,(char*)serialized + currentParsingPos + 2);
}

// APDU command ID 2
// Sign Steem transactions
void handleSign(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
    // P1 is the key index of private key to sign
    // P2 is the APDU stream section number (starts from 0, incremented, ff to process command)
    stringRemoveNonAlphaNum((char*)dataBuffer);
    PRINTF("Serialized string: %s\n",dataBuffer);
    os_memmove(&signreqctx.addrIndex,&p1,sizeof(p1));
    parseTx(dataBuffer);

    // io_exchange_with_code(0x9000,0);
    *flags |= IO_ASYNCH_REPLY;
}

// Deserialize operations for confirmation
void processOps(unsigned int txtype,char serializedDetail[]) {
    unsigned long int pos = 0;
    char charnumstr[3];
    unsigned int charnum = 0;
    PRINTF("%s\n",serializedDetail);
    switch (txtype) {
        case 0: // Vote
            strncpy(&charnumstr,serializedDetail,2);
            charnum = dualCharHexToInt(charnumstr);
            PRINTF("Voter chars: %u\n",charnum);

            // Voter
            char voter[17];
            char voterserial[33];
            strncpy(&voterserial,serializedDetail+2,charnum * 2);
            hexStrToAsciiStr(voter,voterserial);
            PRINTF("Voter: %s\n",voter);

            pos = pos + (charnum * 2) + 2;

            // Author
            char author[17];
            char authorserial[33];
            strncpy(&charnumstr,serializedDetail+pos,2);
            charnum = dualCharHexToInt(charnumstr);
            PRINTF("Author chars: %u\n",charnum);
            strncpy(&authorserial,serializedDetail+pos+2,charnum * 2);
            hexStrToAsciiStr(author,authorserial);
            PRINTF("Author: %s\n",author);

            pos = pos + (charnum * 2) + 2;

            // Permlink
            char permlink[256];
            char permlinkSerial[511];
            strncpy(&charnumstr,serializedDetail+pos,2);
            charnum = dualCharHexToInt(charnumstr);
            PRINTF("Permlink chars: %u\n",charnum);
            strncpy(&permlinkSerial,serializedDetail+pos+2,charnum * 2);
            hexStrToAsciiStr(permlink,permlinkSerial);
            PRINTF("Permlink: %s\n",permlink);

            pos = pos + (charnum * 2) + 2;

            // Weight
            char weightSerial[5];
            strncpy(&weightSerial,serializedDetail+pos,4);
            int weight = parsevoteweight(weightSerial);

            // Prepare confirmation screen
            ux_step = 0;
            ux_step_count = 5;
            UX_DISPLAY(sign_request_confirmation_ui,NULL);
            
            break;
        case 1:
            UX_DISPLAY(sign_request_confirmation_ui,NULL);
        default:
            // Invalid operation type
            THROW(0x6B00);
            break;
    }
}