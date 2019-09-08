from ledgerblue.comm import getDongle

apdu = bytes("8001000000".decode('hex'))
dongle = getDongle(True)
dongle.exchange(apdu)