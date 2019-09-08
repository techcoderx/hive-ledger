from ledgerblue.comm import getDongle

apdu = bytes("8001000000".decode('hex'))
dongle = getDongle(True)
result = dongle.exchange(apdu)
print(result)