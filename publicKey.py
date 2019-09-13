from ledgerblue.comm import getDongle

keyIndex = raw_input("Specify Key Index: ")
apdu = bytes("8001000000".decode('hex') + chr(eval(keyIndex)))
dongle = getDongle(True)
result = dongle.exchange(apdu)
print("")
print("Steem public key: " + result[-53:])