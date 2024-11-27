from analysis.signatures.Signature import Signature


def testMaskSignature():
    mask = 4227858432
    expected_unpack = 402653008
    expected_mask = 335544320
    expected_repack = bytearray([0x00, 0x00, 0x00, 0x14])
    instBytes = bytearray([0x50, 0xFF, 0xFF, 0x17])
    inst = Signature.unpack(instBytes)
    assert inst == expected_unpack
    inst = inst & mask
    assert inst == expected_mask
    instBytes = Signature.pack(inst)
    assert instBytes == expected_repack
