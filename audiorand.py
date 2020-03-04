#!/usr/bin/python3
#
import sys
import sounddevice as sd
import hashlib
import base64

def bin2str_b64(byte_str):
    return base64.b64encode(byte_str)

def str2bin_64(cstr):
    return base64.b64decode(cstr)

class SndRnd:
    def __init__(self):
        self.phone = sd.query_devices(kind='input')
        if len(self.phone) == 0:
            print("No Microphone Device")
            sys.exit()
        self.rawsm = sd.RawInputStream(device=self.phone['name'], dtype='int16')
        self.hash = hashlib.new('sha256')

    def ecc256_random(self, secs):
        frames = secs *int(self.phone['default_samplerate'])
        self.rawsm.start()
        noise = self.rawsm.read(frames)
        self.rawsm.stop()
        self.hash.update(bytes(noise[0]))
        return self.hash.digest()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        secs = int(sys.argv[1])
    else:
        secs = 1
    rndsrc = SndRnd()
    rndnum = rndsrc.ecc256_random(secs)
    b64rnd = bin2str_b64(rndnum)
    fname = ''
    if len(sys.argv) > 2:
        fname = sys.argv[2]
    if len(fname) == 0:
        print(b64rnd.decode("utf-8"))
    else:
        fo = open(fname,'wb')
        fo.write(b64rnd)
        fo.close()
