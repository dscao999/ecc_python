#!/usr/bin/python3
#
import sounddevice as sd
import hashlib

class SndRnd:
    def __init__(self):
        self.phone = sd.query_devices(kind='input')
        if len(self.phone) == 0:
            print("No Microphone Device")
        self.rawsm = sd.RawInputStream(device=self.phone['name'], dtype='int16')
        self.hash = hashlib.new('sha256')

    def ecc256_keygen(self, secs):
        frames = secs *int(self.phone['default_samplerate'])
        self.rawsm.start()
        noise = self.rawsm.read(frames)
        self.rawsm.stop()
        self.hash.update(bytes(noise[0]))
        return self.hash.digest()
