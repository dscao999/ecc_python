#!/usr/bin/python3
#
import os
import sys
import tkinter as tk
import tkinter.filedialog as filedialog
from Crypto.Cipher import AES
import Crypto.Random as random
import audiorand
import ctypes

class KeyFile(tk.Frame):
    def generate_key(self):
        keystr = self.sndrnd.ecc256_random(5)
        self.keylist.append(keystr)
        print(audiorand.bin2str_b64(keystr))

    def load_key(self):
        fname = filedialog.askopenfilename(parent=self, title='Load Key File',
                filetypes=(("secret key", "*.pri"), ("all files", "*.*")))
        if len(fname) == 0:
            return
        self.keylist = []
        mh = audiorand.hashlib.new('ripemd160')
        mh.update(self.passwd_str.get().encode('utf-8'))
        passwd = mh.digest()
        aes = AES.new(passwd[:16], AES.MODE_ECB)
        ifp = open(fname, 'rb')
        cip = ifp.read(48)
        while cip:
            pla = aes.decrypt(cip)
            crc32 = self.libecc.crc32(pla, len(pla))
            if crc32 != 0:
                print("Invalid Pass Word!")
                cip = ifp.read(48)
                continue
            keystr = pla[:32]
            b64key = b'0' + audiorand.bin2str_b64(keystr)
            ecckey = ctypes.create_string_buffer(b'\000', 96)
            self.libecc.ecc_key_import_str(ecckey, b64key)
            pubkey = ctypes.create_string_buffer(b'\000', 48)
            self.libecc.ecc_key_export_str(pubkey, 48, ecckey, 0x7e)
            pubkey = bytes(pubkey).decode('utf-8')
            pkeyhash = ctypes.create_string_buffer(b'\000', 48)
            self.libecc.ecc_key_hash_str(pkeyhash, 32, ecckey)
            pkeyhash = bytes(pkeyhash).decode('utf-8')
            self.keylist.append((keystr, pubkey, pkeyhash))
            cip = ifp.read(48)
        ifp.close()

    def __init__(self, parent=None, fname=None, width=32):
        super().__init__(parent)
        self.mfont = ('courier', 16, 'bold')
        self.pack(side=tk.TOP, expand=tk.YES, fill=tk.BOTH)

        f1 = tk.Frame(self)
        f1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        f2 = tk.Frame(self)
        f2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)

        f1_1 = tk.Frame(f1)
        f1_1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        f1_2 = tk.Frame(f1)
        f1_2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)

        row2 = tk.Frame(f1_1)
        row2.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        passlab = tk.Label(row2, text='  Passwd:', font=self.mfont)
        passlab.pack(side=tk.LEFT)
        self.passwd_str = tk.StringVar()
        self.passwd_str.set('')
        passtext = tk.Entry(row2, show="*", textvariable=self.passwd_str, width=width)
        passtext.config(font=self.mfont)
        passtext.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

        row4 = tk.Frame(f1_2)
        row4.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)
        tk.Button(row4, text="Load Keys", font=self.mfont,
                width=18, command=self.load_key).pack(side=tk.LEFT)
        tk.Button(row4, text="Generate Key", font=self.mfont,
                width=18, command=self.generate_key).pack(side=tk.RIGHT)
        tk.Button(row4, text="Save Keys", font=self.mfont,
                width=18, command=self.save_key).pack()

        self.sndrnd = audiorand.SndRnd()
        self.keylist = []
        self.libecc = ctypes.CDLL("../ecc256/libecc256.so")
        self.libecc.ecc_init()

    def save_key(self):
        fname = filedialog.asksaveasfilename(parent=self, title='Save Key File',
                filetypes=(("secret key", "*.pri"), ("all files", "*.*")))
        if len(fname) == 0:
            return
        mh = audiorand.hashlib.new('ripemd160')
        mh.update(self.passwd_str.get().encode('utf-8'))
        passwd = mh.digest()
        aes = AES.new(passwd[:16], AES.MODE_ECB)
        ofp = open(fname, 'wb')
        for keystr in self.keylist:
            appstr = self.sndrnd.ecc256_random(1)
            plain = keystr[0] + appstr[:12]
            crc32 = self.libecc.crc32(plain, len(plain))
            if (crc32 < 0):
                crc32 += 2**32
            plain += crc32.to_bytes(4, 'big')
            scrtext = aes.encrypt(plain)
            ofp.write(scrtext)
        ofp.close()

    def mexit(self):
        print("I'm exiting!")
        sys.exit()

root = tk.Tk()
root.title(sys.argv[0])

fname=os.getcwd() + '/ecc256_key.pri'
if len(sys.argv) > 1:
    fname = sys.argv[1]

width = len(fname)
if (width < 32): width = 32

keyfile = KeyFile(root, fname, width)

root.protocol('WM_DELETE_WINDOW', keyfile.mexit)

root.mainloop()
