#!/usr/bin/python3
#
import os
import sys
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.messagebox as mesgbox
import hashlib
import ctypes
import TokenTX
import CopyListbox
import socket
import configparser
import pathlib

mfont = ('courier', 16, 'bold')

class PasswdInput(tk.Toplevel):
    def onpwdentry(self, evt):
        self.passwd = self.pwdbox.get()
        self.destroy()

    def onclick(self):
        self.passwd = self.pwdbox.get()
        self.destroy()

    def __init__(self, parent, mfont, text="Please Input Passwd"):
        tk.Toplevel.__init__(self, parent)
        self.title(text)
        topbar = tk.Frame(self)
        topbar.pack(side=tk.TOP, fill=tk.X)
        botbar = tk.Frame(self)
        botbar.pack(side=tk.BOTTOM, fill=tk.Y)
        tk.Label(topbar, text="Password:", font=mfont).pack(side=tk.LEFT)
        passwd = ''
        self.pwdbox = tk.Entry(topbar, show='*', font=mfont)
        self.pwdbox.pack(side=tk.RIGHT)
        tk.Button(botbar, command=self.onclick, text='OK', font=mfont).pack(side=tk.BOTTOM)
        self.bind('<Return>', self.onpwdentry)

    def show(self):
        self.wm_deiconify()
        self.pwdbox.focus_force()
        self.wait_window()
        return self.passwd


class SList(tk.Frame):
    def clearlist(self):
        self.hbox.delete(0, tk.END)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.pack(expand=tk.YES, fill=tk.BOTH);

        f1 = tk.Frame(self)
        f1.pack(side=tk.TOP, expand=tk.YES, fill=tk.BOTH)
        f2 = tk.Frame(self)
        f2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.BOTH)

        tk.Label(f1, text="Public Key Hash:", font=mfont, width=32).pack(side=tk.TOP)

        sbar = tk.Scrollbar(f2)
        hbox = CopyListbox.CopyListbox(f2, relief=tk.SUNKEN, font=mfont, width=32)
        sbar.config(command=hbox.yview)
        hbox.config(yscrollcommand=sbar.set)
        sbar.pack(side=tk.RIGHT, fill=tk.Y)
        hbox.pack(side=tk.LEFT, expand=tk.YES, fill=tk.BOTH)
        self.hbox = hbox

    def append_item(self, pubhash):
        self.hbox.insert(tk.END, pubhash)

class GlobParam:
    def __init__(self, cfg_name):
        mconfig = configparser.ConfigParser()
        mconfig['client'] = {}
        mconfig['server'] = {}
        if len(cfg_name) > 0:
            mconfig.read(cfg_name)

        melib = mconfig['client'].get('library', './libtoktx.so')
        font = mconfig['client'].get('font', 'courier')
        font_size = int(mconfig['client'].get('font_size', '16'))
        font_style = mconfig['client'].get('font_style', 'bold')
        self.libtoktx = ctypes.CDLL(melib)
        self.libtoktx.ecc_init()
        self.keylist = []
        self.keymod = 0
        self.mfont = (font, font_size, font_style)
        self.tries = int(mconfig['client'].get('tries', '25'))

        server = mconfig['server'].get('host', '127.0.0.1')
        sport = mconfig['server'].get('port', '6001')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        txsvr = socket.getaddrinfo(server, sport, family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.setblocking(0)
        self.sock = {'sock': sock, 'sockaddr': txsvr[0][4]}

    def append_key(self, keystr):
        pkeyhash = ctypes.create_string_buffer(b'\000', 48)
        self.libtoktx.ecc_key_hash_str(pkeyhash, 48, keystr)
        pkeyhash = bytes(pkeyhash).decode('utf-8').strip("\000")
        self.keylist.append((keystr, pkeyhash))
        self.keymod = 1
        return pkeyhash
    
    def generate_key(self):
        keystr = bytes(ctypes.create_string_buffer(96, '\0x0'))
        gotone = self.libtoktx.ecc_genkey(keystr);
        if gotone != 0:
            mesgbox.showerror("Error", "Cannot Get Enough Random Bits");
        return self.append_key(keystr)

    def clear_key(self):
        self.keylist_bak = self.keylist[:]
        self.keylist.clear()

    def save_key(self, fname, passwd):
        aeskey_buf = ctypes.create_string_buffer(176)
        self.libtoktx.aes_reset(aeskey_buf, passwd)
        pad = ctypes.create_string_buffer(12)
        secret = ctypes.create_string_buffer(48)
        ofp = open(fname, 'wb')
        for keystr in self.keylist:
            self.libtoktx.rand32bytes(pad, 12, 0)
            plain = keystr[0][:32] + bytes(pad)
            crc32 = self.libtoktx.crc32(plain, len(plain))
            if (crc32 < 0):
                crc32 += 2**32
            plain += crc32.to_bytes(4, 'big')
            self.libtoktx.dsaes(aeskey_buf, plain, secret, 48)
            ofp.write(bytes(secret))
        ofp.close()
        self.keymod = 0

    def load_key(self, fname, passwd):
        self.clear_key()
        aeskey_buf = ctypes.create_string_buffer(176)
        self.libtoktx.aes_reset(aeskey_buf, passwd)
        pla = ctypes.create_string_buffer(48)
        ifp = open(fname, 'rb')
        cip = ifp.read(48)
        khashs = []
        while cip:
            self.libtoktx.un_dsaes(aeskey_buf, cip, pla, 48)
            crc32 = self.libtoktx.crc32(pla, 48)
            if crc32 != 0:
                mesgbox.showerror("Error", "Invalid Password")
                ifp.close()
                self.keylist = self.keylist_bak[:]
                self.keylist_bak.clear()
                return khashs.clear()
            keystr = pla[:32]
            ecckey = bytes(ctypes.create_string_buffer(96))
            self.libtoktx.ecc_get_public(keystr, ecckey)
            khashs.append(self.append_key(ecckey))
            cip = ifp.read(48)
        ifp.close()
        self.keymod = 0
        return khashs

class KeyFile(tk.Frame):
    def generate_key(self):
        khash = self.glob.generate_key()
        if khash:
            self.publist.append_item(khash)

    def load_key(self):
        if self.glob.keymod and mesgbox.askyesno("Confirm Action", \
                "Keys has been modified, Save it?", master=self):
            self.config(cursor="watch")
            self.save_key()
            self.config(cursor="")
        fname = filedialog.askopenfilename(parent=self, title='Load Key File',
                filetypes=(("secret key", "*.pri"), ("all files", "*.*")))
        if len(fname) == 0:
            return
        passwd = PasswdInput(self, self.glob.mfont).show()
        mh = hashlib.new('ripemd160')
        mh.update(passwd.encode('utf-8'))
        passwd = mh.digest()
        khashs = self.glob.load_key(fname, passwd[:16])
        if khashs:
            self.publist.clearlist()
            for pkhash in khashs:
                self.publist.append_item(pkhash)

    def __init__(self, parent, glob, width=32):
        super().__init__(parent)
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
        passlab = tk.Label(row2, text='Key Management', font=mfont)
        passlab.pack(side=tk.TOP)

        row4 = tk.Frame(f1_2)
        row4.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)
        tk.Button(row4, text="Load Keys", font=mfont,
                width=18, command=self.load_key).pack(side=tk.LEFT)
        tk.Button(row4, text="Generate Key", font=mfont,
                width=18, command=self.generate_key).pack(side=tk.RIGHT)
        tk.Button(row4, text="Save Keys", font=mfont,
                width=18, command=self.save_key).pack()

        separator = tk.Frame(f2, height=8, bg='black', bd=2, relief=tk.SUNKEN)
        separator.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        self.publist = SList(f2)
        self.glob = glob

    def save_key(self):
        fname = filedialog.asksaveasfilename(parent=self, title='Save Key File',
                filetypes=(("secret key", "*.pri"), ("all files", "*.*")))
        if len(fname) == 0:
            return
        negpos = fname.rfind('.')
        if negpos == -1 or negpos + 4 < len(fname):
            fname += '.pri'
        mh = hashlib.new('ripemd160')
        passwd0 = PasswdInput(self, self.glob.mfont).show()
        passwd1 = PasswdInput(self, self.glob.mfont, text="Renter Password").show()
        while passwd0 != passwd1 and mesgbox.askretrycancel("Error", "Password Confirmation Failed!"):
            passwd0 = PasswdInput(self, self.glob.mfont).show()
            passwd1 = PasswdInput(self, self.glob.mfont, text="Renter Password").show()
        if passwd0 != passwd1:
            mesgbox.showwarning("Warning", "Keys Not Saved")
            return

        mh.update(passwd0.encode('utf-8'))
        passwd = mh.digest()
        self.glob.save_key(fname, passwd[:16])

    def mexit(self):
        if self.glob.keymod and mesgbox.askyesno("Confirm Action", \
                "Keys has been modified, Save it?", master=self):
            self.config(cursor="watch")
            self.save_key()
            self.config(cursor="")
        sys.exit(0)


if __name__ == "__main__":
    def ttransfer():
        neww = tk.Toplevel(root)
        neww.title("Token Transfer")
        try:
            token_op = TokenTX.TokenTX(neww, keyfile.glob)
        except:
            neww.destroy()
        
    fname=os.getcwd() + '/etoken.ini'
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    if not pathlib.Path(fname).exists():
        print("Warning: Configuration not exit {}".format(fname))
        fname = ''


    root = tk.Tk()
    root.title(sys.argv[0])

    fp1 = tk.Frame(root)
    fp1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X);
    fp2 = tk.Frame(root)
    fp2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X);
    glob = GlobParam(fname)
    keyfile = KeyFile(fp1, glob)

    tk.Button(fp2, text="Token Transfer", font=mfont,
            width=25, command=ttransfer).pack(side=tk.LEFT)
    root.protocol('WM_DELETE_WINDOW', keyfile.mexit)

    root.mainloop()
