#!/usr/bin/python3
#
import sys
import tkinter as tk
import tkinter.filedialog as filedialog
import audiorand

class KeyFile(tk.Frame):
    def generate_key(self):
        keystr = self.sndrnd.ecc256_keygen(5)
        print(len(keystr))
##        self.keyf.config(state='normal')
##        self.keyf.delete(0, 'end')
##        self.keyf.insert(0, keystr)
##        self.keyf.config(state='readonly')
        return keystr

    def __init__(self, parent=None, fname=None):
        super().__init__(parent)
        self.mfont = ('courier', 20, 'bold')
        self.pack(side=tk.TOP, expand=tk.YES, fill=tk.BOTH)

        self.fname = fname

        outer_u = tk.Frame(self)
        outer_u.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        outer_l = tk.Frame(self)
        outer_l.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)

        row1 = tk.Frame(outer_u)
        row1.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)
        keylab = tk.Label(row1, text='Key File:', font=self.mfont)
        keylab.pack(side=tk.LEFT)
        self.keyf = tk.Entry(row1, width=32)
        self.keyf.insert(0, fname)
        self.keyf.config(font=self.mfont, state='readonly')
        self.keyf.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

        row2 = tk.Frame(outer_u)
        row2.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)
        passlab = tk.Label(row2, text='  Passwd:', font=self.mfont)
        passlab.pack(side=tk.LEFT)
        passtext = tk.Entry(row2, show="*", width=32)
        passtext.config(font=self.mfont)
        passtext.pack(side=tk.RIGHT, expand=tk.YES, fill=tk.X)

        row4 = tk.Frame(outer_l)
        row4.pack(side=tk.TOP, expand=tk.YES, fill=tk.X)

        tk.Button(row4, text="Select Key File", command=self.select_file,
                font=self.mfont).pack()

        row5 = tk.Frame(outer_l)
        row5.pack(side=tk.BOTTOM, expand=tk.YES, fill=tk.X)
        tk.Button(row5, text="Generate New Key", font=self.mfont).pack()

        self.sndrnd = audiorand.SndRnd()

    def select_file(self):
        fname = filedialog.askopenfilename(parent=self, multiple=False, title='Select Key File')
        if len(fname) != 0:
            self.keyf.config(state='normal')
            self.keyf.delete(0, 'end')
            self.keyf.insert(0, fname)
            self.keyf.config(state='readonly')
        self.fname =fname

root = tk.Tk()
root.title(sys.argv[0])

fname='ecc256_key.dat'
if len(sys.argv) > 1:
    fname = sys.argv[1]

keyfile = KeyFile(root, fname)

root.mainloop()
