import binascii
from tkinter import *
from PIL import *
from PIL import ImageTk, Image
from tkinter import messagebox
import base64


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)



#SAVE FILE
def save_file():
    note_text = secret_text.get("1.0",END).strip()
    key_entry = master_key_entry.get()

    if not title_entry.get() or not note_text or not master_key_entry.get():
        messagebox.showinfo(title="Info", message="Please check your info!")
    else:
        encrypted_message = encode(key_entry, note_text)

    master_key_entry.delete("0", END)
    title_entry.delete('0', END)
    secret_text.delete("1.0", END)


    try:
        with open("secret.txt",mode='a') as writer:
            writer.write(title_entry.get())
            writer.write("\n")
            writer.write(encrypted_message)
            writer.write("\n")
    except FileNotFoundError:
        with open("secret.txt",mode="w") as writer:
            writer.write(title_entry.get())
            writer.write("\n")
            writer.write(encrypted_message)
            writer.write("\n")


def decrpyt():
    note_text = secret_text.get("1.0", END).strip()
    key_entry = master_key_entry.get()
    try:
        decrypted_message = decode(key_entry,note_text)
        secret_text.delete("1.0",END)
        secret_text.insert("1.0",decrypted_message)
    except:
        messagebox.showinfo(title="Info",message="Please check your info.")


#WINDOW
window = Tk()
window.minsize(width=500,height=700)
window.title("Secret Notes")

#FRAME
frame = Frame(window,width=33,height=33)
frame.pack()

#PHOTO AND LOGO
img = ImageTk.PhotoImage(Image.open("output.png"))

photo = Label(frame,image=img)
photo.pack()
photo.config(width=150,height=150)

photo = PhotoImage(file="output.png")
window.iconphoto(False,photo)

#WIDGETS

title = Label(text="Enter your title")
title.pack()

title_entry = Entry(width=20)
title_entry.pack()

secret_label = Label(text="Enter your secret")
secret_label.pack()


secret_text = Text(width=50,height=15)
secret_text.pack()

master_key_label = Label(text="Enter your master key")
master_key_label.pack()

master_key_entry = Entry(width=30)
master_key_entry.pack()

master_key = master_key_entry.get()

save_button = Button(text="Save & Encrypt",command=save_file)
save_button.pack()

decrypt_button = Button(text="Decrypt",command=decrpyt)
decrypt_button.pack()

window.mainloop()