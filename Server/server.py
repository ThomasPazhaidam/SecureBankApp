import tkinter
#remember to run [pip install customtkinter]
import customtkinter
#remember to run [pip install Pillow]
from PIL import ImageTk, Image
import sqlite3 as sql
from tkinter import ttk
import socket
import threading
import pickle
from datetime import datetime
import sys
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import base64
import hashlib
from methods import generate_nonce, decrypt_message, encrypt_message, derive_keys


shared_key1 = '855dc24ed356091aa1bca8b694c282b1'
key = b'\x9f\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde'
#Master_Key = ""
MAC_Key = ""
Encr_Key = ""

#type -> 1 (registration), 2 (transaction), 3 (sign in)
glbDatagram = {
    "type": 0,
    "cardNumber": 0,
    "password": "",
    "firstName":"",
    "lastName":'',
    "balance": 0.0,
    "txAmount": 0.0,
    "valid": 0
}

'''
Server GUI
'''
#selected account id associated with primary key in database
glbSelectedAccountId = -1



def remove_all_rows():
    # Remove all rows from the TreeView
    for item in tree.get_children():
        tree.delete(item)

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt_data(iv, ct, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return pt

def decrypt_message(iv, ct, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return pt

def verify_mac(message, received_mac, key):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message.encode('utf-8'))
    calculated_mac = base64.b64encode(h.digest()).decode('utf-8')
    return received_mac == calculated_mac

#get user info from database
def GetUserInfo():
    cursor.execute(f"SELECT personId,firstName,lastName,balance FROM user WHERE user.accountNumber='{AccountNumField.get()}'")
    data = cursor.fetchall()
    if(len(data)!=0):
        glbSelectedAccountId = int(data[0][0])
        BalanceText.configure(text=data[0][3])
        FirstNameLastName.configure(text = f"{data[0][1]} {data[0][2]}")
        cursor.execute(f"SELECT transactionId, amount, date FROM transactions WHERE userId='{glbSelectedAccountId}'" )
        data = cursor.fetchall()
        decrypted_data = []
        for row in data:
            # Split the IV and ciphertext based on their sizes (IV is 16 bytes long when base64 encoded)
            iv_amount, ct_amount = row[1][:24], row[1][24:]
            iv_date, ct_date = row[2][:24], row[2][24:]

            # Decrypt each piece of data
            amount = decrypt_data(iv_amount, ct_amount, key)
            date = decrypt_data(iv_date, ct_date, key)
            decrypted_data.append((row[0], amount, date))
        remove_all_rows()
        count = 0

        for rows in decrypted_data:
            tree.insert(parent='',index='end',iid=count,text="",values=(rows[0],rows[1],rows[2]))
            count+=1

    else:
        remove_all_rows()
        glbSelectedAccountId = -1
        BalanceText.configure(text="XXXX.XX")
        FirstNameLastName.configure(text = "First Name Last Name")        



# Function to handle each client connection

'''
TCP Communication
'''
def UpdateDatagram(type=0, cardNumber=0, password="", firstName="", lastName="", balance=0, txAmount=0, valid=0, encrypted_data="", iv="", mac=""):
    Datagram = {
    "type": 0,
    "cardNumber": 0,
    "password": "",
    "firstName":"",
    "lastName":'',
    "balance": 0.0,
    "txAmount": 0.0,
    "valid": 0,
    "encrypted_data": "",
    "iv": '',
    "mac": ''
    }
    Datagram["type"]=type
    Datagram["cardNumber"]=cardNumber
    Datagram["password"]=password
    Datagram["firstName"]=firstName
    Datagram["lastName"]=lastName
    Datagram["balance"]=balance
    Datagram["txAmount"]=txAmount
    Datagram["valid"]=valid
    Datagram["encrypted_data"]=encrypted_data
    Datagram["iv"]=iv
    Datagram["mac"]=mac
    return Datagram

def auth_1(client_socket):
    print("")
    # NEED SERVER AND CLIENT TO AUTHENTICATE EACH OTHER THEN ESTABLISH SHARED
    print("AUTHENTICATION STARTED") 
    #input('Press Enter to start Authentication')

    challenge = generate_nonce()
    print(f'Challenge = {challenge}')
    client_socket.send(challenge.encode())

    # receive challenge response from client
    challenge_response = client_socket.recv(4096)
    print(f'Challenge Response = {challenge_response.decode()}')
    # compute the expected response of the challenge
    expected_response = hashlib.sha256(challenge.encode() + shared_key1.encode()).hexdigest()
    print(f'Expected Response = {expected_response}')

    # now compare expected to received
    if expected_response.encode() == challenge_response:
        print("Client authenticated successfully")
    else:
        print("Authentication failed")

    # authentication done so generate master key
    # generate random master key -> encrypt with already defined key
    master_key = generate_nonce()
    print(f'Master Key = {master_key}')
    # encrypt master key with shared key
    encrypted_master_key = encrypt_message(master_key, shared_key1)
    client_socket.send(encrypted_master_key)
    #client_socket.send(master_key.encode())


    # derive 2 keys using HKDF for MAC and Encryption
    encryption_key, mac_key = derive_keys(master_key.encode())
    global Encr_Key
    Encr_Key = encryption_key
    global MAC_Key
    MAC_Key = mac_key

    print(f"Encryption key: {Encr_Key}")
    print(f"MAC key: {MAC_Key}")
    print("")


def handle_client(client_socket, address):
    print(f"Accepted connection from {address}")

    # Handle client communication
    while True:
        # Receive data from client
        data = client_socket.recv(4096)
        if not data:
            break
        glbDatagram=pickle.loads(data)
        if(glbDatagram['type']==1):
            CreateUser(glbDatagram['cardNumber'], glbDatagram['password'], glbDatagram['firstName'], glbDatagram['lastName'])
        elif(glbDatagram['type']==3):
            verify, balance = VerifyUser(glbDatagram['cardNumber'], glbDatagram['password'])
            glbDatagram=UpdateDatagram(type=3, cardNumber=glbDatagram['cardNumber'],balance=balance, valid=verify)
            client_socket.send(pickle.dumps(glbDatagram))
            # ADDED AUTH FOR VERIFIED USER
            print(glbDatagram["valid"])
            if(glbDatagram["valid"]==1):
                auth_1(client_socket)
        elif(glbDatagram['type']==2):
            encrypted_data = glbDatagram['encrypted_data']
            iv = glbDatagram['iv']
            received_mac = glbDatagram['mac']
            if verify_mac(encrypted_data, received_mac, bytes.fromhex(MAC_Key)):
                # MAC is valid, proceed with decryption
                transaction_data = decrypt_message(iv, encrypted_data, bytes.fromhex(Encr_Key))
                
                # Assuming transaction_data format is "AccountNumber:Amount"
                account_number, amount = transaction_data.split(":")
                
                # Convert amount to the appropriate type as needed, e.g., int or float
                amount = float(amount)  # Example conversion
                NewBalance = UpdateBalance(account_number, amount)
                glbDatagram = UpdateDatagram(type=2, cardNumber=account_number,balance=NewBalance)
                client_socket.send(pickle.dumps(glbDatagram))
            else:
                # MAC verification failed, handle as needed
                print("MAC verification failed.")


    # Close the connection
    client_socket.close()
    print(f"Connection with {address} closed")

# Function to start the server
def start_server(host, port):
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    server_socket.bind((host, port))

    # Listen for incoming connections
    server_socket.listen(5)  # Maximum number of connections to accept

    print(f"Server listening on {host}:{port}")

    # Main loop to accept incoming connections
    while True:
        # Accept a new connection
        client_socket, address = server_socket.accept()

        # Start a new thread to handle the client connection
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.start()

def CreateUser(CardNumber, Password, FirstName, LastName):
    connection = sql.connect('Server/serverdb.db')
    cur = connection.cursor()
    cur.execute(f"INSERT INTO user (firstName, lastName, accountNumber,password,balance) VALUES ('{FirstName}','{LastName}','{CardNumber}', '{Password}','0')")
    connection.commit()
    connection.close()

def VerifyUser(CardNumber, Password):
    balance = -1
    authentication = 0

    connection = sql.connect('Server/serverdb.db')
    cur = connection.cursor()
    cur.execute(f"SELECT password,balance FROM user WHERE user.accountNumber='{CardNumber}'")
    data = cur.fetchall()
    if(len(data)!=0):
        if(data[0][0]==Password):
            authentication = 1
            balance = data[0][1]
    connection.close()
    return authentication, balance
    
def UpdateBalance(CardNumber, Amount):
    connection = sql.connect('Server/serverdb.db')
    cur = connection.cursor()
    cur.execute(f"SELECT balance,personId FROM user WHERE user.accountNumber='{CardNumber}'")
    data = cur.fetchall()
    newBalance = data[0][0] + Amount
    newBalance = round(newBalance,2)
    cur.execute(f"UPDATE user SET balance ='{newBalance}' WHERE user.accountNumber='{CardNumber}'")
    connection.commit()
    # Encryption process before inserting log data
    iv_amount, ct_amount = encrypt_data(str(Amount), key)
    iv_date, ct_date = encrypt_data(str(datetime.now()), key)

    # Concatenate IV with ciphertext before storing (for simplicity)
    encrypted_amount = iv_amount + ct_amount
    encrypted_date = iv_date + ct_date
    cur.execute(f"INSERT INTO transactions (amount, date, userId) VALUES ('{encrypted_amount}','{encrypted_date}','{data[0][1]}')")
    connection.commit()
    cur.execute(f"SELECT balance FROM user WHERE user.accountNumber='{CardNumber}'")
    data = cur.fetchall()
    connection.close()
    return data[0][0]



if __name__ == "__main__":

    if len(sys.argv) == 0:
        print("Please prvoide an arugement for the port number")
        sys.exit(1)
    else:
        port_num = sys.argv[1]
        port_num = int(port_num)
        print(f"Port Number = {port_num}")


    customtkinter.set_appearance_mode("system")
    customtkinter.set_default_color_theme("dark-blue")
    conn = sql.connect('Server/serverdb.db')
    cursor = conn.cursor()

    app = customtkinter.CTk()
    app.geometry("1280x720")
    app.title("Secure Bank")
    background = ImageTk.PhotoImage(Image.open("Server/Photos/background.jpg"))

    #build main window
    label1 = customtkinter.CTkLabel(master=app, image=background)
    label1.pack()
    loginFrame = customtkinter.CTkFrame(master=label1, width=1024, height=576, fg_color=("#001848", "#001848"))
    loginFrame.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

    AccountNumFont = customtkinter.CTkFont('Sans-serif', 15)
    AccountNumField = customtkinter.CTkEntry(master=loginFrame, height= 35, width=220, fg_color="#001848", text_color="#FFFFFF",
                                        placeholder_text_color=("white","white"), border_color=("#872570","#872570"), corner_radius=0, 
                                        font=AccountNumFont, border_width=1, placeholder_text="Card number")
    AccountNumField.place(x=40, y=40)

    LoginButton = customtkinter.CTkButton(master =loginFrame, height = 35, width=100, text="Get history", corner_radius=4,fg_color="#872570", text_color="#001848", 
                                      font = AccountNumFont, hover_color="#5a206d", command=GetUserInfo)
    LoginButton.place(x=275, y=40)
    HeadingFont = customtkinter.CTkFont('Sans-serif', 15, weight='bold')
    BalanceHeadingText = customtkinter.CTkLabel(master=loginFrame, text="BALANCE", font=HeadingFont, text_color="#872570") 
    BalanceHeadingText.place(x=40, y=80)
    BalanceFont = customtkinter.CTkFont('Sans-serif', 25, weight='bold')
    BalanceText = customtkinter.CTkLabel(master=loginFrame, text="XXXX.XX", font=BalanceFont, text_color="#872570") 
    BalanceText.place(x=40, y=100)
    NameFont = customtkinter.CTkFont('Sans-serif', 25)
    FirstNameLastName = customtkinter.CTkLabel(master=loginFrame, text="First Name Last Name", font=NameFont, text_color="#872570") 
    FirstNameLastName.place(x=400, y=43)

    scrollbar = customtkinter.CTkScrollbar(master=loginFrame, orientation="vertical")

    #create tree to display database transaction data
    tree = ttk.Treeview(loginFrame, height=17, yscrollcommand=scrollbar.set)
    tree['columns'] = ("Transaction ID","Transaction", "Time")
    tree.column("#0", width=0,stretch=False)
    tree.column("Transaction ID", anchor="center", width=200)
    tree.column("Transaction", anchor="center", width=200)
    tree.column("Time", anchor="center", width=200)
    tree.heading("Transaction ID", text="Transaction ID", anchor="center")
    tree.heading("Transaction", text="Transaction", anchor="center")
    tree.heading("Time", anchor="center", text="Time")
    tree.place(relx=0.5, y=350, anchor=tkinter.CENTER)

    style= ttk.Style()
    style.theme_use("default")
    # Change the background color of the TreeView
    style.configure("Treeview", background="#872570")
    HeadingFont = customtkinter.CTkFont('Sans-serif', 15)
    style.configure("Treeview.Heading", font=HeadingFont, background="#872570")

    #configure scrollbar
    scrollbar.configure(command=tree.yview)


    # Server configuration
    HOST = '127.0.0.1'  # Localhost
    PORT = 12345  # Port to listen on

    # Start the server in a separate thread
    server_thread = threading.Thread(target=start_server, args=(HOST, port_num))
    server_thread.start()

    app.mainloop()