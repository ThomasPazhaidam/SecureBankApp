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
AccountNumField = customtkinter.CTkEntry(master=loginFrame, height= 35, width=220, fg_color="#001848",
                                    placeholder_text_color=("white","white"), border_color=("#872570","#872570"), corner_radius=0, 
                                    font=AccountNumFont, border_width=1, placeholder_text="Card number")
AccountNumField.place(x=40, y=40)

def remove_all_rows():
    # Remove all rows from the TreeView
    for item in tree.get_children():
        tree.delete(item)

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
        remove_all_rows()
        count = 0
        for rows in data:
            tree.insert(parent='',index='end',iid=count,text="",values=(rows[0],rows[1],rows[2]))
            count+=1

    else:
        remove_all_rows()
        glbSelectedAccountId = -1
        BalanceText.configure(text="XXXX.XX")
        FirstNameLastName.configure(text = "First Name Last Name")        


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
# Function to handle each client connection

'''
TCP Communication
'''
def UpdateDatagram(type=0, cardNumber=0, password="", firstName="", lastName="", balance=0, txAmount=0, valid=0):
    Datagram = {
    "type": 0,
    "cardNumber": 0,
    "password": "",
    "firstName":"",
    "lastName":'',
    "balance": 0.0,
    "txAmount": 0.0,
    "valid": 0
    }
    Datagram["type"]=type
    Datagram["cardNumber"]=cardNumber
    Datagram["password"]=password
    Datagram["firstName"]=firstName
    Datagram["lastName"]=lastName
    Datagram["balance"]=balance
    Datagram["txAmount"]=txAmount
    Datagram["valid"]=valid
    return Datagram

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
        elif(glbDatagram['type']==2):
            NewBalance = UpdateBalance(glbDatagram['cardNumber'],glbDatagram['txAmount'])
            glbDatagram = UpdateDatagram(type=2, cardNumber=glbDatagram['cardNumber'],balance=NewBalance)
            client_socket.send(pickle.dumps(glbDatagram))


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
    cur.execute(f"INSERT INTO transactions (amount, date, userId) VALUES ('{Amount}','{datetime.now()}','{data[0][1]}')")
    connection.commit()
    cur.execute(f"SELECT balance FROM user WHERE user.accountNumber='{CardNumber}'")
    data = cur.fetchall()
    connection.close()
    return data[0][0]

# Server configuration
HOST = '127.0.0.1'  # Localhost
PORT = 12345  # Port to listen on

# Start the server in a separate thread
server_thread = threading.Thread(target=start_server, args=(HOST, PORT))
server_thread.start()

app.mainloop()