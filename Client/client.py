import tkinter
#remember to run [pip install customtkinter]
import customtkinter
#remember to run [pip install Pillow]
from PIL import ImageTk, Image
import socket
import pickle

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
Client GUI
'''
customtkinter.set_appearance_mode("system")
customtkinter.set_default_color_theme("dark-blue")

app = customtkinter.CTk()
app.geometry("1280x720")
app.title("Secure Bank")
background = ImageTk.PhotoImage(Image.open("Client/Photos/background.jpg"))

def CreateLoginPage():
    #login page background
    label1 = customtkinter.CTkLabel(master=app, image=background)
    label1.pack()
    loginFrame = customtkinter.CTkFrame(master=label1, width=320, height=360, fg_color=("#001848", "#001848"))
    loginFrame.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)
    #username and password fields
    fieldFont = customtkinter.CTkFont('Sans-serif', 15)
    usernameField = customtkinter.CTkEntry(master=loginFrame, height= 35, width=220, placeholder_text="Card number", fg_color="transparent",
                                        placeholder_text_color=("white","white"), border_color=("#872570","#872570"), corner_radius=0, font=fieldFont, border_width=1,)
    usernameField.place(x=50, y=85)

    passwordField = customtkinter.CTkEntry(master=loginFrame, height = 35, width=220, placeholder_text="Password (case sensitive)",  fg_color="transparent",
                                        placeholder_text_color=("white","white"), border_color=("#872570","#872570"), corner_radius=0, font=fieldFont, border_width=1)
    passwordField.place(x=50, y=140)
    def login():
        #authenticate user with account number and password
        glbDatagram = UpdateDatagram(type = 3, cardNumber=usernameField.get(),password=passwordField.get())
        client_socket.send(pickle.dumps(glbDatagram))
        data = client_socket.recv(4096)
        glbDatagram = pickle.loads(data)
        if(glbDatagram["valid"]==1):
            CreateMainPage(usernameField.get(), glbDatagram["balance"])
        else:
           failedLabel = customtkinter.CTkLabel(master=loginFrame, font = fieldFont, text= "Login failed.", bg_color="transparent") 
           failedLabel.place(x=50, y=305)

    #login and create user buttons
    LoginButton = customtkinter.CTkButton(master =loginFrame, height = 35, width=220, text="Sign on", corner_radius=4,fg_color="#872570", text_color="#001848", font = fieldFont, hover_color="#5a206d", command=login)
    LoginButton.place(x=50, y=195)

    registerButton = customtkinter.CTkButton(master =loginFrame, height = 35, width=220, text="Register now", corner_radius=4,fg_color="transparent", text_color="#872570", border_color="#872570", 
                                            border_width= 1, font = fieldFont, hover_color="#5a206d", command=CreateRegisterPage)
    registerButton.place(x=50, y=250) 
    app.mainloop()

def CreateRegisterPage():
    RegisterPage = customtkinter.CTkToplevel()

    RegisterPage.attributes('-topmost', True)
    RegisterPage.geometry(f"640x480")
    RegisterPage.title("Registration")
    #login page background
    RegBg = customtkinter.CTkLabel(master=RegisterPage, image=background, text="")
    RegBg.pack()
    #username and password fields
    loginFrame = customtkinter.CTkFrame(master=RegBg, width=320, height=360, fg_color=("#001848", "#001848"))
    loginFrame.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)

    fieldFont = customtkinter.CTkFont('Sans-serif', 15)
    firstNameField = customtkinter.CTkEntry(master=loginFrame, height= 35, width=220, fg_color="#001848",
                                        placeholder_text_color=("white","white"), border_color=("#872570","#872570"), corner_radius=0, font=fieldFont, border_width=1, placeholder_text="First name")
    firstNameField.place(x=50, y=60) 
    lastNameField = customtkinter.CTkEntry(master=loginFrame, height= 35, width=220, fg_color="#001848",
                                        placeholder_text_color=("white","white"), border_color=("#872570","#872570"), corner_radius=0, font=fieldFont, border_width=1, placeholder_text="Last name")
    lastNameField.place(x=50, y=115)

    usernameField = customtkinter.CTkEntry(master=loginFrame, height= 35, width=220, fg_color="#001848",
                                        placeholder_text_color=("white","white"), border_color=("#872570","#872570"), corner_radius=0, font=fieldFont, border_width=1, placeholder_text="Card number")
    usernameField.place(x=50, y=170)

    passwordField = customtkinter.CTkEntry(master=loginFrame, height = 35, width=220, fg_color="#001848",
                                        placeholder_text_color=("white","white"), border_color=("#872570","#872570"), corner_radius=0, font=fieldFont, border_width=1, placeholder_text="Password (case sensitive)")
    passwordField.place(x=50, y=225)
    
    def CreateUser():
        if(firstNameField.get()!="" and lastNameField.get()!="" and usernameField.get()!="" and passwordField.get()):
            #encrypt account creation request to server and get response
            glbDatagram = UpdateDatagram(type=1, cardNumber=int(usernameField.get()), password=passwordField.get(), firstName=firstNameField.get(), lastName=lastNameField.get())
            client_socket.send(pickle.dumps(glbDatagram))
            RegisterPage.destroy()
    
    confirmButton = customtkinter.CTkButton(master =loginFrame, height = 35, width=220, text="Register now", corner_radius=4,fg_color="#872570", text_color="#001848", border_color="#001848", bg_color= "transparent",
                                            border_width= 1, font = fieldFont, hover_color="#5a206d", command=CreateUser)
    confirmButton.place(x=50, y=280) 
    
    RegisterPage.mainloop()

def CreateMainPage(AccountNumber, Balance):
    #if user authenticated reset current window
    for widget in app.winfo_children():
        widget.destroy()
    #build main window
    label1 = customtkinter.CTkLabel(master=app, image=background)
    label1.pack()
    loginFrame = customtkinter.CTkFrame(master=label1, width=1024, height=576, fg_color=("#001848", "#001848"))
    loginFrame.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)
    AccountNumFont = customtkinter.CTkFont('Sans-serif', 40)
    ChequingWordFont = customtkinter.CTkFont('Sans-serif', 20)
    AccountNumberText = customtkinter.CTkLabel(master=loginFrame, text=AccountNumber, font=AccountNumFont, text_color="#872570")
    AccountNumberText.place(relx=0.5, y=80, anchor=tkinter.CENTER)
    ChequingWordLabel = customtkinter.CTkLabel(master=loginFrame, text="Chequing", font=ChequingWordFont, text_color="#872570")
    ChequingWordLabel.place(relx=0.5, y=40, anchor=tkinter.CENTER)

    #account frame
    accountFrame = customtkinter.CTkFrame(master=loginFrame, width=1010, height=450, fg_color=("#872570", "#872570"))
    accountFrame.place(relx=0.5, y=345, anchor=tkinter.CENTER)

    BalanceLabel = customtkinter.CTkLabel(master=accountFrame, text="BALANCE", font=ChequingWordFont, text_color="#001848")
    BalanceLabel.place(relx=0.5, y=40, anchor=tkinter.CENTER)
    BalanceNumberLabel = customtkinter.CTkLabel(master=accountFrame, text=Balance, font=AccountNumFont, text_color="#001848")
    BalanceNumberLabel.place(relx=0.5, y=80, anchor=tkinter.CENTER) 
    DepositWithdrawText = customtkinter.CTkLabel(master=accountFrame, text="DEPOSIT | WITHDRAW", font=ChequingWordFont, text_color="#001848") 
    DepositWithdrawText.place(relx=0.5, y=160, anchor=tkinter.CENTER) 
    amountField = customtkinter.CTkEntry(master=accountFrame, height= 35, width=240, fg_color="#001848",
                                        placeholder_text_color=("white","white"), border_color=("#872570","#872570"), corner_radius=2, font=ChequingWordFont, border_width=1, placeholder_text="Amount")
    amountField.place(relx=0.5, y=200, anchor=tkinter.CENTER)
    #Deposit and Withdraw buttons
    #verify thar user inputted a double
    def is_double(s):
        try:
            float(s)
            return True
        except ValueError:
            return False
    
    def Deposit():
        amountTxt = amountField.get()
        if(is_double(amountTxt)):
            amount = float(amountTxt)
            ProcessTransaction(AccountNumber, amount, BalanceNumberLabel, accountFrame)
    def Withdraw():
        amountTxt = amountField.get()
        if(is_double(amountTxt)):
            amount = float(amountTxt)*-1
            ProcessTransaction(AccountNumber, amount, BalanceNumberLabel, accountFrame)
        
    DepositButton = customtkinter.CTkButton(master =accountFrame, height = 35, width=240, text="Deposit", corner_radius=4,fg_color="transparent", text_color="#001848", 
                                          font = ChequingWordFont, hover_color="#5a206d", border_color="#001848", border_width= 1, command=Deposit)
    DepositButton.place(relx=0.5, y=250, anchor=tkinter.CENTER)

    WithdrawButton = customtkinter.CTkButton(master =accountFrame, height = 35, width=240, text="Withdraw", corner_radius=4,fg_color="#001848", text_color="#872570", 
                                            border_width= 0, font = ChequingWordFont, hover_color="#5a206d", command=Withdraw)
    WithdrawButton.place(relx=0.5, y=300, anchor=tkinter.CENTER)

def ProcessTransaction(AccountNumber, Amount, BalanceNumberLabel, AccountFrame):
    #send request
    glbDatagram = UpdateDatagram(type=2, cardNumber=AccountNumber,txAmount=Amount)
    client_socket.send(pickle.dumps(glbDatagram))
    data = client_socket.recv(4096)
    glbDatagram = pickle.loads(data)    
    #if successful update balance on client app
    Balance = glbDatagram['balance']
    BalanceNumberLabel.configure(text=Balance)
'''
TCP Communication
'''
def InitializeTCP():
    # Client configuration
    HOST = '127.0.0.1'  # Server IP address
    PORT = 12345  # Port to connect to
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to the server
    client_socket.connect((HOST, PORT))
    return client_socket

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

client_socket = InitializeTCP()

CreateLoginPage()
# Close the connection
client_socket.close()