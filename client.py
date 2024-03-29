import tkinter
#remember to run [pip install customtkinter]
import customtkinter
#remember to run [pip install Pillow]
from PIL import ImageTk, Image

customtkinter.set_appearance_mode("system")
customtkinter.set_default_color_theme("dark-blue")

app = customtkinter.CTk()
app.geometry("1280x720")
app.title("Secure Bank")
background = ImageTk.PhotoImage(Image.open("Photos/background.jpg"))

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
        print(usernameField.get())
        print(passwordField.get())
        CreateMainPage(usernameField.get())
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
            print(firstNameField.get())
            print(lastNameField.get())
            print(usernameField.get())
            print(passwordField.get())
            RegisterPage.destroy()
    
    confirmButton = customtkinter.CTkButton(master =loginFrame, height = 35, width=220, text="Register now", corner_radius=4,fg_color="#872570", text_color="#001848", border_color="#001848", bg_color= "transparent",
                                            border_width= 1, font = fieldFont, hover_color="#5a206d", command=CreateUser)
    confirmButton.place(x=50, y=280) 
    
    RegisterPage.mainloop()

def CreateMainPage(AccountNumber):
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
    AccountNumber = customtkinter.CTkLabel(master=loginFrame, text=AccountNumber, font=AccountNumFont)
    AccountNumber.place(relx=0.5, y=80, anchor=tkinter.CENTER)
    ChequingWordLabel = customtkinter.CTkLabel(master=loginFrame, text="Chequing", font=ChequingWordFont)
    ChequingWordLabel.place(relx=0.5, y=40, anchor=tkinter.CENTER)

    #account frame
    accountFrame = customtkinter.CTkFrame(master=loginFrame, width=1010, height=450, fg_color=("#872570", "#872570"))
    accountFrame.place(relx=0.5, y=345, anchor=tkinter.CENTER)

    #get account balance from server
    Balance = '99999.99'
    BalanceLabel = customtkinter.CTkLabel(master=accountFrame, text="BALANCE", font=ChequingWordFont)
    BalanceLabel.place(relx=0.5, y=40, anchor=tkinter.CENTER)
    BalanceNumberLabel = customtkinter.CTkLabel(master=accountFrame, text=Balance, font=AccountNumFont)
    BalanceNumberLabel.place(relx=0.5, y=80, anchor=tkinter.CENTER)  

CreateLoginPage()
