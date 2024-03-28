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

#login page background
background = ImageTk.PhotoImage(Image.open("Photos/background.jpg"))
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

#login and create user buttons
LoginButton = customtkinter.CTkButton(master =loginFrame, height = 35, width=220, text="Sign on", corner_radius=4,fg_color="#872570", text_color="#001848", font = fieldFont, hover_color="#5a206d")
LoginButton.place(x=50, y=195)

registerButton = customtkinter.CTkButton(master =loginFrame, height = 35, width=220, text="Register now", corner_radius=4,fg_color="transparent", text_color="#872570", border_color="#872570", 
                                         border_width= 1, font = fieldFont, hover_color="#5a206d")
registerButton.place(x=50, y=250)
app.mainloop()

