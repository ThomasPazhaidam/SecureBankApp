import tkinter
#remember to run [pip install customtkinter]
import customtkinter
#remember to run [pip install Pillow]
from PIL import ImageTk, Image

customtkinter.set_appearance_mode("system")
customtkinter.set_default_color_theme("dark-blue")

app = customtkinter.CTk()
app.geometry("600x440")
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
usernameField.place(x=50, y=110)

passwordField = customtkinter.CTkEntry(master=loginFrame, height = 35, width=220, placeholder_text="Password (case sensitive)",  fg_color="transparent",
                                       placeholder_text_color=("white","white"), border_color=("#872570","#872570"), corner_radius=0, font=fieldFont, border_width=1)
passwordField.place(x=50, y=165)

#login and create user buttons
LoginButton = 
app.mainloop()

