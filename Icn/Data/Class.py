# Project Python ICN
# Modified 28/04/2019
# Subject : Analyse Binaire
# By Nasm & cie


import tkinter as tk
import tkinter.messagebox as msg
from tkinter import filedialog
import platform
import pefile
import peutils


class Root(tk.Tk):
	# L'Utilisateur Ferme la Fenetre Section
	def section_del(self):
		self.deiconify()
		self.section.withdraw()

	# L'Utilisateur Presse le Bouton pour voir les Sections
	def section_show(self):
		self.withdraw()
		self.section.deiconify()

	# Positionnement pour l'Utilisateur Windows	
	def lancement_windows(self):
		self.lb_file.place(x=10, y=8)
		self.bt_file_explorer.place(x=750, y=10)
		self.e_file.place(x=70, y=13)
		self.e_file.config(width=74)
		self.lb_entrypoint.place(x=20, y=75)
		self.e_entrypoint.place(x=175, y=80)
		self.lb_imagebase.place(x=20, y=130)
		self.e_imagebase.place(x= 175, y=135)
		self.lb_nb_sections.place(x=20, y=185)
		self.e_nb_sections.place(x=220, y=190)
		self.e_packer.pack(side='bottom', pady=20)

	# Positionnement pour l'Utilisateur Linux
	def lancement_linux(self):
		print("N'est pas fini pour Linux")
		self.lb_file.place(x=10, y=8)
		self.bt_file_explorer.place(x=750, y=8)
		self.e_file.place(x=70, y=10)
		self.e_file.config(width=60)
		self.lb_entrypoint.place(x=20, y=75)
		self.e_entrypoint.place(x=175, y=80)
		self.lb_imagebase.place(x=20, y=130)
		self.e_imagebase.place(x= 175, y=135)
		self.lb_nb_sections.place(x=20, y=185)
		self.e_nb_sections.place(x=230, y=190)
		self.e_packer.pack(side='bottom', pady=20)
		self.lb_section_info.place(x=400, y=75)
		self.e_setion_info.place(x=570, y=80)
		self.bt_watch_sections.place(x=700, y=80)

	# L'Utilisateur appuie sur la croix rouge pour quitter
	def off(self):
		question = msg.askquestion("Wait...", "Do you want leave?")
		if question == "yes":
			self.destroy()
			self.section.destroy()
		else:
			pass

	# L'Utilisateur Presse le Bouton Explorateur de Fichier
	def file_explorer(self):
		global source
		source = filedialog.askopenfilename(title="Explorateur de Fichiers", initialdir="C://", filetypes=[("Application", "*.exe")])
		if len(source) > 0:
			self.e_file.config(state='normal')
			self.e_file.delete(0, 'end')
			self.e_file.insert(0, source)
			self.e_file.config(state='disabled')
			self.analyse()
		else:
			pass

	# L'Ananlyse Commence
	def analyse(self):
		global source, len_all_sections
		len_all_sections = 0
		pe = pefile.PE(str(source))
		# Valeur EntryPoint ( Hexa )
		self.e_entrypoint.config(state='normal')
		self.e_entrypoint.delete(0, 'end')
		self.e_entrypoint.insert(0, hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
		self.e_entrypoint.config(state='disabled')

		# Valeur ImageBase ( Hexa )
		self.e_imagebase.config(state='normal')
		self.e_imagebase.delete(0, 'end')
		self.e_imagebase.insert(0, hex(pe.OPTIONAL_HEADER.ImageBase))
		self.e_imagebase.config(state='disabled')

		# Nombre de Sections
		self.e_nb_sections.config(state='normal')
		self.e_nb_sections.delete(0, 'end')
		self.e_nb_sections.insert(0, "        {}".format(pe.FILE_HEADER.NumberOfSections))
		self.e_nb_sections.config(state='disabled')

		# Packer
		signatures = peutils.SignatureDatabase('Data/userdb.txt')
		matches = signatures.match(pe, ep_only = True)
		if matches == None:
			self.e_packer.config(state='normal')
			self.e_packer.delete(0, 'end')
			self.e_packer.insert(10, "	[-] Packer not found")
			self.e_packer.config(state='disabled')
		else:
			self.e_packer.config(state='normal')
			self.e_packer.delete(0, 'end')
			self.e_packer.insert(0, "")
			self.e_packer.config(state='disabled')
		
		# Len All Sections ( Hexa )
		for sec in pe.sections:
			len_all_sections += sec.SizeOfRawData
		self.e_setion_info.config(state='normal')
		self.e_setion_info.insert(0, hex(len_all_sections))
		self.e_setion_info.config(state='disabled')

	def __init__(self):
		# Init Tk()
		super().__init__()

		# Fenetre Principale
		self.geometry('800x320')
		self.config(bg='white')
		self.resizable(height=False, width=False)
		self.title('REsearch')
		self.protocol("WM_DELETE_WINDOW", self.off)

		# Creation Fenetre Section
		self.section = tk.Tk()
		self.section.geometry('800x500')
		self.section.config(bg='black')
		self.section.title('Section Viewer')
		self.section.resizable(height=False, width=False)
		self.section.protocol("WM_DELETE_WINDOW", self.section_del)
		self.section.withdraw()

		# Creation Label Informatif File
		self.lb_file = tk.Label(self, text='File  : ', bg='white', 
									fg='black', font=('verdata', 15))

		# Creation Bouton Explorateur de Fichier
		self.bt_file_explorer = tk.Button(self, command=self.file_explorer, text='...', 
												bg='white', fg='black', font=('verdata', 11))

		# Creation Entry Recevant l'Adresse du Fichier
		self.e_file = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
									state='disabled', disabledbackground='white', 
									disabledforeground='black')

		# Creation Label Informatif Adresse EntryPoint
		self.lb_entrypoint = tk.Label(self, text='EntryPoint  : ', bg='white', 
									fg='black', font=('verdata', 15))

		# Creation Entry Stockant l'Adresse de l'Entrypoint ( Hexa )
		self.e_entrypoint = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
									width=15, state='disabled', disabledbackground='white', 
									disabledforeground='black')

		# Creation Label Informatif ImageBase
		self.lb_imagebase = tk.Label(self, text='ImageBase  : ', bg='white', 
									fg='black', font=('verdata', 15))

		# Creation Entry Stockant la Valeur ImageBase ( Hexa )
		self.e_imagebase = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
									width=15, state='disabled', disabledbackground='white', 
									disabledforeground='black')

		# Creation Label Informatif Nombre de Sections
		self.lb_nb_sections = tk.Label(self, text='Number of Sections  : ', bg='white', 
									fg='black', font=('verdata', 15))

		# Creation Entry Stockant le Nombre de Sections
		self.e_nb_sections = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
									width=10, state='disabled', disabledbackground='white', 
									disabledforeground='black')

		# Creation Entry Stockant Packer
		self.e_packer = tk.Entry(self, bg='white', fg='black', font=('verdata', 20), 
									width=30, state='disabled', disabledbackground='white', 
									disabledforeground='black')

		# Creation Label Informatif Sections
		self.lb_section_info = tk.Label(self, text='Sections Info  : ', bg='white', 
									fg='black', font=('verdata', 15))
		
		# Creation Entry Stockant Toatl Sections ( Hexa )
		self.e_setion_info = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
									width=10, state='disabled', disabledbackground='white', 
									disabledforeground='black')
		
		# Creation Bouton Explorateur de Fichier
		self.bt_watch_sections = tk.Button(self, command=self.file_explorer, text='[*]', 
												bg='white', fg='black', font=('verdata', 11))
