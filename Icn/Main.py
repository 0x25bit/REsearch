# Project Python ICN
# Modified 28/04/2019
# Subject : Analyse Binaire
# By Paul Fouchard, Alexi Guerin


import tkinter as tk
import tkinter.messagebox as msg
import platform
from Data.Class import Root

len_all_sections = 0

if __name__ == '__main__':
    main = Root()
    if platform.system() == 'Windows':
        main.lancement_windows()
        main.mainloop()
    elif platform.system() == 'Linux':
        main.lancement_linux()
        main.mainloop()
    else:
        print("Votre systeme n'est pas compatible avec le programme.")