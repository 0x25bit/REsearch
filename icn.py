"""
pe.OPTIONAL_HEADER.AddressOfEntryPoint
pe.OPTIONAL_HEADER.ImageBase
pe.FILE_HEADER.NumberOfSections
pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0xdeadbeef

for entry in pe.DIRECTORY_ENTRY_IMPORT:
  print entry.dll
  for imp in entry.imports:
    print '\t', hex(imp.address), imp.name

for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
  print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal

"""

import pefile
import peutils

def menu():
    print("1. Mofifier le binaire")
    print("2. Analyse statique")
    choix = input("(main) > ")
    return choix

def static():
    exe = input("Entrer le nom ou le chemin absolu du pe à analyser : ")
    pe = pefile.PE(str(exe))

    print("Number of sections : {} ".format(pe.FILE_HEADER.NumberOfSections))

    print("\n")

    for sec in pe.sections:
        sec.Name = str(sec.Name)
        sec.Name = sec.Name.replace("b'", "")
        sec.Name = sec.Name.replace("\\x00\\x00\\x00'", "")

        if sec.Name == ".reloc\\x00\\x00'":
            sec.Name = sec.Name.replace("\\x00\\x00'", "")

        sec.Name = sec.Name.replace("\\x00", "")




        print("{} at {} Size of raw_data (in {} section) : {}".format(str(sec.Name), hex(sec.VirtualAddress), str(sec.Name), hex(sec.SizeOfRawData)))

    print("\n")


    print("EntryPoint : {}".format(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)))
    print("ImageBase : {}".format(hex(pe.OPTIONAL_HEADER.ImageBase)))

    print("\n")
    print("Imports : ")
    print("\n")


    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(entry.dll)
        for imp in entry.imports:
                print('\t', hex(imp.address), imp.name)
    print("\n")
    print("Infos : ")
    print("\n")

    print(str(pe.dump_info))

    print("\n")


    signatures = peutils.SignatureDatabase('UserDB (1).TXT')

    matches = signatures.match(pe, ep_only = True)

def edit():
    print("1. Modifier l'EntryPoint")
    print("2. Injecter une nouvelle section")

    try :
        choix_edit = int(input("(Edit) > "))
    except :
        print("Entrez un choix correct !")
        edit()

    if choix_edit == 1:
        edit_entry()

def edit_entry():
    exe = input("Entrer le nom ou le chemin absolu du pe à modifier : ")
    try :
        pe = pefile.PE(str(exe))
    except :
        print("Erreur, spécifiez un fichier existant !")
        edit_entry()

    value = input("Entrez une nouvelle addresse pour l'AddressOfEntryPoint : ")

    try :
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = hex(value)

    except :
        print("Entrez un AddressOfEntryPoint valide !!")
        edit_entry()


    print("Etes vous sur de vouloir editer les modifications ? ")

    edit_choice = input("Y/N : ")

    if edit_choice == "Y":
        pe.write(filename=exe)
    else :
        edit_entry()

choix = menu()

if choix == '1':
    edit()
elif choix == '2':
    static()
