import nmap
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import csv
import threading
from tkinter.ttk import Progressbar

# Initialiser le scanner de ports Nmap
nm = nmap.PortScanner()

# Fonction pour effectuer un scan de ports
def effectuer_scan():
    cible = entry_cible.get()  # Obtenir la cible depuis l'entrée utilisateur
    plage_ports = entry_ports.get()  # Obtenir la plage de ports depuis l'entrée utilisateur
    detection_services = var_detection_services.get()  # Vérifier si la détection des services est activée
    detection_os = var_detection_os.get()  # Vérifier si la détection du système d'exploitation est activée
    
    # Effacer la fenêtre de résultats avant de commencer un nouveau scan
    text_resultats.delete(1.0, tk.END)

    if not cible or not plage_ports:
        messagebox.showerror("Erreur de saisie", "Veuillez entrer à la fois la cible et la plage de ports !")
        return

    # Définir les arguments Nmap en fonction des options
    arguments_nmap = '-sS'
    if detection_services:
        arguments_nmap += ' -sV'
    if detection_os:
        arguments_nmap += ' -O'
    
    # Fonction pour exécuter le scan dans un fil séparé
    def scan():
        try:
            btn_scan.config(state=tk.DISABLED)  # Désactiver le bouton de scan pendant l'exécution du scan
            progress_bar.start()
            
            resultats_scan = nm.scan(hosts=cible, ports=plage_ports, arguments=arguments_nmap)
            
            progress_bar.stop()
            btn_scan.config(state=tk.NORMAL)  # Réactiver le bouton de scan après le scan
            
            if cible in resultats_scan['scan']:
                donnees_hote = resultats_scan['scan'][cible]
                if 'tcp' in donnees_hote:
                    text_resultats.insert(tk.END, f"Résultats du scan pour {cible}:\n")
                    for port, details in donnees_hote['tcp'].items():
                        if details['state'] == 'open':
                            service = details.get('name', 'inconnu')
                            version = details.get('version', '')
                            produit = details.get('product', '')
                            text_resultats.insert(tk.END, f"Le port {port} est ouvert ({service}) {produit} {version}\n")
                else:
                    text_resultats.insert(tk.END, f"Aucun port TCP ouvert trouvé dans la plage {plage_ports}.\n")
                
                if 'osclass' in donnees_hote:
                    text_resultats.insert(tk.END, "\nDétails du système d'exploitation:\n")
                    for classe_os in donnees_hote['osclass']:
                        nom_os = classe_os.get('osfamily', 'inconnu')
                        fournisseur_os = classe_os.get('vendor', 'inconnu')
                        precision_os = classe_os.get('accuracy', 'inconnu')
                        text_resultats.insert(tk.END, f"OS : {nom_os} (Fournisseur : {fournisseur_os}, Précision : {precision_os}%)\n")
            else:
                text_resultats.insert(tk.END, f"Impossible de scanner la cible {cible}.\n")
        except Exception as e:
            progress_bar.stop()
            btn_scan.config(state=tk.NORMAL)  # Réactiver le bouton de scan en cas d'erreur
            text_resultats.insert(tk.END, f"Erreur lors du scan de la cible : {str(e)}\n")

    # Exécuter le scan dans un fil séparé pour éviter de bloquer l'interface graphique
    threading.Thread(target=scan).start()

# Fonction pour effacer les champs de saisie et les résultats
def effacer_resultats():
    entry_cible.delete(0, tk.END)
    entry_ports.delete(0, tk.END)
    text_resultats.delete(1.0, tk.END)

# Fonction pour enregistrer les résultats dans un fichier CSV
def enregistrer_resultats():
    resultats = text_resultats.get(1.0, tk.END).strip()
    if not resultats:
        messagebox.showerror("Pas de résultats", "Aucun résultat de scan à enregistrer !")
        return

    chemin_enregistrement = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("Fichiers CSV", "*.csv")])
    if chemin_enregistrement:
        with open(chemin_enregistrement, mode='w', newline='') as fichier:
            ecrivain = csv.writer(fichier)
            ecrivain.writerow(["Résultats du Scan"])
            ecrivain.writerow([resultats])
        messagebox.showinfo("Enregistré", f"Les résultats ont été enregistrés avec succès dans {chemin_enregistrement}")

# Créer la fenêtre principale
root = tk.Tk()
root.title("Scanner de Ports Avancé en Python")
root.geometry("600x500")

# Étiquette et champ de saisie pour l'IP/Domaine de la cible
label_cible = tk.Label(root, text="Cible IP/Domaine :")
label_cible.pack(pady=5)
entry_cible = tk.Entry(root, width=50)
entry_cible.pack(pady=5)

# Étiquette et champ de saisie pour la plage de ports
label_ports = tk.Label(root, text="Plage de Ports (ex: 1-1000) :")
label_ports.pack(pady=5)
entry_ports = tk.Entry(root, width=50)
entry_ports.pack(pady=5)

# Case à cocher pour la détection de services
var_detection_services = tk.IntVar()
chk_detection_services = tk.Checkbutton(root, text="Activer la détection des services (-sV)", variable=var_detection_services)
chk_detection_services.pack(pady=5)

# Case à cocher pour la détection du système d'exploitation
var_detection_os = tk.IntVar()
chk_detection_os = tk.Checkbutton(root, text="Activer la détection du système d'exploitation (-O)", variable=var_detection_os)
chk_detection_os.pack(pady=5)

# Bouton de scan
btn_scan = tk.Button(root, text="Démarrer le Scan", command=effectuer_scan)
btn_scan.pack(pady=10)

# Bouton d'effacement
btn_effacer = tk.Button(root, text="Effacer", command=effacer_resultats)
btn_effacer.pack(pady=5)

# Bouton pour enregistrer les résultats
btn_enregistrer = tk.Button(root, text="Enregistrer les Résultats", command=enregistrer_resultats)
btn_enregistrer.pack(pady=5)

# Zone de texte défilante pour les résultats
text_resultats = scrolledtext.ScrolledText(root, height=10, width=70)
text_resultats.pack(pady=10)

# Barre de progression pour le scan
progress_bar = Progressbar(root, orient=tk.HORIZONTAL, length=400, mode='indeterminate')
progress_bar.pack(pady=10)

# Exécuter la boucle de l'interface graphique
root.mainloop()
