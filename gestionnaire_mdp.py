"""
Gestionnaire de mots de passe sécurisé avec interface graphique Tkinter.

Ce programme permet de :
- Générer des mots de passe aléatoires forts
- Stocker des mots de passe chiffrés dans un fichier
- Afficher, chercher, modifier et supprimer des mots de passe

Sécurité :
- Chiffrement Fernet avec clé stockée dans "clé secrète.key"
- Mots de passe validés (8-100 caractères)
- Données sauvegardées automatiquement après chaque modification

Structure :
- Fonctions globales pour la logique métier
- Classe Application_gestionnaire_mdp pour l'interface graphique
"""

import secrets
import string
import json
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import Listbox, messagebox, ttk


# ======================== VARIABLES GLOBALES IMPORTANTES ========================
# Ces variables sont accessibles dans tout le programme et servent à stocker les données

key_file = "clé secrète.key"
# Gestion de la clé de chiffrement Fernet
# - Si "clé secrète.key" n'existe pas : génère une clé aléatoire et la sauvegarde
# - Si elle existe : charge la clé existante (pour accéder aux données chiffrées)
try:
    clé = open(key_file, "rb").read()
except FileNotFoundError:
    clé = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(clé)
décryptage = Fernet(clé)  # Objet permettant de décrypter les données

# Chargement du répertoire des mots de passe depuis le fichier chiffré
# - Si le fichier existe : charge et déchiffre les données
# - Si absent ou erreur : initialise un dictionnaire vide
try:
    with open("stockage mdp.json", "rb") as f:
        encrypted_data = f.read()  # Lit le fichier chiffré
    decrypted_data = décryptage.decrypt(encrypted_data).decode()  # Déchiffre
    # Convertit en dictionnaire Python
    historique_mdp = json.loads(decrypted_data)
except (FileNotFoundError, json.JSONDecodeError, Exception):
    historique_mdp = {}  # Dictionnaire vide : {nom: mot_de_passe, ...}

# ======================== FONCTIONS GLOBALES ========================
# Ces fonctions sont appelées par différentes parties du programme


def generer_mdp(longueur):
    """Génère un mot de passe aléatoire de la longueur spécifiée.

    Args:
        longueur (int or str): La longueur souhaitée du mot de passe (doit être convertible en int).
    Returns:
        tuple: (mot_de_passe, succès) où mot_de_passe est str et succès est bool.
    """
    if type(longueur) is not int:
        if isinstance(longueur, str) and longueur.isdigit():
            longueur = int(longueur)
        else:
            return 'entrez des nombres entiers valides pour la longueur et le nombre de mots de passe.', False
    if longueur <= 0:
        return 'un mot de passe ne peut pas avoir une longueur négative ou nulle.', False
    if longueur > 100:
        return 'un mot de passe ne peut pas dépasser 100 caractères.', False
    if longueur < 8:
        return 'le mot de passe est trop court. Il doit contenir au moins 8 caractères.', False
    caracters = string.ascii_letters+string.digits+string.punctuation
    mdp = ''.join(secrets.choice(caracters) for j in range(longueur))
    return mdp, True


def verfier_mot_de_passe(mot_de_passe):
    """Vérifie si le mot de passe est à la norme (8 caractères minimum et 100 caractères maximum).

    Args:
        mot_de_passe (str): Le mot de passe à vérifier.
    Returns:
        bool: True si le mot de passe est à la norme, False sinon.
    """
    return (8 <= len(str(mot_de_passe)) <= 100)


def créer_un_mot_de_passe():
    while True:
        try:
            input_length = int(input(
                "Entrez la longueur du mot de passe (supérieure ou égale à 8 et inférieure ou égale à 100): "))
            break

        except ValueError:
            print("Entrée invalide. Veuillez entrer des nombres entiers pour la longueur et le nombre de mots de passe.")
    return (generer_mdp(input_length))


def sauvegarder_mot_de_passe(nom, mot_de_passe, historique):
    """Sauvegarde le mot de passe dans le répertoire des mots de passe.
    Args:
        mot_de_passe (str): Le mot de passe à sauvegarder.
        historique (dict): Le dictionnaire contenant le répertoire des mots de passe.
    """
    historique[nom] = mot_de_passe
    return historique


def chercher_mot_de_passe(nom, historique):
    """Cherche un mot de passe dans le répertoire des mots de passe.
    Args:
        nom (str): Le nom du mot de passe à chercher.
        historique (dict): Le dictionnaire contenant le répertoire des mots de passe.
    Returns:
        str: Le mot de passe correspondant au nom donné, ou un message d'erreur si non trouvé.
    """
    if nom in historique:
        return historique[nom]
    else:
        return f"Aucun mot de passe trouvé sous le nom '{nom}'."


class Application_gestionnaire_mdp:
    """Gestionnaire de mots de passe avec interface Tkinter.

    Cette classe gère l'interface graphique complète du programme :
    - Menu principal avec options
    - Génération et validation de mots de passe
    - Stockage chiffré des données
    - Recherche, modification et suppression

    Attributs :
    - root : Fenêtre principale Tkinter
    - mdp_actuel : Mot de passe en cours de traitement
    - nom : Nom du mot de passe en cours de modification/suppression
    - menu_* : Frames pour chaque interface
    """

    def __init__(self):
        """Initialise l'application Tkinter avec les 3 menus.

        - Crée la fenêtre principale (tk.Tk)
        - Construit les 3 frames (interfaces)
        - Lance la boucle d'événements mainloop()
        """
        self.root = tk.Tk()  # Crée la fenêtre principale
        self.root.title("Gestionnaire de mots de passe")
        self.root.geometry("800x500")

        # Variable pour stocker le mot de passe en cours de traitement
        # Elle permet de passer le mdp entre le menu_mdp et le menu_gestion
        self.mdp_actuel = None
        self.nom = None

        # Crée les 3 interfaces (frames) - importants : les créer dans __init__
        # sinon on ne peut pas les référencer dans changer_menu()
        self.creer_menu_principale()
        self.creer_menu_mdp()
        self.creer_menu_gestion()
        self.creer_menu_recherche()
        # menu_repertoire est créé à la demande pour être à jour
        # Lance la boucle d'événements (permet à Tkinter de fonctionner)
        self.root.mainloop()

    def changer_menu(self, frame):
        """Change le frame affiché à l'écran.

        IMPORTANT : Cette méthode est le cœur de la navigation entre les 3 interfaces.
        Elle masque (pack_forget) tous les frames existants et affiche (pack) celui passé en paramètre.

        Args:
            frame : Le frame (interface) à afficher. Ex: self.menu_principale, self.menu_mdp, etc.

        Fonctionnement :
        1. hasattr() vérifie si l'attribut existe (pour éviter les erreurs)
        2. pack_forget() cache le frame (le retire de l'affichage)
        3. frame.pack() affiche le nouveau frame avec fill="both" (remplit toute la fenêtre)
        """
        # Cache le menu principal s'il existe
        if hasattr(self, 'menu_principale'):
            self.menu_principale.pack_forget()

        # Cache le menu de génération s'il existe
        if hasattr(self, 'menu_mdp'):
            self.menu_mdp.pack_forget()

        # Cache le menu de gestion s'il existe
        if hasattr(self, 'menu_gestion'):
            self.menu_gestion.pack_forget()

        # note: attribute name must match exactly the one set in creer_menu_repertoire
        if hasattr(self, 'menu_repertoire'):
            self.menu_repertoire.pack_forget()

        if hasattr(self, 'menu_recherche'):
            self.menu_recherche.pack_forget()

        if hasattr(self, "menu_modif_mdp"):
            self.menu_modif_mdp.pack_forget()

        # Affiche le frame demandé (remplit toute la fenêtre)
        frame.pack(fill="both", expand=True)

    def enregistrer(self):
        """Sauvegarde le répertoire des mots de passe dans le fichier chiffré.

        Convertit historique_mdp en JSON, le chiffre avec Fernet, et écrit dans 'stockage mdp.json'.
        Appelée automatiquement après chaque modification pour persister les données.
        """
        data_str = json.dumps(historique_mdp)
        encrypted_data = décryptage.encrypt(data_str.encode())
        with open("stockage mdp.json", "wb") as f:
            f.write(encrypted_data)

    def creer_menu_principale(self):
        """Crée et configure le menu principal.

        Ce menu affiche une liste des actions possibles :
        - Ajouter un mot de passe
        - Afficher le répertoire
        - Chercher un mot de passe
        - Modifier un mot de passe
        - Supprimer un mot de passe
        - Quitter

        IMPORTANT : Les boutons pour les autres options (2-6) ont des commentaires TODO
        car leurs fonctionnalités ne sont pas encore implémentées.
        """

        def choix_choisi():
            """Fonction appelée quand l'utilisateur clique sur 'Valider'.

            Elle récupère le choix sélectionné dans la liste et navigue vers l'interface appropriée.
            """
            # Vérifie qu'une option est sélectionnée (curselection() retourne un tuple vide si rien)
            if liste_choix.curselection():
                # Récupère le texte de l'option sélectionnée
                selection = liste_choix.get('active')

                # Si l'utilisateur a choisi "Ajouter un mot de passe"
                if selection == "Ajouter un mot de passe":
                    # Change pour afficher le menu de génération/entrée de mot de passe
                    self.changer_menu(self.menu_mdp)
                elif selection == "Afficher le répertoire des mots de passe":
                    # Recréer le menu pour refléter les changements
                    self.creer_menu_repertoire()
                    self.changer_menu(self.menu_repertoire)
                elif selection == "Chercher, modifier, ou supprimer un mot de passe dans le répertoire":
                    self.changer_menu(self.menu_recherche)
                elif selection == "Quitter":
                    self.enregistrer()
                    messagebox.showinfo(message="Au revoir !")
                    self.menu_principale.destroy()
                    quit()

                # TODO: add handlers for the other choices later
            else:
                # Affiche une alerte si rien n'est sélectionné
                messagebox.showwarning(
                    "Avertissement", "Veuillez choisir un élément dans la liste.")

        # Crée un nouveau frame (conteneur) pour ce menu
        self.menu_principale = tk.Frame(self.root)

        # Ajoute le titre du menu
        tk.Label(
            self.menu_principale, text="Bienvenue dans le gestionnaire de mots de passe!").pack(pady=10)

        # Ajoute une sous-question
        sous_titre = tk.Label(self.menu_principale,
                              text="que souhaitez-vous faire?").pack(pady=5)

        # Crée une Listbox (liste sélectionnable) contenant les options
        liste_choix = Listbox(self.menu_principale)
        liste_choix.insert(1, "Ajouter un mot de passe")
        liste_choix.insert(2, "Afficher le répertoire des mots de passe")
        liste_choix.insert(
            3, "Chercher, modifier, ou supprimer un mot de passe dans le répertoire")
        liste_choix.insert(4, "Quitter")
        liste_choix.pack(ipadx=200)  # ipadx ajoute du padding horizontal

        # Bouton pour valider le choix
        tk.Button(
            self.menu_principale, text="Valider", command=lambda: choix_choisi()).pack()

        # Affiche ce menu principal au démarrage
        self.menu_principale.pack(fill="both", expand=True)

    def creer_menu_mdp(self):
        """Crée le menu de génération/entrée de mot de passe.

        Ce menu offre 2 options :
        1. Générer automatiquement un mot de passe (entrée : longueur)
        2. Entrer manuellement un mot de passe

        Les mots de passe générés ou entrés passent par une vérification avant d'aller au menu de gestion.
        """
        # Crée le frame pour ce menu
        self.menu_mdp = tk.Frame(self.root)

        def generer_click():
            """Fonction appelée au clic sur le bouton 'Générer'.

            1. Récupère la longueur entrée par l'utilisateur
            2. Appelle generer_mdp() (fonction globale) pour générer le mot de passe
            3. Passe le résultat à eligibilite_mdp() pour vérification
            """
            resultat = generer_mdp(longueur.get())
            eligibilite_mdp(resultat[0], resultat[1])

        def eligibilite_mdp(mdp: str, mdp_réalisé):
            """Vérifie si le mot de passe est valide.

            Args:
                mdp (str): Le mot de passe à vérifier
                mdp_réalisé (bool): Indique si la génération a réussi

            Processus :
            - Si génération réussi ET mot de passe valide
              -> Stocke le mdp dans self.mdp_actuel
              -> Affiche le mot de passe dans le menu_gestion
              -> Navigue vers le menu_gestion
            - Sinon -> Affiche un message d'erreur
            """
            if mdp_réalisé:
                # Vérifie que le mdp a au moins 8 caractères
                if verfier_mot_de_passe(mdp):
                    # Stocke le mot de passe dans l'instance pour l'utiliser dans menu_gestion
                    self.mdp_actuel = mdp
                    # Affiche le mot de passe dans le label du menu_gestion
                    self.actualiser_menu_gestion()
                    # Change l'affichage pour montrer le menu_gestion
                    self.changer_menu(self.menu_gestion)
                else:
                    messagebox.showwarning(
                        "Attention", "Le mot de passe n'est pas valide")

            else:
                messagebox.showwarning(
                    "Avertissement", "L'entrée n'est pas valide")

        # ===== SECTION 1 : Génération automatique =====
        tk.Label(
            self.menu_mdp, text="Générer un mot de passe\n Indiquez la longueur (min 8, max 100)").pack(pady=10)
        longueur = tk.StringVar()  # Variable pour stocker l'entrée utilisateur
        tk.Entry(
            self.menu_mdp, width=30, textvariable=longueur).pack()
        tk.Button(
            self.menu_mdp, text="Générer",
            command=lambda: generer_click()  # lambda nécessaire pour appeler une fonction
        ).pack(pady=5)

        # ===== SECTION 2 : Entrée manuelle =====
        tk.Label(self.menu_mdp, text="Ou\nEntrez un mot de passe").pack(pady=10)
        mdp = tk.StringVar()  # Variable pour stocker le mot de passe manuel
        tk.Entry(self.menu_mdp, textvariable=mdp).pack()
        tk.Button(
            self.menu_mdp, text="confirmer",
            # mdp.get() récupère la valeur
            command=lambda: eligibilite_mdp(mdp.get().strip(), True)
        ).pack(pady=5)

    def creer_menu_gestion(self):
        """Crée le menu de gestion/enregistrement du mot de passe.

        Ce menu s'affiche APRÈS que l'utilisateur ait généré ou validé un mot de passe.
        Il permet d'enregistrer le mot de passe sous un nom pour le répertoire.

        IMPORTANT : 
        - self.mdp_actuel contient le mot de passe en attente
        - self.nom_mdp_var sauvegarde le nom entré par l'utilisateur
        """
        # Crée le frame pour ce menu
        self.menu_gestion = tk.Frame(self.root)

        # ===== Label pour afficher le mot de passe généré =====
        # Ce label sera mis à jour par actualiser_menu_gestion()
        self.label_mdp_affiche = tk.Label(
            self.menu_gestion, text="", font=("Arial", 10))
        self.label_mdp_affiche.pack(pady=10)

        # ===== Entrée du nom du mot de passe =====
        tk.Label(self.menu_gestion,
                 text="Entrez un nom pour ce mot de passe:").pack(pady=5)
        self.nom_mdp_var = tk.StringVar()  # Stocke le nom entré
        tk.Entry(self.menu_gestion, textvariable=self.nom_mdp_var).pack()

        def enregistrer():
            """Fonction appelée au clic sur 'Enregistrer'.

            Processus :
            1. Récupère le nom entré (avec .strip() pour enlever les espaces)
            2. Vérifie que le nom n'est pas vide
            3. Sauvegarde (nom, mot_de_passe) dans l'historique_mdp global
            4. Affiche un message de succès
            5. Réinitialise le formulaire
            6. Retourne au menu principal
            """
            global historique_mdp
            nom = self.nom_mdp_var.get().strip()  # .strip() enlève les espaces avant/après
            if not nom:
                # Affiche un avertissement si le nom est vide
                messagebox.showwarning("Attention", "Veuillez entrer un nom.")
                return

            # Ajoute le mot de passe à l'historique (voir fonction sauvegarder_mot_de_passe)
            sauvegarder_mot_de_passe(nom, self.mdp_actuel, historique_mdp)
            self.enregistrer()

            # Affiche un message de confirmation
            messagebox.showinfo(
                "Succès", f"Mot de passe '{nom}' enregistré avec succès!")

            # Réinitialise le champ de texte
            self.nom_mdp_var.set("")

            # Retourne au menu principal
            self.changer_menu(self.menu_principale)

        # ===== Boutons d'action =====
        tk.Button(self.menu_gestion, text="Enregistrer",
                  command=enregistrer).pack(pady=5)
        tk.Button(self.menu_gestion, text="Retour",
                  command=lambda: self.changer_menu(self.menu_mdp)).pack(pady=5)

    def actualiser_menu_gestion(self):
        """Actualise l'affichage du mot de passe généré.

        Cette méthode est appelée avant de passer au menu_gestion.
        Elle met à jour le label_mdp_affiche avec le mot de passe stocké dans self.mdp_actuel.

        IMPORTANT : Cette séparation entre actualiser_menu_gestion() et changer_menu()
        permet de préparer le menu AVANT de l'afficher.
        """
        # Utilise .config() pour modifier le texte d'un label APRÈS sa création
        # (plus efficace que de recréer le label à chaque fois)
        self.label_mdp_affiche.config(
            text=f"Mot de passe :\n{self.mdp_actuel}")

    def creer_menu_repertoire(self):
        """Crée et affiche le menu du répertoire des mots de passe.

        Ce menu affiche tous les mots de passe stockés dans un Treeview.
        Il est recréé à chaque accès pour refléter les modifications récentes.
        """
        if hasattr(self, 'menu_repertoire'):
            self.menu_repertoire.destroy()

        global historique_mdp
        self.menu_repertoire = tk.Frame(self.root)
        tk.Label(self.menu_repertoire,
                 text="Historique des mots de passe").pack(pady=5)

        # Treeview enfant du frame (pas de self.root)
        liste_mdp = ttk.Treeview(self.menu_repertoire, columns=(
            "Nom", "Mot de passe"), show="headings")
        liste_mdp.heading("Nom", text="Nom")
        liste_mdp.heading("Mot de passe", text="Mot de passe")
        liste_mdp.pack(fill="both", expand=True, padx=5, pady=5)

        # Parcours correct du dictionnaire
        for nom, mdp in historique_mdp.items():
            # Affiche le mot de passe en clair dans le Treeview
            liste_mdp.insert("", "end", values=(nom, mdp))

        tk.Button(self.menu_repertoire, text="Retour", command=lambda: self.changer_menu(
            self.menu_principale)).pack(pady=5)

    def creer_menu_recherche(self):
        """Crée le menu de recherche, modification et suppression de mots de passe.

        Permet de chercher un mot de passe par nom, et propose des options pour le modifier ou le supprimer.
        """

        self.menu_recherche = tk.Frame(self.root)

        def verif_présence_nom_mdp(nom):
            global historique_mdp
            if nom in historique_mdp:
                messagebox.showinfo(
                    message=f"Le mot de passe de {nom} est {historique_mdp[nom]}")
                return True
            else:
                messagebox.showinfo(
                    message="Aucun mot de passe n'est enregistré sous ce nom")
                return False

        def modif_mdp(nom):
            if nom in historique_mdp:
                self.nom = nom
                self.creer_menu_modif_mdp()
                self.changer_menu(self.menu_modif_mdp)

            else:
                messagebox.showinfo(message="nom invalide")

        def supp_mdp(nom):
            if nom in historique_mdp:
                self.nom = nom
                del historique_mdp[self.nom]
                self.enregistrer()  # Sauvegarde après suppression
                messagebox.showinfo(message="mot de passe supprimé")
                self.changer_menu(self.menu_principale)
            else:
                messagebox.showerror(message="mot de passe invalide")

        tk.Label(self.menu_recherche,
                 text="entrer le nom du mot de passe recherché").pack()
        mdp_cherche = tk.StringVar()
        tk.Entry(self.menu_recherche, textvariable=mdp_cherche).pack(
            anchor="center")
        tk.Button(self.menu_recherche, text="chercher",
                  command=lambda: verif_présence_nom_mdp(mdp_cherche.get().strip())).pack()
        tk.Button(self.menu_recherche, text="modifier",
                  command=lambda: modif_mdp(mdp_cherche.get().strip())).pack()
        tk.Button(self.menu_recherche, text="supprimer",
                  command=lambda: supp_mdp(mdp_cherche.get().strip())).pack()
        tk.Button(self.menu_recherche, text="retour",
                  command=lambda: self.changer_menu(self.menu_principale)).pack()

    def creer_menu_modif_mdp(self):
        """Crée le menu de modification d'un mot de passe existant.

        Permet d'entrer un nouveau mot de passe pour remplacer l'ancien.
        """

        def modification_mdp(nouv_mdp):
            if verfier_mot_de_passe(nouv_mdp):
                global historique_mdp
                historique_mdp[self.nom] = nouv_mdp
                self.enregistrer()  # Sauvegarde après modification
                messagebox.showinfo(
                    message="mot de passe enregistré avec succès")
                self.changer_menu(self.menu_principale)
            else:
                messagebox.showinfo(message="mot de passe invalide")

        self.menu_modif_mdp = tk.Frame(self.root)
        tk.Label(self.menu_modif_mdp,
                 text=f"entrez le nouveau mdp pour {self.nom} \n longueur min 8 max 100").pack()
        nouv_mdp = tk.StringVar()
        tk.Entry(self.menu_modif_mdp, textvariable=nouv_mdp).pack()
        tk.Button(self.menu_modif_mdp, text="enregistrer",
                  command=lambda: modification_mdp(nouv_mdp.get().strip())).pack()


# ======================== LANCEMENT DE L'APPLICATION ========================
"""
Instanciation de la classe principale pour démarrer l'application.
Cela crée la fenêtre Tkinter et lance la boucle d'événements.
"""

Application_gestionnaire_mdp()
