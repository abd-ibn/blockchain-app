import os
from web3 import Web3
from datetime import datetime
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser
import json

# Infura
INFURA_URL = "https://sepolia.infura.io/v3/<yours>"
PINATA_API_KEY = "<yours>"
PINATA_API_SECRET = "<yours>"

web3 = Web3(Web3.HTTPProvider(INFURA_URL))

# Contract addresses and ABIs
CONTRACT_PATIENT_ADDRESS = "0x9a459AB557d0691170cce2dC52729B801FB3aaE9"
CONTRACT_DOCTOR_ADDRESS = "0xF56C4E528EB09a1b857bB8eD4926440e0d4fA0fC"
CONTRACT_AUDIT_ADDRESS = "0xa42f15b7BbADd27707AAD55273bD97379f885b2f"

# Load ABIs
dir_path = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(dir_path, 'ContractPatientABI.json')) as f:
    CONTRACT_PATIENT_ABI = json.load(f)
with open(os.path.join(dir_path, 'ContractDoctorABI.json')) as f:
    CONTRACT_DOCTOR_ABI = json.load(f)
with open(os.path.join(dir_path, 'ContractAuditABI.json')) as f:
    CONTRACT_AUDIT_ABI = json.load(f)

# Instantiate contracts
contract_patient = web3.eth.contract(address=CONTRACT_PATIENT_ADDRESS, abi=CONTRACT_PATIENT_ABI)
contract_doctor = web3.eth.contract(address=CONTRACT_DOCTOR_ADDRESS, abi=CONTRACT_DOCTOR_ABI)
contract_audit = web3.eth.contract(address=CONTRACT_AUDIT_ADDRESS, abi=CONTRACT_AUDIT_ABI)

# ---------------------------------------------------------------------------------------------------------

class PatientApp:
    def __init__(self, parent):
        self.frame = tk.Frame(parent)
        self.frame.pack(fill="both", expand=True)

        self.private_key = None

        self.main_frame = tk.Frame(self.frame)
        self.main_frame.pack(fill="both", expand=True)

        self.eth_address_label = None
        self.name_label = None
        self.dob_label = None
        self.gender_label = None
        self.address_label = None
        self.phone_label = None
        self.email_label = None
        self.filehash_label = None

        self.create_login_interface()
        self.create_dashboard_interface()
        self.create_registration_interface()

        self.show_frame(self.login_frame)

    def show_frame(self, frame):
        frame.tkraise()

    def create_login_interface(self):
        """Create the login interface."""
        self.login_frame = tk.Frame(self.main_frame, bg="white", padx=0, pady=0)
        self.login_frame.grid(row=0, column=0, sticky="nsew")

        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        top_bar = tk.Frame(self.login_frame, bg="#404040", height=50)
        top_bar.grid(row=0, column=0, columnspan=2, sticky="nsew")
        tk.Label(top_bar, text="Patient Login", bg="#404040", fg="white", font=("Arial", 18, "bold"))\
            .pack(pady=10)

        content_frame = tk.Frame(self.login_frame, bg="white", padx=20, pady=20)
        content_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=20, pady=10)

        self.login_frame.grid_rowconfigure(1, weight=1)
        self.login_frame.grid_columnconfigure(0, weight=1)
        self.login_frame.grid_columnconfigure(1, weight=1)

        tk.Label(content_frame, text="Ethereum Address:", font=("Arial", 12, "bold"), bg="white")\
            .grid(row=0, column=0, padx=10, pady=10)
        self.eth_address_entry = tk.Entry(content_frame, width=40, font=("Arial", 12), bg="white")
        self.eth_address_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(content_frame, text="Private Key:", font=("Arial", 12, "bold"), bg="white")\
            .grid(row=1, column=0, padx=10, pady=10)
        self.private_key_entry = tk.Entry(content_frame, width=40, show="*", font=("Arial", 12), bg="white")
        self.private_key_entry.grid(row=1, column=1, padx=10, pady=10)

        button_style = {
            "font": ("Arial", 12, "bold"),
            "bg": "#404040",
            "fg": "white",
            "activebackground": "#404040",
            "activeforeground": "white",
            "relief": tk.RAISED,
            "bd": 2,
            "width": 15
        }
        login_button = tk.Button(content_frame, text="Login", command=self.handle_action, **button_style)
        login_button.grid(row=2, column=0, columnspan=2, pady=20)

        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)

    def create_dashboard_interface(self):
        """Créer l'interface du tableau de bord."""
        self.dashboard_frame = tk.Frame(self.main_frame)
        self.dashboard_frame.grid(row=0, column=0, sticky="nsew")

        self.dashboard_frame.grid_rowconfigure(0, weight=1)
        self.dashboard_frame.grid_rowconfigure(1, weight=1)
        self.dashboard_frame.grid_columnconfigure(0, weight=1)
        self.dashboard_frame.grid_columnconfigure(1, weight=2)
        self.dashboard_frame.grid_columnconfigure(2, weight=1)

        self.top_bar = tk.Frame(self.dashboard_frame, bg="#404040", height=50)
        self.top_bar.grid(row=0, column=0, columnspan=3, sticky="nsew")

        tk.Label(self.top_bar, text="Tableau de Bord", font=("Arial", 18, "bold"), bg="#404040", fg="white").pack(pady=10)

        tk.Label(self.dashboard_frame, text="Informations du patient :", font=("Arial", 16, "bold")).grid(
            row=1, column=0, columnspan=2, pady=(10, 20)
        )

        tk.Label(self.dashboard_frame, text="Adresse Ethereum :").grid(row=2, column=0, padx=20, pady=5, sticky="e")
        self.eth_address_label = tk.Label(self.dashboard_frame, text="")
        self.eth_address_label.grid(row=2, column=1, padx=20, pady=5, sticky="w")

        tk.Label(self.dashboard_frame, text="Nom Complet :").grid(row=3, column=0, padx=20, pady=5, sticky="e")
        self.name_label = tk.Label(self.dashboard_frame, text="")
        self.name_label.grid(row=3, column=1, padx=20, pady=5, sticky="w")

        tk.Label(self.dashboard_frame, text="Date de Naissance :").grid(row=4, column=0, padx=20, pady=5, sticky="e")
        self.dob_label = tk.Label(self.dashboard_frame, text="")
        self.dob_label.grid(row=4, column=1, padx=20, pady=5, sticky="w")

        tk.Label(self.dashboard_frame, text="Gender :").grid(row=5, column=0, padx=20, pady=5, sticky="e")
        self.gender_label = tk.Label(self.dashboard_frame, text="")
        self.gender_label.grid(row=5, column=1, padx=20, pady=5, sticky="w")

        tk.Label(self.dashboard_frame, text="Adresse :").grid(row=6, column=0, padx=20, pady=5, sticky="e")
        self.address_label = tk.Label(self.dashboard_frame, text="")
        self.address_label.grid(row=6, column=1, padx=20, pady=5, sticky="w")

        tk.Label(self.dashboard_frame, text="Telephone :").grid(row=7, column=0, padx=20, pady=5, sticky="e")
        self.phone_label = tk.Label(self.dashboard_frame, text="")
        self.phone_label.grid(row=7, column=1, padx=20, pady=5, sticky="w")

        tk.Label(self.dashboard_frame, text="Email :").grid(row=8, column=0, padx=20, pady=5, sticky="e")
        self.email_label = tk.Label(self.dashboard_frame, text="")
        self.email_label.grid(row=8, column=1, padx=20, pady=5, sticky="w")

        tk.Label(self.dashboard_frame, text="Medical Record Hash :").grid(row=9, column=0, padx=20, pady=5, sticky="e")
        self.filehash_label = tk.Label(self.dashboard_frame, text="")
        self.filehash_label.grid(row=9, column=1, padx=20, pady=5, sticky="w")

        tk.Label(self.dashboard_frame, text="Gestion des accès :", font=("Arial", 16, "bold")).grid(
            row=12, column=0, columnspan=2, pady=(10, 20)
        )

        tk.Label(self.dashboard_frame, text="Adresse du Médecin :").grid(row=13, column=0, padx=20, pady=5, sticky="e")
        self.doctor_address_entry = tk.Entry(self.dashboard_frame, width=40)
        self.doctor_address_entry.grid(row=13, column=1, padx=20, pady=5, sticky="w")

        button_style = {
            "font": ("Arial", 12, "bold"),
            "bg": "#404040",
            "fg": "white",
            "activebackground": "#404040",
            "activeforeground": "white",
            "relief": tk.RAISED,
            "bd": 2,
            "width": 15
        }
        
        tk.Button(self.dashboard_frame, text="Donner accès", command=self.grant_access, **button_style).grid(
            row=14, column=0, padx=20, pady=5, sticky="e"
        )
        tk.Button(self.dashboard_frame, text="Révoquer accès", command=self.revoke_access, **button_style).grid(
            row=14, column=1, padx=20, pady=5, sticky="w"
        )
        tk.Button(self.dashboard_frame, text="Vérifier accès", command=self.check_access, **button_style).grid(
            row=15, column=0, columnspan=2, pady=10
        )

        self.access_output = tk.Label(self.dashboard_frame, text="", fg="blue", wraplength=400, justify="left")
        self.access_output.grid(row=16, column=0, columnspan=2, pady=(10, 20))

        tk.Label(self.dashboard_frame, text="Historique des actions :", font=("Arial", 16, "bold")).grid(
            row=1, column=2, columnspan=2, pady=(10, 20)
        )

        self.log_text = tk.Text(self.dashboard_frame, width=65, height=30, state="disabled")
        self.log_text.grid(row=2, column=2, columnspan=2, rowspan=13, padx=20, pady=(5, 20))

        tk.Button(self.dashboard_frame, text="Rafraîchir les Logs", command=self.load_logs, **button_style).grid(
            row=15, column=2, columnspan=2, pady=(20, 10)
        )

        tk.Button(self.dashboard_frame, text="Déconnexion", command=self.handle_logout, **button_style).grid(
            row=10, column=0, columnspan=2, pady=(20, 10)
        )

    def load_logs(self):
        """Charger et afficher les logs d'audit pour cet utilisateur."""
        self.log_text.config(state="normal")
        self.log_text.delete(1.0, tk.END)

        try:
            eth_address = self.eth_address_entry.get().strip()

            logs = contract_audit.functions.getPatientAuditTrail(eth_address).call()

            if logs:
                for log in logs:
                    doctor_address = log[0]
                    patient_address = log[1]
                    action = log[2]
                    file_hash = log[3]
                    timestamp = log[4]

                    readable_time = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                    log_entry = (
                        f"Docteur: {doctor_address}\n"
                        f"Patient: {patient_address}\n"
                        f"Action: {action}\n"
                        f"Hash du Fichier: {file_hash if file_hash else 'Non applicable'}\n"
                        f"Date : {readable_time}\n"
                        f"{'-'*50}\n"
                    )
                    self.log_text.insert(tk.END, log_entry)
            else:
                self.log_text.insert(tk.END, "Aucun log trouvé pour cet utilisateur.")
        except Exception as e:
            self.log_text.insert(tk.END, f"Erreur lors de la récupération des logs : {str(e)}")

        self.log_text.config(state="disabled")

    def grant_access(self):
        """Grant access to a doctor."""
        doctor_address = self.doctor_address_entry.get().strip()
        if not Web3.isAddress(doctor_address):
            self.access_output.config(text="Adresse Ethereum invalide.", fg="red")
            return

        if not self.private_key:
            self.access_output.config(text="Clé privée non définie.", fg="red")
            return

        try:
            # Construct the transaction
            transaction = contract_doctor.functions.grantPermission(doctor_address).buildTransaction({
                "from": self.eth_address_entry.get().strip(),
                "gas": 3000000,
                "nonce": web3.eth.getTransactionCount(self.eth_address_entry.get().strip())
            })

            # Sign the transaction with the private key
            signed_txn = web3.eth.account.signTransaction(transaction, private_key=self.private_key)

            # Send the signed transaction
            tx_hash = web3.eth.sendRawTransaction(signed_txn.rawTransaction)

            # Wait for the transaction to be mined
            web3.eth.waitForTransactionReceipt(tx_hash)
            self.access_output.config(text="Accès donné avec succès.", fg="green")
        except Exception as e:
            self.access_output.config(text=f"Erreur lors de l'attribution d'accès : {str(e)}", fg="red")

    def revoke_access(self):
        """Revoke access from a doctor."""
        doctor_address = self.doctor_address_entry.get().strip()
        if not Web3.isAddress(doctor_address):
            self.access_output.config(text="Adresse Ethereum invalide.", fg="red")
            return

        if not self.private_key:
            self.access_output.config(text="Clé privée non définie.", fg="red")
            return

        try:
            # Construct the transaction
            transaction = contract_doctor.functions.revokePermission(doctor_address).buildTransaction({
                "from": self.eth_address_entry.get().strip(),
                "gas": 3000000,
                "nonce": web3.eth.getTransactionCount(self.eth_address_entry.get().strip())
            })

            # Sign the transaction with the private key
            signed_txn = web3.eth.account.signTransaction(transaction, private_key=self.private_key)

            # Send the signed transaction
            tx_hash = web3.eth.sendRawTransaction(signed_txn.rawTransaction)

            # Wait for the transaction to be mined
            web3.eth.waitForTransactionReceipt(tx_hash)
            self.access_output.config(text="Accès révoqué avec succès.", fg="green")
        except Exception as e:
            self.access_output.config(text=f"Erreur lors de la révocation d'accès : {str(e)}", fg="red")

    def check_access(self):
        """Check if a doctor has access."""
        doctor_address = self.doctor_address_entry.get().strip()
        if not Web3.isAddress(doctor_address):
            self.access_output.config(text="Adresse Ethereum invalide.", fg="red")
            return

        try:
            has_access = contract_doctor.functions.checkAccess(self.eth_address_entry.get().strip()).call({
                "from": doctor_address
            })
            if has_access:
                self.access_output.config(text="Le médecin a accès aux dossiers.", fg="green")
            else:
                self.access_output.config(text="Le médecin n'a pas accès aux dossiers.", fg="blue")
        except Exception as e:
            self.access_output.config(text=f"Erreur lors de la vérification d'accès : {str(e)}", fg="red")

    def create_registration_interface(self):
        """Créer l'interface d'enregistrement."""
        self.registration_frame = tk.Frame(self.main_frame, bg="white", padx=0, pady=0)
        self.registration_frame.grid(row=0, column=0, sticky="nsew")

        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        top_bar = tk.Frame(self.registration_frame, bg="#404040", height=50)
        top_bar.grid(row=0, column=0, columnspan=2, sticky="nsew")
        tk.Label(top_bar, text="Patient Registration", bg="#404040", fg="white", font=("Arial", 18, "bold"))\
            .pack(pady=10)

        content_frame = tk.Frame(self.registration_frame, bg="white", padx=20, pady=20)
        content_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=20, pady=10)

        self.registration_frame.grid_rowconfigure(1, weight=1)
        self.registration_frame.grid_columnconfigure(0, weight=1)
        self.registration_frame.grid_columnconfigure(1, weight=1)

        tk.Label(content_frame, text="Nom:", font=("Arial", 12, "bold"), bg="white")\
            .grid(row=0, column=0, padx=10, pady=10)
        self.reg_name_entry = tk.Entry(content_frame, width=40, font=("Arial", 12), bg="white")
        self.reg_name_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(content_frame, text="Date de Naissance:", font=("Arial", 12, "bold"), bg="white")\
            .grid(row=1, column=0, padx=10, pady=10)
        self.reg_dob_entry = tk.Entry(content_frame, width=40, font=("Arial", 12), bg="white")
        self.reg_dob_entry.grid(row=1, column=1, padx=10, pady=10)

        tk.Label(content_frame, text="Gender:", font=("Arial", 12, "bold"), bg="white")\
            .grid(row=2, column=0, padx=10, pady=10)
        self.reg_gender_entry = tk.Entry(content_frame, width=40, font=("Arial", 12), bg="white")
        self.reg_gender_entry.grid(row=2, column=1, padx=10, pady=10)

        tk.Label(content_frame, text="Adresse Residentielle:", font=("Arial", 12, "bold"), bg="white")\
            .grid(row=3, column=0, padx=10, pady=10)
        self.reg_address_entry = tk.Entry(content_frame, width=40, font=("Arial", 12), bg="white")
        self.reg_address_entry.grid(row=3, column=1, padx=10, pady=10)

        tk.Label(content_frame, text="Telephone:", font=("Arial", 12, "bold"), bg="white")\
            .grid(row=4, column=0, padx=10, pady=10)
        self.reg_phone_entry = tk.Entry(content_frame, width=40, font=("Arial", 12), bg="white")
        self.reg_phone_entry.grid(row=4, column=1, padx=10, pady=10)

        tk.Label(content_frame, text="Email:", font=("Arial", 12, "bold"), bg="white")\
            .grid(row=5, column=0, padx=10, pady=10)
        self.reg_email_entry = tk.Entry(content_frame, width=40, font=("Arial", 12), bg="white")
        self.reg_email_entry.grid(row=5, column=1, padx=10, pady=10)

        button_style = {
            "font": ("Arial", 12, "bold"),
            "bg": "#404040",
            "fg": "white",
            "activebackground": "#404040",
            "activeforeground": "white",
            "relief": tk.RAISED,
            "bd": 2,
            "width": 15
        }

        tk.Button(
            content_frame, text="Soumettre", command=self.handle_registration, **button_style
        ).grid(row=6, column=0, columnspan=2, pady=20)

        tk.Button(
            content_frame, text="Retour", command=lambda: self.show_frame(self.login_frame), **button_style
        ).grid(row=7, column=0, columnspan=2, pady=10)

        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)

    def handle_login(self):
        """Gérer la connexion."""
        eth_address = self.eth_address_entry.get().strip()
        private_key = self.private_key_entry.get().strip()

        if not Web3.isAddress(eth_address):
            messagebox.showerror("Erreur", "Adresse Ethereum invalide.")
            return

        self.private_key = private_key

        try:
            user_info = contract_patient.functions.getPatient(eth_address).call()
            if user_info[0]:  # Utilisateur enregistré
                self.display_user_info(user_info)
                self.show_frame(self.dashboard_frame)
            else:
                messagebox.showinfo(
                    "Nouvel Utilisateur",
                    "Cette adresse n'est pas encore enregistrée. Veuillez créer un compte.",
                )
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la connexion : {str(e)}")

    def handle_registration(self):
        """Handle user registration."""
        name = self.reg_name_entry.get().strip()
        dob = self.reg_dob_entry.get().strip()
        eth_address = self.eth_address_entry.get().strip()  # From login form
        private_key = self.private_key_entry.get().strip()  # From login form
        gender = self.reg_gender_entry.get().strip()
        address = self. reg_address_entry.get().strip()
        phone = self.reg_phone_entry.get().strip()
        email = self.reg_email_entry.get().strip()

        if not name or not dob or not gender or not address or not phone or not email:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")
            return

        try:
            # Fetch the correct nonce for the address
            nonce = web3.eth.getTransactionCount(eth_address)

            # Set a gas price slightly higher than the current average
            gas_price = web3.eth.gas_price + web3.toWei(1, 'gwei')

            # Construct the transaction
            tx = contract_patient.functions.registerPatient(name, dob, gender, address, phone, email).buildTransaction({
                'from': eth_address,
                'nonce': nonce,
                'gas': 2000000,
                'gasPrice': gas_price
            })

            # Sign the transaction
            signed_tx = web3.eth.account.sign_transaction(tx, private_key)
            
            # Send the signed transaction
            tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
            
            # Wait for transaction receipt
            web3.eth.waitForTransactionReceipt(tx_hash)

            messagebox.showinfo("Succès", "Compte enregistré avec succès.")
            self.show_frame(self.login_frame)  # Redirect to login page
        except ValueError as e:
            messagebox.showerror("Erreur", f"Erreur liée à la clé privée ou à l'adresse : {str(e)}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'enregistrement : {str(e)}")

    def display_user_info(self, user_info):
        """Afficher les informations de l'utilisateur dans l'interface du tableau de bord."""
        self.name_label.config(text=user_info[0])
        self.dob_label.config(text=user_info[1])
        self.eth_address_label.config(text=self.eth_address_entry.get().strip())
        self.filehash_label.config(text=user_info[3] or "Not available")
        self.gender_label.config(text=user_info[4])
        self.address_label.config(text=user_info[5])
        self.phone_label.config(text=user_info[6])
        self.email_label.config(text=user_info[7])


    def handle_logout(self):
        """Gérer la déconnexion."""
        self.eth_address_entry.delete(0, tk.END)
        self.private_key_entry.delete(0, tk.END)
        self.show_frame(self.login_frame)

    def handle_action(self):
        """Handle login or registration by verifying both Ethereum address and private key."""
        eth_address = self.eth_address_entry.get().strip()
        private_key = self.private_key_entry.get().strip()

        if not Web3.isAddress(eth_address):
            messagebox.showerror("Erreur", "Adresse Ethereum invalide.")
            return

        try:
            derived_address = web3.eth.account.from_key(private_key).address

            if Web3.toChecksumAddress(derived_address) != Web3.toChecksumAddress(eth_address):
                messagebox.showerror("Erreur", "Clé privée incorrecte pour cette adresse Ethereum.")
                return

            self.private_key = private_key
            user_info = contract_patient.functions.getPatient(eth_address).call()

            if user_info[0]:
                self.display_user_info(user_info)
                self.show_frame(self.dashboard_frame)
            else:
                self.show_frame(self.registration_frame)
        except ValueError as e:
            messagebox.showerror("Erreur", "Clé privée invalide.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'action : {str(e)}")

# ---------------------------------------------------------------------------------------------------------

class DoctorApp:
    def __init__(self, parent):
        self.frame = tk.Frame(parent)
        self.frame.pack(fill="both", expand=True)

        tk.Label(self.frame, text="Doctor Section", font=("Arial", 16)).pack()

        self.current_address = None
        self.private_key = None


    def show_login_page(self):
        for widget in self.frame.winfo_children():
            widget.destroy()

        top_bar = tk.Frame(self.frame, bg="#404040", height=50)
        top_bar.pack(fill=tk.X)
        tk.Label(top_bar, text="Doctor Login", bg="#404040", fg="white", font=("Arial", 18, "bold"))\
            .pack(pady=10)

        content_frame = tk.Frame(self.frame, bg="white", padx=20, pady=20)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        tk.Label(content_frame, text="Doctor Ethereum Address:", font=("Arial", 12, "bold"), bg="white")\
            .pack(anchor="w", pady=5)
        self.doctor_address_entry = tk.Entry(content_frame, width=40, font=("Arial", 12), bg="white")
        self.doctor_address_entry.pack(pady=5)

        tk.Label(content_frame, text="Doctor Private Key:", font=("Arial", 12, "bold"), bg="white")\
            .pack(anchor="w", pady=5)
        self.private_key_entry = tk.Entry(content_frame, width=40, show="*", font=("Arial", 12), bg="white")
        self.private_key_entry.pack(pady=5)

        button_style = {
            "font": ("Arial", 12, "bold"),
            "bg": "#404040",
            "fg": "white",
            "activebackground": "#404040",
            "activeforeground": "white",
            "relief": tk.RAISED,
            "bd": 2,
            "width": 15
        }
        tk.Button(content_frame, text="Login", command=self.login, **button_style)\
            .pack(pady=20)

        self.login_message = tk.Label(content_frame, text="", bg="white", fg="red", font=("Arial", 12))
        self.login_message.pack()

    def login(self):
        doctor_address = self.doctor_address_entry.get().strip()
        private_key = self.private_key_entry.get().strip()

        if not web3.isAddress(doctor_address):
            self.login_message.config(text="Invalid Ethereum address.", fg="red")
            return

        try:
            derived_address = web3.eth.account.from_key(private_key).address

            if web3.toChecksumAddress(derived_address) != web3.toChecksumAddress(doctor_address):
                self.login_message.config(text="Private key does not match the Ethereum address.", fg="red")
                return

            self.current_address = doctor_address
            self.private_key = private_key
            self.show_verification_page()

        except ValueError as e:
            self.login_message.config(text="Invalid private key.", fg="red")
        except Exception as e:
            self.login_message.config(text=f"Error during login: {str(e)}", fg="red")

    def show_verification_page(self):
        for widget in self.frame.winfo_children():
            widget.destroy()

        top_bar = tk.Frame(self.frame, bg="#404040", height=50)
        top_bar.pack(fill=tk.X)
        tk.Label(top_bar, text="Patient Verification", bg="#404040", fg="white", font=("Arial", 18, "bold"))\
            .pack(pady=10)

        content_frame = tk.Frame(self.frame, bg="white", padx=20, pady=20)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        tk.Label(content_frame, text="Patient Ethereum Address:", font=("Arial", 12, "bold"), bg="white")\
            .pack(anchor="w", pady=5)
        self.patient_address_entry = tk.Entry(content_frame, width=40, font=("Arial", 12), bg="white")
        self.patient_address_entry.pack(pady=5)

        button_style = {
            "font": ("Arial", 12, "bold"),
            "bg": "#404040",
            "fg": "white",
            "activebackground": "#404040",
            "activeforeground": "white",
            "relief": tk.RAISED,
            "bd": 2,
            "width": 15
        }
        tk.Button(content_frame, text="Check Access", command=self.check_access, **button_style)\
            .pack(pady=20)

        self.access_message = tk.Label(content_frame, text="", fg="blue", font=("Arial", 12), bg="white")
        self.access_message.pack()

        button_frame = tk.Frame(content_frame, bg="white")
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Logout", command=self.show_login_page, **button_style)\
            .pack(side=tk.LEFT, padx=10)

    def show_patient_details(self, patient_data, patient_address):
        for widget in self.frame.winfo_children():
            widget.destroy()

        top_bar = tk.Frame(self.frame, bg="#404040", height=50)
        top_bar.pack(fill=tk.X)
        tk.Label(top_bar, text="Patient Information", bg="#404040", fg="white", font=("Arial", 18, "bold"))\
            .pack(pady=10)

        content_frame = tk.Frame(self.frame, bg="white", padx=20, pady=20)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        details = [
            ("Wallet Address:", patient_data[2]),
            ("Full Name:", patient_data[0]),
            ("Date of Birth:", patient_data[1]),
            ("Gender:", patient_data[4]),
            ("Address:", patient_data[5]),
            ("Phone:", patient_data[6]),
            ("Email:", patient_data[7]),
            ("File Hash:", patient_data[3] if patient_data[3] else "None")
        ]

        for label, value in details:
            row = tk.Frame(content_frame, bg="white")
            row.pack(fill=tk.X, pady=5)
            tk.Label(row, text=label, font=("Arial", 12, "bold"), bg="white", anchor="w", width=20)\
                .pack(side=tk.LEFT, padx=5)
            tk.Label(row, text=value, font=("Arial", 12), bg="white", anchor="w")\
                .pack(side=tk.LEFT, padx=5)

        button_frame = tk.Frame(content_frame, bg="white")
        button_frame.pack(pady=20)

        button_style = {
            "font": ("Arial", 12, "bold"),
            "bg": "#404040",
            "fg": "white",
            "activebackground": "#404040",
            "activeforeground": "white",
            "relief": tk.RAISED,
            "bd": 2,
            "width": 15
        }

        if not patient_data[3]:
            tk.Button(button_frame, text="Upload File", command=lambda: self.upload_file(patient_address), **button_style)\
                .pack(side=tk.LEFT, padx=10)
        else:
            tk.Button(button_frame, text="Update File", command=lambda: self.upload_file(patient_address), **button_style)\
                .pack(side=tk.LEFT, padx=10)
            tk.Button(button_frame, text="Retrieve File", command=lambda: self.retrieve_file(patient_data[3]), **button_style)\
                .pack(side=tk.LEFT, padx=10)

        tk.Button(button_frame, text="Back", command=self.show_verification_page, **button_style)\
            .pack(side=tk.LEFT, padx=10)

    def retrieve_file(self, file_hash):
        # Form the Pinata gateway URL
        ipfs_url = f"https://gateway.pinata.cloud/ipfs/{file_hash}"
        webbrowser.open(ipfs_url)

    def check_access(self):
        patient_address = self.patient_address_entry.get().strip()

        if not web3.isAddress(patient_address):
            self.access_message.config(text="Invalid patient address.", fg="red")
            return

        try:
            has_access = contract_doctor.functions.checkAccess(patient_address).call({"from": self.current_address})
            if has_access:
                patient_data = contract_patient.functions.getPatient(patient_address).call()
                self.show_patient_details(patient_data, patient_address)
            else:
                self.access_message.config(text="Access denied to the patient's information.", fg="red")
        except Exception as e:
            self.access_message.config(text=f"Error: {str(e)}", fg="red")

    def upload_file(self, patient_address):
        file_path = filedialog.askopenfilename(title="Select a file")
        if not file_path:
            return

        try:
            with open(file_path, "rb") as f:
                response = requests.post(
                    "https://api.pinata.cloud/pinning/pinFileToIPFS",
                    headers={"pinata_api_key": PINATA_API_KEY, "pinata_secret_api_key": PINATA_API_SECRET},
                    files={"file": f},
                )
            response_data = response.json()
            file_hash = response_data["IpfsHash"]

            nonce = web3.eth.get_transaction_count(self.current_address)
            transaction = contract_doctor.functions.uploadFile(patient_address, file_hash).buildTransaction({
                "chainId": 11155111,
                "gas": 3000000,
                "gasPrice": web3.toWei("20", "gwei"),
                "nonce": nonce,
            })
            signed_txn = web3.eth.account.sign_transaction(transaction, private_key=self.private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            web3.eth.wait_for_transaction_receipt(tx_hash)

            messagebox.showinfo("Success", f"File uploaded successfully! IPFS Hash: {file_hash}")
        except Exception as e:
            messagebox.showerror("Error", f"File upload failed: {str(e)}")

# ---------------------------------------------------------------------------------------------------------

class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Medical Blockchain App")
        self.root.geometry("1220x738")
        self.current_frame = None
        self.show_main_menu()

    def show_main_menu(self):
        self.clear_frame()
        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(fill="both", expand=True)

        top_bar = tk.Frame(self.current_frame, bg="#404040", height=60)
        top_bar.pack(side="top", fill="x")

        title_label = tk.Label(
            top_bar,
            text="Application Dossier Medical Blockchain",
            bg="#404040",
            fg="white",
            font=("Helvetica", 18, "bold"),
        )
        title_label.pack(pady=10)

        main_body = tk.Frame(self.current_frame)
        main_body.pack(expand=True, fill="both")

        main_body.grid_rowconfigure(0, weight=1)
        main_body.grid_columnconfigure(0, weight=1)
        main_body.grid_columnconfigure(2, weight=1)

        left_frame = tk.Frame(main_body)
        left_frame.grid(row=0, column=0, sticky="nsew")

        left_inner_frame = tk.Frame(left_frame)
        left_inner_frame.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

        patient_label = tk.Label(
            left_inner_frame,
            text="Patient Section",
            font=("Helvetica", 17, "bold"),
        )
        patient_label.pack(pady=20)

        patient_desc = tk.Label(
            left_inner_frame,
            text="Login as Patient",
            font=("Helvetica", 12),
        )
        patient_desc.pack(pady=10)

        patient_button = tk.Button(
            left_inner_frame,
            text="Login",
            command=self.show_patient_section,
            font=("Helvetica", 14),
            width=20,
            bg="#404040",
            fg="white",
        )
        patient_button.pack(pady=10)

        divider = tk.Frame(main_body, bg=main_body.cget('bg'), width=2)
        divider.grid(row=0, column=1, sticky="ns")

        right_frame = tk.Frame(main_body)
        right_frame.grid(row=0, column=2, sticky="nsew")

        right_inner_frame = tk.Frame(right_frame)
        right_inner_frame.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

        doctor_label = tk.Label(
            right_inner_frame,
            text="Doctor Section",
            font=("Helvetica", 17, "bold"),
        )
        doctor_label.pack(pady=20)

        doctor_desc = tk.Label(
            right_inner_frame,
            text="Login as Doctor",
            font=("Helvetica", 12),
        )
        doctor_desc.pack(pady=10)

        doctor_button = tk.Button(
            right_inner_frame,
            text="Login",
            command=self.show_doctor_section,
            font=("Helvetica", 14),
            width=20,
            bg="#404040",
            fg="white",
        )
        doctor_button.pack(pady=10)

    def show_patient_section(self):
        self.clear_frame()
        self.current_frame = PatientApp(self.root).frame

    def show_doctor_section(self):
        self.clear_frame()
        doctor_app = DoctorApp(self.root)
        doctor_app.show_login_page()
        self.current_frame = doctor_app.frame

    def clear_frame(self):
        if self.current_frame:
            self.current_frame.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()

# frame = tk.Tk()
# app = PatientApp(root)
# root.mainloop()

# root = tk.Tk()
# app = DoctorApp(root)
# root.mainloop()