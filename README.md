### **`password-manager`**: A Secure Command-Line Password Manager

`password-manager` is a Python-based command-line tool for managing passwords with robust AES-256 encryption. It ensures your passwords are securely stored, retrieved, and managed with ease.

---

## **Features**

- **Password Encryption:**
  - Uses **AES-256 encryption** with a unique key for each instance to ensure data security.
  
- **Master Password Protection:**
  - Secure the tool with a **master password**, required at every startup.
  - Change the master password anytime from the tool.

- **Add Passwords:**
  - Save passwords with associated labels for easy retrieval.

- **Retrieve Passwords:**
  - View all stored labels along with their passwords in a neatly numbered list.

- **Delete Passwords:**
  - Delete any stored password with a confirmation prompt.

- **User-Friendly Interface:**
  - Simple, clear, and interactive command-line experience.

---

## **Pre-requisites**

- **Python 3.6+** installed on your system.
- **OpenSSL** installed (if not already available).
  - On Debian-based systems (Ubuntu, etc.):
    ```bash
    sudo apt-get install openssl
    ```
  - On Red Hat-based systems (Fedora, CentOS, etc.):
    ```bash
    sudo yum install openssl
    ```
  - On macOS:
    ```bash
    brew install openssl
    ```

---

## **Installation**

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/Omer-Secure/password-manager.git
    ```

2. **Navigate to the Directory:**
    ```bash
    cd password-manager
    ```

3. **Run the Script:**
    ```bash
    python password_manager.py
    ```

---

## **Usage**

### **Starting the Tool**
1. Set a **master password** during the first run.
2. Use the master password every time to unlock the tool.

### **Available Options**
1. **Add Password:** Enter a label and its associated password to securely store it.
2. **View All Passwords:** See a numbered list of all labels with their respective passwords.
3. **Delete a Password:** Select a password by its label to delete it after confirmation.
4. **Change Master Password:** Update the master password after entering the current one.
5. **Exit:** Close the tool.

---

## **Example Session**

```bash
$ python3 password-manager.py

█████████████████████████████████████████████████████████

Welcome to Pass-Manager!

1. Add a password
2. View all stored passwords
3. Delete a password
4. Change the master password
5. Exit

Choose an option:
```

### **Adding a Password**
```plaintext
Enter a label for the password: Email
Enter the password to store: ********
Password stored successfully!
```

### **Viewing Stored Passwords**
```plaintext
1) Email: examplepassword123
2) Bank: securebanking123
```

### **Deleting a Password**
```plaintext
Enter the label of the password to delete: Email
Are you sure you want to delete the password for 'Email'? (yes/no): yes
Password for 'Email' deleted successfully!
```

---

## **License**

This tool is licensed under the [MIT License](LICENSE).

--- 

## **Author**

Developed by [Omer-Secure]. Contributions and feedback are welcome!
