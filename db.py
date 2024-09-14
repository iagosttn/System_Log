from passlib.context import CryptContext
import sqlite3

# Configurar o contexto para hashing de senhas
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], default="pbkdf2_sha256")

# Conectar ao banco de dados
conn = sqlite3.connect('authe.db')
c = conn.cursor()



try:
    # Criar tabela de usuários se não existir
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT, admin INTEGER DEFAULT 0)''')
    conn.commit()

    def create_user(username, password, is_admin=False):
        hashed_password = pwd_context.hash(password)
        c.execute('INSERT INTO users (username, password, admin) VALUES (?, ?, ?)', 
                  (username, hashed_password, int(is_admin)))
        conn.commit()
        print(f"Usuário {username} criado com sucesso.")

    def create_admin(username, password):
        create_user(username, password, is_admin=True)
        print(f"Usuário administrador {username} criado com sucesso.")

    # Verifique se o usuário administrador já existe
    c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    admin_user = c.fetchone()

    if not admin_user:
        # Criar usuário administrador
        '''create_admin('admin', 'amd@2022')'''



except sqlite3.Error as e:
    print(f"Erro de banco de dados: {e}")


# Fechar a conexão com o banco de dados
conn.close()