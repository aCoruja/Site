from flask import Flask, request, render_template, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import jwt, time, sqlite3, uuid, os

# ===== Configurações =====
app = Flask(__name__)
app.secret_key = "minha_chave_super_secreta"  # para sessões
JWT_SECRET = "jwt_secret_local"
JWT_ALG = "HS256"
JWT_EXP_SECONDS = 3600  # 1 hora

# Client registrado
clients = {
    "example-client-1": {
        "name": "App Exemplo",
        "clientSecret": "secret123"
    }
}

# ===== Banco de dados =====
DB_FILE = "users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Cria tabela se não existir
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            full_name TEXT,
            password_hash TEXT
        )
    """)
    # Inserir usuário inicial se tabela vazia
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("""
            INSERT INTO users (username, full_name, password_hash) 
            VALUES (?, ?, ?)
        """, ("joao.silva", "Joao Silva", generate_password_hash("123456")))
    conn.commit()
    conn.close()

init_db()

def get_user(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, username, full_name, password_hash FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "full_name": row[2], "password_hash": row[3]}
    return None

# ===== ROTAS =====

# Página inicial: valida clientID + clientSecret
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        clientID = request.form.get("clientID")
        clientSecret = request.form.get("clientSecret")
        client = clients.get(clientID)
        if client and client.get("clientSecret") == clientSecret:
            session["clientID"] = clientID
            return redirect(url_for("login"))
        return render_template("index.html", error="clientID ou clientSecret inválidos")
    return render_template("index.html")


# Login do usuário
@app.route("/login", methods=["GET", "POST"])
def login():
    if "clientID" not in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = get_user(username)
        if not user or not check_password_hash(user["password_hash"], password):
            return render_template("login.html", error="Usuário ou senha inválidos")
        
        # Criar JWT
        iat = int(time.time())
        exp = iat + JWT_EXP_SECONDS
        payload = {
            "sub": user["username"],
            "name": user["full_name"],
            "email": f"{user['username']}@example.com",
            "role": "admin",
            "iat": iat,
            "exp": exp
        }
        headers = {"alg": JWT_ALG, "typ": "JWT"}
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG, headers=headers)

        # Criar sessão local
        session["sessionID"] = str(uuid.uuid4())
        session["user_id"] = user["id"]

        return render_template("success.html", token=token)
    return render_template("login.html")


# Rota de perfil para teste da sessão
@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("index"))
    return f"Usuário logado ID={session['user_id']}, sessionID={session['sessionID']}"


# Rota para validar token JWT (exemplo)
@app.route("/validate-token", methods=["POST"])
def validate_token():
    data = request.get_json() or {}
    token = data.get("token")
    if not token:
        return jsonify({"error": "token required"}), 400
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return jsonify({"valid": True, "payload": decoded})
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "token expired"}), 401
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 401


# ===== EXECUÇÃO =====
if __name__ == "__main__":
    app.run(debug=True)
