# app.py
import os
os.environ["OTEL_SDK_DISABLED"] = "true"

# ==============================
# Imports
# ==============================
import streamlit as st
import mysql.connector
from mysql.connector.pooling import MySQLConnectionPool
import pandas as pd
import hashlib
from streamlit_autorefresh import st_autorefresh
import plotly.express as px
import plotly.graph_objects as go
import re
import io
from datetime import datetime, timedelta
from pathlib import Path

# tomllib (Py 3.11+) / tomli (fallback) para ler .streamlit/secrets.toml
try:
    import tomllib as _toml
except Exception:
    import tomli as _toml

# bcrypt obrigatório (com compat legado SHA para upgrade transparente)
_BCRYPT_OK = True
try:
    import bcrypt
except Exception:
    _BCRYPT_OK = False

# .env opcional
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ======== AgGrid (opcional) ========
USE_AGGRID = False
if USE_AGGRID:
    try:
        from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, JsCode
    except Exception:
        USE_AGGRID = False

# ==============================
# Config
# ==============================
st.set_page_config(page_title="Fila de Trabalho", layout="wide", page_icon="logo_bakof.png")

# Preferir st.secrets, com fallback ao .env/variáveis
def _get(key, default=None):
    """
    1) ENV var (RECOMENDADO no Render/Heroku/etc)
    2) .streamlit/secrets.toml local (se existir)
    3) default
    """
    # 1) ENV var
    env_key = key.replace(".", "_").upper()
    if env_key in os.environ:
        return os.getenv(env_key, default)

    # 2) secrets.toml local (opcional)
    try:
        secrets_path = Path.cwd() / ".streamlit" / "secrets.toml"
        if secrets_path.exists():
            with open(secrets_path, "rb") as f:
                secrets = _toml.load(f)
            cur = secrets
            for s in key.split("."):
                cur = cur[s]
            return cur
    except Exception:
        pass

    # 3) fallback
    return default

DB_CFG = {
    "host": _get("db.host", "localhost"),
    "user": _get("db.user", "root"),
    "password": _get("db.password", "1235"),
    "database": _get("db.database", "metalurgica"),
}
AUTH_SALT = _get("auth.salt", "troque-este-salt")
SEED_ADMIN_USER = _get("seed.admin_user", "admin")
SEED_ADMIN_PASS = _get("seed.admin_pass", "Adm1nFort3!")  # troque em produção!
REQUIRE_BCRYPT = str(_get("auth.require_bcrypt", "true")).lower() == "true"
INIT_SCHEMA = str(_get("db.init_schema", "true")).lower() == "true"  # em prod: "false"

# ======= Ajustes de performance (intervalos) =======
# refresh padrão de 60s (pode reduzir via env UI_REFRESH_MS=5000)
REFRESH_FILA_MS = int(str(_get("ui.refresh_ms", "60000")))
REFRESH_ADMIN_MS = int(str(_get("ui.refresh_ms_admin", "60000")))

if REQUIRE_BCRYPT and not _BCRYPT_OK:
    raise RuntimeError("bcrypt é obrigatório (defina auth.require_bcrypt=false apenas em dev).")

# ======= TEMA BAKOF (visual) =======
st.markdown("""
<style>
:root{
  --bk-primary:#0057B8;   /* azul Bakof (ajuste se quiser) */
  --bk-primary-2:#0077FF; /* azul claro p/ gradiente */
  --bk-accent:#00AEEF;    /* ciano de detalhe */
  --bk-bg:#0B1220;        /* fundo (dark elegante) */
  --bk-card:#0F1828;      /* card */
  --bk-border:rgba(255,255,255,0.10);
  --bk-text:#E9EEF6;      /* texto principal */
  --bk-sub:#B8C2D3;       /* texto secundário */
}

html, body, [data-testid="stAppViewContainer"]{
  background: var(--bk-bg);
  color: var(--bk-text);
}

/* ===== Topbar ===== */
.bk-topbar {
  background: linear-gradient(90deg, var(--bk-primary), var(--bk-primary-2));
  color: white;
  padding: 14px 18px;
  border-radius: 12px;
  display: flex; align-items: center; gap: 14px;
  box-shadow: 0 6px 18px rgba(0,0,0,0.25);
  margin: 4px 2px 14px 2px;
}
.bk-topbar .bk-logo {
  height: 34px; width:auto; border-radius: 6px;
  background: rgba(255,255,255,0.15);
  padding: 6px 10px; display:flex; align-items:center; justify-content:center;
}
.bk-topbar h1 {
  font-size: 1.15rem; font-weight: 700; margin: 0;
}
.bk-topbar .bk-sub {
  font-size: .85rem; opacity:.95; margin-top: 2px;
}

/* ===== Sidebar ===== */
section[data-testid="stSidebar"] {
  background: linear-gradient(180deg, rgba(0,87,184,0.12), rgba(0,0,0,0));
  border-right: 1px solid var(--bk-border);
}
section[data-testid="stSidebar"] [data-testid="stSidebarContent"]{
  color: var(--bk-text);
}
[data-testid="stSidebarNav"] a{ color: var(--bk-text); }

/* Radio/menu */
div[role="radiogroup"] > label {
  background: rgba(255,255,255,0.03);
  border: 1px solid var(--bk-border);
  padding: 8px 10px; border-radius: 10px; margin-bottom: 8px;
}
div[role="radiogroup"] > label:hover { border-color: rgba(255,255,255,0.25); }

/* ===== Cards ===== */
.card {
  background: var(--bk-card);
  border: 1px solid var(--bk-border);
  border-radius: 14px;
  padding: 16px 16px 12px 16px;
  margin-bottom: 14px;
  box-shadow: 0 6px 16px rgba(0,0,0,0.18);
}
.card h2,.card h3,.card h4 { margin: 0 0 8px 0; font-weight: 700; }

/* ===== Inputs & Selects ===== */
[data-baseweb="select"] > div, .stTextInput > div > div, .stDateInput > div, .stNumberInput > div {
  min-height: 44px; border-radius: 10px !important; border: 1px solid var(--bk-border);
  background: rgba(255,255,255,0.02);
}
.stTextArea textarea, .stTextInput input {
  background: transparent !important; color: var(--bk-text) !important;
}

/* ===== Botões ===== */
.stButton > button, .stForm button[kind="primary"]{
  height: 46px; font-size: 16px; font-weight: 700;
  border-radius: 12px; border: 0;
  color: white; letter-spacing: .2px;
  background: linear-gradient(180deg, var(--bk-primary-2), var(--bk-primary));
  box-shadow: 0 8px 16px rgba(0,119,255,0.28);
  transition: transform .03s ease-in, filter .15s ease-out, box-shadow .2s ease;
}
.stButton > button:hover, .stForm button[kind="primary"]:hover{
  filter: brightness(1.05);
  box-shadow: 0 10px 22px rgba(0,119,255,0.34);
}
.stButton > button:active, .stForm button[kind="primary"]:active{ transform: translateY(1px); }

/* ===== Tabelas ===== */
div[data-testid="stDataFrame"] table{
  border-collapse: separate; border-spacing: 0;
  border: 1px solid var(--bk-border);
  border-radius: 12px; overflow: hidden;
  background: rgba(3,7,18,0.35);
}
div[data-testid="stDataFrame"] thead tr th{
  background: linear-gradient(180deg, rgba(0,119,255,0.18), rgba(0,119,255,0.05));
  color: #EAF3FF; font-weight: 700; border-bottom: 1px solid var(--bk-border);
}
div[data-testid="stDataFrame"] tbody tr td{
  border-bottom: 1px solid rgba(255,255,255,0.06);
}

/* ===== Métricas ===== */
[data-testid="stMetricValue"]{ color: #EAF3FF; }
[data-testid="stMetricLabel"]{ color: var(--bk-sub); }

/* ===== Diversos ===== */
.block-container{ padding-top: 12px; }
.dataframe td, .dataframe th { border-bottom: 2px solid rgba(128,128,128,0.25) !important; }
.stCheckbox > label{ color: var(--bk-text); }
</style>
""", unsafe_allow_html=True)


# ==============================
# Helpers de atualização instantânea
# ==============================
def refresh_now(nav_to: str | None = None):
    """Limpa caches (de dados) e dispara rerun, opcionalmente navegando para outra página."""
    try:
        st.cache_data.clear()
    except Exception:
        pass
    if nav_to:
        st.session_state["_nav_to"] = nav_to
    st.rerun()

# ==============================
# Conexão MySQL: Pool + helpers
# ==============================
@st.cache_resource(show_spinner=False)
def get_pool():
    # conexão mais resiliente e sem travar em rede lenta
    return MySQLConnectionPool(
        pool_name="app_pool",
        pool_size=8,
        host=DB_CFG["host"],
        user=DB_CFG["user"],
        password=DB_CFG["password"],
        database=DB_CFG["database"],
        autocommit=False,
        pool_reset_session=True,
        connection_timeout=6,  # evita “pendurar”
    )

# --- timezone com fallback (corrige erro 1298 em instâncias sem tz tables) ---
def _set_session_tz(cur):
    try:
        cur.execute("SET time_zone='America/Sao_Paulo'")
    except Exception:
        cur.execute("SET time_zone='-03:00'")

def run_query(query, params=None, commit=False):
    pool = get_pool()
    conn = pool.get_connection()
    try:
        try:
            conn.ping(reconnect=True, attempts=2, delay=1)
        except Exception:
            pass
        with conn.cursor(dictionary=True) as cur:
            _set_session_tz(cur)
            cur.execute(query, params or ())
            if commit:
                conn.commit()
            return cur.fetchall() if cur.with_rows else None
    except Exception:
        if commit:
            try: conn.rollback()
            except: pass
        raise
    finally:
        try: conn.close()
        except: pass

def run_tx(steps):
    """steps = [("SQL ...", params), ...] — roda tudo na mesma transação."""
    pool = get_pool()
    conn = pool.get_connection()
    try:
        conn.start_transaction()
        with conn.cursor(dictionary=True) as cur:
            _set_session_tz(cur)
            for sql, params in steps:
                cur.execute(sql, params or ())
        conn.commit()
    except Exception:
        try: conn.rollback()
        except: pass
        raise
    finally:
        try: conn.close()
        except: pass

# helper que devolve rowcount (para operações atômicas)
def exec_rowcount(sql, params=None):
    pool = get_pool()
    conn = pool.get_connection()
    try:
        conn.ping(reconnect=True, attempts=2, delay=1)
        with conn.cursor() as cur:
            _set_session_tz(cur)
            cur.execute(sql, params or ())
            affected = cur.rowcount
        conn.commit()
        return affected
    except Exception:
        try: conn.rollback()
        except: pass
        raise
    finally:
        try: conn.close()
        except: pass

# data “oficial” do DB (cache por request)
def get_db_today_cached():
    if "_db_today" not in st.session_state:
        row = run_query("SELECT CURRENT_DATE() AS d") or [{"d": datetime.now().date()}]
        st.session_state["_db_today"] = row[0]["d"]
    return st.session_state["_db_today"]

# ==============================
# Auth & Schema
# ==============================
ROLES = {
    "ADMIN": "Administrador",
    "OPERADOR": "Operador",
    "SOLICITANTE": "Solicitante",
}

# --- Política de senha forte ---
def validar_senha_forte(pwd: str) -> bool:
    return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$', pwd or ""))

def erro_politica_senha():
    return "A senha deve ter no mínimo 8 caracteres, com ao menos 1 letra maiúscula, 1 minúscula e 1 número."

def _hash_password_sha(pwd: str) -> str:
    return hashlib.sha256((AUTH_SALT + "|" + pwd).encode("utf-8")).hexdigest()

def _is_probably_sha(hash_str: str) -> bool:
    h = str(hash_str or "")
    return len(h) == 64 and all(c in "0123456789abcdef" for c in h.lower())

def hash_password_bcrypt(pwd: str) -> str:
    if REQUIRE_BCRYPT and not _BCRYPT_OK:
        raise RuntimeError("bcrypt é obrigatório.")
    if not validar_senha_forte(pwd):
        raise ValueError(erro_politica_senha())
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

def verify_password(pwd: str, stored_hash: str) -> bool:
    if stored_hash is None:
        return False
    s = str(stored_hash)
    if s.startswith("$2a$") or s.startswith("$2b$") or s.startswith("$2y$"):
        try:
            return bcrypt.checkpw(pwd.encode(), s.encode())
        except Exception:
            return False
    if _is_probably_sha(s):
        return _hash_password_sha(pwd) == s
    return False

def set_user_password(user_id: int, new_pwd: str):
    new_hash = hash_password_bcrypt(new_pwd)
    try:
        run_query(
            "UPDATE usuarios SET senha_hash=%s, senha_trocada_em=NOW() WHERE id=%s",
            (new_hash, user_id),
            commit=True
        )
    except Exception:
        run_query(
            "UPDATE usuarios SET senha_hash=%s WHERE id=%s",
            (new_hash, user_id),
            commit=True
        )

def ensure_schema():
    run_query("""
        CREATE TABLE IF NOT EXISTS usuarios (
          id INT AUTO_INCREMENT PRIMARY KEY,
          nome VARCHAR(120) NOT NULL,
          username VARCHAR(60) NOT NULL UNIQUE,
          senha_hash VARCHAR(128) NOT NULL,
          role ENUM('ADMIN','OPERADOR','SOLICITANTE') NOT NULL DEFAULT 'SOLICITANTE',
          ativo TINYINT(1) NOT NULL DEFAULT 1,
          senha_trocada_em DATETIME NULL,
          criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """, commit=True)

    qtd = run_query("SELECT COUNT(*) AS c FROM usuarios")
    if qtd and qtd[0]["c"] == 0:
        pwd_hash = hash_password_bcrypt(SEED_ADMIN_PASS) if _BCRYPT_OK else _hash_password_sha(SEED_ADMIN_PASS)
        run_query("""
            INSERT INTO usuarios (nome, username, senha_hash, role)
            VALUES (%s, %s, %s, 'ADMIN')
        """, ("Administrador", SEED_ADMIN_USER, pwd_hash), commit=True)

    run_query("""
        CREATE TABLE IF NOT EXISTS colaboradores (
          id INT AUTO_INCREMENT PRIMARY KEY,
          nome VARCHAR(120) NOT NULL,
          status ENUM('Ocioso','Em Execução','Inativo') NOT NULL DEFAULT 'Ocioso'
        )
    """, commit=True)

    run_query("""
        CREATE TABLE IF NOT EXISTS ordens_servico (
          id INT AUTO_INCREMENT PRIMARY KEY,
          data_abertura DATE NOT NULL,
          solicitante VARCHAR(200),
          responsavel_id INT,
          produto VARCHAR(200),
          tipo_servico VARCHAR(200),
          descricao TEXT,
          previsao DATE,
          prioridade ENUM('Normal','Urgente') DEFAULT 'Normal',
          status ENUM('Aberta','Em Execução','Concluída') DEFAULT 'Aberta',
          executor_id INT DEFAULT NULL,
          data_inicio DATETIME NULL,
          data_fim DATETIME NULL,
          arquivada TINYINT(1) NOT NULL DEFAULT 0,
          arquivo_nome VARCHAR(120) NULL,
          arquivada_em DATETIME NULL,
          arquivada_por INT NULL,
          FOREIGN KEY (responsavel_id) REFERENCES colaboradores(id),
          FOREIGN KEY (executor_id) REFERENCES colaboradores(id)
        )
    """, commit=True)

    run_query("""
        CREATE TABLE IF NOT EXISTS ajudantes_os (
          id INT AUTO_INCREMENT PRIMARY KEY,
          os_id INT NOT NULL,
          colaborador_id INT NOT NULL,
          FOREIGN KEY (os_id) REFERENCES ordens_servico(id) ON DELETE CASCADE,
          FOREIGN KEY (colaborador_id) REFERENCES colaboradores(id)
        )
    """, commit=True)
    try:
        run_query("CREATE UNIQUE INDEX ux_aj ON ajudantes_os(os_id, colaborador_id)", commit=True)
    except Exception:
        pass

    run_query("""
        CREATE TABLE IF NOT EXISTS solicitacoes_os (
          id INT AUTO_INCREMENT PRIMARY KEY,
          data_solicitacao DATE NOT NULL,
          solicitante_user_id INT NOT NULL,
          solicitante_setor VARCHAR(120),
          produto VARCHAR(200),
          tipo_servico VARCHAR(200),
          descricao TEXT,
          previsao DATE,
          prioridade ENUM('Normal','Urgente') DEFAULT 'Normal',
          status ENUM('Pendente','Aprovada','Rejeitada') DEFAULT 'Pendente',
          analisado_por INT DEFAULT NULL,
          analisado_em DATETIME DEFAULT NULL,
          FOREIGN KEY (solicitante_user_id) REFERENCES usuarios(id)
        )
    """, commit=True)

    for ddl in [
        "CREATE INDEX idx_os_status ON ordens_servico(status)",
        "CREATE INDEX idx_os_resp ON ordens_servico(responsavel_id)",
        "CREATE INDEX idx_os_exec ON ordens_servico(executor_id)",
        "CREATE INDEX idx_os_datafim ON ordens_servico(data_fim)",
        "CREATE INDEX idx_os_arq ON ordens_servico(arquivada, data_fim)",
        "CREATE INDEX idx_colab_status ON colaboradores(status)"
    ]:
        try:
            run_query(ddl, commit=True)
        except Exception:
            pass

def ensure_column(table: str, column: str, ddl_add: str):
    row = run_query(
        """
        SELECT COUNT(*) AS c
        FROM information_schema.columns
        WHERE table_schema=%s AND table_name=%s AND column_name=%s
        """,
        (DB_CFG["database"], table, column)
    )
    exists = bool(row and row[0]["c"] > 0)
    if not exists:
        run_query(f"ALTER TABLE {table} {ddl_add}", (), commit=True)

# --- garantir DATETIME (evita HH:MM = 00:00) ---
def ensure_datetime_column(table: str, column: str):
    try:
        row = run_query(
            """
            SELECT DATA_TYPE
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND COLUMN_NAME=%s
            """,
            (DB_CFG["database"], table, column)
        )
        if row:
            t = (row[0]["DATA_TYPE"] or "").lower()
            if t != "datetime":
                run_query(f"ALTER TABLE {table} MODIFY COLUMN {column} DATETIME NULL", commit=True)
    except Exception:
        pass

# garantir colunas adicionadas em versões antigas
try:
    ensure_column("usuarios", "senha_trocada_em", "ADD COLUMN senha_trocada_em DATETIME NULL")
except Exception:
    pass
for _tbl,_col,_ddl in [
    ("ordens_servico","arquivada","ADD COLUMN arquivada TINYINT(1) NOT NULL DEFAULT 0"),
    ("ordens_servico","arquivo_nome","ADD COLUMN arquivo_nome VARCHAR(120) NULL"),
    ("ordens_servico","arquivada_em","ADD COLUMN arquivada_em DATETIME NULL"),
    ("ordens_servico","arquivada_por","ADD COLUMN arquivada_por INT NULL"),
]:
    try:
        ensure_column(_tbl,_col,_ddl)
    except Exception:
        pass

# garantir tipo correto
try:
    ensure_datetime_column("ordens_servico", "data_inicio")
    ensure_datetime_column("ordens_servico", "data_fim")
except Exception:
    pass

if INIT_SCHEMA:
    ensure_schema()

def auth_login(username: str, password: str):
    row = run_query("SELECT * FROM usuarios WHERE username=%s AND ativo=1", (username,))
    if not row:
        return None
    u = row[0]
    if verify_password(password, u["senha_hash"]):
        if _is_probably_sha(u["senha_hash"]) and _BCRYPT_OK:
            try:
                set_user_password(u["id"], password)
            except Exception:
                pass
        return {"id": u["id"], "nome": u["nome"], "username": u["username"], "role": u["role"]}
    return None

def auth_logout():
    st.session_state.pop("user", None)

def require_roles(allowed):
    user = st.session_state.get("user")
    if not user:
        st.warning("Faça login para acessar esta área.")
        return False
    if user["role"] not in allowed:
        st.error("Permissão negada.")
        return False
    return True

# ==============================
# Funções de dados/visão
# ==============================
def status_badge(status: str, previsao, prioridade: str = "Normal") -> str:
    urgente = str(prioridade).strip().lower() == "urgente"
    status = (status or "").strip()
    if status == "Concluída":
        return "🟩 Concluída"

    pv = None
    try:
        if previsao and str(previsao) != "":
            pv = pd.to_datetime(previsao).date()
    except Exception:
        pv = None

    hoje = get_db_today_cached()

    if status == "Em Execução":
        if pv and pv < hoje:
            return "🟪 Em execução — atrasada" + (" 🚨" if urgente else "")
        else:
            return "🟦 Em execução" + (" 🚨" if urgente else "")

    if pv:
        if pv < hoje:
            return "🟥 Atrasada" + (" 🚨" if urgente else "")
        if pv == hoje:
            return "🟧 Vence hoje" + (" 🚨" if urgente else "")
    if status == "Aberta":
        return "🟨 Aberta" + (" 🚨" if urgente else "")
    return (status or "—") + (" 🚨" if urgente else "")

def prio_icon(prioridade: str) -> str:
    return "🚨" if str(prioridade).strip().lower() == "urgente" else "—"

def atraso_dias(previsao) -> str:
    try:
        if not previsao or str(previsao) == "":
            return "—"
        pv = pd.to_datetime(previsao).date()
        hoje = get_db_today_cached()
        if pv < hoje:
            return str((hoje - pv).days)
        return "0"
    except Exception:
        return "—"

def load_base():
    # exclui arquivadas por padrão
    os_rows = run_query("""
        SELECT o.*,
               r.nome AS responsavel_nome,
               e.nome AS executor_nome
        FROM ordens_servico o
        LEFT JOIN colaboradores r ON r.id = o.responsavel_id
        LEFT JOIN colaboradores e ON e.id = o.executor_id
        WHERE COALESCE(o.arquivada,0)=0
        ORDER BY o.id
    """) or []
    df = pd.DataFrame(os_rows) if os_rows else pd.DataFrame()
    if df.empty:
        return df, pd.DataFrame()

    if "prioridade" not in df.columns:
        df["prioridade"] = "Normal"
    else:
        df["prioridade"] = df["prioridade"].fillna("Normal")

    ajuda = run_query("""
        SELECT a.os_id, GROUP_CONCAT(c.nome ORDER BY c.nome SEPARATOR ', ') AS ajudantes
        FROM ajudantes_os a
        JOIN colaboradores c ON c.id = a.colaborador_id
        GROUP BY a.os_id
    """) or []
    df_aj = pd.DataFrame(ajuda)
    if not df_aj.empty:
        df = df.merge(df_aj, how="left", left_on="id", right_on="os_id").drop(columns=["os_id"])
    else:
        df["ajudantes"] = None

    def colab_str(row):
        partes = []
        for v in [row.get("executor_nome"), row.get("ajudantes")]:
            if v is None: continue
            try:
                if pd.isna(v): continue
            except Exception:
                pass
            s = str(v).strip()
            if s: partes.append(s)
        return " | ".join(partes) if partes else "—"
    df["Colaboradores"] = df.apply(colab_str, axis=1)

    def produto_fmt(row):
        p = str(row.get("produto") or "—").strip()
        if str(row.get("prioridade","Normal")).lower() == "urgente" and (row.get("status") != "Concluída"):
            return f"🚨 URGENTE — {p}"
        return p
    df["produto_fmt"] = df.apply(produto_fmt, axis=1)

    return df, df_aj

# helpers de data/hora
def _fmt_date_col(series: pd.Series) -> pd.Series:
    dt = pd.to_datetime(series, errors="coerce")
    out = dt.dt.strftime("%d/%m/%Y")
    return out.fillna("—")

def _fmt_datetime_col(series: pd.Series) -> pd.Series:
    dt = pd.to_datetime(series, errors="coerce")
    out = dt.dt.strftime("%d/%m/%Y %H:%M")
    return out.fillna("—")

def view_table(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    ini_dt = pd.to_datetime(df["data_inicio"], errors="coerce") if "data_inicio" in df.columns else pd.NaT

    view = df.copy().rename(columns={
        "id": "Nº OS",
        "data_abertura": "Abertura",
        "solicitante": "Solicitante/Setor",
        "responsavel_nome": "Resp.",
        "produto_fmt": "Produto/Equip.",
        "descricao": "Descrição do Serviço",
        "data_inicio": "Início",
        "previsao": "Previsão",
        "data_fim": "Encerramento",
        "status": "StatusOriginal",
        "prioridade": "Prioridade",
    })

    view["Status"] = view.apply(lambda r: status_badge(r.get("StatusOriginal"), r.get("Previsão"), r.get("Prioridade")), axis=1)
    view["!"] = view["Prioridade"].apply(prio_icon)
    view["_prio_ord"] = view["Prioridade"].apply(lambda x: 0 if str(x).lower() == "urgente" else 1)

    def _atraso(previsao, status_ori):
        try:
            if status_ori == "Concluída" or not previsao or str(previsao) == "":
                return "—"
            pv = pd.to_datetime(previsao).date()
            hoje = get_db_today_cached()
            return str((hoje - pv).days) if pv < hoje else "0"
        except Exception:
            return "—"
    view["Atraso (d)"] = view.apply(lambda r: _atraso(r.get("Previsão"), r.get("StatusOriginal")), axis=1)

    def _atraso_int(x):
        try: return int(x)
        except: return -1
    view["_atraso_sort"] = view["Atraso (d)"].apply(_atraso_int)

    def _status_ord(s):
        s = (s or "").strip()
        if s == "Em Execução": return 0
        if s == "Aberta": return 1
        if s == "Concluída": return 2
        return 3
    view["_status_ord"] = view["StatusOriginal"].apply(_status_ord)
    view["_ini_sort"] = ini_dt.fillna(pd.Timestamp("1970-01-01")).astype("int64")

    cols = ["!","Nº OS","Abertura","Solicitante/Setor","Resp.","Produto/Equip.",
            "Descrição do Serviço","Início","Previsão","Encerramento","Atraso (d)",
            "Status","Colaboradores","Prioridade",
            "_status_ord","_prio_ord","_ini_sort","_atraso_sort"]
    view = view[cols].sort_values(
        by=["_status_ord", "_prio_ord", "_ini_sort", "_atraso_sort", "Nº OS"],
        ascending=[True,       True,      False,       False,          True]
    ).drop(columns=["_status_ord","_prio_ord","_ini_sort","_atraso_sort"])

    for c in ["Solicitante/Setor","Resp.","Produto/Equip.","Descrição do Serviço",
              "Status","Colaboradores","!","Prioridade","Atraso (d)"]:
        view[c] = view[c].fillna("—").astype(str)

    # datas: Abertura/Previsão (data), Início/Encerramento (data+hora)
    view["Abertura"] = _fmt_date_col(view["Abertura"])
    view["Previsão"] = _fmt_date_col(view["Previsão"])
    view["Início"] = _fmt_datetime_col(view["Início"])
    view["Encerramento"] = _fmt_datetime_col(view["Encerramento"])

    return view

def styler_for_table(df_view: pd.DataFrame):
    if df_view.empty: return df_view
    def zebra_and_status(row):
        idx = row.name
        bg = "rgba(255,255,255,0.06)" if idx % 2 == 0 else "rgba(255,255,255,0.12)"
        s = str(row.get("Status",""))
        if s.startswith("🟥"): bg = "rgba(255, 87, 87, 0.18)"
        elif s.startswith("🟧"): bg = "rgba(255, 165, 0, 0.18)"
        elif s.startswith("🟦"): bg = "rgba(100, 181, 246, 0.18)"
        elif s.startswith("🟪"): bg = "rgba(186, 104, 200, 0.20)"
        elif s.startswith("🟨"): bg = "rgba(255, 235, 59, 0.18)"
        elif s.startswith("🟩"): bg = "rgba(76, 175, 80, 0.18)"
        styles = [f"background-color: {bg}; border-bottom: 2px solid rgba(128,128,128,0.35);"] * len(row)
        return styles
    styled = (df_view.style
              .apply(zebra_and_status, axis=1)
              .set_properties(**{"white-space":"pre-wrap"}))
    return styled

def grid_with_colors(df: pd.DataFrame, height=520):
    if df.empty:
        st.dataframe(df, use_container_width=True, height=height)
        return
    if not USE_AGGRID:
        styled = styler_for_table(df)
        st.dataframe(styled, use_container_width=True, height=height)
        return
    from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, JsCode
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_default_column(resizable=True, sortable=True, filter=True)
    gb.configure_column("!", width=60)
    gb.configure_column("Nº OS", width=80)
    gb.configure_column("Abertura", width=110)
    gb.configure_column("Resp.", width=140)
    gb.configure_column("Produto/Equip.", width=200)
    gb.configure_column("Início", width=150)
    gb.configure_column("Previsão", width=110)
    gb.configure_column("Status", width=160)
    gb.configure_column("Solicitante/Setor", width=160)
    gb.configure_column("Descrição do Serviço", width=340)
    gb.configure_column("Colaboradores", width=260)
    row_style = JsCode("""
    function(params) {
      const s = params.data.Status;
      if (!s) return null;
      if (s.indexOf('🟨') === 0) return { 'backgroundColor': '#FFF6BF' };
      if (s.indexOf('🟦') === 0) return { 'backgroundColor': '#CFF4FC' };
      if (s.indexOf('🟥') === 0) return { 'backgroundColor': '#FDE2E2' };
      if (s.indexOf('🟩') === 0) return { 'backgroundColor': '#E6F4EA' };
      if (s.indexOf('🟧') === 0) return { 'backgroundColor': '#FFE6C8' };
      return null;
    }
    """)
    go_opts = gb.build()
    go_opts["getRowStyle"] = row_style
    AgGrid(df, gridOptions=go_opts, update_mode=GridUpdateMode.NO_UPDATE,
           allow_unsafe_jscode=True, fit_columns_on_grid_load=False,
           height=height, theme="balham")

def listar_colaboradores():
    return pd.DataFrame(run_query("SELECT id, nome, status FROM colaboradores ORDER BY nome") or [])

# refs detalhadas p/ exclusão segura
def colaborador_refs_detalhe(colab_id: int) -> dict:
    active_exec = run_query("SELECT COUNT(*) AS c FROM ordens_servico WHERE executor_id=%s AND status!='Concluída'", (colab_id,))
    active_aj = run_query("""
        SELECT COUNT(*) AS c FROM ajudantes_os a
        JOIN ordens_servico o ON o.id=a.os_id
        WHERE a.colaborador_id=%s AND o.status!='Concluída'
    """, (colab_id,))
    done_exec = run_query("SELECT COUNT(*) AS c FROM ordens_servico WHERE executor_id=%s AND status='Concluída'", (colab_id,))
    done_aj = run_query("""
        SELECT COUNT(*) AS c FROM ajudantes_os a
        JOIN ordens_servico o ON o.id=a.os_id
        WHERE a.colaborador_id=%s AND o.status='Concluída'
    """, (colab_id,))
    return {
        "ativos": int((active_exec or [{"c":0}])[0]["c"]) + int((active_aj or [{"c":0}])[0]["c"]),
        "concluidas": int((done_exec or [{"c":0}])[0]["c"]) + int((done_aj or [{"c":0}])[0]["c"])
    }

# ==============================
# Caches de alto impacto
# ==============================
@st.cache_data(ttl=10, show_spinner=False)
def _cached_load_base():
    return load_base()

@st.cache_data(ttl=10, show_spinner=False)
def _cached_listar_colaboradores():
    return listar_colaboradores()

@st.cache_data(ttl=10, show_spinner=False)
def _cached_pending_info():
    row = run_query("SELECT COUNT(*) AS c, COALESCE(MAX(id),0) AS max_id FROM solicitacoes_os WHERE status='Pendente'") or [{"c": 0, "max_id": 0}]
    return int(row[0]["c"]), int(row[0]["max_id"])

# ==============================
# Barra lateral: Login/Logout + Menu
# ==============================
st.sidebar.title("Acesso")

# Logo pequena no sidebar (apenas na tela de login)
if "user" not in st.session_state:
    try:
        st.sidebar.image("logo_bakof.png", width=250)
    except Exception:
        pass

if "login_attempts" not in st.session_state:
    st.session_state["login_attempts"] = 0
if "login_block_until" not in st.session_state:
    st.session_state["login_block_until"] = None

def _login_disponivel():
    until = st.session_state["login_block_until"]
    return (until is None) or (datetime.now() >= until)

if "user" not in st.session_state:
    with st.sidebar.form("form_login"):
        user_in = st.text_input("Usuário")
        pass_in = st.text_input("Senha", type="password")
        ok = st.form_submit_button("Entrar")
        if not _login_disponivel():
            st.sidebar.error("Muitas tentativas. Tente novamente em 2 minutos.")
        elif ok:
            u = auth_login(user_in.strip(), pass_in)
            if u:
                st.session_state["login_attempts"] = 0
                st.session_state["user"] = u
                st.sidebar.success(f"Bem-vindo(a), {u['nome']}!")
                st.rerun()
            else:
                st.session_state["login_attempts"] += 1
                if st.session_state["login_attempts"] >= 5:
                    st.session_state["login_block_until"] = datetime.now() + timedelta(minutes=2)
                st.sidebar.error("Usuário ou senha inválidos.")
    st.stop()
else:
    u = st.session_state["user"]
    st.sidebar.write(f"**{u['nome']}** — {ROLES.get(u['role'], u['role'])}")
    if st.sidebar.button("Sair"):
        auth_logout()
        st.rerun()

# Menu por perfil
if u["role"] == "SOLICITANTE":
    menu_ops = ["📋 Fila de Trabalho", "✅ Concluídas", "📝 Solicitar OS"]
elif u["role"] == "OPERADOR":
    menu_ops = ["📋 Fila de Trabalho", "✅ Concluídas"]
else:  # ADMIN
    menu_ops = ["📋 Fila de Trabalho", "✅ Concluídas", "📝 Solicitações", "🔧 Administração"]

if "🔑 Minha Senha" not in menu_ops:
    menu_ops.append("🔑 Minha Senha")

if "menu" not in st.session_state:
    st.session_state.menu = menu_ops[0]

if "_nav_to" in st.session_state:
    try:
        alvo = next(opt for opt in menu_ops if st.session_state["_nav_to"] in opt)
        st.session_state["menu"] = alvo
    except StopIteration:
        pass
    finally:
        st.session_state.pop("_nav_to", None)

def _get_pending_info():
    return _cached_pending_info()

if u["role"] == "ADMIN":
    st_autorefresh(interval=REFRESH_ADMIN_MS, key="autorefresh_admin_notify")
    pend_count, pend_max_id = _cached_pending_info()
    last_seen = st.session_state.get("last_seen_pend_max_id", 0)

    if pend_count > 0:
        st.sidebar.markdown(f"**🔔 Solicitações pendentes:** **{pend_count}**")
        if st.sidebar.button("Ver agora", key="btn_ver_agora", use_container_width=True):
            st.session_state["_nav_to"] = "Solicitações"
            st.rerun()
    else:
        st.sidebar.caption("🔔 Sem novas solicitações")

    if pend_max_id > last_seen:
        try:
            st.toast(f"🔔 Novas solicitações: {pend_count}", icon="🔔")
        except Exception:
            st.sidebar.warning(f"🔔 Novas solicitações: {pend_count}")
        st.session_state["last_seen_pend_max_id"] = pend_max_id

menu = st.sidebar.radio("Menu", menu_ops, key="menu")

if menu == "📋 Fila de Trabalho":
    st_autorefresh(interval=REFRESH_FILA_MS, key="autorefresh_fila")

# ==============================
# Util: range do mês (para arquivar robusto)
# ==============================
def month_bounds_from_str(ym: str):
    y, m = map(int, ym.split("-"))
    start = datetime(y, m, 1, 0, 0, 0)
    if m == 12:
        end = datetime(y + 1, 1, 1, 0, 0, 0)
    else:
        end = datetime(y, m + 1, 1, 0, 0, 0)
    return start, end

# ==============================
# Páginas
# ==============================

# ---------- FILA ----------
if menu == "📋 Fila de Trabalho":
    st.title("📋 Fila de Trabalho — Metalúrgica Bakof Tec")

    # Filtros
    fcol1, fcol2, fcol3 = st.columns([1,1,2])
    with fcol1:
        filtro_status = st.multiselect("Status", ["Aberta", "Em Execução", "Concluída"], default=["Aberta", "Em Execução"])
    with fcol2:
        df_resp = pd.DataFrame(run_query("SELECT id, nome FROM colaboradores WHERE status!='Inativo' ORDER BY nome") or [])
        mapa_resp = {int(r["id"]): r["nome"] for _, r in df_resp.iterrows()} if not df_resp.empty else {}
        filtro_resp = st.multiselect("Responsável", list(mapa_resp.values()), default=[])
    with fcol3:
        termo_busca = st.text_input("Busca livre (produto, descrição, solicitante, tipo...)").strip()

    # >>>>>> USAR CACHE
    df_base, _ = _cached_load_base()

    # Métricas seguras (quando não há OS, não há coluna 'status')
    if df_base.empty or "status" not in df_base.columns:
        total_abertas = total_exec = total_conc = 0
    else:
        total_abertas = (df_base["status"] == "Aberta").sum()
        total_exec    = (df_base["status"] == "Em Execução").sum()
        total_conc    = (df_base["status"] == "Concluída").sum()

    c1, c2, c3 = st.columns(3)
    c1.metric("⏳ Abertas", total_abertas)
    c2.metric("⚙️ Em execução", total_exec)
    c3.metric("✅ Concluídas", total_conc)
    st.caption("A coluna **!** mostra urgência (🚨). A coluna **Status** usa cor/emoji.")

    # Filtros seguros
    df_fila = df_base.copy()
    if not df_fila.empty:
        if filtro_status and "status" in df_fila.columns:
            df_fila = df_fila[df_fila["status"].isin(filtro_status)]
        if filtro_resp and "responsavel_nome" in df_fila.columns:
            df_fila = df_fila[df_fila["responsavel_nome"].isin(filtro_resp)]
        if termo_busca:
            t = termo_busca.lower()
            possiveis = ["id","produto","descricao","solicitante","tipo_servico",
                        "responsavel_nome","executor_nome","ajudantes"]
            cols_busca = [c for c in possiveis if c in df_fila.columns]
            if cols_busca:
                df_fila = df_fila[df_fila.apply(
                    lambda row: any(t in str(row.get(c, "")).lower() for c in cols_busca),
                    axis=1
                )]

    # Montagem da tabela (também segura)
    if df_fila.empty or "status" not in df_fila.columns:
        table_fila = pd.DataFrame()
    else:
        df_fila_nao_conc = df_fila[df_fila["status"] != "Concluída"].copy()
        table_fila = view_table(df_fila_nao_conc)

    # Renderização
    if table_fila.empty:
        st.info("Nenhuma OS aberta ou em execução.")
    else:
        # >>>>>> GERAR EXCEL SÓ QUANDO CLICAR
        if st.button("⬇️ Gerar Excel desta fila", use_container_width=True, key="btn_build_xlsx_fila"):
            buf = io.BytesIO()
            with pd.ExcelWriter(buf, engine="xlsxwriter") as wr:
                table_fila.to_excel(wr, sheet_name="Fila", index=False)
            st.download_button(
                "Baixar Excel (fila atual)",
                data=buf.getvalue(),
                file_name="fila_trabalho.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
                key="dl_fila"
        )
    grid_with_colors(table_fila, height=520)

        # ======= AÇÕES (OPERADOR e ADMIN) =======
    if u["role"] in ("OPERADOR", "ADMIN"):
        st.divider()
        st.subheader("Ações")

        df_os_raw = pd.DataFrame(run_query("SELECT id, status, executor_id FROM ordens_servico WHERE COALESCE(arquivada,0)=0 ORDER BY id") or [])
        df_ociosos = pd.DataFrame(run_query("SELECT id, nome FROM colaboradores WHERE status='Ocioso' ORDER BY nome") or [])
        abertas_ids = df_os_raw[df_os_raw["status"]=="Aberta"]["id"].tolist() if not df_os_raw.empty else []
        em_exec_ids = df_os_raw[df_os_raw["status"]=="Em Execução"]["id"].tolist() if not df_os_raw.empty else []

        top_left, top_right = st.columns(2)
        bottom_left, bottom_right = st.columns(2)

        # -------- INICIAR --------
        with top_left:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("### ▶️ Iniciar Ordem de serviço")

            with st.form("form_iniciar_os", clear_on_submit=False):
                if not abertas_ids:
                    st.selectbox("Ordens (Abertas)", ["—"], index=0, disabled=True, key="sb_ini_os_disabled")
                else:
                    st.selectbox("Ordens (Abertas)", abertas_ids, index=0, key="sb_ini_os")
                if df_ociosos.empty:
                    st.selectbox("Executor (ociosos)", ["—"], disabled=True)
                else:
                    st.selectbox("Executor (ociosos)", df_ociosos["nome"].tolist(), key="sb_ini_exec")
                submit_ini = st.form_submit_button("Iniciar", use_container_width=True)

            if submit_ini:
                os_iniciar = st.session_state.get("sb_ini_os")
                if not os_iniciar:
                    st.warning("Escolha uma OS aberta.")
                elif df_ociosos.empty:
                    st.warning("Não há executores ociosos.")
                else:
                    try:
                        nome_exec = st.session_state.get("sb_ini_exec")
                        exec_id = int(df_ociosos.loc[df_ociosos["nome"] == nome_exec, "id"].iloc[0])

                        aff1 = exec_rowcount("UPDATE colaboradores SET status='Em Execução' WHERE id=%s AND status='Ocioso'", (exec_id,))
                        if aff1 == 0:
                            st.warning(f"{nome_exec} não está mais ocioso.")
                            refresh_now("📋 Fila de Trabalho")

                        aff2 = exec_rowcount(
                            "UPDATE ordens_servico SET status='Em Execução', data_inicio=NOW(), executor_id=%s "
                            "WHERE id=%s AND status='Aberta' AND COALESCE(arquivada,0)=0",
                            (exec_id, int(os_iniciar))
                        )
                        if aff2 == 0:
                            exec_rowcount("UPDATE colaboradores SET status='Ocioso' WHERE id=%s AND status='Em Execução'", (exec_id,))
                            st.warning("A OS já foi iniciada por outro operador/aba.")
                            refresh_now("📋 Fila de Trabalho")
                        else:
                            st.success(f"OS {os_iniciar} iniciada por {nome_exec}.")
                            refresh_now("📋 Fila de Trabalho")

                    except Exception as e:
                        st.error(f"Erro ao iniciar: {e}")
            st.markdown('</div>', unsafe_allow_html=True)

        # -------- ENCERRAR --------
        with top_right:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("### ✅ Encerrar Ordem de serviço")

            with st.form("form_encerrar_os", clear_on_submit=False):
                if not em_exec_ids:
                    st.selectbox("Ordens (Em execução)", ["—"], index=0, disabled=True, key="sb_end_os_disabled")
                else:
                    st.selectbox("Ordens (Em execução)", em_exec_ids, index=0, key="sb_end_os")
                st.checkbox("Confirmo o encerramento desta OS", value=False, key="chk_end_confirm")
                submit_end = st.form_submit_button("Encerrar", use_container_width=True)

            if submit_end:
                os_encerrar = st.session_state.get("sb_end_os")
                confirmar = bool(st.session_state.get("chk_end_confirm", False))
                if not os_encerrar:
                    st.warning("Escolha uma OS em execução.")
                elif not confirmar:
                    st.warning("Marque a confirmação de encerramento.")
                else:
                    try:
                        os_id = int(os_encerrar)
                        ex_row = run_query("SELECT executor_id FROM ordens_servico WHERE id=%s", (os_id,)) or []
                        aj_rows = run_query("SELECT colaborador_id FROM ajudantes_os WHERE os_id=%s", (os_id,)) or []
                        exec_id = (ex_row[0]["executor_id"] if ex_row else None)

                        run_tx([
                            ("UPDATE ordens_servico SET status='Concluída', data_fim=NOW() WHERE id=%s AND status='Em Execução'", (os_id,))
                        ])

                        if exec_id:
                            ainda_exec = run_query("SELECT 1 FROM ordens_servico WHERE executor_id=%s AND status='Em Execução' LIMIT 1", (exec_id,))
                            ainda_aj = run_query("""
                                SELECT 1 FROM ajudantes_os a
                                JOIN ordens_servico o ON o.id=a.os_id
                                WHERE a.colaborador_id=%s AND o.status='Em Execução' LIMIT 1
                            """, (exec_id,))
                            if not ainda_exec and not ainda_aj:
                                run_query("UPDATE colaboradores SET status='Ocioso' WHERE id=%s", (exec_id,), commit=True)

                        for r in aj_rows:
                            cid = r["colaborador_id"]
                            tem_exec = run_query("SELECT 1 FROM ordens_servico WHERE executor_id=%s AND status='Em Execução' LIMIT 1", (cid,))
                            tem_aj   = run_query("""
                                SELECT 1 FROM ajudantes_os a
                                JOIN ordens_servico o ON o.id=a.os_id
                                WHERE a.colaborador_id=%s AND o.status='Em Execução' LIMIT 1
                            """, (cid,))
                            if not tem_exec and not tem_aj:
                                run_query("UPDATE colaboradores SET status='Ocioso' WHERE id=%s", (cid,), commit=True)

                        st.success(f"OS {os_id} concluída.")
                        refresh_now("📋 Fila de Trabalho")
                    except Exception as e:
                        st.error(f"Erro ao encerrar: {e}")
            st.markdown('</div>', unsafe_allow_html=True)

        # -------- ADICIONAR --------
        with bottom_left:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("### ➕ Adicionar colaborador")

            with st.form("form_add_col", clear_on_submit=False):
                if not em_exec_ids:
                    st.selectbox("Ordens (Em execução)", ["—"], index=0, disabled=True, key="sb_add_os_disabled")
                    os_add_val = None
                else:
                    st.selectbox("Ordens (Em execução)", em_exec_ids, index=0, key="sb_add_os")
                    os_add_val = st.session_state.get("sb_add_os")

                df_colab_add = pd.DataFrame(
                    run_query("SELECT id, nome, status FROM colaboradores WHERE status!='Inativo' ORDER BY nome") or []
                )
                if df_colab_add.empty:
                    st.selectbox("Colaborador (pode estar ocioso ou em execução)", ["—"], disabled=True, key="sb_add_col_disabled")
                else:
                    st.selectbox(
                        "Colaborador (pode estar ocioso ou em execução)",
                        df_colab_add["nome"].tolist(),
                        key="sb_add_col"
                    )

                submit_add = st.form_submit_button("Adicionar", use_container_width=True)

            if submit_add:
                os_add_col = os_add_val
                if not os_add_col:
                    st.warning("Escolha a OS.")
                elif df_colab_add.empty:
                    st.warning("Não há colaboradores disponíveis.")
                else:
                    try:
                        nome_aj = st.session_state.get("sb_add_col")
                        linha = df_colab_add.loc[df_colab_add["nome"] == nome_aj]
                        if linha.empty:
                            st.warning("Colaborador inválido.")
                        else:
                            colab_id = int(linha["id"].iloc[0])
                            colab_status = str(linha["status"].iloc[0] or "")

                            ok_os = run_query(
                                "SELECT 1 FROM ordens_servico WHERE id=%s AND status='Em Execução' AND COALESCE(arquivada,0)=0 LIMIT 1",
                                (int(os_add_col),)
                            )
                            if not ok_os:
                                st.warning("A OS não está mais em execução.")
                                refresh_now("📋 Fila de Trabalho")

                            if colab_status == "Ocioso":
                                exec_rowcount(
                                    "UPDATE colaboradores SET status='Em Execução' WHERE id=%s AND status='Ocioso'",
                                    (colab_id,)
                                )

                            try:
                                run_tx([
                                    ("INSERT INTO ajudantes_os (os_id, colaborador_id) VALUES (%s, %s)", (int(os_add_col), colab_id)),
                                ])
                                st.success(f"{nome_aj} adicionado na OS {os_add_col}.")
                                refresh_now("📋 Fila de Trabalho")
                            except Exception as e:
                                if "Duplicate" in str(e):
                                    st.info(f"{nome_aj} já é ajudante desta OS.")
                                    refresh_now("📋 Fila de Trabalho")
                                else:
                                    st.error(f"Erro ao adicionar: {e}")
                    except Exception as e:
                        st.error(f"Erro ao adicionar: {e}")
            st.markdown("</div>", unsafe_allow_html=True)

        # -------- REMOVER --------
        with bottom_right:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown("### 🗑️ Remover colaborador")

            with st.form("form_rm_col", clear_on_submit=False):
                if not em_exec_ids:
                    st.selectbox("OS (Em execução)", ["—"], index=0, disabled=True, key="sb_rm_os_disabled")
                    os_rm_val = None
                else:
                    st.selectbox("OS (Em execução)", em_exec_ids, index=0, key="sb_rm_os")
                    os_rm_val = st.session_state.get("sb_rm_os")
                if not os_rm_val:
                    st.selectbox("Ajudante", ["—"], disabled=True)
                else:
                    aj_all = pd.DataFrame(run_query("""
                        SELECT a.id, a.os_id, c.nome, a.colaborador_id
                        FROM ajudantes_os a
                        JOIN colaboradores c ON c.id = a.colaborador_id
                        WHERE a.os_id=%s
                        ORDER BY c.nome
                    """, (int(os_rm_val),)) or [])
                    if aj_all.empty:
                        st.selectbox("Ajudante", ["—"], disabled=True)
                    else:
                        st.selectbox("Ajudante", aj_all["nome"].tolist(), key="sb_rm_col")
                submit_rm = st.form_submit_button("Remover", use_container_width=True)

            if submit_rm:
                os_rm = st.session_state.get("sb_rm_os")
                nome_rm = st.session_state.get("sb_rm_col")
                if not os_rm:
                    st.warning("Escolha a OS.")
                elif 'aj_all' not in locals() or aj_all.empty or not nome_rm:
                    st.warning("Não há ajudantes para remover.")
                else:
                    try:
                        aj_id = int(aj_all[aj_all["nome"] == nome_rm]["id"].iloc[0])
                        colab_id_rm = int(aj_all[aj_all["nome"] == nome_rm]["colaborador_id"].iloc[0])
                        aff = exec_rowcount("DELETE FROM ajudantes_os WHERE id=%s", (aj_id,))
                        if aff == 0:
                            st.info("Esse ajudante já havia sido removido.")
                            refresh_now("📋 Fila de Trabalho")

                        ainda_exec = run_query("SELECT 1 FROM ordens_servico WHERE executor_id=%s AND status='Em Execução' LIMIT 1", (colab_id_rm,))
                        ainda_aj   = run_query("""
                            SELECT 1 FROM ajudantes_os a 
                            JOIN ordens_servico o ON o.id=a.os_id
                            WHERE a.colaborador_id=%s AND o.status='Em Execução' LIMIT 1
                        """, (colab_id_rm,))
                        if not ainda_exec and not ainda_aj:
                            run_query("UPDATE colaboradores SET status='Ocioso' WHERE id=%s", (colab_id_rm,), commit=True)

                        st.success(f"{nome_rm} removido da OS {os_rm}.")
                        refresh_now("📋 Fila de Trabalho")
                    except Exception as e:
                        st.error(f"Erro ao remover: {e}")
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("—")
        if st.button("🔄 Atualizar fila", use_container_width=True):
            refresh_now("📋 Fila de Trabalho")

# ---------- CONCLUÍDAS (com filtro de MÊS estável) ----------
elif menu == "✅ Concluídas":
    st.title("✅ Ordens de serviço Concluídas — Metalúrgica Bakof Tec")

    # Proteção contra base vazia (sem colunas)
    df_base, _ = _cached_load_base()
    if df_base.empty or "status" not in df_base.columns:
        df_done = pd.DataFrame()
    else:
        df_done = df_base[df_base["status"].astype(str) == "Concluída"].copy()
    if df_done.empty:
        st.info("Nenhuma OS concluída até o momento.")
    else:
        df_done["data_fim"] = pd.to_datetime(df_done["data_fim"], errors="coerce")
        df_done = df_done.dropna(subset=["data_fim"])

        df_done["mes_ano_str"] = df_done["data_fim"].dt.to_period("M").astype(str)
        meses_disp = sorted(df_done["mes_ano_str"].unique().tolist(), reverse=True)
        if not meses_disp:
            st.info("Nenhuma OS concluída com data de encerramento válida.")
        else:
            if "mes_concluidas" not in st.session_state or st.session_state["mes_concluidas"] not in meses_disp:
                st.session_state["mes_concluidas"] = meses_disp[0]

            col_f1, col_f2, col_f3 = st.columns([2,1,1])
            with col_f1:
                idx_atual = meses_disp.index(st.session_state["mes_concluidas"])
                mes_sel_ui = st.selectbox("Mês de referência", meses_disp, index=idx_atual, key="sel_mes_conc_ui")
                if mes_sel_ui != st.session_state["mes_concluidas"]:
                    st.session_state["mes_concluidas"] = mes_sel_ui
                    st.rerun()
            with col_f2:
                st.write("")
                if st.button("◀︎ Mês anterior", key="mes_prev"):
                    i = meses_disp.index(st.session_state["mes_concluidas"])
                    if i + 1 < len(meses_disp):
                        st.session_state["mes_concluidas"] = meses_disp[i + 1]
                    st.rerun()
            with col_f3:
                st.write("")
                if st.button("Mês seguinte ▶︎", key="mes_next"):
                    i = meses_disp.index(st.session_state["mes_concluidas"])
                    if i - 1 >= 0:
                        st.session_state["mes_concluidas"] = meses_disp[i - 1]
                    st.rerun()

            mes_sel = st.session_state["mes_concluidas"]
            df_mes = df_done[df_done["mes_ano_str"] == mes_sel].copy()

            # ----- ARQUIVAR MÊS EXIBIDO -----
            st.divider()
            st.subheader("📦 Arquivar (mês exibido)")
            ano, mes = mes_sel.split("-")
            with st.form("form_arquivar_mes", clear_on_submit=False):
                nome_arq = st.text_input("Nome do arquivamento", value="OS teste", help="Ex.: OS teste, Lote Setembro, etc.")
                chk = st.checkbox(f"Confirmo o arquivamento das OS concluídas de {mes}/{ano}", value=False)
                btn_arq = st.form_submit_button("Arquivar mês exibido", use_container_width=True)
            if btn_arq:
                if not chk:
                    st.warning("Marque a confirmação.")
                elif not nome_arq.strip():
                    st.warning("Informe um nome para o arquivamento.")
                else:
                    try:
                        dt_ini, dt_fim = month_bounds_from_str(mes_sel)
                        aff = exec_rowcount("""
                            UPDATE ordens_servico
                               SET arquivada=1, arquivo_nome=%s, arquivada_em=NOW(), arquivada_por=%s
                             WHERE status='Concluída'
                               AND COALESCE(arquivada,0)=0
                               AND data_fim >= %s
                               AND data_fim < %s
                        """, (nome_arq.strip(), u["id"], dt_ini, dt_fim))
                        st.success(f"Arquivamento realizado: {aff} OS marcadas como arquivadas.")
                        refresh_now("✅ Concluídas")
                    except Exception as e:
                        st.error(f"Erro ao arquivar: {e}")

            table_mes = view_table(df_mes)
            st.caption(f"Mostrando concluídas de **{mes}/{ano}** — Total: **{len(df_mes)}**")

            if table_mes.empty:
                st.info("Não há OS concluídas neste mês.")
            else:
                if st.button("⬇️ Gerar Excel (mês selecionado)", use_container_width=True, key=f"btn_build_xlsx_{mes_sel}"):
                    buf = io.BytesIO()
                    with pd.ExcelWriter(buf, engine="xlsxwriter") as wr:
                        table_mes.to_excel(wr, sheet_name=f"Concluidas_{mes_sel}", index=False)
                    st.download_button(
                        label="Baixar Excel (mês selecionado)",
                        data=buf.getvalue(),
                        file_name=f"concluidas_{mes_sel}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        use_container_width=True,
                        key=f"dl_concluidas_{mes_sel}"
                    )
                grid_with_colors(table_mes, height=560)

                # >>>>>> GRÁFICOS SOB DEMANDA
                st.divider()
                with st.expander("📈 Mostrar análises (pode demorar)", expanded=False):
                    st.subheader("📈 Análises (mês selecionado)")

                    if not df_mes.empty:
                        dados = (df_mes.assign(dia=pd.to_datetime(df_mes["data_fim"]).dt.date)
                                       .groupby(["dia","prioridade"])["id"]
                                       .count().reset_index()
                                       .rename(columns={"id":"total"}))
                        if not dados.empty:
                            df_g = pd.DataFrame(dados)
                            fig = go.Figure()
                            for pr in sorted(df_g["prioridade"].unique()):
                                sub = df_g[df_g["prioridade"] == pr]
                                fig.add_trace(go.Bar(x=sub["dia"], y=sub["total"], name=str(pr)))
                            fig.update_layout(
                                title=f"Concluídas por dia — {mes}/{ano}",
                                barmode="stack",
                                xaxis_title="Dia",
                                yaxis_title="OS concluídas",
                                legend_title="Prioridade",
                                hovermode="x unified",
                                margin=dict(l=10, r=10, t=40, b=10),
                            )
                            st.plotly_chart(fig, use_container_width=True)

                    df_lt = df_mes.copy()
                    df_lt["data_abertura"] = pd.to_datetime(df_lt["data_abertura"], errors="coerce")
                    df_lt["data_fim"] = pd.to_datetime(df_lt["data_fim"], errors="coerce")
                    df_lt = df_lt.dropna(subset=["data_abertura","data_fim"])
                    if not df_lt.empty:
                        df_lt["lead_time_dias"] = (df_lt["data_fim"].dt.date - df_lt["data_abertura"].dt.date).apply(lambda x: x.days)
                        fig_lt = px.box(df_lt, y="lead_time_dias", points="all",
                                        title=f"Lead time (dias) — {mes}/{ano}")
                        fig_lt.update_layout(margin=dict(l=10, r=10, t=40, b=10), yaxis_title="Dias")
                        st.plotly_chart(fig_lt, use_container_width=True)

                    if not df_mes.empty:
                        df_exec = df_mes.copy()
                        df_exec["executor_nome"] = df_exec["executor_nome"].fillna("—")
                        agg = df_exec.groupby("executor_nome")["id"].count().reset_index().rename(columns={"id": "Total"})
                        fig_exec = px.bar(agg.sort_values("Total", ascending=False), x="executor_nome", y="Total",
                                          title=f"OS concluídas por executor — {mes}/{ano}")
                        st.plotly_chart(fig_exec, use_container_width=True)

            # ----- ARQUIVAMENTOS RECENTES -----
            st.divider()
            st.subheader("🗃️ Arquivamentos recentes")
            arqs = run_query("""
                SELECT arquivo_nome, COUNT(*) AS total,
                       MIN(arquivada_em) AS desde, MAX(arquivada_em) AS ate
                  FROM ordens_servico
                 WHERE COALESCE(arquivada,0)=1
              GROUP BY arquivo_nome
              ORDER BY MAX(arquivada_em) DESC
              LIMIT 10
            """) or []
            df_arq = pd.DataFrame(arqs)
            if df_arq.empty:
                st.caption("Nenhum arquivamento encontrado.")
            else:
                df_arq["desde"] = _fmt_datetime_col(df_arq["desde"])
                df_arq["ate"] = _fmt_datetime_col(df_arq["ate"])
                st.dataframe(df_arq.rename(columns={
                    "arquivo_nome":"Nome do arquivamento","total":"Total de OS","desde":"Primeiro registro","ate":"Último registro"
                }), use_container_width=True, height=300)

# ---------- SOLICITANTE: criar solicitação ----------
elif menu == "📝 Solicitar OS":
    if not require_roles({"SOLICITANTE"}):
        st.stop()
    st.title("📝 Nova Solicitação de OS (aguarda aprovação do Administrador)")
    with st.form("form_solicitar_os", clear_on_submit=True):
        col1, col2, col3 = st.columns(3)
        with col1:
            solicitante_setor = st.text_input("Seu setor / identificação")
        with col2:
            produto = st.text_input("Produto/Equip.")
            tipo_servico = st.text_input("Tipo de serviço")
        with col3:
            previsao = st.date_input("Previsão (estimativa)")
        prioridade = st.selectbox("Prioridade", ["Normal", "Urgente"], index=0)
        descricao = st.text_area("Descrição do serviço")

        submit_sol = st.form_submit_button("Enviar solicitação", type="primary")
    if submit_sol:
        try:
            run_query("""
                INSERT INTO solicitacoes_os
                (data_solicitacao, solicitante_user_id, solicitante_setor, produto, tipo_servico, descricao, previsao, prioridade, status)
                VALUES (CURDATE(), %s, %s, %s, %s, %s, %s, %s, 'Pendente')
            """, (u["id"], solicitante_setor, produto, tipo_servico, descricao, previsao, prioridade), commit=True)
            st.success("Solicitação enviado! Um administrador irá analisar.")
            refresh_now("📝 Solicitar OS")
        except Exception as e:
            st.error(f"Erro ao enviar: {e}")

    st.divider()
    st.subheader("Minhas solicitações")
    minhas = run_query("""
        SELECT id, data_solicitacao, produto, tipo_servico, prioridade, status, analisado_em
        FROM solicitacoes_os
        WHERE solicitante_user_id=%s
        ORDER BY id DESC
    """, (u["id"],)) or []
    dfm = pd.DataFrame(minhas)
    if dfm.empty:
        st.info("Você ainda não possui solicitações.")
    else:
        if "data_solicitacao" in dfm.columns:
            dfm["data_solicitacao"] = _fmt_date_col(dfm["data_solicitacao"])
        if "analisado_em" in dfm.columns:
            dfm["analisado_em"] = _fmt_date_col(dfm["analisado_em"])
        st.dataframe(dfm.rename(columns={
            "id":"ID","data_solicitacao":"Data","produto":"Produto",
            "tipo_servico":"Tipo","prioridade":"Prioridade","status":"Status","analisado_em":"Analisado em"
        }), use_container_width=True, height=420)

# ---------- ADMIN: aprovar/rejeitar solicitações ----------
elif menu == "📝 Solicitações":
    if not require_roles({"ADMIN"}):
        st.stop()
    st.title("📝 Solicitações de OS — Aprovação")

    base = run_query("""
        SELECT s.*, u.nome AS solicitante_nome
        FROM solicitacoes_os s
        JOIN usuarios u ON u.id = s.solicitante_user_id
        WHERE s.status='Pendente'
        ORDER BY s.id ASC
    """) or []
    dfS = pd.DataFrame(base)

    if dfS.empty:
        st.info("Não há solicitações pendentes.")
    else:
        dfS_disp = dfS.copy()
        for c in ["data_solicitacao", "previsao", "analisado_em"]:
            if c in dfS_disp.columns:
                dfS_disp[c] = _fmt_date_col(dfS_disp[c])
        st.dataframe(
            dfS_disp[["id", "data_solicitacao", "solicitante_nome", "solicitante_setor",
                      "produto", "tipo_servico", "prioridade", "previsao", "descricao"]],
            use_container_width=True, height=400
        )

        st.divider()
        st.subheader("Analisar")
        ids = dfS["id"].tolist()

        with st.form("form_aprov", clear_on_submit=False):
            pick = st.selectbox("Solicitação", ids, index=0 if ids else None)
            resp_row = run_query("SELECT id, nome FROM colaboradores WHERE status!='Inativo' ORDER BY nome") or []
            mapa_resp = {r["nome"]: r["id"] for r in resp_row}

            col1, col2 = st.columns(2)
            with col1:
                resp_nome = st.selectbox("Definir Responsável (colaborador)", list(mapa_resp.keys()) if mapa_resp else ["—"])
            with col2:
                acao = st.radio("Ação", ["Aprovar", "Rejeitar"], horizontal=True)

            submit_ap = st.form_submit_button("Confirmar análise", use_container_width=True)

        if submit_ap and pick is not None:
            try:
                if acao == "Rejeitar":
                    run_query("""
                        UPDATE solicitacoes_os
                           SET status='Rejeitada', analisado_por=%s, analisado_em=NOW()
                         WHERE id=%s
                    """, (u["id"], pick), commit=True)
                    st.success(f"Solicitação {pick} rejeitada.")
                    refresh_now("📝 Solicitações")

                else:
                    sol = run_query("SELECT * FROM solicitacoes_os WHERE id=%s", (pick,))
                    if not sol:
                        st.error("Solicitação não encontrada.")
                    else:
                        s = sol[0]
                        resp_id = mapa_resp.get(resp_nome)
                        if not resp_id:
                            st.error("Selecione um responsável válido.")
                        else:
                            run_tx([
                                ("""
                                  INSERT INTO ordens_servico
                                    (data_abertura, solicitante, responsavel_id, produto, tipo_servico, descricao, previsao, prioridade, status)
                                  VALUES (CURDATE(), %s, %s, %s, %s, %s, %s, %s, 'Aberta')
                                 """, (s["solicitante_setor"], resp_id, s["produto"], s["tipo_servico"],
                                       s["descricao"], s["previsao"], s["prioridade"])),
                                # ✅ Corrige bug: garante que o responsável apareça nas listas de executor/ajudante
                                ("UPDATE colaboradores SET status='Ocioso' WHERE id=%s AND status='Inativo'", (resp_id,)),
                                ("UPDATE solicitacoes_os SET status='Aprovada', analisado_por=%s, analisado_em=NOW() WHERE id=%s",
                                 (u["id"], pick))
                            ])
                            st.success(f"Solicitação {pick} aprovada e OS criada!")
                            refresh_now("📋 Fila de Trabalho")
            except Exception as e:
                st.error(f"Erro ao analisar: {e}")

# ---------- ADMIN: Administração geral ----------
elif menu == "🔧 Administração":
    if not require_roles({"ADMIN"}):
        st.stop()
    st.title("🔐 Área Administrativa — Cadastro de OS")

    # ----- Cadastro de OS -----
    with st.form("cadastro_os", clear_on_submit=True):
        col1, col2, col3 = st.columns(3)
        with col1:
            solicitante = st.text_input("Solicitante/Setor")
            responsavel_id = st.number_input("ID do responsável", min_value=1, step=1)
        with col2:
            produto = st.text_input("Produto/Equip.")
            tipo_servico = st.text_input("Tipo de serviço")
        with col3:
            previsao = st.date_input("Previsão")
        prioridade = st.selectbox("Prioridade", ["Normal", "Urgente"], index=0)
        descricao = st.text_area("Descrição do serviço")
        sub_cad = st.form_submit_button("Cadastrar OS", type="primary")

    if sub_cad:
        try:
            ok_resp = run_query("SELECT 1 FROM colaboradores WHERE id=%s", (int(responsavel_id),))
            if not ok_resp:
                st.error("ID de responsável inválido ou inexistente.")
            else:
                run_query("""
                    INSERT INTO ordens_servico
                    (data_abertura, solicitante, responsavel_id, produto, tipo_servico, descricao, previsao, prioridade, status)
                    VALUES (CURDATE(), %s, %s, %s, %s, %s, %s, %s, 'Aberta')
                """, (solicitante, int(responsavel_id), produto, tipo_servico, descricao, previsao, prioridade), commit=True)
                st.success("OS cadastrada com sucesso!")
                refresh_now("📋 Fila de Trabalho")
        except Exception as e:
            st.error(f"Erro ao cadastrar OS: {e}")

    # ----- Produção (gráfico) -----
    st.subheader("📊 Produção — Visão sintetizada")
    dados = run_query("""
        SELECT DATE(data_fim) AS dia, prioridade, COUNT(*) AS total
        FROM ordens_servico
        WHERE status = 'Concluída' AND data_fim IS NOT NULL AND COALESCE(arquivada,0)=0
        GROUP BY DATE(data_fim), prioridade
        ORDER BY dia
    """) or []

    if not dados:
        st.info("Ainda não há OS concluídas para gerar gráfico.")
    else:
        df_g = pd.DataFrame(dados)
        if "prioridade" not in df_g.columns:
            df_g["prioridade"] = "Normal"
        df_g["dia"] = pd.to_datetime(df_g["dia"])
        df_g["semana"] = df_g["dia"].dt.to_period("W").apply(lambda r: r.start_time)
        sem = (df_g.groupby(["semana","prioridade"])["total"].sum().reset_index())
        pivot = sem.pivot_table(index="semana", columns="prioridade", values="total", aggfunc="sum").fillna(0)
        pivot = pivot.rename(columns={"Normal":"Normal", "Urgente":"Urgente"}).sort_index()
        serie_total = pivot.sum(axis=1)
        mm4 = serie_total.rolling(4).mean()
        fig = go.Figure()
        if "Normal" in pivot.columns:
            fig.add_trace(go.Bar(x=pivot.index, y=pivot["Normal"], name="Normal"))
        if "Urgente" in pivot.columns:
            fig.add_trace(go.Bar(x=pivot.index, y=pivot["Urgente"], name="Urgente"))
        fig.add_trace(go.Scatter(x=mm4.index, y=mm4.values, mode="lines",
                                 name="Média móvel (4 sem)", line=dict(width=3)))
        fig.update_layout(
            title="Throughput semanal por prioridade",
            barmode="stack",
            xaxis_title="Semana",
            yaxis_title="OS concluídas",
            legend_title="Legenda",
            hovermode="x unified",
            margin=dict(l=10, r=10, t=40, b=10),
        )
        st.plotly_chart(fig, use_container_width=True)

    # ======= Gestão de Colaboradores (DENTRO de '🔧 Administração') =======
    st.divider()
    st.subheader("👥 Gestão de Colaboradores")

    df_colabs = _cached_listar_colaboradores()
    if df_colabs.empty:
        st.info("Nenhum colaborador cadastrado ainda.")
    else:
        st.caption("Lista atual de colaboradores")
        st.dataframe(
            df_colabs.rename(columns={"id": "ID", "nome": "Nome", "status": "Status"}),
            use_container_width=True,
            height=280
        )

    st.markdown("### ➕ Adicionar novo colaborador")
    with st.form("form_add_colab", clear_on_submit=True):
        col1, col2 = st.columns([2, 1])
        with col1:
            novo_nome = st.text_input("Nome do colaborador", placeholder="Ex.: João da Silva")
        with col2:
            novo_status = st.selectbox("Status inicial", ["Ocioso", "Em Execução", "Inativo"], index=0)
        btn_add = st.form_submit_button("Adicionar", type="primary")

    if btn_add:
        if not novo_nome.strip():
            st.warning("Informe um nome válido.")
        else:
            try:
                run_query(
                    "INSERT INTO colaboradores (nome, status) VALUES (%s, %s)",
                    (novo_nome.strip(), novo_status), commit=True
                )
                st.success(f"Colaborador '{novo_nome.strip()}' adicionado.")
                refresh_now("🔧 Administração")
            except Exception as e:
                st.error(f"Erro ao adicionar colaborador: {e}")

    st.markdown("---")
    st.markdown("### 🗑️ Excluir / Inativar colaborador")

    if df_colabs.empty:
        st.info("Não há colaboradores para excluir/inativar.")
    else:
        colE1, colE2, colE3 = st.columns([2, 1, 1])
        with colE1:
            nome_lista = df_colabs["nome"].tolist()
            escolha = st.selectbox("Selecione o colaborador", nome_lista, index=0)
            colab_id = int(df_colabs.loc[df_colabs["nome"] == escolha, "id"].iloc[0])
            colab_status_atual = str(df_colabs.loc[df_colabs["nome"] == escolha, "status"].iloc[0])
        with colE2:
            acao = st.radio("Ação", ["Excluir definitivamente", "Inativar"], horizontal=False)
        with colE3:
            st.write("")
            st.write(f"**Status atual:** {colab_status_atual}")

        # Referências (ativos/concluídos)
        refs = colaborador_refs_detalhe(colab_id)
        tem_ativos = refs["ativos"] > 0
        tem_conc = refs["concluidas"] > 0

        btn_col1, _ = st.columns([1, 3])
        with btn_col1:
            if acao == "Excluir definitivamente":
                if tem_ativos:
                    st.button("Excluir", disabled=True, use_container_width=True)
                    st.caption("⚠️ Há vínculos em OS Abertas/Em Execução. Remova os vínculos ou conclua as OS. (Você pode Inativar temporariamente.)")
                else:
                    if tem_conc:
                        st.caption(f"ℹ️ Vínculos apenas em OS concluídas ({refs['concluidas']}). Serão removidos automaticamente na exclusão.")
                    if st.button("Excluir", type="primary", use_container_width=True):
                        try:
                            run_tx([
                                ("UPDATE ordens_servico SET executor_id=NULL WHERE executor_id=%s", (colab_id,)),
                                ("UPDATE ordens_servico SET responsavel_id=NULL WHERE responsavel_id=%s", (colab_id,)),
                                ("DELETE FROM ajudantes_os WHERE colaborador_id=%s", (colab_id,)),
                                ("DELETE FROM colaboradores WHERE id=%s", (colab_id,))
                            ])
                            st.success(f"Colaborador '{escolha}' excluído.")
                            refresh_now("🔧 Administração")
                        except Exception as e:
                            st.error(f"Erro ao excluir: {e}")
            else:
                if st.button("Inativar", type="primary", use_container_width=True):
                    try:
                        run_query("UPDATE colaboradores SET status='Inativo' WHERE id=%s", (colab_id,), commit=True)
                        st.success(f"Colaborador '{escolha}' marcado como Inativo.")
                        refresh_now("🔧 Administração")
                    except Exception as e:
                        st.error(f"Erro ao inativar: {e}")

# ---------- MINHA SENHA ----------
elif menu == "🔑 Minha Senha":
    st.title("🔑 Alterar minha senha")

    with st.form("form_minha_senha", clear_on_submit=False):
        col1, col2, col3 = st.columns(3)
        with col1:
            senha_atual = st.text_input("Senha atual", type="password")
        with col2:
            nova_senha = st.text_input("Nova senha", type="password", help="Mínimo 8, com maiúscula, minúscula e número")
        with col3:
            conf_senha = st.text_input("Confirmar nova senha", type="password")
        submit = st.form_submit_button("Salvar nova senha", type="primary", use_container_width=True)

    if submit:
        try:
            if not senha_atual or not nova_senha or not conf_senha:
                st.warning("Preencha todos os campos.")
            elif nova_senha != conf_senha:
                st.error("A confirmação não confere.")
            elif not validar_senha_forte(nova_senha):
                st.error(erro_politica_senha())
            else:
                row = run_query("SELECT senha_hash FROM usuarios WHERE id=%s AND ativo=1", (u["id"],))
                if not row or not verify_password(senha_atual, row[0]["senha_hash"]):
                    st.error("Senha atual incorreta.")
                else:
                    set_user_password(u["id"], nova_senha)
                    st.success("Senha alterada com sucesso! Faça login novamente.")
                    auth_logout()
                    st.rerun()
        except Exception as e:
            st.error(f"Erro ao alterar senha: {e}")

# ===== Rodapé fixo =====
st.markdown(
    """
    <style>
      .gcf-footer {
        position: fixed;
        right: 14px;
        bottom: 10px;
        font-size: 12px;
        opacity: 0.85;
        z-index: 9999;
      }
      .gcf-footer a { text-decoration: none; }
    </style>
    <div class="gcf-footer">
      Desenvolvido por <strong>GCF Softwares</strong> — <strong>Gabriel</strong> · (55) 9 9729-7609 ·
      <a href="https://wa.me/5555997609" target="_blank">WhatsApp</a>
    </div>
    """,
    unsafe_allow_html=True
)
