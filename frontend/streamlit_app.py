# frontend/streamlit_app.py
import streamlit as st
from api_client import register, login, list_users, create_conversation, session_info, send_message, list_messages, rekey_remove
from crypto_client import generate_rsa_keypair, rsa_decrypt, blowfish_encrypt, blowfish_decrypt

st.set_page_config(page_title="Chat E2EE (RSA+Blowfish)", layout="centered")

# --- estado ---
if "priv_pem" not in st.session_state:
    st.session_state.priv_pem = None
if "pub_pem" not in st.session_state:
    st.session_state.pub_pem = None
if "token" not in st.session_state:
    st.session_state.token = ""
if "user" not in st.session_state:
    st.session_state.user = {"id": None, "username": None}
if "conv_keys" not in st.session_state:
    # {conv_id: {version: key_bytes}}
    st.session_state.conv_keys = {}
if "current_conv" not in st.session_state:
    st.session_state.current_conv = None

st.title("🔐 Chat Híbrido (RSA ➜ Blowfish)")

# --- seção 1: chaves RSA locais ---
st.header("1) Minhas chaves RSA (locais)")
col1, col2 = st.columns(2)
with col1:
    if st.button("Gerar par RSA (2048)"):
        priv, pub = generate_rsa_keypair()
        st.session_state.priv_pem = priv
        st.session_state.pub_pem = pub
        st.success("Gerado! Guarde a privada, ela NÃO sai do seu dispositivo.")
with col2:
    if st.session_state.pub_pem:
        st.download_button("Baixar minha chave privada", st.session_state.priv_pem, file_name="rsa_private.pem")
st.text_area("Chave pública (envia ao servidor)", st.session_state.pub_pem or "", height=120)

# --- seção 2: registro/login ---
st.header("2) Registro / Login")
with st.form("auth"):
    username = st.text_input("Usuário")
    password = st.text_input("Senha", type="password")
    action = st.selectbox("Ação", ["Registrar", "Login"])
    ok = st.form_submit_button("OK")
    if ok:
        try:
            if action == "Registrar":
                if not st.session_state.pub_pem:
                    st.warning("Gere sua RSA e deixe a PÚBLICA preenchida acima.")
                else:
                    st.session_state.token = register(username, password, st.session_state.pub_pem)
                    st.session_state.user = {"id": None, "username": username}
                    st.success("Registrado e logado!")
            else:
                st.session_state.token = login(username, password)
                st.session_state.user = {"id": None, "username": username}
                st.success("Logado!")
        except Exception as e:
            st.error(f"Erro: {e}")

if not st.session_state.token:
    st.stop()

# --- seção 3: usuários e criação de conversa/grupo ---
st.header("3) Criar conversa/grupo")
users = list_users()
st.caption("Selecione os membros (incluindo você). Dica: veja os IDs listados abaixo.")
st.json(users)

member_ids_input = st.text_input("IDs dos membros separados por vírgula (ex.: 1,2  para 1:1)")
name = st.text_input("Nome do grupo (opcional)")

if st.button("Criar conversa"):
    try:
        member_ids = [int(x.strip()) for x in member_ids_input.split(",") if x.strip()]
        resp = create_conversation(st.session_state.token, member_ids, name or None)
        st.session_state.current_conv = resp["conversation_id"]
        st.success(f"Conversa criada: ID {st.session_state.current_conv} (key_version {resp['key_version']})")
    except Exception as e:
        st.error(f"Erro: {e}")

# escolher conversa atual manualmente
conv_id_manual = st.text_input("ID da conversa atual (se já souber)", value=str(st.session_state.current_conv or ""))
if conv_id_manual:
    try:
        st.session_state.current_conv = int(conv_id_manual)
    except:
        pass

if not st.session_state.current_conv:
    st.stop()

# --- seção 4: obter/armazenar chave de sessão (decifra com RSA privada) ---
st.header("4) Chave de sessão (Blowfish) da conversa")
if st.button("Obter/atualizar minha session key"):
    try:
        info = session_info(st.session_state.token, st.session_state.current_conv)
        key_version = info["key_version"]
        enc_b64 = info["session_key_encrypted_b64"]
        key_bytes = rsa_decrypt(st.session_state.priv_pem, enc_b64)
        st.session_state.conv_keys.setdefault(st.session_state.current_conv, {})[key_version] = key_bytes
        st.success(f"Chave da conversa {st.session_state.current_conv} armazenada (versão {key_version}).")
    except Exception as e:
        st.error(f"Erro: {e}")

st.write("Chaves que você já guardou (por conversa/versão):")
st.json({str(k): {str(v): f"{len(b)} bytes" for v,b in d.items()} for k,d in st.session_state.conv_keys.items()})

# --- seção 5: enviar mensagem (cifra com Blowfish) ---
st.header("5) Enviar mensagem")
msg = st.text_input("Mensagem")
vers = st.number_input("key_version para cifrar", min_value=1, value=max(st.session_state.conv_keys.get(st.session_state.current_conv, {1:b''}).keys(), default=1))
if st.button("Enviar"):
    try:
        key_map = st.session_state.conv_keys.get(st.session_state.current_conv, {})
        if vers not in key_map:
            st.warning("Você ainda não guardou a chave dessa versão. Clique em 'Obter/atualizar minha session key'.")
        else:
            payload = blowfish_encrypt(key_map[vers], msg, st.session_state.current_conv)
            send_message(st.session_state.token, st.session_state.current_conv, payload["iv"], payload["ciphertext"], payload["hmac"], vers)
            st.success("Enviado!")
    except Exception as e:
        st.error(f"Erro: {e}")

# --- seção 6: ler mensagens (decifra localmente) ---
st.header("6) Mensagens")
if st.button("Atualizar mensagens"):
    try:
        msgs = list_messages(st.session_state.token, st.session_state.current_conv, limit=100)
        out = []
        for m in msgs:
            key_map = st.session_state.conv_keys.get(st.session_state.current_conv, {})
            text = "(sem chave para esta versão)"
            if m["key_version"] in key_map:
                try:
                    text = blowfish_decrypt(key_map[m["key_version"]], m["iv"], m["ciphertext"], m["hmac"], st.session_state.current_conv)
                except Exception as de:
                    text = f"[HMAC falhou / chave errada] {de}"
            out.append(f"#{m['id']}  v{m['key_version']}  from {m['sender_id']}: {text}")
        st.text("\n".join(out) if out else "(sem mensagens)")
    except Exception as e:
        st.error(f"Erro: {e}")

# --- seção 7: rekey (remover alguém do grupo) ---
st.header("7) Remover membro (REKEY)")
rem_id = st.text_input("ID do usuário a remover do grupo (rekey)")
if st.button("Remover e gerar nova chave"):
    try:
        resp = rekey_remove(st.session_state.token, st.session_state.current_conv, int(rem_id))
        st.success(f"Rekey feito. Nova versão: {resp['key_version']}. Clique em 'Obter/atualizar minha session key'.")
    except Exception as e:
        st.error(f"Erro: {e}")
