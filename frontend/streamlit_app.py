import time
import streamlit as st
from api_client import register, login, update_pubkey, list_users, create_conversation, session_info, rotate_key, send_message, list_messages, rekey_remove
from crypto_client import ensure_rsa_keypair, rsa_decrypt, blowfish_encrypt, blowfish_decrypt

st.set_page_config(page_title="Chat E2EE", layout="centered")

if "priv_pem" not in st.session_state:
    st.session_state.priv_pem = None
if "pub_pem" not in st.session_state:
    st.session_state.pub_pem = None
if "token" not in st.session_state:
    st.session_state.token = ""
if "me" not in st.session_state:
    st.session_state.me = None
if "me_id" not in st.session_state:
    st.session_state.me_id = None
if "conv_keys" not in st.session_state:
    st.session_state.conv_keys = {}
if "current_conv" not in st.session_state:
    st.session_state.current_conv = None
if "auto_refresh" not in st.session_state:
    st.session_state.auto_refresh = True
if "last_pull" not in st.session_state:
    st.session_state.last_pull = 0

ensure_rsa_keypair(st.session_state)

st.title("🔐 Chat Seguro")
with st.container():
    c1, c2 = st.columns(2)
    with c1:
        user = st.text_input("Usuário")
    with c2:
        pw = st.text_input("Senha", type="password")
    c3, c4 = st.columns(2)
    with c3:
        if st.button("Entrar"):
            try:
                st.session_state.token = login(user, pw)
                st.session_state.me = user
                update_pubkey(st.session_state.token, st.session_state.pub_pem)
                users = list_users()
                mine = [u for u in users if u["username"] == user]
                st.session_state.me_id = mine[0]["id"] if mine else None
                print(f"ui: logged in me_id={st.session_state.me_id}")
            except Exception as e:
                st.error(str(e))
    with c4:
        if st.button("Registrar e Entrar"):
            try:
                st.session_state.token = register(user, pw, st.session_state.pub_pem)
                st.session_state.me = user
                users = list_users()
                mine = [u for u in users if u["username"] == user]
                st.session_state.me_id = mine[0]["id"] if mine else None
                print(f"ui: registered me_id={st.session_state.me_id}")
            except Exception as e:
                st.error(str(e))

if not st.session_state.token:
    st.stop()

st.subheader("Pessoas e Conversas")
u = list_users()
ids = [str(x["id"])+" • "+x["username"] for x in u]
st.caption("Selecione membros pelo ID")
members = st.multiselect("Membros", ids)
name = st.text_input("Nome do grupo (opcional)")
c5, c6 = st.columns(2)
with c5:
    if st.button("Criar conversa"):
        try:
            mids = [int(x.split(" • ")[0]) for x in members]
            if st.session_state.me_id and st.session_state.me_id not in mids:
                mids.append(st.session_state.me_id)
            r = create_conversation(st.session_state.token, mids, name or None)
            st.session_state.current_conv = r["conversation_id"]
            print(f"ui: conversation {st.session_state.current_conv}")
        except Exception as e:
            st.error(str(e))
with c6:
    conv_id_input = st.text_input("ID da conversa atual", value=str(st.session_state.current_conv or ""))
    if st.button("Usar conversa"):
        try:
            st.session_state.current_conv = int(conv_id_input)
            print(f"ui: set conversation {st.session_state.current_conv}")
        except:
            pass

if not st.session_state.current_conv:
    st.stop()

st.subheader("Chave da Conversa")
c7, c8 = st.columns(2)
with c7:
    if st.button("Obter/Atualizar minha chave"):
        try:
            info = session_info(st.session_state.token, st.session_state.current_conv)
            kv = info["key_version"]
            enc = info["session_key_encrypted_b64"]
            try:
                key_bytes = rsa_decrypt(st.session_state.priv_pem, enc)
            except Exception as e:
                print("ui: decrypt failed, syncing pubkey and rotating")
                update_pubkey(st.session_state.token, st.session_state.pub_pem)
                rotate_key(st.session_state.token, st.session_state.current_conv)
                info = session_info(st.session_state.token, st.session_state.current_conv)
                kv = info["key_version"]
                enc = info["session_key_encrypted_b64"]
                key_bytes = rsa_decrypt(st.session_state.priv_pem, enc)
            st.session_state.conv_keys.setdefault(st.session_state.current_conv, {})[kv] = key_bytes
            st.success(f"Versão {kv} armazenada")
            print(f"ui: key stored v{kv}")
        except Exception as e:
            st.error(str(e))
with c8:
    st.toggle("Auto atualizar mensagens", value=st.session_state.auto_refresh, key="auto_refresh")

st.caption("Chaves armazenadas")
st.json({str(k): {str(v): f"{len(b)} bytes" for v,b in d.items()} for k,d in st.session_state.conv_keys.items()})

st.subheader("Chat")
msg = st.text_input("Mensagem")
kv_default = max(st.session_state.conv_keys.get(st.session_state.current_conv, {1:b''}).keys(), default=1)
kv = st.number_input("Versão da chave", min_value=1, value=kv_default)
c9, c10 = st.columns(2)
with c9:
    if st.button("Enviar"):
        try:
            kmap = st.session_state.conv_keys.get(st.session_state.current_conv, {})
            if kv not in kmap:
                st.warning("Obtenha a chave")
            else:
                payload = blowfish_encrypt(kmap[kv], msg, st.session_state.current_conv)
                send_message(st.session_state.token, st.session_state.current_conv, payload["iv"], payload["ciphertext"], payload["hmac"], kv)
                st.session_state.last_pull = 0
        except Exception as e:
            st.error(str(e))
with c10:
    rid = st.text_input("Remover usuário (ID)")
    if st.button("Rekey"):
        try:
            r = rekey_remove(st.session_state.token, st.session_state.current_conv, int(rid))
            st.success(f"Nova versão {r['key_version']}")
            print(f"ui: rekey to {r['key_version']}")
        except Exception as e:
            st.error(str(e))

def pull_messages():
    try:
        msgs = list_messages(st.session_state.token, st.session_state.current_conv, limit=100)
        out = []
        for m in msgs:
            text = "(sem chave)"
            km = st.session_state.conv_keys.get(st.session_state.current_conv, {})
            if m["key_version"] in km:
                try:
                    text = blowfish_decrypt(km[m["key_version"]], m["iv"], m["ciphertext"], m["hmac"], st.session_state.current_conv)
                except Exception as de:
                    text = f"[falha HMAC] {de}"
            out.append((m["id"], m["key_version"], m["sender_id"], text))
        return out
    except Exception as e:
        st.error(str(e))
        return []

if st.session_state.auto_refresh or st.button("Atualizar"):
    now = time.time()
    if now - st.session_state.last_pull > 1.5:
        st.session_state.last_pull = now
        print("ui: pulling messages")

msgs = pull_messages()
for m in msgs:
    st.write(f"#{m[0]} v{m[1]} de {m[2]}: {m[3]}")
