import time
import streamlit as st
from api_client import register, login, list_users, send_message, history

st.set_page_config(page_title="Chat E2EE", layout="centered")

if "token" not in st.session_state:
    st.session_state.token = ""
if "me" not in st.session_state:
    st.session_state.me = None
if "peer" not in st.session_state:
    st.session_state.peer = None

st.title("🔐 Chat Seguro (E2EE)")

if not st.session_state.token:
    login_tab, register_tab = st.tabs(["Login", "Registrar"])

    with login_tab:
        user = st.text_input("Usuário", key="login_user")
        pw = st.text_input("Senha", type="password", key="login_pass")
        if st.button("Entrar"):
            try:
                st.session_state.token = login(user, pw)
                st.session_state.me = user
                st.success("Login realizado com sucesso!")
            except Exception as e:
                st.error(str(e))

    with register_tab:
        user = st.text_input("Novo usuário", key="reg_user")
        pw = st.text_input("Nova senha", type="password", key="reg_pass")
        if st.button("Registrar e Entrar"):
            try:
                st.session_state.token = register(user, pw)
                st.session_state.me = user
                st.success("Registro e login realizados com sucesso!")
            except Exception as e:
                st.error(str(e))

    st.stop()

st.sidebar.markdown(f"**Bem-vindo, {st.session_state.me}!**")
try:
    users = list_users(st.session_state.token)
except Exception as e:
    st.sidebar.error(str(e))
    users = []

st.sidebar.subheader("Usuários")
if not users:
    st.sidebar.info("Nenhum outro usuário.")
else:
    for u in users:
        uname = u["username"]
        if st.sidebar.button(uname):
            st.session_state.peer = uname

if st.sidebar.button("Sair"):
    st.session_state.clear()
    st.rerun()

if not st.session_state.peer:
    st.info("Selecione um usuário na barra lateral para iniciar uma conversa.")
    st.stop()

peer = st.session_state.peer
st.subheader(f"Chat com {peer}")

# Atualização automática universal (sem autorefresh)
placeholder = st.empty()
time.sleep(2)
st.experimental_set_query_params(_=int(time.time()))
placeholder.empty()

def pull():
    try:
        return history(st.session_state.token, peer)
    except Exception as e:
        st.error(str(e))
        return []

msgs = pull()
for m in msgs:
    is_me = (m["sender_username"] == st.session_state.me)
    align = "flex-end" if is_me else "flex-start"
    bg = "#4CAF50" if is_me else "#1E1E1E"
    text_color = "#FFFFFF" if is_me else "#DDDDDD"
    border = "1px solid #4CAF50" if is_me else "1px solid #333"
    st.markdown(
        f"""
        <div style="display:flex; justify-content:{align}; margin:6px 0;">
            <div style="max-width:70%; padding:10px 14px; background:{bg};
                        border-radius:8px; border:{border}; color:{text_color};
                        font-family:Segoe UI, sans-serif;">
                <div style="font-size:12px; opacity:0.8;">
                    {m['sender_username']} — <em>{m['timestamp']}</em>
                </div>
                <div style="margin-top:4px; white-space:pre-wrap;">
                    {m['plaintext']}
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

st.divider()
msg = st.text_area("Mensagem", height=100)
if st.button("Enviar"):
    if not msg.strip():
        st.warning("Digite uma mensagem.")
    else:
        try:
            send_message(st.session_state.token, peer, msg.strip())
            st.success("Mensagem enviada!")
            time.sleep(0.2)
            st.rerun()
        except Exception as e:
            st.error(str(e))
