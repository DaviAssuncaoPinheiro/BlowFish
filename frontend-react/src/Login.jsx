import { useState, useEffect } from "react";
import { login, register } from "./api";

export default function Login({ onAuth }) {
  const [tab, setTab] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [notify, setNotify] = useState(null);

  useEffect(() => {
    if (!notify) return;
    const t = setTimeout(() => setNotify(null), 4000);
    return () => clearTimeout(t);
  }, [notify]);



  async function submit() {
    if (!username.trim() || !password.trim()) {
      setNotify({ type: "error", text: "Preencha usuário e senha." });
      return;
    }
    setBusy(true);
    try {
      const fn = tab === "login" ? login : register;
      const data = await fn(username.trim(), password.trim());
      onAuth({ 
        username: username.trim(), 
        token: data.token, 
        privateKey: data.private_key, 
        publicKey: data.public_key 
      });
    } catch (e) {
      const message =
        e?.response?.data?.detail ||
        e?.response?.data?.message ||
        e?.message ||
        "Falha na operação";
      setNotify({ type: "error", text: message });
    } finally {
      setBusy(false);
    }
  }



  return (
    <div className="auth-wrap">
      <div className="glass-card auth-card enter-pop">
        <div className="title" style={{ height: 2 }}></div>
        <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 6 }}>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800 }}>Acessar</h2>
          <div style={{ color: "var(--muted)", fontSize: 13 }}>Mensagens seguras</div>
        </div>
        <div className="tabs">
          <button className={tab === "login" ? "active" : ""} onClick={() => setTab("login")}>Entrar</button>
          <button className={tab === "register" ? "active" : ""} onClick={() => setTab("register")}>Registrar</button>
          <div className={`pill ${tab}`} />
        </div>

        <div className="form" style={{ marginTop: 16 }}>
          <div className="input">
            <input
              placeholder="Usuário"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submit()}
            />
          </div>
          <div className="input">
            <input
              placeholder="Senha"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submit()}
            />
          </div>
          <button className="primary" onClick={submit} disabled={busy}>
            {busy ? "Aguarde..." : tab === "login" ? "Entrar" : "Criar conta"}
          </button>
        </div>
      </div>

      <div className="bg fx-a" />
      <div className="bg fx-b" />
      <div className="bg fx-c" />

      {notify && (
        <div className={`toast ${notify.type === "error" ? "error" : "success"}`}>
          {notify.text}
        </div>
      )}
    </div>
  );
}
