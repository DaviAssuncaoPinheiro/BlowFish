import { useState, useEffect } from "react";
// Importações de API atualizadas
import { sendGoogleCode } from "./api";
// Importação do hook de login do Google
import { useGoogleLogin } from "@react-oauth/google";

export default function Login({ onAuth }) {
  const [busy, setBusy] = useState(false);
  const [notify, setNotify] = useState(null);

  useEffect(() => {
    if (!notify) return;
    const t = setTimeout(() => setNotify(null), 4000);
    return () => clearTimeout(t);
  }, [notify]);

  // Função de login com Google
  const handleGoogleLogin = useGoogleLogin({
    // 'flow: "auth-code"' é a parte mais importante.
    // Ele nos dá um 'code' para enviar ao backend.
    flow: "auth-code",
    onSuccess: async (codeResponse) => {
      console.log("Google respondeu com o código:", codeResponse.code);
      setBusy(true);
      try {
        // Envia o código para o nosso backend
        const data = await sendGoogleCode(codeResponse.code);
        
        // 'data' é o nosso TokenOut (token, username, private_key, public_key)
        // A função onAuth do App.jsx espera { username, token, privateKey, publicKey }
        onAuth({
          username: data.username, // O username vem do backend
          token: data.token,
          privateKey: data.private_key,
          publicKey: data.public_key,
        });
        
      } catch (e) {
        const message =
          e?.response?.data?.detail || e?.message || "Falha na operação";
        setNotify({ type: "error", text: message });
      } finally {
        setBusy(false);
      }
    },
    onError: (error) => {
      console.error("Falha no login com Google:", error);
      setNotify({ type: "error", text: "Falha no login com Google." });
    },
  });

  return (
    <div className="auth-wrap">
      <div className="glass-card auth-card enter-pop">
        <div className="title" style={{ height: 2 }}></div>
        <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 20 }}>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800 }}>Acessar</h2>
          <div style={{ color: "var(--muted)", fontSize: 13 }}>Mensagens seguras</div>
        </div>
        
        {/* O formulário antigo foi removido */}
        
        <button 
          className="primary" 
          onClick={() => handleGoogleLogin()} 
          disabled={busy}
          style={{ width: '100%', marginTop: 16 }}
        >
          {busy ? "Aguarde..." : "Entrar com Google"}
        </button>

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