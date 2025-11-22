import { useState, useEffect } from "react";
import { sendGoogleCode, verify2FA } from "./api";
import { useGoogleLogin } from "@react-oauth/google";

export default function Login({ onAuth }) {
  const [step, setStep] = useState("login"); // 'login' ou '2fa'
  const [tempUsername, setTempUsername] = useState(""); // Guarda o email enquanto espera o codigo
  const [otpCode, setOtpCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [notify, setNotify] = useState(null);

  useEffect(() => {
    if (!notify) return;
    const t = setTimeout(() => setNotify(null), 4000);
    return () => clearTimeout(t);
  }, [notify]);

  const handleGoogleLogin = useGoogleLogin({
    flow: "auth-code",
    onSuccess: async (codeResponse) => {
      setBusy(true);
      try {
        // Passo 1: Envia código do Google
        const data = await sendGoogleCode(codeResponse.code);
        
        // Se o backend retornou que precisa de 2FA
        if (data.require_2fa) {
          setTempUsername(data.username);
          setStep("2fa");
          setNotify({ type: "success", text: `Código enviado para ${data.username}` });
        } else {
          // Caso o backend decida logar direto (ex: 2FA desativado ou opcional)
          onAuth({
            username: data.username,
            token: data.token,
            privateKey: data.private_key,
            publicKey: data.public_key,
          });
        }
      } catch (e) {
        const msg = e?.response?.data?.detail || "Erro no login";
        setNotify({ type: "error", text: msg });
      } finally {
        setBusy(false);
      }
    },
    onError: () => setNotify({ type: "error", text: "Falha no Google Login" }),
  });

  async function submitOTP() {
    if (otpCode.length !== 6) {
      setNotify({ type: "error", text: "Digite o código de 6 dígitos." });
      return;
    }
    setBusy(true);
    try {
      // Passo 2: Envia o código do E-mail para validação final
      const data = await verify2FA(tempUsername, otpCode);
      
      // Sucesso! Recebemos o token e as chaves
      onAuth({
        username: data.username,
        token: data.token,
        privateKey: data.private_key,
        publicKey: data.public_key,
      });
    } catch (e) {
      const msg = e?.response?.data?.detail || "Código inválido ou expirado";
      setNotify({ type: "error", text: msg });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <div className="glass-card auth-card enter-pop">
        
        {step === "login" && (
          <>
            <div className="title" style={{ height: 2 }}></div>
            <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 20 }}>
              <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800 }}>Acessar</h2>
              <div style={{ color: "var(--muted)", fontSize: 13 }}>Mensagens seguras</div>
            </div>

            <button 
              className="primary" 
              onClick={() => handleGoogleLogin()} 
              disabled={busy}
              style={{ width: '100%', marginTop: 16 }}
            >
              {busy ? "Conectando..." : "Entrar com Google"}
            </button>
          </>
        )}

        {step === "2fa" && (
          <>
            <div style={{ marginBottom: 20 }}>
              <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800 }}>Verificação</h2>
              <div className="muted" style={{ marginTop: 8 }}>Digite o código enviado para seu e-mail</div>
            </div>
            
            <div className="input" style={{ marginTop: 10 }}>
              <input 
                placeholder="000000"
                value={otpCode}
                onChange={e => setOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                style={{ textAlign: 'center', fontSize: 24, letterSpacing: 4, fontWeight: 'bold' }}
                onKeyDown={(e) => e.key === "Enter" && submitOTP()}
              />
            </div>

            <button 
              className="primary" 
              onClick={submitOTP} 
              disabled={busy}
              style={{ width: '100%', marginTop: 16 }}
            >
              {busy ? "Verificando..." : "Confirmar Código"}
            </button>
            
            <button 
              className="ghost"
              onClick={() => setStep("login")}
              style={{ marginTop: 10, fontSize: 12, width: '100%', border: 'none' }}
            >
              Voltar
            </button>
          </>
        )}

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