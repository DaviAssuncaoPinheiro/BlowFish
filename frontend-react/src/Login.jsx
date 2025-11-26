import { useState, useEffect } from "react";
import { sendGoogleCode, verify2FA, completeRegistration } from "./api";
import { useGoogleLogin } from "@react-oauth/google";

export default function Login({ onAuth }) {
  const [step, setStep] = useState("login"); // 'login', 'register', '2fa'
  const [tempUsername, setTempUsername] = useState(""); 
  const [registerToken, setRegisterToken] = useState(""); // Token temporário para registro
  const [newUsername, setNewUsername] = useState(""); // Input do novo usuário
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
        const data = await sendGoogleCode(codeResponse.code);
        
        if (data.status === "REGISTRATION_REQUIRED") {
          // Usuário novo: vai para tela de escolha de nome
          setRegisterToken(data.register_token);
          setStep("register");
          setNotify({ type: "success", text: "Google autenticado! Escolha seu usuário." });
        } else if (data.status === "2FA_REQUIRED") {
          // Usuário existente: vai para 2FA
          setTempUsername(data.username);
          setStep("2fa");
          setNotify({ type: "success", text: `Código enviado para o e-mail.` });
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

  async function submitUsername() {
    if (!newUsername.trim()) {
      setNotify({ type: "error", text: "Digite um nome de usuário." });
      return;
    }
    setBusy(true);
    try {
      // Envia o nome escolhido + o token que prova que é ele no Google
      const data = await completeRegistration(newUsername.trim(), registerToken);
      
      // Se der certo, o backend já manda o código 2FA
      if (data.status === "2FA_REQUIRED") {
        setTempUsername(data.username);
        setStep("2fa");
        setNotify({ type: "success", text: "Conta criada! Código enviado para seu e-mail." });
      }
    } catch (e) {
        const msg = e?.response?.data?.detail || "Erro ao criar conta";
        setNotify({ type: "error", text: msg });
    } finally {
        setBusy(false);
    }
  }

  async function submitOTP() {
    if (otpCode.length !== 6) {
      setNotify({ type: "error", text: "Digite o código de 6 dígitos." });
      return;
    }
    setBusy(true);
    try {
      const data = await verify2FA(tempUsername, otpCode);
      
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
              <div style={{ color: "var(--muted)", fontSize: 13 }}>Secure Chat v2.0</div>
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

        {step === "register" && (
          <>
            <div style={{ marginBottom: 20 }}>
              <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800 }}>Criar Conta</h2>
              <div className="muted">Escolha como você será visto no chat</div>
            </div>
            
            <div className="input" style={{ marginTop: 10 }}>
              <input 
                placeholder="Nome de Usuário"
                value={newUsername}
                onChange={e => setNewUsername(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && submitUsername()}
              />
            </div>

            <button 
              className="primary" 
              onClick={submitUsername} 
              disabled={busy}
              style={{ width: '100%', marginTop: 16 }}
            >
              {busy ? "Criar e Enviar Código" : "Continuar"}
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
              Cancelar
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