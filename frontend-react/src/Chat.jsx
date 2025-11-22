import { useEffect, useState, useRef, useMemo } from "react";
import {
  getUsers,
  sendMessage,
  getHistory,
  connectSocket,
  listGroups,
  createGroup,
  groupHistory,
  groupSend,
  groupRemoveMember,
  groupAddMember,
  getUserPublicKey,
} from "./api";
import {
  rsaEncrypt,
  rsaDecrypt,
  blowfishEncrypt,
  blowfishDecrypt,
  generateRandomBytes,
  uint8ToBase64,
  base64ToUint8,
  importRsaPrivateKey,
  importRsaPublicKey,
  generateHMAC 
} from "./crypto";

export default function Chat({ me, token, onLogout, privateKey, publicKey }) {
  //console.log("Chat component props: me=", me, "token=", token);
  const [users, setUsers] = useState([]);
  const [groups, setGroups] = useState([]);
  const [peer, setPeer] = useState(null);
  const [peerInput, setPeerInput] = useState("");
  const [peerSuggestions, setPeerSuggestions] = useState([]);
  const [activeGroup, setActiveGroup] = useState(null);
  const [messages, setMessages] = useState([]);
  const [msg, setMsg] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [groupName, setGroupName] = useState("");
  const [memberInput, setMemberInput] = useState("");
  const [selectedUsers, setSelectedUsers] = useState([]);
  const [removeUser, setRemoveUser] = useState("");
  const [addUserInput, setAddUserInput] = useState("");
  const [notify, setNotify] = useState(null);
  const wsRef = useRef(null);
  const bottomRef = useRef(null);
  const [myPrivateKey, setMyPrivateKey] = useState(null);
  const [myPublicKey, setMyPublicKey] = useState(null);
  const [decryptionKey, setDecryptionKey] = useState(null);

  useEffect(() => {
    setMyPrivateKey(privateKey);
    setMyPublicKey(publicKey);
    if (privateKey) {
      importRsaPrivateKey(privateKey)
        .then(setDecryptionKey)
        .catch((err) => {
          console.error("Failed to import private key:", err);
          setNotify({ type: "error", text: "Chave privada inválida." });
        });
    } else {
      setDecryptionKey(null);
    }
  }, [privateKey, publicKey]);

  useEffect(() => {
    console.log("Calling getUsers with token:", token);
    getUsers(token)
      .then((u) => {
        console.log("getUsers returned:", u);
        setUsers(u);
      })
      .catch((error) => {
        console.error("Error fetching users:", error);
        setUsers([]);
      });
    listGroups(token)
      .then((g) => setGroups(g))
      .catch(() => setGroups([]));
  }, [token, me]);

  useEffect(() => {
    console.log("Users state updated:", users);
  }, [users]);

  useEffect(() => {
    if (!me) return;
    wsRef.current = connectSocket(me, async (data) => {
      if (data.type === "group") {
        if (data.system_note) {
          setNotify({ type: "success", text: data.system_note });
          listGroups(token)
            .then((gl) => {
              setGroups(gl);
              const updated = gl.find((g) => g.id === activeGroup?.id);
              if (updated) setActiveGroup(updated);
            })
            .catch(() => {});
        }
      }
    });
    return () => { 
      try {
        wsRef.current && wsRef.current.close();
      } catch {}
    };
  }, [peer, activeGroup, me, token]);

  // Carregar histórico ao selecionar Peer
  useEffect(() => {
    if (peer) {
      setActiveGroup(null);
      setPeerInput(peer);
      getHistory(token, peer)
        .then(async (hist) => {
          if (!decryptionKey) {
            setNotify({
              type: "error",
              text: "Please upload your private key to decrypt messages.",
            });
            return;
          }
          const decryptedMessages = [];
          for (const h of hist) {
            try {
              const isSender = h.sender_username === me;
              const encryptedKey = isSender
                ? h.sender_encrypted_session_key
                : h.encrypted_session_key;

              const sessionKey = await rsaDecrypt(
                decryptionKey,
                base64ToUint8(encryptedKey)
              );

              // --- VERIFICAÇÃO DE INTEGRIDADE (HMAC) ---
              if (h.integrity_hash) {
                const calculatedHash = generateHMAC(h.encrypted_message, h.iv, sessionKey);
                if (calculatedHash !== h.integrity_hash) {
                  throw new Error("INTEGRITY_CHECK_FAILED");
                }
                // 1. DEBUG DE RECEBIMENTO (Sucesso)
                console.log(`✅ [INTEGRIDADE - RECEBIMENTO] Msg ID ${h._id}: Hash Validado com Sucesso! A mensagem é autêntica.`); // <--- DEBUG ADICIONADO
              }
              // -------------------------------------------

              const plaintext = await blowfishDecrypt(
                base64ToUint8(h.encrypted_message),
                sessionKey,
                base64ToUint8(h.iv)
              );
              decryptedMessages.push({
                id: `${h._id}`,
                sender_username: h.sender_username,
                plaintext: plaintext,
                ts: new Date(h.timestamp).getTime(),
              });
            } catch (e) {
              console.error("Failed to decrypt DM:", e);
              let errorMsg = "[Could not decrypt message]";
              if (e.message === "INTEGRITY_CHECK_FAILED") {
                errorMsg = "🚫 ALERTA: Mensagem adulterada ou corrompida!";
              }
              decryptedMessages.push({
                id: `${h._id}`,
                sender_username: h.sender_username,
                plaintext: errorMsg,
                ts: new Date(h.timestamp).getTime(),
                error: true,
              });
            }
          }
          setMessages(decryptedMessages);
        })
        .catch(() => setMessages([]));
    }
  }, [peer, token, decryptionKey]);

  // Implementação de Polling e Descriptografia
  useEffect(() => {
    if (!peer && !activeGroup) {
      return; 
    }

    const fetchAndDecrypt = async () => {
      if (!decryptionKey) {
        return;
      }

      try {
        if (peer) {
          const hist = await getHistory(token, peer);
          const decryptedMessages = [];
          for (const h of hist) {
            try {
              const isSender = h.sender_username === me;
              const encryptedKey = isSender
                ? h.sender_encrypted_session_key
                : h.encrypted_session_key;
              const sessionKey = await rsaDecrypt(decryptionKey, base64ToUint8(encryptedKey));
              
              // --- VERIFICAÇÃO DE INTEGRIDADE (HMAC) ---
              if (h.integrity_hash) {
                const calculatedHash = generateHMAC(h.encrypted_message, h.iv, sessionKey);
                if (calculatedHash !== h.integrity_hash) {
                  throw new Error("INTEGRITY_CHECK_FAILED");
                }
                // (Opcional: adicionei aqui também para garantir que apareça no polling)
                console.log(`✅ [INTEGRIDADE - RECEBIMENTO] Msg ID ${h._id}: Hash Validado com Sucesso!`);
              }
              // -------------------------------------------

              const plaintext = await blowfishDecrypt(base64ToUint8(h.encrypted_message), sessionKey, base64ToUint8(h.iv));
              decryptedMessages.push({
                id: `${h._id}`,
                sender_username: h.sender_username,
                plaintext: plaintext,
                ts: new Date(h.timestamp).getTime(),
              });
            } catch (e) {
              let errorMsg = "[Could not decrypt message]";
              if (e.message === "INTEGRITY_CHECK_FAILED") {
                errorMsg = "🚫 ALERTA: Mensagem adulterada ou corrompida!";
              }
              decryptedMessages.push({
                id: `${h._id}`,
                sender_username: h.sender_username,
                plaintext: errorMsg,
                ts: new Date(h.timestamp).getTime(),
                error: true,
              });
            }
          }
          setMessages(decryptedMessages);
        } else if (activeGroup) {
          const hist = await groupHistory(token, activeGroup.id);
          const decryptedMessages = [];
          for (const h of hist.messages) {
            const keyVersion = hist.key_versions.find(
              (kv) => kv.version === h.key_version
            );
            if (keyVersion) {
              const userKey = keyVersion.keys.find((k) => k.username === me);
              if (userKey) {
                try {
                  const sessionKey = await rsaDecrypt(decryptionKey, base64ToUint8(userKey.encrypted_key));
                  
                  const plaintext = await blowfishDecrypt(base64ToUint8(h.encrypted_message), sessionKey, base64ToUint8(h.iv));
                  decryptedMessages.push({
                    id: `${h._id}`,
                    sender_username: h.sender_username,
                    plaintext: plaintext,
                    ts: new Date(h.timestamp).getTime(),
                    key_version: h.key_version,
                  });
                } catch (e) {
                  decryptedMessages.push({
                    id: `${h._id}`,
                    sender_username: h.sender_username,
                    plaintext: `[Could not decrypt message]`,
                    ts: new Date(h.timestamp).getTime(),
                    error: true,
                  });
                }
              }
            }
          }
          setMessages(decryptedMessages);
        }
      } catch (error) {
        console.error("Polling failed:", error);
      }
    };

    fetchAndDecrypt();
    const intervalId = setInterval(fetchAndDecrypt, 2000); 

    return () => {
      clearInterval(intervalId);
    };
  }, [peer, activeGroup, token, decryptionKey, me]);


  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (!notify) return;
    const t = setTimeout(() => setNotify(null), 4000);
    return () => clearTimeout(t);
  }, [notify]);

  const peers = useMemo(
    () => users.map((u) => u.username).filter((u) => u !== me),
    [users, me]
  );

  useEffect(() => {
    if (!peerInput) {
      setPeerSuggestions([]);
      return;
    }
    const q = peerInput.toLowerCase();
    setPeerSuggestions(
      peers.filter((p) => p.toLowerCase().includes(q)).slice(0, 8)
    );
  }, [peerInput, peers]);

  async function handleSend() {
    const text = msg.trim();
    if (!text) return;

    const optimisticMessage = {
      id: `optimistic-${Date.now()}`,
      sender_username: me,
      plaintext: text,
      ts: Date.now(),
    };
    setMessages((currentMessages) => [...currentMessages, optimisticMessage]);
    setMsg("");

    try {
      if (peer) {
        if (!myPrivateKey) {
          setNotify({
            type: "error",
            text: "Please upload your private key to send direct messages.",
          });
          setMessages((currentMessages) =>
            currentMessages.filter((m) => m.id !== optimisticMessage.id)
          );
          return;
        }
        const recipientPublicKeyPem = await getUserPublicKey(token, peer);
        const recipientPublicKey = await importRsaPublicKey(
          recipientPublicKeyPem
        );
        const senderPublicKey = await importRsaPublicKey(myPublicKey);

        const sessionKey = generateRandomBytes(16); 
        const iv = generateRandomBytes(8); 

        const encryptedMessageUint8 = await blowfishEncrypt(text, sessionKey, iv);
        const encryptedMessageB64 = uint8ToBase64(encryptedMessageUint8);
        const ivB64 = uint8ToBase64(iv);

        // --- GERAÇÃO DO HASH DE INTEGRIDADE ---
        // Assina o IV + Mensagem Criptografada usando a chave da sessão
        const integrityHash = generateHMAC(encryptedMessageB64, ivB64, sessionKey);
        
        // 2. DEBUG DE ENVIO
        console.log(`📤 [INTEGRIDADE - ENVIO] HMAC Gerado: ${integrityHash}. Enviando mensagem segura.`); // <--- DEBUG ADICIONADO
        // --------------------------------------

        const encryptedSessionKeyForRecipient = await rsaEncrypt(
          recipientPublicKey,
          sessionKey
        );
        const encryptedSessionKeyForSender = await rsaEncrypt(
          senderPublicKey,
          sessionKey
        );

        await sendMessage(
          token,
          peer,
          encryptedMessageB64,
          uint8ToBase64(encryptedSessionKeyForRecipient),
          uint8ToBase64(encryptedSessionKeyForSender),
          ivB64,
          integrityHash 
        );
      } else if (activeGroup) {
        if (!myPrivateKey) {
          setNotify({
            type: "error",
            text: "Please upload your private key to send group messages.",
          });
          setMessages((currentMessages) =>
            currentMessages.filter((m) => m.id !== optimisticMessage.id)
          );
          return;
        }
        const keyVersion = activeGroup.key_versions.find(
          (kv) => kv.version === activeGroup.key_version
        );
        if (keyVersion) {
          const userKey = keyVersion.keys.find((k) => k.username === me);
          if (userKey) {
            const sessionKey = await rsaDecrypt(
              decryptionKey,
              base64ToUint8(userKey.encrypted_key)
            );
            const iv = generateRandomBytes(8);
            const encryptedMessageUint8 = await blowfishEncrypt(text, sessionKey, iv);
            await groupSend(
              token,
              activeGroup.id,
              uint8ToBase64(encryptedMessageUint8),
              uint8ToBase64(iv),
              activeGroup.key_version
            );
          }
        }
      } else {
        setNotify({
          type: "error",
          text: "Selecione um destinatário ou grupo.",
        });
        setMessages((currentMessages) =>
          currentMessages.filter((m) => m.id !== optimisticMessage.id)
        );
        return;
      }
    } catch (e) {
      const message =
        e?.response?.data?.detail || e?.message || "Erro ao enviar";
      setNotify({ type: "error", text: message });
      setMessages((currentMessages) =>
        currentMessages.filter((m) => m.id !== optimisticMessage.id)
      );
    }
  }

  async function handleSelectSuggestion(name) {
    setPeer(name);
    setPeerInput(name);
    setPeerSuggestions([]);
    setMessages([]);
    try {
      const hist = await getHistory(token, name);
      setMessages(
        hist.map((h) => ({
          id: `${h.id}`,
          sender_username: h.sender_username,
          plaintext: h.plaintext, 
          ts: new Date(h.timestamp).getTime(),
        }))
      );
    } catch {
      setMessages([]);
    }
  }

  function handlePeerKey(e) {
    if (e.key === "Enter" && peerInput.trim()) {
      const match = peers.find(
        (p) => p.toLowerCase() === peerInput.trim().toLowerCase()
      );
      if (match) {
        setPeer(match);
        setPeerSuggestions([]);
      } else {
        setNotify({ type: "error", text: "Usuário não encontrado" });
      }
    }
  }

  function addMemberFromInput() {
    const name = memberInput.trim();
    if (!name) return;
    if (name === me) {
      setMemberInput("");
      return;
    }
    if (!peers.includes(name)) {
      setNotify({ type: "error", text: `Usuário '${name}' não existe` });
      return;
    }
    if (!selectedUsers.includes(name)) {
      setSelectedUsers((s) => [...s, name]);
    }
    setMemberInput("");
  }

  function removeSelectedUser(name) {
    setSelectedUsers((s) => s.filter((x) => x !== name));
  }

  async function handleCreateGroup() {
    const members = Array.from(new Set([...selectedUsers, me]));
    if (members.length < 2) {
      setNotify({
        type: "error",
        text: "Adicione pelo menos mais uma pessoa ao grupo.",
      });
      return;
    }
    try {
      await createGroup(token, groupName.trim(), members);
      const gl = await listGroups(token);
      setGroups(gl);
      setCreateOpen(false);
      setGroupName("");
      setSelectedUsers([]);
      setNotify({ type: "success", text: "Grupo criado." });
    } catch (e) {
      const message =
        e?.response?.data?.detail || e?.message || "Erro ao criar grupo";
      setNotify({ type: "error", text: message });
    }
  }

  async function handleRemoveMember() {
    if (!activeGroup || !removeUser.trim()) {
      setNotify({ type: "error", text: "Digite o usuário a remover." });
      return;
    }
    try {
      await groupRemoveMember(token, activeGroup.id, removeUser.trim());
      const gl = await listGroups(token);
      setGroups(gl);
      setRemoveUser("");
      const updated = gl.find((gg) => gg.id === activeGroup.id);
      if (updated) {
        setActiveGroup(updated);
      }
      setNotify({
        type: "success",
        text: "Membro removido e chaves atualizadas.",
      });
    } catch (e) {
      const message =
        e?.response?.data?.detail || e?.message || "Erro ao remover membro";
      setNotify({ type: "error", text: message });
    }
  }

  async function handleAddMember() {
    const name = addUserInput.trim();
    if (!activeGroup) {
      setNotify({ type: "error", text: "Abra um grupo primeiro." });
      return;
    }
    if (!name) {
      setNotify({ type: "error", text: "Digite um usuário." });
      return;
    }
    if (name === me) {
      setNotify({ type: "error", text: "Você já está no grupo." });
      return;
    }
    if (!peers.includes(name)) {
      setNotify({ type: "error", text: `Usuário '${name}' não existe` });
      return;
    }
    if (activeGroup.members.includes(name)) {
      setNotify({ type: "error", text: "Usuário já é membro do grupo." });
      return;
    }
    try {
      await groupAddMember(token, activeGroup.id, name);
      const gl = await listGroups(token);
      setGroups(gl);
      const updated = gl.find((gg) => gg.id === activeGroup.id);
      if (updated) {
        setActiveGroup(updated);
      }
      setAddUserInput("");
      setNotify({
        type: "success",
        text: `${name} adicionado ao grupo. Chaves rotacionadas.`,
      });
    } catch (e) {
      const message =
        e?.response?.data?.detail || e?.message || "Erro ao adicionar membro";
      setNotify({ type: "error", text: message });
    }
  }

  async function selectGroup(g) {
    setActiveGroup(g);
    setPeer(null);
    setPeerInput("");
    setMessages([]); 

    try {
      const hist = await groupHistory(token, g.id);
      if (!decryptionKey) {
        setNotify({
          type: "error",
          text: "Chave privada não encontrada para descriptografar mensagens.",
        });
        return;
      }
      const decryptedMessages = [];
      for (const h of hist.messages) {
        const keyVersion = hist.key_versions.find(
          (kv) => kv.version === h.key_version
        );
        if (keyVersion) {
          const userKey = keyVersion.keys.find((k) => k.username === me);
          if (userKey) {
            try {
              const sessionKey = await rsaDecrypt(
                decryptionKey,
                base64ToUint8(userKey.encrypted_key)
              );
              const plaintext = await blowfishDecrypt(
                base64ToUint8(h.encrypted_message),
                sessionKey,
                base64ToUint8(h.iv)
              );
              decryptedMessages.push({
                id: `${h._id}`,
                sender_username: h.sender_username,
                plaintext: plaintext,
                ts: new Date(h.timestamp).getTime(),
                key_version: h.key_version,
              });
            } catch (e) {
              console.error("Failed to decrypt group message:", e);
              decryptedMessages.push({
                id: `${h._id}`,
                sender_username: h.sender_username,
                plaintext: `[Could not decrypt message: ${e.message}]`,
                ts: new Date(h.timestamp).getTime(),
                error: true,
              });
            }
          }
        }
      }
      setMessages(decryptedMessages);
    } catch (e) {
      setMessages([]);
      setNotify({ type: "error", text: "Falha ao carregar histórico do grupo." });
    }
  }


  return (
    <div className="page">
      <aside className="panel left">
        <div className="me-card">
          <div className="me-meta">
            <div className="me-name">{me}</div>
            <div className="muted">online</div>
          </div>

        </div>

        <div className="section">Pessoas</div>
        <div className="user-list">
          {peers.map((u) => (
            <button
              key={u}
              className={`user-tile ${peer === u ? "active" : ""}`}
              onClick={() => {
                setPeer(u);
                setActiveGroup(null);
                setPeerInput(u);
              }}
            >
              <span>{u}</span>
            </button>
          ))}
        </div>
        <div className="section">Grupos</div>
        <div className="user-list">
          {groups.map((g) => (
            <button
              key={g.id}
              className={`user-tile ${
                activeGroup?.id === g.id ? "active" : ""
              }`}
              onClick={() => selectGroup(g)}
            >
              <span>{g.name || `Grupo ${g.id}`}</span>
              <div className="group-members-count">{g.members.length}</div>
            </button>
          ))}
        </div>
        <button className="ghost" onClick={() => setCreateOpen((v) => !v)}>
          {createOpen ? "Fechar" : "Criar grupo"}
        </button>
        {createOpen && (
          <div className="glass-card form-card">
            <input
              placeholder="Nome do grupo (opcional)"
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
            />
            <div className="member-input-row">
              <input
                placeholder="Adicionar membro (digite o nome)"
                value={memberInput}
                onChange={(e) => setMemberInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addMemberFromInput()}
              />
              <button className="add-btn" onClick={addMemberFromInput}>
                +
              </button>
            </div>
            <div className="chips">
              {selectedUsers.map((u) => (
                <div key={u} className="chip">
                  <span>{u}</span>
                  <button onClick={() => removeSelectedUser(u)}>×</button>
                </div>
              ))}
            </div>
            <button className="primary" onClick={handleCreateGroup}>
              Criar grupo
            </button>
          </div>
        )}
        <button className="ghost" onClick={onLogout}>
          Sair
        </button>
      </aside>
      <main className="panel chat">
        {peer || activeGroup ? (
          <>
            <header className="chat-head glass">
              <div className="peer">
                <div className="peer-name">
                  {peer
                    ? peer
                    : activeGroup?.name || `Grupo ${activeGroup?.id}`}
                </div>
                {activeGroup && (
                  <div className="members-inline">
                    <div className="muted">Membros:</div>
                    <div className="members-list">
                      {activeGroup.members.map((m) => (
                        <span key={m} className="member-chip">
                          {m}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </header>
            {activeGroup && (
              <div className="group-admin glass">
                <input
                  placeholder="Remover usuário (digite o nome)"
                  value={removeUser}
                  onChange={(e) => setRemoveUser(e.target.value)}
                />
                <button onClick={handleRemoveMember}>Remover</button>
                <input
                  placeholder="Adicionar usuário (digite o nome)"
                  value={addUserInput}
                  onChange={(e) => setAddUserInput(e.target.value)}
                />
                <button onClick={handleAddMember}>Adicionar</button>
              </div>
            )}
            <section className="thread">
              <div className="messages-wrapper">
                {messages.map((m) => {
                  const mine = m.sender_username === me;
                  return (
                    <div
                      key={m.id}
                      className={`msg ${mine ? "me" : "other"} pop-in`}
                    >
                      <div className="bubble">
                        <div className="meta">{m.sender_username}</div>
                        <div className="text">{m.plaintext}</div>
                      </div>
                    </div>
                  );
                })}
                <div ref={bottomRef} />
              </div>
            </section>
            <footer className="composer glass">
              <input
                placeholder="Mensagem"
                value={msg}
                onChange={(e) => setMsg(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSend()}
              />
              <button onClick={handleSend}>Enviar</button>
            </footer>
          </>
        ) : (
          <div className="empty-state">
            <div className="empty-card">
              <div className="empty-title">Selecione uma pessoa ou grupo</div>
              <div className="muted">As conversas aparecerão aqui</div>
            </div>
          </div>
        )}
      </main>
      {notify && (
        <div
          className={`toast ${notify.type === "error" ? "error" : "success"}`}
        >
          {notify.text}
        </div>
      )}
    </div>
  );
}