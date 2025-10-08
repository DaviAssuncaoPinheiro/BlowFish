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
} from "./api";

export default function Chat({ me, token, onLogout }) {
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

  useEffect(() => {
    getUsers(token).then((u) => setUsers(u)).catch(() => setUsers([]));
    listGroups(token).then((g) => setGroups(g)).catch(() => setGroups([]));
  }, [token]);

  useEffect(() => {
    if (!me) return;
    wsRef.current = connectSocket(me, (data) => {
      if (data.type === "dm") {
        if (data.from === me) {
          return;
        }
        if (peer && (data.from === peer || data.to === peer)) {
          setMessages((m) => [...m, { id: `${Date.now()}-${Math.random()}`, sender_username: data.from, plaintext: data.message, ts: Date.now() }]);
        }
      } else if (data.type === "group") {
        if (data.from === me) {
            return;
        }
        if (activeGroup && data.conversation_id === activeGroup.id) {
          setMessages((m) => [...m, { id: `${Date.now()}-${Math.random()}`, sender_username: data.from, plaintext: data.message, ts: Date.now(), key_version: data.key_version }]);
        }
        if (data.system_note) {
          setNotify({ type: "success", text: data.system_note });
          listGroups(token).then((gl) => {
            setGroups(gl);
            const updated = gl.find((g) => g.id === activeGroup?.id);
            if (updated) setActiveGroup(updated);
          }).catch(()=>{});
        }
      }
    });
    return () => {
      try { wsRef.current && wsRef.current.close(); } catch {}
    };
  }, [peer, activeGroup, me, token]);

  useEffect(() => {
    if (peer) {
      setActiveGroup(null);
      setPeerInput(peer);
      getHistory(token, peer).then((hist) => setMessages(hist.map((h) => ({ id: `${h.id}`, sender_username: h.sender_username, plaintext: h.plaintext, ts: new Date(h.timestamp).getTime() })))).catch(() => setMessages([]));
    }
  }, [peer, token]);

  useEffect(() => {
    if (activeGroup) {
      setPeer(null);
      setPeerInput("");
      groupHistory(token, activeGroup.id).then((hist) => setMessages(hist.map((h) => ({ id: `${h.id}`, sender_username: h.sender_username, plaintext: h.plaintext, ts: new Date(h.timestamp).getTime(), key_version: h.key_version })))).catch(() => setMessages([]));
    }
  }, [activeGroup, token]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (!notify) return;
    const t = setTimeout(() => setNotify(null), 4000);
    return () => clearTimeout(t);
  }, [notify]);

  const peers = useMemo(() => users.map((u) => u.username).filter((u) => u !== me), [users, me]);

  useEffect(() => {
    if (!peerInput) {
      setPeerSuggestions([]);
      return;
    }
    const q = peerInput.toLowerCase();
    setPeerSuggestions(peers.filter((p) => p.toLowerCase().includes(q)).slice(0, 8));
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
        await sendMessage(token, peer, text);
      } else if (activeGroup) {
        await groupSend(token, activeGroup.id, text);
      } else {
        setNotify({ type: "error", text: "Selecione um destinatário ou grupo." });
        setMessages((currentMessages) =>
          currentMessages.filter((m) => m.id !== optimisticMessage.id)
        );
        return;
      }
    } catch (e) {
      const message = e?.response?.data?.detail || e?.message || "Erro ao enviar";
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
      setMessages(hist.map((h) => ({ id: `${h.id}`, sender_username: h.sender_username, plaintext: h.plaintext, ts: new Date(h.timestamp).getTime() })));
    } catch {
      setMessages([]);
    }
  }

  function handlePeerKey(e) {
    if (e.key === "Enter" && peerInput.trim()) {
      const match = peers.find((p) => p.toLowerCase() === peerInput.trim().toLowerCase());
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
      setNotify({ type: "error", text: "Adicione pelo menos mais uma pessoa ao grupo." });
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
      const message = e?.response?.data?.detail || e?.message || "Erro ao criar grupo";
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
      if (updated) setActiveGroup(updated);
      setNotify({ type: "success", text: "Membro removido e chaves atualizadas." });
    } catch (e) {
      const message = e?.response?.data?.detail || e?.message || "Erro ao remover membro";
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
      if (updated) setActiveGroup(updated);
      setAddUserInput("");
      setNotify({ type: "success", text: `${name} adicionado ao grupo. Chaves rotacionadas.` });
    } catch (e) {
      const message = e?.response?.data?.detail || e?.message || "Erro ao adicionar membro";
      setNotify({ type: "error", text: message });
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
        
        {/* === SEÇÃO DE INICIAR CONVERSA REMOVIDA DAQUI === */}

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
              className={`user-tile ${activeGroup?.id === g.id ? "active" : ""}`}
              onClick={() => {
                setActiveGroup(g);
                setPeer(null);
                setPeerInput("");
              }}
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
            <input placeholder="Nome do grupo (opcional)" value={groupName} onChange={(e) => setGroupName(e.target.value)} />
            <div className="member-input-row">
              <input
                placeholder="Adicionar membro (digite o nome)"
                value={memberInput}
                onChange={(e) => setMemberInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addMemberFromInput()}
              />
              <button className="add-btn" onClick={addMemberFromInput}>+</button>
            </div>
            <div className="chips">
              {selectedUsers.map((u) => (
                <div key={u} className="chip">
                  <span>{u}</span>
                  <button onClick={() => removeSelectedUser(u)}>×</button>
                </div>
              ))}
            </div>
            <button className="primary" onClick={handleCreateGroup}>Criar grupo</button>
          </div>
        )}
        <button className="ghost" onClick={onLogout}>Sair</button>
      </aside>
      <main className="panel chat">
        {(peer || activeGroup) ? (
          <>
            <header className="chat-head glass">
              <div className="peer">
                <div className="peer-name">{peer ? peer : activeGroup?.name || `Grupo ${activeGroup?.id}`}</div>
                {activeGroup && (
                  <div className="members-inline">
                    <div className="muted">Membros:</div>
                    <div className="members-list">
                      {activeGroup.members.map((m) => (
                        <span key={m} className="member-chip">{m}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </header>
            {activeGroup && (
              <div className="group-admin glass">
                <input placeholder="Remover usuário (digite o nome)" value={removeUser} onChange={(e) => setRemoveUser(e.target.value)} />
                <button onClick={handleRemoveMember}>Remover</button>
                <input placeholder="Adicionar usuário (digite o nome)" value={addUserInput} onChange={(e) => setAddUserInput(e.target.value)} />
                <button onClick={handleAddMember}>Adicionar</button>
              </div>
            )}
            <section className="thread">
              <div className="messages-wrapper">
                {messages.map((m) => {
                  const mine = m.sender_username === me;
                  return (
                    <div key={m.id} className={`msg ${mine ? "me" : "other"} pop-in`}>
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
              <input placeholder="Mensagem" value={msg} onChange={(e) => setMsg(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleSend()} />
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
        <div className={`toast ${notify.type === "error" ? "error" : "success"}`}>
          {notify.text}
        </div>
      )}
    </div>
  );
}