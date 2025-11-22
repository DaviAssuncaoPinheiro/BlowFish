import axios from "axios";
const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";
const WS_BASE = import.meta.env.VITE_WS_BASE || "ws://localhost:8000";

console.log("API_BASE resolved to:", API_BASE);

export async function login(username, password) {
  console.log("Attempting login for:", username);
  try {
    const res = await axios.post(`${API_BASE}/auth/login`, {
      username,
      password,
    });
    console.log("Login successful, response:", res.data);
    return res.data;
  } catch (error) {
    console.error("Login failed:", error);
    throw error;
  }
}

export async function register(username, password) {
  console.log("Attempting registration for:", username);
  console.log("API_BASE for registration:", API_BASE);
  try {
    console.log("Before axios.post for registration.");
    const res = await axios.post(`${API_BASE}/auth/register`, {
      username,
      password,
    });
    console.log("After axios.post for registration, response:", res.data);
    return res.data;
  } catch (error) {
    console.error("Registration failed in api.js catch block (fetch):", error);
    throw error;
  }
}

// --- FUNÇÕES DE AUTENTICAÇÃO GOOGLE + 2FA ---

export async function sendGoogleCode(code) {
  console.log("Enviando código Google para backend...");
  try {
    const res = await axios.post(`${API_BASE}/auth/google`, { code });
    // O backend pode retornar TokenOut (se for login direto) 
    // OU { require_2fa: true, username: "..." } (se precisar de código)
    return res.data; 
  } catch (error) {
    console.error("Erro no Google Auth:", error);
    throw error;
  }
}

export async function verify2FA(username, code) {
  try {
    const res = await axios.post(`${API_BASE}/auth/verify-2fa`, {
      username,
      code
    });
    // Retorna o TokenOut final (token, keys, etc.)
    return res.data; 
  } catch (error) {
    console.error("Erro na verificação 2FA:", error);
    throw error;
  }
}

// -----------------------------------------------

export async function getUsers(token) {
  const res = await axios.get(`${API_BASE}/users`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data;
}

export async function getUserPublicKey(token, username) {
  const res = await axios.get(`${API_BASE}/users/${username}/public_key`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data.public_key;
}

export async function sendMessage(
  token,
  to,
  encrypted_message,
  encrypted_session_key,
  sender_encrypted_session_key,
  iv,
  integrity_hash 
) {
  const res = await axios.post(
    `${API_BASE}/messages/send`,
    {
      to,
      encrypted_message,
      encrypted_session_key,
      sender_encrypted_session_key,
      iv,
      integrity_hash, 
    },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return res.data;
}

export async function getHistory(token, peer) {
  const res = await axios.get(`${API_BASE}/messages/history`, {
    params: { peer },
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data;
}

export function connectSocket(username, onMessage) {
  const url = `${WS_BASE}/ws/${encodeURIComponent(username)}`;
  const ws = new WebSocket(url);
  ws.onmessage = (ev) => {
    try {
      const data = JSON.parse(ev.data);
      onMessage(data);
    } catch {}
  };
  ws.onopen = () => {};
  ws.onclose = () => {};
  ws.onerror = () => {};
  return ws;
}

export async function listGroups(token) {
  const res = await axios.get(`${API_BASE}/groups`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data;
}

export async function createGroup(token, name, members) {
  const res = await axios.post(
    `${API_BASE}/groups/create`,
    { name, members },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return res.data;
}

export async function groupHistory(token, groupId) {
  const res = await axios.get(`${API_BASE}/groups/${groupId}/history`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data;
}

export async function groupSend(token, groupId, encryptedMessage, iv, keyVersion) {
  const res = await axios.post(
    `${API_BASE}/groups/${groupId}/send`,
    { encrypted_message: encryptedMessage, iv: iv, key_version: keyVersion },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return res.data;
}

export async function groupRemoveMember(token, groupId, username) {
  const res = await axios.post(
    `${API_BASE}/groups/${groupId}/remove`,
    { username },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return res.data;
}

export async function groupAddMember(token, groupId, username) {
  const res = await axios.post(
    `${API_BASE}/groups/${groupId}/add`,
    { username },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return res.data;
}