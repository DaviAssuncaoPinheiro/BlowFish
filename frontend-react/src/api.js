import axios from "axios";
const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";
const WS_BASE = import.meta.env.VITE_WS_BASE || "ws://localhost:8000";

export async function login(username, password) {
  const res = await axios.post(`${API_BASE}/auth/login`, { username, password });
  return res.data.token || res.data;
}
export async function register(username, password) {
  const res = await axios.post(`${API_BASE}/auth/register`, { username, password });
  return res.data.token || res.data;
}
export async function getUsers(token) {
  const res = await axios.get(`${API_BASE}/users`, { headers: { Authorization: `Bearer ${token}` } });
  return res.data;
}
export async function sendMessage(token, to, message) {
  const res = await axios.post(`${API_BASE}/messages/send`, { to, message }, { headers: { Authorization: `Bearer ${token}` } });
  return res.data;
}
export async function getHistory(token, peer) {
  const res = await axios.get(`${API_BASE}/messages/history`, { params: { peer }, headers: { Authorization: `Bearer ${token}` } });
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
  const res = await axios.get(`${API_BASE}/groups`, { headers: { Authorization: `Bearer ${token}` } });
  return res.data;
}
export async function createGroup(token, name, members) {
  const res = await axios.post(`${API_BASE}/groups/create`, { name, members }, { headers: { Authorization: `Bearer ${token}` } });
  return res.data;
}
export async function groupHistory(token, groupId) {
  const res = await axios.get(`${API_BASE}/groups/${groupId}/history`, { headers: { Authorization: `Bearer ${token}` } });
  return res.data;
}
export async function groupSend(token, groupId, message) {
  const res = await axios.post(`${API_BASE}/groups/${groupId}/send`, { message }, { headers: { Authorization: `Bearer ${token}` } });
  return res.data;
}
export async function groupRemoveMember(token, groupId, username) {
  const res = await axios.post(`${API_BASE}/groups/${groupId}/remove`, { username }, { headers: { Authorization: `Bearer ${token}` } });
  return res.data;
}
export async function groupAddMember(token, groupId, username) {
  const res = await axios.post(`${API_BASE}/groups/${groupId}/add`, { username }, { headers: { Authorization: `Bearer ${token}` } });
  return res.data;
}
