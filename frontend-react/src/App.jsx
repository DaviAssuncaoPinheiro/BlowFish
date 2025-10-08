import { useState } from "react";
import Login from "./Login";
import Chat from "./Chat";

export default function App() {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem("chat_user");
    return saved ? JSON.parse(saved) : null;
  });

  function handleAuth(u) {
    localStorage.setItem("chat_user", JSON.stringify(u));
    setUser(u);
  }

  function handleLogout() {
    localStorage.removeItem("chat_user");
    setUser(null);
  }

  return user ? (
    <Chat me={user.username} token={user.token} onLogout={handleLogout} />
  ) : (
    <Login onAuth={handleAuth} />
  );
}
