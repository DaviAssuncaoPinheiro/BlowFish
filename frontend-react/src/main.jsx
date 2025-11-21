import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import "./styles.css";
import { GoogleOAuthProvider } from "@react-oauth/google";

// Coloque seu Client ID do Google aqui
const GOOGLE_CLIENT_ID = "771702899193-cjc8uai5od6tjk1vne6d1qjbcidnl2jq.apps.googleusercontent.com";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <GoogleOAuthProvider clientId={GOOGLE_CLIENT_ID}>
      <App />
    </GoogleOAuthProvider>
  </React.StrictMode>
);