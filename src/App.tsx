import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useAuthStore } from "./store/authStore";
import { useMessageStore } from "./store/messageStore";
import { hydrateSenderKeyStore } from "./services/senderKeyStore";
import QrAuthPage from "./pages/QrAuthPage";
import ChatsPage from "./pages/ChatsPage";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  return isAuthenticated ? <>{children}</> : <Navigate to="/" replace />;
}

export default function App() {
  const hydrateAuth = useAuthStore((s) => s.hydrate);
  const hydrateMessages = useMessageStore((s) => s.hydrate);
  const authHydrated = useAuthStore((s) => s.hydrated);
  const messagesHydrated = useMessageStore((s) => s.hydrated);
  const [bootstrapped, setBootstrapped] = useState(false);

  useEffect(() => {
    void Promise.all([
      hydrateAuth(),
      hydrateMessages(),
      hydrateSenderKeyStore(),
    ]).finally(() => setBootstrapped(true));
  }, [hydrateAuth, hydrateMessages]);

  if (!bootstrapped || !authHydrated || !messagesHydrated) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="h-8 w-8 animate-spin rounded-full border-[3px] border-border border-t-violet-500" />
      </div>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<QrAuthPage />} />
        <Route
          path="/chats"
          element={
            <ProtectedRoute>
              <ChatsPage />
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
