import { useState } from "react";
import { AlertCircle, Download } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { Alert, AlertDescription } from "@/components/ui/alert.jsx";
import { useAuth } from "../contexts/AuthContext.jsx";
import EncryptionModal from "./EncryptionModal.jsx";

const API_BASE_URL = "http://localhost:8080/api/v1";

export default function DownloadButton({
  pluginId,
  pluginName,
  userId,
  onSuccess,
  className = "",
  variant = "default",
  size = "sm",
}) {
  const { token } = useAuth();
  const [error, setError] = useState("");
  const [showEncryptionModal, setShowEncryptionModal] = useState(false);

  const handleDownload = () => {
    setShowEncryptionModal(true);
  };

  return (
    <>
      <Button
        onClick={handleDownload}
        variant={variant}
        size={size}
        className={className}
      >
        <Download className="mr-2 h-4 w-4" />
        Descargar
      </Button>

      {error && (
        <Alert variant="destructive" className="mt-2">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <EncryptionModal
        isOpen={showEncryptionModal}
        onClose={() => setShowEncryptionModal(false)}
        plugin={{
          pluginId: pluginId,
          name: pluginName,
        }}
        userToken={token}
      />
    </>
  );
}
