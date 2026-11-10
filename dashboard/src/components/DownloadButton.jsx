import { useState } from "react";
import { Download } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { useAuth } from "../contexts/AuthContext.jsx";
import EncryptionModal from "./EncryptionModal.jsx";

export default function DownloadButton({
  pluginId,
  pluginName,
  className = "",
  variant = "default",
  size = "sm",
}) {
  const { token } = useAuth();
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
