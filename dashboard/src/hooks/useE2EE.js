import { useState, useEffect, useCallback, useRef } from 'react';
import { getE2EEClient } from '../lib/e2ee';

export const useE2EE = (apiBaseUrl) => {
  const [isInitialized, setIsInitialized] = useState(false);
  const [isEnabled, setIsEnabled] = useState(true);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState(null);
  const clientRef = useRef(null);
  const initPromiseRef = useRef(null);

  useEffect(() => {
    if (!apiBaseUrl) return;

    const initializeE2EE = async () => {
      try {
        if (!clientRef.current) {
          clientRef.current = getE2EEClient(apiBaseUrl);
        }

        const success = await clientRef.current.initialize();
        setIsInitialized(success);
        setIsEnabled(success);
        setError(success ? null : 'E2EE not available on server');
      } catch (err) {
        console.error('E2EE initialization error:', err);
        setError(err.message);
        setIsEnabled(false);
        setIsInitialized(false);
      }
    };

    if (!initPromiseRef.current) {
      initPromiseRef.current = initializeE2EE();
    }

    return () => {
      if (clientRef.current) {
        clientRef.current.clearAllSessionKeys();
      }
    };
  }, [apiBaseUrl]);

  const encrypt = useCallback(async (data, sessionToken = null) => {
    if (!clientRef.current) {
      console.warn('E2EE client not initialized, returning plaintext');
      return typeof data === 'string' ? data : JSON.stringify(data);
    }

    try {
      return await clientRef.current.encryptPayload(data, sessionToken);
    } catch (err) {
      console.error('Encryption error:', err);
      return typeof data === 'string' ? data : JSON.stringify(data);
    }
  }, []);

    const decrypt = useCallback(async (encryptedData, sessionToken = null) => {
    if (!clientRef.current) {
      return typeof encryptedData === 'string'
        ? JSON.parse(encryptedData)
        : encryptedData;
    }

    try {
      return await clientRef.current.decryptResponse(encryptedData, sessionToken);
    } catch (err) {
      console.error('Decryption error:', err);
      return typeof encryptedData === 'string'
        ? JSON.parse(encryptedData)
        : encryptedData;
    }
  }, []);

    const encryptedFetch = useCallback(async (url, options = {}) => {
    try {
      const sessionToken = options.sessionToken || null;

      if (options.body && (options.method === 'POST' || options.method === 'PUT')) {
        const encrypted = await encrypt(options.body, sessionToken);
        options.body = encrypted;
      }

      const response = await fetch(url, options);

      const responseText = await response.text();

      let responseData;
      if (clientRef.current && clientRef.current.isEncryptedResponse(responseText)) {
        responseData = await decrypt(responseText, sessionToken);
      } else {
        responseData = responseText ? JSON.parse(responseText) : null;
      }

      return {
        ok: response.ok,
        status: response.status,
        statusText: response.statusText,
        data: responseData,
        headers: response.headers
      };
    } catch (err) {
      console.error('Encrypted fetch error:', err);
      throw err;
    }
  }, [encrypt, decrypt]);

    const clearSession = useCallback((sessionToken) => {
    if (clientRef.current && sessionToken) {
      clientRef.current.clearSessionKey(sessionToken);
    }
  }, []);

    const fetchStats = useCallback(async () => {
    if (!clientRef.current) return null;

    try {
      const statsData = await clientRef.current.getStats();
      setStats(statsData);
      return statsData;
    } catch (err) {
      console.error('Failed to fetch E2EE stats:', err);
      return null;
    }
  }, []);

    const rotateKeys = useCallback(async (authToken) => {
    if (!clientRef.current) return false;

    try {
      const success = await clientRef.current.triggerKeyRotation(authToken);
      if (success) {
        setIsInitialized(true);
        await fetchStats();
      }
      return success;
    } catch (err) {
      console.error('Key rotation error:', err);
      return false;
    }
  }, [fetchStats]);

    const isEncrypted = useCallback((response) => {
    if (!clientRef.current) return false;
    return clientRef.current.isEncryptedResponse(response);
  }, []);

    const reinitialize = useCallback(async () => {
    if (!clientRef.current) return false;

    try {
      const success = await clientRef.current.initialize();
      setIsInitialized(success);
      setIsEnabled(success);
      setError(success ? null : 'E2EE not available');
      return success;
    } catch (err) {
      console.error('Reinitialization error:', err);
      setError(err.message);
      return false;
    }
  }, []);

  return {
    isInitialized,
    isEnabled,
    isReady: isInitialized && isEnabled,
    error,
    stats,

    encrypt,
    decrypt,
    encryptedFetch,

    clearSession,
    fetchStats,
    rotateKeys,
    isEncrypted,
    reinitialize,

    client: clientRef.current
  };
};

export default useE2EE;
