
class E2EEClient {
  constructor(apiBaseUrl) {
    this.apiBaseUrl = apiBaseUrl;
    this.publicKey = null;
    this.sessionKeys = new Map();
    this.initialized = false;
    this.enabled = true;
  }

    async initialize() {
    try {
      const response = await fetch(`${this.apiBaseUrl}/e2ee/public-key`);

      if (!response.ok) {
        console.warn('E2EE not available on server, using plaintext');
        this.enabled = false;
        return false;
      }

      const data = await response.json();
      if (data.success && data.publicKey) {
        this.publicKey = data.publicKey;
        this.initialized = true;
        return true;
      } else {
        console.warn('Failed to get public key from server');
        this.enabled = false;
        return false;
      }
    } catch (error) {
      console.warn('E2EE initialization failed:', error.message);
      this.enabled = false;
      return false;
    }
  }

    isReady() {
    return this.enabled && this.initialized;
  }

    async encryptPayload(data, sessionToken = null) {
    if (!this.isReady()) {
     
      return typeof data === 'string' ? data : JSON.stringify(data);
    }

    try {
     
      const plaintext = typeof data === 'string' ? data : JSON.stringify(data);

     
      const nonce = this.generateNonce();
      const timestamp = Date.now();

     
      const innerPayload = {
        data: plaintext,
        nonce: nonce,
        timestamp: timestamp
      };

      const innerJson = JSON.stringify(innerPayload);

     
      const { ciphertext, key } = await this.encryptWithAES(innerJson, sessionToken);

     
      const envelope = {
        ciphertext: ciphertext,
        timestamp: timestamp,
        version: '1.0',
        encryptionType: 'AEAD'
      };

     
      if (sessionToken) {
        this.sessionKeys.set(sessionToken, key);
      }

      return JSON.stringify(envelope);
    } catch (error) {
      console.error('Encryption failed:', error);
     
      return typeof data === 'string' ? data : JSON.stringify(data);
    }
  }

    async decryptResponse(encryptedResponse, sessionToken = null) {
   
    if (!this.isEncryptedResponse(encryptedResponse)) {
     
      return typeof encryptedResponse === 'string'
        ? JSON.parse(encryptedResponse)
        : encryptedResponse;
    }

    try {
      const envelope = JSON.parse(encryptedResponse);

      if (!envelope.encrypted || !envelope.ciphertext) {
        return envelope;
      }

     
      const key = this.sessionKeys.get(sessionToken);
      if (!key) {
        console.warn('No session key found for decryption, returning encrypted data');
        return envelope;
      }

     
      const decrypted = await this.decryptWithAES(envelope.ciphertext, key);
      return JSON.parse(decrypted);

    } catch (error) {
      console.error('Decryption failed:', error);
     
      return typeof encryptedResponse === 'string'
        ? JSON.parse(encryptedResponse)
        : encryptedResponse;
    }
  }

    isEncryptedResponse(response) {
    if (!response || typeof response !== 'string') {
      return false;
    }

    try {
      const parsed = JSON.parse(response);
      return parsed.encrypted === true && !!parsed.ciphertext;
    } catch {
      return false;
    }
  }

    async encryptWithAES(plaintext, sessionToken) {
   
    const key = await this.getOrGenerateKey(sessionToken);

   
    const iv = crypto.getRandomValues(new Uint8Array(12));

   
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      key,
      data
    );

   
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);

   
    return {
      ciphertext: this.arrayBufferToBase64(combined),
      key: key
    };
  }

    async decryptWithAES(ciphertextBase64, key) {
   
    const combined = this.base64ToArrayBuffer(ciphertextBase64);

   
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

   
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      key,
      ciphertext
    );

   
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

    async getOrGenerateKey(sessionToken) {
    if (sessionToken && this.sessionKeys.has(sessionToken)) {
      return this.sessionKeys.get(sessionToken);
    }

   
    const key = await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    );

    if (sessionToken) {
      this.sessionKeys.set(sessionToken, key);
    }

    return key;
  }

    generateNonce() {
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    return this.arrayBufferToBase64(nonce);
  }

    clearSessionKey(sessionToken) {
    this.sessionKeys.delete(sessionToken);
  }

    clearAllSessionKeys() {
    this.sessionKeys.clear();
  }

    arrayBufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

    base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

    async getStats() {
    try {
      const response = await fetch(`${this.apiBaseUrl}/e2ee/stats`);
      if (response.ok) {
        const data = await response.json();
        return data.success ? data.stats : null;
      }
      return null;
    } catch (error) {
      console.error('Failed to get E2EE stats:', error);
      return null;
    }
  }

    async triggerKeyRotation(authToken) {
    try {
      const response = await fetch(`${this.apiBaseUrl}/e2ee/rotate-keys`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success) {
         
          await this.initialize();
          return true;
        }
      }
      return false;
    } catch (error) {
      console.error('Key rotation failed:', error);
      return false;
    }
  }
}


let e2eeClientInstance = null;

export const getE2EEClient = (apiBaseUrl) => {
  if (!e2eeClientInstance) {
    e2eeClientInstance = new E2EEClient(apiBaseUrl);
  }
  return e2eeClientInstance;
};

export default E2EEClient;
