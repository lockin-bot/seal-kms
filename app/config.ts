import { got } from 'got-cjs';

export interface SealConfig {
  enclave_package_id: string;
  enclave_endpoint: string;
  enclave_config_object_id: string;
  encrypted_master_key_object_id: string;
  module_name: string;
  otw_name: string;
  kms_package_id: string;
  sui_secret_key: string;
  sui_network: string;
  server_object_ids: string[]; // Server object IDs for Seal key servers (required)
  enclave_object_id?: string; // Will be set after registration
}

export interface EnclaveConfig {
  seal: SealConfig;
}

class ConfigManager {
  private config: EnclaveConfig | null = null;
  private loadPromise: Promise<EnclaveConfig> | null = null;
  private enclaveObjectId: string | null = null;

  async loadConfig(): Promise<EnclaveConfig> {
    if (this.config) {
      return this.config;
    }

    if (this.loadPromise) {
      return this.loadPromise;
    }

    this.loadPromise = this.fetchConfig();
    this.config = await this.loadPromise;
    this.loadPromise = null;

    if (this.enclaveObjectId) {
      this.config.seal.enclave_object_id = this.enclaveObjectId;
    }

    return this.config;
  }

  private async fetchConfig(): Promise<EnclaveConfig> {
    try {
      const maxRetries = 5;
      const retryDelay = 2000;

      for (let i = 0; i < maxRetries; i++) {
        try {
          console.log(
            `Attempting to load enclave configuration (attempt ${i + 1}/${maxRetries})...`,
          );
          const response = await got
            .get('http://127.0.0.1:3000/load_config', {
              timeout: { request: 5000 },
              retry: { limit: 0 },
            })
            .json<EnclaveConfig>();

          console.log('Enclave configuration loaded successfully');
          return response;
        } catch (error) {
          if (i === maxRetries - 1) {
            throw error;
          }
          console.log(`Failed to load config, retrying in ${retryDelay}ms...`);
          await new Promise((resolve) => setTimeout(resolve, retryDelay));
        }
      }

      throw new Error('Failed to load enclave configuration after all retries');
    } catch (error) {
      console.error('Failed to load enclave configuration:', error);
      throw new Error(
        `Enclave configuration loading failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  getConfig(): EnclaveConfig {
    if (!this.config) {
      throw new Error(
        'Enclave configuration not loaded. Call loadConfig() first.',
      );
    }
    return this.config;
  }

  getSealConfig(): SealConfig {
    const sealConfig = this.getConfig().seal;
    if (this.enclaveObjectId) {
      sealConfig.enclave_object_id = this.enclaveObjectId;
    }
    return sealConfig;
  }

  setEnclaveObjectId(objectId: string): void {
    this.enclaveObjectId = objectId;
    if (this.config) {
      this.config.seal.enclave_object_id = objectId;
    }
  }

  getEnclaveObjectId(): string | null {
    return this.enclaveObjectId;
  }

  isLoaded(): boolean {
    return this.config !== null;
  }

  async reloadConfig(): Promise<EnclaveConfig> {
    this.config = null;
    this.loadPromise = null;
    return this.loadConfig();
  }
}

export const configManager = new ConfigManager();
