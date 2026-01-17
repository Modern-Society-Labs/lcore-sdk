/**
 * L{CORE} SDK - IoT Provider Helpers
 *
 * Convenience functions for attesting data from cloud IoT platforms.
 * These generate the correct HTTP provider configurations for common IoT APIs.
 */

import type { AttestRequest, HttpProviderParams, SecretParams } from './types.js'

// ============= AWS IoT =============

export interface AwsIotShadowConfig {
  /** AWS region (e.g., 'us-east-1') */
  region: string
  /** Thing name in AWS IoT */
  thingName: string
  /** Fields to extract from the shadow (JSON paths relative to shadow root) */
  fields: string[]
  /** AWS credentials */
  credentials: {
    /** AWS access key ID */
    accessKeyId: string
    /** AWS secret access key */
    secretAccessKey: string
    /** Optional session token for temporary credentials */
    sessionToken?: string
  }
}

/**
 * Create an attestation request for AWS IoT Device Shadow
 *
 * @example
 * ```typescript
 * const request = awsIotShadow({
 *   region: 'us-east-1',
 *   thingName: 'temperature-sensor-001',
 *   fields: ['state.reported.temperature', 'state.reported.humidity'],
 *   credentials: {
 *     accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
 *     secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
 *   }
 * })
 *
 * const result = await lcore.attest(request)
 * ```
 */
export function awsIotShadow(config: AwsIotShadowConfig): AttestRequest {
  const { region, thingName, fields, credentials } = config

  // AWS IoT Data endpoint
  const url = `https://data-ats.iot.${region}.amazonaws.com/things/${thingName}/shadow`

  // Build AWS Signature v4 authorization header
  // Note: In production, use aws4 library or AWS SDK for proper signing
  const authHeader = buildAwsAuthHeader(credentials, region, 'iotdata')

  const params: HttpProviderParams = {
    url,
    method: 'GET',
    responseRedactions: fields.map(field => ({ jsonPath: field })),
  }

  const secretParams: SecretParams = {
    headers: {
      'Authorization': authHeader,
      ...(credentials.sessionToken && { 'X-Amz-Security-Token': credentials.sessionToken }),
    },
  }

  return {
    provider: 'http',
    params,
    secretParams,
  }
}

// ============= Azure IoT Hub =============

export interface AzureIotTwinConfig {
  /** IoT Hub name (e.g., 'my-iot-hub') */
  hubName: string
  /** Device ID */
  deviceId: string
  /** Fields to extract from the twin (JSON paths) */
  fields: string[]
  /** Azure credentials */
  credentials: {
    /** Shared Access Signature */
    sasToken: string
  }
  /** API version (default: '2021-04-12') */
  apiVersion?: string
}

/**
 * Create an attestation request for Azure IoT Hub Device Twin
 *
 * @example
 * ```typescript
 * const request = azureIotTwin({
 *   hubName: 'my-iot-hub',
 *   deviceId: 'sensor-001',
 *   fields: ['properties.reported.temperature'],
 *   credentials: {
 *     sasToken: process.env.AZURE_SAS_TOKEN!,
 *   }
 * })
 *
 * const result = await lcore.attest(request)
 * ```
 */
export function azureIotTwin(config: AzureIotTwinConfig): AttestRequest {
  const { hubName, deviceId, fields, credentials, apiVersion = '2021-04-12' } = config

  const url = `https://${hubName}.azure-devices.net/twins/${deviceId}?api-version=${apiVersion}`

  const params: HttpProviderParams = {
    url,
    method: 'GET',
    responseRedactions: fields.map(field => ({ jsonPath: field })),
  }

  const secretParams: SecretParams = {
    headers: {
      'Authorization': credentials.sasToken,
    },
  }

  return {
    provider: 'http',
    params,
    secretParams,
  }
}

// ============= Google Cloud IoT =============

export interface GcpIotDeviceConfig {
  /** GCP project ID */
  projectId: string
  /** Cloud region (e.g., 'us-central1') */
  region: string
  /** Registry ID */
  registryId: string
  /** Device ID */
  deviceId: string
  /** Fields to extract from device state */
  fields: string[]
  /** GCP credentials */
  credentials: {
    /** OAuth2 access token */
    accessToken: string
  }
}

/**
 * Create an attestation request for Google Cloud IoT Core Device
 *
 * @example
 * ```typescript
 * const request = gcpIotDevice({
 *   projectId: 'my-project',
 *   region: 'us-central1',
 *   registryId: 'my-registry',
 *   deviceId: 'sensor-001',
 *   fields: ['config', 'state'],
 *   credentials: {
 *     accessToken: process.env.GCP_ACCESS_TOKEN!,
 *   }
 * })
 *
 * const result = await lcore.attest(request)
 * ```
 */
export function gcpIotDevice(config: GcpIotDeviceConfig): AttestRequest {
  const { projectId, region, registryId, deviceId, fields, credentials } = config

  const url = `https://cloudiot.googleapis.com/v1/projects/${projectId}/locations/${region}/registries/${registryId}/devices/${deviceId}`

  const params: HttpProviderParams = {
    url,
    method: 'GET',
    responseRedactions: fields.map(field => ({ jsonPath: field })),
  }

  const secretParams: SecretParams = {
    headers: {
      'Authorization': `Bearer ${credentials.accessToken}`,
    },
  }

  return {
    provider: 'http',
    params,
    secretParams,
  }
}

// ============= Generic REST API =============

export interface GenericApiConfig {
  /** API endpoint URL */
  url: string
  /** HTTP method (default: GET) */
  method?: 'GET' | 'POST' | 'PUT'
  /** Fields to extract (JSON paths) */
  fields: string[]
  /** Optional request body (for POST/PUT) */
  body?: string
  /** Optional validation rules */
  responseMatches?: Array<{ type: 'contains' | 'regex' | 'exact'; value: string }>
  /** Optional headers */
  headers?: Record<string, string>
}

/**
 * Create an attestation request for any REST API
 *
 * @example
 * ```typescript
 * const request = genericApi({
 *   url: 'https://weather.station.local/api/readings',
 *   fields: ['temperature', 'humidity', 'pressure'],
 *   responseMatches: [{ type: 'contains', value: '"status":"ok"' }],
 *   headers: {
 *     'X-API-Key': process.env.WEATHER_API_KEY!,
 *   }
 * })
 *
 * const result = await lcore.attest(request)
 * ```
 */
export function genericApi(config: GenericApiConfig): AttestRequest {
  const { url, method = 'GET', fields, body, responseMatches, headers } = config

  const params: HttpProviderParams = {
    url,
    method,
    ...(body && { body }),
    ...(responseMatches && { responseMatches }),
    responseRedactions: fields.map(field => ({ jsonPath: field })),
  }

  const secretParams: SecretParams | undefined = headers ? { headers } : undefined

  return {
    provider: 'http',
    params,
    ...(secretParams && { secretParams }),
  }
}

// ============= ThingsBoard =============

export interface ThingsBoardConfig {
  /** ThingsBoard server URL */
  serverUrl: string
  /** Device ID */
  deviceId: string
  /** Telemetry keys to extract */
  keys: string[]
  /** ThingsBoard credentials */
  credentials: {
    /** JWT token or device access token */
    token: string
  }
}

/**
 * Create an attestation request for ThingsBoard telemetry
 *
 * @example
 * ```typescript
 * const request = thingsBoard({
 *   serverUrl: 'https://thingsboard.example.com',
 *   deviceId: 'abc123',
 *   keys: ['temperature', 'humidity'],
 *   credentials: {
 *     token: process.env.THINGSBOARD_TOKEN!,
 *   }
 * })
 *
 * const result = await lcore.attest(request)
 * ```
 */
export function thingsBoard(config: ThingsBoardConfig): AttestRequest {
  const { serverUrl, deviceId, keys, credentials } = config

  const url = `${serverUrl}/api/plugins/telemetry/DEVICE/${deviceId}/values/timeseries?keys=${keys.join(',')}`

  const params: HttpProviderParams = {
    url,
    method: 'GET',
    responseRedactions: keys.map(key => ({ jsonPath: key })),
  }

  const secretParams: SecretParams = {
    headers: {
      'X-Authorization': `Bearer ${credentials.token}`,
    },
  }

  return {
    provider: 'http',
    params,
    secretParams,
  }
}

// ============= Home Assistant =============

export interface HomeAssistantConfig {
  /** Home Assistant URL (e.g., 'http://homeassistant.local:8123') */
  url: string
  /** Entity ID (e.g., 'sensor.temperature') */
  entityId: string
  /** Attributes to extract (leave empty for just state) */
  attributes?: string[]
  /** Long-lived access token */
  token: string
}

/**
 * Create an attestation request for Home Assistant entity state
 *
 * @example
 * ```typescript
 * const request = homeAssistant({
 *   url: 'http://homeassistant.local:8123',
 *   entityId: 'sensor.living_room_temperature',
 *   attributes: ['unit_of_measurement', 'friendly_name'],
 *   token: process.env.HASS_TOKEN!,
 * })
 *
 * const result = await lcore.attest(request)
 * ```
 */
export function homeAssistant(config: HomeAssistantConfig): AttestRequest {
  const { url, entityId, attributes = [], token } = config

  const apiUrl = `${url}/api/states/${entityId}`

  const fields = ['state', ...attributes.map(attr => `attributes.${attr}`)]

  const params: HttpProviderParams = {
    url: apiUrl,
    method: 'GET',
    responseRedactions: fields.map(field => ({ jsonPath: field })),
  }

  const secretParams: SecretParams = {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  }

  return {
    provider: 'http',
    params,
    secretParams,
  }
}

// ============= Helpers =============

/**
 * Build AWS Signature v4 authorization header (simplified)
 * Note: For production, use the aws4 npm package for proper signing
 */
function buildAwsAuthHeader(
  credentials: { accessKeyId: string; secretAccessKey: string },
  region: string,
  service: string
): string {
  // This is a placeholder - in production you'd use proper AWS SigV4 signing
  // The actual signing requires the request details (method, path, headers, body)
  // and should be done at request time
  //
  // For now, we return a format that indicates the credentials are available
  // Users should use AWS SDK or aws4 package for proper signing
  return `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/.../${region}/${service}/aws4_request`
}

/**
 * Type for all IoT provider configs
 */
export type IoTProviderConfig =
  | { type: 'aws'; config: AwsIotShadowConfig }
  | { type: 'azure'; config: AzureIotTwinConfig }
  | { type: 'gcp'; config: GcpIotDeviceConfig }
  | { type: 'thingsboard'; config: ThingsBoardConfig }
  | { type: 'homeassistant'; config: HomeAssistantConfig }
  | { type: 'generic'; config: GenericApiConfig }

/**
 * Create an attestation request from a typed IoT provider config
 */
export function createIoTRequest(provider: IoTProviderConfig): AttestRequest {
  switch (provider.type) {
    case 'aws':
      return awsIotShadow(provider.config)
    case 'azure':
      return azureIotTwin(provider.config)
    case 'gcp':
      return gcpIotDevice(provider.config)
    case 'thingsboard':
      return thingsBoard(provider.config)
    case 'homeassistant':
      return homeAssistant(provider.config)
    case 'generic':
      return genericApi(provider.config)
  }
}
