/**
 * Strip sensitive fields from file metadata before returning to API consumers.
 * The secret values remain in the database for internal operations (delete, rename, move)
 * but are never exposed through API responses.
 */

const SENSITIVE_KEYS = [
    'S3SecretAccessKey',
    'S3AccessKeyId',
    'TgBotToken',
];

/**
 * @param {Object|null|undefined} metadata
 * @returns {Object} metadata with sensitive fields removed
 */
export function stripSensitiveMetadata(metadata) {
    if (!metadata || typeof metadata !== 'object') {
        return metadata;
    }
    const cleaned = { ...metadata };
    for (const key of SENSITIVE_KEYS) {
        delete cleaned[key];
    }
    return cleaned;
}
