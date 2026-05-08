import {
  createHash,
  randomBytes,
  scryptSync,
  timingSafeEqual,
  createCipheriv,
  createDecipheriv,
} from "node:crypto";

const DEFAULT_APP_SECRET = "oowa-dev-secret-change-me";
const APP_SECRET = process.env.OOWA_APP_SECRET ?? DEFAULT_APP_SECRET;
const PASSWORD_PREFIX = "scrypt";
const ENCRYPTION_PREFIX = "aes256gcm";

const toBase64Url = (buffer) =>
  buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const fromBase64Url = (value) => {
  const normalized = String(value)
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, "base64");
};

const deriveKey = (appSecret, salt) => scryptSync(appSecret, salt, 32);

export const hashSessionToken = (token) =>
  createHash("sha256").update(String(token)).digest("hex");

export const issueSessionToken = () => toBase64Url(randomBytes(32));

export const hashPassword = (password) => {
  const normalized = String(password ?? "");
  if (normalized.length < 8) {
    throw new Error("비밀번호는 8자 이상이어야 합니다.");
  }

  const salt = randomBytes(16);
  const digest = scryptSync(normalized, salt, 64);
  return `${PASSWORD_PREFIX}$${toBase64Url(salt)}$${toBase64Url(digest)}`;
};

export const verifyPassword = (password, storedHash) => {
  const [prefix, saltValue, digestValue] = String(storedHash ?? "").split("$");
  if (prefix !== PASSWORD_PREFIX || !saltValue || !digestValue) {
    throw new Error("invalid password hash format");
  }

  const expected = fromBase64Url(digestValue);
  const actual = scryptSync(String(password ?? ""), fromBase64Url(saltValue), expected.length);
  return timingSafeEqual(expected, actual);
};

export const encryptSecret = (plainText) => {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", deriveKey(APP_SECRET, salt), iv);
  const encrypted = Buffer.concat([cipher.update(String(plainText), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return [
    ENCRYPTION_PREFIX,
    toBase64Url(salt),
    toBase64Url(iv),
    toBase64Url(tag),
    toBase64Url(encrypted),
  ].join("$");
};

export const decryptSecret = (payload) => {
  const [prefix, saltValue, ivValue, tagValue, encryptedValue] = String(payload ?? "").split(
    "$",
  );
  if (
    prefix !== ENCRYPTION_PREFIX ||
    !saltValue ||
    !ivValue ||
    !tagValue ||
    !encryptedValue
  ) {
    throw new Error("invalid encrypted secret format");
  }

  const salt = fromBase64Url(saltValue);
  const iv = fromBase64Url(ivValue);
  const tag = fromBase64Url(tagValue);
  const encrypted = fromBase64Url(encryptedValue);
  const candidateSecrets =
    APP_SECRET === DEFAULT_APP_SECRET
      ? [APP_SECRET]
      : [APP_SECRET, DEFAULT_APP_SECRET];

  for (const appSecret of candidateSecrets) {
    try {
      const decipher = createDecipheriv("aes-256-gcm", deriveKey(appSecret, salt), iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      return decrypted.toString("utf8");
    } catch {
      // Try the next configured secret for backward compatibility.
    }
  }

  throw new Error("stored wallet secret could not be decrypted");
};
