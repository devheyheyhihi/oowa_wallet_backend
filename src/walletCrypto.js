import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as signMessage,
} from "node:crypto";

const OOWA_TOKEN_ADDRESS =
  "2a6b9ddcaa0b33718154ccc12814fdf16e2583b7838d5e261fb42b0b5e64cfbe";
const SASEUL_GOLD_API_BASE_URL = "https://api.saseulgold.org";
const ADDRESS_PATTERN = /^[0-9a-f]{44}$/;
const PUBLIC_KEY_PATTERN = /^[0-9a-f]{64}$/;
const PRIVATE_KEY_PATTERN = /^[0-9a-f]{64}$/;
const HEX_TIME_SIZE = 14;
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const INSUFFICIENT_FEE_BALANCE_MESSAGE = "Balance is not enough for transfer fee";

const byteToHex = (bytes) => Buffer.from(bytes).toString("hex").toLowerCase();

const stringToUnicode = (str) =>
  Array.prototype.map
    .call(str ?? "", (char) => {
      const code = char.charCodeAt(0).toString(16);
      return code.length > 2 ? `\\u${code}` : char;
    })
    .join("");

const toString = (input) => {
  const value =
    typeof input === "object" && input !== null ? JSON.stringify(input) : String(input);
  return stringToUnicode(value.replace(/\//g, "\\/"));
};

const sha256 = (value) =>
  createHash("sha256").update(typeof value === "string" ? value : toString(value)).digest("hex");

const ripemd160 = (value) =>
  createHash("ripemd160").update(typeof value === "string" ? value : toString(value)).digest("hex");

const hash = (value) => sha256(toString(value));

const hextime = (timestamp) =>
  Number(timestamp).toString(16).padStart(HEX_TIME_SIZE, "0").slice(0, HEX_TIME_SIZE);

const txHash = (tx) => hextime(tx.timestamp) + hash(hash(tx));

const checksum = (value) => sha256(sha256(value)).slice(0, 4);

const getAddressFromPublicKey = (publicKey) => {
  const short = ripemd160(hash(publicKey));
  return `${short}${checksum(short)}`;
};

const getPrivateKeyObject = (privateKeyHex) =>
  createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(privateKeyHex, "hex")]),
    format: "der",
    type: "pkcs8",
  });

export const isSaseulAddress = (address) =>
  ADDRESS_PATTERN.test(String(address ?? "").trim().toLowerCase());

export const deriveWalletFromPrivateKey = (privateKeyInput) => {
  const privateKey = String(privateKeyInput ?? "").trim().toLowerCase();
  if (!PRIVATE_KEY_PATTERN.test(privateKey)) {
    throw new Error("private key must be 64 hex characters");
  }

  const privateKeyObject = getPrivateKeyObject(privateKey);
  const publicKeyDer = createPublicKey(privateKeyObject).export({
    format: "der",
    type: "spki",
  });
  const publicKey = byteToHex(publicKeyDer.subarray(-32));
  if (!PUBLIC_KEY_PATTERN.test(publicKey)) {
    throw new Error("failed to derive public key");
  }

  const address = getAddressFromPublicKey(publicKey);
  if (!ADDRESS_PATTERN.test(address)) {
    throw new Error("failed to derive address");
  }

  return {
    privateKey,
    publicKey,
    address,
  };
};

export const assertWalletShape = ({ privateKey, publicKey, address }) => {
  const derived = deriveWalletFromPrivateKey(privateKey);
  if (publicKey && String(publicKey).trim().toLowerCase() !== derived.publicKey) {
    throw new Error("public key does not match private key");
  }
  if (address && String(address).trim().toLowerCase() !== derived.address) {
    throw new Error("wallet address does not match private key");
  }
  return derived;
};

export const generateWallet = () => deriveWalletFromPrivateKey(byteToHex(randomBytes(32)));

export const signTransferTransaction = ({ wallet, transaction }) => {
  const signature = signMessage(
    null,
    Buffer.from(toString(txHash(transaction)), "utf8"),
    getPrivateKeyObject(wallet.privateKey),
  );

  return {
    public_key: wallet.publicKey,
    signature: byteToHex(signature),
    transaction,
  };
};

export const buildSignedOowaTransfer = async ({ wallet, toAddress, amountRaw }) => {
  const to = String(toAddress ?? "").trim().toLowerCase();
  if (!isSaseulAddress(to)) {
    throw new Error("recipient address must be a 44 character hex address");
  }
  if (!/^\d+$/.test(String(amountRaw ?? ""))) {
    throw new Error("amountRaw must be a numeric string");
  }

  const timestamp = await getSaseulTimestamp();
  const transaction = {
    type: "Transfer",
    token_address: OOWA_TOKEN_ADDRESS,
    to,
    amount: String(amountRaw),
    timestamp,
    from: wallet.address,
  };

  return signTransferTransaction({ wallet, transaction });
};

export const getSaseulTimestamp = async () => {
  const response = await fetch(`${SASEUL_GOLD_API_BASE_URL}/api/ts`);
  if (!response.ok) {
    throw new Error(`timestamp request failed: ${response.status}`);
  }
  return response.json();
};

export const broadcastSignedTransfer = async (payload) => {
  const response = await fetch(`${SASEUL_GOLD_API_BASE_URL}/broadcast/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/plain, */*",
    },
    body: JSON.stringify(payload),
  });

  const text = await response.text();
  let data = text;

  try {
    data = JSON.parse(text);
  } catch {
    // keep raw text
  }

  if (!response.ok) {
    const normalized =
      typeof data === "string" ? data : JSON.stringify(data);
    if (normalized.includes(INSUFFICIENT_FEE_BALANCE_MESSAGE)) {
      throw new Error("수수료로 사용할 사슬골드(SG)가 부족합니다.");
    }
    throw new Error(
      `broadcast failed with ${response.status}: ${normalized}`,
    );
  }

  if (!data || typeof data !== "object") {
    throw new Error(`broadcast returned a non-object response: ${String(data)}`);
  }

  const broadcastOk = data.ok;
  if (
    broadcastOk === false ||
    broadcastOk === "false" ||
    broadcastOk === 0 ||
    broadcastOk === "0"
  ) {
    const normalized = JSON.stringify(data);
    if (normalized.includes(INSUFFICIENT_FEE_BALANCE_MESSAGE)) {
      throw new Error("수수료로 사용할 사슬골드(SG)가 부족합니다.");
    }
    throw new Error(
      `broadcast rejected by upstream: ${normalized}`,
    );
  }

  if (typeof data.txhash !== "string" || !data.txhash.trim()) {
    const normalized = JSON.stringify(data);
    if (normalized.includes(INSUFFICIENT_FEE_BALANCE_MESSAGE)) {
      throw new Error("수수료로 사용할 사슬골드(SG)가 부족합니다.");
    }
    throw new Error(
      `broadcast response missing txhash: ${normalized}`,
    );
  }

  return data;
};
