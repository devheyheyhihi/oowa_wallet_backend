import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  decryptSecret,
  encryptSecret,
  hashPassword,
  hashSessionToken,
  issueSessionToken,
  verifyPassword,
} from "./authCrypto.js";
import {
  assertWalletShape,
  broadcastSignedTransfer,
  buildSignedOowaTransfer,
  deriveWalletFromPrivateKey,
  generateWallet,
} from "./walletCrypto.js";

const NETWORK = "saseul-gold";
const OOWA_TOKEN = {
  symbol: "OOWA",
  tokenAddress: "2a6b9ddcaa0b33718154ccc12814fdf16e2583b7838d5e261fb42b0b5e64cfbe",
  decimals: 18,
};
const SASEUL_GOLD_API_BASE_URL = "https://api.saseulgold.org";
const BPS_DENOMINATOR = 10_000n;
const INVESTMENT_DAILY_RATE_BP = 20n;
const INVESTMENT_CAP_TOTAL_BP = 25_000n;
const INVESTMENT_CAP_REWARD_BP = INVESTMENT_CAP_TOTAL_BP - BPS_DENOMINATOR;
const INVESTMENT_PRODUCT_ID = "oowa-daily-0.2";
const INVESTMENT_PRODUCT_NAME = "OOWA Daily 0.2";
const DAY_IN_MS = 24 * 60 * 60 * 1000;
const ADDRESS_PATTERN = /^[0-9a-f]{44}$/;
const TOKEN_ADDRESS_PATTERN = /^[0-9a-f]{64}$/;
const TXHASH_PATTERN = /^[0-9a-f]{32,128}$/;
const LOGIN_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{3,23}$/;
const PHONE_PATTERN = /^[0-9+\-\s]{8,20}$/;
const require = createRequire(import.meta.url);
const bip39 = require("../../frontend/node_modules/bip39/src/index.js");

let db;

const ensureTableColumn = (database, tableName, columnName, ddl) => {
  const columns = database.prepare(`PRAGMA table_info(${tableName})`).all();
  const exists = columns.some((column) => column.name === columnName);
  if (!exists) {
    database.exec(`ALTER TABLE ${tableName} ADD COLUMN ${ddl}`);
  }
};

const normalizeAddress = (address) => String(address ?? "").trim().toLowerCase();

const assertAddress = (address, field) => {
  const normalized = normalizeAddress(address);
  if (!ADDRESS_PATTERN.test(normalized)) {
    throw new Error(`${field} must be a 44 character hex address`);
  }
  return normalized;
};

const assertTokenAddress = (address) => {
  const normalized = String(address ?? "").trim().toLowerCase();
  if (!TOKEN_ADDRESS_PATTERN.test(normalized)) {
    throw new Error("token_address must be a 64 character hex address");
  }
  return normalized;
};

const assertTxhash = (txhash) => {
  const normalized = String(txhash ?? "").trim().toLowerCase();
  if (!TXHASH_PATTERN.test(normalized)) {
    throw new Error("txhash must be hex");
  }
  return normalized;
};

const assertOptionalAddress = (address, field) => {
  if (address === null || address === undefined || String(address).trim() === "") {
    return null;
  }

  return assertAddress(address, field);
};

const assertOptionalCoordinate = (value, field) => {
  if (value === null || value === undefined || String(value).trim() === "") {
    return null;
  }

  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    throw new Error(`${field} must be a finite number`);
  }

  return numeric;
};

const assertRawAmount = (amount, field) => {
  const normalized = String(amount ?? "").trim();
  if (!/^\d+$/.test(normalized)) {
    throw new Error(`${field} must be a numeric string`);
  }
  if (BigInt(normalized) <= 0n) {
    throw new Error(`${field} must be greater than zero`);
  }
  return normalized;
};

const parseJson = (value) => {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
};

const stringifyJson = (value) => JSON.stringify(value);

const bigintMin = (left, right) => (left < right ? left : right);

const bigintCeilDiv = (left, right) => {
  if (right <= 0n) return 0n;
  return (left + right - 1n) / right;
};

const formatRawTokenAmount = (amount, decimals) => {
  const raw = String(amount ?? "0");
  if (!/^\d+$/.test(raw)) {
    throw new Error("amount must be a numeric string");
  }

  const padded =
    raw.length <= decimals ? `${"0".repeat(decimals - raw.length + 1)}${raw}` : raw;
  const integer = padded.slice(0, -decimals) || "0";
  const fraction = padded.slice(-decimals).replace(/0+$/, "");
  return fraction ? `${integer}.${fraction}` : integer;
};

const normalizeMnemonic = (mnemonic) =>
  String(mnemonic ?? "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");

const deriveWalletFromMnemonic = (mnemonicInput) => {
  const normalizedMnemonic = normalizeMnemonic(mnemonicInput);
  if (!normalizedMnemonic) {
    throw new Error("investment pool wallet is not configured");
  }
  if (!bip39.validateMnemonic(normalizedMnemonic)) {
    throw new Error("investment pool mnemonic is invalid");
  }

  const seed = bip39.mnemonicToSeedSync(normalizedMnemonic);
  const privateKey = createHash("sha256").update(seed).digest("hex");
  return deriveWalletFromPrivateKey(privateKey);
};

const getInvestmentPoolWallet = () => {
  const configuredPrivateKey = String(
    process.env.OOWA_INVESTMENT_POOL_PRIVATE_KEY ?? "",
  )
    .trim()
    .toLowerCase();
  const configuredMnemonic = String(
    process.env.OOWA_INVESTMENT_POOL_MNEMONIC ?? "",
  ).trim();

  const wallet = configuredPrivateKey
    ? deriveWalletFromPrivateKey(configuredPrivateKey)
    : deriveWalletFromMnemonic(configuredMnemonic);
  const configuredAddress = String(
    process.env.OOWA_INVESTMENT_POOL_ADDRESS ?? "",
  ).trim();

  if (configuredAddress) {
    const normalizedAddress = assertAddress(
      configuredAddress,
      "OOWA_INVESTMENT_POOL_ADDRESS",
    );
    if (normalizedAddress !== wallet.address) {
      throw new Error("investment pool address does not match configured wallet");
    }
  }

  return wallet;
};

const getInvestmentProduct = () => {
  let poolWalletAddress = null;
  let investmentAvailable = false;

  try {
    poolWalletAddress = getInvestmentPoolWallet().address;
    investmentAvailable = true;
  } catch {
    poolWalletAddress = null;
    investmentAvailable = false;
  }

  return {
    productId: INVESTMENT_PRODUCT_ID,
    name: INVESTMENT_PRODUCT_NAME,
    dailyRateBasisPoints: Number(INVESTMENT_DAILY_RATE_BP),
    dailyRatePercent: Number(INVESTMENT_DAILY_RATE_BP) / 100,
    capTotalBasisPoints: Number(INVESTMENT_CAP_TOTAL_BP),
    capTotalPercent: Number(INVESTMENT_CAP_TOTAL_BP) / 100,
    capRewardBasisPoints: Number(INVESTMENT_CAP_REWARD_BP),
    capRewardPercent: Number(INVESTMENT_CAP_REWARD_BP) / 100,
    maxRewardDays: Number(INVESTMENT_CAP_REWARD_BP / INVESTMENT_DAILY_RATE_BP),
    poolWalletAddress,
    investmentAvailable,
  };
};

const getBroadcastTxhash = (broadcastResponse) => {
  if (
    !broadcastResponse ||
    typeof broadcastResponse !== "object" ||
    typeof broadcastResponse.txhash !== "string"
  ) {
    throw new Error("broadcast response does not include txhash");
  }

  return assertTxhash(broadcastResponse.txhash);
};

const assertNoSecretFields = (value) => {
  const serialized = JSON.stringify(value).toLowerCase();
  if (
    serialized.includes("privatekey") ||
    serialized.includes("private_key") ||
    serialized.includes("mnemonic") ||
    serialized.includes("seedphrase") ||
    serialized.includes("seed_phrase")
  ) {
    throw new Error("history payload must not include private key or mnemonic");
  }
};

const dbFile = () => {
  const dataDir = path.join(process.cwd(), ".data");
  mkdirSync(dataDir, { recursive: true });
  return path.join(dataDir, "oowa-wallet.sqlite");
};

const getDb = () => {
  if (db) return db;

  db = new DatabaseSync(dbFile());
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id TEXT PRIMARY KEY,
      wallet_address TEXT NOT NULL,
      txhash TEXT NOT NULL,
      direction TEXT NOT NULL,
      entry_kind TEXT NOT NULL DEFAULT 'transfer_in',
      network TEXT NOT NULL,
      tx_type TEXT NOT NULL,
      from_address TEXT NOT NULL,
      to_address TEXT NOT NULL,
      token_address TEXT NOT NULL,
      token_symbol TEXT NOT NULL,
      decimals INTEGER NOT NULL,
      amount_raw TEXT NOT NULL,
      amount_display TEXT NOT NULL,
      chain_timestamp TEXT,
      block_height INTEGER,
      status TEXT NOT NULL,
      public_key TEXT,
      broadcast_response_json TEXT,
      chain_response_json TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      confirmed_at TEXT,
      UNIQUE(wallet_address, txhash)
    );

    CREATE INDEX IF NOT EXISTS idx_wallet_transactions_wallet_created
      ON wallet_transactions (wallet_address, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_wallet_transactions_wallet_chain_time
      ON wallet_transactions (wallet_address, chain_timestamp DESC);

    CREATE INDEX IF NOT EXISTS idx_wallet_transactions_txhash
      ON wallet_transactions (txhash);

    CREATE TABLE IF NOT EXISTS wallet_recipients (
      id TEXT PRIMARY KEY,
      wallet_address TEXT NOT NULL,
      recipient_address TEXT NOT NULL,
      network TEXT NOT NULL,
      label TEXT,
      memo TEXT,
      send_count INTEGER NOT NULL DEFAULT 0,
      last_sent_at TEXT,
      last_txhash TEXT,
      is_favorite INTEGER NOT NULL DEFAULT 0,
      is_hidden INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(wallet_address, recipient_address, network)
    );

    CREATE INDEX IF NOT EXISTS idx_wallet_recipients_wallet_recent
      ON wallet_recipients (wallet_address, last_sent_at DESC);

    CREATE INDEX IF NOT EXISTS idx_wallet_recipients_wallet_favorite
      ON wallet_recipients (wallet_address, is_favorite DESC, last_sent_at DESC);

    CREATE TABLE IF NOT EXISTS wallet_registry (
      wallet_address TEXT PRIMARY KEY,
      is_merchant INTEGER NOT NULL DEFAULT 0,
      merchant_name TEXT,
      referrer_wallet_address TEXT,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_wallet_registry_merchant
      ON wallet_registry (is_merchant, is_active, updated_at DESC);

    CREATE INDEX IF NOT EXISTS idx_wallet_registry_referrer
      ON wallet_registry (referrer_wallet_address);

    CREATE TABLE IF NOT EXISTS merchant_profiles (
      wallet_address TEXT PRIMARY KEY,
      user_id TEXT NOT NULL UNIQUE,
      merchant_name TEXT,
      category TEXT,
      logo_url TEXT,
      postal_code TEXT,
      address_main TEXT,
      address_detail TEXT,
      lat REAL,
      lng REAL,
      phone TEXT,
      description TEXT,
      status TEXT NOT NULL DEFAULT 'draft',
      review_note TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      reviewed_at TEXT,
      reviewed_by TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_merchant_profiles_status
      ON merchant_profiles (status, updated_at DESC);

    CREATE INDEX IF NOT EXISTS idx_merchant_profiles_user_id
      ON merchant_profiles (user_id);

    CREATE TABLE IF NOT EXISTS merchant_profile_change_requests (
      wallet_address TEXT PRIMARY KEY,
      user_id TEXT NOT NULL UNIQUE,
      merchant_name TEXT,
      category TEXT,
      logo_url TEXT,
      postal_code TEXT,
      address_main TEXT,
      address_detail TEXT,
      lat REAL,
      lng REAL,
      phone TEXT,
      description TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      review_note TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      reviewed_at TEXT,
      reviewed_by TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_merchant_profile_change_requests_status
      ON merchant_profile_change_requests (status, updated_at DESC);

    CREATE TABLE IF NOT EXISTS payment_orders (
      id TEXT PRIMARY KEY,
      payer_wallet_address TEXT NOT NULL,
      merchant_wallet_address TEXT NOT NULL,
      total_amount_raw TEXT NOT NULL,
      total_amount_display TEXT NOT NULL,
      merchant_amount_raw TEXT NOT NULL,
      referrer_level1_amount_raw TEXT NOT NULL,
      referrer_level2_amount_raw TEXT NOT NULL,
      referrer_level1_wallet_address TEXT,
      referrer_level2_wallet_address TEXT,
      status TEXT NOT NULL,
      failure_reason TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      completed_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_payment_orders_payer_created
      ON payment_orders (payer_wallet_address, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_payment_orders_merchant_created
      ON payment_orders (merchant_wallet_address, created_at DESC);

    CREATE TABLE IF NOT EXISTS payment_transfers (
      id TEXT PRIMARY KEY,
      payment_order_id TEXT NOT NULL,
      transfer_role TEXT NOT NULL,
      from_wallet_address TEXT NOT NULL,
      to_wallet_address TEXT NOT NULL,
      amount_raw TEXT NOT NULL,
      amount_display TEXT NOT NULL,
      txhash TEXT,
      status TEXT NOT NULL,
      error_message TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      confirmed_at TEXT,
      FOREIGN KEY (payment_order_id) REFERENCES payment_orders(id)
    );

    CREATE INDEX IF NOT EXISTS idx_payment_transfers_order
      ON payment_transfers (payment_order_id, created_at ASC);

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      login_id TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      phone TEXT NOT NULL,
      name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      is_merchant INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      last_login_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_users_login_id
      ON users (login_id);

    CREATE TABLE IF NOT EXISTS user_wallets (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL UNIQUE,
      wallet_address TEXT NOT NULL UNIQUE,
      public_key TEXT NOT NULL UNIQUE,
      encrypted_private_key TEXT NOT NULL,
      encrypted_mnemonic TEXT,
      mnemonic_available INTEGER NOT NULL DEFAULT 0,
      wallet_source TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_user_wallets_wallet_address
      ON user_wallets (wallet_address);

    CREATE TABLE IF NOT EXISTS user_sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_used_at TEXT NOT NULL,
      revoked_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_user_sessions_token_hash
      ON user_sessions (token_hash);

    CREATE TABLE IF NOT EXISTS investment_positions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      wallet_address TEXT NOT NULL,
      principal_raw TEXT NOT NULL,
      principal_display TEXT NOT NULL,
      daily_rate_bp INTEGER NOT NULL,
      cap_total_bp INTEGER NOT NULL,
      max_reward_raw TEXT NOT NULL,
      deposit_txhash TEXT NOT NULL UNIQUE,
      payout_txhash TEXT,
      status TEXT NOT NULL,
      started_at TEXT NOT NULL,
      ended_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      final_reward_raw TEXT,
      final_return_raw TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (wallet_id) REFERENCES user_wallets(id)
    );

    CREATE INDEX IF NOT EXISTS idx_investment_positions_user_status
      ON investment_positions (user_id, status, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_investment_positions_wallet_created
      ON investment_positions (wallet_address, created_at DESC);

    CREATE TABLE IF NOT EXISTS investment_payouts (
      id TEXT PRIMARY KEY,
      position_id TEXT NOT NULL,
      payout_type TEXT NOT NULL,
      principal_raw TEXT NOT NULL,
      reward_raw TEXT NOT NULL,
      total_raw TEXT NOT NULL,
      txhash TEXT,
      status TEXT NOT NULL,
      error_message TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (position_id) REFERENCES investment_positions(id)
    );

    CREATE INDEX IF NOT EXISTS idx_investment_payouts_position
      ON investment_payouts (position_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS admin_audit_logs (
      id TEXT PRIMARY KEY,
      admin_actor TEXT NOT NULL,
      action TEXT NOT NULL,
      target_user_id TEXT,
      target_wallet_address TEXT,
      detail_json TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_created
      ON admin_audit_logs (created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_target_user
      ON admin_audit_logs (target_user_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS admin_sessions (
      id TEXT PRIMARY KEY,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_used_at TEXT NOT NULL,
      revoked_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_admin_sessions_token_hash
      ON admin_sessions (token_hash);
  `);
  ensureTableColumn(db, "merchant_profiles", "lat", "lat REAL");
  ensureTableColumn(db, "merchant_profiles", "lng", "lng REAL");
  ensureTableColumn(
    db,
    "wallet_transactions",
    "entry_kind",
    "entry_kind TEXT NOT NULL DEFAULT 'transfer_in'",
  );
  ensureTableColumn(db, "user_wallets", "encrypted_mnemonic", "encrypted_mnemonic TEXT");
  ensureTableColumn(
    db,
    "user_wallets",
    "mnemonic_available",
    "mnemonic_available INTEGER NOT NULL DEFAULT 0",
  );
  db.exec(`
    UPDATE wallet_transactions
    SET entry_kind = CASE
      WHEN wallet_address = from_address AND wallet_address = to_address THEN 'self_transfer'
      WHEN wallet_address = from_address THEN 'transfer_out'
      WHEN wallet_address = to_address THEN 'transfer_in'
      ELSE 'transfer_in'
    END
    WHERE entry_kind IS NULL OR entry_kind = ''
  `);
  db.exec(`
    INSERT INTO wallet_transactions (
      id,
      wallet_address,
      txhash,
      direction,
      entry_kind,
      network,
      tx_type,
      from_address,
      to_address,
      token_address,
      token_symbol,
      decimals,
      amount_raw,
      amount_display,
      chain_timestamp,
      block_height,
      status,
      public_key,
      broadcast_response_json,
      chain_response_json,
      created_at,
      updated_at,
      confirmed_at
    )
    SELECT
      lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
      substr(lower(hex(randomblob(2))), 2) || '-' ||
      substr('89ab', abs(random()) % 4 + 1, 1) || substr(lower(hex(randomblob(2))), 2) || '-' ||
      lower(hex(randomblob(6))),
      wt.to_address,
      wt.txhash,
      'incoming',
      'transfer_in',
      wt.network,
      wt.tx_type,
      wt.from_address,
      wt.to_address,
      wt.token_address,
      wt.token_symbol,
      wt.decimals,
      wt.amount_raw,
      wt.amount_display,
      wt.chain_timestamp,
      wt.block_height,
      wt.status,
      wt.public_key,
      wt.broadcast_response_json,
      wt.chain_response_json,
      wt.created_at,
      wt.updated_at,
      wt.confirmed_at
    FROM wallet_transactions wt
    JOIN user_wallets uw ON uw.wallet_address = wt.to_address
    LEFT JOIN wallet_transactions mirror
      ON mirror.wallet_address = wt.to_address
     AND mirror.txhash = wt.txhash
    WHERE wt.wallet_address = wt.from_address
      AND wt.to_address != wt.from_address
      AND mirror.id IS NULL
  `);
  return db;
};

const mapTransaction = (row) => ({
  id: row.id,
  walletAddress: row.wallet_address,
  txhash: row.txhash,
  direction: row.direction,
  entryKind: row.entry_kind ?? "transfer_in",
  network: row.network,
  txType: row.tx_type,
  fromAddress: row.from_address,
  toAddress: row.to_address,
  tokenAddress: row.token_address,
  tokenSymbol: row.token_symbol,
  decimals: row.decimals,
  amountRaw: row.amount_raw,
  amountDisplay: row.amount_display,
  chainTimestamp: row.chain_timestamp,
  blockHeight: row.block_height,
  status: row.status,
  publicKey: row.public_key,
  broadcastResponse: parseJson(row.broadcast_response_json),
  chainResponse: parseJson(row.chain_response_json),
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  confirmedAt: row.confirmed_at,
});

const mapRecipient = (row) => ({
  id: row.id,
  walletAddress: row.wallet_address,
  recipientAddress: row.recipient_address,
  network: row.network,
  label: row.label,
  memo: row.memo,
  sendCount: row.send_count,
  lastSentAt: row.last_sent_at,
  lastTxhash: row.last_txhash,
  isFavorite: Boolean(row.is_favorite),
  isHidden: Boolean(row.is_hidden),
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const mapRegistry = (row) => ({
  walletAddress: row.wallet_address,
  isMerchant: Boolean(row.is_merchant),
  merchantName: row.merchant_name,
  referrerWalletAddress: row.referrer_wallet_address,
  isActive: Boolean(row.is_active),
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const mapPaymentOrder = (row) => ({
  id: row.id,
  payerWalletAddress: row.payer_wallet_address,
  merchantWalletAddress: row.merchant_wallet_address,
  totalAmountRaw: row.total_amount_raw,
  totalAmountDisplay: row.total_amount_display,
  merchantAmountRaw: row.merchant_amount_raw,
  referrerLevel1AmountRaw: row.referrer_level1_amount_raw,
  referrerLevel2AmountRaw: row.referrer_level2_amount_raw,
  referrerLevel1WalletAddress: row.referrer_level1_wallet_address,
  referrerLevel2WalletAddress: row.referrer_level2_wallet_address,
  status: row.status,
  failureReason: row.failure_reason,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  completedAt: row.completed_at,
});

const mapPaymentTransfer = (row) => ({
  id: row.id,
  paymentOrderId: row.payment_order_id,
  transferRole: row.transfer_role,
  fromWalletAddress: row.from_wallet_address,
  toWalletAddress: row.to_wallet_address,
  amountRaw: row.amount_raw,
  amountDisplay: row.amount_display,
  txhash: row.txhash,
  status: row.status,
  errorMessage: row.error_message,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  confirmedAt: row.confirmed_at,
});

const mapUser = (row) => ({
  id: row.id,
  loginId: row.login_id,
  phone: row.phone,
  name: row.name,
  status: row.status,
  isMerchant: Boolean(row.is_merchant),
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  lastLoginAt: row.last_login_at,
});

const mapUserWallet = (row) => ({
  id: row.id,
  userId: row.user_id,
  walletAddress: row.wallet_address,
  publicKey: row.public_key,
  mnemonicAvailable: Boolean(row.mnemonic_available),
  walletSource: row.wallet_source,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const mapMerchantProfile = (row) => ({
  walletAddress: row.wallet_address,
  userId: row.user_id,
  merchantName: row.merchant_name,
  category: row.category,
  logoUrl: row.logo_url,
  postalCode: row.postal_code,
  addressMain: row.address_main,
  addressDetail: row.address_detail,
  lat: row.lat,
  lng: row.lng,
  phone: row.phone,
  description: row.description,
  status: row.status,
  reviewNote: row.review_note,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  reviewedAt: row.reviewed_at,
  reviewedBy: row.reviewed_by,
});

const mapMerchantProfileChangeRequest = (row) => ({
  walletAddress: row.wallet_address,
  userId: row.user_id,
  merchantName: row.merchant_name,
  category: row.category,
  logoUrl: row.logo_url,
  postalCode: row.postal_code,
  addressMain: row.address_main,
  addressDetail: row.address_detail,
  lat: row.lat,
  lng: row.lng,
  phone: row.phone,
  description: row.description,
  status: row.status,
  reviewNote: row.review_note,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  reviewedAt: row.reviewed_at,
  reviewedBy: row.reviewed_by,
});

const toSortableTimestampMs = (value) => {
  if (!value) {
    return 0;
  }

  const numeric = Number(value);
  if (Number.isFinite(numeric)) {
    return numeric > 9_999_999_999_999 ? Math.floor(numeric / 1000) : numeric;
  }

  const parsed = new Date(value).getTime();
  return Number.isNaN(parsed) ? 0 : parsed;
};

const computeInvestmentPositionMetrics = (row, now = new Date()) => {
  const principalRaw = BigInt(row.principal_raw);
  const maxRewardRaw = BigInt(
    row.max_reward_raw ??
      ((principalRaw * BigInt(row.cap_total_bp - Number(BPS_DENOMINATOR))) /
        BPS_DENOMINATOR),
  );
  const dailyRewardRaw =
    (principalRaw * BigInt(row.daily_rate_bp)) / BPS_DENOMINATOR;
  const startedAtMs = new Date(row.started_at).getTime();
  const endedAtMs = row.ended_at ? new Date(row.ended_at).getTime() : null;
  const referenceTime = endedAtMs ?? now.getTime();
  const elapsedMs = Math.max(0, referenceTime - startedAtMs);
  const accruedDays = Math.floor(elapsedMs / DAY_IN_MS);

  const calculatedRewardRaw = bigintMin(
    (principalRaw * BigInt(row.daily_rate_bp) * BigInt(accruedDays)) /
      BPS_DENOMINATOR,
    maxRewardRaw,
  );
  const rewardRaw = BigInt(row.final_reward_raw ?? calculatedRewardRaw.toString());
  const totalReturnRaw = BigInt(
    row.final_return_raw ?? (principalRaw + rewardRaw).toString(),
  );
  const remainingRewardRaw =
    rewardRaw >= maxRewardRaw ? 0n : maxRewardRaw - rewardRaw;
  const remainingDays =
    remainingRewardRaw > 0n && dailyRewardRaw > 0n
      ? Number(bigintCeilDiv(remainingRewardRaw, dailyRewardRaw))
      : 0;

  return {
    accruedDays,
    accruedRateBasisPoints: row.daily_rate_bp * accruedDays,
    accruedRatePercent: (row.daily_rate_bp * accruedDays) / 100,
    dailyRewardRaw: dailyRewardRaw.toString(),
    dailyRewardDisplay: formatRawTokenAmount(
      dailyRewardRaw.toString(),
      OOWA_TOKEN.decimals,
    ),
    accruedRewardRaw: rewardRaw.toString(),
    accruedRewardDisplay: formatRawTokenAmount(
      rewardRaw.toString(),
      OOWA_TOKEN.decimals,
    ),
    totalReturnRaw: totalReturnRaw.toString(),
    totalReturnDisplay: formatRawTokenAmount(
      totalReturnRaw.toString(),
      OOWA_TOKEN.decimals,
    ),
    maxRewardRaw: maxRewardRaw.toString(),
    maxRewardDisplay: formatRawTokenAmount(
      maxRewardRaw.toString(),
      OOWA_TOKEN.decimals,
    ),
    maxReturnRaw: (principalRaw + maxRewardRaw).toString(),
    maxReturnDisplay: formatRawTokenAmount(
      (principalRaw + maxRewardRaw).toString(),
      OOWA_TOKEN.decimals,
    ),
    remainingRewardRaw: remainingRewardRaw.toString(),
    remainingRewardDisplay: formatRawTokenAmount(
      remainingRewardRaw.toString(),
      OOWA_TOKEN.decimals,
    ),
    remainingDays,
    capReached: rewardRaw >= maxRewardRaw,
  };
};

const mapInvestmentPosition = (row) => ({
  id: row.id,
  userId: row.user_id,
  walletId: row.wallet_id,
  walletAddress: row.wallet_address,
  principalRaw: row.principal_raw,
  principalDisplay: row.principal_display,
  dailyRateBasisPoints: row.daily_rate_bp,
  capTotalBasisPoints: row.cap_total_bp,
  depositTxhash: row.deposit_txhash,
  payoutTxhash: row.payout_txhash,
  status: row.status,
  startedAt: row.started_at,
  endedAt: row.ended_at,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  finalRewardRaw: row.final_reward_raw,
  finalReturnRaw: row.final_return_raw,
  ...computeInvestmentPositionMetrics(row),
});

const mapInvestmentPayout = (row) => ({
  id: row.id,
  positionId: row.position_id,
  payoutType: row.payout_type,
  principalRaw: row.principal_raw,
  rewardRaw: row.reward_raw,
  totalRaw: row.total_raw,
  txhash: row.txhash,
  status: row.status,
  errorMessage: row.error_message,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const mapAuthSession = (row) => ({
  id: row.session_id,
  userId: row.user_id,
  loginId: row.login_id,
  phone: row.phone,
  name: row.name,
  status: row.status,
  isMerchant: Boolean(row.is_merchant),
  walletId: row.wallet_id,
  walletAddress: row.wallet_address,
  publicKey: row.public_key,
  mnemonicAvailable: Boolean(row.mnemonic_available),
  walletSource: row.wallet_source,
  encryptedPrivateKey: row.encrypted_private_key,
  encryptedMnemonic: row.encrypted_mnemonic,
  expiresAt: row.expires_at,
  createdAt: row.created_at,
  lastUsedAt: row.last_used_at,
  revokedAt: row.revoked_at,
});

const mapAdminUser = (row) => ({
  id: row.user_id,
  loginId: row.login_id,
  phone: row.phone,
  name: row.name,
  status: row.status,
  isMerchant: Boolean(row.is_merchant),
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  lastLoginAt: row.last_login_at,
  wallet: {
    id: row.wallet_id,
    address: row.wallet_address,
    publicKey: row.public_key,
    mnemonicAvailable: Boolean(row.mnemonic_available),
    walletSource: row.wallet_source,
  },
  merchantProfileStatus: row.merchant_status ?? null,
  merchantName: row.merchant_name ?? null,
  transactionCount: Number(row.transaction_count ?? 0),
  recipientCount: Number(row.recipient_count ?? 0),
  paymentCount: Number(row.payment_count ?? 0),
  investmentCount: Number(row.investment_count ?? 0),
  activeInvestmentCount: Number(row.active_investment_count ?? 0),
});

const mapAdminInvestment = (row) => {
  const latestPayout = row.latest_payout_id
    ? mapInvestmentPayout({
        id: row.latest_payout_id,
        position_id: row.id,
        payout_type: row.latest_payout_type,
        principal_raw: row.latest_payout_principal_raw,
        reward_raw: row.latest_payout_reward_raw,
        total_raw: row.latest_payout_total_raw,
        txhash: row.latest_payout_txhash,
        status: row.latest_payout_status,
        error_message: row.latest_payout_error_message,
        created_at: row.latest_payout_created_at,
        updated_at: row.latest_payout_updated_at,
      })
    : null;

  return {
    ...mapInvestmentPosition(row),
    adminStatus: row.admin_status,
    user: {
      id: row.user_id,
      loginId: row.login_id,
      name: row.name,
      phone: row.phone,
    },
    latestPayout,
  };
};

const normalizeLoginId = (loginId) => String(loginId ?? "").trim().toLowerCase();

const assertLoginId = (loginId) => {
  const normalized = normalizeLoginId(loginId);
  if (!LOGIN_ID_PATTERN.test(normalized)) {
    throw new Error("아이디는 영문 소문자, 숫자 포함 4~24자로 입력해주세요.");
  }
  return normalized;
};

const assertPhone = (phone) => {
  const normalized = String(phone ?? "").trim();
  if (!PHONE_PATTERN.test(normalized)) {
    throw new Error("전화번호 형식이 올바르지 않습니다.");
  }
  return normalized;
};

const assertName = (name) => {
  const normalized = String(name ?? "").trim();
  if (normalized.length < 2 || normalized.length > 40) {
    throw new Error("이름은 2자 이상 40자 이하로 입력해주세요.");
  }
  return normalized;
};

const getUserByLoginIdRow = (loginId) =>
  getDb()
    .prepare("SELECT * FROM users WHERE login_id = ?")
    .get(assertLoginId(loginId));

const getUserByIdRow = (userId) =>
  getDb()
    .prepare("SELECT * FROM users WHERE id = ?")
    .get(String(userId ?? "").trim());

const getUserWalletByUserIdRow = (userId) =>
  getDb()
    .prepare("SELECT * FROM user_wallets WHERE user_id = ?")
    .get(userId);

const getUserWalletByAddressRow = (walletAddress) =>
  getDb()
    .prepare("SELECT * FROM user_wallets WHERE wallet_address = ?")
    .get(assertAddress(walletAddress, "walletAddress"));

const getMerchantProfileRowByWallet = (walletAddress) =>
  getDb()
    .prepare("SELECT * FROM merchant_profiles WHERE wallet_address = ?")
    .get(assertAddress(walletAddress, "walletAddress"));

const getMerchantProfileChangeRequestRowByWallet = (walletAddress) =>
  getDb()
    .prepare("SELECT * FROM merchant_profile_change_requests WHERE wallet_address = ?")
    .get(assertAddress(walletAddress, "walletAddress"));

const getInvestmentPositionRowById = (positionId) =>
  getDb()
    .prepare("SELECT * FROM investment_positions WHERE id = ?")
    .get(String(positionId ?? "").trim());

const createSessionRecord = (userId) => {
  const token = issueSessionToken();
  const tokenHash = hashSessionToken(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 30).toISOString();
  const nowIso = now.toISOString();

  getDb()
    .prepare(
      `INSERT INTO user_sessions (
         id,
         user_id,
         token_hash,
         expires_at,
         created_at,
         last_used_at,
         revoked_at
       )
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(randomUUID(), userId, tokenHash, expiresAt, nowIso, nowIso, null);

  return token;
};

const touchSession = (sessionId) => {
  getDb()
    .prepare("UPDATE user_sessions SET last_used_at = ? WHERE id = ?")
    .run(new Date().toISOString(), sessionId);
};

const revokeSessionsByUserId = (userId) => {
  const now = new Date().toISOString();
  getDb()
    .prepare(
      `UPDATE user_sessions
       SET revoked_at = COALESCE(revoked_at, ?),
           last_used_at = ?
       WHERE user_id = ?`,
    )
    .run(now, now, userId);
};

const appendAdminAuditLog = ({
  adminActor = "admin",
  action,
  targetUserId = null,
  targetWalletAddress = null,
  detail = null,
}) => {
  getDb()
    .prepare(
      `INSERT INTO admin_audit_logs (
         id,
         admin_actor,
         action,
         target_user_id,
         target_wallet_address,
         detail_json,
         created_at
       )
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      randomUUID(),
      String(adminActor ?? "admin").trim() || "admin",
      String(action ?? "").trim(),
      targetUserId,
      targetWalletAddress,
      detail ? stringifyJson(detail) : null,
      new Date().toISOString(),
    );
};

const createAdminSessionRecord = () => {
  const token = issueSessionToken();
  const tokenHash = hashSessionToken(token);
  const now = new Date();
  const nowIso = now.toISOString();
  const expiresAt = new Date(now.getTime() + 1000 * 60 * 60 * 12).toISOString();

  getDb()
    .prepare(
      `INSERT INTO admin_sessions (
         id,
         token_hash,
         expires_at,
         created_at,
         last_used_at,
         revoked_at
       )
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(randomUUID(), tokenHash, expiresAt, nowIso, nowIso, null);

  return token;
};

const getAdminSessionRowByToken = (token) =>
  getDb()
    .prepare("SELECT * FROM admin_sessions WHERE token_hash = ?")
    .get(hashSessionToken(token));

const touchAdminSession = (sessionId) => {
  getDb()
    .prepare("UPDATE admin_sessions SET last_used_at = ? WHERE id = ?")
    .run(new Date().toISOString(), sessionId);
};

const getSessionRowByToken = (token) =>
  getDb()
    .prepare(
      `SELECT
         s.id AS session_id,
         s.user_id,
         s.expires_at,
         s.created_at,
         s.last_used_at,
         s.revoked_at,
         u.login_id,
         u.phone,
         u.name,
         u.status,
         u.is_merchant,
         u.created_at AS user_created_at,
         u.updated_at AS user_updated_at,
         u.last_login_at,
         w.id AS wallet_id,
         w.wallet_address,
         w.public_key,
         w.mnemonic_available,
         w.wallet_source,
         w.encrypted_private_key,
         w.encrypted_mnemonic
       FROM user_sessions s
       JOIN users u ON u.id = s.user_id
       JOIN user_wallets w ON w.user_id = u.id
       WHERE s.token_hash = ?`,
    )
    .get(hashSessionToken(token));

const getExistingTransaction = (walletAddress, txhash) => {
  const row = getDb()
    .prepare("SELECT * FROM wallet_transactions WHERE wallet_address = ? AND txhash = ?")
    .get(walletAddress, txhash);

  return row ? mapTransaction(row) : null;
};

const inferTransactionDirection = ({
  walletAddress,
  fromAddress,
  toAddress,
}) => {
  if (walletAddress === fromAddress && walletAddress === toAddress) {
    return "self";
  }
  if (walletAddress === fromAddress) {
    return "outgoing";
  }
  if (walletAddress === toAddress) {
    return "incoming";
  }

  throw new Error("walletAddress is not related to this transaction");
};

const assertEntryKind = (entryKind) => {
  const normalized = String(entryKind ?? "").trim();
  const allowedKinds = [
    "transfer_out",
    "transfer_in",
    "payment_out",
    "payment_merchant",
    "payment_referral_level1",
    "payment_referral_level2",
    "investment_deposit",
    "investment_payout",
    "self_transfer",
  ];

  if (!allowedKinds.includes(normalized)) {
    throw new Error("entryKind is invalid");
  }

  return normalized;
};

const getPaymentOrderRow = (paymentOrderId) =>
  getDb()
    .prepare("SELECT * FROM payment_orders WHERE id = ?")
    .get(paymentOrderId);

const getPaymentOrder = (paymentOrderId) => {
  const row = getPaymentOrderRow(paymentOrderId);
  return row ? mapPaymentOrder(row) : null;
};

export const listPaymentTransfers = (paymentOrderId) => {
  const rows = getDb()
    .prepare(
      `SELECT *
       FROM payment_transfers
       WHERE payment_order_id = ?
       ORDER BY created_at ASC`,
    )
    .all(paymentOrderId);

  return rows.map(mapPaymentTransfer);
};

export const getPaymentOrderWithTransfers = (paymentOrderId) => {
  const order = getPaymentOrder(paymentOrderId);
  return order
    ? {
        ...order,
        transfers: listPaymentTransfers(paymentOrderId),
      }
    : null;
};

const recomputePaymentOrderStatus = (paymentOrderId) => {
  const transfers = listPaymentTransfers(paymentOrderId);
  const now = new Date().toISOString();

  let nextStatus = "created";
  let failureReason = null;
  let completedAt = null;

  const failedTransfers = transfers.filter((transfer) => transfer.status === "failed");
  const broadcastedTransfers = transfers.filter(
    (transfer) => transfer.status === "broadcasted",
  );
  const pendingTransfers = transfers.filter((transfer) => transfer.status === "pending");

  if (failedTransfers.length > 0 && broadcastedTransfers.length > 0) {
    nextStatus = "partial_failed";
    failureReason = failedTransfers[0].errorMessage ?? "payment partially failed";
  } else if (failedTransfers.length > 0) {
    nextStatus = "failed";
    failureReason = failedTransfers[0].errorMessage ?? "payment failed";
  } else if (pendingTransfers.length === 0 && broadcastedTransfers.length > 0) {
    nextStatus = "completed";
    completedAt = now;
  } else if (broadcastedTransfers.length > 0) {
    nextStatus = "processing";
  }

  getDb()
    .prepare(
      `UPDATE payment_orders
       SET status = ?, failure_reason = ?, updated_at = ?, completed_at = ?
       WHERE id = ?`,
    )
    .run(nextStatus, failureReason, now, completedAt, paymentOrderId);

  return getPaymentOrder(paymentOrderId);
};

const fetchChainDetail = async (txhash) => {
  try {
    const response = await fetch(`${SASEUL_GOLD_API_BASE_URL}/txs/${txhash}`, {
      method: "GET",
    });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
};

export const registerUser = ({
  loginId,
  password,
  phone,
  name,
  walletMode,
  wallet,
  mnemonic = null,
  isMerchant = false,
  merchantName = null,
  referrerWalletAddress = null,
}) => {
  const normalizedLoginId = assertLoginId(loginId);
  const normalizedPhone = assertPhone(phone);
  const normalizedName = assertName(name);
  const normalizedMerchantName =
    isMerchant && merchantName && String(merchantName).trim()
      ? String(merchantName).trim()
      : null;
  const normalizedWalletMode =
    walletMode === "imported" || walletMode === "generated" ? walletMode : null;
  const normalizedReferrer = assertOptionalAddress(
    referrerWalletAddress,
    "referrerWalletAddress",
  );

  if (!normalizedWalletMode) {
    throw new Error("walletMode must be imported or generated");
  }

  const nextWallet =
    normalizedWalletMode === "generated"
      ? wallet
        ? assertWalletShape(wallet)
        : generateWallet()
      : assertWalletShape(wallet ?? {});

  if (getUserByLoginIdRow(normalizedLoginId)) {
    throw new Error("이미 사용 중인 아이디입니다.");
  }

  const existingWallet = getDb()
    .prepare("SELECT 1 FROM user_wallets WHERE wallet_address = ?")
    .get(nextWallet.address);
  if (existingWallet) {
    throw new Error("이미 연결된 지갑 주소입니다.");
  }
  if (normalizedReferrer && normalizedReferrer === nextWallet.address) {
    throw new Error("내 지갑 주소는 추천인으로 사용할 수 없습니다.");
  }

  const userId = randomUUID();
  const now = new Date().toISOString();
  const passwordHash = hashPassword(password);
  const encryptedPrivateKey = encryptSecret(nextWallet.privateKey);
  const normalizedMnemonic =
    mnemonic && String(mnemonic).trim()
      ? String(mnemonic).trim().toLowerCase().replace(/\s+/g, " ")
      : null;
  const encryptedMnemonic = normalizedMnemonic ? encryptSecret(normalizedMnemonic) : null;

  getDb().exec("BEGIN IMMEDIATE");
  try {
    getDb()
      .prepare(
        `INSERT INTO users (
           id,
           login_id,
           password_hash,
           phone,
           name,
           status,
           is_merchant,
           created_at,
           updated_at,
           last_login_at
         )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        userId,
        normalizedLoginId,
        passwordHash,
        normalizedPhone,
        normalizedName,
        "active",
        0,
        now,
        now,
        now,
      );

    getDb()
      .prepare(
        `INSERT INTO user_wallets (
           id,
           user_id,
           wallet_address,
           public_key,
           encrypted_private_key,
           encrypted_mnemonic,
           mnemonic_available,
           wallet_source,
           created_at,
           updated_at
         )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        randomUUID(),
        userId,
        nextWallet.address,
        nextWallet.publicKey,
        encryptedPrivateKey,
        encryptedMnemonic,
        encryptedMnemonic ? 1 : 0,
        normalizedWalletMode,
        now,
        now,
      );

    getDb()
      .prepare(
        `INSERT INTO wallet_registry (
           wallet_address,
           is_merchant,
           merchant_name,
           referrer_wallet_address,
           is_active,
           created_at,
           updated_at
         )
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(wallet_address)
         DO UPDATE SET
           is_merchant = excluded.is_merchant,
           merchant_name = excluded.merchant_name,
           referrer_wallet_address = excluded.referrer_wallet_address,
           is_active = excluded.is_active,
           updated_at = excluded.updated_at`,
      )
      .run(
        nextWallet.address,
        0,
        null,
        normalizedReferrer,
        1,
        now,
        now,
      );

    if (isMerchant) {
      getDb()
        .prepare(
          `INSERT INTO merchant_profiles (
             wallet_address,
             user_id,
             merchant_name,
             category,
             logo_url,
             postal_code,
             address_main,
             address_detail,
             phone,
             description,
             status,
             review_note,
             created_at,
             updated_at,
       reviewed_at,
       reviewed_by
      )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(wallet_address)
       DO UPDATE SET
             merchant_name = excluded.merchant_name,
             phone = excluded.phone,
             status = excluded.status,
             updated_at = excluded.updated_at`,
        )
        .run(
          nextWallet.address,
          userId,
          normalizedMerchantName,
          null,
          null,
          null,
          null,
          null,
          normalizedPhone,
          null,
          "draft",
          null,
          now,
          now,
          null,
          null,
        );
    }

    getDb().exec("COMMIT");
  } catch (error) {
    getDb().exec("ROLLBACK");
    throw error;
  }

  const token = createSessionRecord(userId);
  const session = getAuthSession(token);
  if (!session) {
    throw new Error("failed to create session");
  }

  return {
    token,
    session,
  };
};

export const loginUser = ({ loginId, password }) => {
  const userRow = getUserByLoginIdRow(loginId);
  if (!userRow) {
    throw new Error("아이디 또는 비밀번호가 올바르지 않습니다.");
  }

  if (!verifyPassword(password, userRow.password_hash)) {
    throw new Error("아이디 또는 비밀번호가 올바르지 않습니다.");
  }

  if (userRow.status !== "active") {
    throw new Error("사용할 수 없는 계정입니다.");
  }

  const now = new Date().toISOString();
  getDb()
    .prepare("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?")
    .run(now, now, userRow.id);

  const token = createSessionRecord(userRow.id);
  const session = getAuthSession(token);
  if (!session) {
    throw new Error("failed to create session");
  }

  return {
    token,
    session,
  };
};

export const getAuthSession = (token) => {
  const normalizedToken = String(token ?? "").trim();
  if (!normalizedToken) {
    return null;
  }

  const row = getSessionRowByToken(normalizedToken);
  if (!row) {
    return null;
  }

  const session = mapAuthSession(row);
  if (session.revokedAt) {
    return null;
  }
  if (new Date(session.expiresAt).getTime() <= Date.now()) {
    return null;
  }
  if (session.status !== "active") {
    return null;
  }

  touchSession(session.id);

  const merchantProfileRow = getMerchantProfileRowByWallet(row.wallet_address);
  const merchantProfileChangeRequestRow = getMerchantProfileChangeRequestRowByWallet(
    row.wallet_address,
  );

  return {
    token: normalizedToken,
    user: {
      id: row.user_id,
      loginId: row.login_id,
      phone: row.phone,
      name: row.name,
      status: row.status,
      isMerchant: Boolean(row.is_merchant),
      createdAt: row.user_created_at,
      updatedAt: row.user_updated_at,
      lastLoginAt: row.last_login_at,
    },
    wallet: {
      id: row.wallet_id,
      address: row.wallet_address,
      publicKey: row.public_key,
      mnemonicAvailable: Boolean(row.mnemonic_available),
      walletSource: row.wallet_source,
    },
    merchantProfile: merchantProfileRow ? mapMerchantProfile(merchantProfileRow) : null,
    merchantProfileChangeRequest: merchantProfileChangeRequestRow
      ? mapMerchantProfileChangeRequest(merchantProfileChangeRequestRow)
      : null,
  };
};

export const revokeAuthSession = (token) => {
  const normalizedToken = String(token ?? "").trim();
  if (!normalizedToken) {
    return;
  }

  getDb()
    .prepare("UPDATE user_sessions SET revoked_at = ?, last_used_at = ? WHERE token_hash = ?")
    .run(
      new Date().toISOString(),
      new Date().toISOString(),
      hashSessionToken(normalizedToken),
    );
};

export const revealWalletMnemonic = ({ sessionToken, password }) => {
  const session = getAuthSession(sessionToken);
  if (!session) {
    throw new Error("로그인이 필요합니다.");
  }

  const userRow = getUserByLoginIdRow(session.user.loginId);
  if (!userRow) {
    throw new Error("사용자 정보를 찾을 수 없습니다.");
  }

  if (!verifyPassword(password, userRow.password_hash)) {
    throw new Error("비밀번호가 올바르지 않습니다.");
  }

  const walletRow = getUserWalletByUserIdRow(session.user.id);
  if (!walletRow || !walletRow.encrypted_mnemonic || !walletRow.mnemonic_available) {
    throw new Error("저장된 복구 문구가 없습니다.");
  }

  return {
    mnemonic: decryptSecret(walletRow.encrypted_mnemonic),
  };
};

export const loginAdmin = ({ password }) => {
  const adminPassword = String(process.env.OOWA_ADMIN_PASSWORD ?? "");
  if (!adminPassword) {
    throw new Error("admin password is not configured");
  }

  if (String(password ?? "") !== adminPassword) {
    throw new Error("관리자 비밀번호가 올바르지 않습니다.");
  }

  const token = createAdminSessionRecord();
  return {
    token,
    expiresInHours: 12,
  };
};

export const getAdminSession = (token) => {
  const normalizedToken = String(token ?? "").trim();
  if (!normalizedToken) {
    return null;
  }

  const row = getAdminSessionRowByToken(normalizedToken);
  if (!row || row.revoked_at) {
    return null;
  }
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    return null;
  }

  touchAdminSession(row.id);

  return {
    token: normalizedToken,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
  };
};

export const revokeAdminSession = (token) => {
  const normalizedToken = String(token ?? "").trim();
  if (!normalizedToken) {
    return;
  }

  getDb()
    .prepare(
      `UPDATE admin_sessions
       SET revoked_at = COALESCE(revoked_at, ?),
           last_used_at = ?
       WHERE token_hash = ?`,
    )
    .run(
      new Date().toISOString(),
      new Date().toISOString(),
      hashSessionToken(normalizedToken),
    );
};

export const getInvestmentProductDetails = () => getInvestmentProduct();

export const listAuthenticatedInvestments = ({ sessionToken, page = 0, limit = 10 }) => {
  const session = getAuthSession(sessionToken);
  if (!session) {
    throw new Error("로그인이 필요합니다.");
  }

  const offset = page * limit;

  const totalRow = getDb()
    .prepare(
      `SELECT COUNT(*) AS total
       FROM investment_positions
       WHERE user_id = ?`,
    )
    .get(session.user.id);

  const rows = getDb()
    .prepare(
      `SELECT *
       FROM investment_positions
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
    )
    .all(session.user.id, limit, offset);

  return {
    product: getInvestmentProduct(),
    positions: rows.map(mapInvestmentPosition),
    total: totalRow.total,
    page,
    limit,
  };
};

export const startAuthenticatedInvestment = async ({
  sessionToken,
  amountRaw,
}) => {
  const session = getAuthSession(sessionToken);
  if (!session) {
    throw new Error("로그인이 필요합니다.");
  }

  const normalizedAmountRaw = assertRawAmount(amountRaw, "amountRaw");
  const walletRow = getUserWalletByUserIdRow(session.user.id);
  if (!walletRow) {
    throw new Error("지갑 정보를 찾을 수 없습니다.");
  }

  const userWallet = deriveWalletFromPrivateKey(
    decryptSecret(walletRow.encrypted_private_key),
  );
  if (
    userWallet.address !== session.wallet.address ||
    userWallet.publicKey !== session.wallet.publicKey
  ) {
    throw new Error("저장된 지갑 정보가 일치하지 않습니다.");
  }

  const investmentPoolWallet = getInvestmentPoolWallet();
  const signedPayload = await buildSignedOowaTransfer({
    wallet: userWallet,
    toAddress: investmentPoolWallet.address,
    amountRaw: normalizedAmountRaw,
  });
  const broadcastResponse = await broadcastSignedTransfer(signedPayload);
  const savedTransaction = await saveWalletTransaction({
    walletAddress: userWallet.address,
    direction: "outgoing",
    entryKind: "investment_deposit",
    signedPayload,
    broadcastResponse,
    trackRecipient: false,
  });

  const now = new Date().toISOString();
  const principal = BigInt(normalizedAmountRaw);
  const maxRewardRaw = (
    (principal * INVESTMENT_CAP_REWARD_BP) /
    BPS_DENOMINATOR
  ).toString();
  const positionId = randomUUID();

  getDb()
    .prepare(
      `INSERT INTO investment_positions (
         id,
         user_id,
         wallet_id,
         wallet_address,
         principal_raw,
         principal_display,
         daily_rate_bp,
         cap_total_bp,
         max_reward_raw,
         deposit_txhash,
         payout_txhash,
         status,
         started_at,
         ended_at,
         created_at,
         updated_at,
         final_reward_raw,
         final_return_raw
       )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      positionId,
      session.user.id,
      session.wallet.id,
      session.wallet.address,
      normalizedAmountRaw,
      formatRawTokenAmount(normalizedAmountRaw, OOWA_TOKEN.decimals),
      Number(INVESTMENT_DAILY_RATE_BP),
      Number(INVESTMENT_CAP_TOTAL_BP),
      maxRewardRaw,
      savedTransaction.txhash,
      null,
      "active",
      now,
      null,
      now,
      now,
      null,
      null,
    );

  return {
    ok: true,
    userMessage: "투자를 시작했고 잔액을 갱신했습니다.",
    product: getInvestmentProduct(),
    position: mapInvestmentPosition(getInvestmentPositionRowById(positionId)),
    transaction: savedTransaction,
  };
};

export const stopAuthenticatedInvestment = async ({
  sessionToken,
  positionId,
}) => {
  const session = getAuthSession(sessionToken);
  if (!session) {
    throw new Error("로그인이 필요합니다.");
  }

  const row = getInvestmentPositionRowById(positionId);
  if (!row) {
    throw new Error("투자 건을 찾을 수 없습니다.");
  }
  if (row.user_id !== session.user.id) {
    throw new Error("본인의 투자 건만 종료할 수 있습니다.");
  }
  if (row.status !== "active") {
    throw new Error("이미 종료된 투자 건입니다.");
  }

  const metrics = computeInvestmentPositionMetrics(row);
  const investmentPoolWallet = getInvestmentPoolWallet();
  const signedPayload = await buildSignedOowaTransfer({
    wallet: investmentPoolWallet,
    toAddress: session.wallet.address,
    amountRaw: metrics.totalReturnRaw,
  });

  let broadcastResponse;
  try {
    broadcastResponse = await broadcastSignedTransfer(signedPayload);
  } catch (error) {
    const now = new Date().toISOString();
    getDb()
      .prepare(
        `INSERT INTO investment_payouts (
           id,
           position_id,
           payout_type,
           principal_raw,
           reward_raw,
           total_raw,
           txhash,
           status,
           error_message,
           created_at,
           updated_at
         )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        randomUUID(),
        row.id,
        "user_stop",
        row.principal_raw,
        metrics.accruedRewardRaw,
        metrics.totalReturnRaw,
        null,
        "failed",
        error instanceof Error ? error.message.slice(0, 500) : "investment payout failed",
        now,
        now,
      );
    throw error;
  }

  const savedTransaction = await saveWalletTransaction({
    walletAddress: session.wallet.address,
    direction: "incoming",
    entryKind: "investment_payout",
    signedPayload,
    broadcastResponse,
    trackRecipient: false,
  });
  const now = new Date().toISOString();

  getDb().exec("BEGIN IMMEDIATE");
  try {
    getDb()
      .prepare(
        `INSERT INTO investment_payouts (
           id,
           position_id,
           payout_type,
           principal_raw,
           reward_raw,
           total_raw,
           txhash,
           status,
           error_message,
           created_at,
           updated_at
         )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        randomUUID(),
        row.id,
        "user_stop",
        row.principal_raw,
        metrics.accruedRewardRaw,
        metrics.totalReturnRaw,
        savedTransaction.txhash,
        "broadcasted",
        null,
        now,
        now,
      );

    getDb()
      .prepare(
        `UPDATE investment_positions
         SET payout_txhash = ?,
             status = ?,
             ended_at = ?,
             updated_at = ?,
             final_reward_raw = ?,
             final_return_raw = ?
         WHERE id = ?`,
      )
      .run(
        savedTransaction.txhash,
        "completed",
        now,
        now,
        metrics.accruedRewardRaw,
        metrics.totalReturnRaw,
        row.id,
      );

    getDb().exec("COMMIT");
  } catch (error) {
    getDb().exec("ROLLBACK");
    throw error;
  }

  return {
    ok: true,
    userMessage: "투자를 종료했고 원금과 누적 보상을 돌려받았습니다.",
    position: mapInvestmentPosition(getInvestmentPositionRowById(row.id)),
    payout: mapInvestmentPayout(
      getDb()
        .prepare(
          `SELECT *
           FROM investment_payouts
           WHERE position_id = ?
           ORDER BY created_at DESC
           LIMIT 1`,
        )
        .get(row.id),
    ),
    transaction: savedTransaction,
  };
};

export const executeAuthenticatedPayment = async ({
  sessionToken,
  toWalletAddress,
  amountRaw,
}) => {
  const session = getAuthSession(sessionToken);
  if (!session) {
    throw new Error("로그인이 필요합니다.");
  }

  const walletRow = getUserWalletByUserIdRow(session.user.id);
  if (!walletRow) {
    throw new Error("지갑 정보를 찾을 수 없습니다.");
  }

  const privateKey = decryptSecret(walletRow.encrypted_private_key);
  const wallet = deriveWalletFromPrivateKey(privateKey);
  if (wallet.address !== session.wallet.address || wallet.publicKey !== session.wallet.publicKey) {
    throw new Error("저장된 지갑 정보가 일치하지 않습니다.");
  }

  const payment = createPaymentOrder({
    payerWalletAddress: wallet.address,
    toWalletAddress,
    amountRaw,
  });

  const broadcastResults = [];
  let latestRecipients = listWalletRecipients(wallet.address);

  for (const transfer of payment.quote.transfers) {
    try {
      const signedPayload = await buildSignedOowaTransfer({
        wallet,
        toAddress: transfer.toWalletAddress,
        amountRaw: transfer.amountRaw,
      });
      const broadcastResponse = await broadcastSignedTransfer(signedPayload);
      const saved = await recordPaymentTransferBroadcasted({
        paymentOrderId: payment.paymentOrder.id,
        transferRole: transfer.role,
        walletAddress: wallet.address,
        signedPayload,
        broadcastResponse,
        trackRecipient: transfer.role === "recipient" || transfer.role === "merchant",
      });
      latestRecipients = saved.recipients;
      broadcastResults.push({
        role: transfer.role,
        toWalletAddress: transfer.toWalletAddress,
        amountRaw: transfer.amountRaw,
        amountDisplay: transfer.amountDisplay,
        txhash: saved.transaction.txhash,
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "결제 전송 중 오류가 발생했습니다.";
      const failed = recordPaymentTransferFailed({
        paymentOrderId: payment.paymentOrder.id,
        transferRole: transfer.role,
        errorMessage: message,
      });

      if (payment.quote.isMerchantPayment) {
        return {
          ok: true,
          userMessage: "사용자는 24시간 이내로 추천인에게 환급됩니다.",
          hadFailure: true,
          paymentOrder: failed.paymentOrder,
          transfers: failed.transfers,
          quote: payment.quote,
          recipients: latestRecipients,
          results: broadcastResults,
        };
      }

      throw error;
    }
  }

  return {
    ok: true,
    userMessage: payment.quote.isMerchantPayment
      ? "가맹점 결제를 완료했고 잔액을 갱신했습니다."
      : "전송을 완료했고 잔액을 갱신했습니다.",
    hadFailure: false,
    paymentOrder: getPaymentOrder(payment.paymentOrder.id),
    transfers: listPaymentTransfers(payment.paymentOrder.id),
    quote: payment.quote,
    recipients: latestRecipients,
    results: broadcastResults,
  };
};

export const listWalletTransactions = (walletAddress) => {
  const normalizedWallet = assertAddress(walletAddress, "walletAddress");
  const rows = getDb()
    .prepare(
      `SELECT *
       FROM wallet_transactions
       WHERE wallet_address = ?
       ORDER BY COALESCE(chain_timestamp, created_at) DESC
       LIMIT 50`,
    )
    .all(normalizedWallet);

  return rows.map((row) => ({
    ...mapTransaction(row),
    direction: inferTransactionDirection({
      walletAddress: normalizedWallet,
      fromAddress: assertAddress(row.from_address, "from_address"),
      toAddress: assertAddress(row.to_address, "to_address"),
    }),
  }));
};

export const listWalletActivity = (
  walletAddress,
  { page = 0, limit = 20, direction = null, kindFilter = null } = {},
) => {
  const normalizedWallet = assertAddress(walletAddress, "walletAddress");
  const offset = page * limit;

  // Collect payment-related txhashes to exclude from wallet_transactions
  const paymentTxhashRows = getDb()
    .prepare(
      `SELECT DISTINCT pt.txhash
       FROM payment_transfers pt
       JOIN payment_orders po ON po.id = pt.payment_order_id
       WHERE po.payer_wallet_address = ?
         AND pt.txhash IS NOT NULL`,
    )
    .all(normalizedWallet);

  const excludedTxhashes = paymentTxhashRows.map((r) => r.txhash).filter(Boolean);
  const txExclude =
    excludedTxhashes.length > 0
      ? `AND txhash NOT IN (${excludedTxhashes.map(() => "?").join(",")})`
      : "";

  // Kind-based inclusion flags
  // kindFilter: null/"all" = 전체, "transfer" = 송금/입금, "payment" = 결제,
  //             "investment" = 투자, "reward" = 보상
  const KIND_TX_ENTRY_KINDS = {
    transfer: ["transfer_out", "transfer_in", "self_transfer"],
    investment: ["investment_deposit", "investment_payout"],
    reward: ["payment_referral_level1", "payment_referral_level2", "payment_merchant"],
  };
  const includeTx = !kindFilter || kindFilter !== "payment";
  const includePayments =
    (!kindFilter || kindFilter === "payment") && direction !== "incoming";

  // entry_kind filter for wallet_transactions when a specific kind is selected
  const txEntryKinds = kindFilter ? KIND_TX_ENTRY_KINDS[kindFilter] : null;
  const entryKindFilter = txEntryKinds
    ? `AND entry_kind IN (${txEntryKinds.map(() => "?").join(",")})`
    : "";
  const entryKindParams = txEntryKinds ?? [];

  // direction filter for wallet_transactions
  const dirFilter = direction ? `AND direction = ?` : "";
  const dirParams = direction ? [direction] : [];

  // Normalise chain_timestamp (numeric string or ISO) to Unix seconds (REAL)
  // so it sorts correctly against ISO created_at strings.
  const TX_SORT_TS = `
    CASE
      WHEN chain_timestamp IS NOT NULL AND chain_timestamp GLOB '[0-9]*' THEN
        CASE WHEN CAST(chain_timestamp AS REAL) > 9999999999.0
          THEN CAST(chain_timestamp AS REAL) / 1000.0
          ELSE CAST(chain_timestamp AS REAL)
        END
      WHEN chain_timestamp IS NOT NULL THEN
        CAST(strftime('%s', chain_timestamp) AS REAL)
      ELSE
        CAST(strftime('%s', created_at) AS REAL)
    END`;

  // ── total count ──────────────────────────────────────────────────────────
  const txCountParams = includeTx
    ? [normalizedWallet, ...excludedTxhashes, ...entryKindParams, ...dirParams]
    : [];
  const paymentCountParams = includePayments ? [normalizedWallet] : [];

  const txCountSql = includeTx
    ? `SELECT 1 FROM wallet_transactions
       WHERE wallet_address = ? ${txExclude} ${entryKindFilter} ${dirFilter}`
    : "";
  const paymentCountSql = includePayments
    ? `SELECT 1 FROM payment_orders WHERE payer_wallet_address = ?`
    : "";
  const unionCountSql =
    txCountSql && paymentCountSql
      ? `${txCountSql} UNION ALL ${paymentCountSql}`
      : txCountSql || paymentCountSql;

  const totalRow = getDb()
    .prepare(`SELECT COUNT(*) AS total FROM (${unionCountSql})`)
    .get(...txCountParams, ...paymentCountParams);
  const total = totalRow.total;

  // ── paginated ids ─────────────────────────────────────────────────────────
  const txPageParams = includeTx
    ? [normalizedWallet, ...excludedTxhashes, ...entryKindParams, ...dirParams]
    : [];
  const paymentPageParams = includePayments ? [normalizedWallet] : [];

  const txPageSql = includeTx
    ? `SELECT 'transaction' AS kind,
              id            AS row_id,
              ${TX_SORT_TS} AS sort_ts
       FROM wallet_transactions
       WHERE wallet_address = ? ${txExclude} ${entryKindFilter} ${dirFilter}`
    : "";
  const paymentPageSql = includePayments
    ? `SELECT 'payment' AS kind,
              id        AS row_id,
              CAST(strftime('%s', COALESCE(completed_at, updated_at, created_at)) AS REAL) AS sort_ts
       FROM payment_orders
       WHERE payer_wallet_address = ?`
    : "";
  const unionPageSql =
    txPageSql && paymentPageSql
      ? `${txPageSql} UNION ALL ${paymentPageSql}`
      : txPageSql || paymentPageSql;

  const pageRows = getDb()
    .prepare(
      `SELECT kind, row_id FROM (${unionPageSql})
       ORDER BY sort_ts DESC
       LIMIT ? OFFSET ?`,
    )
    .all(...txPageParams, ...paymentPageParams, limit, offset);

  // ── fetch full rows for this page ─────────────────────────────────────────
  const transactionIds = pageRows.filter((r) => r.kind === "transaction").map((r) => r.row_id);
  const paymentIds = pageRows.filter((r) => r.kind === "payment").map((r) => r.row_id);

  const transactionMap = new Map();
  if (transactionIds.length > 0) {
    const rows = getDb()
      .prepare(
        `SELECT * FROM wallet_transactions
         WHERE id IN (${transactionIds.map(() => "?").join(",")})`,
      )
      .all(...transactionIds);
    for (const row of rows) {
      const tx = {
        ...mapTransaction(row),
        direction: inferTransactionDirection({
          walletAddress: normalizedWallet,
          fromAddress: assertAddress(row.from_address, "from_address"),
          toAddress: assertAddress(row.to_address, "to_address"),
        }),
      };
      transactionMap.set(row.id, tx);
    }
  }

  const paymentMap = new Map();
  if (paymentIds.length > 0) {
    const rows = getDb()
      .prepare(
        `SELECT po.*, mp.merchant_name
         FROM payment_orders po
         LEFT JOIN merchant_profiles mp
           ON mp.wallet_address = po.merchant_wallet_address
         WHERE po.id IN (${paymentIds.map(() => "?").join(",")})`,
      )
      .all(...paymentIds);
    for (const row of rows) {
      const paymentOrder = mapPaymentOrder(row);
      const transfers = listPaymentTransfers(row.id);
      paymentMap.set(row.id, {
        ...paymentOrder,
        merchantName: row.merchant_name ?? null,
        transfers,
      });
    }
  }

  // ── reconstruct in sort order ─────────────────────────────────────────────
  const items = pageRows
    .map(({ kind, row_id }) => {
      if (kind === "transaction") {
        const tx = transactionMap.get(row_id);
        if (!tx) return null;
        return {
          id: tx.id,
          kind: "transaction",
          direction: tx.direction,
          sortTimestamp: tx.chainTimestamp ?? tx.createdAt,
          createdAt: tx.createdAt,
          status: tx.status,
          transaction: tx,
        };
      }
      const payment = paymentMap.get(row_id);
      if (!payment) return null;
      return {
        id: payment.id,
        kind: "payment",
        direction: "outgoing",
        sortTimestamp: payment.completedAt ?? payment.updatedAt ?? payment.createdAt,
        createdAt: payment.createdAt,
        status: payment.status,
        payment,
      };
    })
    .filter(Boolean);

  return { items, total, page, limit };
};

export const getMerchantProfile = (walletAddress) => {
  const row = getMerchantProfileRowByWallet(walletAddress);
  return row ? mapMerchantProfile(row) : null;
};

export const getMerchantProfileChangeRequest = (walletAddress) => {
  const row = getMerchantProfileChangeRequestRowByWallet(walletAddress);
  return row ? mapMerchantProfileChangeRequest(row) : null;
};

export const listAdminMerchantProfiles = ({
  statuses = ["draft", "pending", "denied"],
  limit = 20,
  offset = 0,
} = {}) => {
  const allowedStatuses = Array.isArray(statuses) && statuses.length > 0 ? statuses : ["draft"];
  const placeholders = allowedStatuses.map(() => "?").join(", ");
  const normalizedLimit = Math.min(Math.max(1, Number(limit) || 20), 100);
  const normalizedOffset = Math.max(0, Number(offset) || 0);

  const total = getDb()
    .prepare(`SELECT COUNT(*) AS cnt FROM merchant_profiles WHERE status IN (${placeholders})`)
    .get(...allowedStatuses).cnt;

  const rows = getDb()
    .prepare(
      `SELECT *
       FROM merchant_profiles
       WHERE status IN (${placeholders})
       ORDER BY updated_at DESC
       LIMIT ? OFFSET ?`,
    )
    .all(...allowedStatuses, normalizedLimit, normalizedOffset);

  return { profiles: rows.map(mapMerchantProfile), total, limit: normalizedLimit, offset: normalizedOffset };
};

export const listApprovedMerchantProfiles = () => {
  const rows = getDb()
    .prepare(
      `SELECT *
       FROM merchant_profiles
       WHERE status = 'approved'
         AND lat IS NOT NULL
         AND lng IS NOT NULL
       ORDER BY updated_at DESC
       LIMIT 500`,
    )
    .all();

  return rows.map(mapMerchantProfile);
};

export const listAdminMerchantChangeRequests = ({
  statuses = ["pending"],
  limit = 20,
  offset = 0,
} = {}) => {
  const allowedStatuses = Array.isArray(statuses) && statuses.length > 0 ? statuses : ["pending"];
  const placeholders = allowedStatuses.map(() => "?").join(", ");
  const normalizedLimit = Math.min(Math.max(1, Number(limit) || 20), 100);
  const normalizedOffset = Math.max(0, Number(offset) || 0);

  const total = getDb()
    .prepare(
      `SELECT COUNT(*) AS cnt
       FROM merchant_profile_change_requests
       WHERE status IN (${placeholders})`,
    )
    .get(...allowedStatuses).cnt;

  const rows = getDb()
    .prepare(
      `SELECT *
       FROM merchant_profile_change_requests
       WHERE status IN (${placeholders})
       ORDER BY updated_at DESC
       LIMIT ? OFFSET ?`,
    )
    .all(...allowedStatuses, normalizedLimit, normalizedOffset);

  return {
    changeRequests: rows.map(mapMerchantProfileChangeRequest),
    total,
    limit: normalizedLimit,
    offset: normalizedOffset,
  };
};

export const upsertMerchantProfile = ({
  sessionToken,
  merchantName,
  category,
  logoUrl = null,
  postalCode = null,
  addressMain,
  addressDetail = null,
  lat = null,
  lng = null,
  phone = null,
  description = null,
}) => {
  const session = getAuthSession(sessionToken);
  if (!session) {
    throw new Error("로그인이 필요합니다.");
  }

  const normalizedMerchantName = String(merchantName ?? "").trim();
  const normalizedCategory = String(category ?? "").trim();
  const normalizedAddressMain = String(addressMain ?? "").trim();
  if (normalizedMerchantName.length < 2) {
    throw new Error("가맹점명은 2자 이상 입력해주세요.");
  }
  if (normalizedCategory.length < 1) {
    throw new Error("카테고리를 입력해주세요.");
  }
  if (normalizedAddressMain.length < 4) {
    throw new Error("주소를 입력해주세요.");
  }
  const normalizedLat = assertOptionalCoordinate(lat, "lat");
  const normalizedLng = assertOptionalCoordinate(lng, "lng");

  const now = new Date().toISOString();
  const existing = getMerchantProfile(session.wallet.address);
  if (existing?.status === "pending") {
    throw new Error("심사 중인 가맹점 정보는 수정할 수 없습니다.");
  }
  if (existing?.status === "approved") {
    const existingRequest = getMerchantProfileChangeRequest(session.wallet.address);
    getDb()
      .prepare(
        `INSERT INTO merchant_profile_change_requests (
           wallet_address,
           user_id,
           merchant_name,
           category,
           logo_url,
           postal_code,
           address_main,
           address_detail,
           lat,
           lng,
           phone,
           description,
           status,
           review_note,
           created_at,
           updated_at,
           reviewed_at,
           reviewed_by
         )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(wallet_address)
         DO UPDATE SET
           merchant_name = excluded.merchant_name,
           category = excluded.category,
           logo_url = excluded.logo_url,
           postal_code = excluded.postal_code,
           address_main = excluded.address_main,
           address_detail = excluded.address_detail,
           lat = excluded.lat,
           lng = excluded.lng,
           phone = excluded.phone,
           description = excluded.description,
           status = excluded.status,
           review_note = excluded.review_note,
           updated_at = excluded.updated_at,
           reviewed_at = excluded.reviewed_at,
           reviewed_by = excluded.reviewed_by`,
      )
      .run(
        session.wallet.address,
        session.user.id,
        normalizedMerchantName,
        normalizedCategory,
        logoUrl && String(logoUrl).trim() ? String(logoUrl).trim() : null,
        postalCode && String(postalCode).trim() ? String(postalCode).trim() : null,
        normalizedAddressMain,
        addressDetail && String(addressDetail).trim() ? String(addressDetail).trim() : null,
        normalizedLat,
        normalizedLng,
        phone && String(phone).trim() ? String(phone).trim() : session.user.phone,
        description && String(description).trim() ? String(description).trim() : null,
        "pending",
        null,
        existingRequest?.createdAt ?? now,
        now,
        null,
        null,
      );

    return {
      profile: existing,
      changeRequest: getMerchantProfileChangeRequest(session.wallet.address),
    };
  }
  const nextStatus = existing?.status === "approved" ? "approved" : "pending";

  getDb()
    .prepare(
      `INSERT INTO merchant_profiles (
         wallet_address,
         user_id,
         merchant_name,
         category,
         logo_url,
         postal_code,
         address_main,
         address_detail,
         lat,
         lng,
         phone,
         description,
         status,
         review_note,
         created_at,
         updated_at,
       reviewed_at,
       reviewed_by
      )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(wallet_address)
       DO UPDATE SET
         merchant_name = excluded.merchant_name,
         category = excluded.category,
         logo_url = excluded.logo_url,
         postal_code = excluded.postal_code,
         address_main = excluded.address_main,
         address_detail = excluded.address_detail,
         lat = excluded.lat,
         lng = excluded.lng,
         phone = excluded.phone,
         description = excluded.description,
         status = excluded.status,
         review_note = excluded.review_note,
         updated_at = excluded.updated_at,
         reviewed_at = excluded.reviewed_at,
         reviewed_by = excluded.reviewed_by`,
    )
    .run(
      session.wallet.address,
      session.user.id,
      normalizedMerchantName,
      normalizedCategory,
      logoUrl && String(logoUrl).trim() ? String(logoUrl).trim() : null,
      postalCode && String(postalCode).trim() ? String(postalCode).trim() : null,
      normalizedAddressMain,
      addressDetail && String(addressDetail).trim() ? String(addressDetail).trim() : null,
      normalizedLat,
      normalizedLng,
      phone && String(phone).trim() ? String(phone).trim() : session.user.phone,
      description && String(description).trim() ? String(description).trim() : null,
      nextStatus,
      nextStatus === "approved" ? existing?.reviewNote ?? null : null,
      existing?.createdAt ?? now,
      now,
      nextStatus === "approved" ? existing?.reviewedAt ?? null : null,
      nextStatus === "approved" ? existing?.reviewedBy ?? null : null,
    );

  return {
    profile: getMerchantProfile(session.wallet.address),
    changeRequest: getMerchantProfileChangeRequest(session.wallet.address),
  };
};

export const reviewMerchantProfile = ({
  walletAddress,
  status,
  reviewNote = null,
  reviewedBy = "admin",
}) => {
  const normalizedWallet = assertAddress(walletAddress, "walletAddress");
  const existing = getMerchantProfile(normalizedWallet);
  if (!existing) {
    throw new Error("merchant profile not found");
  }
  if (!["approved", "denied"].includes(status)) {
    throw new Error("status must be approved or denied");
  }

  const now = new Date().toISOString();
  getDb().exec("BEGIN IMMEDIATE");
  try {
    getDb()
      .prepare(
        `UPDATE merchant_profiles
         SET status = ?, review_note = ?, updated_at = ?, reviewed_at = ?, reviewed_by = ?
         WHERE wallet_address = ?`,
      )
      .run(
        status,
        reviewNote && String(reviewNote).trim() ? String(reviewNote).trim() : null,
        now,
        now,
        reviewedBy,
        normalizedWallet,
      );

    getDb()
      .prepare("UPDATE users SET is_merchant = ?, updated_at = ? WHERE id = ?")
      .run(status === "approved" ? 1 : 0, now, existing.userId);

    getDb().exec("COMMIT");
  } catch (error) {
    getDb().exec("ROLLBACK");
    throw error;
  }

  return getMerchantProfile(normalizedWallet);
};

export const reviewMerchantProfileChangeRequest = ({
  walletAddress,
  status,
  reviewNote = null,
  reviewedBy = "admin",
}) => {
  const normalizedWallet = assertAddress(walletAddress, "walletAddress");
  const existing = getMerchantProfileChangeRequest(normalizedWallet);
  if (!existing) {
    throw new Error("merchant profile change request not found");
  }
  if (!["approved", "denied"].includes(status)) {
    throw new Error("status must be approved or denied");
  }

  const now = new Date().toISOString();
  getDb().exec("BEGIN IMMEDIATE");
  try {
    if (status === "approved") {
      getDb()
        .prepare(
          `UPDATE merchant_profiles
           SET merchant_name = ?,
               category = ?,
               logo_url = ?,
               postal_code = ?,
               address_main = ?,
               address_detail = ?,
               lat = ?,
               lng = ?,
               phone = ?,
               description = ?,
               review_note = ?,
               updated_at = ?,
               reviewed_at = ?,
               reviewed_by = ?
           WHERE wallet_address = ?`,
        )
        .run(
          existing.merchantName,
          existing.category,
          existing.logoUrl,
          existing.postalCode,
          existing.addressMain,
          existing.addressDetail,
          existing.lat,
          existing.lng,
          existing.phone,
          existing.description,
          reviewNote && String(reviewNote).trim() ? String(reviewNote).trim() : null,
          now,
          now,
          reviewedBy,
          normalizedWallet,
        );
    }

    getDb()
      .prepare(
        `UPDATE merchant_profile_change_requests
         SET status = ?, review_note = ?, updated_at = ?, reviewed_at = ?, reviewed_by = ?
         WHERE wallet_address = ?`,
      )
      .run(
        status,
        reviewNote && String(reviewNote).trim() ? String(reviewNote).trim() : null,
        now,
        now,
        reviewedBy,
        normalizedWallet,
      );

    getDb().exec("COMMIT");
  } catch (error) {
    getDb().exec("ROLLBACK");
    throw error;
  }

  return getMerchantProfileChangeRequest(normalizedWallet);
};

export const listAdminUsers = ({
  search = null,
  statuses = ["active", "disabled", "deleted"],
  limit = 20,
  offset = 0,
} = {}) => {
  const allowedStatuses =
    Array.isArray(statuses) && statuses.length > 0
      ? statuses.map((status) => String(status).trim()).filter(Boolean)
      : ["active", "disabled", "deleted"];
  const statusPlaceholders = allowedStatuses.map(() => "?").join(", ");
  const normalizedLimit = Math.min(Math.max(1, Number(limit) || 20), 100);
  const normalizedOffset = Math.max(0, Number(offset) || 0);
  const params = [...allowedStatuses];
  let searchClause = "";

  if (search && String(search).trim()) {
    const normalizedSearch = `%${String(search).trim()}%`;
    searchClause = `
      AND (
        u.login_id LIKE ?
        OR u.name LIKE ?
        OR u.phone LIKE ?
        OR w.wallet_address LIKE ?
      )
    `;
    params.push(
      normalizedSearch,
      normalizedSearch,
      normalizedSearch,
      normalizedSearch,
    );
  }

  const total = getDb()
    .prepare(
      `SELECT COUNT(*) AS cnt
       FROM users u
       JOIN user_wallets w ON w.user_id = u.id
       LEFT JOIN merchant_profiles mp ON mp.user_id = u.id
       WHERE u.status IN (${statusPlaceholders})
       ${searchClause}`,
    )
    .get(...params).cnt;

  const rows = getDb()
    .prepare(
      `SELECT
         u.id AS user_id,
         u.login_id,
         u.phone,
         u.name,
         u.status,
         u.is_merchant,
         u.created_at,
         u.updated_at,
         u.last_login_at,
         w.id AS wallet_id,
         w.wallet_address,
         w.public_key,
         w.mnemonic_available,
         w.wallet_source,
         mp.status AS merchant_status,
         mp.merchant_name,
         (
           SELECT COUNT(*)
           FROM wallet_transactions wt
           WHERE wt.wallet_address = w.wallet_address
         ) AS transaction_count,
         (
           SELECT COUNT(*)
           FROM wallet_recipients wr
           WHERE wr.wallet_address = w.wallet_address
         ) AS recipient_count,
         (
           SELECT COUNT(*)
           FROM payment_orders po
           WHERE po.payer_wallet_address = w.wallet_address
              OR po.merchant_wallet_address = w.wallet_address
         ) AS payment_count,
         (
           SELECT COUNT(*)
           FROM investment_positions ip
           WHERE ip.user_id = u.id
         ) AS investment_count,
         (
           SELECT COUNT(*)
           FROM investment_positions ip
           WHERE ip.user_id = u.id
             AND ip.status = 'active'
         ) AS active_investment_count
       FROM users u
       JOIN user_wallets w ON w.user_id = u.id
       LEFT JOIN merchant_profiles mp ON mp.user_id = u.id
       WHERE u.status IN (${statusPlaceholders})
       ${searchClause}
       ORDER BY u.created_at DESC
       LIMIT ? OFFSET ?`,
    )
    .all(...params, normalizedLimit, normalizedOffset);

  return { users: rows.map(mapAdminUser), total, limit: normalizedLimit, offset: normalizedOffset };
};

export const getAdminInvestmentSummary = () => {
  const rows = getDb()
    .prepare(
      `SELECT
         ip.*,
         (
           SELECT payout.status
           FROM investment_payouts payout
           WHERE payout.position_id = ip.id
           ORDER BY payout.created_at DESC
           LIMIT 1
         ) AS latest_payout_status
       FROM investment_positions ip`,
    )
    .all();

  let activeCount = 0;
  let completedCount = 0;
  let failedCount = 0;
  let principalTotalRaw = 0n;
  let accruedRewardTotalRaw = 0n;
  let totalReturnTotalRaw = 0n;

  for (const row of rows) {
    const metrics = computeInvestmentPositionMetrics(row);
    const adminStatus =
      row.latest_payout_status === "failed" ? "payout_failed" : row.status;

    if (adminStatus === "active") {
      activeCount += 1;
      principalTotalRaw += BigInt(row.principal_raw);
      accruedRewardTotalRaw += BigInt(metrics.accruedRewardRaw);
      totalReturnTotalRaw += BigInt(metrics.totalReturnRaw);
      continue;
    }

    if (adminStatus === "completed") {
      completedCount += 1;
      continue;
    }

    if (adminStatus === "payout_failed") {
      failedCount += 1;
    }
  }

  return {
    activeCount,
    completedCount,
    failedCount,
    principalTotalRaw: principalTotalRaw.toString(),
    principalTotalDisplay: formatRawTokenAmount(
      principalTotalRaw.toString(),
      OOWA_TOKEN.decimals,
    ),
    accruedRewardTotalRaw: accruedRewardTotalRaw.toString(),
    accruedRewardTotalDisplay: formatRawTokenAmount(
      accruedRewardTotalRaw.toString(),
      OOWA_TOKEN.decimals,
    ),
    totalReturnTotalRaw: totalReturnTotalRaw.toString(),
    totalReturnTotalDisplay: formatRawTokenAmount(
      totalReturnTotalRaw.toString(),
      OOWA_TOKEN.decimals,
    ),
  };
};

export const listAdminInvestments = ({
  statuses = ["active", "completed", "payout_failed"],
  limit = 20,
  offset = 0,
} = {}) => {
  const allowedStatuses =
    Array.isArray(statuses) && statuses.length > 0
      ? statuses.map((status) => String(status).trim()).filter(Boolean)
      : ["active", "completed", "payout_failed"];
  const placeholders = allowedStatuses.map(() => "?").join(", ");
  const normalizedLimit = Math.min(Math.max(1, Number(limit) || 20), 100);
  const normalizedOffset = Math.max(0, Number(offset) || 0);

  const total = getDb()
    .prepare(
      `SELECT COUNT(*) AS cnt
       FROM (
         SELECT
           ip.id,
           ip.status,
           CASE
             WHEN (
               SELECT payout.status
               FROM investment_payouts payout
               WHERE payout.position_id = ip.id
               ORDER BY payout.created_at DESC
               LIMIT 1
             ) = 'failed' THEN 'payout_failed'
             ELSE ip.status
           END AS admin_status
         FROM investment_positions ip
       ) filtered
       WHERE admin_status IN (${placeholders})`,
    )
    .get(...allowedStatuses).cnt;

  const rows = getDb()
    .prepare(
      `SELECT *
       FROM (
         SELECT
           ip.*,
           u.login_id,
           u.name,
           u.phone,
           (
             SELECT payout.id
             FROM investment_payouts payout
             WHERE payout.position_id = ip.id
             ORDER BY payout.created_at DESC
             LIMIT 1
           ) AS latest_payout_id,
           (
             SELECT payout.payout_type
             FROM investment_payouts payout
             WHERE payout.position_id = ip.id
             ORDER BY payout.created_at DESC
             LIMIT 1
           ) AS latest_payout_type,
           (
             SELECT payout.principal_raw
             FROM investment_payouts payout
             WHERE payout.position_id = ip.id
             ORDER BY payout.created_at DESC
             LIMIT 1
           ) AS latest_payout_principal_raw,
           (
             SELECT payout.reward_raw
             FROM investment_payouts payout
             WHERE payout.position_id = ip.id
             ORDER BY payout.created_at DESC
             LIMIT 1
           ) AS latest_payout_reward_raw,
           (
             SELECT payout.total_raw
             FROM investment_payouts payout
             WHERE payout.position_id = ip.id
             ORDER BY payout.created_at DESC
             LIMIT 1
           ) AS latest_payout_total_raw,
           (
             SELECT payout.txhash
             FROM investment_payouts payout
             WHERE payout.position_id = ip.id
             ORDER BY payout.created_at DESC
             LIMIT 1
           ) AS latest_payout_txhash,
           (
             SELECT payout.status
             FROM investment_payouts payout
             WHERE payout.position_id = ip.id
             ORDER BY payout.created_at DESC
             LIMIT 1
           ) AS latest_payout_status,
           (
             SELECT payout.error_message
             FROM investment_payouts payout
             WHERE payout.position_id = ip.id
             ORDER BY payout.created_at DESC
             LIMIT 1
           ) AS latest_payout_error_message,
           (
             SELECT payout.created_at
             FROM investment_payouts payout
             WHERE payout.position_id = ip.id
             ORDER BY payout.created_at DESC
             LIMIT 1
           ) AS latest_payout_created_at,
           (
             SELECT payout.updated_at
             FROM investment_payouts payout
             WHERE payout.position_id = ip.id
             ORDER BY payout.created_at DESC
             LIMIT 1
           ) AS latest_payout_updated_at,
           CASE
             WHEN (
               SELECT payout.status
               FROM investment_payouts payout
               WHERE payout.position_id = ip.id
               ORDER BY payout.created_at DESC
               LIMIT 1
             ) = 'failed' THEN 'payout_failed'
             ELSE ip.status
           END AS admin_status
         FROM investment_positions ip
         JOIN users u ON u.id = ip.user_id
       ) investments
       WHERE admin_status IN (${placeholders})
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
    )
    .all(...allowedStatuses, normalizedLimit, normalizedOffset);

  return {
    investments: rows.map(mapAdminInvestment),
    total,
    limit: normalizedLimit,
    offset: normalizedOffset,
  };
};

export const getAdminUserDetail = ({ userId }) => {
  const normalizedUserId = String(userId ?? "").trim();
  if (!normalizedUserId) {
    throw new Error("userId is required");
  }

  const row = getDb()
    .prepare(
      `SELECT
         u.id AS user_id,
         u.login_id,
         u.phone,
         u.name,
         u.status,
         u.is_merchant,
         u.created_at,
         u.updated_at,
         u.last_login_at,
         w.id AS wallet_id,
         w.wallet_address,
         w.public_key,
         w.mnemonic_available,
         w.wallet_source,
         mp.status AS merchant_status,
         mp.merchant_name,
         (
           SELECT COUNT(*)
           FROM wallet_transactions wt
           WHERE wt.wallet_address = w.wallet_address
         ) AS transaction_count,
         (
           SELECT COUNT(*)
           FROM wallet_recipients wr
           WHERE wr.wallet_address = w.wallet_address
         ) AS recipient_count,
         (
           SELECT COUNT(*)
           FROM payment_orders po
           WHERE po.payer_wallet_address = w.wallet_address
              OR po.merchant_wallet_address = w.wallet_address
         ) AS payment_count,
         (
           SELECT COUNT(*)
           FROM investment_positions ip
           WHERE ip.user_id = u.id
         ) AS investment_count,
         (
           SELECT COUNT(*)
           FROM investment_positions ip
           WHERE ip.user_id = u.id
             AND ip.status = 'active'
         ) AS active_investment_count
       FROM users u
       JOIN user_wallets w ON w.user_id = u.id
       LEFT JOIN merchant_profiles mp ON mp.user_id = u.id
       WHERE u.id = ?`,
    )
    .get(normalizedUserId);

  if (!row) {
    throw new Error("user not found");
  }

  const user = mapAdminUser(row);
  const merchantProfile = getMerchantProfile(row.wallet_address);
  const latestTransactions = getDb()
    .prepare(
      `SELECT *
       FROM wallet_transactions
       WHERE wallet_address = ?
       ORDER BY COALESCE(chain_timestamp, created_at) DESC
       LIMIT 5`,
    )
    .all(row.wallet_address)
    .map(mapTransaction);
  const investments = getDb()
    .prepare(
      `SELECT *
       FROM investment_positions
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT 10`,
    )
    .all(normalizedUserId)
    .map(mapInvestmentPosition);

  return {
    user,
    merchantProfile,
    latestTransactions,
    investments,
  };
};

export const adminResetUserPassword = ({
  userId,
  nextPassword,
  adminActor = "admin",
}) => {
  const userRow = getUserByIdRow(userId);
  if (!userRow) {
    throw new Error("user not found");
  }
  const normalizedPassword = String(nextPassword ?? "");
  const passwordHash = hashPassword(normalizedPassword);
  const now = new Date().toISOString();

  getDb()
    .prepare("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
    .run(passwordHash, now, userRow.id);

  revokeSessionsByUserId(userRow.id);

  const walletRow = getUserWalletByUserIdRow(userRow.id);
  appendAdminAuditLog({
    adminActor,
    action: "user_password_reset",
    targetUserId: userRow.id,
    targetWalletAddress: walletRow?.wallet_address ?? null,
    detail: {
      loginId: userRow.login_id,
    },
  });

  return getAdminUserDetail({ userId: userRow.id });
};

export const adminUpdateUserStatus = ({
  userId,
  status,
  adminActor = "admin",
}) => {
  const userRow = getUserByIdRow(userId);
  if (!userRow) {
    throw new Error("user not found");
  }
  if (!["active", "disabled", "deleted"].includes(status)) {
    throw new Error("status must be active, disabled, or deleted");
  }
  if (userRow.status === "deleted" && status === "active") {
    throw new Error("탈퇴 처리된 계정은 다시 활성화할 수 없습니다.");
  }

  const walletRow = getUserWalletByUserIdRow(userRow.id);
  if (!walletRow) {
    throw new Error("wallet not found");
  }

  const activeInvestmentCount = getDb()
    .prepare(
      `SELECT COUNT(*) AS count
       FROM investment_positions
       WHERE user_id = ?
         AND status = 'active'`,
    )
    .get(userRow.id).count;

  if (status === "deleted" && Number(activeInvestmentCount) > 0) {
    throw new Error("진행 중인 투자 건이 있어 회원탈퇴 처리할 수 없습니다.");
  }

  const now = new Date().toISOString();
  getDb().exec("BEGIN IMMEDIATE");
  try {
    getDb()
      .prepare("UPDATE users SET status = ?, is_merchant = ?, updated_at = ? WHERE id = ?")
      .run(status, status === "active" ? userRow.is_merchant : 0, now, userRow.id);

    if (status !== "active") {
      revokeSessionsByUserId(userRow.id);
      getDb()
        .prepare(
          `UPDATE wallet_registry
           SET is_merchant = 0,
               is_active = 0,
               updated_at = ?
           WHERE wallet_address = ?`,
        )
        .run(now, walletRow.wallet_address);
      getDb()
        .prepare(
          `UPDATE merchant_profiles
           SET status = 'denied',
               review_note = ?,
               updated_at = ?,
               reviewed_at = ?,
               reviewed_by = ?
           WHERE user_id = ?`,
        )
        .run(
          status === "deleted"
            ? "회원탈퇴 처리로 비활성화됨"
            : "관리자 비활성화 처리",
          now,
          now,
          adminActor,
          userRow.id,
        );
    }

    if (status === "active") {
      const merchantProfile = getMerchantProfile(walletRow.wallet_address);
      getDb()
        .prepare(
          `UPDATE wallet_registry
           SET is_active = 1,
               is_merchant = ?,
               updated_at = ?
           WHERE wallet_address = ?`,
        )
        .run(merchantProfile?.status === "approved" ? 1 : 0, now, walletRow.wallet_address);
    }

    appendAdminAuditLog({
      adminActor,
      action:
        status === "deleted"
          ? "user_deleted"
          : status === "disabled"
            ? "user_disabled"
            : "user_enabled",
      targetUserId: userRow.id,
      targetWalletAddress: walletRow.wallet_address,
      detail: {
        loginId: userRow.login_id,
        previousStatus: userRow.status,
        nextStatus: status,
      },
    });

    getDb().exec("COMMIT");
  } catch (error) {
    getDb().exec("ROLLBACK");
    throw error;
  }

  return getAdminUserDetail({ userId: userRow.id });
};

export const listWalletRecipients = (walletAddress) => {
  const normalizedWallet = assertAddress(walletAddress, "walletAddress");
  const rows = getDb()
    .prepare(
      `SELECT *
       FROM wallet_recipients
       WHERE wallet_address = ?
         AND is_hidden = 0
       ORDER BY is_favorite DESC, send_count DESC, last_sent_at DESC
       LIMIT 20`,
    )
    .all(normalizedWallet);

  return rows.map(mapRecipient);
};

export const getWalletRegistry = (walletAddress) => {
  const normalizedWallet = assertAddress(walletAddress, "walletAddress");
  const row = getDb()
    .prepare("SELECT * FROM wallet_registry WHERE wallet_address = ?")
    .get(normalizedWallet);

  return row ? mapRegistry(row) : null;
};

export const upsertWalletRegistry = ({
  walletAddress,
  isMerchant = false,
  merchantName = null,
  referrerWalletAddress = null,
  isActive = true,
}) => {
  const normalizedWallet = assertAddress(walletAddress, "walletAddress");
  const normalizedReferrer = assertOptionalAddress(
    referrerWalletAddress,
    "referrerWalletAddress",
  );

  if (normalizedReferrer && normalizedReferrer === normalizedWallet) {
    throw new Error("wallet cannot refer itself");
  }

  const now = new Date().toISOString();
  const existing = getWalletRegistry(normalizedWallet);

  getDb()
    .prepare(
      `INSERT INTO wallet_registry (
         wallet_address,
         is_merchant,
         merchant_name,
         referrer_wallet_address,
         is_active,
         created_at,
         updated_at
       )
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(wallet_address)
       DO UPDATE SET
         is_merchant = excluded.is_merchant,
         merchant_name = excluded.merchant_name,
         referrer_wallet_address = excluded.referrer_wallet_address,
         is_active = excluded.is_active,
         updated_at = excluded.updated_at`,
    )
    .run(
      normalizedWallet,
      isMerchant ? 1 : 0,
      merchantName && String(merchantName).trim() ? String(merchantName).trim() : null,
      normalizedReferrer,
      isActive ? 1 : 0,
      existing?.createdAt ?? now,
      now,
    );

  return getWalletRegistry(normalizedWallet);
};

export const getPaymentQuote = ({
  payerWalletAddress,
  toWalletAddress,
  amountRaw,
}) => {
  const payer = assertAddress(payerWalletAddress, "payerWalletAddress");
  const recipient = assertAddress(toWalletAddress, "toWalletAddress");
  const totalAmountRaw = assertRawAmount(amountRaw, "amountRaw");
  const total = BigInt(totalAmountRaw);
  const payerRegistry = getWalletRegistry(payer);
  const recipientMerchantProfile = getMerchantProfile(recipient);
  const isMerchantPayment = recipientMerchantProfile?.status === "approved";

  if (!isMerchantPayment) {
    return {
      isMerchantPayment: false,
      merchantWalletAddress: null,
      merchantName: null,
      totalAmountRaw,
      totalAmountDisplay: formatRawTokenAmount(totalAmountRaw, OOWA_TOKEN.decimals),
      referrerLevel1WalletAddress: null,
      referrerLevel2WalletAddress: null,
      transfers: [
        {
          role: "recipient",
          toWalletAddress: recipient,
          amountRaw: totalAmountRaw,
          amountDisplay: formatRawTokenAmount(totalAmountRaw, OOWA_TOKEN.decimals),
        },
      ],
    };
  }

  const level1 = payerRegistry?.referrerWalletAddress
    ? getWalletRegistry(payerRegistry.referrerWalletAddress)
    : null;
  const level1WalletAddress = level1?.isActive ? level1.walletAddress : null;
  const level2 = level1WalletAddress
    ? getWalletRegistry(level1WalletAddress)?.referrerWalletAddress
      ? getWalletRegistry(getWalletRegistry(level1WalletAddress).referrerWalletAddress)
      : null
    : null;
  const level2WalletAddress = level2?.isActive ? level2.walletAddress : null;

  const level1AmountRaw = level1WalletAddress ? (total * 3n) / 100n : 0n;
  const level2AmountRaw = level2WalletAddress ? (total * 7n) / 100n : 0n;
  const merchantAmountRaw = total - level1AmountRaw - level2AmountRaw;

  const transfers = [
    {
      role: "merchant",
      toWalletAddress: recipient,
      amountRaw: merchantAmountRaw.toString(),
      amountDisplay: formatRawTokenAmount(
        merchantAmountRaw.toString(),
        OOWA_TOKEN.decimals,
      ),
    },
  ];

  if (level1WalletAddress && level1AmountRaw > 0n) {
    transfers.push({
      role: "referrer_level1",
      toWalletAddress: level1WalletAddress,
      amountRaw: level1AmountRaw.toString(),
      amountDisplay: formatRawTokenAmount(
        level1AmountRaw.toString(),
        OOWA_TOKEN.decimals,
      ),
    });
  }

  if (level2WalletAddress && level2AmountRaw > 0n) {
    transfers.push({
      role: "referrer_level2",
      toWalletAddress: level2WalletAddress,
      amountRaw: level2AmountRaw.toString(),
      amountDisplay: formatRawTokenAmount(
        level2AmountRaw.toString(),
        OOWA_TOKEN.decimals,
      ),
    });
  }

  return {
    isMerchantPayment: true,
    merchantWalletAddress: recipient,
    merchantName: recipientMerchantProfile?.merchantName ?? null,
    totalAmountRaw,
    totalAmountDisplay: formatRawTokenAmount(totalAmountRaw, OOWA_TOKEN.decimals),
    referrerLevel1WalletAddress: level1WalletAddress,
    referrerLevel2WalletAddress: level2WalletAddress,
    transfers,
  };
};

export const createPaymentOrder = ({
  payerWalletAddress,
  toWalletAddress,
  amountRaw,
}) => {
  const quote = getPaymentQuote({
    payerWalletAddress,
    toWalletAddress,
    amountRaw,
  });
  const paymentOrderId = randomUUID();
  const now = new Date().toISOString();
  const merchantTransfer =
    quote.transfers.find((transfer) => transfer.role === "merchant") ??
    quote.transfers[0];
  const level1Transfer = quote.transfers.find(
    (transfer) => transfer.role === "referrer_level1",
  );
  const level2Transfer = quote.transfers.find(
    (transfer) => transfer.role === "referrer_level2",
  );

  getDb()
    .prepare(
      `INSERT INTO payment_orders (
         id,
         payer_wallet_address,
         merchant_wallet_address,
         total_amount_raw,
         total_amount_display,
         merchant_amount_raw,
         referrer_level1_amount_raw,
         referrer_level2_amount_raw,
         referrer_level1_wallet_address,
         referrer_level2_wallet_address,
         status,
         failure_reason,
         created_at,
         updated_at,
         completed_at
       )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      paymentOrderId,
      assertAddress(payerWalletAddress, "payerWalletAddress"),
      assertAddress(toWalletAddress, "toWalletAddress"),
      quote.totalAmountRaw,
      quote.totalAmountDisplay,
      merchantTransfer?.amountRaw ?? "0",
      level1Transfer?.amountRaw ?? "0",
      level2Transfer?.amountRaw ?? "0",
      quote.referrerLevel1WalletAddress,
      quote.referrerLevel2WalletAddress,
      "created",
      null,
      now,
      now,
      null,
    );

  const insertTransfer = getDb().prepare(
    `INSERT INTO payment_transfers (
       id,
       payment_order_id,
       transfer_role,
       from_wallet_address,
       to_wallet_address,
       amount_raw,
       amount_display,
       txhash,
       status,
       error_message,
       created_at,
       updated_at,
       confirmed_at
     )
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  for (const transfer of quote.transfers) {
    insertTransfer.run(
      randomUUID(),
      paymentOrderId,
      transfer.role,
      assertAddress(payerWalletAddress, "payerWalletAddress"),
      transfer.toWalletAddress,
      transfer.amountRaw,
      transfer.amountDisplay,
      null,
      "pending",
      null,
      now,
      now,
      null,
    );
  }

  return {
    paymentOrder: getPaymentOrder(paymentOrderId),
    transfers: listPaymentTransfers(paymentOrderId),
    quote,
  };
};

export const recordPaymentTransferBroadcasted = async ({
  paymentOrderId,
  transferRole,
  walletAddress,
  signedPayload,
  broadcastResponse,
  trackRecipient = true,
}) => {
  const order = getPaymentOrder(paymentOrderId);
  if (!order) {
    throw new Error("payment order not found");
  }

  const transfer = getDb()
    .prepare(
      `SELECT * FROM payment_transfers
       WHERE payment_order_id = ? AND transfer_role = ?`,
    )
    .get(paymentOrderId, transferRole);

  if (!transfer) {
    throw new Error("payment transfer not found");
  }

  const transferEntryKinds = {
    recipient: {
      sender: "transfer_out",
      receiver: "transfer_in",
    },
    merchant: {
      sender: "payment_out",
      receiver: "payment_merchant",
    },
    referrer_level1: {
      sender: "payment_out",
      receiver: "payment_referral_level1",
    },
    referrer_level2: {
      sender: "payment_out",
      receiver: "payment_referral_level2",
    },
  };
  const transferEntryKind = transferEntryKinds[transferRole] ?? transferEntryKinds.recipient;

  const savedTransaction = await saveWalletTransaction({
    walletAddress,
    direction: "outgoing",
    entryKind: transferEntryKind.sender,
    mirrorEntryKind: transferEntryKind.receiver,
    signedPayload,
    broadcastResponse,
    trackRecipient,
  });
  const now = new Date().toISOString();

  getDb()
    .prepare(
      `UPDATE payment_transfers
       SET txhash = ?, status = ?, error_message = ?, updated_at = ?, confirmed_at = ?
       WHERE payment_order_id = ? AND transfer_role = ?`,
    )
    .run(
      savedTransaction.txhash,
      "broadcasted",
      null,
      now,
      savedTransaction.confirmedAt,
      paymentOrderId,
      transferRole,
    );

  const paymentOrder = recomputePaymentOrderStatus(paymentOrderId);

  return {
    paymentOrder,
    paymentTransfer: mapPaymentTransfer({
      ...transfer,
      txhash: savedTransaction.txhash,
      status: "broadcasted",
      error_message: null,
      updated_at: now,
      confirmed_at: savedTransaction.confirmedAt,
    }),
    transaction: savedTransaction,
    recipients: listWalletRecipients(walletAddress),
  };
};

export const recordPaymentTransferFailed = ({
  paymentOrderId,
  transferRole,
  errorMessage,
}) => {
  const order = getPaymentOrder(paymentOrderId);
  if (!order) {
    throw new Error("payment order not found");
  }

  const now = new Date().toISOString();
  getDb()
    .prepare(
      `UPDATE payment_transfers
       SET status = ?, error_message = ?, updated_at = ?
       WHERE payment_order_id = ? AND transfer_role = ?`,
    )
    .run(
      "failed",
      errorMessage ? String(errorMessage).slice(0, 500) : "transfer failed",
      now,
      paymentOrderId,
      transferRole,
    );

  const paymentOrder = recomputePaymentOrderStatus(paymentOrderId);

  return {
    paymentOrder,
    transfers: listPaymentTransfers(paymentOrderId),
  };
};

export const listAdminPaymentOrders = ({
  statuses = ["partial_failed", "failed"],
  limit = 20,
  offset = 0,
} = {}) => {
  const allowedStatuses = Array.isArray(statuses) && statuses.length > 0 ? statuses : [
    "partial_failed",
    "failed",
  ];
  const placeholders = allowedStatuses.map(() => "?").join(", ");
  const normalizedLimit = Math.min(Math.max(1, Number(limit) || 20), 100);
  const normalizedOffset = Math.max(0, Number(offset) || 0);

  const total = getDb()
    .prepare(`SELECT COUNT(*) AS cnt FROM payment_orders WHERE status IN (${placeholders})`)
    .get(...allowedStatuses).cnt;

  const rows = getDb()
    .prepare(
      `SELECT *
       FROM payment_orders
       WHERE status IN (${placeholders})
       ORDER BY updated_at DESC
       LIMIT ? OFFSET ?`,
    )
    .all(...allowedStatuses, normalizedLimit, normalizedOffset);

  return {
    payments: rows.map((row) => ({
      ...mapPaymentOrder(row),
      transfers: listPaymentTransfers(row.id),
    })),
    total,
    limit: normalizedLimit,
    offset: normalizedOffset,
  };
};

export const saveWalletTransaction = async ({
  walletAddress,
  direction,
  entryKind,
  mirrorEntryKind = null,
  signedPayload,
  broadcastResponse,
  trackRecipient = true,
  mirrorInternalRecipient = true,
}) => {
  assertNoSecretFields({ signedPayload, broadcastResponse });

  if (direction && !["outgoing", "incoming", "self"].includes(direction)) {
    throw new Error("direction is invalid");
  }

  const normalizedWallet = assertAddress(walletAddress, "walletAddress");
  const transaction = signedPayload?.transaction;
  if (!transaction || typeof transaction !== "object") {
    throw new Error("signedPayload.transaction is required");
  }

  const txhash = getBroadcastTxhash(broadcastResponse);
  const fromAddress = assertAddress(transaction.from, "from");
  const toAddress = assertAddress(transaction.to, "to");
  const resolvedDirection = inferTransactionDirection({
    walletAddress: normalizedWallet,
    fromAddress,
    toAddress,
  });
  const resolvedEntryKind = assertEntryKind(
    entryKind ??
      (resolvedDirection === "self"
        ? "self_transfer"
        : resolvedDirection === "outgoing"
          ? "transfer_out"
          : "transfer_in"),
  );
  const tokenAddress = assertTokenAddress(transaction.token_address);
  const now = new Date().toISOString();
  const existing = getExistingTransaction(normalizedWallet, txhash);
  const chainDetail = await fetchChainDetail(txhash);
  const chainTransaction = chainDetail?.data?.transaction;
  const amountRaw =
    chainDetail?.txamount ?? chainTransaction?.amount ?? String(transaction.amount ?? "");
  const chainTimestamp = String(
    chainDetail?.txtimestamp ?? chainTransaction?.timestamp ?? transaction.timestamp,
  );
  const blockHeight = chainDetail?.block_height ?? null;
  const status = blockHeight ? "confirmed" : "broadcasted";
  const confirmedAt = blockHeight ? now : null;

  if (chainDetail?.txhash && assertTxhash(chainDetail.txhash) !== txhash) {
    throw new Error("chain txhash does not match broadcast txhash");
  }
  if (chainDetail?.txfrom && assertAddress(chainDetail.txfrom, "txfrom") !== fromAddress) {
    throw new Error("chain txfrom does not match signed payload");
  }
  if (chainDetail?.txto && assertAddress(chainDetail.txto, "txto") !== toAddress) {
    throw new Error("chain txto does not match signed payload");
  }
  if (chainTransaction?.token_address) {
    const chainToken = assertTokenAddress(chainTransaction.token_address);
    if (chainToken !== tokenAddress) {
      throw new Error("chain token address does not match signed payload");
    }
  }

  getDb()
    .prepare(
      `INSERT INTO wallet_transactions (
         id,
         wallet_address,
         txhash,
         direction,
         entry_kind,
         network,
         tx_type,
         from_address,
         to_address,
         token_address,
         token_symbol,
         decimals,
         amount_raw,
         amount_display,
         chain_timestamp,
         block_height,
         status,
         public_key,
         broadcast_response_json,
         chain_response_json,
         created_at,
         updated_at,
         confirmed_at
       )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(wallet_address, txhash)
       DO UPDATE SET
         direction = excluded.direction,
         entry_kind = excluded.entry_kind,
         tx_type = excluded.tx_type,
         from_address = excluded.from_address,
         to_address = excluded.to_address,
         amount_raw = excluded.amount_raw,
         amount_display = excluded.amount_display,
         chain_timestamp = excluded.chain_timestamp,
         block_height = excluded.block_height,
         status = excluded.status,
         public_key = excluded.public_key,
         broadcast_response_json = excluded.broadcast_response_json,
         chain_response_json = excluded.chain_response_json,
         updated_at = excluded.updated_at,
         confirmed_at = COALESCE(wallet_transactions.confirmed_at, excluded.confirmed_at)`,
    )
    .run(
      existing?.id ?? randomUUID(),
      normalizedWallet,
      txhash,
      resolvedDirection,
      resolvedEntryKind,
      NETWORK,
      transaction.type,
      fromAddress,
      toAddress,
      tokenAddress,
      OOWA_TOKEN.symbol,
      OOWA_TOKEN.decimals,
      amountRaw,
      formatRawTokenAmount(amountRaw, OOWA_TOKEN.decimals),
      chainTimestamp,
      blockHeight,
      status,
      signedPayload.public_key,
      stringifyJson(broadcastResponse),
      chainDetail ? stringifyJson(chainDetail) : null,
      existing?.createdAt ?? now,
      now,
      confirmedAt,
    );

  if (
    trackRecipient &&
    !existing &&
    resolvedDirection === "outgoing" &&
    normalizedWallet !== toAddress
  ) {
    getDb()
      .prepare(
        `INSERT INTO wallet_recipients (
           id,
           wallet_address,
           recipient_address,
           network,
           send_count,
           last_sent_at,
           last_txhash,
           created_at,
           updated_at
         )
         VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)
         ON CONFLICT(wallet_address, recipient_address, network)
         DO UPDATE SET
           send_count = wallet_recipients.send_count + 1,
           last_sent_at = excluded.last_sent_at,
           last_txhash = excluded.last_txhash,
           updated_at = excluded.updated_at`,
      )
      .run(randomUUID(), normalizedWallet, toAddress, NETWORK, now, txhash, now, now);
  }

  if (
    mirrorInternalRecipient &&
    resolvedDirection === "outgoing" &&
    normalizedWallet !== toAddress
  ) {
    const internalRecipientWallet = getUserWalletByAddressRow(toAddress);
    if (internalRecipientWallet) {
      await saveWalletTransaction({
        walletAddress: toAddress,
        direction: "incoming",
        entryKind: mirrorEntryKind ?? "transfer_in",
        signedPayload,
        broadcastResponse,
        trackRecipient: false,
        mirrorInternalRecipient: false,
      });
    }
  }

  const saved = getExistingTransaction(normalizedWallet, txhash);
  if (!saved) {
    throw new Error("failed to save transaction");
  }

  return saved;
};
