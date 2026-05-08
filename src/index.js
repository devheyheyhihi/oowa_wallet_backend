import http from "node:http";
import {
  adminResetUserPassword,
  adminUpdateUserStatus,
  createPaymentOrder,
  executeAuthenticatedPayment,
  getAdminSession,
  getAdminInvestmentSummary,
  getAdminUserDetail,
  getAuthSession,
  getInvestmentProductDetails,
  getMerchantProfile,
  getMerchantProfileChangeRequest,
  getPaymentQuote,
  getWalletRegistry,
  listAuthenticatedInvestments,
  listApprovedMerchantProfiles,
  listAdminMerchantChangeRequests,
  loginUser,
  listAdminMerchantProfiles,
  listAdminInvestments,
  listWalletActivity,
  listWalletRecipients,
  listAdminUsers,
  listAdminPaymentOrders,
  loginAdmin,
  recordPaymentTransferBroadcasted,
  recordPaymentTransferFailed,
  reviewMerchantProfile,
  reviewMerchantProfileChangeRequest,
  revealWalletMnemonic,
  registerUser,
  revokeAdminSession,
  revokeAuthSession,
  saveWalletTransaction,
  startAuthenticatedInvestment,
  stopAuthenticatedInvestment,
  upsertMerchantProfile,
  upsertWalletRegistry,
} from "./historyDb.js";

const PORT = Number(process.env.PORT ?? 4000);
const DEFAULT_ALLOWED_ORIGINS = [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:3002",
  "http://localhost:3003",
];
const ALLOWED_ORIGINS = (process.env.OOWA_ALLOWED_ORIGINS ?? "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const allowedOrigins = ALLOWED_ORIGINS.length
  ? ALLOWED_ORIGINS
  : DEFAULT_ALLOWED_ORIGINS;

const sendJson = (response, status, data, origin) => {
  const body = JSON.stringify(data);
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  };

  if (origin && allowedOrigins.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers.Vary = "Origin";
  }

  response.writeHead(status, headers);
  response.end(body);
};

const sendCorsPreflight = (request, response) => {
  const origin = request.headers.origin;
  const headers = {
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Accept,Authorization",
    "Access-Control-Max-Age": "86400",
  };

  if (origin && allowedOrigins.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers.Vary = "Origin";
  }

  response.writeHead(204, headers);
  response.end();
};

const readBody = async (request) => {
  const chunks = [];
  let size = 0;

  for await (const chunk of request) {
    size += chunk.length;
    if (size > 1_000_000) {
      throw new Error("request body is too large");
    }
    chunks.push(chunk);
  }

  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
};

const requireAdmin = (request) => {
  const authorization = request.headers.authorization;
  if (!authorization || !authorization.startsWith("Bearer ")) {
    const error = new Error("관리자 로그인이 필요합니다.");
    error.statusCode = 403;
    throw error;
  }

  const token = authorization.slice("Bearer ".length).trim();
  const session = getAdminSession(token);
  if (!session) {
    const error = new Error("관리자 세션이 만료되었습니다.");
    error.statusCode = 403;
    throw error;
  }

  return session;
};

const readBearerToken = (request) => {
  const authorization = request.headers.authorization;
  if (!authorization || !authorization.startsWith("Bearer ")) {
    const error = new Error("로그인이 필요합니다.");
    error.statusCode = 401;
    throw error;
  }

  return authorization.slice("Bearer ".length).trim();
};

const routeRequest = async (request, response) => {
  const origin = request.headers.origin;
  const url = new URL(request.url ?? "/", `http://${request.headers.host}`);
  const method = request.method ?? "GET";

  console.log("[request]", {
    method,
    path: url.pathname,
    origin: origin ?? null,
  });

  if (method === "OPTIONS") {
    sendCorsPreflight(request, response);
    return;
  }

  try {
    if (method === "GET" && url.pathname === "/health") {
      sendJson(response, 200, { ok: true }, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/auth/register") {
      const body = await readBody(request);
      const result = registerUser(body);
      sendJson(response, 200, result, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/auth/login") {
      const body = await readBody(request);
      const result = loginUser(body);
      sendJson(response, 200, result, origin);
      return;
    }

    if (method === "GET" && url.pathname === "/api/auth/session") {
      const token = readBearerToken(request);
      const session = getAuthSession(token);
      if (!session) {
        sendJson(response, 401, { error: "세션이 만료되었습니다." }, origin);
        return;
      }
      sendJson(response, 200, session, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/auth/logout") {
      const token = readBearerToken(request);
      revokeAuthSession(token);
      sendJson(response, 200, { ok: true }, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/auth/reveal-mnemonic") {
      const token = readBearerToken(request);
      const body = await readBody(request);
      const result = revealWalletMnemonic({
        sessionToken: token,
        password: body.password,
      });
      sendJson(response, 200, result, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/admin/auth/login") {
      const body = await readBody(request);
      console.log("[admin-auth-login]", {
        bodyHasPassword:
          typeof body.password === "string" && body.password.length > 0,
        adminPasswordConfigured: Boolean(process.env.OOWA_ADMIN_PASSWORD),
      });
      const result = loginAdmin({
        password: body.password,
      });
      sendJson(response, 200, result, origin);
      return;
    }

    if (method === "GET" && url.pathname === "/api/admin/auth/session") {
      const adminSession = requireAdmin(request);
      sendJson(response, 200, adminSession, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/admin/auth/logout") {
      const authorization = request.headers.authorization;
      if (authorization && authorization.startsWith("Bearer ")) {
        revokeAdminSession(authorization.slice("Bearer ".length).trim());
      }
      sendJson(response, 200, { ok: true }, origin);
      return;
    }

    if (method === "GET" && url.pathname === "/api/investment/product") {
      sendJson(response, 200, getInvestmentProductDetails(), origin);
      return;
    }

    if (method === "GET" && url.pathname === "/api/investments/me") {
      const token = readBearerToken(request);
      const page = Math.max(0, parseInt(url.searchParams.get("page") ?? "0", 10) || 0);
      const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") ?? "10", 10) || 10));
      const result = listAuthenticatedInvestments({ sessionToken: token, page, limit });
      sendJson(response, 200, result, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/investments/start") {
      const token = readBearerToken(request);
      const body = await readBody(request);
      const result = await startAuthenticatedInvestment({
        sessionToken: token,
        amountRaw: body.amountRaw,
      });
      sendJson(response, 200, result, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/merchant-profile") {
      const token = readBearerToken(request);
      const body = await readBody(request);
      const result = upsertMerchantProfile({
        sessionToken: token,
        ...body,
      });
      sendJson(response, 200, result, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/transactions") {
      const body = await readBody(request);
      const transaction = await saveWalletTransaction(body);
      const recipients = listWalletRecipients(body.walletAddress);
      sendJson(response, 200, { transaction, recipients }, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/payments/quote") {
      const body = await readBody(request);
      const quote = getPaymentQuote(body);
      sendJson(response, 200, quote, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/payments") {
      const body = await readBody(request);
      const payment = createPaymentOrder(body);
      sendJson(response, 200, payment, origin);
      return;
    }

    const investmentStopMatch = url.pathname.match(
      /^\/api\/investments\/([0-9a-fA-F-]+)\/stop$/,
    );
    if (method === "POST" && investmentStopMatch) {
      const token = readBearerToken(request);
      const result = await stopAuthenticatedInvestment({
        sessionToken: token,
        positionId: investmentStopMatch[1],
      });
      sendJson(response, 200, result, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/payments/execute") {
      const token = readBearerToken(request);
      const body = await readBody(request);
      const payment = await executeAuthenticatedPayment({
        sessionToken: token,
        toWalletAddress: body.toWalletAddress,
        amountRaw: body.amountRaw,
      });
      sendJson(response, 200, payment, origin);
      return;
    }

    if (method === "POST" && url.pathname === "/api/registry") {
      const body = await readBody(request);
      const registry = upsertWalletRegistry(body);
      sendJson(response, 200, { registry }, origin);
      return;
    }

    const paymentBroadcastMatch = url.pathname.match(
      /^\/api\/payments\/([0-9a-fA-F-]+)\/transfers\/([a-z_]+)\/broadcasted$/,
    );
    if (method === "POST" && paymentBroadcastMatch) {
      const body = await readBody(request);
      const result = await recordPaymentTransferBroadcasted({
        paymentOrderId: paymentBroadcastMatch[1],
        transferRole: paymentBroadcastMatch[2],
        ...body,
      });
      sendJson(response, 200, result, origin);
      return;
    }

    const paymentFailedMatch = url.pathname.match(
      /^\/api\/payments\/([0-9a-fA-F-]+)\/transfers\/([a-z_]+)\/failed$/,
    );
    if (method === "POST" && paymentFailedMatch) {
      const body = await readBody(request);
      const result = recordPaymentTransferFailed({
        paymentOrderId: paymentFailedMatch[1],
        transferRole: paymentFailedMatch[2],
        errorMessage: body.errorMessage,
      });
      sendJson(response, 200, result, origin);
      return;
    }

    const activityMatch = url.pathname.match(
      /^\/api\/wallets\/([0-9a-fA-F]{44})\/activity$/,
    );
    if (method === "GET" && activityMatch) {
      const page = Math.max(0, parseInt(url.searchParams.get("page") ?? "0", 10) || 0);
      const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") ?? "20", 10) || 20));
      const directionParam = url.searchParams.get("direction") ?? null;
      const direction = ["outgoing", "incoming"].includes(directionParam ?? "") ? directionParam : null;
      const kindParam = url.searchParams.get("kind") ?? null;
      const kindFilter = ["transfer", "payment", "investment", "reward"].includes(kindParam ?? "")
        ? kindParam
        : null;
      const result = listWalletActivity(activityMatch[1], { page, limit, direction, kindFilter });
      sendJson(
        response,
        200,
        { activity: result.items, total: result.total, page: result.page, limit: result.limit },
        origin,
      );
      return;
    }

    const recipientsMatch = url.pathname.match(
      /^\/api\/wallets\/([0-9a-fA-F]{44})\/recipients$/,
    );
    if (method === "GET" && recipientsMatch) {
      sendJson(
        response,
        200,
        { recipients: listWalletRecipients(recipientsMatch[1]) },
        origin,
      );
      return;
    }

    const registryMatch = url.pathname.match(/^\/api\/registry\/([0-9a-fA-F]{44})$/);
    if (method === "GET" && registryMatch) {
      const registry = getWalletRegistry(registryMatch[1]);
      sendJson(response, 200, { registry }, origin);
      return;
    }

    const merchantProfileMatch = url.pathname.match(
      /^\/api\/merchant-profile\/([0-9a-fA-F]{44})$/,
    );
    if (method === "GET" && merchantProfileMatch) {
      const profile = getMerchantProfile(merchantProfileMatch[1]);
      sendJson(response, 200, { profile }, origin);
      return;
    }

    if (method === "GET" && url.pathname === "/api/merchant-profiles/approved") {
      const profiles = listApprovedMerchantProfiles();
      sendJson(response, 200, { profiles }, origin);
      return;
    }

    if (method === "GET" && url.pathname === "/api/admin/payments") {
      requireAdmin(request);
      const statuses = url.searchParams.get("statuses");
      const paymentType = url.searchParams.get("paymentType") ?? "all";
      const search = url.searchParams.get("search");
      const page = Math.max(0, parseInt(url.searchParams.get("page") ?? "0", 10) || 0);
      const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") ?? "20", 10) || 20));
      const result = listAdminPaymentOrders({
        statuses: statuses
          ? statuses
              .split(",")
              .map((status) => status.trim())
              .filter(Boolean)
          : undefined,
        paymentType,
        search,
        limit,
        offset: page * limit,
      });
      sendJson(response, 200, { ...result, page }, origin);
      return;
    }

    if (method === "GET" && url.pathname === "/api/admin/merchant-profiles") {
      requireAdmin(request);
      const statuses = url.searchParams.get("statuses");
      const search = url.searchParams.get("search");
      const page = Math.max(0, parseInt(url.searchParams.get("page") ?? "0", 10) || 0);
      const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") ?? "20", 10) || 20));
      const result = listAdminMerchantProfiles({
        statuses: statuses
          ? statuses
              .split(",")
              .map((status) => status.trim())
              .filter(Boolean)
          : undefined,
        search,
        limit,
        offset: page * limit,
      });
      sendJson(response, 200, { ...result, page }, origin);
      return;
    }

    if (method === "GET" && url.pathname === "/api/admin/merchant-change-requests") {
      requireAdmin(request);
      const statuses = url.searchParams.get("statuses");
      const search = url.searchParams.get("search");
      const page = Math.max(0, parseInt(url.searchParams.get("page") ?? "0", 10) || 0);
      const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") ?? "20", 10) || 20));
      const result = listAdminMerchantChangeRequests({
        statuses: statuses
          ? statuses
              .split(",")
              .map((status) => status.trim())
              .filter(Boolean)
          : undefined,
        search,
        limit,
        offset: page * limit,
      });
      sendJson(response, 200, { ...result, page }, origin);
      return;
    }

    if (method === "GET" && url.pathname === "/api/admin/users") {
      requireAdmin(request);
      const statuses = url.searchParams.get("statuses");
      const search = url.searchParams.get("search");
      const page = Math.max(0, parseInt(url.searchParams.get("page") ?? "0", 10) || 0);
      const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") ?? "20", 10) || 20));
      const result = listAdminUsers({
        statuses: statuses
          ? statuses
              .split(",")
              .map((status) => status.trim())
              .filter(Boolean)
          : undefined,
        search,
        limit,
        offset: page * limit,
      });
      sendJson(response, 200, { ...result, page }, origin);
      return;
    }

    if (method === "GET" && url.pathname === "/api/admin/investments/summary") {
      requireAdmin(request);
      const summary = getAdminInvestmentSummary();
      sendJson(response, 200, summary, origin);
      return;
    }

    if (method === "GET" && url.pathname === "/api/admin/investments") {
      requireAdmin(request);
      const statuses = url.searchParams.get("statuses");
      const search = url.searchParams.get("search");
      const page = Math.max(0, parseInt(url.searchParams.get("page") ?? "0", 10) || 0);
      const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") ?? "20", 10) || 20));
      const result = listAdminInvestments({
        statuses: statuses
          ? statuses
              .split(",")
              .map((status) => status.trim())
              .filter(Boolean)
          : undefined,
        search,
        limit,
        offset: page * limit,
      });
      sendJson(response, 200, { ...result, page }, origin);
      return;
    }

    const merchantReviewMatch = url.pathname.match(
      /^\/api\/admin\/merchant-profiles\/([0-9a-fA-F]{44})\/(approve|deny)$/,
    );
    if (method === "POST" && merchantReviewMatch) {
      requireAdmin(request);
      const body = await readBody(request);
      const profile = reviewMerchantProfile({
        walletAddress: merchantReviewMatch[1],
        status: merchantReviewMatch[2] === "approve" ? "approved" : "denied",
        reviewNote: body.reviewNote,
        reviewedBy: "admin",
      });
      sendJson(response, 200, { profile }, origin);
      return;
    }

    const merchantChangeReviewMatch = url.pathname.match(
      /^\/api\/admin\/merchant-change-requests\/([0-9a-fA-F]{44})\/(approve|deny)$/,
    );
    if (method === "POST" && merchantChangeReviewMatch) {
      requireAdmin(request);
      const body = await readBody(request);
      const changeRequest = reviewMerchantProfileChangeRequest({
        walletAddress: merchantChangeReviewMatch[1],
        status: merchantChangeReviewMatch[2] === "approve" ? "approved" : "denied",
        reviewNote: body.reviewNote,
        reviewedBy: "admin",
      });
      sendJson(response, 200, { changeRequest }, origin);
      return;
    }

    const adminUserMatch = url.pathname.match(
      /^\/api\/admin\/users\/([0-9a-fA-F-]+)$/,
    );
    if (method === "GET" && adminUserMatch) {
      requireAdmin(request);
      const detail = getAdminUserDetail({
        userId: adminUserMatch[1],
      });
      sendJson(response, 200, detail, origin);
      return;
    }

    const adminUserPasswordMatch = url.pathname.match(
      /^\/api\/admin\/users\/([0-9a-fA-F-]+)\/reset-password$/,
    );
    if (method === "POST" && adminUserPasswordMatch) {
      requireAdmin(request);
      const body = await readBody(request);
      const detail = adminResetUserPassword({
        userId: adminUserPasswordMatch[1],
        nextPassword: body.nextPassword,
        adminActor: "admin",
      });
      sendJson(response, 200, detail, origin);
      return;
    }

    const adminUserStatusMatch = url.pathname.match(
      /^\/api\/admin\/users\/([0-9a-fA-F-]+)\/(enable|disable|delete)$/,
    );
    if (method === "POST" && adminUserStatusMatch) {
      requireAdmin(request);
      const action = adminUserStatusMatch[2];
      const nextStatus =
        action === "enable"
          ? "active"
          : action === "disable"
            ? "disabled"
            : "deleted";
      const detail = adminUpdateUserStatus({
        userId: adminUserStatusMatch[1],
        status: nextStatus,
        adminActor: "admin",
      });
      sendJson(response, 200, detail, origin);
      return;
    }

    sendJson(response, 404, { error: "Not found" }, origin);
  } catch (err) {
    console.error("[request-error]", {
      method,
      path: url.pathname,
      error: err instanceof Error ? err.message : "Request failed",
    });
    sendJson(
      response,
      err instanceof Error && "statusCode" in err ? err.statusCode : 400,
      { error: err instanceof Error ? err.message : "Request failed" },
      origin,
    );
  }
};

const server = http.createServer((request, response) => {
  void routeRequest(request, response);
});

server.listen(PORT, () => {
  console.log(`OOWA wallet backend listening on http://localhost:${PORT}`);
  console.log("[startup]", {
    port: PORT,
    adminPasswordConfigured: Boolean(process.env.OOWA_ADMIN_PASSWORD),
    appSecretConfigured: Boolean(process.env.OOWA_APP_SECRET),
    investmentPoolMnemonicConfigured: Boolean(
      process.env.OOWA_INVESTMENT_POOL_MNEMONIC,
    ),
    investmentPoolPrivateKeyConfigured: Boolean(
      process.env.OOWA_INVESTMENT_POOL_PRIVATE_KEY,
    ),
  });
});
