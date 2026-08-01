const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("JWT_SECRET nao definido. Encerrando (falha fechada) para evitar tokens forjaveis.");
  process.exit(1);
}
const ADMIN_BOOTSTRAP_PASSWORD = process.env.ADMIN_BOOTSTRAP_PASSWORD || "";

const DEFAULT_ALLOWED_ORIGINS = [
  "https://wolf-pecuaria.onrender.com",
  "http://127.0.0.1:4173",
  "http://localhost:4173",
];
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean)
  .concat(DEFAULT_ALLOWED_ORIGINS);

const isExternal = (process.env.DATABASE_URL || "").includes(".render.com");
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isExternal ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 15000,
  max: 10,
});

pool.on("error", (err) => {
  console.error("Pool error:", err.message);
});

app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error("Origem nao permitida por CORS."));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json({ limit: "50mb" }));

// Limite geral: mitiga abuso/DoS via payload repetido, sem afetar uso normal.
// Exclui /api/health via req.originalUrl (dentro de app.use, req.path perde o
// prefixo do mount point e a comparacao direta falharia contra o Render).
const generalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.originalUrl === "/api/health",
  message: { error: "Muitas requisicoes. Tente novamente em instantes." },
});
app.use("/api", generalApiLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Muitas tentativas. Tente novamente em 15 minutos." },
});

function normalizeRole(role) {
  return role === "admin" ? "admin" : "usuario";
}

// So grava (e so entao invalida sessoes antigas via token_version) quando a
// senha de bootstrap efetivamente mudou - evita derrubar sessoes do admin a
// cada reinicio/deploy do servico quando nada mudou.
async function ensureBootstrapAdmin(client) {
  if (!ADMIN_BOOTSTRAP_PASSWORD) {
    return false;
  }

  const existing = await client.query("SELECT password_hash FROM users WHERE username=$1", ["admin"]);
  if (existing.rowCount) {
    const alreadyInSync = await bcrypt.compare(ADMIN_BOOTSTRAP_PASSWORD, existing.rows[0].password_hash);
    if (alreadyInSync) return false;
  }

  const passwordHash = await bcrypt.hash(ADMIN_BOOTSTRAP_PASSWORD, 10);
  const result = await client.query(
    `INSERT INTO users(username,password_hash,role,token_version)
     VALUES($1,$2,'admin',0)
     ON CONFLICT (username) DO UPDATE
     SET password_hash = EXCLUDED.password_hash,
         role = 'admin',
         token_version = users.token_version + 1
     RETURNING id`,
    ["admin", passwordHash]
  );
  return Boolean(result.rowCount);
}

// Reautoriza a cada requisicao a partir do banco (papel e token_version),
// em vez de confiar apenas no que foi assinado no JWT no momento do login.
// Isso faz com que rebaixar/remover um usuario, ou trocar a senha, derrube
// o acesso dele de fato, sem esperar o token expirar (ate 30 dias).
async function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) {
    return res.status(401).json({ error: "Token nao fornecido." });
  }

  let decoded;
  try {
    decoded = jwt.verify(header.replace("Bearer ", ""), JWT_SECRET, { algorithms: ["HS256"] });
  } catch {
    return res.status(401).json({ error: "Token invalido." });
  }

  try {
    const result = await pool.query("SELECT role,token_version FROM users WHERE id=$1", [decoded.id]);
    if (!result.rowCount) {
      return res.status(401).json({ error: "Sessao invalida." });
    }
    const row = result.rows[0];
    if (Number(row.token_version || 0) !== Number(decoded.tokenVersion || 0)) {
      return res.status(401).json({ error: "Sessao expirada. Faca login novamente." });
    }
    req.user = { id: decoded.id, username: decoded.username, role: normalizeRole(row.role) };
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao validar sessao." });
  }
}

// Mescla aditiva: mantem tudo que ja existe no servidor e so acrescenta
// o que e novo (por id, em arrays; por chave, em objetos). Nunca sobrescreve
// um valor ja salvo no servidor, para nao haver perda de dados em conflitos.
function deepMergeAddOnly(serverValue, incomingValue) {
  if (Array.isArray(serverValue) && Array.isArray(incomingValue)) {
    const allHaveIds = (arr) => arr.length === 0 || arr.every((item) => item && typeof item === "object" && "id" in item);
    if (allHaveIds(serverValue) && allHaveIds(incomingValue)) {
      const byId = new Map(serverValue.map((item) => [String(item.id), item]));
      for (const item of incomingValue) {
        const key = String(item.id);
        if (!byId.has(key)) byId.set(key, item);
      }
      return Array.from(byId.values());
    }
    const seen = new Set(serverValue.map((item) => JSON.stringify(item)));
    const merged = [...serverValue];
    for (const item of incomingValue) {
      const key = JSON.stringify(item);
      if (!seen.has(key)) {
        seen.add(key);
        merged.push(item);
      }
    }
    return merged;
  }

  const isPlainObject = (value) => value && typeof value === "object" && !Array.isArray(value);
  const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);
  if (isPlainObject(serverValue) && isPlainObject(incomingValue)) {
    const merged = { ...serverValue };
    for (const key of Object.keys(incomingValue)) {
      if (UNSAFE_KEYS.has(key)) continue;
      merged[key] = key in serverValue
        ? deepMergeAddOnly(serverValue[key], incomingValue[key])
        : incomingValue[key];
    }
    return merged;
  }

  if (serverValue === null || serverValue === undefined) return incomingValue;
  return serverValue;
}

app.get("/", (req, res) => {
  res.json({ status: "ok", sistema: "Wolf Pecuaria API", versao: "1.0.0" });
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", db: "conectado" });
  } catch (err) {
    res.status(503).json({ status: "degradado", error: err.message });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Login e senha obrigatorios." });
  }

  try {
    const normalizedUsername = String(username).trim();
    const result = await pool.query("SELECT id,username,password_hash,role,created_at,token_version FROM users WHERE username=$1", [normalizedUsername]);
    if (!result.rowCount) {
      return res.status(401).json({ error: "Usuario ou senha incorretos." });
    }

    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: "Usuario ou senha incorretos." });
    }

    const role = normalizeRole(user.role);
    const token = jwt.sign(
      { id: user.id, username: user.username, tokenVersion: Number(user.token_version || 0) },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role,
        createdAt: user.created_at,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao autenticar." });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT id,username,role,created_at FROM users WHERE id=$1", [req.user.id]);
    if (!result.rowCount) {
      return res.status(404).json({ error: "Usuario nao encontrado." });
    }

    const user = result.rows[0];
    res.json({
      id: user.id,
      username: user.username,
      role: normalizeRole(user.role),
      createdAt: user.created_at,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao carregar sessao." });
  }
});

app.put("/api/auth/change-password", authLimiter, authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: "Senha atual e nova senha sao obrigatorias." });
  }
  if (String(newPassword).length < 8) {
    return res.status(400).json({ error: "A nova senha deve ter pelo menos 8 caracteres." });
  }

  try {
    const result = await pool.query("SELECT id,password_hash FROM users WHERE id=$1", [req.user.id]);
    if (!result.rowCount) {
      return res.status(404).json({ error: "Usuario nao encontrado." });
    }

    const user = result.rows[0];
    const isValid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isValid) {
      return res.status(400).json({ error: "Senha atual incorreta." });
    }

    const nextHash = await bcrypt.hash(newPassword, 10);
    const updated = await pool.query(
      "UPDATE users SET password_hash=$1, token_version=token_version+1 WHERE id=$2 RETURNING token_version",
      [nextHash, req.user.id]
    );
    // Sobe o token_version invalida sessoes antigas (ex.: dispositivo perdido).
    // Emitimos um token novo aqui pra sessao atual nao cair sozinha no ato.
    const nextTokenVersion = Number(updated.rows[0].token_version || 0);
    const token = jwt.sign(
      { id: req.user.id, username: req.user.username, tokenVersion: nextTokenVersion },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    res.json({ ok: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao atualizar senha." });
  }
});

app.get("/api/users", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Acesso negado." });
  }

  try {
    const rows = (await pool.query("SELECT id,username,role,created_at FROM users ORDER BY id")).rows;
    res.json(rows.map((user) => ({
      id: user.id,
      username: user.username,
      role: normalizeRole(user.role),
      createdAt: user.created_at,
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao listar." });
  }
});

app.post("/api/users", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Acesso negado." });
  }

  const { username, password, role = "usuario" } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Campos obrigatorios." });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ error: "A senha deve ter pelo menos 8 caracteres." });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const created = await pool.query(
      "INSERT INTO users(username,password_hash,role) VALUES($1,$2,$3) RETURNING id,username,role,created_at",
      [username.trim(), passwordHash, normalizeRole(role)]
    );
    const user = created.rows[0];
    res.status(201).json({
      id: user.id,
      username: user.username,
      role: normalizeRole(user.role),
      createdAt: user.created_at,
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Usuario ja existe." });
    }
    console.error(err);
    res.status(500).json({ error: "Erro ao criar." });
  }
});

app.put("/api/users/:id", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Acesso negado." });
  }

  const { username, password, role = "usuario" } = req.body || {};
  if (!username) {
    return res.status(400).json({ error: "Login obrigatorio." });
  }
  if (password && String(password).length < 8) {
    return res.status(400).json({ error: "A senha deve ter pelo menos 8 caracteres." });
  }

  try {
    const currentUser = await pool.query("SELECT id,role FROM users WHERE id=$1", [req.params.id]);
    if (!currentUser.rowCount) {
      return res.status(404).json({ error: "Usuario nao encontrado." });
    }
    const existingRole = normalizeRole(currentUser.rows[0].role);
    const nextRole = normalizeRole(role);
    if (existingRole === "admin" && nextRole !== "admin") {
      const adminCount = await pool.query("SELECT COUNT(*)::int AS total FROM users WHERE role='admin'");
      if (Number(adminCount.rows[0]?.total || 0) <= 1) {
        return res.status(400).json({ error: "Nao e possivel rebaixar o ultimo administrador." });
      }
    }

    // Papel ou senha mudaram: derruba (via token_version) qualquer sessao
    // antiga desse usuario, em vez de deixa-la valida por ate 30 dias.
    if (password) {
      const passwordHash = await bcrypt.hash(password, 10);
      await pool.query(
        "UPDATE users SET username=$1,password_hash=$2,role=$3,token_version=token_version+1 WHERE id=$4",
        [username.trim(), passwordHash, nextRole, req.params.id]
      );
    } else {
      const roleChanged = nextRole !== existingRole;
      await pool.query(
        `UPDATE users SET username=$1,role=$2${roleChanged ? ",token_version=token_version+1" : ""} WHERE id=$3`,
        [username.trim(), nextRole, req.params.id]
      );
    }
    res.json({ ok: true });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Usuario ja existe." });
    }
    console.error(err);
    res.status(500).json({ error: "Erro ao atualizar." });
  }
});

app.delete("/api/users/:id", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Acesso negado." });
  }
  if (String(req.user.id) === String(req.params.id)) {
    return res.status(400).json({ error: "Nao pode remover proprio usuario." });
  }

  try {
    const currentUser = await pool.query("SELECT id,role FROM users WHERE id=$1", [req.params.id]);
    if (!currentUser.rowCount) {
      return res.status(404).json({ error: "Usuario nao encontrado." });
    }
    if (normalizeRole(currentUser.rows[0].role) === "admin") {
      const adminCount = await pool.query("SELECT COUNT(*)::int AS total FROM users WHERE role='admin'");
      if (Number(adminCount.rows[0]?.total || 0) <= 1) {
        return res.status(400).json({ error: "Nao e possivel remover o ultimo administrador." });
      }
    }
    await pool.query("DELETE FROM users WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao remover." });
  }
});

app.get("/api/data", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT payload,updated_at,updated_by,revision FROM farm_data WHERE id=1");
    if (!result.rowCount) {
      return res.json({ payload: null, revision: 0 });
    }

    const row = result.rows[0];
    res.json({
      payload: row.payload,
      updatedAt: row.updated_at,
      updatedBy: row.updated_by,
      revision: Number(row.revision || 0),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao carregar." });
  }
});

app.get("/api/data/revision", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT revision FROM farm_data WHERE id=1");
    res.json({ revision: result.rowCount ? Number(result.rows[0].revision || 0) : 0 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao carregar revisao." });
  }
});

app.post("/api/data", authMiddleware, async (req, res) => {
  const { payload, baseRevision } = req.body || {};
  if (!payload) {
    return res.status(400).json({ error: "Payload obrigatorio." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const current = await client.query("SELECT payload,revision FROM farm_data WHERE id=1 FOR UPDATE");

    if (!current.rowCount) {
      const inserted = await client.query(
        "INSERT INTO farm_data(id,payload,updated_at,updated_by,revision) VALUES(1,$1,NOW(),$2,0) RETURNING updated_at,revision",
        [payload, req.user.username]
      );
      await client.query("COMMIT");
      const row = inserted.rows[0];
      return res.json({ ok: true, savedAt: row.updated_at, revision: Number(row.revision || 0) });
    }

    const serverRevision = Number(current.rows[0].revision || 0);
    if (!Number.isInteger(baseRevision) || baseRevision !== serverRevision) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "Conflito de edicao. Os dados foram alterados em outra sessao.",
        serverRevision,
        payload: current.rows[0].payload,
      });
    }

    const updated = await client.query(
      "UPDATE farm_data SET payload=$1,updated_at=NOW(),updated_by=$2,revision=revision+1 WHERE id=1 RETURNING updated_at,revision",
      [payload, req.user.username]
    );
    await client.query("COMMIT");
    const row = updated.rows[0];
    res.json({ ok: true, savedAt: row.updated_at, revision: Number(row.revision || 0) });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(err);
    res.status(500).json({ error: "Erro ao salvar." });
  } finally {
    client.release();
  }
});

app.post("/api/data/merge", authMiddleware, async (req, res) => {
  const { payload } = req.body || {};
  if (!payload) {
    return res.status(400).json({ error: "Payload obrigatorio." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const current = await client.query("SELECT payload,revision FROM farm_data WHERE id=1 FOR UPDATE");

    if (!current.rowCount) {
      const inserted = await client.query(
        "INSERT INTO farm_data(id,payload,updated_at,updated_by,revision) VALUES(1,$1,NOW(),$2,0) RETURNING updated_at,revision",
        [payload, req.user.username]
      );
      await client.query("COMMIT");
      const row = inserted.rows[0];
      return res.json({ ok: true, savedAt: row.updated_at, revision: Number(row.revision || 0) });
    }

    const merged = deepMergeAddOnly(current.rows[0].payload, payload);
    const updated = await client.query(
      "UPDATE farm_data SET payload=$1,updated_at=NOW(),updated_by=$2,revision=revision+1 WHERE id=1 RETURNING updated_at,revision",
      [merged, req.user.username]
    );
    await client.query("COMMIT");
    const row = updated.rows[0];
    res.json({ ok: true, savedAt: row.updated_at, revision: Number(row.revision || 0) });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(err);
    res.status(500).json({ error: "Erro ao mesclar." });
  } finally {
    client.release();
  }
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query("CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT DEFAULT 'usuario',created_at TIMESTAMPTZ DEFAULT NOW())");
    await client.query("CREATE TABLE IF NOT EXISTS farm_data(id INTEGER PRIMARY KEY DEFAULT 1,payload JSONB NOT NULL,updated_at TIMESTAMPTZ DEFAULT NOW(),updated_by TEXT,revision INTEGER NOT NULL DEFAULT 0)");
    await client.query("ALTER TABLE farm_data ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 0");
    await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0");
    await client.query("ALTER TABLE users ALTER COLUMN role SET DEFAULT 'usuario'");
    await client.query("UPDATE users SET role='usuario' WHERE role IS NULL OR role='' OR role='user'");

    if (!ADMIN_BOOTSTRAP_PASSWORD) {
      console.warn("ADMIN_BOOTSTRAP_PASSWORD nao definido. O usuario admin nao sera criado automaticamente.");
    } else {
      await ensureBootstrapAdmin(client);
      console.log("Usuario admin garantido a partir de ADMIN_BOOTSTRAP_PASSWORD.");
    }

    console.log("Banco inicializado.");
  } finally {
    client.release();
  }
}

// Handler de erro global: cobre erros de middleware (CORS, JSON malformado,
// etc.) que caem fora dos try/catch de cada rota, sem vazar stack trace.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err && err.message === "Origem nao permitida por CORS.") {
    return res.status(403).json({ error: "Origem nao permitida." });
  }
  if (err && err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "JSON invalido." });
  }
  console.error(err);
  res.status(500).json({ error: "Erro interno." });
});

app.listen(PORT, () => {
  console.log(`Wolf Pecuaria API porta ${PORT}`);
  initDB().catch((err) => console.error("DB init error:", err.message));
});
