// OpenSpot — production backend (Postgres edition)
// Express + Neon Postgres + JWT auth + Stripe-ready payments
import express from "express";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Stripe from "stripe";
import "dotenv/config";

const app = express();
app.use(express.json());
app.use(express.static("public"));

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not set. Add it in Render > Environment.");
}

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
});
const q = (text, params) => pool.query(text, params);

async function initDb() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      pass_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );`);
  await q(`
    CREATE TABLE IF NOT EXISTS spots (
      id SERIAL PRIMARY KEY,
      owner_id INTEGER NOT NULL REFERENCES users(id),
      lat DOUBLE PRECISION NOT NULL,
      lng DOUBLE PRECISION NOT NULL,
      price_cents INTEGER NOT NULL,
      note TEXT DEFAULT '',
      open BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT now()
    );`);
  await q(`
    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      spot_id INTEGER NOT NULL REFERENCES spots(id),
      driver_id INTEGER NOT NULL REFERENCES users(id),
      started_at TIMESTAMPTZ DEFAULT now(),
      ended_at TIMESTAMPTZ,
      amount_cents INTEGER,
      payment_status TEXT DEFAULT 'pending'
    );`);
  console.log("Database ready");
}

const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Sign in required" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Session expired — sign in again" });
  }
}

// ---- accounts ----
app.post("/api/signup", async (req, res) => {
  try {
    const { email, name, password } = req.body || {};
    if (!email || !name || !password) return res.status(400).json({ error: "Email, name and password are required" });
    const hash = bcrypt.hashSync(password, 10);
    const r = await q(
      "INSERT INTO users (email, name, pass_hash) VALUES ($1,$2,$3) RETURNING id",
      [email.toLowerCase(), name, hash]
    );
    const token = jwt.sign({ id: r.rows[0].id, name }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, name });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "That email is already registered" });
    console.error("signup:", err.message);
    res.status(500).json({ error: "Could not create account" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const r = await q("SELECT * FROM users WHERE email = $1", [(email || "").toLowerCase()]);
    const u = r.rows[0];
    if (!u || !bcrypt.compareSync(password || "", u.pass_hash)) {
      return res.status(401).json({ error: "Wrong email or password" });
    }
    const token = jwt.sign({ id: u.id, name: u.name }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, name: u.name });
  } catch (err) {
    console.error("login:", err.message);
    res.status(500).json({ error: "Could not sign in" });
  }
});

// ---- spots ----
app.get("/api/spots", async (req, res) => {
  try {
    const r = await q(`
      SELECT s.id, s.lat, s.lng, s.price_cents, s.note, s.open, s.owner_id, u.name AS host,
        (SELECT driver_id FROM sessions WHERE spot_id = s.id AND ended_at IS NULL LIMIT 1) AS taken_by
      FROM spots s JOIN users u ON u.id = s.owner_id
    `);
    res.json(r.rows);
  } catch (err) {
    console.error("spots:", err.message);
    res.status(500).json({ error: "Could not load spots" });
  }
});

app.post("/api/spots", auth, async (req, res) => {
  try {
    const { lat, lng, price_cents, note } = req.body || {};
    if (typeof lat !== "number" || typeof lng !== "number" || !price_cents) {
      return res.status(400).json({ error: "Location and price are required" });
    }
    const r = await q(
      "INSERT INTO spots (owner_id, lat, lng, price_cents, note) VALUES ($1,$2,$3,$4,$5) RETURNING id",
      [req.user.id, lat, lng, Math.round(price_cents), note || ""]
    );
    res.json({ id: r.rows[0].id });
  } catch (err) {
    console.error("create spot:", err.message);
    res.status(500).json({ error: "Could not create listing" });
  }
});

app.patch("/api/spots/:id", auth, async (req, res) => {
  try {
    const r = await q("SELECT * FROM spots WHERE id = $1", [req.params.id]);
    const s = r.rows[0];
    if (!s || s.owner_id !== req.user.id) return res.status(403).json({ error: "Not your listing" });
    await q("UPDATE spots SET open = $1 WHERE id = $2", [!!req.body.open, s.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error("toggle spot:", err.message);
    res.status(500).json({ error: "Could not update listing" });
  }
});

app.delete("/api/spots/:id", auth, async (req, res) => {
  try {
    const r = await q("SELECT * FROM spots WHERE id = $1", [req.params.id]);
    const s = r.rows[0];
    if (!s || s.owner_id !== req.user.id) return res.status(403).json({ error: "Not your listing" });
    await q("DELETE FROM sessions WHERE spot_id = $1", [s.id]);
    await q("DELETE FROM spots WHERE id = $1", [s.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error("delete spot:", err.message);
    res.status(500).json({ error: "Could not remove listing" });
  }
});

// ---- parking sessions ----
app.post("/api/park/:spotId", auth, async (req, res) => {
  try {
    const r = await q("SELECT * FROM spots WHERE id = $1", [req.params.spotId]);
    const spot = r.rows[0];
    if (!spot || !spot.open) return res.status(400).json({ error: "Spot is not available" });
    const busy = await q("SELECT id FROM sessions WHERE spot_id = $1 AND ended_at IS NULL", [spot.id]);
    if (busy.rows.length) return res.status(409).json({ error: "Just taken — pick another spot" });
    const ins = await q(
      "INSERT INTO sessions (spot_id, driver_id) VALUES ($1,$2) RETURNING id",
      [spot.id, req.user.id]
    );
    res.json({ session_id: ins.rows[0].id });
  } catch (err) {
    console.error("park:", err.message);
    res.status(500).json({ error: "Could not start session" });
  }
});

app.post("/api/end/:sessionId", auth, async (req, res) => {
  try {
    const r = await q(
      "SELECT * FROM sessions WHERE id = $1 AND driver_id = $2 AND ended_at IS NULL",
      [req.params.sessionId, req.user.id]
    );
    const s = r.rows[0];
    if (!s) return res.status(404).json({ error: "No active session" });
    const spotR = await q("SELECT * FROM spots WHERE id = $1", [s.spot_id]);
    const spot = spotR.rows[0];
    const hours = Math.max((Date.now() - new Date(s.started_at).getTime()) / 3600000, 0.25); // 15 min minimum
    const amount = Math.round(hours * spot.price_cents);

    await q("UPDATE sessions SET ended_at = now(), amount_cents = $1 WHERE id = $2", [amount, s.id]);

    if (stripe) {
      try {
        const base = (process.env.BASE_URL && process.env.BASE_URL.trim().replace(/\/+$/, "")) || `https://${req.get("host")}`;
        const checkout = await stripe.checkout.sessions.create({
          mode: "payment",
          line_items: [{
            price_data: {
              currency: process.env.CURRENCY || "usd",
              product_data: { name: "Driveway parking" },
              unit_amount: Math.max(amount, 50), // Stripe minimum charge is $0.50
            },
            quantity: 1,
          }],
          success_url: `${base}/?paid=1`,
          cancel_url: `${base}/?paid=0`,
        });
        await q("UPDATE sessions SET payment_status = 'checkout_created' WHERE id = $1", [s.id]);
        return res.json({ amount_cents: amount, pay_url: checkout.url });
      } catch (err) {
        console.error("Stripe checkout failed:", err.message);
        await q("UPDATE sessions SET payment_status = 'stripe_error' WHERE id = $1", [s.id]);
        return res.status(502).json({ error: "Payment setup failed: " + err.message });
      }
    }
    await q("UPDATE sessions SET payment_status = 'simulated' WHERE id = $1", [s.id]);
    res.json({ amount_cents: amount, pay_url: null });
  } catch (err) {
    console.error("end session:", err.message);
    res.status(500).json({ error: "Could not end session" });
  }
});

app.get("/api/me/session", auth, async (req, res) => {
  try {
    const r = await q(`
      SELECT se.id, se.spot_id, se.started_at, sp.price_cents, u.name AS host
      FROM sessions se JOIN spots sp ON sp.id = se.spot_id JOIN users u ON u.id = sp.owner_id
      WHERE se.driver_id = $1 AND se.ended_at IS NULL
    `, [req.user.id]);
    res.json(r.rows[0] || null);
  } catch (err) {
    console.error("me/session:", err.message);
    res.status(500).json({ error: "Could not load session" });
  }
});

const port = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(port, () => console.log(`OpenSpot running on http://localhost:${port}`)))
  .catch((err) => {
    console.error("Database init failed:", err.message);
    process.exit(1);
  });

process.on("unhandledRejection", (err) => console.error("Unhandled rejection:", err));
