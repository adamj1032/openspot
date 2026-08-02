// OpenSpot — production backend
// Express + SQLite + JWT auth + Stripe-ready payments
import express from "express";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Stripe from "stripe";
import "dotenv/config";

const app = express();
app.use(express.json());
app.use(express.static("public"));

const db = new Database(process.env.DB_PATH || "openspot.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS spots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    lat REAL NOT NULL, lng REAL NOT NULL,
    price_cents INTEGER NOT NULL,
    note TEXT DEFAULT '',
    open INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    spot_id INTEGER NOT NULL REFERENCES spots(id),
    driver_id INTEGER NOT NULL REFERENCES users(id),
    started_at TEXT DEFAULT (datetime('now')),
    ended_at TEXT,
    amount_cents INTEGER,
    payment_status TEXT DEFAULT 'pending'
  );
`);

const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

// ---- auth helpers ----
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
app.post("/api/signup", (req, res) => {
  const { email, name, password } = req.body || {};
  if (!email || !name || !password) return res.status(400).json({ error: "Email, name and password are required" });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const r = db.prepare("INSERT INTO users (email, name, pass_hash) VALUES (?,?,?)").run(email.toLowerCase(), name, hash);
    const token = jwt.sign({ id: r.lastInsertRowid, name }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, name });
  } catch {
    res.status(409).json({ error: "That email is already registered" });
  }
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};
  const u = db.prepare("SELECT * FROM users WHERE email = ?").get((email || "").toLowerCase());
  if (!u || !bcrypt.compareSync(password || "", u.pass_hash)) {
    return res.status(401).json({ error: "Wrong email or password" });
  }
  const token = jwt.sign({ id: u.id, name: u.name }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, name: u.name });
});

// ---- spots (the live map) ----
app.get("/api/spots", (req, res) => {
  const rows = db.prepare(`
    SELECT s.id, s.lat, s.lng, s.price_cents, s.note, s.open, s.owner_id, u.name AS host,
      (SELECT driver_id FROM sessions WHERE spot_id = s.id AND ended_at IS NULL) AS taken_by
    FROM spots s JOIN users u ON u.id = s.owner_id
  `).all();
  res.json(rows);
});

app.post("/api/spots", auth, (req, res) => {
  const { lat, lng, price_cents, note } = req.body || {};
  if (typeof lat !== "number" || typeof lng !== "number" || !price_cents) {
    return res.status(400).json({ error: "Location and price are required" });
  }
  const r = db.prepare("INSERT INTO spots (owner_id, lat, lng, price_cents, note) VALUES (?,?,?,?,?)")
    .run(req.user.id, lat, lng, Math.round(price_cents), note || "");
  res.json({ id: r.lastInsertRowid });
});

app.patch("/api/spots/:id", auth, (req, res) => {
  const s = db.prepare("SELECT * FROM spots WHERE id = ?").get(req.params.id);
  if (!s || s.owner_id !== req.user.id) return res.status(403).json({ error: "Not your listing" });
  const open = req.body.open ? 1 : 0;
  db.prepare("UPDATE spots SET open = ? WHERE id = ?").run(open, s.id);
  res.json({ ok: true });
});

app.delete("/api/spots/:id", auth, (req, res) => {
  const s = db.prepare("SELECT * FROM spots WHERE id = ?").get(req.params.id);
  if (!s || s.owner_id !== req.user.id) return res.status(403).json({ error: "Not your listing" });
  db.prepare("DELETE FROM spots WHERE id = ?").run(s.id);
  res.json({ ok: true });
});

// ---- parking sessions ----
app.post("/api/park/:spotId", auth, (req, res) => {
  const spot = db.prepare("SELECT * FROM spots WHERE id = ?").get(req.params.spotId);
  if (!spot || !spot.open) return res.status(400).json({ error: "Spot is not available" });
  const busy = db.prepare("SELECT id FROM sessions WHERE spot_id = ? AND ended_at IS NULL").get(spot.id);
  if (busy) return res.status(409).json({ error: "Just taken — pick another spot" });
  const r = db.prepare("INSERT INTO sessions (spot_id, driver_id) VALUES (?,?)").run(spot.id, req.user.id);
  res.json({ session_id: r.lastInsertRowid });
});

app.post("/api/end/:sessionId", auth, async (req, res) => {
  const s = db.prepare("SELECT * FROM sessions WHERE id = ? AND driver_id = ? AND ended_at IS NULL")
    .get(req.params.sessionId, req.user.id);
  if (!s) return res.status(404).json({ error: "No active session" });
  const spot = db.prepare("SELECT * FROM spots WHERE id = ?").get(s.spot_id);
  const startedMs = new Date(s.started_at + "Z").getTime();
  const hours = Math.max((Date.now() - startedMs) / 3600000, 0.25); // 15 min minimum
  const amount = Math.round(hours * spot.price_cents);

  db.prepare("UPDATE sessions SET ended_at = datetime('now'), amount_cents = ? WHERE id = ?").run(amount, s.id);

  // Stripe: create a checkout for the amount. Without a key, mark as simulated.
  if (stripe) {
    const checkout = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: [{
        price_data: {
          currency: process.env.CURRENCY || "usd",
          product_data: { name: "Driveway parking" },
          unit_amount: amount,
        },
        quantity: 1,
      }],
      success_url: `${process.env.BASE_URL}/?paid=1`,
      cancel_url: `${process.env.BASE_URL}/?paid=0`,
    });
    db.prepare("UPDATE sessions SET payment_status = 'checkout_created' WHERE id = ?").run(s.id);
    return res.json({ amount_cents: amount, pay_url: checkout.url });
  }
  db.prepare("UPDATE sessions SET payment_status = 'simulated' WHERE id = ?").run(s.id);
  res.json({ amount_cents: amount, pay_url: null });
});

app.get("/api/me/session", auth, (req, res) => {
  const s = db.prepare(`
    SELECT se.id, se.spot_id, se.started_at, sp.price_cents, u.name AS host
    FROM sessions se JOIN spots sp ON sp.id = se.spot_id JOIN users u ON u.id = sp.owner_id
    WHERE se.driver_id = ? AND se.ended_at IS NULL
  `).get(req.user.id);
  res.json(s || null);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`OpenSpot running on http://localhost:${port}`));
