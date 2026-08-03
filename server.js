// Parkeroo — production backend (Postgres edition)
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
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_account_id TEXT;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS accepted_terms_at TIMESTAMPTZ;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS payouts_enabled BOOLEAN DEFAULT false;`);
  await q(`ALTER TABLE spots ADD COLUMN IF NOT EXISTS address TEXT DEFAULT '';`);
  await q(`ALTER TABLE spots ADD COLUMN IF NOT EXISTS address_verified BOOLEAN DEFAULT false;`);
  await q(`ALTER TABLE spots ADD COLUMN IF NOT EXISTS photo TEXT;`);
  await q(`
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      spot_id INTEGER NOT NULL REFERENCES spots(id),
      reporter_id INTEGER REFERENCES users(id),
      reason TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );`);
  await q(`ALTER TABLE spots ADD COLUMN IF NOT EXISTS hidden BOOLEAN DEFAULT false;`);
  await q(`
    CREATE TABLE IF NOT EXISTS ratings (
      id SERIAL PRIMARY KEY,
      session_id INTEGER UNIQUE NOT NULL REFERENCES sessions(id),
      spot_id INTEGER NOT NULL REFERENCES spots(id),
      driver_id INTEGER NOT NULL REFERENCES users(id),
      stars INTEGER NOT NULL CHECK (stars BETWEEN 1 AND 5),
      created_at TIMESTAMPTZ DEFAULT now()
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
    const { email, name, password, accepted } = req.body || {};
    if (!email || !name || !password) return res.status(400).json({ error: "Email, name and password are required" });
    if (!accepted) return res.status(400).json({ error: "You must agree to the Terms of Service and Privacy Policy" });
    const hash = bcrypt.hashSync(password, 10);
    const r = await q(
      "INSERT INTO users (email, name, pass_hash, accepted_terms_at) VALUES ($1,$2,$3, now()) RETURNING id",
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

// ---- address geocoding (OpenStreetMap Nominatim) ----
async function geocodeAddress(address) {
  try {
    const url = "https://nominatim.openstreetmap.org/search?format=json&addressdetails=1&limit=1&q=" + encodeURIComponent(address);
    const r = await fetch(url, { headers: { "User-Agent": "Parkeroo/1.0 (https://parkeroo.app)" }, signal: AbortSignal.timeout(8000) });
    const data = await r.json();
    if (!Array.isArray(data) || !data.length) return null;
    const hit = data[0];
    const d = hit.address || {};
    // only accept results precise enough to be a real street address
    const precise = !!(d.house_number && (d.road || d.pedestrian));
    return {
      lat: parseFloat(hit.lat),
      lng: parseFloat(hit.lon),
      label: hit.display_name,
      precise,
    };
  } catch (e) {
    console.error("geocode:", e.message);
    return null;
  }
}

app.get("/api/geocode", auth, async (req, res) => {
  const address = (req.query.address || "").trim();
  if (address.length < 6) return res.status(400).json({ error: "Enter a fuller street address" });
  const hit = await geocodeAddress(address);
  if (!hit) return res.status(404).json({ error: "We couldn't find that address. Check the spelling, and include the town and state." });
  res.json(hit);
});

// ---- spots ----
app.get("/api/spots", async (req, res) => {
  try {
    const r = await q(`
      SELECT s.id, s.lat, s.lng, s.price_cents, s.note, s.open, s.owner_id, s.address, s.address_verified,
        s.photo, u.name AS host, u.payouts_enabled AS host_verified,
        (SELECT driver_id FROM sessions WHERE spot_id = s.id AND ended_at IS NULL LIMIT 1) AS taken_by,
        (SELECT ROUND(AVG(stars)::numeric, 1) FROM ratings WHERE spot_id = s.id) AS rating,
        (SELECT COUNT(*)::int FROM ratings WHERE spot_id = s.id) AS rating_count
      FROM spots s JOIN users u ON u.id = s.owner_id
      WHERE s.hidden = false
    `);
    res.json(r.rows);
  } catch (err) {
    console.error("spots:", err.message);
    res.status(500).json({ error: "Could not load spots" });
  }
});

app.post("/api/spots", auth, async (req, res) => {
  try {
    const { price_cents, note, address, photo } = req.body || {};
    if (!address || address.trim().length < 6) {
      return res.status(400).json({ error: "Enter the street address of your driveway" });
    }
    if (!price_cents || price_cents < 100) {
      return res.status(400).json({ error: "Set an hourly price of at least $1" });
    }
    if (photo && photo.length > 900000) {
      return res.status(413).json({ error: "That photo is too large. Try a smaller one." });
    }

    const hit = await geocodeAddress(address.trim());
    if (!hit) {
      return res.status(404).json({ error: "We couldn't find that address. Check the spelling, and include the town and state." });
    }

    const r = await q(
      `INSERT INTO spots (owner_id, lat, lng, price_cents, note, address, address_verified, photo)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [req.user.id, hit.lat, hit.lng, Math.round(price_cents), note || "", hit.label, hit.precise, photo || null]
    );
    res.json({ id: r.rows[0].id, lat: hit.lat, lng: hit.lng, address: hit.label, precise: hit.precise });
  } catch (err) {
    console.error("create spot:", err.message);
    res.status(500).json({ error: "Could not create listing" });
  }
});

app.get("/api/my/spots", auth, async (req, res) => {
  try {
    const r = await q(`
      SELECT s.*, (SELECT COUNT(*)::int FROM sessions se WHERE se.spot_id = s.id AND se.ended_at IS NOT NULL) AS bookings,
        (SELECT ROUND(AVG(stars)::numeric,1) FROM ratings WHERE spot_id = s.id) AS rating
      FROM spots s WHERE s.owner_id = $1 ORDER BY s.created_at DESC`, [req.user.id]);
    res.json(r.rows);
  } catch (err) {
    console.error("my spots:", err.message);
    res.status(500).json({ error: "Could not load your driveways" });
  }
});

app.post("/api/spots/:id/report", auth, async (req, res) => {
  try {
    const reason = (req.body && req.body.reason || "").trim().slice(0, 500);
    if (!reason) return res.status(400).json({ error: "Tell us briefly what's wrong with this listing" });
    const s = await q("SELECT id FROM spots WHERE id = $1", [req.params.id]);
    if (!s.rows.length) return res.status(404).json({ error: "Listing not found" });
    await q("INSERT INTO reports (spot_id, reporter_id, reason) VALUES ($1,$2,$3)", [req.params.id, req.user.id, reason]);
    const cnt = await q("SELECT COUNT(*)::int AS n FROM reports WHERE spot_id = $1", [req.params.id]);
    if (cnt.rows[0].n >= 2) {
      await q("UPDATE spots SET hidden = true, open = false WHERE id = $1", [req.params.id]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error("report:", err.message);
    res.status(500).json({ error: "Could not send that report" });
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

// ---- ratings & history ----
app.post("/api/rate/:sessionId", auth, async (req, res) => {
  try {
    const stars = parseInt(req.body && req.body.stars);
    if (!stars || stars < 1 || stars > 5) return res.status(400).json({ error: "Rating must be 1 to 5 stars" });
    const r = await q(
      "SELECT * FROM sessions WHERE id = $1 AND driver_id = $2 AND ended_at IS NOT NULL",
      [req.params.sessionId, req.user.id]
    );
    const s = r.rows[0];
    if (!s) return res.status(404).json({ error: "No finished session to rate" });
    await q(
      `INSERT INTO ratings (session_id, spot_id, driver_id, stars) VALUES ($1,$2,$3,$4)
       ON CONFLICT (session_id) DO UPDATE SET stars = $4`,
      [s.id, s.spot_id, req.user.id, stars]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("rate:", err.message);
    res.status(500).json({ error: "Could not save rating" });
  }
});

app.get("/api/history", auth, async (req, res) => {
  try {
    const r = await q(`
      SELECT se.id, se.started_at, se.ended_at, se.amount_cents, u.name AS host, sp.note,
        (SELECT stars FROM ratings WHERE session_id = se.id) AS my_stars
      FROM sessions se JOIN spots sp ON sp.id = se.spot_id JOIN users u ON u.id = sp.owner_id
      WHERE se.driver_id = $1 AND se.ended_at IS NOT NULL
      ORDER BY se.ended_at DESC LIMIT 50
    `, [req.user.id]);
    res.json(r.rows);
  } catch (err) {
    console.error("history:", err.message);
    res.status(500).json({ error: "Could not load history" });
  }
});

app.get("/api/earnings", auth, async (req, res) => {
  try {
    const r = await q(`
      SELECT se.id, se.ended_at, se.amount_cents, du.name AS driver
      FROM sessions se
      JOIN spots sp ON sp.id = se.spot_id
      JOIN users du ON du.id = se.driver_id
      WHERE sp.owner_id = $1 AND se.ended_at IS NOT NULL AND se.amount_cents IS NOT NULL
      ORDER BY se.ended_at DESC LIMIT 50
    `, [req.user.id]);
    const total = r.rows.reduce((a, x) => a + (x.amount_cents || 0), 0);
    res.json({ sessions: r.rows, total_cents: total, host_share_cents: Math.round(total * 0.8) });
  } catch (err) {
    console.error("earnings:", err.message);
    res.status(500).json({ error: "Could not load earnings" });
  }
});

// ---- host payouts (Stripe Connect) ----
const COMMISSION = 0.20; // platform keeps 20%

app.post("/api/connect/onboard", auth, async (req, res) => {
  if (!stripe) return res.status(400).json({ error: "Payments are not configured" });
  try {
    const base = (process.env.BASE_URL && process.env.BASE_URL.trim().replace(/\/+$/, "")) || `https://${req.get("host")}`;
    const r = await q("SELECT stripe_account_id FROM users WHERE id = $1", [req.user.id]);
    let acct = r.rows[0] && r.rows[0].stripe_account_id;
    if (!acct) {
      const uRes = await q("SELECT email, name FROM users WHERE id = $1", [req.user.id]);
      const u = uRes.rows[0] || {};
      const base = (process.env.BASE_URL && process.env.BASE_URL.trim().replace(/\/+$/, "")) || "https://parkeroo.app";
      const account = await stripe.accounts.create({
        type: "express",
        country: "US",
        email: u.email,
        business_type: "individual",
        capabilities: { transfers: { requested: true } },
        business_profile: {
          // pre-fill so hosts are never asked "what do you sell / what's your website"
          mcc: "7523", // parking lots, meters and garages
          url: base,
          product_description: "Rents out a private residential driveway for short-term parking through Parkeroo.",
          name: "Parkeroo host",
        },
        settings: {
          payouts: { schedule: { interval: "daily", delay_days: "minimum" } },
        },
        metadata: { parkeroo_user_id: String(req.user.id) },
      });
      acct = account.id;
      await q("UPDATE users SET stripe_account_id = $1 WHERE id = $2", [acct, req.user.id]);
    }
    const link = await stripe.accountLinks.create({
      account: acct,
      refresh_url: `${base}/?connect=refresh`,
      return_url: `${base}/?connect=done`,
      type: "account_onboarding",
      collection_options: { fields: "currently_due" },
    });
    res.json({ url: link.url });
  } catch (err) {
    console.error("connect onboard:", err.message);
    res.status(502).json({ error: "Payout setup failed: " + err.message });
  }
});

app.post("/api/connect/reset", auth, async (req, res) => {
  if (!stripe) return res.status(400).json({ error: "Payments are not configured" });
  try {
    const r = await q("SELECT stripe_account_id FROM users WHERE id = $1", [req.user.id]);
    const acct = r.rows[0] && r.rows[0].stripe_account_id;
    if (!acct) return res.json({ ok: true, note: "nothing to reset" });

    // Only allow a reset while setup is incomplete. A verified, payout-enabled
    // account must never be wiped: it holds identity checks, bank details and
    // possibly pending transfers.
    const account = await stripe.accounts.retrieve(acct);
    if (account.charges_enabled || account.payouts_enabled) {
      return res.status(409).json({ error: "Your payout account is already active, so it can't be reset. Contact support if the details are wrong." });
    }

    try { await stripe.accounts.del(acct); } catch (e) { console.error("stripe delete:", e.message); }
    await q("UPDATE users SET stripe_account_id = NULL, payouts_enabled = false WHERE id = $1", [req.user.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error("connect reset:", err.message);
    res.status(502).json({ error: "Could not reset payout setup: " + err.message });
  }
});

app.get("/api/connect/status", auth, async (req, res) => {
  try {
    const r = await q("SELECT stripe_account_id FROM users WHERE id = $1", [req.user.id]);
    const acct = r.rows[0] && r.rows[0].stripe_account_id;
    if (!acct || !stripe) return res.json({ connected: false });
    const account = await stripe.accounts.retrieve(acct);
    await q("UPDATE users SET payouts_enabled = $1 WHERE id = $2", [!!account.charges_enabled, req.user.id]);
    res.json({ connected: !!account.charges_enabled, pending: !account.charges_enabled });
  } catch (err) {
    console.error("connect status:", err.message);
    res.json({ connected: false });
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
        const charged = Math.max(amount, 50); // Stripe minimum charge is $0.50
        const hostR = await q("SELECT stripe_account_id FROM users WHERE id = $1", [spot.owner_id]);
        const hostAcct = hostR.rows[0] && hostR.rows[0].stripe_account_id;
        let splitReady = false;
        if (hostAcct) {
          try {
            const acct = await stripe.accounts.retrieve(hostAcct);
            splitReady = !!acct.charges_enabled;
          } catch (e) { splitReady = false; }
        }
        const params = {
          mode: "payment",
          line_items: [{
            price_data: {
              currency: process.env.CURRENCY || "usd",
              product_data: { name: "Driveway parking" },
              unit_amount: charged,
            },
            quantity: 1,
          }],
          success_url: `${base}/?paid=1`,
          cancel_url: `${base}/?paid=0`,
        };
        if (splitReady) {
          params.payment_intent_data = {
            application_fee_amount: Math.round(charged * COMMISSION),
            transfer_data: { destination: hostAcct },
          };
        }
        const checkout = await stripe.checkout.sessions.create(params);
        await q("UPDATE sessions SET payment_status = $1 WHERE id = $2", [splitReady ? 'checkout_split' : 'checkout_no_split', s.id]);
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
  .then(() => app.listen(port, () => console.log(`Parkeroo running on http://localhost:${port}`)))
  .catch((err) => {
    console.error("Database init failed:", err.message);
    process.exit(1);
  });

process.on("unhandledRejection", (err) => console.error("Unhandled rejection:", err));
