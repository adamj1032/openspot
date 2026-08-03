// Parkeroo — production backend (Postgres edition)
// Express + Neon Postgres + JWT auth + Stripe-ready payments
import express from "express";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Stripe from "stripe";
import "dotenv/config";

const app = express();
app.use(express.json({ limit: "4mb" }));
app.use(express.static("public"));

// Body-parser failures (oversized photo, malformed JSON) must come back as JSON,
// not as an HTML error page the front end cannot read.
app.use((err, req, res, next) => {
  if (err && err.type === "entity.too.large") {
    return res.status(413).json({ error: "That photo is too large. Take it again at a smaller size and try once more." });
  }
  if (err && err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "We could not read that request. Try again." });
  }
  return next(err);
});

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
  await q(`ALTER TABLE spots ADD COLUMN IF NOT EXISTS gps_verified BOOLEAN DEFAULT false;`);
  // Arrival instructions are written once by the host and shown only to a driver
  // who has an active booking, since they can contain gate codes or door details.
  await q(`ALTER TABLE spots ADD COLUMN IF NOT EXISTS arrival_note TEXT DEFAULT '';`);
  await q(`ALTER TABLE spots ADD COLUMN IF NOT EXISTS geo_lat DOUBLE PRECISION;`);
  await q(`ALTER TABLE spots ADD COLUMN IF NOT EXISTS geo_lng DOUBLE PRECISION;`);
  // Card on file. Drivers save a card before they can park, and the fare is taken
  // off that card when the session ends rather than by sending them to a payment page
  // with a car already sitting in someone's driveway.
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS payment_method_id TEXT;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS card_brand TEXT;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS card_last4 TEXT;`);
  await q(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS payment_error TEXT;`);
  await q(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      session_id INTEGER NOT NULL REFERENCES sessions(id),
      sender_id INTEGER NOT NULL REFERENCES users(id),
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now(),
      read_at TIMESTAMPTZ
    );`);
  await q(`CREATE INDEX IF NOT EXISTS messages_session_idx ON messages(session_id);`);
  await q(`
    CREATE TABLE IF NOT EXISTS blocks (
      blocker_id INTEGER NOT NULL REFERENCES users(id),
      blocked_id INTEGER NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT now(),
      PRIMARY KEY (blocker_id, blocked_id)
    );`);
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
function tidyAddress(a) {
  return a.replace(/\s+/g, " ").replace(/\s*,\s*/g, ", ").trim();
}

async function nominatim(query) {
  const url = "https://nominatim.openstreetmap.org/search?format=json&addressdetails=1&limit=5&countrycodes=us&q=" + encodeURIComponent(query);
  const r = await fetch(url, {
    headers: { "User-Agent": "Parkeroo/1.0 (support@parkeroo.app)", "Accept-Language": "en" },
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) { console.error("nominatim status", r.status, "for", query); return null; }
  const data = await r.json();
  if (!Array.isArray(data) || !data.length) return null;
  // A house-number match may not be the first result, so prefer one if it is anywhere in the list.
  const scored = data.map((hit) => {
    const d = hit.address || {};
    return {
      lat: parseFloat(hit.lat),
      lng: parseFloat(hit.lon),
      label: hit.display_name,
      precise: !!(d.house_number && (d.road || d.pedestrian)),
    };
  });
  return scored.find((x) => x.precise) || scored[0];
}

async function photon(query) {
  const url = "https://photon.komoot.io/api/?limit=5&lang=en&q=" + encodeURIComponent(query);
  const r = await fetch(url, { headers: { "User-Agent": "Parkeroo/1.0 (support@parkeroo.app)" }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) { console.error("photon status", r.status, "for", query); return null; }
  const data = await r.json();
  const feats = (data && data.features) || [];
  if (!feats.length) return null;
  const scored = feats.map((f) => {
    const p = f.properties || {};
    const label = [p.housenumber && p.street ? `${p.housenumber} ${p.street}` : (p.street || p.name), p.city || p.district, p.state, p.postcode]
      .filter(Boolean).join(", ");
    return {
      lat: f.geometry.coordinates[1],
      lng: f.geometry.coordinates[0],
      label: label || query,
      precise: !!(p.housenumber && p.street),
    };
  });
  return scored.find((x) => x.precise) || scored[0];
}

// The US Census geocoder is the authoritative free source for American street addresses.
// It only ever returns matches at house-number level, has no rate limit, and needs no key,
// so it is the right first choice here and a good backstop when OpenStreetMap is thin.
async function census(query) {
  const url = "https://geocoding.geo.census.gov/geocoder/locations/onelineaddress?benchmark=Public_AR_Current&format=json&address=" + encodeURIComponent(query);
  const r = await fetch(url, { signal: AbortSignal.timeout(8000) });
  if (!r.ok) { console.error("census status", r.status, "for", query); return null; }
  const data = await r.json();
  const m = data && data.result && data.result.addressMatches && data.result.addressMatches[0];
  if (!m || !m.coordinates) return null;
  const lat = Number(m.coordinates.y), lng = Number(m.coordinates.x);
  if (!isFinite(lat) || !isFinite(lng)) return null;
  const label = String(m.matchedAddress || query)
    .toLowerCase()
    .replace(/\b[a-z]/g, (c) => c.toUpperCase())
    .replace(/\b(Nj|Ny|Pa|De|Md|Ct|Ma|Va|Ca|Tx|Fl)\b/g, (x) => x.toUpperCase());
  return { lat, lng, label, precise: true };
}

// Great-circle distance in metres between two coordinates.
function metersBetween(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(a)));
}

// Successful lookups are held briefly. The address is geocoded once when the host taps
// "Find this address" and again a moment later when they publish; without this the second
// call can hit a rate limit and fall through to a vaguer answer than the first, which is
// how the same address ended up precise one minute and street-level the next.
const geoCache = new Map();
const GEO_TTL_MS = 10 * 60 * 1000;

function geoCacheGet(key) {
  const e = geoCache.get(key);
  if (!e) return null;
  if (Date.now() - e.at > GEO_TTL_MS) { geoCache.delete(key); return null; }
  return e.hit;
}

function geoCacheSet(key, hit) {
  if (geoCache.size > 500) geoCache.clear();
  geoCache.set(key, { hit, at: Date.now() });
}

async function geocodeAddress(address) {
  const clean = tidyAddress(address);
  const key = clean.toLowerCase();
  const cached = geoCacheGet(key);
  if (cached) return cached;

  // Try a few phrasings: people type addresses without commas all the time.
  // We do not try to guess where the commas belong, since a wrong guess could place
  // a pin on the wrong street entirely.
  const variants = [clean];
  if (!/usa|united states/i.test(clean)) variants.push(clean + ", USA");

  let fallback = null;

  // Census first: it is the most reliable for US house numbers. Then OpenStreetMap.
  for (const v of variants) {
    for (const provider of [census, nominatim, photon]) {
      try {
        const hit = await provider(v);
        if (!hit || !isFinite(hit.lat) || !isFinite(hit.lng)) continue;
        // A house-number match ends the search. A vaguer one is kept only as a last resort,
        // so a street-level answer from one provider no longer hides an exact answer from another.
        if (hit.precise) { geoCacheSet(key, hit); return hit; }
        if (!fallback) fallback = hit;
      } catch (e) {
        console.error("geocode provider error:", provider.name, e.message);
      }
    }
  }

  if (fallback) geoCacheSet(key, fallback);
  return fallback;
}

app.get("/api/geocode", auth, async (req, res) => {
  const address = (req.query.address || "").trim();
  if (address.length < 6) return res.status(400).json({ error: "Enter a fuller street address" });
  const hit = await geocodeAddress(address);
  if (!hit) return res.status(404).json({ error: "We couldn't place that address. Write it out in full as number and street, town, state — for example 123 Main Street, Anytown, New Jersey" });
  res.json(hit);
});

// ---- email notifications ----
//
// Neither side is sitting in the app during a booking, so a message that only lands
// on screen is a message nobody reads. Email is the cheap delivery path. If no key is
// configured the app carries on silently: notification is a convenience, not a gate.
const MAIL_KEY = process.env.RESEND_API_KEY || "";
const MAIL_FROM = process.env.MAIL_FROM || "Parkeroo <notifications@parkeroo.app>";

async function sendMail(to, subject, text) {
  if (!MAIL_KEY) { console.log("mail skipped (no RESEND_API_KEY):", subject, "->", to); return; }
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": "Bearer " + MAIL_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, text }),
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) console.error("mail send failed", r.status, await r.text().catch(() => ""));
  } catch (e) {
    console.error("mail error:", e.message);
  }
}

// One email per thread per recipient every few minutes, so a back-and-forth
// does not turn into a dozen notifications.
const mailThrottle = new Map();
function mayNotify(sessionId, userId) {
  const key = sessionId + ":" + userId;
  const last = mailThrottle.get(key) || 0;
  if (Date.now() - last < 5 * 60 * 1000) return false;
  if (mailThrottle.size > 2000) mailThrottle.clear();
  mailThrottle.set(key, Date.now());
  return true;
}

// ---- spots ----
app.get("/api/spots", async (req, res) => {
  try {
    const r = await q(`
      SELECT s.id, s.lat, s.lng, s.price_cents, s.note, s.open, s.owner_id, s.address, s.address_verified,
        s.photo, s.gps_verified, u.name AS host, u.payouts_enabled AS host_verified,
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
    const { price_cents, note, address, photo, device_lat, device_lng, device_accuracy, arrival_note } = req.body || {};
    if (!address || address.trim().length < 6) {
      return res.status(400).json({ error: "Enter the street address of your driveway" });
    }
    if (!price_cents || price_cents < 100) {
      return res.status(400).json({ error: "Set an hourly price of at least $1" });
    }
    if (!photo) {
      return res.status(400).json({ error: "A photo of the driveway is required. Drivers need to see where they are pulling in." });
    }
    if (photo.length > 900000) {
      return res.status(413).json({ error: "That photo is too large. Try a smaller one." });
    }

    const hit = await geocodeAddress(address.trim());
    if (!hit) {
      return res.status(404).json({ error: "We couldn't place that address. Write it out in full as number and street, town, state — for example 123 Main Street, Anytown, New Jersey" });
    }

    // Presence check: the host's device must actually be at the driveway when listing it.
    //
    // The radius here is the whole point of the check. Too wide and a host can list any
    // house on their street; a 200m radius covers roughly twenty neighbouring driveways.
    // We use a tight base radius and widen it only by however uncertain the phone says
    // its own fix is, capped, so genuine GPS drift is tolerated but slack is not handed out.
    const PRESENCE_BASE_M = 60;
    const PRESENCE_MAX_M = 120;
    const ACCURACY_LIMIT_M = 100;

    const dLat = Number(device_lat), dLng = Number(device_lng);
    const acc = Number(device_accuracy);

    if (!isFinite(dLat) || !isFinite(dLng)) {
      return res.status(403).json({
        error: "Location sharing is off, so we cannot confirm this listing. Only a person at the property can list it, and we check that every time.",
        code: "not_present",
      });
    }

    // A pin that only resolved to a street or a town centre cannot be checked against.
    // Distance to a town centroid tells us nothing about which driveway you are standing in.
    if (!hit.precise) {
      return res.status(422).json({
        error: "We could only place that address approximately, so we cannot confirm you are at the driveway. Check the house number and spelling, then try again.",
        code: "not_precise",
      });
    }

    // A coarse fix (wifi or mast positioning rather than GPS) is not evidence of presence.
    if (!isFinite(acc) || acc > ACCURACY_LIMIT_M) {
      return res.status(403).json({
        error: "Your device is not reporting a precise enough position for us to confirm this listing. Precise location is required on every listing to keep fake spaces off the map.",
        code: "low_accuracy",
      });
    }

    const allowed = Math.min(PRESENCE_MAX_M, PRESENCE_BASE_M + Math.max(0, acc));
    const gpsMeters = metersBetween(dLat, dLng, hit.lat, hit.lng);

    if (gpsMeters > allowed) {
      // Logged for our own diagnostics, never returned: the distance is a calibration hint.
      console.warn("presence check failed:", Math.round(gpsMeters), "m, user", req.user.id);
      return res.status(403).json({
        error: "This listing was not published. Your device is not at the address you entered, and we only accept listings created at the property itself. This protects homeowners from having their driveways listed by other people.",
        code: "not_present",
      });
    }

    const r = await q(
      `INSERT INTO spots (owner_id, lat, lng, price_cents, note, address, address_verified, photo, gps_verified, arrival_note, geo_lat, geo_lng)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
      // The pin is the host's own position, not the geocoder's. We already proved they are
      // standing at the driveway, and their phone knows that spot far better than a street
      // database does: house-number lookups are often interpolated along the road and can
      // land a hundred metres from the actual house. The geocoded point is kept alongside
      // it purely as the record of what we checked against.
      [req.user.id, dLat, dLng, Math.round(price_cents), note || "", hit.label, hit.precise, photo, true,
       String(arrival_note || "").slice(0, 400), hit.lat, hit.lng]
    );
    res.json({ id: r.rows[0].id, lat: dLat, lng: dLng, address: hit.label, precise: hit.precise, gps_verified: true });
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
    if (typeof req.body.arrival_note === "string") {
      await q("UPDATE spots SET arrival_note = $1 WHERE id = $2", [req.body.arrival_note.slice(0, 400), s.id]);
    }
    if (typeof req.body.open !== "undefined") {
      await q("UPDATE spots SET open = $1 WHERE id = $2", [!!req.body.open, s.id]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error("toggle spot:", err.message);
    res.status(500).json({ error: "Could not update listing" });
  }
});

// Listings made before the pin came from the device still sit wherever the geocoder put
// them. A host can correct one, but only their own, and only from the property itself.
app.post("/api/spots/:id/repin", auth, async (req, res) => {
  try {
    const r = await q("SELECT * FROM spots WHERE id = $1", [req.params.id]);
    const spot = r.rows[0];
    if (!spot || spot.owner_id !== req.user.id) return res.status(403).json({ error: "Not your listing" });

    const dLat = Number(req.body && req.body.device_lat);
    const dLng = Number(req.body && req.body.device_lng);
    const acc = Number(req.body && req.body.device_accuracy);
    if (!isFinite(dLat) || !isFinite(dLng)) {
      return res.status(403).json({ error: "Location sharing is off, so the pin was not moved." });
    }
    if (!isFinite(acc) || acc > 100) {
      return res.status(403).json({ error: "Your device is not reporting a precise enough position to move this pin." });
    }

    const hit = await geocodeAddress(spot.address || "");
    if (hit && hit.precise) {
      const away = metersBetween(dLat, dLng, hit.lat, hit.lng);
      if (away > Math.min(120, 60 + Math.max(0, acc))) {
        console.warn("repin refused:", Math.round(away), "m, spot", spot.id);
        return res.status(403).json({ error: "You are not at the address on this listing, so the pin was not moved." });
      }
    }

    await q("UPDATE spots SET lat = $1, lng = $2 WHERE id = $3", [dLat, dLng, spot.id]);
    res.json({ ok: true, lat: dLat, lng: dLng });
  } catch (err) {
    console.error("repin:", err.message);
    res.status(500).json({ error: "Could not move the pin" });
  }
});

app.delete("/api/spots/:id", auth, async (req, res) => {
  try {
    const r = await q("SELECT * FROM spots WHERE id = $1", [req.params.id]);
    const s = r.rows[0];
    if (!s || s.owner_id !== req.user.id) return res.status(403).json({ error: "Not your listing" });

    const live = await q("SELECT id FROM sessions WHERE spot_id = $1 AND ended_at IS NULL", [s.id]);
    if (live.rows.length) {
      return res.status(409).json({ error: "Someone is parked here right now. You can remove this driveway once they leave." });
    }

    const past = await q("SELECT COUNT(*)::int AS n FROM sessions WHERE spot_id = $1", [s.id]);
    if (past.rows[0].n > 0) {
      // Earnings history has to survive for receipts, disputes and tax records,
      // so a driveway that has been used is retired rather than erased.
      await q("UPDATE spots SET hidden = true, open = false WHERE id = $1", [s.id]);
      return res.json({ ok: true, retired: true });
    }

    await q("DELETE FROM reports WHERE spot_id = $1", [s.id]).catch(()=>{});
    await q("DELETE FROM spots WHERE id = $1", [s.id]);
    res.json({ ok: true, retired: false });
  } catch (err) {
    console.error("delete spot:", err.message);
    res.status(500).json({ error: "Could not remove that driveway. If a booking is still open, wait for it to end and try again." });
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
// ---- cards on file ----
//
// Stripe Checkout in setup mode saves a card without charging it. That keeps card
// details off our server entirely: we only ever hold Stripe's identifiers for them.

async function ensureCustomer(userId) {
  const r = await q("SELECT id, email, name, stripe_customer_id FROM users WHERE id = $1", [userId]);
  const u = r.rows[0];
  if (!u) throw new Error("no such user");
  if (u.stripe_customer_id) return u.stripe_customer_id;
  const c = await stripe.customers.create({ email: u.email, name: u.name, metadata: { user_id: String(u.id) } });
  await q("UPDATE users SET stripe_customer_id = $1 WHERE id = $2", [c.id, u.id]);
  return c.id;
}

app.get("/api/card", auth, async (req, res) => {
  try {
    const r = await q("SELECT payment_method_id, card_brand, card_last4 FROM users WHERE id = $1", [req.user.id]);
    const u = r.rows[0] || {};
    res.json({ saved: !!u.payment_method_id, brand: u.card_brand || "", last4: u.card_last4 || "" });
  } catch (err) {
    console.error("card status:", err.message);
    res.status(500).json({ error: "Could not check your card" });
  }
});

app.post("/api/card/setup", auth, async (req, res) => {
  try {
    if (!stripe) return res.status(503).json({ error: "Payments are not configured yet." });
    const base = (process.env.BASE_URL && process.env.BASE_URL.trim().replace(/\/+$/, "")) || `https://${req.get("host")}`;
    const customer = await ensureCustomer(req.user.id);
    const cs = await stripe.checkout.sessions.create({
      mode: "setup",
      customer,
      success_url: `${base}/?card=1&cs={CHECKOUT_SESSION_ID}`,
      cancel_url: `${base}/?card=0`,
    });
    res.json({ url: cs.url });
  } catch (err) {
    console.error("card setup:", err.message);
    res.status(502).json({ error: "Could not open the card form: " + err.message });
  }
});

// Called when Stripe sends the driver back, to record which card was saved.
app.post("/api/card/confirm", auth, async (req, res) => {
  try {
    if (!stripe) return res.status(503).json({ error: "Payments are not configured yet." });
    const csId = String(req.body && req.body.cs || "");
    if (!csId) return res.status(400).json({ error: "Missing session reference" });
    const cs = await stripe.checkout.sessions.retrieve(csId);
    if (!cs || !cs.setup_intent) return res.status(400).json({ error: "That card form was not completed." });
    const si = await stripe.setupIntents.retrieve(String(cs.setup_intent));
    const pmId = si && si.payment_method;
    if (!pmId) return res.status(400).json({ error: "No card was saved." });
    const pm = await stripe.paymentMethods.retrieve(String(pmId));
    const card = pm.card || {};
    await q("UPDATE users SET payment_method_id = $1, card_brand = $2, card_last4 = $3 WHERE id = $4",
      [pm.id, card.brand || "card", card.last4 || "", req.user.id]);
    res.json({ saved: true, brand: card.brand || "card", last4: card.last4 || "" });
  } catch (err) {
    console.error("card confirm:", err.message);
    res.status(502).json({ error: "Could not save that card: " + err.message });
  }
});

app.delete("/api/card", auth, async (req, res) => {
  try {
    const r = await q("SELECT payment_method_id FROM users WHERE id = $1", [req.user.id]);
    const pm = r.rows[0] && r.rows[0].payment_method_id;
    if (pm && stripe) { try { await stripe.paymentMethods.detach(pm); } catch (e) { console.error("detach:", e.message); } }
    await q("UPDATE users SET payment_method_id = NULL, card_brand = NULL, card_last4 = NULL WHERE id = $1", [req.user.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error("card remove:", err.message);
    res.status(500).json({ error: "Could not remove that card" });
  }
});

app.post("/api/park/:spotId", auth, async (req, res) => {
  try {
    const r = await q("SELECT * FROM spots WHERE id = $1", [req.params.spotId]);
    const spot = r.rows[0];
    if (!spot || !spot.open) return res.status(400).json({ error: "Spot is not available" });
    if (spot.owner_id === req.user.id) return res.status(400).json({ error: "This is your own driveway" });
    if (stripe) {
      const c = await q("SELECT payment_method_id FROM users WHERE id = $1", [req.user.id]);
      if (!c.rows[0] || !c.rows[0].payment_method_id) {
        return res.status(402).json({ error: "Add a card before you park. You are only charged when the session ends.", code: "no_card" });
      }
    }
    const busy = await q("SELECT id FROM sessions WHERE spot_id = $1 AND ended_at IS NULL", [spot.id]);
    if (busy.rows.length) return res.status(409).json({ error: "Just taken — pick another spot" });
    const ins = await q(
      "INSERT INTO sessions (spot_id, driver_id) VALUES ($1,$2) RETURNING id",
      [spot.id, req.user.id]
    );
    res.json({ session_id: ins.rows[0].id, arrival_note: spot.arrival_note || "" });
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
      const base = (process.env.BASE_URL && process.env.BASE_URL.trim().replace(/\/+$/, "")) || `https://${req.get("host")}`;
      const charged = Math.max(amount, 50); // Stripe minimum charge is $0.50
      try {
        const drv = await q("SELECT stripe_customer_id, payment_method_id FROM users WHERE id = $1", [req.user.id]);
        const customer = drv.rows[0] && drv.rows[0].stripe_customer_id;
        const pm = drv.rows[0] && drv.rows[0].payment_method_id;

        const hostR = await q("SELECT stripe_account_id FROM users WHERE id = $1", [spot.owner_id]);
        const hostAcct = hostR.rows[0] && hostR.rows[0].stripe_account_id;
        let splitReady = false;
        if (hostAcct) {
          try {
            const acct = await stripe.accounts.retrieve(hostAcct);
            splitReady = !!acct.charges_enabled;
          } catch (e) { splitReady = false; }
        }

        // The normal path: the card was saved before the car pulled in, so the fare is
        // taken without the driver having to do anything.
        if (customer && pm) {
          const params = {
            amount: charged,
            currency: process.env.CURRENCY || "usd",
            customer,
            payment_method: pm,
            off_session: true,
            confirm: true,
            description: "Driveway parking",
            metadata: { session_id: String(s.id), spot_id: String(spot.id) },
          };
          if (splitReady) {
            params.application_fee_amount = Math.round(charged * COMMISSION);
            params.transfer_data = { destination: hostAcct };
          }
          try {
            const pi = await stripe.paymentIntents.create(params);
            await q("UPDATE sessions SET payment_status = $1, payment_error = NULL WHERE id = $2",
              [splitReady ? "paid_split" : "paid_no_split", s.id]);
            return res.json({ amount_cents: amount, paid: true, pay_url: null, status: pi.status });
          } catch (chargeErr) {
            // A card can fail an hour after it was saved: expired, frozen, or the bank
            // wants the cardholder present. We record the debt and hand back a payment
            // page rather than pretending the booking was free.
            console.error("off-session charge failed:", chargeErr.message);
            await q("UPDATE sessions SET payment_status = 'charge_failed', payment_error = $1 WHERE id = $2",
              [String(chargeErr.message).slice(0, 300), s.id]);
            const recover = await stripe.checkout.sessions.create({
              mode: "payment",
              customer,
              line_items: [{
                price_data: {
                  currency: process.env.CURRENCY || "usd",
                  product_data: { name: "Driveway parking" },
                  unit_amount: charged,
                },
                quantity: 1,
              }],
              ...(splitReady ? { payment_intent_data: {
                application_fee_amount: Math.round(charged * COMMISSION),
                transfer_data: { destination: hostAcct },
              } } : {}),
              success_url: `${base}/?paid=1`,
              cancel_url: `${base}/?paid=0`,
            });
            return res.json({
              amount_cents: amount,
              paid: false,
              pay_url: recover.url,
              error: "Your saved card was declined. Please pay for this booking now.",
            });
          }
        }

        // No card on file. Older accounts can still reach this, so fall back to the
        // payment page rather than letting the fare disappear.
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
        await q("UPDATE sessions SET payment_status = $1 WHERE id = $2",
          [splitReady ? "checkout_split" : "checkout_no_split", s.id]);
        return res.json({ amount_cents: amount, paid: false, pay_url: checkout.url });
      } catch (err) {
        console.error("Stripe failed:", err.message);
        await q("UPDATE sessions SET payment_status = 'stripe_error', payment_error = $1 WHERE id = $2",
          [String(err.message).slice(0, 300), s.id]);
        return res.status(502).json({ error: "Payment failed: " + err.message });
      }
    }
    await q("UPDATE sessions SET payment_status = 'simulated' WHERE id = $1", [s.id]);
    res.json({ amount_cents: amount, pay_url: null });
  } catch (err) {
    console.error("end session:", err.message);
    res.status(500).json({ error: "Could not end session" });
  }
});

// ---- messages ----
//
// A thread exists only for the length of a booking. It opens when a car pulls in and
// closes when the session ends, so neither side keeps a channel to the other afterwards.
// This is deliberately not a phone number swap: a driveway listing is a home address,
// and a number handed over cannot be taken back.

async function threadParties(sessionId, userId) {
  const r = await q(`
    SELECT se.id, se.driver_id, se.ended_at, sp.owner_id, sp.address, sp.arrival_note,
           d.name AS driver_name, d.email AS driver_email,
           h.name AS host_name, h.email AS host_email
    FROM sessions se
    JOIN spots sp ON sp.id = se.spot_id
    JOIN users d ON d.id = se.driver_id
    JOIN users h ON h.id = sp.owner_id
    WHERE se.id = $1
  `, [sessionId]);
  const t = r.rows[0];
  if (!t) return null;
  const isDriver = t.driver_id === userId;
  const isHost = t.owner_id === userId;
  if (!isDriver && !isHost) return null;
  return {
    ...t,
    isDriver,
    active: !t.ended_at,
    otherId: isDriver ? t.owner_id : t.driver_id,
    otherName: isDriver ? t.host_name : t.driver_name,
    otherEmail: isDriver ? t.host_email : t.driver_email,
  };
}

app.get("/api/messages/:sessionId", auth, async (req, res) => {
  try {
    const t = await threadParties(req.params.sessionId, req.user.id);
    if (!t) return res.status(403).json({ error: "Not your booking" });
    const r = await q(
      "SELECT id, sender_id, body, created_at FROM messages WHERE session_id = $1 ORDER BY id",
      [t.id]
    );
    await q("UPDATE messages SET read_at = now() WHERE session_id = $1 AND sender_id <> $2 AND read_at IS NULL",
      [t.id, req.user.id]);
    res.json({
      active: t.active,
      me: req.user.id,
      other: t.otherName,
      address: t.address,
      // Arrival instructions can hold a gate code, so only the driver in the space sees them.
      arrival_note: t.isDriver ? (t.arrival_note || "") : "",
      messages: r.rows,
    });
  } catch (err) {
    console.error("messages get:", err.message);
    res.status(500).json({ error: "Could not load messages" });
  }
});

app.post("/api/messages/:sessionId", auth, async (req, res) => {
  try {
    const t = await threadParties(req.params.sessionId, req.user.id);
    if (!t) return res.status(403).json({ error: "Not your booking" });
    if (!t.active) return res.status(409).json({ error: "This booking has ended, so the thread is closed." });

    const body = String(req.body && req.body.body || "").trim().slice(0, 500);
    if (!body) return res.status(400).json({ error: "Write a message first" });

    const b = await q("SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2", [t.otherId, req.user.id]);
    if (b.rows.length) return res.status(403).json({ error: "You cannot message this user." });

    // A simple flood guard so nobody can hammer the other side.
    const recent = await q(
      "SELECT COUNT(*)::int AS n FROM messages WHERE session_id = $1 AND sender_id = $2 AND created_at > now() - interval '1 minute'",
      [t.id, req.user.id]
    );
    if (recent.rows[0].n >= 12) return res.status(429).json({ error: "Slow down a moment." });

    const ins = await q(
      "INSERT INTO messages (session_id, sender_id, body) VALUES ($1,$2,$3) RETURNING id, sender_id, body, created_at",
      [t.id, req.user.id, body]
    );

    if (t.otherEmail && mayNotify(t.id, t.otherId)) {
      const who = t.isDriver ? "the driver" : "the host";
      sendMail(
        t.otherEmail,
        "New message about your Parkeroo booking",
        `You have a message from ${who} about ${t.address || "your booking"}.\n\n"${body}"\n\nOpen Parkeroo to reply. The thread closes when the booking ends.`
      );
    }

    res.json(ins.rows[0]);
  } catch (err) {
    console.error("messages post:", err.message);
    res.status(500).json({ error: "Could not send message" });
  }
});

app.post("/api/messages/:sessionId/block", auth, async (req, res) => {
  try {
    const t = await threadParties(req.params.sessionId, req.user.id);
    if (!t) return res.status(403).json({ error: "Not your booking" });
    await q("INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
      [req.user.id, t.otherId]);
    console.warn("user blocked:", req.user.id, "blocked", t.otherId, "session", t.id,
      "reason:", String(req.body && req.body.reason || "").slice(0, 200));
    res.json({ ok: true });
  } catch (err) {
    console.error("block:", err.message);
    res.status(500).json({ error: "Could not block that user" });
  }
});

// Open threads for whoever is asking, with unread counts, so the app can show a badge.
app.get("/api/threads", auth, async (req, res) => {
  try {
    const r = await q(`
      SELECT se.id, sp.address,
        CASE WHEN se.driver_id = $1 THEN h.name ELSE d.name END AS other,
        (SELECT COUNT(*)::int FROM messages m
          WHERE m.session_id = se.id AND m.sender_id <> $1 AND m.read_at IS NULL) AS unread
      FROM sessions se
      JOIN spots sp ON sp.id = se.spot_id
      JOIN users d ON d.id = se.driver_id
      JOIN users h ON h.id = sp.owner_id
      WHERE se.ended_at IS NULL AND (se.driver_id = $1 OR sp.owner_id = $1)
    `, [req.user.id]);
    res.json(r.rows);
  } catch (err) {
    console.error("threads:", err.message);
    res.status(500).json({ error: "Could not load threads" });
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
