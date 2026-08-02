# OpenSpot — live driveway parking marketplace

A working full-stack app: drivers see a live map of driveways that homeowners
have listed as paid parking. Homeowners open and close their spot with one tap.

## What is included
- Accounts (sign up / sign in, passwords hashed, JWT sessions)
- Live map (Leaflet + OpenStreetMap, browser GPS)
- Listings API (create, open/close, remove)
- Parking sessions with double-booking protection
- Payments: Stripe Checkout, activated by adding a Stripe key. Without a key,
  payments run in simulated mode so the app is fully testable for free.
- SQLite database (zero setup; swap for Postgres before real scale)

## Run it locally
1. Install Node.js 18+
2. `npm install`
3. `cp .env.example .env` and set JWT_SECRET to any long random string
4. `npm start`
5. Open http://localhost:3000 on two phones/browsers to see the live shared map

## Deploy (cheapest path)
- Render.com or Railway.app: create a Web Service from this folder,
  set the env vars from .env.example, done. Both have free tiers.
- Add a Stripe account and paste the secret key to turn on real payments.

## Before a real public launch (for your developer)
- Swap SQLite for Postgres (one connection-string change plus driver)
- Add Stripe Connect so hosts get paid out automatically (currently the
  checkout charges the driver; payouts to hosts are the next step)
- Add photo upload for listings, reviews, and identity verification
- Add push notifications ("your spot was just taken")
- Wrap as mobile apps with Capacitor if app-store presence is needed;
  the web app already works well on phones as-is
- Check local rules: some cities regulate paid driveway rental
