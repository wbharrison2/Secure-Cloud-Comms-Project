# Project 7 — Interact: Artisan Gem Works Demo Website

> **A hands-on demo of the full Artisan Gem Works e-commerce platform, built from the infrastructure and business logic established across Projects 1–6.**

## 🌐 Live Website

| | Link |
|---|---|
| **Storefront** | [https://wbharrison2.github.io/artisan-gem-works/](https://wbharrison2.github.io/artisan-gem-works/) |
| **Admin Portal** | [https://wbharrison2.github.io/artisan-gem-works/admin.html](https://wbharrison2.github.io/artisan-gem-works/admin.html) |
| **GitHub Repo** | [https://github.com/wbharrison2/artisan-gem-works](https://github.com/wbharrison2/artisan-gem-works) |

> No installation needed — click the Storefront link and start shopping.

---

## Projects 1–6 Summary

| # | Repo | Branch | What It Does |
|---|------|--------|-------------|
| **1** | Cloud-Deployment-Project | `demo/project-4-franchise-ha` | Multi-location AWS infrastructure for Artisan Gem Works — 3-tier VPC, EC2 via SSM, S3 artifact storage, IAM least-privilege, and a high-availability architecture for the Portland flagship and Seattle expansion. |
| **2** | Cloud-Deployment-Project | `demo/project-5-franchise-k8s` | Kubernetes upgrade path for the franchise platform — EKS cluster with Helm charts, horizontal pod autoscaling, and a shared product catalog service across both store locations. |
| **3** | Cloud-Migration-Project | `demo/project-1-local-store` | On-premises to AWS migration baseline — Dockerized app stack, Terraform provisioning, initial product database with the Portland store's 20 shared SKUs. |
| **4** | Cloud-Migration-Project | `demo/project-2-cdn-enhanced` | CDN-accelerated storefront — CloudFront distribution, S3 static hosting, and the full 32-product catalog across Portland and Seattle locations with origin failover. |
| **5** | Cloud-Migration-Project | `demo/project-3-secure-local` | Secure local-to-cloud bridge — VPN tunnel, encrypted S3 transfers, and the customer JWT authentication system with TOTP 2FA for admin access. |
| **6** | Secure-Cloud-Comms-Project | `demo/project-6-franchise-zerotrust` | Zero-trust security layer — AWS VPC Peering between Portland and Seattle environments, KMS encryption for all customer data, Secrets Manager credential rotation, and audit logging for compliance. |

---

## Website Summary — Artisan Gem Works

A fully functional e-commerce demo website for **Artisan Gem Works**, a fine handcrafted jewelry company owned by Mira Chen (a Meridian Jewelry Group brand). The site is themed in **Southern Charm** with a **Temu/Shopify-style** shopping interface.

### Business Details

| Field | Value |
|-------|-------|
| **Company** | Artisan Gem Works |
| **Owner** | Mira Chen |
| **Parent** | Meridian Jewelry Group |
| **Email** | shop@artisangemworks.com |
| **Portland Store** | 2847 NW Thurman St, Portland, OR 97210 · (503) 555-0142 |
| **Seattle Store** | 412 Pine St, Seattle, WA 98101 · (206) 555-0178 |

### What's on the Site

- **32 handcrafted jewelry products** ($65–$287) across rings, pendants, earrings, cuffs, bracelets, necklaces, and gift sets
- **Location-exclusive items** — Portland-only and Seattle-only pieces alongside the shared catalog
- **Flash deals** with live countdown timer
- **Full shopping cart** with quantity management
- **Secure checkout** with simulated Stripe payment processing
- **Order tracking** — auto-generated FedEx tracking number with a 7-step delivery timeline
- **Email confirmation** — rendered preview of the order email sent from `shop@artisangemworks.com`
- **Admin dashboard** — full order management, product catalog, customer list, and sales analytics

### Site Files

```
artisan-gem-works/
├── index.html   ← Main storefront (open this in your browser)
├── style.css    ← Southern charm theme
├── data.js      ← All 32 products with pricing
├── app.js       ← Cart, checkout, tracking & email logic
└── admin.html   ← Admin portal
```

---

## Access the Demo

**The site is live online — no download or installation required.**

| | |
|---|---|
| **Storefront** | https://wbharrison2.github.io/artisan-gem-works/ |
| **Admin Portal** | https://wbharrison2.github.io/artisan-gem-works/admin.html |

Just click either link in any browser to get started.

---

## How to Test the Demo

Follow these steps to experience the full purchase flow:

### Step 1 — Browse the Store
1. Open `index.html` in your browser
2. Use the **category chips** at the top to filter by jewelry type (Rings, Pendants, Earrings, etc.)
3. Click any product card to open the **quick-view modal** with full details and pricing

### Step 2 — Add Items to Your Bag
1. Click **"+ Add"** on any product card, or open the product modal and click **"Add to Bag"**
2. A toast notification confirms the item was added
3. Click the **bag icon** (top right) to open your cart drawer

### Step 3 — Checkout
1. In the cart drawer, click **"Checkout"**
2. Fill in any name, email, and shipping address (e.g. `123 Magnolia Lane, Charleston, SC`)
3. For payment, use the **test card:**
   - **Card Number:** `4242 4242 4242 4242`
   - **Expiry:** any future date (e.g. `12/28`)
   - **CVV:** any 3 digits (e.g. `123`)
4. Click **"Place My Order"**

### Step 4 — View Order Confirmation & Tracking
1. After ~2 seconds you land on the **Order Confirmation** page
2. Your order ID (e.g. `AGW-20260611-4821`) and a **FedEx tracking number** are displayed
3. A **7-step delivery timeline** shows your order progressing from *Order Placed* → *Delivered*

### Step 5 — View the Confirmation Email
1. An **email preview modal** pops up automatically after checkout
2. It shows a formatted email from `shop@artisangemworks.com` to your provided address
3. You can reopen it anytime from the confirmation page by clicking **"View Email"**

### Step 6 — Admin Portal
1. Open `admin.html` (or click **"Admin Portal"** in the store footer)
2. Log in with:
   - **Email:** `admin@artisangemworks.com`
   - **Password:** `Admin!2024Secure`
3. From the dashboard you can:
   - View all orders placed during your session
   - Update order status (Processing → Shipped → Delivered)
   - Browse all 32 products
   - See customer list and sales analytics
   - Export orders as CSV

---

## Demo Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | `admin@artisangemworks.com` | `Admin!2024Secure` |
| Customer | `customer@demo.com` | `Customer!2024Demo` |
| Test Card | `4242 4242 4242 4242` | Any future expiry + any CVV |

> Orders and cart data are stored in your browser's `localStorage` and persist between sessions.

---

*Artisan Gem Works · A Meridian Jewelry Group Brand · Crafted with Southern Love*
