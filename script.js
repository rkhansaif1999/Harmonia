// =========================
// HARMONIA CORE SYSTEM (FIXED + COMPLETE)
// =========================

// The ONLY thing this site keeps in the browser's storage is the
// logged-in user's own session (their info + session token), so the
// page can stay logged in on refresh. That is normal and safe — every
// website does this. Everything else (users, orders, earnings,
// settings) now lives only in your real database (D1) and is always
// fetched fresh from the Worker API, never guessed from local data.
const KEYS = {
    USER: "harmonia_user"
};

// =========================
// SECURITY: ESCAPE USER-PROVIDED TEXT BEFORE INSERTING INTO innerHTML
// Prevents stored XSS (e.g. someone signing up with a name like
// <img src=x onerror=alert(1)> and it executing on an admin's screen)
// =========================
function escapeHTML(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
// =========================
// UI HELPER: MONEY FORMATTING
// Normal amounts show 2 decimals. Sub-cent amounts (e.g. $0.003 per
// micro-task) expand to up to 4 decimals instead of rounding to "$0.00".
// =========================
function formatMoney(amount) {
    const n = Number(amount) || 0;
    if (n === 0) return "$0.00";
    if (Math.abs(n) >= 0.01) return "$" + n.toFixed(2);
    return "$" + n.toFixed(4).replace(/0+$/, "").replace(/\.$/, "");
}

// =========================
// SECURITY: BASIC LOGIN RATE LIMITING
// Locks an email out for 5 minutes after 5 failed attempts
// =========================
const LOGIN_ATTEMPTS_KEY = "harmonia_login_attempts";

function getLoginAttempts() {
    return JSON.parse(localStorage.getItem(LOGIN_ATTEMPTS_KEY)) || {};
}

function isLockedOut(email) {
    const attempts = getLoginAttempts();
    const record = attempts[email];

    if (!record) return false;

    if (record.count >= 5 && Date.now() - record.lastAttempt < 5 * 60 * 1000) {
        return true;
    }

    if (Date.now() - record.lastAttempt >= 5 * 60 * 1000) {
        delete attempts[email];
        localStorage.setItem(LOGIN_ATTEMPTS_KEY, JSON.stringify(attempts));
    }

    return false;
}

function recordFailedAttempt(email) {
    const attempts = getLoginAttempts();
    const record = attempts[email] || { count: 0, lastAttempt: 0 };

    record.count++;
    record.lastAttempt = Date.now();
    attempts[email] = record;

    localStorage.setItem(LOGIN_ATTEMPTS_KEY, JSON.stringify(attempts));
}

function clearLoginAttempts(email) {
    const attempts = getLoginAttempts();
    delete attempts[email];
    localStorage.setItem(LOGIN_ATTEMPTS_KEY, JSON.stringify(attempts));
}

// =========================
// SETTINGS FALLBACK
// The real settings always come from the Worker API
// (GET /api/settings or /api/admin/settings). This function is only
// used as a last-resort default value on the rare old record that
// might be missing a price — it is a fixed constant, not something
// read from or written to local storage.
// =========================
function getSettings() {
    return {
        platformName: "Harmonia",
        pricePerReview: 3,
        autoApproval: "enabled",
        supportEmail: "",
        reviewerEnabled: true,
        reviewerSharePercent: 20
    };
}

// =========================
// UI HELPER: STATUS BADGE
// Wraps a status string in the premium pill styling used
// across every dashboard table (defined in style.css).
// =========================
function statusBadge(status) {
    if (!status) return "";
    const key = String(status).toLowerCase().replace(/[^a-z]/g, "");
    return `<span class="status status-${key}">${escapeHTML(status)}</span>`;
}

// =========================
// SESSION
// The server is the ONLY source of truth for whether you're still
// logged in. It already enforces a real 1-hour "sliding" session:
// every action you take resets the clock to another hour from now,
// and it only truly expires after an hour of no activity - not a
// fixed timer that starts at login. This just keeps the browser
// asking the server, instead of guessing with its own local clock.
// =========================

function saveUser(user, token) {
    const session = { ...user, token: token || null };
    localStorage.setItem(KEYS.USER, JSON.stringify(session));
}

// Wraps fetch() and automatically attaches the logged-in user's
// session token as a Bearer header. Use this for any call to a
// protected /api/... route instead of calling fetch() directly.
let sessionExpiredHandled = false;

async function authFetch(url, options = {}) {
    const user = getUser();
    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {}),
        ...(user?.token ? { "Authorization": "Bearer " + user.token } : {})
    };

    // Guard against a hung request (dead endpoint, network stall, etc.)
    // leaving the caller's UI stuck on a loading state forever.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000);

    let response;
    try {
        response = await fetch(url, { ...options, headers, signal: controller.signal });
    } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === "AbortError") {
            throw new Error("Request timed out. Please check your connection and try again.");
        }
        throw err;
    }
    clearTimeout(timeoutId);

    // If the token is genuinely expired/invalid, the server already
// tells us via 401 on this same call - no need for a separate
// "is my session still good?" ping before every page even loads.
if (response.status === 401 && user?.token && !sessionExpiredHandled) {
    sessionExpiredHandled = true;
    alert("Your session has expired. Please log in again.");
    logout();
}

// 403 means the user is logged in successfully but doesn't have
// permission for this specific API. Keep the session alive.
if (response.status === 403) {
    console.warn("Permission denied.");

    try {
        const data = await response.clone().json();

        if (data?.error) {
            console.warn(data.error);
        }
    } catch (e) {}

    return response;
}

return response;
}

function getUser() {
    try {
        return JSON.parse(localStorage.getItem(KEYS.USER));
    } catch {
        return null;
    }
}

function logout() {
    localStorage.removeItem(KEYS.USER);
    window.location.href = "login.html";
}

// Asks the server whether this session token is still valid. This is
// what actually decides "are you still logged in" - not a local timer.
// If the server confirms it's valid, it also refreshes the locally
// cached copy (in case an admin changed this account's role/status).
async function verifySessionWithServer() {
    const user = getUser();
    if (!user?.token) return false;

    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 10000); // 10 s max
        let response;
        try {
            response = await fetch(WORKER_URL + "/api/session/verify", {
                headers: { "Authorization": "Bearer " + user.token },
                signal: controller.signal
            });
        } finally {
            clearTimeout(timer);
        }

        if (!response.ok) return false;

        const data = await response.json();
        saveUser(data.user, user.token);
        return true;

    } catch (err) {
        console.error("Session check failed (network issue):", err);
        // Don't force a logout just because of a temporary network
        // hiccup - only a real "invalid/expired" answer logs you out.
        return true;
    }
}

const WORKER_URL = "https://round-tree-9996.rkhansaif1999.workers.dev";

async function loginUser(event) {
    event.preventDefault();

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    const role = document.getElementById("role").value;

    if (!role) {
        alert("Please choose an account type.");
        return;
    }

    const MAX_ATTEMPTS = 2;
    const TIMEOUT_MS   = 15000;

    async function attemptLogin() {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
        try {
            const res = await fetch(WORKER_URL + "/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json", "Accept": "application/json" },
                body: JSON.stringify({ email, password }),
                signal: controller.signal
            });
            clearTimeout(timer);
            return res;
        } catch (err) {
            clearTimeout(timer);
            throw err;
        }
    }

    try {
        let response;
        let lastErr;

        for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                if (attempt > 1) await new Promise(r => setTimeout(r, 1500));
                response = await attemptLogin();
                lastErr = null;
                break;
            } catch (err) {
                lastErr = err;
                console.warn(`Login attempt ${attempt} failed:`, err.name, err.message);
            }
        }

        if (lastErr) {
            const msg = lastErr.name === "AbortError"
                ? "The server took too long to respond. Please check your connection and try again."
                : "Unable to connect to the server. Please check your connection and try again.";
            alert(msg);
            console.error("Login failed after retries:", lastErr);
            return;
        }

        let data;
        try {
            data = await response.json();
        } catch (e) {
            alert("Server returned an invalid response. Please try again.");
            console.error("Invalid JSON from /api/login (status " + response.status + "):", e);
            return;
        }

        if (!response.ok) {
            alert(data?.error || "Login failed.");
            return;
        }

        if (!data?.user) {
            alert("Invalid server response (no user data). Please try again.");
            return;
        }

        clearLoginAttempts(email);
        saveUser(data.user, data.token);

        switch (data.user.role) {
            case "admin":    window.location.href = "admin-dashboard.html";    break;
            case "core_team":window.location.href = "admin-dashboard.html";    break;
            case "client":   window.location.href = "client-dashboard.html";   break;
            case "worker":   window.location.href = "worker-dashboard.html";   break;
            case "reviewer": window.location.href = "reviewer-dashboard.html"; break;
            default:         alert("Unknown account role.");
        }

    } catch (err) {
        alert("An unexpected error occurred. Please try again.");
        console.error("Unexpected login error:", err);
    }
}

// =========================
// NOTE: signupUser() is defined per-page (see signup.html), because it
// drives the on-page email-verification step. An older, insecure
// duplicate (unhashed password, no verification) used to live here and
// was silently overridden by that page's version — removed for clarity
// and so it can never accidentally run on a page that doesn't override it.
// =========================

// NOTE: forgot-password.html and reset-password.html each define their
// own real requestPasswordReset()/resetPassword()/resendResetCode()
// functions that call the real Worker API (/api/forgot-password,
// /api/reset-password, /api/reset-password/resend-code). The old
// mock, local-storage versions that used to live here have been removed.

// =========================
// PAGE PROTECTION
//
// SECURITY NOTE: this check (and everything else in this file) is
// client-side JavaScript. It stops a real browser from *rendering*
// a dashboard for someone who isn't logged in - it cannot stop a
// direct HTTP fetch (curl, a scraper, "view source") from downloading
// the raw HTML of a protected page, because that request never runs
// this script at all. Every gated page's <head> hides its content
// (visibility:hidden) until this function proves the session is
// real, and every gated page's <html> also carries
// <meta name="robots" content="noindex"> plus a robots.txt Disallow
// entry, so at least these pages won't be crawled or shown in search
// results. True protection against direct fetching would require a
// server-side check (e.g. a Cloudflare Pages Function / edge
// middleware verifying a real session cookie before the HTML is even
// returned) - that's a hosting-level change, not something JS running
// inside the page itself can guarantee.
// =========================
// "core_team" is an admin-tier role restricted to a subset of admin
// tabs (see options.permission below) - but it also keeps full worker
// access (tasks, unified earnings, payouts, etc.), so being made Core
// Team never takes anything away from someone who was already working
// as a Worker. This helper is what lets one call to protectPage(role)
// admit core_team on both "admin" pages and "worker" pages.
function roleSatisfies(requiredRole, actualRole) {
    if (!requiredRole) return true;
    if (requiredRole === "admin") return actualRole === "admin" || actualRole === "core_team";
    if (requiredRole === "worker") return actualRole === "worker" || actualRole === "core_team";
    return actualRole === requiredRole;
}

async function protectPage(role, options = {}) {
    const user = getUser();

    if (!user || !user.token) {
        window.location.href = "login.html";
        return;
    }

    // Never trust the locally cached role.
// The server is the source of truth.
// We intentionally DO NOT logout here.
// We'll verify everything with the server below.

    // The local copy (localStorage) is just a cache and can be forged
    // by anyone with devtools open. Before revealing this page's
    // content, ask the server - the actual source of truth - whether
    // this token is really valid and really belongs to this role.
    const ok = await verifySessionWithServer();

if (!ok) {
    logout();
    return;
}

const verifiedUser = getUser();

if (!verifiedUser) {
    logout();
    return;
}

if (role && !roleSatisfies(role, verifiedUser.role)) {

    alert("Access denied.");

    if (verifiedUser.role === "admin") {
        window.location.href = "admin-dashboard.html";
        return;
    }

    if (verifiedUser.role === "core_team") {

        if (role === "admin") {
            window.location.href = "admin-dashboard.html";
            return;
        }

        if (role === "worker") {
            window.location.href = "worker-dashboard.html";
            return;
        }
    }

    if (verifiedUser.role === "worker") {
        window.location.href = "worker-dashboard.html";
        return;
    }

    if (verifiedUser.role === "client") {
        window.location.href = "client-dashboard.html";
        return;
    }

    if (verifiedUser.role === "reviewer") {
        window.location.href = "reviewer-dashboard.html";
        return;
    }

    logout();
    return;
}

    // Core Team: on an admin page, gate it behind the tab permission it
    // was called with (skip the check for "dashboard" - that overview
    // page is always reachable as their landing page). On ANY page
    // (admin or worker), reveal/hide the sidebar links and controls
    // that depend on being Core Team specifically.
    if (verifiedUser.role === "core_team") {
        const perms = verifiedUser.permissions || [];
        if (role === "admin" && options.permission && options.permission !== "dashboard" && !perms.includes(options.permission)) {
            alert("You don't have permission to access this page.");
            window.location.href = "admin-dashboard.html";
            return;
        }
        applyCoreTeamRestrictions(perms);
    }

    // Only now do we know this is a real, currently-valid session for
    // the right role - safe to show the page.
    document.body.style.visibility = "visible";
}

// Hides any element tagged data-permission="X" that a logged-in Core
// Team member hasn't been granted, and anything tagged data-admin-only
// (controls reserved for a real admin, e.g. granting Core Team access
// itself). Call this after rendering dynamic content too, if that
// content adds its own data-permission/data-admin-only elements.
function applyCoreTeamRestrictions(perms) {
    document.querySelectorAll("[data-permission]").forEach((el) => {
        if (!perms.includes(el.getAttribute("data-permission"))) el.style.display = "none";
    });
    document.querySelectorAll("[data-admin-only]").forEach((el) => {
        el.style.display = "none";
    });
    // Links to the Worker side (My Tasks, My Earnings) are hidden by
    // default in the admin sidebar markup - only a Core Team member
    // needs them there, since a full admin doesn't have a worker account.
    document.querySelectorAll("[data-core-team-only]").forEach((el) => {
        el.style.display = "";
    });
}

// =========================
// CONTACT / SUPPORT MESSAGES (Cloudflare Worker)
// =========================

async function getContactMessages() {

    try {

       const response = await authFetch(
            WORKER_URL + "/api/admin/contact-messages"
        );

        if (!response.ok) {
            throw new Error("Unable to fetch messages.");
        }

        return await response.json();

    } catch (err) {

        console.error(err);

        return { messages: [] };

    }

}

async function submitContactMessage(msg) {

    try {

        const response = await fetch(
            WORKER_URL + "/api/contact",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(msg)
            }
        );

        return await response.json();

    } catch (err) {

        console.error(err);

        return {
            error: "Unable to submit contact message."
        };

    }

}

// Worker "Contact Support" — a real back-and-forth chat between a
// logged-in worker and admin, instead of a one-way email. Messages
// live in the worker_support_chats table (one row per worker) and
// are fetched/appended over the API. Identity comes from the
// worker's session, not a typed-in name/email.
async function submitWorkerSupportMessage(message) {

    try {

        const response = await authFetch(
            WORKER_URL + "/api/worker/support/send",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ message })
            }
        );

        return await response.json();

    } catch (err) {

        console.error(err);

        return {
            error: "Unable to send message."
        };

    }

}

// GET the logged-in worker's own support chat with admin.
async function fetchWorkerSupportChat() {
    try {
        const response = await authFetch(WORKER_URL + "/api/worker/support");
        return await response.json();
    } catch (err) {
        console.error(err);
        return { error: "Unable to load conversation." };
    }
}

// [ADMIN] List every worker who has a support chat (with last message
// preview + unread flag), newest activity first.
async function fetchAdminWorkerSupportChats() {
    try {
        const response = await authFetch(WORKER_URL + "/api/admin/worker-support");
        return await response.json();
    } catch (err) {
        console.error(err);
        return { error: "Unable to load worker support chats." };
    }
}

// [ADMIN] Full message history for one worker's support chat.
async function fetchAdminWorkerSupportDetail(userId) {
    try {
        const response = await authFetch(WORKER_URL + "/api/admin/worker-support/detail?userId=" + userId);
        return await response.json();
    } catch (err) {
        console.error(err);
        return { error: "Unable to load conversation." };
    }
}

// [ADMIN] Reply in a specific worker's support chat.
async function replyAdminWorkerSupport(userId, message) {
    try {
        const response = await authFetch(WORKER_URL + "/api/admin/worker-support/reply", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ userId, message })
        });
        return await response.json();
    } catch (err) {
        console.error(err);
        return { error: "Unable to send reply." };
    }
}

async function replyToMessage(id, message) {

    try {

       const response = await authFetch(
            WORKER_URL + "/api/admin/contact-messages/reply",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    id,
                    message
                })
            }
        );

        return await response.json();

    } catch (err) {

        console.error(err);

        return {
            error: "Unable to send reply."
        };

    }

}

async function deleteMessage(id) {

    try {

       const response = await authFetch(
            WORKER_URL + "/api/admin/contact-messages/delete",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    id
                })
            }
        );

        return await response.json();

    } catch (err) {

        console.error(err);

        return {
            error: "Unable to delete message."
        };

    }

}
async function sendAnnouncement(audience, subject, message) {

    let response;

    try {
        response = await authFetch(
            WORKER_URL + "/api/admin/announcements/send",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ audience, subject, message })
            }
        );
    } catch (err) {
        // True network failure — couldn't reach the server at all.
        console.error(err);
        return { error: "Unable to connect to the server." };
    }

    try {
        return await response.json();
    } catch (parseErr) {
        // The server returned a non-JSON body. This almost always means
        // Cloudflare's 524 timeout — the Worker was still sending emails
        // when the 30-second wall-clock limit hit. The emails that were
        // sent before the timeout are already delivered. Returning a
        // special flag so the UI can show an amber "still sending"
        // message instead of a misleading red error.
        console.warn("Announcement response not JSON (likely Cloudflare 524 timeout). Emails already sent are delivered.", parseErr);
        return { _timedOut: true };
    }

}
async function updateEmailPermission(id, allowed) {
    const response = await authFetch(WORKER_URL + "/api/admin/users/email-permission", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, allowed })
    });
    const data = await response.json();
    if (!response.ok) {
        alert(data.error || "Failed to update permission.");
        return false;
    }
    return true;
}

async function startWorkerThread(companyEmail, subject, message) {
    try {
        const response = await authFetch(WORKER_URL + "/api/worker/threads/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ companyEmail, subject, message })
        });
        return await response.json();
    } catch (err) {
        console.error(err);
        return { error: "Unable to send email." };
    }
}

async function replyWorkerThread(threadId, message) {
    try {
        const response = await authFetch(WORKER_URL + "/api/worker/threads/reply", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ threadId, message })
        });
        return await response.json();
    } catch (err) {
        console.error(err);
        return { error: "Unable to send reply." };
    }
}

async function fetchWorkerThreads() {
    const response = await authFetch(WORKER_URL + "/api/worker/threads");
    return await response.json();
}

async function fetchWorkerThreadDetail(threadId) {
    const response = await authFetch(WORKER_URL + "/api/worker/threads/detail?threadId=" + threadId);
    return await response.json();
}

async function fetchAdminThreads() {
    const response = await authFetch(WORKER_URL + "/api/admin/worker-threads");
    return await response.json();
}

async function fetchAdminThreadDetail(threadId) {
    const response = await authFetch(WORKER_URL + "/api/admin/worker-threads/detail?threadId=" + threadId);
    return await response.json();
}

async function replyAdminThread(threadId, message) {
    const response = await authFetch(WORKER_URL + "/api/admin/worker-threads/reply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threadId, message })
    });
    return await response.json();
}

async function deleteAdminThread(threadId) {
    try {
        const response = await authFetch(WORKER_URL + "/api/admin/worker-threads/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ threadId })
        });
        return await response.json();
    } catch (err) {
        console.error(err);
        return { error: "Unable to delete conversation." };
    }
}

async function deleteWorkerThread(threadId) {
    try {
        const response = await authFetch(WORKER_URL + "/api/worker/threads/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ threadId })
        });
        return await response.json();
    } catch (err) {
        console.error(err);
        return { error: "Unable to delete conversation." };
    }
}

async function sendDirectEmail(to, subject, message) {
    try {
        const response = await authFetch(
            WORKER_URL + "/api/admin/send-email",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ to, subject, message })
            }
        );
        return await response.json();
    } catch (err) {
        console.error(err);
        return {
            error: "Unable to send email."
        };
    }
}
// =========================
// GLOBAL NAV — public marketing navbar (mobile menu + active link)
// Applies automatically to any page with .navbar/.nav-links
// (index, pricing, contact). Fixes the old rule that just hid every
// link except the last one on mobile with no way to reach them.
// =========================
function setupPublicNav() {
    const nav = document.querySelector(".navbar");
    if (!nav) return;

    const links = nav.querySelector(".nav-links");
    if (!links || nav.querySelector(".navbar-toggle")) return;

    const current = window.location.pathname.split("/").pop() || "index.html";
    links.querySelectorAll("a").forEach(a => {
        if (a.getAttribute("href") === current) a.classList.add("current");
    });

    const toggle = document.createElement("button");
    toggle.className = "navbar-toggle";
    toggle.type = "button";
    toggle.setAttribute("aria-label", "Toggle navigation");
    toggle.innerHTML = "☰";
    nav.appendChild(toggle);

    toggle.addEventListener("click", () => {
        const open = links.classList.toggle("mobile-open");
        toggle.innerHTML = open ? "✕" : "☰";
    });

    links.querySelectorAll("a").forEach(a => {
        a.addEventListener("click", () => {
            links.classList.remove("mobile-open");
            toggle.innerHTML = "☰";
        });
    });
}

// =========================
// GLOBAL NAV — dashboard topbar chrome
// Adds a breadcrumb, page search, notification bell, and a real
// profile dropdown (name/role/logout) to every .topbar, on every
// portal page, without needing to hand-edit each dashboard file.
// =========================
async function fetchNotifications(user) {
    if (!user) return [];
    const notifications = [];

    try {
        if (user.role === "worker" || user.role === "core_team") {
            // Unread support messages from admin
            const chatRes = await authFetch(WORKER_URL + "/api/worker/support");
            if (chatRes.ok) {
                const chatData = await chatRes.json();
                const messages = chatData.messages || [];
                const unreadAdminMessages = messages.filter(m => m.sender === "admin");
                // Count messages after the last worker message
                let lastWorkerIdx = -1;
                messages.forEach((m, i) => { if (m.sender === "worker") lastWorkerIdx = i; });
                const unreadCount = messages.slice(lastWorkerIdx + 1).filter(m => m.sender === "admin").length;
                if (unreadCount > 0) {
                    notifications.push({
                        icon: "💬",
                        text: `You have ${unreadCount} new message${unreadCount > 1 ? "s" : ""} from Support`,
                        link: "worker-dashboard.html#messages"
                    });
                }
            }

            // New tasks assigned
            const tasksRes = await authFetch(WORKER_URL + "/api/worker/tasks");
            if (tasksRes.ok) {
                const tasksData = await tasksRes.json();
                const assigned = (tasksData.tasks || []).filter(t => t.status === "Assigned");
                if (assigned.length > 0) {
                    notifications.push({
                        icon: "📋",
                        text: `You have ${assigned.length} new task${assigned.length > 1 ? "s" : ""} assigned`,
                        link: "worker-dashboard.html#tasks"
                    });
                }
                const needsRevision = (tasksData.tasks || []).filter(t => t.status === "Needs Revision");
                if (needsRevision.length > 0) {
                    notifications.push({
                        icon: "⚠️",
                        text: `${needsRevision.length} task${needsRevision.length > 1 ? "s need" : " needs"} revision`,
                        link: "worker-dashboard.html#tasks"
                    });
                }
            }

            // Pending micro-task applications
            const microRes = await authFetch(WORKER_URL + "/api/worker/micro-tasks");
            if (microRes.ok) {
                const microData = await microRes.json();
                const approvedTasks = (microData.tasks || []).filter(t => t.applicationStatus === "approved");
                if (approvedTasks.length > 0) {
                    notifications.push({
                        icon: "✅",
                        text: `${approvedTasks.length} micro task${approvedTasks.length > 1 ? "s" : ""} approved — ready to work`,
                        link: "worker-dashboard.html#tasks"
                    });
                }
            }
        }

        if (user.role === "client") {
            const ordersRes = await authFetch(WORKER_URL + "/api/orders");
            if (ordersRes.ok) {
                const ordersData = await ordersRes.json();
                const orders = ordersData.orders || [];

                const completed = orders.filter(o => o.status === "Completed");
                if (completed.length > 0) {
                    notifications.push({
                        icon: "🎉",
                        text: `${completed.length} project${completed.length > 1 ? "s" : ""} completed`,
                        link: "client-dashboard.html"
                    });
                }

                const needsPayment = orders.filter(o => o.status === "Awaiting Payment");
                if (needsPayment.length > 0) {
                    notifications.push({
                        icon: "💳",
                        text: `${needsPayment.length} order${needsPayment.length > 1 ? "s" : ""} awaiting payment`,
                        link: "client-dashboard.html"
                    });
                }

                // Admin replies in support chat
                orders.forEach(o => {
                    const chat = o.supportChat || [];
                    if (chat.length > 0 && chat[chat.length - 1].sender === "admin") {
                        notifications.push({
                            icon: "💬",
                            text: `New reply on project "${o.project_name}"`,
                            link: "client-dashboard.html"
                        });
                    }
                });
            }
        }

        if (user.role === "reviewer") {
            const queueRes = await authFetch(WORKER_URL + "/api/reviewer/queue");
            if (queueRes.ok) {
                const queueData = await queueRes.json();
                const pending = (queueData.queue || []).length;
                if (pending > 0) {
                    notifications.push({
                        icon: "🔍",
                        text: `${pending} order${pending > 1 ? "s" : ""} waiting for review`,
                        link: "reviewer-dashboard.html"
                    });
                }
            }
        }

        if (user.role === "admin" || user.role === "core_team") {
            // Pending payment approvals
            const ordersRes = await authFetch(WORKER_URL + "/api/admin/orders");
            if (ordersRes.ok) {
                const ordersData = await ordersRes.json();
                const underReview = (ordersData.orders || []).filter(o => o.status === "Under Review");
                if (underReview.length > 0) {
                    notifications.push({
                        icon: "💳",
                        text: `${underReview.length} payment${underReview.length > 1 ? "s" : ""} awaiting approval`,
                        link: "admin-projects.html"
                    });
                }
            }

            // Unread worker support messages
            const supportRes = await authFetch(WORKER_URL + "/api/admin/worker-support");
            if (supportRes.ok) {
                const supportData = await supportRes.json();
                const unread = (supportData.chats || []).filter(c => c.admin_unread).length;
                if (unread > 0) {
                    notifications.push({
                        icon: "💬",
                        text: `${unread} unread worker support message${unread > 1 ? "s" : ""}`,
                        link: "admin-messages.html"
                    });
                }
            }

            // Unread contact messages
            const contactRes = await authFetch(WORKER_URL + "/api/admin/contact-messages");
            if (contactRes.ok) {
                const contactData = await contactRes.json();
                const unreadContact = (contactData.messages || []).filter(m => m.status === "unread").length;
                if (unreadContact > 0) {
                    notifications.push({
                        icon: "📩",
                        text: `${unreadContact} unread contact message${unreadContact > 1 ? "s" : ""}`,
                        link: "admin-messages.html"
                    });
                }
            }

            // Pending user approvals (if auto-approval is off)
            const usersRes = await authFetch(WORKER_URL + "/api/admin/users");
            if (usersRes.ok) {
                const usersData = await usersRes.json();
                const pendingUsers = (usersData.users || []).filter(u => u.status === "pending").length;
                if (pendingUsers > 0) {
                    notifications.push({
                        icon: "👤",
                        text: `${pendingUsers} user${pendingUsers > 1 ? "s" : ""} pending approval`,
                        link: "admin-workers.html"
                    });
                }
            }

            // Pending task applications
            const appsRes = await authFetch(WORKER_URL + "/api/admin/task-applications");
            if (appsRes.ok) {
                const appsData = await appsRes.json();
                const pendingApps = (appsData.applications || []).filter(a => a.status === "pending").length;
                if (pendingApps > 0) {
                    notifications.push({
                        icon: "📋",
                        text: `${pendingApps} task application${pendingApps > 1 ? "s" : ""} pending`,
                        link: "admin-tasks.html"
                    });
                }
            }
        }

    } catch (err) {
        console.warn("Notification fetch error:", err);
    }

    return notifications;
}

function enhanceTopbar() {
    const topbar = document.querySelector(".topbar");
    if (!topbar || topbar.dataset.enhanced) return;
    topbar.dataset.enhanced = "true";

    const user = getUser();
    const h1 = topbar.querySelector("h1");
    const oldProfile = topbar.querySelector(".profile");

    // ---- breadcrumb + title ----
    if (h1 && !h1.closest(".topbar-left")) {
        const left = document.createElement("div");
        left.className = "topbar-left";

        const crumb = document.createElement("div");
        crumb.className = "breadcrumb";
        const portalName = user
            ? user.role.charAt(0).toUpperCase() + user.role.slice(1) + " Portal"
            : "Harmonia";
        const pageName = h1.textContent.replace(/[^\w\s]/g, "").trim();
        crumb.innerHTML = `${escapeHTML(portalName)} <span>/ ${escapeHTML(pageName)}</span>`;

        h1.parentNode.insertBefore(left, h1);
        left.appendChild(crumb);
        left.appendChild(h1);
    }

    // ---- right cluster: search + notifications + profile ----
    const right = document.createElement("div");
    right.className = "topbar-right";

    // Pages that carry a header ad banner (see e.g. admin-dashboard.html)
    // skip the page-search box so the ad has room and nothing overlaps it.
    const hasAdBanner = !!topbar.querySelector(".adsterra-header-banners");

    let searchWrap = null;
    if (!hasAdBanner) {
        searchWrap = document.createElement("div");
        searchWrap.className = "topbar-search";
        searchWrap.innerHTML = `🔍 <input type="text" id="topbarSearch" placeholder="Search this page...">`;
        right.appendChild(searchWrap);
    }

    const notifWrap = document.createElement("div");
    notifWrap.className = "notif-wrap";
    // Render bell immediately with a loading state, then populate async
    notifWrap.innerHTML = `
        <button class="notif-bell" type="button" aria-label="Notifications">
            🔔
        </button>
        <div class="notif-dropdown">
            <div class="notif-dropdown-title">Notifications</div>
            <div class="notif-empty">Loading...</div>
        </div>
    `;
    right.appendChild(notifWrap);

    // Fetch notifications in the background and update the bell once ready
    fetchNotifications(user).then(notifications => {
        const bellBtn = notifWrap.querySelector(".notif-bell");
        const dropdown = notifWrap.querySelector(".notif-dropdown");

        // Update badge
        const existingBadge = bellBtn.querySelector(".notif-badge");
        if (existingBadge) existingBadge.remove();
        if (notifications.length) {
            const badge = document.createElement("span");
            badge.className = "notif-badge";
            badge.textContent = notifications.length;
            bellBtn.appendChild(badge);
        }

        // Update dropdown content
        dropdown.innerHTML = `
            <div class="notif-dropdown-title">Notifications</div>
            ${
                notifications.length
                    ? notifications.map(n =>
                        `<a class="notif-item" href="${escapeHTML(n.link || "#")}">
                            <span>${n.icon}</span>
                            <span>${escapeHTML(n.text)}</span>
                        </a>`
                      ).join("")
                    : `<div class="notif-empty">You're all caught up 🎉</div>`
            }
        `;
    });

    const profileWrap = document.createElement("div");
    profileWrap.className = "profile-wrap";

    // Settings destination depends on role - only admin has a real
    // settings page today. Other roles will get one later; until then
    // just don't render a dead link for them.
    const SETTINGS_URL_BY_ROLE = {
        admin: "admin-settings.html",
    };

    // Roles that get a "Contact Support" item in the profile dropdown.
    // Currently just workers (worker-support.html) - the sidebar link
    // was removed from all worker-*.html pages and moved in here.
    const SUPPORT_URL_BY_ROLE = {
        worker: "worker-dashboard.html#messages",
    };

    if (user) {
        const initials = (user.fullName || user.role || "U")
            .trim().split(/\s+/).map(w => w[0]).slice(0, 2).join("").toUpperCase();

        const settingsUrl = SETTINGS_URL_BY_ROLE[user.role];
        const settingsLink = settingsUrl
            ? `<a href="${settingsUrl}">⚙ Settings</a>`
            : "";

        const supportUrl = SUPPORT_URL_BY_ROLE[user.role];
        const supportLink = supportUrl
            ? `<a href="${supportUrl}">🎧 Contact Support</a>`
            : "";

        profileWrap.innerHTML = `
            <button class="profile-btn" type="button">
                <span class="profile-avatar">${escapeHTML(initials)}</span>
                <span class="profile-name">${escapeHTML(user.fullName || "Account")}<small>${escapeHTML(user.role)}</small></span>
            </button>
            <div class="profile-menu">
                ${settingsLink}
                ${settingsLink ? "<hr>" : ""}
                ${supportLink}
                ${supportLink ? "<hr>" : ""}
                <button type="button" class="menu-item" onclick="logout()">🚪 Logout</button>
            </div>
        `;
    } else if (oldProfile) {
        profileWrap.innerHTML = `<button class="profile-btn" type="button"><span class="profile-name">${oldProfile.innerHTML}</span></button>`;
    }
    right.appendChild(profileWrap);

    if (oldProfile) oldProfile.remove();
    topbar.appendChild(right);

    // ---- wire dropdown open/close ----
    const bellBtn = notifWrap.querySelector(".notif-bell");
    const notifDropdown = notifWrap.querySelector(".notif-dropdown");
    const profileBtn = profileWrap.querySelector(".profile-btn");
    const profileMenu = profileWrap.querySelector(".profile-menu");

    function closeAll(except) {
        if (notifDropdown && notifDropdown !== except) notifDropdown.classList.remove("open");
        if (profileMenu && profileMenu !== except) profileMenu.classList.remove("open");
    }

    if (bellBtn && notifDropdown) {
        bellBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            const willOpen = !notifDropdown.classList.contains("open");
            closeAll();
            if (willOpen) notifDropdown.classList.add("open");
        });
    }

    if (profileBtn && profileMenu) {
        profileBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            const willOpen = !profileMenu.classList.contains("open");
            closeAll();
            if (willOpen) profileMenu.classList.add("open");
        });
    }

    document.addEventListener("click", () => closeAll());

    // ---- live search across this page's main table, if any ----
    const searchInput = searchWrap ? searchWrap.querySelector("input") : null;
    const table = document.querySelector(".recent table, .main table");

    if (searchInput && table) {
        searchInput.addEventListener("input", () => {
            const term = searchInput.value.trim().toLowerCase();
            table.querySelectorAll("tbody tr").forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(term) ? "" : "none";
            });
        });
    } else if (searchInput) {
        searchWrap.style.display = "none"; // nothing on this page to search
    }
}

// =========================
// PREMIUM UI LAYER
// (visual-only enhancements — no business logic here)
// =========================

document.addEventListener("DOMContentLoaded", () => {

    setupPublicNav();
    enhanceTopbar();

    // ---- Noise overlay + ambient glow are handled purely in CSS ----

    // ---- Scroll-reveal for cards/panels on any page ----
    const revealTargets = document.querySelectorAll(
        ".card, .dashboard-card, .price-card, .recent, .auth-box, .login-box"
    );

    revealTargets.forEach(el => el.classList.add("reveal"));

    if ("IntersectionObserver" in window) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add("in-view");
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.12 });

        revealTargets.forEach(el => observer.observe(el));
    } else {
        revealTargets.forEach(el => el.classList.add("in-view"));
    }

    // ---- Mobile sidebar toggle (only on dashboard pages) ----
    const sidebar = document.querySelector(".sidebar");

    if (sidebar) {
        const toggle = document.createElement("button");
        toggle.className = "sidebar-toggle";
        toggle.setAttribute("aria-label", "Toggle menu");
        toggle.innerHTML = "☰";

        const backdrop = document.createElement("div");
        backdrop.className = "sidebar-backdrop";

        document.body.appendChild(toggle);
        document.body.appendChild(backdrop);

        function closeSidebar() {
            sidebar.classList.remove("open");
            backdrop.classList.remove("open");
        }

        toggle.addEventListener("click", () => {
            sidebar.classList.toggle("open");
            backdrop.classList.toggle("open");
        });

        backdrop.addEventListener("click", closeSidebar);

        sidebar.querySelectorAll("a").forEach(link => {
            link.addEventListener("click", closeSidebar);
        });
    }

    // ---- Disable stray/unlinked sidebar items instead of leaving them
    // as dead clickable-looking text (real bug fix: several <li> items
    // like "Tasks", "Payments", "Analytics", "Support", "Settings" had
    // no href and no active state, so they looked broken/misaligned) ----
    document.querySelectorAll(".sidebar li").forEach(li => {
        const hasLink = li.querySelector("a");
        const isActive = li.classList.contains("active");

        if (!hasLink && !isActive) {
            li.classList.add("disabled-link");
            li.setAttribute("title", "Coming soon");
        }
    });

});

// =========================
// PASSWORD VISIBILITY TOGGLE
// Used on login.html and signup.html. Toggles a password
// <input>'s type between "password" and "text", and swaps
// which eye icon (open/slashed) is shown inside the button.
// Safe no-ops if the input or icons aren't found.
// =========================
function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input || !btn) return;

    const isCurrentlyHidden = input.type === "password";
    input.type = isCurrentlyHidden ? "text" : "password";

    const eyeIcon = btn.querySelector(".icon-eye");
    const eyeOffIcon = btn.querySelector(".icon-eye-off");

    if (eyeIcon && eyeOffIcon) {
        eyeIcon.style.display = isCurrentlyHidden ? "none" : "block";
        eyeOffIcon.style.display = isCurrentlyHidden ? "block" : "none";
    }

    btn.setAttribute("aria-label", isCurrentlyHidden ? "Hide password" : "Show password");
}
