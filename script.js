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

    const response = await fetch(url, { ...options, headers });

    // If the token is genuinely expired/invalid, the server already
    // tells us via 401 on this same call - no need for a separate
    // "is my session still good?" ping before every page even loads.
    if (response.status === 401 && user?.token && !sessionExpiredHandled) {
        sessionExpiredHandled = true;
        alert("Your session has expired. Please log in again.");
        logout();
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
        const response = await fetch(WORKER_URL + "/api/session/verify", {
            headers: { "Authorization": "Bearer " + user.token }
        });
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

    try {

        const response = await fetch(WORKER_URL + "/api/login", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
    },
    body: JSON.stringify({
        email,
        password
    })
});

let data;

try {
    data = await response.json();
} catch (e) {
    alert("Server returned invalid response");
    console.error("Invalid JSON:", e);
    return;
}

if (!response.ok) {
    alert(data?.error || "Login failed.");
    return;
}

if (!data?.user) {
    alert("Invalid server response (no user data)");
    return;
}

        clearLoginAttempts(email);

       saveUser(data.user, data.token);

        switch (data.user.role) {

            case "admin":
                window.location.href = "admin-dashboard.html";
                break;

            case "client":
                window.location.href = "client-dashboard.html";
                break;

            case "worker":
                window.location.href = "worker-dashboard.html";
                break;

            case "reviewer":
                window.location.href = "reviewer-dashboard.html";
                break;

            default:
                alert("Unknown account role.");
        }

    } catch (err) {

        alert("Unable to connect to the server.");

        console.error(err);

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
// =========================
function protectPage(role) {
    const user = getUser();

    if (!user || !user.token) {
        window.location.href = "login.html";
        return;
    }

    if (role && user.role !== role) {
        alert("Access denied");
        logout();
        return;
    }

    // The page's own data calls (via authFetch) already validate this
    // exact session token server-side, the moment they run - so a
    // separate "is my session still good?" ping here was doing the
    // same check twice, on every single page load, for no benefit.
    // authFetch now handles the "expired" case itself if it ever hits it.
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

    try {

        const response = await authFetch(
            WORKER_URL + "/api/admin/announcements/send",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ audience, subject, message })
            }
        );

        return await response.json();

    } catch (err) {

        console.error(err);

        return {
            error: "Unable to send announcement."
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
function buildNotifications(user) {
    // NOTE: this used to read from a fake local-storage "database" of
    // projects/users/earnings that no longer exists. The real data now
    // lives only in D1, behind the Worker API. Returning an empty list
    // here just turns the bell into "no notifications" for now, rather
    // than showing stale/fake counts. Wiring this up to the real
    // per-role API endpoints (e.g. /api/worker/tasks, /api/reviewer/queue)
    // is a nice future improvement, not a security issue.
    if (!user) return [];
    return [];
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

    const searchWrap = document.createElement("div");
    searchWrap.className = "topbar-search";
    searchWrap.innerHTML = `🔍 <input type="text" id="topbarSearch" placeholder="Search this page...">`;
    right.appendChild(searchWrap);

    const notifWrap = document.createElement("div");
    notifWrap.className = "notif-wrap";
    const notifications = buildNotifications(user);
    notifWrap.innerHTML = `
        <button class="notif-bell" type="button" aria-label="Notifications">
            🔔${notifications.length ? `<span class="notif-badge">${notifications.length}</span>` : ""}
        </button>
        <div class="notif-dropdown">
            <div class="notif-dropdown-title">Notifications</div>
            ${
                notifications.length
                    ? notifications.map(n =>
                        `<div class="notif-item"><span>${n.icon}</span><span>${escapeHTML(n.text)}</span></div>`
                      ).join("")
                    : `<div class="notif-empty">You're all caught up 🎉</div>`
            }
        </div>
    `;
    right.appendChild(notifWrap);

    const profileWrap = document.createElement("div");
    profileWrap.className = "profile-wrap";

    // Settings destination depends on role - only admin has a real
    // settings page today. Other roles will get one later; until then
    // just don't render a dead link for them.
    const SETTINGS_URL_BY_ROLE = {
        admin: "admin-settings.html",
    };

    if (user) {
        const initials = (user.fullName || user.role || "U")
            .trim().split(/\s+/).map(w => w[0]).slice(0, 2).join("").toUpperCase();

        const settingsUrl = SETTINGS_URL_BY_ROLE[user.role];
        const settingsLink = settingsUrl
            ? `<a href="${settingsUrl}">⚙ Settings</a>`
            : "";

        profileWrap.innerHTML = `
            <button class="profile-btn" type="button">
                <span class="profile-avatar">${escapeHTML(initials)}</span>
                <span class="profile-name">${escapeHTML(user.fullName || "Account")}<small>${escapeHTML(user.role)}</small></span>
            </button>
            <div class="profile-menu">
                ${settingsLink}
                ${settingsLink ? "<hr>" : ""}
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
    const searchInput = searchWrap.querySelector("input");
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
