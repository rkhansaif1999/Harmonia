// =========================
// HARMONIA CORE SYSTEM (FIXED + COMPLETE)
// =========================

const KEYS = {
    USERS: "harmonia_users",
    USER: "harmonia_user",
    PROJECTS: "harmonia_projects",
    SETTINGS: "harmonia_settings",
    EARNINGS: "harmonia_earnings"
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
// SECURITY: PASSWORD HASHING (SHA-256 via Web Crypto API)
// Note: this is client-side hashing for the current local-storage prototype.
// Once the real backend is connected, passwords will be hashed server-side
// with a proper algorithm (bcrypt/argon2) — this is an interim safeguard
// so plaintext passwords are never sitting in the browser's storage.
// =========================
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
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
// SETTINGS (ADMIN CONTROL PRICING)
// =========================
function getSettings() {
    return JSON.parse(localStorage.getItem(KEYS.SETTINGS)) || {
        platformName: "Harmonia",
        pricePerReview: 3,
        autoApproval: "enabled",
        supportEmail: "",
        reviewerEnabled: true,
        reviewerSharePercent: 20
    };
}

function saveSettings(data) {
    localStorage.setItem(KEYS.SETTINGS, JSON.stringify(data));
}

// =========================
// USERS SYSTEM
// =========================
function getUsers() {
    return JSON.parse(localStorage.getItem(KEYS.USERS)) || [];
}

function saveUsers(users) {
    localStorage.setItem(KEYS.USERS, JSON.stringify(users));
}

// =========================
// SEED DEFAULT ADMIN ACCOUNT (dev/testing only)
// Runs once per browser: if no admin with this email exists yet,
// create it so the site owner can log in immediately without
// going through the console. Safe to remove once a real backend
// and proper admin invite flow is in place.
// =========================
(async function seedDefaultAdmin() {
    const ADMIN_EMAIL = "rkhansaif1999@gmail.com";
    const ADMIN_PASSWORD = "Abc123.,?121";

    const users = getUsers();

    if (users.find(u => u.email === ADMIN_EMAIL)) return;

    const hashed = await hashPassword(ADMIN_PASSWORD);

    users.push({
        id: Date.now(),
        fullName: "Admin",
        email: ADMIN_EMAIL,
        password: hashed,
        role: "admin",
        country: "N/A",
        status: "Active",
        verified: true
    });

    saveUsers(users);
})();

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
// SESSION (with 24-hour expiry)
// =========================
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

function saveUser(user, token) {
    const session = {
        ...user,
        token: token || null,
        sessionExpires: Date.now() + SESSION_DURATION
    };
    localStorage.setItem(KEYS.USER, JSON.stringify(session));
}
// Wraps fetch() and automatically attaches the logged-in user's
// session token as a Bearer header. Use this for any call to a
// protected /api/... route instead of calling fetch() directly.
async function authFetch(url, options = {}) {
    const user = getUser();
    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {}),
        ...(user?.token ? { "Authorization": "Bearer " + user.token } : {})
    };
    return fetch(url, { ...options, headers });
}
function getUser() {
    const session = JSON.parse(localStorage.getItem(KEYS.USER));

    if (!session) return null;

    if (session.sessionExpires && Date.now() > session.sessionExpires) {
        localStorage.removeItem(KEYS.USER);
        return null;
    }

    return session;
}

function logout() {
    localStorage.removeItem(KEYS.USER);
    window.location.href = "login.html";
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

// =========================
// FORGOT / RESET PASSWORD (mock, local-storage based)
// Same pattern as signup verification: a 6-digit code is generated and
// shown via alert() until a real backend + email service is connected.
// =========================
const PASSWORD_RESET_KEY = "harmonia_password_reset";
const RESET_CODE_TTL = 10 * 60 * 1000; // 10 minutes

function generateSixDigitCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function requestPasswordReset(event) {
    event.preventDefault();

    const email = document.getElementById("email").value.trim();
    const users = getUsers();
    const user = users.find(u => u.email === email);

    // Always show the same confirmation whether or not the email exists,
    // so this form can't be used to check which emails are registered.
    if (user) {
        const code = generateSixDigitCode();

        localStorage.setItem(PASSWORD_RESET_KEY, JSON.stringify({
            email,
            code,
            expires: Date.now() + RESET_CODE_TTL
        }));

        alert(
            "Your reset code is: " + code +
            "\n(This will be emailed to you automatically once the backend is connected.)"
        );
    } else {
        alert("If that email is registered, a reset code has been sent.");
    }

    window.location.href = "reset-password.html";
}

function resendResetCode(event) {
    event.preventDefault();

    const pending = JSON.parse(localStorage.getItem(PASSWORD_RESET_KEY));

    if (!pending) {
        alert("Your reset session expired. Please start over.");
        window.location.href = "forgot-password.html";
        return;
    }

    pending.code = generateSixDigitCode();
    pending.expires = Date.now() + RESET_CODE_TTL;

    localStorage.setItem(PASSWORD_RESET_KEY, JSON.stringify(pending));
    alert("New reset code: " + pending.code);
}

async function resetPassword(event) {
    event.preventDefault();

    const code = document.getElementById("resetCode").value.trim();
    const password = document.getElementById("newPassword").value;
    const confirmPassword = document.getElementById("confirmPassword").value;

    const pending = JSON.parse(localStorage.getItem(PASSWORD_RESET_KEY));

    if (!pending || Date.now() > pending.expires) {
        alert("This reset code has expired. Please request a new one.");
        localStorage.removeItem(PASSWORD_RESET_KEY);
        window.location.href = "forgot-password.html";
        return;
    }

    if (code !== pending.code) {
        alert("Incorrect code. Please try again.");
        return;
    }

    if (password.length < 8) {
        alert("Password must be at least 8 characters long.");
        return;
    }

    if (password !== confirmPassword) {
        alert("Passwords do not match.");
        return;
    }

    const hashed = await hashPassword(password);
    let users = getUsers();

    users = users.map(u => {
        if (u.email === pending.email) u.password = hashed;
        return u;
    });

    saveUsers(users);
    localStorage.removeItem(PASSWORD_RESET_KEY);

    alert("Password updated successfully. Please log in.");
    window.location.href = "login.html";
}

// =========================
// PAGE PROTECTION
// =========================
function protectPage(role) {
    const user = getUser();

    if (!user) {
        window.location.href = "login.html";
        return;
    }

    if (role && user.role !== role) {
        alert("Access denied");
        logout();
    }
}

// =========================
// PROJECTS
// =========================
function getProjects() {
    return JSON.parse(localStorage.getItem(KEYS.PROJECTS)) || [];
}

function saveProjects(p) {
    localStorage.setItem(KEYS.PROJECTS, JSON.stringify(p));
}

// =========================
// CREATE PROJECT (CLIENT)
// =========================
function createProject(project) {
    let projects = getProjects();

    const settings = getSettings();

    const reviews = Number(project.reviews || 0);

    projects.push({
        id: Date.now(),
        projectName: project.projectName,
        category: project.category,
        reviews,
        description: project.description,
        status: "Pending",
        clientId: project.clientId,
        clientEmail: project.clientEmail,
        assignedTo: null,
        pricePerReview: settings.pricePerReview,
        totalCost: reviews * settings.pricePerReview
    });

    saveProjects(projects);

    assignTasksAutomatically();
}

// =========================
// ADMIN APPROVE WORKERS
// =========================
function updateUserStatus(id, status) {
    let users = getUsers();

    users = users.map(u => {
        if (u.id == id) u.status = status;
        return u;
    });

    saveUsers(users);
}

// =========================
// ADMIN CHANGE ROLE (PROMOTE / DEMOTE)
// =========================
function updateUserRole(id, newRole) {
    let users = getUsers();

    users = users.map(u => {
        if (u.id == id) {
            u.role = newRole;
            // make sure they're active once promoted/demoted
            u.status = "Active";
        }
        return u;
    });

    saveUsers(users);
}

// =========================
// UPDATE PROJECT / TASK STATUS (general, no payout)
// =========================
function updateProjectStatus(id, status) {
    let projects = getProjects();

    projects = projects.map(p => {
        if (p.id == id) p.status = status;
        return p;
    });

    saveProjects(projects);
}

// =========================
// AUTO ASSIGN WORKERS
// =========================
function assignTasksAutomatically() {
    let projects = getProjects();
    let users = getUsers();

    const workers = users.filter(u =>
        u.role === "worker" && u.status === "Active"
    );

    if (workers.length === 0) return;

    let i = 0;

    projects = projects.map(p => {
        if (!p.assignedTo && p.status === "Pending") {
            p.assignedTo = workers[i].id;
            p.status = "Assigned";

            i++;
            if (i >= workers.length) i = 0;
        }
        return p;
    });

    saveProjects(projects);
}

// =========================
// WORKER SUBMITS COMPLETED WORK FOR REVIEW
// =========================
function submitForReview(id) {
    const settings = getSettings();
    let projects = getProjects();

    projects = projects.map(p => {
        if (p.id == id) {
            // If reviewers are disabled platform-wide, skip straight to payout
            p.status = settings.reviewerEnabled ? "In Review" : "Completed";
        }
        return p;
    });

    saveProjects(projects);

    if (!settings.reviewerEnabled) {
        payOutProject(id);
    }
}

// Backwards-compatible alias used by older pages
function completeProject(id) {
    submitForReview(id);
}

// =========================
// REVIEWER: GET QUEUE
// =========================
function getReviewQueue() {
    return getProjects().filter(p => p.status === "In Review");
}

// =========================
// REVIEWER: APPROVE (pays out worker + reviewer)
// =========================
function approveSubmission(id, reviewerId) {
    let projects = getProjects();

    projects = projects.map(p => {
        if (p.id == id) p.status = "Completed";
        return p;
    });

    saveProjects(projects);
    payOutProject(id, reviewerId);
}

// =========================
// REVIEWER: REJECT (sends back to worker)
// =========================
function rejectSubmission(id, reason) {
    let projects = getProjects();

    projects = projects.map(p => {
        if (p.id == id) {
            p.status = "Needs Revision";
            p.rejectionReason = reason || "No reason given";
        }
        return p;
    });

    saveProjects(projects);
}

// =========================
// WORKER: RESUBMIT AFTER REJECTION
// =========================
function resubmitTask(id) {
    submitForReview(id);
}

// =========================
// PAYOUT LOGIC (called once, on approval / completion)
// =========================
function payOutProject(projectId, reviewerId = null) {
    const projects = getProjects();
    const settings = getSettings();
    const project = projects.find(p => p.id == projectId);

    if (!project) return;

    let earnings = getEarnings();

    // prevent double-payout if this somehow runs twice
    if (earnings.find(e => e.projectId == projectId)) return;

    const total = project.reviews * settings.pricePerReview;

    if (settings.reviewerEnabled && reviewerId) {
        const reviewerCut = total * (settings.reviewerSharePercent / 100);
        const workerCut = total - reviewerCut;

        earnings.push({
            id: Date.now(),
            workerId: project.assignedTo,
            projectId: project.id,
            amount: workerCut,
            role: "worker",
            status: "Pending"
        });

        earnings.push({
            id: Date.now() + 1,
            workerId: reviewerId,
            projectId: project.id,
            amount: reviewerCut,
            role: "reviewer",
            status: "Pending"
        });

    } else {
        earnings.push({
            id: Date.now(),
            workerId: project.assignedTo,
            projectId: project.id,
            amount: total,
            role: "worker",
            status: "Pending"
        });
    }

    localStorage.setItem(KEYS.EARNINGS, JSON.stringify(earnings));
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

        const response = await fetch(
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

        const response = await fetch(
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

// =========================
// EARNINGS
// =========================
function getEarnings() {
    return JSON.parse(localStorage.getItem(KEYS.EARNINGS)) || [];
}

// =========================
// DASHBOARD STATS
// =========================
function getDashboardStats(role, userId = null) {

    const users = getUsers();
    const projects = getProjects();
    const earnings = JSON.parse(localStorage.getItem(KEYS.EARNINGS)) || [];

    if (role === "admin") {
        return {
            workers: users.filter(u => u.role === "worker").length,
            clients: users.filter(u => u.role === "client").length,
            totalProjects: projects.length,
            pendingProjects: projects.filter(p => p.status === "Pending").length
        };
    }

    if (role === "worker") {
        return {
            myTasks: projects.filter(p => p.assignedTo == userId).length,
            completed: projects.filter(p => p.assignedTo == userId && p.status === "Completed").length,
            earnings: earnings.filter(e => e.workerId == userId)
                .reduce((a, b) => a + b.amount, 0)
        };
    }

    if (role === "client") {
        return {
            myProjects: projects.filter(p => p.clientId == userId).length
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
    const notifications = [];
    if (!user) return notifications;

    const projects = getProjects();
    const earnings = getEarnings();

    if (user.role === "worker") {
        const myTasks = projects.filter(p => p.assignedTo == user.id);
        const needsRevision = myTasks.filter(p => p.status === "Needs Revision");
        const pendingPay = earnings.filter(e => e.workerId == user.id && e.status === "Pending");

        needsRevision.forEach(p =>
            notifications.push({ icon: "⚠️", text: `"${p.projectName}" needs revision` })
        );
        if (pendingPay.length) {
            notifications.push({ icon: "💰", text: `${pendingPay.length} payout(s) pending` });
        }
    }

    if (user.role === "client") {
        const myProjects = projects.filter(p => p.clientId == user.id);
        const inReview = myProjects.filter(p => p.status === "In Review");
        if (inReview.length) {
            notifications.push({ icon: "🔍", text: `${inReview.length} project(s) in review` });
        }
    }

    if (user.role === "reviewer") {
        const queue = getReviewQueue();
        if (queue.length) {
            notifications.push({ icon: "📝", text: `${queue.length} submission(s) awaiting review` });
        }
    }

    if (user.role === "admin") {
        const pendingWorkers = getUsers().filter(u => u.role === "worker" && u.status === "Pending");
        const pendingProjects = projects.filter(p => p.status === "Pending");
        if (pendingWorkers.length) {
            notifications.push({ icon: "🧑‍💻", text: `${pendingWorkers.length} worker(s) awaiting approval` });
        }
        if (pendingProjects.length) {
            notifications.push({ icon: "📁", text: `${pendingProjects.length} project(s) awaiting assignment` });
        }
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

    if (user) {
        const initials = (user.fullName || user.role || "U")
            .trim().split(/\s+/).map(w => w[0]).slice(0, 2).join("").toUpperCase();

        profileWrap.innerHTML = `
            <button class="profile-btn" type="button">
                <span class="profile-avatar">${escapeHTML(initials)}</span>
                <span class="profile-name">${escapeHTML(user.fullName || "Account")}<small>${escapeHTML(user.role)}</small></span>
            </button>
            <div class="profile-menu">
                <a href="#">👤 My Profile</a>
                <a href="#">⚙ Settings</a>
                <hr>
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
