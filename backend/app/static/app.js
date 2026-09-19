// AcmeDesk Token Security Lab - Frontend Application
// Single-page app with client-side routing

const STRATEGIES = [
    { name: "timestamp", label: "Long Timestamp Token", description: "Base64URL-encoded timestamp + user ID + static secret" },
    { name: "counter", label: "Long Counter Token", description: "Sequential counter + user ID + small random suffix" },
    { name: "weak_prng", label: "Long Weak PRNG Token", description: "Python random.Random (Mersenne Twister) with predictable seed" },
    { name: "structured", label: "Structured Token", description: "Partially structured token with only 24 bits of entropy" },
    { name: "predictable_hash", label: "Long Hash of Predictable Data", description: "SHA-256(username|timestamp|predictable_nonce) — 64 hex chars" },
    { name: "secure", label: "Secure CSPRNG Token", description: "secrets.token_urlsafe(32) — 256 bits of cryptographic entropy" },
];

// ---- State ----
let state = {
    user: null,
    token: localStorage.getItem("acmedesk_token") || null,
    route: window.location.pathname,
    instructorMode: false,
    labMode: true,
    flash: null,
};

// ---- Utilities ----
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

function navigate(path) {
    history.pushState({}, "", path);
    state.route = path;
    render();
}

function setFlash(type, message) {
    state.flash = { type, message };
}

function clearFlash() {
    state.flash = null;
}

function authHeaders() {
    const headers = { "Content-Type": "application/json" };
    if (state.token) {
        headers["Authorization"] = `Bearer ${state.token}`;
    }
    return headers;
}

async function api(path, options = {}) {
    const response = await fetch(path, {
        ...options,
        headers: {
            ...authHeaders(),
            ...(options.headers || {}),
        },
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(data.detail || "Request failed");
    }
    return data;
}

// ---- Auth helpers ----
function saveSession(token, user) {
    state.token = token;
    state.user = user;
    localStorage.setItem("acmedesk_token", token);
}

function clearSession() {
    state.token = null;
    state.user = null;
    localStorage.removeItem("acmedesk_token");
}

async function refreshUser() {
    if (!state.token) {
        state.user = null;
        return;
    }
    try {
        state.user = await api("/api/auth/me/userinfo");
    } catch (e) {
        clearSession();
    }
}

// ---- Templates ----
function navHtml() {
    const authLinks = state.user
        ? `<a href="#" onclick="event.preventDefault(); navigate('/profile')">Profile</a>
           <a href="#" onclick="event.preventDefault(); navigate('/lab/mailbox')">Mailbox</a>
           <a href="#" onclick="event.preventDefault(); navigate('/lab/token-laboratory')">Token Laboratory</a>
           <a href="#" onclick="event.preventDefault(); navigate('/lab/challenge')">Challenge</a>
           <button onclick="logout()">Log out</button>`
        : `<a href="#" onclick="event.preventDefault(); navigate('/login')">Log in</a>
           <a href="#" onclick="event.preventDefault(); navigate('/register')">Register</a>`;

    return `
    <header>
        <div class="container nav">
            <a href="#" class="brand" onclick="event.preventDefault(); navigate('/')">
                <span class="brand-mark">A</span>
                <span>AcmeDesk</span>
            </a>
            <nav class="nav-links">
                ${authLinks}
                <a href="#" onclick="event.preventDefault(); navigate('/forgot-password')">Reset Password</a>
            </nav>
        </div>
    </header>`;
}

function flashHtml() {
    if (!state.flash) return "";
    const type = state.flash.type || "info";
    const message = state.flash.message || "";
    return `<div class="alert alert-${type}">${escapeHtml(message)}</div>`;
}

function layout(content, opts = {}) {
    return `
    ${navHtml()}
    <main class="container page">
        ${flashHtml()}
        ${content}
    </main>`;
}

// ---- Pages ----
function homePage() {
    const content = `
    <div class="hero">
        <div class="page-header" style="margin-bottom: 40px;">
            <span class="badge badge-lab">Interactive Security Lab</span>
            <h1 style="margin-top: 16px;">Token Length ≠ Token Security</h1>
            <p>A hands-on training lab demonstrating why a password-reset token's security comes from
            <strong>unpredictability</strong>, not from how long it looks.</p>
        </div>
        <div class="grid-2" style="text-align: left;">
            <div class="card">
                <h3><span class="badge badge-vulnerable">Vulnerable Lab</span></h3>
                <p class="mt-2">Explore five intentionally flawed token-generation strategies:</p>
                <ul style="margin: 12px 0 0 20px;" class="text-muted">
                    <li>Long timestamp tokens</li>
                    <li>Sequential counters</li>
                    <li>Weak PRNG (Mersenne Twister)</li>
                    <li>Structured tokens with tiny entropy</li>
                    <li>SHA-256 of predictable input</li>
                </ul>
            </div>
            <div class="card">
                <h3><span class="badge badge-secure">Secure Reference</span></h3>
                <p class="mt-2">Compare against the correct implementation:</p>
                <ul style="margin: 12px 0 0 20px;" class="text-muted">
                    <li>Cryptographically secure random generation</li>
                    <li>Hashed token storage</li>
                    <li>Short expiration window</li>
                    <li>One-time use</li>
                    <li>Burp Suite Sequencer friendly</li>
                </ul>
            </div>
        </div>
        <div class="card" style="margin-top: 20px;">
            <h4>Core Principle</h4>
            <p style="margin-top: 8px;">A token's security is determined by the amount of <strong>unpredictable information</strong>
            an attacker must guess, not by how long or visually complex the token appears.</p>
            <p class="mt-2 text-muted">Use Burp Suite Sequencer to analyze samples from each strategy and discover the difference for yourself.</p>
            <div class="flex gap-2 mt-4 flex-wrap">
                <button class="btn btn-primary" onclick="navigate('/register')">Start Lab</button>
                <button class="btn btn-secondary" onclick="navigate('/lab/token-laboratory')">Token Laboratory</button>
                <button class="btn btn-secondary" onclick="navigate('/lab/challenge')">Challenge Mode</button>
            </div>
        </div>
    </div>`;
    return layout(content);
}

function loginPage() {
    const content = `
    <div class="auth-layout">
        <div class="card">
            <h3>Log in to AcmeDesk</h3>
            <form id="login-form">
                <div class="form-group">
                    <label for="login-email">Email</label>
                    <input type="email" id="login-email" required placeholder="you@example.com">
                </div>
                <div class="form-group">
                    <label for="login-password">Password</label>
                    <input type="password" id="login-password" required placeholder="••••••••">
                </div>
                <button type="submit" class="btn btn-primary" style="width: 100%;">Log in</button>
            </form>
            <p class="text-muted mt-2">Need an account? <a href="#" onclick="event.preventDefault(); navigate('/register')">Register</a></p>
            <p class="text-muted">Forgot your password? <a href="#" onclick="event.preventDefault(); navigate('/forgot-password')">Request a reset</a></p>
        </div>
        <div class="card">
            <h3>Lab Accounts</h3>
            <p class="text-muted">Use these seeded accounts to explore the password reset flow:</p>
            <div class="mt-2" id="lab-accounts">
                <p><code>alice@example.com</code> / <code>Password123!</code></p>
                <p><code>bob@example.com</code> / <code>Password123!</code></p>
                <p><code>admin@example.com</code> / <code>Password123!</code></p>
            </div>
            <p class="text-muted mt-2">These are local-only test accounts created by the lab's seed script.</p>
        </div>
    </div>`;
    return layout(content);
}

function registerPage() {
    const content = `
    <div class="auth-layout">
        <div class="card">
            <h3>Create an AcmeDesk account</h3>
            <form id="register-form">
                <div class="form-group">
                    <label for="register-email">Email</label>
                    <input type="email" id="register-email" required placeholder="you@example.com">
                </div>
                <div class="form-group">
                    <label for="register-password">Password</label>
                    <input type="password" id="register-password" required minlength="8" placeholder="At least 8 characters">
                </div>
                <button type="submit" class="btn btn-primary" style="width: 100%;">Register</button>
            </form>
            <p class="text-muted mt-2">Already have an account? <a href="#" onclick="event.preventDefault(); navigate('/login')">Log in</a></p>
        </div>
        <div class="card">
            <h3>Why register?</h3>
            <p class="text-muted">Registration creates a local test account so you can exercise the complete password reset flow,
            from request to mailbox to token validation.</p>
            <p class="text-muted mt-2">Passwords are stored as bcrypt hashes, demonstrating that even the "secure" parts of the lab
            follow production-style practices where appropriate.</p>
        </div>
    </div>`;
    return layout(content);
}

function forgotPasswordPage() {
    const content = `
    <div class="page-header">
        <span class="badge badge-lab">Password Reset Lab</span>
        <h1 style="margin-top: 16px;">Forgot Password</h1>
        <p>Request a password reset link. Choose a token strategy to explore different generation weaknesses.</p>
    </div>
    <div class="grid-2">
        <div class="card">
            <h3>Request a Reset Link</h3>
            <form id="forgot-form">
                <div class="form-group">
                    <label for="forgot-email">Email</label>
                    <input type="email" id="forgot-email" required placeholder="you@example.com">
                </div>
                <div class="form-group">
                    <label for="forgot-strategy">Token Strategy</label>
                    <select id="forgot-strategy">
                        ${STRATEGIES.map(s => `<option value="${s.name}">${s.label}</option>`).join("")}
                    </select>
                </div>
                <button type="submit" class="btn btn-primary" style="width: 100%;">Send Reset Link</button>
            </form>
            <p class="text-muted mt-2">The token is sent to the <strong>simulated mailbox</strong> — no real email is ever sent.</p>
        </div>
        <div class="card">
            <h3>How it works</h3>
            <ol style="margin-left: 20px;" class="text-muted">
                <li>Choose an email and token strategy</li>
                <li>Open your <a href="#" onclick="event.preventDefault(); navigate('/lab/mailbox')">simulated mailbox</a></li>
                <li>Copy the reset link and its token</li>
                <li>Use Burp Suite Sequencer to analyze samples</li>
                <li>Submit the token to reset the password</li>
            </ol>
            <div class="alert alert-warning mt-4">
                <strong>Remember:</strong> token length does not equal security.
            </div>
        </div>
    </div>`;
    return layout(content);
}

function resetPasswordPage() {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token") || "";
    const content = `
    <div class="page-header">
        <span class="badge badge-lab">Password Reset</span>
        <h1 style="margin-top: 16px;">Reset Your Password</h1>
        <p>Submit your password reset token and choose a new password.</p>
    </div>
    <div class="card" style="max-width: 600px;">
        <form id="reset-form">
            <div class="form-group">
                <label for="reset-token">Reset Token</label>
                <textarea id="reset-token" rows="3" required placeholder="Paste your token here">${escapeHtml(token)}</textarea>
            </div>
            <div class="form-group">
                <label for="new-password">New Password</label>
                <input type="password" id="new-password" required minlength="8" placeholder="At least 8 characters">
            </div>
            <button type="submit" class="btn btn-primary" style="width: 100%;">Reset Password</button>
        </form>
        <p class="text-muted mt-2">Tokens expire after 15 minutes and can only be used once.</p>
    </div>`;
    return layout(content);
}

function profilePage() {
    const content = `
    <div class="page-header">
        <span class="badge badge-lab">Account</span>
        <h1 style="margin-top: 16px;">Your Profile</h1>
    </div>
    <div class="grid-2">
        <div class="card">
            <h3>Account Details</h3>
            <div id="profile-details">
                <p class="text-muted">Loading...</p>
            </div>
        </div>
        <div class="card">
            <h3>Security Notes</h3>
            <ul style="margin-left: 20px;" class="text-muted">
                <li>Passwords are stored as bcrypt hashes</li>
                <li>Sessions use opaque tokens stored server-side</li>
                <li>Reset tokens are hashed in the database</li>
                <li>Reset tokens expire after 15 minutes</li>
                <li>Reset tokens are single-use</li>
            </ul>
        </div>
    </div>`;
    return layout(content);
}

function mailboxPage() {
    const content = `
    <div class="page-header">
        <span class="badge badge-lab">Lab Mailbox</span>
        <h1 style="margin-top: 16px;">Simulated Inbox</h1>
        <p>Password reset links are delivered here instead of real email. This is where you obtain tokens for analysis.</p>
    </div>
    <div class="card">
        <form id="mailbox-form">
            <div class="form-group">
                <label for="mailbox-email">Email address</label>
                <input type="email" id="mailbox-email" required placeholder="you@example.com">
            </div>
            <button type="submit" class="btn btn-primary">Load Mailbox</button>
        </form>
    </div>
    <div id="mailbox-results"></div>`;
    return layout(content);
}

function tokenLaboratoryPage() {
    const content = `
    <div class="page-header">
        <span class="badge badge-lab">Token Laboratory</span>
        <h1 style="margin-top: 16px;">Token Strategy Comparison</h1>
        <p>Compare all six token generation strategies side by side. Enable Instructor Mode to reveal the answers.</p>
    </div>
    <div class="card">
        <div class="flex justify-between align-center flex-wrap gap-2">
            <div>
                <h3 style="display: inline;">Strategy Comparison</h3>
                <span id="instructor-badge"></span>
            </div>
            <button class="btn btn-secondary" onclick="loadLaboratory()">Refresh Data</button>
        </div>
        <p class="text-muted mt-2">Observe the token examples. Which ones actually contain unpredictable information?</p>
    </div>
    <div class="card">
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Strategy</th>
                        <th>Token Example</th>
                        <th>Length</th>
                        <th>Alphabet</th>
                        <th>Generation</th>
                        <th>Predictability</th>
                        <th>Effective Entropy</th>
                        <th>Recommended Usage</th>
                    </tr>
                </thead>
                <tbody id="laboratory-table"></tbody>
            </table>
        </div>
    </div>`;
    return layout(content);
}

function challengePage() {
    const content = `
    <div class="page-header">
        <span class="badge badge-lab">Challenge Mode</span>
        <h1 style="margin-top: 16px;">Which Token is Actually Secure?</h1>
        <p>Six anonymous token samples are waiting. Collect additional samples, analyze them, classify each strategy,
        and identify which one uses a CSPRNG.</p>
    </div>
    <div class="card">
        <div class="flex justify-between align-center flex-wrap gap-2">
            <div>
                <h3 style="display: inline;">Anonymous Samples</h3>
                <span id="challenge-badge"></span>
            </div>
            <button class="btn btn-secondary" onclick="loadChallenge()">Refresh Samples</button>
        </div>
        <p class="text-muted mt-2">Don't trust the token's appearance. Analyze structure, correlations, and statistical properties.</p>
    </div>
    <div class="card">
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Sample</th>
                        <th>Token</th>
                        <th>Length</th>
                        <th>Your Classification</th>
                    </tr>
                </thead>
                <tbody id="challenge-table"></tbody>
            </table>
        </div>
        <button class="btn btn-primary mt-4" onclick="verifyChallenge()">Submit Classifications</button>
        <div id="challenge-results"></div>
    </div>`;
    return layout(content);
}

// ---- API Actions ----
async function handleLogin(e) {
    e.preventDefault();
    const email = $("#login-email").value;
    const password = $("#login-password").value;
    try {
        const data = await api("/api/auth/login", {
            method: "POST",
            body: JSON.stringify({ email, password }),
        });
        saveSession(data.access_token, data.user);
        setFlash("success", "Logged in successfully.");
        navigate("/profile");
    } catch (err) {
        setFlash("error", err.message);
        render();
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const email = $("#register-email").value;
    const password = $("#register-password").value;
    try {
        const data = await api("/api/auth/register", {
            method: "POST",
            body: JSON.stringify({ email, password }),
        });
        saveSession(data.access_token, data.user);
        setFlash("success", "Account created. You are now logged in.");
        navigate("/profile");
    } catch (err) {
        setFlash("error", err.message);
        render();
    }
}

async function handleForgot(e) {
    e.preventDefault();
    const email = $("#forgot-email").value;
    const strategy = $("#forgot-strategy").value;
    try {
        await api("/lab/forgot-password", {
            method: "POST",
            body: JSON.stringify({ email, strategy }),
        });
        setFlash("success", "Reset link sent to the simulated mailbox.");
        navigate("/lab/mailbox");
    } catch (err) {
        setFlash("error", err.message);
        render();
    }
}

async function handleReset(e) {
    e.preventDefault();
    const token = $("#reset-token").value.trim();
    const newPassword = $("#new-password").value;
    try {
        await api("/lab/reset-password", {
            method: "POST",
            body: JSON.stringify({ token, new_password: newPassword }),
        });
        setFlash("success", "Password reset successfully.");
        navigate("/login");
    } catch (err) {
        setFlash("error", err.message);
        render();
    }
}

async function handleMailbox(e) {
    e.preventDefault();
    const email = $("#mailbox-email").value;
    try {
        const entries = await api(`/lab/mailbox/${encodeURIComponent(email)}`);
        renderMailbox(entries);
    } catch (err) {
        setFlash("error", err.message);
        render();
    }
}

async function loadLaboratory() {
    try {
        const data = await api("/lab/token-laboratory");
        renderLaboratory(data);
    } catch (err) {
        $("#laboratory-table").innerHTML = `<tr><td colspan="8" class="text-danger">Failed to load laboratory data: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function loadChallenge() {
    try {
        const data = await api("/lab/challenge");
        renderChallenge(data);
    } catch (err) {
        $("#challenge-table").innerHTML = `<tr><td colspan="4" class="text-danger">Failed to load samples: ${escapeHtml(err.message)}</td></tr>`;
    }
}

async function verifyChallenge() {
    const guesses = {};
    $$("#challenge-table select").forEach(sel => {
        guesses[sel.dataset.sample] = sel.value;
    });
    try {
        const data = await api("/lab/challenge/verify", {
            method: "POST",
            body: JSON.stringify(guesses),
        });
        $("#challenge-results").innerHTML = `
            <div class="alert ${data.score.startsWith("6") ? "alert-success" : "alert-warning"} mt-4">
                <strong>Score: ${escapeHtml(data.score)}</strong> — ${escapeHtml(data.message)}
            </div>`;
    } catch (err) {
        $("#challenge-results").innerHTML = `<div class="alert alert-error mt-4">${escapeHtml(err.message)}</div>`;
    }
}

// ---- Renderers ----
function renderMailbox(entries) {
    const container = $("#mailbox-results");
    if (!entries.length) {
        container.innerHTML = `<div class="alert alert-warning mt-4">No active reset links found for this email.</div>`;
        return;
    }
    container.innerHTML = `<div class="card mt-4"><h3>Reset Links</h3>
        ${entries.map(entry => `
            <div style="border-bottom: 1px solid var(--border); padding: 16px 0;">
                <div class="flex justify-between align-center flex-wrap gap-2">
                    <div>
                        <strong>${escapeHtml(entry.subject)}</strong>
                        <span class="badge badge-lab ml-2">${escapeHtml(entry.strategy)}</span>
                    </div>
                    <span class="text-muted text-sm">${new Date(entry.created_at).toLocaleString()}</span>
                </div>
                <div class="token-box mt-2">${escapeHtml(entry.token)}</div>
                <div class="flex gap-2 mt-2 flex-wrap">
                    <a class="btn btn-secondary" href="/reset?token=${encodeURIComponent(entry.token)}">Open Reset Page</a>
                    <button class="btn btn-secondary" onclick="copyToken('${encodeURIComponent(entry.token)}')">Copy Token</button>
                </div>
            </div>`).join("")}
    </div>`;
}

function renderLaboratory(data) {
    state.instructorMode = data.instructor_mode;
    const tbody = $("#laboratory-table");
    $("#instructor-badge").innerHTML = state.instructorMode
        ? `<span class="badge badge-lab">Instructor Mode: ON</span>`
        : `<span class="badge badge-lab">Instructor Mode: OFF</span>`;

    tbody.innerHTML = data.strategies.map(entry => `
        <tr>
            <td><strong>${escapeHtml(entry.strategy)}</strong><br>
                <span class="badge ${entry.instructor_only ? "badge-vulnerable" : "badge-secure"}">${entry.instructor_only ? "Hidden" : "Revealed"}</span>
            </td>
            <td><div class="token-box">${escapeHtml(entry.token_example)}</div></td>
            <td>${entry.length}</td>
            <td>${escapeHtml(entry.alphabet)}</td>
            <td class="text-muted">${escapeHtml(entry.generation)}</td>
            <td>${escapeHtml(entry.predictability)}</td>
            <td>${entry.effective_entropy_bits !== null && entry.effective_entropy_bits !== undefined
                ? `${entry.effective_entropy_bits} bits`
                : '<span class="text-muted">Hidden</span>'}
            </td>
            <td class="text-muted">${escapeHtml(entry.recommended_usage)}</td>
        </tr>`).join("");
}

function renderChallenge(data) {
    const tbody = $("#challenge-table");
    $("#challenge-badge").innerHTML = data.instructor_mode
        ? `<span class="badge badge-lab">Instructor Mode: ON</span>`
        : `<span class="badge badge-lab">Instructor Mode: OFF</span>`;

    tbody.innerHTML = data.samples.map(sample => `
        <tr>
            <td><strong>#${sample.id}</strong></td>
            <td><div class="token-box">${escapeHtml(sample.token)}</div></td>
            <td>${sample.length}</td>
            <td>
                <select data-sample="${sample.id}">
                    <option value="">— Select strategy —</option>
                    ${STRATEGIES.map(s => `<option value="${s.name}">${s.label}</option>`).join("")}
                </select>
            </td>
        </tr>`).join("");
}

// ---- Logout ----
async function logout() {
    try {
        await api("/api/auth/logout", { method: "POST" });
    } catch (e) {}
    clearSession();
    setFlash("info", "Logged out.");
    navigate("/");
}

function copyToken(encoded) {
    const token = decodeURIComponent(encoded);
    if (navigator.clipboard) {
        navigator.clipboard.writeText(token).then(() => {
            setFlash("success", "Token copied to clipboard.");
            render();
        });
    }
}

// ---- Router ----
function render() {
    const app = $("#app");
    const path = state.route;

    let content;
    switch (path) {
        case "/":
            content = homePage();
            break;
        case "/login":
            content = loginPage();
            break;
        case "/register":
            content = registerPage();
            break;
        case "/forgot-password":
            content = forgotPasswordPage();
            break;
        case "/reset":
            content = resetPasswordPage();
            break;
        case "/profile":
            content = profilePage();
            break;
        case "/lab/mailbox":
            content = mailboxPage();
            break;
        case "/lab/token-laboratory":
            content = tokenLaboratoryPage();
            break;
        case "/lab/challenge":
            content = challengePage();
            break;
        default:
            content = homePage();
    }

    app.innerHTML = content;

    // Attach form handlers
    const loginForm = $("#login-form");
    if (loginForm) loginForm.addEventListener("submit", handleLogin);

    const registerForm = $("#register-form");
    if (registerForm) registerForm.addEventListener("submit", handleRegister);

    const forgotForm = $("#forgot-form");
    if (forgotForm) forgotForm.addEventListener("submit", handleForgot);

    const resetForm = $("#reset-form");
    if (resetForm) resetForm.addEventListener("submit", handleReset);

    const mailboxForm = $("#mailbox-form");
    if (mailboxForm) mailboxForm.addEventListener("submit", handleMailbox);

    // Load page-specific data
    if (path === "/profile" && state.user) {
        $("#profile-details").innerHTML = `
            <p><strong>Email:</strong> ${escapeHtml(state.user.email)}</p>
            <p><strong>User ID:</strong> ${state.user.id}</p>
            <p><strong>Created:</strong> ${new Date(state.user.created_at).toLocaleString()}</p>
        `;
    }
    if (path === "/lab/mailbox") {
        const email = state.user ? state.user.email : "alice@example.com";
        $("#mailbox-email").value = email;
        handleMailbox({ preventDefault() {} });
    }
    if (path === "/lab/token-laboratory") loadLaboratory();
    if (path === "/lab/challenge") loadChallenge();

    // Clear flash after rendering
    clearFlash();
}

// ---- Boot ----
window.addEventListener("popstate", () => {
    state.route = window.location.pathname;
    render();
});

document.addEventListener("DOMContentLoaded", async () => {
    await refreshUser();
    render();
});
