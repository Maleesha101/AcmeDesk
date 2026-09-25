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
    const labLinks = `
        <a href="/lab" onclick="event.preventDefault(); navigate('/lab')">Lab overview</a>
        <a href="/lab/token-laboratory" onclick="event.preventDefault(); navigate('/lab/token-laboratory')">Token lab</a>
        <a href="/lab/mailbox" onclick="event.preventDefault(); navigate('/lab/mailbox')">Mailbox</a>
        <a href="/lab/challenge" onclick="event.preventDefault(); navigate('/lab/challenge')">Challenge</a>`;
    const accountLinks = state.user
        ? `<a href="/" onclick="event.preventDefault(); navigate('/')">Workspace</a>
           <a href="/profile" onclick="event.preventDefault(); navigate('/profile')">Account</a>
           <button onclick="logout()">Sign out</button>`
        : `<a href="/login" onclick="event.preventDefault(); navigate('/login')">Sign in</a>
           <a class="btn btn-primary nav-cta" href="/register" onclick="event.preventDefault(); navigate('/register')">Create account</a>`;
    const isLab = state.route.startsWith("/lab");

    return `
    <header>
        <div class="container nav">
            <a href="/" class="brand" onclick="event.preventDefault(); navigate('/')">
                <span class="brand-mark">A</span>
                <span>AcmeDesk <small>${isLab ? "LEARNING LAB" : "SUPPORT DESK"}</small></span>
            </a>
            <nav class="nav-links">
                ${isLab ? `<a href="/" onclick="event.preventDefault(); navigate('/')">Back to workspace</a>${labLinks}` : accountLinks}
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
    const isLab = state.route.startsWith("/lab");
    return `
    <div class="app-frame ${isLab ? "lab-frame" : ""}">
    ${navHtml()}
    <main class="container page">
        ${flashHtml()}
        ${content}
    </main>
    <footer class="site-footer">
        <div class="container footer-inner">
            <span>AcmeDesk <span class="text-muted">Customer support workspace</span></span>
            ${isLab
                ? `<a href="/" onclick="event.preventDefault(); navigate('/')">Return to workspace</a>`
                : `<a href="/lab" onclick="event.preventDefault(); navigate('/lab')">Security learning lab</a>`}
        </div>
    </footer>
    </div>`;
}

// ---- Pages ----
function homePage() {
    const firstName = state.user ? state.user.email.split("@")[0] : "there";
    const accountLink = state.user
        ? `<a class="btn btn-secondary" href="/profile" onclick="event.preventDefault(); navigate('/profile')">Account settings</a>`
        : `<a class="btn btn-primary" href="/register" onclick="event.preventDefault(); navigate('/register')">Create your account</a>`;
    const content = `
    <div class="workspace-shell">
        <aside class="workspace-sidebar">
            <p class="sidebar-label">WORKSPACE</p>
            <a class="workspace-link is-active" href="/" onclick="event.preventDefault(); navigate('/')"><span class="workspace-icon">I</span>Inbox</a>
            ${state.user
                ? `<a class="workspace-link" href="/profile" onclick="event.preventDefault(); navigate('/profile')"><span class="workspace-icon">A</span>Account</a>`
                : `<a class="workspace-link" href="/login" onclick="event.preventDefault(); navigate('/login')"><span class="workspace-icon">A</span>Sign in</a>`}
            <div class="sidebar-account">
                <span class="presence-dot"></span>
                <span>${state.user ? escapeHtml(state.user.email) : "AcmeDesk workspace"}</span>
            </div>
        </aside>
        <section class="workspace-main">
            <div class="workspace-heading">
                <div>
                    <p class="eyebrow">CUSTOMER SUPPORT</p>
                    <h1>Good to see you, ${escapeHtml(firstName)}</h1>
                    <p class="text-muted">Your conversations and customer context, together in one place.</p>
                </div>
                ${accountLink}
            </div>
            <section class="inbox-panel" aria-labelledby="inbox-title">
                <div class="inbox-toolbar">
                    <div>
                        <h2 id="inbox-title">Inbox</h2>
                        <p class="text-muted">All conversations</p>
                    </div>
                    <span class="inbox-filter">All</span>
                </div>
                <div class="inbox-empty">
                    <span class="empty-mark" aria-hidden="true">A</span>
                    <h3>Your inbox is ready</h3>
                    <p>Customer conversations will appear here when your workspace is connected.</p>
                    ${state.user
                        ? `<a class="text-link" href="/profile" onclick="event.preventDefault(); navigate('/profile')">View your account</a>`
                        : `<div class="flex gap-2 flex-wrap justify-center">
                               <a class="btn btn-primary" href="/register" onclick="event.preventDefault(); navigate('/register')">Create account</a>
                               <a class="btn btn-secondary" href="/login" onclick="event.preventDefault(); navigate('/login')">Sign in</a>
                           </div>`}
                </div>
            </section>
        </section>
    </div>`;
    return layout(content);
}

function loginPage() {
    const content = `
    <div class="auth-screen">
        <section class="auth-context">
            <p class="eyebrow">ACMEDESK / CUSTOMER SUPPORT</p>
            <h1>Make room for the conversations that matter.</h1>
            <p>Sign in to pick up where your team left off.</p>
            <div class="auth-orbit" aria-hidden="true"><span>AD</span><i></i><i></i><i></i></div>
        </section>
        <section class="auth-panel">
            <p class="auth-kicker">WELCOME BACK</p>
            <h2>Sign in</h2>
            <p class="text-muted">Enter your account details to continue.</p>
            <form id="login-form">
                <div class="form-group">
                    <label for="login-email">Email</label>
                    <input type="email" id="login-email" autocomplete="email" required placeholder="you@company.com">
                </div>
                <div class="form-group">
                    <label for="login-password">Password</label>
                    <input type="password" id="login-password" autocomplete="current-password" required placeholder="Your password">
                </div>
                <button type="submit" class="btn btn-primary auth-submit">Sign in</button>
            </form>
            <p class="auth-switch">New to AcmeDesk? <a href="/register" onclick="event.preventDefault(); navigate('/register')">Create an account</a></p>
            <a class="auth-secondary-link" href="/lab/forgot-password" onclick="event.preventDefault(); navigate('/lab/forgot-password')">Forgot your password?</a>
        </section>
    </div>`;
    return layout(content);
}

function registerPage() {
    const content = `
    <div class="auth-screen">
        <section class="auth-context">
            <p class="eyebrow">ACMEDESK / CUSTOMER SUPPORT</p>
            <h1>Start with a clearer view of every customer.</h1>
            <p>Create your account to open your AcmeDesk workspace.</p>
            <div class="auth-orbit" aria-hidden="true"><span>AD</span><i></i><i></i><i></i></div>
        </section>
        <section class="auth-panel">
            <p class="auth-kicker">GET STARTED</p>
            <h2>Create your account</h2>
            <p class="text-muted">Use your work email and choose a password.</p>
            <form id="register-form">
                <div class="form-group">
                    <label for="register-email">Email</label>
                    <input type="email" id="register-email" autocomplete="email" required placeholder="you@company.com">
                </div>
                <div class="form-group">
                    <label for="register-password">Password</label>
                    <input type="password" id="register-password" autocomplete="new-password" required minlength="8" placeholder="At least 8 characters">
                </div>
                <button type="submit" class="btn btn-primary auth-submit">Create account</button>
            </form>
            <p class="auth-switch">Already have an account? <a href="/login" onclick="event.preventDefault(); navigate('/login')">Sign in</a></p>
        </section>
    </div>`;
    return layout(content);
}

function labHomePage() {
    const content = `
    <div class="page-header lab-page-header">
        <span class="badge badge-lab">Learning Lab</span>
        <h1>Token security, hands on</h1>
        <p>Explore how reset-token design affects predictability, entropy, and resistance to attack.</p>
    </div>
    <div class="lab-entry-grid">
        <a class="card lab-entry" href="/lab/token-laboratory" onclick="event.preventDefault(); navigate('/lab/token-laboratory')">
            <span class="lab-entry-index">01</span><h2>Token laboratory</h2>
            <p>Compare six token-generation strategies and inspect their security properties.</p>
            <span class="text-link">Open laboratory</span>
        </a>
        <a class="card lab-entry" href="/lab/challenge" onclick="event.preventDefault(); navigate('/lab/challenge')">
            <span class="lab-entry-index">02</span><h2>Challenge</h2>
            <p>Classify token samples and identify which strategy uses a secure random generator.</p>
            <span class="text-link">Start challenge</span>
        </a>
        <a class="card lab-entry" href="/lab/forgot-password" onclick="event.preventDefault(); navigate('/lab/forgot-password')">
            <span class="lab-entry-index">03</span><h2>Password reset exercise</h2>
            <p>Generate a reset token and inspect it in the simulated mailbox.</p>
            <span class="text-link">Open exercise</span>
        </a>
    </div>`;
    return layout(content);
}

function labForgotPasswordPage() {
    const content = `
    <div class="page-header">
        <span class="badge badge-lab">Password Reset Lab</span>
        <h1 style="margin-top: 16px;">Generate a reset token</h1>
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

function labResetPasswordPage() {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token") || "";
    const content = `
    <div class="page-header">
        <span class="badge badge-lab">Password Reset Lab</span>
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
        <span class="eyebrow">WORKSPACE SETTINGS</span>
        <h1 style="margin-top: 16px;">Your account</h1>
    </div>
    <div class="account-layout">
        <section class="card">
            <h2>Account details</h2>
            <div id="profile-details">
                <p class="text-muted">Loading...</p>
            </div>
        </section>
        <section class="card account-workspace">
            <p class="eyebrow">ACMEDESK</p>
            <h2>Customer support workspace</h2>
            <p class="text-muted">You are signed in and ready to return to your inbox.</p>
            <a class="text-link" href="/" onclick="event.preventDefault(); navigate('/')">Back to inbox</a>
        </section>
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
        navigate("/");
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
        navigate("/");
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
                    <a class="btn btn-secondary" href="/lab/reset?token=${encodeURIComponent(entry.token)}">Open Reset Page</a>
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
        case "/profile":
            content = profilePage();
            break;
        case "/lab":
            content = labHomePage();
            break;
        case "/lab/forgot-password":
            content = labForgotPasswordPage();
            break;
        case "/lab/reset":
            content = labResetPasswordPage();
            break;
        case "/forgot-password":
            history.replaceState({}, "", "/lab/forgot-password");
            state.route = "/lab/forgot-password";
            content = labForgotPasswordPage();
            break;
        case "/reset":
            history.replaceState({}, "", `/lab/reset${window.location.search}`);
            state.route = "/lab/reset";
            content = labResetPasswordPage();
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
