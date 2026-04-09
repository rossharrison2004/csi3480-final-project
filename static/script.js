// Calls /generate backend (uses Python secrets module — CSPRNG)
async function generatePassword() {
    const length  = parseInt(document.getElementById('length').value);
    const upper   = document.getElementById('upper').checked;
    const lower   = document.getElementById('lower').checked;
    const digits  = document.getElementById('digits').checked;
    const symbols = document.getElementById('symbols').checked;

    const res  = await fetch('/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ length, upper, lower, digits, symbols })
    });
    const data = await res.json();

    if (data.error) { alert(data.error); return; }

    document.getElementById('generatedPassword').innerText = data.password;
    showSidebarStrength(data.strength);
}

// Calls /hash backend (bcrypt)
async function hashPassword() {
    const password = document.getElementById('passwordToHash').value;

    const res  = await fetch('/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
    });
    const data = await res.json();

    if (data.error) { alert(data.error); return; }

    document.getElementById('hashedPassword').innerText = data.hash;
    showSidebarStrength(data.strength);
    if (data.hash_analysis) showHashAnalysis(data.hash_analysis);
}

// Calls /verify backend
async function verifyPassword() {
    const password = document.getElementById('verifyPasswordInput').value;
    const hash     = document.getElementById('verifyHashInput').value;

    const res  = await fetch('/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, hash })
    });
    const data = await res.json();

    if (data.error) { alert(data.error); return; }

    const box = document.getElementById('verifyResult');
    if (data.match) {
        box.className = 'feedback-box strong';
        box.innerText  = '✓ Password matches the hash.';
    } else {
        box.className = 'feedback-box weak';
        box.innerText  = '✗ Password does not match the hash.';
    }
}

// Live sidebar update on keystroke (debounced 200ms)
let debounceTimer = null;
async function liveStrength(password) {
    clearTimeout(debounceTimer);
    if (!password) {
        document.getElementById('sidebar-strength').innerHTML = `
            <div class="sidebar-empty">
                <div class="empty-icon">— — —</div>
                <p>No password entered yet.</p>
            </div>`;
        return;
    }

    debounceTimer = setTimeout(async () => {
        const res  = await fetch('/strength', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        const data = await res.json();
        if (data.strength) showSidebarStrength(data.strength);
    }, 200);
}

// Renders the strength UI into the sidebar
function showSidebarStrength(strength) {
    const colorMap = {
        'Weak':      '#ef4444',
        'Medium':    '#f59e0b',
        'Strong':    '#22c55e',
        'Very Weak': '#ef4444'
    };
    const color = colorMap[strength.label] || '#38bdf8';

    const totalSegs  = 6;
    const filledSegs = Math.min(strength.score, totalSegs);
    let meterHTML    = '<div class="strength-meter">';
    for (let i = 0; i < totalSegs; i++) {
        const filled = i < filledSegs;
        meterHTML += `<div class="meter-seg" style="background:${filled ? color : 'rgba(148,163,184,0.1)'}"></div>`;
    }
    meterHTML += '</div>';

    const labelRow = `
        <div class="strength-label-row">
            <span class="strength-label" style="color:${color}">${strength.label}</span>
            <span class="strength-score">${strength.score} / 6</span>
        </div>`;

    const statsRow = `
        <div class="strength-stats">
            <div class="strength-stat">
                <span class="stat-label">Entropy</span>
                <span class="stat-value">${strength.entropy} bits</span>
            </div>
            <div class="strength-stat">
                <span class="stat-label">Est. crack time</span>
                <span class="stat-value" style="color:${color}">${strength.crack_time}</span>
            </div>
        </div>`;

    const badgeDefs = [
        { key: 'has_upper',   label: 'Uppercase' },
        { key: 'has_lower',   label: 'Lowercase' },
        { key: 'has_digits',  label: 'Numbers'   },
        { key: 'has_symbols', label: 'Symbols'   },
        { key: 'has_length',  label: '12+ chars' }
    ];

    let badgesHTML = '<div class="strength-badges">';
    for (const b of badgeDefs) {
        const has   = strength[b.key];
        badgesHTML += `<span class="strength-badge ${has ? 'badge-yes' : 'badge-no'}">${has ? '✓' : '✗'} ${b.label}</span>`;
    }
    badgesHTML += '</div>';

    let tipsHTML = '';
    if (strength.feedback && strength.feedback.length > 0) {
        tipsHTML = '<ul class="strength-tips">' +
            strength.feedback.map(f => `<li>${f}</li>`).join('') +
            '</ul>';
    }

    document.getElementById('sidebar-strength').innerHTML =
        labelRow + meterHTML + statsRow + badgesHTML + tipsHTML;
}

// Renders the bcrypt hash analysis into card 4
function showHashAnalysis(a) {
    document.getElementById('hashAnalysis').innerHTML = `
        <div class="analysis-grid">
            <div class="analysis-row">
                <span class="analysis-label">Algorithm</span>
                <span class="analysis-value">${a.algorithm}</span>
            </div>
            <div class="analysis-row">
                <span class="analysis-label">Cost Factor</span>
                <span class="analysis-value highlight">${a.cost_factor}</span>
            </div>
            <div class="analysis-row">
                <span class="analysis-label">Iterations</span>
                <span class="analysis-value">${a.rounds}</span>
            </div>
            <div class="analysis-row">
                <span class="analysis-label">Time / Guess</span>
                <span class="analysis-value">${a.seconds_per_guess.toFixed(4)}s</span>
            </div>
        </div>

        <div class="hash-structure">
            <span class="analysis-label" style="display:block; margin-bottom:8px;">Hash Structure</span>
            <div class="hash-segments">
                <div class="hash-seg seg-algo">
                    <span class="seg-value">$${a.algorithm.match(/\$(.+?)\$/)[1]}$</span>
                    <span class="seg-label">Algorithm</span>
                </div>
                <div class="hash-seg seg-cost">
                    <span class="seg-value">${String(a.cost_factor).padStart(2,'0')}$</span>
                    <span class="seg-label">Cost</span>
                </div>
                <div class="hash-seg seg-salt">
                    <span class="seg-value">${a.salt.substring(0, 10)}…</span>
                    <span class="seg-label">Salt (22 chars)</span>
                </div>
                <div class="hash-seg seg-hash">
                    <span class="seg-value">${a.hash_segment.substring(0, 10)}…</span>
                    <span class="seg-label">Hash (31 chars)</span>
                </div>
            </div>
        </div>

        <div class="analysis-note">
            <span class="note-icon">ℹ</span>
            <p>${a.why_secure}</p>
        </div>`;
}

// Toggles password field visibility
function toggleVisibility(id) {
    const input = document.getElementById(id);
    input.type  = input.type === 'password' ? 'text' : 'password';
}

// Copies text from an element to clipboard
function copyText(id) {
    const text = document.getElementById(id).innerText;
    navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
}
