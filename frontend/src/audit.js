// SPDX-FileCopyrightText: 2026 OpenBerat contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The sessions and access screen (ADR-0026, ADR-0028). It decides nothing:
// every endpoint it calls checks ADMIN_GROUP on the handler's first line,
// independent of the decision cache, so a non-admin gets a page that says 403
// rather than a page that hides itself. Nothing here writes — revocation is
// POST /api/admin/kill/{sub}, run deliberately from a terminal (INSTALL.md §6).
//
// Plain DOM, no framework (ADR-0027). Everything that came from the API is
// written with textContent — an admin types the application name and a user
// types the path, and this page is on the host whose session cookie is valid
// for every application under .apps.<domain> (ADR-0015).

const notice = document.getElementById('notice');

function say(text) {
  notice.textContent = text;
  notice.hidden = false;
}

// --- Feature Start ---
// 403 and an outage must not read alike. The admin endpoints answer 403 to a
// user outside ADMIN_GROUP and 503 when Postgres or Redis is unreachable;
// drawing the second as the first tells an operator their access was taken
// away, and drawing the first as the second sends them to check a database
// that is fine.
// --- Feature End ---
async function api(path) {
  const response = await fetch(path, { credentials: 'same-origin' });
  if (response.status === 403) {
    throw new Error(`You are not in the group that grants the management plane, so ${path.split('?')[0]} refused you.`);
  }
  if (!response.ok) {
    let detail = '';
    try {
      const body = await response.json();
      if (body && typeof body.error === 'string') detail = ` — ${body.error}`;
    } catch (e) {
      detail = '';
    }
    throw new Error(`${path.split('?')[0]} answered ${response.status}${detail}`);
  }
  return response.json();
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

/// Absolute and local. A relative time ("3 minutes ago") is the wrong unit for
/// a record somebody correlates against an nginx log line.
function when(iso) {
  const at = new Date(iso);
  return Number.isNaN(at.getTime()) ? iso : at.toLocaleString();
}

/// Relative, and only on the Live tab. There the question is how stale a row
/// is, not which log line it matches — "4 h ago" answers it at a glance where
/// a timestamp has to be subtracted from now by hand. The absolute time is
/// still one hover away.
function ago(iso) {
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return iso;
  const seconds = Math.max(0, (Date.now() - at.getTime()) / 1000);
  if (seconds < 90) return 'just now';
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} d ago`;
}

/// What `<input type="datetime-local">` reads and writes: local wall clock, no
/// zone. `toISOString` is UTC, so the offset has to come off first or "today"
/// starts at the wrong hour for everyone east or west of Greenwich.
function localField(at) {
  return new Date(at - at.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

function midnight() {
  const at = new Date();
  at.setHours(0, 0, 0, 0);
  return at;
}

/// The button that carries a subject to the Explain tab. The `sub` is the one
/// value both other tables show and the one `explain` insists on — an admin
/// has a username, and typing a UUID out of a table by hand is how the wrong
/// user gets explained.
function toExplain(sub) {
  const button = el('button', 'quiet tiny', '↗');
  button.type = 'button';
  button.title = 'Explain this subject';
  button.setAttribute('aria-label', `Explain access for ${sub}`);
  button.addEventListener('click', () => {
    document.getElementById('ex-user').value = sub;
    show('explain');
    document.getElementById('ex-host').focus();
  });
  return button;
}

// --- Tabs --------------------------------------------------------------------

const VIEWS = ['live', 'history', 'explain'];

function show(name) {
  const view = VIEWS.includes(name) ? name : 'live';
  for (const other of VIEWS) {
    document.getElementById(`view-${other}`).hidden = other !== view;
    document.getElementById(`tab-${other}`).setAttribute('aria-selected', String(other === view));
  }
  if (location.hash.slice(1) !== view) location.hash = view;
  // Live is the one view that goes stale while it is open, so it reloads
  // whenever it is shown. Deliberately not a timer: a poll left running in a
  // background tab is a SCAN of the whole Redis keyspace, for nobody.
  if (view === 'live') live();
}

for (const name of VIEWS) {
  document.getElementById(`tab-${name}`).addEventListener('click', () => show(name));
}
window.addEventListener('hashchange', () => show(location.hash.slice(1)));

// --- Live --------------------------------------------------------------------

const liveRows = document.getElementById('live-rows');
const liveCount = document.getElementById('live-count');

function liveRow(entry) {
  const row = document.createElement('tr');

  const subject = el('td', 'path');
  subject.append(el('span', 'mono', entry.sub));

  // Null is not "unknown identity" — it is a session that has reached no
  // application yet, which is exactly the session this list exists to show.
  const name = el('td');
  if (entry.last_seen_as) {
    name.append(el('span', null, entry.last_seen_as));
  } else {
    name.append(el('span', 'sub', 'not seen at an application yet'));
  }

  const sessions = el('td');
  sessions.append(el('span', 'tag is-allow', String(entry.sessions)));

  // The only staleness signal there is, and it is per subject rather than per
  // session: it comes from the audit record, so it is empty both for a session
  // minted a second ago and for one nobody has touched since Tuesday. Shown as
  // it is, without a threshold and without calling any row "stale" — there is
  // no data here that would justify either.
  const activity = el('td');
  if (entry.last_activity) {
    const stamp = el('span', null, ago(entry.last_activity));
    stamp.title = when(entry.last_activity);
    activity.append(stamp);
  } else {
    activity.append(el('span', 'sub', 'no request recorded'));
  }

  const action = el('td');
  action.append(toExplain(entry.sub));

  row.append(subject, name, sessions, activity, action);
  return row;
}

function live() {
  liveCount.textContent = 'Reading…';
  api('/api/admin/sessions')
    .then((list) => {
      notice.hidden = true;
      liveRows.replaceChildren(...list.map(liveRow));
      const total = list.reduce((n, entry) => n + entry.sessions, 0);
      liveCount.textContent = list.length === 0
        ? 'No session would authenticate right now.'
        : `${total} session${total === 1 ? '' : 's'} across ${list.length} subject${list.length === 1 ? '' : 's'}`;
    })
    .catch((e) => {
      console.error(e);
      liveRows.replaceChildren();
      liveCount.textContent = '';
      say(e.message);
    });
}

document.getElementById('live-refresh').addEventListener('click', live);

// --- History -----------------------------------------------------------------

const filterForm = document.getElementById('filter-form');
const since = document.getElementById('f-since');
const until = document.getElementById('f-until');
const rows = document.getElementById('rows');
const more = document.getElementById('more');
const count = document.getElementById('count');

/// The keyset cursor: (ts, id) of the last row drawn, or null on the first
/// page. Not an OFFSET — rows arrive at the head of this ordering while an
/// admin pages through it, and the retention job deletes from the tail.
let cursor = null;
let drawn = 0;

function filters() {
  const form = new FormData(filterForm);
  const query = new URLSearchParams();
  for (const name of ['actor', 'app', 'decision', 'reason']) {
    const value = (form.get(name) || '').trim();
    if (value) query.set(name, value);
  }
  // datetime-local gives a wall-clock string with no zone; the endpoint wants
  // an instant. Interpreting it as this browser's local time is what the person
  // typing it meant.
  for (const name of ['since', 'until']) {
    const value = form.get(name);
    if (!value) continue;
    const at = new Date(value);
    if (!Number.isNaN(at.getTime())) query.set(name, at.toISOString());
  }
  return query;
}

function auditRow(event) {
  const row = document.createElement('tr');

  const at = el('td');
  at.append(el('span', null, when(event.ts)));
  // The window only means something when the row stands for more than one
  // request; drawing it always would suggest every row is a range.
  if (event.count > 1) {
    at.append(el('span', 'sub', `${when(event.first_seen)} → ${when(event.last_seen)}`));
  }

  const who = el('td');
  who.append(el('span', null, event.actor_name || event.actor_sub));
  if (event.actor_name) who.append(el('span', 'sub', event.actor_sub));
  who.append(toExplain(event.actor_sub));

  const decision = el('td');
  decision.append(el('span', `tag ${event.decision === 'allow' ? 'is-allow' : 'is-deny'}`, event.decision));
  decision.append(el('span', 'sub', event.reason));

  const requests = el('td');
  requests.append(el('span', null, String(event.count)));
  if (event.distinct_path > 1) {
    requests.append(el('span', 'sub', `${event.distinct_path} distinct paths`));
  }

  const path = el('td', 'path');
  path.append(el('span', null, event.first_path));
  const trail = [event.src_ip, event.request_id].filter(Boolean).join(' · ');
  if (trail) path.append(el('span', 'sub', trail));

  row.append(at, who, el('td', null, event.application_slug), decision, requests, path);
  return row;
}

function page() {
  const query = filters();
  if (cursor) {
    query.set('before_ts', cursor.ts);
    query.set('before_id', cursor.id);
  }
  more.disabled = true;
  api(`/api/admin/audit?${query}`)
    .then((list) => {
      rows.append(...list.map(auditRow));
      drawn += list.length;
      if (list.length > 0) {
        const last = list[list.length - 1];
        cursor = { ts: last.ts, id: last.id };
      }
      // The endpoint's own default page size. A short page is the end of the
      // record, not an error.
      more.hidden = list.length < 100;
      more.disabled = false;
      count.textContent = drawn === 0
        ? 'No rows match those filters.'
        : `${drawn} row${drawn === 1 ? '' : 's'}${more.hidden ? '' : ', more below'}`;
    })
    .catch((e) => {
      console.error(e);
      more.hidden = true;
      count.textContent = '';
      say(e.message);
    });
}

function reload() {
  notice.hidden = true;
  cursor = null;
  drawn = 0;
  rows.replaceChildren();
  page();
}

// --- Feature Start ---
// The history opens on today rather than on the whole table. `audit_event` is
// designed to grow without bound and is kept for a year by default (ADR-0022),
// so an unfiltered first page is the oldest question anybody has and the
// slowest one to answer. "All time" is one click away and says what it is.
// --- Feature End ---
filterForm.addEventListener('submit', (event) => {
  event.preventDefault();
  reload();
});
document.getElementById('filter-today').addEventListener('click', () => {
  since.value = localField(midnight());
  until.value = '';
  reload();
});
document.getElementById('filter-clear').addEventListener('click', () => {
  since.value = '';
  until.value = '';
  reload();
});
more.addEventListener('click', page);

since.value = localField(midnight());
reload();

// --- Explain -----------------------------------------------------------------

const explainForm = document.getElementById('explain-form');
const explainOut = document.getElementById('explain-out');

function verdict(answer) {
  const box = el('div', `verdict ${answer.decision === 'allow' ? 'is-allow' : 'is-deny'}`);
  box.append(el('p', 'verdict-line', `${answer.decision} — ${answer.reason}`));

  const facts = el('dl', 'facts');
  const resource = answer.resource || {};
  const pairs = [
    ['Application', resource.application],
    ['Enabled', resource.enabled === undefined ? undefined : String(resource.enabled)],
    // What the rules were actually matched against. null means the URI was
    // refused before any rule was consulted, and saying so is the whole answer
    // for half the tickets this page exists to close.
    ['Matched against', resource.normalised_path === null
      ? 'nothing — the URI was refused before any rule was consulted'
      : resource.normalised_path],
  ];
  for (const [term, value] of pairs) {
    if (value === undefined) continue;
    facts.append(el('dt', null, term), el('dd', null, value));
  }
  box.append(facts);
  return box;
}

function ruleRow(rule) {
  const row = document.createElement('tr');
  if (rule.matched) row.className = rule.expired ? 'is-expired' : 'is-matched';
  row.append(
    el('td', null, rule.effect),
    el('td', null, rule.path_pattern === '' ? '(the whole application)' : rule.path_pattern),
    el('td', null, `${rule.subject_type}: ${rule.subject_id}`),
    // A rule with a null application_id applies to every application
    // (docs/05 rule 4), and an admin reading a surprising verdict needs to see
    // that the rule they are looking at is not this application's.
    el('td', null, rule.application_id === null ? 'every application' : 'this application'),
    el('td', null, rule.expires_at ? when(rule.expires_at) : '—'),
    el('td', null, rule.matched ? (rule.expired ? 'matched, expired' : 'matched') : 'no'),
  );
  return row;
}

function rulesTable(rules) {
  const scroller = el('div', 'scroller');
  const table = document.createElement('table');
  const head = document.createElement('tr');
  for (const label of ['Effect', 'Pattern', 'Subject', 'Applies to', 'Expires', 'This request']) {
    const cell = el('th', null, label);
    cell.scope = 'col';
    head.append(cell);
  }
  const thead = document.createElement('thead');
  thead.append(head);
  const body = document.createElement('tbody');
  body.append(...rules.map(ruleRow));
  table.append(thead, body);
  scroller.append(table);
  return scroller;
}

explainForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const form = new FormData(explainForm);
  // groups is sent even when empty. The endpoint requires the parameter and
  // refuses to guess: answering without it would drop every group rule and
  // report a denial that would not happen.
  const query = new URLSearchParams({
    user: form.get('user').trim(),
    groups: form.get('groups').trim(),
    host: form.get('host').trim(),
    path: form.get('path'),
  });
  explainOut.replaceChildren(el('p', 'hint', 'Asking…'));
  api(`/api/admin/explain?${query}`)
    .then((answer) => {
      const out = [verdict(answer)];
      if (answer.rules.length === 0) {
        out.push(el('p', 'prose', 'No entitlement row applies to that user on that application. A user with no rule is denied — that is a decision, not an absence.'));
      } else {
        out.push(el('p', 'prose', 'Every row the decision walked, in the order it walked them. A deny that matches wins over any allow.'));
        out.push(rulesTable(answer.rules));
      }
      explainOut.replaceChildren(...out);
    })
    .catch((e) => {
      console.error(e);
      explainOut.replaceChildren(el('p', 'refusal', e.message));
    });
});

// --- The header, shared with the portal --------------------------------------

api('/api/me')
  .then((me) => {
    document.getElementById('whoami').textContent = `Signed in as ${me.username}`;
  })
  .catch(() => {});

const signout = document.getElementById('signout');
signout.addEventListener('click', (event) => {
  event.preventDefault();
  fetch('/api/logout', { method: 'POST', credentials: 'same-origin' })
    .catch((e) => console.error(e))
    .finally(() => { location.href = signout.href; });
});

show(location.hash.slice(1));
