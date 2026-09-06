// The portal grants nothing. This list is whatever /api/apps returned, and
// /api/apps is policy::decide run over the rules the PEP itself applies
// (docs/02) — so a button here is not a second opinion about access.

const apps = document.getElementById('apps');
const notice = document.getElementById('notice');

function say(text) {
  notice.textContent = text;
  notice.hidden = false;
}

async function json(path) {
  const response = await fetch(path, { credentials: 'same-origin' });
  if (!response.ok) throw new Error(`${path} answered ${response.status}`);
  return response.json();
}

// --- Feature Start ---
// Everything an admin typed is written as text, never as markup: the portal is
// the one host every user opens, and the session cookie it carries is valid for
// every application on .apps.<domain> (ADR-0015). An application named
// `<img onerror=...>` would otherwise be stored XSS with that cookie in reach.
// --- Feature End ---
function button(app) {
  const link = document.createElement('a');
  link.className = 'app';
  link.href = app.url;
  const icon = document.createElement('span');
  icon.className = 'icon';
  icon.textContent = app.icon || app.name.slice(0, 1).toUpperCase();
  const text = document.createElement('span');
  text.className = 'app-text';
  const name = document.createElement('span');
  name.className = 'app-name';
  name.textContent = app.name;
  const host = document.createElement('span');
  host.className = 'app-host';
  // Two applications can carry the same name and only the hostname tells them
  // apart. `url` is built from a validated `external_hostname`, but a throw
  // here would take the whole list down and draw as an outage, which it is not.
  try {
    host.textContent = new URL(app.url).host;
  } catch (e) {
    host.hidden = true;
  }
  text.append(name, host);
  link.append(icon, text);
  return link;
}

// --- Feature Start ---
// An empty list and a failed call must not look alike. /api/apps answers 503
// when Postgres is down, and drawing that as "you can reach nothing" tells the
// user their access was revoked when the truth is an outage — the same
// confusion /readyz exists to resolve (docs/02).
// --- Feature End ---
json('/api/apps')
  .then((list) => {
    if (list.length === 0) {
      say('You have access to no applications. Ask whoever administers access to add you to the right AD group.');
      return;
    }
    apps.append(...list.map(button));
  })
  .catch((e) => {
    console.error(e);
    say('The application list could not be loaded. This is an outage, not a change to your access — try again shortly.');
  });

json('/api/me')
  .then((me) => {
    document.getElementById('whoami').textContent = `Signed in as ${me.username}`;
  })
  .catch(() => {});

// --- Feature Start ---
// All three logout steps happen in POST /api/logout, in the order docs/02
// fixes; the href is only the fallback for a browser that never ran this file.
// A failed call still sends the browser on: the link is steps 1 and 2 on its
// own, and leaving somebody signed in because the cache could not be cleared is
// the worse of the two failures.
// --- Feature End ---
const signout = document.getElementById('signout');
signout.addEventListener('click', (event) => {
  event.preventDefault();
  fetch('/api/logout', { method: 'POST', credentials: 'same-origin' })
    .catch((e) => console.error(e))
    .finally(() => { location.href = signout.href; });
});
