// --- Feature Start ---
// nginx puts the refused host in `app` (`@denied`, errors.inc), but anyone can
// type this URL by hand: the value is a display string and nothing else. It is
// written as text, never used as a link, and only when it still looks like a
// hostname — otherwise a crafted /denied?app=… turns the page's own sentence
// into whatever the sender wanted it to say.
// --- Feature End ---
const app = new URLSearchParams(location.search).get('app');
if (app && /^[a-z0-9.-]{1,253}$/.test(app)) {
  document.getElementById('headline').textContent =
    `You are signed in, but your groups do not grant access to ${app}.`;
}
