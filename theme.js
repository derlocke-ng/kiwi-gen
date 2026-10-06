// Kiwi Key Generator - appearance: theme (system/light/dark), accent hue and neutral tint.
// Loaded in <head> so a saved theme applies before the first paint.
(() => {
  const root = document.documentElement;
  const KEYS = { theme: 'kiwi-gen-theme', accent: 'kiwi-gen-contentHue', tint: 'kiwi-gen-headerHue' };
  const DEFAULTS = { theme: 'system', accent: '100', tint: '210' };

  // Storage may be unavailable (private windows); appearance then just isn't remembered.
  const load = key => { try { return localStorage.getItem(KEYS[key]) || DEFAULTS[key]; } catch { return DEFAULTS[key]; } };
  const save = (key, value) => {
    try {
      if (value === DEFAULTS[key]) localStorage.removeItem(KEYS[key]);
      else localStorage.setItem(KEYS[key], value);
    } catch { /* not remembered */ }
  };

  function apply(key, value) {
    if (key === 'theme') {
      if (value === 'system') delete root.dataset.theme;
      else root.dataset.theme = value;
    } else {
      root.style.setProperty(key === 'accent' ? '--accent-hue' : '--tint-hue', value);
    }
  }

  // Earlier versions stored a dark-mode flag instead of a theme.
  try {
    const legacy = localStorage.getItem('kiwi-gen-darkMode');
    if (legacy !== null) {
      localStorage.removeItem('kiwi-gen-darkMode');
      if (!localStorage.getItem(KEYS.theme)) save('theme', legacy === 'true' ? 'dark' : 'light');
    }
  } catch { /* no storage */ }

  for (const key of Object.keys(KEYS)) apply(key, load(key));

  document.addEventListener('DOMContentLoaded', () => {
    const $ = id => document.getElementById(id);
    const popup = $('themePopup');
    const sliders = { accent: $('accentSlider'), tint: $('tintSlider') };
    const labels = { accent: $('accentValue'), tint: $('tintValue') };

    function sync() {
      const theme = load('theme');
      document.querySelectorAll('[data-theme-choice]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.themeChoice === theme)));
      for (const key of ['accent', 'tint']) {
        sliders[key].value = load(key);
        labels[key].textContent = load(key) + '°';
      }
    }

    const close = () => { popup.hidden = true; };
    $('openTheme').addEventListener('click', () => { sync(); popup.hidden = false; });
    $('closeTheme').addEventListener('click', close);
    popup.addEventListener('click', e => { if (e.target === popup) close(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && !popup.hidden) close(); });

    document.querySelectorAll('[data-theme-choice]').forEach(b => b.addEventListener('click', () => {
      save('theme', b.dataset.themeChoice);
      apply('theme', b.dataset.themeChoice);
      sync();
    }));
    for (const key of ['accent', 'tint']) {
      sliders[key].addEventListener('input', () => {
        save(key, sliders[key].value);
        apply(key, sliders[key].value);
        labels[key].textContent = sliders[key].value + '°';
      });
    }
    $('resetTheme').addEventListener('click', () => {
      for (const key of Object.keys(KEYS)) {
        save(key, DEFAULTS[key]);
        apply(key, DEFAULTS[key]);
      }
      sync();
    });
  });
})();
