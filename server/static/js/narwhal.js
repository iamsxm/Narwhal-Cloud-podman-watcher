/**
 * Narwhal Monitor - Frontend Library (narwhal.js)
 * Apple iOS 18 Design interactive utilities, vibrancy effects, and component controllers.
 */

(() => {
  'use strict';

  const ICONS = {
    'sun': `<svg class="nw-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2.5M12 19.5V22M4.93 4.93l1.77 1.77M17.3 17.3l1.77 1.77M2 12h2.5M19.5 12H22M6.7 17.3l-1.77 1.77M19.07 4.93l-1.77 1.77"/></svg>`,
    'moon': `<svg class="nw-icon" viewBox="0 0 24 24"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>`,
    'rotate-cw': `<svg class="nw-icon" viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg>`,
    'arrow-left': `<svg class="nw-icon" viewBox="0 0 24 24"><path d="m12 19-7-7 7-7"/><path d="M19 12H5"/></svg>`,
    'bell': `<svg class="nw-icon" viewBox="0 0 24 24"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>`,
    'bar-chart': `<svg class="nw-icon" viewBox="0 0 24 24"><line x1="12" x2="12" y1="20" y2="10"/><line x1="18" x2="18" y1="20" y2="4"/><line x1="6" x2="6" y1="20" y2="16"/></svg>`,
    'inbox': `<svg class="nw-icon" viewBox="0 0 24 24"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>`,
    'x': `<svg class="nw-icon" viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"/></svg>`,
    'external-link': `<svg class="nw-icon" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" x2="21" y1="14" y2="3"/></svg>`,
    'check': `<svg class="nw-icon" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>`,
    'alert-triangle': `<svg class="nw-icon" viewBox="0 0 24 24"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
  };

  const NW = {
    escapeHtml(value) {
      if (value === null || value === undefined) return '';
      return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    },

    fmtBytes(bytes) {
      const n = Number(bytes || 0);
      if (!Number.isFinite(n) || n <= 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
      const i = Math.floor(Math.log(n) / Math.log(1024));
      const clampedI = Math.min(i, units.length - 1);
      return `${(n / Math.pow(1024, clampedI)).toFixed(clampedI === 0 ? 0 : 2)} ${units[clampedI]}`;
    },

    bpsToMbps(bps) {
      const n = Number(bps || 0);
      if (!Number.isFinite(n)) return 0;
      return n / 1000000;
    },

    buildPolyline(values, maxVal, width = 900, height = 220, padding = 20) {
      if (!Array.isArray(values) || !values.length) return '';
      const len = values.length;
      const effectiveMax = Math.max(1, Number(maxVal) || 1);
      const graphWidth = width - padding * 2;
      const graphHeight = height - padding * 2;

      return values.map((val, idx) => {
        const x = len > 1 ? padding + (idx / (len - 1)) * graphWidth : padding;
        const normalized = Math.min(Math.max(Number(val) || 0, 0), effectiveMax);
        const y = height - padding - (normalized / effectiveMax) * graphHeight;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      }).join(' ');
    },

    semverCompare(v1, v2) {
      const parse = (v) => String(v || '').split(/[+-]/, 1)[0].split('.').map(x => Number(x) || 0);
      const a = parse(v1);
      const b = parse(v2);
      for (let i = 0; i < Math.max(a.length, b.length); i++) {
        const diff = (a[i] || 0) - (b[i] || 0);
        if (diff !== 0) return diff > 0 ? 1 : -1;
      }
      return 0;
    },

    icon(name) {
      return ICONS[name] || '';
    },

    decorateIcons() {
      document.querySelectorAll('[data-icon]').forEach(el => {
        const name = el.getAttribute('data-icon');
        if (name && ICONS[name] && !el.querySelector('svg')) {
          el.insertAdjacentHTML('afterbegin', ICONS[name]);
        }
      });
    },

    initTheme() {
      const current = localStorage.getItem('narwhal-theme') || 'dark';
      document.documentElement.setAttribute('data-theme', current);

      const toggle = document.getElementById('theme-toggle');
      if (toggle) {
        const updateIcon = () => {
          const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
          toggle.innerHTML = isDark ? NW.icon('sun') : NW.icon('moon');
          toggle.setAttribute('aria-label', isDark ? '切换到白天主题' : '切换到夜间主题');
        };
        updateIcon();

        toggle.addEventListener('click', () => {
          const nowDark = document.documentElement.getAttribute('data-theme') !== 'light';
          const next = nowDark ? 'light' : 'dark';
          document.documentElement.setAttribute('data-theme', next);
          localStorage.setItem('narwhal-theme', next);
          updateIcon();
        });
      }
    },

    initSheen(selector = '.card,.kpi-card,.section-card,.panel,.alert-card,.container-card') {
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
      document.querySelectorAll(selector).forEach(card => {
        if (card._sheenInit) return;
        card._sheenInit = true;
        card.addEventListener('mousemove', e => {
          const rect = card.getBoundingClientRect();
          const x = e.clientX - rect.left;
          const y = e.clientY - rect.top;
          card.style.setProperty('--mouse-x', `${x}px`);
          card.style.setProperty('--mouse-y', `${y}px`);
        });
      });
    },

    initReveal(selector = '[data-reveal]') {
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        document.querySelectorAll(selector).forEach(el => {
          el.style.opacity = '1';
          el.style.transform = 'none';
        });
        return;
      }

      if ('IntersectionObserver' in window) {
        const observer = new IntersectionObserver((entries, obs) => {
          entries.forEach(entry => {
            if (entry.isIntersecting) {
              entry.target.style.transition = 'opacity 280ms cubic-bezier(0.16, 1, 0.3, 1), transform 280ms cubic-bezier(0.16, 1, 0.3, 1)';
              entry.target.style.opacity = '1';
              entry.target.style.transform = 'translateY(0)';
              obs.unobserve(entry.target);
            }
          });
        }, { threshold: 0.08 });

        document.querySelectorAll(selector).forEach(el => {
          el.style.opacity = '0';
          el.style.transform = 'translateY(12px)';
          observer.observe(el);
        });
      } else {
        document.querySelectorAll(selector).forEach(el => {
          el.style.opacity = '1';
          el.style.transform = 'none';
        });
      }
    },

    Modal(overlayEl) {
      if (!overlayEl) return { open() {}, close() {} };

      const close = () => {
        overlayEl.hidden = true;
        document.body.style.overflow = '';
      };

      const open = () => {
        overlayEl.hidden = false;
        document.body.style.overflow = 'hidden';
      };

      overlayEl.addEventListener('click', e => {
        if (e.target === overlayEl) close();
      });

      window.addEventListener('keydown', e => {
        if (e.key === 'Escape' && !overlayEl.hidden) close();
      });

      return { open, close };
    },

    toast(message, { error = false, duration = 3000 } = {}) {
      let container = document.querySelector('.nw-toast-container');
      if (!container) {
        container = document.createElement('div');
        container.className = 'nw-toast-container';
        document.body.appendChild(container);
      }

      const toast = document.createElement('div');
      toast.className = `nw-toast ${error ? 'error' : ''}`;
      toast.innerHTML = `${error ? NW.icon('alert-triangle') : NW.icon('check')} <span>${NW.escapeHtml(message)}</span>`;
      container.appendChild(toast);

      setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(12px) scale(0.92)';
        setTimeout(() => toast.remove(), 260);
      }, duration);
    }
  };

  window.NW = NW;
})();
