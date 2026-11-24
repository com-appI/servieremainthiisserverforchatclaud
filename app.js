'use strict';

(() => {
  const config = window.CHATCLAUD_CONFIG || {};
  const $ = (id) => document.getElementById(id);
  const apiBase = String(config.apiBaseUrl || '').replace(/\/$/, '');
  const state = {
    auth: null, db: null, user: null, chats: [], activeChatId: null,
    messages: [], createdAt: null, loading: false, controller: null,
    toastTimer: null, authMode: 'login', cooldownUntil: 0,
    streamText: '', streamBody: null, requestSeq: 0
  };

  const els = {
    feed: $('feed'), empty: $('empty'), input: $('input'), send: $('btnSend'), stop: $('btnStop'),
    search: $('btnSearch'), mic: $('btnMic'), menu: $('btnMenu'), side: $('side'), scrim: $('scrim'),
    history: $('history'), toast: $('toast'), settings: $('settings'),
    settingsBack: $('btnSettingsBack'), openSettings: $('btnOpenSettings'),
    openProfile: $('btnOpenProfile'), openAuth: $('btnOpenAuth'),
    profileHint: $('profileHint'), accountHint: $('accountHint'), sideUser: $('sideUser'),
    authOverlay: $('authOverlay'), authClose: $('authClose'), authForm: $('authForm'),
    authName: $('authName'), authNameLabel: $('authNameLabel'), authEmail: $('authEmail'),
    authPassword: $('authPassword'), authSubmit: $('authSubmit'), authGoogle: $('authGoogle'),
    authForgot: $('authForgot'), authError: $('authError'), authTitle: $('authTitle'),
    authSubtitle: $('authSubtitle'), loginTab: $('loginTab'), registerTab: $('registerTab'),
    profileOverlay: $('profileOverlay'), profileClose: $('profileClose'), profileAvatar: $('profileAvatar'),
    profileDisplayName: $('profileDisplayName'), profileEmailText: $('profileEmailText'),
    profileNameInput: $('profileNameInput'), profileSaveBtn: $('profileSaveBtn'),
    profileSignoutBtn: $('profileSignoutBtn'), profileError: $('profileError'),
    btnProfile: $('btnProfile'), btnAuth: $('btnAuth'),
    setHaptic: $('setHaptic'), toggleHaptic: $('toggleHaptic'),
    setEnter: $('setSendEnter'), toggleEnter: $('toggleEnter'),
    setAnimations: $('setAnimations'), toggleAnimations: $('toggleAnimations')
  };

  const preferences = {
    haptics: localStorage.getItem('ghost-haptics') === 'true',
    enterToSend: localStorage.getItem('ghost-enter-send') !== 'false',
    animations: localStorage.getItem('ghost-animations') !== 'false',
    language: localStorage.getItem('chatclaud-lang') || 'en',
    memoryEnabled: localStorage.getItem('chatclaud-memory') !== 'false',
    userName: localStorage.getItem('chatclaud-user-name') || '',
    userAge: localStorage.getItem('chatclaud-user-age') || ''
  };
  /** @type {{name:string,kind:string,content:any}[]} */
  let pendingAttachments = [];
  function getMediaCacheList() {
    try { return JSON.parse(localStorage.getItem('chatclaud-media-cache') || '[]'); }
    catch { return []; }
  }
  function pushMediaCache(entry) {
    try {
      const list = getMediaCacheList();
      list.unshift({ name: entry.name, kind: entry.kind, at: Date.now(), size: String(entry.content || '').length });
      localStorage.setItem('chatclaud-media-cache', JSON.stringify(list.slice(0, 40)));
      updateMediaCacheHint();
    } catch {}
  }
  function clearMediaCache() {
    localStorage.removeItem('chatclaud-media-cache');
    pendingAttachments = [];
    try { renderAttachStrip(); } catch {}
    updateMediaCacheHint();
    toast('Media cache cleared');
  }
  function updateMediaCacheHint() {
    const el = document.getElementById('mediaCacheHint');
    if (!el) return;
    const n = getMediaCacheList().length;
    el.textContent = n ? (n + ' item' + (n === 1 ? '' : 's')) : 'Empty';
  }

  let memoryCache = [];

  async function loadUserMemories() {
    memoryCache = [];
    if (!state.user || !state.db) return [];
    try {
      const snap = await state.db.collection('users').doc(state.user.uid)
        .collection('memories').orderBy('updatedAt', 'desc').limit(12).get();
      memoryCache = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
    } catch (e) {
      console.warn('memory load', e);
    }
    return memoryCache;
  }

  function rankMemories(query) {
    const q = String(query || '').toLowerCase();
    const tokens = q.split(/[^a-zA-Zа-яА-ЯёЁ0-9]+/).filter((t) => t.length > 2);
    return memoryCache
      .map((m) => {
        const text = String(m.text || '');
        const low = text.toLowerCase();
        let score = 0;
        for (const t of tokens) if (low.includes(t)) score += 2;
        if (m.updatedAt && m.updatedAt.toMillis) score += Math.min(2, m.updatedAt.toMillis() / 1e15);
        return { text, score, tags: m.tags || [] };
      })
      .filter((x) => x.text.trim())
      .sort((a, b) => b.score - a.score);
  }

  function formatMemoryBlock(query) {
    const profileLines = [];
    if (preferences.userName) profileLines.push('- User name: ' + String(preferences.userName).slice(0, 40));
    if (preferences.userAge) profileLines.push('- User age: ' + String(preferences.userAge).slice(0, 3));
    if (preferences.memoryEnabled === false) return profileLines.join('\n');
    if (!memoryCache.length) return profileLines.join('\n');
    const ranked = rankMemories(query);
    const top = (ranked.length ? ranked : memoryCache.map((m) => ({ text: m.text, tags: m.tags })))
      .slice(0, 12);
    const mem = top
      .map((m) => {
        const tag = Array.isArray(m.tags) && m.tags[0] ? ('[' + m.tags[0] + '] ') : '';
        return '- ' + tag + String(m.text || '').trim();
      })
      .filter(Boolean);
    return profileLines.concat(mem).join('\n');
  }

  async function saveMemoryFacts(facts) {
    if (!state.user || !state.db || !Array.isArray(facts)) return;
    const batch = state.db.batch();
    const col = state.db.collection('users').doc(state.user.uid).collection('memories');
    const existing = new Set(memoryCache.map((m) => String(m.text || '').toLowerCase()));
    let n = 0;
    for (const raw of facts) {
      const text = String(raw || '').trim().slice(0, 400);
      if (text.length < 8) continue;
      if (existing.has(text.toLowerCase())) continue;
      const ref = col.doc();
      batch.set(ref, {
        text,
        tags: [],
        source: 'chat',
        updatedAt: firebase.firestore.FieldValue.serverTimestamp()
      });
      existing.add(text.toLowerCase());
      n++;
      if (n >= 3) break;
    }
    if (n) {
      try {
        await batch.commit();
        await loadUserMemories();
      } catch (e) {
        console.warn('memory save', e);
      }
    }
  }

  function extractLocalMemoryCandidates(userText, assistantText) {
    const facts = [];
    const u = String(userText || '');
    const patterns = [
      /(?:меня зовут|my name is)\s+([^.,!\n]{2,40})/i,
      /(?:я живу(?: в)?|i live in|i am from|i'm from|я из)\s+([^.,!\n]{2,60})/i,
      /(?:я предпочитаю|i prefer|мне нравится)\s+([^.,!\n]{2,80})/i,
      /(?:я работаю|i work (?:as|at|in))\s+([^.,!\n]{2,80})/i,
      /(?:запомни|remember(?: that)?)\s*[:\-]?\s*([^.,!\n]{4,120})/i,
      /(?:мой язык|my language is)\s+([^.,!\n]{2,40})/i
    ];
    for (const re of patterns) {
      const m = u.match(re);
      if (m) facts.push(m[0].trim().slice(0, 200));
    }
    // Explicit "запомни:" full sentence
    const remember = u.match(/(?:запомни|remember)\s*[:\-]\s*(.+)$/i);
    if (remember) facts.push(remember[1].trim().slice(0, 200));
    return facts;
  }

  function buildConversationSummary(messages) {
    const list = (messages || []).filter((m) => m.role === 'user' || m.role === 'assistant');
    if (list.length < 10) return '';
    const older = list.slice(0, -8);
    const bits = older.slice(-12).map((m) => {
      const t = String(typeof m.content === 'string' ? m.content : '').replace(/\s+/g, ' ').trim();
      return (m.role === 'user' ? 'User: ' : 'AI: ') + t.slice(0, 160);
    });
    return bits.join('\n').slice(0, 1600);
  }



  const I18N = {
    en: {
      settings: 'Settings', profile: 'Profile', chats: 'Chats', about: 'About', assistant: 'Assistant',
      haptics: 'Haptics', enterSend: 'Press Enter to Send', animations: 'Animations',
      model: 'Model', webSearch: 'Web Search', webSearchHint: 'Auto', voice: 'Voice', voiceHint: 'System',
      version: 'Version', language: 'Language', messagePlaceholder: 'Message',
      sources: 'Sources', thinking: 'Thinking…', searching: 'Searching the web…', reading: 'Reading sources…',
      tryAgain: 'Try again', copied: 'Copied', newChat: 'New chat', signIn: 'Sign in', signOut: 'Sign out'
    },
    ru: {
      settings: 'Настройки', profile: 'Профиль', chats: 'Чаты', about: 'О приложении', assistant: 'Ассистент',
      haptics: 'Вибрация', enterSend: 'Enter — отправить', animations: 'Анимации',
      model: 'Модель', webSearch: 'Поиск', webSearchHint: 'Авто', voice: 'Голос', voiceHint: 'Системный',
      version: 'Версия', language: 'Язык', messagePlaceholder: 'Сообщение',
      sources: 'Источники', thinking: 'Думаю…', searching: 'Ищу в сети…', reading: 'Читаю источники…',
      tryAgain: 'Повторить', copied: 'Скопировано', newChat: 'Новый чат', signIn: 'Войти', signOut: 'Выйти'
    },
    de: {
      settings: 'Einstellungen', profile: 'Profil', chats: 'Chats', about: 'Über', assistant: 'Assistent',
      haptics: 'Haptik', enterSend: 'Enter zum Senden', animations: 'Animationen',
      model: 'Modell', webSearch: 'Websuche', webSearchHint: 'Auto', voice: 'Stimme', voiceHint: 'System',
      version: 'Version', language: 'Sprache', messagePlaceholder: 'Nachricht',
      sources: 'Quellen', thinking: 'Denke nach…', searching: 'Suche im Web…', reading: 'Quellen lesen…',
      tryAgain: 'Erneut versuchen', copied: 'Kopiert', newChat: 'Neuer Chat', signIn: 'Anmelden', signOut: 'Abmelden'
    },
    fr: {
      settings: 'Réglages', profile: 'Profil', chats: 'Discussions', about: 'À propos', assistant: 'Assistant',
      haptics: 'Retour haptique', enterSend: 'Entrée pour envoyer', animations: 'Animations',
      model: 'Modèle', webSearch: 'Recherche', webSearchHint: 'Auto', voice: 'Voix', voiceHint: 'Système',
      version: 'Version', language: 'Langue', messagePlaceholder: 'Message',
      sources: 'Sources', thinking: 'Réflexion…', searching: 'Recherche web…', reading: 'Lecture des sources…',
      tryAgain: 'Réessayer', copied: 'Copié', newChat: 'Nouveau chat', signIn: 'Connexion', signOut: 'Déconnexion'
    }
  };

  function t(key) {
    const lang = preferences.language || 'en';
    return (I18N[lang] && I18N[lang][key]) || I18N.en[key] || key;
  }

  function applyI18n() {
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      const key = el.getAttribute('data-i18n');
      if (key) el.textContent = t(key);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
      const key = el.getAttribute('data-i18n-placeholder');
      if (key) el.setAttribute('placeholder', t(key));
    });
    document.querySelectorAll('.lang-btn').forEach((btn) => {
      btn.classList.toggle('active', btn.getAttribute('data-lang') === preferences.language);
    });
    // live agent label if visible
    if (window.__agentUI?.labelEl) {
      /* leave streaming labels as-is unless idle */
    }
  }


  let voiceRecognition = null;
  let voiceListening = false;

  function toast(message) {
    els.toast.textContent = message;
    els.toast.classList.add('on');
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => els.toast.classList.remove('on'), 2600);
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]);
  }

  function safeExternalHttpsUrl(value) {
    try {
      const url = new URL(String(value || ''));
      const host = url.hostname.toLowerCase().replace(/\.$/, '');
      const ipLiteral = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.startsWith('[') || host.includes(':');
      const blockedSuffixes = ['.localhost', '.local', '.internal', '.test', '.example', '.invalid', '.onion', '.arpa'];
      if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) return null;
      if (!host || ipLiteral || !host.includes('.') || host === 'localhost' || blockedSuffixes.some((suffix) => host.endsWith(suffix))) return null;
      url.hostname = host;
      url.hash = '';
      return url;
    } catch { return null; }
  }

  function formatMessage(value) {
    const blocks = [];
    let safe = escapeHtml(value || '');
    safe = safe.replace(/```([\w+-]*)\n?([\s\S]*?)```/g, (_match, language, code) => {
      const key = `%%CODE_${blocks.length}%%`;
      const lang = escapeHtml(language || '');
      blocks.push(`<pre class="code-block"${lang ? ` data-lang="${lang}"` : ''}><code>${code.replace(/\n$/, '')}</code></pre>`);
      return key;
    });
    safe = safe.replace(/^### (.+)$/gm, '<h3>$1</h3>')
      .replace(/^## (.+)$/gm, '<h2>$1</h2>')
      .replace(/^# (.+)$/gm, '<h1>$1</h1>')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.+?)\*/g, '<em>$1</em>')
      .replace(/`([^`\n]+)`/g, '<code>$1</code>')
      .replace(/\n/g, '<br>');
    return safe.replace(/%%CODE_(\d+)%%/g, (_match, index) => blocks[Number(index)] || '');
  }

  function applyPreferences() {
    const pn = document.getElementById('prefName');
    const pa = document.getElementById('prefAge');
    if (pn && pn.value !== preferences.userName) pn.value = preferences.userName || '';
    if (pa && pa.value !== preferences.userAge) pa.value = preferences.userAge || '';
    updateMediaCacheHint();
    document.body.classList.toggle('no-animations', !preferences.animations);
    els.toggleHaptic?.classList.toggle('on', preferences.haptics);
    els.toggleEnter?.classList.toggle('on', preferences.enterToSend);
    els.toggleAnimations?.classList.toggle('on', preferences.animations);
  }

  function tapHaptic() {
    if (preferences.haptics && typeof navigator.vibrate === 'function') navigator.vibrate(8);
  }

  function savePreferences() {
    localStorage.setItem('ghost-haptics', String(preferences.haptics));
    localStorage.setItem('ghost-enter-send', String(preferences.enterToSend));
    localStorage.setItem('ghost-animations', String(preferences.animations));
    localStorage.setItem('chatclaud-memory', String(preferences.memoryEnabled !== false));
    localStorage.setItem('chatclaud-user-name', String(preferences.userName || '').slice(0, 40));
    localStorage.setItem('chatclaud-user-age', String(preferences.userAge || '').slice(0, 3));
    localStorage.setItem('chatclaud-lang', preferences.language || 'en');
    applyI18n();
    applyPreferences();
  }

  function closeSide() {
    els.side.classList.remove('on');
    els.scrim.classList.remove('on');
  }
  function openSide() {
    tapHaptic();
    els.side.classList.add('on');
    els.scrim.classList.add('on');
  }
  function openSettings() {
    tapHaptic();
    closeSide();
    els.settings.classList.add('on');
  }
  function closeSettings() { els.settings.classList.remove('on'); }
  function openProfile() {
    tapHaptic();
    closeSide();
    if (!state.user) return openAuth('login');
    els.profileError.textContent = '';
    els.profileNameInput.value = state.user.displayName || '';
    els.profileOverlay.classList.remove('hidden');
  }
  function closeProfile() { els.profileOverlay.classList.add('hidden'); }

  function updateAuthUI(user) {
    state.user = user || null;
    const signedIn = Boolean(user);
    const displayName = signedIn ? (user.displayName || 'ChatClaud user') : 'Guest';
    const email = signedIn ? (user.email || 'Google account') : 'Sign in to sync chats';
    if (els.profileHint) els.profileHint.textContent = signedIn ? displayName : 'Guest';
    if (els.accountHint) els.accountHint.textContent = signedIn ? 'Signed in' : 'Sign in';
    if (els.sideUser) els.sideUser.textContent = signedIn ? `${displayName} · ${email}` : 'Not signed in';
    if (els.profileDisplayName) els.profileDisplayName.textContent = displayName;
    if (els.profileEmailText) els.profileEmailText.textContent = email;
    if (els.profileNameInput && signedIn) els.profileNameInput.value = user.displayName || '';
    if (els.profileAvatar) {
      els.profileAvatar.textContent = signedIn ? (user.displayName || user.email || 'G').slice(0, 1).toUpperCase() : 'G';
      els.profileAvatar.style.backgroundImage = '';
      if (signedIn && user.photoURL) {
        try {
          const photo = new URL(user.photoURL);
          if (photo.protocol === 'https:') {
            els.profileAvatar.style.backgroundImage = `url("${photo.href}")`;
            els.profileAvatar.textContent = '';
          }
        } catch { /* Ignore invalid photo URLs. */ }
      }
    }
  }

  let openSwipeId = null;
  function closeAllSwipes() {
    openSwipeId = null;
    els.history.querySelectorAll('.swipe-row').forEach((row) => {
      row.classList.remove('is-open', 'revealing');
      const item = row.querySelector('.chat-item');
      if (item) {
        item.style.transition = 'transform .2s cubic-bezier(.2,.8,.2,1)';
        item.style.transform = 'translateX(0)';
        item.classList.remove('open');
      }
    });
  }

  async function renameChat(chat) {
    const next = window.prompt('Rename chat', chat.title || 'New chat');
    if (next == null) return;
    const name = String(next).trim().slice(0, 60);
    if (!name || !state.user || !state.db) return;
    try {
      await state.db.collection('users').doc(state.user.uid).collection('chats').doc(chat.id).set({ title: name, updatedAt: firebase.firestore.FieldValue.serverTimestamp() }, { merge: true });
      chat.title = name;
      renderHistory();
      toast('Renamed');
    } catch (error) {
      console.warn(error);
      toast('Could not rename chat');
    }
  }

  async function deleteChat(chat) {
    if (!window.confirm('Delete "' + (chat.title || 'chat') + '"?')) return;
    if (!state.user || !state.db) return;
    try {
      await state.db.collection('users').doc(state.user.uid).collection('chats').doc(chat.id).delete();
      state.chats = state.chats.filter((c) => c.id !== chat.id);
      if (state.activeChatId === chat.id) {
        if (state.chats[0]) switchChat(state.chats[0].id);
        else newChat();
      } else {
        renderHistory();
      }
      toast('Deleted');
    } catch (error) {
      console.warn(error);
      toast('Could not delete chat');
    }
  }

  function renderHistory() {
    els.history.innerHTML = '';
    openSwipeId = null;
    if (!state.user) {
      const empty = document.createElement('div');
      empty.style.cssText = 'padding:16px 12px;color:#8e8e93;font-size:13px;';
      empty.textContent = 'Sign in to sync your chats';
      els.history.appendChild(empty);
      return;
    }
    if (!state.chats.length) {
      const empty = document.createElement('div');
      empty.style.cssText = 'padding:16px 12px;color:#8e8e93;font-size:13px;';
      empty.textContent = 'No chats yet';
      els.history.appendChild(empty);
      return;
    }
    state.chats.forEach((chat) => {
      const row = document.createElement('div');
      row.className = 'swipe-row';
      row.innerHTML =
        '<div class="swipe-actions"><button type="button" class="del" aria-label="Delete">' +
        '<svg viewBox="0 0 24 24"><path d="M4 7h16"/><path d="M10 11v6M14 11v6"/><path d="M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12"/><path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/></svg>' +
        '<span>Delete</span></button></div>';
      const item = document.createElement('div');
      item.className = 'chat-item' + (chat.id === state.activeChatId ? ' active' : '');
      item.dataset.chatId = chat.id;
      const meta = document.createElement('div');
      meta.className = 'meta';
      const title = document.createElement('div');
      title.className = 'title';
      title.textContent = chat.title || 'New chat';
      const sub = document.createElement('div');
      sub.className = 'sub';
      const date = chat.updatedAt?.toDate ? chat.updatedAt.toDate() : (chat.updatedAt ? new Date(chat.updatedAt) : null);
      sub.textContent = date && !Number.isNaN(date.getTime()) ? date.toLocaleDateString() : 'Saved chat';
      meta.append(title, sub);
      const pencil = document.createElement('button');
      pencil.type = 'button';
      pencil.className = 'pencil';
      pencil.setAttribute('aria-label', 'Rename');
      pencil.innerHTML = '<svg viewBox="0 0 24 24"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4 11.5-11.5z"/></svg>';
      item.append(meta, pencil);
      row.appendChild(item);
      els.history.appendChild(row);

      const DELETE_W = 76;
      let startX = 0, baseX = 0, dx = 0, dragging = false, axis = null;
      const isOpen = () => item.classList.contains('open');
      const setX = (x, animate) => {
        dx = Math.min(0, Math.max(-DELETE_W, x));
        item.style.transition = animate ? 'transform .22s cubic-bezier(.2,.8,.2,1)' : 'none';
        item.style.transform = 'translateX(' + dx + 'px)';
        if (dx < -4) row.classList.add('revealing');
        else row.classList.remove('revealing');
      };
      const openDelete = () => {
        setX(-DELETE_W, true);
        item.classList.add('open');
        row.classList.add('is-open', 'revealing');
        openSwipeId = chat.id;
      };
      const closeDelete = (animate) => {
        setX(0, animate !== false);
        item.classList.remove('open');
        row.classList.remove('is-open', 'revealing');
        if (openSwipeId === chat.id) openSwipeId = null;
      };
      const onStart = (x) => {
        if (openSwipeId && openSwipeId !== chat.id) closeAllSwipes();
        startX = x; baseX = isOpen() ? -DELETE_W : 0; dx = baseX; dragging = true; axis = null;
        item.style.transition = 'none';
      };
      const onMove = (x) => {
        if (!dragging) return;
        const mx = x - startX;
        if (axis === null && Math.abs(mx) > 7) axis = 'x';
        if (axis !== 'x') return;
        setX(baseX + mx, false);
      };
      const onEnd = () => {
        if (!dragging) return;
        dragging = false;
        if (axis !== 'x') { if (!isOpen()) closeDelete(false); return; }
        if (dx < -DELETE_W * 0.35) openDelete();
        else closeDelete(true);
      };
      item.addEventListener('touchstart', (e) => onStart(e.touches[0].clientX), { passive: true });
      item.addEventListener('touchmove', (e) => {
        onMove(e.touches[0].clientX);
        if (axis === 'x') e.preventDefault();
      }, { passive: false });
      item.addEventListener('touchend', onEnd);
      item.addEventListener('touchcancel', onEnd);
      meta.addEventListener('click', () => {
        if (isOpen()) { closeDelete(true); return; }
        if (axis === 'x' && Math.abs(dx - baseX) > 8) return;
        switchChat(chat.id);
        closeSide();
      });
      pencil.addEventListener('click', (e) => {
        e.preventDefault(); e.stopPropagation();
        if (isOpen()) closeDelete(true);
        renameChat(chat);
      });
      row.querySelector('.del').addEventListener('click', (e) => {
        e.preventDefault(); e.stopPropagation();
        deleteChat(chat);
      });
    });
  }

  function bindSourcesToggles(root) {
    (root || document).querySelectorAll('.sources-toggle').forEach((btn) => {
      if (btn.dataset.bound === '1') return;
      btn.dataset.bound = '1';
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const wrap = btn.closest('.sources-wrap');
        const panel = wrap && wrap.querySelector('.sources-panel');
        if (!panel) return;
        const open = panel.hasAttribute('hidden');
        if (open) panel.removeAttribute('hidden');
        else panel.setAttribute('hidden', '');
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
        wrap.classList.toggle('open', open);
      });
    });
  }

  function buildUserContent(text, attachments) {
    const parts = [];
    const body = String(text || '').trim();
    if (body) parts.push({ type: 'text', text: body });
    for (const file of attachments || []) {
      if (file.kind === 'image' && file.content) {
        parts.push({ type: 'image_url', image_url: { url: file.content } });
        parts.push({ type: 'text', text: 'User attached image: ' + file.name + '. Analyze the image.' });
      } else if (file.content) {
        parts.push({
          type: 'text',
          text: 'User attached file (' + file.kind + '): ' + file.name + '\n\n' + String(file.content).slice(0, 14000)
        });
      }
    }
    if (!parts.length) return body || '';
    if (parts.length === 1 && parts[0].type === 'text') return parts[0].text;
    return parts;
  }

  function renderMessages() {
    els.feed.querySelectorAll('.msg, .agent-status').forEach((node) => node.remove());
    if (!state.messages.length) {
      els.empty.style.display = 'grid';
      if (!els.empty.isConnected) els.feed.appendChild(els.empty);
      renderHistory();
      return;
    }
    els.empty.style.display = 'none';
    state.messages.forEach((message, index) => {
      const wrap = document.createElement('div');
      wrap.className = message.role === 'user' ? 'msg user' : 'msg bot';
      if (message.error) wrap.classList.add('error');
      if (message.role === 'user') {
        const bubble = document.createElement('div');
        bubble.className = 'bubble';
        const atts = Array.isArray(message._attachments) ? message._attachments : [];
        if (atts.length) {
          const row = document.createElement('div');
          row.className = 'msg-atts';
          for (const a of atts) {
            if (a.kind === 'image' && a.content) {
              const img = document.createElement('img');
              img.className = 'msg-att-img';
              img.src = a.content;
              img.alt = a.name || 'image';
              row.appendChild(img);
            } else {
              const chip = document.createElement('div');
              chip.className = 'msg-att-file';
              chip.textContent = (a.name || a.kind || 'file').slice(0, 40);
              row.appendChild(chip);
            }
          }
          bubble.appendChild(row);
        }
        const text = typeof message.content === 'string'
          ? message.content
          : (message.content != null ? String(message.content) : '');
        if (text) {
          const t = document.createElement('div');
          t.className = 'msg-text';
          t.textContent = text;
          bubble.appendChild(t);
        }
        wrap.appendChild(bubble);
      } else {
        const body = document.createElement('div');
        body.className = 'body';
        body.innerHTML = message.content ? formatMessage(message.content) : '';
        if (message.sources?.length) body.insertAdjacentHTML('beforeend', renderSourcesHtml(message.sources));
        wrap.appendChild(body);
        if (message.content && !message.error) wrap.appendChild(createActions(message.content, index));
        if (message.error && message.retry) {
          const retry = document.createElement('button');
          retry.className = 'retry';
          retry.type = 'button';
          retry.textContent = t('tryAgain');
          retry.addEventListener('click', () => retryLast());
          wrap.appendChild(retry);
        }
      }
      els.feed.appendChild(wrap);
    });
    renderHistory();
    bindSourcesToggles(els.feed);
    scrollBottom();
  }

  function createActions(text, index) {
    const actions = document.createElement('div');
    actions.className = 'actions';
    actions.innerHTML =
      '<button type="button" aria-label="Copy" title="Copy"><svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M4 16V6a2 2 0 0 1 2-2h10"/></svg></button>' +
      '<button type="button" aria-label="Speak" title="Speak"><svg viewBox="0 0 24 24"><path d="M4 9v6h3l5 4V5L7 9H4z"/><path d="M16 9a3 3 0 0 1 0 6M18.5 7a6 6 0 0 1 0 10"/></svg></button>';
    actions.children[0].addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(text); toast(t('copied')); }
      catch { toast('Could not copy'); }
    });
    actions.children[1].addEventListener('click', () => {
      try {
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.lang = navigator.language || 'en-US';
        speechSynthesis.cancel(); speechSynthesis.speak(utterance);
      } catch { toast('Speech is unavailable'); }
    });
    return actions;
  }

  function scrollBottom() {
    requestAnimationFrame(() => { els.feed.scrollTop = els.feed.scrollHeight; });
  }

  const AgentUI = {
    el: null, labelEl: null, pendingTimer: null, labelTimer: null, lastAt: 0, lastLabel: '',
    ensure() {
      if (this.el?.isConnected) return;
      const el = document.createElement('div');
      el.id = 'agentStatus';
      el.className = 'agent-status';
      el.innerHTML = '<div class="ball-mark" aria-hidden="true"></div><div class="agent-label">' + t('thinking') + '</div>';
      els.feed.appendChild(el);
      this.el = el;
      this.labelEl = el.querySelector('.agent-label');
    },
    show(label) {
      const next = String(label || '').trim();
      if (!next || next === this.lastLabel) return;
      clearTimeout(this.pendingTimer);
      const delay = this.lastAt ? Math.max(0, 400 - (Date.now() - this.lastAt)) : 0;
      this.pendingTimer = setTimeout(() => {
        if (!state.loading) return;
        this.ensure();
        this.el.classList.add('on');
        if (this.labelEl.textContent !== next) {
          clearTimeout(this.labelTimer);
          this.labelEl.classList.add('swap');
          this.labelTimer = setTimeout(() => {
            if (!this.labelEl) return;
            this.labelEl.textContent = next;
            this.labelEl.classList.remove('swap');
          }, 120);
        }
        this.lastLabel = next;
        this.lastAt = Date.now();
        scrollBottom();
      }, delay);
    },
    hide() {
      clearTimeout(this.pendingTimer);
      clearTimeout(this.labelTimer);
      this.pendingTimer = null;
      this.labelTimer = null;
      if (this.el) this.el.classList.remove('on');
      this.labelEl?.classList.remove('swap');
      this.lastLabel = '';
    },
    reset() { this.hide(); this.lastAt = 0; }
  };

  const GHOST_SVG = '<svg viewBox="0 0 64 64" fill="none"><path d="M32 6c-11 0-20 9.2-20 22.2V46c0 1.4 1.5 2.3 2.7 1.6L20 44.2l5.2 5.4c.8.8 2 .8 2.8 0L32 45.6l4-4 4 4c.8.8 2 .8 2.8 0l5.2-5.4 5.3 3.4c1.2.7 2.7-.2 2.7-1.6V28.2C56 15.2 47 6 32 6z" fill="#F2F2F4"/><circle cx="24.5" cy="28" r="3.2" fill="#111"/><circle cx="39.5" cy="28" r="3.2" fill="#111"/></svg>';

  // Public event interface: server events drive the indicator; the UI never guesses a stage.
  window.ChatClaudAgent = {
    emit(type, payload) {
      if (type === 'status') AgentUI.show(typeof payload === 'string' ? payload : payload?.label);
      if (type === 'done' || type === 'error') AgentUI.hide();
    }
  };

  async function loadChats() {
    if (!state.user || !state.db) return;
    try {
      const snapshot = await state.db.collection('users').doc(state.user.uid)
        .collection('chats').orderBy('updatedAt', 'desc').limit(30).get();
      state.chats = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
      renderHistory();
    } catch (error) {
      console.warn('Chat history unavailable:', error.code || error.message);
      toast('Chat history is unavailable. Check Firestore rules.');
    }
  }

  async function saveActiveChat() {
    if (!state.user || !state.db || !state.activeChatId || !state.messages.length) return;
    const firstUser = state.messages.find((message) => message.role === 'user')?.content || 'New chat';
    const title = firstUser.length > 42 ? `${firstUser.slice(0, 42)}…` : firstUser;
    const payload = {
      title,
      messages: state.messages.slice(-24).map((message) => ({ role: message.role, content: String(message.content || '').slice(0, 12000) })),
      createdAt: state.createdAt || firebase.firestore.FieldValue.serverTimestamp(),
      updatedAt: firebase.firestore.FieldValue.serverTimestamp()
    };
    try {
      await state.db.collection('users').doc(state.user.uid).collection('chats').doc(state.activeChatId).set /* memory-hook */(payload, { merge: true });
      state.chats = [{ id: state.activeChatId, ...payload }, ...state.chats.filter((chat) => chat.id !== state.activeChatId)].slice(0, 30);
      renderHistory();
    } catch (error) {
      console.warn('Could not save chat:', error.code || error.message);
      toast('Could not save this chat. Check Firestore rules.');
    }
  }

  function newChat() {
    tapHaptic();
    if (state.loading) stopGeneration();
    state.activeChatId = null;
    state.createdAt = null;
    state.messages = [];
    AgentUI.reset();
    renderMessages();
    closeSide();
    closeSettings();
    els.input.focus();
  }

  async function switchChat(chatId) {
    const chat = state.chats.find((item) => item.id === chatId);
    if (!chat) return;
    if (state.loading) stopGeneration();
    state.activeChatId = chatId;
    state.createdAt = chat.createdAt || null;
    state.messages = Array.isArray(chat.messages) ? chat.messages.map((message) => ({ role: message.role, content: message.content })) : [];
    AgentUI.reset();
    renderMessages();
    closeSide();
  }

  function setLoading(on) {
    state.loading = on;
    els.send.style.display = on ? 'none' : 'grid';
    els.stop.style.display = on ? 'grid' : 'none';
  }

  function showErrorMessage(message, isBusy = false) {
    AgentUI.hide();
    const assistant = state.messages[state.messages.length - 1];
    const text = isBusy ? 'Server is full right now. Please wait and try again in 2.5 minutes.' : message;
    if (assistant?.role === 'assistant') {
      if (!assistant.content) assistant.content = text;
      assistant.error = true;
      assistant.retry = true;
    } else {
      state.messages.push({ role: 'assistant', content: text, error: true, retry: true });
    }
    renderMessages();
  }

  function retryLast() {
    if (Date.now() < state.cooldownUntil) {
      toast(`Wait ${Math.ceil((state.cooldownUntil - Date.now()) / 1000)}s`);
      return;
    }
    const lastAssistant = state.messages[state.messages.length - 1];
    if (lastAssistant?.role === 'assistant' && lastAssistant.error) state.messages.pop();
    const lastUser = state.messages[state.messages.length - 1];
    if (!lastUser || lastUser.role !== 'user') return;
    const retryText = lastUser.content;
    state.messages.pop();
    renderMessages();
    sendMessage(retryText);
  }

  function handlePacket(packet, requestId) {
    if (requestId !== state.requestSeq || !packet || typeof packet !== 'object') return;
    if (packet.type === 'status') {
      window.ChatClaudAgent.emit('status', packet.label || packet.stage || 'Thinking…');
    } else if (packet.type === 'memory') {
      const fact = String(packet.fact || '').trim();
      const category = String(packet.category || 'other');
      if (fact) {
        saveMemoryFacts([fact]).then(() => {}).catch(() => {});
        // tag category if possible
        (async () => {
          if (!state.user || !state.db || preferences.memoryEnabled === false) return;
          try {
            await state.db.collection('users').doc(state.user.uid).collection('memories').add({
              text: fact.slice(0, 400),
              tags: [category],
              source: 'agent',
              updatedAt: firebase.firestore.FieldValue.serverTimestamp()
            });
            await loadUserMemories();
          } catch {}
        })();
      }
    } else if (packet.type === 'sources') {
      const items = Array.isArray(packet.items) ? packet.items : [];
      const assistant = state.messages[state.messages.length - 1];
      if (assistant?.role === 'assistant') assistant.sources = items;
      renderSourcesLive(items);
    } else if (packet.type === 'token') {
      AgentUI.hide();
      if (typeof packet.text === 'string' && packet.text) {
        state.streamText += packet.text;
        const assistant = state.messages[state.messages.length - 1];
        if (assistant?.role === 'assistant') assistant.content = state.streamText;
        // Smooth stream: append text, re-format lightly without full re-render lockup
        if (state.streamBody) {
          state.streamBody.textContent = state.streamText;
        }
        scrollBottom();
      }
    } else if (packet.type === 'done') {
      window.ChatClaudAgent.emit('done');
      // Final pretty render (markdown / sources) once, not every token
      const assistant = state.messages[state.messages.length - 1];
      if (assistant?.role === 'assistant' && state.streamBody) {
        state.streamBody.innerHTML = formatMessage(assistant.content || '');
        if (assistant.sources?.length) {
          state.streamBody.insertAdjacentHTML('beforeend', renderSourcesHtml(assistant.sources));
          bindSourcesToggles(state.streamBody);
        }
      }
    } else if (packet.type === 'error') {
      window.ChatClaudAgent.emit('error');
      const error = new Error(packet.message || 'The server could not complete the request.');
      error.code = packet.code || 'server_error';
      error.retryAfterSec = Number(packet.retryAfterSec) || 0;
      throw error;
    }
  }

  function renderSourcesHtml(sources) {
    const items = (sources || []).filter((item) => item && safeExternalHttpsUrl(item.url)).slice(0, 8);
    if (!items.length) return '';
    const globe = '<svg class="sources-globe-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>';
    const rows = items.map((item) => {
      const parsedUrl = safeExternalHttpsUrl(item.url);
      if (!parsedUrl) return '';
      const domain = parsedUrl.hostname.replace(/^www\./, '');
      const title = escapeHtml(item.title || domain || parsedUrl.href);
      const safeUrl = escapeHtml(parsedUrl.href);
      const safeDomain = escapeHtml(domain);
      const fav = 'https://www.google.com/s2/favicons?domain=' + encodeURIComponent(domain) + '&sz=32';
      const img = '<img class="source-fav" src="' + fav + '" alt="" width="16" height="16" loading="lazy" referrerpolicy="no-referrer"/>';
      return (
        '<a class="source-row" href="' + safeUrl + '" target="_blank" rel="noopener noreferrer">' +
          img +
          '<span class="source-meta"><span class="source-title">' + title + '</span>' +
          '<span class="source-domain">' + safeDomain + '</span></span>' +
        '</a>'
      );
    }).join('');
    if (!rows) return '';
    return (
      '<div class="sources-wrap">' +
        '<button type="button" class="sources-toggle" aria-expanded="false">' +
          globe + '<span>' + t('sources') + '</span><span class="sources-count">' + items.length + '</span>' +
        '</button>' +
        '<div class="sources-panel" hidden>' + rows + '</div>' +
      '</div>'
    );
  }

  function renderSourcesLive(items) {
    // optional subtle status only — cards appear after answer
    if (!items?.length) return;
  }

  async function sendMessage(rawText) {
    const text = String(rawText || '').trim();
    if (state.loading) return;
    if (!text && !pendingAttachments.length) return;
    tapHaptic();
    if (!state.user) { openAuth('login'); toast('Sign in to start a chat.'); return; }
    if (Date.now() < state.cooldownUntil) {
      toast(`Server is full — wait ${Math.ceil((state.cooldownUntil - Date.now()) / 1000)}s`);
      return;
    }
    if (voiceListening && voiceRecognition) { try { voiceRecognition.stop(); } catch {} }
    if (!state.activeChatId) state.activeChatId = crypto.randomUUID();
    state.createdAt = state.createdAt || new Date();
    const userContent = buildUserContent(text, pendingAttachments);
    const displayText = text || pendingAttachments.map((a) => '📎 ' + a.name).join(', ');
    const userVisible = (displayText || (typeof userContent === 'string' ? userContent : '') || text || 'Attachment').slice(0, 8000);
    state.messages.push({ role: 'user', content: userVisible, _apiContent: userContent, _attachments: pendingAttachments.slice() });
    pendingAttachments = [];
    renderAttachHint();
    state.messages = state.messages.slice(-24);
    if (state.messages[0]?.role === 'assistant') state.messages.shift();
    state.streamText = '';
    const requestId = ++state.requestSeq;
    renderMessages();
    els.input.value = '';
    autoSize();
    setLoading(true);
    AgentUI.reset();
    const controller = new AbortController();
    state.controller = controller;
    state.messages.push({ role: 'assistant', content: '' });
    renderMessages();
    state.streamBody = els.feed.querySelector('.msg.bot:last-of-type .body');

    try {
      const token = await state.user.getIdToken();
      const contextMessages = state.messages.slice(0, -1).slice(-23).map((m) => ({
        role: m.role,
        content: m._apiContent != null ? m._apiContent : m.content
      }));
      const last = state.messages[state.messages.length - 1];
      // last is empty assistant; include previous user with api content via slice above
      // Rebuild: context should end with last user
      const forApi = state.messages
        .filter((m) => m.role === 'user' || (m.role === 'assistant' && m.content && !m.error))
        .slice(-23)
        .map((m) => ({ role: m.role, content: m._apiContent != null ? m._apiContent : m.content }));
      // Prefer forApi over contextMessages
      const payloadMessages = forApi.length ? forApi : contextMessages;
      if (contextMessages[0]?.role === 'assistant') contextMessages.shift();
      const response = await fetch(`${apiBase}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          messages: payloadMessages,
          language: preferences.language || 'en',
          memory: formatMemoryBlock(text),
          summary: buildConversationSummary(state.messages),
          hasVision: payloadMessages.some((m) => Array.isArray(m.content) && m.content.some((p) => p && p.type === 'image_url'))
        }),
        signal: controller.signal
      });

      if (!response.ok) {
        let payload = {};
        try { payload = await response.json(); } catch {}
        const error = new Error(payload.message || payload.error || `Server error (${response.status})`);
        error.code = payload.code || (response.status === 429 ? 'busy' : 'http_error');
        error.retryAfterSec = Number(payload.retryAfterSec) || (response.status === 429 ? 150 : 0);
        throw error;
      }
      if (!response.body) throw new Error('This browser does not support streamed responses.');

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let receivedDone = false;
      const processFrame = (frame) => {
        const data = frame.split(/\r?\n/).filter((line) => line.startsWith('data:')).map((line) => line.slice(5).trim()).join('\n');
        if (!data) return;
        try {
          const packet = JSON.parse(data);
          if (requestId !== state.requestSeq) return;
          if (packet.type === 'done') receivedDone = true;
          handlePacket(packet, requestId);
        } catch (error) {
          if (error instanceof SyntaxError) return;
          throw error;
        }
      };
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const frames = buffer.split(/\r?\n\r?\n/);
        buffer = frames.pop() || '';
        frames.forEach(processFrame);
      }
      buffer += decoder.decode();
      if (buffer.trim()) processFrame(buffer);
      if (!receivedDone && state.streamText.trim()) window.ChatClaudAgent.emit('done');
      if (!state.streamText.trim()) {
        const assistant = state.messages[state.messages.length - 1];
        if (assistant?.role === 'assistant' && !assistant.error) {
          assistant.content = 'Could not get a reply. Please try again.';
          assistant.error = true;
          assistant.retry = true;
        }
      }
      try {
        const lastUser = [...state.messages].reverse().find((m) => m.role === 'user');
        const lastAsst = [...state.messages].reverse().find((m) => m.role === 'assistant' && m.content && !m.error);
        if (lastUser && lastAsst) await saveMemoryFacts(extractLocalMemoryCandidates(lastUser.content, lastAsst.content));
      } catch {}
      await saveActiveChat();
    } catch (error) {
      if (requestId !== state.requestSeq) return;
      if (error.name === 'AbortError') {
        window.ChatClaudAgent.emit('done');
        const assistant = state.messages[state.messages.length - 1];
        if (assistant?.role === 'assistant' && !assistant.content) state.messages.pop();
      } else {
        console.error('ChatClaud stream error:', error.code || error.message);
        const busy = error.code === 'busy' || error.retryAfterSec > 0;
        if (busy) state.cooldownUntil = Date.now() + (error.retryAfterSec || 150) * 1000;
        showErrorMessage(error.message || 'The response failed.', busy);
        toast(busy ? 'Server is full — wait 2.5 min' : 'Could not get a response.');
      }
      await saveActiveChat();
    } finally {
      if (requestId === state.requestSeq) {
        window.ChatClaudAgent.emit('done');
        state.controller = null;
        state.streamBody = null;
        setLoading(false);
        renderMessages();
        els.input.focus();
      }
    }
  }

  function stopGeneration() {
    state.requestSeq += 1;
    if (state.controller) state.controller.abort();
    state.controller = null;
    window.ChatClaudAgent.emit('done');
    const assistant = state.messages[state.messages.length - 1];
    if (assistant?.role === 'assistant' && !assistant.content) assistant.content = 'Generation stopped.';
    setLoading(false);
    state.streamBody = null;
    renderMessages();
    saveActiveChat();
  }

  function autoSize() {
    els.input.style.height = 'auto';
    els.input.style.height = `${Math.min(els.input.scrollHeight, 110)}px`;
  }

  function openAuth(mode = 'login') {
    if (!state.auth) { toast('Firebase did not load. Check the project configuration.'); return; }
    setAuthMode(mode);
    els.authOverlay.classList.remove('hidden');
    setTimeout(() => (mode === 'register' ? els.authName : els.authEmail).focus(), 30);
  }
  function closeAuth() { els.authOverlay.classList.add('hidden'); els.authError.textContent = ''; }
  function setAuthMode(mode) {
    state.authMode = mode;
    const registering = mode === 'register';
    els.authTitle.textContent = registering ? 'Create account' : 'Welcome back';
    els.authSubtitle.textContent = registering ? 'Register to save your chats.' : 'Sign in to continue using ChatClaud.';
    els.authName.classList.toggle('hidden', !registering);
    els.authNameLabel.classList.toggle('hidden', !registering);
    els.authName.required = registering;
    els.authPassword.autocomplete = registering ? 'new-password' : 'current-password';
    els.authSubmit.textContent = registering ? 'Create account' : 'Sign in';
    els.authForgot.classList.toggle('hidden', registering);
    els.loginTab.classList.toggle('active', !registering);
    els.registerTab.classList.toggle('active', registering);
    els.loginTab.setAttribute('aria-selected', String(!registering));
    els.registerTab.setAttribute('aria-selected', String(registering));
    els.authError.textContent = '';
  }

  function authErrorMessage(error) {
    const messages = {
      'auth/invalid-email': 'Check the email address.',
      'auth/user-not-found': 'No account found with this email. Register first.',
      'auth/wrong-password': 'Incorrect password.',
      'auth/invalid-credential': 'Incorrect email or password.',
      'auth/email-already-in-use': 'This email is already registered. Choose Sign in.',
      'auth/weak-password': 'Use a password with at least 6 characters.',
      'auth/too-many-requests': 'Too many attempts. Try again later.',
      'auth/network-request-failed': 'No connection. Check your internet.',
      'auth/operation-not-allowed': 'Enable this sign-in method in Firebase Authentication.',
      'auth/unauthorized-domain': 'Add this domain in Firebase Authorized domains.',
      'auth/popup-closed-by-user': 'The sign-in window was closed.'
    };
    return messages[error?.code] || `Sign-in failed (${error?.code || 'unknown'}).`;
  }

  async function submitAuth(event) {
    event.preventDefault();
    const email = els.authEmail.value.trim();
    const password = els.authPassword.value;
    const registering = state.authMode === 'register';
    els.authSubmit.disabled = true;
    els.authError.textContent = '';
    try {
      if (registering) {
        const credential = await state.auth.createUserWithEmailAndPassword(email, password);
        const name = els.authName.value.trim();
        if (name) await credential.user.updateProfile({ displayName: name });
        closeAuth();
        toast('Account created. Welcome to ChatClaud.');
      } else {
        await state.auth.signInWithEmailAndPassword(email, password);
        closeAuth();
        toast('Signed in.');
      }
    } catch (error) {
      els.authError.textContent = authErrorMessage(error);
    } finally {
      els.authSubmit.disabled = false;
      els.authSubmit.textContent = registering ? 'Create account' : 'Sign in';
    }
  }

  async function signInWithGoogle() {
    const provider = new firebase.auth.GoogleAuthProvider();
    provider.setCustomParameters({ prompt: 'select_account' });
    try {
      await state.auth.signInWithPopup(provider);
      closeAuth();
    } catch (error) {
      if (['auth/popup-blocked', 'auth/cancelled-popup-request', 'auth/operation-not-supported-in-this-environment'].includes(error.code)) {
        try { await state.auth.signInWithRedirect(provider); return; } catch (redirectError) { error = redirectError; }
      }
      els.authError.textContent = authErrorMessage(error);
    }
  }

  async function resetPassword() {
    const email = els.authEmail.value.trim();
    if (!email) { els.authError.textContent = 'Enter your email first.'; els.authEmail.focus(); return; }
    try { await state.auth.sendPasswordResetEmail(email); els.authError.textContent = 'Password reset email sent.'; }
    catch (error) { els.authError.textContent = authErrorMessage(error); }
  }

  async function initializeFirebase() {
    const cfg = config.firebase;
    if (!cfg?.apiKey || !cfg?.projectId || !window.firebase) {
      toast('Firebase did not load. Check config.js.');
      return;
    }
    try {
      const app = firebase.apps.length ? firebase.app() : firebase.initializeApp(cfg);
      state.auth = app.auth();
      state.db = app.firestore();
      await state.auth.setPersistence(firebase.auth.Auth.Persistence.LOCAL);
      state.auth.getRedirectResult().catch(() => {});
      state.auth.onAuthStateChanged(async (user) => {
      if (user) { try { await loadUserMemories(); } catch {} }

        updateAuthUI(user);
        if (user) await loadChats();
        else { state.chats = []; renderHistory(); }
      });
    } catch (error) {
      console.error('Firebase init:', error.code || error.message);
      toast('Firebase initialization failed.');
    }
  }

  // Primary navigation and composer.
  els.menu.onclick = openSide;
  els.scrim.onclick = closeSide;
  $('btnSideNew').onclick = newChat;
  $('btnSettingsBack').onclick = closeSettings;
  els.openSettings.onclick = openSettings;
  els.openProfile.onclick = openProfile;
  els.openAuth.onclick = () => state.user ? state.auth.signOut().then(() => { newChat(); toast('Signed out.'); }) : openAuth('login');
  $('btnProfile').onclick = openProfile;
  $('btnAuth').onclick = () => state.user ? state.auth.signOut().then(() => toast('Signed out.')) : openAuth('login');
  els.history.addEventListener('click', (event) => {
    if (event.target.closest('.pencil, .del, .swipe-actions')) return;
    const item = event.target.closest('[data-chat-id]');
    if (item) switchChat(item.dataset.chatId);
  });
  els.send.onclick = () => sendMessage(els.input.value);
  els.stop.onclick = stopGeneration;
  els.input.addEventListener('input', autoSize);
  els.input.addEventListener('keydown', (event) => {
    const shouldSend = event.key === 'Enter' && (preferences.enterToSend ? !event.shiftKey : event.ctrlKey);
    if (shouldSend) { event.preventDefault(); sendMessage(els.input.value); }
  });

  // Search is automatic on the server; no manual search mode.
  if (els.search) { els.search.style.display = 'none'; }

  const attachButton = $('btnAttach');
  const fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.multiple = true;
  fileInput.accept = 'image/*,video/*,.pdf,.txt,.md,.csv,.json,.zip,application/pdf,application/zip,video/mp4,video/webm';
  fileInput.style.display = 'none';
  document.body.appendChild(fileInput);

  function renderAttachHint() {
    const strip = document.getElementById('attachStrip');
    if (attachButton) {
      if (!pendingAttachments.length) {
        attachButton.title = 'Attach image, PDF, text, or ZIP';
        attachButton.classList.remove('has-files');
      } else {
        attachButton.title = pendingAttachments.map((a) => a.name).join(', ');
        attachButton.classList.add('has-files');
      }
    }
    if (!strip) return;
    if (!pendingAttachments.length) {
      strip.hidden = true;
      strip.innerHTML = '';
      return;
    }
    strip.hidden = false;
    const folderSvg = '<svg class="file-icon" viewBox="0 0 24 24" fill="none"><path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.2l1.6 1.6H18.5A2.5 2.5 0 0 1 21 9.1v7.4a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 16.5v-9z" stroke="#c5d4ea" stroke-width="1.5"/><path d="M3 10h18" stroke="#c5d4ea" stroke-width="1.5"/></svg>';
    strip.innerHTML = pendingAttachments.map((a, i) => {
      const name = String(a.name || 'file').replace(/[<>&]/g, '');
      let body = folderSvg;
      if (a.kind === 'image' && a.content) {
        body = '<img src="' + a.content + '" alt=""/>';
      } else if (a.kind === 'pdf') {
        body = '<svg class="file-icon" viewBox="0 0 24 24" fill="none"><path d="M7 3h7l5 5v13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" stroke="#9cc4ff" stroke-width="1.5"/><path d="M14 3v5h5" stroke="#9cc4ff" stroke-width="1.5"/></svg>';
      } else if (a.kind === 'zip') {
        body = folderSvg;
      }
      return '<div class="attach-chip" data-i="' + i + '">' + body +
        '<span class="chip-name">' + name + '</span>' +
        '<button type="button" class="chip-x" data-remove="' + i + '" aria-label="Remove">×</button></div>';
    }).join('');
    strip.querySelectorAll('[data-remove]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const idx = Number(btn.getAttribute('data-remove'));
        if (!Number.isNaN(idx)) {
          pendingAttachments.splice(idx, 1);
          renderAttachHint();
        }
      });
    });
  }

  async function videoFirstFrameDataUrl(file) {
    return new Promise((resolve) => {
      try {
        const url = URL.createObjectURL(file);
        const video = document.createElement('video');
        video.preload = 'metadata';
        video.muted = true;
        video.playsInline = true;
        video.src = url;
        const fail = () => { try { URL.revokeObjectURL(url); } catch {} resolve(null); };
        video.onerror = fail;
        video.onloadeddata = async () => {
          try {
            video.currentTime = Math.min(0.2, (video.duration || 1) * 0.05);
          } catch { /* seek may fail */ }
        };
        video.onseeked = () => {
          try {
            const canvas = document.createElement('canvas');
            const w = Math.min(1280, video.videoWidth || 640);
            const h = Math.round((video.videoHeight || 360) * (w / (video.videoWidth || 640)));
            canvas.width = w; canvas.height = h;
            canvas.getContext('2d').drawImage(video, 0, 0, w, h);
            const data = canvas.toDataURL('image/jpeg', 0.82);
            URL.revokeObjectURL(url);
            resolve(data);
          } catch { fail(); }
        };
        setTimeout(fail, 8000);
      } catch { resolve(null); }
    });
  }

  function compressImageDataUrl(dataUrl, maxEdge, quality) {
    return new Promise((resolve) => {
      try {
        const img = new Image();
        img.onload = () => {
          try {
            let { width, height } = img;
            const edge = Math.max(width, height);
            const scale = edge > maxEdge ? maxEdge / edge : 1;
            width = Math.max(1, Math.round(width * scale));
            height = Math.max(1, Math.round(height * scale));
            const canvas = document.createElement('canvas');
            canvas.width = width;
            canvas.height = height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0, width, height);
            resolve(canvas.toDataURL('image/jpeg', quality));
          } catch {
            resolve(dataUrl);
          }
        };
        img.onerror = () => resolve(dataUrl);
        img.src = dataUrl;
      } catch {
        resolve(dataUrl);
      }
    });
  }

  function readFileAsDataURL(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ''));
      reader.onerror = () => reject(new Error('read failed'));
      reader.readAsDataURL(file);
    });
  }

  async function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ''));
      reader.onerror = () => reject(new Error('read failed'));
      reader.readAsText(file);
    });
  }

  async function extractPdfText(file) {
    // Lightweight: try pdf.js from CDN; fallback to notice
    try {
      if (!window.pdfjsLib) {
        await new Promise((resolve, reject) => {
          const s = document.createElement('script');
          s.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js';
          s.onload = resolve;
          s.onerror = reject;
          document.head.appendChild(s);
        });
        window.pdfjsLib.GlobalWorkerOptions.workerSrc =
          'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
      }
      const data = new Uint8Array(await file.arrayBuffer());
      const pdf = await window.pdfjsLib.getDocument({ data }).promise;
      const maxPages = Math.min(pdf.numPages, 8);
      const chunks = [];
      for (let i = 1; i <= maxPages; i++) {
        const page = await pdf.getPage(i);
        const content = await page.getTextContent();
        const text = content.items.map((it) => it.str).join(' ');
        chunks.push('--- page ' + i + ' ---\\n' + text);
      }
      return chunks.join('\\n').slice(0, 14000);
    } catch (e) {
      return '[PDF attached: ' + file.name + '. Text extraction unavailable in this browser session.]';
    }
  }

  async function extractZipSummary(file) {
    try {
      if (!window.JSZip) {
        await new Promise((resolve, reject) => {
          const s = document.createElement('script');
          s.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
          s.onload = resolve;
          s.onerror = reject;
          document.head.appendChild(s);
        });
      }
      const zip = await window.JSZip.loadAsync(await file.arrayBuffer());
      const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir).slice(0, 40);
      const lines = ['ZIP archive: ' + file.name, 'Files (' + names.length + ' shown):'];
      for (const name of names) {
        lines.push('- ' + name);
      }
      // Extract small text-like files
      let extracted = 0;
      for (const name of names) {
        if (extracted >= 5) break;
        if (!/.(txt|md|json|csv|js|ts|html|css|xml|log)$/i.test(name)) continue;
        const entry = zip.files[name];
        if (entry._data && entry._data.uncompressedSize > 120000) continue;
        const text = await entry.async('string');
        lines.push('\\n--- ' + name + ' ---\\n' + String(text).slice(0, 3000));
        extracted++;
      }
      return lines.join('\\n').slice(0, 14000);
    } catch (e) {
      return '[ZIP attached: ' + file.name + '. Could not list contents.]';
    }
  }

  async function handleFiles(fileList) {
    const files = Array.from(fileList || []).slice(0, 4);
    for (const file of files) {
      const lower = (file.name || '').toLowerCase();
      const type = file.type || '';
      const isVideo = type.startsWith('video/') || /\.(mp4|webm|mov|m4v)$/i.test(lower);
      const maxBytes = isVideo ? 12 * 1024 * 1024 : 4 * 1024 * 1024;
      if (file.size > maxBytes) {
        toast('File too large (max ' + (isVideo ? '12' : '4') + 'MB): ' + file.name);
        continue;
      }
      try {
        if (type.startsWith('image/') || /\.(png|jpe?g|gif|webp|bmp)$/i.test(lower)) {
          const dataUrl = await readFileAsDataURL(file);
          const optimized = await compressImageDataUrl(dataUrl, 1280, 0.82);
          pendingAttachments.push({ name: file.name, kind: 'image', content: optimized || dataUrl });
          pushMediaCache({ name: file.name, kind: 'image', content: optimized || dataUrl });
        } else if (type.startsWith('video/') || /\.(mp4|webm|mov|m4v)$/i.test(lower)) {
          if (file.size > 12 * 1024 * 1024) {
            toast('Video too large (max 12MB): ' + file.name);
            continue;
          }
          const frame = await videoFirstFrameDataUrl(file);
          if (frame) {
            pendingAttachments.push({ name: file.name, kind: 'image', content: frame, _fromVideo: true });
            pushMediaCache({ name: file.name, kind: 'video-frame', content: frame });
            toast('Video frame attached');
          } else {
            pendingAttachments.push({
              name: file.name,
              kind: 'text',
              content: '[Video attached: ' + file.name + '. Could not extract a frame.]'
            });
          }
        } else if (type === 'application/pdf' || lower.endsWith('.pdf')) {
          const text = await extractPdfText(file);
          pendingAttachments.push({ name: file.name, kind: 'pdf', content: text });
        } else if (type === 'application/zip' || lower.endsWith('.zip')) {
          const text = await extractZipSummary(file);
          pendingAttachments.push({ name: file.name, kind: 'zip', content: text });
        } else {
          const text = await readFileAsText(file);
          pendingAttachments.push({
            name: file.name,
            kind: 'text',
            content: ('[File: ' + file.name + ']\\n' + text).slice(0, 14000)
          });
        }
      } catch {
        toast('Could not read ' + file.name);
      }
    }
    renderAttachHint();
    if (pendingAttachments.length) toast(pendingAttachments.length + ' file(s) ready');
  }

  if (attachButton) {
    attachButton.disabled = false;
    attachButton.removeAttribute('aria-disabled');
    attachButton.title = 'Attach image, PDF, text, or ZIP';
    attachButton.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', async () => {
      await handleFiles(fileInput.files);
      fileInput.value = '';
    });
  }


  // Settings.
  els.setHaptic.onclick = () => {
    preferences.haptics = !preferences.haptics;
    savePreferences();
    tapHaptic();
  };
  els.setEnter.onclick = () => { preferences.enterToSend = !preferences.enterToSend; savePreferences(); };
  els.setAnimations.onclick = () => { preferences.animations = !preferences.animations; savePreferences(); };
  const memBtn = document.getElementById('setMemory');
  const memToggle = document.getElementById('toggleMemory');
  if (memBtn && memToggle) {
    const syncMem = () => memToggle.classList.toggle('on', preferences.memoryEnabled !== false);
    syncMem();
    memBtn.onclick = () => {
      preferences.memoryEnabled = preferences.memoryEnabled === false;
      savePreferences();
      syncMem();
      toast(preferences.memoryEnabled === false ? 'Memory off' : 'Memory on');
    };
  }
  document.getElementById('langGrid')?.addEventListener('click', (event) => {
    const btn = event.target.closest('.lang-btn');
    if (!btn) return;
    const lang = btn.getAttribute('data-lang');
    if (!lang || !I18N[lang]) return;
    preferences.language = lang;
    savePreferences();
    toast(t('language') + ': ' + btn.textContent.trim());
  });

  // Authentication and profile dialogs.
  els.authClose.onclick = closeAuth;
  els.authOverlay.addEventListener('click', (event) => { if (event.target === els.authOverlay) closeAuth(); });
  els.loginTab.onclick = () => setAuthMode('login');
  els.registerTab.onclick = () => setAuthMode('register');
  els.authForm.addEventListener('submit', submitAuth);
  els.authGoogle.onclick = signInWithGoogle;
  els.authForgot.onclick = resetPassword;
  els.profileClose.onclick = closeProfile;
  els.profileOverlay.addEventListener('click', (event) => { if (event.target === els.profileOverlay) closeProfile(); });
  els.profileSaveBtn.onclick = async () => {
    if (!state.user) return openAuth('login');
    const displayName = els.profileNameInput.value.trim();
    if (!displayName) { els.profileError.textContent = 'Enter a display name.'; return; }
    els.profileSaveBtn.disabled = true;
    els.profileError.textContent = '';
    try {
      await state.user.updateProfile({ displayName });
      updateAuthUI(state.auth.currentUser || state.user);
      closeProfile();
      toast('Profile updated.');
    } catch { els.profileError.textContent = 'Could not save the profile name.'; }
    finally { els.profileSaveBtn.disabled = false; }
  };
  els.profileSignoutBtn.onclick = async () => {
    try { await state.auth.signOut(); closeProfile(); newChat(); toast('Signed out.'); }
    catch { els.profileError.textContent = 'Could not sign out.'; }
  };
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') { closeAuth(); closeProfile(); closeSide(); closeSettings(); }
  });

  // Speech-to-text is enabled only when the browser supports it.
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (SpeechRecognition) {
    voiceRecognition = new SpeechRecognition();
    voiceRecognition.continuous = false;
    voiceRecognition.interimResults = true;
    voiceRecognition.lang = navigator.language || 'en-US';
    voiceRecognition.onstart = () => { voiceListening = true; els.mic.classList.add('listening'); };
    voiceRecognition.onend = () => { voiceListening = false; els.mic.classList.remove('listening'); };
    voiceRecognition.onerror = (event) => {
      voiceListening = false; els.mic.classList.remove('listening');
      toast(event.error === 'not-allowed' ? 'Microphone permission denied.' : 'Voice input failed.');
    };
    voiceRecognition.onresult = (event) => {
      let text = '';
      for (let i = event.resultIndex; i < event.results.length; i++) text += event.results[i][0].transcript;
      if (text) { els.input.value = `${els.input.value}${els.input.value ? ' ' : ''}${text.trim()}`; autoSize(); }
    };
  }
  els.mic.onclick = () => {
    tapHaptic();
    if (!voiceRecognition) { toast('Voice input is not supported in this browser.'); return; }
    if (voiceListening) { try { voiceRecognition.stop(); } catch {} }
    else { try { voiceRecognition.start(); } catch { toast('Could not start the microphone.'); } }
  };

  applyPreferences();
  renderHistory();
  initializeFirebase();
  fetch(`${apiBase}/api/health`).then((response) => {
    if (!response.ok) throw new Error('Health endpoint unavailable');
  }).catch(() => console.info('ChatClaud health check unavailable.'));
})();
