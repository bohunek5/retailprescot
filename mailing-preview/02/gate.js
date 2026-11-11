(() => {
  'use strict';
  const STORAGE = 'prescot-mailing-02-preview-key-v1';
  const form = document.querySelector('#unlock-form');
  const field = document.querySelector('#preview-password');
  const submit = form.querySelector('[type=submit]');
  const status = document.querySelector('#unlock-status');
  let config, worker;
  const fromBase64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const toBase64 = bytes => btoa(String.fromCharCode(...bytes));
  const show = (text, error = false) => { status.textContent = text; status.dataset.error = String(error); };
  const readKey = () => { try { return sessionStorage.getItem(STORAGE); } catch { return null; } };
  const clearKey = () => { try { sessionStorage.removeItem(STORAGE); } catch {} };
  const message = data => new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => reject(new Error('timeout')), 15000);
    channel.port1.onmessage = event => { clearTimeout(timer); channel.port1.close(); resolve(event.data); };
    worker.postMessage(data, [channel.port2]);
  });
  navigator.serviceWorker?.addEventListener('message', event => {
    if (event.data?.type === 'RETAIL_REQUEST_KEY' && event.data.build === config?.build) {
      event.ports[0]?.postMessage({key:readKey()});
    }
    if (event.data?.type === 'RETAIL_LOCKED') clearKey();
  });
  navigator.serviceWorker?.addEventListener('controllerchange', () => { worker = navigator.serviceWorker.controller; });
  async function prepare() {
    if (!window.isSecureContext || !crypto?.subtle || !('serviceWorker' in navigator)) throw new Error('unsupported');
    const response = await fetch('preview-config.json', {cache:'no-store'});
    if (!response.ok) throw new Error('network');
    config = await response.json();
    const registration = await navigator.serviceWorker.register('sw.js', {scope:config.scope, updateViaCache:'none'});
    await registration.update();
    worker = registration.installing || registration.waiting || registration.active;
    if (worker.state !== 'activated') await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('activation')), 20000);
      worker.addEventListener('statechange', () => { if (worker.state === 'activated') { clearTimeout(timer); resolve(); } });
    });
    if (!navigator.serviceWorker.controller || navigator.serviceWorker.controller !== worker || new URL(navigator.serviceWorker.controller.scriptURL).pathname !== config.scope + 'sw.js') {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('controller')), 12000);
        navigator.serviceWorker.addEventListener('controllerchange', () => { clearTimeout(timer); resolve(); }, {once:true});
      });
    }
    worker = navigator.serviceWorker.controller;
  }
  async function unlock(raw, remember = true) {
    const result = await message({type:'RETAIL_UNLOCK',key:raw,build:config.build});
    if (!result.ok) throw new Error(result.reason || 'password');
    if (remember) {
      try { sessionStorage.setItem(STORAGE, raw); }
      catch { show('Przeglądarka nie pozwala zachować dostępu w tej karcie. Po odświeżeniu może poprosić o hasło.'); }
    }
    field.value = '';
    // Preserve both the original asset URL and the application hash route.
    location.reload();
  }
  document.querySelector('.reveal').addEventListener('click', event => {
    const button = event.currentTarget;
    const visible = field.type === 'password';
    field.type = visible ? 'text' : 'password';
    button.setAttribute('aria-pressed', String(visible));
    button.setAttribute('aria-label', visible ? 'Ukryj hasło' : 'Pokaż hasło');
    field.focus();
  });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!field.value || submit.disabled) return;
    submit.disabled = true;
    show('Otwieranie podglądu…');
    try {
      await ready;
      const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(field.value), 'PBKDF2', false, ['deriveBits']);
      const bytes = await crypto.subtle.deriveBits({name:'PBKDF2',salt:fromBase64(config.salt),iterations:config.iterations,hash:'SHA-256'}, material, 256);
      await unlock(toBase64(new Uint8Array(bytes)));
    } catch (error) {
      const invalid = error.message === 'password';
      show(invalid ? 'To hasło nie otwiera podglądu. Sprawdź je i spróbuj ponownie.' : 'Nie udało się otworzyć podglądu. Sprawdź połączenie i odśwież stronę. Użyj aktualnej przeglądarki z obsługą bezpiecznej pamięci witryny.', true);
      if (invalid) { field.setAttribute('aria-invalid','true'); field.focus(); field.select(); }
      submit.disabled = false;
    }
  });
  field.addEventListener('input', () => field.removeAttribute('aria-invalid'));
  const ready = prepare();
  ready.then(async () => {
    const saved = readKey();
    if (!saved) return;
    submit.disabled = true;
    show('Przywracanie dostępu w tej karcie…');
    try { await unlock(saved, false); }
    catch { clearKey(); submit.disabled = false; show('Podgląd został zaktualizowany. Wpisz hasło ponownie.'); }
  }).catch(error => {
    submit.disabled = true;
    show(error.message === 'unsupported' ? 'Ten podgląd wymaga aktualnej przeglądarki oraz połączenia HTTPS. Otwórz go w Safari, Chrome, Firefox lub Edge z włączoną pamięcią witryn.' : 'Nie udało się przygotować podglądu. Sprawdź połączenie i odśwież stronę. Jeśli przeglądarka blokuje pamięć witryn, zezwól na nią dla tego podglądu.', true);
  });
})();
