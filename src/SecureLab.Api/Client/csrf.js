// One in-memory token per page. Cookies remain managed by the browser.
let tokenPromise;
export function clearCsrfToken() { tokenPromise = undefined; }

async function token() {
  tokenPromise ??= fetch("/api/auth/csrf-token", {
    credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" }
  }).then(async response => {
    if (!response.ok) throw new Error("Не вдалося одержати CSRF-токен. Перевірте вхід.");
    const body = await response.json();
    if (!body.token) throw new Error("Відсутній CSRF-токен.");
    return body.token;
  }).catch(error => { clearCsrfToken(); throw error; });
  return tokenPromise;
}

export async function csrfFetch(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) throw new Error("Потрібна адреса цього застосунку.");
  const method = (options.method ?? "GET").toUpperCase();
  const publicCredentials = ["/api/auth/login", "/api/auth/register"].includes(url.pathname);
  const headers = new Headers(options.headers);
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && !publicCredentials) {
    headers.set("X-CSRF-TOKEN", await token());
  }
  const response = await fetch(url, { ...options, method, headers, credentials: "same-origin" });
  if ((response.ok && ["/api/auth/login", "/api/auth/logout"].includes(url.pathname)) || response.status === 401) {
    clearCsrfToken();
  }
  // A failed mutation is never automatically retried.
  return response;
}
