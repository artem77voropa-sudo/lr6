import { csrfFetch } from "./csrf.js";

const element = id => document.getElementById(id);
async function apiFetch(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) throw new Error("Потрібна адреса цього застосунку.");
  return csrfFetch(url, options);
}
function setState(state) {
  element("session-state").textContent = state === "active" ? "Сеанс активний" : state === "anonymous" ? "Не ввійшли" : "Стан сеансу невідомий";
  element("incident-fields").disabled = state !== "active";
  if (state !== "active") element("profile").textContent = "";
}
async function jsonBody(response) {
  if (!response.headers.get("Content-Type")?.includes("json")) throw new Error("Сервер повернув неочікуваний формат відповіді.");
  return response.json();
}
async function showFailure(response, target) {
  const body = await jsonBody(response);
  const details = body.errors ? Object.values(body.errors).flat().join("\n") : body.detail || body.title || "Спробуйте ще раз.";
  element(target).textContent = `HTTP ${response.status}\n${details}`;
}
async function refreshProfile() {
  element("profile").textContent = "";
  try {
    const response = await apiFetch("/api/me");
    if (response.status === 401) { setState("anonymous"); return 401; }
    if (!response.ok) throw new Error(`Профіль недоступний: HTTP ${response.status}`);
    const profile = await jsonBody(response);
    setState("active");
    element("profile").textContent = `Профіль: HTTP ${response.status}\nІм’я: ${profile.userName}\nID: ${profile.id}\nРоль: ${profile.role}`;
    return response.status;
  } catch (error) { setState("unknown"); throw error; }
}
async function submitCredentials(event, route, target, onSuccess) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button");
  button.disabled = true;
  element(target).textContent = "Надсилаємо…";
  try {
    let body = JSON.stringify(Object.fromEntries(new FormData(form)));
    const pending = apiFetch(route, { method: "POST", headers: { "Content-Type": "application/json" }, body });
    body = null;
    form.elements.password.value = "";
    const response = await pending;
    if (!response.ok) { await showFailure(response, target); if (route.endsWith("login")) await refreshProfile(); return; }
    await onSuccess(response);
  } catch { element(target).textContent = "Не вдалося виконати запит. Перевірте з’єднання із сервером."; }
  finally { form.elements.password.value = ""; button.disabled = false; }
}
element("register").addEventListener("submit", event => submitCredentials(event, "/api/auth/register", "register-result", async response => {
  const user = await jsonBody(response);
  element("register-result").textContent = `Реєстрація: HTTP ${response.status}\nІм’я: ${user.userName}\nID: ${user.id}\nІм’я для показу: ${user.displayName}\nТепер увійдіть у свій обліковий запис.`;
  await refreshProfile();
}));
element("login").addEventListener("submit", event => submitCredentials(event, "/api/auth/login", "login-result", async response => {
  element("login-result").textContent = `Вхід: HTTP ${response.status}`;
  element("logout-result").textContent = "";
  await refreshProfile();
}));
element("me").addEventListener("click", () => refreshProfile().catch(error => { element("login-result").textContent = error.message; }));
element("logout").addEventListener("click", async () => {
  try {
    const response = await apiFetch("/api/auth/logout", { method: "POST" });
    if (!response.ok) { await showFailure(response, "logout-result"); return; }
    setState("anonymous");
    for (const id of ["login-result", "register-result", "create-result"]) element(id).textContent = "";
    const status = await refreshProfile();
    element("logout-result").textContent = `Вихід: HTTP ${response.status}\nПовторний GET /api/me: HTTP ${status}`;
  } catch { setState("unknown"); element("logout-result").textContent = "Не вдалося підтвердити вихід. Перевірте з’єднання."; }
});
element("create").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const fields = new FormData(form);
  const button = form.querySelector("button");
  button.disabled = true;
  try {
    const request = { title: fields.get("title"), description: fields.get("description"), severity: fields.get("severity"),
      occurredAtUtc: new Date(fields.get("occurredAtUtc")).toISOString() };
    const response = await apiFetch("/api/incidents", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request) });
    if (response.status === 401) setState("anonymous");
    if (!response.ok) { await showFailure(response, "create-result"); return; }
    const incident = await jsonBody(response);
    element("create-result").textContent = `Створення: HTTP ${response.status}\nID: ${incident.id}\nЗаголовок: ${incident.title}\nСтатус: ${incident.status}\nЧас UTC: ${incident.occurredAtUtc}`;
  } catch { element("create-result").textContent = "Не вдалося створити інцидент. Перевірте час події та з’єднання."; }
  finally { button.disabled = false; }
});
const now = new Date();
element("create").elements.occurredAtUtc.value = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
refreshProfile().catch(error => { element("login-result").textContent = error.message; });
