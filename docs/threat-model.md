# Модель загроз ЛР6

Автор: Воропаєв Артем Максимович, КБ-41. Рівень: Добре. Дата: 09.11.2026.

Система: браузер → ASP.NET Core minimal API → Identity/EF Core/Npgsql → PostgreSQL. Вихідний стан: власна ЛР5 v0.5.0, 9cdc1cbe01eaeb48b058664e8521758fe3b348ff. Окремий стенд ЛР6: localhost:5086, securelab_lr06. Production-профіль перевірявся локально, без публікації в інтернет.

## Активи

```text
Недовірений browser / інший origin
        | HTTP input, credentials, cookies + request token
        v
API: validation -> authentication -> authorization / CSRF
        | параметризовані значення, дозволені дії
        v
Identity / EF Core -> PostgreSQL
        | дозволений DTO
        v
Browser: textContent + CSP

API failure -> safe Problem Details + traceId
            -> локальна diagnostic/audit подія з тим самим trace
```

- Цілісність інцидентів, статусів та історії переходів.
- Межа власника/Analyst, захищені коментарі й безпечні DTO.
- Password hashes Identity, authentication/antiforgery cookies та request tokens.
- Доступність пошуку й входу; конфігурація та журнали.

## Межі довіри і перевірки

| Межа / загроза | Контроль | Конкретний доказ |
|---|---|---|
| HTTP body/query → сервер; невалідні значення | DTO, server validation до запису | CreateIncidentTests.T02_InvalidDto_Returns400WithoutWriting; status Unknown → 400/errors.status |
| Введення → SQL; зміна структури запиту | EF parameterization, allowlist sort, literal wildcard handling | SearchRegressionTests.T04/T05, Search_TreatsWildcardCharactersLiterally_InTitleAndDescription |
| Cookie → principal; підроблена ідентичність | Identity login, verified claims, 401/403 без redirect | AuthenticationSecurityTests.A01/A02/A03/A07; CookieAndRateLimitTests |
| Principal → incident/child | IncidentAccess і server-side owner/Analyst | AuthorizationTests.A04/A05/A07/A12, Bob → 404, Morgan → 200 у Chrome |
| Сторінка → cookie-authenticated mutation | Antiforgery до handler, серверний owner/role | CsrfSecurityTests (12 cases); REG-CSRF-01-browser |
| Збережений текст → DOM | textContent, enforced CSP | 25 браузерних checks, description/comment marker не виконується навіть із CSP bypass у тестовому браузері |
| Інший origin → читання відповіді | точний Dev origin 4173, GET, обмежений header, credentials; Production без CORS policy | cors-4173/4174-simple/preflight/cookie; direct HTTP показує межу CORS |
| Запити → ресурси процесу/БД | search 20/10s на Guid principal або IP; login 10/min на IP | SearchRateLimitTests (дві квоти, recovery); LoginLimit_TenPerMinute_SharedClients_ThenRecovers |
| Exception → зовнішня відповідь/внутрішня діагностика | SafeExceptionHandler, safe Problem Details, headers OnStarting | ProductionHardeningTests, before/after-error.json, error-correlation.json |
| Привілейована дія → аудит | allow/deny subject/action/resource/result/time/trace | LR06_Triage_DeniedAndAllowed_AreAudited_AfterObservedState; audit-events.json |

## Entry points

GET /api/incidents, /api/incidents/{id}, /api/incidents/severity-summary, /api/incidents/search; GET child /api/incident-comments/{id}; POST create; PUT/DELETE own incident; POST triage; POST register/login/logout; GET me/session-check/csrf-token; /health; статичні index/auth-lab/browser-lab; Development OpenAPI/Scalar.

Фактичний mutation-периметр і джерела звірки наведено в security-review.md. PATCH у цій реалізації не опубліковано. Child endpoint тільки читає. Token endpoint не виконує доменну мутацію, але змінює antiforgery cookie і вимагає входу.

## Межі й прийняті ризики

Локальні синтетичні дані, один API-процес, один PostgreSQL. Redis, розподілений limiter, реальний TLS, reverse proxy, зовнішні CI, повна історія Git і production deployment не перевірялися. Тести не доводять відсутності всіх можливих атак.

Успадкований /api/incidents/search з ЛР2 лишається публічним глобальним пошуком по навчальних даних; limiter не є ownership check. Захищені list/details/child мають іншу політику. Для реальних конфіденційних даних це неприйнятно без окремого погодження та поширення resource authorization на search. Відповідальний: автор, до реального розгортання.

Login/register не спираються на наявну cookie для дозволу. Login-CSRF та abuse реєстрації винесені за погоджену реалізацію; login quota лише обмежує спроби. XSS власного origin може обходити CSRF, тому DOM-захист збережено. Development cookies на HTTP не мають Secure — це локальний профіль, не production-рекомендація.

Навчальний відомий пароль локальної БД лишається у starter-конфігурації тільки для loopback. Приватний пароль seed-акаунтів зберігається поза Git через DPAPI/env. Для production потрібні окремі credentials, least privilege, TLS і захищене зберігання ключів Data Protection.
