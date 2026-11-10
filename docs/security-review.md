# Security review SecureLab — ЛР6

Воропаєв Артем Максимович (Voropayev Artem Maksymovych), КБ-41. Рівень: **Добре**. Дати перевірки: 09–10.11.2026. Review-start: **9cdc1cbe01eaeb48b058664e8521758fe3b348ff**, власний v0.5.0. SDK: 10.0.403. Поточна реалізація перевірена в робочій гілці lab/6-hardening-review. Прив’язка до остаточного merge commit додається під час експорту після виконання автором Git-процедури; результати робочого дерева не видаються за перевірку ще не створеного commit.

## 1. Executive summary

Репозиторій для подання ЛР6: https://github.com/artem77voropa-sudo/lr6. Git-публікацію та фінальну перевірку merge виконує автор за docs/run-lab06.md.

Перевірено власний ASP.NET Core/Identity/EF Core/PostgreSQL застосунок та браузерні клієнти після ЛР5. Виправлено дві відтворені проблеми: відсутність antiforgery-перевірки на cookie-authenticated змінах і втрату захисних заголовків на unexpected 500. Додано обмеження пошуку та аудит успішного переходу New → Triaged. Повний локальний regression pack: **107 passed, 0 failed, 0 skipped**; Chrome: **25 успішних перевірок**. Прямі HTTP-спостереження підтверджують safe 500, кореляцію trace та дозволений/заборонений переходи. Межі: один локальний процес, синтетичні дані; публічний legacy search, login-CSRF, production TLS та операційне зберігання журналів залишаються окремими ризиками.

## 2. Scope та exclusions

Scope: усі поточні tracked files, нові файли реалізації ЛР6, конфігурація, dependencies, фактичні routes, client calls, PostgreSQL і журнали локального прогону. Початково Git відстежував 182 файли. Точні matching lines і класифікації — secret-match-review.csv; актуальні лічильники — secret-audit.json.

Повна історія Git, stash, інші клони, зовнішні CI, реальні користувачі, публічний deployment, reverse proxy, TLS-сертифікати та Redis не перевірялись. Advanced variant рівня «Відмінно» не обирався. Наявні evidence попередніх ЛР є історичними, не підміняють перевірки ЛР6.

## 3. System overview і trust boundaries

Див. threat-model.md: browser → API → Identity/EF Core → PostgreSQL; окремі межі authentication, resource authorization, CSRF, SQL, DOM, CORS, rate limiting та logs. Кожна межа пов’язана з конкретним test або HTTP/browser evidence. Клієнт не визначає owner/role. Token не є authentication artifact і не надає доступу до чужого ресурсу.

## 4. Methodology та test environment

Windows, .NET SDK 10.0.403, xUnit/WebApplicationFactory, фактичні EF Core/Npgsql/PostgreSQL, Google Chrome (точна версія у fixed-browser.json). API http://localhost:5086; probes localhost:4173 і :4174. БД securelab_lr06 на loopback:55432. Reset обмежений цією БД й виконується до Act; тести послідовні, окремі fixtures очищуються після assertions. БД ЛР4/ЛР5 не очищувались.

Baseline v0.5.0: 90 tests passed. Before F-01 і F-02 отримано на цьому snapshot в окремій БД до змін. Фіксована версія: 107 tests passed, збережені назви/результати в regression-tests.json. Повний локальний TRX і raw logs зберігаються поза Git у C:\dev\lr06-local.

Команда повного прогону: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\dev\lr06-local\Test-Lab06.ps1`. Вона запускає dotnet test SecureLab.sln -c Release --no-restore після локального reset; exit 0. Браузер: Check-Browser-Lab06.ps1 → lab06-browser-checks.py --stage fixed, exit 0. Перед Git-фіксацією результати скопійовано до docs/evidence/lr06; подальші прогони пишуть поза Git.

Production запуск: Start-Lab06.ps1 -Profile Production, --no-launch-profile. Environment підтверджено консольним журналом. ApplyMigrationsOnStartup=false, AllowReset=false у базовій конфігурації. Broken-профіль змінює тільки локальний процес на недоступний порт 54399; звичайний login дає реальний provider failure. Додаткового debug route немає. Після досліду відновлено Development і /health 200.

Production HTTPS cookie-aware перевірки виконано через TestServer: це перевірка поведінки middleware, не доказ реального TLS. Прямий Production HTTP перевірив /health 200, /api/me 401 без Location, /openapi/v1.json 404. /scalar/v1 → 200 text/html є SPA fallback, не Scalar. HSTS на локальному HTTP відсутній; реальний HTTPS/HSTS поза scope.

## 5. Findings summary

| ID | Пріоритет і вплив | Статус / retest |
|---|---|---|
| F-01 | Високий: cookie-мутатор не перевіряв намір через antiforgery; браузерна експлуатованість залежить від CORS/SameSite | Виправлено; REG-CSRF-01, 10 негативних/позитивних пар + browser |
| F-02 | Середній: аварійний шлях втрачав CSP/nosniff/referrer-policy | Виправлено; ProductionHardeningTests і фактичні before/after-error.json |

Пріоритет F-01 вищий через можливу зміну стану від імені сесії. F-02 — послаблення defense-in-depth, а не самостійно доведений витік чи XSS.

## 6. Detailed findings

Окремі файли findings/F-01-csrf.md і findings/F-02-error-headers.md містять передумови, reproduction, impact, root cause, fix, retest, positive control та residual risk. Аудит дозволеного triage додано як hardening; він не видається за третю незалежно відтворену знахідку.

## 7. Regression results

| Контроль | Test / доказ | Результат і межа |
|---|---|---|
| SQLi, T-04/T-05 | SearchRegressionTests, включно з literal wildcard та full expected IDs | Параметризований пошук; апостроф збережено; не стверджує безпеку будь-якого майбутнього SQL |
| Validation T-01/T-02/T-03/T-09 | CreateIncidentTests; http-review.json | 400/errors конкретного поля без запису; валідні 201; конфлікт 409 |
| Authentication A-01…A-07 | AuthenticationSecurityTests, RegistrationSecurityTests, IdentitySeedTests | 401/403 без redirect, server owner, safe DTO, logout; справжні cookies |
| Authorization/IDOR A-04/A-05/A-07/A-12 | AuthorizationTests | Чужі зміни не відбуваються; list/details/child обмежені; Analyst тільки погоджений перехід |
| XSS | BrowserSecurityTests, description/comment-marker, safe-dom-with-csp-bypassed | Текст лишається текстом; marker не виконується; точний апостроф/HTML/Unicode/4000 символів |
| CSRF REG-CSRF-01 | CsrfSecurityTests, REG-CSRF-01-browser | Без/з невалідним token 400 та незмінність; валідний token 201/204 і зміна; старий principal token відхилено |
| CORS | BrowserSecurityTests, cors-4173/4174 × simple/preflight/cookie | 4173 читає дозволений GET, 4174 не читає; direct HTTP може одержати відповідь — CORS не authentication |
| Search limiter | SearchRateLimitTests | 20 допущено, наступний 429; інший Guid має квоту; після 11 s відновлення; anonymous same-IP ділить квоту |
| Login limiter | LoginLimit_TenPerMinute_SharedClients_ThenRecovers | 10 допущено, 11-й 429, після 62 s login 204; /health не заблоковано |
| Error і headers | ProductionHardeningTests, http-review.json, after-error.json | static/API 200, validation 400, 404, 500 мають заголовки; safe body та matching trace |

Усі перевірки стану виконуються до cleanup. Негативні CSRF тести явно прибирають header; звичайні legitimate tests одержують token opt-in, тому захист не маскує потрібну DTO/authorization перевірку.

## 8. Hardening controls

Cookie profile: окрема .SecureLab.LR06.Identity, HttpOnly, SameSite=Lax, Development SameAsRequest, Production Always Secure. Antiforgery cookie — HttpOnly/Strict, Secure у Production; request token лише в пам’яті сторінки. CSP enforced, script-src 'self', без unsafe-inline; DOM використовується через textContent. Headers реєструються через OnStarting перед exception handler.

Джерела звірки mutation-периметра: фактичні MapPost/MapPut/MapDelete в Lab02Endpoints, Lab03Identity, IncidentMutationEndpoints; Development OpenAPI; fetch-виклики auth-lab.js/browser-lab.js/csrf.js. Таблиця враховує семантику, а не тільки автоматичний OpenAPI опис. Історичні .http/scripts ЛР2–5 не є поточним клієнтом ЛР6.

| ID / Method + route | Зміна і джерело | Cookie / browser | Validation / regression |
|---|---|---|---|
| SC-01 POST /api/incidents | create; Lab02Endpoints + обидві форми | так / так | explicit filter; REG-CSRF-01 create |
| SC-02 PUT /api/incidents/{id:guid} | title/description; IncidentMutationEndpoints + Console/script | так / так | explicit filter; REG-CSRF-01 update |
| SC-03 DELETE /api/incidents/{id:guid} | власний New; IncidentMutationEndpoints + script | так / так | explicit filter; REG-CSRF-01 delete |
| SC-04 POST /api/incidents/{id:guid}/triage | New → Triaged; IncidentMutationEndpoints | так / так | explicit filter; REG-CSRF-01 triage; audit |
| SC-05 POST /api/auth/logout | SignOut; Lab03Identity + auth-lab.js | так / так | explicit filter до SignOut; REG-CSRF-01 logout |
| SC-06 POST /api/auth/login | створення auth artifact; Lab03Identity + auth-lab.js | ні / так | публічні credentials; login limiter; ризик login-CSRF не усунено |
| SC-07 POST /api/auth/register | account; Lab03Identity + auth-lab.js | ні / так | публічний DTO/Identity flow; abuse поза реалізованим limiter |

PATCH відсутній; child — GET; GET token вимагає authentication, має no-store та не дозволяє CORS-читання. Клієнтський helper включено в обидві сторінки з мутаціями. Звичайний index тільки читає. Після F5, нового tab та зміни сесії token одержується для поточного principal.

Search limiter не змінює q/sortBy чи SQL; partition використовує verified Guid, а не введений X-User або X-Forwarded-For. Для anonymous — фактичний RemoteIpAddress. Поточні ліміти локальні для процесу; shared multi-instance стан не заявляється. CORS є тільки в Development; token endpoint додатково виключений із цієї policy.

## 9. Dependency and secret audit

Locked restore завершився успішно. `dotnet list SecureLab.sln package --vulnerable --include-transitive --format json` і текстовий варіант використали NuGet source api.nuget.org; жодної відомої vulnerable package у двох projects не повідомлено. Фактичні результати: dependency-audit.json/.txt, audit-restore.txt. Це стан feed на дату перевірки, не гарантія відсутності майбутніх advisory.

| Рішення | Причина | Owner / next action |
|---|---|---|
| Зберегти перевірені locked versions | Direct/transitive audit не повідомив advisory; не оновлювати навмання заради зміни номера | Автор; повторити audit перед поданням/оновленням |
| Не вводити NuGetAuditSuppress чи послаблення warnings | Немає advisory, для якої потрібен temporary acceptance | Автор; нову advisory оцінювати адресно |

Систематичний пошук: поточні git ls-files та нові файли; case-insensitive password/secret/token/connection string/api key/private key/authorization/cookie; окремо private-key/cloud-token markers і точний приватний seed password без його друку. Кожний matching рядок має path, line, scope і класифікацію в secret-match-review.csv. Збіги CancellationToken, Identity schema/PasswordHash, cookie/header names, env reads, tests/assertions і навчальні описи не є автоматично витоком.

Відомий публічний навчальний DB credential у compose, Development config і design-time factory прийнятий лише для loopback: PostgreSQL bind 127.0.0.1. Це не production секрет. Синтетичний unreachable DB credential у ProductionHardeningTests не відкриває БД. Приватний seed password не знайдено в перевірених файлах; він завантажується з локального DPAPI/env. Історію не скановано; у разі реального витоку видалити один рядок недостатньо — потрібні ротація і встановлення меж поширення. Бінарні файли виведені окремо в secret-audit.json; вони не видаються за перевірений текст.

Журнали переглянуто для шести сценаріїв: login success, login rejected, denied triage, validation 400, unexpected 500, successful triage. Audit містить subject/action/resource/result/time/trace; diagnostic 500 — exception type/time/trace. Validation має мінімальний request-completed контекст у тимчасовому ReviewDiagnostics профілі, без body. Вісім фактичних приватних значень поточного HTTP-сеансу (пароль, cookies, tokens, synthetic wrong password) не знайдено в його raw log. У broken log також немає синтетичних credentials. Raw logs не додаються до Git. Стандартний EF diagnostic SQL може бути в локальному журналі; parameter values не вмикалися. Це обмежений огляд цих запусків, не гарантія всіх майбутніх логів.

## 10. Residual risks

- Legacy search публічний і глобальний для навчальних даних; перед реальними конфіденційними даними потрібне окреме ownership рішення. Автор, до deployment.
- Login-CSRF та registration abuse потребують окремої policy; погоджений CSRF-периметр охоплює п’ять cookie-authenticated мутацій. Автор, наступний review.
- HTTP loopback, відкритий study DB credential, локальні Data Protection keys, in-memory rate limits не є production deployment. Потрібні TLS, secrets/keys management, журналювання з контрольованим доступом і за потреби shared limiter.
- Static screenshot/успішний тест стосується конкретного запуску; Git finalization і перевірка merge виконуються окремо за run-lab06.md.

## 11. Conclusion

У перевіреному локальному стані усунуто F-01/F-02, збережено легітимні браузерні сценарії та пройдено regression pack доброго рівня. Доказ пов’язує відмову зі станом ресурсу, позитивний контроль — із фактичною зміною, а safe response 500 — із корельованим internal event. Межі огляду й невиконані production-перевірки зазначено явно.

## 12. Evidence appendix

У docs/evidence/lr06: before-csrf.json; before-error.json; after-error.json; error-correlation.json; http-review.json; production-http.json; audit-events.json; log-review.json; regression-tests.json; fixed-browser.json і PNG; dependency-audit.json/.txt; audit-restore.txt; secret-audit.json; secret-match-review.csv; source-manifest.json. Точні raw logs/TRX — C:\dev\lr06-local, поза Git. source-manifest фіксує перевірені source/test files без самопосилання на звіт.

## Декларація й журнал ШІ

Під час виконання лабораторної роботи використовував ChatGPT/Codex як допоміжний інструмент для уточнення постановки завдання та вимог методички, підготовки й редагування документації, розроблення та виправлення коду. Допомога також охоплювала підготовку тестів, аналіз помилок і перевірку роботи застосунку. Межі локального стенда, правила CSRF-захисту та ліміти запитів узгоджував у процесі роботи.

| Дата / сервіс | Використання | Авторська участь / перевірка |
|---|---|---|
| 09–10.11.2026, ChatGPT/Codex | Допомога з постановкою завдання, документацією, розробленням і виправленням коду та тестів | Узгоджено правила захисту й налаштування стенда; автоматичні перевірки: 107 тестів і 25 браузерних сценаріїв успішні |
