# F-01. Відсутня перевірка CSRF у cookie-authenticated змінах

Актив: цілісність інциденту та сесії. Пріоритет: високий для cookie-периметра; ймовірність залежить від доступного браузерного способу надсилання, SameSite та CORS. Статус: виправлено й повторно перевірено локально.

## Передумови і відтворення

Review-start: 9cdc1cbe01eaeb48b058664e8521758fe3b348ff (v0.5.0). Development, HTTP localhost:5086, окрема securelab_lr06. Alice увійшла через справжній login. Створено лише власний синтетичний New-інцидент. PUT із коректним title/description та authentication cookie, але без antiforgery header, повернув 204; повторний GET показав змінений description. Фікстуру видалено. Доказ: docs/evidence/lr06/before-csrf.json.

Це доказ відсутності серверної перевірки токена, а не доказ універсальної міжсайтової експлуатації. HTTP-клієнт не застосовує браузерні обмеження CORS/SameSite. Реальний сторонній браузерний сценарій залежить від форми запиту й цих обмежень.

## Причина й вплив

Cookie засвідчувала сесію, але сервер не перевіряв, що зміну ініціює клієнт із правильним request token. Самі CORS, SameSite та роль не замінюють antiforgery. Незахищені зміни: create, update, delete, triage та logout.

## Виправлення

Стандартний IAntiforgery: authenticated GET /api/auth/csrf-token, cookie + request token, заголовок X-CSRF-TOKEN. CsrfProtection.ValidateRequestAsync виконується перед handler; помилка повертає 400 із code=csrf_validation_failed. Фільтр призначено кожній із п’яти операцій окремо. Logout перевіряється до SignOutAsync.

Client/csrf.js зберігає request token тільки в пам’яті сторінки, одержує його перед зміною, очищує кеш після login/logout/401. Після F5 або переходу сторінки запит одержує новий токен. Автоматичного повтору невдалої мутації немає. Видача токена не доступна через навчальний CORS origin.

## Retest і позитивний контроль

CsrfSecurityTests.REG_CSRF01_AllMutations_RejectBadTokenWithoutStateChange_ThenAcceptValidPair: 10 варіантів (5 операцій × відсутній/невалідний токен). Для кожного: 400 конкретно через CSRF; стан і сесія незмінні; після одержання правильної пари — 201/204 та очікувана зміна. Тест не додає токен автоматично всім клієнтам harness.

Окремо перевірено старий token Alice після входу Bob, anonymous token endpoint, no-store та відсутність CORS-доступу. Реальний Chrome: REG-CSRF-01-browser → 400/unchanged=true, потім 204/changed=true; форми працюють після F5 і повторного login. Докази: http-review.json і fixed-browser.json у docs/evidence/lr06.

## Залишковий ризик

XSS у власному origin може читати request token: тому збережено textContent і CSP. Login/register публічні, не використовують authentication cookie як дозвіл; login-CSRF та registration abuse залишено окремим задокументованим ризиком. Реальний HTTPS deployment не входив до локального огляду.
