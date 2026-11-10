# F-02. Захисні заголовки губилися на unexpected 500

Актив: захисна політика браузерної відповіді. Пріоритет: середній. Вплив — непослідовний CSP/nosniff/referrer-policy на аварійному шляху; сам по собі цей факт не доводить XSS. Статус: виправлено й повторно перевірено.

## Відтворення

Review-start 9cdc1cbe01eaeb48b058664e8521758fe3b348ff. Production, no-launch-profile, HTTP localhost:5086. Лише для цього процесу підключення БД спрямовано на недоступний loopback-порт 54399. Публічний POST /api/auth/login із синтетичним неправильним паролем викликав фактичну помилку provider. Debug endpoint не додавався.

before-error.json: status 500, application/problem+json, без CSP, X-Content-Type-Options та Referrer-Policy. Тіло вже не розкривало SQL/stack trace; знахідка стосується заголовків, а не вигаданої видачі секретів.

## Причина й виправлення

Middleware заголовків знаходився всередині exception handler. Під час створення аварійної відповіді заголовки очищувалися. Реєстрацію перенесено перед exception handler; Response.OnStarting застосовує політику перед фактичним надсиланням, зокрема після очищення.

SafeExceptionHandler повертає обмежений Problem Details (type/title/status/traceId). У внутрішню подію потрапляють тільки trace, тип exception та час. Сирий exception message не переноситься до HTTP-відповіді. Стандартні внутрішні діагностичні журнали залишаються локально; у доказ експортується мінімальний корельований рядок.

## Retest

Той самий реальний запит у Broken-профілі: 500, application/problem+json, nosniff, no-referrer і enforced CSP. after-error.json містить відповідь; error-correlation.json — її traceId та точний безпечний рядок журналу з тим самим trace. Відповідь не містить SQL, connection string, файлового шляху чи stack trace.

ProductionHardeningTests.Production_Unexpected500_HasHeaders_SafeBody_AndMatchingInternalTrace перевіряє точний набір полів і кореляцію. Production_Authenticated200_Validation400_Resource404_AndStaticHeaders перевіряє 200/400/404. Це HTTPS TestServer без реального TLS-з’єднання. Реальний HTTP Development-клієнт додатково перевіряє static/API 200, validation 400 та 404 у http-review.json.

Після досліду відновлено правильне підключення: /health 200, login 204, нормальні операції працюють. Збережено виняток CSP лише для Scalar у Development; у Production документація не зареєстрована. /scalar/v1 повертає SPA HTML 200, що не є Scalar.

## Залишковий ризик

Headers не виправляють небезпечні DOM sinks і не замінюють authorization. HSTS/HTTPS reverse proxy, зберігання журналів і production monitoring потребують окремого deployment review.
