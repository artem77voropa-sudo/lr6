# Запуск та повторна перевірка ЛР6

## Цей ПК: готовий ізольований стенд

Код: C:\dev\securelab-lr06. API: http://localhost:5086. БД: securelab_lr06, PostgreSQL loopback:55432. Допоміжні скрипти, приватні налаштування й журнали: C:\dev\lr06-local (поза Git). Пароль навчальних акаунтів читається з раніше створеного DPAPI-файла, не з репозиторію.

Відкрий PowerShell. Команди нижче вставляй окремими блоками. ExecutionPolicy Bypass тут діє тільки в запущеному дочірньому процесі.

Повний reset саме БД ЛР6 і regression pack (107 tests):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\dev\lr06-local\Test-Lab06.ps1"
```

Після PASS запусти API; це вікно лишається зайнятим сервером:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\dev\lr06-local\Start-Lab06.ps1"
```

В іншому PowerShell, якщо probes ще не запущені, відкрий два додаткові вікна й у кожному виконай одну команду:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\dev\lr06-local\Start-Probe.ps1" -Port 4173
```

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\dev\lr06-local\Start-Probe.ps1" -Port 4174
```

Браузерний regression (25 checks, реальний Chrome, локальні fixtures очищуються):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\dev\lr06-local\Check-Browser-Lab06.ps1"
```

Цей запуск пише в C:\dev\lr06-local\browser-results і не змінює tracked evidence. Якщо порт зайнятий, не запускай ще одну копію: перевір /health або зупини тільки ЛР6:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\dev\lr06-local\Stop-Lab06.ps1"
```

Детальний гайд для власних скріншотів: C:\dev\lr06-local\screenshot-guide-lr06.md. Він є допомогою для автора й не входить до репозиторію. Файли docs/security-review.md, threat-model.md та findings є результатами роботи й входять до Git.

## Відтворення в іншій локальній копії

Потрібні .NET 10 SDK (перевірено 10.0.403), Docker/PostgreSQL, Git; для browser pack — Python з playwright і встановлений Chrome. Версії .NET пакетів фіксують packages.lock.json. global.json дозволяє latestFeature стабільної .NET 10.

Заздалегідь налаштуй зовні Git ConnectionStrings__SecureLab на окрему локальну БД securelab_lr06 і SeedUsers__Password на навчальний пароль, що відповідає Identity policy. На цьому ПК це робить Use-Lab06.ps1; в іншій машині введи секрет через Read-Host -AsSecureString та перетвори лише в пам’яті для env. Не вставляй значення у tracked files, командний рядок або докази.

Для нового Docker-стенда доступний infra/compose.yaml із відомим study credential і loopback bind. Не змінюй наявний контейнер попередніх ЛР; використай вже запущений локальний PostgreSQL і окремо створи securelab_lr06. Приватний пароль seed і публічний study DB credential — різні речі.

Після налаштування env, у корені саме потрібної копії:

```powershell
$env:ASPNETCORE_ENVIRONMENT = 'Development'
dotnet restore SecureLab.sln --locked-mode
dotnet run --project src/SecureLab.Api -c Release --no-launch-profile -- --reset-database
dotnet test SecureLab.sln -c Release --no-restore --logger "trx;LogFileName=final.trx" --results-directory "C:\dev\lr06-local\test-results"
```

Reset допускається тільки для локальної securelab_lr06. Після тестів у першому вікні запусти `dotnet run --project src/SecureLab.Api -c Release --no-launch-profile --no-build --urls http://localhost:5086`. У другому вікні з тим самим env виконай `python tests/browser/lab06-browser-checks.py --stage fixed --output-dir C:/dev/lr06-local/browser-results`. Probes 4173/4174 повинні бути доступні; вивід raw logs/TRX тримай поза Git.

Для dependency audit:

```powershell
dotnet restore SecureLab.sln --locked-mode
dotnet list SecureLab.sln package --vulnerable --include-transitive
```

## Фінальна Git-процедура — виконує автор

Коміти, merge, tag і push асистент не виконує. Перевірені зміни зараз у робочій гілці. Не додавай C:\dev\lr06-local, DPAPI-файли, raw logs, PDF або власний Word до Git. Спочатку переглянь `git --no-pager diff` і `git status --short`, потім сам зафіксуй узгоджені code/docs/evidence.

Важливо: спільний репозиторій уже має старий v1.0.0 від ЛР1. Його не можна примусово пересувати. Для окремого репозиторію здавання ЛР6 можна створити незалежний clone **без старих tags** після власного commit:

```powershell
git clone --no-tags --single-branch --branch lab/6-hardening-review C:\dev\securelab-lr06 C:\dev\securelab-lr06-delivery
Set-Location C:\dev\securelab-lr06-delivery
git switch -c main 9cdc1cbe01eaeb48b058664e8521758fe3b348ff
git merge --no-ff --no-edit lab/6-hardening-review
```

Не повторюй clone в уже наявну директорію. Перед merge робоче дерево має бути чистим. Це зберігає старий tag у вихідному репозиторії й дозволяє новий незалежний v1.0.0 лише в окремому репозиторії ЛР6.

Тепер повтори .NET і browser regression саме з C:\dev\securelab-lr06-delivery за попереднім розділом: helper Test-Lab06.ps1 прив’язаний до початкової робочої папки, тому для delivery використовуй прямі команди з цього розділу. Журнали й результати — поза delivery. Перевір `git status --short`; лише після PASS обох прогонів:

```powershell
git tag -a v1.0.0 -m "Lab 6 hardening and security review verified"
git rev-parse HEAD
git rev-list -n 1 v1.0.0
git show --no-patch v1.0.0
```

Два hashes мають збігтися. Якщо потрібне виправлення, не став tag до нового прийнятого merge і нового PASS. Не використовуй `git tag -f`.

Погоджений remote: https://github.com/artem77voropa-sudo/lr6.git. У delivery origin спочатку вказує на локальне джерело; перед push автор виконує `git remote set-url origin https://github.com/artem77voropa-sudo/lr6.git`, перевіряє `git remote -v`, і тільки потім надсилає review branch, main і v1.0.0. Не пушити в lr5/lr4 і не використовувати --force.

## PDF і подання

Звіт складається із security-review.md, threat-model.md і двох findings. Чернетка PDF готується поза Git; вона не є фінальним tagged-export. Після merge → regression → tag використай наданий методичкою report-to-html.py з --verified-commit та --final-run. Скрипт перевіряє clean HEAD=tag і додає metadata тільки до зовнішнього експорту.

На цьому ПК оригінал exporter: C:\dev\lr06-resources\commands\report-to-html.py. Запускай з delivery. У PowerShell з налаштованим Python:

```powershell
$verified = git rev-parse HEAD
python C:\dev\lr06-resources\commands\report-to-html.py --output-dir C:\dev\lr06-submission --verified-commit $verified --final-run "107 tests passed; 25 browser checks passed; local final merge verification"
```

Текст final-run дозволено використовувати тільки після фактичного успішного прогону на цьому merge. Відкрий створений HTML і надрукуй у PDF. Після tag tracked docs не редагуй заради запису їхнього власного hash. Здавання: DEL-01 модель; DEL-02 review/findings/PDF; DEL-03 code/tests, verified merge/tag і погоджений remote або приватний ZIP.
