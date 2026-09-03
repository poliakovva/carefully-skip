# carefully-skip — Auto Mode (deny-first policy engine)

Форк фичи **auto-mode** из [Kilo Code](https://github.com/Kilo-Org/kilocode) (ветка `k3menn/auto-mode`).
Кейс 461 «`--carefully-skip-permissions`»: перехват tool-call агента **до выполнения**, лог каждого
вызова и первый детерминированный, **injection-неуязвимый** контроль (deny-first).

Полное описание — в [`docs/auto-mode.md`](docs/auto-mode.md); план/скоуп — в [`docs/roadmap.md`](docs/roadmap.md).

## Что здесь

Пути повторяют структуру kilocode, чтобы фичу можно было положить оверлеем на чекаут kilocode.

```
docs/
  auto-mode.md                                  день 1: дизайн + точка перехвата
  roadmap.md                                    роадмап кейса (4 дня)
packages/opencode/
  src/kilocode/auto-mode/
    index.ts                                    AutoMode.check() — chokepoint: extract → log → rules → deny
    rules.ts                                    чистый deny-first движок (evaluate → Verdict)
    error.ts                                    AutoModeDeniedError (tagged Effect error)
    audit.ts                                    JSONL audit-лог каждого вызова до выполнения
  src/session/tools.ts.integration.patch        9-строчная врезка в session/tools.ts (точка перехвата)
  test/kilocode/
    auto-mode-rules.test.ts                     unit: deny-first правила (мини-датасет: 20 атак + легит)
    auto-mode-check.test.ts                     e2e: check() denies/allows + пишет audit
```

## Как положить обратно на kilocode

Из корня чекаута kilocode:

```bash
# 1. скопировать модуль, тесты и доки
cp -R packages/opencode/src/kilocode/auto-mode  <kilocode>/packages/opencode/src/kilocode/
cp packages/opencode/test/kilocode/auto-mode-*.test.ts <kilocode>/packages/opencode/test/kilocode/
cp docs/auto-mode.md docs/roadmap.md            <kilocode>/docs/

# 2. применить врезку в session/tools.ts
cd <kilocode> && git apply <this-repo>/packages/opencode/src/session/tools.ts.integration.patch
```

Врезка добавляет `import { AutoMode } from "@/kilocode/auto-mode"` и вызов
`yield* AutoMode.check(item.id, args, { sessionID, callID })` сразу после хука
`tool.execute.before` и **перед** `item.execute` — единый chokepoint для всех тулов.

## Тесты

```bash
cd packages/opencode
bun test test/kilocode/auto-mode-rules.test.ts
bun test test/kilocode/auto-mode-check.test.ts
```

Импорты используют алиас `@/…` (`@ = packages/opencode/src`), поэтому тесты гоняются
внутри чекаута kilocode, где настроен bun + tsconfig-алиасы.
