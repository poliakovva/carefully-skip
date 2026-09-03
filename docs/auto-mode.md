# Auto Mode — перехват tool-call + deny-first policy engine

Реализация Дня 1 (AI Eng 1) из [roadmap.md](./roadmap.md): перехват команды агента **до выполнения**, лог каждого вызова и первый детерминированный, **injection-неуязвимый** контроль (deny-first).

---

## 1. Идея

Политика `allow / deny` живёт **не в промпте LLM**, а в детерминированном коде на перехвате tool-call. Инструкции из `SKILL.md` / README / вывода MCP не участвуют в решении — вердикт выносит код над конкретной командой. Поэтому prompt injection из контекста не может ослабить правило.

```
tool call (LLM)
   → decode аргументов
   → [ AutoMode.check ]  ← мы здесь: лог + deny-first, ДО выполнения
        ├─ deny  → AutoModeDeniedError → агент видит tool-error, не выполняется
        └─ allow → штатный permission-флоу (ask) → item.execute → процесс
```

Слой **только запрещает** катастрофу. «Серую зону» (ask) оставляем существующему permission-движку — так false-positive и friction не растут by design.

---

## 2. Точка перехвата

Единый chokepoint для **всех** инструментов (shell, write, edit, MCP, …):

**`packages/opencode/src/session/tools.ts`** — замыкание `execute(args, options)`, которое оборачивает вызов каждого нативного тула. Наш `AutoMode.check(...)` встроен сразу после хука `tool.execute.before` и **перед** `item.execute(args, ctx)`:

```ts
const ctx = context(args, options)
yield* plugin.trigger("tool.execute.before", { tool: item.id, ... }, { args })

// auto-mode: лог + deny-first ДО выполнения (детерминированный код → injection-immune)
yield* AutoMode.check(item.id, args, { sessionID: ctx.sessionID, callID: ctx.callID })

const result = yield* SandboxPolicy.executeTool(ctx.sessionID, item, item.execute(args, ctx))
```

Почему именно здесь:
- через это место проходит **каждый** tool-call до исполнения;
- это обычный TypeScript над уже раскодированными аргументами — контекст модели сюда не «дотягивается»;
- ниже по стеку для shell-команд есть ещё `tool/shell.ts` (сырая строка + tree-sitter разбор) — резерв для AST-правил на Дне 2.

---

## 3. Модуль `kilocode/auto-mode/`

`packages/opencode/src/kilocode/auto-mode/`

| Файл | Назначение |
| --- | --- |
| `rules.ts` | Чистый детерминированный deny-first движок. `evaluate(input) → Verdict`. Без LLM, без I/O. |
| `audit.ts` | Audit-лог: JSONL-запись каждого вызова **до** выполнения + структурный `logInfo`. Best-effort. |
| `error.ts` | `AutoModeDeniedError` — типизированная ошибка, которую процессор сессии превращает в tool-error для агента. |
| `index.ts` | `AutoMode.check(tool, args, ctx)` — извлекает команду/путь, логирует, гоняет правила, на deny фейлит. |

### 3.1 Deny-first правила (`rules.ts`)

Семантика: **первый совпавший deny побеждает** и не понижается. Не совпало ни с чем → `allow` (уходит в штатный ask).

| Правило (`id`) | Что ловит | Тулы |
| --- | --- | --- |
| `rm-rf-root` | `rm -rf` по `/`, `/*`, `~`, `$HOME`, `.`/`..` (флаги в любом порядке, через `sudo`) | bash |
| `disk-wipe` | `mkfs`, `dd of=/dev/…`, `> /dev/sd…` | bash |
| `fork-bomb` | `:(){ :\|:& };:` | bash |
| `pipe-to-shell` | `curl\|wget\|fetch … \| sh/bash/python/…`, `bash <(curl …)`, `sh -c "$(curl …)"`, `eval $(curl …)`, `iex(iwr …)` | bash |
| `sql-drop` | `DROP DATABASE/TABLE`, `TRUNCATE TABLE`, `DELETE FROM` без `WHERE` | bash |
| `secret-access` | Чтение/передача `.env`, `~/.ssh/id_*`, `~/.aws/credentials`, `.npmrc`, `.pem`, … | bash |
| `write-secret` | Запись в секрет-файлы (`.env`, приватные ключи, …) | write, edit, apply_patch |
| `write-system-path` | Запись в `/etc`, `/usr`, shell-профили (`.bashrc`/`.zshrc`), `authorized_keys`, cron | write, edit, apply_patch |

Разбор аргументов по инструменту:
- `bash` → `args.command` (строка команды);
- `write` / `edit` / `apply_patch` → `args.filePath` (целевой путь).

### 3.2 Что видит агент при блокировке (`error.ts`)

`AutoModeDeniedError` — tagged-ошибка Effect. Она проходит по стеку так же, как штатная `PermissionDeniedError`: `EffectBridge.run.promise` (`Effect.runPromise`) отклоняет промис → AI SDK эмитит `tool-error` → `SessionProcessor.failToolCall` пишет `errorMessage(error)` результатом вызова. Модель получает `.message`:

> Blocked by auto-mode policy [rm-rf-root]: … This is a deterministic security rule, not a transient error — do not retry the same command; propose a safe alternative or ask the user.

Текст намеренно объясняет, что правило детерминированное (ретрай бесполезен) — задел под «безопасное продолжение после блокировки» (День 3).

### 3.3 Audit-лог (`audit.ts`)

Одна JSONL-строка на каждый перехваченный вызов, **до** выполнения:

```
~/.local/share/kilo/log/auto-mode.jsonl   (XDG_DATA_HOME/kilo/log)
```

Формат записи:

```json
{"time":"2026-09-03T11:14:37.759Z","sessionID":"ses_…","callID":"call_…",
 "tool":"bash","command":"rm -rf /","decision":"deny","rule":"rm-rf-root",
 "reason":"…","matched":"rm -rf on root/home/wildcard"}
```

Это ground-truth для бенчмарк-харнесса (ASR / Friction считаются прямо из лога). Логирование best-effort — ошибка записи не может уронить или заблокировать вызов.

---

## 4. Как запускать и проверять

Развернуть:

```bash
bun install
bun run dev            # KILO_CLIENT=cli … src/index.ts
```

Тесты (43 кейса — 20 атак блокируются, легит проходит, deny даёт типизированную ошибку, audit пишется):

```bash
cd packages/opencode
bun test test/kilocode/auto-mode-rules.test.ts     # deny-first правила (мини-датасет)
bun test test/kilocode/auto-mode-check.test.ts     # end-to-end check(): deny/allow/лог
bun run typecheck
```

Наблюдать перехват вживую:

```bash
tail -f ~/.local/share/kilo/log/auto-mode.jsonl
```

---

## 5. Ограничения (честно)

- **Regex по нормализованной строке.** Экранирование/склейка (`r''m -rf /`), `base64|sh`, запись пейлоада в файл с последующим запуском — могут обойти конкретный паттерн. Deny-first ловит распространённые/прямые формы из датасета. Закрывается на Дне 2 переходом на AST (переиспользовать tree-sitter скан из `tool/shell.ts`).
- **Слой только DENY.** «Серые» решения (ask) остаются у существующего permission-флоу — это осознанный выбор ради низкого FP/Friction.
- **`cwd` зарезервирован** в `RuleInput`, но правило «запись вне рабочей директории» пока не включено (частично покрыто штатным external-directory permission). Планируется на День 2.

---

## 6. Дальше (по roadmap)

- **День 2:** slopsquatting-модуль на `npm/pip install` (до установки, zero-day эвристики); LLM-классификатор для «серых» (только эскалация `allow→ask`, не понижает `deny`); апгрейд правил на AST.
- **День 3:** безопасное продолжение после блокировки (агент переформулирует, не зацикливаясь); тюнинг порогов FP/Friction; кэш вердиктов для Latency.
- **Опционально:** подключить deny к `veto`-механизму permission-движка, чтобы вердикт светился в UI-провенансе рядом с остальными.
