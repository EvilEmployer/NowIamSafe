# nias — now I am safe

Библиотека перехвата и подавления исключений под Windows x64. Линкуется в целевой
`.exe`/`.dll`, через vectored exception handler (VEH) ловит любое исключение,
логирует точное место (module + RVA + backtrace) для оффлайн-разбора по PDB и —
по настраиваемой политике — пытается восстановить исполнение, снимая упавший
кадр стека через штатную x64-раскрутку.

Цель применения: диагностика собственных сбоев в коде без немедленного краша —
«дожить до лога», собрать телеметрию падений, затем статически разобрать причины.

---

## 1. Область

### v1 (этот этап)
- Источник диспетчеризации: **только VEH** (`RtlAddVectoredExceptionHandler`, `FirstHandler=1`).
- Классификация **всех** исключений, политика реакции — по классу (см. §5).
- Восстановление по умолчанию: **раскрутка одного кадра + sentinel** (см. §6).
- Безаллокационный hot-path + асинхронный логгер (см. §7, §8).
- Разбор упавшей инструкции через **Zydis** (длина + классификация операнда).
- **asmjit** — пул fallback-стабов для узкого кейса (§6.3).
- Форма поставки: статическая либа в `.exe`/`.dll` + опциональная DLL-обёртка.

### v2 (ветка nias/v2-kued — реализовано)
- Хук `KiUserExceptionDispatcher` через inline-patch (14-байтный `jmp [rip]`) +
  голый asm-переходник `kued_thunk.S` (`.intel_syntax`; `__declspec(naked)` на
  clang x64 нет). Встаёт выше всей VEH-цепочки — для софта, который чистит
  `LdrpVectorHandlerList` или держит свой Kued-хук.
- **Самоадаптация под билд:** смещения ContextRecord/ExceptionRecord от RSP и
  адрес неэкспортируемого `RtlDispatchException` извлекаются из пролога на этапе
  установки (Zydis), а не хардкодятся — layout менялся между билдами ntdll.
- **Без трамплина:** пролог не релоцируется (там rip-relative и relative-branch).
  Если мы не восстановили сами, переходник реплицирует штатную диспетчеризацию
  (`RtlDispatchException` → `NtContinue`/`NtRaiseException`).
- Общий конвейер с VEH через `process_fault`; `uninstall_kued` восстанавливает
  оригинал. Валидация: Wine (хук ловит AV раньше VEH, `hits 0→1`); реальная
  Windows — отдельный ctest-тест `kued` (не маскирует v1 при расхождении layout).

Архитектура v1 обязана оставлять место под v2: диспетчеризация скрыта за
интерфейсом `IDispatchSource`, у которого в v1 единственная реализация `VehSource`.

---

## 2. Тулчейн и реальность сборки

**Тулчейн:** **LLVM/Clang**, `-std=c++2c`, Windows x64. Флаги:
`-Wall -Wextra -Wpedantic`. Стандарт — **C++26** и это требование, а не флавор:
в коде есть C++26-конструкции (напр. `= delete("reason")` — P2573), которые
старые режимы отвергают. Минимум — clang 19; CI пинит **clang 20** на всех трёх
ногах (новейший clang, который `windows-latest` несёт из коробки, он же в ubuntu
universe для Linux/mingw — воспроизводимо, без nightly). Используются только
фичи, которые релизный clang реально реализует (`std::to_underlying`, span,
constexpr-логика, `= delete("reason")`); **рефлексия P2996 не реализована ни в
одном релизном clang (и даже на trunk-24 — `No`)**, поэтому в дерево не кладётся —
иначе это некомпилируемый «приблизительный» код.

**Контейнер разработки — Linux.** Отсюда:
- Код канонически на заголовках (§10); модульного фасада в дереве нет.
- Нативного Windows-рантайма нет; поднимается mingw-w64 + wine64 для харнесса.

**Три уровня валидации** (детали — §12):
1. Нативный Linux (clang 20): portable-core (OS-независимая логика) — настоящий
   прогон юнит-тестов прямо здесь, плюс compile-time проверки constexpr-пайплайна.
2. Wine + clang→`x86_64-w64-mingw32`: интеграция VEH/`RtlVirtualUnwind` на реально
   падающем процессе. GNU-ABI + семантика Wine — **не эталон**, но живой сигнал.
3. GitHub Actions `windows-latest`, **LLVM/Clang** (clang driver + Ninja, Windows
   SDK только ради заголовков/импорт-либ; без MSVC cl.exe и VS-генератора):
   **авторитетный** прогон полного fault-injection сьюта. Единственный критерий
   «боевой».

Честно: из Linux-контейнера выдаётся вылизанный продукт, чисто компилирующийся на
clang 20 и прошедший Wine-смоук; реальный боевой сигнал (настоящий ntdll) даёт
только уровень 3.

---

## 3. Архитектура: шов portable / win32

Жёсткое разделение. Вся логика, не требующая Win32, — в portable-core и тестируется
нативно. Win32 остаётся тонким адаптером.

```
                   ┌─────────────────────────────────────────┐
   EXCEPTION_       │  win32 seam (Windows-only)               │
   POINTERS ───────▶│  VehSource: регистрация VEH, адаптер     │
                   │  EXCEPTION_POINTERS → FaultEvent,         │
                   │  RtlLookupFunctionEntry/RtlVirtualUnwind, │
                   │  backtrace, запись решения в *ContextRec  │
                   └───────────────┬───────────────────────────┘
                                   │ FaultEvent (POD, portable)
                                   ▼
   ┌───────────────────────────────────────────────────────────┐
   │ portable core (OS-independent, тестируется на Linux)        │
   │  • policy:  code → Decision                                 │
   │  • decode:  Zydis — длина/операнд упавшей инструкции         │
   │  • stub:    asmjit — пул fallback-стабов (W^X)               │
   │  • log:     POD-запись + codec + lock-free ring + drain      │
   └───────────────────────────────────────────────────────────┘
```

`RtlVirtualUnwind` сам по себе Windows-only и живёт в шве; но **решение** (какая
политика к какому коду, какой sentinel писать, нужен ли стаб) — portable и
проверяется таблицей на Linux. Win32-слой лишь исполняет решение над реальным
`CONTEXT`.

### Модули (компоновка исходников)
```
include/nias/            публичные заголовки (C ABI + C++ facade)
src/portable/            policy, decode (Zydis), stub (asmjit), log, record, ring
src/win32/               veh_source, context_adapter, unwind, backtrace, bootstrap
src/module/nias.ccm      опциональный модульный фасад (только clang24 CI)
tests/portable/          doctest, нативно
tests/wine/              fault-injection exe, под wine64
```

---

## 4. Модель FaultEvent

Переносимое представление снимка исключения — заполняется win32-адаптером,
принимается portable-логикой. Без Windows-типов, чтобы собираться на Linux.

```cpp
enum class FaultClass : std::uint8_t {
  access_violation, illegal_instruction, divide_by_zero, int_overflow,
  misalignment, stack_overflow, breakpoint, cpp_exception, other
};

struct GpContext {               // volatile + те, что нужны для решения/лога
  std::uint64_t rip, rsp, rbp;
  std::uint64_t gpr[16];         // индексация по Zydis register id
  std::uint32_t eflags;
};

struct FaultEvent {
  FaultClass     cls;
  std::uint32_t  native_code;    // напр. 0xC0000005
  std::uint64_t  fault_address;  // для AV — адрес доступа; иначе 0
  std::uint8_t   av_access;      // 0 read / 1 write / 8 execute (из EXCEPTION_RECORD)
  GpContext      ctx;
  std::uint32_t  thread_id;
};
```

---

## 5. Политика по классам исключений

«Все исключения» ≠ единая реакция. Скипом/континью C++-бросок рушится
гарантированно. Таблица политик по умолчанию:

| Класс | native code | Реакция по умолчанию | Почему |
|---|---|---|---|
| C++ throw | `0xE06D7363` | **лог → `CONTINUE_SEARCH`** | бросающий уже закоммитился на раскрутку к `catch`; подавление = corruption |
| access violation | `0xC0000005` | лог → раскрутка 1 кадра + sentinel | штатный x64-unwind по `.pdata` |
| illegal instr. `#UD` | `0xC000001D` | лог → раскрутка 1 кадра + sentinel | то же |
| divide by zero `#DE` | `0xC0000094` | лог → раскрутка 1 кадра + sentinel | то же |
| int overflow | `0xC0000095` | лог → раскрутка 1 кадра + sentinel | то же |
| misalignment | `0xC00000B1` | лог → раскрутка 1 кадра + sentinel | то же |
| stack overflow | `0xC00000FD` | **лог → fast-fail** | хэндлер уже на исчерпанном стеке; восстановить нельзя (см. §7) |
| breakpoint | `0x80000003` | лог → `CONTINUE_SEARCH` (pass-through) | анти-отладочный кейс; это зона v2/Kued |
| прочее | — | лог → `CONTINUE_SEARCH` | не трогаем неизвестное |

Политика конфигурируема: каждому классу можно переопределить реакцию
(`pass_through` / `unwind_one` / `unwind_to_safepoint` / `skip_instruction` /
`fast_fail` / `terminate`). Дефолт для AV — `unwind_one` (замысел «ленивая
разработка без RAII»: nullptr-разыменование → форс-`return 0/nullptr`).

---

## 6. Механика восстановления

### 6.1. Основной путь — раскрутка одного кадра (`unwind_one`)
Не анализ пролога руками, а штатная table-based раскрутка x64. У всех non-leaf
функций есть обязательные `.pdata`/`.xdata`.

```
rf = RtlLookupFunctionEntry(ctx.Rip, &imageBase, nullptr);
if (rf) {
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, ctx.Rip, rf,
                     &unwound, &hdlData, &establisher, nullptr);
    // unwound = контекст ВЫЗЫВАЮЩЕГО: корректный Rsp, восстановленные
    // non-volatile (Rbx,Rbp,Rsi,Rdi,R12..R15), Rip = адрес возврата
    write_sentinel(unwound);           // §6.4
    *ContextRecord = unwound;          // VEH: мутируем и CONTINUE_EXECUTION
    return EXCEPTION_CONTINUE_EXECUTION;
}
```

Надёжно, т.к. опирается на compiler-emitted истину о кадре, а не на угадывание
размера стека.

### 6.2. Leaf-функция (нет `.pdata`)
Кадр не заведён; возврат — просто снять адрес возврата со стека:
```
ctx.Rip = *(std::uint64_t*)ctx.Rsp;  ctx.Rsp += 8;  write_sentinel(ctx);
```

### 6.3. Нет unwind-инфо у non-leaf (JIT, рукописный asm) — fallback через asmjit
Единственный честный кейс для стаба. Генерируем в W^X-странице безопасный выход и
перенаправляем туда `Rip`:
```
add rsp, <guess>    ; балансировка (размер кадра — эвристика, заведомо ненадёжно)
xor eax, eax
ret
```
Размер кадра угадывается из пролога через Zydis (суммируем `sub rsp,imm` / `push`),
при неудаче — политика деградирует до `fast_fail`. Это намеренно крайний случай.

### 6.4. Sentinel
Тип возврата функции неизвестен → зануляем регистры-носители результата
best-effort: `RAX=0`, `RDX=0` (пары/структуры), `XMM0=0` (float/double). Caller
получит `0`/`nullptr`/`0.0`. Задокументированный компромисс: вызывающий код может
поехать — это плата за «подавить и продолжить».

### 6.5. Опасность (документируем явно)
Пропуск/замена инструкции оставляет регистры/флаги/память в неконсистентном
состоянии. `unwind_one` безопаснее скипа (кадр честно сворачивается), но
вызывающий получает sentinel вместо реального значения → возможна порча данных
дальше по логике. Для корректности нужен §6.6.

### 6.6. Safe-point раскрутка (`unwind_to_safepoint`, opt-in)
Для критических участков: пользователь ставит маркер (snapshot `CONTEXT` через
аналог `setjmp` / `RtlCaptureContext`), в хэндлере повторными `RtlVirtualUnwind`
доходим до ближайшего зарегистрированного establisher-frame и делаем
`RtlRestoreContext`. Корректно, но требует явных границ «транзакций» в коде.
Реестр safe-point'ов — в `src/portable` (список кадров), исполнение — в шве.

---

## 7. Инварианты hot-path (VEH-callback)

Callback исполняется в произвольном контексте: возможно под loader lock, на чужом
потоке, на повреждённом стеке. Поэтому:

- **Ноль heap-аллокаций.** Только преаллоцированный арена-буфер.
- **Ноль Win32-вызовов, берущих loader lock** (нет `LoadLibrary`, нет `DbgHelp`
  в hot-path — символизация оффлайн, §8).
- **Ноль блокирующих локов.** Публикация записи — атомарный индекс в ring buffer;
  слив — отдельный logger-поток.
- **Recursion guard:** `thread_local bool in_handler`. Повторный вход (хэндлер
  фолтнул сам в себе) → минимум действий + `CONTINUE_SEARCH`, чтобы не словить
  бесконечную рекурсию.
- **Анти-луп на 100% ядра:** `CONTINUE_EXECUTION` без сдвига `Rip`/контекста =
  повторный фолт на том же адресе. Любое решение «продолжить» обязано изменить
  контекст; иначе — `fast_fail`.
- **Stack overflow:** на входе резервируем слэк через `SetThreadStackGuarantee`,
  чтобы хэндлер вообще смог отработать лог; восстановление не делаем.

---

## 8. Логирование и формат записи

### Hot-path
Заполнить POD-запись фиксированного размера → атомарно опубликовать индекс в
lock-free MPSC ring buffer (преаллоцированная арена). Всё.

### Запись (POD, оффлайн-символизация по PDB)
```
magic, version, record_size
timestamp (QPC/rdtsc), thread_id
native_code, fault_class, av_access
fault_address
rip + {module_base, rva}(rip)              ; module via RtlPcToFileHeader
backtrace[N] = { module_base, rva }        ; N настраивается
volatile regs snapshot (RAX..R15, EFLAGS)
decision (какая политика применена)
decode_info (мнемоника/длина упавшей инструкции из Zydis)
```

### Drain
Отдельный low-priority поток сливает ring в файл через `WriteFile` (или
memory-mapped). Никакого CRT stdio в hot-path.

### Backtrace
`RtlCaptureStackBackTrace` (дёшево, но не ходит по кадрам без unwind-инфо) **или**
ручной цикл `RtlVirtualUnwind` (дороже, корректнее на x64). Для цели «разобрать
статикой» — второй предпочтителен; выбор в конфиге.

### Оффлайн-тул
`tools/symbolize`: читает бинарные записи, резолвит `{module, rva}` по PDB
(`llvm-symbolizer`/`llvm-pdbutil` или DIA SDK). Не в hot-path принципиально
(DbgHelp берёт локи, не reentrancy-safe).

---

## 9. Точки инициализации

- **Статическая либа в `.exe`:** инициализатор в `.CRT$XCU` — ставит VEH до `main`.
- **DLL:** **TLS-callback** (`.CRT$XLB`) — исполняется раньше `DllMain`, на каждом
  attach потока; самый ранний способ встать до чужих регистрантов.
- `FirstHandler=1` — в голову списка VEH. Не спасает, если хост чистит
  `LdrpVectorHandlerList`; это триггер эскалации на v2/Kued.
- Публичный `extern "C"` control-surface (`nias_init/nias_shutdown/nias_configure`)
  — чтобы либу можно было инжектить и звать из C.

---

## 10. Модули vs заголовки — решение

Канон — **`.hh` + `.cc`**. Обоснование: C++26-модули в кросс-наборе (mingw/Wine +
нативный clang) надёжно не держатся, а зависимости (Zydis, asmjit) header/lib-based.
Соответствует преференсу «модули по делу, где тулчейн держит; иначе `.h`».
Модульного фасада в дереве нет — его вводить незачем, пока он не окупается на всех
трёх ногах CI. C++26 здесь — это язык (constexpr-логика, span, `= delete("reason")`,
`std::to_underlying`), а не модульная система.

---

## 11. Зависимости

- **Zydis** — декодер (длина инструкции + классификация операнда). Minimal-режим,
  без аллокаций. Подключение: CMake `FetchContent` (pinned tag) либо vendored
  submodule. Легче Capstone, для x64-length-decode достаточно.
- **asmjit** — генератор fallback-стабов (§6.3). `FetchContent`/submodule.
- **doctest** — тесты (header-only, быстрый).

Версии пинятся тегами, не `master`.

---

## 12. Стратегия тестирования

Тесты — «боевые полные», не заглушки. Три уровня:

**L1 — portable-core, нативно на Linux (clang 20), настоящий прогон:**
- Zydis: реальные байт-последовательности инструкций → длина/операнд/база-регистр.
- asmjit: генерация стаба → исполнение через `mmap(PROT_EXEC)` → проверка эффекта.
- ring buffer: многопоточный MPSC, отсутствие потерь/гонок (TSan).
- record codec: roundtrip, стабильность layout.
- policy: матрица `native_code × av_access × наличие .pdata` → ожидаемое `Decision`.

**L2 — Wine, интеграция на падающем процессе:**
- Кросс-сборка lib+exe под `x86_64-w64-mingw32` (header-mode), запуск `wine64`.
- null-deref AV → ловится VEH → `RtlVirtualUnwind` сворачивает кадр → процесс жив,
  в логе корректные `{module, rva}` и мнемоника.
- divide-by-zero, bad call target → stub-редирект.
- Проверка recursion guard и анти-лупа.

**L3 — GitHub Actions `windows-latest`, авторитетно:**
- clang24+MSVC сборка lib + модульный фасад + весь сьют L1∪L2 на настоящей Windows.
- Linux-джоба для L1 под санитайзерами. Опциональная Wine-джоба.

Зелёный L3 — критерий «боевой».

---

## 13. Публичный API (эскиз)

```cpp
// C ABI — для инжекта и C-потребителей
extern "C" {
  int  nias_init(const nias_config* cfg);   // ставит VEH; идемпотентно
  void nias_shutdown(void);
  void nias_configure(FaultClass cls, Decision d);
  // safe-point (opt-in):
  nias_safepoint* nias_safepoint_push(void); // snapshot контекста
  void nias_safepoint_pop(nias_safepoint*);
}
```
```cpp
// C++ facade (header; реэкспортится модулем на clang24)
namespace nias {
  struct Config { /* ring size, backtrace depth, log sink, per-class policy */ };
  bool init(const Config&);
  void shutdown();
  class SafePoint { public: SafePoint(); ~SafePoint(); }; // RAII вокруг C ABI
}
```

---

## 14. Риски и открытые вопросы

- **Семантика Wine ≠ Windows** в краевых случаях `RtlVirtualUnwind`/VEH. L2 — смоук,
  не эталон; эталон L3.
- **Sentinel-восстановление небезопасно по определению** (§6.5). Для реальной
  корректности — safe-point (§6.6). Дефолт `unwind_one` сознательно «грязный».
- **MSVC vs mingw unwind-метаданные** — оба table-based x64, но раскладка
  `RUNTIME_FUNCTION` и handler-data считать аккуратно; L3 на MSVC обязателен.
- **Stack overflow** — лог-онли; полноценно не решается в VEH.
- Открыто: глубина backtrace по умолчанию; формат sink (файл vs mmap vs named pipe);
  нужен ли x86 (сейчас — нет, только x64).

---

## 15. Вехи

1. **M0 — каркас:** repo, CMake (primary + mingw toolchain-file), deps, CI-скелет.
2. **M1 — portable-core + L1:** policy/decode/stub/log/ring + нативные тесты зелёные.
3. **M2 — win32-слой:** VehSource, адаптер, `unwind_one`, backtrace, bootstrap.
4. **M3 — L2 Wine:** fault-injection зелёный под wine64.
5. **M4 — L3 CI:** `windows-latest` зелёный; safe-point opt-in; полировка в loop.
6. **v2 (позже):** `KuedSource` + asm-переходник.
