# nias — now I am safe

Windows x64 библиотека подавления исключений. Статически линкуется в целевой
`.exe`/`.dll`, ловит любое аппаратное исключение, логирует точное место
(module + RVA + backtrace) для оффлайн-разбора по PDB и по настраиваемой политике
восстанавливает исполнение, сворачивая упавший кадр штатной x64-раскруткой
(`RtlVirtualUnwind`).

Два слоя перехвата:

- **v1 — VEH.** `RtlAddVectoredExceptionHandler` в голове списка. Базовый режим.
- **v2 — Kued.** Инлайн-хук `KiUserExceptionDispatcher` *выше* всей VEH-цепочки —
  для софта, который чистит список VEH или ставит свой Kued-хук (VMProtect,
  Themida и прочее). Опционально, поверх v1.

Полный дизайн и обоснования: [`docs/DESIGN.md`](docs/DESIGN.md).

## Коротко

- Реакция на исключение — по классу: C++ throw (`0xE06D7363`) логируется и
  пропускается; AV сворачивает кадр и возвращает sentinel (RAX/RDX/XMM0 = 0);
  stack overflow — лог + fast-fail. Политика меняется в рантайме.
- Hot-path без аллокаций и локов: запись падает в lock-free MPMC-ring, слив —
  отдельным потоком; символизация оффлайн, в логе только `{module_base, rva}`.
- Разбор упавшей инструкции и пролога — Zydis; fallback-стабы для кода без
  `.pdata` — asmjit. Хук `KiUserExceptionDispatcher` самоадаптируется под билд
  ntdll (офсеты записей и адрес не-экспортируемой `RtlDispatchException`
  извлекаются из пролога, ничего не захардкожено).

## Подключение

`nias` — статическая библиотека `nias_core`. Таргет транзитивно тянет свои
include-пути, `ntdll`, Zydis и asmjit.

Тулчейн — **LLVM/Clang** (`x86_64-pc-windows-msvc`). MSVC `cl.exe` не
поддерживается: asm-thunk написан в GAS-синтаксисе и собирается ассемблером
clang. Стандарт — **C++26** (`-std=c++2c`), это требование: код использует
C++26-конструкции (например `= delete("reason")`), которые старые режимы
отвергают. Нужен clang ≥ 19; CI пинит clang 20 на всех ногах. Рефлексии (P2996)
нет ни в одном релизном clang — поэтому она намеренно не используется.

### CMake, `add_subdirectory`

```cmake
add_subdirectory(third_party/nias)      # вендоринг в дерево проекта
target_link_libraries(your_target PRIVATE nias_core)
```

### CMake, `FetchContent`

```cmake
include(FetchContent)
FetchContent_Declare(nias
  GIT_REPOSITORY https://github.com/EvilEmployer/NowIamSafe
  GIT_TAG main)
FetchContent_MakeAvailable(nias)
target_link_libraries(your_target PRIVATE nias_core)
```

## Использование

```cpp
#include <nias/nias.hh>

int main() {
    nias::Config cfg;
    cfg.log_path = "app.nias.log";   // null => только in-memory ring
    cfg.backtrace_depth = 16;
    nias::init(cfg);                 // VEH в голове списка; идемпотентно

    run_app();                       // любой AV/#DE/... ловится и логируется;
                                     // по политике кадр сворачивается, возврат sentinel

    nias::shutdown();                // снять хук, слить и закрыть лог
}
```

Политика по классу исключений — в рантайме:

```cpp
nias::set_policy(nias::FaultClass::access_violation, nias::Action::unwind_one);
nias::set_policy(nias::FaultClass::stack_overflow,  nias::Action::fast_fail);
```

### Kued (v2) — перехват выше VEH

```cpp
nias::init(cfg);
if (nias::install_kued()) {          // только после init()
    // ... фолты теперь видны раньше любого VEH ...
    nias::uninstall_kued();          // вернуть оригинальные байты ntdll
}
// nias::kued_info() отдаёт извлечённую раскладку (exc_off/ctx_off/dispatch)
// для диагностики на незнакомом билде Windows.
```

### Safe-point — восстановление в известную точку

setjmp-style макрос: фолт под политикой `unwind_to_safepoint` разматывает стек до
ближайшей зарегистрированной точки, а не на один кадр вверх. Это макрос (контекст
снимается в кадре вызывающего), так что `<windows.h>` должен быть в области
видимости.

```cpp
#include <windows.h>
#include <nias/nias.hh>

nias::set_policy(nias::FaultClass::access_violation,
                 nias::Action::unwind_to_safepoint);

nias_safepoint sp;
if (nias_safepoint_set(&sp) == 0) {
    risky();                         // может упасть
    nias_safepoint_clear(&sp);
} else {
    // восстановились после фолта внутри risky()
}
```

Для C-потребителей есть `extern "C"` ABI: `nias_init_default` / `nias_shutdown`.

## Раскладка

```
include/nias/     публичный API (C++ facade + C ABI)
src/portable/     OS-независимая логика (policy, decode, record, stub)
src/win32/        VEH-слой, Kued-хук + asm-thunk, unwind, backtrace, лог, safe-point
tests/portable/   нативные юнит-тесты (doctest)
tests/wine/       fault-injection + Kued-тест под wine64
tools/symbolize/  оффлайн-символизация записей по PDB
```

## Сборка и тесты

```sh
# L1 — portable-core нативно (Linux/clang)
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
ctest --test-dir build --output-on-failure

# L2 — fault-injection + Kued под wine64 (кросс clang -> mingw-w64)
scripts/run-wine-harness.sh
```

## Валидация

| Уровень | Где | Что |
|---|---|---|
| L1 | нативно, Linux/clang 20 + ASan/UBSan | portable-core: Zydis, asmjit, ring, policy, decode |
| L2 | wine64 + clang→mingw | интеграция VEH/unwind/stub/safe-point + Kued на живом процессе |
| L3 | GitHub Actions `windows-latest`, LLVM/Clang | **авторитетно**: реальный ntdll, полный сьют (`portable` + `integration` + `kued`) |

## Чтение лога

Лог бинарный: поток length-prefixed записей `{module_base, rva}` + контекст,
символизация — оффлайн по PDB.

```sh
tools/symbolize/nias_symbolize.py app.nias.log                 # module+rva
tools/symbolize/nias_symbolize.py app.nias.log --exe app.exe   # + llvm-symbolizer
```
