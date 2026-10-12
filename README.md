# nias — now I am safe

Windows x64 библиотека подавления исключений. Линкуется в целевой `.exe`/`.dll`,
через vectored exception handler ловит любое исключение, логирует точное место
(module + RVA + backtrace) для оффлайн-разбора по PDB и по настраиваемой политике
восстанавливает исполнение, сворачивая упавший кадр штатной x64-раскруткой
(`RtlVirtualUnwind`).

> Статус: **в разработке**, v1 (VEH-only). Хук `KiUserExceptionDispatcher` — v2.
> Полный дизайн и обоснования: [`docs/DESIGN.md`](docs/DESIGN.md).

## Коротко

- Источник событий v1 — `RtlAddVectoredExceptionHandler` (`FirstHandler=1`).
- Реакция на исключение — по классу (C++ throw пропускается, AV сворачивает кадр
  и возвращает sentinel, stack overflow — лог + fast-fail). Политика настраивается.
- Hot-path без аллокаций и локов; запись падает в lock-free ring, слив — отдельным
  потоком; символизация оффлайн.
- Разбор упавшей инструкции — Zydis; fallback-стабы — asmjit.

## Раскладка

```
include/nias/     публичный API (C ABI + C++ facade)
src/portable/     OS-независимая логика (policy, decode, stub, log, ring)
src/win32/        VEH-слой, адаптер CONTEXT, unwind, backtrace, bootstrap
src/module/       опциональный модульный фасад nias.ccm (clang 24)
tests/portable/   нативные юнит-тесты (doctest)
tests/wine/       fault-injection под wine64
tools/symbolize/  оффлайн-символизация записей по PDB
```

## Валидация

| Уровень | Где | Что |
|---|---|---|
| L1 | нативно, Linux/clang | portable-core: Zydis, asmjit, ring, policy |
| L2 | wine64 + clang→mingw | интеграция VEH/unwind на падающем процессе |
| L3 | GitHub Actions `windows-latest` | **авторитетно**: clang24/MSVC, полный сьют |

Целевой тулчейн — Clang 24, `-std=c++2c`, x64. Подробности сборки — в `docs/DESIGN.md`.
