# obj2exe (single app)

Visual Studio 2022 / ISO C++14 を前提にした、x64向けGUIアプリです。

## 概要
`MinimalObjToExe.cpp` は、以下を**1回の実行で**行います。

1. メモリ上で最小の x64 COFF OBJ を生成
2. その最小OBJを検証
3. `Hello world!` を表示する最小GUI EXE (PE32+) を生成

つまり `objgen` と `obj2exe` を1つに統合した構成です。

## ビルド
1. 空の C++ プロジェクトを作成（`x64` 構成）
2. `MinimalObjToExe.cpp` を追加
3. 言語標準を **ISO C++14** (`/std:c++14`) に設定
4. ビルド

## 使い方
```text
obj2exe.exe [output.exe]
```

- 省略時は `hello.exe` を生成

## 動作
生成された EXE を実行すると、`Hello world!` メッセージボックスを表示します。
