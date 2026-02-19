# obj2exe (最小OBJ → 最小EXE)

Visual Studio 2022 / ISO C++14 を前提にした、x64向けのGUI変換アプリです。

## できること
- 入力OBJを最小限バリデーション（COFFヘッダ確認）
- GUIサブシステムの最小PE(64bit) EXEを生成
- 生成EXEを実行すると `Hello world!` のメッセージボックスを表示

## ビルド手順 (Visual Studio 2022)
1. 空の C++ プロジェクトを作成（`x64` 構成）
2. `MinimalObjToExe.cpp` を追加
3. 言語標準を **ISO C++14** (`/std:c++14`) に設定
4. ビルド

## 使い方
```text
obj2exe.exe input.obj [output.exe]
```

- `output.exe` 省略時は `input.exe` を自動生成
- 実行結果はメッセージボックスで通知
