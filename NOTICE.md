# サードパーティライセンス表示

`pqc_rails`自体のライセンスは[LICENSE.txt](LICENSE.txt)（Business Source License 1.1）を参照してください。
本ファイルは、`pqc_rails`が同梱・依存する第三者ソフトウェアのライセンス表示をまとめたものです。

## liboqs（同梱・MIT）

`ext/pqc_rails/vendor/liboqs/`（`rake vendor:liboqs`実行後、またはリリース済みgem内）に、
[Open Quantum Safe](https://openquantumsafe.org/)プロジェクトによる
[liboqs](https://github.com/open-quantum-safe/liboqs)のソースを同梱しています。

```
Copyright (c) 2016-2024 The Open Quantum Safe project authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### liboqsが同梱する第三者アルゴリズム参照実装について

liboqs自体のLICENSE.txtが明記する通り、liboqsは各PQCアルゴリズムの参照実装をサブディレクトリ単位で
同梱しており、それぞれ個別のライセンスが適用されます。`pqc_rails`はビルド時にliboqsをデフォルト設定
（全アルゴリズム）でビルドしているため、実際にリンクされる共有ライブラリにはこれら全ての実装が
含まれます。

liboqs 0.16.0のソースツリーを確認したところ、以下の系統のライセンスが含まれています
（いずれも許諾範囲の広いライセンスで、GPL等のコピーレフトライセンスは含まれていません）。
0.16.0でSPHINCS+はFIPS 205標準名の「SLH-DSA」実装(slhdsa-cプロジェクト)に置き換わり、
新規署名アルゴリズム候補「MQOM」が追加されています。

| ライセンス | 主な対象アルゴリズム(一例) |
|---|---|
| MIT | Falcon(参照実装)、SNOVA、MQOM |
| Apache License 2.0 | ML-DSA/Kyber(最適化実装)、BIKE、MAYO、Falcon(ARM NEON実装) |
| Apache-2.0 OR ISC OR MIT(トリプルライセンス) | SLH-DSA(slhdsa-c、FIPS 205参照実装) |
| CC0 1.0 Universal(パブリックドメイン相当) | ML-DSA/Kyber(参照実装)、XMSS |
| Public Domain | Classic McEliece、HQC |
| 個別のコピーライト表示付きライセンス | XMSS/LMS(ステートフル署名、Cisco Systems等) |

**個々のサブディレクトリのLICENSE/NOTICEファイル自体が正本です**。本表は概観のための一覧であり、
153個の個別ライセンスファイル（重複除くと約15種類のライセンス文面）すべての内容を検証・転記した
ものではありません。同梱されたソースツリー（`ext/pqc_rails/vendor/liboqs/`配下の各`LICENSE`/`NOTICE`
ファイル）がそのままgemパッケージに含まれるため、再配布時の表示義務はソースの同梱によって満たされる
設計です。Apache License 2.0が要求する`NOTICE`ファイルの保持についても、上流の`NOTICE`ファイル
（例: `src/sig/mayo/*/NOTICE`）をそのまま同梱することで対応しています。

**既知の限界**：174ファイルの網羅的な法務レビューは未実施です。上記の表はソースの一次確認による
概観であり、規制対応等で正式な法務レビューが必要な場合は、同梱されたソースツリー
（`ext/pqc_rails/vendor/liboqs/`）を対象に別途依頼することを推奨します。

## ffi gem（依存・BSD-3-Clause）

`pqc_rails`はliboqsへのFFIバインディングに[ffi](https://github.com/ffi/ffi) gem（BSD-3-Clause）に
依存しています。ffi自体のソース・バイナリは`pqc_rails`のgemパッケージには同梱していません
（通常の gem依存として`bundle install`時に別途取得されます）。
